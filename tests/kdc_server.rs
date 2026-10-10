#![cfg(all(feature = "kdc", feature = "tokio"))]
//! Network serving checks: our KDC on loopback UDP/TCP driven by the crate's
//! own client transports (MIT net-server.c framing, dispatch.c too-big).

use std::net::SocketAddr;
use std::sync::Arc;

use krb5_rs::kdc::{
    serve_tcp, serve_udp, Kdc, KdcConfig, MemoryStore, PrincipalAttributes, PrincipalStore,
};
use krb5_rs::protocol::{
    AsExchange, AsExchangeConfig, Credential, StepResult, TgsExchange, TgsOptions, TgsStepResult,
};
use krb5_rs::transport::{KdcTransport, TcpTransport, UdpTcpTransport, UdpTransport};
use krb5_rs::types::{KrbErrorMsg, PrincipalName};
use krb5_rs::Krb5Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

const REALM: &str = "NET.REALM";
const PASSWORD: &str = "netpassword";

fn service() -> PrincipalName {
    PrincipalName::new_srv_hst("HTTP", "server.net.realm")
}

struct Server {
    addr: SocketAddr,
}

/// Start UDP and TCP servers on the same loopback port.
async fn start(max_dgram: Option<usize>) -> Server {
    let mut store = MemoryStore::new();
    store
        .add_random_key(
            PrincipalName::new_srv_inst("krbtgt", REALM),
            REALM,
            1,
            &[18, 17],
            PrincipalAttributes::empty(),
        )
        .expect("krbtgt");
    store
        .add_with_password(
            PrincipalName::new_principal("alice"),
            REALM,
            PASSWORD,
            1,
            &[18, 17],
            PrincipalAttributes::REQUIRES_PRE_AUTH,
        )
        .expect("alice");
    store
        .add_random_key(service(), REALM, 1, &[18], PrincipalAttributes::empty())
        .expect("service");
    assert!(store.lookup(&service(), REALM).expect("lookup").is_some());
    let mut config = KdcConfig::new(REALM);
    if let Some(m) = max_dgram {
        config.max_dgram_reply_size = m;
    }
    let kdc = Arc::new(Kdc::new(config, store));

    // An ephemeral TCP port can be unusable for UDP (Windows excluded port
    // ranges differ per protocol), so retry with a fresh port.
    let (tcp, udp, addr) = loop {
        let tcp = TcpListener::bind("127.0.0.1:0").await.expect("bind tcp");
        let addr = tcp.local_addr().expect("addr");
        if let Ok(udp) = UdpSocket::bind(addr).await {
            break (tcp, udp, addr);
        }
    };
    tokio::spawn(serve_udp(Arc::clone(&kdc), udp));
    tokio::spawn(serve_tcp(kdc, tcp));
    Server { addr }
}

async fn as_exchange<T: KdcTransport>(t: &T, password: &str) -> Result<Credential, Krb5Error> {
    let config = AsExchangeConfig::new(PrincipalName::new_principal("alice"), REALM);
    let mut exchange = AsExchange::new(config, password);
    let mut reply = Vec::new();
    loop {
        match exchange.step(&reply)? {
            StepResult::SendToKdc { data, realm } | StepResult::RetryTcp { data, realm } => {
                reply = t.send_recv(&realm, &data).await?;
            }
            StepResult::Complete => return exchange.credential().cloned(),
        }
    }
}

async fn tgs_exchange<T: KdcTransport>(t: &T, tgt: &Credential) -> Result<Credential, Krb5Error> {
    let mut exchange = TgsExchange::new(tgt.clone(), service(), TgsOptions::default());
    let mut reply = Vec::new();
    loop {
        match exchange.step(&reply)? {
            TgsStepResult::SendToKdc { data, realm } | TgsStepResult::RetryTcp { data, realm } => {
                reply = t.send_recv(&realm, &data).await?;
            }
            TgsStepResult::Complete => return exchange.credential().cloned(),
        }
    }
}

async fn full_exchange<T: KdcTransport>(t: &T) {
    let tgt = as_exchange(t, PASSWORD).await.expect("AS exchange");
    let st = tgs_exchange(t, &tgt).await.expect("TGS exchange");
    assert_eq!(st.server, service());
}

/// One framed TCP exchange; returns the reply (None if closed without one).
async fn raw_tcp(addr: SocketAddr, send: &[u8]) -> Option<Vec<u8>> {
    let mut s = TcpStream::connect(addr).await.expect("connect");
    s.write_all(send).await.expect("write");
    let mut len = [0u8; 4];
    s.read_exact(&mut len).await.ok()?;
    let mut body = vec![0u8; u32::from_be_bytes(len) as usize];
    s.read_exact(&mut body).await.ok()?;
    let mut rest = Vec::new();
    s.read_to_end(&mut rest).await.expect("read to close");
    assert!(rest.is_empty(), "server closes after one reply");
    Some(body)
}

fn code(reply: &[u8]) -> i32 {
    rasn::der::decode::<KrbErrorMsg>(reply)
        .expect("KRB-ERROR")
        .error_code
}

#[tokio::test]
async fn udp_transport_as_and_tgs_complete() {
    let s = start(None).await;
    full_exchange(&UdpTransport::new(s.addr)).await;
}

#[tokio::test]
async fn tcp_transport_as_and_tgs_complete() {
    let s = start(None).await;
    full_exchange(&TcpTransport::new(s.addr)).await;
}

#[tokio::test]
async fn udp_small_dgram_limit_returns_response_too_big() {
    let s = start(Some(120)).await;
    let config = AsExchangeConfig::new(PrincipalName::new_principal("alice"), REALM);
    let mut exchange = AsExchange::new(config, PASSWORD);
    let StepResult::SendToKdc { data, realm } = exchange.step(&[]).expect("first step") else {
        panic!("expected SendToKdc");
    };
    let reply = UdpTransport::new(s.addr)
        .send_recv(&realm, &data)
        .await
        .expect("udp reply");
    assert_eq!(code(&reply), 52);
    // The client resends the identical request over TCP (RetryTcp).
    let StepResult::RetryTcp { data: again, .. } = exchange.step(&reply).expect("retry") else {
        panic!("expected RetryTcp");
    };
    assert_eq!(again, data);
    let over_tcp = TcpTransport::new(s.addr)
        .send_recv(&realm, &again)
        .await
        .expect("tcp reply");
    assert_eq!(code(&over_tcp), 25);
}

#[tokio::test]
async fn udp_then_tcp_transport_completes_when_replies_exceed_dgram_limit() {
    let s = start(Some(120)).await;
    full_exchange(&UdpTcpTransport::new(s.addr)).await;
}

#[tokio::test]
async fn tcp_high_bit_length_gets_field_toolong_and_server_keeps_serving() {
    let s = start(None).await;
    let reply = raw_tcp(s.addr, &[0xFF, 0xFF, 0xFF, 0xFF])
        .await
        .expect("error reply");
    assert_eq!(code(&reply), 61);
    full_exchange(&TcpTransport::new(s.addr)).await;
}

#[tokio::test]
async fn tcp_oversize_length_gets_field_toolong_and_server_keeps_serving() {
    let s = start(None).await;
    let reply = raw_tcp(s.addr, &(1024u32 * 1024).to_be_bytes())
        .await
        .expect("error reply");
    assert_eq!(code(&reply), 61);
    full_exchange(&TcpTransport::new(s.addr)).await;
}

#[tokio::test]
async fn tcp_garbage_message_gets_error_reply_and_close() {
    let s = start(None).await;
    let mut msg = 3u32.to_be_bytes().to_vec();
    msg.extend_from_slice(&[1, 2, 3]);
    let reply = raw_tcp(s.addr, &msg).await.expect("error reply");
    assert_eq!(code(&reply), 40);
}

#[tokio::test]
async fn tcp_truncated_message_is_dropped_and_server_keeps_serving() {
    let s = start(None).await;
    {
        let mut c = TcpStream::connect(s.addr).await.expect("connect");
        let mut msg = 100u32.to_be_bytes().to_vec();
        msg.extend_from_slice(&[0x6A, 1]);
        c.write_all(&msg).await.expect("write");
    }
    full_exchange(&TcpTransport::new(s.addr)).await;
}

#[tokio::test]
async fn udp_garbage_datagram_gets_error_reply() {
    let s = start(None).await;
    let sock = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
    sock.send_to(&[9, 9, 9], s.addr).await.expect("send");
    let mut buf = [0u8; 2048];
    let (n, _) = sock.recv_from(&mut buf).await.expect("recv");
    assert_eq!(code(&buf[..n]), 40);
}
