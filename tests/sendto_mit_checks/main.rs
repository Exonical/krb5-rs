#![cfg(feature = "client")]
//! MIT krb5 1.22.2 k5_sendto/k5_sendto_kdc semantics on tokio: pass
//! structure, timing, strategy selection (sendto_kdc.c), deltat parsing
//! (t_deltat.c verbatim), RESPONSE_TOO_BIG retry (get_in_tkt.c), kdclist
//! replica marking (locate_kdc.c), and the primary-KDC retry rule.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use krb5_rs::client::primary::*;
use krb5_rs::error::Krb5Error;
use krb5_rs::locate::*;
use krb5_rs::profile::*;
use krb5_rs::transport::sendto::*;
use krb5_rs::transport::{KdcTransport, LocatedTransport};
use krb5_rs::types::KerberosTime;

#[path = "../common/mod.rs"]
mod common;
use common::krb_error::krb_error_der;

include!("strategy.rs");
include!("deltat.rs");
include!("passes.rs");
include!("tcp.rs");
include!("handler.rs");
include!("located.rs");
include!("primary.rs");

// ---------------------------------------------------------------------------
// Shared fixtures: fake KDCs on 127.0.0.1:0 with scripted behaviour.
// ---------------------------------------------------------------------------

/// Scaled-down timing so the whole suite runs in ~seconds while preserving
/// the MIT pass structure (sendto_kdc.c:1474-1496 shape).
fn fast_cfg() -> SendtoConfig {
    SendtoConfig {
        udp_preference_limit: 1465,
        request_timeout: None,
        timing: SendtoTiming {
            per_server: Duration::from_millis(60),
            first_pass_tail: Duration::from_millis(120),
            initial_backoff: Duration::from_millis(240),
            max_pass: 3,
        },
    }
}

#[derive(Debug, Clone, PartialEq)]
enum Kind {
    Udp,
    Tcp,
}

#[derive(Debug)]
struct Recv {
    server: String,
    kind: Kind,
    #[allow(dead_code)]
    at: Instant,
}

type Log = Arc<Mutex<Vec<Recv>>>;

fn new_log() -> Log {
    Arc::new(Mutex::new(Vec::new()))
}

/// Spawn a UDP responder task. Returns its bound port.
async fn spawn_udp(log: Log, name: &str, reply: Option<Vec<u8>>) -> (u16, Arc<AtomicUsize>) {
    let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = sock.local_addr().unwrap().port();
    let count = Arc::new(AtomicUsize::new(0));
    let count2 = count.clone();
    let name = name.to_string();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        loop {
            let Ok((_n, peer)) = sock.recv_from(&mut buf).await else {
                return;
            };
            count2.fetch_add(1, Ordering::SeqCst);
            log.lock().unwrap().push(Recv {
                server: name.clone(),
                kind: Kind::Udp,
                at: Instant::now(),
            });
            if let Some(r) = &reply {
                let _ = sock.send_to(r, peer).await;
            }
        }
    });
    (port, count)
}

/// Spawn a TCP responder. `action` decides per-connection behavior.
#[derive(Clone)]
enum TcpAction {
    /// Read request, sleep `delay`, send 4-byte len + reply.
    Reply(Duration, Vec<u8>),
    /// Accept, read request, then close.
    CloseAfterRead,
    /// Send a length prefix >1MiB then garbage.
    HugeLen,
}

/// `port` 0 picks a free port; pass a UDP port to colocate TCP+UDP on one
/// port (one server entry with two transports).
async fn spawn_tcp(log: Log, name: &str, action: TcpAction, port: u16) -> u16 {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port))
        .await
        .unwrap();
    let port = listener.local_addr().unwrap().port();
    let name = name.to_string();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = listener.accept().await {
            let log = log.clone();
            let name = name.clone();
            let action = action.clone();
            tokio::spawn(async move {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                log.lock().unwrap().push(Recv {
                    server: name.clone(),
                    kind: Kind::Tcp,
                    at: Instant::now(),
                });
                let mut lenb = [0u8; 4];
                if s.read_exact(&mut lenb).await.is_err() {
                    return;
                }
                let len = u32::from_be_bytes(lenb) as usize;
                let mut buf = vec![0u8; len.min(1 << 20)];
                let _ = s.read_exact(&mut buf).await;
                match action {
                    TcpAction::Reply(d, r) => {
                        tokio::time::sleep(d).await;
                        let _ = s.write_all(&(r.len() as u32).to_be_bytes()).await;
                        let _ = s.write_all(&r).await;
                    }
                    TcpAction::CloseAfterRead => {}
                    TcpAction::HugeLen => {
                        let _ = s.write_all(&((1u32 << 20) + 1).to_be_bytes()).await;
                        let _ = s.write_all(&[0u8; 16]).await;
                    }
                }
            });
        }
    });
    port
}

fn entry(port: u16, transport: Transport) -> ServerEntry {
    ServerEntry {
        hostname: "127.0.0.1".into(),
        port,
        transport,
        uri_path: None,
        primary: None,
    }
}

/// DER-encode a KRB-ERROR with the given error code.
fn krb_error(code: i32) -> Vec<u8> {
    let t: KerberosTime = chrono::DateTime::from_timestamp(1_700_000_000, 0)
        .unwrap()
        .with_timezone(&chrono::FixedOffset::east_opt(0).unwrap());
    krb_error_der(code, "R", Some(t), None)
}
