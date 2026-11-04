//! MS-KKDCP: KDC requests over HTTPS like MIT, ported from MIT
//! tests/t_proxy.py with MIT's tests/proxy-certs and a local proxy.
#![cfg(feature = "kkdcp")]

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use krb5_rs::profile::Profile;
use krb5_rs::transport::{KdcTransport, LocatedTransport, SendtoConfig, SendtoTiming};
use krb5_rs::types::KdcProxyMessage;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/kkdcp")
        .join(name)
}

#[derive(Default)]
struct Seen {
    head: String,
    realm: Option<String>,
    message: Vec<u8>,
}

#[path = "common/mod.rs"]
mod common;

/// A KKDCP proxy answering every request with `reply:` + the request.
async fn start_proxy(pem: &str) -> (u16, Arc<Mutex<Seen>>) {
    start_proxy_to(pem, None).await
}

/// A KKDCP proxy; with `kdc`, forwards each request to that KDC over TCP
/// like python-kdcproxy.
async fn start_proxy_to(pem: &str, kdc: Option<String>) -> (u16, Arc<Mutex<Seen>>) {
    let data = std::fs::read(fixture(pem)).unwrap();
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(&data)
        .collect::<Result<_, _>>()
        .unwrap();
    let key = PrivateKeyDer::from_pem_slice(&data).unwrap();
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(certs, key)
    .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen = Arc::new(Mutex::new(Seen::default()));
    let seen2 = seen.clone();
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                return;
            };
            let acceptor = acceptor.clone();
            let seen = seen2.clone();
            let kdc = kdc.clone();
            tokio::spawn(async move {
                let Ok(mut s) = acceptor.accept(tcp).await else {
                    return;
                };
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                let (head, body) = loop {
                    let n = s.read(&mut chunk).await.unwrap_or(0);
                    if n == 0 {
                        return;
                    }
                    buf.extend_from_slice(&chunk[..n]);
                    if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        let head = String::from_utf8_lossy(&buf[..i]).into_owned();
                        let len: usize = head
                            .lines()
                            .find_map(|l| l.strip_prefix("Content-Length: "))
                            .unwrap()
                            .parse()
                            .unwrap();
                        while buf.len() < i + 4 + len {
                            let n = s.read(&mut chunk).await.unwrap_or(0);
                            if n == 0 {
                                return;
                            }
                            buf.extend_from_slice(&chunk[..n]);
                        }
                        break (head, buf[i + 4..i + 4 + len].to_vec());
                    }
                };
                let pm: KdcProxyMessage = rasn::der::decode(&body).unwrap();
                let km: &[u8] = pm.kerb_message.as_ref();
                assert_eq!(
                    u32::from_be_bytes(km[..4].try_into().unwrap()) as usize,
                    km.len() - 4
                );
                let reply = match &kdc {
                    Some(addr) => {
                        let mut t = tokio::net::TcpStream::connect(addr).await.unwrap();
                        t.write_all(km).await.unwrap();
                        let mut len = [0u8; 4];
                        t.read_exact(&mut len).await.unwrap();
                        let mut r = vec![0u8; u32::from_be_bytes(len) as usize];
                        t.read_exact(&mut r).await.unwrap();
                        r
                    }
                    None => {
                        let mut r = b"reply:".to_vec();
                        r.extend_from_slice(&km[4..]);
                        r
                    }
                };
                {
                    let mut g = seen.lock().unwrap();
                    g.head = head;
                    g.realm = pm
                        .target_domain
                        .as_ref()
                        .map(|r| String::from_utf8_lossy(r.as_bytes()).into_owned());
                    g.message = km[4..].to_vec();
                }
                let mut framed = (reply.len() as u32).to_be_bytes().to_vec();
                framed.extend_from_slice(&reply);
                let out = KdcProxyMessage {
                    kerb_message: framed.into(),
                    target_domain: None,
                    dclocator_hint: None,
                };
                let mut resp =
                    b"HTTP/1.0 200 OK\r\nContent-Type: application/kerberos\r\n\r\n".to_vec();
                resp.extend_from_slice(&rasn::der::encode(&out).unwrap());
                let _ = s.write_all(&resp).await;
                let _ = s.shutdown().await;
            });
        }
    });
    (port, seen)
}

fn transport(kdc: &str, anchors: &[String]) -> LocatedTransport {
    let mut conf = format!(
        "[libdefaults]\n default_realm = KRBTEST.COM\n dns_lookup_kdc = false\n\
         [realms]\n KRBTEST.COM = {{\n  kdc = {kdc}\n"
    );
    for a in anchors {
        conf.push_str(&format!("  http_anchors = {a}\n"));
    }
    conf.push_str(" }\n");
    let profile = Arc::new(Profile::parse(&conf).unwrap());
    let cfg = SendtoConfig {
        timing: SendtoTiming {
            per_server: Duration::from_millis(200),
            first_pass_tail: Duration::from_millis(200),
            initial_backoff: Duration::from_millis(200),
            max_pass: 1,
        },
        ..SendtoConfig::default()
    };
    LocatedTransport::with_config(profile, None, cfg)
}

fn file_anchor() -> Vec<String> {
    vec![format!("FILE:{}", fixture("ca.pem").display())]
}

/// Send through a proxy using `pem`, to `https://<host>:<port>/KdcProxy`.
async fn run(pem: &str, host: &str, anchors: &[String]) -> Result<Vec<u8>, String> {
    let (port, _) = start_proxy(pem).await;
    let t = transport(&format!("https://{host}:{port}/KdcProxy"), anchors);
    t.send_recv("KRBTEST.COM", b"request")
        .await
        .map_err(|e| e.to_string())
}

#[tokio::test]
async fn t_proxy_passes() {
    let none: Vec<String> = Vec::new();
    let anchored = file_anchor();
    let cases: &[(&str, &str, &[String], bool)] = &[
        // 1-4: the issuer isn't trusted.
        ("proxy-no-match.pem", "localhost", &none, false),
        ("proxy-subject.pem", "localhost", &none, false),
        ("proxy-san.pem", "localhost", &none, false),
        ("proxy-badsig.pem", "localhost", &none, false),
        // 5-8: the issuer is trusted.
        ("proxy-no-match.pem", "localhost", &anchored, false),
        ("proxy-subject.pem", "localhost", &anchored, true),
        ("proxy-san.pem", "localhost", &anchored, true),
        ("proxy-badsig.pem", "localhost", &anchored, false),
        // 9-12: an IPv4 address.
        ("proxy-no-match.pem", "127.0.0.1", &anchored, false),
        ("proxy-subject.pem", "127.0.0.1", &anchored, false),
        ("proxy-san.pem", "127.0.0.1", &anchored, true),
        ("proxy-badsig.pem", "127.0.0.1", &anchored, false),
        // 15: SAN names match case-insensitively.
        ("proxy-san.pem", "LocalHost", &anchored, true),
        ("proxy-ideal.pem", "localhost", &anchored, true),
    ];
    for (i, (pem, host, anchors, ok)) in cases.iter().enumerate() {
        let r = run(pem, host, anchors).await;
        if *ok {
            assert_eq!(
                r.as_deref(),
                Ok(&b"reply:request"[..]),
                "case {i}: {pem} {host}"
            );
        } else {
            assert!(r.is_err(), "case {i}: {pem} {host} should fail");
        }
    }
}

#[tokio::test]
async fn proxy_request_like_mit() {
    let (port, seen) = start_proxy("proxy-san.pem").await;
    let t = transport(
        &format!("https://localhost:{port}/KdcProxy"),
        &file_anchor(),
    );
    assert_eq!(
        t.send_recv("KRBTEST.COM", b"abc").await.unwrap(),
        b"reply:abc"
    );
    let g = seen.lock().unwrap();
    let lines: Vec<&str> = g.head.split("\r\n").collect();
    assert_eq!(
        lines,
        [
            "POST /KdcProxy HTTP/1.0",
            &format!("Host: localhost:{port}"),
            "Cache-Control: no-cache",
            "Pragma: no-cache",
            "User-Agent: kerberos/1.0",
            "Content-type: application/kerberos",
            lines[6],
        ]
    );
    assert!(lines[6].starts_with("Content-Length: "));
    assert_eq!(g.realm.as_deref(), Some("KRBTEST.COM"));
    assert_eq!(g.message, b"abc");
}

#[tokio::test]
async fn anchor_locations_like_mit() {
    let dir = std::env::temp_dir().join(format!("krb5rs-kkdcp-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::copy(fixture("ca.pem"), dir.join("ca.pem")).unwrap();
    let ok = run(
        "proxy-san.pem",
        "localhost",
        &[format!("DIR:{}", dir.display())],
    )
    .await;
    assert_eq!(ok.as_deref(), Ok(&b"reply:request"[..]));
    // A directory holding only dot files has no anchors.
    let empty = dir.join("empty");
    std::fs::create_dir_all(&empty).unwrap();
    std::fs::copy(fixture("ca.pem"), empty.join(".hidden.pem")).unwrap();
    assert!(run(
        "proxy-san.pem",
        "localhost",
        &[format!("DIR:{}", empty.display())]
    )
    .await
    .is_err());
    std::env::set_var(
        "KRB5RS_KKDCP_TEST_ANCHOR",
        format!("FILE:{}", fixture("ca.pem").display()),
    );
    let ok = run(
        "proxy-san.pem",
        "localhost",
        &["ENV:KRB5RS_KKDCP_TEST_ANCHOR".into()],
    )
    .await;
    assert_eq!(ok.as_deref(), Ok(&b"reply:request"[..]));
    assert!(run(
        "proxy-san.pem",
        "localhost",
        &["ENV:KRB5RS_KKDCP_NO_SUCH_VAR".into()]
    )
    .await
    .is_err());
    assert!(run("proxy-san.pem", "localhost", &["BOGUS:x".into()])
        .await
        .is_err());
    let _ = std::fs::remove_dir_all(&dir);
}

/// Our client gets a TGT from MIT's KDC through a KKDCP proxy.
#[tokio::test]
#[ignore = "needs the MIT KDC container (docker compose -f docker-compose.test.yml up -d)"]
async fn kinit_through_proxy_against_mit_kdc() {
    let (port, seen) = start_proxy_to("proxy-san.pem", Some(common::kdc::kdc_addr_str())).await;
    let conf = format!(
        "[libdefaults]\n dns_lookup_kdc = false\n\
         [realms]\n TEST.REALM = {{\n  kdc = https://localhost:{port}/KdcProxy\n  http_anchors = FILE:{}\n }}\n",
        fixture("ca.pem").display()
    );
    let t = LocatedTransport::new(Arc::new(Profile::parse(&conf).unwrap()), None);
    let client = krb5_rs::client::KerberosClient::new("TEST.REALM", t);
    client
        .acquire_tgt("testuser", "testpassword")
        .await
        .expect("AS exchange over KKDCP failed");
    assert_eq!(seen.lock().unwrap().realm.as_deref(), Some("TEST.REALM"));
}
