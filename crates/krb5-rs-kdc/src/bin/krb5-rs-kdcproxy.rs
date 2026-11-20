//! `krb5-rs-kdcproxy`: an MS-KKDCP proxy, like python-kdcproxy (the KDC
//! proxy Red Hat ships for IdM). Clients POST a KDC-PROXY-MESSAGE over
//! HTTPS; the proxy forwards it to the realm's KDC or kpasswd server over
//! TCP or UDP and returns the reply.
//!
//! Realm servers come from `kdcproxy.conf` (`KDCPROXY_CONFIG`, else
//! `/usr/local/etc/kdcproxy.conf` and `/etc/kdcproxy.conf`), krb5.conf
//! `[realms]` with `[global] configs = mit`, or DNS SRV records.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use krb5_rs::locate::{DnsResolver, HickoryResolver, ServerEntry, Transport};
use krb5_rs::profile::Profile;
use krb5_rs::transport::{sendto, SendtoConfig, Strategy};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

#[path = "kdcproxy/codec.rs"]
mod codec;
#[path = "kdcproxy/config.rs"]
mod config;

/// `Application.MAX_LENGTH`.
const MAX_LENGTH: usize = 128 * 1024;
const MAX_HEADER: usize = 16 * 1024;
const READ_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Parser)]
#[command(name = "krb5-rs-kdcproxy", version, about = "MS-KKDCP KDC proxy")]
struct Cli {
    /// Address to listen on; repeat for several.
    #[arg(long, value_name = "ADDR", default_value = "0.0.0.0:443")]
    listen: Vec<SocketAddr>,
    /// PEM certificate chain; it may also hold the private key.
    #[arg(long, value_name = "PEM", required_unless_present = "http")]
    cert: Option<PathBuf>,
    /// PEM private key (default: the `--cert` file).
    #[arg(long, value_name = "PEM")]
    key: Option<PathBuf>,
    /// Serve plain HTTP, for use behind a reverse proxy that terminates TLS.
    #[arg(long, conflicts_with_all = ["cert", "key"])]
    http: bool,
    /// kdcproxy.conf to read instead of the default files.
    #[arg(long, env = "KDCPROXY_CONFIG", value_name = "PATH")]
    config: Option<PathBuf>,
}

fn krb5_profile() -> Profile {
    let paths = std::env::var("KRB5_CONFIG").unwrap_or_else(|_| "/etc/krb5.conf".into());
    let mut text = String::new();
    for p in paths.split(':').filter(|p| !p.is_empty()) {
        if let Ok(t) = std::fs::read_to_string(p) {
            text.push_str(&t);
            text.push('\n');
        }
    }
    Profile::parse(&text).unwrap_or_else(|e| die(format!("krb5.conf: {e}")))
}

fn die(msg: impl std::fmt::Display) -> ! {
    eprintln!("krb5-rs-kdcproxy: {msg}");
    std::process::exit(1)
}

fn tls_acceptor(cert: &PathBuf, key: Option<&PathBuf>) -> tokio_rustls::TlsAcceptor {
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    let read =
        |p: &PathBuf| std::fs::read(p).unwrap_or_else(|e| die(format!("{}: {e}", p.display())));
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(&read(cert))
        .collect::<Result<_, _>>()
        .unwrap_or_else(|e| die(format!("{}: {e}", cert.display())));
    if certs.is_empty() {
        die(format!("{}: no certificate", cert.display()));
    }
    let key_path = key.unwrap_or(cert);
    let key = PrivateKeyDer::from_pem_slice(&read(key_path))
        .unwrap_or_else(|e| die(format!("{}: {e}", key_path.display())));
    let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .and_then(|b| b.with_no_client_auth().with_single_cert(certs, key))
    .unwrap_or_else(|e| die(format!("TLS: {e}")));
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    tokio_rustls::TlsAcceptor::from(Arc::new(config))
}

struct Proxy {
    config: config::Config,
    dns: Option<HickoryResolver>,
}

/// An HTTP response: status, extra headers, body.
struct Response(u16, &'static str, Vec<u8>);

fn text(code: u16, msg: impl Into<String>) -> Response {
    Response(code, "text/plain; charset=utf-8", msg.into().into_bytes())
}

fn reason(code: u16) -> &'static str {
    match code {
        200 => "OK",
        400 => "Bad Request",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        411 => "Length Required",
        413 => "Request Entity Too Large",
        431 => "Request Header Fields Too Large",
        503 => "Service Unavailable",
        _ => "Error",
    }
}

/// The servers for `uris`, as `Application.__call__` filters them.
fn entries(uris: &[String]) -> Vec<ServerEntry> {
    uris.iter()
        .filter_map(|u| config::Uri::parse(u))
        .filter_map(|u| {
            let default = match u.scheme.as_str() {
                "kerberos" => 88,
                "kpasswd" => 464,
                _ => return None,
            };
            let transport = match u.transport.as_deref() {
                None => Transport::TcpOrUdp,
                Some("tcp") => Transport::Tcp,
                Some("udp") => Transport::Udp,
                Some(_) => return None,
            };
            Some(ServerEntry {
                hostname: u.host,
                port: u.port.unwrap_or(default),
                transport,
                uri_path: None,
                primary: None,
            })
        })
        .collect()
}

impl Proxy {
    /// `Application.__call__` after the request is read.
    async fn handle(&self, method: &str, body: Result<Vec<u8>, Response>) -> Response {
        if method != "POST" {
            return text(405, format!("Method not allowed ({method})."));
        }
        let body = match body {
            Ok(b) => b,
            Err(r) => return r,
        };
        let req = match codec::decode(&body) {
            Ok(r) => r,
            Err(e) => return text(400, e),
        };
        let kpasswd = matches!(req.kind, codec::Kind::Kpasswd(_));
        let uris = match &req.realm {
            Some(realm) => self.config.lookup(
                realm,
                kpasswd,
                self.dns.as_ref().map(|d| d as &dyn DnsResolver),
            ),
            None => Vec::new(),
        };
        let servers = entries(&uris);
        if servers.is_empty() {
            return text(503, format!("Can't find remote ({req})."));
        }
        let cfg = SendtoConfig::default();
        match sendto(
            &servers,
            &req.message[4..],
            Strategy::UdpLast,
            &cfg,
            &|_| true,
        )
        .await
        {
            Ok(reply) => Response(200, "application/kerberos", codec::encode(&reply.data)),
            Err(e) => {
                tracing::warn!("Exchange for {req} failed: {e:?}");
                text(503, format!("Remote unavailable ({req})."))
            }
        }
    }
}

/// Read one request: the method and the body (or the error response).
async fn read_request<S: AsyncRead + AsyncWrite + Unpin>(
    s: &mut S,
) -> Option<(String, Result<Vec<u8>, Response>)> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let head_end = loop {
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i;
        }
        if buf.len() > MAX_HEADER {
            return Some((String::new(), Err(text(431, "Request header too large."))));
        }
        let n = s.read(&mut chunk).await.ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
    let mut lines = head.split("\r\n");
    let method = lines.next()?.split(' ').next()?.to_uppercase();
    let mut length: Option<i64> = None;
    let mut expect_continue = false;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let (name, value) = (name.trim(), value.trim());
        if name.eq_ignore_ascii_case("content-length") {
            length = value.parse().ok();
        } else if name.eq_ignore_ascii_case("expect") && value.eq_ignore_ascii_case("100-continue")
        {
            expect_continue = true;
        }
    }
    if method != "POST" {
        return Some((method, Err(text(405, ""))));
    }
    let length = match length {
        Some(l) if l >= 0 => l as usize,
        _ => return Some((method, Err(text(411, "Length required.")))),
    };
    if length > MAX_LENGTH {
        return Some((method, Err(text(413, "Request entity too large."))));
    }
    if expect_continue {
        s.write_all(b"HTTP/1.1 100 Continue\r\n\r\n").await.ok()?;
    }
    let mut body = buf.split_off(head_end + 4);
    while body.len() < length {
        let n = s.read(&mut chunk).await.ok()?;
        if n == 0 {
            return None;
        }
        body.extend_from_slice(&chunk[..n]);
    }
    body.truncate(length);
    Some((method, Ok(body)))
}

async fn serve<S: AsyncRead + AsyncWrite + Unpin>(proxy: &Proxy, mut s: S) {
    let resp = match tokio::time::timeout(READ_TIMEOUT, read_request(&mut s)).await {
        Ok(Some((method, body))) => proxy.handle(&method, body).await,
        Ok(None) => return,
        Err(_) => text(408, "Request timeout."),
    };
    let Response(code, ctype, body) = resp;
    let mut out = format!(
        "HTTP/1.1 {code} {}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        reason(code),
        body.len()
    )
    .into_bytes();
    out.extend_from_slice(&body);
    let _ = s.write_all(&out).await;
    let _ = s.shutdown().await;
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();
    let cli = Cli::parse();
    let files: Vec<PathBuf> = match &cli.config {
        Some(p) => vec![p.clone()],
        None => config::DEFAULT_FILES.iter().map(PathBuf::from).collect(),
    };
    let mut ini = Vec::new();
    for f in &files {
        if let Ok(t) = std::fs::read_to_string(f) {
            config::parse_ini(&t, &mut ini)
                .unwrap_or_else(|e| die(format!("{}: {e}", f.display())));
        }
    }
    let config = config::Config::new(&ini, krb5_profile)
        .unwrap_or_else(|e| die(format!("kdcproxy.conf: {e}")));
    let dns = HickoryResolver::new()
        .map_err(|e| tracing::warn!("DNS discovery disabled: {e}"))
        .ok();
    let proxy = Arc::new(Proxy { config, dns });
    let tls = cli.cert.as_ref().map(|c| tls_acceptor(c, cli.key.as_ref()));
    let mut tasks = Vec::new();
    for addr in &cli.listen {
        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .unwrap_or_else(|e| die(format!("{addr}: {e}")));
        tracing::info!("listening on {addr}");
        let proxy = proxy.clone();
        let tls = tls.clone();
        tasks.push(tokio::spawn(async move {
            loop {
                let Ok((tcp, _)) = listener.accept().await else {
                    continue;
                };
                let proxy = proxy.clone();
                let tls = tls.clone();
                tokio::spawn(async move {
                    match tls {
                        Some(tls) => {
                            if let Ok(Ok(s)) =
                                tokio::time::timeout(READ_TIMEOUT, tls.accept(tcp)).await
                            {
                                serve(&proxy, s).await;
                            }
                        }
                        None => serve(&proxy, tcp).await,
                    }
                });
            }
        }));
    }
    for t in tasks {
        let _ = t.await;
    }
}
