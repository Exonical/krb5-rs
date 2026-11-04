//! MS-KKDCP: KDC requests over HTTPS like MIT (sendto_kdc.c
//! `make_proxy_request`, `service_https_*`; plugins/tls/k5tls/openssl.c).

use std::net::IpAddr;
use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{CertificateError, DigitallySignedStruct, RootCertStore, SignatureScheme};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc::UnboundedSender;

use super::conn::ConnEvent;
use crate::locate::Transport;
use crate::transport::MAX_KDC_RESPONSE_SIZE;
use crate::types::KdcProxyMessage;

/// The realm a KKDCP request is for and its `http_anchors`.
#[derive(Debug, Clone, Default)]
pub struct HttpsTarget {
    /// Realm, sent as the proxy message's `target-domain`.
    pub realm: String,
    /// `[realms] <realm> http_anchors` (`FILE:`, `DIR:`, `ENV:`); empty
    /// uses the system's default trust store.
    pub anchors: Vec<String>,
}

/// One HTTPS server entry.
pub(super) struct HttpsPeer {
    pub servername: String,
    pub port: u16,
    pub path: Option<String>,
    pub target: Arc<HttpsTarget>,
}

/// `make_proxy_request`: the HTTP/1.0 POST carrying a KDC-PROXY-MESSAGE
/// whose `kerb-message` is the TCP-framed request.
pub(super) fn proxy_request(peer: &HttpsPeer, message: &[u8]) -> Option<Vec<u8>> {
    let mut km = u32::try_from(message.len()).ok()?.to_be_bytes().to_vec();
    km.extend_from_slice(message);
    let pm = KdcProxyMessage {
        kerb_message: km.into(),
        target_domain: Some(
            rasn::types::GeneralString::from_bytes(peer.target.realm.as_bytes()).ok()?,
        ),
        dclocator_hint: None,
    };
    let body = rasn::der::encode(&pm).ok()?;
    let path = peer.path.as_deref().unwrap_or("");
    let path = path.strip_prefix('/').unwrap_or(path);
    let mut req = format!(
        "POST /{path} HTTP/1.0\r\nHost: {}:{}\r\nCache-Control: no-cache\r\n\
         Pragma: no-cache\r\nUser-Agent: kerberos/1.0\r\n\
         Content-type: application/kerberos\r\nContent-Length: {}\r\n\r\n",
        peer.servername,
        peer.port,
        body.len()
    )
    .into_bytes();
    req.extend_from_slice(&body);
    Some(req)
}

/// `service_https_read`: the KDC reply inside an HTTP response, after the
/// first blank line, with its 4-byte length checked and removed.
pub(super) fn parse_response(buf: &[u8]) -> Option<Vec<u8>> {
    let start = buf.windows(4).position(|w| w == b"\r\n\r\n")? + 4;
    let pm: KdcProxyMessage = rasn::der::decode(&buf[start..]).ok()?;
    let km: &[u8] = pm.kerb_message.as_ref();
    if km.len() < 4 || u32::from_be_bytes([km[0], km[1], km[2], km[3]]) as usize != km.len() - 4 {
        return None;
    }
    Some(km[4..].to_vec())
}

/// HTTPS connection task: connect, TLS handshake (verified like k5tls),
/// write the proxy request, read to end of stream, unwrap the reply.
pub(super) async fn https_conn(
    id: usize,
    idx: usize,
    addr: std::net::SocketAddr,
    peer: Arc<HttpsPeer>,
    message: Vec<u8>,
    tx: UnboundedSender<ConnEvent>,
) {
    let dead = |tx: &UnboundedSender<ConnEvent>| {
        let _ = tx.send(ConnEvent::Dead(id));
    };
    let Some(req) = proxy_request(&peer, &message) else {
        return dead(&tx);
    };
    let Ok(tcp) = TcpStream::connect(addr).await else {
        return dead(&tx);
    };
    let Some(config) = client_config(&peer) else {
        return dead(&tx);
    };
    let Ok(name) = ServerName::try_from(peer.servername.clone()) else {
        return dead(&tx);
    };
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let Ok(mut stream) = connector.connect(name, tcp).await else {
        return dead(&tx);
    };
    if stream.write_all(&req).await.is_err() || stream.flush().await.is_err() {
        return dead(&tx);
    }
    let _ = tx.send(ConnEvent::Established(id));
    let mut buf = Vec::new();
    let mut chunk = vec![0u8; 8192];
    loop {
        match stream.read(&mut chunk).await {
            Ok(0) => break,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            // SSL_OP_IGNORE_UNEXPECTED_EOF: a missing close_notify is fine.
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(_) => return dead(&tx),
        }
        if buf.len() >= MAX_KDC_RESPONSE_SIZE {
            return dead(&tx);
        }
    }
    match parse_response(&buf) {
        Some(reply) => {
            let _ = tx.send(ConnEvent::Reply(id, idx, Transport::Https, reply));
        }
        None => dead(&tx),
    }
}

fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

fn client_config(peer: &HttpsPeer) -> Option<rustls::ClientConfig> {
    let roots = load_anchors(&peer.target.anchors)?;
    let provider = provider();
    let verifier = MitVerifier {
        roots: Arc::new(roots),
        provider: provider.clone(),
        expected: peer.servername.clone(),
    };
    Some(
        rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .ok()?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(verifier))
            .with_no_client_auth(),
    )
}

/// `load_anchors`: the configured anchors, or the system defaults
/// (`SSL_CTX_set_default_verify_paths`).
pub(super) fn load_anchors(anchors: &[String]) -> Option<RootCertStore> {
    let mut store = RootCertStore::empty();
    if anchors.is_empty() {
        let native = rustls_native_certs::load_native_certs();
        if native.certs.is_empty() {
            return None;
        }
        store.add_parsable_certificates(native.certs);
    } else {
        for a in anchors {
            load_anchor(&mut store, a)?;
        }
    }
    Some(store)
}

fn load_anchor(store: &mut RootCertStore, location: &str) -> Option<()> {
    if let Some(path) = location.strip_prefix("FILE:") {
        load_anchor_file(store, std::path::Path::new(path))
    } else if let Some(path) = location.strip_prefix("DIR:") {
        let mut found = false;
        for e in std::fs::read_dir(path).ok()?.flatten() {
            if e.file_name().as_encoded_bytes().first() != Some(&b'.')
                && load_anchor_file(store, &e.path()).is_some()
            {
                found = true;
            }
        }
        found.then_some(())
    } else if let Some(var) = location.strip_prefix("ENV:") {
        load_anchor(store, &std::env::var(var).ok()?)
    } else {
        None
    }
}

fn load_anchor_file(store: &mut RootCertStore, path: &std::path::Path) -> Option<()> {
    let data = std::fs::read(path).ok()?;
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(&data)
        .collect::<Result<_, _>>()
        .ok()?;
    store.add_parsable_certificates(certs);
    Some(())
}

/// k5tls's verification: the chain against the anchors, then
/// `check_cert_name_or_ip` on the server's certificate.
#[derive(Debug)]
struct MitVerifier {
    roots: Arc<RootCertStore>,
    provider: Arc<CryptoProvider>,
    expected: String,
}

impl ServerCertVerifier for MitVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let bad = |e: webpki::Error| {
            rustls::Error::InvalidCertificate(CertificateError::Other(rustls::OtherError(
                Arc::new(e),
            )))
        };
        let cert = webpki::EndEntityCert::try_from(end_entity).map_err(bad)?;
        cert.verify_for_usage(
            self.provider.signature_verification_algorithms.all,
            &self.roots.roots,
            intermediates,
            now,
            webpki::KeyUsage::server_auth(),
            None,
            None,
        )
        .map_err(bad)?;
        if !check_cert_name_or_ip(end_entity.as_ref(), &self.expected) {
            return Err(rustls::Error::InvalidCertificate(
                CertificateError::NotValidForName,
            ));
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// openssl.c `label_match`: ASCII case-insensitive; `*` matches a whole
/// first label.
fn label_match(
    presented: &[u8],
    expected: &[u8],
    allow_wildcard: bool,
    wildcard: &mut bool,
) -> bool {
    if allow_wildcard && presented == b"*" {
        *wildcard = true;
        return true;
    }
    presented.eq_ignore_ascii_case(expected)
}

/// openssl.c `domain_match`: label by label; a wildcard needs at least
/// three labels.
pub(super) fn domain_match(presented: &[u8], expected: &str) -> bool {
    let expected = expected.as_bytes();
    let (mut p, mut r) = (0, 0);
    let mut n_label = 0;
    let mut used_wildcard = false;
    while p < presented.len() && r < expected.len() {
        let q = presented[p..]
            .iter()
            .position(|&c| c == b'.')
            .map_or(presented.len(), |i| p + i);
        let s = expected[r..]
            .iter()
            .position(|&c| c == b'.')
            .map_or(expected.len(), |i| r + i);
        if !label_match(
            &presented[p..q],
            &expected[r..s],
            n_label == 0,
            &mut used_wildcard,
        ) {
            return false;
        }
        p = if q < presented.len() { q + 1 } else { q };
        r = if s < expected.len() { s + 1 } else { s };
        n_label += 1;
    }
    if used_wildcard && n_label <= 2 {
        return false;
    }
    p == presented.len() && r == expected.len()
}

struct CertNames {
    dns: Vec<Vec<u8>>,
    ips: Vec<Vec<u8>>,
    has_dns_san: bool,
    has_ip_san: bool,
    cn: Option<Vec<u8>>,
}

fn cert_names(der: &[u8]) -> Option<CertNames> {
    use x509_cert::der::{Any, Decode, Tag, TagNumber, Tagged};
    let cert = x509_cert::Certificate::from_der(der).ok()?;
    let tbs = &cert.tbs_certificate;
    let mut names = CertNames {
        dns: Vec::new(),
        ips: Vec::new(),
        has_dns_san: false,
        has_ip_san: false,
        cn: None,
    };
    let san_oid = const_oid::db::rfc5280::ID_CE_SUBJECT_ALT_NAME;
    if let Some(ext) = tbs
        .extensions
        .iter()
        .flatten()
        .find(|e| e.extn_id == san_oid)
    {
        // Raw GeneralNames: like OpenSSL, accept non-ASCII dNSName bytes.
        if let Ok(gns) = Vec::<Any>::from_der(ext.extn_value.as_bytes()) {
            for gn in gns {
                match gn.tag() {
                    Tag::ContextSpecific {
                        constructed: false,
                        number,
                    } if number == TagNumber::N2 => {
                        names.has_dns_san = true;
                        names.dns.push(gn.value().to_vec());
                    }
                    Tag::ContextSpecific {
                        constructed: false,
                        number,
                    } if number == TagNumber::N7 => {
                        names.has_ip_san = true;
                        names.ips.push(gn.value().to_vec());
                    }
                    _ => {}
                }
            }
        }
    }
    let cn_oid = const_oid::db::rfc4519::CN;
    names.cn = tbs
        .subject
        .0
        .iter()
        .flat_map(|rdn| rdn.0.iter())
        .find(|a| a.oid == cn_oid)
        .filter(|a| a.value.tag().is_universal())
        .map(|a| a.value.value().to_vec());
    Some(names)
}

/// openssl.c `check_cert_name_or_ip`.
pub(super) fn check_cert_name_or_ip(der: &[u8], expected: &str) -> bool {
    let Some(names) = cert_names(der) else {
        return false;
    };
    if let Ok(ip) = expected.parse::<IpAddr>() {
        // check_cert_address: IP SANs if there are any, else the CN text.
        let octets = match ip {
            IpAddr::V4(a) => a.octets().to_vec(),
            IpAddr::V6(a) => a.octets().to_vec(),
        };
        if names.has_ip_san {
            return names.ips.contains(&octets);
        }
        return names.cn.as_deref() == Some(expected.as_bytes());
    }
    // check_cert_servername: DNS SANs if there are any, else the CN.
    if names.dns.iter().any(|d| domain_match(d, expected)) {
        return true;
    }
    if names.has_dns_san {
        return false;
    }
    names.cn.is_some_and(|cn| domain_match(&cn, expected))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn domain_match_like_openssl_c() {
        assert!(domain_match(b"kdc.example.com", "KDC.Example.COM"));
        assert!(domain_match(b"*.example.com", "kdc.example.com"));
        // A wildcard needs three labels and matches only the first.
        assert!(!domain_match(b"*.com", "example.com"));
        assert!(!domain_match(b"kdc.*.com", "kdc.example.com"));
        assert!(!domain_match(b"*.example.com", "a.b.example.com"));
        assert!(!domain_match(b"k*.example.com", "kdc.example.com"));
        assert!(!domain_match(b"example.com", "kdc.example.com"));
        assert!(!domain_match(b"kdc.example.com", "example.com"));
    }

    #[test]
    fn response_length_checked() {
        let pm = |km: Vec<u8>| {
            let mut r = b"HTTP/1.0 200 OK\r\n\r\n".to_vec();
            r.extend(
                rasn::der::encode(&KdcProxyMessage {
                    kerb_message: km.into(),
                    target_domain: None,
                    dclocator_hint: None,
                })
                .unwrap(),
            );
            r
        };
        assert_eq!(
            parse_response(&pm(vec![0, 0, 0, 2, 9, 9])),
            Some(vec![9, 9])
        );
        assert_eq!(parse_response(&pm(vec![0, 0, 0, 3, 9, 9])), None);
        assert_eq!(parse_response(&pm(vec![0, 0])), None);
        assert_eq!(parse_response(b"HTTP/1.0 200 OK\r\n"), None);
    }
}
