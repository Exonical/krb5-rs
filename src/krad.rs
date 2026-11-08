//! RADIUS client (RFC 2865, RFC 2869 Message-Authenticator), as MIT's
//! `lib/krad` for the OTP KDC module.

use hmac::{Hmac, KeyInit, Mac};
use md5::{Digest, Md5};
use std::io;
use std::time::Duration;
#[cfg(unix)]
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Packet codes (`KRAD_CODE_*`).
pub mod code {
    /// Access-Request.
    pub const ACCESS_REQUEST: u8 = 1;
    /// Access-Accept.
    pub const ACCESS_ACCEPT: u8 = 2;
    /// Access-Reject.
    pub const ACCESS_REJECT: u8 = 3;
    /// Access-Challenge.
    pub const ACCESS_CHALLENGE: u8 = 11;
}

/// Attribute types (`KRAD_ATTR_*`).
pub mod attr {
    /// User-Name.
    pub const USER_NAME: u8 = 1;
    /// User-Password.
    pub const USER_PASSWORD: u8 = 2;
    /// Service-Type.
    pub const SERVICE_TYPE: u8 = 6;
    /// NAS-Identifier.
    pub const NAS_IDENTIFIER: u8 = 32;
    /// Message-Authenticator.
    pub const MESSAGE_AUTHENTICATOR: u8 = 80;
}

/// `KRAD_SERVICE_TYPE_AUTHENTICATE_ONLY`.
pub const SERVICE_TYPE_AUTHENTICATE_ONLY: u32 = 8;
/// `KRAD_PACKET_SIZE_MAX`.
pub const PACKET_SIZE_MAX: usize = 4096;
/// The default RADIUS port (the `radius` service).
pub const DEFAULT_PORT: u16 = 1812;

const OFFSET_AUTH: usize = 4;
const OFFSET_ATTR: usize = 20;
const BLOCKSIZE: usize = 16;
const MAX_PASSWORD: usize = 128;

/// A RADIUS packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet {
    /// Code.
    pub code: u8,
    /// Identifier.
    pub id: u8,
    /// Authenticator.
    pub auth: [u8; 16],
    /// Attributes in order, User-Password decoded where the authenticator
    /// was known.
    pub attrs: Vec<(u8, Vec<u8>)>,
    /// The encoded packet.
    pub raw: Vec<u8>,
}

impl Packet {
    /// The `n`th value of attribute `t`.
    pub fn attr(&self, t: u8, n: usize) -> Option<&[u8]> {
        self.attrs
            .iter()
            .filter(|(k, _)| *k == t)
            .nth(n)
            .map(|(_, v)| v.as_slice())
    }
}

fn md5(parts: &[&[u8]]) -> [u8; 16] {
    let mut h = Md5::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

/// `user_password_encode` (attr.c:146-196).
fn password_encode(secret: &[u8], auth: &[u8; 16], pw: &[u8]) -> io::Result<Vec<u8>> {
    let len = pw.len().div_ceil(BLOCKSIZE).max(1) * BLOCKSIZE;
    if len > MAX_PASSWORD {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "RADIUS data too long",
        ));
    }
    let mut out = vec![0u8; len];
    out[..pw.len()].copy_from_slice(pw);
    let mut prev: [u8; 16] = *auth;
    for blk in out.chunks_mut(BLOCKSIZE) {
        let sum = md5(&[secret, &prev]);
        blk.iter_mut().zip(sum).for_each(|(b, s)| *b ^= s);
        prev.copy_from_slice(blk);
    }
    Ok(out)
}

/// `user_password_decode` (attr.c:198-250).
fn password_decode(secret: &[u8], auth: &[u8; 16], enc: &[u8]) -> Option<Vec<u8>> {
    if !enc.len().is_multiple_of(BLOCKSIZE) || enc.len() > MAX_PASSWORD {
        return None;
    }
    let mut out = Vec::with_capacity(enc.len());
    let mut prev: &[u8] = auth;
    for blk in enc.chunks(BLOCKSIZE) {
        let sum = md5(&[secret, prev]);
        out.extend(blk.iter().zip(sum).map(|(b, s)| b ^ s));
        prev = blk;
    }
    while out.last() == Some(&0) {
        out.pop();
    }
    Some(out)
}

fn bad(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.to_string())
}

/// `calculate_mac` (packet.c:278-320): HMAC-MD5 over the packet with
/// `auth` in the authenticator field and Message-Authenticator zeroed.
fn calculate_mac(secret: &[u8], raw: &[u8], auth: &[u8; 16]) -> Option<[u8; 16]> {
    let at = msgauth_offset(raw)?;
    let mut m = <Hmac<Md5> as KeyInit>::new_from_slice(secret).ok()?;
    m.update(&raw[..OFFSET_AUTH]);
    m.update(auth);
    m.update(&raw[OFFSET_ATTR..at]);
    m.update(&[attr::MESSAGE_AUTHENTICATOR, 18]);
    m.update(&[0u8; 16]);
    m.update(&raw[at + 18..]);
    Some(m.finalize().into_bytes().into())
}

/// `lookup_msgauth_addr` (packet.c:256-272).
fn msgauth_offset(raw: &[u8]) -> Option<usize> {
    let mut i = OFFSET_ATTR;
    while i + 2 < raw.len() {
        if raw[i] == attr::MESSAGE_AUTHENTICATOR {
            return (raw[i + 1] == 18 && i + 18 <= raw.len()).then_some(i);
        }
        let l = usize::from(raw[i + 1]);
        if l < 2 {
            return None;
        }
        i += l;
    }
    None
}

/// `kr_attrset_encode` plus the header: Message-Authenticator first when
/// requested, User-Password hidden with `auth`.
fn encode(
    secret: &[u8],
    code: u8,
    id: u8,
    auth: &[u8; 16],
    attrs: &[(u8, Vec<u8>)],
    msgauth: bool,
) -> io::Result<Vec<u8>> {
    let mut raw = vec![code, id, 0, 0];
    raw.extend_from_slice(auth);
    if msgauth {
        raw.extend_from_slice(&[attr::MESSAGE_AUTHENTICATOR, 18]);
        raw.extend_from_slice(&[0u8; 16]);
    }
    for (t, v) in attrs {
        let v = if *t == attr::USER_PASSWORD {
            password_encode(secret, auth, v)?
        } else {
            v.clone()
        };
        if v.is_empty() || v.len() > 253 {
            return Err(bad("RADIUS attribute length"));
        }
        raw.push(*t);
        raw.push(u8::try_from(v.len() + 2).map_err(|_| bad("RADIUS attribute length"))?);
        raw.extend_from_slice(&v);
    }
    if raw.len() > PACKET_SIZE_MAX {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "RADIUS data too long",
        ));
    }
    let len = u16::try_from(raw.len()).map_err(|_| bad("RADIUS packet length"))?;
    raw[2..4].copy_from_slice(&len.to_be_bytes());
    Ok(raw)
}

fn set_mac(secret: &[u8], raw: &mut [u8], auth: &[u8; 16]) -> io::Result<()> {
    let mac = calculate_mac(secret, raw, auth).ok_or_else(|| bad("Message-Authenticator"))?;
    let at = msgauth_offset(raw).ok_or_else(|| bad("Message-Authenticator"))?;
    raw[at + 2..at + 18].copy_from_slice(&mac);
    Ok(())
}

/// `krad_packet_new_request` (packet.c:346-408). The authenticator is the
/// low 32 bits of the time in host order then random bytes, as MIT's.
pub fn new_request(secret: &str, code: u8, id: u8, attrs: &[(u8, Vec<u8>)]) -> io::Result<Packet> {
    let mut auth = [0u8; 16];
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as u32)
        .unwrap_or(0);
    auth[..4].copy_from_slice(&now.to_ne_bytes());
    auth[4..].iter_mut().for_each(|b| *b = rand::random());
    let msgauth = !secret.is_empty() && code == code::ACCESS_REQUEST;
    let s = secret.as_bytes();
    let mut raw = encode(s, code, id, &auth, attrs, msgauth)?;
    if msgauth {
        set_mac(s, &mut raw, &auth)?;
    }
    decode(s, &raw, Some(&auth))
}

/// `requires_msgauth` (packet.c:228-243).
fn requires_msgauth(secret: &str, code: u8) -> bool {
    !secret.is_empty()
        && matches!(
            code,
            code::ACCESS_REQUEST
                | code::ACCESS_ACCEPT
                | code::ACCESS_REJECT
                | code::ACCESS_CHALLENGE
        )
}

/// `krad_packet_new_response` (packet.c:410-470), for RADIUS servers.
pub fn new_response(
    secret: &str,
    code: u8,
    attrs: &[(u8, Vec<u8>)],
    request: &Packet,
) -> io::Result<Packet> {
    let s = secret.as_bytes();
    let msgauth = requires_msgauth(secret, code);
    let mut raw = encode(s, code, request.id, &request.auth, attrs, msgauth)?;
    // RFC 3579 3.2: the Message-Authenticator (keyed over the request
    // authenticator) is in place before the Response Authenticator.
    if msgauth {
        set_mac(s, &mut raw, &request.auth)?;
    }
    let rauth = md5(&[&raw, s]);
    raw[OFFSET_AUTH..OFFSET_ATTR].copy_from_slice(&rauth);
    decode(s, &raw, Some(&request.auth))
}

/// `decode_packet` (packet.c:498-539): User-Password is decoded with
/// `pw_auth` when given.
fn decode(secret: &[u8], buf: &[u8], pw_auth: Option<&[u8; 16]>) -> io::Result<Packet> {
    if buf.len() < OFFSET_ATTR {
        return Err(bad("short RADIUS packet"));
    }
    let len = usize::from(u16::from_be_bytes([buf[2], buf[3]]));
    if len < OFFSET_ATTR || len > buf.len() || len > PACKET_SIZE_MAX {
        return Err(bad("bad RADIUS packet length"));
    }
    let raw = buf[..len].to_vec();
    let mut auth = [0u8; 16];
    auth.copy_from_slice(&raw[OFFSET_AUTH..OFFSET_ATTR]);
    let mut attrs = Vec::new();
    let mut i = OFFSET_ATTR;
    while i < len {
        if i + 2 > len {
            return Err(bad("bad RADIUS attribute"));
        }
        let l = usize::from(raw[i + 1]);
        if l < 3 || i + l > len {
            return Err(bad("bad RADIUS attribute"));
        }
        let t = raw[i];
        let mut v = raw[i + 2..i + l].to_vec();
        if t == attr::USER_PASSWORD {
            if let Some(a) = pw_auth {
                v = password_decode(secret, a, &v).ok_or_else(|| bad("bad User-Password"))?;
            }
        }
        attrs.push((t, v));
        i += l;
    }
    Ok(Packet {
        code: raw[0],
        id: raw[1],
        auth,
        attrs,
        raw,
    })
}

fn verify_msgauth(secret: &[u8], pkt: &Packet, auth: &[u8; 16]) -> bool {
    match (
        pkt.attr(attr::MESSAGE_AUTHENTICATOR, 0),
        calculate_mac(secret, &pkt.raw, auth),
    ) {
        (Some(got), Some(mac)) => got.len() == 16 && constant_eq(got, &mac),
        _ => false,
    }
}

fn constant_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// `krad_packet_decode_request` (packet.c:541-577), for RADIUS servers: a
/// Message-Authenticator, when present, must verify.
pub fn decode_request(secret: &str, buf: &[u8]) -> io::Result<Packet> {
    let s = secret.as_bytes();
    let first = decode(s, buf, None)?;
    let pkt = decode(s, buf, Some(&first.auth))?;
    if pkt.attr(attr::MESSAGE_AUTHENTICATOR, 0).is_some() && !verify_msgauth(s, &pkt, &pkt.auth) {
        return Err(bad("bad Message-Authenticator"));
    }
    Ok(pkt)
}

/// `krad_packet_decode_response` (packet.c:579-622): a response to
/// `request` must carry its id and the right Response Authenticator, and a
/// Message-Authenticator, when present, must verify. Anything else is
/// `None` and ignored, as MIT keeps waiting.
pub fn decode_response(secret: &str, request: &Packet, buf: &[u8]) -> Option<Packet> {
    let s = secret.as_bytes();
    let pkt = decode(s, buf, None).ok()?;
    if pkt.id != request.id {
        return None;
    }
    let mut tmp = pkt.raw.clone();
    tmp[OFFSET_AUTH..OFFSET_ATTR].copy_from_slice(&request.auth);
    if !constant_eq(&md5(&[&tmp, s]), &pkt.auth) {
        return None;
    }
    if pkt.attr(attr::MESSAGE_AUTHENTICATOR, 0).is_some() && !verify_msgauth(s, &pkt, &request.auth)
    {
        return None;
    }
    Some(pkt)
}

/// `krad_packet_bytes_needed` (packet.c:322-335) for stream framing.
#[cfg(unix)]
fn bytes_needed(buf: &[u8]) -> io::Result<usize> {
    if buf.len() < OFFSET_AUTH {
        return Ok(OFFSET_AUTH - buf.len());
    }
    let len = usize::from(u16::from_be_bytes([buf[2], buf[3]]));
    if !(OFFSET_ATTR..=PACKET_SIZE_MAX).contains(&len) {
        return Err(bad("bad RADIUS packet length"));
    }
    Ok(len.saturating_sub(buf.len()))
}

/// `resolve_remote` (client.c:244-276): `host[:port]` or `[v6][:port]`,
/// port defaulting to the `radius` service.
fn split_remote(remote: &str) -> (String, String) {
    let svc = DEFAULT_PORT.to_string();
    if let Some(rest) = remote.strip_prefix('[') {
        if let Some(end) = rest.rfind(']') {
            let host = rest[..end].to_string();
            let port = rest[end + 1..].strip_prefix(':').map(str::to_string);
            return (host, port.unwrap_or(svc));
        }
        return (remote.to_string(), svc);
    }
    match remote.rsplit_once(':') {
        Some((h, p)) if !p.is_empty() => (h.to_string(), p.to_string()),
        Some((h, _)) => (h.to_string(), svc),
        None => (remote.to_string(), svc),
    }
}

fn timed_out() -> io::Error {
    io::Error::from(io::ErrorKind::TimedOut)
}

/// `krad_client_send` (client.c:278-321, remote.c): send an Access-Request
/// built from `attrs` to `remote` and return the verified response. A
/// remote starting with `/` is a Unix stream socket with no retries;
/// anything else is UDP to each resolved address in turn, each tried
/// `retries + 1` times within `timeout / (retries + 1)`.
pub async fn send(
    remote: &str,
    secret: &str,
    code: u8,
    attrs: &[(u8, Vec<u8>)],
    timeout: Duration,
    retries: usize,
) -> io::Result<Packet> {
    let req = new_request(secret, code, rand::random(), attrs)?;
    if remote.starts_with('/') {
        return send_stream(remote, secret, &req, timeout).await;
    }
    let (host, port) = split_remote(remote);
    let port: u16 = port.parse().map_err(|_| bad("bad RADIUS port"))?;
    let addrs: Vec<_> = tokio::net::lookup_host((host.as_str(), port))
        .await?
        .collect();
    let per = timeout / u32::try_from(retries + 1).unwrap_or(u32::MAX);
    let mut last = timed_out();
    for addr in addrs {
        let bind: std::net::SocketAddr = if addr.is_ipv4() {
            ([0, 0, 0, 0], 0).into()
        } else {
            (std::net::Ipv6Addr::UNSPECIFIED, 0).into()
        };
        let sock = match tokio::net::UdpSocket::bind(bind).await {
            Ok(s) => s,
            Err(e) => {
                last = e;
                continue;
            }
        };
        if let Err(e) = sock.connect(addr).await {
            last = e;
            continue;
        }
        for _ in 0..=retries {
            if let Err(e) = sock.send(&req.raw).await {
                last = e;
                break;
            }
            let wait = async {
                let mut buf = vec![0u8; PACKET_SIZE_MAX];
                loop {
                    let n = sock.recv(&mut buf).await?;
                    if let Some(p) = decode_response(secret, &req, &buf[..n]) {
                        return Ok::<_, io::Error>(p);
                    }
                }
            };
            match tokio::time::timeout(per, wait).await {
                Ok(Ok(p)) => return Ok(p),
                Ok(Err(e)) => {
                    last = e;
                    break;
                }
                Err(_) => last = timed_out(),
            }
        }
    }
    Err(last)
}

#[cfg(unix)]
async fn send_stream(
    path: &str,
    secret: &str,
    req: &Packet,
    timeout: Duration,
) -> io::Result<Packet> {
    let run = async {
        let mut s = tokio::net::UnixStream::connect(path).await?;
        s.write_all(&req.raw).await?;
        loop {
            let mut buf = Vec::new();
            loop {
                let need = bytes_needed(&buf)?;
                if need == 0 {
                    break;
                }
                let at = buf.len();
                buf.resize(at + need, 0);
                s.read_exact(&mut buf[at..]).await?;
            }
            if let Some(p) = decode_response(secret, req, &buf) {
                return Ok(p);
            }
        }
    };
    tokio::time::timeout(timeout, run)
        .await
        .map_err(|_| timed_out())?
}

#[cfg(not(unix))]
async fn send_stream(_: &str, _: &str, _: &Packet, _: Duration) -> io::Result<Packet> {
    Err(io::Error::from(io::ErrorKind::Unsupported))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn password_round_trip_and_rfc2865_length() {
        let auth = [7u8; 16];
        for pw in [&b"a"[..], &[b'x'; 16], &[b'y'; 17], &[b'z'; 128]] {
            let enc = password_encode(b"s3cret", &auth, pw).unwrap();
            assert_eq!(enc.len() % 16, 0);
            assert_eq!(password_decode(b"s3cret", &auth, &enc).unwrap(), pw);
        }
        assert!(password_encode(b"s", &auth, &[1; 129]).is_err());
    }

    #[test]
    fn request_and_response_verify() {
        let attrs = vec![
            (attr::USER_NAME, b"user".to_vec()),
            (attr::USER_PASSWORD, b"otp123".to_vec()),
        ];
        let req = new_request("foo", code::ACCESS_REQUEST, 9, &attrs).unwrap();
        assert_eq!(req.attrs[0].0, attr::MESSAGE_AUTHENTICATOR);
        let got = decode_request("foo", &req.raw).unwrap();
        assert_eq!(got.attr(attr::USER_PASSWORD, 0), Some(&b"otp123"[..]));
        assert!(decode_request("bar", &req.raw).is_err());
        let rsp = new_response("foo", code::ACCESS_ACCEPT, &[], &got).unwrap();
        assert!(rsp.attr(attr::MESSAGE_AUTHENTICATOR, 0).is_some());
        assert_eq!(
            decode_response("foo", &req, &rsp.raw).unwrap().code,
            code::ACCESS_ACCEPT
        );
        assert!(decode_response("bar", &req, &rsp.raw).is_none());
        let mut forged = rsp.raw.clone();
        forged[0] = code::ACCESS_REJECT;
        assert!(decode_response("foo", &req, &forged).is_none());
    }

    #[test]
    fn unix_transport_has_no_message_authenticator() {
        let req = new_request(
            "",
            code::ACCESS_REQUEST,
            1,
            &[(attr::USER_NAME, b"u".to_vec())],
        )
        .unwrap();
        assert!(req.attr(attr::MESSAGE_AUTHENTICATOR, 0).is_none());
    }

    #[test]
    fn remotes_split_like_mit() {
        assert_eq!(split_remote("h:99"), ("h".into(), "99".into()));
        assert_eq!(split_remote("h"), ("h".into(), "1812".into()));
        assert_eq!(split_remote("[::1]:7"), ("::1".into(), "7".into()));
        assert_eq!(split_remote("[::1]"), ("::1".into(), "1812".into()));
    }
}
