//! python-kdcproxy's `kdcproxy/codec.py`: the KDC-PROXY-MESSAGE (MS-KKDCP
//! 2.2.2) carrying a TCP-framed AS-REQ, TGS-REQ or kpasswd request.

use krb5_rs::types::{ApReq, AsReq, KdcProxyMessage, KrbPriv, TgsReq};

/// What the proxied message is (`TGSProxyRequest`, `ASProxyRequest`,
/// `KPASSWDProxyRequest`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Tgs,
    As,
    Kpasswd(u16),
}

/// A decoded proxy request.
#[derive(Debug)]
pub struct Request {
    /// `target-domain`.
    pub realm: Option<String>,
    /// `kerb-message`: the request with its 4-byte length.
    pub message: Vec<u8>,
    pub kind: Kind,
}

impl std::fmt::Display for Request {
    /// `ProxyRequest.__str__`.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let realm = self.realm.as_deref().unwrap_or("None");
        let n = self.message.len() - 4;
        match self.kind {
            Kind::Tgs => write!(f, "{realm} TGS-REQ ({n} bytes)"),
            Kind::As => write!(f, "{realm} AS-REQ ({n} bytes)"),
            Kind::Kpasswd(v) => write!(f, "{realm} KPASSWD-REQ ({n} bytes) (version 0x{v:04x})"),
        }
    }
}

/// `ProxyRequest.parse`; the error is the 400 response body.
pub fn decode(data: &[u8]) -> Result<Request, &'static str> {
    let pm: KdcProxyMessage = rasn::ber::decode(data).map_err(|_| "Invalid request.")?;
    if rasn::der::encode(&pm).map_or(true, |e| e.len() != data.len()) {
        return Err("Invalid request.");
    }
    let realm = pm
        .target_domain
        .as_ref()
        .map(|r| String::from_utf8(r.as_bytes().to_vec()).map_err(|_| "Invalid request."))
        .transpose()?;
    let message: Vec<u8> = pm.kerb_message.to_vec();
    if message.len() < 4
        || u32::from_be_bytes([message[0], message[1], message[2], message[3]]) as usize
            != message.len() - 4
    {
        return Err("Invalid request length.");
    }
    let body = &message[4..];
    let kind = if rasn::ber::decode::<TgsReq>(body).is_ok() {
        Kind::Tgs
    } else if rasn::ber::decode::<AsReq>(body).is_ok() {
        Kind::As
    } else if let Some(v) = kpasswd_version(&message) {
        Kind::Kpasswd(v)
    } else {
        return Err("Invalid request.");
    };
    Ok(Request {
        realm,
        message,
        kind,
    })
}

/// `KPASSWDProxyRequest.parse_request`: RFC 3244 framing around an AP-REQ
/// and a KRB-PRIV.
fn kpasswd_version(request: &[u8]) -> Option<u16> {
    let u16_at = |i: usize| Some(u16::from_be_bytes([*request.get(i)?, *request.get(i + 1)?]));
    if usize::from(u16_at(4)?) != request.len() - 4 {
        return None;
    }
    let version = u16_at(6)?;
    if version != 0x0001 && version != 0xff80 {
        return None;
    }
    let ap_len = usize::from(u16_at(8)?);
    if ap_len > request.len() - 10 {
        return None;
    }
    rasn::ber::decode::<ApReq>(&request[10..10 + ap_len]).ok()?;
    rasn::ber::decode::<KrbPriv>(&request[10 + ap_len..]).ok()?;
    Some(version)
}

/// `encode`: the KDC's reply, given without its length, as a
/// KDC-PROXY-MESSAGE holding the TCP-framed reply.
pub fn encode(reply: &[u8]) -> Vec<u8> {
    let mut framed = u32::try_from(reply.len())
        .unwrap_or(u32::MAX)
        .to_be_bytes()
        .to_vec();
    framed.extend_from_slice(reply);
    let pm = KdcProxyMessage {
        kerb_message: framed.into(),
        target_domain: None,
        dclocator_hint: None,
    };
    rasn::der::encode(&pm).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wrap(message: &[u8], realm: Option<&str>) -> Vec<u8> {
        let mut km = (message.len() as u32).to_be_bytes().to_vec();
        km.extend_from_slice(message);
        rasn::der::encode(&KdcProxyMessage {
            kerb_message: km.into(),
            target_domain: realm
                .map(|r| rasn::types::GeneralString::from_bytes(r.as_bytes()).unwrap()),
            dclocator_hint: None,
        })
        .unwrap()
    }

    #[test]
    fn rejects() {
        assert_eq!(decode(b"junk").unwrap_err(), "Invalid request.");
        assert_eq!(
            decode(&wrap(b"not kerberos", Some("R"))).unwrap_err(),
            "Invalid request."
        );
        let mut bad = wrap(b"", Some("R"));
        bad.push(0);
        assert_eq!(decode(&bad).unwrap_err(), "Invalid request.");
        let pm = KdcProxyMessage {
            kerb_message: vec![0, 0, 0, 9, 1].into(),
            target_domain: None,
            dclocator_hint: None,
        };
        assert_eq!(
            decode(&rasn::der::encode(&pm).unwrap()).unwrap_err(),
            "Invalid request length."
        );
    }

    #[test]
    fn reply_round_trip() {
        let out = encode(b"reply");
        let pm: KdcProxyMessage = rasn::der::decode(&out).unwrap();
        assert_eq!(pm.kerb_message.as_ref(), b"\0\0\0\x05reply");
        assert!(pm.target_domain.is_none());
    }
}
