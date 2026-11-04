//! SPAKE KDC module (MIT `plugins/preauth/spake/spake_kdc.c`).

use super::cookie::CookieState;
use super::error::KdcError;
use crate::crypto::find_etype;
use crate::spake::{
    derive_key, derive_wbytes, update_thash, Group, PaSpake, SpakeChallenge, SpakeFactor,
    SpakeResponse, KEYUSAGE_SPAKE, PA_SPAKE, SF_NONE,
};
use crate::types::error_codes::*;
use crate::types::{EncryptionKey, PaData};

/// `KRB5KDC_ERR_MORE_PREAUTH_DATA_REQUIRED`.
pub(crate) const KDC_ERR_MORE_PREAUTH_DATA_REQUIRED: i32 = 91;

/// Outcome of a verified PA-SPAKE message.
pub(crate) enum SpakeOutcome {
    /// Send this challenge with `KDC_ERR_MORE_PREAUTH_DATA_REQUIRED`.
    Challenge(PaData),
    /// Preauthenticated; K'[0] strengthens the reply key.
    Verified(EncryptionKey),
}

fn failed(status: &str) -> KdcError {
    KdcError::new(KDC_ERR_PREAUTH_FAILED, status)
}

/// `make_cookie`.
fn make_cookie(stage: u16, group: i32, spake: &[u8], thash: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(16 + spake.len() + thash.len());
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&stage.to_be_bytes());
    out.extend_from_slice(&group.to_be_bytes());
    for d in [spake, thash] {
        out.extend_from_slice(&(d.len() as u32).to_be_bytes());
        out.extend_from_slice(d);
    }
    out
}

/// `parse_cookie`: stage, group, SPAKE value and transcript hash.
fn parse_cookie(c: &[u8]) -> Option<(u16, i32, &[u8], &[u8])> {
    let be16 = |b: &[u8]| u16::from_be_bytes([b[0], b[1]]);
    if c.len() < 8 || be16(c) != 1 {
        return None;
    }
    let stage = be16(&c[2..]);
    let group = i32::from_be_bytes([c[4], c[5], c[6], c[7]]);
    let mut rest = &c[8..];
    let mut take = || {
        if rest.len() < 4 {
            return None;
        }
        let n = u32::from_be_bytes([rest[0], rest[1], rest[2], rest[3]]) as usize;
        let d = rest.get(4..4 + n)?;
        rest = &rest[4 + n..];
        Some(d)
    };
    let spake = take()?;
    let thash = take()?;
    Some((stage, group, spake, thash))
}

/// `send_challenge`: a challenge for `group`, with its stage-0 state in the
/// cookie.
pub(crate) fn send_challenge(
    group: Group,
    ikey: &EncryptionKey,
    support: &[u8],
    cookies: &mut CookieState,
) -> Result<PaData, KdcError> {
    let wbytes = derive_wbytes(group, ikey).map_err(|_| failed("SPAKE_WBYTES"))?;
    let (kdcpriv, kdcpub) = group
        .keygen(&wbytes, true)
        .map_err(|_| failed("SPAKE_KEYGEN"))?;
    let msg = PaSpake::Challenge(SpakeChallenge {
        group: group.id(),
        pubkey: kdcpub.into(),
        factors: vec![SpakeFactor {
            factor_type: SF_NONE,
            data: None,
        }],
    });
    let der = rasn::der::encode(&msg)?;
    let mut thash = Vec::new();
    update_thash(group, &mut thash, support, &der);
    cookies.set(PA_SPAKE, make_cookie(0, group.id(), &kdcpriv, &thash));
    Ok(PaData {
        padata_type: PA_SPAKE,
        padata_value: der.into(),
    })
}

/// `spake_edata`: the PA-SPAKE hint, with an optimistic challenge if
/// `challenge` is set. `None` without a client key.
pub(crate) fn edata(
    challenge: Option<Group>,
    ikey: Option<&EncryptionKey>,
    cookies: &mut CookieState,
) -> Result<Option<PaData>, KdcError> {
    let Some(ikey) = ikey else { return Ok(None) };
    match challenge {
        Some(group) => send_challenge(group, ikey, &[], cookies).map(Some),
        None => Ok(Some(PaData {
            padata_type: PA_SPAKE,
            padata_value: Vec::new().into(),
        })),
    }
}

/// `spake_verify`.
pub(crate) fn verify(
    value: &[u8],
    permitted: &[Group],
    ikey: Option<&EncryptionKey>,
    body_der: &[u8],
    cookies: &mut CookieState,
) -> Result<SpakeOutcome, KdcError> {
    let msg: PaSpake = rasn::der::decode(value).map_err(|_| failed("SPAKE_DECODE"))?;
    match msg {
        PaSpake::Support(s) => {
            let group = s
                .groups
                .iter()
                .find_map(|&g| Group::from_id(g).filter(|g| permitted.contains(g)))
                .ok_or_else(|| failed("SPAKE_REJECT_SUPPORT"))?;
            let ikey = ikey.ok_or_else(|| KdcError::new(KDC_ERR_ETYPE_NOSUPP, "SPAKE_NO_KEY"))?;
            send_challenge(group, ikey, value, cookies).map(SpakeOutcome::Challenge)
        }
        PaSpake::Response(r) => verify_response(&r, permitted, ikey, body_der, cookies),
        // verify_encdata: no second factor is implemented.
        PaSpake::EncData(_) | PaSpake::Challenge(_) => Err(failed("SPAKE_UNKNOWN_MESSAGE")),
    }
}

/// `verify_response`.
fn verify_response(
    resp: &SpakeResponse,
    permitted: &[Group],
    ikey: Option<&EncryptionKey>,
    body_der: &[u8],
    cookies: &CookieState,
) -> Result<SpakeOutcome, KdcError> {
    let ikey = ikey.ok_or_else(|| KdcError::new(KDC_ERR_ETYPE_NOSUPP, "SPAKE_NO_KEY"))?;
    let cookie = cookies
        .get(PA_SPAKE)
        .ok_or_else(|| failed("SPAKE_NO_COOKIE"))?;
    let (stage, group, kdcpriv, thash_in) =
        parse_cookie(cookie).ok_or_else(|| failed("SPAKE_BAD_COOKIE"))?;
    if stage != 0 {
        return Err(failed("SPAKE_BAD_COOKIE"));
    }
    let group = Group::from_id(group)
        .filter(|g| permitted.contains(g))
        .ok_or_else(|| failed("SPAKE_BAD_COOKIE"))?;
    let mut thash = thash_in.to_vec();
    update_thash(group, &mut thash, resp.pubkey.as_ref(), &[]);
    let wbytes = derive_wbytes(group, ikey).map_err(|_| failed("SPAKE_WBYTES"))?;
    let result = group
        .result(&wbytes, kdcpriv, resp.pubkey.as_ref(), true)
        .map_err(|_| failed("SPAKE_RESULT"))?;
    let key = |n| {
        derive_key(group, ikey, &wbytes, &result, &thash, body_der, n)
            .map_err(|_| failed("SPAKE_DERIVE"))
    };
    let k1 = key(1)?;
    let plain = find_etype(k1.keytype)
        .map_err(|_| failed("SPAKE_ETYPE"))?
        .decrypt(k1.key_bytes(), KEYUSAGE_SPAKE, resp.factor.cipher.as_ref())
        .map_err(|_| failed("SPAKE_BAD_INTEGRITY"))?;
    let factor: SpakeFactor = rasn::der::decode(&plain).map_err(|_| failed("SPAKE_DECODE"))?;
    if factor.factor_type != SF_NONE {
        return Err(failed("SPAKE_FACTOR"));
    }
    Ok(SpakeOutcome::Verified(key(0)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cookie_round_trips_like_mit() {
        let c = make_cookie(0, 1, &[1, 2, 3], &[9; 32]);
        assert_eq!(&c[..8], &[0, 1, 0, 0, 0, 0, 0, 1]);
        let (stage, group, spake, thash) = parse_cookie(&c).unwrap();
        assert_eq!(
            (stage, group, spake, thash),
            (0, 1, &[1u8, 2, 3][..], &[9u8; 32][..])
        );
        assert!(parse_cookie(&c[..c.len() - 1]).is_none());
        let mut v2 = c.clone();
        v2[1] = 2;
        assert!(parse_cookie(&v2).is_none());
    }
}
