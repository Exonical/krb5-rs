//! Encrypted PA-FX-COOKIE state (MIT `kdc/fast_util.c`
//! `kdc_fast_read_cookie` / `kdc_fast_set_cookie` / `kdc_fast_make_cookie`).

use rasn::prelude::*;

use super::db::{KvnoSel, PrincipalEntry};
use super::error::KdcError;
use crate::crypto::{derive_prfplus, find_etype};
use crate::types::{EncryptionKey, PaData, PaDataType};

/// `KRB5KDC_ERR_PREAUTH_EXPIRED`.
const KDC_ERR_PREAUTH_EXPIRED: i32 = 90;
/// `KRB5_KEYUSAGE_PA_FX_COOKIE`.
const KEYUSAGE_PA_FX_COOKIE: i32 = 513;
/// `COOKIE_LIFETIME` (fast_util.c).
const COOKIE_LIFETIME: i64 = 600;

/// `krb5_secure_cookie`.
#[derive(AsnType, Encode, Decode, Debug, Clone)]
struct SecureCookie {
    #[rasn(tag(explicit(context, 0)))]
    time: i32,
    #[rasn(tag(explicit(context, 1)))]
    data: SequenceOf<PaData>,
}

/// Cookie values read from the request and set for the reply.
#[derive(Default)]
pub(crate) struct CookieState {
    input: Vec<PaData>,
    output: Vec<PaData>,
}

/// `derive_cookie_key`: PRF+(TGT key, "COOKIE" || client principal).
fn derive_cookie_key(tgt_key: &EncryptionKey, client: &[u8]) -> Result<EncryptionKey, KdcError> {
    let mut input = b"COOKIE".to_vec();
    input.extend_from_slice(client);
    derive_prfplus(tgt_key, &input, 0).map_err(|_| KdcError::generic("COOKIE_KEY"))
}

impl CookieState {
    /// `kdc_fast_read_cookie`. `client` is the unparsed request client.
    pub(crate) fn read(
        padata: Option<&[PaData]>,
        local_tgt: &PrincipalEntry,
        client: &[u8],
        now: i64,
    ) -> Result<Self, KdcError> {
        let mut state = Self::default();
        let Some(pa) = padata
            .into_iter()
            .flatten()
            .find(|p| p.padata_type == PaDataType::FxCookie as i32)
        else {
            return Ok(state);
        };
        // Not an MIT version 1 cookie: the "MIT" cookie, or another KDC's.
        let v = pa.padata_value.as_ref();
        if v.len() <= 8 || &v[..4] != b"MIT1" {
            return Ok(state);
        }
        let kvno = u32::from_be_bytes([v[4], v[5], v[6], v[7]]);
        let Some(tgt_key) = local_tgt.find_key(None, KvnoSel::Exact(kvno), &|_| true) else {
            return Ok(state);
        };
        let key = derive_cookie_key(&tgt_key.key, client)?;
        let Ok(profile) = find_etype(key.keytype) else {
            return Ok(state);
        };
        let Ok(plain) = profile.decrypt(key.key_bytes(), KEYUSAGE_PA_FX_COOKIE, &v[8..]) else {
            return Ok(state);
        };
        let Ok(cookie) = rasn::der::decode::<SecureCookie>(&plain) else {
            return Ok(state);
        };
        if now > i64::from(cookie.time) + COOKIE_LIFETIME {
            // Only an error if the cookie is relevant to the request.
            let relevant = cookie.data.iter().any(|c| {
                padata
                    .into_iter()
                    .flatten()
                    .any(|r| r.padata_type == c.padata_type)
            });
            if relevant {
                return Err(KdcError::new(KDC_ERR_PREAUTH_EXPIRED, "PREAUTH_EXPIRED"));
            }
            return Ok(state);
        }
        state.input = cookie.data;
        Ok(state)
    }

    /// `kdc_fast_search_cookie`.
    pub(crate) fn get(&self, pa_type: i32) -> Option<&[u8]> {
        self.input
            .iter()
            .find(|p| p.padata_type == pa_type)
            .map(|p| p.padata_value.as_ref())
    }

    /// `kdc_fast_set_cookie`: the first value set for a type wins.
    pub(crate) fn set(&mut self, pa_type: i32, data: Vec<u8>) {
        if self.output.iter().all(|p| p.padata_type != pa_type) {
            self.output.push(PaData {
                padata_type: pa_type,
                padata_value: data.into(),
            });
        }
    }

    /// `kdc_fast_make_cookie`: the trivial "MIT" cookie without values,
    /// else "MIT1" || kvno || encrypted secure cookie.
    pub(crate) fn make(
        &self,
        local_tgt: &PrincipalEntry,
        client: &[u8],
        now: i64,
    ) -> Result<PaData, KdcError> {
        let tgt_key = local_tgt.find_key(None, KvnoSel::Highest, &|_| true);
        let (Some(tgt_key), false) = (tgt_key, self.output.is_empty()) else {
            return Ok(PaData {
                padata_type: PaDataType::FxCookie as i32,
                padata_value: b"MIT".to_vec().into(),
            });
        };
        let key = derive_cookie_key(&tgt_key.key, client)?;
        let der = rasn::der::encode(&SecureCookie {
            time: i32::try_from(now).unwrap_or(i32::MAX),
            data: self.output.clone(),
        })?;
        let cipher = find_etype(key.keytype)
            .and_then(|p| p.encrypt(key.key_bytes(), KEYUSAGE_PA_FX_COOKIE, &der))
            .map_err(|_| KdcError::generic("MAKE_COOKIE"))?;
        let mut value = b"MIT1".to_vec();
        value.extend_from_slice(&tgt_key.kvno.to_be_bytes());
        value.extend_from_slice(&cipher);
        Ok(PaData {
            padata_type: PaDataType::FxCookie as i32,
            padata_value: value.into(),
        })
    }
}
