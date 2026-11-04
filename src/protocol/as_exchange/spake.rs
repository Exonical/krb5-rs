//! SPAKE client (MIT `plugins/preauth/spake/spake_client.c`).

use super::AsExchange;
use crate::crypto::find_etype;
use crate::protocol::preauth::PreauthHint;
use crate::spake::{
    derive_key, derive_wbytes, update_thash, Group, PaSpake, SpakeChallenge, SpakeFactor,
    SpakeResponse, SpakeSupport, KEYUSAGE_SPAKE, PA_SPAKE, SF_NONE,
};
use crate::types::{EncryptedData, EncryptionKey, PaData};
use crate::Krb5Error;

/// Per-request SPAKE state (`reqstate` in spake_client.c).
#[derive(Default)]
pub(super) struct SpakeClientState {
    /// DER of the PA-SPAKE support message we sent, for the transcript.
    support: Option<Vec<u8>>,
    /// K'[0], set as the AS key once a challenge is answered.
    as_key: Option<EncryptionKey>,
}

impl SpakeClientState {
    pub(super) fn as_key(&self) -> Option<&EncryptionKey> {
        self.as_key.as_ref()
    }
}

fn pa_spake(msg: &PaSpake) -> Result<PaData, Krb5Error> {
    Ok(PaData {
        padata_type: PA_SPAKE,
        padata_value: rasn::der::encode(msg)?.into(),
    })
}

impl AsExchange {
    /// `spake_process`: the padata to send, or `None` when SPAKE cannot
    /// answer this method data and the next mechanism should be tried.
    pub(super) fn spake_process(
        &mut self,
        value: &[u8],
        body_der: &[u8],
        hint: &PreauthHint,
    ) -> Result<Option<PaData>, Krb5Error> {
        if value.is_empty() {
            // An empty PA-SPAKE hint asks for our supported groups.
            return self.spake_send_support();
        }
        match rasn::der::decode::<PaSpake>(value) {
            Ok(PaSpake::Challenge(c)) => self.spake_process_challenge(&c, value, body_der, hint),
            // process_encdata: no second factor is implemented (OP_NOTSUPP).
            _ => Ok(None),
        }
    }

    /// `send_support`.
    fn spake_send_support(&mut self) -> Result<Option<PaData>, Krb5Error> {
        if self.config.spake_groups.is_empty() {
            return Ok(None);
        }
        let msg = PaSpake::Support(SpakeSupport {
            groups: self.config.spake_groups.iter().map(|g| g.id()).collect(),
        });
        let pa = pa_spake(&msg)?;
        self.spake.support = Some(pa.padata_value.as_ref().to_vec());
        Ok(Some(pa))
    }

    /// `process_challenge`.
    fn spake_process_challenge(
        &mut self,
        ch: &SpakeChallenge,
        der_msg: &[u8],
        body_der: &[u8],
        hint: &PreauthHint,
    ) -> Result<Option<PaData>, Krb5Error> {
        // A second challenge after we already set the AS key is unexpected.
        if self.spake.as_key.is_some() {
            return Ok(None);
        }
        let group = Group::from_id(ch.group).filter(|g| self.config.spake_groups.contains(g));
        let Some(group) = group else {
            // Unsupported group: tell the KDC which groups we support, once.
            if self.spake.support.is_none() {
                return self.spake_send_support();
            }
            return Ok(None);
        };
        if !ch.factors.iter().any(|f| f.factor_type == SF_NONE) {
            return Ok(None);
        }
        let mut thash = Vec::new();
        let support = self.spake.support.clone().unwrap_or_default();
        update_thash(group, &mut thash, &support, der_msg);

        let salt = hint.salt.clone().unwrap_or_else(|| self.default_salt());
        let ikey = self.long_term_key(hint.etype, &salt, hint.s2kparams.as_deref())?;
        let crypto = |e: crate::crypto::CryptoError| Krb5Error::Crypto(e.to_string());
        let wbytes = derive_wbytes(group, &ikey).map_err(crypto)?;
        let (private, public) = group
            .keygen(&wbytes, false)
            .map_err(|_| Krb5Error::Crypto("SPAKE keygen".into()))?;
        let Ok(result) = group.result(&wbytes, &private, ch.pubkey.as_ref(), false) else {
            return Ok(None);
        };
        update_thash(group, &mut thash, &public, &[]);

        let k0 = derive_key(group, &ikey, &wbytes, &result, &thash, body_der, 0).map_err(crypto)?;
        let k1 = derive_key(group, &ikey, &wbytes, &result, &thash, body_der, 1).map_err(crypto)?;
        let factor = rasn::der::encode(&SpakeFactor {
            factor_type: SF_NONE,
            data: None,
        })?;
        let cipher = find_etype(k1.keytype)
            .map_err(|_| Krb5Error::UnsupportedEtype(k1.keytype))?
            .encrypt(k1.key_bytes(), KEYUSAGE_SPAKE, &factor)
            .map_err(crypto)?;
        self.spake.as_key = Some(k0);
        let msg = PaSpake::Response(SpakeResponse {
            pubkey: public.into(),
            factor: EncryptedData {
                etype: k1.keytype,
                kvno: None,
                cipher: cipher.into(),
            },
        });
        pa_spake(&msg).map(Some)
    }
}
