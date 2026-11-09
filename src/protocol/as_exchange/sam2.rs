//! SAM-2 pre-authentication, client side (MIT `lib/krb5/krb/preauth_sam2.c`).

use rasn::types::OctetString;

use super::AsExchange;
use crate::crypto::{find_etype, CryptoError};
use crate::sam2::{
    challenge_banner, opt, EncSamResponseEnc2, Sam2Prompt, SamChallenge2, SamChallenge2Body,
    SamFlags, SamResponse2, AP_ERR_BAD_INTEGRITY, KEYUSAGE_CHALLENGE_CKSUM, KEYUSAGE_RESPONSE,
    LIBOS_CANTREADPWD, PA_SAM_RESPONSE_2, SAM_INVALID_ETYPE, SAM_NO_CHECKSUM, SAM_UNSUPPORTED,
};
use crate::types::{EncryptedData, EncryptionKey, PaData};
use crate::Krb5Error;

/// Checksum types `krb5_c_is_keyed_cksum` reports as unkeyed: CRC32,
/// RSA-MD4, RSA-MD5, NIST-SHA and SHA-1.
const UNKEYED: [i32; 5] = [1, 2, 7, 9, 14];

/// `SAMDATA`: the field (at most `max` bytes) or the default.
fn samdata(field: &Option<OctetString>, default: &str, max: usize) -> String {
    match field.as_deref().filter(|f| !f.is_empty()) {
        Some(f) => String::from_utf8_lossy(&f[..f.len().min(max)]).into_owned(),
        None => default.chars().take(max).collect(),
    }
}

fn cant_read() -> Krb5Error {
    Krb5Error::Mit(LIBOS_CANTREADPWD, "Cannot read password")
}

fn unsupported() -> Krb5Error {
    Krb5Error::Mit(SAM_UNSUPPORTED, "Bad SAM flags in obtain_sam_padata")
}

fn crypto(e: CryptoError) -> Krb5Error {
    Krb5Error::Crypto(e.to_string())
}

impl AsExchange {
    /// `sam2_process`: answer a PA-SAM-CHALLENGE-2 with a PA-SAM-RESPONSE-2.
    pub(super) fn sam2_process(&mut self, value: &[u8]) -> Result<PaData, Krb5Error> {
        let responder = self.config.sam2.clone().ok_or_else(cant_read)?;
        let sc2: SamChallenge2 = rasn::der::decode(value)?;
        let body: SamChallenge2Body = rasn::der::decode(sc2.body.as_bytes())?;
        if sc2.cksum.is_empty() {
            return Err(Krb5Error::Mit(
                SAM_NO_CHECKSUM,
                "Missing checksum in SAM challenge",
            ));
        }
        let flags = *body.flags;
        if flags.contains(SamFlags::MUST_PK_ENCRYPT_SAD) {
            return Err(unsupported());
        }
        let Ok(profile) = find_etype(body.etype) else {
            return Err(Krb5Error::Mit(
                SAM_INVALID_ETYPE,
                "Invalid encryption type in SAM challenge",
            ));
        };
        let salt = self
            .last_preauth_salt
            .clone()
            .unwrap_or_else(|| self.default_salt());
        let use_sad = flags.contains(SamFlags::USE_SAD_AS_KEY);
        let mut as_key = if use_sad {
            None
        } else {
            Some(self.long_term_key(body.etype, &salt, self.last_s2kparams.as_deref())?)
        };

        let has_challenge = body.challenge.as_ref().is_some_and(|c| !c.is_empty());
        let prompt = Sam2Prompt {
            name: samdata(&body.type_name, "SAM Authentication", 99),
            banner: samdata(&body.challenge_label, challenge_banner(body.sam_type), 99),
            prompt: format!(
                "{}{}{}{}",
                if has_challenge { "Challenge is [" } else { "" },
                samdata(&body.challenge, "", 20),
                if has_challenge { "], " } else { "" },
                samdata(&body.response_prompt, "passcode", 55),
            ),
        };
        let sad = zeroize::Zeroizing::new((responder.0)(&prompt).ok_or_else(cant_read)?);

        if use_sad {
            let k = profile
                .string_to_key(sad.as_bytes(), &salt, None)
                .map_err(crypto)?;
            as_key = Some(EncryptionKey::new(body.etype, k.to_vec()));
        } else if !flags.contains(SamFlags::SEND_ENCRYPTED_SAD) {
            // Combining the reply key with the SAD is defined only for DES
            // and 3DES, which MIT no longer supports.
            return Err(unsupported());
        }
        let as_key = as_key.ok_or_else(cant_read)?;

        let key_profile = find_etype(as_key.keytype).map_err(crypto)?;
        let mut valid = false;
        for ck in &sc2.cksum {
            if UNKEYED.contains(&ck.cksumtype) {
                continue;
            }
            if key_profile.checksum_type() != ck.cksumtype {
                return Err(Krb5Error::UnsupportedEtype(ck.cksumtype));
            }
            match key_profile.verify_checksum(
                as_key.key_bytes(),
                KEYUSAGE_CHALLENGE_CKSUM,
                sc2.body.as_bytes(),
                ck.checksum.as_ref(),
            ) {
                Ok(()) => {
                    valid = true;
                    break;
                }
                Err(CryptoError::ChecksumMismatch) => {}
                Err(e) => return Err(crypto(e)),
            }
        }
        if !valid {
            // "password incorrect" to the caller.
            return Err(Krb5Error::Mit(
                AP_ERR_BAD_INTEGRITY,
                "Decrypt integrity check failed",
            ));
        }

        let esre2 = EncSamResponseEnc2 {
            nonce: body.nonce,
            sad: if flags.contains(SamFlags::SEND_ENCRYPTED_SAD) {
                opt(sad.as_bytes())
            } else {
                None
            },
        };
        let cipher = key_profile
            .encrypt(
                as_key.key_bytes(),
                KEYUSAGE_RESPONSE,
                &rasn::der::encode(&esre2)?,
            )
            .map_err(crypto)?;
        let sr2 = SamResponse2 {
            sam_type: body.sam_type,
            flags: body.flags,
            track_id: body.track_id.clone(),
            enc_nonce_or_sad: EncryptedData {
                etype: as_key.keytype,
                kvno: None,
                cipher: cipher.into(),
            },
            nonce: body.nonce,
        };
        if use_sad {
            self.sam_key = Some(as_key);
        }
        Ok(PaData {
            padata_type: PA_SAM_RESPONSE_2,
            padata_value: rasn::der::encode(&sr2)?.into(),
        })
    }
}
