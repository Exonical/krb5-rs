//! OTP pre-authentication, client side (MIT `lib/krb5/krb/preauth_otp.c`).

use super::AsExchange;
use crate::crypto::find_etype;
use crate::otp::{
    flags::{COLLECT_PIN, NEXTOTP, SEPARATE_PIN},
    flags_to_bits, tokeninfo_supported, OtpAnswer, OtpTokenInfo, PaOtpChallenge, PaOtpEncRequest,
    PaOtpRequest, KEYUSAGE_PA_OTP_REQUEST, PA_OTP_REQUEST,
};
use crate::types::{EncryptedData, EncryptionKey, PaData};
use crate::Krb5Error;

/// `make_request` (preauth_otp.c:765-865) for the chosen token info.
fn make_request(
    ti: &crate::otp::OtpTokenInfo,
    answer: &OtpAnswer,
) -> Result<PaOtpRequest, Krb5Error> {
    let flags = ti.flag_bits();
    let value = answer.value.clone().unwrap_or_default();
    let mut req = PaOtpRequest {
        flags: flags_to_bits(flags & NEXTOTP),
        nonce: None,
        enc_data: EncryptedData {
            etype: 0,
            kvno: None,
            cipher: Vec::new().into(),
        },
        hash_alg: None,
        iteration_count: None,
        otp_value: Some(value.clone().into_bytes().into()),
        pin: None,
        challenge: None,
        time: None,
        counter: None,
        format: ti.format,
        token_id: ti.token_id.clone(),
        alg_id: ti.alg_id.clone(),
        vendor: ti.vendor.clone(),
    };
    if flags & COLLECT_PIN != 0 {
        if flags & SEPARATE_PIN != 0 {
            // A separate PIN is required (preauth_otp.c:803-811).
            let pin = answer.pin.clone().ok_or(Krb5Error::PreauthFailed)?;
            req.pin = Some(pin);
        } else if let Some(pin) = &answer.pin {
            req.otp_value = Some(format!("{pin}{value}").into_bytes().into());
        }
    }
    Ok(req)
}

impl AsExchange {
    /// `otp_client_process` (preauth_otp.c:1063-1132): answer a
    /// PA-OTP-CHALLENGE with a PA-OTP-REQUEST carrying the encrypted nonce.
    /// Returns `None` when the mechanism cannot run (no armor, no answer,
    /// no supported token).
    pub(super) fn otp_process(&mut self, value: &[u8]) -> Result<Option<PaData>, Krb5Error> {
        let Some(armor) = self.fast_state.armor_key().cloned() else {
            return Ok(None);
        };
        let Ok(mut chl) = rasn::der::decode::<PaOtpChallenge>(value) else {
            return Ok(None);
        };
        chl.tokeninfo.retain(tokeninfo_supported);
        self.filter_config_tokeninfos(&mut chl.tokeninfo);
        let Some(answer) = self.config.otp.clone() else {
            return Ok(None);
        };
        // prompt_for_token (preauth_otp.c:750-753): a single token, as left
        // by the cached choice, is used without asking which.
        let index = if chl.tokeninfo.len() == 1 {
            0
        } else {
            answer.tokeninfo
        };
        let Some(ti) = chl.tokeninfo.get(index) else {
            return Ok(None);
        };
        let mut req = make_request(ti, &answer)?;
        self.save_config_tokeninfo(ti);
        req.enc_data = encrypt_nonce(&armor, &chl)?;
        self.otp_key = Some(armor);
        let der = rasn::der::encode(&req).map_err(Krb5Error::Asn1Encode)?;
        Ok(Some(PaData {
            padata_type: PA_OTP_REQUEST,
            padata_value: der.into(),
        }))
    }
}

impl AsExchange {
    /// `filter_config_tokeninfos` (preauth_otp.c:924-970): keep only the
    /// token matching the input cache's saved vendor/algID/tokenID, when
    /// exactly one matches.
    pub(super) fn filter_config_tokeninfos(&self, tis: &mut Vec<OtpTokenInfo>) {
        let cfg = |k: &str| self.cc_config_in.get(k).map(String::as_bytes);
        let (vendor, alg_id, token_id) = (cfg("vendor"), cfg("algID"), cfg("tokenID"));
        let differs = |want: Option<&[u8]>, have: Option<&[u8]>| match (want, have) {
            (Some(w), Some(h)) => !h.is_empty() && w != h,
            _ => false,
        };
        let matches: Vec<usize> = (0..tis.len())
            .filter(|&i| {
                let ti = &tis[i];
                !differs(vendor, ti.vendor.as_ref().map(|v| v.as_bytes()))
                    && !differs(alg_id, ti.alg_id.as_ref().map(|v| v.as_bytes()))
                    && !differs(token_id, ti.token_id.as_deref())
            })
            .collect();
        if let [i] = matches[..] {
            let ti = tis.swap_remove(i);
            *tis = vec![ti];
        }
    }

    /// `save_config_tokeninfo` (preauth_otp.c:1028-1058).
    pub(super) fn save_config_tokeninfo(&mut self, ti: &OtpTokenInfo) {
        let mut set = |k: &str, v: Option<&[u8]>| {
            if let Some(v) = v.filter(|v| !v.is_empty()) {
                self.cc_config_out
                    .insert(k.to_string(), String::from_utf8_lossy(v).into_owned());
            }
        };
        set("vendor", ti.vendor.as_ref().map(|v| v.as_bytes()));
        set("algID", ti.alg_id.as_ref().map(|v| v.as_bytes()));
        set("tokenID", ti.token_id.as_deref());
    }
}

/// `encrypt_nonce` (preauth_otp.c:425-447).
fn encrypt_nonce(key: &EncryptionKey, chl: &PaOtpChallenge) -> Result<EncryptedData, Krb5Error> {
    let er = rasn::der::encode(&PaOtpEncRequest {
        nonce: chl.nonce.clone(),
    })
    .map_err(Krb5Error::Asn1Encode)?;
    let profile = find_etype(key.keytype).map_err(|_| Krb5Error::UnsupportedEtype(key.keytype))?;
    let cipher = profile
        .encrypt(key.key_bytes(), KEYUSAGE_PA_OTP_REQUEST, &er)
        .map_err(|e| Krb5Error::Crypto(e.to_string()))?;
    Ok(EncryptedData {
        etype: key.keytype,
        kvno: None,
        cipher: cipher.into(),
    })
}
