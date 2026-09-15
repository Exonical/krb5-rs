//! FAST (RFC 6113) request state and the encrypted-challenge preauth
//! mechanism. Mirrors MIT krb5 `lib/krb5/krb/fast.c` and `preauth_ec.c`.

use rasn::types::{BitString, OctetString};

use crate::crypto::{find_etype, fx_cf2, key_usage, EtypeProfile};
use crate::types::{
    AsReq, Checksum, EncryptedData, EncryptionKey, KdcReq, KerberosTime, KrbErrorMsg, KrbFastArmor,
    KrbFastArmoredReq, KrbFastReq, KrbFastResponse, PaData, PaDataType, PaEncTsEnc, PaFxFastReply,
    PaFxFastRequest, PrincipalName, TgsReq, Ticket,
};
use crate::Krb5Error;

use super::ap::{ApReqOptions, AuthContext};
use super::credential::Credential;

/// FX-FAST-ARMOR-AP-REQUEST armor type (RFC 6113 §5.4.1).
pub const FX_FAST_ARMOR_AP_REQUEST: i32 = 1;

/// PA-TGS-REQ padata type (RFC 4120 §7.5.1).
const PA_TGS_REQ: i32 = 1;

/// Which KDC message a FAST request wraps (encoder selection).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FastMsgType {
    /// AS-REQ (msg-type 10).
    As,
    /// TGS-REQ (msg-type 12).
    Tgs,
}

/// FAST mode for the AS exchange.
///
/// Mirrors MIT `krb5_get_init_creds_opt_set_fast_flags` /
/// `set_fast_ccache_name` behavior: the credential is an armor TGT of the
/// request realm.
#[derive(Debug, Clone, Default)]
pub enum FastMode {
    /// Never use FAST (default).
    #[default]
    Disabled,
    /// Armor is available but the first request is sent unarmored; the
    /// exchange upgrades to FAST if the KDC advertises it in a preauth
    /// error (MIT `KRB5INT_FAST_ARMOR_AVAIL` without `DO_FAST`,
    /// get_in_tkt.c:1700-1707).
    Opportunistic(Credential),
    /// FAST is required: the first request is already armored and a reply
    /// without PA-FX-FAST fails (MIT `KRB5_FAST_REQUIRED`).
    Required(Credential),
}

impl FastMode {
    /// The armor credential, if any.
    pub fn armor_credential(&self) -> Option<&Credential> {
        match self {
            Self::Disabled => None,
            Self::Opportunistic(c) | Self::Required(c) => Some(c),
        }
    }

    /// Whether FAST should be used from the first request.
    pub fn required(&self) -> bool {
        matches!(self, Self::Required(_))
    }
}

/// Result of `FastState::process_error` (MIT `krb5int_fast_process_error`).
#[derive(Debug)]
pub struct FastError {
    /// The effective error: the inner FX-ERROR KRB-ERROR when one was
    /// successfully unwrapped, otherwise the original outer error.
    pub err: KrbErrorMsg,
    /// The FAST response padata (or the decoded error e-data in the
    /// unarmored case). Used as method data / cookie source.
    pub padata: Option<Vec<PaData>>,
    /// Whether the client should make a follow-up request.
    pub retry: bool,
}

/// Outputs of a successfully processed FAST response
/// (MIT `krb5int_fast_process_response` side effects).
#[derive(Debug)]
pub struct FastResponseOut {
    /// Client principal asserted by KrbFastFinished (replaces rep.cname).
    pub client: PrincipalName,
    /// Strengthen key for reply-key derivation, if the KDC sent one.
    pub strengthen_key: Option<EncryptionKey>,
    /// Padata carried inside the FAST response (replaces rep.padata).
    pub padata: Vec<PaData>,
}

/// Per-request FAST state (MIT `struct krb5int_fast_request_state`).
pub struct FastState {
    armor: Option<KrbFastArmor>,
    armor_key: Option<EncryptionKey>,
    nonce: u32,
    fast_options: BitString,
    armor_avail: bool,
}

impl FastState {
    /// Create an empty FAST state (MIT `krb5int_fast_make_state`).
    pub fn new() -> Self {
        Self {
            armor: None,
            armor_key: None,
            nonce: 0,
            fast_options: BitString::from_slice(&[]),
            armor_avail: false,
        }
    }

    /// Record that armor credentials are available
    /// (MIT `KRB5INT_FAST_ARMOR_AVAIL`).
    pub fn set_armor_available(&mut self, avail: bool) {
        self.armor_avail = avail;
    }

    /// The current armor key, if one has been derived.
    pub fn armor_key(&self) -> Option<&EncryptionKey> {
        self.armor_key.as_ref()
    }

    /// Build AP-REQ armor from an armor TGT (MIT `fast_armor_ap_request`,
    /// fast.c:52-108).
    pub fn armor_ap_request(&mut self, armor_tgt: &Credential) -> Result<(), Krb5Error> {
        let mut auth_context = AuthContext::new();
        let opts = ApReqOptions {
            use_subkey: true,
            ..ApReqOptions::default()
        };
        let ap_req_der = auth_context.mk_req(&opts, None, armor_tgt)?;
        let subkey = auth_context
            .send_subkey()
            .cloned()
            .ok_or(Krb5Error::ReplyValidation("armor AP-REQ without subkey"))?;
        self.armor_key = Some(
            fx_cf2(
                &subkey,
                b"subkeyarmor",
                &armor_tgt.session_key,
                b"ticketarmor",
            )
            .map_err(|e| Krb5Error::Crypto(e.to_string()))?,
        );
        self.armor = Some(KrbFastArmor {
            armor_type: FX_FAST_ARMOR_AP_REQUEST,
            armor_value: OctetString::from(ap_req_der),
        });
        Ok(())
    }

    /// Derive the implicit TGS armor key used when there is no armor ccache
    /// (MIT `krb5int_fast_tgs_armor` ccache==NULL branch, fast.c:111-142).
    pub fn tgs_armor(
        &mut self,
        subkey: &EncryptionKey,
        session: &EncryptionKey,
    ) -> Result<(), Krb5Error> {
        self.armor = None;
        self.armor_key = Some(
            fx_cf2(subkey, b"subkeyarmor", session, b"ticketarmor")
                .map_err(|e| Krb5Error::Crypto(e.to_string()))?,
        );
        Ok(())
    }

    /// Wrap a KDC-REQ in PA-FX-FAST if armored, else encode it as-is
    /// (MIT `krb5int_fast_prep_req`, fast.c:254-358).
    ///
    /// `to_be_checksummed` is the outer request body DER for AS and the
    /// PA-TGS-REQ AP-REQ DER for TGS (send_tgs.c:277-283).
    pub fn prep_req(
        &mut self,
        req: &KdcReq,
        to_be_checksummed: &[u8],
        msg_type: FastMsgType,
    ) -> Result<Vec<u8>, Krb5Error> {
        let Some(armor_key) = &self.armor_key else {
            return encode_kdc_req(req, msg_type);
        };
        self.nonce = req.req_body.nonce;

        // Inner padata: the request padata minus PA-TGS-REQ entries.
        let original = req.padata.clone().unwrap_or_default();
        let tgs_pa = original.iter().find(|pa| pa.padata_type == PA_TGS_REQ);
        let inner_padata: Vec<PaData> = original
            .iter()
            .filter(|pa| pa.padata_type != PA_TGS_REQ)
            .cloned()
            .collect();

        let fast_req = KrbFastReq {
            fast_options: self.fast_options.clone(),
            padata: inner_padata,
            req_body: req.req_body.clone(),
        };
        let fast_req_der = rasn::der::encode(&fast_req)?;

        let profile =
            find_etype(armor_key.keytype).map_err(|e| Krb5Error::Crypto(e.to_string()))?;
        let req_checksum = Checksum {
            cksumtype: profile.checksum_type(),
            checksum: profile
                .checksum(
                    armor_key.key_bytes(),
                    key_usage::FAST_REQ_CHKSUM,
                    to_be_checksummed,
                )
                .map_err(|e| Krb5Error::Crypto(e.to_string()))?
                .into(),
        };
        let enc_fast_req = EncryptedData {
            etype: armor_key.keytype,
            kvno: None,
            cipher: profile
                .encrypt(armor_key.key_bytes(), key_usage::FAST_ENC, &fast_req_der)
                .map_err(|e| Krb5Error::Crypto(e.to_string()))?
                .into(),
        };
        let armored = PaFxFastRequest::ArmoredData(KrbFastArmoredReq {
            armor: self.armor.clone(),
            req_checksum,
            enc_fast_req,
        });
        let fx_pa = PaData {
            padata_type: PaDataType::FxFast as i32,
            padata_value: rasn::der::encode(&armored)?.into(),
        };

        // Outer padata: AS carries only PA-FX-FAST; TGS puts PA-TGS-REQ
        // first, then PA-FX-FAST, then the remaining original padata
        // (make_tgs_outer_padata, fast.c:234-252).
        let outer_padata = match (msg_type, tgs_pa) {
            (FastMsgType::Tgs, Some(tgs)) => {
                let mut list = Vec::with_capacity(inner_padata_len(&original) + 2);
                list.push(tgs.clone());
                list.push(fx_pa);
                list.extend(
                    original
                        .iter()
                        .filter(|pa| pa.padata_type != PA_TGS_REQ)
                        .cloned(),
                );
                list
            }
            _ => vec![fx_pa],
        };

        let outer = KdcReq {
            pvno: req.pvno,
            msg_type: req.msg_type,
            padata: Some(outer_padata),
            req_body: req.req_body.clone(),
        };
        encode_kdc_req(&outer, msg_type)
    }

    /// Decrypt the PA-FX-FAST-REPLY armored data into a KrbFastResponse
    /// and check the echoed nonce (fast.c:464-495).
    fn decrypt_fast_response(
        &self,
        fx_pa: &PaData,
        armor_key: &EncryptionKey,
    ) -> Result<(KrbFastResponse, &'static dyn EtypeProfile), Krb5Error> {
        let reply: PaFxFastReply = rasn::der::decode(fx_pa.padata_value.as_ref())?;
        let PaFxFastReply::ArmoredData(armored) = reply;
        let profile =
            find_etype(armor_key.keytype).map_err(|e| Krb5Error::Crypto(e.to_string()))?;
        let plain = profile
            .decrypt(
                armor_key.key_bytes(),
                key_usage::FAST_REP,
                armored.enc_fast_rep.cipher.as_ref(),
            )
            .map_err(|_| Krb5Error::DecryptionFailed)?;
        let resp: KrbFastResponse = rasn::der::decode(&plain)?;
        if resp.nonce != self.nonce {
            return Err(Krb5Error::ReplyValidation(
                "nonce modified in FAST response",
            ));
        }
        Ok((resp, profile))
    }

    /// Decrypt and validate the FAST padata of a KRB-ERROR
    /// (MIT `krb5int_fast_process_error`, fast.c:426-515).
    pub fn process_error(&self, err: KrbErrorMsg) -> Result<FastError, Krb5Error> {
        let Some(armor_key) = &self.armor_key else {
            // Unarmored: retry if there's any e_data to process; decode it
            // as METHOD-DATA when possible (typed-data treated as none).
            let e_data: &[u8] = err.e_data.as_ref().map(|d| d.as_ref()).unwrap_or(&[]);
            let retry = !e_data.is_empty();
            let padata: Option<Vec<PaData>> = rasn::der::decode(e_data).ok();
            return Ok(FastError { err, padata, retry });
        };

        let e_data: &[u8] = err.e_data.as_ref().map(|d| d.as_ref()).unwrap_or(&[]);
        let fast_response = (|| -> Result<KrbFastResponse, Krb5Error> {
            let method_data: Vec<PaData> = rasn::der::decode(e_data)?;
            let fx_pa = method_data
                .iter()
                .find(|pa| pa.padata_type == PaDataType::FxFast as i32)
                .ok_or(Krb5Error::FastRequired)?;
            self.decrypt_fast_response(fx_pa, armor_key)
                .map(|(resp, _)| resp)
        })();

        let fast_response = match fast_response {
            Ok(r) => r,
            Err(_) => {
                // Any failure in the FAST decode chain means the KDC does
                // not understand FAST: surface the outer error, no retry.
                return Ok(FastError {
                    err,
                    padata: None,
                    retry: false,
                });
            }
        };

        let fx_error_pa = fast_response
            .padata
            .iter()
            .find(|pa| pa.padata_type == PaDataType::FxError as i32)
            .ok_or(Krb5Error::ReplyValidation(
                "Expecting FX_ERROR pa-data inside FAST container",
            ))?;
        let inner: KrbErrorMsg = rasn::der::decode(fx_error_pa.padata_value.as_ref())?;
        let retry = fast_response.padata.len() > 1
            && fast_response
                .padata
                .iter()
                .any(|pa| pa.padata_type == PaDataType::FxCookie as i32);
        Ok(FastError {
            err: inner,
            padata: Some(fast_response.padata),
            retry,
        })
    }

    /// Decrypt and validate the FAST padata of a KDC-REP
    /// (MIT `krb5int_fast_process_response`, fast.c:517-568).
    ///
    /// Returns `Ok(None)` when the request was not FAST-armored.
    pub fn process_response(
        &self,
        rep_padata: Option<&[PaData]>,
        ticket: &Ticket,
    ) -> Result<Option<FastResponseOut>, Krb5Error> {
        let Some(armor_key) = &self.armor_key else {
            return Ok(None);
        };
        let fx_pa = rep_padata
            .unwrap_or(&[])
            .iter()
            .find(|pa| pa.padata_type == PaDataType::FxFast as i32)
            .ok_or(Krb5Error::FastRequired)?;
        let (resp, profile) = self.decrypt_fast_response(fx_pa, armor_key)?;
        let finished = resp.finished.as_ref().ok_or(Krb5Error::ReplyValidation(
            "FAST response missing finish message",
        ))?;

        // Ticket checksum: armor key, usage 53, over DER(ticket). As with
        // the enc-pa-rep rule we require the armor enctype's mandatory
        // checksum type.
        let ticket_der = rasn::der::encode(ticket)?;
        if finished.ticket_checksum.cksumtype != profile.checksum_type() {
            return Err(Krb5Error::ReplyValidation("Ticket modified in KDC reply"));
        }
        profile
            .verify_checksum(
                armor_key.key_bytes(),
                key_usage::FAST_FINISHED,
                &ticket_der,
                finished.ticket_checksum.checksum.as_ref(),
            )
            .map_err(|_| Krb5Error::ReplyValidation("Ticket modified in KDC reply"))?;

        Ok(Some(FastResponseOut {
            client: finished.cname.clone(),
            strengthen_key: resp.strengthen_key,
            padata: resp.padata,
        }))
    }

    /// Compute the reply decryption key (MIT `krb5int_fast_reply_key`,
    /// fast.c:570-593).
    pub fn reply_key(
        strengthen: Option<&EncryptionKey>,
        existing: &EncryptionKey,
    ) -> Result<EncryptionKey, Krb5Error> {
        match strengthen {
            Some(s) => fx_cf2(s, b"strengthenkey", existing, b"replykey")
                .map_err(|e| Krb5Error::Crypto(e.to_string())),
            None => Ok(existing.clone()),
        }
    }

    /// Whether an error's padata advertises FAST and we should restart
    /// armored (MIT `k5_upgrade_to_fast_p`, fast.c:678-688).
    pub fn upgrade_to_fast_p(&self, padata: &[PaData]) -> bool {
        if self.armor_key.is_some() || !self.armor_avail {
            return false;
        }
        padata
            .iter()
            .any(|pa| pa.padata_type == PaDataType::FxFast as i32)
    }
}

impl Default for FastState {
    fn default() -> Self {
        Self::new()
    }
}

fn inner_padata_len(original: &[PaData]) -> usize {
    original
        .iter()
        .filter(|pa| pa.padata_type != PA_TGS_REQ)
        .count()
}

fn encode_kdc_req(req: &KdcReq, msg_type: FastMsgType) -> Result<Vec<u8>, Krb5Error> {
    match msg_type {
        FastMsgType::As => Ok(rasn::der::encode(&AsReq(req.clone()))?),
        FastMsgType::Tgs => Ok(rasn::der::encode(&TgsReq(req.clone()))?),
    }
}

/// Build a PA-ENCRYPTED-CHALLENGE padata for the client direction
/// (MIT `ec_process` send path, preauth_ec.c:97-143).
pub fn build_pa_encrypted_challenge(
    armor_key: &EncryptionKey,
    as_key: &EncryptionKey,
    ts: KerberosTime,
    usec: Option<i32>,
) -> Result<PaData, Krb5Error> {
    let challenge_key = fx_cf2(
        armor_key,
        b"clientchallengearmor",
        as_key,
        b"challengelongterm",
    )
    .map_err(|e| Krb5Error::Crypto(e.to_string()))?;
    let ts_enc = rasn::der::encode(&PaEncTsEnc {
        patimestamp: ts,
        pausec: usec,
    })?;
    let profile =
        find_etype(challenge_key.keytype).map_err(|e| Krb5Error::Crypto(e.to_string()))?;
    let cipher = profile
        .encrypt(
            challenge_key.key_bytes(),
            key_usage::ENC_CHALLENGE_CLIENT,
            &ts_enc,
        )
        .map_err(|e| Krb5Error::Crypto(e.to_string()))?;
    let enc = EncryptedData {
        etype: challenge_key.keytype,
        kvno: None,
        cipher: cipher.into(),
    };
    Ok(PaData {
        padata_type: PaDataType::EncryptedChallenge as i32,
        padata_value: rasn::der::encode(&enc)?.into(),
    })
}

/// Verify a KDC-direction encrypted challenge found in a reply's FAST
/// padata (MIT `ec_process` verify path, preauth_ec.c:61-90). The
/// timestamp contents are not checked, per MIT's comment; successful
/// decryption proves the KDC holds the client's long-term key.
pub fn verify_kdc_challenge(
    armor_key: &EncryptionKey,
    as_key: &EncryptionKey,
    padata_value: &[u8],
) -> Result<(), Krb5Error> {
    let challenge_key = fx_cf2(
        armor_key,
        b"kdcchallengearmor",
        as_key,
        b"challengelongterm",
    )
    .map_err(|e| Krb5Error::Crypto(e.to_string()))?;
    let enc: EncryptedData = rasn::der::decode(padata_value)?;
    let profile = find_etype(enc.etype).map_err(|_| Krb5Error::UnsupportedEtype(enc.etype))?;
    profile
        .decrypt(
            challenge_key.key_bytes(),
            key_usage::ENC_CHALLENGE_KDC,
            enc.cipher.as_ref(),
        )
        .map_err(|_| Krb5Error::DecryptionFailed)?;
    Ok(())
}
