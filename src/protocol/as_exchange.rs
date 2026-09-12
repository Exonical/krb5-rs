//! AS exchange state machine.
//!
//! Implements the step-based pattern from MIT krb5's `krb5_init_creds_step()`.
//! The caller drives the loop and controls transport — this module only
//! produces outbound messages and consumes inbound responses.

use std::time::Duration;

use chrono::{Timelike, Utc};
use rasn::types::GeneralString;
use zeroize::Zeroizing;

use crate::crypto::{find_etype, key_usage};
use crate::types::{
    AsRep, AsReq, Checksum, EncAsRepPart, EncKdcRepPart, EncTgsRepPart, KdcOptions, KdcRep, KdcReq,
    KdcReqBody, KerberosFlags, KerberosTime, KrbErrorMsg, PaData, PaDataType, PrincipalName,
    TicketFlags,
};
use crate::Krb5Error;

use super::credential::{Credential, TicketTimes};
use super::preauth::{
    build_empty_padata, build_pa_enc_timestamp, build_pa_pac_request, default_salt,
    extract_preauth_hint, PreauthHint,
};
use super::validate::{validate_as_reply, DEFAULT_MAX_CLOCK_SKEW, UTC_OFFSET};

use super::error_codes::ErrorCode;

/// KDC error codes used in match patterns (derived from ErrorCode enum).
const KDC_ERR_PREAUTH_REQUIRED: i32 = ErrorCode::PreauthRequired as i32;
const KRB_ERR_RESPONSE_TOO_BIG: i32 = ErrorCode::ResponseTooBig as i32;
const KDC_ERR_WRONG_REALM: i32 = ErrorCode::WrongRealm as i32;
const KDC_ERR_PREAUTH_FAILED: i32 = ErrorCode::PreauthFailed as i32;
/// RFC 6113 codes not represented in `ErrorCode`.
const KDC_ERR_PREAUTH_EXPIRED: i32 = 90;
const KDC_ERR_MORE_PREAUTH_DATA_REQUIRED: i32 = 91;

/// Maximum pre-authentication loop iterations (matches MIT krb5).
const MAX_PREAUTH_LOOPS: u32 = 16;

/// Configuration for an AS exchange.
#[derive(Debug, Clone)]
pub struct AsExchangeConfig {
    /// Client principal name.
    pub client: PrincipalName,
    /// Kerberos realm.
    pub realm: String,
    /// Preferred encryption types (in order). Default:
    /// [AES-256-SHA1, AES-128-SHA1, AES-256-SHA2, AES-128-SHA2]
    /// (MIT init_ctx.c:59-66, minus des3/rc4/camellia).
    pub etypes: Vec<i32>,
    /// KDC options flags.
    pub kdc_options: KerberosFlags<KdcOptions>,
    /// Requested ticket lifetime. Default: 10 hours.
    pub tkt_lifetime: Duration,
    /// Requested renewable lifetime. Default: 7 days.
    ///
    /// Renewability is controlled by the `KdcOptions::RENEWABLE` flag in
    /// `kdc_options`. To request a non-renewable ticket, clear that flag.
    pub renew_lifetime: Duration,
    /// Whether to request PAC inclusion (for AD environments). Default: true.
    pub request_pac: bool,
    /// Maximum allowed clock skew. Default: 5 minutes.
    pub max_clock_skew: Duration,
}

/// Default provides sensible options (etypes, flags, lifetimes) but leaves
/// `client` and `realm` empty. Use `AsExchangeConfig::new()` instead of
/// `Default::default()` directly — the empty client/realm will cause the
/// exchange to fail at the KDC.
impl Default for AsExchangeConfig {
    fn default() -> Self {
        Self {
            client: PrincipalName::new_principal(""),
            realm: String::new(),
            etypes: vec![18, 17, 20, 19], // AES-256-SHA1, AES-128-SHA1, AES-256-SHA2, AES-128-SHA2
            kdc_options: KerberosFlags::new(
                KdcOptions::FORWARDABLE | KdcOptions::RENEWABLE | KdcOptions::CANONICALIZE,
            ),
            tkt_lifetime: Duration::from_secs(10 * 3600), // 10 hours
            renew_lifetime: Duration::from_secs(7 * 24 * 3600), // 7 days
            request_pac: true,
            max_clock_skew: DEFAULT_MAX_CLOCK_SKEW,
        }
    }
}

impl AsExchangeConfig {
    /// Create a config for the given principal and realm with defaults.
    pub fn new(client: PrincipalName, realm: impl Into<String>) -> Self {
        Self {
            client,
            realm: realm.into(),
            ..Default::default()
        }
    }

    /// Create a config that sends `PA-PAC-REQUEST { include-pac: false }`.
    ///
    /// Use this for non-AD environments where PAC is not needed.
    pub fn new_no_pac(client: PrincipalName, realm: impl Into<String>) -> Self {
        Self {
            client,
            realm: realm.into(),
            request_pac: false,
            ..Default::default()
        }
    }
}

/// Result of a single `step()` call.
#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
// Large variants are acceptable: returned by value at step boundaries,
// not stored in collections. The Vec<u8>+String shape is inherent to the API.
pub enum StepResult {
    /// Send this DER-encoded message to the KDC for the given realm.
    SendToKdc {
        /// DER-encoded AS-REQ.
        data: Vec<u8>,
        /// Realm to send to (for KDC discovery).
        realm: String,
    },
    /// KDC responded with `KRB_ERR_RESPONSE_TOO_BIG` — resend the same
    /// request over TCP.  The `data` field contains the exact AS-REQ bytes
    /// that were last sent (no state change, exchange is still alive).
    RetryTcp {
        /// DER-encoded AS-REQ (same bytes as the previous `SendToKdc`).
        data: Vec<u8>,
        /// Realm.
        realm: String,
    },
    /// Exchange finished successfully. Call `credential()` to extract result.
    Complete,
}

/// Internal state of the AS exchange.
enum AsState {
    /// Build and send the initial AS-REQ (possibly without preauth).
    Initial,
    /// Waiting for KDC response (may transition to Preauth or Complete).
    AwaitReply,
    /// Exchange complete.
    Complete,
}

/// Step-based AS exchange state machine.
///
/// # Usage
///
/// ```rust,ignore
/// let config = AsExchangeConfig::new(principal, "EXAMPLE.COM");
/// let mut exchange = AsExchange::new(config, "password");
/// let mut kdc_reply = Vec::new();
///
/// loop {
///     match exchange.step(&kdc_reply)? {
///         StepResult::SendToKdc { data, realm }
///         | StepResult::RetryTcp { data, realm } => {
///             kdc_reply = transport.send(&realm, &data).await?;
///         }
///         StepResult::Complete => break,
///     }
/// }
///
/// let cred = exchange.credential()?;
/// ```
pub struct AsExchange {
    state: AsState,
    config: AsExchangeConfig,
    password: Zeroizing<String>,
    nonce: u32,
    /// The most recent AS-REQ body (for validation on reply).
    last_req_body: Option<KdcReqBody>,
    /// The most recent DER-encoded AS-REQ (for RetryTcp re-emit).
    last_req_bytes: Vec<u8>,
    /// Persisted salt from preauth hint (for AS-REP decryption).
    last_preauth_salt: Option<Vec<u8>>,
    /// Persisted s2kparams from preauth hint (for AS-REP decryption).
    last_s2kparams: Option<Vec<u8>>,
    /// Persisted etype from preauth hint (for hint-less MORE_PREAUTH_DATA).
    last_preauth_etype: Option<i32>,
    /// PA-FX-COOKIE from the most recent KDC error, echoed verbatim in the
    /// next AS-REQ (MIT preauth2.c:856-884 `copy_cookie`). Not cached:
    /// an error without a cookie clears it.
    cookie: Option<Vec<u8>>,
    /// Whether informational padata (PA-AS-FRESHNESS, PA-REQ-ENC-PA-REP)
    /// may be sent (MIT get_in_tkt.c:873 `info_pa_permitted`).
    info_pa_permitted: bool,
    /// Whether the exchange has already restarted once
    /// (MIT `ctx->restarted` — only one PREAUTH_FAILED restart allowed).
    restarted: bool,
    /// Whether we have sent preauth (PA-ENC-TIMESTAMP) in a request
    /// (MIT `ctx->selected_preauth_type != KRB5_PADATA_NONE`).
    preauth_sent: bool,
    /// Loop counter to prevent infinite preauth loops.
    loop_count: u32,
    /// Output credential.
    credential: Option<Credential>,
}

impl AsExchange {
    /// Create a new AS exchange.
    pub fn new(config: AsExchangeConfig, password: impl Into<String>) -> Self {
        Self {
            state: AsState::Initial,
            config,
            password: Zeroizing::new(password.into()),
            nonce: 0,
            last_req_body: None,
            last_req_bytes: Vec::new(),
            last_preauth_salt: None,
            last_s2kparams: None,
            last_preauth_etype: None,
            cookie: None,
            info_pa_permitted: true,
            restarted: false,
            preauth_sent: false,
            loop_count: 0,
            credential: None,
        }
    }

    /// Advance the state machine.
    ///
    /// On the first call, pass an empty slice. On subsequent calls, pass
    /// the KDC's response bytes.
    pub fn step(&mut self, kdc_reply: &[u8]) -> Result<StepResult, Krb5Error> {
        match self.state {
            AsState::Initial => {
                // First call — build initial AS-REQ (no preauth)
                let (as_req_der, req_body) = self.build_as_req(None)?;
                self.last_req_body = Some(req_body);
                self.last_req_bytes = as_req_der.clone();
                self.state = AsState::AwaitReply;
                Ok(StepResult::SendToKdc {
                    data: as_req_der,
                    realm: self.config.realm.clone(),
                })
            }
            AsState::AwaitReply => {
                // Process KDC response
                self.process_kdc_reply(kdc_reply)
            }
            AsState::Complete => Ok(StepResult::Complete),
        }
    }

    /// Extract the credential after successful completion.
    pub fn credential(&self) -> Result<&Credential, Krb5Error> {
        self.credential
            .as_ref()
            .ok_or(Krb5Error::ReplyValidation("exchange not complete"))
    }

    /// Process a KDC response.
    fn process_kdc_reply(&mut self, kdc_reply: &[u8]) -> Result<StepResult, Krb5Error> {
        if kdc_reply.is_empty() {
            return Err(Krb5Error::ReplyValidation("empty KDC reply"));
        }

        // Try to decode as AS-REP first
        if let Ok(as_rep) = rasn::der::decode::<AsRep>(kdc_reply) {
            if as_rep.0.pvno != 5 || as_rep.0.msg_type != 11 {
                return Err(Krb5Error::ReplyValidation("invalid AS-REP pvno/msg_type"));
            }
            return self.process_as_rep(as_rep);
        }

        // Try to decode as KRB-ERROR
        let krb_error: KrbErrorMsg = rasn::der::decode(kdc_reply)?;
        if krb_error.pvno != 5 || krb_error.msg_type != 30 {
            return Err(Krb5Error::ReplyValidation(
                "invalid KRB-ERROR pvno/msg_type",
            ));
        }

        match krb_error.error_code {
            // MORE_PREAUTH_DATA_REQUIRED (91) is handled like PREAUTH_REQUIRED
            // (MIT get_in_tkt.c:1742): its e-data may lack ETYPE-INFO2, in
            // which case the previously saved etype/salt/s2kparams hint is
            // reused.
            KDC_ERR_PREAUTH_REQUIRED | KDC_ERR_MORE_PREAUTH_DATA_REQUIRED => {
                self.loop_count += 1;
                if self.loop_count > MAX_PREAUTH_LOOPS {
                    return Err(Krb5Error::PreauthLoopExceeded(MAX_PREAUTH_LOOPS));
                }
                // Extract preauth hints from e-data
                let e_data = krb_error.e_data.as_ref().ok_or(Krb5Error::ReplyValidation(
                    "PREAUTH_REQUIRED without e-data",
                ))?;

                // MIT preauth2.c:856-884 `copy_cookie` — copy the PA-FX-COOKIE
                // from this error's METHOD-DATA verbatim into the next AS-REQ.
                self.cookie = extract_cookie(e_data.as_ref());

                let hint = match extract_preauth_hint(e_data.as_ref(), &self.config.etypes) {
                    Ok(hint) => {
                        // Persist salt and s2kparams for AS-REP decryption later
                        self.last_preauth_salt = hint.salt.clone();
                        self.last_s2kparams = hint.s2kparams.clone();
                        self.last_preauth_etype = Some(hint.etype);
                        hint
                    }
                    Err(e) => match self.last_preauth_etype {
                        Some(etype) => PreauthHint {
                            etype,
                            salt: self.last_preauth_salt.clone(),
                            s2kparams: self.last_s2kparams.clone(),
                        },
                        None => return Err(e),
                    },
                };

                // Build AS-REQ with preauth
                let pa_timestamp = self.build_preauth_padata(&hint)?;
                self.preauth_sent = true;
                let (as_req_der, req_body) = self.build_as_req(Some(pa_timestamp))?;
                self.last_req_body = Some(req_body);
                self.last_req_bytes = as_req_der.clone();
                // Stay in AwaitReply state for next response
                Ok(StepResult::SendToKdc {
                    data: as_req_der,
                    realm: self.config.realm.clone(),
                })
            }
            KRB_ERR_RESPONSE_TOO_BIG => {
                // Re-emit the same request for the caller to resend over TCP.
                // State machine stays in AwaitReply — caller feeds TCP response
                // back into step().
                Ok(StepResult::RetryTcp {
                    data: self.last_req_bytes.clone(),
                    realm: self.config.realm.clone(),
                })
            }
            KDC_ERR_WRONG_REALM => {
                // Realm referral — KDC tells us the correct realm.
                // Use the server realm field (mandatory) rather than crealm (optional).
                let new_realm = String::from_utf8_lossy(krb_error.realm.as_bytes()).to_string();
                if new_realm != self.config.realm {
                    self.config.realm = new_realm;
                    return self.restart();
                }
                // If redirected to the same realm, propagate the original error
                Err(Krb5Error::from_error_msg(krb_error))
            }
            KDC_ERR_PREAUTH_FAILED => {
                // MIT get_in_tkt.c:1709-1715 — if no preauth was sent yet and
                // we haven't restarted, the KDC probably disliked the
                // informational padata; retry once without it.
                if !self.preauth_sent && !self.restarted {
                    self.info_pa_permitted = false;
                    self.restarted = true;
                    self.restart()
                } else {
                    Err(Krb5Error::from_error_msg(krb_error))
                }
            }
            KDC_ERR_PREAUTH_EXPIRED => {
                // MIT get_in_tkt.c:1716-1720 — we sent an expired KDC cookie;
                // start over, allowing another restart on PREAUTH_FAILED.
                self.restarted = false;
                self.restart()
            }
            _ => {
                // Other KDC error — propagate
                Err(Krb5Error::from_error_msg(krb_error))
            }
        }
    }

    /// Restart the exchange from the initial (no-preauth) request.
    ///
    /// MIT `restart_init_creds_loop` (get_in_tkt.c): drops the cookie,
    /// preauth hint and loop state. `restarted` is caller-managed: the
    /// PREAUTH_FAILED path sets it, PREAUTH_EXPIRED clears it.
    fn restart(&mut self) -> Result<StepResult, Krb5Error> {
        self.cookie = None;
        self.last_preauth_salt = None;
        self.last_s2kparams = None;
        self.last_preauth_etype = None;
        self.loop_count = 0;
        self.preauth_sent = false;
        let (as_req_der, req_body) = self.build_as_req(None)?;
        self.last_req_body = Some(req_body);
        self.last_req_bytes = as_req_der.clone();
        Ok(StepResult::SendToKdc {
            data: as_req_der,
            realm: self.config.realm.clone(),
        })
    }

    /// Build an AS-REQ message. Returns (DER bytes, request body for validation).
    fn build_as_req(
        &mut self,
        preauth_padata: Option<Vec<PaData>>,
    ) -> Result<(Vec<u8>, KdcReqBody), Krb5Error> {
        // Generate random nonce. Mask to 31 bits — MIT KDC decodes nonce
        // as signed krb5_int32, rejecting DER-encoded values >= 2^31.
        self.nonce = rand::random::<u32>() & 0x7FFF_FFFF;

        let realm = GeneralString::from_bytes(self.config.realm.as_bytes())
            .map_err(|_| Krb5Error::ReplyValidation("invalid realm string"))?;

        // Build server principal: krbtgt/REALM
        let sname = PrincipalName::new_srv_inst("krbtgt", &self.config.realm);

        // Compute till and rtime using checked arithmetic to avoid panic on overflow
        let now = now_kerberos();
        let till_dur = chrono::Duration::seconds(duration_secs_i64(self.config.tkt_lifetime));
        let till = match now.checked_add_signed(till_dur) {
            Some(t) => t,
            None => {
                return Err(Krb5Error::ReplyValidation(
                    "ticket lifetime overflow when computing till",
                ))
            }
        };

        let rtime = if self.config.kdc_options.contains(KdcOptions::RENEWABLE) {
            let rtime_dur =
                chrono::Duration::seconds(duration_secs_i64(self.config.renew_lifetime));
            match now.checked_add_signed(rtime_dur) {
                Some(t) => Some(t),
                None => {
                    return Err(Krb5Error::ReplyValidation(
                        "renewable lifetime overflow when computing rtime",
                    ))
                }
            }
        } else {
            None
        };

        let req_body = KdcReqBody {
            kdc_options: self.config.kdc_options,
            cname: Some(self.config.client.clone()),
            realm: realm.clone(),
            sname: Some(sname),
            from: None,
            till,
            rtime,
            nonce: self.nonce,
            etype: self.config.etypes.clone(),
            addresses: None,
            enc_authorization_data: None,
            additional_tickets: None,
        };

        // Build padata list: [PA-FX-COOKIE] [preauth] [info padata] [PA-PAC-REQUEST]
        let mut padata: Vec<PaData> = Vec::new();

        // Echo the cookie from the most recent KDC error, if any.
        if let Some(cookie) = &self.cookie {
            padata.push(PaData {
                padata_type: PaDataType::FxCookie as i32,
                padata_value: cookie.clone().into(),
            });
        }

        // Add preauth padata if provided
        if let Some(pa_list) = preauth_padata {
            padata.extend(pa_list);
        }

        // MIT get_in_tkt.c:1365-1372 — empty informational padata while
        // info_pa_permitted (PA-AS-FRESHNESS then PA-REQ-ENC-PA-REP).
        if self.info_pa_permitted {
            padata.push(build_empty_padata(PaDataType::AsFreshness as i32));
            padata.push(build_empty_padata(PaDataType::ReqEncPaRep as i32));
        }

        // Always send PA-PAC-REQUEST; `request_pac` controls `include-pac` value
        padata.push(build_pa_pac_request(self.config.request_pac)?);

        // padata always has at least PA-PAC-REQUEST
        let padata_opt = Some(padata);

        let kdc_req = KdcReq {
            pvno: 5,
            msg_type: 10, // AS-REQ
            padata: padata_opt,
            req_body: req_body.clone(),
        };

        let as_req = AsReq(kdc_req);
        let der = rasn::der::encode(&as_req)?;

        Ok((der, req_body))
    }

    /// Build PA-ENC-TIMESTAMP and return as padata vec.
    fn build_preauth_padata(&self, hint: &PreauthHint) -> Result<Vec<PaData>, Krb5Error> {
        // Capture a single instant for both timestamp and microseconds
        let now_utc = Utc::now();
        let now = now_utc
            .with_nanosecond(0)
            .unwrap_or(now_utc)
            .with_timezone(&UTC_OFFSET);
        let usec = now_utc.timestamp_subsec_micros() as i32;

        // Compute salt: use hint salt if present, or compute default
        let salt = match &hint.salt {
            Some(s) => s.clone(),
            None => {
                let components: Vec<&[u8]> = self
                    .config
                    .client
                    .name_string
                    .iter()
                    .map(|s| s.as_bytes())
                    .collect();
                default_salt(&self.config.realm, &components)
            }
        };

        let pa_timestamp = build_pa_enc_timestamp(
            self.password.as_bytes(),
            &salt,
            hint.s2kparams.as_deref(),
            hint.etype,
            now,
            Some(usec),
        )?;

        Ok(vec![pa_timestamp])
    }

    /// Process a successful AS-REP: decrypt enc-part, validate, build credential.
    fn process_as_rep(&mut self, as_rep: AsRep) -> Result<StepResult, Krb5Error> {
        let rep = &as_rep.0;

        // MIT get_in_tkt.c:1411-1425 `check_reply_enctype` — the reply
        // enctype must be one of the etypes we requested.
        if !self.config.etypes.contains(&rep.enc_part.etype) {
            return Err(Krb5Error::ReplyValidation(
                "reply enctype was not requested",
            ));
        }

        // Determine encryption type from enc-part
        let etype = rep.enc_part.etype;
        let profile = find_etype(etype).map_err(|_| Krb5Error::UnsupportedEtype(etype))?;

        // Derive key from password, preferring params from AS-REP padata
        let (salt, s2kparams) = self.compute_reply_key_params(rep);
        let key = profile
            .string_to_key(self.password.as_bytes(), &salt, s2kparams.as_deref())
            .map_err(|e| Krb5Error::Crypto(e.to_string()))?;

        // Decrypt EncAsRepPart (key usage 3)
        let plaintext = profile
            .decrypt(
                &key,
                key_usage::AS_REP_ENCPART,
                rep.enc_part.cipher.as_ref(),
            )
            .map_err(|_| Krb5Error::DecryptionFailed)?;

        // Try EncAsRepPart (APPLICATION 25) first, then EncTgsRepPart (APPLICATION 26)
        // Some KDCs (Heimdal) use APPLICATION 26 for AS-REP enc-part
        let enc_part: EncKdcRepPart = match rasn::der::decode::<EncAsRepPart>(&plaintext) {
            Ok(enc_as) => enc_as.0,
            Err(_) => {
                let enc_tgs: EncTgsRepPart = rasn::der::decode(&plaintext)?;
                enc_tgs.0
            }
        };

        // Validate the reply
        let now = now_kerberos();
        let canonicalize = self.config.kdc_options.contains(KdcOptions::CANONICALIZE);
        let req_body = self
            .last_req_body
            .as_ref()
            .ok_or(Krb5Error::ReplyValidation("no request body saved"))?;

        validate_as_reply(
            self.nonce,
            req_body,
            rep,
            &enc_part,
            canonicalize,
            self.config.max_clock_skew,
            now,
        )?;

        // MIT fast.c:634-675 `krb5int_fast_verify_nego` — when the KDC sets
        // enc-pa-rep it MUST include a PA-REQ-ENC-PA-REP checksum over the
        // exact last-sent AS-REQ bytes, keyed with usage KRB5_KEYUSAGE_AS_REQ.
        // MIT's verify_key rejects a cksumtype outside the key's enctype
        // family with KRB5_BAD_ENCTYPE; until a checksum-type registry exists
        // we require the profile's mandatory cksumtype (unkeyed cksumtypes
        // are therefore rejected as well).
        if enc_part.flags.contains(TicketFlags::ENC_PA_REP) {
            let pa = enc_part
                .encrypted_pa_data
                .as_ref()
                .and_then(|list| {
                    list.iter()
                        .find(|pa| pa.padata_type == PaDataType::ReqEncPaRep as i32)
                })
                .ok_or(Krb5Error::ReplyValidation("PA-REQ-ENC-PA-REP missing"))?;
            let cksum: Checksum = rasn::der::decode(pa.padata_value.as_ref())?;
            if cksum.cksumtype != profile.checksum_type() {
                return Err(Krb5Error::Crypto(
                    "checksum type does not match reply key enctype".to_string(),
                ));
            }
            profile
                .verify_checksum(
                    &key,
                    key_usage::AS_REQ,
                    &self.last_req_bytes,
                    cksum.checksum.as_ref(),
                )
                .map_err(|_| Krb5Error::ReplyValidation("PA-REQ-ENC-PA-REP checksum mismatch"))?;
        }

        // Build credential
        let credential = Credential {
            client: rep.cname.clone(),
            crealm: String::from_utf8_lossy(rep.crealm.as_bytes()).to_string(),
            server: enc_part.sname.clone(),
            srealm: String::from_utf8_lossy(enc_part.srealm.as_bytes()).to_string(),
            session_key: enc_part.key.clone(),
            times: TicketTimes {
                authtime: enc_part.authtime,
                starttime: enc_part.starttime,
                endtime: enc_part.endtime,
                renew_till: enc_part.renew_till,
            },
            ticket: rep.ticket.clone(),
            flags: enc_part.flags,
            addresses: enc_part.caddr.clone(),
            authdata: None,
        };

        self.credential = Some(credential);
        self.state = AsState::Complete;
        Ok(StepResult::Complete)
    }

    /// Compute salt and s2kparams for reply key derivation.
    ///
    /// Tries AS-REP padata first (PA-ETYPE-INFO2), then falls back to
    /// persisted preauth hint values, then default salt.
    fn compute_reply_key_params(&self, rep: &KdcRep) -> (Vec<u8>, Option<Vec<u8>>) {
        // Try to extract salt and s2kparams from reply padata (PA-ETYPE-INFO2)
        if let Some(ref padata) = rep.padata {
            for pa in padata {
                if pa.padata_type == PaDataType::EtypeInfo2 as i32 {
                    if let Ok(entries) = rasn::der::decode::<Vec<crate::types::EtypeInfo2Entry>>(
                        pa.padata_value.as_ref(),
                    ) {
                        for entry in &entries {
                            if entry.etype == rep.enc_part.etype {
                                // RFC 4120: absent salt means use default salt
                                let salt = match &entry.salt {
                                    Some(s) => s.as_bytes().to_vec(),
                                    None => self.default_salt(),
                                };
                                let s2kparams =
                                    entry.s2kparams.as_ref().map(|p| p.as_ref().to_vec());
                                return (salt, s2kparams);
                            }
                        }
                    }
                }
            }
        }

        // Fall back to persisted preauth hint values (from PREAUTH_REQUIRED)
        if let Some(ref salt) = self.last_preauth_salt {
            return (salt.clone(), self.last_s2kparams.clone());
        }

        // Last resort: compute default salt, use persisted s2kparams
        (self.default_salt(), self.last_s2kparams.clone())
    }

    /// Compute default salt from realm and client principal components.
    fn default_salt(&self) -> Vec<u8> {
        let components: Vec<&[u8]> = self
            .config
            .client
            .name_string
            .iter()
            .map(|s| s.as_bytes())
            .collect();
        default_salt(&self.config.realm, &components)
    }
}

/// Extract the PA-FX-COOKIE value from a KDC error's METHOD-DATA, if present.
fn extract_cookie(e_data: &[u8]) -> Option<Vec<u8>> {
    let method_data: Vec<PaData> = rasn::der::decode(e_data).ok()?;
    let pa = method_data
        .iter()
        .find(|pa| pa.padata_type == PaDataType::FxCookie as i32)?;
    let bytes: &[u8] = pa.padata_value.as_ref();
    Some(bytes.to_vec())
}

/// Convert a `Duration` to `i64` seconds, clamping at `i64::MAX` to avoid overflow.
fn duration_secs_i64(dur: Duration) -> i64 {
    let secs = dur.as_secs();
    if secs > i64::MAX as u64 {
        i64::MAX
    } else {
        secs as i64
    }
}

/// Get current time as KerberosTime (chrono DateTime<FixedOffset> in UTC).
///
/// Truncates to whole seconds — RFC 4120 says implementations SHOULD NOT
/// send fractional seconds in GeneralizedTime, and MIT KDC rejects them.
fn now_kerberos() -> KerberosTime {
    let now = Utc::now();
    // with_nanosecond(0) can only fail if value > 1_999_999_999; 0 always succeeds.
    // unwrap_or keeps sub-second precision as safe fallback (KDC may still accept it).
    let truncated = now.with_nanosecond(0).unwrap_or(now);
    truncated.with_timezone(&UTC_OFFSET)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_defaults() {
        let config = AsExchangeConfig::new(PrincipalName::new_principal("user"), "EXAMPLE.COM");
        assert_eq!(config.realm, "EXAMPLE.COM");
        assert_eq!(config.etypes, vec![18, 17, 20, 19]);
        assert!(config.kdc_options.contains(KdcOptions::FORWARDABLE));
        assert!(config.kdc_options.contains(KdcOptions::RENEWABLE));
        assert!(config.kdc_options.contains(KdcOptions::CANONICALIZE));
        assert!(config.request_pac);
        assert_eq!(config.tkt_lifetime, Duration::from_secs(36000));
        assert_eq!(config.renew_lifetime, Duration::from_secs(604800));
    }

    #[test]
    fn test_config_no_pac() {
        let config =
            AsExchangeConfig::new_no_pac(PrincipalName::new_principal("user"), "EXAMPLE.COM");
        assert!(!config.request_pac);
    }

    #[test]
    fn test_exchange_initial_step_produces_as_req() {
        let config = AsExchangeConfig::new(PrincipalName::new_principal("testuser"), "EXAMPLE.COM");
        let mut exchange = AsExchange::new(config, "password");

        let result = exchange.step(&[]).expect("initial step should succeed");
        match result {
            StepResult::SendToKdc { data, realm } => {
                assert_eq!(realm, "EXAMPLE.COM");
                // Should be a valid AS-REQ
                let as_req: AsReq = rasn::der::decode(&data).expect("should decode as AS-REQ");
                assert_eq!(as_req.0.pvno, 5);
                assert_eq!(as_req.0.msg_type, 10);
                assert_eq!(
                    as_req.0.req_body.realm,
                    GeneralString::from_bytes(b"EXAMPLE.COM").expect("realm")
                );
                // Should have PA-PAC-REQUEST in padata
                let padata = as_req.0.padata.expect("should have padata");
                assert!(padata
                    .iter()
                    .any(|pa| pa.padata_type == PaDataType::PaPacRequest as i32));
                // Nonce should be set
                assert_ne!(as_req.0.req_body.nonce, 0);
                // Etypes should match config
                assert_eq!(as_req.0.req_body.etype, vec![18, 17, 20, 19]);
            }
            StepResult::Complete | StepResult::RetryTcp { .. } => {
                panic!("should not be complete or retry on first step")
            }
        }
    }

    #[test]
    fn test_exchange_preauth_required_produces_enc_timestamp() {
        let config = AsExchangeConfig::new(PrincipalName::new_principal("testuser"), "EXAMPLE.COM");
        let mut exchange = AsExchange::new(config, "password");

        // Initial step
        let _result = exchange.step(&[]).expect("initial step");

        // Build a PREAUTH_REQUIRED error response
        let error_reply = build_preauth_required_error();
        let result = exchange
            .step(&error_reply)
            .expect("should handle PREAUTH_REQUIRED");

        match result {
            StepResult::SendToKdc { data, realm } => {
                assert_eq!(realm, "EXAMPLE.COM");
                // Should be an AS-REQ with PA-ENC-TIMESTAMP
                let as_req: AsReq = rasn::der::decode(&data).expect("should decode as AS-REQ");
                let padata = as_req.0.padata.expect("should have padata");
                assert!(padata
                    .iter()
                    .any(|pa| pa.padata_type == PaDataType::EncTimestamp as i32));
            }
            StepResult::Complete | StepResult::RetryTcp { .. } => {
                panic!("should not be complete or retry after preauth required")
            }
        }
    }

    #[test]
    fn test_exchange_loop_count_exceeded() {
        let config = AsExchangeConfig::new(PrincipalName::new_principal("testuser"), "EXAMPLE.COM");
        let mut exchange = AsExchange::new(config, "password");
        // Set initial step so we're in AwaitReply
        let _result = exchange.step(&[]).expect("initial step");
        exchange.loop_count = MAX_PREAUTH_LOOPS;

        let error_reply = build_preauth_required_error();
        let result = exchange.step(&error_reply);
        assert!(matches!(result, Err(Krb5Error::PreauthLoopExceeded(_))));
    }

    #[test]
    fn test_exchange_empty_reply_rejected() {
        let config = AsExchangeConfig::new(PrincipalName::new_principal("testuser"), "EXAMPLE.COM");
        let mut exchange = AsExchange::new(config, "password");
        let _result = exchange.step(&[]).expect("initial step");

        let result = exchange.step(&[]);
        assert!(matches!(result, Err(Krb5Error::ReplyValidation(_))));
    }

    #[test]
    fn test_exchange_response_too_big_returns_retry_tcp() {
        let config = AsExchangeConfig::new(PrincipalName::new_principal("testuser"), "EXAMPLE.COM");
        let mut exchange = AsExchange::new(config, "password");
        let initial = exchange.step(&[]).expect("initial step");

        // Capture the original request bytes
        let original_data = match &initial {
            StepResult::SendToKdc { data, .. } => data.clone(),
            _ => panic!("expected SendToKdc"),
        };

        let error_reply = build_krb_error(KRB_ERR_RESPONSE_TOO_BIG, None);
        let result = exchange.step(&error_reply).expect("should return RetryTcp");
        match result {
            StepResult::RetryTcp { data, realm } => {
                assert_eq!(realm, "EXAMPLE.COM");
                // RetryTcp should re-emit the exact same request bytes
                assert_eq!(data, original_data);
            }
            other => panic!("expected RetryTcp, got: {other:?}"),
        }
    }

    #[test]
    fn test_exchange_wrong_realm_redirects() {
        let config = AsExchangeConfig::new(PrincipalName::new_principal("testuser"), "EXAMPLE.COM");
        let mut exchange = AsExchange::new(config, "password");
        let _result = exchange.step(&[]).expect("initial step");

        let error_reply = build_krb_error(KDC_ERR_WRONG_REALM, Some("OTHER.REALM"));
        let result = exchange.step(&error_reply).expect("should redirect");
        match result {
            StepResult::SendToKdc { realm, data } => {
                assert_eq!(realm, "OTHER.REALM");
                // Verify the new AS-REQ targets the new realm
                let as_req: AsReq = rasn::der::decode(&data).expect("decode AS-REQ");
                assert_eq!(
                    as_req.0.req_body.realm,
                    GeneralString::from_bytes(b"OTHER.REALM").expect("realm")
                );
            }
            StepResult::Complete | StepResult::RetryTcp { .. } => {
                panic!("should redirect, not complete or retry")
            }
        }
        assert_eq!(exchange.config.realm, "OTHER.REALM");
    }

    #[test]
    fn test_exchange_wrong_realm_same_realm_propagates() {
        let config = AsExchangeConfig::new(PrincipalName::new_principal("testuser"), "EXAMPLE.COM");
        let mut exchange = AsExchange::new(config, "password");
        let _result = exchange.step(&[]).expect("initial step");

        // WRONG_REALM but crealm == current realm → propagate error
        let error_reply = build_krb_error(KDC_ERR_WRONG_REALM, Some("EXAMPLE.COM"));
        let result = exchange.step(&error_reply);
        assert!(matches!(result, Err(Krb5Error::KdcError(_))));
    }

    #[test]
    fn test_exchange_kdc_error_propagated() {
        let config = AsExchangeConfig::new(PrincipalName::new_principal("testuser"), "EXAMPLE.COM");
        let mut exchange = AsExchange::new(config, "password");
        let _result = exchange.step(&[]).expect("initial step");

        // C_PRINCIPAL_UNKNOWN (6)
        let error_reply = build_krb_error(6, None);
        let result = exchange.step(&error_reply);
        match result {
            Err(Krb5Error::KdcError(err)) => {
                assert_eq!(err.error_code, 6);
            }
            other => panic!("expected KdcError, got: {other:?}"),
        }
    }

    /// Helper: build a DER-encoded KRB-ERROR with the given error code.
    /// Build a KRB-ERROR. `server_realm` sets the mandatory `realm` field
    /// (used for WRONG_REALM redirect target).
    fn build_krb_error(error_code: i32, server_realm: Option<&str>) -> Vec<u8> {
        let realm_str = server_realm.unwrap_or("EXAMPLE.COM");
        let now = now_kerberos();
        let krb_error = KrbErrorMsg {
            pvno: 5,
            msg_type: 30,
            ctime: None,
            cusec: None,
            stime: now,
            susec: 0,
            error_code,
            crealm: None,
            cname: None,
            realm: GeneralString::from_bytes(realm_str.as_bytes()).expect("realm"),
            sname: PrincipalName::new_srv_inst("krbtgt", realm_str),
            e_text: None,
            e_data: None,
        };
        rasn::der::encode(&krb_error).expect("encode KRB-ERROR")
    }

    /// Helper: build a DER-encoded KRB-ERROR with PREAUTH_REQUIRED and PA-ETYPE-INFO2.
    fn build_preauth_required_error() -> Vec<u8> {
        use crate::types::EtypeInfo2Entry;

        let entries = vec![EtypeInfo2Entry {
            etype: 18,
            salt: Some(GeneralString::from_bytes(b"EXAMPLE.COMtestuser").expect("salt")),
            s2kparams: None,
        }];
        let etype_info2_der = rasn::der::encode(&entries).expect("encode ETYPE-INFO2");

        let method_data = vec![PaData {
            padata_type: PaDataType::EtypeInfo2 as i32,
            padata_value: etype_info2_der.into(),
        }];
        let e_data = rasn::der::encode(&method_data).expect("encode METHOD-DATA");

        let now = now_kerberos();
        let krb_error = KrbErrorMsg {
            pvno: 5,
            msg_type: 30,
            ctime: None,
            cusec: None,
            stime: now,
            susec: 0,
            error_code: KDC_ERR_PREAUTH_REQUIRED,
            crealm: None,
            cname: None,
            realm: GeneralString::from_bytes(b"EXAMPLE.COM").expect("realm"),
            sname: PrincipalName::new_srv_inst("krbtgt", "EXAMPLE.COM"),
            e_text: None,
            e_data: Some(e_data.into()),
        };
        rasn::der::encode(&krb_error).expect("encode KRB-ERROR")
    }
}
