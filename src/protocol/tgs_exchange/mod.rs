//! TGS exchange state machine.
//!
//! Implements the step-based pattern for obtaining service tickets using
//! a previously acquired TGT. Follows MIT krb5's state machine design
//! with cross-realm referral support.

use std::time::Duration;

use crate::crypto::{find_etype, key_usage};
use crate::types::{
    ApOptions, ApReq, Authenticator, Checksum, EncKdcRepPart, EncryptedData, EncryptionKey,
    KdcOptions, KdcReq, KdcReqBody, KerberosFlags, PaData, PrincipalName, TgsRep, TicketFlags,
};
use crate::Krb5Error;
use chrono::{Timelike, Utc};
use rasn::types::GeneralString;
use zeroize::Zeroizing;

use super::credential::{Credential, TicketTimes};
use super::error_codes::ErrorCode;
use super::fast::{FastMsgType, FastState};
use super::validate::{now_kerberos, time_diff, DEFAULT_MAX_CLOCK_SKEW, UTC_OFFSET};

/// Maximum cross-realm referral hops (matches MIT's KRB5_REFERRAL_MAXHOPS).
const MAX_REFERRAL_HOPS: u32 = 10;

/// KDC error codes used in match patterns.
const KDC_ERR_S_PRINCIPAL_UNKNOWN: i32 = ErrorCode::SPrincipalUnknown as i32;
const KRB_ERR_RESPONSE_TOO_BIG: i32 = ErrorCode::ResponseTooBig as i32;

/// PA-DATA type for PA-TGS-REQ (RFC 4120 §7.5.1).
const PA_TGS_REQ: i32 = 1;

/// PA-PAC-OPTIONS padata type (MS-KILE §2.2.10).
const PA_PAC_OPTIONS: i32 = 167;

/// PA-PAC-OPTIONS flags: Branch Aware (bit 1 = 0x40000000 per MS-KILE §2.2.10).
/// This matches what sspi-rs and Windows clients send for AD interop.
/// Claims (bit 0) would be 0x80000000 — not set here.
const PA_PAC_OPTIONS_FLAGS: [u8; 4] = [0x40, 0x00, 0x00, 0x00];

/// Options controlling TGS exchange behavior.
#[derive(Debug, Clone)]
pub struct TgsOptions {
    /// Whether to attempt referral following (CANONICALIZE flag).
    /// Default: true.
    pub canonicalize: bool,
    /// Whether to request forwardable tickets. Default: true.
    pub forwardable: bool,
    /// Whether to request renewable tickets. Default: true.
    pub renewable: bool,
    /// Preferred encryption types. Default: [AES-256, AES-128].
    pub etypes: Vec<i32>,
    /// Maximum allowed clock skew. Default: 5 minutes.
    pub max_clock_skew: Duration,
    /// Whether to include PA-PAC-OPTIONS (Branch Aware flag). Default: true.
    pub pac_options: bool,
}

impl Default for TgsOptions {
    fn default() -> Self {
        Self {
            canonicalize: true,
            forwardable: true,
            renewable: true,
            etypes: vec![18, 17, 20, 19], // AES-256-SHA1, AES-128-SHA1, AES-256-SHA2, AES-128-SHA2
            max_clock_skew: DEFAULT_MAX_CLOCK_SKEW,
            pac_options: true,
        }
    }
}

/// Result of a single `step()` call.
#[derive(Debug)]
// #[allow] not #[expect]: clippy does not fire this lint here, but suppression
// is kept defensively. Variants carry request payloads by value at step boundaries.
#[allow(clippy::large_enum_variant)]
pub enum TgsStepResult {
    /// Send this DER-encoded TGS-REQ to the KDC for the given realm.
    SendToKdc {
        /// DER-encoded TGS-REQ.
        data: Vec<u8>,
        /// Realm to send to.
        realm: String,
    },
    /// Resend the same request over TCP (response too big for UDP).
    RetryTcp {
        /// DER-encoded TGS-REQ (same bytes).
        data: Vec<u8>,
        /// Realm.
        realm: String,
    },
    /// Exchange complete. Call `credential()` to extract result.
    Complete,
}

/// Internal state of the TGS exchange.
enum TgsState {
    /// Initial state — build and send first TGS-REQ.
    Begin,
    /// Waiting for KDC response.
    AwaitReply {
        /// Which logical state to resume after getting the reply.
        resume: ResumeState,
    },
    /// Exchange complete.
    Complete,
}

/// Which state to resume processing after receiving a KDC reply.
#[derive(Debug, Clone)]
enum ResumeState {
    /// Resume referral processing.
    Referrals {
        realms_seen: Vec<String>,
        referral_count: u32,
    },
    /// Resume non-referral processing.
    NonReferral,
}

/// Step-based TGS exchange state machine: feed each KDC reply to `step`
/// until it returns `TgsStepResult::Complete`.
///
/// # Usage
///
/// ```no_run
/// use krb5_rs::protocol::{Credential, TgsExchange, TgsOptions, TgsStepResult};
/// use krb5_rs::types::PrincipalName;
/// use krb5_rs::Krb5Error;
///
/// # struct Transport;
/// # impl Transport {
/// #     async fn send(&self, _realm: &str, _data: &[u8]) -> Result<Vec<u8>, Krb5Error> {
/// #         Ok(Vec::new())
/// #     }
/// # }
/// # fn get_tgt() -> Credential { unimplemented!() }
/// # async fn run(transport: &Transport) -> Result<(), Krb5Error> {
/// let tgt = get_tgt();
/// let target_service = PrincipalName::new_srv_hst("HTTP", "www.example.com");
/// let mut exchange = TgsExchange::new(tgt, target_service, TgsOptions::default());
/// let mut kdc_reply = Vec::new();
///
/// loop {
///     match exchange.step(&kdc_reply)? {
///         TgsStepResult::SendToKdc { data, realm }
///         | TgsStepResult::RetryTcp { data, realm } => {
///             kdc_reply = transport.send(&realm, &data).await?;
///         }
///         TgsStepResult::Complete => break,
///     }
/// }
///
/// let service_cred = exchange.credential()?;
/// # Ok(())
/// # }
/// ```
pub struct TgsExchange {
    state: TgsState,
    /// TGT currently used for requests (may change during referrals).
    cur_tgt: Credential,
    /// Target service principal.
    target_server: PrincipalName,
    /// Options controlling behavior.
    options: TgsOptions,
    /// Subkey generated for the most recent request.
    subkey: Option<EncryptionKey>,
    /// Nonce for the most recent request.
    nonce: u32,
    /// Most recent DER-encoded TGS-REQ (for RetryTcp re-emit).
    last_req_bytes: Vec<u8>,
    /// Realm we last sent to.
    last_realm: String,
    /// Output credential.
    credential: Option<Credential>,
    /// Whether this was a first referral attempt (for fallback to NonReferral).
    first_referral_attempt: bool,
    /// FAST per-request state (MIT always armors TGS requests with the
    /// implicit ccache==NULL armor, send_tgs.c:178).
    fast_state: FastState,
}

impl TgsExchange {
    /// Create a new TGS exchange.
    ///
    /// `tgt` is the TGT credential from a prior AS exchange.
    /// `target` is the service principal to get a ticket for.
    pub fn new(tgt: Credential, target: PrincipalName, options: TgsOptions) -> Self {
        Self {
            state: TgsState::Begin,
            cur_tgt: tgt,
            target_server: target,
            options,
            subkey: None,
            nonce: 0,
            last_req_bytes: Vec::new(),
            last_realm: String::new(),
            credential: None,
            first_referral_attempt: true,
            fast_state: FastState::new(),
        }
    }

    /// Advance the state machine.
    ///
    /// On the first call, pass an empty slice. On subsequent calls, pass
    /// the KDC's response bytes.
    pub fn step(&mut self, kdc_reply: &[u8]) -> Result<TgsStepResult, Krb5Error> {
        match &self.state {
            TgsState::Begin => self.begin(),
            TgsState::AwaitReply { .. } => self.process_reply(kdc_reply),
            TgsState::Complete => Ok(TgsStepResult::Complete),
        }
    }

    /// Extract the credential after successful completion.
    pub fn credential(&self) -> Result<&Credential, Krb5Error> {
        self.credential
            .as_ref()
            .ok_or(Krb5Error::ReplyValidation("TGS exchange not complete"))
    }

    /// Determine the realm to send TGS-REQs to.
    ///
    /// For `krbtgt/X@Y`, the target realm is X (the realm this TGT grants
    /// access to). For a home-realm TGT `krbtgt/MINE@MINE`, this is MINE.
    /// For a cross-realm TGT `krbtgt/OTHER@MINE`, this is OTHER.
    fn tgt_target_realm(&self) -> String {
        let sname = &self.cur_tgt.server;
        if sname.name_type == 2
            && sname.name_string.len() == 2
            && sname.name_string[0].as_bytes() == b"krbtgt"
        {
            String::from_utf8_lossy(sname.name_string[1].as_bytes()).to_string()
        } else {
            // Fallback to srealm for non-krbtgt credentials
            self.cur_tgt.srealm.clone()
        }
    }

    /// Begin the exchange — send the first TGS-REQ.
    fn begin(&mut self) -> Result<TgsStepResult, Krb5Error> {
        if self.options.canonicalize {
            // Start with referral path
            let realm = self.tgt_target_realm();
            let realms_seen = vec![realm.clone()];
            let tgs_req = self.build_tgs_req(true)?;
            self.state = TgsState::AwaitReply {
                resume: ResumeState::Referrals {
                    realms_seen,
                    referral_count: 0,
                },
            };
            self.last_realm = realm.clone();
            Ok(TgsStepResult::SendToKdc {
                data: tgs_req,
                realm,
            })
        } else {
            // Direct non-referral request
            let realm = self.tgt_target_realm();
            let tgs_req = self.build_tgs_req(false)?;
            self.state = TgsState::AwaitReply {
                resume: ResumeState::NonReferral,
            };
            self.last_realm = realm.clone();
            Ok(TgsStepResult::SendToKdc {
                data: tgs_req,
                realm,
            })
        }
    }

    /// Process a KDC reply.
    fn process_reply(&mut self, kdc_reply: &[u8]) -> Result<TgsStepResult, Krb5Error> {
        if kdc_reply.is_empty() {
            return Err(Krb5Error::ReplyValidation("empty KDC reply"));
        }

        // Extract resume state before processing
        let resume = match &self.state {
            TgsState::AwaitReply { resume } => resume.clone(),
            _ => {
                return Err(Krb5Error::ReplyValidation(
                    "process_reply called in wrong state",
                ))
            }
        };

        // Try to decode as TGS-REP first
        if let Ok(tgs_rep) = rasn::der::decode::<TgsRep>(kdc_reply) {
            if tgs_rep.0.pvno != 5 || tgs_rep.0.msg_type != 13 {
                return Err(Krb5Error::ReplyValidation("invalid TGS-REP pvno/msg_type"));
            }
            let step = self.process_tgs_rep(tgs_rep, resume)?;
            // Only disable fallback after successful decrypt/validation —
            // a malformed TGS-REP must not permanently kill the fallback path.
            self.first_referral_attempt = false;
            return Ok(step);
        }

        // Try to decode as KRB-ERROR
        let krb_error = crate::protocol::kdc_rep::decode_krb_error(kdc_reply)?;

        // MIT gc_via_tkt.c:185-240 — unwrap a FAST-wrapped error so the
        // inner KRB-ERROR code drives handling.
        let fe = self.fast_state.process_error(krb_error)?;
        let krb_error = fe.err;

        match krb_error.error_code {
            KRB_ERR_RESPONSE_TOO_BIG => {
                // Re-emit the same request for TCP retry
                self.state = TgsState::AwaitReply { resume };
                Ok(TgsStepResult::RetryTcp {
                    data: self.last_req_bytes.clone(),
                    realm: self.last_realm.clone(),
                })
            }
            KDC_ERR_S_PRINCIPAL_UNKNOWN
                if self.first_referral_attempt
                    && matches!(resume, ResumeState::Referrals { .. }) =>
            {
                // Fallback to non-referral only when in referral mode.
                // Resend to the same KDC that rejected the request.
                self.first_referral_attempt = false;
                let realm = self.tgt_target_realm();
                let tgs_req = self.build_tgs_req(false)?;
                self.state = TgsState::AwaitReply {
                    resume: ResumeState::NonReferral,
                };
                self.last_realm = realm.clone();
                Ok(TgsStepResult::SendToKdc {
                    data: tgs_req,
                    realm,
                })
            }
            _ => Err(Krb5Error::from_error_msg(krb_error)),
        }
    }

    /// Process a successful TGS-REP.
    fn process_tgs_rep(
        &mut self,
        tgs_rep: TgsRep,
        resume: ResumeState,
    ) -> Result<TgsStepResult, Krb5Error> {
        let rep = &tgs_rep.0;

        // MIT decode_kdc.c:64-76 — process the FAST reply; a missing
        // PA-FX-FAST (KDC without FAST) is tolerated for TGS.
        let (mut rep, strengthen_key) = match self
            .fast_state
            .process_response(rep.padata.as_deref(), &rep.ticket)
        {
            Ok(Some(out)) => {
                let mut rep = rep.clone();
                rep.cname = out.client;
                rep.padata = if out.padata.is_empty() {
                    None
                } else {
                    Some(out.padata)
                };
                (rep, out.strengthen_key)
            }
            Ok(None) => (rep.clone(), None),
            Err(Krb5Error::FastRequired) => (rep.clone(), None),
            Err(e) => return Err(e),
        };
        let rep = &mut rep;

        // Decrypt EncTgsRepPart: try subkey first (usage 9), fallback to session key (usage 8)
        let enc_part = self.decrypt_tgs_rep_enc_part(rep, strengthen_key.as_ref())?;

        // Validate reply
        self.validate_tgs_reply(rep, &enc_part)?;

        // Check if this is a referral TGT or the actual service ticket
        let is_referral = self.is_referral_tgt(&enc_part);

        if is_referral {
            return self.handle_referral(rep, &enc_part, resume);
        }

        // Service ticket — build credential and complete
        self.credential = Some(crate::protocol::kdc_rep::credential_from_rep(
            rep, &enc_part,
        ));
        self.state = TgsState::Complete;
        Ok(TgsStepResult::Complete)
    }

    /// Decrypt the EncTgsRepPart from a TGS-REP.
    ///
    /// Per RFC 4120 and MIT krb5: try subkey first (key usage 9),
    /// then fall back to TGT session key (key usage 8) for Heimdal interop.
    /// A FAST strengthen key folds into each reply key
    /// (decode_kdc.c:64-76).
    fn decrypt_tgs_rep_enc_part(
        &self,
        rep: &crate::types::KdcRep,
        strengthen: Option<&EncryptionKey>,
    ) -> Result<EncKdcRepPart, Krb5Error> {
        let mut candidates: Vec<(EncryptionKey, i32)> = Vec::new();
        if let Some(ref subkey) = self.subkey {
            candidates.push((
                FastState::reply_key(strengthen, subkey)?,
                key_usage::TGS_REP_ENCPART_SUBKEY,
            ));
        }
        candidates.push((
            FastState::reply_key(strengthen, &self.cur_tgt.session_key)?,
            key_usage::TGS_REP_ENCPART_SESSKEY,
        ));
        crate::protocol::kdc_rep::decrypt_enc_kdc_rep_part(
            &candidates,
            &rep.enc_part,
            crate::protocol::kdc_rep::decode_enc_tgs_rep_part,
        )
    }

    /// Validate TGS-REP fields.
    fn validate_tgs_reply(
        &self,
        rep: &crate::types::KdcRep,
        enc_part: &EncKdcRepPart,
    ) -> Result<(), Krb5Error> {
        // Client principal must match the TGT holder
        if rep.cname != self.cur_tgt.client {
            return Err(Krb5Error::ReplyValidation("client principal mismatch"));
        }
        if rep.crealm.as_bytes() != self.cur_tgt.crealm.as_bytes() {
            return Err(Krb5Error::ReplyValidation("client realm mismatch"));
        }

        // Nonce must match
        if enc_part.nonce != self.nonce {
            return Err(Krb5Error::ReplyValidation("nonce mismatch"));
        }

        // Ticket sname must match enc-part sname
        if rep.ticket.sname != enc_part.sname {
            return Err(Krb5Error::ReplyValidation(
                "ticket/enc-part server mismatch",
            ));
        }

        // Ticket realm must match enc-part srealm
        if rep.ticket.realm != enc_part.srealm {
            return Err(Krb5Error::ReplyValidation("ticket/enc-part realm mismatch"));
        }

        // For non-referral replies, the service principal must match what we requested
        // when canonicalization is not in use. With CANONICALIZE, the KDC may return
        // a canonicalized SPN. Referral TGTs are validated in handle_referral().
        if !self.is_referral_tgt(enc_part)
            && !self.options.canonicalize
            && enc_part.sname != self.target_server
        {
            return Err(Krb5Error::ReplyValidation(
                "unexpected service principal in TGS-REP",
            ));
        }

        // Clock skew check: only reject times that are too far in the future.
        // In TGS-REPs, authtime is the time of initial AS authentication and can
        // legitimately be far in the past (e.g., service ticket requested hours
        // after TGT acquisition). We only check that starttime/authtime is not
        // unreasonably ahead of "now".
        let now = now_kerberos();
        let check_time = enc_part.starttime.as_ref().unwrap_or(&enc_part.authtime);
        if *check_time > now {
            let skew = time_diff(check_time, &now);
            if skew > self.options.max_clock_skew {
                return Err(Krb5Error::ClockSkew {
                    max_skew: self.options.max_clock_skew,
                });
            }
        }

        Ok(())
    }

    /// Check if a TGS-REP contains a referral TGT (krbtgt/OTHER-REALM).
    ///
    /// A referral TGT has sname = krbtgt/<REALM> where the realm differs
    /// from what we originally requested. If the response matches our
    /// target service principal, it's not a referral.
    fn is_referral_tgt(&self, enc_part: &EncKdcRepPart) -> bool {
        // Must be NT_SRV_INST with 2 components
        if enc_part.sname.name_type != 2 || enc_part.sname.name_string.len() != 2 {
            return false;
        }
        // First component must be "krbtgt"
        if enc_part.sname.name_string[0].as_bytes() != b"krbtgt" {
            return false;
        }
        // If we requested krbtgt/<REALM> and got exactly that, it's not a referral
        if enc_part.sname == self.target_server {
            return false;
        }
        // It's a krbtgt for a different realm → referral
        true
    }
}

mod request;

#[cfg(test)]
mod tests;
