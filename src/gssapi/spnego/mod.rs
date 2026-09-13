//! RFC 4178 SPNEGO over the RFC 4121 Kerberos mechanism.
//!
//! Modelled on MIT krb5 1.22.2 lib/gssapi/spnego/spnego_mech.c.  The DER
//! codec is hand-written to mirror MIT's k5_der/k5input parser exactly,
//! including its leniency (a non-matching tag leaves the cursor unmoved
//! and is treated as "field absent"; a matched tag with a bad length sets
//! the input's error status).
//!
//! Inner mechanism: krb5 only.  All three Kerberos OIDs (canonical, the
//! pre-RFC `krb5_old`, and the Microsoft "wrong" OID) map to the same
//! mechanism — `gss_mech_set_krb5_both` (krb5/gssapi_krb5.c:178-188).
//!
//! Simplifications vs MIT (flagged in the crate docs):
//! - On mechanism negotiation failure MIT returns GSS_S_BAD_MECH *and*
//!   emits a REJECT NegTokenResp error token; we return the error only.
//! - Likewise a failed peer MIC produces the verify error without an
//!   accompanying error token.
//! - `negState` values other than 0-3 are rejected as defective at the
//!   decoder; MIT stores the raw byte and merely lets comparisons fail.

use crate::error::Krb5Error;
use crate::protocol::Credential;

use super::krb5::{AcceptStep, InitStep, Krb5Acceptor, Krb5Context, Krb5Initiator, MECH_KRB5};
use super::token::{der_taglen, der_value_len, parse_token_header};
use super::GssError;

/// SPNEGO mechanism OID 1.3.6.1.5.5.2.
pub const MECH_SPNEGO: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x02];
/// Pre-RFC Kerberos OID 1.3.5.1.5.2 (gss_mech_krb5_old).
pub const MECH_KRB5_OLD: &[u8] = &[0x2b, 0x05, 0x01, 0x05, 0x02];
/// Microsoft "wrong" Kerberos OID 1.2.840.48018.1.2.2
/// (gss_mech_krb5_wrong).
pub const MECH_KRB5_WRONG: &[u8] = &[0x2a, 0x86, 0x48, 0x82, 0xf7, 0x12, 0x01, 0x02, 0x02];
/// NTLMSSP mechanism OID 1.3.6.1.4.1.311.2.2.10.
pub const MECH_NTLMSSP: &[u8] = &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a];

/// Membership in `gss_mech_set_krb5_both`: all three Kerberos OIDs are
/// aliases of the krb5 mechanism (is_kerb_mech, spnego_mech.c:3814-3823).
pub fn is_kerb_mech(oid: &[u8]) -> bool {
    oid == MECH_KRB5 || oid == MECH_KRB5_OLD || oid == MECH_KRB5_WRONG
}

/// SPNEGO negState values (gssapiP_spnego.h:25-28).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum NegState {
    /// accept-completed
    AcceptCompleted = 0,
    /// accept-incomplete
    AcceptIncomplete = 1,
    /// reject
    Reject = 2,
    /// request-mic
    RequestMic = 3,
}

/// Decoded NegTokenInit (spnego_gss_ctx fields, get_negTokenInit:3407).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NegTokenInit {
    /// MechTypeList as OID contents bytes.
    pub mech_types: Vec<Vec<u8>>,
    /// reqFlags, decoded as `bit_string_byte >> 1`.
    pub req_flags: Option<u8>,
    /// mechToken contents.
    pub mech_token: Option<Vec<u8>>,
    /// mechListMIC contents.
    pub mech_list_mic: Option<Vec<u8>>,
}

/// Decoded NegTokenResp (get_negTokenResp:3480).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NegTokenResp {
    /// negState, when present.
    pub neg_state: Option<NegState>,
    /// supportedMech OID contents, when present.
    pub supported_mech: Option<Vec<u8>>,
    /// responseToken contents, when present.
    pub response_token: Option<Vec<u8>>,
    /// mechListMIC contents, when present (dropped when it equals
    /// responseToken — Windows 2000 quirk, :3525-3536).
    pub mech_list_mic: Option<Vec<u8>>,
}

fn gss(e: GssError) -> Krb5Error {
    Krb5Error::Gss(e)
}

/// MIC exchange state shared by both ends (spnego_gss_ctx_id_rec
/// mic_reqd/mic_sent/mic_rcvd).
#[derive(Default)]
struct MicCtx {
    reqd: bool,
    sent: bool,
    rcvd: bool,
}

/// Outcome of one MIC step.
struct MicOut {
    /// MIC to emit in the outgoing token, if any.
    mic: Option<Vec<u8>>,
    /// send_token verdict — only decided when both MICs are now
    /// exchanged (:575-585): `Some(true)` = NO_TOKEN_SEND (MIC was sent
    /// on a previous pass, no token owed), `Some(false)` =
    /// CONT_TOKEN_SEND (a MIC is owed now).  `None` = untouched.
    no_token_send: Option<bool>,
}

/// handle_mic + process_mic (:539-649).  `mic_in` is the peer's MIC,
/// `send_mechtok` indicates a mechanism token is emitted this pass.
/// On a verify/process error MIT sends a REJECT error token; we return
/// the error only.
fn handle_mic(
    mic: &mut MicCtx,
    ctx: &mut Krb5Context,
    mic_in: Option<&[u8]>,
    send_mechtok: bool,
    der_mech_types: &[u8],
    neg_state: &mut NegState,
) -> Result<MicOut, Krb5Error> {
    if mic_in.is_some() {
        if mic.rcvd {
            // Reject a second MIC (:551-555).
            return Err(gss(GssError::DefectiveToken));
        }
    } else if mic.reqd && !send_mechtok {
        // The final mechanism token must carry the MIC (:556-564).
        return Err(gss(GssError::DefectiveToken));
    }
    // process_mic (:601-649).
    let mut mic_out = None;
    if let Some(m) = mic_in {
        ctx.verify_mic(der_mech_types, m)?; // propagates e.g. BadSig
        mic.reqd = true;
        mic.rcvd = true;
    }
    if mic.reqd && !mic.sent {
        mic_out = Some(ctx.get_mic(der_mech_types)?);
        mic.sent = true;
    }
    let mut verdict = None;
    if mic.sent && mic.rcvd {
        *neg_state = NegState::AcceptCompleted;
        // :578-585 — a MIC owed now means a token must be sent even if
        // step 2 downgraded to NO_TOKEN_SEND.
        verdict = Some(mic_out.is_none());
    } else if mic.reqd {
        *neg_state = NegState::AcceptIncomplete;
    }
    // `!mic.reqd && negState == ACCEPT_COMPLETE` leaves the caller's
    // negState untouched, matching the fallthrough at :589-594.
    Ok(MicOut {
        mic: mic_out,
        no_token_send: verdict,
    })
}

mod acceptor;
mod der;
mod initiator;

pub use acceptor::SpnegoAcceptor;
pub use der::{
    decode_neg_token_init, decode_neg_token_resp, encode_neg_token_init, encode_neg_token_resp,
};
pub use initiator::SpnegoInitiator;
