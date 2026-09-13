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

const TAG_HEADER: u8 = 0x60;
const TAG_OID: u8 = 0x06;
const TAG_OCTET_STRING: u8 = 0x04;
const TAG_SEQUENCE: u8 = 0x30;
const TAG_ENUMERATED: u8 = 0x0a;
const TAG_GENERAL_STRING: u8 = 0x1b;
const TAG_BIT_STRING: u8 = 0x03;
const BIT_STRING_LENGTH: u8 = 0x02;
const BIT_STRING_PADDING: u8 = 0x01;
const CTX: u8 = 0xa0;

fn gss(e: GssError) -> Krb5Error {
    Krb5Error::Gss(e)
}

/// Cursor over a DER buffer mirroring MIT's `struct k5input`
/// (k5-der.h): `bad` is the sticky error status set when a read runs past
/// the end or a matched tag has an invalid length.
struct In<'a> {
    buf: &'a [u8],
    bad: bool,
}

impl<'a> In<'a> {
    fn new(buf: &'a [u8]) -> Self {
        In { buf, bad: false }
    }

    /// k5_der_get_taglen + k5_input_get_bytes: if the next byte matches
    /// `tag` and the definite length is valid and in-bounds, consume and
    /// return the contents.  On tag mismatch, return None *without*
    /// consuming or erroring (k5-der.h:118-120).  A matched tag with a
    /// truncated length/value sets `bad` (k5-der.h:123-143).
    fn value(&mut self, tag: u8) -> Option<&'a [u8]> {
        if self.bad || self.buf.first() != Some(&tag) {
            return None;
        }
        self.buf = &self.buf[1..];
        let lenbyte = *self.buf.first().unwrap_or(&0);
        if self.buf.is_empty() {
            self.bad = true;
            return None;
        }
        self.buf = &self.buf[1..];
        let len = if lenbyte < 0x80 {
            lenbyte as usize
        } else {
            let n = (lenbyte & 0x7f) as usize;
            let mut len: usize = 0;
            for _ in 0..n {
                match self.buf.first() {
                    Some(&b) => {
                        match len.checked_mul(256).and_then(|l| l.checked_add(b as usize)) {
                            Some(l) => len = l,
                            None => {
                                self.bad = true;
                                return None;
                            }
                        }
                        self.buf = &self.buf[1..];
                    }
                    None => {
                        self.bad = true;
                        return None;
                    }
                }
            }
            len
        };
        if len > self.buf.len() {
            self.bad = true;
            return None;
        }
        let (v, rest) = self.buf.split_at(len);
        self.buf = rest;
        Some(v)
    }

    fn status(&self) -> bool {
        self.bad
    }
}

/// put_mech_set (:3353-3380): `SEQUENCE OF OID` — the contents of the
/// NegTokenInit [0] field, and the exact blob mechListMIC covers.
fn put_mech_set(mechs: &[Vec<u8>]) -> Vec<u8> {
    let ilen: usize = mechs.iter().map(|o| der_value_len(o.len())).sum();
    let mut out = Vec::new();
    der_taglen(&mut out, TAG_SEQUENCE, ilen);
    for o in mechs {
        der_taglen(&mut out, TAG_OID, o.len());
        out.extend_from_slice(o);
    }
    out
}

/// Decode a `SEQUENCE OF OID` into OID contents vectors.  Mirrors
/// get_mech_set (:3320-3350): the SEQUENCE OF tag is required; every
/// element must be an OID TLV; anything else fails the whole decode
/// (GSS_S_FAILURE in MIT).
fn get_mech_set(field: &[u8]) -> Option<Vec<Vec<u8>>> {
    let mut input = In::new(field);
    let mut seq = In::new(input.value(TAG_SEQUENCE)?);
    let mut mechs = Vec::new();
    while !seq.status() && !seq.buf.is_empty() {
        mechs.push(seq.value(TAG_OID)?.to_vec());
    }
    if seq.status() {
        return None;
    }
    Some(mechs)
}

/// make_spnego_tokenInit_msg (:3618-3700): RFC 2743 framing with
/// MECH_SPNEGO around `[0] { SEQUENCE { [0] mechTypes, [2] mechToken,
/// [3] mechListMIC } }`.  `der_mech_types` is the contents of [0], i.e.
/// the `SEQUENCE OF OID` TLV.  reqFlags is never emitted.  When
/// `neg_hints_compat` is set, the [3] value uses a SEQUENCE tag instead
/// of OCTET STRING (:3688-3693).
pub fn encode_neg_token_init(
    der_mech_types: &[u8],
    mech_token: Option<&[u8]>,
    mic: Option<&[u8]>,
    neg_hints_compat: bool,
) -> Vec<u8> {
    let mut fields = Vec::new();
    der_taglen(&mut fields, CTX, der_mech_types.len());
    fields.extend_from_slice(der_mech_types);
    if let Some(tok) = mech_token {
        der_taglen(&mut fields, CTX | 0x02, der_value_len(tok.len()));
        der_taglen(&mut fields, TAG_OCTET_STRING, tok.len());
        fields.extend_from_slice(tok);
    }
    if let Some(m) = mic {
        der_taglen(&mut fields, CTX | 0x03, der_value_len(m.len()));
        let id = if neg_hints_compat {
            TAG_SEQUENCE
        } else {
            TAG_OCTET_STRING
        };
        der_taglen(&mut fields, id, m.len());
        fields.extend_from_slice(m);
    }
    let mut choice = Vec::new();
    der_taglen(&mut choice, TAG_SEQUENCE, fields.len());
    choice.extend_from_slice(&fields);

    let mut body = Vec::new();
    der_taglen(&mut body, CTX, choice.len());
    body.extend_from_slice(&choice);

    let mut out = Vec::new();
    der_taglen(
        &mut out,
        TAG_HEADER,
        der_value_len(MECH_SPNEGO.len()) + body.len(),
    );
    der_taglen(&mut out, TAG_OID, MECH_SPNEGO.len());
    out.extend_from_slice(MECH_SPNEGO);
    out.extend_from_slice(&body);
    out
}

/// make_spnego_tokenTarg_msg (:3702-3786): unframed
/// `[1] { SEQUENCE { [0] ENUMERATED negState, [1] OID supportedMech,
/// [2] OCTET STRING responseToken, [3] OCTET STRING mechListMIC } }`.
/// supportedMech is emitted only when given (callers pass it on the
/// INIT_TOKEN_SEND reply); an empty responseToken is omitted (:3737).
pub fn encode_neg_token_resp(
    state: NegState,
    supported_mech: Option<&[u8]>,
    token: Option<&[u8]>,
    mic: Option<&[u8]>,
) -> Vec<u8> {
    let mut fields = Vec::new();
    der_taglen(&mut fields, CTX, der_value_len(1));
    der_taglen(&mut fields, TAG_ENUMERATED, 1);
    fields.push(state as u8);
    if let Some(m) = supported_mech {
        der_taglen(&mut fields, CTX | 0x01, der_value_len(m.len()));
        der_taglen(&mut fields, TAG_OID, m.len());
        fields.extend_from_slice(m);
    }
    if let Some(t) = token {
        if !t.is_empty() {
            der_taglen(&mut fields, CTX | 0x02, der_value_len(t.len()));
            der_taglen(&mut fields, TAG_OCTET_STRING, t.len());
            fields.extend_from_slice(t);
        }
    }
    if let Some(m) = mic {
        der_taglen(&mut fields, CTX | 0x03, der_value_len(m.len()));
        der_taglen(&mut fields, TAG_OCTET_STRING, m.len());
        fields.extend_from_slice(m);
    }
    let mut out = Vec::new();
    der_taglen(&mut out, CTX | 0x01, der_value_len(fields.len()));
    der_taglen(&mut out, TAG_SEQUENCE, fields.len());
    out.extend_from_slice(&fields);
    out
}

/// get_negTokenInit (:3407-3478).  `tok` must carry RFC 2743 framing with
/// the SPNEGO OID.  Returns the decoded token plus the exact contents of
/// the [0] mechTypes field (the `SEQUENCE OF` TLV — the MIC input).
pub fn decode_neg_token_init(tok: &[u8]) -> Result<(NegTokenInit, Vec<u8>), GssError> {
    let mut input = In::new(tok);
    // verify_token_header (:3790-3805): framing + thisMech == SPNEGO.
    let mut framed = In::new(input.value(TAG_HEADER).ok_or(GssError::DefectiveToken)?);
    if input.status() {
        return Err(GssError::DefectiveToken);
    }
    let oid = framed.value(TAG_OID).ok_or(GssError::DefectiveToken)?;
    if oid != MECH_SPNEGO {
        return Err(GssError::DefectiveToken);
    }

    let mut seq = In::new(framed.value(CTX).ok_or(GssError::DefectiveToken)?);
    let mut seq = In::new(seq.value(TAG_SEQUENCE).ok_or(GssError::DefectiveToken)?);

    let field = seq.value(CTX).ok_or(GssError::DefectiveToken)?;
    if field.is_empty() {
        return Err(GssError::DefectiveToken);
    }
    let der_mech_types = field.to_vec();
    // get_mech_set failure is GSS_S_FAILURE in MIT (:3448-3451).
    let mech_types = get_mech_set(field).ok_or(GssError::Failure)?;

    let mut req_flags = None;
    if let Some(f) = seq.value(CTX | 0x01) {
        // get_req_flags (:3393-3401): contents are exactly
        // 03 02 01 <flags-byte>; flags = byte >> 1.
        if f.len() != 4
            || f[0] != TAG_BIT_STRING
            || f[1] != BIT_STRING_LENGTH
            || f[2] != BIT_STRING_PADDING
        {
            return Err(GssError::DefectiveToken);
        }
        req_flags = Some(f[3] >> 1);
    }
    let mut mech_token = None;
    if let Some(f) = seq.value(CTX | 0x02) {
        // get_octet_string failure is GSS_S_FAILURE here (:3457-3460).
        mech_token = Some(
            In::new(f)
                .value(TAG_OCTET_STRING)
                .ok_or(GssError::Failure)?
                .to_vec(),
        );
    }
    let mut mech_list_mic = None;
    if let Some(f) = seq.value(CTX | 0x03) {
        mech_list_mic = Some(
            In::new(f)
                .value(TAG_OCTET_STRING)
                .ok_or(GssError::Failure)?
                .to_vec(),
        );
    }
    if seq.status() {
        return Err(GssError::DefectiveToken);
    }
    Ok((
        NegTokenInit {
            mech_types,
            req_flags,
            mech_token,
            mech_list_mic,
        },
        der_mech_types,
    ))
}

/// get_negTokenResp (:3480-3548).  `body` is the unframed NegTokenResp
/// (the `[1]` choice); callers strip optional RFC 2743 framing first.
pub fn decode_neg_token_resp(body: &[u8]) -> Result<NegTokenResp, GssError> {
    let mut input = In::new(body);
    let mut seq = In::new(input.value(CTX | 0x01).ok_or(GssError::DefectiveToken)?);
    // Historically the SEQUENCE tag may be missing (:3494-3496).
    if let Some(inner) = seq.value(TAG_SEQUENCE) {
        seq = In::new(inner);
    }

    let mut neg_state = None;
    if let Some(f) = seq.value(CTX) {
        let en = In::new(f)
            .value(TAG_ENUMERATED)
            .ok_or(GssError::DefectiveToken)?;
        if en.len() != 1 {
            return Err(GssError::DefectiveToken);
        }
        neg_state = Some(match en[0] {
            0 => NegState::AcceptCompleted,
            1 => NegState::AcceptIncomplete,
            2 => NegState::Reject,
            3 => NegState::RequestMic,
            // MIT stores the raw byte and only compares it; we reject
            // out-of-range values at the decoder (documented divergence).
            _ => return Err(GssError::DefectiveToken),
        });
    }
    let mut supported_mech = None;
    if let Some(f) = seq.value(CTX | 0x01) {
        supported_mech = Some(
            In::new(f)
                .value(TAG_OID)
                .ok_or(GssError::DefectiveToken)?
                .to_vec(),
        );
    }
    let mut response_token = None;
    if let Some(f) = seq.value(CTX | 0x02) {
        response_token = Some(
            In::new(f)
                .value(TAG_OCTET_STRING)
                .ok_or(GssError::DefectiveToken)?
                .to_vec(),
        );
    }
    let mut mech_list_mic = None;
    if let Some(f) = seq.value(CTX | 0x03) {
        // MIT dereferences the NULL result here when responseToken is
        // present (:3527-3530); we return DefectiveToken instead.
        match In::new(f).value(TAG_OCTET_STRING) {
            Some(m) => mech_list_mic = Some(m.to_vec()),
            None if response_token.is_some() => return Err(GssError::DefectiveToken),
            None => {}
        }
    }
    // Windows 2000 duplicate-response-token quirk (:3525-3536).
    if let (Some(tok_v), Some(mic_v)) = (&response_token, &mech_list_mic) {
        if tok_v == mic_v {
            mech_list_mic = None;
        }
    }
    if seq.status() {
        return Err(GssError::DefectiveToken);
    }
    Ok(NegTokenResp {
        neg_state,
        supported_mech,
        response_token,
        mech_list_mic,
    })
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

/// SPNEGO initiator (spnego_gss_init_sec_context:979-1157).
///
/// `new` takes the inner Kerberos initiator and the ordered mechanism
/// list; non-Kerberos mechanisms preceding the first Kerberos OID are
/// dropped (we cannot initiate them), exactly like MIT's
/// init_ctx_call_init fallback (:940-960), and the advertised
/// mechTypes is re-encoded without them.
pub struct SpnegoInitiator {
    inner: Option<Krb5Initiator>,
    mech_types: Vec<Vec<u8>>,
    der_mech_types: Vec<u8>,
    internal_mech: Option<Vec<u8>>,
    mech_complete: bool,
    nego_done: bool,
    mic: MicCtx,
    opened: bool,
    /// First call not yet made.
    fresh: bool,
}

impl SpnegoInitiator {
    /// Create an initiator.  `mech_types` is the advertised order; the
    /// first Kerberos OID in it is used optimistically.
    pub fn new(inner: Krb5Initiator, mech_types: Vec<Vec<u8>>) -> Self {
        SpnegoInitiator {
            inner: Some(inner),
            mech_types,
            der_mech_types: Vec::new(),
            internal_mech: None,
            mech_complete: false,
            nego_done: false,
            mic: MicCtx::default(),
            opened: false,
            fresh: true,
        }
    }

    /// Drive the exchange one step (init_ctx_new / init_ctx_cont /
    /// init_ctx_call_init / handle_mic).
    pub fn step(&mut self, input: Option<&[u8]>) -> Result<InitStep, Krb5Error> {
        let mut send_cont = false; // send_token == CONT_TOKEN_SEND
        let mut send_init = false; // send_token == INIT_TOKEN_SEND
        let mut no_token_send = false;
        let mut mechtok_out: Option<Vec<u8>> = None;
        let mut mic_out: Option<Vec<u8>> = None;
        let mut acc_neg_state: Option<NegState> = None;
        let mut resp: Option<NegTokenResp> = None;

        // Step 1: mechanism negotiation.
        if self.fresh {
            self.fresh = false;
            // init_ctx_call_init fallback: drop leading mechs we cannot
            // initiate (non-kerb) and re-encode the advertised list.
            let pos = self
                .mech_types
                .iter()
                .position(|o| is_kerb_mech(o))
                .ok_or_else(|| gss(GssError::BadMech))?;
            self.mech_types.drain(..pos);
            self.internal_mech = Some(self.mech_types[0].clone());
            self.der_mech_types = put_mech_set(&self.mech_types);
            send_init = true;
        } else {
            let body = input.ok_or_else(|| gss(GssError::DefectiveToken))?;
            // MIT's initiator does NOT accept a framed NegTokenResp.
            let r = decode_neg_token_resp(body).map_err(gss)?;
            acc_neg_state = r.neg_state;
            // REJECT with no error token (:715-724).
            if r.neg_state == Some(NegState::Reject) && r.response_token.is_none() {
                return Err(gss(if !self.nego_done {
                    GssError::BadMech
                } else {
                    GssError::Failure
                }));
            }
            if !self.nego_done {
                // init_ctx_nego (:763-833).
                let supported = r
                    .supported_mech
                    .clone()
                    .unwrap_or_else(|| self.internal_mech.clone().unwrap_or_default());
                let internal = self.internal_mech.clone().unwrap_or_default();
                if !(is_kerb_mech(&supported) && is_kerb_mech(&internal)) && supported != internal {
                    // init_ctx_reselect (:836-877).
                    if !self.mech_types.contains(&supported) {
                        return Err(gss(GssError::DefectiveToken));
                    }
                    match r.neg_state {
                        // ACCEPT_INCOMPLETE tolerated only for NTLMSSP
                        // (:857-868).
                        Some(NegState::AcceptIncomplete) if supported == MECH_NTLMSSP => {}
                        Some(NegState::RequestMic) => {}
                        _ => return Err(gss(GssError::DefectiveToken)),
                    }
                    self.mech_complete = false;
                    self.mic.reqd = r.neg_state == Some(NegState::RequestMic);
                    self.internal_mech = Some(supported.clone());
                    // Reselecting a non-krb5 mech cannot succeed: we have
                    // no initiator for it (MIT's gss_init_sec_context
                    // fails with GSS_S_BAD_MECH for an unknown mech).
                    if !is_kerb_mech(&supported) {
                        return Err(gss(GssError::BadMech));
                    }
                    send_cont = true;
                } else if r.response_token.is_none() {
                    if self.mech_complete {
                        no_token_send = true;
                    } else {
                        return Err(gss(GssError::DefectiveToken));
                    }
                } else if r.response_token.as_deref() == Some(b"") && self.mech_complete {
                    no_token_send = true; // old IIS empty-token quirk
                } else if self.mech_complete {
                    return Err(gss(GssError::DefectiveToken));
                } else {
                    send_cont = true;
                }
                self.nego_done = true;
            } else if self.mech_complete == r.response_token.is_some() {
                // Later replies: (!complete && no token) ||
                // (complete && token) → defective (:728-733).
                return Err(gss(GssError::DefectiveToken));
            } else if !self.mech_complete || (self.mic.reqd && self.integ()) {
                send_cont = true;
            } else {
                no_token_send = true;
            }
            resp = Some(r);
        }

        // Step 2: invoke the inner krb5 mechanism (:1063-1074).
        if !self.mech_complete {
            let mechtok_in = resp.as_ref().and_then(|r| r.response_token.clone());
            let inner = self
                .inner
                .as_mut()
                .ok_or_else(|| gss(GssError::NoContext))?;
            let out = inner.step(mechtok_in.as_deref())?;
            match out {
                InitStep::Continue(t) => mechtok_out = Some(t),
                InitStep::Complete(t) => {
                    self.mech_complete = true;
                    mechtok_out = t;
                    if send_cont
                        && mechtok_out.as_deref().unwrap_or(&[]).is_empty()
                        && !(self.mic.reqd && self.integ())
                    {
                        // :931-935 — even number of token exchanges.
                        send_cont = false;
                        no_token_send = true;
                    }
                }
            }
            // An acceptor error token the mech didn't flag (:917-922).
            if acc_neg_state == Some(NegState::Reject) {
                return Err(gss(GssError::DefectiveToken));
            }
        }

        // Step 3: MICs (:1079-1091).
        let mut neg_state = NegState::AcceptIncomplete;
        if self.mech_complete && self.integ() {
            let mic_in = resp.as_ref().and_then(|r| r.mech_list_mic.clone());
            let send_mechtok = mechtok_out.as_deref().is_some_and(|t| !t.is_empty());
            let ctx = self
                .inner
                .as_mut()
                .and_then(|i| i.ctx_mut())
                .ok_or_else(|| gss(GssError::NoContext))?;
            let out = handle_mic(
                &mut self.mic,
                ctx,
                mic_in.as_deref(),
                send_mechtok,
                &self.der_mech_types,
                &mut neg_state,
            )?;
            mic_out = out.mic;
            if let Some(nts) = out.no_token_send {
                no_token_send = nts;
                send_cont = !nts;
            }
        }

        // Output (:1095-1136).  Complete iff NO_TOKEN_SEND or the outgoing
        // negState reached ACCEPT_COMPLETE.
        let complete = no_token_send || neg_state == NegState::AcceptCompleted;
        if complete {
            self.opened = true;
        }
        if send_init {
            let tok = encode_neg_token_init(
                &self.der_mech_types,
                mechtok_out.as_deref(),
                mic_out.as_deref(),
                false,
            );
            return Ok(if complete {
                InitStep::Complete(Some(tok))
            } else {
                InitStep::Continue(tok)
            });
        }
        let tok = if send_cont {
            Some(encode_neg_token_resp(
                neg_state,
                None,
                mechtok_out.as_deref(),
                mic_out.as_deref(),
            ))
        } else {
            None
        };
        Ok(if complete {
            InitStep::Complete(tok)
        } else {
            InitStep::Continue(tok.unwrap_or_default())
        })
    }

    /// Whether the context flags carry INTEG — our krb5 mechanism always
    /// sets it (krb5.rs forces CONF|INTEG), like init_ctx_call_init:893.
    fn integ(&self) -> bool {
        true
    }

    /// Extract the established context; fails while the SPNEGO exchange
    /// is incomplete.
    pub fn context(self) -> Result<Krb5Context, Krb5Error> {
        if !self.opened {
            return Err(gss(GssError::NoContext));
        }
        let mut ctx = self
            .inner
            .ok_or_else(|| gss(GssError::NoContext))?
            .context()?;
        ctx.clear_prot_ready();
        Ok(ctx)
    }

    /// The negotiated mechanism OID (optimistic until the first reply).
    pub fn negotiated_mech(&self) -> Option<&[u8]> {
        self.internal_mech.as_deref()
    }
}

/// SPNEGO acceptor (spnego_gss_accept_sec_context:1546-1730).
pub struct SpnegoAcceptor {
    inner: Option<Krb5Acceptor>,
    /// The acceptor's supported mechanism list (advertised in NegHints).
    mech_types: Vec<Vec<u8>>,
    der_mech_types: Vec<u8>,
    /// Echoed as supportedMech; may be MECH_KRB5_WRONG.
    internal_mech: Option<Vec<u8>>,
    mech_complete: bool,
    mic: MicCtx,
    opened: bool,
    /// True while no NegTokenInit has been accepted (covers the
    /// post-NegHints state — MIT discards the hints context, so the next
    /// token is parsed as a fresh NegTokenInit either way).
    first: bool,
    /// True until the first reply has been emitted (supportedMech is
    /// sent only with INIT_TOKEN_SEND).
    send_supported_mech: bool,
}

/// NegHints GeneralString contents (make_NegHints:1177).
const HINT_NAME: &[u8] = b"not_defined_in_RFC4178@please_ignore";

impl SpnegoAcceptor {
    /// Create an acceptor over the inner Kerberos acceptor; `mech_types`
    /// is the acceptor's supported list (e.g. `[MECH_KRB5]`).
    pub fn new(inner: Krb5Acceptor, mech_types: Vec<Vec<u8>>) -> Self {
        SpnegoAcceptor {
            inner: Some(inner),
            mech_types,
            der_mech_types: Vec::new(),
            internal_mech: None,
            mech_complete: false,
            mic: MicCtx::default(),
            opened: false,
            first: true,
            send_supported_mech: false,
        }
    }

    /// Process one input token (acc_ctx_hints / acc_ctx_new /
    /// acc_ctx_cont / acc_ctx_call_acc / handle_mic).
    pub fn step(&mut self, input: &[u8]) -> Result<AcceptStep, Krb5Error> {
        let mut neg_state;
        let mut send_init = false; // INIT_TOKEN_SEND
        let mut send_cont = false; // CONT_TOKEN_SEND
        let mut mechtok_in: Option<Vec<u8>> = None;
        let mut mic_in: Option<Vec<u8>> = None;
        let mut hints = false;

        if self.first && input.is_empty() {
            // acc_ctx_hints (:1227-1278): NegHints compatibility reply.
            hints = true;
            neg_state = NegState::AcceptIncomplete;
            send_init = true;
            self.der_mech_types = put_mech_set(&self.mech_types);
        } else if self.first || self.internal_mech.is_none() {
            // acc_ctx_new (:1283-1358).
            self.first = false;
            let (init, der) = decode_neg_token_init(input).map_err(gss)?;
            // negotiate_mech (:3551-3581): only the MS wrong OID is
            // mapped to krb5; a match at index 0 → ACCEPT_INCOMPLETE,
            // later → REQUEST_MIC.
            let mut found: Option<(usize, Vec<u8>)> = None;
            for (i, oid) in init.mech_types.iter().enumerate() {
                let wrong = oid.as_slice() == MECH_KRB5_WRONG;
                let mapped: &[u8] = if wrong { MECH_KRB5 } else { oid };
                if self.mech_types.iter().any(|o| o == mapped) {
                    let echo = if wrong { oid.clone() } else { mapped.to_vec() };
                    found = Some((i, echo));
                    break;
                }
            }
            let Some((idx, echo)) = found else {
                // MIT also emits a REJECT error token; we return only
                // the error.
                return Err(gss(GssError::BadMech));
            };
            neg_state = if idx == 0 {
                NegState::AcceptIncomplete
            } else {
                NegState::RequestMic
            };
            self.internal_mech = Some(echo);
            self.der_mech_types = der;
            if neg_state == NegState::RequestMic {
                self.mic.reqd = true;
            }
            send_init = true;
            self.send_supported_mech = true;
            mechtok_in = init.mech_token;
            mic_in = init.mech_list_mic;
        } else {
            // acc_ctx_cont (:1361-1419): NegTokenResp, optionally framed
            // with the SPNEGO OID (old Sun compatibility).
            let body: &[u8] = if input.first() == Some(&TAG_HEADER) {
                match parse_token_header(input) {
                    Some((mech, b)) if mech == MECH_SPNEGO => b,
                    _ => return Err(gss(GssError::DefectiveToken)),
                }
            } else {
                input
            };
            let r = decode_neg_token_resp(body).map_err(gss)?;
            if r.response_token.is_none() && r.mech_list_mic.is_none() {
                return Err(gss(GssError::DefectiveToken));
            }
            if r.supported_mech.is_some() {
                return Err(gss(GssError::DefectiveToken));
            }
            neg_state = NegState::AcceptIncomplete;
            send_cont = true;
            mechtok_in = r.response_token;
            mic_in = r.mech_list_mic;
        }

        // Step 2: invoke the inner mech (:1660-1671).
        let mut mechtok_out: Option<Vec<u8>> = None;
        if neg_state != NegState::RequestMic {
            if let Some(tok) = mechtok_in {
                // acc_ctx_vfy_oid (:1424-1468): the mechToken's framing
                // OID must equal internal_mech or be a krb5 alias.
                let (mechoid, _b) =
                    parse_token_header(&tok).ok_or_else(|| gss(GssError::DefectiveToken))?;
                let internal = self.internal_mech.clone().unwrap_or_default();
                if mechoid != internal && !(is_kerb_mech(&internal) && is_kerb_mech(mechoid)) {
                    return Err(gss(GssError::BadMech));
                }
                let inner = self
                    .inner
                    .as_mut()
                    .ok_or_else(|| gss(GssError::NoContext))?;
                match inner.step(&tok)? {
                    AcceptStep::Complete { token } => {
                        self.mech_complete = true;
                        mechtok_out = token;
                        if !self.mic.reqd || !self.integ() {
                            neg_state = NegState::AcceptCompleted;
                        }
                    }
                    AcceptStep::ContinueNeeded(t) => {
                        mechtok_out = Some(t);
                    }
                }
            }
        }

        // Step 3: MICs (:1673-1681).
        let mut mic_out: Option<Vec<u8>> = None;
        let mut no_token_send = false;
        if self.mech_complete && self.integ() {
            let send_mechtok = mechtok_out.as_deref().is_some_and(|t| !t.is_empty());
            let ctx = self
                .inner
                .as_mut()
                .and_then(|a| a.ctx_mut())
                .ok_or_else(|| gss(GssError::NoContext))?;
            let out = handle_mic(
                &mut self.mic,
                ctx,
                mic_in.as_deref(),
                send_mechtok,
                &self.der_mech_types,
                &mut neg_state,
            )?;
            mic_out = out.mic;
            if let Some(nts) = out.no_token_send {
                no_token_send = nts;
                if !nts {
                    send_cont = true;
                    send_init = false;
                }
            }
        }

        // Output (:1685-1700).
        let complete = neg_state == NegState::AcceptCompleted;
        if complete {
            self.opened = true;
        }
        let token = if hints {
            // NegHints blob: [0] { GeneralString hint } carried in the
            // [3] slot under a SEQUENCE tag (make_NegHints:1172-1204 +
            // negHintsCompat at :3688-3693).
            let mut hint = Vec::new();
            der_taglen(&mut hint, CTX, der_value_len(HINT_NAME.len()));
            der_taglen(&mut hint, TAG_GENERAL_STRING, HINT_NAME.len());
            hint.extend_from_slice(HINT_NAME);
            Some(encode_neg_token_init(
                &self.der_mech_types,
                None,
                Some(&hint),
                true,
            ))
        } else if (send_init || send_cont) && !no_token_send {
            let supported = if self.send_supported_mech && send_init {
                self.internal_mech.as_deref()
            } else {
                None
            };
            self.send_supported_mech = false;
            Some(encode_neg_token_resp(
                neg_state,
                supported,
                mechtok_out.as_deref(),
                mic_out.as_deref(),
            ))
        } else {
            None
        };
        Ok(if complete {
            AcceptStep::Complete { token }
        } else {
            AcceptStep::ContinueNeeded(token.unwrap_or_default())
        })
    }

    /// Whether the context flags carry INTEG — our krb5 mechanism always
    /// sets it.
    fn integ(&self) -> bool {
        true
    }

    /// Extract the established context; fails while the SPNEGO exchange
    /// is incomplete.
    pub fn context(self) -> Result<Krb5Context, Krb5Error> {
        if !self.opened {
            return Err(gss(GssError::NoContext));
        }
        let mut ctx = self
            .inner
            .ok_or_else(|| gss(GssError::NoContext))?
            .context()?;
        ctx.clear_prot_ready();
        Ok(ctx)
    }

    /// Delegated credentials received by the inner mechanism, if any.
    pub fn delegated_creds(&self) -> Option<&[Credential]> {
        self.inner.as_ref().and_then(|a| a.delegated_creds())
    }

    /// The negotiated mechanism OID as echoed in supportedMech.
    pub fn negotiated_mech(&self) -> Option<&[u8]> {
        self.internal_mech.as_deref()
    }
}
