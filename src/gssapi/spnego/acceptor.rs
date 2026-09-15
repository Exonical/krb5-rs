//! SPNEGO acceptor (spnego_gss_accept_sec_context:1546-1730).

use super::der::{put_mech_set, CTX, TAG_GENERAL_STRING, TAG_HEADER};
use super::*;

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
        spnego_context(self.opened, self.inner)
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
