//! SPNEGO initiator (spnego_gss_init_sec_context:979-1157).

use super::der::put_mech_set;
use super::*;

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
        spnego_context(self.opened, self.inner)
    }

    /// The negotiated mechanism OID (optimistic until the first reply).
    pub fn negotiated_mech(&self) -> Option<&[u8]> {
        self.internal_mech.as_deref()
    }
}
