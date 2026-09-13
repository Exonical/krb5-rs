//! Initiator-side context establishment (init_sec_context.c).

use super::*;

/// Initiator-side context establishment (init_sec_context.c
/// kg_new_connection / mutual_auth).
pub struct Krb5Initiator {
    cred: Credential,
    tgt: Option<Credential>,
    req_flags: GssFlags,
    cb: Option<ChannelBindings>,
    ac: Option<AuthContext>,
    gss_flags: GssFlags,
    ctx: Option<Krb5Context>,
    /// Set after the AP-REQ is emitted; `step` then expects the AP-REP.
    awaiting_rep: bool,
    done: bool,
}

impl Krb5Initiator {
    /// Create an initiator (init_sec_context.c:461-688).
    ///
    /// `cred` is the service ticket; `tgt` is the credential to forward when
    /// DELEG applies.  Deviation: MIT obtains a *forwarded* TGT from the KDC
    /// (krb5_fwd_tgt_creds, a FORWARDED TGS-REQ); we forward `tgt` as
    /// supplied.
    pub fn new(
        cred: Credential,
        tgt: Option<Credential>,
        req_flags: GssFlags,
        cb: Option<ChannelBindings>,
    ) -> Result<Self, Krb5Error> {
        // init_sec_context.c:546-553 — CHANNEL_BOUND is never put on the
        // wire; it only arms the cbt AP_OPTIONS authdata.
        let mut gss_flags = req_flags
            & (GssFlags::CONF
                | GssFlags::INTEG
                | GssFlags::MUTUAL
                | GssFlags::REPLAY
                | GssFlags::SEQUENCE
                | GssFlags::DELEG
                | GssFlags::DCE_STYLE
                | GssFlags::IDENTIFY
                | GssFlags::EXTENDED_ERROR);
        gss_flags |= GssFlags::TRANS | GssFlags::CONF | GssFlags::INTEG;
        // :584-586 — DELEG_POLICY promotes to DELEG only with OK_AS_DELEGATE.
        if req_flags.contains(GssFlags::DELEG_POLICY)
            && cred.flags.contains(TicketFlags::OK_AS_DELEGATE)
        {
            gss_flags |= GssFlags::DELEG | GssFlags::DELEG_POLICY;
        }
        if gss_flags.contains(GssFlags::DELEG) && tgt.is_none() {
            gss_flags.remove(GssFlags::DELEG | GssFlags::DELEG_POLICY);
        }
        Ok(Krb5Initiator {
            cred,
            tgt,
            req_flags,
            cb,
            ac: None,
            gss_flags,
            ctx: None,
            awaiting_rep: false,
            done: false,
        })
    }

    /// Drive the exchange one step.
    pub fn step(&mut self, input: Option<&[u8]>) -> Result<InitStep, Krb5Error> {
        if self.done {
            return Err(gss(GssError::ContextEstablished));
        }
        if !self.awaiting_rep {
            if input.is_some() {
                return Err(gss(GssError::DefectiveToken));
            }
            return self.first_step();
        }
        let rep = input.ok_or(Krb5Error::Gss(GssError::DefectiveToken))?;
        self.mutual_auth(rep)
    }

    /// make_ap_req_v1 + make_gss_checksum (init_sec_context.c:240-454).
    fn first_step(&mut self) -> Result<InitStep, Krb5Error> {
        let mut flags = self.gss_flags;
        let session = self.cred.session_key.clone();

        let mut ac = AuthContext::new();
        ac.set_flags(AuthContextFlags::DO_SEQUENCE);
        ac.set_req_cksumtype(CKSUM_GSS_CBINDINGS);

        // Delegation: build the KRB-CRED first so its length is known.
        // RFC 4121 §4.1.1 — encrypted in the session key, so the scratch
        // context carries the session key and no send subkey
        // (init_sec_context.c:255-283).
        let mut credmsg: Option<Vec<u8>> = None;
        if flags.contains(GssFlags::DELEG) {
            let built = (|| -> Result<Vec<u8>, Krb5Error> {
                let tgt = self.tgt.clone().ok_or(Krb5Error::Gss(GssError::NoCred))?;
                // gen_seq_number equivalent (gen_seqnum.c): random nonzero,
                // masked to 0x3fffffff.
                let mut seq = u32::from_be_bytes(generate_random(4).try_into().expect("4 bytes"));
                seq &= 0x3fffffff;
                if seq == 0 {
                    seq = 1;
                }
                let mut scratch = AuthContext::new();
                scratch.set_flags(AuthContextFlags::DO_SEQUENCE);
                scratch.set_session_key(session.clone());
                scratch.set_local_seq_number(seq);
                // mk_cred consumes seq as nonce and bumps to seq+1; the
                // AP-REQ authenticator then carries seq+1, matching MIT's
                // ordering (mk_req_ext.c:139-202).
                let (msg, _rdata) = scratch.mk_cred(&[tgt])?;
                ac.set_local_seq_number(seq.wrapping_add(1));
                Ok(msg)
            })();
            match built {
                Ok(m) => {
                    if m.len() + 28 > i16::MAX as usize {
                        return Err(gss(GssError::Failure));
                    }
                    credmsg = Some(m);
                }
                Err(_) => {
                    // init_sec_context.c:285-289 — drop DELEG silently.
                    flags.remove(GssFlags::DELEG | GssFlags::DELEG_POLICY);
                }
            }
        }

        let mut cksum_body = Vec::new();
        cksum_body.extend_from_slice(&16u32.to_le_bytes());
        match &self.cb {
            Some(cb) => cksum_body.extend_from_slice(&cb_checksum(cb)),
            None => cksum_body.extend_from_slice(&[0u8; 16]),
        }
        cksum_body.extend_from_slice(&flags.bits().to_le_bytes());
        if let Some(m) = &credmsg {
            cksum_body.extend_from_slice(&KRB5_GSS_FOR_CREDS_OPTION.to_le_bytes());
            cksum_body.extend_from_slice(&(m.len() as u16).to_le_bytes());
            cksum_body.extend_from_slice(m);
        }

        let opts = ApReqOptions {
            mutual_required: flags.contains(GssFlags::MUTUAL),
            use_session_key: false,
            use_subkey: true,
            etype_negotiation: flags.contains(GssFlags::MUTUAL),
            cbt: self.req_flags.contains(GssFlags::CHANNEL_BOUND),
        };
        let ap_req = ac.mk_req(&opts, Some(&cksum_body), &self.cred)?;
        self.gss_flags = flags;

        let mut token = make_token_header(MECH_KRB5, ap_req.len(), Some(TOK_AP_REQ));
        token.extend_from_slice(&ap_req);

        // kg_setup_keys: proto 1, mandatory cksumtype implied by etype.
        let key = ac.send_subkey().cloned().unwrap_or_else(|| session.clone());
        let seq_send = ac.local_seq_number() as u64;

        if flags.contains(GssFlags::MUTUAL) {
            self.ac = Some(ac);
            self.ctx = Some(Krb5Context::partial(
                flags,
                true,
                self.cred.client.clone(),
                self.cred.crealm.clone(),
                self.cred.server.clone(),
                self.cred.times.endtime,
                key,
                seq_send,
            ));
            self.awaiting_rep = true;
            Ok(InitStep::Continue(token))
        } else {
            // init_sec_context.c:632-641 — no AP-REP; seq_recv = seq_send.
            let mut ctx = Krb5Context::partial(
                flags | GssFlags::PROT_READY,
                true,
                self.cred.client.clone(),
                self.cred.crealm.clone(),
                self.cred.server.clone(),
                self.cred.times.endtime,
                key,
                seq_send,
            );
            ctx.seqstate = SeqState::new(
                seq_send,
                flags.contains(GssFlags::REPLAY),
                flags.contains(GssFlags::SEQUENCE),
                true,
            );
            self.ctx = Some(ctx);
            self.done = true;
            Ok(InitStep::Complete(Some(token)))
        }
    }

    /// mutual_auth (init_sec_context.c:695-868).
    fn mutual_auth(&mut self, token: &[u8]) -> Result<InitStep, Krb5Error> {
        let (mech, body) =
            parse_token_header(token).ok_or(Krb5Error::Gss(GssError::DefectiveToken))?;
        if mech != MECH_KRB5 || body.len() < 2 {
            return Err(gss(GssError::DefectiveToken));
        }
        let toktype = u16::from_be_bytes(body[..2].try_into().expect("2"));
        if toktype == TOK_CTX_ERROR {
            let err: KrbErrorMsg = rasn::der::decode(&body[2..])
                .map_err(|_| Krb5Error::Gss(GssError::DefectiveToken))?;
            return Err(Krb5Error::KdcError(Box::new(err)));
        }
        if toktype != TOK_AP_REP {
            return Err(gss(GssError::DefectiveToken));
        }
        let ac = self
            .ac
            .as_mut()
            .ok_or(Krb5Error::Gss(GssError::NoContext))?;
        let enc = ac.rd_rep(&body[2..])?;

        let mut ctx = self.ctx.take().ok_or(Krb5Error::Gss(GssError::NoContext))?;
        ctx.seqstate = SeqState::new(
            ac.remote_seq_number() as u64,
            ctx.flags.contains(GssFlags::REPLAY),
            ctx.flags.contains(GssFlags::SEQUENCE),
            true,
        );
        if let Some(sub) = enc.subkey {
            // proto == 1 → always keep the acceptor subkey (:808-825).
            ctx.acceptor_subkey = Some(sub);
        }
        ctx.flags |= GssFlags::PROT_READY;
        self.ctx = Some(ctx);
        self.done = true;
        Ok(InitStep::Complete(None))
    }

    /// Extract the established context.
    pub fn context(self) -> Result<Krb5Context, Krb5Error> {
        if !self.done {
            return Err(gss(GssError::NoContext));
        }
        self.ctx.ok_or(Krb5Error::Gss(GssError::NoContext))
    }

    /// The established context, for SPNEGO mechListMIC operations
    /// (spnego_mech.c process_mic uses the inner mech's get_mic/verify_mic).
    pub(crate) fn ctx_mut(&mut self) -> Option<&mut Krb5Context> {
        self.ctx.as_mut()
    }
}
