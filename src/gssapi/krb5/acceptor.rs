//! Acceptor-side context establishment (accept_sec_context.c).

use super::*;

/// Acceptor-side context establishment (accept_sec_context.c
/// kg_accept_krb5).
pub struct Krb5Acceptor {
    keys: Box<dyn KeySource + Send>,
    server: Option<PrincipalName>,
    cb: Option<ChannelBindings>,
    ctx: Option<Krb5Context>,
    delegated: Option<Vec<Credential>>,
    done: bool,
    iakerb_conv: Option<Vec<u8>>,
    /// The accepted service ticket as a credential (for S4U2Proxy).
    accepted: Option<crate::ccache::CcCredential>,
    rcache: Option<crate::protocol::ap::Rcache>,
}

impl Krb5Acceptor {
    /// Create an acceptor.  `keys` resolves the service ticket key;
    /// `server` restricts the accepted service principal (rd_req's
    /// `server` argument).
    pub fn new(
        keys: Box<dyn KeySource + Send>,
        server: Option<PrincipalName>,
        cb: Option<ChannelBindings>,
    ) -> Self {
        Krb5Acceptor {
            keys,
            server,
            cb,
            ctx: None,
            delegated: None,
            done: false,
            iakerb_conv: None,
            accepted: None,
            rcache: None,
        }
    }

    /// Use `rcache` for the AP-REQ instead of the default replay cache
    /// (the credential's rcache, accept_sec_context.c:808-813).
    #[must_use]
    pub fn with_rcache(mut self, rcache: Option<crate::protocol::ap::Rcache>) -> Self {
        self.rcache = rcache;
        self
    }

    /// The constrained-delegation credential gss_accept_sec_context makes
    /// when no TGT was forwarded and `verifier` is a GSS_C_BOTH credential
    /// (accept_sec_context.c:944-957): the accepted ticket in a proxy
    /// credential for S4U2Proxy.  `None` when that does not apply.
    pub fn constrained_deleg_cred(
        &self,
        ctx: &crate::ccache::CcContext,
        verifier: &crate::gssapi::cred::GssCred,
    ) -> Result<Option<crate::gssapi::cred::GssCred>, Krb5Error> {
        if self.delegated.is_some() || verifier.usage != crate::gssapi::cred::CredUsage::Both {
            return Ok(None);
        }
        let subject = self
            .accepted
            .as_ref()
            .ok_or(Krb5Error::Gss(GssError::NoContext))?;
        verifier.compose_deleg_cred(ctx, subject).map(Some)
    }

    /// Accept for the IAKERB mechanism (iakerb.c:888-904): a nonempty
    /// `conv` must be covered by the initiator's IAKERB-FINISHED.
    pub(crate) fn with_iakerb(mut self, conv: Vec<u8>) -> Self {
        self.iakerb_conv = (!conv.is_empty()).then_some(conv);
        self
    }

    /// Process an initial context token.
    pub fn step(&mut self, input: &[u8]) -> Result<AcceptStep, Krb5Error> {
        if self.done {
            return Err(gss(GssError::ContextEstablished));
        }
        // parse_init_token: wrong mech, wrong tokid, or a raw AP-REQ
        // (DCE-style, unsupported) are all defective here.
        let (mech, body) =
            parse_token_header(input).ok_or(Krb5Error::Gss(GssError::DefectiveToken))?;
        // accept_sec_context.c:640-655 — the krb5 and IAKERB OIDs both
        // reach kg_accept_krb5, and replies carry the OID received.
        let mech_used: &'static [u8] = if mech == MECH_KRB5 {
            MECH_KRB5
        } else if mech == MECH_IAKERB {
            MECH_IAKERB
        } else {
            return Err(gss(GssError::DefectiveToken));
        };
        if body.len() < 2 {
            return Err(gss(GssError::DefectiveToken));
        }
        if u16::from_be_bytes(body[..2].try_into().expect("2")) != TOK_AP_REQ {
            return Err(gss(GssError::DefectiveToken));
        }

        let mut ac = AuthContext::new();
        ac.set_rcache(self.rcache.clone());
        let ap_ticket = rasn::der::decode::<ApReq>(&body[2..])
            .ok()
            .map(|r| r.ticket);
        let sname: Option<PrincipalName> = ap_ticket.as_ref().map(|t| t.sname.clone());
        let result = ac.rd_req(&body[2..], self.server.as_ref(), &*self.keys)?;
        ac.set_flags(ac.flags() | AuthContextFlags::DO_SEQUENCE);

        let auth = &result.authenticator;
        let session = ac
            .session_key()
            .cloned()
            .ok_or(Krb5Error::Gss(GssError::Failure))?;

        let gss_flags = self.process_checksum(&mut ac, auth, &session, &result)?;

        let mut flags = gss_flags | GssFlags::TRANS;
        // :906-919 — subkey = recv_subkey or session key.
        let key = ac.recv_subkey().cloned().unwrap_or_else(|| session.clone());
        let seq_recv = ac.remote_seq_number() as u64;

        if flags.contains(GssFlags::DCE_STYLE) {
            flags |= GssFlags::MUTUAL;
        }

        let mut ctx = Krb5Context::partial(
            flags,
            false,
            auth.cname.clone(),
            String::from_utf8_lossy(auth.crealm.as_bytes()).into_owned(),
            sname.unwrap_or_else(|| PrincipalName {
                name_type: 0,
                name_string: Vec::new(),
            }),
            result.ticket.endtime,
            key,
            // Non-mutual: seq_send = seq_recv
            // (accept_sec_context.c:1107-1109).
            seq_recv,
        );
        ctx.mech = mech_used;
        ctx.authtime = result.ticket.authtime;
        ctx.ticket_flags = result.ticket.flags;
        ctx.authdata = result
            .ticket
            .authorization_data
            .iter()
            .chain(auth.authorization_data.iter())
            .flatten()
            .cloned()
            .collect();
        ctx.ticket_key = session.clone();
        // rd_req_dec.c:640-649 krb5int_authdata_verify with the ticket key.
        let tkt = ap_ticket.ok_or(Krb5Error::Gss(GssError::DefectiveToken))?;
        let skey = self
            .keys
            .get_key(
                &tkt.sname,
                tkt.realm.as_bytes(),
                tkt.enc_part.kvno,
                tkt.enc_part.etype,
            )
            .map_err(|_| Krb5Error::Gss(GssError::Failure))?;
        ctx.name_attrs = super::name_attrs::NameAttrs::import(&result.ticket, &skey)?;
        let t = &result.ticket;
        let secs = |t: &KerberosTime| t.timestamp() as u32;
        self.accepted = Some(crate::ccache::CcCredential {
            client: t.cname.clone(),
            crealm: String::from_utf8_lossy(t.crealm.as_bytes()).into_owned(),
            server: tkt.sname.clone(),
            srealm: String::from_utf8_lossy(tkt.realm.as_bytes()).into_owned(),
            keyblock: t.key.clone(),
            authtime: secs(&t.authtime),
            starttime: t.starttime.as_ref().map_or(0, secs),
            endtime: secs(&t.endtime),
            renew_till: t.renew_till.as_ref().map_or(0, secs),
            is_skey: false,
            ticket_flags: t.flags.bits(),
            addresses: Vec::new(),
            authdata: Vec::new(),
            ticket: rasn::der::encode(&tkt).map_err(|_| Krb5Error::Gss(GssError::Failure))?,
            second_ticket: Vec::new(),
        });
        ctx.initial_ticket = result
            .ticket
            .flags
            .contains(crate::types::TicketFlags::INITIAL);
        ctx.seqstate = SeqState::new(
            seq_recv,
            flags.contains(GssFlags::REPLAY),
            flags.contains(GssFlags::SEQUENCE),
            true,
        );

        if flags.contains(GssFlags::MUTUAL) {
            // :1020-1037 — proto == 1 → always generate an acceptor subkey.
            ac.set_flags(ac.flags() | AuthContextFlags::USE_SUBKEY);
            let ap_rep = ac.mk_rep()?;
            ctx.seq_send = ac.local_seq_number() as u64;
            ctx.acceptor_subkey = ac.send_subkey().cloned();
            ctx.flags |= GssFlags::PROT_READY;

            let mut token = make_token_header(mech_used, ap_rep.len(), Some(TOK_AP_REP));
            token.extend_from_slice(&ap_rep);
            self.ctx = Some(ctx);
            self.done = true;
            Ok(AcceptStep::Complete { token: Some(token) })
        } else {
            self.ctx = Some(ctx);
            self.done = true;
            Ok(AcceptStep::Complete { token: None })
        }
    }

    /// process_checksum + check_cbt (accept_sec_context.c:424-626).
    fn process_checksum(
        &mut self,
        ac: &mut AuthContext,
        auth: &Authenticator,
        session: &EncryptionKey,
        result: &crate::protocol::ap::RdReqResult,
    ) -> Result<GssFlags, Krb5Error> {
        let mut cb_match = false;
        let mut flags = GssFlags::empty();
        let mut finished = false;

        match &auth.cksum {
            None => {}
            Some(cksum) if cksum.cksumtype != CKSUM_GSS_CBINDINGS => {
                // :494-516 — keyed checksum verified over the empty buffer.
                let profile = find_cksumtype(cksum.cksumtype)
                    .map_err(|_| Krb5Error::Gss(GssError::BadSig))?;
                profile
                    .verify_checksum(
                        session.key_bytes(),
                        crate::crypto::key_usage::AP_REQ_AUTH_CKSUM,
                        b"",
                        &cksum.checksum,
                    )
                    .map_err(|_| Krb5Error::Gss(GssError::BadSig))?;
                flags = GssFlags::REPLAY | GssFlags::SEQUENCE;
                if result.ap_options.contains(ApOptions::MUTUAL_REQUIRED) {
                    flags |= GssFlags::MUTUAL;
                }
            }
            Some(cksum) => {
                let data = cksum.checksum.as_ref();
                if data.len() < 24 {
                    return Err(gss(GssError::BadBindings));
                }
                let cb_len = u32::from_le_bytes(data[0..4].try_into().expect("4"));
                if cb_len != 16 {
                    return Err(gss(GssError::Failure));
                }
                let token_cb = &data[4..20];
                if let Some(cb) = &self.cb {
                    let present = token_cb.iter().any(|&b| b != 0);
                    cb_match = token_cb == cb_checksum(cb);
                    if present && !cb_match {
                        return Err(gss(GssError::BadBindings));
                    }
                }
                let token_flags = u32::from_le_bytes(data[20..24].try_into().expect("4"));
                // :560-566 — mask to initiator-meaningful flags.
                flags = GssFlags::from_bits_truncate(token_flags)
                    & (GssFlags::INTEG
                        | GssFlags::CONF
                        | GssFlags::MUTUAL
                        | GssFlags::REPLAY
                        | GssFlags::SEQUENCE
                        | GssFlags::DCE_STYLE
                        | GssFlags::IDENTIFY
                        | GssFlags::EXTENDED_ERROR);
                if cb_match {
                    flags |= GssFlags::CHANNEL_BOUND;
                }
                let mut rest = &data[24..];
                if rest.len() >= 4 && token_flags & GssFlags::DELEG.bits() != 0 {
                    let id = u16::from_le_bytes(rest[0..2].try_into().expect("2"));
                    let len = u16::from_le_bytes(rest[2..4].try_into().expect("2")) as usize;
                    rest = &rest[4..];
                    if id != KRB5_GSS_FOR_CREDS_OPTION || rest.len() < len {
                        return Err(gss(GssError::Failure));
                    }
                    let credmsg = &rest[..len];
                    rest = &rest[len..];
                    // rd_and_store_for_creds (:163-230): clear flags so no
                    // replay/sequence check applies; on failure retry with a
                    // keyless context (unencrypted KRB-CRED interpretation).
                    let saved = ac.flags();
                    ac.set_flags(AuthContextFlags::empty());
                    let creds = match ac.rd_cred(credmsg) {
                        Ok((creds, _)) => Some(creds),
                        Err(_) => {
                            let mut fresh = AuthContext::new();
                            fresh.set_flags(AuthContextFlags::empty());
                            ac.set_flags(saved);
                            match fresh.rd_cred(credmsg) {
                                Ok((creds, _)) => Some(creds),
                                Err(e) => return Err(e),
                            }
                        }
                    };
                    ac.set_flags(saved);
                    self.delegated = creds;
                    flags |= GssFlags::DELEG;
                }
                // Trailing extensions: u32be id, u32be len, bytes; ignore
                // unknown ids (:579-599).
                while !rest.is_empty() {
                    if rest.len() < 8 {
                        return Err(gss(GssError::Failure));
                    }
                    let id = u32::from_be_bytes(rest[0..4].try_into().expect("4"));
                    let len = u32::from_be_bytes(rest[4..8].try_into().expect("4")) as usize;
                    if rest.len() - 8 < len {
                        return Err(gss(GssError::Failure));
                    }
                    let ext = &rest[8..8 + len];
                    // kg_process_extension (:374-400).
                    if id == GSS_EXTS_FINISHED {
                        let conv = self
                            .iakerb_conv
                            .as_deref()
                            .ok_or(Krb5Error::Gss(GssError::Failure))?;
                        let key = ac.recv_subkey().ok_or(Krb5Error::Gss(GssError::Failure))?;
                        crate::gssapi::iakerb::verify_finished(key, conv, ext)?;
                        finished = true;
                    }
                    rest = &rest[8 + len..];
                }
            }
        }

        // check_cbt (:424-449): client asserting AP_OPTIONS CBT + acceptor
        // bindings + mismatch → BadBindings.
        let mut client_cbt = false;
        if let Some(ad) = &auth.authorization_data {
            for el in ad {
                let inner: &[AuthorizationDataElement] = if el.ad_type == 1 {
                    match rasn::der::decode::<Vec<AuthorizationDataElement>>(&el.ad_data) {
                        Ok(v) => {
                            if v.iter().any(|e| {
                                e.ad_type == AD_AP_OPTIONS
                                    && e.ad_data.as_ref() == AP_OPTIONS_CBT.to_le_bytes()
                            }) {
                                client_cbt = true;
                            }
                            continue;
                        }
                        Err(_) => continue,
                    }
                } else {
                    std::slice::from_ref(el)
                };
                if inner.iter().any(|e| {
                    e.ad_type == AD_AP_OPTIONS && e.ad_data.as_ref() == AP_OPTIONS_CBT.to_le_bytes()
                }) {
                    client_cbt = true;
                }
            }
        }
        if client_cbt && self.cb.is_some() && !cb_match {
            return Err(gss(GssError::BadBindings));
        }
        // :850-853.
        if self.iakerb_conv.is_some() && !finished {
            return Err(gss(GssError::BadSig));
        }
        Ok(flags)
    }

    /// Extract the established context.
    pub fn context(self) -> Result<Krb5Context, Krb5Error> {
        if !self.done {
            return Err(gss(GssError::NoContext));
        }
        self.ctx.ok_or(Krb5Error::Gss(GssError::NoContext))
    }

    /// Delegated credentials received in the initial token, if any.
    pub fn delegated_creds(&self) -> Option<&[Credential]> {
        self.delegated.as_deref()
    }

    /// The established context, for SPNEGO mechListMIC operations.
    pub(crate) fn ctx_mut(&mut self) -> Option<&mut Krb5Context> {
        self.ctx.as_mut()
    }
}
