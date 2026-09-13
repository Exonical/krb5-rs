//! RFC 4121 (CFX) GSS-API Kerberos 5 mechanism.
//!
//! Modelled on MIT krb5 1.22.2: lib/gssapi/krb5/init_sec_context.c,
//! accept_sec_context.c, k5sealv3.c, k5sealv3iov.c, util_cksum.c,
//! util_crypt.c, wrap_size_limit.c.  Only CFX (proto 1) tokens are
//! produced and accepted; all registered enctypes are "newer" enctypes
//! per util_crypt.c:123-125 `kg_setup_keys`.

use std::time::Duration;

use crate::crypto::util::generate_random;
use crate::crypto::{find_cksumtype, find_etype};
use crate::error::Krb5Error;
use crate::protocol::ap::{ApReqOptions, AuthContext, AuthContextFlags, KeySource};
use crate::protocol::Credential;
use crate::types::*;

use super::seqstate::{SeqState, SeqStatus};
use super::token::{make_token_header, parse_token_header};
use super::GssError;
pub use super::GssFlags;

/// DER encoding of the krb5 mechanism OID 1.2.840.113554.1.2.2.
pub const MECH_KRB5: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02];

const TOK_AP_REQ: u16 = 0x0100;
const TOK_AP_REP: u16 = 0x0200;
const TOK_CTX_ERROR: u16 = 0x0300;
const TOK_MIC: u16 = 0x0404;
const TOK_WRAP: u16 = 0x0504;

const FLAG_SENDER_IS_ACCEPTOR: u8 = 0x01;
const FLAG_WRAP_CONFIDENTIAL: u8 = 0x02;
const FLAG_ACCEPTOR_SUBKEY: u8 = 0x04;

/// GSS key usages (gssapiP_krb5.h:144-147).
const USAGE_ACCEPTOR_SEAL: i32 = 22;
const USAGE_ACCEPTOR_SIGN: i32 = 23;
const USAGE_INITIATOR_SEAL: i32 = 24;
const USAGE_INITIATOR_SIGN: i32 = 25;

/// CKSUMTYPE_GSS_CBINDINGS (accept_sec_context.c).
const CKSUM_GSS_CBINDINGS: i32 = 0x8003;
/// KRB5_GSS_FOR_CREDS_OPTION.
const KRB5_GSS_FOR_CREDS_OPTION: u16 = 1;
/// KERB_AP_OPTIONS_CBT (MS-KILE), stored little-endian in authdata.
const AP_OPTIONS_CBT: u32 = 0x4000;
const AD_AP_OPTIONS: i32 = 143;

/// Channel bindings (gss_channel_bindings_struct).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelBindings {
    /// Initiator address family.
    pub initiator_addrtype: u32,
    /// Initiator address bytes.
    pub initiator_address: Vec<u8>,
    /// Acceptor address family.
    pub acceptor_addrtype: u32,
    /// Acceptor address bytes.
    pub acceptor_address: Vec<u8>,
    /// Application-supplied data.
    pub application_data: Vec<u8>,
}

/// util_cksum.c:31-80 `kg_checksum_channel_bindings` — plain MD5 over the
/// little-endian serialization.
fn cb_checksum(cb: &ChannelBindings) -> [u8; 16] {
    use md5::Digest;
    let mut input = Vec::new();
    input.extend_from_slice(&cb.initiator_addrtype.to_le_bytes());
    input.extend_from_slice(&(cb.initiator_address.len() as u32).to_le_bytes());
    input.extend_from_slice(&cb.initiator_address);
    input.extend_from_slice(&cb.acceptor_addrtype.to_le_bytes());
    input.extend_from_slice(&(cb.acceptor_address.len() as u32).to_le_bytes());
    input.extend_from_slice(&cb.acceptor_address);
    input.extend_from_slice(&(cb.application_data.len() as u32).to_le_bytes());
    input.extend_from_slice(&cb.application_data);
    md5::Md5::digest(&input).into()
}

fn gss(e: GssError) -> Krb5Error {
    Krb5Error::Gss(e)
}

/// Result of an initiator step.
#[derive(Debug)]
pub enum InitStep {
    /// Send this token and wait for the peer's reply.
    Continue(Vec<u8>),
    /// Context established; the inner token (if any) still needs sending.
    /// `Complete(Some)` is reserved for DCE-style third-leg output, which is
    /// not implemented, so normal completion is always `Complete(None)` —
    /// except that a *non-mutual* first step completes with its AP-REQ token.
    Complete(Option<Vec<u8>>),
}

/// Result of an acceptor step.
#[derive(Debug)]
pub enum AcceptStep {
    /// Context established; `token` carries the AP-REP when mutual.
    Complete {
        /// Token to send to the initiator (AP-REP), if any.
        token: Option<Vec<u8>>,
    },
    /// Send this token and wait for more input (unused without DCE style).
    ContinueNeeded(Vec<u8>),
}

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

/// Acceptor-side context establishment (accept_sec_context.c
/// kg_accept_krb5).
pub struct Krb5Acceptor {
    keys: Box<dyn KeySource>,
    server: Option<PrincipalName>,
    cb: Option<ChannelBindings>,
    ctx: Option<Krb5Context>,
    delegated: Option<Vec<Credential>>,
    done: bool,
}

impl Krb5Acceptor {
    /// Create an acceptor.  `keys` resolves the service ticket key;
    /// `server` restricts the accepted service principal (rd_req's
    /// `server` argument).
    pub fn new(
        keys: Box<dyn KeySource>,
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
        }
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
        if mech != MECH_KRB5 || body.len() < 2 {
            return Err(gss(GssError::DefectiveToken));
        }
        if u16::from_be_bytes(body[..2].try_into().expect("2")) != TOK_AP_REQ {
            return Err(gss(GssError::DefectiveToken));
        }

        let mut ac = AuthContext::new();
        let sname: Option<PrincipalName> = rasn::der::decode::<ApReq>(&body[2..])
            .ok()
            .map(|r| r.ticket.sname);
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

            let mut token = make_token_header(MECH_KRB5, ap_rep.len(), Some(TOK_AP_REP));
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
                    let len = u32::from_be_bytes(rest[4..8].try_into().expect("4")) as usize;
                    if rest.len() < 8 + len {
                        return Err(gss(GssError::Failure));
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

/// Output of [`Krb5Context::unwrap`].  `seq` carries the MIT
/// supplementary sequence status (the message is still valid even when
/// it is Gap/Unseq/Old/Duplicate — callers decide whether to drop it).
#[derive(Debug)]
pub struct Unwrapped {
    /// Plaintext message.
    pub data: Vec<u8>,
    /// Whether the token was confidentiality-protected.
    pub conf: bool,
    /// Sequence/replay status.
    pub seq: SeqStatus,
}

/// An established krb5 GSS context (krb5_gss_ctx_id_rec, proto 1).
pub struct Krb5Context {
    flags: GssFlags,
    initiate: bool,
    initiator: PrincipalName,
    crealm: String,
    acceptor: PrincipalName,
    endtime: KerberosTime,
    /// MIT `ctx->subkey` (initiator's subkey, or session key if none).
    key: EncryptionKey,
    /// MIT `ctx->acceptor_subkey`; `Some` == have_acceptor_subkey.
    acceptor_subkey: Option<EncryptionKey>,
    seq_send: u64,
    seqstate: SeqState,
}

impl Krb5Context {
    #[allow(clippy::too_many_arguments)]
    fn partial(
        flags: GssFlags,
        initiate: bool,
        initiator: PrincipalName,
        crealm: String,
        acceptor: PrincipalName,
        endtime: KerberosTime,
        key: EncryptionKey,
        seq_send: u64,
    ) -> Self {
        Krb5Context {
            flags,
            initiate,
            initiator,
            crealm,
            acceptor,
            endtime,
            key,
            acceptor_subkey: None,
            seq_send,
            seqstate: SeqState::new(0, false, false, true),
        }
    }

    /// Established context flags (incl. TRANS and PROT_READY).
    pub fn flags(&self) -> GssFlags {
        self.flags
    }

    /// SPNEGO reports `ctx_flags & ~GSS_C_PROT_READY_FLAG`
    /// (spnego_mech.c:1093-1094, :1684).
    pub(crate) fn clear_prot_ready(&mut self) {
        self.flags &= !GssFlags::PROT_READY;
    }

    /// Initiator principal.
    pub fn initiator(&self) -> &PrincipalName {
        &self.initiator
    }

    /// Initiator realm.
    pub fn initiator_realm(&self) -> &str {
        &self.crealm
    }

    /// Acceptor (service) principal.
    pub fn acceptor(&self) -> &PrincipalName {
        &self.acceptor
    }

    /// True on the initiator side.
    pub fn is_initiator(&self) -> bool {
        self.initiate
    }

    /// Remaining credential lifetime (saturates at zero).
    pub fn lifetime(&self) -> Duration {
        let now = chrono::Utc::now();
        self.endtime
            .with_timezone(&chrono::Utc)
            .signed_duration_since(now)
            .to_std()
            .unwrap_or(Duration::ZERO)
    }

    /// The per-message key: acceptor subkey when present, else `key`
    /// (k5sealv3.c:86-93).
    fn msg_key(&self) -> &EncryptionKey {
        self.acceptor_subkey.as_ref().unwrap_or(&self.key)
    }

    /// Wrap a message (k5sealv3.c:60-287 make_seal_token_v3).
    pub fn wrap(&mut self, conf: bool, msg: &[u8]) -> Result<Vec<u8>, Krb5Error> {
        let key = self.msg_key().clone();
        let profile = find_etype(key.keytype).map_err(|e| Krb5Error::Crypto(e.to_string()))?;
        let usage = if self.initiate {
            USAGE_INITIATOR_SEAL
        } else {
            USAGE_ACCEPTOR_SEAL
        };
        let mut hdr = Vec::with_capacity(16);
        hdr.extend_from_slice(&TOK_WRAP.to_be_bytes());
        hdr.push(
            if self.initiate {
                0
            } else {
                FLAG_SENDER_IS_ACCEPTOR
            } | if conf { FLAG_WRAP_CONFIDENTIAL } else { 0 }
                | if self.acceptor_subkey.is_some() {
                    FLAG_ACCEPTOR_SUBKEY
                } else {
                    0
                },
        );
        hdr.push(0xff);
        if conf {
            hdr.extend_from_slice(&0u16.to_be_bytes()); // EC
            hdr.extend_from_slice(&0u16.to_be_bytes()); // RRC
            hdr.extend_from_slice(&self.seq_send.to_be_bytes());
            let mut plain = Vec::with_capacity(msg.len() + 16);
            plain.extend_from_slice(msg);
            plain.extend_from_slice(&hdr);
            let cipher = profile
                .encrypt(key.key_bytes(), usage, &plain)
                .map_err(|e| Krb5Error::Crypto(e.to_string()))?;
            let mut token = hdr;
            token.extend_from_slice(&cipher);
            self.seq_send += 1;
            Ok(token)
        } else {
            hdr.extend_from_slice(&0u16.to_be_bytes()); // EC=0 for checksum
            hdr.extend_from_slice(&0u16.to_be_bytes()); // RRC
            hdr.extend_from_slice(&self.seq_send.to_be_bytes());
            let mut plain = Vec::with_capacity(msg.len() + 16);
            plain.extend_from_slice(msg);
            plain.extend_from_slice(&hdr);
            let sum = profile
                .checksum(key.key_bytes(), usage, &plain)
                .map_err(|e| Krb5Error::Crypto(e.to_string()))?;
            let mut token = hdr;
            // Fix up EC = checksum length (:253-265).
            token[4..6].copy_from_slice(&(sum.len() as u16).to_be_bytes());
            token.extend_from_slice(msg);
            token.extend_from_slice(&sum);
            self.seq_send += 1;
            Ok(token)
        }
    }

    /// Unwrap a message (k5sealv3iov.c:274-468 unseal_v3_iov).
    ///
    /// RRC handling deviation: MIT's flat-token path requires
    /// `rrc == trailer_len + 16 + ec`; this API accepts any RRC by rotating
    /// the body left by `rrc` first (k5unsealiov.c:471-478 semantics), which
    /// is a strict superset of what MIT accepts for contiguous tokens.
    pub fn unwrap(&mut self, token: &[u8]) -> Result<Unwrapped, Krb5Error> {
        let (key, usage) = self.recv_key_usage(token, true)?;
        let hdr = self.check_common(token, TOK_WRAP)?;
        let conf = token[2] & FLAG_WRAP_CONFIDENTIAL != 0;
        let ec = u16::from_be_bytes(token[4..6].try_into().expect("2")) as usize;
        let rrc = u16::from_be_bytes(token[6..8].try_into().expect("2")) as usize;
        let seq = u64::from_be_bytes(token[8..16].try_into().expect("8"));
        let profile = find_etype(key.keytype).map_err(|e| Krb5Error::Crypto(e.to_string()))?;
        let mut body = token[16..].to_vec();
        if rrc != 0 {
            let n = rrc % body.len().max(1);
            body.rotate_left(n);
        }
        let data = if conf {
            let plain = profile
                .decrypt(key.key_bytes(), usage, &body)
                .map_err(|_| Krb5Error::Gss(GssError::BadSig))?;
            if plain.len() < 16 + ec {
                return Err(gss(GssError::DefectiveToken));
            }
            // Validate the embedded header copy (:402-409).
            let althdr = &plain[plain.len() - 16..];
            if althdr[..2] != TOK_WRAP.to_be_bytes()
                || althdr[2] != token[2]
                || althdr[3] != token[3]
                || u16::from_be_bytes(althdr[4..6].try_into().expect("2")) as usize != ec
                || althdr[8..] != token[8..16]
            {
                return Err(gss(GssError::DefectiveToken));
            }
            plain[..plain.len() - 16 - ec].to_vec()
        } else {
            // Mandatory-cksumtype checksum length (hmac-sha1-96 = 12 for
            // etypes 17/18; aes-sha2 = 16/24 for etypes 19/20).
            let cksum_len = profile.checksum_size();
            if ec != cksum_len || body.len() < cksum_len {
                return Err(gss(GssError::DefectiveToken));
            }
            let msg = &body[..body.len() - cksum_len];
            let mut hdr_zeroed = hdr.clone();
            hdr_zeroed[4] = 0;
            hdr_zeroed[5] = 0;
            hdr_zeroed[6] = 0;
            hdr_zeroed[7] = 0;
            let mut input = Vec::with_capacity(msg.len() + 16);
            input.extend_from_slice(msg);
            input.extend_from_slice(&hdr_zeroed);
            profile
                .verify_checksum(
                    key.key_bytes(),
                    usage,
                    &input,
                    &body[body.len() - cksum_len..],
                )
                .map_err(|_| Krb5Error::Gss(GssError::BadSig))?;
            msg.to_vec()
        };
        Ok(Unwrapped {
            data,
            conf,
            seq: self.seqstate.check(seq),
        })
    }

    /// Generate a MIC token (k5sealv3.c KG_TOK_MIC_MSG path).
    pub fn get_mic(&mut self, msg: &[u8]) -> Result<Vec<u8>, Krb5Error> {
        let key = self.msg_key().clone();
        let profile = find_etype(key.keytype).map_err(|e| Krb5Error::Crypto(e.to_string()))?;
        let usage = if self.initiate {
            USAGE_INITIATOR_SIGN
        } else {
            USAGE_ACCEPTOR_SIGN
        };
        let mut hdr = Vec::with_capacity(16);
        hdr.extend_from_slice(&TOK_MIC.to_be_bytes());
        hdr.push(
            if self.initiate {
                0
            } else {
                FLAG_SENDER_IS_ACCEPTOR
            } | if self.acceptor_subkey.is_some() {
                FLAG_ACCEPTOR_SUBKEY
            } else {
                0
            },
        );
        hdr.push(0xff);
        hdr.extend_from_slice(&0xffffu16.to_be_bytes());
        hdr.extend_from_slice(&0xffffu16.to_be_bytes());
        hdr.extend_from_slice(&self.seq_send.to_be_bytes());
        let mut input = Vec::with_capacity(msg.len() + 16);
        input.extend_from_slice(msg);
        input.extend_from_slice(&hdr);
        let sum = profile
            .checksum(key.key_bytes(), usage, &input)
            .map_err(|e| Krb5Error::Crypto(e.to_string()))?;
        let mut token = hdr;
        token.extend_from_slice(&sum);
        self.seq_send += 1;
        Ok(token)
    }

    /// Verify a MIC token over `msg`; the Ok value is the supplementary
    /// sequence status (like `unwrap`, verification still succeeds).
    pub fn verify_mic(&mut self, msg: &[u8], mic: &[u8]) -> Result<SeqStatus, Krb5Error> {
        let (key, usage) = self.recv_key_usage(mic, false)?;
        let hdr = self.check_common(mic, TOK_MIC)?;
        let seq = u64::from_be_bytes(mic[8..16].try_into().expect("8"));
        let profile = find_etype(key.keytype).map_err(|e| Krb5Error::Crypto(e.to_string()))?;
        let mut input = Vec::with_capacity(msg.len() + 16);
        input.extend_from_slice(msg);
        input.extend_from_slice(&hdr);
        profile
            .verify_checksum(key.key_bytes(), usage, &input, &mic[16..])
            .map_err(|_| Krb5Error::Gss(GssError::BadSig))?;
        Ok(self.seqstate.check(seq))
    }

    /// Header checks shared by unwrap/verify_mic: length, direction
    /// (k5sealv3iov.c:314-318), tok id, filler byte.  Returns the 16-byte
    /// header as received.
    fn check_common(&self, token: &[u8], tok_id: u16) -> Result<Vec<u8>, Krb5Error> {
        if token.len() < 16 {
            return Err(gss(GssError::DefectiveToken));
        }
        let acceptor_flag = if self.initiate {
            FLAG_SENDER_IS_ACCEPTOR
        } else {
            0
        };
        if token[2] & FLAG_SENDER_IS_ACCEPTOR != acceptor_flag {
            return Err(gss(GssError::BadSig));
        }
        if u16::from_be_bytes(token[..2].try_into().expect("2")) != tok_id {
            return Err(gss(GssError::DefectiveToken));
        }
        if token[3] != 0xff {
            return Err(gss(GssError::DefectiveToken));
        }
        Ok(token[..16].to_vec())
    }

    /// The peer's per-message key and usage (seal vs sign).  The acceptor
    /// subkey is used only when we have it AND the token flags it
    /// (k5sealv3iov.c:322-329).
    fn recv_key_usage(&self, token: &[u8], seal: bool) -> Result<(&EncryptionKey, i32), Krb5Error> {
        let usage = if seal {
            if self.initiate {
                USAGE_ACCEPTOR_SEAL
            } else {
                USAGE_INITIATOR_SEAL
            }
        } else if self.initiate {
            USAGE_ACCEPTOR_SIGN
        } else {
            USAGE_INITIATOR_SIGN
        };
        let key = match &self.acceptor_subkey {
            Some(sub) if token.len() >= 3 && token[2] & FLAG_ACCEPTOR_SUBKEY != 0 => sub,
            _ => &self.key,
        };
        Ok((key, usage))
    }

    /// Largest plaintext fitting `output_size` (wrap_size_limit.c:98-150
    /// CFX branch).
    pub fn wrap_size_limit(&self, conf: bool, output_size: usize) -> usize {
        let key = self.msg_key();
        let Ok(profile) = find_etype(key.keytype) else {
            return 0;
        };
        if conf {
            // CTS encrypts without block padding, so
            // encrypt_size(n) = n + confounder + trailer
            // (krb5int_aes_crypto_length).  MIT's loop converges to the
            // closed form output - 16 - confounder - trailer, then
            // subtracts 16 for the encrypted header copy (:112-119).
            let sz = output_size
                .saturating_sub(16 + profile.confounder_size() + profile.checksum_size());
            // MIT's `if (sz > 16) sz -= 16; else sz = 0` — saturating_sub is
            // equivalent.
            sz.saturating_sub(16)
        } else {
            output_size.saturating_sub(16 + profile.checksum_size())
        }
    }
}
