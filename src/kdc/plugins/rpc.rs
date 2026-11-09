//! kdcpolicy and audit modules as separate processes, reached over the
//! RPC in [`crate::plugin::rpc`].
//!
//! [`serve_kdcpolicy`] and [`serve_audit`] run the module side for a
//! [`KdcPolicy`] or [`Audit`]; [`kdcpolicy`] and [`audit`] connect the KDC
//! side.

use std::io::{self, Read, Write};

use crate::plugin::rpc::{bad, Conn, KRB_ERR_GENERIC};
pub use crate::plugin::rpc::{
    read_message, serve, unix_connector, write_message, CallError, Client, Connect, InitError,
    Message, Stream, ERROR_TABLE_BASE_KRB5, PLUGIN_NO_HANDLE, PLUGIN_VER_NOTSUPP, PROTOCOL_VERSION,
};

use super::{
    Audit, AuditStage, AuditState, AuthdataRequest, KdcAuthdata, KdcPolicy, PolicyLimits,
    PolicyRefusal, PolicyRequest,
};
use crate::kdc::{KeyEntry, PrincipalAttributes, PrincipalEntry};
use crate::types::{AuthorizationDataElement, EncTicketPart, EncryptionKey, PrincipalName};

/// [`call::INITIALIZE`]'s string for a kdcpolicy module.
pub const KDCPOLICY_HANDSHAKE: &str = "KRB5RS-KDCPOLICY-V-1";
/// [`call::INITIALIZE`]'s string for an audit module.
pub const AUDIT_HANDSHAKE: &str = "KRB5RS-AUDIT-V-2";
/// [`call::INITIALIZE`]'s string for a KDC authdata module.
pub const KDCAUTHDATA_HANDSHAKE: &str = "KRB5RS-KDCAUTHDATA-V-2";

/// Call numbers.
pub mod call {
    pub use crate::plugin::rpc::call::{ERROR, FINALIZE, INITIALIZE};
    /// `check_as`: `sssas` client, server, ticket client, indicators;
    /// answered with `ii` lifetime and renewable lifetime.
    pub const CHECK_AS: u32 = 3;
    /// `check_tgs`, as [`CHECK_AS`].
    pub const CHECK_TGS: u32 = 4;
    /// `kdc_start`: `i` success.
    pub const KDC_START: u32 = 5;
    /// `kdc_stop`: `i` success.
    pub const KDC_STOP: u32 = 6;
    /// `as_req`: `i` success and the audit state (`sisisssisssssi`).
    pub const AS_REQ: u32 = 7;
    /// `tgs_req`, as [`AS_REQ`].
    pub const TGS_REQ: u32 = 8;
    /// `s4u2self`, as [`AS_REQ`].
    pub const S4U2SELF: u32 = 9;
    /// `s4u2proxy`, as [`AS_REQ`].
    pub const S4U2PROXY: u32 = 10;
    /// `u2u`, as [`AS_REQ`].
    pub const U2U: u32 = 11;
    /// authdata `handle`: `ii` flags and message type; client, server,
    /// header server and S4U client each as `ay` DER PrincipalName (empty
    /// for none) and `s` realm; `ay ay ay` client, server and header keys
    /// (DER EncryptionKey, empty for none); `ay` request; `ay ay` request
    /// and reply tickets (DER EncTicketPart, empty for none); then the
    /// client, server and header server database entries (`krb5_db_entry`),
    /// each `i` present (0 or 1) followed, when present, by the entry:
    /// `ay s` name and realm, `i` attributes, `ay ay ay ay ay` max life, max
    /// renewable life, expiration, password expiration and last admin unlock
    /// (8-byte big-endian seconds, empty for none), `i` key count and per key
    /// `i ay` kvno and DER EncryptionKey and `i ay i ay` salt and s2kparams
    /// (present flag and value), `as as` allowed to delegate to and from,
    /// `s s s s` require_auth, otp, pkinit_cert_match and policy, `ay`
    /// security epoch (8-byte big-endian). Answered with `ay` the reply
    /// ticket's authorization data (DER, empty for none).
    pub const HANDLE: u32 = 12;
}

fn der_opt<T: rasn::Encode>(v: Option<&T>) -> io::Result<Vec<u8>> {
    v.map_or(Ok(Vec::new()), |v| {
        rasn::der::encode(v).map_err(|e| bad(e.to_string()))
    })
}

fn opt_der<T: rasn::Decode>(b: &[u8]) -> io::Result<Option<T>> {
    if b.is_empty() {
        return Ok(None);
    }
    rasn::der::decode(b)
        .map(Some)
        .map_err(|e| bad(e.to_string()))
}

fn put_principal(m: &mut Message, p: Option<&super::Principal>) -> io::Result<()> {
    m.put_bytes(&der_opt(p.map(|(n, _)| n))?)
        .put_str(p.map(|(_, r)| r.as_str()));
    Ok(())
}

fn get_principal(m: &mut Message) -> io::Result<Option<super::Principal>> {
    let name: Option<PrincipalName> = opt_der(&m.get_bytes()?)?;
    let realm = m.get_str()?;
    Ok(name.map(|n| (n, realm.unwrap_or_default())))
}

fn put_i64_opt(m: &mut Message, v: Option<i64>) {
    m.put_bytes(&v.map_or(Vec::new(), |v| v.to_be_bytes().to_vec()));
}

fn get_i64_opt(m: &mut Message) -> io::Result<Option<i64>> {
    let b = m.get_bytes()?;
    if b.is_empty() {
        return Ok(None);
    }
    let b: [u8; 8] = b.try_into().map_err(|_| bad("bad integer"))?;
    Ok(Some(i64::from_be_bytes(b)))
}

fn put_opt_bytes(m: &mut Message, v: Option<&[u8]>) {
    m.put_i32(i32::from(v.is_some()))
        .put_bytes(v.unwrap_or_default());
}

fn get_opt_bytes(m: &mut Message) -> io::Result<Option<Vec<u8>>> {
    let present = m.get_i32()? != 0;
    let v = m.get_bytes()?;
    Ok(present.then_some(v))
}

fn put_entry(m: &mut Message, e: Option<&PrincipalEntry>) -> io::Result<()> {
    let Some(e) = e else {
        m.put_i32(0);
        return Ok(());
    };
    m.put_i32(1);
    put_principal(m, Some(&(e.name.clone(), e.realm.clone())))?;
    m.put_i32(e.attributes.bits() as i32);
    let secs = |d: Option<std::time::Duration>| d.map(|d| d.as_secs() as i64);
    let ts = |t: Option<&crate::types::KerberosTime>| t.map(|t| t.timestamp());
    put_i64_opt(m, secs(e.max_life));
    put_i64_opt(m, secs(e.max_renewable_life));
    put_i64_opt(m, ts(e.expiration.as_ref()));
    put_i64_opt(m, ts(e.pw_expiration.as_ref()));
    put_i64_opt(m, ts(e.last_admin_unlock.as_ref()));
    m.put_i32(i32::try_from(e.keys.len()).map_err(|_| bad("too many keys"))?);
    for k in &e.keys {
        m.put_i32(k.kvno as i32).put_bytes(&der_opt(Some(&k.key))?);
        put_opt_bytes(m, k.salt.as_deref());
        put_opt_bytes(m, k.s2kparams.as_deref());
    }
    m.put_strs(&e.allowed_to_delegate_to)
        .put_strs(&e.allowed_to_delegate_from)
        .put_str(e.require_auth.as_deref())
        .put_str(e.otp.as_deref())
        .put_str(e.pkinit_cert_match.as_deref())
        .put_str(e.policy.as_deref())
        .put_bytes(&e.security_epoch.to_be_bytes());
    Ok(())
}

fn get_entry(m: &mut Message) -> io::Result<Option<PrincipalEntry>> {
    if m.get_i32()? == 0 {
        return Ok(None);
    }
    let (name, realm) = get_principal(m)?.ok_or_else(|| bad("missing entry name"))?;
    let attributes = PrincipalAttributes::from_bits_retain(m.get_i32()? as u32);
    let dur = |v: Option<i64>| v.map(|v| std::time::Duration::from_secs(v.max(0) as u64));
    let time = |v: Option<i64>| v.map(crate::kdc::policy::kerberos_time);
    let max_life = dur(get_i64_opt(m)?);
    let max_renewable_life = dur(get_i64_opt(m)?);
    let expiration = time(get_i64_opt(m)?);
    let pw_expiration = time(get_i64_opt(m)?);
    let last_admin_unlock = time(get_i64_opt(m)?);
    let n = usize::try_from(m.get_i32()?).map_err(|_| bad("bad key count"))?;
    let mut keys = Vec::new();
    for _ in 0..n {
        let kvno = m.get_i32()? as u32;
        let key: EncryptionKey = opt_der(&m.get_bytes()?)?.ok_or_else(|| bad("missing key"))?;
        let salt = get_opt_bytes(m)?;
        let s2kparams = get_opt_bytes(m)?;
        keys.push(KeyEntry {
            kvno,
            key,
            salt,
            s2kparams,
        });
    }
    let allowed_to_delegate_to = m.get_strs()?;
    let allowed_to_delegate_from = m.get_strs()?;
    let require_auth = m.get_str()?;
    let otp = m.get_str()?;
    let pkinit_cert_match = m.get_str()?;
    let policy = m.get_str()?;
    let epoch: [u8; 8] = m
        .get_bytes()?
        .try_into()
        .map_err(|_| bad("bad security epoch"))?;
    Ok(Some(PrincipalEntry {
        name,
        realm,
        attributes,
        max_life,
        max_renewable_life,
        expiration,
        pw_expiration,
        keys,
        allowed_to_delegate_to,
        allowed_to_delegate_from,
        require_auth,
        otp,
        pkinit_cert_match,
        policy,
        security_epoch: u64::from_be_bytes(epoch),
        last_admin_unlock,
    }))
}

fn put_authdata(m: &mut Message, r: &AuthdataRequest, reply: &EncTicketPart) -> io::Result<()> {
    m.put_i32(r.flags).put_i32(r.msg_type);
    for p in [&r.client, &r.server, &r.header_server, &r.for_user] {
        put_principal(m, p.as_ref())?;
    }
    for k in [&r.client_key, &r.server_key, &r.header_key] {
        m.put_bytes(&der_opt(k.as_ref())?);
    }
    m.put_bytes(&r.req_pkt)
        .put_bytes(&der_opt(r.enc_tkt_req.as_ref())?)
        .put_bytes(&der_opt(Some(reply))?);
    for e in [&r.client_entry, &r.server_entry, &r.header_server_entry] {
        put_entry(m, e.as_ref())?;
    }
    Ok(())
}

fn get_authdata(m: &mut Message) -> io::Result<(AuthdataRequest, EncTicketPart)> {
    let flags = m.get_i32()?;
    let msg_type = m.get_i32()?;
    let client = get_principal(m)?;
    let server = get_principal(m)?;
    let header_server = get_principal(m)?;
    let for_user = get_principal(m)?;
    let client_key: Option<EncryptionKey> = opt_der(&m.get_bytes()?)?;
    let server_key: Option<EncryptionKey> = opt_der(&m.get_bytes()?)?;
    let header_key: Option<EncryptionKey> = opt_der(&m.get_bytes()?)?;
    let req_pkt = m.get_bytes()?;
    let enc_tkt_req: Option<EncTicketPart> = opt_der(&m.get_bytes()?)?;
    let reply: EncTicketPart = opt_der(&m.get_bytes()?)?.ok_or_else(|| bad("missing ticket"))?;
    let client_entry = get_entry(m)?;
    let server_entry = get_entry(m)?;
    let header_server_entry = get_entry(m)?;
    m.finish()?;
    let r = AuthdataRequest {
        flags,
        msg_type,
        client,
        server,
        header_server,
        client_key,
        server_key,
        header_key,
        req_pkt,
        for_user,
        enc_tkt_req,
        client_entry,
        server_entry,
        header_server_entry,
    };
    Ok((r, reply))
}

/// Serve `module` as a KDC authdata module on `stream`.
pub fn serve_kdcauthdata<S: Read + Write>(stream: S, module: &dyn KdcAuthdata) -> io::Result<()> {
    serve(stream, KDCAUTHDATA_HANDSHAKE, |req| {
        let mut answer = Message::new(req.call);
        Ok(match req.call {
            call::INITIALIZE => module.init().map(|()| answer).map_err(|c| (c, None)),
            call::FINALIZE => {
                module.fini();
                Ok(answer)
            }
            call::HANDLE => {
                let (r, mut reply) = get_authdata(req)?;
                match module.handle(&r, &mut reply) {
                    Ok(()) => {
                        answer.put_bytes(&der_opt(reply.authorization_data.as_ref())?);
                        Ok(answer)
                    }
                    Err(c) => Err((c, None)),
                }
            }
            _ => Err((PLUGIN_NO_HANDLE, None)),
        })
    })
}

/// A KDC authdata module reached over RPC; a call that fails is an error,
/// which the KDC logs.
pub struct RemoteAuthdata(Conn);

impl KdcAuthdata for RemoteAuthdata {
    fn name(&self) -> &str {
        &self.0.name
    }
    fn handle(&self, req: &AuthdataRequest, reply: &mut EncTicketPart) -> Result<(), i32> {
        let generic = ERROR_TABLE_BASE_KRB5 + KRB_ERR_GENERIC;
        let mut m = Message::new(call::HANDLE);
        put_authdata(&mut m, req, reply).map_err(|_| generic)?;
        match self.0.call(&m) {
            Ok(Ok(mut a)) => {
                let mut list = || -> io::Result<Option<Vec<AuthorizationDataElement>>> {
                    let b = a.get_bytes()?;
                    a.finish()?;
                    opt_der(&b)
                };
                reply.authorization_data = list().map_err(|_| generic)?;
                Ok(())
            }
            Ok(Err((code, _))) => Err(code),
            Err(_) => Err(generic),
        }
    }
}

fn put_request(m: &mut Message, r: &PolicyRequest) {
    m.put_str(r.client.as_deref())
        .put_str(Some(&r.server))
        .put_str(r.ticket_client.as_deref())
        .put_strs(&r.auth_indicators);
}

fn get_request(m: &mut Message) -> io::Result<PolicyRequest> {
    let r = PolicyRequest {
        client: m.get_str()?,
        server: m.get_str()?.ok_or_else(|| bad("missing server"))?,
        ticket_client: m.get_str()?,
        auth_indicators: m.get_strs()?,
    };
    m.finish()?;
    Ok(r)
}

/// Serve `module` as a kdcpolicy module on `stream`.
pub fn serve_kdcpolicy<S: Read + Write>(stream: S, module: &dyn KdcPolicy) -> io::Result<()> {
    serve(stream, KDCPOLICY_HANDSHAKE, |req| {
        let answer = Message::new(req.call);
        Ok(match req.call {
            call::INITIALIZE => module.init().map(|()| answer).map_err(|c| (c, None)),
            call::FINALIZE => {
                module.fini();
                Ok(answer)
            }
            call::CHECK_AS | call::CHECK_TGS => {
                let r = get_request(req)?;
                let result = if req.call == call::CHECK_AS {
                    module.check_as(&r)
                } else {
                    module.check_tgs(&r)
                };
                match result {
                    Ok(l) => {
                        let mut answer = answer;
                        let clamp = |v: i64| i32::try_from(v.max(0)).unwrap_or(i32::MAX);
                        answer
                            .put_i32(clamp(l.lifetime))
                            .put_i32(clamp(l.renew_lifetime));
                        Ok(answer)
                    }
                    Err(e) => Err((ERROR_TABLE_BASE_KRB5 + e.code, Some(e.status))),
                }
            }
            _ => Err((ERROR_TABLE_BASE_KRB5 + KRB_ERR_GENERIC, None)),
        })
    })
}

fn put_aprinc(m: &mut Message, p: Option<&super::AuditPrincipal>) {
    m.put_i32(i32::from(p.is_some()));
    if let Some(p) = p {
        m.put_i32(p.name_type).put_i32(p.components.len() as i32);
        for c in &p.components {
            m.put_bytes(c);
        }
        m.put_bytes(&p.realm);
    }
}

fn get_aprinc(m: &mut Message) -> io::Result<Option<super::AuditPrincipal>> {
    if m.get_i32()? == 0 {
        return Ok(None);
    }
    let name_type = m.get_i32()?;
    let n = get_count(m)?;
    let components = (0..n).map(|_| m.get_bytes()).collect::<io::Result<_>>()?;
    Ok(Some(super::AuditPrincipal {
        name_type,
        components,
        realm: m.get_bytes()?,
    }))
}

fn get_count(m: &mut Message) -> io::Result<usize> {
    usize::try_from(m.get_i32()?)
        .ok()
        .filter(|n| *n <= 4096)
        .ok_or_else(|| bad("bad count"))
}

fn put_i32s(m: &mut Message, v: Option<&[i32]>) {
    m.put_i32(v.map_or(-1, |v| v.len() as i32));
    for x in v.unwrap_or_default() {
        m.put_i32(*x);
    }
}

fn get_i32s(m: &mut Message) -> io::Result<Option<Vec<i32>>> {
    let n = match m.get_i32()? {
        -1 => return Ok(None),
        n => usize::try_from(n)
            .ok()
            .filter(|n| *n <= 4096)
            .ok_or_else(|| bad("bad count"))?,
    };
    Ok(Some(
        (0..n).map(|_| m.get_i32()).collect::<io::Result<_>>()?,
    ))
}

fn put_arequest(m: &mut Message, r: Option<&super::AuditRequest>) {
    m.put_i32(i32::from(r.is_some()));
    let Some(r) = r else { return };
    put_aprinc(m, r.client.as_ref());
    put_aprinc(m, r.server.as_ref());
    m.put_i32(r.kdc_options)
        .put_i32(r.from)
        .put_i32(r.till)
        .put_i32(r.rtime);
    put_i32s(m, Some(&r.etypes));
    put_i32s(m, r.pa_types.as_deref());
    m.put_i32(r.addresses.as_ref().map_or(-1, |a| a.len() as i32));
    for (t, a) in r.addresses.iter().flatten() {
        m.put_i32(*t).put_bytes(a);
    }
    put_aprinc(m, r.second_ticket.as_ref().map(|t| &t.0));
    m.put_i32(r.second_ticket.as_ref().map_or(0, |t| t.1));
}

fn get_arequest(m: &mut Message) -> io::Result<Option<super::AuditRequest>> {
    if m.get_i32()? == 0 {
        return Ok(None);
    }
    let client = get_aprinc(m)?;
    let server = get_aprinc(m)?;
    let (kdc_options, from, till, rtime) = (m.get_i32()?, m.get_i32()?, m.get_i32()?, m.get_i32()?);
    let etypes = get_i32s(m)?.unwrap_or_default();
    let pa_types = get_i32s(m)?;
    let addresses = match m.get_i32()? {
        -1 => None,
        n => {
            let n = usize::try_from(n)
                .ok()
                .filter(|n| *n <= 4096)
                .ok_or_else(|| bad("bad count"))?;
            Some(
                (0..n)
                    .map(|_| Ok((m.get_i32()?, m.get_bytes()?)))
                    .collect::<io::Result<_>>()?,
            )
        }
    };
    let second = get_aprinc(m)?;
    let second_etype = m.get_i32()?;
    Ok(Some(super::AuditRequest {
        client,
        server,
        kdc_options,
        from,
        till,
        rtime,
        etypes,
        pa_types,
        addresses,
        second_ticket: second.map(|p| (p, second_etype)),
    }))
}

fn put_areply(m: &mut Message, r: Option<&super::AuditReply>) {
    m.put_i32(i32::from(r.is_some()));
    let Some(r) = r else { return };
    put_aprinc(m, r.ticket_server.as_ref());
    m.put_i32(r.ticket_etype);
    m.put_i32(i32::from(r.ticket_part.is_some()));
    if let Some(p) = &r.ticket_part {
        put_aprinc(m, Some(&p.client));
        m.put_i32(p.flags)
            .put_i32(p.session_etype)
            .put_i32(p.start)
            .put_i32(p.end)
            .put_i32(p.renew_till)
            .put_i32(p.authtime)
            .put_bytes(&p.tr_contents);
    }
    m.put_i32(r.etype);
    put_i32s(m, r.pa_types.as_deref());
}

fn get_areply(m: &mut Message) -> io::Result<Option<super::AuditReply>> {
    if m.get_i32()? == 0 {
        return Ok(None);
    }
    let ticket_server = get_aprinc(m)?;
    let ticket_etype = m.get_i32()?;
    let ticket_part = if m.get_i32()? != 0 {
        Some(super::AuditTicketPart {
            client: get_aprinc(m)?.unwrap_or_default(),
            flags: m.get_i32()?,
            session_etype: m.get_i32()?,
            start: m.get_i32()?,
            end: m.get_i32()?,
            renew_till: m.get_i32()?,
            authtime: m.get_i32()?,
            tr_contents: m.get_bytes()?,
        })
    } else {
        None
    };
    Ok(Some(super::AuditReply {
        ticket_server,
        ticket_etype,
        ticket_part,
        etype: m.get_i32()?,
        pa_types: get_i32s(m)?,
    }))
}

fn put_state(m: &mut Message, st: &AuditState) {
    let addr = st.cl_addr.map(|a| a.to_string());
    m.put_str(Some(&st.req_id))
        .put_str(addr.as_deref())
        .put_i32(i32::from(st.cl_port))
        .put_i32(st.stage as i32)
        .put_str(st.status.as_deref())
        .put_str(st.client.as_deref())
        .put_str(st.server.as_deref())
        .put_i32(st.error_code)
        .put_str(st.tkt_in_id.as_deref())
        .put_str(st.tkt_out_id.as_deref())
        .put_str(st.evid_tkt_id.as_deref())
        .put_str(st.cl_realm.as_deref())
        .put_str(st.s4u2self_user.as_deref())
        .put_i32(st.violation);
    put_aprinc(m, st.s4u2self_principal.as_ref());
    put_arequest(m, st.request.as_ref());
    put_areply(m, st.reply.as_ref());
}

fn get_state(m: &mut Message) -> io::Result<AuditState> {
    let req_id = m.get_str()?.unwrap_or_default();
    let cl_addr = m.get_str()?.and_then(|a| a.parse().ok());
    let cl_port = u16::try_from(m.get_i32()?).unwrap_or(0);
    let stage = match m.get_i32()? {
        2 => AuditStage::SrvcPrinc,
        3 => AuditStage::ValidatePol,
        4 => AuditStage::IssueTkt,
        5 => AuditStage::EncrRep,
        _ => AuditStage::AuthnReqCl,
    };
    let st = AuditState {
        req_id,
        cl_addr,
        cl_port,
        stage,
        status: m.get_str()?,
        client: m.get_str()?,
        server: m.get_str()?,
        error_code: m.get_i32()?,
        tkt_in_id: m.get_str()?,
        tkt_out_id: m.get_str()?,
        evid_tkt_id: m.get_str()?,
        cl_realm: m.get_str()?,
        s4u2self_user: m.get_str()?,
        violation: m.get_i32()?,
        s4u2self_principal: get_aprinc(m)?,
        request: get_arequest(m)?,
        reply: get_areply(m)?,
    };
    m.finish()?;
    Ok(st)
}

/// Serve `module` as an audit module on `stream`.
pub fn serve_audit<S: Read + Write>(stream: S, module: &dyn Audit) -> io::Result<()> {
    serve(stream, AUDIT_HANDSHAKE, |req| {
        let answer = Message::new(req.call);
        Ok(match req.call {
            call::INITIALIZE => module.open().map(|()| answer).map_err(|c| (c, None)),
            call::FINALIZE => {
                module.close();
                Ok(answer)
            }
            call::KDC_START | call::KDC_STOP => {
                let ok = req.get_i32()? != 0;
                req.finish()?;
                if req.call == call::KDC_START {
                    module.kdc_start(ok);
                } else {
                    module.kdc_stop(ok);
                }
                Ok(answer)
            }
            call::AS_REQ..=call::U2U => {
                let ok = req.get_i32()? != 0;
                let st = get_state(req)?;
                match req.call {
                    call::AS_REQ => module.as_req(ok, &st),
                    call::TGS_REQ => module.tgs_req(ok, &st),
                    call::S4U2SELF => module.s4u2self(ok, &st),
                    call::S4U2PROXY => module.s4u2proxy(ok, &st),
                    _ => module.u2u(ok, &st),
                }
                Ok(answer)
            }
            _ => Err((ERROR_TABLE_BASE_KRB5 + KRB_ERR_GENERIC, None)),
        })
    })
}

/// A kdcpolicy module reached over RPC.
pub struct RemotePolicy(Conn);

impl RemotePolicy {
    fn check(&self, call: u32, req: &PolicyRequest) -> Result<PolicyLimits, PolicyRefusal> {
        let mut m = Message::new(call);
        put_request(&mut m, req);
        let unavailable = |e: io::Error| PolicyRefusal {
            code: KRB_ERR_GENERIC,
            status: format!("kdcpolicy module {}: {e}", self.0.name),
        };
        match self.0.call(&m).map_err(unavailable)? {
            Ok(mut a) => {
                let mut limits = || -> io::Result<PolicyLimits> {
                    let l = PolicyLimits {
                        lifetime: i64::from(a.get_i32()?.max(0)),
                        renew_lifetime: i64::from(a.get_i32()?.max(0)),
                    };
                    a.finish()?;
                    Ok(l)
                };
                limits().map_err(unavailable)
            }
            Err((code, status)) => {
                let c = code.wrapping_sub(ERROR_TABLE_BASE_KRB5);
                Err(PolicyRefusal {
                    code: if (0..128).contains(&c) {
                        c
                    } else {
                        KRB_ERR_GENERIC
                    },
                    status: status.unwrap_or_else(|| "KDC policy rejects request".into()),
                })
            }
        }
    }
}

impl KdcPolicy for RemotePolicy {
    fn name(&self) -> &str {
        &self.0.name
    }
    fn check_as(&self, req: &PolicyRequest) -> Result<PolicyLimits, PolicyRefusal> {
        self.check(call::CHECK_AS, req)
    }
    fn check_tgs(&self, req: &PolicyRequest) -> Result<PolicyLimits, PolicyRefusal> {
        self.check(call::CHECK_TGS, req)
    }
}

/// An audit module reached over RPC. Errors are ignored, as MIT ignores
/// audit callback results.
pub struct RemoteAudit(Conn);

impl RemoteAudit {
    fn event(&self, call: u32, success: bool) {
        let mut m = Message::new(call);
        m.put_i32(i32::from(success));
        let _ = self.0.call(&m);
    }

    fn req(&self, call: u32, success: bool, st: &AuditState) {
        let mut m = Message::new(call);
        m.put_i32(i32::from(success));
        put_state(&mut m, st);
        let _ = self.0.call(&m);
    }
}

impl Audit for RemoteAudit {
    fn name(&self) -> &str {
        &self.0.name
    }
    fn kdc_start(&self, success: bool) {
        self.event(call::KDC_START, success);
    }
    fn kdc_stop(&self, success: bool) {
        self.event(call::KDC_STOP, success);
    }
    fn as_req(&self, success: bool, st: &AuditState) {
        self.req(call::AS_REQ, success, st);
    }
    fn tgs_req(&self, success: bool, st: &AuditState) {
        self.req(call::TGS_REQ, success, st);
    }
    fn s4u2self(&self, success: bool, st: &AuditState) {
        self.req(call::S4U2SELF, success, st);
    }
    fn s4u2proxy(&self, success: bool, st: &AuditState) {
        self.req(call::S4U2PROXY, success, st);
    }
    fn u2u(&self, success: bool, st: &AuditState) {
        self.req(call::U2U, success, st);
    }
}

/// Connect to the kdcpolicy module `name`.
pub fn kdcpolicy(name: &str, connect: Connect) -> Result<RemotePolicy, InitError> {
    Conn::open(name, KDCPOLICY_HANDSHAKE, connect).map(RemotePolicy)
}

/// Connect to the KDC authdata module `name`.
pub fn kdcauthdata(name: &str, connect: Connect) -> Result<RemoteAuthdata, InitError> {
    Conn::open(name, KDCAUTHDATA_HANDSHAKE, connect).map(RemoteAuthdata)
}

/// Connect to the audit module `name`.
pub fn audit(name: &str, connect: Connect) -> Result<RemoteAudit, InitError> {
    Conn::open(name, AUDIT_HANDSHAKE, connect).map(RemoteAudit)
}

/// [`call::INITIALIZE`]'s string for the ACE/Server bridge the
/// `securid_sam2` module uses.
pub const SECURID_ACE_HANDSHAKE: &str = "KRB5RS-SECURID-ACE-V-1";

/// Call numbers of the ACE/Server bridge.
pub mod ace_call {
    pub use crate::plugin::rpc::call::{ERROR, FINALIZE, INITIALIZE};
    /// `SD_Init`: answered with `i` handle.
    pub const SD_INIT: u32 = 3;
    /// `SD_Lock`: `is` handle, user; answered with `i` ACM code.
    pub const SD_LOCK: u32 = 4;
    /// `SD_Check`: `iss` handle, passcode, user; answered with `i`.
    pub const SD_CHECK: u32 = 5;
    /// `SD_Next`: `is` handle, passcode; answered with `i`.
    pub const SD_NEXT: u32 = 6;
    /// `SD_Pin`: `is` handle, PIN; answered with `i`.
    pub const SD_PIN: u32 = 7;
    /// `SD_Close`: `i` handle.
    pub const SD_CLOSE: u32 = 8;
    /// `AceGetMinPinLen`, `AceGetMaxPinLen`, `AceGetAlphanumeric`: `i`
    /// handle; answered with `iii` min, max, alphanumeric, or an error.
    pub const PIN_PARAMS: u32 = 9;
}

/// Run the ACE/Server bridge side for `ace` on `stream`.
pub fn serve_securid_ace<S: Read + Write>(
    stream: S,
    ace: &dyn crate::kdc::securid_sam2::AceServer,
) -> io::Result<()> {
    serve(stream, SECURID_ACE_HANDSHAKE, |req| {
        let mut answer = Message::new(req.call);
        let handle = |req: &mut Message| req.get_i32().map(|h| h as u32);
        Ok(match req.call {
            ace_call::INITIALIZE | ace_call::FINALIZE => Ok(answer),
            ace_call::SD_INIT => {
                req.finish()?;
                ace.init()
                    .map(|h| {
                        answer.put_i32(h as i32);
                        answer
                    })
                    .map_err(|c| (c, None))
            }
            ace_call::SD_LOCK | ace_call::SD_NEXT | ace_call::SD_PIN => {
                let h = handle(req)?;
                let s = req.get_str()?.unwrap_or_default();
                req.finish()?;
                let code = match req.call {
                    ace_call::SD_LOCK => ace.lock(h, &s),
                    ace_call::SD_NEXT => ace.next(h, &s),
                    _ => ace.pin(h, &s),
                };
                answer.put_i32(code);
                Ok(answer)
            }
            ace_call::SD_CHECK => {
                let h = handle(req)?;
                let passcode = req.get_str()?.unwrap_or_default();
                let user = req.get_str()?.unwrap_or_default();
                req.finish()?;
                answer.put_i32(ace.check(h, &passcode, &user));
                Ok(answer)
            }
            ace_call::SD_CLOSE => {
                let h = handle(req)?;
                req.finish()?;
                ace.close(h);
                Ok(answer)
            }
            ace_call::PIN_PARAMS => {
                let h = handle(req)?;
                req.finish()?;
                match ace.pin_params(h) {
                    Some(p) => {
                        answer
                            .put_i32(p.min)
                            .put_i32(p.max)
                            .put_i32(i32::from(p.alphanumeric));
                        Ok(answer)
                    }
                    None => Err((ERROR_TABLE_BASE_KRB5 + KRB_ERR_GENERIC, None)),
                }
            }
            _ => Err((ERROR_TABLE_BASE_KRB5 + KRB_ERR_GENERIC, None)),
        })
    })
}

/// The ACE/Server reached over RPC. A call that fails in transport
/// answers as a refusal.
pub struct RemoteAce(Conn);

impl RemoteAce {
    fn code(&self, m: &Message) -> i32 {
        match self.0.call(m) {
            Ok(Ok(mut r)) => r.get_i32().unwrap_or(-1),
            Ok(Err(_)) | Err(_) => -1,
        }
    }
}

impl crate::kdc::securid_sam2::AceServer for RemoteAce {
    fn init(&self) -> Result<u32, i32> {
        match self.0.call(&Message::new(ace_call::SD_INIT)) {
            Ok(Ok(mut r)) => r.get_i32().map(|h| h as u32).map_err(|_| -1),
            Ok(Err((c, _))) => Err(c),
            Err(_) => Err(-1),
        }
    }
    fn lock(&self, handle: u32, user: &str) -> i32 {
        let mut m = Message::new(ace_call::SD_LOCK);
        m.put_i32(handle as i32).put_str(Some(user));
        self.code(&m)
    }
    fn check(&self, handle: u32, passcode: &str, user: &str) -> i32 {
        let mut m = Message::new(ace_call::SD_CHECK);
        m.put_i32(handle as i32)
            .put_str(Some(passcode))
            .put_str(Some(user));
        self.code(&m)
    }
    fn next(&self, handle: u32, passcode: &str) -> i32 {
        let mut m = Message::new(ace_call::SD_NEXT);
        m.put_i32(handle as i32).put_str(Some(passcode));
        self.code(&m)
    }
    fn pin(&self, handle: u32, pin: &str) -> i32 {
        let mut m = Message::new(ace_call::SD_PIN);
        m.put_i32(handle as i32).put_str(Some(pin));
        self.code(&m)
    }
    fn close(&self, handle: u32) {
        let mut m = Message::new(ace_call::SD_CLOSE);
        m.put_i32(handle as i32);
        let _ = self.0.call(&m);
    }
    fn pin_params(&self, handle: u32) -> Option<crate::kdc::securid_sam2::PinParams> {
        let mut m = Message::new(ace_call::PIN_PARAMS);
        m.put_i32(handle as i32);
        let mut r = self.0.call(&m).ok()?.ok()?;
        Some(crate::kdc::securid_sam2::PinParams {
            min: r.get_i32().ok()?,
            max: r.get_i32().ok()?,
            alphanumeric: r.get_i32().ok()? != 0,
        })
    }
}

/// Connect the `securid_sam2` module to the ACE/Server bridge `name`.
pub fn securid_ace(name: &str, connect: Connect) -> Result<RemoteAce, InitError> {
    Conn::open(name, SECURID_ACE_HANDSHAKE, connect).map(RemoteAce)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::net::UnixStream;
    use std::sync::{Arc, Mutex};

    /// MIT's `plugins/kdcpolicy/test/main.c`.
    struct MitTest;

    fn limits(ind: &[String], divisor: i64) -> Result<PolicyLimits, PolicyRefusal> {
        let life = match ind.first().map(String::as_str) {
            None => return Ok(PolicyLimits::default()),
            Some("ONE_HOUR") => 3600 / divisor,
            Some("SEVEN_HOURS") => 7 * 3600 / divisor,
            Some(_) => return Err(refused()),
        };
        Ok(PolicyLimits {
            lifetime: life,
            renew_lifetime: life * 2,
        })
    }

    fn refused() -> PolicyRefusal {
        PolicyRefusal {
            code: super::super::KDC_ERR_POLICY,
            status: "LOCAL_POLICY".into(),
        }
    }

    impl KdcPolicy for MitTest {
        fn name(&self) -> &str {
            "test"
        }
        fn check_as(&self, r: &PolicyRequest) -> Result<PolicyLimits, PolicyRefusal> {
            if r.client.as_deref().is_some_and(|c| c.starts_with("fail@")) {
                return Err(refused());
            }
            limits(&r.auth_indicators, 1)
        }
        fn check_tgs(&self, r: &PolicyRequest) -> Result<PolicyLimits, PolicyRefusal> {
            if r.server.starts_with("fail@") || r.server.starts_with("fail/") {
                return Err(refused());
            }
            limits(&r.auth_indicators, 2)
        }
    }

    struct NoHandle;
    impl KdcPolicy for NoHandle {
        fn name(&self) -> &str {
            "skip"
        }
        fn init(&self) -> Result<(), i32> {
            Err(PLUGIN_NO_HANDLE)
        }
    }

    #[derive(Default)]
    struct Log(Mutex<Vec<String>>);
    impl Audit for Log {
        fn name(&self) -> &str {
            "log"
        }
        fn open(&self) -> Result<(), i32> {
            self.push("open".into());
            Ok(())
        }
        fn close(&self) {
            self.push("close".into());
        }
        fn kdc_start(&self, ok: bool) {
            self.push(format!("kdc_start {ok}"));
        }
        fn as_req(&self, ok: bool, st: &AuditState) {
            self.push(format!("as_req {ok} {st:?}"));
        }
        fn u2u(&self, ok: bool, st: &AuditState) {
            self.push(format!("u2u {ok} {:?}", st.status));
        }
    }
    impl Log {
        fn push(&self, s: String) {
            self.0.lock().expect("lock").push(s);
        }
    }

    /// A connector whose every connection is served by `serve` on a thread.
    fn connector<F>(serve: F) -> Connect
    where
        F: Fn(UnixStream) + Send + Sync + Clone + 'static,
    {
        Box::new(move || {
            let (a, b) = UnixStream::pair()?;
            let serve = serve.clone();
            std::thread::spawn(move || serve(b));
            Ok(Box::new(a) as Box<dyn Stream>)
        })
    }

    fn req(client: Option<&str>, server: &str, ind: &[&str]) -> PolicyRequest {
        PolicyRequest {
            client: client.map(Into::into),
            server: server.into(),
            ticket_client: None,
            auth_indicators: ind.iter().map(|s| (*s).to_string()).collect(),
        }
    }

    #[test]
    fn kdcpolicy_over_rpc_like_mit_test_module() {
        let m = kdcpolicy(
            "test",
            connector(|s| {
                let _ = serve_kdcpolicy(s, &MitTest);
            }),
        )
        .expect("connect");
        let l = |lifetime, renew_lifetime| PolicyLimits {
            lifetime,
            renew_lifetime,
        };
        assert_eq!(
            m.check_as(&req(Some("u@R"), "krbtgt/R@R", &["SEVEN_HOURS"])),
            Ok(l(7 * 3600, 14 * 3600))
        );
        assert_eq!(
            m.check_tgs(&req(None, "host/x@R", &["ONE_HOUR"])),
            Ok(l(1800, 3600))
        );
        assert_eq!(
            m.check_as(&req(Some("u@R"), "krbtgt/R@R", &[])),
            Ok(l(0, 0))
        );
        assert_eq!(
            m.check_as(&req(Some("fail@R"), "krbtgt/R@R", &[])),
            Err(refused())
        );
        assert_eq!(m.check_tgs(&req(None, "fail@R", &[])), Err(refused()));
        assert_eq!(
            m.check_as(&req(Some("u@R"), "k@R", &["OTHER"])),
            Err(refused())
        );
    }

    #[test]
    fn init_results_and_unreachable_modules() {
        let e = kdcpolicy(
            "skip",
            connector(|s| {
                let _ = serve_kdcpolicy(s, &NoHandle);
            }),
        )
        .err()
        .expect("refused");
        assert!(
            matches!(e, InitError::Refused((PLUGIN_NO_HANDLE, None))),
            "{e:?}"
        );
        // The wrong interface refuses the handshake, like a vtable version.
        let e = audit(
            "test",
            connector(|s| {
                let _ = serve_kdcpolicy(s, &MitTest);
            }),
        )
        .err()
        .expect("refused");
        assert!(
            matches!(e, InitError::Refused((PLUGIN_VER_NOTSUPP, None))),
            "{e:?}"
        );
        let e = kdcpolicy("gone", Box::new(|| Err(io::ErrorKind::NotFound.into())))
            .err()
            .expect("unavailable");
        assert!(matches!(e, InitError::Unavailable(_)), "{e:?}");
    }

    #[test]
    fn policy_fails_closed_and_reconnects() {
        let calls = Arc::new(Mutex::new(0));
        let n = Arc::clone(&calls);
        // The first connection dies after initializing.
        let m = kdcpolicy(
            "test",
            connector(move |mut s| {
                let first = {
                    let mut c = n.lock().expect("lock");
                    *c += 1;
                    *c == 1
                };
                if first {
                    let mut v = [0u8];
                    let _ = s.read_exact(&mut v);
                    let _ = s.write_all(&v);
                    if let Ok((id, m)) = read_message(&mut s) {
                        let _ = write_message(&mut s, id, &Message::new(m.call));
                    }
                    return;
                }
                let _ = serve(s, KDCPOLICY_HANDSHAKE, |req| {
                    if req.call == call::CHECK_AS {
                        get_request(req)?;
                        let mut a = Message::new(req.call);
                        a.put_i32(60).put_i32(120);
                        return Ok(Ok(a));
                    }
                    Ok(Ok(Message::new(req.call)))
                });
            }),
        )
        .expect("connect");
        let e = m
            .check_as(&req(Some("u@R"), "k@R", &[]))
            .expect_err("closed");
        assert_eq!(e.code, KRB_ERR_GENERIC);
        assert_eq!(
            m.check_as(&req(Some("u@R"), "k@R", &[])),
            Ok(PolicyLimits {
                lifetime: 60,
                renew_lifetime: 120
            })
        );
        assert_eq!(*calls.lock().expect("lock"), 2);
    }

    #[test]
    fn audit_state_round_trips() {
        let log = Arc::new(Log::default());
        let l = Arc::clone(&log);
        let m = audit(
            "log",
            connector(move |s| {
                let _ = serve_audit(s, &*l);
            }),
        )
        .expect("connect");
        let mut st = AuditState::new("192.0.2.1:88".parse().ok());
        st.stage = AuditStage::EncrRep;
        st.status = Some("ISSUE".into());
        st.client = Some("u@R".into());
        st.tkt_out_id = Some("AB".into());
        st.violation = 2;
        m.kdc_start(true);
        m.as_req(false, &st);
        m.u2u(true, &st);
        m.tgs_req(true, &st);
        drop(m);
        let got = log.0.lock().expect("lock").clone();
        assert_eq!(
            got,
            [
                "open".to_string(),
                "kdc_start true".into(),
                format!("as_req false {st:?}"),
                "u2u true Some(\"ISSUE\")".into(),
                "close".into(),
            ]
        );
    }

    #[test]
    fn malformed_requests_are_answered() {
        let (mut a, b) = UnixStream::pair().expect("pair");
        let t = std::thread::spawn(move || serve_kdcpolicy(b, &MitTest));
        a.write_all(&[7]).expect("version");
        let mut v = [0u8];
        a.read_exact(&mut v).expect("version");
        assert_eq!(v[0], PROTOCOL_VERSION);
        let mut m = Message::new(call::CHECK_AS);
        m.put_i32(1);
        write_message(&mut a, 9, &m).expect("write");
        let (id, mut r) = read_message(&mut a).expect("read");
        assert_eq!((id, r.call), (9, call::ERROR));
        assert_eq!(
            r.get_i32().expect("code"),
            ERROR_TABLE_BASE_KRB5 + KRB_ERR_GENERIC
        );
        write_message(&mut a, 10, &Message::new(call::FINALIZE)).expect("write");
        assert_eq!(read_message(&mut a).expect("read").1.call, call::FINALIZE);
        t.join().expect("join").expect("serve");
    }

    struct Capture(Arc<Mutex<Vec<AuthdataRequest>>>);

    impl KdcAuthdata for Capture {
        fn name(&self) -> &str {
            "capture"
        }
        fn handle(&self, req: &AuthdataRequest, _reply: &mut EncTicketPart) -> Result<(), i32> {
            self.0.lock().expect("lock").push(req.clone());
            Ok(())
        }
    }

    #[test]
    fn authdata_entries_round_trip() {
        let got = Arc::new(Mutex::new(Vec::new()));
        let g = Arc::clone(&got);
        let m = kdcauthdata(
            "capture",
            connector(move |s| {
                let _ = serve_kdcauthdata(s, &Capture(Arc::clone(&g)));
            }),
        )
        .expect("connect");
        let t = crate::kdc::policy::kerberos_time;
        let entry = PrincipalEntry {
            name: PrincipalName::new_principal("alice"),
            realm: "R".into(),
            attributes: PrincipalAttributes::REQUIRES_PRE_AUTH
                | PrincipalAttributes::REQUIRES_HW_AUTH,
            max_life: Some(std::time::Duration::from_secs(3600)),
            max_renewable_life: None,
            expiration: Some(t(1_900_000_000)),
            pw_expiration: None,
            keys: vec![
                KeyEntry {
                    kvno: 3,
                    key: EncryptionKey::new(18, vec![7; 32]),
                    salt: Some(Vec::new()),
                    s2kparams: None,
                },
                KeyEntry {
                    kvno: 3,
                    key: EncryptionKey::new(17, vec![8; 16]),
                    salt: None,
                    s2kparams: Some(vec![0, 0, 16, 0]),
                },
            ],
            allowed_to_delegate_to: vec!["svc@R".into()],
            allowed_to_delegate_from: Vec::new(),
            require_auth: Some("otp".into()),
            otp: None,
            pkinit_cert_match: Some("<SAN>alice".into()),
            policy: Some("default".into()),
            security_epoch: u64::MAX - 1,
            last_admin_unlock: Some(t(1_700_000_000)),
        };
        let req = AuthdataRequest {
            msg_type: super::super::MSG_AS_REQ,
            client_entry: Some(entry.clone()),
            header_server_entry: Some(entry),
            ..AuthdataRequest::default()
        };
        let at = chrono::DateTime::from_timestamp(1_700_000_000, 0)
            .expect("time")
            .fixed_offset();
        let mut reply = EncTicketPart {
            flags: crate::types::KerberosFlags::new(crate::types::TicketFlags::empty()),
            key: EncryptionKey::new(18, vec![1; 32]),
            crealm: crate::kdc::error::general_string("R").expect("realm"),
            cname: PrincipalName::new_principal("alice"),
            transited: crate::types::TransitedEncoding {
                tr_type: 1,
                contents: Vec::new().into(),
            },
            authtime: at,
            starttime: None,
            endtime: at,
            renew_till: None,
            caddr: None,
            authorization_data: None,
        };
        m.handle(&req, &mut reply).expect("handle");
        drop(m);
        let got = got.lock().expect("lock").clone();
        assert_eq!(got.len(), 1);
        assert_eq!(format!("{:?}", got[0]), format!("{req:?}"));
    }
}
