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

use super::{Audit, AuditStage, AuditState, KdcPolicy, PolicyLimits, PolicyRefusal, PolicyRequest};

/// [`call::INITIALIZE`]'s string for a kdcpolicy module.
pub const KDCPOLICY_HANDSHAKE: &str = "KRB5RS-KDCPOLICY-V-1";
/// [`call::INITIALIZE`]'s string for an audit module.
pub const AUDIT_HANDSHAKE: &str = "KRB5RS-AUDIT-V-1";

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

/// Connect to the audit module `name`.
pub fn audit(name: &str, connect: Connect) -> Result<RemoteAudit, InitError> {
    Conn::open(name, AUDIT_HANDSHAKE, connect).map(RemoteAudit)
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
}
