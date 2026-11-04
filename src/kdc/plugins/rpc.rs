//! kdcpolicy and audit modules as separate processes, reached over RPC the
//! way p11-kit remotes PKCS #11 modules (as in
//! <https://github.com/smallstep/go-p11-kit>): the KDC connects to a
//! module's socket, agrees on a protocol version, and sends each callback
//! as a request; the module answers each in turn.
//!
//! Framing follows p11-kit's RPC: one version byte each way (the module
//! answers the lower of the client's and its own), then messages of
//! `id u32, options_len u32, buffer_len u32` (big-endian) followed by
//! `options_len` ignored bytes and a buffer of `call u32`, a signature
//! (`u32` length and bytes) and the fields. Field types: `i` is an `i32`,
//! `s` a string (`u32` length, `0xFFFFFFFF` for none, UTF-8 bytes) and `as`
//! a `u32` count of strings. A failed call is answered with call
//! [`call::ERROR`] and `is`: an MIT com_err code and an optional status.
//! The first request is [`call::INITIALIZE`] with the interface's handshake
//! string, and the last [`call::FINALIZE`].
//!
//! [`serve_kdcpolicy`] and [`serve_audit`] run the module side for a
//! [`KdcPolicy`] or [`Audit`]; [`kdcpolicy`] and [`audit`] connect the KDC
//! side.

use std::io::{self, Read, Write};
use std::sync::{Mutex, MutexGuard, PoisonError};

use super::{Audit, AuditStage, AuditState, KdcPolicy, PolicyLimits, PolicyRefusal, PolicyRequest};

/// The RPC protocol version.
pub const PROTOCOL_VERSION: u8 = 1;
/// [`call::INITIALIZE`]'s string for a kdcpolicy module.
pub const KDCPOLICY_HANDSHAKE: &str = "KRB5RS-KDCPOLICY-V-1";
/// [`call::INITIALIZE`]'s string for an audit module.
pub const AUDIT_HANDSHAKE: &str = "KRB5RS-AUDIT-V-1";
/// `KRB5_PLUGIN_NO_HANDLE`.
pub const PLUGIN_NO_HANDLE: i32 = -1_765_328_135;
/// `KRB5_PLUGIN_VER_NOTSUPP`.
pub const PLUGIN_VER_NOTSUPP: i32 = -1_765_328_136;
/// `ERROR_TABLE_BASE_krb5`: protocol error `n` is com_err code base + `n`.
pub const ERROR_TABLE_BASE_KRB5: i32 = -1_765_328_384;
const KRB_ERR_GENERIC: i32 = 60;
const MAX_MESSAGE: u32 = 1 << 20;

/// Call numbers.
pub mod call {
    /// A failed call's answer.
    pub const ERROR: u32 = 0;
    /// `init` / `open`: `s` handshake.
    pub const INITIALIZE: u32 = 1;
    /// `fini` / `close`.
    pub const FINALIZE: u32 = 2;
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

fn bad(m: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, m.into())
}

/// A request or answer.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Message {
    /// The call number.
    pub call: u32,
    sig: String,
    buf: Vec<u8>,
    pos: usize,
}

impl Message {
    /// An empty message for `call`.
    pub fn new(call: u32) -> Self {
        Self {
            call,
            ..Self::default()
        }
    }

    /// Append an `i`.
    pub fn put_i32(&mut self, v: i32) -> &mut Self {
        self.sig.push('i');
        self.buf.extend(v.to_be_bytes());
        self
    }

    fn raw_str(&mut self, s: Option<&str>) {
        match s {
            Some(s) => {
                // A string over 4 GiB makes the message too long to send.
                let n = u32::try_from(s.len()).unwrap_or(u32::MAX - 1);
                self.buf.extend(n.to_be_bytes());
                self.buf.extend(s.as_bytes());
            }
            None => self.buf.extend(u32::MAX.to_be_bytes()),
        }
    }

    /// Append an `s`.
    pub fn put_str(&mut self, s: Option<&str>) -> &mut Self {
        self.sig.push('s');
        self.raw_str(s);
        self
    }

    /// Append an `as`.
    pub fn put_strs(&mut self, v: &[String]) -> &mut Self {
        self.sig.push_str("as");
        let n = u32::try_from(v.len()).unwrap_or(u32::MAX);
        self.buf.extend(n.to_be_bytes());
        for s in v {
            self.raw_str(Some(s));
        }
        self
    }

    fn expect(&mut self, want: &str) -> io::Result<()> {
        if self.sig.starts_with(want) {
            self.sig.drain(..want.len());
            Ok(())
        } else {
            Err(bad(format!("expected '{want}', have '{}'", self.sig)))
        }
    }

    fn take(&mut self, n: usize) -> io::Result<&[u8]> {
        let end = self
            .pos
            .checked_add(n)
            .filter(|&e| e <= self.buf.len())
            .ok_or_else(|| bad("truncated message"))?;
        let s = &self.buf[self.pos..end];
        self.pos = end;
        Ok(s)
    }

    fn raw_u32(&mut self) -> io::Result<u32> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// Read an `i`.
    pub fn get_i32(&mut self) -> io::Result<i32> {
        self.expect("i")?;
        let b = self.take(4)?;
        Ok(i32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn raw_string(&mut self) -> io::Result<Option<String>> {
        let n = self.raw_u32()?;
        if n == u32::MAX {
            return Ok(None);
        }
        let b = self.take(n as usize)?.to_vec();
        String::from_utf8(b)
            .map(Some)
            .map_err(|_| bad("string is not UTF-8"))
    }

    /// Read an `s`.
    pub fn get_str(&mut self) -> io::Result<Option<String>> {
        self.expect("s")?;
        self.raw_string()
    }

    /// Read an `as`.
    pub fn get_strs(&mut self) -> io::Result<Vec<String>> {
        self.expect("as")?;
        let n = self.raw_u32()?;
        let mut v = Vec::new();
        for _ in 0..n {
            v.push(
                self.raw_string()?
                    .ok_or_else(|| bad("missing string in array"))?,
            );
        }
        Ok(v)
    }

    /// Fail if fields are left unread.
    pub fn finish(&self) -> io::Result<()> {
        if !self.sig.is_empty() || self.pos != self.buf.len() {
            return Err(bad(format!("trailing elements '{}'", self.sig)));
        }
        Ok(())
    }
}

fn be32(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}

/// Send `m` as message `id`.
pub fn write_message(w: &mut impl Write, id: u32, m: &Message) -> io::Result<()> {
    let sig_len = u32::try_from(m.sig.len()).map_err(|_| bad("message too long"))?;
    let len = u32::try_from(8 + m.sig.len() + m.buf.len())
        .ok()
        .filter(|&l| l <= MAX_MESSAGE)
        .ok_or_else(|| bad("message too long"))?;
    let mut out = Vec::with_capacity(12 + len as usize);
    out.extend(id.to_be_bytes());
    out.extend(0u32.to_be_bytes());
    out.extend(len.to_be_bytes());
    out.extend(m.call.to_be_bytes());
    out.extend(sig_len.to_be_bytes());
    out.extend(m.sig.as_bytes());
    out.extend(&m.buf);
    w.write_all(&out)?;
    w.flush()
}

/// Receive a message and its id.
pub fn read_message(r: &mut impl Read) -> io::Result<(u32, Message)> {
    let mut h = [0u8; 12];
    r.read_exact(&mut h)?;
    let (id, opts, len) = (be32(&h[0..4]), be32(&h[4..8]), be32(&h[8..12]));
    let total = opts
        .checked_add(len)
        .filter(|&t| t <= MAX_MESSAGE)
        .ok_or_else(|| bad("message too long"))?;
    let mut b = vec![0; total as usize];
    r.read_exact(&mut b)?;
    let mut m = Message {
        buf: b.split_off(opts as usize),
        ..Message::default()
    };
    m.call = m.raw_u32()?;
    let n = m.raw_u32()?;
    let sig = m.take(n as usize)?.to_vec();
    m.sig = String::from_utf8(sig).map_err(|_| bad("signature is not UTF-8"))?;
    Ok((id, m))
}

/// An error answer: com_err code and status.
pub type CallError = (i32, Option<String>);

fn error_message(code: i32, status: Option<&str>) -> Message {
    let mut m = Message::new(call::ERROR);
    m.put_i32(code).put_str(status);
    m
}

/// The KDC end of a module connection.
pub struct Client<S> {
    stream: S,
    next_id: u32,
}

impl<S: Read + Write> Client<S> {
    /// Agree on the protocol version and initialize the module.
    pub fn handshake(mut stream: S, handshake: &str) -> io::Result<Result<Self, CallError>> {
        stream.write_all(&[PROTOCOL_VERSION])?;
        stream.flush()?;
        let mut v = [0u8];
        stream.read_exact(&mut v)?;
        if v[0] != PROTOCOL_VERSION {
            return Err(bad(format!("module speaks protocol version {}", v[0])));
        }
        let mut c = Self { stream, next_id: 0 };
        let mut m = Message::new(call::INITIALIZE);
        m.put_str(Some(handshake));
        Ok(c.call(&m)?.map(|_| c))
    }

    /// Send `m` and wait for its answer.
    pub fn call(&mut self, m: &Message) -> io::Result<Result<Message, CallError>> {
        self.next_id = self.next_id.wrapping_add(1);
        write_message(&mut self.stream, self.next_id, m)?;
        let (id, mut r) = read_message(&mut self.stream)?;
        if id != self.next_id {
            return Err(bad("answer to another request"));
        }
        if r.call == call::ERROR {
            let code = r.get_i32()?;
            let status = r.get_str()?;
            r.finish()?;
            return Ok(Err((code, status)));
        }
        if r.call != m.call {
            return Err(bad("answer to another call"));
        }
        Ok(Ok(r))
    }
}

/// Serve the module end of a connection: `handle` answers every request
/// after the handshake, including [`call::INITIALIZE`] and
/// [`call::FINALIZE`], after which the connection ends.
pub fn serve<S: Read + Write>(
    mut stream: S,
    handshake: &str,
    mut handle: impl FnMut(&mut Message) -> io::Result<Result<Message, CallError>>,
) -> io::Result<()> {
    let mut v = [0u8];
    stream.read_exact(&mut v)?;
    stream.write_all(&[v[0].min(PROTOCOL_VERSION)])?;
    stream.flush()?;
    loop {
        let (id, mut req) = match read_message(&mut stream) {
            Ok(r) => r,
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(e) => return Err(e),
        };
        let done = req.call == call::FINALIZE;
        let answer = if req.call == call::INITIALIZE
            && req.get_str().ok().flatten().as_deref() != Some(handshake)
        {
            Err((PLUGIN_VER_NOTSUPP, None))
        } else {
            // A request that doesn't decode is answered, as p11-kit does,
            // so the connection stays in step.
            handle(&mut req).unwrap_or_else(|e| {
                Err((ERROR_TABLE_BASE_KRB5 + KRB_ERR_GENERIC, Some(e.to_string())))
            })
        };
        let m = match answer {
            Ok(m) => m,
            Err((code, status)) => error_message(code, status.as_deref()),
        };
        write_message(&mut stream, id, &m)?;
        if done {
            return Ok(());
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

/// A connection the KDC can read and write.
pub trait Stream: Read + Write + Send {}
impl<T: Read + Write + Send> Stream for T {}

/// Opens a new connection to a module.
pub type Connect = Box<dyn Fn() -> io::Result<Box<dyn Stream>> + Send + Sync>;

/// Why a module was not loaded.
#[derive(Debug)]
pub enum InitError {
    /// The module could not be reached; MIT skips a module that does not load.
    Unavailable(io::Error),
    /// The module's `init`/`open` failed with this code.
    Refused(CallError),
}

impl std::fmt::Display for InitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unavailable(e) => write!(f, "{e}"),
            Self::Refused((code, _)) => write!(f, "{code}"),
        }
    }
}

struct Conn {
    name: String,
    handshake: &'static str,
    connect: Connect,
    client: Mutex<Option<Client<Box<dyn Stream>>>>,
}

impl Conn {
    fn open(name: &str, handshake: &'static str, connect: Connect) -> Result<Self, InitError> {
        let stream = connect().map_err(InitError::Unavailable)?;
        let client = Client::handshake(stream, handshake)
            .map_err(InitError::Unavailable)?
            .map_err(InitError::Refused)?;
        Ok(Self {
            name: name.into(),
            handshake,
            connect,
            client: Mutex::new(Some(client)),
        })
    }

    fn lock(&self) -> MutexGuard<'_, Option<Client<Box<dyn Stream>>>> {
        self.client.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// One call; calls run one at a time, and a broken connection is
    /// opened again (and the module initialized again) on the next call.
    fn call(&self, m: &Message) -> io::Result<Result<Message, CallError>> {
        let mut client = self.lock();
        if client.is_none() {
            match Client::handshake((self.connect)()?, self.handshake)? {
                Ok(c) => *client = Some(c),
                Err((code, _)) => {
                    return Err(io::Error::other(format!(
                        "module {} failed to initialize: {code}",
                        self.name
                    )))
                }
            }
        }
        let Some(c) = client.as_mut() else {
            return Err(io::Error::other("no connection"));
        };
        let r = c.call(m);
        if r.is_err() {
            *client = None;
        }
        r
    }
}

impl Drop for Conn {
    fn drop(&mut self) {
        if let Some(c) = self.lock().as_mut() {
            let _ = c.call(&Message::new(call::FINALIZE));
        }
    }
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

/// Connect to a Unix socket, with `timeout` on each read and write.
#[cfg(unix)]
pub fn unix_connector(path: std::path::PathBuf, timeout: std::time::Duration) -> Connect {
    Box::new(move || {
        let s = std::os::unix::net::UnixStream::connect(&path)?;
        s.set_read_timeout(Some(timeout))?;
        s.set_write_timeout(Some(timeout))?;
        Ok(Box::new(s) as Box<dyn Stream>)
    })
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::net::UnixStream;
    use std::sync::Arc;

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
