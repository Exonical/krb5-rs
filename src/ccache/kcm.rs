//! KCM ccaches (cc_kcm.c): credentials held by a KCM daemon (Heimdal kcm,
//! SSSD) reached over a Unix socket.

use std::cell::{Cell, RefCell};
use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;

use super::marshal::{marshal_cred, marshal_mcred, marshal_princ, unmarshal_cred, unmarshal_princ};
use super::retrieve::retrieve_in;
use super::{
    config_cred, config_matches, CcCredential, CcError, Ccache, MatchCred, MatchFlags, CONFIG_REALM,
};
use crate::types::PrincipalName;

fn arr4(s: &[u8]) -> [u8; 4] {
    let mut a = [0; 4];
    a.copy_from_slice(&s[..4]);
    a
}

/// `DEFAULT_KCM_SOCKET_PATH`.
pub const DEFAULT_SOCKET: &str = "/var/run/.heim_org.h5l.kcm-socket";
const MAX_REPLY_SIZE: usize = 10 * 1024 * 1024;
const UUID_LEN: usize = 16;
const VERSION_MAJOR: u8 = 2;
const VERSION_MINOR: u8 = 0;

/// KCM opcodes (kcm.h).
#[allow(missing_docs)]
pub mod op {
    pub const NOOP: u16 = 0;
    pub const GET_NAME: u16 = 1;
    pub const RESOLVE: u16 = 2;
    pub const GEN_NEW: u16 = 3;
    pub const INITIALIZE: u16 = 4;
    pub const DESTROY: u16 = 5;
    pub const STORE: u16 = 6;
    pub const RETRIEVE: u16 = 7;
    pub const GET_PRINCIPAL: u16 = 8;
    pub const GET_CRED_UUID_LIST: u16 = 9;
    pub const GET_CRED_BY_UUID: u16 = 10;
    pub const REMOVE_CRED: u16 = 11;
    pub const SET_FLAGS: u16 = 12;
    pub const CHOWN: u16 = 13;
    pub const CHMOD: u16 = 14;
    pub const GET_INITIAL_TICKET: u16 = 15;
    pub const GET_TICKET: u16 = 16;
    pub const MOVE_CACHE: u16 = 17;
    pub const GET_CACHE_UUID_LIST: u16 = 18;
    pub const GET_CACHE_BY_UUID: u16 = 19;
    pub const GET_DEFAULT_CACHE: u16 = 20;
    pub const SET_DEFAULT_CACHE: u16 = 21;
    pub const GET_KDC_OFFSET: u16 = 22;
    pub const SET_KDC_OFFSET: u16 = 23;
    pub const GET_CRED_LIST: u16 = 13001;
    pub const REPLACE: u16 = 13002;
}

/// Heimdal match flags (kcm.h).
mod tc {
    pub const GC_CACHED: u32 = 1;
    pub const MATCH_KEYTYPE: u32 = 1 << 30;
    pub const MATCH_SRV_NAMEONLY: u32 = 1 << 29;
    pub const MATCH_FLAGS_EXACT: u32 = 1 << 28;
    pub const MATCH_FLAGS: u32 = 1 << 27;
    pub const MATCH_TIMES_EXACT: u32 = 1 << 26;
    pub const MATCH_TIMES: u32 = 1 << 25;
    pub const MATCH_AUTHDATA: u32 = 1 << 24;
    pub const MATCH_2ND_TKT: u32 = 1 << 23;
    pub const MATCH_IS_SKEY: u32 = 1 << 22;
}

/// MIT error codes a KCM daemon returns that change client behavior.
mod code {
    pub const CC_END: i32 = -1_765_328_242;
    pub const CC_NOTFOUND: i32 = -1_765_328_243;
    pub const FCC_NOFILE: i32 = -1_765_328_189;
    pub const FCC_INTERNAL: i32 = -1_765_328_188;
    pub const CC_IO: i32 = -1_765_328_191;
    pub const CC_NOSUPP: i32 = -1_765_328_137;
    pub const CC_FORMAT: i32 = -1_765_328_185;
}

/// `map_tcflags`.
fn map_tcflags(f: MatchFlags) -> u32 {
    let pairs = [
        (MatchFlags::TIMES, tc::MATCH_TIMES),
        (MatchFlags::IS_SKEY, tc::MATCH_IS_SKEY),
        (MatchFlags::FLAGS, tc::MATCH_FLAGS),
        (MatchFlags::TIMES_EXACT, tc::MATCH_TIMES_EXACT),
        (MatchFlags::FLAGS_EXACT, tc::MATCH_FLAGS_EXACT),
        (MatchFlags::AUTHDATA, tc::MATCH_AUTHDATA),
        (MatchFlags::SRV_NAMEONLY, tc::MATCH_SRV_NAMEONLY),
        (MatchFlags::SECOND_TKT, tc::MATCH_2ND_TKT),
        (MatchFlags::KTYPE, tc::MATCH_KEYTYPE),
    ];
    pairs
        .iter()
        .filter(|(m, _)| f.contains(*m))
        .fold(0, |acc, (_, h)| acc | h)
}

/// A failed KCM call: a status from the daemon or a local error.
enum KcmErr {
    Status(i32),
    Local(CcError),
}

impl From<CcError> for KcmErr {
    fn from(e: CcError) -> Self {
        Self::Local(e)
    }
}

impl KcmErr {
    /// `unsupported_op_error`.
    fn unsupported(&self) -> bool {
        matches!(
            self,
            Self::Status(code::FCC_INTERNAL | code::CC_IO | code::CC_NOSUPP)
        )
    }

    fn is(&self, c: i32) -> bool {
        matches!(self, Self::Status(s) if *s == c)
    }

    fn into_cc(self) -> CcError {
        match self {
            Self::Local(e) => e,
            Self::Status(code::CC_END) => CcError::End,
            Self::Status(code::CC_NOTFOUND) => CcError::NotFound,
            Self::Status(code::FCC_NOFILE) => CcError::NoFile("No credentials cache found".into()),
            Self::Status(code::CC_FORMAT) => malformed(),
            Self::Status(c) => CcError::code("KCM", format!("KCM daemon error {c}")),
        }
    }
}

fn malformed() -> CcError {
    CcError::code(
        "KRB5_KCM_MALFORMED_REPLY",
        "Malformed reply from KCM daemon",
    )
}

/// `map_invalid`.
fn map_invalid(e: CcError) -> CcError {
    match e {
        CcError::Format => malformed(),
        e => e,
    }
}

fn cc_io() -> CcError {
    CcError::code("KRB5_CC_IO", "Credentials cache I/O operation failed")
}

/// A connection to the KCM daemon (`struct kcmio`).
struct KcmIo {
    path: String,
    stream: UnixStream,
}

impl KcmIo {
    /// `kcmio_unix_socket_connect`: `path` is `[libdefaults] kcm_socket`.
    fn connect(path: Option<&str>) -> Result<Self, CcError> {
        let path = path.unwrap_or(DEFAULT_SOCKET).to_string();
        let stream = Self::open(&path)?;
        Ok(Self { path, stream })
    }

    fn open(path: &str) -> Result<UnixStream, CcError> {
        let no_server = || CcError::code("KRB5_KCM_NO_SERVER", "No KCM server found");
        if path == "-" {
            return Err(no_server());
        }
        UnixStream::connect(path).map_err(|e| {
            if e.kind() == io::ErrorKind::NotFound {
                no_server()
            } else {
                CcError::Io(e)
            }
        })
    }

    /// `kcmio_call`: send a request and return the reply after its status.
    fn call(&mut self, req: &[u8]) -> Result<Vec<u8>, KcmErr> {
        let mut msg = (req.len() as u32).to_be_bytes().to_vec();
        msg.extend_from_slice(req);
        if let Err(e) = self.stream.write_all(&msg) {
            if e.kind() != io::ErrorKind::BrokenPipe {
                return Err(CcError::Io(e).into());
            }
            // The daemon closed an idle connection; reconnect once.
            self.stream = Self::open(&self.path)?;
            self.stream.write_all(&msg).map_err(CcError::Io)?;
        }
        let read4 = |s: &mut UnixStream| -> Result<[u8; 4], CcError> {
            let mut b = [0; 4];
            s.read_exact(&mut b).map_err(|e| {
                if e.kind() == io::ErrorKind::UnexpectedEof {
                    cc_io()
                } else {
                    CcError::Io(e)
                }
            })?;
            Ok(b)
        };
        let len = u32::from_be_bytes(read4(&mut self.stream)?) as usize;
        if len > MAX_REPLY_SIZE {
            return Err(CcError::code("KRB5_KCM_REPLY_TOO_BIG", "KCM daemon reply too big").into());
        }
        let status = i32::from_be_bytes(read4(&mut self.stream)?);
        let mut reply = vec![0; len];
        if status != 0 {
            // Consume the body so the next call on this stream starts in sync.
            let _ = self.stream.read_exact(&mut reply);
            return Err(KcmErr::Status(status));
        }
        self.stream.read_exact(&mut reply).map_err(|_| cc_io())?;
        if reply.len() < 4 {
            return Err(malformed().into());
        }
        let status = i32::from_be_bytes(arr4(&reply[..4]));
        if status != 0 {
            return Err(KcmErr::Status(status));
        }
        reply.drain(..4);
        Ok(reply)
    }

    fn request(
        &mut self,
        opcode: u16,
        cache: Option<&str>,
        args: &[u8],
    ) -> Result<Vec<u8>, KcmErr> {
        let mut req = vec![VERSION_MAJOR, VERSION_MINOR];
        req.extend_from_slice(&opcode.to_be_bytes());
        if let Some(name) = cache {
            req.extend_from_slice(name.as_bytes());
            req.push(0);
        }
        req.extend_from_slice(args);
        self.call(&req)
    }
}

/// `kcmreq_get_name`.
fn get_name(reply: &[u8]) -> Result<String, CcError> {
    let end = reply.iter().position(|&b| b == 0).ok_or_else(malformed)?;
    Ok(String::from_utf8_lossy(&reply[..end]).into_owned())
}

/// `kcmreq_get_uuid_list`.
fn get_uuid_list(reply: &[u8]) -> Result<Vec<[u8; UUID_LEN]>, CcError> {
    if !reply.len().is_multiple_of(UUID_LEN) {
        return Err(malformed());
    }
    Ok(reply.as_chunks::<UUID_LEN>().0.to_vec())
}

/// `kcmreq_get_cred_list`.
fn get_cred_list(reply: &[u8]) -> Result<Vec<CcCredential>, CcError> {
    let take = |pos: &mut usize, n: usize| -> Result<&[u8], CcError> {
        let s = reply.get(*pos..*pos + n).ok_or_else(malformed)?;
        *pos += n;
        Ok(s)
    };
    let mut pos = 0;
    let count = u32::from_be_bytes(arr4(take(&mut pos, 4)?)) as usize;
    if count > (reply.len() - pos) / 4 {
        return Err(malformed());
    }
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        let len = u32::from_be_bytes(arr4(take(&mut pos, 4)?)) as usize;
        let data = take(&mut pos, len)?;
        out.push(unmarshal_cred(data, 4).map_err(|_| malformed())?);
    }
    Ok(out)
}

/// A KCM cache.
pub struct KcmCcache {
    residual: String,
    io: RefCell<KcmIo>,
    time_offset: Cell<Option<i32>>,
}

impl KcmCcache {
    fn call(&self, opcode: u16, args: &[u8]) -> Result<Vec<u8>, KcmErr> {
        self.io
            .borrow_mut()
            .request(opcode, Some(&self.residual), args)
    }

    /// `kcm_resolve`: an empty residual names the daemon's default cache.
    /// `socket` is `[libdefaults] kcm_socket`.
    pub fn resolve(residual: &str, socket: Option<&str>) -> Result<Self, CcError> {
        let mut io = KcmIo::connect(socket)?;
        let residual = if residual.is_empty() {
            let r = io
                .request(op::GET_DEFAULT_CACHE, None, &[])
                .map_err(KcmErr::into_cc)?;
            get_name(&r)?
        } else {
            residual.to_string()
        };
        Ok(Self::with_io(residual, io))
    }

    fn with_io(residual: String, io: KcmIo) -> Self {
        Self {
            residual,
            io: RefCell::new(io),
            time_offset: Cell::new(None),
        }
    }

    /// `kcm_gen_new`: a new cache named by the daemon.
    pub fn gen_new(socket: Option<&str>) -> Result<Self, CcError> {
        let mut io = KcmIo::connect(socket)?;
        let r = io
            .request(op::GEN_NEW, None, &[])
            .map_err(KcmErr::into_cc)?;
        Ok(Self::with_io(get_name(&r)?, io))
    }

    /// The full name, `KCM:residual`.
    pub fn name(&self) -> String {
        format!("KCM:{}", self.residual)
    }

    /// The KDC time offset (seconds) to send at `initialize`.
    pub fn set_time_offset(&mut self, secs: i32) {
        self.time_offset.set(Some(secs));
    }

    /// `get_kdc_offset`: the daemon's KDC time offset for this cache.
    pub fn time_offset(&self) -> Option<i32> {
        let r = self.call(op::GET_KDC_OFFSET, &[]).ok()?;
        Some(i32::from_be_bytes(r.get(..4)?.try_into().ok()?))
    }

    /// `kcm_destroy`.
    pub fn destroy(self) -> Result<(), CcError> {
        self.call(op::DESTROY, &[])
            .map(drop)
            .map_err(KcmErr::into_cc)
    }

    /// `kcm_switch_to`: make this the daemon's default cache.
    pub fn switch_to(&self) -> Result<(), CcError> {
        self.call(op::SET_DEFAULT_CACHE, &[])
            .map(drop)
            .map_err(KcmErr::into_cc)
    }

    /// `kcm_replace`: reinitialize with `client` and `creds` in one call,
    /// or one step at a time when the daemon lacks `REPLACE`.
    pub fn replace(
        &mut self,
        client: &PrincipalName,
        realm: &str,
        creds: &[CcCredential],
    ) -> Result<(), CcError> {
        let mut args = self.time_offset.get().unwrap_or(0).to_be_bytes().to_vec();
        args.extend_from_slice(&marshal_princ(client, realm, 4));
        args.extend_from_slice(&(creds.len() as u32).to_be_bytes());
        for c in creds {
            let m = marshal_cred(c, 4);
            args.extend_from_slice(&(m.len() as u32).to_be_bytes());
            args.extend_from_slice(&m);
        }
        match self.call(op::REPLACE, &args) {
            Ok(_) => Ok(()),
            Err(e) if e.unsupported() => {
                self.initialize(client, realm)?;
                creds.iter().try_for_each(|c| self.store(c))
            }
            Err(e) => Err(e.into_cc()),
        }
    }

    /// `kcm_ptcursor_new` / `kcm_ptcursor_next`: the daemon's caches,
    /// default first, when the default cache name has type KCM.
    pub fn collection(
        default_name: Option<&str>,
        socket: Option<&str>,
    ) -> Result<Vec<Self>, CcError> {
        let Some(residual) = default_name.and_then(|d| d.strip_prefix("KCM:")) else {
            return Ok(Vec::new());
        };
        let mut io = KcmIo::connect(socket)?;
        let exists = |io: &mut KcmIo, name: &str| {
            let mut a = name.as_bytes().to_vec();
            a.push(0);
            io.request(op::GET_PRINCIPAL, None, &a).is_ok()
        };
        let mut names = Vec::new();
        if !residual.is_empty() {
            if exists(&mut io, residual) {
                names.push(residual.to_string());
            }
        } else {
            let uuids = match io.request(op::GET_CACHE_UUID_LIST, None, &[]) {
                Ok(r) => get_uuid_list(&r)?,
                Err(e) if e.is(code::FCC_NOFILE) => return Ok(Vec::new()),
                Err(e) => return Err(e.into_cc()),
            };
            let primary = get_name(
                &io.request(op::GET_DEFAULT_CACHE, None, &[])
                    .map_err(KcmErr::into_cc)?,
            )?;
            if exists(&mut io, &primary) {
                names.push(primary.clone());
            }
            for u in uuids {
                let name = match io.request(op::GET_CACHE_BY_UUID, None, &u) {
                    Ok(r) => get_name(&r)?,
                    // Deleted since the list was read.
                    Err(e) if e.is(code::CC_END) || e.is(code::FCC_NOFILE) => continue,
                    Err(e) => return Err(e.into_cc()),
                };
                if name != primary {
                    names.push(name);
                }
            }
        }
        names
            .into_iter()
            .map(|n| Ok(Self::with_io(n, KcmIo::connect(socket)?)))
            .collect()
    }
}

impl Ccache for KcmCcache {
    fn initialize(&mut self, client: &PrincipalName, realm: &str) -> Result<(), CcError> {
        self.call(op::INITIALIZE, &marshal_princ(client, realm, 4))
            .map_err(KcmErr::into_cc)?;
        if let Some(offset) = self.time_offset.get() {
            let _ = self.call(op::SET_KDC_OFFSET, &offset.to_be_bytes());
        }
        Ok(())
    }

    fn principal(&self) -> Result<(PrincipalName, String), CcError> {
        let not_found = || {
            CcError::NoFile(format!(
                "Credentials cache 'KCM:{}' not found",
                self.residual
            ))
        };
        match self.call(op::GET_PRINCIPAL, &[]) {
            Ok(r) if r.is_empty() => Err(not_found()),
            Ok(r) => unmarshal_princ(&r, 4).map_err(map_invalid),
            Err(e) if e.is(code::FCC_NOFILE) => Err(not_found()),
            Err(e) => Err(map_invalid(e.into_cc())),
        }
    }

    fn store(&mut self, cred: &CcCredential) -> Result<(), CcError> {
        self.call(op::STORE, &marshal_cred(cred, 4))
            .map(drop)
            .map_err(KcmErr::into_cc)
    }

    fn creds(&self) -> Result<Vec<CcCredential>, CcError> {
        match self.call(op::GET_CRED_LIST, &[]) {
            Ok(r) => get_cred_list(&r),
            Err(e) if e.unsupported() => {
                let r = self
                    .call(op::GET_CRED_UUID_LIST, &[])
                    .map_err(KcmErr::into_cc)?;
                get_uuid_list(&r)?
                    .iter()
                    .map(|u| {
                        let r = self
                            .call(op::GET_CRED_BY_UUID, u)
                            .map_err(KcmErr::into_cc)?;
                        unmarshal_cred(&r, 4).map_err(map_invalid)
                    })
                    .collect()
            }
            Err(e) => Err(e.into_cc()),
        }
    }

    fn remove_cred(&mut self, flags: MatchFlags, m: &MatchCred) -> Result<(), CcError> {
        let mut args = map_tcflags(flags).to_be_bytes().to_vec();
        args.extend_from_slice(&marshal_mcred(m));
        self.call(op::REMOVE_CRED, &args)
            .map(drop)
            .map_err(KcmErr::into_cc)
    }

    fn retrieve(
        &self,
        flags: MatchFlags,
        m: &MatchCred,
        ktypes: Option<&[i32]>,
    ) -> Result<CcCredential, CcError> {
        // KCM_GC_CACHED keeps SSSD from asking the KDC for a missing ticket.
        let mut args = (map_tcflags(flags) | tc::GC_CACHED).to_be_bytes().to_vec();
        args.extend_from_slice(&marshal_mcred(m));
        let local = || retrieve_in(&self.creds()?, flags, m, ktypes);
        let cred = match self.call(op::RETRIEVE, &args) {
            Ok(r) => unmarshal_cred(&r, 4).map_err(map_invalid)?,
            Err(e) if e.unsupported() => return local(),
            Err(e) if e.is(code::CC_END) => return Err(CcError::NotFound),
            Err(e) => return Err(map_invalid(e.into_cc())),
        };
        // The daemon can't match on the permitted session key types.
        if flags.contains(MatchFlags::SUPPORTED_KTYPES) {
            if let Some(k) = ktypes {
                if !k.contains(&cred.keyblock.keytype) {
                    return local();
                }
            }
        }
        Ok(cred)
    }

    fn set_config(
        &mut self,
        principal: Option<(&PrincipalName, &str)>,
        key: &str,
        data: Option<&[u8]>,
    ) -> Result<(), CcError> {
        let m = MatchCred {
            server: Some((
                super::config_principal(principal, key),
                CONFIG_REALM.to_string(),
            )),
            ..Default::default()
        };
        // krb5_cc_set_config: removal failure is ignored.
        let _ = self.remove_cred(MatchFlags::empty(), &m);
        if let Some(data) = data {
            let (client, realm) = self.principal()?;
            self.store(&config_cred(&client, &realm, principal, key, data))?;
        }
        Ok(())
    }

    fn get_config(
        &self,
        principal: Option<(&PrincipalName, &str)>,
        key: &str,
    ) -> Result<Option<Vec<u8>>, CcError> {
        Ok(self
            .creds()?
            .into_iter()
            .find(|c| config_matches(c, principal, key))
            .map(|c| c.ticket))
    }
}
