//! MIT `kprop`/`kpropd` full-database propagation.
//!
//! Wire-compatible with MIT krb5 1.22.2 (`src/kprop/kprop.c`, `kpropd.c`,
//! `kprop_util.c`) including the `krb5_sendauth`/`krb5_recvauth` exchange
//! (`lib/krb5/krb/sendauth.c`, `recvauth.c`): every message is a 4-byte
//! big-endian length followed by the data; the client sends the sendauth
//! and application versions, the server answers with one status byte, then
//! an AP-REQ (mutual) and AP-REP follow. The database size travels in a
//! KRB-SAFE message, the dump in KRB-PRIV blocks of at most 32 KiB with
//! chained cipher state, and the server acknowledges with a KRB-SAFE
//! message carrying the size once the load succeeded.

use std::collections::HashMap;
use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use chrono::{Timelike, Utc};
use rasn::types::{GeneralString, OctetString};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::crypto::enctype_from_name;
use crate::profile::Profile;
use crate::protocol::ap::{ApError, ApReqOptions, AuthContext, AuthContextFlags, KeySource};
use crate::protocol::Credential;
use crate::types::error_codes::*;
use crate::types::{ApOptions, ApReq, HostAddress, KrbErrorMsg, PrincipalName};
use crate::Krb5Error;

/// Service name of the kprop principal (`kprop.h` `KPROP_SERVICE_NAME`).
pub const KPROP_SERVICE_NAME: &str = "host";
/// Service name in `/etc/services` (`kprop.h` `KPROP_SERVICE`).
pub const KPROP_SERVICE: &str = "krb5_prop";
/// Default TCP port (`kprop.h` `KPROP_PORT`).
pub const KPROP_PORT: u16 = 754;
/// Application protocol version (`kprop.h` `KPROP_PROT_VERSION`).
pub const KPROP_PROT_VERSION: &str = "kprop5_01";
/// Sendauth protocol version (`sendauth.c` `sendauth_version`).
pub const SENDAUTH_VERSION: &str = "KRB5_SENDAUTH_V1.0";
/// Database block size (`kprop.h` `KPROP_BUFSIZ`).
pub const KPROP_BUFSIZ: usize = 32768;
/// Largest message accepted. MIT reads any length; a KRB-PRIV block of
/// [`KPROP_BUFSIZ`] bytes is far below this.
pub const MAX_MESSAGE: usize = 1024 * 1024;

/// Errors of a kprop exchange.
#[derive(Debug)]
pub enum KpropError {
    /// Socket or file I/O failed.
    Io(io::Error),
    /// A Kerberos operation failed.
    Krb5(Krb5Error),
    /// The peer rejected the sendauth version (status byte 1).
    BadAuthVersion,
    /// The peer rejected the application version (status byte 2).
    BadApplVersion,
    /// The peer sent an unknown sendauth status byte.
    BadResponse,
    /// The peer sent a KRB-ERROR.
    Remote(Box<KrbErrorMsg>),
    /// Any other protocol violation.
    Protocol(String),
}

impl fmt::Display for KpropError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "{e}"),
            Self::Krb5(e) => write!(f, "{e}"),
            Self::BadAuthVersion => f.write_str("Bad sendauth version was sent"),
            Self::BadApplVersion => f.write_str("Bad application version was sent (via sendauth)"),
            Self::BadResponse => f.write_str("Bad response (during sendauth exchange)"),
            Self::Remote(e) => {
                let text = error_text(e);
                if e.error_code == KRB_ERR_GENERIC {
                    write!(f, "Generic remote error: {text}")
                } else {
                    write!(f, "error {} signalled from server: {text}", e.error_code)
                }
            }
            Self::Protocol(s) => f.write_str(s),
        }
    }
}

impl std::error::Error for KpropError {}

impl From<io::Error> for KpropError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<Krb5Error> for KpropError {
    fn from(e: Krb5Error) -> Self {
        Self::Krb5(e)
    }
}

/// The `e-text` of a KRB-ERROR without MIT's trailing NUL.
pub fn error_text(e: &KrbErrorMsg) -> String {
    e.e_text
        .as_ref()
        .map(|t| {
            String::from_utf8_lossy(t.as_bytes())
                .trim_end_matches('\0')
                .to_string()
        })
        .unwrap_or_default()
}

fn nul_terminated(s: &str) -> Vec<u8> {
    let mut v = s.as_bytes().to_vec();
    v.push(0);
    v
}

/// `krb5_write_message`: 4-byte big-endian length, then the data.
pub async fn write_message<W: AsyncWrite + Unpin>(w: &mut W, data: &[u8]) -> io::Result<()> {
    let len = u32::try_from(data.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "message too long"))?;
    let mut buf = Vec::with_capacity(4 + data.len());
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(data);
    w.write_all(&buf).await?;
    w.flush().await
}

/// `krb5_read_message`.
pub async fn read_message<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<Vec<u8>> {
    let mut len = [0u8; 4];
    r.read_exact(&mut len).await?;
    let len = usize::try_from(u32::from_be_bytes(len))
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "message too long"))?;
    if len > MAX_MESSAGE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("message of {len} bytes exceeds {MAX_MESSAGE}"),
        ));
    }
    let mut data = vec![0u8; len];
    r.read_exact(&mut data).await?;
    Ok(data)
}

/// `encode_database_size` (kprop_util.c): four bytes for 1..=2^32-1,
/// otherwise four zero bytes and the 64-bit size.
pub fn encode_database_size(size: u64) -> Vec<u8> {
    match u32::try_from(size) {
        Ok(small) if small != 0 => small.to_be_bytes().to_vec(),
        _ => {
            let mut v = vec![0u8; 4];
            v.extend_from_slice(&size.to_be_bytes());
            v
        }
    }
}

/// `decode_database_size` (kprop_util.c).
pub fn decode_database_size(data: &[u8]) -> Result<u64, KpropError> {
    let malformed = || KpropError::Protocol("malformed database size message".into());
    if let Ok(four) = <[u8; 4]>::try_from(data) {
        return Ok(u64::from(u32::from_be_bytes(four)));
    }
    if data.len() == 12 && data[..4] == [0, 0, 0, 0] {
        let wide = <[u8; 8]>::try_from(&data[4..]).map_err(|_| malformed())?;
        let size = u64::from_be_bytes(wide);
        if size == 0 || size > u64::from(u32::MAX) {
            return Ok(size);
        }
    }
    Err(malformed())
}

/// `k5_sockaddr_to_address` for the KRB-SAFE/KRB-PRIV sender address.
pub fn host_address(addr: &SocketAddr) -> HostAddress {
    match addr {
        SocketAddr::V4(a) => HostAddress {
            addr_type: 2,
            address: OctetString::from(a.ip().octets().to_vec()),
        },
        SocketAddr::V6(a) => HostAddress {
            addr_type: 24,
            address: OctetString::from(a.ip().octets().to_vec()),
        },
    }
}

/// Auth context as kprop and kpropd set it up: `DO_SEQUENCE` only and a
/// local address but no remote one (kprop.c:293-296, kpropd.c:1228-1241;
/// kpropd uses the peer's address as its "local" address).
pub fn new_auth_context(local: &SocketAddr, clockskew: Duration) -> AuthContext {
    let mut ctx = AuthContext::new();
    ctx.set_flags(AuthContextFlags::DO_SEQUENCE);
    ctx.set_clockskew(clockskew);
    ctx.set_addrs(Some(host_address(local)), None);
    ctx
}

/// The `host/<host>` service principal (`sn2princ_realm`); the host name is
/// lowercased and not canonicalized, as with MIT's default
/// `dns_canonicalize_hostname = fallback`.
pub fn host_service(host: &str) -> PrincipalName {
    PrincipalName::new_srv_hst(KPROP_SERVICE_NAME, &host.to_ascii_lowercase())
}

/// This host's name as `gethostname` returns it, before
/// [`HostCanon::candidates`] (`krb5_sname_to_principal(NULL, ...)`).
pub fn local_hostname() -> io::Result<String> {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .or_else(|| std::env::var("HOSTNAME").ok().filter(|s| !s.is_empty()))
        .or_else(|| {
            std::fs::read_to_string("/etc/hostname")
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
        })
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "cannot determine host name"))
}

/// `[libdefaults] dns_canonicalize_hostname` (`init_ctx.c`, default
/// `fallback`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CanonMode {
    /// Only the name as given, qualified with the default domain.
    False,
    /// Only the DNS-canonicalized name.
    True,
    /// The qualified name first, then the DNS-canonicalized one.
    Fallback,
}

/// Host-name canonicalization of `krb5_sname_to_principal` and
/// `k5_canonprinc` (`sn2princ.c`).
#[derive(Clone, Debug)]
pub struct HostCanon {
    /// `dns_canonicalize_hostname`.
    pub mode: CanonMode,
    /// `rdns`: prefer the reverse lookup of the first address.
    pub rdns: bool,
    /// Domain appended to single-component names (`qualify_shortname`,
    /// default the first resolver search domain).
    pub qualify: Option<String>,
}

impl HostCanon {
    /// Settings from `[libdefaults]`, as `krb5_init_context` reads them.
    pub fn from_profile(profile: &Profile) -> Self {
        let lib = |k: &str| profile.get_string(&["libdefaults", k]);
        let mode = match lib("dns_canonicalize_hostname") {
            Some(v) if v.eq_ignore_ascii_case("fallback") => CanonMode::Fallback,
            Some(v) => match parse_bool(&v) {
                Some(true) => CanonMode::True,
                Some(false) => CanonMode::False,
                None => CanonMode::Fallback,
            },
            None => CanonMode::Fallback,
        };
        let rdns = lib("rdns").and_then(|v| parse_bool(&v)).unwrap_or(true);
        let qualify = match lib("qualify_shortname") {
            Some(v) => Some(v).filter(|v| !v.is_empty()),
            None => {
                primary_domain(&std::fs::read_to_string("/etc/resolv.conf").unwrap_or_default())
            }
        };
        Self {
            mode,
            rdns,
            qualify,
        }
    }

    /// The names `k5_canonprinc` tries for `host`, in order, lower case.
    pub fn candidates(&self, host: &str) -> Vec<String> {
        let mut out = Vec::new();
        if self.mode != CanonMode::True {
            out.push(self.expand(host, false));
        }
        if self.mode != CanonMode::False {
            let name = self.expand(host, true);
            if !out.contains(&name) {
                out.push(name);
            }
        }
        out
    }

    /// `expand_hostname` (sn2princ.c:89-153).
    fn expand(&self, host: &str, use_dns: bool) -> String {
        let canonical = if use_dns {
            dns_canonical(host, self.rdns)
        } else {
            None
        };
        let mut name = match (canonical, &self.qualify) {
            (Some(name), _) => name,
            (None, Some(domain)) if !host.contains('.') => format!("{host}.{domain}"),
            (None, _) => host.to_string(),
        };
        name.make_ascii_lowercase();
        if name.len() > 1 && name.ends_with('.') {
            name.pop();
        }
        name
    }
}

/// MIT profile booleans (`prof_get.c` `parse_boolean`).
fn parse_bool(v: &str) -> Option<bool> {
    match v.to_ascii_lowercase().as_str() {
        "y" | "yes" | "true" | "t" | "1" | "on" => Some(true),
        "n" | "no" | "false" | "nil" | "0" | "off" => Some(false),
        _ => None,
    }
}

/// The resolver's first search domain (`k5_primary_domain`): the last
/// `search` or `domain` line of resolv.conf wins.
fn primary_domain(resolv: &str) -> Option<String> {
    let mut domain = None;
    for line in resolv.lines() {
        let mut words = line.split_whitespace();
        if let Some("search" | "domain") = words.next() {
            domain = words.next().map(|d| d.trim_end_matches('.').to_string());
        }
    }
    domain.filter(|d| !d.is_empty())
}

/// Forward lookup with `AI_CANONNAME`, then optionally a reverse lookup of
/// the first address, as `expand_hostname` does.
#[cfg(unix)]
#[expect(
    unsafe_code,
    reason = "std has no getaddrinfo(AI_CANONNAME) or getnameinfo"
)]
fn dns_canonical(host: &str, rdns: bool) -> Option<String> {
    use std::ffi::{CStr, CString};
    let c_host = CString::new(host).ok()?;
    // SAFETY: an all-zero addrinfo is a valid "no constraints" hints value.
    let mut hints: libc::addrinfo = unsafe { std::mem::zeroed() };
    hints.ai_flags = libc::AI_CANONNAME;
    let mut res: *mut libc::addrinfo = std::ptr::null_mut();
    // SAFETY: c_host is NUL-terminated, hints is initialized and res is a
    // valid out-pointer; the list it receives is freed below.
    let err = unsafe { libc::getaddrinfo(c_host.as_ptr(), std::ptr::null(), &hints, &mut res) };
    if err != 0 || res.is_null() {
        return None;
    }
    // SAFETY: getaddrinfo succeeded, so res points to a valid list that
    // stays alive until freeaddrinfo.
    let ai = unsafe { &*res };
    let mut name = None;
    if !ai.ai_canonname.is_null() {
        // SAFETY: ai_canonname is a NUL-terminated string owned by the list.
        let canon = unsafe { CStr::from_ptr(ai.ai_canonname) };
        name = Some(canon.to_string_lossy().into_owned());
    }
    if rdns {
        let mut buf = [0 as libc::c_char; 1025];
        let len = libc::socklen_t::try_from(buf.len()).unwrap_or(0);
        // SAFETY: ai_addr/ai_addrlen describe a valid socket address and
        // buf is writable for len bytes; no service buffer is requested.
        let err = unsafe {
            libc::getnameinfo(
                ai.ai_addr,
                ai.ai_addrlen,
                buf.as_mut_ptr(),
                len,
                std::ptr::null_mut(),
                0,
                libc::NI_NAMEREQD,
            )
        };
        if err == 0 {
            // SAFETY: getnameinfo NUL-terminates buf on success.
            let reverse = unsafe { CStr::from_ptr(buf.as_ptr()) };
            name = Some(reverse.to_string_lossy().into_owned());
        }
    }
    // SAFETY: res came from a successful getaddrinfo and is freed once.
    unsafe { libc::freeaddrinfo(res) };
    name
}

#[cfg(not(unix))]
fn dns_canonical(_host: &str, _rdns: bool) -> Option<String> {
    None
}

/// `getservbyname("krb5_prop", "tcp")` with MIT's numeric fallback: a
/// number, a `/etc/services` name, or 754 for the default service.
pub fn service_port(port: &str) -> Option<u16> {
    if let Ok(n) = port.parse() {
        return Some(n);
    }
    let services = std::fs::read_to_string("/etc/services").unwrap_or_default();
    services_port(&services, port).or((port == KPROP_SERVICE).then_some(KPROP_PORT))
}

fn services_port(services: &str, name: &str) -> Option<u16> {
    services.lines().find_map(|line| {
        let line = line.split('#').next()?;
        let mut words = line.split_whitespace();
        let service = words.next()?;
        let (port, proto) = words.next()?.split_once('/')?;
        let named = service == name || words.any(|alias| alias == name);
        (named && proto == "tcp")
            .then(|| port.parse().ok())
            .flatten()
    })
}

/// Parties named in a KRB-ERROR.
#[derive(Clone, Copy)]
pub struct ErrorParties<'a> {
    /// Realm of the service.
    pub realm: &'a str,
    /// The kprop service principal.
    pub server: &'a PrincipalName,
    /// The client principal and realm, once known.
    pub client: Option<(&'a PrincipalName, &'a str)>,
}

/// Encode a KRB-ERROR the way kprop/kpropd `send_error` do; the text
/// carries MIT's trailing NUL.
pub fn krb_error(parties: ErrorParties<'_>, code: i32, text: &str) -> Vec<u8> {
    let now = Utc::now();
    let msg = KrbErrorMsg {
        pvno: 5,
        msg_type: 30,
        ctime: None,
        cusec: None,
        stime: now.with_nanosecond(0).unwrap_or(now).fixed_offset(),
        susec: i32::try_from(now.timestamp_subsec_micros()).unwrap_or(0),
        error_code: code,
        crealm: parties
            .client
            .and_then(|(_, r)| GeneralString::from_bytes(r.as_bytes()).ok()),
        cname: parties.client.map(|(c, _)| c.clone()),
        realm: GeneralString::from_bytes(parties.realm.as_bytes()).unwrap_or_default(),
        sname: parties.server.clone(),
        e_text: GeneralString::from_bytes(&nul_terminated(text)).ok(),
        e_data: None,
    };
    rasn::der::encode(&msg).unwrap_or_default()
}

/// Protocol error code for a failed Kerberos call (`retval -
/// ERROR_TABLE_BASE_krb5`, or `KRB_ERR_GENERIC`).
pub fn error_code(e: &Krb5Error) -> i32 {
    match e {
        Krb5Error::Ap(a) => crate::kdc::error::ap_error_code(*a),
        _ => KRB_ERR_GENERIC,
    }
}

async fn send_error<S: AsyncWrite + Unpin>(
    stream: &mut S,
    parties: ErrorParties<'_>,
    code: i32,
    text: &str,
) {
    let _ = write_message(stream, &krb_error(parties, code, text)).await;
}

async fn fail<S: AsyncWrite + Unpin>(
    stream: &mut S,
    parties: ErrorParties<'_>,
    e: KpropError,
    context: &str,
) -> KpropError {
    let (code, text) = match &e {
        KpropError::Krb5(k) if error_code(k) != KRB_ERR_GENERIC => {
            (error_code(k), context.to_string())
        }
        _ => (KRB_ERR_GENERIC, format!("{e} {context}")),
    };
    send_error(stream, parties, code, &text).await;
    KpropError::Protocol(format!("{e} {context}"))
}

fn remote_error(msg: &[u8]) -> KpropError {
    match rasn::der::decode::<KrbErrorMsg>(msg) {
        Ok(e) => KpropError::Remote(Box::new(e)),
        Err(_) => KpropError::Protocol("undecodable KRB-ERROR from peer".into()),
    }
}

fn is_krb_error(msg: &[u8]) -> bool {
    msg.first() == Some(&0x7e)
}

/// Client half of `krb5_sendauth` with `AP_OPTS_MUTUAL_REQUIRED`.
pub async fn sendauth<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    ctx: &mut AuthContext,
    cred: &Credential,
) -> Result<(), KpropError> {
    write_message(stream, &nul_terminated(SENDAUTH_VERSION)).await?;
    write_message(stream, &nul_terminated(KPROP_PROT_VERSION)).await?;
    let mut status = [0u8; 1];
    stream.read_exact(&mut status).await?;
    match status[0] {
        0 => {}
        1 => return Err(KpropError::BadAuthVersion),
        2 => return Err(KpropError::BadApplVersion),
        _ => return Err(KpropError::BadResponse),
    }
    let opts = ApReqOptions {
        mutual_required: true,
        ..ApReqOptions::default()
    };
    let ap_req = ctx.mk_req(&opts, None, cred)?;
    write_message(stream, &ap_req).await?;
    let reply = read_message(stream).await?;
    if !reply.is_empty() {
        return Err(remote_error(&reply));
    }
    let ap_rep = read_message(stream).await?;
    ctx.rd_rep(&ap_rep)?;
    Ok(())
}

/// Send the database (`xmit_database`, kprop.c:400-545): size, KRB-PRIV
/// blocks read from `database`, then wait for the matching acknowledgement.
pub async fn xmit_database<S, R>(
    stream: &mut S,
    ctx: &mut AuthContext,
    parties: ErrorParties<'_>,
    database: &mut R,
    size: u64,
) -> Result<(), KpropError>
where
    S: AsyncRead + AsyncWrite + Unpin,
    R: AsyncRead + Unpin,
{
    let safe = match ctx.mk_safe(&encode_database_size(size)) {
        Ok((m, _)) => m,
        Err(e) => {
            return Err(fail(stream, parties, e.into(), "while encoding database size").await)
        }
    };
    write_message(stream, &safe).await?;
    if let Err(e) = ctx.init_ivector() {
        return Err(fail(
            stream,
            parties,
            e.into(),
            "failed while initializing i_vector",
        )
        .await);
    }
    let mut buf = vec![0u8; KPROP_BUFSIZ];
    let mut sent: u64 = 0;
    loop {
        let n = database.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        let block = match ctx.mk_priv(&buf[..n]) {
            Ok((m, _)) => m,
            Err(e) => {
                let context = format!("while encoding database block starting at {sent}");
                return Err(fail(stream, parties, e.into(), &context).await);
            }
        };
        write_message(stream, &block).await?;
        sent += u64::try_from(n).unwrap_or(u64::MAX);
    }
    if sent != size {
        let text = "Premature EOF found for database file!";
        send_error(stream, parties, KRB_ERR_GENERIC, text).await;
        return Err(KpropError::Protocol(text.into()));
    }
    let reply = read_message(stream)
        .await
        .map_err(|e| KpropError::Protocol(format!("{e} while reading response from server")))?;
    if is_krb_error(&reply) {
        return Err(remote_error(&reply));
    }
    let (data, _) = ctx.rd_safe(&reply).map_err(|e| {
        KpropError::Protocol(format!("{e} while decoding final size packet from server"))
    })?;
    let acked = decode_database_size(&data)?;
    if acked != size {
        return Err(KpropError::Protocol(format!(
            "Kpropd sent database size {acked}, expecting {size}"
        )));
    }
    Ok(())
}

/// The authenticated kprop client.
#[derive(Debug, Clone)]
pub struct Authenticated {
    /// Client principal name.
    pub client: PrincipalName,
    /// Client realm.
    pub crealm: String,
    /// Enctype of the service ticket (`ticket->enc_part.enctype`).
    pub etype: i32,
}

impl Authenticated {
    /// `name@REALM`, as matched against `kpropd.acl`.
    pub fn principal(&self) -> String {
        format!("{}@{}", self.client, self.crealm)
    }
}

/// Server half of `krb5_recvauth` (recvauth.c:40-215) for `kprop5_01`.
pub async fn recvauth<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    ctx: &mut AuthContext,
    servers: &[PrincipalName],
    realm: &str,
    keys: &(dyn KeySource + Sync),
    replay: Option<&ReplayCache>,
) -> Result<Authenticated, KpropError> {
    let Some(first) = servers.first() else {
        return Err(KpropError::Protocol("no server principal".into()));
    };
    let parties = ErrorParties {
        realm,
        server: first,
        client: None,
    };
    let sendauth_version = read_message(stream).await?;
    let mut problem = None;
    if sendauth_version != nul_terminated(SENDAUTH_VERSION) {
        problem = Some((1u8, KpropError::BadAuthVersion));
    }
    let appl_version = read_message(stream).await?;
    if problem.is_none() && appl_version != nul_terminated(KPROP_PROT_VERSION) {
        problem = Some((2u8, KpropError::BadApplVersion));
    }
    let status = problem.as_ref().map_or(0, |(b, _)| *b);
    stream.write_all(&[status]).await?;
    stream.flush().await?;
    if let Some((_, e)) = problem {
        return Err(e);
    }
    let ap_req = read_message(stream).await?;
    // The ticket must be for one of our host principal's canonical names in
    // our realm (k5_sname_compare); an undecodable request fails in rd_req.
    let server = match rasn::der::decode::<ApReq>(&ap_req) {
        Ok(req) => {
            let ours = req.ticket.realm.as_bytes() == realm.as_bytes();
            let found = servers
                .iter()
                .find(|s| ours && s.name_string == req.ticket.sname.name_string);
            let Some(found) = found else {
                let e = Krb5Error::Ap(ApError::WrongPrinc);
                send_error(stream, parties, error_code(&e), &e.to_string()).await;
                return Err(e.into());
            };
            found
        }
        Err(_) => first,
    };
    let auth = match ctx.rd_req(&ap_req, Some(server), keys) {
        Ok(a) => a,
        Err(e) => {
            send_error(stream, parties, error_code(&e), &e.to_string()).await;
            return Err(e.into());
        }
    };
    let crealm = String::from_utf8_lossy(auth.ticket.crealm.as_bytes()).to_string();
    let client = auth.ticket.cname.clone();
    if let Some(cache) = replay {
        let name = format!("{client}@{crealm}");
        let ctime = auth.authenticator.ctime.timestamp();
        if !cache.check(&name, ctime, auth.authenticator.cusec, ctx_skew(ctx)) {
            send_error(stream, parties, KRB_AP_ERR_REPEAT, "Request is a replay").await;
            return Err(KpropError::Protocol(format!(
                "replayed authenticator from {name}"
            )));
        }
    }
    let etype = rasn::der::decode::<ApReq>(&ap_req)
        .map(|r| r.ticket.enc_part.etype)
        .map_err(|_| KpropError::Protocol("undecodable AP-REQ".into()))?;
    write_message(stream, &[]).await?;
    if auth.ap_options.contains(ApOptions::MUTUAL_REQUIRED) {
        let rep = ctx.mk_rep()?;
        write_message(stream, &rep).await?;
    }
    Ok(Authenticated {
        client,
        crealm,
        etype,
    })
}

fn ctx_skew(_ctx: &AuthContext) -> Duration {
    Duration::from_secs(300)
}

/// `authorized_principal` (kpropd.c:1303-1352): a line matches when it
/// starts with the principal followed by whitespace or the end of line, and
/// any enctype after it names the ticket's enctype.
pub fn authorized_principal(acl: &str, principal: &str, etype: i32) -> bool {
    for line in acl.split('\n') {
        let Some(rest) = line.strip_prefix(principal) else {
            continue;
        };
        if rest
            .chars()
            .next()
            .is_some_and(|c| !c.is_ascii_whitespace())
        {
            continue;
        }
        let rest = rest.trim_start_matches(|c: char| c.is_ascii_whitespace());
        if rest.is_empty() || enctype_from_name(rest) == Some(etype) {
            return true;
        }
    }
    false
}

/// Receive the database into `out` (`recv_database`, kpropd.c:1357-1475).
/// Returns the size and the KRB-SAFE acknowledgement to send once the load
/// succeeded.
pub async fn recv_database<S, W>(
    stream: &mut S,
    ctx: &mut AuthContext,
    parties: ErrorParties<'_>,
    out: &mut W,
) -> Result<(u64, Vec<u8>), KpropError>
where
    S: AsyncRead + AsyncWrite + Unpin,
    W: AsyncWrite + Unpin,
{
    let msg = match read_message(stream).await {
        Ok(m) => m,
        Err(e) => return Err(fail(stream, parties, e.into(), "while reading database size").await),
    };
    if is_krb_error(&msg) {
        return Err(remote_error(&msg));
    }
    let data = match ctx.rd_safe(&msg) {
        Ok((d, _)) => d,
        Err(e) => {
            return Err(fail(stream, parties, e.into(), "while decoding database size").await)
        }
    };
    let size = match decode_database_size(&data) {
        Ok(s) => s,
        Err(_) => {
            let text = "malformed database size message";
            send_error(stream, parties, KRB_ERR_GENERIC, text).await;
            return Err(KpropError::Protocol(text.into()));
        }
    };
    if let Err(e) = ctx.init_ivector() {
        return Err(fail(
            stream,
            parties,
            e.into(),
            "failed while initializing i_vector",
        )
        .await);
    }
    let mut received: u64 = 0;
    while received < size {
        let msg = match read_message(stream).await {
            Ok(m) => m,
            Err(e) => {
                let context = format!("while reading database block starting at offset {received}");
                return Err(fail(stream, parties, e.into(), &context).await);
            }
        };
        if is_krb_error(&msg) {
            return Err(remote_error(&msg));
        }
        let block = match ctx.rd_priv(&msg) {
            Ok((b, _)) => b,
            Err(e) => {
                let context =
                    format!("while decoding database block starting at offset {received}");
                return Err(fail(stream, parties, e.into(), &context).await);
            }
        };
        if let Err(e) = out.write_all(&block).await {
            let context = format!("while writing database block starting at offset {received}");
            return Err(fail(stream, parties, e.into(), &context).await);
        }
        received += u64::try_from(block.len()).unwrap_or(u64::MAX);
    }
    out.flush().await?;
    if received > size {
        let text = format!("Received {received} bytes, expected {size} bytes for database file");
        send_error(stream, parties, KRB_ERR_GENERIC, &text).await;
        return Err(KpropError::Protocol(text));
    }
    match ctx.mk_safe(&encode_database_size(size)) {
        Ok((conf, _)) => Ok((size, conf)),
        Err(e) => Err(fail(
            stream,
            parties,
            e.into(),
            "while encoding # of received bytes",
        )
        .await),
    }
}

/// Replay cache shared by every connection: an authenticator is accepted
/// once within twice the clock-skew window.
#[derive(Default)]
pub struct ReplayCache {
    seen: Mutex<HashMap<(String, i64, i32), Instant>>,
}

impl ReplayCache {
    /// True if the authenticator is new.
    pub fn check(&self, client: &str, ctime: i64, cusec: i32, window: Duration) -> bool {
        let mut seen = self.seen.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        seen.retain(|_, at| now.duration_since(*at) < window * 2);
        seen.insert((client.to_string(), ctime, cusec), now)
            .is_none()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn database_size_encoding_matches_kprop_util() {
        assert_eq!(encode_database_size(1), vec![0, 0, 0, 1]);
        assert_eq!(encode_database_size(u64::from(u32::MAX)), vec![0xff; 4]);
        let big = u64::from(u32::MAX) + 1;
        let enc = encode_database_size(big);
        assert_eq!(enc.len(), 12);
        assert_eq!(decode_database_size(&enc).expect("test step"), big);
        assert_eq!(encode_database_size(0), vec![0; 12]);
        assert_eq!(decode_database_size(&[0; 12]).expect("test step"), 0);
        for size in [1, 4096, u64::from(u32::MAX)] {
            assert_eq!(
                decode_database_size(&encode_database_size(size)).expect("test step"),
                size
            );
        }
        let mut small_as_wide = vec![0u8; 4];
        small_as_wide.extend_from_slice(&5u64.to_be_bytes());
        assert!(decode_database_size(&small_as_wide).is_err());
        assert!(decode_database_size(&[1; 12]).is_err());
        assert!(decode_database_size(&[0; 8]).is_err());
    }

    #[test]
    fn acl_matches_like_kpropd() {
        let acl = "host/kdc1.example.com@EXAMPLE.COM\n\
                   host/kdc2.example.com@EXAMPLE.COM aes256-cts-hmac-sha1-96\n\
                   host/kdc3.example.com@EXAMPLE.COMX\n";
        assert!(authorized_principal(
            acl,
            "host/kdc1.example.com@EXAMPLE.COM",
            17
        ));
        assert!(authorized_principal(
            acl,
            "host/kdc2.example.com@EXAMPLE.COM",
            18
        ));
        assert!(!authorized_principal(
            acl,
            "host/kdc2.example.com@EXAMPLE.COM",
            17
        ));
        assert!(!authorized_principal(
            acl,
            "host/kdc3.example.com@EXAMPLE.COM",
            18
        ));
        assert!(!authorized_principal(
            acl,
            "host/kdc4.example.com@EXAMPLE.COM",
            18
        ));
        assert!(authorized_principal("p@R\t\n", "p@R", 18));
    }

    #[test]
    fn host_names_canonicalize_like_sn2princ() {
        let fixed = HostCanon {
            mode: CanonMode::False,
            rdns: false,
            qualify: Some("example.com".into()),
        };
        assert_eq!(fixed.candidates("KDC1"), vec!["kdc1.example.com"]);
        assert_eq!(fixed.candidates("kdc1.other.org."), vec!["kdc1.other.org"]);
        let bare = HostCanon {
            qualify: None,
            ..fixed.clone()
        };
        assert_eq!(bare.candidates("kdc1"), vec!["kdc1"]);
        let profile = Profile::parse(
            "[libdefaults]\n dns_canonicalize_hostname = false\n rdns = no\n qualify_shortname = ex.org\n",
        )
        .expect("profile");
        let canon = HostCanon::from_profile(&profile);
        assert_eq!(canon.mode, CanonMode::False);
        assert!(!canon.rdns);
        assert_eq!(canon.candidates("kdc1"), vec!["kdc1.ex.org"]);
        let fallback = HostCanon::from_profile(&Profile::parse("").expect("profile"));
        assert_eq!(fallback.mode, CanonMode::Fallback);
        assert!(fallback.rdns);
        assert_eq!(
            primary_domain("domain a.org\nsearch b.org c.org\n").as_deref(),
            Some("b.org")
        );
        assert_eq!(primary_domain("nameserver 1.1.1.1\n"), None);
    }

    #[test]
    fn service_port_reads_services_then_defaults() {
        let services = "ssh 22/tcp\nkrb5_prop 17540/tcp kprop # local\nfoo 9/udp\n";
        assert_eq!(services_port(services, "krb5_prop"), Some(17540));
        assert_eq!(services_port(services, "kprop"), Some(17540));
        assert_eq!(services_port(services, "foo"), None);
        assert_eq!(service_port("7540"), Some(7540));
        assert_eq!(service_port("no-such-service-name"), None);
    }

    #[tokio::test]
    async fn version_mismatch_gets_status_byte() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        let keys = crate::keytab::FileKeytab::new(
            std::env::temp_dir().join("krb5rs-kprop-test-missing.keytab"),
        );
        let name = host_service("kdc.example.com");
        let srv = async {
            let mut ctx = AuthContext::new();
            recvauth(
                &mut server,
                &mut ctx,
                std::slice::from_ref(&name),
                "EXAMPLE.COM",
                &keys,
                None,
            )
            .await
        };
        let cli = async {
            write_message(&mut client, &nul_terminated(SENDAUTH_VERSION))
                .await
                .expect("test step");
            write_message(&mut client, b"kprop5_00\0")
                .await
                .expect("test step");
            let mut status = [0u8; 1];
            client.read_exact(&mut status).await.expect("test step");
            status[0]
        };
        let (res, status) = tokio::join!(srv, cli);
        assert_eq!(status, 2);
        assert!(matches!(res, Err(KpropError::BadApplVersion)));
    }

    #[tokio::test]
    async fn messages_round_trip_and_are_bounded() {
        let (mut a, mut b) = tokio::io::duplex(64);
        tokio::spawn(async move {
            write_message(&mut a, b"hello").await.expect("test step");
            a.write_all(
                &u32::try_from(MAX_MESSAGE + 1)
                    .expect("test step")
                    .to_be_bytes(),
            )
            .await
            .expect("test step");
        });
        assert_eq!(read_message(&mut b).await.expect("test step"), b"hello");
        assert!(read_message(&mut b).await.is_err());
    }
}
