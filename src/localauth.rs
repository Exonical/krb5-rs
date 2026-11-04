//! Mapping principals to local accounts, like MIT's localauth interface
//! (lib/krb5/os/localauth*.c): [`aname_to_localname`] is
//! `krb5_aname_to_localname` and [`kuserok`] is `krb5_kuserok`.
//!
//! The built-in modules are MIT's, in MIT's order: `default` (type
//! `DEFAULT`), `rule` (type `RULE`), `names` (`auth_to_local_names`),
//! `auth_to_local`, `k5login` and `an2ln`. `[plugins] localauth`
//! `disable` and `enable_only` apply as in MIT. Modules configured as
//! `module = name:unix:path=...` run as separate processes over
//! [`crate::plugin::rpc`] (see [`serve_localauth`]) and come first.

use std::io::{self, Read, Write};
use std::sync::Arc;

use crate::plugin::rpc::{self, Message, PLUGIN_NO_HANDLE};
use crate::plugin::{self as plugins, Configured};
use crate::profile::Profile;
use crate::types::PrincipalName;

/// `KRB5_LNAME_NOTRANS`.
pub const LNAME_NOTRANS: i32 = rpc::ERROR_TABLE_BASE_KRB5 + 176;
/// `KRB5_CONFIG_BADFORMAT`.
pub const CONFIG_BADFORMAT: i32 = rpc::ERROR_TABLE_BASE_KRB5 + 136;
/// `KRB5_ERR_NO_SERVICE`: a module that has gone away or answered
/// malformed data, which fails closed.
const NO_SERVICE: i32 = rpc::ERROR_TABLE_BASE_KRB5 + 245;
/// `KRB5_PLUGIN_BAD_MODULE_SPEC`.
const PLUGIN_BAD_MODULE_SPEC: i32 = -1_750_600_192 + 1;
/// [`rpc::call::INITIALIZE`]'s string for a localauth module.
pub const LOCALAUTH_HANDSHAKE: &str = "KRB5RS-LOCALAUTH-V-1";

/// localauth call numbers.
pub mod call {
    pub use crate::plugin::rpc::call::{FINALIZE, INITIALIZE};
    /// `an2ln_types`: answered with `as` types (empty for an untyped module).
    pub const AN2LN_TYPES: u32 = 3;
    /// `userok`: `s` principal, `s` local name; answered empty to allow.
    pub const USEROK: u32 = 4;
    /// `an2ln`: `s` type, `s` residual, `s` principal; answered with `s`.
    pub const AN2LN: u32 = 5;
}

/// A localauth module (`krb5_localauth_vtable`). Principals are passed
/// unparsed with their realm. `userok` returns `Ok` to allow,
/// `PLUGIN_NO_HANDLE` for no opinion, or another code to deny; `an2ln`
/// returns [`LNAME_NOTRANS`] for no mapping, or another code to stop.
pub trait LocalauthModule: Send + Sync {
    /// The module name.
    fn name(&self) -> &str;
    /// `an2ln_types`: the `auth_to_local` types this module handles. A
    /// typed module is reached only through `auth_to_local`.
    fn an2ln_types(&self) -> Vec<String> {
        Vec::new()
    }
    /// `init`.
    fn init(&self) -> Result<(), i32> {
        Ok(())
    }
    /// `fini`.
    fn fini(&self) {}
    /// `userok`.
    fn userok(&self, _aname: &str, _lname: &str) -> Result<(), i32> {
        Err(PLUGIN_NO_HANDLE)
    }
    /// `an2ln`.
    fn an2ln(
        &self,
        _type: Option<&str>,
        _residual: Option<&str>,
        _aname: &str,
    ) -> Result<String, i32> {
        Err(LNAME_NOTRANS)
    }
}

/// Serve a localauth module on `stream`.
pub fn serve_localauth<S: Read + Write>(stream: S, module: &dyn LocalauthModule) -> io::Result<()> {
    rpc::serve(stream, LOCALAUTH_HANDSHAKE, |req| {
        let mut answer = Message::new(req.call);
        let res = match req.call {
            call::INITIALIZE => module.init(),
            call::FINALIZE => {
                module.fini();
                Ok(())
            }
            call::AN2LN_TYPES => {
                req.finish()?;
                answer.put_strs(&module.an2ln_types());
                Ok(())
            }
            call::USEROK => {
                let aname = req.get_str()?.unwrap_or_default();
                let lname = req.get_str()?.unwrap_or_default();
                req.finish()?;
                module.userok(&aname, &lname)
            }
            call::AN2LN => {
                let ty = req.get_str()?;
                let residual = req.get_str()?;
                let aname = req.get_str()?.unwrap_or_default();
                req.finish()?;
                module
                    .an2ln(ty.as_deref(), residual.as_deref(), &aname)
                    .map(|l| {
                        answer.put_str(Some(&l));
                    })
            }
            _ => Err(PLUGIN_NO_HANDLE),
        };
        Ok(res.map(|()| answer).map_err(|c| (c, None)))
    })
}

/// localauth errors, with MIT's com_err text.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LocalauthError {
    /// `KRB5_LNAME_NOTRANS`.
    #[error("No translation available for requested principal")]
    NoTranslation,
    /// `KRB5_CONFIG_BADFORMAT`.
    #[error("Improper format of Kerberos configuration file")]
    BadFormat,
    /// Another com_err code, from a module or from loading the modules.
    #[error("localauth error {0}")]
    Code(i32),
}

impl LocalauthError {
    fn from_code(code: i32) -> Self {
        match code {
            LNAME_NOTRANS => NoTranslation,
            CONFIG_BADFORMAT => BadFormat,
            c => LocalauthError::Code(c),
        }
    }
}

use LocalauthError::{BadFormat, NoTranslation};

/// The size of the buffer `an2ln_userok` maps into (`MAX_USERNAME`).
const MAX_USERNAME: usize = 65;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Builtin {
    Default,
    Rule,
    Names,
    AuthToLocal,
    K5login,
    An2ln,
}

impl Builtin {
    const ALL: [Builtin; 6] = [
        Builtin::Default,
        Builtin::Rule,
        Builtin::Names,
        Builtin::AuthToLocal,
        Builtin::K5login,
        Builtin::An2ln,
    ];

    fn name(self) -> &'static str {
        match self {
            Builtin::Default => "default",
            Builtin::Rule => "rule",
            Builtin::Names => "names",
            Builtin::AuthToLocal => "auth_to_local",
            Builtin::K5login => "k5login",
            Builtin::An2ln => "an2ln",
        }
    }

    /// `an2ln_types`: typed modules are reached only via `auth_to_local`.
    fn an2ln_type(self) -> Option<&'static str> {
        match self {
            Builtin::Default => Some("DEFAULT"),
            Builtin::Rule => Some("RULE"),
            _ => None,
        }
    }
}

enum Module {
    Builtin(Builtin),
    Remote {
        conn: Arc<rpc::Conn>,
        types: Vec<String>,
    },
}

impl Module {
    fn types(&self) -> Vec<&str> {
        match self {
            Module::Builtin(b) => b.an2ln_type().into_iter().collect(),
            Module::Remote { types, .. } => types.iter().map(String::as_str).collect(),
        }
    }
}

/// localauth.c `load_localauth_modules`: a module that can't be reached,
/// or whose `an2ln_types` conflict with an earlier module's, is skipped.
fn load_modules(profile: &Profile) -> Result<Vec<Module>, i32> {
    let names = Builtin::ALL.map(Builtin::name);
    let list =
        plugins::configured(&[profile], "localauth", &names).map_err(|_| PLUGIN_BAD_MODULE_SPEC)?;
    let mut modules: Vec<Module> = Vec::new();
    for c in list {
        let m = match c {
            Configured::Builtin(n) => match Builtin::ALL.iter().find(|b| b.name() == n) {
                Some(&b) => Module::Builtin(b),
                None => continue,
            },
            Configured::Remote(n, path) => {
                let Some(conn) = plugins::remote(LOCALAUTH_HANDSHAKE, &n, &path) else {
                    continue;
                };
                let types = match conn.call(&Message::new(call::AN2LN_TYPES)) {
                    Ok(Ok(mut a)) => match (a.get_strs(), a.finish()) {
                        (Ok(t), Ok(())) => t,
                        _ => continue,
                    },
                    _ => continue,
                };
                Module::Remote { conn, types }
            }
        };
        // check_conflict
        let conflict = m
            .types()
            .iter()
            .any(|t| modules.iter().any(|o| o.types().contains(t)));
        if !conflict {
            modules.push(m);
        }
    }
    Ok(modules)
}

enum Userok {
    Accept,
    NoHandle,
    #[cfg_attr(not(unix), allow(dead_code))]
    Deny,
}

/// The localauth modules of a profile, in MIT's order.
pub struct Localauth<'a> {
    profile: &'a Profile,
    modules: Result<Vec<Module>, i32>,
}

impl<'a> Localauth<'a> {
    /// Load the modules, filtered by `[plugins] localauth` `disable` and
    /// `enable_only` (plugin.c `configure_interface`).
    pub fn new(profile: &'a Profile) -> Self {
        Localauth {
            profile,
            modules: load_modules(profile),
        }
    }

    fn modules(&self) -> &[Module] {
        self.modules.as_deref().unwrap_or_default()
    }

    /// `krb5_aname_to_localname`: the first untyped module that maps the
    /// principal wins; any error other than "no translation" stops.
    pub fn aname_to_localname(
        &self,
        aname: &PrincipalName,
        realm: &str,
    ) -> Result<String, LocalauthError> {
        if let Err(c) = self.modules {
            return Err(LocalauthError::from_code(c));
        }
        for m in self.modules() {
            if !m.types().is_empty() {
                continue;
            }
            match self.an2ln(m, None, None, aname, realm) {
                Ok(l) => return Ok(l),
                Err(NoTranslation) => {}
                Err(e) => return Err(e),
            }
        }
        Err(NoTranslation)
    }

    /// `krb5_kuserok`: false if any module denies, else true if one
    /// accepts.
    pub fn kuserok(&self, aname: &PrincipalName, realm: &str, lname: &str) -> bool {
        if self.modules.is_err() {
            return false;
        }
        let mut accepted = false;
        for m in self.modules() {
            match self.userok(m, aname, realm, lname) {
                Userok::Accept => accepted = true,
                Userok::NoHandle => {}
                Userok::Deny => return false,
            }
        }
        accepted
    }

    fn an2ln(
        &self,
        m: &Module,
        ty: Option<&str>,
        residual: Option<&str>,
        aname: &PrincipalName,
        realm: &str,
    ) -> Result<String, LocalauthError> {
        let m = match m {
            Module::Builtin(b) => *b,
            Module::Remote { conn, .. } => {
                let mut req = Message::new(call::AN2LN);
                req.put_str(ty)
                    .put_str(residual)
                    .put_str(Some(&crate::ccache::unparse_name(aname, realm)));
                return match conn.call(&req) {
                    Ok(Ok(mut a)) => match (a.get_str(), a.finish()) {
                        (Ok(Some(l)), Ok(())) => Ok(l),
                        _ => Err(LocalauthError::Code(NO_SERVICE)),
                    },
                    Ok(Err((c, _))) => Err(LocalauthError::from_code(c)),
                    // A module that has gone away stops the mapping rather
                    // than letting a later module map the principal.
                    Err(_) => Err(LocalauthError::Code(NO_SERVICE)),
                };
            }
        };
        match m {
            Builtin::Default => self.an2ln_default(aname, realm),
            Builtin::Rule => an2ln_rule(residual, aname, realm),
            Builtin::Names => self.an2ln_names(aname),
            Builtin::AuthToLocal => self.an2ln_auth_to_local(aname, realm),
            Builtin::K5login | Builtin::An2ln => Err(NoTranslation),
        }
    }

    fn userok(&self, m: &Module, aname: &PrincipalName, realm: &str, lname: &str) -> Userok {
        let m = match m {
            Module::Builtin(b) => *b,
            Module::Remote { conn, .. } => {
                let mut req = Message::new(call::USEROK);
                req.put_str(Some(&crate::ccache::unparse_name(aname, realm)))
                    .put_str(Some(lname));
                return match conn.call(&req) {
                    Ok(Ok(a)) if a.finish().is_ok() => Userok::Accept,
                    Ok(Err((PLUGIN_NO_HANDLE, _))) => Userok::NoHandle,
                    // A denial, a malformed answer, or a module that has
                    // gone away: fail closed.
                    _ => Userok::Deny,
                };
            }
        };
        match m {
            Builtin::K5login => self.userok_k5login(aname, realm, lname),
            Builtin::An2ln => match self.aname_to_localname(aname, realm) {
                Ok(l) if l.len() < MAX_USERNAME && l == lname => Userok::Accept,
                _ => Userok::NoHandle,
            },
            _ => Userok::NoHandle,
        }
    }

    fn default_realm(&self) -> Result<String, LocalauthError> {
        crate::locate::default_realm(self.profile).ok_or(NoTranslation)
    }

    /// localauth.c `an2ln_default`: the first component of a principal in
    /// the default realm, with an optional second component equal to the
    /// default realm.
    fn an2ln_default(&self, aname: &PrincipalName, realm: &str) -> Result<String, LocalauthError> {
        let def = self.default_realm()?;
        let comps = &aname.name_string;
        let ok = realm == def
            && match comps.len() {
                1 => true,
                2 => comps[1].as_bytes() == def.as_bytes(),
                _ => false,
            };
        if !ok {
            return Err(NoTranslation);
        }
        Ok(cstr(comps[0].as_bytes()))
    }

    /// localauth.c `an2ln_auth_to_local`.
    fn an2ln_auth_to_local(
        &self,
        aname: &PrincipalName,
        realm: &str,
    ) -> Result<String, LocalauthError> {
        let def = self.default_realm()?;
        let values = self.profile.get_values(&["realms", &def, "auth_to_local"]);
        if values.is_empty() {
            return self.an2ln_default(aname, realm);
        }
        let mut ret = Err(NoTranslation);
        for v in &values {
            if ret != Err(NoTranslation) {
                break;
            }
            let (ty, residual) = match v.split_once(':') {
                Some((t, r)) => (t, Some(r)),
                None => (v.as_str(), None),
            };
            ret = match self.modules().iter().find(|m| m.types().contains(&ty)) {
                Some(m) => self.an2ln(m, Some(ty), residual, aname, realm),
                None => Err(BadFormat),
            };
        }
        ret
    }

    /// localauth_names.c: the last `auth_to_local_names` value for the
    /// principal name without its realm, in the default realm's section.
    fn an2ln_names(&self, aname: &PrincipalName) -> Result<String, LocalauthError> {
        let def = self.default_realm()?;
        let pname = unparse_no_realm(aname);
        self.profile
            .get_values(&["realms", &def, "auth_to_local_names", &pname])
            .pop()
            .ok_or(NoTranslation)
    }

    #[cfg(not(unix))]
    fn userok_k5login(&self, _: &PrincipalName, _: &str, _: &str) -> Userok {
        Userok::NoHandle
    }

    /// localauth_k5login.c `userok_k5login`.
    #[cfg(unix)]
    fn userok_k5login(&self, aname: &PrincipalName, realm: &str, lname: &str) -> Userok {
        use std::os::unix::fs::MetadataExt;
        let Ok(authoritative) = self
            .profile
            .get_boolean(&["libdefaults", "k5login_authoritative"], true)
        else {
            return Userok::Deny;
        };
        let deny = if authoritative {
            Userok::Deny
        } else {
            Userok::NoHandle
        };
        let Some((home, uid)) = getpwnam(lname) else {
            return deny;
        };
        let filename = match self
            .profile
            .get_string(&["libdefaults", "k5login_directory"])
        {
            Some(dir) => std::path::Path::new(&dir).join(lname),
            None => home.join(".k5login"),
        };
        if !filename.exists() {
            return Userok::NoHandle;
        }
        let princname = crate::ccache::unparse_name(aname, realm);
        let Ok(f) = std::fs::File::open(&filename) else {
            return deny;
        };
        // The file must be owned by the user or by root.
        let owner_ok = match f.metadata() {
            Ok(md) => md.uid() == uid || file_owner_ok(md.uid()),
            Err(_) => false,
        };
        if !owner_ok {
            return deny;
        }
        // Read line by line, as MIT's fgets loop does.
        let mut r = std::io::BufReader::new(f);
        loop {
            match fgets_line(&mut r) {
                Ok(Some(l)) if l == princname.as_bytes() => return Userok::Accept,
                Ok(Some(_)) => {}
                Ok(None) | Err(_) => return deny,
            }
        }
    }
}

/// `krb5_aname_to_localname` with the built-in modules of `profile`.
pub fn aname_to_localname(
    profile: &Profile,
    aname: &PrincipalName,
    realm: &str,
) -> Result<String, LocalauthError> {
    Localauth::new(profile).aname_to_localname(aname, realm)
}

/// `krb5_kuserok` with the built-in modules of `profile`.
pub fn kuserok(profile: &Profile, aname: &PrincipalName, realm: &str, lname: &str) -> bool {
    Localauth::new(profile).kuserok(aname, realm, lname)
}

/// A C string: bytes up to the first NUL.
fn cstr(b: &[u8]) -> String {
    let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    String::from_utf8_lossy(&b[..end]).into_owned()
}

/// `krb5_unparse_name_flags(.., KRB5_PRINCIPAL_UNPARSE_NO_REALM, ..)`.
fn unparse_no_realm(aname: &PrincipalName) -> String {
    let full = crate::ccache::unparse_name(aname, "");
    full[..full.len() - 1].to_string()
}

#[cfg(all(unix, any(target_os = "macos", target_os = "ios")))]
fn file_owner_ok(uid: u32) -> bool {
    // FILE_OWNER_OK: root, or UNKNOWNUID on HFS volumes.
    uid == 0 || uid == 99
}

#[cfg(all(unix, not(any(target_os = "macos", target_os = "ios"))))]
fn file_owner_ok(uid: u32) -> bool {
    uid == 0
}

/// BUFSIZ, the `fgets` buffer `userok_k5login` reads lines into.
#[cfg(all(
    unix,
    any(target_os = "macos", target_os = "ios", target_os = "freebsd")
))]
const BUFSIZ: usize = 1024;
#[cfg(all(
    unix,
    not(any(target_os = "macos", target_os = "ios", target_os = "freebsd"))
))]
const BUFSIZ: usize = 8192;

/// The lines `userok_k5login` compares: `fgets` into a BUFSIZ buffer with
/// the newline removed; the rest of an overlong line is skipped, and a line
/// ends at a NUL for `strcmp`.
#[cfg(unix)]
fn fgets_line(r: &mut impl std::io::BufRead) -> std::io::Result<Option<Vec<u8>>> {
    let mut line = Vec::new();
    let mut read_any = false;
    loop {
        let avail = r.fill_buf()?;
        if avail.is_empty() {
            break;
        }
        read_any = true;
        let (take, done) = match avail.iter().position(|&c| c == b'\n') {
            Some(i) => (i, true),
            None => (avail.len(), false),
        };
        let room = (BUFSIZ - 1).saturating_sub(line.len());
        line.extend_from_slice(&avail[..take.min(room)]);
        r.consume(take + usize::from(done));
        if done {
            break;
        }
    }
    if !read_any {
        return Ok(None);
    }
    let end = line.iter().position(|&c| c == 0).unwrap_or(line.len());
    line.truncate(end);
    Ok(Some(line))
}

/// `k5_getpwnam_r`: the home directory and UID of `name`.
#[cfg(unix)]
#[allow(unsafe_code)]
fn getpwnam(name: &str) -> Option<(std::path::PathBuf, u32)> {
    use std::os::unix::ffi::OsStrExt;
    let cname = std::ffi::CString::new(name).ok()?;
    let mut buf = vec![0 as libc::c_char; 16384];
    // SAFETY: an all-zero passwd is a valid value (null pointers, zero ids).
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut out: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: getpwnam_r writes into pwd and buf (sized as passed) and sets
    // out to &pwd on success; pw_dir points into buf, read before it drops.
    let rc = unsafe {
        libc::getpwnam_r(
            cname.as_ptr(),
            &mut pwd,
            buf.as_mut_ptr(),
            buf.len(),
            &mut out,
        )
    };
    if rc != 0 || out.is_null() || pwd.pw_dir.is_null() {
        return None;
    }
    // SAFETY: pw_dir is a NUL-terminated string inside buf.
    let dir = unsafe { std::ffi::CStr::from_ptr(pwd.pw_dir) };
    Some((
        std::path::PathBuf::from(std::ffi::OsStr::from_bytes(dir.to_bytes())),
        pwd.pw_uid,
    ))
}

/// C `strtol` on `s`: the value and the bytes consumed, or `None` on
/// overflow (ERANGE). No digits consumes nothing and yields 0.
fn strtol(s: &[u8]) -> Option<(i64, usize)> {
    let mut i = 0;
    while i < s.len() && matches!(s[i], b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c) {
        i += 1;
    }
    let neg = match s.get(i) {
        Some(b'-') => {
            i += 1;
            true
        }
        Some(b'+') => {
            i += 1;
            false
        }
        _ => false,
    };
    let start = i;
    let mut v: i64 = 0;
    while let Some(d) = s.get(i).filter(|c| c.is_ascii_digit()) {
        v = v.checked_mul(10)?.checked_add(i64::from(d - b'0'))?;
        i += 1;
    }
    if i == start {
        return Some((0, 0));
    }
    Some((if neg { -v } else { v }, i))
}

/// localauth_rule.c `aname_get_selstring`: the selection string and the
/// rest of the rule.
fn selstring<'r>(
    rule: &'r [u8],
    aname: &PrincipalName,
    realm: &str,
) -> Result<(Vec<u8>, &'r [u8]), LocalauthError> {
    if rule.first() != Some(&b'[') {
        return Ok((unparse_no_realm(aname).into_bytes(), rule));
    }
    let mut cur = &rule[1..];
    let (num, used) = strtol(cur).ok_or(BadFormat)?;
    if num < 0 || cur.get(used) != Some(&b':') {
        return Err(BadFormat);
    }
    let comps = &aname.name_string;
    if usize::try_from(num).ok() != Some(comps.len()) {
        return Err(NoTranslation);
    }
    cur = &cur[used + 1..];
    let mut out = Vec::new();
    loop {
        let n = cur
            .iter()
            .position(|&c| c == b'$' || c == b']')
            .unwrap_or(cur.len());
        out.extend_from_slice(&cur[..n]);
        cur = &cur[n..];
        if cur.first() != Some(&b'$') {
            break;
        }
        let Some((ind, used)) = strtol(&cur[1..]) else {
            break;
        };
        if ind > num {
            break;
        }
        cur = &cur[1 + used..];
        let data = if ind > 0 {
            comps[(ind - 1) as usize].as_bytes()
        } else {
            realm.as_bytes()
        };
        out.extend_from_slice(cstr_bytes(data));
    }
    if cur.first() != Some(&b']') {
        return Err(BadFormat);
    }
    Ok((out, &cur[1..]))
}

fn cstr_bytes(b: &[u8]) -> &[u8] {
    &b[..b.iter().position(|&c| c == 0).unwrap_or(b.len())]
}

/// localauth_rule.c `an2ln_rule`: `[n:fmt]`, then `(regexp)`, then
/// `s/regexp/repl/[g]` expressions.
fn an2ln_rule(
    rule: Option<&str>,
    aname: &PrincipalName,
    realm: &str,
) -> Result<String, LocalauthError> {
    let rule = rule.ok_or(BadFormat)?;
    let (sel, mut cur) = selstring(rule.as_bytes(), aname, realm)?;
    if cur.first() == Some(&b'(') {
        let end = cur[1..].iter().position(|&c| c == b')').ok_or(BadFormat)?;
        let re = Regex::new(&cur[1..1 + end]).ok_or(NoTranslation)?;
        match re.find(&sel) {
            Some((0, e)) if e == sel.len() => {}
            _ => return Err(NoTranslation),
        }
        cur = &cur[end + 2..];
    }
    let out = replacer(sel, cur)?;
    Ok(String::from_utf8_lossy(&out).into_owned())
}

/// localauth_rule.c `aname_replacer`.
fn replacer(mut current: Vec<u8>, mut cp: &[u8]) -> Result<Vec<u8>, LocalauthError> {
    while !cp.is_empty() {
        while cp.first().is_some_and(|c| c.is_ascii_whitespace()) {
            cp = &cp[1..];
        }
        if !cp.starts_with(b"s/") {
            return Err(BadFormat);
        }
        let ep = cp[2..].iter().position(|&c| c == b'/').ok_or(BadFormat)? + 2;
        let tp = cp[ep + 1..]
            .iter()
            .position(|&c| c == b'/')
            .ok_or(BadFormat)?
            + ep
            + 1;
        let (rule, repl) = (&cp[2..ep], &cp[ep + 1..tp]);
        cp = &cp[tp + 1..];
        let global = cp.first() == Some(&b'g');
        if global {
            cp = &cp[1..];
        }
        current = replace(rule, repl, global, &current)?;
    }
    Ok(current)
}

/// localauth_rule.c `do_replacement`.
fn replace(
    rule: &[u8],
    repl: &[u8],
    global: bool,
    input: &[u8],
) -> Result<Vec<u8>, LocalauthError> {
    let re = Regex::new(rule).ok_or(NoTranslation)?;
    let mut out = Vec::new();
    let mut rest = input;
    while let Some((s, e)) = re.find(rest) {
        out.extend_from_slice(&rest[..s]);
        out.extend_from_slice(repl);
        rest = &rest[e..];
        // MIT loops forever on an empty global match; stop instead.
        if !global || e == 0 {
            break;
        }
    }
    out.extend_from_slice(rest);
    Ok(out)
}

/// The system's POSIX extended regular expressions, as MIT uses on Unix.
#[cfg(unix)]
struct Regex(Box<libc::regex_t>);

#[cfg(unix)]
#[allow(unsafe_code)]
impl Regex {
    fn new(pattern: &[u8]) -> Option<Self> {
        let pat = std::ffi::CString::new(pattern).ok()?;
        // SAFETY: regex_t is plain data that regcomp initializes.
        let mut re: Box<libc::regex_t> = Box::new(unsafe { std::mem::zeroed() });
        // SAFETY: re is writable and pat is NUL-terminated.
        if unsafe { libc::regcomp(&mut *re, pat.as_ptr(), libc::REG_EXTENDED) } != 0 {
            return None;
        }
        Some(Regex(re))
    }

    /// The first match in `s` (C string semantics) as byte offsets.
    fn find(&self, s: &[u8]) -> Option<(usize, usize)> {
        let s = std::ffi::CString::new(cstr_bytes(s)).ok()?;
        let mut m = libc::regmatch_t { rm_so: 0, rm_eo: 0 };
        // SAFETY: self.0 was compiled by regcomp; m has room for 1 match.
        let rc = unsafe { libc::regexec(&*self.0, s.as_ptr(), 1, &mut m, 0) };
        (rc == 0).then_some((m.rm_so as usize, m.rm_eo as usize))
    }
}

#[cfg(unix)]
#[allow(unsafe_code)]
impl Drop for Regex {
    fn drop(&mut self) {
        // SAFETY: self.0 was compiled by regcomp and is freed once.
        unsafe { libc::regfree(&mut *self.0) }
    }
}

/// Without a system regex library, the `regex` crate (leftmost-first,
/// not POSIX leftmost-longest).
#[cfg(not(unix))]
struct Regex(regex::bytes::Regex);

#[cfg(not(unix))]
impl Regex {
    fn new(pattern: &[u8]) -> Option<Self> {
        regex::bytes::Regex::new(std::str::from_utf8(pattern).ok()?)
            .ok()
            .map(Regex)
    }

    fn find(&self, s: &[u8]) -> Option<(usize, usize)> {
        self.0.find(cstr_bytes(s)).map(|m| (m.start(), m.end()))
    }
}
