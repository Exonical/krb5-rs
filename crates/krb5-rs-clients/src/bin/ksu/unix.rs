//! MIT `ksu` (src/clients/ksu): Kerberized su. Installed setuid root.

#![deny(unsafe_code)]

use std::io::{BufRead, Read};
use std::os::unix::fs::MetadataExt;
use std::os::unix::process::CommandExt;
use std::sync::Arc;
use std::time::Duration;

use krb5_rs::ccache::{
    is_config_principal, parse_principal, resolve, unparse_name, AnyCcache, CcContext,
    CcCredential, CcError, Ccache, MatchCred, MatchFlags,
};
use krb5_rs::client::vfy::VerifyInitCredsOptions;
use krb5_rs::profile::{string_to_deltat, Profile};
use krb5_rs::protocol::{AsExchange, AsExchangeConfig, Credential};
use krb5_rs::types::{KdcOptions, KerberosFlags, PrincipalName};
use krb5_rs::Krb5Error;
use krb5_rs_clients::tktutil::cc_message;
use krb5_rs_clients::{
    com_err, kerberos_client, krb5_message, libdefault_boolean, libdefault_string, progname,
    runtime, sname_to_principal, syslog, Getopt,
};

/// libc calls with no safe std equivalent.
#[allow(unsafe_code)]
mod sys {
    use std::ffi::{CStr, CString};
    use std::io;

    pub struct Passwd {
        pub name: String,
        pub uid: u32,
        pub gid: u32,
        pub dir: String,
        pub shell: Option<String>,
    }

    fn cstr(p: *const libc::c_char) -> Option<String> {
        if p.is_null() {
            return None;
        }
        // SAFETY: a non-null pointer from getpw*_r or getlogin_r/ttyname_r
        // into a buffer they NUL-terminated.
        Some(unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned())
    }

    fn getpw(
        call: impl Fn(
            *mut libc::passwd,
            *mut libc::c_char,
            usize,
            *mut *mut libc::passwd,
        ) -> libc::c_int,
    ) -> Option<Passwd> {
        let mut buf: Vec<libc::c_char> = vec![0; 16384];
        loop {
            // SAFETY: passwd is plain data; all-zero is a valid value.
            let mut pw: libc::passwd = unsafe { std::mem::zeroed() };
            let mut out = std::ptr::null_mut();
            let r = call(&mut pw, buf.as_mut_ptr(), buf.len(), &mut out);
            if r == libc::ERANGE && buf.len() < 1 << 20 {
                buf.resize(buf.len() * 2, 0);
                continue;
            }
            if r != 0 || out.is_null() {
                return None;
            }
            return Some(Passwd {
                name: cstr(pw.pw_name).unwrap_or_default(),
                uid: pw.pw_uid,
                gid: pw.pw_gid,
                dir: cstr(pw.pw_dir).unwrap_or_default(),
                shell: cstr(pw.pw_shell),
            });
        }
    }

    pub fn getpwnam(name: &str) -> Option<Passwd> {
        let c = CString::new(name).ok()?;
        // SAFETY: valid name, passwd, buffer and result pointers.
        getpw(|pw, b, n, out| unsafe { libc::getpwnam_r(c.as_ptr(), pw, b, n, out) })
    }

    pub fn getpwuid(uid: u32) -> Option<Passwd> {
        // SAFETY: valid passwd, buffer and result pointers.
        getpw(|pw, b, n, out| unsafe { libc::getpwuid_r(uid, pw, b, n, out) })
    }

    pub fn getlogin() -> Option<String> {
        // SAFETY: getlogin returns NULL or a static NUL-terminated string,
        // copied before any other call can change it.
        cstr(unsafe { libc::getlogin() })
    }

    pub fn ttyname(fd: libc::c_int) -> Option<String> {
        let mut buf: [libc::c_char; 4096] = [0; 4096];
        // SAFETY: buf is writable for its length.
        if unsafe { libc::ttyname_r(fd, buf.as_mut_ptr(), buf.len()) } != 0 {
            return None;
        }
        cstr(buf.as_ptr())
    }

    fn check(r: libc::c_int) -> io::Result<()> {
        if r == -1 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    pub fn getuid() -> u32 {
        // SAFETY: no arguments; cannot fail.
        unsafe { libc::getuid() }
    }

    /// `getauxval(AT_SECURE)`: running setuid or setgid.
    pub fn at_secure() -> bool {
        #[cfg(target_os = "linux")]
        {
            // SAFETY: plain libc call.
            unsafe { libc::getauxval(libc::AT_SECURE) != 0 }
        }
        #[cfg(not(target_os = "linux"))]
        {
            // SAFETY: plain system calls; cannot fail.
            unsafe { libc::getuid() != libc::geteuid() || libc::getgid() != libc::getegid() }
        }
    }

    pub fn geteuid() -> u32 {
        // SAFETY: no arguments; cannot fail.
        unsafe { libc::geteuid() }
    }

    pub fn seteuid(uid: u32) -> io::Result<()> {
        // SAFETY: plain system call.
        check(unsafe { libc::seteuid(uid) })
    }

    pub fn setuid(uid: u32) -> io::Result<()> {
        // SAFETY: plain system call.
        check(unsafe { libc::setuid(uid) })
    }

    pub fn setgid(gid: u32) -> io::Result<()> {
        // SAFETY: plain system call.
        check(unsafe { libc::setgid(gid) })
    }

    pub fn initgroups(user: &str, gid: u32) -> io::Result<()> {
        let c = CString::new(user).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
        // SAFETY: c is a valid NUL-terminated string.
        check(unsafe { libc::initgroups(c.as_ptr(), gid) })
    }

    pub fn tcgetpgrp(fd: libc::c_int) -> libc::pid_t {
        // SAFETY: plain system call on a descriptor number.
        unsafe { libc::tcgetpgrp(fd) }
    }

    pub fn tcsetpgrp(fd: libc::c_int, pgrp: libc::pid_t) {
        // SAFETY: plain system call on a descriptor number.
        unsafe { libc::tcsetpgrp(fd, pgrp) };
    }

    pub fn kill(pid: libc::pid_t, sig: libc::c_int) {
        // SAFETY: plain system call.
        unsafe { libc::kill(pid, sig) };
    }

    pub fn getpid() -> libc::pid_t {
        // SAFETY: no arguments; cannot fail.
        unsafe { libc::getpid() }
    }

    /// `waitpid(pid, &status, WUNTRACED)`.
    pub fn waitpid_untraced(pid: libc::pid_t) -> io::Result<libc::c_int> {
        let mut status = 0;
        // SAFETY: status is a valid out pointer.
        let r = unsafe { libc::waitpid(pid, &mut status, libc::WUNTRACED) };
        if r == -1 {
            Err(io::Error::last_os_error())
        } else {
            Ok(status)
        }
    }
}

const KS_TEMPORARY_CACHE: &str = "MEMORY:_ksu";
const KS_TEMPORARY_PRINC: &str = "_ksu/_ksu@_ksu";
const DEF_CSH: &str = "/bin/csh";
const CMD_PATH: &str = "/usr/local/sbin /usr/local/bin /sbin /bin /usr/sbin /usr/bin";
const KRB5_LOGIN_NAME: &str = ".k5login";
const KRB5_USERS_NAME: &str = ".k5users";
const PERMIT_ALL_COMMANDS: &str = "*";
const MAXPATHLEN: usize = 4096;
/// `LOG_AUTH | LOG_WARNING` and `LOG_AUTH | LOG_NOTICE`.
const LOG_AUTH_WARNING: u8 = 4 * 8 + 4;
const LOG_AUTH_NOTICE: u8 = 4 * 8 + 5;

type Princ = (PrincipalName, String);

/// Variables MIT reads with `secure_getenv`, so a setuid ksu ignores
/// them, plus krb5-rs's `PKI_DUMP_DIR`. They still reach the command.
const SECURE_ENV: &[&str] = &[
    "KRB5_KTNAME",
    "KRB5_CLIENT_KTNAME",
    "KRB5_TRACE",
    "KRB5RCACHENAME",
    "KRB5RCACHETYPE",
    "KRB5RCACHEDIR",
    "TMPDIR",
    "GSS_MECH_CONFIG",
    "NEGOEX_NO_OPTIMISTIC_TOKEN",
    "PKI_DUMP_DIR",
    "HOME",
];

/// `strerror(errno)`: the OS error text without Rust's "(os error N)".
fn os_msg(e: &std::io::Error) -> String {
    let s = e.to_string();
    match s.rfind(" (os error ") {
        Some(i) => s[..i].to_string(),
        None => s,
    }
}

/// The prompter's newline after a password sits in stdout's buffer
/// until ksu exits (it is lost when ksu execs).
static PENDING_NEWLINE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

fn exit(code: i32) -> ! {
    if PENDING_NEWLINE.load(std::sync::atomic::Ordering::Relaxed) {
        println!();
    }
    std::process::exit(code)
}

/// `krb5_prompter_posix` for ksu's prompt, which already ends in ": ".
fn read_password(prompt: &str) -> std::io::Result<zeroize::Zeroizing<String>> {
    use std::io::{IsTerminal, Write};
    let mut out = std::io::stdout();
    write!(out, "{prompt}: ")?;
    out.flush()?;
    let line = if std::io::stdin().is_terminal() {
        zeroize::Zeroizing::new(rpassword::read_password()?)
    } else {
        let mut line = zeroize::Zeroizing::new(String::new());
        if std::io::stdin().lock().read_line(&mut line)? == 0 {
            return Err(std::io::ErrorKind::UnexpectedEof.into());
        }
        if line.ends_with('\n') {
            line.pop();
        }
        line
    };
    PENDING_NEWLINE.store(true, std::sync::atomic::Ordering::Relaxed);
    Ok(line)
}

fn same_princ(a: &Princ, b: &Princ) -> bool {
    a.0.name_string == b.0.name_string && a.1 == b.1
}

fn unparse(p: &Princ) -> String {
    unparse_name(&p.0, &p.1)
}

struct Ksu {
    profile: Arc<Profile>,
    ctx: CcContext,
    quiet: bool,
    source_uid: u32,
    target_uid: u32,
    k5login_path: String,
    k5users_path: String,
    gb_err: Option<String>,
    clockskew: i64,
    rt: tokio::runtime::Runtime,
}

/// `syslog(pri, ...)` after `openlog(prog_name, LOG_PID | LOG_NDELAY, LOG_AUTH)`.
fn log(pri: u8, msg: &str) {
    syslog(&format!("{}[{}]", progname(), sys::getpid()), pri, msg);
}

/// `ontty()`: `" on <tty>"` for stderr's terminal.
fn ontty() -> String {
    sys::ttyname(2)
        .map(|t| format!(" on {t}"))
        .unwrap_or_default()
}

/// `get_first_token`: leading blanks stay part of the first token.
/// `get_next_token`: later tokens skip blanks.
fn tokens(line: &str) -> Vec<String> {
    let blank = [' ', '\t'];
    let trimmed = line.trim_start_matches(blank);
    if trimmed.is_empty() {
        return Vec::new();
    }
    let lead = line.len() - trimmed.len();
    let end = lead + trimmed.find(blank).unwrap_or(trimmed.len());
    let mut out = vec![line[..end].to_string()];
    out.extend(
        line[end..]
            .split(blank)
            .filter(|t| !t.is_empty())
            .map(str::to_string),
    );
    out
}

/// `get_line` over a whole file: lines without their newline.
fn file_lines(f: std::fs::File) -> Vec<String> {
    std::io::BufReader::new(f)
        .split(b'\n')
        .map_while(Result::ok)
        .map(|l| String::from_utf8_lossy(&l).into_owned())
        .collect()
}

/// `fowner`: owned by `uid` or by root.
fn fowner(f: &std::fs::File, uid: u32) -> bool {
    match f.metadata() {
        Ok(m) => m.uid() == uid || m.uid() == 0,
        Err(_) => false,
    }
}

/// Open an authorization file the way `krb5_authorization` and
/// `get_authorized_princ_names` do: `None` when it cannot be used.
fn open_authz(path: &str, uid: u32) -> Option<std::fs::File> {
    let f = std::fs::File::open(path).ok()?;
    fowner(&f, uid).then_some(f)
}

fn k5login_lookup(lines: &[String], princname: &str) -> bool {
    for line in lines {
        let t = tokens(line);
        if t.first().map(String::as_str) == Some(princname) {
            return t.len() == 1;
        }
    }
    false
}

/// `fcmd_resolve`: the full paths a `.k5users` command can name.
fn fcmd_resolve(fcmd: &str) -> Result<Vec<String>, String> {
    if fcmd.starts_with('/') {
        return Ok(vec![fcmd.to_string()]);
    }
    if fcmd.contains('/') {
        return Err(format!(
            "Error: bad entry - {fcmd} in {KRB5_USERS_NAME} file, must be either full path or just the cmd name\n"
        ));
    }
    Ok(CMD_PATH
        .split([' ', '\t'])
        .filter(|d| !d.is_empty())
        .map(|d| format!("{d}/{fcmd}"))
        .collect())
}

/// `match_commands`: `Ok(Some(path))` when `fcmd` permits `cmd`.
fn match_commands(fcmd: &str, cmd: &str) -> Result<Option<String>, String> {
    let arr = fcmd_resolve(fcmd)?;
    if !cmd.contains('/') {
        let postfix = |f: &String| f.rsplit('/').next() == Some(cmd);
        if !arr.iter().any(postfix) {
            return Ok(None);
        }
        // find_first_cmd_that_exists
        if let Some(f) = arr.iter().find(|f| std::fs::metadata(f).is_ok()) {
            return Ok(Some(f.clone()));
        }
        let mut err = String::from("Error: not found -> ");
        for f in &arr {
            err.push_str(&format!(" {f} "));
        }
        err.push('\n');
        return Err(err);
    }
    Ok(arr.iter().any(|f| f == cmd).then(|| cmd.to_string()))
}

/// `k5users_lookup`, reading on from wherever `lines` is (heuristic.c's
/// `filter` calls it repeatedly on one stream without rewinding).
fn k5users_lookup(
    lines: &mut dyn Iterator<Item = &String>,
    princname: &str,
    cmd: Option<&str>,
) -> (bool, Option<String>) {
    for line in lines {
        let t = tokens(line);
        if t.first().map(String::as_str) != Some(princname) {
            continue;
        }
        let fcmd = t.get(1).map(String::as_str);
        if fcmd == Some(PERMIT_ALL_COMMANDS) {
            if t.len() == 2 {
                return (true, cmd.map(str::to_string));
            }
            return (false, None);
        }
        let Some(cmd) = cmd else {
            return (fcmd.is_none(), None);
        };
        for f in &t[1..] {
            match match_commands(f, cmd) {
                Err(e) => return (false, Some(e)),
                Ok(Some(path)) => return (true, Some(path)),
                Ok(None) => {}
            }
        }
        return (false, None);
    }
    (false, None)
}

impl Ksu {
    /// `krb5_authorization`: whether `client` may become `luser` (running
    /// `cmd`), and the resolved command or an error text for the user.
    fn authorization(
        &self,
        client: &Princ,
        luser: &str,
        cmd: Option<&str>,
    ) -> (bool, Option<String>) {
        let Some(pwd) = sys::getpwnam(luser) else {
            return (false, None);
        };
        let princname = unparse(client);
        let have_login = std::fs::metadata(&self.k5login_path).is_ok();
        let have_users = std::fs::metadata(&self.k5users_path).is_ok();
        let mut login = None;
        let mut users = None;
        if have_login {
            match open_authz(&self.k5login_path, pwd.uid) {
                Some(f) => login = Some(file_lines(f)),
                None => return (false, None),
            }
        }
        if have_users {
            match open_authz(&self.k5users_path, pwd.uid) {
                Some(f) => users = Some(file_lines(f)),
                None => return (false, None),
            }
        }
        let mut ok = false;
        let mut out = None;
        if let Some(lines) = &login {
            ok = k5login_lookup(lines, &princname);
            if ok {
                out = cmd.map(str::to_string);
            }
        }
        if let (Some(lines), false) = (&users, ok) {
            (ok, out) = k5users_lookup(&mut lines.iter(), &princname, cmd);
        }
        if !have_login && !have_users {
            // krb5_aname_to_localname with lnsize = strlen(princname).
            if let Ok(local) =
                krb5_rs::localauth::aname_to_localname(&self.profile, &client.0, &client.1)
            {
                ok = local.len() < princname.len() && local == luser;
            }
        }
        (ok, out)
    }

    /// `get_authorized_princ_names`: the `.k5login` names plus the
    /// `.k5users` names that permit `cmd`.
    fn authorized_princ_names(&mut self, luser: &str, cmd: Option<&str>) -> Vec<String> {
        let Some(pwd) = sys::getpwnam(luser) else {
            return Vec::new();
        };
        let have_login = std::fs::metadata(&self.k5login_path).is_ok();
        let have_users = std::fs::metadata(&self.k5users_path).is_ok();
        let mut login = None;
        if have_login {
            match open_authz(&self.k5login_path, pwd.uid) {
                Some(f) => login = Some(file_lines(f)),
                None => return Vec::new(),
            }
        }
        let mut users_filt = None;
        if have_users {
            let Some(f) = open_authz(&self.k5users_path, pwd.uid) else {
                return Vec::new();
            };
            let lines = file_lines(f);
            let names: Vec<String> = lines
                .iter()
                .filter_map(|l| tokens(l).into_iter().next())
                .collect();
            let mut stream = lines.iter();
            let mut kept = Vec::new();
            for n in names {
                let (found, out) = k5users_lookup(&mut stream, &n, cmd);
                if found {
                    kept.push(n);
                } else if out.is_some() {
                    self.gb_err = out;
                }
            }
            users_filt = Some(kept);
        }
        let login_list: Option<Vec<String>> = login.map(|lines| {
            lines
                .iter()
                .filter_map(|l| tokens(l).into_iter().next())
                .collect()
        });
        match (login_list, users_filt) {
            (None, b) => b.unwrap_or_default(),
            (Some(a), None) => a,
            (Some(mut a), Some(b)) => {
                for n in b {
                    if !a.contains(&n) {
                        a.push(n);
                    }
                }
                a
            }
        }
    }

    /// `krb5_check_exp`: expired once past the end time plus clock skew.
    fn expired(&self, c: &CcCredential) -> bool {
        i64::from(krb5_rs_clients::now()) > i64::from(c.endtime) + self.clockskew
    }

    /// `krb5_get_nonexp_tkts`.
    fn nonexp_tkts(&self, cc: &AnyCcache) -> Result<Vec<CcCredential>, CcError> {
        Ok(cc
            .creds()?
            .into_iter()
            .filter(|c| is_config_principal(&c.server, &c.srealm) || !self.expired(c))
            .collect())
    }

    /// `krb5_ccache_copy`: `dst` is initialized for `target` and gets the
    /// unexpired credentials of `src` (only `primary`'s when `restrict`).
    /// `true` when one of them is `primary`'s.
    fn ccache_copy(
        &self,
        src: &AnyCcache,
        target: &Princ,
        dst: &mut AnyCcache,
        restrict: bool,
        primary: &Princ,
    ) -> Result<bool, CcError> {
        let arr = if is_initialized(src) {
            self.nonexp_tkts(src)?
        } else {
            Vec::new()
        };
        dst.initialize(&target.0, &target.1)?;
        let mine = |c: &CcCredential| same_princ(&(c.client.clone(), c.crealm.clone()), primary);
        let stored = arr.iter().any(mine);
        for c in &arr {
            if !restrict || mine(c) {
                dst.store(c)?;
            }
        }
        Ok(stored)
    }

    /// `krb5_ccache_filter`: keep only `prst`'s credentials.
    fn ccache_filter(&self, cc: &mut AnyCcache, prst: &Princ) -> Result<(), CcError> {
        if !is_initialized(cc) {
            return Ok(());
        }
        let arr = self.nonexp_tkts(cc)?;
        let (p, r) = cc.principal()?;
        cc.initialize(&p, &r)?;
        for c in arr
            .iter()
            .filter(|c| same_princ(&(c.client.clone(), c.crealm.clone()), prst))
        {
            cc.store(c)?;
        }
        Ok(())
    }

    /// `find_ticket`: an unexpired ticket for `server`, by name only.
    fn find_ticket(
        &self,
        cc: &AnyCcache,
        client: &Princ,
        server: &Princ,
    ) -> Result<Option<CcCredential>, CcError> {
        let m = MatchCred {
            client: Some(client.clone()),
            server: Some(server.clone()),
            ..Default::default()
        };
        let ktypes = krb5_rs::protocol::TgsOptions::default().etypes;
        match cc.retrieve(
            MatchFlags::SRV_NAMEONLY | MatchFlags::SUPPORTED_KTYPES,
            &m,
            Some(&ktypes),
        ) {
            Ok(c) if !self.expired(&c) => Ok(Some(c)),
            Ok(_) | Err(CcError::NotFound) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// `find_either_ticket`: a ticket for `end_server` or the local TGT.
    fn find_either_ticket(
        &self,
        cc: &AnyCcache,
        client: &Princ,
        end_server: &Princ,
    ) -> Result<bool, CcError> {
        if !is_initialized(cc) {
            return Ok(false);
        }
        if self.find_ticket(cc, client, end_server)?.is_some() {
            return Ok(true);
        }
        let tgt = (
            PrincipalName::new_srv_inst("krbtgt", &client.1),
            client.1.clone(),
        );
        Ok(self.find_ticket(cc, client, &tgt)?.is_some())
    }
}

/// `ks_ccache_is_initialized`.
fn is_initialized(cc: &AnyCcache) -> bool {
    cc.principal().is_ok()
}

/// `get_best_princ_for_target`'s result: the principal, or
/// `NOT_AUTHORIZED` (`hp`).
enum Best {
    Client(Princ),
    NotAuthorized,
}

impl Ksu {
    fn parse(&self, name: &str) -> Result<Princ, String> {
        let realm = krb5_rs::locate::default_realm(&self.profile);
        parse_principal(name, realm.as_deref())
            .ok_or_else(|| "Malformed representation of principal".to_string())
    }

    /// `get_best_princ_for_target` (heuristic.c:493-735).
    #[allow(clippy::too_many_arguments)]
    fn best_princ_for_target(
        &mut self,
        source_user: &str,
        target_user: &str,
        cc_source: &AnyCcache,
        cmd: Option<&str>,
    ) -> Result<Best, String> {
        let cc_def_princ = if is_initialized(cc_source) {
            Some(cc_source.principal().map_err(|e| cc_message(&e))?)
        } else {
            None
        };
        let target_client = self.parse(target_user)?;
        let source_client = self.parse(source_user)?;
        if self.source_uid == 0 {
            if self.target_uid != 0 {
                return Ok(Best::Client(target_client));
            }
            return Ok(Best::Client(cc_def_princ.unwrap_or(target_client)));
        }
        if self.source_uid == self.target_uid {
            return Ok(Best::Client(cc_def_princ.unwrap_or(target_client)));
        }
        sys::seteuid(0)
            .and_then(|()| sys::seteuid(self.target_uid))
            .map_err(|e| os_msg(&e))?;
        if std::fs::metadata(&self.k5login_path).is_err()
            && std::fs::metadata(&self.k5users_path).is_err()
        {
            return Ok(match cmd {
                Some(_) => Best::NotAuthorized,
                None => Best::Client(target_client),
            });
        }
        let aplist = self.authorized_princ_names(target_user, cmd);
        if aplist.is_empty() {
            return Ok(Best::NotAuthorized);
        }
        let end_server = sname_to_principal(&self.rt, &self.profile, None, "host");
        let trials = [cc_def_princ, Some(target_client), Some(source_client)];
        let mut found = [false; 3];
        for (i, p) in trials.iter().enumerate() {
            let Some(p) = p else { continue };
            if aplist.iter().any(|n| *n == unparse(p)) {
                found[i] = true;
                if self
                    .find_either_ticket(cc_source, p, &end_server)
                    .map_err(|e| cc_message(&e))?
                {
                    return Ok(Best::Client(p.clone()));
                }
            }
        }
        for n in &aplist {
            let p = self.parse(n)?;
            if self
                .find_either_ticket(cc_source, &p, &end_server)
                .map_err(|e| cc_message(&e))?
            {
                return Ok(Best::Client(p));
            }
        }
        for (i, p) in trials.iter().enumerate() {
            if let (true, Some(p)) = (found[i], p) {
                return Ok(Best::Client(p.clone()));
            }
        }
        // PRINC_LOOK_AHEAD
        for p in trials.iter().flatten() {
            if let Some(c) = self.closest_principal(&aplist, p)? {
                return Ok(Best::Client(c));
            }
        }
        Ok(Best::NotAuthorized)
    }

    /// `get_closest_principal`: the entry in `plist` in `client`'s realm
    /// whose leading components are `client`'s, with the fewest components.
    fn closest_principal(&self, plist: &[String], client: &Princ) -> Result<Option<Princ>, String> {
        let cn = &client.0.name_string;
        let mut best: Option<Princ> = None;
        for n in plist {
            let t = self.parse(n)?;
            let pn = &t.0.name_string;
            if cn.len() > pn.len() || t.1 != client.1 || cn[..] != pn[..cn.len()] {
                continue;
            }
            match &best {
                Some(b) if b.0.name_string.len() <= pn.len() => {}
                _ => best = Some(t),
            }
        }
        Ok(best)
    }
}

/// The `krb5_get_init_creds_opt` settings from the command line.
#[derive(Default)]
struct GicOpts {
    forwardable: Option<bool>,
    proxiable: Option<bool>,
    lifetime: Option<i32>,
    rlife: Option<i32>,
}

impl Ksu {
    /// `ksu_get_tgt_via_passwd`: prompt, get a TGT into `out` (the gic
    /// out_ccache) and return it; `zero_password` when none was typed.
    fn tgt_via_passwd(
        &self,
        client: &Princ,
        o: &GicOpts,
        out: &mut AnyCcache,
    ) -> (Option<Credential>, bool) {
        let name = unparse(client);
        let password = match read_password(&format!("Kerberos password for {name}: ")) {
            Ok(p) => p,
            Err(_) => {
                com_err(
                    "Cannot read password",
                    &format!("while reading password for '{name}'\n"),
                );
                return (None, false);
            }
        };
        if password.is_empty() {
            eprintln!("No password given");
            return (None, true);
        }
        let (p, r) = (&self.profile, &client.1);
        let mut c = AsExchangeConfig::new(client.0.clone(), r.clone());
        let mut kopt = KdcOptions::empty();
        if o.forwardable
            .unwrap_or_else(|| libdefault_boolean(p, r, "forwardable").unwrap_or(false))
        {
            kopt |= KdcOptions::FORWARDABLE;
        }
        if o.proxiable
            .unwrap_or_else(|| libdefault_boolean(p, r, "proxiable").unwrap_or(false))
        {
            kopt |= KdcOptions::PROXIABLE;
        }
        if libdefault_boolean(p, r, "canonicalize").unwrap_or(false) {
            kopt |= KdcOptions::CANONICALIZE;
        }
        let deltat = |n: &str| libdefault_string(p, r, n).and_then(|s| string_to_deltat(&s).ok());
        let tkt_life = o
            .lifetime
            .or_else(|| deltat("ticket_lifetime"))
            .unwrap_or(24 * 60 * 60);
        let renew_life = o.rlife.or_else(|| deltat("renew_lifetime")).unwrap_or(0);
        if renew_life > 0 {
            kopt |= KdcOptions::RENEWABLE;
        }
        c.kdc_options = KerberosFlags::new(kopt);
        c.tkt_lifetime = Duration::from_secs(u64::try_from(tkt_life).unwrap_or(0));
        c.renew_lifetime = Duration::from_secs(u64::try_from(renew_life).unwrap_or(0));
        if let Some(s) = libdefault_string(p, r, "default_tkt_enctypes") {
            c.etypes = krb5_rs::crypto::parse_enctype_list(&s, &c.etypes);
        }
        let kc = kerberos_client(&self.profile, r);
        let res = self
            .rt
            .block_on(kc.get_init_creds(AsExchange::new(c, password.as_str())))
            .and_then(|x| x.credential().cloned());
        drop(password);
        let cred = match res {
            Ok(c) => c,
            Err(e) => {
                let bad = matches!(e, Krb5Error::DecryptionFailed)
                    || matches!(e, Krb5Error::Mit(c, _) if c == krb5_rs::sam2::AP_ERR_BAD_INTEGRITY);
                if bad {
                    eprintln!("{}: Password incorrect", progname());
                } else {
                    com_err(krb5_message(&e), "while getting initial credentials");
                }
                return (None, false);
            }
        };
        // The gic out_ccache replaces the cache's contents.
        let stored = out
            .initialize(&cred.client, &cred.crealm)
            .and_then(|()| out.store(&CcCredential::from(&cred)));
        if let Err(e) = stored {
            com_err(cc_message(&e), "while storing credentials");
            return (None, false);
        }
        (Some(cred), false)
    }

    /// `krb5_auth_check` (krb_auth_su.c:33-131).
    fn auth_check(&self, client: &Princ, o: &GicOpts, cc: &mut AnyCcache) -> bool {
        let tgtq = (
            PrincipalName::new_srv_inst("krbtgt", &client.1),
            client.1.clone(),
        );
        let tgt = match self.find_ticket(cc, client, &tgtq) {
            Ok(t) => t,
            Err(e) => {
                com_err(cc_message(&e), "while retrieving creds from cache");
                return false;
            }
        };
        let cred = match tgt {
            Some(t) => match Credential::try_from(&t) {
                Ok(c) => c,
                Err(e) => {
                    com_err(e, "while retrieving creds from cache");
                    return false;
                }
            },
            None => {
                if let Err(e) = sys::seteuid(0).and_then(|()| sys::seteuid(self.target_uid)) {
                    krb5_rs_clients::com_err_as(
                        "ksu",
                        format!("{} while switching to target uid", os_msg(&e)),
                    );
                    return false;
                }
                eprintln!(
                    "WARNING: Your password may be exposed if you enter it here and are logged "
                );
                eprintln!("         in remotely using an unsecure (non-encrypted) channel. ");
                let (c, _) = self.tgt_via_passwd(client, o, cc);
                let Some(c) = c else {
                    let _ = sys::seteuid(0);
                    return false;
                };
                if let Err(e) = sys::seteuid(0) {
                    krb5_rs_clients::com_err_as(
                        "ksu",
                        format!("{} while reclaiming root uid", os_msg(&e)),
                    );
                    return false;
                }
                c
            }
        };
        let kc = kerberos_client(&self.profile, &client.1);
        let opts = VerifyInitCredsOptions {
            ap_req_nofail: Some(true),
            profile: Some(&self.profile),
        };
        if let Err(e) = self
            .rt
            .block_on(kc.verify_init_creds(&cred, None, None, None, &opts))
        {
            com_err(krb5_message(&e), "while verifying ticket for server");
            return false;
        }
        true
    }
}

/// `gen_sym`: six random bytes in base64, with `/` and `+` as `_` and `-`.
fn gen_sym() -> std::io::Result<String> {
    use base64::Engine;
    let mut bytes = [0u8; 6];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    Ok(base64::engine::general_purpose::STANDARD
        .encode(bytes)
        .replace('/', "_")
        .replace('+', "-"))
}

/// `getusershell(3)` as glibc reads `/etc/shells`.
fn standard_shell(sh: &str) -> bool {
    let shells: Vec<String> = match std::fs::File::open("/etc/shells") {
        Ok(f) => file_lines(f)
            .iter()
            .filter_map(|l| {
                let start = l.find(['#', '/'])?;
                let l = &l[start..];
                if l.starts_with('#') {
                    return None;
                }
                let end = l
                    .find(|c: char| c.is_whitespace() || c == '#')
                    .unwrap_or(l.len());
                Some(l[..end].to_string())
            })
            .collect(),
        Err(_) => vec!["/bin/sh".into(), "/bin/csh".into()],
    };
    shells.iter().any(|s| s == sh)
}

fn usage() {
    eprintln!("Usage: {} [target user] [-n principal] [-c source cachename] [-k] [-r time] [-p|-P] [-f|-F] [-l lifetime] [-zZ] [-q] [-e command [args... ] ] [-a [args... ] ]",
        progname()
    );
}

impl Ksu {
    fn print_status(&self, msg: &str) {
        if !self.quiet {
            eprint!("{msg}");
        }
    }

    /// `sweep_up`: destroy the target cache as the target user.
    fn sweep_up(&self, cc: AnyCcache) {
        let _ = sys::seteuid(0);
        if let Err(e) = sys::seteuid(self.target_uid) {
            com_err(
                os_msg(&e),
                "while changing to target uid for destroying ccache",
            );
            exit(1);
        }
        if is_initialized(&cc) {
            if let Err(e) = cc.destroy() {
                com_err(cc_message(&e), "while destroying cache");
            }
        }
    }

    /// `resolve_target_cache` (main.c:877-950): `None` after reporting.
    fn resolve_target_cache(&mut self, princ: &Princ) -> Option<(AnyCcache, bool)> {
        // get_configured_defccname: forget KRB5CCNAME.
        std::env::remove_var("KRB5CCNAME");
        self.ctx = CcContext::from_env(Some(&self.profile));
        let defname = match self.ctx.default_ccname() {
            Ok(n) => n,
            Err(e) => {
                com_err(cc_message(&e), "while determining target ccache name");
                return None;
            }
        };
        let target = if defname.contains(':') {
            defname
        } else {
            format!("FILE:{defname}")
        };
        let ty = target.split(':').next().unwrap_or_default().to_string();
        if !matches!(ty.as_str(), "DIR" | "KEYRING" | "KCM") {
            let name = loop {
                let sym = match gen_sym() {
                    Ok(s) => s,
                    Err(e) => {
                        com_err(
                            os_msg(&e),
                            "while generating part of the target ccache name",
                        );
                        return None;
                    }
                };
                let name = format!("{target}.{sym}");
                if !resolve(&self.ctx, &name)
                    .map(|c| is_initialized(&c))
                    .unwrap_or(false)
                {
                    break name;
                }
            };
            return resolve(&self.ctx, &name).ok().map(|c| (c, false));
        }
        if let Ok(c) = krb5_rs::ccache::cache_match(&self.ctx, &princ.0, &princ.1) {
            return Some((c, true));
        }
        let mut c = match krb5_rs::ccache::new_unique(&self.ctx, &ty) {
            Ok(c) => c,
            Err(e) => {
                com_err(cc_message(&e), "while creating new target ccache");
                return None;
            }
        };
        if let Err(e) = c.initialize(&princ.0, &princ.1) {
            com_err(cc_message(&e), "while initializing target cache");
            return None;
        }
        Some((c, false))
    }
}

pub fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.is_empty() {
        exit(1);
    }
    // init_secure_context: the source user's KRB5_CONFIG is ignored.
    std::env::remove_var("KRB5_CONFIG");
    let mut hidden_env = Vec::new();
    if sys::at_secure() {
        for name in SECURE_ENV {
            if let Some(v) = std::env::var_os(name) {
                std::env::remove_var(name);
                hidden_env.push((*name, v));
            }
        }
    }
    if progname().len() > 50 {
        com_err(
            "program name too long - quitting to avoid triggering system logging bugs",
            "",
        );
        exit(1);
    }
    let profile = Arc::new(krb5_rs_clients::profile());
    let clockskew = libdefault_string(&profile, "", "clockskew")
        .and_then(|s| s.trim().parse::<i64>().ok())
        .unwrap_or(300);
    let mut k = Ksu {
        ctx: CcContext::from_env(Some(&profile)),
        profile,
        quiet: false,
        source_uid: sys::getuid(),
        target_uid: 0,
        k5login_path: String::new(),
        k5users_path: String::new(),
        gb_err: None,
        clockskew,
        rt: runtime(),
    };
    let (target_user, pargs) = match args.get(1) {
        Some(a) if !a.starts_with('-') => (a.clone(), args[2..].to_vec()),
        _ => ("root".to_string(), args[1..].to_vec()),
    };
    if let Err(e) = sys::seteuid(k.source_uid) {
        com_err(os_msg(&e), "while setting euid to source user");
        exit(1);
    }

    let mut o = GicOpts::default();
    let mut client: Option<Princ> = None;
    let mut given_princ = false;
    let mut cc_source_name: Option<String> = None;
    let mut cmd: Option<String> = None;
    // params[0] is reserved for the command or shell (get_params).
    let mut params: Vec<String> = vec![String::new()];
    let (mut keep, mut some_rest_copy, mut all_rest_copy) = (false, false, false);
    let mut errflg = 0;
    let mut done = false;
    let mut g = Getopt::from_args(pargs.clone(), "n:c:r:a:zZDfFpPkql:e:");
    while !done {
        let Some((c, arg)) = g.next() else { break };
        let arg = arg.unwrap_or_default();
        match c {
            'r' | 'l' => {
                let v = if arg.len() >= 14 {
                    "bad-time".to_string()
                } else {
                    arg
                };
                match string_to_deltat(&v) {
                    Ok(d) if d != 0 => {
                        if c == 'r' {
                            o.rlife = Some(d);
                        } else {
                            o.lifetime = Some(d);
                        }
                    }
                    _ => {
                        eprintln!("Bad lifetime value ({v} hours?)");
                        errflg += 1;
                    }
                }
            }
            'a' => {
                params = std::iter::once(String::new())
                    .chain(g.args()[g.optind() - 1..].iter().cloned())
                    .collect();
                done = true;
            }
            'p' => o.proxiable = Some(true),
            'P' => o.proxiable = Some(false),
            'f' => o.forwardable = Some(true),
            'F' => o.forwardable = Some(false),
            'k' => keep = true,
            'q' => k.quiet = true,
            'n' => match k.parse(&arg) {
                Ok(p) => {
                    client = Some(p);
                    given_princ = true;
                }
                Err(e) => {
                    com_err(e, &format!("when parsing name {arg}"));
                    errflg += 1;
                    given_princ = true;
                }
            },
            'z' => {
                if all_rest_copy {
                    eprintln!("-z option is mutually exclusive with -Z.");
                    errflg += 1;
                }
                some_rest_copy = true;
            }
            'Z' => {
                if some_rest_copy {
                    eprintln!("-Z option is mutually exclusive with -z.");
                    errflg += 1;
                }
                all_rest_copy = true;
            }
            'c' => {
                if cc_source_name.is_none() {
                    let ok = resolve(&k.ctx, &arg)
                        .map(|c| (is_initialized(&c), None))
                        .unwrap_or_else(|e| (false, Some(e)));
                    if !ok.0 {
                        let ctx = format!("while looking for credentials cache {arg}");
                        match ok.1 {
                            Some(e) => com_err(cc_message(&e), &ctx),
                            None => com_err("No such file or directory", &ctx),
                        }
                        exit(1);
                    }
                    cc_source_name = Some(arg);
                } else {
                    eprintln!("Only one -c option allowed");
                    errflg += 1;
                }
            }
            'e' => {
                cmd = Some(arg);
                params = std::iter::once(String::new())
                    .chain(g.args()[g.optind()..].iter().cloned())
                    .collect();
                done = true;
            }
            _ => errflg += 1,
        }
    }
    if errflg > 0 || (!done && g.optind() != pargs.len()) {
        usage();
        exit(2);
    }

    // The source user: getlogin() if it is the real uid, else the uid's entry.
    let source = sys::getlogin()
        .and_then(|n| sys::getpwnam(&n))
        .filter(|p| p.uid == k.source_uid)
        .or_else(|| sys::getpwuid(k.source_uid));
    let Some(source) = source else {
        eprintln!("ksu: who are you?");
        exit(1);
    };
    let target_user = if target_user == "." {
        source.name.clone()
    } else {
        target_user
    };
    let Some(target_pwd) = sys::getpwnam(&target_user) else {
        eprintln!("ksu: unknown login {target_user}");
        exit(1);
    };
    k.target_uid = target_pwd.uid;
    if target_pwd.dir.len() + KRB5_LOGIN_NAME.len().max(KRB5_USERS_NAME.len()) + 1 >= MAXPATHLEN {
        eprintln!(
            "home directory name `{}' too long, can't search for .k5login",
            target_pwd.dir
        );
        exit(1);
    }
    k.k5login_path = format!("{}/{KRB5_LOGIN_NAME}", target_pwd.dir);
    k.k5users_path = format!("{}/{KRB5_USERS_NAME}", target_pwd.dir);

    let cc_source_tag = match cc_source_name {
        Some(n) => n,
        None => match k.ctx.default_ccname() {
            Ok(n) => n,
            Err(_) => {
                eprintln!("ksu: failed to get default ccache name");
                exit(1);
            }
        },
    };
    let cc_source = match resolve(&k.ctx, &cc_source_tag) {
        Ok(c) => c,
        Err(e) => {
            com_err(cc_message(&e), "while getting source cache");
            exit(1);
        }
    };
    let ontty = ontty();

    let mut hp = false;
    if client.is_none() {
        match k.best_princ_for_target(&source.name, &target_user, &cc_source, cmd.as_deref()) {
            Ok(Best::Client(p)) => client = Some(p),
            Ok(Best::NotAuthorized) => hp = true,
            Err(e) => {
                com_err(e, "while selecting the best principal");
                exit(1);
            }
        }
    }
    // heuristic.c leaves the euid at the target; get it back.
    if sys::geteuid() != k.source_uid {
        if let Err(e) = sys::seteuid(0).and_then(|()| sys::seteuid(k.source_uid)) {
            com_err(
                os_msg(&e),
                "while returning to source uid after finding best principal",
            );
            exit(1);
        }
    }
    if hp {
        if let Some(e) = &k.gb_err {
            eprint!("{e}");
        }
        eprintln!("account {target_user}: authorization failed");
        match &cmd {
            Some(c) => log(
                LOG_AUTH_WARNING,
                &format!(
                    "Account {target_user}: authorization for {} for execution of {c} failed",
                    source.name
                ),
            ),
            None => log(
                LOG_AUTH_WARNING,
                &format!(
                    "Account {target_user}: authorization of {} failed",
                    source.name
                ),
            ),
        }
        exit(1);
    }
    let Some(client) = client else {
        eprintln!("account {target_user}: authorization failed");
        exit(1);
    };

    let restrict = k.source_uid == 0 && k.target_uid != 0;
    let tmp_princ = match k.parse(KS_TEMPORARY_PRINC) {
        Ok(p) => p,
        Err(e) => {
            com_err(e, "while parsing temporary name");
            exit(1);
        }
    };
    let mut cc_tmp = match resolve(&k.ctx, KS_TEMPORARY_CACHE) {
        Ok(c) => c,
        Err(e) => {
            com_err(cc_message(&e), "while creating temporary cache");
            exit(1);
        }
    };
    let src_name = cc_source.name();
    let src_short = src_name
        .split_once(':')
        .map_or(src_name.as_str(), |(_, r)| r);
    let mut stored = match k.ccache_copy(&cc_source, &tmp_princ, &mut cc_tmp, restrict, &client) {
        Ok(s) => s,
        Err(e) => {
            com_err(
                cc_message(&e),
                &format!("while copying cache {src_short} to {KS_TEMPORARY_CACHE}"),
            );
            exit(1);
        }
    };
    if let Err(e) = sys::seteuid(0) {
        com_err(os_msg(&e), "while reclaiming root uid");
        exit(1);
    }
    let client_name = unparse(&client);

    let mut exec_cmd = None;
    if k.source_uid == 0 || k.target_uid == k.source_uid {
        if !all_rest_copy && given_princ && !stored {
            eprintln!("WARNING: Your password may be exposed if you enter it here and are logged");
            eprintln!("         in remotely using an unsecure (non-encrypted) channel.");
            let (c, zero_password) = k.tgt_via_passwd(&client, &o, &mut cc_tmp);
            if c.is_none() {
                if !zero_password {
                    eprintln!("Goodbye");
                    exit(1);
                }
                eprintln!("Could not get a tgt for {client_name} ");
            }
            stored = true;
        }
    } else {
        if !k.auth_check(&client, &o, &mut cc_tmp) {
            eprintln!("Authentication failed.");
            log(
                LOG_AUTH_WARNING,
                &format!(
                    "'{} {target_user}' authentication failed for {}{ontty}",
                    progname(),
                    source.name
                ),
            );
            exit(1);
        }
        stored = true;
        k.print_status(&format!("Authenticated {client_name}\n"));
        log(
            LOG_AUTH_NOTICE,
            &format!(
                "'{} {target_user}' authenticated {client_name} for {}{ontty}",
                progname(),
                source.name
            ),
        );
        if let Err(e) = sys::seteuid(k.target_uid) {
            com_err(
                os_msg(&e),
                "while switching to target for authorization check",
            );
            exit(1);
        }
        let (authorized, fcmd) = k.authorization(&client, &target_user, cmd.as_deref());
        if let Err(e) = sys::seteuid(0) {
            com_err(
                os_msg(&e),
                "while switching back from target after authorization check",
            );
            exit(1);
        }
        if authorized {
            match &cmd {
                Some(_) => {
                    let ec = fcmd.clone().unwrap_or_default();
                    k.print_status(&format!(
                        "Account {target_user}: authorization for {client_name} for execution of\n"
                    ));
                    k.print_status(&format!("               {ec} successful\n"));
                    log(LOG_AUTH_NOTICE, &format!("Account {target_user}: authorization for {client_name} for execution of {ec} successful"));
                }
                None => {
                    k.print_status(&format!(
                        "Account {target_user}: authorization for {client_name} successful\n"
                    ));
                    log(
                        LOG_AUTH_NOTICE,
                        &format!(
                            "Account {target_user}: authorization for {client_name} successful"
                        ),
                    );
                }
            }
            exec_cmd = fcmd;
        } else {
            match &cmd {
                Some(c) => {
                    // exec_cmd carries the error text back.
                    if let Some(e) = &fcmd {
                        eprint!("{e}");
                        log(LOG_AUTH_WARNING, e);
                    }
                    eprintln!("Account {target_user}: authorization for {client_name} for execution of {c} failed");
                    log(LOG_AUTH_WARNING, &format!("Account {target_user}: authorization for {client_name} for execution of {c} failed"));
                }
                None => {
                    eprintln!("Account {target_user}: authorization of {client_name} failed");
                    log(
                        LOG_AUTH_WARNING,
                        &format!("Account {target_user}: authorization of {client_name} failed"),
                    );
                }
            }
            exit(1);
        }
    }

    if some_rest_copy {
        if let Err(e) = k.ccache_filter(&mut cc_tmp, &client) {
            com_err(cc_message(&e), "while calling cc_filter");
            exit(1);
        }
    }
    if all_rest_copy {
        if let Err(e) = cc_tmp.initialize(&tmp_princ.0, &tmp_princ.1) {
            com_err(cc_message(&e), "while erasing target cache");
            exit(1);
        }
        stored = false;
    }

    // The target's shell, or /bin/csh when it has none.
    let shell = target_pwd
        .shell
        .clone()
        .unwrap_or_else(|| DEF_CSH.to_string());
    if k.source_uid != 0 && !standard_shell(&shell) {
        eprintln!("ksu: permission denied (shell).");
        exit(1);
    }
    if target_pwd.uid != 0 {
        std::env::set_var("USER", &target_pwd.name);
    }
    std::env::set_var("HOME", &target_pwd.dir);
    std::env::set_var("SHELL", &shell);
    if let Err(e) = sys::setgid(target_pwd.gid) {
        eprintln!("ksu: setgid: {}", os_msg(&e));
        exit(1);
    }
    if sys::initgroups(&target_pwd.name, target_pwd.gid).is_err() {
        eprintln!("ksu: initgroups failed.");
        exit(1);
    }
    if target_user == source.name {
        k.print_status(&format!(
            "Leaving uid as {} ({})\n",
            target_user, target_pwd.uid
        ));
    } else {
        k.print_status(&format!(
            "Changing uid to {} ({})\n",
            target_user, target_pwd.uid
        ));
    }
    if let Err(e) = sys::setuid(target_pwd.uid) {
        eprintln!("ksu: setuid: {}", os_msg(&e));
        sys::kill(sys::getpid(), 0);
        exit(1);
    }

    let Some((mut cc_target, reused)) = k.resolve_target_cache(&client) else {
        exit(1);
    };
    if reused {
        keep = true;
    }
    let cc_target_tag = cc_target.name();
    if stored {
        if let Err(e) = k.ccache_copy(&cc_tmp, &client, &mut cc_target, false, &client) {
            com_err(
                cc_message(&e),
                &format!("while copying cache {KS_TEMPORARY_CACHE} to {cc_target_tag}"),
            );
            exit(1);
        }
        if !is_initialized(&cc_target) {
            krb5_rs_clients::com_err_as(
                progname(),
                format!(
                    "{target_user} does not have correct permissions for {cc_target_tag}, {} aborted",
                    progname()
                ),
            );
            exit(1);
        }
    }
    std::env::set_var("KRB5CCNAME", &cc_target_tag);
    // The temporary cache is in this process's memory only.
    let _ = cc_tmp.destroy();

    if k.source_uid == 0 || k.source_uid == k.target_uid {
        exec_cmd = cmd.clone();
    }
    params[0] = match (&cmd, exec_cmd) {
        (Some(_), Some(c)) => c,
        (Some(c), None) => {
            eprintln!("Internal error: command {c} did not get resolved");
            exit(1);
        }
        (None, _) => shell,
    };

    for (name, v) in hidden_env.iter().filter(|(n, _)| *n != "HOME") {
        std::env::set_var(name, v);
    }
    let prog = params[0].clone();
    // execv does no PATH search.
    let path = if prog.contains('/') {
        prog.clone()
    } else {
        format!("./{prog}")
    };
    let mut command = std::process::Command::new(&path);
    command.arg0(&prog).args(&params[1..]);
    if keep {
        let e = command.exec();
        com_err(os_msg(&e), &format!("while trying to execv {prog}"));
        k.sweep_up(cc_target);
        exit(1);
    }
    let child = match command.spawn() {
        Ok(c) => c,
        Err(e) => {
            com_err(os_msg(&e), &format!("while trying to execv {prog}"));
            k.sweep_up(cc_target);
            exit(1);
        }
    };
    let pid = libc::pid_t::try_from(child.id()).unwrap_or(-1);
    let status = loop {
        match sys::waitpid_untraced(pid) {
            Ok(st) if libc::WIFSTOPPED(st) => {
                // Stop with the child; on resume give it the terminal back.
                let pgrp = sys::tcgetpgrp(1);
                sys::kill(sys::getpid(), libc::SIGSTOP);
                sys::tcsetpgrp(1, pgrp);
                sys::kill(pid, libc::SIGCONT);
            }
            Ok(st) => break Some(st),
            Err(e) => {
                com_err(os_msg(&e), "while calling waitpid");
                break None;
            }
        }
    };
    k.sweep_up(cc_target);
    exit(match status {
        Some(st) if libc::WIFEXITED(st) => libc::WEXITSTATUS(st),
        _ => 1,
    });
}
