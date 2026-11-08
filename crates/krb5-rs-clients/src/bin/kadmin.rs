//! `kadmin` (MIT `src/kadmin/cli/kadmin.c`, `keytab.c` and `ss_wrapper.c`):
//! remote administration through kadmind's kadm5 RPC interface.

use std::fmt::Display;
use std::io::{BufRead, Write};
use std::sync::Arc;

use chrono::{Local, Offset, TimeZone};
use krb5_rs::ccache::{default_cache, parse_principal, resolve, unparse_name, CcContext, Ccache};
use krb5_rs::client::vfy::{default_keytab_name, resolve_keytab};
use krb5_rs::crypto::{enctype_name, parse_keysalt_list, SaltType, ETYPE_REGISTRY};
use krb5_rs::kdc::kdb::admin::{attribute_names, AttrChange};
use krb5_rs::kdc::kdb::getdate::get_date_rel;
use krb5_rs::kdc::kdb::kadm5::{code, mask, KeySalt, PolicyEnt, PrincipalEnt};
use krb5_rs::kdc::kdb::mit::TlData;
use krb5_rs::kdc::PrincipalAttributes;
use krb5_rs::keytab::KeytabEntry;
use krb5_rs::profile::string_to_deltat;
use krb5_rs::types::EncryptionKey;
use krb5_rs_clients::kadm5::{Auth, Error, Handle, InitParams};
use krb5_rs_clients::ss::{Exec, Request, Subsystem};
use krb5_rs_clients::{now, Getopt};

/// `KRB5_TL_DB_ARGS` (kdb.h).
const TL_DB_ARGS: u16 = 0x7fff;
/// `KRB5_TL_LAST_ADMIN_UNLOCK` (kdb.h).
const TL_LAST_ADMIN_UNLOCK: u16 = 0x0700;
/// `KRB5_KDB_DISALLOW_ALL_TIX`.
const DISALLOW_ALL_TIX: u32 = 0x40;
/// `EINVAL`, what the client library's `kadm5_lock` returns.
const EINVAL: u32 = 22;

struct Kadmin {
    h: Handle,
    whoami: String,
    def_realm: String,
    script_mode: bool,
    locked: bool,
    ccache_name: bool,
    exit_status: i32,
}

impl Kadmin {
    /// `info`: stdout, suppressed in script mode.
    fn info(&self, s: impl AsRef<str>) {
        if !self.script_mode {
            print!("{}", s.as_ref());
            let _ = std::io::stdout().flush();
        }
    }

    /// `error`: stderr; a failure in script mode sets the exit status.
    fn error(&mut self, s: impl AsRef<str>) {
        if self.script_mode {
            self.exit_status = 1;
        }
        eprint!("{}", s.as_ref());
    }

    /// `com_err` through `extended_com_err_fn`.
    fn com_err(&mut self, prog: &str, e: Option<&dyn Display>, msg: impl AsRef<str>) {
        match e {
            Some(e) => self.error(format!("{prog}: {e} ")),
            None => self.error(format!("{prog}: ")),
        }
        self.error(format!("{}\n", msg.as_ref()));
    }

    /// `kadmin_parse_name`: append the default realm unless the name has
    /// an unescaped `@`, then parse and unparse it.
    fn parse_name(&self, s: &str) -> Option<String> {
        let full = if has_unescaped(s, '@') {
            s.to_string()
        } else {
            format!("{s}@{}", self.def_realm)
        };
        let (n, r) = parse_principal(&full, Some(&self.def_realm))?;
        Some(unparse_name(&n, &r))
    }

    /// [`Self::parse_name`] with `com_err(caller, ret, context)` on failure.
    fn parse_or_err(&mut self, s: &str, caller: &str, context: &str) -> Option<String> {
        let r = self.parse_name(s);
        if r.is_none() {
            self.com_err(caller, Some(&MALFORMED), context);
        }
        r
    }

    fn policy_exists(&mut self, name: &str) -> bool {
        self.h.get_policy(name).is_ok()
    }

    /// `parse_date`.
    fn parse_date(&mut self, s: &str, now: i64) -> Option<i64> {
        let d = get_date_rel(s, now);
        if d.is_none() {
            self.error(format!("Invalid date specification \"{s}\".\n"));
        }
        d
    }

    /// `parse_interval`: a delta time, or a date relative to now.
    fn parse_interval(&mut self, s: &str, now: i64) -> Option<i64> {
        if let Ok(d) = string_to_deltat(s) {
            return Some(i64::from(d));
        }
        let date = self.parse_date(s, now)?;
        if date == 0 {
            return Some(0);
        }
        if date < now {
            self.error(format!("Interval specification \"{s}\" is in the past.\n"));
            return None;
        }
        Some(date - now)
    }
}

/// `KRB5_PARSE_MALFORMED`.
const MALFORMED: &str = "Malformed representation of principal";

fn has_unescaped(s: &str, c: char) -> bool {
    let mut esc = false;
    for ch in s.chars() {
        if esc {
            esc = false;
        } else if ch == '\\' {
            esc = true;
        } else if ch == c {
            return true;
        }
    }
    false
}

/// Index of the first unescaped `c`.
fn find_unescaped(s: &str, c: char) -> Option<usize> {
    let mut esc = false;
    for (i, ch) in s.char_indices() {
        if esc {
            esc = false;
        } else if ch == '\\' {
            esc = true;
        } else if ch == c {
            return Some(i);
        }
    }
    None
}

/// `strdur`: `[-]N day(s) HH:MM:SS`.
fn strdur(d: i64) -> String {
    let neg = if d < 0 { "-" } else { "" };
    let d = d.unsigned_abs();
    let days = d / 86400;
    format!(
        "{neg}{days} {} {:02}:{:02}:{:02}",
        if days == 1 { "day" } else { "days" },
        d % 86400 / 3600,
        d % 3600 / 60,
        d % 60
    )
}

/// `strdate`: `strftime("%a %b %d %H:%M:%S %Z %Y")` in local time.
fn strdate(t: u32) -> String {
    let Some(lt) = Local.timestamp_opt(i64::from(t), 0).single() else {
        return "(error)".into();
    };
    let zone = if lt.offset().fix().local_minus_utc() == 0 {
        "UTC".to_string()
    } else {
        lt.format("%:z").to_string()
    };
    format!(
        "{} {zone} {}",
        lt.format("%a %b %d %H:%M:%S"),
        lt.format("%Y")
    )
}

fn date_or_never(t: u32) -> String {
    if t == 0 {
        "[never]".into()
    } else {
        strdate(t)
    }
}

/// `atoi`: leading decimal digits, else 0.
fn atoi(s: &str) -> i64 {
    let s = s.trim_start();
    let (neg, digits) = match s.as_bytes().first() {
        Some(b'-') => (true, &s[1..]),
        Some(b'+') => (false, &s[1..]),
        _ => (false, s),
    };
    let n: i64 = digits
        .chars()
        .take_while(char::is_ascii_digit)
        .fold(0i64, |a, c| {
            a.saturating_mul(10)
                .saturating_add(i64::from(c as u8 - b'0'))
        });
    if neg {
        -n
    } else {
        n
    }
}

/// `krb5_string_to_keysalts` into wire `(enctype, salttype)` pairs.
fn keysalts(s: &str) -> Result<Vec<KeySalt>, String> {
    let v = parse_keysalt_list(s).map_err(|e| e.to_string())?;
    if v.is_empty() {
        return Err("Invalid argument".into());
    }
    Ok(v.into_iter()
        .map(|(e, st)| {
            let t = match st {
                SaltType::Normal => 0,
                SaltType::NoRealm => 2,
                SaltType::OnlyRealm => 3,
            };
            (e, t)
        })
        .collect())
}

fn usage(whoami: &str) -> ! {
    eprint!(
        "Usage: {whoami} [-r realm] [-p principal] [-q query] [clnt|local args]\n              [command args...]\n\tclnt args: [-s admin_server[:port]] [[-c ccache]|[-k [-t keytab]]]|[-n] [-O | -N]\n\tlocal args: [-x db_args]* [-d dbname] [-e \"enc:salt ...\"] [-m] [-w password] where,\n\t[-x db_args]* - any number of database specific arguments.\n\t\t\tLook at each database documentation for supported arguments\n"
    );
    std::process::exit(1)
}

fn die(whoami: &str, e: impl Display, ctx: &str) -> ! {
    eprintln!("{whoami}: {e} {ctx}");
    std::process::exit(1)
}

fn os_user() -> Option<String> {
    ["USER", "LOGNAME", "USERNAME"]
        .iter()
        .find_map(|v| std::env::var(v).ok().filter(|u| !u.is_empty()))
}

/// `kadmin_startup` and `main` (kadmin.c:288-610, ss_wrapper.c).
fn main() {
    let argv: Vec<String> = std::env::args().collect();
    let whoami = argv
        .first()
        .map(|a| a.rsplit('/').next().unwrap_or(a).to_string())
        .unwrap_or_else(|| "kadmin".into());
    let profile = Arc::new(krb5_rs_clients::profile());
    let mut g = Getopt::from_args(
        argv.get(1..).unwrap_or(&[]).to_vec(),
        "x:r:p:knq:w:d:s:mc:t:e:ON",
    );
    let (mut realm, mut princstr, mut ccache_name, mut keytab_name) = (None, None, None, None);
    let (mut password, mut query, mut server) = (None, None, None);
    let (mut use_keytab, mut use_anon, mut old_auth) = (false, false, false);
    for (c, v) in &mut g {
        match c {
            // Local-mode options; the client library ignores them.
            'x' | 'd' | 'm' | 'e' | 'N' => {}
            'r' => realm = v,
            'p' => princstr = v,
            'c' => ccache_name = v,
            'k' => use_keytab = true,
            'n' => use_anon = true,
            't' => keytab_name = v,
            'w' => password = v,
            'q' => query = v,
            's' => server = v,
            'O' => old_auth = true,
            _ => usage(&whoami),
        }
    }
    if (ccache_name.is_some() && use_keytab)
        || (keytab_name.is_some() && !use_keytab)
        || (ccache_name.is_some() && use_anon)
        || (use_anon && use_keytab)
    {
        usage(&whoami);
    }
    let rest = g.rest().to_vec();
    if query.is_some() && !rest.is_empty() {
        eprint!("{whoami}: -q is exclusive with command-line query");
        usage(&whoami);
    }
    let script_mode = !rest.is_empty();
    let Some(def_realm) = realm.or_else(|| krb5_rs::locate::default_realm(&profile)) else {
        eprintln!("{whoami}: unable to get default realm");
        std::process::exit(1)
    };
    let ctx = CcContext::from_env(Some(&profile));
    let cc = match &ccache_name {
        Some(n) => resolve(&ctx, n)
            .unwrap_or_else(|e| die(&whoami, e, &format!("while opening credentials cache {n}"))),
        None => default_cache(&ctx)
            .unwrap_or_else(|e| die(&whoami, e, "while opening default credentials cache")),
    };
    let princstr = match princstr {
        Some(p) => p,
        None if use_anon => format!("WELLKNOWN/ANONYMOUS@{def_realm}"),
        None if ccache_name.is_some() => match cc.principal() {
            Ok((n, r)) => unparse_name(&n, &r),
            Err(e) => die(&whoami, e, "while retrieving principal name"),
        },
        None if use_keytab => {
            let host = dns_lookup::get_hostname()
                .unwrap_or_else(|e| die(&whoami, e, "creating host service principal"))
                .to_ascii_lowercase();
            let hr = krb5_rs::locate::host_realm(&profile, &host)
                .into_iter()
                .next()
                .filter(|r| !r.is_empty())
                .unwrap_or_else(|| def_realm.clone());
            format!("host/{host}@{hr}")
        }
        None => match cc.principal() {
            Ok((n, r)) => {
                let mut s = unparse_name(&n, &r);
                if let Some(i) = find_unescaped(&s, '@') {
                    s.truncate(i);
                }
                if let Some(i) = find_unescaped(&s, '/') {
                    s.truncate(i);
                }
                format!("{s}/admin@{def_realm}")
            }
            Err(_) => match os_user() {
                Some(u) => format!("{u}/admin@{def_realm}"),
                None => {
                    eprintln!("{whoami}: unable to figure out a principal name");
                    std::process::exit(1)
                }
            },
        },
    };
    let Some((cname, crealm)) = parse_principal(&princstr, Some(&def_realm)) else {
        die(&whoami, MALFORMED, "while parsing principal name")
    };
    let auth = if ccache_name.is_some() {
        if !script_mode {
            println!("Authenticating as principal {princstr} with existing credentials.")
        };
        Auth::Ccache(cc)
    } else if use_anon {
        if !script_mode {
            println!("Authenticating as principal {princstr} with password; anonymous requested.")
        };
        Auth::Anonymous
    } else if use_keytab {
        match &keytab_name {
            Some(k) => {
                if !script_mode {
                    println!("Authenticating as principal {princstr} with keytab {k}.")
                }
            }
            None => {
                if !script_mode {
                    println!("Authenticating as principal {princstr} with default keytab.")
                }
            }
        }
        Auth::Keytab(keytab_name.clone())
    } else {
        if !script_mode {
            println!("Authenticating as principal {princstr} with password.")
        };
        let pw = match password {
            Some(p) => p,
            None => rpassword::prompt_password(format!("Password for {princstr}: "))
                .unwrap_or_else(|e| {
                    die(
                        &whoami,
                        e,
                        &format!("while initializing {whoami} interface"),
                    )
                }),
        };
        Auth::Password(pw)
    };
    let init_ctx = format!("while initializing {whoami} interface");
    let (host, port) =
        krb5_rs_clients::kadm5::admin_server(&profile, &def_realm, server.as_deref())
            .unwrap_or_else(|e| die(&whoami, e, &init_ctx));
    let params = InitParams {
        profile: &profile,
        client: (&cname, &crealm),
        realm: &def_realm,
        server: (&host, port),
        service: old_auth.then_some("kadmin/admin"),
    };
    let h = Handle::init(&params, &auth).unwrap_or_else(|e| die(&whoami, e, &init_ctx));
    let mut st = Kadmin {
        h,
        whoami: whoami.clone(),
        def_realm,
        script_mode,
        locked: false,
        ccache_name: ccache_name.is_some(),
        exit_status: 0,
    };
    let name: &'static str = Box::leak(whoami.clone().into_boxed_str());
    let ss = Subsystem { name, table: TABLE };
    if !rest.is_empty() {
        if ss.execute_command(&mut st, &rest) == Exec::NotFound {
            eprintln!("{whoami}: Command not found {}", rest[0]);
            st.exit_status = 1;
        }
    } else if let Some(q) = query {
        if ss.execute_line(&mut st, &q) == Exec::NotFound {
            eprintln!("{whoami}: Command not found {q}");
            st.exit_status = 1;
        }
    } else {
        ss.listen(&mut st);
    }
    let code = if quit(&mut st) { 1 } else { st.exit_status };
    std::process::exit(code)
}

/// `quit` (kadmin.c:610-634).
fn quit(st: &mut Kadmin) -> bool {
    if st.locked {
        st.com_err(
            "quit",
            Some(&Error::Kadm5(EINVAL)),
            "while unlocking locked database",
        );
        return true;
    }
    if st.ccache_name && !st.script_mode {
        eprint!("\n\x07\x07\x07Administration credentials NOT DESTROYED.\n");
    }
    false
}

/// `krb5_read_password`: prompt twice; the entries must match.
fn read_password(p1: &str, p2: &str) -> Result<String, &'static str> {
    let a = rpassword::prompt_password(format!("{p1}: ")).map_err(|_| "Cannot read password")?;
    let b = rpassword::prompt_password(format!("{p2}: ")).map_err(|_| "Cannot read password")?;
    if a != b {
        return Err("Password mismatch");
    }
    Ok(a)
}

/// Print a yes/no question and read the reply; true only for `yes`.
fn confirm(q: &str) -> bool {
    print!("{q}");
    let _ = std::io::stdout().flush();
    let mut line = String::new();
    let _ = std::io::stdin().lock().read_line(&mut line);
    line == "yes\n" || line == "yes"
}

fn lock(st: &mut Kadmin, _: &[String]) {
    if !st.locked {
        st.com_err("lock", Some(&Error::Kadm5(EINVAL)), "");
    }
}

fn unlock(st: &mut Kadmin, _: &[String]) {
    if st.locked {
        st.com_err("unlock", Some(&Error::Kadm5(EINVAL)), "");
    }
}

fn delprinc(st: &mut Kadmin, argv: &[String]) {
    if !(argv.len() == 2 || (argv.len() == 3 && argv[1] == "-force")) {
        st.error("usage: delete_principal [-force] principal\n");
        return;
    }
    let Some(canon) = st.parse_or_err(
        &argv[argv.len() - 1],
        "delete_principal",
        "while parsing principal name",
    ) else {
        return;
    };
    if argv.len() == 2
        && !st.script_mode
        && !confirm(&format!(
            "Are you sure you want to delete the principal \"{canon}\"? (yes/no): "
        ))
    {
        eprintln!("Principal \"{canon}\" not deleted");
        return;
    }
    if let Err(e) = st.h.delete_principal(&canon) {
        st.com_err(
            "delete_principal",
            Some(&e),
            format!("while deleting principal \"{canon}\""),
        );
        return;
    }
    st.info(format!(
        "Principal \"{canon}\" deleted.\nMake sure that you have removed this principal from all ACLs before reusing.\n"
    ));
}

fn renprinc(st: &mut Kadmin, argv: &[String]) {
    if !(argv.len() == 3 || (argv.len() == 4 && argv[1] == "-force")) {
        st.error("usage: rename_principal [-force] old_principal new_principal\n");
        return;
    }
    let n = argv.len();
    let Some(old) = st.parse_or_err(
        &argv[n - 2],
        "rename_principal",
        "while parsing old principal name",
    ) else {
        return;
    };
    let Some(new) = st.parse_or_err(
        &argv[n - 1],
        "rename_principal",
        "while parsing new principal name",
    ) else {
        return;
    };
    if n == 3
        && !st.script_mode
        && !confirm(&format!(
            "Are you sure you want to rename the principal \"{old}\" to \"{new}\"? (yes/no): "
        ))
    {
        eprintln!("Principal \"{old}\" not renamed");
        return;
    }
    if let Err(e) = st.h.rename_principal(&old, &new) {
        st.com_err(
            "rename_principal",
            Some(&e),
            format!("while renaming principal \"{old}\" to \"{new}\""),
        );
        return;
    }
    st.info(format!(
        "Principal \"{old}\" renamed to \"{new}\".\nMake sure that you have removed the old principal from all ACLs before reusing.\n"
    ));
}

fn addalias(st: &mut Kadmin, argv: &[String]) {
    if argv.len() != 3 {
        st.error("usage: add_alias alias_principal target_principal\n");
        return;
    }
    let Some(alias) = st.parse_or_err(&argv[1], "add_alias", "while parsing alias principal name")
    else {
        return;
    };
    let Some(target) =
        st.parse_or_err(&argv[2], "add_alias", "while parsing target principal name")
    else {
        return;
    };
    if let Err(e) = st.h.create_alias(&alias, &target) {
        st.com_err(
            "add_alias",
            Some(&e),
            format!("while aliasing principal \"{alias}\" to \"{target}\""),
        );
        return;
    }
    st.info(format!("Principal \"{alias}\" aliased to \"{target}\".\n"));
}

fn cpw_usage(st: &mut Kadmin, s: Option<&str>) {
    if let Some(s) = s {
        st.error(format!("change_password: {s}\n"));
    }
    st.error(
        "usage: change_password [-randkey] [-keepold] [-e keysaltlist] [-pw password] principal\n",
    );
}

fn cpw(st: &mut Kadmin, argv: &[String]) {
    let (mut pw, mut randkey, mut keepold, mut ks) = (None, false, false, None);
    let mut i = 1;
    while i < argv.len() && argv[i].starts_with('-') {
        match argv[i].as_str() {
            "-x" => {
                i += 1;
                if i >= argv.len() {
                    cpw_usage(st, Some("missing db argument"));
                    return;
                }
            }
            "-pw" => {
                i += 1;
                if i >= argv.len() {
                    cpw_usage(st, Some("missing password arg"));
                    return;
                }
                pw = Some(argv[i].clone());
            }
            "-randkey" => randkey = true,
            "-keepold" => keepold = true,
            "-e" => {
                i += 1;
                if i >= argv.len() {
                    cpw_usage(st, Some("missing keysaltlist arg"));
                    return;
                }
                match keysalts(&argv[i]) {
                    Ok(k) => ks = Some(k),
                    Err(e) => {
                        st.com_err(
                            "change_password",
                            Some(&e),
                            format!("while parsing keysalts {}", argv[i]),
                        );
                        return;
                    }
                }
            }
            o => {
                st.com_err("change_password", None, format!("unrecognized option {o}"));
                cpw_usage(st, None);
                return;
            }
        }
        i += 1;
    }
    match argv.len() - i {
        0 => {
            cpw_usage(st, Some("missing principal name"));
            return;
        }
        1 => {}
        _ => {
            cpw_usage(st, Some("too many arguments"));
            return;
        }
    }
    let Some(canon) = st.parse_or_err(&argv[i], "change_password", "while parsing principal name")
    else {
        return;
    };
    if randkey {
        if let Err(e) = st.h.randkey_principal(&canon, keepold, ks.as_deref()) {
            st.com_err(
                "change_password",
                Some(&e),
                format!("while randomizing key for \"{canon}\"."),
            );
            return;
        }
        st.info(format!("Key for \"{canon}\" randomized.\n"));
        return;
    }
    let pass = match pw {
        Some(p) => p,
        None => match read_password(
            &format!("Enter password for principal \"{canon}\""),
            &format!("Re-enter password for principal \"{canon}\""),
        ) {
            Ok(p) => p,
            Err(e) => {
                st.com_err(
                    "change_password",
                    Some(&e),
                    format!("while reading password for \"{canon}\"."),
                );
                return;
            }
        },
    };
    if let Err(e) = st.h.chpass_principal(&canon, &pass, keepold, ks) {
        st.com_err(
            "change_password",
            Some(&e),
            format!("while changing password for \"{canon}\"."),
        );
        return;
    }
    st.info(format!("Password for \"{canon}\" changed.\n"));
}

/// The parsed `kadmin_parse_princ_args` result.
#[derive(Default)]
struct PrincArgs {
    rec: PrincipalEnt,
    mask: i32,
    pass: Option<String>,
    randkey: bool,
    nokey: bool,
    ks: Option<Vec<KeySalt>>,
    canon: String,
}

/// `kadmin_parse_princ_args` (kadmin.c:1048-1182); `None` means usage.
fn parse_princ_args(
    st: &mut Kadmin,
    argv: &[String],
    attrs: u32,
    caller: &str,
) -> Option<PrincArgs> {
    let mut a = PrincArgs::default();
    a.rec.attributes = attrs;
    let now = i64::from(now());
    let argc = argv.len();
    if argc < 2 {
        return None;
    }
    let mut i = 1;
    while i < argc - 1 {
        let opt = argv[i].as_str();
        let takes = matches!(
            opt,
            "-x" | "-expire"
                | "-pwexpire"
                | "-maxlife"
                | "-maxrenewlife"
                | "-kvno"
                | "-policy"
                | "-pw"
                | "-e"
        );
        if takes {
            i += 1;
            if i > argc - 2 {
                return None;
            }
        }
        let v = argv[i].as_str();
        match opt {
            "-x" => {
                let mut d = v.as_bytes().to_vec();
                d.push(0);
                a.rec.tl_data.push(TlData {
                    kind: TL_DB_ARGS,
                    data: d,
                });
                a.mask |= mask::TL_DATA;
            }
            "-expire" => {
                a.rec.princ_expire_time = st.parse_date(v, now)? as u32;
                a.mask |= mask::PRINC_EXPIRE_TIME;
            }
            "-pwexpire" => {
                a.rec.pw_expiration = st.parse_date(v, now)? as u32;
                a.mask |= mask::PW_EXPIRATION;
            }
            "-maxlife" => {
                a.rec.max_life = st.parse_interval(v, now)? as u32;
                a.mask |= mask::MAX_LIFE;
            }
            "-maxrenewlife" => {
                a.rec.max_renewable_life = st.parse_interval(v, now)? as u32;
                a.mask |= mask::MAX_RLIFE;
            }
            "-kvno" => {
                a.rec.kvno = atoi(v) as u32;
                a.mask |= mask::KVNO;
            }
            "-policy" => {
                a.rec.policy = Some(v.as_bytes().to_vec());
                a.mask |= mask::POLICY;
            }
            "-clearpolicy" => {
                a.rec.policy = None;
                a.mask |= mask::POLICY_CLR;
            }
            "-pw" => a.pass = Some(v.to_string()),
            "-randkey" => a.randkey = true,
            "-nokey" => a.nokey = true,
            "-unlock" => {
                a.rec.fail_auth_count = 0;
                a.mask |= mask::FAIL_AUTH_COUNT;
                a.rec.tl_data.push(TlData {
                    kind: TL_LAST_ADMIN_UNLOCK,
                    data: (now as u32).to_le_bytes().to_vec(),
                });
                a.mask |= mask::TL_DATA;
            }
            "-e" => match keysalts(v) {
                Ok(k) => a.ks = Some(k),
                Err(e) => {
                    st.com_err(caller, Some(&e), format!("while parsing keysalts {v}"));
                    return None;
                }
            },
            spec => {
                let mut c = AttrChange::default();
                c.add_spec(spec).ok()?;
                a.rec.attributes = (a.rec.attributes | c.set) & !c.clear;
                a.mask |= mask::ATTRIBUTES;
            }
        }
        i += 1;
    }
    if i != argc - 1 {
        return None;
    }
    a.canon = st.parse_or_err(&argv[argc - 1], caller, "while parsing principal")?;
    a.rec.principal = Some(a.canon.as_bytes().to_vec());
    Some(a)
}

const ATTR_HELP: &str = "\tattributes are:\n\t\tallow_postdated allow_forwardable allow_tgs_req allow_renewable\n\t\tallow_proxiable allow_dup_skey allow_tix requires_preauth\n\t\trequires_hwauth needchange allow_svr password_changing_service\n\t\tok_as_delegate ok_to_auth_as_delegate no_auth_data_required\n\t\tlockdown_keys\n\nwhere,\n\t[-x db_princ_args]* - any number of database specific arguments.\n\t\t\tLook at each database documentation for supported arguments\n";

fn addprinc_usage(st: &mut Kadmin) {
    st.error(format!(
        "usage: add_principal [options] principal\n\toptions are:\n\t\t[-randkey|-nokey] [-x db_princ_args]* [-expire expdate] [-pwexpire pwexpdate] [-maxlife maxtixlife]\n\t\t[-kvno kvno] [-policy policy] [-clearpolicy]\n\t\t[-pw password] [-maxrenewlife maxrenewlife]\n\t\t[-e keysaltlist]\n\t\t[{{+|-}}attribute]\n{ATTR_HELP}"
    ));
}

fn modprinc_usage(st: &mut Kadmin) {
    st.error(format!(
        "usage: modify_principal [options] principal\n\toptions are:\n\t\t[-x db_princ_args]* [-expire expdate] [-pwexpire pwexpdate] [-maxlife maxtixlife]\n\t\t[-kvno kvno] [-policy policy] [-clearpolicy]\n\t\t[-maxrenewlife maxrenewlife] [-unlock] [{{+|-}}attribute]\n{ATTR_HELP}"
    ));
}

fn policy_name(rec: &PrincipalEnt) -> String {
    rec.policy
        .as_deref()
        .map(|p| String::from_utf8_lossy(p).into_owned())
        .unwrap_or_default()
}

/// `prepare_dummy_password`: 255 characters that pass any policy.
fn dummy_password() -> String {
    let mut s = String::from("6F a[");
    for i in s.len()..255 {
        s.push(char::from(b'a' + (i % 26) as u8));
    }
    s
}

fn addprinc(st: &mut Kadmin, argv: &[String]) {
    let Some(mut a) = parse_princ_args(st, argv, 0, "add_principal") else {
        addprinc_usage(st);
        return;
    };
    let canon = a.canon.clone();
    if a.mask & mask::POLICY != 0 {
        let p = policy_name(&a.rec);
        if !st.script_mode && !st.policy_exists(&p) {
            eprintln!("WARNING: policy \"{p}\" does not exist");
        }
    } else if a.mask & mask::POLICY_CLR == 0 {
        if st.policy_exists("default") {
            if !st.script_mode {
                eprintln!("No policy specified for {canon}; assigning \"default\"");
            }
            a.rec.policy = Some(b"default".to_vec());
            a.mask |= mask::POLICY;
        } else if !st.script_mode {
            eprintln!("No policy specified for {canon}; defaulting to no policy");
        }
    }
    a.mask &= !mask::POLICY_CLR;
    let mut pass = a.pass.take();
    if a.nokey {
        pass = None;
        a.mask |= mask::KEY_DATA;
    } else if a.randkey {
        pass = None;
    } else if pass.is_none() {
        match read_password(
            &format!("Enter password for principal \"{canon}\""),
            &format!("Re-enter password for principal \"{canon}\""),
        ) {
            Ok(p) => pass = Some(p),
            Err(e) => {
                st.com_err(
                    "add_principal",
                    Some(&e),
                    format!("while reading password for \"{canon}\"."),
                );
                return;
            }
        }
    }
    a.mask |= mask::PRINCIPAL;
    let mut r =
        st.h.create_principal(a.rec.clone(), a.mask, a.ks.clone(), pass);
    let mut old_style = false;
    if a.randkey && matches!(r, Err(Error::Kadm5(EINVAL))) {
        a.rec.attributes |= DISALLOW_ALL_TIX;
        a.mask |= mask::ATTRIBUTES;
        r =
            st.h.create_principal(a.rec.clone(), a.mask, a.ks.clone(), Some(dummy_password()));
        old_style = true;
    }
    if a.nokey && matches!(r, Err(Error::Kadm5(code::BAD_MASK))) {
        st.error(format!(
            "Admin server does not support -nokey while creating \"{canon}\"\n"
        ));
        return;
    }
    if let Err(e) = r {
        st.com_err(
            "add_principal",
            Some(&e),
            format!("while creating \"{canon}\"."),
        );
        return;
    }
    if old_style {
        if let Err(e) = st.h.randkey_principal(&canon, false, a.ks.as_deref()) {
            st.com_err(
                "add_principal",
                Some(&e),
                format!("while randomizing key for \"{canon}\"."),
            );
            return;
        }
        a.rec.attributes &= !DISALLOW_ALL_TIX;
        if let Err(e) = st.h.modify_principal(a.rec.clone(), mask::ATTRIBUTES) {
            st.com_err(
                "add_principal",
                Some(&e),
                format!("while clearing DISALLOW_ALL_TIX for \"{canon}\"."),
            );
            return;
        }
    }
    st.info(format!("Principal \"{canon}\" created.\n"));
}

fn modprinc(st: &mut Kadmin, argv: &[String]) {
    if argv.len() < 2 {
        modprinc_usage(st);
        return;
    }
    let Some(canon) = st.parse_or_err(
        &argv[argv.len() - 1],
        "modify_principal",
        "while parsing principal",
    ) else {
        return;
    };
    let old = match st.h.get_principal(&canon, mask::PRINCIPAL_NORMAL_MASK) {
        Ok(o) => o,
        Err(e) => {
            st.com_err(
                "modify_principal",
                Some(&e),
                format!("while getting \"{canon}\"."),
            );
            return;
        }
    };
    let a = match parse_princ_args(st, argv, old.attributes, "modify_principal") {
        Some(a) if a.ks.is_none() && !a.randkey && !a.nokey && a.pass.is_none() => a,
        _ => {
            modprinc_usage(st);
            return;
        }
    };
    if a.mask & mask::POLICY != 0 {
        let p = policy_name(&a.rec);
        if !st.script_mode && !st.policy_exists(&p) {
            eprintln!("WARNING: policy \"{p}\" does not exist");
        }
    }
    if a.mask != 0 {
        if let Err(e) = st.h.modify_principal(a.rec, a.mask) {
            st.com_err(
                "modify_principal",
                Some(&e),
                format!("while modifying \"{canon}\"."),
            );
            return;
        }
    }
    st.info(format!("Principal \"{canon}\" modified.\n"));
}

/// `krb5_salttype_to_string`.
fn salttype_name(t: i16) -> String {
    match t {
        0 => "normal".into(),
        1 => "v4".into(),
        2 => "norealm".into(),
        3 => "onlyrealm".into(),
        4 => "special".into(),
        5 => "afs3".into(),
        t => format!("<Salt type 0x{t:x}>"),
    }
}

fn getprinc_text(st: &mut Kadmin, d: &PrincipalEnt, princ: &str) -> String {
    let modname = d
        .mod_name
        .as_deref()
        .map(|m| String::from_utf8_lossy(m).into_owned())
        .unwrap_or_default();
    let mut o = format!("Principal: {princ}\n");
    o += &format!("Expiration date: {}\n", date_or_never(d.princ_expire_time));
    o += &format!(
        "Last password change: {}\n",
        date_or_never(d.last_pwd_change)
    );
    o += &format!(
        "Password expiration date: {}\n",
        date_or_never(d.pw_expiration)
    );
    o += &format!("Maximum ticket life: {}\n", strdur(i64::from(d.max_life)));
    o += &format!(
        "Maximum renewable life: {}\n",
        strdur(i64::from(d.max_renewable_life))
    );
    o += &format!("Last modified: {} ({modname})\n", strdate(d.mod_date));
    o += &format!(
        "Last successful authentication: {}\n",
        date_or_never(d.last_success)
    );
    o += &format!(
        "Last failed authentication: {}\n",
        date_or_never(d.last_failed)
    );
    o += &format!("Failed password attempts: {}\n", d.fail_auth_count);
    o += &format!("Number of keys: {}\n", d.key_data.len());
    for &(ver, kvno, t0, t1) in &d.key_data {
        let et = i32::from(t0);
        let name =
            enctype_name(et).map_or_else(|| format!("<Encryption type 0x{et:x}>"), str::to_string);
        let dep = if !ETYPE_REGISTRY.contains_key(&et) {
            "UNSUPPORTED:"
        } else if matches!(et, 6 | 16 | 23 | 24) {
            "DEPRECATED:"
        } else {
            ""
        };
        o += &format!("Key: vno {kvno}, {dep}{name}");
        if ver > 1 && t1 != 0 {
            o += &format!(":{}", salttype_name(t1));
        }
        o.push('\n');
    }
    o += &format!("MKey: vno {}\n", d.mkvno);
    o += "Attributes:";
    let names = attribute_names(PrincipalAttributes::from_bits_retain(d.attributes));
    for n in names.split(' ').filter(|n| !n.is_empty()) {
        o += &format!(" {n}");
    }
    o.push('\n');
    match d.policy.as_deref() {
        None => o += "Policy: [none]\n",
        Some(p) => {
            let p = String::from_utf8_lossy(p).into_owned();
            let missing = if st.policy_exists(&p) {
                ""
            } else {
                " [does not exist]"
            };
            o += &format!("Policy: {p}{missing}\n");
        }
    }
    o
}

fn getprinc_terse(d: &PrincipalEnt, princ: &str) -> String {
    let modname = d
        .mod_name
        .as_deref()
        .map(|m| String::from_utf8_lossy(m).into_owned())
        .unwrap_or_default();
    let pol = d.policy.as_deref().map_or_else(
        || "[none]".into(),
        |p| String::from_utf8_lossy(p).into_owned(),
    );
    let mut o = format!(
        "\"{princ}\"\t{}\t{}\t{}\t{}\t\"{modname}\"\t{}\t{}\t{}\t{}\t\"{pol}\"\t{}\t{}\t{}\t{}\t{}",
        d.princ_expire_time as i32,
        d.last_pwd_change as i32,
        d.pw_expiration as i32,
        d.max_life as i32,
        d.mod_date as i32,
        d.attributes as i32,
        d.kvno as i32,
        d.mkvno as i32,
        d.max_renewable_life as i32,
        d.last_success as i32,
        d.last_failed as i32,
        d.fail_auth_count as i32,
        d.key_data.len()
    );
    for &(ver, kvno, t0, t1) in &d.key_data {
        o += &format!("\t{ver}\t{kvno}\t{t0}\t{t1}");
    }
    o.push('\n');
    o
}

fn getprinc(st: &mut Kadmin, argv: &[String]) {
    let terse = argv.len() == 3 && argv[1] == "-terse";
    if !(argv.len() == 2 || terse) {
        st.error("usage: get_principal [-terse] principal\n");
        return;
    }
    let Some(canon) = st.parse_or_err(
        &argv[argv.len() - 1],
        "get_principal",
        "while parsing principal",
    ) else {
        return;
    };
    let d = match st
        .h
        .get_principal(&canon, mask::PRINCIPAL_NORMAL_MASK | mask::KEY_DATA)
    {
        Ok(d) => d,
        Err(e) => {
            st.com_err(
                "get_principal",
                Some(&e),
                format!("while retrieving \"{canon}\"."),
            );
            return;
        }
    };
    let princ = d.principal.as_deref().map_or_else(
        || canon.clone(),
        |p| String::from_utf8_lossy(p).into_owned(),
    );
    let out = if terse {
        getprinc_terse(&d, &princ)
    } else {
        getprinc_text(st, &d, &princ)
    };
    print!("{out}");
}

fn getprincs(st: &mut Kadmin, argv: &[String]) {
    if argv.len() > 2 {
        st.error("usage: get_principals [expression]\n");
        return;
    }
    match st.h.get_principals(argv.get(1).map(String::as_str)) {
        Ok(names) => names.iter().for_each(|n| println!("{n}")),
        Err(e) => st.com_err("get_principals", Some(&e), "while retrieving list."),
    }
}

/// `kadmin_parse_policy_args`; `None` means usage.
fn parse_policy_args(st: &mut Kadmin, argv: &[String], caller: &str) -> Option<(PolicyEnt, i32)> {
    let mut p = PolicyEnt::default();
    let mut m = 0;
    let now = i64::from(now());
    let argc = argv.len();
    if argc < 2 {
        return None;
    }
    let mut i = 1;
    while i < argc - 1 {
        let opt = argv[i].clone();
        i += 1;
        if i > argc - 2 {
            return None;
        }
        let v = argv[i].as_str();
        match opt.as_str() {
            "-maxlife" => {
                p.pw_max_life = st.parse_interval(v, now)? as i32;
                m |= mask::PW_MAX_LIFE;
            }
            "-minlife" => {
                p.pw_min_life = st.parse_interval(v, now)? as i32;
                m |= mask::PW_MIN_LIFE;
            }
            "-minlength" => {
                p.pw_min_length = atoi(v) as i32;
                m |= mask::PW_MIN_LENGTH;
            }
            "-minclasses" => {
                p.pw_min_classes = atoi(v) as i32;
                m |= mask::PW_MIN_CLASSES;
            }
            "-history" => {
                p.pw_history_num = atoi(v) as i32;
                m |= mask::PW_HISTORY_NUM;
            }
            "-maxfailure" => {
                p.pw_max_fail = atoi(v) as u32;
                m |= mask::PW_MAX_FAILURE;
            }
            "-failurecountinterval" => {
                p.pw_failcnt_interval = st.parse_interval(v, now)? as i32;
                m |= mask::PW_FAILURE_COUNT_INTERVAL;
            }
            "-lockoutduration" => {
                p.pw_lockout_duration = st.parse_interval(v, now)? as i32;
                m |= mask::PW_LOCKOUT_DURATION;
            }
            "-allowedkeysalts" => {
                if v == "-" {
                    p.allowed_keysalts = None;
                } else {
                    if let Err(e) = keysalts(v) {
                        st.com_err(caller, Some(&e), format!("while parsing keysalts {v}"));
                        return None;
                    }
                    p.allowed_keysalts = Some(v.to_string());
                }
                m |= mask::POLICY_ALLOWED_KEYSALTS;
            }
            _ => return None,
        }
        i += 1;
    }
    if i != argc - 1 {
        let w = st.whoami.clone();
        st.error(format!("{w}: parser lost count!\n"));
        return None;
    }
    p.policy = Some(argv[argc - 1].clone());
    Some((p, m))
}

fn addmodpol_usage(st: &mut Kadmin, func: &str) {
    st.error(format!(
        "usage; {func} [options] policy\n\toptions are:\n\t\t[-maxlife time] [-minlife time] [-minlength length]\n\t\t[-minclasses number] [-history number]\n\t\t[-maxfailure number] [-failurecountinterval time]\n\t\t[-allowedkeysalts keysalts]\n\t\t[-lockoutduration time]\n"
    ));
}

fn addpol(st: &mut Kadmin, argv: &[String]) {
    let Some((p, m)) = parse_policy_args(st, argv, "add_policy") else {
        addmodpol_usage(st, "add_policy");
        return;
    };
    let name = argv[argv.len() - 1].clone();
    if let Err(e) = st.h.create_policy(p, m | mask::POLICY) {
        st.com_err(
            "add_policy",
            Some(&e),
            format!("while creating policy \"{name}\"."),
        );
    }
}

fn modpol(st: &mut Kadmin, argv: &[String]) {
    let Some((p, m)) = parse_policy_args(st, argv, "modify_policy") else {
        addmodpol_usage(st, "modify_policy");
        return;
    };
    let name = argv[argv.len() - 1].clone();
    if let Err(e) = st.h.modify_policy(p, m) {
        st.com_err(
            "modify_policy",
            Some(&e),
            format!("while modifying policy \"{name}\"."),
        );
    }
}

fn delpol(st: &mut Kadmin, argv: &[String]) {
    if !(argv.len() == 2 || (argv.len() == 3 && argv[1] == "-force")) {
        st.error("usage: delete_policy [-force] policy\n");
        return;
    }
    let name = argv[argv.len() - 1].clone();
    if argv.len() == 2
        && !st.script_mode
        && !confirm(&format!(
            "Are you sure you want to delete the policy \"{name}\"? (yes/no): "
        ))
    {
        eprintln!("Policy \"{name}\" not deleted.");
        return;
    }
    if let Err(e) = st.h.delete_policy(&name) {
        st.com_err(
            "delete_policy:",
            Some(&e),
            format!("while deleting policy \"{name}\""),
        );
    }
}

fn getpol(st: &mut Kadmin, argv: &[String]) {
    let terse = argv.len() == 3 && argv[1] == "-terse";
    if !(argv.len() == 2 || terse) {
        st.error("usage: get_policy [-terse] policy\n");
        return;
    }
    let name = argv[argv.len() - 1].clone();
    let p = match st.h.get_policy(&name) {
        Ok(p) => p,
        Err(e) => {
            st.com_err(
                "get_policy",
                Some(&e),
                format!("while retrieving policy \"{name}\"."),
            );
            return;
        }
    };
    let pname = p.policy.clone().unwrap_or(name);
    if terse {
        println!(
            "\"{pname}\"\t{}\t{}\t{}\t{}\t{}\t0\t{}\t{}\t{}\t{}",
            p.pw_max_life,
            p.pw_min_life,
            p.pw_min_length,
            p.pw_min_classes,
            p.pw_history_num,
            p.pw_max_fail,
            p.pw_failcnt_interval,
            p.pw_lockout_duration,
            p.allowed_keysalts.as_deref().unwrap_or("-")
        );
        return;
    }
    println!("Policy: {pname}");
    println!(
        "Maximum password life: {}",
        strdur(i64::from(p.pw_max_life))
    );
    println!(
        "Minimum password life: {}",
        strdur(i64::from(p.pw_min_life))
    );
    println!("Minimum password length: {}", p.pw_min_length);
    println!(
        "Minimum number of password character classes: {}",
        p.pw_min_classes
    );
    println!("Number of old keys kept: {}", p.pw_history_num);
    println!(
        "Maximum password failures before lockout: {}",
        p.pw_max_fail
    );
    println!(
        "Password failure count reset interval: {}",
        strdur(i64::from(p.pw_failcnt_interval))
    );
    println!(
        "Password lockout duration: {}",
        strdur(i64::from(p.pw_lockout_duration))
    );
    if let Some(k) = &p.allowed_keysalts {
        println!("Allowed key/salt types: {k}");
    }
}

fn getpols(st: &mut Kadmin, argv: &[String]) {
    if argv.len() > 2 {
        st.error("usage: get_policies [expression]\n");
        return;
    }
    match st.h.get_policies(argv.get(1).map(String::as_str)) {
        Ok(names) => names.iter().for_each(|n| println!("{n}")),
        Err(e) => st.com_err("get_policies", Some(&e), "while retrieving list."),
    }
}

fn getprivs(st: &mut Kadmin, argv: &[String]) {
    if argv.len() != 1 {
        st.error("usage: get_privs\n");
        return;
    }
    match st.h.get_privs() {
        Ok(p) => {
            let mut o = String::from("current privileges:");
            for (i, n) in ["INQUIRE", "ADD", "MODIFY", "DELETE"].iter().enumerate() {
                if p & (1 << i) != 0 {
                    o += &format!(" {n}");
                }
            }
            println!("{o}");
        }
        Err(e) => st.com_err("get_privs", Some(&e), "while retrieving privileges"),
    }
}

fn purgekeys(st: &mut Kadmin, argv: &[String]) {
    let (keepkvno, name) = match argv.len() {
        4 if argv[1] == "-keepkvno" => (atoi(&argv[2]) as i32, &argv[3]),
        3 if argv[1] == "-all" => (i32::MAX, &argv[2]),
        2 => (-1, &argv[1]),
        _ => {
            st.error("usage: purgekeys [-all|-keepkvno oldest_kvno_to_keep] principal\n");
            return;
        }
    };
    let Some(canon) = st.parse_or_err(name, "purgekeys", "while parsing principal") else {
        return;
    };
    if let Err(e) = st.h.purgekeys(&canon, keepkvno) {
        st.com_err(
            "purgekeys",
            Some(&e),
            format!("while purging keys for principal \"{canon}\""),
        );
        return;
    }
    if keepkvno == i32::MAX {
        st.info(format!("All keys for principal \"{canon}\" removed.\n"));
    } else {
        st.info(format!("Old keys for principal \"{canon}\" purged.\n"));
    }
}

fn getstrs(st: &mut Kadmin, argv: &[String]) {
    if argv.len() != 2 {
        st.error("usage: get_strings principal\n");
        return;
    }
    let Some(canon) = st.parse_or_err(&argv[1], "get_strings", "while parsing principal") else {
        return;
    };
    match st.h.get_strings(&canon) {
        Ok(v) if v.is_empty() => println!("(No string attributes.)"),
        Ok(v) => v.iter().for_each(|(k, val)| println!("{k}: {val}")),
        Err(e) => st.com_err(
            "get_strings",
            Some(&e),
            format!("while getting attributes for principal \"{canon}\""),
        ),
    }
}

fn setstr(st: &mut Kadmin, argv: &[String]) {
    if argv.len() != 4 {
        st.error("usage: set_string principal key value\n");
        return;
    }
    let Some(canon) = st.parse_or_err(&argv[1], "set_string", "while parsing principal") else {
        return;
    };
    if let Err(e) = st.h.set_string(&canon, &argv[2], Some(&argv[3])) {
        st.com_err(
            "set_string",
            Some(&e),
            format!("while setting attribute on principal \"{canon}\""),
        );
        return;
    }
    st.info(format!("Attribute set for principal \"{canon}\".\n"));
}

fn delstr(st: &mut Kadmin, argv: &[String]) {
    if argv.len() != 3 {
        st.error("usage: del_string principal key\n");
        return;
    }
    let Some(canon) = st.parse_or_err(&argv[1], "delstring", "while parsing principal") else {
        return;
    };
    if let Err(e) = st.h.set_string(&canon, &argv[2], None) {
        st.com_err(
            "del_string",
            Some(&e),
            format!("while deleting attribute from principal \"{canon}\""),
        );
        return;
    }
    st.info(format!("Attribute removed from principal \"{canon}\".\n"));
}

/// `process_keytab` (keytab.c): the keytab name as MIT prints it.
fn keytab_str(_st: &mut Kadmin, name: Option<&str>) -> Option<String> {
    let s = match name {
        Some(n) if n.contains(':') => n.to_string(),
        Some(n) => format!("WRFILE:{n}"),
        None => {
            let d = default_keytab_name(Some(&krb5_rs_clients::profile()));
            match d.strip_prefix("FILE:") {
                Some(p) => format!("WRFILE:{p}"),
                None => d,
            }
        }
    };
    Some(s)
}

fn etype_label(et: i32) -> String {
    enctype_name(et).map_or_else(|| format!("etype {et}"), str::to_string)
}

fn add_usage(st: &mut Kadmin) {
    st.error("Usage: ktadd [-k[eytab] keytab] [-q] [-e keysaltlist] [-norandkey] [principal | -glob princ-exp] [...]\n");
}

fn rem_usage(st: &mut Kadmin) {
    st.error("Usage: ktremove [-k[eytab] keytab] [-q] principal [kvno|\"all\"|\"old\"]\n");
}

/// `kadmin_keytab_add` (keytab.c:113-200).
fn ktadd(st: &mut Kadmin, argv: &[String]) {
    let (mut kt, mut quiet, mut norandkey, mut ks) = (None::<String>, false, false, None);
    let mut i = 1;
    while i < argv.len() {
        let a = argv[i].as_str();
        if a.starts_with("-k") {
            i += 1;
            if i >= argv.len() || kt.is_some() {
                add_usage(st);
                return;
            }
            kt = Some(argv[i].clone());
        } else if a == "-q" {
            quiet = true;
        } else if a == "-norandkey" {
            norandkey = true;
        } else if a == "-e" {
            i += 1;
            if i >= argv.len() {
                add_usage(st);
                return;
            }
            match keysalts(&argv[i]) {
                Ok(k) => ks = Some(k),
                Err(e) => {
                    st.com_err(
                        "ktadd",
                        Some(&e),
                        format!("while parsing keysalts {}", argv[i]),
                    );
                    return;
                }
            }
        } else {
            break;
        }
        i += 1;
    }
    if i >= argv.len() {
        add_usage(st);
        return;
    }
    if norandkey && ks.is_some() {
        st.error("cannot specify keysaltlist when not changing key\n");
        return;
    }
    let Some(ktname) = keytab_str(st, kt.as_deref()) else {
        return;
    };
    let w = st.whoami.clone();
    let mut keytab = match resolve_keytab(&ktname) {
        Ok(k) => k,
        Err(e) => {
            st.com_err(&w, Some(&e), format!("while resolving keytab {ktname}"));
            return;
        }
    };
    let princs: Vec<String> = if argv[i] == "-glob" {
        let Some(exp) = argv.get(i + 1) else {
            add_usage(st);
            return;
        };
        match st.h.get_principals(Some(exp)) {
            Ok(v) => v,
            Err(e) => {
                st.com_err(
                    &w,
                    Some(&e),
                    format!("while expanding expression \"{exp}\"."),
                );
                return;
            }
        }
    } else {
        argv[i..].to_vec()
    };
    for p in &princs {
        ktadd_one(
            st,
            &mut *keytab,
            &ktname,
            p,
            quiet,
            norandkey,
            ks.as_deref(),
        );
    }
}

/// `add_principal` (keytab.c:202-290).
fn ktadd_one(
    st: &mut Kadmin,
    keytab: &mut dyn krb5_rs::client::vfy::VerifyKeytab,
    ktname: &str,
    princ_str: &str,
    quiet: bool,
    norandkey: bool,
    ks: Option<&[KeySalt]>,
) {
    let w = st.whoami.clone();
    let Some(canon) = st.parse_name(princ_str) else {
        st.com_err(
            &w,
            Some(&MALFORMED),
            format!("while parsing -add principal name {princ_str}"),
        );
        return;
    };
    let Some((pname, prealm)) = parse_principal(&canon, Some(&st.def_realm)) else {
        return;
    };
    let keys: Result<Vec<(u32, EncryptionKey)>, Error> = if norandkey {
        st.h.get_principal_keys(&canon, 0).map(|v| {
            v.into_iter()
                .map(|k| (k.kvno, EncryptionKey::new(k.key.enctype, k.key.contents)))
                .collect()
        })
    } else {
        st.h.randkey_principal(&canon, false, ks).and_then(|v| {
            let kvno =
                st.h.get_principal(&canon, mask::PRINCIPAL_NORMAL_MASK)?
                    .kvno;
            Ok(v.into_iter()
                .map(|k| (kvno, EncryptionKey::new(k.enctype, k.contents)))
                .collect())
        })
    };
    let keys = match keys {
        Ok(k) => k,
        Err(Error::Kadm5(code::UNK_PRINC)) => {
            st.error(format!("{w}: Principal {princ_str} does not exist.\n"));
            return;
        }
        Err(e) => {
            st.com_err(&w, Some(&e), format!("while changing {princ_str}'s key"));
            return;
        }
    };
    for (kvno, key) in keys {
        let et = key.keytype;
        let entry = KeytabEntry {
            principal: pname.clone(),
            realm: prealm.clone(),
            timestamp: now(),
            kvno,
            key,
        };
        if let Err(e) = keytab.add_entry(&entry) {
            st.com_err(&w, Some(&e), "while adding key to keytab");
            return;
        }
        if !quiet {
            println!(
                "Entry for principal {princ_str} with kvno {kvno}, encryption type {} added to keytab {ktname}.",
                etype_label(et)
            );
        }
    }
}

#[derive(PartialEq, Clone, Copy)]
enum RemMode {
    High,
    All,
    Old,
    Spec(u32),
}

/// `kadmin_keytab_remove` and `remove_principal` (keytab.c).
fn ktremove(st: &mut Kadmin, argv: &[String]) {
    let (mut kt, mut quiet) = (None::<String>, false);
    let mut i = 1;
    while i < argv.len() {
        let a = argv[i].as_str();
        if a.starts_with("-k") {
            i += 1;
            if i >= argv.len() || kt.is_some() {
                rem_usage(st);
                return;
            }
            kt = Some(argv[i].clone());
        } else if a == "-q" {
            quiet = true;
        } else {
            break;
        }
        i += 1;
    }
    let rest = &argv[i..];
    if rest.len() != 1 && rest.len() != 2 {
        rem_usage(st);
        return;
    }
    let Some(ktname) = keytab_str(st, kt.as_deref()) else {
        return;
    };
    let w = st.whoami.clone();
    let mut keytab = match resolve_keytab(&ktname) {
        Ok(k) => k,
        Err(e) => {
            st.com_err(&w, Some(&e), format!("while resolving keytab {ktname}"));
            return;
        }
    };
    let princ_str = &rest[0];
    let Some(canon) = st.parse_name(princ_str) else {
        st.com_err(
            &w,
            Some(&MALFORMED),
            format!("while parsing principal name {princ_str}"),
        );
        return;
    };
    let Some((pname, prealm)) = parse_principal(&canon, Some(&st.def_realm)) else {
        return;
    };
    let mode = match rest.get(1).map(String::as_str) {
        None => RemMode::High,
        Some("all") => RemMode::All,
        Some("old") => RemMode::Old,
        Some(s) => RemMode::Spec(atoi(s) as u32),
    };
    let entries = match keytab.entries() {
        Ok(e) => e,
        Err(_) => {
            st.error(format!("{w}: Keytab {ktname} does not exist.\n"));
            return;
        }
    };
    let mine: Vec<KeytabEntry> = entries
        .into_iter()
        .filter(|e| e.principal.name_string == pname.name_string && e.realm == prealm)
        .collect();
    let kvno = match mode {
        RemMode::Spec(k) => {
            if !mine.iter().any(|e| e.kvno == k) {
                st.error(format!(
                    "{w}: No entry for principal {princ_str} with kvno {k} exists in keytab {ktname}\n"
                ));
                return;
            }
            k
        }
        _ => match mine.iter().map(|e| e.kvno).max() {
            Some(k) => k,
            None => {
                st.error(format!(
                    "{w}: No entry for principal {princ_str} exists in keytab {ktname}\n"
                ));
                return;
            }
        },
    };
    let mut did = false;
    for e in &mine {
        let hit = match mode {
            RemMode::All => true,
            RemMode::Old => e.kvno != kvno,
            RemMode::High | RemMode::Spec(_) => e.kvno == kvno,
        };
        if !hit {
            continue;
        }
        if let Err(err) = keytab.remove_entry(e) {
            st.com_err(&w, Some(&err), "while deleting entry from keytab");
            return;
        }
        did = true;
        if !quiet {
            println!(
                "Entry for principal {princ_str} with kvno {} removed from keytab {ktname}.",
                e.kvno
            );
        }
    }
    if !did && mode == RemMode::Old {
        eprintln!("{w}: There is only one entry for principal {princ_str} in keytab {ktname}");
    }
}

/// `kadmin_ct.ct`.
static TABLE: &[Request<Kadmin>] = &[
    Request {
        names: &["add_principal", "addprinc", "ank"],
        info: "Add principal",
        func: addprinc,
    },
    Request {
        names: &["delete_principal", "delprinc"],
        info: "Delete principal",
        func: delprinc,
    },
    Request {
        names: &["modify_principal", "modprinc"],
        info: "Modify principal",
        func: modprinc,
    },
    Request {
        names: &["rename_principal", "renprinc"],
        info: "Rename principal",
        func: renprinc,
    },
    Request {
        names: &["add_alias", "alias"],
        info: "Add alias",
        func: addalias,
    },
    Request {
        names: &["change_password", "cpw"],
        info: "Change password",
        func: cpw,
    },
    Request {
        names: &["get_principal", "getprinc"],
        info: "Get principal",
        func: getprinc,
    },
    Request {
        names: &[
            "list_principals",
            "listprincs",
            "get_principals",
            "getprincs",
        ],
        info: "List principals",
        func: getprincs,
    },
    Request {
        names: &["add_policy", "addpol"],
        info: "Add policy",
        func: addpol,
    },
    Request {
        names: &["modify_policy", "modpol"],
        info: "Modify policy",
        func: modpol,
    },
    Request {
        names: &["delete_policy", "delpol"],
        info: "Delete policy",
        func: delpol,
    },
    Request {
        names: &["get_policy", "getpol"],
        info: "Get policy",
        func: getpol,
    },
    Request {
        names: &["list_policies", "listpols", "get_policies", "getpols"],
        info: "List policies",
        func: getpols,
    },
    Request {
        names: &["get_privs", "getprivs"],
        info: "Get privileges",
        func: getprivs,
    },
    Request {
        names: &["ktadd", "xst"],
        info: "Add entry(s) to a keytab",
        func: ktadd,
    },
    Request {
        names: &["ktremove", "ktrem"],
        info: "Remove entry(s) from a keytab",
        func: ktremove,
    },
    Request {
        names: &["lock"],
        info: "Lock database exclusively (use with extreme caution!)",
        func: lock,
    },
    Request {
        names: &["unlock"],
        info: "Release exclusive database lock",
        func: unlock,
    },
    Request {
        names: &["purgekeys"],
        info: "Purge previously retained old keys from a principal",
        func: purgekeys,
    },
    Request {
        names: &["get_strings", "getstrs"],
        info: "Show string attributes on a principal",
        func: getstrs,
    },
    Request {
        names: &["set_string", "setstr"],
        info: "Set a string attribute on a principal",
        func: setstr,
    },
    Request {
        names: &["del_string", "delstr"],
        info: "Delete a string attribute on a principal",
        func: delstr,
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations() {
        assert_eq!(strdur(0), "0 days 00:00:00");
        assert_eq!(strdur(86400 + 3661), "1 day 01:01:01");
        assert_eq!(strdur(-90061), "-1 day 01:01:01");
    }

    #[test]
    fn escapes_and_atoi() {
        assert!(has_unescaped("a@B", '@'));
        assert!(!has_unescaped("a\\@b", '@'));
        assert_eq!(find_unescaped("u/admin@R", '/'), Some(1));
        assert_eq!(atoi("12x"), 12);
        assert_eq!(atoi("x"), 0);
        assert_eq!(atoi("-3"), -3);
    }

    #[test]
    fn dummy_and_keysalts() {
        let d = dummy_password();
        assert_eq!(d.len(), 255);
        assert!(d.starts_with("6F a[f"));
        assert_eq!(keysalts("aes256-cts:norealm").unwrap(), vec![(18, 2)]);
        assert!(keysalts("bogus:normal").is_err());
    }
}
