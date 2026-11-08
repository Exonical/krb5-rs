//! Shared pieces of the MIT-compatible command-line tools.

#![forbid(unsafe_code)]

use std::sync::OnceLock;

use chrono::{Local, Locale, TimeZone};
use krb5_rs::profile::Profile;

static PROGNAME: OnceLock<String> = OnceLock::new();

/// `GET_PROGNAME(argv[0])`.
pub fn progname() -> &'static str {
    PROGNAME.get_or_init(|| {
        std::env::args()
            .next()
            .map(|a| {
                std::path::Path::new(&a)
                    .file_name()
                    .map(|f| f.to_string_lossy().into_owned())
                    .unwrap_or(a)
            })
            .unwrap_or_default()
    })
}

pub mod kadm5;
pub mod ss;

/// `com_err(progname, code, fmt)`: `prog: message context`.
pub fn com_err(msg: impl std::fmt::Display, context: &str) {
    if context.is_empty() {
        eprintln!("{}: {msg}", progname());
    } else {
        eprintln!("{}: {msg} {context}", progname());
    }
}

/// `com_err(whoami, 0, msg)` with an explicit `whoami` (`ss_error`).
pub fn com_err_as(whoami: &str, msg: impl std::fmt::Display) {
    eprintln!("{whoami}: {msg}");
}

/// [`com_err`], then `exit(code)`.
pub fn fail(msg: impl std::fmt::Display, context: &str, code: i32) -> ! {
    com_err(msg, context);
    std::process::exit(code)
}

/// The profile from `KRB5_CONFIG` (default `/etc/krb5.conf`), as
/// `krb5_init_context` reads it.
pub fn profile() -> Profile {
    let paths = std::env::var("KRB5_CONFIG").unwrap_or_else(|_| "/etc/krb5.conf".into());
    let mut text = String::new();
    for p in paths.split(':').filter(|p| !p.is_empty()) {
        if let Ok(t) = std::fs::read_to_string(p) {
            text.push_str(&t);
            text.push('\n');
        }
    }
    Profile::parse(&text).unwrap_or_else(|e| fail(e, "while initializing krb5", 1))
}

/// The `LC_TIME` locale (`setlocale(LC_ALL, "")`).
fn time_locale() -> Locale {
    let name = ["LC_ALL", "LC_TIME", "LANG"]
        .iter()
        .find_map(|k| std::env::var(k).ok().filter(|v| !v.is_empty()))
        .unwrap_or_default();
    let base = name.split(['.', '@']).next().unwrap_or("");
    Locale::try_from(base).unwrap_or(Locale::POSIX)
}

/// `krb5_timestamp_to_sfstring` with a buffer of `bufsize` bytes: the first
/// format of MIT's table whose result fits.
pub fn sfstring(ts: u32, bufsize: usize) -> Option<String> {
    const FORMATS: [&str; 9] = [
        "%c",
        "%d %b %Y %T",
        "%x %X",
        "%x %T",
        "%x %R",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M",
        "%Y%m%d%H%M%S",
        "%Y%m%d%H%M",
    ];
    let t = Local.timestamp_opt(i64::from(ts), 0).single()?;
    let loc = time_locale();
    FORMATS
        .iter()
        .map(|f| t.format_localized(f, loc).to_string())
        .find(|s| s.len() < bufsize)
}

/// `krb5_timestamp_to_sfstring(ts, buf, width + 1, &' ')`: padded to `width`.
pub fn printtime(ts: u32, width: usize) -> String {
    sfstring(ts, width + 1)
        .map(|s| format!("{s:<width$}"))
        .unwrap_or_default()
}

/// klist's `timestamp_width`.
pub fn timestamp_width(now: u32) -> usize {
    sfstring(now, 20)
        .or_else(|| sfstring(now, 8192))
        .map(|s| s.len())
        .unwrap_or(15)
}

/// klist's `etype_string`: `krb5_enctype_to_name(.., FALSE, ..)` with a
/// `DEPRECATED:` prefix (MIT `etypes.c` ETYPE_DEPRECATED).
pub fn etype_string(etype: i32) -> String {
    let dep = if matches!(etype, 6 | 16 | 23 | 24) {
        "DEPRECATED:"
    } else {
        ""
    };
    match krb5_rs::crypto::enctype_name(etype) {
        Some(n) => format!("{dep}{n}"),
        None => format!("{dep}etype {etype}"),
    }
}

/// The current time.
pub fn now() -> u32 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as u32)
        .unwrap_or(0)
}

/// POSIX `getopt` over `args` (without `argv[0]`). Options stop at the
/// first operand or `--`; the operands are left in [`Getopt::rest`].
pub struct Getopt {
    args: Vec<String>,
    spec: &'static str,
    idx: usize,
    pos: usize,
}

impl Getopt {
    /// Parse `std::env::args()` against `spec` (`"c:p:"`).
    pub fn new(spec: &'static str) -> Self {
        Self::from_args(std::env::args().skip(1).collect(), spec)
    }

    /// Parse `args` against `spec`.
    pub fn from_args(args: Vec<String>, spec: &'static str) -> Self {
        Self {
            args,
            spec,
            idx: 0,
            pos: 0,
        }
    }

    /// The operands after the options.
    pub fn rest(&self) -> &[String] {
        &self.args[self.idx.min(self.args.len())..]
    }
}

impl Iterator for Getopt {
    /// The option character (`'?'` for an error) and its argument.
    type Item = (char, Option<String>);

    fn next(&mut self) -> Option<Self::Item> {
        if self.pos == 0 {
            let a = self.args.get(self.idx)?;
            if a == "--" {
                self.idx += 1;
                return None;
            }
            if !a.starts_with('-') || a.len() == 1 {
                return None;
            }
            self.pos = 1;
        }
        let arg = self.args[self.idx].clone();
        let c = arg[self.pos..].chars().next()?;
        self.pos += c.len_utf8();
        let at_end = self.pos >= arg.len();
        let spec_pos = (c != ':').then(|| self.spec.find(c)).flatten();
        let Some(sp) = spec_pos else {
            eprintln!("{}: invalid option -- '{c}'", progname());
            if at_end {
                self.idx += 1;
                self.pos = 0;
            }
            return Some(('?', None));
        };
        if self.spec[sp + 1..].starts_with(':') {
            let val = if !at_end {
                Some(arg[self.pos..].to_string())
            } else {
                self.idx += 1;
                self.args.get(self.idx).cloned()
            };
            self.idx += 1;
            self.pos = 0;
            return match val {
                Some(v) => Some((c, Some(v))),
                None => {
                    eprintln!("{}: option requires an argument -- '{c}'", progname());
                    Some(('?', None))
                }
            };
        }
        if at_end {
            self.idx += 1;
            self.pos = 0;
        }
        Some((c, None))
    }
}

/// `krb5int_libdefault_string`: `[libdefaults] realm = { name }`, then
/// `[libdefaults] name`.
pub fn libdefault_string(profile: &Profile, realm: &str, name: &str) -> Option<String> {
    profile
        .get_string(&["libdefaults", realm, name])
        .or_else(|| profile.get_string(&["libdefaults", name]))
}

/// `krb5int_libdefault_boolean`.
pub fn libdefault_boolean(profile: &Profile, realm: &str, name: &str) -> Option<bool> {
    libdefault_string(profile, realm, name).and_then(|s| match s.to_ascii_lowercase().as_str() {
        "y" | "yes" | "true" | "t" | "1" | "on" => Some(true),
        "n" | "no" | "false" | "nil" | "0" | "off" => Some(false),
        _ => None,
    })
}

/// The `krb5_err.et` / `com_err` text for a library error.
pub fn krb5_message(e: &krb5_rs::Krb5Error) -> String {
    use krb5_rs::Krb5Error as E;
    match e {
        // get_in_tkt.c:1936-1946 and gc_via_tkt.c:202-214 name the principal.
        E::KdcError(m) if m.error_code == 6 && m.cname.is_some() => {
            let (Some(c), Some(r)) = (&m.cname, &m.crealm) else {
                return "Client not found in Kerberos database".into();
            };
            format!(
                "Client '{}' not found in Kerberos database",
                krb5_rs::ccache::unparse_name(c, &String::from_utf8_lossy(r.as_ref()))
            )
        }
        E::KdcError(m) if m.error_code == 7 => format!(
            "Server {} not found in Kerberos database",
            krb5_rs::ccache::unparse_name(&m.sname, &String::from_utf8_lossy(m.realm.as_ref()))
        ),
        E::KdcError(m) => krb5_rs::protocol::ErrorCode::from_i32(m.error_code)
            .map(|c| c.description().to_string())
            .unwrap_or_else(|| format!("KDC error {}", m.error_code)),
        E::DecryptionFailed => "Decrypt integrity check failed".into(),
        E::PreauthFailed => "Preauthentication failed".into(),
        E::ClockSkew { .. } => "Clock skew too great".into(),
        other => other.to_string(),
    }
}

/// The local host's canonical name (`krb5_sname_to_principal` with a NULL
/// host): `gethostname`, forward-canonicalized, lowercased.
pub fn local_fqdn() -> Option<String> {
    let host = dns_lookup::get_hostname().ok()?;
    let hints = dns_lookup::AddrInfoHints {
        flags: 2, // AI_CANONNAME
        ..Default::default()
    };
    let canon = dns_lookup::getaddrinfo(Some(&host), None, Some(hints))
        .ok()
        .and_then(|mut it| it.find_map(|a| a.ok().and_then(|a| a.canonname)))
        .unwrap_or(host);
    Some(canon.to_lowercase())
}

/// `krb5_string_to_timestamp` (str_conv.c:142-200), in local time.
pub fn string_to_timestamp(s: &str) -> Option<i64> {
    use chrono::{NaiveDate, NaiveDateTime, NaiveTime};
    const FULL: [&str; 7] = [
        "%Y%m%d%H%M%S",
        "%Y.%m.%d.%H.%M.%S",
        "%y%m%d%H%M%S",
        "%y.%m.%d.%H.%M.%S",
        "%d-%b-%Y:%T",
        "%d-%b-%Y:%R",
        "%x:%X",
    ];
    const NO_SEC: [&str; 1] = ["%y%m%d%H%M"];
    const TIME: [&str; 4] = ["%H%M%S", "%H%M", "%T", "%R"];
    let local = |n: NaiveDateTime| {
        Local
            .from_local_datetime(&n)
            .earliest()
            .map(|t| t.timestamp())
    };
    for f in FULL.iter().chain(NO_SEC.iter()) {
        if let Ok(n) = NaiveDateTime::parse_from_str(s, f) {
            return local(n);
        }
    }
    let today: NaiveDate = Local::now().date_naive();
    for f in TIME {
        if let Ok(t) = NaiveTime::parse_from_str(s, f) {
            return local(today.and_time(t));
        }
    }
    None
}

/// A client for `realm` using the profile's KDC locations, DNS and
/// host-name canonicalization settings.
pub fn kerberos_client(
    profile: &std::sync::Arc<Profile>,
    realm: &str,
) -> krb5_rs::client::KerberosClient<krb5_rs::transport::LocatedTransport> {
    type Dns = std::sync::Arc<dyn krb5_rs::locate::DnsResolver + Send + Sync>;
    let dns: Option<Dns> = krb5_rs::locate::HickoryResolver::new()
        .ok()
        .map(|r| std::sync::Arc::new(r) as Dns);
    let transport = krb5_rs::transport::LocatedTransport::new(profile.clone(), dns);
    krb5_rs::client::KerberosClient::new(realm.to_string(), transport)
        .with_host_canonicalization(krb5_rs::client::HostCanonicalization::from_profile(profile))
}

/// A current-thread runtime for the async client calls.
pub fn runtime() -> tokio::runtime::Runtime {
    match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => fail(e, "while initializing krb5 library", 1),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn opts(args: &[&str], spec: &'static str) -> (Vec<(char, Option<String>)>, Vec<String>) {
        let mut g = Getopt::from_args(args.iter().map(|s| s.to_string()).collect(), spec);
        let v: Vec<_> = g.by_ref().collect();
        (v, g.rest().to_vec())
    }

    #[test]
    fn getopt_like_posix() {
        let (v, rest) = opts(&["-ef", "-cFILE:x", "-p", "a@R", "name", "-q"], "efc:p:q");
        assert_eq!(
            v,
            [
                ('e', None),
                ('f', None),
                ('c', Some("FILE:x".into())),
                ('p', Some("a@R".into()))
            ]
        );
        assert_eq!(rest, ["name", "-q"]);
        let (v, rest) = opts(&["-x", "--", "-q"], "q");
        assert_eq!(v, [('?', None)]);
        assert_eq!(rest, ["-q"]);
        let (v, _) = opts(&["-c"], "c:");
        assert_eq!(v, [('?', None)]);
    }

    #[test]
    fn etype_strings() {
        assert_eq!(etype_string(18), "aes256-cts-hmac-sha1-96");
        assert_eq!(etype_string(23), "DEPRECATED:arcfour-hmac");
        assert_eq!(etype_string(999), "etype 999");
    }
}
