//! MIT `krb5kdc` options (kdc/main.c `initialize_realms`, getopt string
//! `x:r:d:mM:k:R:P:p:nw:4:T:X3`), accepted alongside krb5-rs's `--long`
//! options.

use std::ffi::OsString;
use std::path::PathBuf;

/// The options in force when a realm is named with `-r`
/// (main.c:686-700); the ones after the last `-r` go to the default realm
/// when no `-r` is given (main.c:788-812).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct RealmArgs {
    pub realm: Option<String>,
    /// `-x` and `-d` (as `dbname=PATH`); cleared after each new realm.
    pub db_args: Vec<String>,
    /// `-m`: type the master password in, if kdc.conf names no stash.
    pub manual: bool,
    /// `-M`.
    pub mkey_name: Option<String>,
    /// `-k` (or aes256-cts after `-m`).
    pub menctype: Option<i32>,
    /// `-p`: UDP and TCP listen ports for realms kdc.conf gives none.
    pub ports: Option<String>,
    /// `-T`.
    pub time_offset: i64,
}

#[derive(Debug, Default, PartialEq)]
pub struct MitArgs {
    /// Realms named with `-r`, without repeats (`find_realm_data`).
    pub realms: Vec<RealmArgs>,
    /// The options after the last `-r`.
    pub defaults: RealmArgs,
    /// `-n`.
    pub nofork: bool,
    /// `-w`.
    pub workers: usize,
    /// `-P`.
    pub pid_file: Option<PathBuf>,
    /// Messages MIT prints and carries on after (`-k` with a bad enctype).
    pub warnings: Vec<String>,
}

/// `DEFAULT_KDC_ENCTYPE`.
const DEFAULT_KDC_ENCTYPE: i32 = 18;

/// krb5-rs's long options that take a value.
const LONG_WITH_VALUE: &[&str] = &[
    "config",
    "krb5-config",
    "realm",
    "listen",
    "master-password-file",
    "keytab",
    "max-life",
    "max-renewable-life",
    "shutdown-timeout",
    "metrics-listen",
];

/// MIT's `usage()` (main.c:580-594).
pub fn usage(name: &str) -> String {
    format!(
        "usage: {name} [-x db_args]* [-d dbpathname] [-r dbrealmname]\n\
         \t\t[-T time_offset] [-m] [-k masterenctype]\n\
         \t\t[-M masterkeyname] [-p port] [-P pid_file]\n\
         \t\t[-n] [-w numworkers] [/]\n\n\
         where,\n\
         \t[-x db_args]* - Any number of database specific arguments.\n\
         \t\t\tLook at each database module documentation for \
         \t\t\tsupported arguments\n"
    )
}

/// C `atoi`.
fn atoi(s: &str) -> i64 {
    let s = s.trim_start();
    let (neg, digits) = match s.as_bytes().first() {
        Some(b'-') => (true, &s[1..]),
        Some(b'+') => (false, &s[1..]),
        _ => (false, s),
    };
    let n = digits
        .bytes()
        .take_while(u8::is_ascii_digit)
        .fold(0i64, |n, d| {
            n.saturating_mul(10).saturating_add(i64::from(d - b'0'))
        });
    if neg {
        -n
    } else {
        n
    }
}

/// Split `args` (with `argv[0]` first) into the `--long` options, for clap,
/// and MIT's options. `Err(())` means MIT would print its usage.
pub fn parse(args: impl IntoIterator<Item = OsString>) -> Result<(Vec<OsString>, MitArgs), ()> {
    let mut args = args.into_iter();
    let argv0 = args.next().unwrap_or_else(|| "krb5-rs-kdc".into());
    let progname = argv0.to_string_lossy().into_owned();
    let mut long = vec![argv0];
    let mut mit = MitArgs::default();
    let mut cur = RealmArgs::default();
    let mut db_name: Option<String> = None;
    while let Some(arg) = args.next() {
        let text = arg.to_string_lossy().into_owned();
        if text == "--" {
            break;
        }
        if let Some(name) = text.strip_prefix("--") {
            let takes_value = !name.contains('=') && LONG_WITH_VALUE.contains(&name);
            long.push(arg);
            if takes_value {
                long.extend(args.next());
            }
            continue;
        }
        let Some(opts) = text.strip_prefix('-').filter(|o| !o.is_empty()) else {
            // getopt leaves operands alone and MIT never looks at them.
            continue;
        };
        for (i, c) in opts.char_indices() {
            if !"xrdMkRPpw4T".contains(c) {
                match c {
                    'm' => {
                        cur.manual = true;
                        cur.menctype.get_or_insert(DEFAULT_KDC_ENCTYPE);
                    }
                    'n' => mit.nofork = true,
                    'X' | '3' => {}
                    _ => return Err(()),
                }
                continue;
            }
            let rest = &opts[i + c.len_utf8()..];
            let value = if rest.is_empty() {
                args.next().ok_or(())?.to_string_lossy().into_owned()
            } else {
                rest.to_string()
            };
            match c {
                'x' => cur.db_args.push(value),
                'r' => {
                    if !mit
                        .realms
                        .iter()
                        .any(|r| r.realm.as_deref() == Some(&value))
                    {
                        let mut r = cur.clone();
                        r.realm = Some(value);
                        mit.realms.push(r);
                        cur.db_args.clear();
                    }
                }
                'd' => {
                    // Only the first -d names the database (main.c:712-716).
                    let name = db_name.get_or_insert_with(|| format!("dbname={value}"));
                    cur.db_args.push(name.clone());
                }
                'M' => cur.mkey_name = Some(value),
                'k' => match krb5_rs::crypto::enctype_from_name(&value) {
                    Some(e) => cur.menctype = Some(e),
                    None => mit
                        .warnings
                        .push(format!("{progname}: invalid enctype {value}")),
                },
                'P' => mit.pid_file = Some(PathBuf::from(value)),
                'p' => cur.ports = Some(value),
                'T' => cur.time_offset = atoi(&value),
                'w' => {
                    mit.workers = usize::try_from(atoi(&value))
                        .ok()
                        .filter(|&n| n > 0)
                        .ok_or(())?;
                }
                _ => {} // -R and -4 are defunct.
            }
            break;
        }
    }
    mit.defaults = cur;
    Ok((long, mit))
}

/// The realms to serve: those named with `-r`, then `--realm`; else the
/// default realm (`None`) with the options given.
pub fn realms(mit: &MitArgs, long_realm: Option<&str>) -> Vec<RealmArgs> {
    let mut out = mit.realms.clone();
    if let Some(name) = long_realm {
        if !out.iter().any(|r| r.realm.as_deref() == Some(name)) {
            out.push(RealmArgs {
                realm: Some(name.to_string()),
                ..mit.defaults.clone()
            });
        }
    }
    if out.is_empty() {
        out.push(mit.defaults.clone());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(args: &[&str]) -> Result<(Vec<String>, MitArgs), ()> {
        let all = std::iter::once("krb5kdc").chain(args.iter().copied());
        parse(all.map(OsString::from))
            .map(|(l, m)| (l.into_iter().map(|s| s.into_string().unwrap()).collect(), m))
    }

    #[test]
    fn options_apply_to_the_realms_after_them() {
        let (_, m) = p(&[
            "-p", "2001", "-r", "R1", "-p", "2002", "-r", "R2", "-r", "R3",
        ])
        .unwrap();
        let ports: Vec<_> = m.realms.iter().map(|r| r.ports.as_deref()).collect();
        assert_eq!(ports, [Some("2001"), Some("2002"), Some("2002")]);
        let names: Vec<_> = m.realms.iter().map(|r| r.realm.as_deref()).collect();
        assert_eq!(names, [Some("R1"), Some("R2"), Some("R3")]);
    }

    #[test]
    fn db_args_reset_after_each_realm_and_d_is_dbname() {
        let (_, m) = p(&[
            "-x", "a", "-d", "/db1", "-r", "R1", "-d", "/db2", "-r", "R2", "-r", "R1",
        ])
        .unwrap();
        assert_eq!(m.realms[0].db_args, ["a", "dbname=/db1"]);
        assert_eq!(m.realms[1].db_args, ["dbname=/db1"]);
        assert_eq!(m.realms.len(), 2);
    }

    #[test]
    fn flags_values_and_long_options() {
        let (long, m) = p(&[
            "-nm",
            "-kaes128-cts",
            "-M",
            "K/M2",
            "-P",
            "/run/kdc.pid",
            "-w",
            "3",
            "-T",
            "-30",
            "--config",
            "/etc/kdc.conf",
            "--wait-for-database",
            "-R",
            "x",
            "-4",
            "y",
            "-X",
            "-3",
            "/",
            "--listen=127.0.0.1:88",
        ])
        .unwrap();
        assert_eq!(
            long,
            [
                "krb5kdc",
                "--config",
                "/etc/kdc.conf",
                "--wait-for-database",
                "--listen=127.0.0.1:88"
            ]
        );
        assert!(m.nofork);
        assert_eq!(m.workers, 3);
        assert_eq!(m.pid_file, Some(PathBuf::from("/run/kdc.pid")));
        let d = &m.defaults;
        assert!(d.manual);
        assert_eq!(d.menctype, Some(17));
        assert_eq!(d.mkey_name.as_deref(), Some("K/M2"));
        assert_eq!(d.time_offset, -30);
        assert_eq!(realms(&m, None), std::slice::from_ref(&m.defaults));
    }

    #[test]
    fn m_defaults_to_aes256_and_bad_k_only_warns() {
        let (_, m) = p(&["-m", "-k", "bogus"]).unwrap();
        assert_eq!(m.defaults.menctype, Some(18));
        assert_eq!(m.warnings, ["krb5kdc: invalid enctype bogus"]);
    }

    #[test]
    fn bad_options_are_usage_errors() {
        assert!(p(&["-w", "0"]).is_err());
        assert!(p(&["-w", "x"]).is_err());
        assert!(p(&["-q"]).is_err());
        assert!(p(&["-r"]).is_err());
    }

    #[test]
    fn long_realm_adds_a_realm() {
        let (_, m) = p(&["-r", "A"]).unwrap();
        let r = realms(&m, Some("B"));
        assert_eq!(r.len(), 2);
        assert_eq!(realms(&m, Some("A")).len(), 1);
        let (_, m) = p(&[]).unwrap();
        assert_eq!(realms(&m, Some("B"))[0].realm.as_deref(), Some("B"));
    }
}
