//! `ktutil` (MIT krb5 1.22.2 `src/kadmin/ktutil`).

#![forbid(unsafe_code)]

use std::io::{BufRead, Write};
use std::sync::Arc;

use krb5_rs::ccache::{parse_principal, unparse_name};
use krb5_rs::client::vfy::resolve_keytab;
use krb5_rs::keytab::KeytabEntry;
use krb5_rs::protocol::AsExchangeConfig;
use krb5_rs::types::EncryptionKey;
use krb5_rs_clients::ss::{Request, Subsystem};
use krb5_rs_clients::{com_err_as, etype_string, krb5_message, now, sfstring};

struct Ktutil {
    profile: Arc<krb5_rs::profile::Profile>,
    list: Vec<KeytabEntry>,
}

fn err(argv0: &str, msg: impl std::fmt::Display, context: &str) {
    com_err_as(argv0, format!("{msg} {context}"));
}

fn clear_list(k: &mut Ktutil, argv: &[String]) {
    if argv.len() != 1 {
        eprintln!("{}: invalid arguments", argv[0]);
        return;
    }
    k.list.clear();
}

fn read_v5(k: &mut Ktutil, argv: &[String]) {
    if argv.len() != 2 {
        eprintln!("{}: must specify keytab to read", argv[0]);
        return;
    }
    let ctx = format!("while reading keytab \"{}\"", argv[1]);
    match resolve_keytab(&argv[1]).map_err(|e| krb5_message(&e)) {
        Ok(kt) => match kt.entries() {
            Ok(es) => k.list.extend(es),
            Err(e) => err(&argv[0], e, &ctx),
        },
        Err(e) => err(&argv[0], e, &ctx),
    }
}

fn read_v4(_: &mut Ktutil, argv: &[String]) {
    eprintln!("{}: reading srvtabs is no longer supported", argv[0]);
}

fn write_v5(k: &mut Ktutil, argv: &[String]) {
    if argv.len() != 2 {
        eprintln!("{}: must specify keytab to write", argv[0]);
        return;
    }
    let ctx = format!("while writing keytab \"{}\"", argv[1]);
    let mut kt = match resolve_keytab(&format!("WRFILE:{}", argv[1])) {
        Ok(kt) => kt,
        Err(e) => return err(&argv[0], krb5_message(&e), &ctx),
    };
    for e in &k.list {
        if let Err(e) = kt.add_entry(e) {
            return err(&argv[0], e, &ctx);
        }
    }
}

fn write_v4(_: &mut Ktutil, argv: &[String]) {
    eprintln!("{}: writing srvtabs is no longer supported", argv[0]);
}

/// `k5_hex_decode` after ktutil's odd-length fixup.
fn hex_key(line: &str) -> Result<Vec<u8>, ()> {
    let mut s = line.to_string();
    if s.len() % 2 == 1 {
        s.push('0');
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2).ok_or(())?, 16).map_err(|_| ()))
        .collect()
}

/// `ktutil_add`: build the entry; `Err` carries a com_err message.
fn ktutil_add(
    k: &mut Ktutil,
    princ_str: &str,
    fetch: bool,
    kvno: u32,
    enctype_str: Option<&str>,
    use_pass: bool,
    salt_str: Option<&str>,
) -> Result<(), String> {
    let defrealm = krb5_rs::locate::default_realm(&k.profile);
    let (princ, realm) = parse_principal(princ_str, defrealm.as_deref())
        .ok_or("Malformed representation of principal")?;
    let princ_full = unparse_name(&princ, &realm);
    let mut enctype = match enctype_str {
        Some(s) => krb5_rs::crypto::enctype_from_name(s).ok_or("Bad encryption type")?,
        None => 0,
    };
    let key = if use_pass {
        let pw = rpassword::prompt_password(format!("Password for {princ_full}: "))
            .map_err(|_| "Cannot read password")?;
        let (salt, params) = if !fetch {
            let salt = match salt_str {
                Some(s) => s.as_bytes().to_vec(),
                None => {
                    let mut s = realm.as_bytes().to_vec();
                    for c in &princ.name_string {
                        s.extend_from_slice(c.as_bytes());
                    }
                    s
                }
            };
            (salt, None)
        } else {
            let mut config = AsExchangeConfig::new(princ.clone(), realm.clone());
            if enctype != 0 {
                config.etypes = vec![enctype];
            }
            let client = krb5_clients_client(&k.profile, &realm);
            let rt = krb5_rs_clients::runtime();
            let (e, salt, params) = rt
                .block_on(client.get_etype_info(config))
                .map_err(|e| krb5_message(&e))?
                .ok_or("KDC has no support for encryption type")?;
            enctype = e;
            (salt, params)
        };
        let bytes = krb5_rs::crypto::find_etype(enctype)
            .and_then(|e| e.string_to_key(pw.as_bytes(), &salt, params.as_deref()))
            .map_err(|e| e.to_string())?;
        EncryptionKey::new(enctype, bytes.to_vec())
    } else {
        print!("Key for {princ_full} (hex): ");
        let _ = std::io::stdout().flush();
        let mut buf = String::new();
        let _ = std::io::stdin().lock().read_line(&mut buf);
        let buf = buf.strip_suffix('\n').unwrap_or(&buf);
        if buf.is_empty() {
            eprintln!("addent: Error reading key.");
            return Ok(());
        }
        let Ok(bytes) = hex_key(buf) else {
            eprintln!("addent: Illegal character in key.");
            return Ok(());
        };
        EncryptionKey::new(enctype, bytes)
    };
    k.list.push(KeytabEntry {
        principal: princ,
        realm,
        timestamp: now(),
        kvno,
        key,
    });
    Ok(())
}

fn krb5_clients_client(
    profile: &Arc<krb5_rs::profile::Profile>,
    realm: &str,
) -> krb5_rs::client::KerberosClient<krb5_rs::transport::LocatedTransport> {
    krb5_rs_clients::kerberos_client(profile, realm)
}

fn add_entry(k: &mut Ktutil, argv: &[String]) {
    let (mut princ, mut enctype, mut salt) = (None, None, None);
    let (mut kvno, mut use_pass, mut use_key, mut use_kvno, mut fetch) = (0u32, 0, 0, 0, 0);
    let mut i = 1;
    while i < argv.len() {
        match argv[i].as_str() {
            "-p" => {
                i += 1;
                princ = argv.get(i).cloned();
            }
            "-k" => {
                i += 1;
                kvno = argv.get(i).map_or(0, |s| atoi(s) as u32);
                use_kvno += 1;
            }
            "-e" => {
                i += 1;
                enctype = argv.get(i).cloned();
            }
            "-password" => use_pass += 1,
            "-key" => use_key += 1,
            "-s" => {
                i += 1;
                salt = argv.get(i).cloned();
            }
            "-f" => fetch += 1,
            _ => {}
        }
        i += 1;
    }
    let Some(princ) = princ
        .filter(|_| use_pass + use_key == 1 && use_kvno != 0 && !(fetch != 0 && salt.is_some()))
    else {
        eprintln!(
            "usage: {} (-key | -password) -p principal -k kvno [-e enctype] [-f|-s salt]",
            argv[0]
        );
        return;
    };
    if fetch == 0 && enctype.is_none() {
        eprintln!("enctype must be specified if not using -f");
        return;
    }
    if let Err(e) = ktutil_add(
        k,
        &princ,
        fetch != 0,
        kvno,
        enctype.as_deref(),
        use_pass != 0,
        salt.as_deref(),
    ) {
        err(&argv[0], e, "while adding new entry");
    }
}

/// C `atoi`: leading blanks, optional sign, then digits.
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
            n.wrapping_mul(10).wrapping_add(i64::from(d - b'0'))
        });
    if neg {
        -n
    } else {
        n
    }
}

fn delete_entry(k: &mut Ktutil, argv: &[String]) {
    if argv.len() != 2 {
        eprintln!("{}: must specify entry to delete", argv[0]);
        return;
    }
    let idx = atoi(&argv[1]) as i32;
    if idx >= 1 && (idx as usize) <= k.list.len() {
        k.list.remove(idx as usize - 1);
    } else {
        err(
            &argv[0],
            "Invalid argument",
            &format!("while deleting entry {idx}"),
        );
    }
}

fn list(k: &mut Ktutil, argv: &[String]) {
    let (mut show_time, mut show_keys, mut show_enctype) = (false, false, false);
    for a in &argv[1..] {
        match a.as_str() {
            "-t" => show_time = true,
            "-k" => show_keys = true,
            "-e" => show_enctype = true,
            _ => {
                eprintln!("{0}: usage: {0} [-t] [-k] [-e]", argv[0]);
                return;
            }
        }
    }
    print!(
        "{}",
        list_output(&k.list, show_time, show_keys, show_enctype)
    );
}

fn list_output(
    list: &[KeytabEntry],
    show_time: bool,
    show_keys: bool,
    show_enctype: bool,
) -> String {
    let mut out = String::new();
    if show_time {
        out.push_str("slot KVNO Timestamp         Principal\n");
        out.push_str(&format!("---- ---- ----------------- {}\n", "-".repeat(51)));
    } else {
        out.push_str("slot KVNO Principal\n");
        out.push_str(&format!("---- ---- {}\n", "-".repeat(69)));
    }
    for (i, e) in list.iter().enumerate() {
        out.push_str(&format!("{:4} {:4} ", i + 1, e.kvno as i32));
        if show_time {
            if let Some(t) = sfstring(e.timestamp, 18) {
                out.push_str(&format!("{t:<17} "));
            }
        }
        out.push_str(&format!("{:>40}", unparse_name(&e.principal, &e.realm)));
        if show_enctype {
            out.push_str(&format!(" ({}) ", etype_string(e.key.keytype)));
        }
        if show_keys {
            out.push_str(" (0x");
            for b in e.key.key_bytes() {
                out.push_str(&format!("{b:02x}"));
            }
            out.push(')');
        }
        out.push('\n');
    }
    out
}

static TABLE: &[Request<Ktutil>] = &[
    Request {
        names: &["clear_list", "clear"],
        info: "Clear the current keylist.",
        func: clear_list,
    },
    Request {
        names: &["read_kt", "rkt"],
        info: "Read a krb5 keytab into the current keylist.",
        func: read_v5,
    },
    Request {
        names: &["read_st", "rst"],
        info: "Deprecated and removed.",
        func: read_v4,
    },
    Request {
        names: &["write_kt", "wkt"],
        info: "Write the current keylist to a krb5 keytab.",
        func: write_v5,
    },
    Request {
        names: &["write_st", "wst"],
        info: "Deprecated and removed.",
        func: write_v4,
    },
    Request {
        names: &["add_entry", "addent"],
        info: "Add an entry to the current keylist.",
        func: add_entry,
    },
    Request {
        names: &["delete_entry", "delent"],
        info: "Delete an entry from the current keylist.",
        func: delete_entry,
    },
    Request {
        names: &["list", "l"],
        info: "List the current keylist.",
        func: list,
    },
];

fn main() {
    let profile = Arc::new(krb5_rs_clients::profile());
    let mut k = Ktutil {
        profile,
        list: Vec::new(),
    };
    Subsystem {
        name: "ktutil",
        table: TABLE,
    }
    .listen(&mut k);
}

#[cfg(test)]
mod tests {
    use super::*;
    use krb5_rs::types::PrincipalName;

    #[test]
    fn hex_and_atoi() {
        assert_eq!(hex_key("abc").unwrap(), [0xab, 0xc0]);
        assert!(hex_key("zz").is_err());
        assert_eq!(atoi(" 12x"), 12);
        assert_eq!(atoi("-3"), -3);
        assert_eq!(atoi("x"), 0);
    }

    #[test]
    fn list_layout() {
        let e = KeytabEntry {
            principal: PrincipalName::new_srv_inst("host", "a.example"),
            realm: "EXAMPLE.COM".into(),
            timestamp: 0,
            kvno: 3,
            key: EncryptionKey::new(18, vec![1, 2]),
        };
        let out = list_output(&[e], false, true, true);
        let row = out.lines().nth(2).unwrap();
        assert_eq!(
            row,
            format!(
                "   1    3 {:>40} (aes256-cts-hmac-sha1-96)  (0x0102)",
                "host/a.example@EXAMPLE.COM"
            )
        );
    }
}
