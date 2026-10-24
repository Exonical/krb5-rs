//! `krb5-rs-kproplog`: MIT `kproplog` (`kprop/kproplog.c`) for the iprop
//! update log.

use std::fs::File;
use std::path::PathBuf;

use krb5_rs::kdc::kdb::mit::ulog::{
    read_entry, read_header, Header, Key, Princ, Tl, Ulog, Update, Value, KDB_CORRUPT, KDB_STABLE,
    KDB_ULOG_HDR_MAGIC, KDB_ULOG_MAGIC, KDB_UNSTABLE,
};
use krb5_rs::kdc::{default_realm, RealmConfig};
use krb5_rs::profile::Profile;

const OUTFLAGS: [Option<&str>; 24] = [
    Some("DISALLOW_POSTDATED"),
    Some("DISALLOW_FORWARDABLE"),
    Some("DISALLOW_TGT_BASED"),
    Some("DISALLOW_RENEWABLE"),
    Some("DISALLOW_PROXIABLE"),
    Some("DISALLOW_DUP_SKEY"),
    Some("DISALLOW_ALL_TIX"),
    Some("REQUIRES_PRE_AUTH"),
    Some("REQUIRES_HW_AUTH"),
    Some("REQUIRES_PWCHANGE"),
    None,
    None,
    Some("DISALLOW_SVR"),
    Some("PWCHANGE_SERVICE"),
    Some("SUPPORT_DESMD5"),
    Some("NEW_PRINC"),
    None,
    None,
    None,
    None,
    Some("OK_AS_DELEGATE"),
    Some("OK_TO_AUTH_AS_DELEGATE"),
    Some("NO_AUTH_DATA_REQUIRED"),
    Some("LOCKDOWN_KEYS"),
];

fn progname() -> String {
    std::env::args()
        .next()
        .unwrap_or_else(|| "krb5-rs-kproplog".into())
}

/// `usage` (`kproplog.c:26-33`).
fn usage() -> ! {
    let p = progname();
    eprint!("\nUsage: {p} [-h] [-v] [-v] [-e num]\n\t{p} -R\n\n");
    std::process::exit(1)
}

fn die(message: String) -> ! {
    eprint!("{message}");
    std::process::exit(1)
}

/// `ctime(3)`, including its newline.
fn ctime(seconds: u32) -> String {
    chrono::DateTime::from_timestamp(i64::from(seconds), 0).map_or_else(
        || "(error)".into(),
        |t| {
            t.with_timezone(&chrono::Local)
                .format("%a %b %e %H:%M:%S %Y\n")
                .to_string()
        },
    )
}

/// `print_flags` / `krb5_flags_to_strings` (`lib/kadm5/str_conv.c:200-259`).
fn print_flags(flags: u32) {
    for bit in 0..32 {
        if flags & (1 << bit) == 0 {
            continue;
        }
        match OUTFLAGS.get(bit).copied().flatten() {
            Some(name) => println!("\t\t\t{name}"),
            None => println!("\t\t\t0x{:08x}", 1u64 << bit),
        }
    }
}

fn print_time(t: u32) {
    if t == 0 {
        println!("\t\t\tNone");
    } else {
        print!("\t\t\t{}", ctime(t));
    }
}

/// `krb5_deltat_to_string` (`lib/krb5/krb/str_conv.c:259-281`).
fn deltat(d: u32) -> String {
    let d = d as i32;
    let (days, rest) = (d / 86400, d % 86400);
    let (h, m, s) = (rest / 3600, rest % 3600 / 60, rest % 60);
    let unit = if days > 1 { "days" } else { "day" };
    if days == 0 {
        format!("{h}:{m:02}:{s:02}")
    } else if h != 0 || m != 0 || s != 0 {
        format!("{days} {unit} {h:02}:{m:02}:{s:02}")
    } else {
        format!("{days} {unit}")
    }
}

fn print_deltat(d: u32) {
    println!("\t\t\t{}", deltat(d));
}

fn hex(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02x}")).collect()
}

fn print_str(tag: &str, s: &[u8]) {
    let text = s.split(|b| *b == 0).next().unwrap_or_default();
    println!(
        "\t\t\t{tag}({}): {}",
        s.len(),
        String::from_utf8_lossy(text)
    );
}

fn print_princ(p: &Princ) {
    print_str("realm", &p.realm);
    for (magic, data) in &p.components {
        println!("\t\t\tmagic: 0x{magic:x}");
        print_str("princ", data);
    }
}

fn print_key(k: &Key) {
    println!("\t\t\tver: {}", k.ver);
    println!("\t\t\tkvno: {}", k.kvno);
    for e in &k.enctypes {
        println!("\t\t\tenc type: 0x{e:x}");
    }
    for c in &k.contents {
        println!("\t\t\tkey({}): 0x{}", c.len(), hex(c));
    }
}

fn print_tldata(tls: &[Tl]) {
    println!("\t\t\titems: {}", tls.len());
    for tl in tls {
        println!("\t\t\ttype: 0x{:x}", tl.kind);
        println!("\t\t\tvalue({}): 0x{}", tl.data.len(), hex(&tl.data));
    }
}

/// `print_attr` (`kproplog.c:201-313`).
fn print_attr(v: &Value, vverbose: bool) {
    let label = match v {
        Value::AttrFlags(_) => "Attribute flags",
        Value::MaxLife(_) => "Maximum ticket life",
        Value::MaxRenewLife(_) => "Maximum renewable life",
        Value::Exp(_) => "Principal expiration",
        Value::PwExp(_) => "Password expiration",
        Value::LastSuccess(_) => "Last successful auth",
        Value::LastFailed(_) => "Last failed auth",
        Value::FailAuthCount(_) => "Failed passwd attempt",
        Value::Princ(_) => "Principal",
        Value::KeyData(_) => "Key data",
        Value::TlData(_) => "TL data",
        Value::Len(_) => "Length",
        Value::PwLastChange(_) => "Password last changed",
        Value::ModPrinc(_) => "Modifying principal",
        Value::ModTime(_) => "Modification time",
        Value::ModWhere(_) => "Modified where",
        Value::PwPolicy(_) => "Password policy",
        Value::PwPolicySwitch(_) => "Password policy switch",
        Value::PwHistKvno(_) => "Password history KVNO",
        Value::PwHist(_) => "Password history",
        Value::Extension(..) => return,
    };
    println!("\t\t{label}");
    if !vverbose {
        return;
    }
    match v {
        Value::AttrFlags(f) => print_flags(*f),
        Value::MaxLife(d) | Value::MaxRenewLife(d) => print_deltat(*d),
        Value::Exp(t)
        | Value::PwExp(t)
        | Value::LastSuccess(t)
        | Value::LastFailed(t)
        | Value::PwLastChange(t)
        | Value::ModTime(t) => print_time(*t),
        Value::FailAuthCount(n) | Value::PwHistKvno(n) => println!("\t\t\t{}", *n as i32),
        Value::Princ(p) | Value::ModPrinc(p) => print_princ(p),
        Value::KeyData(keys) => keys.iter().for_each(print_key),
        Value::TlData(tls) => print_tldata(tls),
        Value::Len(n) => println!("\t\t\t{n}"),
        Value::ModWhere(s) => print_str("where", s),
        Value::PwPolicy(s) => print_str("policy", s),
        Value::PwPolicySwitch(b) => println!("\t\t\t{}", i32::from(*b)),
        Value::PwHist(_) => println!("\t\t\tPW history elided"),
        Value::Extension(..) => {}
    }
}

/// `print_update` (`kproplog.c:315-400`).
fn print_update(file: &File, h: &Header, entry: u32, ulogentries: u32, verbose: u32) {
    let start = if entry != 0 && entry < h.num {
        h.last_sno - entry
    } else {
        h.first_sno.wrapping_sub(1)
    };
    let mut i = start;
    while i < h.last_sno {
        let index = i % ulogentries.max(1);
        i += 1;
        let Ok((eh, data)) = read_entry(file, h.block, index) else {
            print!("Entry data decode failure\n\n");
            std::process::exit(1)
        };
        if eh.umagic != KDB_ULOG_MAGIC {
            die("Corrupt update entry\n\n".into());
        }
        println!("---");
        println!("Update Entry");
        println!("\tUpdate serial # : {}", eh.sno);
        if eh.entry_size == 0 {
            println!("\tDummy entry");
            continue;
        }
        let Ok(upd) = Update::decode(&data) else {
            print!("Entry data decode failure\n\n");
            std::process::exit(1)
        };
        println!(
            "\tUpdate operation : {}",
            if upd.deleted { "Delete" } else { "Add" }
        );
        print_str_line("\tUpdate principal : ", &upd.princ_name);
        println!("\tUpdate size : {}", eh.entry_size);
        println!(
            "\tUpdate committed : {}",
            if eh.commit { "True" } else { "False" }
        );
        if eh.time.seconds == 0 {
            println!("\tUpdate time stamp : None");
        } else {
            print!("\tUpdate time stamp : {}", ctime(eh.time.seconds));
        }
        println!("\tAttributes changed : {}", upd.values.len());
        if verbose > 0 {
            for v in &upd.values {
                print_attr(v, verbose > 1);
            }
        }
    }
}

fn print_str_line(prefix: &str, s: &[u8]) {
    let text = s.split(|b| *b == 0).next().unwrap_or_default();
    println!("{prefix}{}", String::from_utf8_lossy(text));
}

fn config() -> RealmConfig {
    let kdc_conf = std::env::var_os("KRB5_KDC_PROFILE").map_or_else(
        || PathBuf::from("/usr/local/var/krb5kdc/kdc.conf"),
        PathBuf::from,
    );
    let krb5_conf = std::env::var_os("KRB5_CONFIG")
        .map_or_else(|| PathBuf::from("/etc/krb5.conf"), PathBuf::from);
    let Ok(kdc) = Profile::load(&kdc_conf) else {
        die("Couldn't read database_name\n\n".into())
    };
    let krb5 = krb5_conf
        .exists()
        .then(|| Profile::load(&krb5_conf).ok())
        .flatten();
    let Some(realm) = default_realm(&kdc, krb5.as_ref()) else {
        die("Couldn't read database_name\n\n".into())
    };
    RealmConfig::from_profiles(&kdc, krb5.as_ref(), &realm)
        .unwrap_or_else(|_| die("Couldn't read database_name\n\n".into()))
}

fn main() {
    let (mut verbose, mut headeronly, mut reset, mut entry) = (0u32, false, false, 0u32);
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        let Some(flags) = arg.strip_prefix('-').filter(|f| !f.is_empty()) else {
            usage()
        };
        let mut chars = flags.char_indices();
        while let Some((i, c)) = chars.next() {
            match c {
                'h' => headeronly = true,
                'R' => reset = true,
                'v' => verbose += 1,
                'e' => {
                    let rest = &flags[i + 1..];
                    let value = if rest.is_empty() {
                        args.next().unwrap_or_else(|| usage())
                    } else {
                        rest.to_owned()
                    };
                    let digits: String = value
                        .trim_start()
                        .chars()
                        .take_while(char::is_ascii_digit)
                        .collect();
                    entry = digits.parse().unwrap_or(0);
                    break;
                }
                _ => usage(),
            }
        }
    }
    let cfg = config();
    let logfile = cfg.iprop.logfile.clone();
    println!("\nKerberos update log ({})", logfile.display());
    if reset {
        let Ok(ulog) = Ulog::map(&logfile, cfg.iprop.ulogsize) else {
            die(format!("Unable to map log file {}\n\n", logfile.display()))
        };
        if ulog.init_header().is_err() {
            die(format!(
                "Couldn't reinitialize ulog file {}\n\n",
                logfile.display()
            ));
        }
        println!("Reinitialized the ulog.");
        return;
    }
    let Ok(file) = File::open(&logfile) else {
        die(format!("Unable to map log file {}\n\n", logfile.display()))
    };
    let Ok(h) = read_header(&file) else {
        die(format!("Unable to map log file {}\n\n", logfile.display()))
    };
    if h.hmagic != KDB_ULOG_HDR_MAGIC {
        die("Corrupt header log, exiting\n\n".into());
    }
    println!("Update log dump :");
    println!("\tLog version # : {}", h.db_version_num);
    match h.state {
        KDB_STABLE => println!("\tLog state : Stable"),
        KDB_UNSTABLE => println!("\tLog state : Unstable"),
        KDB_CORRUPT => println!("\tLog state : Corrupt"),
        s => println!("\tLog state : Unknown state: {s}"),
    }
    println!("\tEntry block size : {}", h.block);
    println!("\tNumber of entries : {}", h.num);
    if h.last_sno == 0 {
        println!("\tLast serial # : None");
    } else {
        if h.first_sno == 0 {
            println!("\tFirst serial # : None");
        } else {
            println!("\tFirst serial # : {}", h.first_sno);
        }
        println!("\tLast serial # : {}", h.last_sno);
    }
    if h.last_time.seconds == 0 {
        println!("\tLast time stamp : None");
    } else {
        if h.first_time.seconds == 0 {
            println!("\tFirst time stamp : None");
        } else {
            print!("\tFirst time stamp : {}", ctime(h.first_time.seconds));
        }
        println!("\tLast time stamp : {}", ctime(h.last_time.seconds));
    }
    if !headeronly && h.num != 0 {
        print_update(&file, &h, entry, cfg.iprop.ulogsize, verbose);
    }
    println!();
}
