//! MIT `klist` (src/clients/klist/klist.c).

#![forbid(unsafe_code)]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use krb5_rs::ccache::{
    collection, default_cache, is_config_principal, unparse_name, AnyCcache, CcContext,
    CcCredential, Ccache,
};
use krb5_rs::types::{HostAddress, Ticket};
use krb5_rs_clients::{com_err, etype_string, fail, now, printtime, profile, progname, Getopt};

#[derive(PartialEq)]
enum Mode {
    Default,
    Ccache,
    Keytab,
}

#[derive(Default)]
struct Opts {
    show_flags: bool,
    show_time: bool,
    status_only: bool,
    show_keys: bool,
    show_etype: bool,
    show_addresses: bool,
    no_resolve: bool,
    show_adtype: bool,
    show_config: bool,
    use_client_keytab: bool,
    list_all: bool,
    show_all: bool,
    width: usize,
    now: u32,
}

fn usage() -> ! {
    eprintln!(
        "Usage: {} [-e] [-V] [[-c] [-l] [-A] [-d] [-f] [-s] [-a [-n]]] [-k [-i] [-t] [-K]] [-C] [name]",
        progname()
    );
    for l in [
        "\t-c specifies credentials cache",
        "\t-k specifies keytab",
        "\t   (Default is credentials cache)",
        "\t-i uses default client keytab if no name given",
        "\t-l lists credential caches in collection",
        "\t-A shows content of all credential caches",
        "\t-e shows the encryption type",
        "\t-V shows the Kerberos version and exits",
        "\toptions for credential caches:",
        "\t\t-d shows the submitted authorization data types",
        "\t\t-f shows credentials flags",
        "\t\t-s sets exit status based on valid tgt existence",
        "\t\t-a displays the address list",
        "\t\t\t-n do not reverse-resolve",
        "\toptions for keytabs:",
        "\t\t-t shows keytab entry timestamps",
        "\t\t-K shows keytab entry keys",
        "\t\t-C includes configuration data entries",
    ] {
        eprintln!("{l}");
    }
    std::process::exit(1)
}

fn main() {
    let mut o = Opts::default();
    let mut mode = Mode::Default;
    let mut print_version = false;
    let mut g = Getopt::new("dfetKsnacki45lAVC");
    for (c, _) in g.by_ref() {
        match c {
            'd' => o.show_adtype = true,
            'f' => o.show_flags = true,
            'e' => o.show_etype = true,
            't' => o.show_time = true,
            'K' => o.show_keys = true,
            's' => o.status_only = true,
            'n' => o.no_resolve = true,
            'a' => o.show_addresses = true,
            'c' | 'k' => {
                if mode != Mode::Default {
                    usage();
                }
                mode = if c == 'c' { Mode::Ccache } else { Mode::Keytab };
            }
            'i' => o.use_client_keytab = true,
            '4' => {
                eprintln!("Kerberos 4 is no longer supported");
                std::process::exit(3);
            }
            '5' => {}
            'l' => o.list_all = true,
            'A' => o.show_all = true,
            'C' => o.show_config = true,
            'V' => print_version = true,
            _ => usage(),
        }
    }
    if o.no_resolve && !o.show_addresses {
        usage();
    }
    if mode != Mode::Keytab {
        if o.show_time || o.show_keys {
            usage();
        }
        if (o.show_all && o.list_all) || (o.status_only && o.list_all) {
            usage();
        }
    } else if o.show_flags || o.status_only || o.show_addresses || o.show_all || o.list_all {
        usage();
    }
    let rest = g.rest().to_vec();
    if rest.len() > 1 {
        eprintln!("Extra arguments (starting with \"{}\").", rest[1]);
        usage();
    }
    if print_version {
        println!("krb5-rs version {}", env!("CARGO_PKG_VERSION"));
        std::process::exit(0);
    }
    let name = rest.into_iter().next();
    o.now = now();
    o.width = krb5_rs_clients::timestamp_width(o.now);
    let profile = profile();
    let mut ctx = CcContext::from_env(Some(&profile));
    if mode != Mode::Keytab && name.is_some() {
        ctx.default_name = name.clone();
    }
    let status = if o.list_all {
        list_all_ccaches(&o, &ctx)
    } else if o.show_all {
        show_all_ccaches(&o, &ctx)
    } else if mode != Mode::Keytab {
        match default_cache(&ctx) {
            Ok(c) if o.status_only => check_ccache(&o, &c),
            Ok(c) => show_ccache(&o, &c),
            Err(e) => {
                if !o.status_only {
                    com_err(e, "while resolving ccache");
                }
                1
            }
        }
    } else {
        do_keytab(&o, &profile, name.as_deref())
    };
    std::process::exit(status);
}

/// The keytab's full name (`krb5_kt_get_name`).
fn keytab_full_name(name: &str) -> String {
    match name.split_once(':') {
        Some((t, _)) if t.len() > 1 && !t.contains('/') => name.to_string(),
        _ => format!("FILE:{name}"),
    }
}

fn do_keytab(o: &Opts, profile: &krb5_rs::profile::Profile, name: Option<&str>) -> i32 {
    let ktname = match name {
        None if o.use_client_keytab => krb5_rs::client::default_client_keytab_name(Some(profile))
            .unwrap_or_else(|e| fail(e, "while getting default client keytab", 1)),
        None => krb5_rs::ccache::expand_path_tokens(&krb5_rs::client::vfy::default_keytab_name(
            Some(profile),
        ))
        .unwrap_or_else(|e| fail(e, "while getting default keytab", 1)),
        Some(n) => n.to_string(),
    };
    let kt = krb5_rs::client::vfy::resolve_keytab(&ktname).unwrap_or_else(|e| {
        let ctx = match name {
            Some(n) => format!("while resolving keytab {n}"),
            None if o.use_client_keytab => "while getting default client keytab".into(),
            None => "while getting default keytab".into(),
        };
        fail(e, &ctx, 1)
    });
    println!("Keytab name: {}", keytab_full_name(&ktname));
    let entries = kt
        .entries()
        .unwrap_or_else(|e| fail(e, "while starting keytab scan", 1));
    if o.show_time {
        print!("KVNO Timestamp");
        print!("{}", " ".repeat((o.width + 2).saturating_sub(9)));
        println!("Principal");
        print!("---- ");
        print!("{} ", "-".repeat(o.width));
        println!("{}", "-".repeat(78usize.saturating_sub(o.width + 5)));
    } else {
        println!("KVNO Principal");
        println!("---- --------------------------------------------------------------------------");
    }
    for e in entries {
        let mut line = format!("{:4} ", e.kvno);
        if o.show_time {
            line.push_str(&printtime(e.timestamp, o.width));
            line.push(' ');
        }
        line.push_str(&unparse_name(&e.principal, &e.realm));
        if o.show_etype {
            line.push_str(&format!(" ({}) ", etype_string(e.key.keytype)));
        }
        if o.show_keys {
            line.push_str(" (0x");
            for b in e.key.key_bytes() {
                line.push_str(&format!("{b:02x}"));
            }
            line.push(')');
        }
        println!("{line}");
    }
    0
}

fn list_all_ccaches(o: &Opts, ctx: &CcContext) -> i32 {
    let caches = match collection(ctx) {
        Ok(c) => c,
        Err(e) => {
            if !o.status_only {
                com_err(e, "while listing ccache collection");
            }
            return 1;
        }
    };
    println!("{:<30} Cache name", "Principal name");
    println!("{:<30} ----------", "--------------");
    let mut status = 1;
    for c in caches {
        let Ok((p, r)) = c.principal() else {
            continue;
        };
        let princ: String = unparse_name(&p, &r).chars().take(30).collect();
        let expired = check_ccache(o, &c) != 0;
        println!(
            "{princ:<30} {}{}",
            c.name(),
            if expired { " (Expired)" } else { "" }
        );
        status = 0;
    }
    status
}

fn show_all_ccaches(o: &Opts, ctx: &CcContext) -> i32 {
    let caches = match collection(ctx) {
        Ok(c) => c,
        Err(e) => {
            if !o.status_only {
                com_err(e, "while listing ccache collection");
            }
            return 1;
        }
    };
    let mut status = 1;
    for (i, c) in caches.iter().enumerate() {
        if !o.status_only && i > 0 {
            println!();
        }
        let st = if o.status_only {
            check_ccache(o, c)
        } else {
            show_ccache(o, c)
        };
        if st == 0 {
            status = 0;
        }
    }
    status
}

fn is_local_tgt(c: &CcCredential, realm: &str) -> bool {
    c.server.name_string.len() == 2
        && c.srealm == realm
        && c.server.name_string[0].as_bytes() == b"krbtgt"
        && c.server.name_string[1].as_bytes() == realm.as_bytes()
}

fn check_ccache(o: &Opts, cache: &AnyCcache) -> i32 {
    let Ok((_, realm)) = cache.principal() else {
        return 1;
    };
    let Ok(creds) = cache.creds() else {
        return 1;
    };
    let (mut found_tgt, mut current_tgt, mut current_cred) = (false, false, false);
    for c in &creds {
        if is_local_tgt(c, &realm) {
            found_tgt = true;
            if c.endtime > o.now {
                current_tgt = true;
            }
        } else if !is_config_principal(&c.server, &c.srealm) && c.endtime > o.now {
            current_cred = true;
        }
    }
    let ok = if found_tgt { current_tgt } else { current_cred };
    i32::from(!ok)
}

/// `krb5_cc_get_type`, `krb5_cc_get_name`.
fn type_and_name(cache: &AnyCcache) -> String {
    let full = cache.name();
    let (t, r) = krb5_rs::ccache::split_name(&full);
    format!("{t}:{r}")
}

fn show_ccache(o: &Opts, cache: &AnyCcache) -> i32 {
    let (p, r) = match cache.principal() {
        Ok(v) => v,
        Err(e) => {
            com_err(e, "");
            return 1;
        }
    };
    let defname = unparse_name(&p, &r);
    println!(
        "Ticket cache: {}\nDefault principal: {defname}\n",
        type_and_name(cache)
    );
    let pad = |s: &str| " ".repeat((o.width + 3).saturating_sub(s.len() + 1));
    println!(
        "Valid starting{}Expires{}Service principal",
        pad("Valid starting"),
        pad("Expires")
    );
    let creds = match cache.creds() {
        Ok(c) => c,
        Err(e) => {
            com_err(e, "while retrieving a ticket");
            return 1;
        }
    };
    for c in &creds {
        if o.show_config || !is_config_principal(&c.server, &c.srealm) {
            show_credential(o, c, &defname);
        }
    }
    0
}

/// klist.c `flags_string`.
fn flags_string(f: u32) -> String {
    const FLAGS: [(u32, char); 14] = [
        (0x4000_0000, 'F'),
        (0x2000_0000, 'f'),
        (0x1000_0000, 'P'),
        (0x0800_0000, 'p'),
        (0x0400_0000, 'D'),
        (0x0200_0000, 'd'),
        (0x0100_0000, 'i'),
        (0x0080_0000, 'R'),
        (0x0040_0000, 'I'),
        (0x0010_0000, 'H'),
        (0x0020_0000, 'A'),
        (0x0008_0000, 'T'),
        (0x0004_0000, 'O'),
        (0x0002_0000, 'a'),
    ];
    FLAGS
        .iter()
        .filter(|(b, _)| f & b != 0)
        .map(|(_, c)| *c)
        .collect()
}

/// klist.c `print_config_data`.
fn config_data(mut col: usize, data: &[u8]) -> String {
    let mut out = String::new();
    for &b in data {
        while col < 8 {
            out.push(' ');
            col += 1;
        }
        if b > 0x20 && b < 0x7f {
            out.push(b as char);
            col += 1;
        } else {
            let s = format!("\\{b:03o}");
            col += s.len();
            out.push_str(&s);
        }
        if col > 72 {
            out.push('\n');
            col = 0;
        }
    }
    if col > 0 {
        out.push('\n');
    }
    out
}

/// klist.c `one_addr`.
fn one_addr(a: &HostAddress, no_resolve: bool) -> String {
    let ip = match (a.addr_type, a.address.len()) {
        (2, 4) => {
            let b: [u8; 4] = a.address[..].try_into().unwrap_or_default();
            IpAddr::V4(Ipv4Addr::from(b))
        }
        (24, 16) => {
            let b: [u8; 16] = a.address[..].try_into().unwrap_or_default();
            IpAddr::V6(Ipv6Addr::from(b))
        }
        (2 | 24, len) => {
            return format!("broken address (type {} length {len})", a.addr_type);
        }
        (t, _) => return format!("unknown addrtype {t}"),
    };
    if no_resolve {
        return ip.to_string();
    }
    dns_lookup::lookup_addr(&ip).unwrap_or_else(|_| ip.to_string())
}

fn show_credential(o: &Opts, cred: &CcCredential, defname: &str) {
    let is_config = is_config_principal(&cred.server, &cred.srealm);
    let name = unparse_name(&cred.client, &cred.crealm);
    let sname = unparse_name(&cred.server, &cred.srealm);
    let tkt = if is_config {
        None
    } else {
        rasn::der::decode::<Ticket>(&cred.ticket).ok()
    };
    let starttime = if cred.starttime == 0 {
        cred.authtime
    } else {
        cred.starttime
    };
    let mut out = String::new();
    let mut ccol = 0;
    let mut extra = 0;
    if !is_config {
        out.push_str(&format!(
            "{}  {}  {sname}\n",
            printtime(starttime, o.width),
            printtime(cred.endtime, o.width)
        ));
    } else {
        out.push_str("config: ");
        ccol = 8;
        for (i, c) in cred.server.name_string.iter().enumerate().skip(1) {
            let s = String::from_utf8_lossy(c.as_bytes());
            let s = if i > 1 {
                format!("({s})")
            } else {
                s.into_owned()
            };
            ccol += s.len();
            out.push_str(&s);
        }
        out.push_str(" = ");
        ccol += 3;
    }
    if name != defname {
        out.push_str(&format!("\tfor client {name}"));
        extra += 1;
    }
    if is_config {
        out.push_str(&config_data(ccol, &cred.ticket));
    }
    let sep = |extra: i32| if extra == 0 { "\t" } else { ", " };
    if cred.renew_till != 0 {
        out.push_str(sep(extra));
        out.push_str("renew until ");
        out.push_str(&printtime(cred.renew_till, o.width));
        extra += 2;
    }
    if o.show_flags {
        let flags = flags_string(cred.ticket_flags);
        if !flags.is_empty() {
            out.push_str(sep(extra));
            out.push_str(&format!("Flags: {flags}"));
            extra += 1;
        }
    }
    if extra > 2 {
        out.push('\n');
        extra = 0;
    }
    if let (true, Some(t)) = (o.show_etype, &tkt) {
        out.push_str(sep(extra));
        out.push_str(&format!(
            "Etype (skey, tkt): {}, {} ",
            etype_string(cred.keyblock.keytype),
            etype_string(t.enc_part.etype)
        ));
        extra += 1;
    }
    if o.show_adtype && !cred.authdata.is_empty() {
        out.push_str(sep(extra));
        let types: Vec<String> = cred
            .authdata
            .iter()
            .map(|a| a.ad_type.to_string())
            .collect();
        out.push_str(&format!("AD types: {}", types.join(", ")));
        extra += 1;
    }
    if extra > 0 {
        out.push('\n');
    }
    if o.show_addresses {
        if cred.addresses.is_empty() {
            out.push_str("\tAddresses: (none)\n");
        } else {
            let a: Vec<String> = cred
                .addresses
                .iter()
                .map(|a| one_addr(a, o.no_resolve))
                .collect();
            out.push_str(&format!("\tAddresses: {}\n", a.join(", ")));
        }
    }
    if let Some(t) = &tkt {
        let same = t.realm.as_bytes() == cred.srealm.as_bytes()
            && t.sname.name_string.len() == cred.server.name_string.len()
            && t.sname
                .name_string
                .iter()
                .zip(&cred.server.name_string)
                .all(|(a, b)| a.as_bytes() == b.as_bytes());
        if !same {
            let realm = String::from_utf8_lossy(t.realm.as_bytes());
            out.push_str(&format!(
                "\tTicket server: {}\n",
                unparse_name(&t.sname, &realm)
            ));
        }
    }
    print!("{out}");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_like_mit() {
        assert_eq!(flags_string(0x40e1_0000), "FRIA");
        assert_eq!(flags_string(0), "");
    }

    #[test]
    fn config_data_escapes_and_wraps() {
        assert_eq!(config_data(10, b"ab\x01"), "ab\\001\n");
        assert_eq!(config_data(0, b"x"), "        x\n");
    }
}
