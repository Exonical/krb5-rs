//! `kvno` (MIT krb5 1.22.2 `src/clients/kvno/kvno.c`).

#![forbid(unsafe_code)]

use std::sync::Arc;

use krb5_rs::ccache::{
    default_cache, parse_principal, resolve, unparse_name, AnyCcache, CcContext, CcCredential,
    Ccache, MemoryCcache,
};
use krb5_rs::client::{
    canonicalize_hostname, vfy::resolve_keytab, CanonHost, CredsRequest, GcOptions,
    HostCanonicalization, KerberosClient,
};
use krb5_rs::protocol::Credential;
use krb5_rs::transport::LocatedTransport;
use krb5_rs::types::{PrincipalName, Ticket};
use krb5_rs_clients::{krb5_message, progname, Getopt};

const SHOPTS: &str = "uCc:e:hk:qPS:I:U:F:";

fn xusage() -> ! {
    eprintln!(
        "usage: {} [-c ccache] [-e etype] [-k keytab] [-q] [-u | -S sname]\n\
         \t[[{{-F cert_file | {{-I | -U}} for_user}} [-P]] | --u2u ccache]\n\
         \t[--cached-only] [--no-store] [--out-cache] service1 service2 ...",
        progname()
    );
    std::process::exit(1)
}

/// `extended_com_err_fn`: "prog: message context".
fn err(msg: impl std::fmt::Display, context: &str) {
    eprintln!("{}: {msg} {context}", progname());
}

fn die(msg: impl std::fmt::Display, context: &str) -> ! {
    err(msg, context);
    std::process::exit(1)
}

#[derive(Default)]
struct Opts {
    ccache: Option<String>,
    etype: Option<String>,
    keytab: Option<String>,
    sname: Option<String>,
    cached_only: bool,
    canon: bool,
    no_store: bool,
    unknown: bool,
    quiet: bool,
    for_user: Option<String>,
    for_user_enterprise: bool,
    for_user_cert_file: Option<String>,
    proxy: bool,
    out_ccname: Option<String>,
    u2u_ccname: Option<String>,
    names: Vec<String>,
}

fn parse_options() -> Opts {
    let mut o = Opts::default();
    let mut impersonate = false;
    let mut args = Vec::new();
    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        if a == "--" {
            args.push(a);
            args.extend(it.by_ref());
            break;
        }
        let Some(long) = a.strip_prefix("--") else {
            args.push(a);
            continue;
        };
        let (name, inline) = match long.split_once('=') {
            Some((n, v)) => (n, Some(v.to_string())),
            None => (long, None),
        };
        match name {
            "cached-only" => o.cached_only = true,
            "no-store" => o.no_store = true,
            "out-cache" | "u2u" => {
                let Some(v) = inline.or_else(|| it.next()) else {
                    eprintln!("{}: option '--{name}' requires an argument", progname());
                    xusage();
                };
                if name == "u2u" {
                    o.u2u_ccname = Some(v);
                } else {
                    o.out_ccname = Some(v);
                }
            }
            _ => {
                eprintln!("{}: unrecognized option '{a}'", progname());
                xusage();
            }
        }
    }
    let mut g = Getopt::from_args(args, SHOPTS);
    for (c, arg) in g.by_ref() {
        match c {
            'C' => o.canon = true,
            'c' => o.ccache = arg,
            'e' => o.etype = arg,
            'h' => xusage(),
            'k' => o.keytab = arg,
            'q' => o.quiet = true,
            'P' => o.proxy = true,
            'S' => {
                o.sname = arg;
                if o.unknown {
                    eprintln!("Options -u and -S are mutually exclusive");
                    xusage();
                }
            }
            'u' => {
                o.unknown = true;
                if o.sname.is_some() {
                    eprintln!("Options -u and -S are mutually exclusive");
                    xusage();
                }
            }
            'I' | 'U' => {
                impersonate = true;
                o.for_user_enterprise = c == 'U';
                o.for_user = arg;
            }
            'F' => {
                impersonate = true;
                o.for_user_cert_file = arg;
            }
            _ => xusage(),
        }
    }
    if o.u2u_ccname.is_some() && impersonate {
        eprintln!("Options --u2u and -I|-U|-F are mutually exclusive");
        xusage();
    }
    if o.proxy && !impersonate {
        eprintln!(
            "Option -P (constrained delegation) requires option -I|-U|-F (protocol transition)"
        );
        xusage();
    }
    o.names = g.rest().to_vec();
    if o.names.is_empty() {
        xusage();
    }
    o
}

/// `read_pem_file`: the first certificate in a PEM file, as DER.
fn read_pem_file(path: &str) -> Result<Vec<u8>, String> {
    use base64::Engine;
    let text = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    let mut lines = text.lines().map(str::trim);
    lines
        .by_ref()
        .find(|l| l.starts_with("-----BEGIN CERTIFICATE-----"))
        .ok_or("No begin line not found")?;
    let mut b64 = String::new();
    loop {
        let l = lines.next().ok_or("No end line found")?;
        if l.starts_with("-----END ") {
            break;
        }
        if l.is_empty() || l.contains(':') {
            return Err("Unexpected header line".into());
        }
        b64.push_str(l);
    }
    base64::engine::general_purpose::STANDARD
        .decode(b64)
        .map_err(|_| "Invalid base64".into())
}

/// `krb5_parse_name_flags` with optional `KRB5_PRINCIPAL_PARSE_ENTERPRISE`.
fn parse_name(s: &str, enterprise: bool, defrealm: Option<&str>) -> Option<(PrincipalName, String)> {
    if enterprise {
        let (name, realm) = match s.rsplit_once('@') {
            Some((n, r)) if n.contains('@') => (n.to_string(), r.to_string()),
            _ => (s.to_string(), defrealm?.to_string()),
        };
        let mut p = PrincipalName::new_principal(&name);
        p.name_type = 10;
        return Some((p, realm));
    }
    parse_principal(s, defrealm)
}

/// `krb5_sname_to_principal(host, sname, KRB5_NT_SRV_HST)` (sn2princ.c).
fn sname_to_principal(
    rt: &tokio::runtime::Runtime,
    profile: &krb5_rs::profile::Profile,
    canon: &HostCanonicalization,
    host: &str,
    sname: &str,
) -> (PrincipalName, String) {
    if canon.dns_canonicalize_hostname == CanonHost::Fallback {
        return (PrincipalName::new_srv_hst(sname, host), String::new());
    }
    let use_dns = canon.dns_canonicalize_hostname == CanonHost::True;
    let h = rt.block_on(canonicalize_hostname(canon, host, use_dns));
    let realm = krb5_rs::locate::host_realm(profile, &h)
        .into_iter()
        .next()
        .unwrap_or_default();
    (PrincipalName::new_srv_hst(sname, &h), realm)
}

/// `krb5_server_decrypt_ticket_keytab` (srv_dec_tkt.c:74-131): try every
/// entry with the ticket's enctype.
fn keytab_decrypts(kt: &dyn krb5_rs::client::vfy::VerifyKeytab, ticket: &Ticket) -> Result<(), String> {
    let etype = ticket.enc_part.etype;
    let mut found = false;
    for e in kt.entries().map_err(|e| e.to_string())? {
        if e.key.keytype != etype {
            continue;
        }
        found = true;
        if krb5_rs::protocol::ap::decrypt_ticket(&e.key, ticket).is_ok() {
            return Ok(());
        }
    }
    Err(if found {
        "Decrypt integrity check failed".into()
    } else {
        "Key table entry not found".into()
    })
}

struct Ctx<'a> {
    rt: &'a tokio::runtime::Runtime,
    client: &'a KerberosClient<LocatedTransport>,
    profile: &'a krb5_rs::profile::Profile,
    canon: HostCanonicalization,
    defrealm: Option<String>,
    me: (PrincipalName, String),
    etype: i32,
    options: GcOptions,
    for_user: Option<(PrincipalName, String)>,
    user_cert: Option<Vec<u8>>,
    u2u_ticket: Option<Ticket>,
    keytab: Option<Box<dyn krb5_rs::client::vfy::VerifyKeytab>>,
}

fn kvno(o: &Opts, cx: &Ctx, ccache: &mut AnyCcache, name: &str) -> Option<Credential> {
    let server = match &o.sname {
        Some(s) => Some(sname_to_principal(cx.rt, cx.profile, &cx.canon, name, s)),
        None => parse_principal(name, cx.defrealm.as_deref()),
    };
    let Some((mut server, srealm)) = server else {
        if !o.quiet {
            err(
                "Malformed representation of principal",
                &format!("while parsing principal name {name}"),
            );
        }
        return None;
    };
    if o.unknown {
        server.name_type = 0;
    }
    let princ = unparse_name(&server, &srealm);
    let (me, mrealm) = &cx.me;
    let result = if cx.for_user.is_some() || cx.user_cert.is_some() {
        if !o.proxy && !(server.name_string == me.name_string && srealm == *mrealm) {
            err("Invalid argument", "client and server principal names must match");
            return None;
        }
        let (fu, fr) = cx
            .for_user
            .clone()
            .unwrap_or((PrincipalName::new_principal(""), String::new()));
        let mut req = CredsRequest::new(fu, fr, me.clone(), mrealm.clone());
        req.enctype = cx.etype;
        cx.rt.block_on(cx.client.get_credentials_for_user(
            ccache,
            cx.options,
            &req,
            cx.user_cert.as_deref(),
        ))
    } else {
        let mut req = CredsRequest::new(me.clone(), mrealm.clone(), server.clone(), srealm.clone());
        req.enctype = cx.etype;
        req.second_ticket = cx.u2u_ticket.clone();
        cx.rt
            .block_on(cx.client.get_credentials(ccache, cx.options, &req))
    };
    let creds = match result {
        Ok(c) => c,
        Err(e) => {
            err(krb5_message(&e), &format!("while getting credentials for {princ}"));
            return None;
        }
    };
    let kvno = creds.ticket.enc_part.kvno.unwrap_or(0);
    if let Some(kt) = cx.keytab.as_deref() {
        if let Err(e) = keytab_decrypts(kt, &creds.ticket) {
            if !o.quiet {
                eprintln!("{princ}: kvno = {kvno}, keytab entry invalid");
            }
            err(e, &format!("while decrypting ticket for {princ}"));
            return None;
        }
        if !o.quiet {
            println!("{princ}: kvno = {kvno}, keytab entry valid");
        }
    } else if !o.quiet {
        println!("{princ}: kvno = {kvno}");
    }
    if o.proxy {
        let req = CredsRequest::new(
            creds.client.clone(),
            creds.crealm.clone(),
            server,
            srealm,
        );
        return match cx.rt.block_on(cx.client.get_credentials_for_proxy(
            ccache,
            GcOptions::CANONICALIZE,
            &req,
            &creds,
        )) {
            Ok(c) => Some(c),
            Err(e) => {
                err(krb5_message(&e), &format!("{princ}: constrained delegation failed"));
                None
            }
        };
    }
    Some(creds)
}

/// `get_u2u_ticket`: the local TGT of `ccname`'s client.
fn get_u2u_ticket(ctx: &CcContext, ccname: &str) -> Result<Ticket, String> {
    let cc = resolve(ctx, ccname).map_err(|e| e.to_string())?;
    let (_, r) = cc.principal().map_err(|e| e.to_string())?;
    let c = cc
        .creds()
        .map_err(|e| e.to_string())?
        .into_iter()
        .find(|c| {
            c.server.name_string.len() == 2
                && c.server.name_string[0].as_bytes() == b"krbtgt"
                && c.server.name_string[1].as_bytes() == r.as_bytes()
                && c.srealm == r
        })
        .ok_or("Matching credential not found")?;
    Credential::try_from(&c)
        .map(|c| c.ticket)
        .map_err(|e| e.to_string())
}

fn main() {
    let o = parse_options();
    let mut options = GcOptions::empty();
    if o.canon {
        options |= GcOptions::CANONICALIZE;
    }
    if o.cached_only {
        options |= GcOptions::CACHED;
    }
    if o.no_store || o.out_ccname.is_some() {
        options |= GcOptions::NO_STORE;
    }
    let profile = Arc::new(krb5_rs_clients::profile());
    let ctx = CcContext::from_env(Some(&profile));
    let etype = match &o.etype {
        Some(s) => krb5_rs::crypto::enctype_from_name(s).unwrap_or_else(|| {
            die("Invalid encryption type", "while converting etype")
        }),
        None => 0,
    };
    let mut ccache = match &o.ccache {
        Some(n) => resolve(&ctx, n),
        None => default_cache(&ctx),
    }
    .unwrap_or_else(|e| die(e, "while opening ccache"));
    let mut out_ccache = o.out_ccname.as_ref().map(|n| {
        resolve(&ctx, n).unwrap_or_else(|e| die(e, "while resolving output ccache"))
    });
    let keytab = o.keytab.as_ref().map(|n| {
        resolve_keytab(n).unwrap_or_else(|e| die(e, &format!("resolving keytab {n}")))
    });
    let defrealm = krb5_rs::locate::default_realm(&profile);
    let for_user = o.for_user.as_ref().map(|u| {
        parse_name(u, o.for_user_enterprise, defrealm.as_deref()).unwrap_or_else(|| {
            die(
                "Malformed representation of principal",
                &format!("while parsing principal name {u}"),
            )
        })
    });
    let user_cert = o.for_user_cert_file.as_ref().map(|f| {
        read_pem_file(f)
            .unwrap_or_else(|e| die(e, &format!("while reading certificate file {f}")))
    });
    let u2u_ticket = o.u2u_ccname.as_ref().map(|n| {
        get_u2u_ticket(&ctx, n).unwrap_or_else(|e| {
            die(e, &format!("while getting user-to-user ticket from {n}"))
        })
    });
    if u2u_ticket.is_some() {
        options |= GcOptions::USER_USER;
    }
    let me = ccache
        .principal()
        .unwrap_or_else(|e| die(e, "while getting client principal name"));
    let rt = krb5_rs_clients::runtime();
    let client = krb5_rs_clients::kerberos_client(&profile, &me.1);
    let cx = Ctx {
        rt: &rt,
        client: &client,
        profile: &profile,
        canon: HostCanonicalization::from_profile(&profile),
        defrealm,
        me,
        etype,
        options,
        for_user,
        user_cert,
        u2u_ticket,
        keytab,
    };
    let mut mcc = out_ccache.as_ref().map(|_| MemoryCcache::new());
    let mut initialized = false;
    let mut errors = 0;
    for name in &o.names {
        let Some(creds) = kvno(&o, &cx, &mut ccache, name) else {
            errors += 1;
            continue;
        };
        if let Some(m) = mcc.as_mut() {
            if !initialized {
                m.initialize(&creds.client, &creds.crealm)
                    .unwrap_or_else(|e| die(e, "while initializing output ccache"));
                initialized = true;
            }
            m.store(&CcCredential::from(&creds))
                .unwrap_or_else(|e| die(e, "while storing creds in output ccache"));
        }
    }
    if errors == 0 {
        if let (Some(m), Some(out)) = (mcc.as_ref(), out_ccache.as_mut()) {
            // krb5_cc_move.
            let moved = m.principal().and_then(|(p, r)| {
                out.initialize(&p, &r)?;
                m.creds()?.iter().try_for_each(|c| out.store(c))
            });
            if let Err(e) = moved {
                die(e, "while writing output ccache");
            }
        }
    }
    std::process::exit(i32::from(errors > 0));
}
