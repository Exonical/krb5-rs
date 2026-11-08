//! `kinit` (MIT krb5 1.22.2 `src/clients/kinit/kinit.c`).

#![forbid(unsafe_code)]

use std::sync::Arc;
use std::time::Duration;

use krb5_rs::ccache::{
    cache_match, default_cache, new_unique, parse_principal, resolve, unparse_name, AnyCcache,
    CcContext, CcCredential, CcError, Ccache, MemoryCcache,
};
use krb5_rs::client::{default_client_keytab_name, vfy::resolve_keytab, KerberosClient};
use krb5_rs::profile::{string_to_deltat, Profile};
use krb5_rs::protocol::{AsExchangeConfig, Credential, FastMode};
use krb5_rs::types::{KdcOptions, KerberosFlags, PrincipalName};
use krb5_rs::Krb5Error;
use krb5_rs_clients::{
    com_err, krb5_message, libdefault_boolean, libdefault_string, local_fqdn, progname,
    string_to_timestamp, Getopt,
};

const SHOPTS: &str = "r:fpFPn54aAVl:s:c:kit:T:RS:vX:CEI:";

#[derive(PartialEq, Clone, Copy)]
enum Action {
    InitPw,
    InitKt,
    Renew,
    Validate,
}

struct Opts {
    verbose: bool,
    lifetime: i32,
    rlife: i32,
    starttime: i32,
    forwardable: bool,
    not_forwardable: bool,
    proxiable: bool,
    not_proxiable: bool,
    request_pac: bool,
    not_request_pac: bool,
    anonymous: bool,
    addresses: bool,
    no_addresses: bool,
    canonicalize: bool,
    enterprise: bool,
    use_client_keytab: bool,
    keytab_name: Option<String>,
    armor_ccache: Option<String>,
    out_cache: Option<String>,
    in_cache: Option<String>,
    service_name: Option<String>,
    pa_opts: Vec<(String, String)>,
    action: Action,
    principal_name: Option<String>,
}

fn usage() -> ! {
    let p = progname();
    eprint!(
        "Usage: {p} [-V] [-l lifetime] [-s start_time] [-r renewable_life]\n\
         \t[-f | -F] [-p | -P] [-n] [-a | -A] [-C] [-E]\n\
         \t[--request-pac | --no-request-pac]\n\
         \t[-v] [-R] [-k [-i|-t keytab_file]] [-c cachename]\n\
         \t[-S service_name] [-I input_ccache] [-T ticket_armor_cache]\n\
         \t[-X <attribute>[=<value>]] [principal]\n\n"
    );
    eprintln!("    options:");
    for l in [
        "\t-V verbose",
        "\t-l lifetime",
        "\t-s start time",
        "\t-r renewable lifetime",
        "\t-f forwardable",
        "\t-F not forwardable",
        "\t-p proxiable",
        "\t-P not proxiable",
        "\t-n anonymous",
        "\t-a include addresses",
        "\t-A do not include addresses",
        "\t-v validate",
        "\t-R renew",
        "\t-C canonicalize",
        "\t-E client is enterprise principal name",
        "\t-k use keytab",
        "\t-i use default client keytab (with -k)",
        "\t-t filename of keytab to use",
        "\t-c Kerberos 5 cache name",
        "\t-S service",
        "\t-I input credential cache",
        "\t-T armor credential cache",
        "\t-X <attribute>[=<value>]",
    ] {
        eprintln!("{l}");
    }
    std::process::exit(2)
}

/// The getopt_long table (kinit.c:178-194): long names become their short
/// options, and the PAC flags are set directly.
fn long_options(args: Vec<String>, o: &mut Opts, errflg: &mut u32) -> Vec<String> {
    let mut out = Vec::new();
    let mut it = args.into_iter();
    while let Some(a) = it.next() {
        if a == "--" {
            out.push(a);
            out.extend(it);
            break;
        }
        let Some(name) = a.strip_prefix("--") else {
            out.push(a);
            continue;
        };
        let short = match name {
            "noforwardable" => "-F",
            "noproxiable" => "-P",
            "addresses" => "-a",
            "forwardable" => "-f",
            "proxiable" => "-p",
            "noaddresses" => "-A",
            "canonicalize" => "-C",
            "enterprise" => "-E",
            "request-pac" => {
                o.request_pac = true;
                continue;
            }
            "no-request-pac" => {
                o.not_request_pac = true;
                continue;
            }
            _ => {
                eprintln!("{}: unrecognized option '{a}'", progname());
                *errflg += 1;
                continue;
            }
        };
        out.push(short.into());
    }
    out
}

fn parse_options() -> Opts {
    let mut o = Opts {
        verbose: false,
        lifetime: 0,
        rlife: 0,
        starttime: 0,
        forwardable: false,
        not_forwardable: false,
        proxiable: false,
        not_proxiable: false,
        request_pac: false,
        not_request_pac: false,
        anonymous: false,
        addresses: false,
        no_addresses: false,
        canonicalize: false,
        enterprise: false,
        use_client_keytab: false,
        keytab_name: None,
        armor_ccache: None,
        out_cache: None,
        in_cache: None,
        service_name: None,
        pa_opts: Vec::new(),
        action: Action::InitPw,
        principal_name: None,
    };
    let mut errflg = 0u32;
    let args = long_options(std::env::args().skip(1).collect(), &mut o, &mut errflg);
    let mut g = Getopt::from_args(args, SHOPTS);
    for (c, arg) in g.by_ref() {
        let arg = arg.unwrap_or_default();
        match c {
            'V' => o.verbose = true,
            'l' | 'r' => match string_to_deltat(&arg) {
                Ok(v) if v != 0 => {
                    if c == 'l' {
                        o.lifetime = v;
                    } else {
                        o.rlife = v;
                    }
                }
                _ => {
                    eprintln!("Bad lifetime value {arg}");
                    errflg += 1;
                }
            },
            'f' => o.forwardable = true,
            'F' => o.not_forwardable = true,
            'p' => o.proxiable = true,
            'P' => o.not_proxiable = true,
            'n' => o.anonymous = true,
            'a' => o.addresses = true,
            'A' => o.no_addresses = true,
            's' => match string_to_deltat(&arg) {
                Ok(v) if v != 0 => o.starttime = v,
                _ => {
                    // An absolute time; undocumented but kept (kinit.c:296-307).
                    match string_to_timestamp(&arg).filter(|&t| t != 0) {
                        Some(t) => {
                            o.starttime =
                                i32::try_from(t - i64::from(krb5_rs_clients::now())).unwrap_or(0)
                        }
                        None => {
                            eprintln!("Bad start time value {arg}");
                            errflg += 1;
                        }
                    }
                }
            },
            'S' => o.service_name = Some(arg),
            'k' => o.action = Action::InitKt,
            'i' => o.use_client_keytab = true,
            't' => {
                if o.keytab_name.is_some() {
                    eprintln!("Only one -t option allowed.");
                    errflg += 1;
                } else {
                    o.keytab_name = Some(arg);
                }
            }
            'T' => {
                if o.armor_ccache.is_some() {
                    eprintln!("Only one armor_ccache");
                    errflg += 1;
                } else {
                    o.armor_ccache = Some(arg);
                }
            }
            'R' => o.action = Action::Renew,
            'v' => o.action = Action::Validate,
            'c' => {
                if o.out_cache.is_some() {
                    eprintln!("Only one -c option allowed");
                    errflg += 1;
                } else {
                    o.out_cache = Some(arg);
                }
            }
            'I' => {
                if o.in_cache.is_some() {
                    eprintln!("Only one -I option allowed");
                    errflg += 1;
                } else {
                    o.in_cache = Some(arg);
                }
            }
            'X' => {
                let (k, v) = match arg.split_once('=') {
                    Some((k, v)) => (k.to_string(), v.to_string()),
                    None => (arg, "yes".to_string()),
                };
                o.pa_opts.push((k, v));
            }
            'C' => o.canonicalize = true,
            'E' => o.enterprise = true,
            '4' => {
                eprintln!("Kerberos 4 is no longer supported");
                std::process::exit(3);
            }
            '5' => {}
            _ => errflg += 1,
        }
    }
    if o.forwardable && o.not_forwardable {
        eprintln!("Only one of -f and -F allowed");
        errflg += 1;
    }
    if o.proxiable && o.not_proxiable {
        eprintln!("Only one of -p and -P allowed");
        errflg += 1;
    }
    if o.request_pac && o.not_request_pac {
        eprintln!("Only one of --request-pac and --no-request-pac allowed");
        errflg += 1;
    }
    if o.addresses && o.no_addresses {
        eprintln!("Only one of -a and -A allowed");
        errflg += 1;
    }
    if o.keytab_name.is_some() && o.use_client_keytab {
        eprintln!("Only one of -t and -i allowed");
        errflg += 1;
    }
    if (o.keytab_name.is_some() || o.use_client_keytab) && o.action != Action::InitKt {
        o.action = Action::InitKt;
        eprintln!("keytab specified, forcing -k");
    }
    let rest = g.rest();
    if rest.len() > 1 {
        eprintln!("Extra arguments (starting with \"{}\").", rest[1]);
        errflg += 1;
    }
    if errflg > 0 {
        usage();
    }
    o.principal_name = rest.first().cloned();
    o
}

struct K5 {
    ctx: CcContext,
    profile: Arc<Profile>,
    out_cc: AnyCcache,
    in_cc: Option<AnyCcache>,
    me: PrincipalName,
    realm: String,
    name: String,
    switch_to_cache: bool,
}

/// Cache types with a collection and a primary cache
/// (`krb5_cc_support_switch`).
fn support_switch(ty: &str) -> bool {
    matches!(ty, "DIR" | "KEYRING" | "KCM" | "API")
}

fn cache_type(c: &AnyCcache) -> &'static str {
    match c {
        AnyCcache::File(_) => "FILE",
        AnyCcache::Memory(..) => "MEMORY",
        AnyCcache::Dir(_) => "DIR",
        #[cfg(target_os = "linux")]
        AnyCcache::Keyring(_) => "KEYRING",
        #[cfg(unix)]
        AnyCcache::Kcm(_) => "KCM",
    }
}

/// `krb5_parse_name_flags`, with `KRB5_PRINCIPAL_PARSE_ENTERPRISE` for -E.
fn parse_name(
    s: &str,
    enterprise: bool,
    defrealm: Option<&str>,
) -> Option<(PrincipalName, String)> {
    if enterprise {
        // The whole string (with any unescaped '@' kept) is one component,
        // in the default realm unless a trailing realm follows a second '@'.
        let (name, realm) = match s.rsplit_once('@') {
            Some((n, r)) if n.contains('@') => (n.to_string(), r.to_string()),
            _ => (s.to_string(), defrealm?.to_string()),
        };
        let mut p = PrincipalName::new_principal(&name);
        p.name_type = 10; // KRB5_NT_ENTERPRISE_PRINCIPAL
        return Some((p, realm));
    }
    parse_principal(s, defrealm)
}

fn os_user() -> Option<String> {
    ["USER", "LOGNAME", "USERNAME"]
        .iter()
        .find_map(|v| std::env::var(v).ok().filter(|u| !u.is_empty()))
}

fn k5_begin(o: &mut Opts) -> Option<K5> {
    let profile = Arc::new(krb5_rs_clients::profile());
    let ctx = CcContext::from_env(Some(&profile));
    let defrealm = krb5_rs::locate::default_realm(&profile);
    let mut out_cc = None;
    let mut defcache = None;
    let mut defcache_princ = None;
    let mut deftype = "";
    if let Some(n) = &o.out_cache {
        match resolve(&ctx, n) {
            Ok(c) => out_cc = Some(c),
            Err(e) => {
                com_err(e, &format!("resolving ccache {n}"));
                return None;
            }
        }
        if o.verbose {
            eprintln!("Using specified cache: {n}");
        }
    } else {
        match default_cache(&ctx) {
            Ok(c) => {
                deftype = cache_type(&c);
                defcache_princ = c.principal().ok();
                defcache = Some(c);
            }
            Err(e) => {
                com_err(e, "while getting default ccache");
                return None;
            }
        }
    }

    let mut me: Option<(PrincipalName, String)> = None;
    if let Some(n) = &o.principal_name {
        match parse_name(n, o.enterprise, defrealm.as_deref()) {
            Some(p) => me = Some(p),
            None => {
                com_err(
                    "Malformed representation of principal",
                    &format!("when parsing name {n}"),
                );
                return None;
            }
        }
    } else if o.anonymous {
        let Some(r) = defrealm.clone() else {
            com_err("Cannot find default realm", "while getting default realm");
            return None;
        };
        let mut p = PrincipalName::new_srv_inst("WELLKNOWN", "ANONYMOUS");
        p.name_type = 11; // KRB5_NT_WELLKNOWN
        me = Some((p, r));
    } else if o.action == Action::InitKt && o.use_client_keytab {
        let kt = default_client_keytab_name(Some(&profile))
            .and_then(|n| resolve_keytab(&n))
            .map_err(|e| com_err(e, "When resolving the default client keytab"))
            .ok()?;
        match kt.entries().ok().and_then(|e| e.into_iter().next()) {
            Some(e) => me = Some((e.principal, e.realm)),
            None => {
                com_err(
                    "Key table file not found or empty",
                    "When determining client principal name from keytab",
                );
                return None;
            }
        }
    } else if o.action == Action::InitKt {
        let Some(host) = local_fqdn() else {
            com_err(
                "Hostname cannot be canonicalized",
                "when creating default server principal name",
            );
            return None;
        };
        let realm = krb5_rs::locate::host_realm(&profile, &host)
            .into_iter()
            .next()
            .or_else(|| defrealm.clone())
            .unwrap_or_default();
        me = Some((PrincipalName::new_srv_inst("host", &host), realm));
    } else if let Some(c) = &out_cc {
        me = c.principal().ok();
    } else if let Some(p) = defcache_princ.clone() {
        out_cc = defcache.take();
        me = Some(p);
    }
    let (me, realm) = match me {
        Some(m) => m,
        None => {
            let Some(name) = os_user() else {
                eprintln!("Unable to identify user");
                return None;
            };
            match parse_name(&name, o.enterprise, defrealm.as_deref()) {
                Some(p) => p,
                None => {
                    com_err(
                        "Malformed representation of principal",
                        &format!("when parsing name {name}"),
                    );
                    return None;
                }
            }
        }
    };

    let mut switch_to_cache = false;
    if out_cc.is_none() && support_switch(deftype) {
        match cache_match(&ctx, &me, &realm) {
            Ok(c) => {
                if o.verbose {
                    eprintln!("Using existing cache: {}", c.name());
                }
                out_cc = Some(c);
                switch_to_cache = true;
            }
            Err(e) if !matches!(&e, CcError::Code { name, .. } if *name == "KRB5_CC_NOTFOUND") => {
                com_err(
                    e,
                    &format!(
                        "while searching for ccache for {}",
                        o.principal_name.as_deref().unwrap_or("(null)")
                    ),
                );
                return None;
            }
            Err(_) if defcache_princ.is_some() => match new_unique(&ctx, deftype) {
                Ok(c) => {
                    if o.verbose {
                        eprintln!("Using new cache: {}", c.name());
                    }
                    out_cc = Some(c);
                    switch_to_cache = true;
                }
                Err(e) => {
                    com_err(e, "while generating new ccache");
                    return None;
                }
            },
            Err(_) => {}
        }
    }
    let out_cc = match out_cc {
        Some(c) => c,
        None => {
            let c = defcache.take()?;
            if o.verbose {
                eprintln!("Using default cache: {}", c.name());
            }
            c
        }
    };
    let mut in_cc = None;
    if let Some(n) = &o.in_cache {
        match resolve(&ctx, n) {
            Ok(c) => in_cc = Some(c),
            Err(e) => {
                com_err(e, &format!("resolving ccache {n}"));
                return None;
            }
        }
        if o.verbose {
            eprintln!("Using specified input cache: {n}");
        }
    }
    let name = unparse_name(&me, &realm);
    if o.verbose {
        eprintln!("Using principal: {name}");
    }
    o.principal_name = Some(name.clone());
    Some(K5 {
        ctx,
        profile,
        out_cc,
        in_cc,
        me,
        realm,
        name,
        switch_to_cache,
    })
}

/// Local addresses for `-a` (`krb5_os_localaddr`).
fn local_addresses() -> Vec<krb5_rs::types::HostAddress> {
    let mut out = Vec::new();
    let Ok(host) = dns_lookup::get_hostname() else {
        return out;
    };
    let Ok(it) = dns_lookup::getaddrinfo(Some(&host), None, None) else {
        return out;
    };
    for a in it.flatten() {
        let (ty, bytes) = match a.sockaddr.ip() {
            std::net::IpAddr::V4(v) => (2, v.octets().to_vec()),
            std::net::IpAddr::V6(v) => (24, v.octets().to_vec()),
        };
        let ha = krb5_rs::types::HostAddress {
            addr_type: ty,
            address: bytes.into(),
        };
        if !out.contains(&ha) {
            out.push(ha);
        }
    }
    out
}

/// `pkinit_libdefault_strings` (pkinit_profile.c): `[realms]`, then
/// `[libdefaults] realm`, then `[libdefaults]`.
fn pkinit_strings(profile: &Profile, realm: &str, name: &str) -> Vec<String> {
    for path in [
        vec!["realms", realm, name],
        vec!["libdefaults", realm, name],
        vec!["libdefaults", name],
    ] {
        let v = profile.get_values(&path);
        if !v.is_empty() {
            return v;
        }
    }
    Vec::new()
}

fn pkinit_config(
    k5: &K5,
    o: &Opts,
) -> Result<Option<Arc<krb5_rs::pkinit::client::ClientConfig>>, String> {
    use krb5_rs::pkinit::client::ClientConfig;
    use krb5_rs::pkinit::x509::TrustStore;
    let mut ids: Vec<String> = Vec::new();
    let mut anchors: Vec<String> = Vec::new();
    for (k, v) in &o.pa_opts {
        match k.as_str() {
            "X509_user_identity" => ids.push(v.clone()),
            "X509_anchors" => anchors.push(v.clone()),
            _ => {}
        }
    }
    if anchors.is_empty() {
        anchors = pkinit_strings(&k5.profile, &k5.realm, "pkinit_anchors");
    }
    if ids.is_empty() {
        ids = pkinit_strings(&k5.profile, &k5.realm, "pkinit_identities");
    }
    if ids.is_empty() && !o.anonymous {
        return Ok(None);
    }
    let mut store = TrustStore::default();
    for a in &anchors {
        store.load(a, true)?;
    }
    for p in pkinit_strings(&k5.profile, &k5.realm, "pkinit_pool") {
        store.load(&p, false)?;
    }
    let mut cfg = if o.anonymous && ids.is_empty() {
        ClientConfig::anonymous(store)
    } else {
        let mut last = String::new();
        let mut found = None;
        for id in &ids {
            match ClientConfig::from_identity_spec(id, store.clone(), &k5.profile, &k5.realm) {
                Ok(c) => {
                    found = Some(c);
                    break;
                }
                Err(e) => last = e,
            }
        }
        found.ok_or(last)?
    };
    if o.pa_opts
        .iter()
        .any(|(k, v)| k == "disable_freshness" && v == "yes")
    {
        cfg.disable_freshness = true;
    }
    Ok(Some(cfg.shared()))
}

/// The armor TGT from `-T` (`krb5_get_init_creds_opt_set_fast_ccache_name`).
fn armor(k5: &K5, name: &str) -> Result<FastMode, String> {
    let c = resolve(&k5.ctx, name).map_err(|e| e.to_string())?;
    let (_, r) = c.principal().map_err(|e| e.to_string())?;
    let tgt = c
        .creds()
        .map_err(|e| e.to_string())?
        .into_iter()
        .find(|cr| {
            cr.server.name_string.len() == 2
                && cr.server.name_string[0].as_bytes() == b"krbtgt"
                && cr.srealm == r
        })
        .ok_or_else(|| "Matching credential not found".to_string())?;
    let cred = Credential::try_from(&tgt).map_err(|e| e.to_string())?;
    Ok(FastMode::Opportunistic(cred))
}

fn as_config(k5: &K5, o: &Opts) -> Result<AsExchangeConfig, String> {
    let p = &k5.profile;
    let r = &k5.realm;
    let mut c = AsExchangeConfig::new(k5.me.clone(), r.clone());
    // get_in_tkt.c:896-1005.
    let mut kopt = KdcOptions::empty();
    let forwardable = if o.forwardable || o.not_forwardable {
        o.forwardable
    } else {
        libdefault_boolean(p, r, "forwardable").unwrap_or(false)
    };
    if forwardable {
        kopt |= KdcOptions::FORWARDABLE;
    }
    let proxiable = if o.proxiable || o.not_proxiable {
        o.proxiable
    } else {
        libdefault_boolean(p, r, "proxiable").unwrap_or(false)
    };
    if proxiable {
        kopt |= KdcOptions::PROXIABLE;
    }
    if o.canonicalize || libdefault_boolean(p, r, "canonicalize").unwrap_or(false) {
        kopt |= KdcOptions::CANONICALIZE;
    }
    let deltat = |name: &str| -> Result<Option<i32>, String> {
        libdefault_string(p, r, name)
            .map(|s| string_to_deltat(&s).map_err(|e| e.to_string()))
            .transpose()
    };
    let tkt_life = if o.lifetime != 0 {
        o.lifetime
    } else {
        deltat("ticket_lifetime")?.unwrap_or(24 * 60 * 60)
    };
    let renew_life = if o.rlife != 0 {
        o.rlife
    } else {
        deltat("renew_lifetime")?.unwrap_or(0)
    };
    if renew_life > 0 {
        kopt |= KdcOptions::RENEWABLE;
    }
    c.kdc_options = KerberosFlags::new(kopt);
    c.tkt_lifetime = Duration::from_secs(u64::try_from(tkt_life).unwrap_or(0));
    c.renew_lifetime = Duration::from_secs(u64::try_from(renew_life).unwrap_or(0));
    c.start_time = u32::try_from(o.starttime).unwrap_or(0);
    if let Some(s) = libdefault_string(p, r, "default_tkt_enctypes") {
        c.etypes = krb5_rs::crypto::parse_enctype_list(&s, &c.etypes);
    }
    c.addresses = if o.addresses {
        Some(local_addresses())
    } else if o.no_addresses || libdefault_boolean(p, r, "noaddresses").unwrap_or(true) {
        None
    } else {
        Some(local_addresses())
    };
    if o.not_request_pac {
        c.request_pac = false;
    }
    if let Some(s) = &o.service_name {
        let (sp, _) = parse_principal(s, Some(r)).ok_or("Malformed representation of principal")?;
        c.server = Some(sp);
    }
    if let Some(a) = &o.armor_ccache {
        c.fast = armor(k5, a)?;
    }
    if let Some(s) = libdefault_string(p, r, "spake_preauth_groups") {
        c.spake_groups = s
            .split([' ', ',', '\t'])
            .filter_map(krb5_rs::spake::Group::from_name)
            .collect();
    }
    c.pkinit = pkinit_config(k5, o)?;
    Ok(c)
}

/// Write `cred` as the cache's only credential (`krb5_cc_initialize` and
/// `k5_cc_store_primary_cred`).
fn store_primary(
    cache: &mut dyn Ccache,
    cred: &Credential,
    client: &PrincipalName,
    realm: &str,
) -> Result<(), CcError> {
    cache.initialize(client, realm)?;
    cache.store(&CcCredential::from(cred))
}

fn k5_kinit(o: &Opts, k5: &mut K5) -> bool {
    for (k, v) in &o.pa_opts {
        if o.verbose {
            eprintln!("PA Option {k} = {v}");
        }
    }
    let dns: Option<Arc<dyn krb5_rs::locate::DnsResolver + Send + Sync>> =
        krb5_rs::locate::HickoryResolver::new()
            .ok()
            .map(|r| Arc::new(r) as Arc<dyn krb5_rs::locate::DnsResolver + Send + Sync>);
    let transport = krb5_rs::transport::LocatedTransport::new(k5.profile.clone(), dns);
    let client = KerberosClient::new(k5.realm.clone(), transport);
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            com_err(e, "while initializing Kerberos 5 library");
            return false;
        }
    };
    let mut pwprompt = false;
    let result: Result<Credential, Krb5Error> = match o.action {
        Action::InitPw | Action::InitKt => {
            let config = match as_config(k5, o) {
                Ok(c) => c,
                Err(e) => {
                    com_err(e, "while getting initial credentials");
                    return false;
                }
            };
            if o.action == Action::InitKt {
                let ktname = match (&o.keytab_name, o.use_client_keytab) {
                    (Some(n), _) => n.clone(),
                    (None, true) => match default_client_keytab_name(Some(&k5.profile)) {
                        Ok(n) => n,
                        Err(e) => {
                            com_err(e, "resolving default client keytab");
                            return false;
                        }
                    },
                    (None, false) => krb5_rs::client::vfy::default_keytab_name(Some(&k5.profile)),
                };
                let kt = match resolve_keytab(&ktname) {
                    Ok(k) => k,
                    Err(e) => {
                        com_err(e, &format!("resolving keytab {ktname}"));
                        return false;
                    }
                };
                if o.verbose && o.keytab_name.is_some() {
                    eprintln!("Using keytab: {ktname}");
                }
                // lookup_etypes_for_keytab (gic_keytab.c:85-140).
                let entries: Vec<_> = kt
                    .entries()
                    .unwrap_or_default()
                    .into_iter()
                    .filter(|e| {
                        e.principal.name_string == k5.me.name_string
                            && e.realm == k5.realm
                            && krb5_rs::crypto::find_etype(e.key.keytype).is_ok()
                    })
                    .collect();
                match entries.iter().map(|e| e.kvno).max() {
                    Some(max) => {
                        let keys = entries
                            .into_iter()
                            .filter(|e| e.kvno == max)
                            .map(|e| e.key)
                            .collect();
                        rt.block_on(client.acquire_tgt_with_keys(config, keys))
                    }
                    None => {
                        com_err(
                            format!(
                                "Keytab contains no suitable keys for {} while getting initial credentials",
                                k5.name
                            ),
                            "",
                        );
                        return false;
                    }
                }
            } else {
                let password = if config.pkinit.is_some()
                    || krb5_rs::types::is_anonymous_name(&k5.me)
                {
                    String::new()
                } else {
                    pwprompt = true;
                    match rpassword::prompt_password(format!("Password for {}: ", k5.name)) {
                        Ok(p) => p,
                        Err(_) => {
                            com_err("Cannot read password", "while getting initial credentials");
                            return false;
                        }
                    }
                };
                rt.block_on(client.acquire_tgt_with_config(config, &password))
            }
        }
        Action::Renew | Action::Validate => {
            let server = match &o.service_name {
                Some(s) => parse_principal(s, Some(&k5.realm)).map(|(p, _)| (p, k5.realm.clone())),
                None => Some((
                    PrincipalName::new_srv_inst("krbtgt", &k5.realm),
                    k5.realm.clone(),
                )),
            };
            let old = server.and_then(|(sp, sr)| {
                k5.in_cc
                    .as_ref()
                    .unwrap_or(&k5.out_cc)
                    .creds()
                    .ok()?
                    .into_iter()
                    .find(|c| {
                        c.server.name_string == sp.name_string
                            && c.srealm == sr
                            && c.client.name_string == k5.me.name_string
                    })
            });
            match old.map(|c| Credential::try_from(&c)) {
                Some(Ok(old)) => {
                    let opt = if o.action == Action::Renew {
                        KdcOptions::RENEW
                    } else {
                        KdcOptions::VALIDATE
                    };
                    rt.block_on(client.get_valrenewed_creds(&old, opt))
                }
                Some(Err(e)) => {
                    com_err(e, &format!("while {}", valrenew_doing(o.action)));
                    return false;
                }
                None => {
                    com_err(
                        "Matching credential not found",
                        &format!("while {}", valrenew_doing(o.action)),
                    );
                    return false;
                }
            }
        }
    };
    let doing = match o.action {
        Action::InitPw | Action::InitKt => "getting initial credentials",
        Action::Validate => "validating credentials",
        Action::Renew => "renewing credentials",
    };
    let cred = match result {
        Ok(c) => c,
        Err(e) => {
            let bad_integrity = matches!(e, Krb5Error::DecryptionFailed);
            let preauth_failed = matches!(e, Krb5Error::PreauthFailed)
                || matches!(&e, Krb5Error::KdcError(m) if m.error_code == 24);
            if bad_integrity || (pwprompt && preauth_failed) {
                eprintln!("{}: Password incorrect while {doing}", progname());
            } else {
                com_err(krb5_message(&e), &format!("while {doing}"));
            }
            return false;
        }
    };
    let cprinc = if o.canonicalize || matches!(o.action, Action::InitPw | Action::InitKt) {
        (cred.client.clone(), cred.crealm.clone())
    } else {
        (k5.me.clone(), k5.realm.clone())
    };
    if matches!(o.action, Action::InitPw | Action::InitKt) {
        // The gic out_ccache (get_in_tkt.c:1615-1660): stage in MEMORY,
        // then replace the output cache's contents.
        if let Err(e) = store_primary(&mut k5.out_cc, &cred, &cprinc.0, &cprinc.1) {
            com_err(e, "while storing credentials");
            return false;
        }
    } else {
        let mut mcc = MemoryCcache::new();
        if let Err(e) = store_primary(&mut mcc, &cred, &cprinc.0, &cprinc.1) {
            com_err(e, "when creating temporary cache");
            return false;
        }
        if o.verbose {
            eprintln!("Initialized cache");
        }
        let staged = match mcc.creds() {
            Ok(s) => s,
            Err(e) => {
                com_err(e, "while storing credentials");
                return false;
            }
        };
        let moved = k5
            .out_cc
            .initialize(&cprinc.0, &cprinc.1)
            .and_then(|()| staged.iter().try_for_each(|c| k5.out_cc.store(c)));
        if let Err(e) = moved {
            com_err(
                e,
                &format!(
                    "while saving to cache {}",
                    o.out_cache.as_deref().unwrap_or("")
                ),
            );
            return false;
        }
        if o.verbose {
            eprintln!("Stored credentials");
        }
    }
    if k5.switch_to_cache {
        if let Err(e) = k5.out_cc.switch_to() {
            com_err(e, "while switching to new ccache");
            return false;
        }
    }
    true
}

fn valrenew_doing(a: Action) -> &'static str {
    if a == Action::Renew {
        "renewing credentials"
    } else {
        "validating credentials"
    }
}

fn main() {
    let mut o = parse_options();
    let authed = match k5_begin(&mut o) {
        Some(mut k5) => k5_kinit(&o, &mut k5),
        None => false,
    };
    if authed && o.verbose {
        eprintln!("Authenticated to Kerberos v5");
    }
    if !authed {
        std::process::exit(1);
    }
}
