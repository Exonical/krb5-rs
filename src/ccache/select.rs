//! Credential cache selection for a target service (MIT
//! lib/krb5/ccache/ccselect.c and the built-in `k5identity`, `realm` and
//! `hostname` modules).

use super::{cache_match, collection, unparse_name, AnyCcache, CcContext, CcError, Ccache};
use crate::profile::Profile;
use crate::types::PrincipalName;

const NT_PRINCIPAL: i32 = 1;
const NT_SRV_HST: i32 = 3;

/// A client principal and realm.
pub type Client = (PrincipalName, String);

/// What a ccselect module decided (MIT `choose` return values).
enum Choice {
    /// A cache and its client principal (0).
    Found(AnyCcache, Client),
    /// The client principal to use, which has no cache (KRB5_CC_NOTFOUND).
    NotFound(Client),
    /// No opinion (KRB5_PLUGIN_NO_HANDLE).
    Pass,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Module {
    K5identity,
    Realm,
    Hostname,
}

impl Module {
    fn name(self) -> &'static str {
        match self {
            Module::K5identity => "k5identity",
            Module::Realm => "realm",
            Module::Hostname => "hostname",
        }
    }

    fn authoritative(self) -> bool {
        self == Module::K5identity
    }
}

/// The result of [`cc_select`].
pub struct Selection {
    /// The chosen cache, if a module found one.
    pub cache: Option<AnyCcache>,
    /// The chosen client principal, if a module named one.
    pub client: Option<Client>,
}

/// The enabled built-in modules in MIT's registration order, after
/// `[plugins] ccselect` `disable` and `enable_only` (plugin.c
/// `configure_interface`).
fn modules(profile: Option<&Profile>) -> Vec<Module> {
    let mut list = Vec::new();
    #[cfg(not(windows))]
    list.push(Module::K5identity);
    list.push(Module::Realm);
    list.push(Module::Hostname);
    let get =
        |k: &str| profile.map_or_else(Vec::new, |p| p.get_values(&["plugins", "ccselect", k]));
    let disable = get("disable");
    list.retain(|m| !disable.iter().any(|d| d == m.name()));
    let enable = get("enable_only");
    if !enable.is_empty() {
        list = enable
            .iter()
            .filter_map(|e| list.iter().copied().find(|m| m.name() == e))
            .fold(Vec::new(), |mut v, m| {
                if !v.contains(&m) {
                    v.push(m);
                }
                v
            });
    }
    list
}

/// `krb5_cc_select`: the cache (and client principal) to use for
/// `server@srealm`. An empty `srealm` is the referral realm. Authoritative
/// modules (`k5identity`) are asked before heuristic ones (`realm`,
/// `hostname`). Returns KRB5_CC_NOTFOUND when no module chose anything; a
/// module that named a client without a cache returns its client and no
/// cache.
pub fn cc_select(
    ctx: &CcContext,
    profile: Option<&Profile>,
    server: &PrincipalName,
    srealm: &str,
) -> Result<Selection, CcError> {
    // The fallback host realm stands in for the referral realm.
    let mut srealm = srealm.to_string();
    if srealm.is_empty() && server.name_type == NT_SRV_HST && server.name_string.len() == 2 {
        if let Some(p) = profile {
            if let Some(r) = crate::locate::fallback_host_realm(p, &comp(server, 1))
                .into_iter()
                .next()
            {
                srealm = r;
            }
        }
    }
    let sname = unparse_name(server, &srealm);
    let mods = modules(profile);
    for authoritative in [true, false] {
        for m in mods.iter().filter(|m| m.authoritative() == authoritative) {
            match choose(*m, ctx, profile, server, &srealm) {
                Ok(Choice::Found(cache, client)) => {
                    crate::k5trace!(
                        "ccselect module {} chose cache {} with client principal {} for server principal {}",
                        m.name(),
                        cache.name(),
                        unparse_name(&client.0, &client.1),
                        sname
                    );
                    return Ok(Selection {
                        cache: Some(cache),
                        client: Some(client),
                    });
                }
                Ok(Choice::NotFound(client)) => {
                    crate::k5trace!(
                        "ccselect module {} chose client principal {} for server principal {} but found no cache",
                        m.name(),
                        unparse_name(&client.0, &client.1),
                        sname
                    );
                    return Ok(Selection {
                        cache: None,
                        client: Some(client),
                    });
                }
                Ok(Choice::Pass) => {}
                Err(e) => {
                    crate::k5trace!(
                        "ccselect module {} yielded error {} for server principal {}",
                        m.name(),
                        crate::trace::kerr(-1, &e.to_string()),
                        sname
                    );
                    return Err(e);
                }
            }
        }
    }
    crate::k5trace!("ccselect can't find appropriate cache for server principal {sname}");
    Err(CcError::code(
        "KRB5_CC_NOTFOUND",
        "Matching credential not found",
    ))
}

/// The cache a GSS initiator with no credential uses for `server@srealm`
/// (acquire_cred.c `kg_cred_resolve`): the [`cc_select`] choice, else the
/// default cache. A client principal chosen without a cache is an error.
pub fn select_cache(
    ctx: &CcContext,
    profile: Option<&Profile>,
    server: &PrincipalName,
    srealm: &str,
) -> Result<AnyCcache, CcError> {
    match cc_select(ctx, profile, server, srealm) {
        Ok(Selection { cache: Some(c), .. }) => Ok(c),
        Ok(Selection {
            client: Some((n, r)),
            ..
        }) => Err(CcError::code(
            "KRB5_CC_NOTFOUND",
            format!(
                "Can't find client principal {} in cache collection",
                unparse_name(&n, &r)
            ),
        )),
        Ok(_) => super::default_cache(ctx),
        Err(CcError::Code {
            name: "KRB5_CC_NOTFOUND",
            ..
        }) => {
            let c = super::default_cache(ctx)?;
            crate::k5trace!(
                "ccselect choosing default cache {} for server principal {}",
                c.name(),
                unparse_name(server, srealm)
            );
            Ok(c)
        }
        Err(e) => Err(e),
    }
}

fn comp(p: &PrincipalName, i: usize) -> String {
    p.name_string
        .get(i)
        .map(|s| String::from_utf8_lossy(s.as_bytes()).into_owned())
        .unwrap_or_default()
}

fn choose(
    m: Module,
    ctx: &CcContext,
    profile: Option<&Profile>,
    server: &PrincipalName,
    srealm: &str,
) -> Result<Choice, CcError> {
    match m {
        Module::K5identity => k5identity_choose(ctx, profile, server, srealm),
        Module::Realm => realm_choose(ctx, srealm),
        Module::Hostname => hostname_choose(ctx, server),
    }
}

/// `$HOME`, else the euid's home directory (ccselect_k5identity.c
/// `get_homedir`).
fn homedir() -> Option<std::path::PathBuf> {
    if let Some(h) = std::env::var_os("HOME") {
        return Some(h.into());
    }
    #[cfg(unix)]
    {
        euid_homedir()
    }
    #[cfg(not(unix))]
    {
        None
    }
}

#[cfg(unix)]
#[allow(unsafe_code)]
fn euid_homedir() -> Option<std::path::PathBuf> {
    use std::os::unix::ffi::OsStrExt;
    let mut buf = vec![0 as libc::c_char; 16384];
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut out: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: getpwuid_r writes into pwd/buf (sized as passed) and sets out
    // to &pwd on success; pw_dir points into buf, read before buf drops.
    let rc = unsafe {
        libc::getpwuid_r(
            libc::geteuid(),
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
    Some(std::ffi::OsStr::from_bytes(dir.to_bytes()).into())
}

fn k5identity_choose(
    ctx: &CcContext,
    profile: Option<&Profile>,
    server: &PrincipalName,
    srealm: &str,
) -> Result<Choice, CcError> {
    let Some(home) = homedir() else {
        return Ok(Choice::Pass);
    };
    let Ok(text) = std::fs::read(home.join(".k5identity")) else {
        return Ok(Choice::Pass);
    };
    let defrealm = profile.and_then(crate::locate::default_realm);
    let Some(client) = String::from_utf8_lossy(&text)
        .lines()
        .find_map(|l| parse_k5identity_line(l, server, srealm, defrealm.as_deref()))
    else {
        return Ok(Choice::Pass);
    };
    match cache_match(ctx, &client.0, &client.1) {
        Ok(c) => Ok(Choice::Found(c, client)),
        Err(CcError::Code {
            name: "KRB5_CC_NOTFOUND",
            ..
        }) => Ok(Choice::NotFound(client)),
        Err(e) => Err(e),
    }
}

/// ccselect_k5identity.c `parse_line`: `principal [name=pattern ...]`.
fn parse_k5identity_line(
    line: &str,
    server: &PrincipalName,
    srealm: &str,
    defrealm: Option<&str>,
) -> Option<Client> {
    let mut fields = line
        .split([' ', '\t', '\r', '\n'])
        .filter(|f| !f.is_empty());
    let princ = fields.next()?;
    if princ.starts_with('#') {
        return None;
    }
    for f in fields {
        let (name, value) = f.split_once('=')?;
        if !check_constraint(name, value, server, srealm) {
            return None;
        }
    }
    parse_name(princ, defrealm)
}

fn check_constraint(name: &str, value: &str, server: &PrincipalName, srealm: &str) -> bool {
    let host_based = server.name_type == NT_SRV_HST && server.name_string.len() >= 2;
    match name {
        "realm" => fnmatch(value, srealm),
        "service" => host_based && fnmatch(value, &comp(server, 0)),
        "host" => host_based && fnmatch(value, &comp(server, 1).to_ascii_lowercase()),
        // Unrecognized constraints are critical.
        _ => false,
    }
}

/// `fnmatch(pattern, s, 0)`: `*`, `?`, `[...]` (with `!`/`^` negation
/// and ranges) and `\` escapes.
pub(crate) fn fnmatch(pattern: &str, s: &str) -> bool {
    fn m(p: &[char], s: &[char]) -> bool {
        match p.first() {
            None => s.is_empty(),
            Some('*') => (0..=s.len()).any(|i| m(&p[1..], &s[i..])),
            Some('?') => !s.is_empty() && m(&p[1..], &s[1..]),
            Some('[') => {
                let Some(&c) = s.first() else { return false };
                let mut i = 1;
                let neg = matches!(p.get(1), Some('!' | '^'));
                if neg {
                    i += 1;
                }
                let start = i;
                let mut hit = false;
                while i < p.len() && (p[i] != ']' || i == start) {
                    if p.get(i + 1) == Some(&'-') && p.get(i + 2).is_some_and(|&e| e != ']') {
                        if p[i] <= c && c <= p[i + 2] {
                            hit = true;
                        }
                        i += 3;
                    } else {
                        if p[i] == c {
                            hit = true;
                        }
                        i += 1;
                    }
                }
                if i >= p.len() {
                    // No closing bracket: '[' is literal.
                    return c == '[' && m(&p[1..], &s[1..]);
                }
                hit != neg && m(&p[i + 1..], &s[1..])
            }
            Some('\\') if p.len() > 1 => s.first() == Some(&p[1]) && m(&p[2..], &s[1..]),
            Some(&c) => s.first() == Some(&c) && m(&p[1..], &s[1..]),
        }
    }
    let p: Vec<char> = pattern.chars().collect();
    let s: Vec<char> = s.chars().collect();
    m(&p, &s)
}

/// `krb5_parse_name`: components split on unescaped `/`, realm after the
/// unescaped `@` (else the default realm).
pub(crate) fn parse_name(s: &str, defrealm: Option<&str>) -> Option<Client> {
    let mut comps = vec![String::new()];
    let mut realm = String::new();
    let mut in_realm = false;
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        let ch = match c {
            '\\' => match chars.next()? {
                'n' => '\n',
                't' => '\t',
                'b' => '\u{8}',
                '0' => '\0',
                o => o,
            },
            '/' if !in_realm => {
                comps.push(String::new());
                continue;
            }
            '@' if !in_realm => {
                in_realm = true;
                continue;
            }
            '/' | '@' => return None,
            o => o,
        };
        if in_realm {
            realm.push(ch);
        } else {
            comps.last_mut()?.push(ch);
        }
    }
    if realm.is_empty() {
        realm = defrealm?.to_string();
    }
    let name_string = comps
        .iter()
        .map(|p| rasn::types::GeneralString::from_bytes(p.as_bytes()).ok())
        .collect::<Option<_>>()?;
    Some((
        PrincipalName {
            name_type: NT_PRINCIPAL,
            name_string,
        },
        realm,
    ))
}

fn realm_choose(ctx: &CcContext, srealm: &str) -> Result<Choice, CcError> {
    if srealm.is_empty() {
        return Ok(Choice::Pass);
    }
    for c in collection(ctx)? {
        if let Ok(client) = c.principal() {
            if client.1 == srealm {
                return Ok(Choice::Found(c, client));
            }
        }
    }
    Ok(Choice::Pass)
}

fn hostname_choose(ctx: &CcContext, server: &PrincipalName) -> Result<Choice, CcError> {
    if server.name_type != NT_SRV_HST || server.name_string.len() < 2 {
        return Ok(Choice::Pass);
    }
    let host = comp(server, 1).to_ascii_uppercase();
    let mut best: Option<(AnyCcache, Client)> = None;
    for c in collection(ctx)? {
        // ccselect_hostname.c stops the scan at a cache with no principal.
        let client = c.principal()?;
        let mut domain = host.as_str();
        loop {
            if best.as_ref().is_some_and(|b| b.1 .1.len() >= domain.len()) {
                break;
            }
            if client.1 == domain {
                best = Some((c, client));
                break;
            }
            match domain.find('.') {
                Some(d) => domain = &domain[d + 1..],
                None => break,
            }
        }
    }
    Ok(match best {
        Some((c, client)) => Choice::Found(c, client),
        None => Choice::Pass,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fnmatch_like_libc() {
        assert!(fnmatch("ho*t", "host"));
        assert!(fnmatch("h?st", "host"));
        assert!(fnmatch("[a-h]ost", "host"));
        assert!(!fnmatch("[!h]ost", "host"));
        assert!(!fnmatch("bogus", "host"));
        assert!(fnmatch("KRBTEST.COM", "KRBTEST.COM"));
        assert!(fnmatch("\\*", "*"));
    }

    #[test]
    fn k5identity_lines() {
        let host = PrincipalName::new_srv_inst("host", "LocalHost");
        let mut hst = host.clone();
        hst.name_type = NT_SRV_HST;
        let p = |l| parse_k5identity_line(l, &hst, "KRBTEST.COM", Some("DEF.REALM"));
        assert_eq!(
            p("alice@KRBTEST.COM realm=KRBTEST.COM").expect("alice").1,
            "KRBTEST.COM"
        );
        let z = p("zaphod@KRBTEST2.COM service=ho*t host=localhost").expect("zaphod");
        assert_eq!(unparse_name(&z.0, &z.1), "zaphod@KRBTEST2.COM");
        assert!(p("noprinc service=bogus").is_none());
        assert!(p("# comment").is_none());
        assert!(p("x unknown=1").is_none());
        assert!(p("x malformed").is_none());
        assert_eq!(p("bob").expect("bob").1, "DEF.REALM");
        // Unknown name type: service/host constraints don't match.
        let mut unk = host;
        unk.name_type = 0;
        assert!(parse_k5identity_line("a service=host", &unk, "R", Some("R")).is_none());
    }

    #[test]
    fn parse_name_escapes() {
        let (n, r) = parse_name("a\\/b/c@R", None).expect("parse");
        assert_eq!(n.name_string.len(), 2);
        assert_eq!(n.name_string[0].as_bytes(), b"a/b");
        assert_eq!(r, "R");
        assert!(parse_name("a@b@c", None).is_none());
        assert!(parse_name("a", None).is_none());
    }
}
