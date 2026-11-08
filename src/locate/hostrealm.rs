//! Host-to-realm mapping like MIT's hostrealm interface (hostrealm.c):
//! `krb5_get_host_realm`, `krb5_get_fallback_host_realm` and
//! `krb5_get_default_realm` ask each module in turn. The built-in modules
//! are MIT's `profile` (`[domain_realm]`, `default_realm`), `dns` and
//! `domain` (realm_try_domains / parent-domain heuristics); `dns` asks
//! `_kerberos` TXT records when `dns_lookup_realm` is on, through the
//! system resolver (feature `dns`) or one passed to the `_with_dns`
//! functions; modules
//! configured as `[plugins] hostrealm { module = name:unix:path=... }` run
//! as separate processes over [`crate::plugin::rpc`] and come first, as in
//! MIT's plugin order.

use std::io::{self, Read, Write};
use std::sync::Arc;

use super::DnsResolver;
use crate::plugin::rpc::{self, Message, PLUGIN_NO_HANDLE};
use crate::plugin::{self as plugins, Configured};
use crate::profile::Profile;

/// `KRB5_CONFIG_NODEFREALM`.
pub const CONFIG_NODEFREALM: i32 = rpc::ERROR_TABLE_BASE_KRB5 + 224;
/// `KRB5_EAI_FAIL`.
pub const EAI_FAIL: i32 = rpc::ERROR_TABLE_BASE_KRB5 + 239;
/// `KRB5_PLUGIN_BAD_MODULE_SPEC`.
pub const PLUGIN_BAD_MODULE_SPEC: i32 = -1_750_600_192 + 1;
/// [`rpc::call::INITIALIZE`]'s string for a hostrealm module.
pub const HOSTREALM_HANDSHAKE: &str = "KRB5RS-HOSTREALM-V-1";

/// hostrealm call numbers.
pub mod call {
    pub use crate::plugin::rpc::call::{FINALIZE, INITIALIZE};
    /// `host_realm`: `s` host; answered with `as` realms.
    pub const HOST_REALM: u32 = 3;
    /// `fallback_realm`: `s` host; answered with `as` realms.
    pub const FALLBACK_REALM: u32 = 4;
    /// `default_realm`: answered with `as` realms.
    pub const DEFAULT_REALM: u32 = 5;
}

/// A hostrealm module (`krb5_hostrealm_vtable`). Each method returns the
/// realms, `PLUGIN_NO_HANDLE` to defer to later modules, or another com_err
/// code to stop.
pub trait HostRealm: Send + Sync {
    /// The module name.
    fn name(&self) -> &str;
    /// `init`.
    fn init(&self) -> Result<(), i32> {
        Ok(())
    }
    /// `fini`.
    fn fini(&self) {}
    /// `host_realm`.
    fn host_realm(&self, _host: &str) -> Result<Vec<String>, i32> {
        Err(PLUGIN_NO_HANDLE)
    }
    /// `fallback_realm`.
    fn fallback_realm(&self, _host: &str) -> Result<Vec<String>, i32> {
        Err(PLUGIN_NO_HANDLE)
    }
    /// `default_realm`.
    fn default_realm(&self) -> Result<Vec<String>, i32> {
        Err(PLUGIN_NO_HANDLE)
    }
}

/// Serve a hostrealm module on `stream`.
pub fn serve_hostrealm<S: Read + Write>(stream: S, module: &dyn HostRealm) -> io::Result<()> {
    rpc::serve(stream, HOSTREALM_HANDSHAKE, |req| {
        let mut answer = Message::new(req.call);
        let realms = match req.call {
            call::INITIALIZE => {
                return Ok(module.init().map(|()| answer).map_err(|c| (c, None)));
            }
            call::FINALIZE => {
                module.fini();
                return Ok(Ok(answer));
            }
            call::HOST_REALM | call::FALLBACK_REALM => {
                let host = req.get_str()?.unwrap_or_default();
                req.finish()?;
                if req.call == call::HOST_REALM {
                    module.host_realm(&host)
                } else {
                    module.fallback_realm(&host)
                }
            }
            call::DEFAULT_REALM => {
                req.finish()?;
                module.default_realm()
            }
            _ => return Ok(Err((PLUGIN_NO_HANDLE, None))),
        };
        Ok(realms
            .map(|r| {
                answer.put_strs(&r);
                answer
            })
            .map_err(|c| (c, None)))
    })
}

enum Module {
    Profile,
    Dns,
    Domain,
    Remote(Arc<rpc::Conn>),
}

/// The enabled modules in MIT's order (`load_hostrealm_modules`); a
/// module that can't be reached or initialized is skipped, as in MIT.
fn modules(profile: &Profile) -> Result<Vec<Module>, i32> {
    let list = plugins::configured(&[profile], "hostrealm", &["profile", "dns", "domain"])
        .map_err(|_| PLUGIN_BAD_MODULE_SPEC)?;
    Ok(list
        .into_iter()
        .filter_map(|c| match c {
            Configured::Builtin(n) => match n.as_str() {
                "profile" => Some(Module::Profile),
                "dns" => Some(Module::Dns),
                "domain" => Some(Module::Domain),
                _ => None,
            },
            Configured::Remote(n, path) => {
                plugins::remote(HOSTREALM_HANDSHAKE, &n, &path).map(Module::Remote)
            }
        })
        .collect())
}

fn remote_call(conn: &rpc::Conn, m: &Message) -> Result<Vec<String>, i32> {
    match conn.call(m) {
        Ok(Ok(mut a)) => {
            let r = a.get_strs().map_err(|_| PLUGIN_NO_HANDLE)?;
            a.finish().map_err(|_| PLUGIN_NO_HANDLE)?;
            Ok(r)
        }
        Ok(Err((code, _))) => Err(code),
        // A module that has gone away defers, like one that isn't loaded.
        Err(_) => Err(PLUGIN_NO_HANDLE),
    }
}

impl Module {
    fn host_realm(&self, profile: &Profile, host: &str) -> Result<Vec<String>, i32> {
        match self {
            Module::Profile => profile_host_realm(profile, host),
            Module::Remote(c) => {
                let mut m = Message::new(call::HOST_REALM);
                m.put_str(Some(host));
                remote_call(c, &m)
            }
            Module::Dns | Module::Domain => Err(PLUGIN_NO_HANDLE),
        }
    }

    fn fallback_realm(
        &self,
        profile: &Profile,
        dns: Option<&dyn DnsResolver>,
        host: &str,
    ) -> Result<Vec<String>, i32> {
        match self {
            Module::Domain => domain_fallback_realm(profile, host),
            Module::Dns => dns_fallback_realm(profile, dns, host),
            Module::Remote(c) => {
                let mut m = Message::new(call::FALLBACK_REALM);
                m.put_str(Some(host));
                remote_call(c, &m)
            }
            Module::Profile => Err(PLUGIN_NO_HANDLE),
        }
    }

    fn default_realm(
        &self,
        profile: &Profile,
        dns: Option<&dyn DnsResolver>,
    ) -> Result<Vec<String>, i32> {
        match self {
            Module::Dns => dns_default_realm(profile, dns),
            Module::Profile => profile
                .get_string(&["libdefaults", "default_realm"])
                .map(|r| vec![r])
                .ok_or(PLUGIN_NO_HANDLE),
            Module::Remote(c) => remote_call(c, &Message::new(call::DEFAULT_REALM)),
            Module::Domain => Err(PLUGIN_NO_HANDLE),
        }
    }
}

/// The system resolver the `dns` module uses when none is passed in; MIT
/// built without KRB5_DNS_LOOKUP (no feature `dns` here) has none, and the
/// module declines.
fn system_dns() -> Option<&'static dyn DnsResolver> {
    #[cfg(feature = "dns")]
    {
        static RESOLVER: std::sync::OnceLock<Option<super::HickoryResolver>> =
            std::sync::OnceLock::new();
        RESOLVER
            .get_or_init(|| super::HickoryResolver::new().ok())
            .as_ref()
            .map(|r| r as &dyn DnsResolver)
    }
    #[cfg(not(feature = "dns"))]
    {
        None
    }
}

/// `_krb5_use_dns_realm` (locate_kdc.c:95-99): `dns_lookup_realm`, else
/// `dns_fallback`, default false.
fn use_dns_realm(profile: &Profile) -> bool {
    super::maybe_use_dns(profile, "dns_lookup_realm", false)
}

/// txt_lookup_name (dnsglue.c:368-397): `prefix.name.`, or the bare
/// prefix (left to the resolver's search list) when there is no name.
fn txt_lookup_name(prefix: &str, name: Option<&str>) -> String {
    match name {
        Some(n) if !n.is_empty() => {
            let mut s = format!("{prefix}.{n}");
            if !s.ends_with('.') {
                s.push('.');
            }
            s
        }
        _ => prefix.to_string(),
    }
}

/// k5_try_realm_txt_rr (dnsglue.c:449-498): the first string of the first
/// TXT answer, less one trailing dot.
fn try_realm_txt(dns: &dyn DnsResolver, prefix: &str, name: Option<&str>) -> Option<String> {
    let txtname = txt_lookup_name(prefix, name);
    let answers = match dns.txt(&txtname) {
        Ok(a) => a,
        Err(()) => {
            crate::k5trace!(
                "TXT record {} not found",
                crate::trace::data(txtname.as_bytes())
            );
            return None;
        }
    };
    let mut realm = answers.into_iter().next()?;
    // "Avoid a common error."
    if realm.ends_with('.') {
        realm.pop();
    }
    crate::k5trace!(
        "TXT record {} found: {}",
        crate::trace::data(txtname.as_bytes()),
        crate::trace::data(realm.as_bytes())
    );
    Some(realm)
}

/// hostrealm_dns.c `txt_lookup`: `_kerberos.<fqdn>` and each parent
/// domain.
fn txt_lookup(dns: &dyn DnsResolver, fqdn: &str) -> Option<String> {
    let mut rest = Some(fqdn);
    while let Some(f) = rest.filter(|f| !f.is_empty()) {
        if let Some(r) = try_realm_txt(dns, "_kerberos", Some(f)) {
            return Some(r);
        }
        rest = f.find('.').map(|d| &f[d + 1..]);
    }
    None
}

/// hostrealm_dns.c `dns_fallback_realm`.
fn dns_fallback_realm(
    profile: &Profile,
    dns: Option<&dyn DnsResolver>,
    host: &str,
) -> Result<Vec<String>, i32> {
    let Some(dns) = dns else {
        return Err(PLUGIN_NO_HANDLE);
    };
    if !use_dns_realm(profile) || is_numeric_address(host) {
        return Err(PLUGIN_NO_HANDLE);
    }
    txt_lookup(dns, host)
        .map(|r| vec![r])
        .ok_or(PLUGIN_NO_HANDLE)
}

/// hostrealm_dns.c `dns_default_realm`: the local host's domains, then a
/// global `_kerberos` record.
fn dns_default_realm(profile: &Profile, dns: Option<&dyn DnsResolver>) -> Result<Vec<String>, i32> {
    let Some(dns) = dns else {
        return Err(PLUGIN_NO_HANDLE);
    };
    if !use_dns_realm(profile) {
        return Err(PLUGIN_NO_HANDLE);
    }
    let localhost = fq_local_hostname()?;
    txt_lookup(dns, &localhost)
        .or_else(|| try_realm_txt(dns, "_kerberos", None))
        .map(|r| vec![r])
        .ok_or(PLUGIN_NO_HANDLE)
}

/// krb5int_get_fq_local_hostname (hostrealm.c:255-279): `gethostname`,
/// forward-canonicalized with `AI_CANONNAME`.
fn fq_local_hostname() -> Result<String, i32> {
    #[cfg(unix)]
    let host = rustix::system::uname()
        .nodename()
        .to_string_lossy()
        .into_owned();
    #[cfg(not(unix))]
    let host = std::env::var("COMPUTERNAME").unwrap_or_default();
    if host.is_empty() {
        return Err(EAI_FAIL);
    }
    #[cfg(any(
        feature = "kdc",
        all(feature = "client", any(unix, windows, not(feature = "dns")))
    ))]
    {
        super::dns_canonical(&host, false).ok_or(EAI_FAIL)
    }
    #[cfg(not(any(
        feature = "kdc",
        all(feature = "client", any(unix, windows, not(feature = "dns")))
    )))]
    {
        Ok(host)
    }
}

/// hostrealm_profile.c `profile_host_realm`: `[domain_realm]` for the host,
/// then each suffix, with the pointer landing at each dot so ".dom" keys
/// match.
fn profile_host_realm(profile: &Profile, host: &str) -> Result<Vec<String>, i32> {
    if is_numeric_address(host) {
        return Err(PLUGIN_NO_HANDLE);
    }
    let bytes = host.as_bytes();
    let mut p: Option<usize> = Some(0);
    while let Some(i) = p {
        if let Some(r) = profile.get_string(&["domain_realm", &host[i..]]) {
            return Ok(vec![r]);
        }
        p = match bytes.get(i) {
            Some(b'.') => Some(i + 1),
            Some(_) => host[i..].find('.').map(|d| i + d),
            None => None,
        };
    }
    Err(PLUGIN_NO_HANDLE)
}

/// Locate `suffix` as a realm (profile KDC lookup; the domain module uses
/// k5_locate_kdc, which falls back to DNS — our host_realm API is
/// profile-only, so only profile-configured realms count).
fn realm_is_locatable(profile: &Profile, realm: &str) -> bool {
    !profile.get_values(&["realms", realm, "kdc"]).is_empty()
}

/// hostrealm_domain.c `domain_fallback_realm`.
fn domain_fallback_realm(profile: &Profile, host: &str) -> Result<Vec<String>, i32> {
    if is_numeric_address(host) {
        return Err(PLUGIN_NO_HANDLE);
    }
    let limit = profile
        .get_integer(&["libdefaults", "realm_try_domains"], -1)
        .unwrap_or(-1);
    let uhost = host.to_uppercase();
    // Try progressively shorter suffixes as realms: -1 means no search,
    // 0 means only the full domain, etc.  Stop at a single label.
    let mut suffix = uhost.as_str();
    let mut limit = limit;
    while limit >= 0 {
        limit -= 1;
        let Some(dot) = suffix.find('.') else { break };
        if realm_is_locatable(profile, suffix) {
            return Ok(vec![suffix.to_string()]);
        }
        suffix = &suffix[dot + 1..];
    }
    // Upper-cased parent domain, regardless of locatability.
    match uhost.find('.') {
        Some(d) => Ok(vec![uhost[d + 1..].to_string()]),
        None => Err(PLUGIN_NO_HANDLE),
    }
}

/// `krb5_get_host_realm`: the first module's realms; unmapped hosts give
/// `[""]`, MIT's referral realm.
pub fn get_host_realm(profile: &Profile, host: &str) -> Result<Vec<String>, i32> {
    let mods = modules(profile)?;
    let host = clean(host);
    for m in &mods {
        match m.host_realm(profile, &host) {
            Err(PLUGIN_NO_HANDLE) => {}
            r => return r,
        }
    }
    Ok(vec![String::new()])
}

/// `krb5_get_fallback_host_realm`: the first module's realms, else the
/// default realm.
pub fn get_fallback_host_realm(profile: &Profile, host: &str) -> Result<Vec<String>, i32> {
    get_fallback_host_realm_with_dns(profile, host, system_dns())
}

/// [`get_fallback_host_realm`] with the `dns` module asking `dns`
/// (`None`: the module declines).
pub fn get_fallback_host_realm_with_dns(
    profile: &Profile,
    host: &str,
    dns: Option<&dyn DnsResolver>,
) -> Result<Vec<String>, i32> {
    let host = clean(host);
    let mods = modules(profile)?;
    for m in &mods {
        match m.fallback_realm(profile, dns, &host) {
            Err(PLUGIN_NO_HANDLE) => {}
            r => return r,
        }
    }
    get_default_realm_with(profile, dns, &mods).map(|r| vec![r])
}

/// `krb5_get_default_realm`: the first realm of the first module that
/// answers, or `KRB5_CONFIG_NODEFREALM`.
pub fn get_default_realm(profile: &Profile) -> Result<String, i32> {
    get_default_realm_with_dns(profile, system_dns())
}

/// [`get_default_realm`] with the `dns` module asking `dns` (`None`: the
/// module declines).
pub fn get_default_realm_with_dns(
    profile: &Profile,
    dns: Option<&dyn DnsResolver>,
) -> Result<String, i32> {
    get_default_realm_with(profile, dns, &modules(profile)?)
}

fn get_default_realm_with(
    profile: &Profile,
    dns: Option<&dyn DnsResolver>,
    mods: &[Module],
) -> Result<String, i32> {
    for m in mods {
        match m.default_realm(profile, dns) {
            Ok(r) => return r.into_iter().next().ok_or(CONFIG_NODEFREALM),
            Err(PLUGIN_NO_HANDLE) => {}
            Err(e) => return Err(e),
        }
    }
    Err(CONFIG_NODEFREALM)
}

/// [`get_host_realm`], with no realms on error.
pub fn host_realm(profile: &Profile, host: &str) -> Vec<String> {
    get_host_realm(profile, host).unwrap_or_default()
}

/// [`get_fallback_host_realm`], with no realms on error.
pub fn fallback_host_realm(profile: &Profile, host: &str) -> Vec<String> {
    get_fallback_host_realm(profile, host).unwrap_or_default()
}

/// [`get_default_realm`], `None` on error.
pub fn default_realm(profile: &Profile) -> Option<String> {
    get_default_realm(profile).ok()
}

/// clean_hostname (hostrealm.c:301-310): fold to lowercase, strip one
/// trailing dot.
fn clean(host: &str) -> String {
    let mut h = host.to_lowercase();
    if h.ends_with('.') {
        h.pop();
    }
    h
}

/// k5_is_numeric_address (hostrealm.c:318-339): digits+dots with exactly
/// three dots, or any colon.
fn is_numeric_address(name: &str) -> bool {
    if name.bytes().all(|b| b.is_ascii_digit() || b == b'.')
        && name.bytes().filter(|&b| b == b'.').count() == 3
    {
        return true;
    }
    name.contains(':')
}

/// `[realms]` `<realm>` default_domain (krb5_get_realm_domain).
pub fn realm_domain(profile: &Profile, realm: &str) -> Option<String> {
    profile.get_string(&["realms", realm, "default_domain"])
}
