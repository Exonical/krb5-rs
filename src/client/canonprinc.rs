//! Host-based service name candidates (MIT os/sn2princ.c `k5_canonprinc`).

use rasn::types::GeneralString;

use crate::profile::{conf_boolean, Profile};
use crate::types::PrincipalName;

/// `dns_canonicalize_hostname` (init_ctx.c:240-248).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CanonHost {
    /// Use host names as given.
    False,
    /// Names were canonicalized with DNS when built.
    True,
    /// Try the name without DNS, then with DNS (MIT's default).
    Fallback,
}

/// The `[libdefaults]` settings `k5_canonprinc` uses.
#[derive(Debug, Clone)]
pub struct HostCanonicalization {
    /// `dns_canonicalize_hostname`. Default: fallback.
    pub dns_canonicalize_hostname: CanonHost,
    /// `rdns`. Default: true.
    pub rdns: bool,
    /// `qualify_shortname`; unset means the OS primary domain.
    pub qualify_shortname: Option<String>,
}

impl Default for HostCanonicalization {
    fn default() -> Self {
        Self {
            dns_canonicalize_hostname: CanonHost::Fallback,
            rdns: true,
            qualify_shortname: None,
        }
    }
}

impl HostCanonicalization {
    /// Read the settings from a krb5.conf profile.
    pub fn from_profile(profile: &Profile) -> Self {
        let mode = match profile.get_string(&["libdefaults", "dns_canonicalize_hostname"]) {
            Some(v) if v.eq_ignore_ascii_case("fallback") => CanonHost::Fallback,
            Some(v) => match conf_boolean(&v) {
                Some(true) => CanonHost::True,
                Some(false) => CanonHost::False,
                None => CanonHost::Fallback,
            },
            None => CanonHost::Fallback,
        };
        Self {
            dns_canonicalize_hostname: mode,
            rdns: profile
                .get_boolean(&["libdefaults", "rdns"], true)
                .unwrap_or(true),
            qualify_shortname: profile.get_string(&["libdefaults", "qualify_shortname"]),
        }
    }
}

/// `k5_primary_domain` (dnsglue.c): the resolver's default domain.
fn os_primary_domain() -> Option<String> {
    if let Ok(v) = std::env::var("LOCALDOMAIN") {
        return v.split_whitespace().next().map(str::to_string);
    }
    let conf = std::fs::read_to_string("/etc/resolv.conf").ok()?;
    let mut domain = None;
    for line in conf.lines() {
        let mut words = line.split_whitespace();
        match words.next() {
            Some("domain") | Some("search") => domain = words.next().map(str::to_string),
            _ => {}
        }
    }
    domain
}

/// `qualify_shortname` (sn2princ.c).
fn qualify_shortname(c: &HostCanonicalization, host: &str) -> Option<String> {
    let domain = match &c.qualify_shortname {
        Some(d) => d.clone(),
        None => os_primary_domain()?,
    };
    (!domain.is_empty()).then(|| format!("{host}.{domain}"))
}

/// The getaddrinfo(AI_CANONNAME) name, then the getnameinfo(NI_NAMEREQD)
/// name with `rdns`, looked up with hickory-resolver (the crate has no
/// unsafe code for libc's resolver).
#[cfg(feature = "dns")]
async fn dns_canonical_name(host: &str, rdns: bool) -> Option<String> {
    use hickory_resolver::proto::rr::RData;
    let resolver = hickory_resolver::Resolver::builder_tokio().ok()?.build();
    let lookup = resolver.lookup_ip(host).await.ok()?;
    let mut canon = lookup
        .as_lookup()
        .records()
        .iter()
        .rev()
        .find_map(|r| match r.data() {
            RData::CNAME(c) => Some(c.0.to_utf8()),
            _ => None,
        })
        .unwrap_or_else(|| host.to_string());
    if rdns {
        if let Some(ip) = lookup.iter().next() {
            if let Some(ptr) = resolver
                .reverse_lookup(ip)
                .await
                .ok()
                .and_then(|r| r.iter().next().map(|n| n.0.to_utf8()))
            {
                canon = ptr;
            }
        }
    }
    Some(canon)
}

/// Without a DNS resolver the lookup fails, as getaddrinfo would.
#[cfg(not(feature = "dns"))]
async fn dns_canonical_name(_host: &str, _rdns: bool) -> Option<String> {
    None
}

/// `expand_hostname` (sn2princ.c).
async fn expand_hostname(c: &HostCanonicalization, host: &str, use_dns: bool) -> String {
    let mut canon = None;
    if use_dns {
        canon = dns_canonical_name(host, c.rdns).await;
    }
    let mut canon = match canon {
        Some(n) => n,
        None if !host.contains('.') => {
            qualify_shortname(c, host).unwrap_or_else(|| host.to_string())
        }
        None => host.to_string(),
    };
    canon.make_ascii_lowercase();
    if canon.ends_with('.') {
        canon.pop();
    }
    canon
}

/// `split_trailer` (sn2princ.c): a ":port" suffix kept off the host.
fn split_trailer(s: &str) -> (&str, &str) {
    match s.find(':') {
        Some(i) if s.len() - i != 1 && !s[i + 1..].contains(':') => (&s[..i], &s[i..]),
        _ => (s, ""),
    }
}

/// The `k5_canonprinc` iterator with `no_hostrealm` set.
pub(crate) struct CanonPrinc<'a> {
    princ: &'a PrincipalName,
    step: u32,
    canonhost: Option<String>,
}

impl<'a> CanonPrinc<'a> {
    pub(crate) fn new(princ: &'a PrincipalName) -> Self {
        Self {
            princ,
            step: 0,
            canonhost: None,
        }
    }

    /// The next candidate name, or `None` when there are no more.
    pub(crate) async fn next(&mut self, c: &HostCanonicalization) -> Option<PrincipalName> {
        self.step += 1;
        let p = self.princ;
        if p.name_type != 3
            || p.name_string.len() != 2
            || p.name_string[1].as_bytes().is_empty()
            || c.dns_canonicalize_hostname != CanonHost::Fallback
        {
            return (self.step == 1).then(|| p.clone());
        }
        if self.step > 2 {
            return None;
        }
        let name = String::from_utf8_lossy(p.name_string[1].as_bytes()).into_owned();
        let (host, trailer) = split_trailer(&name);
        let combined = format!(
            "{}{trailer}",
            expand_hostname(c, host, self.step == 2).await
        );
        if self.canonhost.as_deref() == Some(combined.as_str()) {
            return None;
        }
        self.canonhost = Some(combined.clone());
        Some(PrincipalName {
            name_type: p.name_type,
            name_string: vec![
                p.name_string[0].clone(),
                GeneralString::from_bytes(combined.as_bytes()).ok()?,
            ],
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_trailer_keeps_a_single_port() {
        assert_eq!(split_trailer("host:8080"), ("host", ":8080"));
        assert_eq!(split_trailer("host:"), ("host:", ""));
        assert_eq!(split_trailer("a:b:c"), ("a:b:c", ""));
    }

    #[tokio::test]
    async fn fallback_qualifies_lowercases_and_strips_the_dot() {
        let c = HostCanonicalization {
            qualify_shortname: Some("Example.COM.".into()),
            rdns: false,
            ..Default::default()
        };
        let p = PrincipalName::new_srv_hst("HTTP", "Web:8080");
        let mut it = CanonPrinc::new(&p);
        let first = it.next(&c).await.expect("candidate");
        assert_eq!(first.to_string(), "HTTP/web.example.com:8080");
    }

    #[tokio::test]
    async fn non_host_names_and_non_fallback_yield_the_name_once() {
        let c = HostCanonicalization {
            dns_canonicalize_hostname: CanonHost::False,
            ..Default::default()
        };
        let p = PrincipalName::new_srv_hst("HTTP", "web");
        let mut it = CanonPrinc::new(&p);
        assert_eq!(it.next(&c).await, Some(p.clone()));
        assert_eq!(it.next(&c).await, None);
        let inst = PrincipalName::new_srv_inst("HTTP", "web");
        let mut it = CanonPrinc::new(&inst);
        assert_eq!(
            it.next(&HostCanonicalization::default()).await,
            Some(inst.clone())
        );
        assert_eq!(it.next(&HostCanonicalization::default()).await, None);
    }
}
