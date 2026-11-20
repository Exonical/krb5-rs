//! python-kdcproxy's configuration (`kdcproxy/config/__init__.py` and
//! `config/mit.py`): `kdcproxy.conf` realm sections, `[global] configs =
//! mit` for krb5.conf `[realms]`, and DNS SRV discovery.

use std::collections::HashMap;

use krb5_rs::locate::DnsResolver;
use krb5_rs::profile::Profile;

/// `KDCProxyConfig.default_filenames`, read in order (later files win).
pub const DEFAULT_FILES: [&str; 2] = ["/usr/local/etc/kdcproxy.conf", "/etc/kdcproxy.conf"];

const GLOBAL: &str = "global";

/// One INI section as configparser reads it: lowercased keys, last
/// assignment wins, indented lines continue the previous value.
type Ini = Vec<(String, HashMap<String, String>)>;

/// configparser's `read`: unreadable files are skipped.
pub fn parse_ini(text: &str, ini: &mut Ini) -> Result<(), String> {
    let mut cur: Option<usize> = None;
    let mut last_key: Option<String> = None;
    for (n, raw) in text.lines().enumerate() {
        let line = raw.trim_end();
        let trimmed = line.trim_start();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with(';') {
            continue;
        }
        if line.starts_with([' ', '\t']) {
            if let (Some(i), Some(k)) = (cur, &last_key) {
                let v = ini[i].1.entry(k.clone()).or_default();
                v.push('\n');
                v.push_str(trimmed);
                continue;
            }
        }
        if let Some(name) = trimmed.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            let i = match ini.iter().position(|(s, _)| s == name) {
                Some(i) => i,
                None => {
                    ini.push((name.to_string(), HashMap::new()));
                    ini.len() - 1
                }
            };
            cur = Some(i);
            last_key = None;
            continue;
        }
        let Some(i) = cur else {
            return Err(format!("line {}: assignment before any section", n + 1));
        };
        let Some(sep) = trimmed.find(['=', ':']) else {
            return Err(format!("line {}: expected `key = value`", n + 1));
        };
        let key = trimmed[..sep].trim().to_lowercase();
        let value = trimmed[sep + 1..].trim().to_string();
        ini[i].1.insert(key.clone(), value);
        last_key = Some(key);
    }
    Ok(())
}

/// configparser's `getboolean`.
fn boolean(v: &str) -> Result<bool, String> {
    match v.to_lowercase().as_str() {
        "1" | "yes" | "true" | "on" => Ok(true),
        "0" | "no" | "false" | "off" => Ok(false),
        _ => Err(format!("not a boolean: {v}")),
    }
}

#[derive(Default, Debug)]
struct Section {
    use_dns: Option<bool>,
    silence_port_warn: Option<bool>,
    dns_realm_discovery: Option<bool>,
    kerberos: Vec<String>,
    kpasswd: Vec<String>,
}

/// `MITConfig`: server URIs from krb5.conf `[realms]`.
#[derive(Default, Debug)]
struct MitConfig {
    realms: HashMap<String, MitRealm>,
}

#[derive(Default, Debug)]
struct MitRealm {
    kdc: Vec<String>,
    admin_server: Vec<String>,
    kpasswd_server: Vec<String>,
}

/// Whether `s` would give `urlparse` a host name (it has a `scheme://`).
fn has_netloc(s: &str) -> bool {
    s.split_once("://").is_some_and(|(scheme, rest)| {
        !scheme.is_empty()
            && scheme
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "+-.".contains(c))
            && !rest.is_empty()
    })
}

impl MitConfig {
    fn from_profile(profile: &Profile) -> MitConfig {
        let mut realms = HashMap::new();
        for realm in profile.subsection_names(&["realms"]) {
            let mut r = MitRealm::default();
            for key in ["kdc", "admin_server", "kpasswd_server"] {
                for hostport in profile.get_values(&["realms", &realm, key]) {
                    let uri = if has_netloc(&hostport) {
                        if key == "admin_server"
                            && Uri::parse(&hostport).is_some_and(|u| u.port.is_some())
                        {
                            Some(format!("kpasswd://{}", strip_port(host_part(&hostport))))
                        } else {
                            Some(hostport)
                        }
                    } else {
                        let scheme = if key == "kdc" { "kerberos" } else { "kpasswd" };
                        if key == "admin_server" {
                            Some(format!("kpasswd://{}", strip_port(&hostport)))
                        } else {
                            Some(format!("{scheme}://{hostport}"))
                        }
                    };
                    let list = match key {
                        "kdc" => &mut r.kdc,
                        "admin_server" => &mut r.admin_server,
                        _ => &mut r.kpasswd_server,
                    };
                    list.extend(uri);
                }
            }
            realms.insert(realm, r);
        }
        MitConfig { realms }
    }

    fn lookup(&self, realm: &str, kpasswd: bool) -> Vec<String> {
        let Some(r) = get_ci(&self.realms, realm) else {
            return Vec::new();
        };
        if kpasswd {
            r.kpasswd_server
                .iter()
                .chain(&r.admin_server)
                .cloned()
                .collect()
        } else {
            r.kdc.clone()
        }
    }
}

/// The `host[:port]` after `scheme://`, without any path.
fn host_part(uri: &str) -> &str {
    let rest = uri.split_once("://").map_or(uri, |(_, r)| r);
    rest.split('/').next().unwrap_or(rest)
}

/// `hostport.split(':', 1)[0]` for names, keeping a bracketed IPv6 address.
fn strip_port(hostport: &str) -> &str {
    if hostport.starts_with('[') {
        return hostport.find(']').map_or(hostport, |i| &hostport[..=i]);
    }
    hostport.split(':').next().unwrap_or(hostport)
}

/// A parsed server URI: `kerberos[+tcp|+udp]://host[:port]` or `kpasswd...`.
#[derive(Debug, PartialEq, Eq)]
pub struct Uri {
    pub scheme: String,
    pub transport: Option<String>,
    pub host: String,
    pub port: Option<u16>,
}

impl Uri {
    /// `urlparse` as `Application.__call__` uses it. `None` for anything
    /// it would skip.
    pub fn parse(s: &str) -> Option<Uri> {
        let (scheme, rest) = s.split_once("://")?;
        let scheme = scheme.to_lowercase();
        let (base, transport) = match scheme.split_once('+') {
            Some((b, t)) => (b.to_string(), Some(t.to_string())),
            None => (scheme.clone(), None),
        };
        let netloc = rest.split(['/', '?', '#']).next()?;
        let netloc = netloc.rsplit_once('@').map_or(netloc, |(_, h)| h);
        let (host, port) = if let Some(v6) = netloc.strip_prefix('[') {
            let (h, after) = v6.split_once(']')?;
            (h.to_string(), after.strip_prefix(':'))
        } else {
            match netloc.split_once(':') {
                Some((h, p)) => (h.to_string(), Some(p)),
                None => (netloc.to_string(), None),
            }
        };
        let port = match port {
            Some("") | None => None,
            Some(p) => Some(p.parse().ok()?),
        };
        if host.is_empty() {
            return None;
        }
        Some(Uri {
            scheme: base,
            transport,
            host: host.to_lowercase(),
            port,
        })
    }
}

/// `MetaResolver` over `KDCProxyConfig`, the optional `MITConfig` and DNS.
pub struct Config {
    sections: HashMap<String, Section>,
    mit: Option<MitConfig>,
}

impl Config {
    /// `KDCProxyConfig.__init__` from the INI text of the config files and
    /// the krb5.conf profile for `configs = mit`.
    pub fn new(ini: &Ini, profile: impl FnOnce() -> Profile) -> Result<Config, String> {
        let mut sections = HashMap::new();
        let mut mit = None;
        for (name, kv) in ini {
            let mut s = Section::default();
            let get_bool = |k: &str| kv.get(k).map(|v| boolean(v)).transpose();
            s.use_dns = get_bool("use_dns")?;
            s.silence_port_warn = get_bool("silence_port_warn")?;
            if name == GLOBAL {
                s.dns_realm_discovery = get_bool("dns_realm_discovery")?;
                if let Some(m) = kv.get("configs") {
                    if m == "mit" {
                        mit = Some(());
                    } else {
                        tracing::error!(
                            "Error reading config: No module named 'kdcproxy.config.{m}'"
                        );
                    }
                }
            } else if !name.starts_with('*') {
                for (key, list) in [("kerberos", &mut s.kerberos), ("kpasswd", &mut s.kpasswd)] {
                    if let Some(v) = kv.get(key) {
                        list.extend(v.split_whitespace().map(str::to_string));
                    }
                }
            }
            sections.insert(name.clone(), s);
        }
        Ok(Config {
            sections,
            mit: mit.map(|()| MitConfig::from_profile(&profile())),
        })
    }

    /// MS-KKDCP 2.2.2: target-domain "is not case-sensitive".
    fn section(&self, name: &str) -> Option<&Section> {
        get_ci(&self.sections, name)
            .filter(|_| !name.eq_ignore_ascii_case(GLOBAL) || name == GLOBAL)
    }

    /// Exact realm section, then `*suffix` sections from the longest.
    fn realm_rules(realm: &str) -> impl Iterator<Item = String> + '_ {
        let labels: Vec<&str> = realm.split('.').collect();
        std::iter::once(realm.to_string())
            .chain((0..labels.len()).map(move |i| format!("*{}", labels[i..].join("."))))
    }

    fn realm_configured(&self, realm: &str) -> bool {
        Self::realm_rules(realm).any(|r| self.section(&r).is_some())
            || self
                .mit
                .as_ref()
                .is_some_and(|m| get_ci(&m.realms, realm).is_some())
    }

    /// `KDCProxyConfig.param`: realm, wildcard, global, then the default.
    fn param(&self, realm: Option<&str>, get: fn(&Section) -> Option<bool>, default: bool) -> bool {
        realm
            .into_iter()
            .flat_map(Self::realm_rules)
            .chain(std::iter::once(GLOBAL.to_string()))
            .find_map(|r| self.section(&r).and_then(get))
            .unwrap_or(default)
    }

    /// `MetaResolver.lookup`: the realm's server URIs, deduplicated.
    pub fn lookup(&self, realm: &str, kpasswd: bool, dns: Option<&dyn DnsResolver>) -> Vec<String> {
        if realm == GLOBAL {
            return Vec::new();
        }
        let from_conf = self
            .section(realm)
            .map(|s| {
                if kpasswd {
                    s.kpasswd.clone()
                } else {
                    s.kerberos.clone()
                }
            })
            .unwrap_or_default();
        let servers = unique(from_conf);
        if !servers.is_empty() {
            return servers;
        }
        if let Some(m) = &self.mit {
            let servers = unique(m.lookup(realm, kpasswd));
            if !servers.is_empty() {
                return servers;
            }
        }
        let allowed = (self.realm_configured(realm)
            || self.param(None, |s| s.dns_realm_discovery, false))
            && self.param(Some(realm), |s| s.use_dns, true);
        match dns {
            Some(dns) if allowed => {
                let silenced = self.param(Some(realm), |s| s.silence_port_warn, false);
                unique(dns_lookup(dns, realm, kpasswd, silenced))
            }
            _ => Vec::new(),
        }
    }
}

fn unique(items: Vec<String>) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    items
        .into_iter()
        .filter(|i| seen.insert(i.clone()))
        .collect()
}

/// `DNSResolver.lookup`: `_kerberos` (or `_kpasswd`, then `_kerberos-adm`)
/// SRV records over TCP then UDP, by priority.
fn dns_lookup(dns: &dyn DnsResolver, realm: &str, kpasswd: bool, silenced: bool) -> Vec<String> {
    let service = if kpasswd { "kpasswd" } else { "kerberos" };
    let expected = if kpasswd { 464 } else { 88 };
    let mut out = Vec::new();
    for proto in ["tcp", "udp"] {
        let query = |sv: &str| {
            let mut r = dns
                .srv(&format!("_{sv}._{proto}.{realm}."))
                .unwrap_or_default();
            r.sort_by_key(|r| r.priority);
            r
        };
        let mut sv = service;
        let mut records = query(sv);
        if records.is_empty() && kpasswd {
            sv = "kerberos-adm";
            records = query(sv);
        }
        for r in records {
            let host = r.target.trim_end_matches('.');
            if host.is_empty() {
                continue;
            }
            if !silenced && r.port != expected {
                tracing::warn!(
                    "DNS SRV record _{sv}._{proto}.{realm}. points to KDC {host} with \
                     non-standard port {} ({expected} expected)",
                    r.port
                );
            }
            out.push(format!("{service}://{host}:{}", r.port));
        }
    }
    out
}

/// `map[name]`, else the entry whose key matches `name` ignoring case.
fn get_ci<'a, V>(map: &'a HashMap<String, V>, name: &str) -> Option<&'a V> {
    map.get(name).or_else(|| {
        map.iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use krb5_rs::locate::{SrvRecord, UriRecord};

    fn config(text: &str, krb5: &str) -> Config {
        let mut ini = Ini::new();
        parse_ini(text, &mut ini).unwrap();
        Config::new(&ini, || Profile::parse(krb5).unwrap()).unwrap()
    }

    struct Dns;
    impl DnsResolver for Dns {
        fn srv(&self, name: &str) -> Result<Vec<SrvRecord>, ()> {
            let rec = |priority, target: &str, port| SrvRecord {
                priority,
                weight: 0,
                port,
                target: target.into(),
            };
            Ok(match name {
                "_kerberos._tcp.DNS.TEST." => {
                    vec![rec(2, "b.dns.test.", 88), rec(1, "a.dns.test.", 88)]
                }
                "_kerberos-adm._udp.DNS.TEST." => vec![rec(0, "adm.dns.test.", 749)],
                _ => vec![],
            })
        }
        fn uri(&self, _: &str) -> Result<Vec<UriRecord>, ()> {
            Ok(vec![])
        }
    }

    #[test]
    fn realm_sections() {
        let c = config(
            "[EXAMPLE.COM]\nkerberos = kerberos://kdc1:88 kerberos+tcp://kdc2\n  kerberos://kdc1:88\nkpasswd = kpasswd://kdc1\n",
            "",
        );
        assert_eq!(
            c.lookup("EXAMPLE.COM", false, None),
            ["kerberos://kdc1:88", "kerberos+tcp://kdc2"]
        );
        assert_eq!(c.lookup("EXAMPLE.COM", true, None), ["kpasswd://kdc1"]);
        assert!(c.lookup("OTHER.COM", false, Some(&Dns)).is_empty());
        assert!(c.lookup("global", false, None).is_empty());
    }

    #[test]
    fn realm_case_insensitive() {
        let mut ini = Vec::new();
        parse_ini(
            "[global]\nconfigs = mit\n[EXAMPLE.COM]\nkerberos = kerberos://kdc1\n[*CORP.COM]\nuse_dns = false\n",
            &mut ini,
        )
        .unwrap();
        let c = Config::new(&ini, || {
            Profile::parse("[realms]\nAD.CONTOSO.COM = {\n kdc = dc1.contoso.com\n}\n").unwrap()
        })
        .unwrap();
        assert_eq!(c.lookup("example.com", false, None), ["kerberos://kdc1"]);
        assert_eq!(
            c.lookup("ad.contoso.com", false, None),
            ["kerberos://dc1.contoso.com"]
        );
        assert!(!c.param(Some("eu.corp.com"), |s| s.use_dns, true));
    }

    #[test]
    fn mit_realms() {
        let c = config(
            "[global]\nconfigs = mit\n",
            "[realms]\nEXAMPLE.COM = {\n kdc = kdc1.example.com:88\n kdc = https://proxy/KdcProxy\n admin_server = kdc1.example.com:749\n kpasswd_server = kdc1.example.com\n}\n",
        );
        assert_eq!(
            c.lookup("EXAMPLE.COM", false, None),
            ["kerberos://kdc1.example.com:88", "https://proxy/KdcProxy"]
        );
        assert_eq!(
            c.lookup("EXAMPLE.COM", true, None),
            ["kpasswd://kdc1.example.com"]
        );
    }

    #[test]
    fn dns_discovery() {
        assert!(config("", "")
            .lookup("DNS.TEST", false, Some(&Dns))
            .is_empty());
        let c = config("[global]\ndns_realm_discovery = true\n", "");
        assert_eq!(
            c.lookup("DNS.TEST", false, Some(&Dns)),
            ["kerberos://a.dns.test:88", "kerberos://b.dns.test:88"]
        );
        assert_eq!(
            c.lookup("DNS.TEST", true, Some(&Dns)),
            ["kpasswd://adm.dns.test:749"]
        );
        let c = config(
            "[*TEST]\nuse_dns = false\n[global]\ndns_realm_discovery = yes\n",
            "",
        );
        assert!(c.lookup("DNS.TEST", false, Some(&Dns)).is_empty());
        let c = config("[DNS.TEST]\n", "");
        assert_eq!(c.lookup("DNS.TEST", false, Some(&Dns)).len(), 2);
    }

    #[test]
    fn uris() {
        assert_eq!(
            Uri::parse("Kerberos+TCP://KDC1:750/x"),
            Some(Uri {
                scheme: "kerberos".into(),
                transport: Some("tcp".into()),
                host: "kdc1".into(),
                port: Some(750)
            })
        );
        assert_eq!(Uri::parse("kpasswd://[::1]:464").unwrap().host, "::1");
        assert_eq!(Uri::parse("kerberos://kdc").unwrap().port, None);
        assert!(Uri::parse("kerberos://kdc:x").is_none());
        assert!(Uri::parse("kdc:88").is_none());
    }

    #[test]
    fn bad_boolean() {
        let mut ini = Ini::new();
        parse_ini("[global]\nuse_dns = maybe\n", &mut ini).unwrap();
        assert!(Config::new(&ini, || Profile::parse("").unwrap()).is_err());
    }
}
