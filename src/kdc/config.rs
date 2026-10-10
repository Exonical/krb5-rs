//! kdc.conf realm configuration (MIT kdc/main.c:240-330 and 600-700,
//! lib/apputils/net-server.c listen syntax, include/osconf.hin defaults).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};
use std::path::PathBuf;
use std::time::Duration;

use super::KdcConfig;
use crate::crypto::{enctype_from_name, parse_enctype_list, parse_keysalt_list, SaltType};
use crate::profile::{Profile, ProfileError};

/// MIT `KRB5_DEFAULT_SUPPORTED_ENCTYPES` (osconf.hin:109-111).
const DEFAULT_SUPPORTED_ENCTYPES: &str =
    "aes256-cts-hmac-sha1-96:normal aes128-cts-hmac-sha1-96:normal";
/// MIT `KDC_DIR` (osconf.hin:72, the default `LOCALSTATEDIR` is `/usr/local/var`).
const KDC_DIR: &str = "/usr/local/var/krb5kdc";
/// MIT `DEFAULT_KDC_PORTLIST` (osconf.hin:99).
const DEFAULT_KDC_PORTLIST: &str = "88";
/// MIT `KRB5_DEFAULT_PORT`.
const DEFAULT_PORT: u16 = 88;
/// MIT `MAX_DGRAM_SIZE` (osconf.hin:113).
const MAX_DGRAM_SIZE: usize = 65536;
/// MIT `KRB5_KDB_MAX_LIFE` / `KRB5_KDB_MAX_RLIFE` (k5-int.h:132-133), seconds.
const DEFAULT_MAX_LIFE: i32 = 24 * 3600;
const DEFAULT_MAX_RENEWABLE_LIFE: i32 = 7 * 24 * 3600;
/// Default `clockskew` (krb5.conf `[libdefaults]`).
const DEFAULT_CLOCKSKEW: i32 = 300;

/// Configuration error.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// A profile value could not be parsed.
    #[error("profile error: {0}")]
    Profile(#[from] ProfileError),
    /// A value is present but unusable.
    #[error("invalid configuration: {0}")]
    Invalid(String),
}

/// Everything the KDC needs to know about one realm.
///
/// `database_name` points at this crate's own database file format
/// ([`crate::kdc::kdb::FileStore`]), not an MIT db2/LMDB database.
#[derive(Debug, Clone)]
pub struct RealmConfig {
    /// KDC behaviour settings.
    pub kdc: KdcConfig,
    /// Path of the principal database (`database_name`).
    pub database_name: PathBuf,
    /// Path of the master key stash (`key_stash_file`).
    pub key_stash_file: PathBuf,
    /// Master key enctype (`master_key_type`).
    pub master_key_type: i32,
    /// Key/salt combinations generated for new keys (`supported_enctypes`).
    pub supported_keysalts: Vec<(i32, SaltType)>,
    /// UDP listen addresses (`kdc_listen` / `kdc_ports`).
    pub udp_listen: Vec<SocketAddr>,
    /// TCP listen addresses (`kdc_tcp_listen` / `kdc_tcp_ports`, defaulting
    /// to the UDP list as in kdc/main.c:969-971).
    pub tcp_listen: Vec<SocketAddr>,
}

/// The realm to serve when none is given: the only `[realms]` subsection of
/// kdc.conf, else krb5.conf `[libdefaults] default_realm`.
pub fn default_realm(kdc_conf: &Profile, krb5_conf: Option<&Profile>) -> Option<String> {
    let realms = kdc_conf.subsection_names(&["realms"]);
    if let [only] = realms.as_slice() {
        return Some(only.clone());
    }
    krb5_conf.and_then(|p| p.get_string(&["libdefaults", "default_realm"]))
}

/// `kdc_listen`, falling back to the old `kdc_ports` name
/// (kdc/main.c:256-266, 621-627).
fn listen_setting(kdc_conf: &Profile, realm: &str, new: &str, old: &str) -> Option<String> {
    let at = |section: &[&str], key: &str| {
        let mut path = section.to_vec();
        path.push(key);
        kdc_conf.get_string(&path)
    };
    at(&["realms", realm], new)
        .or_else(|| at(&["realms", realm], old))
        .or_else(|| at(&["kdcdefaults"], new))
        .or_else(|| at(&["kdcdefaults"], old))
}

/// Parse one MIT listen specifier list (net-server.c:381-430 with
/// ADDRESSES_DELIM ",; " and `k5_parse_host_string`,
/// parse_host_string.c:70-130): `port`, `host`, `host:port`, `[v6]:port`.
/// A bare port or no host binds both wildcard addresses (getaddrinfo with
/// AI_PASSIVE, net-server.c:956-957). Pathnames are skipped.
pub fn parse_listen_addresses(s: &str, default_port: u16) -> Result<Vec<SocketAddr>, ConfigError> {
    let bad = |t: &str| ConfigError::Invalid(format!("bad listen address {t:?}"));
    let mut out: Vec<SocketAddr> = Vec::new();
    for token in s.split([',', ';', ' ']).filter(|t| !t.is_empty()) {
        if token.starts_with('/') {
            continue;
        }
        let (host, port): (Option<&str>, &str) = if token.bytes().all(|b| b.is_ascii_digit()) {
            (None, token)
        } else if let Some(rest) = token.strip_prefix('[') {
            let (h, after) = rest.split_once(']').ok_or_else(|| bad(token))?;
            (Some(h), after.strip_prefix(':').unwrap_or(""))
        } else {
            match token.split_once(':') {
                Some((h, p)) if !h.is_empty() => (Some(h), p),
                Some(_) => return Err(bad(token)),
                None => (Some(token), ""),
            }
        };
        let port: u16 = if port.is_empty() {
            default_port
        } else {
            port.parse().map_err(|_| bad(token))?
        };
        let addrs: Vec<SocketAddr> = match host {
            None => vec![
                SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port),
                SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port),
            ],
            Some(h) => match h.parse::<IpAddr>() {
                Ok(ip) => vec![SocketAddr::new(ip, port)],
                Err(_) => (h, port)
                    .to_socket_addrs()
                    .map_err(|_| bad(token))?
                    .collect(),
            },
        };
        for a in addrs {
            if !out.contains(&a) {
                out.push(a);
            }
        }
    }
    Ok(out)
}

impl RealmConfig {
    /// Build the configuration for `realm` (kdc/main.c `init_realm` and
    /// `initialize_realms`). `krb5_conf` supplies `[libdefaults]`
    /// `clockskew` and `permitted_enctypes`; kdc.conf is used if absent.
    pub fn from_profiles(
        kdc_conf: &Profile,
        krb5_conf: Option<&Profile>,
        realm: &str,
    ) -> Result<Self, ConfigError> {
        let r = |key: &str| kdc_conf.get_string(&["realms", realm, key]);
        let libdefaults = krb5_conf.unwrap_or(kdc_conf);

        let max_life = deltat(kdc_conf, &["realms", realm, "max_life"], DEFAULT_MAX_LIFE)?;
        let max_renewable_life = deltat(
            kdc_conf,
            &["realms", realm, "max_renewable_life"],
            DEFAULT_MAX_RENEWABLE_LIFE,
        )?;
        let clockskew = deltat(
            libdefaults,
            &["libdefaults", "clockskew"],
            DEFAULT_CLOCKSKEW,
        )?;
        let max_dgram = kdc_conf.get_integer(
            &["kdcdefaults", "kdc_max_dgram_reply_size"],
            MAX_DGRAM_SIZE as i64,
        )?;

        let default_etypes = [18, 17, 20, 19];
        let supported_enctypes =
            match libdefaults.get_string(&["libdefaults", "permitted_enctypes"]) {
                Some(s) => {
                    let list = parse_enctype_list(&s, &default_etypes);
                    if list.is_empty() {
                        return Err(ConfigError::Invalid(
                            "permitted_enctypes names no supported enctype".into(),
                        ));
                    }
                    list
                }
                None => default_etypes.to_vec(),
            };

        let keysalts_str =
            r("supported_enctypes").unwrap_or_else(|| DEFAULT_SUPPORTED_ENCTYPES.into());
        let supported_keysalts =
            parse_keysalt_list(&keysalts_str).map_err(|e| ConfigError::Invalid(e.to_string()))?;
        if supported_keysalts.is_empty() {
            return Err(ConfigError::Invalid(
                "supported_enctypes names no supported enctype".into(),
            ));
        }

        let udp_str = listen_setting(kdc_conf, realm, "kdc_listen", "kdc_ports")
            .unwrap_or_else(|| DEFAULT_KDC_PORTLIST.into());
        let tcp_str = listen_setting(kdc_conf, realm, "kdc_tcp_listen", "kdc_tcp_ports")
            .unwrap_or_else(|| udp_str.clone());

        let mut kdc = KdcConfig::new(realm);
        kdc.max_life = Duration::from_secs(u64::try_from(max_life).unwrap_or(0));
        kdc.max_renewable_life =
            Duration::from_secs(u64::try_from(max_renewable_life).unwrap_or(0));
        kdc.supported_enctypes = supported_enctypes;
        kdc.clockskew = Duration::from_secs(u64::try_from(clockskew).unwrap_or(0));
        kdc.max_dgram_reply_size = usize::try_from(max_dgram).unwrap_or(MAX_DGRAM_SIZE);
        kdc.realm_profile = krb5_conf.cloned();
        kdc.host_based_services = service_list(kdc_conf, realm, "host_based_services");
        kdc.no_host_referral = service_list(kdc_conf, realm, "no_host_referral");
        kdc.reject_bad_transit =
            kdc_conf.get_boolean(&["realms", realm, "reject_bad_transit"], true)?;
        kdc.disable_pac = kdc_conf.get_boolean(&["realms", realm, "disable_pac"], false)?;

        Ok(Self {
            kdc,
            database_name: r("database_name")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from(format!("{KDC_DIR}/principal"))),
            key_stash_file: r("key_stash_file")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from(format!("{KDC_DIR}/.k5.{realm}"))),
            master_key_type: r("master_key_type")
                .and_then(|s| enctype_from_name(&s))
                .unwrap_or(18),
            supported_keysalts,
            udp_listen: parse_listen_addresses(&udp_str, DEFAULT_PORT)?,
            tcp_listen: parse_listen_addresses(&tcp_str, DEFAULT_PORT)?,
        })
    }
}

/// A service list: all `[kdcdefaults]` values followed by all realm values
/// (`combine`, kdc/main.c:171-189, over `krb5_aprof_get_string_all`), split
/// on whitespace and commas (`in_list`, do_tgs_req.c:420-435).
fn service_list(kdc_conf: &Profile, realm: &str, key: &str) -> Vec<String> {
    let mut values = kdc_conf.get_values(&["kdcdefaults", key]);
    values.extend(kdc_conf.get_values(&["realms", realm, key]));
    values
        .iter()
        .flat_map(|v| v.split(|c: char| c.is_whitespace() || c == ','))
        .filter(|t| !t.is_empty())
        .map(str::to_string)
        .collect()
}

fn deltat(p: &Profile, names: &[&str], default: i32) -> Result<i32, ConfigError> {
    Ok(p.get_deltat(names, default)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// kdc.conf written by tests/kdc/setup.sh.
    const SETUP_KDC_CONF: &str = "[kdcdefaults]\n    kdc_ports = 88\n    kdc_tcp_ports = 88\n\
[realms]\n    TEST.REALM = {\n        database_name = /var/lib/krb5kdc/principal\n        \
admin_keytab = /var/lib/krb5kdc/kadm5.keytab\n        acl_file = /etc/krb5kdc/kadm5.acl\n        \
key_stash_file = /etc/krb5kdc/stash\n        max_life = 24h\n        max_renewable_life = 7d\n        \
supported_enctypes = aes256-cts-hmac-sha1-96:normal aes128-cts-hmac-sha1-96:normal\n        \
default_principal_flags = +preauth\n    }\n";

    fn profile(s: &str) -> Profile {
        Profile::parse(s).expect("parse")
    }

    #[test]
    fn from_profiles_parses_setup_sh_kdc_conf() {
        let cfg = RealmConfig::from_profiles(&profile(SETUP_KDC_CONF), None, "TEST.REALM")
            .expect("config");
        assert_eq!(
            cfg.database_name,
            PathBuf::from("/var/lib/krb5kdc/principal")
        );
        assert_eq!(cfg.key_stash_file, PathBuf::from("/etc/krb5kdc/stash"));
        assert_eq!(cfg.kdc.max_life, Duration::from_secs(24 * 3600));
        assert_eq!(
            cfg.kdc.max_renewable_life,
            Duration::from_secs(7 * 24 * 3600)
        );
        assert_eq!(
            cfg.supported_keysalts,
            vec![(18, SaltType::Normal), (17, SaltType::Normal)]
        );
        assert_eq!(cfg.udp_listen.len(), 2);
        assert!(cfg.udp_listen.iter().all(|a| a.port() == 88));
        assert_eq!(cfg.tcp_listen, cfg.udp_listen);
        assert_eq!(cfg.master_key_type, 18);
    }

    #[test]
    fn from_profiles_applies_mit_defaults() {
        let cfg = RealmConfig::from_profiles(&profile("[realms]\n R = {\n }\n"), None, "R")
            .expect("config");
        assert_eq!(cfg.kdc.max_life, Duration::from_secs(86400));
        assert_eq!(cfg.kdc.max_renewable_life, Duration::from_secs(7 * 86400));
        assert_eq!(cfg.kdc.clockskew, Duration::from_secs(300));
        assert_eq!(cfg.kdc.max_dgram_reply_size, 65536);
        assert_eq!(cfg.kdc.supported_enctypes, vec![18, 17, 20, 19]);
        assert_eq!(
            cfg.database_name,
            PathBuf::from("/usr/local/var/krb5kdc/principal")
        );
        assert_eq!(
            cfg.key_stash_file,
            PathBuf::from("/usr/local/var/krb5kdc/.k5.R")
        );
        assert_eq!(cfg.supported_keysalts.len(), 2);
    }

    #[test]
    fn from_profiles_realm_overrides_kdcdefaults_and_old_names() {
        let kdc = profile(
            "[kdcdefaults]\n kdc_listen = 1000\n kdc_tcp_listen = 1001\n \
             kdc_max_dgram_reply_size = 1400\n[realms]\n R = {\n kdc_ports = 2000\n }\n",
        );
        let cfg = RealmConfig::from_profiles(&kdc, None, "R").expect("config");
        assert!(cfg.udp_listen.iter().all(|a| a.port() == 2000));
        assert!(cfg.tcp_listen.iter().all(|a| a.port() == 1001));
        assert_eq!(cfg.kdc.max_dgram_reply_size, 1400);
    }

    #[test]
    fn from_profiles_reads_libdefaults_from_krb5_conf() {
        let kdc = profile("[realms]\n R = {\n }\n");
        let krb5 = profile("[libdefaults]\n clockskew = 120\n permitted_enctypes = aes256-cts\n");
        let cfg = RealmConfig::from_profiles(&kdc, Some(&krb5), "R").expect("config");
        assert_eq!(cfg.kdc.clockskew, Duration::from_secs(120));
        assert_eq!(cfg.kdc.supported_enctypes, vec![18]);
    }

    #[test]
    fn from_profiles_rejects_unusable_enctype_settings() {
        let kdc = profile("[realms]\n R = {\n supported_enctypes = rc4-hmac:normal\n }\n");
        assert!(RealmConfig::from_profiles(&kdc, None, "R").is_err());
        let kdc = profile("[realms]\n R = {\n }\n");
        let krb5 = profile("[libdefaults]\n permitted_enctypes = rc4\n");
        assert!(RealmConfig::from_profiles(&kdc, Some(&krb5), "R").is_err());
    }

    #[test]
    fn parse_listen_addresses_bare_port_binds_both_wildcards() {
        let got = parse_listen_addresses("88", 88).expect("parse");
        assert_eq!(
            got,
            vec![
                "0.0.0.0:88".parse().expect("v4"),
                "[::]:88".parse().expect("v6")
            ]
        );
    }

    #[test]
    fn parse_listen_addresses_handles_hosts_ports_and_delimiters() {
        let got = parse_listen_addresses("127.0.0.1, [::1]:8888;10.0.0.1:99 /skipped", 88)
            .expect("parse");
        assert_eq!(
            got,
            vec![
                "127.0.0.1:88".parse().expect("a"),
                "[::1]:8888".parse().expect("b"),
                "10.0.0.1:99".parse().expect("c"),
            ]
        );
    }

    #[test]
    fn parse_listen_addresses_rejects_bad_ports() {
        assert!(parse_listen_addresses("127.0.0.1:99999", 88).is_err());
        assert!(parse_listen_addresses(":88", 88).is_err());
    }

    #[test]
    fn from_profiles_reads_referral_and_transit_settings() {
        let kdc = profile(
            "[kdcdefaults]\n host_based_services = http\n[realms]\n R = {\n \
             host_based_services = ftp, imap\n no_host_referral = *\n \
             reject_bad_transit = false\n disable_pac = true\n }\n",
        );
        let krb5 = profile("[domain_realm]\n .a.com = A.COM\n");
        let cfg = RealmConfig::from_profiles(&kdc, Some(&krb5), "R").expect("config");
        assert_eq!(cfg.kdc.host_based_services, vec!["http", "ftp", "imap"]);
        assert_eq!(cfg.kdc.no_host_referral, vec!["*"]);
        assert!(!cfg.kdc.reject_bad_transit);
        assert!(cfg.kdc.disable_pac);
        assert!(cfg.kdc.realm_profile.is_some());
        let plain = RealmConfig::from_profiles(&profile("[realms]\n R = {\n }\n"), None, "R")
            .expect("config");
        assert!(plain.kdc.reject_bad_transit && plain.kdc.realm_profile.is_none());
    }

    #[test]
    fn default_realm_prefers_sole_kdc_conf_realm_then_krb5_conf() {
        let one = profile("[realms]\n A = {\n }\n");
        assert_eq!(default_realm(&one, None), Some("A".into()));
        let two = profile("[realms]\n A = {\n }\n B = {\n }\n");
        assert_eq!(default_realm(&two, None), None);
        let krb5 = profile("[libdefaults]\n default_realm = B\n");
        assert_eq!(default_realm(&two, Some(&krb5)), Some("B".into()));
    }
}
