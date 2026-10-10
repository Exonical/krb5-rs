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

/// Default port of the propagation listener (MIT kpropd's `krb5_prop`).
const DEFAULT_KPROP_PORT: u16 = 754;
/// Default `kprop_poll_interval`, seconds.
const DEFAULT_KPROP_POLL_INTERVAL: i32 = 60;

/// Database propagation settings: krb5-rs extensions to kdc.conf `[realms]`
/// with no MIT counterpart (MIT uses kprop/kpropd push).
///
/// A primary sets `kprop_listen`; a replica sets `kprop_primary` plus one of
/// `kprop_keytab` and `kprop_password_file`. Both together is an error.
#[derive(Debug, Clone, Default)]
pub struct PropagationSettings {
    /// `kprop_listen`: where the primary serves replicas (empty = off).
    pub listen: Vec<SocketAddr>,
    /// `kprop_primary` (`host:port`): set on replicas.
    pub primary: Option<String>,
    /// `kprop_primary_kdc` (`host:port`): the KDC replicas get their ticket
    /// from (default: the `kprop_primary` host on port 88).
    pub primary_kdc: Option<String>,
    /// `kprop_service`: the kprop service principal as `name@REALM`
    /// (default `kprop/primary@REALM`).
    pub service: String,
    /// `kprop_client`: the replica principal as `name@REALM` (default
    /// `kprop/replica@REALM`).
    pub client: String,
    /// `kprop_acl`: principals (`name@REALM`) the primary lets pull
    /// (default: `kprop_client`).
    pub acl: Vec<String>,
    /// `kprop_keytab`: the replica's key.
    pub keytab: Option<PathBuf>,
    /// `kprop_password_file`: file whose first line is the replica's password.
    pub password_file: Option<PathBuf>,
    /// `kprop_poll_interval` (deltat, default 60 s).
    pub poll_interval: Duration,
}

impl PropagationSettings {
    /// Whether this KDC is a replica (`kprop_primary` set).
    pub fn is_replica(&self) -> bool {
        self.primary.is_some()
    }
}

fn with_realm(name: &str, realm: &str) -> String {
    if name.contains('@') {
        name.to_string()
    } else {
        format!("{name}@{realm}")
    }
}

/// `host:port` with the port replaced by `default_port`.
fn host_with_port(addr: &str, default_port: u16) -> String {
    match addr.rsplit_once(':') {
        Some((host, port)) if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => {
            // [v6]:port keeps its brackets; a bare v6 address has several colons.
            if host.contains(':') && !host.ends_with(']') {
                format!("[{addr}]:{default_port}")
            } else {
                format!("{host}:{default_port}")
            }
        }
        _ => format!("{addr}:{default_port}"),
    }
}

fn propagation_settings(
    kdc_conf: &Profile,
    realm: &str,
) -> Result<PropagationSettings, ConfigError> {
    let r = |key: &str| kdc_conf.get_string(&["realms", realm, key]);
    let invalid = |m: &str| ConfigError::Invalid(m.to_string());

    let listen = match r("kprop_listen") {
        Some(spec) => parse_listen_addresses(&spec, DEFAULT_KPROP_PORT)?,
        None => Vec::new(),
    };
    let primary = r("kprop_primary");
    if !listen.is_empty() && primary.is_some() {
        return Err(invalid(
            "kprop_listen (primary) and kprop_primary (replica) are mutually exclusive",
        ));
    }
    let keytab = r("kprop_keytab").map(PathBuf::from);
    let password_file = r("kprop_password_file").map(PathBuf::from);
    if primary.is_some() && keytab.is_some() == password_file.is_some() {
        return Err(invalid(
            "a replica needs exactly one of kprop_keytab and kprop_password_file",
        ));
    }
    let client = with_realm(
        &r("kprop_client").unwrap_or_else(|| "kprop/replica".into()),
        realm,
    );
    let acl = {
        let listed = kdc_conf.get_values(&["realms", realm, "kprop_acl"]);
        let names: Vec<String> = listed
            .iter()
            .flat_map(|v| v.split(|c: char| c.is_whitespace() || c == ','))
            .filter(|s| !s.is_empty())
            .map(|s| with_realm(s, realm))
            .collect();
        if names.is_empty() {
            vec![client.clone()]
        } else {
            names
        }
    };
    let primary_kdc = r("kprop_primary_kdc")
        .or_else(|| primary.as_deref().map(|p| host_with_port(p, DEFAULT_PORT)));
    let poll = deltat(
        kdc_conf,
        &["realms", realm, "kprop_poll_interval"],
        DEFAULT_KPROP_POLL_INTERVAL,
    )?;
    if poll <= 0 {
        return Err(invalid("kprop_poll_interval must be positive"));
    }
    Ok(PropagationSettings {
        listen,
        primary,
        primary_kdc,
        service: with_realm(
            &r("kprop_service").unwrap_or_else(|| "kprop/primary".into()),
            realm,
        ),
        client,
        acl,
        keytab,
        password_file,
        poll_interval: Duration::from_secs(u64::try_from(poll).unwrap_or(60)),
    })
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
    /// Database propagation (`kprop_*`).
    pub propagation: PropagationSettings,
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
        // The db2 module options live in `[dbmodules]` under the realm's
        // `database_module`, which defaults to the realm name (MIT
        // kdb5.c `get_conf_section`; kdb_db2.c:267-277).
        let module = r("database_module").unwrap_or_else(|| realm.to_string());
        for (key, slot) in [
            ("disable_lockout", &mut kdc.disable_lockout),
            ("disable_last_success", &mut kdc.disable_last_success),
        ] {
            let path = ["dbmodules", module.as_str(), key];
            *slot = match (
                kdc_conf.get_string(&path),
                krb5_conf.and_then(|p| p.get_string(&path)),
            ) {
                (None, None) => false,
                (Some(_), _) => kdc_conf.get_boolean(&path, false)?,
                (None, Some(_)) => krb5_conf.map_or(Ok(false), |p| p.get_boolean(&path, false))?,
            };
        }
        #[cfg(feature = "pkinit")]
        {
            kdc.pkinit = pkinit_settings(kdc_conf, realm)?;
        }

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
            propagation: propagation_settings(kdc_conf, realm)?,
        })
    }
}

/// PKINIT settings from `[realms]`/`[kdcdefaults]` (pkinit_srv.c
/// `pkinit_init_kdc_profile` :958-1040; `pkinit_kdcdefault_*` look in the
/// realm first, then `[kdcdefaults]`). PKINIT is off without
/// `pkinit_identity`; `pkinit_anchors` is then required.
#[cfg(feature = "pkinit")]
fn pkinit_settings(
    kdc_conf: &Profile,
    realm: &str,
) -> Result<Option<std::sync::Arc<crate::pkinit::server::ServerConfig>>, ConfigError> {
    use crate::pkinit::cms::Identity;
    use crate::pkinit::server::ServerConfig;
    use crate::pkinit::x509::TrustStore;

    let one = |key: &str| {
        kdc_conf
            .get_string(&["realms", realm, key])
            .or_else(|| kdc_conf.get_string(&["kdcdefaults", key]))
    };
    let all = |key: &str| {
        let mut v = kdc_conf.get_values(&["realms", realm, key]);
        if v.is_empty() {
            v = kdc_conf.get_values(&["kdcdefaults", key]);
        }
        v
    };
    let boolean = |key: &str| -> Result<bool, ConfigError> {
        match one(key) {
            None => Ok(false),
            Some(s) => match s.to_ascii_lowercase().as_str() {
                "true" | "yes" | "on" | "1" => Ok(true),
                "false" | "no" | "off" | "0" => Ok(false),
                _ => Err(ConfigError::Invalid(format!("{key}: not a boolean"))),
            },
        }
    };
    let invalid = |m: String| ConfigError::Invalid(m);

    let Some(identity_spec) = one("pkinit_identity") else {
        return Ok(None);
    };
    let anchors = all("pkinit_anchors");
    if anchors.is_empty() {
        return Err(invalid(format!(
            "No pkinit_anchors supplied for realm {realm}"
        )));
    }
    if one("pkinit_kdc_ocsp").is_some() {
        return Err(invalid(format!("OCSP is not supported: (realm: {realm})")));
    }
    let identity = Identity::from_spec(&identity_spec).map_err(invalid)?;
    let mut store = TrustStore::default();
    for a in anchors {
        store.load(&a, true).map_err(invalid)?;
    }
    for p in all("pkinit_pool") {
        store.load(&p, false).map_err(invalid)?;
    }
    for r in all("pkinit_revoke") {
        store.load_crls(&r).map_err(invalid)?;
    }
    let mut server = ServerConfig::new(identity, store);
    server.dh_min_bits =
        crate::pkinit::kex::parse_dh_min_bits(one("pkinit_dh_min_bits").as_deref());
    server.allow_upn = boolean("pkinit_allow_upn")?;
    server.require_crl_checking = boolean("pkinit_require_crl_checking")?;
    server.require_freshness = boolean("pkinit_require_freshness")?;
    if let Some(eku) = one("pkinit_eku_checking") {
        match eku.to_ascii_lowercase().as_str() {
            "kpclientauth" => {}
            "sclogin" => server.accept_secondary_eku = true,
            "none" => server.require_eku = false,
            _ => {}
        }
    }
    server.indicators = all("pkinit_indicator");
    Ok(Some(std::sync::Arc::new(server)))
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

#[cfg(test)]
mod propagation_tests {
    use super::*;

    fn settings(realm_body: &str) -> Result<PropagationSettings, ConfigError> {
        let p = Profile::parse(&format!("[realms]\n R = {{\n{realm_body}\n }}\n")).expect("conf");
        propagation_settings(&p, "R")
    }

    #[test]
    fn defaults_are_off_with_kprop_principals() {
        let s = settings("").expect("settings");
        assert!(s.listen.is_empty() && !s.is_replica());
        assert_eq!(s.service, "kprop/primary@R");
        assert_eq!(s.client, "kprop/replica@R");
        assert_eq!(s.acl, vec!["kprop/replica@R".to_string()]);
        assert_eq!(s.poll_interval, Duration::from_secs(60));
    }

    #[test]
    fn primary_settings() {
        let s = settings(
            "  kprop_listen = 127.0.0.1:7540\n  kprop_acl = kprop/a kprop/b@R\n  \
             kprop_service = kprop/kdc0",
        )
        .expect("settings");
        assert_eq!(s.listen, vec!["127.0.0.1:7540".parse().expect("addr")]);
        assert_eq!(
            s.acl,
            vec!["kprop/a@R".to_string(), "kprop/b@R".to_string()]
        );
        assert_eq!(s.service, "kprop/kdc0@R");
    }

    #[test]
    fn replica_settings_default_the_kdc_to_the_primary_host_on_port_88() {
        let s = settings(
            "  kprop_primary = kdc-0.example.com:754\n  kprop_keytab = /k/replica.keytab\n  \
             kprop_poll_interval = 30s",
        )
        .expect("settings");
        assert!(s.is_replica());
        assert_eq!(s.primary_kdc.as_deref(), Some("kdc-0.example.com:88"));
        assert_eq!(s.keytab, Some(PathBuf::from("/k/replica.keytab")));
        assert_eq!(s.poll_interval, Duration::from_secs(30));
        let s = settings(
            "  kprop_primary = [2001:db8::1]:754\n  kprop_password_file = /k/pw\n  \
             kprop_primary_kdc = other:8888",
        )
        .expect("settings");
        assert_eq!(s.primary_kdc.as_deref(), Some("other:8888"));
        assert_eq!(host_with_port("[2001:db8::1]:754", 88), "[2001:db8::1]:88");
        assert_eq!(host_with_port("host", 88), "host:88");
    }

    #[test]
    fn invalid_combinations_are_errors() {
        assert!(
            settings("  kprop_listen = 754\n  kprop_primary = h:754\n  kprop_keytab = /k").is_err()
        );
        assert!(settings("  kprop_primary = h:754").is_err());
        assert!(settings(
            "  kprop_primary = h:754\n  kprop_keytab = /k\n  kprop_password_file = /p"
        )
        .is_err());
        assert!(settings("  kprop_poll_interval = 0").is_err());
    }
}

#[cfg(test)]
mod dbmodule_tests {
    use super::*;

    fn config(text: &str, krb5: Option<&str>) -> RealmConfig {
        let kdc = Profile::parse(text).expect("kdc.conf");
        let krb5 = krb5.map(|t| Profile::parse(t).expect("krb5.conf"));
        RealmConfig::from_profiles(&kdc, krb5.as_ref(), "R").expect("config")
    }

    #[test]
    fn lockout_options_default_to_off_and_read_dbmodules_by_realm_name() {
        let c = config("[realms]\n R = {\n }\n", None);
        assert!(!c.kdc.disable_lockout && !c.kdc.disable_last_success && c.kdc.tgs_recheck_client);
        let c = config(
            "[realms]\n R = {\n }\n[dbmodules]\n R = {\n  disable_lockout = true\n }\n",
            None,
        );
        assert!(c.kdc.disable_lockout && !c.kdc.disable_last_success);
    }

    #[test]
    fn database_module_selects_the_dbmodules_section_and_krb5_conf_is_consulted() {
        let c = config(
            "[realms]\n R = {\n  database_module = other\n }\n[dbmodules]\n R = {\n  disable_lockout = true\n }\n \
             other = {\n  disable_last_success = true\n }\n",
            None,
        );
        assert!(!c.kdc.disable_lockout && c.kdc.disable_last_success);
        let c = config(
            "[realms]\n R = {\n }\n",
            Some("[dbmodules]\n R = {\n  disable_lockout = true\n }\n"),
        );
        assert!(c.kdc.disable_lockout);
    }
}
