//! kldap settings: `[dbmodules]` keys (`krb5_ldap_read_server_params`,
//! ldap_misc.c:311-438), `-x` database arguments
//! (`krb5_ldap_parse_db_params`, ldap_misc.c:201-298) and the service
//! password file (`krb5_ldap_readpassword`, ldap_service_stash.c:63-115).

use krb5_rs::kdc::store::{StoreError, StoreErrorKind};
use krb5_rs::kdc::DbModuleConfig;

/// Which daemon is connecting (`KRB5_KDB_SRV_TYPE_KDC` / `_ADMIN`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerType {
    /// The KDC: `ldap_kdc_*` keys.
    Kdc,
    /// kadmind and the admin tools: `ldap_kadmind_*` keys.
    Admin,
}

/// `DEFAULT_CONNS_PER_SERVER` (kdb_ldap.h:62).
pub const DEFAULT_CONNS_PER_SERVER: u32 = 5;

/// The connection settings of a kldap database.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LdapConfig {
    /// `ldap_servers` (default `ldapi://`).
    pub servers: Vec<String>,
    /// `ldap_kerberos_container_dn`.
    pub container_dn: Option<String>,
    /// `ldap_kdc_dn` / `ldap_kadmind_dn` or `-x binddn`.
    pub bind_dn: Option<String>,
    /// `-x bindpwd`, else read from `service_password_file`.
    pub bind_pwd: Option<String>,
    /// `ldap_service_password_file`.
    pub service_password_file: Option<String>,
    /// SASL mechanism, authcid, authzid and realm.
    pub sasl_mech: Option<String>,
    /// SASL authentication identity.
    pub sasl_authcid: Option<String>,
    /// SASL authorization identity.
    pub sasl_authzid: Option<String>,
    /// SASL realm.
    pub sasl_realm: Option<String>,
    /// `ldap_conns_per_server` or `-x nconns`.
    pub max_server_conns: u32,
    /// `disable_last_success`.
    pub disable_last_success: bool,
    /// `disable_lockout`.
    pub disable_lockout: bool,
}

fn invalid(msg: impl Into<String>) -> StoreError {
    StoreError::new(StoreErrorKind::Rejected, msg.into())
}

fn boolean(v: Option<&str>) -> bool {
    matches!(
        v.map(str::to_ascii_lowercase).as_deref(),
        Some("y" | "yes" | "true" | "t" | "1" | "on")
    )
}

impl LdapConfig {
    /// Settings from `db_args` then the `[dbmodules]` section, as MIT reads
    /// them (db args win).
    pub fn new(
        module: &DbModuleConfig,
        db_args: &[String],
        srv: ServerType,
    ) -> Result<Self, StoreError> {
        let mut c = LdapConfig::default();
        let mut hosts = Vec::new();
        for arg in db_args {
            let (opt, val) = match arg.split_once('=') {
                Some((o, v)) => (o.trim(), Some(v.trim())),
                None => (arg.trim(), None),
            };
            if opt == "temporary" {
                return Err(invalid("KDB module requires -update argument"));
            }
            let val = val
                .ok_or_else(|| invalid(format!("'{opt}' value missing")))?
                .to_string();
            match opt {
                "binddn" => c.bind_dn = Some(val),
                "nconns" => {
                    let n = val.parse::<u32>().unwrap_or(0);
                    c.max_server_conns = if n == 0 { DEFAULT_CONNS_PER_SERVER } else { n };
                }
                "bindpwd" => c.bind_pwd = Some(val),
                "sasl_mech" => c.sasl_mech = Some(val),
                "sasl_authcid" => c.sasl_authcid = Some(val),
                "sasl_authzid" => c.sasl_authzid = Some(val),
                "sasl_realm" => c.sasl_realm = Some(val),
                "host" => hosts.push(val),
                "debug" => {}
                _ => return Err(invalid(format!("unknown option '{opt}'"))),
            }
        }
        let pick = |kdc: &str, adm: &str| {
            module
                .get(if srv == ServerType::Kdc { kdc } else { adm })
                .map(str::to_string)
        };
        if c.max_server_conns == 0 {
            c.max_server_conns = match module.get("ldap_conns_per_server") {
                Some(v) => v
                    .trim()
                    .parse()
                    .map_err(|_| invalid("Improper format of ldap_conns_per_server"))?,
                None => DEFAULT_CONNS_PER_SERVER,
            };
        }
        if c.max_server_conns < 2 {
            return Err(invalid("Minimum connections required per server is 2"));
        }
        c.bind_dn = c.bind_dn.or_else(|| pick("ldap_kdc_dn", "ldap_kadmind_dn"));
        c.service_password_file = module.get("ldap_service_password_file").map(str::to_string);
        c.sasl_mech = c
            .sasl_mech
            .or_else(|| pick("ldap_kdc_sasl_mech", "ldap_kadmind_sasl_mech"));
        c.sasl_authcid = c
            .sasl_authcid
            .or_else(|| pick("ldap_kdc_sasl_authcid", "ldap_kadmind_sasl_authcid"));
        c.sasl_authzid = c
            .sasl_authzid
            .or_else(|| pick("ldap_kdc_sasl_authzid", "ldap_kadmind_sasl_authzid"));
        c.sasl_realm = c
            .sasl_realm
            .or_else(|| pick("ldap_kdc_sasl_realm", "ldap_kadmind_sasl_realm"));
        c.container_dn = module.get("ldap_kerberos_container_dn").map(str::to_string);
        c.servers = if !hosts.is_empty() {
            hosts
        } else {
            match module.get("ldap_servers") {
                None => vec!["ldapi://".to_string()],
                Some(s) => s
                    .split(|ch: char| ch.is_whitespace() || ch == ',')
                    .filter(|s| !s.is_empty())
                    .map(str::to_string)
                    .collect(),
            }
        };
        c.disable_last_success = boolean(module.get("disable_last_success"));
        c.disable_lockout = boolean(module.get("disable_lockout"));
        Ok(c)
    }

    /// The simple-bind password: `-x bindpwd`, else the bind DN's entry in
    /// the service password file (`validate_context`, kdb_ldap_conn.c).
    pub fn password(&self) -> Result<Option<String>, StoreError> {
        if self.bind_pwd.is_some() || self.sasl_mech.is_some() {
            return Ok(self.bind_pwd.clone());
        }
        let (Some(dn), Some(file)) = (&self.bind_dn, &self.service_password_file) else {
            return Ok(None);
        };
        read_password(file, dn).map(Some)
    }
}

/// `krb5_ldap_readpassword` (ldap_service_stash.c:63-115).
pub fn read_password(filename: &str, name: &str) -> Result<String, StoreError> {
    let text = std::fs::read_to_string(filename)
        .map_err(|e| invalid(format!("Cannot open LDAP password file '{filename}': {e}")))?;
    for line in text.lines() {
        let start = line.trim_start();
        if start.starts_with('!') || start.starts_with('#') {
            continue;
        }
        if let Some(sep) = start.find('#') {
            if start[..sep].eq_ignore_ascii_case(name) {
                return dec_password(&start[sep + 1..]);
            }
        }
    }
    Err(invalid(format!(
        "Bind DN entry '{name}' missing in LDAP password file '{filename}'"
    )))
}

/// `dec_password` (ldap_service_stash.c:38-61).
fn dec_password(s: &str) -> Result<String, StoreError> {
    let hex = s
        .strip_prefix("{HEX}")
        .ok_or_else(|| invalid("Not a hexadecimal password"))?;
    if hex.len() % 2 != 0 {
        return Err(invalid("Password corrupt"));
    }
    let bytes = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16))
        .collect::<Result<Vec<u8>, _>>()
        .map_err(|_| invalid("Password corrupt"))?;
    String::from_utf8(bytes).map_err(|_| invalid("Password corrupt"))
}

/// `stashsrvpw`'s line for `dn` (kdb5_ldap_services.c).
pub fn stash_line(dn: &str, password: &str) -> String {
    let hex: String = password.bytes().map(|b| format!("{b:02x}")).collect();
    format!("{dn}#{{HEX}}{hex}\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn module(pairs: &[(&str, &str)]) -> DbModuleConfig {
        DbModuleConfig {
            library: Some("kldap".into()),
            options: pairs
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        }
    }

    #[test]
    fn server_params_and_db_args() {
        let m = module(&[
            ("ldap_servers", "ldap://a, ldaps://b"),
            ("ldap_kdc_dn", "cn=kdc"),
            ("ldap_kadmind_dn", "cn=adm"),
            ("disable_lockout", "true"),
        ]);
        let c = LdapConfig::new(&m, &[], ServerType::Kdc).unwrap();
        assert_eq!(c.servers, ["ldap://a", "ldaps://b"]);
        assert_eq!(c.bind_dn.as_deref(), Some("cn=kdc"));
        assert_eq!(c.max_server_conns, 5);
        assert!(c.disable_lockout && !c.disable_last_success);
        let c = LdapConfig::new(
            &m,
            &["binddn=cn=x".into(), "host=ldapi://".into()],
            ServerType::Admin,
        )
        .unwrap();
        assert_eq!(c.bind_dn.as_deref(), Some("cn=x"));
        assert_eq!(c.servers, ["ldapi://"]);
        let e = |args: &[&str]| {
            let a: Vec<String> = args.iter().map(|s| s.to_string()).collect();
            LdapConfig::new(&m, &a, ServerType::Kdc)
                .unwrap_err()
                .to_string()
        };
        assert!(e(&["temporary"]).contains("KDB module requires -update argument"));
        assert!(e(&["binddn"]).contains("'binddn' value missing"));
        assert!(e(&["bogus=1"]).contains("unknown option 'bogus'"));
        assert!(LdapConfig::new(
            &module(&[("ldap_conns_per_server", "1")]),
            &[],
            ServerType::Kdc
        )
        .unwrap_err()
        .to_string()
        .contains("Minimum connections required per server is 2"));
        assert_eq!(
            LdapConfig::new(&module(&[]), &[], ServerType::Kdc)
                .unwrap()
                .servers,
            ["ldapi://"]
        );
    }

    #[test]
    fn service_password_file() {
        let path = std::env::temp_dir().join(format!("kldap-pw-{}", std::process::id()));
        let text = format!(
            "# comment\n! other\n{}",
            stash_line("cn=KDC,dc=x", "s3cret")
        );
        std::fs::write(&path, text).unwrap();
        let p = path.to_str().unwrap();
        assert_eq!(read_password(p, "CN=kdc,DC=x").unwrap(), "s3cret");
        assert!(read_password(p, "cn=other")
            .unwrap_err()
            .to_string()
            .contains("missing in LDAP password file"));
        std::fs::remove_file(&path).unwrap();
    }
}
