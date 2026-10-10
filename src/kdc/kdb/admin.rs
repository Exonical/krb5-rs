//! kadmin.local-style administration of a [`FileStore`] (MIT
//! kadmin/cli/kadmin.c, kadmin/cli/keytab.c, lib/kadm5/srv/svr_principal.c,
//! lib/kadm5/str_conv.c).

use std::path::Path;
use std::time::Duration;

use chrono::{DateTime, Utc};

use super::file::{FileStore, PrincipalRecord};
use crate::crypto::{enctype_name, SaltType};
use crate::kdc::db::{
    keys_from_password, random_keys, PrincipalAttributes, PrincipalEntry, StoreError,
};
use crate::kdc::policy::kerberos_time;
use crate::keytab::{FileKeytab, Keytab, KeytabEntry};
use crate::types::{KerberosTime, PrincipalName};

fn err(msg: impl Into<String>) -> StoreError {
    StoreError(msg.into())
}

/// MIT flag table (str_conv.c:44-92): spec, bits, inverted (an `allow_*`
/// spec clears a DISALLOW bit). `md5`/`new_princ` are omitted: this crate
/// has no DES/MD5 support.
const FLAG_TABLE: &[(&str, u32, bool)] = &[
    ("allow_postdated", 0x1, true),
    ("postdateable", 0x1, true),
    ("disallow_postdated", 0x1, false),
    ("allow_forwardable", 0x2, true),
    ("forwardable", 0x2, true),
    ("disallow_forwardable", 0x2, false),
    ("allow_tgs_req", 0x4, true),
    ("tgt_based", 0x4, true),
    ("disallow_tgt_based", 0x4, false),
    ("allow_renewable", 0x8, true),
    ("renewable", 0x8, true),
    ("disallow_renewable", 0x8, false),
    ("allow_proxiable", 0x10, true),
    ("proxiable", 0x10, true),
    ("disallow_proxiable", 0x10, false),
    ("allow_dup_skey", 0x20, true),
    ("dup_skey", 0x20, true),
    ("disallow_dup_skey", 0x20, false),
    ("allow_tickets", 0x40, true),
    ("allow_tix", 0x40, true),
    ("disallow_all_tix", 0x40, false),
    ("preauth", 0x80, false),
    ("requires_pre_auth", 0x80, false),
    ("requires_preauth", 0x80, false),
    ("hwauth", 0x100, false),
    ("requires_hw_auth", 0x100, false),
    ("requires_hwauth", 0x100, false),
    ("needchange", 0x200, false),
    ("pwchange", 0x200, false),
    ("requires_pwchange", 0x200, false),
    ("allow_svr", 0x1000, true),
    ("service", 0x1000, true),
    ("disallow_svr", 0x1000, false),
    ("password_changing_service", 0x2000, false),
    ("pwchange_service", 0x2000, false),
    ("pwservice", 0x2000, false),
    ("ok_as_delegate", 0x10_0000, false),
    ("ok_to_auth_as_delegate", 0x20_0000, false),
    ("no_auth_data_required", 0x40_0000, false),
    ("lockdown_keys", 0x80_0000, false),
];

/// Attribute changes parsed from `{+|-}flag` specs
/// (`krb5_flagspec_to_mask`, str_conv.c:136-172).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AttrChange {
    /// Bits to set.
    pub set: u32,
    /// Bits to clear.
    pub clear: u32,
}

impl AttrChange {
    /// Add one spec such as `+requires_preauth`, `-allow_tix` or `0x40`.
    pub fn add_spec(&mut self, spec: &str) -> Result<(), StoreError> {
        let (negated, rest) = match spec.as_bytes().first() {
            Some(b'-') => (true, &spec[1..]),
            Some(b'+') => (false, &spec[1..]),
            _ => (false, spec),
        };
        let name = rest.replace('-', "_").to_ascii_lowercase();
        let (bits, inverted) =
            if let Some(&(_, bits, inv)) = FLAG_TABLE.iter().find(|(n, _, _)| *n == name) {
                (bits, inv)
            } else if let Some(hex) = name.strip_prefix("0x") {
                (
                    u32::from_str_radix(hex, 16).map_err(|_| err(format!("bad flag {spec:?}")))?,
                    false,
                )
            } else {
                return Err(err(format!("unknown attribute {spec:?}")));
            };
        if inverted != negated {
            self.clear |= bits;
            self.set &= !bits;
        } else {
            self.set |= bits;
            self.clear &= !bits;
        }
        Ok(())
    }

    /// Apply to an attribute set.
    pub fn apply(&self, attrs: PrincipalAttributes) -> PrincipalAttributes {
        PrincipalAttributes::from_bits_retain((attrs.bits() | self.set) & !self.clear)
    }
}

/// Parse a time argument: `never`, unix seconds, or RFC 3339. (MIT accepts
/// full getdate(3) syntax; that is not implemented.) `None` means never.
pub fn parse_time(s: &str) -> Result<Option<KerberosTime>, StoreError> {
    if s.eq_ignore_ascii_case("never") || s == "0" {
        return Ok(None);
    }
    if let Ok(secs) = s.parse::<i64>() {
        return Ok(Some(kerberos_time(secs)));
    }
    DateTime::parse_from_rfc3339(s)
        .map(|t| Some(t.with_timezone(&Utc).fixed_offset()))
        .map_err(|_| {
            err(format!(
                "cannot parse time {s:?} (use never, unix seconds or RFC 3339)"
            ))
        })
}

/// Parse a lifetime argument with the profile delta-time syntax (`10h`,
/// `7d`, `1:00:00`, seconds); zero means no limit.
pub fn parse_lifetime(s: &str) -> Result<Option<Duration>, StoreError> {
    let secs = crate::profile::string_to_deltat(s).map_err(|e| err(e.to_string()))?;
    Ok(u64::try_from(secs)
        .ok()
        .filter(|&s| s != 0)
        .map(Duration::from_secs))
}

/// Parse `name[@REALM]`; the realm defaults to `default_realm`.
pub fn parse_principal(
    s: &str,
    default_realm: &str,
) -> Result<(PrincipalName, String), StoreError> {
    let (name, realm) = match s.split_once('@') {
        Some((n, r)) => (n, r.to_string()),
        None => (s, default_realm.to_string()),
    };
    let parsed: PrincipalName = name.parse().map_err(|e| err(format!("{e}")))?;
    let name_type = if name.starts_with("krbtgt/") {
        2
    } else {
        parsed.name_type
    };
    Ok((
        PrincipalName {
            name_type,
            ..parsed
        },
        realm,
    ))
}

/// Options for [`Admin::add_principal`] and [`Admin::modify_principal`].
#[derive(Debug, Clone, Default)]
pub struct PrincipalOptions {
    /// Attribute changes.
    pub attributes: AttrChange,
    /// Maximum ticket life (`Some(None)` removes the limit).
    pub max_life: Option<Option<Duration>>,
    /// Maximum renewable life.
    pub max_renewable_life: Option<Option<Duration>>,
    /// Principal expiration.
    pub expiration: Option<Option<KerberosTime>>,
    /// Password expiration.
    pub pw_expiration: Option<Option<KerberosTime>>,
    /// Clear the traditional S4U2Proxy target list first.
    pub clear_delegate_to: bool,
    /// Principals added to the traditional S4U2Proxy target list
    /// (`-allow_delegate_to`; this tool's own option, MIT has no kadmin
    /// equivalent outside LDAP).
    pub delegate_to: Vec<String>,
    /// Clear the resource-based (RBCD) delegator list first.
    pub clear_delegate_from: bool,
    /// Principals added to the RBCD delegator list (`-allow_delegate_from`).
    pub delegate_from: Vec<String>,
}

fn update_list(list: &mut Vec<String>, clear: bool, add: &[String], realm: &str) {
    if clear {
        list.clear();
    }
    for name in add {
        let full = if name.contains('@') {
            name.clone()
        } else {
            format!("{name}@{realm}")
        };
        if !list.contains(&full) {
            list.push(full);
        }
    }
}

/// Administration operations over a [`FileStore`].
pub struct Admin<'a> {
    store: &'a FileStore,
    keysalts: Vec<(i32, SaltType)>,
}

impl<'a> Admin<'a> {
    /// Administer `store`, generating keys for `keysalts`
    /// (`supported_enctypes`).
    pub fn new(store: &'a FileStore, keysalts: Vec<(i32, SaltType)>) -> Self {
        Self { store, keysalts }
    }

    fn require(&self, name: &PrincipalName, realm: &str) -> Result<PrincipalRecord, StoreError> {
        self.store
            .get_record(name, realm)?
            .ok_or_else(|| err(format!("Principal {name}@{realm} does not exist")))
    }

    fn apply_options(entry: &mut PrincipalEntry, opts: &PrincipalOptions) {
        entry.attributes = opts.attributes.apply(entry.attributes);
        if let Some(v) = &opts.max_life {
            entry.max_life = *v;
        }
        if let Some(v) = &opts.max_renewable_life {
            entry.max_renewable_life = *v;
        }
        if let Some(v) = &opts.expiration {
            entry.expiration = *v;
        }
        if let Some(v) = &opts.pw_expiration {
            entry.pw_expiration = *v;
        }
        let realm = entry.realm.clone();
        update_list(
            &mut entry.allowed_to_delegate_to,
            opts.clear_delegate_to,
            &opts.delegate_to,
            &realm,
        );
        update_list(
            &mut entry.allowed_to_delegate_from,
            opts.clear_delegate_from,
            &opts.delegate_from,
            &realm,
        );
    }

    /// `addprinc` (`kadm5_create_principal`): kvno 1, keys from `password`
    /// or random (`-randkey`). Fails if the principal exists.
    pub fn add_principal(
        &self,
        name: &PrincipalName,
        realm: &str,
        password: Option<&str>,
        opts: &PrincipalOptions,
    ) -> Result<(), StoreError> {
        if self.store.get_record(name, realm)?.is_some() {
            return Err(err(format!(
                "Principal or policy already exists: {name}@{realm}"
            )));
        }
        let keys = match password {
            Some(pw) => keys_from_password(name, realm, pw, 1, &self.keysalts),
            None => random_keys(1, &self.etypes()),
        }
        .map_err(|e| err(e.to_string()))?;
        let mut entry = PrincipalEntry {
            allowed_to_delegate_to: Vec::new(),
            allowed_to_delegate_from: Vec::new(),
            name: name.clone(),
            realm: realm.to_string(),
            attributes: PrincipalAttributes::empty(),
            max_life: None,
            max_renewable_life: None,
            expiration: None,
            pw_expiration: None,
            keys,
        };
        Self::apply_options(&mut entry, opts);
        self.store.put(entry)
    }

    fn etypes(&self) -> Vec<i32> {
        let mut e: Vec<i32> = Vec::new();
        for &(etype, _) in &self.keysalts {
            if !e.contains(&etype) {
                e.push(etype);
            }
        }
        e
    }

    /// `delprinc`.
    pub fn delete_principal(&self, name: &PrincipalName, realm: &str) -> Result<(), StoreError> {
        if self.store.delete(name, realm)? {
            Ok(())
        } else {
            Err(err(format!("Principal {name}@{realm} does not exist")))
        }
    }

    /// `cpw` (`kadm5_chpass_principal` / `kadm5_randkey_principal`): the new
    /// keys get kvno = highest + 1; older keys are dropped unless
    /// `keep_old`. Clears REQUIRES_PWCHANGE and records the password change.
    pub fn change_password(
        &self,
        name: &PrincipalName,
        realm: &str,
        password: Option<&str>,
        keep_old: bool,
    ) -> Result<u32, StoreError> {
        let rec = self.require(name, realm)?;
        let mut entry = rec.entry;
        let kvno = entry.current_kvno().unwrap_or(0) + 1;
        let mut keys = match password {
            Some(pw) => keys_from_password(name, realm, pw, kvno, &self.keysalts),
            None => random_keys(kvno, &self.etypes()),
        }
        .map_err(|e| err(e.to_string()))?;
        if keep_old {
            keys.extend(entry.keys);
        }
        entry.keys = keys;
        entry
            .attributes
            .remove(PrincipalAttributes::REQUIRES_PWCHANGE);
        self.store
            .put_record(entry, Some(kerberos_time(Utc::now().timestamp())))?;
        Ok(kvno)
    }

    /// `modprinc`.
    pub fn modify_principal(
        &self,
        name: &PrincipalName,
        realm: &str,
        opts: &PrincipalOptions,
    ) -> Result<(), StoreError> {
        let rec = self.require(name, realm)?;
        let mut entry = rec.entry;
        Self::apply_options(&mut entry, opts);
        self.store.put_record(entry, rec.last_pwd_change)
    }

    /// `getprinc` data.
    pub fn get_principal(
        &self,
        name: &PrincipalName,
        realm: &str,
    ) -> Result<PrincipalRecord, StoreError> {
        self.require(name, realm)
    }

    /// `listprincs`: `name@REALM`, sorted.
    pub fn list_principals(&self) -> Result<Vec<String>, StoreError> {
        let mut out: Vec<String> = self
            .store
            .list()?
            .iter()
            .map(|e| format!("{}@{}", e.name, e.realm))
            .collect();
        out.sort();
        Ok(out)
    }

    /// `ktadd` (keytab.c:120-330): by default new random keys (kvno + 1,
    /// old keys dropped, `keepold` FALSE) are generated and written; with
    /// `norandkey` the current-kvno keys are written unchanged.
    pub fn ktadd(
        &self,
        name: &PrincipalName,
        realm: &str,
        keytab: &Path,
        randomize: bool,
    ) -> Result<u32, StoreError> {
        if randomize {
            self.change_password(name, realm, None, false)?;
        }
        let entry = self.require(name, realm)?.entry;
        let kvno = entry
            .current_kvno()
            .ok_or_else(|| err("principal has no keys"))?;
        let mut kt = FileKeytab::new(keytab);
        let now = u32::try_from(Utc::now().timestamp()).unwrap_or(0);
        for k in entry.keys.iter().filter(|k| k.kvno == kvno) {
            kt.add_entry(&KeytabEntry {
                principal: entry.name.clone(),
                realm: entry.realm.clone(),
                timestamp: now,
                kvno,
                key: k.key.clone(),
            })
            .map_err(|e| err(format!("writing keytab: {e}")))?;
        }
        Ok(kvno)
    }
}

/// Describe a record in `getprinc` style (MIT kadmin.c:`kadmin_getprinc`);
/// keys are never printed.
pub fn format_principal(rec: &PrincipalRecord) -> String {
    let e = &rec.entry;
    let time = |t: &Option<KerberosTime>| match t {
        Some(t) => t
            .with_timezone(&Utc)
            .format("%a %b %d %H:%M:%S UTC %Y")
            .to_string(),
        None => "[never]".to_string(),
    };
    let life = |d: Option<Duration>| {
        let s = d.map_or(0, |d| d.as_secs());
        format!(
            "{} days {:02}:{:02}:{:02}",
            s / 86400,
            s % 86400 / 3600,
            s % 3600 / 60,
            s % 60
        )
    };
    let mut out = format!("Principal: {}@{}\n", e.name, e.realm);
    out += &format!("Expiration date: {}\n", time(&e.expiration));
    out += &format!("Last password change: {}\n", time(&rec.last_pwd_change));
    out += &format!("Password expiration date: {}\n", time(&e.pw_expiration));
    out += &format!("Maximum ticket life: {}\n", life(e.max_life));
    out += &format!("Maximum renewable life: {}\n", life(e.max_renewable_life));
    out += &format!("Last modified: {}\n", time(&rec.mod_time));
    for (label, list) in [
        ("Allowed to delegate to", &e.allowed_to_delegate_to),
        ("Allowed to delegate from", &e.allowed_to_delegate_from),
    ] {
        if !list.is_empty() {
            out += &format!("{label}: {}\n", list.join(", "));
        }
    }
    out += &format!("Number of keys: {}\n", e.keys.len());
    for k in &e.keys {
        let salt = match &k.salt {
            None => "Version 5 - Normal",
            Some(_) => "Version 5 - Explicit salt",
        };
        out += &format!(
            "Key: vno {}, {}, {}\n",
            k.kvno,
            enctype_name(k.key.keytype).unwrap_or("unknown"),
            salt
        );
    }
    out += "MKey: vno 1\n";
    out += &format!("Attributes: {}\n", attribute_names(e.attributes));
    out += "Policy: [none]\n";
    out
}

/// MIT output names (`outflags`, str_conv.c:94-119) for set attributes.
pub fn attribute_names(attrs: PrincipalAttributes) -> String {
    const NAMES: &[(u32, &str)] = &[
        (0x1, "DISALLOW_POSTDATED"),
        (0x2, "DISALLOW_FORWARDABLE"),
        (0x4, "DISALLOW_TGT_BASED"),
        (0x8, "DISALLOW_RENEWABLE"),
        (0x10, "DISALLOW_PROXIABLE"),
        (0x20, "DISALLOW_DUP_SKEY"),
        (0x40, "DISALLOW_ALL_TIX"),
        (0x80, "REQUIRES_PRE_AUTH"),
        (0x100, "REQUIRES_HW_AUTH"),
        (0x200, "REQUIRES_PWCHANGE"),
        (0x1000, "DISALLOW_SVR"),
        (0x2000, "PWCHANGE_SERVICE"),
        (0x10_0000, "OK_AS_DELEGATE"),
        (0x20_0000, "OK_TO_AUTH_AS_DELEGATE"),
        (0x40_0000, "NO_AUTH_DATA_REQUIRED"),
        (0x80_0000, "LOCKDOWN_KEYS"),
    ];
    NAMES
        .iter()
        .filter(|(b, _)| attrs.bits() & b != 0)
        .map(|(_, n)| *n)
        .collect::<Vec<_>>()
        .join(" ")
}
