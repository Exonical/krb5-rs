//! kadmin.local-style administration of a [`FileStore`] (MIT
//! kadmin/cli/kadmin.c, kadmin/cli/keytab.c, lib/kadm5/srv/svr_principal.c,
//! lib/kadm5/str_conv.c).

use std::path::Path;
use std::time::Duration;

use chrono::{DateTime, Utc};

use super::file::FileStore;
use crate::crypto::{enctype_name, SaltType};
use crate::kdc::db::{keys_from_password, random_keys, PrincipalAttributes, PrincipalEntry};
use crate::kdc::policy::kerberos_time;
use crate::kdc::store::{AdminStore, Policy, PrincipalRecord, StoreError};
use crate::keytab::{FileKeytab, Keytab, KeytabEntry};
use crate::types::{KerberosTime, PrincipalName};

fn err(msg: impl Into<String>) -> StoreError {
    StoreError::backend(msg)
}

fn missing(what: impl std::fmt::Display) -> StoreError {
    StoreError::not_found(format!("{what} does not exist"))
}

fn duplicate(what: impl std::fmt::Display) -> StoreError {
    StoreError::conflict(format!("Principal or policy already exists: {what}"))
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

/// Parse `name[@REALM]` with MIT escaping/type inference
/// (`lib/krb5/krb/parse.c:40-172`); the realm defaults to `default_realm`.
pub fn parse_principal(
    s: &str,
    default_realm: &str,
) -> Result<(PrincipalName, String), StoreError> {
    crate::kdc::kdb::mit::parse_name_with_default(s, default_realm)
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
    /// `-policy NAME` (`Some(Some)`) or `-clearpolicy` (`Some(None)`)
    /// (kadmin.c:`kadmin_parse_princ_args`).
    pub policy: Option<Option<String>>,
    /// `-unlock` (kadmin.c:1020-1041): restart lockout counting. Records the
    /// time of the unlock, which `locked_check_p` honours.
    pub unlock: bool,
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

/// Run a future that is expected to complete without waiting (a store whose
/// futures are ready immediately, like [`FileStore`]). It polls with a no-op
/// waker and yields the thread between polls, so a store that does wait still
/// works, only without a reactor of its own.
fn block_on<F: std::future::Future>(fut: F) -> F::Output {
    use std::task::{Context, Poll, Waker};
    let mut fut = std::pin::pin!(fut);
    let mut cx = Context::from_waker(Waker::noop());
    loop {
        if let Poll::Ready(v) = fut.as_mut().poll(&mut cx) {
            return v;
        }
        std::thread::yield_now();
    }
}

/// kadmin-style administration over any [`AdminStore`]: the semantics (epoch
/// bumps, policy validation, kadm5 rules) live here once, for the file
/// database and for CockroachDB alike. Every mutation is one atomic store
/// operation.
pub struct AdminOps<S: AdminStore> {
    store: S,
    keysalts: Vec<(i32, SaltType)>,
}

impl<S: AdminStore> AdminOps<S> {
    /// Administer `store`, generating keys for `keysalts`
    /// (`supported_enctypes`).
    pub fn new(store: S, keysalts: Vec<(i32, SaltType)>) -> Self {
        Self { store, keysalts }
    }

    async fn require(
        &self,
        name: &PrincipalName,
        realm: &str,
    ) -> Result<PrincipalRecord, StoreError> {
        self.store
            .get_record(name, realm)
            .await?
            .ok_or_else(|| missing(format!("Principal {name}@{realm}")))
    }

    /// Apply `opts`; returns whether anything security-relevant changed
    /// (attributes, expirations, delegation lists, policy, unlock), in which
    /// case `security_epoch` is bumped (docs/architecture/kdb.md §3).
    fn apply_options(entry: &mut PrincipalEntry, opts: &PrincipalOptions) -> bool {
        let before = (
            entry.attributes,
            entry.expiration,
            entry.pw_expiration,
            entry.allowed_to_delegate_to.clone(),
            entry.allowed_to_delegate_from.clone(),
            entry.policy.clone(),
        );
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
        if let Some(p) = &opts.policy {
            entry.policy = p.clone();
        }
        if opts.unlock {
            entry.last_admin_unlock = Some(kerberos_time(Utc::now().timestamp()));
        }
        let after = (
            entry.attributes,
            entry.expiration,
            entry.pw_expiration,
            entry.allowed_to_delegate_to.clone(),
            entry.allowed_to_delegate_from.clone(),
            entry.policy.clone(),
        );
        let changed = before != after || opts.unlock;
        if changed {
            entry.security_epoch += 1;
        }
        changed
    }

    /// `KADM5_UNK_POLICY` for a `-policy` naming a policy that does not exist
    /// (svr_principal.c:117).
    async fn check_policy(&self, opts: &PrincipalOptions) -> Result<(), StoreError> {
        if let Some(Some(name)) = &opts.policy {
            if self.store.get_policy(name).await?.is_none() {
                return Err(missing(format!("Policy \"{name}\"")));
            }
        }
        Ok(())
    }

    /// `addprinc` (`kadm5_create_principal`): kvno 1, keys from `password`
    /// or random (`-randkey`). Fails if the principal exists.
    pub async fn add_principal(
        &self,
        name: &PrincipalName,
        realm: &str,
        password: Option<&str>,
        opts: &PrincipalOptions,
    ) -> Result<(), StoreError> {
        if self.store.get_record(name, realm).await?.is_some() {
            return Err(duplicate(format!("{name}@{realm}")));
        }
        self.check_policy(opts).await?;
        let keys = match password {
            Some(pw) => keys_from_password(name, realm, pw, 1, &self.keysalts),
            None => random_keys(1, &self.etypes()),
        }
        .map_err(|e| err(e.to_string()))?;
        let mut entry = PrincipalEntry {
            allowed_to_delegate_to: Vec::new(),
            allowed_to_delegate_from: Vec::new(),
            policy: None,
            security_epoch: 0,
            last_admin_unlock: None,
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
        entry.security_epoch = 1;
        self.store
            .create_principal(entry, Some(kerberos_time(Utc::now().timestamp())))
            .await
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
    pub async fn delete_principal(
        &self,
        name: &PrincipalName,
        realm: &str,
    ) -> Result<(), StoreError> {
        if self.store.delete_principal(name, realm).await? {
            Ok(())
        } else {
            Err(missing(format!("Principal {name}@{realm}")))
        }
    }

    /// `cpw` (`kadm5_chpass_principal` / `kadm5_randkey_principal`): the new
    /// keys get kvno = highest + 1; older keys are dropped unless
    /// `keep_old`. Clears REQUIRES_PWCHANGE and records the password change.
    pub async fn change_password(
        &self,
        name: &PrincipalName,
        realm: &str,
        password: Option<&str>,
        keep_old: bool,
    ) -> Result<u32, StoreError> {
        let keysalts = self.keysalts.clone();
        let etypes = self.etypes();
        let callback_name = name.clone();
        let callback_realm = realm.to_owned();
        let password = password.map(str::to_owned);
        self.store
            .update_principal(name, realm, move |rec| {
                let kvno = rec.entry.current_kvno().unwrap_or(0) + 1;
                let mut keys = match password.as_deref() {
                    Some(pw) => {
                        keys_from_password(&callback_name, &callback_realm, pw, kvno, &keysalts)
                    }
                    None => random_keys(kvno, &etypes),
                }
                .map_err(|e| err(e.to_string()))?;
                if keep_old {
                    keys.extend(rec.entry.keys.iter().cloned());
                }
                rec.entry.keys = keys;
                rec.entry
                    .attributes
                    .remove(PrincipalAttributes::REQUIRES_PWCHANGE);
                // A new key is a key rotation or password reset: bump the
                // epoch. MIT also zeroes `fail_auth_count`
                // (svr_principal.c:1343, 1473); the counter lives in the KDC
                // process here, so record an unlock time.
                rec.entry.security_epoch += 1;
                let now = kerberos_time(Utc::now().timestamp());
                rec.entry.last_admin_unlock = Some(now);
                rec.last_pwd_change = Some(now);
                Ok(())
            })
            .await
            .map(|updated| updated.entry.current_kvno().unwrap_or(0))
    }

    /// `modprinc`.
    pub async fn modify_principal(
        &self,
        name: &PrincipalName,
        realm: &str,
        opts: &PrincipalOptions,
    ) -> Result<(), StoreError> {
        self.check_policy(opts).await?;
        let opts = opts.clone();
        self.store
            .update_principal(name, realm, move |rec| {
                Self::apply_options(&mut rec.entry, &opts);
                Ok(())
            })
            .await?;
        Ok(())
    }

    /// `add_policy` (`kadm5_create_policy`, svr_policy.c:59-180).
    pub async fn add_policy(&self, policy: Policy) -> Result<(), StoreError> {
        validate_policy(&policy)?;
        if self.store.get_policy(&policy.name).await?.is_some() {
            return Err(duplicate(format!("policy {}", policy.name)));
        }
        self.store
            .create_policy(Policy {
                security_epoch: 1,
                ..policy
            })
            .await
    }

    /// `modify_policy` (`kadm5_modify_policy`, svr_policy.c:254-380): the
    /// changed policy gets a higher `security_epoch`.
    pub async fn modify_policy(&self, name: &str, change: &PolicyChange) -> Result<(), StoreError> {
        let change = change.clone();
        self.store
            .update_policy(name, move |policy| {
                change.apply(policy);
                validate_policy(policy)?;
                policy.security_epoch += 1;
                Ok(())
            })
            .await?;
        Ok(())
    }

    /// `delete_policy` (`kadm5_delete_policy`, svr_policy.c:183-208). Like
    /// MIT's db2 module it does not refuse a policy that principals still
    /// name; such a name then counts as no policy.
    pub async fn delete_policy(&self, name: &str) -> Result<(), StoreError> {
        if self.store.delete_policy(name).await? {
            Ok(())
        } else {
            Err(missing(format!("Policy \"{name}\"")))
        }
    }

    /// `get_policy`.
    pub async fn get_policy(&self, name: &str) -> Result<Policy, StoreError> {
        self.store
            .get_policy(name)
            .await?
            .ok_or_else(|| missing(format!("Policy \"{name}\"")))
    }

    /// `list_policies`, sorted by name.
    pub async fn list_policies(&self) -> Result<Vec<String>, StoreError> {
        Ok(self
            .store
            .list_policies()
            .await?
            .into_iter()
            .map(|p| p.name)
            .collect())
    }

    /// `getprinc` data.
    pub async fn get_principal(
        &self,
        name: &PrincipalName,
        realm: &str,
    ) -> Result<PrincipalRecord, StoreError> {
        self.require(name, realm).await
    }

    /// `listprincs`: `name@REALM`, sorted.
    pub async fn list_principals(&self) -> Result<Vec<String>, StoreError> {
        let mut out: Vec<String> = self
            .store
            .list_principals()
            .await?
            .iter()
            .map(|r| format!("{}@{}", r.entry.name, r.entry.realm))
            .collect();
        out.sort();
        Ok(out)
    }

    /// `ktadd` (keytab.c:120-330): by default new random keys (kvno + 1,
    /// old keys dropped, `keepold` FALSE) are generated and written; with
    /// `norandkey` the current-kvno keys are written unchanged.
    pub async fn ktadd(
        &self,
        name: &PrincipalName,
        realm: &str,
        keytab: &Path,
        randomize: bool,
    ) -> Result<u32, StoreError> {
        if randomize {
            self.change_password(name, realm, None, false).await?;
        }
        let entry = self.require(name, realm).await?.entry;
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

/// Administration operations over a [`FileStore`]: the synchronous face of
/// [`AdminOps`], for the standalone database.
pub struct Admin<'a> {
    ops: AdminOps<&'a FileStore>,
}

impl<'a> Admin<'a> {
    /// Administer `store`, generating keys for `keysalts`
    /// (`supported_enctypes`).
    pub fn new(store: &'a FileStore, keysalts: Vec<(i32, SaltType)>) -> Self {
        Self {
            ops: AdminOps::new(store, keysalts),
        }
    }

    /// See [`AdminOps::add_principal`].
    pub fn add_principal(
        &self,
        name: &PrincipalName,
        realm: &str,
        password: Option<&str>,
        opts: &PrincipalOptions,
    ) -> Result<(), StoreError> {
        block_on(self.ops.add_principal(name, realm, password, opts))
    }

    /// See [`AdminOps::delete_principal`].
    pub fn delete_principal(&self, name: &PrincipalName, realm: &str) -> Result<(), StoreError> {
        block_on(self.ops.delete_principal(name, realm))
    }

    /// See [`AdminOps::change_password`].
    pub fn change_password(
        &self,
        name: &PrincipalName,
        realm: &str,
        password: Option<&str>,
        keep_old: bool,
    ) -> Result<u32, StoreError> {
        block_on(self.ops.change_password(name, realm, password, keep_old))
    }

    /// See [`AdminOps::modify_principal`].
    pub fn modify_principal(
        &self,
        name: &PrincipalName,
        realm: &str,
        opts: &PrincipalOptions,
    ) -> Result<(), StoreError> {
        block_on(self.ops.modify_principal(name, realm, opts))
    }

    /// See [`AdminOps::add_policy`].
    pub fn add_policy(&self, policy: Policy) -> Result<(), StoreError> {
        block_on(self.ops.add_policy(policy))
    }

    /// See [`AdminOps::modify_policy`].
    pub fn modify_policy(&self, name: &str, change: &PolicyChange) -> Result<(), StoreError> {
        block_on(self.ops.modify_policy(name, change))
    }

    /// See [`AdminOps::delete_policy`].
    pub fn delete_policy(&self, name: &str) -> Result<(), StoreError> {
        block_on(self.ops.delete_policy(name))
    }

    /// See [`AdminOps::get_policy`].
    pub fn get_policy(&self, name: &str) -> Result<Policy, StoreError> {
        block_on(self.ops.get_policy(name))
    }

    /// See [`AdminOps::list_policies`].
    pub fn list_policies(&self) -> Result<Vec<String>, StoreError> {
        block_on(self.ops.list_policies())
    }

    /// See [`AdminOps::get_principal`].
    pub fn get_principal(
        &self,
        name: &PrincipalName,
        realm: &str,
    ) -> Result<PrincipalRecord, StoreError> {
        block_on(self.ops.get_principal(name, realm))
    }

    /// See [`AdminOps::list_principals`].
    pub fn list_principals(&self) -> Result<Vec<String>, StoreError> {
        block_on(self.ops.list_principals())
    }

    /// See [`AdminOps::ktadd`].
    pub fn ktadd(
        &self,
        name: &PrincipalName,
        realm: &str,
        keytab: &Path,
        randomize: bool,
    ) -> Result<u32, StoreError> {
        block_on(self.ops.ktadd(name, realm, keytab, randomize))
    }
}

/// Changes for [`Admin::modify_policy`] (kadmin.c:1646-1695 options).
#[derive(Debug, Clone, Default)]
pub struct PolicyChange {
    /// `-maxlife`.
    pub pw_max_life: Option<u32>,
    /// `-minlife`.
    pub pw_min_life: Option<u32>,
    /// `-minlength`.
    pub pw_min_length: Option<u32>,
    /// `-minclasses`.
    pub pw_min_classes: Option<u32>,
    /// `-history`.
    pub pw_history_num: Option<u32>,
    /// `-maxfailure`.
    pub pw_max_fail: Option<u32>,
    /// `-failurecountinterval`.
    pub pw_failcnt_interval: Option<u32>,
    /// `-lockoutduration`.
    pub pw_lockout_duration: Option<u32>,
    /// `-allowedkeysalts` (`Some(None)` for `-`, which clears it).
    pub allowed_keysalts: Option<Option<String>>,
}

impl PolicyChange {
    /// Apply the changes to `policy`.
    pub fn apply(&self, policy: &mut Policy) {
        macro_rules! set {
            ($f:ident) => {
                if let Some(v) = self.$f {
                    policy.$f = v;
                }
            };
        }
        set!(pw_max_life);
        set!(pw_min_life);
        set!(pw_min_length);
        set!(pw_min_classes);
        set!(pw_history_num);
        set!(pw_max_fail);
        set!(pw_failcnt_interval);
        set!(pw_lockout_duration);
        if let Some(v) = &self.allowed_keysalts {
            policy.allowed_keysalts = v.clone();
        }
    }

    /// A new policy called `name` with these settings.
    pub fn into_policy(self, name: &str) -> Policy {
        let mut policy = Policy {
            name: name.to_string(),
            ..Policy::default()
        };
        self.apply(&mut policy);
        policy
    }
}

/// `kadm5_create_policy` name and lifetime checks (svr_policy.c:70-110).
fn validate_policy(p: &Policy) -> Result<(), StoreError> {
    if p.name.is_empty() || p.name.bytes().any(|b| !(b' '..=b'~').contains(&b)) {
        return Err(err(format!("bad policy name {:?}", p.name)));
    }
    if p.pw_min_life > p.pw_max_life && p.pw_max_life != 0 {
        return Err(err(
            "minimum password life is greater than the maximum (KADM5_BAD_MIN_PASS_LIFE)",
        ));
    }
    Ok(())
}

/// Describe a policy in `get_policy` style (kadmin.c:1799-1815).
pub fn format_policy(p: &Policy) -> String {
    let dur = |s: u32| {
        if s == 0 {
            "[none]".to_string()
        } else {
            format!(
                "{} days {:02}:{:02}:{:02}",
                s / 86400,
                s % 86400 / 3600,
                s % 3600 / 60,
                s % 60
            )
        }
    };
    let mut out = format!("Policy: {}\n", p.name);
    out += &format!("Maximum password life: {}\n", dur(p.pw_max_life));
    out += &format!("Minimum password life: {}\n", dur(p.pw_min_life));
    out += &format!("Minimum password length: {}\n", p.pw_min_length);
    out += &format!(
        "Minimum number of password character classes: {}\n",
        p.pw_min_classes
    );
    out += &format!("Number of old keys kept: {}\n", p.pw_history_num);
    out += &format!(
        "Maximum password failures before lockout: {}\n",
        p.pw_max_fail
    );
    out += &format!(
        "Password failure count reset interval: {}\n",
        dur(p.pw_failcnt_interval)
    );
    out += &format!(
        "Password lockout duration: {}\n",
        dur(p.pw_lockout_duration)
    );
    if let Some(k) = &p.allowed_keysalts {
        out += &format!("Allowed key/salt types: {k}\n");
    }
    out
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
    match &e.policy {
        Some(p) => out += &format!("Policy: {p}\n"),
        None => out += "Policy: [none]\n",
    }
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
