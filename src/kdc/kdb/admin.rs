//! kadmin.local-style administration of a [`FileStore`] (MIT
//! kadmin/cli/kadmin.c, kadmin/cli/keytab.c, lib/kadm5/srv/svr_principal.c,
//! lib/kadm5/str_conv.c).

use std::path::Path;
use std::time::Duration;

use chrono::{DateTime, Utc};

use super::file::FileStore;
use crate::crypto::{enctype_name, SaltType};
use crate::kdc::db::{keys_from_password, random_keys, PrincipalAttributes, PrincipalEntry};
use crate::kdc::kdb::mit::{history_entry, history_key_matches, KeyData};
use crate::kdc::policy::kerberos_time;
use crate::kdc::store::{
    AdminStore, PasswordHistory, Policy, PrincipalRecord, StoreError, StoreErrorKind,
};
use crate::keytab::{FileKeytab, Keytab, KeytabEntry};
use crate::types::{EncryptionKey, KerberosString, KerberosTime, PrincipalName};

fn err(msg: impl Into<String>) -> StoreError {
    StoreError::backend(msg)
}

/// kadm5 error texts (`lib/kadm5/kadm_err.et:29-37`).
const PASS_Q_TOOSHORT: &str = "Password is too short";
const PASS_Q_CLASS: &str = "Password does not contain enough character classes";
const PASS_REUSE: &str = "Cannot reuse password";
const PROTECT_PRINCIPAL: &str = "Cannot change protected principal";

/// `aes256-cts-hmac-sha1-96`, MIT's default `master_key_type`.
const DEFAULT_HISTORY_ENCTYPE: i32 = 18;

/// The policy part of `passwd_check` (`check_against_policy`,
/// `lib/kadm5/srv/server_misc.c:73-102`): the length in bytes, then the
/// number of C-locale character classes (lower, upper, digit, punctuation,
/// and everything else, including space and non-ASCII bytes).
pub fn check_password(password: &str, policy: &Policy) -> Result<(), StoreError> {
    if password.len() < policy.pw_min_length as usize {
        return Err(StoreError::rejected(PASS_Q_TOOSHORT));
    }
    let mut classes = [false; 5];
    for byte in password.bytes() {
        let class = match byte {
            b'a'..=b'z' => 0,
            b'A'..=b'Z' => 1,
            b'0'..=b'9' => 2,
            0x21..=0x2f | 0x3a..=0x40 | 0x5b..=0x60 | 0x7b..=0x7e => 3,
            _ => 4,
        };
        classes[class] = true;
    }
    if (classes.iter().filter(|&&c| c).count() as u32) < policy.pw_min_classes {
        return Err(StoreError::rejected(PASS_Q_CLASS));
    }
    Ok(())
}

/// Add one password to the history queue (`add_to_history`,
/// `lib/kadm5/srv/svr_principal.c:1091-1208`). The queue holds at most
/// `pw_history_num - 1` entries; it is reset when the history key changed,
/// grows by inserting at `old_key_next`, and keeps only the newest entries
/// when the policy's history shrank.
fn add_to_history(
    hist: &mut PasswordHistory,
    hist_kvno: u32,
    pw_history_num: u32,
    entry: Vec<KeyData>,
) {
    let nhist = pw_history_num;
    if nhist <= 1 {
        return;
    }
    if hist.admin_history_kvno != hist_kvno {
        hist.old_keys.clear();
        hist.old_key_next = 0;
        hist.admin_history_kvno = hist_kvno;
    }
    let nkeys = hist.old_keys.len();
    let mut knext = hist.old_key_next as usize;
    let keep = nhist as usize - 1;
    if nkeys + 1 < nhist as usize {
        // Shift the entries from knext on forward to make room (:1119-1140).
        hist.old_keys.insert(knext.min(nkeys), Vec::new());
    } else if nkeys + 1 > nhist as usize {
        // tmp[i] = old[(i + nkeys + knext - keep) % nkeys] (:1141-1184).
        hist.old_keys = (0..keep)
            .map(|i| hist.old_keys[(i + nkeys + knext - keep) % nkeys].clone())
            .collect();
        knext = 0;
    }
    if knext + 1 > hist.old_keys.len() {
        knext = 0;
    }
    hist.old_keys[knext] = entry;
    knext += 1;
    if knext == keep {
        knext = 0;
    }
    hist.old_key_next = knext as u32;
}

/// `kadmin/history` (`KADM5_HIST_PRINCIPAL`, `lib/kadm5/admin.h:66`).
fn history_principal() -> PrincipalName {
    let part = |s: &[u8]| KerberosString::from_bytes(s).expect("ASCII name component");
    PrincipalName {
        name_type: 1,
        name_string: vec![part(b"kadmin"), part(b"history")],
    }
}

/// Whether `name` is `kadmin/history`, comparing name components but not the
/// name type, as `krb5_principal_compare` does (the realm is the one being
/// administered).
fn is_history_principal(name: &PrincipalName) -> bool {
    name.name_string == history_principal().name_string
}

fn plus_seconds(time: i64, seconds: u32) -> KerberosTime {
    kerberos_time(time + i64::from(seconds))
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
    history_enctype: i32,
}

impl<S: AdminStore> AdminOps<S> {
    /// Administer `store`, generating keys for `keysalts`
    /// (`supported_enctypes`).
    pub fn new(store: S, keysalts: Vec<(i32, SaltType)>) -> Self {
        Self {
            store,
            keysalts,
            history_enctype: DEFAULT_HISTORY_ENCTYPE,
        }
    }

    /// The enctype of a newly created `kadmin/history` key: MIT uses the
    /// realm's `master_key_type` (`lib/kadm5/srv/server_kdb.c:154`).
    pub fn with_history_enctype(mut self, enctype: i32) -> Self {
        self.history_enctype = enctype;
        self
    }

    /// The policy `name` refers to, if it exists; a missing policy counts as
    /// none (`get_policy`, `svr_principal.c:103-118`).
    async fn policy_named(&self, name: Option<&str>) -> Result<Option<Policy>, StoreError> {
        match name {
            Some(name) => self.store.get_policy(name).await,
            None => Ok(None),
        }
    }

    /// The `kadmin/history` keys and their kvno, creating the principal on
    /// first use (`kdb_get_hist_key`/`create_hist`,
    /// `lib/kadm5/srv/server_kdb.c:141-223`).
    async fn history_keys(&self, realm: &str) -> Result<(Vec<EncryptionKey>, u32), StoreError> {
        let name = history_principal();
        let record = match self.store.get_record(&name, realm).await? {
            Some(record) => record,
            None => {
                // MIT sets max_life to KRB5_KDB_DISALLOW_ALL_TIX (0x40), i.e.
                // 64 seconds, and re-randomizes the key to kvno 2 for pre-1.8
                // compatibility (server_kdb.c:147-163); mirrored as is.
                let entry = PrincipalEntry {
                    name: name.clone(),
                    realm: realm.to_owned(),
                    attributes: PrincipalAttributes::empty(),
                    max_life: Some(Duration::from_secs(0x40)),
                    max_renewable_life: None,
                    expiration: None,
                    pw_expiration: None,
                    keys: random_keys(2, &[self.history_enctype])
                        .map_err(|e| err(e.to_string()))?,
                    allowed_to_delegate_to: Vec::new(),
                    allowed_to_delegate_from: Vec::new(),
                    policy: None,
                    security_epoch: 1,
                    last_admin_unlock: None,
                };
                let now = Some(kerberos_time(Utc::now().timestamp()));
                match self.store.create_principal(entry, now).await {
                    Err(e) if e.kind() != StoreErrorKind::Conflict => return Err(e),
                    _ => {}
                }
                self.require(&name, realm).await?
            }
        };
        let kvno = record
            .entry
            .current_kvno()
            .ok_or_else(|| err("History entry contains no key data"))?;
        Ok((record.entry.keys.into_iter().map(|k| k.key).collect(), kvno))
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
        // svr_principal.c:364-374: a password must satisfy the policy.
        let policy = match &opts.policy {
            Some(Some(name)) => self.policy_named(Some(name)).await?,
            _ => None,
        };
        if let (Some(pw), Some(policy)) = (password, &policy) {
            check_password(pw, policy)?;
        }
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
        let now = Utc::now().timestamp();
        // svr_principal.c:406-412: without -pwexpire, the policy's
        // pw_max_life sets the password expiration.
        if opts.pw_expiration.is_none() {
            if let Some(policy) = policy.filter(|p| p.pw_max_life != 0) {
                entry.pw_expiration = Some(plus_seconds(now, policy.pw_max_life));
            }
        }
        entry.security_epoch = 1;
        self.store
            .create_principal(entry, Some(kerberos_time(now)))
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

    /// `cpw` (`kadm5_chpass_principal_3`, `svr_principal.c:1219-1360`, and
    /// `kadm5_randkey_principal_3`, `:1388-1497`): the new keys get kvno =
    /// highest + 1; older keys are dropped unless `keep_old`. Clears
    /// REQUIRES_PWCHANGE and records the password change.
    ///
    /// With a password and a policy, the password must satisfy the policy and
    /// must not be the current one; where the backend stores kadm5 password
    /// history (klmdb), it must not be in the history either, and the old
    /// password is added to it. Either way the password expiration restarts
    /// from the policy's `pw_max_life`, or is cleared without one.
    pub async fn change_password(
        &self,
        name: &PrincipalName,
        realm: &str,
        password: Option<&str>,
        keep_old: bool,
    ) -> Result<u32, StoreError> {
        let history_target = is_history_principal(name);
        // svr_principal.c:1247-1249, 1430-1438.
        if history_target && (password.is_some() || keep_old) {
            return Err(StoreError::rejected(PROTECT_PRINCIPAL));
        }
        let current = self.require(name, realm).await?;
        let policy_name = current.entry.policy.clone();
        let policy = self.policy_named(policy_name.as_deref()).await?;
        let mut hist = None;
        if let (Some(pw), Some(policy)) = (password, &policy) {
            // MIT fetches (creating) the history key before checking the
            // password (svr_principal.c:1269-1284).
            if current.password_history.is_some() {
                hist = Some(self.history_keys(realm).await?);
            }
            check_password(pw, policy)?;
        }

        let keysalts = self.keysalts.clone();
        let mut etypes = self.etypes();
        if history_target {
            etypes.truncate(1);
        }
        let callback_name = name.clone();
        let callback_realm = realm.to_owned();
        let password = password.map(str::to_owned);
        self.store
            .update_principal(name, realm, move |rec| {
                if rec.entry.policy != policy_name {
                    return Err(StoreError::conflict(
                        "principal policy changed concurrently; retry",
                    ));
                }
                let kvno = rec.entry.current_kvno().unwrap_or(0) + 1;
                let mut keys = match password.as_deref() {
                    Some(pw) => {
                        keys_from_password(&callback_name, &callback_realm, pw, kvno, &keysalts)
                    }
                    None => random_keys(kvno, &etypes),
                }
                .map_err(|e| err(e.to_string()))?;
                if let (Some(_), Some(policy)) = (&password, &policy) {
                    // check_pw_reuse against the current password
                    // (svr_principal.c:1307-1312), then against the history
                    // and add the current password to it (:1314-1333).
                    let old_kvno = rec.entry.current_kvno();
                    let current_keys: Vec<&EncryptionKey> = rec
                        .entry
                        .keys
                        .iter()
                        .filter(|k| Some(k.kvno) == old_kvno)
                        .map(|k| &k.key)
                        .collect();
                    let reused = keys.iter().any(|new| {
                        current_keys.iter().any(|old| {
                            old.keytype == new.key.keytype && old.key_bytes() == new.key.key_bytes()
                        })
                    });
                    if reused {
                        return Err(StoreError::rejected(PASS_REUSE));
                    }
                    if let (true, Some(history), Some((hist_keys, hist_kvno))) = (
                        policy.pw_history_num > 1,
                        rec.password_history.as_mut(),
                        &hist,
                    ) {
                        if history.admin_history_kvno == *hist_kvno
                            && history.old_keys.iter().flatten().any(|data| {
                                keys.iter()
                                    .any(|new| history_key_matches(data, hist_keys, &new.key))
                            })
                        {
                            return Err(StoreError::rejected(PASS_REUSE));
                        }
                        let entry = history_entry(&rec.entry, &hist_keys[0])?;
                        if !entry.is_empty() {
                            add_to_history(history, *hist_kvno, policy.pw_history_num, entry);
                        }
                    }
                }
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
                let now = Utc::now().timestamp();
                // svr_principal.c:1306, 1335-1336, 1465-1467.
                rec.entry.pw_expiration = policy
                    .as_ref()
                    .filter(|p| p.pw_max_life != 0)
                    .map(|p| plus_seconds(now, p.pw_max_life));
                rec.entry.last_admin_unlock = Some(kerberos_time(now));
                rec.last_pwd_change = Some(kerberos_time(now));
                Ok(())
            })
            .await
            .map(|updated| updated.entry.current_kvno().unwrap_or(0))
    }

    /// `modprinc` (`kadm5_modify_principal`, `svr_principal.c:601-634`):
    /// setting a policy restarts the password expiration from the last
    /// password change and the policy's `pw_max_life` unless `-pwexpire` is
    /// given; clearing the policy clears it, even over `-pwexpire`.
    pub async fn modify_principal(
        &self,
        name: &PrincipalName,
        realm: &str,
        opts: &PrincipalOptions,
    ) -> Result<(), StoreError> {
        self.check_policy(opts).await?;
        let new_policy = match &opts.policy {
            Some(Some(name)) => self.policy_named(Some(name)).await?,
            _ => None,
        };
        let opts = opts.clone();
        self.store
            .update_principal(name, realm, move |rec| {
                let had_policy = rec.entry.policy.is_some();
                let bumped = Self::apply_options(&mut rec.entry, &opts);
                let before = rec.entry.pw_expiration;
                if opts.pw_expiration.is_none() {
                    if let Some(policy) = &new_policy {
                        let changed = rec.last_pwd_change.map_or(0, |t| t.timestamp());
                        rec.entry.pw_expiration = (policy.pw_max_life != 0)
                            .then(|| plus_seconds(changed, policy.pw_max_life));
                    }
                }
                if matches!(opts.policy, Some(None)) && had_policy {
                    rec.entry.pw_expiration = None;
                }
                if !bumped && rec.entry.pw_expiration != before {
                    rec.entry.security_epoch += 1;
                }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kdc::kdb::master_key_from_password;

    fn policy(min_length: u32, min_classes: u32) -> Policy {
        Policy {
            name: "p".into(),
            pw_min_length: min_length,
            pw_min_classes: min_classes,
            ..Policy::default()
        }
    }

    fn rejected_with(result: Result<impl std::fmt::Debug, StoreError>, text: &str) {
        let error = result.expect_err("expected a policy rejection");
        assert_eq!(error.kind(), StoreErrorKind::Rejected, "{error}");
        assert_eq!(error.message(), text);
    }

    #[test]
    fn password_length_is_checked_in_bytes_before_classes() {
        rejected_with(check_password("abcdefg", &policy(8, 0)), PASS_Q_TOOSHORT);
        check_password("abcdefgh", &policy(8, 0)).expect("8 bytes");
        // Two bytes in UTF-8: one character, but long enough at length 2.
        check_password("\u{e9}", &policy(2, 0)).expect("UTF-8 counts bytes");
        rejected_with(check_password("ab", &policy(8, 4)), PASS_Q_TOOSHORT);
    }

    #[test]
    fn password_classes_follow_the_c_locale() {
        let classes = |pw: &str| {
            (1..=6)
                .take_while(|&n| check_password(pw, &policy(0, n)).is_ok())
                .last()
                .unwrap_or(0)
        };
        assert_eq!(classes("lower"), 1);
        assert_eq!(classes("lowerUPPER"), 2);
        assert_eq!(classes("lowerUPPER123"), 3);
        for punct in ["!", "/", ":", "@", "[", "`", "{", "~"] {
            assert_eq!(classes(punct), 1, "{punct}");
            assert_eq!(classes(&format!("a{punct}")), 2, "{punct}");
        }
        // Space, controls and non-ASCII bytes are the fifth class.
        assert_eq!(classes("a "), 2);
        assert_eq!(classes("a\u{e9}"), 2);
        assert_eq!(classes("aA1! "), 5);
        rejected_with(check_password("aaaaaaaa", &policy(0, 2)), PASS_Q_CLASS);
    }

    fn key(tag: u8) -> Vec<KeyData> {
        vec![KeyData {
            ver: 2,
            kvno: u16::from(tag),
            fields: vec![(18, vec![tag]), (0, Vec::new())],
        }]
    }

    fn tags(hist: &PasswordHistory) -> Vec<u8> {
        hist.old_keys.iter().map(|e| e[0].fields[0].1[0]).collect()
    }

    #[test]
    fn history_queue_grows_wraps_and_resets_like_mit() {
        // Traced through svr_principal.c:1091-1208 with pw_history_num 3,
        // i.e. at most 2 stored passwords.
        let mut hist = PasswordHistory::default();
        add_to_history(&mut hist, 2, 3, key(b'A'));
        assert_eq!((tags(&hist), hist.old_key_next), (b"A".to_vec(), 1));
        add_to_history(&mut hist, 2, 3, key(b'B'));
        assert_eq!((tags(&hist), hist.old_key_next), (b"AB".to_vec(), 0));
        add_to_history(&mut hist, 2, 3, key(b'C'));
        assert_eq!((tags(&hist), hist.old_key_next), (b"CB".to_vec(), 1));
        add_to_history(&mut hist, 2, 3, key(b'D'));
        assert_eq!((tags(&hist), hist.old_key_next), (b"CD".to_vec(), 0));
        // pw_history_num 1 only checks the current password: no change.
        add_to_history(&mut hist, 2, 1, key(b'X'));
        assert_eq!((tags(&hist), hist.old_key_next), (b"CD".to_vec(), 0));
        // A new history key restarts the queue (:1106-1114).
        add_to_history(&mut hist, 3, 3, key(b'E'));
        assert_eq!((tags(&hist), hist.old_key_next), (b"E".to_vec(), 1));
        assert_eq!(hist.admin_history_kvno, 3);
    }

    #[test]
    fn history_queue_grows_mid_queue_and_shrinks_to_the_newest() {
        // [C, B] with next 1 (C newest); history grows to 4: D is inserted
        // at index 1 and B, the oldest, is overwritten next.
        let mut hist = PasswordHistory {
            admin_history_kvno: 2,
            old_key_next: 1,
            old_keys: vec![key(b'C'), key(b'B')],
        };
        add_to_history(&mut hist, 2, 4, key(b'D'));
        assert_eq!((tags(&hist), hist.old_key_next), (b"CDB".to_vec(), 2));

        // [E, B, C, D] with next 1 (E newest, D before it). Shrinking to 3
        // copies old[(i + 4 + 1 - 2) % 4] = [D, E], then F replaces D.
        let mut hist = PasswordHistory {
            admin_history_kvno: 2,
            old_key_next: 1,
            old_keys: vec![key(b'E'), key(b'B'), key(b'C'), key(b'D')],
        };
        add_to_history(&mut hist, 2, 3, key(b'F'));
        assert_eq!((tags(&hist), hist.old_key_next), (b"FE".to_vec(), 1));
    }

    fn temp(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("krb5rs_admin_{}_{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        dir.join("principal")
    }

    fn file_store(tag: &str) -> FileStore {
        let master = master_key_from_password("R", "m", 18).expect("master");
        FileStore::create(&temp(tag), "R", &master).expect("create")
    }

    fn with_policy(name: &str) -> PrincipalOptions {
        PrincipalOptions {
            policy: Some(Some(name.into())),
            ..PrincipalOptions::default()
        }
    }

    const DAY: u32 = 86_400;

    #[test]
    fn file_store_enforces_policy_quality_and_current_password_reuse() {
        let store = file_store("quality");
        let admin = Admin::new(&store, vec![(18, SaltType::Normal)]);
        admin
            .add_policy(Policy {
                name: "strict".into(),
                pw_min_length: 8,
                pw_min_classes: 2,
                pw_history_num: 3,
                ..Policy::default()
            })
            .expect("policy");
        let alice = PrincipalName::new_principal("alice");
        rejected_with(
            admin.add_principal(&alice, "R", Some("Short1"), &with_policy("strict")),
            PASS_Q_TOOSHORT,
        );
        assert!(store.get_record(&alice, "R").expect("read").is_none());
        admin
            .add_principal(&alice, "R", Some("Longer-pw1"), &with_policy("strict"))
            .expect("good password");
        rejected_with(
            admin.change_password(&alice, "R", Some("alllowercase"), false),
            PASS_Q_CLASS,
        );
        rejected_with(
            admin.change_password(&alice, "R", Some("Longer-pw1"), false),
            PASS_REUSE,
        );
        admin
            .change_password(&alice, "R", Some("Another-pw2"), false)
            .expect("new password");
        // The file store keeps no history, so only the current password is
        // refused.
        admin
            .change_password(&alice, "R", Some("Longer-pw1"), false)
            .expect("no deep history on the file store");
        // Without a policy any password goes.
        let bob = PrincipalName::new_principal("bob");
        admin
            .add_principal(&bob, "R", Some("x"), &PrincipalOptions::default())
            .expect("no policy");
        admin
            .change_password(&bob, "R", Some("x"), false)
            .expect("no policy, no reuse check");
    }

    #[test]
    fn password_expiration_follows_the_policy() {
        let store = file_store("pwexpire");
        let admin = Admin::new(&store, vec![(18, SaltType::Normal)]);
        admin
            .add_policy(Policy {
                name: "expiring".into(),
                pw_max_life: DAY,
                ..Policy::default()
            })
            .expect("policy");
        let alice = PrincipalName::new_principal("alice");
        let expiry = |admin: &Admin| {
            let record = admin.get_principal(&alice, "R").expect("alice");
            (
                record.entry.pw_expiration.map(|t| t.timestamp()),
                record.last_pwd_change.map(|t| t.timestamp()).unwrap_or(0),
            )
        };
        let near = |(expiry, changed): (Option<i64>, i64)| {
            expiry.is_some_and(|e| e - changed == i64::from(DAY))
        };

        admin
            .add_principal(&alice, "R", None, &with_policy("expiring"))
            .expect("add");
        assert!(near(expiry(&admin)), "{:?}", expiry(&admin));

        let explicit = PrincipalOptions {
            pw_expiration: Some(Some(kerberos_time(2_000_000_000))),
            ..PrincipalOptions::default()
        };
        admin
            .modify_principal(&alice, "R", &explicit)
            .expect("pwexpire");
        assert_eq!(expiry(&admin).0, Some(2_000_000_000));

        admin
            .change_password(&alice, "R", None, false)
            .expect("randkey");
        assert!(near(expiry(&admin)), "randkey restarts it");

        admin
            .modify_principal(&alice, "R", &explicit)
            .expect("pwexpire");
        admin
            .modify_principal(&alice, "R", &with_policy("expiring"))
            .expect("set policy");
        assert!(near(expiry(&admin)), "setting the policy restarts it");

        let clear = PrincipalOptions {
            policy: Some(None),
            pw_expiration: Some(Some(kerberos_time(2_000_000_000))),
            ..PrincipalOptions::default()
        };
        admin
            .modify_principal(&alice, "R", &clear)
            .expect("clear policy");
        assert_eq!(expiry(&admin).0, None, "clearing wins over -pwexpire");

        admin
            .modify_principal(&alice, "R", &explicit)
            .expect("pwexpire");
        admin
            .change_password(&alice, "R", None, false)
            .expect("randkey");
        assert_eq!(expiry(&admin).0, None, "no policy: randkey clears it");
    }

    #[test]
    fn history_principal_is_protected() {
        let store = file_store("protect");
        let admin = Admin::new(&store, vec![(18, SaltType::Normal), (17, SaltType::Normal)]);
        let hist = history_principal();
        admin
            .add_principal(&hist, "R", None, &PrincipalOptions::default())
            .expect("add kadmin/history");
        rejected_with(
            admin.change_password(&hist, "R", Some("pw"), false),
            PROTECT_PRINCIPAL,
        );
        rejected_with(
            admin.change_password(&hist, "R", None, true),
            PROTECT_PRINCIPAL,
        );
        admin
            .change_password(&hist, "R", None, false)
            .expect("randkey");
        let keys = admin.get_principal(&hist, "R").expect("hist").entry.keys;
        assert_eq!(keys.len(), 1, "randkey gives the history principal one key");
    }
}
