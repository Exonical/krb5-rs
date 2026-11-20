//! [`Db2Store`]: krb5-rs's KDB interface over an MIT db2 database
//! (`plugins/kdb/db2/kdb_db2.c`).

use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use krb5_rs::kdc::kdb::mit::mkey::{entry_mkvno, MasterKeys};
use krb5_rs::kdc::kdb::mit::ulog::{entry_from_update, update_from_entry, Ulog, UlogLock, Update};
use krb5_rs::kdc::kdb::mit::{
    merge_policy, merge_record, new_entry, policy_from_entry, record_from_entry, unparse_name,
    update_tl_data, MitEntry, MitPolicy, TlData, ACTKVNO, MKVNO,
};
use krb5_rs::kdc::{
    kerberos_time, random_keys, AdminStore, AuthState, AuthStateStore, AuthStateUpdate,
    HealthCheck, KeyEntry, Policy, PolicyStore, PrincipalAttributes, PrincipalEntry,
    PrincipalRecord, PrincipalStore, StoreError,
};
use krb5_rs::types::{EncryptionKey, KerberosString, KerberosTime, PrincipalName};

use crate::codec::{
    decode_entry, decode_policy, encode_entry, encode_policy, policy_key, zeroed_keys,
};
use crate::env::{suffixed, Db2Files, Guard, SUFFIX_LOCK, SUFFIX_POLICY, SUFFIX_POLICY_LOCK};

/// The db2 module's `[dbmodules]` settings (`configure_context`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Db2Options {
    pub hash: bool,
    pub disable_lockout: bool,
    pub disable_last_success: bool,
    pub master_key_name: String,
}

impl Db2Options {
    pub fn from_config(config: &krb5_rs::kdc::RealmConfig) -> Result<Self, StoreError> {
        let flag = |key: &str| -> Result<Option<bool>, StoreError> {
            config
                .db_module
                .get(key)
                .map(|v| match v.to_ascii_lowercase().as_str() {
                    "true" | "yes" | "on" | "1" | "y" | "t" => Ok(true),
                    "false" | "no" | "off" | "0" | "n" | "f" | "nil" => Ok(false),
                    _ => Err(StoreError::backend(format!("{key}: not a boolean"))),
                })
                .transpose()
        };
        Ok(Self {
            hash: config.db_module.db2_hash,
            disable_lockout: flag("disable_lockout")?.unwrap_or(config.kdc.disable_lockout),
            disable_last_success: flag("disable_last_success")?
                .unwrap_or(config.kdc.disable_last_success),
            master_key_name: config.master_key_name.clone(),
        })
    }
}

struct Inner {
    files: Db2Files,
    master: std::sync::RwLock<MasterKeys>,
    supplied_master: EncryptionKey,
    realm: String,
    options: Db2Options,
    ulog: Option<Ulog>,
}

/// An MIT db2 database opened in place.
#[derive(Clone)]
pub struct Db2Store {
    inner: Arc<Inner>,
}

fn io_err(what: &str, e: io::Error) -> StoreError {
    match e.kind() {
        io::ErrorKind::NotFound => StoreError::not_found(format!("{what}: {e}")),
        io::ErrorKind::WouldBlock => StoreError::unavailable(format!("{what}: {e}")),
        _ => StoreError::backend(format!("{what}: {e}")),
    }
}

fn db_key(name: &[u8]) -> Vec<u8> {
    let mut key = name.to_vec();
    key.push(0);
    key
}

fn now_time() -> KerberosTime {
    let seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX));
    kerberos_time(seconds)
}

fn admin_name(realm: &str) -> Vec<u8> {
    unparse_name(&PrincipalName::new_principal("krb5-rs-kdb"), realm)
}

fn auth_state_of(entry: &MitEntry) -> AuthState {
    AuthState {
        fail_count: entry.fail_auth_count,
        last_failed: i64::from(entry.last_failed),
        last_success: i64::from(entry.last_success),
    }
}

fn set_auth_state(entry: &mut MitEntry, state: AuthState) -> Result<(), StoreError> {
    entry.last_success = u32::try_from(state.last_success)
        .map_err(|_| StoreError::backend("last_success is outside MIT's u32 timestamp range"))?;
    entry.last_failed = u32::try_from(state.last_failed)
        .map_err(|_| StoreError::backend("last_failed is outside MIT's u32 timestamp range"))?;
    entry.fail_auth_count = state.fail_count;
    Ok(())
}

async fn spawn_write<T, F>(operation: &'static str, f: F) -> Result<T, StoreError>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, StoreError> + Send + 'static,
{
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| StoreError::unavailable(format!("db2 {operation} worker failed: {e}")))?
}

fn get_entry(g: &mut Guard<'_>, key: &[u8]) -> Result<Option<MitEntry>, StoreError> {
    g.principal
        .get(key)
        .map_err(|e| io_err("reading principal", e))?
        .map(|v| decode_entry(&v))
        .transpose()
}

fn put_entry(g: &mut Guard<'_>, entry: &MitEntry) -> Result<Vec<u8>, StoreError> {
    let (key, value) = encode_entry(entry)?;
    g.principal
        .put(&key, &value)
        .map_err(|e| io_err("writing principal", e))?;
    Ok(key)
}

/// `krb5_db2_delete_principal`: overwrite the keys with zeros, then delete.
fn delete_entry(g: &mut Guard<'_>, key: &[u8]) -> Result<bool, StoreError> {
    let Some(entry) = get_entry(g, key)? else {
        return Ok(false);
    };
    put_entry(g, &zeroed_keys(entry))?;
    g.principal
        .delete(key)
        .map_err(|e| io_err("deleting principal", e))
}

fn all_entries(g: &mut Guard<'_>) -> Result<Vec<MitEntry>, StoreError> {
    let mut out = Vec::new();
    let mut err = None;
    g.principal
        .for_each(|_, v| match decode_entry(&v) {
            Ok(e) => {
                out.push(e);
                Ok(true)
            }
            Err(e) => {
                err = Some(e);
                Ok(false)
            }
        })
        .map_err(|e| io_err("iterating principals", e))?;
    err.map_or(Ok(out), Err)
}

fn all_policies(g: &mut Guard<'_>) -> Result<Vec<MitPolicy>, StoreError> {
    let pol = g
        .policy()
        .map_err(|e| io_err("opening policy database", e))?;
    pol.entries()
        .map_err(|e| io_err("iterating policies", e))?
        .iter()
        .map(|(_, v)| decode_policy(v))
        .collect()
}

fn mit_policy(policy: Policy) -> MitPolicy {
    MitPolicy {
        name: policy.name,
        pw_min_life: policy.pw_min_life,
        pw_max_life: policy.pw_max_life,
        pw_min_length: policy.pw_min_length,
        pw_min_classes: policy.pw_min_classes,
        pw_history_num: policy.pw_history_num,
        pw_max_fail: policy.pw_max_fail,
        pw_failcnt_interval: policy.pw_failcnt_interval,
        pw_lockout_duration: policy.pw_lockout_duration,
        attributes: policy.attributes,
        max_life: policy.max_life,
        max_renewable_life: policy.max_renewable_life,
        allowed_keysalts: policy.allowed_keysalts,
        tl_data: policy
            .tl_data
            .into_iter()
            .map(|t| TlData {
                kind: t.kind,
                data: t.data,
            })
            .collect(),
    }
}

fn exists_error(key: &[u8]) -> StoreError {
    let key = key.strip_suffix(&[0]).unwrap_or(key);
    StoreError::conflict(format!(
        "Principal or policy already exists: {}",
        String::from_utf8_lossy(key)
    ))
}

impl Db2Store {
    /// `kdb5_util create`.
    pub fn create(
        config: &krb5_rs::kdc::RealmConfig,
        master: &EncryptionKey,
    ) -> Result<Self, StoreError> {
        let options = Db2Options::from_config(config)?;
        let realm = config.kdc.realm.as_str();
        let base = &config.database_name;
        if base.exists() {
            return Err(StoreError::conflict(format!(
                "Cannot open DB2 database '{}': File exists",
                base.display()
            )));
        }
        let life = (config.kdc.max_life != Duration::ZERO).then_some(config.kdc.max_life);
        let renewable = (config.kdc.max_renewable_life != Duration::ZERO)
            .then_some(config.kdc.max_renewable_life);
        let expiration = config.default_principal_expiration;
        let now = now_time();
        let master_principal =
            krb5_rs::kdc::kdb::master::master_principal_named(&options.master_key_name)?;
        let creator_key = unparse_name(&PrincipalName::new_principal("db_creation"), realm);
        let tgt_principal = PrincipalName {
            name_type: 2,
            name_string: vec![
                KerberosString::from_bytes(b"krbtgt")
                    .map_err(|e| StoreError::backend(e.to_string()))?,
                KerberosString::from_bytes(realm.as_bytes())
                    .map_err(|e| StoreError::backend(e.to_string()))?,
            ],
        };
        let record = |name: PrincipalName, attributes, keys| PrincipalRecord {
            unlock: false,
            entry: PrincipalEntry {
                name,
                realm: realm.to_owned(),
                attributes,
                max_life: life,
                max_renewable_life: renewable,
                expiration,
                pw_expiration: None,
                keys,
                allowed_to_delegate_to: Vec::new(),
                allowed_to_delegate_from: Vec::new(),
                require_auth: None,
                otp: None,
                pkinit_cert_match: None,
                session_enctypes: None,
                policy: None,
                security_epoch: 0,
                last_admin_unlock: None,
            },
            last_pwd_change: None,
            mod_time: Some(now),
            mod_by: Some(creator_key.clone()),
            password_history: None,
        };
        let km_record = record(
            master_principal,
            PrincipalAttributes::DISALLOW_ALL_TIX | PrincipalAttributes::LOCKDOWN_KEYS,
            vec![KeyEntry {
                kvno: 1,
                key: master.clone(),
                salt: None,
                s2kparams: None,
            }],
        );
        let mut tgt_keys = Vec::with_capacity(config.supported_keysalts.len());
        // kdb5_create encrypts each random krbtgt key with a NULL keysalt.
        for (enctype, _salt_type) in &config.supported_keysalts {
            let mut key = random_keys(1, &[*enctype])
                .map_err(|e| StoreError::backend(e.to_string()))?
                .pop()
                .ok_or_else(|| StoreError::backend("no random krbtgt key generated"))?;
            key.salt = None;
            tgt_keys.push(key);
        }
        let tgt_record = record(tgt_principal, PrincipalAttributes::LOCKDOWN_KEYS, tgt_keys);
        let single = MasterKeys::single(master.clone());
        let mut km = new_entry(&km_record, &single, &creator_key)?;
        let mkvno_tl = km
            .tl_data
            .iter()
            .position(|tl| tl.kind == MKVNO)
            .map(|at| km.tl_data.remove(at));
        let mut actkvno = Vec::with_capacity(8);
        actkvno.extend_from_slice(&1u16.to_le_bytes());
        actkvno.extend_from_slice(&1u16.to_le_bytes());
        actkvno.extend_from_slice(&0u32.to_le_bytes());
        km.tl_data.push(TlData {
            kind: ACTKVNO,
            data: actkvno,
        });
        km.tl_data.extend(mkvno_tl);
        let mut tgt = new_entry(&tgt_record, &single, &creator_key)?;
        tgt.tl_data.retain(|tl| tl.kind != MKVNO);

        if let Some(parent) = base.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent)
                .map_err(|e| io_err("creating database directory", e))?;
        }
        let files =
            Db2Files::create(base, options.hash).map_err(|e| io_err("creating DB2 database", e))?;
        {
            let mut g = files.write().map_err(|e| io_err("locking database", e))?;
            put_entry(&mut g, &km)?;
            put_entry(&mut g, &tgt)?;
            g.commit().map_err(|e| io_err("writing database", e))?;
        }
        let store = Self::from_files(files, realm, master, options);
        store.refresh_master()?;
        store.with_ulog(config)
    }

    pub fn open(
        config: &krb5_rs::kdc::RealmConfig,
        master: &EncryptionKey,
    ) -> Result<Self, StoreError> {
        let store = Self::open_without_master_key(config, master)?;
        store.refresh_master()?;
        store.with_ulog(config)
    }

    pub fn open_without_master(config: &krb5_rs::kdc::RealmConfig) -> Result<Self, StoreError> {
        Self::open_without_master_key(config, &EncryptionKey::new(0, Vec::new()))?.with_ulog(config)
    }

    fn open_without_master_key(
        config: &krb5_rs::kdc::RealmConfig,
        master: &EncryptionKey,
    ) -> Result<Self, StoreError> {
        let options = Db2Options::from_config(config)?;
        let base = &config.database_name;
        if !base.exists() {
            return Err(StoreError::not_found(format!(
                "Cannot open DB2 database '{}': No such file or directory",
                base.display()
            )));
        }
        let files =
            Db2Files::open(base, options.hash).map_err(|e| io_err("opening DB2 database", e))?;
        Ok(Self::from_files(
            files,
            config.kdc.realm.as_str(),
            master,
            options,
        ))
    }

    fn from_files(
        files: Db2Files,
        realm: &str,
        master: &EncryptionKey,
        options: Db2Options,
    ) -> Self {
        Self {
            inner: Arc::new(Inner {
                files,
                master: std::sync::RwLock::new(MasterKeys::single(master.clone())),
                supplied_master: master.clone(),
                realm: realm.to_owned(),
                options,
                ulog: None,
            }),
        }
    }

    fn with_ulog(mut self, config: &krb5_rs::kdc::RealmConfig) -> Result<Self, StoreError> {
        if config.iprop.enabled {
            let ulog = Ulog::map(&config.iprop.logfile, config.iprop.ulogsize)?;
            Arc::get_mut(&mut self.inner)
                .ok_or_else(|| StoreError::backend("db2 store is already shared"))?
                .ulog = Some(ulog);
        }
        Ok(self)
    }

    pub fn ulog(&self) -> Option<&Ulog> {
        self.inner.ulog.as_ref()
    }

    /// `krb5_db2_get_age`.
    pub fn age(&self) -> Option<std::time::SystemTime> {
        self.inner.files.age()
    }

    pub fn options(&self) -> &Db2Options {
        &self.inner.options
    }

    fn lock_ulog(&self) -> Result<Option<UlogLock<'_>>, StoreError> {
        self.inner.ulog.as_ref().map(Ulog::lock).transpose()
    }

    fn log_held(&self, held: Option<&UlogLock<'_>>, mut update: Update) -> Result<(), StoreError> {
        match (self.inner.ulog.as_ref(), held) {
            (Some(ulog), Some(held)) => ulog.add_update_locked(held, &mut update),
            _ => Ok(()),
        }
    }

    fn reset_ulog(&self) -> Result<(), StoreError> {
        self.inner.ulog.as_ref().map_or(Ok(()), Ulog::init_header)
    }

    fn read(&self) -> Result<Guard<'_>, StoreError> {
        self.inner
            .files
            .read()
            .map_err(|e| io_err("locking database", e))
    }

    fn write(&self) -> Result<Guard<'_>, StoreError> {
        self.inner
            .files
            .write()
            .map_err(|e| io_err("locking database", e))
    }

    fn refresh_master(&self) -> Result<(), StoreError> {
        let name =
            krb5_rs::kdc::kdb::master::master_principal_named(&self.inner.options.master_key_name)?;
        let raw = self
            .get_raw(&name, &self.inner.realm)?
            .ok_or_else(|| StoreError::backend("db2 database has no K/M principal"))?;
        let loaded = self.master_keys().keys.clone();
        let keys = match loaded
            .iter()
            .map(|(_, key)| key)
            .find_map(|key| MasterKeys::fetch(&raw, key).ok())
        {
            Some(keys) => keys,
            None => MasterKeys::fetch(&raw, &self.inner.supplied_master)?,
        };
        *self
            .inner
            .master
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = keys;
        Ok(())
    }

    fn master_keys(&self) -> std::sync::RwLockReadGuard<'_, MasterKeys> {
        self.inner
            .master
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn decode(&self, entry: &MitEntry) -> Result<PrincipalRecord, StoreError> {
        if self.master_keys().get(entry_mkvno(entry)?).is_none() {
            self.refresh_master()?;
        }
        record_from_entry(entry, &self.master_keys())
    }

    fn get_raw(&self, name: &PrincipalName, realm: &str) -> Result<Option<MitEntry>, StoreError> {
        let key = db_key(&unparse_name(name, realm));
        get_entry(&mut self.read()?, &key)
    }

    pub fn principal_sync(
        &self,
        name: &PrincipalName,
        realm: &str,
    ) -> Result<Option<PrincipalEntry>, StoreError> {
        Ok(self.get_record_sync(name, realm)?.map(|r| r.entry))
    }

    /// The stored entry, lockout fields included.
    pub fn raw_entry(
        &self,
        name: &PrincipalName,
        realm: &str,
    ) -> Result<Option<MitEntry>, StoreError> {
        self.get_raw(name, realm)
    }

    pub fn raw_policy(&self, name: &str) -> Result<Option<MitPolicy>, StoreError> {
        let mut g = self.read()?;
        let pol = g
            .policy()
            .map_err(|e| io_err("opening policy database", e))?;
        pol.get(&policy_key(name))
            .map_err(|e| io_err("reading policy", e))?
            .map(|v| decode_policy(&v))
            .transpose()
    }

    pub fn policy_names_sync(&self) -> Result<Vec<String>, StoreError> {
        Ok(self
            .list_policies_sync()?
            .into_iter()
            .map(|p| p.name)
            .collect())
    }

    fn get_record_sync(
        &self,
        name: &PrincipalName,
        realm: &str,
    ) -> Result<Option<PrincipalRecord>, StoreError> {
        self.get_raw(name, realm)?
            .as_ref()
            .map(|e| self.decode(e))
            .transpose()
    }

    fn list_records_sync(&self) -> Result<Vec<PrincipalRecord>, StoreError> {
        self.refresh_master()?;
        let entries = all_entries(&mut self.read()?)?;
        let keys = self.master_keys();
        entries
            .iter()
            .map(|e| record_from_entry(e, &keys))
            .collect()
    }

    fn get_policy_sync(&self, name: &str) -> Result<Option<Policy>, StoreError> {
        Ok(self.raw_policy(name)?.as_ref().map(policy_from_entry))
    }

    fn list_policies_sync(&self) -> Result<Vec<Policy>, StoreError> {
        let mut policies: Vec<Policy> = all_policies(&mut self.read()?)?
            .iter()
            .map(policy_from_entry)
            .collect();
        policies.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(policies)
    }

    fn auth_state_sync(&self, name: &PrincipalName, realm: &str) -> Result<AuthState, StoreError> {
        Ok(self
            .get_raw(name, realm)?
            .as_ref()
            .map(auth_state_of)
            .unwrap_or_default())
    }

    /// `krb5_db2_lockout_audit`: the counters live in the principal entry,
    /// written with `krb5_db2_put_principal` (not logged to iprop).
    fn apply_auth_state_sync(
        &self,
        name: &PrincipalName,
        realm: &str,
        update: AuthStateUpdate,
    ) -> Result<AuthState, StoreError> {
        let opts = &self.inner.options;
        let key = db_key(&unparse_name(name, realm));
        let mut g = self.write()?;
        let Some(mut entry) = get_entry(&mut g, &key)? else {
            return Ok(AuthState::default());
        };
        let mut state = auth_state_of(&entry);
        let before = state;
        match update {
            AuthStateUpdate::Failure { .. } if opts.disable_lockout => {}
            AuthStateUpdate::Success {
                stamp,
                clear_failures,
                record_success,
            } => state.apply(&AuthStateUpdate::Success {
                stamp,
                clear_failures: clear_failures && !opts.disable_lockout,
                record_success: record_success && !opts.disable_last_success,
            }),
            other => state.apply(&other),
        }
        if state != before {
            set_auth_state(&mut entry, state)?;
            put_entry(&mut g, &entry)?;
            g.commit().map_err(|e| io_err("writing principal", e))?;
        }
        Ok(state)
    }

    fn create_principal_sync(
        &self,
        entry: PrincipalEntry,
        last_pwd_change: Option<KerberosTime>,
    ) -> Result<(), StoreError> {
        let modifier = admin_name(&self.inner.realm);
        self.create_principal_as(entry, last_pwd_change, modifier, &[])
    }

    fn create_principal_as(
        &self,
        entry: PrincipalEntry,
        last_pwd_change: Option<KerberosTime>,
        modifier: Vec<u8>,
        tl: &[TlData],
    ) -> Result<(), StoreError> {
        self.refresh_master()?;
        let record = PrincipalRecord {
            unlock: false,
            mod_time: Some(now_time()),
            last_pwd_change,
            mod_by: Some(modifier.clone()),
            password_history: None,
            entry,
        };
        let mut raw = new_entry(&record, &self.master_keys(), &modifier)?;
        update_tl_data(&mut raw, tl);
        self.create_raw(&raw)
    }

    pub fn create_raw(&self, raw: &MitEntry) -> Result<(), StoreError> {
        let (key, _) = encode_entry(raw)?;
        let held = self.lock_ulog()?;
        {
            let mut g = self.write()?;
            if get_entry(&mut g, &key)?.is_some() {
                return Err(exists_error(&key));
            }
            put_entry(&mut g, raw)?;
            g.commit().map_err(|e| io_err("writing principal", e))?;
        }
        self.log_held(held.as_ref(), update_from_entry(None, raw))
    }

    pub fn rename_raw<F>(&self, name: &PrincipalName, realm: &str, f: F) -> Result<(), StoreError>
    where
        F: FnOnce(MitEntry, &MasterKeys) -> Result<MitEntry, StoreError>,
    {
        self.refresh_master()?;
        let keys = self.master_keys().clone();
        let src_name = unparse_name(name, realm);
        let src = db_key(&src_name);
        let held = self.lock_ulog()?;
        let renamed = {
            let mut g = self.write()?;
            let entry = get_entry(&mut g, &src)?.ok_or_else(|| {
                StoreError::not_found(format!("Principal {name}@{realm} does not exist"))
            })?;
            let renamed = f(entry, &keys)?;
            let (dest, _) = encode_entry(&renamed)?;
            if get_entry(&mut g, &dest)?.is_some() {
                return Err(exists_error(&dest));
            }
            put_entry(&mut g, &renamed)?;
            delete_entry(&mut g, &src)?;
            g.commit().map_err(|e| io_err("writing principal", e))?;
            renamed
        };
        self.log_held(held.as_ref(), update_from_entry(None, &renamed))?;
        self.log_held(held.as_ref(), Update::deletion(src_name))
    }

    fn update_principal_sync<F>(
        &self,
        name: &PrincipalName,
        realm: &str,
        f: F,
    ) -> Result<PrincipalRecord, StoreError>
    where
        F: FnMut(&mut PrincipalRecord) -> Result<(), StoreError>,
    {
        self.update_principal_as(name, realm, admin_name(realm), &[], f)
    }

    fn update_principal_as<F>(
        &self,
        name: &PrincipalName,
        realm: &str,
        modifier: Vec<u8>,
        tl: &[TlData],
        mut f: F,
    ) -> Result<PrincipalRecord, StoreError>
    where
        F: FnMut(&mut PrincipalRecord) -> Result<(), StoreError>,
    {
        self.refresh_master()?;
        let key = db_key(&unparse_name(name, realm));
        let held = self.lock_ulog()?;
        let (current, raw, record) = {
            let mut g = self.write()?;
            let mut raw = get_entry(&mut g, &key)?.ok_or_else(|| {
                StoreError::not_found(format!("Principal {name}@{realm} does not exist"))
            })?;
            let current = raw.clone();
            let keys = self.master_keys().clone();
            let mut record = record_from_entry(&raw, &keys)?;
            f(&mut record)?;
            record.mod_time = Some(now_time());
            record.mod_by = Some(modifier.clone());
            merge_record(&mut raw, &record, &keys, Some(&modifier))?;
            update_tl_data(&mut raw, tl);
            put_entry(&mut g, &raw)?;
            g.commit().map_err(|e| io_err("writing principal", e))?;
            (current, raw, record)
        };
        if self.inner.ulog.is_some() {
            self.log_held(held.as_ref(), update_from_entry(Some(&current), &raw))?;
        }
        Ok(record)
    }

    pub fn master_key_list(&self) -> Result<MasterKeys, StoreError> {
        self.refresh_master()?;
        Ok(self.master_keys().clone())
    }

    pub fn raw_entries(&self) -> Result<Vec<MitEntry>, StoreError> {
        Ok(self.dump_entries()?.0)
    }

    pub fn update_raw<F>(&self, name: &PrincipalName, realm: &str, f: F) -> Result<bool, StoreError>
    where
        F: FnOnce(&mut MitEntry, &MasterKeys) -> Result<bool, StoreError>,
    {
        self.refresh_master()?;
        let keys = self.master_keys().clone();
        let key = db_key(&unparse_name(name, realm));
        let held = self.lock_ulog()?;
        let (current, raw) = {
            let mut g = self.write()?;
            let mut raw = get_entry(&mut g, &key)?.ok_or_else(|| {
                StoreError::not_found(format!("Principal {name}@{realm} does not exist"))
            })?;
            let current = raw.clone();
            if !f(&mut raw, &keys)? {
                return Ok(false);
            }
            put_entry(&mut g, &raw)?;
            g.commit().map_err(|e| io_err("writing principal", e))?;
            (current, raw)
        };
        if self.inner.ulog.is_some() {
            self.log_held(held.as_ref(), update_from_entry(Some(&current), &raw))?;
        }
        self.refresh_master()?;
        Ok(true)
    }

    fn delete_principal_sync(&self, name: &PrincipalName, realm: &str) -> Result<bool, StoreError> {
        let held = self.lock_ulog()?;
        let name = unparse_name(name, realm);
        let deleted = self.delete_unlogged(&name)?;
        if deleted {
            self.log_held(held.as_ref(), Update::deletion(name))?;
        }
        Ok(deleted)
    }

    fn delete_unlogged(&self, name: &[u8]) -> Result<bool, StoreError> {
        let mut g = self.write()?;
        let deleted = delete_entry(&mut g, &db_key(name))?;
        g.commit().map_err(|e| io_err("writing principal", e))?;
        Ok(deleted)
    }

    pub fn replay_updates(&self, updates: &[Update]) -> Result<(), StoreError> {
        let ulog = self
            .inner
            .ulog
            .as_ref()
            .ok_or_else(|| StoreError::backend("Iprop not enabled"))?;
        let result = updates.iter().filter(|u| u.commit).try_for_each(|upd| {
            if upd.deleted {
                self.delete_unlogged(&upd.princ_name)?;
            } else {
                self.replay_put(upd)?;
            }
            ulog.store_replayed(upd)
        });
        if result.is_err() {
            let _ = ulog.init_header();
        }
        result
    }

    fn replay_put(&self, upd: &Update) -> Result<(), StoreError> {
        let old = db_key(&upd.princ_name);
        let mut g = self.write()?;
        let current = get_entry(&mut g, &old)?;
        let entry = entry_from_update(current, upd)?;
        let key = put_entry(&mut g, &entry)?;
        if key != old {
            delete_entry(&mut g, &old)?;
        }
        g.commit().map_err(|e| io_err("writing principal", e))
    }

    fn create_policy_sync(&self, policy: Policy) -> Result<(), StoreError> {
        let raw = mit_policy(policy);
        let key = policy_key(&raw.name);
        let value = encode_policy(&raw)?;
        {
            let mut g = self.write()?;
            let pol = g
                .policy()
                .map_err(|e| io_err("opening policy database", e))?;
            if pol
                .get(&key)
                .map_err(|e| io_err("reading policy", e))?
                .is_some()
            {
                return Err(StoreError::conflict(format!(
                    "Principal or policy already exists: policy {}",
                    raw.name
                )));
            }
            pol.put(&key, &value)
                .map_err(|e| io_err("writing policy", e))?;
            g.commit().map_err(|e| io_err("writing policy", e))?;
        }
        self.reset_ulog()
    }

    fn update_policy_sync<F>(&self, name: &str, mut f: F) -> Result<Policy, StoreError>
    where
        F: FnMut(&mut Policy) -> Result<(), StoreError>,
    {
        let key = policy_key(name);
        let policy = {
            let mut g = self.write()?;
            let pol = g
                .policy()
                .map_err(|e| io_err("opening policy database", e))?;
            let bytes = pol
                .get(&key)
                .map_err(|e| io_err("reading policy", e))?
                .ok_or_else(|| {
                    StoreError::not_found(format!("Policy \"{name}\" does not exist"))
                })?;
            let mut raw = decode_policy(&bytes)?;
            let mut policy = policy_from_entry(&raw);
            f(&mut policy)?;
            merge_policy(&mut raw, &policy)?;
            pol.put(&key, &encode_policy(&raw)?)
                .map_err(|e| io_err("writing policy", e))?;
            g.commit().map_err(|e| io_err("writing policy", e))?;
            policy
        };
        self.reset_ulog()?;
        Ok(policy)
    }

    fn delete_policy_sync(&self, name: &str) -> Result<bool, StoreError> {
        let deleted = {
            let mut g = self.write()?;
            let pol = g
                .policy()
                .map_err(|e| io_err("opening policy database", e))?;
            let deleted = pol
                .delete(&policy_key(name))
                .map_err(|e| io_err("deleting policy", e))?;
            g.commit().map_err(|e| io_err("writing policy", e))?;
            deleted
        };
        if deleted {
            self.reset_ulog()?;
        }
        Ok(deleted)
    }

    pub fn dump_entries(&self) -> Result<(Vec<MitEntry>, Vec<MitPolicy>), StoreError> {
        let mut g = self.read()?;
        let entries = all_entries(&mut g)?;
        let policies = all_policies(&mut g)?;
        Ok((entries, policies))
    }

    /// `kdb5_util load`: a full load builds `<name>~` and moves it into
    /// place (`krb5_db2_promote_db`); `-update` writes in place.
    pub fn load_dump(
        config: &krb5_rs::kdc::RealmConfig,
        entries: &[MitEntry],
        policies: &[MitPolicy],
        update: bool,
        merge_nra: bool,
        log_from: usize,
    ) -> Result<(), StoreError> {
        let options = Db2Options::from_config(config)?;
        let base = config.database_name.clone();
        if update && !base.exists() {
            return Err(StoreError::not_found(format!(
                "Cannot open DB2 database '{}': No such file or directory",
                base.display()
            )));
        }
        if let Some(parent) = base.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent)
                .map_err(|e| io_err("creating database directory", e))?;
        }
        let ulog = match update && config.iprop.enabled {
            true => Some(Ulog::map(&config.iprop.logfile, config.iprop.ulogsize)?),
            false => None,
        };
        let held = ulog.as_ref().map(Ulog::lock).transpose()?;
        let mut logged = Vec::new();
        if update {
            let files = Db2Files::open(&base, options.hash)
                .map_err(|e| io_err("opening DB2 database", e))?;
            let mut g = files.write().map_err(|e| io_err("locking database", e))?;
            for (i, entry) in entries.iter().enumerate() {
                let (key, _) = encode_entry(entry)?;
                let current = get_entry(&mut g, &key)?;
                if ulog.is_some() && i >= log_from {
                    logged.push(update_from_entry(current.as_ref(), entry));
                }
                let mut entry = entry.clone();
                if let (true, Some(current)) = (merge_nra, current.as_ref()) {
                    entry.last_success = current.last_success;
                    entry.last_failed = current.last_failed;
                    entry.fail_auth_count = current.fail_auth_count;
                }
                put_entry(&mut g, &entry)?;
            }
            Self::put_policies(&mut g, policies)?;
            if let Some(ulog) = &ulog {
                for update in &logged {
                    ulog.check_fits(update)?;
                }
            }
            g.commit().map_err(|e| io_err("writing database", e))?;
        } else {
            let temp = suffixed(&base, "~");
            Db2Files::destroy(&temp).map_err(|e| io_err("removing temporary database", e))?;
            let files = Db2Files::create(&temp, options.hash)
                .map_err(|e| io_err("creating DB2 database", e))?;
            {
                let mut g = files.write().map_err(|e| io_err("locking database", e))?;
                for entry in entries {
                    put_entry(&mut g, entry)?;
                }
                Self::put_policies(&mut g, policies)?;
                g.commit().map_err(|e| io_err("writing database", e))?;
            }
            drop(files);
            promote(&temp, &base)?;
        }
        if let (Some(ulog), Some(held)) = (&ulog, &held) {
            if !policies.is_empty() {
                ulog.init_header_locked(held)?;
            }
            for mut update in logged {
                if let Err(e) = ulog.add_update_locked(held, &mut update) {
                    ulog.init_header_locked(held)?;
                    return Err(e);
                }
            }
        }
        Ok(())
    }

    fn put_policies(g: &mut Guard<'_>, policies: &[MitPolicy]) -> Result<(), StoreError> {
        let pol = g
            .policy()
            .map_err(|e| io_err("opening policy database", e))?;
        for p in policies {
            pol.put(&policy_key(&p.name), &encode_policy(p)?)
                .map_err(|e| io_err("writing policy", e))?;
        }
        Ok(())
    }

    pub fn as_caller(&self, modifier: Vec<u8>) -> CallerStore {
        CallerStore {
            store: self.clone(),
            modifier,
            tl_data: Vec::new(),
        }
    }
}

/// `ctx_promote`: move the temporary database over the real one under the
/// real database's exclusive lock.
fn promote(temp: &Path, base: &Path) -> Result<(), StoreError> {
    let rename = |from: PathBuf, to: PathBuf| {
        std::fs::rename(&from, &to).map_err(|e| io_err("renaming loaded database", e))
    };
    // krb5_db2_promote_db: an existing real database must be locked first.
    let existing = if base.exists() {
        Some(Db2Files::open(base, false).map_err(|e| io_err("opening DB2 database", e))?)
    } else {
        None
    };
    let guard = match &existing {
        Some(f) => Some(f.write().map_err(|e| io_err("locking database", e))?),
        None => None,
    };
    rename(temp.to_path_buf(), base.to_path_buf())?;
    rename(suffixed(temp, SUFFIX_POLICY), suffixed(base, SUFFIX_POLICY))?;
    drop(guard);
    for suffix in [SUFFIX_LOCK, SUFFIX_POLICY_LOCK] {
        let real = suffixed(base, suffix);
        if real.exists() {
            let _ = std::fs::remove_file(suffixed(temp, suffix));
        } else {
            rename(suffixed(temp, suffix), real)?;
        }
    }
    Ok(())
}

/// A [`Db2Store`] view whose principal writes record `modifier` as the
/// last modifier (`kdb_put_entry`).
#[derive(Clone)]
pub struct CallerStore {
    store: Db2Store,
    modifier: Vec<u8>,
    tl_data: Vec<TlData>,
}

impl CallerStore {
    pub fn with_tl_data(mut self, tl: Vec<TlData>) -> Self {
        self.tl_data = tl;
        self
    }
}

impl PrincipalStore for Db2Store {
    async fn lookup(
        &self,
        name: &PrincipalName,
        realm: &str,
    ) -> Result<Option<PrincipalEntry>, StoreError> {
        self.principal_sync(name, realm)
    }
}

impl PolicyStore for Db2Store {
    async fn policy(&self, name: &str) -> Result<Option<Policy>, StoreError> {
        self.get_policy_sync(name)
    }
}

impl AuthStateStore for Db2Store {
    async fn auth_state(&self, name: &PrincipalName, realm: &str) -> Result<AuthState, StoreError> {
        self.auth_state_sync(name, realm)
    }

    fn apply(
        &self,
        name: &PrincipalName,
        realm: &str,
        update: &AuthStateUpdate,
    ) -> impl std::future::Future<Output = Result<AuthState, StoreError>> + Send {
        let store = self.clone();
        let name = name.clone();
        let realm = realm.to_owned();
        let update = *update;
        spawn_write("lockout update", move || {
            store.apply_auth_state_sync(&name, &realm, update)
        })
    }
}

impl HealthCheck for Db2Store {
    async fn health(&self) -> Result<(), StoreError> {
        self.read()
            .map(|_| ())
            .map_err(|e| StoreError::unavailable(format!("db2 health check: {e}")))
    }
}

impl AdminStore for Db2Store {
    async fn get_record(
        &self,
        name: &PrincipalName,
        realm: &str,
    ) -> Result<Option<PrincipalRecord>, StoreError> {
        self.get_record_sync(name, realm)
    }

    fn create_principal(
        &self,
        entry: PrincipalEntry,
        last_pwd_change: Option<KerberosTime>,
    ) -> impl std::future::Future<Output = Result<(), StoreError>> + Send {
        let store = self.clone();
        spawn_write("principal create", move || {
            store.create_principal_sync(entry, last_pwd_change)
        })
    }

    fn update_principal<F>(
        &self,
        name: &PrincipalName,
        realm: &str,
        f: F,
    ) -> impl std::future::Future<Output = Result<PrincipalRecord, StoreError>> + Send
    where
        F: FnMut(&mut PrincipalRecord) -> Result<(), StoreError> + Send + 'static,
    {
        let store = self.clone();
        let name = name.clone();
        let realm = realm.to_owned();
        spawn_write("principal update", move || {
            store.update_principal_sync(&name, &realm, f)
        })
    }

    fn delete_principal(
        &self,
        name: &PrincipalName,
        realm: &str,
    ) -> impl std::future::Future<Output = Result<bool, StoreError>> + Send {
        let store = self.clone();
        let name = name.clone();
        let realm = realm.to_owned();
        spawn_write("principal delete", move || {
            store.delete_principal_sync(&name, &realm)
        })
    }

    async fn list_principals(&self) -> Result<Vec<PrincipalRecord>, StoreError> {
        self.list_records_sync()
    }

    async fn get_policy(&self, name: &str) -> Result<Option<Policy>, StoreError> {
        self.get_policy_sync(name)
    }

    fn create_policy(
        &self,
        policy: Policy,
    ) -> impl std::future::Future<Output = Result<(), StoreError>> + Send {
        let store = self.clone();
        spawn_write("policy create", move || store.create_policy_sync(policy))
    }

    fn update_policy<F>(
        &self,
        name: &str,
        f: F,
    ) -> impl std::future::Future<Output = Result<Policy, StoreError>> + Send
    where
        F: FnMut(&mut Policy) -> Result<(), StoreError> + Send + 'static,
    {
        let store = self.clone();
        let name = name.to_owned();
        spawn_write("policy update", move || store.update_policy_sync(&name, f))
    }

    fn delete_policy(
        &self,
        name: &str,
    ) -> impl std::future::Future<Output = Result<bool, StoreError>> + Send {
        let store = self.clone();
        let name = name.to_owned();
        spawn_write("policy delete", move || store.delete_policy_sync(&name))
    }

    async fn list_policies(&self) -> Result<Vec<Policy>, StoreError> {
        self.list_policies_sync()
    }
}

impl AdminStore for CallerStore {
    fn get_record(
        &self,
        name: &PrincipalName,
        realm: &str,
    ) -> impl std::future::Future<Output = Result<Option<PrincipalRecord>, StoreError>> + Send {
        self.store.get_record(name, realm)
    }

    fn create_principal(
        &self,
        entry: PrincipalEntry,
        last_pwd_change: Option<KerberosTime>,
    ) -> impl std::future::Future<Output = Result<(), StoreError>> + Send {
        let store = self.store.clone();
        let modifier = self.modifier.clone();
        let tl = self.tl_data.clone();
        spawn_write("principal create", move || {
            store.create_principal_as(entry, last_pwd_change, modifier, &tl)
        })
    }

    fn update_principal<F>(
        &self,
        name: &PrincipalName,
        realm: &str,
        f: F,
    ) -> impl std::future::Future<Output = Result<PrincipalRecord, StoreError>> + Send
    where
        F: FnMut(&mut PrincipalRecord) -> Result<(), StoreError> + Send + 'static,
    {
        let store = self.store.clone();
        let modifier = self.modifier.clone();
        let name = name.clone();
        let realm = realm.to_owned();
        let tl = self.tl_data.clone();
        spawn_write("principal update", move || {
            store.update_principal_as(&name, &realm, modifier, &tl, f)
        })
    }

    fn delete_principal(
        &self,
        name: &PrincipalName,
        realm: &str,
    ) -> impl std::future::Future<Output = Result<bool, StoreError>> + Send {
        self.store.delete_principal(name, realm)
    }

    fn list_principals(
        &self,
    ) -> impl std::future::Future<Output = Result<Vec<PrincipalRecord>, StoreError>> + Send {
        self.store.list_principals()
    }

    fn get_policy(
        &self,
        name: &str,
    ) -> impl std::future::Future<Output = Result<Option<Policy>, StoreError>> + Send {
        self.store.get_policy(name)
    }

    fn create_policy(
        &self,
        policy: Policy,
    ) -> impl std::future::Future<Output = Result<(), StoreError>> + Send {
        self.store.create_policy(policy)
    }

    fn update_policy<F>(
        &self,
        name: &str,
        f: F,
    ) -> impl std::future::Future<Output = Result<Policy, StoreError>> + Send
    where
        F: FnMut(&mut Policy) -> Result<(), StoreError> + Send + 'static,
    {
        self.store.update_policy(name, f)
    }

    fn delete_policy(
        &self,
        name: &str,
    ) -> impl std::future::Future<Output = Result<bool, StoreError>> + Send {
        self.store.delete_policy(name)
    }

    fn list_policies(
        &self,
    ) -> impl std::future::Future<Output = Result<Vec<Policy>, StoreError>> + Send {
        self.store.list_policies()
    }
}
