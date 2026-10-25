use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use fs2::FileExt;
use heed::types::Bytes;
use heed::{Database, Env, EnvFlags, EnvOpenOptions, WithTls, WithoutTls};
use krb5_rs::kdc::kdb::mit::mkey::{entry_mkvno, MasterKeys};
use krb5_rs::kdc::kdb::mit::ulog::{entry_from_update, update_from_entry, Ulog, Update};
use krb5_rs::kdc::kdb::mit::{
    decode_lockout, encode_lockout, merge_policy, merge_record, new_entry, policy_from_entry,
    record_from_entry, unparse_name, MitEntry, MitPolicy, TlData, ACTKVNO, MKVNO,
};
use krb5_rs::kdc::kdb::FileStore;
use krb5_rs::kdc::{
    kerberos_time, random_keys, AdminStore, AuthState, AuthStateStore, AuthStateUpdate,
    HealthCheck, KeyEntry, Policy, PolicyStore, PrincipalAttributes, PrincipalEntry,
    PrincipalRecord, PrincipalStore, StoreError,
};
use krb5_rs::types::{EncryptionKey, KerberosString, KerberosTime, PrincipalName};

type Db = Database<Bytes, Bytes>;
type MainEnv = Env<WithoutTls>;
type LockoutEnv = Env<WithTls>;

/// MIT klmdb environment settings. `max_readers = 0` uses LMDB's default.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LmdbOptions {
    /// LMDB map size in MiB (MIT default: 128).
    pub mapsize_mb: usize,
    /// LMDB reader slots; zero selects the library default (MIT default).
    pub max_readers: u32,
    /// Disable sync for the principal/policy environment only.
    pub nosync: bool,
    /// Disable lockout failure updates.
    pub disable_lockout: bool,
    /// Disable last-success updates.
    pub disable_last_success: bool,
}

impl Default for LmdbOptions {
    fn default() -> Self {
        Self {
            mapsize_mb: 128,
            max_readers: 0,
            nosync: false,
            disable_lockout: false,
            disable_last_success: false,
        }
    }
}

impl LmdbOptions {
    /// Read the klmdb-specific settings from `[dbmodules]`.
    pub fn from_db_module(
        module: &krb5_rs::kdc::DbModuleConfig,
        disable_lockout: bool,
        disable_last_success: bool,
    ) -> Result<Self, StoreError> {
        let number = |key: &str, default: usize| -> Result<usize, StoreError> {
            module
                .get(key)
                .map(|value| {
                    value
                        .parse::<usize>()
                        .map_err(|_| StoreError::backend(format!("{key}: not a number")))
                })
                .unwrap_or(Ok(default))
        };
        let mut options = Self {
            mapsize_mb: number("mapsize", 128)?,
            max_readers: u32::try_from(number("max_readers", 0)?)
                .map_err(|_| StoreError::backend("max_readers is too large"))?,
            nosync: false,
            disable_lockout,
            disable_last_success,
        };
        if let Some(value) = module.get("nosync") {
            options.nosync = match value.to_ascii_lowercase().as_str() {
                "true" | "yes" | "on" | "1" => true,
                "false" | "no" | "off" | "0" => false,
                _ => return Err(StoreError::backend("nosync: not a boolean")),
            };
        }
        Ok(options)
    }
}

struct Inner {
    main_env: MainEnv,
    principal_db: Db,
    policy_db: Db,
    lockout: Option<(LockoutEnv, Db)>,
    master: std::sync::RwLock<MasterKeys>,
    supplied_master: EncryptionKey,
    realm: String,
    options: LmdbOptions,
    ulog: Option<Ulog>,
    #[cfg(test)]
    fail_lockout_write: std::sync::atomic::AtomicBool,
}

/// Failure injection for the crash-safety tests; always default otherwise.
#[derive(Clone, Copy, Default)]
struct Faults {
    /// Stop publishing before this step of [`PUBLISH_ORDER`].
    publish_stop: Option<usize>,
    /// Stop after publishing a conversion, before the legacy backup rename.
    before_backup: bool,
    /// Fail `create` once its temporary environments exist.
    after_create_envs: bool,
}

/// A synchronous LMDB store. Store reads are done inline because they are
/// short read-only transactions over memory-mapped pages; all mutations are
/// submitted to Tokio's blocking pool.
#[derive(Clone)]
pub struct LmdbStore {
    inner: Arc<Inner>,
}

fn backend(operation: &str, error: impl std::fmt::Display) -> StoreError {
    StoreError::backend(format!("LMDB {operation}: {error}"))
}

fn appended(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(suffix);
    PathBuf::from(name)
}

fn main_path(database_name: &Path) -> PathBuf {
    appended(database_name, ".mdb")
}

fn lockout_path(database_name: &Path) -> PathBuf {
    appended(database_name, ".lockout.mdb")
}

fn create_parent(database_name: &Path) -> Result<(), StoreError> {
    if let Some(parent) = database_name.parent().filter(|p| !p.as_os_str().is_empty()) {
        fs::create_dir_all(parent).map_err(|e| backend("creating database directory", e))?;
    }
    Ok(())
}

fn map_size(options: &LmdbOptions) -> Result<usize, StoreError> {
    options
        .mapsize_mb
        .checked_mul(1024 * 1024)
        .ok_or_else(|| StoreError::backend("mapsize is too large"))
}

fn open_main_env(path: &Path, options: &LmdbOptions) -> Result<MainEnv, StoreError> {
    let mut builder = EnvOpenOptions::new();
    builder.max_dbs(2);
    if options.mapsize_mb != 0 {
        builder.map_size(map_size(options)?);
    }
    if options.max_readers != 0 {
        builder.max_readers(options.max_readers);
    }
    let mut flags = EnvFlags::NO_SUB_DIR;
    if options.nosync {
        flags |= EnvFlags::NO_SYNC;
    }
    unsafe {
        builder.flags(flags);
    }
    let builder = builder.read_txn_without_tls();
    unsafe { builder.open(path) }.map_err(|e| backend("opening principal environment", e))
}

fn open_lockout_env(path: &Path, options: &LmdbOptions) -> Result<LockoutEnv, StoreError> {
    let mut builder = EnvOpenOptions::new();
    builder.max_dbs(1);
    if options.mapsize_mb != 0 {
        builder.map_size(map_size(options)?);
    }
    if options.max_readers != 0 {
        builder.max_readers(options.max_readers);
    }
    unsafe {
        builder.flags(EnvFlags::NO_SUB_DIR | EnvFlags::NO_SYNC);
    }
    unsafe { builder.open(path) }.map_err(|e| backend("opening lockout environment", e))
}

fn zero_record() -> [u8; 12] {
    encode_lockout(0, 0, 0)
}

fn lockout_key(principal: &PrincipalName, realm: &str) -> Vec<u8> {
    unparse_name(principal, realm)
}

fn now_time() -> KerberosTime {
    let seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| {
            i64::try_from(duration.as_secs()).unwrap_or(i64::MAX)
        });
    kerberos_time(seconds)
}

fn lockout_from_bytes(bytes: Option<&[u8]>) -> Result<AuthState, StoreError> {
    let Some(bytes) = bytes else {
        return Ok(AuthState::default());
    };
    let (last_success, last_failed, fail_count) = decode_lockout(bytes)?;
    Ok(AuthState {
        fail_count,
        last_failed: i64::from(last_failed),
        last_success: i64::from(last_success),
    })
}

fn lockout_bytes(state: AuthState) -> Result<[u8; 12], StoreError> {
    let last_success = u32::try_from(state.last_success)
        .map_err(|_| StoreError::backend("last_success is outside MIT's u32 timestamp range"))?;
    let last_failed = u32::try_from(state.last_failed)
        .map_err(|_| StoreError::backend("last_failed is outside MIT's u32 timestamp range"))?;
    Ok(encode_lockout(last_success, last_failed, state.fail_count))
}

async fn spawn_write<T, F>(operation: &'static str, f: F) -> Result<T, StoreError>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, StoreError> + Send + 'static,
{
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| StoreError::unavailable(format!("LMDB {operation} worker failed: {e}")))?
}

impl LmdbStore {
    /// Create the two MIT-klmdb environments and seed `K/M` and `krbtgt`
    /// (`kadmin/dbutil/kdb5_create.c:291-292, 378-467`).
    ///
    /// The entries are built before anything touches disk, then written to
    /// temporary environments that are published only once seeded and
    /// verified, so a failed `create` leaves nothing behind and can be rerun.
    pub fn create(
        config: &krb5_rs::kdc::RealmConfig,
        master: &EncryptionKey,
    ) -> Result<Self, StoreError> {
        Self::create_with(config, master, Faults::default())
    }

    fn create_with(
        config: &krb5_rs::kdc::RealmConfig,
        master: &EncryptionKey,
        faults: Faults,
    ) -> Result<Self, StoreError> {
        let options = LmdbOptions::from_db_module(
            &config.db_module,
            config.kdc.disable_lockout,
            config.kdc.disable_last_success,
        )?;
        let database_name = &config.database_name;
        let realm = config.kdc.realm.as_str();
        let keysalts = &config.supported_keysalts;
        let max_life = config.kdc.max_life;
        let max_renewable_life = config.kdc.max_renewable_life;
        let expiration = config.default_principal_expiration;
        if main_path(database_name).exists() {
            return Err(StoreError::conflict(format!(
                "database {}.mdb already exists",
                database_name.display()
            )));
        }
        if FileStore::has_database_magic(database_name)? {
            return Err(StoreError::conflict(format!(
                "a legacy krb5-rs file database exists at {}; it is converted automatically when opened with db_library = klmdb (any other command or the KDC); create was not run",
                database_name.display()
            )));
        }
        let now = now_time();
        let life = (max_life != Duration::ZERO).then_some(max_life);
        let renewable = (max_renewable_life != Duration::ZERO).then_some(max_renewable_life);

        let master_principal = PrincipalName {
            name_type: 1,
            name_string: vec![
                KerberosString::from_bytes(b"K").map_err(|e| StoreError::backend(e.to_string()))?,
                KerberosString::from_bytes(b"M").map_err(|e| StoreError::backend(e.to_string()))?,
            ],
        };
        let creator = PrincipalName {
            name_type: 2,
            name_string: vec![KerberosString::from_bytes(b"db_creation")
                .map_err(|e| StoreError::backend(e.to_string()))?],
        };
        let tgt_principal = PrincipalName {
            name_type: 2,
            name_string: vec![
                KerberosString::from_bytes(b"krbtgt")
                    .map_err(|e| StoreError::backend(e.to_string()))?,
                KerberosString::from_bytes(realm.as_bytes())
                    .map_err(|e| StoreError::backend(e.to_string()))?,
            ],
        };
        let creator_key = unparse_name(&creator, realm);
        let km_record = PrincipalRecord {
            entry: PrincipalEntry {
                name: master_principal.clone(),
                realm: realm.to_owned(),
                attributes: PrincipalAttributes::DISALLOW_ALL_TIX
                    | PrincipalAttributes::LOCKDOWN_KEYS,
                max_life: life,
                max_renewable_life: renewable,
                expiration,
                pw_expiration: None,
                keys: vec![KeyEntry {
                    kvno: 1,
                    key: master.clone(),
                    salt: None,
                    s2kparams: None,
                }],
                allowed_to_delegate_to: Vec::new(),
                allowed_to_delegate_from: Vec::new(),
                policy: None,
                security_epoch: 0,
                last_admin_unlock: None,
            },
            last_pwd_change: None,
            mod_time: Some(now),
            mod_by: Some(creator_key.clone()),
            password_history: None,
        };
        let mut tgt_keys = Vec::with_capacity(keysalts.len());
        // MIT kdb5_create's TGT keysalt iterator ignores the salt type and
        // encrypts each random key with a NULL keysalt (`kdb5_create.c:338-374`).
        for (enctype, _salt_type) in keysalts {
            let mut key = random_keys(1, &[*enctype])
                .map_err(|e| StoreError::backend(e.to_string()))?
                .pop()
                .ok_or_else(|| StoreError::backend("no random krbtgt key generated"))?;
            key.salt = None;
            tgt_keys.push(key);
        }
        let tgt_record = PrincipalRecord {
            entry: PrincipalEntry {
                name: tgt_principal.clone(),
                realm: realm.to_owned(),
                attributes: PrincipalAttributes::LOCKDOWN_KEYS,
                max_life: life,
                max_renewable_life: renewable,
                expiration,
                pw_expiration: None,
                keys: tgt_keys,
                allowed_to_delegate_to: Vec::new(),
                allowed_to_delegate_from: Vec::new(),
                policy: None,
                security_epoch: 0,
                last_admin_unlock: None,
            },
            last_pwd_change: None,
            mod_time: Some(now),
            mod_by: Some(creator_key.clone()),
            password_history: None,
        };
        let mut km = new_entry(
            &km_record,
            &MasterKeys::single(master.clone()),
            &creator_key,
        )?;
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
        if let Some(mkvno) = mkvno_tl {
            km.tl_data.push(mkvno);
        }
        let mut tgt = new_entry(
            &tgt_record,
            &MasterKeys::single(master.clone()),
            &creator_key,
        )?;
        tgt.tl_data.retain(|tl| tl.kind != MKVNO);

        create_parent(database_name)?;
        let temp_base = appended(database_name, ".create.tmp");
        let temp_guard = TempEnvironments(temp_base.clone());
        temp_guard.remove_files();
        {
            let temp = Self::open_environments(&temp_base, realm, master, options.clone(), true)?;
            if faults.after_create_envs {
                return Err(StoreError::backend(
                    "injected failure after creating environments",
                ));
            }
            temp.insert_initial(vec![km, tgt])?;
            if let Some((env, db)) = &temp.inner.lockout {
                let mut txn = env
                    .write_txn()
                    .map_err(|e| backend("opening lockout write transaction", e))?;
                for principal in [&master_principal, &tgt_principal] {
                    let key = lockout_key(principal, realm);
                    db.put(&mut txn, &key, &zero_record())
                        .map_err(|e| backend("seeding lockout record", e))?;
                }
                txn.commit()
                    .map_err(|e| backend("committing lockout records", e))?;
            }
            temp.verify_master()?;
            temp.sync_all()?;
        }
        if main_path(database_name).exists() {
            return Err(StoreError::conflict(format!(
                "database {}.mdb already exists",
                database_name.display()
            )));
        }
        publish_environments(&temp_base, database_name, faults.publish_stop)?;
        let store = Self::open_environments(database_name, realm, master, options, false)?;
        store.verify_master()?;
        store.with_ulog(config)
    }

    fn with_ulog(mut self, config: &krb5_rs::kdc::RealmConfig) -> Result<Self, StoreError> {
        if config.iprop.enabled {
            let ulog = Ulog::map(&config.iprop.logfile, config.iprop.ulogsize)?;
            Arc::get_mut(&mut self.inner)
                .ok_or_else(|| StoreError::backend("klmdb store is already shared"))?
                .ulog = Some(ulog);
        }
        Ok(self)
    }

    /// The update log, when `iprop_enable` is set.
    pub fn ulog(&self) -> Option<&Ulog> {
        self.inner.ulog.as_ref()
    }

    /// `ulog_add_update` after a logged change (`lib/kdb/kdb5.c:981-1051`).
    fn log(&self, mut update: Update) -> Result<(), StoreError> {
        self.inner
            .ulog
            .as_ref()
            .map_or(Ok(()), |ulog| ulog.add_update(&mut update))
    }

    /// Policy changes reinitialize the ulog so replicas resync fully
    /// (`lib/kdb/kdb5.c:2441-2525`).
    fn reset_ulog(&self) -> Result<(), StoreError> {
        self.inner.ulog.as_ref().map_or(Ok(()), Ulog::init_header)
    }

    fn sync_all(&self) -> Result<(), StoreError> {
        self.inner
            .main_env
            .force_sync()
            .map_err(|e| backend("syncing principal environment", e))?;
        if let Some((env, _)) = &self.inner.lockout {
            env.force_sync()
                .map_err(|e| backend("syncing lockout environment", e))?;
        }
        Ok(())
    }

    /// Open an MIT klmdb database, converting a legacy krb5-rs file database
    /// if the `.mdb` environment is absent.
    pub fn open(
        config: &krb5_rs::kdc::RealmConfig,
        master: &EncryptionKey,
    ) -> Result<Self, StoreError> {
        let options = LmdbOptions::from_db_module(
            &config.db_module,
            config.kdc.disable_lockout,
            config.kdc.disable_last_success,
        )?;
        let database_name = &config.database_name;
        let realm = config.kdc.realm.as_str();
        let main = main_path(database_name);
        if FileStore::has_database_magic(database_name)? {
            if main.exists() {
                finish_legacy_backup(database_name)?;
            } else {
                auto_convert_legacy(database_name, master, realm, &options, Faults::default())?;
            }
        }
        if !main.exists() {
            return Err(StoreError::not_found(format!(
                "klmdb environment {} does not exist",
                main.display()
            )));
        }
        let store = Self::open_environments(database_name, realm, master, options, false)?;
        store.verify_master()?;
        store.with_ulog(config)
    }

    fn open_environments(
        database_name: &Path,
        realm: &str,
        master: &EncryptionKey,
        options: LmdbOptions,
        create_lockout: bool,
    ) -> Result<Self, StoreError> {
        let main_env = open_main_env(&main_path(database_name), &options)?;
        let mut txn = main_env
            .write_txn()
            .map_err(|e| backend("opening principal write transaction", e))?;
        let principal_db = main_env
            .create_database::<Bytes, Bytes>(&mut txn, Some("principal"))
            .map_err(|e| backend("opening principal database", e))?;
        let policy_db = main_env
            .create_database::<Bytes, Bytes>(&mut txn, Some("policy"))
            .map_err(|e| backend("opening policy database", e))?;
        txn.commit()
            .map_err(|e| backend("committing primary databases", e))?;

        let lockout = if !options.disable_lockout || !options.disable_last_success {
            let env = open_lockout_env(&lockout_path(database_name), &options)?;
            let mut txn = env
                .write_txn()
                .map_err(|e| backend("opening lockout write transaction", e))?;
            let db = env
                .create_database::<Bytes, Bytes>(&mut txn, Some("lockout"))
                .map_err(|e| backend("opening lockout database", e))?;
            txn.commit()
                .map_err(|e| backend("committing lockout database", e))?;
            Some((env, db))
        } else if create_lockout || !lockout_path(database_name).exists() {
            let env = open_lockout_env(&lockout_path(database_name), &options)?;
            let mut txn = env
                .write_txn()
                .map_err(|e| backend("creating disabled lockout environment", e))?;
            let _db = env
                .create_database::<Bytes, Bytes>(&mut txn, Some("lockout"))
                .map_err(|e| backend("creating disabled lockout database", e))?;
            txn.commit()
                .map_err(|e| backend("committing disabled lockout database", e))?;
            drop(env);
            None
        } else {
            None
        };

        Ok(Self {
            inner: Arc::new(Inner {
                main_env,
                principal_db,
                policy_db,
                lockout,
                master: std::sync::RwLock::new(MasterKeys::single(master.clone())),
                supplied_master: master.clone(),
                realm: realm.to_owned(),
                options,
                ulog: None,
                #[cfg(test)]
                fail_lockout_write: std::sync::atomic::AtomicBool::new(false),
            }),
        })
    }

    fn verify_master(&self) -> Result<(), StoreError> {
        self.refresh_master()
    }

    /// `krb5_db_fetch_mkey_list`: reread `K/M` and decrypt its master keys
    /// with the supplied (stashed) key.
    fn refresh_master(&self) -> Result<(), StoreError> {
        let name = PrincipalName {
            name_type: 1,
            name_string: vec![
                KerberosString::from_bytes(b"K").map_err(|e| StoreError::backend(e.to_string()))?,
                KerberosString::from_bytes(b"M").map_err(|e| StoreError::backend(e.to_string()))?,
            ],
        };
        let raw = self
            .get_raw(&name, &self.inner.realm)?
            .ok_or_else(|| StoreError::backend("klmdb database has no K/M principal"))?;
        let keys = MasterKeys::fetch(&raw, &self.inner.supplied_master)?;
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

    /// Decode an entry, rereading the master-key list when the entry's
    /// master key is not in it (`krb5_dbe_find_mkey`, `kdb5.c:1412-1450`).
    fn decode(&self, entry: &MitEntry) -> Result<PrincipalRecord, StoreError> {
        if self.master_keys().get(entry_mkvno(entry)?).is_none() {
            self.refresh_master()?;
        }
        record_from_entry(entry, &self.master_keys())
    }

    fn insert_initial(&self, entries: Vec<MitEntry>) -> Result<(), StoreError> {
        let mut txn = self
            .inner
            .main_env
            .write_txn()
            .map_err(|e| backend("opening initial write transaction", e))?;
        for entry in entries {
            let (key, value) = entry.encode()?;
            if self
                .inner
                .principal_db
                .get(&txn, &key)
                .map_err(|e| backend("checking initial principal", e))?
                .is_some()
            {
                return Err(StoreError::conflict("initial MIT principal already exists"));
            }
            self.inner
                .principal_db
                .put(&mut txn, &key, &value)
                .map_err(|e| backend("writing initial principal", e))?;
        }
        txn.commit()
            .map_err(|e| backend("committing initial principals", e))
    }

    fn get_raw(&self, name: &PrincipalName, realm: &str) -> Result<Option<MitEntry>, StoreError> {
        let key = unparse_name(name, realm);
        let txn = self
            .inner
            .main_env
            .read_txn()
            .map_err(|e| backend("opening principal read transaction", e))?;
        self.inner
            .principal_db
            .get(&txn, &key)
            .map_err(|e| backend("reading principal", e))?
            .map(|value| MitEntry::decode(&key, value))
            .transpose()
    }

    /// The decrypted entry for `name`, read synchronously.
    pub fn principal_sync(
        &self,
        name: &PrincipalName,
        realm: &str,
    ) -> Result<Option<PrincipalEntry>, StoreError> {
        Ok(self
            .get_record_sync(name, realm)?
            .map(|record| record.entry))
    }

    fn get_record_sync(
        &self,
        name: &PrincipalName,
        realm: &str,
    ) -> Result<Option<PrincipalRecord>, StoreError> {
        self.get_raw(name, realm)?
            .as_ref()
            .map(|entry| self.decode(entry))
            .transpose()
    }

    fn list_records_sync(&self) -> Result<Vec<PrincipalRecord>, StoreError> {
        self.refresh_master()?;
        let txn = self
            .inner
            .main_env
            .read_txn()
            .map_err(|e| backend("opening principal iteration transaction", e))?;
        let mut records = Vec::new();
        let iter = self
            .inner
            .principal_db
            .iter(&txn)
            .map_err(|e| backend("iterating principals", e))?;
        for item in iter {
            let (key, value) = item.map_err(|e| backend("reading principal iteration", e))?;
            let entry = MitEntry::decode(key, value)?;
            records.push(record_from_entry(&entry, &self.master_keys())?);
        }
        Ok(records)
    }

    fn get_policy_sync(&self, name: &str) -> Result<Option<Policy>, StoreError> {
        let txn = self
            .inner
            .main_env
            .read_txn()
            .map_err(|e| backend("opening policy read transaction", e))?;
        self.inner
            .policy_db
            .get(&txn, name.as_bytes())
            .map_err(|e| backend("reading policy", e))?
            .map(|value| {
                MitPolicy::decode(name.as_bytes(), value).map(|entry| policy_from_entry(&entry))
            })
            .transpose()
    }

    fn list_policies_sync(&self) -> Result<Vec<Policy>, StoreError> {
        let txn = self
            .inner
            .main_env
            .read_txn()
            .map_err(|e| backend("opening policy iteration transaction", e))?;
        let mut policies = Vec::new();
        let iter = self
            .inner
            .policy_db
            .iter(&txn)
            .map_err(|e| backend("iterating policies", e))?;
        for item in iter {
            let (key, value) = item.map_err(|e| backend("reading policy iteration", e))?;
            let entry = MitPolicy::decode(key, value)?;
            policies.push(policy_from_entry(&entry));
        }
        policies.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(policies)
    }

    fn auth_state_sync(&self, key: &[u8]) -> Result<AuthState, StoreError> {
        let Some((env, db)) = &self.inner.lockout else {
            return Ok(AuthState::default());
        };
        let txn = env
            .read_txn()
            .map_err(|e| backend("opening lockout read transaction", e))?;
        let value = db
            .get(&txn, key)
            .map_err(|e| backend("reading lockout state", e))?;
        lockout_from_bytes(value)
    }

    fn apply_auth_state_sync(
        &self,
        key: &[u8],
        update: AuthStateUpdate,
    ) -> Result<AuthState, StoreError> {
        let Some((env, db)) = &self.inner.lockout else {
            return Ok(AuthState::default());
        };
        let mut txn = env
            .write_txn()
            .map_err(|e| backend("opening lockout write transaction", e))?;
        let value = db
            .get(&txn, key)
            .map_err(|e| backend("reading lockout state", e))?;
        let mut state = lockout_from_bytes(value)?;
        match update {
            AuthStateUpdate::Failure { .. } if self.inner.options.disable_lockout => {}
            AuthStateUpdate::Success {
                stamp,
                clear_failures,
                record_success,
            } => state.apply(&AuthStateUpdate::Success {
                stamp,
                clear_failures: clear_failures && !self.inner.options.disable_lockout,
                record_success: record_success && !self.inner.options.disable_last_success,
            }),
            other => state.apply(&other),
        }
        let value = lockout_bytes(state)?;
        db.put(&mut txn, key, &value)
            .map_err(|e| backend("writing lockout state", e))?;
        txn.commit()
            .map_err(|e| backend("committing lockout state", e))?;
        Ok(state)
    }

    fn create_principal_sync(
        &self,
        entry: PrincipalEntry,
        last_pwd_change: Option<KerberosTime>,
    ) -> Result<(), StoreError> {
        self.refresh_master()?;
        let key = unparse_name(&entry.name, &entry.realm);
        let modifier = admin_name(&self.inner.realm);
        let record = PrincipalRecord {
            mod_time: Some(now_time()),
            last_pwd_change,
            mod_by: Some(modifier.clone()),
            password_history: None,
            entry,
        };
        let raw = new_entry(&record, &self.master_keys(), &modifier)?;
        let (_, value) = raw.encode()?;
        let mut txn = self
            .inner
            .main_env
            .write_txn()
            .map_err(|e| backend("opening principal write transaction", e))?;
        if self
            .inner
            .principal_db
            .get(&txn, &key)
            .map_err(|e| backend("checking principal", e))?
            .is_some()
        {
            return Err(StoreError::conflict(format!(
                "Principal or policy already exists: {}",
                String::from_utf8_lossy(&key)
            )));
        }
        self.inner
            .principal_db
            .put(&mut txn, &key, &value)
            .map_err(|e| backend("writing principal", e))?;
        // MIT's klmdb_put_principal commits the principal first and then
        // reports a lockout write failure (`plugins/kdb/lmdb/kdb_lmdb.c:
        // 747-816`), leaving a principal that a retried create refuses. Here
        // the lockout record is committed while the principal transaction is
        // still open: a lockout failure aborts the create, and a principal
        // commit failure leaves only a harmless zeroed lockout record that
        // the next create overwrites.
        if let Some((env, db)) = &self.inner.lockout {
            self.check_lockout_fault()?;
            let mut lockout_txn = env
                .write_txn()
                .map_err(|e| backend("opening lockout write transaction", e))?;
            db.put(&mut lockout_txn, &key, &zero_record())
                .map_err(|e| backend("creating lockout record", e))?;
            lockout_txn
                .commit()
                .map_err(|e| backend("committing lockout record", e))?;
        }
        txn.commit()
            .map_err(|e| backend("committing principal", e))?;
        self.log(update_from_entry(None, &raw))
    }

    #[cfg(test)]
    fn check_lockout_fault(&self) -> Result<(), StoreError> {
        if self
            .inner
            .fail_lockout_write
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            return Err(StoreError::backend("injected lockout write failure"));
        }
        Ok(())
    }

    #[cfg(not(test))]
    fn check_lockout_fault(&self) -> Result<(), StoreError> {
        Ok(())
    }

    fn update_principal_sync<F>(
        &self,
        name: &PrincipalName,
        realm: &str,
        mut f: F,
    ) -> Result<PrincipalRecord, StoreError>
    where
        F: FnMut(&mut PrincipalRecord) -> Result<(), StoreError>,
    {
        self.refresh_master()?;
        let key = unparse_name(name, realm);
        let mut txn = self
            .inner
            .main_env
            .write_txn()
            .map_err(|e| backend("opening principal write transaction", e))?;
        let value = self
            .inner
            .principal_db
            .get(&txn, &key)
            .map_err(|e| backend("reading principal for update", e))?
            .ok_or_else(|| {
                StoreError::not_found(format!("Principal {name}@{realm} does not exist"))
            })?
            .to_vec();
        let mut raw = MitEntry::decode(&key, &value)?;
        let current = self.inner.ulog.as_ref().map(|_| raw.clone());
        let mut record = record_from_entry(&raw, &self.master_keys())?;
        f(&mut record)?;
        record.mod_time = Some(now_time());
        let modifier = admin_name(realm);
        record.mod_by = Some(modifier.clone());
        merge_record(&mut raw, &record, &self.master_keys(), Some(&modifier))?;
        let (_, value) = raw.encode()?;
        self.inner
            .principal_db
            .put(&mut txn, &key, &value)
            .map_err(|e| backend("writing updated principal", e))?;
        txn.commit()
            .map_err(|e| backend("committing updated principal", e))?;
        if let Some(current) = current {
            self.log(update_from_entry(Some(&current), &raw))?;
        }
        Ok(record)
    }

    /// The current master-key list (rereading `K/M`).
    pub fn master_key_list(&self) -> Result<MasterKeys, StoreError> {
        self.refresh_master()?;
        Ok(self.master_keys().clone())
    }

    /// Every principal entry as stored.
    pub fn raw_entries(&self) -> Result<Vec<MitEntry>, StoreError> {
        Ok(self.dump_entries()?.0)
    }

    /// Read-modify-write one stored entry, as `krb5_db_get_principal` +
    /// `krb5_db_put_principal` (logged when iprop is on). `f` returns false
    /// to leave the entry unchanged.
    pub fn update_raw<F>(&self, name: &PrincipalName, realm: &str, f: F) -> Result<bool, StoreError>
    where
        F: FnOnce(&mut MitEntry, &MasterKeys) -> Result<bool, StoreError>,
    {
        self.refresh_master()?;
        let keys = self.master_keys().clone();
        let key = unparse_name(name, realm);
        let mut txn = self
            .inner
            .main_env
            .write_txn()
            .map_err(|e| backend("opening principal write transaction", e))?;
        let value = self
            .inner
            .principal_db
            .get(&txn, &key)
            .map_err(|e| backend("reading principal for update", e))?
            .ok_or_else(|| {
                StoreError::not_found(format!("Principal {name}@{realm} does not exist"))
            })?
            .to_vec();
        let mut raw = MitEntry::decode(&key, &value)?;
        let current = raw.clone();
        if !f(&mut raw, &keys)? {
            return Ok(false);
        }
        let (_, value) = raw.encode()?;
        self.inner
            .principal_db
            .put(&mut txn, &key, &value)
            .map_err(|e| backend("writing updated principal", e))?;
        txn.commit()
            .map_err(|e| backend("committing updated principal", e))?;
        if self.inner.ulog.is_some() {
            self.log(update_from_entry(Some(&current), &raw))?;
        }
        self.refresh_master()?;
        Ok(true)
    }

    fn delete_principal_sync(&self, name: &PrincipalName, realm: &str) -> Result<bool, StoreError> {
        let key = unparse_name(name, realm);
        let deleted = self.delete_unlogged(&key)?;
        if deleted {
            self.log(Update::deletion(key))?;
        }
        Ok(deleted)
    }

    /// `ulog_replay` (`lib/kdb/kdb_log.c:401-476`): apply updates received
    /// from the primary without logging them as new changes, then store each
    /// one in the ulog with its primary serial number. On failure the ulog is
    /// reinitialized, so the next poll asks for a full resync.
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
        let mut txn = self
            .inner
            .main_env
            .write_txn()
            .map_err(|e| backend("opening principal write transaction", e))?;
        let current = self
            .inner
            .principal_db
            .get(&txn, &upd.princ_name)
            .map_err(|e| backend("reading principal for update", e))?
            .map(|v| MitEntry::decode(&upd.princ_name, v))
            .transpose()?;
        let entry = entry_from_update(current, upd)?;
        let (key, value) = entry.encode()?;
        if key != upd.princ_name {
            self.inner
                .principal_db
                .delete(&mut txn, &upd.princ_name)
                .map_err(|e| backend("deleting renamed principal", e))?;
        }
        self.inner
            .principal_db
            .put(&mut txn, &key, &value)
            .map_err(|e| backend("writing replayed principal", e))?;
        txn.commit()
            .map_err(|e| backend("committing replayed principal", e))
    }

    fn delete_unlogged(&self, key: &[u8]) -> Result<bool, StoreError> {
        let mut txn = self
            .inner
            .main_env
            .write_txn()
            .map_err(|e| backend("opening principal delete transaction", e))?;
        let deleted = self
            .inner
            .principal_db
            .delete(&mut txn, key)
            .map_err(|e| backend("deleting principal", e))?;
        txn.commit()
            .map_err(|e| backend("committing principal deletion", e))?;
        // Like MIT, a lockout deletion failure is ignored once the principal
        // is gone (`plugins/kdb/lmdb/kdb_lmdb.c:833-834`); a later create
        // overwrites any leftover record.
        if let (true, Some((env, db))) = (deleted, &self.inner.lockout) {
            let _ = self.check_lockout_fault().and_then(|()| {
                let mut txn = env
                    .write_txn()
                    .map_err(|e| backend("opening lockout delete transaction", e))?;
                db.delete(&mut txn, key)
                    .map_err(|e| backend("deleting lockout record", e))?;
                txn.commit()
                    .map_err(|e| backend("committing lockout deletion", e))
            });
        }
        Ok(deleted)
    }

    fn create_policy_sync(&self, policy: Policy) -> Result<(), StoreError> {
        self.create_policy_unlogged(policy)?;
        self.reset_ulog()
    }

    fn update_policy_sync<F>(&self, name: &str, f: F) -> Result<Policy, StoreError>
    where
        F: FnMut(&mut Policy) -> Result<(), StoreError>,
    {
        let policy = self.update_policy_unlogged(name, f)?;
        self.reset_ulog()?;
        Ok(policy)
    }

    fn delete_policy_sync(&self, name: &str) -> Result<bool, StoreError> {
        let deleted = self.delete_policy_unlogged(name)?;
        if deleted {
            self.reset_ulog()?;
        }
        Ok(deleted)
    }

    fn create_policy_unlogged(&self, policy: Policy) -> Result<(), StoreError> {
        let key = policy.name.as_bytes().to_vec();
        let value = MitPolicy {
            name: policy.name.clone(),
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
            tl_data: Vec::new(),
        }
        .encode()?;
        let mut txn = self
            .inner
            .main_env
            .write_txn()
            .map_err(|e| backend("opening policy write transaction", e))?;
        if self
            .inner
            .policy_db
            .get(&txn, &key)
            .map_err(|e| backend("checking policy", e))?
            .is_some()
        {
            return Err(StoreError::conflict(format!(
                "Principal or policy already exists: policy {}",
                String::from_utf8_lossy(&key)
            )));
        }
        self.inner
            .policy_db
            .put(&mut txn, &key, &value)
            .map_err(|e| backend("writing policy", e))?;
        txn.commit().map_err(|e| backend("committing policy", e))
    }

    fn update_policy_unlogged<F>(&self, name: &str, mut f: F) -> Result<Policy, StoreError>
    where
        F: FnMut(&mut Policy) -> Result<(), StoreError>,
    {
        let key = name.as_bytes();
        let mut txn = self
            .inner
            .main_env
            .write_txn()
            .map_err(|e| backend("opening policy update transaction", e))?;
        let bytes = self
            .inner
            .policy_db
            .get(&txn, key)
            .map_err(|e| backend("reading policy for update", e))?
            .ok_or_else(|| StoreError::not_found(format!("Policy \"{name}\" does not exist")))?
            .to_vec();
        let mut raw = MitPolicy::decode(key, &bytes)?;
        let mut policy = policy_from_entry(&raw);
        f(&mut policy)?;
        merge_policy(&mut raw, &policy)?;
        let value = raw.encode()?;
        self.inner
            .policy_db
            .put(&mut txn, key, &value)
            .map_err(|e| backend("writing updated policy", e))?;
        txn.commit()
            .map_err(|e| backend("committing updated policy", e))?;
        Ok(policy)
    }

    fn delete_policy_unlogged(&self, name: &str) -> Result<bool, StoreError> {
        let mut txn = self
            .inner
            .main_env
            .write_txn()
            .map_err(|e| backend("opening policy delete transaction", e))?;
        let deleted = self
            .inner
            .policy_db
            .delete(&mut txn, name.as_bytes())
            .map_err(|e| backend("deleting policy", e))?;
        txn.commit()
            .map_err(|e| backend("committing policy deletion", e))?;
        Ok(deleted)
    }
}

impl LmdbStore {
    /// Raw entries in key order with their lockout state, as `kdb5_util dump`
    /// sees them through `klmdb_iterate` (`plugins/kdb/lmdb/kdb_lmdb.c:841-880`).
    pub fn dump_entries(&self) -> Result<(Vec<MitEntry>, Vec<MitPolicy>), StoreError> {
        let txn = self
            .inner
            .main_env
            .read_txn()
            .map_err(|e| backend("opening dump transaction", e))?;
        let mut entries = Vec::new();
        for item in self
            .inner
            .principal_db
            .iter(&txn)
            .map_err(|e| backend("iterating principals", e))?
        {
            let (key, value) = item.map_err(|e| backend("reading principal iteration", e))?;
            let mut entry = MitEntry::decode(key, value)?;
            entry.set_auth_state(self.auth_state_sync(key)?)?;
            entries.push(entry);
        }
        let mut policies = Vec::new();
        for item in self
            .inner
            .policy_db
            .iter(&txn)
            .map_err(|e| backend("iterating policies", e))?
        {
            let (key, value) = item.map_err(|e| backend("reading policy iteration", e))?;
            policies.push(MitPolicy::decode(key, value)?);
        }
        Ok((entries, policies))
    }

    /// Load dump records. Without `update` this mirrors klmdb's `temporary`
    /// load: the principal and policy databases are emptied and refilled in
    /// one write transaction that is only committed once everything is
    /// written (`plugins/kdb/lmdb/kdb_lmdb.c:62-76,635-647,1004-1020`).
    /// Deviation: MIT writes lockout records outside that transaction while
    /// loading; here they are staged in one lockout transaction committed
    /// right after the main one, so a load that fails before the main commit
    /// changes nothing. Only a failing lockout commit can leave the new
    /// principals with their old lockout rows. Like MIT, the lockout database
    /// is not emptied. `merge_nra` keeps existing lockout records, as MIT's
    /// klmdb does for iprop loads (`plugins/kdb/lmdb/kdb_lmdb.c:72-76,795-799`).
    pub fn load_dump(
        config: &krb5_rs::kdc::RealmConfig,
        entries: &[MitEntry],
        policies: &[MitPolicy],
        update: bool,
        merge_nra: bool,
    ) -> Result<(), StoreError> {
        let options = LmdbOptions::from_db_module(
            &config.db_module,
            config.kdc.disable_lockout,
            config.kdc.disable_last_success,
        )?;
        let database_name = &config.database_name;
        let main = main_path(database_name);
        if update && !main.exists() {
            return Err(StoreError::not_found(format!(
                "klmdb environment {} does not exist",
                main.display()
            )));
        }
        create_parent(database_name)?;
        let env = open_main_env(&main, &options)?;
        let mut txn = env
            .write_txn()
            .map_err(|e| backend("opening load transaction", e))?;
        let principal_db = env
            .create_database::<Bytes, Bytes>(&mut txn, Some("principal"))
            .map_err(|e| backend("opening principal database", e))?;
        let policy_db = env
            .create_database::<Bytes, Bytes>(&mut txn, Some("policy"))
            .map_err(|e| backend("opening policy database", e))?;
        if !update {
            principal_db
                .clear(&mut txn)
                .map_err(|e| backend("emptying principal database", e))?;
            policy_db
                .clear(&mut txn)
                .map_err(|e| backend("emptying policy database", e))?;
        }
        for entry in entries {
            let (key, value) = entry.encode()?;
            principal_db
                .put(&mut txn, &key, &value)
                .map_err(|e| backend("loading principal", e))?;
        }
        for policy in policies {
            policy_db
                .put(&mut txn, policy.name.as_bytes(), &policy.encode()?)
                .map_err(|e| backend("loading policy", e))?;
        }
        let lockout_env = open_lockout_env(&lockout_path(database_name), &options)?;
        let mut lockout_txn = lockout_env
            .write_txn()
            .map_err(|e| backend("opening lockout load transaction", e))?;
        let lockout_db = lockout_env
            .create_database::<Bytes, Bytes>(&mut lockout_txn, Some("lockout"))
            .map_err(|e| backend("opening lockout database", e))?;
        if !options.disable_lockout || !options.disable_last_success {
            for entry in entries {
                let key = unparse_name(&entry.principal, &entry.realm);
                if merge_nra
                    && lockout_db
                        .get(&lockout_txn, &key)
                        .map_err(|e| backend("reading lockout record", e))?
                        .is_some()
                {
                    continue;
                }
                let value =
                    encode_lockout(entry.last_success, entry.last_failed, entry.fail_auth_count);
                lockout_db
                    .put(&mut lockout_txn, &key, &value)
                    .map_err(|e| backend("loading lockout state", e))?;
            }
        }
        txn.commit().map_err(|e| backend("committing load", e))?;
        lockout_txn
            .commit()
            .map_err(|e| backend("committing lockout load", e))
    }
}

fn creator_name(realm: &str) -> Vec<u8> {
    let principal = PrincipalName::new_principal("db_creation");
    unparse_name(&principal, realm)
}

fn admin_name(realm: &str) -> Vec<u8> {
    unparse_name(&PrincipalName::new_principal("krb5-rs-kdb"), realm)
}

struct ConvertLock(fs::File);

impl Drop for ConvertLock {
    fn drop(&mut self) {
        let _ = FileExt::unlock(&self.0);
    }
}

/// Environment files in publish order. The main `.mdb` goes last, so its
/// presence means the whole set is in place.
const PUBLISH_ORDER: [&str; 4] = [".lockout.mdb-lock", ".lockout.mdb", ".mdb-lock", ".mdb"];

struct TempEnvironments(PathBuf);

impl TempEnvironments {
    fn remove_files(&self) {
        for suffix in PUBLISH_ORDER {
            let _ = fs::remove_file(appended(&self.0, suffix));
        }
    }
}

impl Drop for TempEnvironments {
    fn drop(&mut self) {
        self.remove_files();
    }
}

/// Move closed temporary environments into place, main `.mdb` last.
fn publish_environments(
    temp_base: &Path,
    database_name: &Path,
    stop_before: Option<usize>,
) -> Result<(), StoreError> {
    for (step, suffix) in PUBLISH_ORDER.into_iter().enumerate() {
        if stop_before == Some(step) {
            return Err(StoreError::backend("injected stop while publishing"));
        }
        rename_env_file(
            &appended(temp_base, suffix),
            &appended(database_name, suffix),
        )?;
    }
    sync_parent(&main_path(database_name));
    Ok(())
}

fn conversion_lock(database_name: &Path) -> Result<ConvertLock, StoreError> {
    let lock_path = appended(database_name, ".convert.lock");
    let lock_file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&lock_path)
        .map_err(|e| {
            StoreError::backend(format!(
                "opening conversion lock {}: {e}",
                lock_path.display()
            ))
        })?;
    FileExt::lock_exclusive(&lock_file).map_err(|e| {
        StoreError::unavailable(format!(
            "acquiring conversion lock {}: {e}",
            lock_path.display()
        ))
    })?;
    Ok(ConvertLock(lock_file))
}

fn backup_path(database_name: &Path) -> PathBuf {
    appended(database_name, ".krb5rs-file.bak")
}

/// Move the converted legacy file to its backup name. Run once the klmdb
/// environments are published, and again by `open` when a conversion stopped
/// between publishing and this step.
fn move_legacy_to_backup(database_name: &Path) -> Result<(), StoreError> {
    let backup = backup_path(database_name);
    fs::rename(database_name, &backup).map_err(|e| {
        StoreError::backend(format!(
            "moving converted legacy database to {}: {e}",
            backup.display()
        ))
    })?;
    sync_parent(&backup);
    eprintln!(
        "converted legacy krb5-rs database {} to MIT klmdb; backup: {}",
        database_name.display(),
        backup.display()
    );
    Ok(())
}

/// Finish a conversion interrupted after the klmdb environments were
/// published but before the legacy file was moved to its backup.
fn finish_legacy_backup(database_name: &Path) -> Result<(), StoreError> {
    let _guard = conversion_lock(database_name)?;
    if !main_path(database_name).exists() || !FileStore::has_database_magic(database_name)? {
        return Ok(());
    }
    let backup = backup_path(database_name);
    if backup.exists() {
        return Err(StoreError::conflict(format!(
            "both a legacy krb5-rs file database {} and its backup {} exist next to the klmdb environment; remove the one that is not wanted",
            database_name.display(),
            backup.display()
        )));
    }
    move_legacy_to_backup(database_name)
}

#[cfg(unix)]
fn sync_parent(path: &Path) {
    if let Some(parent) = path.parent() {
        if let Ok(dir) = fs::File::open(parent) {
            let _ = dir.sync_all();
        }
    }
}

#[cfg(not(unix))]
fn sync_parent(_path: &Path) {}

fn rename_env_file(from: &Path, to: &Path) -> Result<(), StoreError> {
    if !from.exists() {
        return Ok(());
    }
    fs::rename(from, to).map_err(|e| {
        StoreError::backend(format!(
            "renaming LMDB environment {} to {}: {e}",
            from.display(),
            to.display()
        ))
    })
}

/// Ensure migrated K/M entries have MIT's initially-active master-key tuple
/// (`kadmin/dbutil/kdb5_create.c:423-434`).
fn ensure_master_actkvno(entry: &mut MitEntry) -> Result<(), StoreError> {
    if entry.principal.name_string.len() != 2
        || entry.principal.name_string[0].as_slice() != b"K"
        || entry.principal.name_string[1].as_slice() != b"M"
        || entry.tl_data.iter().any(|tl| tl.kind == ACTKVNO)
    {
        return Ok(());
    }
    let mkvno = entry
        .tl_data
        .iter()
        .find(|tl| tl.kind == MKVNO)
        .map(|tl| {
            let value: [u8; 2] = tl
                .data
                .as_slice()
                .try_into()
                .map_err(|_| StoreError::corrupt("MIT MKVNO tl-data must be 2 bytes"))?;
            Ok::<_, StoreError>(u16::from_le_bytes(value))
        })
        .transpose()?
        .unwrap_or(1);
    let mut data = Vec::with_capacity(8);
    data.extend_from_slice(&1u16.to_le_bytes());
    data.extend_from_slice(&mkvno.to_le_bytes());
    data.extend_from_slice(&0u32.to_le_bytes());
    entry.tl_data.push(TlData {
        kind: ACTKVNO,
        data,
    });
    Ok(())
}

/// Convert a legacy krb5-rs file database to klmdb, keeping it as a backup.
///
/// Crash safety: the environments are built under temporary names and
/// published with the main `.mdb` last, so a missing `.mdb` means the next
/// open converts again from scratch, and a present one means only the backup
/// rename may be left (see [`finish_legacy_backup`]). The file store's own
/// write lock is held from export to backup, so no file-store writer can
/// change the database while it is converted.
fn auto_convert_legacy(
    database_name: &Path,
    master: &EncryptionKey,
    realm: &str,
    options: &LmdbOptions,
    faults: Faults,
) -> Result<(), StoreError> {
    let main = main_path(database_name);
    let _guard = conversion_lock(database_name)?;
    if main.exists() || !FileStore::has_database_magic(database_name)? {
        return Ok(());
    }
    let backup = backup_path(database_name);
    if backup.exists() {
        return Err(StoreError::conflict(format!(
            "legacy database backup {} already exists",
            backup.display()
        )));
    }

    let legacy = FileStore::open(database_name, master)?;
    if legacy.realm() != realm {
        return Err(StoreError::backend(format!(
            "legacy file database is for realm {}, expected {realm}",
            legacy.realm()
        )));
    }
    let _writer = legacy.write_lock().map_err(|e| {
        StoreError::unavailable(format!(
            "the legacy file database is locked by a writer ({e}); retry once file-store writers have stopped"
        ))
    })?;
    let (records, policies) = legacy.export_records()?;
    let temp_base = appended(database_name, ".convert.tmp");
    let temp_guard = TempEnvironments(temp_base.clone());
    temp_guard.remove_files();
    {
        let temp = LmdbStore::open_environments(&temp_base, realm, master, options.clone(), true)?;
        let creator = creator_name(realm);
        let mut raw_entries = Vec::with_capacity(records.len());
        for record in &records {
            let mut entry = new_entry(record, &MasterKeys::single(master.clone()), &creator)?;
            ensure_master_actkvno(&mut entry)?;
            raw_entries.push(entry);
        }
        temp.insert_initial(raw_entries)?;
        for policy in policies.iter().cloned() {
            temp.create_policy_sync(policy)?;
        }

        if temp.list_records_sync()?.len() != records.len()
            || temp.list_policies_sync()?.len() != policies.len()
        {
            return Err(StoreError::corrupt(
                "legacy database conversion count verification failed",
            ));
        }
        temp.verify_master()?;
        temp.sync_all()?;
    }

    publish_environments(&temp_base, database_name, faults.publish_stop)?;
    if faults.before_backup {
        return Err(StoreError::backend(
            "injected stop before the legacy backup",
        ));
    }
    move_legacy_to_backup(database_name)
}

impl PrincipalStore for LmdbStore {
    async fn lookup(
        &self,
        name: &PrincipalName,
        realm: &str,
    ) -> Result<Option<PrincipalEntry>, StoreError> {
        Ok(self
            .get_record_sync(name, realm)?
            .map(|record| record.entry))
    }
}

impl PolicyStore for LmdbStore {
    async fn policy(&self, name: &str) -> Result<Option<Policy>, StoreError> {
        self.get_policy_sync(name)
    }
}

impl AuthStateStore for LmdbStore {
    async fn auth_state(&self, name: &PrincipalName, realm: &str) -> Result<AuthState, StoreError> {
        let key = lockout_key(name, realm);
        self.auth_state_sync(&key)
    }

    fn apply(
        &self,
        name: &PrincipalName,
        realm: &str,
        update: &AuthStateUpdate,
    ) -> impl std::future::Future<Output = Result<AuthState, StoreError>> + Send {
        let store = self.clone();
        let key = lockout_key(name, realm);
        let update = *update;
        spawn_write("lockout update", move || {
            store.apply_auth_state_sync(&key, update)
        })
    }
}

impl HealthCheck for LmdbStore {
    async fn health(&self) -> Result<(), StoreError> {
        self.inner
            .main_env
            .read_txn()
            .map(|_| ())
            .map_err(|e| StoreError::unavailable(format!("LMDB health check: {e}")))
    }
}

impl AdminStore for LmdbStore {
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

#[cfg(test)]
mod tests {
    use super::*;
    use krb5_rs::kdc::kdb::admin::AdminOps;
    use krb5_rs::kdc::kdb::{master_key_from_password, FileStore};
    use krb5_rs::kdc::store::{AdminStore, StoreErrorKind};
    use krb5_rs::profile::Profile;

    fn test_config(path: &Path) -> krb5_rs::kdc::RealmConfig {
        let profile = Profile::parse(
            "[realms]\n LMDB.TEST = {\n  database_module = lmdb\n }\n\
             [dbmodules]\n lmdb = {\n  db_library = klmdb\n }\n",
        )
        .expect("profile");
        let mut config = krb5_rs::kdc::RealmConfig::from_profiles(&profile, None, "LMDB.TEST")
            .expect("realm config");
        config.database_name = path.to_path_buf();
        config
    }

    fn tl(entry: &MitEntry, kind: u16) -> Option<&[u8]> {
        entry
            .tl_data
            .iter()
            .find(|item| item.kind == kind)
            .map(|item| item.data.as_slice())
    }

    #[test]
    fn module_options_use_mit_defaults_and_profile_values() {
        let module = krb5_rs::kdc::DbModuleConfig {
            library: Some("klmdb".into()),
            options: [
                ("mapsize".into(), "256".into()),
                ("max_readers".into(), "80".into()),
                ("nosync".into(), "yes".into()),
            ]
            .into(),
        };
        let options = LmdbOptions::from_db_module(&module, true, false).expect("options");
        assert_eq!(options.mapsize_mb, 256);
        assert_eq!(options.max_readers, 80);
        assert!(options.nosync);
        assert!(options.disable_lockout);
        assert!(!options.disable_last_success);
        let defaults =
            LmdbOptions::from_db_module(&krb5_rs::kdc::DbModuleConfig::default(), false, false)
                .expect("defaults");
        assert_eq!(defaults, LmdbOptions::default());
    }

    fn principal(name: &str) -> PrincipalEntry {
        PrincipalEntry {
            name: PrincipalName::new_principal(name),
            realm: "LMDB.TEST".into(),
            attributes: PrincipalAttributes::REQUIRES_PRE_AUTH,
            max_life: None,
            max_renewable_life: None,
            expiration: None,
            pw_expiration: None,
            keys: random_keys(1, &[18]).expect("random key"),
            allowed_to_delegate_to: Vec::new(),
            allowed_to_delegate_from: Vec::new(),
            policy: None,
            security_epoch: 0,
            last_admin_unlock: None,
        }
    }

    #[test]
    fn mit_dump_loads_and_dumps_back_byte_for_byte() {
        use krb5_rs::kdc::kdb::mit::dump::{read_dump, write_dump, DumpVersion, Record};
        let data = fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/fixtures/mit-dump/v7.dump"
        ))
        .expect("MIT fixture");
        let (_, records, _) = read_dump(&data, "v7", None).expect("parse");
        let (mut entries, mut policies) = (Vec::new(), Vec::new());
        for record in records {
            match record {
                Record::Principal(entry) => entries.push(entry),
                Record::Policy(policy) => policies.push(policy),
            }
        }
        let directory = tempfile::tempdir().expect("tempdir");
        let profile = Profile::parse(
            "[realms]\n DUMP.TEST = {\n  database_module = lmdb\n }\n\
             [dbmodules]\n lmdb = {\n  db_library = klmdb\n }\n",
        )
        .expect("profile");
        let mut config = krb5_rs::kdc::RealmConfig::from_profiles(&profile, None, "DUMP.TEST")
            .expect("realm config");
        config.database_name = directory.path().join("principal");
        let master = master_key_from_password("DUMP.TEST", "master-password-for-dump-fixtures", 18)
            .expect("master key");
        assert!(LmdbStore::load_dump(&config, &entries, &policies, true, false).is_err());
        LmdbStore::load_dump(&config, &entries, &policies, false, false).expect("load");
        let dumped = {
            let store = LmdbStore::open(&config, &master).expect("open loaded database");
            let (entries, policies) = store.dump_entries().expect("dump");
            write_dump(DumpVersion::R111, &entries, &policies)
        };
        assert_eq!(
            String::from_utf8_lossy(&dumped),
            String::from_utf8_lossy(&data)
        );

        LmdbStore::load_dump(&config, &entries[..1], &policies[..1], true, false).expect("update");
        let count = |config| {
            let store = LmdbStore::open(config, &master).expect("open");
            let (entries, policies) = store.dump_entries().expect("dump");
            (entries.len(), policies.len())
        };
        assert_eq!(count(&config), (entries.len(), policies.len()));
        LmdbStore::load_dump(&config, &entries[..1], &policies[..1], false, false)
            .expect("replace");
        assert_eq!(count(&config), (1, 1));
    }

    fn test_store(path: &Path) -> (LmdbStore, EncryptionKey) {
        let master =
            master_key_from_password("LMDB.TEST", "master password", 18).expect("master key");
        let store = LmdbStore::create(&test_config(path), &master).expect("create LMDB");
        (store, master)
    }

    #[tokio::test]
    async fn create_modify_delete_policies_and_reopen_persist() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("principal");
        let (store, master) = test_store(&path);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(main_path(&path))
                    .expect("main environment metadata")
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
            assert_eq!(
                fs::metadata(lockout_path(&path))
                    .expect("lockout environment metadata")
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
        let record_count = store.list_records_sync().expect("records").len();
        assert_eq!(record_count, 2);
        let tgt = PrincipalName::new_srv_inst("krbtgt", "LMDB.TEST");
        let tgt_raw = store
            .get_raw(&tgt, "LMDB.TEST")
            .expect("TGT read")
            .expect("TGT");
        assert!(tgt_raw.tl_data.iter().all(|tl| tl.kind != MKVNO));
        let km = PrincipalName {
            name_type: 1,
            name_string: vec![
                KerberosString::from_bytes(b"K").expect("K"),
                KerberosString::from_bytes(b"M").expect("M"),
            ],
        };
        let km_raw = store
            .get_raw(&km, "LMDB.TEST")
            .expect("K/M read")
            .expect("K/M");
        assert_eq!(tl(&km_raw, MKVNO), Some(&[1, 0][..]));
        assert!(tl(&km_raw, ACTKVNO).is_some());
        store
            .create_principal(principal("alice"), None)
            .await
            .expect("create principal");
        let alice = PrincipalName::new_principal("alice");
        let existing = store
            .get_record(&alice, "LMDB.TEST")
            .await
            .expect("get record")
            .expect("alice exists");
        assert_eq!(existing.entry.keys[0].key.keytype, 18);
        store
            .update_principal(&alice, "LMDB.TEST", move |record| {
                record.entry.max_life = Some(Duration::from_secs(600));
                record.entry.attributes |= PrincipalAttributes::LOCKDOWN_KEYS;
                Ok(())
            })
            .await
            .expect("modify principal");
        let modified = store
            .get_record(&alice, "LMDB.TEST")
            .await
            .expect("get modified")
            .expect("alice");
        assert_eq!(modified.entry.max_life, Some(Duration::from_secs(600)));
        assert!(modified
            .entry
            .attributes
            .contains(PrincipalAttributes::LOCKDOWN_KEYS));

        let policy = Policy {
            name: "default".into(),
            pw_min_length: 8,
            ..Policy::default()
        };
        store.create_policy(policy).await.expect("create policy");
        store
            .update_policy("default", move |policy| {
                policy.pw_history_num = 4;
                Ok(())
            })
            .await
            .expect("modify policy");
        let policy = store
            .get_policy("default")
            .await
            .expect("get policy")
            .expect("policy exists");
        assert_eq!((policy.pw_min_length, policy.pw_history_num), (8, 4));

        let main_key = unparse_name(&alice, "LMDB.TEST");
        let before = {
            let txn = store.inner.main_env.read_txn().expect("read txn");
            store
                .inner
                .principal_db
                .get(&txn, &main_key)
                .expect("principal read")
                .expect("alice")
                .to_vec()
        };
        let updated_state = store
            .apply(
                &alice,
                "LMDB.TEST",
                &AuthStateUpdate::Failure {
                    stamp: 100,
                    failcnt_interval: 0,
                    last_admin_unlock: None,
                },
            )
            .await
            .expect("record failure");
        assert_eq!(updated_state.fail_count, 1);
        let after = {
            let txn = store.inner.main_env.read_txn().expect("read txn");
            store
                .inner
                .principal_db
                .get(&txn, &main_key)
                .expect("principal read")
                .expect("alice")
                .to_vec()
        };
        assert_eq!(before, after, "lockout state belongs only to lockout.mdb");
        assert_eq!(
            store
                .auth_state(&alice, "LMDB.TEST")
                .await
                .expect("read lockout")
                .fail_count,
            1
        );

        assert!(store
            .delete_principal(&alice, "LMDB.TEST")
            .await
            .expect("delete principal"));
        assert_eq!(
            store
                .auth_state(&alice, "LMDB.TEST")
                .await
                .expect("lockout removed"),
            AuthState::default()
        );
        assert!(store.delete_policy("default").await.expect("delete policy"));
        drop(store);

        let reopened = LmdbStore::open(&test_config(&path), &master).expect("reopen");
        assert_eq!(reopened.list_records_sync().expect("records").len(), 2);
        assert!(reopened
            .get_policy_sync("default")
            .expect("policy read")
            .is_none());
    }

    #[tokio::test]
    async fn concurrent_readers_observe_valid_records_during_writes() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("principal");
        let (store, _) = test_store(&path);
        let alice = PrincipalName::new_principal("alice");
        store
            .create_principal(principal("alice"), None)
            .await
            .expect("create alice");
        let reader_store = store.clone();
        let reader = tokio::spawn(async move {
            for _ in 0..100 {
                let record = reader_store
                    .get_record(&alice, "LMDB.TEST")
                    .await
                    .expect("read during write")
                    .expect("alice remains present");
                assert_eq!(record.entry.keys[0].key.key_bytes().len(), 32);
            }
        });
        for n in 1..=20 {
            store
                .update_principal(
                    &PrincipalName::new_principal("alice"),
                    "LMDB.TEST",
                    move |r| {
                        r.entry.max_life = Some(Duration::from_secs(n));
                        Ok(())
                    },
                )
                .await
                .expect("write during reads");
        }
        reader.await.expect("reader task");
    }

    #[test]
    fn disabled_lockout_environment_is_created_but_not_opened() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("principal");
        let master =
            master_key_from_password("LMDB.TEST", "master password", 18).expect("master key");
        let mut config = test_config(&path);
        config.kdc.disable_lockout = true;
        config.kdc.disable_last_success = true;
        let store = LmdbStore::create(&config, &master).expect("create");
        assert!(lockout_path(&path).exists());
        assert!(store.inner.lockout.is_none());
        drop(store);
        let reopened = LmdbStore::open(&config, &master).expect("reopen with disabled lockout");
        assert!(reopened.inner.lockout.is_none());
    }

    #[tokio::test]
    async fn metadata_modify_keeps_missing_mkvno_and_password_change_adds_one() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("principal");
        let config = test_config(&path);
        let master =
            master_key_from_password("LMDB.TEST", "master password", 18).expect("master key");
        let store = LmdbStore::create(&config, &master).expect("create");
        let alice = PrincipalName::new_principal("alice");
        store
            .create_principal(principal("alice"), None)
            .await
            .expect("create alice");

        let key = unparse_name(&alice, "LMDB.TEST");
        {
            let mut txn = store.inner.main_env.write_txn().expect("write transaction");
            let value = store
                .inner
                .principal_db
                .get(&txn, &key)
                .expect("read principal")
                .expect("alice")
                .to_vec();
            let mut raw = MitEntry::decode(&key, &value).expect("decode principal");
            raw.tl_data.retain(|tl| tl.kind != MKVNO);
            let (_, value) = raw.encode().expect("encode without MKVNO");
            store
                .inner
                .principal_db
                .put(&mut txn, &key, &value)
                .expect("write without MKVNO");
            txn.commit().expect("commit without MKVNO");
        }

        store
            .update_principal(&alice, "LMDB.TEST", |record| {
                record.entry.max_life = Some(Duration::from_secs(1200));
                Ok(())
            })
            .await
            .expect("metadata-only modify");
        let raw = store
            .get_raw(&alice, "LMDB.TEST")
            .expect("read modified principal")
            .expect("alice");
        assert!(raw.tl_data.iter().all(|tl| tl.kind != MKVNO));

        let admin = AdminOps::new(store.clone(), config.supported_keysalts.clone());
        assert_eq!(
            admin
                .change_password(&alice, "LMDB.TEST", Some("new-password"), false)
                .await
                .expect("password change"),
            2
        );
        let raw = store
            .get_raw(&alice, "LMDB.TEST")
            .expect("read rekeyed principal")
            .expect("alice");
        assert_eq!(tl(&raw, MKVNO), Some(&[1, 0][..]));
        drop(admin);
        drop(store);

        let reopened = LmdbStore::open(&config, &master).expect("reopen");
        let rekeyed = reopened
            .get_record_sync(&alice, "LMDB.TEST")
            .expect("read rekeyed record")
            .expect("alice");
        assert_eq!(rekeyed.entry.keys.iter().map(|key| key.kvno).max(), Some(2));
    }

    #[test]
    fn open_loads_a_rotated_master_key_list_with_old_or_new_key() {
        use krb5_rs::kdc::kdb::mit::mkey::{
            add_new_mkey, lookup_actkvno, now, update_actkvno, use_mkey,
        };
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("principal");
        let config = test_config(&path);
        let (store, master) = test_store(&path);
        let km = PrincipalName {
            name_type: 1,
            name_string: vec![
                KerberosString::from_bytes(b"K").expect("K"),
                KerberosString::from_bytes(b"M").expect("M"),
            ],
        };
        let second =
            krb5_rs::kdc::kdb::master_key_from_password("LMDB.TEST", "second", master.keytype)
                .expect("second master key");
        store
            .update_raw(&km, "LMDB.TEST", |entry, keys| {
                add_new_mkey(entry, keys, &second)?;
                let mut list = lookup_actkvno(entry)?;
                use_mkey(&mut list, 2, 0, now())?;
                update_actkvno(entry, &list);
                Ok(true)
            })
            .expect("rotate");
        drop(store);

        let krbtgt = PrincipalName {
            name_type: 2,
            name_string: vec![
                KerberosString::from_bytes(b"krbtgt").expect("krbtgt"),
                KerberosString::from_bytes(b"LMDB.TEST").expect("realm"),
            ],
        };
        for supplied in [&master, &second] {
            let store = LmdbStore::open(&config, supplied).expect("open rotated database");
            let keys = store.master_key_list().expect("master keys");
            assert_eq!(
                keys.keys.iter().map(|(v, _)| *v).collect::<Vec<_>>(),
                [2, 1]
            );
            assert_eq!(keys.active().expect("active").0, 2);
            assert!(store
                .get_record_sync(&krbtgt, "LMDB.TEST")
                .expect("read krbtgt under master key 1")
                .is_some());
        }
    }

    #[test]
    fn create_refuses_legacy_file_database_without_converting() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("principal");
        let config = test_config(&path);
        let master =
            master_key_from_password("LMDB.TEST", "master password", 18).expect("master key");
        let file = FileStore::create(&path, "LMDB.TEST", &master).expect("create file database");
        drop(file);

        let error = match LmdbStore::create(&config, &master) {
            Ok(_) => panic!("create unexpectedly converted the legacy file database"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("create was not run"));
        assert!(path.exists());
        assert!(!main_path(&path).exists());
        assert!(!appended(&path, ".krb5rs-file.bak").exists());
    }

    #[tokio::test]
    async fn policy_modification_preserves_unmodeled_tl_data() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("principal");
        let (store, _) = test_store(&path);
        let original = MitPolicy {
            name: "foreign-policy".into(),
            pw_min_life: 0,
            pw_max_life: 0,
            pw_min_length: 0,
            pw_min_classes: 0,
            pw_history_num: 0,
            pw_max_fail: 0,
            pw_failcnt_interval: 0,
            pw_lockout_duration: 0,
            attributes: 0,
            max_life: 0,
            max_renewable_life: 0,
            allowed_keysalts: None,
            tl_data: vec![TlData {
                kind: 0x7777,
                data: vec![9, 8, 7, 6],
            }],
        };
        let key = original.name.as_bytes().to_vec();
        let value = original.encode().expect("policy encoding");
        {
            let mut txn = store.inner.main_env.write_txn().expect("policy seed txn");
            store
                .inner
                .policy_db
                .put(&mut txn, &key, &value)
                .expect("seed policy");
            txn.commit().expect("commit seed policy");
        }
        store
            .update_policy("foreign-policy", move |policy| {
                policy.pw_min_length = 12;
                Ok(())
            })
            .await
            .expect("modify policy");
        let txn = store.inner.main_env.read_txn().expect("policy read txn");
        let value = store
            .inner
            .policy_db
            .get(&txn, &key)
            .expect("read policy")
            .expect("policy exists")
            .to_vec();
        let after = MitPolicy::decode(&key, &value).expect("decode policy");
        assert_eq!(after.pw_min_length, 12);
        assert_eq!(after.tl_data, original.tl_data);
    }

    #[tokio::test]
    async fn legacy_file_auto_conversion_is_recoverable_and_idempotent() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("principal");
        let master =
            master_key_from_password("LMDB.TEST", "master password", 18).expect("master key");
        let file = FileStore::create(&path, "LMDB.TEST", &master).expect("create file db");
        file.create_principal(principal("alice"), None)
            .await
            .expect("add alice to file db");
        file.create_policy(Policy {
            name: "default".into(),
            pw_history_num: 3,
            ..Policy::default()
        })
        .await
        .expect("add policy to file db");
        let (expected_records, expected_policies) = file.export_records().expect("snapshot");
        drop(file);

        let temp_base = appended(&path, ".convert.tmp");
        fs::write(appended(&temp_base, ".mdb"), b"interrupted main env").expect("temp main");
        fs::write(
            appended(&temp_base, ".lockout.mdb"),
            b"interrupted lockout env",
        )
        .expect("temp lockout");

        let config = test_config(&path);
        let converted = LmdbStore::open(&config, &master).expect("auto convert");
        assert!(!path.exists());
        assert!(appended(&path, ".krb5rs-file.bak").exists());
        assert!(!appended(&temp_base, ".mdb").exists());
        assert!(!appended(&temp_base, ".lockout.mdb").exists());
        let converted_records = converted.list_records_sync().expect("converted records");
        assert_eq!(converted_records.len(), expected_records.len());
        for expected in &expected_records {
            let actual = converted
                .get_record(&expected.entry.name, &expected.entry.realm)
                .await
                .expect("converted get")
                .expect("record converted");
            assert_eq!(actual.entry.name, expected.entry.name);
            assert_eq!(actual.entry.realm, expected.entry.realm);
            assert_eq!(actual.entry.attributes, expected.entry.attributes);
            assert_eq!(actual.entry.max_life, expected.entry.max_life);
            assert_eq!(
                actual.entry.max_renewable_life,
                expected.entry.max_renewable_life
            );
            assert_eq!(actual.entry.expiration, expected.entry.expiration);
            assert_eq!(actual.entry.pw_expiration, expected.entry.pw_expiration);
            assert_eq!(
                actual.entry.allowed_to_delegate_to,
                expected.entry.allowed_to_delegate_to
            );
            assert_eq!(
                actual.entry.allowed_to_delegate_from,
                expected.entry.allowed_to_delegate_from
            );
            assert_eq!(actual.entry.policy, expected.entry.policy);
            assert_eq!(
                actual.entry.last_admin_unlock,
                expected.entry.last_admin_unlock
            );
            assert_eq!(actual.last_pwd_change, expected.last_pwd_change);
            assert_eq!(actual.mod_time, expected.mod_time);
            assert_eq!(
                actual.mod_by.as_deref(),
                Some(b"db_creation@LMDB.TEST".as_slice())
            );
            assert_eq!(actual.entry.security_epoch, 0);
            assert_eq!(actual.entry.keys.len(), expected.entry.keys.len());
            for (a, b) in actual.entry.keys.iter().zip(&expected.entry.keys) {
                assert_eq!(a.kvno, b.kvno);
                assert_eq!(a.key.keytype, b.key.keytype);
                assert_eq!(a.key.key_bytes(), b.key.key_bytes());
                assert_eq!(a.salt, b.salt);
                assert!(a.s2kparams.is_none());
            }
        }
        assert_eq!(
            converted.list_policies_sync().expect("converted policies"),
            expected_policies
                .iter()
                .map(|p| {
                    let mut p = p.clone();
                    p.security_epoch = 0;
                    p
                })
                .collect::<Vec<_>>()
        );

        let backup = appended(&path, ".krb5rs-file.bak");
        let backup_bytes = fs::read(&backup).expect("backup");
        drop(converted);
        let reopened = LmdbStore::open(&config, &master).expect("second open");
        assert_eq!(
            reopened.list_records_sync().expect("records").len(),
            expected_records.len()
        );
        assert_eq!(fs::read(backup).expect("backup unchanged"), backup_bytes);
    }

    /// A legacy file database holding `alice` and `bob`.
    async fn legacy_database(path: &Path) -> EncryptionKey {
        let master =
            master_key_from_password("LMDB.TEST", "master password", 18).expect("master key");
        let file = FileStore::create(path, "LMDB.TEST", &master).expect("create file db");
        for name in ["alice", "bob"] {
            file.create_principal(principal(name), None)
                .await
                .expect("add principal to file db");
        }
        master
    }

    fn klmdb_files(path: &Path) -> Vec<PathBuf> {
        PUBLISH_ORDER
            .iter()
            .flat_map(|suffix| {
                [
                    appended(path, suffix),
                    appended(&appended(path, ".convert.tmp"), suffix),
                    appended(&appended(path, ".create.tmp"), suffix),
                ]
            })
            .filter(|file| file.exists())
            .collect()
    }

    fn assert_converted(store: &LmdbStore, path: &Path) {
        let names: Vec<String> = store
            .list_records_sync()
            .expect("records")
            .iter()
            .map(|record| record.entry.name.to_string())
            .collect();
        for name in ["alice", "bob"] {
            assert!(
                names.contains(&name.to_string()),
                "{name} missing: {names:?}"
            );
        }
        assert!(!path.exists(), "legacy file left in place");
        assert!(backup_path(path).exists(), "no legacy backup");
        assert!(lockout_path(path).exists(), "no lockout environment");
    }

    #[tokio::test]
    async fn conversion_stopped_before_publishing_main_is_redone_on_open() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("principal");
        let master = legacy_database(&path).await;
        let config = test_config(&path);
        let options = LmdbOptions::default();
        let faults = Faults {
            publish_stop: Some(PUBLISH_ORDER.len() - 1),
            ..Faults::default()
        };
        auto_convert_legacy(&path, &master, "LMDB.TEST", &options, faults)
            .expect_err("injected stop");
        assert!(lockout_path(&path).exists(), "lockout published first");
        assert!(!main_path(&path).exists(), "main must be published last");
        assert!(path.exists() && !backup_path(&path).exists());

        let store = LmdbStore::open(&config, &master).expect("open redoes the conversion");
        assert_converted(&store, &path);
    }

    #[tokio::test]
    async fn conversion_stopped_before_backup_is_finished_on_open() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("principal");
        let master = legacy_database(&path).await;
        let config = test_config(&path);
        let faults = Faults {
            before_backup: true,
            ..Faults::default()
        };
        auto_convert_legacy(&path, &master, "LMDB.TEST", &LmdbOptions::default(), faults)
            .expect_err("injected stop");
        assert!(main_path(&path).exists() && path.exists());
        assert!(!backup_path(&path).exists());

        let store = LmdbStore::open(&config, &master).expect("open finishes the backup");
        assert_converted(&store, &path);
    }

    #[tokio::test]
    async fn open_refuses_both_legacy_file_and_backup_beside_klmdb() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("principal");
        let master = legacy_database(&path).await;
        let config = test_config(&path);
        let faults = Faults {
            before_backup: true,
            ..Faults::default()
        };
        auto_convert_legacy(&path, &master, "LMDB.TEST", &LmdbOptions::default(), faults)
            .expect_err("injected stop");
        fs::copy(&path, backup_path(&path)).expect("second copy");

        let error = match LmdbStore::open(&config, &master) {
            Ok(_) => panic!("open guessed which legacy file to keep"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), StoreErrorKind::Conflict);
        assert!(path.exists() && backup_path(&path).exists());
    }

    #[tokio::test]
    async fn conversion_waits_for_file_store_writers() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("principal");
        let master = legacy_database(&path).await;
        let legacy_bytes = fs::read(&path).expect("legacy bytes");
        let config = test_config(&path);
        let writer = FileStore::open(&path, &master).expect("writer");
        let lock = writer.write_lock().expect("writer lock");

        let error = match LmdbStore::open(&config, &master) {
            Ok(_) => panic!("converted while a file-store writer held the lock"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), StoreErrorKind::Unavailable);
        assert!(klmdb_files(&path).is_empty(), "{:?}", klmdb_files(&path));
        assert_eq!(fs::read(&path).expect("legacy unchanged"), legacy_bytes);

        drop(lock);
        let store = LmdbStore::open(&config, &master).expect("convert after the writer");
        assert_converted(&store, &path);
    }

    #[test]
    fn failed_create_leaves_nothing_and_can_be_rerun() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("principal");
        let config = test_config(&path);
        let master =
            master_key_from_password("LMDB.TEST", "master password", 18).expect("master key");
        for faults in [
            Faults {
                after_create_envs: true,
                ..Faults::default()
            },
            Faults {
                publish_stop: Some(PUBLISH_ORDER.len() - 1),
                ..Faults::default()
            },
        ] {
            assert!(LmdbStore::create_with(&config, &master, faults).is_err());
            assert!(!main_path(&path).exists());
            assert!(!appended(&appended(&path, ".create.tmp"), ".mdb").exists());
        }
        let store = LmdbStore::create(&config, &master).expect("rerun create");
        store.verify_master().expect("seeded K/M");
    }

    #[tokio::test]
    async fn klmdb_keeps_mit_password_history() {
        use krb5_rs::kdc::kdb::admin::PrincipalOptions;

        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("principal");
        let config = test_config(&path);
        let (store, _master) = test_store(&path);
        let admin = AdminOps::new(store.clone(), config.supported_keysalts.clone());
        admin
            .add_policy(Policy {
                name: "hist".into(),
                pw_history_num: 3,
                ..Policy::default()
            })
            .await
            .expect("policy");
        let alice = PrincipalName::new_principal("alice");
        let opts = PrincipalOptions {
            policy: Some(Some("hist".into())),
            ..PrincipalOptions::default()
        };
        admin
            .add_principal(&alice, "LMDB.TEST", Some("pw-0"), &opts)
            .await
            .expect("add");
        let cpw = |pw: &'static str| admin.change_password(&alice, "LMDB.TEST", Some(pw), false);
        for pw in ["pw-a", "pw-b", "pw-c"] {
            cpw(pw).await.expect(pw);
        }
        // pw_history_num 3 keeps the two previous passwords plus the current.
        for pw in ["pw-a", "pw-b", "pw-c"] {
            let error = cpw(pw).await.expect_err(pw);
            assert_eq!(error.kind(), StoreErrorKind::Rejected, "{pw}: {error}");
            assert_eq!(error.message(), "Cannot reuse password");
        }
        let record = store
            .get_record_sync(&alice, "LMDB.TEST")
            .expect("read")
            .expect("alice");
        let history = record.password_history.expect("klmdb stores history");
        assert_eq!(history.old_keys.len(), 2);
        assert_eq!(history.admin_history_kvno, 2);

        let hist_name = PrincipalName {
            name_type: 1,
            name_string: vec![
                KerberosString::from_bytes(b"kadmin").expect("kadmin"),
                KerberosString::from_bytes(b"history").expect("history"),
            ],
        };
        let hist = store
            .get_record_sync(&hist_name, "LMDB.TEST")
            .expect("read")
            .expect("kadmin/history created on first use");
        assert_eq!(hist.entry.keys.iter().map(|k| k.kvno).max(), Some(2));
        assert_eq!(hist.entry.max_life, Some(Duration::from_secs(64)));
        let error = admin
            .change_password(&hist_name, "LMDB.TEST", Some("x"), false)
            .await
            .expect_err("protected");
        assert_eq!(error.message(), "Cannot change protected principal");

        cpw("pw-0").await.expect("dropped out of the history");
        // A new history key makes the old entries unreadable, so MIT resets
        // the history on the next change (svr_principal.c:1106-1114, 1317).
        admin
            .change_password(&hist_name, "LMDB.TEST", None, false)
            .await
            .expect("randkey kadmin/history");
        cpw("pw-a")
            .await
            .expect("history reset by the new history key");
        let history = store
            .get_record_sync(&alice, "LMDB.TEST")
            .expect("read")
            .expect("alice")
            .password_history
            .expect("history");
        assert_eq!(history.admin_history_kvno, 3);
        assert_eq!(history.old_keys.len(), 1);
    }

    #[tokio::test]
    async fn lockout_write_failure_does_not_strand_a_principal() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("principal");
        let (store, _master) = test_store(&path);
        let alice = PrincipalName::new_principal("alice");
        let fault = &store.inner.fail_lockout_write;
        fault.store(true, std::sync::atomic::Ordering::SeqCst);
        store
            .create_principal(principal("alice"), None)
            .await
            .expect_err("lockout failure fails the create");
        assert!(store.get_raw(&alice, "LMDB.TEST").expect("read").is_none());

        fault.store(false, std::sync::atomic::Ordering::SeqCst);
        store
            .create_principal(principal("alice"), None)
            .await
            .expect("retried create");

        fault.store(true, std::sync::atomic::Ordering::SeqCst);
        assert!(store
            .delete_principal(&alice, "LMDB.TEST")
            .await
            .expect("delete ignores the lockout failure"));
        assert!(store.get_raw(&alice, "LMDB.TEST").expect("read").is_none());
    }
}
