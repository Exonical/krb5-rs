//! File-backed principal database.
//!
//! Writes serialise through `<path>.lock` (created exclusively), rewrite the
//! database to `<path>.tmp`, sync it and rename it over the original, so a
//! reader never sees a partial file. Readers reload when the file's
//! modification time or length changes.

use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::RwLock;
use std::time::SystemTime;

use chrono::Utc;
use rasn::types::{GeneralString, OctetString};

use super::format::{KdbFile, KdbKey, KdbPolicy, KdbPrincipal, KdbTlData, MAGIC, VERSION};
use super::master::master_principal;
use super::mit::mkey::{entry_mkvno, ActKvno, MasterKeys};
use super::mit::{
    merge_policy, new_entry, policy_from_entry, record_from_entry, unparse_name, MitEntry,
    MitPolicy, TlData, ACTKVNO, MKEY_AUX,
};
use crate::kdc::db::{
    random_keys, store_key, KeyEntry, PrincipalAttributes, PrincipalEntry, StoreKey,
};
use crate::kdc::policy::{kerberos_time, ts};
use crate::kdc::replication::{StoredKey, StoredPrincipal};
use crate::kdc::store::{
    AdminStore, HealthCheck, Policy, PolicyStore, PrincipalRecord, PrincipalStore, StoreError,
    StoreErrorKind,
};
use crate::types::{EncryptionKey, KerberosTime, PrincipalName};

fn err(msg: impl Into<String>) -> StoreError {
    StoreError::backend(msg)
}

fn policy_from_record(p: &KdbPolicy) -> Result<Policy, StoreError> {
    Ok(Policy {
        name: String::from_utf8_lossy(p.name.as_bytes()).to_string(),
        pw_min_life: p.pw_min_life,
        pw_max_life: p.pw_max_life,
        pw_min_length: p.pw_min_length,
        pw_min_classes: p.pw_min_classes,
        pw_history_num: p.pw_history_num,
        pw_max_fail: p.pw_max_fail,
        pw_failcnt_interval: p.pw_failcnt_interval,
        pw_lockout_duration: p.pw_lockout_duration,
        attributes: p.attributes,
        max_life: p.max_life,
        max_renewable_life: p.max_renewable_life,
        allowed_keysalts: p
            .allowed_keysalts
            .as_ref()
            .map(|g| String::from_utf8_lossy(g.as_bytes()).to_string()),
        security_epoch: p.security_epoch.unwrap_or(0),
        tl_data: Policy::tl_data_from_bytes(p.tl_data.as_deref().unwrap_or(&[]))?,
    })
}

fn policy_to_record(p: &Policy) -> Result<KdbPolicy, StoreError> {
    Ok(KdbPolicy {
        name: general(&p.name)?,
        pw_min_life: p.pw_min_life,
        pw_max_life: p.pw_max_life,
        pw_min_length: p.pw_min_length,
        pw_min_classes: p.pw_min_classes,
        pw_history_num: p.pw_history_num,
        pw_max_fail: p.pw_max_fail,
        pw_failcnt_interval: p.pw_failcnt_interval,
        pw_lockout_duration: p.pw_lockout_duration,
        attributes: p.attributes,
        max_life: p.max_life,
        max_renewable_life: p.max_renewable_life,
        allowed_keysalts: p.allowed_keysalts.as_deref().map(general).transpose()?,
        security_epoch: Some(p.security_epoch),
        tl_data: (!p.tl_data.is_empty())
            .then(|| p.tl_data_bytes().map(Into::into))
            .transpose()?,
    })
}

fn general(s: &str) -> Result<GeneralString, StoreError> {
    GeneralString::from_bytes(s.as_bytes()).map_err(|_| err(format!("invalid string {s:?}")))
}

fn general_list(l: &[String]) -> Result<Option<Vec<GeneralString>>, StoreError> {
    if l.is_empty() {
        return Ok(None);
    }
    l.iter()
        .map(|s| general(s))
        .collect::<Result<Vec<_>, _>>()
        .map(Some)
}

fn string_list(l: &Option<Vec<GeneralString>>) -> Vec<String> {
    l.iter()
        .flatten()
        .map(|g| String::from_utf8_lossy(g.as_bytes()).to_string())
        .collect()
}

type Stamp = (SystemTime, u64);

#[derive(Default)]
struct Cache {
    stamp: Option<Stamp>,
    serial: u64,
    records: HashMap<StoreKey, KdbPrincipal>,
    policies: HashMap<String, Policy>,
}

/// Persistent [`PrincipalStore`] in this crate's own file format (not MIT's
/// db2). Keys are encrypted under the master key.
pub struct FileStore {
    path: PathBuf,
    realm: String,
    master: EncryptionKey,
    /// Master-key list from `K/M`, reloaded with the cache.
    masters: RwLock<MasterKeys>,
    cache: RwLock<Cache>,
}

struct LockGuard(PathBuf);

impl Drop for LockGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn sibling(path: &Path, suffix: &str) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(suffix);
    PathBuf::from(s)
}

fn stamp_of(path: &Path) -> Result<Stamp, StoreError> {
    let md = std::fs::metadata(path).map_err(|e| err(format!("{}: {e}", path.display())))?;
    Ok((md.modified().unwrap_or(SystemTime::UNIX_EPOCH), md.len()))
}

fn read_file(path: &Path) -> Result<(Stamp, KdbFile), StoreError> {
    let stamp = stamp_of(path)?;
    let bytes = std::fs::read(path).map_err(|e| err(format!("{}: {e}", path.display())))?;
    Ok((stamp, parse_image(&bytes)?))
}

/// Decode and sanity-check the bytes of a database file.
fn parse_image(bytes: &[u8]) -> Result<KdbFile, StoreError> {
    let body = bytes
        .strip_prefix(MAGIC.as_slice())
        .ok_or_else(|| StoreError::corrupt("not a krb5-rs database (bad magic)"))?;
    let file: KdbFile = rasn::der::decode(body)
        .map_err(|e| StoreError::corrupt(format!("corrupt database: {e}")))?;
    if file.version != VERSION {
        return Err(StoreError::corrupt(format!(
            "unsupported database version {}",
            file.version
        )));
    }
    Ok(file)
}

fn write_atomic(path: &Path, file: &KdbFile) -> Result<(), StoreError> {
    let tmp = sibling(path, ".tmp");
    let mut bytes = MAGIC.to_vec();
    bytes.extend(rasn::der::encode(file).map_err(|e| err(e.to_string()))?);
    let result = (|| -> std::io::Result<()> {
        let mut f = crate::fsutil::create_private(&tmp)?;
        f.write_all(&bytes)?;
        f.sync_all()?;
        drop(f);
        std::fs::rename(&tmp, path)
    })();
    result.map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        err(format!("writing {}: {e}", path.display()))
    })
}

/// A file record in the shared stored form: keys stay encrypted.
fn stored_of(r: &KdbPrincipal) -> StoredPrincipal {
    let lossy = |g: &GeneralString| String::from_utf8_lossy(g.as_bytes()).to_string();
    StoredPrincipal {
        name: r.name.clone(),
        realm: lossy(&r.realm),
        attributes: r.attributes,
        max_life: r.max_life,
        max_renewable_life: r.max_renewable_life,
        expiration: r.expiration.as_ref().map(ts),
        pw_expiration: r.pw_expiration.as_ref().map(ts),
        last_pwd_change: r.last_pwd_change.as_ref().map(ts),
        mod_time: r.mod_time.as_ref().map(ts),
        keys: r
            .keys
            .iter()
            .map(|k| StoredKey {
                kvno: k.kvno,
                enctype: k.enctype,
                mkvno: k.mkvno,
                enc_key: k.enc_key.to_vec(),
                salt: k.salt.as_ref().map(|s| s.to_vec()),
                s2kparams: k.s2kparams.as_ref().map(|s| s.to_vec()),
            })
            .collect(),
        allowed_to_delegate_to: string_list(&r.allowed_to_delegate_to),
        allowed_to_delegate_from: string_list(&r.allowed_to_delegate_from),
        policy: r.policy.as_ref().map(lossy),
        security_epoch: r.security_epoch.unwrap_or(0),
        last_admin_unlock: r.last_admin_unlock.as_ref().map(ts),
        tl_data: r
            .tl_data
            .iter()
            .flatten()
            .map(|t| TlData {
                kind: t.kind,
                data: t.data.to_vec(),
            })
            .collect(),
    }
}

/// Inverse of [`stored_of`].
fn kdb_of(sp: &StoredPrincipal) -> Result<KdbPrincipal, StoreError> {
    let keys = sp
        .keys
        .iter()
        .map(|k| KdbKey {
            kvno: k.kvno,
            enctype: k.enctype,
            mkvno: k.mkvno,
            enc_key: OctetString::from(k.enc_key.clone()),
            salt: k.salt.clone().map(OctetString::from),
            s2kparams: k.s2kparams.clone().map(OctetString::from),
        })
        .collect();
    Ok(KdbPrincipal {
        name: sp.name.clone(),
        realm: general(&sp.realm)?,
        attributes: sp.attributes,
        max_life: sp.max_life,
        max_renewable_life: sp.max_renewable_life,
        expiration: sp.expiration.map(kerberos_time),
        pw_expiration: sp.pw_expiration.map(kerberos_time),
        last_pwd_change: sp.last_pwd_change.map(kerberos_time),
        mod_time: sp.mod_time.map(kerberos_time),
        keys,
        allowed_to_delegate_to: general_list(&sp.allowed_to_delegate_to)?,
        allowed_to_delegate_from: general_list(&sp.allowed_to_delegate_from)?,
        policy: sp.policy.as_deref().map(general).transpose()?,
        security_epoch: (sp.security_epoch != 0).then_some(sp.security_epoch),
        last_admin_unlock: sp.last_admin_unlock.map(kerberos_time),
        tl_data: (!sp.tl_data.is_empty()).then(|| {
            sp.tl_data
                .iter()
                .map(|t| KdbTlData {
                    kind: t.kind,
                    data: OctetString::from(t.data.clone()),
                })
                .collect()
        }),
    })
}

/// `keys` with `kvno` as the active master key, to wrap one entry's keys
/// under the master key it already uses.
fn active_as(keys: &MasterKeys, kvno: u16) -> MasterKeys {
    MasterKeys {
        keys: keys.keys.clone(),
        actkvno: vec![ActKvno { kvno, act_time: 0 }],
    }
}

fn is_km(p: &KdbPrincipal, km: &PrincipalName, realm: &str) -> bool {
    p.name == *km && p.realm.as_bytes() == realm.as_bytes()
}

fn to_time(t: &Option<KerberosTime>) -> Option<KerberosTime> {
    *t
}

impl FileStore {
    /// Whether `path` begins with this crate's legacy file-store magic. Used
    /// only by the opt-in klmdb migration path.
    pub fn has_database_magic(path: &Path) -> Result<bool, StoreError> {
        use std::io::Read;

        let mut file = match std::fs::File::open(path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(err(format!("{}: {error}", path.display()))),
        };
        let mut magic = [0; 8];
        match file.read_exact(&mut magic) {
            Ok(()) => Ok(&magic == MAGIC),
            Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => Ok(false),
            Err(error) => Err(err(format!("{}: {error}", path.display()))),
        }
    }

    /// Create a new database holding `K/M@REALM` and `krbtgt/REALM@REALM`
    /// with random keys for the default key/salt list (aes256, aes128).
    pub fn create(path: &Path, realm: &str, master: &EncryptionKey) -> Result<Self, StoreError> {
        Self::create_with(path, realm, master, &[18, 17])
    }

    /// [`FileStore::create`] with explicit krbtgt etypes.
    pub fn create_with(
        path: &Path,
        realm: &str,
        master: &EncryptionKey,
        tgt_etypes: &[i32],
    ) -> Result<Self, StoreError> {
        if path.exists() {
            return Err(err(format!("database {} already exists", path.display())));
        }
        let store = Self {
            path: path.to_path_buf(),
            realm: realm.to_string(),
            master: master.clone(),
            masters: RwLock::new(MasterKeys::single(master.clone())),
            cache: RwLock::new(Cache::default()),
        };
        let now = kerberos_time(Utc::now().timestamp());
        let km_key = KeyEntry {
            kvno: 1,
            key: master.clone(),
            salt: None,
            s2kparams: None,
        };
        let km = PrincipalEntry {
            allowed_to_delegate_to: Vec::new(),
            allowed_to_delegate_from: Vec::new(),
            policy: None,
            security_epoch: 0,
            last_admin_unlock: None,
            name: master_principal()?,
            realm: realm.to_string(),
            attributes: PrincipalAttributes::DISALLOW_ALL_TIX
                | PrincipalAttributes::REQUIRES_PRE_AUTH
                | PrincipalAttributes::LOCKDOWN_KEYS,
            max_life: None,
            max_renewable_life: None,
            expiration: None,
            pw_expiration: None,
            keys: vec![km_key],
        };
        let tgs_name = PrincipalName {
            name_type: 2,
            name_string: vec![general("krbtgt")?, general(realm)?],
        };
        let tgs = PrincipalEntry {
            allowed_to_delegate_to: Vec::new(),
            allowed_to_delegate_from: Vec::new(),
            policy: None,
            security_epoch: 0,
            last_admin_unlock: None,
            name: tgs_name,
            realm: realm.to_string(),
            attributes: PrincipalAttributes::empty(),
            max_life: None,
            max_renewable_life: None,
            expiration: None,
            pw_expiration: None,
            keys: random_keys(1, tgt_etypes).map_err(|e| err(e.to_string()))?,
        };
        let principals = vec![
            store.to_record(&km, Some(now), Some(now), None, &store.master_keys())?,
            store.to_record(&tgs, Some(now), Some(now), None, &store.master_keys())?,
        ];
        let file = KdbFile {
            version: VERSION,
            realm: general(realm)?,
            principals,
            serial: Some(1),
            policies: None,
        };
        write_atomic(path, &file)?;
        store.refresh(true)?;
        Ok(store)
    }

    /// Open an existing database. `master` must open the newest `K/M` key,
    /// directly or through `KRB5_TL_MKEY_AUX` (`krb5_db_fetch_mkey_list`).
    pub fn open(path: &Path, master: &EncryptionKey) -> Result<Self, StoreError> {
        let (_, file) = read_file(path)?;
        let realm = String::from_utf8_lossy(file.realm.as_bytes()).to_string();
        let master_name = master_principal()?;
        let km = file
            .principals
            .iter()
            .find(|p| p.name == master_name && p.realm.as_bytes() == realm.as_bytes())
            .ok_or_else(|| err("database has no K/M principal"))?;
        let keys = stored_of(km)
            .master_keys(master)
            .map_err(|_| err("incorrect master key"))?;
        let store = Self {
            path: path.to_path_buf(),
            realm,
            master: master.clone(),
            masters: RwLock::new(keys),
            cache: RwLock::new(Cache::default()),
        };
        store.refresh(true)?;
        Ok(store)
    }

    /// The realm this database serves.
    pub fn realm(&self) -> &str {
        &self.realm
    }

    /// The database file.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The modification serial: 1 at creation, incremented by every write,
    /// 0 for a file written before serials existed.
    pub fn serial(&self) -> u64 {
        let _ = self.refresh(false);
        self.read_cache().serial
    }

    /// The raw database file and its serial, from one read (writes replace
    /// the file atomically, so the pair is consistent).
    pub fn snapshot(&self) -> Result<(u64, Vec<u8>), StoreError> {
        let bytes =
            std::fs::read(&self.path).map_err(|e| err(format!("{}: {e}", self.path.display())))?;
        let file = parse_image(&bytes)?;
        Ok((file.serial.unwrap_or(0), bytes))
    }

    /// Check that `path` is a database for `realm` that opens under
    /// `master` (magic, version, realm, and the K/M key check), returning
    /// its serial.
    pub fn verify_image(
        path: &Path,
        realm: &str,
        master: &EncryptionKey,
    ) -> Result<u64, StoreError> {
        let store = Self::open(path, master)?;
        if store.realm != realm {
            return Err(err(format!(
                "database is for realm {}, expected {realm}",
                store.realm
            )));
        }
        Ok(store.serial())
    }

    /// Store `e` with its keys under the active master key; unchanged keys
    /// of `previous` keep their stored form and master key version.
    fn to_record(
        &self,
        e: &PrincipalEntry,
        last_pwd_change: Option<KerberosTime>,
        mod_time: Option<KerberosTime>,
        previous: Option<&KdbPrincipal>,
        keys: &MasterKeys,
    ) -> Result<KdbPrincipal, StoreError> {
        let (pwd, modified) = (last_pwd_change.as_ref().map(ts), mod_time.as_ref().map(ts));
        let sp = match previous {
            Some(p) => StoredPrincipal::from_update(e, pwd, modified, keys, &stored_of(p))?,
            None => StoredPrincipal::from_entry(e, pwd, modified, keys)?,
        };
        kdb_of(&sp)
    }

    fn decrypt_record(&self, r: &KdbPrincipal) -> Result<PrincipalRecord, StoreError> {
        self.decrypt_with(r, &self.master_keys())
    }

    fn decrypt_with(
        &self,
        r: &KdbPrincipal,
        keys: &MasterKeys,
    ) -> Result<PrincipalRecord, StoreError> {
        Ok(PrincipalRecord {
            entry: stored_of(r).into_entry(keys)?,
            last_pwd_change: to_time(&r.last_pwd_change),
            password_history: None,
            mod_time: to_time(&r.mod_time),
            mod_by: None,
        })
    }

    fn master_keys(&self) -> MasterKeys {
        self.masters
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// The master-key list of the `K/M` in `list` (the file read under the
    /// write lock), which becomes the loaded list, so a write never wraps keys
    /// under a stale active key (`kdb_get_active_mkey` rereads `K/M`,
    /// `server_kdb.c:84-98`).
    fn masters_in(&self, list: &[KdbPrincipal]) -> Result<MasterKeys, StoreError> {
        let km_name = master_principal()?;
        let Some(km) = list.iter().find(|p| is_km(p, &km_name, &self.realm)) else {
            return Ok(self.master_keys());
        };
        let keys = stored_of(km)
            .master_keys(&self.master)
            .map_err(|_| err("incorrect master key"))?;
        *self.masters.write().unwrap_or_else(|e| e.into_inner()) = keys.clone();
        Ok(keys)
    }

    /// The master-key list (`krb5_db_fetch_mkey_list`).
    pub fn master_key_list(&self) -> Result<MasterKeys, StoreError> {
        self.refresh(false)?;
        Ok(self.master_keys())
    }

    /// Every principal as a raw MIT entry with its keys still encrypted,
    /// for the `kdb5_util` master-key commands.
    pub fn raw_entries(&self) -> Result<Vec<MitEntry>, StoreError> {
        self.refresh(false)?;
        let cache = self.read_cache();
        let mut raws = cache
            .records
            .values()
            .map(|r| stored_of(r).to_raw())
            .collect::<Result<Vec<_>, _>>()?;
        raws.sort_by_cached_key(|e| unparse_name(&e.principal, &e.realm));
        Ok(raws)
    }

    /// Read-modify-write one principal's raw MIT entry under the write lock;
    /// `f` returns false to leave it unchanged.
    pub fn update_raw<F>(&self, name: &PrincipalName, realm: &str, f: F) -> Result<bool, StoreError>
    where
        F: FnOnce(&mut MitEntry, &MasterKeys) -> Result<bool, StoreError>,
    {
        self.refresh(false)?;
        let key = store_key(name, realm);
        self.modify(|list| {
            let pos = list
                .iter()
                .position(|p| {
                    let r = String::from_utf8_lossy(p.realm.as_bytes()).to_string();
                    store_key(&p.name, &r) == key
                })
                .ok_or_else(|| {
                    StoreError::not_found(format!("Principal {name}@{realm} does not exist"))
                })?;
            let keys = self.masters_in(list)?;
            let mut sp = stored_of(&list[pos]);
            let mut raw = sp.to_raw()?;
            if !f(&mut raw, &keys)? {
                return Ok(false);
            }
            sp.apply_raw(&raw)?;
            list[pos] = kdb_of(&sp)?;
            Ok(true)
        })
    }

    fn read_cache(&self) -> std::sync::RwLockReadGuard<'_, Cache> {
        self.cache.read().unwrap_or_else(|e| e.into_inner())
    }

    /// Reload the cache if the file changed (or `force`).
    fn refresh(&self, force: bool) -> Result<(), StoreError> {
        let current = stamp_of(&self.path)?;
        if !force && self.read_cache().stamp == Some(current) {
            return Ok(());
        }
        let (stamp, file) = read_file(&self.path)?;
        let km_name = master_principal()?;
        if let Some(km) = file
            .principals
            .iter()
            .find(|p| is_km(p, &km_name, &self.realm))
        {
            let keys = stored_of(km)
                .master_keys(&self.master)
                .map_err(|_| err("incorrect master key"))?;
            *self.masters.write().unwrap_or_else(|e| e.into_inner()) = keys;
        }
        let records = file
            .principals
            .into_iter()
            .map(|p| {
                let realm = String::from_utf8_lossy(p.realm.as_bytes()).to_string();
                (store_key(&p.name, &realm), p)
            })
            .collect();
        let policies = file
            .policies
            .iter()
            .flatten()
            .map(|p| {
                let policy = policy_from_record(p)?;
                Ok((policy.name.clone(), policy))
            })
            .collect::<Result<_, StoreError>>()?;
        let mut cache = self.cache.write().unwrap_or_else(|e| e.into_inner());
        *cache = Cache {
            stamp: Some(stamp),
            serial: file.serial.unwrap_or(0),
            records,
            policies,
        };
        Ok(())
    }

    /// The record for a principal, with bookkeeping fields.
    pub fn get_record(
        &self,
        name: &PrincipalName,
        realm: &str,
    ) -> Result<Option<PrincipalRecord>, StoreError> {
        self.refresh(false)?;
        let raw = self
            .read_cache()
            .records
            .get(&store_key(name, realm))
            .cloned();
        raw.as_ref().map(|r| self.decrypt_record(r)).transpose()
    }

    fn lock(&self) -> Result<LockGuard, StoreError> {
        let path = sibling(&self.path, ".lock");
        crate::fsutil::create_new_private(&path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                err(format!("database locked ({} exists)", path.display()))
            } else {
                err(format!("creating {}: {e}", path.display()))
            }
        })?;
        Ok(LockGuard(path))
    }

    /// Take the write lock (`<path>.lock`) until the guard drops, so no
    /// file-store writer changes the database meanwhile (klmdb migration).
    pub fn write_lock(&self) -> Result<impl Drop, StoreError> {
        self.lock()
    }

    /// Run `f` over the on-disk principal list under the write lock.
    fn modify<R>(
        &self,
        f: impl FnOnce(&mut Vec<KdbPrincipal>) -> Result<R, StoreError>,
    ) -> Result<R, StoreError> {
        self.modify_file(|file| f(&mut file.principals))
    }

    /// Run `f` over the whole on-disk file under the write lock.
    fn modify_file<R>(
        &self,
        f: impl FnOnce(&mut KdbFile) -> Result<R, StoreError>,
    ) -> Result<R, StoreError> {
        let _guard = self.lock()?;
        let (_, mut file) = read_file(&self.path)?;
        let out = f(&mut file)?;
        file.serial = Some(file.serial.unwrap_or(0) + 1);
        write_atomic(&self.path, &file)?;
        self.refresh(true)?;
        Ok(out)
    }

    /// Insert or replace a principal (modification time set to now; the
    /// last password change of an existing record is kept, a new record's is
    /// set to now).
    pub fn put(&self, entry: PrincipalEntry) -> Result<(), StoreError> {
        let existing = self.get_record(&entry.name, &entry.realm)?;
        let pwd = existing
            .and_then(|r| r.last_pwd_change)
            .or_else(|| Some(kerberos_time(Utc::now().timestamp())));
        self.put_record(entry, pwd)
    }

    /// Insert or replace a principal with an explicit last password change.
    pub fn put_record(
        &self,
        entry: PrincipalEntry,
        last_pwd_change: Option<KerberosTime>,
    ) -> Result<(), StoreError> {
        let key = store_key(&entry.name, &entry.realm);
        self.modify(|list| {
            let pos = list.iter().position(|p| {
                let realm = String::from_utf8_lossy(p.realm.as_bytes()).to_string();
                store_key(&p.name, &realm) == key
            });
            let keys = self.masters_in(list)?;
            let record = self.to_record(
                &entry,
                last_pwd_change,
                Some(kerberos_time(Utc::now().timestamp())),
                pos.map(|i| &list[i]),
                &keys,
            )?;
            match pos {
                Some(i) => list[i] = record,
                None => list.push(record),
            }
            Ok(())
        })
    }

    /// Remove a principal; returns whether it existed.
    pub fn delete(&self, name: &PrincipalName, realm: &str) -> Result<bool, StoreError> {
        let key = store_key(name, realm);
        self.modify(|list| {
            let before = list.len();
            list.retain(|p| {
                let r = String::from_utf8_lossy(p.realm.as_bytes()).to_string();
                store_key(&p.name, &r) != key
            });
            Ok(list.len() != before)
        })
    }

    /// The policy called `name`.
    pub fn get_policy(&self, name: &str) -> Result<Option<Policy>, StoreError> {
        self.refresh(false)?;
        Ok(self.read_cache().policies.get(name).cloned())
    }

    /// Insert or replace a policy.
    pub fn put_policy(&self, policy: Policy) -> Result<(), StoreError> {
        let record = policy_to_record(&policy)?;
        self.modify_file(|file| {
            let list = file.policies.get_or_insert_with(Vec::new);
            list.retain(|p| p.name.as_bytes() != record.name.as_bytes());
            list.push(record);
            Ok(())
        })
    }

    /// Remove a policy; returns whether it existed.
    pub fn delete_policy(&self, name: &str) -> Result<bool, StoreError> {
        self.modify_file(|file| {
            let Some(list) = file.policies.as_mut() else {
                return Ok(false);
            };
            let before = list.len();
            list.retain(|p| p.name.as_bytes() != name.as_bytes());
            Ok(list.len() != before)
        })
    }

    /// Every policy, sorted by name.
    pub fn list_policies(&self) -> Result<Vec<Policy>, StoreError> {
        self.refresh(false)?;
        let mut all: Vec<Policy> = self.read_cache().policies.values().cloned().collect();
        all.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(all)
    }

    /// Every principal's record.
    pub(crate) fn list_records(&self) -> Result<Vec<PrincipalRecord>, StoreError> {
        self.refresh(false)?;
        let raws: Vec<KdbPrincipal> = self.read_cache().records.values().cloned().collect();
        raws.iter().map(|r| self.decrypt_record(r)).collect()
    }

    /// Snapshot all principals and policies for migration to another
    /// authoritative backend.
    pub fn export_records(&self) -> Result<(Vec<PrincipalRecord>, Vec<Policy>), StoreError> {
        self.refresh(false)?;
        let (raws, mut policies) = {
            let cache = self.read_cache();
            (
                cache
                    .records
                    .values()
                    .cloned()
                    .collect::<Vec<KdbPrincipal>>(),
                cache.policies.values().cloned().collect::<Vec<Policy>>(),
            )
        };
        policies.sort_by(|a, b| a.name.cmp(&b.name));
        let records = raws
            .iter()
            .map(|r| self.decrypt_record(r))
            .collect::<Result<_, _>>()?;
        Ok((records, policies))
    }

    /// Principals and policies as MIT dump entries in klmdb key order.
    /// Deviation: the file store keeps only what [`PrincipalRecord`] and
    /// [`Policy`] model (no lockout state, string attributes, password
    /// history), so only that is dumped.
    pub fn dump_entries(&self) -> Result<(Vec<MitEntry>, Vec<MitPolicy>), StoreError> {
        let (_, policies) = self.export_records()?;
        let creator = unparse_name(&PrincipalName::new_principal("db_creation"), &self.realm);
        let keys = self.master_keys();
        let raws: Vec<KdbPrincipal> = self.read_cache().records.values().cloned().collect();
        let mut entries = raws
            .iter()
            .map(|raw| {
                let sp = stored_of(raw);
                let mkvno = sp.keys.first().map_or(Ok(1), |k| {
                    u16::try_from(k.mkvno).map_err(|_| err("master key version out of range"))
                })?;
                let mut entry = new_entry(
                    &self.decrypt_record(raw)?,
                    &active_as(&keys, mkvno),
                    &creator,
                )?;
                entry.tl_data.extend(sp.tl_data);
                Ok(entry)
            })
            .collect::<Result<Vec<_>, StoreError>>()?;
        entries.sort_by_cached_key(|e| unparse_name(&e.principal, &e.realm));
        let policies = policies
            .iter()
            .map(|policy| {
                let mut entry = MitPolicy {
                    name: String::new(),
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
                    tl_data: Vec::new(),
                };
                merge_policy(&mut entry, policy).map(|()| entry)
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok((entries, policies))
    }

    /// Load dump records. Without `update` the new database is written to
    /// `<path>~` and renamed over `path`, like MIT's db2 temporary database
    /// (`plugins/kdb/db2/kdb_db2.c:298,1419-1460`). `master` must open the
    /// dump's `K/M`; each entry keeps its master key version. Fields the file
    /// store does not model are dropped.
    pub fn load_dump(
        path: &Path,
        realm: &str,
        master: &EncryptionKey,
        entries: &[MitEntry],
        policies: &[MitPolicy],
        update: bool,
    ) -> Result<(), StoreError> {
        let km_name = master_principal()?;
        let dumped_km = entries
            .iter()
            .find(|e| e.principal == km_name && e.realm == realm);
        let store = if update {
            Self::open(path, master)?
        } else {
            Self {
                path: path.to_path_buf(),
                realm: realm.to_string(),
                master: master.clone(),
                masters: RwLock::new(MasterKeys::single(master.clone())),
                cache: RwLock::new(Cache::default()),
            }
        };
        let keys = match dumped_km {
            Some(km) => MasterKeys::fetch(km, master)?,
            None => store.master_keys(),
        };
        let mut principals = Vec::with_capacity(entries.len());
        for entry in entries {
            let record = record_from_entry(entry, &keys)?;
            let mut sp = StoredPrincipal::from_entry(
                &record.entry,
                record.last_pwd_change.as_ref().map(ts),
                record.mod_time.as_ref().map(ts),
                &active_as(&keys, entry_mkvno(entry)?),
            )?;
            sp.tl_data = entry
                .tl_data
                .iter()
                .filter(|t| matches!(t.kind, ACTKVNO | MKEY_AUX))
                .cloned()
                .collect();
            principals.push((
                store_key(&record.entry.name, &record.entry.realm),
                kdb_of(&sp)?,
            ));
        }
        let policies = policies
            .iter()
            .map(|p| policy_to_record(&policy_from_entry(p)))
            .collect::<Result<Vec<_>, _>>()?;
        let merge = |file: &mut KdbFile| {
            let mut index: HashMap<StoreKey, usize> = HashMap::new();
            for (i, p) in file.principals.iter().enumerate() {
                let realm = String::from_utf8_lossy(p.realm.as_bytes()).to_string();
                index.insert(store_key(&p.name, &realm), i);
            }
            for (key, record) in principals {
                match index.get(&key) {
                    Some(&i) => file.principals[i] = record,
                    None => {
                        index.insert(key, file.principals.len());
                        file.principals.push(record);
                    }
                }
            }
            let list = file.policies.get_or_insert_with(Vec::new);
            for policy in policies {
                list.retain(|p| p.name.as_bytes() != policy.name.as_bytes());
                list.push(policy);
            }
        };
        if update {
            return store.modify_file(|file| {
                merge(file);
                Ok(())
            });
        }
        let _guard = store.lock()?;
        let serial = read_file(path).map_or(0, |(_, f)| f.serial.unwrap_or(0));
        let mut file = KdbFile {
            version: VERSION,
            realm: general(realm)?,
            principals: Vec::new(),
            serial: Some(serial + 1),
            policies: None,
        };
        merge(&mut file);
        let temporary = sibling(path, "~");
        write_atomic(&temporary, &file)?;
        std::fs::rename(&temporary, path).map_err(|e| {
            let _ = std::fs::remove_file(&temporary);
            err(format!("renaming {}: {e}", temporary.display()))
        })
    }

    /// Insert a new principal under the write lock; `Conflict` if it exists.
    pub(crate) fn create_record(
        &self,
        entry: PrincipalEntry,
        last_pwd_change: Option<KerberosTime>,
    ) -> Result<(), StoreError> {
        let key = store_key(&entry.name, &entry.realm);
        self.modify(|list| {
            let record = self.to_record(
                &entry,
                last_pwd_change,
                Some(kerberos_time(Utc::now().timestamp())),
                None,
                &self.masters_in(list)?,
            )?;
            let exists = list.iter().any(|p| {
                let realm = String::from_utf8_lossy(p.realm.as_bytes()).to_string();
                store_key(&p.name, &realm) == key
            });
            if exists {
                return Err(StoreError::conflict(format!(
                    "Principal or policy already exists: {}@{}",
                    entry.name, entry.realm
                )));
            }
            list.push(record);
            Ok(())
        })
    }

    /// Read-modify-write a principal under the write lock.
    pub(crate) fn update_record(
        &self,
        name: &PrincipalName,
        realm: &str,
        mut f: impl FnMut(&mut PrincipalRecord) -> Result<(), StoreError>,
    ) -> Result<PrincipalRecord, StoreError> {
        let key = store_key(name, realm);
        self.modify(|list| {
            let pos = list
                .iter()
                .position(|p| {
                    let r = String::from_utf8_lossy(p.realm.as_bytes()).to_string();
                    store_key(&p.name, &r) == key
                })
                .ok_or_else(|| {
                    StoreError::not_found(format!("Principal {name}@{realm} does not exist"))
                })?;
            let keys = self.masters_in(list)?;
            let mut rec = self.decrypt_with(&list[pos], &keys)?;
            f(&mut rec)?;
            rec.mod_time = Some(kerberos_time(Utc::now().timestamp()));
            list[pos] = self.to_record(
                &rec.entry,
                rec.last_pwd_change,
                rec.mod_time,
                Some(&list[pos]),
                &keys,
            )?;
            Ok(rec)
        })
    }

    /// Insert a new policy under the write lock; `Conflict` if it exists.
    pub(crate) fn create_policy_record(&self, policy: Policy) -> Result<(), StoreError> {
        let record = policy_to_record(&policy)?;
        self.modify_file(|file| {
            let list = file.policies.get_or_insert_with(Vec::new);
            if list
                .iter()
                .any(|p| p.name.as_bytes() == record.name.as_bytes())
            {
                return Err(StoreError::conflict(format!(
                    "Principal or policy already exists: policy {}",
                    policy.name
                )));
            }
            list.push(record);
            Ok(())
        })
    }

    /// Read-modify-write a policy under the write lock.
    pub(crate) fn update_policy_record(
        &self,
        name: &str,
        mut f: impl FnMut(&mut Policy) -> Result<(), StoreError>,
    ) -> Result<Policy, StoreError> {
        self.modify_file(|file| {
            let pos = file
                .policies
                .iter()
                .flatten()
                .position(|p| p.name.as_bytes() == name.as_bytes())
                .ok_or_else(|| {
                    StoreError::not_found(format!("Policy \"{name}\" does not exist"))
                })?;
            let list = file.policies.as_mut().expect("found above");
            let mut policy = policy_from_record(&list[pos])?;
            f(&mut policy)?;
            list[pos] = policy_to_record(&policy)?;
            Ok(policy)
        })
    }

    /// Every principal with decrypted keys.
    pub fn list(&self) -> Result<Vec<PrincipalEntry>, StoreError> {
        self.refresh(false)?;
        let raws: Vec<KdbPrincipal> = self.read_cache().records.values().cloned().collect();
        raws.iter()
            .map(|r| self.decrypt_record(r).map(|rec| rec.entry))
            .collect()
    }
}

impl PrincipalStore for FileStore {
    fn lookup(
        &self,
        name: &PrincipalName,
        realm: &str,
    ) -> impl std::future::Future<Output = Result<Option<PrincipalEntry>, StoreError>> + Send {
        std::future::ready(self.get_record(name, realm).map(|r| r.map(|r| r.entry)))
    }
}

impl PolicyStore for FileStore {
    fn policy(
        &self,
        name: &str,
    ) -> impl std::future::Future<Output = Result<Option<Policy>, StoreError>> + Send {
        std::future::ready(self.get_policy(name))
    }
}

impl HealthCheck for FileStore {
    fn health(&self) -> impl std::future::Future<Output = Result<(), StoreError>> + Send {
        std::future::ready(
            self.refresh(false)
                .map_err(|e| StoreError::new(StoreErrorKind::Unavailable, e.message().to_string())),
        )
    }
}

/// The file backend applies each operation under its write lock; the futures
/// complete immediately.
impl AdminStore for FileStore {
    fn get_record(
        &self,
        name: &PrincipalName,
        realm: &str,
    ) -> impl std::future::Future<Output = Result<Option<PrincipalRecord>, StoreError>> + Send {
        std::future::ready(FileStore::get_record(self, name, realm))
    }

    fn create_principal(
        &self,
        entry: PrincipalEntry,
        last_pwd_change: Option<KerberosTime>,
    ) -> impl std::future::Future<Output = Result<(), StoreError>> + Send {
        std::future::ready(self.create_record(entry, last_pwd_change))
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
        std::future::ready(self.update_record(name, realm, f))
    }

    fn delete_principal(
        &self,
        name: &PrincipalName,
        realm: &str,
    ) -> impl std::future::Future<Output = Result<bool, StoreError>> + Send {
        std::future::ready(self.delete(name, realm))
    }

    fn list_principals(
        &self,
    ) -> impl std::future::Future<Output = Result<Vec<PrincipalRecord>, StoreError>> + Send {
        std::future::ready(self.list_records())
    }

    fn get_policy(
        &self,
        name: &str,
    ) -> impl std::future::Future<Output = Result<Option<Policy>, StoreError>> + Send {
        std::future::ready(FileStore::get_policy(self, name))
    }

    fn create_policy(
        &self,
        policy: Policy,
    ) -> impl std::future::Future<Output = Result<(), StoreError>> + Send {
        std::future::ready(self.create_policy_record(policy))
    }

    fn update_policy<F>(
        &self,
        name: &str,
        f: F,
    ) -> impl std::future::Future<Output = Result<Policy, StoreError>> + Send
    where
        F: FnMut(&mut Policy) -> Result<(), StoreError> + Send + 'static,
    {
        std::future::ready(self.update_policy_record(name, f))
    }

    fn delete_policy(
        &self,
        name: &str,
    ) -> impl std::future::Future<Output = Result<bool, StoreError>> + Send {
        std::future::ready(FileStore::delete_policy(self, name))
    }

    fn list_policies(
        &self,
    ) -> impl std::future::Future<Output = Result<Vec<Policy>, StoreError>> + Send {
        std::future::ready(FileStore::list_policies(self))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kdc::kdb::master_key_from_password;

    fn temp(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("krb5rs_file_{}_{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        dir.join("principal")
    }

    fn user(name: &str) -> PrincipalEntry {
        PrincipalEntry {
            name: PrincipalName::new_principal(name),
            realm: "R".into(),
            attributes: PrincipalAttributes::empty(),
            max_life: None,
            max_renewable_life: None,
            expiration: None,
            pw_expiration: None,
            keys: random_keys(1, &[18]).expect("keys"),
            allowed_to_delegate_to: Vec::new(),
            allowed_to_delegate_from: Vec::new(),
            policy: None,
            security_epoch: 0,
            last_admin_unlock: None,
        }
    }

    #[test]
    fn writes_reread_the_master_key_list_another_store_changed() {
        use crate::kdc::kdb::mit::mkey::{
            add_new_mkey, entry_mkvno, lookup_actkvno, now, update_actkvno, use_mkey,
        };
        let path = temp("stale_masters");
        let master = master_key_from_password("R", "master", 18).expect("master");
        let a = FileStore::create(&path, "R", &master).expect("create");
        let b = FileStore::open(&path, &master).expect("open");
        a.create_record(user("alice"), None).expect("alice");
        let km = master_principal().expect("K/M");
        let second = master_key_from_password("R", "second", 18).expect("second");
        b.update_raw(&km, "R", |e, keys| {
            add_new_mkey(e, keys, &second)?;
            Ok(true)
        })
        .expect("add_mkey");
        b.update_raw(&km, "R", |e, _| {
            let mut list = lookup_actkvno(e)?;
            use_mkey(&mut list, 2, 0, now())?;
            update_actkvno(e, &list);
            Ok(true)
        })
        .expect("use_mkey");

        a.create_record(user("carol"), None).expect("carol");
        a.update_record(&PrincipalName::new_principal("alice"), "R", |r| {
            r.entry.keys = random_keys(2, &[18]).expect("keys");
            Ok(())
        })
        .expect("rekey alice");
        let mkvno = |n: &str| {
            b.raw_entries()
                .expect("entries")
                .into_iter()
                .find(|e| e.principal == PrincipalName::new_principal(n))
                .map(|e| entry_mkvno(&e).expect("mkvno"))
        };
        assert_eq!(mkvno("carol"), Some(2));
        assert_eq!(mkvno("alice"), Some(2));
    }

    #[test]
    fn mit_dump_loads_into_and_dumps_from_the_file_store() {
        use crate::kdc::kdb::mit::dump::{read_dump, write_dump, DumpVersion, Record};
        let data = std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/mit-dump/v7.dump"
        ))
        .expect("fixture");
        let (_, records, _) = read_dump(&data, "v7", None).expect("parse");
        let (mut entries, mut policies) = (Vec::new(), Vec::new());
        for record in records {
            match record {
                Record::Principal(entry) => entries.push(entry),
                Record::Policy(policy) => policies.push(policy),
            }
        }
        let names = |entries: &[MitEntry]| {
            entries
                .iter()
                .map(|e| unparse_name(&e.principal, &e.realm))
                .collect::<Vec<_>>()
        };
        let realm = "DUMP.TEST";
        let master = master_key_from_password(realm, "master-password-for-dump-fixtures", 18)
            .expect("master");
        let path = temp("dump");
        assert!(FileStore::load_dump(&path, realm, &master, &entries, &policies, true).is_err());
        FileStore::load_dump(&path, realm, &master, &entries, &policies, false).expect("load");
        assert!(!path.with_file_name("principal~").exists());

        let store = FileStore::open(&path, &master).expect("open");
        assert!(store
            .get_record(&PrincipalName::new_principal("alice"), realm)
            .expect("alice")
            .is_some());
        let (dumped, dumped_policies) = store.dump_entries().expect("dump");
        assert_eq!(names(&dumped), names(&entries));
        for (ours, theirs) in dumped.iter().zip(&entries) {
            assert_eq!(ours.key_data.len(), theirs.key_data.len());
            assert_eq!(ours.attributes, theirs.attributes);
        }
        let policy_names = |p: &[MitPolicy]| p.iter().map(|p| p.name.clone()).collect::<Vec<_>>();
        assert_eq!(policy_names(&dumped_policies), policy_names(&policies));
        let text = write_dump(DumpVersion::R111, &dumped, &dumped_policies);
        let (_, reread, _) = read_dump(&text, "ours", None).expect("reread");
        assert_eq!(reread.len(), entries.len() + policies.len());

        drop(store);
        FileStore::load_dump(&path, realm, &master, &entries[1..2], &[], true).expect("update");
        let (after_update, after_update_policies) = FileStore::open(&path, &master)
            .expect("open")
            .dump_entries()
            .expect("dump");
        assert_eq!(after_update.len(), entries.len());
        assert_eq!(after_update_policies.len(), policies.len());
        FileStore::load_dump(&path, realm, &master, &entries[..2], &[], false).expect("replace");
        let (replaced, replaced_policies) = FileStore::open(&path, &master)
            .expect("open")
            .dump_entries()
            .expect("dump");
        assert_eq!(names(&replaced), names(&entries[..2]));
        assert!(replaced_policies.is_empty());
    }

    #[test]
    fn serial_starts_at_one_and_increments_on_every_write() {
        let path = temp("serial");
        let master = master_key_from_password("R", "m", 18).expect("master");
        let store = FileStore::create(&path, "R", &master).expect("create");
        assert_eq!(store.serial(), 1);
        store.put(user("a")).expect("put");
        assert_eq!(store.serial(), 2);
        store
            .delete(&PrincipalName::new_principal("a"), "R")
            .expect("delete");
        assert_eq!(store.serial(), 3);
        let (serial, bytes) = store.snapshot().expect("snapshot");
        assert_eq!(serial, 3);
        assert_eq!(bytes, std::fs::read(&path).expect("read"));
        assert_eq!(FileStore::open(&path, &master).expect("open").serial(), 3);
        assert_eq!(
            FileStore::verify_image(&path, "R", &master).expect("verify"),
            3
        );
        assert!(FileStore::verify_image(&path, "OTHER", &master).is_err());
        let wrong = master_key_from_password("R", "wrong", 18).expect("key");
        assert!(FileStore::verify_image(&path, "R", &wrong).is_err());
    }

    #[test]
    fn a_file_without_a_serial_loads_as_zero_and_gets_one_on_the_next_write() {
        let path = temp("legacy");
        let master = master_key_from_password("R", "m", 18).expect("master");
        drop(FileStore::create(&path, "R", &master).expect("create"));
        let (_, mut file) = read_file(&path).expect("read");
        file.serial = None;
        write_atomic(&path, &file).expect("rewrite without serial");

        let store = FileStore::open(&path, &master).expect("old file opens");
        assert_eq!(store.serial(), 0);
        store.put(user("a")).expect("put");
        assert_eq!(store.serial(), 1);
        assert!(store
            .get_record(&PrincipalName::new_principal("a"), "R")
            .expect("record")
            .is_some());
    }

    #[test]
    fn a_truncated_image_is_corrupt() {
        let path = temp("truncated");
        let master = master_key_from_password("R", "m", 18).expect("master");
        let mut bytes = MAGIC.to_vec();
        bytes.extend([0x30, 0x82, 0x01]);
        std::fs::write(&path, bytes).expect("write truncated image");

        let error = match FileStore::open(&path, &master) {
            Ok(_) => panic!("truncated database unexpectedly opened"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), StoreErrorKind::Corrupt);
    }

    #[test]
    fn an_incorrect_master_key_is_a_backend_error() {
        let path = temp("wrong-master");
        let master = master_key_from_password("R", "m", 18).expect("master");
        drop(FileStore::create(&path, "R", &master).expect("create"));
        let wrong = master_key_from_password("R", "wrong", 18).expect("wrong key");

        let error = match FileStore::open(&path, &wrong) {
            Ok(_) => panic!("database opened with wrong master key"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), StoreErrorKind::Backend);
        assert!(error.message().contains("incorrect master key"));
    }
}
