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
use std::time::{Duration, SystemTime};

use chrono::Utc;
use rasn::types::{GeneralString, OctetString};

use super::format::{KdbFile, KdbKey, KdbPolicy, KdbPrincipal, MAGIC, VERSION};
use super::master::{decrypt_key, encrypt_key, master_principal};
use crate::kdc::db::{
    random_keys, store_key, KeyEntry, PrincipalAttributes, PrincipalEntry, StoreKey,
};
use crate::kdc::policy::kerberos_time;
use crate::kdc::store::{
    AdminStore, HealthCheck, Policy, PolicyStore, PrincipalStore, StoreError, StoreErrorKind,
};
use crate::types::{EncryptionKey, KerberosTime, PrincipalName};

fn err(msg: impl Into<String>) -> StoreError {
    StoreError::backend(msg)
}

fn policy_from_record(p: &KdbPolicy) -> Policy {
    Policy {
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
    }
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

/// A database record: the principal plus bookkeeping the KDC does not use.
#[derive(Debug, Clone)]
pub struct PrincipalRecord {
    /// The principal as the KDC sees it (keys decrypted).
    pub entry: PrincipalEntry,
    /// Last password change.
    pub last_pwd_change: Option<KerberosTime>,
    /// Last modification.
    pub mod_time: Option<KerberosTime>,
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
        .ok_or_else(|| err("not a krb5-rs database (bad magic)"))?;
    let file: KdbFile =
        rasn::der::decode(body).map_err(|e| err(format!("corrupt database: {e}")))?;
    if file.version != VERSION {
        return Err(err(format!(
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

fn to_time(t: &Option<KerberosTime>) -> Option<KerberosTime> {
    *t
}

impl FileStore {
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
            store.to_record(&km, Some(now), Some(now))?,
            store.to_record(&tgs, Some(now), Some(now))?,
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

    /// Open an existing database, verifying the master key against the
    /// stored `K/M` key.
    pub fn open(path: &Path, master: &EncryptionKey) -> Result<Self, StoreError> {
        let (_, file) = read_file(path)?;
        let realm = String::from_utf8_lossy(file.realm.as_bytes()).to_string();
        let store = Self {
            path: path.to_path_buf(),
            realm,
            master: master.clone(),
            cache: RwLock::new(Cache::default()),
        };
        store.refresh(true)?;
        let km = store
            .get_record(&master_principal()?, &store.realm)?
            .ok_or_else(|| err("database has no K/M principal"))?;
        let stored = km.entry.keys.first().ok_or_else(|| err("K/M has no key"))?;
        if stored.key.key_bytes() != master.key_bytes() || stored.key.keytype != master.keytype {
            return Err(err("incorrect master key"));
        }
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

    fn to_record(
        &self,
        e: &PrincipalEntry,
        last_pwd_change: Option<KerberosTime>,
        mod_time: Option<KerberosTime>,
    ) -> Result<KdbPrincipal, StoreError> {
        let secs = |d: Option<Duration>| d.map(|d| d.as_secs());
        let mut keys = Vec::with_capacity(e.keys.len());
        for k in &e.keys {
            keys.push(KdbKey {
                kvno: k.kvno,
                enctype: k.key.keytype,
                mkvno: 1,
                enc_key: OctetString::from(encrypt_key(&self.master, &k.key)?),
                salt: k.salt.clone().map(OctetString::from),
                s2kparams: k.s2kparams.clone().map(OctetString::from),
            });
        }
        Ok(KdbPrincipal {
            name: e.name.clone(),
            realm: general(&e.realm)?,
            attributes: e.attributes.bits(),
            max_life: secs(e.max_life),
            max_renewable_life: secs(e.max_renewable_life),
            expiration: to_time(&e.expiration),
            pw_expiration: to_time(&e.pw_expiration),
            last_pwd_change,
            mod_time,
            keys,
            allowed_to_delegate_to: general_list(&e.allowed_to_delegate_to)?,
            allowed_to_delegate_from: general_list(&e.allowed_to_delegate_from)?,
            policy: e.policy.as_deref().map(general).transpose()?,
            security_epoch: (e.security_epoch != 0).then_some(e.security_epoch),
            last_admin_unlock: e.last_admin_unlock,
        })
    }

    fn decrypt_record(&self, r: &KdbPrincipal) -> Result<PrincipalRecord, StoreError> {
        let mut keys = Vec::with_capacity(r.keys.len());
        for k in &r.keys {
            keys.push(KeyEntry {
                kvno: k.kvno,
                key: decrypt_key(&self.master, k.enctype, k.enc_key.as_ref())?,
                salt: k.salt.as_ref().map(|s| s.to_vec()),
                s2kparams: k.s2kparams.as_ref().map(|s| s.to_vec()),
            });
        }
        Ok(PrincipalRecord {
            entry: PrincipalEntry {
                name: r.name.clone(),
                realm: String::from_utf8_lossy(r.realm.as_bytes()).to_string(),
                attributes: PrincipalAttributes::from_bits_retain(r.attributes),
                max_life: r.max_life.map(Duration::from_secs),
                max_renewable_life: r.max_renewable_life.map(Duration::from_secs),
                expiration: to_time(&r.expiration),
                pw_expiration: to_time(&r.pw_expiration),
                keys,
                allowed_to_delegate_to: string_list(&r.allowed_to_delegate_to),
                allowed_to_delegate_from: string_list(&r.allowed_to_delegate_from),
                policy: r
                    .policy
                    .as_ref()
                    .map(|g| String::from_utf8_lossy(g.as_bytes()).to_string()),
                security_epoch: r.security_epoch.unwrap_or(0),
                last_admin_unlock: r.last_admin_unlock,
            },
            last_pwd_change: to_time(&r.last_pwd_change),
            mod_time: to_time(&r.mod_time),
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
                let policy = policy_from_record(p);
                (policy.name.clone(), policy)
            })
            .collect();
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
        let record = self.to_record(
            &entry,
            last_pwd_change,
            Some(kerberos_time(Utc::now().timestamp())),
        )?;
        let key = store_key(&entry.name, &entry.realm);
        self.modify(|list| {
            list.retain(|p| {
                let realm = String::from_utf8_lossy(p.realm.as_bytes()).to_string();
                store_key(&p.name, &realm) != key
            });
            list.push(record);
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
    fn get_principal(
        &self,
        name: &PrincipalName,
        realm: &str,
    ) -> impl std::future::Future<Output = Result<Option<PrincipalEntry>, StoreError>> + Send {
        std::future::ready(self.get_record(name, realm).map(|r| r.map(|r| r.entry)))
    }

    fn put_principal(
        &self,
        entry: PrincipalEntry,
    ) -> impl std::future::Future<Output = Result<(), StoreError>> + Send {
        std::future::ready(self.put(entry))
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
    ) -> impl std::future::Future<Output = Result<Vec<PrincipalEntry>, StoreError>> + Send {
        std::future::ready(self.list())
    }

    fn get_policy(
        &self,
        name: &str,
    ) -> impl std::future::Future<Output = Result<Option<Policy>, StoreError>> + Send {
        std::future::ready(FileStore::get_policy(self, name))
    }

    fn put_policy(
        &self,
        policy: Policy,
    ) -> impl std::future::Future<Output = Result<(), StoreError>> + Send {
        std::future::ready(FileStore::put_policy(self, policy))
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
}
