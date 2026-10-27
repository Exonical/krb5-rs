//! Replication domain types and the replica sink interface
//! (docs/architecture/kdb.md §5). The engine and the authoritative source
//! belong to later PRs; a local replica database implements [`ReplicaSink`].
//!
//! Replicated data never carries plaintext keys: [`StoredKey`] holds the MIT
//! `encrypt_key.c` layout (see [`crate::kdc::kdb::master::encrypt_key`]), which
//! needs the master key to open.

use std::cmp::Ordering;
use std::fmt;
use std::future::Future;
use std::str::FromStr;
use std::time::Duration;

use chrono::{DateTime, TimeZone, Utc};

use super::db::{KeyEntry, PrincipalAttributes, PrincipalEntry};
use super::kdb::master::{decrypt_key, encrypt_key};
use super::kdb::mit::mkey::{entry_mkvno, MasterKeys};
use super::kdb::mit::{
    merge_record, record_without_keys, CONSTRAINED_DELEGATION_ACL, LAST_ADMIN_UNLOCK,
    LAST_PWD_CHANGE,
};
use super::kdb::mit::{KeyData, MitEntry, TlData, ACTKVNO, MKEY_AUX, MKVNO, MOD_PRINC};
use super::policy::{kerberos_time, ts};
use super::store::{Policy, PrincipalRecord, StoreError};
use crate::types::{EncryptionKey, PrincipalName};

/// A CockroachDB hybrid logical clock timestamp, the decimal
/// `wall_nanos.logical` of `cluster_logical_timestamp()` (the logical part is
/// ten digits). Totally ordered by (wall, logical).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ReplicationTs {
    /// Wall clock, nanoseconds since the Unix epoch.
    pub wall_nanos: i64,
    /// Logical counter within the same wall time.
    pub logical: u32,
}

impl ReplicationTs {
    /// The smallest timestamp: "before everything".
    pub const ZERO: ReplicationTs = ReplicationTs {
        wall_nanos: 0,
        logical: 0,
    };

    /// A timestamp from its parts.
    pub fn new(wall_nanos: i64, logical: u32) -> Self {
        Self {
            wall_nanos,
            logical,
        }
    }

    /// The wall-clock time.
    pub fn wall_time(&self) -> DateTime<Utc> {
        Utc.timestamp_nanos(self.wall_nanos)
    }
}

impl PartialOrd for ReplicationTs {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ReplicationTs {
    fn cmp(&self, other: &Self) -> Ordering {
        (self.wall_nanos, self.logical).cmp(&(other.wall_nanos, other.logical))
    }
}

impl fmt::Display for ReplicationTs {
    /// `wall.logical` with a ten-digit logical part, CockroachDB's format.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{:010}", self.wall_nanos, self.logical)
    }
}

/// Why a [`ReplicationTs`] string did not parse.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid replication timestamp {0:?}")]
pub struct ParseTsError(pub String);

impl FromStr for ReplicationTs {
    type Err = ParseTsError;

    /// Parses `wall` or `wall.logical`; the logical part is a decimal
    /// fraction of at most ten digits (so `1.5` is logical 5000000000).
    fn from_str(s: &str) -> Result<Self, ParseTsError> {
        let bad = || ParseTsError(s.to_string());
        let (wall, logical) = match s.split_once('.') {
            Some((w, l)) => (w, l),
            None => (s, ""),
        };
        let wall_nanos: i64 = wall.parse().map_err(|_| bad())?;
        if logical.len() > 10 || !logical.bytes().all(|b| b.is_ascii_digit()) {
            return Err(bad());
        }
        let padded = format!("{logical:0<10}");
        let logical: u64 = padded.parse().map_err(|_| bad())?;
        Ok(Self {
            wall_nanos,
            logical: u32::try_from(logical).map_err(|_| bad())?,
        })
    }
}

/// One long-term key in its at-rest form (MIT `krb5_key_data`): encrypted
/// under the master key, never plaintext.
#[derive(Clone, PartialEq, Eq)]
pub struct StoredKey {
    /// Key version number.
    pub kvno: u32,
    /// Enctype of the (decrypted) key.
    pub enctype: i32,
    /// Master key version that encrypted it.
    pub mkvno: u32,
    /// `encrypt_key.c` layout: 2-byte LE key length plus the encrypted key.
    pub enc_key: Vec<u8>,
    /// Explicit salt.
    pub salt: Option<Vec<u8>>,
    /// String-to-key parameters.
    pub s2kparams: Option<Vec<u8>>,
}

impl fmt::Debug for StoredKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StoredKey")
            .field("kvno", &self.kvno)
            .field("enctype", &self.enctype)
            .field("mkvno", &self.mkvno)
            .field("enc_key", &format_args!("<{} bytes>", self.enc_key.len()))
            .finish_non_exhaustive()
    }
}

/// A principal as stored and replicated: [`PrincipalEntry`] with encrypted
/// keys and unix-second times.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredPrincipal {
    /// Principal name.
    pub name: PrincipalName,
    /// Realm.
    pub realm: String,
    /// `PrincipalAttributes` bits.
    pub attributes: u32,
    /// Maximum ticket life, seconds.
    pub max_life: Option<u64>,
    /// Maximum renewable life, seconds.
    pub max_renewable_life: Option<u64>,
    /// Principal expiration, unix seconds.
    pub expiration: Option<i64>,
    /// Password expiration, unix seconds.
    pub pw_expiration: Option<i64>,
    /// Last password change, unix seconds.
    pub last_pwd_change: Option<i64>,
    /// Last modification, unix seconds.
    pub mod_time: Option<i64>,
    /// Encrypted keys, newest kvno first.
    pub keys: Vec<StoredKey>,
    /// Traditional S4U2Proxy targets.
    pub allowed_to_delegate_to: Vec<String>,
    /// RBCD delegators.
    pub allowed_to_delegate_from: Vec<String>,
    /// Policy name.
    pub policy: Option<String>,
    /// Security epoch.
    pub security_epoch: u64,
    /// Last administrative unlock, unix seconds.
    pub last_admin_unlock: Option<i64>,
    /// MIT tl-data the model has no field for: `K/M`'s `KRB5_TL_ACTKVNO`
    /// and `KRB5_TL_MKEY_AUX`.
    pub tl_data: Vec<TlData>,
}

fn same_keys(a: &[KeyEntry], b: &[KeyEntry]) -> bool {
    a.len() == b.len()
        && a.iter().zip(b).all(|(a, b)| {
            a.kvno == b.kvno
                && a.key.keytype == b.key.keytype
                && a.key.key_bytes() == b.key.key_bytes()
                && a.salt == b.salt
                && a.s2kparams == b.s2kparams
        })
}

fn mit_u32(v: Option<i64>) -> u32 {
    v.and_then(|v| u32::try_from(v).ok()).unwrap_or(0)
}

/// MIT `put_tl_data` layout for tl-data in a database column (as
/// `Policy::tl_data_bytes`); `None` when empty.
pub fn encode_tl_data(tl: &[TlData]) -> Result<Option<Vec<u8>>, StoreError> {
    if tl.is_empty() {
        return Ok(None);
    }
    let too_big = |_| StoreError::rejected("principal tl-data too large");
    let mut out = u16::try_from(tl.len())
        .map_err(too_big)?
        .to_le_bytes()
        .to_vec();
    for t in tl {
        out.extend_from_slice(&t.kind.to_le_bytes());
        out.extend_from_slice(&u16::try_from(t.data.len()).map_err(too_big)?.to_le_bytes());
        out.extend_from_slice(&t.data);
    }
    Ok(Some(out))
}

/// Inverse of [`encode_tl_data`].
pub fn decode_tl_data(b: Option<&[u8]>) -> Result<Vec<TlData>, StoreError> {
    let b = b.unwrap_or_default();
    if b.is_empty() {
        return Ok(Vec::new());
    }
    let bad = || StoreError::corrupt("truncated principal tl-data");
    let u16_at = |at: usize| {
        b.get(at..at + 2)
            .map(|x| u16::from_le_bytes([x[0], x[1]]))
            .ok_or_else(bad)
    };
    let count = u16_at(0)?;
    let mut at = 2;
    let mut out = Vec::with_capacity(usize::from(count));
    for _ in 0..count {
        let (kind, len) = (u16_at(at)?, usize::from(u16_at(at + 2)?));
        let data = b.get(at + 4..at + 4 + len).ok_or_else(bad)?.to_vec();
        out.push(TlData { kind, data });
        at += 4 + len;
    }
    if at != b.len() {
        return Err(bad());
    }
    Ok(out)
}

impl StoredPrincipal {
    /// Encrypt `entry`'s keys under the active master key and record its
    /// version, as `krb5_dbe_encrypt_key_data` with `krb5_dbe_find_act_mkey`.
    pub fn from_entry(
        entry: &PrincipalEntry,
        last_pwd_change: Option<i64>,
        mod_time: Option<i64>,
        keys: &MasterKeys,
    ) -> Result<Self, StoreError> {
        let (mkvno, master) = keys.active()?;
        let mut stored = Vec::with_capacity(entry.keys.len());
        for k in &entry.keys {
            stored.push(StoredKey {
                kvno: k.kvno,
                enctype: k.key.keytype,
                mkvno: u32::from(mkvno),
                enc_key: encrypt_key(master, &k.key)?,
                salt: k.salt.clone(),
                s2kparams: k.s2kparams.clone(),
            });
        }
        Ok(Self::with_keys(entry, last_pwd_change, mod_time, stored))
    }

    /// [`StoredPrincipal::from_entry`] for a rewrite of `previous`: when the
    /// keys are unchanged their stored form (and master key version) is
    /// kept, as `krb5_db_put_principal` keeps untouched `key_data`; tl-data
    /// is carried over.
    pub fn from_update(
        entry: &PrincipalEntry,
        last_pwd_change: Option<i64>,
        mod_time: Option<i64>,
        keys: &MasterKeys,
        previous: &StoredPrincipal,
    ) -> Result<Self, StoreError> {
        let mut sp = match previous.clone().into_entry(keys) {
            Ok(old) if same_keys(&old.keys, &entry.keys) => {
                Self::with_keys(entry, last_pwd_change, mod_time, previous.keys.clone())
            }
            _ => Self::from_entry(entry, last_pwd_change, mod_time, keys)?,
        };
        sp.tl_data = previous.tl_data.clone();
        Ok(sp)
    }

    fn with_keys(
        entry: &PrincipalEntry,
        last_pwd_change: Option<i64>,
        mod_time: Option<i64>,
        keys: Vec<StoredKey>,
    ) -> Self {
        Self {
            name: entry.name.clone(),
            realm: entry.realm.clone(),
            attributes: entry.attributes.bits(),
            max_life: entry.max_life.map(|d| d.as_secs()),
            max_renewable_life: entry.max_renewable_life.map(|d| d.as_secs()),
            expiration: entry.expiration.as_ref().map(ts),
            pw_expiration: entry.pw_expiration.as_ref().map(ts),
            last_pwd_change,
            mod_time,
            keys,
            allowed_to_delegate_to: entry.allowed_to_delegate_to.clone(),
            allowed_to_delegate_from: entry.allowed_to_delegate_from.clone(),
            policy: entry.policy.clone(),
            security_epoch: entry.security_epoch,
            last_admin_unlock: entry.last_admin_unlock.as_ref().map(ts),
            tl_data: Vec::new(),
        }
    }

    /// Decrypt each key with the master key version it records; a missing
    /// master key, a wrong one or a damaged blob is an error.
    pub fn into_entry(self, masters: &MasterKeys) -> Result<PrincipalEntry, StoreError> {
        let mut keys = Vec::with_capacity(self.keys.len());
        for k in self.keys {
            let master = u16::try_from(k.mkvno)
                .ok()
                .and_then(|v| masters.get(v))
                .ok_or_else(|| {
                    StoreError::backend(format!(
                        "No matching key in entry (master key version {})",
                        k.mkvno
                    ))
                })?;
            keys.push(KeyEntry {
                kvno: k.kvno,
                key: decrypt_key(master, k.enctype, &k.enc_key)?,
                salt: k.salt,
                s2kparams: k.s2kparams,
            });
        }
        Ok(PrincipalEntry {
            name: self.name,
            realm: self.realm,
            attributes: PrincipalAttributes::from_bits_retain(self.attributes),
            max_life: self.max_life.map(Duration::from_secs),
            max_renewable_life: self.max_renewable_life.map(Duration::from_secs),
            expiration: self.expiration.map(kerberos_time),
            pw_expiration: self.pw_expiration.map(kerberos_time),
            keys,
            allowed_to_delegate_to: self.allowed_to_delegate_to,
            allowed_to_delegate_from: self.allowed_to_delegate_from,
            policy: self.policy,
            security_epoch: self.security_epoch,
            last_admin_unlock: self.last_admin_unlock.map(kerberos_time),
        })
    }

    /// The MIT entry the master-key commands work on: keys stay encrypted,
    /// with the stored master key version as `KRB5_TL_MKVNO`.
    pub fn to_raw(&self) -> Result<MitEntry, StoreError> {
        let mut tl_data = self.tl_data.clone();
        if let Some(mkvno) = self.keys.first().map(|k| k.mkvno).filter(|v| *v != 1) {
            let mkvno = u16::try_from(mkvno)
                .map_err(|_| StoreError::corrupt("master key version out of range"))?;
            tl_data.push(TlData {
                kind: MKVNO,
                data: mkvno.to_le_bytes().to_vec(),
            });
        }
        let key_data = self
            .keys
            .iter()
            .map(|k| {
                Ok(KeyData {
                    ver: 1,
                    kvno: u16::try_from(k.kvno)
                        .map_err(|_| StoreError::corrupt("kvno exceeds MIT's 16 bits"))?,
                    fields: vec![(
                        i16::try_from(k.enctype)
                            .map_err(|_| StoreError::corrupt("enctype exceeds i16"))?,
                        k.enc_key.clone(),
                    )],
                })
            })
            .collect::<Result<_, StoreError>>()?;
        Ok(MitEntry {
            principal: self.name.clone(),
            realm: self.realm.clone(),
            attributes: self.attributes,
            max_life: self
                .max_life
                .and_then(|v| u32::try_from(v).ok())
                .unwrap_or(0),
            max_renewable_life: self
                .max_renewable_life
                .and_then(|v| u32::try_from(v).ok())
                .unwrap_or(0),
            expiration: mit_u32(self.expiration),
            pw_expiration: mit_u32(self.pw_expiration),
            last_success: 0,
            last_failed: 0,
            fail_auth_count: 0,
            tl_data,
            key_data,
        })
    }

    /// Take back the keys, master key version, `KRB5_TL_ACTKVNO`,
    /// `KRB5_TL_MKEY_AUX` and `KRB5_TL_MOD_PRINC` time of an entry from
    /// [`StoredPrincipal::to_raw`] after a master-key command changed it.
    /// A key keeps its salt when its kvno and enctype are unchanged.
    pub fn apply_raw(&mut self, raw: &MitEntry) -> Result<(), StoreError> {
        let mkvno = u32::from(entry_mkvno(raw)?);
        let mut keys = Vec::with_capacity(raw.key_data.len());
        for data in &raw.key_data {
            let (etype, blob) = data
                .fields
                .first()
                .ok_or_else(|| StoreError::corrupt("key-data record has no key field"))?;
            let (kvno, enctype) = (u32::from(data.kvno), i32::from(*etype));
            let old = self
                .keys
                .iter()
                .find(|k| k.kvno == kvno && k.enctype == enctype);
            keys.push(StoredKey {
                kvno,
                enctype,
                mkvno,
                enc_key: blob.clone(),
                salt: old.and_then(|k| k.salt.clone()),
                s2kparams: old.and_then(|k| k.s2kparams.clone()),
            });
        }
        self.keys = keys;
        self.tl_data = raw
            .tl_data
            .iter()
            .filter(|t| matches!(t.kind, ACTKVNO | MKEY_AUX))
            .cloned()
            .collect();
        if let Some(t) = raw.tl_data.iter().find(|t| t.kind == MOD_PRINC) {
            if let Some(bytes) = t.data.get(..4) {
                let secs = u32::from_le_bytes(bytes.try_into().expect("4 bytes"));
                self.mod_time = Some(i64::from(secs));
            }
        }
        Ok(())
    }

    /// The full MIT entry (keys still encrypted): [`Self::to_raw`] with the
    /// stored fields kept as their MIT tl-data (`LAST_PWD_CHANGE`,
    /// `KADM_DATA`, delegation ACLs and attributes), as remote kadmin reads it.
    /// `keys` is only consulted for the active master key version; the
    /// stored keys are not decrypted.
    pub fn to_mit(&self, keys: &MasterKeys) -> Result<MitEntry, StoreError> {
        let mut raw = self.to_raw()?;
        let key_data = std::mem::take(&mut raw.key_data);
        let has_mod_princ = raw.tl_data.iter().any(|t| t.kind == MOD_PRINC);
        let keyless = StoredPrincipal {
            keys: Vec::new(),
            ..self.clone()
        };
        let record = PrincipalRecord {
            entry: keyless.into_entry(keys)?,
            last_pwd_change: self.last_pwd_change.map(kerberos_time),
            mod_time: self.mod_time.filter(|_| has_mod_princ).map(kerberos_time),
            mod_by: None,
            password_history: None,
        };
        merge_record(&mut raw, &record, keys, None)?;
        raw.key_data = key_data;
        Ok(raw)
    }

    /// The inverse of [`Self::to_mit`]: the stored fields from the entry's
    /// tl-data, its encrypted keys unchanged, and every other tl-data kept.
    /// `previous` supplies what MIT entries do not carry (security epoch).
    pub fn from_mit(
        raw: &MitEntry,
        previous: Option<&StoredPrincipal>,
    ) -> Result<Self, StoreError> {
        let mut record = record_without_keys(raw)?;
        if let Some(p) = previous {
            record.entry.security_epoch = p.security_epoch;
        }
        let mut sp = Self::with_keys(
            &record.entry,
            record.last_pwd_change.as_ref().map(ts),
            record.mod_time.as_ref().map(ts),
            Vec::new(),
        );
        sp.apply_raw(raw)?;
        sp.mod_time = record.mod_time.as_ref().map(ts);
        sp.tl_data = raw
            .tl_data
            .iter()
            .filter(|t| {
                !matches!(
                    t.kind,
                    LAST_PWD_CHANGE | LAST_ADMIN_UNLOCK | CONSTRAINED_DELEGATION_ACL | MKVNO
                )
            })
            .cloned()
            .collect();
        Ok(sp)
    }

    /// `krb5_db_fetch_mkey_list` for a stored `K/M`: `supplied` opens the
    /// newest master key, directly or through `KRB5_TL_MKEY_AUX`.
    pub fn master_keys(&self, supplied: &EncryptionKey) -> Result<MasterKeys, StoreError> {
        MasterKeys::fetch(&self.to_raw()?, supplied)
    }
}

/// A policy as stored and replicated (the same fields as [`Policy`]).
pub type StoredPolicy = Policy;

/// A lockout replicated from the authority (docs/architecture §8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockoutRecord {
    /// Realm of the locked principal.
    pub realm: String,
    /// The locked principal.
    pub name: PrincipalName,
    /// When the lockout tripped, unix seconds.
    pub locked_at: i64,
    /// When it ends, unix seconds; `None` = until an administrator unlocks.
    pub unlock_at: Option<i64>,
    /// The KDC that reported it.
    pub source_kdc: String,
}

/// One replicated change, with the authoritative version (commit timestamp)
/// of the entity after it. A delete carries the version of the deletion, which
/// the replica keeps as a tombstone so an older re-create cannot resurrect it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Change {
    /// Insert or replace a principal.
    UpsertPrincipal {
        /// The principal.
        principal: StoredPrincipal,
        /// Version of this state.
        version: ReplicationTs,
    },
    /// Delete a principal.
    DeletePrincipal {
        /// Realm.
        realm: String,
        /// Name.
        name: PrincipalName,
        /// Version of the deletion.
        version: ReplicationTs,
    },
    /// Insert or replace a policy.
    UpsertPolicy {
        /// The policy.
        policy: StoredPolicy,
        /// Version of this state.
        version: ReplicationTs,
    },
    /// Delete a policy.
    DeletePolicy {
        /// Policy name.
        name: String,
        /// Version of the deletion.
        version: ReplicationTs,
    },
    /// Insert or replace a lockout.
    UpsertLockout {
        /// The lockout.
        record: LockoutRecord,
        /// Version of this state.
        version: ReplicationTs,
    },
    /// Delete (lift) a lockout.
    DeleteLockout {
        /// Realm.
        realm: String,
        /// Name.
        name: PrincipalName,
        /// Version of the deletion.
        version: ReplicationTs,
    },
}

impl Change {
    /// The version carried by the change.
    pub fn version(&self) -> ReplicationTs {
        match self {
            Change::UpsertPrincipal { version, .. }
            | Change::DeletePrincipal { version, .. }
            | Change::UpsertPolicy { version, .. }
            | Change::DeletePolicy { version, .. }
            | Change::UpsertLockout { version, .. }
            | Change::DeleteLockout { version, .. } => *version,
        }
    }
}

/// The changes up to and including `upto`, applied together with moving the
/// replica's checkpoint to `upto`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChangeBatch {
    /// The read timestamp the batch is complete up to.
    pub upto: ReplicationTs,
    /// The changes.
    pub changes: Vec<Change>,
}

/// Where a replica stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReplicaCheckpoint {
    /// Everything up to this timestamp has been applied.
    pub ts: ReplicationTs,
    /// The snapshot the database was built from, if it was bootstrapped.
    pub snapshot_ts: Option<ReplicationTs>,
    /// When the checkpoint last advanced, unix seconds.
    pub applied_at: i64,
}

/// What [`ReplicaSink::apply`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ApplyOutcome {
    /// Changes that changed the replica.
    pub applied: usize,
    /// Changes ignored because the replica already held a newer (or equal)
    /// version.
    pub skipped_stale: usize,
}

/// Encode a principal name as one key string: components joined by `/`, with
/// `\` and `/` inside a component escaped (as in MIT's unparse). Replication
/// keys entities by this string; the name type travels separately and is
/// ignored when comparing, as in MIT.
pub fn encode_principal_key(name: &PrincipalName) -> Result<String, StoreError> {
    let mut out = String::new();
    for (i, comp) in name.name_string.iter().enumerate() {
        if i > 0 {
            out.push('/');
        }
        let s = std::str::from_utf8(comp.as_bytes())
            .map_err(|_| StoreError::conflict("principal name component is not UTF-8"))?;
        for c in s.chars() {
            if c == '\\' || c == '/' {
                out.push('\\');
            }
            out.push(c);
        }
    }
    Ok(out)
}

/// Inverse of [`encode_principal_key`].
pub fn decode_principal_key(key: &str, name_type: i32) -> Result<PrincipalName, StoreError> {
    let mut parts: Vec<String> = vec![String::new()];
    let mut chars = key.chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' => parts.last_mut().expect("one part exists").push(
                chars
                    .next()
                    .ok_or_else(|| StoreError::corrupt("dangling escape in a principal key"))?,
            ),
            '/' => parts.push(String::new()),
            c => parts.last_mut().expect("one part exists").push(c),
        }
    }
    let name_string = parts
        .into_iter()
        .map(|p| {
            rasn::types::GeneralString::try_from(p)
                .map_err(|_| StoreError::corrupt("principal key is not a GeneralString"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(PrincipalName {
        name_type,
        name_string,
    })
}

/// A consistent snapshot of the authoritative data at [`Snapshot::ts`], read
/// page by page so the engine can feed a [`RebuildWriter`] without holding
/// everything in memory.
pub trait Snapshot: Send {
    /// The timestamp the snapshot is read at: the checkpoint after loading it.
    fn ts(&self) -> ReplicationTs;

    /// The authority's clock (as an HLC wall time) when the snapshot's read
    /// timestamp was chosen, from the same read: `source_now() - ts()` is how
    /// far behind the present the snapshot is, independent of the KDC clock.
    fn source_now(&self) -> ReplicationTs;

    /// The next page of `Change` upserts, or `None` when the snapshot is
    /// exhausted. The versions are those of the stored rows.
    fn next_page(&mut self)
        -> impl Future<Output = Result<Option<Vec<Change>>, StoreError>> + Send;
}

/// One read of the authoritative log ([`ReplicationSource::poll`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PollResult {
    /// The changes and the timestamp they are complete up to.
    pub batch: ChangeBatch,
    /// The authority's clock (an HLC wall time) in the same read. `source_now
    /// - batch.upto` is the replication lag as the authority sees it; it never
    ///   compares the KDC's wall clock with an HLC timestamp.
    pub source_now: ReplicationTs,
    /// More changes are waiting: the batch stopped at the limit, so poll again
    /// at once.
    pub truncated: bool,
}

/// Where a replica reports its progress (CockroachDB `replica_status`).
pub trait ReplicaRegistry: Send + Sync {
    /// Record that `kdc_id` in `region` has applied everything up to
    /// `applied_ts`.
    fn heartbeat(
        &self,
        kdc_id: &str,
        region: &str,
        applied_ts: ReplicationTs,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;
}

/// The authoritative side of replication (docs §5): complete, ordered change
/// batches and a snapshot for bootstrap.
///
/// Correctness rests on reading at a fixed timestamp `T`: CockroachDB's
/// timestamp cache guarantees no write into a span read at `T` can later
/// commit at or below `T`, so the log rows in `(since, T]` are final once read.
pub trait ReplicationSource: Send + Sync {
    /// The snapshot type.
    type Snapshot: Snapshot;

    /// Start a snapshot at a fresh read timestamp.
    fn snapshot(&self) -> impl Future<Output = Result<Self::Snapshot, StoreError>> + Send;

    /// [`ReplicationSource::poll`] without the freshness details.
    fn changes_since(
        &self,
        since: ReplicationTs,
        limit: usize,
    ) -> impl Future<Output = Result<ChangeBatch, StoreError>> + Send {
        async move { Ok(self.poll(since, limit).await?.batch) }
    }

    /// The changes with commit timestamp in `(since, upto]`, in commit order,
    /// as the current state of each changed entity read at `upto` (absent
    /// means deleted: the change is a `Delete` carrying the log row's
    /// version). `upto` is the read timestamp, or, when more than `limit` log
    /// rows qualify, the last commit timestamp included. One commit timestamp
    /// is never split across batches, so a batch can exceed `limit`.
    fn poll(
        &self,
        since: ReplicationTs,
        limit: usize,
    ) -> impl Future<Output = Result<PollResult, StoreError>> + Send;

    /// The low watermark of retained log rows: a replica whose checkpoint is
    /// below it must rebuild from a snapshot. `None` if nothing was pruned.
    fn pruned_before(
        &self,
    ) -> impl Future<Output = Result<Option<ReplicationTs>, StoreError>> + Send;
}

#[cfg(feature = "tokio")]
mod engine;
#[cfg(feature = "tokio")]
pub use engine::{
    FreshnessGate, RebuildPolicy, ReplicaStatus, ReplicationConfig, ReplicationEngine,
    StatusSnapshot, StrictGate,
};

/// A replica database that applies replicated changes (docs §5).
pub trait ReplicaSink: Send + Sync {
    /// The writer returned by [`ReplicaSink::begin_rebuild`].
    type Rebuild: RebuildWriter;

    /// The checkpoint, or `None` for a replica that was never bootstrapped.
    fn checkpoint(
        &self,
    ) -> impl Future<Output = Result<Option<ReplicaCheckpoint>, StoreError>> + Send;

    /// Apply `batch` atomically together with moving the checkpoint to
    /// `batch.upto`: either all of it is visible or none. A change is applied
    /// only if its version is newer than the replica's.
    fn apply(
        &self,
        batch: ChangeBatch,
    ) -> impl Future<Output = Result<ApplyOutcome, StoreError>> + Send;

    /// Start a rebuild: write a complete snapshot taken at `snapshot_ts` into
    /// a new database; readers keep the current one until
    /// [`RebuildWriter::commit`].
    fn begin_rebuild(
        &self,
        snapshot_ts: ReplicationTs,
    ) -> impl Future<Output = Result<Self::Rebuild, StoreError>> + Send;
}

/// Writes a snapshot for [`ReplicaSink::begin_rebuild`].
pub trait RebuildWriter: Send {
    /// Add a chunk of the snapshot.
    fn write(
        &mut self,
        changes: Vec<Change>,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;

    /// Make the new database the current one atomically (the checkpoint
    /// becomes the snapshot timestamp).
    fn commit(self) -> impl Future<Output = Result<(), StoreError>> + Send;

    /// Discard the rebuild.
    fn abort(self) -> impl Future<Output = Result<(), StoreError>> + Send;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamps_round_trip_and_order_by_wall_then_logical() {
        let a: ReplicationTs = "1700000000000000000.0000000001".parse().expect("parse");
        assert_eq!(a, ReplicationTs::new(1_700_000_000_000_000_000, 1));
        assert_eq!(a.to_string(), "1700000000000000000.0000000001");
        let b = ReplicationTs::new(1_700_000_000_000_000_000, 2);
        let c = ReplicationTs::new(1_700_000_000_000_000_001, 0);
        assert!(a < b && b < c);
        assert_eq!(ReplicationTs::ZERO.to_string(), "0.0000000000");
        for ts in [a, b, c, ReplicationTs::new(5, 4_000_000_000)] {
            assert_eq!(ts.to_string().parse::<ReplicationTs>(), Ok(ts));
        }
    }

    #[test]
    fn timestamps_without_a_logical_part_or_with_a_short_fraction_parse() {
        assert_eq!("42".parse(), Ok(ReplicationTs::new(42, 0)));
        // A decimal fraction: .4 is four billion in ten digits; .5 would not fit the
        // 32-bit logical counter.
        assert_eq!("1.4".parse(), Ok(ReplicationTs::new(1, 4_000_000_000)));
        assert!("1.5".parse::<ReplicationTs>().is_err());
        for bad in ["", ".1", "x", "1.", "1.12345678901", "1.-1", "1.9999999999"] {
            if bad == "1." {
                assert_eq!(bad.parse(), Ok(ReplicationTs::new(1, 0)));
            } else {
                assert!(bad.parse::<ReplicationTs>().is_err(), "{bad}");
            }
        }
    }

    #[test]
    fn wall_time_is_the_nanosecond_clock() {
        let t = ReplicationTs::new(1_700_000_000_123_456_789, 0).wall_time();
        assert_eq!(t.timestamp(), 1_700_000_000);
        assert_eq!(t.timestamp_subsec_nanos(), 123_456_789);
    }

    #[test]
    fn stored_keys_debug_never_shows_key_bytes() {
        let k = StoredKey {
            kvno: 1,
            enctype: 18,
            mkvno: 1,
            enc_key: vec![0xAB; 40],
            salt: None,
            s2kparams: None,
        };
        let shown = format!("{k:?}");
        assert!(!shown.to_lowercase().contains("ab, ab") && !shown.contains("171"));
        assert!(shown.contains("40 bytes"));
    }

    #[test]
    fn principals_convert_to_the_stored_form_and_back_under_the_master_key() {
        let master = crate::kdc::kdb::master_key_from_password("R", "m", 18).expect("master");
        let wrong = crate::kdc::kdb::master_key_from_password("R", "w", 18).expect("wrong");
        let mut store = crate::kdc::MemoryStore::new();
        store
            .add_with_password(
                PrincipalName::new_principal("u"),
                "R",
                "pw",
                3,
                &[18, 17],
                PrincipalAttributes::REQUIRES_PRE_AUTH,
            )
            .expect("add");
        let mut entry = store
            .get(&PrincipalName::new_principal("u"), "R")
            .expect("entry");
        entry.policy = Some("p".into());
        entry.security_epoch = 7;
        let masters = MasterKeys::single(master.clone());
        let stored =
            StoredPrincipal::from_entry(&entry, Some(10), Some(20), &masters).expect("stored");
        assert_eq!(stored.keys.len(), 2);
        for (s, k) in stored.keys.iter().zip(&entry.keys) {
            assert_ne!(&s.enc_key[2..], k.key.key_bytes(), "keys are encrypted");
        }
        let back = stored.clone().into_entry(&masters).expect("decrypt");
        assert_eq!(back.keys[0].key.key_bytes(), entry.keys[0].key.key_bytes());
        assert_eq!(
            (back.policy.as_deref(), back.security_epoch),
            (Some("p"), 7)
        );
        assert!(stored
            .clone()
            .into_entry(&MasterKeys::single(wrong.clone()))
            .is_err());

        // A second master key, active now: new writes use it, unchanged
        // rewrites keep the old wrapping, and each key opens by its mkvno.
        let mut km = StoredPrincipal::from_entry(
            &PrincipalEntry {
                keys: vec![KeyEntry {
                    kvno: 1,
                    key: master.clone(),
                    salt: None,
                    s2kparams: None,
                }],
                ..entry.clone()
            },
            None,
            None,
            &masters,
        )
        .expect("K/M");
        let mut raw = km.to_raw().expect("raw");
        let kvno =
            crate::kdc::kdb::mit::mkey::add_new_mkey(&mut raw, &masters, &wrong).expect("add");
        km.apply_raw(&raw).expect("apply");
        assert_eq!((kvno, km.keys.len(), km.keys[0].mkvno), (2, 2, 2));
        let both = km.master_keys(&master).expect("old key opens via MKEY_AUX");
        assert_eq!(both.keys.len(), 2);
        let mut rotated = both.clone();
        rotated.actkvno = vec![crate::kdc::kdb::mit::mkey::ActKvno {
            kvno: 2,
            act_time: 0,
        }];
        let kept =
            StoredPrincipal::from_update(&entry, None, None, &rotated, &stored).expect("unchanged");
        assert_eq!(kept.keys, stored.keys);
        let mut changed = entry.clone();
        changed.keys.truncate(1);
        let fresh =
            StoredPrincipal::from_update(&changed, None, None, &rotated, &stored).expect("new");
        assert_eq!(fresh.keys[0].mkvno, 2);
        let back = fresh.into_entry(&both).expect("opens under kvno 2");
        assert_eq!(back.keys[0].key.key_bytes(), entry.keys[0].key.key_bytes());
        assert!(stored.into_entry(&rotated).is_ok());
    }
}
