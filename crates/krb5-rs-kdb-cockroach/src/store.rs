//! [`CockroachStore`]: the authoritative store.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use krb5_rs::kdc::kdb::master::decrypt_key;
use krb5_rs::kdc::replication::{
    decode_principal_key, encode_principal_key, Change, ChangeBatch, LockoutRecord, PollResult,
    ReplicaRegistry, ReplicationSource, ReplicationTs, Snapshot, StoredKey, StoredPrincipal,
};
use krb5_rs::kdc::{
    AdminStore, AuthoritativeState, HealthCheck, Policy, PrincipalAttributes, PrincipalEntry,
    PrincipalRecord, SecurityState, StoreError,
};
use krb5_rs::types::{EncryptionKey, KerberosTime, PrincipalName};
use tokio_postgres::Row;

use crate::config::{CockroachConfig, ReplicationRead};
use crate::db::{transaction_id, BoxFut, Db, Metrics, Params, Tx, TxError};
use crate::schema::{self, MigrateOptions, MigrateReport, SCHEMA_VERSION};
use crate::FailPoint;

pub(crate) fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

fn kt(secs: i64) -> KerberosTime {
    chrono::DateTime::from_timestamp(secs, 0)
        .unwrap_or_default()
        .fixed_offset()
}

fn conflict_exists(what: impl std::fmt::Display) -> StoreError {
    StoreError::conflict(format!("Principal or policy already exists: {what}"))
}

fn ts_of(s: &str) -> Result<ReplicationTs, StoreError> {
    s.parse::<ReplicationTs>()
        .map_err(|e| StoreError::corrupt(e.to_string()))
}

fn to_i64(n: u64) -> Result<i64, StoreError> {
    i64::try_from(n).map_err(|_| StoreError::conflict("value out of range"))
}

fn opt_u(n: Option<u64>) -> Result<Option<i64>, StoreError> {
    n.map(to_i64).transpose()
}

/// Extra bucket overlap for the closed-timestamp lead and maximum HLC skew
/// beyond the transaction's wall-clock duration.
const COMMIT_SKEW_MARGIN: Duration = Duration::from_secs(5);

/// Inclusive bucket range holding every log row with MVCC timestamp in
/// `(since, upto]`.
fn scan_buckets(
    since: ReplicationTs,
    upto: ReplicationTs,
    transaction_timeout_ms: i64,
    bucket_width_seconds: i64,
) -> (i64, i64) {
    let transaction_timeout_ns =
        i128::from(transaction_timeout_ms.max(0)).saturating_mul(1_000_000);
    let skew_margin_ns = i128::try_from(COMMIT_SKEW_MARGIN.as_nanos()).unwrap_or(i128::MAX);
    let overlap_ns =
        i64::try_from(transaction_timeout_ns.saturating_add(skew_margin_ns)).unwrap_or(i64::MAX);
    let lower = since
        .wall_nanos
        .saturating_sub(overlap_ns)
        .div_euclid(1_000_000_000)
        .div_euclid(bucket_width_seconds);
    let upper = upto
        .wall_nanos
        .div_euclid(1_000_000_000)
        .div_euclid(bucket_width_seconds);
    (lower, upper)
}

/// A heartbeat row of `replica_status`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplicaStatus {
    /// The KDC's identifier.
    pub kdc_id: String,
    /// Its region.
    pub region: String,
    /// The checkpoint it last reported.
    pub applied_ts: ReplicationTs,
    /// When the heartbeat arrived, unix seconds (database clock).
    pub seen_at: i64,
}

/// Result of [`CockroachStore::wait_applied`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WaitOutcome {
    /// Live KDCs whose checkpoint is at or past the timestamp.
    pub applied: usize,
    /// KDCs with a heartbeat within the live window.
    pub total: usize,
    /// KDCs ignored because their last heartbeat is outside the live window.
    pub stale: usize,
}

impl WaitOutcome {
    /// Every live KDC has applied the timestamp, and at least one is live.
    pub fn complete(&self) -> bool {
        self.total > 0 && self.applied == self.total
    }
}

/// The CockroachDB authoritative store for one realm's administration.
///
/// It implements [`AdminStore`] (every mutation is one SERIALIZABLE
/// transaction with the client-side retry protocol), [`ReplicationSource`],
/// [`AuthoritativeState`] and [`HealthCheck`]. Keys are stored only in MIT
/// `encrypt_key.c` layout under the master key.
#[derive(Clone)]
pub struct CockroachStore {
    db: Arc<Db>,
    master: EncryptionKey,
    realm: String,
}

impl std::fmt::Debug for CockroachStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CockroachStore")
            .field("config", &self.db.config)
            .field("realm", &self.realm)
            .finish_non_exhaustive()
    }
}

const PRINCIPAL_COLUMNS: &str = "p.realm, p.name, p.name_type, p.attributes, p.max_life, \
    p.max_renewable_life, p.expiration, p.pw_expiration, p.last_pwd_change, p.mod_time, \
    p.policy, p.security_epoch, p.last_admin_unlock, p.delegate_to, p.delegate_from, \
    p.deleted, p.crdb_internal_mvcc_timestamp::STRING, \
    k.kvno, k.enctype, k.mkvno, k.enc_key, k.salt, k.s2kparams";

fn principal_sql(filter: &str) -> String {
    principal_sql_at("", filter)
}

/// `at` is an `AS OF SYSTEM TIME '...'` clause (or empty); CockroachDB wants
/// it at the end of the FROM clause.
fn principal_sql_at(at: &str, filter: &str) -> String {
    format!(
        "SELECT {PRINCIPAL_COLUMNS} FROM principals p LEFT JOIN principal_keys k \
         ON k.realm = p.realm AND k.name = p.name {at} {filter} \
         ORDER BY p.realm, p.name, k.kvno DESC, k.enctype ASC"
    )
}

/// Group join rows (realm, name, ..., keys) into principals with versions.
fn stored_principals(
    rows: &[Row],
) -> Result<Vec<(StoredPrincipal, ReplicationTs, bool)>, StoreError> {
    let mut out: Vec<(StoredPrincipal, ReplicationTs, bool)> = Vec::new();
    let mut last: Option<(String, String)> = None;
    for row in rows {
        let realm: String = row.get(0);
        let key: String = row.get(1);
        if last.as_ref() != Some(&(realm.clone(), key.clone())) {
            let name_type = i32::try_from(row.get::<_, i64>(2))
                .map_err(|_| StoreError::corrupt("name type out of range"))?;
            let u = |i: usize| -> Result<Option<u64>, StoreError> {
                row.get::<_, Option<i64>>(i)
                    .map(|v| u64::try_from(v).map_err(|_| StoreError::corrupt("negative value")))
                    .transpose()
            };
            let sp = StoredPrincipal {
                name: decode_principal_key(&key, name_type)?,
                realm: realm.clone(),
                attributes: u32::try_from(row.get::<_, i64>(3))
                    .map_err(|_| StoreError::corrupt("attributes"))?,
                max_life: u(4)?,
                max_renewable_life: u(5)?,
                expiration: row.get(6),
                pw_expiration: row.get(7),
                last_pwd_change: row.get(8),
                mod_time: row.get(9),
                policy: row.get(10),
                security_epoch: u64::try_from(row.get::<_, i64>(11))
                    .map_err(|_| StoreError::corrupt("negative epoch"))?,
                last_admin_unlock: row.get(12),
                allowed_to_delegate_to: row.get(13),
                allowed_to_delegate_from: row.get(14),
                keys: Vec::new(),
            };
            let deleted: bool = row.get(15);
            let version = ts_of(&row.get::<_, String>(16))?;
            out.push((sp, version, deleted));
            last = Some((realm, key));
        }
        if let Some(kvno) = row.get::<_, Option<i64>>(17) {
            let conv = |v: i64, what: &str| {
                u32::try_from(v).map_err(|_| StoreError::corrupt(format!("{what} out of range")))
            };
            out.last_mut()
                .expect("a principal precedes its keys")
                .0
                .keys
                .push(StoredKey {
                    kvno: conv(kvno, "kvno")?,
                    enctype: i32::try_from(row.get::<_, i64>(18))
                        .map_err(|_| StoreError::corrupt("enctype"))?,
                    mkvno: conv(row.get::<_, i64>(19), "mkvno")?,
                    enc_key: row.get(20),
                    salt: row.get(21),
                    s2kparams: row.get(22),
                });
        }
    }
    Ok(out)
}

const POLICY_COLUMNS: &str = "name, pw_min_life, pw_max_life, pw_min_length, pw_min_classes, \
    pw_history_num, pw_max_fail, pw_failcnt_interval, pw_lockout_duration, attributes, \
    max_life, max_renewable_life, allowed_keysalts, security_epoch, deleted, \
    crdb_internal_mvcc_timestamp::STRING, tl_data";

fn policy_of(row: &Row) -> Result<(Policy, ReplicationTs, bool), StoreError> {
    let n = |i: usize| {
        u32::try_from(row.get::<_, i64>(i))
            .map_err(|_| StoreError::corrupt("policy field out of range"))
    };
    Ok((
        Policy {
            name: row.get(0),
            pw_min_life: n(1)?,
            pw_max_life: n(2)?,
            pw_min_length: n(3)?,
            pw_min_classes: n(4)?,
            pw_history_num: n(5)?,
            pw_max_fail: n(6)?,
            pw_failcnt_interval: n(7)?,
            pw_lockout_duration: n(8)?,
            attributes: n(9)?,
            max_life: n(10)?,
            max_renewable_life: n(11)?,
            allowed_keysalts: row.get(12),
            security_epoch: u64::try_from(row.get::<_, i64>(13))
                .map_err(|_| StoreError::corrupt("negative epoch"))?,
            tl_data: Policy::tl_data_from_bytes(
                &row.get::<_, Option<Vec<u8>>>(16).unwrap_or_default(),
            )?,
        },
        ts_of(&row.get::<_, String>(15))?,
        row.get(14),
    ))
}

fn lockout_of(row: &Row) -> Result<(LockoutRecord, ReplicationTs, bool), StoreError> {
    let name_type = i32::try_from(row.get::<_, i64>(2))
        .map_err(|_| StoreError::corrupt("name type out of range"))?;
    Ok((
        LockoutRecord {
            realm: row.get(0),
            name: decode_principal_key(&row.get::<_, String>(1), name_type)?,
            locked_at: row.get(3),
            unlock_at: row.get(4),
            source_kdc: row.get(5),
        },
        ts_of(&row.get::<_, String>(7))?,
        row.get(6),
    ))
}

const LOCKOUT_COLUMNS: &str = "realm, name, name_type, locked_at, unlock_at, source_kdc, deleted, \
    crdb_internal_mvcc_timestamp::STRING";

/// Append a log row in the bucket selected by the transaction's non-pinning
/// start timestamp.
async fn log(tx: &Tx, entity: &str, realm: &str, key: &str, op: &str) -> Result<(), TxError> {
    let id = transaction_id();
    tx.execute(
        "INSERT INTO replication_log (bucket, id, entity, realm, \"key\", op, txn_id) \
         SELECT floor(EXTRACT(EPOCH FROM now()) / bucket_width_seconds)::INT8, \
         $1::STRING::UUID, $2, $3, $4, $5, $6::STRING::UUID \
         FROM replication_meta WHERE id = 1",
        &[&id, &entity, &realm, &key, &op, &tx.transaction_id],
    )
    .await?;
    Ok(())
}

/// Write `sp` (insert or update) and its keys, then log it.
async fn write_principal(tx: &Tx, sp: &StoredPrincipal, create: bool) -> Result<(), TxError> {
    let key = encode_principal_key(&sp.name)?;
    let name_type = i64::from(sp.name.name_type);
    let attributes = i64::from(sp.attributes);
    let (max_life, max_renewable) = (opt_u(sp.max_life)?, opt_u(sp.max_renewable_life)?);
    let epoch = to_i64(sp.security_epoch)?;
    let params: Params<'_> = &[
        &sp.realm,
        &key,
        &name_type,
        &attributes,
        &max_life,
        &max_renewable,
        &sp.expiration,
        &sp.pw_expiration,
        &sp.last_pwd_change,
        &sp.mod_time,
        &sp.policy,
        &epoch,
        &sp.last_admin_unlock,
        &sp.allowed_to_delegate_to,
        &sp.allowed_to_delegate_from,
    ];
    if create {
        tx.execute(
            "INSERT INTO principals (realm, name, name_type, attributes, max_life, \
             max_renewable_life, expiration, pw_expiration, last_pwd_change, mod_time, policy, \
             security_epoch, last_admin_unlock, delegate_to, delegate_from, deleted) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, \
             false)",
            params,
        )
        .await?;
    } else {
        tx.execute(
            "UPDATE principals SET name_type = $3, attributes = $4, max_life = $5, \
             max_renewable_life = $6, expiration = $7, pw_expiration = $8, \
             last_pwd_change = $9, mod_time = $10, policy = $11, security_epoch = $12, \
             last_admin_unlock = $13, delegate_to = $14, delegate_from = $15, \
             deleted = false, mod_by = current_user() \
             WHERE realm = $1 AND name = $2",
            params,
        )
        .await?;
        tx.execute(
            "DELETE FROM principal_keys WHERE realm = $1 AND name = $2",
            &[&sp.realm, &key],
        )
        .await?;
    }
    for k in &sp.keys {
        let (kvno, enctype, mkvno) = (i64::from(k.kvno), i64::from(k.enctype), i64::from(k.mkvno));
        tx.execute(
            "INSERT INTO principal_keys (realm, name, kvno, enctype, mkvno, enc_key, salt, \
             s2kparams) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
            &[
                &sp.realm,
                &key,
                &kvno,
                &enctype,
                &mkvno,
                &k.enc_key,
                &k.salt,
                &k.s2kparams,
            ],
        )
        .await?;
    }
    log(tx, "principal", &sp.realm, &key, "upsert").await
}

async fn write_policy(tx: &Tx, p: &Policy, create: bool) -> Result<(), TxError> {
    let v = |n: u32| i64::from(n);
    let (a, b, c, d, e, f, g, h, i, j, k) = (
        v(p.pw_min_life),
        v(p.pw_max_life),
        v(p.pw_min_length),
        v(p.pw_min_classes),
        v(p.pw_history_num),
        v(p.pw_max_fail),
        v(p.pw_failcnt_interval),
        v(p.pw_lockout_duration),
        v(p.attributes),
        v(p.max_life),
        v(p.max_renewable_life),
    );
    let epoch = to_i64(p.security_epoch)?;
    let tl = (!p.tl_data.is_empty()).then(|| p.tl_data_bytes());
    let params: Params<'_> = &[
        &p.name,
        &a,
        &b,
        &c,
        &d,
        &e,
        &f,
        &g,
        &h,
        &i,
        &j,
        &k,
        &p.allowed_keysalts,
        &epoch,
        &tl,
    ];
    if create {
        tx.execute(
            "INSERT INTO policies (name, pw_min_life, pw_max_life, pw_min_length, \
             pw_min_classes, pw_history_num, pw_max_fail, pw_failcnt_interval, \
             pw_lockout_duration, attributes, max_life, max_renewable_life, allowed_keysalts, \
             security_epoch, tl_data, deleted) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, \
             $15, false)",
            params,
        )
        .await?;
    } else {
        tx.execute(
            "UPDATE policies SET pw_min_life = $2, pw_max_life = $3, pw_min_length = $4, \
             pw_min_classes = $5, pw_history_num = $6, pw_max_fail = $7, \
             pw_failcnt_interval = $8, pw_lockout_duration = $9, attributes = $10, \
             max_life = $11, max_renewable_life = $12, allowed_keysalts = $13, \
             security_epoch = $14, tl_data = $15, deleted = false WHERE name = $1",
            params,
        )
        .await?;
    }
    log(tx, "policy", "", &p.name, "upsert").await
}

impl CockroachStore {
    /// Connect and check that the schema is current. Does not verify the
    /// master key (use [`CockroachStore::open`] for that).
    pub async fn connect(
        config: CockroachConfig,
        master_key: EncryptionKey,
        realm: &str,
    ) -> Result<Self, StoreError> {
        Self::connect_with(config, master_key, realm, FailPoint::default()).await
    }

    /// [`CockroachStore::connect`] with a failure-injection hook.
    #[doc(hidden)]
    pub async fn connect_with(
        config: CockroachConfig,
        master_key: EncryptionKey,
        realm: &str,
        fail_point: FailPoint,
    ) -> Result<Self, StoreError> {
        let mut db = Db::connect(config)?;
        Arc::get_mut(&mut db)
            .expect("the pool was just created")
            .fail_point = fail_point;
        let version = schema::current_version(&db).await?;
        if version != SCHEMA_VERSION {
            return Err(StoreError::backend(format!(
                "database schema version is {version}, this build needs {SCHEMA_VERSION}: \
                 run `krb5-rs-kdb database migrate`"
            )));
        }
        let timeout_ms = i64::try_from(db.config.transaction_timeout.as_millis())
            .map_err(|_| StoreError::backend("cockroach_transaction_timeout is out of range"))?;
        let meta = db
            .rows(
                "SELECT transaction_timeout_ms FROM replication_meta WHERE id = 1",
                &[],
            )
            .await?;
        let stored_timeout: i64 = meta
            .first()
            .ok_or_else(|| StoreError::corrupt("replication_meta row is missing"))?
            .get(0);
        if stored_timeout != timeout_ms {
            return Err(StoreError::backend(format!(
                "cockroach_transaction_timeout is {}ms but replication_meta requires {stored_timeout}ms",
                timeout_ms
            )));
        }
        Ok(Self {
            db,
            master: master_key,
            realm: realm.to_string(),
        })
    }

    /// Connect and verify the master key against the realm's stored `K/M`
    /// key, as [`FileStore::open`](krb5_rs::kdc::kdb::FileStore::open) does.
    pub async fn open(
        config: CockroachConfig,
        master_key: EncryptionKey,
        realm: &str,
    ) -> Result<Self, StoreError> {
        let store = Self::connect(config, master_key, realm).await?;
        store.verify_master().await?;
        Ok(store)
    }

    /// Apply migrations (and the optional role and multi-region steps) with
    /// the given connection settings. Idempotent.
    pub async fn migrate(
        mut config: CockroachConfig,
        opts: &MigrateOptions,
    ) -> Result<MigrateReport, StoreError> {
        // Multi-region DDL waits for schema-change jobs across all regions.
        // It is an operator operation, not a KDC hot-path query, so don't use
        // the normal 10-second statement timeout for the migration runner.
        config.statement_timeout = config
            .statement_timeout
            .max(std::time::Duration::from_secs(300));
        let timeout_ms = i64::try_from(config.transaction_timeout.as_millis())
            .map_err(|_| StoreError::backend("cockroach_transaction_timeout is out of range"))?;
        let db = Db::connect(config)?;
        let report = schema::migrate(&db, opts).await?;
        db.rows(
            "UPDATE replication_meta SET transaction_timeout_ms = $1 WHERE id = 1 RETURNING 1",
            &[&timeout_ms],
        )
        .await?;
        Ok(report)
    }

    /// The realm this store verifies and creates.
    pub fn realm(&self) -> &str {
        &self.realm
    }

    /// Transaction counters.
    pub fn metrics(&self) -> &Metrics {
        &self.db.metrics
    }

    /// The connection settings.
    pub fn config(&self) -> &CockroachConfig {
        &self.db.config
    }

    fn km_name() -> Result<PrincipalName, StoreError> {
        decode_principal_key("K/M", 1)
    }

    /// Check that the master key opens the realm's `K/M` entry.
    pub async fn verify_master(&self) -> Result<(), StoreError> {
        let rows = self
            .db
            .rows(
                &principal_sql("WHERE p.realm = $1 AND p.name = $2 AND p.deleted = false"),
                &[&self.realm, &"K/M"],
            )
            .await?;
        let (sp, _, _) = stored_principals(&rows)?
            .into_iter()
            .next()
            .ok_or_else(|| {
                StoreError::not_found(format!("realm {} has no K/M entry", self.realm))
            })?;
        let key = sp
            .keys
            .first()
            .ok_or_else(|| StoreError::corrupt("K/M has no key"))?;
        let km = decrypt_key(&self.master, key.enctype, &key.enc_key).map_err(|_| {
            StoreError::backend("the master key does not match the database (cannot decrypt K/M)")
        })?;
        if km.key_bytes() != self.master.key_bytes() {
            return Err(StoreError::backend(
                "the master key does not match the database (K/M differs)",
            ));
        }
        Ok(())
    }

    /// Create the realm: `K/M` (holding the master key, encrypted under
    /// itself, as MIT stores it) and `krbtgt/REALM` with random keys for
    /// `tgt_etypes`, in one transaction. Fails if the realm exists.
    pub async fn create_realm(&self, tgt_etypes: &[i32]) -> Result<(), StoreError> {
        let realm = self.realm.clone();
        let now = now_unix();
        let km = PrincipalEntry {
            name: Self::km_name()?,
            realm: realm.clone(),
            attributes: PrincipalAttributes::DISALLOW_ALL_TIX
                | PrincipalAttributes::REQUIRES_PRE_AUTH
                | PrincipalAttributes::LOCKDOWN_KEYS,
            max_life: None,
            max_renewable_life: None,
            expiration: None,
            pw_expiration: None,
            keys: vec![krb5_rs::kdc::KeyEntry {
                kvno: 1,
                key: self.master.clone(),
                salt: None,
                s2kparams: None,
            }],
            allowed_to_delegate_to: Vec::new(),
            allowed_to_delegate_from: Vec::new(),
            policy: None,
            security_epoch: 1,
            last_admin_unlock: None,
        };
        let tgs = PrincipalEntry {
            name: decode_principal_key(&format!("krbtgt/{}", escape(&realm)), 2)?,
            attributes: PrincipalAttributes::empty(),
            keys: krb5_rs::kdc::random_keys(1, tgt_etypes)
                .map_err(|e| StoreError::backend(e.to_string()))?,
            ..km.clone()
        };
        let tgs = PrincipalEntry {
            security_epoch: 1,
            ..tgs
        };
        let stored = [
            StoredPrincipal::from_entry(&km, Some(now), Some(now), &self.master)?,
            StoredPrincipal::from_entry(&tgs, Some(now), Some(now), &self.master)?,
        ];
        let master_enctype = i64::from(self.master.keytype);
        let stored = &stored;
        let realm_ref = &realm;
        self.db
            .run_tx(|tx| {
                Box::pin(async move {
                    let inserted = tx
                        .execute(
                            "INSERT INTO realms (name, master_kvno, master_enctype) \
                             VALUES ($1, 1, $2) ON CONFLICT (name) DO NOTHING",
                            &[realm_ref, &master_enctype],
                        )
                        .await?;
                    if inserted == 0 {
                        return Err(conflict_exists(format!("realm {realm_ref}")).into());
                    }
                    for sp in stored {
                        write_principal(&tx, sp, true).await?;
                    }
                    Ok(())
                })
            })
            .await
    }

    fn record_of(&self, sp: StoredPrincipal) -> Result<PrincipalRecord, StoreError> {
        let (last_pwd_change, mod_time) = (sp.last_pwd_change, sp.mod_time);
        Ok(PrincipalRecord {
            entry: sp.into_entry(&self.master)?,
            last_pwd_change: last_pwd_change.map(kt),
            mod_time: mod_time.map(kt),
            mod_by: None,
            password_history: None,
        })
    }

    /// Record a KDC heartbeat: the checkpoint `applied_ts` it has reached.
    pub async fn heartbeat(
        &self,
        kdc_id: &str,
        region: &str,
        applied_ts: ReplicationTs,
    ) -> Result<(), StoreError> {
        let ts = applied_ts.to_string();
        self.db
            .rows(
                "UPSERT INTO replica_status (kdc_id, region, applied_ts, seen_at) \
                 VALUES ($1, $2, $3::STRING::DECIMAL, now()) RETURNING 1",
                &[&kdc_id, &region, &ts],
            )
            .await?;
        Ok(())
    }

    /// Every KDC's last heartbeat.
    pub async fn replica_statuses(&self) -> Result<Vec<ReplicaStatus>, StoreError> {
        let rows = self
            .db
            .rows(
                "SELECT kdc_id, region, applied_ts::STRING, \
                 EXTRACT(EPOCH FROM seen_at)::INT8 FROM replica_status ORDER BY region, kdc_id",
                &[],
            )
            .await?;
        rows.iter()
            .map(|r| {
                Ok(ReplicaStatus {
                    kdc_id: r.get(0),
                    region: r.get(1),
                    applied_ts: ts_of(&r.get::<_, String>(2))?,
                    seen_at: r.get(3),
                })
            })
            .collect()
    }

    /// Poll the heartbeats until every KDC seen within `live_within` is at or
    /// past `since`, or `timeout` elapses. Stale heartbeat rows are reported
    /// separately and do not count as live KDCs.
    pub async fn wait_applied(
        &self,
        since: ReplicationTs,
        timeout: std::time::Duration,
        live_within: std::time::Duration,
    ) -> Result<WaitOutcome, StoreError> {
        let deadline = tokio::time::Instant::now() + timeout;
        let live_millis = i64::try_from(live_within.as_millis()).unwrap_or(i64::MAX);
        loop {
            let rows = self
                .db
                .rows(
                    "SELECT applied_ts::STRING, \
                     now() - seen_at <= ($1::INT8 * INTERVAL '1 millisecond') \
                     FROM replica_status ORDER BY region, kdc_id",
                    &[&live_millis],
                )
                .await?;
            let mut outcome = WaitOutcome {
                applied: 0,
                total: 0,
                stale: 0,
            };
            for row in &rows {
                if row.get::<_, bool>(1) {
                    outcome.total += 1;
                    if ts_of(&row.get::<_, String>(0))? >= since {
                        outcome.applied += 1;
                    }
                } else {
                    outcome.stale += 1;
                }
            }
            if outcome.complete() || tokio::time::Instant::now() >= deadline {
                return Ok(outcome);
            }
            tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        }
    }

    /// Delete log rows older than `older_than` (relative to the database
    /// clock) and raise `pruned_before` to the cutoff, in one transaction.
    /// Returns the cutoff and the number of rows deleted.
    pub async fn prune(
        &self,
        older_than: std::time::Duration,
    ) -> Result<(ReplicationTs, u64), StoreError> {
        let nanos = i64::try_from(older_than.as_nanos())
            .map_err(|_| StoreError::backend("duration out of range"))?;
        self.db
            .run_tx(|tx| {
                Box::pin(async move {
                    let meta = tx
                        .query_one(
                            "SELECT bucket_width_seconds, transaction_timeout_ms \
                             FROM replication_meta WHERE id = 1",
                            &[],
                        )
                        .await?;
                    let bucket_width: i64 = meta.get(0);
                    let timeout_ms: i64 = meta.get(1);
                    if bucket_width <= 0 || timeout_ms <= 0 {
                        return Err(StoreError::corrupt(
                            "replication bucket width and transaction timeout must be positive",
                        )
                        .into());
                    }
                    let cutoff = ReplicationTs::new(tx.ts.wall_nanos.saturating_sub(nanos), 0);
                    let cutoff_s = cutoff.to_string();
                    let oldest_bucket = scan_buckets(cutoff, cutoff, timeout_ms, bucket_width).0;
                    let deleted = tx
                        .execute(
                            "DELETE FROM replication_log WHERE bucket < $1",
                            &[&oldest_bucket],
                        )
                        .await?;
                    tx.execute(
                        "UPDATE replication_meta SET pruned_before = \
                         greatest(pruned_before, $1::STRING::DECIMAL) WHERE id = 1",
                        &[&cutoff_s],
                    )
                    .await?;
                    tx.execute(
                        "DELETE FROM principals WHERE deleted = true AND \
                         crdb_internal_mvcc_timestamp::STRING::DECIMAL < $1::STRING::DECIMAL",
                        &[&cutoff_s],
                    )
                    .await?;
                    tx.execute(
                        "DELETE FROM policies WHERE deleted = true AND \
                         crdb_internal_mvcc_timestamp::STRING::DECIMAL < $1::STRING::DECIMAL",
                        &[&cutoff_s],
                    )
                    .await?;
                    tx.execute(
                        "DELETE FROM lockouts WHERE deleted = true AND \
                         crdb_internal_mvcc_timestamp::STRING::DECIMAL < $1::STRING::DECIMAL",
                        &[&cutoff_s],
                    )
                    .await?;
                    let marker_age_ms = i64::try_from(older_than.as_millis())
                        .unwrap_or(i64::MAX)
                        .max(timeout_ms);
                    tx.execute(
                        "DELETE FROM transaction_markers WHERE created_at < \
                         now() - ($1::INT8 * INTERVAL '1 millisecond')",
                        &[&marker_age_ms],
                    )
                    .await?;
                    Ok((cutoff, deleted))
                })
            })
            .await
    }

    /// Report a lockout that tripped on `source_kdc`: upsert the `lockouts`
    /// row and its log row. Touches nothing else, so a KDC's database user
    /// needs no write access to `principals`.
    pub async fn report_lockout(&self, record: &LockoutRecord) -> Result<(), StoreError> {
        let key = encode_principal_key(&record.name)?;
        let name_type = i64::from(record.name.name_type);
        let (key, name_type) = (&key, &name_type);
        self.db
            .run_tx(|tx| {
                Box::pin(async move {
                    tx.execute(
                        "INSERT INTO lockouts (realm, name, name_type, locked_at, unlock_at, \
                         source_kdc, deleted) VALUES ($1, $2, $3, $4, $5, $6, false) \
                         ON CONFLICT (realm, name) DO UPDATE SET locked_at = excluded.locked_at, \
                         unlock_at = excluded.unlock_at, source_kdc = excluded.source_kdc, \
                         deleted = false",
                        &[
                            &record.realm,
                            key,
                            name_type,
                            &record.locked_at,
                            &record.unlock_at,
                            &record.source_kdc,
                        ],
                    )
                    .await?;
                    log(&tx, "lockout", &record.realm, key, "upsert").await
                })
            })
            .await
    }

    /// A read-only transaction at the replication read timestamp.
    async fn read_tx<'f, R, F>(&self, body: F) -> Result<R, StoreError>
    where
        R: Send,
        F: FnMut(Tx) -> BoxFut<'f, R> + Send + 'f,
    {
        let mut body = body;
        match self.db.config.replication_read {
            ReplicationRead::Present => self.db.run_read(None, &mut body).await,
            ReplicationRead::Follower => {
                match self
                    .db
                    .run_read(Some("follower_read_timestamp()"), &mut body)
                    .await
                {
                    // A follower read reaches about 4.2 s into the past: just
                    // after the database or its tables were created they do not
                    // exist yet (3D000 / 42P01), and freshly granted privileges
                    // do not apply yet (42501). Read the present once; a real
                    // error repeats there and is returned.
                    Err(e)
                        if ["3D000", "42P01", "42501", "42703"]
                            .iter()
                            .any(|c| e.message().contains(c)) =>
                    {
                        self.db.run_read(None, &mut body).await
                    }
                    other => other,
                }
            }
        }
    }
}

fn escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('/', "\\/")
}

impl AdminStore for CockroachStore {
    async fn get_record(
        &self,
        name: &PrincipalName,
        realm: &str,
    ) -> Result<Option<PrincipalRecord>, StoreError> {
        let key = encode_principal_key(name)?;
        let rows = self
            .db
            .rows(
                &principal_sql("WHERE p.realm = $1 AND p.name = $2 AND p.deleted = false"),
                &[&realm, &key],
            )
            .await?;
        stored_principals(&rows)?
            .into_iter()
            .next()
            .filter(|(_, _, deleted)| !deleted)
            .map(|(sp, _, _)| self.record_of(sp))
            .transpose()
    }

    async fn create_principal(
        &self,
        entry: PrincipalEntry,
        last_pwd_change: Option<KerberosTime>,
    ) -> Result<(), StoreError> {
        let sp = StoredPrincipal::from_entry(
            &entry,
            last_pwd_change.map(|t| t.timestamp()),
            Some(now_unix()),
            &self.master,
        )?;
        let sp = &sp;
        self.db
            .run_tx(|tx| {
                Box::pin(async move {
                    let key = encode_principal_key(&sp.name)?;
                    let exists = tx
                        .query_opt(
                            "SELECT deleted FROM principals WHERE realm = $1 AND name = $2 \
                             FOR UPDATE",
                            &[&sp.realm, &key],
                        )
                        .await?;
                    match exists.map(|row| row.get::<_, bool>(0)) {
                        Some(false) => Err(conflict_exists(format!("{}@{}", key, sp.realm)).into()),
                        Some(true) => write_principal(&tx, sp, false).await,
                        None => write_principal(&tx, sp, true).await,
                    }
                })
            })
            .await
    }

    async fn update_principal<F>(
        &self,
        name: &PrincipalName,
        realm: &str,
        f: F,
    ) -> Result<PrincipalRecord, StoreError>
    where
        F: FnMut(&mut PrincipalRecord) -> Result<(), StoreError> + Send + 'static,
    {
        let key = encode_principal_key(name)?;
        let f = Arc::new(Mutex::new(f));
        let (key_ref, realm_s) = (&key, realm.to_string());
        let (master, what) = (&self.master, format!("{name}@{realm}"));
        let stored = self
            .db
            .run_tx(|tx| {
                let f = Arc::clone(&f);
                let realm_s = realm_s.clone();
                let what = what.clone();
                Box::pin(async move {
                    let rows = tx
                        .query(
                            &principal_sql(
                                "WHERE p.realm = $1 AND p.name = $2 AND p.deleted = false",
                            ),
                            &[&realm_s, key_ref],
                        )
                        .await?;
                    let (sp, _, _) =
                        stored_principals(&rows)?
                            .into_iter()
                            .next()
                            .ok_or_else(|| {
                                StoreError::not_found(format!("Principal {what} does not exist"))
                            })?;
                    let (last_pwd, mod_time) = (sp.last_pwd_change, sp.mod_time);
                    let mut rec = PrincipalRecord {
                        entry: sp.into_entry(master)?,
                        last_pwd_change: last_pwd.map(kt),
                        mod_time: mod_time.map(kt),
                        mod_by: None,
                        password_history: None,
                    };
                    let unlock_before = rec.entry.last_admin_unlock.map(|t| t.timestamp());
                    {
                        let mut f = f.lock().unwrap_or_else(|e| e.into_inner());
                        (f)(&mut rec)?;
                    }
                    let unlocked =
                        rec.entry.last_admin_unlock.map(|t| t.timestamp()) != unlock_before;
                    let now = now_unix();
                    let sp = StoredPrincipal::from_entry(
                        &rec.entry,
                        rec.last_pwd_change.map(|t| t.timestamp()),
                        Some(now),
                        master,
                    )?;
                    write_principal(&tx, &sp, false).await?;
                    if unlocked {
                        // An administrative unlock lifts the replicated lockout.
                        let lifted = tx
                            .execute(
                                "UPDATE lockouts SET deleted = true \
                                 WHERE realm = $1 AND name = $2 AND deleted = false",
                                &[&realm_s, key_ref],
                            )
                            .await?;
                        if lifted > 0 {
                            log(&tx, "lockout", &realm_s, key_ref, "delete").await?;
                        }
                    }
                    Ok(sp)
                })
            })
            .await?;
        self.record_of(stored)
    }

    async fn delete_principal(
        &self,
        name: &PrincipalName,
        realm: &str,
    ) -> Result<bool, StoreError> {
        let key = encode_principal_key(name)?;
        let (key, realm) = (&key, realm.to_string());
        self.db
            .run_tx(|tx| {
                let realm = realm.clone();
                Box::pin(async move {
                    let gone = tx
                        .execute(
                            "UPDATE principals SET deleted = true, \
                             mod_time = EXTRACT(EPOCH FROM now())::INT8, mod_by = current_user() \
                             WHERE realm = $1 AND name = $2 AND deleted = false",
                            &[&realm, key],
                        )
                        .await?;
                    if gone == 0 {
                        return Ok(false);
                    }
                    tx.execute(
                        "DELETE FROM principal_keys WHERE realm = $1 AND name = $2",
                        &[&realm, key],
                    )
                    .await?;
                    log(&tx, "principal", &realm, key, "delete").await?;
                    let lifted = tx
                        .execute(
                            "UPDATE lockouts SET deleted = true \
                             WHERE realm = $1 AND name = $2 AND deleted = false",
                            &[&realm, key],
                        )
                        .await?;
                    if lifted > 0 {
                        log(&tx, "lockout", &realm, key, "delete").await?;
                    }
                    Ok(true)
                })
            })
            .await
    }

    async fn list_principals(&self) -> Result<Vec<PrincipalRecord>, StoreError> {
        let rows = self
            .db
            .rows(&principal_sql("WHERE p.deleted = false"), &[])
            .await?;
        stored_principals(&rows)?
            .into_iter()
            .map(|(sp, _, _)| self.record_of(sp))
            .collect()
    }

    async fn get_policy(&self, name: &str) -> Result<Option<Policy>, StoreError> {
        let rows = self
            .db
            .rows(
                &format!(
                    "SELECT {POLICY_COLUMNS} FROM policies WHERE name = $1 AND deleted = false"
                ),
                &[&name],
            )
            .await?;
        rows.first()
            .map(|r| policy_of(r).map(|(p, _, _)| p))
            .transpose()
    }

    async fn create_policy(&self, policy: Policy) -> Result<(), StoreError> {
        let policy = &policy;
        self.db
            .run_tx(|tx| {
                Box::pin(async move {
                    let exists = tx
                        .query_opt(
                            "SELECT deleted FROM policies WHERE name = $1 FOR UPDATE",
                            &[&policy.name],
                        )
                        .await?;
                    match exists.map(|row| row.get::<_, bool>(0)) {
                        Some(false) => {
                            Err(conflict_exists(format!("policy {}", policy.name)).into())
                        }
                        Some(true) => write_policy(&tx, policy, false).await,
                        None => write_policy(&tx, policy, true).await,
                    }
                })
            })
            .await
    }

    async fn update_policy<F>(&self, name: &str, f: F) -> Result<Policy, StoreError>
    where
        F: FnMut(&mut Policy) -> Result<(), StoreError> + Send + 'static,
    {
        let f = Arc::new(Mutex::new(f));
        let name = name.to_string();
        self.db
            .run_tx(|tx| {
                let (f, name) = (Arc::clone(&f), name.clone());
                Box::pin(async move {
                    let rows = tx
                        .query(
                            &format!(
                                "SELECT {POLICY_COLUMNS} FROM policies \
                                 WHERE name = $1 AND deleted = false"
                            ),
                            &[&name],
                        )
                        .await?;
                    let (mut policy, _, _) =
                        rows.first().map(policy_of).transpose()?.ok_or_else(|| {
                            StoreError::not_found(format!("Policy \"{name}\" does not exist"))
                        })?;
                    {
                        let mut f = f.lock().unwrap_or_else(|e| e.into_inner());
                        (f)(&mut policy)?;
                    }
                    write_policy(&tx, &policy, false).await?;
                    Ok(policy)
                })
            })
            .await
    }

    async fn delete_policy(&self, name: &str) -> Result<bool, StoreError> {
        let name = name.to_string();
        self.db
            .run_tx(|tx| {
                let name = name.clone();
                Box::pin(async move {
                    let gone = tx
                        .execute(
                            "UPDATE policies SET deleted = true WHERE name = $1 AND deleted = false",
                            &[&name],
                        )
                        .await?;
                    if gone == 0 {
                        return Ok(false);
                    }
                    log(&tx, "policy", "", &name, "delete").await?;
                    Ok(true)
                })
            })
            .await
    }

    async fn list_policies(&self) -> Result<Vec<Policy>, StoreError> {
        let rows = self
            .db
            .rows(
                &format!(
                    "SELECT {POLICY_COLUMNS} FROM policies WHERE deleted = false ORDER BY name"
                ),
                &[],
            )
            .await?;
        rows.iter()
            .map(|r| policy_of(r).map(|(p, _, _)| p))
            .collect()
    }
}

impl HealthCheck for CockroachStore {
    async fn health(&self) -> Result<(), StoreError> {
        self.db.rows("SELECT 1", &[]).await.map(|_| ())
    }
}

impl AuthoritativeState for CockroachStore {
    /// A point read with the statement timeout as its bound: the principal's
    /// epoch, whether it is disabled, and whether a replicated lockout is
    /// active. A missing principal is `NotFound`; a slow or unreachable
    /// database is `Unavailable`.
    async fn security_state(
        &self,
        name: &PrincipalName,
        realm: &str,
    ) -> Result<SecurityState, StoreError> {
        let key = encode_principal_key(name)?;
        let params: [&(dyn tokio_postgres::types::ToSql + Sync); 2] = [&realm, &key];
        let read = self.db.rows(
            "SELECT p.security_epoch, p.attributes, l.unlock_at, l.locked_at IS NOT NULL \
             FROM principals p LEFT JOIN lockouts l ON l.realm = p.realm AND l.name = p.name \
             AND l.deleted = false \
             WHERE p.realm = $1 AND p.name = $2 AND p.deleted = false",
            &params,
        );
        let rows = tokio::time::timeout(self.db.config.statement_timeout, read)
            .await
            .map_err(|_| StoreError::unavailable("authoritative read timed out"))??;
        let row = rows.first().ok_or_else(|| {
            StoreError::not_found(format!("Principal {name}@{realm} does not exist"))
        })?;
        let attributes = row.get::<_, i64>(1);
        let unlock_at: Option<i64> = row.get(2);
        let has_lockout: bool = row.get(3);
        Ok(SecurityState {
            epoch: u64::try_from(row.get::<_, i64>(0)).unwrap_or(0),
            disabled: attributes & i64::from(PrincipalAttributes::DISALLOW_ALL_TIX.bits()) != 0,
            locked: has_lockout && unlock_at.is_none_or(|u| u > now_unix()),
        })
    }
}

/// Snapshot paging stages.
enum Stage {
    Principals,
    Policies,
    Lockouts,
    Done,
}

/// A paged snapshot at one read timestamp ([`ReplicationSource::snapshot`]).
pub struct CockroachSnapshot {
    db: Arc<Db>,
    ts: ReplicationTs,
    source_now: ReplicationTs,
    pruned_before: ReplicationTs,
    stage: Stage,
    cursor: (String, String),
}

const SNAPSHOT_PAGE: i64 = 100;

impl Snapshot for CockroachSnapshot {
    fn ts(&self) -> ReplicationTs {
        self.ts
    }

    fn source_now(&self) -> ReplicationTs {
        self.source_now
    }

    async fn next_page(&mut self) -> Result<Option<Vec<Change>>, StoreError> {
        let at = format!("AS OF SYSTEM TIME '{}'", self.ts);
        loop {
            match self.stage {
                Stage::Principals => {
                    let filter = format!(
                        "WHERE (p.realm, p.name) IN (\
                         SELECT realm, name FROM principals {at} \
                         WHERE (realm, name) > ($1, $2) \
                         AND (deleted = false OR crdb_internal_mvcc_timestamp::STRING::DECIMAL >= \
                              $3::STRING::DECIMAL) \
                         ORDER BY realm, name LIMIT {SNAPSHOT_PAGE})"
                    );
                    let rows = self
                        .db
                        .rows(
                            &principal_sql_at(&at, &filter),
                            &[
                                &self.cursor.0,
                                &self.cursor.1,
                                &self.pruned_before.to_string(),
                            ],
                        )
                        .await?;
                    let principals = stored_principals(&rows)?;
                    let Some((last, _, _)) = principals.last() else {
                        self.stage = Stage::Policies;
                        self.cursor = (String::new(), String::new());
                        continue;
                    };
                    self.cursor = (last.realm.clone(), encode_principal_key(&last.name)?);
                    let out = principals
                        .into_iter()
                        .map(|(principal, version, deleted)| {
                            if deleted {
                                Change::DeletePrincipal {
                                    realm: principal.realm,
                                    name: principal.name,
                                    version,
                                }
                            } else {
                                Change::UpsertPrincipal { principal, version }
                            }
                        })
                        .collect();
                    return Ok(Some(out));
                }
                Stage::Policies => {
                    let rows = self
                        .db
                        .rows(
                            &format!(
                                "SELECT {POLICY_COLUMNS} FROM policies {at} \
                                 WHERE name > $1 AND (deleted = false OR \
                                 crdb_internal_mvcc_timestamp::STRING::DECIMAL >= $2::STRING::DECIMAL) \
                                 ORDER BY name LIMIT {SNAPSHOT_PAGE}"
                            ),
                            &[&self.cursor.0, &self.pruned_before.to_string()],
                        )
                        .await?;
                    let Some(last) = rows.last() else {
                        self.stage = Stage::Lockouts;
                        self.cursor = (String::new(), String::new());
                        continue;
                    };
                    self.cursor = (last.get(0), String::new());
                    let mut out = Vec::new();
                    for r in &rows {
                        let (policy, version, deleted) = policy_of(r)?;
                        out.push(if deleted {
                            Change::DeletePolicy {
                                name: policy.name,
                                version,
                            }
                        } else {
                            Change::UpsertPolicy { policy, version }
                        });
                    }
                    return Ok(Some(out));
                }
                Stage::Lockouts => {
                    let rows = self
                        .db
                        .rows(
                            &format!(
                                "SELECT {LOCKOUT_COLUMNS} FROM lockouts {at} \
                                 WHERE (realm, name) > ($1, $2) AND (deleted = false OR \
                                 crdb_internal_mvcc_timestamp::STRING::DECIMAL >= $3::STRING::DECIMAL) \
                                 ORDER BY realm, name \
                                 LIMIT {SNAPSHOT_PAGE}"
                            ),
                            &[
                                &self.cursor.0,
                                &self.cursor.1,
                                &self.pruned_before.to_string(),
                            ],
                        )
                        .await?;
                    let Some(last) = rows.last() else {
                        self.stage = Stage::Done;
                        continue;
                    };
                    self.cursor = (last.get(0), last.get(1));
                    let mut out = Vec::new();
                    for r in &rows {
                        let (record, version, deleted) = lockout_of(r)?;
                        out.push(if deleted {
                            Change::DeleteLockout {
                                realm: record.realm,
                                name: record.name,
                                version,
                            }
                        } else {
                            Change::UpsertLockout { record, version }
                        });
                    }
                    return Ok(Some(out));
                }
                Stage::Done => return Ok(None),
            }
        }
    }
}

/// One `replication_log` row.
struct LogRow {
    mvcc_ts: ReplicationTs,
    entity: String,
    realm: String,
    key: String,
}

fn log_row(r: &Row) -> Result<LogRow, StoreError> {
    Ok(LogRow {
        mvcc_ts: ts_of(&r.get::<_, String>(0))?,
        entity: r.get(1),
        realm: r.get(2),
        key: r.get(3),
    })
}

enum PollMaterialization {
    Complete(Vec<Change>),
    Truncated(Vec<LogRow>),
}

struct PollRead {
    upto: ReplicationTs,
    materialization: PollMaterialization,
    source_now: ReplicationTs,
    truncated: bool,
}

async fn materialize_changes(tx: &Tx, rows: &[LogRow]) -> Result<Vec<Change>, TxError> {
    // The state of each changed entity at the same read timestamp; absent
    // means deleted, with the log row's version.
    let mut seen: Vec<(String, String, String)> = Vec::new();
    let mut changes = Vec::new();
    for r in rows.iter().rev() {
        let id = (r.entity.clone(), r.realm.clone(), r.key.clone());
        if seen.contains(&id) {
            continue;
        }
        seen.push(id);
        let fallback_version = rows
            .iter()
            .filter(|o| o.entity == r.entity && o.realm == r.realm && o.key == r.key)
            .map(|o| o.mvcc_ts)
            .max()
            .unwrap_or(r.mvcc_ts);
        changes.push(match r.entity.as_str() {
            "principal" => {
                let found = tx
                    .query(
                        &principal_sql("WHERE p.realm = $1 AND p.name = $2"),
                        &[&r.realm, &r.key],
                    )
                    .await?;
                match stored_principals(&found)?.into_iter().next() {
                    Some((_, version, true)) => Change::DeletePrincipal {
                        realm: r.realm.clone(),
                        name: decode_principal_key(&r.key, 1)?,
                        version,
                    },
                    Some((principal, version, false)) => {
                        Change::UpsertPrincipal { principal, version }
                    }
                    None => Change::DeletePrincipal {
                        realm: r.realm.clone(),
                        name: decode_principal_key(&r.key, 1)?,
                        version: fallback_version,
                    },
                }
            }
            "policy" => {
                let found = tx
                    .query(
                        &format!("SELECT {POLICY_COLUMNS} FROM policies WHERE name = $1"),
                        &[&r.key],
                    )
                    .await?;
                match found.first() {
                    Some(row) => {
                        let (policy, version, deleted) = policy_of(row)?;
                        if deleted {
                            Change::DeletePolicy {
                                name: r.key.clone(),
                                version,
                            }
                        } else {
                            Change::UpsertPolicy { policy, version }
                        }
                    }
                    None => Change::DeletePolicy {
                        name: r.key.clone(),
                        version: fallback_version,
                    },
                }
            }
            "lockout" => {
                let found = tx
                    .query(
                        &format!(
                            "SELECT {LOCKOUT_COLUMNS} FROM lockouts \
                             WHERE realm = $1 AND name = $2"
                        ),
                        &[&r.realm, &r.key],
                    )
                    .await?;
                match found.first() {
                    Some(row) => {
                        let (record, version, deleted) = lockout_of(row)?;
                        if deleted {
                            Change::DeleteLockout {
                                realm: r.realm.clone(),
                                name: decode_principal_key(&r.key, 1)?,
                                version,
                            }
                        } else {
                            Change::UpsertLockout { record, version }
                        }
                    }
                    None => Change::DeleteLockout {
                        realm: r.realm.clone(),
                        name: decode_principal_key(&r.key, 1)?,
                        version: fallback_version,
                    },
                }
            }
            other => {
                return Err(
                    StoreError::corrupt(format!("unknown replication entity {other:?}")).into(),
                )
            }
        });
    }
    // `rev()` above walked newest first; keep commit order.
    changes.reverse();
    Ok(changes)
}

const LOG_COLUMNS: &str = "crdb_internal_mvcc_timestamp::STRING, entity, realm, \"key\", op";

impl ReplicationSource for CockroachStore {
    type Snapshot = CockroachSnapshot;

    async fn snapshot(&self) -> Result<CockroachSnapshot, StoreError> {
        // Touch a table at the read timestamp, so a timestamp older than the
        // schema falls back to the present (see `read_tx`).
        let (ts, source_now, pruned_before) = self
            .read_tx(|tx| {
                Box::pin(async move {
                    let row = tx
                        .query_one(
                            "SELECT pruned_before::STRING FROM replication_meta WHERE id = 1",
                            &[],
                        )
                        .await?;
                    let pruned_before = ts_of(&row.get::<_, String>(0))?;
                    Ok((tx.ts, tx.source_now, pruned_before))
                })
            })
            .await?;
        Ok(CockroachSnapshot {
            db: Arc::clone(&self.db),
            ts,
            source_now,
            pruned_before,
            stage: Stage::Principals,
            cursor: (String::new(), String::new()),
        })
    }

    async fn poll(&self, since: ReplicationTs, limit: usize) -> Result<PollResult, StoreError> {
        let since_ts = since;
        let since = since.to_string();
        let since = &since;
        let limit = i64::try_from(limit.max(1)).unwrap_or(i64::MAX - 1);
        let fetch_limit = limit.saturating_add(1);
        let read = self
            .read_tx(|tx| {
                Box::pin(async move {
                    let upto_read = tx.ts;
                    let meta = tx
                        .query_one(
                            "SELECT pruned_before::STRING, bucket_width_seconds, \
                         transaction_timeout_ms FROM replication_meta WHERE id = 1",
                            &[],
                        )
                        .await?;
                    let watermark = ts_of(&meta.get::<_, String>(0))?;
                    let bucket_width: i64 = meta.get(1);
                    let transaction_timeout_ms: i64 = meta.get(2);
                    if bucket_width <= 0 || transaction_timeout_ms <= 0 {
                        return Err(StoreError::corrupt(
                            "replication bucket width and transaction timeout must be positive",
                        )
                        .into());
                    }
                    if since_ts < watermark {
                        return Err(StoreError::stale(
                            "replication checkpoint is below pruned_before; rebuild required",
                        )
                        .into());
                    }
                    if upto_read <= since_ts {
                        // A read timestamp at or below the checkpoint (a follower
                        // read right after a fallback to the present) knows
                        // nothing new, and the checkpoint must not go backwards.
                        return Ok(PollRead {
                            upto: since_ts,
                            materialization: PollMaterialization::Complete(Vec::new()),
                            source_now: tx.source_now,
                            truncated: false,
                        });
                    }
                    let t = upto_read.to_string();
                    let (first_bucket, last_bucket) =
                        scan_buckets(since_ts, upto_read, transaction_timeout_ms, bucket_width);
                    let first = tx
                        .query(
                            &format!(
                                "SELECT {LOG_COLUMNS} FROM replication_log \
                             WHERE bucket BETWEEN $1 AND $2 \
                             AND crdb_internal_mvcc_timestamp::STRING::DECIMAL > \
                                 $3::STRING::DECIMAL \
                             AND crdb_internal_mvcc_timestamp::STRING::DECIMAL <= \
                                 $4::STRING::DECIMAL \
                             ORDER BY crdb_internal_mvcc_timestamp, bucket, id LIMIT $5"
                            ),
                            &[&first_bucket, &last_bucket, since, &t, &fetch_limit],
                        )
                        .await?;
                    let candidates: Vec<LogRow> =
                        first.iter().map(log_row).collect::<Result<_, _>>()?;
                    let mut truncated = false;
                    let mut upto = upto_read;
                    let mut rows = candidates;
                    if rows.len() > limit as usize {
                        let cutoff = rows[limit as usize - 1].mvcc_ts;
                        let cutoff_s = cutoff.to_string();
                        truncated = tx
                            .query_opt(
                                "SELECT 1 FROM replication_log \
                             WHERE bucket BETWEEN $1 AND $2 \
                             AND crdb_internal_mvcc_timestamp::STRING::DECIMAL > \
                                 $3::STRING::DECIMAL \
                             AND crdb_internal_mvcc_timestamp::STRING::DECIMAL <= \
                                 $4::STRING::DECIMAL LIMIT 1",
                                &[&first_bucket, &last_bucket, &cutoff_s, &t],
                            )
                            .await?
                            .is_some();
                        upto = if truncated { cutoff } else { upto_read };
                        let upto_s = upto.to_string();
                        let all = tx
                            .query(
                                &format!(
                                    "SELECT {LOG_COLUMNS} FROM replication_log \
                                 WHERE bucket BETWEEN $1 AND $2 \
                                 AND crdb_internal_mvcc_timestamp::STRING::DECIMAL > \
                                     $3::STRING::DECIMAL \
                                 AND crdb_internal_mvcc_timestamp::STRING::DECIMAL <= \
                                     $4::STRING::DECIMAL \
                                 ORDER BY crdb_internal_mvcc_timestamp, bucket, id"
                                ),
                                &[&first_bucket, &last_bucket, since, &upto_s],
                            )
                            .await?;
                        rows = all.iter().map(log_row).collect::<Result<_, _>>()?;
                    }
                    let materialization = if truncated {
                        PollMaterialization::Truncated(rows)
                    } else {
                        PollMaterialization::Complete(materialize_changes(&tx, &rows).await?)
                    };
                    Ok(PollRead {
                        upto,
                        materialization,
                        source_now: tx.source_now,
                        truncated,
                    })
                })
            })
            .await?;

        let changes = match read.materialization {
            PollMaterialization::Complete(changes) => changes,
            PollMaterialization::Truncated(rows) => {
                let aost = format!("'{}'", read.upto);
                let rows = Arc::new(rows);
                self.db
                    .run_read(Some(&aost), &mut |tx| {
                        let rows = Arc::clone(&rows);
                        Box::pin(async move { materialize_changes(&tx, &rows).await })
                    })
                    .await?
            }
        };
        Ok(PollResult {
            batch: ChangeBatch {
                upto: read.upto,
                changes,
            },
            source_now: read.source_now,
            truncated: read.truncated,
        })
    }

    async fn pruned_before(&self) -> Result<Option<ReplicationTs>, StoreError> {
        let rows = self
            .db
            .rows(
                "SELECT pruned_before::STRING FROM replication_meta WHERE id = 1",
                &[],
            )
            .await?;
        match rows.first() {
            Some(r) => {
                let ts = ts_of(&r.get::<_, String>(0))?;
                Ok((ts != ReplicationTs::ZERO).then_some(ts))
            }
            None => Ok(None),
        }
    }
}

impl ReplicaRegistry for CockroachStore {
    async fn heartbeat(
        &self,
        kdc_id: &str,
        region: &str,
        applied_ts: ReplicationTs,
    ) -> Result<(), StoreError> {
        CockroachStore::heartbeat(self, kdc_id, region, applied_ts).await
    }
}

#[cfg(test)]
mod tests {
    use super::{scan_buckets, ReplicationTs};

    const SECOND: i64 = 1_000_000_000;
    const TRANSACTION_TIMEOUT_MS: i64 = 30_000;
    const BUCKET_WIDTH_SECONDS: i64 = 10;

    #[test]
    fn scan_buckets_includes_start_bucket_before_the_transaction_timeout() {
        let since = ReplicationTs::new(100 * SECOND, 0);
        let start = since.wall_nanos - 31 * SECOND;
        let start_bucket = start.div_euclid(SECOND).div_euclid(BUCKET_WIDTH_SECONDS);
        let without_margin = (since.wall_nanos - 30 * SECOND)
            .div_euclid(SECOND)
            .div_euclid(BUCKET_WIDTH_SECONDS);
        let (first, _) = scan_buckets(
            since,
            ReplicationTs::new(109 * SECOND, 0),
            TRANSACTION_TIMEOUT_MS,
            BUCKET_WIDTH_SECONDS,
        );

        assert_eq!(start_bucket, 6);
        assert_eq!(without_margin, 7);
        assert_eq!(first, 6);
        assert!(first <= start_bucket);
    }

    #[test]
    fn scan_buckets_upper_bound_is_the_upto_bucket() {
        let upto = ReplicationTs::new(129 * SECOND + 999, 5);
        let (_, last) = scan_buckets(
            ReplicationTs::new(100 * SECOND, 0),
            upto,
            TRANSACTION_TIMEOUT_MS,
            BUCKET_WIDTH_SECONDS,
        );

        assert_eq!(last, 12);
    }

    #[test]
    fn prune_and_poll_use_the_same_oldest_bucket() {
        let cutoff = ReplicationTs::new(100 * SECOND, 0);
        let prune_oldest =
            scan_buckets(cutoff, cutoff, TRANSACTION_TIMEOUT_MS, BUCKET_WIDTH_SECONDS).0;
        let poll_oldest = scan_buckets(
            cutoff,
            ReplicationTs::new(150 * SECOND, 0),
            TRANSACTION_TIMEOUT_MS,
            BUCKET_WIDTH_SECONDS,
        )
        .0;

        assert_eq!(prune_oldest, poll_oldest);
    }

    #[test]
    fn scan_buckets_handles_negative_and_zero_adjacent_timestamps() {
        let (negative_lower, zero_upper) = scan_buckets(
            ReplicationTs::new(-1, 0),
            ReplicationTs::new(0, 0),
            TRANSACTION_TIMEOUT_MS,
            BUCKET_WIDTH_SECONDS,
        );
        let (zero_lower, next_upper) = scan_buckets(
            ReplicationTs::new(0, 0),
            ReplicationTs::new(1, 0),
            TRANSACTION_TIMEOUT_MS,
            BUCKET_WIDTH_SECONDS,
        );

        assert_eq!((negative_lower, zero_upper), (-4, 0));
        assert_eq!((zero_lower, next_upper), (-4, 0));
    }
}
