//! [`TursoReplica`]: the KDC's local read replica on Turso (MVCC).

use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock, Weak};

use tokio::sync::RwLock as AsyncRwLock;

use krb5_rs::kdc::kdb::mit::mkey::MasterKeys;
use krb5_rs::kdc::replication::{
    ApplyOutcome, Change, ChangeBatch, RebuildWriter, ReplicaCheckpoint, ReplicaSink, ReplicationTs,
};
use krb5_rs::kdc::{
    AuthState, AuthStateStore, AuthStateUpdate, HealthCheck, Policy, PolicyStore, PrincipalEntry,
    PrincipalStore, StoreError,
};
use krb5_rs::types::{EncryptionKey, PrincipalName};
use turso::{Connection, Value};

use crate::changes::{
    apply_changes, encode_name, policy_from_row, principal_from_rows, read_checkpoint,
    write_checkpoint, LOOKUP_SQL, POLICY_SQL,
};
use crate::db::{
    backoff, exec, int, is_conflict, journal_mode, map_err, now_unix, query, schema_version, text,
    Inner, TxError, SCHEMA_VERSION,
};
use crate::TursoOptions;

const CURRENT_FILE: &str = "CURRENT";
const INITIAL_FILE: &str = "replica-initial.db";

type BoxFut<'a, R> = Pin<Box<dyn Future<Output = Result<R, TxError>> + Send + 'a>>;

/// Counters for observability (a metrics hook).
#[derive(Debug, Default)]
pub struct ReplicaMetrics {
    apply_retries: AtomicU64,
    auth_retries: AtomicU64,
}

impl ReplicaMetrics {
    /// Times a replication write was retried after an MVCC conflict.
    pub fn apply_retries(&self) -> u64 {
        self.apply_retries.load(Ordering::Relaxed)
    }

    /// Times an authentication-state write was retried after a conflict.
    pub fn auth_retries(&self) -> u64 {
        self.auth_retries.load(Ordering::Relaxed)
    }
}

/// What [`TursoReplica::status`] reports.
#[derive(Debug, Clone)]
pub struct ReplicaStatus {
    /// `PRAGMA journal_mode` of the open database.
    pub journal_mode: String,
    /// Always true for a replica that opened (MVCC is enforced).
    pub mvcc: bool,
    /// Schema version recorded in the database.
    pub schema_version: i64,
    /// The replication checkpoint, absent before the first bootstrap.
    pub checkpoint: Option<ReplicaCheckpoint>,
    /// The error of the most recent failed apply, cleared by a success.
    pub last_apply_error: Option<String>,
    /// The database file in use.
    pub database: PathBuf,
}

struct Pending {
    file_name: String,
    inner: Weak<Inner>,
}

struct Shared {
    dir: PathBuf,
    options: TursoOptions,
    master: EncryptionKey,
    /// The master-key list from the replicated `K/M`, reloaded when a key
    /// names a version it lacks.
    masters: RwLock<MasterKeys>,
    current: RwLock<Arc<Inner>>,
    auth_state_writes: AsyncRwLock<()>,
    pending: Mutex<Vec<Pending>>,
    metrics: ReplicaMetrics,
    last_apply_error: Mutex<Option<String>>,
}

/// A local replica database on Turso with MVCC.
///
/// `path` is a directory holding the database files (`replica-*.db` with their
/// `-log`) and the `CURRENT` pointer naming the one in use. Reads use a fixed
/// pool of connections with cached prepared statements and never wait for
/// replication writes (MVCC snapshots); writes are short `BEGIN CONCURRENT`
/// transactions retried on conflict.
///
/// Keys are stored encrypted under the master key (MIT `encrypt_key.c`
/// layout); no plaintext key reaches the database files, logs or errors.
#[derive(Clone)]
pub struct TursoReplica(Arc<Shared>);

impl std::fmt::Debug for TursoReplica {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TursoReplica")
            .field("dir", &self.0.dir)
            .finish_non_exhaustive()
    }
}

fn sidecars(file_name: &str) -> [String; 4] {
    [
        file_name.to_string(),
        format!("{file_name}-log"),
        format!("{file_name}-wal"),
        format!("{file_name}-shm"),
    ]
}

fn remove_db_files(dir: &Path, file_name: &str) -> bool {
    let mut ok = true;
    for f in sidecars(file_name) {
        match std::fs::remove_file(dir.join(&f)) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => ok = false,
        }
    }
    ok
}

fn io_err(what: &str, e: std::io::Error) -> StoreError {
    StoreError::unavailable(format!("{what}: {e}"))
}

fn sync_file(path: &Path) {
    if let Ok(f) = std::fs::OpenOptions::new().write(true).open(path) {
        let _ = f.sync_all();
    }
}

impl TursoReplica {
    /// Open the replica in directory `path`, creating it (and an empty
    /// database) if absent, following `CURRENT`. The database must be in MVCC
    /// mode: a new one is switched to it and verified; an existing one in any
    /// other mode is an error. Migrations run on every open.
    pub async fn open(
        path: impl AsRef<Path>,
        options: TursoOptions,
        master_key: EncryptionKey,
    ) -> Result<Self, StoreError> {
        let dir = path.as_ref().to_path_buf();
        std::fs::create_dir_all(&dir).map_err(|e| io_err("creating the replica directory", e))?;
        let pointer = dir.join(CURRENT_FILE);
        let (name, create) = match std::fs::read_to_string(&pointer) {
            Ok(s) => (s.trim().to_string(), false),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (INITIAL_FILE.to_string(), true),
            Err(e) => return Err(io_err("reading CURRENT", e)),
        };
        if name.is_empty() || name.contains(['/', '\\']) || name.contains("..") {
            return Err(StoreError::corrupt("CURRENT does not name a database file"));
        }
        let inner = Inner::open(&dir.join(&name), &options, create).await?;
        if create {
            Self::write_pointer(&dir, &name)?;
        }
        let this = Self(Arc::new(Shared {
            dir,
            options,
            masters: RwLock::new(MasterKeys::single(master_key.clone())),
            master: master_key,
            current: RwLock::new(inner),
            auth_state_writes: AsyncRwLock::new(()),
            pending: Mutex::new(Vec::new()),
            metrics: ReplicaMetrics::default(),
            last_apply_error: Mutex::new(None),
        }));
        this.remove_orphans(&name);
        Ok(this)
    }

    fn write_pointer(dir: &Path, name: &str) -> Result<(), StoreError> {
        let tmp = dir.join(format!("{CURRENT_FILE}.tmp"));
        {
            use std::io::Write;
            let mut f = std::fs::File::create(&tmp).map_err(|e| io_err("writing CURRENT", e))?;
            f.write_all(name.as_bytes())
                .and_then(|()| f.sync_all())
                .map_err(|e| io_err("writing CURRENT", e))?;
        }
        std::fs::rename(&tmp, dir.join(CURRENT_FILE))
            .map_err(|e| io_err("replacing CURRENT", e))?;
        // Best effort: make the rename durable (not possible on every platform).
        if let Ok(d) = std::fs::File::open(dir) {
            let _ = d.sync_all();
        }
        Ok(())
    }

    /// Delete database files that `CURRENT` does not name (a rebuild that
    /// never committed, or one superseded before a restart).
    fn remove_orphans(&self, keep: &str) {
        let Ok(entries) = std::fs::read_dir(&self.0.dir) else {
            return;
        };
        let keep = sidecars(keep);
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.starts_with("replica-") && !keep.contains(&name) {
                let _ = std::fs::remove_file(entry.path());
            }
        }
    }

    fn current(&self) -> Arc<Inner> {
        Arc::clone(&self.0.current.read().unwrap_or_else(|e| e.into_inner()))
    }

    /// The directory holding the replica.
    pub fn path(&self) -> &Path {
        &self.0.dir
    }

    /// The database file currently served.
    pub fn current_database(&self) -> PathBuf {
        self.current().path.clone()
    }

    /// Retry and other counters.
    pub fn metrics(&self) -> &ReplicaMetrics {
        &self.0.metrics
    }

    /// Delete database files of replaced databases that no reader holds any
    /// more (the platform may refuse while a file is open; try again later).
    pub fn cleanup_old_files(&self) {
        let mut pending = self.0.pending.lock().unwrap_or_else(|e| e.into_inner());
        pending.retain(|p| {
            if p.inner.strong_count() > 0 {
                return true;
            }
            !remove_db_files(&self.0.dir, &p.file_name)
        });
    }

    /// Run `body` in a `BEGIN CONCURRENT` transaction, retrying conflicts
    /// with bounded exponential backoff.
    async fn write_tx<R, F>(
        &self,
        inner: &Inner,
        retries: &AtomicU64,
        mut body: F,
    ) -> Result<R, StoreError>
    where
        R: Send,
        F: for<'a> FnMut(&'a Connection) -> BoxFut<'a, R> + Send,
    {
        let opts = &self.0.options;
        let pooled = inner.conn().await;
        let conn: &Connection = &pooled;
        let mut attempt = 0u32;
        loop {
            let run = async {
                conn.execute("BEGIN CONCURRENT", ()).await?;
                let out = body(conn).await?;
                conn.execute("COMMIT", ()).await?;
                Ok::<R, TxError>(out)
            }
            .await;
            match run {
                Ok(out) => return Ok(out),
                Err(e) => {
                    let _ = conn.execute("ROLLBACK", ()).await;
                    let conflict = matches!(&e, TxError::Turso(t) if is_conflict(t));
                    if conflict && attempt < opts.max_retries {
                        retries.fetch_add(1, Ordering::Relaxed);
                        tokio::time::sleep(backoff(
                            attempt,
                            opts.retry_base_delay,
                            opts.retry_max_delay,
                        ))
                        .await;
                        attempt += 1;
                        continue;
                    }
                    return Err(e.into_store());
                }
            }
        }
    }

    async fn copy_auth_state(&self, from: &Inner, to: &Inner) -> Result<(), StoreError> {
        let conn = from.conn().await;
        let rows = query(
            &conn,
            "SELECT realm, name, fail_count, last_failed, last_success \
             FROM auth_state ORDER BY realm, name",
            Vec::new(),
        )
        .await
        .map_err(map_err)?;
        let rows = rows
            .iter()
            .map(|row| {
                Ok((
                    text(row, 0)?,
                    text(row, 1)?,
                    int(row, 2)?,
                    int(row, 3)?,
                    int(row, 4)?,
                ))
            })
            .collect::<Result<Vec<_>, StoreError>>()?;
        drop(conn);

        for chunk in rows.chunks(1000) {
            let chunk = Arc::new(chunk.to_vec());
            self.write_tx(to, &self.0.metrics.auth_retries, |conn| {
                let chunk = Arc::clone(&chunk);
                Box::pin(async move {
                    for (realm, name, fail_count, last_failed, last_success) in chunk.iter() {
                        exec(
                            conn,
                            "INSERT INTO auth_state \
                             (realm, name, fail_count, last_failed, last_success) \
                             VALUES (?, ?, ?, ?, ?) \
                             ON CONFLICT (realm, name) DO UPDATE SET \
                             fail_count = excluded.fail_count, \
                             last_failed = excluded.last_failed, \
                             last_success = excluded.last_success",
                            vec![
                                Value::Text(realm.clone()),
                                Value::Text(name.clone()),
                                Value::Integer(*fail_count),
                                Value::Integer(*last_failed),
                                Value::Integer(*last_success),
                            ],
                        )
                        .await?;
                    }
                    Ok(())
                })
            })
            .await?;
        }
        Ok(())
    }

    /// Health details: journal mode, schema version, checkpoint, last error.
    pub async fn status(&self) -> Result<ReplicaStatus, StoreError> {
        let inner = self.current();
        let pooled = inner.conn().await;
        let mode = journal_mode(&pooled).await?;
        Ok(ReplicaStatus {
            mvcc: mode.eq_ignore_ascii_case("mvcc"),
            journal_mode: mode,
            schema_version: schema_version(&pooled).await?,
            checkpoint: read_checkpoint(&pooled).await?,
            last_apply_error: self
                .0
                .last_apply_error
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone(),
            database: inner.path.clone(),
        })
    }

    async fn lookup_stored(
        &self,
        name: &PrincipalName,
        realm: &str,
    ) -> Result<Option<PrincipalEntry>, StoreError> {
        let key = encode_name(name)?;
        let inner = self.current();
        let rows = {
            let conn = inner.conn().await;
            query(
                &conn,
                LOOKUP_SQL,
                vec![Value::Text(realm.to_string()), Value::Text(key.clone())],
            )
            .await
            .map_err(map_err)?
        };
        let Some(sp) = principal_from_rows(realm, &key, &rows)? else {
            return Ok(None);
        };
        let known = |keys: &MasterKeys| {
            sp.keys.iter().all(|k| {
                u16::try_from(k.mkvno)
                    .ok()
                    .and_then(|v| keys.get(v))
                    .is_some()
            })
        };
        if !known(&self.0.masters.read().unwrap_or_else(|e| e.into_inner())) {
            self.reload_masters(&inner, realm).await?;
        }
        let masters = self
            .0
            .masters
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        sp.into_entry(&masters).map(Some)
    }

    /// `krb5_db_fetch_mkey_list` against the replicated `K/M`.
    async fn reload_masters(&self, inner: &Inner, realm: &str) -> Result<(), StoreError> {
        let rows = {
            let conn = inner.conn().await;
            query(
                &conn,
                LOOKUP_SQL,
                vec![
                    Value::Text(realm.to_string()),
                    Value::Text("K/M".to_string()),
                ],
            )
            .await
            .map_err(map_err)?
        };
        let km = principal_from_rows(realm, "K/M", &rows)?
            .ok_or_else(|| StoreError::not_found(format!("realm {realm} has no K/M entry")))?;
        let keys = km.master_keys(&self.0.master)?;
        *self.0.masters.write().unwrap_or_else(|e| e.into_inner()) = keys;
        Ok(())
    }
}

impl PrincipalStore for TursoReplica {
    async fn lookup(
        &self,
        name: &PrincipalName,
        realm: &str,
    ) -> Result<Option<PrincipalEntry>, StoreError> {
        self.lookup_stored(name, realm).await
    }
}

impl PolicyStore for TursoReplica {
    async fn policy(&self, name: &str) -> Result<Option<Policy>, StoreError> {
        let inner = self.current();
        let conn = inner.conn().await;
        let rows = query(&conn, POLICY_SQL, vec![Value::Text(name.to_string())])
            .await
            .map_err(map_err)?;
        rows.first().map(policy_from_row).transpose()
    }
}

impl HealthCheck for TursoReplica {
    async fn health(&self) -> Result<(), StoreError> {
        let status = self.status().await?;
        if !status.mvcc {
            return Err(StoreError::backend(format!(
                "journal mode is {}, not mvcc",
                status.journal_mode
            )));
        }
        if status.schema_version != SCHEMA_VERSION {
            return Err(StoreError::backend(format!(
                "schema version {} (expected {SCHEMA_VERSION})",
                status.schema_version
            )));
        }
        Ok(())
    }
}

/// Fold a replicated lockout into the local counters: while it is active the
/// principal looks as if it had failed `u32::MAX` times at `locked_at`, so the
/// library's MIT lockout check (`locked_check_p`) locks it for the policy's
/// duration.
fn merge_lockout(state: &mut AuthState, locked_at: i64, unlock_at: Option<i64>) {
    if unlock_at.is_none_or(|u| u > now_unix()) {
        state.fail_count = u32::MAX;
        state.last_failed = state.last_failed.max(locked_at);
    }
}

impl AuthStateStore for TursoReplica {
    async fn auth_state(&self, name: &PrincipalName, realm: &str) -> Result<AuthState, StoreError> {
        let key = encode_name(name)?;
        let inner = self.current();
        let conn = inner.conn().await;
        let params = || vec![Value::Text(realm.to_string()), Value::Text(key.clone())];
        let rows = query(
            &conn,
            "SELECT fail_count, last_failed, last_success FROM auth_state \
             WHERE realm = ? AND name = ?",
            params(),
        )
        .await
        .map_err(map_err)?;
        let mut state = match rows.first() {
            Some(r) => AuthState {
                fail_count: u32::try_from(int(r, 0)?).unwrap_or(u32::MAX),
                last_failed: int(r, 1)?,
                last_success: int(r, 2)?,
            },
            None => AuthState::default(),
        };
        let locks = query(
            &conn,
            "SELECT locked_at, unlock_at FROM lockouts \
             WHERE realm = ? AND name = ? AND deleted = 0",
            params(),
        )
        .await
        .map_err(map_err)?;
        if let Some(r) = locks.first() {
            merge_lockout(&mut state, int(r, 0)?, crate::db::opt_int(r, 1)?);
        }
        Ok(state)
    }

    async fn apply(
        &self,
        name: &PrincipalName,
        realm: &str,
        update: &AuthStateUpdate,
    ) -> Result<AuthState, StoreError> {
        let key = encode_name(name)?;
        let _guard = self.0.auth_state_writes.read().await;
        let inner = self.current();
        let (key, realm, update) = (key, realm.to_string(), *update);
        self.write_tx(&inner, &self.0.metrics.auth_retries, |conn| {
            let (key, realm) = (key.clone(), realm.clone());
            Box::pin(async move {
                let params = || vec![Value::Text(realm.clone()), Value::Text(key.clone())];
                let rows = query(
                    conn,
                    "SELECT fail_count, last_failed, last_success FROM auth_state \
                     WHERE realm = ? AND name = ?",
                    params(),
                )
                .await?;
                let exists = !rows.is_empty();
                let mut state = match rows.first() {
                    Some(r) => AuthState {
                        fail_count: u32::try_from(int(r, 0)?).unwrap_or(u32::MAX),
                        last_failed: int(r, 1)?,
                        last_success: int(r, 2)?,
                    },
                    None => AuthState::default(),
                };
                state.apply(&update);
                let values = [
                    Value::Integer(i64::from(state.fail_count)),
                    Value::Integer(state.last_failed),
                    Value::Integer(state.last_success),
                ];
                if exists {
                    let mut p = values.to_vec();
                    p.extend(params());
                    exec(
                        conn,
                        "UPDATE auth_state SET fail_count = ?, last_failed = ?, \
                         last_success = ? WHERE realm = ? AND name = ?",
                        p,
                    )
                    .await?;
                } else {
                    let mut p = params();
                    p.extend(values);
                    exec(
                        conn,
                        "INSERT INTO auth_state (realm, name, fail_count, last_failed, \
                         last_success) VALUES (?, ?, ?, ?, ?)",
                        p,
                    )
                    .await?;
                }
                Ok(state)
            })
        })
        .await
    }
}

impl ReplicaSink for TursoReplica {
    type Rebuild = TursoRebuild;

    async fn checkpoint(&self) -> Result<Option<ReplicaCheckpoint>, StoreError> {
        let inner = self.current();
        let conn = inner.conn().await;
        read_checkpoint(&conn).await
    }

    async fn apply(&self, batch: ChangeBatch) -> Result<ApplyOutcome, StoreError> {
        let inner = self.current();
        let fail_point = self.0.options.fail_point.clone();
        let batch = Arc::new(batch);
        let result = self
            .write_tx(&inner, &self.0.metrics.apply_retries, |conn| {
                let (batch_ref, fail_point) = (Arc::clone(&batch), fail_point.clone());
                Box::pin(async move {
                    let (applied, skipped_stale) =
                        apply_changes(conn, &batch_ref.changes, &fail_point).await?;
                    fail_point.hit("apply:before_checkpoint");
                    write_checkpoint(conn, batch_ref.upto, None).await?;
                    fail_point.hit("apply:before_commit");
                    Ok(ApplyOutcome {
                        applied,
                        skipped_stale,
                    })
                })
            })
            .await;
        *self
            .0
            .last_apply_error
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = result.as_ref().err().map(ToString::to_string);
        self.cleanup_old_files();
        result
    }

    async fn begin_rebuild(&self, snapshot_ts: ReplicationTs) -> Result<TursoRebuild, StoreError> {
        self.cleanup_old_files();
        let current = self
            .current()
            .path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        let mut file_name = format!("replica-{snapshot_ts}.db");
        let mut n = 1;
        while file_name == current
            || self
                .0
                .pending
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .iter()
                .any(|p| p.file_name == file_name)
        {
            file_name = format!("replica-{snapshot_ts}-{n}.db");
            n += 1;
        }
        // An earlier attempt that never committed may have left files behind.
        remove_db_files(&self.0.dir, &file_name);
        let inner = Inner::open(&self.0.dir.join(&file_name), &self.0.options, true).await?;
        Ok(TursoRebuild {
            replica: self.clone(),
            inner,
            file_name,
            snapshot_ts,
        })
    }
}

/// A snapshot being written into a new database (see
/// [`ReplicaSink::begin_rebuild`]).
pub struct TursoRebuild {
    replica: TursoReplica,
    inner: Arc<Inner>,
    file_name: String,
    snapshot_ts: ReplicationTs,
}

impl RebuildWriter for TursoRebuild {
    async fn write(&mut self, changes: Vec<Change>) -> Result<(), StoreError> {
        let fail_point = self.replica.0.options.fail_point.clone();
        let changes = Arc::new(changes);
        self.replica
            .write_tx(&self.inner, &self.replica.0.metrics.apply_retries, |conn| {
                let (changes, fail_point) = (Arc::clone(&changes), fail_point.clone());
                Box::pin(async move {
                    apply_changes(conn, &changes, &fail_point).await?;
                    Ok(())
                })
            })
            .await
    }

    async fn commit(self) -> Result<(), StoreError> {
        let Self {
            replica,
            inner,
            file_name,
            snapshot_ts,
        } = self;
        let _auth_state_guard = replica.0.auth_state_writes.write().await;
        let old_current = replica.current();
        replica.copy_auth_state(&old_current, &inner).await?;
        let ts = snapshot_ts;
        replica
            .write_tx(&inner, &replica.0.metrics.apply_retries, |conn| {
                Box::pin(async move {
                    write_checkpoint(conn, ts, Some(ts)).await?;
                    Ok(())
                })
            })
            .await?;
        // Fold the log into the database file while nobody reads it, then
        // make both durable before the pointer names the new database.
        {
            let conn = inner.conn().await;
            let _ = query(&conn, "PRAGMA wal_checkpoint(TRUNCATE)", Vec::new()).await;
        }
        let dir = &replica.0.dir;
        for f in sidecars(&file_name) {
            sync_file(&dir.join(f));
        }
        TursoReplica::write_pointer(dir, &file_name)?;
        let old = {
            let mut current = replica.0.current.write().unwrap_or_else(|e| e.into_inner());
            std::mem::replace(&mut *current, inner)
        };
        drop(old_current);
        let old_name = old
            .path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        replica
            .0
            .pending
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(Pending {
                file_name: old_name,
                inner: Arc::downgrade(&old),
            });
        drop(old);
        replica.cleanup_old_files();
        Ok(())
    }

    async fn abort(self) -> Result<(), StoreError> {
        let Self {
            replica,
            inner,
            file_name,
            ..
        } = self;
        drop(inner);
        remove_db_files(&replica.0.dir, &file_name);
        Ok(())
    }
}
