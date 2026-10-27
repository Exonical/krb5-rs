//! Opening a Turso database: MVCC enforcement, migrations, the connection
//! pool, and the small query helpers the rest of the crate builds on.

use std::path::{Path, PathBuf};

use std::sync::{Arc, Mutex};
use std::time::Duration;

use krb5_rs::kdc::StoreError;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use turso::{Builder, Connection, Database, Row, Value};

use crate::TursoOptions;

/// Newest schema version this build understands.
pub(crate) const SCHEMA_VERSION: i64 = 3;

/// Forward-only migrations: (version, name, SQL).
const MIGRATIONS: &[(i64, &str, &str)] = &[
    (1, "initial", include_str!("migrations/v1.sql")),
    (2, "policy tl_data", include_str!("migrations/v2.sql")),
    (3, "principal tl_data", include_str!("migrations/v3.sql")),
];

/// A failure inside a transaction body: the database's, or one of ours.
pub(crate) enum TxError {
    Turso(turso::Error),
    Store(StoreError),
}

impl From<turso::Error> for TxError {
    fn from(e: turso::Error) -> Self {
        TxError::Turso(e)
    }
}

impl From<StoreError> for TxError {
    fn from(e: StoreError) -> Self {
        TxError::Store(e)
    }
}

impl TxError {
    pub(crate) fn into_store(self) -> StoreError {
        match self {
            TxError::Turso(e) => map_err(e),
            TxError::Store(e) => e,
        }
    }
}

/// Map a database error to a [`StoreError`] without leaking backend types.
pub(crate) fn map_err(e: turso::Error) -> StoreError {
    use turso::Error as E;
    let msg = e.to_string();
    match e {
        E::Busy(_) | E::BusySnapshot(_) | E::Interrupt(_) | E::IoError(..) | E::Readonly(_) => {
            StoreError::unavailable(msg)
        }
        E::Corrupt(_) | E::NotAdb(_) => StoreError::corrupt(msg),
        E::Constraint(_) => StoreError::conflict(msg),
        _ => StoreError::backend(msg),
    }
}

/// An optimistic-concurrency conflict worth retrying.
pub(crate) fn is_conflict(e: &turso::Error) -> bool {
    match e {
        turso::Error::Busy(_) | turso::Error::BusySnapshot(_) => true,
        // turso 0.8.1 reports MVCC write-write conflicts as a plain
        // `Error::Error` (turso_core `LimboError::WriteWriteConflict`,
        // `Conflict`, `TxTerminated`), so classify by message.
        turso::Error::Error(m) => {
            m.starts_with("Write-write conflict")
                || m.starts_with("Conflict")
                || m.starts_with("Transaction terminated")
        }
        _ => false,
    }
}

/// Run `sql` and collect every row.
pub(crate) async fn query(
    conn: &Connection,
    sql: &str,
    params: Vec<Value>,
) -> Result<Vec<Row>, turso::Error> {
    let mut stmt = conn.prepare_cached(sql).await?;
    let mut rows = stmt.query(params).await?;
    let mut out = Vec::new();
    while let Some(row) = rows.next().await? {
        out.push(row);
    }
    Ok(out)
}

/// Run a statement that returns no rows.
pub(crate) async fn exec(
    conn: &Connection,
    sql: &str,
    params: Vec<Value>,
) -> Result<u64, turso::Error> {
    let mut stmt = conn.prepare_cached(sql).await?;
    stmt.execute(params).await
}

pub(crate) fn int(row: &Row, i: usize) -> Result<i64, StoreError> {
    match row.get_value(i).map_err(map_err)? {
        Value::Integer(n) => Ok(n),
        other => Err(StoreError::corrupt(format!(
            "column {i}: expected an integer, found {other:?}"
        ))),
    }
}

pub(crate) fn opt_int(row: &Row, i: usize) -> Result<Option<i64>, StoreError> {
    match row.get_value(i).map_err(map_err)? {
        Value::Null => Ok(None),
        Value::Integer(n) => Ok(Some(n)),
        other => Err(StoreError::corrupt(format!(
            "column {i}: expected an integer, found {other:?}"
        ))),
    }
}

pub(crate) fn text(row: &Row, i: usize) -> Result<String, StoreError> {
    match row.get_value(i).map_err(map_err)? {
        Value::Text(s) => Ok(s),
        _ => Err(StoreError::corrupt(format!("column {i}: expected text"))),
    }
}

pub(crate) fn opt_text(row: &Row, i: usize) -> Result<Option<String>, StoreError> {
    match row.get_value(i).map_err(map_err)? {
        Value::Null => Ok(None),
        Value::Text(s) => Ok(Some(s)),
        _ => Err(StoreError::corrupt(format!("column {i}: expected text"))),
    }
}

pub(crate) fn blob(row: &Row, i: usize) -> Result<Vec<u8>, StoreError> {
    match row.get_value(i).map_err(map_err)? {
        Value::Blob(b) => Ok(b),
        _ => Err(StoreError::corrupt(format!("column {i}: expected a blob"))),
    }
}

pub(crate) fn opt_blob(row: &Row, i: usize) -> Result<Option<Vec<u8>>, StoreError> {
    match row.get_value(i).map_err(map_err)? {
        Value::Null => Ok(None),
        Value::Blob(b) => Ok(Some(b)),
        _ => Err(StoreError::corrupt(format!("column {i}: expected a blob"))),
    }
}

/// A fixed set of connections handed out one task at a time.
pub(crate) struct Pool {
    conns: Mutex<Vec<Connection>>,
    permits: Arc<Semaphore>,
}

/// A connection on loan; returned to the pool on drop.
pub(crate) struct Pooled {
    conn: Option<Connection>,
    pool: Arc<Pool>,
    _permit: OwnedSemaphorePermit,
}

impl std::ops::Deref for Pooled {
    type Target = Connection;

    fn deref(&self) -> &Connection {
        self.conn.as_ref().expect("connection present until drop")
    }
}

impl Drop for Pooled {
    fn drop(&mut self) {
        if let Some(conn) = self.conn.take() {
            self.pool
                .conns
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(conn);
        }
    }
}

/// One open database file with its connection pool.
pub(crate) struct Inner {
    _db: Database,
    pool: Arc<Pool>,
    pub(crate) path: PathBuf,
}

impl Inner {
    /// Open (creating when `create` and missing) the MVCC database at `path`.
    pub(crate) async fn open(
        path: &Path,
        options: &TursoOptions,
        create: bool,
    ) -> Result<Arc<Inner>, StoreError> {
        let existed = std::fs::metadata(path)
            .map(|m| m.len() > 0)
            .unwrap_or(false);
        if !existed && !create {
            return Err(StoreError::not_found(format!(
                "database file {} does not exist",
                path.display()
            )));
        }
        let path_str = path
            .to_str()
            .ok_or_else(|| StoreError::backend("database path is not valid UTF-8"))?;
        let db = Builder::new_local(path_str)
            .experimental_mvcc_passive_checkpoint(options.passive_checkpoint)
            .build()
            .await
            .map_err(map_err)?;
        let conn = db.connect().map_err(map_err)?;
        conn.busy_timeout(options.busy_timeout).map_err(map_err)?;
        if !existed {
            conn.pragma_update("journal_mode", "'mvcc'")
                .await
                .map_err(map_err)?;
        }
        // MVCC only: verify on every open, never fall back to another mode.
        let mode = journal_mode(&conn).await?;
        if !mode.eq_ignore_ascii_case("mvcc") {
            return Err(StoreError::backend(format!(
                "{} is in journal mode {mode:?}; krb5-rs requires MVCC",
                path.display()
            )));
        }
        if let Some(threshold) = options.mvcc_checkpoint_threshold {
            conn.pragma_update("mvcc_checkpoint_threshold", threshold)
                .await
                .map_err(map_err)?;
        }
        migrate(&conn).await?;

        let size = options.pool_size.max(2);
        let mut conns = Vec::with_capacity(size);
        for _ in 0..size {
            let c = db.connect().map_err(map_err)?;
            c.busy_timeout(options.busy_timeout).map_err(map_err)?;
            conns.push(c);
        }
        Ok(Arc::new(Inner {
            _db: db,
            pool: Arc::new(Pool {
                conns: Mutex::new(conns),
                permits: Arc::new(Semaphore::new(size)),
            }),
            path: path.to_path_buf(),
        }))
    }

    /// Borrow a connection, waiting if every one is in use.
    pub(crate) async fn conn(&self) -> Pooled {
        let permit = Arc::clone(&self.pool.permits)
            .acquire_owned()
            .await
            .expect("the pool semaphore is never closed");
        let conn = self
            .pool
            .conns
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .pop()
            .expect("a permit guarantees a free connection");
        Pooled {
            conn: Some(conn),
            pool: Arc::clone(&self.pool),
            _permit: permit,
        }
    }
}

/// `PRAGMA journal_mode`.
pub(crate) async fn journal_mode(conn: &Connection) -> Result<String, StoreError> {
    let rows = query(conn, "PRAGMA journal_mode", Vec::new())
        .await
        .map_err(map_err)?;
    let row = rows
        .first()
        .ok_or_else(|| StoreError::backend("PRAGMA journal_mode returned nothing"))?;
    text(row, 0)
}

/// The schema version recorded in the database (0 for none).
pub(crate) async fn schema_version(conn: &Connection) -> Result<i64, StoreError> {
    let rows = query(
        conn,
        "SELECT COALESCE(MAX(version), 0) FROM schema_migrations",
        Vec::new(),
    )
    .await
    .map_err(map_err)?;
    int(
        rows.first()
            .ok_or_else(|| StoreError::corrupt("no version row"))?,
        0,
    )
}

/// Create `schema_migrations` and apply every migration newer than the
/// database. Idempotent and forward only; a database newer than this build
/// is refused.
async fn migrate(conn: &Connection) -> Result<(), StoreError> {
    exec(
        conn,
        "CREATE TABLE IF NOT EXISTS schema_migrations (\
         version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at INTEGER NOT NULL)",
        Vec::new(),
    )
    .await
    .map_err(map_err)?;
    let current = schema_version(conn).await?;
    if current > SCHEMA_VERSION {
        return Err(StoreError::backend(format!(
            "database schema version {current} is newer than the supported {SCHEMA_VERSION}"
        )));
    }
    for (version, name, sql) in MIGRATIONS.iter().filter(|(v, _, _)| *v > current) {
        let applied = async {
            conn.execute("BEGIN", ()).await?;
            conn.execute_batch(sql).await?;
            exec(
                conn,
                "INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, ?, ?)",
                vec![
                    Value::Integer(*version),
                    Value::Text((*name).to_string()),
                    Value::Integer(now_unix()),
                ],
            )
            .await?;
            conn.execute("COMMIT", ()).await?;
            Ok::<(), turso::Error>(())
        }
        .await;
        if let Err(e) = applied {
            let _ = conn.execute("ROLLBACK", ()).await;
            return Err(map_err(e));
        }
    }
    Ok(())
}

pub(crate) fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

/// Delay before retry `attempt` (0-based): exponential from `base`, capped.
pub(crate) fn backoff(attempt: u32, base: Duration, max: Duration) -> Duration {
    base.saturating_mul(1u32 << attempt.min(16)).min(max)
}
