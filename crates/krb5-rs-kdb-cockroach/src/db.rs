//! The connection pool and the CockroachDB client-side retry protocol.

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use deadpool_postgres::{Manager, ManagerConfig, Object, Pool, RecyclingMethod, Runtime};
use krb5_rs::kdc::replication::ReplicationTs;
use krb5_rs::kdc::StoreError;
use rand::Rng;
use tokio_postgres::types::ToSql;
use tokio_postgres::{Row, Statement};

use crate::config::{parse_url, CockroachConfig};

/// SQLSTATE of a CockroachDB transaction that must be retried.
const RETRY: &str = "40001";
const AMBIGUOUS: &str = "40003";

/// Params for a statement.
pub(crate) type Params<'a> = &'a [&'a (dyn ToSql + Sync)];

/// A failure inside a transaction body: the database's, or ours.
pub(crate) enum TxError {
    Pg(tokio_postgres::Error),
    Store(StoreError),
}

impl From<tokio_postgres::Error> for TxError {
    fn from(e: tokio_postgres::Error) -> Self {
        TxError::Pg(e)
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
            TxError::Pg(e) => map_err(&e),
            TxError::Store(e) => e,
        }
    }
}

/// Map a driver error to a [`StoreError`] without leaking secrets (the driver
/// never includes passwords or key bytes in its errors).
pub(crate) fn map_err(e: &tokio_postgres::Error) -> StoreError {
    let msg = match e.as_db_error() {
        Some(db) => format!("{} (SQLSTATE {})", db.message(), db.code().code()),
        None => e.to_string(),
    };
    match e.code().map(|c| c.code()) {
        Some("40001" | "40003") => {
            StoreError::conflict(format!("transaction retry exhausted: {msg}"))
        }
        Some("23505") => StoreError::conflict(msg),
        Some("57014") => StoreError::unavailable(format!("statement timed out: {msg}")),
        Some(s) if s.starts_with("08") || s.starts_with("57") || s.starts_with("53") => {
            StoreError::unavailable(msg)
        }
        Some(_) => StoreError::backend(msg),
        None if e.is_closed() => StoreError::unavailable(msg),
        None => StoreError::unavailable(msg),
    }
}

fn is_retry(e: &tokio_postgres::Error) -> bool {
    e.code().is_some_and(|c| c.code() == RETRY)
}

/// A pooled connection that is discarded, not recycled, unless a transaction
/// ended cleanly (a dropped future must not leave one open in the pool).
struct Guarded {
    conn: Option<Arc<Object>>,
    clean: bool,
}

impl Guarded {
    fn client(&self) -> &Object {
        self.conn.as_ref().expect("connection present until drop")
    }

    fn handle(&self) -> Arc<Object> {
        Arc::clone(self.conn.as_ref().expect("connection present until drop"))
    }
}

impl Drop for Guarded {
    fn drop(&mut self) {
        if let Some(conn) = self.conn.take() {
            if !self.clean {
                if let Ok(obj) = Arc::try_unwrap(conn) {
                    drop(Object::take(obj));
                }
            }
        }
    }
}

/// Counters.
#[derive(Debug, Default)]
pub struct Metrics {
    pub(crate) tx_retries: AtomicU64,
}

impl Metrics {
    /// Transactions retried after a serialization failure (SQLSTATE 40001).
    pub fn tx_retries(&self) -> u64 {
        self.tx_retries.load(Ordering::Relaxed)
    }
}

/// A transaction in progress.
#[derive(Clone)]
pub(crate) struct Tx {
    client: Arc<Object>,
    /// Read timestamp, or the transaction start timestamp for a write.
    pub ts: ReplicationTs,
    /// The authority's present HLC sampled with the read timestamp. For a
    /// historical read, this is distinct from `ts`.
    pub source_now: ReplicationTs,
    /// Stable id across attempts for ambiguous commit verification.
    pub transaction_id: String,
}

impl Tx {
    async fn stmt(&self, sql: &str) -> Result<Statement, tokio_postgres::Error> {
        self.client.prepare_cached(sql).await
    }

    pub(crate) async fn query(&self, sql: &str, p: Params<'_>) -> Result<Vec<Row>, TxError> {
        let s = self.stmt(sql).await?;
        Ok(self.client.query(&s, p).await?)
    }

    pub(crate) async fn query_one(&self, sql: &str, p: Params<'_>) -> Result<Row, TxError> {
        let s = self.stmt(sql).await?;
        Ok(self.client.query_one(&s, p).await?)
    }

    pub(crate) async fn execute(&self, sql: &str, p: Params<'_>) -> Result<u64, TxError> {
        let s = self.stmt(sql).await?;
        Ok(self.client.execute(&s, p).await?)
    }

    pub(crate) async fn query_opt(&self, sql: &str, p: Params<'_>) -> Result<Option<Row>, TxError> {
        let s = self.stmt(sql).await?;
        Ok(self.client.query_opt(&s, p).await?)
    }
}

pub(crate) type BoxFut<'f, R> = Pin<Box<dyn Future<Output = Result<R, TxError>> + Send + 'f>>;

/// Pool plus retry policy.
pub(crate) struct Db {
    pool: Pool,
    pub(crate) config: CockroachConfig,
    pub(crate) metrics: Metrics,
    pub(crate) max_retries: u32,
    pub(crate) fail_point: crate::FailPoint,
}

impl Db {
    pub(crate) fn connect(config: CockroachConfig) -> Result<Arc<Db>, StoreError> {
        let parsed = parse_url(&config)?;
        let mgr_cfg = ManagerConfig {
            recycling_method: RecyclingMethod::Fast,
        };
        let manager = if parsed.tls {
            let tls = crate::tls::connector(&config)?;
            Manager::from_config(parsed.pg, tls, mgr_cfg)
        } else {
            tracing_warn_insecure();
            Manager::from_config(parsed.pg, tokio_postgres::NoTls, mgr_cfg)
        };
        let pool = Pool::builder(manager)
            // Ambiguous commit resolution reads the marker on a second
            // connection while the original one is discarded.
            .max_size(config.pool_size.max(2))
            .wait_timeout(Some(config.connect_timeout))
            .create_timeout(Some(config.connect_timeout))
            .runtime(Runtime::Tokio1)
            .build()
            .map_err(|e| StoreError::backend(format!("building the pool: {e}")))?;
        Ok(Arc::new(Db {
            pool,
            config,
            metrics: Metrics::default(),
            max_retries: 80,
            fail_point: crate::FailPoint::default(),
        }))
    }

    async fn get(&self) -> Result<Guarded, StoreError> {
        if let Some(max_idle) = self.config.pool_idle_timeout.filter(|d| !d.is_zero()) {
            let _ = self
                .pool
                .retain(|_, metrics| metrics.last_used() < max_idle);
        }
        let conn = self.pool.get().await.map_err(|e| match e {
            deadpool_postgres::PoolError::Backend(e) => map_err(&e),
            other => StoreError::unavailable(format!("connection pool: {other}")),
        })?;
        Ok(Guarded {
            conn: Some(Arc::new(conn)),
            clean: false,
        })
    }

    /// A connection for non-transactional statements (migrations, DDL).
    pub(crate) async fn simple(&self, sql: &str) -> Result<(), StoreError> {
        let mut attempt = 0;
        loop {
            let mut g = self.get().await?;
            match g.client().batch_execute(sql).await {
                Ok(()) => {
                    g.clean = true;
                    return Ok(());
                }
                Err(error) if is_retry(&error) => {
                    drop(g);
                    self.again(&mut attempt)
                        .await
                        .map_err(TxError::into_store)?;
                }
                Err(error) => return Err(map_err(&error)),
            }
        }
    }

    /// Run `sql` and return its rows outside a transaction.
    pub(crate) async fn rows(&self, sql: &str, p: Params<'_>) -> Result<Vec<Row>, StoreError> {
        let mut g = self.get().await?;
        let r = async {
            let s = g.client().prepare_cached(sql).await?;
            g.client().query(&s, p).await
        }
        .await
        .map_err(|e| map_err(&e));
        g.clean = true;
        r
    }

    /// Run `body` in one SERIALIZABLE transaction with CockroachDB's
    /// `SAVEPOINT cockroach_restart` retry protocol on SQLSTATE 40001.
    pub(crate) async fn run_tx<'f, R, F>(&self, mut body: F) -> Result<R, StoreError>
    where
        R: Send,
        F: FnMut(Tx) -> BoxFut<'f, R> + Send + 'f,
    {
        let mut attempt = 0u32;
        let tx_id = transaction_id();
        let mut ambiguous_result = None;
        loop {
            if ambiguous_result.is_some() && self.marker_exists(&tx_id).await? {
                return Ok(ambiguous_result
                    .take()
                    .expect("an ambiguous output was checked above"));
            }
            let mut g = self.get().await?;
            let outcome = self.attempt(&g, &mut body, &mut attempt, &tx_id).await;
            match outcome {
                Ok(v) => {
                    g.clean = true;
                    return Ok(v);
                }
                Err(Attempt::Restart) => {
                    // COMMIT returned a retryable error after the savepoint
                    // was released, so retry the complete transaction.
                    let _ = g.client().batch_execute("ROLLBACK").await;
                    drop(g);
                    continue;
                }
                Err(Attempt::Ambiguous(v)) => {
                    // The old connection is not reused after an unknown
                    // COMMIT outcome. A retry carries the same marker id.
                    ambiguous_result = Some(v);
                    drop(g);
                    continue;
                }
                Err(Attempt::Committed(v)) => {
                    // The marker proves the transaction committed. Discard
                    // the connection whose COMMIT response was ambiguous.
                    drop(g);
                    return Ok(v);
                }
                Err(Attempt::Fail(e)) => {
                    g.clean = g.client().batch_execute("ROLLBACK").await.is_ok();
                    if ambiguous_result.is_some() && self.marker_exists(&tx_id).await? {
                        drop(g);
                        return Ok(ambiguous_result
                            .take()
                            .expect("an ambiguous output was checked above"));
                    }
                    return Err(e.into_store());
                }
            }
        }
    }

    /// Run `body` in a read-only transaction, optionally `AS OF SYSTEM TIME
    /// aost` (an expression such as `follower_read_timestamp()`). The present
    /// HLC is sampled from the source, then the transaction is opened at the
    /// AOST expression and its exact read HLC is taken from inside it.
    /// Retried on SQLSTATE 40001.
    pub(crate) async fn run_read<'f, R, F>(
        &self,
        aost: Option<&str>,
        body: &mut F,
    ) -> Result<R, StoreError>
    where
        R: Send,
        F: FnMut(Tx) -> BoxFut<'f, R> + Send + 'f,
    {
        let mut attempt = 0u32;
        loop {
            let mut g = self.get().await?;
            let client = g.client();
            let result = async {
                let row = client
                    .query_one("SELECT cluster_logical_timestamp()::STRING", &[])
                    .await?;
                let source_now: String = row.get(0);
                let source_now = source_now
                    .parse::<ReplicationTs>()
                    .map_err(|e| TxError::Store(StoreError::corrupt(e.to_string())))?;
                let begin = match aost {
                    Some(expr) => format!("BEGIN READ ONLY AS OF SYSTEM TIME {expr}"),
                    None => format!("BEGIN READ ONLY AS OF SYSTEM TIME '{source_now}'"),
                };
                client.batch_execute(&begin).await?;
                let row = client
                    .query_one("SELECT cluster_logical_timestamp()::STRING", &[])
                    .await?;
                let text: String = row.get(0);
                let ts = text
                    .parse::<ReplicationTs>()
                    .map_err(|e| TxError::Store(StoreError::corrupt(e.to_string())))?;
                let tx = Tx {
                    client: g.handle(),
                    ts,
                    source_now,
                    transaction_id: String::new(),
                };
                let out = body(tx).await?;
                client.batch_execute("COMMIT").await?;
                Ok::<R, TxError>(out)
            }
            .await;
            match result {
                Ok(out) => {
                    g.clean = true;
                    return Ok(out);
                }
                Err(e) => {
                    g.clean = g.client().batch_execute("ROLLBACK").await.is_ok();
                    match e {
                        TxError::Pg(pg) if is_retry(&pg) => {
                            self.again(&mut attempt)
                                .await
                                .map_err(TxError::into_store)?;
                            continue;
                        }
                        other => return Err(other.into_store()),
                    }
                }
            }
        }
    }

    async fn attempt<'f, R, F>(
        &self,
        g: &Guarded,
        body: &mut F,
        attempt: &mut u32,
        tx_id: &str,
    ) -> Result<R, Attempt<R>>
    where
        R: Send,
        F: FnMut(Tx) -> BoxFut<'f, R> + Send + 'f,
    {
        let client = g.client();
        let fail = |e: tokio_postgres::Error| Attempt::Fail(TxError::Pg(e));
        client
            .batch_execute("BEGIN ISOLATION LEVEL SERIALIZABLE")
            .await
            .map_err(fail)?;
        client
            .batch_execute("SAVEPOINT cockroach_restart")
            .await
            .map_err(fail)?;
        let out = loop {
            let attempt_id = transaction_id();
            let result = async {
                let row = client
                    .query_one(
                        "SELECT (EXTRACT(EPOCH FROM now()) * 1000000000)::INT8::STRING",
                        &[],
                    )
                    .await?;
                let text: String = row.get(0);
                let ts = text
                    .parse::<ReplicationTs>()
                    .map_err(|e| TxError::Store(StoreError::corrupt(e.to_string())))?;
                let tx = Tx {
                    client: g.handle(),
                    ts,
                    source_now: ts,
                    transaction_id: tx_id.to_string(),
                };
                let out = body(tx).await?;
                client
                    .execute(
                        "INSERT INTO transaction_markers (id, logical_id) VALUES ($1, $2)",
                        &[&attempt_id, &tx_id],
                    )
                    .await?;
                self.fail_point.hit("tx:before_release");
                client
                    .batch_execute("RELEASE SAVEPOINT cockroach_restart")
                    .await?;
                Ok::<R, TxError>(out)
            }
            .await;
            match result {
                Ok(out) => break out,
                Err(TxError::Pg(e)) if is_retry(&e) => {
                    self.again(attempt).await.map_err(Attempt::Fail)?;
                    if client
                        .batch_execute("ROLLBACK TO SAVEPOINT cockroach_restart")
                        .await
                        .is_err()
                    {
                        return Err(Attempt::Restart);
                    }
                }
                Err(e) => return Err(Attempt::Fail(e)),
            }
        };
        match client.batch_execute("COMMIT").await {
            Ok(()) if self.fail_point.take_ambiguous_commit() => {
                self.resolve_ambiguous(tx_id, out, attempt).await
            }
            Ok(()) => Ok(out),
            Err(e) if is_retry(&e) => {
                self.again(attempt).await.map_err(Attempt::Fail)?;
                Err(Attempt::Restart)
            }
            Err(e) if is_ambiguous(&e) => self.resolve_ambiguous(tx_id, out, attempt).await,
            Err(e) => Err(fail(e)),
        }
    }

    async fn resolve_ambiguous<R>(
        &self,
        tx_id: &str,
        output: R,
        attempt: &mut u32,
    ) -> Result<R, Attempt<R>> {
        match self.marker_exists(tx_id).await {
            Ok(true) => Err(Attempt::Committed(output)),
            Ok(false) => {
                self.again(attempt).await.map_err(Attempt::Fail)?;
                Err(Attempt::Ambiguous(output))
            }
            Err(e) => Err(Attempt::Fail(TxError::Store(e))),
        }
    }

    async fn marker_exists(&self, tx_id: &str) -> Result<bool, StoreError> {
        let rows = self
            .rows(
                "SELECT 1::INT8 FROM transaction_markers \
                 WHERE logical_id = $1 LIMIT 1",
                &[&tx_id],
            )
            .await?;
        Ok(!rows.is_empty())
    }

    /// Count a retry, back off with jitter, or give up. A give-up is a
    /// failure; a `Restart` outcome is returned by the caller.
    async fn again(&self, attempt: &mut u32) -> Result<(), TxError> {
        *attempt += 1;
        self.metrics.tx_retries.fetch_add(1, Ordering::Relaxed);
        if *attempt > self.max_retries {
            return Err(TxError::Store(StoreError::conflict(
                "transaction retry limit exceeded",
            )));
        }
        let base = 2u64.saturating_mul(1 << (*attempt).min(6)).min(100);
        let jitter = u64::from(rand_u32()) % (base / 2 + 1);
        tokio::time::sleep(Duration::from_millis(base / 2 + jitter)).await;
        Ok(())
    }
}

enum Attempt<R> {
    /// The transaction was lost to a commit-time retry error: run it again.
    Restart,
    /// Commit may still be resolving; retry with the same marker id and
    /// retain the result in case the marker appears.
    Ambiguous(R),
    /// The marker confirms that COMMIT succeeded despite the lost response.
    Committed(R),
    Fail(TxError),
}

fn is_ambiguous(e: &tokio_postgres::Error) -> bool {
    e.code().is_some_and(|c| c.code() == AMBIGUOUS)
}

pub(crate) fn transaction_id() -> String {
    let mut id = [0u8; 16];
    rand::rng().fill_bytes(&mut id);
    id[6] = (id[6] & 0x0f) | 0x40;
    id[8] = (id[8] & 0x3f) | 0x80;
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut formatted = [0u8; 36];
    let mut output = 0;
    for (index, byte) in id.into_iter().enumerate() {
        if matches!(index, 4 | 6 | 8 | 10) {
            formatted[output] = b'-';
            output += 1;
        }
        formatted[output] = HEX[(byte >> 4) as usize];
        formatted[output + 1] = HEX[(byte & 0x0f) as usize];
        output += 2;
    }
    String::from_utf8(formatted.to_vec()).expect("hexadecimal UUID is ASCII")
}

fn rand_u32() -> u32 {
    use std::hash::{BuildHasher, Hasher};
    std::collections::hash_map::RandomState::new()
        .build_hasher()
        .finish() as u32
}

fn tracing_warn_insecure() {
    eprintln!("krb5-rs-kdb-cockroach: WARNING: connecting to CockroachDB without TLS (cockroach_insecure)");
}

#[cfg(test)]
mod tests {
    use super::transaction_id;

    #[test]
    fn transaction_id_is_a_compact_v4_uuid() {
        let id = transaction_id();
        assert_eq!(id.len(), 36);
        assert_eq!(&id[8..9], "-");
        assert_eq!(&id[13..14], "-");
        assert_eq!(&id[18..19], "-");
        assert_eq!(&id[23..24], "-");
        assert_eq!(&id[14..15], "4");
        assert!(matches!(&id[19..20], "8" | "9" | "a" | "b"));
    }
}
