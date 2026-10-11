//! The connection pool and the CockroachDB client-side retry protocol.

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use deadpool_postgres::{Manager, ManagerConfig, Object, Pool, RecyclingMethod, Runtime};
use krb5_rs::kdc::replication::ReplicationTs;
use krb5_rs::kdc::StoreError;
use tokio_postgres::types::ToSql;
use tokio_postgres::{Row, Statement};

use crate::config::{parse_url, CockroachConfig};

/// SQLSTATE of a CockroachDB transaction that must be retried.
const RETRY: &str = "40001";

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

/// A transaction in progress: the connection plus the transaction's pinned
/// commit timestamp.
#[derive(Clone)]
pub(crate) struct Tx {
    client: Arc<Object>,
    /// `cluster_logical_timestamp()` of this attempt; stamped on every row the
    /// transaction writes.
    pub ts: ReplicationTs,
}

impl Tx {
    async fn stmt(&self, sql: &str) -> Result<Statement, tokio_postgres::Error> {
        self.client.prepare_cached(sql).await
    }

    pub(crate) async fn query(
        &self,
        sql: &str,
        p: Params<'_>,
    ) -> Result<Vec<Row>, tokio_postgres::Error> {
        let s = self.stmt(sql).await?;
        self.client.query(&s, p).await
    }

    pub(crate) async fn execute(
        &self,
        sql: &str,
        p: Params<'_>,
    ) -> Result<u64, tokio_postgres::Error> {
        let s = self.stmt(sql).await?;
        self.client.execute(&s, p).await
    }

    pub(crate) async fn query_opt(
        &self,
        sql: &str,
        p: Params<'_>,
    ) -> Result<Option<Row>, tokio_postgres::Error> {
        let s = self.stmt(sql).await?;
        self.client.query_opt(&s, p).await
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
            .max_size(config.pool_size.max(1))
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
        let g = self.get().await?;
        let r = g.client().batch_execute(sql).await.map_err(|e| map_err(&e));
        let mut g = g;
        g.clean = r.is_ok();
        r
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

    /// Run `body` in one SERIALIZABLE transaction with the CockroachDB retry
    /// protocol: `SAVEPOINT cockroach_restart`, `ROLLBACK TO SAVEPOINT` and
    /// re-run on SQLSTATE 40001 (also at `RELEASE`; a 40001 at `COMMIT`
    /// restarts the whole transaction), bounded, with backoff and jitter. The
    /// body is re-run from the start each time and sees a fresh `ts`.
    pub(crate) async fn run_tx<'f, R, F>(&self, mut body: F) -> Result<R, StoreError>
    where
        R: Send,
        F: FnMut(Tx) -> BoxFut<'f, R> + Send + 'f,
    {
        let mut attempt = 0u32;
        loop {
            let mut g = self.get().await?;
            let outcome = self.attempt(&g, &mut body, &mut attempt).await;
            match outcome {
                Ok(v) => {
                    g.clean = true;
                    return Ok(v);
                }
                Err(Attempt::Restart) => {
                    // Rolled back cleanly (or the connection is discarded).
                    g.clean = g.client().batch_execute("ROLLBACK").await.is_ok();
                    drop(g);
                    continue;
                }
                Err(Attempt::Fail(e)) => {
                    g.clean = g.client().batch_execute("ROLLBACK").await.is_ok();
                    return Err(e.into_store());
                }
            }
        }
    }

    /// Run `body` in a read-only transaction, optionally `AS OF SYSTEM TIME
    /// aost` (an expression such as `follower_read_timestamp()`). `Tx::ts` is
    /// `cluster_logical_timestamp()` inside the transaction, which is the
    /// transaction's (historical) read timestamp. Retried on SQLSTATE 40001.
    pub(crate) async fn run_read<'f, R, F>(
        &self,
        aost: Option<&str>,
        body: &mut F,
    ) -> Result<R, StoreError>
    where
        R: Send,
        F: FnMut(Tx) -> BoxFut<'f, R> + Send + 'f,
    {
        let begin = match aost {
            Some(a) => format!("BEGIN READ ONLY AS OF SYSTEM TIME {a}"),
            None => "BEGIN READ ONLY".to_string(),
        };
        let mut attempt = 0u32;
        loop {
            let mut g = self.get().await?;
            let client = g.client();
            let result = async {
                client.batch_execute(&begin).await?;
                let row = client
                    .query_one("SELECT cluster_logical_timestamp()::STRING", &[])
                    .await?;
                let ts: String = row.get(0);
                let ts = ts
                    .parse::<ReplicationTs>()
                    .map_err(|e| TxError::Store(StoreError::corrupt(e.to_string())))?;
                let tx = Tx {
                    client: g.handle(),
                    ts,
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
                        TxError::Pg(pg) if is_retry(&pg) => match self.again(&mut attempt).await {
                            Ok(()) => continue,
                            Err(Attempt::Fail(e)) => return Err(e.into_store()),
                            Err(Attempt::Restart) => continue,
                        },
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
    ) -> Result<R, Attempt>
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
        loop {
            let result = async {
                let row = client
                    .query_one("SELECT cluster_logical_timestamp()::STRING", &[])
                    .await?;
                let ts: String = row.get(0);
                let ts = ts
                    .parse::<ReplicationTs>()
                    .map_err(|e| TxError::Store(StoreError::corrupt(e.to_string())))?;
                let tx = Tx {
                    client: g.handle(),
                    ts,
                };
                let out = body(tx).await?;
                self.fail_point.hit("tx:before_release");
                client
                    .batch_execute("RELEASE SAVEPOINT cockroach_restart")
                    .await?;
                Ok::<R, TxError>(out)
            }
            .await;
            match result {
                Ok(out) => {
                    return match client.batch_execute("COMMIT").await {
                        Ok(()) => Ok(out),
                        Err(e) if is_retry(&e) => {
                            self.again(attempt).await?;
                            Err(Attempt::Restart)
                        }
                        Err(e) => Err(fail(e)),
                    };
                }
                Err(TxError::Pg(e)) if is_retry(&e) => {
                    self.again(attempt).await?;
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
        }
    }

    /// Count a retry, back off with jitter, or give up. A give-up is a
    /// failure; a `Restart` outcome is returned by the caller.
    async fn again(&self, attempt: &mut u32) -> Result<(), Attempt> {
        *attempt += 1;
        self.metrics.tx_retries.fetch_add(1, Ordering::Relaxed);
        if *attempt > self.max_retries {
            return Err(Attempt::Fail(TxError::Store(StoreError::conflict(
                "transaction retry limit exceeded",
            ))));
        }
        let base = 2u64.saturating_mul(1 << (*attempt).min(6)).min(100);
        let jitter = u64::from(rand_u32()) % (base / 2 + 1);
        tokio::time::sleep(Duration::from_millis(base / 2 + jitter)).await;
        Ok(())
    }
}

enum Attempt {
    /// The transaction was lost to a commit-time retry error: run it again.
    Restart,
    Fail(TxError),
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
