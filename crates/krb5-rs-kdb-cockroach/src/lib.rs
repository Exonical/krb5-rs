//! CockroachDB authoritative database module for the krb5-rs KDC
//! (docs/architecture/kdb.md).

mod config;
mod db;
mod schema;
mod store;
mod tls;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

pub use config::{redact_url, CockroachConfig, ReplicationRead};
pub use db::Metrics;
pub use schema::{MigrateOptions, MigrateReport, MultiRegion, SCHEMA_VERSION};
pub use store::{CockroachSnapshot, CockroachStore, ReplicaStatus, WaitOutcome};

type Hook = Arc<dyn Fn(&str) + Send + Sync>;

/// A hook called at named points of a transaction (tests inject failures).
#[derive(Clone, Default)]
pub struct FailPoint {
    hook: Option<Hook>,
    ambiguous_commit: Arc<AtomicBool>,
}

impl FailPoint {
    /// Call `f` with the name of every point reached.
    pub fn new(f: impl Fn(&str) + Send + Sync + 'static) -> Self {
        Self {
            hook: Some(Arc::new(f)),
            ambiguous_commit: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Simulate a connection losing the response after the server committed.
    /// The database commit is real; the test hook reports it to the retry
    /// protocol as if it were SQLSTATE 40003.
    #[doc(hidden)]
    pub fn ambiguous_commit_once() -> Self {
        Self {
            hook: None,
            ambiguous_commit: Arc::new(AtomicBool::new(true)),
        }
    }

    pub(crate) fn hit(&self, point: &str) {
        if let Some(f) = &self.hook {
            f(point);
        }
    }

    pub(crate) fn take_ambiguous_commit(&self) -> bool {
        self.ambiguous_commit.swap(false, Ordering::SeqCst)
    }
}

impl std::fmt::Debug for FailPoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(
            if self.hook.is_some() || self.ambiguous_commit.load(Ordering::Relaxed) {
                "FailPoint(set)"
            } else {
                "FailPoint(none)"
            },
        )
    }
}

mod reporter;
pub use reporter::CockroachLockoutReporter;

/// Run `sql` (one or more statements, no result) with the given settings.
/// For administration scripts and tests.
#[doc(hidden)]
pub async fn run_sql(config: &CockroachConfig, sql: &str) -> Result<(), krb5_rs::kdc::StoreError> {
    db::Db::connect(config.clone())?.simple(sql).await
}

/// Run a query and return its first column as text. For tests.
#[doc(hidden)]
pub async fn query_text(
    config: &CockroachConfig,
    sql: &str,
) -> Result<Vec<String>, krb5_rs::kdc::StoreError> {
    let rows = db::Db::connect(config.clone())?.rows(sql, &[]).await?;
    Ok(rows.iter().map(|r| r.get::<_, String>(0)).collect())
}
