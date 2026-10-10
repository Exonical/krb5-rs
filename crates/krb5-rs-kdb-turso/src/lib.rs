//! Turso (MVCC) local replica database for the krb5-rs KDC.
//!
//! [`TursoReplica`] is an optional plug-in: it implements the KDC's
//! [`PrincipalStore`](krb5_rs::kdc::PrincipalStore),
//! [`PolicyStore`](krb5_rs::kdc::PolicyStore),
//! [`AuthStateStore`](krb5_rs::kdc::AuthStateStore) and
//! [`HealthCheck`](krb5_rs::kdc::HealthCheck) over a local database file, and
//! [`ReplicaSink`](krb5_rs::kdc::replication::ReplicaSink) so a replication
//! engine can keep it current (docs/architecture/kdb.md).
//!
//! MVCC is mandatory: a database that is not in MVCC journal mode is refused
//! on create and on every open, never switched back to WAL.
//!
//! Turso limits that shape the design: WITHOUT ROWID tables cannot have
//! indexes (rowid tables with UNIQUE indexes are used); row versions live in
//! memory; isolation is snapshot, not serializable; and
//! `wal_checkpoint(TRUNCATE)` blocks readers, so it is only used on a database
//! nobody reads yet (a rebuild). The passive MVCC checkpoint is experimental
//! and off by default ([`TursoOptions::passive_checkpoint`]).

mod changes;
mod db;
mod replica;

use std::sync::Arc;
use std::time::Duration;

pub use replica::{ReplicaMetrics, ReplicaStatus, TursoRebuild, TursoReplica};

/// A hook called at named points of a write (tests inject failures there).
#[derive(Clone, Default)]
pub struct FailPoint(Option<Hook>);

type Hook = Arc<dyn Fn(&str) + Send + Sync>;

impl FailPoint {
    /// Call `f` with the name of every point reached.
    pub fn new(f: impl Fn(&str) + Send + Sync + 'static) -> Self {
        Self(Some(Arc::new(f)))
    }

    pub(crate) fn hit(&self, point: &str) {
        if let Some(f) = &self.0 {
            f(point);
        }
    }
}

impl std::fmt::Debug for FailPoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(if self.0.is_some() {
            "FailPoint(set)"
        } else {
            "FailPoint(none)"
        })
    }
}

/// How a replica is opened.
#[derive(Debug, Clone)]
pub struct TursoOptions {
    /// Connections in the pool (at least 2; one is needed for writes).
    pub pool_size: usize,
    /// `PRAGMA mvcc_checkpoint_threshold`: logical-log bytes that trigger a
    /// checkpoint (`-1` disables it); `None` keeps Turso's default.
    pub mvcc_checkpoint_threshold: Option<i64>,
    /// Enable Turso's experimental passive MVCC checkpoint. Off by default:
    /// it is experimental in 0.8.1.
    pub passive_checkpoint: bool,
    /// Per-connection busy timeout.
    pub busy_timeout: Duration,
    /// Retries of a write that hit an MVCC conflict.
    pub max_retries: u32,
    /// First retry delay; doubles each retry.
    pub retry_base_delay: Duration,
    /// Upper bound of the retry delay.
    pub retry_max_delay: Duration,
    /// Failure injection for tests.
    #[doc(hidden)]
    pub fail_point: FailPoint,
}

impl Default for TursoOptions {
    fn default() -> Self {
        Self {
            pool_size: 8,
            mvcc_checkpoint_threshold: None,
            passive_checkpoint: false,
            busy_timeout: Duration::from_secs(5),
            max_retries: 12,
            retry_base_delay: Duration::from_millis(2),
            retry_max_delay: Duration::from_millis(200),
            fail_point: FailPoint::default(),
        }
    }
}
