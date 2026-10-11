//! Fire-and-forget lockout reporting to the authority.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use krb5_rs::kdc::replication::LockoutRecord;
use krb5_rs::kdc::{LockoutReport, LockoutReporter};
use tokio::sync::mpsc;

use crate::store::CockroachStore;

#[derive(Debug, Default)]
struct Counters {
    reported: AtomicU64,
    dropped: AtomicU64,
    failed: AtomicU64,
}

/// Reports tripped lockouts to CockroachDB through a bounded queue and a
/// background task that retries with backoff. [`LockoutReporter::report`]
/// never blocks and never fails the request: when the queue is full the
/// report is dropped and counted.
///
/// The store should connect as the `kdc_replica` user: reporting writes only
/// `lockouts` and `replication_log`, never `principals`.
#[derive(Clone)]
pub struct CockroachLockoutReporter {
    tx: mpsc::Sender<LockoutRecord>,
    counters: Arc<Counters>,
    source_kdc: Arc<str>,
}

impl std::fmt::Debug for CockroachLockoutReporter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CockroachLockoutReporter")
            .field("source_kdc", &self.source_kdc)
            .finish_non_exhaustive()
    }
}

impl CockroachLockoutReporter {
    /// Start the background task (needs a Tokio runtime). `queue` bounds the
    /// reports waiting to be written; `source_kdc` names this KDC in the
    /// records.
    pub fn spawn(store: CockroachStore, source_kdc: impl Into<String>, queue: usize) -> Self {
        let (tx, mut rx) = mpsc::channel::<LockoutRecord>(queue.max(1));
        let counters = Arc::new(Counters::default());
        let worker = Arc::clone(&counters);
        tokio::spawn(async move {
            while let Some(record) = rx.recv().await {
                let mut delay = Duration::from_millis(100);
                let mut done = false;
                for _ in 0..6 {
                    if store.report_lockout(&record).await.is_ok() {
                        done = true;
                        break;
                    }
                    tokio::time::sleep(delay).await;
                    delay = (delay * 2).min(Duration::from_secs(5));
                }
                let slot = if done {
                    &worker.reported
                } else {
                    &worker.failed
                };
                slot.fetch_add(1, Ordering::Relaxed);
            }
        });
        Self {
            tx,
            counters,
            source_kdc: source_kdc.into().into(),
        }
    }

    /// Reports written to CockroachDB.
    pub fn reported(&self) -> u64 {
        self.counters.reported.load(Ordering::Relaxed)
    }

    /// Reports dropped because the queue was full.
    pub fn dropped(&self) -> u64 {
        self.counters.dropped.load(Ordering::Relaxed)
    }

    /// Reports given up on after the retries.
    pub fn failed(&self) -> u64 {
        self.counters.failed.load(Ordering::Relaxed)
    }
}

impl LockoutReporter for CockroachLockoutReporter {
    fn report(&self, report: LockoutReport) {
        let record = LockoutRecord {
            realm: report.realm,
            name: report.principal,
            locked_at: report.stamp,
            unlock_at: (report.lockout_duration > 0).then(|| {
                report
                    .stamp
                    .saturating_add(i64::from(report.lockout_duration))
            }),
            source_kdc: self.source_kdc.to_string(),
        };
        if self.tx.try_send(record).is_err() {
            self.counters.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }
}
