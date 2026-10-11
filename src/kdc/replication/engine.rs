//! Polling replication engine (docs/architecture/kdb.md §5).

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::sync::watch;

use super::{
    RebuildWriter, ReplicaRegistry, ReplicaSink, ReplicationSource, ReplicationTs, Snapshot,
};
use crate::kdc::{
    AuthoritativeState, ConsistencyGate, GateDecision, PrincipalEntry, StoreErrorKind,
};

/// What to do if the source pruned past this replica's checkpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RebuildPolicy {
    /// Bootstrap a fresh snapshot automatically.
    Auto,
    /// Mark the replica failed and wait for operator intervention.
    Manual,
}

/// Replication engine parameters.
#[derive(Debug, Clone)]
pub struct ReplicationConfig {
    /// Interval between successful polls with no more work (default 1 s).
    pub poll_interval: Duration,
    /// Maximum number of log rows requested per poll (one commit timestamp may
    /// make a batch larger).
    pub batch_limit: usize,
    /// Initial error retry delay.
    pub retry_min: Duration,
    /// Maximum retry delay.
    pub retry_max: Duration,
    /// Action when the source has pruned beyond the local checkpoint.
    pub rebuild: RebuildPolicy,
    /// Heartbeat period.
    pub heartbeat_interval: Duration,
    /// This KDC's stable identifier.
    pub kdc_id: String,
    /// This KDC's CockroachDB region.
    pub region: String,
}

impl Default for ReplicationConfig {
    fn default() -> Self {
        Self {
            poll_interval: Duration::from_secs(1),
            batch_limit: 1000,
            retry_min: Duration::from_millis(100),
            retry_max: Duration::from_secs(30),
            rebuild: RebuildPolicy::Auto,
            heartbeat_interval: Duration::from_secs(5),
            kdc_id: std::env::var("POD_NAME")
                .or_else(|_| hostname())
                .unwrap_or_else(|_| "krb5-rs-kdc".to_string()),
            region: String::new(),
        }
    }
}

fn hostname() -> Result<String, std::env::VarError> {
    std::env::var("HOSTNAME")
}

/// Last successfully applied timestamp, freshness input, counters and error
/// state. Cloned handles share this snapshot; fields are guarded by a short
/// mutex so metric/readiness scrapes never hold the replication task.
#[derive(Debug, Clone)]
pub struct StatusSnapshot {
    /// Initial snapshot has been installed.
    pub bootstrapped: bool,
    /// Highest completely applied timestamp.
    pub applied_ts: ReplicationTs,
    /// Source time minus the last read timestamp, measured by the source.
    pub source_lag: Duration,
    /// Monotonic time at which that read returned; never compare HLC directly
    /// with the KDC wall clock.
    pub observed_at: Option<Instant>,
    /// Consecutive source/sink failures.
    pub consecutive_failures: u64,
    /// Total source/sink failures since this process started.
    pub failures: u64,
    /// Kind of the most recent error, no backend details or secrets.
    pub last_error_kind: Option<StoreErrorKind>,
    /// A rebuild is active.
    pub rebuilding: bool,
    /// Number of changes applied.
    pub applied: u64,
    /// Number of stale changes skipped by the sink.
    pub skipped_stale: u64,
    /// Number of backoff/retry cycles.
    pub retries: u64,
    /// Snapshots installed (the initial bootstrap and rebuilds).
    pub rebuilds: u64,
    /// Most recent snapshot duration.
    pub snapshot_duration: Duration,
    /// Manual rebuild required because the source pruned the checkpoint.
    pub needs_rebuild: bool,
}

/// Alias retained for the concise name used by daemon wiring and metrics.
pub type ReplicaStatus = StatusSnapshot;

impl Default for StatusSnapshot {
    fn default() -> Self {
        Self {
            bootstrapped: false,
            applied_ts: ReplicationTs::ZERO,
            source_lag: Duration::ZERO,
            observed_at: None,
            consecutive_failures: 0,
            failures: 0,
            last_error_kind: None,
            rebuilding: false,
            applied: 0,
            skipped_stale: 0,
            retries: 0,
            rebuilds: 0,
            snapshot_duration: Duration::ZERO,
            needs_rebuild: false,
        }
    }
}

impl StatusSnapshot {
    /// Freshness according to the source clock, independent of local clock
    /// skew. Returns `None` before the first successful source read.
    pub fn freshness(&self) -> Option<Duration> {
        self.observed_at
            .map(|observed| self.source_lag.saturating_add(observed.elapsed()))
    }
}

/// Replicates one `ReplicationSource` into one `ReplicaSink` and publishes
/// heartbeats to a [`ReplicaRegistry`].
pub struct ReplicationEngine<S, K, R>
where
    S: ReplicationSource,
    K: ReplicaSink,
    R: ReplicaRegistry,
{
    source: S,
    sink: K,
    registry: Arc<R>,
    cfg: ReplicationConfig,
    status: Arc<Mutex<StatusSnapshot>>,
}

impl<S, K, R> ReplicationEngine<S, K, R>
where
    S: ReplicationSource,
    K: ReplicaSink,
    R: ReplicaRegistry + 'static,
{
    /// Set up a replication task. It does not start until [`run`](Self::run).
    pub fn new(source: S, sink: K, registry: R, cfg: ReplicationConfig) -> Self {
        Self {
            source,
            sink,
            registry: Arc::new(registry),
            cfg,
            status: Arc::new(Mutex::new(StatusSnapshot::default())),
        }
    }

    /// A shared status snapshot for `/readyz`, `/metrics` and metrics tests.
    pub fn status(&self) -> StatusSnapshot {
        self.status
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// Complete startup bootstrap/freshness work before a daemon binds its
    /// listener. If there is no checkpoint this builds a snapshot; if state
    /// exists it performs one incremental read/apply first.
    pub async fn bootstrap(&self) -> Result<(), crate::kdc::StoreError> {
        loop {
            match self.cycle().await {
                Ok(true) => continue,
                Ok(false) => {
                    self.clear_failure();
                    return Ok(());
                }
                Err(e) => {
                    self.record_failure(e.kind());
                    return Err(e);
                }
            }
        }
    }

    /// Shared status for a [`FreshnessGate`] or a metrics exporter.
    pub fn status_handle(&self) -> Arc<Mutex<StatusSnapshot>> {
        Arc::clone(&self.status)
    }

    /// Run until shutdown. Bootstrap and each `apply` are awaited to
    /// completion and are never cancelled mid-transaction. The independent
    /// heartbeat task stops after the in-flight engine work is done.
    pub async fn run(&self, mut shutdown: watch::Receiver<bool>) {
        let heartbeat = self.spawn_heartbeats(shutdown.clone());
        let mut retry = self.cfg.retry_min.max(Duration::from_millis(1));
        loop {
            if *shutdown.borrow() {
                break;
            }
            match self.cycle().await {
                Ok(progress) => {
                    retry = self.cfg.retry_min.max(Duration::from_millis(1));
                    self.clear_failure();
                    if progress {
                        continue;
                    }
                    tokio::select! {
                        _ = tokio::time::sleep(self.cfg.poll_interval) => {}
                        r = shutdown.changed() => {
                            if r.is_err() || *shutdown.borrow() {
                                break;
                            }
                        }
                    }
                }
                Err(e) => {
                    self.record_failure(e.kind());
                    self.status
                        .lock()
                        .unwrap_or_else(|x| x.into_inner())
                        .retries += 1;
                    tokio::select! {
                        _ = tokio::time::sleep(jitter(retry)) => {}
                        r = shutdown.changed() => {
                            if r.is_err() || *shutdown.borrow() {
                                break;
                            }
                        }
                    }
                    retry = retry.saturating_mul(2).min(self.cfg.retry_max);
                }
            }
        }
        let _ = heartbeat.await;
    }

    fn spawn_heartbeats(&self, mut shutdown: watch::Receiver<bool>) -> tokio::task::JoinHandle<()> {
        let status = Arc::clone(&self.status);
        let registry = Arc::clone(&self.registry);
        let kdc_id = self.cfg.kdc_id.clone();
        let region = self.cfg.region.clone();
        let interval = self.cfg.heartbeat_interval.max(Duration::from_millis(1));
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(interval);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tokio::select! {
                    _ = tick.tick() => {
                        let ts = {
                            let s = status.lock().unwrap_or_else(|e| e.into_inner());
                            s.bootstrapped.then_some(s.applied_ts)
                        };
                        if let Some(ts) = ts {
                            if let Err(e) = registry.heartbeat(&kdc_id, &region, ts).await {
                                let mut s = status.lock().unwrap_or_else(|e| e.into_inner());
                                s.consecutive_failures = s.consecutive_failures.saturating_add(1);
                                s.failures = s.failures.saturating_add(1);
                                s.last_error_kind = Some(e.kind());
                            }
                        }
                    }
                    r = shutdown.changed() => {
                        if r.is_err() || *shutdown.borrow() {
                            break;
                        }
                    }
                }
            }
        })
    }

    /// One cycle. `true` means the source truncated a batch, so the next one
    /// should be requested immediately without polling sleep.
    async fn cycle(&self) -> Result<bool, crate::kdc::StoreError> {
        use super::ReplicaCheckpoint;

        let checkpoint = self.sink.checkpoint().await?;
        let pruned = self.source.pruned_before().await?;
        let needs_snapshot = match (checkpoint, pruned) {
            (None, _) => true,
            (Some(cp), Some(p)) if cp.ts < p => match self.cfg.rebuild {
                RebuildPolicy::Auto => true,
                RebuildPolicy::Manual => {
                    let mut s = self.status.lock().unwrap_or_else(|e| e.into_inner());
                    s.needs_rebuild = true;
                    s.bootstrapped = false;
                    return Err(crate::kdc::StoreError::stale(
                        "replica checkpoint is below pruned_before; manual rebuild required",
                    ));
                }
            },
            _ => false,
        };

        if needs_snapshot {
            self.rebuild().await?;
            return Ok(false);
        }

        let since = checkpoint.unwrap_or(ReplicaCheckpoint {
            ts: ReplicationTs::ZERO,
            snapshot_ts: None,
            applied_at: 0,
        });
        let poll = self
            .source
            .poll(since.ts, self.cfg.batch_limit.max(1))
            .await?;
        let observed = Instant::now();
        let lag = ts_delta(poll.source_now, poll.batch.upto);
        if !poll.batch.changes.is_empty() {
            let outcome = self.sink.apply(poll.batch.clone()).await?;
            let mut s = self.status.lock().unwrap_or_else(|e| e.into_inner());
            s.applied = s.applied.saturating_add(outcome.applied as u64);
            s.skipped_stale = s.skipped_stale.saturating_add(outcome.skipped_stale as u64);
        } else if poll.batch.upto > since.ts {
            // An empty poll advances the freshness timestamp too.
            self.sink
                .apply(super::ChangeBatch {
                    upto: poll.batch.upto,
                    changes: Vec::new(),
                })
                .await?;
        }
        {
            let mut s = self.status.lock().unwrap_or_else(|e| e.into_inner());
            s.bootstrapped = true;
            s.applied_ts = poll.batch.upto.max(since.ts);
            s.source_lag = lag;
            s.observed_at = Some(observed);
            s.needs_rebuild = false;
        }
        Ok(poll.truncated)
    }

    async fn rebuild(&self) -> Result<(), crate::kdc::StoreError> {
        let start = Instant::now();
        {
            self.status
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .rebuilding = true;
        }
        let result = async {
            let mut snapshot = self.source.snapshot().await?;
            let observed = Instant::now();
            let ts = snapshot.ts();
            let source_now = snapshot.source_now();
            let mut writer = self.sink.begin_rebuild(ts).await?;
            let write_result = async {
                loop {
                    match snapshot.next_page().await? {
                        Some(page) if !page.is_empty() => writer.write(page).await?,
                        Some(_) => {}
                        None => break,
                    }
                }
                Ok::<_, crate::kdc::StoreError>(())
            }
            .await;
            if let Err(e) = write_result {
                let _ = writer.abort().await;
                return Err(e);
            }
            // Commit is atomic; do not select shutdown while it is in flight.
            writer.commit().await?;
            Ok::<_, crate::kdc::StoreError>((ts, source_now, observed))
        }
        .await;
        let (ts, source_now, observed) = match result {
            Ok(v) => v,
            Err(e) => {
                self.status
                    .lock()
                    .unwrap_or_else(|x| x.into_inner())
                    .rebuilding = false;
                return Err(e);
            }
        };
        let mut s = self.status.lock().unwrap_or_else(|e| e.into_inner());
        s.bootstrapped = true;
        s.applied_ts = ts;
        s.source_lag = ts_delta(source_now, ts);
        s.observed_at = Some(observed);
        s.rebuilding = false;
        s.needs_rebuild = false;
        s.rebuilds = s.rebuilds.saturating_add(1);
        s.snapshot_duration = start.elapsed();
        Ok(())
    }

    fn clear_failure(&self) {
        let mut s = self.status.lock().unwrap_or_else(|e| e.into_inner());
        s.consecutive_failures = 0;
        s.last_error_kind = None;
    }

    fn record_failure(&self, kind: crate::kdc::StoreErrorKind) {
        let mut s = self.status.lock().unwrap_or_else(|e| e.into_inner());
        s.consecutive_failures = s.consecutive_failures.saturating_add(1);
        s.failures = s.failures.saturating_add(1);
        s.last_error_kind = Some(kind);
    }
}

/// Fail-closed bounded freshness gate (docs §7.1–7.3).
pub struct FreshnessGate {
    status: Arc<Mutex<StatusSnapshot>>,
    max_staleness: Duration,
}

impl FreshnessGate {
    /// Use the engine status and a maximum source-clock staleness.
    pub fn new(status: Arc<Mutex<StatusSnapshot>>, max_staleness: Duration) -> Self {
        Self {
            status,
            max_staleness,
        }
    }

    /// The current source-clock freshness, if bootstrap has completed.
    pub fn freshness(&self) -> Option<Duration> {
        self.status
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .freshness()
    }

    /// Whether the KDC is ready under this freshness bound.
    pub fn ready(&self) -> bool {
        let status = self.status.lock().unwrap_or_else(|e| e.into_inner());
        status.bootstrapped
            && !status.needs_rebuild
            && !status.rebuilding
            && status
                .freshness()
                .is_some_and(|freshness| freshness <= self.max_staleness)
    }
}

impl ConsistencyGate for FreshnessGate {
    async fn check(&self, _principals: &[&PrincipalEntry]) -> GateDecision {
        let status = self.status.lock().unwrap_or_else(|e| e.into_inner());
        if !status.bootstrapped || status.needs_rebuild || status.rebuilding {
            return GateDecision::Reject {
                reason: "REPLICA_NOT_READY".to_string(),
            };
        }
        match status.freshness() {
            Some(freshness) if freshness <= self.max_staleness => GateDecision::Allow,
            _ => GateDecision::Reject {
                reason: "REPLICA_STALE".to_string(),
            },
        }
    }
}

/// Strict fail-closed gate: freshness plus a bounded authoritative security
/// state read for every involved local principal.
pub struct StrictGate<A: AuthoritativeState> {
    freshness: FreshnessGate,
    authority: Arc<A>,
    authoritative_timeout: Duration,
}

impl<A: AuthoritativeState> StrictGate<A> {
    /// Build with the authoritative store and timeout (the recommended default
    /// is 500 ms).
    pub fn new(
        status: Arc<Mutex<StatusSnapshot>>,
        max_staleness: Duration,
        authority: Arc<A>,
        authoritative_timeout: Duration,
    ) -> Self {
        Self {
            freshness: FreshnessGate::new(status, max_staleness),
            authority,
            authoritative_timeout,
        }
    }

    /// The bounded freshness result used by readiness.
    pub fn ready(&self) -> bool {
        self.freshness.ready()
    }
}

impl<A: AuthoritativeState> ConsistencyGate for StrictGate<A> {
    async fn check(&self, principals: &[&PrincipalEntry]) -> GateDecision {
        match self.freshness.check(principals).await {
            GateDecision::Allow => {}
            rejected => return rejected,
        }
        for principal in principals {
            let authoritative = tokio::time::timeout(
                self.authoritative_timeout,
                self.authority
                    .security_state(&principal.name, &principal.realm),
            )
            .await;
            let authoritative = match authoritative {
                Ok(Ok(state)) => state,
                Ok(Err(_)) | Err(_) => {
                    return GateDecision::Reject {
                        reason: "AUTHORITY_UNAVAILABLE".to_string(),
                    }
                }
            };
            if authoritative.epoch > principal.security_epoch
                || authoritative.disabled
                || authoritative.locked
            {
                return GateDecision::Reject {
                    reason: "AUTHORITATIVE_MISMATCH".to_string(),
                };
            }
        }
        GateDecision::Allow
    }
}

/// Positive source-time minus read-time in whole nanoseconds.
fn ts_delta(source_now: ReplicationTs, ts: ReplicationTs) -> Duration {
    let nanos = source_now.wall_nanos.saturating_sub(ts.wall_nanos).max(0);
    Duration::from_nanos(nanos as u64)
}

fn jitter(d: Duration) -> Duration {
    use std::hash::{BuildHasher, Hasher};
    let rand = std::collections::hash_map::RandomState::new()
        .build_hasher()
        .finish();
    let half = d.as_nanos() / 2;
    let spread = (rand as u128) % (half + 1);
    Duration::from_nanos(u64::try_from(half.saturating_add(spread)).unwrap_or(u64::MAX))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kdc::{GateDecision, PrincipalAttributes, SecurityState};
    use crate::types::PrincipalName;

    #[test]
    fn freshness_is_source_lag_plus_monotonic_time_not_kdc_wall_time() {
        let mut s = StatusSnapshot::default();
        assert_eq!(s.freshness(), None);
        s.source_lag = Duration::from_millis(25);
        s.observed_at = Some(Instant::now() - Duration::from_millis(10));
        assert!(s.freshness().expect("observed timestamp") >= Duration::from_millis(35));
    }

    #[test]
    fn ts_lag_never_goes_negative() {
        assert_eq!(
            ts_delta(ReplicationTs::new(5, 0), ReplicationTs::new(10, 0)),
            Duration::ZERO
        );
        assert_eq!(
            ts_delta(
                ReplicationTs::new(10_000_000_000, 0),
                ReplicationTs::new(4_000_000_000, 0)
            ),
            Duration::from_secs(6)
        );
    }

    struct Authority {
        state: Result<SecurityState, crate::kdc::StoreError>,
    }

    impl AuthoritativeState for Authority {
        async fn security_state(
            &self,
            _name: &PrincipalName,
            _realm: &str,
        ) -> Result<SecurityState, crate::kdc::StoreError> {
            self.state.clone()
        }
    }

    struct SlowAuthority;

    impl AuthoritativeState for SlowAuthority {
        async fn security_state(
            &self,
            _name: &PrincipalName,
            _realm: &str,
        ) -> Result<SecurityState, crate::kdc::StoreError> {
            tokio::time::sleep(Duration::from_secs(1)).await;
            Ok(SecurityState::default())
        }
    }

    fn principal() -> PrincipalEntry {
        let mut store = crate::kdc::MemoryStore::new();
        store
            .add_random_key(
                PrincipalName::new_principal("p"),
                "R",
                1,
                &[18],
                PrincipalAttributes::empty(),
            )
            .expect("principal");
        store
            .get(&PrincipalName::new_principal("p"), "R")
            .expect("entry")
    }

    fn fresh_status() -> Arc<Mutex<StatusSnapshot>> {
        Arc::new(Mutex::new(StatusSnapshot {
            bootstrapped: true,
            applied_ts: ReplicationTs::new(100, 0),
            source_lag: Duration::from_millis(5),
            observed_at: Some(Instant::now()),
            ..StatusSnapshot::default()
        }))
    }

    #[tokio::test]
    async fn freshness_gate_fails_closed_until_bootstrapped_and_fresh() {
        let status = Arc::new(Mutex::new(StatusSnapshot::default()));
        let gate = FreshnessGate::new(Arc::clone(&status), Duration::from_secs(30));
        assert_eq!(
            gate.check(&[]).await,
            GateDecision::Reject {
                reason: "REPLICA_NOT_READY".into()
            }
        );
        *status.lock().expect("lock") = StatusSnapshot {
            bootstrapped: true,
            source_lag: Duration::from_secs(31),
            observed_at: Some(Instant::now()),
            ..StatusSnapshot::default()
        };
        assert_eq!(
            gate.check(&[]).await,
            GateDecision::Reject {
                reason: "REPLICA_STALE".into()
            }
        );
    }

    #[tokio::test]
    async fn strict_gate_checks_epoch_disabled_locked_and_authority_timeout() {
        let entry = principal();
        let status = fresh_status();
        let gate = StrictGate::new(
            Arc::clone(&status),
            Duration::from_secs(30),
            Arc::new(Authority {
                state: Ok(SecurityState {
                    epoch: entry.security_epoch + 1,
                    ..SecurityState::default()
                }),
            }),
            Duration::from_millis(100),
        );
        assert_eq!(
            gate.check(&[&entry]).await,
            GateDecision::Reject {
                reason: "AUTHORITATIVE_MISMATCH".into()
            }
        );

        let gate = StrictGate::new(
            Arc::clone(&status),
            Duration::from_secs(30),
            Arc::new(Authority {
                state: Ok(SecurityState {
                    disabled: true,
                    ..SecurityState::default()
                }),
            }),
            Duration::from_millis(100),
        );
        assert_eq!(
            gate.check(&[&entry]).await,
            GateDecision::Reject {
                reason: "AUTHORITATIVE_MISMATCH".into()
            }
        );

        let gate = StrictGate::new(
            status,
            Duration::from_secs(30),
            Arc::new(Authority {
                state: Err(crate::kdc::StoreError::unavailable("down")),
            }),
            Duration::from_millis(100),
        );
        assert_eq!(
            gate.check(&[&entry]).await,
            GateDecision::Reject {
                reason: "AUTHORITY_UNAVAILABLE".into()
            }
        );

        let gate = StrictGate::new(
            fresh_status(),
            Duration::from_secs(30),
            Arc::new(SlowAuthority),
            Duration::from_millis(1),
        );
        assert_eq!(
            gate.check(&[&entry]).await,
            GateDecision::Reject {
                reason: "AUTHORITY_UNAVAILABLE".into()
            }
        );
    }

    #[test]
    fn freshness_status_uses_monotonic_elapsed_and_source_lag() {
        let s = StatusSnapshot {
            bootstrapped: true,
            applied_ts: ReplicationTs::new(10, 0),
            source_lag: Duration::from_millis(50),
            observed_at: Some(Instant::now() - Duration::from_millis(15)),
            ..StatusSnapshot::default()
        };
        assert!(s.freshness().expect("freshness") >= Duration::from_millis(65));
        assert!(s.freshness().expect("freshness") < Duration::from_secs(1));
    }
}
