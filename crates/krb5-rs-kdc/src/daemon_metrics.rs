//! Prometheus metrics and a tiny HTTP/1.1 scrape/health endpoint.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use krb5_rs::kdc::replication::StatusSnapshot;
use krb5_rs::kdc::{Outcome, RequestKind, RequestSummary};
use prometheus_client::encoding::text::encode;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::metrics::histogram::{exponential_buckets, Histogram};
use prometheus_client::registry::Registry;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::task::JoinSet;
use tracing::warn;

const CONNECTION_TIMEOUT: Duration = Duration::from_secs(5);

/// Prometheus registry plus handles used by the daemon's instrumented paths.
#[derive(Debug)]
pub struct Metrics {
    registry: Registry,
    requests: Family<Vec<(String, String)>, Counter>,
    gate_rejections: Family<Vec<(String, String)>, Counter>,
    principal_lookup: Histogram,
    store_time: Family<Vec<(String, String)>, Histogram>,
    local_db_errors: Counter,
    replication_freshness: Gauge<f64, AtomicU64>,
    replication_applied_ts: Gauge<f64, AtomicU64>,
    replication_applied: Counter,
    replication_skipped_stale: Counter,
    replication_retries: Counter,
    replication_failures: Counter,
    replication_rebuilds: Counter,
    replication_snapshot_duration: Histogram,
    lockout_reports: Counter,
    lockout_drops: Counter,
    last_applied: AtomicU64,
    last_skipped_stale: AtomicU64,
    last_retries: AtomicU64,
    last_failures: AtomicU64,
    last_rebuilds: AtomicU64,
    last_lockout_reports: AtomicU64,
    last_lockout_drops: AtomicU64,
}

impl Metrics {
    /// Construct and register the daemon's metrics.
    pub fn new() -> Self {
        let mut registry = Registry::default();
        let requests = Family::<Vec<(String, String)>, Counter>::default();
        let gate_rejections = Family::<Vec<(String, String)>, Counter>::default();
        let principal_lookup = Histogram::new(exponential_buckets(0.0005, 2.0, 16));
        let store_time = Family::<Vec<(String, String)>, Histogram>::new_with_constructor(|| {
            Histogram::new(exponential_buckets(0.0005, 2.0, 16))
        });
        let local_db_errors = Counter::default();
        let replication_freshness = Gauge::<f64, AtomicU64>::default();
        let replication_applied_ts = Gauge::<f64, AtomicU64>::default();
        let replication_applied = Counter::default();
        let replication_skipped_stale = Counter::default();
        let replication_retries = Counter::default();
        let replication_failures = Counter::default();
        let replication_rebuilds = Counter::default();
        let replication_snapshot_duration = Histogram::new(exponential_buckets(0.01, 2.0, 16));
        let lockout_reports = Counter::default();
        let lockout_drops = Counter::default();
        registry.register(
            "krb5_requests",
            "Requests processed by the KDC, by request type and outcome code.",
            requests.clone(),
        );
        registry.register(
            "krb5_gate_rejections",
            "KDC requests rejected by a consistency gate, by low-cardinality reason.",
            gate_rejections.clone(),
        );
        registry.register(
            "krb5_principal_lookup_seconds",
            "PrincipalStore lookup duration.",
            principal_lookup.clone(),
        );
        registry.register(
            "krb5_kdc_store_time_seconds",
            "Time spent awaiting KDC stores during a request.",
            store_time.clone(),
        );
        registry.register(
            "krb5_local_db_errors_total",
            "Local replica database errors.",
            local_db_errors.clone(),
        );
        registry.register(
            "krb5_replication_freshness_seconds",
            "Source-clock-safe replication freshness.",
            replication_freshness.clone(),
        );
        registry.register(
            "krb5_replication_applied_timestamp_seconds",
            "Wall component of the applied CockroachDB HLC.",
            replication_applied_ts.clone(),
        );
        registry.register(
            "krb5_replication_applied_total",
            "Replicated changes applied.",
            replication_applied.clone(),
        );
        registry.register(
            "krb5_replication_skipped_stale_total",
            "Replicated changes skipped as stale.",
            replication_skipped_stale.clone(),
        );
        registry.register(
            "krb5_replication_retries_total",
            "Replication retry/backoff cycles.",
            replication_retries.clone(),
        );
        registry.register(
            "krb5_replication_failures_total",
            "Replication failures since daemon start.",
            replication_failures.clone(),
        );
        registry.register(
            "krb5_replication_rebuilds_total",
            "Snapshots installed (the initial bootstrap and rebuilds).",
            replication_rebuilds.clone(),
        );
        registry.register(
            "krb5_replication_snapshot_duration_seconds",
            "Duration of the most recent replica snapshot/rebuild.",
            replication_snapshot_duration.clone(),
        );
        registry.register(
            "krb5_lockout_reports_total",
            "Lockout reports written to the authority.",
            lockout_reports.clone(),
        );
        registry.register(
            "krb5_lockout_drops_total",
            "Lockout reports dropped because the bounded queue was full.",
            lockout_drops.clone(),
        );
        Self {
            registry,
            requests,
            gate_rejections,
            principal_lookup,
            store_time,
            local_db_errors,
            replication_freshness,
            replication_applied_ts,
            replication_applied,
            replication_skipped_stale,
            replication_retries,
            replication_failures,
            replication_rebuilds,
            replication_snapshot_duration,
            lockout_reports,
            lockout_drops,
            last_applied: AtomicU64::new(0),
            last_skipped_stale: AtomicU64::new(0),
            last_retries: AtomicU64::new(0),
            last_failures: AtomicU64::new(0),
            last_rebuilds: AtomicU64::new(0),
            last_lockout_reports: AtomicU64::new(0),
            last_lockout_drops: AtomicU64::new(0),
        }
    }

    pub fn observe_principal_lookup(&self, elapsed: Duration, ok: bool) {
        self.principal_lookup.observe(elapsed.as_secs_f64());
        if !ok {
            self.local_db_errors.inc();
        }
    }

    pub fn record_request(&self, summary: &RequestSummary) {
        let kind = match summary.kind {
            RequestKind::As => "as",
            RequestKind::Tgs => "tgs",
            RequestKind::Unknown => "unknown",
        };
        let (code, status) = match &summary.outcome {
            Outcome::Issued => ("issued".to_string(), None),
            Outcome::Error { code, status } => (code.to_string(), status.as_deref()),
        };
        // Store failures surface as SVC_UNAVAILABLE or GENERIC with the lookup
        // status; the same statuses also label not-found errors, which are not
        // database failures.
        let store_failure = matches!(&summary.outcome, Outcome::Error { code: 29 | 60, .. });
        if store_failure
            && status.is_some_and(|s| {
                matches!(
                    s,
                    "LOOKING_UP_AUTH_STATE"
                        | "LOOKING_UP_POLICY"
                        | "LOOKING_UP_CLIENT"
                        | "LOOKING_UP_SERVER"
                        | "LOOKING_UP_S4U2SELF_PRINCIPAL"
                        | "GET_LOCAL_TGT"
                        | "UNKNOWN_SERVER"
                        | "2ND_TKT_SERVER"
                        | "FIND_FAST"
                )
            })
        {
            self.local_db_errors.inc();
        }
        self.requests
            .get_or_create(&vec![
                ("kind".to_string(), kind.to_string()),
                ("outcome".to_string(), code),
            ])
            .inc();
        if summary.gate_rejected {
            let reason = status
                .filter(|s| {
                    matches!(
                        *s,
                        "REPLICA_STALE"
                            | "REPLICA_NOT_READY"
                            | "AUTHORITATIVE_MISMATCH"
                            | "AUTHORITY_UNAVAILABLE"
                            | "AUTHORITATIVE_CLIENT_DISABLED"
                            | "AUTHORITATIVE_CLIENT_LOCKED_OUT"
                            | "AUTHORITATIVE_CLIENT_DELETED"
                            | "AUTHORITATIVE_SERVER_DISABLED"
                            | "AUTHORITATIVE_SERVER_DELETED"
                    )
                })
                .unwrap_or("OTHER");
            self.gate_rejections
                .get_or_create(&vec![("reason".to_string(), reason.to_string())])
                .inc();
        }
        self.store_time
            .get_or_create(&vec![("kind".to_string(), kind.to_string())])
            .observe(summary.store_time.as_secs_f64());
    }

    pub fn set_replication(&self, status: &StatusSnapshot) {
        self.replication_freshness.set(
            status
                .freshness()
                .map_or(f64::INFINITY, |d| d.as_secs_f64()),
        );
        self.replication_applied_ts
            .set(status.applied_ts.wall_time().timestamp() as f64);
        increment_delta(
            &self.replication_applied,
            &self.last_applied,
            status.applied,
        );
        increment_delta(
            &self.replication_skipped_stale,
            &self.last_skipped_stale,
            status.skipped_stale,
        );
        increment_delta(
            &self.replication_retries,
            &self.last_retries,
            status.retries,
        );
        increment_delta(
            &self.replication_failures,
            &self.last_failures,
            status.failures,
        );
        let previous_rebuilds = self.last_rebuilds.swap(status.rebuilds, Ordering::Relaxed);
        if status.rebuilds > previous_rebuilds {
            self.replication_rebuilds
                .inc_by(status.rebuilds - previous_rebuilds);
            self.replication_snapshot_duration
                .observe(status.snapshot_duration.as_secs_f64());
        }
    }

    pub fn set_lockout_reporter(&self, reported: u64, dropped: u64) {
        increment_delta(&self.lockout_reports, &self.last_lockout_reports, reported);
        increment_delta(&self.lockout_drops, &self.last_lockout_drops, dropped);
    }

    pub fn encode(&self) -> String {
        let mut text = String::new();
        if let Err(e) = encode(&mut text, &self.registry) {
            warn!("encoding Prometheus metrics: {e}");
        }
        text
    }
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

fn increment_delta(counter: &Counter, last: &AtomicU64, current: u64) {
    let previous = last.swap(current, Ordering::Relaxed);
    if current > previous {
        counter.inc_by(current - previous);
    }
}

/// Serve only `GET /metrics`, `/healthz` and `/readyz`. No Hyper runtime or
/// extra protocol dependency is required.
pub async fn serve(
    listener: TcpListener,
    metrics: Arc<Metrics>,
    status: Option<Arc<std::sync::Mutex<StatusSnapshot>>>,
    lockout_counters: Option<Arc<dyn Fn() -> (u64, u64) + Send + Sync>>,
    max_staleness: Duration,
    mut shutdown: watch::Receiver<bool>,
) -> std::io::Result<()> {
    let mut tasks = JoinSet::new();
    loop {
        tokio::select! {
            accepted = listener.accept() => match accepted {
                Ok((stream, _)) => {
                    let (metrics, status) = (Arc::clone(&metrics), status.clone());
                    let lockout_counters = lockout_counters.clone();
                    tasks.spawn(async move {
                        let _ = handle(
                            stream,
                            metrics,
                            status,
                            lockout_counters,
                            max_staleness,
                        )
                        .await;
                    });
                }
                Err(e) => warn!("metrics listener accept failed: {e}"),
            },
            _ = tasks.join_next(), if !tasks.is_empty() => {}
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
        }
    }
    let drained = tokio::time::timeout(CONNECTION_TIMEOUT, async {
        while tasks.join_next().await.is_some() {}
    })
    .await;
    if drained.is_err() {
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
    }
    Ok(())
}

async fn handle(
    stream: TcpStream,
    metrics: Arc<Metrics>,
    status: Option<Arc<std::sync::Mutex<StatusSnapshot>>>,
    lockout_counters: Option<Arc<dyn Fn() -> (u64, u64) + Send + Sync>>,
    max_staleness: Duration,
) -> std::io::Result<()> {
    match tokio::time::timeout(
        CONNECTION_TIMEOUT,
        handle_request(stream, metrics, status, lockout_counters, max_staleness),
    )
    .await
    {
        Ok(result) => result,
        Err(_) => Ok(()),
    }
}

async fn handle_request(
    mut stream: TcpStream,
    metrics: Arc<Metrics>,
    status: Option<Arc<std::sync::Mutex<StatusSnapshot>>>,
    lockout_counters: Option<Arc<dyn Fn() -> (u64, u64) + Send + Sync>>,
    max_staleness: Duration,
) -> std::io::Result<()> {
    let mut request = [0u8; 2048];
    let n = stream.read(&mut request).await?;
    let first = std::str::from_utf8(&request[..n])
        .ok()
        .and_then(|r| r.lines().next())
        .unwrap_or("");
    let path = first.split_whitespace().nth(1).unwrap_or("");
    let (code, content_type, body) = match (first.starts_with("GET "), path) {
        (true, "/metrics") => ("200 OK", "text/plain; version=0.0.4; charset=utf-8", {
            if let Some(status) = &status {
                metrics.set_replication(&status.lock().unwrap_or_else(|e| e.into_inner()));
            }
            if let Some(counters) = &lockout_counters {
                let (reported, dropped) = counters();
                metrics.set_lockout_reporter(reported, dropped);
            }
            metrics.encode()
        }),
        (true, "/healthz") => ("200 OK", "text/plain; charset=utf-8", "ok\n".to_string()),
        (true, "/readyz") => {
            let ready = status.as_ref().is_none_or(|status| {
                let s = status.lock().unwrap_or_else(|e| e.into_inner());
                s.bootstrapped
                    && !s.needs_rebuild
                    && !s.rebuilding
                    && s.freshness().is_some_and(|f| f <= max_staleness)
            });
            if ready {
                ("200 OK", "text/plain; charset=utf-8", "ready\n".to_string())
            } else {
                (
                    "503 Service Unavailable",
                    "text/plain; charset=utf-8",
                    "not ready\n".to_string(),
                )
            }
        }
        _ => (
            "404 Not Found",
            "text/plain; charset=utf-8",
            "not found\n".to_string(),
        ),
    };
    let response = format!(
        "HTTP/1.1 {code}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(response.as_bytes()).await?;
    stream.shutdown().await
}

#[cfg(test)]
mod tests {
    use super::{
        handle, serve, Metrics, Outcome, RequestKind, RequestSummary, StatusSnapshot,
        CONNECTION_TIMEOUT,
    };
    use krb5_rs::kdc::Transport;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    async fn connected_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let address = listener.local_addr().expect("address");
        let client = TcpStream::connect(address).await.expect("connect");
        let (server, _) = listener.accept().await.expect("accept");
        (server, client)
    }

    async fn ready_response(status: StatusSnapshot) -> String {
        let (server, mut client) = connected_pair().await;
        let task = tokio::spawn(handle(
            server,
            Arc::new(Metrics::new()),
            Some(Arc::new(Mutex::new(status))),
            None,
            Duration::from_secs(1),
        ));
        client
            .write_all(b"GET /readyz HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .expect("request");
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.expect("response");
        task.await.expect("handler").expect("handle");
        String::from_utf8(response).expect("UTF-8 response")
    }

    #[tokio::test(start_paused = true)]
    async fn idle_connection_closes_after_the_connection_timeout() {
        let (server, mut client) = connected_pair().await;
        let task = tokio::spawn(handle(
            server,
            Arc::new(Metrics::new()),
            None,
            None,
            Duration::from_secs(1),
        ));
        tokio::task::yield_now().await;
        tokio::time::advance(CONNECTION_TIMEOUT).await;
        task.await.expect("handler").expect("handle");

        let mut byte = [0];
        assert_eq!(client.read(&mut byte).await.expect("closed connection"), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn shutdown_drains_or_aborts_idle_connections_within_the_timeout() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let address = listener.local_addr().expect("address");
        let (shutdown, rx) = tokio::sync::watch::channel(false);
        let task = tokio::spawn(serve(
            listener,
            Arc::new(Metrics::new()),
            None,
            None,
            Duration::from_secs(1),
            rx,
        ));
        let mut client = TcpStream::connect(address).await.expect("connect");
        for _ in 0..4 {
            tokio::task::yield_now().await;
        }
        shutdown.send(true).expect("shutdown");
        tokio::time::advance(CONNECTION_TIMEOUT).await;
        task.await.expect("server").expect("serve");

        let mut byte = [0];
        assert_eq!(client.read(&mut byte).await.expect("closed connection"), 0);
    }

    #[tokio::test]
    async fn readyz_reflects_bootstrap_and_freshness() {
        let unbootstrapped = ready_response(StatusSnapshot::default()).await;
        assert!(unbootstrapped.starts_with("HTTP/1.1 503 Service Unavailable"));

        let fresh = StatusSnapshot {
            bootstrapped: true,
            observed_at: Some(std::time::Instant::now()),
            ..StatusSnapshot::default()
        };
        let response = ready_response(fresh).await;
        assert!(response.starts_with("HTTP/1.1 200 OK"));
    }

    #[test]
    fn client_lookup_service_error_counts_as_a_local_database_error() {
        let metrics = Metrics::new();
        metrics.record_request(&RequestSummary {
            kind: RequestKind::Tgs,
            transport: Transport::Tcp,
            client: None,
            server: None,
            etypes: Vec::new(),
            outcome: Outcome::Error {
                code: 29,
                status: Some("LOOKING_UP_CLIENT".into()),
            },
            reply_etype: None,
            ticket_etype: None,
            gate_rejected: false,
            store_time: Duration::ZERO,
        });

        assert_eq!(metrics.local_db_errors.get(), 1);

        metrics.record_request(&RequestSummary {
            kind: RequestKind::Tgs,
            transport: Transport::Tcp,
            client: None,
            server: None,
            etypes: Vec::new(),
            outcome: Outcome::Error {
                code: 7,
                status: Some("UNKNOWN_SERVER".into()),
            },
            reply_etype: None,
            ticket_etype: None,
            gate_rejected: false,
            store_time: Duration::ZERO,
        });
        assert_eq!(
            metrics.local_db_errors.get(),
            1,
            "not found is not a DB error"
        );
    }

    #[test]
    fn authoritative_client_denial_counts_as_a_gate_rejection() {
        let metrics = Metrics::new();
        metrics.record_request(&RequestSummary {
            kind: RequestKind::As,
            transport: Transport::Tcp,
            client: Some("alice@R".into()),
            server: Some("krbtgt/R@R".into()),
            etypes: vec![18],
            outcome: Outcome::Error {
                code: 18,
                status: Some("AUTHORITATIVE_CLIENT_DISABLED".into()),
            },
            reply_etype: None,
            ticket_etype: None,
            gate_rejected: true,
            store_time: Duration::ZERO,
        });

        assert_eq!(
            metrics
                .gate_rejections
                .get_or_create(&vec![(
                    "reason".to_string(),
                    "AUTHORITATIVE_CLIENT_DISABLED".to_string(),
                )])
                .get(),
            1
        );
    }
}
