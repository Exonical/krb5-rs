//! Engine-to-Turso bootstrap, freshness and heartbeat on a real Turso file.

use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use krb5_rs::kdc::kdb::master_key_from_password;
use krb5_rs::kdc::replication::{
    Change, ChangeBatch, PollResult, RebuildPolicy, ReplicaRegistry, ReplicationConfig,
    ReplicationEngine, ReplicationSource, ReplicationTs, Snapshot,
};
use krb5_rs::kdc::{HealthCheck, MemoryStore, PrincipalAttributes, PrincipalStore, StoreError};
use krb5_rs::types::{EncryptionKey, PrincipalName};
use krb5_rs_kdb_turso::{TursoOptions, TursoReplica};
use tokio::sync::watch;

const REALM: &str = "ENGINE.TEST";

struct Tmp(PathBuf);

impl Tmp {
    fn new() -> Self {
        static N: AtomicUsize = AtomicUsize::new(0);
        let p = std::env::temp_dir().join(format!(
            "krb5rs_replication_engine_{}_{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).expect("directory");
        Self(p)
    }
}

impl Drop for Tmp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn master() -> EncryptionKey {
    master_key_from_password(REALM, "engine-master", 18).expect("master key")
}

fn principal() -> krb5_rs::kdc::replication::StoredPrincipal {
    let mut store = MemoryStore::new();
    store
        .add_with_password(
            PrincipalName::new_principal("alice"),
            REALM,
            "pw",
            1,
            &[18],
            PrincipalAttributes::empty(),
        )
        .expect("add");
    krb5_rs::kdc::replication::StoredPrincipal::from_entry(
        &store
            .get(&PrincipalName::new_principal("alice"), REALM)
            .expect("entry"),
        None,
        None,
        &master(),
    )
    .expect("stored")
}

struct Pages {
    ts: ReplicationTs,
    source_now: ReplicationTs,
    pages: VecDeque<Vec<Change>>,
}

impl Snapshot for Pages {
    fn ts(&self) -> ReplicationTs {
        self.ts
    }

    fn source_now(&self) -> ReplicationTs {
        self.source_now
    }

    async fn next_page(&mut self) -> Result<Option<Vec<Change>>, StoreError> {
        Ok(self.pages.pop_front())
    }
}

struct Source {
    ts: ReplicationTs,
    source_now: ReplicationTs,
    snapshot: Vec<Change>,
    pruned: Arc<Mutex<Option<ReplicationTs>>>,
}

impl ReplicationSource for Source {
    type Snapshot = Pages;

    async fn snapshot(&self) -> Result<Self::Snapshot, StoreError> {
        let ts = self
            .pruned
            .lock()
            .expect("prune watermark")
            .map_or(self.ts, |p| self.ts.max(p));
        Ok(Pages {
            ts,
            source_now: self.source_now.max(ts),
            pages: VecDeque::from(vec![self.snapshot.clone(), Vec::new()]),
        })
    }

    async fn poll(&self, since: ReplicationTs, _limit: usize) -> Result<PollResult, StoreError> {
        Ok(PollResult {
            batch: ChangeBatch {
                upto: self.ts.max(since),
                changes: Vec::new(),
            },
            source_now: self.source_now.max(self.ts.max(since)),
            truncated: false,
        })
    }

    async fn pruned_before(&self) -> Result<Option<ReplicationTs>, StoreError> {
        Ok(*self.pruned.lock().expect("prune watermark"))
    }
}

#[derive(Clone, Default)]
struct Registry(Arc<Mutex<Vec<(String, String, ReplicationTs)>>>);

impl ReplicaRegistry for Registry {
    async fn heartbeat(
        &self,
        kdc_id: &str,
        region: &str,
        applied_ts: ReplicationTs,
    ) -> Result<(), StoreError> {
        self.0.lock().expect("registry lock").push((
            kdc_id.to_string(),
            region.to_string(),
            applied_ts,
        ));
        Ok(())
    }
}

fn now_ts() -> ReplicationTs {
    let wall = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    ReplicationTs::new(i64::try_from(wall).expect("timestamp range"), 0)
}

#[tokio::test]
async fn engine_bootstraps_turso_before_ready_and_heartbeats_its_checkpoint() {
    let tmp = Tmp::new();
    let sink = TursoReplica::open(&tmp.0, TursoOptions::default(), master())
        .await
        .expect("open replica");
    let ts = now_ts();
    let source = Source {
        ts,
        source_now: ReplicationTs::new(ts.wall_nanos + 50_000_000, ts.logical),
        snapshot: vec![Change::UpsertPrincipal {
            principal: principal(),
            version: ts,
        }],
        pruned: Arc::new(Mutex::new(None)),
    };
    let registry = Registry::default();
    let cfg = ReplicationConfig {
        heartbeat_interval: Duration::from_millis(10),
        poll_interval: Duration::from_millis(10),
        kdc_id: "unit-kdc".into(),
        region: "ohio".into(),
        ..ReplicationConfig::default()
    };
    let engine = ReplicationEngine::new(source, sink.clone(), registry.clone(), cfg);

    engine
        .bootstrap()
        .await
        .expect("bootstrap before listeners");
    assert!(engine.status().bootstrapped);
    assert_eq!(engine.status().applied_ts, ts);
    assert!(engine.status().freshness().expect("freshness") < Duration::from_millis(250));
    assert!(sink
        .lookup(&PrincipalName::new_principal("alice"), REALM)
        .await
        .expect("lookup")
        .is_some());

    let (shutdown, rx) = watch::channel(false);
    let task = tokio::spawn(async move { engine.run(rx).await });
    tokio::time::sleep(Duration::from_millis(40)).await;
    shutdown.send(true).expect("shutdown");
    tokio::time::timeout(Duration::from_secs(2), task)
        .await
        .expect("engine stops")
        .expect("join");
    assert!(registry
        .0
        .lock()
        .expect("registry")
        .iter()
        .any(|(id, region, applied)| id == "unit-kdc" && region == "ohio" && *applied >= ts));
    sink.health().await.expect("healthy");
}

#[tokio::test]
async fn the_manual_rebuild_policy_marks_pruned_replicas_unready() {
    let tmp = Tmp::new();
    let sink = TursoReplica::open(&tmp.0, TursoOptions::default(), master())
        .await
        .expect("open");
    let ts = now_ts();
    // Bootstrap with a source and then let the source report a prune watermark
    // beyond the sink's checkpoint.
    let pruned = Arc::new(Mutex::new(None));
    let source = Source {
        ts,
        source_now: ts,
        snapshot: Vec::new(),
        pruned: Arc::clone(&pruned),
    };
    let registry = Registry::default();
    let cfg = ReplicationConfig {
        rebuild: RebuildPolicy::Manual,
        ..ReplicationConfig::default()
    };
    let engine = ReplicationEngine::new(source, sink.clone(), registry, cfg);
    engine.bootstrap().await.expect("initial bootstrap");
    *pruned.lock().expect("watermark") = Some(ReplicationTs::new(ts.wall_nanos + 1, 0));
    let state = engine.status_handle();
    let (shutdown, rx) = watch::channel(false);
    let task = tokio::spawn(async move { engine.run(rx).await });
    for _ in 0..100 {
        if state.lock().expect("status").needs_rebuild {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(state.lock().expect("status").needs_rebuild);
    shutdown.send(true).expect("shutdown");
    tokio::time::timeout(Duration::from_secs(2), task)
        .await
        .expect("engine stops")
        .expect("join");
    let gate = krb5_rs::kdc::replication::FreshnessGate::new(state, Duration::from_secs(30));
    assert!(!gate.ready());
}

#[tokio::test]
async fn the_auto_rebuild_policy_rebuilds_after_the_checkpoint_is_pruned() {
    let tmp = Tmp::new();
    let sink = TursoReplica::open(&tmp.0, TursoOptions::default(), master())
        .await
        .expect("open");
    let ts = now_ts();
    let pruned = Arc::new(Mutex::new(None));
    let source = Source {
        ts,
        source_now: ts,
        snapshot: vec![Change::UpsertPrincipal {
            principal: principal(),
            version: ts,
        }],
        pruned: Arc::clone(&pruned),
    };
    let engine = ReplicationEngine::new(
        source,
        sink.clone(),
        Registry::default(),
        ReplicationConfig {
            rebuild: RebuildPolicy::Auto,
            poll_interval: Duration::from_millis(10),
            ..ReplicationConfig::default()
        },
    );
    engine.bootstrap().await.expect("initial snapshot");
    *pruned.lock().expect("watermark") = Some(ReplicationTs::new(ts.wall_nanos + 1, 0));
    let (shutdown, rx) = watch::channel(false);
    let status = engine.status_handle();
    let task = tokio::spawn(async move { engine.run(rx).await });
    for _ in 0..100 {
        if status.lock().expect("status").rebuilds >= 2 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(status.lock().expect("status").rebuilds >= 2);
    assert!(status.lock().expect("status").bootstrapped);
    shutdown.send(true).expect("shutdown");
    tokio::time::timeout(Duration::from_secs(2), task)
        .await
        .expect("engine stops")
        .expect("join");
    sink.health().await.expect("healthy");
}
