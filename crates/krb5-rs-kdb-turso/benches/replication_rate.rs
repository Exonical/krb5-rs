//! Lookup p50/p99 under realistic bounded replication rates.
//! Run with `cargo bench -p krb5-rs-kdb-turso --bench replication_rate`.

use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use krb5_rs::kdc::kdb::master_key_from_password;
use krb5_rs::kdc::replication::{Change, ChangeBatch, ReplicaSink, ReplicationTs, StoredPrincipal};
use krb5_rs::kdc::{MemoryStore, PrincipalAttributes, PrincipalStore};
use krb5_rs::types::{EncryptionKey, PrincipalName};
use krb5_rs_kdb_turso::{TursoOptions, TursoReplica};

const REALM: &str = "RATE.TEST";
const PRINCIPALS: usize = 1000;
const SAMPLE_DURATION: Duration = Duration::from_secs(2);

fn master() -> EncryptionKey {
    master_key_from_password(REALM, "rate-bench-master", 18).expect("master")
}

fn stored(i: usize) -> StoredPrincipal {
    let mut store = MemoryStore::new();
    let name = PrincipalName::new_principal(&format!("user{i}"));
    store
        .add_with_password(
            name.clone(),
            REALM,
            "password",
            1,
            &[18, 17],
            PrincipalAttributes::empty(),
        )
        .expect("principal");
    StoredPrincipal::from_entry(
        &store.get(&name, REALM).expect("entry"),
        None,
        None,
        &krb5_rs::kdc::kdb::mit::mkey::MasterKeys::single(master()),
    )
    .expect("stored")
}

fn batch(clock: &AtomicI64, principals: &[StoredPrincipal]) -> ChangeBatch {
    let ts = ReplicationTs::new(clock.fetch_add(1, Ordering::SeqCst), 0);
    ChangeBatch {
        upto: ts,
        changes: principals
            .iter()
            .map(|p| Change::UpsertPrincipal {
                principal: p.clone(),
                version: ts,
            })
            .collect(),
    }
}

async fn lookup_samples(
    replica: &TursoReplica,
    concurrency: usize,
    duration: Duration,
) -> Vec<u64> {
    let deadline = tokio::time::Instant::now() + duration;
    let mut tasks = Vec::with_capacity(concurrency);
    for task in 0..concurrency {
        let replica = replica.clone();
        tasks.push(tokio::spawn(async move {
            let mut samples = Vec::new();
            let mut i = 0usize;
            while tokio::time::Instant::now() < deadline {
                let name =
                    PrincipalName::new_principal(&format!("user{}", (task * 31 + i) % PRINCIPALS));
                let start = Instant::now();
                replica
                    .lookup(&name, REALM)
                    .await
                    .expect("lookup")
                    .expect("principal exists");
                samples.push(start.elapsed().as_nanos() as u64);
                i += 1;
            }
            samples
        }));
    }
    let mut samples = Vec::new();
    for task in tasks {
        samples.extend(task.await.expect("lookup task"));
    }
    samples.sort_unstable();
    samples
}

fn percentile(samples: &[u64], p: usize) -> f64 {
    let i = ((samples.len() - 1) * p / 100).min(samples.len() - 1);
    samples[i] as f64 / 1_000.0
}

async fn sample_case(
    replica: &TursoReplica,
    principals: Arc<Vec<StoredPrincipal>>,
    clock: Arc<AtomicI64>,
    concurrency: usize,
    interval: Option<Duration>,
) {
    let stop = Arc::new(AtomicBool::new(false));
    let apply_samples = Arc::new(Mutex::new(Vec::new()));
    let writer = interval.map(|period| {
        let (replica, stop, principals, clock, apply_samples) = (
            replica.clone(),
            Arc::clone(&stop),
            Arc::clone(&principals),
            Arc::clone(&clock),
            Arc::clone(&apply_samples),
        );
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(period);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            while !stop.load(Ordering::Relaxed) {
                tick.tick().await;
                if stop.load(Ordering::Relaxed) {
                    break;
                }
                let started = Instant::now();
                replica
                    .apply(batch(&clock, &principals[..10]))
                    .await
                    .expect("replication batch");
                apply_samples
                    .lock()
                    .expect("apply samples")
                    .push(started.elapsed().as_nanos() as u64);
            }
        })
    });
    tokio::time::sleep(Duration::from_millis(100)).await;
    let samples = lookup_samples(replica, concurrency, SAMPLE_DURATION).await;
    stop.store(true, Ordering::Relaxed);
    if let Some(writer) = writer {
        writer.await.expect("writer");
    }
    let label = match interval {
        None => "idle baseline",
        Some(d) if d == Duration::from_secs(1) => "10 principals/s",
        Some(_) => "10 principals/100ms",
    };
    println!(
        "{label}, concurrency {concurrency}: {} lookups, p50 {:.1} us, p99 {:.1} us",
        samples.len(),
        percentile(&samples, 50),
        percentile(&samples, 99)
    );
    let mut applies = apply_samples.lock().expect("apply samples").clone();
    if !applies.is_empty() {
        applies.sort_unstable();
        println!(
            "{label}, batch apply: {} batches, p50 {:.1} ms, p99 {:.1} ms",
            applies.len(),
            percentile(&applies, 50) / 1000.0,
            percentile(&applies, 99) / 1000.0
        );
    }
}

#[tokio::main(flavor = "multi_thread", worker_threads = 8)]
async fn main() {
    let path = std::env::temp_dir().join(format!("krb5rs_rate_bench_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&path);
    let mut options = TursoOptions::default();
    options.pool_size = std::env::var("TURSO_BENCH_POOL_SIZE")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(options.pool_size)
        .max(2);
    println!("Turso lookup benchmark pool_size={}", options.pool_size);
    let replica = TursoReplica::open(&path, options, master())
        .await
        .expect("open Turso");
    let principals: Arc<Vec<_>> = Arc::new((0..PRINCIPALS).map(stored).collect());
    let clock = Arc::new(AtomicI64::new(1_700_000_000_000_000_000));
    for chunk in principals.chunks(100) {
        replica.apply(batch(&clock, chunk)).await.expect("seed");
    }
    for interval in [
        None,
        Some(Duration::from_secs(1)),
        Some(Duration::from_millis(100)),
    ] {
        for concurrency in [1usize, 8, 64] {
            sample_case(
                &replica,
                Arc::clone(&principals),
                Arc::clone(&clock),
                concurrency,
                interval,
            )
            .await;
        }
    }
    drop(replica);
    let _ = std::fs::remove_dir_all(path);
}
