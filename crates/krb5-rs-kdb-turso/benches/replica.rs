//! Replica benchmarks: lookup latency at several concurrencies, lookups while
//! a writer applies batches continuously, and apply throughput by batch size.
//! Run with `cargo bench -p krb5-rs-kdb-turso`.

use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use krb5_rs::kdc::kdb::master_key_from_password;
use krb5_rs::kdc::replication::{Change, ChangeBatch, ReplicaSink, ReplicationTs, StoredPrincipal};
use krb5_rs::kdc::{MemoryStore, PrincipalAttributes, PrincipalStore};
use krb5_rs::types::{EncryptionKey, PrincipalName};
use krb5_rs_kdb_turso::{TursoOptions, TursoReplica};
use tokio::runtime::Runtime;

const REALM: &str = "BENCH.TEST";
const PRINCIPALS: usize = 1000;

fn master() -> EncryptionKey {
    master_key_from_password(REALM, "bench-master", 18).expect("master key")
}

fn stored(i: usize) -> StoredPrincipal {
    let mut store = MemoryStore::new();
    let name = PrincipalName::new_principal(&format!("user{i}"));
    store
        .add_with_password(
            name.clone(),
            REALM,
            "pw",
            1,
            &[18, 17],
            PrincipalAttributes::empty(),
        )
        .expect("add");
    let entry = store.get(&name, REALM).expect("entry");
    StoredPrincipal::from_entry(&entry, None, None, &master()).expect("stored")
}

fn batch(clock: &AtomicI64, principals: &[StoredPrincipal]) -> ChangeBatch {
    let t = ReplicationTs::new(clock.fetch_add(1, Ordering::SeqCst), 0);
    ChangeBatch {
        upto: t,
        changes: principals
            .iter()
            .map(|p| Change::UpsertPrincipal {
                principal: p.clone(),
                version: t,
            })
            .collect(),
    }
}

struct Fixture {
    _dir: std::path::PathBuf,
    replica: TursoReplica,
    clock: Arc<AtomicI64>,
}

fn fixture(rt: &Runtime, tag: &str) -> Fixture {
    let dir = std::env::temp_dir().join(format!("krb5rs_turso_bench_{}_{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let replica = rt.block_on(async {
        TursoReplica::open(&dir, TursoOptions::default(), master())
            .await
            .expect("open")
    });
    let clock = Arc::new(AtomicI64::new(1));
    let all: Vec<StoredPrincipal> = (0..PRINCIPALS).map(stored).collect();
    for chunk in all.chunks(200) {
        rt.block_on(replica.apply(batch(&clock, chunk)))
            .expect("seed");
    }
    Fixture {
        _dir: dir,
        replica,
        clock,
    }
}

async fn lookups(replica: &TursoReplica, tasks: usize, per_task: usize) {
    let mut handles = Vec::with_capacity(tasks);
    for t in 0..tasks {
        let r = replica.clone();
        handles.push(tokio::spawn(async move {
            for i in 0..per_task {
                let name =
                    PrincipalName::new_principal(&format!("user{}", (t * 31 + i) % PRINCIPALS));
                r.lookup(&name, REALM)
                    .await
                    .expect("lookup")
                    .expect("exists");
            }
        }));
    }
    for h in handles {
        h.await.expect("task");
    }
}

fn bench_lookup(c: &mut Criterion) {
    let rt = Runtime::new().expect("runtime");
    let fx = fixture(&rt, "lookup");
    let mut g = c.benchmark_group("lookup");
    g.sample_size(20).measurement_time(Duration::from_secs(4));
    for tasks in [1usize, 8, 64] {
        let per_task = 20;
        g.throughput(Throughput::Elements((tasks * per_task) as u64));
        g.bench_with_input(
            BenchmarkId::new("concurrent_tasks", tasks),
            &tasks,
            |b, &tasks| {
                b.to_async(&rt)
                    .iter(|| lookups(&fx.replica, tasks, per_task));
            },
        );
    }
    g.finish();
}

fn bench_lookup_under_apply(c: &mut Criterion) {
    let rt = Runtime::new().expect("runtime");
    let fx = fixture(&rt, "mixed");
    let stop = Arc::new(AtomicBool::new(false));
    let applied = Arc::new(AtomicI64::new(0));
    let writer = {
        let (r, clock, stop, applied) = (
            fx.replica.clone(),
            Arc::clone(&fx.clock),
            Arc::clone(&stop),
            Arc::clone(&applied),
        );
        let batch_of: Vec<StoredPrincipal> = (0..10).map(stored).collect();
        rt.spawn(async move {
            while !stop.load(Ordering::Relaxed) {
                r.apply(batch(&clock, &batch_of)).await.expect("apply");
                applied.fetch_add(1, Ordering::Relaxed);
            }
        })
    };
    let mut g = c.benchmark_group("lookup_under_continuous_apply");
    g.sample_size(20).measurement_time(Duration::from_secs(4));
    for tasks in [1usize, 8, 64] {
        let per_task = 20;
        g.throughput(Throughput::Elements((tasks * per_task) as u64));
        g.bench_with_input(
            BenchmarkId::new("concurrent_tasks", tasks),
            &tasks,
            |b, &tasks| {
                b.to_async(&rt)
                    .iter(|| lookups(&fx.replica, tasks, per_task));
            },
        );
    }
    g.finish();
    stop.store(true, Ordering::Relaxed);
    let _ = rt.block_on(writer);
    println!(
        "batches of 10 applied by the background writer: {}",
        applied.load(Ordering::Relaxed)
    );
}

fn bench_apply(c: &mut Criterion) {
    let rt = Runtime::new().expect("runtime");
    let fx = fixture(&rt, "apply");
    let mut g = c.benchmark_group("apply");
    g.sample_size(10).measurement_time(Duration::from_secs(4));
    for size in [1usize, 10, 100, 1000] {
        let changes: Vec<StoredPrincipal> = (0..size).map(stored).collect();
        g.throughput(Throughput::Elements(size as u64));
        g.bench_with_input(BenchmarkId::new("batch_size", size), &size, |b, _| {
            b.to_async(&rt).iter(|| async {
                fx.replica
                    .apply(batch(&fx.clock, &changes))
                    .await
                    .expect("apply")
            });
        });
    }
    g.finish();
}

criterion_group!(benches, bench_lookup, bench_lookup_under_apply, bench_apply);
criterion_main!(benches);
