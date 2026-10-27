//! Real Turso files: opening, migrations, replication semantics, concurrency,
//! rebuilds, crash recovery and serving a KDC.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use krb5_rs::kdc::kdb::master_key_from_password;
use krb5_rs::kdc::replication::{
    Change, ChangeBatch, LockoutRecord, RebuildWriter, ReplicaSink, ReplicationTs, StoredKey,
    StoredPrincipal,
};
use krb5_rs::kdc::{
    AuthStateStore, AuthStateUpdate, HealthCheck, Kdc, KdcConfig, MemoryStore, Policy, PolicyStore,
    PrincipalAttributes, PrincipalStore, StoreErrorKind,
};
use krb5_rs::protocol::{
    AsExchange, AsExchangeConfig, StepResult, TgsExchange, TgsOptions, TgsStepResult,
};
use krb5_rs::types::{EncryptionKey, PrincipalName};
use krb5_rs_kdb_turso::{FailPoint, TursoOptions, TursoReplica};

const REALM: &str = "TURSO.TEST";

struct TmpDir(PathBuf);

impl TmpDir {
    fn new() -> Self {
        static N: AtomicUsize = AtomicUsize::new(0);
        let dir = std::env::temp_dir().join(format!(
            "krb5rs_turso_{}_{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("tmp dir");
        Self(dir)
    }

    fn files(&self) -> Vec<String> {
        let mut v: Vec<String> = std::fs::read_dir(&self.0)
            .expect("read_dir")
            .map(|e| e.expect("entry").file_name().to_string_lossy().to_string())
            .collect();
        v.sort();
        v
    }
}

impl Drop for TmpDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn master() -> EncryptionKey {
    master_key_from_password(REALM, "master-password", 18).expect("master key")
}

fn name(s: &str) -> PrincipalName {
    PrincipalName::new_principal(s)
}

fn ts(n: i64) -> ReplicationTs {
    ReplicationTs::new(n * 1000, 0)
}

async fn open(dir: &Path) -> TursoReplica {
    open_with(dir, TursoOptions::default()).await
}

async fn open_with(dir: &Path, options: TursoOptions) -> TursoReplica {
    TursoReplica::open(dir, options, master())
        .await
        .expect("open replica")
}

/// A stored principal with a known password-derived key.
fn principal(who: &str, pw: &str, kvno: u32, epoch: u64) -> StoredPrincipal {
    let mut store = MemoryStore::new();
    store
        .add_with_password(
            name(who),
            REALM,
            pw,
            kvno,
            &[18, 17],
            PrincipalAttributes::empty(),
        )
        .expect("add");
    let mut e = store.get(&name(who), REALM).expect("entry");
    e.security_epoch = epoch;
    StoredPrincipal::from_entry(&e, Some(5), Some(6), &master()).expect("stored")
}

fn up(p: StoredPrincipal, v: ReplicationTs) -> Change {
    Change::UpsertPrincipal {
        principal: p,
        version: v,
    }
}

fn del(who: &str, v: ReplicationTs) -> Change {
    Change::DeletePrincipal {
        realm: REALM.into(),
        name: name(who),
        version: v,
    }
}

fn batch(upto: ReplicationTs, changes: Vec<Change>) -> ChangeBatch {
    ChangeBatch { upto, changes }
}

async fn epoch_of(r: &TursoReplica, who: &str) -> Option<u64> {
    r.lookup(&name(who), REALM)
        .await
        .expect("lookup")
        .map(|e| e.security_epoch)
}

// ------------------------------------------------------------- opening

#[tokio::test]
async fn mvcc_is_set_on_create_and_verified_on_reopen() {
    let dir = TmpDir::new();
    {
        let r = open(&dir.0).await;
        let s = r.status().await.expect("status");
        assert!(
            s.mvcc && s.journal_mode.eq_ignore_ascii_case("mvcc"),
            "{s:?}"
        );
        assert_eq!(s.schema_version, 2);
        assert!(s.checkpoint.is_none());
        r.health().await.expect("healthy");
    }
    let r = open(&dir.0).await;
    assert!(r.status().await.expect("status").mvcc);
    assert_eq!(
        dir.files()
            .iter()
            .filter(|f| f.as_str() == "CURRENT")
            .count(),
        1
    );
}

#[tokio::test]
async fn a_wal_mode_database_is_rejected_not_converted() {
    let dir = TmpDir::new();
    let file = dir.0.join("replica-initial.db");
    {
        let db = turso::Builder::new_local(file.to_str().expect("utf-8"))
            .build()
            .await
            .expect("build");
        let conn = db.connect().expect("connect");
        conn.execute("CREATE TABLE t (a INTEGER)", ())
            .await
            .expect("create");
    }
    std::fs::write(dir.0.join("CURRENT"), "replica-initial.db").expect("pointer");
    let err = TursoReplica::open(&dir.0, TursoOptions::default(), master())
        .await
        .expect_err("not MVCC");
    assert!(err.message().contains("MVCC"), "{err}");
}

#[tokio::test]
async fn migrations_are_idempotent_and_a_newer_schema_is_refused() {
    let dir = TmpDir::new();
    drop(open(&dir.0).await);
    drop(open(&dir.0).await);
    let file = dir.0.join("replica-initial.db");
    {
        let db = turso::Builder::new_local(file.to_str().expect("utf-8"))
            .build()
            .await
            .expect("build");
        let conn = db.connect().expect("connect");
        let mut rows = conn
            .query("SELECT COUNT(*) FROM schema_migrations", ())
            .await
            .expect("count");
        let n: i64 = rows
            .next()
            .await
            .expect("row")
            .expect("one")
            .get(0)
            .expect("int");
        assert_eq!(n, 2, "reopening must not re-apply the migrations");
        conn.execute("BEGIN CONCURRENT", ()).await.expect("begin");
        conn.execute(
            "INSERT INTO schema_migrations (version, name, applied_at) VALUES (99, 'future', 0)",
            (),
        )
        .await
        .expect("insert");
        conn.execute("COMMIT", ()).await.expect("commit");
    }
    let err = TursoReplica::open(&dir.0, TursoOptions::default(), master())
        .await
        .expect_err("newer schema");
    assert!(err.message().contains("newer"), "{err}");
}

// ------------------------------------------------------------- applying

#[tokio::test]
async fn apply_upserts_deletes_and_recreates_with_versions() {
    let dir = TmpDir::new();
    let r = open(&dir.0).await;
    assert!(r.checkpoint().await.expect("checkpoint").is_none());

    let out = ReplicaSink::apply(
        &r,
        batch(ts(10), vec![up(principal("a", "pw1", 1, 1), ts(10))]),
    )
    .await
    .expect("apply");
    assert_eq!((out.applied, out.skipped_stale), (1, 0));
    let got = r
        .lookup(&name("a"), REALM)
        .await
        .expect("lookup")
        .expect("a");
    assert_eq!(got.keys.len(), 2);
    assert_eq!(got.keys[0].kvno, 1);
    assert_eq!(r.checkpoint().await.expect("cp").expect("some").ts, ts(10));

    // Newer state replaces it, keys included.
    ReplicaSink::apply(
        &r,
        batch(ts(20), vec![up(principal("a", "pw2", 2, 2), ts(20))]),
    )
    .await
    .expect("update");
    let got = r
        .lookup(&name("a"), REALM)
        .await
        .expect("lookup")
        .expect("a");
    assert_eq!(
        (got.keys.len(), got.keys[0].kvno, got.security_epoch),
        (2, 2, 2)
    );

    // Delete, then a re-create with a newer version.
    ReplicaSink::apply(&r, batch(ts(30), vec![del("a", ts(30))]))
        .await
        .expect("delete");
    assert!(r.lookup(&name("a"), REALM).await.expect("lookup").is_none());
    ReplicaSink::apply(
        &r,
        batch(ts(40), vec![up(principal("a", "pw3", 3, 3), ts(40))]),
    )
    .await
    .expect("recreate");
    assert_eq!(epoch_of(&r, "a").await, Some(3));
    assert_eq!(r.checkpoint().await.expect("cp").expect("some").ts, ts(40));
}

#[tokio::test]
async fn stale_duplicate_and_out_of_order_changes_are_handled() {
    let dir = TmpDir::new();
    let r = open(&dir.0).await;
    ReplicaSink::apply(
        &r,
        batch(ts(50), vec![up(principal("a", "pw", 1, 5), ts(50))]),
    )
    .await
    .expect("apply");

    // An older update is skipped; an equal version is idempotent.
    let out = ReplicaSink::apply(
        &r,
        batch(
            ts(60),
            vec![
                up(principal("a", "old", 1, 1), ts(40)),
                up(principal("a", "pw", 1, 5), ts(50)),
            ],
        ),
    )
    .await
    .expect("apply");
    assert_eq!((out.applied, out.skipped_stale), (0, 2));
    assert_eq!(epoch_of(&r, "a").await, Some(5));

    // Out of order within a batch: the newest version wins either way.
    ReplicaSink::apply(
        &r,
        batch(
            ts(90),
            vec![
                up(principal("b", "v3", 1, 3), ts(80)),
                up(principal("b", "v2", 1, 2), ts(70)),
            ],
        ),
    )
    .await
    .expect("apply");
    assert_eq!(epoch_of(&r, "b").await, Some(3));

    // The checkpoint never moves backwards.
    ReplicaSink::apply(&r, batch(ts(10), vec![]))
        .await
        .expect("empty");
    assert_eq!(r.checkpoint().await.expect("cp").expect("some").ts, ts(90));
}

#[tokio::test]
async fn tombstones_block_a_stale_resurrection() {
    let dir = TmpDir::new();
    let r = open(&dir.0).await;
    // A delete arriving before any create leaves a tombstone.
    ReplicaSink::apply(&r, batch(ts(20), vec![del("ghost", ts(20))]))
        .await
        .expect("delete");
    let out = ReplicaSink::apply(
        &r,
        batch(ts(25), vec![up(principal("ghost", "pw", 1, 1), ts(10))]),
    )
    .await
    .expect("stale create");
    assert_eq!(out.skipped_stale, 1);
    assert!(r
        .lookup(&name("ghost"), REALM)
        .await
        .expect("lookup")
        .is_none());

    // The same for a deleted principal that existed.
    ReplicaSink::apply(
        &r,
        batch(ts(30), vec![up(principal("a", "pw", 1, 1), ts(30))]),
    )
    .await
    .expect("create");
    ReplicaSink::apply(&r, batch(ts(40), vec![del("a", ts(40))]))
        .await
        .expect("delete");
    let out = ReplicaSink::apply(
        &r,
        batch(ts(45), vec![up(principal("a", "pw", 1, 9), ts(35))]),
    )
    .await
    .expect("stale update");
    assert_eq!(out.skipped_stale, 1);
    assert!(r.lookup(&name("a"), REALM).await.expect("lookup").is_none());
}

#[tokio::test]
async fn a_failing_change_applies_nothing_and_leaves_the_checkpoint() {
    let dir = TmpDir::new();
    let r = open(&dir.0).await;
    ReplicaSink::apply(
        &r,
        batch(ts(10), vec![up(principal("keep", "pw", 1, 1), ts(10))]),
    )
    .await
    .expect("apply");

    // The last change has two keys with the same (kvno, enctype): the unique
    // index rejects it after the earlier changes were already written.
    let mut bad = principal("bad", "pw", 1, 1);
    let dup: StoredKey = bad.keys[0].clone();
    bad.keys.push(dup);
    let err = ReplicaSink::apply(
        &r,
        batch(
            ts(20),
            vec![
                up(principal("new1", "pw", 1, 1), ts(20)),
                up(principal("keep", "pw", 1, 99), ts(20)),
                up(bad, ts(20)),
            ],
        ),
    )
    .await
    .expect_err("invalid change");
    assert_eq!(err.kind(), StoreErrorKind::Conflict, "{err}");
    assert!(r
        .lookup(&name("new1"), REALM)
        .await
        .expect("lookup")
        .is_none());
    assert_eq!(epoch_of(&r, "keep").await, Some(1));
    assert_eq!(r.checkpoint().await.expect("cp").expect("some").ts, ts(10));
    assert!(r.status().await.expect("status").last_apply_error.is_some());
    // A later good batch clears the error.
    ReplicaSink::apply(&r, batch(ts(30), vec![]))
        .await
        .expect("apply");
    assert!(r.status().await.expect("status").last_apply_error.is_none());
}

#[tokio::test]
async fn policies_and_lockouts_replicate_too() {
    let dir = TmpDir::new();
    let r = open(&dir.0).await;
    let policy = Policy {
        name: "lock".into(),
        pw_max_fail: 3,
        pw_failcnt_interval: 60,
        pw_lockout_duration: 600,
        security_epoch: 4,
        allowed_keysalts: Some("aes256-cts-hmac-sha1-96:normal".into()),
        tl_data: vec![krb5_rs::kdc::PolicyTlData {
            kind: 300,
            data: b"tl".to_vec(),
        }],
        ..Policy::default()
    };
    ReplicaSink::apply(
        &r,
        batch(
            ts(10),
            vec![
                Change::UpsertPolicy {
                    policy: policy.clone(),
                    version: ts(10),
                },
                Change::UpsertLockout {
                    record: LockoutRecord {
                        realm: REALM.into(),
                        name: name("victim"),
                        locked_at: 1_000,
                        unlock_at: None,
                        source_kdc: "kdc-1".into(),
                    },
                    version: ts(10),
                },
            ],
        ),
    )
    .await
    .expect("apply");
    assert_eq!(r.policy("lock").await.expect("policy"), Some(policy));
    // A replicated, still-active lockout shows up in the auth state.
    let st = r.auth_state(&name("victim"), REALM).await.expect("state");
    assert_eq!((st.fail_count, st.last_failed), (u32::MAX, 1_000));
    // Lifting it (a newer delete) removes it; the policy can be deleted too.
    ReplicaSink::apply(
        &r,
        batch(
            ts(20),
            vec![
                Change::DeleteLockout {
                    realm: REALM.into(),
                    name: name("victim"),
                    version: ts(20),
                },
                Change::DeletePolicy {
                    name: "lock".into(),
                    version: ts(20),
                },
            ],
        ),
    )
    .await
    .expect("apply");
    assert_eq!(
        r.auth_state(&name("victim"), REALM)
            .await
            .expect("state")
            .fail_count,
        0
    );
    assert!(r.policy("lock").await.expect("policy").is_none());
}

// ------------------------------------------------------------ crash

/// Child half of the crash test: apply one batch, then die inside the second
/// one, between its statements and the commit.
#[tokio::test]
#[ignore = "run by the crash-recovery test in a child process"]
async fn crash_child() {
    let Ok(dir) = std::env::var("KRB5RS_TURSO_CRASH_DIR") else {
        return;
    };
    let armed = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let flag = Arc::clone(&armed);
    let options = TursoOptions {
        fail_point: FailPoint::new(move |point| {
            if flag.load(Ordering::SeqCst) && point == "apply:before_commit" {
                std::process::abort();
            }
        }),
        ..TursoOptions::default()
    };
    let r = open_with(Path::new(&dir), options).await;
    ReplicaSink::apply(
        &r,
        batch(ts(10), vec![up(principal("durable", "pw", 1, 1), ts(10))]),
    )
    .await
    .expect("first batch");
    armed.store(true, Ordering::SeqCst);
    let _ = ReplicaSink::apply(
        &r,
        batch(
            ts(20),
            vec![
                up(principal("lost", "pw", 1, 1), ts(20)),
                up(principal("durable", "pw", 1, 77), ts(20)),
            ],
        ),
    )
    .await;
    unreachable!("the fail point aborts the process");
}

#[tokio::test]
async fn a_process_killed_mid_batch_recovers_to_the_last_committed_state() {
    let dir = TmpDir::new();
    let exe = std::env::current_exe().expect("test exe");
    let status = std::process::Command::new(exe)
        .args(["--exact", "crash_child", "--ignored", "--nocapture"])
        .env("KRB5RS_TURSO_CRASH_DIR", &dir.0)
        .status()
        .expect("spawn child");
    assert!(!status.success(), "the child must have died");

    let r = open(&dir.0).await;
    assert_eq!(r.checkpoint().await.expect("cp").expect("some").ts, ts(10));
    assert_eq!(epoch_of(&r, "durable").await, Some(1));
    assert!(r
        .lookup(&name("lost"), REALM)
        .await
        .expect("lookup")
        .is_none());
    // And it still takes writes.
    ReplicaSink::apply(
        &r,
        batch(ts(30), vec![up(principal("lost", "pw", 1, 2), ts(30))]),
    )
    .await
    .expect("apply after recovery");
    assert_eq!(epoch_of(&r, "lost").await, Some(2));
}

// ------------------------------------------------------- concurrency

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn readers_see_consistent_principal_and_keys_while_a_writer_applies() {
    let dir = TmpDir::new();
    let r = open_with(
        &dir.0,
        TursoOptions {
            pool_size: 8,
            ..TursoOptions::default()
        },
    )
    .await;
    // Generation g: kvno = g, epoch = g, password "pw-g": keys and epoch must agree.
    let generation = |g: u32| principal("hot", &format!("pw-{g}"), g, u64::from(g));
    ReplicaSink::apply(&r, batch(ts(1), vec![up(generation(1), ts(1))]))
        .await
        .expect("seed");

    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let mut readers = Vec::new();
    for _ in 0..8 {
        let (r, stop) = (r.clone(), Arc::clone(&stop));
        readers.push(tokio::spawn(async move {
            let mut reads = 0u64;
            while !stop.load(Ordering::Relaxed) {
                let e = r
                    .lookup(&name("hot"), REALM)
                    .await
                    .expect("lookup never fails during replication")
                    .expect("the principal always exists");
                let kvno = e.keys[0].kvno;
                assert_eq!(u64::from(kvno), e.security_epoch, "torn read");
                assert!(
                    e.keys.iter().all(|k| k.kvno == kvno),
                    "mixed key generations"
                );
                reads += 1;
            }
            reads
        }));
    }
    for g in 2..=60u32 {
        ReplicaSink::apply(
            &r,
            batch(ts(i64::from(g)), vec![up(generation(g), ts(i64::from(g)))]),
        )
        .await
        .expect("apply");
    }
    stop.store(true, Ordering::Relaxed);
    let mut total = 0;
    for h in readers {
        total += h.await.expect("reader");
    }
    assert!(total > 0);
    assert_eq!(epoch_of(&r, "hot").await, Some(60));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_writers_on_one_row_both_commit_after_retries() {
    let dir = TmpDir::new();
    let r = open(&dir.0).await;
    let who = name("contended");
    let mut tasks = Vec::new();
    for _ in 0..8 {
        let (r, who) = (r.clone(), who.clone());
        tasks.push(tokio::spawn(async move {
            for _ in 0..10 {
                AuthStateStore::apply(
                    &r,
                    &who,
                    REALM,
                    &AuthStateUpdate::Failure {
                        stamp: 100,
                        failcnt_interval: 0,
                        last_admin_unlock: None,
                    },
                )
                .await
                .expect("auth-state write");
            }
        }));
    }
    for t in tasks {
        t.await.expect("writer");
    }
    // 80 failures, none lost to a conflict.
    let st = r.auth_state(&who, REALM).await.expect("state");
    assert_eq!(st.fail_count, 80);
    println!("auth retries: {}", r.metrics().auth_retries());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_apply_and_an_auth_state_write_race_without_losing_either() {
    let dir = TmpDir::new();
    let r = open(&dir.0).await;
    let who = name("racer");
    let applier = {
        let r = r.clone();
        tokio::spawn(async move {
            for g in 1..=30u32 {
                ReplicaSink::apply(
                    &r,
                    batch(
                        ts(i64::from(g)),
                        vec![up(
                            principal("racer", "pw", g, u64::from(g)),
                            ts(i64::from(g)),
                        )],
                    ),
                )
                .await
                .expect("apply");
            }
        })
    };
    let failer = {
        let (r, who) = (r.clone(), who.clone());
        tokio::spawn(async move {
            for _ in 0..30 {
                AuthStateStore::apply(
                    &r,
                    &who,
                    REALM,
                    &AuthStateUpdate::Failure {
                        stamp: 1,
                        failcnt_interval: 0,
                        last_admin_unlock: None,
                    },
                )
                .await
                .expect("auth write");
            }
        })
    };
    applier.await.expect("applier");
    failer.await.expect("failer");
    assert_eq!(epoch_of(&r, "racer").await, Some(30));
    assert_eq!(
        r.auth_state(&who, REALM).await.expect("state").fail_count,
        30
    );
}

#[tokio::test]
async fn recorded_auth_failures_survive_a_rebuild() {
    let dir = TmpDir::new();
    let r = open(&dir.0).await;
    let who = name("victim");
    for stamp in [100, 200] {
        AuthStateStore::apply(
            &r,
            &who,
            REALM,
            &AuthStateUpdate::Failure {
                stamp,
                failcnt_interval: 0,
                last_admin_unlock: None,
            },
        )
        .await
        .expect("record failure");
    }
    let before = r.auth_state(&who, REALM).await.expect("state before");
    assert_eq!((before.fail_count, before.last_failed), (2, 200));

    let mut rebuild = r.begin_rebuild(ts(100)).await.expect("begin rebuild");
    rebuild.write(Vec::new()).await.expect("empty snapshot");
    rebuild.commit().await.expect("commit rebuild");

    let after = r.auth_state(&who, REALM).await.expect("state after");
    assert_eq!(after.fail_count, before.fail_count);
    assert_eq!(after.last_failed, before.last_failed);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_auth_failures_racing_a_rebuild_are_all_preserved() {
    let dir = TmpDir::new();
    let options = TursoOptions {
        max_retries: 128,
        ..TursoOptions::default()
    };
    let r = open_with(&dir.0, options).await;
    let who = name("racer");
    for stamp in 0..7 {
        AuthStateStore::apply(
            &r,
            &who,
            REALM,
            &AuthStateUpdate::Failure {
                stamp,
                failcnt_interval: 0,
                last_admin_unlock: None,
            },
        )
        .await
        .expect("seed failure");
    }

    let mut rebuild = r.begin_rebuild(ts(100)).await.expect("begin rebuild");
    rebuild.write(Vec::new()).await.expect("empty snapshot");

    let barrier = Arc::new(tokio::sync::Barrier::new(52));
    let mut writers = Vec::new();
    for _ in 0..50 {
        let (r, who, barrier) = (r.clone(), who.clone(), Arc::clone(&barrier));
        writers.push(tokio::spawn(async move {
            barrier.wait().await;
            AuthStateStore::apply(
                &r,
                &who,
                REALM,
                &AuthStateUpdate::Failure {
                    stamp: 10,
                    failcnt_interval: 0,
                    last_admin_unlock: None,
                },
            )
            .await
            .expect("concurrent failure");
        }));
    }
    let commit_barrier = Arc::clone(&barrier);
    let commit = tokio::spawn(async move {
        commit_barrier.wait().await;
        rebuild.commit().await.expect("commit rebuild");
    });
    barrier.wait().await;
    for writer in writers {
        writer.await.expect("writer task");
    }
    commit.await.expect("rebuild task");

    assert_eq!(
        r.auth_state(&who, REALM)
            .await
            .expect("final state")
            .fail_count,
        57
    );
}

// ------------------------------------------------------------ rebuild

fn files_of(dir: &TmpDir) -> Vec<String> {
    dir.files()
        .into_iter()
        .filter(|f| f.starts_with("replica-"))
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_rebuild_switches_atomically_while_readers_run_and_old_files_go() {
    let dir = TmpDir::new();
    let r = open(&dir.0).await;
    ReplicaSink::apply(
        &r,
        batch(ts(10), vec![up(principal("old", "pw", 1, 1), ts(10))]),
    )
    .await
    .expect("apply");
    let old_file = r.current_database();

    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let reader = {
        let (r, stop) = (r.clone(), Arc::clone(&stop));
        tokio::spawn(async move {
            // Lookups never fail; and once the new database is visible the old
            // one never shows again (the switch is atomic and one way).
            while !stop.load(Ordering::Relaxed) {
                let new = r.lookup(&name("new"), REALM).await.expect("lookup");
                let old = r.lookup(&name("old"), REALM).await.expect("lookup");
                if new.is_some() {
                    assert!(old.is_none(), "both worlds visible after the switch");
                }
            }
        })
    };

    let mut rebuild = r.begin_rebuild(ts(100)).await.expect("begin");
    // Readers still see the old database while the snapshot is written.
    assert!(r
        .lookup(&name("new"), REALM)
        .await
        .expect("lookup")
        .is_none());
    rebuild
        .write(vec![up(principal("new", "pw", 1, 1), ts(90))])
        .await
        .expect("write");
    rebuild.commit().await.expect("commit");

    assert!(r
        .lookup(&name("new"), REALM)
        .await
        .expect("lookup")
        .is_some());
    assert!(r
        .lookup(&name("old"), REALM)
        .await
        .expect("lookup")
        .is_none());
    let cp = r.checkpoint().await.expect("cp").expect("some");
    assert_eq!((cp.ts, cp.snapshot_ts), (ts(100), Some(ts(100))));
    assert_ne!(r.current_database(), old_file);

    stop.store(true, Ordering::Relaxed);
    reader.await.expect("reader");
    r.cleanup_old_files();
    assert!(
        !old_file.exists(),
        "old database removed: {:?}",
        dir.files()
    );
    assert_eq!(
        files_of(&dir).iter().filter(|f| f.ends_with(".db")).count(),
        1,
        "{:?}",
        dir.files()
    );
}

#[tokio::test]
async fn a_restart_follows_current_and_an_aborted_rebuild_leaves_nothing() {
    let dir = TmpDir::new();
    {
        let r = open(&dir.0).await;
        ReplicaSink::apply(
            &r,
            batch(ts(10), vec![up(principal("old", "pw", 1, 1), ts(10))]),
        )
        .await
        .expect("apply");
        // An aborted rebuild changes nothing and removes its files.
        let mut aborted = r.begin_rebuild(ts(50)).await.expect("begin");
        aborted
            .write(vec![up(principal("never", "pw", 1, 1), ts(50))])
            .await
            .expect("write");
        aborted.abort().await.expect("abort");
        assert!(r
            .lookup(&name("never"), REALM)
            .await
            .expect("lookup")
            .is_none());
        assert_eq!(
            files_of(&dir).iter().filter(|f| f.ends_with(".db")).count(),
            1
        );

        let mut b = r.begin_rebuild(ts(100)).await.expect("begin");
        b.write(vec![up(principal("new", "pw", 1, 1), ts(100))])
            .await
            .expect("write");
        b.commit().await.expect("commit");
    }
    // A leftover from a crashed, uncommitted rebuild is cleaned on open.
    std::fs::write(dir.0.join("replica-999.db"), b"junk").expect("orphan");
    let r = open(&dir.0).await;
    assert!(r
        .lookup(&name("new"), REALM)
        .await
        .expect("lookup")
        .is_some());
    assert!(r
        .lookup(&name("old"), REALM)
        .await
        .expect("lookup")
        .is_none());
    assert_eq!(r.checkpoint().await.expect("cp").expect("some").ts, ts(100));
    assert!(!dir.0.join("replica-999.db").exists());
    assert_eq!(
        files_of(&dir).iter().filter(|f| f.ends_with(".db")).count(),
        1,
        "{:?}",
        dir.files()
    );
}

// ------------------------------------------------- KDC end to end, at rest

fn service() -> PrincipalName {
    PrincipalName::new_srv_hst("HTTP", "svc.turso.test")
}

/// Principals created by a FileStore, converted for replication.
fn file_store_changes(dir: &TmpDir) -> Vec<Change> {
    use krb5_rs::crypto::SaltType;
    use krb5_rs::kdc::kdb::admin::{Admin, PrincipalOptions};
    use krb5_rs::kdc::kdb::FileStore;
    let store = FileStore::create(&dir.0.join("principal"), REALM, &master()).expect("create");
    let admin = Admin::new(&store, vec![(18, SaltType::Normal), (17, SaltType::Normal)]);
    let plain = PrincipalOptions::default();
    admin
        .add_principal(&name("alice"), REALM, Some("alice-pw"), &plain)
        .expect("alice");
    admin
        .add_principal(&service(), REALM, None, &plain)
        .expect("service");
    let mut out = Vec::new();
    for (i, e) in store.list().expect("list").into_iter().enumerate() {
        let rec = store
            .get_record(&e.name, &e.realm)
            .expect("record")
            .expect("present");
        out.push(up(
            StoredPrincipal::from_entry(
                &rec.entry,
                rec.last_pwd_change.map(|t| t.timestamp()),
                None,
                &master(),
            )
            .expect("stored"),
            ts(1 + i64::try_from(i).expect("small")),
        ));
    }
    out
}

#[tokio::test]
async fn a_kdc_on_the_replica_serves_as_and_tgs_and_counts_lockouts() {
    let files = TmpDir::new();
    let changes = file_store_changes(&files);
    let dir = TmpDir::new();
    let r = open(&dir.0).await;
    ReplicaSink::apply(&r, batch(ts(10), changes))
        .await
        .expect("apply");
    ReplicaSink::apply(
        &r,
        batch(
            ts(11),
            vec![Change::UpsertPolicy {
                policy: Policy {
                    name: "lock".into(),
                    pw_max_fail: 2,
                    pw_lockout_duration: 3600,
                    ..Policy::default()
                },
                version: ts(11),
            }],
        ),
    )
    .await
    .expect("policy");
    // Put alice under the policy with preauth required (a newer version).
    let mut alice = r
        .lookup(&name("alice"), REALM)
        .await
        .expect("lookup")
        .expect("alice");
    alice.policy = Some("lock".into());
    alice.attributes |= PrincipalAttributes::REQUIRES_PRE_AUTH;
    ReplicaSink::apply(
        &r,
        batch(
            ts(12),
            vec![up(
                StoredPrincipal::from_entry(&alice, None, None, &master()).expect("stored"),
                ts(12),
            )],
        ),
    )
    .await
    .expect("update alice");

    let kdc = Kdc::builder(KdcConfig::new(REALM), r.clone())
        .policies(r.clone())
        .auth_state(r.clone())
        .build();

    let login = |pw: &'static str| {
        let kdc = &kdc;
        async move {
            let config = AsExchangeConfig::new(name("alice"), REALM);
            let mut ex = AsExchange::new(config, pw);
            let mut reply = Vec::new();
            loop {
                match ex.step(&reply) {
                    Ok(StepResult::SendToKdc { data, .. })
                    | Ok(StepResult::RetryTcp { data, .. }) => {
                        reply = kdc.handle(&data).await;
                    }
                    Ok(StepResult::Complete) => return Ok(ex.credential().expect("TGT").clone()),
                    Err(e) => return Err(e),
                }
            }
        }
    };
    let tgt = login("alice-pw").await.expect("AS");
    let mut tgs = TgsExchange::new(tgt, service(), TgsOptions::default());
    let mut reply = Vec::new();
    while let TgsStepResult::SendToKdc { data, .. } | TgsStepResult::RetryTcp { data, .. } =
        tgs.step(&reply).expect("TGS step")
    {
        reply = kdc.handle(&data).await;
    }
    assert!(tgs.credential().is_ok(), "TGS issued a ticket");

    // Two wrong passwords lock alice out; the counters live in Turso.
    assert!(login("nope").await.is_err());
    assert!(login("nope").await.is_err());
    let st = r.auth_state(&name("alice"), REALM).await.expect("state");
    assert_eq!(st.fail_count, 2);
    let locked = login("alice-pw").await.expect_err("locked out");
    assert!(
        format!("{locked:?}").contains("18") || format!("{locked}").contains("revoked"),
        "{locked:?}"
    );
}

#[tokio::test]
async fn an_as_request_honours_a_lockout_replicated_from_the_authority() {
    let files = TmpDir::new();
    let changes = file_store_changes(&files);
    let dir = TmpDir::new();
    let r = open(&dir.0).await;
    ReplicaSink::apply(&r, batch(ts(10), changes))
        .await
        .expect("principals");
    ReplicaSink::apply(
        &r,
        batch(
            ts(11),
            vec![Change::UpsertPolicy {
                policy: Policy {
                    name: "lock".into(),
                    pw_max_fail: 2,
                    pw_lockout_duration: 0,
                    ..Policy::default()
                },
                version: ts(11),
            }],
        ),
    )
    .await
    .expect("policy");
    let mut alice = r
        .lookup(&name("alice"), REALM)
        .await
        .expect("lookup")
        .expect("alice");
    alice.policy = Some("lock".into());
    alice.attributes |= PrincipalAttributes::REQUIRES_PRE_AUTH;
    ReplicaSink::apply(
        &r,
        batch(
            ts(12),
            vec![up(
                StoredPrincipal::from_entry(&alice, None, None, &master()).expect("stored"),
                ts(12),
            )],
        ),
    )
    .await
    .expect("policy assignment");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs() as i64;
    ReplicaSink::apply(
        &r,
        batch(
            ts(13),
            vec![Change::UpsertLockout {
                record: LockoutRecord {
                    realm: REALM.into(),
                    name: name("alice"),
                    locked_at: now,
                    unlock_at: None,
                    source_kdc: "kdc-primary".into(),
                },
                version: ts(13),
            }],
        ),
    )
    .await
    .expect("lockout");

    let kdc = Kdc::builder(KdcConfig::new(REALM), r.clone())
        .policies(r.clone())
        .auth_state(r.clone())
        .build();
    let mut exchange = AsExchange::new(AsExchangeConfig::new(name("alice"), REALM), "alice-pw");
    let mut reply = Vec::new();
    let code = loop {
        match exchange.step(&reply).expect("AS step") {
            StepResult::SendToKdc { data, .. } | StepResult::RetryTcp { data, .. } => {
                reply = kdc.handle(&data).await;
                if let Ok(err) = rasn::der::decode::<krb5_rs::types::KrbErrorMsg>(&reply) {
                    break err.error_code;
                }
            }
            StepResult::Complete => panic!("the locked principal unexpectedly received a TGT"),
        }
    };
    assert_eq!(
        code, 18,
        "replicated lockout must be KDC_ERR_CLIENT_REVOKED"
    );
}

#[tokio::test]
async fn no_plaintext_key_bytes_reach_the_database_files() {
    let dir = TmpDir::new();
    let r = open(&dir.0).await;
    let mut store = MemoryStore::new();
    store
        .add_with_password(
            name("secret"),
            REALM,
            "very-secret-password",
            1,
            &[18],
            PrincipalAttributes::empty(),
        )
        .expect("add");
    let entry = store.get(&name("secret"), REALM).expect("entry");
    let key = entry.keys[0].key.key_bytes().to_vec();
    ReplicaSink::apply(
        &r,
        batch(
            ts(1),
            vec![up(
                StoredPrincipal::from_entry(&entry, None, None, &master()).expect("stored"),
                ts(1),
            )],
        ),
    )
    .await
    .expect("apply");
    // Also force the log into the database file, then scan everything.
    drop(r);
    let r = open(&dir.0).await;
    assert!(r
        .lookup(&name("secret"), REALM)
        .await
        .expect("lookup")
        .is_some());
    drop(r);
    let mut scanned = 0;
    for f in dir.files() {
        let bytes = std::fs::read(dir.0.join(&f)).expect("read");
        scanned += bytes.len();
        assert!(
            !bytes.windows(key.len()).any(|w| w == key.as_slice()),
            "plaintext key found in {f}"
        );
        assert!(!bytes.windows(20).any(|w| w == b"very-secret-password"));
    }
    assert!(scanned > 0);
}
