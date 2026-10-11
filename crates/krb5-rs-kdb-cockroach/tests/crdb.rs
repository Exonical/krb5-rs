//! Integration tests against a real CockroachDB cluster. All are `#[ignore]`d:
//! start the cluster with `tests/crdb/cluster.sh up` and run
//! `cargo test -p krb5-rs-kdb-cockroach --test crdb -- --ignored --test-threads=1`
//! (set `CRDB_HOST` to the address that reaches the published ports).

mod common;

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use common::*;
use krb5_rs::kdc::kdb::admin::{AdminOps, PolicyChange, PrincipalOptions};
use krb5_rs::kdc::replication::{
    Change, ReplicationSource, ReplicationTs, Snapshot, StoredPrincipal,
};
use krb5_rs::kdc::{
    AdminStore, AuthoritativeState, LockoutReport, LockoutReporter, PrincipalAttributes,
    StoreErrorKind,
};
use krb5_rs_kdb_cockroach::{
    CockroachConfig, CockroachLockoutReporter, CockroachStore, FailPoint, MigrateOptions,
    MultiRegion,
};

fn ops(store: &CockroachStore) -> AdminOps<CockroachStore> {
    AdminOps::new(store.clone(), keysalts())
}

fn plain() -> PrincipalOptions {
    PrincipalOptions::default()
}

fn delegate(to: &str) -> PrincipalOptions {
    PrincipalOptions {
        delegate_to: vec![to.to_string()],
        ..PrincipalOptions::default()
    }
}

async fn count(db: &TestDb, table: &str) -> i64 {
    db.text(&format!("SELECT count(*)::STRING FROM {table}"))
        .await[0]
        .parse()
        .expect("count")
}

// ------------------------------------------------------------ migrations

#[tokio::test]
#[ignore = "needs the CockroachDB test cluster"]
async fn migrations_are_idempotent() {
    let db = TestDb::new("migrate").await;
    let opts = MigrateOptions {
        create_roles: true,
        multi_region: None,
    };
    let first = CockroachStore::migrate(db.root(), &opts)
        .await
        .expect("first");
    let second = CockroachStore::migrate(db.root(), &opts)
        .await
        .expect("second");
    assert_eq!((first.from, first.to), (0, 1));
    assert_eq!((second.from, second.to), (1, 1));
    assert_eq!(count(&db, "schema_migrations").await, 1);
    let tables = db
        .text("SELECT string_agg(table_name, ',' ORDER BY table_name) FROM [SHOW TABLES]")
        .await;
    for t in [
        "lockouts",
        "policies",
        "principal_keys",
        "principals",
        "realms",
        "replica_status",
        "replication_log",
        "replication_meta",
        "schema_migrations",
    ] {
        assert!(tables[0].contains(t), "{t} missing from {}", tables[0]);
    }
    // A store refuses a database that has not been migrated.
    let empty = TestDb::new("unmigrated").await;
    let err = CockroachStore::connect(empty.admin(), master(), REALM)
        .await
        .expect_err("needs migrate");
    assert!(err.message().contains("migrate"), "{err}");
    empty.drop_db().await;
    db.drop_db().await;
}

#[tokio::test]
#[ignore = "needs the CockroachDB test cluster"]
async fn the_multi_region_step_sets_regions_global_tables_and_regional_by_row() {
    let db = TestDb::new("multiregion").await;
    CockroachStore::migrate(
        db.root(),
        &MigrateOptions {
            create_roles: true,
            multi_region: Some(MultiRegion {
                primary_region: "california".into(),
                regions: vec!["california".into(), "ohio".into(), "washington-dc".into()],
            }),
        },
    )
    .await
    .expect("migrate");
    // Idempotent.
    CockroachStore::migrate(
        db.root(),
        &MigrateOptions {
            create_roles: false,
            multi_region: Some(MultiRegion {
                primary_region: "california".into(),
                regions: vec!["california".into(), "ohio".into(), "washington-dc".into()],
            }),
        },
    )
    .await
    .expect("migrate again");
    let regions = db
        .text("SELECT string_agg(region, ',' ORDER BY region) FROM [SHOW REGIONS FROM DATABASE]")
        .await;
    assert_eq!(regions[0], "california,ohio,washington-dc");
    let primary = db
        .text("SELECT region FROM [SHOW REGIONS FROM DATABASE] WHERE \"primary\"")
        .await;
    assert_eq!(primary[0], "california");
    for t in [
        "principals",
        "principal_keys",
        "policies",
        "lockouts",
        "replication_log",
        "replication_meta",
        "realms",
    ] {
        let ddl = db
            .text(&format!(
                "SELECT create_statement FROM [SHOW CREATE TABLE {t}]"
            ))
            .await;
        assert!(ddl[0].contains("LOCALITY GLOBAL"), "{t}: {}", ddl[0]);
    }
    let ddl = db
        .text("SELECT create_statement FROM [SHOW CREATE TABLE replica_status]")
        .await;
    assert!(ddl[0].contains("LOCALITY REGIONAL BY ROW"), "{}", ddl[0]);
    let localities = db
        .text("SELECT string_agg(region, ';' ORDER BY region) FROM [SHOW REGIONS FROM CLUSTER]")
        .await;
    println!("cluster localities: {}", localities[0]);
    for r in ["california", "ohio", "washington-dc"] {
        assert!(localities[0].contains(r), "{}", localities[0]);
    }
    // The realm can be created and administered on the multi-region schema.
    let store = CockroachStore::connect(db.admin(), master(), REALM)
        .await
        .expect("connect");
    store.create_realm(&[18]).await.expect("realm");
    ops(&store)
        .add_principal(&name("alice"), REALM, Some("pw"), &plain())
        .await
        .expect("addprinc");
    db.drop_db().await;
}

// ------------------------------------------------------------------- TLS

#[tokio::test]
#[ignore = "needs the CockroachDB test cluster"]
async fn tls_verify_full_succeeds_wrong_ca_and_missing_client_cert_fail() {
    let db = TestDb::new("tls").await;
    db.migrate().await;
    CockroachStore::connect(db.admin(), master(), REALM)
        .await
        .expect("verify-full with the right CA and client certificate");

    // A certificate that is not the cluster CA does not anchor the server.
    let mut wrong_ca = db.admin();
    wrong_ca.ca = Some(certs().join("client.kdc_admin.crt"));
    let err = CockroachStore::connect(wrong_ca, master(), REALM)
        .await
        .expect_err("wrong CA");
    println!("wrong CA: {err}");

    // No client certificate: the server (certificate authentication) refuses.
    let mut no_cert = db.admin();
    no_cert.cert = None;
    no_cert.key = None;
    let err = CockroachStore::connect(no_cert, master(), REALM)
        .await
        .expect_err("no client certificate");
    println!("no client certificate: {err}");

    // Plaintext is refused unless explicitly allowed.
    let mut plain_cfg = db.admin();
    plain_cfg.url = plain_cfg
        .url
        .replace("sslmode=verify-full", "sslmode=disable");
    let err = CockroachStore::connect(plain_cfg, master(), REALM)
        .await
        .expect_err("plaintext refused");
    assert!(err.message().contains("refused"), "{err}");

    // Password authentication over TLS also works.
    krb5_rs_kdb_cockroach::run_sql(
        &db.root(),
        &format!(
            "CREATE USER IF NOT EXISTS pwuser WITH PASSWORD 'p4ss-word'; \
             GRANT CONNECT ON DATABASE \"{0}\" TO pwuser; \
             GRANT SELECT ON TABLE schema_migrations TO pwuser;",
            db.name
        ),
    )
    .await
    .expect("password user");
    let mut pw = CockroachConfig::new(format!(
        "postgresql://pwuser:p4ss-word@{}:{}/{}?sslmode=verify-full",
        host(),
        port(),
        db.name
    ));
    pw.ca = Some(certs().join("ca.crt"));
    assert!(
        !format!("{pw:?}").contains("p4ss-word"),
        "the password must not be printed"
    );
    CockroachStore::connect(pw, master(), REALM)
        .await
        .expect("password over TLS");
    db.drop_db().await;
}

// ----------------------------------------------------------- admin ops

#[tokio::test]
#[ignore = "needs the CockroachDB test cluster"]
async fn the_realm_needs_the_right_master_key_and_exists_once() {
    let (db, store) = TestDb::with_realm("realm").await;
    CockroachStore::open(db.admin(), master(), REALM)
        .await
        .expect("right key");
    let wrong = krb5_rs::kdc::kdb::master_key_from_password(REALM, "another", 18).expect("key");
    let err = CockroachStore::open(db.admin(), wrong, REALM)
        .await
        .expect_err("wrong master key");
    assert!(err.message().contains("master key"), "{err}");
    let err = store.create_realm(&[18]).await.expect_err("twice");
    assert_eq!(err.kind(), StoreErrorKind::Conflict);
    // K/M and krbtgt exist; keys are stored encrypted, never in the clear.
    assert_eq!(count(&db, "principals").await, 2);
    let leaked = db
        .text(&format!(
            "SELECT count(*)::STRING FROM principal_keys WHERE enc_key = '\\x{}'::BYTES",
            master()
                .key_bytes()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        ))
        .await;
    assert_eq!(
        leaked[0], "0",
        "the master key must not be stored in the clear"
    );
    db.drop_db().await;
}

#[tokio::test]
#[ignore = "needs the CockroachDB test cluster"]
async fn a_failing_transaction_leaves_nothing_partial() {
    let (db, store) = TestDb::with_realm("atomic").await;
    let before = (
        count(&db, "principals").await,
        count(&db, "principal_keys").await,
        count(&db, "replication_log").await,
    );

    // (a) The second key repeats the first's (kvno, enctype): the unique key
    // rejects it after the principal row and the first key were written.
    let mut entry = store
        .get_record(&decode("krbtgt/CRDB.TEST"), REALM)
        .await
        .expect("get")
        .expect("krbtgt")
        .entry;
    entry.name = name("broken");
    let dup = entry.keys[0].clone();
    entry.keys.push(dup);
    let err = store
        .create_principal(entry, None)
        .await
        .expect_err("duplicate key");
    assert_eq!(err.kind(), StoreErrorKind::Conflict, "{err}");
    let after = (
        count(&db, "principals").await,
        count(&db, "principal_keys").await,
        count(&db, "replication_log").await,
    );
    assert_eq!(
        before, after,
        "nothing may remain of the failed transaction"
    );

    // (b) The task dies between the writes and the commit: the connection is
    // discarded, the server rolls the transaction back.
    let armed = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&armed);
    let faulty = CockroachStore::connect_with(
        db.admin(),
        master(),
        REALM,
        FailPoint::new(move |p| {
            if p == "tx:before_release" && flag.load(Ordering::SeqCst) {
                panic!("injected fault");
            }
        }),
    )
    .await
    .expect("connect");
    armed.store(true, Ordering::SeqCst);
    let o = ops(&faulty);
    let task = tokio::spawn(async move {
        let _ = o
            .add_principal(&name("ghost"), REALM, Some("pw"), &plain())
            .await;
    });
    assert!(task.await.expect_err("the task panics").is_panic());
    armed.store(false, Ordering::SeqCst);
    let after = (
        count(&db, "principals").await,
        count(&db, "principal_keys").await,
        count(&db, "replication_log").await,
    );
    assert_eq!(before, after, "an interrupted transaction left rows behind");
    // The pool still works afterwards (the dirty connection was discarded).
    ops(&faulty)
        .add_principal(&name("ghost"), REALM, Some("pw"), &plain())
        .await
        .expect("addprinc");
    assert_eq!(count(&db, "principals").await, before.0 + 1);
    db.drop_db().await;
}

fn decode(s: &str) -> krb5_rs::types::PrincipalName {
    krb5_rs::kdc::replication::decode_principal_key(
        &s.replace('/', "\\/").replacen("\\/", "/", 1),
        1,
    )
    .expect("name")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs the CockroachDB test cluster"]
async fn sixteen_concurrent_modprincs_all_succeed_through_retries() {
    let (db, store) = TestDb::with_realm("modprinc").await;
    ops(&store)
        .add_principal(&name("hot"), REALM, Some("pw"), &plain())
        .await
        .expect("addprinc");
    let mut tasks = Vec::new();
    for t in 0..16 {
        let o = ops(&store);
        tasks.push(tokio::spawn(async move {
            for j in 0..5 {
                o.modify_principal(&name("hot"), REALM, &delegate(&format!("HTTP/t{t}-{j}")))
                    .await
                    .expect("modprinc must succeed through retries");
            }
        }));
    }
    for t in tasks {
        t.await.expect("task");
    }
    let rec = store
        .get_record(&name("hot"), REALM)
        .await
        .expect("get")
        .expect("hot");
    assert_eq!(
        rec.entry.allowed_to_delegate_to.len(),
        80,
        "no update may be lost"
    );
    assert_eq!(
        rec.entry.security_epoch, 81,
        "created at 1, bumped by each of 80 changes"
    );
    let versions = db
        .text("SELECT commit_ts::STRING FROM replication_log WHERE \"key\" = 'hot' ORDER BY commit_ts")
        .await;
    assert_eq!(versions.len(), 81);
    let parsed: Vec<ReplicationTs> = versions.iter().map(|v| v.parse().expect("ts")).collect();
    assert!(
        parsed.windows(2).all(|w| w[0] < w[1]),
        "versions strictly increase"
    );
    let current = db
        .text("SELECT version::STRING FROM principals WHERE name = 'hot'")
        .await;
    assert_eq!(
        current[0].parse::<ReplicationTs>().expect("ts"),
        *parsed.last().expect("some")
    );
    println!(
        "tx retries during the 80 contended updates: {}",
        store.metrics().tx_retries()
    );
    db.drop_db().await;
}

// ------------------------------------------------------------ replication

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs the CockroachDB test cluster"]
async fn every_committed_change_is_eventually_observed_and_none_is_missed() {
    let (db, store) = TestDb::with_realm("complete").await;
    let replica = CockroachStore::connect(db.replica(), master(), REALM)
        .await
        .expect("replica");
    let done = Arc::new(AtomicBool::new(false));
    let final_ts: Arc<std::sync::Mutex<Option<ReplicationTs>>> = Arc::default();

    let mut writers = Vec::new();
    for w in 0..8 {
        let o = ops(&store);
        writers.push(tokio::spawn(async move {
            for j in 0..30 {
                let who = name(&format!("w{w}-{j}"));
                o.add_principal(&who, REALM, Some("pw"), &plain())
                    .await
                    .expect("add");
                o.modify_principal(&who, REALM, &delegate("HTTP/x"))
                    .await
                    .expect("mod");
                if j % 3 == 2 {
                    o.delete_principal(&who, REALM).await.expect("del");
                }
            }
        }));
    }

    let reader = {
        let (replica, done, final_ts) = (replica.clone(), Arc::clone(&done), Arc::clone(&final_ts));
        tokio::spawn(async move {
            let mut seen: HashMap<String, (ReplicationTs, bool)> = HashMap::new();
            let mut since = ReplicationTs::ZERO;
            let mut batches = 0;
            loop {
                let finished = done.load(Ordering::SeqCst);
                let batch = replica
                    .changes_since(since, 25)
                    .await
                    .expect("changes_since");
                assert!(batch.upto >= since, "the checkpoint never goes backwards");
                batches += 1;
                for c in &batch.changes {
                    let (key, version, deleted) = match c {
                        Change::UpsertPrincipal { principal, version } => {
                            (principal.name.to_string(), *version, false)
                        }
                        Change::DeletePrincipal { name, version, .. } => {
                            (name.to_string(), *version, true)
                        }
                        _ => continue,
                    };
                    let e = seen.entry(key).or_insert((ReplicationTs::ZERO, false));
                    if *e < (version, deleted) && version >= e.0 {
                        *e = (version, deleted);
                    }
                }
                since = batch.upto;
                // Follower reads trail the present by about 4.2 s: keep polling
                // until the checkpoint has passed the last commit.
                let target = *final_ts.lock().expect("lock");
                if finished && target.is_some_and(|t| since >= t) {
                    return (seen, batches);
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
    };
    for w in writers {
        w.await.expect("writer");
    }
    let last = db
        .text("SELECT max(commit_ts)::STRING FROM replication_log")
        .await;
    *final_ts.lock().expect("lock") = Some(last[0].parse().expect("ts"));
    done.store(true, Ordering::SeqCst);
    let (seen, batches) = reader.await.expect("reader");
    println!(
        "completeness: {} entities observed over {batches} batches",
        seen.len()
    );

    // 8 writers x 30 principals, a third deleted again; K/M and krbtgt too.
    let live = db
        .text("SELECT name || ' ' || version::STRING FROM principals WHERE name LIKE 'w%'")
        .await;
    assert_eq!(live.len(), 8 * 20);
    for line in &live {
        let (n, v) = line.split_once(' ').expect("name version");
        let (version, deleted) = seen
            .get(n)
            .unwrap_or_else(|| panic!("{n} was never observed"));
        assert!(!deleted, "{n} is live but the reader saw it deleted");
        assert_eq!(
            *version,
            v.parse::<ReplicationTs>().expect("ts"),
            "{n}: final version"
        );
    }
    let deleted: Vec<_> = seen
        .iter()
        .filter(|(k, (_, d))| k.starts_with('w') && *d)
        .collect();
    assert_eq!(deleted.len(), 8 * 10, "every delete was observed");
    db.drop_db().await;
}

#[tokio::test]
#[ignore = "needs the CockroachDB test cluster"]
async fn one_commit_timestamp_is_never_split_across_batches() {
    let (db, store) = TestDb::with_realm("groups").await;
    let o = ops(&store);
    let mut present = db.replica();
    present.replication_read = krb5_rs_kdb_cockroach::ReplicationRead::Present;
    let replica = CockroachStore::connect(present, master(), REALM)
        .await
        .expect("replica");
    // Each iteration commits two log rows with one timestamp: the principal
    // upsert and the lifted lockout.
    for i in 0..12 {
        let who = name(&format!("g{i}"));
        o.add_principal(&who, REALM, Some("pw"), &plain())
            .await
            .expect("add");
        replica
            .report_lockout(&krb5_rs::kdc::replication::LockoutRecord {
                realm: REALM.into(),
                name: who.clone(),
                locked_at: 1,
                unlock_at: None,
                source_kdc: "kdc-test".into(),
            })
            .await
            .expect("report");
        o.modify_principal(
            &who,
            REALM,
            &PrincipalOptions {
                unlock: true,
                ..plain()
            },
        )
        .await
        .expect("unlock lifts the lockout in the same transaction");
    }
    let pairs = db
        .text("SELECT count(*)::STRING FROM (SELECT commit_ts FROM replication_log GROUP BY commit_ts HAVING count(*) = 2)")
        .await;
    assert_eq!(
        pairs[0],
        "13", // 12 unlocks plus the realm creation (K/M and krbtgt)
        "each unlock wrote its principal row and lockout row together"
    );

    // A limit of 1 would split every pair; the batch must still hold both.
    let mut since = ReplicationTs::ZERO;
    let mut batches = 0;
    let mut paired = 0;
    loop {
        let batch = replica.changes_since(since, 1).await.expect("batch");
        if batch.changes.is_empty() {
            break;
        }
        batches += 1;
        // The unlock transaction wrote the principal row and the lockout
        // delete with one timestamp: they must arrive in one batch. (The
        // earlier lockout report is a separate one-row transaction.)
        let together = batch.changes.iter().any(|c| {
            match c {
            Change::DeleteLockout { name, .. } => batch.changes.iter().any(|p| {
                matches!(p, Change::UpsertPrincipal { principal, .. } if principal.name == *name)
            }),
            _ => false,
        }
        });
        if together {
            paired += 1;
        }
        assert!(batch.upto > since, "progress");
        since = batch.upto;
    }
    assert_eq!(paired, 12, "a transaction's rows were split across batches");
    println!(
        "batch limit 1: {batches} batches for {} log rows",
        count(&db, "replication_log").await
    );
    // A larger limit returns the same final state in fewer batches.
    let mut since = ReplicationTs::ZERO;
    let mut big = 0;
    loop {
        let batch = replica.changes_since(since, 1000).await.expect("batch");
        if batch.changes.is_empty() {
            break;
        }
        big += 1;
        since = batch.upto;
    }
    assert!(big < batches);
    db.drop_db().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs the CockroachDB test cluster"]
async fn a_snapshot_plus_changes_since_equals_the_final_state_under_concurrent_writes() {
    let (db, store) = TestDb::with_realm("snapshot").await;
    let o = ops(&store);
    for i in 0..30 {
        o.add_principal(&name(&format!("s{i}")), REALM, Some("pw"), &plain())
            .await
            .expect("seed");
    }
    let replica = CockroachStore::connect(db.replica(), master(), REALM)
        .await
        .expect("replica");

    let mut writers = Vec::new();
    for w in 0..4 {
        let o = ops(&store);
        writers.push(tokio::spawn(async move {
            for j in 0..20 {
                let target = name(&format!("s{}", (w * 7 + j) % 30));
                // (another writer may have deleted the target meanwhile)
                let _ = o
                    .modify_principal(&target, REALM, &delegate(&format!("HTTP/{w}-{j}")))
                    .await;
                if j % 5 == 0 {
                    o.add_principal(&name(&format!("n{w}-{j}")), REALM, Some("pw"), &plain())
                        .await
                        .expect("add");
                }
                if j % 7 == 6 {
                    let _ = o
                        .delete_principal(&name(&format!("s{}", 29 - w)), REALM)
                        .await;
                }
            }
        }));
    }
    tokio::time::sleep(Duration::from_millis(150)).await;

    // The snapshot, page by page, into a model keyed by principal.
    let mut model: HashMap<String, (ReplicationTs, u64, usize)> = HashMap::new();
    let mut snap = replica.snapshot().await.expect("snapshot");
    let t = snap.ts();
    while let Some(page) = snap.next_page().await.expect("page") {
        for c in page {
            if let Change::UpsertPrincipal { principal, version } = c {
                model.insert(
                    principal.name.to_string(),
                    (
                        version,
                        principal.security_epoch,
                        principal.allowed_to_delegate_to.len(),
                    ),
                );
            }
        }
    }
    for w in writers {
        w.await.expect("writer");
    }
    // Then the changes since T, applied only when newer, until the
    // checkpoint (a follower read, about 4.2 s behind) passes the last commit.
    let last: ReplicationTs = db
        .text("SELECT max(commit_ts)::STRING FROM replication_log")
        .await[0]
        .parse()
        .expect("ts");
    let mut since = t;
    loop {
        let batch = replica.changes_since(since, 40).await.expect("changes");
        if batch.changes.is_empty() && since >= last {
            break;
        }
        if batch.changes.is_empty() {
            tokio::time::sleep(Duration::from_millis(200)).await;
            since = batch.upto;
            continue;
        }
        for c in batch.changes {
            match c {
                Change::UpsertPrincipal { principal, version } => {
                    let key = principal.name.to_string();
                    if model.get(&key).is_none_or(|(v, _, _)| *v < version) {
                        model.insert(
                            key,
                            (
                                version,
                                principal.security_epoch,
                                principal.allowed_to_delegate_to.len(),
                            ),
                        );
                    }
                }
                Change::DeletePrincipal { name, .. } => {
                    model.remove(&name.to_string());
                }
                _ => {}
            }
        }
        since = batch.upto;
    }
    let mut truth: HashMap<String, (ReplicationTs, u64, usize)> = HashMap::new();
    for rec in store.list_principals().await.expect("list") {
        let version = db
            .text(&format!(
                "SELECT version::STRING FROM principals WHERE name = '{}'",
                rec.entry.name.to_string().replace('\'', "''")
            ))
            .await;
        truth.insert(
            rec.entry.name.to_string(),
            (
                version[0].parse().expect("ts"),
                rec.entry.security_epoch,
                rec.entry.allowed_to_delegate_to.len(),
            ),
        );
    }
    println!(
        "snapshot at {t}: {} principals in the final state",
        truth.len()
    );
    assert_eq!(
        model, truth,
        "snapshot at T + changes_since(T) must equal the final state"
    );
    db.drop_db().await;
}

#[tokio::test]
#[ignore = "needs the CockroachDB test cluster"]
async fn pruned_before_and_prune_follow_the_log() {
    let (db, store) = TestDb::with_realm("prune").await;
    let replica = CockroachStore::connect(db.replica(), master(), REALM)
        .await
        .expect("replica");
    assert_eq!(replica.pruned_before().await.expect("pruned"), None);
    let o = ops(&store);
    for i in 0..3 {
        o.add_principal(&name(&format!("old{i}")), REALM, Some("pw"), &plain())
            .await
            .expect("add");
    }
    tokio::time::sleep(Duration::from_secs(3)).await;
    for i in 0..3 {
        o.add_principal(&name(&format!("new{i}")), REALM, Some("pw"), &plain())
            .await
            .expect("add");
    }
    let before = count(&db, "replication_log").await;
    // The realm's two principals, three old and three new additions.
    assert_eq!(before, 8);
    let (cutoff, deleted) = store.prune(Duration::from_secs(2)).await.expect("prune");
    assert_eq!(
        deleted, 5,
        "the realm rows and the three old additions are older than 2s"
    );
    assert_eq!(count(&db, "replication_log").await, 3);
    assert_eq!(replica.pruned_before().await.expect("pruned"), Some(cutoff));
    // Pruning never lowers the watermark.
    store
        .prune(Duration::from_secs(3600))
        .await
        .expect("prune again");
    assert_eq!(replica.pruned_before().await.expect("pruned"), Some(cutoff));
    // The replica role may not prune.
    let err = replica
        .prune(Duration::from_secs(0))
        .await
        .expect_err("replica cannot prune");
    println!("replica prune: {err}");
    db.drop_db().await;
}

// --------------------------------------------- authority, lockouts, status

#[tokio::test]
#[ignore = "needs the CockroachDB test cluster"]
async fn authoritative_state_reports_epoch_disabled_and_lockout() {
    let (db, store) = TestDb::with_realm("authority").await;
    let o = ops(&store);
    o.add_principal(&name("bob"), REALM, Some("pw"), &plain())
        .await
        .expect("add");
    let replica = CockroachStore::connect(db.replica(), master(), REALM)
        .await
        .expect("replica");

    let s = replica
        .security_state(&name("bob"), REALM)
        .await
        .expect("state");
    assert_eq!((s.epoch, s.disabled, s.locked), (1, false, false));

    let mut disable = plain();
    disable
        .attributes
        .add_spec("+disallow_all_tix")
        .expect("attr");
    o.modify_principal(&name("bob"), REALM, &disable)
        .await
        .expect("disable");
    let s = replica
        .security_state(&name("bob"), REALM)
        .await
        .expect("state");
    assert_eq!((s.epoch, s.disabled, s.locked), (2, true, false));

    // A lockout reported by a KDC (as the replica user) shows as locked...
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs() as i64;
    let record = krb5_rs::kdc::replication::LockoutRecord {
        realm: REALM.into(),
        name: name("bob"),
        locked_at: now,
        unlock_at: Some(now + 3600),
        source_kdc: "kdc-eu".into(),
    };
    replica.report_lockout(&record).await.expect("report");
    assert!(
        replica
            .security_state(&name("bob"), REALM)
            .await
            .expect("state")
            .locked
    );
    // ... an expired one does not ...
    let expired = krb5_rs::kdc::replication::LockoutRecord {
        unlock_at: Some(now - 10),
        ..record.clone()
    };
    replica.report_lockout(&expired).await.expect("report");
    assert!(
        !replica
            .security_state(&name("bob"), REALM)
            .await
            .expect("state")
            .locked
    );
    // ... and an administrative unlock lifts a standing one, bumping the epoch.
    replica.report_lockout(&record).await.expect("report");
    o.modify_principal(
        &name("bob"),
        REALM,
        &PrincipalOptions {
            unlock: true,
            ..plain()
        },
    )
    .await
    .expect("unlock");
    let s = replica
        .security_state(&name("bob"), REALM)
        .await
        .expect("state");
    assert_eq!((s.epoch, s.locked), (3, false));
    assert_eq!(count(&db, "lockouts").await, 0);

    let err = replica
        .security_state(&name("nobody"), REALM)
        .await
        .expect_err("missing");
    assert_eq!(err.kind(), StoreErrorKind::NotFound);

    // An unreachable database is `Unavailable`, within the connect timeout.
    let mut dead = db.replica();
    dead.url = dead.url.replace(&format!(":{}/", port()), ":1/");
    dead.connect_timeout = Duration::from_secs(2);
    let unreachable = CockroachStore::connect(dead, master(), REALM).await;
    assert!(unreachable.is_err());
    db.drop_db().await;
}

#[tokio::test]
#[ignore = "needs the CockroachDB test cluster"]
async fn the_replica_role_writes_lockouts_and_heartbeats_but_nothing_else() {
    let (db, store) = TestDb::with_realm("privileges").await;
    ops(&store)
        .add_principal(&name("carol"), REALM, Some("pw"), &plain())
        .await
        .expect("add");
    let replica = CockroachStore::connect(db.replica(), master(), REALM)
        .await
        .expect("replica");
    let o = ops(&replica);
    let err = o
        .add_principal(&name("mallory"), REALM, Some("pw"), &plain())
        .await
        .expect_err("a KDC cannot create principals");
    println!("replica create_principal: {err}");
    assert!(o
        .modify_principal(&name("carol"), REALM, &delegate("x"))
        .await
        .is_err());
    assert!(o.delete_principal(&name("carol"), REALM).await.is_err());
    assert!(o
        .add_policy(PolicyChange::default().into_policy("p"))
        .await
        .is_err());
    // It can read what it replicates.
    assert!(replica
        .get_record(&name("carol"), REALM)
        .await
        .expect("read")
        .is_some());
    // And it can heartbeat and report lockouts.
    replica
        .heartbeat("kdc-1", "ohio", ReplicationTs::new(5, 0))
        .await
        .expect("heartbeat");
    db.drop_db().await;
}

#[tokio::test]
#[ignore = "needs the CockroachDB test cluster"]
async fn the_lockout_reporter_writes_in_the_background_and_counts_drops_when_full() {
    let (db, store) = TestDb::with_realm("reporter").await;
    ops(&store)
        .add_principal(&name("dave"), REALM, Some("pw"), &plain())
        .await
        .expect("add");
    let replica = CockroachStore::connect(db.replica(), master(), REALM)
        .await
        .expect("replica");
    let reporter = CockroachLockoutReporter::spawn(replica, "kdc-us", 1);
    let report = |n: &str| LockoutReport {
        principal: name(n),
        realm: REALM.into(),
        stamp: 1_700_000_000,
        fail_count: 5,
        lockout_duration: 600,
    };
    // A burst the single-slot queue cannot hold: report() never blocks; the
    // rest is dropped and counted. (The current-thread runtime does not run
    // the writer during this synchronous loop.)
    for _ in 0..50 {
        reporter.report(report("dave"));
    }
    assert!(reporter.dropped() >= 40, "dropped {}", reporter.dropped());
    for _ in 0..100 {
        if reporter.reported() >= 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(reporter.reported() >= 1);
    assert_eq!(reporter.failed(), 0);
    let row = db
        .text("SELECT locked_at::STRING || ',' || unlock_at::STRING || ',' || source_kdc FROM lockouts WHERE name = 'dave'")
        .await;
    assert_eq!(row[0], "1700000000,1700000600,kdc-us");
    assert!(count(&db, "replication_log").await >= 3);
    println!(
        "reporter: reported {}, dropped {}",
        reporter.reported(),
        reporter.dropped()
    );
    db.drop_db().await;
}

#[tokio::test]
#[ignore = "needs the CockroachDB test cluster"]
async fn heartbeats_drive_wait_applied() {
    let (db, store) = TestDb::with_realm("heartbeat").await;
    let kdc = |region: &'static str| {
        let cfg = db.replica();
        async move {
            CockroachStore::connect(cfg, master(), REALM)
                .await
                .expect("replica")
        }
        .map(move |s| (s, region))
    };
    use futures_like::FutureExt;
    let (a, ra) = kdc("california").await;
    let (b, rb) = kdc("ohio").await;
    let target = ReplicationTs::new(2_000, 0);
    assert_eq!(
        store
            .wait_applied(target, Duration::from_millis(300))
            .await
            .expect("wait"),
        krb5_rs_kdb_cockroach::WaitOutcome {
            applied: 0,
            total: 0
        },
        "nobody has reported"
    );
    a.heartbeat("kdc-a", ra, ReplicationTs::new(3_000, 0))
        .await
        .expect("hb");
    b.heartbeat("kdc-b", rb, ReplicationTs::new(1_000, 0))
        .await
        .expect("hb");
    let out = store
        .wait_applied(target, Duration::from_millis(500))
        .await
        .expect("wait");
    assert_eq!((out.applied, out.total), (1, 2));
    assert!(!out.complete());
    let statuses = store.replica_statuses().await.expect("status");
    assert_eq!(statuses.len(), 2);
    assert_eq!(statuses[0].region, "california");
    // The slow KDC catches up while we wait.
    let waiter = {
        let store = store.clone();
        tokio::spawn(async move { store.wait_applied(target, Duration::from_secs(10)).await })
    };
    tokio::time::sleep(Duration::from_millis(500)).await;
    b.heartbeat("kdc-b", rb, ReplicationTs::new(2_500, 0))
        .await
        .expect("hb");
    let out = waiter.await.expect("task").expect("wait");
    assert!(out.complete(), "{out:?}");
    db.drop_db().await;
}

mod futures_like {
    pub trait FutureExt: std::future::Future + Sized {
        fn map<T>(self, f: impl FnOnce(Self::Output) -> T) -> impl std::future::Future<Output = T> {
            async move { f(self.await) }
        }
    }
    impl<F: std::future::Future> FutureExt for F {}
}

// ----------------------------------------------------------------- parity

#[tokio::test]
#[ignore = "needs the CockroachDB test cluster"]
async fn the_same_admin_scenario_gives_the_same_entries_on_file_and_cockroach() {
    use krb5_rs::kdc::kdb::FileStore;
    let (db, crdb) = TestDb::with_realm("parity").await;
    let dir = std::env::temp_dir().join(format!("krb5rs_parity_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("dir");
    let file = FileStore::create_with(&dir.join("principal"), REALM, &master(), &[18, 17])
        .expect("file store");

    async fn scenario<S: AdminStore>(o: &AdminOps<S>) -> Vec<String> {
        let mut log = Vec::new();
        o.add_policy(
            PolicyChange {
                pw_max_fail: Some(3),
                pw_lockout_duration: Some(600),
                ..PolicyChange::default()
            }
            .into_policy("lock"),
        )
        .await
        .expect("addpol");
        let mut attrs = PrincipalOptions::default();
        attrs
            .attributes
            .add_spec("+requires_preauth")
            .expect("attr");
        attrs.policy = Some(Some("lock".into()));
        attrs.delegate_to = vec!["HTTP/a".into(), "HTTP/b".into()];
        o.add_principal(&name("alice"), REALM, Some("pw1"), &attrs)
            .await
            .expect("add alice");
        o.add_principal(&name("svc"), REALM, None, &PrincipalOptions::default())
            .await
            .expect("add svc");
        o.modify_principal(
            &name("alice"),
            REALM,
            &PrincipalOptions {
                max_life: Some(Some(Duration::from_secs(3600))),
                ..PrincipalOptions::default()
            },
        )
        .await
        .expect("mod");
        let dup = o
            .add_principal(
                &name("alice"),
                REALM,
                Some("x"),
                &PrincipalOptions::default(),
            )
            .await
            .expect_err("dup");
        log.push(format!("dup: {:?}", dup.kind()));
        let kvno = o
            .change_password(&name("alice"), REALM, Some("pw2"), true)
            .await
            .expect("cpw");
        log.push(format!("kvno {kvno}"));
        o.modify_principal(
            &name("alice"),
            REALM,
            &PrincipalOptions {
                unlock: true,
                ..PrincipalOptions::default()
            },
        )
        .await
        .expect("unlock");
        o.modify_principal(
            &name("alice"),
            REALM,
            &PrincipalOptions {
                policy: Some(None),
                ..PrincipalOptions::default()
            },
        )
        .await
        .expect("clear");
        o.modify_policy(
            "lock",
            &PolicyChange {
                pw_max_fail: Some(5),
                ..PolicyChange::default()
            },
        )
        .await
        .expect("modpol");
        o.delete_principal(&name("svc"), REALM).await.expect("del");
        let missing = o
            .delete_principal(&name("svc"), REALM)
            .await
            .expect_err("gone");
        log.push(format!("missing: {:?}", missing.kind()));
        let bad = o
            .modify_principal(
                &name("alice"),
                REALM,
                &PrincipalOptions {
                    policy: Some(Some("nope".into())),
                    ..PrincipalOptions::default()
                },
            )
            .await
            .expect_err("policy");
        log.push(format!("badpol: {:?}", bad.kind()));
        for p in o.list_principals().await.expect("list") {
            if p.starts_with("alice") {
                let rec = o.get_principal(&name("alice"), REALM).await.expect("get");
                let e = &rec.entry;
                // The order of keys within one kvno is not significant.
                let mut kv: Vec<_> = e.keys.iter().map(|k| (k.kvno, k.key.keytype)).collect();
                kv.sort();
                log.push(format!(
                    "{p} attrs={:#x} life={:?} epoch={} policy={:?} to={:?} keys={kv:?} unlock={}",
                    e.attributes.bits(),
                    e.max_life,
                    e.security_epoch,
                    e.policy,
                    e.allowed_to_delegate_to,
                    e.last_admin_unlock.is_some()
                ));
            } else {
                log.push(p);
            }
        }
        let pol = o.get_policy("lock").await.expect("getpol");
        log.push(format!(
            "policy lock: fail={} dur={} epoch={}",
            pol.pw_max_fail, pol.pw_lockout_duration, pol.security_epoch
        ));
        log.push(format!(
            "policies {:?}",
            o.list_policies().await.expect("listpols")
        ));
        log
    }

    let on_file = scenario(&AdminOps::new(&file, keysalts())).await;
    let on_crdb = scenario(&ops(&crdb)).await;
    for l in &on_crdb {
        println!("{l}");
    }
    assert_eq!(on_file, on_crdb);
    let _ = std::fs::remove_dir_all(&dir);
    db.drop_db().await;
    let _ = PrincipalAttributes::empty();
    let _ = StoredPrincipal::from_entry;
}

// ----------------------------------------------------------- measurements

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "measurement: prints latencies, run with --nocapture"]
async fn measure_admin_write_latency_regional_vs_global_and_changes_since() {
    async fn run(db: &TestDb, label: &str) {
        let store = CockroachStore::connect(db.admin(), master(), REALM)
            .await
            .expect("connect");
        store.create_realm(&[18]).await.expect("realm");
        let o = ops(&store);
        let who = name("lat");
        o.add_principal(&who, REALM, Some("pw"), &plain())
            .await
            .expect("add");
        let mut lat = Vec::new();
        for i in 0..60 {
            let t = std::time::Instant::now();
            o.modify_principal(&who, REALM, &delegate(&format!("HTTP/{i}")))
                .await
                .expect("mod");
            lat.push(t.elapsed());
        }
        lat.sort();
        let ms = |d: Duration| d.as_secs_f64() * 1000.0;
        println!(
            "{label}: modprinc n=60 median {:.1} ms, p95 {:.1} ms, max {:.1} ms",
            ms(lat[30]),
            ms(lat[56]),
            ms(lat[59])
        );
        // Let the follower-read horizon (4.2 s) pass over the writes.
        tokio::time::sleep(Duration::from_secs(6)).await;
        let mut present_cfg = db.replica();
        present_cfg.replication_read = krb5_rs_kdb_cockroach::ReplicationRead::Present;
        let present = CockroachStore::connect(present_cfg, master(), REALM)
            .await
            .expect("replica");
        let follower = CockroachStore::connect(db.replica(), master(), REALM)
            .await
            .expect("replica");
        for mode in [
            "batch of 1 log row (limit 1, present read)",
            "batch of 1 log row (limit 1, follower read)",
            "empty poll (follower read)",
            "empty poll (present read)",
        ] {
            let mut samples = Vec::new();
            for _ in 0..40 {
                let replica = if mode.contains("present") {
                    &present
                } else {
                    &follower
                };
                let since = if mode.starts_with("empty") {
                    replica
                        .changes_since(ReplicationTs::ZERO, 1_000_000)
                        .await
                        .expect("c")
                        .upto
                } else {
                    ReplicationTs::ZERO
                };
                let t = std::time::Instant::now();
                let b = replica.changes_since(since, 1).await.expect("changes");
                samples.push(t.elapsed());
                assert_eq!(b.changes.is_empty(), mode.starts_with("empty"), "{mode}");
            }
            samples.sort();
            println!(
                "{label}: changes_since {mode}: median {:.1} ms, p95 {:.1} ms",
                ms(samples[20]),
                ms(samples[38])
            );
        }
    }
    let regional = TestDb::new("latreg").await;
    regional.migrate().await;
    run(&regional, "regional (single-region tables)").await;
    regional.drop_db().await;

    let global = TestDb::new("latglobal").await;
    CockroachStore::migrate(
        global.root(),
        &MigrateOptions {
            create_roles: true,
            multi_region: Some(MultiRegion {
                primary_region: "california".into(),
                regions: vec!["california".into(), "ohio".into(), "washington-dc".into()],
            }),
        },
    )
    .await
    .expect("migrate");
    run(&global, "GLOBAL tables, 3 regions").await;
    global.drop_db().await;
}
