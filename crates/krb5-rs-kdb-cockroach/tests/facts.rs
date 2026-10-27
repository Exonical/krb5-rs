//! Verification of the CockroachDB behaviours docs/architecture/kdb.md §5
//! relies on, against a real cluster (`#[ignore]`d; see tests/crdb/cluster.sh).
//! Run with `-- --ignored --nocapture` to see the evidence.

mod common;

use common::*;
use krb5_rs::kdc::replication::ReplicationTs;
use tokio_postgres::error::SqlState;
use tokio_postgres::{Client, NoTls};

/// A raw session as root (TLS through the crate's own rustls setup is not
/// public, so build one here).
async fn raw(database: &str) -> Client {
    raw_with_options(database, None).await
}

async fn raw_with_options(database: &str, options: Option<&str>) -> Client {
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    let c = config("root", database);
    let mut roots = rustls::RootCertStore::empty();
    for cert in CertificateDer::pem_file_iter(c.ca.as_ref().expect("ca")).expect("ca pem") {
        roots.add(cert.expect("cert")).expect("root");
    }
    let chain: Vec<_> = CertificateDer::pem_file_iter(c.cert.as_ref().expect("cert"))
        .expect("pem")
        .map(|c| c.expect("cert"))
        .collect();
    let key = PrivateKeyDer::from_pem_file(c.key.as_ref().expect("key")).expect("key");
    let provider = std::sync::Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let tls = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("versions")
        .with_root_certificates(roots)
        .with_client_auth_cert(chain, key)
        .expect("client auth");
    let mut pg = tokio_postgres::Config::new();
    pg.host(host())
        .port(port())
        .user("root")
        .dbname(database)
        .ssl_mode(tokio_postgres::config::SslMode::Require);
    if let Some(options) = options {
        pg.options(options);
    }
    let (client, conn) = pg
        .connect(tokio_postgres_rustls::MakeRustlsConnect::new(tls))
        .await
        .expect("connect");
    tokio::spawn(conn);
    let _ = NoTls;
    client
}

#[tokio::test]
#[ignore = "needs the CockroachDB test cluster"]
async fn transaction_timeout_aborts_the_server_transaction_without_a_client_deadline() {
    // `statement_timeout=0` ensures the abort is not a statement/client timer.
    // Root only observes `transaction_timeout` when it is supplied as a
    // connection option, matching the production pool configuration.
    let c = raw_with_options(
        "defaultdb",
        Some("-c transaction_timeout=1s -c statement_timeout=0"),
    )
    .await;
    let setting = one(&c, "SHOW transaction_timeout").await;
    assert_eq!(setting, "1000");
    let table = format!("tx_timeout_pr7_{}", std::process::id());
    c.batch_execute(&format!(
        "CREATE TABLE IF NOT EXISTS {table} (id INT PRIMARY KEY)"
    ))
    .await
    .expect("create");
    c.batch_execute(&format!("DELETE FROM {table}"))
        .await
        .expect("clear");

    c.batch_execute("BEGIN").await.expect("begin");
    c.batch_execute(&format!("INSERT INTO {table} VALUES (1)"))
        .await
        .expect("insert");
    // No query is in flight here. The server must abort the open transaction
    // after its transaction_timeout while the client sleeps.
    tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
    let commit = c.batch_execute("COMMIT").await;
    println!("COMMIT after server transaction_timeout: {commit:?}");
    assert!(commit.is_err(), "the server must abort the expired session");
    let check = raw("defaultdb").await;
    let remaining: i64 = check
        .query_one(&format!("SELECT count(*)::INT8 FROM {table}"), &[])
        .await
        .expect("read after abort")
        .get(0);
    assert_eq!(
        remaining, 0,
        "the server must not commit an expired transaction"
    );
    check
        .batch_execute(&format!("DROP TABLE {table}"))
        .await
        .expect("drop");
}

async fn one(c: &Client, sql: &str) -> String {
    c.query_one(sql, &[]).await.expect(sql).get::<_, String>(0)
}

async fn aost_mvcc(c: &Client, table: &str, t: &str) -> String {
    c.batch_execute(&format!("BEGIN READ ONLY AS OF SYSTEM TIME '{t}'"))
        .await
        .expect("begin AOST");
    assert_eq!(
        one(c, "SELECT cluster_logical_timestamp()::STRING").await,
        t
    );
    let mvcc = one(
        c,
        &format!("SELECT crdb_internal_mvcc_timestamp::STRING FROM {table} WHERE id = 1"),
    )
    .await;
    c.batch_execute("COMMIT").await.expect("commit AOST");
    mvcc
}

#[tokio::test]
#[ignore = "needs the CockroachDB test cluster"]
async fn fact_mvcc_timestamp_is_the_aost_row_version_and_monotonic_on_global_rows() {
    use krb5_rs_kdb_cockroach::{CockroachStore, MigrateOptions, MultiRegion};

    let db = TestDb::new("mvccver").await;
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
    .expect("multi-region migration");
    let c = raw(&db.name).await;
    c.batch_execute(
        "CREATE TABLE mvcc_probe (id INT8 PRIMARY KEY, val INT8 NOT NULL) LOCALITY GLOBAL",
    )
    .await
    .expect("create global probe");
    c.batch_execute("INSERT INTO mvcc_probe VALUES (1, 1)")
        .await
        .expect("insert");

    let t1 = one(&c, "SELECT cluster_logical_timestamp()::STRING").await;
    let v1 = aost_mvcc(&c, "mvcc_probe", &t1)
        .await
        .parse::<ReplicationTs>()
        .expect("initial MVCC");
    println!("GLOBAL MVCC version after insert: {v1}");
    assert_eq!(
        one(&c, "SELECT val::STRING FROM mvcc_probe WHERE id = 1").await,
        "1"
    );

    c.batch_execute("UPDATE mvcc_probe SET val = 2 WHERE id = 1")
        .await
        .expect("update 1");
    let t2 = one(&c, "SELECT cluster_logical_timestamp()::STRING").await;
    let v2 = aost_mvcc(&c, "mvcc_probe", &t2)
        .await
        .parse::<ReplicationTs>()
        .expect("second MVCC");
    assert!(v2 > v1, "first update did not advance the row MVCC version");

    c.batch_execute("UPDATE mvcc_probe SET val = 3 WHERE id = 1")
        .await
        .expect("update 2");
    let t3 = one(&c, "SELECT cluster_logical_timestamp()::STRING").await;
    let v3 = aost_mvcc(&c, "mvcc_probe", &t3)
        .await
        .parse::<ReplicationTs>()
        .expect("third MVCC");
    assert!(
        v3 > v2,
        "second update did not advance the row MVCC version"
    );
    assert_eq!(
        one(&c, "SELECT val::STRING FROM mvcc_probe WHERE id = 1").await,
        "3"
    );
    db.drop_db().await;
}

#[tokio::test]
#[ignore = "needs the CockroachDB test cluster"]
async fn fact_bucket_scan_finds_a_long_transaction_from_its_start_bucket() {
    use krb5_rs_kdb_cockroach::{CockroachStore, MigrateOptions, MultiRegion};

    let db = TestDb::new("bucketold").await;
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
    .expect("multi-region migration");
    let setup = raw(&db.name).await;
    setup
        .batch_execute("CREATE TABLE bucket_probe (id INT8 PRIMARY KEY, val INT8 NOT NULL)")
        .await
        .expect("create probe");
    setup
        .batch_execute("UPDATE replication_meta SET transaction_timeout_ms = 3000 WHERE id = 1")
        .await
        .expect("test transaction bound");

    for attempt in 1..=3 {
        let writer = raw_with_options(
            &db.name,
            Some("-c transaction_timeout=3s -c statement_timeout=0"),
        )
        .await;
        let observer = raw(&db.name).await;
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(20);
        loop {
            let epoch = one(&observer, "SELECT EXTRACT(EPOCH FROM now())::STRING").await;
            let second = epoch.parse::<f64>().expect("server time");
            if second % 10.0 >= 8.5 {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "missed bucket boundary"
            );
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }

        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();
        let (committed_tx, committed_rx) = tokio::sync::oneshot::channel();
        let writer_task = tokio::spawn(async move {
            writer.batch_execute("BEGIN").await.expect("begin writer");
            let txn_start = one(&writer, "SELECT EXTRACT(EPOCH FROM now())::STRING")
                .await
                .parse::<f64>()
                .expect("txn start");
            let bucket = one(
                &writer,
                "SELECT floor(EXTRACT(EPOCH FROM now()) / bucket_width_seconds)::INT8::STRING \
                 FROM replication_meta WHERE id = 1",
            )
            .await
            .parse::<i64>()
            .expect("start bucket");
            started_tx.send((txn_start, bucket)).expect("send start");
            release_rx.await.expect("release writer");
            writer
                .batch_execute(
                    "INSERT INTO bucket_probe VALUES (1, 1); \
                     INSERT INTO replication_log (bucket,id,entity,realm,\"key\",op,txn_id) \
                     SELECT floor(EXTRACT(EPOCH FROM now())/bucket_width_seconds)::INT8, \
                     '00000000-0000-4000-8000-000000000001'::UUID, 'principal', \
                     'R', 'alice', 'upsert', '00000000-0000-4000-8000-000000000002'::UUID \
                     FROM replication_meta WHERE id=1",
                )
                .await
                .expect("write data and log");
            let result = writer.batch_execute("COMMIT").await;
            committed_tx
                .send(
                    result
                        .as_ref()
                        .map_or_else(|e| e.to_string(), |_| "ok".into()),
                )
                .expect("send commit");
            result
        });

        let (txn_start, start_bucket) = started_rx.await.expect("writer started");
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(3);
        let checkpoint_bucket = loop {
            let current_bucket = one(
                &observer,
                "SELECT floor(EXTRACT(EPOCH FROM now())/10)::INT8::STRING",
            )
            .await
            .parse::<i64>()
            .expect("current bucket");
            if current_bucket > start_bucket {
                break current_bucket;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "writer did not span a bucket boundary"
            );
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        };
        let ckpt = one(&observer, "SELECT cluster_logical_timestamp()::STRING").await;
        let ckpt_ts = ckpt.parse::<ReplicationTs>().expect("checkpoint");
        let d = 3_000_000_000i64;
        let width = 10i64;
        let low_bucket = (ckpt_ts.wall_nanos - d)
            .div_euclid(1_000_000_000)
            .div_euclid(width);
        assert!(
            start_bucket >= low_bucket,
            "D scan omitted the writer's bucket"
        );
        assert!(start_bucket < checkpoint_bucket);
        println!(
            "writer transaction start={txn_start}, log bucket={start_bucket}, \
             ckpt={ckpt}, scan low bucket={low_bucket}"
        );
        observer
            .batch_execute(&format!("BEGIN READ ONLY AS OF SYSTEM TIME '{ckpt}'"))
            .await
            .expect("begin checkpoint scan");
        let visible = observer
            .query_one(
                "SELECT count(*)::INT8 FROM replication_log WHERE bucket BETWEEN $1 AND $2",
                &[&low_bucket, &checkpoint_bucket],
            )
            .await
            .expect("scan checkpoint bucket range")
            .get::<_, i64>(0);
        assert_eq!(visible, 0, "the uncommitted log row is not visible at ckpt");
        observer
            .batch_execute("COMMIT")
            .await
            .expect("commit checkpoint scan");
        release_tx.send(()).expect("release writer");
        let writer_commit = committed_rx.await.expect("writer commit time");
        println!("writer commit after checkpoint read: {writer_commit}");
        match writer_task.await.expect("writer completes") {
            Err(e) if attempt < 3 && e.code() == Some(&SqlState::T_R_SERIALIZATION_FAILURE) => {
                println!("attempt {attempt}: writer must retry: {e}");
                continue;
            }
            result => result.expect("commit writer"),
        }

        let t = one(&observer, "SELECT cluster_logical_timestamp()::STRING").await;
        let t_ts = t.parse::<ReplicationTs>().expect("read timestamp");
        let high_bucket = t_ts.wall_nanos.div_euclid(1_000_000_000).div_euclid(width);
        assert!(
            start_bucket < high_bucket,
            "test did not cross a bucket boundary"
        );
        observer
            .batch_execute(&format!("BEGIN READ ONLY AS OF SYSTEM TIME '{t}'"))
            .await
            .expect("begin after-commit AOST");
        let row = observer
            .query_opt(
                "SELECT id::STRING, crdb_internal_mvcc_timestamp::STRING FROM replication_log \
                 WHERE bucket BETWEEN $1 AND $2 \
                 AND crdb_internal_mvcc_timestamp::STRING::DECIMAL > $3::STRING::DECIMAL \
                 AND crdb_internal_mvcc_timestamp::STRING::DECIMAL <= $4::STRING::DECIMAL",
                &[&low_bucket, &high_bucket, &ckpt, &t],
            )
            .await
            .expect("bucket range scan");
        let row = row.expect("the start-bucket row must be found in the D window");
        let row_version = row
            .get::<_, String>(1)
            .parse::<ReplicationTs>()
            .expect("log row MVCC");
        assert!(row_version > ckpt_ts);
        observer
            .batch_execute("COMMIT")
            .await
            .expect("commit after-commit AOST");
        break;
    }
    db.drop_db().await;
}

#[tokio::test]
#[ignore = "needs the CockroachDB test cluster"]
async fn fact_cluster_logical_timestamp_inside_an_as_of_system_time_transaction() {
    let db = TestDb::migrated("facts1").await;
    let c = raw(&db.name).await;
    let now = one(&c, "SELECT cluster_logical_timestamp()::STRING").await;
    println!("present: cluster_logical_timestamp() = {now}");
    assert!(now.contains('.') && now.split('.').nth(1).map(str::len) == Some(10));

    // A read-only AOST transaction: cluster_logical_timestamp() is the AOST
    // timestamp, not the present time.
    c.batch_execute("BEGIN READ ONLY AS OF SYSTEM TIME '-3s'")
        .await
        .expect("begin");
    let aost = one(&c, "SELECT cluster_logical_timestamp()::STRING").await;
    let txn_ts = one(
        &c,
        "SELECT (EXTRACT(EPOCH FROM transaction_timestamp()) * 1000000)::INT8::STRING",
    )
    .await;
    c.batch_execute("COMMIT").await.expect("commit");
    println!("inside BEGIN READ ONLY AS OF SYSTEM TIME '-3s': {aost} (txn micros {txn_ts})");
    let now_wall: i128 = now.split('.').next().expect("wall").parse().expect("int");
    let aost_wall: i128 = aost.split('.').next().expect("wall").parse().expect("int");
    let behind = (now_wall - aost_wall) / 1_000_000_000;
    println!("AOST timestamp is {behind}s behind the earlier present read");
    assert!(
        (2..=6).contains(&behind),
        "expected about 3s behind, got {behind}s"
    );

    // An explicit decimal T is accepted by AOST and returned unchanged.
    c.batch_execute("CREATE TABLE t (k INT PRIMARY KEY)")
        .await
        .expect("create");
    c.batch_execute("INSERT INTO t VALUES (1)")
        .await
        .expect("insert");
    tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
    let t = one(&c, "SELECT cluster_logical_timestamp()::STRING").await;
    c.batch_execute("INSERT INTO t VALUES (2)")
        .await
        .expect("insert");
    c.batch_execute(&format!("BEGIN READ ONLY AS OF SYSTEM TIME '{t}'"))
        .await
        .expect("begin");
    let at_t = one(&c, "SELECT cluster_logical_timestamp()::STRING").await;
    let count = one(&c, "SELECT count(*)::STRING FROM t").await;
    c.batch_execute("COMMIT").await.expect("commit");
    println!(
        "explicit T={t}: inside AOST T cluster_logical_timestamp()={at_t}, rows visible={count}"
    );
    assert_eq!(at_t, t, "an explicit decimal T is returned unchanged");
    assert_eq!(count, "1", "the read at T does not see the later insert");
    db.drop_db().await;
}

#[tokio::test]
#[ignore = "needs the CockroachDB test cluster"]
async fn fact_cluster_logical_timestamp_pins_the_commit_timestamp_of_a_write_transaction() {
    let db = TestDb::migrated("facts2").await;
    let c = raw(&db.name).await;
    c.batch_execute("CREATE TABLE w (k INT PRIMARY KEY, ts DECIMAL)")
        .await
        .expect("create");
    // The value read inside the transaction is the commit timestamp: check it
    // against the row's own MVCC timestamp.
    let mut restarts = 0;
    for i in 0..5i64 {
        let ts = loop {
            c.batch_execute("BEGIN").await.expect("begin");
            let ts = one(&c, "SELECT cluster_logical_timestamp()::STRING").await;
            c.execute("INSERT INTO w VALUES ($1, $2::STRING::DECIMAL)", &[&i, &ts])
                .await
                .expect("insert");
            match c.batch_execute("COMMIT").await {
                Ok(()) => break ts,
                Err(e) => {
                    // A pushed transaction restarts rather than committing at a stale value.
                    assert_eq!(e.code().map(|c| c.code()), Some("40001"), "{e}");
                    restarts += 1;
                    let _ = c.batch_execute("ROLLBACK").await;
                }
            }
        };
        let mvcc = one(
            &c,
            &format!("SELECT crdb_internal_mvcc_timestamp::STRING FROM w WHERE k = {i}"),
        )
        .await;
        println!("txn {i}: pinned {ts}, row MVCC commit timestamp {mvcc}");
        assert_eq!(
            ts.parse::<krb5_rs::kdc::replication::ReplicationTs>()
                .unwrap(),
            mvcc.parse::<krb5_rs::kdc::replication::ReplicationTs>()
                .unwrap(),
            "the commit timestamp equals the pinned timestamp"
        );
    }

    println!("restarts needed by the pinned-timestamp transactions: {restarts}");
    // (1) The timestamp cache: a writer that touches a span another
    // transaction has already read commits ABOVE that reader's timestamp, so
    // the reader's view of the span is final once read (§5 step 2).
    let a = raw(&db.name).await;
    let b = raw(&db.name).await;
    a.batch_execute("BEGIN").await.expect("begin");
    let read_ts = one(&a, "SELECT cluster_logical_timestamp()::STRING").await;
    a.query("SELECT * FROM w", &[])
        .await
        .expect("read the span");
    b.batch_execute("INSERT INTO w VALUES (100, 0)")
        .await
        .expect("later writer");
    let writer_ts = one(
        &b,
        "SELECT crdb_internal_mvcc_timestamp::STRING FROM w WHERE k = 100",
    )
    .await;
    a.batch_execute("COMMIT").await.expect("commit reader");
    println!("reader read the span at {read_ts}; a later writer into it committed at {writer_ts}");
    assert!(
        writer_ts
            .parse::<krb5_rs::kdc::replication::ReplicationTs>()
            .unwrap()
            > read_ts
                .parse::<krb5_rs::kdc::replication::ReplicationTs>()
                .unwrap(),
        "a write into a span read at T must commit above T"
    );

    // (2) A writer that pinned its timestamp and is then pushed (a newer
    // committed value on a key it writes) restarts with 40001 instead of
    // committing with the stale value.
    a.batch_execute("BEGIN").await.expect("begin");
    let stale = one(&a, "SELECT cluster_logical_timestamp()::STRING").await;
    b.batch_execute("INSERT INTO w VALUES (102, 0)")
        .await
        .expect("newer value");
    let r = match a
        .execute("UPSERT INTO w VALUES (102, $1::STRING::DECIMAL)", &[&stale])
        .await
    {
        Err(e) => Err(e),
        Ok(_) => a.batch_execute("COMMIT").await,
    };
    println!(
        "pushed writer result: {:?}",
        r.as_ref()
            .map_err(|e| e.code().map(|c| c.code().to_string()))
    );
    let e = r.expect_err("a pushed transaction that pinned its timestamp must not commit");
    assert_eq!(e.code().map(|c| c.code()), Some("40001"));
    let _ = a.batch_execute("ROLLBACK").await;
    db.drop_db().await;
}

#[tokio::test]
#[ignore = "needs the CockroachDB test cluster"]
async fn fact_global_tables_and_cluster_logical_timestamp() {
    use krb5_rs_kdb_cockroach::{CockroachStore, MigrateOptions};

    let db = TestDb::new("facts3").await;
    CockroachStore::migrate(
        db.root(),
        &MigrateOptions {
            create_roles: true,
            multi_region: None,
        },
    )
    .await
    .expect("migrate");
    let c = raw(&db.name).await;
    c.batch_execute(
        "ALTER DATABASE \"x\" SET PRIMARY REGION \"california\""
            .replace('x', &db.name)
            .as_str(),
    )
    .await
    .expect("primary region");
    for r in ["ohio", "washington-dc"] {
        c.batch_execute(&format!(
            "ALTER DATABASE \"{}\" ADD REGION \"{r}\"",
            db.name
        ))
        .await
        .expect("region");
    }
    c.batch_execute("CREATE TABLE g (k INT PRIMARY KEY, ts DECIMAL)")
        .await
        .expect("create");
    c.batch_execute("ALTER TABLE g SET LOCALITY GLOBAL")
        .await
        .expect("global");
    let mut walls = Vec::new();
    for i in 0..4i64 {
        c.batch_execute("BEGIN").await.expect("begin");
        let ts = one(&c, "SELECT cluster_logical_timestamp()::STRING").await;
        c.execute("INSERT INTO g VALUES ($1, $2::STRING::DECIMAL)", &[&i, &ts])
            .await
            .expect("insert");
        let t0 = std::time::Instant::now();
        c.batch_execute("COMMIT").await.expect("commit");
        let waited = t0.elapsed();
        let mvcc = one(
            &c,
            &format!("SELECT crdb_internal_mvcc_timestamp::STRING FROM g WHERE k = {i}"),
        )
        .await;
        println!("GLOBAL txn {i}: pinned {ts}, MVCC {mvcc}, COMMIT took {waited:?}");
        let (p, m) = (
            ts.parse::<krb5_rs::kdc::replication::ReplicationTs>()
                .unwrap(),
            mvcc.parse::<krb5_rs::kdc::replication::ReplicationTs>()
                .unwrap(),
        );
        // A non-blocking transaction commits in the future; record how far.
        walls.push((m.wall_nanos - p.wall_nanos) / 1_000_000);
        assert!(
            m >= p,
            "the row can never commit below the pinned timestamp"
        );
    }
    println!("GLOBAL: row commit timestamp minus pinned timestamp (ms): {walls:?}");
    db.drop_db().await;
}
