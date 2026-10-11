//! Verification of the CockroachDB behaviours docs/architecture/kdb.md §5
//! relies on, against a real cluster (`#[ignore]`d; see tests/crdb/cluster.sh).
//! Run with `-- --ignored --nocapture` to see the evidence.

mod common;

use common::*;
use tokio_postgres::{Client, NoTls};

/// A raw session as root (TLS through the crate's own rustls setup is not
/// public, so build one here).
async fn raw(database: &str) -> Client {
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
    let (client, conn) = tokio_postgres::Config::new()
        .host(host())
        .port(port())
        .user("root")
        .dbname(database)
        .ssl_mode(tokio_postgres::config::SslMode::Require)
        .connect(tokio_postgres_rustls::MakeRustlsConnect::new(tls))
        .await
        .expect("connect");
    tokio::spawn(conn);
    let _ = NoTls;
    client
}

async fn one(c: &Client, sql: &str) -> String {
    c.query_one(sql, &[]).await.expect(sql).get::<_, String>(0)
}

#[tokio::test]
#[ignore = "needs the CockroachDB test cluster"]
async fn fact_cluster_logical_timestamp_inside_an_as_of_system_time_transaction() {
    let db = TestDb::new("facts1").await;
    db.migrate().await;
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
    let db = TestDb::new("facts2").await;
    db.migrate().await;
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
    let db = TestDb::new("facts3").await;
    db.migrate().await;
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
