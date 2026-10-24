//! Integration tests against a real CockroachDB cluster. All are `#[ignore]`d:
//! start the cluster with `tests/crdb/cluster.sh up` and run
//! `cargo test -p krb5-rs-kdb-cockroach --test crdb -- --ignored --test-threads=1`
//! (set `CRDB_HOST` to the address that reaches the published ports).

mod common;

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::*;
use krb5_rs::kdc::kdb::admin::{AdminOps, PolicyChange, PrincipalOptions};
use krb5_rs::kdc::replication::{
    Change, ReplicationSource, ReplicationTs, Snapshot, StoredPrincipal,
};
use krb5_rs::kdc::{
    AdminStore, AuthoritativeState, LockoutReport, LockoutReporter, PrincipalAttributes,
    PrincipalStore, StoreErrorKind,
};
use krb5_rs::types::PrincipalName;
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

async fn assert_principal_mirror(
    authority: &CockroachStore,
    replica: &krb5_rs_kdb_turso::TursoReplica,
) {
    for record in authority.list_principals().await.expect("authority list") {
        let local = replica
            .lookup(&record.entry.name, REALM)
            .await
            .expect("replica lookup")
            .unwrap_or_else(|| panic!("replica is missing {}", record.entry.name));
        let source = record.entry;
        assert_eq!(local.attributes, source.attributes, "{}", source.name);
        assert_eq!(
            local.security_epoch, source.security_epoch,
            "{}",
            source.name
        );
        assert_eq!(local.policy, source.policy, "{}", source.name);
        assert_eq!(local.expiration, source.expiration, "{}", source.name);
        assert_eq!(local.pw_expiration, source.pw_expiration, "{}", source.name);
        assert_eq!(
            local.allowed_to_delegate_to, source.allowed_to_delegate_to,
            "{}",
            source.name
        );
        assert_eq!(
            local.allowed_to_delegate_from, source.allowed_to_delegate_from,
            "{}",
            source.name
        );
        assert_eq!(local.keys.len(), source.keys.len(), "{}", source.name);
        for (local_key, source_key) in local.keys.iter().zip(&source.keys) {
            assert_eq!(local_key.kvno, source_key.kvno, "{}", source.name);
            assert_eq!(
                local_key.key.keytype, source_key.key.keytype,
                "{}",
                source.name
            );
            assert_eq!(
                local_key.key.key_bytes(),
                source_key.key.key_bytes(),
                "{}",
                source.name
            );
            assert_eq!(local_key.salt, source_key.salt, "{}", source.name);
            assert_eq!(local_key.s2kparams, source_key.s2kparams, "{}", source.name);
        }
    }
}

struct Proxy {
    address: std::net::SocketAddr,
    cut: tokio::sync::watch::Sender<bool>,
    delay: tokio::sync::watch::Sender<Duration>,
    stop: tokio::sync::watch::Sender<bool>,
    task: tokio::task::JoinHandle<()>,
}

impl Proxy {
    async fn start(bind_ip: &str, upstream: std::net::SocketAddr) -> Self {
        use tokio::net::TcpListener;

        let listener = TcpListener::bind((bind_ip, 0)).await.expect("proxy bind");
        let address = listener.local_addr().expect("proxy address");
        let (cut, mut cut_rx) = tokio::sync::watch::channel(false);
        let (delay, delay_rx) = tokio::sync::watch::channel(Duration::ZERO);
        let (stop, mut stop_rx) = tokio::sync::watch::channel(false);
        let task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    accepted = listener.accept() => {
                        let Ok((client, _)) = accepted else { continue };
                        if *cut_rx.borrow() || *stop_rx.borrow() {
                            drop(client);
                            continue;
                        }
                        let cut_conn = cut_rx.clone();
                        let delay_conn = delay_rx.clone();
                        let stop_conn = stop_rx.clone();
                        tokio::spawn(async move {
                            if *cut_conn.borrow() || *stop_conn.borrow() {
                                return;
                            }
                            let Ok(server) = tokio::net::TcpStream::connect(upstream).await else {
                                return;
                            };
                            let (client_read, client_write) = client.into_split();
                            let (server_read, server_write) = server.into_split();
                            let to_server = proxy_stream(
                                client_read,
                                server_write,
                                cut_conn.clone(),
                                delay_conn.clone(),
                                stop_conn.clone(),
                            );
                            let to_client = proxy_stream(
                                server_read,
                                client_write,
                                cut_conn,
                                delay_conn,
                                stop_conn,
                            );
                            let _ = tokio::try_join!(to_server, to_client);
                        });
                    }
                    changed = cut_rx.changed() => {
                        if changed.is_err() { break; }
                    }
                    changed = stop_rx.changed() => {
                        if changed.is_err() || *stop_rx.borrow() { break; }
                    }
                }
            }
        });
        Self {
            address,
            cut,
            delay,
            stop,
            task,
        }
    }

    fn set_cut(&self, cut: bool) {
        self.cut.send(cut).expect("proxy cut state");
    }

    fn set_delay(&self, delay: Duration) {
        self.delay.send(delay).expect("proxy delay");
    }

    async fn stop(self) {
        let _ = self.stop.send(true);
        let _ = self.task.await;
    }
}

async fn proxy_stream<R, W>(
    mut read: R,
    mut write: W,
    mut cut: tokio::sync::watch::Receiver<bool>,
    mut delay: tokio::sync::watch::Receiver<Duration>,
    mut stop: tokio::sync::watch::Receiver<bool>,
) -> std::io::Result<()>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut buf = [0; 16 * 1024];
    loop {
        if *cut.borrow() || *stop.borrow() {
            return Ok(());
        }
        let n = tokio::select! {
            result = read.read(&mut buf) => result?,
            changed = cut.changed() => {
                if changed.is_err() || *cut.borrow() { return Ok(()); }
                continue;
            }
            changed = stop.changed() => {
                if changed.is_err() || *stop.borrow() { return Ok(()); }
                continue;
            }
        };
        if n == 0 {
            return Ok(());
        }
        let mut until = tokio::time::Instant::now() + *delay.borrow();
        loop {
            let remaining = until.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                break;
            }
            tokio::select! {
                _ = tokio::time::sleep(remaining) => break,
                changed = delay.changed() => {
                    if changed.is_err() { return Ok(()); }
                    until = tokio::time::Instant::now() + *delay.borrow();
                }
                changed = cut.changed() => {
                    if changed.is_err() || *cut.borrow() { return Ok(()); }
                }
                changed = stop.changed() => {
                    if changed.is_err() || *stop.borrow() { return Ok(()); }
                }
            }
        }
        tokio::select! {
            result = write.write_all(&buf[..n]) => result?,
            changed = cut.changed() => {
                if changed.is_err() || *cut.borrow() { return Ok(()); }
            }
            changed = stop.changed() => {
                if changed.is_err() || *stop.borrow() { return Ok(()); }
            }
        }
    }
}

async fn as_login<S: PrincipalStore>(
    kdc: &krb5_rs::kdc::Kdc<S>,
    principal: &PrincipalName,
    password: &str,
) -> Result<krb5_rs::protocol::Credential, i32> {
    use krb5_rs::protocol::{AsExchange, AsExchangeConfig, StepResult};

    let mut exchange = AsExchange::new(AsExchangeConfig::new(principal.clone(), REALM), password);
    let mut reply = Vec::new();
    loop {
        match exchange.step(&reply) {
            Ok(StepResult::SendToKdc { data, .. }) | Ok(StepResult::RetryTcp { data, .. }) => {
                reply = kdc.handle(&data).await
            }
            Ok(StepResult::Complete) => {
                return Ok(exchange.credential().expect("TGT").clone());
            }
            Err(krb5_rs::Krb5Error::KdcError(error)) => return Err(error.error_code),
            Err(_) => return Err(-1),
        }
    }
}

#[derive(Clone)]
struct CountingSource {
    inner: CockroachStore,
    snapshots: Arc<AtomicUsize>,
}

impl ReplicationSource for CountingSource {
    type Snapshot = <CockroachStore as ReplicationSource>::Snapshot;

    fn snapshot(
        &self,
    ) -> impl std::future::Future<Output = Result<Self::Snapshot, krb5_rs::kdc::StoreError>> + Send
    {
        self.snapshots.fetch_add(1, Ordering::SeqCst);
        self.inner.snapshot()
    }

    fn poll(
        &self,
        since: ReplicationTs,
        limit: usize,
    ) -> impl std::future::Future<
        Output = Result<krb5_rs::kdc::replication::PollResult, krb5_rs::kdc::StoreError>,
    > + Send {
        self.inner.poll(since, limit)
    }

    fn pruned_before(
        &self,
    ) -> impl std::future::Future<Output = Result<Option<ReplicationTs>, krb5_rs::kdc::StoreError>> + Send
    {
        self.inner.pruned_before()
    }
}

#[derive(Clone)]
struct GatedSink {
    inner: krb5_rs_kdb_turso::TursoReplica,
    started: Arc<tokio::sync::Notify>,
    applied: Arc<AtomicUsize>,
    batches: Arc<Mutex<Vec<krb5_rs::kdc::replication::ChangeBatch>>>,
}

impl krb5_rs::kdc::replication::ReplicaSink for GatedSink {
    type Rebuild =
        <krb5_rs_kdb_turso::TursoReplica as krb5_rs::kdc::replication::ReplicaSink>::Rebuild;

    async fn checkpoint(
        &self,
    ) -> Result<Option<krb5_rs::kdc::replication::ReplicaCheckpoint>, krb5_rs::kdc::StoreError>
    {
        self.inner.checkpoint().await
    }

    async fn apply(
        &self,
        batch: krb5_rs::kdc::replication::ChangeBatch,
    ) -> Result<krb5_rs::kdc::replication::ApplyOutcome, krb5_rs::kdc::StoreError> {
        self.started.notify_one();
        tokio::time::sleep(Duration::from_millis(500)).await;
        let result = self.inner.apply(batch.clone()).await?;
        self.batches
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .push(batch);
        self.applied.fetch_add(1, Ordering::SeqCst);
        Ok(result)
    }

    async fn begin_rebuild(
        &self,
        snapshot_ts: ReplicationTs,
    ) -> Result<Self::Rebuild, krb5_rs::kdc::StoreError> {
        self.inner.begin_rebuild(snapshot_ts).await
    }
}

// ------------------------------------------------------------ migrations

#[tokio::test]
#[ignore = "needs the CockroachDB test cluster"]
async fn concurrent_migrations_of_a_fresh_database_all_succeed() {
    // Racing migrations force serialization retries of the schema script; a
    // retry must not re-run DDL that an earlier attempt already committed.
    for _ in 0..3 {
        let db = TestDb::new("migrate_race").await;
        let opts = MigrateOptions {
            create_roles: true,
            multi_region: None,
        };
        let mut runs = tokio::task::JoinSet::new();
        for _ in 0..4 {
            let (config, opts) = (db.root(), opts.clone());
            runs.spawn(async move { CockroachStore::migrate(config, &opts).await });
        }
        while let Some(run) = runs.join_next().await {
            let report = run.expect("migrate task").expect("concurrent migrate");
            assert_eq!(report.to, 1);
        }
        assert_eq!(count(&db, "schema_migrations").await, 1);
        assert_eq!(count(&db, "replication_meta").await, 1);
    }
}

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
        "transaction_markers",
    ] {
        assert!(tables[0].contains(t), "{t} missing from {}", tables[0]);
    }
    let log_columns = db
        .text("SELECT string_agg(column_name, ',' ORDER BY column_name) FROM [SHOW COLUMNS FROM replication_log]")
        .await;
    assert!(
        log_columns[0].contains("bucket")
            && log_columns[0].contains("id")
            && log_columns[0].contains("txn_id")
            && !log_columns[0].contains("commit_ts"),
        "{}",
        log_columns[0]
    );
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
    ] {
        let ddl = db
            .text(&format!(
                "SELECT create_statement FROM [SHOW CREATE TABLE {t}]"
            ))
            .await;
        assert!(ddl[0].contains("LOCALITY GLOBAL"), "{t}: {}", ddl[0]);
    }
    let realms_ddl = db
        .text("SELECT create_statement FROM [SHOW CREATE TABLE realms]")
        .await;
    assert!(
        realms_ddl[0].contains("LOCALITY REGIONAL BY TABLE"),
        "{}",
        realms_ddl[0]
    );
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
    let db = TestDb::migrated("tls").await;
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
             GRANT SELECT ON TABLE schema_migrations, replication_meta TO pwuser;",
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

#[tokio::test]
#[ignore = "needs the CockroachDB test cluster"]
async fn a_simulated_ambiguous_commit_is_resolved_by_its_attempt_marker() {
    let db = TestDb::migrated("ambiguous").await;
    let store = CockroachStore::connect_with(
        db.admin(),
        master(),
        REALM,
        FailPoint::ambiguous_commit_once(),
    )
    .await
    .expect("connect");
    store.create_realm(&[18, 17]).await.expect("realm");

    // Simulation: the database COMMIT succeeds, then the failpoint makes the
    // client treat its response as lost/SQLSTATE 40003. The attempt marker is
    // visible, so the operation returns its saved result without replaying.
    ops(&store)
        .add_principal(&name("once"), REALM, Some("pw"), &plain())
        .await
        .expect("resolve the ambiguous result");
    assert_eq!(
        db.text("SELECT count(*)::STRING FROM principals WHERE name = 'once'")
            .await[0],
        "1"
    );
    assert_eq!(
        db.text("SELECT count(*)::STRING FROM transaction_markers")
            .await[0],
        "2",
        "realm creation and one add, not a duplicate add"
    );
    db.drop_db().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs CockroachDB; creates a real Turso replica and in-process KDC"]
async fn engine_bootstrap_incremental_updates_and_kdc_requests_use_turso() {
    use krb5_rs::kdc::replication::{
        FreshnessGate, RebuildPolicy, ReplicationConfig, ReplicationEngine,
    };
    use krb5_rs::kdc::{AuthStateStore, Kdc, KdcConfig, PolicyStore};
    use krb5_rs::protocol::{
        AsExchange, AsExchangeConfig, Credential, StepResult, TgsExchange, TgsOptions,
        TgsStepResult,
    };
    use krb5_rs_kdb_cockroach::run_sql;
    use krb5_rs_kdb_turso::{TursoOptions, TursoReplica};

    fn http() -> PrincipalName {
        PrincipalName::new_srv_hst("HTTP", "svc.crdb.test")
    }

    let (db, admin_store) = TestDb::with_realm("engine").await;
    let admin = ops(&admin_store);
    admin
        .add_policy(
            PolicyChange {
                pw_max_fail: Some(3),
                pw_lockout_duration: Some(300),
                ..PolicyChange::default()
            }
            .into_policy("lock"),
        )
        .await
        .expect("add policy");
    let mut alice_opts = plain();
    alice_opts.policy = Some(Some("lock".into()));
    admin
        .add_principal(&name("alice"), REALM, Some("alice-pw"), &alice_opts)
        .await
        .expect("alice");
    admin
        .add_principal(&http(), REALM, None, &plain())
        .await
        .expect("service");
    run_sql(
        &db.admin(),
        "INSERT INTO principals \
         (realm, name, name_type, attributes, security_epoch) \
         SELECT 'CRDB.TEST', 'bulk-' || i::STRING, 1, 0, 1 \
         FROM generate_series(0, 1999) AS g(i)",
    )
    .await
    .expect("seed 2,000 snapshot principals");
    assert_eq!(count(&db, "principals").await, 2004);

    let path = std::env::temp_dir().join(format!("krb5rs_crdb_engine_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&path);
    let replica = TursoReplica::open(&path, TursoOptions::default(), master())
        .await
        .expect("open Turso");
    let mut config = db.replica();
    config.replication_read = krb5_rs_kdb_cockroach::ReplicationRead::Present;
    let source = CockroachStore::connect(config, master(), REALM)
        .await
        .expect("replication source");
    let engine = ReplicationEngine::new(
        source.clone(),
        replica.clone(),
        source.clone(),
        ReplicationConfig {
            poll_interval: Duration::from_millis(30),
            heartbeat_interval: Duration::from_millis(30),
            kdc_id: "engine-kdc".into(),
            region: "california".into(),
            rebuild: RebuildPolicy::Auto,
            ..ReplicationConfig::default()
        },
    );
    // A daemon binds its listeners only after bootstrap resolves.
    engine.bootstrap().await.expect("snapshot bootstrap");
    assert!(engine.status().bootstrapped);
    assert!(replica
        .lookup(&name("alice"), REALM)
        .await
        .expect("lookup")
        .is_some());
    assert!(replica
        .lookup(&name("bulk-1999"), REALM)
        .await
        .expect("bulk lookup")
        .is_some());
    let gate = FreshnessGate::new(engine.status_handle(), Duration::from_secs(30));
    let kdc = Kdc::builder(KdcConfig::new(REALM), replica.clone())
        .policies(replica.clone())
        .auth_state(replica.clone())
        .consistency(gate)
        .build();

    async fn as_exchange<S: PrincipalStore>(
        kdc: &Kdc<S>,
        who: &PrincipalName,
        password: &str,
    ) -> Result<Credential, i32> {
        let mut exchange = AsExchange::new(AsExchangeConfig::new(who.clone(), REALM), password);
        let mut reply = Vec::new();
        loop {
            match exchange.step(&reply) {
                Ok(StepResult::SendToKdc { data, .. }) | Ok(StepResult::RetryTcp { data, .. }) => {
                    reply = kdc.handle(&data).await
                }
                Ok(StepResult::Complete) => return Ok(exchange.credential().expect("TGT").clone()),
                Err(krb5_rs::Krb5Error::KdcError(e)) => return Err(e.error_code),
                Err(_) => return Err(-1),
            }
        }
    }

    async fn tgs_exchange<S: PrincipalStore>(
        kdc: &Kdc<S>,
        tgt: Credential,
    ) -> Result<Credential, i32> {
        let mut exchange = TgsExchange::new(tgt, http(), TgsOptions::default());
        let mut reply = Vec::new();
        loop {
            match exchange.step(&reply) {
                Ok(TgsStepResult::SendToKdc { data, .. })
                | Ok(TgsStepResult::RetryTcp { data, .. }) => reply = kdc.handle(&data).await,
                Ok(TgsStepResult::Complete) => {
                    return Ok(exchange.credential().expect("service ticket").clone())
                }
                Err(krb5_rs::Krb5Error::KdcError(e)) => return Err(e.error_code),
                Err(_) => return Err(-1),
            }
        }
    }

    let old_tgt = as_exchange(&kdc, &name("alice"), "alice-pw")
        .await
        .expect("AS from Turso");
    assert!(tgs_exchange(&kdc, old_tgt.clone()).await.is_ok());

    let (shutdown, rx) = tokio::sync::watch::channel(false);
    let task = tokio::spawn(async move { engine.run(rx).await });

    admin
        .modify_policy(
            "lock",
            &PolicyChange {
                pw_max_fail: Some(5),
                ..PolicyChange::default()
            },
        )
        .await
        .expect("modify policy");
    for _ in 0..200 {
        if replica
            .policy("lock")
            .await
            .expect("policy")
            .is_some_and(|p| p.pw_max_fail == 5)
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert_eq!(
        replica
            .policy("lock")
            .await
            .expect("policy")
            .expect("lock")
            .pw_max_fail,
        5
    );

    admin
        .add_principal(&name("bob"), REALM, Some("bob-pw"), &alice_opts)
        .await
        .expect("create");
    for _ in 0..200 {
        if replica
            .lookup(&name("bob"), REALM)
            .await
            .expect("lookup")
            .is_some()
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(replica
        .lookup(&name("bob"), REALM)
        .await
        .expect("lookup")
        .is_some());

    admin
        .change_password(&name("alice"), REALM, Some("alice-new"), true)
        .await
        .expect("cpw -keepold");
    let mut alice = None;
    for _ in 0..200 {
        alice = replica.lookup(&name("alice"), REALM).await.expect("lookup");
        if alice
            .as_ref()
            .is_some_and(|p| p.keys.iter().any(|k| k.kvno == 2))
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(alice
        .as_ref()
        .is_some_and(|p| p.keys.iter().any(|k| k.kvno == 1) && p.keys.iter().any(|k| k.kvno == 2)));
    assert!(
        tgs_exchange(&kdc, old_tgt).await.is_ok(),
        "old TGT remains valid after keepold"
    );
    assert!(as_exchange(&kdc, &name("alice"), "alice-new").await.is_ok());
    admin
        .change_password(&name("alice"), REALM, None, true)
        .await
        .expect("randkey -keepold");
    let mut alice = None;
    for _ in 0..200 {
        alice = replica.lookup(&name("alice"), REALM).await.expect("lookup");
        if alice
            .as_ref()
            .is_some_and(|p| p.keys.iter().any(|k| k.kvno == 3))
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(alice.as_ref().is_some_and(|p| {
        p.keys.iter().any(|k| k.kvno == 1) && p.keys.iter().any(|k| k.kvno == 3)
    }));

    // A lockout written by a KDC using the replica role reaches the AS check
    // through Turso's local auth-state overlay.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs() as i64;
    let replica_writer = CockroachStore::connect(db.replica(), master(), REALM)
        .await
        .expect("replica writer");
    replica_writer
        .report_lockout(&krb5_rs::kdc::replication::LockoutRecord {
            realm: REALM.into(),
            name: name("bob"),
            locked_at: now,
            unlock_at: None,
            source_kdc: "engine-kdc".into(),
        })
        .await
        .expect("report lockout");
    for _ in 0..200 {
        if replica
            .auth_state(&name("bob"), REALM)
            .await
            .expect("replicated auth state")
            .fail_count
            == u32::MAX
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(matches!(
        as_exchange(&kdc, &name("bob"), "bob-pw").await,
        Err(18)
    ));

    admin
        .delete_principal(&http(), REALM)
        .await
        .expect("delete service");
    for _ in 0..200 {
        if replica
            .lookup(&http(), REALM)
            .await
            .expect("lookup")
            .is_none()
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(replica
        .lookup(&http(), REALM)
        .await
        .expect("lookup")
        .is_none());
    admin
        .delete_principal(&name("alice"), REALM)
        .await
        .expect("delete");
    for _ in 0..200 {
        if replica
            .lookup(&name("alice"), REALM)
            .await
            .expect("lookup")
            .is_none()
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(replica
        .lookup(&name("alice"), REALM)
        .await
        .expect("lookup")
        .is_none());

    shutdown.send(true).expect("shutdown");
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .expect("in-flight work drains")
        .expect("engine task");
    drop(kdc);
    drop(replica_writer);
    drop(source);
    drop(replica);
    let _ = std::fs::remove_dir_all(&path);
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
        .text(
            "SELECT crdb_internal_mvcc_timestamp::STRING FROM replication_log \
             WHERE entity = 'principal' AND \"key\" = 'hot' \
             ORDER BY crdb_internal_mvcc_timestamp",
        )
        .await;
    assert_eq!(versions.len(), 81);
    let parsed: Vec<ReplicationTs> = versions.iter().map(|v| v.parse().expect("ts")).collect();
    assert!(
        parsed.windows(2).all(|w| w[0] < w[1]),
        "row MVCC versions strictly increase"
    );
    let current = db
        .text(
            "SELECT crdb_internal_mvcc_timestamp::STRING FROM principals \
              WHERE realm = 'CRDB.TEST' AND name = 'hot'",
        )
        .await;
    assert_eq!(current[0], *versions.last().expect("version history"));
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
        .text(
            "SELECT max(crdb_internal_mvcc_timestamp::STRING::DECIMAL)::STRING \
             FROM replication_log",
        )
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
        .text(
            "SELECT name || ' ' || crdb_internal_mvcc_timestamp::STRING \
              FROM principals WHERE name LIKE 'w%' AND deleted = false",
        )
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
        .text(
            "SELECT count(*)::STRING FROM (SELECT crdb_internal_mvcc_timestamp \
               FROM replication_log GROUP BY crdb_internal_mvcc_timestamp HAVING count(*) = 2)",
        )
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

#[tokio::test]
#[ignore = "needs the CockroachDB test cluster"]
async fn a_truncated_batch_materializes_entities_at_its_checkpoint() {
    use krb5_rs::kdc::replication::ReplicaSink;
    use krb5_rs_kdb_cockroach::ReplicationRead;
    use krb5_rs_kdb_turso::{TursoOptions, TursoReplica};

    let (db, store) = TestDb::with_realm("truncatedmaterialize").await;
    let mut config = db.replica();
    config.replication_read = ReplicationRead::Present;
    let source = CockroachStore::connect(config, master(), REALM)
        .await
        .expect("present-time source");
    let dir = std::env::temp_dir().join(format!("krb5rs_crdb_truncated_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("replica directory");
    let replica = TursoReplica::open(&dir, TursoOptions::default(), master())
        .await
        .expect("open replica");

    let initial = source
        .poll(ReplicationTs::ZERO, 1000)
        .await
        .expect("initial poll");
    assert!(!initial.truncated);
    let s0 = initial.batch.upto;
    ReplicaSink::apply(&replica, initial.batch)
        .await
        .expect("seed replica");

    let admin = ops(&store);
    let a = name("a");
    let b = name("b");
    admin
        .add_principal(
            &a,
            REALM,
            Some("a-password"),
            &PrincipalOptions {
                max_life: Some(Some(Duration::from_secs(3600))),
                ..plain()
            },
        )
        .await
        .expect("add a");
    let after_a = source.poll(s0, 1000).await.expect("poll after a");
    let t1 = after_a
        .batch
        .changes
        .iter()
        .find_map(|change| match change {
            Change::UpsertPrincipal { principal, version } if principal.name == a => {
                assert_eq!(principal.max_life, Some(3600));
                Some(*version)
            }
            _ => None,
        })
        .expect("a at t1");

    admin
        .add_principal(&b, REALM, Some("b-password"), &plain())
        .await
        .expect("add b");
    admin
        .modify_principal(
            &a,
            REALM,
            &PrincipalOptions {
                max_life: Some(Some(Duration::from_secs(7200))),
                ..plain()
            },
        )
        .await
        .expect("modify a");

    let all = source.poll(s0, 1000).await.expect("complete preview");
    let mut t2 = None;
    let mut t3 = None;
    for change in &all.batch.changes {
        match change {
            Change::UpsertPrincipal { principal, version } if principal.name == b => {
                t2 = Some(*version);
            }
            Change::UpsertPrincipal { principal, version } if principal.name == a => {
                assert_eq!(principal.max_life, Some(7200));
                t3 = Some(*version);
            }
            _ => {}
        }
    }
    let t2 = t2.expect("b at t2");
    let t3 = t3.expect("a at t3");
    assert!(t1 < t2 && t2 < t3);

    let first = source.poll(s0, 1).await.expect("truncated poll");
    assert!(first.truncated);
    assert_eq!(first.batch.upto, t1);
    assert!(
        first
            .batch
            .changes
            .iter()
            .all(|change| change.version() <= first.batch.upto),
        "{:?}",
        first.batch
    );
    assert!(matches!(
        first.batch.changes.as_slice(),
        [Change::UpsertPrincipal { principal, version }]
            if principal.name == a
                && *version == t1
                && principal.max_life == Some(3600)
    ));
    ReplicaSink::apply(&replica, first.batch.clone())
        .await
        .expect("apply t1");

    let second = source
        .poll(first.batch.upto, 1)
        .await
        .expect("poll after t1");
    assert!(second.truncated);
    assert_eq!(second.batch.upto, t2);
    assert!(matches!(
        second.batch.changes.as_slice(),
        [Change::UpsertPrincipal { principal, version }]
            if principal.name == b && *version == t2
    ));
    ReplicaSink::apply(&replica, second.batch.clone())
        .await
        .expect("apply t2");

    let third = source
        .poll(second.batch.upto, 1)
        .await
        .expect("poll after t2");
    assert!(!third.truncated);
    assert!(matches!(
        third.batch.changes.as_slice(),
        [Change::UpsertPrincipal { principal, version }]
            if principal.name == a
                && *version == t3
                && principal.max_life == Some(7200)
    ));
    ReplicaSink::apply(&replica, third.batch)
        .await
        .expect("apply t3");
    assert_principal_mirror(&store, &replica).await;

    db.drop_db().await;
    let _ = std::fs::remove_dir_all(dir);
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
        .text(
            "SELECT max(crdb_internal_mvcc_timestamp::STRING::DECIMAL)::STRING \
             FROM replication_log",
        )
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
                "SELECT crdb_internal_mvcc_timestamp::STRING FROM principals \
                 WHERE realm = 'CRDB.TEST' AND name = '{}'",
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
    use krb5_rs_kdb_cockroach::run_sql;

    let db = TestDb::new("prune").await;
    let mut migrator_cfg = db.root();
    migrator_cfg.transaction_timeout = Duration::from_secs(1);
    CockroachStore::migrate(
        migrator_cfg,
        &MigrateOptions {
            create_roles: true,
            multi_region: None,
        },
    )
    .await
    .expect("migrate");
    run_sql(
        &db.root(),
        "UPDATE replication_meta SET bucket_width_seconds = 1 WHERE id = 1",
    )
    .await
    .expect("short test bucket");
    let mut admin_cfg = db.admin();
    admin_cfg.transaction_timeout = Duration::from_secs(1);
    let store = CockroachStore::connect(admin_cfg, master(), REALM)
        .await
        .expect("admin store");
    store.create_realm(&[18, 17]).await.expect("realm");
    let mut replica_cfg = db.replica();
    replica_cfg.transaction_timeout = Duration::from_secs(1);
    let replica = CockroachStore::connect(replica_cfg, master(), REALM)
        .await
        .expect("replica");
    assert_eq!(replica.pruned_before().await.expect("pruned"), None);
    let o = ops(&store);
    for i in 0..3 {
        o.add_principal(&name(&format!("old{i}")), REALM, Some("pw"), &plain())
            .await
            .expect("add");
    }
    tokio::time::sleep(Duration::from_secs(10)).await;
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
        "the realm rows and three old additions are beyond retention, D, and the skew margin"
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
    let lockout = db
        .text("SELECT deleted::STRING FROM lockouts WHERE realm = 'CRDB.TEST' AND name = 'bob'")
        .await;
    assert_eq!(lockout[0], "true", "unlock leaves a replicated tombstone");

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
            .wait_applied(target, Duration::from_millis(300), Duration::from_secs(120),)
            .await
            .expect("wait"),
        krb5_rs_kdb_cockroach::WaitOutcome {
            applied: 0,
            total: 0,
            stale: 0,
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
        .wait_applied(target, Duration::from_millis(500), Duration::from_secs(120))
        .await
        .expect("wait");
    assert_eq!((out.applied, out.total), (1, 2));
    assert_eq!(out.stale, 0);
    assert!(!out.complete());
    let statuses = store.replica_statuses().await.expect("status");
    assert_eq!(statuses.len(), 2);
    assert_eq!(statuses[0].region, "california");
    // The slow KDC catches up while we wait.
    let waiter = {
        let store = store.clone();
        tokio::spawn(async move {
            store
                .wait_applied(target, Duration::from_secs(10), Duration::from_secs(120))
                .await
        })
    };
    tokio::time::sleep(Duration::from_millis(500)).await;
    b.heartbeat("kdc-b", rb, ReplicationTs::new(2_500, 0))
        .await
        .expect("hb");
    let out = waiter.await.expect("task").expect("wait");
    assert!(out.complete(), "{out:?}");
    db.drop_db().await;
}

#[tokio::test]
#[ignore = "needs the CockroachDB test cluster"]
async fn wait_applied_ignores_stale_heartbeat_rows() {
    use krb5_rs_kdb_cockroach::run_sql;

    let (db, store) = TestDb::with_realm("staleheartbeat").await;
    let target = ReplicationTs::new(2_000, 0);
    store
        .heartbeat("kdc-old", "california", ReplicationTs::new(3_000, 0))
        .await
        .expect("old heartbeat");
    run_sql(
        &db.root(),
        "UPDATE replica_status SET seen_at = now() - INTERVAL '10 minutes' \
         WHERE kdc_id = 'kdc-old'",
    )
    .await
    .expect("age heartbeat");

    let out = store
        .wait_applied(target, Duration::ZERO, Duration::from_secs(60))
        .await
        .expect("wait");
    assert_eq!(
        out,
        krb5_rs_kdb_cockroach::WaitOutcome {
            applied: 0,
            total: 0,
            stale: 1,
        }
    );
    assert!(!out.complete());
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
    CockroachStore::migrate(
        regional.root(),
        &MigrateOptions {
            create_roles: true,
            multi_region: None,
        },
    )
    .await
    .expect("regional migration");
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs the CockroachDB and Turso test infrastructure"]
async fn the_engine_bootstraps_turso_then_propagates_admin_changes_to_a_kdc() {
    use krb5_rs::kdc::replication::{
        FreshnessGate, RebuildPolicy, ReplicationConfig, ReplicationEngine,
    };
    use krb5_rs::kdc::{Kdc, KdcConfig, PrincipalStore};
    use krb5_rs::protocol::{
        AsExchange, AsExchangeConfig, Credential, StepResult, TgsExchange, TgsOptions,
        TgsStepResult,
    };
    use krb5_rs_kdb_turso::{TursoOptions, TursoReplica};

    struct Tmp(PathBuf);
    impl Tmp {
        fn new() -> Self {
            let p = std::env::temp_dir().join(format!("krb5rs_crdb_engine_{}", std::process::id()));
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
    fn http() -> PrincipalName {
        PrincipalName::new_srv_hst("HTTP", "svc.crdb.test")
    }
    async fn login<S: PrincipalStore>(
        kdc: &Kdc<S>,
        user: &PrincipalName,
        password: &str,
    ) -> Result<Credential, i32> {
        let mut exchange = AsExchange::new(AsExchangeConfig::new(user.clone(), REALM), password);
        let mut reply = Vec::new();
        loop {
            match exchange.step(&reply) {
                Ok(StepResult::SendToKdc { data, .. }) | Ok(StepResult::RetryTcp { data, .. }) => {
                    reply = kdc.handle(&data).await;
                }
                Ok(StepResult::Complete) => return Ok(exchange.credential().expect("TGT").clone()),
                Err(krb5_rs::Krb5Error::KdcError(err)) => return Err(err.error_code),
                Err(_) => return Err(-1),
            }
        }
    }
    async fn service_ticket<S: PrincipalStore>(
        kdc: &Kdc<S>,
        tgt: Credential,
    ) -> Result<Credential, i32> {
        let mut exchange = TgsExchange::new(tgt, http(), TgsOptions::default());
        let mut reply = Vec::new();
        loop {
            match exchange.step(&reply) {
                Ok(TgsStepResult::SendToKdc { data, .. })
                | Ok(TgsStepResult::RetryTcp { data, .. }) => {
                    reply = kdc.handle(&data).await;
                }
                Ok(TgsStepResult::Complete) => {
                    return Ok(exchange.credential().expect("ST").clone())
                }
                Err(krb5_rs::Krb5Error::KdcError(err)) => return Err(err.error_code),
                Err(_) => return Err(-1),
            }
        }
    }
    let (db, authority) = TestDb::with_realm("engine").await;
    let admin = ops(&authority);
    admin
        .add_principal(&name("alice"), REALM, Some("alice-pw"), &plain())
        .await
        .expect("alice");
    admin
        .add_principal(&http(), REALM, None, &plain())
        .await
        .expect("service");

    let temp = Tmp::new();
    let mut authority_cfg = db.admin();
    authority_cfg.replication_read = krb5_rs_kdb_cockroach::ReplicationRead::Present;
    let source = CockroachStore::connect(authority_cfg, master(), REALM)
        .await
        .expect("source");
    let replica = TursoReplica::open(&temp.0, TursoOptions::default(), master())
        .await
        .expect("Turso replica");
    let engine = ReplicationEngine::new(
        source.clone(),
        replica.clone(),
        source.clone(),
        ReplicationConfig {
            poll_interval: Duration::from_millis(50),
            heartbeat_interval: Duration::from_millis(50),
            kdc_id: "engine-test-kdc".into(),
            region: "california".into(),
            rebuild: RebuildPolicy::Auto,
            ..ReplicationConfig::default()
        },
    );
    // Listener binding in the daemon happens after this returns.
    engine.bootstrap().await.expect("snapshot bootstrap");
    assert!(engine.status().bootstrapped);
    assert!(replica
        .lookup(&name("alice"), REALM)
        .await
        .expect("lookup")
        .is_some());

    let gate = FreshnessGate::new(engine.status_handle(), Duration::from_secs(30));
    let kdc = Kdc::builder(KdcConfig::new(REALM), replica.clone())
        .policies(replica.clone())
        .auth_state(replica.clone())
        .consistency(gate)
        .build();
    let old_tgt = login(&kdc, &name("alice"), "alice-pw")
        .await
        .expect("AS from Turso");
    assert!(
        service_ticket(&kdc, old_tgt.clone()).await.is_ok(),
        "TGS from Turso"
    );

    let (shutdown, rx) = tokio::sync::watch::channel(false);
    let task = tokio::spawn(async move { engine.run(rx).await });
    admin
        .modify_principal(&name("alice"), REALM, &delegate("HTTP/one"))
        .await
        .expect("modprinc");
    let mut updated = None;
    for _ in 0..200 {
        updated = replica.lookup(&name("alice"), REALM).await.expect("lookup");
        if updated.as_ref().is_some_and(|p| {
            p.allowed_to_delegate_to
                .iter()
                .any(|name| name.contains("HTTP/one"))
        }) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(updated.is_some_and(|p| {
        p.allowed_to_delegate_to
            .iter()
            .any(|name| name.contains("HTTP/one"))
    }));

    // cpw retains the old kvno when keepold=true, so a TGT issued just before
    // the password change continues to obtain a service ticket.
    admin
        .change_password(&name("alice"), REALM, Some("alice-new"), true)
        .await
        .expect("cpw -keepold");
    let mut rotated = None;
    for _ in 0..200 {
        rotated = replica.lookup(&name("alice"), REALM).await.expect("lookup");
        if rotated
            .as_ref()
            .is_some_and(|p| p.keys.iter().any(|key| key.kvno == 2))
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    let rotated = rotated.expect("rotated principal");
    assert!(rotated.keys.iter().any(|k| k.kvno == 1));
    assert!(rotated.keys.iter().any(|k| k.kvno == 2));
    assert!(
        service_ticket(&kdc, old_tgt).await.is_ok(),
        "old TGT survives keepold"
    );
    assert!(
        login(&kdc, &name("alice"), "alice-new").await.is_ok(),
        "new key propagated"
    );

    let mut disabled = PrincipalOptions::default();
    disabled
        .attributes
        .add_spec("+disallow_all_tix")
        .expect("attribute");
    admin
        .modify_principal(&name("alice"), REALM, &disabled)
        .await
        .expect("disable");
    let mut local = None;
    for _ in 0..200 {
        local = replica.lookup(&name("alice"), REALM).await.expect("lookup");
        if local
            .as_ref()
            .is_some_and(|p| p.attributes.contains(PrincipalAttributes::DISALLOW_ALL_TIX))
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(local.is_some_and(|p| { p.attributes.contains(PrincipalAttributes::DISALLOW_ALL_TIX) }));
    assert!(matches!(
        login(&kdc, &name("alice"), "alice-new").await,
        Err(18)
    ));

    shutdown.send(true).expect("shutdown");
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .expect("clean shutdown")
        .expect("join");
    db.drop_db().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs a CockroachDB cluster; exercises a cuttable TCP proxy"]
async fn a_partition_stales_one_kdc_while_a_healthy_kdc_serves_and_the_replica_recovers() {
    use krb5_rs::kdc::replication::{
        FreshnessGate, RebuildPolicy, ReplicationConfig, ReplicationEngine,
    };
    use krb5_rs::kdc::{Kdc, KdcConfig};
    use krb5_rs_kdb_turso::{TursoOptions, TursoReplica};

    let (db, admin_store) = TestDb::with_realm("partition").await;
    let admin = ops(&admin_store);
    admin
        .add_principal(&name("hot"), REALM, Some("pw"), &plain())
        .await
        .expect("hot");
    let replica1_dir =
        std::env::temp_dir().join(format!("krb5rs_partition_a_{}", std::process::id()));
    let replica2_dir =
        std::env::temp_dir().join(format!("krb5rs_partition_b_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&replica1_dir);
    let _ = std::fs::remove_dir_all(&replica2_dir);
    let replica1 = TursoReplica::open(&replica1_dir, TursoOptions::default(), master())
        .await
        .expect("replica A");
    let replica2 = TursoReplica::open(&replica2_dir, TursoOptions::default(), master())
        .await
        .expect("replica B");
    let upstream = format!("{}:{}", host(), port())
        .parse()
        .expect("upstream address");
    let proxy_host = "127.0.0.1";
    let proxy = Proxy::start(proxy_host, upstream).await;
    let mut proxied = db.replica();
    proxied.url = format!(
        "postgresql://kdc_replica@{}:{}/{}?sslmode=verify-full",
        proxy_host,
        proxy.address.port(),
        db.name
    );
    let mut direct = db.replica();
    direct.replication_read = krb5_rs_kdb_cockroach::ReplicationRead::Present;
    proxied.replication_read = krb5_rs_kdb_cockroach::ReplicationRead::Present;
    let source_a = CockroachStore::connect(proxied, master(), REALM)
        .await
        .expect("proxied source");
    let source_b = CockroachStore::connect(direct, master(), REALM)
        .await
        .expect("healthy source");
    let cfg = |kdc_id: &str| ReplicationConfig {
        poll_interval: Duration::from_millis(50),
        heartbeat_interval: Duration::from_millis(50),
        kdc_id: kdc_id.into(),
        region: "california".into(),
        rebuild: RebuildPolicy::Auto,
        ..ReplicationConfig::default()
    };
    let engine_a = ReplicationEngine::new(
        source_a.clone(),
        replica1.clone(),
        source_a.clone(),
        cfg("kdc-a"),
    );
    let engine_b = ReplicationEngine::new(
        source_b.clone(),
        replica2.clone(),
        source_b.clone(),
        cfg("kdc-b"),
    );
    engine_a.bootstrap().await.expect("bootstrap A");
    engine_b.bootstrap().await.expect("bootstrap B");
    let kdc_a = Kdc::builder(KdcConfig::new(REALM), replica1.clone())
        .policies(replica1.clone())
        .auth_state(replica1.clone())
        .consistency(FreshnessGate::new(
            engine_a.status_handle(),
            Duration::from_millis(300),
        ))
        .build();
    let kdc_b = Kdc::builder(KdcConfig::new(REALM), replica2.clone())
        .policies(replica2.clone())
        .auth_state(replica2.clone())
        .consistency(FreshnessGate::new(
            engine_b.status_handle(),
            Duration::from_secs(2),
        ))
        .build();
    let (shutdown_a, rx_a) = tokio::sync::watch::channel(false);
    let (shutdown_b, rx_b) = tokio::sync::watch::channel(false);
    let task_a = tokio::spawn(async move { engine_a.run(rx_a).await });
    let task_b = tokio::spawn(async move { engine_b.run(rx_b).await });

    proxy.set_cut(true);
    let mut writers = Vec::new();
    for w in 0..3 {
        let writer_store = admin_store.clone();
        let o = ops(&writer_store);
        writers.push(tokio::spawn(async move {
            let transient = name(&format!("partition-{w}"));
            o.add_principal(&transient, REALM, Some("pw"), &plain())
                .await
                .expect("create during partition");
            for i in 0..8 {
                let _ = o
                    .modify_principal(&name("hot"), REALM, &delegate(&format!("HTTP/{w}-{i}")))
                    .await;
            }
            o.delete_principal(&transient, REALM)
                .await
                .expect("delete during partition");
        }));
    }
    for w in writers {
        w.await.expect("writer");
    }
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert_eq!(
        as_login(&kdc_a, &name("hot"), "pw").await.map(|_| ()),
        Err(29),
        "stale KDC fails closed"
    );
    assert!(
        as_login(&kdc_b, &name("hot"), "pw").await.is_ok(),
        "healthy KDC keeps serving"
    );

    proxy.set_cut(false);
    for _ in 0..400 {
        let source = admin_store
            .get_record(&name("hot"), REALM)
            .await
            .expect("authority")
            .expect("hot");
        let replica = replica1
            .lookup(&name("hot"), REALM)
            .await
            .expect("replica")
            .expect("hot");
        if source.entry.security_epoch == replica.security_epoch
            && source.entry.allowed_to_delegate_to == replica.allowed_to_delegate_to
            && source.entry.keys.len() == replica.keys.len()
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    let source = admin_store.list_principals().await.expect("authority");
    for source in source {
        let replica = replica1
            .lookup(&source.entry.name, REALM)
            .await
            .expect("replica")
            .unwrap_or_else(|| panic!("missing {}", source.entry.name));
        assert_eq!(source.entry.security_epoch, replica.security_epoch);
        assert_eq!(
            source.entry.allowed_to_delegate_to,
            replica.allowed_to_delegate_to
        );
        assert_eq!(
            source.entry.keys.iter().map(|k| k.kvno).collect::<Vec<_>>(),
            replica.keys.iter().map(|k| k.kvno).collect::<Vec<_>>(),
            "key versions for {}",
            source.entry.name
        );
    }
    for w in 0..3 {
        assert!(replica1
            .lookup(&name(&format!("partition-{w}")), REALM)
            .await
            .expect("replica")
            .is_none());
    }
    assert!(
        as_login(&kdc_a, &name("hot"), "pw").await.is_ok(),
        "partitioned KDC recovers"
    );

    shutdown_a.send(true).expect("shutdown A");
    shutdown_b.send(true).expect("shutdown B");
    tokio::time::timeout(Duration::from_secs(5), async {
        task_a.await.expect("engine A");
        task_b.await.expect("engine B");
    })
    .await
    .expect("engines shut down cleanly");
    proxy.stop().await;
    drop((replica1, replica2));
    let _ = std::fs::remove_dir_all(replica1_dir);
    let _ = std::fs::remove_dir_all(replica2_dir);
    db.drop_db().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs the CockroachDB test cluster"]
async fn strict_mode_rejects_authoritative_security_changes_the_replica_has_not_applied() {
    use krb5_rs::kdc::replication::{
        FreshnessGate, RebuildPolicy, ReplicationConfig, ReplicationEngine, StrictGate,
    };
    use krb5_rs::kdc::{ConsistencyGate, GateDecision, GateSubject, Kdc, KdcConfig, PrincipalRole};
    use krb5_rs_kdb_turso::{TursoOptions, TursoReplica};

    let (db, admin_store) = TestDb::with_realm("strict").await;
    let admin = ops(&admin_store);
    admin
        .add_principal(&name("hot"), REALM, Some("pw"), &plain())
        .await
        .expect("hot");

    let path = std::env::temp_dir().join(format!("krb5rs_strict_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&path);
    let replica = TursoReplica::open(&path, TursoOptions::default(), master())
        .await
        .expect("replica");
    let mut source_config = db.replica();
    source_config.replication_read = krb5_rs_kdb_cockroach::ReplicationRead::Present;
    let source = CockroachStore::connect(source_config.clone(), master(), REALM)
        .await
        .expect("authority source");
    let engine = ReplicationEngine::new(
        source.clone(),
        replica.clone(),
        source.clone(),
        ReplicationConfig {
            poll_interval: Duration::from_millis(25),
            kdc_id: "strict-test".into(),
            region: "california".into(),
            rebuild: RebuildPolicy::Auto,
            ..ReplicationConfig::default()
        },
    );
    engine.bootstrap().await.expect("initial bootstrap");
    let status = engine.status_handle();
    let bounded = Kdc::builder(KdcConfig::new(REALM), replica.clone())
        .policies(replica.clone())
        .auth_state(replica.clone())
        .consistency(FreshnessGate::new(
            Arc::clone(&status),
            Duration::from_secs(60),
        ))
        .build();
    let strict = Kdc::builder(KdcConfig::new(REALM), replica.clone())
        .policies(replica.clone())
        .auth_state(replica.clone())
        .consistency(StrictGate::new(
            Arc::clone(&status),
            Duration::from_secs(60),
            Arc::new(source.clone()),
            Duration::from_millis(500),
        ))
        .build();

    assert!(as_login(&bounded, &name("hot"), "pw").await.is_ok());
    assert!(as_login(&strict, &name("hot"), "pw").await.is_ok());

    let mut disabled = plain();
    disabled
        .attributes
        .add_spec("+disallow_all_tix")
        .expect("disable attribute");
    admin
        .modify_principal(&name("hot"), REALM, &disabled)
        .await
        .expect("disable at authority");
    assert!(
        matches!(as_login(&strict, &name("hot"), "pw").await, Err(18)),
        "strict mode returns MIT's client-revoked code for an authoritative disable"
    );
    // Bounded mode keeps serving within the documented replication window.
    assert!(
        as_login(&bounded, &name("hot"), "pw").await.is_ok(),
        "bounded mode may serve before the disable is replicated"
    );

    let mut reenabled = plain();
    reenabled
        .attributes
        .add_spec("-disallow_all_tix")
        .expect("enable attribute");
    admin
        .modify_principal(&name("hot"), REALM, &reenabled)
        .await
        .expect("re-enable at authority");
    admin
        .change_password(&name("hot"), REALM, Some("new-pw"), true)
        .await
        .expect("cpw -keepold");
    assert!(
        matches!(as_login(&strict, &name("hot"), "pw").await, Err(29)),
        "strict mode rejects the greater authoritative security epoch"
    );
    assert!(
        as_login(&bounded, &name("hot"), "pw").await.is_ok(),
        "bounded mode still has the old local key until replication"
    );

    let upstream = format!("{}:{}", host(), port())
        .parse()
        .expect("upstream address");
    let proxy = Proxy::start("127.0.0.1", upstream).await;
    let mut proxied_config = source_config;
    proxied_config.url = format!(
        "postgresql://kdc_replica@127.0.0.1:{}/{}?sslmode=verify-full",
        proxy.address.port(),
        db.name
    );
    let proxied_authority = CockroachStore::connect(proxied_config, master(), REALM)
        .await
        .expect("proxied authority");
    let unavailable_gate = StrictGate::new(
        Arc::clone(&status),
        Duration::from_secs(60),
        Arc::new(proxied_authority.clone()),
        Duration::from_millis(500),
    );
    let local_hot = replica
        .lookup(&name("hot"), REALM)
        .await
        .expect("local lookup")
        .expect("local hot");
    proxy.set_cut(true);
    assert_eq!(
        unavailable_gate
            .check(&[GateSubject {
                entry: &local_hot,
                role: PrincipalRole::Client,
            }])
            .await,
        GateDecision::Reject {
            reason: "AUTHORITY_UNAVAILABLE".into()
        }
    );
    let unavailable_kdc = Kdc::builder(KdcConfig::new(REALM), replica.clone())
        .policies(replica.clone())
        .auth_state(replica.clone())
        .consistency(StrictGate::new(
            Arc::clone(&status),
            Duration::from_secs(60),
            Arc::new(proxied_authority.clone()),
            Duration::from_millis(500),
        ))
        .build();
    let started = tokio::time::Instant::now();
    assert!(matches!(
        tokio::time::timeout(
            Duration::from_secs(1),
            as_login(&unavailable_kdc, &name("hot"), "pw")
        )
        .await
        .expect("authority failure is bounded"),
        Err(29)
    ));
    assert!(started.elapsed() < Duration::from_secs(1));
    proxy.set_cut(false);
    proxy.stop().await;
    drop(proxied_authority);

    engine.bootstrap().await.expect("apply re-enable and cpw");
    assert!(as_login(&strict, &name("hot"), "new-pw").await.is_ok());
    assert!(as_login(&bounded, &name("hot"), "new-pw").await.is_ok());

    admin
        .modify_principal(&name("hot"), REALM, &disabled)
        .await
        .expect("disable again");
    engine.bootstrap().await.expect("apply second disable");
    let local_hot = replica
        .lookup(&name("hot"), REALM)
        .await
        .expect("local lookup")
        .expect("local hot");
    assert!(local_hot
        .attributes
        .contains(PrincipalAttributes::DISALLOW_ALL_TIX));
    assert!(
        matches!(as_login(&bounded, &name("hot"), "new-pw").await, Err(18)),
        "the bounded KDC returns MIT KDC_ERR_CLIENT_REVOKED once the disable is local"
    );
    assert!(
        matches!(as_login(&strict, &name("hot"), "new-pw").await, Err(18)),
        "strict allows the gate and the local MIT check returns client-revoked"
    );

    drop((unavailable_kdc, strict, bounded, engine, replica, source));
    let _ = std::fs::remove_dir_all(&path);
    db.drop_db().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs the CockroachDB test cluster"]
async fn an_engine_restarted_on_existing_turso_state_resumes_without_a_snapshot() {
    use krb5_rs::kdc::replication::{
        RebuildPolicy, ReplicaSink, ReplicationConfig, ReplicationEngine,
    };
    use krb5_rs_kdb_turso::{TursoOptions, TursoReplica};

    let (db, admin_store) = TestDb::with_realm("resume").await;
    let admin = ops(&admin_store);
    for principal in ["base-update", "base-delete", "base-stable"] {
        admin
            .add_principal(&name(principal), REALM, Some("pw"), &plain())
            .await
            .expect("seed principal");
    }
    let path = std::env::temp_dir().join(format!("krb5rs_resume_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&path);
    let replica = TursoReplica::open(&path, TursoOptions::default(), master())
        .await
        .expect("open replica");
    let mut config = db.replica();
    config.replication_read = krb5_rs_kdb_cockroach::ReplicationRead::Present;
    let source = CockroachStore::connect(config, master(), REALM)
        .await
        .expect("source");
    let cfg = ReplicationConfig {
        poll_interval: Duration::from_millis(25),
        heartbeat_interval: Duration::from_millis(50),
        batch_limit: 50,
        kdc_id: "resume-kdc".into(),
        region: "california".into(),
        rebuild: RebuildPolicy::Auto,
        ..ReplicationConfig::default()
    };
    let engine1 =
        ReplicationEngine::new(source.clone(), replica.clone(), source.clone(), cfg.clone());
    engine1.bootstrap().await.expect("initial bootstrap");
    let status1 = engine1.status_handle();
    let (shutdown1, rx1) = tokio::sync::watch::channel(false);
    let task1 = tokio::spawn(async move { engine1.run(rx1).await });

    admin
        .add_principal(&name("during-run"), REALM, Some("pw"), &plain())
        .await
        .expect("add while running");
    for _ in 0..200 {
        if replica
            .lookup(&name("during-run"), REALM)
            .await
            .expect("lookup")
            .is_some()
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(replica
        .lookup(&name("during-run"), REALM)
        .await
        .expect("lookup")
        .is_some());
    shutdown1.send(true).expect("shutdown engine one");
    tokio::time::timeout(Duration::from_secs(5), task1)
        .await
        .expect("engine one drains")
        .expect("engine one joins");
    let checkpoint1 = status1.lock().expect("engine one status").applied_ts;
    drop(replica);

    admin
        .add_principal(&name("while-stopped"), REALM, Some("pw"), &plain())
        .await
        .expect("add while stopped");
    admin
        .modify_principal(&name("base-update"), REALM, &delegate("HTTP/resumed"))
        .await
        .expect("modify while stopped");
    admin
        .delete_principal(&name("base-delete"), REALM)
        .await
        .expect("delete while stopped");

    let reopened = TursoReplica::open(&path, TursoOptions::default(), master())
        .await
        .expect("reopen replica");
    let snapshots = Arc::new(AtomicUsize::new(0));
    let counted_source = CountingSource {
        inner: source.clone(),
        snapshots: Arc::clone(&snapshots),
    };
    let engine2 = ReplicationEngine::new(counted_source, reopened.clone(), source.clone(), cfg);
    engine2.bootstrap().await.expect("resume from checkpoint");
    let status2 = engine2.status_handle();
    let (shutdown2, rx2) = tokio::sync::watch::channel(false);
    let task2 = tokio::spawn(async move { engine2.run(rx2).await });
    tokio::time::sleep(Duration::from_millis(50)).await;
    shutdown2.send(true).expect("shutdown engine two");
    tokio::time::timeout(Duration::from_secs(5), task2)
        .await
        .expect("engine two stops")
        .expect("engine two joins");
    let checkpoint2 = reopened
        .checkpoint()
        .await
        .expect("checkpoint")
        .expect("existing checkpoint");
    let status2 = status2.lock().expect("engine two status").clone();
    assert_eq!(snapshots.load(Ordering::SeqCst), 0);
    assert_eq!(status2.rebuilds, 0);
    assert!(status2.applied_ts >= checkpoint1);
    assert!(checkpoint2.ts >= checkpoint1);
    assert_principal_mirror(&admin_store, &reopened).await;
    assert!(reopened
        .lookup(&name("base-delete"), REALM)
        .await
        .expect("deleted lookup")
        .is_none());

    drop((reopened, source));
    let _ = std::fs::remove_dir_all(&path);
    db.drop_db().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs the CockroachDB test cluster"]
async fn shutdown_during_an_apply_waits_for_it_and_leaves_no_partial_batch() {
    use krb5_rs::kdc::replication::{
        RebuildPolicy, ReplicaSink, ReplicationConfig, ReplicationEngine,
    };
    use krb5_rs_kdb_turso::{TursoOptions, TursoReplica};

    let (db, admin_store) = TestDb::with_realm("shutdownapply").await;
    let admin = ops(&admin_store);
    let path = std::env::temp_dir().join(format!("krb5rs_shutdown_apply_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&path);
    let replica = TursoReplica::open(&path, TursoOptions::default(), master())
        .await
        .expect("open replica");
    let mut source_config = db.replica();
    source_config.replication_read = krb5_rs_kdb_cockroach::ReplicationRead::Present;
    let source = CockroachStore::connect(source_config, master(), REALM)
        .await
        .expect("source");
    let started = Arc::new(tokio::sync::Notify::new());
    let applied = Arc::new(AtomicUsize::new(0));
    let batches = Arc::new(Mutex::new(Vec::new()));
    let sink = GatedSink {
        inner: replica.clone(),
        started: Arc::clone(&started),
        applied: Arc::clone(&applied),
        batches: Arc::clone(&batches),
    };
    let cfg = ReplicationConfig {
        poll_interval: Duration::from_millis(10),
        batch_limit: 50,
        kdc_id: "shutdown-kdc".into(),
        region: "california".into(),
        rebuild: RebuildPolicy::Auto,
        ..ReplicationConfig::default()
    };
    let engine = ReplicationEngine::new(source.clone(), sink.clone(), source.clone(), cfg.clone());
    engine.bootstrap().await.expect("initial snapshot");
    let initial = engine.status().applied_ts;

    for i in 0..200 {
        admin
            .add_principal(&name(&format!("shutdown-{i}")), REALM, Some("pw"), &plain())
            .await
            .expect("seed pending batch");
    }
    let waiting = started.notified();
    let (shutdown, rx) = tokio::sync::watch::channel(false);
    let task = tokio::spawn(async move { engine.run(rx).await });
    tokio::time::timeout(Duration::from_secs(10), waiting)
        .await
        .expect("apply starts");
    let completed_before_shutdown = applied.load(Ordering::SeqCst);
    shutdown.send(true).expect("shutdown");
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        !task.is_finished(),
        "shutdown must not cancel an in-flight apply"
    );
    tokio::time::timeout(Duration::from_secs(10), task)
        .await
        .expect("apply drains")
        .expect("engine task");

    assert_eq!(completed_before_shutdown, 0);
    assert_eq!(applied.load(Ordering::SeqCst), 1);
    let applied_batches = batches.lock().expect("batch log").clone();
    assert_eq!(applied_batches.len(), 1);
    let completed = &applied_batches[0];
    assert!(completed.upto > initial);
    drop((sink, replica));

    let reopened = TursoReplica::open(&path, TursoOptions::default(), master())
        .await
        .expect("reopen");
    let checkpoint = reopened
        .checkpoint()
        .await
        .expect("checkpoint")
        .expect("checkpoint exists");
    assert_eq!(checkpoint.ts, completed.upto);
    for change in &completed.changes {
        if let Change::UpsertPrincipal { principal, .. } = change {
            assert!(reopened
                .lookup(&principal.name, REALM)
                .await
                .expect("replica lookup")
                .is_some());
        }
    }

    let restarted = ReplicationEngine::new(source.clone(), reopened.clone(), source.clone(), cfg);
    restarted
        .bootstrap()
        .await
        .expect("resume from committed batch");
    assert_principal_mirror(&admin_store, &reopened).await;

    drop((restarted, reopened, source));
    let _ = std::fs::remove_dir_all(&path);
    db.drop_db().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs a CockroachDB cluster; simulates regional link lag"]
async fn a_lagging_kdc_fails_closed_while_a_current_kdc_serves_and_heartbeats_show_progress() {
    use krb5_rs::kdc::replication::{
        FreshnessGate, RebuildPolicy, ReplicationConfig, ReplicationEngine,
    };
    use krb5_rs::kdc::{Kdc, KdcConfig};
    use krb5_rs_kdb_turso::{TursoOptions, TursoReplica};

    let db = TestDb::new("regionlag").await;
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
    let admin_store = CockroachStore::connect(db.admin(), master(), REALM)
        .await
        .expect("admin store");
    admin_store.create_realm(&[18, 17]).await.expect("realm");
    let admin = ops(&admin_store);
    admin
        .add_principal(&name("hot"), REALM, Some("pw"), &plain())
        .await
        .expect("hot");

    let replica_a_dir = std::env::temp_dir().join(format!("krb5rs_lag_a_{}", std::process::id()));
    let replica_b_dir = std::env::temp_dir().join(format!("krb5rs_lag_b_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&replica_a_dir);
    let _ = std::fs::remove_dir_all(&replica_b_dir);
    let replica_a = TursoReplica::open(&replica_a_dir, TursoOptions::default(), master())
        .await
        .expect("replica A");
    let replica_b = TursoReplica::open(&replica_b_dir, TursoOptions::default(), master())
        .await
        .expect("replica B");
    let upstream = format!("{}:{}", host(), port())
        .parse()
        .expect("upstream address");
    let proxy = Proxy::start("127.0.0.1", upstream).await;
    let mut direct_config = db.replica();
    direct_config.replication_read = krb5_rs_kdb_cockroach::ReplicationRead::Present;
    let source_a = CockroachStore::connect(direct_config, master(), REALM)
        .await
        .expect("direct source");
    let mut proxied_config = db.replica();
    proxied_config.url = format!(
        "postgresql://kdc_replica@127.0.0.1:{}/{}?sslmode=verify-full",
        proxy.address.port(),
        db.name
    );
    proxied_config.replication_read = krb5_rs_kdb_cockroach::ReplicationRead::Present;
    let source_b = CockroachStore::connect(proxied_config, master(), REALM)
        .await
        .expect("proxied source");
    let config = |kdc_id: &str, region: &str| ReplicationConfig {
        poll_interval: Duration::from_millis(50),
        heartbeat_interval: Duration::from_millis(100),
        batch_limit: 100,
        kdc_id: kdc_id.into(),
        region: region.into(),
        rebuild: RebuildPolicy::Auto,
        ..ReplicationConfig::default()
    };
    let engine_a = ReplicationEngine::new(
        source_a.clone(),
        replica_a.clone(),
        source_a.clone(),
        config("kdc-ca", "california"),
    );
    let engine_b = ReplicationEngine::new(
        source_b.clone(),
        replica_b.clone(),
        source_b.clone(),
        config("kdc-oh", "ohio"),
    );
    engine_a.bootstrap().await.expect("bootstrap A");
    engine_b.bootstrap().await.expect("bootstrap B");
    let status_a = engine_a.status_handle();
    let status_b = engine_b.status_handle();
    let kdc_a = Kdc::builder(KdcConfig::new(REALM), replica_a.clone())
        .policies(replica_a.clone())
        .auth_state(replica_a.clone())
        .consistency(FreshnessGate::new(
            Arc::clone(&status_a),
            Duration::from_secs(2),
        ))
        .build();
    let kdc_b = Kdc::builder(KdcConfig::new(REALM), replica_b.clone())
        .policies(replica_b.clone())
        .auth_state(replica_b.clone())
        .consistency(FreshnessGate::new(
            Arc::clone(&status_b),
            Duration::from_secs(2),
        ))
        .build();
    let (shutdown_a, rx_a) = tokio::sync::watch::channel(false);
    let (shutdown_b, rx_b) = tokio::sync::watch::channel(false);
    let task_a = tokio::spawn(async move { engine_a.run(rx_a).await });
    let task_b = tokio::spawn(async move { engine_b.run(rx_b).await });
    tokio::time::sleep(Duration::from_millis(250)).await;

    // This delay simulates regional lag between nodes on one machine; it is
    // not a real cross-region latency measurement.
    proxy.set_delay(Duration::from_millis(1500));
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let mut writers = Vec::new();
    for writer_id in 0..2 {
        let writer_store = admin_store.clone();
        let stop_at = deadline;
        writers.push(tokio::spawn(async move {
            let writer = ops(&writer_store);
            let mut sequence = 0;
            while tokio::time::Instant::now() < stop_at {
                let principal = name(&format!("lag-{writer_id}-{sequence}"));
                writer
                    .add_principal(&principal, REALM, Some("pw"), &plain())
                    .await
                    .expect("concurrent regional write");
                sequence += 1;
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }));
    }

    let max_staleness = Duration::from_secs(2);
    let stale_deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        let a = status_a.lock().expect("status A").clone();
        let b = status_b.lock().expect("status B").clone();
        if a.freshness()
            .is_some_and(|freshness| freshness <= max_staleness)
            && b.freshness()
                .is_some_and(|freshness| freshness > max_staleness)
            && a.applied_ts > b.applied_ts
        {
            break;
        }
        assert!(
            tokio::time::Instant::now() < stale_deadline,
            "the delayed replica did not fall behind"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let current_login = as_login(&kdc_a, &name("hot"), "pw").await;
    assert!(
        current_login.is_ok(),
        "the current KDC must keep serving; status={:?}",
        status_a.lock().expect("status A").clone()
    );
    assert_eq!(
        as_login(&kdc_b, &name("hot"), "pw").await.map(|_| ()),
        Err(29)
    );
    for writer in writers {
        writer.await.expect("writer task");
    }
    let statuses = source_a.replica_statuses().await.expect("heartbeats");
    let ca = statuses
        .iter()
        .find(|s| s.kdc_id == "kdc-ca")
        .expect("ca heartbeat");
    let oh = statuses
        .iter()
        .find(|s| s.kdc_id == "kdc-oh")
        .expect("oh heartbeat");
    assert_eq!(ca.region, "california");
    assert_eq!(oh.region, "ohio");
    assert!(ca.applied_ts > oh.applied_ts);

    proxy.set_delay(Duration::ZERO);
    let mut converged = false;
    for _ in 0..400 {
        let a = status_a.lock().expect("status A").clone();
        let b = status_b.lock().expect("status B").clone();
        let heartbeats = source_a
            .replica_statuses()
            .await
            .expect("recovered heartbeats");
        let ca = heartbeats
            .iter()
            .find(|status| status.kdc_id == "kdc-ca")
            .expect("ca heartbeat");
        let oh = heartbeats
            .iter()
            .find(|status| status.kdc_id == "kdc-oh")
            .expect("oh heartbeat");
        if b.applied_ts >= a.applied_ts
            && b.freshness()
                .is_some_and(|freshness| freshness <= max_staleness)
            && oh.applied_ts >= ca.applied_ts
        {
            converged = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(converged, "replica and heartbeats did not catch up");
    assert!(as_login(&kdc_b, &name("hot"), "pw").await.is_ok());
    assert_principal_mirror(&admin_store, &replica_a).await;
    assert_principal_mirror(&admin_store, &replica_b).await;

    shutdown_a.send(true).expect("shutdown A");
    shutdown_b.send(true).expect("shutdown B");
    tokio::time::timeout(Duration::from_secs(5), async {
        task_a.await.expect("engine A");
        task_b.await.expect("engine B");
    })
    .await
    .expect("engines stop");
    proxy.stop().await;
    drop((kdc_a, kdc_b, source_a, source_b, replica_a, replica_b));
    let _ = std::fs::remove_dir_all(replica_a_dir);
    let _ = std::fs::remove_dir_all(replica_b_dir);
    db.drop_db().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "flake hunt: loops the GLOBAL-tables modprinc scenario and prints every full error"]
async fn hunt_global_modprinc_errors() {
    let rounds: usize = std::env::var("HUNT_ROUNDS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(50);
    let db = TestDb::new("hunt").await;
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
    let store = CockroachStore::connect(db.admin(), master(), REALM)
        .await
        .expect("connect");
    store.create_realm(&[18]).await.expect("realm");
    let o = ops(&store);
    let who = name("lat");
    o.add_principal(&who, REALM, Some("pw"), &plain())
        .await
        .expect("add");
    let mut errors: Vec<String> = Vec::new();
    let pause = std::env::var("HUNT_PAUSE_MS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(0);
    for round in 0..rounds {
        let start_retries = store.metrics().tx_retries();
        let result = o
            .modify_principal(&who, REALM, &delegate(&format!("HTTP/{round}")))
            .await;
        if let Err(e) = result {
            errors.push(format!(
                "round {round}: {e:?}; retry_count={}",
                store.metrics().tx_retries() - start_retries
            ));
        }
        if pause > 0 {
            tokio::time::sleep(Duration::from_millis(pause)).await;
        }
    }
    println!("hunt: {} errors in {rounds} rounds", errors.len());
    for e in &errors {
        println!("{e}");
    }
    assert!(errors.is_empty(), "GLOBAL modprinc failures: {errors:#?}");
    db.drop_db().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs the CockroachDB test cluster"]
async fn regional_modprinc_hunt_runs_with_a_concurrent_present_time_reader() {
    let rounds: usize = std::env::var("HUNT_ROUNDS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(50);
    let (db, store) = TestDb::with_realm("presentreader").await;
    let o = ops(&store);
    let who = name("lat");
    o.add_principal(&who, REALM, Some("pw"), &plain())
        .await
        .expect("add");

    let mut reader_config = db.admin();
    reader_config.replication_read = krb5_rs_kdb_cockroach::ReplicationRead::Present;
    let reader = CockroachStore::connect(reader_config, master(), REALM)
        .await
        .expect("reader");
    let (stop, mut stop_rx) = tokio::sync::watch::channel(false);
    let reader_task = tokio::spawn(async move {
        let mut since = ReplicationTs::ZERO;
        loop {
            if *stop_rx.borrow() {
                break;
            }
            let result = tokio::select! {
                _ = stop_rx.changed() => break,
                result = reader.poll(since, 32) => result.expect("present poll"),
            };
            since = result.batch.upto;
            if !result.truncated {
                tokio::task::yield_now().await;
            }
        }
    });

    let mut errors = Vec::new();
    for round in 0..rounds {
        let retries = store.metrics().tx_retries();
        if let Err(error) = o
            .modify_principal(&who, REALM, &delegate(&format!("HTTP/{round}")))
            .await
        {
            errors.push(format!(
                "round {round}: {error:?}; retries={}",
                store.metrics().tx_retries() - retries
            ));
        }
    }
    stop.send(true).expect("stop reader");
    reader_task.await.expect("reader task");
    println!(
        "regional present-reader hunt: {} failures in {rounds} operations",
        errors.len()
    );
    for error in &errors {
        println!("{error}");
    }
    assert!(errors.is_empty(), "regional modprinc errors: {errors:#?}");
    db.drop_db().await;
}
