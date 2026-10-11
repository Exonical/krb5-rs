#![cfg(feature = "cockroach")]
//! `krb5-rs-kdb` against CockroachDB (`db_library = krb5-rs-cockroach`).
//! `#[ignore]`d: start the cluster with `tests/crdb/cluster.sh up` and run
//! `cargo test -p krb5-rs-kdc --features cockroach --test cockroach_cli -- --ignored`
//! with `CRDB_HOST` set to the address that reaches the published ports.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use krb5_rs::kdc::replication::ReplicationTs;
use krb5_rs_kdb_cockroach::{run_sql, CockroachConfig, CockroachStore};

const REALM: &str = "CLI.CRDB";

fn host() -> String {
    std::env::var("CRDB_HOST").unwrap_or_else(|_| "127.0.0.1".into())
}

fn port() -> u16 {
    std::env::var("CRDB_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(26257)
}

fn certs() -> PathBuf {
    std::env::var("CRDB_CERTS")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/crdb/certs")
        })
}

fn slash(p: &Path) -> String {
    p.to_string_lossy().replace('\\', "/")
}

fn crdb_config(user: &str, db: &str) -> CockroachConfig {
    let mut c = CockroachConfig::new(format!(
        "postgresql://{user}@{}:{}/{db}?sslmode=verify-full",
        host(),
        port()
    ));
    let d = certs();
    c.ca = Some(d.join("ca.crt"));
    c.cert = Some(d.join(format!("client.{user}.crt")));
    c.key = Some(d.join(format!("client.{user}.key")));
    c
}

fn write_conf(dir: &Path, name: &str, user: &str, db: &str) -> PathBuf {
    let d = certs();
    let path = dir.join(name);
    std::fs::write(
        &path,
        format!(
            "[realms]\n {REALM} = {{\n  database_module = crdb\n  key_stash_file = {}\n  \
             supported_enctypes = aes256-cts-hmac-sha1-96:normal aes128-cts-hmac-sha1-96:normal\n }}\n\
             [dbmodules]\n crdb = {{\n  db_library = krb5-rs-cockroach\n  \
             cockroach_url = postgresql://{user}@{}:{}/{db}?sslmode=verify-full\n  \
             cockroach_ca = {}\n  cockroach_cert = {}\n  cockroach_key = {}\n }}\n",
            slash(&dir.join("stash")),
            host(),
            port(),
            slash(&d.join("ca.crt")),
            slash(&d.join(format!("client.{user}.crt"))),
            slash(&d.join(format!("client.{user}.key"))),
        ),
    )
    .expect("write kdc.conf");
    path
}

fn kdb(conf: &Path, args: &[&str], stdin: &str) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_krb5-rs-kdb"))
        .args(["--config", &conf.to_string_lossy(), "--realm", REALM])
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn krb5-rs-kdb");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(stdin.as_bytes())
        .expect("stdin");
    child.wait_with_output().expect("wait")
}

fn ok(conf: &Path, args: &[&str], stdin: &str) -> String {
    let out = kdb(conf, args, stdin);
    assert!(
        out.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).to_string()
}

#[tokio::test]
#[ignore = "needs the CockroachDB test cluster"]
async fn kdb_administers_a_cockroachdb_realm_and_reports_replication() {
    let dir = std::env::temp_dir().join(format!("krb5rs_crdb_cli_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("dir");
    let db = format!("krb5cli_{}", std::process::id());
    run_sql(
        &crdb_config("root", "defaultdb"),
        &format!("CREATE DATABASE \"{db}\""),
    )
    .await
    .expect("create database");

    let root = write_conf(&dir, "root.conf", "root", &db);
    let admin = write_conf(&dir, "admin.conf", "kdc_admin", &db);

    // Without migrations the CLI says what to do.
    let out = kdb(
        &admin,
        &["create", "-s"],
        "master-password
",
    );
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("migrate"));

    let out = ok(&root, &["database", "migrate", "--create-roles"], "");
    assert!(out.contains("Schema version 0 -> 1"), "{out}");
    let out = ok(&root, &["database", "migrate", "--create-roles"], "");
    assert!(out.contains("Schema version 1 -> 1"), "{out}");

    // Realm creation, with a stash, then the kadmin commands.
    ok(&admin, &["create", "-s"], "master-password\n");
    assert!(dir.join("stash").exists());
    ok(&admin, &["addprinc", "alice"], "alice-pw\n");
    ok(&admin, &["addprinc", "-randkey", "HTTP/svc.cli.crdb"], "");
    ok(
        &admin,
        &[
            "addpol",
            "-maxfailure",
            "3",
            "-lockoutduration",
            "10m",
            "lock",
        ],
        "",
    );
    ok(
        &admin,
        &["modprinc", "-policy", "lock", "+requires_preauth", "alice"],
        "",
    );
    let got = ok(&admin, &["getprinc", "alice"], "");
    assert!(
        got.contains("Policy: lock") && got.contains("REQUIRES_PRE_AUTH"),
        "{got}"
    );
    assert!(
        ok(&admin, &["getpol", "lock"], "").contains("Maximum password failures before lockout: 3")
    );
    let list = ok(&admin, &["listprincs"], "");
    for p in [
        "K/M@CLI.CRDB",
        "krbtgt/CLI.CRDB@CLI.CRDB",
        "alice@CLI.CRDB",
        "HTTP/svc.cli.crdb@CLI.CRDB",
    ] {
        assert!(list.contains(p), "{p} not in {list}");
    }
    ok(&admin, &["cpw", "-randkey", "alice"], "");
    let keytab = dir.join("svc.keytab");
    ok(
        &admin,
        &[
            "ktadd",
            "-k",
            &keytab.to_string_lossy(),
            "HTTP/svc.cli.crdb",
        ],
        "",
    );
    assert!(keytab.exists());
    ok(&admin, &["delprinc", "alice"], "");
    assert!(!kdb(&admin, &["getprinc", "alice"], "").status.success());

    // A wrong master key is refused when opening the realm.
    let _ = std::fs::remove_file(dir.join("stash"));
    let out = kdb(&admin, &["stash"], "not-the-master\n");
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("master key"));
    ok(&admin, &["stash"], "master-password\n");

    // Replication status, wait-applied and prune.
    ok(&admin, &["replication", "status"], "");
    let replica = CockroachStore::connect(
        crdb_config("kdc_replica", &db),
        krb5_rs::kdc::kdb::master_key_from_password(REALM, "master-password", 18).expect("key"),
        REALM,
    )
    .await
    .expect("replica");
    replica
        .heartbeat("kdc-cli", "ohio", ReplicationTs::new(5_000, 0))
        .await
        .expect("heartbeat");
    let status = ok(&admin, &["replication", "status"], "");
    assert!(
        status.contains("kdc-cli") && status.contains("ohio"),
        "{status}"
    );
    let out = ok(
        &admin,
        &[
            "replication",
            "wait-applied",
            "--since",
            "4000",
            "--timeout",
            "2s",
            "--live-within",
            "2m",
        ],
        "",
    );
    assert!(
        out.contains("1 of 1 live KDCs") && out.contains("0 not seen within 2m ignored"),
        "{out}"
    );
    let late = kdb(
        &admin,
        &[
            "replication",
            "wait-applied",
            "--since",
            "9000",
            "--timeout",
            "1s",
            "--live-within",
            "2m",
        ],
        "",
    );
    assert_eq!(late.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&late.stdout).contains("0 of 1 live KDCs"),
        "{}",
        String::from_utf8_lossy(&late.stdout)
    );
    let out = ok(&admin, &["replication", "prune", "--older-than", "0s"], "");
    assert!(
        out.contains("Pruned") && out.contains("pruned_before"),
        "{out}"
    );

    let _ = run_sql(
        &crdb_config("root", "defaultdb"),
        &format!("DROP DATABASE \"{db}\" CASCADE"),
    )
    .await;
    let _ = std::fs::remove_dir_all(&dir);
}
