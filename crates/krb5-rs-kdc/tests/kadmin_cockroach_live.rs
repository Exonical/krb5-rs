//! Live interop: MIT 1.22.2 `kadmin` and `kpasswd` against `krb5-rs-kadmind`
//! with `db_library = krb5-rs-cockroach`, and `kinit` against a CockroachDB
//! `krb5-rs-kdc` reading the same realm. kadmind and the KDC run on this
//! host; the MIT client runs in the Compose stack's MIT container
//! (`KPROP_LIVE_CONTAINER`, default `krb5-rs-kdc-1`; `CONTAINER_CLI`, default
//! `podman`) and reaches them at `KDC_LIVE_HOST`. Start the cluster with
//! `tests/crdb/cluster.sh up` (`CRDB_HOST`, `CRDB_PORT`, `CRDB_CERTS` as for
//! `cockroach_cli`).
#![cfg(all(feature = "klmdb", feature = "cockroach"))]

use std::io::Write;
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use krb5_rs_kdb_cockroach::{run_sql, CockroachConfig};

const REALM: &str = "KADM.CRDB";
const KDC_PORT: u16 = 17088;
const KADMIN_PORT: u16 = 17491;
const KPASSWD_PORT: u16 = 17464;

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

fn live_host() -> String {
    std::env::var("KDC_LIVE_HOST").unwrap_or_else(|_| "192.168.127.254".into())
}

fn container_cli() -> String {
    std::env::var("CONTAINER_CLI").unwrap_or_else(|_| "podman".into())
}

fn container() -> String {
    std::env::var("KPROP_LIVE_CONTAINER").unwrap_or_else(|_| "krb5-rs-kdc-1".into())
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

/// A kdc.conf for `user` with extra `[realms]` and `[dbmodules]` relations.
fn write_conf(dir: &Path, name: &str, user: &str, db: &str, realm: &str, module: &str) -> PathBuf {
    let d = certs();
    let path = dir.join(name);
    std::fs::write(
        &path,
        format!(
            "[realms]\n {REALM} = {{\n  database_module = crdb\n  key_stash_file = {}\n  \
             supported_enctypes = aes256-cts-hmac-sha1-96:normal aes128-cts-hmac-sha1-96:normal\n\
             {realm} }}\n\
             [dbmodules]\n crdb = {{\n  db_library = krb5-rs-cockroach\n  \
             cockroach_url = postgresql://{user}@{}:{}/{db}?sslmode=verify-full\n  \
             cockroach_ca = {}\n  cockroach_cert = {}\n  cockroach_key = {}\n{module} }}\n",
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

fn kdb(conf: &Path, args: &[&str], stdin: &str) -> String {
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
    let out = child.wait_with_output().expect("wait");
    assert!(
        out.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

struct Daemons(Vec<Child>);

impl Drop for Daemons {
    fn drop(&mut self) {
        for c in &mut self.0 {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

fn wait_port(port: u16) {
    let deadline = Instant::now() + Duration::from_secs(60);
    while TcpStream::connect(("127.0.0.1", port)).is_err() {
        assert!(Instant::now() < deadline, "port {port} did not open");
        std::thread::sleep(Duration::from_millis(200));
    }
}

#[tokio::test]
#[ignore = "needs the CockroachDB test cluster and the MIT container of the Compose stack"]
async fn mit_kadmin_and_kpasswd_administer_a_cockroachdb_realm() {
    let temp = tempfile::tempdir().expect("temp dir");
    let dir = temp.path();
    let db = format!("krb5t_kadmin_live_{}", std::process::id());
    run_sql(
        &crdb_config("root", "defaultdb"),
        &format!("CREATE DATABASE \"{db}\""),
    )
    .await
    .expect("create database");
    let root = write_conf(dir, "root.conf", "root", &db, "", "");
    let admin = write_conf(dir, "admin.conf", "kdc_admin", &db, "", "");
    kdb(&root, &["database", "migrate", "--create-roles"], "");
    let master = dir.join("master");
    std::fs::write(&master, "master-password\n").expect("master password");
    let master = master.to_string_lossy().into_owned();
    kdb(&admin, &["--master-password-file", &master, "init"], "");
    let stash = slash(&dir.join("stash"));
    kdb(
        &admin,
        &["--master-password-file", &master, "stash", "-f", &stash],
        "",
    );
    for (name, pw) in [("admin/admin", "admin-pw"), ("alice", "alice-pw")] {
        kdb(
            &admin,
            &["--master-password-file", &master, "addprinc", name],
            &format!("{pw}\n{pw}\n"),
        );
    }

    std::fs::write(dir.join("acl"), format!("admin/admin@{REALM} *\n")).expect("acl");
    let kadmind_conf = write_conf(
        dir,
        "kadmind.conf",
        "kdc_admin",
        &db,
        &format!(
            "  acl_file = {}\n  kadmind_listen = 0.0.0.0:{KADMIN_PORT}\n  \
             kpasswd_listen = 0.0.0.0:{KPASSWD_PORT}\n",
            slash(&dir.join("acl"))
        ),
        "",
    );
    let kdc_conf = write_conf(
        dir,
        "kdc.conf",
        "kdc_replica",
        &db,
        "",
        &format!(
            "  replica_path = {}\n  kdc_id = kadmin-live\n",
            slash(&dir.join("replica"))
        ),
    );
    let krb5_conf = dir.join("krb5.conf");
    std::fs::write(
        &krb5_conf,
        format!("[libdefaults]\n default_realm = {REALM}\n"),
    )
    .expect("krb5.conf");
    let kdc_log = std::fs::File::create(dir.join("kdc.log")).expect("kdc log");
    let kadmind_log = std::fs::File::create(dir.join("kadmind.log")).expect("kadmind log");
    let mut daemons = Daemons(Vec::new());
    daemons.0.push(
        Command::new(env!("CARGO_BIN_EXE_krb5-rs-kdc"))
            .args(["--config", &kdc_conf.to_string_lossy()])
            .args(["--krb5-config", &krb5_conf.to_string_lossy()])
            .args(["--realm", REALM, "--master-password-file", &master])
            .args(["--listen", &format!("0.0.0.0:{KDC_PORT}")])
            .stdout(kdc_log.try_clone().expect("log"))
            .stderr(kdc_log)
            .spawn()
            .expect("spawn krb5-rs-kdc"),
    );
    daemons.0.push(
        Command::new(env!("CARGO_BIN_EXE_krb5-rs-kadmind"))
            .args(["-r", REALM, "-nofork"])
            .env("KRB5_KDC_PROFILE", &kadmind_conf)
            .env("KRB5_CONFIG", &krb5_conf)
            .stdout(kadmind_log.try_clone().expect("log"))
            .stderr(kadmind_log)
            .spawn()
            .expect("spawn krb5-rs-kadmind"),
    );
    wait_port(KDC_PORT);
    wait_port(KADMIN_PORT);
    wait_port(KPASSWD_PORT);

    let script = SCRIPT
        .replace("@REALM@", REALM)
        .replace("@HOST@", &live_host())
        .replace("@KDC@", &KDC_PORT.to_string())
        .replace("@KADMIN@", &KADMIN_PORT.to_string())
        .replace("@KPASSWD@", &KPASSWD_PORT.to_string());
    let mut child = Command::new(container_cli())
        .args(["exec", "-i", &container(), "bash", "-s"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("container exec");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(script.as_bytes())
        .expect("script");
    let out = child.wait_with_output().expect("wait");
    let stdout = String::from_utf8_lossy(&out.stdout);
    drop(daemons);
    assert!(
        out.status.success() && stdout.contains("KADMIN_COCKROACH_LIVE_OK"),
        "MIT kadmin script failed\nstdout:\n{stdout}\nstderr:\n{}\nkdc.log:\n{}\nkadmind.log:\n{}",
        String::from_utf8_lossy(&out.stderr),
        std::fs::read_to_string(dir.join("kdc.log")).unwrap_or_default(),
        std::fs::read_to_string(dir.join("kadmind.log")).unwrap_or_default(),
    );
    run_sql(
        &crdb_config("root", "defaultdb"),
        &format!("DROP DATABASE \"{db}\" CASCADE"),
    )
    .await
    .expect("drop database");
}

const SCRIPT: &str = r#"
set -euo pipefail
B=/tmp/kadmin-cockroach-live
R=@REALM@
rm -rf "$B"
mkdir -p "$B"
cat > "$B/krb5.conf" <<EOF
[libdefaults]
 default_realm = $R
 dns_lookup_kdc = false
 rdns = false
 udp_preference_limit = 1
[realms]
 $R = {
  kdc = @HOST@:@KDC@
  admin_server = @HOST@:@KADMIN@
  kpasswd_server = @HOST@:@KPASSWD@
 }
EOF
export KRB5_CONFIG=$B/krb5.conf KRB5CCNAME=$B/cc
fail() { echo "FAIL: $*"; exit 1; }
kadm() { kadmin -p admin/admin -w admin-pw -q "$1" 2>&1; }
# The KDC serves from its replica, which follows CockroachDB.
retry() { for _ in $(seq 1 60); do "$@" >/dev/null 2>&1 && return 0; sleep 1; done; "$@"; }
login() { echo "$2" | kinit -c "$B/cc_${1//\//_}" "$1" >/dev/null; }

retry login alice alice-pw || fail "alice kinit"
retry login admin/admin admin-pw || fail "admin kinit"
out=$(kadm "getprinc krbtgt/$R")
grep -q "Last modified: .* (db_creation@$R)" <<<"$out" || fail "realm principal: $out"
out=$(kadm "getprinc kadmin/admin")
grep -q "Last modified: .* (krb5-rs-kdb@$R)" <<<"$out" || fail "init principal: $out"
out=$(kadm "getprinc alice")
grep -q "Last modified: .* (krb5-rs-kdb@$R)" <<<"$out" || fail "krb5-rs-kdb principal: $out"
out=$(kadm "addprinc -pw carol-pw +requires_preauth carol")
grep -q "Principal \"carol@$R\" created." <<<"$out" || fail "addprinc: $out"
out=$(kadm "getprinc carol")
grep -q "Last modified: .* (admin/admin@$R)" <<<"$out" || fail "modifier: $out"
grep -q "REQUIRES_PRE_AUTH" <<<"$out" || fail "attributes: $out"
out=$(kadm "setstr carol session_enctypes aes256-cts")
out=$(kadm "getstrs carol")
grep -q "session_enctypes: aes256-cts" <<<"$out" || fail "getstrs: $out"
out=$(kadm "addpol -minlength 10 long")
out=$(kadm "modprinc -policy long carol")
out=$(kadm "getprinc carol")
grep -q "Policy: long" <<<"$out" || fail "policy: $out"
out=$(kadm "alias calias@$R carol@$R")
grep -q "Principal \"calias@$R\" aliased to \"carol@$R\"." <<<"$out" || fail "alias: $out"
out=$(kadm "renprinc -force calias dave" || true)
grep -q "rename_principal: Operation unsupported on alias principal name while renaming" <<<"$out" \
  || fail "rename alias: $out"
out=$(kadm "renprinc -force carol dave")
grep -q "Principal \"carol@$R\" renamed to \"dave@$R\"." <<<"$out" || fail "renprinc: $out"
out=$(kadm "getstrs dave")
grep -q "session_enctypes: aes256-cts" <<<"$out" || fail "strings after rename: $out"
out=$(kadm "listprincs")
grep -qx "dave@$R" <<<"$out" || fail "listprincs: $out"
if grep -qx "carol@$R" <<<"$out"; then fail "carol still listed: $out"; fi
out=$(kadm "cpw -pw dave-password-1 dave")
grep -q "Password for \"dave@$R\" changed." <<<"$out" || fail "cpw: $out"

retry login dave dave-password-1 || fail "dave kinit"
if printf 'dave-password-1\nshort\nshort\n' | kpasswd dave > "$B/k1.out" 2>&1; then
  fail "short password accepted"
fi
grep -q "Password change rejected: New password is too short." "$B/k1.out" \
  || fail "policy: $(cat $B/k1.out)"
printf 'dave-password-1\ndave-password-2\ndave-password-2\n' | kpasswd dave > "$B/k2.out" 2>&1 \
  || fail "kpasswd: $(cat $B/k2.out)"
grep -q "Password changed." "$B/k2.out" || fail "kpasswd: $(cat $B/k2.out)"
retry login dave dave-password-2 || fail "new password rejected"
out=$(kadm "delprinc -force dave")
grep -q "Principal \"dave@$R\" deleted." <<<"$out" || fail "delprinc: $out"
echo KADMIN_COCKROACH_LIVE_OK
"#;
