//! `krb5-rs-kprop` pushes a klmdb dump to `krb5-rs-kpropd`, which loads it
//! with `krb5-rs-kdb` (the MIT kprop/kpropd/kdb5_util split), on loopback.

use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant, SystemTime};

use krb5_rs::kdc::kdb::kprop::{local_hostname, HostCanon};
use krb5_rs::profile::Profile;

const LIBDEFAULTS: &str = "[libdefaults]\n dns_canonicalize_hostname = false\n";

const REALM: &str = "KPROP.TEST";
const MASTER: &str = "master-password\n";

struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> TempDir {
        let dir = std::env::temp_dir().join(format!("krb5rs_kprop_{}_{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        TempDir(dir)
    }

    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct Proc(Child);

impl Drop for Proc {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .and_then(|l| l.local_addr())
        .expect("free port")
        .port()
}

fn slash(p: &Path) -> String {
    p.to_string_lossy().replace('\\', "/")
}

/// A klmdb realm under `dir/name`; primary and replica share the stash.
fn write_conf(dir: &TempDir, name: &str) -> PathBuf {
    let db = dir.path(name);
    std::fs::create_dir_all(&db).expect("db dir");
    let conf = dir.path(&format!("{name}.conf"));
    std::fs::write(
        &conf,
        format!(
            "[realms]\n {REALM} = {{\n  database_name = {}\n  key_stash_file = {}\n  \
             supported_enctypes = aes256-cts-hmac-sha1-96:normal\n }}\n",
            slash(&db.join("principal")),
            slash(&dir.path("stash")),
        ),
    )
    .expect("kdc.conf");
    conf
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
        .expect("write stdin");
    child.wait_with_output().expect("wait")
}

fn kdb_ok(conf: &Path, args: &[&str], stdin: &str) -> String {
    let out = kdb(conf, args, stdin);
    assert!(
        out.status.success(),
        "{args:?} failed: {}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).to_string()
}

struct Realm {
    dir: TempDir,
    replica: PathBuf,
    krb5: PathBuf,
    keytab: PathBuf,
    dump: PathBuf,
    host: String,
    _kdc: Proc,
}

fn realm(tag: &str) -> Realm {
    let dir = TempDir::new(tag);
    let canon = HostCanon::from_profile(&Profile::parse(LIBDEFAULTS).expect("profile"));
    let host = canon.candidates(&local_hostname().expect("hostname"))[0].clone();
    let primary = write_conf(&dir, "primary");
    let replica = write_conf(&dir, "replica");
    let keytab = dir.path("krb5.keytab");
    let host_princ = format!("host/{host}");
    kdb_ok(&primary, &["create", "-s"], MASTER);
    kdb_ok(&primary, &["addprinc", "alice"], "alice-password\n");
    kdb_ok(&primary, &["addprinc", "-randkey", &host_princ], "");
    kdb_ok(
        &primary,
        &["ktadd", "-k", &keytab.to_string_lossy(), &host_princ],
        "",
    );
    let dump = dir.path("replica_datatrans");
    kdb_ok(&primary, &["dump", &dump.to_string_lossy()], "");

    let port = free_port();
    let kdc = Proc(
        Command::new(env!("CARGO_BIN_EXE_krb5-rs-kdc"))
            .args(["--config", &primary.to_string_lossy()])
            .args(["--listen", &format!("127.0.0.1:{port}")])
            .env_remove("RUST_LOG")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn krb5-rs-kdc"),
    );
    let deadline = Instant::now() + Duration::from_secs(20);
    while TcpStream::connect(("127.0.0.1", port)).is_err() {
        assert!(Instant::now() < deadline, "krb5-rs-kdc did not start");
        std::thread::sleep(Duration::from_millis(50));
    }
    let krb5 = dir.path("krb5.conf");
    std::fs::write(
        &krb5,
        format!(
            "{LIBDEFAULTS} default_realm = {REALM}\n udp_preference_limit = 1\n\
             [realms]\n {REALM} = {{\n  kdc = 127.0.0.1:{port}\n }}\n"
        ),
    )
    .expect("krb5.conf");
    Realm {
        dir,
        replica,
        krb5,
        keytab,
        dump,
        host,
        _kdc: kdc,
    }
}

/// `krb5-rs-kpropd -D -t` on a fresh port, once it printed `ready`.
fn kpropd(r: &Realm, acl: &str) -> (Proc, u16) {
    let acl_file = r.dir.path("kpropd.acl");
    std::fs::write(&acl_file, acl).expect("acl");
    let port = free_port();
    let mut child = Command::new(env!("CARGO_BIN_EXE_krb5-rs-kpropd"))
        .args(["-D", "-t", "-P", &port.to_string(), "-r", REALM])
        .args(["-s", &r.keytab.to_string_lossy()])
        .args(["-a", &acl_file.to_string_lossy()])
        .args(["-f", &r.dir.path("from_master").to_string_lossy()])
        .args(["-p", env!("CARGO_BIN_EXE_krb5-rs-kdb")])
        .env("KRB5_KDC_PROFILE", &r.replica)
        .env("KRB5_CONFIG", &r.krb5)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn krb5-rs-kpropd");
    let stdout = child.stdout.take().expect("stdout");
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            let _ = tx.send(line);
        }
    });
    let line = rx
        .recv_timeout(Duration::from_secs(20))
        .expect("kpropd ready");
    assert_eq!(line, "ready");
    (Proc(child), port)
}

fn kprop(r: &Realm, port: u16) -> Output {
    Command::new(env!("CARGO_BIN_EXE_krb5-rs-kprop"))
        .args(["-r", REALM, "-P", &port.to_string()])
        .args(["-f", &r.dump.to_string_lossy()])
        .args(["-s", &r.keytab.to_string_lossy()])
        .arg(&r.host)
        .env("KRB5_CONFIG", &r.krb5)
        .output()
        .expect("run krb5-rs-kprop")
}

/// Wait for a `-t` kpropd to exit and return its stderr.
fn finish(mut p: Proc) -> (bool, String) {
    let deadline = Instant::now() + Duration::from_secs(20);
    let status = loop {
        if let Some(s) = p.0.try_wait().expect("try_wait") {
            break s;
        }
        assert!(Instant::now() < deadline, "kpropd did not exit");
        std::thread::sleep(Duration::from_millis(50));
    };
    let mut err = String::new();
    if let Some(mut stderr) = p.0.stderr.take() {
        let _ = std::io::Read::read_to_string(&mut stderr, &mut err);
    }
    (status.success(), err)
}

fn text(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

#[test]
fn kprop_pushes_the_dump_and_kpropd_loads_it() {
    let r = realm("full");
    assert!(
        !kdb(&r.replica, &["getprinc", "alice"], "").status.success(),
        "replica starts empty"
    );
    let (daemon, port) = kpropd(&r, &format!("host/{}@{REALM}\n", r.host));
    let out = kprop(&r, port);
    assert!(out.status.success(), "{}", text(&out));
    assert!(
        text(&out).contains(&format!("Database propagation to {}: SUCCEEDED", r.host)),
        "{}",
        text(&out)
    );
    let (ok, err) = finish(daemon);
    assert!(ok, "kpropd: {err}");
    assert_eq!(
        std::fs::read(r.dir.path("from_master")).expect("from_master"),
        std::fs::read(&r.dump).expect("dump"),
    );
    assert!(!r.dir.path("from_master.temp").exists());
    let last_prop = r
        .dir
        .path(&format!("replica_datatrans.{}.last_prop", r.host));
    assert_eq!(std::fs::read(last_prop).expect("last_prop"), b"\0");
    let princ = kdb_ok(&r.replica, &["getprinc", "alice"], "");
    assert!(princ.contains(&format!("alice@{REALM}")), "{princ}");
}

#[test]
fn kpropd_rejects_a_principal_missing_from_the_acl() {
    let r = realm("acl");
    let acl = format!(
        "host/{host}@{REALM}x\nhost/{host}@{REALM} des3-cbc-sha1\n",
        host = r.host
    );
    let (daemon, port) = kpropd(&r, &acl);
    let out = kprop(&r, port);
    assert!(!out.status.success(), "{}", text(&out));
    let (_, err) = finish(daemon);
    assert!(
        err.contains(&format!(
            "Rejected connection from unauthorized principal host/{}@{REALM}",
            r.host
        )),
        "{err}"
    );
    assert!(!r.dir.path("from_master").exists());
    assert!(!kdb(&r.replica, &["getprinc", "alice"], "").status.success());
}

#[test]
fn kprop_refuses_a_dump_newer_than_its_dump_ok_stamp() {
    let r = realm("stale");
    let ok = std::fs::File::options()
        .write(true)
        .open(r.dir.path("replica_datatrans.dump_ok"))
        .expect("dump_ok");
    ok.set_modified(SystemTime::UNIX_EPOCH + Duration::from_secs(1))
        .expect("set mtime");
    let out = kprop(&r, free_port());
    assert!(!out.status.success());
    assert!(text(&out).contains("more recent than"), "{}", text(&out));
}
