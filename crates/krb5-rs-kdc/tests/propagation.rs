//! A primary and a replica `krb5-rs-kdc` daemon on loopback: the replica
//! pulls the database, follows primary changes, and is read-only for
//! `krb5-rs-kdb`.

use std::io::{BufRead, BufReader, Write};
use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use krb5_rs::protocol::{AsExchange, AsExchangeConfig, StepResult};
use krb5_rs::transport::{KdcTransport, TcpTransport};
use krb5_rs::types::PrincipalName;

const REALM: &str = "PROP.DAEMON";

struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("krb5rs_prop_d_{}_{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        Self(dir)
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

fn slash(p: &Path) -> String {
    p.to_string_lossy().replace(std::path::MAIN_SEPARATOR, "/")
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("bind")
        .local_addr()
        .expect("addr")
        .port()
}

fn conf(dir: &TempDir, name: &str, extra: &str) -> PathBuf {
    let path = dir.path(&format!("{name}.conf"));
    std::fs::write(
        &path,
        format!(
            "[realms]\n {REALM} = {{\n  database_name = {}\n  key_stash_file = {}\n  \
             supported_enctypes = aes256-cts-hmac-sha1-96:normal\n{extra}\n }}\n",
            slash(&dir.path(&format!("{name}.db"))),
            slash(&dir.path(&format!("{name}.stash"))),
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

fn kdb_ok(conf: &Path, args: &[&str], stdin: &str) {
    let out = kdb(conf, args, stdin);
    assert!(
        out.status.success(),
        "{args:?}: {}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

struct Daemon {
    child: Child,
    lines: Arc<Mutex<Vec<String>>>,
}

impl Daemon {
    fn start(conf: &Path, listen: &str) -> Daemon {
        let mut child = Command::new(env!("CARGO_BIN_EXE_krb5-rs-kdc"))
            .args(["--config", &conf.to_string_lossy(), "--listen", listen])
            .args(["--shutdown-timeout", "2"])
            .env_remove("RUST_LOG")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn krb5-rs-kdc");
        let lines = Arc::new(Mutex::new(Vec::new()));
        for stream in [
            Box::new(child.stdout.take().expect("stdout")) as Box<dyn std::io::Read + Send>,
            Box::new(child.stderr.take().expect("stderr")),
        ] {
            let lines = Arc::clone(&lines);
            std::thread::spawn(move || {
                for line in BufReader::new(stream).lines().map_while(Result::ok) {
                    lines.lock().expect("lock").push(line);
                }
            });
        }
        Daemon { child, lines }
    }

    fn snapshot(&self) -> Vec<String> {
        self.lines.lock().expect("lock").clone()
    }

    fn wait_for(&self, needle: &str) -> String {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if let Some(l) = self.snapshot().into_iter().find(|l| l.contains(needle)) {
                return l;
            }
            assert!(
                Instant::now() < deadline,
                "no log line containing {needle:?}: {:?}",
                self.snapshot()
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    fn listening(&self, suffix: &str) -> SocketAddr {
        let line = self.wait_for(suffix);
        let rest = line.split("listening on ").nth(1).expect("address");
        rest.strip_suffix(suffix)
            .expect("suffix")
            .trim()
            .trim()
            .parse()
            .expect("address")
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

async fn login(addr: SocketAddr, user: &str, password: &str) -> bool {
    let kdc = TcpTransport::new(addr);
    let config = AsExchangeConfig::new(PrincipalName::new_principal(user), REALM);
    let mut exchange = AsExchange::new(config, password);
    let mut reply = Vec::new();
    loop {
        match exchange.step(&reply) {
            Ok(StepResult::SendToKdc { data, realm })
            | Ok(StepResult::RetryTcp { data, realm }) => {
                match kdc.send_recv(&realm, &data).await {
                    Ok(r) => reply = r,
                    Err(_) => return false,
                }
            }
            Ok(StepResult::Complete) => return true,
            Err(_) => return false,
        }
    }
}

#[cfg(unix)]
fn terminate(child: &mut Child) -> std::process::ExitStatus {
    let status = Command::new("kill")
        .arg("-TERM")
        .arg(child.id().to_string())
        .status()
        .expect("kill");
    assert!(status.success());
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(s) = child.try_wait().expect("try_wait") {
            return s;
        }
        assert!(Instant::now() < deadline, "daemon did not exit");
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[tokio::test]
async fn replica_pulls_follows_the_primary_and_is_read_only() {
    let dir = TempDir::new("e2e");
    let (kdc_port, kprop_port) = (free_port(), free_port());
    let primary_conf = conf(
        &dir,
        "primary",
        &format!("  kprop_listen = 127.0.0.1:{kprop_port}"),
    );

    kdb_ok(&primary_conf, &["create", "-s"], "master\n");
    kdb_ok(
        &primary_conf,
        &["addprinc", "-randkey", "kprop/primary"],
        "",
    );
    kdb_ok(
        &primary_conf,
        &["addprinc", "-randkey", "kprop/replica"],
        "",
    );
    kdb_ok(&primary_conf, &["addprinc", "alice"], "alice-pw\n");
    let keytab = dir.path("replica.keytab");
    kdb_ok(
        &primary_conf,
        &[
            "ktadd",
            "-norandkey",
            "-k",
            &keytab.to_string_lossy(),
            "kprop/replica",
        ],
        "",
    );

    let replica_conf = conf(
        &dir,
        "replica",
        &format!(
            "  kprop_primary = 127.0.0.1:{kprop_port}\n  kprop_primary_kdc = 127.0.0.1:{kdc_port}\n  \
             kprop_keytab = {}\n  kprop_poll_interval = 1s",
            slash(&keytab)
        ),
    );
    std::fs::copy(dir.path("primary.stash"), dir.path("replica.stash")).expect("copy stash");

    #[allow(unused_mut)]
    let mut primary = Daemon::start(&primary_conf, &format!("127.0.0.1:{kdc_port}"));
    primary.wait_for("(kprop)");
    #[allow(unused_mut)]
    let mut replica = Daemon::start(&replica_conf, "127.0.0.1:0");
    // The initial pull completes before the KDC binds.
    let listening = replica.wait_for("(tcp)");
    let lines = replica.snapshot();
    let installed = lines
        .iter()
        .position(|l| l.contains("installed database serial"));
    let bound = lines.iter().position(|l| l.contains("listening on"));
    assert!(installed.is_some() && installed < bound, "{lines:?}");
    assert!(listening.contains("listening on"));
    let replica_tcp = replica.listening("(tcp)");

    assert!(login(replica_tcp, "alice", "alice-pw").await);
    assert!(!login(replica_tcp, "bob", "bob-pw").await);

    kdb_ok(&primary_conf, &["addprinc", "bob"], "bob-pw\n");
    let mut seen = false;
    for _ in 0..60 {
        if login(replica_tcp, "bob", "bob-pw").await {
            seen = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    assert!(seen, "replica never saw bob: {:?}", replica.snapshot());
    primary.wait_for("served kprop/replica@PROP.DAEMON");

    // The replica's database is read-only for the admin tool.
    let out = kdb(&replica_conf, &["addprinc", "carol"], "pw\n");
    assert_eq!(out.status.code(), Some(1));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("replica") && err.contains("--force"), "{err}");
    assert!(kdb(&replica_conf, &["getprinc", "bob"], "")
        .status
        .success());

    #[cfg(unix)]
    {
        assert!(terminate(&mut replica.child).success());
        assert!(terminate(&mut primary.child).success());
    }
}

#[tokio::test]
async fn a_replica_with_a_corrupt_database_pulls_and_serves_a_fresh_copy() {
    let dir = TempDir::new("corrupt");
    let (kdc_port, kprop_port) = (free_port(), free_port());
    let primary_conf = conf(
        &dir,
        "primary",
        &format!("  kprop_listen = 127.0.0.1:{kprop_port}"),
    );
    kdb_ok(&primary_conf, &["create", "-s"], "master\n");
    kdb_ok(
        &primary_conf,
        &["addprinc", "-randkey", "kprop/primary"],
        "",
    );
    kdb_ok(
        &primary_conf,
        &["addprinc", "-randkey", "kprop/replica"],
        "",
    );
    kdb_ok(&primary_conf, &["addprinc", "alice"], "alice-pw\n");
    let keytab = dir.path("replica.keytab");
    kdb_ok(
        &primary_conf,
        &[
            "ktadd",
            "-norandkey",
            "-k",
            &keytab.to_string_lossy(),
            "kprop/replica",
        ],
        "",
    );

    let replica_conf = conf(
        &dir,
        "replica",
        &format!(
            "  kprop_primary = 127.0.0.1:{kprop_port}\n  kprop_primary_kdc = 127.0.0.1:{kdc_port}\n  \
             kprop_keytab = {}\n  kprop_poll_interval = 1s",
            slash(&keytab)
        ),
    );
    std::fs::copy(dir.path("primary.stash"), dir.path("replica.stash")).expect("copy stash");
    std::fs::write(dir.path("replica.db"), b"truncated database image").expect("corrupt replica");

    #[allow(unused_mut)]
    let mut primary = Daemon::start(&primary_conf, &format!("127.0.0.1:{kdc_port}"));
    primary.wait_for("(kprop)");
    #[allow(unused_mut)]
    let mut replica = Daemon::start(&replica_conf, "127.0.0.1:0");
    replica.wait_for("(tcp)");
    let lines = replica.snapshot();
    let recovered = lines
        .iter()
        .position(|line| line.contains("installed database serial"));
    let listening = lines.iter().position(|line| line.contains("listening on"));
    assert!(
        lines
            .iter()
            .any(|line| line.contains("local replica database") && line.contains("damaged")),
        "{lines:?}"
    );
    assert!(recovered.is_some() && recovered < listening, "{lines:?}");
    assert!(login(replica.listening("(tcp)"), "alice", "alice-pw").await);

    #[cfg(unix)]
    {
        assert!(terminate(&mut replica.child).success());
        assert!(terminate(&mut primary.child).success());
    }
}

#[test]
fn a_replica_with_no_database_and_no_primary_waits_and_exits_cleanly_on_sigterm() {
    let dir = TempDir::new("wait");
    let conf_path = conf(
        &dir,
        "lonely",
        &format!(
            "  kprop_primary = 127.0.0.1:{}\n  kprop_keytab = {}",
            free_port(),
            slash(&dir.path("none.keytab"))
        ),
    );
    // A stash is required to open (and later verify) the database.
    let seed = conf(&dir, "seed", "");
    kdb_ok(&seed, &["create", "-s"], "master\n");
    std::fs::copy(dir.path("seed.stash"), dir.path("lonely.stash")).expect("stash");
    #[allow(unused_mut)]
    let mut daemon = Daemon::start(&conf_path, "127.0.0.1:0");
    daemon.wait_for("pulling from");
    daemon.wait_for("pull failed");
    assert!(
        !daemon.snapshot().iter().any(|l| l.contains("listening on")),
        "must not serve before it has a database"
    );
    #[cfg(unix)]
    assert!(terminate(&mut daemon.child).success());
    #[cfg(not(unix))]
    drop(daemon);
}
