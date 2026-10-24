//! Runs the built `krb5-rs-kdc` binary against a database created with the
//! library, on ephemeral loopback ports.

use std::io::{BufRead, BufReader};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use krb5_rs::kdc::kdb::admin::{Admin, PrincipalOptions};
use krb5_rs::kdc::kdb::{master_key_from_password, write_stash, FileStore};
use krb5_rs::kdc::{PrincipalStore, RealmConfig};
use krb5_rs::profile::Profile;
use krb5_rs::protocol::{
    AsExchange, AsExchangeConfig, Credential, StepResult, TgsExchange, TgsOptions, TgsStepResult,
};
use krb5_rs::transport::{KdcTransport, TcpTransport, UdpTransport};
use krb5_rs::types::PrincipalName;
use krb5_rs::Krb5Error;

const REALM: &str = "DAEMON.TEST";
const PASSWORD: &str = "alice-password";

fn service() -> PrincipalName {
    PrincipalName::new_srv_hst("HTTP", "server.daemon.test")
}

struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("krb5rs_kdcd_{}_{tag}", std::process::id()));
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
    p.to_string_lossy().replace('\\', "/")
}

/// Create kdc.conf plus a database and stash holding alice, krbtgt and a
/// service, the way `krb5-rs-kdb` would.
fn make_realm(dir: &TempDir) -> PathBuf {
    let conf_path = dir.path("kdc.conf");
    std::fs::write(
        &conf_path,
        format!(
            "[realms]\n {REALM} = {{\n  database_name = {}\n  key_stash_file = {}\n  \
             max_life = 24h\n  max_renewable_life = 7d\n  \
             supported_enctypes = aes256-cts-hmac-sha1-96:normal aes128-cts-hmac-sha1-96:normal\n }}\n\
             [dbmodules]\n {REALM} = {{\n  db_library = krb5-rs-file\n }}\n",
            slash(&dir.path("principal")),
            slash(&dir.path("stash")),
        ),
    )
    .expect("write kdc.conf");
    let kdc_conf = Profile::load(&conf_path).expect("kdc.conf");
    let cfg = RealmConfig::from_profiles(&kdc_conf, None, REALM).expect("realm config");
    let key = master_key_from_password(REALM, "master", cfg.master_key_type).expect("master key");
    let etypes: Vec<i32> = cfg.supported_keysalts.iter().map(|(e, _)| *e).collect();
    let store =
        FileStore::create_with(&cfg.database_name, REALM, &key, &etypes).expect("create database");
    write_stash(&cfg.key_stash_file, REALM, &key).expect("stash");
    let admin = Admin::new(&store, cfg.supported_keysalts.clone());
    let opts = PrincipalOptions::default();
    admin
        .add_principal(
            &PrincipalName::new_principal("alice"),
            REALM,
            Some(PASSWORD),
            &opts,
        )
        .expect("alice");
    admin
        .add_principal(&service(), REALM, None, &opts)
        .expect("service");
    conf_path
}

struct Daemon {
    child: Child,
    lines: Arc<Mutex<Vec<String>>>,
    udp: SocketAddr,
    tcp: SocketAddr,
}

impl Daemon {
    fn start(conf: &Path, extra: &[&str]) -> Daemon {
        let mut child = Command::new(env!("CARGO_BIN_EXE_krb5-rs-kdc"))
            .args([
                "--config",
                &conf.to_string_lossy(),
                "--listen",
                "127.0.0.1:0",
            ])
            .args(extra)
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
        let mut daemon = Daemon {
            child,
            lines,
            udp: "0.0.0.0:0".parse().expect("addr"),
            tcp: "0.0.0.0:0".parse().expect("addr"),
        };
        daemon.udp = daemon.listening("(udp)");
        daemon.tcp = daemon.listening("(tcp)");
        daemon
    }

    fn snapshot(&self) -> Vec<String> {
        self.lines.lock().expect("lock").clone()
    }

    fn listening(&self, suffix: &str) -> SocketAddr {
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            for l in self.snapshot() {
                if let Some(rest) = l.split("listening on ").nth(1) {
                    if let Some(addr) = rest.strip_suffix(suffix) {
                        return addr.trim().parse().expect("listen address");
                    }
                }
            }
            assert!(
                Instant::now() < deadline,
                "daemon did not report listening{suffix}: {:?}",
                self.snapshot()
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    fn wait_for_line(&self, needle: &str) -> String {
        let deadline = Instant::now() + Duration::from_secs(10);
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

    fn wait_for_count(&self, needle: &str, count: usize) {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let found = self
                .snapshot()
                .iter()
                .filter(|line| line.contains(needle))
                .count();
            if found >= count {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "found {found} of {count} lines containing {needle:?}: {:?}",
                self.snapshot()
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

async fn as_exchange<T: KdcTransport>(t: &T) -> Result<Credential, Krb5Error> {
    let config = AsExchangeConfig::new(PrincipalName::new_principal("alice"), REALM);
    let mut exchange = AsExchange::new(config, PASSWORD);
    let mut reply = Vec::new();
    loop {
        match exchange.step(&reply)? {
            StepResult::SendToKdc { data, realm } | StepResult::RetryTcp { data, realm } => {
                reply = t.send_recv(&realm, &data).await?;
            }
            StepResult::Complete => return exchange.credential().cloned(),
        }
    }
}

async fn tgs_exchange<T: KdcTransport>(t: &T, tgt: &Credential) -> Result<Credential, Krb5Error> {
    let mut exchange = TgsExchange::new(tgt.clone(), service(), TgsOptions::default());
    let mut reply = Vec::new();
    loop {
        match exchange.step(&reply)? {
            TgsStepResult::SendToKdc { data, realm } | TgsStepResult::RetryTcp { data, realm } => {
                reply = t.send_recv(&realm, &data).await?;
            }
            TgsStepResult::Complete => return exchange.credential().cloned(),
        }
    }
}

#[tokio::test]
async fn serves_as_and_tgs_over_udp_and_tcp_and_logs_each_request() {
    let dir = TempDir::new("serve");
    let conf = make_realm(&dir);
    let daemon = Daemon::start(&conf, &[]);

    let udp = UdpTransport::new(daemon.udp);
    let tgt = as_exchange(&udp).await.expect("AS over UDP");
    let ticket = tgs_exchange(&udp, &tgt).await.expect("TGS over UDP");
    assert_eq!(ticket.server, service());

    let tcp = TcpTransport::new(daemon.tcp);
    let tgt = as_exchange(&tcp).await.expect("AS over TCP");
    tgs_exchange(&tcp, &tgt).await.expect("TGS over TCP");

    daemon.wait_for_count("AS_REQ", 2);
    daemon.wait_for_count("TGS_REQ", 2);
    let lines = daemon.snapshot();
    let count = |needle: &str| lines.iter().filter(|l| l.contains(needle)).count();
    // Each AS exchange is NEEDED_PREAUTH then ISSUE or just ISSUE; each TGS one ISSUE.
    assert!(count("AS_REQ") >= 2, "{lines:?}");
    assert_eq!(count("TGS_REQ"), 2, "{lines:?}");
    assert!(
        lines.iter().any(|l| l.contains(&format!(
            "ISSUE: alice@{REALM} for krbtgt/{REALM}@{REALM}, etypes {{rep=18 tkt=18}}"
        ))),
        "{lines:?}"
    );
    assert!(
        lines.iter().any(
            |l| l.contains("TGS_REQ (4 etypes {18 17 20 19}) 127.0.0.1:")
                && l.contains(&format!(
                    "ISSUE: alice@{REALM} for HTTP/server.daemon.test@{REALM}"
                ))
        ),
        "{lines:?}"
    );
}

#[tokio::test]
async fn failed_requests_are_logged_with_mits_status() {
    let dir = TempDir::new("fail");
    let conf = make_realm(&dir);
    let daemon = Daemon::start(&conf, &[]);
    let config = AsExchangeConfig::new(PrincipalName::new_principal("nobody"), REALM);
    let mut exchange = AsExchange::new(config, "x");
    let StepResult::SendToKdc { data, realm } = exchange.step(&[]).expect("step") else {
        panic!("expected a request");
    };
    UdpTransport::new(daemon.udp)
        .send_recv(&realm, &data)
        .await
        .expect("reply");
    let line = daemon.wait_for_line("CLIENT_NOT_FOUND");
    assert!(
        line.contains(&format!(
            "nobody@{REALM} for krbtgt/{REALM}@{REALM}, error 6"
        )),
        "{line}"
    );
}

#[test]
fn bad_configuration_exits_non_zero_with_a_message() {
    let dir = TempDir::new("bad");
    let out = Command::new(env!("CARGO_BIN_EXE_krb5-rs-kdc"))
        .args(["--config", &dir.path("missing.conf").to_string_lossy()])
        .output()
        .expect("run");
    assert!(!out.status.success());
    let text =
        String::from_utf8_lossy(&out.stdout).to_string() + &String::from_utf8_lossy(&out.stderr);
    assert!(text.contains("missing.conf"), "{text}");
}

#[cfg(unix)]
fn send_signal(child: &Child, signal: &str) {
    let status = Command::new("kill")
        .arg(format!("-{signal}"))
        .arg(child.id().to_string())
        .status()
        .expect("kill");
    assert!(status.success());
}

#[cfg(unix)]
fn wait_exit(child: &mut Child, limit: Duration) -> std::process::ExitStatus {
    let deadline = Instant::now() + limit;
    loop {
        if let Some(status) = child.try_wait().expect("try_wait") {
            return status;
        }
        assert!(
            Instant::now() < deadline,
            "daemon did not exit in {limit:?}"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[cfg(unix)]
#[test]
fn sigterm_exits_cleanly_after_the_timeout_with_an_idle_tcp_connection() {
    let dir = TempDir::new("term_idle");
    let conf = make_realm(&dir);
    let mut daemon = Daemon::start(&conf, &["--shutdown-timeout", "2"]);
    // A connection that never sends a request.
    let _idle = std::net::TcpStream::connect(daemon.tcp).expect("connect");
    std::thread::sleep(Duration::from_millis(300));

    let started = Instant::now();
    send_signal(&daemon.child, "TERM");
    let status = wait_exit(&mut daemon.child, Duration::from_secs(8));
    assert!(status.success(), "exit status {status:?}");
    assert!(
        started.elapsed() >= Duration::from_secs(2),
        "waited for the idle connection"
    );
    daemon.wait_for_line("shutdown timeout");
}

#[cfg(unix)]
#[test]
fn sigterm_and_sigint_exit_promptly_when_idle() {
    for signal in ["TERM", "INT"] {
        let dir = TempDir::new(&format!("term_{signal}"));
        let conf = make_realm(&dir);
        let mut daemon = Daemon::start(&conf, &[]);
        let started = Instant::now();
        send_signal(&daemon.child, signal);
        let status = wait_exit(&mut daemon.child, Duration::from_secs(5));
        assert!(status.success(), "{signal}: {status:?}");
        assert!(started.elapsed() < Duration::from_secs(3));
        daemon.wait_for_line("shutdown complete");
    }
}

#[tokio::test]
async fn master_password_file_replaces_the_stash() {
    let dir = TempDir::new("mpf");
    let conf = dir.path("kdc.conf");
    std::fs::write(
        &conf,
        format!(
            "[realms]\n {REALM} = {{\n  database_name = {}\n  key_stash_file = {}\n  \
             supported_enctypes = aes256-cts-hmac-sha1-96:normal\n }}\n",
            slash(&dir.path("principal")),
            slash(&dir.path("stash")),
        ),
    )
    .expect("kdc.conf");
    let master = dir.path("master");
    let alice = dir.path("alice-pw");
    std::fs::write(&master, "master-secret\n").expect("master");
    std::fs::write(&alice, PASSWORD).expect("password");
    let out = Command::new(env!("CARGO_BIN_EXE_krb5-rs-kdb"))
        .args([
            "--config",
            &conf.to_string_lossy(),
            "--realm",
            REALM,
            "init",
        ])
        .args(["--master-password-file", &master.to_string_lossy()])
        .args(["--password", &format!("alice={}", alice.display())])
        .output()
        .expect("kdb init");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!dir.path("stash").exists(), "no stash was requested");

    // Without the stash or the flag the daemon cannot start.
    let out = Command::new(env!("CARGO_BIN_EXE_krb5-rs-kdc"))
        .args([
            "--config",
            &conf.to_string_lossy(),
            "--listen",
            "127.0.0.1:0",
        ])
        .output()
        .expect("run");
    assert!(!out.status.success());

    let daemon = Daemon::start(
        &conf,
        &["--master-password-file", &master.to_string_lossy()],
    );
    let tcp = TcpTransport::new(daemon.tcp);
    let cred = as_exchange(&tcp).await.expect("AS exchange");
    assert_eq!(cred.client, PrincipalName::new_principal("alice"));

    // The wrong master password is refused at startup.
    std::fs::write(&master, "wrong\n").expect("master");
    let out = Command::new(env!("CARGO_BIN_EXE_krb5-rs-kdc"))
        .args([
            "--config",
            &conf.to_string_lossy(),
            "--listen",
            "127.0.0.1:0",
        ])
        .args(["--master-password-file", &master.to_string_lossy()])
        .output()
        .expect("run");
    assert!(!out.status.success());
}

fn kdb_run(conf: &Path, args: &[&str], stdin: &str) {
    use std::io::Write;
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
}

/// One AS attempt as `user`; Ok on a ticket, else the KDC error code.
async fn attempt(addr: std::net::SocketAddr, user: &str, password: &str) -> Result<(), i32> {
    let t = TcpTransport::new(addr);
    let config = AsExchangeConfig::new(PrincipalName::new_principal(user), REALM);
    let mut exchange = AsExchange::new(config, password);
    let mut reply = Vec::new();
    loop {
        match exchange.step(&reply) {
            Ok(StepResult::SendToKdc { data, realm })
            | Ok(StepResult::RetryTcp { data, realm }) => {
                reply = t.send_recv(&realm, &data).await.expect("KDC reply");
            }
            Ok(StepResult::Complete) => return Ok(()),
            Err(Krb5Error::KdcError(m)) => return Err(m.error_code),
            Err(e) => panic!("unexpected error {e:?}"),
        }
    }
}

#[tokio::test]
async fn metrics_endpoint_scrapes_low_cardinality_data_without_principal_or_key_material() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let dir = TempDir::new("metrics");
    let conf = make_realm(&dir);
    let daemon = Daemon::start(&conf, &["--metrics-listen", "127.0.0.1:0"]);
    assert_eq!(attempt(daemon.tcp, "alice", PASSWORD).await, Ok(()));
    let address = daemon.listening("(metrics/health)");
    let mut stream = tokio::net::TcpStream::connect(address)
        .await
        .expect("connect metrics");
    stream
        .write_all(b"GET /metrics HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .expect("request");
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.expect("response");
    let response = String::from_utf8(response).expect("utf8");
    assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");
    assert!(response.contains("krb5_requests"), "{response}");
    assert!(
        response.contains("krb5_kdc_store_time_seconds"),
        "{response}"
    );
    assert!(!response.contains("alice"), "principal name leaked");
    assert!(!response.contains(PASSWORD), "password leaked");
    let profile = Profile::load(&conf).expect("profile");
    let cfg = RealmConfig::from_profiles(&profile, None, REALM).expect("realm config");
    let master =
        master_key_from_password(REALM, "master", cfg.master_key_type).expect("master key");
    let store = FileStore::open(&cfg.database_name, &master).expect("store");
    let key = store
        .lookup(&PrincipalName::new_principal("alice"), REALM)
        .await
        .expect("lookup")
        .expect("alice")
        .keys[0]
        .key
        .key_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    assert!(!response.contains(&key), "key material leaked");

    let mut health = tokio::net::TcpStream::connect(address)
        .await
        .expect("health");
    health
        .write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .expect("request");
    let mut response = Vec::new();
    health.read_to_end(&mut response).await.expect("response");
    assert!(response.starts_with(b"HTTP/1.1 200 OK"));

    let mut ready = tokio::net::TcpStream::connect(address)
        .await
        .expect("ready");
    ready
        .write_all(b"GET /readyz HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .expect("request");
    let mut response = Vec::new();
    ready.read_to_end(&mut response).await.expect("response");
    assert!(response.starts_with(b"HTTP/1.1 200 OK"));
}

#[tokio::test]
async fn lockout_policy_from_the_database_applies_in_the_daemon() {
    let dir = TempDir::new("lockout");
    let conf = make_realm(&dir);
    kdb_run(
        &conf,
        &[
            "addpol",
            "-maxfailure",
            "2",
            "-lockoutduration",
            "1h",
            "tight",
        ],
        "",
    );
    kdb_run(
        &conf,
        &["addprinc", "+requires_preauth", "-policy", "tight", "carol"],
        "carol-pw\n",
    );
    let daemon = Daemon::start(&conf, &[]);
    assert_eq!(attempt(daemon.tcp, "carol", "wrong").await, Err(24));
    assert_eq!(attempt(daemon.tcp, "carol", "wrong").await, Err(24));
    // Locked out now, even with the right password.
    assert_eq!(attempt(daemon.tcp, "carol", "carol-pw").await, Err(18));
    daemon.wait_for_line("LOCKED_OUT: carol@");

    // An administrator unlocks; the daemon sees it on its next request.
    kdb_run(&conf, &["modprinc", "-unlock", "carol"], "");
    assert_eq!(attempt(daemon.tcp, "carol", "carol-pw").await, Ok(()));
    // alice (no policy) is unaffected by any of this.
    assert_eq!(attempt(daemon.tcp, "alice", PASSWORD).await, Ok(()));
}

#[cfg(feature = "turso")]
#[tokio::test]
async fn the_daemon_serves_from_a_turso_replica_selected_by_db_library() {
    use krb5_rs::kdc::replication::{
        Change, ChangeBatch, ReplicaSink, ReplicationTs, StoredPrincipal,
    };
    use krb5_rs_kdb_turso::{TursoOptions, TursoReplica};

    let dir = TempDir::new("turso");
    let conf = make_realm(&dir);
    let kdc_conf = Profile::load(&conf).expect("kdc.conf");
    let cfg = RealmConfig::from_profiles(&kdc_conf, None, REALM).expect("realm config");
    let key = master_key_from_password(REALM, "master", cfg.master_key_type).expect("master key");
    let store = FileStore::open(&cfg.database_name, &key).expect("open file store");
    let replica_dir = dir.path("replica");
    {
        let replica = TursoReplica::open(&replica_dir, TursoOptions::default(), key.clone())
            .await
            .expect("open replica");
        let ts = ReplicationTs::new(1_000, 0);
        let changes = store
            .list()
            .expect("list")
            .iter()
            .map(|e| Change::UpsertPrincipal {
                principal: StoredPrincipal::from_entry(e, None, None, &key).expect("stored"),
                version: ts,
            })
            .collect();
        replica
            .apply(ChangeBatch { upto: ts, changes })
            .await
            .expect("apply");
    }
    // Point the realm at the replica and take the file database away.
    let text = std::fs::read_to_string(&conf)
        .expect("read kdc.conf")
        .replace(
            "  db_library = krb5-rs-file\n",
            &format!(
                "  db_library = krb5-rs-turso\n  replica_path = {}\n",
                slash(&replica_dir)
            ),
        );
    std::fs::write(&conf, text).expect("write kdc.conf");
    std::fs::remove_file(&cfg.database_name).expect("remove the file database");

    let daemon = Daemon::start(&conf, &[]);
    assert_eq!(attempt(daemon.tcp, "alice", PASSWORD).await, Ok(()));
    assert_eq!(attempt(daemon.tcp, "nobody", PASSWORD).await, Err(6));
}
