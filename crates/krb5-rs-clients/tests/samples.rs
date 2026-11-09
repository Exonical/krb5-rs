//! MIT's sample-program tests (`appl/sample/t_sample.py`,
//! `appl/user_user/t_user2user.py`) against an in-process KDC.

use std::io::{BufRead, BufReader, Write};
use std::net::{SocketAddr, TcpListener};
use std::os::fd::OwnedFd;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;

use krb5_rs::kdc::{serve_tcp, serve_udp, Kdc, KdcConfig, MemoryStore, PrincipalAttributes};
use krb5_rs::types::PrincipalName;

const REALM: &str = "SAMPLE.REALM";
const KINIT: &str = env!("CARGO_BIN_EXE_krb5-rs-kinit");
const KTUTIL: &str = env!("CARGO_BIN_EXE_krb5-rs-ktutil");
const SCLIENT: &str = env!("CARGO_BIN_EXE_krb5-rs-sclient");
const SSERVER: &str = env!("CARGO_BIN_EXE_krb5-rs-sserver");
const UUCLIENT: &str = env!("CARGO_BIN_EXE_krb5-rs-uu-client");
const UUSERVER: &str = env!("CARGO_BIN_EXE_krb5-rs-uu-server");

struct Realm {
    dir: tempfile::TempDir,
    host: String,
}

/// The local host name, which sserver uses for its own principal.
fn hostname() -> String {
    krb5_rs::kdc::kdb::kprop::local_hostname()
        .expect("hostname")
        .to_ascii_lowercase()
}

impl Realm {
    fn start() -> Self {
        let host = hostname();
        let mut store = MemoryStore::new();
        let tgs = PrincipalName::new_srv_inst("krbtgt", REALM);
        store
            .add_random_key(tgs, REALM, 1, &[18, 17], PrincipalAttributes::empty())
            .expect("krbtgt");
        for (name, pw) in [("alice", "alicepw"), ("bob", "bobpw")] {
            store
                .add_with_password(
                    PrincipalName::new_principal(name),
                    REALM,
                    pw,
                    1,
                    &[18, 17],
                    PrincipalAttributes::REQUIRES_PRE_AUTH,
                )
                .expect("user");
        }
        store
            .add_with_password(
                PrincipalName::new_srv_hst("sample", &host),
                REALM,
                "samplepw",
                1,
                &[18],
                PrincipalAttributes::empty(),
            )
            .expect("sample service");
        let kdc = Arc::new(Kdc::new(KdcConfig::new(REALM), store));
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("runtime");
            rt.block_on(async move {
                let (tcp, udp, addr) = loop {
                    let tcp = tokio::net::TcpListener::bind("127.0.0.1:0")
                        .await
                        .expect("bind tcp");
                    let addr = tcp.local_addr().expect("addr");
                    if let Ok(udp) = tokio::net::UdpSocket::bind(addr).await {
                        break (tcp, udp, addr);
                    }
                };
                tx.send(addr).expect("send addr");
                tokio::spawn(serve_udp(Arc::clone(&kdc), udp));
                serve_tcp(kdc, tcp).await
            })
        });
        let addr: SocketAddr = rx.recv().expect("kdc addr");
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            dir.path().join("krb5.conf"),
            format!(
                "[libdefaults]\n default_realm = {REALM}\n dns_canonicalize_hostname = false\n \
                  rdns = false\n qualify_shortname = \"\"\n dns_lookup_kdc = false\n dns_lookup_realm = false\n\
                 [realms]\n {REALM} = {{\n  kdc = {addr}\n }}\n\
                 [domain_realm]\n {host} = {REALM}\n"
            ),
        )
        .expect("krb5.conf");
        let realm = Realm { dir, host };
        for (name, pw) in [("alice", "alicepw"), ("bob", "bobpw")] {
            let out = realm.run(KINIT, &[name], name, Some(pw)).expect("kinit");
            assert!(out.status.success(), "kinit {name}: {}", stderr(&out));
        }
        let ktutil = format!(
            "addent -password -p sample/{}@{REALM} -k 1 -e aes256-cts-hmac-sha1-96\n\
             samplepw\nwkt {}\nquit\n",
            realm.host,
            realm.keytab().display()
        );
        let out = realm
            .run(KTUTIL, &[], "alice", Some(&ktutil))
            .expect("ktutil");
        assert!(out.status.success(), "ktutil: {}", stderr(&out));
        realm
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    fn keytab(&self) -> PathBuf {
        self.path("sample.keytab")
    }

    fn cmd(&self, bin: &str, args: &[&str], user: &str) -> Command {
        let mut c = Command::new(bin);
        c.args(args)
            .env("KRB5_CONFIG", self.path("krb5.conf"))
            .env("KRB5CCNAME", format!("FILE:{}", self.path(user).display()))
            .env("KRB5RCACHENAME", "none:")
            .env("KRB5_KTNAME", format!("FILE:{}", self.keytab().display()))
            .env_remove("KRB5_TRACE");
        c
    }

    fn run(
        &self,
        bin: &str,
        args: &[&str],
        user: &str,
        input: Option<&str>,
    ) -> std::io::Result<std::process::Output> {
        let mut child = self
            .cmd(bin, args, user)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        if let Some(i) = input {
            child.stdin.take().expect("stdin").write_all(i.as_bytes())?;
        }
        drop(child.stdin.take());
        child.wait_with_output()
    }

    /// Start a listening server and wait for its ready line.
    fn server(&self, bin: &str, args: &[&str], user: &str, ready: &str) -> Child {
        let mut child = self
            .cmd(bin, args, user)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn server");
        let mut line = String::new();
        BufReader::new(child.stdout.as_mut().expect("stdout"))
            .read_line(&mut line)
            .expect("ready line");
        assert_eq!(line.trim_end(), ready);
        child
    }
}

fn stdout(o: &std::process::Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn stderr(o: &std::process::Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .and_then(|l| l.local_addr())
        .expect("free port")
        .port()
}

fn assert_sample_reply(out: &std::process::Output) {
    assert!(
        out.status.success(),
        "sclient: {}{}",
        stdout(out),
        stderr(out)
    );
    let text = stdout(out);
    assert!(text.contains("sendauth succeeded"), "{text}");
    assert!(text.contains(&format!("You are alice@{REALM}")), "{text}");
}

/// t_sample.py: sserver listening on a port.
#[test]
fn sample_standalone() {
    let realm = Realm::start();
    let port = free_port().to_string();
    let kt = format!("FILE:{}", realm.keytab().display());
    let server = realm.server(SSERVER, &["-p", &port, "-S", &kt], "bob", "starting...");
    let out = realm
        .run(SCLIENT, &[&realm.host, &port], "alice", None)
        .expect("sclient");
    let status = server.wait_with_output().expect("sserver");
    assert_sample_reply(&out);
    assert!(status.status.success());
    assert!(stdout(&out).starts_with("connected\n"));
}

/// t_sample.py: sserver started from inetd with the connection on fd 0.
#[test]
fn sample_inetd() {
    let realm = Realm::start();
    let listener = TcpListener::bind("127.0.0.1:0").expect("listen");
    let port = listener.local_addr().expect("addr").port().to_string();
    let accept = std::thread::spawn(move || listener.accept().expect("accept").0);
    let client = realm
        .cmd(SCLIENT, &[&realm.host, &port], "alice")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("sclient");
    let conn = accept.join().expect("accepted");
    let server = realm
        .cmd(SSERVER, &[], "bob")
        .stdin(Stdio::from(OwnedFd::from(conn)))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("sserver");
    let out = client.wait_with_output().expect("sclient");
    let srv = server.wait_with_output().expect("sserver");
    assert!(
        srv.status.success(),
        "sserver {:?}: {}",
        srv.status,
        stderr(&srv)
    );
    assert_sample_reply(&out);
}

/// A server whose keytab doesn't hold the key is refused.
#[test]
fn sample_wrong_key_rejected() {
    let realm = Realm::start();
    let port = free_port().to_string();
    let empty = realm.path("empty.keytab");
    let ktutil = format!(
        "addent -password -p sample/{}@{REALM} -k 1 -e aes256-cts-hmac-sha1-96\n\
         wrongpw\nwkt {}\nquit\n",
        realm.host,
        empty.display()
    );
    let out = realm
        .run(KTUTIL, &[], "alice", Some(&ktutil))
        .expect("ktutil");
    assert!(out.status.success(), "ktutil: {}", stderr(&out));
    let kt = format!("FILE:{}", empty.display());
    let server = realm.server(SSERVER, &["-p", &port, "-S", &kt], "bob", "starting...");
    let out = realm
        .run(SCLIENT, &[&realm.host, &port], "alice", None)
        .expect("sclient");
    let srv = server.wait_with_output().expect("sserver");
    assert_eq!(srv.status.code(), Some(1));
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(
        stdout(&out).contains("sendauth rejected, error reply is:"),
        "{}",
        stdout(&out)
    );
}

/// t_user2user.py.
#[test]
fn user_to_user() {
    let realm = Realm::start();
    let port = free_port().to_string();
    let server = realm.server(UUSERVER, &[&port], "bob", "Server started");
    let out = realm
        .run(UUCLIENT, &[&realm.host, "message", &port], "alice", None)
        .expect("uu-client");
    let srv = server.wait_with_output().expect("uu-server");
    assert!(srv.status.success(), "uu-server: {}", stderr(&srv));
    assert!(out.status.success(), "uu-client: {}", stderr(&out));
    let text = stdout(&out);
    assert!(
        text.contains("uu-client: server says \"Hello, other end of connection.\"."),
        "{text}"
    );
    assert!(
        text.contains(&format!("server is named \"bob@{REALM}\"")),
        "{text}"
    );
    assert!(stdout(&srv).contains(&format!(
        "uu-server: client principal is \"alice@{REALM}\"."
    )));
}
