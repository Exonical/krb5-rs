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
const GSSCLIENT: &str = env!("CARGO_BIN_EXE_krb5-rs-gss-client");
const GSSSERVER: &str = env!("CARGO_BIN_EXE_krb5-rs-gss-server");
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
        store
            .add_with_password(
                PrincipalName::new_srv_hst("host", &host),
                REALM,
                "hostpw",
                1,
                &[18],
                PrincipalAttributes::empty(),
            )
            .expect("host service");
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
             samplepw\naddent -password -p host/{0}@{REALM} -k 1 -e aes256-cts-hmac-sha1-96\nhostpw\nwkt {}\nquit\n",
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

impl Realm {
    /// Start gss-server and wait for "starting..." on its stderr.
    fn gss_server(&self, port: &str) -> Child {
        let mut child = self
            .cmd(GSSSERVER, &["-export", "-port", port, "host"], "server")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn gss-server");
        let mut line = String::new();
        BufReader::new(child.stderr.as_mut().expect("stderr"))
            .read_line(&mut line)
            .expect("ready line");
        assert_eq!(line.trim_end(), "starting...");
        child
    }

    /// t_gss_sample.py server_client_test: one exchange with gss-client.
    fn gss_client(&self, port: &str, args: &[&str], user: &str) -> std::process::Output {
        let mut a = vec!["-port", port];
        a.extend_from_slice(args);
        a.extend_from_slice(&[&self.host, "host", "testmsg"]);
        self.run(GSSCLIENT, &a, user, None).expect("gss-client")
    }
}

fn gss_ok(out: &std::process::Output) {
    let text = stdout(out);
    assert!(out.status.success(), "gss-client: {text}{}", stderr(out));
    assert!(text.contains("Signature verified."), "{text}");
}

fn stop_gss_server(mut server: Child, messages: usize) {
    let _ = server.kill();
    let out = server.wait_with_output().expect("gss-server");
    let text = stdout(&out);
    assert_eq!(
        text.matches("Received message: \"testmsg\"").count(),
        messages,
        "{text}"
    );
    assert!(
        text.contains(&format!("Accepted connection: \"alice@{REALM}\"")),
        "{text}"
    );
}

const GSS_MECHS: &[&[&str]] = &[&["-krb5"], &["-spnego"], &["-iakerb"], &["-krb5", "-dce"]];

/// t_gss_sample.py tgs_test and ap_test: a cached TGT, then the cached
/// service ticket.
#[test]
fn gss_sample_tgs_and_ap() {
    let realm = Realm::start();
    let port = free_port().to_string();
    let server = realm.gss_server(&port);
    for mech in GSS_MECHS {
        gss_ok(&realm.gss_client(&port, mech, "alice"));
        gss_ok(&realm.gss_client(&port, mech, "alice"));
    }
    stop_gss_server(server, GSS_MECHS.len() * 2);
}

/// t_gss_sample.py pw_test and wrong_pw_test.
#[test]
fn gss_sample_password() {
    let realm = Realm::start();
    let port = free_port().to_string();
    let server = realm.gss_server(&port);
    for mech in GSS_MECHS {
        let mut args = mech.to_vec();
        args.extend_from_slice(&["-user", "alice", "-pass", "alicepw"]);
        gss_ok(&realm.gss_client(&port, &args, "nocache"));
        let mut args = mech.to_vec();
        args.extend_from_slice(&["-user", "alice", "-pass", "wrongpw"]);
        let out = realm.gss_client(&port, &args, "nocache");
        assert!(!out.status.success());
        let op = if mech[0] == "-iakerb" {
            "initializing context"
        } else {
            "acquiring creds"
        };
        assert!(
            stdout(&out).contains(&format!("GSS-API error {op}")),
            "{}",
            stdout(&out)
        );
    }
    let _ = std::fs::remove_file(realm.path("nocache"));
    stop_gss_server(server, GSS_MECHS.len());
}

/// t_gss_sample.py: credentials from the default client keytab.
#[test]
fn gss_sample_client_keytab() {
    let realm = Realm::start();
    let ckt = realm.path("client.keytab");
    let script = format!(
        "addent -password -p alice@{REALM} -k 1 -e aes256-cts-hmac-sha1-96\nalicepw\nwkt {}\nquit\n",
        ckt.display()
    );
    let out = realm
        .run(KTUTIL, &[], "alice", Some(&script))
        .expect("ktutil");
    assert!(out.status.success(), "ktutil: {}", stderr(&out));
    let port = free_port().to_string();
    let server = realm.gss_server(&port);
    for mech in [&["-krb5"][..], &["-spnego"]] {
        let mut a = vec!["-port", &port];
        a.extend_from_slice(mech);
        a.extend_from_slice(&["-user", "alice", &realm.host, "host", "testmsg"]);
        let out = realm
            .cmd(GSSCLIENT, &a, "kt")
            .env("KRB5_CLIENT_KTNAME", format!("FILE:{}", ckt.display()))
            .output()
            .expect("gss-client");
        gss_ok(&out);
        let _ = std::fs::remove_file(realm.path("kt"));
    }
    stop_gss_server(server, 2);
}

/// Message counts, unwrapped and unsigned messages, and an
/// unauthenticated connection.
#[test]
fn gss_sample_message_options() {
    let realm = Realm::start();
    let port = free_port().to_string();
    let mut server = realm.gss_server(&port);
    let out = realm.gss_client(&port, &["-mcount", "3", "-ccount", "2"], "alice");
    gss_ok(&out);
    assert_eq!(stdout(&out).matches("Signature verified.").count(), 6);
    let out = realm.gss_client(&port, &["-nw", "-nm"], "alice");
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(stdout(&out).contains("Response received."));
    let out = realm.gss_client(&port, &["-na"], "alice");
    assert!(out.status.success(), "{}", stderr(&out));
    let _ = server.kill();
    let srv = server.wait_with_output().expect("gss-server");
    let text = stdout(&srv);
    assert_eq!(
        text.matches("Received message: \"testmsg\"").count(),
        8,
        "{text}"
    );
    assert!(
        text.contains("Accepted unauthenticated connection."),
        "{text}"
    );
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
