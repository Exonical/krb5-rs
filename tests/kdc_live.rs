#![cfg(all(feature = "kdc", feature = "tokio"))]
//! Live interop: MIT krb5 client tools (in the `krb5-rs-kdc-1` container)
//! against OUR KDC running in-process on the host.
//!
//! Requires podman + the compose container (`podman compose -f
//! docker-compose.test.yml up -d kdc`). The container reaches the host via
//! `KDC_LIVE_HOST` (default: the gvproxy host alias 192.168.127.254); the
//! test KDC listens on 0.0.0.0:10388 (and a second one with a tiny UDP
//! reply limit on 10389).
//!
//! Run with:
//!   cargo test --all-features --test kdc_live -- --ignored --test-threads=1

use std::io::Write;
use std::process::{Command, Stdio};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use krb5_rs::kdc::{
    serve_tcp, serve_udp, Kdc, KdcConfig, MemoryStore, PrincipalAttributes, PrincipalStore,
};
use krb5_rs::keytab::{FileKeytab, Keytab, KeytabEntry};
use krb5_rs::types::PrincipalName;
use tokio::net::{TcpListener, UdpSocket};

#[path = "common/mod.rs"]
mod common;
use common::kdc::{cp_in, KDC_CONTAINER};

const REALM: &str = "RUST.REALM";
/// Address the container uses to reach the host. On a podman WSL machine
/// `host.containers.internal` is the VM bridge, so default to the gvproxy
/// host alias; override with `KDC_LIVE_HOST`.
fn host() -> String {
    std::env::var("KDC_LIVE_HOST").unwrap_or_else(|_| "192.168.127.254".into())
}

const PORT: u16 = 10388;
const PORT_SMALL_DGRAM: u16 = 10389;
const ALICE_PASSWORD: &str = "alice-live-password";
const SERVICE_KEYTAB_IN_CONTAINER: &str = "/tmp/rust-service.keytab";

fn service() -> PrincipalName {
    PrincipalName::new_srv_hst("HTTP", "server.rust.realm")
}

struct Live {
    keytab_path: std::path::PathBuf,
}

fn live() -> &'static Live {
    static LIVE: OnceLock<Live> = OnceLock::new();
    LIVE.get_or_init(|| {
        let mut store = MemoryStore::new();
        store
            .add_random_key(
                PrincipalName::new_srv_inst("krbtgt", REALM),
                REALM,
                1,
                &[18, 17],
                PrincipalAttributes::empty(),
            )
            .expect("krbtgt");
        store
            .add_with_password(
                PrincipalName::new_principal("alice"),
                REALM,
                ALICE_PASSWORD,
                1,
                &[18, 17],
                PrincipalAttributes::REQUIRES_PRE_AUTH,
            )
            .expect("alice");
        store
            .add_random_key(service(), REALM, 1, &[18, 17], PrincipalAttributes::empty())
            .expect("service");

        let keytab_path = common::kdc::tmp("service.keytab");
        let _ = std::fs::remove_file(&keytab_path);
        let mut keytab = FileKeytab::new(&keytab_path);
        let entry = store
            .lookup(&service(), REALM)
            .expect("lookup")
            .expect("service entry");
        for k in &entry.keys {
            keytab
                .add_entry(&KeytabEntry {
                    principal: service(),
                    realm: REALM.to_string(),
                    timestamp: 0,
                    kvno: k.kvno,
                    key: k.key.clone(),
                })
                .expect("write keytab");
        }

        // Two KDCs over identical principals.
        let mut second = MemoryStore::new();
        for name in [
            PrincipalName::new_srv_inst("krbtgt", REALM),
            PrincipalName::new_principal("alice"),
            service(),
        ] {
            let e = store.lookup(&name, REALM).expect("lookup").expect("entry");
            second.insert(e);
        }

        let mut config = KdcConfig::new(REALM);
        config.max_renewable_life = Duration::from_secs(7 * 24 * 3600);
        let mut small = config.clone();
        small.max_dgram_reply_size = 200;
        let main_kdc = Arc::new(Kdc::new(config, store));
        let small_kdc = Arc::new(Kdc::new(small, second));

        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().expect("runtime");
            rt.block_on(async move {
                for (kdc, port) in [(main_kdc, PORT), (small_kdc, PORT_SMALL_DGRAM)] {
                    let addr = format!("0.0.0.0:{port}");
                    let udp = UdpSocket::bind(&addr).await.expect("bind udp");
                    let tcp = TcpListener::bind(&addr).await.expect("bind tcp");
                    tokio::spawn(serve_udp(Arc::clone(&kdc), udp));
                    tokio::spawn(serve_tcp(kdc, tcp));
                }
                ready_tx.send(()).expect("ready");
                std::future::pending::<()>().await;
            });
        });
        ready_rx.recv().expect("servers started");
        Live { keytab_path }
    })
}

/// Run `cmd` in the MIT container; optional stdin. Returns (status, output).
fn run(cmd: &str, stdin: Option<&str>) -> (i32, String) {
    let mut child = Command::new(common::kdc::container_cli())
        .args(["exec", "-i", KDC_CONTAINER, "bash", "-c", cmd])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("podman exec");
    {
        let mut pipe = child.stdin.take().expect("stdin");
        if let Some(s) = stdin {
            pipe.write_all(s.as_bytes()).expect("write stdin");
        }
    }
    let out = child.wait_with_output().expect("wait");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    (out.status.code().unwrap_or(-1), text)
}

/// Write a krb5.conf for RUST.REALM into the container and return its
/// path. `extra` lands in `[libdefaults]`.
fn krb5_conf(name: &str, port: u16, extra: &str) -> String {
    live();
    let path = format!("/tmp/rust-krb5-{name}.conf");
    let conf = format!(
        "[libdefaults]\n default_realm = {REALM}\n dns_lookup_kdc = false\n \
         dns_lookup_realm = false\n forwardable = true\n {extra}\n[realms]\n {REALM} = {{\n  \
         kdc = {host}:{port}\n }}\n",
        host = host()
    );
    let (code, out) = run(&format!("cat > {path}"), Some(&conf));
    assert_eq!(code, 0, "write krb5.conf: {out}");
    path
}

fn env(conf: &str, cc: &str) -> String {
    format!("KRB5_CONFIG={conf} KRB5CCNAME={cc}")
}

fn kinit(env: &str, args: &str, password: &str) -> (i32, String) {
    run(
        &format!("{env} kinit {args}"),
        Some(&format!("{password}\n")),
    )
}

/// Fail early with a connectivity diagnosis if the container cannot reach
/// the host KDC port.
fn require_connectivity() {
    live();
    let (code, out) = run(
        &format!("timeout 5 bash -c 'echo > /dev/tcp/{}/{PORT}'", host()),
        None,
    );
    assert_eq!(
        code,
        0,
        "container cannot reach {}:{PORT} over TCP ({out}); \
         a host firewall rule for the test binary may be required",
        host()
    );
}

#[test]
#[ignore = "requires podman + MIT client container"]
fn mit_kinit_default_udp_succeeds_and_klist_shows_tgt() {
    require_connectivity();
    let conf = krb5_conf("udp", PORT, "");
    let e = env(&conf, "/tmp/cc_a");
    let (code, out) = kinit(&e, "alice@RUST.REALM", ALICE_PASSWORD);
    assert_eq!(code, 0, "kinit: {out}");
    let (code, klist) = run(&format!("{e} klist"), None);
    assert_eq!(code, 0, "klist: {klist}");
    assert!(
        klist.contains("krbtgt/RUST.REALM@RUST.REALM"),
        "klist: {klist}"
    );
}

#[test]
#[ignore = "requires podman + MIT client container"]
fn mit_kinit_wrong_password_fails_with_preauth_failure() {
    require_connectivity();
    let conf = krb5_conf("udp", PORT, "");
    let e = env(&conf, "/tmp/cc_b");
    let (code, out) = kinit(&e, "alice@RUST.REALM", "definitely-wrong");
    assert_ne!(code, 0, "kinit must fail: {out}");
    assert!(out.contains("Password incorrect"), "kinit: {out}");
}

#[test]
#[ignore = "requires podman + MIT client container"]
fn mit_kinit_renewable_then_renew_succeeds() {
    require_connectivity();
    let conf = krb5_conf("udp", PORT, "");
    let e = env(&conf, "/tmp/cc_c");
    let (code, out) = kinit(&e, "-r 1d alice@RUST.REALM", ALICE_PASSWORD);
    assert_eq!(code, 0, "kinit -r: {out}");
    let (_, klist) = run(&format!("{e} klist"), None);
    assert!(klist.contains("renew until"), "klist: {klist}");
    let (code, out) = run(&format!("{e} kinit -R"), None);
    assert_eq!(code, 0, "kinit -R: {out}");
    let (code, klist) = run(&format!("{e} klist"), None);
    assert_eq!(code, 0, "klist: {klist}");
    assert!(klist.contains("krbtgt/RUST.REALM@RUST.REALM"), "{klist}");
}

#[test]
#[ignore = "requires podman + MIT client container"]
fn mit_kvno_service_ticket_decrypts_with_service_keytab() {
    require_connectivity();
    let conf = krb5_conf("udp", PORT, "");
    let e = env(&conf, "/tmp/cc_d");
    let (code, out) = kinit(&e, "alice@RUST.REALM", ALICE_PASSWORD);
    assert_eq!(code, 0, "kinit: {out}");
    let (code, out) = run(&format!("{e} kvno HTTP/server.rust.realm@RUST.REALM"), None);
    assert_eq!(code, 0, "kvno: {out}");
    assert!(
        out.contains("HTTP/server.rust.realm@RUST.REALM: kvno = 1"),
        "{out}"
    );

    cp_in(&live().keytab_path, SERVICE_KEYTAB_IN_CONTAINER);
    let (code, out) = run(
        &format!("{e} kvno -k {SERVICE_KEYTAB_IN_CONTAINER} HTTP/server.rust.realm@RUST.REALM"),
        None,
    );
    assert_eq!(code, 0, "kvno -k: {out}");
    assert!(out.contains("keytab entry valid"), "{out}");
}

#[test]
#[ignore = "requires podman + MIT client container"]
fn mit_kinit_fast_armor_succeeds_with_encrypted_challenge() {
    require_connectivity();
    let conf = krb5_conf("udp", PORT, "");
    let armor = env(&conf, "/tmp/cc_e_armor");
    let (code, out) = kinit(&armor, "alice@RUST.REALM", ALICE_PASSWORD);
    assert_eq!(code, 0, "armor kinit: {out}");

    let e = env(&conf, "/tmp/cc_e");
    let (code, out) = run(
        &format!("{e} KRB5_TRACE=/dev/stderr kinit -T /tmp/cc_e_armor alice@RUST.REALM"),
        Some(&format!("{ALICE_PASSWORD}\n")),
    );
    assert_eq!(code, 0, "FAST kinit: {out}");
    assert!(
        out.contains("FAST negotiation") || out.contains("fast"),
        "{out}"
    );
    assert!(out.contains("encrypted_challenge"), "{out}");

    let (code, out) = run(&format!("{e} kvno HTTP/server.rust.realm@RUST.REALM"), None);
    assert_eq!(code, 0, "kvno from FAST ccache: {out}");
}

#[test]
#[ignore = "requires podman + MIT client container"]
fn mit_trace_of_plain_kinit_shows_fast_negotiation() {
    require_connectivity();
    let conf = krb5_conf("udp", PORT, "");
    let e = env(&conf, "/tmp/cc_h");
    let (code, out) = run(
        &format!("{e} KRB5_TRACE=/dev/stderr kinit alice@RUST.REALM"),
        Some(&format!("{ALICE_PASSWORD}\n")),
    );
    assert_eq!(code, 0, "kinit: {out}");
    assert!(out.contains("FAST negotiation: available"), "{out}");
}

#[test]
#[ignore = "requires podman + MIT client container"]
fn mit_kinit_and_kvno_over_forced_tcp_succeed() {
    require_connectivity();
    let conf = krb5_conf("tcp", PORT, "udp_preference_limit = 1");
    let e = env(&conf, "/tmp/cc_f");
    let (code, out) = kinit(&e, "alice@RUST.REALM", ALICE_PASSWORD);
    assert_eq!(code, 0, "kinit over TCP: {out}");
    let (code, out) = run(&format!("{e} kvno HTTP/server.rust.realm@RUST.REALM"), None);
    assert_eq!(code, 0, "kvno over TCP: {out}");
}

#[test]
#[ignore = "requires podman + MIT client container"]
fn mit_kinit_falls_back_to_tcp_when_udp_reply_is_too_big() {
    require_connectivity();
    let conf = krb5_conf("small", PORT_SMALL_DGRAM, "");
    let e = env(&conf, "/tmp/cc_g");
    let (code, out) = run(
        &format!("{e} KRB5_TRACE=/dev/stderr kinit alice@RUST.REALM"),
        Some(&format!("{ALICE_PASSWORD}\n")),
    );
    assert_eq!(code, 0, "kinit with tiny UDP limit: {out}");
    assert!(
        out.contains("Initiating TCP connection to stream"),
        "trace should show the TCP retry: {out}"
    );
}
