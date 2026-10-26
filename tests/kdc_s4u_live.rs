#![cfg(all(feature = "kdc", feature = "tokio"))]
//! Live S4U interop with MIT krb5 1.22.2.
//!
//! * MIT client tools (`kinit -k`, `kvno -I ... [-P]`) in `krb5-rs-kdc-1`
//!   against OUR KDC (TEST.REALM on the host).
//! * OUR client against MIT's TEST.REALM KDC (db2: S4U2Self works, S4U2Proxy
//!   is refused at the KDB policy stage).
//!
//! `kvno -U` parses its argument as an enterprise principal, which makes MIT
//! look up the user's realm with an AS referral request; `-I` (plain
//! principal) is used instead.
//!
//! Requires podman + the compose container. Run with:
//!   cargo test --all-features --test kdc_s4u_live -- --ignored --test-threads=1

use std::io::Write;
use std::process::{Command, Stdio};
use std::sync::{Arc, OnceLock};

use krb5_rs::crypto::find_etype;
use krb5_rs::kdc::{
    serve_tcp, serve_udp, Kdc, KdcConfig, MemoryStore, PrincipalAttributes, PrincipalEntry,
};
use krb5_rs::keytab::{FileKeytab, Keytab, KeytabEntry};
use krb5_rs::pac::{ticket_pac, verify_ticket_pac};
use krb5_rs::protocol::ap::decrypt_ticket;
use krb5_rs::protocol::{
    AsExchange, AsExchangeConfig, Credential, StepResult, TgsExchange, TgsOptions, TgsStepResult,
};
use krb5_rs::types::{EncryptionKey, PrincipalName, TicketFlags};
use krb5_rs::Krb5Error;
use tokio::net::{TcpListener, UdpSocket};

#[path = "common/mod.rs"]
mod common;
use common::kdc::{container_cli, kdc_addr_str, kdc_send_to, KDC_CONTAINER, TEST_REALM as REALM};

const PORT: u16 = 10394;
const USER_PW: &str = "s4u-user-password";
const SVC_KEYTAB: &str = "/tmp/s4u-svc.keytab";
const CONF: &str = "/tmp/s4u-krb5.conf";

fn host() -> String {
    std::env::var("KDC_LIVE_HOST").unwrap_or_else(|_| "192.168.127.254".into())
}

fn tgs() -> PrincipalName {
    PrincipalName::new_srv_inst("krbtgt", REALM)
}

fn svc(host: &str) -> PrincipalName {
    PrincipalName::new_srv_hst("HTTP", &format!("{host}.test.realm"))
}

struct Live {
    keytab: std::path::PathBuf,
}

fn live() -> &'static Live {
    static LIVE: OnceLock<Live> = OnceLock::new();
    LIVE.get_or_init(|| {
        let mut store = MemoryStore::new();
        let none = PrincipalAttributes::empty();
        store
            .add_random_key(tgs(), REALM, 1, &[18, 17], none)
            .expect("krbtgt");
        store
            .add_with_password(
                PrincipalName::new_principal("alice"),
                REALM,
                USER_PW,
                1,
                &[18, 17],
                none,
            )
            .expect("alice");
        let mut add = |name: &str, attrs: PrincipalAttributes, to: &[&str], from: &[&str]| {
            let n = svc(name);
            store
                .add_with_password(n.clone(), REALM, "svc-password", 1, &[18, 17], attrs)
                .expect("service");
            let mut e: PrincipalEntry = store.get(&n, REALM).expect("entry");
            e.allowed_to_delegate_to = to.iter().map(|s| s.to_string()).collect();
            e.allowed_to_delegate_from = from.iter().map(|s| s.to_string()).collect();
            store.insert(e);
        };
        // The impersonating service: may delegate to `target` (traditional).
        add(
            "s4u",
            PrincipalAttributes::OK_TO_AUTH_AS_DELEGATE,
            &["HTTP/target.test.realm"],
            &[],
        );
        // A service with delegation targets but without ok-to-auth-as-delegate:
        // its S4U2Self tickets are not forwardable.
        add("nofwd", none, &["HTTP/target.test.realm"], &[]);
        add("target", none, &[], &[]);
        add("denied", none, &[], &[]);
        add("rbcdt", none, &[], &["HTTP/s4u.test.realm@TEST.REALM"]);

        let keytab = common::kdc::tmp("s4u_svc.keytab");
        let _ = std::fs::remove_file(&keytab);
        let mut kt = FileKeytab::new(&keytab);
        for name in ["s4u", "nofwd"] {
            let n = svc(name);
            let e = store.get(&n, REALM).expect("entry");
            for k in &e.keys {
                kt.add_entry(&KeytabEntry {
                    principal: n.clone(),
                    realm: REALM.to_string(),
                    timestamp: 0,
                    kvno: k.kvno,
                    key: k.key.clone(),
                })
                .expect("keytab");
            }
        }

        let mut config = KdcConfig::new(REALM);
        config.max_renewable_life = std::time::Duration::from_secs(7 * 24 * 3600);
        let kdc = Arc::new(Kdc::new(config, store));
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().expect("runtime");
            rt.block_on(async move {
                let addr = format!("0.0.0.0:{PORT}");
                let udp = UdpSocket::bind(&addr).await.expect("bind udp");
                let tcp = TcpListener::bind(&addr).await.expect("bind tcp");
                tokio::spawn(serve_udp(Arc::clone(&kdc), udp));
                tokio::spawn(serve_tcp(kdc, tcp));
                tx.send(()).expect("ready");
                std::future::pending::<()>().await;
            });
        });
        rx.recv().expect("server started");
        Live { keytab }
    })
}

fn run(cmd: &str, stdin: Option<&str>) -> (i32, String) {
    let mut child = Command::new(container_cli())
        .args(["exec", "-i", KDC_CONTAINER, "bash", "-c", cmd])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("container exec");
    {
        let mut pipe = child.stdin.take().expect("stdin");
        if let Some(s) = stdin {
            pipe.write_all(s.as_bytes()).expect("write stdin");
        }
    }
    let out = child.wait_with_output().expect("wait");
    (
        out.status.code().unwrap_or(-1),
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ),
    )
}

fn setup(cc: &str, principal: &str) -> String {
    let live = live();
    let krb5 = format!(
        "[libdefaults]\n default_realm = {REALM}\n dns_lookup_kdc = false\n \
         dns_lookup_realm = false\n forwardable = true\n dns_canonicalize_hostname = false\n\
         [realms]\n {REALM} = {{\n  kdc = {}:{PORT}\n }}\n[domain_realm]\n \
         .test.realm = {REALM}\n",
        host()
    );
    let (code, out) = run(&format!("cat > {CONF}"), Some(&krb5));
    assert_eq!(code, 0, "write krb5.conf: {out}");
    let cp = Command::new(container_cli())
        .args([
            "cp",
            &live.keytab.to_string_lossy(),
            &format!("{KDC_CONTAINER}:{SVC_KEYTAB}"),
        ])
        .output()
        .expect("cp");
    assert!(cp.status.success(), "cp keytab: {cp:?}");
    let env = format!("KRB5_CONFIG={CONF} KRB5CCNAME={cc} KRB5_KDC_PROFILE=/etc/krb5kdc/kdc.conf");
    let (code, out) = run(
        &format!("{env} kinit -k -t {SVC_KEYTAB} {principal}@{REALM}"),
        None,
    );
    assert_eq!(code, 0, "kinit -k: {out}");
    env
}

/// The `Flags:` line of the first ticket in `klist -f` whose service is
/// `service` (flags of the TGT excluded).
fn ticket_flags(klist: &str, service: &str) -> String {
    let mut lines = klist.lines();
    while let Some(l) = lines.next() {
        if l.starts_with(|c: char| c.is_ascii_digit()) && l.trim_end().ends_with(service) {
            for next in lines.by_ref() {
                if let Some((_, f)) = next.rsplit_once("Flags: ") {
                    return f.trim().to_string();
                }
            }
        }
    }
    panic!("no ticket for {service} in {klist}");
}

#[test]
#[ignore = "requires podman + MIT client container"]
fn mit_kvno_s4u2self_against_our_kdc() {
    let e = setup("/tmp/cc_s4u_self", "HTTP/s4u.test.realm");
    let (code, out) = run(
        &format!("{e} KRB5_TRACE=/dev/stderr kvno -I alice HTTP/s4u.test.realm@{REALM}"),
        None,
    );
    assert_eq!(code, 0, "kvno -I: {out}");
    assert!(out.contains("kvno = 1"), "{out}");
    assert!(out.contains("S4U2Self") || out.contains("s4u"), "{out}");
    let (_, klist) = run(&format!("{e} klist -f"), None);
    // ok-to-auth-as-delegate: the S4U2Self ticket is forwardable.
    let flags = ticket_flags(&klist, &format!("HTTP/s4u.test.realm@{REALM}"));
    assert!(flags.contains('F'), "{klist}");
    // The ticket decrypts with the service keytab (kvno -k).
    let (code, out) = run(
        &format!("{e} kvno -I alice -k {SVC_KEYTAB} HTTP/s4u.test.realm@{REALM}"),
        None,
    );
    assert_eq!(code, 0, "kvno -k: {out}");
    assert!(out.contains("keytab entry valid"), "{out}");
}

#[test]
#[ignore = "requires podman + MIT client container"]
fn mit_kvno_s4u2self_is_not_forwardable_with_delegation_targets_only() {
    let e = setup("/tmp/cc_s4u_nofwd", "HTTP/nofwd.test.realm");
    let (code, out) = run(
        &format!("{e} kvno -I alice HTTP/nofwd.test.realm@{REALM}"),
        None,
    );
    assert_eq!(code, 0, "kvno -I: {out}");
    let (_, klist) = run(&format!("{e} klist -f"), None);
    let flags = ticket_flags(&klist, &format!("HTTP/nofwd.test.realm@{REALM}"));
    assert!(!flags.contains('F'), "{klist}");
}

#[test]
#[ignore = "requires podman + MIT client container"]
fn mit_kvno_s4u2proxy_traditional_and_rbcd_against_our_kdc() {
    let e = setup("/tmp/cc_s4u_proxy", "HTTP/s4u.test.realm");
    for target in ["target", "rbcdt"] {
        let (code, out) = run(
            &format!(
                "{e} KRB5_TRACE=/dev/stderr kvno -I alice -P HTTP/{target}.test.realm@{REALM}"
            ),
            None,
        );
        assert_eq!(code, 0, "kvno -P {target}: {out}");
    }
    let (_, klist) = run(&format!("{e} klist"), None);
    for target in ["target", "rbcdt"] {
        assert!(
            klist.contains(&format!("HTTP/{target}.test.realm@{REALM}")),
            "{klist}"
        );
    }
}

#[test]
#[ignore = "requires podman + MIT client container"]
fn mit_kvno_s4u2proxy_denied_target_is_refused_by_our_kdc() {
    let e = setup("/tmp/cc_s4u_denied", "HTTP/s4u.test.realm");
    let (code, out) = run(
        &format!("{e} kvno -I alice -P HTTP/denied.test.realm@{REALM}"),
        None,
    );
    assert_ne!(code, 0, "{out}");
    assert!(out.contains("constrained delegation failed"), "{out}");
    assert!(out.contains("KDC can't fulfill requested option"), "{out}");
}

/// `kvno -F` input: a principal name as a fake PEM certificate (t_s4u.py
/// `princ_cert`).
const FAKE_CERT: &str = "-----BEGIN CERTIFICATE-----\nYWxpY2U=\n-----END y\n";

#[test]
#[ignore = "requires podman + MIT client container"]
fn mit_kvno_s4u2self_by_certificate_fails_like_against_mits_db2() {
    // Neither MIT db2 nor our MemoryStore maps certificates to principals
    // (KRB5_PLUGIN_OP_NOTSUPP): the AS probe gets a generic error.
    let (code, out) = run("cat > /tmp/s4u-cert", Some(FAKE_CERT));
    assert_eq!(code, 0, "{out}");
    let mit = "KRB5CCNAME=/tmp/cc_s4u_cert_mit";
    let (code, out) = run(
        &format!("{mit} kinit HTTP/server.test.realm@{REALM}"),
        Some("httpsecret\n"),
    );
    assert_eq!(code, 0, "kinit against MIT: {out}");
    let (mit_code, mit_out) = run(
        &format!("{mit} kvno -F /tmp/s4u-cert HTTP/server.test.realm@{REALM}"),
        None,
    );
    let e = setup("/tmp/cc_s4u_cert", "HTTP/s4u.test.realm");
    let (code, out) = run(
        &format!("{e} KRB5_TRACE=/dev/stderr kvno -F /tmp/s4u-cert HTTP/s4u.test.realm@{REALM}"),
        None,
    );
    assert_ne!(mit_code, 0, "{mit_out}");
    assert_ne!(code, 0, "{out}");
    assert!(
        out.contains("Getting initial credentials for @TEST.REALM"),
        "{out}"
    );
    let want = "kvno: Generic error (see e-text) while getting credentials for";
    assert!(mit_out.contains(want), "{mit_out}");
    assert!(out.contains(want), "{out}");
}

/// Copy a ccache between the container and the host (`to_host`) or back.
fn cp_ccache(container_path: &str, host_path: &std::path::Path, to_host: bool) {
    let remote = format!("{KDC_CONTAINER}:{container_path}");
    let local = host_path.to_string_lossy().into_owned();
    if to_host {
        let (code, out) = run(&format!("chmod 644 {container_path}"), None);
        assert_eq!(code, 0, "chmod: {out}");
    }
    let (from, to) = if to_host {
        (remote, local)
    } else {
        (local, remote)
    };
    let cp = Command::new(container_cli())
        .args(["cp", &from, &to])
        .output()
        .expect("cp");
    assert!(cp.status.success(), "cp ccache: {cp:?}");
}

#[cfg(feature = "client")]
#[test]
#[ignore = "requires podman + MIT client container"]
fn mit_kvno_and_our_client_share_s4u_ccache_entries() {
    use krb5_rs::ccache::FileCcache;
    use krb5_rs::client::{CredsRequest, GcOptions, KerberosClient};
    use krb5_rs::transport::TcpTransport;

    let cc = "/tmp/cc_s4u_share";
    let e = setup(cc, "HTTP/s4u.test.realm");
    let (code, out) = run(
        &format!("{e} kvno -I alice -P HTTP/target.test.realm@{REALM}"),
        None,
    );
    assert_eq!(code, 0, "kvno -P target: {out}");
    let local = common::kdc::tmp("cc_s4u_share");
    let _ = std::fs::remove_file(&local);
    cp_ccache(cc, &local, true);

    let addr = format!("{}:{PORT}", host()).parse().expect("addr");
    let client = KerberosClient::new(REALM, TcpTransport::new(addr));
    let mut ccache = FileCcache::new(&local);
    let alice = PrincipalName::new_principal("alice");
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    rt.block_on(async {
        // MIT's S4U2Self and S4U2Proxy entries satisfy cached-only lookups.
        let self_req = CredsRequest::new(alice.clone(), REALM, svc("s4u"), REALM);
        let evidence = client
            .get_credentials_for_user(&mut ccache, GcOptions::CACHED, &self_req, None)
            .await
            .expect("MIT's S4U2Self entry");
        assert_eq!(evidence.client, alice);
        let target = CredsRequest::new(alice.clone(), REALM, svc("target"), REALM);
        client
            .get_credentials_for_proxy(&mut ccache, GcOptions::CACHED, &target, &evidence)
            .await
            .expect("MIT's S4U2Proxy entry");
        // An S4U2Proxy credential we store, from MIT's evidence ticket.
        let rbcd = CredsRequest::new(alice.clone(), REALM, svc("rbcdt"), REALM);
        let r = client
            .get_credentials_for_proxy(&mut ccache, GcOptions::CACHED, &rbcd, &evidence)
            .await;
        assert!(r.is_err(), "nothing cached for rbcdt yet");
        client
            .get_credentials_for_proxy(&mut ccache, GcOptions::empty(), &rbcd, &evidence)
            .await
            .expect("S4U2Proxy to rbcdt");
    });

    cp_ccache(cc, &local, false);
    let (code, out) = run(
        &format!(
            "{e} KRB5_TRACE=/dev/stderr kvno --cached-only -I alice -P HTTP/rbcdt.test.realm@{REALM}"
        ),
        None,
    );
    assert_eq!(code, 0, "kvno --cached-only rbcdt: {out}");
    assert!(!out.contains("Sending request"), "{out}");
}

// ----------------------------------------------- our client against MIT's KDC

fn kdc_send(realm: &str, data: &[u8]) -> Vec<u8> {
    assert_eq!(realm, REALM);
    kdc_send_to(&kdc_addr_str(), data).expect("MIT KDC reply")
}

fn service_tgt() -> Credential {
    // HTTP/server.test.realm has the known password "httpsecret"
    // (tests/kdc/setup.sh).
    let config = AsExchangeConfig::new(
        PrincipalName::new_srv_hst("HTTP", "server.test.realm"),
        REALM,
    );
    let mut ex = AsExchange::new(config, "httpsecret");
    let mut reply = Vec::new();
    while let StepResult::SendToKdc { data, .. } | StepResult::RetryTcp { data, .. } =
        ex.step(&reply).expect("AS step")
    {
        reply = kdc_send(REALM, &data);
    }
    ex.credential().expect("TGT").clone()
}

fn run_tgs(mut ex: TgsExchange) -> Result<Credential, Krb5Error> {
    let mut reply = Vec::new();
    loop {
        match ex.step(&reply)? {
            TgsStepResult::SendToKdc { data, realm } | TgsStepResult::RetryTcp { data, realm } => {
                reply = kdc_send(&realm, &data);
            }
            TgsStepResult::Complete => return Ok(ex.credential().expect("cred").clone()),
        }
    }
}

fn http_key() -> EncryptionKey {
    let key = find_etype(18)
        .expect("etype")
        .string_to_key(b"httpsecret", b"TEST.REALMHTTPserver.test.realm", None)
        .expect("s2k");
    EncryptionKey::new(18, key.to_vec())
}

#[test]
#[ignore = "requires podman + MIT KDC container"]
fn our_client_s4u2self_against_mit_kdc_verifies_reply_and_pac() {
    let tgt = service_tgt();
    let user = PrincipalName::new_principal("testuser");
    let cred = run_tgs(TgsExchange::s4u2self(
        tgt,
        user.clone(),
        REALM,
        TgsOptions::default(),
    ))
    .expect("S4U2Self against MIT");
    assert_eq!(cred.client, user);
    assert_eq!(
        cred.server.name_string,
        PrincipalName::new_srv_hst("HTTP", "server.test.realm").name_string
    );
    // db2 has no delegation lists, so MIT leaves the ticket forwardable.
    assert!(cred.flags.contains(TicketFlags::FORWARDABLE));

    let part = decrypt_ticket(&http_key(), &cred.ticket).expect("decrypt");
    let pac = ticket_pac(&part).expect("parse").expect("MIT issues a PAC");
    assert_eq!(pac.client_info().expect("client info").name, "testuser");
    verify_ticket_pac(
        &part,
        &PrincipalName::new_srv_hst("HTTP", "server.test.realm"),
        &http_key(),
        None,
    )
    .expect("MIT's S4U2Self PAC verifies")
    .expect("PAC");
}

#[test]
#[ignore = "requires podman + MIT KDC container"]
fn our_client_s4u2proxy_reaches_mits_policy_stage_and_is_refused() {
    let tgt = service_tgt();
    let service = PrincipalName::new_srv_hst("HTTP", "server.test.realm");
    let evidence = run_tgs(TgsExchange::s4u2self(
        tgt.clone(),
        PrincipalName::new_principal("testuser"),
        REALM,
        TgsOptions::default(),
    ))
    .expect("evidence ticket");
    let err = run_tgs(TgsExchange::s4u2proxy(
        tgt,
        evidence,
        service,
        TgsOptions::default(),
    ))
    .expect_err("db2 supports no constrained delegation");
    let Krb5Error::KdcError(m) = err else {
        panic!("expected KDC error, got {err:?}");
    };
    assert_eq!(m.error_code, 13, "KDC_ERR_BADOPTION");
    // The failure is MIT's check_s4u2proxy_policy, not request parsing: the
    // KDC log carries its status string.
    let logs = Command::new(container_cli())
        .args(["logs", "--tail", "60", KDC_CONTAINER])
        .output()
        .expect("logs");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&logs.stdout),
        String::from_utf8_lossy(&logs.stderr)
    );
    assert!(
        text.contains("UNSUPPORTED_S4U2PROXY_REQUEST"),
        "KDC log lacks the policy status:\n{text}"
    );
}
