#![cfg(all(feature = "kdc", feature = "tokio"))]
//! Live cross-realm S4U2Proxy (RBCD) interop with MIT krb5 1.22.2: OUR KDC
//! serves TEST.REALM on the host, the MIT KDC in `krb5-rs-kdc-other-1` serves
//! OTHER.REALM (trust password "crosstrust", tests/kdc/setup-other.sh). MIT
//! `kvno -I ... -P` runs in the other-realm container.
//!
//! Cross-realm S4U2Self is not exercised here: MIT's client asks the user's
//! realm for an enterprise server name, which only MIT's test KDB module
//! answers with a referral (db2 and LMDB do not).
//!
//! Requires podman + both compose containers. Run with:
//!   cargo test --all-features --test kdc_s4u_xrealm_live -- --ignored --test-threads=1

use std::io::Write;
use std::process::{Command, Stdio};
use std::sync::{Arc, OnceLock};

use krb5_rs::kdc::{
    serve_tcp, serve_udp, Kdc, KdcConfig, MemoryStore, PrincipalAttributes, PrincipalEntry,
};
use krb5_rs::keytab::{FileKeytab, Keytab, KeytabEntry};
use krb5_rs::profile::Profile;
use krb5_rs::protocol::{
    AsExchange, AsExchangeConfig, Credential, StepResult, TgsExchange, TgsOptions, TgsStepResult,
};
use krb5_rs::types::PrincipalName;
use krb5_rs::Krb5Error;
use tokio::net::{TcpListener, UdpSocket};

#[path = "common/mod.rs"]
mod common;
use common::kdc::container_cli;

const OTHER_CONTAINER: &str = "krb5-rs-kdc-other-1";
const REALM: &str = "TEST.REALM";
const OTHER_REALM: &str = "OTHER.REALM";
const PORT: u16 = 10397;
const TRUST_PASSWORD: &str = "crosstrust";
const OUR_KEYTAB: &str = "/tmp/xs4u-test.keytab";
const OTHER_KEYTAB: &str = "/tmp/xs4u-other.keytab";
const CONF: &str = "/tmp/xs4u-krb5.conf";
/// The OTHER.REALM impersonator, as RBCD entries name it.
/// Our client's impersonating service (TEST.REALM, known password).
const CLIENT_SVC_PASSWORD: &str = "xs4u-client-svc-password";
const OTHER_IMPERSONATOR: &str = "HTTP/xs4u.other.realm@OTHER.REALM";

fn host() -> String {
    std::env::var("KDC_LIVE_HOST").unwrap_or_else(|_| "192.168.127.254".into())
}

fn tgs(instance: &str) -> PrincipalName {
    PrincipalName::new_srv_inst("krbtgt", instance)
}

fn svc(host: &str) -> PrincipalName {
    PrincipalName::new_srv_hst("HTTP", host)
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
            .add_random_key(tgs(REALM), REALM, 1, &[18, 17], none)
            .expect("krbtgt");
        store
            .add_with_password(tgs(OTHER_REALM), REALM, TRUST_PASSWORD, 1, &[18, 17], none)
            .expect("outgoing trust");
        store
            .add_with_password(tgs(REALM), OTHER_REALM, TRUST_PASSWORD, 1, &[18, 17], none)
            .expect("incoming trust");
        store
            .add_with_password(
                PrincipalName::new_principal("tuser"),
                REALM,
                "xs4u-user-password",
                1,
                &[18, 17],
                none,
            )
            .expect("user");
        let mut add = |host: &str, attrs: PrincipalAttributes, from: &[&str]| {
            let n = svc(host);
            store
                .add_random_key(n.clone(), REALM, 1, &[18, 17], attrs)
                .expect("service");
            let mut e: PrincipalEntry = store.get(&n, REALM).expect("entry");
            e.allowed_to_delegate_from = from.iter().map(|s| s.to_string()).collect();
            store.insert(e);
        };
        add(
            "xs4u.test.realm",
            PrincipalAttributes::OK_TO_AUTH_AS_DELEGATE | PrincipalAttributes::REQUIRES_PRE_AUTH,
            &[],
        );
        add("rbcd.test.realm", none, &[OTHER_IMPERSONATOR]);
        add("norbcd.test.realm", none, &[]);
        store
            .add_with_password(
                svc("xs4uc.test.realm"),
                REALM,
                CLIENT_SVC_PASSWORD,
                1,
                &[18, 17],
                PrincipalAttributes::OK_TO_AUTH_AS_DELEGATE,
            )
            .expect("client service");

        let keytab = common::kdc::tmp("xs4u_test.keytab");
        let _ = std::fs::remove_file(&keytab);
        let mut kt = FileKeytab::new(&keytab);
        let n = svc("xs4u.test.realm");
        for k in &store.get(&n, REALM).expect("entry").keys {
            kt.add_entry(&KeytabEntry {
                principal: n.clone(),
                realm: REALM.to_string(),
                timestamp: 0,
                kvno: k.kvno,
                key: k.key.clone(),
            })
            .expect("keytab");
        }

        let mut config = KdcConfig::new(REALM);
        config.max_renewable_life = std::time::Duration::from_secs(7 * 24 * 3600);
        config.realm_profile = Some(
            Profile::parse(
                "[domain_realm]\n .other.realm = OTHER.REALM\n other.realm = OTHER.REALM\n",
            )
            .expect("krb5.conf"),
        );
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
        .args(["exec", "-i", OTHER_CONTAINER, "bash", "-c", cmd])
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

/// The MIT KDC's log so far (it logs to stderr).
fn other_kdc_log() -> String {
    let out = Command::new(container_cli())
        .args(["logs", OTHER_CONTAINER])
        .output()
        .expect("container logs");
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

/// Write the client krb5.conf (no `[domain_realm]` for the target hosts, so
/// `kvno -S` yields referral-realm names as S4U2Proxy requires), create the
/// OTHER.REALM principals and copy our impersonator's keytab in.
fn setup() {
    static DONE: OnceLock<()> = OnceLock::new();
    DONE.get_or_init(|| {
        let live = live();
        let conf = format!(
            "[libdefaults]\n default_realm = {OTHER_REALM}\n dns_lookup_kdc = false\n \
             dns_lookup_realm = false\n forwardable = true\n dns_canonicalize_hostname = false\n\
             [realms]\n {REALM} = {{\n  kdc = {}:{PORT}\n }}\n {OTHER_REALM} = {{\n  \
             kdc = 127.0.0.1:88\n }}\n",
            host()
        );
        let (code, out) = run(&format!("cat > {CONF}"), Some(&conf));
        assert_eq!(code, 0, "write krb5.conf: {out}");
        let (code, out) = run(
            &format!("timeout 5 bash -c 'echo > /dev/tcp/{}/{PORT}'", host()),
            None,
        );
        assert_eq!(
            code,
            0,
            "container cannot reach {}:{PORT} ({out}); a host firewall rule may be required",
            host()
        );
        for q in [
            format!("delprinc -force {OTHER_IMPERSONATOR}"),
            "delprinc -force HTTP/target.other.realm@OTHER.REALM".into(),
            "delprinc -force xuser@OTHER.REALM".into(),
            format!("addprinc -randkey +ok_to_auth_as_delegate {OTHER_IMPERSONATOR}"),
            "addprinc -randkey HTTP/target.other.realm@OTHER.REALM".into(),
            "addprinc -randkey xuser@OTHER.REALM".into(),
        ] {
            run(&format!("kadmin.local -q '{q}'"), None);
        }
        let (code, out) = run(
            &format!("rm -f {OTHER_KEYTAB}; kadmin.local -q 'ktadd -k {OTHER_KEYTAB} {OTHER_IMPERSONATOR}'"),
            None,
        );
        assert_eq!(code, 0, "ktadd: {out}");
        let cp = Command::new(container_cli())
            .args([
                "cp",
                &live.keytab.to_string_lossy(),
                &format!("{OTHER_CONTAINER}:{OUR_KEYTAB}"),
            ])
            .output()
            .expect("container cp");
        assert!(cp.status.success(), "cp keytab: {cp:?}");
    });
}

fn env(cc: &str) -> String {
    format!("KRB5_CONFIG={CONF} KRB5CCNAME={cc} KRB5_TRACE=/dev/stderr")
}

fn kinit_other(cc: &str) -> String {
    setup();
    let e = env(cc);
    let (code, out) = run(
        &format!("{e} kinit -k -t {OTHER_KEYTAB} {OTHER_IMPERSONATOR}"),
        None,
    );
    assert_eq!(code, 0, "kinit -k: {out}");
    e
}

#[test]
#[ignore = "requires podman + both compose containers"]
fn mit_cross_realm_rbcd_into_our_realm_is_granted() {
    let e = kinit_other("/tmp/cc_xs4u_rbcd");
    let (code, out) = run(
        &format!("{e} kvno -I xuser@{OTHER_REALM} -P -S HTTP rbcd.test.realm"),
        None,
    );
    assert_eq!(code, 0, "kvno -P: {out}");
    let (_, klist) = run(&format!("{e} klist"), None);
    assert!(
        klist.contains(&format!("Ticket server: HTTP/rbcd.test.realm@{REALM}")),
        "{klist}"
    );
    assert!(
        klist.contains(&format!("for client xuser@{OTHER_REALM}")),
        "{klist}"
    );
}

#[test]
#[ignore = "requires podman + both compose containers"]
fn mit_cross_realm_rbcd_into_our_realm_without_an_entry_is_refused() {
    let e = kinit_other("/tmp/cc_xs4u_norbcd");
    let (code, out) = run(
        &format!("{e} kvno -I xuser@{OTHER_REALM} -P -S HTTP norbcd.test.realm"),
        None,
    );
    assert_ne!(code, 0, "{out}");
    assert!(out.contains("KDC can't fulfill requested option"), "{out}");
}

#[test]
#[ignore = "requires podman + both compose containers"]
fn our_proxy_referral_passes_mits_cross_realm_evidence_checks() {
    setup();
    let e = env("/tmp/cc_xs4u_ours");
    let (code, out) = run(
        &format!("{e} kinit -k -t {OUR_KEYTAB} HTTP/xs4u.test.realm@{REALM}"),
        None,
    );
    assert_eq!(code, 0, "kinit -k: {out}");
    let before = other_kdc_log().len();
    let (code, out) = run(
        &format!("{e} kvno -I tuser@{REALM} -P -S HTTP target.other.realm"),
        None,
    );
    // MIT's db2 has no RBCD lists, so the final request fails at MIT's
    // policy stage, after verify_deleg_pac accepted our referral's PAC.
    assert_ne!(code, 0, "{out}");
    assert!(
        out.contains(&format!("krbtgt/{OTHER_REALM}@{REALM}")),
        "no referral from our KDC: {out}"
    );
    let log = other_kdc_log();
    let log = &log[before.min(log.len())..];
    assert!(log.contains("UNSUPPORTED_S4U2PROXY_REQUEST"), "{log}");
    for bad in [
        "S4U2PROXY_CROSS_STKT_PAC",
        "XREALM_EVIDENCE_TICKET_MISMATCH",
        "RBCD_PAC_PRINC",
    ] {
        assert!(!log.contains(bad), "{log}");
    }
}

/// Our client's KDC routing: TEST.REALM is the in-process KDC, OTHER.REALM
/// the MIT container.
fn send(realm: &str, data: &[u8]) -> Vec<u8> {
    let addr = if realm == REALM {
        format!("127.0.0.1:{PORT}")
    } else {
        assert_eq!(realm, OTHER_REALM);
        let out = Command::new(container_cli())
            .args([
                "inspect",
                "-f",
                "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
                OTHER_CONTAINER,
            ])
            .output()
            .expect("container inspect");
        format!("{}:88", String::from_utf8_lossy(&out.stdout).trim())
    };
    common::kdc::kdc_send_to(&addr, data).expect("KDC reply")
}

fn run_tgs(mut ex: TgsExchange) -> Result<Credential, Krb5Error> {
    let mut reply = Vec::new();
    loop {
        match ex.step(&reply)? {
            TgsStepResult::SendToKdc { data, realm } | TgsStepResult::RetryTcp { data, realm } => {
                reply = send(&realm, &data);
            }
            TgsStepResult::Complete => return Ok(ex.credential().expect("cred").clone()),
        }
    }
}

#[test]
#[ignore = "requires podman + both compose containers"]
fn our_client_follows_cross_realm_s4u2self_referrals_through_mit() {
    setup();
    let mut ex = AsExchange::new(
        AsExchangeConfig::new(svc("xs4uc.test.realm"), REALM),
        CLIENT_SVC_PASSWORD,
    );
    let mut reply = Vec::new();
    while let StepResult::SendToKdc { data, realm } | StepResult::RetryTcp { data, realm } =
        ex.step(&reply).expect("AS step")
    {
        reply = send(&realm, &data);
    }
    let tgt = ex.credential().expect("TGT").clone();
    // A TGT to the user's realm first, as krb5_get_self_cred_from_kdc does.
    let cross = run_tgs(TgsExchange::new(
        tgt,
        tgs(OTHER_REALM),
        TgsOptions::default(),
    ))
    .expect("cross-realm TGT");
    let opts = TgsOptions {
        canonicalize: true,
        ..TgsOptions::default()
    };
    let cred = run_tgs(TgsExchange::s4u2self(
        cross,
        PrincipalName::new_principal("xuser"),
        OTHER_REALM,
        opts,
    ))
    .expect("cross-realm S4U2Self");
    assert_eq!(
        cred.client.name_string,
        PrincipalName::new_principal("xuser").name_string
    );
    assert_eq!(cred.crealm, OTHER_REALM);
    assert_eq!(cred.server.name_string, svc("xs4uc.test.realm").name_string);
    assert_eq!(cred.srealm, REALM);
}
