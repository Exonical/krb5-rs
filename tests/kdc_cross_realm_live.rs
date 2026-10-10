#![cfg(all(feature = "kdc", feature = "tokio"))]
//! Live cross-realm interop: OUR KDC serves TEST.REALM on the host, the MIT
//! KDC in `krb5-rs-kdc-other-1` serves OTHER.REALM (tests/kdc/setup-other.sh:
//! trust principals with password "crosstrust"). MIT client tools run in the
//! other-realm container.
//!
//! Requires podman + both compose containers. Run with:
//!   cargo test --all-features --test kdc_cross_realm_live -- --ignored --test-threads=1

use std::io::Write;
use std::process::{Command, Stdio};
use std::sync::{Arc, OnceLock};

use krb5_rs::kdc::{
    serve_tcp, serve_udp, Kdc, KdcConfig, MemoryStore, PrincipalAttributes, PrincipalStore,
};
use krb5_rs::keytab::{FileKeytab, Keytab, KeytabEntry};
use krb5_rs::profile::Profile;
use krb5_rs::types::PrincipalName;
use tokio::net::{TcpListener, UdpSocket};

#[path = "common/mod.rs"]
mod common;
use common::kdc::container_cli;

const OTHER_CONTAINER: &str = "krb5-rs-kdc-other-1";
const REALM: &str = "TEST.REALM";
const OTHER_REALM: &str = "OTHER.REALM";
const PORT: u16 = 10391;
const USER_PASSWORD: &str = "cross-user-password";
const OTHER_USER_PASSWORD: &str = "other-user-password";
const TRUST_PASSWORD: &str = "crosstrust";
const KEYTAB_IN_CONTAINER: &str = "/tmp/cross-test-service.keytab";

fn host() -> String {
    std::env::var("KDC_LIVE_HOST").unwrap_or_else(|_| "192.168.127.254".into())
}

fn tgs(instance: &str) -> PrincipalName {
    PrincipalName::new_srv_inst("krbtgt", instance)
}

fn service() -> PrincipalName {
    PrincipalName::new_srv_hst("HTTP", "server.test.realm")
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
            .add_with_password(
                PrincipalName::new_principal("tuser"),
                REALM,
                USER_PASSWORD,
                1,
                &[18, 17],
                PrincipalAttributes::REQUIRES_PRE_AUTH,
            )
            .expect("user");
        store
            .add_random_key(service(), REALM, 1, &[18, 17], none)
            .expect("service");
        // krbtgt/OTHER.REALM@TEST.REALM (outgoing) and
        // krbtgt/TEST.REALM@OTHER.REALM (incoming), setup-other.sh:46-51.
        store
            .add_with_password(tgs(OTHER_REALM), REALM, TRUST_PASSWORD, 1, &[18, 17], none)
            .expect("outgoing trust");
        store
            .add_with_password(tgs(REALM), OTHER_REALM, TRUST_PASSWORD, 1, &[18, 17], none)
            .expect("incoming trust");

        let keytab = common::kdc::tmp("cross_service.keytab");
        let _ = std::fs::remove_file(&keytab);
        let mut kt = FileKeytab::new(&keytab);
        let entry = store
            .lookup(&service(), REALM)
            .expect("lookup")
            .expect("entry");
        for k in &entry.keys {
            kt.add_entry(&KeytabEntry {
                principal: service(),
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

        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().expect("runtime");
            rt.block_on(async move {
                let addr = format!("0.0.0.0:{PORT}");
                let udp = UdpSocket::bind(&addr).await.expect("bind udp");
                let tcp = TcpListener::bind(&addr).await.expect("bind tcp");
                tokio::spawn(serve_udp(Arc::clone(&kdc), udp));
                tokio::spawn(serve_tcp(kdc, tcp));
                ready_tx.send(()).expect("ready");
                std::future::pending::<()>().await;
            });
        });
        ready_rx.recv().expect("server started");
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

const CONF: &str = "/tmp/cross-krb5.conf";
const CONF_MISMAPPED: &str = "/tmp/cross-krb5-mismapped.conf";

/// Client config whose [domain_realm] sends each realm's hosts to the other
/// realm, so host-based requests start at the wrong KDC and need a referral.
fn write_mismapped_conf() {
    write_conf();
    let conf = format!(
        "[libdefaults]\n default_realm = {REALM}\n dns_lookup_kdc = false\n \
         dns_lookup_realm = false\n dns_canonicalize_hostname = false\n[realms]\n {REALM} = {{\n  \
         kdc = {}:{PORT}\n }}\n {OTHER_REALM} = {{\n  kdc = 127.0.0.1:88\n }}\n[domain_realm]\n \
         .test.realm = {OTHER_REALM}\n .other.realm = {REALM}\n",
        host()
    );
    let (code, out) = run(&format!("cat > {CONF_MISMAPPED}"), Some(&conf));
    assert_eq!(code, 0, "write krb5.conf: {out}");
}

fn write_conf() {
    live();
    let conf = format!(
        "[libdefaults]\n default_realm = {REALM}\n dns_lookup_kdc = false\n \
         dns_lookup_realm = false\n forwardable = true\n[realms]\n {REALM} = {{\n  kdc = {}:{PORT}\n }}\n \
         {OTHER_REALM} = {{\n  kdc = 127.0.0.1:88\n }}\n[domain_realm]\n .test.realm = {REALM}\n \
         test.realm = {REALM}\n .other.realm = {OTHER_REALM}\n other.realm = {OTHER_REALM}\n",
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
}

fn env(cc: &str) -> String {
    format!("KRB5_CONFIG={CONF} KRB5CCNAME={cc}")
}

fn copy_keytab_in() {
    let out = Command::new(container_cli())
        .args([
            "cp",
            &live().keytab.to_string_lossy(),
            &format!("{OTHER_CONTAINER}:{KEYTAB_IN_CONTAINER}"),
        ])
        .output()
        .expect("container cp");
    assert!(out.status.success(), "cp keytab: {out:?}");
}

#[test]
#[ignore = "requires podman + MIT client containers"]
fn mit_kinit_on_our_realm_then_kvno_in_other_realm_uses_our_cross_realm_tgt() {
    write_conf();
    let e = env("/tmp/cc_cross_a");
    let (code, out) = run(
        &format!("{e} kinit tuser@{REALM}"),
        Some(&format!("{USER_PASSWORD}\n")),
    );
    assert_eq!(code, 0, "kinit: {out}");
    let (code, out) = run(
        &format!("{e} KRB5_TRACE=/dev/stderr kvno HTTP/service.other.realm@{OTHER_REALM}"),
        None,
    );
    assert_eq!(code, 0, "kvno: {out}");
    assert!(
        out.contains(&format!("HTTP/service.other.realm@{OTHER_REALM}: kvno = 1")),
        "{out}"
    );
    let (_, klist) = run(&format!("{e} klist"), None);
    assert!(
        klist.contains(&format!("krbtgt/{OTHER_REALM}@{REALM}")),
        "{klist}"
    );
    assert!(
        klist.contains(&format!("HTTP/service.other.realm@{OTHER_REALM}")),
        "{klist}"
    );
}

#[test]
#[ignore = "requires podman + MIT client containers"]
fn mit_kvno_canonicalize_follows_our_referral_to_the_other_realm() {
    write_mismapped_conf();
    let e = format!("KRB5_CONFIG={CONF_MISMAPPED} KRB5CCNAME=/tmp/cc_cross_ref");
    let (code, out) = run(
        &format!("{e} kinit tuser@{REALM}"),
        Some(&format!("{USER_PASSWORD}\n")),
    );
    assert_eq!(code, 0, "kinit: {out}");
    let (code, out) = run(
        &format!("{e} KRB5_TRACE=/dev/stderr kvno -C -S HTTP service.other.realm"),
        None,
    );
    assert_eq!(code, 0, "kvno -C -S: {out}");
    assert!(out.contains("referrals on"), "{out}");
    let (_, klist) = run(&format!("{e} klist"), None);
    // MIT caches the referred ticket under the requested name and records
    // the canonical server.
    assert!(
        klist.contains(&format!(
            "Ticket server: HTTP/service.other.realm@{OTHER_REALM}"
        )),
        "{klist}"
    );
}

fn ensure_other_user() {
    let (_, _) = run(
        "kadmin.local -q 'delprinc -force otheruser@OTHER.REALM'",
        None,
    );
    let (code, out) = run(
        "kadmin.local -q 'addprinc otheruser@OTHER.REALM'",
        Some(&format!("{OTHER_USER_PASSWORD}\n{OTHER_USER_PASSWORD}\n")),
    );
    assert_eq!(code, 0, "addprinc: {out}");
}

fn other_user_login(cc: &str, conf: &str) -> String {
    write_mismapped_conf();
    ensure_other_user();
    let e = format!("KRB5_CONFIG={conf} KRB5CCNAME={cc}");
    let (code, out) = run(
        &format!("{e} kinit otheruser@{OTHER_REALM}"),
        Some(&format!("{OTHER_USER_PASSWORD}\n")),
    );
    assert_eq!(code, 0, "kinit other: {out}");
    e
}

#[test]
#[ignore = "requires podman + MIT client containers"]
fn our_kdc_accepts_mit_cross_realm_tgt_and_service_ticket_decrypts_with_keytab() {
    let e = other_user_login("/tmp/cc_cross_b", CONF);
    let (code, out) = run(
        &format!("{e} KRB5_TRACE=/dev/stderr kvno HTTP/server.test.realm@{REALM}"),
        None,
    );
    assert_eq!(code, 0, "kvno: {out}");
    assert!(
        out.contains(&format!("HTTP/server.test.realm@{REALM}: kvno = 1")),
        "{out}"
    );

    copy_keytab_in();
    let (code, out) = run(
        &format!("{e} kvno -k {KEYTAB_IN_CONTAINER} HTTP/server.test.realm@{REALM}"),
        None,
    );
    assert_eq!(code, 0, "kvno -k: {out}");
    assert!(out.contains("keytab entry valid"), "{out}");
}

#[test]
#[ignore = "requires podman + MIT client containers"]
fn mit_referral_to_our_realm_is_accepted_by_our_kdc() {
    let e = other_user_login("/tmp/cc_cross_b_ref", CONF_MISMAPPED);
    let (code, out) = run(
        &format!("{e} KRB5_TRACE=/dev/stderr kvno -C -S HTTP server.test.realm"),
        None,
    );
    assert_eq!(code, 0, "kvno -C: {out}");
    let (_, klist) = run(&format!("{e} klist"), None);
    assert!(
        klist.contains(&format!("HTTP/server.test.realm@{REALM}")),
        "{klist}"
    );
}

/// Our client against MIT's OTHER.REALM KDC: the referral TGT MIT issues
/// carries the stored (kadmin `addprinc`) name type, which must not stop the
/// client following it.
#[test]
#[ignore = "requires podman + MIT client containers"]
fn our_client_follows_mit_referral_to_our_kdc() {
    use common::kdc::{kdc_other_addr_str, kdc_send_to};
    use krb5_rs::protocol::{
        AsExchange, AsExchangeConfig, StepResult, TgsExchange, TgsOptions, TgsStepResult,
    };

    live();
    ensure_other_user();
    let ours = format!("127.0.0.1:{PORT}");
    let send = |realm: &str, data: &[u8]| {
        let addr = if realm == REALM {
            ours.clone()
        } else {
            kdc_other_addr_str()
        };
        kdc_send_to(&addr, data).expect("KDC reply")
    };

    let config = AsExchangeConfig::new(PrincipalName::new_principal("otheruser"), OTHER_REALM);
    let mut as_ex = AsExchange::new(config, OTHER_USER_PASSWORD);
    let mut reply = Vec::new();
    while let StepResult::SendToKdc { data, .. } | StepResult::RetryTcp { data, .. } =
        as_ex.step(&reply).expect("AS step")
    {
        reply = send(OTHER_REALM, &data);
    }
    let tgt = as_ex.credential().expect("TGT").clone();

    let mut tgs = TgsExchange::new(tgt, service(), TgsOptions::default());
    let mut reply = Vec::new();
    let mut realms = Vec::new();
    let cred = loop {
        match tgs.step(&reply).expect("TGS step") {
            TgsStepResult::SendToKdc { data, realm } | TgsStepResult::RetryTcp { data, realm } => {
                reply = send(&realm, &data);
                realms.push(realm);
            }
            TgsStepResult::Complete => break tgs.credential().expect("credential").clone(),
        }
    };
    assert_eq!(realms, vec![OTHER_REALM.to_string(), REALM.to_string()]);
    assert_eq!(cred.server, service());
    assert_eq!(cred.crealm, OTHER_REALM);
}
