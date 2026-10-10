#![cfg(all(feature = "kdc", feature = "tokio"))]
//! Live PAC interop with MIT krb5 1.22 (which issues PACs by default).
//!
//! Requires podman + the compose containers. Run with:
//!   cargo test --all-features --test kdc_pac_live -- --ignored --test-threads=1

use std::io::Write;
use std::process::{Command, Stdio};
use std::sync::{Arc, OnceLock};

use krb5_rs::crypto::find_etype;
use krb5_rs::kdc::{serve_tcp, serve_udp, Kdc, KdcConfig, MemoryStore, PrincipalAttributes};
use krb5_rs::keytab::{FileKeytab, Keytab};
use krb5_rs::pac::{
    ticket_pac, verify_ticket_pac, PAC_CLIENT_INFO, PAC_FULL_CHECKSUM, PAC_PRIVSVR_CHECKSUM,
    PAC_SERVER_CHECKSUM, PAC_TICKET_CHECKSUM,
};
use krb5_rs::profile::Profile;
use krb5_rs::protocol::ap::decrypt_ticket;
use krb5_rs::protocol::{
    AsExchange, AsExchangeConfig, StepResult, TgsExchange, TgsOptions, TgsStepResult,
};
use krb5_rs::types::{EncryptionKey, PrincipalName};
use tokio::net::{TcpListener, UdpSocket};

#[path = "common/mod.rs"]
mod common;
use common::kdc::{
    acquire_tgt, container_cli, get_service_ticket, kdc_other_addr_str, kdc_send_to, KDC_CONTAINER,
    TEST_REALM,
};

const OTHER_CONTAINER: &str = "krb5-rs-kdc-other-1";
const OTHER_REALM: &str = "OTHER.REALM";
const OUR_PORT: u16 = 10392;
const CROSS_PORT: u16 = 10393;
const PASSWORD: &str = "pac-live-password";
const HTTP_PASSWORD: &str = "httpsecret";
const TRUST_PASSWORD: &str = "crosstrust";

fn host() -> String {
    std::env::var("KDC_LIVE_HOST").unwrap_or_else(|_| "192.168.127.254".into())
}

fn tgs(instance: &str) -> PrincipalName {
    PrincipalName::new_srv_inst("krbtgt", instance)
}

fn http() -> PrincipalName {
    PrincipalName::new_srv_hst("HTTP", "server.test.realm")
}

fn s2k_18(password: &str, salt: &str) -> EncryptionKey {
    let key = find_etype(18)
        .expect("etype")
        .string_to_key(password.as_bytes(), salt.as_bytes(), None)
        .expect("s2k");
    EncryptionKey::new(18, key.to_vec())
}

/// Our TEST.REALM KDC on `OUR_PORT` (service key = MIT's `httpsecret` key)
/// and a second one with the OTHER.REALM trust on `CROSS_PORT`.
fn start_servers() {
    static STARTED: OnceLock<()> = OnceLock::new();
    STARTED.get_or_init(|| {
        let build = |with_trust: bool| {
            let mut store = MemoryStore::new();
            let none = PrincipalAttributes::empty();
            store
                .add_random_key(tgs(TEST_REALM), TEST_REALM, 1, &[18, 17], none)
                .expect("krbtgt");
            store
                .add_with_password(
                    PrincipalName::new_principal("pacuser"),
                    TEST_REALM,
                    PASSWORD,
                    1,
                    &[18, 17],
                    PrincipalAttributes::REQUIRES_PRE_AUTH,
                )
                .expect("user");
            store
                .add_with_password(http(), TEST_REALM, HTTP_PASSWORD, 1, &[18, 17], none)
                .expect("service");
            let mut config = KdcConfig::new(TEST_REALM);
            if with_trust {
                store
                    .add_with_password(
                        tgs(OTHER_REALM),
                        TEST_REALM,
                        TRUST_PASSWORD,
                        1,
                        &[18, 17],
                        none,
                    )
                    .expect("outgoing trust");
                store
                    .add_with_password(
                        tgs(TEST_REALM),
                        OTHER_REALM,
                        TRUST_PASSWORD,
                        1,
                        &[18, 17],
                        none,
                    )
                    .expect("incoming trust");
                config.realm_profile = Some(
                    Profile::parse("[domain_realm]\n .other.realm = OTHER.REALM\n").expect("conf"),
                );
            }
            Arc::new(Kdc::new(config, store))
        };
        let servers = [(build(false), OUR_PORT), (build(true), CROSS_PORT)];
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().expect("runtime");
            rt.block_on(async move {
                for (kdc, port) in servers {
                    let addr = format!("0.0.0.0:{port}");
                    let udp = UdpSocket::bind(&addr).await.expect("bind udp");
                    let tcp = TcpListener::bind(&addr).await.expect("bind tcp");
                    tokio::spawn(serve_udp(Arc::clone(&kdc), udp));
                    tokio::spawn(serve_tcp(kdc, tcp));
                }
                tx.send(()).expect("ready");
                std::future::pending::<()>().await;
            });
        });
        rx.recv().expect("servers started");
    });
}

fn run_in(container: &str, cmd: &str, stdin: Option<&str>) -> (i32, String) {
    let mut child = Command::new(container_cli())
        .args(["exec", "-i", container, "bash", "-c", cmd])
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

#[test]
#[ignore = "requires podman + MIT KDC container"]
fn our_library_parses_and_verifies_pac_in_mit_issued_service_ticket() {
    let tgt = acquire_tgt("testuser", "testpassword", TEST_REALM).expect("TGT");
    let cred = get_service_ticket(&tgt, http()).expect("service ticket");
    let key = s2k_18(HTTP_PASSWORD, "TEST.REALMHTTPserver.test.realm");
    let part = decrypt_ticket(&key, &cred.ticket).expect("decrypt with the service key");

    let pac = ticket_pac(&part)
        .expect("parse MIT PAC")
        .expect("MIT 1.22 issues a PAC by default");
    let types = pac.types();
    // krb5 1.22 service-ticket PACs carry client info, ticket, server,
    // privsvr and full checksums (pac_sign.c sign_pac / add_ticket_signature).
    for ty in [
        PAC_CLIENT_INFO,
        PAC_SERVER_CHECKSUM,
        PAC_PRIVSVR_CHECKSUM,
        PAC_TICKET_CHECKSUM,
        PAC_FULL_CHECKSUM,
    ] {
        assert!(types.contains(&ty), "missing buffer {ty} in {types:?}");
    }
    let info = pac.client_info().expect("client info");
    assert_eq!(info.name, "testuser");
    assert_eq!(info.authtime, part.authtime.timestamp());

    // The server checksum verifies with the service key; the KDC key is not
    // known to the test (random krbtgt), so the privsvr, ticket and full
    // checksums cannot be checked here.
    let user = PrincipalName::new_principal("testuser");
    pac.verify(
        part.authtime.timestamp(),
        Some((&user, TEST_REALM)),
        Some(&key),
        None,
    )
    .expect("MIT's server checksum verifies");
    verify_ticket_pac(&part, &http(), &key, None)
        .expect("verify as a service would")
        .expect("PAC present");
    assert!(verify_ticket_pac(&part, &http(), &s2k_18("wrong", "salt"), None).is_err());
}

#[test]
#[ignore = "requires podman + MIT KDC container"]
fn mit_decodes_and_decrypts_service_ticket_with_pac_from_our_kdc() {
    start_servers();
    let conf = "/tmp/pac-live-krb5.conf";
    let krb5 = format!(
        "[libdefaults]\n default_realm = {TEST_REALM}\n dns_lookup_kdc = false\n \
         dns_lookup_realm = false\n[realms]\n {TEST_REALM} = {{\n  kdc = {}:{OUR_PORT}\n }}\n",
        host()
    );
    let (code, out) = run_in(KDC_CONTAINER, &format!("cat > {conf}"), Some(&krb5));
    assert_eq!(code, 0, "write krb5.conf: {out}");
    let env = format!("KRB5_CONFIG={conf} KRB5CCNAME=/tmp/cc_pac_live");
    let (code, out) = run_in(
        KDC_CONTAINER,
        &format!("{env} kinit pacuser@{TEST_REALM}"),
        Some(&format!("{PASSWORD}\n")),
    );
    assert_eq!(code, 0, "kinit: {out}");
    // /etc/krb5.keytab holds MIT's HTTP/server.test.realm key, the same
    // `httpsecret` key our KDC serves.
    let (code, out) = run_in(
        KDC_CONTAINER,
        &format!("{env} kvno -k /etc/krb5.keytab HTTP/server.test.realm@{TEST_REALM}"),
        None,
    );
    assert_eq!(code, 0, "kvno -k: {out}");
    assert!(out.contains("keytab entry valid"), "{out}");
}

#[test]
#[ignore = "requires podman + both MIT KDC containers"]
fn mit_other_realm_accepts_our_pac_and_issues_a_pac_we_can_verify() {
    start_servers();
    // Export the OTHER.REALM service key without changing it.
    let (code, out) = run_in(
        OTHER_CONTAINER,
        "rm -f /tmp/svc-pac.keytab; kadmin.local -q 'ktadd -norandkey -k /tmp/svc-pac.keytab \
         HTTP/service.other.realm@OTHER.REALM'",
        None,
    );
    assert_eq!(code, 0, "ktadd: {out}");
    let local = common::kdc::tmp("svc-pac.keytab");
    let _ = std::fs::remove_file(&local);
    let cp = Command::new(container_cli())
        .args([
            "cp",
            &format!("{OTHER_CONTAINER}:/tmp/svc-pac.keytab"),
            &local.to_string_lossy(),
        ])
        .output()
        .expect("cp");
    assert!(cp.status.success(), "cp out: {cp:?}");
    let service = PrincipalName::new_srv_hst("HTTP", "service.other.realm");
    let svc_key = FileKeytab::new(&local)
        .get_entry(&service, OTHER_REALM, None, Some(18))
        .expect("service key in keytab")
        .key;

    // Our client: AS against our KDC, then a referral to MIT's OTHER.REALM.
    let ours = format!("127.0.0.1:{CROSS_PORT}");
    let send = |realm: &str, data: &[u8]| {
        let addr = if realm == TEST_REALM {
            ours.clone()
        } else {
            kdc_other_addr_str()
        };
        kdc_send_to(&addr, data).expect("KDC reply")
    };
    let config = AsExchangeConfig::new(PrincipalName::new_principal("pacuser"), TEST_REALM);
    let mut as_ex = AsExchange::new(config, PASSWORD);
    let mut reply = Vec::new();
    while let StepResult::SendToKdc { data, .. } | StepResult::RetryTcp { data, .. } =
        as_ex.step(&reply).expect("AS step")
    {
        reply = send(TEST_REALM, &data);
    }
    let tgt = as_ex.credential().expect("TGT").clone();
    let mut ex = TgsExchange::new(tgt, service.clone(), TgsOptions::default());
    let mut reply = Vec::new();
    let cred = loop {
        match ex.step(&reply).expect("TGS step") {
            TgsStepResult::SendToKdc { data, realm } | TgsStepResult::RetryTcp { data, realm } => {
                reply = send(&realm, &data);
            }
            TgsStepResult::Complete => break ex.credential().expect("credential").clone(),
        }
    };

    let part = decrypt_ticket(&svc_key, &cred.ticket).expect("decrypt with the OTHER.REALM key");
    let pac = ticket_pac(&part)
        .expect("parse")
        .expect("MIT issued a PAC after verifying ours");
    let user = PrincipalName::new_principal("pacuser");
    pac.verify(
        part.authtime.timestamp(),
        Some((&user, TEST_REALM)),
        Some(&svc_key),
        None,
    )
    .expect("server checksum of MIT's PAC verifies; client info was carried over");
    verify_ticket_pac(&part, &service, &svc_key, None)
        .expect("service-side verification")
        .expect("PAC");
}
