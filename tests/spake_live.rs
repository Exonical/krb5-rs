#![cfg(all(feature = "kdc", feature = "tokio"))]
//! Live SPAKE interop with MIT krb5 1.22.2:
//! - our client against the MIT KDCs with SPAKE enabled (tests/kdc/setup.sh:
//!   10191 waits for the support message, 10192 sends an optimistic P-256
//!   challenge);
//! - MIT `kinit` (in `krb5-rs-kdc-1`) against our KDC with SPAKE enabled,
//!   in-process on the host (10393; 10398 with an optimistic challenge).
//!
//! Run with:
//!   cargo test --all-features --test spake_live -- --ignored --test-threads=1

use std::io::Write;
use std::process::{Command, Stdio};
use std::sync::{Arc, OnceLock};

use krb5_rs::kdc::{serve_tcp, serve_udp, Kdc, KdcConfig, MemoryStore, PrincipalAttributes};
use krb5_rs::protocol::{AsExchange, AsExchangeConfig, StepResult};
use krb5_rs::spake::{Group, PaSpake};
use krb5_rs::types::{KrbErrorMsg, PaData, PrincipalName, TicketFlags};
use tokio::net::{TcpListener, UdpSocket};

#[path = "common/mod.rs"]
mod common;
use common::kdc::{kdc_host, kdc_send_to, KDC_CONTAINER};

const REALM: &str = "SPAKE.REALM";
const PORT: u16 = 10393;
const PORT_OPTIMISTIC: u16 = 10398;
const PASSWORD: &str = "spake-live-password";

fn host() -> String {
    std::env::var("KDC_LIVE_HOST").unwrap_or_else(|_| "192.168.127.254".into())
}

/// Drive our client against `addr`, returning every KDC reply.
fn our_kinit(addr: &str, groups: &[Group]) -> Vec<Vec<u8>> {
    let password =
        std::env::var("KDC_TESTUSER1_PASSWORD").unwrap_or_else(|_| "testpassword".into());
    let mut config = AsExchangeConfig::new(PrincipalName::new_principal("testuser"), "TEST.REALM");
    config.spake_groups = groups.to_vec();
    let mut exchange = AsExchange::new(config, password);
    let mut replies = Vec::new();
    let mut input = Vec::new();
    for _ in 0..16 {
        match exchange.step(&input).expect("AS step") {
            StepResult::SendToKdc { data, .. } | StepResult::RetryTcp { data, .. } => {
                input = kdc_send_to(addr, &data).expect("send");
                replies.push(input.clone());
            }
            StepResult::Complete => {
                let cred = exchange.credential().expect("credential");
                assert!(cred.flags.contains(TicketFlags::PRE_AUTHENT));
                return replies;
            }
        }
    }
    panic!("AS exchange did not complete");
}

fn method_data(reply: &[u8]) -> Vec<PaData> {
    let err: KrbErrorMsg = rasn::der::decode(reply).expect("KRB-ERROR");
    rasn::der::decode(err.e_data.as_ref().expect("e-data").as_ref()).expect("METHOD-DATA")
}

fn spake(md: &[PaData]) -> &PaData {
    md.iter().find(|p| p.padata_type == 151).expect("PA-SPAKE")
}

fn challenge_group(pa: &PaData) -> i32 {
    match rasn::der::decode::<PaSpake>(pa.padata_value.as_ref()).expect("PA-SPAKE") {
        PaSpake::Challenge(c) => c.group,
        other => panic!("not a challenge: {other:?}"),
    }
}

#[test]
#[ignore = "requires the MIT KDC container"]
fn our_client_against_mit_spake_kdc_every_group() {
    let addr = format!("{}:10191", kdc_host());
    for group in Group::ALL {
        let replies = our_kinit(&addr, &[group]);
        // PREAUTH_REQUIRED with an empty PA-SPAKE, MORE_PREAUTH with MIT's
        // challenge for our group, then the AS-REP.
        assert_eq!(replies.len(), 3, "{group:?}");
        assert!(spake(&method_data(&replies[0])).padata_value.is_empty());
        let more = method_data(&replies[1]);
        assert_eq!(challenge_group(spake(&more)), group.id());
        let cookie = more.iter().find(|p| p.padata_type == 133).expect("cookie");
        assert!(cookie.padata_value.as_ref().starts_with(b"MIT1"));
    }
}

#[test]
#[ignore = "requires the MIT KDC container"]
fn our_client_answers_mit_optimistic_challenge() {
    let addr = format!("{}:10192", kdc_host());
    let replies = our_kinit(&addr, &[Group::P256]);
    assert_eq!(replies.len(), 2);
    assert_eq!(challenge_group(spake(&method_data(&replies[0]))), 2);
    // Not permitted by the client: it sends support and MIT re-challenges.
    let replies = our_kinit(&addr, &[Group::Edwards25519]);
    assert_eq!(replies.len(), 3);
    assert_eq!(challenge_group(spake(&method_data(&replies[1]))), 1);
}

fn live() {
    static LIVE: OnceLock<()> = OnceLock::new();
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
                PrincipalName::new_principal("sam"),
                REALM,
                PASSWORD,
                1,
                &[18, 17],
                PrincipalAttributes::REQUIRES_PRE_AUTH,
            )
            .expect("sam");
        for (svc, require) in [("strong", "otp strong"), ("hardware", "hardware")] {
            let name = PrincipalName::new_srv_inst("host", svc);
            store
                .add_random_key(
                    name.clone(),
                    REALM,
                    1,
                    &[18, 17],
                    PrincipalAttributes::empty(),
                )
                .expect("service");
            let mut entry = store.get(&name, REALM).expect("service entry");
            entry.require_auth = Some(require.into());
            store.insert(entry);
        }
        let mut second = MemoryStore::new();
        for name in [
            PrincipalName::new_srv_inst("krbtgt", REALM),
            PrincipalName::new_principal("sam"),
        ] {
            second.insert(store.get(&name, REALM).expect("entry"));
        }
        let mut config = KdcConfig::new(REALM);
        config.spake_groups = Group::ALL.to_vec();
        config.spake_indicators = vec!["strong".into()];
        let mut optimistic = config.clone();
        optimistic.spake_challenge = Some(Group::Edwards25519);
        let kdcs = [
            (Arc::new(Kdc::new(config, store)), PORT),
            (Arc::new(Kdc::new(optimistic, second)), PORT_OPTIMISTIC),
        ];
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().expect("runtime");
            rt.block_on(async move {
                for (kdc, port) in kdcs {
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
    });
}

fn run(cmd: &str, stdin: Option<&str>) -> (i32, String) {
    let mut child = Command::new(common::kdc::container_cli())
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

/// MIT `kinit sam` against our KDC on `port`, traced; `groups` is the
/// client's `spake_preauth_groups`.
fn mit_kinit(port: u16, groups: &str, password: &str) -> (i32, String) {
    live();
    let conf = format!("/tmp/spake-krb5-{port}.conf");
    let text = format!(
        "[libdefaults]\n default_realm = {REALM}\n dns_lookup_kdc = false\n \
         dns_lookup_realm = false\n spake_preauth_groups = {groups}\n[realms]\n {REALM} = {{\n  \
         kdc = {}:{port}\n }}\n",
        host()
    );
    let (code, out) = run(&format!("cat > {conf}"), Some(&text));
    assert_eq!(code, 0, "write krb5.conf: {out}");
    run(
        &format!(
            "KRB5_CONFIG={conf} KRB5CCNAME=/tmp/spake_cc_{port} KRB5_TRACE=/dev/stderr kinit sam"
        ),
        Some(&format!("{password}\n")),
    )
}

#[test]
#[ignore = "requires the MIT client container"]
fn mit_kinit_spake_against_our_kdc_every_group() {
    for group in Group::ALL {
        let (code, out) = mit_kinit(PORT, group.name(), PASSWORD);
        assert_eq!(code, 0, "{group:?}: {out}");
        assert!(out.contains("Sending SPAKE support message"), "{out}");
        assert!(
            out.contains(&format!(
                "SPAKE challenge received with group {}",
                group.id()
            )),
            "{out}"
        );
        assert!(out.contains("Sending SPAKE response"), "{out}");
    }
}

#[test]
#[ignore = "requires the MIT client container"]
fn mit_kinit_answers_our_optimistic_challenge() {
    let (code, out) = mit_kinit(PORT_OPTIMISTIC, "edwards25519", PASSWORD);
    assert_eq!(code, 0, "{out}");
    assert!(
        out.contains("SPAKE challenge received with group 1"),
        "{out}"
    );
    assert!(!out.contains("Sending SPAKE support message"), "{out}");
    // A client without edwards25519 sends support and gets a P-256 challenge.
    let (code, out) = mit_kinit(PORT_OPTIMISTIC, "P-256", PASSWORD);
    assert_eq!(code, 0, "{out}");
    assert!(
        out.contains("SPAKE challenge received with group 2"),
        "{out}"
    );
}

#[test]
#[ignore = "requires the MIT client container"]
fn mit_kinit_spake_wrong_password_fails() {
    let (code, out) = mit_kinit(PORT, "edwards25519", "not-the-password");
    assert_ne!(code, 0, "{out}");
    assert!(out.contains("Sending SPAKE response"), "{out}");
    assert!(out.contains("Preauthentication failed"), "{out}");
}

/// MIT `kvno` for `service` with the cache `mit_kinit` left for `port`.
fn mit_kvno(port: u16, service: &str) -> (i32, String) {
    run(
        &format!(
            "KRB5_CONFIG=/tmp/spake-krb5-{port}.conf KRB5CCNAME=/tmp/spake_cc_{port} kvno {service}"
        ),
        None,
    )
}

#[test]
#[ignore = "requires the MIT client container"]
fn mit_kvno_needs_our_spake_indicator() {
    let (code, out) = mit_kinit(PORT, "edwards25519", PASSWORD);
    assert_eq!(code, 0, "{out}");
    // The SPAKE indicator rides in the TGT's CAMMAC to the TGS request.
    let (code, out) = mit_kvno(PORT, "host/strong");
    assert_eq!(code, 0, "{out}");
    let (code, out) = mit_kvno(PORT, "host/hardware");
    assert_ne!(code, 0, "{out}");
    assert!(out.contains("KDC policy rejects request"), "{out}");
}
