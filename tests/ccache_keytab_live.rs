//! Live MIT KDC interop for ccache and keytab (P6a).
//!
//! Requires the podman KDC (krb5-rs-kdc-1, ${KDC_HOST}:10188) running via
//! `podman compose -f docker-compose.test.yml up -d`.
//!
//! Run with:
//!   cargo test --all-features --test ccache_keytab_live -- --ignored --nocapture

use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::Command;
use std::time::Duration;

use krb5_rs::ccache::*;
use krb5_rs::crypto::find_etype;
use krb5_rs::keytab::*;
use krb5_rs::protocol::ap::{ApReqOptions, AuthContext};
use krb5_rs::protocol::{
    AsExchange, AsExchangeConfig, Credential, StepResult, TgsExchange, TgsOptions, TgsStepResult,
};
use krb5_rs::types::*;
use krb5_rs::Krb5Error;
use rasn::types::GeneralString;

const KDC: &str = "krb5-rs-kdc-1";
const REALM: &str = "TEST.REALM";
const MAX_KDC_RESPONSE_SIZE: usize = 1024 * 1024;

fn kdc_addr() -> String {
    format!(
        "{}:10188",
        std::env::var("KDC_HOST").unwrap_or_else(|_| "127.0.0.1".into())
    )
}

fn pod(args: &[&str]) -> std::process::Output {
    Command::new("podman").args(args).output().expect("podman")
}

fn exec_kdc(cmd: &str) -> String {
    let out = pod(&["exec", KDC, "bash", "-c", cmd]);
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

fn tmp(name: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!("krb5rs_live_{}_{}", std::process::id(), name))
}

fn cp_out(cpath: &str, name: &str) -> std::path::PathBuf {
    let local = tmp(name);
    let _ = std::fs::remove_file(&local);
    let out = pod(&["cp", &format!("{KDC}:{cpath}"), &local.to_string_lossy()]);
    assert!(out.status.success(), "podman cp out failed");
    local
}

fn cp_in(local: &std::path::Path, cpath: &str) {
    let out = pod(&["cp", &local.to_string_lossy(), &format!("{KDC}:{cpath}")]);
    assert!(out.status.success(), "podman cp in failed");
}

fn gs(b: &[u8]) -> GeneralString {
    GeneralString::from_bytes(b).expect("general string")
}

fn p2(a: &str, b: &str) -> PrincipalName {
    PrincipalName {
        name_type: 2,
        name_string: vec![gs(a.as_bytes()), gs(b.as_bytes())],
    }
}

fn kdc_send(data: &[u8]) -> std::io::Result<Vec<u8>> {
    let mut stream = TcpStream::connect(kdc_addr())?;
    stream.set_nodelay(true)?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    let mut msg = Vec::with_capacity(4 + data.len());
    msg.extend_from_slice(&(data.len() as u32).to_be_bytes());
    msg.extend_from_slice(data);
    stream.write_all(&msg)?;
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let resp_len = u32::from_be_bytes(len_buf) as usize;
    assert!(resp_len <= MAX_KDC_RESPONSE_SIZE);
    let mut resp = vec![0u8; resp_len];
    stream.read_exact(&mut resp)?;
    Ok(resp)
}

fn acquire_tgt(principal: &str, password: &str) -> Result<Credential, Krb5Error> {
    let config = AsExchangeConfig::new(PrincipalName::new_principal(principal), REALM);
    let mut exchange = AsExchange::new(config, password);
    let mut kdc_reply = Vec::new();
    for _ in 0..32 {
        match exchange.step(&kdc_reply)? {
            StepResult::SendToKdc { data, .. } | StepResult::RetryTcp { data, .. } => {
                kdc_reply = kdc_send(&data).map_err(Krb5Error::Transport)?;
            }
            StepResult::Complete => return exchange.credential().cloned(),
        }
    }
    Err(Krb5Error::ReplyValidation("AS exchange did not complete"))
}

fn get_service_ticket(tgt: &Credential, target: PrincipalName) -> Result<Credential, Krb5Error> {
    let mut exchange = TgsExchange::new(tgt.clone(), target, TgsOptions::default());
    let mut kdc_reply = Vec::new();
    for _ in 0..32 {
        match exchange.step(&kdc_reply)? {
            TgsStepResult::SendToKdc { data, .. } | TgsStepResult::RetryTcp { data, .. } => {
                kdc_reply = kdc_send(&data).map_err(Krb5Error::Transport)?;
            }
            TgsStepResult::Complete => return exchange.credential().cloned(),
        }
    }
    Err(Krb5Error::ReplyValidation("TGS exchange did not complete"))
}

fn s2k_18(password: &str, salt: &str) -> Vec<u8> {
    find_etype(18)
        .expect("etype")
        .string_to_key(password.as_bytes(), salt.as_bytes(), None)
        .expect("s2k")
        .to_vec()
}

/// Test 27: read an MIT-written ccache; use the TGT for a TGS exchange.
#[test]
#[ignore = "requires KDC: podman compose -f docker-compose.test.yml up -d"]
fn read_mit_ccache_and_tgs() {
    exec_kdc("rm -f /tmp/rs_cc");
    let r = exec_kdc("echo testpassword | kinit -c /tmp/rs_cc testuser; echo rc=$?");
    assert!(r.contains("rc=0"), "kinit failed: {r}");
    let local = cp_out("/tmp/rs_cc", "rs_cc_in");

    let cc = FileCcache::new(&local);
    let (p, realm) = cc.principal().expect("principal");
    assert_eq!(p.name_string[0].as_bytes(), b"testuser");
    assert_eq!(realm, REALM);

    let krbtgt = p2("krbtgt", REALM);
    let creds = cc.creds().expect("creds");
    let tgt = creds
        .iter()
        .find(|c| c.server.name_string == krbtgt.name_string && c.srealm == REALM)
        .expect("krbtgt cred");
    assert!(tgt.ticket_flags & TicketFlags::INITIAL.bits() != 0);

    // MIT stores the winning preauth type (2 = enc-timestamp) in the cache
    // config (get_in_tkt.c pa_type record).
    assert_eq!(
        cc.get_config(Some((&krbtgt, REALM)), "pa_type")
            .expect("get_config"),
        Some(b"2".to_vec())
    );

    let cred = Credential::try_from(tgt).expect("to credential");
    let svc = p2("HTTP", "server.test.realm");
    get_service_ticket(&cred, svc).expect("tgs exchange");
}

/// Test 28: Rust-written ccache → MIT klist reads it → MIT kvno appends.
#[test]
#[ignore = "requires KDC: podman compose -f docker-compose.test.yml up -d"]
fn write_ccache_mit_klist_kvno() {
    let cred = acquire_tgt("testuser", "testpassword").expect("as exchange");

    let path = tmp("rs_cc_out");
    let _ = std::fs::remove_file(&path);
    let mut cc = FileCcache::new(&path);
    cc.initialize(&cred.client, &cred.crealm).expect("init");
    cc.store(&CcCredential::from(&cred)).expect("store");

    exec_kdc("rm -f /tmp/rs_out");
    cp_in(&path, "/tmp/rs_out");

    let list = exec_kdc("klist -c /tmp/rs_out; echo rc=$?");
    assert!(list.contains("rc=0"), "klist failed: {list}");
    assert!(
        list.contains("Default principal: testuser@TEST.REALM"),
        "{list}"
    );
    assert!(list.contains("krbtgt/TEST.REALM@TEST.REALM"), "{list}");

    let kvno_out = exec_kdc("kvno -c /tmp/rs_out HTTP/server.test.realm; echo rc=$?");
    assert!(kvno_out.contains("rc=0"), "kvno failed: {kvno_out}");

    let back = cp_out("/tmp/rs_out", "rs_cc_back");
    let creds = FileCcache::new(&back).creds().expect("creds");
    assert_eq!(creds.len(), 2);
    assert!(creds.iter().any(|c| c
        .server
        .name_string
        .first()
        .is_some_and(|c| c.as_bytes() == b"HTTP")
        && c.server
            .name_string
            .get(1)
            .is_some_and(|c| c.as_bytes() == b"server.test.realm")));
}

/// Test 29: read /etc/krb5.keytab; use it as KeySource for a live AP-REQ.
#[test]
#[ignore = "requires KDC: podman compose -f docker-compose.test.yml up -d"]
fn read_mit_keytab_and_ap_req() {
    let local = cp_out("/etc/krb5.keytab", "krb5.keytab");
    let kt = FileKeytab::new(&local);
    let (p, realm) = (p2("HTTP", "server.test.realm"), REALM.to_string());
    let e = kt
        .get_entry(&p, &realm, None, Some(18))
        .expect("keytab entry");
    assert_eq!(e.kvno, 1);
    let expect = s2k_18("httpsecret", "TEST.REALMHTTPserver.test.realm");
    assert_eq!(e.key.key_bytes(), &expect[..]);

    let tgt = acquire_tgt("testuser", "testpassword").expect("as");
    let svc = get_service_ticket(&tgt, p.clone()).expect("tgs");
    let mut ctx = AuthContext::new();
    let req = ctx
        .mk_req(&ApReqOptions::default(), None, &svc)
        .expect("mk_req");
    let mut srv = AuthContext::new();
    srv.rd_req(&req, Some(&p), &kt).expect("rd_req");
}

/// Test 30: Rust-written keytab → MIT klist -k -K -t reads it.
#[test]
#[ignore = "requires KDC: podman compose -f docker-compose.test.yml up -d"]
fn write_keytab_mit_klist() {
    let path = tmp("rs.kt");
    let _ = std::fs::remove_file(&path);
    let key = s2k_18("httpsecret", "TEST.REALMHTTPserver.test.realm");
    let mut kt = FileKeytab::new(&path);
    kt.add_entry(&KeytabEntry {
        principal: p2("HTTP", "server.test.realm"),
        realm: REALM.to_string(),
        timestamp: 1_700_000_000,
        kvno: 1,
        key: EncryptionKey::new(18, key.clone()),
    })
    .expect("add");

    exec_kdc("rm -f /tmp/rs.kt");
    cp_in(&path, "/tmp/rs.kt");
    let list = exec_kdc("klist -k -K -t /tmp/rs.kt; echo rc=$?");
    assert!(list.contains("rc=0"), "klist -k failed: {list}");
    assert!(list.contains("HTTP/server.test.realm@TEST.REALM"), "{list}");
    let hex = key.iter().map(|b| format!("{b:02x}")).collect::<String>();
    assert!(list.contains(&format!("0x{hex}")), "{list}");
}
