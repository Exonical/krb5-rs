#![cfg(all(feature = "kdc", feature = "test-pki", feature = "tokio"))]
//! Live PKINIT interop with MIT krb5 1.22.2 (tests/kdc/pki holds the test
//! certificates; see its README).
//!
//! * MIT `kinit -X X509_user_identity=...` in `krb5-rs-kdc-1` against OUR KDC
//!   (realm PKI.REALM on the host).
//! * OUR client against MIT's TEST.REALM KDC (port 10188; 10190 is a second
//!   MIT KDC process requiring freshness tokens, see tests/kdc/setup.sh).
//!
//! Requires podman + the compose container. Run with:
//!   cargo test --all-features --test kdc_pkinit_live -- --ignored --test-threads=1

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::{Arc, OnceLock};

use krb5_rs::kdc::{serve_tcp, serve_udp, Kdc, KdcConfig, MemoryStore, PrincipalAttributes};
use krb5_rs::pkinit::client::ClientConfig;
use krb5_rs::pkinit::cms::Identity;
use krb5_rs::pkinit::server::ServerConfig;
use krb5_rs::pkinit::x509::TrustStore;
use krb5_rs::pkinit::Group;
use krb5_rs::protocol::fast::FastMode;
use krb5_rs::protocol::{AsExchange, AsExchangeConfig, Credential, StepResult};
use krb5_rs::types::{KrbErrorMsg, PrincipalName};
use krb5_rs::Krb5Error;
use tokio::net::{TcpListener, UdpSocket};

#[path = "common/mod.rs"]
mod common;
use common::kdc::{container_cli, kdc_host, kdc_send_to, KDC_CONTAINER};

const PKI_REALM: &str = "PKI.REALM";
const PORT: u16 = 10395;
const PORT_FRESH: u16 = 10396;
const MIT_PORT: u16 = 10188;
const MIT_FRESH_PORT: u16 = 10190;
const PW: &str = "pkinit-user-password";
const CONF: &str = "/tmp/pkinit-krb5.conf";

fn pki_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/kdc/pki")
}

fn host() -> String {
    std::env::var("KDC_LIVE_HOST").unwrap_or_else(|_| "192.168.127.254".into())
}

fn name(n: &str) -> PrincipalName {
    PrincipalName::new_principal(n)
}

fn anon() -> PrincipalName {
    let mut n = PrincipalName::new_srv_inst("WELLKNOWN", "ANONYMOUS");
    n.name_type = 11;
    n
}

fn pki_spec(cert: &str, key: &str) -> String {
    format!(
        "FILE:{0}/{cert}.pem,{0}/{key}.pem",
        pki_dir().to_string_lossy()
    )
}

fn anchors(ca: &str) -> TrustStore {
    let mut store = TrustStore::default();
    store
        .load(
            &format!("FILE:{}/{ca}.pem", pki_dir().to_string_lossy()),
            true,
        )
        .expect("anchors");
    store
}

fn our_kdc(require_freshness: bool) -> Kdc<MemoryStore> {
    let mut store = MemoryStore::new();
    store
        .add_random_key(
            PrincipalName::new_srv_inst("krbtgt", PKI_REALM),
            PKI_REALM,
            1,
            &[18, 17],
            PrincipalAttributes::empty(),
        )
        .expect("krbtgt");
    store
        .add_random_key(
            anon(),
            PKI_REALM,
            1,
            &[18, 17],
            PrincipalAttributes::empty(),
        )
        .expect("anonymous");
    for user in ["pkiuser", "armoruser"] {
        store
            .add_with_password(
                name(user),
                PKI_REALM,
                PW,
                1,
                &[18, 17],
                PrincipalAttributes::REQUIRES_PRE_AUTH,
            )
            .expect("user");
    }
    let identity =
        Identity::from_spec(&pki_spec("kdc-pki-realm", "kdc-key")).expect("KDC identity");
    let mut server = ServerConfig::new(identity, anchors("ca"));
    server.require_freshness = require_freshness;
    let mut config = KdcConfig::new(PKI_REALM);
    config.max_renewable_life = std::time::Duration::from_secs(7 * 24 * 3600);
    config.pkinit = Some(Arc::new(server));
    Kdc::new(config, store)
}

fn serve() {
    static STARTED: OnceLock<()> = OnceLock::new();
    STARTED.get_or_init(|| {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().expect("runtime");
            rt.block_on(async move {
                for (port, fresh) in [(PORT, false), (PORT_FRESH, true)] {
                    let kdc = Arc::new(our_kdc(fresh));
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

/// Write the MIT client krb5.conf for PKI.REALM served by us on `port`.
fn mit_conf(port: u16, anchors: &str, realm_extra: &str) -> String {
    serve();
    let conf = format!(
        "[libdefaults]\n default_realm = {PKI_REALM}\n dns_lookup_kdc = false\n \
         dns_lookup_realm = false\n[realms]\n {PKI_REALM} = {{\n  kdc = {}:{port}\n  \
         pkinit_anchors = FILE:/pki/{anchors}.pem\n{realm_extra}\n }}\n",
        host()
    );
    let (code, out) = run(&format!("cat > {CONF}"), Some(&conf));
    assert_eq!(code, 0, "write krb5.conf: {out}");
    let (code, out) = run(
        &format!("timeout 5 bash -c 'echo > /dev/tcp/{}/{port}'", host()),
        None,
    );
    assert_eq!(
        code,
        0,
        "container cannot reach {}:{port} ({out}); a host firewall rule may be required",
        host()
    );
    format!("KRB5_CONFIG={CONF}")
}

fn x509(cert: &str, key: &str) -> String {
    format!("-X X509_user_identity=FILE:/pki/{cert}.pem,/pki/{key}.pem")
}

fn kinit_pkinit(
    env: &str,
    cc: &str,
    cert: &str,
    key: &str,
    user: &str,
    armor: &str,
) -> (i32, String) {
    run(
        &format!(
            "{env} KRB5CCNAME={cc} KRB5_TRACE=/dev/stderr kinit {armor} {} {user}@{PKI_REALM} \
             < /dev/null",
            x509(cert, key)
        ),
        None,
    )
}

// ------------------------------------------------- MIT client -> our KDC

fn assert_pkinit_login(out: &str, cc: &str, env: &str) {
    assert!(out.contains("PKINIT client verified DH reply"), "{out}");
    let (_, klist) = run(&format!("{env} KRB5CCNAME={cc} klist"), None);
    assert!(
        klist.contains(&format!("krbtgt/{PKI_REALM}@{PKI_REALM}")),
        "{klist}"
    );
}

#[test]
#[ignore = "requires podman + MIT client container"]
fn mit_kinit_rsa_certificate_logs_in_to_our_kdc_with_dh() {
    let env = mit_conf(PORT, "ca", "");
    let (code, out) = kinit_pkinit(
        &env,
        "/tmp/cc_pk_rsa",
        "pkiuser-rsa",
        "client-rsa-key",
        "pkiuser",
        "",
    );
    assert_eq!(code, 0, "kinit: {out}");
    assert!(out.contains("2048-bit DH key exchange group"), "{out}");
    assert_pkinit_login(&out, "/tmp/cc_pk_rsa", &env);
}

#[test]
#[ignore = "requires podman + MIT client container"]
fn mit_kinit_ec_certificate_with_ecdh_logs_in_to_our_kdc() {
    let env = mit_conf(PORT, "ca", "  pkinit_dh_min_bits = P-256");
    let (code, out) = kinit_pkinit(
        &env,
        "/tmp/cc_pk_ec",
        "pkiuser-ec",
        "client-ec-key",
        "pkiuser",
        "",
    );
    assert_eq!(code, 0, "kinit: {out}");
    assert!(out.contains("P-256 key exchange group"), "{out}");
    assert_pkinit_login(&out, "/tmp/cc_pk_ec", &env);
}

#[test]
#[ignore = "requires podman + MIT client container"]
fn mit_kinit_fast_armored_pkinit_logs_in_to_our_kdc() {
    let env = mit_conf(PORT, "ca", "");
    let (code, out) = run(
        &format!("{env} KRB5CCNAME=/tmp/cc_pk_armor kinit armoruser@{PKI_REALM}"),
        Some(&format!("{PW}\n")),
    );
    assert_eq!(code, 0, "armor kinit: {out}");
    let (code, out) = kinit_pkinit(
        &env,
        "/tmp/cc_pk_fast",
        "pkiuser-rsa",
        "client-rsa-key",
        "pkiuser",
        "-T /tmp/cc_pk_armor",
    );
    assert_eq!(code, 0, "kinit -T: {out}");
    assert_pkinit_login(&out, "/tmp/cc_pk_fast", &env);
}

#[test]
#[ignore = "requires podman + MIT client container"]
fn mit_kinit_gets_a_freshness_token_from_our_kdc() {
    let env = mit_conf(PORT_FRESH, "ca", "");
    let (code, out) = kinit_pkinit(
        &env,
        "/tmp/cc_pk_fresh",
        "pkiuser-rsa",
        "client-rsa-key",
        "pkiuser",
        "",
    );
    assert_eq!(code, 0, "kinit: {out}");
    assert!(
        out.contains("PKINIT client received freshness token from KDC"),
        "{out}"
    );
    assert_pkinit_login(&out, "/tmp/cc_pk_fresh", &env);
}

#[test]
#[ignore = "requires podman + MIT client container"]
fn mit_kinit_errors_when_our_kdc_rejects_the_certificate() {
    // The client verifies its own certificate first (MIT cms_signeddata_create),
    // so it must trust the rogue CA for the KDC to be the one rejecting it.
    let env = mit_conf(PORT, "ca", "  pkinit_anchors = FILE:/pki/rogue-ca.pem");
    // Issued by a CA our KDC does not trust.
    let (code, out) = kinit_pkinit(
        &env,
        "/tmp/cc_pk_bad1",
        "rogue-pkiuser-rsa",
        "client-rsa-key",
        "pkiuser",
        "",
    );
    assert_ne!(code, 0, "{out}");
    assert!(out.contains("Can't verify certificate"), "{out}");
    // A certificate for another principal.
    let (code, out) = kinit_pkinit(
        &env,
        "/tmp/cc_pk_bad2",
        "otheruser-pki-rsa",
        "client-rsa-key",
        "pkiuser",
        "",
    );
    assert_ne!(code, 0, "{out}");
    assert!(out.contains("Client name mismatch"), "{out}");
}

fn kinit_anonymous(env: &str, cc: &str) -> (i32, String) {
    run(
        &format!("{env} KRB5CCNAME={cc} KRB5_TRACE=/dev/stderr kinit -n @{PKI_REALM} < /dev/null"),
        None,
    )
}

#[test]
#[ignore = "requires podman + MIT client container"]
fn mit_kinit_anonymous_logs_in_to_our_kdc() {
    let env = mit_conf(PORT, "ca", "");
    let (code, out) = kinit_anonymous(&env, "/tmp/cc_pk_anon");
    assert_eq!(code, 0, "kinit -n: {out}");
    assert!(out.contains("PKINIT client verified DH reply"), "{out}");
    let (_, klist) = run(&format!("{env} KRB5CCNAME=/tmp/cc_pk_anon klist -f"), None);
    assert!(
        klist.contains("Default principal: WELLKNOWN/ANONYMOUS@WELLKNOWN:ANONYMOUS"),
        "{klist}"
    );
    assert!(
        klist.contains(&format!("krbtgt/{PKI_REALM}@{PKI_REALM}")),
        "{klist}"
    );
    // klist -f shows the anonymous ticket flag as `a`.
    let flags = klist
        .lines()
        .find_map(|l| l.trim().strip_prefix("Flags: "))
        .expect("flags line");
    assert!(flags.contains('a'), "{klist}");
}

#[test]
#[ignore = "requires podman + MIT client container"]
fn mit_kinit_armors_with_an_anonymous_ticket_from_our_kdc() {
    let env = mit_conf(PORT, "ca", "");
    let (code, out) = kinit_anonymous(&env, "/tmp/cc_pk_anon_armor");
    assert_eq!(code, 0, "kinit -n: {out}");
    let (code, out) = run(
        &format!(
            "{env} KRB5CCNAME=/tmp/cc_pk_armored KRB5_TRACE=/dev/stderr \
             kinit -T /tmp/cc_pk_anon_armor armoruser@{PKI_REALM}"
        ),
        Some(&format!("{PW}\n")),
    );
    assert_eq!(code, 0, "armored kinit: {out}");
    assert!(out.contains("FAST armor ccache"), "{out}");
    assert!(out.contains("encrypted_challenge (138)"), "{out}");
}

// ------------------------------------------------- our client -> MIT KDC

fn mit_addr(port: u16) -> String {
    format!("{}:{port}", kdc_host())
}

struct Run {
    result: Result<Credential, Krb5Error>,
    error_codes: Vec<i32>,
}

impl Run {
    fn code(&self) -> i32 {
        match &self.result {
            Err(Krb5Error::KdcError(m)) => m.error_code,
            other => panic!("expected a KDC error, got {other:?}"),
        }
    }
}

fn run_as(
    port: u16,
    user: &str,
    cfg: Option<ClientConfig>,
    password: &str,
    fast: Option<Credential>,
) -> Run {
    let mut config = AsExchangeConfig::new(name(user), "TEST.REALM");
    config.pkinit = cfg.map(Arc::new);
    if let Some(armor) = fast {
        config.fast = FastMode::Required(armor);
    }
    run_config(port, config, password)
}

fn run_config(port: u16, config: AsExchangeConfig, password: &str) -> Run {
    let mut ex = AsExchange::new(config, password);
    let mut input = Vec::new();
    let mut error_codes = Vec::new();
    let result = loop {
        match ex.step(&input) {
            Ok(StepResult::SendToKdc { data, .. }) | Ok(StepResult::RetryTcp { data, .. }) => {
                input = kdc_send_to(&mit_addr(port), &data).expect("MIT KDC reply");
                if let Ok(e) = rasn::der::decode::<KrbErrorMsg>(&input) {
                    error_codes.push(e.error_code);
                }
            }
            Ok(StepResult::Complete) => break ex.credential().cloned(),
            Err(e) => break Err(e),
        }
    };
    Run {
        result,
        error_codes,
    }
}

fn client_cfg(cert: &str, key: &str, ca: &str) -> ClientConfig {
    let identity = Identity::from_spec(&pki_spec(cert, key)).expect("client identity");
    ClientConfig::new(identity, anchors(ca))
}

#[test]
#[ignore = "requires podman + MIT KDC container"]
fn our_client_logs_in_to_mit_with_rsa_and_dh() {
    let r = run_as(
        MIT_PORT,
        "testuser",
        Some(client_cfg("testuser-rsa", "client-rsa-key", "ca")),
        "wrong",
        None,
    );
    let cred = r.result.expect("PKINIT login without a password");
    assert_eq!(cred.client, name("testuser"));
}

#[test]
#[ignore = "requires podman + MIT KDC container"]
fn our_client_logs_in_to_mit_with_ec_certificate_and_every_group() {
    for group in Group::ALL {
        let mut cfg = client_cfg("testuser-ec", "client-ec-key", "ca");
        cfg.dh_group = group;
        let r = run_as(MIT_PORT, "testuser", Some(cfg), "wrong", None);
        assert!(r.result.is_ok(), "{}: {:?}", group.name(), r.result.err());
    }
}

#[test]
#[ignore = "requires podman + MIT KDC container"]
fn our_client_negotiates_up_from_dh_1024_via_mits_td_dh_parameters() {
    let mut cfg = client_cfg("testuser-rsa", "client-rsa-key", "ca");
    cfg.dh_group = Group::Modp1024;
    let r = run_as(MIT_PORT, "testuser", Some(cfg), "wrong", None);
    assert!(r.error_codes.contains(&65), "{:?}", r.error_codes);
    assert!(r.result.is_ok(), "{:?}", r.result.err());
}

#[test]
#[ignore = "requires podman + MIT KDC container"]
fn our_client_fast_armored_pkinit_against_mit() {
    let armor = run_as(MIT_PORT, "testuser2", None, "password2", None)
        .result
        .expect("armor TGT");
    let r = run_as(
        MIT_PORT,
        "testuser",
        Some(client_cfg("testuser-rsa", "client-rsa-key", "ca")),
        "wrong",
        Some(armor),
    );
    assert!(r.result.is_ok(), "{:?}", r.result.err());
}

#[test]
#[ignore = "requires podman + MIT KDC container"]
fn freshness_required_by_mit_is_satisfied_and_enforced() {
    let r = run_as(
        MIT_FRESH_PORT,
        "testuser",
        Some(client_cfg("testuser-rsa", "client-rsa-key", "ca")),
        "wrong",
        None,
    );
    assert!(r.result.is_ok(), "{:?}", r.result.err());

    let mut cfg = client_cfg("testuser-rsa", "client-rsa-key", "ca");
    cfg.disable_freshness = true;
    let r = run_as(MIT_FRESH_PORT, "testuser", Some(cfg), "wrong", None);
    assert_eq!(r.code(), 24, "{:?}", r.error_codes);
}

#[test]
#[ignore = "requires podman + MIT KDC container"]
fn mit_rejections_reach_our_client_with_mits_codes() {
    // Certificate for another principal: CLIENT_NAME_MISMATCH.
    let r = run_as(
        MIT_PORT,
        "testuser",
        Some(client_cfg("otheruser-rsa", "client-rsa-key", "ca")),
        "wrong",
        None,
    );
    assert_eq!(r.code(), 75);
    // Untrusted CA: CANT_VERIFY_CERTIFICATE.
    let r = run_as(
        MIT_PORT,
        "testuser",
        Some(client_cfg("rogue-testuser-rsa", "client-rsa-key", "ca")),
        "wrong",
        None,
    );
    assert_eq!(r.code(), 70);
    // We do not trust MIT's KDC certificate.
    let r = run_as(
        MIT_PORT,
        "testuser",
        Some(client_cfg("testuser-rsa", "client-rsa-key", "rogue-ca")),
        "wrong",
        None,
    );
    match r.result {
        Err(Krb5Error::Crypto(m)) => assert!(m.contains("error 70"), "{m}"),
        other => panic!("expected a client-side PKINIT error, got {other:?}"),
    }
}

#[test]
#[ignore = "requires podman + MIT KDC container"]
fn our_client_anonymous_pkinit_against_mit() {
    let mut config = AsExchangeConfig::new(anon(), "TEST.REALM");
    config.pkinit = Some(Arc::new(ClientConfig::anonymous(anchors("ca"))));
    let cred = run_config(MIT_PORT, config, "unused")
        .result
        .expect("anonymous PKINIT");
    assert_eq!(cred.client, anon());
    assert_eq!(cred.crealm, "WELLKNOWN:ANONYMOUS");
    assert!(cred.flags.contains(krb5_rs::types::TicketFlags::ANONYMOUS));
}

#[test]
#[ignore = "requires podman + MIT KDC container"]
fn our_client_armors_with_an_anonymous_ticket_from_mit() {
    let mut config = AsExchangeConfig::new(anon(), "TEST.REALM");
    config.pkinit = Some(Arc::new(ClientConfig::anonymous(anchors("ca"))));
    let armor = run_config(MIT_PORT, config, "unused")
        .result
        .expect("anonymous armor TGT");
    let r = run_as(MIT_PORT, "testuser2", None, "password2", Some(armor));
    assert!(r.result.is_ok(), "{:?}", r.result.err());
}
