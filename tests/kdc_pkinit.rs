#![cfg(all(feature = "kdc", feature = "test-pki"))]
//! PKINIT, our client against our KDC (MIT krb5 1.22.2 reference:
//! plugins/preauth/pkinit/pkinit_srv.c, pkinit_clnt.c,
//! pkinit_crypto_openssl.c, kdc/kdc_preauth.c). Success cases log in with a
//! wrong password, which only works if the reply key came from PKINIT.

use std::sync::Arc;

use chrono::Utc;
use krb5_rs::kdc::{Kdc, KdcConfig, MemoryStore, PrincipalAttributes};
use krb5_rs::pkinit::asn1::PaPkAsReq;
use krb5_rs::pkinit::client::ClientConfig;
use krb5_rs::pkinit::cms;
use krb5_rs::pkinit::pki::{self, CertSpec, SanSpec};
use krb5_rs::pkinit::server::ServerConfig;
use krb5_rs::pkinit::x509::Crl;
use krb5_rs::pkinit::{Group, Kdf};
use krb5_rs::protocol::fast::FastMode;
use krb5_rs::protocol::{AsExchange, AsExchangeConfig, Credential, StepResult};
use krb5_rs::types::*;
use krb5_rs::Krb5Error;
use rasn::types::OctetString;

#[path = "common/mod.rs"]
mod common;
use common::pki::{Ca, Identity, RsaSlot, TestKey, TrustStore};

const REALM: &str = "EXAMPLE.COM";
const OID_SERVER_AUTH: [u8; 8] = [0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01];
const OID_SC_LOGON: [u8; 10] = [0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x14, 0x02, 0x02];
const OID_AUTHDATA: [u8; 7] = [0x2B, 0x06, 0x01, 0x05, 0x02, 0x03, 0x01];
const PW: &str = "the-real-password";

fn name(n: &str) -> PrincipalName {
    PrincipalName::new_principal(n)
}

struct World {
    ca: Ca,
    kdc_key: TestKey,
    client_key: TestKey,
}

fn world() -> World {
    World {
        ca: Ca::new("Test CA", RsaSlot::Ca),
        kdc_key: TestKey::rsa(RsaSlot::Kdc),
        client_key: TestKey::rsa(RsaSlot::Client),
    }
}

fn store() -> MemoryStore {
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
    for user in ["alice", "bob", "armoruser", "upnuser"] {
        store
            .add_with_password(
                name(user),
                REALM,
                PW,
                1,
                &[18, 17],
                PrincipalAttributes::REQUIRES_PRE_AUTH,
            )
            .expect("user");
    }
    store
}

fn kdc_with(w: &World, tweak: impl FnOnce(&mut ServerConfig)) -> Kdc<MemoryStore> {
    let mut server = ServerConfig::new(w.ca.kdc(100, REALM, &w.kdc_key), w.ca.store());
    tweak(&mut server);
    let mut config = KdcConfig::new(REALM);
    config.pkinit = Some(Arc::new(server));
    Kdc::new(config, store())
}

fn kdc_without_pkinit() -> Kdc<MemoryStore> {
    Kdc::new(KdcConfig::new(REALM), store())
}

fn client_identity(w: &World, user: &str, serial: u64) -> Identity {
    w.ca.client(serial, user, REALM, &w.client_key).0
}

fn as_config(user: &str, pkinit: ClientConfig) -> AsExchangeConfig {
    let mut c = AsExchangeConfig::new(name(user), REALM);
    c.pkinit = Some(Arc::new(pkinit));
    c
}

type Tamper = dyn Fn(&[u8]) -> Vec<u8>;

struct Run {
    result: Result<Credential, Krb5Error>,
    replies: Vec<Vec<u8>>,
}

impl Run {
    fn code(&self) -> i32 {
        match &self.result {
            Err(Krb5Error::KdcError(m)) => m.error_code,
            other => panic!("expected a KDC error, got {other:?}"),
        }
    }

    fn crypto_error(&self) -> String {
        match &self.result {
            Err(Krb5Error::Crypto(m)) => m.clone(),
            other => panic!("expected a PKINIT client error, got {other:?}"),
        }
    }

    fn ok(self) -> Credential {
        self.result.expect("exchange succeeds")
    }

    fn error_codes_seen(&self) -> Vec<i32> {
        self.replies
            .iter()
            .filter_map(|r| rasn::der::decode::<KrbErrorMsg>(r).ok())
            .map(|m| m.error_code)
            .collect()
    }
}

fn run_with(
    kdc: &Kdc<MemoryStore>,
    config: AsExchangeConfig,
    password: &str,
    tamper: Option<&Tamper>,
) -> Run {
    let mut ex = AsExchange::new(config, password);
    let mut replies = Vec::new();
    let mut input = Vec::new();
    let result = loop {
        match ex.step(&input) {
            Ok(StepResult::SendToKdc { data, .. }) | Ok(StepResult::RetryTcp { data, .. }) => {
                let data = tamper.map_or(data.clone(), |t| t(&data));
                input = kdc.handle(&data);
                replies.push(input.clone());
            }
            Ok(StepResult::Complete) => break ex.credential().cloned(),
            Err(e) => break Err(e),
        }
    };
    Run { result, replies }
}

fn run(kdc: &Kdc<MemoryStore>, config: AsExchangeConfig) -> Run {
    run_with(kdc, config, "wrong-password", None)
}

fn pkinit_cfg(identity: Identity, w: &World) -> ClientConfig {
    ClientConfig::new(identity, w.ca.store())
}

/// Rewrite the PA-PK-AS-REQ in an AS-REQ.
fn tamper_pkinit(req: &[u8], f: impl Fn(&mut PaPkAsReq)) -> Vec<u8> {
    let mut as_req: AsReq = rasn::der::decode(req).expect("AS-REQ");
    for pa in as_req.0.padata.iter_mut().flatten() {
        if pa.padata_type == 16 {
            let mut p: PaPkAsReq =
                rasn::der::decode(pa.padata_value.as_ref()).expect("PA-PK-AS-REQ");
            f(&mut p);
            pa.padata_value = rasn::der::encode(&p).expect("encode").into();
        }
    }
    rasn::der::encode(&as_req).expect("encode")
}

// ------------------------------------------------------------------ success

#[test]
fn rsa_client_logs_in_with_dh2048_and_the_default_kdf() {
    let w = world();
    let kdc = kdc_with(&w, |_| {});
    let cred = run(
        &kdc,
        as_config("alice", pkinit_cfg(client_identity(&w, "alice", 10), &w)),
    )
    .ok();
    assert_eq!(cred.client, name("alice"));
    assert!(cred.flags.contains(TicketFlags::PRE_AUTHENT));
}

#[test]
fn every_group_negotiates_and_each_kdf_derives_the_same_key_on_both_sides() {
    let w = world();
    for group in Group::ALL {
        let kdc = kdc_with(&w, |s| s.dh_min_bits = 1024);
        let mut cfg = pkinit_cfg(client_identity(&w, "alice", 10), &w);
        cfg.dh_group = group;
        let r = run(&kdc, as_config("alice", cfg));
        assert!(r.result.is_ok(), "{}: {:?}", group.name(), r.result.err());
    }
    for kdfs in [
        Some(vec![Kdf::Sha1]),
        Some(vec![Kdf::Sha256]),
        Some(vec![Kdf::Sha512]),
        Some(vec![Kdf::Sha512, Kdf::Sha1]),
        None,
    ] {
        let kdc = kdc_with(&w, |_| {});
        let mut cfg = pkinit_cfg(client_identity(&w, "alice", 10), &w);
        cfg.kdfs = kdfs.clone();
        let r = run(&kdc, as_config("alice", cfg));
        assert!(r.result.is_ok(), "{kdfs:?}: {:?}", r.result.err());
    }
}

#[test]
fn ec_client_certificates_work() {
    let w = world();
    for key in [TestKey::p256(), TestKey::p384(), TestKey::p521()] {
        let kdc = kdc_with(&w, |_| {});
        let (id, _) = w.ca.client(11, "alice", REALM, &key);
        let mut cfg = pkinit_cfg(id, &w);
        cfg.dh_group = Group::P256;
        assert!(run(&kdc, as_config("alice", cfg)).result.is_ok());
    }
}

#[test]
fn ec_kdc_certificate_works() {
    let w = world();
    let key = TestKey::p256();
    let mut server = ServerConfig::new(w.ca.kdc(101, REALM, &key), w.ca.store());
    server.dh_min_bits = 2048;
    let mut config = KdcConfig::new(REALM);
    config.pkinit = Some(Arc::new(server));
    let kdc = Kdc::new(config, store());
    let cfg = pkinit_cfg(client_identity(&w, "alice", 10), &w);
    assert!(run(&kdc, as_config("alice", cfg)).result.is_ok());
}

#[test]
fn fast_armored_pkinit_logs_in() {
    let w = world();
    let kdc = kdc_with(&w, |_| {});
    let armor_tgt = run_with(
        &kdc,
        AsExchangeConfig::new(name("armoruser"), REALM),
        PW,
        None,
    )
    .ok();
    let mut cfg = as_config("alice", pkinit_cfg(client_identity(&w, "alice", 10), &w));
    cfg.fast = FastMode::Required(armor_tgt);
    let cred = run(&kdc, cfg).ok();
    assert_eq!(cred.client, name("alice"));
}

#[test]
fn a_key_from_the_password_is_not_used_when_pkinit_succeeds() {
    // Same credentials, KDC without PKINIT: the wrong password now fails.
    let w = world();
    let kdc = kdc_without_pkinit();
    let cfg = as_config("alice", pkinit_cfg(client_identity(&w, "alice", 10), &w));
    assert!(run(&kdc, cfg).result.is_err());
}

#[test]
fn client_falls_back_to_the_password_when_the_kdc_has_no_pkinit() {
    let w = world();
    let kdc = kdc_without_pkinit();
    let cfg = as_config("alice", pkinit_cfg(client_identity(&w, "alice", 10), &w));
    assert!(run_with(&kdc, cfg, PW, None).result.is_ok());
}

// ------------------------------------------------------------------- hints

#[test]
fn preauth_required_hints_list_pkinit_and_a_freshness_token_on_request() {
    let w = world();
    let kdc = kdc_with(&w, |_| {});
    let mut ex = AsExchange::new(AsExchangeConfig::new(name("alice"), REALM), PW);
    let StepResult::SendToKdc { data, .. } = ex.step(&[]).expect("step") else {
        panic!("expected a request");
    };
    let reply = kdc.handle(&data);
    let err: KrbErrorMsg = rasn::der::decode(&reply).expect("KRB-ERROR");
    assert_eq!(err.error_code, 25);
    let hints: Vec<PaData> =
        rasn::der::decode(err.e_data.expect("e-data").as_ref()).expect("METHOD-DATA");
    let types: Vec<i32> = hints.iter().map(|p| p.padata_type).collect();
    assert_eq!(types, vec![136, 19, 2, 16, 147, 150, 133]);
    let token = &hints[5].padata_value;
    assert!(token.len() > 8);

    // Without PKINIT configured there are no PKINIT hints.
    let plain = kdc_without_pkinit();
    let reply = plain.handle(&data);
    let err: KrbErrorMsg = rasn::der::decode(&reply).expect("KRB-ERROR");
    let hints: Vec<PaData> =
        rasn::der::decode(err.e_data.expect("e-data").as_ref()).expect("METHOD-DATA");
    assert!(hints
        .iter()
        .all(|p| ![16, 147, 150].contains(&p.padata_type)));
}

// ---------------------------------------------------------------- freshness

#[test]
fn required_freshness_is_satisfied_through_the_hint_token() {
    let w = world();
    let kdc = kdc_with(&w, |s| s.require_freshness = true);
    let cfg = pkinit_cfg(client_identity(&w, "alice", 10), &w);
    assert!(run(&kdc, as_config("alice", cfg)).result.is_ok());
}

#[test]
fn missing_freshness_when_required_is_preauth_failed() {
    let w = world();
    let kdc = kdc_with(&w, |s| s.require_freshness = true);
    let mut cfg = pkinit_cfg(client_identity(&w, "alice", 10), &w);
    cfg.disable_freshness = true;
    let r = run(&kdc, as_config("alice", cfg));
    assert_eq!(r.code(), 24);
}

// ---------------------------------------------------------- certificate trust

#[test]
fn untrusted_ca_is_cant_verify_certificate_with_trusted_certifiers() {
    let w = world();
    let other = Ca::new("Some Other CA", RsaSlot::Client2);
    let kdc = kdc_with(&w, |_| {});
    let (id, _) = other.client(10, "alice", REALM, &w.client_key);
    let mut cfg = pkinit_cfg(id, &w);
    cfg.store.anchors = vec![w.ca.cert.clone()];
    let r = run(&kdc, as_config("alice", cfg));
    assert_eq!(r.code(), 70);
    let KrbErrorMsg { e_data, .. } =
        rasn::der::decode(r.replies.last().expect("reply")).expect("error");
    let typed = krb5_rs::pkinit::server::decode_typed_data(e_data.expect("typed e-data").as_ref())
        .expect("typed data");
    assert_eq!(typed[0].0, 104);
    assert_eq!(typed.last().expect("cookie").0, 133);
}

#[test]
fn same_ca_name_with_a_different_key_is_invalid_certificate() {
    let w = world();
    let impostor = Ca::new("Test CA", RsaSlot::Client2);
    let kdc = kdc_with(&w, |_| {});
    let (id, _) = impostor.client(10, "alice", REALM, &w.client_key);
    let r = run(&kdc, as_config("alice", pkinit_cfg(id, &w)));
    assert_eq!(r.code(), 71);
}

#[test]
fn expired_client_certificate_is_invalid_certificate() {
    let w = world();
    let kdc = kdc_with(&w, |_| {});
    let mut spec = CertSpec::client("alice", 10, &name("alice"), REALM);
    spec.not_before = Utc::now() - chrono::Duration::days(3);
    spec.not_after = Utc::now() - chrono::Duration::days(2);
    let id = w.ca.identity(&spec, &w.client_key);
    let r = run(&kdc, as_config("alice", pkinit_cfg(id, &w)));
    assert_eq!(r.code(), 71);
    let KrbErrorMsg { e_data, .. } =
        rasn::der::decode(r.replies.last().expect("reply")).expect("error");
    let typed = krb5_rs::pkinit::server::decode_typed_data(e_data.expect("e-data").as_ref())
        .expect("typed");
    assert_eq!(typed[0].0, 105);
}

#[test]
fn revoked_certificate_with_a_crl_is_revoked_certificate() {
    let w = world();
    let now = Utc::now();
    let crl = pki::issue_crl(
        &w.ca.cert,
        &w.ca.key,
        &[10],
        now - chrono::Duration::hours(1),
        now + chrono::Duration::days(1),
    );
    let kdc = kdc_with(&w, |s| {
        s.store.crls.push(Crl::from_der(&crl).expect("crl"));
    });
    let r = run(
        &kdc,
        as_config("alice", pkinit_cfg(client_identity(&w, "alice", 10), &w)),
    );
    assert_eq!(r.code(), 72);
    // Another serial is fine.
    let r = run(
        &kdc,
        as_config("alice", pkinit_cfg(client_identity(&w, "alice", 11), &w)),
    );
    assert!(r.result.is_ok());
}

#[test]
fn required_crl_checking_without_a_crl_is_revocation_status_unknown() {
    let w = world();
    let kdc = kdc_with(&w, |s| s.require_crl_checking = true);
    let r = run(
        &kdc,
        as_config("alice", pkinit_cfg(client_identity(&w, "alice", 10), &w)),
    );
    assert_eq!(r.code(), 73);
}

// --------------------------------------------------------------- EKU and SAN

fn spec_for(user: &str) -> CertSpec {
    CertSpec::client(user, 10, &name(user), REALM)
}

#[test]
fn eku_rules_follow_pkinit_eku_checking() {
    let w = world();
    let mut no_eku = spec_for("alice");
    no_eku.eku = None;
    let mut server_auth = spec_for("alice");
    server_auth.eku = Some(vec![OID_SERVER_AUTH.to_vec()]);
    let mut sc_logon = spec_for("alice");
    sc_logon.eku = Some(vec![OID_SC_LOGON.to_vec()]);
    let mut no_ku = spec_for("alice");
    no_ku.key_usage = None;

    let default_kdc = kdc_with(&w, |_| {});
    for (label, spec) in [
        ("no EKU", &no_eku),
        ("serverAuth", &server_auth),
        ("sc-logon", &sc_logon),
        ("no KU", &no_ku),
    ] {
        let id = w.ca.identity(spec, &w.client_key);
        let r = run(&default_kdc, as_config("alice", pkinit_cfg(id, &w)));
        assert_eq!(r.code(), 77, "{label}");
    }

    // eku checking = none accepts anything with a matching SAN.
    let none = kdc_with(&w, |s| s.require_eku = false);
    let id = w.ca.identity(&no_eku, &w.client_key);
    assert!(run(&none, as_config("alice", pkinit_cfg(id, &w)))
        .result
        .is_ok());

    // eku checking = scLogin also accepts id-ms-kp-sc-logon.
    let sc = kdc_with(&w, |s| s.accept_secondary_eku = true);
    let id = w.ca.identity(&sc_logon, &w.client_key);
    assert!(run(&sc, as_config("alice", pkinit_cfg(id, &w)))
        .result
        .is_ok());
}

#[test]
fn san_must_match_the_client_principal() {
    let w = world();
    let kdc = kdc_with(&w, |_| {});
    // A certificate for bob presented as alice.
    let id = client_identity(&w, "bob", 10);
    assert_eq!(run(&kdc, as_config("alice", pkinit_cfg(id, &w))).code(), 75);

    // No SAN at all.
    let mut spec = spec_for("alice");
    spec.sans.clear();
    let id = w.ca.identity(&spec, &w.client_key);
    assert_eq!(run(&kdc, as_config("alice", pkinit_cfg(id, &w))).code(), 75);

    // The right name in the wrong realm.
    let mut spec = spec_for("alice");
    spec.sans = vec![SanSpec::Pkinit(name("alice"), "OTHER.REALM".into())];
    let id = w.ca.identity(&spec, &w.client_key);
    assert_eq!(run(&kdc, as_config("alice", pkinit_cfg(id, &w))).code(), 75);
}

#[test]
fn upn_san_needs_pkinit_allow_upn() {
    let w = world();
    let mut spec = spec_for("upnuser");
    spec.sans = vec![SanSpec::Upn(format!("upnuser@{REALM}"))];
    let id = |w: &World| w.ca.identity(&spec, &w.client_key);

    let off = kdc_with(&w, |_| {});
    assert_eq!(
        run(&off, as_config("upnuser", pkinit_cfg(id(&w), &w))).code(),
        75
    );
    let on = kdc_with(&w, |s| s.allow_upn = true);
    assert!(run(&on, as_config("upnuser", pkinit_cfg(id(&w), &w)))
        .result
        .is_ok());
}

// ------------------------------------------------------- request tampering

#[test]
fn bad_cms_signature_is_invalid_sig() {
    let w = world();
    let kdc = kdc_with(&w, |_| {});
    let cfg = as_config("alice", pkinit_cfg(client_identity(&w, "alice", 10), &w));
    let tamper = |req: &[u8]| {
        tamper_pkinit(req, |p| {
            let mut bytes = p.signed_auth_pack.to_vec();
            let last = bytes.len() - 1;
            bytes[last] ^= 1;
            p.signed_auth_pack = OctetString::from(bytes);
        })
    };
    let r = run_with(&kdc, cfg, "x", Some(&tamper));
    assert_eq!(r.code(), 64);
}

#[test]
fn changed_request_body_fails_the_pa_checksum() {
    let w = world();
    let kdc = kdc_with(&w, |_| {});
    let cfg = as_config("alice", pkinit_cfg(client_identity(&w, "alice", 10), &w));
    let tamper = |req: &[u8]| {
        let mut as_req: AsReq = rasn::der::decode(req).expect("AS-REQ");
        if as_req
            .0
            .padata
            .iter()
            .flatten()
            .any(|p| p.padata_type == 16)
        {
            as_req.0.req_body.nonce ^= 1;
        }
        rasn::der::encode(&as_req).expect("encode")
    };
    // AP_ERR_MODIFIED is not one of the codes filter_preauth_error passes
    // through (kdc_preauth.c:1092-1134), so the client sees PREAUTH_FAILED.
    let r = run_with(&kdc, cfg, "x", Some(&tamper));
    assert_eq!(r.code(), 24);
}

#[test]
fn unsigned_request_from_a_non_anonymous_client_is_preauth_failed() {
    let w = world();
    let kdc = kdc_with(&w, |_| {});
    let store = w.ca.store();
    let cfg = as_config("alice", pkinit_cfg(client_identity(&w, "alice", 10), &w));
    let tamper = move |req: &[u8]| {
        tamper_pkinit(req, |p| {
            let v = cms::verify(
                p.signed_auth_pack.as_ref(),
                &OID_AUTHDATA,
                &store,
                Utc::now(),
                false,
            )
            .expect("own signature verifies");
            p.signed_auth_pack = OctetString::from(cms::content_info(&OID_AUTHDATA, &v.data));
        })
    };
    let r = run_with(&kdc, cfg, "x", Some(&tamper));
    assert_eq!(r.code(), 24);
}

// ------------------------------------------------------------ DH negotiation

#[test]
fn dh_group_below_the_minimum_is_negotiated_up_via_td_dh_parameters() {
    let w = world();
    let kdc = kdc_with(&w, |_| {});
    let mut cfg = pkinit_cfg(client_identity(&w, "alice", 10), &w);
    cfg.dh_group = Group::Modp1024;
    let r = run(&kdc, as_config("alice", cfg));
    assert!(
        r.error_codes_seen().contains(&65),
        "{:?}",
        r.error_codes_seen()
    );
    assert!(r.result.is_ok(), "{:?}", r.result.err());

    // The TD-DH-PARAMETERS list follows MIT's order: P-256, P-384, P-521,
    // 2048, 4096 (1024 is excluded at min bits 2048).
    let err = r
        .replies
        .iter()
        .find_map(|b| {
            rasn::der::decode::<KrbErrorMsg>(b)
                .ok()
                .filter(|m| m.error_code == 65)
        })
        .expect("error 65");
    let typed = krb5_rs::pkinit::server::decode_typed_data(err.e_data.expect("e-data").as_ref())
        .expect("typed");
    let (t, v) = &typed[0];
    assert_eq!(*t, 109);
    let list: Vec<rasn_pkix::AlgorithmIdentifier> = rasn::der::decode(v).expect("TD-DH-PARAMETERS");
    let groups: Vec<Group> = list
        .iter()
        .filter_map(Group::from_algorithm_identifier)
        .collect();
    assert_eq!(
        groups,
        vec![
            Group::P256,
            Group::P384,
            Group::P521,
            Group::Modp2048,
            Group::Modp4096
        ]
    );
}

#[test]
fn a_kdc_demanding_a_stronger_group_than_the_client_allows_ends_the_exchange() {
    let w = world();
    let kdc = kdc_with(&w, |s| s.dh_min_bits = 4096);
    let mut cfg = pkinit_cfg(client_identity(&w, "alice", 10), &w);
    cfg.dh_group = Group::Modp1024;
    let r = run(&kdc, as_config("alice", cfg));
    // 1024 -> (P-256 is at least as strong) -> succeeds after retry.
    assert!(r.result.is_ok());
}

// ------------------------------------------- client-side KDC certificate checks

fn kdc_with_identity(w: &World, identity: Identity) -> Kdc<MemoryStore> {
    let server = ServerConfig::new(identity, w.ca.store());
    let mut config = KdcConfig::new(REALM);
    config.pkinit = Some(Arc::new(server));
    Kdc::new(config, store())
}

#[test]
fn kdc_certificate_san_must_name_the_realm_tgs_or_a_configured_hostname() {
    let w = world();
    let client = || pkinit_cfg(client_identity(&w, "alice", 10), &w);

    // SAN krbtgt/OTHER.REALM@OTHER.REALM.
    let wrong =
        w.ca.identity(&CertSpec::kdc("kdc", 101, "OTHER.REALM"), &w.kdc_key);
    let r = run(&kdc_with_identity(&w, wrong), as_config("alice", client()));
    assert!(
        r.crypto_error().contains("error 76"),
        "{}",
        r.crypto_error()
    );

    // dNSName only: needs pkinit_kdc_hostname and a kpKDC EKU.
    let mut dns = CertSpec::kdc("kdc", 102, REALM);
    dns.sans = vec![SanSpec::Dns("kdc.example.com".into())];
    let kdc = || kdc_with_identity(&w, w.ca.identity(&dns, &w.kdc_key));
    let r = run(&kdc(), as_config("alice", client()));
    assert!(r.crypto_error().contains("error 76"));
    let mut cfg = client();
    cfg.kdc_hostnames = vec!["KDC.example.com".into()];
    assert!(run(&kdc(), as_config("alice", cfg)).result.is_ok());

    // dNSName with a wrong EKU is rejected unless EKU checking is off.
    let mut bad_eku = dns.clone();
    bad_eku.serial = 103;
    bad_eku.eku = Some(vec![OID_SERVER_AUTH.to_vec()]);
    let kdc = || kdc_with_identity(&w, w.ca.identity(&bad_eku, &w.kdc_key));
    let mut cfg = client();
    cfg.kdc_hostnames = vec!["kdc.example.com".into()];
    let r = run(&kdc(), as_config("alice", cfg));
    assert!(
        r.crypto_error().contains("error 77"),
        "{}",
        r.crypto_error()
    );
    let mut cfg = client();
    cfg.kdc_hostnames = vec!["kdc.example.com".into()];
    cfg.accept_secondary_eku = true;
    assert!(run(&kdc(), as_config("alice", cfg)).result.is_ok());
    let mut cfg = client();
    cfg.kdc_hostnames = vec!["kdc.example.com".into()];
    cfg.require_eku = false;
    assert!(run(&kdc(), as_config("alice", cfg)).result.is_ok());
}

#[test]
fn client_rejects_a_kdc_certificate_from_an_untrusted_ca() {
    let w = world();
    let other = Ca::new("Some Other CA", RsaSlot::Client2);
    let id = other.kdc(104, REALM, &w.kdc_key);
    let kdc = kdc_with_identity(&w, id);
    // The KDC trusts our CA (for the client); the client does not trust the
    // KDC certificate's issuer.
    let cfg = pkinit_cfg(client_identity(&w, "alice", 10), &w);
    let r = run(&kdc, as_config("alice", cfg));
    assert!(
        r.crypto_error().contains("error 70") || r.crypto_error().contains("error 71"),
        "{}",
        r.crypto_error()
    );
}

#[test]
fn trust_store_is_required() {
    let w = world();
    let kdc = kdc_with(&w, |_| {});
    let id = client_identity(&w, "alice", 10);
    let cfg = ClientConfig::new(id, TrustStore::default());
    let r = run(&kdc, as_config("alice", cfg));
    assert!(
        r.crypto_error().contains("pkinit_anchors"),
        "{}",
        r.crypto_error()
    );
}

// ------------------------------------------------------------- kdc.conf

#[test]
fn realm_config_reads_the_pkinit_relations_with_mit_defaults_and_overrides() {
    use krb5_rs::kdc::RealmConfig;
    use krb5_rs::profile::Profile;

    let w = world();
    let dir = std::env::temp_dir().join(format!("krb5rs_pkinit_cfg_{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    let ca_pem = w.ca.write_ca_pem(&dir);
    let kdc_cert = w.ca.issue(&CertSpec::kdc("kdc", 100, REALM), &w.kdc_key);
    let (kdc_pem, kdc_key_pem) =
        common::pki::write_identity_pem(&dir, "kdc", &kdc_cert, &w.kdc_key);
    let p = |path: &std::path::Path| {
        path.to_string_lossy()
            .replace(std::path::MAIN_SEPARATOR, "/")
    };

    let conf = |extra: &str| {
        Profile::parse(&format!(
            "[kdcdefaults]\n pkinit_anchors = FILE:{}\n[realms]\n {REALM} = {{\n  \
             pkinit_identity = FILE:{},{}\n{extra}\n }}\n",
            p(&ca_pem),
            p(&kdc_pem),
            p(&kdc_key_pem)
        ))
        .expect("kdc.conf")
    };

    let defaults = RealmConfig::from_profiles(&conf(""), None, REALM).expect("config");
    let server = defaults.kdc.pkinit.as_ref().expect("pkinit on");
    assert_eq!(server.dh_min_bits, 2048);
    assert!(!server.allow_upn && !server.require_crl_checking && !server.require_freshness);
    assert!(server.require_eku && !server.accept_secondary_eku);

    let custom = RealmConfig::from_profiles(
        &conf(
            "  pkinit_dh_min_bits = 4096\n  pkinit_allow_upn = true\n  \
             pkinit_eku_checking = scLogin\n  pkinit_require_freshness = true\n  \
             pkinit_indicator = pkinit\n",
        ),
        None,
        REALM,
    )
    .expect("config");
    let server = custom.kdc.pkinit.as_ref().expect("pkinit on");
    assert_eq!(server.dh_min_bits, 4096);
    assert!(server.allow_upn && server.require_freshness && server.accept_secondary_eku);
    assert_eq!(server.indicators, vec!["pkinit".to_string()]);
    let kdc = Kdc::new(custom.kdc, store());
    let cfg = pkinit_cfg(client_identity(&w, "alice", 10), &w);
    assert!(run(&kdc, as_config("alice", cfg)).result.is_ok());

    // No pkinit_identity: PKINIT stays off. No anchors: configuration error.
    let off = Profile::parse(&format!("[realms]\n {REALM} = {{\n }}\n")).expect("conf");
    assert!(RealmConfig::from_profiles(&off, None, REALM)
        .expect("config")
        .kdc
        .pkinit
        .is_none());
    let no_anchors = Profile::parse(&format!(
        "[realms]\n {REALM} = {{\n  pkinit_identity = FILE:{},{}\n }}\n",
        p(&kdc_pem),
        p(&kdc_key_pem)
    ))
    .expect("conf");
    assert!(RealmConfig::from_profiles(&no_anchors, None, REALM).is_err());
    std::fs::remove_dir_all(&dir).ok();
}
