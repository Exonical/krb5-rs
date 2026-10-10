//! Path validation behaviour (OpenSSL `X509_verify_cert` rules as MIT uses
//! them) and certificate extension parsing.

use chrono::Duration;

use super::*;
use crate::pkinit::pki::{self, CertSpec, RsaSlot, SanSpec, TestKey};

pub(crate) struct Pki {
    pub ca: Cert,
    pub ca_key: TestKey,
    pub store: TrustStore,
}

pub(crate) fn pki(ec: bool) -> Pki {
    let ca_key = if ec {
        TestKey::p256()
    } else {
        TestKey::rsa(RsaSlot::Ca)
    };
    let ca = pki::issue(&CertSpec::ca("Test CA", 1), &ca_key, None, &ca_key);
    let store = TrustStore {
        anchors: vec![ca.clone()],
        ..TrustStore::default()
    };
    Pki { ca, ca_key, store }
}

fn leaf(p: &Pki, spec: CertSpec) -> Cert {
    let key = TestKey::rsa(RsaSlot::Client);
    pki::issue(&spec, &key, Some(&p.ca), &p.ca_key)
}

fn now() -> DateTime<Utc> {
    Utc::now()
}

#[test]
fn valid_chains_verify_for_rsa_and_ec_cas() {
    for ec in [false, true] {
        let p = pki(ec);
        let c = leaf(&p, CertSpec::new("alice", 10));
        let chain = verify_chain(&c, &[], &p.store, now(), false).expect("verify");
        assert_eq!(chain.len(), 2);
        assert_eq!(chain[1].der(), p.ca.der());
    }
}

#[test]
fn ecdsa_p384_and_p521_issuers_sign_and_verify() {
    for key in [TestKey::p384(), TestKey::p521()] {
        let ca = pki::issue(&CertSpec::ca("EC CA", 1), &key, None, &key);
        let store = TrustStore {
            anchors: vec![ca.clone()],
            ..TrustStore::default()
        };
        let c = pki::issue(&CertSpec::new("x", 2), &TestKey::p256(), Some(&ca), &key);
        verify_chain(&c, &[], &store, now(), false).expect("verify");
    }
}

#[test]
fn untrusted_issuer_is_cant_verify_and_bad_signature_is_invalid() {
    let p = pki(false);
    let other = pki(true);
    let c = leaf(&p, CertSpec::new("alice", 10));
    // Same CA name, different key: the name matches but the signature fails.
    assert!(matches!(
        verify_chain(&c, &[], &other.store, now(), false),
        Err(VerifyError::Invalid(_))
    ));
    let unrelated_key = TestKey::rsa(RsaSlot::Client2);
    let unrelated = pki::issue(
        &CertSpec::ca("Unrelated CA", 1),
        &unrelated_key,
        None,
        &unrelated_key,
    );
    let store = TrustStore {
        anchors: vec![unrelated],
        ..TrustStore::default()
    };
    assert_eq!(
        verify_chain(&c, &[], &store, now(), false),
        Err(VerifyError::NoIssuer)
    );
    assert_eq!(
        verify_chain(&c, &[], &TrustStore::default(), now(), false),
        Err(VerifyError::NoIssuer)
    );
}

#[test]
fn expired_and_not_yet_valid_certificates_are_invalid() {
    let p = pki(false);
    let mut spec = CertSpec::new("alice", 10);
    spec.not_after = now() - Duration::hours(1);
    spec.not_before = now() - Duration::days(2);
    let expired = leaf(&p, spec);
    assert!(matches!(
        verify_chain(&expired, &[], &p.store, now(), false),
        Err(VerifyError::Invalid(m)) if m.contains("expired")
    ));
    let mut spec = CertSpec::new("alice", 11);
    spec.not_before = now() + Duration::hours(2);
    spec.not_after = now() + Duration::days(2);
    let future = leaf(&p, spec);
    assert!(matches!(
        verify_chain(&future, &[], &p.store, now(), false),
        Err(VerifyError::Invalid(m)) if m.contains("not yet valid")
    ));
    let c = leaf(&p, CertSpec::new("alice", 12));
    assert!(verify_chain(&c, &[], &p.store, now() + Duration::hours(5), false).is_ok());
    assert!(verify_chain(&c, &[], &p.store, now() + Duration::days(5), false).is_err());
}

#[test]
fn intermediates_come_from_the_message_or_the_pool_and_need_ca_constraints() {
    let p = pki(false);
    let inter_key = TestKey::rsa(RsaSlot::Kdc);
    let mut inter_spec = CertSpec::ca("Intermediate", 2);
    inter_spec.ca = Some(Some(0));
    let inter = pki::issue(&inter_spec, &inter_key, Some(&p.ca), &p.ca_key);
    let leaf_key = TestKey::rsa(RsaSlot::Client);
    let c = pki::issue(
        &CertSpec::new("alice", 20),
        &leaf_key,
        Some(&inter),
        &inter_key,
    );

    assert_eq!(
        verify_chain(&c, &[], &p.store, now(), false),
        Err(VerifyError::NoIssuer)
    );
    let chain = verify_chain(&c, std::slice::from_ref(&inter), &p.store, now(), false)
        .expect("untrusted intermediate");
    assert_eq!(chain.len(), 3);
    let mut pooled = p.store.clone();
    pooled.intermediates.push(inter.clone());
    assert!(verify_chain(&c, &[], &pooled, now(), false).is_ok());

    // pathLen 0 forbids a second intermediate below it.
    let inter2_key = TestKey::rsa(RsaSlot::Client2);
    let inter2 = pki::issue(
        &CertSpec::ca("Intermediate 2", 3),
        &inter2_key,
        Some(&inter),
        &inter_key,
    );
    let deep = pki::issue(
        &CertSpec::new("bob", 21),
        &leaf_key,
        Some(&inter2),
        &inter2_key,
    );
    assert!(matches!(
        verify_chain(&deep, &[inter.clone(), inter2], &p.store, now(), false),
        Err(VerifyError::Invalid(m)) if m.contains("path length")
    ));

    // A leaf certificate cannot issue.
    let not_ca = pki::issue(
        &CertSpec::new("NotCA", 4),
        &inter_key,
        Some(&p.ca),
        &p.ca_key,
    );
    let child = pki::issue(
        &CertSpec::new("child", 22),
        &leaf_key,
        Some(&not_ca),
        &inter_key,
    );
    assert!(matches!(
        verify_chain(&child, &[not_ca], &p.store, now(), false),
        Err(VerifyError::Invalid(m)) if m.contains("basicConstraints")
    ));
}

#[test]
fn crls_revoke_and_require_crl_checking_demands_one() {
    let p = pki(false);
    let c = leaf(&p, CertSpec::new("alice", 30));
    let good = leaf(&p, CertSpec::new("bob", 31));
    let ts = now();
    let crl_der = pki::issue_crl(
        &p.ca,
        &p.ca_key,
        &[30],
        ts - Duration::hours(1),
        ts + Duration::days(1),
    );
    let mut with_crl = p.store.clone();
    with_crl.crls.push(Crl::from_der(&crl_der).expect("crl"));

    assert_eq!(
        verify_chain(&c, &[], &with_crl, now(), false),
        Err(VerifyError::Revoked)
    );
    // The CRL also covers the CA's own check (issuer = itself).
    assert!(verify_chain(&good, &[], &with_crl, now(), true).is_ok());
    assert!(verify_chain(&good, &[], &p.store, now(), false).is_ok());
    assert_eq!(
        verify_chain(&good, &[], &p.store, now(), true),
        Err(VerifyError::CrlUnavailable)
    );
    // An expired CRL is a hard failure.
    let stale = pki::issue_crl(
        &p.ca,
        &p.ca_key,
        &[],
        ts - Duration::days(3),
        ts - Duration::days(2),
    );
    let mut with_stale = p.store.clone();
    with_stale.crls.push(Crl::from_der(&stale).expect("crl"));
    assert!(matches!(
        verify_chain(&good, &[], &with_stale, now(), false),
        Err(VerifyError::Invalid(_))
    ));
    // A CRL signed by someone else is ignored.
    let other = pki(true);
    let foreign = pki::issue_crl(
        &p.ca,
        &other.ca_key,
        &[31],
        ts - Duration::hours(1),
        ts + Duration::days(1),
    );
    let mut with_foreign = p.store.clone();
    with_foreign
        .crls
        .push(Crl::from_der(&foreign).expect("crl"));
    assert!(verify_chain(&good, &[], &with_foreign, now(), false).is_ok());
}

#[test]
fn tampered_certificates_fail_signature_verification() {
    let p = pki(false);
    let c = leaf(&p, CertSpec::new("alice", 40));
    let mut der = c.der().to_vec();
    let at = der.len() / 3;
    der[at] ^= 1;
    if let Ok(bad) = Cert::from_der(&der) {
        assert!(verify_chain(&bad, &[], &p.store, now(), false).is_err());
    }
}

#[test]
fn extensions_sans_eku_and_key_usage_are_parsed() {
    let p = pki(false);
    let princ = PrincipalName::new_principal("alice");
    let mut spec = CertSpec::client("alice", 50, &princ, "EXAMPLE.COM");
    spec.sans.push(SanSpec::Upn("alice@EXAMPLE.COM".into()));
    spec.sans.push(SanSpec::Dns("kdc.example.com".into()));
    let c = leaf(&p, spec);
    let sans = c.sans();
    assert_eq!(sans.len(), 3);
    assert_eq!(sans[0], San::Pkinit(princ, "EXAMPLE.COM".into()));
    assert_eq!(sans[1], San::Upn("alice@EXAMPLE.COM".into()));
    assert_eq!(sans[2], San::Dns("kdc.example.com".into()));
    assert_eq!(c.eku(), Some(vec![asn1::ID_PKINIT_KP_CLIENT_AUTH.to_vec()]));
    assert!(c.has_digital_signature_ku());
    assert!(!c.is_ec());

    let bare = leaf(&p, CertSpec::new("bare", 51));
    assert!(bare.sans().is_empty());
    assert_eq!(bare.eku(), None);
    assert!(!bare.has_digital_signature_ku());
}

#[test]
fn ca_key_usage_without_key_cert_sign_cannot_issue() {
    let p = pki(false);
    let inter_key = TestKey::rsa(RsaSlot::Kdc);
    let mut spec = CertSpec::ca("NoSign CA", 5);
    spec.key_usage = Some(0x80);
    let inter = pki::issue(&spec, &inter_key, Some(&p.ca), &p.ca_key);
    let c = pki::issue(
        &CertSpec::new("x", 6),
        &TestKey::rsa(RsaSlot::Client),
        Some(&inter),
        &inter_key,
    );
    assert!(matches!(
        verify_chain(&c, &[inter], &p.store, now(), false),
        Err(VerifyError::Invalid(m)) if m.contains("keyCertSign")
    ));
}

#[test]
fn raw_signatures_verify_for_every_hash_and_key_type() {
    let all = vec![Hash::Sha1, Hash::Sha256, Hash::Sha384, Hash::Sha512];
    for (key, hashes) in [
        (TestKey::rsa(RsaSlot::Client), all.clone()),
        (TestKey::p256(), all),
        (TestKey::p384(), vec![Hash::Sha256, Hash::Sha384]),
        (TestKey::p521(), vec![Hash::Sha256, Hash::Sha512]),
    ] {
        let ca = pki::issue(&CertSpec::ca("k", 1), &key, None, &key);
        for h in hashes {
            let sig = key.key.sign(h, b"hello").expect("sign");
            let alg = key.key.signature_algorithm(h);
            assert!(verify_signature(ca.spki(), &alg, None, b"hello", &sig));
            assert!(!verify_signature(ca.spki(), &alg, None, b"hellp", &sig));
        }
    }
    let rsa = TestKey::rsa(RsaSlot::Client);
    let ca = pki::issue(&CertSpec::ca("k", 1), &rsa, None, &rsa);
    let sig = rsa.key.sign(Hash::Sha256, b"x").expect("sign");
    let plain = asn1::alg_null(asn1::RSA_ENCRYPTION);
    assert!(verify_signature(
        ca.spki(),
        &plain,
        Some(Hash::Sha256),
        b"x",
        &sig
    ));
    assert!(!verify_signature(ca.spki(), &plain, None, b"x", &sig));
    assert!(!verify_signature(
        ca.spki(),
        &plain,
        Some(Hash::Sha1),
        b"x",
        &sig
    ));
}

#[test]
fn private_keys_load_from_pem_and_reject_encrypted_or_missing_ones() {
    let k = TestKey::rsa(RsaSlot::Client);
    assert!(PrivateKey::from_pem(k.pem()).is_ok());
    for k in [TestKey::p256(), TestKey::p384(), TestKey::p521()] {
        assert!(PrivateKey::from_pem(k.pem()).expect("pkcs8 ec").is_ec());
    }
    assert!(PrivateKey::from_pem("nothing").is_err());
    let enc = "-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----\n";
    assert!(PrivateKey::from_pem(enc).is_err());
}
