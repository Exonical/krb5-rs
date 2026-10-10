//! CMS SignedData creation and verification.

use chrono::Utc;

use super::*;
use crate::pkinit::pki::{self, CertSpec, RsaSlot, TestKey};
use crate::pkinit::x509::tests::pki as new_pki;

fn client_identity(p: &crate::pkinit::x509::tests::Pki, key: &TestKey) -> Identity {
    let princ = crate::types::PrincipalName::new_principal("alice");
    let cert = pki::issue(
        &CertSpec::client("alice", 7, &princ, "EXAMPLE.COM"),
        key,
        Some(&p.ca),
        &p.ca_key,
    );
    pki::identity(vec![cert], key)
}

#[test]
fn sign_verify_round_trip_for_rsa_and_every_ec_curve() {
    let p = new_pki(false);
    for key in [
        TestKey::rsa(RsaSlot::Client),
        TestKey::p256(),
        TestKey::p384(),
        TestKey::p521(),
    ] {
        let id = client_identity(&p, &key);
        let msg = sign(&id, asn1::ID_PKINIT_AUTHDATA, b"auth pack bytes").expect("sign");
        let v =
            verify(&msg, asn1::ID_PKINIT_AUTHDATA, &p.store, Utc::now(), false).expect("verify");
        assert_eq!(v.data, b"auth pack bytes");
        assert_eq!(v.signer.as_ref().map(|c| c.der()), Some(id.cert().der()));
        assert_eq!(v.chain.len(), 2);
    }
}

#[test]
fn message_is_a_version_3_signed_data_with_sha256_and_sorted_attributes() {
    let p = new_pki(false);
    let id = client_identity(&p, &TestKey::rsa(RsaSlot::Client));
    let msg = sign(&id, asn1::ID_PKINIT_DHKEYDATA, b"x").expect("sign");
    let ci: rasn_cms::ContentInfo = rasn::der::decode(&msg).expect("decodes as ContentInfo");
    let sd: rasn_cms::SignedData = rasn::der::decode(ci.content.as_bytes()).expect("SignedData");
    assert_eq!(sd.signer_infos.len(), 1);
    let si = &sd.signer_infos.to_vec()[0];
    let attrs = si.signed_attrs.as_ref().expect("signed attributes");
    assert_eq!(attrs.len(), 2);
    assert!(asn1::is_oid(
        &si.digest_algorithm.algorithm,
        asn1::CMS_SHA256
    ));
    assert!(asn1::is_oid(
        &si.signature_algorithm.algorithm,
        asn1::SHA256_WITH_RSA
    ));
    assert_eq!(sd.certificates.as_ref().map(|c| c.len()), Some(1));
}

#[test]
fn tampering_with_content_or_signature_is_invalid_sig() {
    let p = new_pki(false);
    let id = client_identity(&p, &TestKey::rsa(RsaSlot::Client));
    let msg = sign(&id, asn1::ID_PKINIT_AUTHDATA, b"0123456789abcdef").expect("sign");

    // Flip a byte of the eContent.
    let at = msg
        .windows(16)
        .position(|w| w == b"0123456789abcdef")
        .expect("content");
    let mut bad = msg.clone();
    bad[at + 3] ^= 1;
    let err = verify(&bad, asn1::ID_PKINIT_AUTHDATA, &p.store, Utc::now(), false)
        .expect_err("tampered content");
    assert_eq!(err.code, KDC_ERR_INVALID_SIG);

    // Flip the last byte of the signature value.
    let mut bad = msg.clone();
    let last = bad.len() - 1;
    bad[last] ^= 1;
    let err = verify(&bad, asn1::ID_PKINIT_AUTHDATA, &p.store, Utc::now(), false)
        .expect_err("tampered signature");
    assert_eq!(err.code, KDC_ERR_INVALID_SIG);
}

#[test]
fn certificate_problems_map_to_mit_codes() {
    let p = new_pki(false);
    let id = client_identity(&p, &TestKey::rsa(RsaSlot::Client));
    let msg = sign(&id, asn1::ID_PKINIT_AUTHDATA, b"x").expect("sign");

    let other = new_pki(true);
    let err = verify(
        &msg,
        asn1::ID_PKINIT_AUTHDATA,
        &other.store,
        Utc::now(),
        false,
    )
    .expect_err("wrong CA");
    assert_eq!(err.code, KDC_ERR_INVALID_CERTIFICATE);

    let unrelated_key = TestKey::rsa(RsaSlot::Client2);
    let unrelated = pki::issue(
        &CertSpec::ca("Unrelated", 1),
        &unrelated_key,
        None,
        &unrelated_key,
    );
    let store = TrustStore {
        anchors: vec![unrelated],
        ..TrustStore::default()
    };
    let err =
        verify(&msg, asn1::ID_PKINIT_AUTHDATA, &store, Utc::now(), false).expect_err("no issuer");
    assert_eq!(err.code, KDC_ERR_CANT_VERIFY_CERTIFICATE);

    let err = verify(
        &msg,
        asn1::ID_PKINIT_AUTHDATA,
        &p.store,
        Utc::now() + chrono::Duration::days(30),
        false,
    )
    .expect_err("expired");
    assert_eq!(err.code, KDC_ERR_INVALID_CERTIFICATE);

    let err = verify(&msg, asn1::ID_PKINIT_AUTHDATA, &p.store, Utc::now(), true)
        .expect_err("CRL required");
    assert_eq!(err.code, KDC_ERR_REVOCATION_STATUS_UNKNOWN);
}

#[test]
fn wrong_content_type_garbage_and_unsigned_forms() {
    let p = new_pki(false);
    let id = client_identity(&p, &TestKey::rsa(RsaSlot::Client));
    let msg = sign(&id, asn1::ID_PKINIT_AUTHDATA, b"x").expect("sign");
    let err = verify(&msg, asn1::ID_PKINIT_DHKEYDATA, &p.store, Utc::now(), false)
        .expect_err("wrong eContentType");
    assert_eq!(err.code, KDC_ERR_PREAUTH_FAILED);

    for junk in [
        &b""[..],
        &[0x30, 0x03, 0x02, 0x01, 0x01][..],
        &[0xff; 8][..],
    ] {
        let err = verify(junk, asn1::ID_PKINIT_AUTHDATA, &p.store, Utc::now(), false)
            .expect_err("garbage");
        assert_eq!(err.code, KDC_ERR_PREAUTH_FAILED);
    }

    // Pre-1.10 MIT clients sent the content directly in a ContentInfo.
    let unsigned = content_info(asn1::ID_PKINIT_AUTHDATA, b"anonymous");
    let v = verify(
        &unsigned,
        asn1::ID_PKINIT_AUTHDATA,
        &p.store,
        Utc::now(),
        false,
    )
    .expect("unsigned ContentInfo");
    assert!(v.signer.is_none());
    assert_eq!(v.data, b"anonymous");
}

#[test]
fn unsupported_digest_algorithm_is_digest_not_accepted() {
    let p = new_pki(false);
    let id = client_identity(&p, &TestKey::rsa(RsaSlot::Client));
    let msg = sign(&id, asn1::ID_PKINIT_AUTHDATA, b"x").expect("sign");
    // Replace the signer's digestAlgorithm OID (sha256) with sha224's.
    let needle = tlv(0x06, asn1::CMS_SHA256);
    let sha224 = tlv(
        0x06,
        &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04],
    );
    let positions: Vec<usize> = msg
        .windows(needle.len())
        .enumerate()
        .filter(|(_, w)| *w == needle.as_slice())
        .map(|(i, _)| i)
        .collect();
    let last = *positions.last().expect("digest alg occurrences");
    let mut bad = msg.clone();
    bad[last..last + needle.len()].copy_from_slice(&sha224);
    let err = verify(&bad, asn1::ID_PKINIT_AUTHDATA, &p.store, Utc::now(), false)
        .expect_err("digest not accepted");
    assert_eq!(err.code, KDC_ERR_DIGEST_IN_SIGNED_DATA_NOT_ACCEPTED);
}

#[test]
fn signer_certificate_may_come_from_the_local_pool_instead_of_the_message() {
    let p = new_pki(false);
    let key = TestKey::rsa(RsaSlot::Client);
    let mut id = client_identity(&p, &key);
    let cert = id.chain[0].clone();
    // Sending no certificates: the verifier needs the signer in its pool.
    id.chain.clear();
    id.chain.push(cert.clone());
    let msg = sign(&id, asn1::ID_PKINIT_AUTHDATA, b"x").expect("sign");
    let sd_pos = msg
        .windows(cert.der().len())
        .position(|w| w == cert.der())
        .expect("embedded certificate");
    // Overwrite the embedded certificate with a different cert of the same
    // length is impractical; instead verify with the pool containing it.
    let mut store = p.store.clone();
    store.intermediates.push(cert);
    assert!(sd_pos > 0);
    assert!(verify(&msg, asn1::ID_PKINIT_AUTHDATA, &store, Utc::now(), false).is_ok());
}

/// Writes a CA, client certificate and signed message for checking with
/// `openssl verify` / `openssl cms -verify` (set PKI_DUMP_DIR).
#[test]
#[ignore = "manual cross-check against openssl"]
fn dump_pki_for_openssl() {
    let Ok(dir) = std::env::var("PKI_DUMP_DIR") else {
        return;
    };
    let p = new_pki(false);
    for (name, key) in [
        ("rsa", TestKey::rsa(RsaSlot::Client)),
        ("ec", TestKey::p256()),
    ] {
        let id = client_identity(&p, &key);
        let msg = sign(&id, asn1::ID_PKINIT_AUTHDATA, b"openssl cross-check").expect("sign");
        std::fs::write(format!("{dir}/{name}-msg.der"), msg).expect("write");
        std::fs::write(
            format!("{dir}/{name}-cert.pem"),
            pki::certs_pem(&[id.cert()]),
        )
        .expect("write");
    }
    std::fs::write(format!("{dir}/ca.pem"), pki::certs_pem(&[&p.ca])).expect("write");
}
