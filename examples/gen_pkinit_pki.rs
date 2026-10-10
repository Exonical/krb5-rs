//! Regenerates the committed PKINIT test PKI in `tests/kdc/pki/`.
//!
//! TESTING ONLY: the keys are unprotected and (for RSA) fixed in the source.
//!
//! ```sh
//! cargo run --features test-pki --example gen_pkinit_pki -- tests/kdc/pki
//! ```

use std::path::PathBuf;

use chrono::{Duration, Utc};
use krb5_rs::pkinit::pki::{self, CertSpec, RsaSlot, SanSpec, TestKey};
use krb5_rs::pkinit::x509::Cert;
use krb5_rs::types::PrincipalName;

const TEST_REALM: &str = "TEST.REALM";
const PKI_REALM: &str = "PKI.REALM";

struct Out {
    dir: PathBuf,
}

impl Out {
    fn cert(&self, name: &str, cert: &Cert) {
        std::fs::write(
            self.dir.join(format!("{name}.pem")),
            pki::certs_pem(&[cert]),
        )
        .expect("write certificate");
    }

    fn key(&self, name: &str, key: &TestKey) {
        std::fs::write(self.dir.join(format!("{name}-key.pem")), key.pem()).expect("write key");
    }
}

fn long_lived(mut spec: CertSpec) -> CertSpec {
    spec.not_before = Utc::now() - Duration::days(1);
    spec.not_after = Utc::now() + Duration::days(365 * 20);
    spec
}

fn main() {
    let dir = PathBuf::from(
        std::env::args()
            .nth(1)
            .unwrap_or_else(|| "tests/kdc/pki".into()),
    );
    std::fs::create_dir_all(&dir).expect("create output directory");
    let out = Out { dir };

    let ca_key = TestKey::rsa(RsaSlot::Ca);
    let ca = pki::issue(
        &long_lived(CertSpec::ca("krb5-rs PKINIT Test CA", 1)),
        &ca_key,
        None,
        &ca_key,
    );
    out.cert("ca", &ca);

    let rogue_key = TestKey::rsa(RsaSlot::Client2);
    let rogue = pki::issue(
        &long_lived(CertSpec::ca("krb5-rs Rogue Test CA", 1)),
        &rogue_key,
        None,
        &rogue_key,
    );
    out.cert("rogue-ca", &rogue);

    let kdc_key = TestKey::rsa(RsaSlot::Kdc);
    out.key("kdc", &kdc_key);
    for (name, realm, serial) in [
        ("kdc-test-realm", TEST_REALM, 10),
        ("kdc-pki-realm", PKI_REALM, 11),
    ] {
        let cert = pki::issue(
            &long_lived(CertSpec::kdc(
                &format!("kdc.{}", realm.to_lowercase()),
                serial,
                realm,
            )),
            &kdc_key,
            Some(&ca),
            &ca_key,
        );
        out.cert(name, &cert);
    }

    let rsa_key = TestKey::rsa(RsaSlot::Client);
    out.key("client-rsa", &rsa_key);
    let ec_key = TestKey::p256();
    out.key("client-ec", &ec_key);
    let mut serial = 100;
    let mut client = |out: &Out,
                      name: &str,
                      user: &str,
                      realm: &str,
                      key: &TestKey,
                      issuer: (&Cert, &TestKey)| {
        serial += 1;
        let principal = PrincipalName::new_principal(user);
        let cert = pki::issue(
            &long_lived(CertSpec::client(user, serial, &principal, realm)),
            key,
            Some(issuer.0),
            issuer.1,
        );
        out.cert(name, &cert);
    };
    let good = (&ca, &ca_key);
    client(&out, "testuser-rsa", "testuser", TEST_REALM, &rsa_key, good);
    client(&out, "testuser-ec", "testuser", TEST_REALM, &ec_key, good);
    client(&out, "pkiuser-rsa", "pkiuser", PKI_REALM, &rsa_key, good);
    client(&out, "pkiuser-ec", "pkiuser", PKI_REALM, &ec_key, good);
    // A certificate for another principal, presented as testuser/pkiuser.
    client(
        &out,
        "otheruser-rsa",
        "otheruser",
        TEST_REALM,
        &rsa_key,
        good,
    );
    client(
        &out,
        "otheruser-pki-rsa",
        "otheruser",
        PKI_REALM,
        &rsa_key,
        good,
    );
    // Issued by a CA nobody trusts.
    let bad = (&rogue, &rogue_key);
    client(
        &out,
        "rogue-testuser-rsa",
        "testuser",
        TEST_REALM,
        &rsa_key,
        bad,
    );
    client(
        &out,
        "rogue-pkiuser-rsa",
        "pkiuser",
        PKI_REALM,
        &rsa_key,
        bad,
    );

    // A UPN-only certificate for pkiuser.
    let mut upn = long_lived(CertSpec::client(
        "pkiuser",
        200,
        &PrincipalName::new_principal("pkiuser"),
        PKI_REALM,
    ));
    upn.sans = vec![SanSpec::Upn(format!("pkiuser@{PKI_REALM}"))];
    out.cert(
        "pkiuser-upn-rsa",
        &pki::issue(&upn, &rsa_key, Some(&ca), &ca_key),
    );
}
