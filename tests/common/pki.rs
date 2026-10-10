//! Test PKI for PKINIT: a CA plus KDC and client certificates built with the
//! library's own issuer (`krb5_rs::pkinit::pki`). Certificates and keys can be
//! written as PEM files for other implementations to consume.
#![cfg(feature = "test-pki")]

use std::path::{Path, PathBuf};

pub use krb5_rs::pkinit::cms::Identity;
pub use krb5_rs::pkinit::pki::{self, CertSpec, RsaSlot, TestKey};
pub use krb5_rs::pkinit::x509::{Cert, TrustStore};

use krb5_rs::types::PrincipalName;

/// A CA and the identities issued from it.
pub struct Ca {
    pub cert: Cert,
    pub key: TestKey,
}

impl Ca {
    /// A fresh RSA CA named `cn`.
    pub fn new(cn: &str, slot: RsaSlot) -> Ca {
        let key = TestKey::rsa(slot);
        let cert = pki::issue(&CertSpec::ca(cn, 1), &key, None, &key);
        Ca { cert, key }
    }

    /// Issue `spec` for `subject_key`.
    pub fn issue(&self, spec: &CertSpec, subject_key: &TestKey) -> Cert {
        pki::issue(spec, subject_key, Some(&self.cert), &self.key)
    }

    /// An identity for `spec` with `key`.
    pub fn identity(&self, spec: &CertSpec, key: &TestKey) -> Identity {
        pki::identity(vec![self.issue(spec, key)], key)
    }

    /// A client identity for `principal@realm`.
    pub fn client(
        &self,
        serial: u64,
        principal: &str,
        realm: &str,
        key: &TestKey,
    ) -> (Identity, Cert) {
        let name = PrincipalName::new_principal(principal);
        let cert = self.issue(&CertSpec::client(principal, serial, &name, realm), key);
        (pki::identity(vec![cert.clone()], key), cert)
    }

    /// A KDC identity for `krbtgt/realm`.
    pub fn kdc(&self, serial: u64, realm: &str, key: &TestKey) -> Identity {
        self.identity(&CertSpec::kdc("kdc", serial, realm), key)
    }

    /// Trust only this CA.
    pub fn store(&self) -> TrustStore {
        TrustStore {
            anchors: vec![self.cert.clone()],
            ..TrustStore::default()
        }
    }

    /// Write `ca.pem` into `dir`.
    pub fn write_ca_pem(&self, dir: &Path) -> PathBuf {
        let path = dir.join("ca.pem");
        std::fs::write(&path, pki::certs_pem(&[&self.cert])).expect("write ca.pem");
        path
    }
}

/// Write `cert` and `key` as `<name>.pem` / `<name>-key.pem` in `dir`.
pub fn write_identity_pem(
    dir: &Path,
    name: &str,
    cert: &Cert,
    key: &TestKey,
) -> (PathBuf, PathBuf) {
    let cert_path = dir.join(format!("{name}.pem"));
    let key_path = dir.join(format!("{name}-key.pem"));
    std::fs::write(&cert_path, pki::certs_pem(&[cert])).expect("write cert");
    std::fs::write(&key_path, key.pem()).expect("write key");
    (cert_path, key_path)
}
