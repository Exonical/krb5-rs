//! A small certificate and CRL issuer for tests and tooling: self-signed CAs,
//! KDC and client certificates with the extensions PKINIT looks at
//! (id-pkinit-san, UPN, dNSName, EKU, keyUsage, basicConstraints).
//!
//! It is not a general CA: names are single-CN, there are no authority or
//! subject key identifiers, and RSA test keys are fixed (see
//! `pki_keys.rs`) because RSA key generation is slow in debug builds.

use chrono::{DateTime, Datelike, Timelike, Utc};
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey};
use rsa::RsaPrivateKey;

use super::asn1;
use super::cms::Identity;
use super::der::{self, tlv};
use super::pem;
use super::pki_keys;
use super::x509::{Cert, Hash, PrivateKey};
use crate::types::PrincipalName;

/// Which fixed RSA test key to use.
#[derive(Debug, Clone, Copy)]
pub enum RsaSlot {
    /// CA key.
    Ca,
    /// KDC key.
    Kdc,
    /// Client key.
    Client,
    /// A second client key.
    Client2,
}

/// A test key pair and its PEM encoding.
pub struct TestKey {
    /// The private key.
    pub key: PrivateKey,
    pem: String,
    spki: Vec<u8>,
}

impl TestKey {
    /// One of the fixed RSA-2048 keys.
    pub fn rsa(slot: RsaSlot) -> TestKey {
        let pem_text = match slot {
            RsaSlot::Ca => pki_keys::RSA_CA,
            RsaSlot::Kdc => pki_keys::RSA_KDC,
            RsaSlot::Client => pki_keys::RSA_CLIENT,
            RsaSlot::Client2 => pki_keys::RSA_CLIENT2,
        };
        let der = &pem::decode_all(pem_text)[0].1;
        let key = RsaPrivateKey::from_pkcs8_der(der)
            .or_else(|_| RsaPrivateKey::from_pkcs1_der(der))
            .expect("valid built-in key");
        let spki = key
            .to_public_key()
            .to_public_key_der()
            .expect("public key encodes")
            .as_bytes()
            .to_vec();
        TestKey {
            key: PrivateKey::Rsa(Box::new(key)),
            pem: pem_text.to_string(),
            spki,
        }
    }

    fn ec_spki(curve_oid: &[u8], point: &[u8]) -> Vec<u8> {
        let alg = tlv(
            0x30,
            &[tlv(0x06, asn1::ID_EC_PUBLIC_KEY), tlv(0x06, curve_oid)].concat(),
        );
        let mut bits = vec![0u8];
        bits.extend_from_slice(point);
        tlv(0x30, &[alg, tlv(0x03, &bits)].concat())
    }

    /// A fresh P-256 key.
    pub fn p256() -> TestKey {
        use p256::elliptic_curve::Generate;
        let sk = p256::SecretKey::generate_from_rng(&mut rand::rng());
        let point = sk.public_key().to_sec1_bytes();
        TestKey {
            pem: pem::encode("PRIVATE KEY", sk.to_pkcs8_der().expect("pkcs8").as_bytes()),
            spki: Self::ec_spki(asn1::SECP256R1, &point),
            key: PrivateKey::P256(sk),
        }
    }

    /// A fresh P-384 key.
    pub fn p384() -> TestKey {
        use p384::elliptic_curve::Generate;
        let sk = p384::SecretKey::generate_from_rng(&mut rand::rng());
        let point = sk.public_key().to_sec1_bytes();
        TestKey {
            pem: pem::encode("PRIVATE KEY", sk.to_pkcs8_der().expect("pkcs8").as_bytes()),
            spki: Self::ec_spki(asn1::SECP384R1, &point),
            key: PrivateKey::P384(sk),
        }
    }

    /// A fresh P-521 key.
    pub fn p521() -> TestKey {
        use p521::elliptic_curve::Generate;
        let sk = p521::SecretKey::generate_from_rng(&mut rand::rng());
        let point = sk.public_key().to_sec1_bytes();
        TestKey {
            pem: pem::encode("PRIVATE KEY", sk.to_pkcs8_der().expect("pkcs8").as_bytes()),
            spki: Self::ec_spki(asn1::SECP521R1, &point),
            key: PrivateKey::P521(sk),
        }
    }

    /// The private key as PEM.
    pub fn pem(&self) -> &str {
        &self.pem
    }
}

/// A subject alternative name to put in a certificate.
#[derive(Debug, Clone)]
pub enum SanSpec {
    /// id-pkinit-san with the given principal and realm.
    Pkinit(PrincipalName, String),
    /// Microsoft UPN.
    Upn(String),
    /// dNSName.
    Dns(String),
}

/// Certificate contents.
#[derive(Debug, Clone)]
pub struct CertSpec {
    /// Subject CN.
    pub subject_cn: String,
    /// Serial number.
    pub serial: u64,
    /// Start of validity.
    pub not_before: DateTime<Utc>,
    /// End of validity.
    pub not_after: DateTime<Utc>,
    /// `Some(pathlen)` makes this a CA (basicConstraints cA=TRUE).
    pub ca: Option<Option<u32>>,
    /// keyUsage first byte (0x80 digitalSignature, 0x04 keyCertSign);
    /// `None` omits the extension.
    pub key_usage: Option<u8>,
    /// extendedKeyUsage OIDs (DER content bytes); `None` omits it.
    pub eku: Option<Vec<Vec<u8>>>,
    /// Subject alternative names.
    pub sans: Vec<SanSpec>,
    /// Digest for the signature.
    pub hash: Hash,
}

impl CertSpec {
    /// A valid-for-a-day certificate with no extensions.
    pub fn new(subject_cn: &str, serial: u64) -> CertSpec {
        let now = Utc::now();
        CertSpec {
            subject_cn: subject_cn.to_string(),
            serial,
            not_before: now - chrono::Duration::hours(1),
            not_after: now + chrono::Duration::days(1),
            ca: None,
            key_usage: None,
            eku: None,
            sans: Vec::new(),
            hash: Hash::Sha256,
        }
    }

    /// A CA certificate.
    pub fn ca(cn: &str, serial: u64) -> CertSpec {
        CertSpec {
            ca: Some(None),
            key_usage: Some(0x04 | 0x02),
            ..CertSpec::new(cn, serial)
        }
    }

    /// A client certificate for `principal@realm` (pkinit SAN,
    /// digitalSignature, id-pkinit-KPClientAuth).
    pub fn client(cn: &str, serial: u64, principal: &PrincipalName, realm: &str) -> CertSpec {
        CertSpec {
            key_usage: Some(0x80),
            eku: Some(vec![asn1::ID_PKINIT_KP_CLIENT_AUTH.to_vec()]),
            sans: vec![SanSpec::Pkinit(principal.clone(), realm.to_string())],
            ..CertSpec::new(cn, serial)
        }
    }

    /// A KDC certificate for `krbtgt/REALM@REALM` (pkinit SAN,
    /// digitalSignature, id-pkinit-KPKdc).
    pub fn kdc(cn: &str, serial: u64, realm: &str) -> CertSpec {
        let tgs = PrincipalName {
            name_type: 2,
            name_string: ["krbtgt", realm]
                .iter()
                .map(|s| rasn::types::GeneralString::from_bytes(s.as_bytes()).expect("string"))
                .collect(),
        };
        CertSpec {
            key_usage: Some(0x80),
            eku: Some(vec![asn1::ID_PKINIT_KP_KDC.to_vec()]),
            sans: vec![SanSpec::Pkinit(tgs, realm.to_string())],
            ..CertSpec::new(cn, serial)
        }
    }
}

/// DER Name with a single CN (UTF8String).
pub fn name_der(cn: &str) -> Vec<u8> {
    let atv = tlv(
        0x30,
        &[tlv(0x06, &[0x55, 0x04, 0x03]), tlv(0x0C, cn.as_bytes())].concat(),
    );
    tlv(0x30, &tlv(0x31, &atv))
}

fn time_der(t: DateTime<Utc>) -> Vec<u8> {
    let (tag, text) = if (1950..2050).contains(&t.year()) {
        (
            0x17,
            format!(
                "{:02}{:02}{:02}{:02}{:02}{:02}Z",
                t.year() % 100,
                t.month(),
                t.day(),
                t.hour(),
                t.minute(),
                t.second()
            ),
        )
    } else {
        (
            0x18,
            format!(
                "{:04}{:02}{:02}{:02}{:02}{:02}Z",
                t.year(),
                t.month(),
                t.day(),
                t.hour(),
                t.minute(),
                t.second()
            ),
        )
    };
    tlv(tag, text.as_bytes())
}

fn san_der(sans: &[SanSpec]) -> Vec<u8> {
    let mut body = Vec::new();
    for s in sans {
        match s {
            SanSpec::Pkinit(p, realm) => {
                let der = rasn::der::encode(&asn1::Krb5PrincipalName {
                    realm: rasn::types::GeneralString::from_bytes(realm.as_bytes()).expect("realm"),
                    principal_name: p.clone(),
                })
                .expect("encodes");
                let on = [tlv(0x06, asn1::ID_PKINIT_SAN), tlv(0xA0, &der)].concat();
                body.extend(tlv(0xA0, &on));
            }
            SanSpec::Upn(u) => {
                let on = [
                    tlv(0x06, asn1::ID_MS_SAN_UPN),
                    tlv(0xA0, &tlv(0x0C, u.as_bytes())),
                ]
                .concat();
                body.extend(tlv(0xA0, &on));
            }
            SanSpec::Dns(d) => body.extend(tlv(0x82, d.as_bytes())),
        }
    }
    tlv(0x30, &body)
}

fn extension(oid: &[u8], critical: bool, value: Vec<u8>) -> Vec<u8> {
    let mut c = tlv(0x06, oid);
    if critical {
        c.extend(tlv(0x01, &[0xFF]));
    }
    c.extend(tlv(0x04, &value));
    tlv(0x30, &c)
}

fn sig_alg_der(key: &PrivateKey, hash: Hash) -> Vec<u8> {
    let alg = key.signature_algorithm(hash);
    rasn::der::encode(&alg).expect("encodes")
}

/// Issue a certificate for `subject_key` signed by `issuer` (`None` for
/// self-signed) with `issuer_key`.
pub fn issue(
    spec: &CertSpec,
    subject_key: &TestKey,
    issuer: Option<&Cert>,
    issuer_key: &TestKey,
) -> Cert {
    let subject = name_der(&spec.subject_cn);
    let issuer_name = issuer.map_or_else(|| subject.clone(), |c| c.subject_der().to_vec());
    let sig_alg = sig_alg_der(&issuer_key.key, spec.hash);

    let mut exts = Vec::new();
    if let Some(path) = spec.ca {
        let mut bc = tlv(0x01, &[0xFF]);
        if let Some(p) = path {
            bc.extend(der::uint(&[p as u8]));
        }
        exts.extend(extension(asn1::EXT_BASIC_CONSTRAINTS, true, tlv(0x30, &bc)));
    }
    if let Some(ku) = spec.key_usage {
        let unused = ku.trailing_zeros().min(7) as u8;
        exts.extend(extension(
            asn1::EXT_KEY_USAGE_BITS,
            true,
            tlv(0x03, &[unused, ku]),
        ));
    }
    if let Some(eku) = &spec.eku {
        let body: Vec<u8> = eku.iter().flat_map(|o| tlv(0x06, o)).collect();
        exts.extend(extension(asn1::EXT_EXT_KEY_USAGE, false, tlv(0x30, &body)));
    }
    if !spec.sans.is_empty() {
        exts.extend(extension(
            asn1::EXT_SUBJECT_ALT_NAME,
            false,
            san_der(&spec.sans),
        ));
    }

    let mut tbs = tlv(0xA0, &der::uint(&[2]));
    tbs.extend(der::uint(&spec.serial.to_be_bytes()));
    tbs.extend(sig_alg.clone());
    tbs.extend(issuer_name);
    tbs.extend(tlv(
        0x30,
        &[time_der(spec.not_before), time_der(spec.not_after)].concat(),
    ));
    tbs.extend(subject);
    tbs.extend(subject_key.spki.clone());
    if !exts.is_empty() {
        tbs.extend(tlv(0xA3, &tlv(0x30, &exts)));
    }
    let tbs = tlv(0x30, &tbs);
    let signature = issuer_key
        .key
        .sign(spec.hash, &tbs)
        .expect("signing a test certificate");
    let mut sig_bits = vec![0u8];
    sig_bits.extend(signature);
    let cert = tlv(0x30, &[tbs, sig_alg, tlv(0x03, &sig_bits)].concat());
    Cert::from_der(&cert).expect("issued certificate parses")
}

/// Issue a CRL from `issuer` listing `revoked` serial numbers.
pub fn issue_crl(
    issuer: &Cert,
    issuer_key: &TestKey,
    revoked: &[u64],
    this_update: DateTime<Utc>,
    next_update: DateTime<Utc>,
) -> Vec<u8> {
    let sig_alg = sig_alg_der(&issuer_key.key, Hash::Sha256);
    let mut tbs = der::uint(&[1]);
    tbs.extend(sig_alg.clone());
    tbs.extend(issuer.subject_der());
    tbs.extend(time_der(this_update));
    tbs.extend(time_der(next_update));
    if !revoked.is_empty() {
        let entries: Vec<u8> = revoked
            .iter()
            .flat_map(|s| {
                tlv(
                    0x30,
                    &[der::uint(&s.to_be_bytes()), time_der(this_update)].concat(),
                )
            })
            .collect();
        tbs.extend(tlv(0x30, &entries));
    }
    let tbs = tlv(0x30, &tbs);
    let signature = issuer_key
        .key
        .sign(Hash::Sha256, &tbs)
        .expect("signing a test CRL");
    let mut sig_bits = vec![0u8];
    sig_bits.extend(signature);
    tlv(0x30, &[tbs, sig_alg, tlv(0x03, &sig_bits)].concat())
}

/// PEM encoding of a CRL.
pub fn crl_pem(der: &[u8]) -> String {
    pem::encode("X509 CRL", der)
}

/// PEM encoding of certificates.
pub fn certs_pem(certs: &[&Cert]) -> String {
    certs
        .iter()
        .map(|c| pem::encode("CERTIFICATE", c.der()))
        .collect()
}

/// An identity from a certificate and the key it was issued for.
pub fn identity(chain: Vec<Cert>, key: &TestKey) -> Identity {
    Identity {
        chain,
        key: PrivateKey::from_pem(key.pem()).expect("test key parses"),
    }
}
