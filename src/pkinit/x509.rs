//! X.509 certificates, keys and path validation, implementing the
//! OpenSSL `X509_verify_cert` semantics MIT relies on (pkinit_crypto_openssl.c
//! `cms_signeddata_verify` :2058-2157, `openssl_callback*` :3354-3371).

use chrono::{DateTime, Utc};
use rasn::types::ObjectIdentifier;
use rasn_pkix::{AlgorithmIdentifier, Certificate, CertificateList, SubjectPublicKeyInfo, Time};
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::pkcs8::{DecodePrivateKey, DecodePublicKey};
use rsa::{Pkcs1v15Sign, RsaPrivateKey, RsaPublicKey};
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha384, Sha512};

use super::asn1::{self, ID_PKINIT_SAN};
use super::der;
use super::pem;
use crate::types::PrincipalName;

/// A digest algorithm used in certificates and CMS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Hash {
    /// SHA-1.
    Sha1,
    /// SHA-256.
    Sha256,
    /// SHA-384.
    Sha384,
    /// SHA-512.
    Sha512,
}

impl Hash {
    /// Digest `data`.
    pub fn digest(self, data: &[u8]) -> Vec<u8> {
        match self {
            Hash::Sha1 => Sha1::digest(data).to_vec(),
            Hash::Sha256 => Sha256::digest(data).to_vec(),
            Hash::Sha384 => Sha384::digest(data).to_vec(),
            Hash::Sha512 => Sha512::digest(data).to_vec(),
        }
    }

    /// The CMS digest algorithm OID content bytes (`md_from_cms_oid`).
    pub fn oid_bytes(self) -> &'static [u8] {
        match self {
            Hash::Sha1 => asn1::CMS_SHA1,
            Hash::Sha256 => asn1::CMS_SHA256,
            Hash::Sha384 => asn1::CMS_SHA384,
            Hash::Sha512 => asn1::CMS_SHA512,
        }
    }

    /// Recognise a CMS digest algorithm OID.
    pub fn from_oid(id: &ObjectIdentifier) -> Option<Hash> {
        [Hash::Sha1, Hash::Sha256, Hash::Sha384, Hash::Sha512]
            .into_iter()
            .find(|h| asn1::is_oid(id, h.oid_bytes()))
    }

    /// PKCS#1 v1.5 DigestInfo prefix (RFC 8017 9.2 note 1).
    fn rsa_prefix(self) -> &'static [u8] {
        match self {
            Hash::Sha1 => &[
                0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04,
                0x14,
            ],
            Hash::Sha256 => &[
                0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x01, 0x05, 0x00, 0x04, 0x20,
            ],
            Hash::Sha384 => &[
                0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x02, 0x05, 0x00, 0x04, 0x30,
            ],
            Hash::Sha512 => &[
                0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x03, 0x05, 0x00, 0x04, 0x40,
            ],
        }
    }

    fn rsa_sig_oid(self) -> &'static [u8] {
        match self {
            Hash::Sha1 => asn1::SHA1_WITH_RSA,
            Hash::Sha256 => asn1::SHA256_WITH_RSA,
            Hash::Sha384 => asn1::SHA384_WITH_RSA,
            Hash::Sha512 => asn1::SHA512_WITH_RSA,
        }
    }

    fn ecdsa_sig_oid(self) -> &'static [u8] {
        match self {
            Hash::Sha1 => asn1::ECDSA_SHA1,
            Hash::Sha256 => asn1::ECDSA_SHA256,
            Hash::Sha384 => asn1::ECDSA_SHA384,
            Hash::Sha512 => asn1::ECDSA_SHA512,
        }
    }
}

/// A signature algorithm decoded from an AlgorithmIdentifier.
#[derive(Debug, Clone, Copy)]
enum SigAlg {
    Rsa(Hash),
    /// `rsaEncryption`: the digest comes from elsewhere (CMS digestAlgorithm).
    RsaUnspecified,
    Ecdsa(Hash),
}

fn sig_alg(a: &AlgorithmIdentifier) -> Option<SigAlg> {
    let all = [Hash::Sha1, Hash::Sha256, Hash::Sha384, Hash::Sha512];
    for h in all {
        if asn1::is_oid(&a.algorithm, h.rsa_sig_oid()) {
            return Some(SigAlg::Rsa(h));
        }
        if asn1::is_oid(&a.algorithm, h.ecdsa_sig_oid()) {
            return Some(SigAlg::Ecdsa(h));
        }
    }
    asn1::is_oid(&a.algorithm, asn1::RSA_ENCRYPTION).then_some(SigAlg::RsaUnspecified)
}

/// Verify `sig` over `data` with the public key in `spki`. `digest_hint` is
/// the CMS digestAlgorithm, used when the signature algorithm is plain
/// `rsaEncryption`.
pub fn verify_signature(
    spki: &SubjectPublicKeyInfo,
    alg: &AlgorithmIdentifier,
    digest_hint: Option<Hash>,
    data: &[u8],
    sig: &[u8],
) -> bool {
    let Some(alg) = sig_alg(alg) else {
        return false;
    };
    match alg {
        SigAlg::Rsa(_) | SigAlg::RsaUnspecified => {
            let hash = match alg {
                SigAlg::Rsa(h) => h,
                _ => match digest_hint {
                    Some(h) => h,
                    None => return false,
                },
            };
            let Ok(spki_der) = rasn::der::encode(spki) else {
                return false;
            };
            let Ok(key) = RsaPublicKey::from_public_key_der(&spki_der) else {
                return false;
            };
            let scheme = Pkcs1v15Sign {
                hash_len: Some(hash.digest(b"").len()),
                prefix: hash.rsa_prefix().into(),
            };
            key.verify(scheme, &hash.digest(data), sig).is_ok()
        }
        SigAlg::Ecdsa(hash) => {
            let digest = hash.digest(data);
            let point = spki.subject_public_key.as_raw_slice();
            let Some(params) = spki.algorithm.parameters.as_ref() else {
                return false;
            };
            let Some((oid_tlv, _)) = der::read(params.as_bytes()) else {
                return false;
            };
            macro_rules! ecdsa {
                ($m:ident) => {{
                    use $m::ecdsa::signature::hazmat::PrehashVerifier;
                    let Ok(vk) = $m::ecdsa::VerifyingKey::from_sec1_bytes(point) else {
                        return false;
                    };
                    let Ok(s) = $m::ecdsa::Signature::from_der(sig) else {
                        return false;
                    };
                    vk.verify_prehash(&digest, &s).is_ok()
                }};
            }
            match oid_tlv.content {
                c if c == asn1::SECP256R1 => ecdsa!(p256),
                c if c == asn1::SECP384R1 => ecdsa!(p384),
                c if c == asn1::SECP521R1 => ecdsa!(p521),
                _ => false,
            }
        }
    }
}

/// A private signing key (PKCS#8, PKCS#1 RSA or SEC1 EC).
pub enum PrivateKey {
    /// RSA.
    Rsa(Box<RsaPrivateKey>),
    /// NIST P-256.
    P256(p256::SecretKey),
    /// NIST P-384.
    P384(p384::SecretKey),
    /// NIST P-521.
    P521(p521::SecretKey),
}

impl PrivateKey {
    /// Parse the first private key in a PEM file; encrypted keys are not
    /// supported.
    pub fn from_pem(text: &str) -> Result<PrivateKey, String> {
        for (label, der) in pem::decode_all(text) {
            let key = match label.as_str() {
                "RSA PRIVATE KEY" => RsaPrivateKey::from_pkcs1_der(&der)
                    .ok()
                    .map(|k| PrivateKey::Rsa(Box::new(k))),
                "EC PRIVATE KEY" => Self::ec_sec1(&der),
                "PRIVATE KEY" => RsaPrivateKey::from_pkcs8_der(&der)
                    .ok()
                    .map(|k| PrivateKey::Rsa(Box::new(k)))
                    .or_else(|| Self::ec_pkcs8(&der)),
                "ENCRYPTED PRIVATE KEY" => {
                    return Err("encrypted private keys are not supported".into())
                }
                _ => continue,
            };
            return key.ok_or_else(|| format!("cannot parse {label}"));
        }
        Err("no private key found".into())
    }

    fn ec_sec1(der: &[u8]) -> Option<PrivateKey> {
        p256::SecretKey::from_sec1_der(der)
            .ok()
            .map(PrivateKey::P256)
            .or_else(|| {
                p384::SecretKey::from_sec1_der(der)
                    .ok()
                    .map(PrivateKey::P384)
            })
            .or_else(|| {
                p521::SecretKey::from_sec1_der(der)
                    .ok()
                    .map(PrivateKey::P521)
            })
    }

    fn ec_pkcs8(der: &[u8]) -> Option<PrivateKey> {
        p256::SecretKey::from_pkcs8_der(der)
            .ok()
            .map(PrivateKey::P256)
            .or_else(|| {
                p384::SecretKey::from_pkcs8_der(der)
                    .ok()
                    .map(PrivateKey::P384)
            })
            .or_else(|| {
                p521::SecretKey::from_pkcs8_der(der)
                    .ok()
                    .map(PrivateKey::P521)
            })
    }

    /// Whether this is an EC key (selects ecdsa-with-SHA256 in CMS,
    /// `cert_sig_alg`, :1699-1712).
    pub fn is_ec(&self) -> bool {
        !matches!(self, PrivateKey::Rsa(_))
    }

    /// The CMS signatureAlgorithm for `hash` with this key.
    pub fn signature_algorithm(&self, hash: Hash) -> AlgorithmIdentifier {
        if self.is_ec() {
            asn1::alg(hash.ecdsa_sig_oid())
        } else {
            asn1::alg_null(hash.rsa_sig_oid())
        }
    }

    /// Sign `data`, hashing it with `hash`.
    pub fn sign(&self, hash: Hash, data: &[u8]) -> Result<Vec<u8>, String> {
        let digest = hash.digest(data);
        macro_rules! ecdsa {
            ($m:ident, $k:expr) => {{
                use $m::ecdsa::signature::hazmat::PrehashSigner;
                let sk = $m::ecdsa::SigningKey::from($k);
                let sig: $m::ecdsa::Signature =
                    sk.sign_prehash(&digest).map_err(|e| e.to_string())?;
                Ok(sig.to_der().as_bytes().to_vec())
            }};
        }
        match self {
            PrivateKey::Rsa(k) => {
                let scheme = Pkcs1v15Sign {
                    hash_len: Some(digest.len()),
                    prefix: hash.rsa_prefix().into(),
                };
                k.sign(scheme, &digest).map_err(|e| e.to_string())
            }
            PrivateKey::P256(k) => ecdsa!(p256, k),
            PrivateKey::P384(k) => ecdsa!(p384, k),
            PrivateKey::P521(k) => ecdsa!(p521, k),
        }
    }
}

/// One Subject Alternative Name entry that PKINIT cares about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum San {
    /// id-pkinit-san KRB5PrincipalName.
    Pkinit(PrincipalName, String),
    /// Microsoft UPN otherName.
    Upn(String),
    /// dNSName.
    Dns(String),
}

/// A parsed X.509 certificate with the raw bytes needed for verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cert {
    der: Vec<u8>,
    cert: Certificate,
    tbs: Vec<u8>,
    subject: Vec<u8>,
    issuer: Vec<u8>,
    not_before: DateTime<Utc>,
    not_after: DateTime<Utc>,
    extensions: Vec<RawExtension>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RawExtension {
    oid: Vec<u8>,
    critical: bool,
    value: Vec<u8>,
}

fn time_to_utc(t: &Time) -> DateTime<Utc> {
    match t {
        Time::Utc(u) => *u,
        Time::General(g) => g.with_timezone(&Utc),
    }
}

impl Cert {
    /// Parse a DER certificate.
    pub fn from_der(der_bytes: &[u8]) -> Result<Cert, String> {
        let cert: Certificate = rasn::der::decode(der_bytes).map_err(|e| e.to_string())?;
        let (outer, _) = der::read(der_bytes).ok_or("bad certificate")?;
        let kids = der::children(outer.content).ok_or("bad certificate")?;
        let tbs = kids.first().ok_or("bad certificate")?;
        let fields = der::children(tbs.content).ok_or("bad TBS")?;
        let mut idx = 0;
        if fields.first().is_some_and(|f| f.tag == 0xA0) {
            idx = 1;
        }
        let issuer = fields.get(idx + 2).ok_or("bad TBS")?.whole.to_vec();
        let subject = fields.get(idx + 4).ok_or("bad TBS")?.whole.to_vec();
        let mut extensions = Vec::new();
        if let Some(ext_wrapper) = fields.iter().find(|f| f.tag == 0xA3) {
            let (seq, _) = der::read(ext_wrapper.content).ok_or("bad extensions")?;
            for e in der::children(seq.content).ok_or("bad extensions")? {
                let parts = der::children(e.content).ok_or("bad extension")?;
                let oid = parts.first().ok_or("bad extension")?.content.to_vec();
                let critical = parts
                    .get(1)
                    .is_some_and(|p| p.tag == 0x01 && p.content == [0xFF]);
                let value = parts.last().ok_or("bad extension")?.content.to_vec();
                extensions.push(RawExtension {
                    oid,
                    critical,
                    value,
                });
            }
        }
        let validity = &cert.tbs_certificate.validity;
        Ok(Cert {
            der: der_bytes.to_vec(),
            tbs: tbs.whole.to_vec(),
            subject,
            issuer,
            not_before: time_to_utc(&validity.not_before),
            not_after: time_to_utc(&validity.not_after),
            extensions,
            cert,
        })
    }

    /// Every certificate in a PEM file.
    pub fn all_from_pem(text: &str) -> Result<Vec<Cert>, String> {
        pem::decode_all(text)
            .into_iter()
            .filter(|(l, _)| {
                l == "CERTIFICATE" || l == "TRUSTED CERTIFICATE" || l == "X509 CERTIFICATE"
            })
            .map(|(_, d)| Cert::from_der(&d))
            .collect()
    }

    /// The DER encoding.
    pub fn der(&self) -> &[u8] {
        &self.der
    }

    /// The decoded certificate.
    pub fn certificate(&self) -> &Certificate {
        &self.cert
    }

    /// Raw DER of the issuer name.
    pub fn issuer_der(&self) -> &[u8] {
        &self.issuer
    }

    /// Raw DER of the subject name.
    pub fn subject_der(&self) -> &[u8] {
        &self.subject
    }

    /// Whether the certificate is self-issued (subject equals issuer).
    pub fn is_self_issued(&self) -> bool {
        self.subject == self.issuer
    }

    fn ext(&self, oid: &[u8]) -> Option<&RawExtension> {
        self.extensions.iter().find(|e| e.oid == oid)
    }

    /// basicConstraints: (cA, pathLenConstraint).
    fn basic_constraints(&self) -> Option<(bool, Option<u32>)> {
        let e = self.ext(asn1::EXT_BASIC_CONSTRAINTS)?;
        let (seq, _) = der::read(&e.value)?;
        let mut ca = false;
        let mut path = None;
        for k in der::children(seq.content)? {
            match k.tag {
                0x01 => ca = k.content == [0xFF],
                0x02 => {
                    path = Some(
                        der::uint_magnitude(k.content)
                            .iter()
                            .fold(0u32, |a, b| (a << 8) | u32::from(*b)),
                    )
                }
                _ => {}
            }
        }
        Some((ca, path))
    }

    /// The keyUsage bit string's first byte (bit 0 = digitalSignature).
    fn key_usage_byte(&self) -> Option<u8> {
        let e = self.ext(asn1::EXT_KEY_USAGE_BITS)?;
        let (bits, _) = der::read(&e.value)?;
        bits.content.get(1).copied().or(Some(0))
    }

    /// Whether keyUsage is present and includes digitalSignature
    /// (`ku_reject` is not satisfied only if the extension exists;
    /// pkinit_crypto_openssl.c:2564-2578).
    pub fn has_digital_signature_ku(&self) -> bool {
        self.key_usage_byte().is_some_and(|b| b & 0x80 != 0)
    }

    /// Extended key usage OIDs (DER content bytes), `None` without the
    /// extension.
    pub fn eku(&self) -> Option<Vec<Vec<u8>>> {
        let e = self.ext(asn1::EXT_EXT_KEY_USAGE)?;
        let (seq, _) = der::read(&e.value)?;
        Some(
            der::children(seq.content)?
                .into_iter()
                .filter(|k| k.tag == 0x06)
                .map(|k| k.content.to_vec())
                .collect(),
        )
    }

    /// Subject alternative names of the kinds PKINIT uses
    /// (`crypto_retrieve_X509_sans`, :3375-3560).
    pub fn sans(&self) -> Vec<San> {
        let mut out = Vec::new();
        let Some(e) = self.ext(asn1::EXT_SUBJECT_ALT_NAME) else {
            return out;
        };
        let Some((seq, _)) = der::read(&e.value) else {
            return out;
        };
        for name in der::children(seq.content).unwrap_or_default() {
            match name.tag {
                0xA0 => {
                    let Some(parts) = der::children(name.content) else {
                        continue;
                    };
                    let (Some(id), Some(val)) = (parts.first(), parts.get(1)) else {
                        continue;
                    };
                    let Some((inner, _)) = der::read(val.content) else {
                        continue;
                    };
                    if id.content == ID_PKINIT_SAN {
                        if let Ok(p) = rasn::der::decode::<asn1::Krb5PrincipalName>(inner.whole) {
                            out.push(San::Pkinit(
                                p.principal_name,
                                String::from_utf8_lossy(p.realm.as_bytes()).to_string(),
                            ));
                        }
                    } else if id.content == asn1::ID_MS_SAN_UPN {
                        out.push(San::Upn(String::from_utf8_lossy(inner.content).to_string()));
                    }
                }
                0x82 => out.push(San::Dns(String::from_utf8_lossy(name.content).to_string())),
                _ => {}
            }
        }
        out
    }

    /// The subject public key.
    pub fn spki(&self) -> &SubjectPublicKeyInfo {
        &self.cert.tbs_certificate.subject_public_key_info
    }

    /// Whether the certificate is an EC certificate (for CMS signatures).
    pub fn is_ec(&self) -> bool {
        asn1::is_oid(&self.spki().algorithm.algorithm, asn1::ID_EC_PUBLIC_KEY)
    }

    /// Verify this certificate's signature with `issuer`'s key.
    fn signed_by(&self, issuer: &Cert) -> bool {
        verify_signature(
            issuer.spki(),
            &self.cert.signature_algorithm,
            None,
            &self.tbs,
            self.cert.signature_value.as_raw_slice(),
        )
    }

    /// Serial number as a magnitude.
    fn serial(&self) -> Vec<u8> {
        let d = rasn::der::encode(&self.cert.tbs_certificate.serial_number).unwrap_or_default();
        der::read(&d)
            .map(|(t, _)| der::uint_magnitude(t.content).to_vec())
            .unwrap_or_default()
    }

    /// The validity period.
    pub fn validity(&self) -> (DateTime<Utc>, DateTime<Utc>) {
        (self.not_before, self.not_after)
    }
}

/// A parsed CRL.
#[derive(Debug, Clone)]
pub struct Crl {
    issuer: Vec<u8>,
    tbs: Vec<u8>,
    list: CertificateList,
    next_update: Option<DateTime<Utc>>,
    this_update: DateTime<Utc>,
}

impl Crl {
    /// Parse a DER CRL.
    pub fn from_der(der_bytes: &[u8]) -> Result<Crl, String> {
        let list: CertificateList = rasn::der::decode(der_bytes).map_err(|e| e.to_string())?;
        let (outer, _) = der::read(der_bytes).ok_or("bad CRL")?;
        let kids = der::children(outer.content).ok_or("bad CRL")?;
        let tbs = kids.first().ok_or("bad CRL")?;
        let fields = der::children(tbs.content).ok_or("bad TBS CRL")?;
        // version is optional (INTEGER), then signature, issuer.
        let skip = usize::from(fields.first().is_some_and(|f| f.tag == 0x02));
        let issuer = fields.get(skip + 1).ok_or("bad TBS CRL")?.whole.to_vec();
        Ok(Crl {
            issuer,
            tbs: tbs.whole.to_vec(),
            next_update: list.tbs_cert_list.next_update.as_ref().map(time_to_utc),
            this_update: time_to_utc(&list.tbs_cert_list.this_update),
            list,
        })
    }

    /// Every CRL in a PEM file.
    pub fn all_from_pem(text: &str) -> Result<Vec<Crl>, String> {
        pem::decode_all(text)
            .into_iter()
            .filter(|(l, _)| l == "X509 CRL")
            .map(|(_, d)| Crl::from_der(&d))
            .collect()
    }
}

/// Anchors, intermediates and CRLs (MIT `idctx->trustedCAs`,
/// `intermediateCAs`, `revoked`).
#[derive(Debug, Clone, Default)]
pub struct TrustStore {
    /// Trusted CA certificates (pkinit_anchors).
    pub anchors: Vec<Cert>,
    /// Untrusted intermediates (pkinit_pool).
    pub intermediates: Vec<Cert>,
    /// Revocation lists (pkinit_revoke).
    pub crls: Vec<Crl>,
}

impl TrustStore {
    /// Load a `FILE:` or `DIR:` anchors/pool specification, adding
    /// certificates (and CRLs) found there.
    pub fn load(&mut self, spec: &str, into_anchors: bool) -> Result<(), String> {
        let (kind, path) = spec
            .split_once(':')
            .ok_or_else(|| format!("unsupported identity specification {spec:?}"))?;
        let mut files = Vec::new();
        match kind {
            "FILE" => files.push(std::path::PathBuf::from(path)),
            "DIR" => {
                for entry in std::fs::read_dir(path).map_err(|e| format!("{path}: {e}"))? {
                    let p = entry.map_err(|e| e.to_string())?.path();
                    if p.is_file() {
                        files.push(p);
                    }
                }
            }
            "PKCS11" | "PKCS12" | "ENV" => {
                return Err(format!("{kind} identities are not supported"));
            }
            _ => return Err(format!("unsupported identity specification {spec:?}")),
        }
        for f in files {
            let text = std::fs::read_to_string(&f).map_err(|e| format!("{}: {e}", f.display()))?;
            let certs = Cert::all_from_pem(&text)?;
            if into_anchors {
                self.anchors.extend(certs);
            } else {
                self.intermediates.extend(certs);
            }
            self.crls.extend(Crl::all_from_pem(&text)?);
        }
        Ok(())
    }

    /// Load CRLs from a `FILE:`/`DIR:` pkinit_revoke specification.
    pub fn load_crls(&mut self, spec: &str) -> Result<(), String> {
        let (kind, path) = spec
            .split_once(':')
            .ok_or_else(|| format!("unsupported revoke specification {spec:?}"))?;
        let mut files = Vec::new();
        match kind {
            "FILE" => files.push(std::path::PathBuf::from(path)),
            "DIR" => {
                for entry in std::fs::read_dir(path).map_err(|e| format!("{path}: {e}"))? {
                    let p = entry.map_err(|e| e.to_string())?.path();
                    if p.is_file() {
                        files.push(p);
                    }
                }
            }
            _ => return Err(format!("unsupported revoke specification {spec:?}")),
        }
        for f in files {
            let text = std::fs::read_to_string(&f).map_err(|e| format!("{}: {e}", f.display()))?;
            self.crls.extend(Crl::all_from_pem(&text)?);
        }
        Ok(())
    }
}

/// Why path validation failed, with the MIT error each maps to
/// (pkinit_crypto_openssl.c:2132-2151).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum VerifyError {
    /// `X509_V_ERR_CERT_REVOKED` -> KDC_ERR_REVOKED_CERTIFICATE.
    #[error("certificate revoked")]
    Revoked,
    /// `X509_V_ERR_UNABLE_TO_GET_CRL` -> KDC_ERR_REVOCATION_STATUS_UNKNOWN.
    #[error("unable to get CRL")]
    CrlUnavailable,
    /// Issuer not found -> KDC_ERR_CANT_VERIFY_CERTIFICATE.
    #[error("unable to get issuer certificate")]
    NoIssuer,
    /// Anything else -> KDC_ERR_INVALID_CERTIFICATE.
    #[error("invalid certificate: {0}")]
    Invalid(&'static str),
}

const MAX_DEPTH: usize = 100;

/// OpenSSL's default handling of critical extensions: known ones pass.
fn check_critical(c: &Cert) -> Result<(), VerifyError> {
    const KNOWN: &[&[u8]] = &[
        asn1::EXT_BASIC_CONSTRAINTS,
        asn1::EXT_KEY_USAGE_BITS,
        asn1::EXT_SUBJECT_ALT_NAME,
        asn1::EXT_EXT_KEY_USAGE,
        &[0x55, 0x1D, 0x0E],
        &[0x55, 0x1D, 0x23],
        &[0x55, 0x1D, 0x1F],
        &[0x55, 0x1D, 0x20],
    ];
    for e in &c.extensions {
        if e.critical && !KNOWN.contains(&e.oid.as_slice()) {
            return Err(VerifyError::Invalid("unhandled critical extension"));
        }
    }
    Ok(())
}

fn check_validity(c: &Cert, now: DateTime<Utc>) -> Result<(), VerifyError> {
    if now < c.not_before {
        return Err(VerifyError::Invalid("certificate is not yet valid"));
    }
    if now > c.not_after {
        return Err(VerifyError::Invalid("certificate has expired"));
    }
    Ok(())
}

/// `X509_check_ca`-style CA checks for an issuing certificate with `below`
/// non-self-issued intermediates beneath it.
fn check_ca(c: &Cert, below: u32) -> Result<(), VerifyError> {
    match c.basic_constraints() {
        Some((true, path)) => {
            if path.is_some_and(|p| below > p) {
                return Err(VerifyError::Invalid("path length constraint exceeded"));
            }
        }
        Some((false, _)) => return Err(VerifyError::Invalid("issuer is not a CA")),
        None => return Err(VerifyError::Invalid("issuer has no basicConstraints")),
    }
    if let Some(ku) = c.key_usage_byte() {
        // keyCertSign is bit 5.
        if ku & 0x04 == 0 {
            return Err(VerifyError::Invalid("issuer keyUsage lacks keyCertSign"));
        }
    }
    Ok(())
}

fn crl_for<'a>(store: &'a TrustStore, issuer_name: &[u8], issuer_cert: &Cert) -> Option<&'a Crl> {
    store.crls.iter().find(|crl| {
        crl.issuer == issuer_name
            && verify_signature(
                issuer_cert.spki(),
                &crl.list.signature_algorithm,
                None,
                &crl.tbs,
                crl.list.signature.as_raw_slice(),
            )
    })
}

/// Verify `leaf` against `store`, using `untrusted` (certificates received in
/// the message) as additional intermediates, at time `now`. Returns the chain
/// from the leaf to the trust anchor. CRLs are consulted for every
/// certificate in the chain; a missing CRL is an error only when
/// `require_crl` (`openssl_callback_ignore_crls`, :3372-3379).
pub fn verify_chain(
    leaf: &Cert,
    untrusted: &[Cert],
    store: &TrustStore,
    now: DateTime<Utc>,
    require_crl: bool,
) -> Result<Vec<Cert>, VerifyError> {
    verify_chain_detail(leaf, untrusted, store, now, require_crl).map_err(|(e, _)| e)
}

/// [`verify_chain`] that also returns the certificate the failure concerns
/// (OpenSSL's "current cert", MIT `reqctx->received_cert`).
pub fn verify_chain_detail(
    leaf: &Cert,
    untrusted: &[Cert],
    store: &TrustStore,
    now: DateTime<Utc>,
    require_crl: bool,
) -> Result<Vec<Cert>, (VerifyError, Box<Cert>)> {
    let mut offender = leaf.clone();
    verify_chain_inner(leaf, untrusted, store, now, require_crl, &mut offender)
        .map_err(|e| (e, Box::new(offender)))
}

fn verify_chain_inner(
    leaf: &Cert,
    untrusted: &[Cert],
    store: &TrustStore,
    now: DateTime<Utc>,
    require_crl: bool,
    offender: &mut Cert,
) -> Result<Vec<Cert>, VerifyError> {
    if store.anchors.is_empty() {
        return Err(VerifyError::NoIssuer);
    }
    let mut chain = vec![leaf.clone()];
    loop {
        let current = chain.last().expect("non-empty").clone();
        *offender = current.clone();
        if chain.len() > MAX_DEPTH {
            return Err(VerifyError::Invalid("certificate chain too long"));
        }
        // The certificate is itself a trust anchor.
        if store.anchors.iter().any(|a| a.der == current.der) {
            break;
        }
        let below = chain.iter().skip(1).filter(|c| !c.is_self_issued()).count() as u32;
        let candidates = store
            .anchors
            .iter()
            .map(|c| (true, c))
            .chain(store.intermediates.iter().map(|c| (false, c)))
            .chain(untrusted.iter().map(|c| (false, c)))
            .filter(|(_, c)| c.subject == current.issuer);
        let mut found: Option<(bool, &Cert)> = None;
        let mut sig_failed = false;
        for (anchor, cand) in candidates {
            if current.signed_by(cand) {
                found = Some((anchor, cand));
                break;
            }
            sig_failed = true;
        }
        let Some((anchor, issuer)) = found else {
            if sig_failed {
                return Err(VerifyError::Invalid("certificate signature failure"));
            }
            return Err(if current.is_self_issued() {
                VerifyError::Invalid("self-signed certificate in chain")
            } else {
                VerifyError::NoIssuer
            });
        };
        check_ca(issuer, below)?;
        chain.push(issuer.clone());
        if anchor {
            break;
        }
        if issuer.is_self_issued() {
            return Err(VerifyError::Invalid("self-signed certificate in chain"));
        }
    }

    for c in &chain {
        *offender = c.clone();
        check_validity(c, now)?;
        check_critical(c)?;
    }

    // CRL_CHECK | CRL_CHECK_ALL: every certificate, up to and including the
    // trust anchor, against the CRL of its issuer.
    for (i, c) in chain.iter().enumerate() {
        *offender = c.clone();
        let issuer = chain.get(i + 1).unwrap_or(c);
        match crl_for(store, &c.issuer, issuer) {
            None => {
                if require_crl {
                    return Err(VerifyError::CrlUnavailable);
                }
            }
            Some(crl) => {
                if crl.this_update > now || crl.next_update.is_some_and(|n| n < now) {
                    return Err(VerifyError::Invalid("CRL is not time valid"));
                }
                let serial = c.serial();
                if crl.list.tbs_cert_list.revoked_certificates.iter().any(|r| {
                    let d = rasn::der::encode(&r.user_certificate).unwrap_or_default();
                    der::read(&d).is_some_and(|(t, _)| der::uint_magnitude(t.content) == serial)
                }) {
                    return Err(VerifyError::Revoked);
                }
            }
        }
    }
    Ok(chain)
}

#[cfg(test)]
pub(crate) mod tests;
