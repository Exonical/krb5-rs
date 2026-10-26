//! CMS SignedData for PKINIT (MIT pkinit_crypto_openssl.c
//! `cms_signeddata_create` :1714-1930, `cms_signeddata_verify` :1931-2467,
//! `cms_contentinfo_create` :1654-1697).
//!
//! The signer always digests with SHA-256 and uses the key's natural
//! signature algorithm (sha256WithRSAEncryption or ecdsa-with-SHA256, both
//! with NULL parameters as OpenSSL writes them). The SignedData is built
//! directly in DER so the signed attributes are byte-exact.

use chrono::{DateTime, Utc};

use super::asn1;
use super::der::{self, tlv};
use super::pem;
use super::x509::{
    verify_chain_detail, verify_signature, Cert, Hash, PrivateKey, TrustStore, VerifyError,
};
use crate::types::error_codes::*;

/// A PKINIT failure carrying the KDC error code MIT reports for it.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("PKINIT error {code}: {message}")]
pub struct PkinitError {
    /// KRB-ERROR error-code.
    pub code: i32,
    /// Human-readable detail.
    pub message: String,
    /// The certificate a validation failure concerns (MIT
    /// `reqctx->received_cert`).
    pub cert: Option<Box<Cert>>,
}

impl PkinitError {
    /// An error with `code`.
    pub fn new(code: i32, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            cert: None,
        }
    }
}

impl From<VerifyError> for PkinitError {
    /// pkinit_crypto_openssl.c:2132-2151.
    fn from(e: VerifyError) -> Self {
        let code = match e {
            VerifyError::Revoked => KDC_ERR_REVOKED_CERTIFICATE,
            VerifyError::CrlUnavailable => KDC_ERR_REVOCATION_STATUS_UNKNOWN,
            VerifyError::NoIssuer => KDC_ERR_CANT_VERIFY_CERTIFICATE,
            VerifyError::Invalid(_) => KDC_ERR_INVALID_CERTIFICATE,
        };
        PkinitError::new(code, e.to_string())
    }
}

/// A certificate chain and private key (`FILE:` identities).
pub struct Identity {
    /// The identity certificate first, then any intermediates.
    pub chain: Vec<Cert>,
    /// The signing key.
    pub key: PrivateKey,
}

impl Identity {
    /// Build an identity from PEM text: certificates (leaf first) and a
    /// private key; `key_pem` may be the same text as `cert_pem`.
    pub fn from_pem(cert_pem: &str, key_pem: &str) -> Result<Identity, String> {
        let chain = Cert::all_from_pem(cert_pem)?;
        if chain.is_empty() {
            return Err("no certificate found".into());
        }
        Ok(Identity {
            chain,
            key: PrivateKey::from_pem(key_pem)?,
        })
    }

    /// Parse a MIT identity specification: `FILE:cert[,key]` (`pkinit_identity`,
    /// `X509_user_identity`). PKCS11, PKCS12 and DIR identities are not
    /// supported.
    pub fn from_spec(spec: &str) -> Result<Identity, String> {
        let (kind, rest) = spec
            .split_once(':')
            .ok_or_else(|| format!("unsupported identity {spec:?}"))?;
        if kind != "FILE" {
            return Err(format!("{kind} identities are not supported"));
        }
        let (cert_path, key_path) = rest.split_once(',').unwrap_or((rest, rest));
        let read = |p: &str| std::fs::read_to_string(p).map_err(|e| format!("{p}: {e}"));
        Identity::from_pem(&read(cert_path)?, &read(key_path)?)
    }

    /// The identity certificate.
    pub fn cert(&self) -> &Cert {
        &self.chain[0]
    }
}

fn alg_id(oid: &[u8]) -> Vec<u8> {
    let mut c = tlv(0x06, oid);
    c.extend([0x05, 0x00]);
    tlv(0x30, &c)
}

/// Raw INTEGER TLV of a certificate's serial number and its issuer name.
fn issuer_and_serial(cert: &Cert) -> Result<Vec<u8>, PkinitError> {
    let (outer, _) = der::read(cert.der())
        .ok_or_else(|| PkinitError::new(KDC_ERR_PREAUTH_FAILED, "bad certificate"))?;
    let kids = der::children(outer.content)
        .ok_or_else(|| PkinitError::new(KDC_ERR_PREAUTH_FAILED, "bad certificate"))?;
    let tbs = der::children(kids[0].content)
        .ok_or_else(|| PkinitError::new(KDC_ERR_PREAUTH_FAILED, "bad certificate"))?;
    let idx = usize::from(tbs.first().is_some_and(|f| f.tag == 0xA0));
    let mut body = cert.issuer_der().to_vec();
    body.extend_from_slice(tbs[idx].whole);
    Ok(tlv(0x30, &body))
}

/// DER IssuerAndSerialNumber of `cert` (`PKCS7_ISSUER_AND_SERIAL`).
pub fn issuer_and_serial_der(cert: &Cert) -> Option<Vec<u8>> {
    issuer_and_serial(cert).ok()
}

/// The ContentInfo of an unsigned eContent (`cms_contentinfo_create`).
pub fn content_info(econtent_type: &[u8], data: &[u8]) -> Vec<u8> {
    let mut c = tlv(0x06, econtent_type);
    c.extend(tlv(0xA0, &tlv(0x04, data)));
    tlv(0x30, &c)
}

/// Create a SignedData ContentInfo over `data` with eContentType
/// `econtent_type` (`cms_signeddata_create`).
pub fn sign(
    identity: &Identity,
    econtent_type: &[u8],
    data: &[u8],
) -> Result<Vec<u8>, PkinitError> {
    let hash = Hash::Sha256;
    let fail = |m: String| PkinitError::new(KDC_ERR_PREAUTH_FAILED, m);

    // Signed attributes, DER SET OF sorted by encoding: contentType,
    // messageDigest.
    let attr =
        |oid: &[u8], value: Vec<u8>| tlv(0x30, &[tlv(0x06, oid), tlv(0x31, &value)].concat());
    let mut attrs = [
        attr(asn1::PKCS9_CONTENT_TYPE, tlv(0x06, econtent_type)),
        attr(asn1::PKCS9_MESSAGE_DIGEST, tlv(0x04, &hash.digest(data))),
    ];
    attrs.sort();
    let attrs_body = attrs.concat();
    let signature = identity
        .key
        .sign(hash, &tlv(0x31, &attrs_body))
        .map_err(|e| fail(format!("signing failed: {e}")))?;

    let sig_oid: &[u8] = if identity.key.is_ec() {
        asn1::ECDSA_SHA256
    } else {
        asn1::SHA256_WITH_RSA
    };
    let mut signer = der::uint(&[1]);
    signer.extend(issuer_and_serial(identity.cert())?);
    signer.extend(alg_id(asn1::CMS_SHA256));
    signer.extend(tlv(0xA0, &attrs_body));
    signer.extend(alg_id(sig_oid));
    signer.extend(tlv(0x04, &signature));

    let mut signed = der::uint(&[3]);
    signed.extend(tlv(0x31, &alg_id(asn1::CMS_SHA256)));
    let mut encap = tlv(0x06, econtent_type);
    encap.extend(tlv(0xA0, &tlv(0x04, data)));
    signed.extend(tlv(0x30, &encap));
    // Certificates: the identity chain without self-signed roots
    // (MIT drops the last element of the verified chain).
    let certs: Vec<u8> = identity
        .chain
        .iter()
        .enumerate()
        .filter(|(i, c)| *i == 0 || !c.is_self_issued())
        .flat_map(|(_, c)| c.der().to_vec())
        .collect();
    signed.extend(tlv(0xA0, &certs));
    signed.extend(tlv(0x31, &tlv(0x30, &signer)));

    let mut ci = tlv(0x06, asn1::ID_SIGNED_DATA);
    ci.extend(tlv(0xA0, &tlv(0x30, &signed)));
    Ok(tlv(0x30, &ci))
}

/// A SignedData ContentInfo over `data` without certificates or signers
/// (`cms_signeddata_create` with no identity certificate: anonymous PKINIT).
pub fn sign_anonymous(econtent_type: &[u8], data: &[u8]) -> Vec<u8> {
    let mut signed = der::uint(&[3]);
    signed.extend(tlv(0x31, &[]));
    let mut encap = tlv(0x06, econtent_type);
    encap.extend(tlv(0xA0, &tlv(0x04, data)));
    signed.extend(tlv(0x30, &encap));
    signed.extend(tlv(0x31, &[]));
    let mut ci = tlv(0x06, asn1::ID_SIGNED_DATA);
    ci.extend(tlv(0xA0, &tlv(0x30, &signed)));
    tlv(0x30, &ci)
}

/// The verified contents of a SignedData message.
#[derive(Debug)]
pub struct Verified {
    /// The eContent.
    pub data: Vec<u8>,
    /// The signer's certificate (`None` for an unsigned message).
    pub signer: Option<Cert>,
    /// The verified chain from the signer to the trust anchor.
    pub chain: Vec<Cert>,
}

/// Verify a CMS message of the given eContentType
/// (`cms_signeddata_verify`). An unsigned ContentInfo of the expected type
/// (pre-1.10 MIT clients) or a SignedData without signers yields
/// `signer: None`.
pub fn verify(
    message: &[u8],
    expected_type: &[u8],
    store: &TrustStore,
    now: DateTime<Utc>,
    require_crl: bool,
) -> Result<Verified, PkinitError> {
    let preauth = |m: &str| PkinitError::new(KDC_ERR_PREAUTH_FAILED, m);
    let bad_sig = |m: &str| PkinitError::new(KDC_ERR_INVALID_SIG, m);

    let (ci, _) = der::read(message).ok_or_else(|| preauth("Failed to decode CMS message"))?;
    let ci_kids =
        der::children(ci.content).ok_or_else(|| preauth("Failed to decode CMS message"))?;
    let (Some(ctype), Some(wrapped)) = (ci_kids.first(), ci_kids.get(1)) else {
        return Err(preauth("Failed to decode CMS message"));
    };
    let (inner, _) =
        der::read(wrapped.content).ok_or_else(|| preauth("Failed to decode CMS message"))?;

    if ctype.content == expected_type {
        if inner.tag != 0x04 {
            return Err(preauth("Invalid pkinit packet: octet string expected"));
        }
        return Ok(Verified {
            data: inner.content.to_vec(),
            signer: None,
            chain: Vec::new(),
        });
    }
    if ctype.content != asn1::ID_SIGNED_DATA {
        return Err(preauth("wrong oid"));
    }

    let sd = der::children(inner.content).ok_or_else(|| preauth("Failed to decode CMS message"))?;
    let mut idx = 1; // skip version
    let _digest_algs = sd.get(idx).ok_or_else(|| preauth("bad SignedData"))?;
    idx += 1;
    let encap = sd.get(idx).ok_or_else(|| preauth("bad SignedData"))?;
    idx += 1;
    let mut message_certs: Vec<Cert> = Vec::new();
    while let Some(t) = sd.get(idx) {
        match t.tag {
            0xA0 => {
                let mut rest = t.content;
                while let Some((c, r)) = der::read(rest) {
                    if let Ok(cert) = Cert::from_der(c.whole) {
                        message_certs.push(cert);
                    }
                    rest = r;
                }
            }
            0xA1 => {}
            _ => break,
        }
        idx += 1;
    }
    let signer_infos = sd
        .get(idx)
        .filter(|t| t.tag == 0x31)
        .ok_or_else(|| preauth("bad SignedData"))?;

    let encap_kids =
        der::children(encap.content).ok_or_else(|| preauth("bad encapsulated content"))?;
    let econtent_type = encap_kids
        .first()
        .ok_or_else(|| preauth("bad encapsulated content"))?;
    let econtent = encap_kids
        .get(1)
        .and_then(|w| der::read(w.content))
        .filter(|(o, _)| o.tag == 0x04)
        .map(|(o, _)| o.content.to_vec());

    let signers = der::children(signer_infos.content).ok_or_else(|| preauth("bad SignerInfos"))?;
    let Some(si) = signers.first() else {
        // Not actually signed (anonymous).
        if econtent_type.content != expected_type {
            return Err(preauth("wrong oid"));
        }
        return Ok(Verified {
            data: econtent.ok_or_else(|| preauth("no content"))?,
            signer: None,
            chain: Vec::new(),
        });
    };

    let f = der::children(si.content).ok_or_else(|| preauth("bad SignerInfo"))?;
    let mut i = 1; // skip version
    let sid = f.get(i).ok_or_else(|| preauth("bad SignerInfo"))?;
    i += 1;
    let digest_alg = f.get(i).ok_or_else(|| preauth("bad SignerInfo"))?;
    i += 1;
    let signed_attrs = f.get(i).filter(|t| t.tag == 0xA0).copied();
    if signed_attrs.is_some() {
        i += 1;
    }
    let sig_alg_tlv = f.get(i).ok_or_else(|| preauth("bad SignerInfo"))?;
    i += 1;
    let signature = f
        .get(i)
        .filter(|t| t.tag == 0x04)
        .ok_or_else(|| preauth("bad SignerInfo"))?;

    // Find the signer certificate among the message and local certificates.
    let all: Vec<&Cert> = store
        .anchors
        .iter()
        .chain(store.intermediates.iter())
        .chain(message_certs.iter())
        .collect();
    let signer = match sid.tag {
        0x30 => {
            let parts = der::children(sid.content).ok_or_else(|| preauth("bad signer id"))?;
            let issuer = parts.first().ok_or_else(|| preauth("bad signer id"))?;
            let serial = parts.get(1).ok_or_else(|| preauth("bad signer id"))?;
            all.iter()
                .find(|c| {
                    c.issuer_der() == issuer.whole
                        && issuer_and_serial(c)
                            .ok()
                            .and_then(|b| der::read(&b).map(|(t, _)| t.content.to_vec()))
                            .is_some_and(|ias| ias.ends_with(serial.whole))
                })
                .copied()
        }
        _ => None,
    }
    .cloned()
    .ok_or_else(|| preauth("signer certificate not found"))?;

    let chain = verify_chain_detail(&signer, &message_certs, store, now, require_crl).map_err(
        |(e, cert)| PkinitError {
            cert: Some(cert),
            ..PkinitError::from(e)
        },
    )?;

    // CMS_verify.
    let digest_oid = der::children(digest_alg.content)
        .and_then(|k| k.first().map(|o| o.content.to_vec()))
        .ok_or_else(|| preauth("bad digest algorithm"))?;
    let hash = Hash::from_oid(&asn1::oid(&digest_oid)).ok_or_else(|| {
        PkinitError::new(
            KDC_ERR_DIGEST_IN_SIGNED_DATA_NOT_ACCEPTED,
            "Failed to verify CMS message: unknown digest",
        )
    })?;
    if econtent_type.content != expected_type {
        // Verification runs before the eContentType comparison in MIT, but
        // either failure ends in an error for the same input; keep the
        // MIT message for the type check.
    }
    let content = econtent.clone().ok_or_else(|| bad_sig("no content"))?;
    let sig_alg: rasn_pkix::AlgorithmIdentifier =
        rasn::der::decode(sig_alg_tlv.whole).map_err(|_| bad_sig("bad signature algorithm"))?;

    let signed_bytes: Vec<u8> = match signed_attrs {
        Some(attrs) => {
            // contentType must match and messageDigest must be the digest of
            // the content.
            let mut ct_ok = true;
            let mut md_ok = false;
            for a in der::children(attrs.content).ok_or_else(|| bad_sig("bad attributes"))? {
                let parts = der::children(a.content).ok_or_else(|| bad_sig("bad attribute"))?;
                let (Some(t), Some(v)) = (parts.first(), parts.get(1)) else {
                    continue;
                };
                let Some((val, _)) = der::read(v.content) else {
                    continue;
                };
                if t.content == asn1::PKCS9_CONTENT_TYPE {
                    ct_ok = val.content == econtent_type.content;
                } else if t.content == asn1::PKCS9_MESSAGE_DIGEST {
                    md_ok = val.content == hash.digest(&content).as_slice();
                }
            }
            if !ct_ok || !md_ok {
                return Err(bad_sig("Failed to verify CMS message"));
            }
            tlv(0x31, attrs.content)
        }
        None => content.clone(),
    };
    if !verify_signature(
        signer.spki(),
        &sig_alg,
        Some(hash),
        &signed_bytes,
        signature.content,
    ) {
        return Err(bad_sig("Failed to verify CMS message"));
    }

    if econtent_type.content != expected_type {
        return Err(preauth("wrong oid"));
    }
    Ok(Verified {
        data: content,
        signer: Some(signer),
        chain,
    })
}

/// Write a certificate chain and key as PEM (used by tests and tooling).
pub fn chain_pem(chain: &[Cert]) -> String {
    chain
        .iter()
        .map(|c| pem::encode("CERTIFICATE", c.der()))
        .collect()
}

#[cfg(test)]
mod tests;
