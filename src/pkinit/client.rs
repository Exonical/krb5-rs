//! Client side of PKINIT (MIT pkinit_clnt.c `pkinit_as_req_create` :107-230,
//! `pkinit_as_rep_parse` :395-540, `verify_kdc_san`/`verify_kdc_eku`
//! :342-395, `pkinit_client_tryagain` :930-1010).

use std::sync::Arc;

use chrono::{DateTime, Utc};
use rasn::types::OctetString;

use super::asn1::{
    self, AuthPack, KdcDhKeyInfo, KdfAlgorithmId, PaChecksum2, PaPkAsRep, PaPkAsReq,
    PkAuthenticator,
};
use super::cms::{self, Identity, PkinitError};
use super::kex::{Group, Kdf, KeyPair, DEFAULT_DH_MIN_BITS};
use super::server::{identifiers_of, TD_DH_PARAMETERS};
use super::x509::{Hash, San, TrustStore};
use crate::types::error_codes::*;
use crate::types::{EncryptionKey, KerberosTime, PrincipalName};

/// Client-side PKINIT settings (`X509_user_identity`, `pkinit_anchors`,
/// `pkinit_pool`, `pkinit_revoke`, `pkinit_eku_checking`,
/// `pkinit_dh_min_bits`, `pkinit_kdc_hostname`,
/// `pkinit_require_crl_checking`).
pub struct ClientConfig {
    /// The user's certificate chain and key.
    pub identity: Identity,
    /// Anchors (required), pool and CRLs.
    pub store: TrustStore,
    /// Initial key exchange group (`pkinit_dh_min_bits`, default 2048-bit DH).
    pub dh_group: Group,
    /// `pkinit_require_crl_checking` (default false).
    pub require_crl_checking: bool,
    /// KDC certificate EKU checking (`pkinit_eku_checking` other than `none`;
    /// default on).
    pub require_eku: bool,
    /// `pkinit_eku_checking = kpServerAuth` also accepts id-kp-serverAuth.
    pub accept_secondary_eku: bool,
    /// `pkinit_kdc_hostname` values, matched against dNSName SANs.
    pub kdc_hostnames: Vec<String>,
    /// Do not send a freshness token even when one was received
    /// (`disable_freshness`, a MIT test option).
    pub disable_freshness: bool,
    /// NOT A MIT OPTION (testing knob): the KDFs offered in the request, in
    /// order. The default is MIT's list and order (sha256, sha1, sha512);
    /// `None` omits the list, which makes the KDC use RFC 4556's
    /// octetstring2key.
    #[doc(hidden)]
    pub kdfs: Option<Vec<Kdf>>,
}

impl ClientConfig {
    /// MIT defaults (`pkinit_init_req_opts`, pkinit_lib.c).
    pub fn new(identity: Identity, store: TrustStore) -> Self {
        Self {
            identity,
            store,
            dh_group: Group::from_bits(DEFAULT_DH_MIN_BITS).unwrap_or(Group::Modp2048),
            require_crl_checking: false,
            require_eku: true,
            accept_secondary_eku: false,
            kdc_hostnames: Vec::new(),
            disable_freshness: false,
            kdfs: Some(Kdf::SUPPORTED.to_vec()),
        }
    }

    /// Wrap in an `Arc` for use in `AsExchangeConfig`.
    pub fn shared(self) -> Arc<Self> {
        Arc::new(self)
    }
}

impl std::fmt::Debug for ClientConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientConfig")
            .field("dh_group", &self.dh_group)
            .field("require_eku", &self.require_eku)
            .field("kdc_hostnames", &self.kdc_hostnames)
            .finish_non_exhaustive()
    }
}

/// Build the PA-PK-AS-REQ value (`pa_pkinit_gen_req` + `pkinit_as_req_create`).
/// `body_der` is the DER of the (inner) KDC-REQ-BODY the checksums cover.
pub fn build_request(
    cfg: &ClientConfig,
    group: Group,
    body_der: &[u8],
    nonce: u32,
    ctime: KerberosTime,
    cusec: i32,
    freshness: Option<&[u8]>,
) -> Result<(Vec<u8>, KeyPair), PkinitError> {
    let fail = |m: String| PkinitError::new(KDC_ERR_PREAUTH_FAILED, m);
    if cfg.store.anchors.is_empty() {
        return Err(fail("No pkinit_anchors supplied".into()));
    }
    let keypair = KeyPair::generate(group);

    // crypto_generate_checksums (:5757-5789).
    let pa_checksum2 = PaChecksum2 {
        checksum: OctetString::from(Hash::Sha256.digest(body_der)),
        algorithm_identifier: asn1::alg(asn1::CMS_SHA256),
    };
    let auth_pack = AuthPack {
        pk_authenticator: PkAuthenticator {
            cusec,
            ctime,
            nonce,
            pa_checksum: OctetString::from(Hash::Sha1.digest(body_der)),
            freshness_token: if cfg.disable_freshness {
                None
            } else {
                freshness.map(|f| OctetString::from(f.to_vec()))
            },
            pa_checksum2: Some(pa_checksum2),
        },
        client_public_value: Some(keypair.spki()),
        // supported_cms_algs (pkinit_constants.c:134-140).
        supported_cms_types: Some(vec![
            asn1::alg(asn1::ECDSA_SHA512),
            asn1::alg(asn1::ECDSA_SHA256),
            asn1::alg(asn1::SHA512_WITH_RSA),
            asn1::alg(asn1::SHA256_WITH_RSA),
        ]),
        client_dh_nonce: None,
        supported_kdfs: cfg.kdfs.as_ref().map(|list| {
            list.iter()
                .map(|k| KdfAlgorithmId {
                    kdf_id: asn1::oid(k.oid_bytes()),
                })
                .collect()
        }),
    };
    let auth_der = rasn::der::encode(&auth_pack).map_err(|e| fail(e.to_string()))?;
    let signed = cms::sign(&cfg.identity, asn1::ID_PKINIT_AUTHDATA, &auth_der)?;
    let anchors: Vec<_> = cfg.store.anchors.iter().collect();
    let req = PaPkAsReq {
        signed_auth_pack: OctetString::from(signed),
        trusted_certifiers: Some(identifiers_of(&anchors)),
        kdc_pk_id: None,
    };
    let der = rasn::der::encode(&req).map_err(|e| fail(e.to_string()))?;
    Ok((der, keypair))
}

/// The KDC certificate checks of `pkinit_as_rep_parse`
/// (`verify_kdc_san`, `verify_kdc_eku`).
fn check_kdc_cert(
    cfg: &ClientConfig,
    cert: &super::x509::Cert,
    realm: &str,
) -> Result<(), PkinitError> {
    let sans = cert.sans();
    let mismatch = || {
        PkinitError::new(
            KDC_ERR_KDC_NAME_MISMATCH,
            "did not find an acceptable SAN in KDC certificate",
        )
    };
    let tgs_matches = sans.iter().any(|s| match s {
        San::Pkinit(p, r) => {
            r == realm
                && p.name_string.len() == 2
                && p.name_string[0].as_bytes() == b"krbtgt"
                && p.name_string[1].as_bytes() == realm.as_bytes()
        }
        _ => false,
    });
    if tgs_matches {
        return Ok(());
    }
    let dns_matches = !cfg.kdc_hostnames.is_empty()
        && sans.iter().any(|s| match s {
            San::Dns(d) => cfg.kdc_hostnames.iter().any(|h| h.eq_ignore_ascii_case(d)),
            _ => false,
        });
    if !dns_matches {
        return Err(mismatch());
    }
    if cfg.require_eku {
        let ok = cert.eku().is_some_and(|ekus| {
            ekus.iter().any(|e| {
                e == asn1::ID_PKINIT_KP_KDC
                    || (cfg.accept_secondary_eku && e == asn1::ID_KP_SERVER_AUTH)
            })
        }) && cert.has_digital_signature_ku();
        if !ok {
            return Err(PkinitError::new(
                KDC_ERR_INCONSISTENT_KEY_PURPOSE,
                "did not find an acceptable EKU in KDC certificate",
            ));
        }
    }
    Ok(())
}

/// Process a PA-PK-AS-REP and derive the reply key (`pkinit_as_rep_parse`).
/// `as_req_der` is the AS-REQ packet that was sent.
#[expect(clippy::too_many_arguments, reason = "mirrors pkinit_as_rep_parse")]
pub fn process_reply(
    cfg: &ClientConfig,
    keypair: &KeyPair,
    padata: &[u8],
    as_req_der: &[u8],
    client: &PrincipalName,
    server: &PrincipalName,
    realm: &str,
    etype: i32,
    now: DateTime<Utc>,
) -> Result<EncryptionKey, PkinitError> {
    let fail = |m: &str| PkinitError::new(KDC_ERR_PREAUTH_FAILED, m);
    let rep: PaPkAsRep = rasn::der::decode(padata).map_err(|_| fail("decode of PA-PK-AS-REP"))?;
    let PaPkAsRep::DhInfo(dh) = rep else {
        return Err(fail("unknown PA-PK-AS-REP type"));
    };
    let verified = cms::verify(
        dh.dh_signed_data.as_ref(),
        asn1::ID_PKINIT_DHKEYDATA,
        &cfg.store,
        now,
        cfg.require_crl_checking,
    )?;
    let signer = verified
        .signer
        .ok_or_else(|| fail("KDC reply is not signed"))?;
    check_kdc_cert(cfg, &signer, realm)?;

    let info: KdcDhKeyInfo =
        rasn::der::decode(&verified.data).map_err(|_| fail("decode of KDCDHKeyInfo"))?;
    if !info.subject_public_key.len().is_multiple_of(8) {
        return Err(fail("KDC public value is not whole bytes"));
    }
    let secret = keypair
        .agree(info.subject_public_key.as_raw_slice())
        .map_err(|e| fail(&e.to_string()))?;
    let kdf = match &dh.kdf {
        None => None,
        Some(id) => Some(Kdf::from_oid(&id.kdf_id).ok_or_else(|| fail("unsupported KDF"))?),
    };
    super::kex::pkinit_kdf(
        &secret,
        kdf,
        etype,
        (client, realm),
        (server, realm),
        as_req_der,
        padata,
    )
    .map_err(|e| fail(&e.to_string()))
}

/// `pkinit_process_td_dh_params` (:3309-3352): the first group in the KDC's
/// list that we know and that is at least as strong as the one we offered.
pub fn negotiate_group(current: Group, td_dh_parameters: &[u8]) -> Option<Group> {
    let list: Vec<rasn_pkix::AlgorithmIdentifier> = rasn::der::decode(td_dh_parameters).ok()?;
    list.iter()
        .filter_map(Group::from_algorithm_identifier)
        .find(|g| g.bits() >= current.bits())
}

/// The TD-DH-PARAMETERS element of KDC error e-data, if any.
pub fn find_td_dh(typed: &[(i32, Vec<u8>)]) -> Option<&[u8]> {
    typed
        .iter()
        .find(|(t, _)| *t == TD_DH_PARAMETERS)
        .map(|(_, v)| v.as_slice())
}
