//! KDC side of PKINIT (MIT pkinit_srv.c `pkinit_server_verify_padata`
//! :414-625, `pkinit_server_return_padata` :763-940, certauth modules
//! :1141-1215).

use std::sync::Arc;

use chrono::{DateTime, Utc};
use rasn::types::{BitString, OctetString};

use super::asn1::{
    self, AuthPack, DhRepInfo, ExternalPrincipalIdentifier, KdcDhKeyInfo, KdfAlgorithmId,
    PaPkAsRep, PaPkAsReq,
};
use super::cms::{self, Identity, PkinitError};
use super::kex::{self, decode_spki, Group, Kdf, KeyPair, DEFAULT_DH_MIN_BITS};
use super::x509::{Cert, San, TrustStore};
use crate::types::error_codes::*;
use crate::types::{is_anonymous_name, EncryptionKey, PrincipalName, ANONYMOUS_REALM};

/// PA-DATA types and TD (typed data) types used by PKINIT.
pub const PA_PK_AS_REQ: i32 = 16;
/// PA-PK-AS-REP.
pub const PA_PK_AS_REP: i32 = 17;
/// PA-PKINIT-KX (RFC 6112).
pub const PA_PKINIT_KX: i32 = 147;
/// PA-AS-FRESHNESS (RFC 8070).
pub const PA_AS_FRESHNESS: i32 = 150;
/// TD-TRUSTED-CERTIFIERS (pkinit.h:52).
pub const TD_TRUSTED_CERTIFIERS: i32 = 104;
/// TD-INVALID-CERTIFICATES (pkinit.h:53).
pub const TD_INVALID_CERTIFICATES: i32 = 105;
/// TD-DH-PARAMETERS (pkinit.h:54).
pub const TD_DH_PARAMETERS: i32 = 109;

/// Per-realm KDC settings (`pkinit_*` kdc.conf relations, pkinit_srv.c
/// `pkinit_init_kdc_profile` :958-1040).
pub struct ServerConfig {
    /// The KDC certificate chain and key (`pkinit_identity`).
    pub identity: Identity,
    /// Anchors, pool and CRLs (`pkinit_anchors`, `pkinit_pool`,
    /// `pkinit_revoke`).
    pub store: TrustStore,
    /// `pkinit_dh_min_bits` as a strength-equivalent size (default 2048).
    pub dh_min_bits: u32,
    /// `pkinit_allow_upn` (default false).
    pub allow_upn: bool,
    /// `pkinit_require_crl_checking` (default false).
    pub require_crl_checking: bool,
    /// Whether client EKU checking is on (`pkinit_eku_checking` other than
    /// `none`; default on).
    pub require_eku: bool,
    /// `pkinit_eku_checking = scLogin` also accepts id-ms-kp-sc-logon.
    pub accept_secondary_eku: bool,
    /// `pkinit_require_freshness` (default false).
    pub require_freshness: bool,
    /// `pkinit_indicator` values (stored; authentication indicators are not
    /// issued).
    pub indicators: Vec<String>,
}

impl ServerConfig {
    /// Defaults per MIT (`pkinit_init_plg_opts`, pkinit_lib.c).
    pub fn new(identity: Identity, store: TrustStore) -> Self {
        Self {
            identity,
            store,
            dh_min_bits: DEFAULT_DH_MIN_BITS,
            allow_upn: false,
            require_crl_checking: false,
            require_eku: true,
            accept_secondary_eku: false,
            require_freshness: false,
            indicators: Vec::new(),
        }
    }

    /// Wrap in an `Arc` for sharing.
    pub fn shared(self) -> Arc<Self> {
        Arc::new(self)
    }
}

impl std::fmt::Debug for ServerConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerConfig")
            .field("dh_min_bits", &self.dh_min_bits)
            .field("allow_upn", &self.allow_upn)
            .field("require_crl_checking", &self.require_crl_checking)
            .field("require_eku", &self.require_eku)
            .field("require_freshness", &self.require_freshness)
            .finish_non_exhaustive()
    }
}

/// What the KDC knows about the request being processed.
pub struct RequestInfo<'a> {
    /// DER of the (inner) KDC-REQ-BODY (`cb->request_body`).
    pub body_der: &'a [u8],
    /// DER of the AS-REQ packet (`req_pkt`).
    pub as_req_der: &'a [u8],
    /// Request client name and realm.
    pub client: &'a PrincipalName,
    /// Client realm: the request realm, or `WELLKNOWN:ANONYMOUS` once an
    /// anonymous request's client has been replaced (do_as_req.c:716-733).
    pub client_realm: &'a str,
    /// Request realm (server and client realm in an AS-REQ).
    pub realm: &'a str,
    /// Request server name.
    pub server: &'a PrincipalName,
    /// Request nonce.
    pub nonce: u32,
    /// Requested enctypes in order.
    pub etypes: &'a [i32],
}

/// A failed verification with the data MIT puts in the error.
#[derive(Debug, Clone)]
pub struct Failure {
    /// Error code (before MIT's `filter_preauth_error`).
    pub code: i32,
    /// Detail text.
    pub message: String,
    /// Typed e-data elements (`pkinit_create_edata`, :95-125).
    pub e_data: Vec<(i32, Vec<u8>)>,
}

impl Failure {
    fn new(code: i32, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            e_data: Vec::new(),
        }
    }
}

/// A verified PA-PK-AS-REQ.
#[derive(Debug)]
pub struct Verified {
    /// The authenticated client certificate (`None` for anonymous PKINIT).
    pub client_cert: Option<Cert>,
    /// The client's key agreement group and public value (`None` for the
    /// unsupported RSA mode).
    pub client_dh: Option<(Group, Vec<u8>)>,
    /// The KDFs the client offered, in its order.
    pub supported_kdfs: Option<Vec<Kdf>>,
    /// A valid freshness token was presented.
    pub valid_freshness: bool,
}

pub(super) fn identifiers_of(certs: &[&Cert]) -> Vec<ExternalPrincipalIdentifier> {
    certs
        .iter()
        .map(|c| ExternalPrincipalIdentifier {
            subject_name: Some(OctetString::from(c.subject_der().to_vec())),
            issuer_and_serial_number: super::cms::issuer_and_serial_der(c).map(OctetString::from),
            subject_key_identifier: None,
        })
        .collect()
}

fn identifiers(certs: &[&Cert]) -> Vec<u8> {
    rasn::der::encode(&identifiers_of(certs)).unwrap_or_default()
}

/// TD-DH-PARAMETERS list (`pkinit_create_td_dh_parameters`, :3206-3262).
pub fn td_dh_parameters(dh_min_bits: u32) -> Vec<u8> {
    let list: Vec<_> = Group::ALL
        .into_iter()
        .filter(|g| match g {
            Group::P256 => dh_min_bits <= kex::DH_P256_BITS,
            Group::P384 => dh_min_bits <= kex::DH_P384_BITS,
            Group::P521 => true,
            Group::Modp2048 => dh_min_bits <= 2048,
            Group::Modp4096 => dh_min_bits <= 4096,
            Group::Modp1024 => dh_min_bits <= 1024,
        })
        .map(|g| g.algorithm_identifier())
        .collect();
    rasn::der::encode(&list).unwrap_or_default()
}

fn edata_for(cfg: &ServerConfig, code: i32, received: Option<&Cert>) -> Vec<(i32, Vec<u8>)> {
    match code {
        KDC_ERR_CANT_VERIFY_CERTIFICATE => {
            let anchors: Vec<&Cert> = cfg.store.anchors.iter().collect();
            vec![(TD_TRUSTED_CERTIFIERS, identifiers(&anchors))]
        }
        KDC_ERR_DH_KEY_PARAMETERS_NOT_ACCEPTED => {
            vec![(TD_DH_PARAMETERS, td_dh_parameters(cfg.dh_min_bits))]
        }
        KDC_ERR_INVALID_CERTIFICATE | KDC_ERR_REVOKED_CERTIFICATE => received
            .map(|c| vec![(TD_INVALID_CERTIFICATES, identifiers(&[c]))])
            .unwrap_or_default(),
        _ => Vec::new(),
    }
}

/// `pkinit_san_authorize` result for the certificate.
enum SanResult {
    Match,
    NoHandle,
    Mismatch,
}

fn names_equal(a: &PrincipalName, b: &PrincipalName) -> bool {
    a.name_string.len() == b.name_string.len()
        && a.name_string
            .iter()
            .zip(&b.name_string)
            .all(|(x, y)| x.as_bytes() == y.as_bytes())
}

fn unparse(name: &PrincipalName) -> String {
    name.name_string
        .iter()
        .map(|c| String::from_utf8_lossy(c.as_bytes()).to_string())
        .collect::<Vec<_>>()
        .join("/")
}

/// `verify_client_san` (:158-258).
fn verify_client_san(
    cfg: &ServerConfig,
    cert: &Cert,
    client: &PrincipalName,
    realm: &str,
) -> SanResult {
    let sans = cert.sans();
    let princs: Vec<_> = sans
        .iter()
        .filter_map(|s| match s {
            San::Pkinit(p, r) => Some((p, r)),
            _ => None,
        })
        .collect();
    let upns: Vec<&String> = if cfg.allow_upn {
        sans.iter()
            .filter_map(|s| match s {
                San::Upn(u) => Some(u),
                _ => None,
            })
            .collect()
    } else {
        Vec::new()
    };
    if princs.is_empty() && upns.is_empty() {
        return SanResult::NoHandle;
    }
    if princs
        .iter()
        .any(|(p, r)| r.as_str() == realm && names_equal(p, client))
    {
        return SanResult::Match;
    }
    for upn in upns {
        let (user, urealm) = upn.rsplit_once('@').unwrap_or((upn.as_str(), realm));
        if urealm == realm && user == unparse(client) {
            return SanResult::Match;
        }
    }
    SanResult::Mismatch
}

/// `crypto_check_cert_eku` for a client certificate (:2499-2580).
fn client_eku_ok(cfg: &ServerConfig, cert: &Cert) -> bool {
    let Some(ekus) = cert.eku() else {
        return false;
    };
    let found = ekus.iter().any(|e| {
        e == asn1::ID_PKINIT_KP_CLIENT_AUTH
            || (cfg.accept_secondary_eku && e == asn1::ID_MS_KP_SC_LOGON)
    });
    found && cert.has_digital_signature_ku()
}

/// `authorize_cert` (:331-401) over the built-in certauth modules
/// (pkinit_san, pkinit_eku).
fn authorize_cert(
    cfg: &ServerConfig,
    cert: &Cert,
    client: &PrincipalName,
    realm: &str,
) -> Result<(), PkinitError> {
    let mut accepted = false;
    match verify_client_san(cfg, cert, client, realm) {
        SanResult::Match => accepted = true,
        SanResult::NoHandle => {}
        SanResult::Mismatch => {
            return Err(PkinitError::new(
                KDC_ERR_CLIENT_NAME_MISMATCH,
                "certificate does not match the client principal",
            ))
        }
    }
    if cfg.require_eku && !client_eku_ok(cfg, cert) {
        return Err(PkinitError::new(
            KDC_ERR_INCONSISTENT_KEY_PURPOSE,
            "client certificate has no acceptable extended key usage",
        ));
    }
    if accepted {
        Ok(())
    } else {
        Err(PkinitError::new(
            KDC_ERR_CLIENT_NAME_MISMATCH,
            "no certificate authorization module accepted the certificate",
        ))
    }
}

/// Verify a PA-PK-AS-REQ (`pkinit_server_verify_padata`). `check_freshness`
/// validates a freshness token (`check_freshness_token`, kdc_preauth.c
/// :513-565). `skew_secs` is the allowed clock skew.
pub fn verify(
    cfg: &ServerConfig,
    padata: &[u8],
    req: &RequestInfo<'_>,
    now: DateTime<Utc>,
    skew_secs: i64,
    check_freshness: &dyn Fn(&[u8]) -> bool,
) -> Result<Verified, Failure> {
    let preauth = |m: &str| Failure::new(KDC_ERR_PREAUTH_FAILED, m);
    let parsed: PaPkAsReq =
        rasn::der::decode(padata).map_err(|_| preauth("decode of PA-PK-AS-REQ failed"))?;

    let verified = cms::verify(
        parsed.signed_auth_pack.as_ref(),
        asn1::ID_PKINIT_AUTHDATA,
        &cfg.store,
        now,
        cfg.require_crl_checking,
    )
    .map_err(|e| Failure {
        e_data: edata_for(cfg, e.code, e.cert.as_deref()),
        code: e.code,
        message: e.message,
    })?;

    let signer = verified.signer;
    match &signer {
        Some(cert) => authorize_cert(cfg, cert, req.client, req.realm).map_err(|e| Failure {
            e_data: edata_for(cfg, e.code, Some(cert)),
            code: e.code,
            message: e.message,
        })?,
        None if !(is_anonymous_name(req.client) && req.client_realm == ANONYMOUS_REALM) => {
            return Err(preauth(
                "Pkinit request not signed, but client not anonymous.",
            ))
        }
        None => {}
    }

    let auth_pack: AuthPack =
        rasn::der::decode(&verified.data).map_err(|_| preauth("decode of AuthPack failed"))?;
    let pka = &auth_pack.pk_authenticator;
    if (now.timestamp() - pka.ctime.timestamp()).abs() > skew_secs {
        return Err(Failure::new(KRB_AP_ERR_SKEW, "clock skew too great"));
    }

    let client_dh = match &auth_pack.client_public_value {
        Some(spki) => {
            let (group, raw) = decode_spki(spki).map_err(|_| dh_failure(cfg))?;
            if group.bits() < cfg.dh_min_bits {
                return Err(dh_failure(cfg));
            }
            Some((group, raw))
        }
        None => None,
    };
    if client_dh.is_none() && signer.is_none() {
        return Err(preauth(
            "Anonymous pkinit without DH public value not supported.",
        ));
    }

    // crypto_verify_checksums (:5791-5818): SHA-1 paChecksum, and the
    // optional paChecksum2 in the algorithm it names.
    let modified = |m: &str| Failure::new(KRB_AP_ERR_MODIFIED, m);
    if super::x509::Hash::Sha1.digest(req.body_der) != pka.pa_checksum.as_ref() {
        return Err(modified("paChecksum mismatch"));
    }
    if let Some(c2) = &pka.pa_checksum2 {
        let ok = super::x509::Hash::from_oid(&c2.algorithm_identifier.algorithm)
            .is_some_and(|h| h.digest(req.body_der) == c2.checksum.as_ref());
        if !ok {
            return Err(modified("paChecksum2 mismatch"));
        }
    }

    let mut valid_freshness = false;
    if let Some(tok) = &pka.freshness_token {
        if !check_freshness(tok.as_ref()) {
            return Err(Failure::new(
                KDC_ERR_PREAUTH_EXPIRED,
                "freshness token invalid",
            ));
        }
        valid_freshness = true;
    }
    // kdcPkId mismatches are ignored (:566-584).

    // check_log_freshness applies only to signed requests (:584-589).
    if cfg.require_freshness && signer.is_some() && !valid_freshness {
        return Err(preauth("no freshness token, rejecting auth"));
    }

    let supported_kdfs = auth_pack.supported_kdfs.as_ref().map(|l| {
        l.iter()
            .filter_map(|k| Kdf::from_oid(&k.kdf_id))
            .collect::<Vec<_>>()
    });
    Ok(Verified {
        client_cert: signer,
        client_dh,
        supported_kdfs,
        valid_freshness,
    })
}

fn dh_failure(cfg: &ServerConfig) -> Failure {
    Failure {
        code: KDC_ERR_DH_KEY_PARAMETERS_NOT_ACCEPTED,
        message: "key parameters not accepted".into(),
        e_data: edata_for(cfg, KDC_ERR_DH_KEY_PARAMETERS_NOT_ACCEPTED, None),
    }
}

/// `KDC_ERR_PREAUTH_EXPIRED` (RFC 6113).
pub const KDC_ERR_PREAUTH_EXPIRED: i32 = 90;

/// Build the PA-PK-AS-REP value and the replacement reply key
/// (`pkinit_server_return_padata`).
pub fn reply(
    cfg: &ServerConfig,
    verified: &Verified,
    req: &RequestInfo<'_>,
) -> Result<(Vec<u8>, EncryptionKey), PkinitError> {
    let etype = req
        .etypes
        .iter()
        .copied()
        .find(|e| crate::crypto::find_etype(*e).is_ok())
        .ok_or_else(|| PkinitError::new(KDC_ERR_ETYPE_NOSUPP, "no supported enctype"))?;
    let Some((group, client_pub)) = &verified.client_dh else {
        return Err(PkinitError::new(
            KDC_ERR_PREAUTH_FAILED,
            "Unsupported PKINIT RSA request",
        ));
    };
    let server = KeyPair::generate(*group);
    let secret = server
        .agree(client_pub)
        .map_err(|e| PkinitError::new(KDC_ERR_PREAUTH_FAILED, e.to_string()))?;

    let info = KdcDhKeyInfo {
        subject_public_key: BitString::from_slice(server.public_value()),
        nonce: req.nonce,
        dh_key_expiration: None,
    };
    let info_der = rasn::der::encode(&info)
        .map_err(|e| PkinitError::new(KDC_ERR_PREAUTH_FAILED, e.to_string()))?;
    let signed = cms::sign(&cfg.identity, asn1::ID_PKINIT_DHKEYDATA, &info_der)?;

    // pkinit_pick_kdf_alg (:696-733): the first server-supported KDF the
    // client offered.
    let kdf = verified
        .supported_kdfs
        .as_ref()
        .and_then(|offered| Kdf::SUPPORTED.into_iter().find(|k| offered.contains(k)));
    let rep = PaPkAsRep::DhInfo(DhRepInfo {
        dh_signed_data: OctetString::from(signed),
        server_dh_nonce: None,
        kdf: kdf.map(|k| KdfAlgorithmId {
            kdf_id: asn1::oid(k.oid_bytes()),
        }),
    });
    let rep_der = rasn::der::encode(&rep)
        .map_err(|e| PkinitError::new(KDC_ERR_PREAUTH_FAILED, e.to_string()))?;
    let key = kex::pkinit_kdf(
        &secret,
        kdf,
        etype,
        (req.client, req.client_realm),
        (req.server, req.realm),
        req.as_req_der,
        &rep_der,
    )
    .map_err(|e| PkinitError::new(KDC_ERR_PREAUTH_FAILED, e.to_string()))?;
    Ok((rep_der, key))
}

/// Encode typed e-data (TYPED-DATA ::= SEQUENCE OF { data-type [0],
/// data-value [1] }), `encode_krb5_typed_data`.
pub fn encode_typed_data(items: &[(i32, Vec<u8>)]) -> Vec<u8> {
    let list: Vec<asn1::TypedData> = items
        .iter()
        .map(|(t, v)| asn1::TypedData {
            data_type: *t,
            data_value: Some(OctetString::from(v.clone())),
        })
        .collect();
    rasn::der::encode(&list).unwrap_or_default()
}

/// Decode TYPED-DATA into (type, value) pairs.
pub fn decode_typed_data(der: &[u8]) -> Option<Vec<(i32, Vec<u8>)>> {
    let list: Vec<asn1::TypedData> = rasn::der::decode(der).ok()?;
    Some(
        list.into_iter()
            .map(|t| {
                (
                    t.data_type,
                    t.data_value.map(|v| v.to_vec()).unwrap_or_default(),
                )
            })
            .collect(),
    )
}
