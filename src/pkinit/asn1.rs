//! ASN.1 structures of RFC 4556 / RFC 8636 (MIT lib/krb5/asn.1/asn1_k_encode.c
//! :1340-1520) and the object identifiers PKINIT uses (MIT
//! pkinit_constants.c, pkinit_crypto_openssl.c `pkinit_init_pkinit_oids`).

#![allow(missing_docs)] // Field names follow the RFC 4556 ASN.1 modules.

use rasn::prelude::*;
use rasn::types::{BitString, GeneralString, ObjectIdentifier, OctetString};
use rasn_pkix::AlgorithmIdentifier;

use crate::types::{KerberosTime, PrincipalName};

macro_rules! oid_consts {
    ($($(#[$m:meta])* $name:ident = [$($b:expr),+];)+) => {
        $($(#[$m])* pub(crate) const $name: &[u8] = &[$($b),+];)+
    };
}

oid_consts! {
    /// id-pkinit-authData (1.3.6.1.5.2.3.1).
    ID_PKINIT_AUTHDATA = [0x2B, 0x06, 0x01, 0x05, 0x02, 0x03, 0x01];
    /// id-pkinit-DHKeyData (1.3.6.1.5.2.3.2).
    ID_PKINIT_DHKEYDATA = [0x2B, 0x06, 0x01, 0x05, 0x02, 0x03, 0x02];
    /// id-pkinit-san (1.3.6.1.5.2.2).
    ID_PKINIT_SAN = [0x2B, 0x06, 0x01, 0x05, 0x02, 0x02];
    /// id-pkinit-KPClientAuth (1.3.6.1.5.2.3.4).
    ID_PKINIT_KP_CLIENT_AUTH = [0x2B, 0x06, 0x01, 0x05, 0x02, 0x03, 0x04];
    /// id-pkinit-KPKdc (1.3.6.1.5.2.3.5).
    ID_PKINIT_KP_KDC = [0x2B, 0x06, 0x01, 0x05, 0x02, 0x03, 0x05];
    /// id-ms-kp-sc-logon (1.3.6.1.4.1.311.20.2.2).
    ID_MS_KP_SC_LOGON = [0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x14, 0x02, 0x02];
    /// id-ms-san-upn (1.3.6.1.4.1.311.20.2.3).
    ID_MS_SAN_UPN = [0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x14, 0x02, 0x03];
    /// id-kp-serverAuth (1.3.6.1.5.5.7.3.1).
    ID_KP_SERVER_AUTH = [0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01];
    /// id-pkinit-kdf-ah-sha1 (RFC 8636).
    KDF_SHA1 = [0x2B, 0x06, 0x01, 0x05, 0x02, 0x03, 0x06, 0x01];
    /// id-pkinit-kdf-ah-sha256.
    KDF_SHA256 = [0x2B, 0x06, 0x01, 0x05, 0x02, 0x03, 0x06, 0x02];
    /// id-pkinit-kdf-ah-sha512.
    KDF_SHA512 = [0x2B, 0x06, 0x01, 0x05, 0x02, 0x03, 0x06, 0x03];
    /// sha-1 (1.3.14.3.2.26).
    CMS_SHA1 = [0x2B, 0x0E, 0x03, 0x02, 0x1A];
    /// id-sha256.
    CMS_SHA256 = [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
    /// id-sha384.
    CMS_SHA384 = [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02];
    /// id-sha512.
    CMS_SHA512 = [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03];
    /// rsaEncryption.
    RSA_ENCRYPTION = [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01];
    /// sha1WithRSAEncryption.
    SHA1_WITH_RSA = [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x05];
    /// sha256WithRSAEncryption.
    SHA256_WITH_RSA = [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B];
    /// sha384WithRSAEncryption.
    SHA384_WITH_RSA = [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0C];
    /// sha512WithRSAEncryption.
    SHA512_WITH_RSA = [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0D];
    /// ecdsa-with-SHA1.
    ECDSA_SHA1 = [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x01];
    /// ecdsa-with-SHA256.
    ECDSA_SHA256 = [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02];
    /// ecdsa-with-SHA384.
    ECDSA_SHA384 = [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x03];
    /// ecdsa-with-SHA512.
    ECDSA_SHA512 = [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x04];
    /// id-ecPublicKey.
    ID_EC_PUBLIC_KEY = [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01];
    /// prime256v1.
    SECP256R1 = [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
    /// secp384r1.
    SECP384R1 = [0x2B, 0x81, 0x04, 0x00, 0x22];
    /// secp521r1.
    SECP521R1 = [0x2B, 0x81, 0x04, 0x00, 0x23];
    /// dhpublicnumber (RFC 3279 section 2.3.3).
    DH_PUBLIC_NUMBER = [0x2A, 0x86, 0x48, 0xCE, 0x3E, 0x02, 0x01];
    /// id-signedData.
    ID_SIGNED_DATA = [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02];
    /// pkcs-9 contentType.
    PKCS9_CONTENT_TYPE = [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x03];
    /// pkcs-9 messageDigest.
    PKCS9_MESSAGE_DIGEST = [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x04];
    /// id-ce-keyUsage.
    EXT_KEY_USAGE_BITS = [0x55, 0x1D, 0x0F];
    /// id-ce-subjectAltName.
    EXT_SUBJECT_ALT_NAME = [0x55, 0x1D, 0x11];
    /// id-ce-basicConstraints.
    EXT_BASIC_CONSTRAINTS = [0x55, 0x1D, 0x13];
    /// id-ce-extKeyUsage.
    EXT_EXT_KEY_USAGE = [0x55, 0x1D, 0x25];
}

/// The `ObjectIdentifier` with the given DER content bytes.
pub(crate) fn oid(content: &[u8]) -> ObjectIdentifier {
    rasn::der::decode(&super::der::tlv(0x06, content)).expect("valid OID content")
}

/// An AlgorithmIdentifier with absent parameters.
pub(crate) fn alg(content: &[u8]) -> AlgorithmIdentifier {
    AlgorithmIdentifier {
        algorithm: oid(content),
        parameters: None,
    }
}

/// An AlgorithmIdentifier with NULL parameters.
pub(crate) fn alg_null(content: &[u8]) -> AlgorithmIdentifier {
    AlgorithmIdentifier {
        algorithm: oid(content),
        parameters: Some(rasn::types::Any::new(vec![0x05, 0x00])),
    }
}

/// Whether `id` has exactly the DER content bytes `content`.
pub(crate) fn is_oid(id: &ObjectIdentifier, content: &[u8]) -> bool {
    id == &oid(content)
}

/// KDFAlgorithmId (RFC 8636): `SEQUENCE { kdf-id [0] OBJECT IDENTIFIER }`.
#[derive(AsnType, Encode, Decode, Debug, Clone, PartialEq, Eq)]
pub struct KdfAlgorithmId {
    #[rasn(tag(explicit(context, 0)))]
    pub kdf_id: ObjectIdentifier,
}

/// PAChecksum2 (RFC 8636).
#[derive(AsnType, Encode, Decode, Debug, Clone)]
pub struct PaChecksum2 {
    #[rasn(tag(explicit(context, 0)))]
    pub checksum: OctetString,
    #[rasn(tag(explicit(context, 1)))]
    pub algorithm_identifier: AlgorithmIdentifier,
}

/// PKAuthenticator (RFC 4556 3.2.1 with RFC 8070/8636 additions).
#[derive(AsnType, Encode, Decode, Debug, Clone)]
pub struct PkAuthenticator {
    #[rasn(tag(explicit(context, 0)))]
    pub cusec: i32,
    #[rasn(tag(explicit(context, 1)))]
    pub ctime: KerberosTime,
    #[rasn(tag(explicit(context, 2)))]
    pub nonce: u32,
    #[rasn(tag(explicit(context, 3)))]
    pub pa_checksum: OctetString,
    #[rasn(tag(explicit(context, 4)))]
    pub freshness_token: Option<OctetString>,
    #[rasn(tag(explicit(context, 5)))]
    pub pa_checksum2: Option<PaChecksum2>,
}

/// AuthPack (RFC 4556 3.2.1).
#[derive(AsnType, Encode, Decode, Debug, Clone)]
pub struct AuthPack {
    #[rasn(tag(explicit(context, 0)))]
    pub pk_authenticator: PkAuthenticator,
    #[rasn(tag(explicit(context, 1)))]
    pub client_public_value: Option<rasn_pkix::SubjectPublicKeyInfo>,
    #[rasn(tag(explicit(context, 2)))]
    pub supported_cms_types: Option<Vec<AlgorithmIdentifier>>,
    #[rasn(tag(explicit(context, 3)))]
    pub client_dh_nonce: Option<OctetString>,
    #[rasn(tag(explicit(context, 4)))]
    pub supported_kdfs: Option<Vec<KdfAlgorithmId>>,
}

/// ExternalPrincipalIdentifier (RFC 4556 3.2.1).
#[derive(AsnType, Encode, Decode, Debug, Clone)]
pub struct ExternalPrincipalIdentifier {
    #[rasn(tag(context, 0))]
    pub subject_name: Option<OctetString>,
    #[rasn(tag(context, 1))]
    pub issuer_and_serial_number: Option<OctetString>,
    #[rasn(tag(context, 2))]
    pub subject_key_identifier: Option<OctetString>,
}

/// PA-PK-AS-REQ (RFC 4556 3.2.1).
#[derive(AsnType, Encode, Decode, Debug, Clone)]
pub struct PaPkAsReq {
    #[rasn(tag(context, 0))]
    pub signed_auth_pack: OctetString,
    #[rasn(tag(explicit(context, 1)))]
    pub trusted_certifiers: Option<Vec<ExternalPrincipalIdentifier>>,
    #[rasn(tag(context, 2))]
    pub kdc_pk_id: Option<OctetString>,
}

/// DHRepInfo (RFC 4556 3.2.3 with RFC 8636's kdf).
#[derive(AsnType, Encode, Decode, Debug, Clone)]
pub struct DhRepInfo {
    #[rasn(tag(context, 0))]
    pub dh_signed_data: OctetString,
    #[rasn(tag(explicit(context, 1)))]
    pub server_dh_nonce: Option<OctetString>,
    #[rasn(tag(explicit(context, 2)))]
    pub kdf: Option<KdfAlgorithmId>,
}

/// PA-PK-AS-REP (RFC 4556 3.2.3).
#[derive(AsnType, Encode, Decode, Debug, Clone)]
#[rasn(choice)]
pub enum PaPkAsRep {
    #[rasn(tag(explicit(context, 0)))]
    DhInfo(DhRepInfo),
    #[rasn(tag(context, 1))]
    EncKeyPack(OctetString),
}

/// KDCDHKeyInfo (RFC 4556 3.2.3).
#[derive(AsnType, Encode, Decode, Debug, Clone)]
pub struct KdcDhKeyInfo {
    #[rasn(tag(explicit(context, 0)))]
    pub subject_public_key: BitString,
    #[rasn(tag(explicit(context, 1)))]
    pub nonce: u32,
    #[rasn(tag(explicit(context, 2)))]
    pub dh_key_expiration: Option<KerberosTime>,
}

/// KRB5PrincipalName (RFC 4556 3.2.2): `{ realm [0], principalName [1] }`.
#[derive(AsnType, Encode, Decode, Debug, Clone)]
pub struct Krb5PrincipalName {
    #[rasn(tag(explicit(context, 0)))]
    pub realm: GeneralString,
    #[rasn(tag(explicit(context, 1)))]
    pub principal_name: PrincipalName,
}

/// PkinitSuppPubInfo (RFC 8636 3.1).
#[derive(AsnType, Encode, Decode, Debug, Clone)]
pub struct PkinitSuppPubInfo {
    #[rasn(tag(explicit(context, 0)))]
    pub enctype: i32,
    #[rasn(tag(explicit(context, 1)))]
    pub as_req: OctetString,
    #[rasn(tag(explicit(context, 2)))]
    pub pk_as_rep: OctetString,
}

/// OtherInfo of SP 800-56A (RFC 8636 3.1): the first field has no context
/// tag; the principals are wrapped in OCTET STRINGs.
#[derive(AsnType, Encode, Decode, Debug, Clone)]
pub struct OtherInfo {
    pub algorithm_identifier: AlgorithmIdentifier,
    #[rasn(tag(explicit(context, 0)))]
    pub party_u_info: OctetString,
    #[rasn(tag(explicit(context, 1)))]
    pub party_v_info: OctetString,
    #[rasn(tag(explicit(context, 2)))]
    pub supp_pub_info: OctetString,
}

/// DomainParameters (RFC 3279 2.3.3), without the optional j and validation
/// parameters.
#[derive(AsnType, Encode, Decode, Debug, Clone)]
pub struct DomainParameters {
    pub p: rasn::types::Integer,
    pub g: rasn::types::Integer,
    pub q: rasn::types::Integer,
}

/// TYPED-DATA element (RFC 4120 7.5.9 / RFC 4556 e-data).
#[derive(AsnType, Encode, Decode, Debug, Clone)]
pub struct TypedData {
    #[rasn(tag(explicit(context, 0)))]
    pub data_type: i32,
    #[rasn(tag(explicit(context, 1)))]
    pub data_value: Option<OctetString>,
}
