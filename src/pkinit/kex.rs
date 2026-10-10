//! Key agreement groups and key derivation (MIT pkinit_crypto_openssl.c:
//! `pkinit_init_dh_params` :1475-1498, `client_create_dh`/`server_*`
//! :2927-3092, `pkinit_kdf` :2784-2870, `octetstring2key` :2570-2650).
//!
//! Supported groups are MIT's: MODP 2/14/16 (Oakley 1024/2048/4096) and the
//! NIST curves P-256/384/521. The shared secret is the DH value padded to the
//! modulus size, or the ECDH x coordinate.

use std::sync::OnceLock;

use crypto_bigint::modular::{BoxedMontyForm, BoxedMontyParams};
use crypto_bigint::{BoxedUint, Odd};
use rasn::types::{BitString, Integer, OctetString};
use rasn_pkix::{AlgorithmIdentifier, SubjectPublicKeyInfo};
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha512};
use zeroize::Zeroizing;

use super::asn1::{self, DomainParameters, Krb5PrincipalName, OtherInfo, PkinitSuppPubInfo};
use super::der;
use super::groups_data::{MODP_1024_DER, MODP_2048_DER, MODP_4096_DER};
use crate::crypto::find_etype;
use crate::types::{EncryptionKey, PrincipalName};

/// `parse_dh_min_bits` (pkinit_crypto_openssl.c:5673-5703): a modulus size
/// (rounded up to 1024/2048/4096) or a curve name, as a strength-equivalent
/// size; anything else is the default (2048).
pub fn parse_dh_min_bits(value: Option<&str>) -> u32 {
    let Some(s) = value.map(str::trim) else {
        return DEFAULT_DH_MIN_BITS;
    };
    match s.parse::<i64>() {
        Ok(1024) => 1024,
        Ok(n) if n > 1024 && n <= 2048 => 2048,
        Ok(n) if n > 2048 && n <= 4096 => 4096,
        Ok(_) => DEFAULT_DH_MIN_BITS,
        Err(_) => match s.to_ascii_lowercase().as_str() {
            "p-256" => DH_P256_BITS,
            "p-384" => DH_P384_BITS,
            "p-521" => DH_P521_BITS,
            _ => DEFAULT_DH_MIN_BITS,
        },
    }
}

/// Why a key-exchange or key-derivation step failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum KexError {
    /// The peer's key is malformed or uses a group we do not accept.
    #[error("unacceptable key exchange parameters: {0}")]
    BadParameters(&'static str),
    /// A cryptographic operation failed.
    #[error("key exchange failure: {0}")]
    Crypto(&'static str),
}

/// A well-known key agreement group.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Group {
    /// MODP group 2 (1024 bits).
    Modp1024,
    /// MODP group 14 (2048 bits).
    Modp2048,
    /// MODP group 16 (4096 bits).
    Modp4096,
    /// NIST P-256.
    P256,
    /// NIST P-384.
    P384,
    /// NIST P-521.
    P521,
}

/// `PKINIT_DH_P256_BITS` and friends (pkinit.h:63-65): the finite-field
/// strength equivalents used to compare groups.
pub const DH_P256_BITS: u32 = 3072;
/// See [`DH_P256_BITS`].
pub const DH_P384_BITS: u32 = 7680;
/// See [`DH_P256_BITS`].
pub const DH_P521_BITS: u32 = 15360;
/// `PKINIT_DEFAULT_DH_MIN_BITS` (pkinit.h:60).
pub const DEFAULT_DH_MIN_BITS: u32 = 2048;

impl Group {
    /// Every group, in the order MIT lists them in TD-DH-PARAMETERS
    /// (pkinit_crypto_openssl.c:3224-3239).
    pub const ALL: [Group; 6] = [
        Group::P256,
        Group::P384,
        Group::P521,
        Group::Modp2048,
        Group::Modp4096,
        Group::Modp1024,
    ];

    /// Strength-equivalent bit size (`check_dh_wellknown`, :2873-2893).
    pub fn bits(self) -> u32 {
        match self {
            Group::Modp1024 => 1024,
            Group::Modp2048 => 2048,
            Group::Modp4096 => 4096,
            Group::P256 => DH_P256_BITS,
            Group::P384 => DH_P384_BITS,
            Group::P521 => DH_P521_BITS,
        }
    }

    /// The group with the given strength-equivalent size (`choose_dh_group`,
    /// :2909-2925).
    pub fn from_bits(bits: u32) -> Option<Group> {
        Group::ALL.into_iter().find(|g| g.bits() == bits)
    }

    /// Short description (`group_desc`, :2895-2907).
    pub fn name(self) -> &'static str {
        match self {
            Group::Modp1024 => "1024-bit DH",
            Group::Modp2048 => "2048-bit DH",
            Group::Modp4096 => "4096-bit DH",
            Group::P256 => "P-256",
            Group::P384 => "P-384",
            Group::P521 => "P-521",
        }
    }

    /// The AlgorithmIdentifier MIT puts in TD-DH-PARAMETERS
    /// (pkinit_constants.c `oakley_*`, `ec_p*`).
    pub fn algorithm_identifier(self) -> AlgorithmIdentifier {
        let (id, params): (&[u8], Vec<u8>) = match self {
            Group::Modp1024 => (asn1::DH_PUBLIC_NUMBER, MODP_1024_DER.to_vec()),
            Group::Modp2048 => (asn1::DH_PUBLIC_NUMBER, MODP_2048_DER.to_vec()),
            Group::Modp4096 => (asn1::DH_PUBLIC_NUMBER, MODP_4096_DER.to_vec()),
            Group::P256 => (asn1::ID_EC_PUBLIC_KEY, der::tlv(0x06, asn1::SECP256R1)),
            Group::P384 => (asn1::ID_EC_PUBLIC_KEY, der::tlv(0x06, asn1::SECP384R1)),
            Group::P521 => (asn1::ID_EC_PUBLIC_KEY, der::tlv(0x06, asn1::SECP521R1)),
        };
        AlgorithmIdentifier {
            algorithm: asn1::oid(id),
            parameters: Some(rasn::types::Any::new(params)),
        }
    }

    /// Recognise a well-known group from an AlgorithmIdentifier
    /// (`decode_dh_params`/`decode_ec_params` plus `check_dh_wellknown`).
    pub fn from_algorithm_identifier(a: &AlgorithmIdentifier) -> Option<Group> {
        let params = a.parameters.as_ref()?.as_bytes();
        if asn1::is_oid(&a.algorithm, asn1::DH_PUBLIC_NUMBER) {
            let dp: DomainParameters = rasn::der::decode(params).ok()?;
            let (p, g, q) = (to_mag(&dp.p), to_mag(&dp.g), to_mag(&dp.q));
            [Group::Modp1024, Group::Modp2048, Group::Modp4096]
                .into_iter()
                .find(|grp| {
                    let known = modp(*grp);
                    p == known.p_bytes && g == [2] && q == known.q_bytes
                })
        } else if asn1::is_oid(&a.algorithm, asn1::ID_EC_PUBLIC_KEY) {
            let (t, rest) = der::read(params)?;
            if t.tag != 0x06 || !rest.is_empty() {
                return None;
            }
            [Group::P256, Group::P384, Group::P521]
                .into_iter()
                .find(|g| t.content == curve_oid(*g))
        } else {
            None
        }
    }
}

fn curve_oid(g: Group) -> &'static [u8] {
    match g {
        Group::P256 => asn1::SECP256R1,
        Group::P384 => asn1::SECP384R1,
        _ => asn1::SECP521R1,
    }
}

fn to_mag(i: &Integer) -> Vec<u8> {
    let d = rasn::der::encode(i).expect("integer encodes");
    let (t, _) = der::read(&d).expect("integer TLV");
    der::uint_magnitude(t.content).to_vec()
}

struct Modp {
    p_bytes: Vec<u8>,
    q_bytes: Vec<u8>,
    params: BoxedMontyParams,
    bits: u32,
}

fn modp(g: Group) -> &'static Modp {
    static CACHE: OnceLock<[Modp; 3]> = OnceLock::new();
    let all = CACHE.get_or_init(|| {
        [MODP_1024_DER, MODP_2048_DER, MODP_4096_DER].map(|der_bytes| {
            let dp: DomainParameters = rasn::der::decode(der_bytes).expect("built-in group");
            let p_bytes = to_mag(&dp.p);
            let q_bytes = to_mag(&dp.q);
            let bits = (p_bytes.len() * 8) as u32;
            let prec = bits.div_ceil(64) * 64;
            let p = BoxedUint::from_be_slice(&p_bytes, prec).expect("p fits");
            let odd = Option::from(Odd::new(p)).expect("p is odd");
            Modp {
                p_bytes,
                q_bytes,
                params: BoxedMontyParams::new(odd),
                bits: prec,
            }
        })
    });
    match g {
        Group::Modp1024 => &all[0],
        Group::Modp2048 => &all[1],
        _ => &all[2],
    }
}

fn modexp(m: &Modp, base: &BoxedUint, exp: &BoxedUint) -> BoxedUint {
    BoxedMontyForm::new(base.clone(), &m.params)
        .pow(exp)
        .retrieve()
}

fn uint_from(bytes: &[u8], bits: u32) -> Result<BoxedUint, KexError> {
    BoxedUint::from_be_slice(bytes, bits).map_err(|_| KexError::BadParameters("value too large"))
}

enum Secret {
    Dh { x: BoxedUint },
    P256(p256::ecdh::EphemeralSecret),
    P384(p384::ecdh::EphemeralSecret),
    P521(p521::ecdh::EphemeralSecret),
}

/// An ephemeral key agreement key pair.
pub struct KeyPair {
    group: Group,
    secret: Secret,
    public: Vec<u8>,
}

fn random_bytes(n: usize) -> Zeroizing<Vec<u8>> {
    Zeroizing::new((0..n).map(|_| rand::random::<u8>()).collect())
}

macro_rules! ec_arms {
    ($grp:expr, $mod:ident, $variant:ident) => {{
        let secret =
            <$mod::ecdh::EphemeralSecret as $mod::elliptic_curve::Generate>::generate_from_rng(
                &mut rand::rng(),
            );
        let public = $mod::PublicKey::from(&secret).to_sec1_bytes().to_vec();
        KeyPair {
            group: $grp,
            secret: Secret::$variant(secret),
            public,
        }
    }};
}

impl KeyPair {
    /// Generate a key pair in `group` (`generate_dh_pkey`, :820-844).
    pub fn generate(group: Group) -> KeyPair {
        match group {
            Group::P256 => ec_arms!(group, p256, P256),
            Group::P384 => ec_arms!(group, p384, P384),
            Group::P521 => ec_arms!(group, p521, P521),
            _ => {
                let m = modp(group);
                // Private value in [2, q): one bit shorter than q, then
                // forced above 1.
                let q_len = m.q_bytes.len();
                let mut buf = random_bytes(q_len);
                buf[0] &= 0x7f;
                buf[q_len - 1] |= 2;
                let x = BoxedUint::from_be_slice(&buf, m.bits).expect("fits");
                let g = BoxedUint::from_be_slice(&[2], m.bits).expect("fits");
                let y = modexp(m, &g, &x);
                let public = der::uint(&y.to_be_bytes_trimmed_vartime());
                KeyPair {
                    group,
                    secret: Secret::Dh { x },
                    public,
                }
            }
        }
    }

    /// The group of this key pair.
    pub fn group(&self) -> Group {
        self.group
    }

    /// The raw public value: DER INTEGER for DH, the uncompressed point for
    /// EC (`dh_pubkey_der`, :737-818). This is the content of
    /// KDCDHKeyInfo.subjectPublicKey.
    pub fn public_value(&self) -> &[u8] {
        &self.public
    }

    /// The SubjectPublicKeyInfo a client sends in AuthPack.clientPublicValue
    /// (`encode_spki`, :404-620).
    pub fn spki(&self) -> SubjectPublicKeyInfo {
        SubjectPublicKeyInfo {
            algorithm: self.group.algorithm_identifier(),
            subject_public_key: BitString::from_slice(&self.public),
        }
    }

    /// Compute the shared secret with the peer's raw public value (`dh_result`,
    /// :677-735).
    pub fn agree(&self, peer_public: &[u8]) -> Result<Zeroizing<Vec<u8>>, KexError> {
        macro_rules! ec {
            ($mod:ident, $s:expr) => {{
                let pk = $mod::PublicKey::from_sec1_bytes(peer_public)
                    .map_err(|_| KexError::BadParameters("invalid EC point"))?;
                Ok(Zeroizing::new(
                    $s.diffie_hellman(&pk).raw_secret_bytes().to_vec(),
                ))
            }};
        }
        match &self.secret {
            Secret::P256(s) => ec!(p256, s),
            Secret::P384(s) => ec!(p384, s),
            Secret::P521(s) => ec!(p521, s),
            Secret::Dh { x } => {
                let m = modp(self.group);
                let (t, rest) =
                    der::read(peer_public).ok_or(KexError::BadParameters("bad DH public value"))?;
                if t.tag != 0x02 || !rest.is_empty() {
                    return Err(KexError::BadParameters("bad DH public value"));
                }
                let y_bytes = der::uint_magnitude(t.content);
                let y = uint_from(y_bytes, m.bits)?;
                check_dh_public(m, &y, y_bytes)?;
                let z = modexp(m, &y, x);
                let full = z.to_be_bytes();
                let want = m.p_bytes.len();
                let mut out = vec![0u8; want];
                let src = &full[full.len().saturating_sub(want)..];
                out[want - src.len()..].copy_from_slice(src);
                Ok(Zeroizing::new(out))
            }
        }
    }
}

/// `DH_check_pub_key`: 1 < y < p - 1, and y^q = 1 for these safe-prime
/// groups.
fn check_dh_public(m: &Modp, y: &BoxedUint, y_bytes: &[u8]) -> Result<(), KexError> {
    let one = BoxedUint::one_with_precision(m.bits);
    if y.cmp_vartime(&one).is_le() || y_bytes.len() > m.p_bytes.len() {
        return Err(KexError::BadParameters("DH public value too small"));
    }
    let p = uint_from(&m.p_bytes, m.bits)?;
    let pm1 = p.wrapping_sub(&one);
    if !y.cmp_vartime(&pm1).is_lt() {
        return Err(KexError::BadParameters("DH public value too large"));
    }
    let q = uint_from(&m.q_bytes, m.bits)?;
    if modexp(m, y, &q) != one {
        return Err(KexError::BadParameters("DH public value not in subgroup"));
    }
    Ok(())
}

/// Decode a peer SubjectPublicKeyInfo into its well-known group and raw
/// public value (`decode_spki`, `check_dh_wellknown`).
pub fn decode_spki(spki: &SubjectPublicKeyInfo) -> Result<(Group, Vec<u8>), KexError> {
    let group = Group::from_algorithm_identifier(&spki.algorithm)
        .ok_or(KexError::BadParameters("not a well-known group"))?;
    let raw = spki.subject_public_key.as_raw_slice().to_vec();
    if !spki.subject_public_key.len().is_multiple_of(8) {
        return Err(KexError::BadParameters("public key is not whole bytes"));
    }
    Ok((group, raw))
}

/// `pkinit_kdf`'s algorithm selection (RFC 8636): no id means RFC 4556's
/// octetstring2key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kdf {
    /// id-pkinit-kdf-ah-sha1.
    Sha1,
    /// id-pkinit-kdf-ah-sha256.
    Sha256,
    /// id-pkinit-kdf-ah-sha512.
    Sha512,
}

impl Kdf {
    /// The server's preference order (`supported_kdf_alg_ids`,
    /// pkinit_constants.c:49-54), also the order a client offers.
    pub const SUPPORTED: [Kdf; 3] = [Kdf::Sha256, Kdf::Sha1, Kdf::Sha512];

    /// The OID content bytes.
    pub fn oid_bytes(self) -> &'static [u8] {
        match self {
            Kdf::Sha1 => asn1::KDF_SHA1,
            Kdf::Sha256 => asn1::KDF_SHA256,
            Kdf::Sha512 => asn1::KDF_SHA512,
        }
    }

    /// Recognise a KDF OID.
    pub fn from_oid(id: &rasn::types::ObjectIdentifier) -> Option<Kdf> {
        Kdf::SUPPORTED
            .into_iter()
            .find(|k| asn1::is_oid(id, k.oid_bytes()))
    }

    fn hash(self, parts: &[&[u8]]) -> Vec<u8> {
        fn run<D: Digest>(parts: &[&[u8]]) -> Vec<u8> {
            let mut d = D::new();
            for p in parts {
                d.update(p);
            }
            d.finalize().to_vec()
        }
        match self {
            Kdf::Sha1 => run::<Sha1>(parts),
            Kdf::Sha256 => run::<Sha256>(parts),
            Kdf::Sha512 => run::<Sha512>(parts),
        }
    }
}

/// `octetstring2key` (RFC 4556 3.2.3.1; pkinit_crypto_openssl.c:2570-2650):
/// concatenated `SHA1(counter || secret)` blocks give the key material.
pub fn octetstring2key(etype: i32, secret: &[u8]) -> Result<EncryptionKey, KexError> {
    let profile = find_etype(etype).map_err(|_| KexError::Crypto("unsupported enctype"))?;
    let mut buf = Vec::with_capacity(secret.len() + 20);
    let mut counter = 0u8;
    while buf.len() < secret.len() {
        buf.extend(Kdf::Sha1.hash(&[&[counter], secret]));
        counter = counter.wrapping_add(1);
    }
    if buf.len() < profile.key_bytes() {
        return Err(KexError::Crypto("secret too short for the enctype"));
    }
    let seed = &buf[..profile.key_bytes()];
    let key = profile
        .random_to_key(seed)
        .map_err(|_| KexError::Crypto("random-to-key failed"))?;
    Ok(EncryptionKey::new(etype, key.to_vec()))
}

fn principal_info(name: &PrincipalName, realm: &str) -> Result<OctetString, KexError> {
    let realm = rasn::types::GeneralString::from_bytes(realm.as_bytes())
        .map_err(|_| KexError::Crypto("invalid realm"))?;
    let der = rasn::der::encode(&Krb5PrincipalName {
        realm,
        principal_name: name.clone(),
    })
    .map_err(|_| KexError::Crypto("encoding principal"))?;
    Ok(OctetString::from(der))
}

/// `pkinit_kdf` (pkinit_crypto_openssl.c:2784-2870, RFC 8636 3.1): derive the
/// AS reply key. `as_req` is the encoded AS-REQ and `pk_as_rep` the encoded
/// PA-PK-AS-REP; `party_u` is the client and `party_v` the server principal
/// as they appear in the request.
pub fn pkinit_kdf(
    secret: &[u8],
    kdf: Option<Kdf>,
    etype: i32,
    party_u: (&PrincipalName, &str),
    party_v: (&PrincipalName, &str),
    as_req: &[u8],
    pk_as_rep: &[u8],
) -> Result<EncryptionKey, KexError> {
    let Some(kdf) = kdf else {
        return octetstring2key(etype, secret);
    };
    let profile = find_etype(etype).map_err(|_| KexError::Crypto("unsupported enctype"))?;
    let rand_len = profile.key_bytes();
    let material = sskdf_material(
        secret, kdf, etype, party_u, party_v, as_req, pk_as_rep, rand_len,
    )?;
    let key = profile
        .random_to_key(&material)
        .map_err(|_| KexError::Crypto("random-to-key failed"))?;
    Ok(EncryptionKey::new(etype, key.to_vec()))
}

/// The OtherInfo-keyed SP 800-56A output of `pkinit_kdf` before
/// random-to-key (`rand_len` bytes).
#[expect(
    clippy::too_many_arguments,
    reason = "mirrors pkinit_kdf plus the key length"
)]
pub(super) fn sskdf_material(
    secret: &[u8],
    kdf: Kdf,
    etype: i32,
    party_u: (&PrincipalName, &str),
    party_v: (&PrincipalName, &str),
    as_req: &[u8],
    pk_as_rep: &[u8],
    rand_len: usize,
) -> Result<Zeroizing<Vec<u8>>, KexError> {
    let supp = rasn::der::encode(&PkinitSuppPubInfo {
        enctype: etype,
        as_req: OctetString::from(as_req.to_vec()),
        pk_as_rep: OctetString::from(pk_as_rep.to_vec()),
    })
    .map_err(|_| KexError::Crypto("encoding SuppPubInfo"))?;
    let other = rasn::der::encode(&OtherInfo {
        algorithm_identifier: asn1::alg(kdf.oid_bytes()),
        party_u_info: principal_info(party_u.0, party_u.1)?,
        party_v_info: principal_info(party_v.0, party_v.1)?,
        supp_pub_info: OctetString::from(supp),
    })
    .map_err(|_| KexError::Crypto("encoding OtherInfo"))?;

    // SP 800-56A concatenation KDF (builtin_sskdf, :2717-2783).
    let mut material = Zeroizing::new(Vec::new());
    let mut counter = 1u32;
    while material.len() < rand_len {
        material.extend(kdf.hash(&[&counter.to_be_bytes(), secret, &other]));
        counter += 1;
    }
    material.truncate(rand_len);
    Ok(material)
}

#[cfg(test)]
mod tests;
