//! Kerberos encryption and checksum framework (RFC 3961).
//!
//! Provides pluggable encryption type profiles behind the [`EtypeProfile`] trait,
//! with a global registry for runtime lookup by etype number.

mod aes_cts;
mod aes_sha1;
mod aes_sha2;
mod dk;
mod hmac_sha1;
mod nfold;
pub(crate) mod util;

pub use aes_sha1::{Aes128CtsHmacSha196, Aes256CtsHmacSha196};
pub use aes_sha2::{Aes128CtsHmacSha256128, Aes256CtsHmacSha384192};

use std::collections::HashMap;
use std::sync::LazyLock;

use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::types::EncryptionKey;

/// Standard Kerberos key usage values (RFC 4120).
pub mod key_usage {
    /// Client pre-auth encrypted timestamp.
    pub const PA_ENC_TIMESTAMP: i32 = 1;
    /// Ticket encrypted part (KDC uses service key).
    pub const TICKET: i32 = 2;
    /// AS-REP encrypted part (client's key).
    pub const AS_REP_ENCPART: i32 = 3;
    /// TGS-REQ authenticator checksum (session key).
    pub const TGS_REQ_AUTH_CKSUM: i32 = 6;
    /// TGS-REQ authenticator (encrypted with session key).
    pub const TGS_REQ_AUTH: i32 = 7;
    /// TGS-REP enc-part (session key -- Heimdal compat).
    pub const TGS_REP_ENCPART_SESSKEY: i32 = 8;
    /// TGS-REP enc-part (subkey -- preferred).
    pub const TGS_REP_ENCPART_SUBKEY: i32 = 9;
    /// AP-REQ authenticator checksum.
    pub const AP_REQ_AUTH_CKSUM: i32 = 10;
    /// AP-REQ authenticator.
    pub const AP_REQ_AUTH: i32 = 11;
    /// AP-REP encrypted part.
    pub const AP_REP_ENCPART: i32 = 12;
    /// KRB-PRIV encrypted part.
    pub const KRB_PRIV_ENCPART: i32 = 13;
    /// KRB-CRED encrypted part.
    pub const KRB_CRED_ENCPART: i32 = 14;
    /// KRB-SAFE checksum.
    pub const KRB_SAFE_CKSUM: i32 = 15;
    /// PA-REQ-ENC-PA-REP checksum over the AS-REQ (RFC 6806 §11).
    pub const AS_REQ: i32 = 56;
    /// FAST request checksum over the request body / AP-REQ (RFC 6113 §5.4.2).
    pub const FAST_REQ_CHKSUM: i32 = 50;
    /// FAST encrypted KrbFastReq (RFC 6113 §5.4.2).
    pub const FAST_ENC: i32 = 51;
    /// FAST encrypted KrbFastResponse (RFC 6113 §5.4.3).
    pub const FAST_REP: i32 = 52;
    /// FAST finished ticket checksum (RFC 6113 §5.4.3).
    pub const FAST_FINISHED: i32 = 53;
    /// Client-direction encrypted challenge (RFC 6113 §5.4.5).
    pub const ENC_CHALLENGE_CLIENT: i32 = 54;
    /// KDC-direction encrypted challenge (RFC 6113 §5.4.5).
    pub const ENC_CHALLENGE_KDC: i32 = 55;
}

/// Errors from cryptographic operations.
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    /// Integrity check (HMAC) failed during decryption.
    #[error("integrity check failed")]
    IntegrityFailure,

    /// Input too short for the expected operation.
    #[error("input too short for decryption")]
    InputTooShort,

    /// Key size does not match the expected length.
    #[error("invalid key size")]
    BadKeySize,

    /// Invalid string-to-key parameters.
    #[error("invalid string-to-key parameters")]
    BadParams,

    /// Checksum verification failed.
    #[error("checksum mismatch")]
    ChecksumMismatch,

    /// Requested encryption type is not supported/registered.
    #[error("unsupported encryption type")]
    UnsupportedEtype,
}

/// Purpose of a derived sub-key — the fifth byte of the derivation constant
/// (RFC 3961 §5.1, RFC 8009 §3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyPurpose {
    /// Encryption sub-key (Ke) — derivation byte 0xAA.
    Encryption,
    /// Integrity sub-key (Ki) — derivation byte 0x55.
    Integrity,
    /// Checksum sub-key (Kc) — derivation byte 0x99.
    Checksum,
}

impl KeyPurpose {
    /// The derivation-constant byte for this purpose.
    pub(crate) fn byte(self) -> u8 {
        match self {
            Self::Encryption => 0xAA,
            Self::Integrity => 0x55,
            Self::Checksum => 0x99,
        }
    }
}

/// A complete RFC 3961 encryption type profile.
///
/// Each implementation bundles a cipher, checksum algorithm, and
/// string-to-key function into a single coherent profile.
pub trait EtypeProfile: Send + Sync {
    /// The etype number (e.g., 17 for AES128, 18 for AES256).
    fn etype(&self) -> i32;

    /// Key size in bytes (input to `random_to_key`).
    fn key_bytes(&self) -> usize;

    /// Actual protocol key length in bytes.
    fn key_length(&self) -> usize;

    /// Block size of the underlying cipher.
    fn block_size(&self) -> usize;

    /// Size of the confounder prepended to plaintext.
    fn confounder_size(&self) -> usize;

    /// Size of the integrity checksum appended to ciphertext.
    fn checksum_size(&self) -> usize;

    /// The mandatory checksum type number for this etype (RFC 3961 §6.2).
    ///
    /// For AES128: `hmac-sha1-96-aes128` (15).
    /// For AES256: `hmac-sha1-96-aes256` (16).
    ///
    /// Required method (no default) — every etype MUST define its checksum type.
    /// Crate is pre-1.0; no downstream implementors exist.
    fn checksum_type(&self) -> i32;

    /// Encrypt plaintext with the given key and key usage number.
    fn encrypt(&self, key: &[u8], key_usage: i32, plaintext: &[u8])
        -> Result<Vec<u8>, CryptoError>;

    /// Decrypt ciphertext with the given key and key usage number.
    /// Verifies integrity and strips confounder.
    fn decrypt(
        &self,
        key: &[u8],
        key_usage: i32,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, CryptoError>;

    /// Derive an encryption key from a password and salt.
    fn string_to_key(
        &self,
        password: &[u8],
        salt: &[u8],
        params: Option<&[u8]>,
    ) -> Result<Zeroizing<Vec<u8>>, CryptoError>;

    /// Compute a keyed checksum over data.
    fn checksum(&self, key: &[u8], key_usage: i32, data: &[u8]) -> Result<Vec<u8>, CryptoError>;

    /// Derive a sub-key for the given usage and purpose.
    ///
    /// aes-sha1 profiles: RFC 3961 DK(key, BE32(usage) || purpose).
    /// aes-sha2 profiles: RFC 8009 §3 KDF-HMAC-SHA2(key,
    /// BE32(usage) || purpose, k) with k = key_length bits for
    /// `Encryption`, and 128 (etype 19) / 192 (etype 20) bits for
    /// `Integrity`/`Checksum` (MIT krb/enc_etm.c:50-82).
    fn derive_key(
        &self,
        key: &[u8],
        usage: i32,
        purpose: KeyPurpose,
    ) -> Result<Zeroizing<Vec<u8>>, CryptoError>;

    /// Length in bytes of one [`EtypeProfile::prf`] output block.
    fn prf_length(&self) -> usize;

    /// Pseudo-random function over `input` keyed by `key`.
    ///
    /// aes-sha1: RFC 3961 §5.3 simplified-profile PRF
    /// (MIT krb/prf_dk.c). aes-sha2: RFC 8009 §5 PRF =
    /// KDF-HMAC-SHA2(key, "prf" || input, 256/384 bits)
    /// (MIT krb/prf_aes2.c:36-43).
    fn prf(&self, key: &[u8], input: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoError>;

    /// Verify a keyed checksum using constant-time comparison.
    fn verify_checksum(
        &self,
        key: &[u8],
        key_usage: i32,
        data: &[u8],
        checksum: &[u8],
    ) -> Result<(), CryptoError> {
        let computed = self.checksum(key, key_usage, data)?;
        if bool::from(computed.ct_eq(checksum)) {
            Ok(())
        } else {
            Err(CryptoError::ChecksumMismatch)
        }
    }

    /// Convert random bytes to a protocol key.
    fn random_to_key(&self, random: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoError>;
}

/// Registry of available encryption types.
pub static ETYPE_REGISTRY: LazyLock<HashMap<i32, &'static dyn EtypeProfile>> =
    LazyLock::new(|| {
        let aes128 = &Aes128CtsHmacSha196 as &dyn EtypeProfile;
        let aes256 = &Aes256CtsHmacSha196 as &dyn EtypeProfile;
        let aes128_sha2 = &Aes128CtsHmacSha256128 as &dyn EtypeProfile;
        let aes256_sha2 = &Aes256CtsHmacSha384192 as &dyn EtypeProfile;
        HashMap::from([
            (aes128.etype(), aes128),
            (aes256.etype(), aes256),
            (aes128_sha2.etype(), aes128_sha2),
            (aes256_sha2.etype(), aes256_sha2),
        ])
    });

/// Look up an etype implementation by number.
pub fn find_etype(etype: i32) -> Result<&'static dyn EtypeProfile, CryptoError> {
    ETYPE_REGISTRY
        .get(&etype)
        .copied()
        .ok_or(CryptoError::UnsupportedEtype)
}

/// Look up the profile whose mandatory checksum type matches `cksumtype`.
///
/// Maps 15→etype 17, 16→18, 19→19, 20→20; anything else is unsupported.
pub fn find_cksumtype(cksumtype: i32) -> Result<&'static dyn EtypeProfile, CryptoError> {
    let etype = match cksumtype {
        15 => 17,
        16 => 18,
        19 => 19,
        20 => 20,
        _ => return Err(CryptoError::UnsupportedEtype),
    };
    find_etype(etype)
}

/// RFC 6113 PRF+ — `PRF(key, 1||input) || PRF(key, 2||input) || ...`
/// truncated to `out_len` bytes (MIT krb/cf2.c:38-79 `krb5_c_prfplus`).
pub fn prf_plus(
    profile: &dyn EtypeProfile,
    key: &[u8],
    input: &[u8],
    out_len: usize,
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let prflen = profile.prf_length();
    if prflen == 0 {
        return Err(CryptoError::BadParams);
    }
    let nblocks = out_len.div_ceil(prflen);
    if nblocks > 255 {
        return Err(CryptoError::BadParams);
    }
    let mut prf_in = Zeroizing::new(Vec::with_capacity(1 + input.len()));
    prf_in.push(0);
    prf_in.extend_from_slice(input);
    let mut out = Zeroizing::new(Vec::with_capacity(nblocks * prflen));
    for i in 0..nblocks {
        prf_in[0] = (i + 1) as u8;
        let block = profile.prf(key, &prf_in)?;
        let take = prflen.min(out_len - i * prflen);
        out.extend_from_slice(&block[..take]);
    }
    out.truncate(out_len);
    Ok(out)
}

/// RFC 6113 §5.1 KRB-FX-CF2 — combine two keys into one keyed by `k1`'s
/// enctype (MIT krb/cf2.c:123-176 `krb5_c_fx_cf2_simple`).
pub fn fx_cf2(
    k1: &EncryptionKey,
    pepper1: &[u8],
    k2: &EncryptionKey,
    pepper2: &[u8],
) -> Result<EncryptionKey, CryptoError> {
    let out_profile = find_etype(k1.keytype)?;
    let n = out_profile.key_bytes();
    let a = prf_plus(find_etype(k1.keytype)?, k1.key_bytes(), pepper1, n)?;
    let b = prf_plus(find_etype(k2.keytype)?, k2.key_bytes(), pepper2, n)?;
    let mut xored = a;
    for (x, y) in xored.iter_mut().zip(b.iter()) {
        *x ^= y;
    }
    let key = out_profile.random_to_key(&xored)?;
    Ok(EncryptionKey::new(k1.keytype, key.to_vec()))
}

/// Derive a fresh key of `out_etype` via PRF+ (MIT krb/cf2.c:81-121
/// `krb5_c_derive_prfplus`). `out_etype` 0 keeps `k`'s enctype.
pub fn derive_prfplus(
    k: &EncryptionKey,
    input: &[u8],
    out_etype: i32,
) -> Result<EncryptionKey, CryptoError> {
    let etype = if out_etype == 0 { k.keytype } else { out_etype };
    let out_profile = find_etype(etype)?;
    let rnd = prf_plus(
        find_etype(k.keytype)?,
        k.key_bytes(),
        input,
        out_profile.key_bytes(),
    )?;
    let key = out_profile.random_to_key(&rnd)?;
    Ok(EncryptionKey::new(etype, key.to_vec()))
}
