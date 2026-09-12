//! AES-128-CTS-HMAC-SHA256-128 (etype 19) and AES-256-CTS-HMAC-SHA384-192
//! (etype 20) — RFC 8009.
//!
//! Mirrors MIT krb5: KDF-HMAC-SHA2 derivation (krb/derive.c,
//! DERIVE_SP800_108_HMAC), PBKDF2 string-to-key with enctype-name pepper
//! (krb/s2k_pbkdf2.c:196-216), and encrypt-then-MAC over IV||C
//! (krb/enc_etm.c krb5int_etm_encrypt/decrypt).

use hmac::{Hmac, KeyInit, Mac};
use sha2::{Sha256, Sha384};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use super::aes_cts::{aes_cts_decrypt, aes_cts_encrypt};
use super::util::generate_random;
use super::{CryptoError, EtypeProfile, KeyPurpose};

const AES_BLOCK: usize = 16;
/// Default PBKDF2 iteration count (RFC 8009 §4, MIT s2k_pbkdf2.c:215).
const DEFAULT_ITERATIONS: u32 = 32768;

/// AES-128-CTS-HMAC-SHA256-128 (etype 19).
pub struct Aes128CtsHmacSha256128;

/// AES-256-CTS-HMAC-SHA384-192 (etype 20).
pub struct Aes256CtsHmacSha384192;

/// Trait abstracting the SHA-2 hash used by each profile.
trait Sha2Hash {
    /// HMAC-SHA-2 of `key` over `data` (full hash length).
    fn hmac(key: &[u8], data: &[u8]) -> Vec<u8>;

    /// PBKDF2-HMAC-SHA-2 into `out`.
    fn pbkdf2(password: &[u8], salt: &[u8], iterations: u32, out: &mut [u8]);
}

struct Sha256Hash;
struct Sha384Hash;

impl Sha2Hash for Sha256Hash {
    fn hmac(key: &[u8], data: &[u8]) -> Vec<u8> {
        let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(key).expect("HMAC accepts any key");
        mac.update(data);
        mac.finalize().into_bytes().to_vec()
    }

    fn pbkdf2(password: &[u8], salt: &[u8], iterations: u32, out: &mut [u8]) {
        pbkdf2::pbkdf2_hmac::<Sha256>(password, salt, iterations, out);
    }
}

impl Sha2Hash for Sha384Hash {
    fn hmac(key: &[u8], data: &[u8]) -> Vec<u8> {
        let mut mac = <Hmac<Sha384> as KeyInit>::new_from_slice(key).expect("HMAC accepts any key");
        mac.update(data);
        mac.finalize().into_bytes().to_vec()
    }

    fn pbkdf2(password: &[u8], salt: &[u8], iterations: u32, out: &mut [u8]) {
        pbkdf2::pbkdf2_hmac::<Sha384>(password, salt, iterations, out);
    }
}

/// RFC 8009 §3 KDF-HMAC-SHA2 (MIT builtin/kdf.c:33-73
/// `k5_sp800_108_counter_hmac`):
/// `HMAC(key, BE32(1) || label || 0x00 || context || BE32(out_bits))`
/// truncated to `out_bits`/8 bytes.
fn kdf_hmac_sha2<H: Sha2Hash>(
    key: &[u8],
    label: &[u8],
    context: &[u8],
    out_bits: usize,
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    if key.is_empty() || !out_bits.is_multiple_of(8) || out_bits == 0 {
        return Err(CryptoError::BadParams);
    }
    let mut data = Vec::with_capacity(9 + label.len() + context.len());
    data.extend_from_slice(&1u32.to_be_bytes());
    data.extend_from_slice(label);
    data.push(0x00);
    data.extend_from_slice(context);
    data.extend_from_slice(&(out_bits as u32).to_be_bytes());
    let out = H::hmac(key, &data);
    Ok(Zeroizing::new(out[..out_bits / 8].to_vec()))
}

/// Derive a sub-key (MIT krb/enc_etm.c:50-82 `derive_keys`): label is
/// BE32(usage) || purpose byte. Ke uses key_length bits; Ki/Kc use half the
/// hash length (128/192 bits for etypes 19/20).
fn sha2_derive<H: Sha2Hash>(
    key: &[u8],
    usage: i32,
    purpose: KeyPurpose,
    key_len: usize,
    hash_len: usize,
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    if key.len() != key_len {
        return Err(CryptoError::BadKeySize);
    }
    let usage = u32::try_from(usage).map_err(|_| CryptoError::BadParams)?;
    let mut label = usage.to_be_bytes().to_vec();
    label.push(purpose.byte());
    let out_bits = match purpose {
        KeyPurpose::Encryption => key_len * 8,
        KeyPurpose::Integrity | KeyPurpose::Checksum => (hash_len / 2) * 8,
    };
    kdf_hmac_sha2::<H>(key, &label, b"", out_bits)
}

fn sha2_encrypt<H: Sha2Hash>(
    key: &[u8],
    usage: i32,
    plaintext: &[u8],
    key_len: usize,
    hash_len: usize,
) -> Result<Vec<u8>, CryptoError> {
    let ke = sha2_derive::<H>(key, usage, KeyPurpose::Encryption, key_len, hash_len)?;
    let ki = sha2_derive::<H>(key, usage, KeyPurpose::Integrity, key_len, hash_len)?;

    let confounder = generate_random(AES_BLOCK);
    let mut data = Zeroizing::new(Vec::with_capacity(AES_BLOCK + plaintext.len()));
    data.extend_from_slice(&confounder);
    data.extend_from_slice(plaintext);

    let ct = aes_cts_encrypt(&ke, &data)?;

    // MIT enc_etm.c: HMAC over IV || C, IV = 16 zero bytes, truncated to
    // hash_len/2.
    let mut mac_input = Vec::with_capacity(AES_BLOCK + ct.len());
    mac_input.extend_from_slice(&[0u8; AES_BLOCK]);
    mac_input.extend_from_slice(&ct);
    let tag = H::hmac(&ki, &mac_input);

    let mut out = ct;
    out.extend_from_slice(&tag[..hash_len / 2]);
    Ok(out)
}

fn sha2_decrypt<H: Sha2Hash>(
    key: &[u8],
    usage: i32,
    ciphertext: &[u8],
    key_len: usize,
    hash_len: usize,
) -> Result<Vec<u8>, CryptoError> {
    let ct_len = ciphertext
        .len()
        .checked_sub(hash_len / 2)
        .ok_or(CryptoError::InputTooShort)?;
    if ct_len < AES_BLOCK {
        return Err(CryptoError::InputTooShort);
    }

    let ki = sha2_derive::<H>(key, usage, KeyPurpose::Integrity, key_len, hash_len)?;
    let (ct, tag) = ciphertext.split_at(ct_len);
    let mut mac_input = Vec::with_capacity(AES_BLOCK + ct.len());
    mac_input.extend_from_slice(&[0u8; AES_BLOCK]);
    mac_input.extend_from_slice(ct);
    let computed = H::hmac(&ki, &mac_input);
    if !bool::from(computed[..hash_len / 2].ct_eq(tag)) {
        return Err(CryptoError::IntegrityFailure);
    }

    let ke = sha2_derive::<H>(key, usage, KeyPurpose::Encryption, key_len, hash_len)?;
    let plain = Zeroizing::new(aes_cts_decrypt(&ke, ct)?);
    Ok(plain[AES_BLOCK..].to_vec())
}

/// MIT s2k_pbkdf2.c:196-216 `krb5int_aes2_string_to_key`:
/// saltp = enctype_name || 0x00 || salt; tkey = PBKDF2-HMAC-SHAx(pw, saltp,
/// iter, key_length); key = KDF-HMAC-SHA2(tkey, "kerberos", key_length bits).
fn sha2_string_to_key<H: Sha2Hash>(
    password: &[u8],
    salt: &[u8],
    params: Option<&[u8]>,
    key_len: usize,
    enctype_name: &str,
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let iter_count = match params {
        Some(p) if p.len() == 4 => {
            let arr: [u8; 4] = p.try_into().map_err(|_| CryptoError::BadParams)?;
            let count = u32::from_be_bytes(arr);
            if count == 0 {
                return Err(CryptoError::BadParams);
            }
            count
        }
        Some(_) => return Err(CryptoError::BadParams),
        None => DEFAULT_ITERATIONS,
    };

    let mut saltp = Vec::with_capacity(enctype_name.len() + 1 + salt.len());
    saltp.extend_from_slice(enctype_name.as_bytes());
    saltp.push(0x00);
    saltp.extend_from_slice(salt);

    let mut tkey = Zeroizing::new(vec![0u8; key_len]);
    H::pbkdf2(password, &saltp, iter_count, &mut tkey);

    kdf_hmac_sha2::<H>(&tkey, b"kerberos", b"", key_len * 8)
}

fn sha2_checksum<H: Sha2Hash>(
    key: &[u8],
    usage: i32,
    data: &[u8],
    key_len: usize,
    hash_len: usize,
) -> Result<Vec<u8>, CryptoError> {
    let kc = sha2_derive::<H>(key, usage, KeyPurpose::Checksum, key_len, hash_len)?;
    Ok(H::hmac(&kc, data)[..hash_len / 2].to_vec())
}

fn sha2_random_to_key(random: &[u8], expected: usize) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    if random.len() != expected {
        return Err(CryptoError::BadKeySize);
    }
    Ok(Zeroizing::new(random.to_vec()))
}

/// RFC 8009 §5 PRF (MIT prf_aes2.c:36-43): KDF-HMAC-SHA2(key,
/// "prf" || input, hash_len bits).
fn sha2_prf<H: Sha2Hash>(
    key: &[u8],
    input: &[u8],
    hash_len: usize,
    key_len: usize,
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    if key.len() != key_len {
        return Err(CryptoError::BadKeySize);
    }
    kdf_hmac_sha2::<H>(key, b"prf", input, hash_len * 8)
}

impl EtypeProfile for Aes128CtsHmacSha256128 {
    fn etype(&self) -> i32 {
        19
    }
    fn key_bytes(&self) -> usize {
        16
    }
    fn key_length(&self) -> usize {
        16
    }
    fn block_size(&self) -> usize {
        AES_BLOCK
    }
    fn confounder_size(&self) -> usize {
        AES_BLOCK
    }
    fn checksum_size(&self) -> usize {
        16 // hmac-sha256-128
    }
    fn checksum_type(&self) -> i32 {
        19 // hmac-sha256-128-aes128
    }
    fn prf_length(&self) -> usize {
        32
    }

    fn derive_key(
        &self,
        key: &[u8],
        usage: i32,
        purpose: KeyPurpose,
    ) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        sha2_derive::<Sha256Hash>(key, usage, purpose, self.key_length(), 32)
    }

    fn encrypt(
        &self,
        key: &[u8],
        key_usage: i32,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        sha2_encrypt::<Sha256Hash>(key, key_usage, plaintext, self.key_length(), 32)
    }

    fn decrypt(
        &self,
        key: &[u8],
        key_usage: i32,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        sha2_decrypt::<Sha256Hash>(key, key_usage, ciphertext, self.key_length(), 32)
    }

    fn string_to_key(
        &self,
        password: &[u8],
        salt: &[u8],
        params: Option<&[u8]>,
    ) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        sha2_string_to_key::<Sha256Hash>(
            password,
            salt,
            params,
            self.key_length(),
            "aes128-cts-hmac-sha256-128",
        )
    }

    fn checksum(&self, key: &[u8], key_usage: i32, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        sha2_checksum::<Sha256Hash>(key, key_usage, data, self.key_length(), 32)
    }

    fn prf(&self, key: &[u8], input: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        sha2_prf::<Sha256Hash>(key, input, 32, self.key_length())
    }

    fn random_to_key(&self, random: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        sha2_random_to_key(random, 16)
    }
}

impl EtypeProfile for Aes256CtsHmacSha384192 {
    fn etype(&self) -> i32 {
        20
    }
    fn key_bytes(&self) -> usize {
        32
    }
    fn key_length(&self) -> usize {
        32
    }
    fn block_size(&self) -> usize {
        AES_BLOCK
    }
    fn confounder_size(&self) -> usize {
        AES_BLOCK
    }
    fn checksum_size(&self) -> usize {
        24 // hmac-sha384-192
    }
    fn checksum_type(&self) -> i32 {
        20 // hmac-sha384-192-aes256
    }
    fn prf_length(&self) -> usize {
        48
    }

    fn derive_key(
        &self,
        key: &[u8],
        usage: i32,
        purpose: KeyPurpose,
    ) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        sha2_derive::<Sha384Hash>(key, usage, purpose, self.key_length(), 48)
    }

    fn encrypt(
        &self,
        key: &[u8],
        key_usage: i32,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        sha2_encrypt::<Sha384Hash>(key, key_usage, plaintext, self.key_length(), 48)
    }

    fn decrypt(
        &self,
        key: &[u8],
        key_usage: i32,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        sha2_decrypt::<Sha384Hash>(key, key_usage, ciphertext, self.key_length(), 48)
    }

    fn string_to_key(
        &self,
        password: &[u8],
        salt: &[u8],
        params: Option<&[u8]>,
    ) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        sha2_string_to_key::<Sha384Hash>(
            password,
            salt,
            params,
            self.key_length(),
            "aes256-cts-hmac-sha384-192",
        )
    }

    fn checksum(&self, key: &[u8], key_usage: i32, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        sha2_checksum::<Sha384Hash>(key, key_usage, data, self.key_length(), 48)
    }

    fn prf(&self, key: &[u8], input: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        sha2_prf::<Sha384Hash>(key, input, 48, self.key_length())
    }

    fn random_to_key(&self, random: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        sha2_random_to_key(random, 32)
    }
}
