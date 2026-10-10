//! AES-128-CTS-HMAC-SHA1-96 (etype 17) and AES-256-CTS-HMAC-SHA1-96 (etype 18).
//!
//! Both variants share identical logic parameterized by key size,
//! matching MIT's approach where both use the same encrypt/decrypt functions.

use sha1::Digest;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use super::aes_cts::{aes_cts_decrypt, aes_cts_encrypt};
use super::dk::{derive_key, dk};
use super::hmac_sha1::hmac_sha1_96;
use super::util::generate_random;
use super::{CryptoError, EtypeProfile, KeyPurpose};

const AES_BLOCK: usize = 16;
const HMAC_TRAILER: usize = 12; // HMAC-SHA1-96 = 96 bits

/// AES-128-CTS-HMAC-SHA1-96 (etype 17).
pub struct Aes128CtsHmacSha196;

/// AES-256-CTS-HMAC-SHA1-96 (etype 18).
pub struct Aes256CtsHmacSha196;

// Shared implementation parameterized by key size.
// `expected_key_len` enforces that the key matches the profile (16 for AES-128, 32 for AES-256).
fn aes_encrypt(
    key: &[u8],
    key_usage: i32,
    plaintext: &[u8],
    expected_key_len: usize,
) -> Result<Vec<u8>, CryptoError> {
    validate_exact_key_len(key, expected_key_len)?;
    let ke = derive_key(key, key_usage, 0xAA)?;
    let ki = derive_key(key, key_usage, 0x55)?;

    let confounder = generate_random(AES_BLOCK);
    let mut data = Zeroizing::new(Vec::with_capacity(AES_BLOCK + plaintext.len()));
    data.extend_from_slice(&confounder);
    data.extend_from_slice(plaintext);

    let hmac = hmac_sha1_96(&ki, &data);
    let mut ct = aes_cts_encrypt(&ke, &data)?;
    ct.extend_from_slice(&hmac);
    Ok(ct)
}

fn aes_decrypt(
    key: &[u8],
    key_usage: i32,
    ciphertext: &[u8],
    expected_key_len: usize,
) -> Result<Vec<u8>, CryptoError> {
    validate_exact_key_len(key, expected_key_len)?;
    let ke = derive_key(key, key_usage, 0xAA)?;
    let ki = derive_key(key, key_usage, 0x55)?;

    let ct_len = ciphertext
        .len()
        .checked_sub(HMAC_TRAILER)
        .ok_or(CryptoError::InputTooShort)?;

    if ct_len < AES_BLOCK {
        return Err(CryptoError::InputTooShort);
    }

    let (ct, received_hmac) = ciphertext.split_at(ct_len);
    let plain = Zeroizing::new(aes_cts_decrypt(&ke, ct)?);
    let computed_hmac = hmac_sha1_96(&ki, plain.as_slice());

    if !bool::from(computed_hmac.ct_eq(received_hmac)) {
        return Err(CryptoError::IntegrityFailure);
    }

    Ok(plain[AES_BLOCK..].to_vec()) // strip confounder
}

fn aes_string_to_key(
    password: &[u8],
    salt: &[u8],
    params: Option<&[u8]>,
    key_length: usize,
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let iter_count = match params {
        Some(p) if p.len() == 4 => {
            let arr: [u8; 4] = p.try_into().map_err(|_| CryptoError::BadParams)?;
            let count = u32::from_be_bytes(arr);
            // RFC 3962: 0x00000000 means 2^32 iterations (sentinel), reject as unsupported
            if count == 0 {
                return Err(CryptoError::BadParams);
            }
            count
        }
        Some(_) => return Err(CryptoError::BadParams),
        None => 4096,
    };

    let mut seed = Zeroizing::new(vec![0u8; key_length]);
    pbkdf2::pbkdf2_hmac::<sha1::Sha1>(password, salt, iter_count, &mut seed);

    let derived = dk(&seed, b"kerberos", key_length, AES_BLOCK)?;
    Ok(Zeroizing::new(derived))
}

/// Strictly enforce that `key.len()` matches the expected length for a profile.
fn validate_exact_key_len(key: &[u8], expected: usize) -> Result<(), CryptoError> {
    if key.len() == expected {
        Ok(())
    } else {
        Err(CryptoError::BadKeySize)
    }
}

fn aes_checksum(
    key: &[u8],
    key_usage: i32,
    data: &[u8],
    expected_key_len: usize,
) -> Result<Vec<u8>, CryptoError> {
    validate_exact_key_len(key, expected_key_len)?;
    let kc = derive_key(key, key_usage, 0x99)?;
    Ok(hmac_sha1_96(&kc, data))
}

fn aes_random_to_key(random: &[u8], expected: usize) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    if random.len() != expected {
        return Err(CryptoError::BadKeySize);
    }
    Ok(Zeroizing::new(random.to_vec()))
}

/// RFC 3961 §5.3 simplified-profile PRF (MIT krb/prf_dk.c:30-67):
/// tmp = SHA-1(input) truncated to the block size (16); out =
/// AES-CBC(DK(key, "prf"), IV=0, tmp).
fn aes_prf(key: &[u8], input: &[u8], key_len: usize) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    validate_exact_key_len(key, key_len)?;
    let mut tmp = sha1::Sha1::digest(input).to_vec();
    tmp.truncate(AES_BLOCK);
    let kp = dk(key, b"prf", key_len, AES_BLOCK)?;
    let out = aes_cts_encrypt(&kp, &tmp)?;
    Ok(Zeroizing::new(out))
}

macro_rules! impl_aes_sha1_profile {
    ($t:ty, $etype:expr, $klen:expr, $cksum:expr) => {
        impl EtypeProfile for $t {
            fn etype(&self) -> i32 {
                $etype
            }
            fn key_bytes(&self) -> usize {
                $klen
            }
            fn key_length(&self) -> usize {
                $klen
            }
            fn block_size(&self) -> usize {
                AES_BLOCK
            }
            fn confounder_size(&self) -> usize {
                AES_BLOCK
            }
            fn checksum_size(&self) -> usize {
                HMAC_TRAILER
            }
            fn checksum_type(&self) -> i32 {
                $cksum
            }

            fn encrypt(
                &self,
                key: &[u8],
                key_usage: i32,
                plaintext: &[u8],
            ) -> Result<Vec<u8>, CryptoError> {
                aes_encrypt(key, key_usage, plaintext, self.key_length())
            }

            fn decrypt(
                &self,
                key: &[u8],
                key_usage: i32,
                ciphertext: &[u8],
            ) -> Result<Vec<u8>, CryptoError> {
                aes_decrypt(key, key_usage, ciphertext, self.key_length())
            }

            fn string_to_key(
                &self,
                password: &[u8],
                salt: &[u8],
                params: Option<&[u8]>,
            ) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
                aes_string_to_key(password, salt, params, $klen)
            }

            fn checksum(
                &self,
                key: &[u8],
                key_usage: i32,
                data: &[u8],
            ) -> Result<Vec<u8>, CryptoError> {
                aes_checksum(key, key_usage, data, self.key_length())
            }

            fn derive_key(
                &self,
                key: &[u8],
                usage: i32,
                purpose: KeyPurpose,
            ) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
                validate_exact_key_len(key, self.key_length())?;
                derive_key(key, usage, purpose.byte())
            }

            fn prf_length(&self) -> usize {
                AES_BLOCK
            }

            fn prf(&self, key: &[u8], input: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
                aes_prf(key, input, self.key_length())
            }

            fn random_to_key(&self, random: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
                aes_random_to_key(random, $klen)
            }
        }
    };
}

// checksum types: 15 = hmac-sha1-96-aes128, 16 = hmac-sha1-96-aes256
impl_aes_sha1_profile!(Aes128CtsHmacSha196, 17, 16, 15);
impl_aes_sha1_profile!(Aes256CtsHmacSha196, 18, 32, 16);

#[cfg(test)]
mod tests;
