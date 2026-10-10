//! HMAC-MD5 keyed checksum (`KERB_CHECKSUM_HMAC_MD5`, type -138; RFC 4757
//! section 4, MS-SFU 2.2.1), MIT lib/crypto/krb/checksum_hmac_md5.c:41-94.
//!
//! The signing key is `HMAC-MD5(key, "signaturekey\0")` and the checksum is
//! `HMAC-MD5(Ksign, MD5(usage_le32 || data))`. As in MIT the key is used as
//! raw bytes whatever the enctype it belongs to.

use hmac::{Hmac, KeyInit, Mac};
use md5::{Digest, Md5};

use super::CryptoError;

const MD5_BLOCK: usize = 64;

/// `krb5int_arcfour_translate_usage` (lib/crypto/krb/arcfour.c).
fn translate_usage(usage: i32) -> i32 {
    match usage {
        3 | 9 => 8,
        23 => 13,
        other => other,
    }
}

/// MIT rejects keys longer than the MD5 block size (`KRB5_BAD_ENCTYPE`).
pub(crate) fn hmac_md5_checksum(
    key: &[u8],
    usage: i32,
    data: &[u8],
) -> Result<[u8; 16], CryptoError> {
    if key.len() > MD5_BLOCK {
        return Err(CryptoError::BadKeySize);
    }
    let mut ks =
        <Hmac<Md5> as KeyInit>::new_from_slice(key).map_err(|_| CryptoError::BadKeySize)?;
    ks.update(b"signaturekey\0");
    let ks = ks.finalize().into_bytes();

    let mut md5 = Md5::new();
    md5.update(translate_usage(usage).to_le_bytes());
    md5.update(data);
    let inner = md5.finalize();

    let mut mac =
        <Hmac<Md5> as KeyInit>::new_from_slice(&ks).map_err(|_| CryptoError::BadKeySize)?;
    mac.update(&inner);
    Ok(mac.finalize().into_bytes().into())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// MIT lib/crypto/crypto_tests/t_cksums.c:96-103.
    #[test]
    fn matches_mit_t_cksums_vector() {
        let key = [
            0xF7, 0xD3, 0xA1, 0x55, 0xAF, 0x5E, 0x23, 0x8A, 0x0B, 0x7A, 0x87, 0x1A, 0x96, 0xBA,
            0x2A, 0xB2,
        ];
        let want = [
            0xEB, 0x38, 0xCC, 0x97, 0xE2, 0x23, 0x0F, 0x59, 0xDA, 0x41, 0x17, 0xDC, 0x58, 0x59,
            0xD7, 0xEC,
        ];
        let got = hmac_md5_checksum(&key, 6, b"seventeen eighteen nineteen twenty").expect("cksum");
        assert_eq!(got, want);
    }

    #[test]
    fn long_keys_are_rejected_and_aes_sized_keys_work() {
        assert!(hmac_md5_checksum(&[0; 65], 17, b"x").is_err());
        assert!(hmac_md5_checksum(&[7; 32], 17, b"x").is_ok());
    }
}
