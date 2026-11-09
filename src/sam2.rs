//! SAM-2 (single-use authentication mechanism) pre-authentication messages,
//! as encoded by MIT (`asn1_k_encode.c`, `k5-int.h`), and the constants the
//! `securid_sam2` KDC module and the `sam2` client module share.

use rasn::prelude::*;

use crate::plugin::rpc::ERROR_TABLE_BASE_KRB5;
use crate::types::{Checksum, EncryptedData, Flags, KerberosFlags};

/// `KRB5_PADATA_SAM_CHALLENGE_2`.
pub const PA_SAM_CHALLENGE_2: i32 = 30;
/// `KRB5_PADATA_SAM_RESPONSE_2`.
pub const PA_SAM_RESPONSE_2: i32 = 31;

/// `KRB5_KEYUSAGE_PA_SAM_CHALLENGE_CKSUM`.
pub const KEYUSAGE_CHALLENGE_CKSUM: i32 = 25;
/// `KRB5_KEYUSAGE_PA_SAM_CHALLENGE_TRACKID`.
pub const KEYUSAGE_CHALLENGE_TRACKID: i32 = 26;
/// `KRB5_KEYUSAGE_PA_SAM_RESPONSE`.
pub const KEYUSAGE_RESPONSE: i32 = 27;

/// `PA_SAM_TYPE_SECURID` (Security Dynamics).
pub const TYPE_SECURID: i32 = 5;
/// `PA_SAM_TYPE_GRAIL` (`PA_SAM_TYPE_EXP_BASE + 0`, for testing).
pub const TYPE_GRAIL: i32 = 128;

/// `KRB5_PREAUTH_BAD_TYPE`.
pub const PREAUTH_BAD_TYPE: i32 = ERROR_TABLE_BASE_KRB5 + 208;
/// `KRB5_PREAUTH_NO_KEY`.
pub const PREAUTH_NO_KEY: i32 = ERROR_TABLE_BASE_KRB5 + 209;
/// `KRB5_SAM_UNSUPPORTED`.
pub const SAM_UNSUPPORTED: i32 = ERROR_TABLE_BASE_KRB5 + 225;
/// `KRB5_SAM_INVALID_ETYPE`.
pub const SAM_INVALID_ETYPE: i32 = ERROR_TABLE_BASE_KRB5 + 226;
/// `KRB5_SAM_NO_CHECKSUM`.
pub const SAM_NO_CHECKSUM: i32 = ERROR_TABLE_BASE_KRB5 + 227;

/// `KRB5_LIBOS_CANTREADPWD`.
pub const LIBOS_CANTREADPWD: i32 = ERROR_TABLE_BASE_KRB5 + 130;
/// `KRB5KRB_AP_ERR_BAD_INTEGRITY`.
pub const AP_ERR_BAD_INTEGRITY: i32 = ERROR_TABLE_BASE_KRB5 + 31;

/// The prompt MIT's `sam2` client module shows (preauth_sam2.c).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sam2Prompt {
    /// Prompter name: `sam-type-name`, or "SAM Authentication".
    pub name: String,
    /// Prompter banner: `sam-challenge-label`, or a label for the SAM type.
    pub banner: String,
    /// "Challenge is [<challenge>], " (if there is a challenge), then
    /// `sam-response-prompt` or "passcode". The answer is hidden.
    pub prompt: String,
}

/// Answers a [`Sam2Prompt`] with the single-use authentication data, as
/// MIT's prompter does; `None` fails the mechanism.
#[derive(Clone)]
pub struct Sam2Responder(pub std::sync::Arc<Sam2Answer>);

/// The function behind a [`Sam2Responder`].
pub type Sam2Answer = dyn Fn(&Sam2Prompt) -> Option<String> + Send + Sync;

impl std::fmt::Debug for Sam2Responder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Sam2Responder")
    }
}

/// `sam_challenge_banner` (preauth_sam2.c).
pub fn challenge_banner(sam_type: i32) -> &'static str {
    match sam_type {
        1 => "Challenge for Enigma Logic mechanism",
        2 | 8 => "Challenge for Digital Pathways mechanism",
        6 | 7 => "Challenge for Activcard mechanism",
        3 => "Challenge for Enhanced S/Key mechanism",
        4 => "Challenge for Traditional S/Key mechanism",
        TYPE_SECURID | 129 => "Challenge for Security Dynamics mechanism",
        _ => "Challenge from authentication server",
    }
}

bitflags::bitflags! {
    /// `sam-flags` (`KRB5_SAM_*`).
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct SamFlags: u32 {
        /// `KRB5_SAM_USE_SAD_AS_KEY`.
        const USE_SAD_AS_KEY      = 0x8000_0000;
        /// `KRB5_SAM_SEND_ENCRYPTED_SAD`.
        const SEND_ENCRYPTED_SAD  = 0x4000_0000;
        /// `KRB5_SAM_MUST_PK_ENCRYPT_SAD`.
        const MUST_PK_ENCRYPT_SAD = 0x2000_0000;
    }
}

impl Flags for SamFlags {
    fn to_bytes(&self) -> [u8; 4] {
        self.bits().to_be_bytes()
    }
    fn from_bytes(bytes: &[u8]) -> Self {
        let mut b = [0u8; 4];
        b[..bytes.len().min(4)].copy_from_slice(&bytes[..bytes.len().min(4)]);
        Self::from_bits_retain(u32::from_be_bytes(b))
    }
    fn empty() -> Self {
        SamFlags::empty()
    }
}

/// `krb5_sam_challenge_2`: the DER of the body, and its checksums.
#[derive(AsnType, Encode, Decode, Debug, Clone)]
pub struct SamChallenge2 {
    /// `sam_body`.
    #[rasn(tag(explicit(context, 0)))]
    pub body: Any,
    /// `sam_cksum`.
    #[rasn(tag(explicit(context, 1)))]
    pub cksum: SequenceOf<Checksum>,
}

/// `krb5_sam_challenge_2_body`.
#[derive(AsnType, Encode, Decode, Debug, Clone, PartialEq, Eq)]
pub struct SamChallenge2Body {
    /// `sam_sam_type`.
    #[rasn(tag(explicit(context, 0)))]
    pub sam_type: i32,
    /// `sam_flags`.
    #[rasn(tag(explicit(context, 1)))]
    pub flags: KerberosFlags<SamFlags>,
    /// `sam_type_name`.
    #[rasn(tag(explicit(context, 2)))]
    pub type_name: Option<OctetString>,
    /// `sam_track_id`.
    #[rasn(tag(explicit(context, 3)))]
    pub track_id: Option<OctetString>,
    /// `sam_challenge_label`.
    #[rasn(tag(explicit(context, 4)))]
    pub challenge_label: Option<OctetString>,
    /// `sam_challenge`.
    #[rasn(tag(explicit(context, 5)))]
    pub challenge: Option<OctetString>,
    /// `sam_response_prompt`.
    #[rasn(tag(explicit(context, 6)))]
    pub response_prompt: Option<OctetString>,
    /// `sam_pk_for_sad`.
    #[rasn(tag(explicit(context, 7)))]
    pub pk_for_sad: Option<OctetString>,
    /// `sam_nonce`.
    #[rasn(tag(explicit(context, 8)))]
    pub nonce: i32,
    /// `sam_etype`.
    #[rasn(tag(explicit(context, 9)))]
    pub etype: i32,
}

/// `krb5_enc_sam_response_enc_2`.
#[derive(AsnType, Encode, Decode, Debug, Clone, PartialEq, Eq)]
pub struct EncSamResponseEnc2 {
    /// `sam_nonce`.
    #[rasn(tag(explicit(context, 0)))]
    pub nonce: i32,
    /// `sam_sad`.
    #[rasn(tag(explicit(context, 1)))]
    pub sad: Option<OctetString>,
}

/// `krb5_sam_response_2`.
#[derive(AsnType, Encode, Decode, Debug, Clone)]
pub struct SamResponse2 {
    /// `sam_sam_type`.
    #[rasn(tag(explicit(context, 0)))]
    pub sam_type: i32,
    /// `sam_flags`.
    #[rasn(tag(explicit(context, 1)))]
    pub flags: KerberosFlags<SamFlags>,
    /// `sam_track_id`.
    #[rasn(tag(explicit(context, 2)))]
    pub track_id: Option<OctetString>,
    /// `sam_enc_nonce_or_sad`.
    #[rasn(tag(explicit(context, 3)))]
    pub enc_nonce_or_sad: EncryptedData,
    /// `sam_nonce`.
    #[rasn(tag(explicit(context, 4)))]
    pub nonce: i32,
}

/// MIT stores absent optional strings as empty data and omits them.
pub(crate) fn opt(b: &[u8]) -> Option<OctetString> {
    (!b.is_empty()).then(|| OctetString::from(b.to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        s.split_whitespace()
            .map(|b| u8::from_str_radix(b, 16).expect("hex"))
            .collect()
    }

    // MIT tests/asn.1/reference_encode.out:51-54 (ktest.c:487-531).
    #[test]
    fn mit_reference_encodings() {
        let sc2 = SamChallenge2 {
            body: Any::new(hex("30 0B 04 09 63 68 61 6C 6C 65 6E 67 65")),
            cksum: vec![Checksum {
                cksumtype: 1,
                checksum: b"1234".to_vec().into(),
            }],
        };
        let want = hex(
            "30 22 A0 0D 30 0B 04 09 63 68 61 6C 6C 65 6E 67 65 A1 11 30 0F 30 0D A0 03 02 01 01 \
             A1 06 04 04 31 32 33 34",
        );
        assert_eq!(rasn::der::encode(&sc2).expect("enc"), want);
        let back: SamChallenge2 = rasn::der::decode(&want).expect("dec");
        assert_eq!(back.body.as_bytes(), sc2.body.as_bytes());

        let body = SamChallenge2Body {
            sam_type: 42,
            flags: SamFlags::USE_SAD_AS_KEY.into(),
            type_name: opt(b"type name"),
            track_id: None,
            challenge_label: opt(b"challenge label"),
            challenge: opt(b"challenge ipse"),
            response_prompt: opt(b"response_prompt ipse"),
            pk_for_sad: None,
            nonce: 0x543210,
            etype: 20,
        };
        let want = hex(
            "30 64 A0 03 02 01 2A A1 07 03 05 00 80 00 00 00 A2 0B 04 09 74 79 70 65 20 6E 61 6D \
             65 A4 11 04 0F 63 68 61 6C 6C 65 6E 67 65 20 6C 61 62 65 6C A5 10 04 0E 63 68 61 6C \
             6C 65 6E 67 65 20 69 70 73 65 A6 16 04 14 72 65 73 70 6F 6E 73 65 5F 70 72 6F 6D 70 \
             74 20 69 70 73 65 A8 05 02 03 54 32 10 A9 03 02 01 14",
        );
        assert_eq!(rasn::der::encode(&body).expect("enc"), want);
        assert_eq!(
            rasn::der::decode::<SamChallenge2Body>(&want).expect("dec"),
            body
        );

        let sr2 = SamResponse2 {
            sam_type: 43,
            flags: SamFlags::USE_SAD_AS_KEY.into(),
            track_id: opt(b"track data"),
            enc_nonce_or_sad: EncryptedData {
                etype: 20,
                kvno: Some(3382),
                cipher: b"nonce or sad".to_vec().into(),
            },
            nonce: 0x543210,
        };
        let want = hex(
            "30 42 A0 03 02 01 2B A1 07 03 05 00 80 00 00 00 A2 0C 04 0A 74 72 61 63 6B 20 64 61 \
             74 61 A3 1D 30 1B A0 03 02 01 14 A1 04 02 02 0D 36 A2 0E 04 0C 6E 6F 6E 63 65 20 6F \
             72 20 73 61 64 A4 05 02 03 54 32 10",
        );
        assert_eq!(rasn::der::encode(&sr2).expect("enc"), want);
        let back: SamResponse2 = rasn::der::decode(&want).expect("dec");
        assert_eq!(back.track_id, sr2.track_id);
        assert_eq!(back.nonce, sr2.nonce);

        let esre = EncSamResponseEnc2 {
            nonce: 88,
            sad: opt(b"enc_sam_response_enc_2"),
        };
        let want = hex(
            "30 1F A0 03 02 01 58 A1 18 04 16 65 6E 63 5F 73 61 6D 5F 72 65 73 70 6F 6E 73 65 5F \
             65 6E 63 5F 32",
        );
        assert_eq!(rasn::der::encode(&esre).expect("enc"), want);
        assert_eq!(
            rasn::der::decode::<EncSamResponseEnc2>(&want).expect("dec"),
            esre
        );
    }
}
