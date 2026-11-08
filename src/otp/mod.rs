//! OTP pre-authentication (RFC 6560; MIT `plugins/preauth/otp` and
//! `lib/krb5/krb/preauth_otp.c`).

use crate::types::{EncryptedData, KerberosTime};
use rasn::prelude::*;

/// `KRB5_PADATA_OTP_CHALLENGE`.
pub const PA_OTP_CHALLENGE: i32 = 141;
/// `KRB5_PADATA_OTP_REQUEST`.
pub const PA_OTP_REQUEST: i32 = 142;
/// `KRB5_KEYUSAGE_PA_OTP_REQUEST`.
pub const KEYUSAGE_PA_OTP_REQUEST: i32 = 45;

/// `KRB5_OTP_FLAG_*` (k5-int.h), as the 32-bit value of the KerberosFlags.
pub mod flags {
    /// `KRB5_OTP_FLAG_NEXTOTP`.
    pub const NEXTOTP: u32 = 0x4000_0000;
    /// `KRB5_OTP_FLAG_COMBINE`.
    pub const COMBINE: u32 = 0x2000_0000;
    /// `KRB5_OTP_FLAG_COLLECT_PIN`.
    pub const COLLECT_PIN: u32 = 0x1000_0000;
    /// `KRB5_OTP_FLAG_NO_COLLECT_PIN`.
    pub const NO_COLLECT_PIN: u32 = 0x0800_0000;
    /// `KRB5_OTP_FLAG_ENCRYPT_NONCE`.
    pub const ENCRYPT_NONCE: u32 = 0x0400_0000;
    /// `KRB5_OTP_FLAG_SEPARATE_PIN`.
    pub const SEPARATE_PIN: u32 = 0x0200_0000;
    /// `KRB5_OTP_FLAG_CHECK_DIGIT`.
    pub const CHECK_DIGIT: u32 = 0x0100_0000;
}

/// `KRB5_OTP_FORMAT_BASE64`.
pub const FORMAT_BASE64: i32 = 3;

/// KerberosFlags as a 32-bit BIT STRING, bit 0 the most significant.
pub fn flags_to_bits(v: u32) -> BitString {
    BitString::from_slice(&v.to_be_bytes())
}

/// The 32-bit value of a KerberosFlags BIT STRING (MIT `k5_asn1_decode_
/// bitstring`: the first four octets, zero padded).
pub fn bits_to_flags(b: &BitString) -> u32 {
    let mut out = [0u8; 4];
    for (i, byte) in b.as_raw_slice().iter().take(4).enumerate() {
        out[i] = *byte;
    }
    u32::from_be_bytes(out)
}

/// OTP-TOKENINFO.
#[derive(AsnType, Encode, Decode, Debug, Clone, PartialEq, Eq)]
pub struct OtpTokenInfo {
    /// OTPFlags.
    #[rasn(tag(context, 0))]
    pub flags: BitString,
    /// otp-vendor.
    #[rasn(tag(context, 1))]
    pub vendor: Option<Utf8String>,
    /// otp-challenge.
    #[rasn(tag(context, 2))]
    pub challenge: Option<OctetString>,
    /// otp-length.
    #[rasn(tag(context, 3))]
    pub length: Option<i32>,
    /// otp-format.
    #[rasn(tag(context, 4))]
    pub format: Option<i32>,
    /// otp-tokenID.
    #[rasn(tag(context, 5))]
    pub token_id: Option<OctetString>,
    /// otp-algID.
    #[rasn(tag(context, 6))]
    pub alg_id: Option<Utf8String>,
    /// supportedHashAlg (AlgorithmIdentifiers, kept undecoded).
    #[rasn(tag(context, 7))]
    pub supported_hash_alg: Option<SequenceOf<Any>>,
    /// iterationCount.
    #[rasn(tag(context, 8))]
    pub iteration_count: Option<i32>,
}

impl OtpTokenInfo {
    /// The 32-bit OTP flags.
    pub fn flag_bits(&self) -> u32 {
        bits_to_flags(&self.flags)
    }
}

/// PA-OTP-CHALLENGE.
#[derive(AsnType, Encode, Decode, Debug, Clone, PartialEq, Eq)]
pub struct PaOtpChallenge {
    /// nonce.
    #[rasn(tag(context, 0))]
    pub nonce: OctetString,
    /// otp-service.
    #[rasn(tag(context, 1))]
    pub service: Option<Utf8String>,
    /// otp-tokenInfo (SIZE(1..MAX)).
    #[rasn(tag(context, 2))]
    pub tokeninfo: SequenceOf<OtpTokenInfo>,
    /// salt.
    #[rasn(tag(context, 3))]
    pub salt: Option<GeneralString>,
    /// s2kparams.
    #[rasn(tag(context, 4))]
    pub s2kparams: Option<OctetString>,
}

/// PA-OTP-REQUEST.
#[derive(AsnType, Encode, Decode, Debug, Clone)]
pub struct PaOtpRequest {
    /// OTPFlags.
    #[rasn(tag(context, 0))]
    pub flags: BitString,
    /// nonce.
    #[rasn(tag(context, 1))]
    pub nonce: Option<OctetString>,
    /// encData (PA-OTP-ENC-REQUEST or PA-ENC-TS-ENC, usage 45).
    #[rasn(tag(context, 2))]
    pub enc_data: EncryptedData,
    /// hashAlg.
    #[rasn(tag(context, 3))]
    pub hash_alg: Option<Any>,
    /// iterationCount.
    #[rasn(tag(context, 4))]
    pub iteration_count: Option<i32>,
    /// otp-value.
    #[rasn(tag(context, 5))]
    pub otp_value: Option<OctetString>,
    /// otp-pin.
    #[rasn(tag(context, 6))]
    pub pin: Option<Utf8String>,
    /// otp-challenge.
    #[rasn(tag(context, 7))]
    pub challenge: Option<OctetString>,
    /// otp-time.
    #[rasn(tag(context, 8))]
    pub time: Option<KerberosTime>,
    /// otp-counter.
    #[rasn(tag(context, 9))]
    pub counter: Option<OctetString>,
    /// otp-format.
    #[rasn(tag(context, 10))]
    pub format: Option<i32>,
    /// otp-tokenID.
    #[rasn(tag(context, 11))]
    pub token_id: Option<OctetString>,
    /// otp-algID.
    #[rasn(tag(context, 12))]
    pub alg_id: Option<Utf8String>,
    /// otp-vendor.
    #[rasn(tag(context, 13))]
    pub vendor: Option<Utf8String>,
}

/// PA-OTP-ENC-REQUEST.
#[derive(AsnType, Encode, Decode, Debug, Clone, PartialEq, Eq)]
pub struct PaOtpEncRequest {
    /// The challenge nonce.
    #[rasn(tag(context, 0))]
    pub nonce: OctetString,
}

/// A responder answer for the OTP question (MIT `codec_decode_answer`,
/// preauth_otp.c:375-423): the index of the chosen token info in the
/// challenge's supported list, the OTP value and an optional PIN.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OtpAnswer {
    /// Index into the supported token infos; ignored when only one is
    /// left (after an input cache's saved choice), as MIT does not prompt.
    pub tokeninfo: usize,
    /// The one-time password.
    pub value: Option<String>,
    /// The PIN, when the token collects one.
    pub pin: Option<String>,
}

fn printable(b: Option<&[u8]>) -> bool {
    b.is_none_or(|b| b.iter().all(|&c| (0x20..0x7f).contains(&c)))
}

/// `is_tokeninfo_supported` (preauth_otp.c:869-897).
pub fn tokeninfo_supported(ti: &OtpTokenInfo) -> bool {
    use flags::{COLLECT_PIN, NO_COLLECT_PIN, SEPARATE_PIN};
    let supported = COLLECT_PIN | NO_COLLECT_PIN | SEPARATE_PIN;
    ti.flag_bits() & !supported == 0
        && ti.supported_hash_alg.is_none()
        && ti.iteration_count.is_none_or(|n| n < 0)
        && printable(ti.vendor.as_ref().map(|v| v.as_bytes()))
        && printable(ti.challenge.as_deref())
        && ti.format != Some(FORMAT_BASE64)
}
