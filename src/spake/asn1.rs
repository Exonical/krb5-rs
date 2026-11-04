//! SPAKE ASN.1 (draft-ietf-kitten-krb-spake-preauth, MIT `asn1_k_encode.c`).

use crate::types::EncryptedData;
use rasn::prelude::*;

/// SPAKESecondFactor.
#[derive(AsnType, Encode, Decode, Debug, Clone, PartialEq, Eq)]
pub struct SpakeFactor {
    /// Factor type (`SF_NONE` = 1).
    #[rasn(tag(explicit(context, 0)))]
    pub factor_type: i32,
    /// Factor-specific data.
    #[rasn(tag(explicit(context, 1)))]
    pub data: Option<OctetString>,
}

/// SPAKESupport.
#[derive(AsnType, Encode, Decode, Debug, Clone, PartialEq, Eq)]
pub struct SpakeSupport {
    /// Supported group numbers, most preferred first.
    #[rasn(tag(explicit(context, 0)))]
    pub groups: SequenceOf<i32>,
}

/// SPAKEChallenge.
#[derive(AsnType, Encode, Decode, Debug, Clone, PartialEq, Eq)]
pub struct SpakeChallenge {
    /// Group number.
    #[rasn(tag(explicit(context, 0)))]
    pub group: i32,
    /// KDC public element.
    #[rasn(tag(explicit(context, 1)))]
    pub pubkey: OctetString,
    /// Offered second factors.
    #[rasn(tag(explicit(context, 2)))]
    pub factors: SequenceOf<SpakeFactor>,
}

/// SPAKEResponse.
#[derive(AsnType, Encode, Decode, Debug, Clone)]
pub struct SpakeResponse {
    /// Client public element.
    #[rasn(tag(explicit(context, 0)))]
    pub pubkey: OctetString,
    /// `SPAKEFactor` encrypted in K'[1], usage `KEYUSAGE_SPAKE`.
    #[rasn(tag(explicit(context, 1)))]
    pub factor: EncryptedData,
}

/// PA-SPAKE.
#[derive(AsnType, Encode, Decode, Debug, Clone)]
#[rasn(choice)]
pub enum PaSpake {
    /// Client's supported groups.
    #[rasn(tag(explicit(context, 0)))]
    Support(SpakeSupport),
    /// KDC challenge.
    #[rasn(tag(explicit(context, 1)))]
    Challenge(SpakeChallenge),
    /// Client response.
    #[rasn(tag(explicit(context, 2)))]
    Response(SpakeResponse),
    /// Second-factor data, encrypted in K'[2]/K'[3].
    #[rasn(tag(explicit(context, 3)))]
    EncData(EncryptedData),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn mit_vector_messages_roundtrip() {
        for v in super::super::vectors::VECTORS {
            let der = hex(v.challenge);
            let msg: PaSpake = rasn::der::decode(&der).unwrap();
            let PaSpake::Challenge(c) = &msg else {
                panic!("{msg:?}")
            };
            assert_eq!(c.group, v.group);
            assert_eq!(
                c.factors,
                vec![SpakeFactor {
                    factor_type: 1,
                    data: None
                }]
            );
            assert_eq!(rasn::der::encode(&msg).unwrap(), der);
            if let Some(s) = v.support {
                let der = hex(s);
                let msg: PaSpake = rasn::der::decode(&der).unwrap();
                assert!(matches!(msg, PaSpake::Support(_)));
                assert_eq!(rasn::der::encode(&msg).unwrap(), der);
            }
        }
    }
}
