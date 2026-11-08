//! AD-CAMMAC (RFC 7751) and AD-AUTHENTICATION-INDICATOR.

use rasn::prelude::*;

use super::{AuthorizationDataElement, Checksum, PrincipalName};

/// `KRB5_AUTHDATA_IF_RELEVANT`.
const AD_IF_RELEVANT: i32 = 1;
/// `KRB5_AUTHDATA_CAMMAC`.
pub const AD_CAMMAC: i32 = 96;
/// `KRB5_AUTHDATA_AUTH_INDICATOR`.
pub const AD_AUTH_INDICATOR: i32 = 97;
/// `KRB5_KEYUSAGE_CAMMAC`.
pub const KEYUSAGE_CAMMAC: i32 = 64;

/// Verifier-MAC.
#[derive(AsnType, Encode, Decode, Debug, Clone)]
pub struct VerifierMac {
    /// identifier.
    #[rasn(tag(explicit(context, 0)))]
    pub identifier: Option<PrincipalName>,
    /// kvno.
    #[rasn(tag(explicit(context, 1)))]
    pub kvno: Option<u32>,
    /// enctype.
    #[rasn(tag(explicit(context, 2)))]
    pub enctype: Option<i32>,
    /// mac.
    #[rasn(tag(explicit(context, 3)))]
    pub mac: Checksum,
}

/// AD-CAMMAC.
#[derive(AsnType, Encode, Decode, Debug, Clone)]
pub struct Cammac {
    /// elements.
    #[rasn(tag(explicit(context, 0)))]
    pub elements: SequenceOf<AuthorizationDataElement>,
    /// kdc-verifier.
    #[rasn(tag(explicit(context, 1)))]
    pub kdc_verifier: Option<VerifierMac>,
    /// svc-verifier.
    #[rasn(tag(explicit(context, 2)))]
    pub svc_verifier: Option<VerifierMac>,
    /// other-verifiers.
    #[rasn(tag(explicit(context, 3)))]
    pub other_verifiers: Option<SequenceOf<VerifierMac>>,
}

/// `krb5_find_authdata` for `ad_type`, looking inside AD-IF-RELEVANT.
pub fn find_authdata(list: &[AuthorizationDataElement], ad_type: i32, out: &mut Vec<Vec<u8>>) {
    for el in list {
        if el.ad_type == ad_type {
            out.push(el.ad_data.to_vec());
        } else if el.ad_type == AD_IF_RELEVANT {
            if let Ok(inner) =
                rasn::der::decode::<Vec<AuthorizationDataElement>>(el.ad_data.as_ref())
            {
                find_authdata(&inner, ad_type, out);
            }
        }
    }
}
