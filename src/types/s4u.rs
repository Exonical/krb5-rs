//! MS-SFU padata (S4U2Self): PA-FOR-USER and PA-S4U-X509-USER.

use rasn::prelude::*;

use super::{Checksum, KerberosString, PrincipalName, Realm};

/// PA-FOR-USER (MS-SFU 2.2.1; MIT `krb5_pa_for_user`).
#[derive(AsnType, Encode, Decode, Debug, Clone)]
pub struct PaForUser {
    #[rasn(tag(explicit(context, 0)))]
    pub user_name: PrincipalName,
    #[rasn(tag(explicit(context, 1)))]
    pub user_realm: Realm,
    #[rasn(tag(explicit(context, 2)))]
    pub cksum: Checksum,
    #[rasn(tag(explicit(context, 3)))]
    pub auth_package: KerberosString,
}

/// S4UUserID (MS-SFU 2.2.2).
#[derive(AsnType, Encode, Decode, Debug, Clone)]
pub struct S4uUserId {
    #[rasn(tag(explicit(context, 0)))]
    pub nonce: u32,
    #[rasn(tag(explicit(context, 1)))]
    pub cname: Option<PrincipalName>,
    #[rasn(tag(explicit(context, 2)))]
    pub crealm: Realm,
    #[rasn(tag(explicit(context, 3)))]
    pub subject_certificate: Option<OctetString>,
    #[rasn(tag(explicit(context, 4)))]
    pub options: Option<BitString>,
}

/// PA-S4U-X509-USER (MS-SFU 2.2.2).
#[derive(AsnType, Encode, Decode, Debug, Clone)]
pub struct PaS4uX509User {
    #[rasn(tag(explicit(context, 0)))]
    pub user_id: S4uUserId,
    #[rasn(tag(explicit(context, 1)))]
    pub cksum: Checksum,
}

/// `KRB5_S4U_OPTS_USE_REPLY_KEY_USAGE` (k5-int.h:772).
pub const S4U_OPTS_USE_REPLY_KEY_USAGE: u32 = 0x2000_0000;
/// `KRB5_PA_PAC_OPTIONS_RBCD` (k5-int.h:579).
pub const PA_PAC_OPTIONS_RBCD: u32 = 0x1000_0000;
