//! On-disk representation of the principal database: the 8-byte magic
//! `KRB5RSDB` followed by a DER `KdbFile`.

use rasn::prelude::*;

use crate::types::{KerberosTime, PrincipalName};

/// File magic.
pub(super) const MAGIC: &[u8; 8] = b"KRB5RSDB";
/// Current format version.
pub(super) const VERSION: u32 = 1;

/// `KdbFile ::= SEQUENCE { version, realm, principals }`.
#[derive(AsnType, Encode, Decode, Debug, Clone)]
pub(super) struct KdbFile {
    #[rasn(tag(explicit(context, 0)))]
    pub version: u32,
    #[rasn(tag(explicit(context, 1)))]
    pub realm: GeneralString,
    #[rasn(tag(explicit(context, 2)))]
    pub principals: Vec<KdbPrincipal>,
}

/// One principal record; lifetimes are in seconds.
#[derive(AsnType, Encode, Decode, Debug, Clone)]
pub(super) struct KdbPrincipal {
    #[rasn(tag(explicit(context, 0)))]
    pub name: PrincipalName,
    #[rasn(tag(explicit(context, 1)))]
    pub realm: GeneralString,
    #[rasn(tag(explicit(context, 2)))]
    pub attributes: u32,
    #[rasn(tag(explicit(context, 3)))]
    pub max_life: Option<u64>,
    #[rasn(tag(explicit(context, 4)))]
    pub max_renewable_life: Option<u64>,
    #[rasn(tag(explicit(context, 5)))]
    pub expiration: Option<KerberosTime>,
    #[rasn(tag(explicit(context, 6)))]
    pub pw_expiration: Option<KerberosTime>,
    #[rasn(tag(explicit(context, 7)))]
    pub last_pwd_change: Option<KerberosTime>,
    #[rasn(tag(explicit(context, 8)))]
    pub mod_time: Option<KerberosTime>,
    #[rasn(tag(explicit(context, 9)))]
    pub keys: Vec<KdbKey>,
}

/// One master-key-encrypted long-term key (MIT `krb5_key_data`).
#[derive(AsnType, Encode, Decode, Debug, Clone)]
pub(super) struct KdbKey {
    #[rasn(tag(explicit(context, 0)))]
    pub kvno: u32,
    #[rasn(tag(explicit(context, 1)))]
    pub enctype: i32,
    #[rasn(tag(explicit(context, 2)))]
    pub mkvno: u32,
    #[rasn(tag(explicit(context, 3)))]
    pub enc_key: OctetString,
    #[rasn(tag(explicit(context, 4)))]
    pub salt: Option<OctetString>,
    #[rasn(tag(explicit(context, 5)))]
    pub s2kparams: Option<OctetString>,
}
