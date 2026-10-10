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
    /// Incremented by every write; absent (read as 0) in files written
    /// before propagation existed.
    #[rasn(tag(explicit(context, 3)))]
    pub serial: Option<u64>,
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
    #[rasn(tag(explicit(context, 10)))]
    pub allowed_to_delegate_to: Option<Vec<GeneralString>>,
    #[rasn(tag(explicit(context, 11)))]
    pub allowed_to_delegate_from: Option<Vec<GeneralString>>,
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A record as written before the delegation lists existed.
    #[derive(AsnType, Encode, Decode, Debug, Clone)]
    struct LegacyPrincipal {
        #[rasn(tag(explicit(context, 0)))]
        name: PrincipalName,
        #[rasn(tag(explicit(context, 1)))]
        realm: GeneralString,
        #[rasn(tag(explicit(context, 2)))]
        attributes: u32,
        #[rasn(tag(explicit(context, 9)))]
        keys: Vec<KdbKey>,
    }

    /// A file as written before the serial existed.
    #[derive(AsnType, Encode, Decode, Debug, Clone)]
    struct LegacyFile {
        #[rasn(tag(explicit(context, 0)))]
        version: u32,
        #[rasn(tag(explicit(context, 1)))]
        realm: GeneralString,
        #[rasn(tag(explicit(context, 2)))]
        principals: Vec<KdbPrincipal>,
    }

    #[test]
    fn files_without_a_serial_still_decode() {
        let legacy = LegacyFile {
            version: VERSION,
            realm: GeneralString::from_bytes(b"R").expect("realm"),
            principals: Vec::new(),
        };
        let der = rasn::der::encode(&legacy).expect("encode");
        let file: KdbFile = rasn::der::decode(&der).expect("decode legacy file");
        assert_eq!(file.serial, None);
    }

    #[test]
    fn records_without_delegation_lists_still_decode() {
        let legacy = LegacyPrincipal {
            name: PrincipalName::new_principal("old"),
            realm: GeneralString::from_bytes(b"R").expect("realm"),
            attributes: 0,
            keys: Vec::new(),
        };
        let der = rasn::der::encode(&legacy).expect("encode");
        let rec: KdbPrincipal = rasn::der::decode(&der).expect("decode legacy record");
        assert!(rec.allowed_to_delegate_to.is_none() && rec.allowed_to_delegate_from.is_none());
    }
}
