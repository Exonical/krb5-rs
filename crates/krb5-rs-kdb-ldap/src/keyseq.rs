//! `krbPrincipalKey` / `krbPwdHistory` values: MIT's KrbKeySet
//! (lib/krb5/asn.1/ldap_key_seq.c, ldap_principal2.c:394-454).

use krb5_rs::kdc::kdb::mit::KeyData;
use krb5_rs::kdc::store::StoreError;
use rasn::prelude::*;

#[derive(AsnType, Encode, Decode, Debug, Clone, PartialEq, Eq)]
struct KrbSalt {
    #[rasn(tag(explicit(context, 0)))]
    salt_type: i16,
    #[rasn(tag(explicit(context, 1)))]
    salt: Option<OctetString>,
}

#[derive(AsnType, Encode, Decode, Debug, Clone, PartialEq, Eq)]
struct EncryptionKey {
    #[rasn(tag(explicit(context, 0)))]
    keytype: i16,
    #[rasn(tag(explicit(context, 1)))]
    keyvalue: OctetString,
}

#[derive(AsnType, Encode, Decode, Debug, Clone, PartialEq, Eq)]
struct KrbKey {
    #[rasn(tag(explicit(context, 0)))]
    salt: Option<KrbSalt>,
    #[rasn(tag(explicit(context, 1)))]
    key: EncryptionKey,
}

#[derive(AsnType, Encode, Decode, Debug, Clone, PartialEq, Eq)]
struct KrbKeySet {
    #[rasn(tag(explicit(context, 0)))]
    attribute_major_vno: Integer,
    #[rasn(tag(explicit(context, 1)))]
    attribute_minor_vno: Integer,
    #[rasn(tag(explicit(context, 2)))]
    kvno: u16,
    #[rasn(tag(explicit(context, 3)))]
    mkvno: i32,
    #[rasn(tag(explicit(context, 4)))]
    keys: SequenceOf<KrbKey>,
}

/// One decoded key set: its master kvno and key data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeySet {
    /// mkvno (`krbPrincipalKey`) or `admin_history_kvno` (`krbPwdHistory`).
    pub mkvno: i32,
    /// Key data, all with the set's kvno.
    pub key_data: Vec<KeyData>,
}

fn bad(msg: &str) -> StoreError {
    StoreError::corrupt(msg.to_string())
}

/// `encode_keys` (ldap_principal2.c:473-528): one value for key data that
/// share a kvno. A version-1 key gets an empty normal salt.
pub fn encode(key_data: &[KeyData], mkvno: i32) -> Result<Vec<u8>, StoreError> {
    let first = key_data
        .first()
        .ok_or_else(|| bad("no key data to encode"))?;
    let keys = key_data
        .iter()
        .map(|k| {
            let (keytype, key) = k.fields.first().cloned().unwrap_or_default();
            let (salt_type, salt) = k.fields.get(1).cloned().unwrap_or_default();
            KrbKey {
                salt: Some(KrbSalt {
                    salt_type,
                    salt: (!salt.is_empty()).then(|| salt.into()),
                }),
                key: EncryptionKey {
                    keytype,
                    keyvalue: key.into(),
                },
            }
        })
        .collect();
    let set = KrbKeySet {
        attribute_major_vno: 1.into(),
        attribute_minor_vno: 1.into(),
        kvno: first.kvno,
        mkvno,
        keys,
    };
    rasn::der::encode(&set).map_err(|e| bad(&format!("encoding krbPrincipalKey: {e}")))
}

/// `asn1_decode_sequence_of_keys` (ldap_principal2.c:416-447).
pub fn decode(value: &[u8]) -> Result<KeySet, StoreError> {
    let set: KrbKeySet = rasn::ber::decode(value).map_err(|_| bad("ASN.1 bad format"))?;
    if set.attribute_major_vno != 1.into() || set.attribute_minor_vno != 1.into() {
        return Err(bad("ASN.1 bad format"));
    }
    let key_data = set
        .keys
        .into_iter()
        .map(|k| {
            let mut fields = vec![(k.key.keytype, k.key.keyvalue.to_vec())];
            if let Some(s) = k.salt {
                fields.push((s.salt_type, s.salt.map(|s| s.to_vec()).unwrap_or_default()));
            }
            KeyData {
                ver: fields.len() as u16,
                kvno: set.kvno,
                fields,
            }
        })
        .collect();
    Ok(KeySet {
        mkvno: set.mkvno,
        key_data,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_version_one_salt() {
        let kd = vec![
            KeyData {
                ver: 2,
                kvno: 3,
                fields: vec![(18, vec![1; 32]), (3, b"salt".to_vec())],
            },
            KeyData {
                ver: 1,
                kvno: 3,
                fields: vec![(17, vec![2; 16])],
            },
        ];
        let set = decode(&encode(&kd, 1).unwrap()).unwrap();
        assert_eq!(set.mkvno, 1);
        assert_eq!(set.key_data[0], kd[0]);
        // MIT always encodes a salt, so the version-1 key comes back as 2.
        assert_eq!(set.key_data[1].ver, 2);
        assert_eq!(set.key_data[1].fields[1], (0, Vec::new()));
    }
}
