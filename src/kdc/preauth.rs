//! KDC pre-authentication (MIT kdc_preauth.c, kdc_preauth_encts.c,
//! kdc_util.c `kdc_handle_protected_negotiation`).

use std::time::Duration;

use rasn::types::OctetString;

use super::db::{KeyEntry, KvnoSel, PrincipalEntry};
use super::error::{general_string, KdcError};
use crate::crypto::{find_etype, key_usage};
use crate::types::error_codes::*;
use crate::types::{
    Checksum, EncryptedData, EncryptionKey, EtypeInfo2Entry, PaData, PaDataType, PaEncTsEnc,
};

/// The client key chosen for the reply (MIT `select_client_key`,
/// do_as_req.c:102-131).
#[derive(Debug, Clone)]
pub(crate) struct ClientKey {
    /// The request etype that matched (also the reply enctype).
    pub etype: i32,
    /// The database key.
    pub entry: KeyEntry,
}

/// First requested etype for which the client has a permitted key at its
/// highest kvno.
pub(crate) fn select_client_key(
    client: &PrincipalEntry,
    requested: &[i32],
    permitted: &dyn Fn(i32) -> bool,
) -> Option<ClientKey> {
    requested.iter().copied().find_map(|etype| {
        if find_etype(etype).is_err() {
            return None;
        }
        client
            .find_key(Some(etype), KvnoSel::Highest, permitted)
            .map(|k| ClientKey {
                etype,
                entry: k.clone(),
            })
    })
}

/// Find the padata element of `padata_type`.
pub(crate) fn find_padata(padata: Option<&[PaData]>, padata_type: PaDataType) -> Option<&PaData> {
    padata?.iter().find(|p| p.padata_type == padata_type as i32)
}

/// Verify PA-ENC-TIMESTAMP (MIT `enc_ts_verify`, kdc_preauth_encts.c:46-119,
/// with `filter_preauth_error`, kdc_preauth.c:1092-1134): decrypt with each
/// client key of the offered etype at the highest kvno (usage 1), then
/// check the clock skew. Failures other than skew become PREAUTH_FAILED.
pub(crate) fn verify_enc_timestamp(
    pa: &PaData,
    client: &PrincipalEntry,
    permitted: &dyn Fn(i32) -> bool,
    now: i64,
    clockskew: Duration,
) -> Result<(), KdcError> {
    let failed = || KdcError::new(KDC_ERR_PREAUTH_FAILED, "PREAUTH_FAILED");

    let enc: EncryptedData = rasn::der::decode(pa.padata_value.as_ref()).map_err(|_| failed())?;
    let profile = find_etype(enc.etype).map_err(|_| failed())?;
    let top = client.current_kvno().ok_or_else(failed)?;

    let plaintext = client
        .keys
        .iter()
        .filter(|k| k.kvno == top && k.key.keytype == enc.etype && permitted(enc.etype))
        .find_map(|k| {
            profile
                .decrypt(
                    k.key.key_bytes(),
                    key_usage::PA_ENC_TIMESTAMP,
                    enc.cipher.as_ref(),
                )
                .ok()
        })
        .ok_or_else(failed)?;

    let ts: PaEncTsEnc = rasn::der::decode(&plaintext).map_err(|_| failed())?;
    let skew = i64::try_from(clockskew.as_secs()).unwrap_or(i64::MAX);
    if (ts.patimestamp.timestamp() - now).abs() > skew {
        return Err(KdcError::new(KRB_AP_ERR_SKEW, "PREAUTH_FAILED"));
    }
    Ok(())
}

/// PA-ETYPE-INFO2 for the selected client key (MIT `make_etype_info`,
/// kdc_preauth.c:1508-1576, `add_etype_info`, :767-800).
///
/// Deviation: MIT always leaves s2kparams empty; a stored s2kparams is
/// advertised here so clients derive the same key.
pub(crate) fn etype_info2_padata(
    client: &PrincipalEntry,
    key: &ClientKey,
) -> Result<PaData, KdcError> {
    let entry = EtypeInfo2Entry {
        etype: key.etype,
        salt: Some(general_string(&String::from_utf8_lossy(
            &client.salt_for(&key.entry),
        ))?),
        s2kparams: key.entry.s2kparams.clone().map(OctetString::from),
    };
    Ok(PaData {
        padata_type: PaDataType::EtypeInfo2 as i32,
        padata_value: OctetString::from(rasn::der::encode(&vec![entry])?),
    })
}

/// Hint METHOD-DATA for PREAUTH_REQUIRED / PREAUTH_FAILED e-data
/// (MIT `get_preauth_hint_list`, kdc_preauth.c:974-1014): PA-ETYPE-INFO2
/// when a client key was selected, then an empty PA-ENC-TIMESTAMP (enc_ts_get,
/// kdc_preauth_encts.c:31-44: requires client keys, no FAST armor). With
/// `hw_only` (REQUIRES_HW_AUTH) only hardware mechanisms are listed, so
/// PA-ENC-TIMESTAMP is omitted.
///
// FAST: the leading empty PA-FX-FAST advertisement (kdc_preauth.c:999-1001)
// is added by kdc::fast in the next milestone.
pub(crate) fn hint_list(
    client: &PrincipalEntry,
    key: Option<&ClientKey>,
    hw_only: bool,
) -> Result<Vec<u8>, KdcError> {
    let mut list = Vec::new();
    if let Some(k) = key {
        list.push(etype_info2_padata(client, k)?);
    }
    if !hw_only && !client.keys.is_empty() {
        list.push(PaData {
            padata_type: PaDataType::EncTimestamp as i32,
            padata_value: OctetString::from(Vec::new()),
        });
    }
    Ok(rasn::der::encode(&list)?)
}

/// PA-REQ-ENC-PA-REP (MIT `kdc_handle_protected_negotiation`,
/// kdc_util.c:1767-1807): checksum of the raw request keyed with the
/// reply key (usage `KRB5_KEYUSAGE_AS_REQ`), default checksum type of the
/// key's enctype.
///
// FAST: the trailing empty PA-FX-FAST element (kdc_util.c:1800-1801) is
// added by kdc::fast in the next milestone.
pub(crate) fn enc_pa_rep_padata(
    reply_key: &EncryptionKey,
    raw_request: &[u8],
) -> Result<PaData, KdcError> {
    let profile = find_etype(reply_key.keytype).map_err(|_| KdcError::generic("NO_ETYPE"))?;
    let checksum = profile
        .checksum(reply_key.key_bytes(), key_usage::AS_REQ, raw_request)
        .map_err(|_| KdcError::generic("CHECKSUM_FAILED"))?;
    let der = rasn::der::encode(&Checksum {
        cksumtype: profile.checksum_type(),
        checksum: OctetString::from(checksum),
    })?;
    Ok(PaData {
        padata_type: PaDataType::ReqEncPaRep as i32,
        padata_value: OctetString::from(der),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kdc::db::PrincipalAttributes;
    use crate::types::PrincipalName;

    const NOW: i64 = 1_700_000_000;

    fn client_with_password() -> PrincipalEntry {
        let name = PrincipalName::new_principal("u");
        let salt = b"Ru".to_vec();
        let key = find_etype(18)
            .expect("etype")
            .string_to_key(b"pw", &salt, None)
            .expect("s2k");
        PrincipalEntry {
            name,
            realm: "R".into(),
            attributes: PrincipalAttributes::empty(),
            max_life: None,
            max_renewable_life: None,
            expiration: None,
            pw_expiration: None,
            keys: vec![KeyEntry {
                kvno: 1,
                key: EncryptionKey::new(18, key.to_vec()),
                salt: None,
                s2kparams: None,
            }],
        }
    }

    fn timestamp_pa(client: &PrincipalEntry, at: i64) -> PaData {
        let key = &client.keys[0].key;
        let ts = PaEncTsEnc {
            patimestamp: crate::kdc::policy::kerberos_time(at),
            pausec: Some(0),
        };
        let cipher = find_etype(18)
            .expect("etype")
            .encrypt(
                key.key_bytes(),
                key_usage::PA_ENC_TIMESTAMP,
                &rasn::der::encode(&ts).expect("encode"),
            )
            .expect("encrypt");
        let enc = EncryptedData {
            etype: 18,
            kvno: None,
            cipher: OctetString::from(cipher),
        };
        PaData {
            padata_type: 2,
            padata_value: OctetString::from(rasn::der::encode(&enc).expect("encode")),
        }
    }

    fn permit(_: i32) -> bool {
        true
    }

    #[test]
    fn verify_enc_timestamp_valid_timestamp_succeeds() {
        let c = client_with_password();
        let pa = timestamp_pa(&c, NOW);
        assert!(verify_enc_timestamp(&pa, &c, &permit, NOW, Duration::from_secs(300)).is_ok());
    }

    #[test]
    fn verify_enc_timestamp_skewed_timestamp_is_skew_error() {
        let c = client_with_password();
        let pa = timestamp_pa(&c, NOW - 301);
        let err = verify_enc_timestamp(&pa, &c, &permit, NOW, Duration::from_secs(300))
            .expect_err("skew");
        assert_eq!(err.code, KRB_AP_ERR_SKEW);
    }

    #[test]
    fn verify_enc_timestamp_wrong_key_is_preauth_failed() {
        let c = client_with_password();
        let mut other = client_with_password();
        other.keys[0].key = EncryptionKey::new(18, vec![7; 32]);
        let pa = timestamp_pa(&other, NOW);
        let err = verify_enc_timestamp(&pa, &c, &permit, NOW, Duration::from_secs(300))
            .expect_err("bad key");
        assert_eq!(err.code, KDC_ERR_PREAUTH_FAILED);
    }

    #[test]
    fn verify_enc_timestamp_garbage_padata_is_preauth_failed() {
        let c = client_with_password();
        let pa = PaData {
            padata_type: 2,
            padata_value: OctetString::from(vec![1, 2, 3]),
        };
        let err = verify_enc_timestamp(&pa, &c, &permit, NOW, Duration::from_secs(300))
            .expect_err("garbage");
        assert_eq!(err.code, KDC_ERR_PREAUTH_FAILED);
    }

    #[test]
    fn hint_list_orders_etype_info2_before_enc_timestamp() {
        let c = client_with_password();
        let key = select_client_key(&c, &[23, 18], &permit).expect("key");
        assert_eq!(key.etype, 18);
        let der = hint_list(&c, Some(&key), false).expect("hints");
        let list: Vec<PaData> = rasn::der::decode(&der).expect("decode");
        let types: Vec<i32> = list.iter().map(|p| p.padata_type).collect();
        assert_eq!(types, vec![19, 2]);
        let info: Vec<EtypeInfo2Entry> =
            rasn::der::decode(list[0].padata_value.as_ref()).expect("info2");
        assert_eq!(info.len(), 1);
        assert_eq!(info[0].etype, 18);
        assert_eq!(
            info[0].salt.as_ref().map(|s| s.as_bytes().to_vec()),
            Some(b"Ru".to_vec())
        );
    }

    #[test]
    fn hint_list_hw_only_omits_enc_timestamp() {
        let c = client_with_password();
        let der = hint_list(&c, None, true).expect("hints");
        let list: Vec<PaData> = rasn::der::decode(&der).expect("decode");
        assert!(list.is_empty());
    }

    #[test]
    fn enc_pa_rep_padata_checksum_covers_raw_request() {
        let key = EncryptionKey::new(18, vec![3; 32]);
        let pa = enc_pa_rep_padata(&key, b"raw-request").expect("padata");
        assert_eq!(pa.padata_type, 149);
        let ck: Checksum = rasn::der::decode(pa.padata_value.as_ref()).expect("checksum");
        assert_eq!(ck.cksumtype, 16);
        find_etype(18)
            .expect("etype")
            .verify_checksum(
                key.key_bytes(),
                key_usage::AS_REQ,
                b"raw-request",
                ck.checksum.as_ref(),
            )
            .expect("valid");
    }
}
