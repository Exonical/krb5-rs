//! KDC pre-authentication (MIT kdc_preauth.c, kdc_preauth_encts.c,
//! kdc_util.c `kdc_handle_protected_negotiation`).

use std::time::Duration;

use rasn::types::OctetString;

use super::db::{KeyEntry, KvnoSel, PrincipalEntry};
use super::error::{general_string, KdcError};
use crate::crypto::{find_etype, fx_cf2, key_usage};
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
/// (MIT `get_preauth_hint_list`, kdc_preauth.c:974-1014, plus the cookie
/// added by `prepare_error_as`, do_as_req.c:785-796): an empty PA-FX-FAST,
/// PA-ETYPE-INFO2 when a client key was selected, then each mechanism's
/// hint. With a client key (`have_client_keys`, kdc_preauth.c:435-447) that
/// is an empty PA-ENCRYPTED-CHALLENGE inside FAST (ec_edata,
/// kdc_preauth_ec.c:37-49) or an empty PA-ENC-TIMESTAMP outside it
/// (enc_ts_get, kdc_preauth_encts.c:31-44). With `hw_only`
/// (REQUIRES_HW_AUTH) only hardware mechanisms are listed, so neither is.
/// The trailing PA-FX-COOKIE is the trivial "MIT" cookie
/// (kdc_fast_make_cookie, fast_util.c:673-676; no cookie state is kept).
#[cfg(test)]
pub(crate) fn hint_list(
    client: &PrincipalEntry,
    key: Option<&ClientKey>,
    hw_only: bool,
    armored: bool,
) -> Result<Vec<u8>, KdcError> {
    hint_list_with(client, key, hw_only, armored, &[])
}

/// [`hint_list`] with extra module hints (PKINIT's PA-PK-AS-REQ,
/// PA-PKINIT-KX and freshness token) placed after the built-in mechanisms
/// and before the cookie.
pub(crate) fn hint_list_with(
    client: &PrincipalEntry,
    key: Option<&ClientKey>,
    hw_only: bool,
    armored: bool,
    extras: &[PaData],
) -> Result<Vec<u8>, KdcError> {
    let empty = |t: PaDataType| PaData {
        padata_type: t as i32,
        padata_value: OctetString::from(Vec::new()),
    };
    let mut list = vec![empty(PaDataType::FxFast)];
    if let Some(k) = key {
        list.push(etype_info2_padata(client, k)?);
        if !hw_only {
            list.push(empty(if armored {
                PaDataType::EncryptedChallenge
            } else {
                PaDataType::EncTimestamp
            }));
        }
    }
    list.extend(extras.iter().cloned());
    list.push(PaData {
        padata_type: PaDataType::FxCookie as i32,
        padata_value: OctetString::from(b"MIT".to_vec()),
    });
    Ok(rasn::der::encode(&list)?)
}

/// PA-REQ-ENC-PA-REP and the empty PA-FX-FAST that follows it (MIT
/// `kdc_handle_protected_negotiation`, kdc_util.c:1767-1807): checksum of
/// the raw request keyed with the reply key (usage `KRB5_KEYUSAGE_AS_REQ`),
/// default checksum type of the key's enctype.
pub(crate) fn enc_pa_rep_padata(
    reply_key: &EncryptionKey,
    raw_request: &[u8],
) -> Result<Vec<PaData>, KdcError> {
    let profile = find_etype(reply_key.keytype).map_err(|_| KdcError::generic("NO_ETYPE"))?;
    let checksum = profile
        .checksum(reply_key.key_bytes(), key_usage::AS_REQ, raw_request)
        .map_err(|_| KdcError::generic("CHECKSUM_FAILED"))?;
    let der = rasn::der::encode(&Checksum {
        cksumtype: profile.checksum_type(),
        checksum: OctetString::from(checksum),
    })?;
    Ok(vec![
        PaData {
            padata_type: PaDataType::ReqEncPaRep as i32,
            padata_value: OctetString::from(der),
        },
        PaData {
            padata_type: PaDataType::FxFast as i32,
            padata_value: OctetString::from(Vec::new()),
        },
    ])
}

/// Verify PA-ENCRYPTED-CHALLENGE (MIT `ec_verify`, kdc_preauth_ec.c:51-152,
/// with `filter_preauth_error`). Requires an armor key (ENOENT outside FAST
/// surfaces as PREAUTH_FAILED). Tries each permitted client key for the
/// request etypes in order (`client_keys`, kdc_preauth.c:353-383) with
/// challenge key cf2(armor, "clientchallengearmor", key,
/// "challengelongterm"), usage 54. Returns the KDC-direction challenge key
/// and the matching client key etype on success.
pub(crate) fn verify_encrypted_challenge(
    pa: &PaData,
    client: &PrincipalEntry,
    requested: &[i32],
    permitted: &dyn Fn(i32) -> bool,
    armor_key: Option<&EncryptionKey>,
    now: i64,
    clockskew: Duration,
) -> Result<EncryptionKey, KdcError> {
    let failed = || KdcError::new(KDC_ERR_PREAUTH_FAILED, "PREAUTH_FAILED");
    let armor = armor_key.ok_or_else(failed)?;
    let enc: EncryptedData = rasn::der::decode(pa.padata_value.as_ref()).map_err(|_| failed())?;

    let mut matched = None;
    for &etype in requested {
        if find_etype(etype).is_err() {
            continue;
        }
        let Some(entry) = client.find_key(Some(etype), KvnoSel::Highest, permitted) else {
            continue;
        };
        let Ok(challenge_key) = fx_cf2(
            armor,
            b"clientchallengearmor",
            &entry.key,
            b"challengelongterm",
        ) else {
            continue;
        };
        if enc.etype != challenge_key.keytype {
            continue;
        }
        let Ok(profile) = find_etype(challenge_key.keytype) else {
            continue;
        };
        if let Ok(plain) = profile.decrypt(
            challenge_key.key_bytes(),
            key_usage::ENC_CHALLENGE_CLIENT,
            enc.cipher.as_ref(),
        ) {
            matched = Some((entry, plain));
            break;
        }
    }
    let (entry, plain) = matched.ok_or_else(failed)?;

    let ts: PaEncTsEnc = rasn::der::decode(&plain).map_err(|_| failed())?;
    let skew = i64::try_from(clockskew.as_secs()).unwrap_or(i64::MAX);
    if (ts.patimestamp.timestamp() - now).abs() > skew {
        return Err(KdcError::new(KRB_AP_ERR_SKEW, "PREAUTH_FAILED"));
    }
    fx_cf2(
        armor,
        b"kdcchallengearmor",
        &entry.key,
        b"challengelongterm",
    )
    .map_err(|_| failed())
}

/// KDC-direction PA-ENCRYPTED-CHALLENGE (MIT `ec_return`,
/// kdc_preauth_ec.c:154-205): the current time encrypted with the KDC
/// challenge key, usage 55.
pub(crate) fn encrypted_challenge_padata(
    kdc_challenge_key: &EncryptionKey,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<PaData, KdcError> {
    use chrono::Timelike;
    let ts = PaEncTsEnc {
        patimestamp: now.with_nanosecond(0).unwrap_or(now).fixed_offset(),
        pausec: Some(i32::try_from(now.timestamp_subsec_micros()).unwrap_or(0)),
    };
    let profile = find_etype(kdc_challenge_key.keytype)
        .map_err(|_| KdcError::generic("ENC_CHALLENGE_RETURN"))?;
    let cipher = profile
        .encrypt(
            kdc_challenge_key.key_bytes(),
            key_usage::ENC_CHALLENGE_KDC,
            &rasn::der::encode(&ts)?,
        )
        .map_err(|_| KdcError::generic("ENC_CHALLENGE_RETURN"))?;
    let enc = EncryptedData {
        etype: kdc_challenge_key.keytype,
        kvno: None,
        cipher: OctetString::from(cipher),
    };
    Ok(PaData {
        padata_type: PaDataType::EncryptedChallenge as i32,
        padata_value: OctetString::from(rasn::der::encode(&enc)?),
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
            allowed_to_delegate_to: Vec::new(),
            allowed_to_delegate_from: Vec::new(),
            policy: None,
            security_epoch: 0,
            last_admin_unlock: None,
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

    fn hint_types(
        c: &PrincipalEntry,
        key: Option<&ClientKey>,
        hw: bool,
        armored: bool,
    ) -> Vec<i32> {
        let der = hint_list(c, key, hw, armored).expect("hints");
        let list: Vec<PaData> = rasn::der::decode(&der).expect("decode");
        list.iter().map(|p| p.padata_type).collect()
    }

    #[test]
    fn hint_list_unarmored_orders_fast_etype_info2_enc_timestamp_cookie() {
        let c = client_with_password();
        let key = select_client_key(&c, &[23, 18], &permit).expect("key");
        assert_eq!(key.etype, 18);
        assert_eq!(
            hint_types(&c, Some(&key), false, false),
            vec![136, 19, 2, 133]
        );
        let der = hint_list(&c, Some(&key), false, false).expect("hints");
        let list: Vec<PaData> = rasn::der::decode(&der).expect("decode");
        let info: Vec<EtypeInfo2Entry> =
            rasn::der::decode(list[1].padata_value.as_ref()).expect("info2");
        assert_eq!(info.len(), 1);
        assert_eq!(info[0].etype, 18);
        assert_eq!(
            info[0].salt.as_ref().map(|s| s.as_bytes().to_vec()),
            Some(b"Ru".to_vec())
        );
        assert_eq!(list[3].padata_value.as_ref(), b"MIT");
    }

    #[test]
    fn hint_list_armored_offers_encrypted_challenge_not_enc_timestamp() {
        let c = client_with_password();
        let key = select_client_key(&c, &[18], &permit).expect("key");
        assert_eq!(
            hint_types(&c, Some(&key), false, true),
            vec![136, 19, 138, 133]
        );
    }

    #[test]
    fn hint_list_without_client_key_has_no_mechanism_hints() {
        let c = client_with_password();
        assert_eq!(hint_types(&c, None, false, false), vec![136, 133]);
    }

    #[test]
    fn hint_list_hw_only_omits_mechanism_hints() {
        let c = client_with_password();
        let key = select_client_key(&c, &[18], &permit).expect("key");
        assert_eq!(hint_types(&c, Some(&key), true, false), vec![136, 19, 133]);
    }

    #[test]
    fn enc_pa_rep_padata_checksum_covers_raw_request_and_adds_empty_fast() {
        let key = EncryptionKey::new(18, vec![3; 32]);
        let list = enc_pa_rep_padata(&key, b"raw-request").expect("padata");
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].padata_type, 149);
        assert_eq!(list[1].padata_type, 136);
        assert!(list[1].padata_value.is_empty());
        let ck: Checksum = rasn::der::decode(list[0].padata_value.as_ref()).expect("checksum");
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

    fn challenge_pa(armor: &EncryptionKey, client: &PrincipalEntry, at: i64) -> PaData {
        let ts = PaEncTsEnc {
            patimestamp: crate::kdc::policy::kerberos_time(at),
            pausec: Some(0),
        };
        let ck = fx_cf2(
            armor,
            b"clientchallengearmor",
            &client.keys[0].key,
            b"challengelongterm",
        )
        .expect("cf2");
        let cipher = find_etype(ck.keytype)
            .expect("etype")
            .encrypt(
                ck.key_bytes(),
                key_usage::ENC_CHALLENGE_CLIENT,
                &rasn::der::encode(&ts).expect("encode"),
            )
            .expect("encrypt");
        let enc = EncryptedData {
            etype: ck.keytype,
            kvno: None,
            cipher: OctetString::from(cipher),
        };
        PaData {
            padata_type: 138,
            padata_value: OctetString::from(rasn::der::encode(&enc).expect("encode")),
        }
    }

    #[test]
    fn verify_encrypted_challenge_valid_challenge_returns_kdc_challenge_key() {
        let c = client_with_password();
        let armor = EncryptionKey::new(18, vec![4; 32]);
        let pa = challenge_pa(&armor, &c, NOW);
        let key = verify_encrypted_challenge(
            &pa,
            &c,
            &[18],
            &permit,
            Some(&armor),
            NOW,
            Duration::from_secs(300),
        )
        .expect("verified");
        let expected = fx_cf2(
            &armor,
            b"kdcchallengearmor",
            &c.keys[0].key,
            b"challengelongterm",
        )
        .expect("cf2");
        assert_eq!(key.key_bytes(), expected.key_bytes());
        let out = encrypted_challenge_padata(&key, chrono::Utc::now()).expect("reply");
        assert_eq!(out.padata_type, 138);
    }

    #[test]
    fn verify_encrypted_challenge_without_armor_is_preauth_failed() {
        let c = client_with_password();
        let armor = EncryptionKey::new(18, vec![4; 32]);
        let pa = challenge_pa(&armor, &c, NOW);
        let err = verify_encrypted_challenge(
            &pa,
            &c,
            &[18],
            &permit,
            None,
            NOW,
            Duration::from_secs(300),
        )
        .expect_err("no armor");
        assert_eq!(err.code, KDC_ERR_PREAUTH_FAILED);
    }

    #[test]
    fn verify_encrypted_challenge_skewed_timestamp_is_skew_error() {
        let c = client_with_password();
        let armor = EncryptionKey::new(18, vec![4; 32]);
        let pa = challenge_pa(&armor, &c, NOW - 400);
        let err = verify_encrypted_challenge(
            &pa,
            &c,
            &[18],
            &permit,
            Some(&armor),
            NOW,
            Duration::from_secs(300),
        )
        .expect_err("skew");
        assert_eq!(err.code, KRB_AP_ERR_SKEW);
    }

    #[test]
    fn verify_encrypted_challenge_wrong_armor_is_preauth_failed() {
        let c = client_with_password();
        let pa = challenge_pa(&EncryptionKey::new(18, vec![4; 32]), &c, NOW);
        let other = EncryptionKey::new(18, vec![5; 32]);
        let err = verify_encrypted_challenge(
            &pa,
            &c,
            &[18],
            &permit,
            Some(&other),
            NOW,
            Duration::from_secs(300),
        )
        .expect_err("wrong armor");
        assert_eq!(err.code, KDC_ERR_PREAUTH_FAILED);
    }
}
