//! Authentication indicators in CAMMAC authdata (MIT `kdc/cammac.c`,
//! `kdc/authind.c`, `kdc_authdata.c` `add_auth_indicators` /
//! `get_auth_indicators`).

use rasn::prelude::*;

use super::db::{KvnoSel, PrincipalEntry};
use super::error::KdcError;
use crate::crypto::find_etype;
use crate::pac::AD_IF_RELEVANT;
use crate::types::{AuthorizationDataElement, Checksum, EncTicketPart, EncryptionKey};

/// `KRB5_AUTHDATA_CAMMAC`.
pub(crate) const AD_CAMMAC: i32 = 96;
/// `KRB5_AUTHDATA_AUTH_INDICATOR`.
pub(crate) const AD_AUTH_INDICATOR: i32 = 97;
/// `KRB5_KEYUSAGE_CAMMAC`.
const KEYUSAGE_CAMMAC: i32 = 64;

/// Verifier-MAC.
#[derive(AsnType, Encode, Decode, Debug, Clone)]
struct VerifierMac {
    #[rasn(tag(explicit(context, 0)))]
    identifier: Option<crate::types::PrincipalName>,
    #[rasn(tag(explicit(context, 1)))]
    kvno: Option<u32>,
    #[rasn(tag(explicit(context, 2)))]
    enctype: Option<i32>,
    #[rasn(tag(explicit(context, 3)))]
    mac: Checksum,
}

/// AD-CAMMAC.
#[derive(AsnType, Encode, Decode, Debug, Clone)]
struct Cammac {
    #[rasn(tag(explicit(context, 0)))]
    elements: SequenceOf<AuthorizationDataElement>,
    #[rasn(tag(explicit(context, 1)))]
    kdc_verifier: Option<VerifierMac>,
    #[rasn(tag(explicit(context, 2)))]
    svc_verifier: Option<VerifierMac>,
    #[rasn(tag(explicit(context, 3)))]
    other_verifiers: Option<SequenceOf<VerifierMac>>,
}

fn checksum(key: &EncryptionKey, data: &[u8]) -> Result<Checksum, KdcError> {
    let profile = find_etype(key.keytype).map_err(|_| KdcError::generic("CAMMAC"))?;
    let mac = profile
        .checksum(key.key_bytes(), KEYUSAGE_CAMMAC, data)
        .map_err(|_| KdcError::generic("CAMMAC"))?;
    Ok(Checksum {
        cksumtype: profile.checksum_type(),
        checksum: mac.into(),
    })
}

/// `encode_kdcver_encpart`: the ticket part with `elements` as its authdata.
fn kdcver_encpart(
    part: &EncTicketPart,
    elements: &[AuthorizationDataElement],
) -> Result<Vec<u8>, KdcError> {
    let mut ck = part.clone();
    ck.authorization_data = Some(elements.to_vec());
    Ok(rasn::der::encode(&ck)?)
}

/// The krbtgt key the KDC verifier uses: the first key at `kvno` that
/// krb5-rs implements.
fn tgt_key(tgt: &PrincipalEntry, kvno: KvnoSel) -> Option<(u32, &EncryptionKey)> {
    tgt.find_key(None, kvno, &|e| find_etype(e).is_ok())
        .map(|k| (k.kvno, &k.key))
}

/// `add_auth_indicators`: append the indicators to the ticket in an
/// AD-IF-RELEVANT { AD-CAMMAC { AD-AUTH-INDICATOR } }.
pub(crate) fn add_auth_indicators(
    part: &mut EncTicketPart,
    indicators: &[String],
    server_key: &EncryptionKey,
    local_tgt: &PrincipalEntry,
) -> Result<(), KdcError> {
    if indicators.is_empty() {
        return Ok(());
    }
    let strings: Vec<Utf8String> = indicators.to_vec();
    let contents = vec![AuthorizationDataElement {
        ad_type: AD_AUTH_INDICATOR,
        ad_data: rasn::der::encode(&strings)?.into(),
    }];
    let (kvno, key) =
        tgt_key(local_tgt, KvnoSel::Highest).ok_or_else(|| KdcError::generic("CAMMAC"))?;
    let kdc_verifier = VerifierMac {
        identifier: None,
        kvno: Some(kvno),
        enctype: None,
        mac: checksum(key, &kdcver_encpart(part, &contents)?)?,
    };
    let svc_verifier = VerifierMac {
        identifier: None,
        kvno: None,
        enctype: None,
        mac: checksum(server_key, &rasn::der::encode(&contents)?)?,
    };
    let cammac = Cammac {
        elements: contents,
        kdc_verifier: Some(kdc_verifier),
        svc_verifier: Some(svc_verifier),
        other_verifiers: None,
    };
    let inner = vec![AuthorizationDataElement {
        ad_type: AD_CAMMAC,
        ad_data: rasn::der::encode(&cammac)?.into(),
    }];
    part.authorization_data
        .get_or_insert_with(Vec::new)
        .push(AuthorizationDataElement {
            ad_type: AD_IF_RELEVANT,
            ad_data: rasn::der::encode(&inner)?.into(),
        });
    Ok(())
}

/// `krb5_find_authdata` for `ad_type`, looking inside AD-IF-RELEVANT.
fn find_authdata(list: &[AuthorizationDataElement], ad_type: i32, out: &mut Vec<Vec<u8>>) {
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

/// `get_auth_indicators`: indicators from CAMMACs in `part` whose KDC
/// verifier checks out against the local krbtgt (`cammac_check_kdcver`).
pub(crate) fn get_auth_indicators(part: &EncTicketPart, local_tgt: &PrincipalEntry) -> Vec<String> {
    let mut found = Vec::new();
    find_authdata(
        part.authorization_data.as_deref().unwrap_or(&[]),
        AD_CAMMAC,
        &mut found,
    );
    let mut out: Vec<String> = Vec::new();
    for der in found {
        let Ok(cammac) = rasn::der::decode::<Cammac>(&der) else {
            continue;
        };
        let Some(ver) = &cammac.kdc_verifier else {
            continue;
        };
        let sel = match ver.kvno {
            Some(k) => KvnoSel::Exact(k),
            None => KvnoSel::Highest,
        };
        let Some((_, key)) = tgt_key(local_tgt, sel) else {
            continue;
        };
        if ver.enctype.is_some_and(|e| e != key.keytype) {
            continue;
        }
        let Ok(data) = kdcver_encpart(part, &cammac.elements) else {
            continue;
        };
        let Ok(want) = checksum(key, &data) else {
            continue;
        };
        if want.cksumtype != ver.mac.cksumtype
            || !bool::from(subtle::ConstantTimeEq::ct_eq(
                want.checksum.as_ref(),
                ver.mac.checksum.as_ref(),
            ))
        {
            continue;
        }
        let mut inds = Vec::new();
        find_authdata(&cammac.elements, AD_AUTH_INDICATOR, &mut inds);
        for d in inds {
            if let Ok(list) = rasn::der::decode::<Vec<Utf8String>>(&d) {
                for s in list {
                    let s = s.to_string();
                    if !out.contains(&s) {
                        out.push(s);
                    }
                }
            }
        }
    }
    out
}

/// `check_indicators`: a server's `require_auth` string attribute lists
/// indicators, any one of which the ticket must carry.
pub(crate) fn check_indicators(
    require_auth: Option<&str>,
    indicators: &[String],
) -> Result<(), KdcError> {
    let Some(req) = require_auth else {
        return Ok(());
    };
    if req
        .split(' ')
        .filter(|s| !s.is_empty())
        .any(|r| indicators.iter().any(|i| i == r))
    {
        return Ok(());
    }
    Err(KdcError::new(
        crate::types::error_codes::KDC_ERR_POLICY,
        &format!("Required auth indicators not present in ticket: {req}"),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kdc::db::{MemoryStore, PrincipalAttributes};
    use crate::kdc::error::general_string;
    use crate::types::{PrincipalName, TicketFlags};

    fn tgt(name: &str) -> PrincipalEntry {
        let mut store = MemoryStore::new();
        let p = PrincipalName::new_principal(name);
        store
            .add_random_key(p.clone(), "R", 1, &[18, 17], PrincipalAttributes::empty())
            .expect("tgt");
        store.get(&p, "R").expect("entry")
    }

    fn part() -> EncTicketPart {
        let t = chrono::DateTime::from_timestamp(1_700_000_000, 0)
            .expect("time")
            .fixed_offset();
        EncTicketPart {
            flags: crate::types::KerberosFlags::new(TicketFlags::empty()),
            key: EncryptionKey::new(18, vec![1; 32]),
            crealm: general_string("R").expect("realm"),
            cname: PrincipalName::new_principal("alice"),
            transited: crate::types::TransitedEncoding {
                tr_type: 1,
                contents: Vec::new().into(),
            },
            authtime: t,
            starttime: None,
            endtime: t,
            renew_till: None,
            caddr: None,
            authorization_data: None,
        }
    }

    fn svc_key() -> EncryptionKey {
        EncryptionKey::new(18, vec![7; 32])
    }

    fn inds(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn indicators_round_trip_in_if_relevant_cammac() {
        let local = tgt("krbtgt");
        let mut p = part();
        add_auth_indicators(&mut p, &inds(&["otp", "strong"]), &svc_key(), &local).expect("add");
        let ad = p.authorization_data.as_deref().expect("authdata");
        assert_eq!(ad.len(), 1);
        assert_eq!(ad[0].ad_type, AD_IF_RELEVANT);
        assert_eq!(get_auth_indicators(&p, &local), inds(&["otp", "strong"]));
    }

    #[test]
    fn no_indicators_adds_no_authdata() {
        let local = tgt("krbtgt");
        let mut p = part();
        add_auth_indicators(&mut p, &[], &svc_key(), &local).expect("add");
        assert!(p.authorization_data.is_none());
    }

    #[test]
    fn changed_ticket_fails_kdc_verifier() {
        let local = tgt("krbtgt");
        let mut p = part();
        add_auth_indicators(&mut p, &inds(&["strong"]), &svc_key(), &local).expect("add");
        p.cname = PrincipalName::new_principal("mallory");
        assert!(get_auth_indicators(&p, &local).is_empty());
    }

    #[test]
    fn other_kdc_key_fails_kdc_verifier() {
        let mut p = part();
        add_auth_indicators(&mut p, &inds(&["strong"]), &svc_key(), &tgt("krbtgt")).expect("add");
        assert!(get_auth_indicators(&p, &tgt("other")).is_empty());
    }

    #[test]
    fn malformed_cammac_is_skipped() {
        let local = tgt("krbtgt");
        let mut p = part();
        p.authorization_data = Some(vec![AuthorizationDataElement {
            ad_type: AD_CAMMAC,
            ad_data: vec![0x30, 0x03, 0x01].into(),
        }]);
        assert!(get_auth_indicators(&p, &local).is_empty());
    }

    #[test]
    fn require_auth_needs_any_one_listed_indicator() {
        assert!(check_indicators(None, &[]).is_ok());
        assert!(check_indicators(Some("hardware strong"), &inds(&["strong"])).is_ok());
        assert!(check_indicators(Some("hardware"), &inds(&["strong"])).is_err());
        assert!(check_indicators(Some("hardware"), &[]).is_err());
    }
}
