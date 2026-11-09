//! MIT's sample KDC authdata module, `greet`
//! (plugins/authdata/greet_server/greet_auth.c), and
//! `krb5_make_authdata_kdc_issued` / `krb5_verify_authdata_kdc_issued`
//! (lib/krb5/krb/authdata_enc.c).

use subtle::ConstantTimeEq;

use super::{AuthdataRequest, KdcAuthdata, Principal, MSG_TGS_REQ};
use crate::crypto::find_etype;
use crate::pac::AD_IF_RELEVANT;
use crate::plugin::rpc::{ERROR_TABLE_BASE_KRB5, KRB_ERR_GENERIC};
use crate::types::{
    AdKdcIssued, AuthorizationDataElement, Checksum, EncTicketPart, EncryptionKey, PrincipalName,
    AD_KDC_ISSUED, KEYUSAGE_AD_KDCISSUED_CKSUM,
};

/// The greet authdata type.
pub const AD_GREET: i32 = -42;
/// The greeting.
pub const GREETING: &str = "Hello, KDC issued acceptor world!";

const GENERIC: i32 = ERROR_TABLE_BASE_KRB5 + KRB_ERR_GENERIC;

fn kdc_issued_checksum(
    key: &EncryptionKey,
    elements: &[AuthorizationDataElement],
) -> Result<Checksum, i32> {
    let profile = find_etype(key.keytype).map_err(|_| GENERIC)?;
    let data = rasn::der::encode(&elements.to_vec()).map_err(|_| GENERIC)?;
    let mac = profile
        .checksum(key.key_bytes(), KEYUSAGE_AD_KDCISSUED_CKSUM, &data)
        .map_err(|_| GENERIC)?;
    Ok(Checksum {
        cksumtype: profile.checksum_type(),
        checksum: mac.into(),
    })
}

/// `krb5_make_authdata_kdc_issued`: an AD-KDC-ISSUED element holding
/// `elements`, checksummed with `key` and naming `issuer`.
pub fn make_authdata_kdc_issued(
    key: &EncryptionKey,
    issuer: Option<(&PrincipalName, &str)>,
    elements: &[AuthorizationDataElement],
) -> Result<AuthorizationDataElement, i32> {
    let ad = AdKdcIssued {
        ad_checksum: kdc_issued_checksum(key, elements)?,
        i_realm: issuer
            .map(|(_, r)| rasn::types::GeneralString::try_from(r.as_bytes().to_vec()))
            .transpose()
            .map_err(|_| GENERIC)?,
        i_sname: issuer.map(|(n, _)| n.clone()),
        elements: elements.to_vec(),
    };
    Ok(AuthorizationDataElement {
        ad_type: AD_KDC_ISSUED,
        ad_data: rasn::der::encode(&ad).map_err(|_| GENERIC)?.into(),
    })
}

/// `krb5_verify_authdata_kdc_issued`: the issuer and elements of an
/// AD-KDC-ISSUED element whose checksum `key` verifies.
pub fn verify_authdata_kdc_issued(
    key: &EncryptionKey,
    el: &AuthorizationDataElement,
) -> Option<(Option<Principal>, Vec<AuthorizationDataElement>)> {
    if el.ad_type != AD_KDC_ISSUED {
        return None;
    }
    let ad: AdKdcIssued = rasn::der::decode(el.ad_data.as_ref()).ok()?;
    let want = kdc_issued_checksum(key, &ad.elements).ok()?;
    if want.cksumtype != ad.ad_checksum.cksumtype
        || !bool::from(
            want.checksum
                .as_ref()
                .ct_eq(ad.ad_checksum.checksum.as_ref()),
        )
    {
        return None;
    }
    let issuer = match (ad.i_sname, ad.i_realm) {
        (Some(n), Some(r)) => Some((n, String::from_utf8_lossy(r.as_bytes()).into_owned())),
        _ => None,
    };
    Some((issuer, ad.elements))
}

/// The `greet` module: on TGS requests, adds an AD-IF-RELEVANT holding an
/// AD-KDC-ISSUED [`AD_GREET`] [`GREETING`], signed with the new ticket's
/// session key and naming the header ticket's server, ahead of the
/// ticket's other authorization data.
pub struct Greet;

impl KdcAuthdata for Greet {
    fn name(&self) -> &str {
        "greet"
    }

    fn handle(&self, req: &AuthdataRequest, reply: &mut EncTicketPart) -> Result<(), i32> {
        if req.msg_type != MSG_TGS_REQ {
            return Ok(());
        }
        let greeting = AuthorizationDataElement {
            ad_type: AD_GREET,
            ad_data: GREETING.as_bytes().to_vec().into(),
        };
        let issuer = req.header_server.as_ref().map(|(n, r)| (n, r.as_str()));
        let kdc_issued = make_authdata_kdc_issued(&reply.key, issuer, &[greeting])?;
        let if_relevant = AuthorizationDataElement {
            ad_type: AD_IF_RELEVANT,
            ad_data: rasn::der::encode(&vec![kdc_issued])
                .map_err(|_| GENERIC)?
                .into(),
        };
        let mut list = vec![if_relevant];
        list.extend(reply.authorization_data.take().unwrap_or_default());
        reply.authorization_data = Some(list);
        Ok(())
    }
}
