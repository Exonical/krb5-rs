//! MIT's sample KDC authdata module, `greet`
//! (plugins/authdata/greet_server/greet_auth.c), and
//! `krb5_make_authdata_kdc_issued` / `krb5_verify_authdata_kdc_issued`
//! (lib/krb5/krb/authdata_enc.c).

use super::{AuthdataRequest, KdcAuthdata, Principal, MSG_TGS_REQ};
use crate::pac::AD_IF_RELEVANT;
use crate::plugin::rpc::{ERROR_TABLE_BASE_KRB5, KRB_ERR_GENERIC};
use crate::types::{AuthorizationDataElement, EncTicketPart, EncryptionKey};

const GENERIC: i32 = ERROR_TABLE_BASE_KRB5 + KRB_ERR_GENERIC;

/// The greet authdata type.
pub use crate::authdata::greet::AD_GREET;
/// The greeting.
pub const GREETING: &str = "Hello, KDC issued acceptor world!";

/// `krb5_make_authdata_kdc_issued`.
pub use crate::authdata::make_authdata_kdc_issued;

/// `krb5_verify_authdata_kdc_issued`: the issuer and elements of an
/// AD-KDC-ISSUED element whose checksum `key` verifies.
pub fn verify_authdata_kdc_issued(
    key: &EncryptionKey,
    el: &AuthorizationDataElement,
) -> Option<(Option<Principal>, Vec<AuthorizationDataElement>)> {
    crate::authdata::verify_authdata_kdc_issued(key, el)
        .ok()
        .flatten()
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
