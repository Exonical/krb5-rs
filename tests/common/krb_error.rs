//! Shared KRB-ERROR builders.

use krb5_rs::types::{KerberosTime, KrbErrorMsg, PrincipalName};
use rasn::types::{GeneralString, OctetString};

/// Build a KRB-ERROR message. `stime` defaults to the unix epoch when `None`
/// (deterministic — use `Some(now())` where a live timestamp is wanted).
pub fn krb_error_msg(
    code: i32,
    realm: &str,
    stime: Option<KerberosTime>,
    e_data: Option<Vec<u8>>,
) -> KrbErrorMsg {
    KrbErrorMsg {
        pvno: 5,
        msg_type: 30,
        ctime: None,
        cusec: None,
        stime: stime.unwrap_or_else(|| {
            chrono::DateTime::from_timestamp(0, 0)
                .expect("epoch")
                .fixed_offset()
        }),
        susec: 0,
        error_code: code,
        crealm: None,
        cname: None,
        realm: GeneralString::from_bytes(realm.as_bytes()).expect("realm"),
        sname: PrincipalName::new_srv_inst("krbtgt", realm),
        e_text: None,
        e_data: e_data.map(OctetString::from),
    }
}

/// DER-encode a KRB-ERROR built by [`krb_error_msg`].
pub fn krb_error_der(
    code: i32,
    realm: &str,
    stime: Option<KerberosTime>,
    e_data: Option<Vec<u8>>,
) -> Vec<u8> {
    rasn::der::encode(&krb_error_msg(code, realm, stime, e_data)).expect("encode KRB-ERROR")
}
