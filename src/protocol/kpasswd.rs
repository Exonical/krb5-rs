//! The kpasswd protocol messages shared by the client and the server
//! (RFC 3244; MIT `lib/krb5/krb/chpw.c`).

use rasn::prelude::*;

use crate::error::Krb5Error;
use crate::protocol::ap::{ApError, AuthContext, AuthContextFlags};
use crate::types::{KrbErrorMsg, PrincipalName};

/// `DEFAULT_KPASSWD_PORT` (`include/osconf.hin`).
pub const KPASSWD_PORT: u16 = 464;
/// Set-password protocol version (`RFC3244_VERSION`, `schpw.c`).
pub const RFC3244_VERSION: u16 = 0xff80;

/// `KRB5_KPASSWD_SUCCESS`.
pub const KPASSWD_SUCCESS: u16 = 0;
/// `KRB5_KPASSWD_MALFORMED`.
pub const KPASSWD_MALFORMED: u16 = 1;
/// `KRB5_KPASSWD_HARDERROR`.
pub const KPASSWD_HARDERROR: u16 = 2;
/// `KRB5_KPASSWD_AUTHERROR`.
pub const KPASSWD_AUTHERROR: u16 = 3;
/// `KRB5_KPASSWD_SOFTERROR`.
pub const KPASSWD_SOFTERROR: u16 = 4;
/// `KRB5_KPASSWD_ACCESSDENIED`.
pub const KPASSWD_ACCESSDENIED: u16 = 5;
/// `KRB5_KPASSWD_BAD_VERSION`.
pub const KPASSWD_BAD_VERSION: u16 = 6;
/// `KRB5_KPASSWD_INITIAL_FLAG_NEEDED`.
pub const KPASSWD_INITIAL_FLAG_NEEDED: u16 = 7;

/// `ChangePasswdData` (RFC 3244 §2; `krb5_setpw_req`,
/// `asn1_k_encode.c`).
#[derive(AsnType, Encode, Decode, Debug, Clone, PartialEq, Eq)]
pub struct ChangePasswdData {
    /// New password.
    #[rasn(tag(explicit(context, 0)))]
    pub newpasswd: OctetString,
    /// Target principal name.
    #[rasn(tag(explicit(context, 1)))]
    pub targname: Option<PrincipalName>,
    /// Target principal realm.
    #[rasn(tag(explicit(context, 2)))]
    pub targrealm: Option<GeneralString>,
}

fn frame(version: u16, ap: &[u8], body: &[u8]) -> Result<Vec<u8>, Krb5Error> {
    let too_long = || Krb5Error::Protocol("kpasswd request too long".into());
    let total = u16::try_from(6 + ap.len() + body.len()).map_err(|_| too_long())?;
    let ap_len = u16::try_from(ap.len()).map_err(|_| too_long())?;
    let mut out = Vec::with_capacity(usize::from(total));
    out.extend_from_slice(&total.to_be_bytes());
    out.extend_from_slice(&version.to_be_bytes());
    out.extend_from_slice(&ap_len.to_be_bytes());
    out.extend_from_slice(ap);
    out.extend_from_slice(body);
    Ok(out)
}

/// `krb5int_mk_chpw_req` (chpw.c:13-65): a version 1 request carrying
/// `password` in a KRB-PRIV made with `ctx` (which needs its local
/// address set).
pub fn mk_chpw_req(
    ctx: &mut AuthContext,
    ap_req: &[u8],
    password: &[u8],
) -> Result<Vec<u8>, Krb5Error> {
    ctx.set_flags(AuthContextFlags::DO_SEQUENCE);
    let (cipher, _) = ctx.mk_priv(password)?;
    frame(1, ap_req, &cipher)
}

/// `krb5int_mk_setpw_req` (chpw.c:264-331): an RFC 3244 request setting
/// the password of `target@realm`.
pub fn mk_setpw_req(
    ctx: &mut AuthContext,
    ap_req: &[u8],
    target: &PrincipalName,
    realm: &str,
    password: &[u8],
) -> Result<Vec<u8>, Krb5Error> {
    ctx.set_flags(AuthContextFlags::DO_SEQUENCE);
    let req = ChangePasswdData {
        newpasswd: OctetString::from(password.to_vec()),
        targname: Some(target.clone()),
        targrealm: Some(
            GeneralString::try_from(realm.as_bytes().to_vec())
                .map_err(|_| Krb5Error::Protocol("invalid realm".into()))?,
        ),
    };
    let encoded = rasn::der::encode(&req)?;
    let (cipher, _) = ctx.mk_priv(&encoded)?;
    frame(RFC3244_VERSION, ap_req, &cipher)
}

/// `get_error_edata` (chpw.c:67-91): a KRB-ERROR's e-data, or the error
/// itself when it carries none.
fn error_edata(packet: &[u8]) -> Result<Vec<u8>, Krb5Error> {
    let err: KrbErrorMsg = rasn::der::decode(packet)?;
    match &err.e_data {
        Some(d) => Ok(d.to_vec()),
        None => Err(Krb5Error::from_error_msg(err)),
    }
}

/// `get_clear_result` (chpw.c:93-180): the decrypted result and whether
/// it came from a KRB-ERROR.
fn clear_result(ctx: &mut AuthContext, packet: &[u8]) -> Result<(Vec<u8>, bool), Krb5Error> {
    // krb5_is_krb_error: an unframed KRB-ERROR (RFC 3244 replies, and MS
    // AD for version 1).
    if packet.first() == Some(&0x7e) {
        return Ok((error_edata(packet)?, true));
    }
    if packet.len() < 6 {
        return Err(ApError::Modified.into());
    }
    if usize::from(u16::from_be_bytes([packet[0], packet[1]])) != packet.len() {
        return Err(ApError::Modified.into());
    }
    let vno = u16::from_be_bytes([packet[2], packet[3]]);
    if vno != 1 && vno != RFC3244_VERSION {
        return Err(Krb5Error::KdcError(Box::new(bad_pvno())));
    }
    let ap_len = usize::from(u16::from_be_bytes([packet[4], packet[5]]));
    let rest = &packet[6..];
    if ap_len > rest.len() {
        return Err(ApError::Modified.into());
    }
    // A zero-length AP-REP is a framed KRB-ERROR.
    if ap_len == 0 {
        return Ok((error_edata(rest)?, true));
    }
    let send_subkey = ctx.send_subkey().cloned();
    ctx.rd_rep(&rest[..ap_len])?;
    // Per the spec the reply is under our subkey (chpw.c:160-163).
    ctx.set_recv_subkey(send_subkey);
    let (clear, _) = ctx.rd_priv(&rest[ap_len..])?;
    Ok((clear, false))
}

/// MIT returns `KRB5KDC_ERR_BAD_PVNO` for an unknown reply version.
fn bad_pvno() -> KrbErrorMsg {
    KrbErrorMsg {
        pvno: 5,
        msg_type: 30,
        ctime: None,
        cusec: None,
        stime: chrono::DateTime::from_timestamp(0, 0)
            .unwrap_or_default()
            .fixed_offset(),
        susec: 0,
        error_code: crate::types::error_codes::KDC_ERR_BAD_PVNO,
        crealm: None,
        cname: None,
        realm: Default::default(),
        sname: PrincipalName::new_principal(""),
        e_text: None,
        e_data: None,
    }
}

/// `krb5int_rd_chpw_rep` (chpw.c:182-230): the result code and the
/// server's result string.
pub fn rd_chpw_rep(ctx: &mut AuthContext, packet: &[u8]) -> Result<(u16, Vec<u8>), Krb5Error> {
    let (clear, is_error) = clear_result(ctx, packet)?;
    if clear.len() < 2 {
        return Err(ApError::Modified.into());
    }
    let code = u16::from_be_bytes([clear[0], clear[1]]);
    if code > KPASSWD_INITIAL_FLAG_NEEDED || (is_error && code == KPASSWD_SUCCESS) {
        return Err(ApError::Modified.into());
    }
    Ok((code, clear[2..].to_vec()))
}

/// `krb5_chpw_result_code_string` (chpw.c:232-262).
pub fn result_code_string(code: u16) -> &'static str {
    match code {
        KPASSWD_MALFORMED => "Malformed request error",
        KPASSWD_HARDERROR => "Server error",
        KPASSWD_AUTHERROR => "Authentication error",
        KPASSWD_SOFTERROR => "Password change rejected",
        KPASSWD_ACCESSDENIED => "Access denied",
        KPASSWD_BAD_VERSION => "Wrong protocol version",
        KPASSWD_INITIAL_FLAG_NEEDED => "Initial password required",
        0 => "Success",
        _ => "Password change failed",
    }
}

const AD_POLICY_INFO_LENGTH: usize = 30;
const AD_POLICY_TIME_TO_DAYS: u64 = 86_400 * 10_000_000;
const AD_POLICY_COMPLEX: u32 = 0x1;

/// `decode_ad_policy_info` (chpw.c:333-445): the message for an Active
/// Directory password policy reply.
fn ad_policy_message(data: &[u8]) -> Option<String> {
    if data.len() != AD_POLICY_INFO_LENGTH || data[..2] != [0, 0] {
        return None;
    }
    let u32_at = |i: usize| u32::from_be_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);
    let u64_at = |i: usize| {
        let mut b = [0u8; 8];
        b.copy_from_slice(&data[i..i + 8]);
        u64::from_be_bytes(b)
    };
    let min_length = u32_at(2);
    let history = u32_at(6);
    let properties = u32_at(10);
    let min_age = u64_at(22);
    let mut parts = Vec::new();
    if properties & AD_POLICY_COMPLEX != 0 {
        parts.push(
            "The password must include numbers or symbols.  Don't include any part of your \
             name in the password."
                .to_string(),
        );
    }
    if min_length > 0 {
        parts.push(if min_length == 1 {
            "The password must contain at least 1 character.".to_string()
        } else {
            format!("The password must contain at least {min_length} characters.")
        });
    }
    if history > 0 {
        parts.push(if history == 1 {
            "The password must be different from the previous password.".to_string()
        } else {
            format!("The password must be different from the previous {history} passwords.")
        });
    }
    if min_age > 0 {
        let days = (min_age / AD_POLICY_TIME_TO_DAYS).max(1);
        parts.push(if days == 1 {
            "The password can only be changed once a day.".to_string()
        } else {
            format!("The password can only be changed every {days} days.")
        });
    }
    (!parts.is_empty()).then(|| parts.join("  "))
}

/// `krb5_chpw_message` (chpw.c:447-480): a message to show the user for
/// the server's result string.
pub fn chpw_message(server_string: &[u8]) -> String {
    if let Some(m) = ad_policy_message(server_string) {
        return m;
    }
    if !server_string.is_empty() && !server_string.contains(&0) {
        if let Ok(s) = std::str::from_utf8(server_string) {
            return s.to_string();
        }
    }
    "Try a more complex password, or contact your administrator.".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(min_len: u32, history: u32, props: u32, min_age: u64) -> Vec<u8> {
        let mut v = vec![0, 0];
        v.extend_from_slice(&min_len.to_be_bytes());
        v.extend_from_slice(&history.to_be_bytes());
        v.extend_from_slice(&props.to_be_bytes());
        v.extend_from_slice(&0u64.to_be_bytes());
        v.extend_from_slice(&min_age.to_be_bytes());
        v
    }

    // MIT src/tests/misc/test_chpw_message.c.
    #[test]
    fn chpw_message_matches_mit() {
        assert_eq!(
            chpw_message(b"This is a valid string."),
            "This is a valid string."
        );
        assert!(chpw_message(b"\0This is not valid.").contains("contact your administrator"));
        assert!(chpw_message(b"").contains("contact your administrator"));
        let m = chpw_message(&policy(0, 0, 1, 0));
        assert!(m.contains("The password must include numbers or symbols."));
        assert!(m.contains("Don't include any part of your name in the password."));
        assert!(chpw_message(&policy(13, 0, 0, 0))
            .contains("The password must contain at least 13 characters."));
        assert!(chpw_message(&policy(0, 9, 0, 0))
            .contains("The password must be different from the previous 9 passwords."));
        assert!(chpw_message(&policy(0, 0, 0, 0x0000_0192_54d3_8000))
            .contains("The password can only be changed every 2 days."));
        let all = chpw_message(&policy(5, 13, 1, 0x0000_00c9_2a69_c000));
        for s in [
            "The password can only be changed once a day.",
            "The password must be different from the previous 13 passwords.",
            "The password must contain at least 5 characters.",
            "The password must include numbers or symbols.",
        ] {
            assert!(all.contains(s), "{all}");
        }
        // A policy with nothing set is not a message (chpw.c:420-423).
        assert!(chpw_message(&policy(0, 0, 0, 0)).contains("contact your administrator"));
    }

    #[test]
    fn result_code_strings_match_mit() {
        assert_eq!(
            result_code_string(KPASSWD_SOFTERROR),
            "Password change rejected"
        );
        assert_eq!(
            result_code_string(KPASSWD_INITIAL_FLAG_NEEDED),
            "Initial password required"
        );
        assert_eq!(result_code_string(99), "Password change failed");
    }

    #[test]
    fn rd_chpw_rep_rejects_bad_framing_like_mit() {
        let mut ctx = AuthContext::new();
        let bad_len = [0, 9, 0, 1, 0, 0];
        assert!(matches!(
            rd_chpw_rep(&mut ctx, &bad_len),
            Err(Krb5Error::Ap(ApError::Modified))
        ));
        let bad_vno = [0, 6, 0, 2, 0, 0];
        assert!(matches!(
            rd_chpw_rep(&mut ctx, &bad_vno),
            Err(Krb5Error::KdcError(e)) if e.error_code == crate::types::error_codes::KDC_ERR_BAD_PVNO
        ));
        let short_ap = [0, 8, 0, 1, 0, 5, 1, 2];
        assert!(matches!(
            rd_chpw_rep(&mut ctx, &short_ap),
            Err(Krb5Error::Ap(ApError::Modified))
        ));
    }

    #[test]
    fn rd_chpw_rep_reads_krb_error_e_data() {
        let mut err = bad_pvno();
        err.error_code = 41;
        let mut data = KPASSWD_ACCESSDENIED.to_be_bytes().to_vec();
        data.extend_from_slice(b"no");
        err.e_data = Some(OctetString::from(data));
        let der = rasn::der::encode(&err).expect("encode");
        let mut ctx = AuthContext::new();
        assert_eq!(
            rd_chpw_rep(&mut ctx, &der).expect("reply"),
            (KPASSWD_ACCESSDENIED, b"no".to_vec())
        );
        // A framed KRB-ERROR (zero-length AP-REP) works the same way.
        let mut framed = vec![0, 0, 0, 1, 0, 0];
        framed.extend_from_slice(&der);
        let n = u16::try_from(framed.len()).expect("len").to_be_bytes();
        framed[..2].copy_from_slice(&n);
        assert_eq!(
            rd_chpw_rep(&mut ctx, &framed).expect("reply").0,
            KPASSWD_ACCESSDENIED
        );
        // A success code in an error is malformed (chpw.c:221-224).
        err.e_data = Some(OctetString::from(vec![0, 0]));
        let der = rasn::der::encode(&err).expect("encode");
        assert!(rd_chpw_rep(&mut ctx, &der).is_err());
        // Without e-data the error itself is returned.
        err.e_data = None;
        let der = rasn::der::encode(&err).expect("encode");
        assert!(matches!(
            rd_chpw_rep(&mut ctx, &der),
            Err(Krb5Error::KdcError(e)) if e.error_code == 41
        ));
    }
}
