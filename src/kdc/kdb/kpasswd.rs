//! The kpasswd service (RFC 3244; MIT `kadmin/server/schpw.c` and
//! `schpw_util_wrapper`/`check_min_life` in `kadmin/server/misc.c`).
//! Transport (UDP datagrams, TCP four-byte length prefix) is the caller's.

use std::net::SocketAddr;
use std::time::Duration;

use chrono::{Timelike, Utc};
use rasn::prelude::*;

use super::admin::{AdminOps, PASS_Q_CLASS, PASS_Q_TOOSHORT, PASS_REUSE};
use super::kprop::{error_code, host_address, ReplayCache};
use super::mit::parse_name_with_default;
use crate::kdc::store::{AdminStore, StoreErrorKind};
use crate::kdc::PrincipalAttributes;
use crate::protocol::ap::{AuthContext, AuthContextFlags, KeySource};
use crate::types::error_codes::KRB_AP_ERR_REPEAT;
use crate::types::{HostAddress, KrbErrorMsg, PrincipalName, TicketFlags};

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

const KRB_ERR_MAX: i32 = 127;
const KRB_ERR_GENERIC: i32 = 60;
/// `ADDRTYPE_DIRECTIONAL` (`k5_addr_directional_accept`).
const ADDRTYPE_DIRECTIONAL: i32 = 3;

const PASSWORD_NOT_CHANGED: &str = "Password not changed.";
const WHILE_TRYING_TO_CHANGE: &str = "while trying to change password.";
const PASSWORD_REUSE: &str =
    "New password was used previously. Please choose a different password.";

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

/// A framed request split into its parts.
#[derive(Debug, PartialEq, Eq)]
pub struct Request<'a> {
    /// Protocol version: 1 or [`RFC3244_VERSION`].
    pub version: u16,
    /// The AP-REQ for `kadmin/changepw`.
    pub ap_req: &'a [u8],
    /// The KRB-PRIV carrying the password (or `ChangePasswdData`).
    pub krb_priv: &'a [u8],
}

/// Split a request (`schpw.c:41-104`). An error is a request MIT drops
/// without replying.
pub fn parse_request(req: &[u8]) -> Result<Request<'_>, String> {
    if req.len() < 4 {
        return Err("Request was truncated".into());
    }
    let plen = usize::from(u16::from_be_bytes([req[0], req[1]]));
    if plen != req.len() {
        return Err("Request length was inconsistent".into());
    }
    let version = u16::from_be_bytes([req[2], req[3]]);
    if version != 1 && version != RFC3244_VERSION {
        return Err(format!(
            "Request contained unknown protocol version number {version}"
        ));
    }
    let ap_len = match req.get(4..6) {
        Some(b) => usize::from(u16::from_be_bytes([b[0], b[1]])),
        None => return Err("Request was truncated in AP-REQ".into()),
    };
    if 6 + ap_len >= req.len() {
        return Err("Request was truncated in AP-REQ".into());
    }
    Ok(Request {
        version,
        ap_req: &req[6..6 + ap_len],
        krb_priv: &req[6 + ap_len..],
    })
}

/// Authorization for changing another principal's password: MIT
/// `acl_check(ACL_CHANGEPW)` with (client, client realm, target, target
/// realm).
pub type Authorize<'a> = dyn Fn(&PrincipalName, &str, &PrincipalName, &str) -> bool + 'a;

/// What the service needs besides the database.
pub struct Service<'a> {
    /// Our realm.
    pub realm: &'a str,
    /// Keys for `kadmin/changepw@REALM`.
    pub keys: &'a dyn KeySource,
    /// Authenticator replay cache.
    pub replay: Option<&'a ReplayCache>,
    /// Clock skew used for the replay window.
    pub clockskew: Duration,
    /// `ACL_CHANGEPW` check for non-self changes.
    pub authorize: &'a Authorize<'a>,
}

/// Result of one request.
#[derive(Debug)]
pub struct Processed {
    /// The framed reply, or `None` when MIT sends nothing.
    pub reply: Option<Vec<u8>>,
    /// The line MIT logs at `LOG_NOTICE`.
    pub log: String,
}

struct Failure {
    status: u16,
    text: String,
    code: i32,
}

struct Authenticated {
    client: PrincipalName,
    crealm: String,
    initial: bool,
    clear: Vec<u8>,
}

fn changepw_principal(realm: &str) -> PrincipalName {
    parse_name_with_default("kadmin/changepw", realm)
        .map(|(n, _)| n)
        .expect("kadmin/changepw parses")
}

fn unparse(name: &PrincipalName, realm: &str) -> String {
    String::from_utf8_lossy(&super::mit::unparse_name(name, realm)).into_owned()
}

fn authenticate(
    ctx: &mut AuthContext,
    svc: &Service<'_>,
    server: &PrincipalName,
    req: &Request<'_>,
    ap_rep: &mut Vec<u8>,
) -> Result<Authenticated, Failure> {
    let fail = |status, text: &str, code| Failure {
        status,
        text: text.into(),
        code,
    };
    let auth = ctx
        .rd_req(req.ap_req, Some(server), svc.keys)
        .map_err(|e| {
            fail(
                KPASSWD_AUTHERROR,
                "Failed reading application request",
                error_code(&e),
            )
        })?;
    let crealm = String::from_utf8_lossy(auth.ticket.crealm.as_bytes()).into_owned();
    let client = auth.ticket.cname.clone();
    if let Some(cache) = svc.replay {
        let name = unparse(&client, &crealm);
        let ctime = auth.authenticator.ctime.timestamp();
        if !cache.check(&name, ctime, auth.authenticator.cusec, svc.clockskew) {
            return Err(fail(
                KPASSWD_AUTHERROR,
                "Failed reading application request",
                KRB_AP_ERR_REPEAT,
            ));
        }
    }
    *ap_rep = ctx.mk_rep().map_err(|e| {
        fail(
            KPASSWD_AUTHERROR,
            "Failed replying to application request",
            error_code(&e),
        )
    })?;
    let (clear, _) = ctx.rd_priv(req.krb_priv).map_err(|e| {
        fail(
            KPASSWD_HARDERROR,
            "Failed decrypting request",
            error_code(&e),
        )
    })?;
    Ok(Authenticated {
        client,
        crealm,
        initial: auth.ticket.flags.contains(TicketFlags::INITIAL),
        clear,
    })
}

/// `ctime(3)` without its newline.
fn ctime(seconds: i64) -> String {
    chrono::DateTime::from_timestamp(seconds, 0).map_or_else(
        || "(error)".into(),
        |t| {
            t.with_timezone(&chrono::Local)
                .format("%a %b %e %H:%M:%S %Y")
                .to_string()
        },
    )
}

fn too_soon(until: i64) -> String {
    format!(
        "Password cannot be changed because it was changed too recently.\n\
         Please wait until {} before you change it.\n\
         If you need to change your password before then, contact your system\n\
         security administrator.",
        ctime(until)
    )
}

fn too_short(min_length: u32) -> String {
    format!(
        "New password is too short.\n\
         Please choose a password which is at least {min_length} characters long."
    )
}

fn too_few_classes(min_classes: u32) -> String {
    format!(
        "New password does not have enough character classes.\n\
         The character classes are:\n\
         \t- lower-case letters,\n\
         \t- upper-case letters,\n\
         \t- digits,\n\
         \t- punctuation, and\n\
         \t- all other characters (e.g., control characters).\n\
         Please choose a password with at least {min_classes} character classes."
    )
}

fn not_changed(error: &str) -> String {
    format!("{PASSWORD_NOT_CHANGED}\n{error} {WHILE_TRYING_TO_CHANGE}\n")
}

/// `check_min_life` (`misc.c:59-125`).
async fn check_min_life<S: AdminStore>(
    admin: &AdminOps<S>,
    name: &PrincipalName,
    realm: &str,
) -> Result<(), (u16, String)> {
    let rec = admin
        .get_principal(name, realm)
        .await
        .map_err(|_| (KPASSWD_HARDERROR, String::new()))?;
    let Some(policy) = rec.entry.policy.as_deref() else {
        return Ok(());
    };
    let policy = match admin.get_policy(policy).await {
        Ok(p) => p,
        Err(e) if e.kind() == StoreErrorKind::NotFound => return Ok(()),
        Err(_) => return Err((KPASSWD_HARDERROR, String::new())),
    };
    let last = rec.last_pwd_change.map_or(0, |t| t.timestamp());
    let now = Utc::now().timestamp();
    if now - last < i64::from(policy.pw_min_life)
        && !rec
            .entry
            .attributes
            .contains(PrincipalAttributes::REQUIRES_PWCHANGE)
    {
        return Err((
            KPASSWD_SOFTERROR,
            too_soon(last + i64::from(policy.pw_min_life)),
        ));
    }
    Ok(())
}

/// `kadm5_chpass_principal_util` (`lib/kadm5/chpass_util.c:126-239`)
/// with `process_chpw_request`'s status mapping (`schpw.c:249-271`).
async fn chpass_util<S: AdminStore>(
    admin: &AdminOps<S>,
    name: &PrincipalName,
    realm: &str,
    password: &str,
) -> (u16, String) {
    let e = match admin
        .change_password(name, realm, Some(password), false)
        .await
    {
        Ok(_) => return (KPASSWD_SUCCESS, String::new()),
        Err(e) => e,
    };
    if e.kind() == StoreErrorKind::Rejected && e.message() == PASS_REUSE {
        return (KPASSWD_SOFTERROR, PASSWORD_REUSE.into());
    }
    let quality = e.kind() == StoreErrorKind::Rejected
        && (e.message() == PASS_Q_TOOSHORT || e.message() == PASS_Q_CLASS);
    if !quality {
        return (KPASSWD_HARDERROR, not_changed(e.message()));
    }
    let policy = match admin.get_principal(name, realm).await {
        Ok(rec) => match rec.entry.policy.as_deref() {
            Some(p) => admin.get_policy(p).await.ok(),
            None => None,
        },
        Err(_) => None,
    };
    let Some(policy) = policy else {
        return (KPASSWD_SOFTERROR, not_changed(e.message()));
    };
    if e.message() == PASS_Q_TOOSHORT {
        (KPASSWD_SOFTERROR, too_short(policy.pw_min_length))
    } else {
        (KPASSWD_SOFTERROR, too_few_classes(policy.pw_min_classes))
    }
}

/// `schpw_util_wrapper` (`misc.c:13-57`).
async fn schpw_util_wrapper<S: AdminStore>(
    admin: &AdminOps<S>,
    svc: &Service<'_>,
    (client, crealm): (&PrincipalName, &str),
    (target, trealm): (&PrincipalName, &str),
    initial: bool,
    password: &str,
) -> (u16, String) {
    let is_self = client.name_string == target.name_string && crealm == trealm;
    if is_self {
        if !initial {
            return (
                KPASSWD_INITIAL_FLAG_NEEDED,
                "Ticket must be derived from a password".into(),
            );
        }
        if let Err(e) = check_min_life(admin, target, trealm).await {
            return e;
        }
    }
    if !is_self && !(svc.authorize)(client, crealm, target, trealm) {
        return (KPASSWD_ACCESSDENIED, "Unauthorized request".into());
    }
    chpass_util(admin, target, trealm, password).await
}

fn result_data(status: u16, text: &str) -> Vec<u8> {
    let mut out = status.to_be_bytes().to_vec();
    out.extend_from_slice(text.as_bytes());
    out
}

fn local_address(local: &SocketAddr) -> HostAddress {
    if local.ip().is_unspecified() {
        HostAddress {
            addr_type: ADDRTYPE_DIRECTIONAL,
            address: OctetString::from_static(&[0, 0, 0, 1]),
        }
    } else {
        host_address(local)
    }
}

/// The KRB-ERROR `process_chpw_request` sends when no KRB-PRIV could be
/// made (`schpw.c:309-340`).
fn kpasswd_error(realm: &str, server: &PrincipalName, code: i32, e_data: Vec<u8>) -> Vec<u8> {
    let now = Utc::now();
    let code = if (0..=KRB_ERR_MAX).contains(&code) {
        code
    } else {
        KRB_ERR_GENERIC
    };
    let msg = KrbErrorMsg {
        pvno: 5,
        msg_type: 30,
        ctime: None,
        cusec: None,
        stime: now.with_nanosecond(0).unwrap_or(now).fixed_offset(),
        susec: 0,
        error_code: code,
        crealm: None,
        cname: None,
        realm: GeneralString::from_bytes(realm.as_bytes()).unwrap_or_default(),
        sname: server.clone(),
        e_text: None,
        e_data: Some(OctetString::from(e_data)),
    };
    rasn::der::encode(&msg).unwrap_or_default()
}

fn frame(ap_rep: &[u8], body: &[u8]) -> Option<Vec<u8>> {
    let total = u16::try_from(6 + ap_rep.len() + body.len()).ok()?;
    let ap_len = u16::try_from(ap_rep.len()).ok()?;
    let mut out = Vec::with_capacity(usize::from(total));
    out.extend_from_slice(&total.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&ap_len.to_be_bytes());
    out.extend_from_slice(ap_rep);
    out.extend_from_slice(body);
    Some(out)
}

/// `process_chpw_request` (`schpw.c:18-399`): `local` is the address the
/// request arrived on and `remote` the sender.
pub async fn process_request<S: AdminStore>(
    admin: &AdminOps<S>,
    svc: &Service<'_>,
    local: &SocketAddr,
    remote: &SocketAddr,
    req: &[u8],
) -> Processed {
    let from = remote.ip();
    let parsed = match parse_request(req) {
        Ok(p) => p,
        Err(text) => {
            return Processed {
                reply: None,
                log: format!("chpw request from {from}: {text}"),
            }
        }
    };
    let server = changepw_principal(svc.realm);
    let mut ctx = AuthContext::new();
    ctx.set_flags(AuthContextFlags::DO_SEQUENCE);
    let mut ap_rep = Vec::new();
    let (status, mut text, code, log) =
        match authenticate(&mut ctx, svc, &server, &parsed, &mut ap_rep) {
            Err(f) => {
                let log = format!("chpw request from {from}: {}", f.text);
                (f.status, f.text, f.code, log)
            }
            Ok(auth) => {
                let (status, text, log) = change(admin, svc, &parsed, auth, from).await;
                (status, text, 0, log)
            }
        };
    let mut status = status;
    let mut code = code;
    let mut cipher = Vec::new();
    if !ap_rep.is_empty() {
        ctx.set_addrs(Some(local_address(local)), None);
        match ctx.mk_priv(&result_data(status, &text)) {
            Ok((c, _)) => cipher = c,
            Err(e) => {
                status = KPASSWD_HARDERROR;
                text = "Failed encrypting reply".into();
                code = error_code(&e);
            }
        }
    }
    if cipher.is_empty() {
        ap_rep.clear();
        cipher = kpasswd_error(svc.realm, &server, code, result_data(status, &text));
    }
    Processed {
        reply: frame(&ap_rep, &cipher),
        log,
    }
}

async fn change<S: AdminStore>(
    admin: &AdminOps<S>,
    svc: &Service<'_>,
    req: &Request<'_>,
    auth: Authenticated,
    from: std::net::IpAddr,
) -> (u16, String, String) {
    let client_str = unparse(&auth.client, &auth.crealm);
    let (password, target) = if req.version == RFC3244_VERSION {
        match rasn::der::decode::<ChangePasswdData>(&auth.clear) {
            Ok(d) => {
                let target = d.targname.map(|n| {
                    let realm = d
                        .targrealm
                        .map(|r| String::from_utf8_lossy(r.as_bytes()).into_owned())
                        .unwrap_or_default();
                    (n, realm)
                });
                (d.newpasswd.to_vec(), target)
            }
            Err(_) => {
                let text = "Failed decoding ChangePasswdData".to_string();
                let log = format!("setpw request from {from} by {client_str}: {text}");
                return (KPASSWD_MALFORMED, text, log);
            }
        }
    } else {
        (auth.clear, None)
    };
    let password = match password.iter().position(|&b| b == 0) {
        Some(n) => &password[..n],
        None => &password[..],
    };
    let (status, text) = match std::str::from_utf8(password) {
        Ok(pw) => {
            let (tname, trealm) = target
                .as_ref()
                .map_or((&auth.client, auth.crealm.as_str()), |(n, r)| {
                    (n, r.as_str())
                });
            schpw_util_wrapper(
                admin,
                svc,
                (&auth.client, &auth.crealm),
                (tname, trealm),
                auth.initial,
                pw,
            )
            .await
        }
        Err(_) => (
            KPASSWD_HARDERROR,
            not_changed("Password is not valid UTF-8"),
        ),
    };
    let outcome = if status == KPASSWD_SUCCESS {
        "success".to_string()
    } else {
        text.lines().next().unwrap_or_default().to_string()
    };
    let log = if req.version == RFC3244_VERSION {
        let target_str = target
            .as_ref()
            .map_or_else(|| client_str.clone(), |(n, r)| unparse(n, r));
        format!("setpw request from {from} by {client_str} for {target_str}: {outcome}")
    } else {
        format!("chpw request from {from} for {client_str}: {outcome}")
    };
    (status, text, log)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn framed(version: u16, ap_req: &[u8], rest: &[u8]) -> Vec<u8> {
        let total = u16::try_from(6 + ap_req.len() + rest.len()).expect("len");
        let mut v = total.to_be_bytes().to_vec();
        v.extend_from_slice(&version.to_be_bytes());
        v.extend_from_slice(&u16::try_from(ap_req.len()).expect("len").to_be_bytes());
        v.extend_from_slice(ap_req);
        v.extend_from_slice(rest);
        v
    }

    #[test]
    fn requests_are_split_like_schpw() {
        let req = framed(1, b"apreq", b"priv");
        assert_eq!(
            parse_request(&req),
            Ok(Request {
                version: 1,
                ap_req: b"apreq",
                krb_priv: b"priv",
            })
        );
        let req = framed(RFC3244_VERSION, b"a", b"p");
        assert_eq!(parse_request(&req).expect("ok").version, RFC3244_VERSION);
    }

    #[test]
    fn malformed_requests_are_dropped_with_mit_reasons() {
        assert_eq!(
            parse_request(&[0, 3, 0]),
            Err("Request was truncated".into())
        );
        let mut req = framed(1, b"a", b"p");
        req[1] += 1;
        assert_eq!(
            parse_request(&req),
            Err("Request length was inconsistent".into())
        );
        assert_eq!(
            parse_request(&framed(2, b"a", b"p")),
            Err("Request contained unknown protocol version number 2".into())
        );
        assert_eq!(
            parse_request(&framed(1, b"apreq", b"")),
            Err("Request was truncated in AP-REQ".into())
        );
        assert_eq!(
            parse_request(&[0, 4, 0, 1]),
            Err("Request was truncated in AP-REQ".into())
        );
    }

    #[test]
    fn change_passwd_data_matches_rfc3244() {
        let (name, _) = parse_name_with_default("alice", "R").expect("name");
        let data = ChangePasswdData {
            newpasswd: OctetString::from_static(b"pw"),
            targname: Some(name),
            targrealm: Some(GeneralString::from_bytes(b"R").expect("realm")),
        };
        let der = rasn::der::encode(&data).expect("encode");
        let mut expected = vec![0x30, 0x1f, 0xa0, 0x04, 0x04, 0x02, b'p', b'w'];
        expected.extend_from_slice(&[0xa1, 0x12, 0x30, 0x10, 0xa0, 0x03, 0x02, 0x01, 0x01]);
        expected.extend_from_slice(&[0xa1, 0x09, 0x30, 0x07, 0x1b, 0x05]);
        expected.extend_from_slice(b"alice");
        expected.extend_from_slice(&[0xa2, 0x03, 0x1b, 0x01, b'R']);
        assert_eq!(der, expected);
        assert_eq!(
            rasn::der::decode::<ChangePasswdData>(&der).expect("decode"),
            data
        );
        let pw_only = ChangePasswdData {
            newpasswd: OctetString::from_static(b"pw"),
            targname: None,
            targrealm: None,
        };
        assert_eq!(
            rasn::der::encode(&pw_only).expect("encode"),
            [0x30, 0x06, 0xa0, 0x04, 0x04, 0x02, b'p', b'w']
        );
    }

    #[test]
    fn replies_are_framed_with_version_one() {
        let r = frame(b"rep", b"priv").expect("frame");
        assert_eq!(&r[..6], &[0, 13, 0, 1, 0, 3]);
        assert_eq!(&r[6..], b"reppriv");
        assert_eq!(result_data(KPASSWD_SOFTERROR, "x"), [0, 4, b'x']);
    }

    #[test]
    fn kpasswd_errors_carry_the_result_in_e_data() {
        let server = changepw_principal("R");
        let der = kpasswd_error("R", &server, 1_000, result_data(KPASSWD_AUTHERROR, "f"));
        let msg: KrbErrorMsg = rasn::der::decode(&der).expect("decode");
        assert_eq!(msg.error_code, KRB_ERR_GENERIC);
        assert_eq!(msg.susec, 0);
        assert!(msg.e_text.is_none() && msg.cname.is_none());
        assert_eq!(msg.e_data.expect("e_data").to_vec(), [0, 3, b'f']);
        assert_eq!(unparse(&msg.sname, "R"), "kadmin/changepw@R");
    }

    #[test]
    fn messages_match_chpass_util_strings() {
        assert!(too_short(8).ends_with("at least 8 characters long."));
        assert!(too_few_classes(3).contains("\n\t- digits,\n"));
        assert_eq!(
            not_changed("boom"),
            "Password not changed.\nboom while trying to change password.\n"
        );
        assert!(!too_soon(0).contains("1970\n"));
    }
}
