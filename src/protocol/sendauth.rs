//! `krb5_sendauth`/`krb5_recvauth` (MIT `lib/krb5/krb/sendauth.c`,
//! `recvauth.c`) and `krb5_write_message`/`krb5_read_message`
//! (`write_msg.c`, `read_msg.c`).
//!
//! Every message is a 4-byte big-endian length followed by the data.  The
//! client sends the sendauth and application versions (NUL-terminated), the
//! server answers with one status byte, then the AP-REQ follows; the server
//! answers with an empty message or a KRB-ERROR, and with an AP-REP when
//! mutual authentication was requested.

use std::fmt;
use std::io;

use chrono::{Timelike, Utc};
use rasn::types::GeneralString;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::protocol::ap::{ApReqOptions, AuthContext, KeySource, RdReqResult};
use crate::protocol::Credential;
use crate::types::error_codes::KRB_ERR_GENERIC;
use crate::types::{ApOptions, ApReq, KrbErrorMsg, PrincipalName};
use crate::Krb5Error;

/// Sendauth protocol version (`sendauth.c` `sendauth_version`).
pub const SENDAUTH_VERSION: &str = "KRB5_SENDAUTH_V1.0";
/// Largest message accepted by [`read_message`].  MIT reads any length.
pub const MAX_MESSAGE: usize = 1024 * 1024;

/// Errors of a sendauth/recvauth exchange.
#[derive(Debug)]
pub enum SendauthError {
    /// Socket I/O failed.
    Io(io::Error),
    /// A Kerberos operation failed.
    Krb5(Krb5Error),
    /// The peer rejected the sendauth version (`KRB5_SENDAUTH_BADAUTHVERS`).
    BadAuthVersion,
    /// The peer rejected the application version
    /// (`KRB5_SENDAUTH_BADAPPLVERS`).
    BadApplVersion,
    /// The peer sent an unknown status byte (`KRB5_SENDAUTH_BADRESPONSE`).
    BadResponse,
    /// The server answered the AP-REQ with a KRB-ERROR
    /// (`KRB5_SENDAUTH_REJECTED`).
    Rejected(Box<KrbErrorMsg>),
    /// Any other protocol violation.
    Protocol(String),
}

impl fmt::Display for SendauthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "{e}"),
            Self::Krb5(e) => write!(f, "{e}"),
            Self::BadAuthVersion => f.write_str("Bad sendauth version was sent"),
            Self::BadApplVersion => f.write_str("Bad application version was sent (via sendauth)"),
            Self::BadResponse => f.write_str("Bad response (during sendauth exchange)"),
            Self::Rejected(_) => {
                f.write_str("Server rejected authentication (during sendauth exchange)")
            }
            Self::Protocol(s) => f.write_str(s),
        }
    }
}

impl std::error::Error for SendauthError {}

impl From<io::Error> for SendauthError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<Krb5Error> for SendauthError {
    fn from(e: Krb5Error) -> Self {
        Self::Krb5(e)
    }
}

/// The `e-text` of a KRB-ERROR without MIT's trailing NUL.
pub fn error_text(e: &KrbErrorMsg) -> String {
    e.e_text
        .as_ref()
        .map(|t| {
            String::from_utf8_lossy(t.as_bytes())
                .trim_end_matches('\0')
                .to_string()
        })
        .unwrap_or_default()
}

/// Protocol error code for a failed Kerberos call (`retval -
/// ERROR_TABLE_BASE_krb5`, or `KRB_ERR_GENERIC`).
pub fn error_code(e: &Krb5Error) -> i32 {
    match e {
        Krb5Error::Ap(a) => crate::protocol::ap::ap_error_code(*a),
        _ => KRB_ERR_GENERIC,
    }
}

pub(crate) fn nul_terminated(s: &str) -> Vec<u8> {
    let mut v = s.as_bytes().to_vec();
    v.push(0);
    v
}

/// `krb5_write_message`: 4-byte big-endian length, then the data.
pub async fn write_message<W: AsyncWrite + Unpin>(w: &mut W, data: &[u8]) -> io::Result<()> {
    let len = u32::try_from(data.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "message too long"))?;
    let mut buf = Vec::with_capacity(4 + data.len());
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(data);
    w.write_all(&buf).await?;
    w.flush().await
}

/// `krb5_read_message`.
pub async fn read_message<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<Vec<u8>> {
    let mut len = [0u8; 4];
    r.read_exact(&mut len).await?;
    let len = usize::try_from(u32::from_be_bytes(len))
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "message too long"))?;
    if len > MAX_MESSAGE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("message of {len} bytes exceeds {MAX_MESSAGE}"),
        ));
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf).await?;
    Ok(buf)
}

/// Encode a KRB-ERROR as `krb5_recvauth` does: `server` (or `????`) and its
/// realm, with the text carrying MIT's trailing NUL.
pub fn krb_error(
    server: &PrincipalName,
    realm: &str,
    client: Option<(&PrincipalName, &str)>,
    code: i32,
    text: &str,
) -> Vec<u8> {
    let now = Utc::now();
    let msg = KrbErrorMsg {
        pvno: 5,
        msg_type: 30,
        ctime: None,
        cusec: None,
        stime: now.with_nanosecond(0).unwrap_or(now).fixed_offset(),
        susec: i32::try_from(now.timestamp_subsec_micros()).unwrap_or(0),
        error_code: code,
        crealm: client.and_then(|(_, r)| GeneralString::from_bytes(r.as_bytes()).ok()),
        cname: client.map(|(c, _)| c.clone()),
        realm: GeneralString::from_bytes(realm.as_bytes()).unwrap_or_default(),
        sname: server.clone(),
        e_text: GeneralString::from_bytes(&nul_terminated(text)).ok(),
        e_data: None,
    };
    rasn::der::encode(&msg).unwrap_or_default()
}

/// Client half of `krb5_sendauth` (sendauth.c:44-238) with the service
/// ticket already obtained.  `in_data` is checksummed into the
/// authenticator.  Returns once the server accepted the AP-REQ and, with
/// `mutual_required`, its AP-REP verified.
pub async fn sendauth<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    ctx: &mut AuthContext,
    appl_version: &str,
    opts: &ApReqOptions,
    in_data: Option<&[u8]>,
    cred: &Credential,
) -> Result<(), SendauthError> {
    write_message(stream, &nul_terminated(SENDAUTH_VERSION)).await?;
    write_message(stream, &nul_terminated(appl_version)).await?;
    let mut status = [0u8; 1];
    stream.read_exact(&mut status).await?;
    match status[0] {
        0 => {}
        1 => return Err(SendauthError::BadAuthVersion),
        2 => return Err(SendauthError::BadApplVersion),
        _ => return Err(SendauthError::BadResponse),
    }
    let ap_req = ctx.mk_req(opts, in_data, cred)?;
    write_message(stream, &ap_req).await?;
    let reply = read_message(stream).await?;
    if !reply.is_empty() {
        return Err(match rasn::der::decode::<KrbErrorMsg>(&reply) {
            Ok(e) => SendauthError::Rejected(Box::new(e)),
            Err(_) => SendauthError::Protocol("undecodable KRB-ERROR from server".into()),
        });
    }
    if opts.mutual_required {
        let ap_rep = read_message(stream).await?;
        ctx.rd_rep(&ap_rep)?;
    }
    Ok(())
}

/// Server half of `krb5_recvauth` (recvauth.c:40-215).  `server` restricts
/// the accepted service principal as in `krb5_rd_req`; `realm` fills the
/// realm of a KRB-ERROR sent back.
pub async fn recvauth<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    ctx: &mut AuthContext,
    appl_version: &str,
    server: Option<&PrincipalName>,
    realm: &str,
    keys: &dyn KeySource,
) -> Result<RdReqResult, SendauthError> {
    let sendauth_version = read_message(stream).await?;
    let mut problem = None;
    if sendauth_version != nul_terminated(SENDAUTH_VERSION) {
        problem = Some((1u8, SendauthError::BadAuthVersion));
    }
    let version = read_message(stream).await?;
    if problem.is_none() && version != nul_terminated(appl_version) {
        problem = Some((2u8, SendauthError::BadApplVersion));
    }
    let status = problem.as_ref().map_or(0, |(b, _)| *b);
    stream.write_all(&[status]).await?;
    stream.flush().await?;
    if let Some((_, e)) = problem {
        return Err(e);
    }
    let ap_req = read_message(stream).await?;
    match ctx.rd_req(&ap_req, server, keys) {
        Ok(auth) => {
            write_message(stream, &[]).await?;
            if auth.ap_options.contains(ApOptions::MUTUAL_REQUIRED) {
                let rep = ctx.mk_rep()?;
                write_message(stream, &rep).await?;
            }
            Ok(auth)
        }
        Err(e) => {
            let unknown = PrincipalName::new_principal("????");
            let sname = server.unwrap_or(&unknown);
            let err_realm = match (server, rasn::der::decode::<ApReq>(&ap_req)) {
                (None, Ok(req)) => String::from_utf8_lossy(req.ticket.realm.as_bytes()).to_string(),
                _ => realm.to_string(),
            };
            let msg = krb_error(sname, &err_realm, None, error_code(&e), &e.to_string());
            let _ = write_message(stream, &msg).await;
            Err(e.into())
        }
    }
}
