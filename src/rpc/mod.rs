//! ONC RPC version 2 over TCP (RFC 5531), as used by MIT's gssrpc
//! (`src/lib/rpc`), with RPCSEC_GSS authentication in [`gss`].

pub mod gss;
pub mod xdr;

use std::fmt;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use xdr::{XdrError, XdrReader, XdrWriter};

/// `RPC_MSG_VERSION`.
pub const RPC_VERSION: u32 = 2;
/// `AUTH_NONE`.
pub const AUTH_NONE: u32 = 0;
/// `RPCSEC_GSS` (`auth_gss.h`).
pub const RPCSEC_GSS: u32 = 6;
/// `MAX_AUTH_BYTES` (`auth.h`).
pub const MAX_AUTH_BYTES: usize = 400;
/// The largest record accepted from a peer.
pub const MAX_RECORD: usize = 16 * 1024 * 1024;

const LAST_FRAGMENT: u32 = 0x8000_0000;
const CALL: u32 = 0;
const REPLY: u32 = 1;
const MSG_ACCEPTED: u32 = 0;
const MSG_DENIED: u32 = 1;

/// An `opaque_auth`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct OpaqueAuth {
    /// `oa_flavor`.
    pub flavor: u32,
    /// `oa_base`.
    pub body: Vec<u8>,
}

impl OpaqueAuth {
    /// `gssrpc__null_auth`.
    pub fn none() -> Self {
        Self::default()
    }

    fn write(&self, w: &mut XdrWriter) {
        w.u32(self.flavor);
        w.opaque(&self.body);
    }

    fn read(r: &mut XdrReader<'_>) -> Result<Self, XdrError> {
        let flavor = r.u32()?;
        let body = r.opaque_max(MAX_AUTH_BYTES)?.to_vec();
        Ok(Self { flavor, body })
    }
}

/// `accept_stat`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AcceptStat {
    /// `SUCCESS`.
    Success,
    /// `PROG_UNAVAIL`.
    ProgUnavail,
    /// `PROG_MISMATCH` with the supported low/high versions.
    ProgMismatch(u32, u32),
    /// `PROC_UNAVAIL`.
    ProcUnavail,
    /// `GARBAGE_ARGS`.
    GarbageArgs,
    /// `SYSTEM_ERR`.
    SystemErr,
}

/// `auth_stat`, including the RPCSEC_GSS values.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthStat {
    /// `AUTH_OK`.
    Ok,
    /// `AUTH_BADCRED`.
    BadCred,
    /// `AUTH_REJECTEDCRED`.
    RejectedCred,
    /// `AUTH_BADVERF`.
    BadVerf,
    /// `AUTH_REJECTEDVERF`.
    RejectedVerf,
    /// `AUTH_TOOWEAK`.
    TooWeak,
    /// `AUTH_INVALIDRESP`.
    InvalidResp,
    /// `AUTH_FAILED`.
    Failed,
    /// `RPCSEC_GSS_CREDPROBLEM`.
    GssCredProblem,
    /// `RPCSEC_GSS_CTXPROBLEM`.
    GssCtxProblem,
    /// Any other value.
    Other(u32),
}

impl AuthStat {
    /// The wire value.
    pub fn code(self) -> u32 {
        match self {
            Self::Ok => 0,
            Self::BadCred => 1,
            Self::RejectedCred => 2,
            Self::BadVerf => 3,
            Self::RejectedVerf => 4,
            Self::TooWeak => 5,
            Self::InvalidResp => 6,
            Self::Failed => 7,
            Self::GssCredProblem => 13,
            Self::GssCtxProblem => 14,
            Self::Other(v) => v,
        }
    }

    /// Decode a wire value.
    pub fn from_code(v: u32) -> Self {
        match v {
            0 => Self::Ok,
            1 => Self::BadCred,
            2 => Self::RejectedCred,
            3 => Self::BadVerf,
            4 => Self::RejectedVerf,
            5 => Self::TooWeak,
            6 => Self::InvalidResp,
            7 => Self::Failed,
            13 => Self::GssCredProblem,
            14 => Self::GssCtxProblem,
            v => Self::Other(v),
        }
    }
}

/// The header of a `CALL` message up to and including the verifier.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CallHeader {
    /// `rm_xid`.
    pub xid: u32,
    /// `cb_prog`.
    pub prog: u32,
    /// `cb_vers`.
    pub vers: u32,
    /// `cb_proc`.
    pub proc_: u32,
    /// `cb_cred`.
    pub cred: OpaqueAuth,
    /// `cb_verf`.
    pub verf: OpaqueAuth,
}

impl CallHeader {
    /// The bytes from `xid` through the credential, which RPCSEC_GSS signs
    /// (`svc_auth_gss.c:svcauth_gss_validate`).
    pub fn signed_part(&self) -> Vec<u8> {
        let mut w = XdrWriter::default();
        w.u32(self.xid);
        w.u32(CALL);
        w.u32(RPC_VERSION);
        w.u32(self.prog);
        w.u32(self.vers);
        w.u32(self.proc_);
        self.cred.write(&mut w);
        w.0
    }

    /// Encode the header; the procedure arguments follow.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = XdrWriter(self.signed_part());
        self.verf.write(&mut w);
        w.0
    }
}

/// A decoded `CALL` message.
#[derive(Clone, Debug)]
pub struct Call {
    /// The header.
    pub header: CallHeader,
    /// The undecoded arguments.
    pub args: Vec<u8>,
}

/// Why a call message could not be decoded.
#[derive(Debug)]
pub enum CallError {
    /// Not decodable at all; MIT drops the record.
    Garbage(XdrError),
    /// A call with the wrong `rpcvers`; answered with `RPC_MISMATCH`.
    RpcMismatch(u32),
}

impl Call {
    /// Decode a record.
    pub fn decode(record: &[u8]) -> Result<Self, CallError> {
        let mut r = XdrReader::new(record);
        let g = CallError::Garbage;
        let xid = r.u32().map_err(g)?;
        if r.u32().map_err(g)? != CALL {
            return Err(CallError::Garbage(XdrError("not a call")));
        }
        if r.u32().map_err(g)? != RPC_VERSION {
            return Err(CallError::RpcMismatch(xid));
        }
        let prog = r.u32().map_err(g)?;
        let vers = r.u32().map_err(g)?;
        let proc_ = r.u32().map_err(g)?;
        let cred = OpaqueAuth::read(&mut r).map_err(g)?;
        let verf = OpaqueAuth::read(&mut r).map_err(g)?;
        Ok(Self {
            header: CallHeader {
                xid,
                prog,
                vers,
                proc_,
                cred,
                verf,
            },
            args: r.rest().to_vec(),
        })
    }
}

/// A `REPLY` message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reply {
    /// `MSG_ACCEPTED`; `results` is set only for `SUCCESS`.
    Accepted {
        /// `ar_verf`.
        verf: OpaqueAuth,
        /// `ar_stat`.
        stat: AcceptStat,
        /// Undecoded results.
        results: Vec<u8>,
    },
    /// `MSG_DENIED`/`RPC_MISMATCH` with the supported versions.
    RpcMismatch(u32, u32),
    /// `MSG_DENIED`/`AUTH_ERROR`.
    AuthError(AuthStat),
}

impl Reply {
    /// Encode as the reply to `xid`.
    pub fn encode(&self, xid: u32) -> Vec<u8> {
        let mut w = XdrWriter::default();
        w.u32(xid);
        w.u32(REPLY);
        match self {
            Self::Accepted {
                verf,
                stat,
                results,
            } => {
                w.u32(MSG_ACCEPTED);
                verf.write(&mut w);
                match stat {
                    AcceptStat::Success => {
                        w.u32(0);
                        w.0.extend_from_slice(results);
                    }
                    AcceptStat::ProgUnavail => w.u32(1),
                    AcceptStat::ProgMismatch(low, high) => {
                        w.u32(2);
                        w.u32(*low);
                        w.u32(*high);
                    }
                    AcceptStat::ProcUnavail => w.u32(3),
                    AcceptStat::GarbageArgs => w.u32(4),
                    AcceptStat::SystemErr => w.u32(5),
                }
            }
            Self::RpcMismatch(low, high) => {
                w.u32(MSG_DENIED);
                w.u32(0);
                w.u32(*low);
                w.u32(*high);
            }
            Self::AuthError(stat) => {
                w.u32(MSG_DENIED);
                w.u32(1);
                w.u32(stat.code());
            }
        }
        w.0
    }

    /// Decode a record, returning the xid and the reply.
    pub fn decode(record: &[u8]) -> Result<(u32, Self), XdrError> {
        let mut r = XdrReader::new(record);
        let xid = r.u32()?;
        if r.u32()? != REPLY {
            return Err(XdrError("not a reply"));
        }
        let reply = match r.u32()? {
            MSG_ACCEPTED => {
                let verf = OpaqueAuth::read(&mut r)?;
                let stat = match r.u32()? {
                    0 => AcceptStat::Success,
                    1 => AcceptStat::ProgUnavail,
                    2 => AcceptStat::ProgMismatch(r.u32()?, r.u32()?),
                    3 => AcceptStat::ProcUnavail,
                    4 => AcceptStat::GarbageArgs,
                    5 => AcceptStat::SystemErr,
                    _ => return Err(XdrError("bad accept_stat")),
                };
                let results = if stat == AcceptStat::Success {
                    r.rest().to_vec()
                } else {
                    Vec::new()
                };
                Self::Accepted {
                    verf,
                    stat,
                    results,
                }
            }
            MSG_DENIED => match r.u32()? {
                0 => Self::RpcMismatch(r.u32()?, r.u32()?),
                1 => Self::AuthError(AuthStat::from_code(r.u32()?)),
                _ => return Err(XdrError("bad reject_stat")),
            },
            _ => return Err(XdrError("bad reply_stat")),
        };
        Ok((xid, reply))
    }
}

/// An RPC failure seen by a caller.
#[derive(Debug)]
pub enum RpcError {
    /// Transport failure.
    Io(std::io::Error),
    /// A message that does not decode.
    Xdr(XdrError),
    /// The server did not accept the call.
    Accept(AcceptStat),
    /// The server rejected the RPC version.
    RpcMismatch(u32, u32),
    /// The server rejected the authentication.
    Auth(AuthStat),
    /// A reply to a different call.
    XidMismatch,
    /// A GSS-API failure, with MIT's major/minor status when the peer sent
    /// one.
    Gss(String),
}

impl fmt::Display for RpcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "RPC: {e}"),
            Self::Xdr(e) => write!(f, "RPC: Can't decode result ({})", e.0),
            Self::Accept(s) => write!(f, "RPC: call not accepted ({s:?})"),
            Self::RpcMismatch(l, h) => write!(f, "RPC: Incompatible versions of RPC ({l}-{h})"),
            Self::Auth(s) => write!(f, "RPC: Authentication error; why = {s:?}"),
            Self::XidMismatch => f.write_str("RPC: reply does not match the call"),
            Self::Gss(e) => write!(f, "RPC: GSS-API failure: {e}"),
        }
    }
}

impl std::error::Error for RpcError {}

impl From<std::io::Error> for RpcError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<XdrError> for RpcError {
    fn from(e: XdrError) -> Self {
        Self::Xdr(e)
    }
}

/// Read one record-marked record (`xdr_rec.c`), refusing more than
/// [`MAX_RECORD`] bytes. `Ok(None)` is a clean end of stream.
pub async fn read_record<S: AsyncRead + Unpin>(
    stream: &mut S,
) -> Result<Option<Vec<u8>>, std::io::Error> {
    let mut record = Vec::new();
    loop {
        let mut mark = [0u8; 4];
        if record.is_empty() {
            if stream.read(&mut mark[..1]).await? == 0 {
                return Ok(None);
            }
            stream.read_exact(&mut mark[1..]).await?;
        } else {
            stream.read_exact(&mut mark).await?;
        }
        let mark = u32::from_be_bytes(mark);
        let len = usize::try_from(mark & !LAST_FRAGMENT)
            .map_err(|_| std::io::Error::other("RPC fragment too large"))?;
        if record.len().saturating_add(len) > MAX_RECORD {
            return Err(std::io::Error::other("RPC record too large"));
        }
        let start = record.len();
        record.resize(start + len, 0);
        stream.read_exact(&mut record[start..]).await?;
        if mark & LAST_FRAGMENT != 0 {
            return Ok(Some(record));
        }
    }
}

/// Write `record` as a single last fragment.
pub async fn write_record<S: AsyncWrite + Unpin>(
    stream: &mut S,
    record: &[u8],
) -> Result<(), std::io::Error> {
    let len = u32::try_from(record.len())
        .ok()
        .filter(|l| l & LAST_FRAGMENT == 0 && record.len() <= MAX_RECORD)
        .ok_or_else(|| std::io::Error::other("RPC record too large"))?;
    let mut out = Vec::with_capacity(record.len() + 4);
    out.extend_from_slice(&(len | LAST_FRAGMENT).to_be_bytes());
    out.extend_from_slice(record);
    stream.write_all(&out).await?;
    stream.flush().await
}
