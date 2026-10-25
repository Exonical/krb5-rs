//! RPCSEC_GSS (RFC 2203) over the krb5 GSS-API mechanism, following MIT's
//! `src/lib/rpc/auth_gss.c`, `svc_auth_gss.c` and `authgss_prot.c`.

use tokio::io::{AsyncRead, AsyncWrite};

use super::xdr::{XdrError, XdrReader, XdrWriter};
use super::{
    read_record, write_record, AcceptStat, AuthStat, Call, CallHeader, OpaqueAuth, Reply, RpcError,
    MAX_AUTH_BYTES, RPCSEC_GSS,
};
use crate::gssapi::krb5::{AcceptStep, InitStep, Krb5Acceptor, Krb5Context, Krb5Initiator};

/// `RPCSEC_GSS_VERSION`.
pub const RPCSEC_GSS_VERSION: u32 = 1;
/// `MAXSEQ`.
pub const MAXSEQ: u32 = 0x8000_0000;
/// The sequence window MIT's server grants (`sizeof(gd->seqmask) * 8`).
pub const SEQ_WINDOW: u32 = 32;
/// The context handle MIT's server hands out (`svc_auth_gss.c`).
pub const SERVER_HANDLE: &[u8] = b"xxxx";

/// `rpc_gss_proc_t`.
pub mod proc_ {
    /// `RPCSEC_GSS_DATA`.
    pub const DATA: u32 = 0;
    /// `RPCSEC_GSS_INIT`.
    pub const INIT: u32 = 1;
    /// `RPCSEC_GSS_CONTINUE_INIT`.
    pub const CONTINUE_INIT: u32 = 2;
    /// `RPCSEC_GSS_DESTROY`.
    pub const DESTROY: u32 = 3;
}

/// `rpc_gss_svc_t`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Service {
    /// `RPCSEC_GSS_SVC_NONE`.
    None = 1,
    /// `RPCSEC_GSS_SVC_INTEGRITY`.
    Integrity = 2,
    /// `RPCSEC_GSS_SVC_PRIVACY`.
    Privacy = 3,
}

impl Service {
    fn from_code(v: u32) -> Option<Self> {
        match v {
            1 => Some(Self::None),
            2 => Some(Self::Integrity),
            3 => Some(Self::Privacy),
            _ => None,
        }
    }
}

/// `rpc_gss_cred_t`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Cred {
    /// `gc_v`.
    pub version: u32,
    /// `gc_proc`.
    pub proc_: u32,
    /// `gc_seq`.
    pub seq: u32,
    /// `gc_svc`.
    pub service: u32,
    /// `gc_ctx`.
    pub handle: Vec<u8>,
}

impl Cred {
    /// Encode as an `opaque_auth` body.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = XdrWriter::default();
        w.u32(self.version);
        w.u32(self.proc_);
        w.u32(self.seq);
        w.u32(self.service);
        w.opaque(&self.handle);
        w.0
    }

    /// Decode an `opaque_auth` body.
    pub fn decode(body: &[u8]) -> Result<Self, XdrError> {
        let mut r = XdrReader::new(body);
        Ok(Self {
            version: r.u32()?,
            proc_: r.u32()?,
            seq: r.u32()?,
            service: r.u32()?,
            handle: r.opaque_max(MAX_AUTH_BYTES)?.to_vec(),
        })
    }
}

/// `rpc_gss_init_res`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct InitRes {
    /// `gr_ctx`.
    pub handle: Vec<u8>,
    /// `gr_major`.
    pub major: u32,
    /// `gr_minor`.
    pub minor: u32,
    /// `gr_win`.
    pub window: u32,
    /// `gr_token`.
    pub token: Vec<u8>,
}

/// `GSS_S_CONTINUE_NEEDED`.
pub const GSS_S_CONTINUE_NEEDED: u32 = 1;
/// `GSS_S_FAILURE`.
pub const GSS_S_FAILURE: u32 = 0x000d_0000;

impl InitRes {
    /// Encode.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = XdrWriter::default();
        w.opaque(&self.handle);
        w.u32(self.major);
        w.u32(self.minor);
        w.u32(self.window);
        w.opaque(&self.token);
        w.0
    }

    /// Decode.
    pub fn decode(body: &[u8]) -> Result<Self, XdrError> {
        let mut r = XdrReader::new(body);
        Ok(Self {
            handle: r.opaque()?.to_vec(),
            major: r.u32()?,
            minor: r.u32()?,
            window: r.u32()?,
            token: r.opaque()?.to_vec(),
        })
    }
}

fn gss(e: crate::Krb5Error) -> RpcError {
    RpcError::Gss(e.to_string())
}

/// `xdr_rpc_gss_wrap_data`: protect `seq` and the encoded arguments.
pub fn wrap_body(
    ctx: &mut Krb5Context,
    service: Service,
    seq: u32,
    body: &[u8],
) -> Result<Vec<u8>, RpcError> {
    let mut data = XdrWriter::default();
    data.u32(seq);
    data.0.extend_from_slice(body);
    let mut w = XdrWriter::default();
    match service {
        Service::None => return Ok(body.to_vec()),
        Service::Integrity => {
            let mic = ctx.get_mic(&data.0).map_err(gss)?;
            w.opaque(&data.0);
            w.opaque(&mic);
        }
        Service::Privacy => w.opaque(&ctx.wrap(true, &data.0).map_err(gss)?),
    }
    Ok(w.0)
}

/// `xdr_rpc_gss_unwrap_data`: check and strip the protection and `seq`.
pub fn unwrap_body(
    ctx: &mut Krb5Context,
    service: Service,
    seq: u32,
    body: &[u8],
) -> Result<Vec<u8>, RpcError> {
    let mut r = XdrReader::new(body);
    let data = match service {
        Service::None => return Ok(body.to_vec()),
        Service::Integrity => {
            let data = r.opaque()?.to_vec();
            let mic = r.opaque()?;
            ctx.verify_mic(&data, mic).map_err(gss)?;
            data
        }
        Service::Privacy => {
            let u = ctx.unwrap(r.opaque()?).map_err(gss)?;
            if !u.conf {
                return Err(RpcError::Gss("unwrapped data was not encrypted".into()));
            }
            u.data
        }
    };
    let mut d = XdrReader::new(&data);
    if d.u32()? != seq {
        return Err(RpcError::Gss("sequence number mismatch".into()));
    }
    Ok(d.rest().to_vec())
}

fn gss_verf(body: Vec<u8>) -> OpaqueAuth {
    OpaqueAuth {
        flavor: RPCSEC_GSS,
        body,
    }
}

/// An RPCSEC_GSS client on one connection (`authgss_create`).
pub struct GssClient<S> {
    stream: S,
    prog: u32,
    vers: u32,
    xid: u32,
    ctx: Krb5Context,
    handle: Vec<u8>,
    seq: u32,
    service: Service,
}

impl<S: AsyncRead + AsyncWrite + Unpin> GssClient<S> {
    async fn exchange(
        stream: &mut S,
        header: &CallHeader,
        args: &[u8],
    ) -> Result<(OpaqueAuth, Vec<u8>), RpcError> {
        let mut msg = header.encode();
        msg.extend_from_slice(args);
        write_record(stream, &msg).await?;
        let record = read_record(stream)
            .await?
            .ok_or_else(|| RpcError::Io(std::io::ErrorKind::UnexpectedEof.into()))?;
        let (xid, reply) = Reply::decode(&record)?;
        if xid != header.xid {
            return Err(RpcError::XidMismatch);
        }
        match reply {
            Reply::Accepted {
                verf,
                stat: AcceptStat::Success,
                results,
            } => Ok((verf, results)),
            Reply::Accepted { stat, .. } => Err(RpcError::Accept(stat)),
            Reply::RpcMismatch(l, h) => Err(RpcError::RpcMismatch(l, h)),
            Reply::AuthError(s) => Err(RpcError::Auth(s)),
        }
    }

    /// Establish the context (`authgss_refresh`), with `xid` as the first
    /// transaction id.
    pub async fn connect(
        mut stream: S,
        prog: u32,
        vers: u32,
        xid: u32,
        mut initiator: Krb5Initiator,
        service: Service,
    ) -> Result<Self, RpcError> {
        let mut xid = xid;
        let mut handle = Vec::new();
        let mut gc_proc = proc_::INIT;
        let mut input: Option<Vec<u8>> = None;
        loop {
            let token = match initiator.step(input.as_deref()).map_err(gss)? {
                InitStep::Continue(t) => (t, false),
                InitStep::Complete(t) => (t.unwrap_or_default(), true),
            };
            let (token, complete) = token;
            if token.is_empty() && complete {
                return Err(RpcError::Gss("context completed without a reply".into()));
            }
            let cred = Cred {
                version: RPCSEC_GSS_VERSION,
                proc_: gc_proc,
                seq: 0,
                service: service as u32,
                handle: handle.clone(),
            };
            let header = CallHeader {
                xid,
                prog,
                vers,
                proc_: 0,
                cred: gss_verf(cred.encode()),
                verf: OpaqueAuth::none(),
            };
            xid = xid.wrapping_add(1);
            let mut args = XdrWriter::default();
            args.opaque(&token);
            let (verf, results) = Self::exchange(&mut stream, &header, &args.0).await?;
            let res = InitRes::decode(&results)?;
            if res.major != 0 && res.major != GSS_S_CONTINUE_NEEDED {
                return Err(RpcError::Gss(format!(
                    "server major {:#x} minor {}",
                    res.major, res.minor
                )));
            }
            if !res.handle.is_empty() {
                handle = res.handle.clone();
            }
            gc_proc = proc_::CONTINUE_INIT;
            if res.major == 0 {
                if !complete {
                    match initiator.step(Some(&res.token)).map_err(gss)? {
                        InitStep::Complete(None) => {}
                        InitStep::Complete(Some(t)) if t.is_empty() => {}
                        _ => return Err(RpcError::Gss("context not complete".into())),
                    }
                }
                let mut ctx = initiator.context().map_err(gss)?;
                ctx.verify_mic(&res.window.to_be_bytes(), &verf.body)
                    .map_err(gss)?;
                return Ok(Self {
                    stream,
                    prog,
                    vers,
                    xid,
                    ctx,
                    handle,
                    seq: 0,
                    service,
                });
            }
            input = Some(res.token);
        }
    }

    /// The established context.
    pub fn context(&self) -> &Krb5Context {
        &self.ctx
    }

    /// Call `proc_` with encoded `args`, returning the encoded results.
    pub async fn call(&mut self, proc_: u32, args: &[u8]) -> Result<Vec<u8>, RpcError> {
        self.seq = self.seq.wrapping_add(1);
        let (_, results) = self.send(proc_::DATA, proc_, args).await?;
        unwrap_body(&mut self.ctx, self.service, self.seq, &results)
    }

    async fn send(
        &mut self,
        gc_proc: u32,
        proc_: u32,
        args: &[u8],
    ) -> Result<(OpaqueAuth, Vec<u8>), RpcError> {
        let cred = Cred {
            version: RPCSEC_GSS_VERSION,
            proc_: gc_proc,
            seq: self.seq,
            service: self.service as u32,
            handle: self.handle.clone(),
        };
        let mut header = CallHeader {
            xid: self.xid,
            prog: self.prog,
            vers: self.vers,
            proc_,
            cred: gss_verf(cred.encode()),
            verf: OpaqueAuth::none(),
        };
        self.xid = self.xid.wrapping_add(1);
        header.verf = gss_verf(self.ctx.get_mic(&header.signed_part()).map_err(gss)?);
        let body = if gc_proc == proc_::DATA {
            wrap_body(&mut self.ctx, self.service, self.seq, args)?
        } else {
            Vec::new()
        };
        let (verf, results) = Self::exchange(&mut self.stream, &header, &body).await?;
        self.ctx
            .verify_mic(&self.seq.to_be_bytes(), &verf.body)
            .map_err(|_| RpcError::Auth(AuthStat::InvalidResp))?;
        Ok((verf, results))
    }

    /// `authgss_destroy_context`: tell the server to drop the context.
    pub async fn destroy(mut self) -> Result<(), RpcError> {
        self.seq = self.seq.wrapping_add(1);
        self.send(proc_::DESTROY, 0, &[]).await.map(|_| ())
    }
}

/// What the server should do with a call.
pub enum ServerStep {
    /// Send this reply record; nothing to dispatch.
    Send(Vec<u8>),
    /// Run the procedure on `args`, then answer with [`GssServer::reply`].
    Dispatch {
        /// `cb_proc`.
        proc_: u32,
        /// The unprotected arguments.
        args: Vec<u8>,
        /// The sequence number to answer with.
        seq: u32,
    },
}

struct Established {
    ctx: Krb5Context,
    service: Service,
    seqlast: u32,
    seqmask: u32,
}

/// The server side of RPCSEC_GSS on one connection (`gssrpc__svcauth_gss`).
pub struct GssServer {
    acceptor: Box<dyn Fn() -> Krb5Acceptor + Send + Sync>,
    pending: Option<Krb5Acceptor>,
    est: Option<Established>,
}

fn auth_error(xid: u32, stat: AuthStat) -> ServerStep {
    ServerStep::Send(Reply::AuthError(stat).encode(xid))
}

impl GssServer {
    /// A connection whose contexts are accepted by acceptors from
    /// `acceptor`.
    pub fn new(acceptor: Box<dyn Fn() -> Krb5Acceptor + Send + Sync>) -> Self {
        Self {
            acceptor,
            pending: None,
            est: None,
        }
    }

    /// The established context, if any.
    pub fn context(&self) -> Option<&Krb5Context> {
        self.est.as_ref().map(|e| &e.ctx)
    }

    /// Authenticate `call`.
    pub fn handle(&mut self, call: &Call) -> ServerStep {
        let h = &call.header;
        if h.cred.flavor != RPCSEC_GSS || h.cred.body.is_empty() {
            return auth_error(h.xid, AuthStat::BadCred);
        }
        let Ok(gc) = Cred::decode(&h.cred.body) else {
            return auth_error(h.xid, AuthStat::BadCred);
        };
        let Some(service) = Service::from_code(gc.service) else {
            return auth_error(h.xid, AuthStat::BadCred);
        };
        if gc.version != RPCSEC_GSS_VERSION {
            return auth_error(h.xid, AuthStat::BadCred);
        }
        if let Some(est) = &mut self.est {
            if gc.seq > MAXSEQ {
                return auth_error(h.xid, AuthStat::GssCtxProblem);
            }
            if gc.seq > est.seqlast {
                let shift = gc.seq - est.seqlast;
                est.seqmask = est.seqmask.checked_shl(shift).unwrap_or(0) | 1;
                est.seqlast = gc.seq;
            } else {
                let offset = est.seqlast - gc.seq;
                if offset >= SEQ_WINDOW || est.seqmask & (1 << offset) != 0 {
                    return auth_error(h.xid, AuthStat::GssCtxProblem);
                }
                est.seqmask |= 1 << offset;
            }
        }
        match gc.proc_ {
            proc_::INIT | proc_::CONTINUE_INIT => self.init(call, service),
            proc_::DATA | proc_::DESTROY => {
                let Some(est) = &mut self.est else {
                    return auth_error(h.xid, AuthStat::GssCredProblem);
                };
                if gc.proc_ == proc_::DESTROY && h.proc_ != 0 {
                    return auth_error(h.xid, AuthStat::Failed);
                }
                if est.ctx.verify_mic(&h.signed_part(), &h.verf.body).is_err() {
                    return auth_error(h.xid, AuthStat::GssCredProblem);
                }
                if gc.proc_ == proc_::DESTROY {
                    let out = self.reply(h.xid, gc.seq, &[]);
                    self.est = None;
                    return match out {
                        Ok(r) => ServerStep::Send(r),
                        Err(_) => auth_error(h.xid, AuthStat::Failed),
                    };
                }
                match unwrap_body(&mut est.ctx, est.service, gc.seq, &call.args) {
                    Ok(args) => ServerStep::Dispatch {
                        proc_: h.proc_,
                        args,
                        seq: gc.seq,
                    },
                    Err(_) => ServerStep::Send(
                        Reply::Accepted {
                            verf: OpaqueAuth::none(),
                            stat: AcceptStat::GarbageArgs,
                            results: Vec::new(),
                        }
                        .encode(h.xid),
                    ),
                }
            }
            _ => auth_error(h.xid, AuthStat::RejectedCred),
        }
    }

    fn init(&mut self, call: &Call, service: Service) -> ServerStep {
        let xid = call.header.xid;
        if call.header.proc_ != 0 {
            return auth_error(xid, AuthStat::Failed);
        }
        let mut r = XdrReader::new(&call.args);
        let Ok(token) = r.opaque() else {
            return ServerStep::Send(
                Reply::Accepted {
                    verf: OpaqueAuth::none(),
                    stat: AcceptStat::GarbageArgs,
                    results: Vec::new(),
                }
                .encode(xid),
            );
        };
        let mut acceptor = self.pending.take().unwrap_or_else(|| (self.acceptor)());
        let (major, out) = match acceptor.step(token) {
            Ok(AcceptStep::Complete { token }) => (0, token.unwrap_or_default()),
            Ok(AcceptStep::ContinueNeeded(t)) => (GSS_S_CONTINUE_NEEDED, t),
            Err(_) => return auth_error(xid, AuthStat::RejectedCred),
        };
        let res = InitRes {
            handle: SERVER_HANDLE.to_vec(),
            major,
            minor: 0,
            window: SEQ_WINDOW,
            token: out,
        };
        let mut verf = OpaqueAuth::none();
        if major == 0 {
            let Ok(mut ctx) = acceptor.context() else {
                return auth_error(xid, AuthStat::Failed);
            };
            let Ok(mic) = ctx.get_mic(&SEQ_WINDOW.to_be_bytes()) else {
                return auth_error(xid, AuthStat::Failed);
            };
            verf = gss_verf(mic);
            self.est = Some(Established {
                ctx,
                service,
                seqlast: 0,
                seqmask: 0,
            });
        } else {
            self.pending = Some(acceptor);
        }
        ServerStep::Send(
            Reply::Accepted {
                verf,
                stat: AcceptStat::Success,
                results: res.encode(),
            }
            .encode(xid),
        )
    }

    /// The reply record for a dispatched call that failed with `stat`
    /// (`svcerr_noproc`, `svcerr_decode`, ...), with the call's verifier.
    pub fn reply_error(
        &mut self,
        xid: u32,
        seq: u32,
        stat: AcceptStat,
    ) -> Result<Vec<u8>, RpcError> {
        let est = self
            .est
            .as_mut()
            .ok_or_else(|| RpcError::Gss("no context".into()))?;
        let verf = gss_verf(est.ctx.get_mic(&seq.to_be_bytes()).map_err(gss)?);
        Ok(Reply::Accepted {
            verf,
            stat,
            results: Vec::new(),
        }
        .encode(xid))
    }

    /// The reply record for a dispatched call (`svcauth_gss_nextverf` and
    /// `svcauth_gss_wrap`).
    pub fn reply(&mut self, xid: u32, seq: u32, results: &[u8]) -> Result<Vec<u8>, RpcError> {
        let est = self
            .est
            .as_mut()
            .ok_or_else(|| RpcError::Gss("no context".into()))?;
        let verf = gss_verf(est.ctx.get_mic(&seq.to_be_bytes()).map_err(gss)?);
        let results = wrap_body(&mut est.ctx, est.service, seq, results)?;
        Ok(Reply::Accepted {
            verf,
            stat: AcceptStat::Success,
            results,
        }
        .encode(xid))
    }
}
