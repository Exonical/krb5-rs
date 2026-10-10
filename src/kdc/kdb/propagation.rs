//! Primary-to-replica database propagation, protocol `KRB5RS-PROP-1`.
//!
//! The idea is MIT's kprop/kpropd (src/kprop/kprop.c `xmit_database`,
//! :405-520; kpropd.c :1200-1480) reversed into a pull model so replicas can
//! come and go: a replica connects to the primary, authenticates with a
//! Kerberos ticket for the primary's kprop service, asks for the database
//! (naming the serial it already has) and receives the raw database file in
//! KRB-PRIV blocks of 32 KiB (`KPROP_BUFSIZ`) unless it is already current.
//!
//! Wire protocol over one TCP connection; every message is a frame of a
//! 4-byte big-endian length plus bytes (`krb5_write_message`), at most
//! [`MAX_FRAME`] long:
//!
//! 1. client: the version string `KRB5RS-PROP-1`;
//! 2. client: an AP-REQ for the kprop service (mutual authentication, subkey);
//! 3. server: the AP-REP, or a single KRB-ERROR frame and close;
//! 4. client: KRB-SAFE(`PropRequest { realm, have-serial }`);
//! 5. server: KRB-SAFE(`PropReply { status, serial, size, sha256 }`), then for
//!    a full transfer `ceil(size / 32 KiB)` KRB-PRIV(block) frames;
//! 6. client: KRB-SAFE(`PropAck { ok }`).
//!
//! Both sides use DO_TIME + DO_SEQUENCE and the negotiated subkeys. The
//! KRB-SAFE/KRB-PRIV addresses are the fixed constant `0.0.0.0` on both
//! sides: replicas reach the primary through NAT and service addresses, so
//! socket addresses cannot be compared, and the message integrity does not
//! depend on them (it is keyed by the session subkeys).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use chrono::{Timelike, Utc};
use rasn::prelude::*;
use rasn::types::{GeneralString, OctetString};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{lookup_host, TcpListener, TcpStream};
use tokio::sync::{watch, Semaphore};
use tokio::task::JoinSet;

use super::FileStore;
use crate::keytab::{key_for_principal, FileKeytab};
use crate::protocol::ap::{ApReqOptions, AuthContext, AuthContextFlags, KeySource};
use crate::protocol::{
    AsExchange, AsExchangeConfig, Credential, StepResult, TgsExchange, TgsOptions, TgsStepResult,
};
use crate::transport::{KdcTransport, TcpTransport};
use crate::types::error_codes::*;
use crate::types::{EncryptionKey, HostAddress, KrbErrorMsg, PrincipalName};
use crate::Krb5Error;

/// The version string a client opens with.
pub const PROP_VERSION: &str = "KRB5RS-PROP-1";
/// Database block size (MIT `KPROP_BUFSIZ`, kprop.h).
pub const BLOCK_SIZE: usize = 32 * 1024;
/// Largest frame either side accepts: 1 MiB plus message overhead.
pub const MAX_FRAME: usize = 1024 * 1024 + 4096;
/// Largest database a replica accepts.
pub const MAX_DB_SIZE: u64 = 512 * 1024 * 1024;

const STATUS_UP_TO_DATE: u32 = 0;
const STATUS_FULL: u32 = 1;

/// `PropRequest ::= SEQUENCE { realm [0], have-serial [1] OPTIONAL }`.
#[derive(AsnType, Encode, Decode, Debug, Clone)]
struct PropRequest {
    #[rasn(tag(explicit(context, 0)))]
    realm: GeneralString,
    #[rasn(tag(explicit(context, 1)))]
    have_serial: Option<u64>,
}

/// `PropReply ::= SEQUENCE { status [0], serial [1], size [2], sha256 [3] OPTIONAL }`
/// with status 0 = up to date, 1 = full transfer follows.
#[derive(AsnType, Encode, Decode, Debug, Clone)]
struct PropReply {
    #[rasn(tag(explicit(context, 0)))]
    status: u32,
    #[rasn(tag(explicit(context, 1)))]
    serial: u64,
    #[rasn(tag(explicit(context, 2)))]
    size: u64,
    #[rasn(tag(explicit(context, 3)))]
    sha256: Option<OctetString>,
}

/// `PropAck ::= SEQUENCE { ok [0] BOOLEAN }`.
#[derive(AsnType, Encode, Decode, Debug, Clone)]
struct PropAck {
    #[rasn(tag(explicit(context, 0)))]
    ok: bool,
}

/// Why a propagation step failed.
#[derive(Debug, thiserror::Error)]
pub enum PropError {
    /// Socket failure or timeout.
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
    /// Kerberos failure (AS/TGS exchange, AP or SAFE/PRIV processing).
    #[error("kerberos error: {0}")]
    Kerberos(String),
    /// The primary answered with a KRB-ERROR.
    #[error("primary rejected the request: error {code} ({text})")]
    Rejected {
        /// KRB-ERROR error-code.
        code: i32,
        /// KRB-ERROR e-text.
        text: String,
    },
    /// The peer broke the protocol.
    #[error("protocol error: {0}")]
    Protocol(String),
    /// The received database failed validation; the existing one is kept.
    #[error("received database rejected: {0}")]
    Validation(String),
    /// Local database error.
    #[error("database error: {0}")]
    Store(String),
    /// Bad configuration.
    #[error("configuration error: {0}")]
    Config(String),
}

impl From<Krb5Error> for PropError {
    fn from(e: Krb5Error) -> Self {
        PropError::Kerberos(e.to_string())
    }
}

/// What a pull achieved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PullOutcome {
    /// The replica already had the primary's serial.
    UpToDate,
    /// The database was replaced; `serial` is the new serial.
    Updated {
        /// Serial of the database now installed.
        serial: u64,
    },
}

/// Something worth logging.
#[derive(Debug, Clone)]
pub enum PropEvent {
    /// The primary served a replica.
    Served {
        /// Replica address.
        peer: SocketAddr,
        /// Authenticated replica principal.
        client: String,
        /// Serial of the primary's database.
        serial: u64,
        /// Bytes sent (0 when the replica was current).
        bytes: u64,
        /// Whether the replica confirmed a successful install.
        acknowledged: bool,
    },
    /// The primary refused or failed a connection.
    Refused {
        /// Replica address.
        peer: SocketAddr,
        /// Authenticated principal, if authentication got that far.
        client: Option<String>,
        /// Why.
        reason: String,
    },
    /// A replica pull finished.
    Pulled(PullOutcome),
    /// A replica pull failed.
    PullFailed {
        /// The error.
        error: String,
        /// Delay before the next attempt.
        retry_in: Duration,
    },
}

impl std::fmt::Display for PropEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PropEvent::Served {
                peer,
                client,
                serial,
                bytes,
                acknowledged,
            } => write!(
                f,
                "kprop: served {client} at {peer}: serial {serial}, {bytes} bytes, {}",
                if *acknowledged {
                    "acknowledged"
                } else {
                    "not acknowledged"
                }
            ),
            PropEvent::Refused {
                peer,
                client,
                reason,
            } => write!(
                f,
                "kprop: refused {} at {peer}: {reason}",
                client.as_deref().unwrap_or("unauthenticated client")
            ),
            PropEvent::Pulled(PullOutcome::UpToDate) => {
                write!(f, "kprop: database is up to date")
            }
            PropEvent::Pulled(PullOutcome::Updated { serial }) => {
                write!(f, "kprop: installed database serial {serial}")
            }
            PropEvent::PullFailed { error, retry_in } => {
                write!(f, "kprop: pull failed: {error}; retrying in {retry_in:?}")
            }
        }
    }
}

/// Receives [`PropEvent`]s.
pub type PropLogger = Arc<dyn Fn(&PropEvent) + Send + Sync>;

/// Primary-side settings.
#[derive(Clone)]
pub struct PropServerConfig {
    /// The kprop service principal (`kprop/primary`, in the store's realm);
    /// its key must be in the database.
    pub service: PrincipalName,
    /// Principals (`name@REALM`) allowed to pull.
    pub acl: Vec<String>,
    /// Allowed clock skew for authenticators and SAFE/PRIV timestamps.
    pub clockskew: Duration,
    /// Per-message read/write timeout.
    pub io_timeout: Duration,
    /// Concurrent connections served; further ones wait in the accept queue.
    pub max_connections: usize,
    /// Event sink.
    pub logger: Option<PropLogger>,
}

impl PropServerConfig {
    /// Defaults: 300 s skew, 30 s I/O timeout, 8 concurrent connections.
    pub fn new(service: PrincipalName, acl: Vec<String>) -> Self {
        Self {
            service,
            acl,
            clockskew: Duration::from_secs(300),
            io_timeout: Duration::from_secs(30),
            max_connections: 8,
            logger: None,
        }
    }
}

/// How a replica obtains its long-term key.
#[derive(Debug, Clone)]
pub enum PropSecret {
    /// Look the key up in a keytab (`kprop_keytab`).
    Keytab(PathBuf),
    /// First line of a file, run through string-to-key with the default salt
    /// (`kprop_password_file`).
    PasswordFile(PathBuf),
}

/// Replica-side settings.
#[derive(Clone)]
pub struct PropClientConfig {
    /// The realm of the database.
    pub realm: String,
    /// The primary's propagation address (`host:port`).
    pub primary: String,
    /// The primary's KDC address (`host:port`, TCP), used to obtain the
    /// ticket for the kprop service.
    pub kdc: String,
    /// The replica principal (`kprop/replica`).
    pub client: PrincipalName,
    /// The kprop service principal (`kprop/primary`).
    pub service: PrincipalName,
    /// The replica's long-term key.
    pub secret: PropSecret,
    /// The replica's database file.
    pub db_path: PathBuf,
    /// The replica's master key, proving the received database is its own.
    pub master_key: EncryptionKey,
    /// Time between pulls (±10% jitter).
    pub poll_interval: Duration,
    /// Per-message and per-exchange timeout.
    pub io_timeout: Duration,
    /// Event sink.
    pub logger: Option<PropLogger>,
}

fn emit(logger: &Option<PropLogger>, event: PropEvent) {
    if let Some(log) = logger {
        log(&event);
    }
}

// ----------------------------------------------------------------- framing

async fn write_frame(
    stream: &mut TcpStream,
    data: &[u8],
    timeout: Duration,
) -> Result<(), PropError> {
    if data.len() > MAX_FRAME {
        return Err(PropError::Protocol("frame too large".into()));
    }
    let mut out = Vec::with_capacity(4 + data.len());
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    out.extend_from_slice(data);
    tokio::time::timeout(timeout, stream.write_all(&out))
        .await
        .map_err(|_| io_timeout())??;
    Ok(())
}

async fn read_frame(stream: &mut TcpStream, timeout: Duration) -> Result<Vec<u8>, PropError> {
    let mut len = [0u8; 4];
    tokio::time::timeout(timeout, stream.read_exact(&mut len))
        .await
        .map_err(|_| io_timeout())??;
    let len = u32::from_be_bytes(len) as usize;
    if len > MAX_FRAME {
        return Err(PropError::Protocol(format!(
            "frame of {len} bytes is too large"
        )));
    }
    let mut data = vec![0u8; len];
    tokio::time::timeout(timeout, stream.read_exact(&mut data))
        .await
        .map_err(|_| io_timeout())??;
    Ok(data)
}

fn io_timeout() -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::TimedOut, "timed out")
}

// ----------------------------------------------------------- shared helpers

/// The fixed address both sides put in KRB-SAFE/KRB-PRIV messages.
fn constant_address() -> HostAddress {
    HostAddress {
        addr_type: 2,
        address: OctetString::from(vec![0, 0, 0, 0]),
    }
}

fn new_context(clockskew: Duration) -> AuthContext {
    let mut ctx = AuthContext::new();
    ctx.set_flags(
        AuthContextFlags::DO_TIME | AuthContextFlags::DO_SEQUENCE | AuthContextFlags::USE_SUBKEY,
    );
    ctx.set_clockskew(clockskew);
    ctx.set_addrs(Some(constant_address()), Some(constant_address()));
    ctx
}

fn general(s: &str) -> Result<GeneralString, PropError> {
    GeneralString::from_bytes(s.as_bytes())
        .map_err(|_| PropError::Protocol(format!("invalid string {s:?}")))
}

fn der<T: Encode>(value: &T) -> Result<Vec<u8>, PropError> {
    rasn::der::encode(value).map_err(|e| PropError::Protocol(e.to_string()))
}

fn principal_string(name: &PrincipalName, realm: &str) -> String {
    format!("{name}@{realm}")
}

fn kdc_error(code: i32, realm: &str, service: &PrincipalName, text: &str) -> Vec<u8> {
    let now = Utc::now();
    let msg = KrbErrorMsg {
        pvno: 5,
        msg_type: 30,
        ctime: None,
        cusec: None,
        stime: now.with_nanosecond(0).unwrap_or(now).fixed_offset(),
        susec: i32::try_from(now.timestamp_subsec_micros()).unwrap_or(0),
        error_code: code,
        crealm: None,
        cname: None,
        realm: GeneralString::from_bytes(realm.as_bytes()).unwrap_or_default(),
        sname: service.clone(),
        e_text: GeneralString::from_bytes(text.as_bytes()).ok(),
        e_data: None,
    };
    rasn::der::encode(&msg).unwrap_or_default()
}

// ------------------------------------------------------------------ server

/// Looks up the kprop service key in the primary's own database.
struct StoreKeys<'a> {
    store: &'a FileStore,
    service: &'a PrincipalName,
}

impl KeySource for StoreKeys<'_> {
    fn get_key(
        &self,
        server: &PrincipalName,
        realm: &[u8],
        kvno: Option<i32>,
        etype: i32,
    ) -> Result<EncryptionKey, crate::protocol::ap::ApError> {
        use crate::protocol::ap::ApError;
        if server.name_string != self.service.name_string || realm != self.store.realm().as_bytes()
        {
            return Err(ApError::NotUs);
        }
        let entry = self
            .store
            .get_record(self.service, self.store.realm())
            .map_err(|_| ApError::NoKey)?
            .ok_or(ApError::NoKey)?
            .entry;
        let mut etype_seen = false;
        for k in &entry.keys {
            if k.key.keytype != etype {
                continue;
            }
            etype_seen = true;
            if kvno.is_none_or(|v| i64::from(k.kvno) == i64::from(v)) {
                return Ok(k.key.clone());
            }
        }
        Err(if etype_seen {
            ApError::BadKeyver
        } else {
            ApError::NoKey
        })
    }
}

/// Replay cache shared by every connection: an authenticator is accepted
/// once within the clock-skew window.
#[derive(Default)]
struct ReplayCache {
    seen: Mutex<HashMap<(String, i64, i32), Instant>>,
}

impl ReplayCache {
    /// True if the authenticator is new.
    fn check(&self, client: &str, ctime: i64, cusec: i32, window: Duration) -> bool {
        let mut seen = self.seen.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        seen.retain(|_, at| now.duration_since(*at) < window * 2);
        seen.insert((client.to_string(), ctime, cusec), now)
            .is_none()
    }
}

struct ServerState {
    store: Arc<FileStore>,
    config: PropServerConfig,
    replay: ReplayCache,
}

/// Run the propagation server on `listener` until `shutdown` is signalled,
/// then wait for the open connections (callers bound that with a timeout).
/// The kprop service principal must have a key in `store`.
pub async fn serve_propagation(
    store: Arc<FileStore>,
    config: PropServerConfig,
    listener: TcpListener,
    shutdown: Option<watch::Receiver<bool>>,
) -> std::io::Result<()> {
    let state = Arc::new(ServerState {
        store,
        replay: ReplayCache::default(),
        config,
    });
    let permits = Arc::new(Semaphore::new(state.config.max_connections.max(1)));
    let mut shutdown = shutdown;
    let mut tasks = JoinSet::new();
    loop {
        let wait_shutdown = async {
            match shutdown.as_mut() {
                Some(rx) => loop {
                    if *rx.borrow() {
                        return;
                    }
                    if rx.changed().await.is_err() {
                        return std::future::pending().await;
                    }
                },
                None => std::future::pending().await,
            }
        };
        let accepted = tokio::select! {
            r = listener.accept() => r,
            () = wait_shutdown => break,
            Some(_) = tasks.join_next(), if !tasks.is_empty() => continue,
        };
        let (stream, peer) = match accepted {
            Ok(v) => v,
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::ConnectionAborted | std::io::ErrorKind::ConnectionReset
                ) =>
            {
                continue
            }
            Err(e) => return Err(e),
        };
        let Ok(permit) = Arc::clone(&permits).acquire_owned().await else {
            continue;
        };
        let state = Arc::clone(&state);
        tasks.spawn(async move {
            let _permit = permit;
            let result = handle_connection(&state, stream, peer).await;
            if let Err((client, reason)) = result {
                emit(
                    &state.config.logger,
                    PropEvent::Refused {
                        peer,
                        client,
                        reason,
                    },
                );
            }
        });
    }
    drop(listener);
    while tasks.join_next().await.is_some() {}
    Ok(())
}

type Refusal = (Option<String>, String);

async fn handle_connection(
    state: &ServerState,
    mut stream: TcpStream,
    peer: SocketAddr,
) -> Result<(), Refusal> {
    let realm = state.store.realm().to_string();
    let service = &state.config.service;
    let timeout = state.config.io_timeout;
    let skew = state.config.clockskew;
    let refuse = |client: Option<String>, reason: &str| (client, reason.to_string());
    let io = |e: PropError| (None, e.to_string());

    async fn reject(
        stream: &mut TcpStream,
        code: i32,
        realm: &str,
        service: &PrincipalName,
        text: &str,
        timeout: Duration,
    ) {
        let _ = write_frame(stream, &kdc_error(code, realm, service, text), timeout).await;
        let _ = stream.shutdown().await;
    }

    let version = read_frame(&mut stream, timeout).await.map_err(io)?;
    if version != PROP_VERSION.as_bytes() {
        reject(
            &mut stream,
            KRB_AP_ERR_BADVERSION,
            &realm,
            service,
            "BAD_PROTOCOL_VERSION",
            timeout,
        )
        .await;
        return Err(refuse(None, "unsupported protocol version"));
    }

    let ap_req = read_frame(&mut stream, timeout).await.map_err(io)?;
    let mut ctx = new_context(skew);
    let keys = StoreKeys {
        store: &state.store,
        service,
    };
    let auth = match ctx.rd_req(&ap_req, Some(service), &keys) {
        Ok(a) => a,
        Err(e) => {
            let code = match &e {
                Krb5Error::Ap(a) => crate::kdc::error::ap_error_code(*a),
                _ => KRB_ERR_GENERIC,
            };
            reject(
                &mut stream,
                code,
                &realm,
                service,
                "AUTHENTICATION_FAILED",
                timeout,
            )
            .await;
            return Err(refuse(None, &format!("authentication failed: {e}")));
        }
    };
    let client = principal_string(
        &auth.ticket.cname,
        &String::from_utf8_lossy(auth.ticket.crealm.as_bytes()),
    );
    let ctime = auth.authenticator.ctime.timestamp();
    if !state
        .replay
        .check(&client, ctime, auth.authenticator.cusec, skew)
    {
        reject(
            &mut stream,
            KRB_AP_ERR_REPEAT,
            &realm,
            service,
            "REPLAY",
            timeout,
        )
        .await;
        return Err(refuse(Some(client), "replayed authenticator"));
    }
    if !state.config.acl.contains(&client) {
        reject(
            &mut stream,
            KDC_ERR_POLICY,
            &realm,
            service,
            "UNAUTHORIZED",
            timeout,
        )
        .await;
        return Err(refuse(Some(client), "principal is not in kprop_acl"));
    }

    let fail = |client: &str| {
        let client = client.to_string();
        move |e: PropError| (Some(client.clone()), e.to_string())
    };
    let ap_rep = ctx
        .mk_rep()
        .map_err(|e| (Some(client.clone()), e.to_string()))?;
    write_frame(&mut stream, &ap_rep, timeout)
        .await
        .map_err(fail(&client))?;

    let request_safe = read_frame(&mut stream, timeout)
        .await
        .map_err(fail(&client))?;
    let (request, _) = ctx
        .rd_safe(&request_safe)
        .map_err(|e| (Some(client.clone()), format!("bad request message: {e}")))?;
    let request: PropRequest = rasn::der::decode(&request)
        .map_err(|e| (Some(client.clone()), format!("bad request: {e}")))?;
    if request.realm.as_bytes() != realm.as_bytes() {
        reject(
            &mut stream,
            KDC_ERR_WRONG_REALM,
            &realm,
            service,
            "WRONG_REALM",
            timeout,
        )
        .await;
        return Err(refuse(
            Some(client),
            &format!(
                "replica asked for realm {}",
                String::from_utf8_lossy(request.realm.as_bytes())
            ),
        ));
    }

    let (serial, image) = state
        .store
        .snapshot()
        .map_err(|e| (Some(client.clone()), e.to_string()))?;
    let up_to_date = request.have_serial == Some(serial);
    let reply = if up_to_date {
        PropReply {
            status: STATUS_UP_TO_DATE,
            serial,
            size: 0,
            sha256: None,
        }
    } else {
        PropReply {
            status: STATUS_FULL,
            serial,
            size: image.len() as u64,
            sha256: Some(OctetString::from(Sha256::digest(&image).to_vec())),
        }
    };
    let (safe, _) = ctx
        .mk_safe(&der(&reply).map_err(fail(&client))?)
        .map_err(|e| (Some(client.clone()), e.to_string()))?;
    write_frame(&mut stream, &safe, timeout)
        .await
        .map_err(fail(&client))?;
    let mut sent = 0u64;
    if !up_to_date {
        for block in image.chunks(BLOCK_SIZE) {
            let (private, _) = ctx
                .mk_priv(block)
                .map_err(|e| (Some(client.clone()), e.to_string()))?;
            write_frame(&mut stream, &private, timeout)
                .await
                .map_err(fail(&client))?;
            sent += block.len() as u64;
        }
    }

    let acknowledged = match read_frame(&mut stream, timeout).await {
        Ok(frame) => ctx
            .rd_safe(&frame)
            .ok()
            .and_then(|(data, _)| rasn::der::decode::<PropAck>(&data).ok())
            .is_some_and(|a| a.ok),
        Err(_) => false,
    };
    emit(
        &state.config.logger,
        PropEvent::Served {
            peer,
            client,
            serial,
            bytes: sent,
            acknowledged,
        },
    );
    Ok(())
}

// ------------------------------------------------------------------ client

async fn resolve(addr: &str) -> Result<SocketAddr, PropError> {
    lookup_host(addr)
        .await?
        .next()
        .ok_or_else(|| PropError::Config(format!("{addr} does not resolve")))
}

fn secret_key(config: &PropClientConfig) -> Result<Option<EncryptionKey>, PropError> {
    match &config.secret {
        PropSecret::Keytab(path) => {
            key_for_principal(&FileKeytab::new(path), &config.client, &config.realm)
                .map(Some)
                .map_err(|e| PropError::Config(format!("keytab {}: {e}", path.display())))
        }
        PropSecret::PasswordFile(_) => Ok(None),
    }
}

async fn run_as<T: KdcTransport>(
    transport: &T,
    mut exchange: AsExchange,
) -> Result<Credential, PropError> {
    let mut reply = Vec::new();
    for _ in 0..32 {
        match exchange.step(&reply)? {
            StepResult::SendToKdc { data, realm } | StepResult::RetryTcp { data, realm } => {
                reply = transport.send_recv(&realm, &data).await?;
            }
            StepResult::Complete => return Ok(exchange.credential()?.clone()),
        }
    }
    Err(PropError::Protocol("AS exchange did not finish".into()))
}

async fn run_tgs<T: KdcTransport>(
    transport: &T,
    mut exchange: TgsExchange,
) -> Result<Credential, PropError> {
    let mut reply = Vec::new();
    for _ in 0..32 {
        match exchange.step(&reply)? {
            TgsStepResult::SendToKdc { data, realm } | TgsStepResult::RetryTcp { data, realm } => {
                reply = transport.send_recv(&realm, &data).await?;
            }
            TgsStepResult::Complete => return Ok(exchange.credential()?.clone()),
        }
    }
    Err(PropError::Protocol("TGS exchange did not finish".into()))
}

/// Get a ticket for the kprop service from the primary's KDC.
async fn service_ticket(config: &PropClientConfig) -> Result<Credential, PropError> {
    let kdc = TcpTransport::with_timeout(resolve(&config.kdc).await?, config.io_timeout);
    let mut as_config = AsExchangeConfig::new(config.client.clone(), config.realm.clone());
    as_config.request_pac = false;
    let exchange = match (secret_key(config)?, &config.secret) {
        (Some(key), _) => AsExchange::with_key(as_config, key),
        (None, PropSecret::PasswordFile(path)) => {
            let text = std::fs::read_to_string(path)
                .map_err(|e| PropError::Config(format!("{}: {e}", path.display())))?;
            let password = text.lines().next().unwrap_or("").trim_end_matches('\r');
            if password.is_empty() {
                return Err(PropError::Config(format!("{} is empty", path.display())));
            }
            AsExchange::new(as_config, password)
        }
        (None, PropSecret::Keytab(_)) => unreachable!("keytab secrets yield a key"),
    };
    let tgt = run_as(&kdc, exchange).await?;
    run_tgs(
        &kdc,
        TgsExchange::new(tgt, config.service.clone(), TgsOptions::default()),
    )
    .await
}

fn temp_path(config: &PropClientConfig) -> PathBuf {
    let mut s = config.db_path.as_os_str().to_owned();
    s.push(".prop");
    PathBuf::from(s)
}

/// Pull the database from the primary once.
///
/// The received file is written next to the replica database, checked (size,
/// SHA-256, magic and version, realm, and that it opens under the replica's
/// master key) and only then renamed over it; on any failure the existing
/// database is left untouched.
pub async fn pull_once(config: &PropClientConfig) -> Result<PullOutcome, PropError> {
    let timeout = config.io_timeout;
    let cred = service_ticket(config).await?;
    let addr = resolve(&config.primary).await?;
    let mut stream = tokio::time::timeout(timeout, TcpStream::connect(addr))
        .await
        .map_err(|_| io_timeout())??;
    stream.set_nodelay(true)?;

    write_frame(&mut stream, PROP_VERSION.as_bytes(), timeout).await?;
    let mut ctx = new_context(Duration::from_secs(300));
    let ap_req = ctx.mk_req(
        &ApReqOptions {
            mutual_required: true,
            use_subkey: true,
            ..ApReqOptions::default()
        },
        None,
        &cred,
    )?;
    write_frame(&mut stream, &ap_req, timeout).await?;

    let first = read_frame(&mut stream, timeout).await?;
    if first.first() == Some(&0x7E) {
        return Err(match rasn::der::decode::<KrbErrorMsg>(&first) {
            Ok(e) => PropError::Rejected {
                code: e.error_code,
                text: e
                    .e_text
                    .map(|t| String::from_utf8_lossy(t.as_bytes()).to_string())
                    .unwrap_or_default(),
            },
            Err(_) => PropError::Protocol("undecodable KRB-ERROR".into()),
        });
    }
    ctx.rd_rep(&first)
        .map_err(|e| PropError::Kerberos(format!("mutual authentication failed: {e}")))?;

    let have_serial = FileStore::open(&config.db_path, &config.master_key)
        .ok()
        .map(|s| s.serial());
    let request = PropRequest {
        realm: general(&config.realm)?,
        have_serial,
    };
    let (safe, _) = ctx.mk_safe(&der(&request)?)?;
    write_frame(&mut stream, &safe, timeout).await?;

    let reply_frame = read_frame(&mut stream, timeout).await?;
    if reply_frame.first() == Some(&0x7E) {
        return Err(match rasn::der::decode::<KrbErrorMsg>(&reply_frame) {
            Ok(e) => PropError::Rejected {
                code: e.error_code,
                text: e
                    .e_text
                    .map(|t| String::from_utf8_lossy(t.as_bytes()).to_string())
                    .unwrap_or_default(),
            },
            Err(_) => PropError::Protocol("undecodable KRB-ERROR".into()),
        });
    }
    let (reply, _) = ctx.rd_safe(&reply_frame)?;
    let reply: PropReply =
        rasn::der::decode(&reply).map_err(|e| PropError::Protocol(format!("bad reply: {e}")))?;

    let ack = |ok: bool| -> Result<Vec<u8>, PropError> { der(&PropAck { ok }) };
    match reply.status {
        STATUS_UP_TO_DATE => {
            let (safe, _) = ctx.mk_safe(&ack(true)?)?;
            write_frame(&mut stream, &safe, timeout).await?;
            Ok(PullOutcome::UpToDate)
        }
        STATUS_FULL => {
            let installed = receive_database(config, &mut ctx, &mut stream, &reply).await;
            let ok = installed.is_ok();
            let (safe, _) = ctx.mk_safe(&ack(ok)?)?;
            let _ = write_frame(&mut stream, &safe, timeout).await;
            installed.map(|serial| PullOutcome::Updated { serial })
        }
        other => Err(PropError::Protocol(format!("unknown status {other}"))),
    }
}

async fn receive_database(
    config: &PropClientConfig,
    ctx: &mut AuthContext,
    stream: &mut TcpStream,
    reply: &PropReply,
) -> Result<u64, PropError> {
    let timeout = config.io_timeout;
    if reply.size == 0 || reply.size > MAX_DB_SIZE {
        return Err(PropError::Validation(format!(
            "unacceptable database size {}",
            reply.size
        )));
    }
    let expected_sha = reply
        .sha256
        .as_ref()
        .ok_or_else(|| PropError::Validation("no checksum in reply".into()))?
        .to_vec();

    let tmp = temp_path(config);
    let result = async {
        let mut file = crate::fsutil::create_private(&tmp)
            .map_err(|e| PropError::Store(format!("{}: {e}", tmp.display())))?;
        let mut hasher = Sha256::new();
        let mut received = 0u64;
        while received < reply.size {
            let frame = read_frame(stream, timeout).await?;
            let (block, _) = ctx.rd_priv(&frame)?;
            if block.is_empty()
                || block.len() > BLOCK_SIZE
                || received + block.len() as u64 > reply.size
            {
                return Err(PropError::Validation("block size out of range".into()));
            }
            std::io::Write::write_all(&mut file, &block)
                .map_err(|e| PropError::Store(format!("{}: {e}", tmp.display())))?;
            hasher.update(&block);
            received += block.len() as u64;
        }
        file.sync_all()
            .map_err(|e| PropError::Store(format!("{}: {e}", tmp.display())))?;
        drop(file);
        if hasher.finalize().as_slice() != expected_sha.as_slice() {
            return Err(PropError::Validation("checksum mismatch".into()));
        }
        let serial = FileStore::verify_image(&tmp, &config.realm, &config.master_key)
            .map_err(|e| PropError::Validation(e.to_string()))?;
        if serial != reply.serial {
            return Err(PropError::Validation(format!(
                "database serial {serial} does not match announced {}",
                reply.serial
            )));
        }
        std::fs::rename(&tmp, &config.db_path)
            .map_err(|e| PropError::Store(format!("installing database: {e}")))?;
        Ok(serial)
    }
    .await;
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

/// Pull repeatedly until `shutdown` is signalled: every `poll_interval`
/// (±10% jitter) after a success, with exponential backoff (1 s doubling,
/// capped at the poll interval) after a failure. Events go to
/// `config.logger`.
pub async fn run_replica_loop(config: PropClientConfig, mut shutdown: watch::Receiver<bool>) {
    let mut failures = 0u32;
    loop {
        let delay = match pull_once(&config).await {
            Ok(outcome) => {
                failures = 0;
                emit(&config.logger, PropEvent::Pulled(outcome));
                jittered(config.poll_interval)
            }
            Err(e) => {
                let retry_in = backoff(failures, config.poll_interval);
                failures = failures.saturating_add(1);
                emit(
                    &config.logger,
                    PropEvent::PullFailed {
                        error: e.to_string(),
                        retry_in,
                    },
                );
                retry_in
            }
        };
        tokio::select! {
            () = tokio::time::sleep(delay) => {}
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    return;
                }
            }
        }
        if *shutdown.borrow() {
            return;
        }
    }
}

/// Pull until one succeeds, with the same backoff (used before a replica
/// with no database serves anything). Returns `None` if `shutdown` fires.
pub async fn initial_pull(
    config: &PropClientConfig,
    shutdown: &mut watch::Receiver<bool>,
) -> Option<PullOutcome> {
    let mut failures = 0u32;
    loop {
        match pull_once(config).await {
            Ok(outcome) => {
                emit(&config.logger, PropEvent::Pulled(outcome));
                return Some(outcome);
            }
            Err(e) => {
                let retry_in = backoff(failures, config.poll_interval);
                failures = failures.saturating_add(1);
                emit(
                    &config.logger,
                    PropEvent::PullFailed {
                        error: e.to_string(),
                        retry_in,
                    },
                );
                tokio::select! {
                    () = tokio::time::sleep(retry_in) => {}
                    changed = shutdown.changed() => {
                        if changed.is_err() || *shutdown.borrow() {
                            return None;
                        }
                    }
                }
            }
        }
    }
}

/// 1 s, 2 s, 4 s, ... capped at `cap` (at least 1 s).
pub(crate) fn backoff(failures: u32, cap: Duration) -> Duration {
    let cap = cap.max(Duration::from_secs(1));
    Duration::from_secs(1u64 << failures.min(20)).min(cap)
}

/// `interval` ±10%.
pub(crate) fn jittered(interval: Duration) -> Duration {
    let spread = interval.as_secs_f64() * 0.1;
    let offset = (f64::from(rand::random::<u16>()) / f64::from(u16::MAX) * 2.0 - 1.0) * spread;
    Duration::from_secs_f64((interval.as_secs_f64() + offset).max(0.0))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_doubles_and_is_capped_at_the_poll_interval() {
        let cap = Duration::from_secs(10);
        let seq: Vec<u64> = (0..6).map(|n| backoff(n, cap).as_secs()).collect();
        assert_eq!(seq, vec![1, 2, 4, 8, 10, 10]);
        assert_eq!(backoff(0, Duration::ZERO), Duration::from_secs(1));
        assert_eq!(backoff(u32::MAX, cap), cap);
    }

    #[test]
    fn jitter_stays_within_ten_percent() {
        for _ in 0..200 {
            let d = jittered(Duration::from_secs(100)).as_secs_f64();
            assert!((90.0..=110.0).contains(&d), "{d}");
        }
    }

    #[test]
    fn replay_cache_accepts_each_authenticator_once() {
        let cache = ReplayCache::default();
        let w = Duration::from_secs(300);
        assert!(cache.check("a@R", 100, 1, w));
        assert!(!cache.check("a@R", 100, 1, w));
        assert!(cache.check("a@R", 100, 2, w));
        assert!(cache.check("b@R", 100, 1, w));
    }
}
