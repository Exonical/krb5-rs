//! UDP and TCP serving for [`Kdc`] (MIT lib/apputils/net-server.c).
//!
//! The caller binds the sockets; the functions here run until an I/O error
//! on the socket or listener itself, or until the optional shutdown signal
//! (a [`tokio::sync::watch`] channel set to `true`) fires.

use std::collections::VecDeque;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{watch, Mutex, Notify};
use tokio::task::AbortHandle;

use super::{Kdc, PrincipalStore, RequestSummary, Transport};
use crate::types::error_codes::KRB_ERR_FIELD_TOOLONG;
use crate::types::{AsReq, TgsReq};

/// MIT `MAX_DGRAM_SIZE` (osconf.hin:113): UDP receive buffer size.
const MAX_DGRAM_SIZE: usize = 65536;
/// Per-connection buffer (net-server.c:1278): 1 MiB, of which 4 bytes are
/// the length prefix.
const MAX_TCP_MESSAGE: u32 = 1024 * 1024 - 4;
/// MIT `max_stream_data_connections` (net-server.c:85): beyond this many
/// open stream connections the oldest is closed (:1192-1230).
const MAX_STREAM_CONNECTIONS: usize = 45;

/// Called with a summary of every request and the peer it came from
/// (MIT `log_as_req` / `log_tgs_req`).
pub type RequestLogger = Arc<dyn Fn(&RequestSummary, SocketAddr) + Send + Sync>;

/// Optional behaviour for [`serve_udp_with`] and [`serve_tcp_with`].
#[derive(Clone, Default)]
pub struct ServeOptions {
    /// Per-request callback.
    pub logger: Option<RequestLogger>,
    /// When the value becomes `true` the server stops accepting; TCP serving
    /// then waits for the connections already open before returning.
    pub shutdown: Option<watch::Receiver<bool>>,
}

/// What [`serve_udp_with`] and [`serve_tcp_with`] hand requests to: one
/// realm's [`Kdc`], or several realms in one process ([`KdcRealms`]).
pub trait KdcService: Send + Sync + 'static {
    /// [`Kdc::handle_summarized_from`].
    fn handle_summarized_from(
        &self,
        request: &[u8],
        transport: Transport,
        peer: Option<SocketAddr>,
    ) -> impl std::future::Future<Output = (Vec<u8>, Option<RequestSummary>)> + Send;

    /// A KRB-ERROR with only `code` set, for transport-level errors.
    fn bare_error(&self, code: i32, now: chrono::DateTime<chrono::Utc>) -> Vec<u8>;
}

impl<S: PrincipalStore + 'static> KdcService for Kdc<S> {
    async fn handle_summarized_from(
        &self,
        request: &[u8],
        transport: Transport,
        peer: Option<SocketAddr>,
    ) -> (Vec<u8>, Option<RequestSummary>) {
        let (reply, summary) = Kdc::handle_summarized_from(self, request, transport, peer).await;
        (reply, Some(summary))
    }

    fn bare_error(&self, code: i32, now: chrono::DateTime<chrono::Utc>) -> Vec<u8> {
        Kdc::bare_error(self, code, now)
    }
}

/// Several realms served by one process, as MIT's `krb5kdc -r A -r B`
/// (`setup_server_realm`, kdc/main.c:117-137): with more than one realm a
/// request goes to the realm named in its body, and a request for a realm
/// not served gets no reply (dispatch.c:154-158, net-server.c
/// `process_packet_response`). With one realm every request goes to it.
pub struct KdcRealms<S: PrincipalStore> {
    realms: Vec<Arc<Kdc<S>>>,
}

impl<S: PrincipalStore + 'static> KdcRealms<S> {
    /// The realms in command-line order. Panics if `realms` is empty.
    pub fn new(realms: Vec<Arc<Kdc<S>>>) -> Self {
        assert!(!realms.is_empty(), "KdcRealms needs at least one realm");
        Self { realms }
    }

    /// The served realms.
    pub fn realms(&self) -> &[Arc<Kdc<S>>] {
        &self.realms
    }

    /// The realm a request is for; `Err(())` for a realm not served. A
    /// request that can't be decoded goes to the first realm, which
    /// answers it as a single-realm KDC would.
    fn pick(&self, request: &[u8]) -> Result<&Kdc<S>, ()> {
        if self.realms.len() == 1 {
            return Ok(&self.realms[0]);
        }
        let realm = match request.first() {
            Some(0x6A) => rasn::der::decode::<AsReq>(request)
                .ok()
                .map(|r| r.0.req_body.realm),
            Some(0x6C) => rasn::der::decode::<TgsReq>(request)
                .ok()
                .map(|r| r.0.req_body.realm),
            _ => None,
        };
        let Some(realm) = realm else {
            return Ok(&self.realms[0]);
        };
        self.realms
            .iter()
            .find(|k| k.config.realm.as_bytes() == realm.as_bytes())
            .map(|k| &**k)
            .ok_or(())
    }
}

impl<S: PrincipalStore + 'static> KdcService for KdcRealms<S> {
    async fn handle_summarized_from(
        &self,
        request: &[u8],
        transport: Transport,
        peer: Option<SocketAddr>,
    ) -> (Vec<u8>, Option<RequestSummary>) {
        match self.pick(request) {
            Ok(kdc) => {
                let (reply, summary) = kdc.handle_summarized_from(request, transport, peer).await;
                (reply, Some(summary))
            }
            // Not processed, so not logged (dispatch.c:154-158).
            Err(()) => (Vec::new(), None),
        }
    }

    fn bare_error(&self, code: i32, now: chrono::DateTime<chrono::Utc>) -> Vec<u8> {
        self.realms[0].bare_error(code, now)
    }
}

/// Resolves once `rx` holds `true`; never resolves without a receiver or if
/// the sender is dropped without signalling.
async fn shutdown_requested(rx: &mut Option<watch::Receiver<bool>>) {
    let Some(rx) = rx else {
        return std::future::pending().await;
    };
    loop {
        if *rx.borrow() {
            return;
        }
        if rx.changed().await.is_err() {
            return std::future::pending().await;
        }
    }
}

/// Serve UDP requests on `socket` until the socket itself fails
/// (MIT `process_packet`, net-server.c:1130-1190). Replies longer than
/// `max_dgram_reply_size` become KRB_ERR_RESPONSE_TOO_BIG
/// (see [`Kdc::handle_udp`]). Per-datagram send errors are ignored.
pub async fn serve_udp<K: KdcService>(kdc: Arc<K>, socket: UdpSocket) -> io::Result<()> {
    serve_udp_with(kdc, socket, ServeOptions::default()).await
}

/// [`serve_udp`] with a request logger and/or shutdown signal.
pub async fn serve_udp_with<K: KdcService>(
    kdc: Arc<K>,
    socket: UdpSocket,
    mut options: ServeOptions,
) -> io::Result<()> {
    let mut buf = vec![0u8; MAX_DGRAM_SIZE];
    loop {
        let received = tokio::select! {
            r = socket.recv_from(&mut buf) => r,
            () = shutdown_requested(&mut options.shutdown) => return Ok(()),
        };
        let (n, peer) = match received {
            Ok(v) => v,
            // Windows reports ICMP port-unreachable for an earlier reply
            // as a receive error on an unconnected socket.
            Err(e) if e.kind() == io::ErrorKind::ConnectionReset => continue,
            Err(e) => return Err(e),
        };
        let (reply, summary) = kdc
            .handle_summarized_from(&buf[..n], Transport::Udp, Some(peer))
            .await;
        if let (Some(log), Some(summary)) = (&options.logger, &summary) {
            log(summary, peer);
        }
        // A dropped repeat or a discarded request gets no reply
        // (net-server.c process_packet_response).
        if summary.as_ref().and_then(|s| s.lookaside) == Some(super::LookasideHit::Dropped)
            || reply.is_empty()
        {
            continue;
        }
        // MIT logs and drops on send failure (net-server.c:1112-1124).
        let _ = socket.send_to(&reply, peer).await;
    }
}

/// Serve TCP requests on `listener` until the listener itself fails.
///
/// Like MIT (net-server.c:1366-1450, 1305-1337) each connection carries one
/// request: a 4-byte big-endian length, the message, then one framed reply
/// and close. A length above the 1 MiB buffer (including any with the high
/// bit set) gets a framed KRB_ERR_FIELD_TOOLONG error and a close
/// (:1391-1413, :1492-1494). At most 45 connections stay open; the oldest
/// is dropped when another arrives (:1282, :1571). There is no idle timeout.
pub async fn serve_tcp<K: KdcService>(kdc: Arc<K>, listener: TcpListener) -> io::Result<()> {
    serve_tcp_with(kdc, listener, ServeOptions::default()).await
}

/// Counts open connections and wakes a waiter when the count reaches zero.
#[derive(Default)]
struct InFlight {
    count: AtomicUsize,
    idle: Notify,
}

struct InFlightGuard(Arc<InFlight>);

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        if self.0.count.fetch_sub(1, Ordering::SeqCst) == 1 {
            self.0.idle.notify_waiters();
        }
    }
}

/// [`serve_tcp`] with a request logger and/or shutdown signal. On shutdown
/// the listener stops accepting and this future completes once every open
/// connection has finished; callers that cannot wait forever (a client that
/// never sends its request keeps its connection open) should bound it with a
/// timeout.
pub async fn serve_tcp_with<K: KdcService>(
    kdc: Arc<K>,
    listener: TcpListener,
    mut options: ServeOptions,
) -> io::Result<()> {
    let open: Arc<Mutex<VecDeque<(u64, AbortHandle)>>> = Arc::new(Mutex::new(VecDeque::new()));
    let in_flight = Arc::new(InFlight::default());
    let mut next_id: u64 = 0;
    loop {
        let accepted = tokio::select! {
            r = listener.accept() => r,
            () = shutdown_requested(&mut options.shutdown) => break,
        };
        let (stream, peer) = match accepted {
            Ok(v) => v,
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::ConnectionAborted | io::ErrorKind::ConnectionReset
                ) =>
            {
                continue
            }
            Err(e) => return Err(e),
        };
        let id = next_id;
        next_id += 1;
        let conn_kdc = Arc::clone(&kdc);
        let registry = Arc::clone(&open);
        let logger = options.logger.clone();
        in_flight.count.fetch_add(1, Ordering::SeqCst);
        let guard = InFlightGuard(Arc::clone(&in_flight));
        let mut open_guard = open.lock().await;
        let handle = tokio::spawn(async move {
            let _guard = guard;
            let _ = serve_connection(&*conn_kdc, stream, peer, logger.as_ref()).await;
            registry.lock().await.retain(|(i, _)| *i != id);
        });
        open_guard.push_back((id, handle.abort_handle()));
        if open_guard.len() > MAX_STREAM_CONNECTIONS {
            if let Some((_, oldest)) = open_guard.pop_front() {
                oldest.abort();
            }
        }
    }
    // Stop listening (new connections are refused), then wait for the open
    // ones.
    drop(listener);
    loop {
        let notified = in_flight.idle.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        if in_flight.count.load(Ordering::SeqCst) == 0 {
            return Ok(());
        }
        notified.await;
    }
}

async fn write_framed(stream: &mut TcpStream, reply: &[u8]) -> io::Result<()> {
    let len = u32::try_from(reply.len()).map_err(|_| io::ErrorKind::InvalidData)?;
    let mut out = Vec::with_capacity(4 + reply.len());
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(reply);
    stream.write_all(&out).await?;
    stream.shutdown().await
}

async fn serve_connection<K: KdcService>(
    kdc: &K,
    mut stream: TcpStream,
    peer: SocketAddr,
    logger: Option<&RequestLogger>,
) -> io::Result<()> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf);
    if len > MAX_TCP_MESSAGE {
        let reply = kdc.bare_error(KRB_ERR_FIELD_TOOLONG, chrono::Utc::now());
        return write_framed(&mut stream, &reply).await;
    }
    let mut request = vec![0u8; usize::try_from(len).map_err(|_| io::ErrorKind::InvalidData)?];
    stream.read_exact(&mut request).await?;
    let (reply, summary) = kdc
        .handle_summarized_from(&request, Transport::Tcp, Some(peer))
        .await;
    if let (Some(log), Some(summary)) = (logger, &summary) {
        log(summary, peer);
    }
    // A dropped repeat or a discarded request closes the connection
    // unanswered (net-server.c process_tcp_response).
    if summary.as_ref().and_then(|s| s.lookaside) == Some(super::LookasideHit::Dropped)
        || reply.is_empty()
    {
        return Ok(());
    }
    write_framed(&mut stream, &reply).await
}
