//! Per-connection tasks for `k5_sendto` (sendto_kdc.c:885-1220).
//!
//! Each resolved address gets its own connection.  UDP connections send
//! (and retransmit) from the main loop; the task only waits for one reply.
//! TCP connections perform connect + framed write + framed read in their
//! task and are never retransmitted.

use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{lookup_host, TcpStream, UdpSocket};
use tokio::sync::mpsc::UnboundedSender;
use tokio::task::JoinHandle;

use crate::locate::{ServerEntry, Transport};
use crate::transport::MAX_KDC_RESPONSE_SIZE;

/// Maximum UDP datagram buffer (sendto_kdc.c uses a 64 KiB buffer).
const MAX_UDP_SIZE: usize = 65535;

/// An event reported by a connection task.
pub(super) enum ConnEvent {
    /// A reply arrived (conn id, server index, actual transport, data).
    Reply(usize, usize, Transport, Vec<u8>),
    /// The connection died and must not be retried (conn id).
    Dead(usize),
    /// A TCP connection reached READING state (connected + request
    /// written).  Only established TCP conns make waits unbounded
    /// (any_tcp_connections counts WRITING/READING, not CONNECTING).
    Established(usize),
}

/// A resolved connection that has not been started yet.
pub(super) struct PendingConn {
    /// Index into the caller's server list.
    pub server_index: usize,
    /// Actual transport this connection will use (Udp or Tcp).
    pub transport: Transport,
    /// Bound+connected UDP socket, for UDP connections.
    pub udp: Option<Arc<UdpSocket>>,
    /// Remote socket address (TCP; also kept for UDP bookkeeping).
    pub addr: ConnAddr,
    /// Server name, port, path and realm, for HTTPS connections.
    #[cfg(feature = "kkdcp")]
    pub https: Option<Arc<super::https::HttpsPeer>>,
}

#[derive(Clone)]
pub(super) enum ConnAddr {
    /// IP socket address.
    Inet(std::net::SocketAddr),
    /// Unix socket path (unix only).
    #[cfg(unix)]
    Unix(std::path::PathBuf),
}

/// `{raddr}` for a connection: socket type and address (trace.c).
pub(super) fn raddr(t: Transport, a: &ConnAddr) -> String {
    match a {
        ConnAddr::Inet(s) => crate::trace::raddr(t != Transport::Udp, s),
        #[cfg(unix)]
        ConnAddr::Unix(p) => format!("stream {}", p.display()),
    }
}

/// A started connection with its running task.
pub(super) struct LiveConn {
    /// Connection id.
    pub id: usize,
    /// Actual transport.
    pub transport: Transport,
    /// UDP socket for retransmission (None for TCP).
    pub udp: Option<Arc<UdpSocket>>,
    /// Remote address, for tracing.
    pub addr: ConnAddr,
    /// Task handle; abort to kill the connection.
    pub task: JoinHandle<()>,
    /// TCP conn has connected and written the request (READING state).
    pub established: bool,
}

/// Split a server entry into (preferred, deferred) transports for a given
/// strategy (resolve_server, sendto_kdc.c:805-882).
fn entry_transports(
    t: Transport,
    no_udp: bool,
    udp_last: bool,
    https: bool,
) -> (Vec<Transport>, Vec<Transport>) {
    match t {
        Transport::Udp => {
            if no_udp {
                (Vec::new(), Vec::new())
            } else if udp_last {
                (Vec::new(), vec![Transport::Udp])
            } else {
                (vec![Transport::Udp], Vec::new())
            }
        }
        Transport::Tcp => {
            if udp_last {
                (vec![Transport::Tcp], Vec::new())
            } else {
                (Vec::new(), vec![Transport::Tcp])
            }
        }
        Transport::TcpOrUdp => {
            if no_udp {
                (vec![Transport::Tcp], Vec::new())
            } else if udp_last {
                (vec![Transport::Tcp], vec![Transport::Udp])
            } else {
                (vec![Transport::Udp], vec![Transport::Tcp])
            }
        }
        // Never deferred (resolve_server); skipped without a target.
        Transport::Https if https => (vec![Transport::Https], Vec::new()),
        Transport::Https => (Vec::new(), Vec::new()),
    }
}

/// Resolve all server entries into pending connections, preserving order
/// (resolve_server + getaddrinfo loop, sendto_kdc.c:805-882).
///
/// Returns `(non_deferred, deferred)`.  `no_udp` and `udp_last` select the
/// strategy's per-entry behavior.
pub(super) async fn resolve(
    servers: &[ServerEntry],
    no_udp: bool,
    udp_last: bool,
    https: Option<Arc<super::HttpsTarget>>,
) -> (Vec<PendingConn>, Vec<PendingConn>) {
    let mut ready = Vec::new();
    let mut deferred = Vec::new();
    for (idx, e) in servers.iter().enumerate() {
        let (now, later) = entry_transports(
            e.transport,
            no_udp,
            udp_last,
            cfg!(feature = "kkdcp") && https.is_some(),
        );
        for (t, is_deferred) in now
            .into_iter()
            .map(|t| (t, false))
            .chain(later.into_iter().map(|t| (t, true)))
        {
            for conn in resolve_one(idx, e, t, https.as_ref()).await {
                if is_deferred {
                    deferred.push(conn);
                } else {
                    ready.push(conn);
                }
            }
        }
    }
    (ready, deferred)
}

/// Resolve one server entry to connections for each of its addresses.
async fn resolve_one(
    idx: usize,
    e: &ServerEntry,
    t: Transport,
    https: Option<&Arc<super::HttpsTarget>>,
) -> Vec<PendingConn> {
    #[cfg(not(feature = "kkdcp"))]
    let _ = https;
    if e.hostname.starts_with('/') && t != Transport::Https {
        return resolve_unix(idx, e, t);
    }
    let addrs = match lookup_host((e.hostname.as_str(), e.port)).await {
        Ok(a) => a,
        Err(_) => return Vec::new(),
    };
    let mut out = Vec::new();
    for addr in addrs {
        match t {
            Transport::Udp => {
                let bind = if addr.is_ipv4() {
                    "0.0.0.0:0"
                } else {
                    "[::]:0"
                };
                let sock = match UdpSocket::bind(bind).await {
                    Ok(s) => s,
                    Err(_) => continue,
                };
                if sock.connect(addr).await.is_err() {
                    continue;
                }
                out.push(PendingConn {
                    server_index: idx,
                    transport: Transport::Udp,
                    udp: Some(Arc::new(sock)),
                    addr: ConnAddr::Inet(addr),
                    #[cfg(feature = "kkdcp")]
                    https: None,
                });
            }
            #[cfg(feature = "kkdcp")]
            Transport::Https => {
                let Some(target) = https else { continue };
                out.push(PendingConn {
                    server_index: idx,
                    transport: Transport::Https,
                    udp: None,
                    addr: ConnAddr::Inet(addr),
                    https: Some(Arc::new(super::https::HttpsPeer {
                        servername: e.hostname.clone(),
                        port: e.port,
                        path: e.uri_path.clone(),
                        target: target.clone(),
                    })),
                });
            }
            _ => out.push(PendingConn {
                server_index: idx,
                transport: Transport::Tcp,
                udp: None,
                addr: ConnAddr::Inet(addr),
                #[cfg(feature = "kkdcp")]
                https: None,
            }),
        }
    }
    out
}

#[cfg(unix)]
fn resolve_unix(idx: usize, e: &ServerEntry, t: Transport) -> Vec<PendingConn> {
    // UNIX-domain sockets carry the TCP framing (sendto_kdc.c).
    if t == Transport::Udp {
        return Vec::new();
    }
    vec![PendingConn {
        server_index: idx,
        transport: Transport::Tcp,
        udp: None,
        addr: ConnAddr::Unix(e.hostname.clone().into()),
        #[cfg(feature = "kkdcp")]
        https: None,
    }]
}

#[cfg(not(unix))]
fn resolve_unix(_idx: usize, _e: &ServerEntry, _t: Transport) -> Vec<PendingConn> {
    // MIT skips UNIX socket paths on Windows (sendto_kdc.c).
    Vec::new()
}

/// Start a pending connection (start_connection/maybe_send).
///
/// `id` identifies the connection in events.  For UDP the caller must have
/// already sent the first datagram via [`retransmit`].
pub(super) fn start(
    id: usize,
    conn: PendingConn,
    message: &[u8],
    tx: UnboundedSender<ConnEvent>,
) -> LiveConn {
    let idx = conn.server_index;
    let task = match conn.transport {
        Transport::Udp => {
            let sock = conn.udp.clone().expect("udp conn has socket");
            tokio::spawn(async move {
                let mut buf = vec![0u8; MAX_UDP_SIZE];
                match sock.recv(&mut buf).await {
                    Ok(n) => {
                        buf.truncate(n);
                        let _ = tx.send(ConnEvent::Reply(id, idx, Transport::Udp, buf));
                    }
                    Err(_) => {
                        let _ = tx.send(ConnEvent::Dead(id));
                    }
                }
            })
        }
        #[cfg(feature = "kkdcp")]
        Transport::Https => {
            let msg = message.to_vec();
            match (conn.addr.clone(), conn.https.clone()) {
                (ConnAddr::Inet(a), Some(peer)) => {
                    tokio::spawn(super::https::https_conn(id, idx, a, peer, msg, tx))
                }
                _ => tokio::spawn(async move {
                    let _ = tx.send(ConnEvent::Dead(id));
                }),
            }
        }
        _ => {
            let msg = message.to_vec();
            tokio::spawn(tcp_conn(id, idx, conn.addr.clone(), msg, tx))
        }
    };
    LiveConn {
        id,
        transport: conn.transport,
        udp: conn.udp,
        addr: conn.addr,
        task,
        established: false,
    }
}

/// Retransmit on a live UDP connection (maybe_send; TCP returns -1 and is
/// never retransmitted).  A send error kills the connection — the caller
/// should treat a false return as "kill this conn".
pub(super) async fn retransmit(conn: &LiveConn, message: &[u8]) -> bool {
    match &conn.udp {
        Some(sock) => sock.send(message).await.is_ok(),
        None => false,
    }
}

/// TCP connection task: connect, write the framed request, read the framed
/// reply (service_tcp_*: 4-byte BE length, 1 MiB cap, EOF kills).
async fn tcp_conn(
    id: usize,
    idx: usize,
    addr: ConnAddr,
    message: Vec<u8>,
    tx: UnboundedSender<ConnEvent>,
) {
    let ra = raddr(Transport::Tcp, &addr);
    crate::k5trace!("Initiating TCP connection to {ra}");
    let fail = |e: std::io::Error| {
        crate::k5trace!("TCP error connecting to {ra}: {}", crate::trace::errno(&e));
        let _ = tx.send(ConnEvent::Dead(id));
    };
    match &addr {
        ConnAddr::Inet(a) => match TcpStream::connect(a).await {
            Ok(s) => {
                crate::k5trace!("Sending TCP request to {ra}");
                tcp_io(id, idx, s, message, tx).await
            }
            Err(e) => fail(e),
        },
        #[cfg(unix)]
        ConnAddr::Unix(p) => match tokio::net::UnixStream::connect(p).await {
            Ok(s) => {
                crate::k5trace!("Sending TCP request to {ra}");
                tcp_io(id, idx, s, message, tx).await
            }
            Err(e) => fail(e),
        },
    }
}

/// Framed write + read over any stream (shared by TCP and UNIX sockets).
async fn tcp_io<S>(
    id: usize,
    idx: usize,
    mut stream: S,
    message: Vec<u8>,
    tx: UnboundedSender<ConnEvent>,
) where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let dead = |tx: &UnboundedSender<ConnEvent>| {
        let _ = tx.send(ConnEvent::Dead(id));
    };
    let len = u32::try_from(message.len()).unwrap_or(u32::MAX);
    if stream.write_all(&len.to_be_bytes()).await.is_err()
        || stream.write_all(&message).await.is_err()
    {
        return dead(&tx);
    }
    // Conn is now in READING state (sendto_kdc.c service_tcp_read).
    let _ = tx.send(ConnEvent::Established(id));
    let mut hdr = [0u8; 4];
    if stream.read_exact(&mut hdr).await.is_err() {
        return dead(&tx);
    }
    let rlen = u32::from_be_bytes(hdr) as usize;
    // MAX_KRB5_MESSAGE_LENGTH: a length over 1 MiB kills the connection.
    if rlen == 0 || rlen > MAX_KDC_RESPONSE_SIZE {
        return dead(&tx);
    }
    let mut buf = vec![0u8; rlen];
    match stream.read_exact(&mut buf).await {
        Ok(_) => {
            let _ = tx.send(ConnEvent::Reply(id, idx, Transport::Tcp, buf));
        }
        Err(_) => dead(&tx),
    }
}
