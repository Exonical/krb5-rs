//! UDP and TCP serving for [`Kdc`] (MIT lib/apputils/net-server.c).
//!
//! The caller binds the sockets; the functions here run until an I/O error
//! on the socket or listener itself.

use std::collections::VecDeque;
use std::io;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::Mutex;
use tokio::task::AbortHandle;

use super::{Kdc, PrincipalStore};
use crate::types::error_codes::KRB_ERR_FIELD_TOOLONG;

/// MIT `MAX_DGRAM_SIZE` (osconf.hin:113): UDP receive buffer size.
const MAX_DGRAM_SIZE: usize = 65536;
/// Per-connection buffer (net-server.c:1278): 1 MiB, of which 4 bytes are
/// the length prefix.
const MAX_TCP_MESSAGE: u32 = 1024 * 1024 - 4;
/// MIT `max_stream_data_connections` (net-server.c:85): beyond this many
/// open stream connections the oldest is closed (:1192-1230).
const MAX_STREAM_CONNECTIONS: usize = 45;

/// Serve UDP requests on `socket` until the socket itself fails
/// (MIT `process_packet`, net-server.c:1130-1190). Replies longer than
/// `max_dgram_reply_size` become KRB_ERR_RESPONSE_TOO_BIG
/// (see [`Kdc::handle_udp`]). Per-datagram send errors are ignored.
pub async fn serve_udp<S: PrincipalStore + 'static>(
    kdc: Arc<Kdc<S>>,
    socket: UdpSocket,
) -> io::Result<()> {
    let mut buf = vec![0u8; MAX_DGRAM_SIZE];
    loop {
        let (n, peer) = match socket.recv_from(&mut buf).await {
            Ok(v) => v,
            // Windows reports ICMP port-unreachable for an earlier reply
            // as a receive error on an unconnected socket.
            Err(e) if e.kind() == io::ErrorKind::ConnectionReset => continue,
            Err(e) => return Err(e),
        };
        let reply = kdc.handle_udp(&buf[..n]);
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
pub async fn serve_tcp<S: PrincipalStore + 'static>(
    kdc: Arc<Kdc<S>>,
    listener: TcpListener,
) -> io::Result<()> {
    let open: Arc<Mutex<VecDeque<(u64, AbortHandle)>>> = Arc::new(Mutex::new(VecDeque::new()));
    let mut next_id: u64 = 0;
    loop {
        let (stream, _) = match listener.accept().await {
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
        let mut guard = open.lock().await;
        let handle = tokio::spawn(async move {
            let _ = serve_connection(&conn_kdc, stream).await;
            registry.lock().await.retain(|(i, _)| *i != id);
        });
        guard.push_back((id, handle.abort_handle()));
        if guard.len() > MAX_STREAM_CONNECTIONS {
            if let Some((_, oldest)) = guard.pop_front() {
                oldest.abort();
            }
        }
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

async fn serve_connection<S: PrincipalStore>(
    kdc: &Kdc<S>,
    mut stream: TcpStream,
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
    write_framed(&mut stream, &kdc.handle(&request)).await
}
