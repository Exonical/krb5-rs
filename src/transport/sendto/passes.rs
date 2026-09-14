//! Pass structure and timing for `k5_sendto` (sendto_kdc.c:1470-1605).
//!
//! MIT default timing (sendto_kdc.c:78):
//! - pass 1: one second per non-deferred connection, then contact each
//!   deferred connection with a per-server wait after each, then a
//!   two-second tail wait.
//! - passes 2..=max_pass: retransmit every live UDP connection with a
//!   per-server wait after each, then an exponentially growing backoff
//!   (4s, 8s, ...).
//!
//! While any TCP connection is in WRITING/READING state the waits are
//! unbounded (any_tcp_connections, sendto_kdc.c:1389-1403); only
//! `request_timeout` bounds the whole request.

use std::time::{Duration, Instant};

use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver};

use crate::locate::Transport;

use super::conn::{self, ConnEvent, LiveConn, PendingConn};
use super::{KdcReply, SendtoConfig, SendtoError};

/// Run the send/retry loop over the resolved connections.
///
/// `ready` connections are contacted in order during pass 1; `deferred`
/// connections are then started one at a time with a per-server wait
/// after each, before the tail wait (sendto_kdc.c:1560-1580).
pub(super) async fn run(
    ready: Vec<PendingConn>,
    deferred: Vec<PendingConn>,
    message: &[u8],
    cfg: &SendtoConfig,
    accept: &(dyn Fn(&[u8]) -> bool + Sync),
    last_reply: &mut Option<(usize, Transport)>,
) -> Result<KdcReply, SendtoError> {
    let (tx, mut rx) = unbounded_channel();
    let deadline = cfg.request_timeout.map(|d| Instant::now() + d);
    let mut live: Vec<LiveConn> = Vec::new();
    let mut next_id = 0usize;
    let timing = &cfg.timing;

    // Pass 1: contact non-deferred conns in order, waiting per_server
    // after each (sendto_kdc.c:1553-1568).
    for p in ready {
        start_conn(&mut live, &mut next_id, p, message, &tx).await;
        if let Some(r) = wait_window(
            &mut live,
            &mut rx,
            timing.per_server,
            deadline,
            accept,
            last_reply,
        )
        .await
        {
            return Ok(r);
        }
    }
    // Contact each deferred connection with a per-server wait after each,
    // then wait the first-pass tail (sendto_kdc.c:1563-1578).
    for p in deferred {
        start_conn(&mut live, &mut next_id, p, message, &tx).await;
        if let Some(r) = wait_window(
            &mut live,
            &mut rx,
            timing.per_server,
            deadline,
            accept,
            last_reply,
        )
        .await
        {
            return Ok(r);
        }
    }
    if let Some(r) = wait_window(
        &mut live,
        &mut rx,
        timing.first_pass_tail,
        deadline,
        accept,
        last_reply,
    )
    .await
    {
        return Ok(r);
    }

    // Passes 2..=max_pass: retransmit UDP conns (per_server wait after
    // each), then exponential backoff (sendto_kdc.c:1582-1600).
    let mut backoff = timing.initial_backoff;
    for _pass in 2..=timing.max_pass {
        if live.is_empty() {
            break;
        }
        for i in 0..live.len() {
            if live[i].transport == Transport::Udp {
                let id = live[i].id;
                if !conn::retransmit(&live[i], message).await {
                    kill(&mut live, id);
                    continue;
                }
                if let Some(r) = wait_window(
                    &mut live,
                    &mut rx,
                    timing.per_server,
                    deadline,
                    accept,
                    last_reply,
                )
                .await
                {
                    return Ok(r);
                }
            }
        }
        if let Some(r) =
            wait_window(&mut live, &mut rx, backoff, deadline, accept, last_reply).await
        {
            return Ok(r);
        }
        backoff = backoff.saturating_mul(2);
    }

    Err(SendtoError::KdcUnreach)
}

/// Start a pending connection; UDP sends the first datagram immediately.
async fn start_conn(
    live: &mut Vec<LiveConn>,
    next_id: &mut usize,
    p: PendingConn,
    message: &[u8],
    tx: &tokio::sync::mpsc::UnboundedSender<ConnEvent>,
) {
    let id = *next_id;
    *next_id += 1;
    let is_udp = p.transport == Transport::Udp;
    let c = conn::start(id, p, message, tx.clone());
    if is_udp && !conn::retransmit(&c, message).await {
        c.task.abort();
        return;
    }
    live.push(c);
}

/// Kill a connection by id (kill_conn): abort its task and drop it; killed
/// connections are never retried.
fn kill(live: &mut Vec<LiveConn>, id: usize) {
    if let Some(pos) = live.iter().position(|c| c.id == id) {
        live.remove(pos).task.abort();
    }
}

/// Wait for an acceptable reply for up to `dur`, consuming connection
/// events.  Returns the reply on `accept` success; `None` when the window
/// elapses or the request deadline is reached.
async fn wait_window(
    live: &mut Vec<LiveConn>,
    rx: &mut UnboundedReceiver<ConnEvent>,
    dur: Duration,
    deadline: Option<Instant>,
    accept: &(dyn Fn(&[u8]) -> bool + Sync),
    last_reply: &mut Option<(usize, Transport)>,
) -> Option<KdcReply> {
    loop {
        // any_tcp_connections: while a TCP conn is in WRITING/READING
        // (established) the wait is unbounded; only the request deadline
        // applies.  CONNECTING conns do not count (sendto_kdc.c:1389-1403).
        let any_tcp = live
            .iter()
            .any(|c| c.transport == Transport::Tcp && c.established);
        let win = if any_tcp { None } else { Some(dur) };
        let clipped = match (win, deadline) {
            (Some(w), Some(d)) => Some(w.min(d.saturating_duration_since(Instant::now()))),
            (Some(w), None) => Some(w),
            (None, Some(d)) => Some(d.saturating_duration_since(Instant::now())),
            (None, None) => None,
        };
        let ev = match clipped {
            Some(t) if t.is_zero() => return None,
            Some(t) => match tokio::time::timeout(t, rx.recv()).await {
                Ok(Some(e)) => e,
                Ok(None) | Err(_) => return None,
            },
            None => rx.recv().await?,
        };
        match ev {
            ConnEvent::Reply(id, idx, t, data) => {
                // MIT records the responding server on receipt, before the
                // accept verdict (krb5int_sendtokdc kdclist_add).
                *last_reply = Some((idx, t));
                if accept(&data) {
                    return Some(KdcReply {
                        data,
                        server_index: idx,
                        transport: t,
                    });
                }
                // Reply not acceptable: kill the conn, keep waiting.
                kill(live, id);
            }
            ConnEvent::Dead(id) => kill(live, id),
            ConnEvent::Established(id) => {
                if let Some(c) = live.iter_mut().find(|c| c.id == id) {
                    c.established = true;
                }
            }
        }
    }
}
