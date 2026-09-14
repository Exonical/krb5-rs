//! `k5_sendto` / `k5_sendto_kdc` (lib/krb5/os/sendto_kdc.c) on tokio.
//!
//! Sends a request to a list of located servers with MIT's pass/timing
//! semantics, transport strategy, and service-unavailable handling.  See
//! `passes` for the pass structure and `conn` for per-connection
//! behavior.

mod conn;
mod passes;

use std::time::Duration;

use crate::locate::{ServerEntry, Transport};
use crate::types::KrbErrorMsg;

/// MIT `MAX_PASS` (sendto_kdc.c): total number of passes.
const MIT_MAX_PASS: u32 = 3;
/// MIT `DEFAULT_UDP_PREF_LIMIT` (sendto_kdc.c:78).
const DEFAULT_UDP_PREF_LIMIT: usize = 1465;
/// MIT `HARD_UDP_LIMIT` (sendto_kdc.c:80).
const HARD_UDP_LIMIT: usize = 32700;

/// Timing knobs for the sendto pass loop (sendto_kdc.c:78, 1553-1600).
#[derive(Debug, Clone)]
pub struct SendtoTiming {
    /// Wait after each individual send/retransmit (`per_server`).
    pub per_server: Duration,
    /// Tail wait at the end of pass 1 (`first_pass_tail`).
    pub first_pass_tail: Duration,
    /// First backoff; doubles each subsequent pass.
    pub initial_backoff: Duration,
    /// Total number of passes (`MAX_PASS` = 3).
    pub max_pass: u32,
}

impl Default for SendtoTiming {
    fn default() -> Self {
        // MIT defaults: 1s per server, 2s first-pass tail, 4s/8s backoffs,
        // 3 passes (sendto_kdc.c:78).
        SendtoTiming {
            per_server: Duration::from_secs(1),
            first_pass_tail: Duration::from_secs(2),
            initial_backoff: Duration::from_secs(4),
            max_pass: MIT_MAX_PASS,
        }
    }
}

/// Configuration for [`sendto`]/[`sendto_kdc`].
#[derive(Debug, Clone)]
pub struct SendtoConfig {
    /// `udp_preference_limit` (already clamped via [`udp_pref_limit`]).
    pub udp_preference_limit: usize,
    /// `request_timeout` — absolute bound on the whole request
    /// (init_ctx.c:254-262, read as a deltat).
    pub request_timeout: Option<Duration>,
    /// Pass timing.
    pub timing: SendtoTiming,
}

impl Default for SendtoConfig {
    fn default() -> Self {
        SendtoConfig {
            udp_preference_limit: DEFAULT_UDP_PREF_LIMIT,
            request_timeout: None,
            timing: SendtoTiming::default(),
        }
    }
}

/// `udp_preference_limit` profile clamping (sendto_kdc.c:474-489):
/// absent or negative -> 1465; above `HARD_UDP_LIMIT` (32700) -> 32700.
pub fn udp_pref_limit(profile_value: Option<i64>) -> usize {
    match profile_value {
        None => DEFAULT_UDP_PREF_LIMIT,
        Some(v) if v < 0 => DEFAULT_UDP_PREF_LIMIT,
        Some(v) if v as u64 > HARD_UDP_LIMIT as u64 => HARD_UDP_LIMIT,
        Some(v) => v as usize,
    }
}

/// Which transports to try in which order (sendto_kdc.c:490-495).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Strategy {
    /// Try UDP before TCP (request fits the UDP preference limit).
    UdpFirst,
    /// Try TCP before UDP (request over the limit, UDP still allowed).
    UdpLast,
    /// TCP only (`no_udp` set, e.g. after KRB_ERR_RESPONSE_TOO_BIG).
    NoUdp,
}

/// Strategy selection (sendto_kdc.c:490-495): `no_udp` forces TCP-only;
/// otherwise the message length against `limit` picks the order.
pub fn strategy_for(message_len: usize, no_udp: bool, limit: usize) -> Strategy {
    if no_udp {
        Strategy::NoUdp
    } else if message_len <= limit {
        Strategy::UdpFirst
    } else {
        Strategy::UdpLast
    }
}

/// Errors from [`sendto`]/[`sendto_kdc`].
#[derive(Debug)]
pub enum SendtoError {
    /// All connections failed or timed out (KRB5_KDC_UNREACH).
    KdcUnreach,
    /// Every contacted KDC reported `KDC_ERR_SVC_UNAVAILABLE` (error 29)
    /// and nothing usable arrived (sendto_kdc.c:536-540).
    SvcUnavailable,
    /// I/O error.
    Io(std::io::Error),
}

impl std::fmt::Display for SendtoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SendtoError::KdcUnreach => write!(f, "cannot contact any KDC"),
            SendtoError::SvcUnavailable => write!(f, "KDC service unavailable"),
            SendtoError::Io(e) => write!(f, "sendto I/O error: {e}"),
        }
    }
}

impl std::error::Error for SendtoError {}

/// A successful KDC reply.
#[derive(Debug)]
pub struct KdcReply {
    /// Raw reply bytes.
    pub data: Vec<u8>,
    /// Index into the `servers` slice of the entry that answered.
    pub server_index: usize,
    /// Actual transport the reply arrived on (Udp or Tcp).
    pub transport: Transport,
}

/// `k5_sendto`: send `message` to the located `servers` per `strategy`.
///
/// `accept` is MIT's `k5_sendto` callback: a reply for which it returns
/// false kills that connection and the walk continues.
pub async fn sendto(
    servers: &[ServerEntry],
    message: &[u8],
    strategy: Strategy,
    cfg: &SendtoConfig,
    accept: &(dyn Fn(&[u8]) -> bool + Sync),
) -> Result<KdcReply, SendtoError> {
    let (no_udp, udp_last) = match strategy {
        Strategy::UdpFirst => (false, false),
        Strategy::UdpLast => (false, true),
        Strategy::NoUdp => (true, false),
    };
    let (ready, deferred) = conn::resolve(servers, no_udp, udp_last).await;
    passes::run(ready, deferred, message, cfg, accept, &mut None).await
}

/// `k5_sendto_kdc` (sendto_kdc.c:446-540): strategy from the message
/// length and `udp_preference_limit`; the accept callback is
/// `check_for_svc_unavailable` — a KRB-ERROR with error code 29
/// (`KDC_ERR_SVC_UNAVAILABLE`) is rejected so the walk continues; if all
/// servers fail after a 29 was seen, returns [`SendtoError::SvcUnavailable`].
pub async fn sendto_kdc(
    servers: &[ServerEntry],
    message: &[u8],
    no_udp: bool,
    cfg: &SendtoConfig,
) -> Result<KdcReply, SendtoError> {
    sendto_kdc_track(servers, message, no_udp, cfg, None).await
}

/// `sendto_kdc` additionally reporting the `(server_index, transport)` of
/// the most recent reply received — including replies the svc-unavailable
/// callback rejected (MIT records `server_used` on receipt).
pub(crate) async fn sendto_kdc_track(
    servers: &[ServerEntry],
    message: &[u8],
    no_udp: bool,
    cfg: &SendtoConfig,
    mut last_reply: Option<&mut Option<(usize, Transport)>>,
) -> Result<KdcReply, SendtoError> {
    let strategy = strategy_for(message.len(), no_udp, cfg.udp_preference_limit);
    let saw_svc_unavail = std::sync::atomic::AtomicBool::new(false);
    let accept = |data: &[u8]| {
        // check_for_svc_unavailable (sendto_kdc.c:396-417): only a decoded
        // KRB-ERROR carrying error 29 is unacceptable.
        if let Ok(err) = rasn::der::decode::<KrbErrorMsg>(data) {
            if err.msg_type == 30
                && err.error_code == crate::types::error_codes::KDC_ERR_SVC_UNAVAILABLE
            {
                saw_svc_unavail.store(true, std::sync::atomic::Ordering::SeqCst);
                return false;
            }
        }
        true
    };
    let (no_udp_s, udp_last) = match strategy {
        Strategy::UdpFirst => (false, false),
        Strategy::UdpLast => (false, true),
        Strategy::NoUdp => (true, false),
    };
    let (ready, deferred) = conn::resolve(servers, no_udp_s, udp_last).await;
    let mut last = None;
    let slot = match last_reply.as_mut() {
        Some(r) => &mut **r,
        None => &mut last,
    };
    match passes::run(ready, deferred, message, cfg, &accept, slot).await {
        Err(SendtoError::KdcUnreach)
            if saw_svc_unavail.load(std::sync::atomic::Ordering::SeqCst) =>
        {
            Err(SendtoError::SvcUnavailable)
        }
        r => r,
    }
}
