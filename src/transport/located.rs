//! Profile/DNS-located KDC transport (`krb5int_sendtokdc` layering):
//! locate KDCs for the realm, send via [`sendto_kdc`], record which KDC
//! was used, and perform the RESPONSE_TOO_BIG no-UDP retry
//! (get_in_tkt.c:566-580).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::locate::{DnsResolver, Locator, ServerEntry, Transport};
use crate::profile::Profile;
use crate::transport::sendto::{self, SendtoConfig};
use crate::transport::KdcTransport;
use crate::types::error_codes;
use crate::types::KrbErrorMsg;
use crate::Krb5Error;

struct Inner {
    profile: Arc<Profile>,
    dns: Option<Arc<dyn DnsResolver + Send + Sync>>,
    cfg: SendtoConfig,
    use_primary: AtomicBool,
    kdcs: Mutex<Vec<(String, ServerEntry)>>,
}

/// KDC transport that locates servers from the profile/DNS for each realm
/// and sends via MIT `k5_sendto_kdc` semantics.
///
/// Cheaply cloneable (shares the recorded KDC list).
#[derive(Clone)]
pub struct LocatedTransport {
    inner: Arc<Inner>,
}

impl LocatedTransport {
    /// Build a transport whose sendto config is taken from the profile:
    /// `[libdefaults] udp_preference_limit` (clamped per
    /// sendto_kdc.c:474-489) and `request_timeout` (deltat seconds,
    /// init_ctx.c:254-262).
    pub fn new(
        profile: Arc<Profile>,
        dns: Option<Arc<dyn DnsResolver + Send + Sync>>,
    ) -> LocatedTransport {
        let limit = sendto::udp_pref_limit(
            profile
                .get_integer(&["libdefaults", "udp_preference_limit"], -1)
                .ok(),
        );
        let request_timeout = profile
            .get_deltat(&["libdefaults", "request_timeout"], 0)
            .ok()
            .filter(|&v| v > 0)
            .map(|v| Duration::from_secs(v as u64));
        let cfg = SendtoConfig {
            udp_preference_limit: limit,
            request_timeout,
            ..SendtoConfig::default()
        };
        Self::with_config(profile, dns, cfg)
    }

    /// Build with an explicit sendto config (tests / custom timing).
    pub fn with_config(
        profile: Arc<Profile>,
        dns: Option<Arc<dyn DnsResolver + Send + Sync>>,
        cfg: SendtoConfig,
    ) -> LocatedTransport {
        LocatedTransport {
            inner: Arc::new(Inner {
                profile,
                dns,
                cfg,
                use_primary: AtomicBool::new(false),
                kdcs: Mutex::new(Vec::new()),
            }),
        }
    }

    /// Select primary KDCs only (k5_locate_kdc `get_primaries`), used by
    /// the "retry with primary KDC" rule.
    pub fn set_use_primary(&self, v: bool) {
        self.inner.use_primary.store(v, Ordering::SeqCst);
    }

    /// Whether primary-only location is in effect.
    pub fn use_primary(&self) -> bool {
        self.inner.use_primary.load(Ordering::SeqCst)
    }

    /// `(realm, entry)` for each KDC that produced a reply, in order.
    pub fn kdcs_used(&self) -> Vec<(String, ServerEntry)> {
        self.inner.kdcs.lock().expect("kdcs mutex").clone()
    }

    /// Clear the recorded KDC list.
    pub fn clear_kdcs(&self) {
        self.inner.kdcs.lock().expect("kdcs mutex").clear();
    }

    /// Test helper: record a used KDC without contacting it.
    pub fn record_for_test(&self, realm: &str, entry: ServerEntry) {
        self.inner
            .kdcs
            .lock()
            .expect("kdcs mutex")
            .push((realm.to_string(), entry));
    }

    /// `kdclist_any_replicas` (locate_kdc.c:935-1012): true if any recorded
    /// KDC is a replica — i.e., the realm has a primary list and the entry
    /// is not on it.  Entries already known primary are skipped; all
    /// same-realm+transport entries are marked in one pass.
    pub fn any_replicas(&self) -> bool {
        let mut kdcs = self.inner.kdcs.lock().expect("kdcs mutex");
        for pos in 0..kdcs.len() {
            if kdcs[pos].1.primary == Some(true) {
                continue;
            }
            let (realm, transport) = (kdcs[pos].0.clone(), kdcs[pos].1.transport);
            let locator = Locator::new(self.inner.profile.as_ref(), self.dns_ref());
            let primaries = locator
                .locate_kdc(&realm, true, transport == Transport::Tcp)
                .unwrap_or_default();
            if primaries.is_empty() {
                // No primary list: every entry is considered primary.
                for (_, e) in kdcs.iter_mut() {
                    e.primary = Some(true);
                }
                return false;
            }
            let mut replica = false;
            for (_, e) in kdcs.iter_mut() {
                if e.transport != transport {
                    continue;
                }
                let is_primary = primaries
                    .iter()
                    .any(|p| p.hostname == e.hostname && p.port == e.port);
                e.primary = Some(is_primary);
                if !is_primary {
                    replica = true;
                }
            }
            if replica {
                return true;
            }
        }
        false
    }

    fn dns_ref(&self) -> Option<&dyn DnsResolver> {
        self.inner.dns.as_deref().map(|d| d as &dyn DnsResolver)
    }

    /// Locate KDCs for `realm` and send `message` once (no retry).
    async fn exchange(
        &self,
        realm: &str,
        message: &[u8],
        no_udp: bool,
    ) -> Result<Vec<u8>, Krb5Error> {
        let servers = {
            let locator = Locator::new(self.inner.profile.as_ref(), self.dns_ref());
            locator.locate_kdc(realm, self.use_primary(), no_udp)?
        };
        let mut last: Option<(usize, Transport)> = None;
        let result =
            sendto::sendto_kdc_track(&servers, message, no_udp, &self.inner.cfg, Some(&mut last))
                .await;
        // Record the last server that produced a reply, accepted or not
        // (MIT kdclist_add runs when a response is received).
        if let Some((idx, t)) = last {
            if let Some(entry) = servers.get(idx) {
                let mut e = entry.clone();
                e.transport = t;
                self.inner
                    .kdcs
                    .lock()
                    .expect("kdcs mutex")
                    .push((realm.to_string(), e));
            }
        }
        Ok(result?.data)
    }
}

impl KdcTransport for LocatedTransport {
    async fn send_recv(&self, realm: &str, message: &[u8]) -> Result<Vec<u8>, Krb5Error> {
        let reply = self.exchange(realm, message, false).await?;
        // get_in_tkt.c:566-580 / get_creds.c:1210-1235: a KRB-ERROR 52
        // (KRB_ERR_RESPONSE_TOO_BIG) over UDP is retried once with UDP
        // disabled.
        if let Ok(err) = rasn::der::decode::<KrbErrorMsg>(&reply) {
            if err.msg_type == 30 && err.error_code == error_codes::KRB_ERR_RESPONSE_TOO_BIG {
                return self.exchange(realm, message, true).await;
            }
        }
        Ok(reply)
    }
}
