//! Kerberos KDC (server side): AS and TGS request processing.
//!
//! Pure request-bytes → reply-bytes logic modelled on MIT krb5 1.22.2
//! `src/kdc` (dispatch.c, do_as_req.c, do_tgs_req.c, kdc_util.c,
//! tgs_policy.c, kdc_preauth.c, kdc_preauth_encts.c). No networking: feed a
//! DER request to [`Kdc::handle`] and send the returned DER reply.
//!
//! One KDC serves one realm. Cross-realm trust (incoming and outgoing
//! `krbtgt/` keys), host-based referrals, alternate cross-realm TGTs and
//! transited-path policy follow MIT (see [`KdcConfig::realm_profile`]). Tickets
//! carry an MS-PAC with client info and signatures, issued, verified and
//! re-signed as MIT's `handle_pac` does (see [`crate::pac`]); there is no
//! logon-information source. No user-to-user, postdating, validation, proxy
//! tickets. Repeated request packets are answered from MIT's lookaside cache
//! (see [`LookasideHit`]). Principal lockout follows MIT's db2 module
//! (see [`lockout`]).
//! FAST (RFC 6113) armor, encrypted challenge and armored replies/errors are
//! handled in the `fast` module.

mod as_req;
mod authdata;
mod cammac;
mod config;
mod cookie;
mod db;
mod error;
mod fast;
mod lookaside;
pub use lookaside::LookasideHit;
pub mod kdb;
pub mod lockout;
mod otp;
mod pkinit;
pub mod plugins;
mod policy;
mod preauth;
pub mod replication;
mod reqbody;
mod s4u;
#[cfg(feature = "tokio")]
mod server;
mod spake;
pub mod store;
mod summary;
mod tgs_req;

use std::future::Future;
#[cfg(feature = "tokio")]
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
#[cfg(feature = "tokio")]
use std::time::Instant;

use crate::profile::Profile;

use chrono::{DateTime, Utc};

#[cfg(feature = "tokio")]
pub use otp::TokenType as OtpTokenType;
pub use server::{
    serve_tcp, serve_tcp_with, serve_udp, serve_udp_with, RequestLogger, ServeOptions,
};

pub use summary::{Outcome, RequestKind, RequestSummary, Transport};

pub use config::{
    default_realm, otp_config_error, parse_listen_addresses, ConfigError, DbModuleConfig,
    IpropConfig, RealmConfig,
};
pub use db::{
    keys_from_password, random_keys, salt_bytes, KeyEntry, MemoryStore, PrincipalAttributes,
    PrincipalEntry,
};
pub use policy::kerberos_time;
pub use store::{
    AdminStore, AlwaysAllow, AuthState, AuthStateStore, AuthStateUpdate, AuthoritativeDenial,
    AuthoritativeState, ConsistencyGate, GateDecision, GateSubject, HealthCheck, LockoutReport,
    LockoutReporter, MemoryAuthState, NoPolicies, NoopLockoutReporter, Policy, PolicyStore,
    PolicyTlData, PrincipalRecord, PrincipalRole, PrincipalStore, SecurityState, SharedAuthState,
    StoreError, StoreErrorKind,
};

use std::sync::Arc;

use store::{DynAuthState, DynGate, DynPolicies};

use db::KvnoSel;
use error::{build_krb_error, krbtgt_name, ErrorContext, Failure, KdcError};
use policy::{secs, RealmLimits};

use crate::crypto::find_etype;
use crate::crypto::util::generate_random;
use crate::types::error_codes::*;
use crate::types::{
    ApReq, AsRep, AsReq, EncryptionKey, KdcOptions, KdcReq, PrincipalName, TgsRep, TgsReq, Ticket,
};

#[cfg(feature = "tokio")]
tokio::task_local! {
    static STORE_TIME_NANOS: std::sync::Arc<AtomicU64>;
}

const TAG_AS_REQ: u8 = 0x6A;
const TAG_TGS_REQ: u8 = 0x6C;

/// KDC configuration (MIT kdc.conf `[realms]` subset).
#[derive(Debug, Clone)]
pub struct KdcConfig {
    /// The realm served.
    pub realm: String,
    /// Maximum ticket lifetime (MIT `max_life`, default 24h); zero is
    /// unlimited.
    pub max_life: Duration,
    /// Maximum renewable lifetime (MIT `max_renewable_life`); zero issues no
    /// renewable tickets.
    pub max_renewable_life: Duration,
    /// Permitted enctypes for keys and session keys.
    pub supported_enctypes: Vec<i32>,
    /// Allowed clock skew for authenticators and timestamps.
    pub clockskew: Duration,
    /// Largest reply sent over UDP; larger replies are replaced by
    /// `KRB_ERR_RESPONSE_TOO_BIG` (MIT `kdc_max_dgram_reply_size`).
    pub max_dgram_reply_size: usize,
    /// The KDC's krb5.conf, for `[domain_realm]` (referrals) and `[capaths]`
    /// (transit checking and alternate TGTs). Without it only hierarchical
    /// realm relationships are known and no host-to-realm mapping exists.
    pub realm_profile: Option<Profile>,
    /// MIT `host_based_services`: service names for which NT-UNKNOWN
    /// principals may be referred (`*` for all).
    pub host_based_services: Vec<String>,
    /// MIT `no_host_referral`: service names that never get referrals
    /// (`*` for all).
    pub no_host_referral: Vec<String>,
    /// MIT `reject_bad_transit` (default true): refuse tickets whose
    /// transited path was not checked successfully.
    pub reject_bad_transit: bool,
    /// MIT `disable_pac` (kdc.conf realm relation, kdc/main.c:338): never
    /// issue a PAC.
    pub disable_pac: bool,
    /// MIT db2 `disable_lockout` (`[dbmodules]`, kdb_db2.c:273-277): never
    /// check or count failed authentications.
    pub disable_lockout: bool,
    /// MIT db2 `disable_last_success` (kdb_db2.c:267-271): do not record the
    /// time of the last successful authentication.
    pub disable_last_success: bool,
    /// krb5-rs extension (not in MIT, whose TGS path never re-reads the header
    /// ticket's client): re-check a local client at TGS time and refuse it
    /// when it is now disabled, expired or locked out. Default true.
    pub tgs_recheck_client: bool,
    /// MIT `restrict_anonymous_to_tgt` (kdc.conf realm relation,
    /// kdc_util.c:701-712): anonymous clients may only get local TGTs.
    pub restrict_anonymous_to_tgt: bool,
    /// SPAKE groups the KDC permits (`[libdefaults] spake_preauth_groups`);
    /// empty, the MIT KDC default, disables SPAKE.
    pub spake_groups: Vec<crate::spake::Group>,
    /// Optimistic challenge group (`[kdcdefaults] spake_preauth_kdc_challenge`).
    pub spake_challenge: Option<crate::spake::Group>,
    /// Auth indicators for SPAKE (`[realms] spake_preauth_indicator`).
    pub spake_indicators: Vec<String>,
    /// `[realms] encrypted_challenge_indicator`: asserted on a successful
    /// encrypted challenge (kdc_preauth_ec.c:91-141).
    pub encrypted_challenge_indicator: Option<String>,
    /// OTP token types (`[otp]`, MIT otp_state.c `token_types_decode`);
    /// `None` when they fail to load, which disables OTP as a failed
    /// `otp_init` does.
    pub otp_token_types: Option<Vec<otp::TokenType>>,
    /// PKINIT settings; `None` leaves PKINIT off (MIT: no `pkinit_identity`).
    #[cfg(feature = "pkinit")]
    pub pkinit: Option<std::sync::Arc<crate::pkinit::server::ServerConfig>>,
}

impl KdcConfig {
    /// Defaults for `realm`: 24h tickets, no renewable tickets,
    /// AES (18, 17, 20, 19), 300s clock skew, 65536-byte UDP replies
    /// (MIT falls back to `MAX_DGRAM_SIZE` when `kdc_max_dgram_reply_size`
    /// is unset, main.c:636-638; its docs say 4096).
    pub fn new(realm: impl Into<String>) -> Self {
        Self {
            realm: realm.into(),
            max_life: Duration::from_secs(24 * 3600),
            max_renewable_life: Duration::ZERO,
            supported_enctypes: vec![18, 17, 20, 19],
            clockskew: Duration::from_secs(300),
            max_dgram_reply_size: 65536,
            realm_profile: None,
            host_based_services: Vec::new(),
            no_host_referral: Vec::new(),
            reject_bad_transit: true,
            disable_pac: false,
            disable_lockout: false,
            disable_last_success: false,
            tgs_recheck_client: true,
            restrict_anonymous_to_tgt: false,
            spake_groups: Vec::new(),
            spake_challenge: None,
            spake_indicators: Vec::new(),
            encrypted_challenge_indicator: None,
            otp_token_types: Some(vec![otp::default_type()]),
            #[cfg(feature = "pkinit")]
            pkinit: None,
        }
    }
}

/// A KDC serving one realm from a [`PrincipalStore`].
pub struct Kdc<S: PrincipalStore> {
    config: KdcConfig,
    store: S,
    policies: Arc<dyn DynPolicies>,
    auth_state: Arc<dyn DynAuthState>,
    gate: Arc<dyn DynGate>,
    reporter: Arc<dyn LockoutReporter>,
    kdcpolicy: Vec<Arc<dyn plugins::KdcPolicy>>,
    audit: Vec<Arc<dyn plugins::Audit>>,
    lookaside: lookaside::Lookaside,
}

/// Builds a [`Kdc`] with injected services (docs/architecture/kdb.md §3).
///
/// The principal store is a generic parameter of [`Kdc`] (the hot path stays
/// statically dispatched); the other services are type-erased through private
/// object-safe adapters, so the public API is one family of native async
/// traits. Every service defaults to the behaviour `Kdc::new` always had:
/// no policies (lockout inert), in-memory authentication state, an
/// always-allow consistency gate and a no-op lockout reporter.
pub struct KdcBuilder<S: PrincipalStore> {
    config: KdcConfig,
    store: S,
    policies: Arc<dyn DynPolicies>,
    auth_state: Arc<dyn DynAuthState>,
    gate: Arc<dyn DynGate>,
    reporter: Arc<dyn LockoutReporter>,
    kdcpolicy: Vec<Arc<dyn plugins::KdcPolicy>>,
    audit: Vec<Arc<dyn plugins::Audit>>,
}

impl<S: PrincipalStore> KdcBuilder<S> {
    /// Use `policies` to resolve a principal's policy name (lockout
    /// parameters).
    pub fn policies(mut self, policies: impl PolicyStore + 'static) -> Self {
        self.policies = Arc::new(policies);
        self
    }

    /// Keep failure counters and last-success times in `state`.
    pub fn auth_state(mut self, state: impl AuthStateStore + 'static) -> Self {
        self.auth_state = Arc::new(state);
        self
    }

    /// Consult `gate` before issuing tickets (replica freshness, strict
    /// authoritative checks).
    pub fn consistency(mut self, gate: impl ConsistencyGate + 'static) -> Self {
        self.gate = Arc::new(gate);
        self
    }

    /// Report tripped lockouts to `reporter`.
    pub fn lockout_reporter(mut self, reporter: impl LockoutReporter + 'static) -> Self {
        self.reporter = Arc::new(reporter);
        self
    }

    /// Run `modules` (in order) as MIT's kdcpolicy modules.
    pub fn kdcpolicy(mut self, modules: Vec<Arc<dyn plugins::KdcPolicy>>) -> Self {
        self.kdcpolicy = modules;
        self
    }

    /// Report requests to `modules` as MIT's audit modules.
    pub fn audit(mut self, modules: Vec<Arc<dyn plugins::Audit>>) -> Self {
        self.audit = modules;
        self
    }

    /// Finish.
    pub fn build(self) -> Kdc<S> {
        Kdc {
            config: self.config,
            store: self.store,
            policies: self.policies,
            auth_state: self.auth_state,
            gate: self.gate,
            reporter: self.reporter,
            kdcpolicy: self.kdcpolicy,
            audit: self.audit,
            lookaside: lookaside::Lookaside::default(),
        }
    }
}

impl<S: PrincipalStore> Kdc<S> {
    /// Create a KDC. The store must hold `krbtgt/REALM@REALM`. Equivalent to
    /// `Kdc::builder(config, store).build()`.
    pub fn new(config: KdcConfig, store: S) -> Self {
        Self::builder(config, store).build()
    }

    /// Replace the kdcpolicy and audit modules (see [`KdcBuilder::kdcpolicy`]
    /// and [`KdcBuilder::audit`]).
    #[must_use]
    pub fn with_plugins(
        mut self,
        kdcpolicy: Vec<Arc<dyn plugins::KdcPolicy>>,
        audit: Vec<Arc<dyn plugins::Audit>>,
    ) -> Self {
        self.kdcpolicy = kdcpolicy;
        self.audit = audit;
        self
    }

    /// Start a [`KdcBuilder`].
    pub fn builder(config: KdcConfig, store: S) -> KdcBuilder<S> {
        KdcBuilder {
            config,
            store,
            policies: Arc::new(NoPolicies),
            auth_state: Arc::new(MemoryAuthState::new()),
            gate: Arc::new(AlwaysAllow),
            reporter: Arc::new(NoopLockoutReporter),
            kdcpolicy: Vec::new(),
            audit: Vec::new(),
        }
    }

    /// Process one DER request at the current time; always returns DER
    /// (AS-REP, TGS-REP or KRB-ERROR).
    pub async fn handle(&self, request: &[u8]) -> Vec<u8> {
        self.handle_at(request, Utc::now()).await
    }

    /// [`Kdc::handle`] with an injectable clock.
    pub async fn handle_at(&self, request: &[u8], now: DateTime<Utc>) -> Vec<u8> {
        self.handle_from_at(request, now, None).await
    }

    /// [`Kdc::handle_at`] for a request from `peer` (the audit modules'
    /// client address).
    pub async fn handle_from_at(
        &self,
        request: &[u8],
        now: DateTime<Utc>,
        peer: Option<std::net::SocketAddr>,
    ) -> Vec<u8> {
        match self.dispatch(request, now, peer).await {
            Ok(reply) => reply,
            Err(f) => build_krb_error(&f.err, &f.ctx, now),
        }
    }

    /// [`Kdc::handle`] for a UDP datagram: a reply longer than
    /// `max_dgram_reply_size` is replaced by `KRB_ERR_RESPONSE_TOO_BIG`
    /// (MIT `finish_dispatch`, dispatch.c:54-63).
    pub async fn handle_udp(&self, request: &[u8]) -> Vec<u8> {
        self.handle_udp_at(request, Utc::now()).await
    }

    /// [`Kdc::handle_udp`] with an injectable clock.
    pub async fn handle_udp_at(&self, request: &[u8], now: DateTime<Utc>) -> Vec<u8> {
        self.handle_udp_from_at(request, now, None).await
    }

    /// [`Kdc::handle_udp_at`] for a datagram from `peer`.
    pub async fn handle_udp_from_at(
        &self,
        request: &[u8],
        now: DateTime<Utc>,
        peer: Option<std::net::SocketAddr>,
    ) -> Vec<u8> {
        let reply = self.handle_from_at(request, now, peer).await;
        if reply.len() > self.config.max_dgram_reply_size {
            return self.bare_error(KRB_ERR_RESPONSE_TOO_BIG, now);
        }
        reply
    }

    /// Process one request like [`Kdc::handle`] (or [`Kdc::handle_udp`] for
    /// [`Transport::Udp`]) and summarise it for logging. A packet repeating
    /// one seen in the last two minutes gets the same reply without being
    /// processed again, or no reply (an empty one) while the first copy is
    /// still being processed (MIT `dispatch`, dispatch.c:113-141); see
    /// [`RequestSummary::lookaside`].
    pub async fn handle_summarized(
        &self,
        request: &[u8],
        transport: Transport,
    ) -> (Vec<u8>, RequestSummary) {
        self.handle_summarized_from(request, transport, None).await
    }

    /// [`Kdc::handle_summarized`] for a request from `peer`.
    pub async fn handle_summarized_from(
        &self,
        request: &[u8],
        transport: Transport,
        peer: Option<std::net::SocketAddr>,
    ) -> (Vec<u8>, RequestSummary) {
        let now = Utc::now();
        // finish_dispatch (dispatch.c:54-63) applies to cached replies too.
        let datagram = |reply: Vec<u8>| match transport {
            Transport::Udp if reply.len() > self.config.max_dgram_reply_size => {
                self.bare_error(KRB_ERR_RESPONSE_TOO_BIG, Utc::now())
            }
            _ => reply,
        };
        if let Some(hit) = self.lookaside.check(request) {
            let (reply, hit) = match hit {
                Some(reply) => (datagram(reply), LookasideHit::Resent),
                None => (Vec::new(), LookasideHit::Dropped),
            };
            let mut summary = RequestSummary::new(request, &reply, transport);
            summary.lookaside = Some(hit);
            return (reply, summary);
        }
        let pending = lookaside::InProgress::start(&self.lookaside, request, now.timestamp());
        #[cfg(feature = "tokio")]
        let timer = std::sync::Arc::new(AtomicU64::new(0));
        #[cfg(feature = "tokio")]
        let reply = STORE_TIME_NANOS
            .scope(
                std::sync::Arc::clone(&timer),
                self.handle_from_at(request, now, peer),
            )
            .await;
        #[cfg(not(feature = "tokio"))]
        let reply = self.handle_from_at(request, now, peer).await;
        pending.finish(&reply, Utc::now().timestamp());
        let reply = datagram(reply);
        let summary = RequestSummary::new(request, &reply, transport);
        #[cfg(feature = "tokio")]
        let summary = {
            let mut summary = summary;
            summary.store_time = Duration::from_nanos(timer.load(Ordering::Relaxed));
            summary
        };
        (reply, summary)
    }

    /// A KRB-ERROR with no client, text or e-data and the local TGS as
    /// server (MIT `make_too_big_error`, dispatch.c:178-209, and
    /// `make_toolong_error`, kdc_util.c:1882-1912).
    pub(crate) fn bare_error(&self, code: i32, now: DateTime<Utc>) -> Vec<u8> {
        let err = KdcError {
            code,
            e_text: None,
            e_data: None,
            typed_e_data: false,
        };
        build_krb_error(&err, &self.local_context(), now)
    }

    /// MIT `dispatch` (dispatch.c:89-175).
    async fn dispatch(
        &self,
        request: &[u8],
        now: DateTime<Utc>,
        peer: Option<std::net::SocketAddr>,
    ) -> Result<Vec<u8>, Box<Failure>> {
        let local = self.local_context();
        let fail = |err: KdcError, ctx: &ErrorContext| {
            Box::new(Failure {
                err,
                ctx: ctx.clone(),
            })
        };

        let (decoded, is_as): (KdcReq, bool) = match request.first() {
            Some(&TAG_TGS_REQ) => match rasn::der::decode::<TgsReq>(request) {
                Ok(r) => (r.0, false),
                Err(_) => return Err(fail(KdcError::generic("ASN1_DECODE"), &local)),
            },
            Some(&TAG_AS_REQ) => match rasn::der::decode::<AsReq>(request) {
                Ok(r) => (r.0, true),
                Err(_) => return Err(fail(KdcError::generic("ASN1_DECODE"), &local)),
            },
            _ => {
                return Err(fail(
                    KdcError::new(KRB_AP_ERR_MSG_TYPE, "BAD_MESSAGE_TYPE"),
                    &local,
                ))
            }
        };

        let mut ctx = self.request_context(&decoded, is_as);
        if decoded.pvno != 5 {
            return Err(fail(KdcError::new(KDC_ERR_BAD_PVNO, "BAD_PVNO"), &ctx));
        }
        if decoded.req_body.realm.as_bytes() != self.config.realm.as_bytes() {
            return Err(fail(
                KdcError::new(KDC_ERR_WRONG_REALM, "WRONG_REALM"),
                &ctx,
            ));
        }

        let result = if is_as {
            self.process_as_req(&decoded, request, now, &mut ctx).await
        } else {
            self.process_tgs_req(&decoded, request, now, &mut ctx).await
        };
        if !self.audit.is_empty() {
            self.kau_request(is_as, &decoded, &ctx, peer, &result);
        }
        result.map_err(|err| Box::new(Failure { err, ctx }))
    }

    /// `kau_as_req`, `kau_tgs_req`, `kau_s4u2self`, `kau_s4u2proxy` and
    /// `kau_u2u` for a processed request.
    fn kau_request(
        &self,
        is_as: bool,
        outer: &KdcReq,
        ctx: &ErrorContext,
        peer: Option<std::net::SocketAddr>,
        result: &Result<Vec<u8>, KdcError>,
    ) {
        // After FAST, the inner request is the one processed (kdc_find_fast).
        let req = ctx.audit_req.as_deref().unwrap_or(outer);
        let realm = &self.config.realm;
        let unparse = |p: &PrincipalName| {
            String::from_utf8_lossy(&kdb::mit::unparse_name(p, realm)).into_owned()
        };
        let tkt_id = |t: &Ticket| plugins::ticket_id(t.enc_part.cipher.as_ref());
        let mut st = plugins::AuditState::new(peer);
        st.client = req.req_body.cname.as_ref().map(unparse);
        st.server = req.req_body.sname.as_ref().map(unparse);
        st.cl_realm = Some(String::from_utf8_lossy(req.req_body.realm.as_bytes()).into_owned());
        let success = result.is_ok();
        match result {
            Ok(reply) => {
                st.stage = plugins::AuditStage::EncrRep;
                st.status = Some("ISSUE".into());
                let ticket = if is_as {
                    rasn::der::decode::<AsRep>(reply).ok().map(|r| r.0.ticket)
                } else {
                    rasn::der::decode::<TgsRep>(reply).ok().map(|r| r.0.ticket)
                };
                st.tkt_out_id = ticket.as_ref().map(tkt_id);
            }
            Err(e) => {
                st.error_code = e.code;
                st.status = e.e_text.clone();
                if e.code == plugins::KDC_ERR_POLICY {
                    st.violation = plugins::LOCAL_POLICY;
                }
            }
        }
        let padata = req.padata.as_deref().unwrap_or_default();
        if is_as {
            for m in &self.audit {
                m.as_req(success, &st);
            }
            return;
        }
        st.s4u2self_user = ctx.s4u2self_user.clone();
        st.tkt_in_id = outer
            .padata
            .as_deref()
            .unwrap_or_default()
            .iter()
            .find(|p| p.padata_type == 1)
            .and_then(|p| rasn::der::decode::<ApReq>(p.padata_value.as_ref()).ok())
            .map(|ap| tkt_id(&ap.ticket));
        let opts = req.req_body.kdc_options;
        st.evid_tkt_id = req
            .req_body
            .additional_tickets
            .as_ref()
            .and_then(|t| t.first())
            .map(tkt_id);
        // PA-FOR-USER and PA-S4U-X509-USER.
        if padata
            .iter()
            .any(|p| p.padata_type == 129 || p.padata_type == 130)
        {
            for m in &self.audit {
                m.s4u2self(success, &st);
            }
        }
        if opts.contains(KdcOptions::CNAME_IN_ADDL_TKT) {
            for m in &self.audit {
                m.s4u2proxy(success, &st);
            }
        }
        if opts.contains(KdcOptions::ENC_TKT_IN_SKEY) {
            for m in &self.audit {
                m.u2u(success, &st);
            }
        }
        for m in &self.audit {
            m.tgs_req(success, &st);
        }
    }

    /// `check_kdcpolicy_as` / `check_kdcpolicy_tgs` (`kdc/policy.c`).
    #[allow(clippy::too_many_arguments)]
    fn check_kdcpolicy(
        &self,
        auth_indicators: &[String],
        tgs: bool,
        client: Option<&PrincipalName>,
        ticket_client: Option<(&PrincipalName, &str)>,
        server: &PrincipalName,
        now: i64,
        times: &mut policy::Times,
    ) -> Result<(), KdcError> {
        if self.kdcpolicy.is_empty() {
            return Ok(());
        }
        let realm = &self.config.realm;
        let req = plugins::PolicyRequest {
            client: client
                .map(|c| String::from_utf8_lossy(&kdb::mit::unparse_name(c, realm)).into_owned()),
            server: String::from_utf8_lossy(&kdb::mit::unparse_name(server, realm)).into_owned(),
            ticket_client: ticket_client
                .map(|(c, r)| String::from_utf8_lossy(&kdb::mit::unparse_name(c, r)).into_owned()),
            auth_indicators: auth_indicators.to_vec(),
        };
        plugins::check_policy(
            &self.kdcpolicy,
            tgs,
            &req,
            now,
            &mut times.endtime,
            &mut times.renew_till,
        )
        .map_err(|r| KdcError::new(r.code, &r.status))
    }

    fn local_context(&self) -> ErrorContext {
        ErrorContext {
            realm: self.config.realm.clone(),
            sname: krbtgt_name(&self.config.realm).unwrap_or(PrincipalName {
                name_type: 2,
                name_string: Vec::new(),
            }),
            crealm: None,
            cname: None,
            fast: None,
            audit_req: None,
            s4u2self_user: None,
        }
    }

    /// KRB-ERROR echo fields from the request (prepare_error_as /
    /// prepare_error_tgs: server from the request, client from the AS
    /// request; TGS clients are learned from the header ticket).
    fn request_context(&self, req: &KdcReq, is_as: bool) -> ErrorContext {
        let realm = String::from_utf8_lossy(req.req_body.realm.as_bytes()).to_string();
        let sname = req
            .req_body
            .sname
            .clone()
            .or_else(|| krbtgt_name(&realm).ok())
            .unwrap_or_else(|| self.local_context().sname);
        ErrorContext {
            crealm: is_as.then(|| realm.clone()),
            cname: if is_as {
                req.req_body.cname.clone()
            } else {
                None
            },
            realm,
            sname,
            fast: None,
            audit_req: None,
            s4u2self_user: None,
        }
    }

    /// Permitted enctype predicate (MIT `krb5_is_permitted_enctype`).
    fn permitted(&self) -> impl Fn(i32) -> bool + '_ {
        move |etype| find_etype(etype).is_ok() && self.config.supported_enctypes.contains(&etype)
    }

    fn limits(&self) -> RealmLimits {
        RealmLimits {
            max_life: secs(self.config.max_life),
            max_renewable_life: secs(self.config.max_renewable_life),
        }
    }

    async fn lookup(
        &self,
        name: &PrincipalName,
        realm: &str,
        status: &str,
    ) -> Result<Option<PrincipalEntry>, KdcError> {
        // A store that cannot be reached (or is too stale) is an unavailable
        // service, so clients move on to another KDC: MIT maps
        // KRB5_KDB_CANTLOCK_DB the same way (do_as_req.c:578-579, 597-598).
        self.measure_store(self.store.lookup(name, realm))
            .await
            .map_err(|e| match e.kind() {
                StoreErrorKind::Unavailable | StoreErrorKind::Stale => {
                    KdcError::new(KDC_ERR_SVC_UNAVAILABLE, status)
                }
                _ => KdcError::generic(status),
            })
    }

    /// `krb5_db_get_s4u_x509_principal` with the error mapping of
    /// [`Kdc::lookup`]; a name mismatch is KDC_ERR_CLIENT_NAME_MISMATCH.
    async fn lookup_s4u_x509(
        &self,
        cert: &[u8],
        name: &PrincipalName,
        realm: &str,
        referral_ok: bool,
        status: &str,
    ) -> Result<Option<PrincipalEntry>, KdcError> {
        self.measure_store(self.store.lookup_s4u_x509(cert, name, realm, referral_ok))
            .await
            .map_err(|e| match e.kind() {
                StoreErrorKind::Unavailable | StoreErrorKind::Stale => {
                    KdcError::new(KDC_ERR_SVC_UNAVAILABLE, status)
                }
                StoreErrorKind::NameMismatch => KdcError::new(
                    crate::types::error_codes::KDC_ERR_CLIENT_NAME_MISMATCH,
                    status,
                ),
                _ => KdcError::generic(status),
            })
    }

    /// Measure one store await in the current summarized request.
    pub(crate) async fn measure_store<F: Future>(&self, future: F) -> F::Output {
        #[cfg(feature = "tokio")]
        let start = Instant::now();
        let result = future.await;
        #[cfg(feature = "tokio")]
        {
            let nanos = u64::try_from(start.elapsed().as_nanos()).unwrap_or(u64::MAX);
            let _ = STORE_TIME_NANOS.try_with(|timer| {
                timer.fetch_add(nanos, Ordering::Relaxed);
            });
        }
        result
    }

    /// Ask the consistency gate whether tickets involving `subjects` may be
    /// issued (docs/architecture/kdb.md §7).
    async fn consistency_gate(&self, subjects: &[GateSubject<'_>]) -> Result<(), KdcError> {
        match self.gate.check(subjects).await {
            GateDecision::Allow => Ok(()),
            GateDecision::Reject { reason } => Err(KdcError::new(KDC_ERR_SVC_UNAVAILABLE, &reason)),
            GateDecision::Deny { index, denial } => {
                let Some(subject) = subjects.get(index) else {
                    return Err(KdcError::new(
                        KDC_ERR_SVC_UNAVAILABLE,
                        "AUTHORITATIVE_MISMATCH",
                    ));
                };
                // MIT kdc_util.c:777-787 maps a locked client to
                // KDC_ERR_CLIENT_REVOKED and a locked service to
                // KDC_ERR_S_PRINCIPAL_UNKNOWN; check_lockout uses the same
                // client code (lockout.rs:131; MIT kdc_db2.c:1546-1549).
                let (code, status) = match (subject.role, denial) {
                    (PrincipalRole::Client, AuthoritativeDenial::Disabled) => {
                        (KDC_ERR_CLIENT_REVOKED, "AUTHORITATIVE_CLIENT_DISABLED")
                    }
                    (PrincipalRole::Client, AuthoritativeDenial::LockedOut) => {
                        (KDC_ERR_CLIENT_REVOKED, "AUTHORITATIVE_CLIENT_LOCKED_OUT")
                    }
                    (PrincipalRole::Client, AuthoritativeDenial::Deleted) => {
                        (KDC_ERR_C_PRINCIPAL_UNKNOWN, "AUTHORITATIVE_CLIENT_DELETED")
                    }
                    (PrincipalRole::Server, AuthoritativeDenial::Disabled) => {
                        (KDC_ERR_S_PRINCIPAL_UNKNOWN, "AUTHORITATIVE_SERVER_DISABLED")
                    }
                    (PrincipalRole::Server, AuthoritativeDenial::Deleted) => {
                        (KDC_ERR_S_PRINCIPAL_UNKNOWN, "AUTHORITATIVE_SERVER_DELETED")
                    }
                    (PrincipalRole::Server, AuthoritativeDenial::LockedOut) => {
                        (KDC_ERR_SVC_UNAVAILABLE, "AUTHORITATIVE_MISMATCH")
                    }
                };
                Err(KdcError::new(code, status))
            }
        }
    }

    /// `get_local_tgt` (MIT kdc_util.c:485-525): the local krbtgt must exist
    /// and have a usable current key.
    async fn require_local_tgt(&self) -> Result<PrincipalEntry, KdcError> {
        const STATUS: &str = "GET_LOCAL_TGT";
        let name = krbtgt_name(&self.config.realm)?;
        let tgt = self
            .lookup(&name, &self.config.realm, STATUS)
            .await?
            .ok_or_else(|| KdcError::generic(STATUS))?;
        tgt.find_key(None, KvnoSel::Highest, &self.permitted())
            .ok_or_else(|| KdcError::generic(STATUS))?;
        Ok(tgt)
    }
}

/// Random session key of `etype` (MIT `krb5_c_make_random_key`).
fn random_key(etype: i32) -> Result<EncryptionKey, KdcError> {
    let profile =
        find_etype(etype).map_err(|_| KdcError::new(KDC_ERR_ETYPE_NOSUPP, "BAD_ETYPE"))?;
    let key = profile
        .random_to_key(&generate_random(profile.key_bytes()))
        .map_err(|_| KdcError::generic("RANDOM_KEY"))?;
    Ok(EncryptionKey::new(etype, key.to_vec()))
}

/// `krb5_is_tgs_principal`.
fn is_tgs_principal(name: &PrincipalName) -> bool {
    name.name_string.len() == 2 && name.name_string[0].as_bytes() == b"krbtgt"
}

/// Name comparison ignoring the name type (MIT princ_comp.c).
fn names_equal(a: &PrincipalName, b: &PrincipalName) -> bool {
    a.name_string == b.name_string
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::KrbErrorMsg;

    fn kdc(max_dgram: usize) -> Kdc<MemoryStore> {
        let mut config = KdcConfig::new("R");
        config.max_dgram_reply_size = max_dgram;
        Kdc::new(config, MemoryStore::new())
    }

    fn decode(der: &[u8]) -> KrbErrorMsg {
        rasn::der::decode(der).expect("KRB-ERROR")
    }

    #[tokio::test]
    async fn handle_udp_reply_within_limit_is_unchanged() {
        let reply = kdc(4096).handle_udp(&[1, 2, 3]).await;
        assert_eq!(decode(&reply).error_code, KRB_AP_ERR_MSG_TYPE);
    }

    #[tokio::test]
    async fn handle_udp_oversize_reply_becomes_response_too_big() {
        let k = kdc(10);
        let full = k.handle(&[1, 2, 3]).await;
        assert!(full.len() > 10);
        let err = decode(&k.handle_udp(&[1, 2, 3]).await);
        assert_eq!(err.error_code, KRB_ERR_RESPONSE_TOO_BIG);
        assert!(err.cname.is_none() && err.crealm.is_none());
        assert!(err.e_text.is_none() && err.e_data.is_none());
        assert_eq!(err.realm.as_bytes(), b"R");
        assert_eq!(err.sname.to_string(), "krbtgt/R");
    }

    #[tokio::test]
    async fn handle_udp_reply_exactly_at_limit_is_not_replaced() {
        let probe = kdc(4096).handle(&[1, 2, 3]).await;
        let reply = kdc(probe.len()).handle_udp(&[1, 2, 3]).await;
        assert_eq!(decode(&reply).error_code, KRB_AP_ERR_MSG_TYPE);
    }
}
