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
//! logon-information source. No PKINIT, S4U, user-to-user, postdating,
//! validation, proxy tickets, lockout or lookaside cache.
//! FAST (RFC 6113) armor, encrypted challenge and armored replies/errors are
//! handled in the `fast` module.

mod as_req;
mod authdata;
mod config;
mod db;
mod error;
mod fast;
pub mod kdb;
mod pkinit;
mod policy;
mod preauth;
mod reqbody;
mod s4u;
#[cfg(feature = "tokio")]
mod server;
mod summary;
mod tgs_req;

use std::time::Duration;

use crate::profile::Profile;

use chrono::{DateTime, Utc};

#[cfg(feature = "tokio")]
pub use server::{
    serve_tcp, serve_tcp_with, serve_udp, serve_udp_with, RequestLogger, ServeOptions,
};

pub use summary::{Outcome, RequestKind, RequestSummary, Transport};

pub use config::{default_realm, parse_listen_addresses, ConfigError, RealmConfig};
pub use db::{
    keys_from_password, random_keys, salt_bytes, KeyEntry, MemoryStore, PrincipalAttributes,
    PrincipalEntry, PrincipalStore, StoreError,
};

use db::KvnoSel;
use error::{build_krb_error, krbtgt_name, ErrorContext, Failure, KdcError};
use policy::{secs, RealmLimits};

use crate::crypto::find_etype;
use crate::crypto::util::generate_random;
use crate::types::error_codes::*;
use crate::types::{AsReq, EncryptionKey, KdcReq, PrincipalName, TgsReq};

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
            #[cfg(feature = "pkinit")]
            pkinit: None,
        }
    }
}

/// A KDC serving one realm from a [`PrincipalStore`].
pub struct Kdc<S: PrincipalStore> {
    config: KdcConfig,
    store: S,
}

impl<S: PrincipalStore> Kdc<S> {
    /// Create a KDC. The store must hold `krbtgt/REALM@REALM`.
    pub fn new(config: KdcConfig, store: S) -> Self {
        Self { config, store }
    }

    /// Process one DER request at the current time; always returns DER
    /// (AS-REP, TGS-REP or KRB-ERROR).
    pub fn handle(&self, request: &[u8]) -> Vec<u8> {
        self.handle_at(request, Utc::now())
    }

    /// [`Kdc::handle`] with an injectable clock.
    pub fn handle_at(&self, request: &[u8], now: DateTime<Utc>) -> Vec<u8> {
        match self.dispatch(request, now) {
            Ok(reply) => reply,
            Err(f) => build_krb_error(&f.err, &f.ctx, now),
        }
    }

    /// [`Kdc::handle`] for a UDP datagram: a reply longer than
    /// `max_dgram_reply_size` is replaced by `KRB_ERR_RESPONSE_TOO_BIG`
    /// (MIT `finish_dispatch`, dispatch.c:54-63).
    pub fn handle_udp(&self, request: &[u8]) -> Vec<u8> {
        self.handle_udp_at(request, Utc::now())
    }

    /// [`Kdc::handle_udp`] with an injectable clock.
    pub fn handle_udp_at(&self, request: &[u8], now: DateTime<Utc>) -> Vec<u8> {
        let reply = self.handle_at(request, now);
        if reply.len() > self.config.max_dgram_reply_size {
            return self.bare_error(KRB_ERR_RESPONSE_TOO_BIG, now);
        }
        reply
    }

    /// Process one request like [`Kdc::handle`] (or [`Kdc::handle_udp`] for
    /// [`Transport::Udp`]) and summarise it for logging.
    pub fn handle_summarized(
        &self,
        request: &[u8],
        transport: Transport,
    ) -> (Vec<u8>, RequestSummary) {
        let reply = match transport {
            Transport::Udp => self.handle_udp(request),
            Transport::Tcp => self.handle(request),
        };
        let summary = RequestSummary::new(request, &reply, transport);
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
    fn dispatch(&self, request: &[u8], now: DateTime<Utc>) -> Result<Vec<u8>, Box<Failure>> {
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
            self.process_as_req(&decoded, request, now, &mut ctx)
        } else {
            self.process_tgs_req(&decoded, request, now, &mut ctx)
        };
        result.map_err(|err| Box::new(Failure { err, ctx }))
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

    fn lookup(
        &self,
        name: &PrincipalName,
        realm: &str,
        status: &str,
    ) -> Result<Option<PrincipalEntry>, KdcError> {
        self.store
            .lookup(name, realm)
            .map_err(|_| KdcError::generic(status))
    }

    /// `get_local_tgt` (MIT kdc_util.c:485-525): the local krbtgt must exist
    /// and have a usable current key.
    fn require_local_tgt(&self) -> Result<PrincipalEntry, KdcError> {
        const STATUS: &str = "GET_LOCAL_TGT";
        let name = krbtgt_name(&self.config.realm)?;
        let tgt = self
            .lookup(&name, &self.config.realm, STATUS)?
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

    #[test]
    fn handle_udp_reply_within_limit_is_unchanged() {
        let reply = kdc(4096).handle_udp(&[1, 2, 3]);
        assert_eq!(decode(&reply).error_code, KRB_AP_ERR_MSG_TYPE);
    }

    #[test]
    fn handle_udp_oversize_reply_becomes_response_too_big() {
        let k = kdc(10);
        let full = k.handle(&[1, 2, 3]);
        assert!(full.len() > 10);
        let err = decode(&k.handle_udp(&[1, 2, 3]));
        assert_eq!(err.error_code, KRB_ERR_RESPONSE_TOO_BIG);
        assert!(err.cname.is_none() && err.crealm.is_none());
        assert!(err.e_text.is_none() && err.e_data.is_none());
        assert_eq!(err.realm.as_bytes(), b"R");
        assert_eq!(err.sname.to_string(), "krbtgt/R");
    }

    #[test]
    fn handle_udp_reply_exactly_at_limit_is_not_replaced() {
        let probe = kdc(4096).handle(&[1, 2, 3]);
        let reply = kdc(probe.len()).handle_udp(&[1, 2, 3]);
        assert_eq!(decode(&reply).error_code, KRB_AP_ERR_MSG_TYPE);
    }
}
