//! Kerberos KDC (server side): AS and TGS request processing.
//!
//! Pure request-bytes → reply-bytes logic modelled on MIT krb5 1.22.2
//! `src/kdc` (dispatch.c, do_as_req.c, do_tgs_req.c, kdc_util.c,
//! tgs_policy.c, kdc_preauth.c, kdc_preauth_encts.c). No networking: feed a
//! DER request to [`Kdc::handle`] and send the returned DER reply.
//!
//! Single realm only; no PKINIT, PAC/authdata, cross-realm, S4U, user-to-user,
//! postdating, validation, proxy tickets, lockout or lookaside cache.
//! FAST is handled by a later `kdc::fast` module.

mod as_req;
mod db;
mod error;
mod policy;
mod preauth;
mod reqbody;
mod tgs_req;

use std::time::Duration;

use chrono::{DateTime, Utc};

pub use db::{
    KeyEntry, MemoryStore, PrincipalAttributes, PrincipalEntry, PrincipalStore, StoreError,
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
}

impl KdcConfig {
    /// Defaults for `realm`: 24h tickets, no renewable tickets,
    /// AES (18, 17, 20, 19), 300s clock skew.
    pub fn new(realm: impl Into<String>) -> Self {
        Self {
            realm: realm.into(),
            max_life: Duration::from_secs(24 * 3600),
            max_renewable_life: Duration::ZERO,
            supported_enctypes: vec![18, 17, 20, 19],
            clockskew: Duration::from_secs(300),
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
