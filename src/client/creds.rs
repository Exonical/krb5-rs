//! Credential acquisition through a credential cache (MIT get_creds.c
//! `krb5_get_credentials`).

use std::time::{SystemTime, UNIX_EPOCH};

use bitflags::bitflags;

use super::canonprinc::CanonPrinc;
use super::KerberosClient;
use crate::ccache::{CcCredential, CcError, Ccache, MatchCred, MatchFlags};
use crate::protocol::ap::ApError;
use crate::protocol::{Credential, TgsExchange, TgsOptions};
use crate::transport::KdcTransport;
use crate::types::{AuthorizationDataElement, PrincipalName, Ticket};
use crate::Krb5Error;

/// `KRB5KDC_ERR_S_PRINCIPAL_UNKNOWN`.
pub(super) const S_PRINCIPAL_UNKNOWN: i32 = 7;

bitflags! {
    /// `krb5_get_credentials` options (MIT `KRB5_GC_*`, krb5.hin).
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    pub struct GcOptions: u32 {
        /// Want a user-to-user ticket (`KRB5_GC_USER_USER`).
        const USER_USER = 1;
        /// Want a cached ticket only (`KRB5_GC_CACHED`).
        const CACHED = 2;
        /// Set the CANONICALIZE KDC option (`KRB5_GC_CANONICALIZE`).
        const CANONICALIZE = 4;
        /// Do not store the result in the ccache (`KRB5_GC_NO_STORE`).
        const NO_STORE = 8;
        /// Request forwardable tickets (`KRB5_GC_FORWARDABLE`).
        const FORWARDABLE = 16;
        /// Set DISABLE-TRANSITED-CHECK (`KRB5_GC_NO_TRANSIT_CHECK`).
        const NO_TRANSIT_CHECK = 32;
        /// Constrained delegation (`KRB5_GC_CONSTRAINED_DELEGATION`).
        const CONSTRAINED_DELEGATION = 64;
    }
}

/// The requested credential (MIT `in_creds`).
#[derive(Debug, Clone)]
pub struct CredsRequest {
    /// Client principal.
    pub client: PrincipalName,
    /// Client realm.
    pub crealm: String,
    /// Server principal.
    pub server: PrincipalName,
    /// Server realm; empty is the referral realm (start in the client's
    /// realm).
    pub srealm: String,
    /// Required session key enctype, or 0 for any (`keyblock.enctype`).
    pub enctype: i32,
    /// Authorization data the cached credential must carry.
    pub authdata: Option<Vec<AuthorizationDataElement>>,
    /// Second ticket, for user-to-user and constrained delegation.
    pub second_ticket: Option<Ticket>,
}

impl CredsRequest {
    /// A request for `server@srealm` as `client@crealm`.
    pub fn new(
        client: PrincipalName,
        crealm: impl Into<String>,
        server: PrincipalName,
        srealm: impl Into<String>,
    ) -> Self {
        Self {
            client,
            crealm: crealm.into(),
            server,
            srealm: srealm.into(),
            enctype: 0,
            authdata: None,
            second_ticket: None,
        }
    }
}

/// `krb5int_tgtname`: `krbtgt/<target>`.
pub(super) fn tgt_name(target: &str) -> PrincipalName {
    PrincipalName::new_srv_inst("krbtgt", target)
}

/// `krb5_principal_compare` (the name type is ignored).
pub(super) fn same_principal(a: &PrincipalName, ar: &str, b: &PrincipalName, br: &str) -> bool {
    ar == br && a.name_string == b.name_string
}

/// KRB5_CC_NOTFOUND or KRB5_CC_NOT_KTYPE: the cache does not hold it.
pub(super) fn is_cache_miss(e: &Krb5Error) -> bool {
    matches!(e, Krb5Error::Ccache(CcError::NotFound | CcError::NotKtype))
}

fn now() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u32::try_from(d.as_secs()).unwrap_or(u32::MAX))
}

fn invalid(what: &'static str) -> Krb5Error {
    Krb5Error::ReplyValidation(what)
}

fn from_cache(c: &CcCredential) -> Result<Credential, Krb5Error> {
    Ok(Credential::try_from(c)?)
}

impl<T: KdcTransport> KerberosClient<T> {
    /// The TGS options for a request under `options` (get_creds.c
    /// `krb5_tkt_creds_init`).
    pub(super) fn gc_tgs_options(&self, options: GcOptions) -> TgsOptions {
        let mut tgs = self.tgs_options.clone();
        if options.contains(GcOptions::CANONICALIZE) {
            tgs.canonicalize = true;
        }
        if options.contains(GcOptions::FORWARDABLE) {
            tgs.forwardable = true;
        }
        if options.contains(GcOptions::NO_TRANSIT_CHECK) {
            tgs.disable_transited_check = true;
        }
        tgs
    }

    /// `k5_get_cached_cred` (get_creds.c:52-150).
    pub(super) fn get_cached_cred<C: Ccache>(
        &self,
        options: GcOptions,
        ccache: &C,
        req: &CredsRequest,
    ) -> Result<Credential, Krb5Error> {
        let mut fields = MatchFlags::TIMES | MatchFlags::AUTHDATA | MatchFlags::SUPPORTED_KTYPES;
        let ktypes = &self.tgs_options.etypes;
        if req.enctype != 0 {
            fields |= MatchFlags::KTYPE;
            if !ktypes.contains(&req.enctype) {
                return Err(CcError::NotKtype.into());
            }
        }
        let mut m = MatchCred {
            client: Some((req.client.clone(), req.crealm.clone())),
            server: Some((req.server.clone(), req.srealm.clone())),
            etype: req.enctype,
            endtime: now(),
            authdata: req.authdata.clone(),
            ..MatchCred::default()
        };
        if options.intersects(GcOptions::USER_USER | GcOptions::CONSTRAINED_DELEGATION) {
            fields |= MatchFlags::SECOND_TKT;
            if options.contains(GcOptions::USER_USER) {
                fields |= MatchFlags::IS_SKEY;
                m.is_skey = true;
            }
            let ticket = req
                .second_ticket
                .as_ref()
                .ok_or(invalid("no second ticket"))?;
            m.second_ticket = Some(rasn::der::encode(ticket)?);
        }
        // The impersonated client is unknown here; the second ticket
        // identifies it.
        if options.contains(GcOptions::CONSTRAINED_DELEGATION) {
            m.client = None;
        }
        from_cache(&ccache.retrieve(fields, &m, Some(ktypes))?)
    }

    /// Store `cred` in `ccache` (`krb5_cc_store_cred`), with the request's
    /// second ticket as `krb5_get_cred_via_tkt_ext` copies it.
    pub(super) fn store_cred<C: Ccache>(
        ccache: &mut C,
        cred: &Credential,
        second_ticket: Option<&Ticket>,
    ) -> Result<(), Krb5Error> {
        let mut cc = CcCredential::from(cred);
        if let Some(t) = second_ticket {
            cc.second_ticket = rasn::der::encode(t)?;
        }
        Ok(ccache.store(&cc)?)
    }

    /// `get_cached_tgt` (get_creds.c:759-795): an unexpired TGT for
    /// `realm`, whatever realm issued it. Only KRB5_CC_NOT_KTYPE is an
    /// error.
    fn get_cached_tgt<C: Ccache>(
        &self,
        ccache: &C,
        req: &CredsRequest,
        realm: &str,
    ) -> Result<Option<Credential>, Krb5Error> {
        let m = MatchCred {
            client: Some((req.client.clone(), req.crealm.clone())),
            server: Some((tgt_name(realm), realm.to_string())),
            endtime: now(),
            ..MatchCred::default()
        };
        let flags = MatchFlags::SUPPORTED_KTYPES | MatchFlags::SRV_NAMEONLY | MatchFlags::TIMES;
        match ccache.retrieve(flags, &m, Some(&self.tgs_options.etypes)) {
            Ok(c) => from_cache(&c).map(Some),
            Err(CcError::NotKtype) => Err(CcError::NotKtype.into()),
            Err(_) => Ok(None),
        }
    }

    /// `get_cached_local_tgt` (get_creds.c:797-838).
    fn get_cached_local_tgt<C: Ccache>(
        &self,
        ccache: &C,
        req: &CredsRequest,
    ) -> Result<Credential, Krb5Error> {
        let m = MatchCred {
            client: Some((req.client.clone(), req.crealm.clone())),
            server: Some((tgt_name(&req.crealm), req.crealm.clone())),
            ..MatchCred::default()
        };
        let tgt = ccache.retrieve(
            MatchFlags::SUPPORTED_KTYPES,
            &m,
            Some(&self.tgs_options.etypes),
        )?;
        if now() > tgt.endtime {
            return Err(ApError::TktExpired.into());
        }
        from_cache(&tgt)
    }

    /// Get a credential through `ccache` (MIT `krb5_get_credentials`,
    /// get_creds.c:1042-1330): the cached credential for `req` if there is
    /// one, else a TGS exchange from the cached TGT for the server's realm
    /// or the client's local TGT. A TGT obtained for the server's realm is
    /// cached (get_creds.c:951-954), and the result is cached unless
    /// [`GcOptions::NO_STORE`]; it names the requested server and carries
    /// the requested authdata (`complete`, get_creds.c:450-472). Each
    /// `k5_canonprinc` candidate for the server is tried while the KDC
    /// answers "server not found".
    ///
    /// Constrained delegation goes through
    /// [`KerberosClient::get_credentials_for_proxy`].
    pub async fn get_credentials<C: Ccache>(
        &self,
        ccache: &mut C,
        options: GcOptions,
        req: &CredsRequest,
    ) -> Result<Credential, Krb5Error> {
        if options.contains(GcOptions::CONSTRAINED_DELEGATION) {
            return Err(invalid(
                "constrained delegation requires get_credentials_for_proxy",
            ));
        }
        // check_cache (get_creds.c:1042-1068).
        match self.get_cached_cred(options, ccache, req) {
            Ok(cred) => return Ok(cred),
            Err(e) if !is_cache_miss(&e) || options.contains(GcOptions::CACHED) => return Err(e),
            Err(_) => {}
        }
        if options.contains(GcOptions::USER_USER) {
            return Err(invalid("user-to-user TGS requests are not supported"));
        }
        let tgs = self.gc_tgs_options(options);
        let mut iter = CanonPrinc::new(&req.server);
        let mut last = None;
        while let Some(server) = iter.next(&self.host_canon).await {
            match self.tkt_creds(ccache, req, server, tgs.clone()).await {
                Err(Krb5Error::KdcError(m)) if m.error_code == S_PRINCIPAL_UNKNOWN => {
                    last = Some(Krb5Error::KdcError(m));
                }
                Err(e) => return Err(e),
                Ok(mut cred) => {
                    cred.server = req.server.clone();
                    cred.srealm = req.srealm.clone();
                    cred.authdata = req.authdata.clone();
                    if !options.contains(GcOptions::NO_STORE) {
                        let _ = Self::store_cred(ccache, &cred, None);
                    }
                    return Ok(cred);
                }
            }
        }
        Err(last.unwrap_or(invalid("no candidate server principal")))
    }

    /// `begin` through the referral states for one server candidate.
    async fn tkt_creds<C: Ccache>(
        &self,
        ccache: &mut C,
        req: &CredsRequest,
        server: PrincipalName,
        tgs: TgsOptions,
    ) -> Result<Credential, Krb5Error> {
        // An unspecified server realm starts with the TGT realm.
        let srealm = if req.srealm.is_empty() {
            &req.crealm
        } else {
            &req.srealm
        };
        // begin_get_tgt (get_creds.c:987-1030).
        let local = *srealm == req.crealm;
        let mut tgt = None;
        if !local {
            tgt = self.get_cached_tgt(ccache, req, srealm)?;
        }
        let tgt = match tgt {
            Some(tgt) => tgt,
            None => {
                let local_tgt = self.get_cached_local_tgt(ccache, req)?;
                if local {
                    local_tgt
                } else {
                    let tgt = self
                        .run_tgs(TgsExchange::new(local_tgt, tgt_name(srealm), tgs.clone()))
                        .await?;
                    if tgt.server.name_string == tgt_name(srealm).name_string {
                        let _ = Self::store_cred(ccache, &tgt, None);
                    }
                    tgt
                }
            }
        };
        self.run_tgs(TgsExchange::new(tgt, server, tgs).with_authdata(req.authdata.clone()))
            .await
    }
}
