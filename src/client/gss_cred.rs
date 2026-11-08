//! GSS S4U glue: gss_acquire_cred_impersonate_name (s4u_gss_glue.c) and
//! the initiator's ticket for a target from a credential handle, with
//! S4U2Proxy for proxy credentials (init_sec_context.c `get_credentials`).

use super::creds::{same_principal, CredsRequest, GcOptions};
use super::KerberosClient;
use crate::ccache::{new_unique, resolve, AnyCcache, CcContext, CcCredential, Ccache};
use crate::gssapi::cred::{CredCache, CredUsage, GssCred};
use crate::gssapi::GssError;
use crate::protocol::Credential;
use crate::transport::KdcTransport;
use crate::types::PrincipalName;
use crate::Krb5Error;

fn gss(e: GssError) -> Krb5Error {
    Krb5Error::Gss(e)
}

/// The credential's cache: the named cache, or a new MEMORY cache holding
/// the exported contents.
fn open_cache(ctx: &CcContext, cred: &GssCred) -> Result<AnyCcache, Krb5Error> {
    let fail = |_| gss(GssError::Failure);
    match &cred.ccache {
        None => Err(gss(GssError::NoCred)),
        Some(CredCache::Named(name)) => resolve(ctx, name).map_err(fail),
        Some(CredCache::Memory { principal, creds }) => {
            let mut cache = new_unique(ctx, "MEMORY").map_err(fail)?;
            cache.initialize(&principal.0, &principal.1).map_err(fail)?;
            for c in creds {
                cache.store(c).map_err(fail)?;
            }
            Ok(cache)
        }
    }
}

impl<T: KdcTransport> KerberosClient<T> {
    /// gss_acquire_cred_impersonate_name (s4u_gss_glue.c:38-170): an
    /// S4U2Self ticket for `user` to the impersonator, composed into a proxy
    /// credential.
    pub async fn acquire_cred_impersonate_name(
        &self,
        ctx: &CcContext,
        imp: &GssCred,
        user: &PrincipalName,
        user_realm: &str,
    ) -> Result<GssCred, Krb5Error> {
        if !matches!(imp.usage, CredUsage::Initiate | CredUsage::Both) {
            return Err(gss(GssError::NoCred));
        }
        let (iname, irealm) = imp.principal().ok_or(gss(GssError::NoCred))?.clone();
        let mut cache = open_cache(ctx, imp)?;
        let mut req = CredsRequest::new(user.clone(), user_realm, iname, &irealm);
        if let Some(&e) = imp.req_enctypes.as_ref().and_then(|e| e.first()) {
            req.enctype = e;
        }
        let cred = self
            .get_credentials_for_user(
                &mut cache,
                GcOptions::CANONICALIZE | GcOptions::NO_STORE,
                &req,
                None,
            )
            .await
            .map_err(|_| gss(GssError::Failure))?;
        imp.compose_deleg_cred(ctx, &CcCredential::from(&cred))
    }

    /// The service ticket gss_init_sec_context uses for `server` with
    /// `cred` (init_sec_context.c:120-215): with a proxy credential, the
    /// evidence ticket itself when `server` is the impersonator, else
    /// S4U2Proxy; IAKERB credentials only look in the cache.  A MEMORY
    /// credential's cache is a copy, so new tickets are not kept in `cred`.
    pub async fn gss_service_cred(
        &self,
        ctx: &CcContext,
        cred: &GssCred,
        server: PrincipalName,
        srealm: &str,
    ) -> Result<Credential, Krb5Error> {
        let (name, realm) = cred.principal().ok_or(gss(GssError::NoCred))?.clone();
        let mut cache = open_cache(ctx, cred)?;
        let req = CredsRequest::new(name.clone(), &realm, server.clone(), srealm);
        let mut flags = GcOptions::empty();
        if let Some((imp, imp_realm)) = &cred.impersonator {
            if same_principal(imp, imp_realm, &server, srealm) {
                flags |= GcOptions::CACHED;
            } else {
                let creds = cache.creds().map_err(|_| gss(GssError::Failure))?;
                let evidence = creds
                    .iter()
                    .find(|c| {
                        c.authdata.is_empty()
                            && same_principal(&c.client, &c.crealm, &name, &realm)
                            && same_principal(&c.server, &c.srealm, imp, imp_realm)
                    })
                    .ok_or(gss(GssError::NoCred))?;
                let evidence = Credential::try_from(evidence)
                    .map_err(|_| gss(GssError::DefectiveCredential))?;
                let out = self
                    .get_credentials_for_proxy(&mut cache, GcOptions::CANONICALIZE, &req, &evidence)
                    .await?;
                if !same_principal(&out.client, &out.crealm, &name, &realm) {
                    return Err(gss(GssError::Failure));
                }
                return Ok(out);
            }
        }
        if cred.iakerb_mech {
            flags |= GcOptions::CACHED;
        }
        self.get_credentials(&mut cache, flags, &req).await
    }
}
