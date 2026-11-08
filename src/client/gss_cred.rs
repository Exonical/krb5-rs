//! GSS S4U glue: gss_acquire_cred_impersonate_name (s4u_gss_glue.c) and
//! the initiator's ticket for a target from a credential handle, with
//! S4U2Proxy for proxy credentials (init_sec_context.c `get_credentials`).

use super::creds::{same_principal, CredsRequest, GcOptions};
use super::vfy::{default_keytab_name, resolve_keytab, VerifyInitCredsOptions};
use super::KerberosClient;
use crate::ccache::{new_unique, resolve, AnyCcache, CcContext, CcCredential, Ccache};
use crate::gssapi::cred::{CredCache, CredUsage, GssCred, GssName};
use crate::gssapi::GssError;
use crate::profile::Profile;
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

/// The krb5 mechanism's cred-store keys (gssapiP_krb5.h KRB5_CS_*_URN).
#[derive(Debug, Clone, Default)]
pub struct CredStore {
    /// `ccache`.
    pub ccache: Option<String>,
    /// `client_keytab`.
    pub client_keytab: Option<String>,
    /// `keytab`.
    pub keytab: Option<String>,
    /// `rcache`.
    pub rcache: Option<String>,
    /// `password`.
    pub password: Option<String>,
    /// `verify`: verify a password TGT with this principal's key (empty for
    /// the default host principal).
    pub verify: Option<String>,
}

impl<T: KdcTransport> KerberosClient<T> {
    /// gss_acquire_cred_from (acquire_cred.c:1199-1336): validate the cred
    /// store as MIT does, then make an initiator credential from the
    /// password (optionally verified against `verify`'s key in `keytab`),
    /// the `ccache`, or the default cache, and record the acceptor keytab
    /// and rcache.
    pub async fn acquire_cred_from(
        &self,
        ctx: &CcContext,
        profile: Option<&Profile>,
        name: Option<&PrincipalName>,
        usage: CredUsage,
        store: &CredStore,
        iakerb: bool,
    ) -> Result<GssCred, Krb5Error> {
        let fail = || gss(GssError::Failure);
        if let Some(c) = &store.ccache {
            resolve(ctx, c).map_err(|_| gss(GssError::NoCred))?;
        }
        for kt in [&store.client_keytab, &store.keytab].into_iter().flatten() {
            resolve_keytab(kt).map_err(|_| gss(GssError::NoCred))?;
        }
        if store.password.is_some() {
            if name.is_none() {
                return Err(gss(GssError::BadName));
            }
            if usage == CredUsage::Accept || store.ccache.is_some() || store.client_keytab.is_some()
            {
                return Err(fail());
            }
        }
        let verify = match &store.verify {
            None => None,
            Some(_) if iakerb || store.password.is_none() => return Err(fail()),
            Some(v) if v.is_empty() => Some(None),
            Some(v) => Some(Some(
                crate::ccache::parse_principal(v, Some(&self.realm)).ok_or_else(fail)?,
            )),
        };
        let mut cred = GssCred::empty(usage);
        if usage != CredUsage::Initiate {
            cred.keytab = Some(
                store
                    .keytab
                    .clone()
                    .unwrap_or_else(|| default_keytab_name(profile)),
            );
            cred.rcache = store.rcache.clone();
        }
        if usage == CredUsage::Accept {
            cred.name = name.map(|n| GssName::principal(n.clone(), self.realm.clone()));
            return Ok(cred);
        }
        let mut init = if let Some(password) = &store.password {
            let client = name.ok_or(gss(GssError::BadName))?.clone();
            let (cache, tgt) = self
                .acquire_cred_with_password(ctx, client, password)
                .await?;
            if let Some(vp) = &verify {
                let kt = match &store.keytab {
                    Some(k) => Some(resolve_keytab(k)?),
                    None => None,
                };
                let opts = VerifyInitCredsOptions {
                    profile,
                    ..Default::default()
                };
                let server = vp.as_ref().map(|(n, r)| (n, r.as_str()));
                self.verify_init_creds(&tgt, server, kt.as_deref(), None, &opts)
                    .await?;
            }
            let mut c = GssCred::from_ccache(ctx, &cache.name())?;
            c.password = Some(password.clone());
            c
        } else {
            let ccname = match &store.ccache {
                Some(c) => c.clone(),
                None => crate::ccache::default_cache(ctx)
                    .map_err(|_| gss(GssError::NoCred))?
                    .name(),
            };
            let c = GssCred::from_ccache(ctx, &ccname)?;
            if let (Some(want), Some((have, _))) = (name, c.principal()) {
                if want.name_string != have.name_string {
                    return Err(gss(GssError::NoCred));
                }
            }
            c
        };
        init.usage = usage;
        init.keytab = cred.keytab;
        init.rcache = cred.rcache;
        init.client_keytab = store.client_keytab.clone();
        init.iakerb_mech = iakerb;
        Ok(init)
    }

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
    /// S4U2Proxy; IAKERB credentials only look in the cache.  Tickets
    /// fetched for a MEMORY credential are kept in `cred`, as in MIT's
    /// in-process cache.
    pub async fn gss_service_cred(
        &self,
        ctx: &CcContext,
        cred: &mut GssCred,
        server: PrincipalName,
        srealm: &str,
    ) -> Result<Credential, Krb5Error> {
        let (out, cache) = self.service_cred_inner(ctx, cred, server, srealm).await;
        if let (Some(CredCache::Memory { creds, .. }), Some(cache)) = (&mut cred.ccache, cache) {
            if let Ok(now) = cache.creds() {
                *creds = now;
            }
            let _ = cache.destroy();
        }
        out
    }

    async fn service_cred_inner(
        &self,
        ctx: &CcContext,
        cred: &GssCred,
        server: PrincipalName,
        srealm: &str,
    ) -> (Result<Credential, Krb5Error>, Option<AnyCcache>) {
        let mut cache = match open_cache(ctx, cred) {
            Ok(c) => c,
            Err(e) => return (Err(e), None),
        };
        let out = self
            .service_cred_with(&mut cache, cred, server, srealm)
            .await;
        let keep = matches!(cred.ccache, Some(CredCache::Memory { .. })).then_some(cache);
        (out, keep)
    }

    async fn service_cred_with(
        &self,
        cache: &mut AnyCcache,
        cred: &GssCred,
        server: PrincipalName,
        srealm: &str,
    ) -> Result<Credential, Krb5Error> {
        let (name, realm) = cred.principal().ok_or(gss(GssError::NoCred))?.clone();
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
                // init_sec_context.c:186-190: IAKERB only looks in the cache.
                let mut proxy_flags = GcOptions::CANONICALIZE;
                if cred.iakerb_mech {
                    proxy_flags |= GcOptions::CACHED;
                }
                let evidence = Credential::try_from(evidence)
                    .map_err(|_| gss(GssError::DefectiveCredential))?;
                let out = self
                    .get_credentials_for_proxy(cache, proxy_flags, &req, &evidence)
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
        self.get_credentials(cache, flags, &req).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gssapi::GssError;
    use crate::transport::UdpTransport;

    fn major(e: Krb5Error) -> Option<GssError> {
        match e {
            Krb5Error::Gss(g) => Some(g),
            _ => None,
        }
    }

    #[tokio::test]
    async fn acquire_cred_from_validates_store_like_mit() {
        let client = KerberosClient::new(
            "EXAMPLE.COM",
            UdpTransport::new("127.0.0.1:9".parse().expect("addr")),
        );
        let ctx = CcContext::default();
        let user = crate::ccache::parse_principal("user", Some("EXAMPLE.COM"))
            .expect("principal")
            .0;
        let pw = CredStore {
            password: Some("pw".into()),
            ..Default::default()
        };
        let err = client
            .acquire_cred_from(&ctx, None, None, CredUsage::Initiate, &pw, false)
            .await
            .expect_err("must fail");
        assert_eq!(major(err), Some(GssError::BadName));
        for (usage, store) in [
            (CredUsage::Accept, pw.clone()),
            (
                CredUsage::Initiate,
                CredStore {
                    ccache: Some("MEMORY:x".into()),
                    ..pw.clone()
                },
            ),
            (
                CredUsage::Initiate,
                CredStore {
                    verify: Some(String::new()),
                    ..Default::default()
                },
            ),
        ] {
            let err = client
                .acquire_cred_from(&ctx, None, Some(&user), usage, &store, false)
                .await
                .expect_err("must fail");
            assert_eq!(major(err), Some(GssError::Failure));
        }
        let iakerb = CredStore {
            verify: Some(String::new()),
            ..pw.clone()
        };
        let err = client
            .acquire_cred_from(&ctx, None, Some(&user), CredUsage::Initiate, &iakerb, true)
            .await
            .expect_err("must fail");
        assert_eq!(major(err), Some(GssError::Failure));
        let accept = CredStore {
            keytab: Some("MEMORY:acf".into()),
            rcache: Some("none:".into()),
            ..Default::default()
        };
        let cred = client
            .acquire_cred_from(&ctx, None, Some(&user), CredUsage::Accept, &accept, false)
            .await
            .expect("accept cred");
        assert_eq!(cred.keytab.as_deref(), Some("MEMORY:acf"));
        assert_eq!(cred.rcache.as_deref(), Some("none:"));
    }
}
