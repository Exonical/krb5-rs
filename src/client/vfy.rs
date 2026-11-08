//! `krb5_verify_init_creds` (MIT `lib/krb5/krb/vfy_increds.c`).

use super::creds::same_principal;
use super::{CredsRequest, GcOptions, KerberosClient};
use crate::ccache::{CcCredential, Ccache, MemoryCcache};
use crate::error::Krb5Error;
use crate::keytab::{FileKeytab, Keytab, KtError, MemoryKeytab};
use crate::profile::{conf_boolean, Profile};
use crate::protocol::ap::{ApReqOptions, AuthContext, AuthContextFlags, KeySource};
use crate::protocol::Credential;
use crate::transport::KdcTransport;
use crate::types::PrincipalName;

/// `DEFKTNAME`.
pub const DEFAULT_KEYTAB_NAME: &str = "FILE:/etc/krb5.keytab";

/// A keytab usable for verification: enumerable and a key source.
pub trait VerifyKeytab: Keytab {
    /// The keytab as an AP-REQ key source.
    fn key_source(&self) -> &dyn KeySource;
}

impl<T: Keytab + KeySource> VerifyKeytab for T {
    fn key_source(&self) -> &dyn KeySource {
        self
    }
}

/// `krb5_verify_init_creds_opt`.
#[derive(Debug, Clone, Copy, Default)]
pub struct VerifyInitCredsOptions<'a> {
    /// `KRB5_VERIFY_INIT_CREDS_OPT_AP_REQ_NOFAIL`; `None` reads
    /// `verify_ap_req_nofail` from `profile`.
    pub ap_req_nofail: Option<bool>,
    /// The profile for `verify_ap_req_nofail` and `default_keytab_name`.
    pub profile: Option<&'a Profile>,
}

/// `krb5int_libdefault_boolean`: `[libdefaults] realm = { name }`, then
/// `[libdefaults] name`.
fn libdefault_boolean(profile: &Profile, realm: &str, name: &str) -> Option<bool> {
    profile
        .get_string(&["libdefaults", realm, name])
        .or_else(|| profile.get_string(&["libdefaults", name]))
        .and_then(|s| conf_boolean(&s))
}

/// `nofail` (vfy_increds.c:33-45).
fn nofail(opts: &VerifyInitCredsOptions<'_>, creds: &Credential) -> bool {
    if let Some(v) = opts.ap_req_nofail {
        return v;
    }
    opts.profile
        .and_then(|p| libdefault_boolean(p, &creds.crealm, "verify_ap_req_nofail"))
        .unwrap_or(false)
}

/// `krb5_kt_default_name`: `KRB5_KTNAME`, then `default_keytab_name`,
/// then [`DEFAULT_KEYTAB_NAME`].
pub fn default_keytab_name(profile: Option<&Profile>) -> String {
    std::env::var("KRB5_KTNAME")
        .ok()
        .or_else(|| profile.and_then(|p| p.get_string(&["libdefaults", "default_keytab_name"])))
        .unwrap_or_else(|| DEFAULT_KEYTAB_NAME.to_string())
}

/// `krb5_kt_default`: the FILE, WRFILE or MEMORY keytab named by
/// [`default_keytab_name`].
pub fn default_keytab(profile: Option<&Profile>) -> Result<Box<dyn VerifyKeytab>, Krb5Error> {
    resolve_keytab(&default_keytab_name(profile))
}

/// `krb5_kt_resolve` for the FILE, WRFILE and MEMORY types; a name with
/// no type prefix (or a one-letter one, a DOS drive) is a FILE path.
pub fn resolve_keytab(name: &str) -> Result<Box<dyn VerifyKeytab>, Krb5Error> {
    Ok(match name.split_once(':') {
        Some(("FILE" | "WRFILE", rest)) => Box::new(FileKeytab::new(rest)),
        Some(("MEMORY", rest)) => Box::new(MemoryKeytab::resolve(rest)),
        Some((t, _)) if t.len() > 1 && !t.contains('/') => {
            return Err(Krb5Error::Protocol(format!("unsupported keytab type {t}")));
        }
        _ => Box::new(FileKeytab::new(name)),
    })
}

/// `copy_creds_except` (vfy_increds.c:47-80).
fn copy_creds_except(
    from: &MemoryCcache,
    to: &mut dyn Ccache,
    princ: &PrincipalName,
    realm: &str,
) -> Result<(), Krb5Error> {
    for c in from.creds()? {
        if !same_principal(&c.server, &c.srealm, princ, realm) {
            to.store(&c)?;
        }
    }
    Ok(())
}

impl<T: KdcTransport> KerberosClient<T> {
    /// `get_vfy_cred` (vfy_increds.c:82-182).
    async fn get_vfy_cred<'c>(
        &self,
        creds: &Credential,
        server: (&PrincipalName, &str),
        keytab: &dyn VerifyKeytab,
        out: Option<&mut (dyn Ccache + 'c)>,
    ) -> Result<(), Krb5Error> {
        let mut cache = None;
        let ap_req = if same_principal(&creds.server, &creds.srealm, server.0, server.1) {
            AuthContext::new().mk_req(&ApReqOptions::default(), None, creds)?
        } else {
            let mut cc = MemoryCcache::new();
            cc.initialize(&creds.client, &creds.crealm)?;
            cc.store(&CcCredential::from(creds))?;
            let req = CredsRequest::new(
                creds.client.clone(),
                creds.crealm.clone(),
                server.0.clone(),
                server.1,
            );
            let svc = self
                .get_credentials(&mut cc, GcOptions::empty(), &req)
                .await?;
            let ap = AuthContext::new().mk_req(&ApReqOptions::default(), None, &svc)?;
            cache = Some(cc);
            ap
        };

        // No replay checks: we would only be replaying to ourselves.
        let mut ac = AuthContext::new();
        ac.set_flags(AuthContextFlags::empty());
        ac.rd_req(&ap_req, Some(server.0), keytab.key_source())?;

        if let (Some(out), Some(cc)) = (out, cache) {
            if out.principal().is_err() {
                out.initialize(&creds.client, &creds.crealm)?;
                copy_creds_except(&cc, out, &creds.server, &creds.srealm)?;
            } else {
                copy_creds_except(&cc, out, server.0, server.1)?;
            }
        }
        Ok(())
    }

    /// `krb5_verify_init_creds`: check that `creds` came from the real
    /// KDC by getting a ticket for `server` (or each `host/*` principal
    /// in `keytab`) and decrypting it with `keytab` (the default keytab
    /// when `None`). Credentials obtained on the way are stored in `out`,
    /// initializing it if needed. Without a usable key this succeeds
    /// unless `ap_req_nofail` is set.
    pub async fn verify_init_creds(
        &self,
        creds: &Credential,
        server: Option<(&PrincipalName, &str)>,
        keytab: Option<&dyn VerifyKeytab>,
        mut out: Option<&mut dyn Ccache>,
        opts: &VerifyInitCredsOptions<'_>,
    ) -> Result<(), Krb5Error> {
        let default;
        let keytab: &dyn VerifyKeytab = match keytab {
            Some(k) => k,
            None => {
                default = default_keytab(opts.profile)?;
                default.as_ref()
            }
        };
        let mut have_keys = false;
        let ret = async {
            if let Some(server) = server {
                keytab.get_entry(server.0, server.1, None, None)?;
                have_keys = true;
                return self.get_vfy_cred(creds, server, keytab, out).await;
            }
            let mut hosts: Vec<(PrincipalName, String)> = Vec::new();
            for e in keytab.entries()? {
                let is_host = e.principal.name_string.len() == 2
                    && e.principal.name_string[0].as_bytes() == b"host";
                if is_host
                    && !hosts
                        .iter()
                        .any(|(p, r)| same_principal(p, r, &e.principal, &e.realm))
                {
                    hosts.push((e.principal, e.realm));
                }
            }
            if hosts.is_empty() {
                return Err(KtError::NotFound.into());
            }
            have_keys = true;
            let mut ret = Ok(());
            for (p, r) in &hosts {
                ret = self
                    .get_vfy_cred(creds, (p, r), keytab, out.as_deref_mut())
                    .await;
                if ret.is_ok() {
                    break;
                }
            }
            ret
        }
        .await;
        if !have_keys && !nofail(opts, creds) {
            return Ok(());
        }
        ret
    }
}
