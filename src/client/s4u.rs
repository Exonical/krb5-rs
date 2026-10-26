//! S4U at the credential-cache layer (MIT s4u_creds.c
//! `krb5_get_credentials_for_user`, `k5_get_proxy_cred_from_kdc`).

use std::time::Duration;

use super::canonprinc::CanonPrinc;
use super::creds::{
    is_cache_miss, same_principal, tgt_name, CredsRequest, GcOptions, S_PRINCIPAL_UNKNOWN,
};
use super::{KerberosClient, MAX_EXCHANGE_STEPS};
use crate::ccache::Ccache;
use crate::protocol::{
    AsExchange, AsExchangeConfig, Credential, StepResult, TgsExchange, TgsStepResult,
};
use crate::transport::KdcTransport;
use crate::types::{KdcOptions, KerberosFlags, PrincipalName};
use crate::Krb5Error;

/// `KRB5_NT_ENTERPRISE_PRINCIPAL`.
const NT_ENTERPRISE: i32 = 10;

impl<T: KdcTransport> KerberosClient<T> {
    pub(super) async fn run_tgs(&self, mut exchange: TgsExchange) -> Result<Credential, Krb5Error> {
        let mut kdc_reply = Vec::new();
        for _ in 0..MAX_EXCHANGE_STEPS {
            match exchange.step(&kdc_reply)? {
                TgsStepResult::SendToKdc { data, realm } => {
                    kdc_reply = self.transport.send_recv(&realm, &data).await?;
                }
                TgsStepResult::RetryTcp { .. } => {
                    return Err(Krb5Error::ReplyValidation(
                        "TGS exchange requested TCP retry, but the client transport cannot \
                         explicitly force TCP; configure TcpTransport or UdpTcpTransport",
                    ));
                }
                TgsStepResult::Complete => return exchange.credential().cloned(),
            }
        }
        Err(Krb5Error::ReplyValidation(
            "TGS exchange did not complete within step limit",
        ))
    }

    /// S4U2Self (`krb5_get_credentials_for_user`, s4u_creds.c:648-735):
    /// a ticket to `req.server@req.srealm` (the service whose TGT is in
    /// `ccache`) for `req.client@req.crealm`. The cache is checked for the
    /// requested user, then (for an enterprise name) for the user in the
    /// discovered realm, and, when the KDC returns a different user, for
    /// that user. The user's realm comes from `s4u_identify_user`
    /// (s4u_creds.c:40-87): `req.crealm` for a named user, the service
    /// realm for the anonymous principal, and for an enterprise name (type
    /// 10) an AS probe starting in the service realm that follows client
    /// referrals (`k5_identify_realm`). The TGT to the user's realm comes
    /// from [`KerberosClient::get_credentials`] (s4u_creds.c:473-484). The
    /// result is stored unless [`GcOptions::NO_STORE`].
    pub async fn get_credentials_for_user<C: Ccache>(
        &self,
        ccache: &mut C,
        mut options: GcOptions,
        req: &CredsRequest,
    ) -> Result<Credential, Krb5Error> {
        if options.contains(GcOptions::CONSTRAINED_DELEGATION) {
            return Err(Krb5Error::ReplyValidation(
                "constrained delegation is not S4U2Self",
            ));
        }
        // Uncanonicalized check.
        match self.get_cached_cred(options, ccache, req) {
            Ok(cred) => return Ok(cred),
            Err(e) if !is_cache_miss(&e) || options.contains(GcOptions::CACHED) => return Err(e),
            Err(_) => {}
        }
        let realm = self
            .s4u_identify_user(&req.srealm, &req.client, &req.crealm)
            .await?;
        if req.client.name_type == NT_ENTERPRISE {
            // Post-canonicalization check for enterprise principals.
            let mut m = req.clone();
            m.crealm.clone_from(&realm);
            match self.get_cached_cred(options, ccache, &m) {
                Err(e) if is_cache_miss(&e) => {}
                r => return r,
            }
        }
        // krb5_get_self_cred_from_kdc (s4u_creds.c:420-640).
        let tgtq = CredsRequest::new(
            req.server.clone(),
            req.srealm.clone(),
            tgt_name(&realm),
            req.srealm.clone(),
        );
        let tgt = self.get_credentials(ccache, options, &tgtq).await?;
        let mut cred = self
            .run_tgs(
                TgsExchange::s4u2self(tgt, req.client.clone(), realm, self.gc_tgs_options(options))
                    .with_authdata(req.authdata.clone()),
            )
            .await?;
        // A canonicalized user may already have cached credentials.
        if !same_principal(&req.client, &req.crealm, &cred.client, &cred.crealm) {
            let mut m = req.clone();
            m.client = cred.client.clone();
            m.crealm = cred.crealm.clone();
            match self.get_cached_cred(options, ccache, &m) {
                Ok(old) => {
                    cred = old;
                    options |= GcOptions::NO_STORE;
                }
                Err(e) if is_cache_miss(&e) => {}
                Err(e) => return Err(e),
            }
        }
        cred.authdata = req.authdata.clone();
        if !options.contains(GcOptions::NO_STORE) {
            Self::store_cred(ccache, &cred, None)?;
        }
        Ok(cred)
    }

    async fn s4u_identify_user(
        &self,
        service_realm: &str,
        user: &PrincipalName,
        user_realm: &str,
    ) -> Result<String, Krb5Error> {
        if user.name_type != NT_ENTERPRISE {
            let anonymous = user_realm == "WELLKNOWN:ANONYMOUS"
                && user.name_string.len() == 2
                && user.name_string[0].as_bytes() == b"WELLKNOWN"
                && user.name_string[1].as_bytes() == b"ANONYMOUS";
            return Ok(if anonymous {
                service_realm.to_string()
            } else {
                user_realm.to_string()
            });
        }
        // k5_identify_realm (get_in_tkt.c:2053-2090).
        let mut config = AsExchangeConfig::new(user.clone(), service_realm);
        config.kdc_options = KerberosFlags::new(KdcOptions::CANONICALIZE);
        config.tkt_lifetime = Duration::from_secs(15);
        config.renew_lifetime = Duration::ZERO;
        config.identify_realm = true;
        let mut exchange = AsExchange::new(config, "");
        let mut kdc_reply = Vec::new();
        for _ in 0..MAX_EXCHANGE_STEPS {
            match exchange.step(&kdc_reply)? {
                StepResult::SendToKdc { data, realm } => {
                    kdc_reply = self.transport.send_recv(&realm, &data).await?;
                }
                StepResult::RetryTcp { .. } => {
                    return Err(Krb5Error::ReplyValidation(
                        "KDC requested TCP retry, but the client transport cannot \
                         explicitly force TCP; configure TcpTransport or UdpTcpTransport",
                    ));
                }
                StepResult::Complete => return Ok(exchange.client_realm().to_string()),
            }
        }
        Err(Krb5Error::ReplyValidation(
            "AS exchange did not complete within step limit",
        ))
    }

    /// S4U2Proxy (`krb5_get_credentials_for_proxy`, s4u_creds.c:1195-1260):
    /// a ticket to `req.server@req.srealm` for `req.client@req.crealm`,
    /// the client of `evidence`, a ticket to the service whose TGT is in
    /// `ccache`. As in `k5_get_proxy_cred_from_kdc` (s4u_creds.c:1148-1190),
    /// the cache is checked by server and evidence ticket, each
    /// `k5_canonprinc` candidate for the server (with `no_hostrealm`) is
    /// tried while the KDC answers "server not found", the credential
    /// names the server as requested, and it is stored unless
    /// [`GcOptions::NO_STORE`]. The service's TGT comes from
    /// [`KerberosClient::get_credentials`] (`get_client_tgt`).
    pub async fn get_credentials_for_proxy<C: Ccache>(
        &self,
        ccache: &mut C,
        options: GcOptions,
        req: &CredsRequest,
        evidence: &Credential,
    ) -> Result<Credential, Krb5Error> {
        if !same_principal(&evidence.client, &evidence.crealm, &req.client, &req.crealm) {
            return Err(Krb5Error::ReplyValidation(
                "evidence ticket is for another client",
            ));
        }
        let mut s4u = req.clone();
        s4u.client = evidence.server.clone();
        s4u.crealm = evidence.srealm.clone();
        s4u.second_ticket = Some(evidence.ticket.clone());
        let cred = self
            .get_proxy_cred_from_kdc(
                ccache,
                options | GcOptions::CONSTRAINED_DELEGATION,
                &s4u,
                evidence,
            )
            .await?;
        if !same_principal(&req.client, &req.crealm, &cred.client, &cred.crealm) {
            return Err(Krb5Error::ReplyValidation("S4U reply was modified"));
        }
        Ok(cred)
    }

    async fn get_proxy_cred_from_kdc<C: Ccache>(
        &self,
        ccache: &mut C,
        options: GcOptions,
        req: &CredsRequest,
        evidence: &Credential,
    ) -> Result<Credential, Krb5Error> {
        match self.get_cached_cred(options, ccache, req) {
            Err(e) if is_cache_miss(&e) && !options.contains(GcOptions::CACHED) => {}
            r => return r,
        }
        let options = options - GcOptions::CONSTRAINED_DELEGATION;
        let mut iter = CanonPrinc::new(&req.server);
        let mut last = None;
        while let Some(server) = iter.next(&self.host_canon).await {
            // get_client_tgt (s4u_creds.c:786-805).
            let tgtq = CredsRequest::new(
                req.client.clone(),
                req.crealm.clone(),
                tgt_name(&req.crealm),
                req.crealm.clone(),
            );
            let tgt = self.get_credentials(ccache, options, &tgtq).await?;
            let exchange =
                TgsExchange::s4u2proxy(tgt, evidence.clone(), server, self.gc_tgs_options(options))
                    .with_authdata(req.authdata.clone());
            match self.run_tgs(exchange).await {
                Ok(mut cred) => {
                    cred.server = req.server.clone();
                    cred.srealm = req.srealm.clone();
                    cred.authdata = req.authdata.clone();
                    if !options.contains(GcOptions::NO_STORE) {
                        let _ = Self::store_cred(ccache, &cred, req.second_ticket.as_ref());
                    }
                    return Ok(cred);
                }
                Err(Krb5Error::KdcError(m)) if m.error_code == S_PRINCIPAL_UNKNOWN => {
                    last = Some(Krb5Error::KdcError(m));
                }
                Err(e) => return Err(e),
            }
        }
        Err(last.unwrap_or(Krb5Error::ReplyValidation("no candidate server principal")))
    }
}
