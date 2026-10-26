//! S4U at the credential-cache layer (MIT s4u_creds.c
//! `krb5_get_credentials_for_user`, `k5_get_proxy_cred_from_kdc`).

use std::time::Duration;

use super::canonprinc::CanonPrinc;
use super::{KerberosClient, MAX_EXCHANGE_STEPS};
use crate::protocol::{
    AsExchange, AsExchangeConfig, Credential, StepResult, TgsExchange, TgsOptions, TgsStepResult,
};
use crate::transport::KdcTransport;
use crate::types::{KdcOptions, KerberosFlags, PrincipalName};
use crate::Krb5Error;

/// `KRB5_NT_ENTERPRISE_PRINCIPAL`.
const NT_ENTERPRISE: i32 = 10;
/// `KRB5KDC_ERR_S_PRINCIPAL_UNKNOWN`.
const S_PRINCIPAL_UNKNOWN: i32 = 7;

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

    /// S4U2Self (`krb5_get_credentials_for_user`, s4u_creds.c:653-720):
    /// a ticket to the service holding `tgt` for `user`. The user's realm
    /// comes from `s4u_identify_user` (s4u_creds.c:40-87): `user_realm` for
    /// a named user, the service realm for the anonymous principal, and for
    /// an enterprise name (type 10) an AS probe starting in the service
    /// realm that follows client referrals (`k5_identify_realm`).
    pub async fn get_credentials_for_user(
        &self,
        tgt: &Credential,
        user: &PrincipalName,
        user_realm: &str,
        options: TgsOptions,
    ) -> Result<Credential, Krb5Error> {
        let realm = self.s4u_identify_user(tgt, user, user_realm).await?;
        self.run_tgs(TgsExchange::s4u2self(
            tgt.clone(),
            user.clone(),
            realm,
            options,
        ))
        .await
    }

    async fn s4u_identify_user(
        &self,
        tgt: &Credential,
        user: &PrincipalName,
        user_realm: &str,
    ) -> Result<String, Krb5Error> {
        if user.name_type != NT_ENTERPRISE {
            let anonymous = user_realm == "WELLKNOWN:ANONYMOUS"
                && user.name_string.len() == 2
                && user.name_string[0].as_bytes() == b"WELLKNOWN"
                && user.name_string[1].as_bytes() == b"ANONYMOUS";
            return Ok(if anonymous {
                tgt.crealm.clone()
            } else {
                user_realm.to_string()
            });
        }
        // k5_identify_realm (get_in_tkt.c:2053-2090).
        let mut config = AsExchangeConfig::new(user.clone(), tgt.crealm.clone());
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

    /// S4U2Proxy (`k5_get_proxy_cred_from_kdc`, s4u_creds.c:1132-1190): try
    /// each `k5_canonprinc` candidate for `target` (with `no_hostrealm`)
    /// while the KDC answers "server not found". The credential names
    /// `target` as requested.
    pub async fn get_credentials_for_proxy(
        &self,
        tgt: &Credential,
        evidence: &Credential,
        target: &PrincipalName,
        options: TgsOptions,
    ) -> Result<Credential, Krb5Error> {
        let mut iter = CanonPrinc::new(target);
        let mut last = None;
        while let Some(server) = iter.next(&self.host_canon).await {
            let exchange =
                TgsExchange::s4u2proxy(tgt.clone(), evidence.clone(), server, options.clone());
            match self.run_tgs(exchange).await {
                Ok(mut cred) => {
                    cred.server = target.clone();
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
