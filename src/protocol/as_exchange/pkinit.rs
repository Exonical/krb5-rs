//! PKINIT in the AS exchange (MIT pkinit_clnt.c `pkinit_client_process`
//! :903-1000, `pkinit_client_tryagain` :1006-1070).

use super::*;
use crate::pkinit::cms::PkinitError;
use crate::pkinit::server::{
    decode_typed_data, PA_AS_FRESHNESS, PA_PK_AS_REP, PA_PK_AS_REQ, TD_DH_PARAMETERS,
};
use crate::pkinit::{client, Group};
use crate::types::KrbErrorMsg;

/// Pkinit error codes that end the exchange unless a retry applies
/// (KDC_ERR_CLIENT_NOT_TRUSTED .. KDC_ERR_PUBLIC_KEY_ENCRYPTION_NOT_SUPPORTED).
const PKINIT_ERROR_RANGE: std::ops::RangeInclusive<i32> = 62..=81;

fn pkinit_error(e: PkinitError) -> Krb5Error {
    Krb5Error::Crypto(format!("PKINIT: {e}"))
}

impl AsExchange {
    /// Remember the freshness token offered in the KDC's method data
    /// (`KRB5_PADATA_AS_FRESHNESS` case of `pkinit_client_process`, :930).
    pub(super) fn note_freshness(&mut self, method: &[PaData]) {
        if let Some(pa) = method.iter().find(|p| p.padata_type == PA_AS_FRESHNESS) {
            self.freshness_token = Some(pa.padata_value.as_ref().to_vec());
        }
    }

    /// Whether PKINIT can answer a method-data list.
    pub(super) fn pkinit_offered(&self, method: &[PaData]) -> bool {
        self.config.pkinit.is_some()
            && !self.preauth_failed.contains(&PA_PK_AS_REQ)
            && method.iter().any(|p| p.padata_type == PA_PK_AS_REQ)
    }

    /// Replace the placeholder PA-PK-AS-REQ with the real value, computed
    /// over the request body (`pa_pkinit_gen_req`, :56-150).
    pub(super) fn fill_pkinit(
        &mut self,
        padata: Option<Vec<PaData>>,
        req_body: &KdcReqBody,
    ) -> Result<Option<Vec<PaData>>, Krb5Error> {
        let (Some(cfg), Some(mut list)) = (self.config.pkinit.clone(), padata) else {
            return Ok(None);
        };
        let Some(slot) = list
            .iter_mut()
            .find(|p| p.padata_type == PA_PK_AS_REQ && p.padata_value.is_empty())
        else {
            return Ok(Some(list));
        };
        let body_der = rasn::der::encode(req_body)?;
        let (ctime, cusec) = self.preauth_time(true);
        let (value, keypair) = client::build_request(
            &cfg,
            self.pkinit_group,
            &body_der,
            self.nonce,
            ctime,
            cusec,
            self.freshness_token.as_deref(),
        )
        .map_err(pkinit_error)?;
        slot.padata_value = value.into();
        self.pkinit_keypair = Some(keypair);
        Ok(Some(list))
    }

    /// Derive the reply key from a PA-PK-AS-REP in the reply padata
    /// (`pa_pkinit_parse_rep`, :288-340). `None` when the reply carries none.
    pub(super) fn pkinit_reply_key(
        &self,
        rep: &KdcRep,
    ) -> Result<Option<EncryptionKey>, Krb5Error> {
        let Some(pa) = rep
            .padata
            .iter()
            .flatten()
            .find(|p| p.padata_type == PA_PK_AS_REP)
        else {
            return Ok(None);
        };
        let (Some(cfg), Some(keypair)) = (&self.config.pkinit, &self.pkinit_keypair) else {
            return Err(Krb5Error::ReplyValidation(
                "PA-PK-AS-REP without a PKINIT request",
            ));
        };
        let server = PrincipalName::new_srv_inst("krbtgt", &self.config.realm);
        client::process_reply(
            cfg,
            keypair,
            pa.padata_value.as_ref(),
            &self.last_req_bytes,
            &self.config.client,
            &server,
            &self.config.realm,
            rep.enc_part.etype,
            chrono::Utc::now(),
        )
        .map(Some)
        .map_err(pkinit_error)
    }

    /// PKINIT error handling (`pkinit_client_tryagain`): retry with the
    /// KDC's key exchange group on KDC_ERR_DH_KEY_PARAMETERS_NOT_ACCEPTED;
    /// other PKINIT errors end the exchange.
    pub(super) fn pkinit_error(
        &mut self,
        err: &KrbErrorMsg,
        err_padata: Option<&[PaData]>,
    ) -> Option<Result<StepResult, Krb5Error>> {
        if self.selected_preauth_type != Some(PA_PK_AS_REQ)
            || !PKINIT_ERROR_RANGE.contains(&err.error_code)
        {
            return None;
        }
        if err.error_code == KDC_ERR_DH_KEY_PARAMETERS_NOT_ACCEPTED {
            let typed: Vec<(i32, Vec<u8>)> = err_padata
                .map(|l| {
                    l.iter()
                        .map(|p| (p.padata_type, p.padata_value.as_ref().to_vec()))
                        .collect()
                })
                .filter(|l: &Vec<_>| l.iter().any(|(t, _)| *t == TD_DH_PARAMETERS))
                .or_else(|| {
                    err.e_data
                        .as_ref()
                        .and_then(|d| decode_typed_data(d.as_ref()))
                })
                .unwrap_or_default();
            let next = client::find_td_dh(&typed)
                .and_then(|td| client::negotiate_group(self.pkinit_group, td));
            if let (Some(group), true) = (next, self.loop_count < MAX_PREAUTH_LOOPS) {
                self.pkinit_group = group;
                self.loop_count += 1;
                return Some(self.send_preauth_request());
            }
        }
        Some(Err(Krb5Error::from_error_msg(err.clone())))
    }

    /// The initial key exchange group from the configuration.
    pub(super) fn initial_pkinit_group(config: &AsExchangeConfig) -> Group {
        config
            .pkinit
            .as_ref()
            .map_or(Group::Modp2048, |c| c.dh_group)
    }
}
