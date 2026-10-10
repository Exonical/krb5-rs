//! PKINIT in AS-REQ processing (MIT pkinit_srv.c driven by kdc_preauth.c:
//! `check_padata`, `get_preauth_hint_list`, `return_padata`, freshness tokens
//! :507-565 and :827-905, `filter_preauth_error` :1092-1134).

#[cfg(feature = "pkinit")]
mod imp {
    use chrono::{DateTime, Utc};
    use rasn::types::OctetString;

    use crate::crypto::{find_etype, key_usage};
    use crate::kdc::db::{KvnoSel, PrincipalEntry};
    use crate::kdc::error::KdcError;
    use crate::kdc::{Kdc, PrincipalStore};
    pub(in crate::kdc) use crate::pkinit::server::Verified;
    use crate::pkinit::server::{
        self, RequestInfo, PA_AS_FRESHNESS, PA_PKINIT_KX, PA_PK_AS_REP, PA_PK_AS_REQ,
    };
    use crate::types::error_codes::*;
    use crate::types::{EncryptionKey, KdcReq, PaData};

    /// `FRESHNESS_LIFETIME` (kdc_preauth.c:90).
    const FRESHNESS_LIFETIME: i64 = 600;

    /// `filter_preauth_error`: only these module errors reach the client.
    pub(crate) fn filter_preauth_error(code: i32) -> i32 {
        match code {
            0
            | KRB_AP_ERR_BAD_INTEGRITY
            | KRB_AP_ERR_SKEW
            | KDC_ERR_PREAUTH_REQUIRED
            | KDC_ERR_ETYPE_NOSUPP
            | KDC_ERR_CLIENT_NOT_TRUSTED
            | KDC_ERR_INVALID_SIG
            | KDC_ERR_DH_KEY_PARAMETERS_NOT_ACCEPTED
            | KDC_ERR_CANT_VERIFY_CERTIFICATE
            | KDC_ERR_INVALID_CERTIFICATE
            | KDC_ERR_REVOKED_CERTIFICATE
            | KDC_ERR_REVOCATION_STATUS_UNKNOWN
            | KDC_ERR_CLIENT_NAME_MISMATCH
            | KDC_ERR_INCONSISTENT_KEY_PURPOSE
            | KDC_ERR_DIGEST_IN_CERT_NOT_ACCEPTED
            | KDC_ERR_PA_CHECKSUM_MUST_BE_INCLUDED
            | KDC_ERR_DIGEST_IN_SIGNED_DATA_NOT_ACCEPTED
            | KDC_ERR_PUBLIC_KEY_ENCRYPTION_NOT_SUPPORTED
            | KDC_ERR_CERTIFICATE_MISMATCH
            | KDC_ERR_KDC_NOT_TRUSTED
            | KDC_ERR_REVOCATION_STATUS_UNAVAILABLE
            | 100 // KDC_ERR_NO_ACCEPTABLE_KDF
            | 91 => code, // KDC_ERR_MORE_PREAUTH_DATA_REQUIRED
            _ => KDC_ERR_PREAUTH_FAILED,
        }
    }

    impl<S: PrincipalStore> Kdc<S> {
        /// Module hints for PREAUTH_REQUIRED/PREAUTH_FAILED e-data:
        /// PA-PK-AS-REQ and PA-PKINIT-KX (empty), then a PA-AS-FRESHNESS token
        /// when the request carried an empty PA-AS-FRESHNESS
        /// (`pkinit_server_get_edata` :384-409, `add_freshness_token`).
        pub(in crate::kdc) fn pkinit_hint_extras(
            &self,
            request: &KdcReq,
            local_tgt: &PrincipalEntry,
            now: DateTime<Utc>,
        ) -> Result<Vec<PaData>, KdcError> {
            if self.config.pkinit.is_none() {
                return Ok(Vec::new());
            }
            let empty = |t: i32| PaData {
                padata_type: t,
                padata_value: OctetString::from(Vec::new()),
            };
            let mut out = vec![empty(PA_PK_AS_REQ), empty(PA_PKINIT_KX)];
            let asked = request
                .padata
                .iter()
                .flatten()
                .any(|p| p.padata_type == PA_AS_FRESHNESS);
            if asked {
                out.push(PaData {
                    padata_type: PA_AS_FRESHNESS,
                    padata_value: OctetString::from(self.freshness_token(local_tgt, now)?),
                });
            }
            Ok(out)
        }

        /// Token = timestamp || krbtgt kvno || checksum of the timestamp
        /// under the local TGT key, usage 514.
        fn freshness_token(
            &self,
            local_tgt: &PrincipalEntry,
            now: DateTime<Utc>,
        ) -> Result<Vec<u8>, KdcError> {
            let key = local_tgt
                .find_key(None, KvnoSel::Highest, &self.permitted())
                .ok_or_else(|| KdcError::generic("FRESHNESS_TOKEN"))?;
            let profile =
                find_etype(key.key.keytype).map_err(|_| KdcError::generic("FRESHNESS_TOKEN"))?;
            let ts = u32::try_from(now.timestamp()).unwrap_or(0).to_be_bytes();
            let sum = profile
                .checksum(key.key.key_bytes(), key_usage::PA_AS_FRESHNESS, &ts)
                .map_err(|_| KdcError::generic("FRESHNESS_TOKEN"))?;
            let mut token = ts.to_vec();
            token.extend_from_slice(&key.kvno.to_be_bytes());
            token.extend(sum);
            Ok(token)
        }

        /// `check_freshness_token` (kdc_preauth.c:513-565).
        fn freshness_valid(
            &self,
            local_tgt: &PrincipalEntry,
            token: &[u8],
            now: DateTime<Utc>,
        ) -> bool {
            if token.len() <= 8 {
                return false;
            }
            let ts = i64::from(u32::from_be_bytes([token[0], token[1], token[2], token[3]]));
            let kvno = u32::from_be_bytes([token[4], token[5], token[6], token[7]]);
            if now.timestamp() > ts + FRESHNESS_LIFETIME {
                return false;
            }
            local_tgt.keys.iter().filter(|k| k.kvno == kvno).any(|k| {
                find_etype(k.key.keytype).is_ok_and(|p| {
                    p.verify_checksum(
                        k.key.key_bytes(),
                        key_usage::PA_AS_FRESHNESS,
                        &token[..4],
                        &token[8..],
                    )
                    .is_ok()
                })
            })
        }

        /// Verify a PA-PK-AS-REQ. `None` when PKINIT is not configured (the
        /// padata is then not recognised).
        #[allow(clippy::too_many_arguments)]
        pub(in crate::kdc) fn pkinit_verify(
            &self,
            pa: &PaData,
            request: &KdcReq,
            raw: &[u8],
            body_der: &[u8],
            local_tgt: &PrincipalEntry,
            now: DateTime<Utc>,
        ) -> Option<Result<Verified, KdcError>> {
            if pa.padata_type != PA_PK_AS_REQ {
                return None;
            }
            let cfg = self.config.pkinit.as_ref()?;
            let body = &request.req_body;
            let (Some(client), Some(server_name)) = (body.cname.as_ref(), body.sname.as_ref())
            else {
                return Some(Err(KdcError::new(KDC_ERR_PREAUTH_FAILED, "PREAUTH_FAILED")));
            };
            let info = RequestInfo {
                body_der,
                as_req_der: raw,
                client,
                realm: &self.config.realm,
                server: server_name,
                nonce: body.nonce,
                etypes: &body.etype,
            };
            let skew = i64::try_from(self.config.clockskew.as_secs()).unwrap_or(i64::MAX);
            let result =
                server::verify(cfg, pa.padata_value.as_ref(), &info, now, skew, &|token| {
                    self.freshness_valid(local_tgt, token, now)
                });
            Some(result.map_err(|f| {
                let code = filter_preauth_error(f.code);
                let mut err = KdcError::new(code, "PREAUTH_FAILED");
                if code == f.code && !f.e_data.is_empty() {
                    let items = f
                        .e_data
                        .into_iter()
                        .map(|(t, v)| PaData {
                            padata_type: t,
                            padata_value: OctetString::from(v),
                        })
                        .collect();
                    if let Ok(typed) = err.clone().with_typed_e_data(items) {
                        err = typed;
                    }
                }
                err
            }))
        }

        /// `pkinit_server_return_padata`: the PA-PK-AS-REP and the replacement
        /// reply key.
        pub(in crate::kdc) fn pkinit_return(
            &self,
            verified: &Verified,
            request: &KdcReq,
            raw: &[u8],
            body_der: &[u8],
        ) -> Result<(PaData, EncryptionKey), KdcError> {
            let cfg = self
                .config
                .pkinit
                .as_ref()
                .ok_or_else(|| KdcError::generic("PKINIT_NOT_CONFIGURED"))?;
            let body = &request.req_body;
            let (Some(client), Some(server_name)) = (body.cname.as_ref(), body.sname.as_ref())
            else {
                return Err(KdcError::new(KDC_ERR_PREAUTH_FAILED, "PREAUTH_FAILED"));
            };
            let info = RequestInfo {
                body_der,
                as_req_der: raw,
                client,
                realm: &self.config.realm,
                server: server_name,
                nonce: body.nonce,
                etypes: &body.etype,
            };
            let (value, key) = server::reply(cfg, verified, &info)
                .map_err(|e| KdcError::new(filter_preauth_error(e.code), "PREAUTH_FAILED"))?;
            Ok((
                PaData {
                    padata_type: PA_PK_AS_REP,
                    padata_value: OctetString::from(value),
                },
                key,
            ))
        }
    }
}

#[cfg(not(feature = "pkinit"))]
mod imp {
    use chrono::{DateTime, Utc};

    use crate::kdc::db::PrincipalEntry;
    use crate::kdc::error::KdcError;
    use crate::kdc::{Kdc, PrincipalStore};
    use crate::types::{EncryptionKey, KdcReq, PaData};

    /// Uninhabited without the `pkinit` feature.
    pub(in crate::kdc) enum Verified {}

    impl<S: PrincipalStore> Kdc<S> {
        pub(in crate::kdc) fn pkinit_hint_extras(
            &self,
            _request: &KdcReq,
            _local_tgt: &PrincipalEntry,
            _now: DateTime<Utc>,
        ) -> Result<Vec<PaData>, KdcError> {
            Ok(Vec::new())
        }

        pub(in crate::kdc) fn pkinit_verify(
            &self,
            _pa: &PaData,
            _request: &KdcReq,
            _raw: &[u8],
            _body_der: &[u8],
            _local_tgt: &PrincipalEntry,
            _now: DateTime<Utc>,
        ) -> Option<Result<Verified, KdcError>> {
            None
        }

        pub(in crate::kdc) fn pkinit_return(
            &self,
            verified: &Verified,
            _request: &KdcReq,
            _raw: &[u8],
            _body_der: &[u8],
        ) -> Result<(PaData, EncryptionKey), KdcError> {
            match *verified {}
        }
    }
}
