//! AS-REQ processing (MIT do_as_req.c `process_as_req` /
//! `finish_process_as_req`, kdc_preauth.c `check_padata` /
//! `return_padata`).

use chrono::{DateTime, Utc};
use rasn::types::OctetString;

use super::authdata::include_pac_p;
use super::cookie::CookieState;
use super::db::{KvnoSel, PrincipalAttributes, PrincipalEntry};
use super::error::{general_string, ErrorContext, KdcError};
use super::fast::{anonymous_client, FastInputs};
use super::policy::{
    get_ticket_endtime, get_ticket_flags, get_ticket_renewtime, kerberos_time,
    select_session_keytype, ts, validate_as_request, Times, KDC_INFINITY,
};
use super::preauth::{
    enc_pa_rep_padata, encrypted_challenge_padata, etype_info2_padata, find_padata, hint_list_with,
    select_client_key, verify_enc_timestamp, verify_encrypted_challenge,
};
use super::reqbody::raw_req_body;
use super::spake::{self as kdc_spake, SpakeOutcome, KDC_ERR_MORE_PREAUTH_DATA_REQUIRED};
use super::{is_tgs_principal, random_key, GateSubject, Kdc, PrincipalRole, PrincipalStore};
use crate::crypto::{find_etype, fx_cf2, key_usage};
use crate::protocol::ap::encrypt_ticket_part;
use crate::types::error_codes::*;
use crate::types::{
    is_anonymous_name, AsRep, EncAsRepPart, EncKdcRepPart, EncTicketPart, EncryptedData,
    EncryptionKey, KdcOptions, KdcRep, KdcReq, KerberosFlags, LastReqEntry, PaData, PaDataType,
    PrincipalName, TicketFlags, TransitedEncoding, ANONYMOUS_REALM,
};

/// `KRB5_NT_X500_PRINCIPAL`.
const NT_X500_PRINCIPAL: i32 = 6;

/// `KRB5_PADATA_PKINIT_KX`.
const PA_PKINIT_KX: i32 = 147;

/// MIT `get_key_exp` (do_as_req.c:83-91).
fn key_expiration(entry: &PrincipalEntry) -> Option<i64> {
    let exp = entry.expiration.as_ref().map(ts).filter(|&t| t != 0);
    let pw = entry.pw_expiration.as_ref().map(ts).filter(|&t| t != 0);
    match (exp, pw) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, b) => a.or(b),
    }
}

fn optional_time(t: i64) -> Option<crate::types::KerberosTime> {
    (t != 0).then(|| kerberos_time(t))
}

impl<S: PrincipalStore> Kdc<S> {
    /// MIT `process_as_req` (do_as_req.c:470-767) and
    /// `finish_process_as_req` (:194-423), then the KDB audit hook
    /// (`log_as_req` -> `krb5_db_audit_as_req`, kdc_log.c:93): lockout
    /// counters see every outcome once the client is known.
    pub(super) async fn process_as_req(
        &self,
        req: &KdcReq,
        raw: &[u8],
        now: DateTime<Utc>,
        ctx: &mut ErrorContext,
    ) -> Result<Vec<u8>, KdcError> {
        let mut audited: Option<PrincipalEntry> = None;
        let result = self
            .process_as_req_inner(req, raw, now, ctx, &mut audited)
            .await;
        if let Some(client) = audited {
            let code = result.as_ref().map_or_else(|e| e.code, |_| 0);
            self.audit_as(&client, now.timestamp(), code).await;
        }
        result
    }

    async fn process_as_req_inner(
        &self,
        req: &KdcReq,
        raw: &[u8],
        now: DateTime<Utc>,
        ctx: &mut ErrorContext,
        audited: &mut Option<PrincipalEntry>,
    ) -> Result<Vec<u8>, KdcError> {
        let kdc_time = now.timestamp();
        if req.msg_type != 10 {
            return Err(KdcError::generic("VALIDATE_MESSAGE_TYPE"));
        }

        // kdc_find_fast (do_as_req.c:526-536): later processing uses the inner
        // request; the PA-REQ-ENC-PA-REP checksum still covers `raw`.
        let outer_body =
            raw_req_body(raw).map_err(|_| KdcError::new(KRB_ERR_GENERIC, "FIND_FAST"))?;
        let inner = self
            .find_fast(
                req,
                FastInputs {
                    checksummed: outer_body,
                    tgs_subkey: None,
                    tgs_session: None,
                },
                now,
                &mut ctx.fast,
            )
            .await
            .map_err(|e| KdcError {
                e_text: Some("FIND_FAST".into()),
                ..e
            })?;
        let request = inner.as_ref().unwrap_or(req);
        let fast = ctx.fast.take();
        *ctx = self.request_context(request, true);
        ctx.fast = fast;
        if !self.audit.is_empty() {
            ctx.audit_req = inner.clone().map(Box::new);
        }
        if request.req_body.realm.as_bytes() != self.config.realm.as_bytes() {
            return Err(KdcError::new(KDC_ERR_WRONG_REALM, "WRONG_REALM"));
        }
        let body = &request.req_body;
        let realm = &self.config.realm;
        let opts: KdcOptions = *body.kdc_options;

        let cname = body
            .cname
            .as_ref()
            .ok_or_else(|| KdcError::new(KDC_ERR_C_PRINCIPAL_UNKNOWN, "NULL_CLIENT"))?;
        let sname = body
            .sname
            .as_ref()
            .ok_or_else(|| KdcError::new(KDC_ERR_S_PRINCIPAL_UNKNOWN, "NULL_SERVER"))?;

        // lookup_client (do_as_req.c:133-151): a certificate in
        // PA-S4U-X509-USER identifies an X.500 client, and may refer it.
        let cert = request
            .padata
            .iter()
            .flatten()
            .find(|p| p.padata_type == super::s4u::PA_S4U_X509_USER)
            .map(|p| p.padata_value.as_ref())
            .filter(|c| !c.is_empty() && cname.name_type == NT_X500_PRINCIPAL);
        let found = match cert {
            Some(c) => {
                self.lookup_s4u_x509(c, cname, realm, true, "LOOKING_UP_CLIENT")
                    .await?
            }
            None => self.lookup(cname, realm, "LOOKING_UP_CLIENT").await?,
        };
        let client =
            found.ok_or_else(|| KdcError::new(KDC_ERR_C_PRINCIPAL_UNKNOWN, "CLIENT_NOT_FOUND"))?;
        *audited = Some(client.clone());
        ctx.audit_stage = crate::kdc::plugins::AuditStage::SrvcPrinc;
        let server = self
            .lookup(sname, realm, "LOOKING_UP_SERVER")
            .await?
            .ok_or_else(|| KdcError::new(KDC_ERR_S_PRINCIPAL_UNKNOWN, "SERVER_NOT_FOUND"))?;
        // The store returned a client from another realm (a KDB alias): a
        // client referral if KRB5_KDB_FLAG_REFERRAL_OK (do_as_req.c:575-577,
        // 609-616), with the canonical client in the error (:806).
        if client.realm != server.realm {
            if !(opts.contains(KdcOptions::CANONICALIZE) || cname.name_type == 10 || cert.is_some())
            {
                return Err(KdcError::new(
                    KDC_ERR_C_PRINCIPAL_UNKNOWN,
                    "CLIENT_NOT_FOUND",
                ));
            }
            ctx.crealm = Some(client.realm.clone());
            ctx.cname = Some(client.name.clone());
            return Err(KdcError::new(KDC_ERR_WRONG_REALM, "REFERRAL"));
        }
        let local_tgt = self.require_local_tgt().await?;
        self.consistency_gate(&[
            GateSubject {
                entry: &client,
                role: PrincipalRole::Client,
            },
            GateSubject {
                entry: &server,
                role: PrincipalRole::Server,
            },
        ])
        .await?;

        ctx.audit_stage = crate::kdc::plugins::AuditStage::ValidatePol;
        validate_as_request(opts, &client, &server, kdc_time)?;
        // check_anon (kdc_util.c:701-712, :795-798).
        if self.config.restrict_anonymous_to_tgt
            && is_anonymous_name(&client.name)
            && !is_local_tgs(sname, realm)
        {
            return Err(KdcError::new(KDC_ERR_POLICY, "ANONYMOUS NOT ALLOWED"));
        }
        // Anonymous requests (do_as_req.c:716-733): the client becomes
        // WELLKNOWN/ANONYMOUS@WELLKNOWN:ANONYMOUS and must preauthenticate.
        let anonymous = opts.contains(KdcOptions::REQUEST_ANONYMOUS);
        if anonymous && !is_anonymous_name(cname) {
            return Err(KdcError::new(
                KDC_ERR_BADOPTION,
                "VALIDATE_ANONYMOUS_PRINCIPAL",
            ));
        }
        let client = if anonymous {
            let mut c = client;
            c.attributes |= PrincipalAttributes::REQUIRES_PRE_AUTH;
            c
        } else {
            client
        };
        // krb5_db_check_policy_as, the last step of validate_as_request
        // (kdc_util.c:801).
        self.check_lockout(&client, kdc_time).await?;
        // kdc_fast_read_cookie (do_as_req.c:747), keyed to the request client.
        let cookie_client = super::kdb::mit::unparse_name(cname, realm);
        let mut cookies = CookieState::read(
            request.padata.as_deref(),
            &local_tgt,
            &cookie_client,
            kdc_time,
        )?;

        let permitted = self.permitted();
        ctx.audit_stage = crate::kdc::plugins::AuditStage::IssueTkt;
        let session_etype = select_session_keytype(&server, &body.etype, &permitted)
            .ok_or_else(|| KdcError::new(KDC_ERR_ETYPE_NOSUPP, "BAD_ENCRYPTION_TYPE"))?;
        let session_key = random_key(session_etype)?;

        let canonicalize = opts.contains(KdcOptions::CANONICALIZE);
        let tkt_sname = if canonicalize && is_tgs_principal(sname) && is_tgs_principal(&server.name)
        {
            server.name.clone()
        } else {
            sname.clone()
        };
        let tkt_cname = if anonymous {
            anonymous_client()?.1
        } else if canonicalize {
            client.name.clone()
        } else {
            cname.clone()
        };

        let mut flags = get_ticket_flags(opts, Some(&client), &server, None);
        let limits = self.limits();
        let req_till = ts(&body.till);
        let req_rtime = body.rtime.as_ref().map(ts).unwrap_or(0);
        let mut times = Times {
            authtime: kdc_time,
            // do_as_req.c:692-695.
            starttime: if opts.contains(KdcOptions::POSTDATED) {
                body.from.as_ref().map(ts).unwrap_or(0)
            } else {
                kdc_time
            },
            endtime: 0,
            renew_till: 0,
        };
        times.endtime = get_ticket_endtime(
            &limits,
            times.starttime,
            KDC_INFINITY,
            req_till,
            Some(&client),
            &server,
        );
        get_ticket_renewtime(
            &limits,
            opts,
            req_rtime,
            req_till,
            None,
            Some(&client),
            &server,
            &mut flags,
            &mut times,
        );
        if times.starttime == times.authtime {
            times.starttime = 0;
        }

        let client_key = select_client_key(&client, &body.etype, &permitted);
        let armored_request = ctx.fast.as_ref().is_some_and(|f| f.armor_key.is_some());
        // The body PKINIT checksums cover: the inner request's when armored
        // (`cb->request_body`), else the raw body.
        let pk_body_der: Vec<u8> = if armored_request {
            rasn::der::encode(&request.req_body)?
        } else {
            outer_body.to_vec()
        };
        let pk_extras = self.pkinit_hint_extras(request, &local_tgt, now)?;
        let mut pkinit_verified = None;

        // check_padata (kdc_preauth.c:1336-1377, 1176-1207).
        let armored = ctx.fast.as_ref().and_then(|f| f.armor_key.clone());
        let mut pa_found = false;
        let mut pa_ok = false;
        let mut saved: Option<KdcError> = None;
        let mut kdc_challenge_key = None;
        let mut spake_key: Option<EncryptionKey> = None;
        let mut spake_more: Option<PaData> = None;
        let mut otp_indicators: Option<Vec<String>> = None;
        let client_unparsed = crate::ccache::unparse_name(&client.name, &client.realm);
        for pa in request.padata.iter().flatten() {
            let verified = if pa.padata_type == PaDataType::EncTimestamp as i32 {
                verify_enc_timestamp(pa, &client, &permitted, kdc_time, self.config.clockskew)
                    .map(|()| None)
            } else if pa.padata_type == PaDataType::EncryptedChallenge as i32 {
                verify_encrypted_challenge(
                    pa,
                    &client,
                    &body.etype,
                    &permitted,
                    armored.as_ref(),
                    kdc_time,
                    self.config.clockskew,
                )
                .map(Some)
            } else if pa.padata_type == crate::spake::PA_SPAKE
                && !self.config.spake_groups.is_empty()
            {
                match kdc_spake::verify(
                    pa.padata_value.as_ref(),
                    &self.config.spake_groups,
                    client_key.as_ref().map(|k| &k.entry.key),
                    &pk_body_der,
                    &mut cookies,
                ) {
                    Ok(SpakeOutcome::Verified(k0)) => {
                        spake_key = Some(k0);
                        Ok(None)
                    }
                    Ok(SpakeOutcome::Challenge(ch)) => {
                        spake_more.get_or_insert(ch);
                        Err(KdcError::new(
                            KDC_ERR_MORE_PREAUTH_DATA_REQUIRED,
                            "MORE_PREAUTH_DATA_REQUIRED",
                        ))
                    }
                    Err(e) => Err(e),
                }
            } else if let (true, Some(types)) = (
                pa.padata_type == crate::otp::PA_OTP_REQUEST,
                self.config.otp_token_types.as_deref(),
            ) {
                super::otp::verify(
                    types,
                    pa.padata_value.as_ref(),
                    armored.as_ref(),
                    &client_unparsed,
                    client.otp.as_deref(),
                    kdc_time,
                    self.config.clockskew,
                )
                .await
                .map(|ind| {
                    otp_indicators = Some(ind);
                    None
                })
            } else if pa.padata_type == crate::sam2::PA_SAM_RESPONSE_2
                && self.securid_sam2.is_some()
            {
                // verify_*_data_2 set TKT_FLG_HW_AUTH on success.
                self.sam2_verify(pa, &client).await.map(|()| {
                    flags |= TicketFlags::HW_AUTHENT;
                    None
                })
            } else {
                match self.pkinit_verify(
                    pa,
                    request,
                    raw,
                    &pk_body_der,
                    &local_tgt,
                    client.pkinit_cert_match.as_deref(),
                    now,
                ) {
                    None => continue,
                    Some(Ok(v)) => {
                        // pkinit_srv.c:602-603.
                        if super::pkinit::hw_authent(&v) {
                            flags |= TicketFlags::HW_AUTHENT;
                        }
                        pkinit_verified = Some(v);
                        Ok(None)
                    }
                    Some(Err(e)) => Err(e),
                }
            };
            pa_found = true;
            match verified {
                Ok(challenge_key) => {
                    pa_ok = true;
                    flags |= TicketFlags::PRE_AUTHENT;
                    kdc_challenge_key = kdc_challenge_key.or(challenge_key);
                }
                Err(e) => {
                    saved.get_or_insert(e);
                }
            }
        }
        let hw_only = client
            .attributes
            .contains(PrincipalAttributes::REQUIRES_HW_AUTH);
        let is_armored = armored.is_some();
        // otp_edata (otp/main.c:219-275): principals with an `otp` string
        // attribute, armored requests only; not offered to hardware-only
        // clients (no PA_HARDWARE, kdc_preauth.c:956).
        let otp_hint = match (&self.config.otp_token_types, &client.otp, &armored) {
            (Some(_), Some(_), Some(k)) if !hw_only => Some(super::otp::challenge(k, kdc_time)?),
            _ => None,
        };
        // spake_edata (spake_kdc.c), skipped for hardware-only clients.
        let spake_hint = |cookies: &mut CookieState| {
            if self.config.spake_groups.is_empty() || hw_only {
                return None;
            }
            kdc_spake::edata(
                self.config.spake_challenge,
                client_key.as_ref().map(|k| &k.entry.key),
                cookies,
            )
            .ok()
            .flatten()
        };
        if let (true, false, Some(mut err)) = (pa_found, pa_ok, saved) {
            // finish_preauth (do_as_req.c:434-466): PREAUTH_FAILED carries
            // the hint list.
            // maybe_add_etype_info2 (kdc_preauth.c:1149-1172) and the cookie
            // every error's e-data carries (do_as_req.c:785-795).
            if err.code == KDC_ERR_MORE_PREAUTH_DATA_REQUIRED {
                let mut list: Vec<PaData> = spake_more.into_iter().collect();
                if find_padata(request.padata.as_deref(), PaDataType::FxCookie).is_none() {
                    if let Some(ck) = &client_key {
                        list.push(etype_info2_padata(&client, ck)?);
                    }
                }
                list.push(cookies.make(&local_tgt, &cookie_client, kdc_time)?);
                err = err.with_e_data(rasn::der::encode(&list)?);
            }
            if err.code == KDC_ERR_PREAUTH_FAILED {
                let extras = self
                    .hint_extras(&pk_extras, &client, client_key.as_ref(), kdc_time)
                    .await;
                err = err.with_e_data(hint_list_with(
                    &client,
                    client_key.as_ref(),
                    hw_only,
                    is_armored,
                    &extras,
                    otp_hint.clone(),
                    spake_hint(&mut cookies),
                    cookies.make(&local_tgt, &cookie_client, kdc_time)?,
                )?);
            }
            return Err(err);
        }

        // missing_required_preauth (kdc_preauth.c:729-752).
        let missing = if client
            .attributes
            .contains(PrincipalAttributes::REQUIRES_PRE_AUTH)
            && !flags.contains(TicketFlags::PRE_AUTHENT)
        {
            Some("NEEDED_PREAUTH")
        } else if hw_only && !flags.contains(TicketFlags::HW_AUTHENT) {
            Some("NEEDED_HW_PREAUTH")
        } else {
            None
        };
        if let Some(status) = missing {
            let extras = self
                .hint_extras(&pk_extras, &client, client_key.as_ref(), kdc_time)
                .await;
            return Err(KdcError::new(KDC_ERR_PREAUTH_REQUIRED, status).with_e_data(
                hint_list_with(
                    &client,
                    client_key.as_ref(),
                    hw_only,
                    is_armored,
                    &extras,
                    otp_hint.clone(),
                    spake_hint(&mut cookies),
                    cookies.make(&local_tgt, &cookie_client, kdc_time)?,
                )?,
            ));
        }

        let server_key = server
            .find_key(None, KvnoSel::Highest, &permitted)
            .ok_or_else(|| KdcError::generic("FINDING_SERVER_KEY"))?;
        let replaced = match &pkinit_verified {
            Some(v) => Some(self.pkinit_return(v, request, raw, &pk_body_der)?),
            None => None,
        };
        // replace_reply_key(armor key, is_strengthen = FALSE) from OTP
        // (otp/main.c:162-165): no etype-info2 for the replaced key.
        let otp_key = armored.clone().filter(|_| otp_indicators.is_some());
        let client_key = client_key.filter(|_| replaced.is_none() && otp_key.is_none());
        let (reply_etype, base_key) = match (&replaced, &client_key) {
            (Some((_, key)), _) => (key.keytype, key.clone()),
            (None, _) if otp_key.is_some() => {
                let k = otp_key
                    .clone()
                    .ok_or_else(|| KdcError::generic("OTP_KEY"))?;
                (k.keytype, k)
            }
            (None, Some(ck)) => (ck.etype, ck.entry.key.clone()),
            (None, None) => {
                return Err(KdcError::new(KDC_ERR_ETYPE_NOSUPP, "CANT_FIND_CLIENT_KEY"))
            }
        };
        // replace_reply_key(is_strengthen = TRUE) from SPAKE: K'[0] is the
        // reply key; etype-info2 is still returned.
        let base_key = spake_key.clone().unwrap_or(base_key);

        // return_padata (kdc_preauth.c:1438-1493): module padata (the KDC
        // challenge), then etype-info2 for the key.
        let mut reply_padata = Vec::new();
        if let Some(key) = &kdc_challenge_key {
            reply_padata.push(encrypted_challenge_padata(key, now)?);
        }
        if let Some((pa, _)) = &replaced {
            // A replaced reply key gets no etype-info (kdc_preauth.c:1476-1488).
            reply_padata.push(pa.clone());
        } else if let Some(ck) = &client_key {
            reply_padata.push(etype_info2_padata(&client, ck)?);
        }

        // return_pkinit_kx (pkinit_srv.c:626-680): an anonymous reply carries
        // the KDC's contribution to the session key, which becomes
        // KRB-FX-CF2(session, "PKINIT", reply key, "KEYEXCHANGE").
        let session_key = if anonymous {
            reply_padata.push(pkinit_kx_padata(&session_key, &base_key)?);
            fx_cf2(&session_key, b"PKINIT", &base_key, b"KEYEXCHANGE")
                .map_err(|_| KdcError::generic("PKINIT_KX"))?
        } else {
            session_key
        };
        let tkt_crealm = if anonymous {
            general_string(ANONYMOUS_REALM)?
        } else {
            body.realm.clone()
        };

        // check_kdcpolicy_as (do_as_req.c:214-223).
        // Indicators asserted by the preauth mechanism that succeeded
        // (add_auth_indicator, kdc_preauth.c:458; authind_add dedups).
        let mut indicators: Vec<String> = Vec::new();
        let mut add = |ind: &str| {
            if !indicators.iter().any(|i| i == ind) {
                indicators.push(ind.to_owned());
            }
        };
        if spake_key.is_some() {
            self.config.spake_indicators.iter().for_each(|i| add(i));
        }
        otp_indicators.iter().flatten().for_each(|i| add(i));
        if kdc_challenge_key.is_some() {
            if let Some(ai) = &self.config.encrypted_challenge_indicator {
                add(ai);
            }
        }
        #[cfg(feature = "pkinit")]
        if let (Some(v), Some(pk)) = (&pkinit_verified, &self.config.pkinit) {
            // Only a signed (non-anonymous) request (pkinit_srv.c:591).
            if v.client_cert.is_some() {
                v.certauth_indicators.iter().for_each(|i| add(i));
                pk.indicators.iter().for_each(|i| add(i));
            }
        }
        self.check_kdcpolicy(
            &indicators,
            false,
            Some(cname),
            None,
            &server.name,
            kdc_time,
            &mut times,
        )?;
        let tkt_flags = KerberosFlags::new(flags);
        let mut part = EncTicketPart {
            flags: tkt_flags,
            key: session_key.clone(),
            crealm: tkt_crealm.clone(),
            cname: tkt_cname.clone(),
            transited: TransitedEncoding {
                tr_type: 1,
                contents: OctetString::from(Vec::new()),
            },
            authtime: kerberos_time(times.authtime),
            starttime: optional_time(times.starttime),
            endtime: kerberos_time(times.endtime),
            renew_till: optional_time(times.renew_till),
            caddr: body.addresses.clone(),
            authorization_data: None,
        };
        self.issue_as_pac(
            &mut part,
            &server,
            &server_key.key,
            &local_tgt,
            include_pac_p(request.padata.as_deref()),
            &indicators,
            || {
                use super::plugins::{kdb_flags, AuthdataRequest, MSG_AS_REQ};
                // KRB5_NT_ENTERPRISE_PRINCIPAL.
                let enterprise = body.cname.as_ref().is_some_and(|c| c.name_type == 10);
                AuthdataRequest {
                    flags: kdb_flags::CLIENT
                        | if canonicalize || enterprise {
                            kdb_flags::REFERRAL_OK
                        } else {
                            0
                        },
                    msg_type: MSG_AS_REQ,
                    client: Some((client.name.clone(), client.realm.clone())),
                    server: Some((server.name.clone(), server.realm.clone())),
                    client_key: client_key.as_ref().map(|k| k.entry.key.clone()),
                    server_key: Some(server_key.key.clone()),
                    req_pkt: raw.to_vec(),
                    client_entry: Some(client.clone()),
                    server_entry: Some(server.clone()),
                    ..AuthdataRequest::default()
                }
            },
        )?;
        // check_indicators (do_as_req.c:284-288).
        super::cammac::check_indicators(server.require_auth.as_deref(), &indicators)?;
        let kvno =
            i32::try_from(server_key.kvno).map_err(|_| KdcError::generic("FINDING_SERVER_KEY"))?;
        ctx.audit_tkt = Some(part.clone());
        let ticket =
            encrypt_ticket_part(&server_key.key, Some(kvno), realm, tkt_sname.clone(), &part)?;

        // kdc_fast_response_handle_padata / kdc_fast_handle_reply_key
        // (do_as_req.c:301-313).
        let mut outer_cname = tkt_cname.clone();
        let mut outer_crealm = tkt_crealm.clone();
        let (outer_padata, reply_key) = match ctx.fast.as_mut().filter(|f| f.armor_key.is_some()) {
            Some(fast) => {
                let outer = fast.wrap_reply(
                    reply_padata,
                    &ticket,
                    (if anonymous { ANONYMOUS_REALM } else { realm }, &tkt_cname),
                    reply_etype,
                    now,
                )?;
                if fast.hide_client() {
                    let (r, n) = anonymous_client()?;
                    outer_crealm = general_string(&r)?;
                    outer_cname = n;
                }
                (outer, fast.reply_key(&base_key)?)
            }
            None => (reply_padata, base_key.clone()),
        };

        // return_enc_padata (kdc_preauth.c:1636-1663) with the final reply key.
        let enc_padata =
            if find_padata(request.padata.as_deref(), PaDataType::ReqEncPaRep).is_some() {
                enc_pa_rep_padata(&reply_key, raw)?
            } else {
                Vec::new()
            };

        let enc = EncAsRepPart(EncKdcRepPart {
            key: session_key,
            // fetch_last_req_info (kdc_util.c:679-687): KRB5_LRQ_NONE, 0.
            last_req: vec![LastReqEntry {
                lr_type: 0,
                lr_value: kerberos_time(0),
            }],
            nonce: body.nonce,
            key_expiration: key_expiration(&client).map(kerberos_time),
            flags: tkt_flags,
            authtime: part.authtime,
            starttime: part.starttime,
            endtime: part.endtime,
            renew_till: part.renew_till,
            srealm: body.realm.clone(),
            sname: tkt_sname,
            caddr: body.addresses.clone(),
            encrypted_pa_data: (!enc_padata.is_empty()).then_some(enc_padata),
        });
        let profile = find_etype(reply_etype)
            .map_err(|_| KdcError::new(KDC_ERR_ETYPE_NOSUPP, "CANT_FIND_CLIENT_KEY"))?;
        let cipher = profile
            .encrypt(
                reply_key.key_bytes(),
                key_usage::AS_REP_ENCPART,
                &rasn::der::encode(&enc)?,
            )
            .map_err(|_| KdcError::generic("ENCRYPT_REPLY"))?;

        let rep = AsRep(KdcRep {
            pvno: 5,
            msg_type: 11,
            padata: Some(outer_padata),
            crealm: outer_crealm,
            cname: outer_cname,
            ticket,
            // do_as_req.c:329-330 sets the kvno after encoding, so the
            // wire enc-part carries none.
            enc_part: EncryptedData {
                etype: reply_etype,
                kvno: None,
                cipher: OctetString::from(cipher),
            },
        });
        Ok(rasn::der::encode(&rep)?)
    }
}

/// `is_local_tgs_principal`: `krbtgt/REALM` for the served realm.
pub(crate) fn is_local_tgs(name: &PrincipalName, realm: &str) -> bool {
    name.name_string.len() == 2
        && name.name_string[0].as_bytes() == b"krbtgt"
        && name.name_string[1].as_bytes() == realm.as_bytes()
}

/// PA-PKINIT-KX (RFC 6112 section 5.4): the KDC contribution key `session`
/// encrypted in the reply key.
fn pkinit_kx_padata(
    session: &EncryptionKey,
    reply_key: &EncryptionKey,
) -> Result<PaData, KdcError> {
    let profile = find_etype(reply_key.keytype).map_err(|_| KdcError::generic("PKINIT_KX"))?;
    let cipher = profile
        .encrypt(
            reply_key.key_bytes(),
            key_usage::PA_PKINIT_KX,
            &rasn::der::encode(session)?,
        )
        .map_err(|_| KdcError::generic("PKINIT_KX"))?;
    let enc = EncryptedData {
        etype: reply_key.keytype,
        kvno: None,
        cipher: OctetString::from(cipher),
    };
    Ok(PaData {
        padata_type: PA_PKINIT_KX,
        padata_value: OctetString::from(rasn::der::encode(&enc)?),
    })
}
