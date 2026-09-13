//! AS-REQ construction and preauth helpers (get_in_tkt.c, preauth2.c).

use super::*;

impl AsExchange {
    /// Build an AS-REQ message. Returns (DER bytes, request body for validation).
    pub(super) fn build_as_req(
        &mut self,
        preauth_padata: Option<Vec<PaData>>,
    ) -> Result<(Vec<u8>, KdcReqBody), Krb5Error> {
        // Generate random nonce. Mask to 31 bits — MIT KDC decodes nonce
        // as signed krb5_int32, rejecting DER-encoded values >= 2^31.
        self.nonce = rand::random::<u32>() & 0x7FFF_FFFF;

        let realm = GeneralString::from_bytes(self.config.realm.as_bytes())
            .map_err(|_| Krb5Error::ReplyValidation("invalid realm string"))?;

        // Build server principal: krbtgt/REALM
        let sname = PrincipalName::new_srv_inst("krbtgt", &self.config.realm);

        // Compute till and rtime using checked arithmetic to avoid panic on overflow
        let now = now_kerberos();
        let till_dur = chrono::Duration::seconds(duration_secs_i64(self.config.tkt_lifetime));
        let till = match now.checked_add_signed(till_dur) {
            Some(t) => t,
            None => {
                return Err(Krb5Error::ReplyValidation(
                    "ticket lifetime overflow when computing till",
                ))
            }
        };

        let rtime = if self.config.kdc_options.contains(KdcOptions::RENEWABLE) {
            let rtime_dur =
                chrono::Duration::seconds(duration_secs_i64(self.config.renew_lifetime));
            match now.checked_add_signed(rtime_dur) {
                Some(t) => Some(t),
                None => {
                    return Err(Krb5Error::ReplyValidation(
                        "renewable lifetime overflow when computing rtime",
                    ))
                }
            }
        } else {
            None
        };

        let req_body = KdcReqBody {
            kdc_options: self.config.kdc_options,
            cname: Some(self.config.client.clone()),
            realm: realm.clone(),
            sname: Some(sname),
            from: None,
            till,
            rtime,
            nonce: self.nonce,
            etype: self.config.etypes.clone(),
            addresses: None,
            enc_authorization_data: None,
            additional_tickets: None,
        };

        // Build padata list: [PA-FX-COOKIE] [preauth] [info padata] [PA-PAC-REQUEST]
        let mut padata: Vec<PaData> = Vec::new();

        // Echo the cookie from the most recent KDC error, if any.
        if let Some(cookie) = &self.cookie {
            padata.push(PaData {
                padata_type: PaDataType::FxCookie as i32,
                padata_value: cookie.clone().into(),
            });
        }

        // Add preauth padata if provided
        if let Some(pa_list) = preauth_padata {
            padata.extend(pa_list);
        }

        // MIT get_in_tkt.c:1365-1372 — empty informational padata while
        // info_pa_permitted (PA-AS-FRESHNESS then PA-REQ-ENC-PA-REP).
        if self.info_pa_permitted {
            padata.push(build_empty_padata(PaDataType::AsFreshness as i32));
            padata.push(build_empty_padata(PaDataType::ReqEncPaRep as i32));
        }

        // Always send PA-PAC-REQUEST; `request_pac` controls `include-pac` value
        padata.push(build_pa_pac_request(self.config.request_pac)?);

        // padata always has at least PA-PAC-REQUEST
        let padata_opt = Some(padata);

        let kdc_req = KdcReq {
            pvno: 5,
            msg_type: 10, // AS-REQ
            padata: padata_opt,
            req_body: req_body.clone(),
        };

        // MIT get_in_tkt.c:836 + :1391-1395 — the checksum input is the
        // DER-encoded outer request body; the returned bytes are the outer
        // (possibly FAST-armored) request.
        let body_der = rasn::der::encode(&req_body)?;
        let der = self
            .fast_state
            .prep_req(&kdc_req, &body_der, FastMsgType::As)?;

        Ok((der, req_body))
    }

    /// Current time for preauth, applying the KDC offset when permitted
    /// (MIT `k5_init_creds_current_time`, get_in_tkt.c:683-697):
    /// `allow_unauth` permits an offset learned from an unarmored error.
    pub(super) fn preauth_time(&self, allow_unauth: bool) -> (KerberosTime, i32) {
        let now_utc = Utc::now();
        let adj = match self.pa_offset {
            Some(o) if allow_unauth || o.auth => {
                now_utc + o.secs + chrono::Duration::microseconds(o.usec)
            }
            _ => now_utc,
        };
        let usec = adj.timestamp_subsec_micros() as i32;
        let ts = adj
            .with_nanosecond(0)
            .unwrap_or(adj)
            .with_timezone(&UTC_OFFSET);
        (ts, usec)
    }

    /// Record the KDC time offset from a preauth error
    /// (MIT `note_req_timestamp`, get_in_tkt.c:1430-1440): the offset is
    /// authenticated (AUTH_OFFSET) only when the error was FAST-armored.
    pub(super) fn note_req_timestamp(&mut self, stime: KerberosTime, susec: i32) {
        let now_utc = Utc::now();
        let now_fixed = now_utc.fixed_offset();
        self.pa_offset = Some(PaOffset {
            secs: stime.signed_duration_since(now_fixed),
            usec: susec as i64 - now_utc.timestamp_subsec_micros() as i64,
            auth: self.fast_state.armor_key().is_some(),
        });
    }

    /// Build PA-ENC-TIMESTAMP and return as padata.
    /// Uses the KDC time offset whenever known (allow_unauth=TRUE, MIT
    /// preauth_enc_timestamp via get_preauth_time).
    pub(super) fn build_pa_enc_timestamp(&self, hint: &PreauthHint) -> Result<PaData, Krb5Error> {
        let (now, usec) = self.preauth_time(true);

        // Compute salt: use hint salt if present, or compute default
        let salt = match &hint.salt {
            Some(s) => s.clone(),
            None => self.default_salt(),
        };

        build_pa_enc_timestamp(
            self.password.as_bytes(),
            &salt,
            hint.s2kparams.as_deref(),
            hint.etype,
            now,
            Some(usec),
        )
    }

    /// Compute default salt from realm and client principal components.
    pub(super) fn default_salt(&self) -> Vec<u8> {
        let components: Vec<&[u8]> = self
            .config
            .client
            .name_string
            .iter()
            .map(|s| s.as_bytes())
            .collect();
        default_salt(&self.config.realm, &components)
    }
}
