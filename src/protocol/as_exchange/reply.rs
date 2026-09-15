//! AS-REP processing and reply validation (get_in_tkt.c process_response).

use super::*;

impl AsExchange {
    /// Process a successful AS-REP: decrypt enc-part, validate, build credential.
    pub(super) fn process_as_rep(&mut self, as_rep: AsRep) -> Result<StepResult, Krb5Error> {
        let rep = &as_rep.0;

        // MIT get_in_tkt.c:1411-1425 `check_reply_enctype` — the reply
        // enctype must be one of the etypes we requested.
        if !self.config.etypes.contains(&rep.enc_part.etype) {
            return Err(Krb5Error::ReplyValidation(
                "reply enctype was not requested",
            ));
        }

        // MIT fast.c:517-568 `krb5int_fast_process_response` — when the
        // request was FAST-armored, the reply must carry PA-FX-FAST; the
        // response's finished client and padata replace the reply's.
        let fast_out = self
            .fast_state
            .process_response(rep.padata.as_deref(), &rep.ticket)?;
        let mut rep = rep.clone();
        let mut strengthen_key = None;
        if let Some(out) = fast_out {
            rep.cname = out.client;
            rep.padata = if out.padata.is_empty() {
                None
            } else {
                Some(out.padata)
            };
            strengthen_key = out.strengthen_key;
        }
        let rep = &rep;

        // Determine encryption type from enc-part
        let etype = rep.enc_part.etype;
        let profile = find_etype(etype).map_err(|_| Krb5Error::UnsupportedEtype(etype))?;

        // Derive key from password, preferring params from AS-REP padata
        // (which is the FAST response padata when armored — MIT overwrites
        // resp->padata before the final k5_preauth pass).
        let (salt, s2kparams) = self.compute_reply_key_params(rep);
        let as_key = EncryptionKey::new(
            etype,
            profile
                .string_to_key(self.password.as_bytes(), &salt, s2kparams.as_deref())
                .map_err(|e| Krb5Error::Crypto(e.to_string()))?
                .to_vec(),
        );

        // MIT fast.c:570-593 — a strengthen key folds into the reply key.
        let reply_key = FastState::reply_key(strengthen_key.as_ref(), &as_key)?;

        // Decrypt EncAsRepPart (key usage 3); some KDCs (Heimdal) tag the
        // enc-part as EncTgsRepPart [APPLICATION 26] — handled inside the
        // shared decoder.
        let enc_part = crate::protocol::kdc_rep::decrypt_enc_kdc_rep_part(
            &[(reply_key.clone(), key_usage::AS_REP_ENCPART)],
            &rep.enc_part,
            crate::protocol::kdc_rep::decode_enc_as_rep_part,
        )?;

        // Validate the reply
        let now = now_kerberos();
        let canonicalize = self.config.kdc_options.contains(KdcOptions::CANONICALIZE);
        let req_body = self
            .last_req_body
            .as_ref()
            .ok_or(Krb5Error::ReplyValidation("no request body saved"))?;

        validate_as_reply(
            self.nonce,
            req_body,
            rep,
            &enc_part,
            canonicalize,
            self.config.max_clock_skew,
            now,
        )?;

        // MIT fast.c:634-675 `krb5int_fast_verify_nego` — when the KDC sets
        // enc-pa-rep it MUST include a PA-REQ-ENC-PA-REP checksum over the
        // exact last-sent AS-REQ bytes, keyed with usage KRB5_KEYUSAGE_AS_REQ.
        // MIT's verify_key rejects a cksumtype outside the key's enctype
        // family with KRB5_BAD_ENCTYPE; until a checksum-type registry exists
        // we require the profile's mandatory cksumtype (unkeyed cksumtypes
        // are therefore rejected as well).
        if enc_part.flags.contains(TicketFlags::ENC_PA_REP) {
            let pa = enc_part
                .encrypted_pa_data
                .as_ref()
                .and_then(|list| {
                    list.iter()
                        .find(|pa| pa.padata_type == PaDataType::ReqEncPaRep as i32)
                })
                .ok_or(Krb5Error::ReplyValidation("PA-REQ-ENC-PA-REP missing"))?;
            let cksum: Checksum = rasn::der::decode(pa.padata_value.as_ref())?;
            let reply_profile = find_etype(reply_key.keytype)
                .map_err(|_| Krb5Error::UnsupportedEtype(reply_key.keytype))?;
            if cksum.cksumtype != reply_profile.checksum_type() {
                return Err(Krb5Error::Crypto(
                    "checksum type does not match reply key enctype".to_string(),
                ));
            }
            reply_profile
                .verify_checksum(
                    reply_key.key_bytes(),
                    key_usage::AS_REQ,
                    &self.last_req_bytes,
                    cksum.checksum.as_ref(),
                )
                .map_err(|_| Krb5Error::ReplyValidation("PA-REQ-ENC-PA-REP checksum mismatch"))?;
            // fast.c:664-675 — FAST is available when PA-FX-FAST is also
            // present in the encrypted padata.
            self.fast_avail = enc_part
                .encrypted_pa_data
                .as_deref()
                .unwrap_or(&[])
                .iter()
                .any(|pa| pa.padata_type == PaDataType::FxFast as i32);
        }

        // Final reply padata: a KDC encrypted challenge proves the KDC
        // holds the long-term key (preauth_ec.c:61-90). MIT treats a
        // verification failure as non-fatal (must_preauth false), so we
        // record the outcome instead of failing.
        if let (Some(armor_key), Some(challenge)) = (
            self.fast_state.armor_key(),
            rep.padata
                .as_deref()
                .unwrap_or(&[])
                .iter()
                .find(|pa| pa.padata_type == PaDataType::EncryptedChallenge as i32),
        ) {
            self.kdc_verified =
                verify_kdc_challenge(armor_key, &as_key, challenge.padata_value.as_ref()).is_ok();
        }

        // Build credential
        self.credential = Some(crate::protocol::kdc_rep::credential_from_rep(
            rep, &enc_part,
        ));
        self.state = AsState::Complete;
        Ok(StepResult::Complete)
    }

    /// Compute salt and s2kparams for reply key derivation.
    ///
    /// Tries AS-REP padata first (PA-ETYPE-INFO2), then falls back to
    /// persisted preauth hint values, then default salt.
    fn compute_reply_key_params(&self, rep: &KdcRep) -> (Vec<u8>, Option<Vec<u8>>) {
        // Try to extract salt and s2kparams from reply padata (PA-ETYPE-INFO2)
        if let Some(ref padata) = rep.padata {
            for pa in padata {
                if pa.padata_type == PaDataType::EtypeInfo2 as i32 {
                    if let Ok(entries) = rasn::der::decode::<Vec<crate::types::EtypeInfo2Entry>>(
                        pa.padata_value.as_ref(),
                    ) {
                        for entry in &entries {
                            if entry.etype == rep.enc_part.etype {
                                // RFC 4120: absent salt means use default salt
                                let salt = match &entry.salt {
                                    Some(s) => s.as_bytes().to_vec(),
                                    None => self.default_salt(),
                                };
                                let s2kparams =
                                    entry.s2kparams.as_ref().map(|p| p.as_ref().to_vec());
                                return (salt, s2kparams);
                            }
                        }
                    }
                }
            }
        }

        // Fall back to persisted preauth hint values (from PREAUTH_REQUIRED)
        if let Some(ref salt) = self.last_preauth_salt {
            return (salt.clone(), self.last_s2kparams.clone());
        }

        // Last resort: compute default salt, use persisted s2kparams
        (self.default_salt(), self.last_s2kparams.clone())
    }
}

impl AsExchange {
    /// Restart the exchange from the initial (no-preauth) request.
    ///
    /// MIT `restart_init_creds_loop` (get_in_tkt.c): drops the cookie,
    /// preauth hint and loop state, and rebuilds the FAST state — arming
    /// it when `fast_upgrade` or FAST-required is set. `restarted` is
    /// caller-managed: the PREAUTH_FAILED path sets it, PREAUTH_EXPIRED
    /// clears it.
    pub(super) fn restart(&mut self, fast_upgrade: bool) -> Result<StepResult, Krb5Error> {
        self.cookie = None;
        self.last_preauth_salt = None;
        self.last_s2kparams = None;
        self.last_preauth_etype = None;
        self.method_padata = None;
        self.selected_preauth_type = None;
        self.preauth_failed.clear();
        self.loop_count = 0;
        self.preauth_sent = false;
        let do_fast = self.config.fast.required() || fast_upgrade;
        self.reset_fast_state(do_fast)?;
        let (as_req_der, req_body) = self.build_as_req(None)?;
        self.last_req_body = Some(req_body);
        self.last_req_bytes = as_req_der.clone();
        Ok(StepResult::SendToKdc {
            data: as_req_der,
            realm: self.config.realm.clone(),
        })
    }
}
