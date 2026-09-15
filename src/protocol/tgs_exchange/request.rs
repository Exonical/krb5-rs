//! TGS-REQ construction helpers (send_tgs.c, gc_via_tkt.c).

use super::*;

impl TgsExchange {
    /// Build a TGS-REQ message.
    ///
    /// Returns the DER-encoded TGS-REQ. Generates a fresh subkey and nonce.
    pub(super) fn build_tgs_req(&mut self, canonicalize: bool) -> Result<Vec<u8>, Krb5Error> {
        // Generate random nonce (31-bit, same as AS exchange)
        self.nonce = rand::random::<u32>() & 0x7FFF_FFFF;

        // Generate subkey (same etype as TGT session key)
        let etype = self.cur_tgt.session_key.keytype;
        let profile = find_etype(etype).map_err(|_| Krb5Error::UnsupportedEtype(etype))?;
        let random_bytes: Zeroizing<Vec<u8>> = Zeroizing::new(
            (0..profile.key_bytes())
                .map(|_| rand::random::<u8>())
                .collect(),
        );
        let mut subkey_bytes = profile
            .random_to_key(random_bytes.as_ref())
            .map_err(|e| Krb5Error::Crypto(e.to_string()))?;
        // Move key bytes out of Zeroizing without cloning.
        // std::mem::take replaces the inner Vec with empty (zeroized on Zeroizing drop).
        let subkey = EncryptionKey::new(etype, std::mem::take(&mut *subkey_bytes));
        self.subkey = Some(subkey.clone());

        // Build KDC-REQ-BODY
        let target_realm = self.tgt_target_realm();
        let realm = GeneralString::from_bytes(target_realm.as_bytes())
            .map_err(|_| Krb5Error::ReplyValidation("invalid realm string"))?;

        let mut kdc_opts = KdcOptions::empty();
        if self.options.renewable {
            kdc_opts |= KdcOptions::RENEWABLE;
        }
        if self.options.forwardable {
            kdc_opts |= KdcOptions::FORWARDABLE;
        }
        if canonicalize {
            kdc_opts |= KdcOptions::CANONICALIZE;
        }

        // Request 10h lifetime; KDC will cap to its policy maximum
        let till = now_kerberos()
            .checked_add_signed(chrono::Duration::hours(10))
            .ok_or(Krb5Error::ReplyValidation("till overflow"))?;

        let req_body = KdcReqBody {
            kdc_options: KerberosFlags::new(kdc_opts),
            cname: None, // TGS-REQ does not include cname in body
            realm,
            sname: Some(self.target_server.clone()),
            from: None,
            till,
            rtime: None,
            nonce: self.nonce,
            etype: self.options.etypes.clone(),
            addresses: None,
            enc_authorization_data: None,
            additional_tickets: None,
        };

        // DER-encode req_body for checksum computation
        let req_body_der = rasn::der::encode(&req_body)?;

        // MIT send_tgs.c:178 — every TGS-REQ is FAST-armored with the
        // implicit armor derived from subkey + TGT session key.
        self.fast_state = FastState::new();
        self.fast_state
            .tgs_armor(&subkey, &self.cur_tgt.session_key)?;

        // Build PA-TGS-REQ (AP-REQ wrapping the TGT)
        let pa_tgs_req = self.build_pa_tgs_req(&req_body_der, &subkey)?;
        let ap_req_der: Vec<u8> = pa_tgs_req.padata_value.as_ref().to_vec();

        // Build padata list
        let mut padata = vec![pa_tgs_req];

        // Add PA-PAC-OPTIONS if requested
        if self.options.pac_options {
            padata.push(build_pa_pac_options()?);
        }

        // Build TGS-REQ
        let kdc_req = KdcReq {
            pvno: 5,
            msg_type: 12, // TGS-REQ
            padata: Some(padata),
            req_body,
        };

        // send_tgs.c:277-283 — the FAST request checksum covers the AP-REQ
        // DER, not the request body.
        let der = self
            .fast_state
            .prep_req(&kdc_req, &ap_req_der, FastMsgType::Tgs)?;
        self.last_req_bytes = der.clone();

        Ok(der)
    }

    /// Build PA-TGS-REQ padata: AP-REQ wrapping the TGT with keyed checksum.
    fn build_pa_tgs_req(
        &self,
        req_body_der: &[u8],
        subkey: &EncryptionKey,
    ) -> Result<PaData, Krb5Error> {
        let session_key = &self.cur_tgt.session_key;
        let etype = session_key.keytype;
        let profile = find_etype(etype).map_err(|_| Krb5Error::UnsupportedEtype(etype))?;

        // 1. Compute keyed checksum of DER-encoded KDC-REQ-BODY (key usage 6)
        let cksum_bytes = profile
            .checksum(
                session_key.key_bytes(),
                key_usage::TGS_REQ_AUTH_CKSUM,
                req_body_der,
            )
            .map_err(|e| Krb5Error::Crypto(e.to_string()))?;

        let cksum = Checksum {
            cksumtype: profile.checksum_type(),
            checksum: cksum_bytes.into(),
        };

        // 2. Build Authenticator — derive ctime and cusec from a single Utc::now()
        // to avoid second-boundary skew between the two fields.
        let now_instant = Utc::now();
        let usec = now_instant.timestamp_subsec_micros() as i32;
        // Truncate to whole seconds for ctime (RFC 4120: no fractional seconds).
        let ctime = now_instant
            .with_nanosecond(0)
            .unwrap_or(now_instant)
            .with_timezone(&UTC_OFFSET);

        let crealm = GeneralString::from_bytes(self.cur_tgt.crealm.as_bytes())
            .map_err(|_| Krb5Error::ReplyValidation("invalid crealm string"))?;

        let authenticator = Authenticator {
            authenticator_vno: 5,
            crealm,
            cname: self.cur_tgt.client.clone(),
            cksum: Some(cksum),
            cusec: usec,
            ctime,
            subkey: Some(subkey.clone()),
            seq_number: None,
            authorization_data: None,
        };

        // 3. Encrypt Authenticator with TGT session key (key usage 7)
        let auth_der = rasn::der::encode(&authenticator)?;
        let encrypted_auth = profile
            .encrypt(session_key.key_bytes(), key_usage::TGS_REQ_AUTH, &auth_der)
            .map_err(|e| Krb5Error::Crypto(e.to_string()))?;

        // 4. Build AP-REQ
        let ap_req = ApReq {
            pvno: 5,
            msg_type: 14,
            ap_options: KerberosFlags::new(ApOptions::empty()),
            ticket: self.cur_tgt.ticket.clone(),
            authenticator: EncryptedData {
                etype,
                kvno: None,
                cipher: encrypted_auth.into(),
            },
        };

        let ap_req_der = rasn::der::encode(&ap_req)?;

        Ok(PaData {
            padata_type: PA_TGS_REQ,
            padata_value: ap_req_der.into(),
        })
    }
}

/// Build PA-PAC-OPTIONS padata with Branch Aware flag.
pub(super) fn build_pa_pac_options() -> Result<PaData, Krb5Error> {
    use crate::types::PaPacOptions;
    use rasn::types::BitString;

    let pac_options = PaPacOptions {
        flags: BitString::from_slice(&PA_PAC_OPTIONS_FLAGS),
    };
    let der = rasn::der::encode(&pac_options)?;

    Ok(PaData {
        padata_type: PA_PAC_OPTIONS,
        padata_value: der.into(),
    })
}

impl TgsExchange {
    /// Handle a referral TGT response.
    pub(super) fn handle_referral(
        &mut self,
        rep: &crate::types::KdcRep,
        enc_part: &EncKdcRepPart,
        resume: ResumeState,
    ) -> Result<TgsStepResult, Krb5Error> {
        let (mut realms_seen, referral_count) = match resume {
            ResumeState::Referrals {
                realms_seen,
                referral_count,
            } => (realms_seen, referral_count),
            ResumeState::NonReferral => {
                // Got a referral in non-referral mode — treat as error
                return Err(Krb5Error::ReplyValidation(
                    "unexpected referral in non-referral mode",
                ));
            }
        };

        let new_count = referral_count + 1;
        if new_count > MAX_REFERRAL_HOPS {
            return Err(Krb5Error::ReferralLimitExceeded(MAX_REFERRAL_HOPS));
        }

        // Extract the referral realm from the TGT's sname (krbtgt/REALM)
        let referral_realm =
            String::from_utf8_lossy(enc_part.sname.name_string[1].as_bytes()).to_string();

        // Loop detection
        if realms_seen.contains(&referral_realm) {
            return Err(Krb5Error::ReferralLoop {
                realm: referral_realm,
            });
        }
        realms_seen.push(referral_realm.clone());

        // Build a Credential from the referral TGT.
        //
        // ok-as-delegate propagation (per MIT krb5 behavior):
        // Strip OK_AS_DELEGATE from the referral TGT unless the
        // cross-realm TGT we used to make this request also had it.
        // This prevents a foreign KDC from unilaterally granting
        // delegation rights.
        let mut referral_flags = enc_part.flags;
        if !self.cur_tgt.flags.contains(TicketFlags::OK_AS_DELEGATE) {
            *referral_flags &= !TicketFlags::OK_AS_DELEGATE;
        }

        let referral_tgt = Credential {
            client: rep.cname.clone(),
            crealm: String::from_utf8_lossy(rep.crealm.as_bytes()).to_string(),
            server: enc_part.sname.clone(),
            srealm: String::from_utf8_lossy(enc_part.srealm.as_bytes()).to_string(),
            session_key: enc_part.key.clone(),
            times: TicketTimes {
                authtime: enc_part.authtime,
                starttime: enc_part.starttime,
                endtime: enc_part.endtime,
                renew_till: enc_part.renew_till,
            },
            ticket: rep.ticket.clone(),
            flags: referral_flags,
            addresses: enc_part.caddr.clone(),
            authdata: None,
        };

        // Use the referral TGT for the next request
        self.cur_tgt = referral_tgt;

        // Send TGS-REQ to the referral realm
        let tgs_req = self.build_tgs_req(true)?;
        self.state = TgsState::AwaitReply {
            resume: ResumeState::Referrals {
                realms_seen,
                referral_count: new_count,
            },
        };
        self.last_realm = referral_realm.clone();
        Ok(TgsStepResult::SendToKdc {
            data: tgs_req,
            realm: referral_realm,
        })
    }
}
