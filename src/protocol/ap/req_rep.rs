//! AP-REQ/AP-REP exchange (mk_req_ext.c, rd_req_dec.c, mk_rep.c, rd_rep.c).

use super::*;

impl AuthContext {
    /// Build an AP-REQ (mk_req_ext.c:104-254).
    pub fn mk_req(
        &mut self,
        opts: &ApReqOptions,
        in_data: Option<&[u8]>,
        cred: &Credential,
    ) -> Result<Vec<u8>, Krb5Error> {
        if cred.ticket.enc_part.cipher.is_empty() {
            return Err(ApError::NoTktSupplied.into());
        }
        if opts.etype_negotiation && !opts.mutual_required {
            return Err(Krb5Error::ReplyValidation(
                "etype negotiation requires mutual auth",
            ));
        }
        self.validate_times(
            cred.times.authtime,
            cred.times.starttime,
            cred.times.endtime,
        )?;

        self.key = Some(cred.session_key.clone());
        let session = cred.session_key.clone();
        let session_profile =
            find_etype(session.keytype).map_err(|e| Krb5Error::Crypto(e.to_string()))?;

        if self
            .flags
            .intersects(AuthContextFlags::DO_SEQUENCE | AuthContextFlags::RET_SEQUENCE)
            && self.local_seq == 0
        {
            self.gen_seq_number();
        }

        if opts.use_subkey && self.send_subkey.is_none() {
            self.generate_and_save_subkey(session.keytype)?;
        }

        let cksum = if let Some(data) = in_data {
            if self.req_cksumtype == 0x8003 {
                Some(Checksum {
                    cksumtype: 0x8003,
                    checksum: OctetString::from(data.to_vec()),
                })
            } else {
                Some(Checksum {
                    cksumtype: session_profile.checksum_type(),
                    checksum: OctetString::from(
                        session_profile
                            .checksum(session.key_bytes(), key_usage::AP_REQ_AUTH_CKSUM, data)
                            .map_err(|e| Krb5Error::Crypto(e.to_string()))?,
                    ),
                })
            }
        } else {
            None
        };

        let desired: Option<Vec<i32>> = if opts.etype_negotiation {
            Some(
                self.permitted_etypes
                    .clone()
                    .unwrap_or_else(|| DEFAULT_ETYPES.to_vec()),
            )
        } else {
            None
        };

        let (ctime, cusec) = self.now();
        let mut authdata: Vec<AuthorizationDataElement> = Vec::new();
        if let Some(inner) = make_ap_authdata(desired.as_deref(), session.keytype, opts.cbt)? {
            authdata.push(inner);
        }
        if let Some(cred_ad) = &cred.authdata {
            authdata.extend(cred_ad.iter().cloned());
        }

        let auth = Authenticator {
            authenticator_vno: 5,
            crealm: GeneralString::from_bytes(cred.crealm.as_bytes())
                .map_err(|_| Krb5Error::ReplyValidation("invalid crealm"))?,
            cname: cred.client.clone(),
            cksum,
            cusec,
            ctime,
            subkey: self.send_subkey.clone(),
            // MIT asn1_k_encode.c omits seq-number when zero.
            seq_number: if self.local_seq != 0 {
                Some(self.local_seq)
            } else {
                None
            },
            authorization_data: if authdata.is_empty() {
                None
            } else {
                Some(authdata)
            },
        };
        let auth_der = rasn::der::encode(&auth)?;
        let cipher = session_profile
            .encrypt(session.key_bytes(), key_usage::AP_REQ_AUTH, &auth_der)
            .map_err(|e| Krb5Error::Crypto(e.to_string()))?;

        let mut ap_options = ApOptions::empty();
        if opts.mutual_required {
            ap_options |= ApOptions::MUTUAL_REQUIRED;
        }
        if opts.use_session_key {
            ap_options |= ApOptions::USE_SESSION_KEY;
        }

        let req = ApReq {
            pvno: 5,
            msg_type: 14,
            ap_options: KerberosFlags::new(ap_options),
            ticket: cred.ticket.clone(),
            authenticator: EncryptedData {
                etype: session.keytype,
                kvno: None,
                cipher: OctetString::from(cipher),
            },
        };
        self.authentp = Some(auth);
        Ok(rasn::der::encode(&req)?)
    }

    /// Read and verify an AP-REQ (rd_req_dec.c:472-787).
    pub fn rd_req(
        &mut self,
        ap_req: &[u8],
        server: Option<&PrincipalName>,
        keys: &dyn KeySource,
    ) -> Result<RdReqResult, Krb5Error> {
        // krb5_is_ap_req: first byte must be APPLICATION 14 (0x6E).
        if ap_req.first() != Some(&0x6E) {
            return Err(ApError::MsgType.into());
        }
        let req: ApReq = rasn::der::decode(ap_req)?;
        if req.msg_type != 14 {
            return Err(ApError::MsgType.into());
        }
        if req.pvno != 5 {
            return Err(ApError::BadVersion.into());
        }

        let enc_part = if let Some(key) = self.tkt_key.take() {
            decrypt_ticket(&key, &req.ticket)?
        } else {
            let sname = server.unwrap_or(&req.ticket.sname);
            let key = keys.get_key(
                sname,
                req.ticket.realm.as_bytes(),
                req.ticket.enc_part.kvno,
                req.ticket.enc_part.etype,
            )?;
            decrypt_ticket(&key, &req.ticket)?
        };

        let session = enc_part.key.clone();
        let session_profile =
            find_etype(session.keytype).map_err(|e| Krb5Error::Crypto(e.to_string()))?;

        let plain = session_profile
            .decrypt(
                session.key_bytes(),
                key_usage::AP_REQ_AUTH,
                &req.authenticator.cipher,
            )
            .map_err(|_| Krb5Error::Ap(ApError::BadIntegrity))?;
        let auth: Authenticator =
            rasn::der::decode(&plain).map_err(|_| Krb5Error::Ap(ApError::BadIntegrity))?;

        // rd_req_dec.c:530-534 — principal compare incl. realm.
        if auth.cname.name_string != enc_part.cname.name_string || auth.crealm != enc_part.crealm {
            return Err(ApError::BadMatch.into());
        }

        if let Some(remote) = self.effective_remote_addr() {
            if !address_search(&remote, enc_part.caddr.as_deref()) {
                return Err(ApError::BadAddr.into());
            }
        }

        // Hierarchical cross-realm check, rd_req_dec.c:606-610.
        // Deviation: MIT calls krb5_check_transited_list (capaths); with no
        // capaths support any non-empty unchecked transited list is rejected.
        if !enc_part
            .flags
            .contains(TicketFlags::TRANSITED_POLICY_CHECKED)
            && !enc_part.transited.contents.is_empty()
        {
            return Err(ApError::IllCrTkt.into());
        }

        if self.flags.contains(AuthContextFlags::DO_TIME) {
            // rc_base.c:147-163: tag = trailing checksum-length bytes of the
            // authenticator ciphertext.
            let tag_len = session_profile
                .checksum(session.key_bytes(), 0, &[])
                .map_err(|e| Krb5Error::Crypto(e.to_string()))?
                .len();
            let cipher = &req.authenticator.cipher;
            if cipher.len() < tag_len {
                return Err(ApError::BadIntegrity.into());
            }
            let tag = cipher[cipher.len() - tag_len..].to_vec();
            if !self.rcache.insert(tag) {
                return Err(ApError::Repeat.into());
            }
        }

        self.validate_times(enc_part.authtime, enc_part.starttime, enc_part.endtime)?;
        self.check_clockskew(auth.ctime)?;

        if enc_part.flags.contains(TicketFlags::INVALID) {
            return Err(ApError::TktInvalid.into());
        }

        // RFC 4537, rd_req_dec.c:652-727.
        let rfc4537 = decode_etype_list(&auth);
        let mandatory_index = rfc4537.len();
        let mut desired = rfc4537;
        if let Some(sub) = &auth.subkey {
            desired.push(sub.keytype);
        }
        desired.push(session.keytype);

        let permitted: Option<Vec<i32>> = if self.flags.contains(AuthContextFlags::PERMIT_ALL) {
            None
        } else {
            Some(
                self.permitted_etypes
                    .clone()
                    .unwrap_or_else(|| DEFAULT_ETYPES.to_vec()),
            )
        };
        self.negotiated_etype = negotiate_etype(&desired, mandatory_index, permitted.as_deref())?;

        self.remote_seq = auth.seq_number.unwrap_or(0);
        if let Some(sub) = &auth.subkey {
            self.recv_subkey = Some(sub.clone());
            self.send_subkey = Some(sub.clone());
        } else {
            self.recv_subkey = None;
            self.send_subkey = None;
        }
        self.key = Some(session);

        // rd_req_dec.c:757-761 — without mutual auth, local_seq becomes the
        // complement of the remote seq number.
        if !req.ap_options.contains(ApOptions::MUTUAL_REQUIRED) && self.remote_seq != 0 {
            self.local_seq ^= self.remote_seq;
        }

        self.authentp = Some(auth);
        Ok(RdReqResult {
            ticket: enc_part,
            ap_options: KerberosFlags::new(ApOptions::from_bits_truncate(
                req.ap_options.bits() & AP_OPTS_WIRE,
            )),
            authenticator: self.authentp.clone().expect("just stored"),
        })
    }

    /// Build an AP-REP (mk_rep.c:67-140 `k5_mk_rep`, non-DCE).
    pub fn mk_rep(&mut self) -> Result<Vec<u8>, Krb5Error> {
        let auth = self
            .authentp
            .clone()
            .ok_or(Krb5Error::ReplyValidation("no authenticator"))?;
        let key = self
            .key
            .clone()
            .ok_or(Krb5Error::ReplyValidation("no key"))?;

        if self
            .flags
            .intersects(AuthContextFlags::DO_SEQUENCE | AuthContextFlags::RET_SEQUENCE)
            && self.local_seq == 0
        {
            self.gen_seq_number();
        }

        let subkey = if self.flags.contains(AuthContextFlags::USE_SUBKEY) {
            if self.negotiated_etype == 0 {
                return Err(Krb5Error::ReplyValidation("no negotiated etype"));
            }
            self.generate_and_save_subkey(self.negotiated_etype)?;
            self.send_subkey.clone()
        } else {
            auth.subkey.clone()
        };

        let enc = EncApRepPart {
            ctime: auth.ctime,
            cusec: auth.cusec,
            subkey,
            seq_number: if self.local_seq != 0 {
                Some(self.local_seq)
            } else {
                None
            },
        };
        let der = rasn::der::encode(&enc)?;
        let profile = find_etype(key.keytype).map_err(|e| Krb5Error::Crypto(e.to_string()))?;
        let cipher = profile
            .encrypt(key.key_bytes(), key_usage::AP_REP_ENCPART, &der)
            .map_err(|e| Krb5Error::Crypto(e.to_string()))?;
        let rep = ApRep {
            pvno: 5,
            msg_type: 15,
            enc_part: EncryptedData {
                etype: key.keytype,
                kvno: None,
                cipher: OctetString::from(cipher),
            },
        };
        Ok(rasn::der::encode(&rep)?)
    }

    /// Read and verify an AP-REP (rd_rep.c:68-145).
    pub fn rd_rep(&mut self, ap_rep: &[u8]) -> Result<EncApRepPart, Krb5Error> {
        // krb5_is_ap_rep: first byte APPLICATION 15 (0x6F).
        if ap_rep.first() != Some(&0x6F) {
            return Err(ApError::MsgType.into());
        }
        let rep: ApRep = rasn::der::decode(ap_rep).map_err(|_| Krb5Error::Ap(ApError::MsgType))?;
        let key = self
            .key
            .clone()
            .ok_or(Krb5Error::ReplyValidation("no key"))?;
        let profile =
            find_etype(rep.enc_part.etype).map_err(|e| Krb5Error::Crypto(e.to_string()))?;
        let plain = profile
            .decrypt(
                key.key_bytes(),
                key_usage::AP_REP_ENCPART,
                &rep.enc_part.cipher,
            )
            .map_err(|_| Krb5Error::Ap(ApError::BadIntegrity))?;
        let enc: EncApRepPart =
            rasn::der::decode(&plain).map_err(|_| Krb5Error::Ap(ApError::BadIntegrity))?;

        let auth = self
            .authentp
            .as_ref()
            .ok_or(Krb5Error::ReplyValidation("no authenticator"))?;
        if enc.ctime != auth.ctime || enc.cusec != auth.cusec {
            return Err(ApError::MutualFailed.into());
        }
        if let Some(sub) = &enc.subkey {
            self.recv_subkey = Some(sub.clone());
            self.send_subkey = Some(sub.clone());
            self.negotiated_etype = sub.keytype;
        }
        self.remote_seq = enc.seq_number.unwrap_or(0);
        Ok(enc)
    }
}
