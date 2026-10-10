//! KRB-SAFE and KRB-PRIV messages (mk_safe.c, rd_safe.c, mk_priv.c, rd_priv.c).

use super::*;

impl AuthContext {
    /// Build a KRB-SAFE message (mk_safe.c:44-174).
    pub fn mk_safe(&mut self, user_data: &[u8]) -> Result<(Vec<u8>, ReplayData), Krb5Error> {
        if self.local_addr.is_none() {
            return Err(ApError::LocalAddrRequired.into());
        }
        let (ts, usec, seq) = self.gen_rdata();
        let local = self.effective_local_addr();
        let remote = self.effective_remote_addr();
        let key = self
            .send_subkey
            .clone()
            .or_else(|| self.key.clone())
            .ok_or(Krb5Error::ReplyValidation("no key"))?;
        let profile = find_etype(key.keytype).map_err(|e| Krb5Error::Crypto(e.to_string()))?;
        let body = KrbSafeBody {
            user_data: OctetString::from(user_data.to_vec()),
            timestamp: ts,
            usec,
            seq_number: seq,
            s_address: local.expect("checked above"),
            r_address: remote,
        };
        // mk_safe.c:66-70 — zero-length type-0 checksum for the first pass.
        let zero = Checksum {
            cksumtype: 0,
            checksum: OctetString::from(Vec::new()),
        };
        let mut safe = KrbSafe {
            pvno: 5,
            msg_type: 20,
            safe_body: body,
            cksum: zero.clone(),
        };
        let zerosafe_der = rasn::der::encode(&safe)?;
        let sum = profile
            .checksum(key.key_bytes(), key_usage::KRB_SAFE_CKSUM, &zerosafe_der)
            .map_err(|e| Krb5Error::Crypto(e.to_string()))?;
        safe.cksum = Checksum {
            cksumtype: profile.checksum_type(),
            checksum: OctetString::from(sum),
        };
        let der = rasn::der::encode(&safe)?;
        self.check_replay(None, safe.cksum.checksum.to_vec())?;
        if self
            .flags
            .intersects(AuthContextFlags::DO_SEQUENCE | AuthContextFlags::RET_SEQUENCE)
        {
            self.local_seq = self.local_seq.wrapping_add(1);
        }
        Ok((der, self.ret_rdata(ts, usec, seq)))
    }

    /// Read and verify a KRB-SAFE message (rd_safe.c:43-178).
    pub fn rd_safe(&mut self, msg: &[u8]) -> Result<(Vec<u8>, ReplayData), Krb5Error> {
        if msg.first() != Some(&0x74) {
            return Err(ApError::MsgType.into());
        }
        let safe: KrbSafe = rasn::der::decode(msg).map_err(|_| Krb5Error::Ap(ApError::MsgType))?;
        if safe.pvno != 5 || safe.msg_type != 20 {
            return Err(ApError::MsgType.into());
        }
        let profile = match find_cksumtype(safe.cksum.cksumtype) {
            Ok(p) => p,
            Err(_) => {
                // Known unkeyed collision-proof types → InappCksum
                // (krb5_c_is_keyed_cksum false); unknown → SumTypeNoSupp.
                return Err(match safe.cksum.cksumtype {
                    1..=8 | 12 | 14 => ApError::InappCksum.into(),
                    _ => ApError::SumTypeNoSupp.into(),
                });
            }
        };
        self.check_addrs(
            Some(&safe.safe_body.s_address),
            safe.safe_body.r_address.as_ref(),
        )?;
        let key = self
            .recv_subkey
            .clone()
            .or_else(|| self.key.clone())
            .ok_or(Krb5Error::ReplyValidation("no key"))?;

        // Re-encode with the zero checksum and verify (rd_safe.c:76-99).
        let mut zerosafe = safe.clone();
        zerosafe.cksum = Checksum {
            cksumtype: 0,
            checksum: OctetString::from(Vec::new()),
        };
        let zerosafe_der = rasn::der::encode(&zerosafe)?;
        let mut valid = profile
            .verify_checksum(
                key.key_bytes(),
                key_usage::KRB_SAFE_CKSUM,
                &zerosafe_der,
                &safe.cksum.checksum,
            )
            .is_ok();
        if !valid {
            // RFC 1510 fallback: checksum over the KRB-SAFE-BODY alone.
            let body_der = rasn::der::encode(&safe.safe_body)?;
            valid = profile
                .verify_checksum(
                    key.key_bytes(),
                    key_usage::KRB_SAFE_CKSUM,
                    &body_der,
                    &safe.cksum.checksum,
                )
                .is_ok();
        }
        if !valid {
            return Err(ApError::Modified.into());
        }

        let rdata = (
            safe.safe_body.timestamp,
            safe.safe_body.usec,
            safe.safe_body.seq_number,
        );
        self.check_replay(rdata.0, safe.cksum.checksum.to_vec())?;
        if self.flags.contains(AuthContextFlags::DO_SEQUENCE) {
            if !self.check_seqnum(rdata.2.unwrap_or(0)) {
                return Err(ApError::BadOrder.into());
            }
            self.remote_seq = self.remote_seq.wrapping_add(1);
        }
        Ok((
            safe.safe_body.user_data.to_vec(),
            self.ret_rdata(rdata.0, rdata.1, rdata.2),
        ))
    }

    /// Build a KRB-PRIV message (mk_priv.c:88-150).
    pub fn mk_priv(&mut self, user_data: &[u8]) -> Result<(Vec<u8>, ReplayData), Krb5Error> {
        if self.local_addr.is_none() {
            return Err(ApError::LocalAddrRequired.into());
        }
        let (ts, usec, seq) = self.gen_rdata();
        let local = self.effective_local_addr();
        let remote = self.effective_remote_addr();
        let key = self
            .send_subkey
            .clone()
            .or_else(|| self.key.clone())
            .ok_or(Krb5Error::ReplyValidation("no key"))?;
        let profile = find_etype(key.keytype).map_err(|e| Krb5Error::Crypto(e.to_string()))?;
        let encpart = EncKrbPrivPart {
            user_data: OctetString::from(user_data.to_vec()),
            timestamp: ts,
            usec,
            seq_number: seq,
            s_address: local.expect("checked above"),
            r_address: remote,
        };
        let der = rasn::der::encode(&encpart)?;
        let cipher = profile
            .encrypt(key.key_bytes(), key_usage::KRB_PRIV_ENCPART, &der)
            .map_err(|e| Krb5Error::Crypto(e.to_string()))?;
        let privmsg = KrbPriv {
            pvno: 5,
            msg_type: 21,
            enc_part: EncryptedData {
                etype: key.keytype,
                kvno: None,
                cipher: OctetString::from(cipher),
            },
        };
        let out = rasn::der::encode(&privmsg)?;
        // Tag = trailing checksum-length bytes of ciphertext (rc_base.c:147).
        let tag_len = profile
            .checksum(key.key_bytes(), 0, &[])
            .map_err(|e| Krb5Error::Crypto(e.to_string()))?
            .len();
        let tag = privmsg.enc_part.cipher[privmsg.enc_part.cipher.len() - tag_len..].to_vec();
        self.check_replay(None, tag)?;
        if self
            .flags
            .intersects(AuthContextFlags::DO_SEQUENCE | AuthContextFlags::RET_SEQUENCE)
        {
            self.local_seq = self.local_seq.wrapping_add(1);
        }
        Ok((out, self.ret_rdata(ts, usec, seq)))
    }

    /// Read and verify a KRB-PRIV message (rd_priv.c:88-150).
    pub fn rd_priv(&mut self, msg: &[u8]) -> Result<(Vec<u8>, ReplayData), Krb5Error> {
        if msg.first() != Some(&0x75) {
            return Err(ApError::MsgType.into());
        }
        let privmsg: KrbPriv =
            rasn::der::decode(msg).map_err(|_| Krb5Error::Ap(ApError::MsgType))?;
        if privmsg.pvno != 5 || privmsg.msg_type != 21 {
            return Err(ApError::MsgType.into());
        }
        let key = self
            .recv_subkey
            .clone()
            .or_else(|| self.key.clone())
            .ok_or(Krb5Error::ReplyValidation("no key"))?;
        let profile =
            find_etype(privmsg.enc_part.etype).map_err(|e| Krb5Error::Crypto(e.to_string()))?;
        let plain = profile
            .decrypt(
                key.key_bytes(),
                key_usage::KRB_PRIV_ENCPART,
                &privmsg.enc_part.cipher,
            )
            .map_err(|_| Krb5Error::Ap(ApError::BadIntegrity))?;
        let encpart: EncKrbPrivPart =
            rasn::der::decode(&plain).map_err(|_| Krb5Error::Ap(ApError::BadIntegrity))?;
        self.check_addrs(Some(&encpart.s_address), encpart.r_address.as_ref())?;
        let tag_len = profile
            .checksum(key.key_bytes(), 0, &[])
            .map_err(|e| Krb5Error::Crypto(e.to_string()))?
            .len();
        let tag = privmsg.enc_part.cipher[privmsg.enc_part.cipher.len() - tag_len..].to_vec();
        self.check_replay(encpart.timestamp, tag)?;
        if self.flags.contains(AuthContextFlags::DO_SEQUENCE) {
            if !self.check_seqnum(encpart.seq_number.unwrap_or(0)) {
                return Err(ApError::BadOrder.into());
            }
            self.remote_seq = self.remote_seq.wrapping_add(1);
        }
        Ok((
            encpart.user_data.to_vec(),
            self.ret_rdata(encpart.timestamp, encpart.usec, encpart.seq_number),
        ))
    }
}
