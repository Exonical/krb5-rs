//! KRB-CRED messages (mk_cred.c, rd_cred.c).

use super::*;

impl AuthContext {
    /// Build a KRB-CRED message (mk_cred.c:37-212; unencrypted form per
    /// RFC 6448 when no key is available).
    pub fn mk_cred(&mut self, creds: &[Credential]) -> Result<(Vec<u8>, ReplayData), Krb5Error> {
        let (mut ts, mut usec, seq) = self.gen_rdata();
        // mk_cred.c:176-181 — historically the timestamp is always set.
        if ts.is_none() {
            let (t, u) = self.now();
            ts = Some(t);
            usec = Some(u);
        }
        let local = self.effective_local_addr();
        let remote = self.effective_remote_addr();
        let key = self.send_subkey.clone().or_else(|| self.key.clone());

        let mut tickets = Vec::with_capacity(creds.len());
        let mut infos = Vec::with_capacity(creds.len());
        for c in creds {
            tickets.push(c.ticket.clone());
            infos.push(KrbCredInfo {
                key: c.session_key.clone(),
                prealm: Some(
                    GeneralString::from_bytes(c.crealm.as_bytes())
                        .map_err(|_| Krb5Error::ReplyValidation("invalid crealm"))?,
                ),
                pname: Some(c.client.clone()),
                flags: Some(c.flags),
                authtime: Some(c.times.authtime),
                starttime: c.times.starttime,
                endtime: Some(c.times.endtime),
                renew_till: c.times.renew_till,
                srealm: Some(
                    GeneralString::from_bytes(c.srealm.as_bytes())
                        .map_err(|_| Krb5Error::ReplyValidation("invalid srealm"))?,
                ),
                sname: Some(c.server.clone()),
                caddr: c.addresses.clone(),
            });
        }
        let encpart = EncKrbCredPart {
            ticket_info: infos,
            nonce: seq,
            timestamp: ts,
            usec,
            s_address: local,
            r_address: remote,
        };
        let der = rasn::der::encode(&encpart)?;
        let enc_data = if let Some(key) = &key {
            let profile = find_etype(key.keytype).map_err(|e| Krb5Error::Crypto(e.to_string()))?;
            let cipher = profile
                .encrypt(key.key_bytes(), key_usage::KRB_CRED_ENCPART, &der)
                .map_err(|e| Krb5Error::Crypto(e.to_string()))?;
            EncryptedData {
                etype: key.keytype,
                kvno: None,
                cipher: OctetString::from(cipher),
            }
        } else {
            EncryptedData {
                etype: 0,
                kvno: None,
                cipher: OctetString::from(der),
            }
        };
        let cred_msg = KrbCred {
            pvno: 5,
            msg_type: 22,
            tickets,
            enc_part: enc_data.clone(),
        };
        let out = rasn::der::encode(&cred_msg)?;
        if let Some(key) = &key {
            let profile = find_etype(key.keytype).map_err(|e| Krb5Error::Crypto(e.to_string()))?;
            let tag_len = profile
                .checksum(key.key_bytes(), 0, &[])
                .map_err(|e| Krb5Error::Crypto(e.to_string()))?
                .len();
            let tag = enc_data.cipher[enc_data.cipher.len() - tag_len..].to_vec();
            self.check_replay(None, tag)?;
        }
        if self
            .flags
            .intersects(AuthContextFlags::DO_SEQUENCE | AuthContextFlags::RET_SEQUENCE)
        {
            self.local_seq = self.local_seq.wrapping_add(1);
        }
        Ok((out, self.ret_rdata(ts, usec, seq)))
    }

    /// Read and verify a KRB-CRED message (rd_cred.c:42-204).
    pub fn rd_cred(&mut self, msg: &[u8]) -> Result<(Vec<Credential>, ReplayData), Krb5Error> {
        if msg.first() != Some(&0x76) {
            return Err(ApError::MsgType.into());
        }
        let cred_msg: KrbCred =
            rasn::der::decode(msg).map_err(|_| Krb5Error::Ap(ApError::MsgType))?;
        if cred_msg.pvno != 5 || cred_msg.msg_type != 22 {
            return Err(ApError::MsgType.into());
        }
        let cipher = cred_msg.enc_part.cipher.to_vec();
        let encpart: EncKrbCredPart = if self.recv_subkey.is_none() && self.key.is_none() {
            rasn::der::decode(&cipher)?
        } else {
            let mut plain = None;
            for key in [self.recv_subkey.as_ref(), self.key.as_ref()]
                .into_iter()
                .flatten()
            {
                if let Ok(profile) = find_etype(cred_msg.enc_part.etype) {
                    if let Ok(p) =
                        profile.decrypt(key.key_bytes(), key_usage::KRB_CRED_ENCPART, &cipher)
                    {
                        plain = Some(p);
                        break;
                    }
                }
            }
            let plain = plain.ok_or(Krb5Error::Ap(ApError::BadIntegrity))?;
            rasn::der::decode(&plain).map_err(|_| Krb5Error::Ap(ApError::BadIntegrity))?
        };

        let mut out = Vec::with_capacity(cred_msg.tickets.len());
        for (i, ticket) in cred_msg.tickets.iter().enumerate() {
            let info = encpart
                .ticket_info
                .get(i)
                .ok_or(Krb5Error::Ap(ApError::Modified))?;
            out.push(Credential {
                client: info.pname.clone().unwrap_or_else(|| PrincipalName {
                    name_type: 0,
                    name_string: Vec::new(),
                }),
                crealm: info
                    .prealm
                    .as_ref()
                    .map(|r| String::from_utf8_lossy(r.as_ref()).to_string())
                    .unwrap_or_default(),
                server: info.sname.clone().unwrap_or_else(|| PrincipalName {
                    name_type: 0,
                    name_string: Vec::new(),
                }),
                srealm: info
                    .srealm
                    .as_ref()
                    .map(|r| String::from_utf8_lossy(r.as_ref()).to_string())
                    .unwrap_or_default(),
                session_key: info.key.clone(),
                times: crate::protocol::credential::TicketTimes {
                    authtime: info.authtime.unwrap_or_else(now_kerberos),
                    starttime: info.starttime,
                    endtime: info.endtime.unwrap_or_else(now_kerberos),
                    renew_till: info.renew_till,
                },
                ticket: ticket.clone(),
                flags: info.flags.unwrap_or_default(),
                addresses: info.caddr.clone(),
                authdata: None,
            });
        }

        if self.recv_subkey.is_some() || self.key.is_some() {
            let profile = find_etype(cred_msg.enc_part.etype)
                .map_err(|e| Krb5Error::Crypto(e.to_string()))?;
            let tag_len = profile
                .checksum(
                    self.recv_subkey
                        .as_ref()
                        .or(self.key.as_ref())
                        .expect("keyed")
                        .key_bytes(),
                    0,
                    &[],
                )
                .map_err(|e| Krb5Error::Crypto(e.to_string()))?
                .len();
            let tag = cipher[cipher.len() - tag_len..].to_vec();
            self.check_replay(encpart.timestamp, tag)?;
        }
        if self.flags.contains(AuthContextFlags::DO_SEQUENCE) {
            if encpart.nonce.unwrap_or(0) != self.remote_seq {
                return Err(ApError::BadOrder.into());
            }
            self.remote_seq = self.remote_seq.wrapping_add(1);
        }
        Ok((
            out,
            self.ret_rdata(encpart.timestamp, encpart.usec, encpart.nonce),
        ))
    }
}
