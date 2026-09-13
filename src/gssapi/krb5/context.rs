//! Established context: wrap/unwrap/MIC (k5sealv3.c, util_crypt.c).

use super::*;

/// Output of [`Krb5Context::unwrap`].  `seq` carries the MIT
/// supplementary sequence status (the message is still valid even when
/// it is Gap/Unseq/Old/Duplicate — callers decide whether to drop it).
#[derive(Debug)]
pub struct Unwrapped {
    /// Plaintext message.
    pub data: Vec<u8>,
    /// Whether the token was confidentiality-protected.
    pub conf: bool,
    /// Sequence/replay status.
    pub seq: SeqStatus,
}

/// An established krb5 GSS context (krb5_gss_ctx_id_rec, proto 1).
pub struct Krb5Context {
    pub(super) flags: GssFlags,
    pub(super) initiate: bool,
    pub(super) initiator: PrincipalName,
    pub(super) crealm: String,
    pub(super) acceptor: PrincipalName,
    pub(super) endtime: KerberosTime,
    /// MIT `ctx->subkey` (initiator's subkey, or session key if none).
    pub(super) key: EncryptionKey,
    /// MIT `ctx->acceptor_subkey`; `Some` == have_acceptor_subkey.
    pub(super) acceptor_subkey: Option<EncryptionKey>,
    pub(super) seq_send: u64,
    pub(super) seqstate: SeqState,
}

impl Krb5Context {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn partial(
        flags: GssFlags,
        initiate: bool,
        initiator: PrincipalName,
        crealm: String,
        acceptor: PrincipalName,
        endtime: KerberosTime,
        key: EncryptionKey,
        seq_send: u64,
    ) -> Self {
        Krb5Context {
            flags,
            initiate,
            initiator,
            crealm,
            acceptor,
            endtime,
            key,
            acceptor_subkey: None,
            seq_send,
            seqstate: SeqState::new(0, false, false, true),
        }
    }

    /// Established context flags (incl. TRANS and PROT_READY).
    pub fn flags(&self) -> GssFlags {
        self.flags
    }

    /// SPNEGO reports `ctx_flags & ~GSS_C_PROT_READY_FLAG`
    /// (spnego_mech.c:1093-1094, :1684).
    pub(crate) fn clear_prot_ready(&mut self) {
        self.flags &= !GssFlags::PROT_READY;
    }

    /// Initiator principal.
    pub fn initiator(&self) -> &PrincipalName {
        &self.initiator
    }

    /// Initiator realm.
    pub fn initiator_realm(&self) -> &str {
        &self.crealm
    }

    /// Acceptor (service) principal.
    pub fn acceptor(&self) -> &PrincipalName {
        &self.acceptor
    }

    /// True on the initiator side.
    pub fn is_initiator(&self) -> bool {
        self.initiate
    }

    /// Remaining credential lifetime (saturates at zero).
    pub fn lifetime(&self) -> Duration {
        let now = chrono::Utc::now();
        self.endtime
            .with_timezone(&chrono::Utc)
            .signed_duration_since(now)
            .to_std()
            .unwrap_or(Duration::ZERO)
    }

    /// The per-message key: acceptor subkey when present, else `key`
    /// (k5sealv3.c:86-93).
    fn msg_key(&self) -> &EncryptionKey {
        self.acceptor_subkey.as_ref().unwrap_or(&self.key)
    }

    /// Wrap a message (k5sealv3.c:60-287 make_seal_token_v3).
    pub fn wrap(&mut self, conf: bool, msg: &[u8]) -> Result<Vec<u8>, Krb5Error> {
        let key = self.msg_key().clone();
        let profile = find_etype(key.keytype).map_err(|e| Krb5Error::Crypto(e.to_string()))?;
        let usage = if self.initiate {
            USAGE_INITIATOR_SEAL
        } else {
            USAGE_ACCEPTOR_SEAL
        };
        let mut hdr = Vec::with_capacity(16);
        hdr.extend_from_slice(&TOK_WRAP.to_be_bytes());
        hdr.push(
            if self.initiate {
                0
            } else {
                FLAG_SENDER_IS_ACCEPTOR
            } | if conf { FLAG_WRAP_CONFIDENTIAL } else { 0 }
                | if self.acceptor_subkey.is_some() {
                    FLAG_ACCEPTOR_SUBKEY
                } else {
                    0
                },
        );
        hdr.push(0xff);
        if conf {
            hdr.extend_from_slice(&0u16.to_be_bytes()); // EC
            hdr.extend_from_slice(&0u16.to_be_bytes()); // RRC
            hdr.extend_from_slice(&self.seq_send.to_be_bytes());
            let mut plain = Vec::with_capacity(msg.len() + 16);
            plain.extend_from_slice(msg);
            plain.extend_from_slice(&hdr);
            let cipher = profile
                .encrypt(key.key_bytes(), usage, &plain)
                .map_err(|e| Krb5Error::Crypto(e.to_string()))?;
            let mut token = hdr;
            token.extend_from_slice(&cipher);
            self.seq_send += 1;
            Ok(token)
        } else {
            hdr.extend_from_slice(&0u16.to_be_bytes()); // EC=0 for checksum
            hdr.extend_from_slice(&0u16.to_be_bytes()); // RRC
            hdr.extend_from_slice(&self.seq_send.to_be_bytes());
            let mut plain = Vec::with_capacity(msg.len() + 16);
            plain.extend_from_slice(msg);
            plain.extend_from_slice(&hdr);
            let sum = profile
                .checksum(key.key_bytes(), usage, &plain)
                .map_err(|e| Krb5Error::Crypto(e.to_string()))?;
            let mut token = hdr;
            // Fix up EC = checksum length (:253-265).
            token[4..6].copy_from_slice(&(sum.len() as u16).to_be_bytes());
            token.extend_from_slice(msg);
            token.extend_from_slice(&sum);
            self.seq_send += 1;
            Ok(token)
        }
    }

    /// Unwrap a message (k5sealv3iov.c:274-468 unseal_v3_iov).
    ///
    /// RRC handling deviation: MIT's flat-token path requires
    /// `rrc == trailer_len + 16 + ec`; this API accepts any RRC by rotating
    /// the body left by `rrc` first (k5unsealiov.c:471-478 semantics), which
    /// is a strict superset of what MIT accepts for contiguous tokens.
    pub fn unwrap(&mut self, token: &[u8]) -> Result<Unwrapped, Krb5Error> {
        let (key, usage) = self.recv_key_usage(token, true)?;
        let hdr = self.check_common(token, TOK_WRAP)?;
        let conf = token[2] & FLAG_WRAP_CONFIDENTIAL != 0;
        let ec = u16::from_be_bytes(token[4..6].try_into().expect("2")) as usize;
        let rrc = u16::from_be_bytes(token[6..8].try_into().expect("2")) as usize;
        let seq = u64::from_be_bytes(token[8..16].try_into().expect("8"));
        let profile = find_etype(key.keytype).map_err(|e| Krb5Error::Crypto(e.to_string()))?;
        let mut body = token[16..].to_vec();
        if rrc != 0 {
            let n = rrc % body.len().max(1);
            body.rotate_left(n);
        }
        let data = if conf {
            let plain = profile
                .decrypt(key.key_bytes(), usage, &body)
                .map_err(|_| Krb5Error::Gss(GssError::BadSig))?;
            if plain.len() < 16 + ec {
                return Err(gss(GssError::DefectiveToken));
            }
            // Validate the embedded header copy (:402-409).
            let althdr = &plain[plain.len() - 16..];
            if althdr[..2] != TOK_WRAP.to_be_bytes()
                || althdr[2] != token[2]
                || althdr[3] != token[3]
                || u16::from_be_bytes(althdr[4..6].try_into().expect("2")) as usize != ec
                || althdr[8..] != token[8..16]
            {
                return Err(gss(GssError::DefectiveToken));
            }
            plain[..plain.len() - 16 - ec].to_vec()
        } else {
            // Mandatory-cksumtype checksum length (hmac-sha1-96 = 12 for
            // etypes 17/18; aes-sha2 = 16/24 for etypes 19/20).
            let cksum_len = profile.checksum_size();
            if ec != cksum_len || body.len() < cksum_len {
                return Err(gss(GssError::DefectiveToken));
            }
            let msg = &body[..body.len() - cksum_len];
            let mut hdr_zeroed = hdr.clone();
            hdr_zeroed[4] = 0;
            hdr_zeroed[5] = 0;
            hdr_zeroed[6] = 0;
            hdr_zeroed[7] = 0;
            let mut input = Vec::with_capacity(msg.len() + 16);
            input.extend_from_slice(msg);
            input.extend_from_slice(&hdr_zeroed);
            profile
                .verify_checksum(
                    key.key_bytes(),
                    usage,
                    &input,
                    &body[body.len() - cksum_len..],
                )
                .map_err(|_| Krb5Error::Gss(GssError::BadSig))?;
            msg.to_vec()
        };
        Ok(Unwrapped {
            data,
            conf,
            seq: self.seqstate.check(seq),
        })
    }

    /// Generate a MIC token (k5sealv3.c KG_TOK_MIC_MSG path).
    pub fn get_mic(&mut self, msg: &[u8]) -> Result<Vec<u8>, Krb5Error> {
        let key = self.msg_key().clone();
        let profile = find_etype(key.keytype).map_err(|e| Krb5Error::Crypto(e.to_string()))?;
        let usage = if self.initiate {
            USAGE_INITIATOR_SIGN
        } else {
            USAGE_ACCEPTOR_SIGN
        };
        let mut hdr = Vec::with_capacity(16);
        hdr.extend_from_slice(&TOK_MIC.to_be_bytes());
        hdr.push(
            if self.initiate {
                0
            } else {
                FLAG_SENDER_IS_ACCEPTOR
            } | if self.acceptor_subkey.is_some() {
                FLAG_ACCEPTOR_SUBKEY
            } else {
                0
            },
        );
        hdr.push(0xff);
        hdr.extend_from_slice(&0xffffu16.to_be_bytes());
        hdr.extend_from_slice(&0xffffu16.to_be_bytes());
        hdr.extend_from_slice(&self.seq_send.to_be_bytes());
        let mut input = Vec::with_capacity(msg.len() + 16);
        input.extend_from_slice(msg);
        input.extend_from_slice(&hdr);
        let sum = profile
            .checksum(key.key_bytes(), usage, &input)
            .map_err(|e| Krb5Error::Crypto(e.to_string()))?;
        let mut token = hdr;
        token.extend_from_slice(&sum);
        self.seq_send += 1;
        Ok(token)
    }

    /// Verify a MIC token over `msg`; the Ok value is the supplementary
    /// sequence status (like `unwrap`, verification still succeeds).
    pub fn verify_mic(&mut self, msg: &[u8], mic: &[u8]) -> Result<SeqStatus, Krb5Error> {
        let (key, usage) = self.recv_key_usage(mic, false)?;
        let hdr = self.check_common(mic, TOK_MIC)?;
        let seq = u64::from_be_bytes(mic[8..16].try_into().expect("8"));
        let profile = find_etype(key.keytype).map_err(|e| Krb5Error::Crypto(e.to_string()))?;
        let mut input = Vec::with_capacity(msg.len() + 16);
        input.extend_from_slice(msg);
        input.extend_from_slice(&hdr);
        profile
            .verify_checksum(key.key_bytes(), usage, &input, &mic[16..])
            .map_err(|_| Krb5Error::Gss(GssError::BadSig))?;
        Ok(self.seqstate.check(seq))
    }

    /// Header checks shared by unwrap/verify_mic: length, direction
    /// (k5sealv3iov.c:314-318), tok id, filler byte.  Returns the 16-byte
    /// header as received.
    fn check_common(&self, token: &[u8], tok_id: u16) -> Result<Vec<u8>, Krb5Error> {
        if token.len() < 16 {
            return Err(gss(GssError::DefectiveToken));
        }
        let acceptor_flag = if self.initiate {
            FLAG_SENDER_IS_ACCEPTOR
        } else {
            0
        };
        if token[2] & FLAG_SENDER_IS_ACCEPTOR != acceptor_flag {
            return Err(gss(GssError::BadSig));
        }
        if u16::from_be_bytes(token[..2].try_into().expect("2")) != tok_id {
            return Err(gss(GssError::DefectiveToken));
        }
        if token[3] != 0xff {
            return Err(gss(GssError::DefectiveToken));
        }
        Ok(token[..16].to_vec())
    }

    /// The peer's per-message key and usage (seal vs sign).  The acceptor
    /// subkey is used only when we have it AND the token flags it
    /// (k5sealv3iov.c:322-329).
    fn recv_key_usage(&self, token: &[u8], seal: bool) -> Result<(&EncryptionKey, i32), Krb5Error> {
        let usage = if seal {
            if self.initiate {
                USAGE_ACCEPTOR_SEAL
            } else {
                USAGE_INITIATOR_SEAL
            }
        } else if self.initiate {
            USAGE_ACCEPTOR_SIGN
        } else {
            USAGE_INITIATOR_SIGN
        };
        let key = match &self.acceptor_subkey {
            Some(sub) if token.len() >= 3 && token[2] & FLAG_ACCEPTOR_SUBKEY != 0 => sub,
            _ => &self.key,
        };
        Ok((key, usage))
    }

    /// Largest plaintext fitting `output_size` (wrap_size_limit.c:98-150
    /// CFX branch).
    pub fn wrap_size_limit(&self, conf: bool, output_size: usize) -> usize {
        let key = self.msg_key();
        let Ok(profile) = find_etype(key.keytype) else {
            return 0;
        };
        if conf {
            // CTS encrypts without block padding, so
            // encrypt_size(n) = n + confounder + trailer
            // (krb5int_aes_crypto_length).  MIT's loop converges to the
            // closed form output - 16 - confounder - trailer, then
            // subtracts 16 for the encrypted header copy (:112-119).
            let sz = output_size
                .saturating_sub(16 + profile.confounder_size() + profile.checksum_size());
            // MIT's `if (sz > 16) sz -= 16; else sz = 0` — saturating_sub is
            // equivalent.
            sz.saturating_sub(16)
        } else {
            output_size.saturating_sub(16 + profile.checksum_size())
        }
    }
}
