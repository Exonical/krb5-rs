//! IOV per-message calls: gss_wrap_iov, gss_unwrap_iov, gss_get_mic_iov,
//! gss_verify_mic_iov and the `_length` forms (k5sealiov.c,
//! k5sealv3iov.c, k5unsealiov.c, util_cksum.c checksum_iov_v3).
//! Header, trailer and padding buffers are always resized, as with MIT's
//! GSS_IOV_BUFFER_FLAG_ALLOCATE.

use super::*;
use crate::crypto::CryptoIov;

/// GSS_IOV_BUFFER_TYPE_* (gssapi_ext.h).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IovType {
    /// GSS_IOV_BUFFER_TYPE_EMPTY.
    Empty,
    /// GSS_IOV_BUFFER_TYPE_DATA: encrypted (wrap) and signed.
    Data,
    /// GSS_IOV_BUFFER_TYPE_HEADER.
    Header,
    /// GSS_IOV_BUFFER_TYPE_MECH_PARAMS.
    MechParams,
    /// GSS_IOV_BUFFER_TYPE_TRAILER.
    Trailer,
    /// GSS_IOV_BUFFER_TYPE_PADDING (always empty for CFX).
    Padding,
    /// GSS_IOV_BUFFER_TYPE_STREAM: a complete wrap token to unwrap.
    Stream,
    /// GSS_IOV_BUFFER_TYPE_SIGN_ONLY: signed, never encrypted.
    SignOnly,
    /// GSS_IOV_BUFFER_TYPE_MIC_TOKEN.
    MicToken,
}

/// One gss_iov_buffer_desc.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GssIov {
    /// Buffer type.
    pub kind: IovType,
    /// Buffer contents.
    pub buf: Vec<u8>,
}

impl GssIov {
    /// A buffer of `kind` holding `buf`.
    pub fn new(kind: IovType, buf: impl Into<Vec<u8>>) -> Self {
        GssIov {
            kind,
            buf: buf.into(),
        }
    }
}

/// kg_locate_iov: the only buffer of `kind`; none if absent or repeated.
fn locate(iov: &[GssIov], kind: IovType) -> Option<usize> {
    let mut found = iov.iter().enumerate().filter(|(_, b)| b.kind == kind);
    let first = found.next().map(|(i, _)| i);
    if found.next().is_some() {
        None
    } else {
        first
    }
}

/// kg_translate_flag_iov: DATA and PADDING are DATA, SIGN_ONLY is
/// SIGN_ONLY, everything else is skipped.
fn regions<'a>(iov: &'a mut [GssIov], extra: Option<&'a mut [u8]>) -> Vec<CryptoIov<'a>> {
    let mut out: Vec<CryptoIov<'a>> = iov
        .iter_mut()
        .filter(|b| matches!(b.kind, IovType::Data | IovType::Padding | IovType::SignOnly))
        .map(|b| CryptoIov {
            sign_only: b.kind == IovType::SignOnly,
            data: &mut b.buf,
        })
        .collect();
    if let Some(data) = extra {
        out.push(CryptoIov {
            sign_only: false,
            data,
        });
    }
    out
}

/// checksum_iov_v3 input: the signed regions, then the 16-byte header.
fn checksum_input(iov: &[GssIov], hdr: &[u8]) -> Vec<u8> {
    let mut input = Vec::new();
    for b in iov
        .iter()
        .filter(|b| matches!(b.kind, IovType::Data | IovType::Padding | IovType::SignOnly))
    {
        input.extend_from_slice(&b.buf);
    }
    input.extend_from_slice(&hdr[..16]);
    input
}

fn crypto(e: crate::crypto::CryptoError) -> Krb5Error {
    Krb5Error::Crypto(e.to_string())
}

impl Krb5Context {
    /// gss_wrap_iov (kg_seal_iov, make_seal_token_v3_iov).  Returns
    /// conf_state: false when `conf` was asked for but there is no DATA
    /// buffer.
    pub fn wrap_iov(&mut self, conf: bool, iov: &mut [GssIov]) -> Result<bool, Krb5Error> {
        self.seal_iov(conf, iov, false)
    }

    /// gss_get_mic_iov: the MIC token goes into the MIC_TOKEN buffer.
    pub fn get_mic_iov(&mut self, iov: &mut [GssIov]) -> Result<(), Krb5Error> {
        self.seal_iov(false, iov, true).map(|_| ())
    }

    /// gss_wrap_iov_length (kg_seal_iov_length): sizes the header,
    /// trailer and padding buffers.
    pub fn wrap_iov_length(&self, conf: bool, iov: &mut [GssIov]) -> Result<bool, Krb5Error> {
        self.seal_iov_length(conf, iov, false)
    }

    /// gss_get_mic_iov_length.
    pub fn get_mic_iov_length(&self, iov: &mut [GssIov]) -> Result<(), Krb5Error> {
        self.seal_iov_length(false, iov, true).map(|_| ())
    }

    /// gss_unwrap_iov (kg_unseal_iov).  With a STREAM buffer the token is
    /// split as kg_unseal_stream_iov does and the plaintext is written to
    /// the single DATA buffer.  Returns `(conf_state, sequence status)`.
    pub fn unwrap_iov(&mut self, iov: &mut [GssIov]) -> Result<(bool, SeqStatus), Krb5Error> {
        if locate(iov, IovType::Stream).is_some() {
            self.unseal_stream_iov(iov)
        } else {
            self.unseal_iov(iov, false)
        }
    }

    /// gss_verify_mic_iov: the token is in the MIC_TOKEN buffer.
    pub fn verify_mic_iov(&mut self, iov: &mut [GssIov]) -> Result<SeqStatus, Krb5Error> {
        if locate(iov, IovType::Stream).is_some() {
            return Err(gss(GssError::Failure));
        }
        self.unseal_iov(iov, true).map(|(_, seq)| seq)
    }

    fn seal_iov(&mut self, conf: bool, iov: &mut [GssIov], mic: bool) -> Result<bool, Krb5Error> {
        // kg_seal_iov: no DATA buffer means integrity only.
        let conf = conf && !mic && iov.iter().any(|b| b.kind == IovType::Data);
        let hidx = locate(
            iov,
            if mic {
                IovType::MicToken
            } else {
                IovType::Header
            },
        )
        .ok_or(gss(GssError::Failure))?;
        let tidx = if mic {
            None
        } else {
            locate(iov, IovType::Trailer)
        };
        if let Some(p) = locate(iov, IovType::Padding) {
            iov[p].buf.clear();
        }
        let key = self.msg_key().clone();
        let profile = find_etype(key.keytype).map_err(crypto)?;
        let usage = match (mic, self.initiate) {
            (false, true) => USAGE_INITIATOR_SEAL,
            (false, false) => USAGE_ACCEPTOR_SEAL,
            (true, true) => USAGE_INITIATOR_SIGN,
            (true, false) => USAGE_ACCEPTOR_SIGN,
        };
        let dce = self.flags.contains(GssFlags::DCE_STYLE);
        let mut hdr = [0u8; 16];
        hdr[..2].copy_from_slice(&if mic { TOK_MIC } else { TOK_WRAP }.to_be_bytes());
        hdr[2] = if self.initiate {
            0
        } else {
            FLAG_SENDER_IS_ACCEPTOR
        } | if self.acceptor_subkey.is_some() {
            FLAG_ACCEPTOR_SUBKEY
        } else {
            0
        };
        hdr[3] = 0xff;
        hdr[8..].copy_from_slice(&self.seq_send.to_be_bytes());
        let (header, trailer) = if conf {
            hdr[2] |= FLAG_WRAP_CONFIDENTIAL;
            // CTS needs no padding, so EC is 0 unless DCE style.
            let ec = if dce { profile.block_size() } else { 0 };
            hdr[4..6].copy_from_slice(&(ec as u16).to_be_bytes());
            let mut tbuf = vec![0xff; ec];
            tbuf.extend_from_slice(&hdr);
            let (conf_ct, cksum) = profile
                .encrypt_iov(key.key_bytes(), usage, &mut regions(iov, Some(&mut tbuf)))
                .map_err(crypto)?;
            let rrc = if tidx.is_none() {
                ec + 16 + cksum.len() - if dce { ec } else { 0 }
            } else {
                0
            };
            hdr[6..8].copy_from_slice(&(rrc as u16).to_be_bytes());
            let mut trailer = tbuf;
            trailer.extend_from_slice(&cksum);
            let mut header = hdr.to_vec();
            if tidx.is_none() {
                header.extend_from_slice(&trailer);
            }
            header.extend_from_slice(&conf_ct);
            (header, trailer)
        } else {
            if mic {
                hdr[4..8].copy_from_slice(&[0xff; 4]);
            }
            let cksum = profile
                .checksum(key.key_bytes(), usage, &checksum_input(iov, &hdr))
                .map_err(crypto)?;
            if !mic {
                let rrc = if tidx.is_none() { cksum.len() } else { 0 };
                hdr[4..6].copy_from_slice(&(cksum.len() as u16).to_be_bytes());
                hdr[6..8].copy_from_slice(&(rrc as u16).to_be_bytes());
            }
            let mut header = hdr.to_vec();
            if tidx.is_none() {
                header.extend_from_slice(&cksum);
            }
            (header, cksum)
        };
        iov[hidx].buf = header;
        if let Some(t) = tidx {
            iov[t].buf = trailer;
        }
        self.seq_send += 1;
        Ok(conf)
    }

    fn seal_iov_length(
        &self,
        conf: bool,
        iov: &mut [GssIov],
        mic: bool,
    ) -> Result<bool, Krb5Error> {
        let hidx = locate(
            iov,
            if mic {
                IovType::MicToken
            } else {
                IovType::Header
            },
        )
        .ok_or(gss(GssError::Failure))?;
        let tidx = locate(iov, IovType::Trailer);
        let dce_or_mic = mic || self.flags.contains(GssFlags::DCE_STYLE);
        let conf = conf && iov.iter().any(|b| b.kind == IovType::Data);
        let profile = find_etype(self.msg_key().keytype).map_err(crypto)?;
        let mut headerlen = 16;
        let trailerlen = if conf {
            headerlen += profile.confounder_size();
            let ec = if dce_or_mic { profile.block_size() } else { 0 };
            16 + profile.checksum_size() + ec
        } else {
            profile.checksum_size()
        };
        match tidx {
            None => headerlen += trailerlen,
            Some(t) => iov[t].buf = vec![0; trailerlen],
        }
        if let Some(p) = locate(iov, IovType::Padding) {
            iov[p].buf.clear();
        }
        iov[hidx].buf = vec![0; headerlen];
        Ok(conf)
    }

    /// kg_unseal_iov_token / gss_krb5int_unseal_v3_iov.
    fn unseal_iov(
        &mut self,
        iov: &mut [GssIov],
        mic: bool,
    ) -> Result<(bool, SeqStatus), Krb5Error> {
        let hidx = locate(
            iov,
            if mic {
                IovType::MicToken
            } else {
                IovType::Header
            },
        )
        .ok_or(gss(GssError::Failure))?;
        if locate(iov, IovType::Padding).is_some_and(|p| !iov[p].buf.is_empty()) {
            return Err(gss(GssError::DefectiveToken));
        }
        let tidx = locate(iov, IovType::Trailer);
        let mut header = iov[hidx].buf.clone();
        // Only CFX token ids are supported (no RFC 1964 tokens).
        if header.len() < 2
            || ![TOK_MIC, TOK_WRAP, 0x0405].contains(&u16::from_be_bytes([header[0], header[1]]))
        {
            return Err(gss(GssError::DefectiveToken));
        }
        let hdr = self.check_common(&header, if mic { TOK_MIC } else { TOK_WRAP })?;
        let (key, usage) = self.recv_key_usage(&header, !mic)?;
        let key = key.clone();
        let profile = find_etype(key.keytype).map_err(crypto)?;
        let k5_trailer = profile.checksum_size();
        let seq = u64::from_be_bytes(hdr[8..16].try_into().expect("8"));
        let bad_sig = || gss(GssError::BadSig);
        let mut conf = false;
        if !mic {
            conf = hdr[2] & FLAG_WRAP_CONFIDENTIAL != 0;
            let ec = u16::from_be_bytes([hdr[4], hdr[5]]) as usize;
            let rrc = u16::from_be_bytes([hdr[6], hdr[7]]) as usize;
            let dce = self.flags.contains(GssFlags::DCE_STYLE);
            if tidx.is_none() {
                let desired = k5_trailer
                    + if conf {
                        16 + if dce { 0 } else { ec }
                    } else {
                        0
                    };
                if rrc != desired {
                    return Err(gss(GssError::DefectiveToken));
                }
            } else if rrc != 0 {
                return Err(gss(GssError::DefectiveToken));
            }
            if conf {
                // kg_translate_iov_v3.
                let k5_header = profile.confounder_size();
                let gss_trailerlen = ec + 16 + k5_trailer;
                let mut gss_headerlen = 16 + k5_header;
                match tidx {
                    None => {
                        if rrc + if dce { ec } else { 0 } != gss_trailerlen {
                            return Err(bad_sig());
                        }
                        gss_headerlen += gss_trailerlen;
                    }
                    Some(t) if iov[t].buf.len() != gss_trailerlen => return Err(bad_sig()),
                    Some(_) => {}
                }
                if header.len() != gss_headerlen {
                    return Err(bad_sig());
                }
                let mut tail = match tidx {
                    None => header[16..16 + gss_trailerlen].to_vec(),
                    Some(t) => iov[t].buf.clone(),
                };
                let confounder = header[header.len() - k5_header..].to_vec();
                let (tbuf, cksum) = tail.split_at_mut(ec + 16);
                profile
                    .decrypt_iov(
                        key.key_bytes(),
                        usage,
                        &confounder,
                        &mut regions(iov, Some(tbuf)),
                        cksum,
                    )
                    .map_err(|_| bad_sig())?;
                let alt = &tail[ec..ec + 16];
                if alt[..2] != TOK_WRAP.to_be_bytes()
                    || alt[2] != hdr[2]
                    || alt[3] != hdr[3]
                    || u16::from_be_bytes([alt[4], alt[5]]) as usize != ec
                    || alt[8..] != hdr[8..]
                {
                    return Err(gss(GssError::DefectiveToken));
                }
                match tidx {
                    None => header[16..16 + gss_trailerlen].copy_from_slice(&tail),
                    Some(t) => iov[t].buf = tail,
                }
                iov[hidx].buf = header;
            } else {
                if ec != k5_trailer {
                    return Err(gss(GssError::DefectiveToken));
                }
                header[4..8].fill(0);
                iov[hidx].buf = header.clone();
                self.verify_checksum_iov(iov, &header, tidx, rrc, &key, usage)?;
            }
        } else {
            let rrc = if tidx.is_some() { 0 } else { header.len() - 16 };
            self.verify_checksum_iov(iov, &header, tidx, rrc, &key, usage)?;
        }
        Ok((conf, self.seqstate.check(seq)))
    }

    /// checksum_iov_v3 with verify set.
    fn verify_checksum_iov(
        &self,
        iov: &[GssIov],
        header: &[u8],
        tidx: Option<usize>,
        rrc: usize,
        key: &EncryptionKey,
        usage: i32,
    ) -> Result<(), Krb5Error> {
        let profile = find_etype(key.keytype).map_err(crypto)?;
        let len = profile.checksum_size();
        let cksum = match tidx {
            None if rrc == len && header.len() == 16 + len => &header[16..],
            Some(t) if iov[t].buf.len() == len => &iov[t].buf[..],
            _ => return Err(gss(GssError::BadSig)),
        };
        profile
            .verify_checksum(key.key_bytes(), usage, &checksum_input(iov, header), cksum)
            .map_err(|_| gss(GssError::BadSig))
    }

    /// kg_unseal_stream_iov: split STREAM into HEADER | SIGN_ONLY/DATA |
    /// PADDING | TRAILER and unwrap that.
    fn unseal_stream_iov(&mut self, iov: &mut [GssIov]) -> Result<(bool, SeqStatus), Krb5Error> {
        if self.flags.contains(GssFlags::DCE_STYLE) {
            return Err(gss(GssError::Failure));
        }
        let sidx = locate(iov, IovType::Stream).ok_or(gss(GssError::Failure))?;
        let mut stream = iov[sidx].buf.clone();
        if stream.len() < 16 {
            return Err(gss(GssError::DefectiveToken));
        }
        let data_idx: Vec<usize> = (0..iov.len())
            .filter(|&i| iov[i].kind == IovType::Data)
            .collect();
        let [data_idx] = data_idx[..] else {
            return Err(gss(GssError::Failure));
        };
        let toktype = u16::from_be_bytes([stream[0], stream[1]]);
        if ![TOK_MIC, TOK_WRAP, 0x0405].contains(&toktype) {
            return Err(gss(GssError::DefectiveToken));
        }
        let profile = find_etype(self.msg_key().keytype).map_err(crypto)?;
        let conf = stream[2] & FLAG_WRAP_CONFIDENTIAL != 0;
        let ec = if conf {
            u16::from_be_bytes([stream[4], stream[5]]) as usize
        } else {
            0
        };
        let rrc = u16::from_be_bytes([stream[6], stream[7]]) as usize;
        if rrc != 0 {
            let body = &mut stream[16..];
            if !body.is_empty() {
                let n = rrc % body.len();
                body.rotate_left(n);
            }
            stream[6..8].fill(0);
        }
        let headerlen = 16 + if conf { profile.confounder_size() } else { 0 };
        let trailerlen = ec + if conf { 16 } else { 0 } + profile.checksum_size();
        if stream.len() < headerlen + trailerlen {
            return Err(gss(GssError::DefectiveToken));
        }
        let mut tiov = vec![GssIov::new(IovType::Header, &stream[..headerlen])];
        let mut tdata = 0;
        for (i, b) in iov.iter().enumerate() {
            if i == data_idx {
                tdata = tiov.len();
                tiov.push(GssIov::new(
                    IovType::Data,
                    &stream[headerlen..stream.len() - trailerlen],
                ));
            } else if b.kind == IovType::SignOnly {
                tiov.push(b.clone());
            }
        }
        tiov.push(GssIov::new(IovType::Padding, Vec::new()));
        tiov.push(GssIov::new(
            IovType::Trailer,
            &stream[stream.len() - trailerlen..],
        ));
        let out = self.unseal_iov(&mut tiov, false)?;
        iov[data_idx].buf = std::mem::take(&mut tiov[tdata].buf);
        Ok(out)
    }
}
