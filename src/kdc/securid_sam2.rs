//! MIT's `securid_sam2` kdcpreauth module (plugins/preauth/securid_sam2):
//! SAM-2 challenges (PA-SAM-CHALLENGE-2) for principals with a
//! `<client>/SECURID` or `<client>/GRAIL` entry, and verification of the
//! client's PA-SAM-RESPONSE-2.
//!
//! MIT calls RSA's proprietary ACE/Server SDK (`SD_Init`, `SD_Lock`,
//! `SD_Check`, `SD_Next`, `SD_Pin`, `SD_Close`, `AceGetMaxPinLen`, ...)
//! in-process. Here those calls go through [`AceServer`], which a deployment
//! implements, for example over the socket RPC of
//! [`super::plugins::rpc::securid_ace`]. GRAIL is MIT's test mechanism,
//! compiled in only with `GRAIL_PREAUTH`; here it is off unless
//! [`SecuridSam2::with_grail`] turns it on.

use std::sync::Arc;

use rasn::types::{Any, OctetString};

use super::db::{KvnoSel, PrincipalEntry};
use super::error::{general_string, KdcError};
use super::preauth::ClientKey;
use super::{Kdc, PrincipalStore};
use crate::crypto::find_etype;
use crate::sam2::{
    opt, EncSamResponseEnc2, SamChallenge2, SamChallenge2Body, SamFlags, SamResponse2,
    KEYUSAGE_CHALLENGE_CKSUM, KEYUSAGE_CHALLENGE_TRACKID, KEYUSAGE_RESPONSE, PA_SAM_CHALLENGE_2,
    TYPE_GRAIL, TYPE_SECURID,
};
use crate::types::error_codes::*;
use crate::types::{Checksum, EncryptionKey, PaData};

/// `KRB5KDC_ERR_DISCARD`: the KDC sends no reply at all (do_as_req.c:372).
pub(crate) const KDC_ERR_DISCARD: i32 = -1_750_600_192 + 3;

/// ACE/Server result codes (`sdi_defs.h`).
pub mod acm {
    /// `ACM_OK`.
    pub const OK: i32 = 0;
    /// `ACM_ACCESS_DENIED`.
    pub const ACCESS_DENIED: i32 = 1;
    /// `ACM_NEXT_CODE_REQUIRED`.
    pub const NEXT_CODE_REQUIRED: i32 = 2;
    /// `ACM_NEW_PIN_REQUIRED`.
    pub const NEW_PIN_REQUIRED: i32 = 5;
    /// `ACM_NEW_PIN_ACCEPTED`.
    pub const NEW_PIN_ACCEPTED: i32 = 6;
}

/// The longest passcode MIT accepts (`LENPRNST` in the ACE SDK headers).
pub const LENPRNST: usize = 16;

/// PIN rules for a new PIN (`AceGetMinPinLen`, `AceGetMaxPinLen`,
/// `AceGetAlphanumeric`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PinParams {
    /// Shortest PIN.
    pub min: i32,
    /// Longest PIN.
    pub max: i32,
    /// Whether the PIN may contain letters.
    pub alphanumeric: bool,
}

/// The ACE/Server calls MIT's `securid2.c` makes. Codes are [`acm`] values.
pub trait AceServer: Send + Sync {
    /// `SD_Init`: open a session; `Err` is the failure code.
    fn init(&self) -> Result<u32, i32>;
    /// `SD_Lock`.
    fn lock(&self, handle: u32, user: &str) -> i32;
    /// `SD_Check`.
    fn check(&self, handle: u32, passcode: &str, user: &str) -> i32;
    /// `SD_Next`: the next tokencode.
    fn next(&self, handle: u32, passcode: &str) -> i32;
    /// `SD_Pin`: set a new PIN.
    fn pin(&self, handle: u32, pin: &str) -> i32;
    /// `SD_Close`.
    fn close(&self, handle: u32);
    /// The PIN rules, `None` if any of the three calls fails.
    fn pin_params(&self, handle: u32) -> Option<PinParams>;
}

/// The `securid_sam2` module's settings.
#[derive(Clone)]
pub struct SecuridSam2 {
    ace: Option<Arc<dyn AceServer>>,
    grail: bool,
    hostid: u32,
}

impl std::fmt::Debug for SecuridSam2 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecuridSam2")
            .field("ace", &self.ace.is_some())
            .field("grail", &self.grail)
            .field("hostid", &self.hostid)
            .finish()
    }
}

impl SecuridSam2 {
    /// SecurID through `ace` (MIT `ARL_SECURID_PREAUTH`); `None` leaves only
    /// GRAIL, if enabled.
    pub fn new(ace: Option<Arc<dyn AceServer>>) -> Self {
        Self {
            ace,
            grail: false,
            hostid: host_id(),
        }
    }

    /// Also answer `<client>/GRAIL` principals (MIT `GRAIL_PREAUTH`).
    #[must_use]
    pub fn with_grail(mut self) -> Self {
        self.grail = true;
        self
    }

    /// Replace the host ID put in SecurID track data (MIT `gethostid()`);
    /// a response carrying another host's ID is discarded.
    #[must_use]
    pub fn with_hostid(mut self, hostid: u32) -> Self {
        self.hostid = hostid;
        self
    }
}

/// `gethostid()` as glibc computes it: `/etc/hostid` if present, otherwise
/// derived from the host name.
fn host_id() -> u32 {
    if let Ok(b) = std::fs::read("/etc/hostid") {
        if b.len() >= 4 {
            return u32::from_ne_bytes([b[0], b[1], b[2], b[3]]);
        }
    }
    let name = std::fs::read("/proc/sys/kernel/hostname").unwrap_or_default();
    name.iter().fold(0x811c_9dc5u32, |h, &c| {
        (h ^ u32::from(c)).wrapping_mul(0x0100_0193)
    })
}

const STATE_NEW_PIN: u8 = 1;
const STATE_NEW_PIN_AGAIN: u8 = 2;
const STATE_NEXT_CODE: u8 = 3;
const STATE_INITIAL: u8 = 4;

const PASSCODE_MESSAGE: &str = "SecurID Passcode";
const NEXT_PASSCODE_MESSAGE: &str = "Next Passcode";
const NEW_PIN_AGAIN_MESSAGE: &str = "New PIN Again";

/// `struct securid_track_data`.
struct Track {
    state: u8,
    hostid: u32,
    handle: u32,
    passcode: Vec<u8>,
}

impl Track {
    const MIN_LEN: usize = 9;

    fn encode(&self) -> Vec<u8> {
        let mut v = vec![self.state];
        v.extend_from_slice(&self.hostid.to_be_bytes());
        v.extend_from_slice(&self.handle.to_be_bytes());
        v.extend_from_slice(&self.passcode);
        v
    }

    fn decode(b: &[u8]) -> Option<Self> {
        (b.len() >= Self::MIN_LEN).then(|| Self {
            state: b[0],
            hostid: u32::from_be_bytes([b[1], b[2], b[3], b[4]]),
            handle: u32::from_be_bytes([b[5], b[6], b[7], b[8]]),
            passcode: b[9..].to_vec(),
        })
    }
}

fn failed(status: &str) -> KdcError {
    KdcError::new(KDC_ERR_PREAUTH_FAILED, status)
}

fn integrity() -> KdcError {
    KdcError::new(KRB_AP_ERR_BAD_INTEGRITY, "PREAUTH_FAILED")
}

fn body(sam_type: i32, prompt: &str, etype: i32) -> SamChallenge2Body {
    SamChallenge2Body {
        sam_type,
        flags: SamFlags::SEND_ENCRYPTED_SAD.into(),
        type_name: None,
        track_id: None,
        challenge_label: None,
        challenge: None,
        response_prompt: opt(prompt.as_bytes()),
        pk_for_sad: None,
        nonce: rand::random::<i32>(),
        etype,
    }
}

/// `sam_make_challenge`: the body with the client key's mandatory checksum
/// (key usage 25).
fn make_challenge(body: &SamChallenge2Body, key: &EncryptionKey) -> Result<PaData, KdcError> {
    let der = rasn::der::encode(body)?;
    let prof = find_etype(key.keytype).map_err(|_| failed("SAM_CHECKSUM"))?;
    let cksum = prof
        .checksum(key.key_bytes(), KEYUSAGE_CHALLENGE_CKSUM, &der)
        .map_err(|_| failed("SAM_CHECKSUM"))?;
    let sc2 = SamChallenge2 {
        body: Any::new(der),
        cksum: vec![Checksum {
            cksumtype: prof.checksum_type(),
            checksum: cksum.into(),
        }],
    };
    Ok(PaData {
        padata_type: PA_SAM_CHALLENGE_2,
        padata_value: rasn::der::encode(&sc2)?.into(),
    })
}

fn encrypt_track(key: &EncryptionKey, data: &[u8]) -> Result<OctetString, KdcError> {
    find_etype(key.keytype)
        .and_then(|p| p.encrypt(key.key_bytes(), KEYUSAGE_CHALLENGE_TRACKID, data))
        .map(Into::into)
        .map_err(|_| failed("SAM_TRACK_ID"))
}

fn decrypt_track(key: &EncryptionKey, data: &[u8]) -> Result<Vec<u8>, KdcError> {
    find_etype(key.keytype)
        .and_then(|p| p.decrypt(key.key_bytes(), KEYUSAGE_CHALLENGE_TRACKID, data))
        .map_err(|_| integrity())
}

/// The part of `verify_*_data_2` both mechanisms share: the client key the
/// response names, the decrypted ENC-SAM-RESPONSE-ENC-2, a nonce match and
/// a non-empty SAD.
fn open_response(
    client: &PrincipalEntry,
    sr2: &SamResponse2,
) -> Result<(EncryptionKey, Vec<u8>), KdcError> {
    let enc = &sr2.enc_nonce_or_sad;
    if enc.cipher.is_empty() {
        return Err(failed("PREAUTH_FAILED"));
    }
    let kvno = match enc.kvno {
        Some(k) if k != 0 => KvnoSel::Exact(k as u32),
        _ => KvnoSel::Highest,
    };
    let key = client
        .find_key(Some(enc.etype), kvno, &|_| true)
        .map(|k| k.key.clone())
        .ok_or_else(|| failed("PREAUTH_FAILED"))?;
    let plain = find_etype(key.keytype)
        .and_then(|p| p.decrypt(key.key_bytes(), KEYUSAGE_RESPONSE, enc.cipher.as_ref()))
        .map_err(|_| integrity())?;
    let esre2: EncSamResponseEnc2 =
        rasn::der::decode(&plain).map_err(|_| failed("PREAUTH_FAILED"))?;
    if esre2.nonce != sr2.nonce {
        return Err(failed("PREAUTH_FAILED"));
    }
    let sad = esre2.sad.map(|s| s.to_vec()).unwrap_or_default();
    if sad.is_empty() {
        return Err(failed("PREAUTH_FAILED"));
    }
    Ok((key, sad))
}

impl<S: PrincipalStore> Kdc<S> {
    /// `sam_get_db_entry`: `<client>/SECURID`, then `<client>/GRAIL`, limited
    /// to `want` unless it is 0.
    async fn sam_entry(
        &self,
        client: &PrincipalEntry,
        want: i32,
    ) -> Result<Option<(i32, PrincipalEntry)>, KdcError> {
        for (comp, ty) in [("SECURID", TYPE_SECURID), ("GRAIL", TYPE_GRAIL)] {
            if want != 0 && want != ty {
                continue;
            }
            let mut name = client.name.clone();
            name.name_string.push(general_string(comp)?);
            if let Some(e) = self.lookup(&name, &client.realm, "SAM_LOOKUP").await? {
                return Ok(Some((ty, e)));
            }
        }
        Ok(None)
    }

    /// `get_securid_key` / `get_grail_key`: the newest key of the SAM entry.
    async fn sam_key(&self, client: &PrincipalEntry, ty: i32) -> Result<EncryptionKey, KdcError> {
        let (_, entry) = self
            .sam_entry(client, ty)
            .await?
            .ok_or_else(|| failed("PREAUTH_NO_KEY"))?;
        entry
            .find_key(None, KvnoSel::Highest, &|_| true)
            .map(|k| k.key.clone())
            .ok_or_else(|| failed("PREAUTH_NO_KEY"))
    }

    /// The PKINIT hints followed by the SAM-2 challenge, if any (the module
    /// is PA_HARDWARE, so it is offered to hardware-only clients too).
    pub(super) async fn hint_extras(
        &self,
        pk_extras: &[PaData],
        client: &PrincipalEntry,
        client_key: Option<&ClientKey>,
        kdc_time: i64,
    ) -> Vec<PaData> {
        let mut v = pk_extras.to_vec();
        v.extend(self.sam2_edata(client, client_key, kdc_time).await);
        v
    }

    /// `kdc_include_padata`: a PA-SAM-CHALLENGE-2 hint, or `None` when the
    /// client has no usable SAM entry or the mechanism fails.
    pub(super) async fn sam2_edata(
        &self,
        client: &PrincipalEntry,
        client_key: Option<&ClientKey>,
        now: i64,
    ) -> Option<PaData> {
        let m = self.securid_sam2.as_ref()?;
        let (ty, _) = self.sam_entry(client, 0).await.ok()??;
        let key = &client_key?.entry.key;
        if key.keytype == 0 {
            return None;
        }
        let r = match ty {
            TYPE_SECURID if m.ace.is_some() => self.securid_edata(m, client, key).await,
            TYPE_GRAIL if m.grail => self.grail_edata(client, key, now).await,
            _ => return None,
        };
        r.ok()
    }

    /// `get_securid_edata_2`.
    async fn securid_edata(
        &self,
        m: &SecuridSam2,
        client: &PrincipalEntry,
        key: &EncryptionKey,
    ) -> Result<PaData, KdcError> {
        let mut b = body(TYPE_SECURID, PASSCODE_MESSAGE, key.keytype);
        let track = Track {
            state: STATE_INITIAL,
            hostid: m.hostid,
            handle: 0,
            passcode: Vec::new(),
        };
        let sam_key = self.sam_key(client, TYPE_SECURID).await?;
        b.track_id = Some(encrypt_track(&sam_key, &track.encode())?);
        make_challenge(&b, key)
    }

    /// `get_grail_edata`.
    async fn grail_edata(
        &self,
        client: &PrincipalEntry,
        key: &EncryptionKey,
        now: i64,
    ) -> Result<PaData, KdcError> {
        let tval = now.rem_euclid(77777);
        let mut b = body(TYPE_GRAIL, &format!("Enter {tval}"), key.keytype);
        let sam_key = self.sam_key(client, TYPE_GRAIL).await?;
        b.track_id = Some(encrypt_track(&sam_key, tval.to_string().as_bytes())?);
        make_challenge(&b, key)
    }

    /// `kdc_verify_preauth`: `Ok` when the response authenticates the
    /// client, which earns the ticket HW-AUTHENT and PRE-AUTHENT. A further
    /// challenge MIT builds is dropped as MIT drops it (it passes no e-data
    /// to `respond`), leaving only KDC_ERR_PREAUTH_REQUIRED.
    pub(super) async fn sam2_verify(
        &self,
        pa: &PaData,
        client: &PrincipalEntry,
    ) -> Result<(), KdcError> {
        let Some(m) = self.securid_sam2.as_ref() else {
            return Err(failed("PREAUTH_FAILED"));
        };
        let sr2: SamResponse2 =
            rasn::der::decode(pa.padata_value.as_ref()).map_err(|_| failed("PREAUTH_FAILED"))?;
        match sr2.sam_type {
            TYPE_SECURID if m.ace.is_some() => self.securid_verify(m, client, &sr2).await,
            TYPE_GRAIL if m.grail => self.grail_verify(client, &sr2).await,
            _ => Err(failed("PREAUTH_BAD_TYPE")),
        }
    }

    /// `verify_grail_data`.
    async fn grail_verify(
        &self,
        client: &PrincipalEntry,
        sr2: &SamResponse2,
    ) -> Result<(), KdcError> {
        let (_, sad) = open_response(client, sr2)?;
        let sam_key = self.sam_key(client, TYPE_GRAIL).await?;
        let mut track = decrypt_track(&sam_key, sr2.track_id.as_deref().unwrap_or_default())?;
        // Some enctypes aren't length-preserving.
        while track.last().is_some_and(|c| !c.is_ascii_digit()) {
            track.pop();
        }
        if track != sad {
            return Err(failed("PREAUTH_FAILED"));
        }
        Ok(())
    }

    /// `verify_securid_data_2`.
    async fn securid_verify(
        &self,
        m: &SecuridSam2,
        client: &PrincipalEntry,
        sr2: &SamResponse2,
    ) -> Result<(), KdcError> {
        let Some(ace) = m.ace.as_deref() else {
            return Err(failed("PREAUTH_BAD_TYPE"));
        };
        let (client_key, sad) = open_response(client, sr2)?;
        if sad.len() > LENPRNST {
            return Err(failed("PREAUTH_FAILED"));
        }
        // The passcode is copied into a NUL-terminated buffer.
        let pc_bytes = sad.split(|&c| c == 0).next().unwrap_or_default();
        let passcode = String::from_utf8_lossy(pc_bytes).into_owned();
        let user = crate::ccache::unparse_name(&client.name, &client.realm);
        let securid_user = user.split('@').next().unwrap_or_default().to_string();

        let track = match sr2.track_id.as_deref().filter(|t| !t.is_empty()) {
            None => None,
            Some(enc) => {
                let sam_key = self.sam_key(client, TYPE_SECURID).await?;
                let t = Track::decode(&decrypt_track(&sam_key, enc)?)
                    .ok_or_else(|| failed("PREAUTH_FAILED"))?;
                if t.hostid != m.hostid {
                    return Err(KdcError::new(KDC_ERR_DISCARD, "DISCARD"));
                }
                Some(t)
            }
        };
        let required = || KdcError::new(KDC_ERR_PREAUTH_REQUIRED, "PREAUTH_REQUIRED");
        match track {
            Some(t) if t.state == STATE_NEW_PIN_AGAIN => {
                let first = t.passcode.split(|&c| c == 0).next().unwrap_or_default();
                if first != pc_bytes {
                    return Err(failed("PREAUTH_FAILED"));
                }
                let r = ace.pin(t.handle, &passcode);
                ace.close(t.handle);
                if r == acm::NEW_PIN_ACCEPTED {
                    Ok(())
                } else {
                    Err(failed("PREAUTH_FAILED"))
                }
            }
            Some(t) if t.state == STATE_NEW_PIN => {
                let mut b = body(TYPE_SECURID, NEW_PIN_AGAIN_MESSAGE, client_key.keytype);
                let mut saved = pc_bytes.to_vec();
                saved.resize(LENPRNST + 1, 0);
                let next = Track {
                    state: STATE_NEW_PIN_AGAIN,
                    hostid: m.hostid,
                    handle: t.handle,
                    passcode: saved,
                };
                let sam_key = self.sam_key(client, TYPE_SECURID).await?;
                b.track_id = Some(encrypt_track(&sam_key, &next.encode())?);
                make_challenge(&b, &client_key)?;
                Err(required())
            }
            Some(t) if t.state == STATE_NEXT_CODE => {
                let r = ace.next(t.handle, &passcode);
                ace.close(t.handle);
                if r == acm::OK {
                    Ok(())
                } else {
                    Err(failed("PREAUTH_FAILED"))
                }
            }
            Some(t) if t.state != STATE_INITIAL => Err(failed("PREAUTH_FAILED")),
            _ => {
                let Ok(h) = ace.init() else {
                    return Err(failed("PREAUTH_FAILED"));
                };
                if ace.lock(h, &securid_user) != acm::OK {
                    ace.close(h);
                    return Err(failed("PREAUTH_FAILED"));
                }
                match ace.check(h, &passcode, &securid_user) {
                    acm::OK => {
                        ace.close(h);
                        Ok(())
                    }
                    acm::ACCESS_DENIED => {
                        ace.close(h);
                        Err(failed("PREAUTH_FAILED"))
                    }
                    r @ (acm::NEW_PIN_REQUIRED | acm::NEXT_CODE_REQUIRED) => {
                        let new_pin = r == acm::NEW_PIN_REQUIRED;
                        let mut b = body(TYPE_SECURID, NEXT_PASSCODE_MESSAGE, client_key.keytype);
                        if new_pin {
                            b.challenge_label = ace.pin_params(h).and_then(|p| {
                                opt(format!(
                                    "New PIN must contain {} to {} {}digits",
                                    p.min,
                                    p.max,
                                    if p.alphanumeric { "alphanumeric " } else { "" }
                                )
                                .as_bytes())
                            });
                        }
                        let next = Track {
                            state: if new_pin {
                                STATE_NEW_PIN
                            } else {
                                STATE_NEXT_CODE
                            },
                            hostid: m.hostid,
                            handle: h,
                            passcode: Vec::new(),
                        };
                        let sam_key = self.sam_key(client, TYPE_SECURID).await?;
                        b.track_id = Some(encrypt_track(&sam_key, &next.encode())?);
                        let _ = make_challenge(&b, &client_key);
                        // Deviation from MIT: the challenge never reaches
                        // the client, so nothing can resume this session;
                        // MIT leaves it open.
                        ace.close(h);
                        Err(required())
                    }
                    _ => {
                        // MIT leaves the session open here too.
                        ace.close(h);
                        Err(failed("PREAUTH_FAILED"))
                    }
                }
            }
        }
    }
}
