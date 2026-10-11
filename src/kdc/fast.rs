//! KDC-side FAST (RFC 6113): armor handling, reply/error wrapping
//! (MIT fast_util.c `kdc_find_fast`, `armor_ap_request`,
//! `kdc_fast_response_handle_padata`, `kdc_fast_handle_error`,
//! `kdc_fast_handle_reply_key`, `kdc_fast_hide_client`).

use chrono::{DateTime, Timelike, Utc};
use rasn::types::{BitString, OctetString};

use super::db::KvnoSel;
use super::error::{general_string, krbtgt_name, KdcError};
use super::preauth::find_padata;
use super::{names_equal, random_key, Kdc, PrincipalEntry, PrincipalStore};
use crate::crypto::{find_cksumtype, find_etype, fx_cf2, key_usage};
use crate::protocol::ap::{ApError, AuthContext, AuthContextFlags, KeySource};
use crate::types::error_codes::*;
use crate::types::{
    ApReq, Checksum, EncryptedData, EncryptionKey, KdcReq, KrbErrorMsg, KrbFastArmor,
    KrbFastArmoredRep, KrbFastFinished, KrbFastReq, KrbFastResponse, PaData, PaDataType,
    PaFxFastReply, PaFxFastRequest, PrincipalName, Ticket,
};
use crate::Krb5Error;

/// KRB5_FAST_ARMOR_AP_REQUEST.
const FAST_ARMOR_AP_REQUEST: i32 = 1;
/// KRB5_FAST_OPTION_HIDE_CLIENT_NAMES (MIT krb5.h).
const FAST_OPTION_HIDE_CLIENT_NAMES: u32 = 0x4000_0000;
/// MIT `UNSUPPORTED_CRITICAL_FAST_OPTIONS` (kdc_util.h).
const UNSUPPORTED_CRITICAL_FAST_OPTIONS: u32 = 0xbfff_0000;
/// KRB5_NT_WELLKNOWN.
const NT_WELLKNOWN: i32 = 11;

/// Per-request FAST state (MIT `struct kdc_request_state`, reqstate.h).
#[derive(Debug, Clone)]
pub(crate) struct KdcFastState {
    /// Armor key; its presence is what makes errors armored.
    pub armor_key: Option<EncryptionKey>,
    /// Strengthen key generated for the reply.
    pub strengthen_key: Option<EncryptionKey>,
    /// First four bytes of the FAST options, big-endian; set once the inner
    /// request has been accepted (fast_util.c:230).
    pub fast_options: u32,
    /// Nonce of the request currently being processed.
    pub nonce: u32,
}

impl KdcFastState {
    /// `kdc_fast_hide_client` (fast_util.c:443-447).
    pub(crate) fn hide_client(&self) -> bool {
        self.fast_options & FAST_OPTION_HIDE_CLIENT_NAMES != 0
    }

    /// `kdc_fast_handle_reply_key` (fast_util.c:426-441): the strengthened
    /// reply key.
    pub(crate) fn reply_key(&self, existing: &EncryptionKey) -> Result<EncryptionKey, KdcError> {
        match (&self.armor_key, &self.strengthen_key) {
            (Some(_), Some(strengthen)) => {
                fx_cf2(strengthen, b"strengthenkey", existing, b"replykey")
                    .map_err(|_| KdcError::generic("FAST_REPLY_KEY"))
            }
            _ => Ok(existing.clone()),
        }
    }

    /// `kdc_fast_response_handle_padata` (fast_util.c:276-355): move
    /// `reply_padata` into an encrypted KrbFastResponse with a fresh
    /// strengthen key and a `finished` proof over `ticket`, returning the
    /// outer padata list (PA-FX-FAST only).
    pub(crate) fn wrap_reply(
        &mut self,
        reply_padata: Vec<PaData>,
        ticket: &Ticket,
        client: (&str, &PrincipalName),
        reply_etype: i32,
        now: DateTime<Utc>,
    ) -> Result<Vec<PaData>, KdcError> {
        let armor = self
            .armor_key
            .clone()
            .ok_or_else(|| KdcError::generic("NO_ARMOR_KEY"))?;
        let strengthen = random_key(reply_etype)?;
        self.strengthen_key = Some(strengthen.clone());

        let profile = find_etype(armor.keytype).map_err(|_| KdcError::generic("FAST_FINISHED"))?;
        let ticket_der = rasn::der::encode(ticket)?;
        let ticket_checksum = Checksum {
            cksumtype: profile.checksum_type(),
            checksum: OctetString::from(
                profile
                    .checksum(armor.key_bytes(), key_usage::FAST_FINISHED, &ticket_der)
                    .map_err(|_| KdcError::generic("FAST_FINISHED"))?,
            ),
        };
        let response = KrbFastResponse {
            padata: reply_padata,
            strengthen_key: Some(strengthen),
            finished: Some(KrbFastFinished {
                timestamp: now.with_nanosecond(0).unwrap_or(now).fixed_offset(),
                usec: i32::try_from(now.timestamp_subsec_micros()).unwrap_or(0),
                crealm: general_string(client.0)?,
                cname: client.1.clone(),
                ticket_checksum,
            }),
            nonce: self.nonce,
        };
        Ok(vec![encrypt_fast_reply(&armor, &response)?])
    }
}

/// `encrypt_fast_reply` (fast_util.c:92-117): PA-FX-FAST carrying the
/// armored KrbFastResponse.
fn encrypt_fast_reply(
    armor_key: &EncryptionKey,
    response: &KrbFastResponse,
) -> Result<PaData, KdcError> {
    let profile = find_etype(armor_key.keytype).map_err(|_| KdcError::generic("FAST_ENCRYPT"))?;
    let cipher = profile
        .encrypt(
            armor_key.key_bytes(),
            key_usage::FAST_REP,
            &rasn::der::encode(response)?,
        )
        .map_err(|_| KdcError::generic("FAST_ENCRYPT"))?;
    let reply = PaFxFastReply::ArmoredData(KrbFastArmoredRep {
        enc_fast_rep: EncryptedData {
            etype: armor_key.keytype,
            kvno: None,
            cipher: OctetString::from(cipher),
        },
    });
    Ok(PaData {
        padata_type: PaDataType::FxFast as i32,
        padata_value: OctetString::from(rasn::der::encode(&reply)?),
    })
}

/// `kdc_fast_handle_error` (fast_util.c:364-424): the outer e-data
/// (METHOD-DATA holding only PA-FX-FAST) for an armored error. `inner` is
/// the error with its e-data removed and the real client; `in_padata` is
/// the caller's padata (hints, cookie), to which PA-FX-ERROR is appended.
pub(crate) fn wrap_error(
    state: &KdcFastState,
    inner: &KrbErrorMsg,
    mut in_padata: Vec<PaData>,
) -> Result<Vec<u8>, KdcError> {
    let armor = state
        .armor_key
        .as_ref()
        .ok_or_else(|| KdcError::generic("NO_ARMOR_KEY"))?;
    in_padata.push(PaData {
        padata_type: PaDataType::FxError as i32,
        padata_value: OctetString::from(rasn::der::encode(inner)?),
    });
    let response = KrbFastResponse {
        padata: in_padata,
        strengthen_key: None,
        finished: None,
        nonce: state.nonce,
    };
    Ok(rasn::der::encode(&vec![encrypt_fast_reply(
        armor, &response,
    )?])?)
}

/// `krb5_anonymous_principal` (realm, name).
pub(crate) fn anonymous_client() -> Result<(String, PrincipalName), KdcError> {
    Ok((
        "WELLKNOWN:ANONYMOUS".to_string(),
        PrincipalName {
            name_type: NT_WELLKNOWN,
            name_string: vec![general_string("WELLKNOWN")?, general_string("ANONYMOUS")?],
        },
    ))
}

fn options_word(bits: &BitString) -> u32 {
    let mut word = [0u8; 4];
    for (dst, src) in word.iter_mut().zip(bits.as_raw_slice()) {
        *dst = *src;
    }
    u32::from_be_bytes(word)
}

/// Inputs to [`Kdc::find_fast`] that depend on the request kind.
pub(crate) struct FastInputs<'a> {
    /// Data covered by the FAST req_checksum: the raw outer req-body for AS,
    /// the PA-TGS-REQ padata value for TGS.
    pub checksummed: &'a [u8],
    /// TGS authenticator subkey (implicit armor).
    pub tgs_subkey: Option<&'a EncryptionKey>,
    /// TGS header ticket session key.
    pub tgs_session: Option<&'a EncryptionKey>,
}

/// KeySource over a principal entry fetched from the store before `rd_req`
/// runs (which is synchronous), standing in for MIT's realm keytab in
/// `armor_ap_request` (fast_util.c:52-54).
struct StoreKeySource<'a, S: PrincipalStore> {
    kdc: &'a Kdc<S>,
    entry: Option<PrincipalEntry>,
}

impl<S: PrincipalStore> KeySource for StoreKeySource<'_, S> {
    fn get_key(
        &self,
        _server: &PrincipalName,
        _realm: &[u8],
        kvno: Option<i32>,
        etype: i32,
    ) -> Result<EncryptionKey, ApError> {
        let entry = self.entry.as_ref().ok_or(ApError::NoKey)?;
        let sel = match kvno {
            Some(k) if k > 0 => KvnoSel::Exact(u32::try_from(k).map_err(|_| ApError::BadKeyver)?),
            _ => KvnoSel::Any,
        };
        entry
            .find_key(Some(etype), sel, &self.kdc.permitted())
            .map(|k| k.key.clone())
            .ok_or(ApError::BadKeyver)
    }
}

impl<S: PrincipalStore> Kdc<S> {
    /// `armor_ap_request` (MIT fast_util.c:35-90).
    async fn armor_ap_request(
        &self,
        armor: &KrbFastArmor,
        now: DateTime<Utc>,
    ) -> Result<EncryptionKey, KdcError> {
        let mut auth_ctx = AuthContext::new();
        auth_ctx.set_flags(AuthContextFlags::empty());
        auth_ctx.set_clockskew(self.config.clockskew);
        auth_ctx.set_time_offset(now - Utc::now());
        auth_ctx.set_permitted_etypes(Some(self.config.supported_enctypes.clone()));
        let ap_bytes = armor.armor_value.as_ref();
        // rd_req looks the key up synchronously: fetch the ticket server's
        // entry first (the ticket names it in the clear).
        let entry = match rasn::der::decode::<ApReq>(ap_bytes) {
            Ok(ap) => self
                .measure_store(self.store.lookup(
                    &ap.ticket.sname,
                    &String::from_utf8_lossy(ap.ticket.realm.as_bytes()),
                ))
                .await
                .ok()
                .flatten(),
            Err(_) => None,
        };
        let rd = auth_ctx
            .rd_req(ap_bytes, None, &StoreKeySource { kdc: self, entry })
            .map_err(|e| match e {
                Krb5Error::Ap(a) => KdcError::new(super::error::ap_error_code(a), "FIND_FAST"),
                _ => KdcError::generic("FIND_FAST"),
            })?;
        let ap: ApReq = rasn::der::decode(ap_bytes).map_err(|_| KdcError::generic("FIND_FAST"))?;
        let local_tgs = krbtgt_name(&self.config.realm)?;
        if !names_equal(&local_tgs, &ap.ticket.sname) {
            return Err(KdcError::new(
                KDC_ERR_SERVER_NOMATCH,
                "ap-request armor for something other than the local TGS",
            ));
        }
        let subkey = rd
            .authenticator
            .subkey
            .ok_or_else(|| KdcError::new(KDC_ERR_POLICY, "ap-request armor without subkey"))?;
        fx_cf2(&subkey, b"subkeyarmor", &rd.ticket.key, b"ticketarmor")
            .map_err(|_| KdcError::generic("FIND_FAST"))
    }

    /// `kdc_find_fast` (MIT fast_util.c:126-247). Returns the inner request
    /// when PA-FX-FAST was present and accepted. The armor key is recorded
    /// in `fast` as soon as it exists, so later failures are armored.
    pub(super) async fn find_fast(
        &self,
        req: &KdcReq,
        inputs: FastInputs<'_>,
        now: DateTime<Utc>,
        fast: &mut Option<KdcFastState>,
    ) -> Result<Option<KdcReq>, KdcError> {
        const STATUS: &str = "FIND_FAST";
        let Some(fast_pa) = find_padata(req.padata.as_deref(), PaDataType::FxFast) else {
            return Ok(None);
        };
        let PaFxFastRequest::ArmoredData(armored) =
            rasn::der::decode(fast_pa.padata_value.as_ref())
                .map_err(|_| KdcError::generic(STATUS))?;

        let mut armor_key = None;
        if let Some(armor) = &armored.armor {
            match armor.armor_type {
                FAST_ARMOR_AP_REQUEST => {
                    if inputs.tgs_subkey.is_some() {
                        return Err(KdcError::new(
                            KDC_ERR_PREAUTH_FAILED,
                            "Ap-request armor not permitted with TGS",
                        ));
                    }
                    armor_key = Some(self.armor_ap_request(armor, now).await?);
                }
                other => {
                    return Err(KdcError::new(
                        KDC_ERR_PREAUTH_FAILED,
                        &format!("Unknown FAST armor type {other}"),
                    ))
                }
            }
        }
        if armor_key.is_none() {
            armor_key = match (inputs.tgs_subkey, inputs.tgs_session) {
                (Some(subkey), Some(session)) => Some(
                    fx_cf2(subkey, b"subkeyarmor", session, b"ticketarmor")
                        .map_err(|_| KdcError::generic(STATUS))?,
                ),
                _ => {
                    return Err(KdcError::new(
                        KDC_ERR_PREAUTH_FAILED,
                        "No armor key but FAST armored request present",
                    ))
                }
            };
        }
        let armor_key = armor_key.ok_or_else(|| KdcError::generic(STATUS))?;
        let state = fast.insert(KdcFastState {
            armor_key: Some(armor_key.clone()),
            strengthen_key: None,
            fast_options: 0,
            nonce: req.req_body.nonce,
        });

        let profile = find_etype(armor_key.keytype).map_err(|_| KdcError::generic(STATUS))?;
        if armored.enc_fast_req.etype != armor_key.keytype {
            return Err(KdcError::generic(STATUS));
        }
        let plain = profile
            .decrypt(
                armor_key.key_bytes(),
                key_usage::FAST_ENC,
                armored.enc_fast_req.cipher.as_ref(),
            )
            .map_err(|_| KdcError::new(KRB_AP_ERR_BAD_INTEGRITY, STATUS))?;
        let fast_req: KrbFastReq =
            rasn::der::decode(&plain).map_err(|_| KdcError::generic(STATUS))?;

        // krb5_c_verify_checksum + krb5_c_is_keyed_cksum (:207-224).
        let cksum = &armored.req_checksum;
        match cksum.cksumtype {
            15 | 16 | 19 | 20 => {
                let cprofile = find_cksumtype(cksum.cksumtype)
                    .map_err(|_| KdcError::new(KDC_ERR_SUMTYPE_NOSUPP, STATUS))?;
                if cprofile.etype() != armor_key.keytype {
                    return Err(KdcError::generic(STATUS));
                }
                cprofile
                    .verify_checksum(
                        armor_key.key_bytes(),
                        key_usage::FAST_REQ_CHKSUM,
                        inputs.checksummed,
                        cksum.checksum.as_ref(),
                    )
                    .map_err(|_| {
                        KdcError::new(
                            KRB_AP_ERR_MODIFIED,
                            "FAST req_checksum invalid; request modified",
                        )
                    })?;
            }
            1..=14 => {
                return Err(KdcError::new(
                    KDC_ERR_POLICY,
                    "Unkeyed checksum used in fast_req",
                ))
            }
            _ => return Err(KdcError::new(KDC_ERR_SUMTYPE_NOSUPP, STATUS)),
        }

        let options = options_word(&fast_req.fast_options);
        if options & UNSUPPORTED_CRITICAL_FAST_OPTIONS != 0 {
            return Err(KdcError::new(
                KDC_ERR_UNKNOWN_CRITICAL_FAST_OPTION,
                "UNKNOWN_CRITICAL_FAST_OPTION",
            ));
        }
        state.fast_options = options;
        state.nonce = fast_req.req_body.nonce;
        Ok(Some(KdcReq {
            pvno: req.pvno,
            msg_type: req.msg_type,
            padata: Some(fast_req.padata),
            req_body: fast_req.req_body,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kdc::db::{MemoryStore, PrincipalAttributes};
    use crate::kdc::KdcConfig;
    use crate::types::{KdcOptions, KdcReqBody, KerberosFlags};

    const REALM: &str = "R";

    fn kdc() -> Kdc<MemoryStore> {
        let mut store = MemoryStore::new();
        store
            .add_random_key(
                krbtgt_name(REALM).expect("name"),
                REALM,
                1,
                &[18],
                PrincipalAttributes::empty(),
            )
            .expect("krbtgt");
        Kdc::new(KdcConfig::new(REALM), store)
    }

    fn body(nonce: u32) -> KdcReqBody {
        KdcReqBody {
            kdc_options: KerberosFlags::new(KdcOptions::empty()),
            cname: None,
            realm: general_string(REALM).expect("realm"),
            sname: None,
            from: None,
            till: DateTime::<Utc>::from_timestamp(1_000_000, 0)
                .expect("time")
                .fixed_offset(),
            rtime: None,
            nonce,
            etype: vec![18],
            addresses: None,
            enc_authorization_data: None,
            additional_tickets: None,
        }
    }

    fn key(b: u8) -> EncryptionKey {
        EncryptionKey::new(18, vec![b; 32])
    }

    struct Built {
        outer: KdcReq,
        armor_key: EncryptionKey,
    }

    /// Armored request built with the implicit TGS armor.
    fn build(
        subkey: &EncryptionKey,
        session: &EncryptionKey,
        checksummed: &[u8],
        armor: Option<KrbFastArmor>,
        options: &[u8],
    ) -> Built {
        let armor_key = fx_cf2(subkey, b"subkeyarmor", session, b"ticketarmor").expect("cf2");
        let profile = find_etype(18).expect("etype");
        let fast_req = KrbFastReq {
            fast_options: BitString::from_slice(options),
            padata: Vec::new(),
            req_body: body(77),
        };
        let cipher = profile
            .encrypt(
                armor_key.key_bytes(),
                key_usage::FAST_ENC,
                &rasn::der::encode(&fast_req).expect("encode"),
            )
            .expect("encrypt");
        let checksum = profile
            .checksum(
                armor_key.key_bytes(),
                key_usage::FAST_REQ_CHKSUM,
                checksummed,
            )
            .expect("checksum");
        let pa = PaFxFastRequest::ArmoredData(crate::types::KrbFastArmoredReq {
            armor,
            req_checksum: Checksum {
                cksumtype: profile.checksum_type(),
                checksum: OctetString::from(checksum),
            },
            enc_fast_req: EncryptedData {
                etype: 18,
                kvno: None,
                cipher: OctetString::from(cipher),
            },
        });
        Built {
            outer: KdcReq {
                pvno: 5,
                msg_type: 12,
                padata: Some(vec![PaData {
                    padata_type: 136,
                    padata_value: OctetString::from(rasn::der::encode(&pa).expect("encode")),
                }]),
                req_body: body(1),
            },
            armor_key,
        }
    }

    async fn run(
        built: &Built,
        checksummed: &[u8],
        subkey: Option<&EncryptionKey>,
        session: Option<&EncryptionKey>,
    ) -> (Result<Option<KdcReq>, KdcError>, Option<KdcFastState>) {
        let mut state = None;
        let res = kdc()
            .find_fast(
                &built.outer,
                FastInputs {
                    checksummed,
                    tgs_subkey: subkey,
                    tgs_session: session,
                },
                Utc::now(),
                &mut state,
            )
            .await;
        (res, state)
    }

    #[tokio::test]
    async fn find_fast_implicit_armor_derives_cf2_key_and_returns_inner_request() {
        let (sub, sess) = (key(1), key(2));
        let built = build(&sub, &sess, b"pa-tgs-req", None, &[0x40, 0, 0, 0]);
        let (res, state) = run(&built, b"pa-tgs-req", Some(&sub), Some(&sess)).await;
        let inner = res.expect("ok").expect("inner request");
        assert_eq!(inner.req_body.nonce, 77);
        assert_eq!(inner.msg_type, 12);
        let state = state.expect("state");
        assert_eq!(
            state.armor_key.as_ref().expect("armor").key_bytes(),
            built.armor_key.key_bytes()
        );
        assert!(state.hide_client());
        assert_eq!(state.nonce, 77);
    }

    #[tokio::test]
    async fn find_fast_without_fast_padata_returns_none() {
        let mut state = None;
        let req = KdcReq {
            pvno: 5,
            msg_type: 10,
            padata: None,
            req_body: body(1),
        };
        let res = kdc()
            .find_fast(
                &req,
                FastInputs {
                    checksummed: &[],
                    tgs_subkey: None,
                    tgs_session: None,
                },
                Utc::now(),
                &mut state,
            )
            .await;
        assert!(res.expect("ok").is_none());
        assert!(state.is_none());
    }

    #[tokio::test]
    async fn find_fast_tampered_checksummed_data_is_modified_and_armored() {
        let (sub, sess) = (key(1), key(2));
        let built = build(&sub, &sess, b"pa-tgs-req", None, &[]);
        let (res, state) = run(&built, b"pa-tgs-reQ", Some(&sub), Some(&sess)).await;
        assert_eq!(res.expect_err("tampered").code, KRB_AP_ERR_MODIFIED);
        assert!(state.expect("armor recorded").armor_key.is_some());
    }

    #[tokio::test]
    async fn find_fast_unknown_armor_type_is_preauth_failed_and_unarmored() {
        let (sub, sess) = (key(1), key(2));
        let armor = KrbFastArmor {
            armor_type: 2,
            armor_value: OctetString::from(Vec::new()),
        };
        let built = build(&sub, &sess, b"x", Some(armor), &[]);
        let (res, state) = run(&built, b"x", None, None).await;
        assert_eq!(res.expect_err("armor").code, KDC_ERR_PREAUTH_FAILED);
        assert!(state.is_none());
    }

    #[tokio::test]
    async fn find_fast_no_armor_and_no_subkey_is_preauth_failed() {
        let (sub, sess) = (key(1), key(2));
        let built = build(&sub, &sess, b"x", None, &[]);
        let (res, _) = run(&built, b"x", None, None).await;
        assert_eq!(res.expect_err("no armor").code, KDC_ERR_PREAUTH_FAILED);
    }

    #[tokio::test]
    async fn find_fast_ap_request_armor_with_tgs_subkey_is_preauth_failed() {
        let (sub, sess) = (key(1), key(2));
        let armor = KrbFastArmor {
            armor_type: 1,
            armor_value: OctetString::from(vec![0x6E, 0]),
        };
        let built = build(&sub, &sess, b"x", Some(armor), &[]);
        let (res, _) = run(&built, b"x", Some(&sub), Some(&sess)).await;
        assert_eq!(res.expect_err("armor").code, KDC_ERR_PREAUTH_FAILED);
    }

    #[tokio::test]
    async fn find_fast_critical_option_bit_is_unknown_critical_option() {
        let (sub, sess) = (key(1), key(2));
        let built = build(&sub, &sess, b"x", None, &[0x80, 0, 0, 0]);
        let (res, state) = run(&built, b"x", Some(&sub), Some(&sess)).await;
        assert_eq!(
            res.expect_err("critical").code,
            KDC_ERR_UNKNOWN_CRITICAL_FAST_OPTION
        );
        assert!(!state.expect("state").hide_client());
    }

    #[tokio::test]
    async fn find_fast_non_critical_option_bit_is_accepted() {
        let (sub, sess) = (key(1), key(2));
        let built = build(&sub, &sess, b"x", None, &[0, 0, 0x80, 0]);
        let (res, _) = run(&built, b"x", Some(&sub), Some(&sess)).await;
        assert!(res.expect("ok").is_some());
    }

    #[test]
    fn wrap_error_round_trips_through_armor_key() {
        let armor = key(5);
        let state = KdcFastState {
            armor_key: Some(armor.clone()),
            strengthen_key: None,
            fast_options: 0,
            nonce: 99,
        };
        let inner = KrbErrorMsg {
            pvno: 5,
            msg_type: 30,
            ctime: None,
            cusec: None,
            stime: Utc::now().fixed_offset(),
            susec: 0,
            error_code: 25,
            crealm: None,
            cname: None,
            realm: general_string(REALM).expect("realm"),
            sname: krbtgt_name(REALM).expect("sname"),
            e_text: None,
            e_data: None,
        };
        let hint = PaData {
            padata_type: 133,
            padata_value: OctetString::from(b"MIT".to_vec()),
        };
        let der = wrap_error(&state, &inner, vec![hint]).expect("wrap");
        let outer: Vec<PaData> = rasn::der::decode(&der).expect("METHOD-DATA");
        assert_eq!(outer.len(), 1);
        assert_eq!(outer[0].padata_type, 136);
        let PaFxFastReply::ArmoredData(rep) =
            rasn::der::decode(outer[0].padata_value.as_ref()).expect("reply");
        let plain = find_etype(18)
            .expect("etype")
            .decrypt(
                armor.key_bytes(),
                key_usage::FAST_REP,
                rep.enc_fast_rep.cipher.as_ref(),
            )
            .expect("decrypt");
        let resp: KrbFastResponse = rasn::der::decode(&plain).expect("response");
        assert_eq!(resp.nonce, 99);
        assert!(resp.strengthen_key.is_none() && resp.finished.is_none());
        let types: Vec<i32> = resp.padata.iter().map(|p| p.padata_type).collect();
        assert_eq!(types, vec![133, 137]);
        let fx: KrbErrorMsg =
            rasn::der::decode(resp.padata[1].padata_value.as_ref()).expect("FX-ERROR");
        assert_eq!(fx.error_code, 25);
    }

    #[test]
    fn reply_key_without_armor_is_unchanged_and_with_armor_is_strengthened() {
        let existing = key(9);
        let plain = KdcFastState {
            armor_key: None,
            strengthen_key: None,
            fast_options: 0,
            nonce: 0,
        };
        assert_eq!(
            plain.reply_key(&existing).expect("key").key_bytes(),
            existing.key_bytes()
        );
        let armored = KdcFastState {
            armor_key: Some(key(1)),
            strengthen_key: Some(key(2)),
            fast_options: 0,
            nonce: 0,
        };
        let expected = fx_cf2(&key(2), b"strengthenkey", &existing, b"replykey").expect("cf2");
        assert_eq!(
            armored.reply_key(&existing).expect("key").key_bytes(),
            expected.key_bytes()
        );
    }
}
