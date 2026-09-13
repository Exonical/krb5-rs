//! MIT krb5 semantics checks for FAST (RFC 6113) and the encrypted
//! challenge preauth mechanism (krb5-1.22.2 reference: lib/krb5/krb/fast.c,
//! preauth_ec.c, get_in_tkt.c, send_tgs.c, decode_kdc.c, gc_via_tkt.c).
//! Uses only the public API; the fake KDC derives the armor key itself by
//! decrypting the armor AP-REQ authenticator, never reading exchange state.

use krb5_rs::crypto::{find_etype, fx_cf2, key_usage};
use krb5_rs::protocol::fast::{
    build_pa_encrypted_challenge, verify_kdc_challenge, FastMode, FastState,
};
use krb5_rs::protocol::{
    AsExchange, AsExchangeConfig, Credential, StepResult, TgsExchange, TgsOptions, TgsStepResult,
    TicketTimes,
};
use krb5_rs::types::*;
use krb5_rs::Krb5Error;
use rasn::types::{BitString, GeneralString, OctetString};

const PA_TGS_REQ: i32 = 1;
const PA_ENC_TIMESTAMP: i32 = 2;
const PA_ETYPE_INFO2: i32 = 19;
const PA_FX_COOKIE: i32 = 133;
const PA_FX_FAST: i32 = 136;
const PA_FX_ERROR: i32 = 137;
const PA_ENCRYPTED_CHALLENGE: i32 = 138;
const PA_REQ_ENC_PA_REP: i32 = 149;
const PA_AS_FRESHNESS: i32 = 150;
const PA_PAC_REQUEST: i32 = 128;

const KDC_ERR_PREAUTH_REQUIRED: i32 = 25;
const KRB_ERR_GENERIC: i32 = 60;

const REALM: &str = "EXAMPLE.COM";
const CLIENT: &str = "testuser";
const PASSWORD: &str = "password";
const SALT: &[u8] = b"EXAMPLE.COMtestuser";

fn now() -> KerberosTime {
    chrono::Utc::now().fixed_offset()
}

fn gs(s: &str) -> GeneralString {
    GeneralString::from_bytes(s.as_bytes()).expect("generalstring")
}

fn profile18() -> &'static dyn krb5_rs::crypto::EtypeProfile {
    find_etype(18).expect("etype 18")
}

/// Password-derived AS key used by the fake KDC.
fn as_key() -> EncryptionKey {
    EncryptionKey::new(
        18,
        profile18()
            .string_to_key(PASSWORD.as_bytes(), SALT, None)
            .expect("s2k")
            .to_vec(),
    )
}

/// A fake armor TGT: real session key, opaque (undecryptable) ticket.
fn armor_tgt() -> Credential {
    let t = now();
    Credential {
        client: PrincipalName::new_principal(CLIENT),
        crealm: REALM.to_string(),
        server: PrincipalName::new_srv_inst("krbtgt", REALM),
        srealm: REALM.to_string(),
        session_key: EncryptionKey::new(18, rand::random::<[u8; 32]>().to_vec()),
        times: TicketTimes {
            authtime: t - chrono::Duration::minutes(5),
            starttime: Some(t - chrono::Duration::minutes(5)),
            endtime: t + chrono::Duration::hours(10),
            renew_till: None,
        },
        ticket: Ticket {
            tkt_vno: 5,
            realm: gs(REALM),
            sname: PrincipalName::new_srv_inst("krbtgt", REALM),
            enc_part: EncryptedData {
                etype: 18,
                kvno: Some(1),
                cipher: OctetString::from(rand::random::<[u8; 64]>().to_vec()),
            },
        },
        flags: KerberosFlags::new(TicketFlags::INITIAL | TicketFlags::PRE_AUTHENT),
        addresses: None,
        authdata: None,
    }
}

fn config_required(tgt: &Credential) -> AsExchangeConfig {
    let mut c = AsExchangeConfig::new(PrincipalName::new_principal(CLIENT), REALM);
    c.fast = FastMode::Required(tgt.clone());
    c
}

fn unwrap_send(result: StepResult) -> Vec<u8> {
    match result {
        StepResult::SendToKdc { data, .. } => data,
        other => panic!("expected SendToKdc, got: {other:?}"),
    }
}

fn unwrap_tgs_send(result: TgsStepResult) -> Vec<u8> {
    match result {
        TgsStepResult::SendToKdc { data, .. } => data,
        other => panic!("expected SendToKdc, got: {other:?}"),
    }
}

fn padata_types(padata: &[PaData]) -> Vec<i32> {
    padata.iter().map(|pa| pa.padata_type).collect()
}

fn find_pa(padata: &[PaData], ty: i32) -> Option<&PaData> {
    padata.iter().find(|pa| pa.padata_type == ty)
}

/// Extract PA-FX-FAST (KrbFastArmoredReq) from an encoded KDC-REQ.
fn armored_req_of(kdc_req: &KdcReq) -> KrbFastArmoredReq {
    let pa =
        find_pa(kdc_req.padata.as_deref().unwrap_or(&[]), PA_FX_FAST).expect("PA-FX-FAST padata");
    let fx: PaFxFastRequest =
        rasn::der::decode(pa.padata_value.as_ref()).expect("decode PA-FX-FAST-REQUEST");
    match fx {
        PaFxFastRequest::ArmoredData(a) => a,
    }
}

/// Decrypt an AP-REQ authenticator with `key` (usage 11) and return the subkey.
fn ap_req_subkey(ap_req_der: &[u8], key: &EncryptionKey) -> EncryptionKey {
    let ap_req: ApReq = rasn::der::decode(ap_req_der).expect("decode AP-REQ");
    let profile = find_etype(key.keytype).expect("etype");
    let plain = profile
        .decrypt(
            key.key_bytes(),
            key_usage::AP_REQ_AUTH,
            ap_req.authenticator.cipher.as_ref(),
        )
        .expect("decrypt authenticator");
    let auth: Authenticator = rasn::der::decode(&plain).expect("decode authenticator");
    auth.subkey.expect("authenticator subkey")
}

/// Derive the armor key the way the KDC would: subkey from the armor AP-REQ
/// (AS case) combined with the armor TGT session key via FX-CF2.
fn armor_key_from_armor(armor: &KrbFastArmor, tgt: &Credential) -> EncryptionKey {
    assert_eq!(armor.armor_type, 1, "FX_FAST_ARMOR_AP_REQUEST");
    let subkey = ap_req_subkey(armor.armor_value.as_ref(), &tgt.session_key);
    fx_cf2(&subkey, b"subkeyarmor", &tgt.session_key, b"ticketarmor").expect("cf2")
}

/// Derive the armor key used for an armored AS-REQ emitted by an exchange in
/// Required mode with `tgt` as the armor credential.
fn as_armor_key(as_req_der: &[u8], tgt: &Credential) -> EncryptionKey {
    let as_req: AsReq = rasn::der::decode(as_req_der).expect("decode AS-REQ");
    let armored = armored_req_of(&as_req.0);
    armor_key_from_armor(armored.armor.as_ref().expect("armor"), tgt)
}

/// Decrypt the inner KrbFastReq of an armored KDC-REQ (usage 51).
fn inner_fast_req(kdc_req: &KdcReq, armor_key: &EncryptionKey) -> KrbFastReq {
    let armored = armored_req_of(kdc_req);
    let profile = find_etype(armor_key.keytype).expect("etype");
    let plain = profile
        .decrypt(
            armor_key.key_bytes(),
            key_usage::FAST_ENC,
            armored.enc_fast_req.cipher.as_ref(),
        )
        .expect("decrypt enc-fast-req");
    rasn::der::decode(&plain).expect("decode KrbFastReq")
}

/// Wrap `padata` into a KrbFastResponse and the PA-FX-FAST-REPLY padata.
fn fast_reply_padata(
    armor_key: &EncryptionKey,
    fast_padata: Vec<PaData>,
    nonce: u32,
    finished: Option<KrbFastFinished>,
    strengthen: Option<EncryptionKey>,
) -> PaData {
    let resp = KrbFastResponse {
        padata: fast_padata,
        strengthen_key: strengthen,
        finished,
        nonce,
    };
    let resp_der = rasn::der::encode(&resp).expect("encode KrbFastResponse");
    let profile = find_etype(armor_key.keytype).expect("etype");
    let cipher = profile
        .encrypt(armor_key.key_bytes(), key_usage::FAST_REP, &resp_der)
        .expect("encrypt fast rep");
    let reply = PaFxFastReply::ArmoredData(KrbFastArmoredRep {
        enc_fast_rep: EncryptedData {
            etype: armor_key.keytype,
            kvno: None,
            cipher: cipher.into(),
        },
    });
    PaData {
        padata_type: PA_FX_FAST,
        padata_value: rasn::der::encode(&reply).expect("encode fx reply").into(),
    }
}

/// Build a FAST-wrapped KRB-ERROR: outer error whose e-data is METHOD-DATA
/// containing PA-FX-FAST; inner error + `extra` inside the FAST response.
fn fast_error_reply(
    armor_key: &EncryptionKey,
    nonce: u32,
    inner: &KrbErrorMsg,
    extra: Vec<PaData>,
) -> Vec<u8> {
    let mut fast_padata = vec![PaData {
        padata_type: PA_FX_ERROR,
        padata_value: rasn::der::encode(inner).expect("encode inner error").into(),
    }];
    fast_padata.extend(extra);
    let fx = fast_reply_padata(armor_key, fast_padata, nonce, None, None);
    let e_data = rasn::der::encode(&vec![fx]).expect("encode method-data");
    let outer = KrbErrorMsg {
        e_data: Some(e_data.into()),
        ..inner.clone()
    };
    rasn::der::encode(&outer).expect("encode outer error")
}

fn krb_error(code: i32, stime: KerberosTime, e_data: Option<Vec<u8>>) -> KrbErrorMsg {
    KrbErrorMsg {
        pvno: 5,
        msg_type: 30,
        ctime: None,
        cusec: None,
        stime,
        susec: 12345,
        error_code: code,
        crealm: None,
        cname: None,
        realm: gs(REALM),
        sname: PrincipalName::new_srv_inst("krbtgt", REALM),
        e_text: None,
        e_data: e_data.map(OctetString::from),
    }
}

fn etype_info2_pa() -> PaData {
    let entries = vec![EtypeInfo2Entry {
        etype: 18,
        salt: Some(gs("EXAMPLE.COMtestuser")),
        s2kparams: None,
    }];
    PaData {
        padata_type: PA_ETYPE_INFO2,
        padata_value: rasn::der::encode(&entries).expect("etype-info2").into(),
    }
}

fn empty_pa(ty: i32) -> PaData {
    PaData {
        padata_type: ty,
        padata_value: OctetString::from(Vec::new()),
    }
}

fn cookie_pa(c: &[u8]) -> PaData {
    PaData {
        padata_type: PA_FX_COOKIE,
        padata_value: OctetString::from(c.to_vec()),
    }
}

fn ticket_for(sname: PrincipalName) -> Ticket {
    Ticket {
        tkt_vno: 5,
        realm: gs(REALM),
        sname,
        enc_part: EncryptedData {
            etype: 18,
            kvno: Some(1),
            cipher: OctetString::from(rand::random::<[u8; 64]>().to_vec()),
        },
    }
}

struct AsRepSpec {
    nonce: u32,
    armor_key: EncryptionKey,
    /// client principal in KrbFastFinished
    finished_cname: PrincipalName,
    /// ticket the checksum is computed over
    cksum_ticket: Ticket,
    /// ticket placed in the reply
    ticket: Ticket,
    strengthen: Option<EncryptionKey>,
    /// extra padata inside the FAST response
    fast_padata: Vec<PaData>,
    /// padata inside EncKdcRepPart.encrypted_pa_data
    enc_padata: Option<Vec<PaData>>,
    flags: TicketFlags,
    /// encrypt enc-part with this key instead of the strengthened reply key
    enc_key_override: Option<EncryptionKey>,
    /// include the 136 reply padata at all
    include_fx_reply: bool,
    /// include a KDC encrypted-challenge padata in the FAST response
    kdc_challenge: bool,
}

/// Build a FAST armored AS-REP per MIT's process_response expectations.
fn build_fast_as_rep(spec: &AsRepSpec) -> Vec<u8> {
    let profile = profile18();
    let akey = as_key();
    let reply_key = match &spec.strengthen {
        Some(s) => fx_cf2(s, b"strengthenkey", &akey, b"replykey").expect("cf2"),
        None => akey.clone(),
    };

    let session_key = EncryptionKey::new(18, rand::random::<[u8; 32]>().to_vec());
    let t = now();
    let enc_kdc_rep = EncKdcRepPart {
        key: session_key,
        last_req: vec![LastReqEntry {
            lr_type: 0,
            lr_value: t,
        }],
        nonce: spec.nonce,
        key_expiration: None,
        flags: KerberosFlags::new(spec.flags),
        authtime: t,
        starttime: Some(t),
        endtime: t + chrono::Duration::hours(10),
        renew_till: None,
        srealm: gs(REALM),
        sname: PrincipalName::new_srv_inst("krbtgt", REALM),
        caddr: None,
        encrypted_pa_data: spec.enc_padata.clone(),
    };
    let plaintext = rasn::der::encode(&EncAsRepPart(enc_kdc_rep)).expect("encode EncAsRepPart");
    let enc_key = spec.enc_key_override.clone().unwrap_or(reply_key);
    let enc_profile = find_etype(enc_key.keytype).expect("etype");
    let cipher = enc_profile
        .encrypt(enc_key.key_bytes(), key_usage::AS_REP_ENCPART, &plaintext)
        .expect("encrypt enc-part");

    let mut rep_padata = Vec::new();
    if spec.include_fx_reply {
        let ticket_der = rasn::der::encode(&spec.cksum_ticket).expect("ticket der");
        let finished = KrbFastFinished {
            timestamp: t,
            usec: 0,
            crealm: gs(REALM),
            cname: spec.finished_cname.clone(),
            ticket_checksum: Checksum {
                cksumtype: profile.checksum_type(),
                checksum: profile
                    .checksum(
                        spec.armor_key.key_bytes(),
                        key_usage::FAST_FINISHED,
                        &ticket_der,
                    )
                    .expect("ticket cksum")
                    .into(),
            },
        };
        let mut fast_padata = spec.fast_padata.clone();
        if spec.kdc_challenge {
            let ckey = fx_cf2(
                &spec.armor_key,
                b"kdcchallengearmor",
                &akey,
                b"challengelongterm",
            )
            .expect("cf2");
            let ts = rasn::der::encode(&PaEncTsEnc {
                patimestamp: t,
                pausec: Some(1),
            })
            .expect("ts");
            let ccipher = profile
                .encrypt(ckey.key_bytes(), key_usage::ENC_CHALLENGE_KDC, &ts)
                .expect("kdc challenge");
            let enc = EncryptedData {
                etype: ckey.keytype,
                kvno: None,
                cipher: ccipher.into(),
            };
            fast_padata.push(PaData {
                padata_type: PA_ENCRYPTED_CHALLENGE,
                padata_value: rasn::der::encode(&enc).expect("enc data").into(),
            });
        }
        rep_padata.push(fast_reply_padata(
            &spec.armor_key,
            fast_padata,
            spec.nonce,
            Some(finished),
            spec.strengthen.clone(),
        ));
    }

    let rep = KdcRep {
        pvno: 5,
        msg_type: 11,
        padata: if rep_padata.is_empty() {
            None
        } else {
            Some(rep_padata)
        },
        crealm: gs(REALM),
        cname: PrincipalName::new_principal(CLIENT),
        ticket: spec.ticket.clone(),
        enc_part: EncryptedData {
            etype: enc_key.keytype,
            kvno: None,
            cipher: cipher.into(),
        },
    };
    rasn::der::encode(&AsRep(rep)).expect("encode AS-REP")
}

fn base_spec(armor_key: &EncryptionKey, nonce: u32) -> AsRepSpec {
    let ticket = ticket_for(PrincipalName::new_srv_inst("krbtgt", REALM));
    AsRepSpec {
        nonce,
        armor_key: armor_key.clone(),
        finished_cname: PrincipalName::new_principal(CLIENT),
        ticket: ticket.clone(),
        cksum_ticket: ticket,
        strengthen: None,
        fast_padata: vec![etype_info2_pa()],
        enc_padata: None,
        flags: TicketFlags::INITIAL,
        enc_key_override: None,
        include_fx_reply: true,
        kdc_challenge: false,
    }
}

fn last_nonce(req_der: &[u8]) -> u32 {
    let as_req: AsReq = rasn::der::decode(req_der).expect("decode AS-REQ");
    as_req.0.req_body.nonce
}

// ---------------------------------------------------------------------------
// Group 1: FAST ASN.1 types and constants (RFC 6113 §5.4)
// ---------------------------------------------------------------------------

#[test]
fn fast_asn1_types_and_constants() {
    // Padata type assignments (RFC 6113 §7).
    assert_eq!(PaDataType::FxCookie as i32, 133);
    assert_eq!(PaDataType::FxFast as i32, 136);
    assert_eq!(PaDataType::FxError as i32, 137);
    assert_eq!(PaDataType::EncryptedChallenge as i32, 138);
    // Key usages (RFC 6113 §5.4.6).
    assert_eq!(key_usage::FAST_REQ_CHKSUM, 50);
    assert_eq!(key_usage::FAST_ENC, 51);
    assert_eq!(key_usage::FAST_REP, 52);
    assert_eq!(key_usage::FAST_FINISHED, 53);
    assert_eq!(key_usage::ENC_CHALLENGE_CLIENT, 54);
    assert_eq!(key_usage::ENC_CHALLENGE_KDC, 55);

    // KrbFastReq field tags: fast-options [0], padata [1], req-body [2].
    let inner = KrbFastReq {
        fast_options: BitString::from_slice(&[]),
        padata: vec![empty_pa(150)],
        req_body: KdcReqBody {
            kdc_options: KerberosFlags::new(KdcOptions::FORWARDABLE),
            cname: Some(PrincipalName::new_principal(CLIENT)),
            realm: gs(REALM),
            sname: Some(PrincipalName::new_srv_inst("krbtgt", REALM)),
            from: None,
            till: now(),
            rtime: None,
            nonce: 7,
            etype: vec![18],
            addresses: None,
            enc_authorization_data: None,
            additional_tickets: None,
        },
    };
    let der = rasn::der::encode(&inner).expect("encode KrbFastReq");
    assert_eq!(der[0], 0x30, "SEQUENCE");
    // fields tagged a0 (explicit [0]), a1, a2 must appear in order
    let a0 = der
        .windows(2)
        .position(|w| w == [0xa0, 0x03])
        .expect("tag 0");
    let a1 = der.windows(2).position(|w| w[0] == 0xa1).expect("tag 1");
    let a2 = der.windows(2).position(|w| w[0] == 0xa2).expect("tag 2");
    assert!(a0 < a1 && a1 < a2);
    let back: KrbFastReq = rasn::der::decode(&der).expect("roundtrip");
    assert_eq!(back.req_body.nonce, 7);
    assert_eq!(back.padata.len(), 1);

    // PA-FX-FAST-REQUEST is a CHOICE: armored-data [0].
    let armored = KrbFastArmoredReq {
        armor: Some(KrbFastArmor {
            armor_type: 1,
            armor_value: OctetString::from(b"APREQ".to_vec()),
        }),
        req_checksum: Checksum {
            cksumtype: 16,
            checksum: OctetString::from(b"cksum".to_vec()),
        },
        enc_fast_req: EncryptedData {
            etype: 18,
            kvno: None,
            cipher: OctetString::from(b"cipher".to_vec()),
        },
    };
    let fx = PaFxFastRequest::ArmoredData(armored);
    let fx_der = rasn::der::encode(&fx).expect("encode fx-req");
    assert_eq!(fx_der[0], 0xa0, "CHOICE armored-data context tag 0");
    let fx_back: PaFxFastRequest = rasn::der::decode(&fx_der).expect("fx roundtrip");
    let PaFxFastRequest::ArmoredData(back) = fx_back;
    assert_eq!(back.armor.as_ref().expect("armor").armor_type, 1);
    assert_eq!(back.req_checksum.cksumtype, 16);

    // PA-FX-FAST-REPLY CHOICE.
    let fxrep = PaFxFastReply::ArmoredData(KrbFastArmoredRep {
        enc_fast_rep: EncryptedData {
            etype: 18,
            kvno: None,
            cipher: OctetString::from(b"x".to_vec()),
        },
    });
    let r = rasn::der::encode(&fxrep).expect("encode fx-rep");
    assert_eq!(r[0], 0xa0);
    let _: PaFxFastReply = rasn::der::decode(&r).expect("roundtrip");
}

// ---------------------------------------------------------------------------
// Group 2: armor construction (fast.c:52-142)
// ---------------------------------------------------------------------------

#[test]
fn armor_ap_request_constructs_subkey_ap_req_and_cf2_key() {
    let tgt = armor_tgt();
    let mut state = FastState::new();
    state.armor_ap_request(&tgt).expect("armor_ap_request");
    let armor_key = state.armor_key().expect("armor key").clone();

    // Push a dummy AS-REQ through prep_req to observe the stored armor.
    let req = KdcReq {
        pvno: 5,
        msg_type: 10,
        padata: Some(vec![empty_pa(150)]),
        req_body: KdcReqBody {
            kdc_options: KerberosFlags::new(KdcOptions::empty()),
            cname: Some(PrincipalName::new_principal(CLIENT)),
            realm: gs(REALM),
            sname: Some(PrincipalName::new_srv_inst("krbtgt", REALM)),
            from: None,
            till: now(),
            rtime: None,
            nonce: 42,
            etype: vec![18],
            addresses: None,
            enc_authorization_data: None,
            additional_tickets: None,
        },
    };
    let body_der = rasn::der::encode(&req.req_body).expect("body");
    let out = state
        .prep_req(&req, &body_der, krb5_rs::protocol::fast::FastMsgType::As)
        .expect("prep_req");
    let as_req: AsReq = rasn::der::decode(&out).expect("decode outer");
    let armored = armored_req_of(&as_req.0);
    let armor = armored.armor.as_ref().expect("armor present");
    assert_eq!(armor.armor_type, 1);

    let ap_req: ApReq = rasn::der::decode(armor.armor_value.as_ref()).expect("AP-REQ");
    // The armor AP-REQ is for krbtgt/<realm>, uses a subkey, no mutual flag.
    assert_eq!(
        ap_req.ticket.sname,
        PrincipalName::new_srv_inst("krbtgt", REALM)
    );
    let opts = u32::from_be_bytes(ap_req.ap_options.to_bytes());
    assert_eq!(opts & ApOptions::MUTUAL_REQUIRED.bits(), 0);
    let subkey = ap_req_subkey(armor.armor_value.as_ref(), &tgt.session_key);

    let expected = fx_cf2(&subkey, b"subkeyarmor", &tgt.session_key, b"ticketarmor").expect("cf2");
    assert_eq!(armor_key.keytype, expected.keytype);
    assert_eq!(armor_key.key_bytes(), expected.key_bytes());
}

#[test]
fn tgs_armor_ccache_null_branch_has_no_armor_field() {
    let subkey = EncryptionKey::new(18, rand::random::<[u8; 32]>().to_vec());
    let session = EncryptionKey::new(18, rand::random::<[u8; 32]>().to_vec());
    let mut state = FastState::new();
    state.tgs_armor(&subkey, &session).expect("tgs_armor");
    let expected = fx_cf2(&subkey, b"subkeyarmor", &session, b"ticketarmor").expect("cf2");
    assert_eq!(
        state.armor_key().expect("key").key_bytes(),
        expected.key_bytes()
    );

    let req = KdcReq {
        pvno: 5,
        msg_type: 12,
        padata: Some(vec![PaData {
            padata_type: PA_TGS_REQ,
            padata_value: OctetString::from(b"APREQ".to_vec()),
        }]),
        req_body: KdcReqBody {
            kdc_options: KerberosFlags::new(KdcOptions::empty()),
            cname: None,
            realm: gs(REALM),
            sname: Some(PrincipalName::new_srv_inst("HTTP", "h.example.com")),
            from: None,
            till: now(),
            rtime: None,
            nonce: 9,
            etype: vec![18],
            addresses: None,
            enc_authorization_data: None,
            additional_tickets: None,
        },
    };
    let out = state
        .prep_req(&req, b"APREQ", krb5_rs::protocol::fast::FastMsgType::Tgs)
        .expect("prep_req");
    let tgs_req: TgsReq = rasn::der::decode(&out).expect("decode outer");
    let armored = armored_req_of(&tgs_req.0);
    assert!(armored.armor.is_none(), "ccache==NULL armor is implicit");
    // TGS outer padata: [PA-TGS-REQ, PA-FX-FAST, ...]
    let types = padata_types(tgs_req.0.padata.as_deref().expect("padata"));
    assert_eq!(&types[..2], &[PA_TGS_REQ, PA_FX_FAST]);
}

#[test]
fn prep_req_without_armor_key_passes_request_through() {
    let mut state = FastState::new();
    let req = KdcReq {
        pvno: 5,
        msg_type: 10,
        padata: Some(vec![empty_pa(150)]),
        req_body: KdcReqBody {
            kdc_options: KerberosFlags::new(KdcOptions::empty()),
            cname: Some(PrincipalName::new_principal(CLIENT)),
            realm: gs(REALM),
            sname: Some(PrincipalName::new_srv_inst("krbtgt", REALM)),
            from: None,
            till: now(),
            rtime: None,
            nonce: 3,
            etype: vec![18],
            addresses: None,
            enc_authorization_data: None,
            additional_tickets: None,
        },
    };
    let out = state
        .prep_req(&req, b"x", krb5_rs::protocol::fast::FastMsgType::As)
        .expect("prep_req");
    let expected = rasn::der::encode(&AsReq(req.clone())).expect("encode");
    assert_eq!(out, expected);
}

// ---------------------------------------------------------------------------
// Group 3: FAST request construction via the AS exchange (fast.c:254-358)
// ---------------------------------------------------------------------------

#[test]
fn as_required_first_request_is_armored() {
    let tgt = armor_tgt();
    let mut exchange = AsExchange::new(config_required(&tgt), PASSWORD);
    let req_der = unwrap_send(exchange.step(&[]).expect("initial step"));

    let as_req: AsReq = rasn::der::decode(&req_der).expect("decode AS-REQ");
    let padata = as_req.0.padata.as_deref().expect("padata");
    assert_eq!(padata_types(padata), vec![PA_FX_FAST]);

    let armored = armored_req_of(&as_req.0);
    let armor = armored.armor.as_ref().expect("armor");
    assert_eq!(armor.armor_type, 1);
    let ap_req: ApReq = rasn::der::decode(armor.armor_value.as_ref()).expect("AP-REQ");
    assert_eq!(
        ap_req.ticket.sname,
        PrincipalName::new_srv_inst("krbtgt", REALM)
    );
    let opts = u32::from_be_bytes(ap_req.ap_options.to_bytes());
    assert_eq!(opts & ApOptions::MUTUAL_REQUIRED.bits(), 0);

    let armor_key = as_armor_key(&req_der, &tgt);
    let profile = profile18();

    // req_checksum: armor key, usage 50, over DER of the outer req_body,
    // mandatory checksum type.
    assert_eq!(armored.req_checksum.cksumtype, profile.checksum_type());
    let body_der = rasn::der::encode(&as_req.0.req_body).expect("body der");
    profile
        .verify_checksum(
            armor_key.key_bytes(),
            key_usage::FAST_REQ_CHKSUM,
            &body_der,
            armored.req_checksum.checksum.as_ref(),
        )
        .expect("req_checksum");

    // enc_fast_req: usage 51 → KrbFastReq
    let inner = inner_fast_req(&as_req.0, &armor_key);
    assert!(inner.fast_options.as_raw_slice().iter().all(|b| *b == 0));
    assert_eq!(
        rasn::der::encode(&inner.req_body).expect("inner body"),
        body_der,
        "inner req_body == outer req_body"
    );
    assert_eq!(
        padata_types(&inner.padata),
        vec![PA_AS_FRESHNESS, PA_REQ_ENC_PA_REP, PA_PAC_REQUEST]
    );
    assert_eq!(inner.req_body.nonce, as_req.0.req_body.nonce);
}

#[test]
fn as_opportunistic_upgrades_on_fx_fast_hint() {
    let tgt = armor_tgt();
    let mut config = AsExchangeConfig::new(PrincipalName::new_principal(CLIENT), REALM);
    config.fast = FastMode::Opportunistic(tgt.clone());
    let mut exchange = AsExchange::new(config, PASSWORD);

    // First request is unarmored.
    let req1 = unwrap_send(exchange.step(&[]).expect("initial"));
    let as_req: AsReq = rasn::der::decode(&req1).expect("decode");
    assert!(!padata_types(as_req.0.padata.as_deref().expect("padata")).contains(&PA_FX_FAST));

    // Unarmored PREAUTH_REQUIRED advertising FAST (padata 136 + etype-info +
    // enc-timestamp + cookie).
    let e_data = rasn::der::encode(&vec![
        etype_info2_pa(),
        empty_pa(PA_FX_FAST),
        empty_pa(PA_ENC_TIMESTAMP),
        cookie_pa(b"C1"),
    ])
    .expect("method data");
    let err = krb_error(KDC_ERR_PREAUTH_REQUIRED, now(), Some(e_data));
    let req2 = unwrap_send(
        exchange
            .step(&rasn::der::encode(&err).expect("err"))
            .expect("upgrade step"),
    );

    // Restarted request is armored and fresh: no cookie, no preauth.
    let as_req: AsReq = rasn::der::decode(&req2).expect("decode req2");
    assert_eq!(
        padata_types(as_req.0.padata.as_deref().expect("padata")),
        vec![PA_FX_FAST]
    );
    let armor_key = as_armor_key(&req2, &tgt);
    let inner = inner_fast_req(&as_req.0, &armor_key);
    assert_eq!(
        padata_types(&inner.padata),
        vec![PA_AS_FRESHNESS, PA_REQ_ENC_PA_REP, PA_PAC_REQUEST],
        "fresh restart: no cookie, no preauth"
    );

    // While armored, an unarmored PREAUTH_REQUIRED is a FAST decode failure:
    // the outer error surfaces with no retry (fast.c:441-452 + :1760-1766).
    let err = krb_error(
        KDC_ERR_PREAUTH_REQUIRED,
        now(),
        Some(rasn::der::encode(&vec![etype_info2_pa()]).expect("md")),
    );
    match exchange.step(&rasn::der::encode(&err).expect("err")) {
        Err(Krb5Error::KdcError(e)) => assert_eq!(e.error_code, KDC_ERR_PREAUTH_REQUIRED),
        other => panic!("expected KdcError(25), got: {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Group 3b/7: FAST error handling (fast.c:426-515)
// ---------------------------------------------------------------------------

/// Drive a Required-mode exchange through an armored PREAUTH_REQUIRED whose
/// FAST response carries `fast_padata` (in addition to the FX-ERROR wrapper).
/// Returns (next request DER, armor key).
fn drive_fast_error(
    exchange: &mut AsExchange,
    tgt: &Credential,
    req1: &[u8],
    inner: &KrbErrorMsg,
    fast_padata: Vec<PaData>,
) -> Vec<u8> {
    let armor_key = as_armor_key(req1, tgt);
    let nonce = last_nonce(req1);
    let reply = fast_error_reply(&armor_key, nonce, inner, fast_padata);
    unwrap_send(exchange.step(&reply).expect("fast error step"))
}

#[test]
fn as_fast_error_unwraps_and_sends_encrypted_challenge() {
    let tgt = armor_tgt();
    let mut exchange = AsExchange::new(config_required(&tgt), PASSWORD);
    let req1 = unwrap_send(exchange.step(&[]).expect("initial"));
    let armor_key = as_armor_key(&req1, &tgt);

    // Inner PREAUTH_REQUIRED whose FAST response padata offers the encrypted
    // challenge plus etype-info and a cookie. stime is 300s in the past: the
    // client must apply the KDC time offset (AUTH_OFFSET) to the challenge.
    let stime = now() - chrono::Duration::seconds(300);
    let inner = krb_error(
        KDC_ERR_PREAUTH_REQUIRED,
        stime,
        Some(rasn::der::encode(&Vec::<PaData>::new()).expect("empty")),
    );
    let req2 = drive_fast_error(
        &mut exchange,
        &tgt,
        &req1,
        &inner,
        vec![
            etype_info2_pa(),
            empty_pa(PA_ENCRYPTED_CHALLENGE),
            cookie_pa(b"C9"),
        ],
    );

    let as_req: AsReq = rasn::der::decode(&req2).expect("decode req2");
    assert_eq!(
        padata_types(as_req.0.padata.as_deref().expect("padata")),
        vec![PA_FX_FAST]
    );
    let inner_req = inner_fast_req(&as_req.0, &armor_key);
    assert_eq!(
        padata_types(&inner_req.padata),
        vec![
            PA_FX_COOKIE,
            PA_ENCRYPTED_CHALLENGE,
            PA_AS_FRESHNESS,
            PA_REQ_ENC_PA_REP,
            PA_PAC_REQUEST
        ]
    );
    assert_eq!(
        find_pa(&inner_req.padata, PA_FX_COOKIE)
            .expect("cookie")
            .padata_value
            .as_ref(),
        b"C9"
    );

    // Decrypt PA-ENCRYPTED-CHALLENGE: client derivation + usage 54.
    let enc: EncryptedData = rasn::der::decode(
        find_pa(&inner_req.padata, PA_ENCRYPTED_CHALLENGE)
            .expect("challenge")
            .padata_value
            .as_ref(),
    )
    .expect("decode enc-data");
    let ckey = fx_cf2(
        &armor_key,
        b"clientchallengearmor",
        &as_key(),
        b"challengelongterm",
    )
    .expect("cf2");
    let plain = profile18()
        .decrypt(
            ckey.key_bytes(),
            key_usage::ENC_CHALLENGE_CLIENT,
            enc.cipher.as_ref(),
        )
        .expect("decrypt challenge");
    let ts: PaEncTsEnc = rasn::der::decode(&plain).expect("decode ts");
    let skew = (ts.patimestamp - stime).num_seconds().abs();
    assert!(
        skew <= 2,
        "challenge timestamp should use KDC offset: {skew}s"
    );
}

#[test]
fn as_fast_error_with_enc_timestamp_offer_sends_type2() {
    let tgt = armor_tgt();
    let mut exchange = AsExchange::new(config_required(&tgt), PASSWORD);
    let req1 = unwrap_send(exchange.step(&[]).expect("initial"));
    let armor_key = as_armor_key(&req1, &tgt);

    let stime = now() - chrono::Duration::seconds(300);
    let inner = krb_error(KDC_ERR_PREAUTH_REQUIRED, stime, None);
    let req2 = drive_fast_error(
        &mut exchange,
        &tgt,
        &req1,
        &inner,
        vec![
            etype_info2_pa(),
            empty_pa(PA_ENC_TIMESTAMP),
            cookie_pa(b"ck"),
        ],
    );
    let as_req: AsReq = rasn::der::decode(&req2).expect("decode req2");
    let inner_req = inner_fast_req(&as_req.0, &armor_key);
    let types = padata_types(&inner_req.padata);
    assert!(
        types.contains(&PA_ENC_TIMESTAMP),
        "type 2 present: {types:?}"
    );
    assert!(!types.contains(&PA_ENCRYPTED_CHALLENGE));

    // Timestamp uses the authenticated KDC offset (stime -300s).
    let enc: EncryptedData = rasn::der::decode(
        find_pa(&inner_req.padata, PA_ENC_TIMESTAMP)
            .expect("ts pa")
            .padata_value
            .as_ref(),
    )
    .expect("decode enc-data");
    let plain = profile18()
        .decrypt(
            as_key().key_bytes(),
            key_usage::PA_ENC_TIMESTAMP,
            enc.cipher.as_ref(),
        )
        .expect("decrypt ts");
    let ts: PaEncTsEnc = rasn::der::decode(&plain).expect("decode ts");
    let skew = (ts.patimestamp - stime).num_seconds().abs();
    assert!(skew <= 2, "timestamp should use KDC offset: {skew}s");
}

#[test]
fn as_fast_error_nonce_mismatch_surfaces_outer_error() {
    let tgt = armor_tgt();
    let mut exchange = AsExchange::new(config_required(&tgt), PASSWORD);
    let req1 = unwrap_send(exchange.step(&[]).expect("initial"));
    let armor_key = as_armor_key(&req1, &tgt);
    let nonce = last_nonce(&req1);

    let inner = krb_error(KDC_ERR_PREAUTH_REQUIRED, now(), None);
    // Wrong nonce inside the FAST response.
    let reply = fast_error_reply(&armor_key, nonce ^ 1, &inner, vec![cookie_pa(b"c")]);
    match exchange.step(&reply) {
        Err(Krb5Error::KdcError(e)) => assert_eq!(e.error_code, KDC_ERR_PREAUTH_REQUIRED),
        other => panic!("expected outer KdcError(25), got: {other:?}"),
    }
}

#[test]
fn as_fast_error_without_fx_error_is_fatal() {
    let tgt = armor_tgt();
    let mut exchange = AsExchange::new(config_required(&tgt), PASSWORD);
    let req1 = unwrap_send(exchange.step(&[]).expect("initial"));
    let armor_key = as_armor_key(&req1, &tgt);
    let nonce = last_nonce(&req1);

    // FAST response with no PA-FX-ERROR padata at all.
    let fx = fast_reply_padata(&armor_key, vec![cookie_pa(b"c")], nonce, None, None);
    let e_data = rasn::der::encode(&vec![fx]).expect("md");
    let outer = krb_error(KDC_ERR_PREAUTH_REQUIRED, now(), Some(e_data));
    match exchange.step(&rasn::der::encode(&outer).expect("err")) {
        Err(Krb5Error::ReplyValidation(_)) => {}
        other => panic!("expected ReplyValidation, got: {other:?}"),
    }
}

#[test]
fn as_fast_error_without_cookie_does_not_retry() {
    let tgt = armor_tgt();
    let mut exchange = AsExchange::new(config_required(&tgt), PASSWORD);
    let req1 = unwrap_send(exchange.step(&[]).expect("initial"));
    let armor_key = as_armor_key(&req1, &tgt);
    let nonce = last_nonce(&req1);

    // FAST response contains only FX-ERROR → retry = false. The inner code
    // (GENERIC 60) surfaces even though the outer code is PREAUTH_REQUIRED.
    // (Inner PREAUTH_FAILED here would instead hit MIT's restart branch —
    // get_in_tkt.c:1709-1715 runs before retry is consulted.)
    let inner = krb_error(KRB_ERR_GENERIC, now(), None);
    let reply = fast_error_reply(&armor_key, nonce, &inner, Vec::new());
    match exchange.step(&reply) {
        Err(Krb5Error::KdcError(e)) => assert_eq!(e.error_code, KRB_ERR_GENERIC),
        other => panic!("expected inner KdcError(60), got: {other:?}"),
    }
}

#[test]
fn malformed_fast_error_falls_back_to_outer_error() {
    let tgt = armor_tgt();
    let mut exchange = AsExchange::new(config_required(&tgt), PASSWORD);
    let req1 = unwrap_send(exchange.step(&[]).expect("initial"));
    let nonce = last_nonce(&req1);
    let _ = nonce;

    // Garbage e_data that doesn't decode as METHOD-DATA at all.
    let outer = krb_error(KRB_ERR_GENERIC, now(), Some(vec![0xde, 0xad]));
    match exchange.step(&rasn::der::encode(&outer).expect("err")) {
        Err(Krb5Error::KdcError(e)) => assert_eq!(e.error_code, KRB_ERR_GENERIC),
        other => panic!("expected KdcError(60), got: {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Group 4: AS FAST response processing (fast.c:517-593, 634-675)
// ---------------------------------------------------------------------------

/// Run Required-mode AS exchange to first request; return (exchange, req der,
/// armor key, nonce).
fn start_required(tgt: &Credential) -> (AsExchange, Vec<u8>, EncryptionKey, u32) {
    let mut exchange = AsExchange::new(config_required(tgt), PASSWORD);
    let req = unwrap_send(exchange.step(&[]).expect("initial"));
    let key = as_armor_key(&req, tgt);
    let nonce = last_nonce(&req);
    (exchange, req, key, nonce)
}

#[test]
fn as_fast_response_strengthened_reply_completes() {
    let tgt = armor_tgt();
    let (mut exchange, req, armor_key, nonce) = start_required(&tgt);

    let strengthen = EncryptionKey::new(18, rand::random::<[u8; 32]>().to_vec());
    // enc-pa-rep over the OUTER request bytes, keyed by the reply key.
    let reply_key = fx_cf2(&strengthen, b"strengthenkey", &as_key(), b"replykey").expect("cf2");
    let cksum = Checksum {
        cksumtype: profile18().checksum_type(),
        checksum: profile18()
            .checksum(reply_key.key_bytes(), key_usage::AS_REQ, &req)
            .expect("cksum")
            .into(),
    };
    let enc_padata = vec![
        PaData {
            padata_type: PA_REQ_ENC_PA_REP,
            padata_value: rasn::der::encode(&cksum).expect("cksum").into(),
        },
        empty_pa(PA_FX_FAST),
    ];
    let mut spec = base_spec(&armor_key, nonce);
    spec.strengthen = Some(strengthen);
    spec.flags = TicketFlags::INITIAL | TicketFlags::ENC_PA_REP;
    spec.enc_padata = Some(enc_padata);
    spec.kdc_challenge = true;

    let rep = build_fast_as_rep(&spec);
    match exchange.step(&rep).expect("step") {
        StepResult::Complete => {}
        other => panic!("expected Complete, got: {other:?}"),
    }
    let cred = exchange.credential().expect("credential");
    // Session key came from inside the encrypted reply.
    assert_eq!(cred.session_key.keytype, 18);
    assert_eq!(cred.session_key.key_bytes().len(), 32);
    assert!(
        exchange.fast_avail(),
        "FAST + valid enc-pa-rep ⇒ fast_avail"
    );
    assert!(
        exchange.kdc_verified(),
        "valid KDC challenge ⇒ kdc_verified"
    );
}

#[test]
fn as_fast_response_without_enc_pa_rep_flag_not_fast_avail() {
    let tgt = armor_tgt();
    let (mut exchange, _req, armor_key, nonce) = start_required(&tgt);
    let spec = base_spec(&armor_key, nonce);
    match exchange.step(&build_fast_as_rep(&spec)).expect("step") {
        StepResult::Complete => {}
        other => panic!("expected Complete, got: {other:?}"),
    }
    assert!(!exchange.fast_avail());
    assert!(!exchange.kdc_verified(), "no challenge padata");
}

#[test]
fn as_fast_response_missing_finished_fails() {
    let tgt = armor_tgt();
    let (mut exchange, _req, armor_key, nonce) = start_required(&tgt);
    // Build FAST reply with finished = None.
    let fx = fast_reply_padata(&armor_key, vec![etype_info2_pa()], nonce, None, None);
    let session_key = EncryptionKey::new(18, vec![1u8; 32]);
    let t = now();
    let enc_kdc_rep = EncKdcRepPart {
        key: session_key,
        last_req: vec![],
        nonce,
        key_expiration: None,
        flags: KerberosFlags::new(TicketFlags::INITIAL),
        authtime: t,
        starttime: Some(t),
        endtime: t + chrono::Duration::hours(1),
        renew_till: None,
        srealm: gs(REALM),
        sname: PrincipalName::new_srv_inst("krbtgt", REALM),
        caddr: None,
        encrypted_pa_data: None,
    };
    let plaintext = rasn::der::encode(&EncAsRepPart(enc_kdc_rep)).expect("enc");
    let cipher = profile18()
        .encrypt(as_key().key_bytes(), key_usage::AS_REP_ENCPART, &plaintext)
        .expect("cipher");
    let rep = KdcRep {
        pvno: 5,
        msg_type: 11,
        padata: Some(vec![fx]),
        crealm: gs(REALM),
        cname: PrincipalName::new_principal(CLIENT),
        ticket: ticket_for(PrincipalName::new_srv_inst("krbtgt", REALM)),
        enc_part: EncryptedData {
            etype: 18,
            kvno: None,
            cipher: cipher.into(),
        },
    };
    let rep_der = rasn::der::encode(&AsRep(rep)).expect("rep");
    match exchange.step(&rep_der) {
        Err(Krb5Error::ReplyValidation(_)) => {}
        other => panic!("expected ReplyValidation, got: {other:?}"),
    }
}

#[test]
fn as_fast_response_wrong_ticket_checksum_fails() {
    let tgt = armor_tgt();
    let (mut exchange, _req, armor_key, nonce) = start_required(&tgt);
    let mut spec = base_spec(&armor_key, nonce);
    // Checksum computed over a *different* ticket than the one in the reply.
    spec.cksum_ticket = ticket_for(PrincipalName::new_srv_inst("krbtgt", "OTHER.REALM"));
    match exchange.step(&build_fast_as_rep(&spec)) {
        Err(Krb5Error::ReplyValidation(_)) => {}
        other => panic!("expected ReplyValidation, got: {other:?}"),
    }
}

#[test]
fn as_fast_response_nonce_mismatch_fails() {
    let tgt = armor_tgt();
    let (mut exchange, _req, armor_key, nonce) = start_required(&tgt);
    let mut spec = base_spec(&armor_key, nonce);
    spec.nonce = nonce ^ 1;
    match exchange.step(&build_fast_as_rep(&spec)) {
        Err(_) => {}
        other => panic!("expected error, got: {other:?}"),
    }
}

#[test]
fn as_required_reply_without_fast_is_fast_required() {
    let tgt = armor_tgt();
    let (mut exchange, _req, armor_key, nonce) = start_required(&tgt);
    let mut spec = base_spec(&armor_key, nonce);
    spec.include_fx_reply = false;
    match exchange.step(&build_fast_as_rep(&spec)) {
        Err(Krb5Error::FastRequired) => {}
        other => panic!("expected FastRequired, got: {other:?}"),
    }
}

#[test]
fn as_fast_response_finished_cname_mismatch_fails() {
    let tgt = armor_tgt();
    let mut config = config_required(&tgt);
    // cname check only applies without canonicalization.
    config.kdc_options = KerberosFlags::new(KdcOptions::empty());
    let mut exchange = AsExchange::new(config, PASSWORD);
    let req = unwrap_send(exchange.step(&[]).expect("initial"));
    let armor_key = as_armor_key(&req, &tgt);
    let nonce = last_nonce(&req);

    let mut spec = base_spec(&armor_key, nonce);
    spec.finished_cname = PrincipalName::new_principal("someoneelse");
    match exchange.step(&build_fast_as_rep(&spec)) {
        Err(Krb5Error::ReplyValidation(_)) => {}
        other => panic!("expected ReplyValidation, got: {other:?}"),
    }
}

#[test]
fn as_fast_response_plain_reply_key_with_strengthen_fails() {
    let tgt = armor_tgt();
    let (mut exchange, _req, armor_key, nonce) = start_required(&tgt);
    let mut spec = base_spec(&armor_key, nonce);
    spec.strengthen = Some(EncryptionKey::new(18, rand::random::<[u8; 32]>().to_vec()));
    // KDC wrongly encrypted with the plain AS key instead of the
    // strengthened reply key.
    spec.enc_key_override = Some(as_key());
    match exchange.step(&build_fast_as_rep(&spec)) {
        Err(Krb5Error::DecryptionFailed) => {}
        other => panic!("expected DecryptionFailed, got: {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Group 5: TGS behavior (send_tgs.c:172-180,277-283; decode_kdc.c:45-85)
// ---------------------------------------------------------------------------

fn make_tgt_for_tgs() -> Credential {
    armor_tgt()
}

fn tgs_target() -> PrincipalName {
    PrincipalName::new_srv_inst("HTTP", "web.example.com")
}

/// Derive the TGS armor key from a sent TGS-REQ: subkey from the PA-TGS-REQ
/// AP-REQ authenticator, combined with the TGT session key.
fn tgs_armor_key(tgs_req_der: &[u8], tgt: &Credential) -> (EncryptionKey, Vec<u8>, TgsReq) {
    let tgs_req: TgsReq = rasn::der::decode(tgs_req_der).expect("decode TGS-REQ");
    let pa = find_pa(tgs_req.0.padata.as_deref().expect("padata"), PA_TGS_REQ).expect("PA-TGS-REQ");
    let ap_req_der: &[u8] = pa.padata_value.as_ref();
    let ap_req: ApReq = rasn::der::decode(ap_req_der).expect("AP-REQ");
    // TGS authenticator is encrypted with the session key, usage 7.
    let profile = find_etype(tgt.session_key.keytype).expect("etype");
    let plain = profile
        .decrypt(
            tgt.session_key.key_bytes(),
            key_usage::TGS_REQ_AUTH,
            ap_req.authenticator.cipher.as_ref(),
        )
        .expect("decrypt tgs authenticator");
    let auth: Authenticator = rasn::der::decode(&plain).expect("authenticator");
    let subkey = auth.subkey.expect("tgs subkey");
    let key = fx_cf2(&subkey, b"subkeyarmor", &tgt.session_key, b"ticketarmor").expect("cf2");
    (key, ap_req_der.to_vec(), tgs_req)
}

#[test]
fn tgs_first_request_is_always_fast_armored() {
    let tgt = make_tgt_for_tgs();
    let mut exchange = TgsExchange::new(
        tgt.clone(),
        tgs_target(),
        TgsOptions {
            pac_options: false,
            ..TgsOptions::default()
        },
    );
    let req_der = unwrap_tgs_send(exchange.step(&[]).expect("first step"));
    let (armor_key, ap_req_der, tgs_req) = tgs_armor_key(&req_der, &tgt);

    // Outer padata: [PA-TGS-REQ, PA-FX-FAST].
    let types = padata_types(tgs_req.0.padata.as_deref().expect("padata"));
    assert_eq!(types, vec![PA_TGS_REQ, PA_FX_FAST]);

    let armored = armored_req_of(&tgs_req.0);
    // Implicit (ccache==NULL) armor: no armor field.
    assert!(armored.armor.is_none());

    // req_checksum: armor key usage 50 over the AP-REQ DER, not the body.
    let profile = profile18();
    assert_eq!(armored.req_checksum.cksumtype, profile.checksum_type());
    profile
        .verify_checksum(
            armor_key.key_bytes(),
            key_usage::FAST_REQ_CHKSUM,
            &ap_req_der,
            armored.req_checksum.checksum.as_ref(),
        )
        .expect("req checksum over AP-REQ DER");

    // Inner fast req: empty padata, req_body == outer body.
    let inner = inner_fast_req(&tgs_req.0, &armor_key);
    assert!(inner.padata.is_empty(), "inner padata must be empty");
    assert_eq!(
        rasn::der::encode(&inner.req_body).expect("inner body"),
        rasn::der::encode(&tgs_req.0.req_body).expect("outer body"),
    );
}

/// Build a TGS-REP answering `tgs_req_der`; `enc` selects the encryption.
enum TgsEnc {
    /// Plain subkey, usage 9, no FAST reply.
    PlainSubkey,
    /// FAST reply with strengthen key; enc-part under strengthened subkey/9.
    FastStrengthenedSubkey,
    /// FAST reply with strengthen key; enc-part under strengthened session/8.
    FastStrengthenedSession,
}

fn build_tgs_rep(
    tgs_req_der: &[u8],
    tgt: &Credential,
    armor_key: &EncryptionKey,
    enc: TgsEnc,
) -> Vec<u8> {
    let tgs_req: TgsReq = rasn::der::decode(tgs_req_der).expect("decode TGS-REQ");
    let nonce = tgs_req.0.req_body.nonce;
    let pa = find_pa(tgs_req.0.padata.as_deref().expect("padata"), PA_TGS_REQ).expect("PA-TGS-REQ");
    let ap_req: ApReq = rasn::der::decode(pa.padata_value.as_ref()).expect("ap-req");
    let profile = find_etype(tgt.session_key.keytype).expect("etype");
    let plain = profile
        .decrypt(
            tgt.session_key.key_bytes(),
            key_usage::TGS_REQ_AUTH,
            ap_req.authenticator.cipher.as_ref(),
        )
        .expect("auth");
    let auth: Authenticator = rasn::der::decode(&plain).expect("auth");
    let subkey = auth.subkey.expect("subkey");

    let ticket = ticket_for(tgs_target());
    let t = now();
    let enc_part = EncKdcRepPart {
        key: EncryptionKey::new(18, rand::random::<[u8; 32]>().to_vec()),
        last_req: vec![],
        nonce,
        key_expiration: None,
        flags: KerberosFlags::new(TicketFlags::FORWARDABLE | TicketFlags::RENEWABLE),
        authtime: t,
        starttime: Some(t),
        endtime: t + chrono::Duration::hours(1),
        renew_till: None,
        srealm: gs(REALM),
        sname: tgs_target(),
        caddr: None,
        encrypted_pa_data: None,
    };
    let plaintext = rasn::der::encode(&EncTgsRepPart(enc_part)).expect("enc part");

    let (rep_padata, enc_key, usage) = match enc {
        TgsEnc::PlainSubkey => (None, subkey, key_usage::TGS_REP_ENCPART_SUBKEY),
        TgsEnc::FastStrengthenedSubkey | TgsEnc::FastStrengthenedSession => {
            let strengthen = EncryptionKey::new(18, rand::random::<[u8; 32]>().to_vec());
            let (base, usage) = if matches!(enc, TgsEnc::FastStrengthenedSubkey) {
                (subkey, key_usage::TGS_REP_ENCPART_SUBKEY)
            } else {
                (tgt.session_key.clone(), key_usage::TGS_REP_ENCPART_SESSKEY)
            };
            let reply_key = fx_cf2(&strengthen, b"strengthenkey", &base, b"replykey").expect("cf2");
            let ticket_der = rasn::der::encode(&ticket).expect("ticket");
            let finished = KrbFastFinished {
                timestamp: t,
                usec: 0,
                crealm: gs(REALM),
                cname: tgt.client.clone(),
                ticket_checksum: Checksum {
                    cksumtype: profile18().checksum_type(),
                    checksum: profile18()
                        .checksum(armor_key.key_bytes(), key_usage::FAST_FINISHED, &ticket_der)
                        .expect("cksum")
                        .into(),
                },
            };
            let fx = fast_reply_padata(
                armor_key,
                Vec::new(),
                nonce,
                Some(finished),
                Some(strengthen),
            );
            (Some(vec![fx]), reply_key, usage)
        }
    };
    let enc_profile = find_etype(enc_key.keytype).expect("etype");
    let cipher = enc_profile
        .encrypt(enc_key.key_bytes(), usage, &plaintext)
        .expect("encrypt");
    let rep = KdcRep {
        pvno: 5,
        msg_type: 13,
        padata: rep_padata,
        crealm: gs(REALM),
        cname: tgt.client.clone(),
        ticket,
        enc_part: EncryptedData {
            etype: enc_key.keytype,
            kvno: None,
            cipher: cipher.into(),
        },
    };
    rasn::der::encode(&TgsRep(rep)).expect("tgs-rep")
}

#[test]
fn tgs_reply_without_fast_still_decrypts() {
    let tgt = make_tgt_for_tgs();
    let mut exchange = TgsExchange::new(
        tgt.clone(),
        tgs_target(),
        TgsOptions {
            pac_options: false,
            ..TgsOptions::default()
        },
    );
    let req = unwrap_tgs_send(exchange.step(&[]).expect("first"));
    let (armor_key, _ap, _r) = tgs_armor_key(&req, &tgt);
    let rep = build_tgs_rep(&req, &tgt, &armor_key, TgsEnc::PlainSubkey);
    match exchange.step(&rep).expect("step") {
        TgsStepResult::Complete => {}
        other => panic!("expected Complete, got: {other:?}"),
    }
}

#[test]
fn tgs_reply_with_strengthened_subkey_decrypts() {
    let tgt = make_tgt_for_tgs();
    let mut exchange = TgsExchange::new(
        tgt.clone(),
        tgs_target(),
        TgsOptions {
            pac_options: false,
            ..TgsOptions::default()
        },
    );
    let req = unwrap_tgs_send(exchange.step(&[]).expect("first"));
    let (armor_key, _ap, _r) = tgs_armor_key(&req, &tgt);
    let rep = build_tgs_rep(&req, &tgt, &armor_key, TgsEnc::FastStrengthenedSubkey);
    match exchange.step(&rep).expect("step") {
        TgsStepResult::Complete => {}
        other => panic!("expected Complete, got: {other:?}"),
    }
}

#[test]
fn tgs_reply_with_strengthened_session_fallback_decrypts() {
    let tgt = make_tgt_for_tgs();
    let mut exchange = TgsExchange::new(
        tgt.clone(),
        tgs_target(),
        TgsOptions {
            pac_options: false,
            ..TgsOptions::default()
        },
    );
    let req = unwrap_tgs_send(exchange.step(&[]).expect("first"));
    let (armor_key, _ap, _r) = tgs_armor_key(&req, &tgt);
    let rep = build_tgs_rep(&req, &tgt, &armor_key, TgsEnc::FastStrengthenedSession);
    match exchange.step(&rep).expect("step") {
        TgsStepResult::Complete => {}
        other => panic!("expected Complete, got: {other:?}"),
    }
}

#[test]
fn tgs_fast_error_surfaces_inner_code() {
    let tgt = make_tgt_for_tgs();
    let mut exchange = TgsExchange::new(
        tgt.clone(),
        tgs_target(),
        TgsOptions {
            pac_options: false,
            canonicalize: false,
            ..TgsOptions::default()
        },
    );
    let req = unwrap_tgs_send(exchange.step(&[]).expect("first"));
    let (armor_key, _ap, tgs_req) = tgs_armor_key(&req, &tgt);
    let nonce = tgs_req.0.req_body.nonce;

    let inner = krb_error(KRB_ERR_GENERIC, now(), None);
    let reply = fast_error_reply(&armor_key, nonce, &inner, Vec::new());
    match exchange.step(&reply) {
        Err(Krb5Error::KdcError(e)) => assert_eq!(e.error_code, KRB_ERR_GENERIC),
        other => panic!("expected inner KdcError(60), got: {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Group 6/7: encrypted challenge builders (preauth_ec.c:61-143)
// ---------------------------------------------------------------------------

#[test]
fn encrypted_challenge_client_direction_roundtrips() {
    let armor_key = EncryptionKey::new(18, rand::random::<[u8; 32]>().to_vec());
    let akey = as_key();
    let ts = now();
    let pa =
        build_pa_encrypted_challenge(&armor_key, &akey, ts, Some(42)).expect("build challenge");
    assert_eq!(pa.padata_type, PA_ENCRYPTED_CHALLENGE);

    let enc: EncryptedData = rasn::der::decode(pa.padata_value.as_ref()).expect("enc-data");
    assert_eq!(enc.etype, akey.keytype);
    let ckey = fx_cf2(
        &armor_key,
        b"clientchallengearmor",
        &akey,
        b"challengelongterm",
    )
    .expect("cf2");
    let plain = profile18()
        .decrypt(
            ckey.key_bytes(),
            key_usage::ENC_CHALLENGE_CLIENT,
            enc.cipher.as_ref(),
        )
        .expect("decrypt");
    let decoded: PaEncTsEnc = rasn::der::decode(&plain).expect("ts");
    assert_eq!(decoded.pausec, Some(42));
}

#[test]
fn kdc_challenge_verifies_and_rejects_client_direction() {
    let armor_key = EncryptionKey::new(18, rand::random::<[u8; 32]>().to_vec());
    let akey = as_key();

    // Build a KDC-direction challenge by hand (usage 55, kdc derivation).
    let kkey = fx_cf2(
        &armor_key,
        b"kdcchallengearmor",
        &akey,
        b"challengelongterm",
    )
    .expect("cf2");
    let ts = rasn::der::encode(&PaEncTsEnc {
        patimestamp: now(),
        pausec: Some(1),
    })
    .expect("ts");
    let cipher = profile18()
        .encrypt(kkey.key_bytes(), key_usage::ENC_CHALLENGE_KDC, &ts)
        .expect("enc");
    let enc = EncryptedData {
        etype: kkey.keytype,
        kvno: None,
        cipher: cipher.into(),
    };
    let enc_der = rasn::der::encode(&enc).expect("enc der");
    verify_kdc_challenge(&armor_key, &akey, &enc_der).expect("kdc challenge verifies");

    // A client-direction ciphertext must not verify as a KDC challenge.
    let client_pa =
        build_pa_encrypted_challenge(&armor_key, &akey, now(), Some(1)).expect("client challenge");
    assert!(verify_kdc_challenge(&armor_key, &akey, client_pa.padata_value.as_ref()).is_err());
}
