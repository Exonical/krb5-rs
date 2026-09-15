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
use rasn::types::{BitString, OctetString};

#[path = "../common/mod.rs"]
mod common;
use common::fixtures::{gs, now, unwrap_send, unwrap_tgs_send};
use common::krb_error::krb_error_msg;

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
    krb_error_msg(code, REALM, Some(stime), e_data)
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

include!("armor.rs");
include!("request.rs");
include!("error.rs");
include!("response.rs");
include!("tgs.rs");
include!("challenge.rs");
