//! KDC-side FAST (RFC 6113): fast_util.c, kdc_preauth_ec.c,
//! kdc_util.c `kdc_handle_protected_negotiation`.

use super::*;
use krb5_rs::crypto::fx_cf2;
use krb5_rs::keytab::{KeytabEntry, MemoryKeytab};
use krb5_rs::protocol::ap::{ApReqOptions, AuthContext};
use krb5_rs::protocol::fast::{build_pa_encrypted_challenge, FastMode};
use rasn::types::BitString;

const PA_FX_FAST: i32 = 136;
const PA_FX_ERROR: i32 = 137;
const PA_FX_COOKIE: i32 = 133;
const PA_ENC_TIMESTAMP: i32 = 2;
const PA_ETYPE_INFO2: i32 = 19;
const PA_ENCRYPTED_CHALLENGE: i32 = 138;

fn types(padata: &[PaData]) -> Vec<i32> {
    padata.iter().map(|p| p.padata_type).collect()
}

/// Armor material for a hand-built FAST request.
struct Armor {
    key: EncryptionKey,
    subkey: Option<EncryptionKey>,
    armor: KrbFastArmor,
}

/// AP-REQ armor from `tgt` (RFC 6113 §5.4.1), optionally with a subkey.
fn ap_armor(tgt: &Credential, use_subkey: bool) -> Armor {
    let mut ctx = AuthContext::new();
    let opts = ApReqOptions {
        use_subkey,
        ..ApReqOptions::default()
    };
    let der = ctx.mk_req(&opts, None, tgt).expect("armor AP-REQ");
    let key = match ctx.send_subkey() {
        Some(sub) => fx_cf2(sub, b"subkeyarmor", &tgt.session_key, b"ticketarmor").expect("cf2"),
        None => tgt.session_key.clone(),
    };
    Armor {
        key,
        subkey: ctx.send_subkey().cloned(),
        armor: KrbFastArmor {
            armor_type: 1,
            armor_value: OctetString::from(der),
        },
    }
}

struct FastAs {
    name: &'static str,
    options: KdcOptions,
    inner_padata: Vec<PaData>,
    fast_options: Vec<u8>,
    armor_type: Option<i32>,
    flip_checksum: bool,
}

impl FastAs {
    fn new(name: &'static str) -> Self {
        Self {
            name,
            options: KdcOptions::FORWARDABLE,
            inner_padata: Vec::new(),
            fast_options: Vec::new(),
            armor_type: Some(1),
            flip_checksum: false,
        }
    }
}

fn as_body(name: &str) -> KdcReqBody {
    KdcReqBody {
        kdc_options: KerberosFlags::new(KdcOptions::FORWARDABLE),
        cname: Some(PrincipalName::new_principal(name)),
        realm: gs(REALM),
        sname: Some(krbtgt()),
        from: None,
        till: at(3600),
        rtime: None,
        nonce: 4242,
        etype: vec![18, 17],
        addresses: None,
        enc_authorization_data: None,
        additional_tickets: None,
    }
}

/// Hand-built armored AS-REQ (outer body == inner body, as our client
/// sends it); `armor` supplies the armor key and the armor field.
fn build_fast_as(armor: &Armor, spec: FastAs) -> Vec<u8> {
    let mut body = as_body(spec.name);
    body.kdc_options = KerberosFlags::new(spec.options);
    let profile = find_etype(armor.key.keytype).expect("etype");
    let fast_req = KrbFastReq {
        fast_options: BitString::from_slice(&spec.fast_options),
        padata: spec.inner_padata,
        req_body: body.clone(),
    };
    let cipher = profile
        .encrypt(
            armor.key.key_bytes(),
            key_usage::FAST_ENC,
            &rasn::der::encode(&fast_req).expect("encode"),
        )
        .expect("encrypt");
    let mut checksum = profile
        .checksum(
            armor.key.key_bytes(),
            key_usage::FAST_REQ_CHKSUM,
            &rasn::der::encode(&body).expect("encode body"),
        )
        .expect("checksum");
    if spec.flip_checksum {
        checksum[0] ^= 0xFF;
    }
    let armor_field = spec.armor_type.map(|t| KrbFastArmor {
        armor_type: t,
        armor_value: armor.armor.armor_value.clone(),
    });
    let pa = PaFxFastRequest::ArmoredData(KrbFastArmoredReq {
        armor: armor_field,
        req_checksum: Checksum {
            cksumtype: profile.checksum_type(),
            checksum: OctetString::from(checksum),
        },
        enc_fast_req: EncryptedData {
            etype: armor.key.keytype,
            kvno: None,
            cipher: OctetString::from(cipher),
        },
    });
    rasn::der::encode(&AsReq(KdcReq {
        pvno: 5,
        msg_type: 10,
        padata: Some(vec![PaData {
            padata_type: PA_FX_FAST,
            padata_value: OctetString::from(rasn::der::encode(&pa).expect("encode")),
        }]),
        req_body: body,
    }))
    .expect("encode AS-REQ")
}

fn open_fast_pa(pa: &PaData, armor_key: &EncryptionKey) -> KrbFastResponse {
    assert_eq!(pa.padata_type, PA_FX_FAST);
    let PaFxFastReply::ArmoredData(rep) =
        rasn::der::decode(pa.padata_value.as_ref()).expect("PA-FX-FAST-REPLY");
    let plain = find_etype(armor_key.keytype)
        .expect("etype")
        .decrypt(
            armor_key.key_bytes(),
            key_usage::FAST_REP,
            rep.enc_fast_rep.cipher.as_ref(),
        )
        .expect("decrypt KrbFastResponse");
    rasn::der::decode(&plain).expect("KrbFastResponse")
}

/// Outer KRB-ERROR, its armored response and the inner FX-ERROR.
fn open_fast_error(
    reply: &[u8],
    armor_key: &EncryptionKey,
) -> (KrbErrorMsg, KrbFastResponse, KrbErrorMsg) {
    let outer = krb_error(reply);
    let pas = method_data(&outer);
    assert_eq!(
        types(&pas),
        vec![PA_FX_FAST],
        "outer e-data is only PA-FX-FAST"
    );
    let resp = open_fast_pa(&pas[0], armor_key);
    let fx = resp
        .padata
        .iter()
        .find(|p| p.padata_type == PA_FX_ERROR)
        .expect("FX-ERROR");
    let inner: KrbErrorMsg = rasn::der::decode(fx.padata_value.as_ref()).expect("inner KRB-ERROR");
    (outer, resp, inner)
}

fn user_as_key() -> EncryptionKey {
    EncryptionKey::new(
        18,
        find_etype(18)
            .expect("etype")
            .string_to_key(
                PASSWORD.as_bytes(),
                format!("{REALM}{USER}").as_bytes(),
                None,
            )
            .expect("s2k")
            .to_vec(),
    )
}

fn armored_config(tgt: &Credential) -> AsExchangeConfig {
    let mut config = as_config(USER);
    config.fast = FastMode::Required(tgt.clone());
    config
}

#[test]
fn as_exchange_fast_required_completes_with_armored_replies() {
    let f = fixture();
    let tgt = get_tgt(&f);
    let (exchange, run) = run_as_keep(&f.kdc, armored_config(&tgt), PASSWORD);
    let cred = run.result.expect("FAST AS exchange");

    assert_eq!(run.replies.len(), 2);
    let first = krb_error(&run.replies[0]);
    assert_eq!(first.error_code, 25);
    assert_eq!(types(&method_data(&first)), vec![PA_FX_FAST]);
    let rep: AsRep = rasn::der::decode(&run.replies[1]).expect("AS-REP");
    assert_eq!(
        types(rep.0.padata.as_deref().expect("padata")),
        vec![PA_FX_FAST]
    );

    assert!(cred
        .flags
        .contains(TicketFlags::PRE_AUTHENT | TicketFlags::INITIAL));
    assert!(cred.flags.contains(TicketFlags::ENC_PA_REP));
    assert!(exchange.kdc_verified(), "client verified the KDC challenge");
    assert!(exchange.fast_avail());
    let part = decrypt_ticket(&f.tgs_key, &cred.ticket).expect("ticket");
    assert_eq!(part.cname, user());
}

#[test]
fn as_req_fast_first_error_hints_inner_list_in_mit_order() {
    let f = fixture();
    let tgt = get_tgt(&f);
    let armor = ap_armor(&tgt, true);
    let reply = f.kdc.handle(&build_fast_as(&armor, FastAs::new(USER)));
    let (outer, resp, inner) = open_fast_error(&reply, &armor.key);
    assert_eq!(outer.error_code, 25);
    assert_eq!(inner.error_code, 25);
    assert!(inner.e_data.is_none());
    assert_eq!(resp.nonce, 4242);
    assert!(resp.strengthen_key.is_none() && resp.finished.is_none());
    assert_eq!(
        types(&resp.padata),
        vec![
            PA_FX_FAST,
            PA_ETYPE_INFO2,
            PA_ENCRYPTED_CHALLENGE,
            PA_FX_COOKIE,
            PA_FX_ERROR
        ]
    );
    assert!(!types(&resp.padata).contains(&PA_ENC_TIMESTAMP));
    assert_eq!(resp.padata[3].padata_value.as_ref(), b"MIT");
}

#[test]
fn as_exchange_fast_opportunistic_upgrades_after_unarmored_preauth_required() {
    let f = fixture();
    let tgt = get_tgt(&f);
    let mut config = as_config(USER);
    config.fast = FastMode::Opportunistic(tgt.clone());
    let (exchange, run) = run_as_keep(&f.kdc, config, PASSWORD);
    let cred = run.result.expect("opportunistic FAST exchange");

    let first = krb_error(&run.replies[0]);
    assert_eq!(first.error_code, 25);
    assert_eq!(
        types(&method_data(&first)),
        vec![PA_FX_FAST, PA_ETYPE_INFO2, PA_ENC_TIMESTAMP, PA_FX_COOKIE]
    );
    let rep: AsRep = rasn::der::decode(run.replies.last().expect("reply")).expect("AS-REP");
    assert_eq!(
        types(rep.0.padata.as_deref().expect("padata")),
        vec![PA_FX_FAST]
    );
    assert!(exchange.kdc_verified());
    assert!(cred.flags.contains(TicketFlags::PRE_AUTHENT));
}

#[test]
fn as_exchange_without_fast_but_enc_pa_rep_reports_fast_available() {
    let f = fixture();
    let (exchange, run) = run_as_keep(&f.kdc, as_config(USER), PASSWORD);
    run.result.expect("AS exchange");
    assert!(exchange.fast_avail());
    assert!(!exchange.kdc_verified());
}

#[test]
fn as_exchange_fast_wrong_password_surfaces_preauth_failed() {
    let f = fixture();
    let tgt = get_tgt(&f);
    let run = run_as(&f.kdc, armored_config(&tgt), "wrong-password");
    assert_eq!(kdc_code(&run.result.expect_err("must fail")), 24);
}

#[test]
fn as_req_fast_wrong_challenge_error_is_armored_with_hints() {
    let f = fixture();
    let tgt = get_tgt(&f);
    let armor = ap_armor(&tgt, true);
    let bad_key = EncryptionKey::new(18, vec![1; 32]);
    let pa = build_pa_encrypted_challenge(&armor.key, &bad_key, at(0), Some(0)).expect("challenge");
    let mut spec = FastAs::new(USER);
    spec.inner_padata = vec![pa];
    let (outer, resp, inner) =
        open_fast_error(&f.kdc.handle(&build_fast_as(&armor, spec)), &armor.key);
    assert_eq!((outer.error_code, inner.error_code), (24, 24));
    assert!(types(&resp.padata).contains(&PA_ENCRYPTED_CHALLENGE));
}

#[test]
fn as_req_fast_encrypted_timestamp_inside_tunnel_is_accepted() {
    let f = fixture();
    let tgt = get_tgt(&f);
    let armor = ap_armor(&tgt, true);
    let mut spec = FastAs::new(USER);
    spec.inner_padata = vec![enc_timestamp_padata(USER, PASSWORD, at(0))];
    let reply = f.kdc.handle(&build_fast_as(&armor, spec));
    let rep: AsRep = rasn::der::decode(&reply).expect("AS-REP");
    let padata = rep.0.padata.expect("padata");
    assert_eq!(types(&padata), vec![PA_FX_FAST]);
    let resp = open_fast_pa(&padata[0], &armor.key);
    let strengthen = resp.strengthen_key.expect("strengthen key");
    let reply_key =
        fx_cf2(&strengthen, b"strengthenkey", &user_as_key(), b"replykey").expect("cf2");
    let plain = find_etype(18)
        .expect("etype")
        .decrypt(
            reply_key.key_bytes(),
            key_usage::AS_REP_ENCPART,
            rep.0.enc_part.cipher.as_ref(),
        )
        .expect("decrypt enc-part with strengthened key");
    let enc: EncAsRepPart = rasn::der::decode(&plain).expect("EncASRepPart");
    assert!(enc.0.flags.contains(TicketFlags::PRE_AUTHENT));
    assert_eq!(enc.0.nonce, 4242);
    let finished = resp.finished.expect("finished");
    assert_eq!(finished.cname, user());
    let ticket_der = rasn::der::encode(&rep.0.ticket).expect("encode ticket");
    find_etype(18)
        .expect("etype")
        .verify_checksum(
            armor.key.key_bytes(),
            key_usage::FAST_FINISHED,
            &ticket_der,
            finished.ticket_checksum.checksum.as_ref(),
        )
        .expect("ticket checksum");
}

#[test]
fn as_req_encrypted_challenge_without_fast_is_preauth_failed_with_enc_timestamp_hint() {
    let f = fixture();
    let pa = build_pa_encrypted_challenge(
        &EncryptionKey::new(18, vec![2; 32]),
        &user_as_key(),
        at(0),
        Some(0),
    )
    .expect("challenge");
    let req = build_as_req(USER, KdcOptions::FORWARDABLE, vec![18], vec![pa]);
    let err = krb_error(&f.kdc.handle(&req));
    assert_eq!(err.error_code, 24);
    assert_eq!(
        types(&method_data(&err)),
        vec![PA_FX_FAST, PA_ETYPE_INFO2, PA_ENC_TIMESTAMP, PA_FX_COOKIE]
    );
}

#[test]
fn as_req_fast_checksum_mismatch_returns_modified_in_armored_error() {
    let f = fixture();
    let tgt = get_tgt(&f);
    let armor = ap_armor(&tgt, true);
    let mut spec = FastAs::new(USER);
    spec.flip_checksum = true;
    let (outer, _, inner) =
        open_fast_error(&f.kdc.handle(&build_fast_as(&armor, spec)), &armor.key);
    assert_eq!((outer.error_code, inner.error_code), (41, 41));
}

#[test]
fn as_req_fast_armor_ticket_for_non_krbtgt_service_returns_server_nomatch_unarmored() {
    let f = fixture();
    let tgt = get_tgt(&f);
    let svc = run_tgs(&f.kdc, &tgt, service(), TgsOptions::default())
        .result
        .expect("service ticket");
    let armor = ap_armor(&svc, true);
    let err = krb_error(&f.kdc.handle(&build_fast_as(&armor, FastAs::new(USER))));
    assert_eq!(err.error_code, 26);
    assert!(err.e_data.is_none());
}

#[test]
fn as_req_fast_armor_ap_req_without_subkey_returns_policy() {
    let f = fixture();
    let tgt = get_tgt(&f);
    let armor = ap_armor(&tgt, false);
    let err = krb_error(&f.kdc.handle(&build_fast_as(&armor, FastAs::new(USER))));
    assert_eq!(err.error_code, 12);
}

#[test]
fn as_req_fast_unknown_armor_type_returns_preauth_failed() {
    let f = fixture();
    let tgt = get_tgt(&f);
    let armor = ap_armor(&tgt, true);
    let mut spec = FastAs::new(USER);
    spec.armor_type = Some(2);
    assert_eq!(
        krb_error(&f.kdc.handle(&build_fast_as(&armor, spec))).error_code,
        24
    );
}

#[test]
fn as_req_fast_without_armor_returns_preauth_failed() {
    let f = fixture();
    let tgt = get_tgt(&f);
    let armor = ap_armor(&tgt, true);
    let mut spec = FastAs::new(USER);
    spec.armor_type = None;
    assert_eq!(
        krb_error(&f.kdc.handle(&build_fast_as(&armor, spec))).error_code,
        24
    );
}

#[test]
fn as_req_fast_critical_option_bit_returns_unknown_critical_option_armored() {
    let f = fixture();
    let tgt = get_tgt(&f);
    let armor = ap_armor(&tgt, true);
    let mut spec = FastAs::new(USER);
    spec.fast_options = vec![0x80, 0, 0, 0];
    let (outer, _, inner) =
        open_fast_error(&f.kdc.handle(&build_fast_as(&armor, spec)), &armor.key);
    assert_eq!((outer.error_code, inner.error_code), (93, 93));
}

#[test]
fn as_req_fast_hide_client_names_anonymizes_outer_error_but_not_inner() {
    let f = fixture();
    let tgt = get_tgt(&f);
    let armor = ap_armor(&tgt, true);
    let mut spec = FastAs::new(USER);
    spec.fast_options = vec![0x40, 0, 0, 0];
    let (outer, _, inner) =
        open_fast_error(&f.kdc.handle(&build_fast_as(&armor, spec)), &armor.key);
    let anon = outer.cname.expect("outer cname");
    assert_eq!(anon.name_type, 11);
    assert_eq!(anon.to_string(), "WELLKNOWN/ANONYMOUS");
    assert_eq!(
        outer.crealm.as_ref().map(|r| r.as_bytes().to_vec()),
        Some(b"WELLKNOWN:ANONYMOUS".to_vec())
    );
    assert_eq!(inner.cname, Some(user()));
    assert_eq!(
        inner.crealm.as_ref().map(|r| r.as_bytes().to_vec()),
        Some(REALM.as_bytes().to_vec())
    );
}

#[test]
fn as_req_fast_hide_client_names_anonymizes_outer_reply_and_keeps_finished_name() {
    let f = fixture();
    let tgt = get_tgt(&f);
    let armor = ap_armor(&tgt, true);
    let mut spec = FastAs::new(USER);
    spec.fast_options = vec![0x40, 0, 0, 0];
    spec.inner_padata = vec![enc_timestamp_padata(USER, PASSWORD, at(0))];
    let reply = f.kdc.handle(&build_fast_as(&armor, spec));
    let rep: AsRep = rasn::der::decode(&reply).expect("AS-REP");
    assert_eq!(rep.0.cname.name_type, 11);
    assert_eq!(rep.0.crealm.as_bytes(), b"WELLKNOWN:ANONYMOUS");
    let resp = open_fast_pa(&rep.0.padata.expect("padata")[0], &armor.key);
    let finished = resp.finished.expect("finished");
    assert_eq!(finished.cname, user());
    assert_eq!(finished.crealm.as_bytes(), REALM.as_bytes());
}

#[test]
fn tgs_exchange_fast_reply_is_armored_and_credential_authenticates() {
    let f = fixture();
    let tgt = get_tgt(&f);
    let run = run_tgs(&f.kdc, &tgt, service(), TgsOptions::default());
    let cred = run.result.expect("TGS exchange");

    let rep: TgsRep = rasn::der::decode(run.replies.last().expect("reply")).expect("TGS-REP");
    assert_eq!(
        types(rep.0.padata.as_deref().expect("padata")),
        vec![PA_FX_FAST]
    );

    let mut client = AuthContext::new();
    let ap_req = client
        .mk_req(&ApReqOptions::default(), None, &cred)
        .expect("mk_req");
    let keytab = MemoryKeytab::from_entries(vec![KeytabEntry {
        principal: service(),
        realm: REALM.to_string(),
        timestamp: 0,
        kvno: 1,
        key: f.service_key.clone(),
    }]);
    let rd = AuthContext::new()
        .rd_req(&ap_req, None, &keytab)
        .expect("rd_req");
    assert_eq!(rd.ticket.cname, user());
}

#[test]
fn tgs_exchange_fast_unknown_service_surfaces_inner_error_code() {
    let f = fixture();
    let tgt = get_tgt(&f);
    let run = run_tgs(
        &f.kdc,
        &tgt,
        PrincipalName::new_srv_hst("HTTP", "missing.test.realm"),
        TgsOptions::default(),
    );
    assert_eq!(kdc_code(&run.result.expect_err("must fail")), 7);
    let outer = krb_error(run.replies.last().expect("reply"));
    assert_eq!(outer.error_code, 7);
    assert_eq!(types(&method_data(&outer)), vec![PA_FX_FAST]);
    assert_eq!(outer.cname, Some(user()));
}

#[test]
fn tgs_req_fast_ap_request_armor_with_subkey_returns_preauth_failed() {
    let f = fixture();
    let tgt = get_tgt(&f);
    let armor = ap_armor(&tgt, true);
    let (req, _) = build_tgs_req(&tgt, TgsReqSpec::new(service(), KdcOptions::empty()));
    let mut decoded: TgsReq = rasn::der::decode(&req).expect("decode");
    let as_wrapper = rasn::der::decode::<AsReq>(&build_fast_as(&armor, FastAs::new(USER)))
        .expect("decode FAST AS");
    let fx = as_wrapper
        .0
        .padata
        .expect("padata")
        .into_iter()
        .next()
        .expect("PA-FX-FAST");
    decoded.0.padata.as_mut().expect("padata").push(fx);
    let der = rasn::der::encode(&decoded).expect("encode");
    assert_eq!(krb_error(&f.kdc.handle(&der)).error_code, 24);
}

/// Replace the outer client of a KDC-REP with the anonymous principal, as a
/// KDC honouring FAST hide-client-names would (the outer cname/crealm are
/// not integrity-protected; the real client is in the encrypted finished).
fn anonymize_outer_client(rep: &mut KdcRep) {
    rep.cname = PrincipalName {
        name_type: 11,
        name_string: vec![gs("WELLKNOWN"), gs("ANONYMOUS")],
    };
    rep.crealm = gs("WELLKNOWN:ANONYMOUS");
}

#[test]
fn fast_hide_client_reply_finished_restores_real_client_realm() {
    use krb5_rs::protocol::fast::FastState;
    let f = fixture();
    let tgt = get_tgt(&f);
    let armor = ap_armor(&tgt, true);
    let mut spec = FastAs::new(USER);
    spec.fast_options = vec![0x40, 0, 0, 0];
    spec.inner_padata = vec![enc_timestamp_padata(USER, PASSWORD, at(0))];
    let reply = f.kdc.handle(&build_fast_as(&armor, spec));
    let rep: AsRep = rasn::der::decode(&reply).expect("AS-REP");
    assert_eq!(rep.0.crealm.as_bytes(), b"WELLKNOWN:ANONYMOUS");

    let mut state = FastState::new();
    state
        .tgs_armor(armor.subkey.as_ref().expect("subkey"), &tgt.session_key)
        .expect("armor key");
    assert_eq!(
        state.armor_key().expect("armor key").key_bytes(),
        armor.key.key_bytes()
    );
    // prep_req records the request nonce the response must echo.
    let probe = KdcReq {
        pvno: 5,
        msg_type: 10,
        padata: None,
        req_body: as_body(USER),
    };
    state
        .prep_req(&probe, &[], krb5_rs::protocol::fast::FastMsgType::As)
        .expect("prep_req");
    let out = state
        .process_response(rep.0.padata.as_deref(), &rep.0.ticket)
        .expect("process_response")
        .expect("armored");
    assert_eq!(out.crealm.as_bytes(), REALM.as_bytes());
    assert_eq!(out.client, user());
}

#[test]
fn as_exchange_fast_anonymous_outer_client_completes_with_real_client() {
    let f = fixture();
    let tgt = get_tgt(&f);
    let mut exchange = AsExchange::new(armored_config(&tgt), PASSWORD);
    let mut reply = Vec::new();
    while let StepResult::SendToKdc { data, .. } | StepResult::RetryTcp { data, .. } =
        exchange.step(&reply).expect("step")
    {
        reply = f.kdc.handle(&data);
        if let Ok(mut rep) = rasn::der::decode::<AsRep>(&reply) {
            anonymize_outer_client(&mut rep.0);
            reply = rasn::der::encode(&rep).expect("encode");
        }
    }
    let cred = exchange.credential().expect("credential");
    assert_eq!(cred.client, user());
    assert_eq!(cred.crealm, REALM);
}

#[test]
fn tgs_exchange_fast_anonymous_outer_client_completes_with_real_client() {
    let f = fixture();
    let tgt = get_tgt(&f);
    let mut exchange = TgsExchange::new(tgt, service(), TgsOptions::default());
    let mut reply = Vec::new();
    while let TgsStepResult::SendToKdc { data, .. } | TgsStepResult::RetryTcp { data, .. } =
        exchange.step(&reply).expect("step")
    {
        reply = f.kdc.handle(&data);
        if let Ok(mut rep) = rasn::der::decode::<TgsRep>(&reply) {
            anonymize_outer_client(&mut rep.0);
            reply = rasn::der::encode(&rep).expect("encode");
        }
    }
    let cred = exchange.credential().expect("credential");
    assert_eq!(cred.client, user());
    assert_eq!(cred.crealm, REALM);
}
