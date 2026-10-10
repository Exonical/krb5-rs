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

