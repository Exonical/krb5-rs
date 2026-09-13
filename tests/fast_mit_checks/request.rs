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

