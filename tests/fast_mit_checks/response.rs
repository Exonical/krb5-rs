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

