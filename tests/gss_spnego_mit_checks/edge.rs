// --- 8. initiator rejection/error paths --------------------------------------------

#[test]
fn initiator_rejects() {
    let skey = random_key(18);

    // First reply REJECT without a responseToken → GSS_S_BAD_MECH
    // (init_ctx_cont:715-724).
    let cred = svc_cred(&skey, 18);
    let mut init = new_initiator(cred, GssFlags::MUTUAL, vec![MECH_KRB5.to_vec()]);
    cont(init.step(None).expect("init"));
    let rej = encode_neg_token_resp(NegState::Reject, None, None, None);
    assert_eq!(
        gss_err(init.step(Some(&rej)).unwrap_err()),
        GssError::BadMech
    );

    // supportedMech not in the initiator's list → DefectiveToken
    // (init_ctx_reselect:847-851).
    let cred = svc_cred(&skey, 18);
    let mut init = new_initiator(cred, GssFlags::MUTUAL, vec![MECH_KRB5.to_vec()]);
    cont(init.step(None).expect("init"));
    let bad = encode_neg_token_resp(NegState::RequestMic, Some(MECH_NTLMSSP), None, None);
    assert_eq!(
        gss_err(init.step(Some(&bad)).unwrap_err()),
        GssError::DefectiveToken
    );

    // ACCEPT_INCOMPLETE with no responseToken while the (mutual) mech is not
    // complete → DefectiveToken (init_ctx_nego:800-809).
    let cred = svc_cred(&skey, 18);
    let mut init = new_initiator(cred, GssFlags::MUTUAL, vec![MECH_KRB5.to_vec()]);
    cont(init.step(None).expect("init"));
    let no_tok = encode_neg_token_resp(NegState::AcceptIncomplete, Some(MECH_KRB5), None, None);
    assert_eq!(
        gss_err(init.step(Some(&no_tok)).unwrap_err()),
        GssError::DefectiveToken
    );

    // A mech token arriving after the mech completed → DefectiveToken
    // (init_ctx_nego:817-820).  Non-mutual krb5 completes on the first call.
    let cred = svc_cred(&skey, 18);
    let mut init = new_initiator(cred, GssFlags::empty(), vec![MECH_KRB5.to_vec()]);
    cont(init.step(None).expect("init"));
    let spurious = encode_neg_token_resp(
        NegState::AcceptIncomplete,
        Some(MECH_KRB5),
        Some(b"x"),
        None,
    );
    assert_eq!(
        gss_err(init.step(Some(&spurious)).unwrap_err()),
        GssError::DefectiveToken
    );

    // A MIC that fails verification → the verify error (BadSig), not a
    // DefectiveToken (process_mic:610-619 propagates gss_verify_mic's ret).
    let cred = svc_cred(&skey, 18);
    let mut init = new_initiator(cred, GssFlags::MUTUAL, vec![MECH_KRB5.to_vec()]);
    let t1 = cont(init.step(None).expect("init"));
    let (ni, _der) = decode_neg_token_init(&t1).expect("decode");
    let mechtok = ni.mech_token.expect("mechtok");
    let mut raw_acc = Krb5Acceptor::new(Box::new(OneKey(skey.clone())), Some(service()), None);
    let ap_rep = accept_complete(raw_acc.step(&mechtok).expect("raw accept")).expect("rep");
    let mut acc_ctx = raw_acc.context().expect("raw ctx");
    let bad_mic = acc_ctx.get_mic(b"not-the-mech-list").expect("mic");
    let resp = encode_neg_token_resp(
        NegState::AcceptIncomplete,
        Some(MECH_KRB5),
        Some(&ap_rep),
        Some(&bad_mic),
    );
    assert_eq!(
        gss_err(init.step(Some(&resp)).unwrap_err()),
        GssError::BadSig
    );
}

// --- 9. initiator MIC request handling ----------------------------------------------

#[test]
fn initiator_mic_when_acceptor_requests() {
    let skey = random_key(18);

    // A crafted RequestMic reselecting the same krb5 mechanism with no
    // responseToken: both OIDs are kerb mechs so this is NOT a counter-
    // proposal; no token while the mech is incomplete → DefectiveToken
    // (init_ctx_nego:800-809).
    let cred = svc_cred(&skey, 18);
    let mut init = new_initiator(cred, GssFlags::MUTUAL, vec![MECH_KRB5.to_vec()]);
    cont(init.step(None).expect("init"));
    let req_mic = encode_neg_token_resp(NegState::RequestMic, Some(MECH_KRB5), None, None);
    assert_eq!(
        gss_err(init.step(Some(&req_mic)).unwrap_err()),
        GssError::DefectiveToken
    );

    // Positive case: mech completes (mutual), acceptor sends
    // ACCEPT_INCOMPLETE + AP-REP + acceptor MIC.  The initiator verifies the
    // MIC, sends its own, and completes with a token (handle_mic:573-585:
    // mic_out present → CONT_TOKEN_SEND; negState ACCEPT_COMPLETE → COMPLETE).
    let cred = svc_cred(&skey, 18);
    let mut init = new_initiator(cred, GssFlags::MUTUAL, vec![MECH_KRB5.to_vec()]);
    let t1 = cont(init.step(None).expect("init"));
    let (ni, der) = decode_neg_token_init(&t1).expect("decode");
    let mut raw_acc = Krb5Acceptor::new(Box::new(OneKey(skey.clone())), Some(service()), None);
    let ap_rep = accept_complete(
        raw_acc
            .step(ni.mech_token.as_deref().expect("mt"))
            .expect("accept"),
    )
    .expect("rep");
    let mut acc_ctx = raw_acc.context().expect("acc ctx");
    let acc_mic = acc_ctx.get_mic(&der).expect("acc mic");

    let resp = encode_neg_token_resp(
        NegState::AcceptIncomplete,
        None,
        Some(&ap_rep),
        Some(&acc_mic),
    );
    let out = init_complete(init.step(Some(&resp)).expect("init step"))
        .expect("initiator must still send its MIC");
    let nr = decode_neg_token_resp(&out).expect("decode initiator resp");
    assert_eq!(nr.neg_state, Some(NegState::AcceptCompleted));
    assert!(nr.supported_mech.is_none());
    assert!(nr.response_token.is_none());
    let init_mic = nr.mech_list_mic.expect("initiator MIC");
    acc_ctx
        .verify_mic(&der, &init_mic)
        .expect("acceptor verifies initiator MIC");

    // A second MIC after one was already received → DefectiveToken
    // (handle_mic:551-555).
    let second_mic = acc_ctx.get_mic(&der).expect("mic2");
    let resp2 = encode_neg_token_resp(NegState::AcceptCompleted, None, None, Some(&second_mic));
    assert_eq!(
        gss_err(init.step(Some(&resp2)).unwrap_err()),
        GssError::DefectiveToken
    );
}

// --- 10. NegHints -------------------------------------------------------------------

#[test]
fn neg_hints() {
    let skey = random_key(18);
    let mut acc = new_acceptor(&skey, vec![MECH_KRB5.to_vec()]);
    let tok = accept_continue(acc.step(b"").expect("hints"));

    // The token is a framed NegTokenInit advertising our mech list, with the
    // [3] mechListMIC slot carrying a SEQUENCE-tagged NegHints blob
    // (make_NegHints:1172-1204 + make_spnego_tokenInit_msg negHintsCompat
    // at :3688-3693): 30 28 a0 26 1b 24 "not_defined_in_RFC4178@please_ignore".
    let mut hint = vec![0x30, 0x28, 0xa0, 0x26, 0x1b, 0x24];
    hint.extend_from_slice(HINT_NAME);
    assert!(
        tok.windows(hint.len()).any(|w| w == hint.as_slice()),
        "NegHints blob not found in token"
    );
    // And the advertised mechTypes blob is present verbatim.
    let mt = mech_types_der(&[MECH_KRB5]);
    assert!(tok.windows(mt.len()).any(|w| w == mt.as_slice()));

    // A normal NegTokenInit then proceeds as usual (the hints context is
    // discarded — internal_mech was never set).
    let cred = svc_cred(&skey, 18);
    let mut init = new_initiator(cred, GssFlags::empty(), vec![MECH_KRB5.to_vec()]);
    let t1 = cont(init.step(None).expect("init"));
    let resp = accept_complete(acc.step(&t1).expect("accept")).expect("resp");
    let nr = decode_neg_token_resp(&resp).expect("decode");
    assert_eq!(nr.neg_state, Some(NegState::AcceptCompleted));
    assert!(init_complete(init.step(Some(&resp)).expect("fin")).is_none());
}
