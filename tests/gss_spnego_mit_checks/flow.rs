// --- 4. initiator first token ----------------------------------------------------

#[test]
fn init_first_token_is_neg_token_init_with_optimistic_krb5() {
    let skey = random_key(18);
    let cred = svc_cred(&skey, 18);
    // A non-krb5 OID listed first is dropped (init_ctx_call_init:940-960
    // fallback drops the failed first mech and re-encodes DER_mechTypes).
    let mut init = new_initiator(
        cred,
        GssFlags::empty(),
        vec![MECH_NTLMSSP.to_vec(), MECH_KRB5.to_vec()],
    );
    let tok = cont(init.step(None).expect("step"));
    let (ni, der) = decode_neg_token_init(&tok).expect("decode");
    assert_eq!(ni.mech_types, vec![MECH_KRB5.to_vec()]);
    assert_eq!(der, mech_types_der(&[MECH_KRB5]));
    let mechtok = ni.mech_token.expect("mechToken");
    let (mech, body) = parse_token_header(&mechtok).expect("inner framing");
    assert_eq!(mech, MECH_KRB5);
    assert_eq!(&body[..2], &[0x01, 0x00]); // TOK_ID_AP_REQ
                                           // Even with a completed (non-mutual) inner mech, SPNEGO returns
                                           // Continue because negState != ACCEPT_COMPLETE (:1095-1098).
    assert!(init.context().is_err());
}

#[test]
fn init_first_token_mutual_returns_continue() {
    let skey = random_key(18);
    let cred = svc_cred(&skey, 18);
    let mut init = new_initiator(cred, GssFlags::MUTUAL, vec![MECH_KRB5.to_vec()]);
    cont(init.step(None).expect("step"));
    assert!(init.context().is_err());
}

// --- 5. acceptor basic flow -------------------------------------------------------

#[test]
fn spnego_roundtrip_mutual() {
    let skey = random_key(18);
    let cred = svc_cred(&skey, 18);
    let mut init = new_initiator(
        cred,
        GssFlags::MUTUAL | GssFlags::REPLAY | GssFlags::SEQUENCE,
        vec![MECH_KRB5.to_vec()],
    );
    let t1 = cont(init.step(None).expect("init"));

    let mut acc = new_acceptor(&skey, vec![MECH_KRB5.to_vec()]);
    let resp = accept_complete(acc.step(&t1).expect("accept")).expect("resp token");
    let nr = decode_neg_token_resp(&resp).expect("decode resp");
    assert_eq!(nr.neg_state, Some(NegState::AcceptCompleted));
    assert_eq!(nr.supported_mech.as_deref(), Some(MECH_KRB5));
    // First mech in the initiator list → ACCEPT_INCOMPLETE → no MIC required;
    // mutual krb5 completes and returns the AP-REP.
    assert!(nr.response_token.is_some());
    assert!(nr.mech_list_mic.is_none());
    let (mech, body) =
        parse_token_header(nr.response_token.as_deref().expect("tok")).expect("ap-rep framing");
    assert_eq!(mech, MECH_KRB5);
    assert_eq!(&body[..2], &[0x02, 0x00]);

    assert!(init_complete(init.step(Some(&resp)).expect("step2")).is_none());
    assert_eq!(init.negotiated_mech(), Some(MECH_KRB5));
    assert_eq!(acc.negotiated_mech(), Some(MECH_KRB5));

    let mut ic = init.context().expect("init ctx");
    let mut ac = acc.context().expect("acc ctx");
    assert!(!ic.flags().contains(GssFlags::PROT_READY));
    assert!(!ac.flags().contains(GssFlags::PROT_READY));
    let w = ic.wrap(true, b"hello").expect("wrap");
    assert_eq!(ac.unwrap(&w).expect("unwrap").data, b"hello");
    let w2 = ac.wrap(true, b"world").expect("wrap");
    assert_eq!(ic.unwrap(&w2).expect("unwrap").data, b"world");
}

#[test]
fn spnego_roundtrip_non_mutual() {
    let skey = random_key(18);
    let cred = svc_cred(&skey, 18);
    let mut init = new_initiator(
        cred,
        GssFlags::REPLAY | GssFlags::SEQUENCE,
        vec![MECH_KRB5.to_vec()],
    );
    let t1 = cont(init.step(None).expect("init"));

    let mut acc = new_acceptor(&skey, vec![MECH_KRB5.to_vec()]);
    let resp = accept_complete(acc.step(&t1).expect("accept")).expect("resp token");
    let nr = decode_neg_token_resp(&resp).expect("decode resp");
    assert_eq!(nr.neg_state, Some(NegState::AcceptCompleted));
    assert_eq!(nr.supported_mech.as_deref(), Some(MECH_KRB5));
    assert!(nr.response_token.is_none());
    assert!(nr.mech_list_mic.is_none());

    assert!(init_complete(init.step(Some(&resp)).expect("step2")).is_none());
    let ic = init.context().expect("init ctx");
    assert!(!ic.flags().contains(GssFlags::MUTUAL));
}

// --- 6. MIC exchange (REQUEST_MIC path) -------------------------------------------

#[test]
fn request_mic_path() {
    let skey = random_key(18);
    // Initiator advertises [NTLMSSP, KRB5]: the acceptor picks index 1 →
    // REQUEST_MIC (negotiate_mech:3570-3572), and the mechToken is NOT fed
    // to the mech (spnego_gss_accept_sec_context:1663).
    let der = mech_types_der(&[MECH_NTLMSSP, MECH_KRB5]);
    let ap_req1 = raw_ap_req(&skey, GssFlags::empty());
    let t1 = encode_neg_token_init(&der, Some(&ap_req1), None, false);

    let mut acc = new_acceptor(&skey, vec![MECH_KRB5.to_vec()]);
    let r1 = accept_continue(acc.step(&t1).expect("accept1"));
    let nr1 = decode_neg_token_resp(&r1).expect("decode r1");
    assert_eq!(nr1.neg_state, Some(NegState::RequestMic));
    assert_eq!(nr1.supported_mech.as_deref(), Some(MECH_KRB5));
    assert!(nr1.response_token.is_none());
    assert!(nr1.mech_list_mic.is_none());
    // The mechToken is NOT consumed on the REQUEST_MIC path
    // (spnego_gss_accept_sec_context:1663) — proven implicitly when the
    // next step still accepts a fresh AP-REQ (context() takes self, so it
    // cannot be probed mid-exchange).

    // The initiator re-sends a real (mutual) AP-REQ in a NegTokenResp.
    let cred2 = svc_cred(&skey, 18);
    let mut init_b = Krb5Initiator::new(cred2, None, GssFlags::MUTUAL, None).expect("init_b");
    let ap_req2 = cont(init_b.step(None).expect("init_b step"));
    let t2 = encode_neg_token_resp(NegState::AcceptIncomplete, None, Some(&ap_req2), None);

    let r2 = accept_continue(acc.step(&t2).expect("accept2"));
    let nr2 = decode_neg_token_resp(&r2).expect("decode r2");
    assert_eq!(nr2.neg_state, Some(NegState::AcceptIncomplete));
    // supportedMech is only sent with INIT_TOKEN_SEND (first reply).
    assert!(nr2.supported_mech.is_none());
    let ap_rep = nr2.response_token.clone().expect("AP-REP in r2");
    let acc_mic = nr2.mech_list_mic.clone().expect("acceptor MIC in r2");

    // Finish the inner mutual exchange and verify the acceptor MIC over the
    // exact DER mechTypes bytes.
    assert!(init_complete(init_b.step(Some(&ap_rep)).expect("init_b rep")).is_none());
    let mut ctx_b = init_b.context().expect("ctx_b");
    ctx_b
        .verify_mic(&der, &acc_mic)
        .expect("verify acceptor MIC");

    // Initiator's final message: MIC only, no responseToken.
    let init_mic = ctx_b.get_mic(&der).expect("initiator MIC");
    let t3 = encode_neg_token_resp(NegState::AcceptIncomplete, None, None, Some(&init_mic));
    // Both MICs sent and received → ACCEPT_COMPLETE and, since the MIC was
    // already sent on the previous pass, NO_TOKEN_SEND (handle_mic:573-585)
    // → complete with no output token.
    let out3 = accept_complete(acc.step(&t3).expect("accept3"));
    assert!(out3.is_none(), "no token when both MICs already exchanged");
    assert_eq!(acc.negotiated_mech(), Some(MECH_KRB5));
    let mut ctx_a = acc.context().expect("acc ctx");
    ctx_a
        .verify_mic(&der, &init_mic)
        .expect("verify initiator MIC");
}

// --- 7. acceptor rejection/error paths ---------------------------------------------

#[test]
fn acceptor_rejects() {
    let skey = random_key(18);
    let der_k = mech_types_der(&[MECH_KRB5]);

    // No common mechanism → GSS_S_BAD_MECH (acc_ctx_new:1333-1336; MIT also
    // emits a REJECT error token, which our API does not carry).
    let t = encode_neg_token_init(&mech_types_der(&[MECH_NTLMSSP]), None, None, false);
    let mut acc = new_acceptor(&skey, vec![MECH_KRB5.to_vec()]);
    assert_eq!(gss_err(acc.step(&t).unwrap_err()), GssError::BadMech);

    // Inner mechToken framed with the SPNEGO OID: acc_ctx_vfy_oid →
    // GSS_S_BAD_MECH.
    let ap_req = raw_ap_req(&skey, GssFlags::empty());
    let (_m, body) = parse_token_header(&ap_req).expect("hdr");
    let mut framed = make_token_header(MECH_SPNEGO, body.len(), None);
    framed.extend_from_slice(body);
    let t = encode_neg_token_init(&der_k, Some(&framed), None, false);
    let mut acc = new_acceptor(&skey, vec![MECH_KRB5.to_vec()]);
    assert_eq!(gss_err(acc.step(&t).unwrap_err()), GssError::BadMech);

    // MS wrong krb5 OID listed first with a correct-OID krb5 mechToken:
    // negotiate_mech maps WRONG→krb5 (i==0 → ACCEPT_INCOMPLETE) and echoes
    // the wrong OID back verbatim as supportedMech (:3574-3577).
    let der_wk = mech_types_der(&[MECH_KRB5_WRONG, MECH_KRB5]);
    let t = encode_neg_token_init(&der_wk, Some(&ap_req), None, false);
    let mut acc = new_acceptor(&skey, vec![MECH_KRB5.to_vec()]);
    let resp = accept_complete(acc.step(&t).expect("accept wrong-oid")).expect("tok");
    let nr = decode_neg_token_resp(&resp).expect("decode");
    assert_eq!(nr.supported_mech.as_deref(), Some(MECH_KRB5_WRONG));

    // A NegTokenResp as the first token → DefectiveToken (the [1] choice
    // cannot be a NegTokenInit).
    let resp_tok = encode_neg_token_resp(NegState::AcceptIncomplete, None, None, None);
    let mut acc = new_acceptor(&skey, vec![MECH_KRB5.to_vec()]);
    assert_eq!(
        gss_err(acc.step(&resp_tok).unwrap_err()),
        GssError::DefectiveToken
    );

    // After REQUEST_MIC, a subsequent token with neither responseToken nor
    // mechListMIC → DefectiveToken (acc_ctx_cont:1400-1404).
    let der_nk = mech_types_der(&[MECH_NTLMSSP, MECH_KRB5]);
    let t1 = encode_neg_token_init(&der_nk, None, None, false);
    let mut acc = new_acceptor(&skey, vec![MECH_KRB5.to_vec()]);
    accept_continue(acc.step(&t1).expect("req-mic"));
    let empty_resp = encode_neg_token_resp(NegState::AcceptIncomplete, None, None, None);
    assert_eq!(
        gss_err(acc.step(&empty_resp).unwrap_err()),
        GssError::DefectiveToken
    );

    // supportedMech on a subsequent token → DefectiveToken (:1405-1408).
    let mut acc2 = new_acceptor(&skey, vec![MECH_KRB5.to_vec()]);
    accept_continue(acc2.step(&t1).expect("req-mic"));
    let sup_resp = encode_neg_token_resp(
        NegState::AcceptIncomplete,
        Some(MECH_KRB5),
        Some(b"x"),
        None,
    );
    assert_eq!(
        gss_err(acc2.step(&sup_resp).unwrap_err()),
        GssError::DefectiveToken
    );
}

