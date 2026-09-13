// --- 1. constants and OID classification ---------------------------------------

#[test]
fn oid_constants_and_is_kerb_mech() {
    assert_eq!(MECH_SPNEGO, &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x02]);
    assert_eq!(MECH_KRB5_OLD, &[0x2b, 0x05, 0x01, 0x05, 0x02]);
    assert_eq!(
        MECH_KRB5_WRONG,
        &[0x2a, 0x86, 0x48, 0x82, 0xf7, 0x12, 0x01, 0x02, 0x02]
    );
    assert_eq!(
        MECH_NTLMSSP,
        &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a]
    );
    assert_eq!(
        MECH_KRB5,
        &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02]
    );
    // is_kerb_mech == membership in gss_mech_set_krb5_both
    // (gssapi_krb5.c:178-188 — {krb5, krb5_old, krb5_wrong}).
    assert!(is_kerb_mech(MECH_KRB5));
    assert!(is_kerb_mech(MECH_KRB5_OLD));
    assert!(is_kerb_mech(MECH_KRB5_WRONG));
    assert!(!is_kerb_mech(MECH_NTLMSSP));
    assert!(!is_kerb_mech(MECH_SPNEGO));
}

// --- 2. exact codec vectors ------------------------------------------------------

#[test]
fn codec_neg_token_init_layout() {
    let der = mech_types_der(&[MECH_KRB5, MECH_KRB5_WRONG]);
    let tok = encode_neg_token_init(&der, Some(b"T"), None, false);
    let expected: &[u8] = &[
        0x60, 0x2b, 0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02, // framing
        0xa0, 0x21, 0x30, 0x1f, // [0] SEQUENCE
        0xa0, 0x18, // [0] mechTypes
        0x30, 0x16, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02, 0x06, 0x09,
        0x2a, 0x86, 0x48, 0x82, 0xf7, 0x12, 0x01, 0x02, 0x02, // SEQUENCE OF OIDs
        0xa2, 0x03, 0x04, 0x01, 0x54, // [2] OCTET STRING "T"
    ];
    assert_eq!(tok, expected);

    // Roundtrip: decoded fields and the exact DER mechTypes blob (for MIC).
    let (init, der_back) = decode_neg_token_init(&tok).expect("decode");
    assert_eq!(
        init.mech_types,
        vec![MECH_KRB5.to_vec(), MECH_KRB5_WRONG.to_vec()]
    );
    assert_eq!(init.mech_token.as_deref(), Some(b"T".as_ref()));
    assert!(init.mech_list_mic.is_none());
    assert!(init.req_flags.is_none());
    assert_eq!(der_back, der);

    // With [3] MIC present.
    let tok2 = encode_neg_token_init(&der, None, Some(b"M"), false);
    let (init2, _) = decode_neg_token_init(&tok2).expect("decode");
    assert_eq!(init2.mech_list_mic.as_deref(), Some(b"M".as_ref()));
    assert!(init2.mech_token.is_none());
}

#[test]
fn codec_neg_token_init_req_flags_and_errors() {
    let der = mech_types_der(&[MECH_KRB5]);

    // reqFlags [1] contents must be exactly 03 02 01 <byte> (BIT_STRING,
    // BIT_STRING_LENGTH=2, BIT_STRING_PADDING=1, spnego_mech.c:3393-3401);
    // flags = byte >> 1.
    let mut t = vec![0x60, 0x00];
    let mut inner = vec![0xa0, 0x00, 0x30, 0x00];
    let mut fields = Vec::new();
    fields.extend_from_slice(&[0xa0, der.len() as u8]);
    fields.extend_from_slice(&der);
    fields.extend_from_slice(&[0xa1, 0x04, 0x03, 0x02, 0x01, 0x40]);
    inner[3] = fields.len() as u8;
    inner.extend_from_slice(&fields);
    inner[1] = inner.len() as u8 - 2;
    let framed_len = 8 + inner.len();
    t[1] = framed_len as u8;
    t.extend_from_slice(&[0x06, 0x06]);
    t.extend_from_slice(MECH_SPNEGO);
    t.extend_from_slice(&inner);
    let (init, _) = decode_neg_token_init(&t).expect("decode with reqFlags");
    assert_eq!(init.req_flags, Some(0x40 >> 1));

    // Length-3 reqFlags field contents → DefectiveToken.
    let bad3 = {
        let mut f = Vec::new();
        f.extend_from_slice(&[0xa0, der.len() as u8]);
        f.extend_from_slice(&der);
        f.extend_from_slice(&[0xa1, 0x03, 0x03, 0x02, 0x01]);
        let mut i = vec![0xa0, (f.len() + 2) as u8, 0x30, f.len() as u8];
        i.extend_from_slice(&f);
        let mut o = vec![0x60, (8 + i.len()) as u8, 0x06, 0x06];
        o.extend_from_slice(MECH_SPNEGO);
        o.extend_from_slice(&i);
        o
    };
    assert_eq!(
        decode_neg_token_init(&bad3).unwrap_err(),
        GssError::DefectiveToken
    );

    // Wrong padding byte (0x07 is not BIT_STRING_PADDING=0x01) → Defective.
    let badpad = {
        let mut f = Vec::new();
        f.extend_from_slice(&[0xa0, der.len() as u8]);
        f.extend_from_slice(&der);
        f.extend_from_slice(&[0xa1, 0x04, 0x03, 0x02, 0x07, 0x40]);
        let mut i = vec![0xa0, (f.len() + 2) as u8, 0x30, f.len() as u8];
        i.extend_from_slice(&f);
        let mut o = vec![0x60, (8 + i.len()) as u8, 0x06, 0x06];
        o.extend_from_slice(MECH_SPNEGO);
        o.extend_from_slice(&i);
        o
    };
    assert_eq!(
        decode_neg_token_init(&badpad).unwrap_err(),
        GssError::DefectiveToken
    );

    // Empty mechTypes field → DefectiveToken (get_negTokenInit:3434-3436).
    let empty_mt = {
        let f = vec![0xa0, 0x00];
        let mut i = vec![0xa0, (f.len() + 2) as u8, 0x30, f.len() as u8];
        i.extend_from_slice(&f);
        let mut o = vec![0x60, (8 + i.len()) as u8, 0x06, 0x06];
        o.extend_from_slice(MECH_SPNEGO);
        o.extend_from_slice(&i);
        o
    };
    assert_eq!(
        decode_neg_token_init(&empty_mt).unwrap_err(),
        GssError::DefectiveToken
    );

    // Wrong framing OID → DefectiveToken (verify_token_header:3790-3802).
    let wrong_oid = {
        let mut o = vec![0x60, (8 + 4) as u8, 0x06, 0x06];
        o.extend_from_slice(MECH_KRB5);
        o.extend_from_slice(&[0xa0, 0x02, 0x30, 0x00]);
        o
    };
    assert_eq!(
        decode_neg_token_init(&wrong_oid).unwrap_err(),
        GssError::DefectiveToken
    );

    // Missing [0] choice tag → DefectiveToken.
    let no_choice = {
        let mut o = vec![0x60, 0x0a, 0x06, 0x06];
        o.extend_from_slice(MECH_SPNEGO);
        o.extend_from_slice(&[0x30, 0x00]);
        o
    };
    assert_eq!(
        decode_neg_token_init(&no_choice).unwrap_err(),
        GssError::DefectiveToken
    );
}

#[test]
fn codec_neg_token_resp() {
    let tok = encode_neg_token_resp(
        NegState::AcceptIncomplete,
        Some(MECH_KRB5),
        Some(b"T"),
        Some(b"M"),
    );
    let expected: &[u8] = &[
        0xa1, 0x1e, 0x30, 0x1c, // [1] SEQUENCE
        0xa0, 0x03, 0x0a, 0x01, 0x01, // negState accept-incomplete
        0xa1, 0x0b, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02,
        0x02, // supportedMech
        0xa2, 0x03, 0x04, 0x01, 0x54, // responseToken "T"
        0xa3, 0x03, 0x04, 0x01, 0x4d, // mechListMIC "M"
    ];
    assert_eq!(tok, expected);

    let resp = decode_neg_token_resp(&tok).expect("decode");
    assert_eq!(resp.neg_state, Some(NegState::AcceptIncomplete));
    assert_eq!(resp.supported_mech.as_deref(), Some(MECH_KRB5));
    assert_eq!(resp.response_token.as_deref(), Some(b"T".as_ref()));
    assert_eq!(resp.mech_list_mic.as_deref(), Some(b"M".as_ref()));

    // Zero-length responseToken is omitted entirely
    // (make_spnego_tokenTarg_msg:3737-3738 token->length > 0).
    let tok2 = encode_neg_token_resp(NegState::Reject, None, Some(b""), None);
    let expected2: &[u8] = &[0xa1, 0x07, 0x30, 0x05, 0xa0, 0x03, 0x0a, 0x01, 0x02];
    assert_eq!(tok2, expected2);
    let resp2 = decode_neg_token_resp(&tok2).expect("decode");
    assert_eq!(resp2.neg_state, Some(NegState::Reject));
    assert!(resp2.response_token.is_none());

    // Missing SEQUENCE tag tolerated (get_negTokenResp:3494-3496).
    let no_seq: &[u8] = &[0xa1, 0x05, 0xa0, 0x03, 0x0a, 0x01, 0x00];
    let resp3 = decode_neg_token_resp(no_seq).expect("decode no-seq");
    assert_eq!(resp3.neg_state, Some(NegState::AcceptCompleted));

    // ENUMERATED length != 1 → DefectiveToken (:3500-3502).
    let bad_enum: &[u8] = &[0xa1, 0x06, 0xa0, 0x04, 0x0a, 0x02, 0x00, 0x00];
    assert_eq!(
        decode_neg_token_resp(bad_enum).unwrap_err(),
        GssError::DefectiveToken
    );

    // Windows 2000 quirk (:3525-3536): mechListMIC byte-identical to
    // responseToken is discarded.
    let dup = encode_neg_token_resp(
        NegState::AcceptIncomplete,
        None,
        Some(b"same-bytes"),
        Some(b"same-bytes"),
    );
    let resp4 = decode_neg_token_resp(&dup).expect("decode dup");
    assert_eq!(
        resp4.response_token.as_deref(),
        Some(b"same-bytes".as_ref())
    );
    assert!(resp4.mech_list_mic.is_none());
}

