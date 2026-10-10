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

