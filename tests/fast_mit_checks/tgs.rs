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

