#[test]
fn rd_req_msg_type_and_pvno() {
    let skey = random_key(18);
    let session = random_key(18);
    let cred = good_cred(&skey, &session);
    let mut client = AuthContext::new();
    let req = client.mk_req(&opts(), None, &cred).expect("mk_req");

    // An AP-REP is not an AP-REQ.
    let ap_rep = ApRep {
        pvno: 5,
        msg_type: 15,
        enc_part: EncryptedData {
            etype: 18,
            kvno: None,
            cipher: OctetString::from(vec![0u8; 64]),
        },
    };
    let rep_der = rasn::der::encode(&ap_rep).expect("encode AP-REP");
    let mut server = AuthContext::new();
    let e = server
        .rd_req(&rep_der, Some(&service()), &OneKey(skey.clone()))
        .unwrap_err();
    assert_eq!(ap_err(e), ApError::MsgType);

    let mut ap_req: ApReq = rasn::der::decode(&req).expect("decode");
    ap_req.pvno = 4;
    let bad = rasn::der::encode(&ap_req).expect("encode");
    let mut server = AuthContext::new();
    let e = server
        .rd_req(&bad, Some(&service()), &OneKey(skey))
        .unwrap_err();
    assert_eq!(ap_err(e), ApError::BadVersion);
}

// --- AP-REP / mutual ----------------------------------------------------------

fn do_exchange(
    client_flags: AuthContextFlags,
    server_flags: AuthContextFlags,
    o: &ApReqOptions,
) -> (AuthContext, AuthContext, EncryptionKey, EncryptionKey) {
    let skey = random_key(18);
    let session = random_key(18);
    let cred = good_cred(&skey, &session);
    let mut client = AuthContext::new();
    client.set_flags(client_flags);
    let req = client.mk_req(o, None, &cred).expect("mk_req");
    let mut server = AuthContext::new();
    server.set_flags(server_flags);
    server
        .rd_req(&req, Some(&service()), &OneKey(skey.clone()))
        .expect("rd_req");
    (client, server, skey, session)
}

#[test]
fn mutual_auth_mk_rep_rd_rep() {
    let mut o = opts();
    o.mutual_required = true;
    o.use_subkey = true;
    let (mut client, mut server, _skey, _session) = do_exchange(
        AuthContextFlags::DO_SEQUENCE,
        AuthContextFlags::DO_SEQUENCE,
        &o,
    );

    let rep_der = server.mk_rep().expect("mk_rep");
    let rep = client.rd_rep(&rep_der).expect("rd_rep");

    let auth = client.authenticator().expect("authenticator");
    assert_eq!(rep.ctime, auth.ctime);
    assert_eq!(rep.cusec, auth.cusec);
    assert_eq!(client.remote_seq_number(), server.local_seq_number());
    assert_ne!(client.remote_seq_number(), 0);
    assert_eq!(
        rep.subkey.as_ref().expect("subkey").key_bytes(),
        client.send_subkey().expect("send_subkey").key_bytes()
    );

    // RFC 4537: server USE_SUBKEY flag generates a negotiated-etype subkey.
    let mut o = opts();
    o.mutual_required = true;
    o.etype_negotiation = true;
    let skey = random_key(18);
    let session = random_key(18);
    let cred = good_cred(&skey, &session);
    let mut client = AuthContext::new();
    client.set_flags(AuthContextFlags::DO_SEQUENCE);
    client.set_permitted_etypes(Some(vec![20, 19, 18]));
    let req = client.mk_req(&o, None, &cred).expect("mk_req");
    let mut server = AuthContext::new();
    server.set_flags(AuthContextFlags::DO_SEQUENCE | AuthContextFlags::USE_SUBKEY);
    // Server preference decides (rd_req_dec.c:889-900); prefer aes-sha2.
    server.set_permitted_etypes(Some(vec![20, 19, 18, 17]));
    server
        .rd_req(&req, Some(&service()), &OneKey(skey))
        .expect("rd_req");
    assert_eq!(server.negotiated_etype(), 20);
    let rep_der = server.mk_rep().expect("mk_rep");
    let rep = client.rd_rep(&rep_der).expect("rd_rep");
    let sub = rep.subkey.expect("negotiated subkey");
    assert_eq!(sub.keytype, 20);
    assert_eq!(
        client.recv_subkey().expect("recv_subkey").key_bytes(),
        server.send_subkey().expect("send_subkey").key_bytes()
    );
}

#[test]
fn rd_rep_rejects_mismatched_ctime() {
    let mut o = opts();
    o.mutual_required = true;
    let (mut client, server, _skey, session) =
        do_exchange(AuthContextFlags::empty(), AuthContextFlags::empty(), &o);
    drop(server);
    let auth = client.authenticator().expect("auth").clone();

    for (ctime, cusec) in [
        (auth.ctime + chrono::Duration::seconds(1), auth.cusec),
        (auth.ctime, auth.cusec + 1),
    ] {
        let enc = EncApRepPart {
            ctime,
            cusec,
            subkey: None,
            seq_number: None,
        };
        let cipher = find_etype(18)
            .expect("etype")
            .encrypt(
                session.key_bytes(),
                12,
                &rasn::der::encode(&enc).expect("encode"),
            )
            .expect("encrypt");
        let rep = ApRep {
            pvno: 5,
            msg_type: 15,
            enc_part: EncryptedData {
                etype: 18,
                kvno: None,
                cipher: OctetString::from(cipher),
            },
        };
        let der = rasn::der::encode(&rep).expect("encode");
        let e = client.rd_rep(&der).unwrap_err();
        assert_eq!(ap_err(e), ApError::MutualFailed);
    }
}

#[test]
fn rd_rep_wrong_key_fails() {
    let mut o = opts();
    o.mutual_required = true;
    let (mut client, _server, _skey, _session) =
        do_exchange(AuthContextFlags::empty(), AuthContextFlags::empty(), &o);
    let auth = client.authenticator().expect("auth").clone();
    let enc = EncApRepPart {
        ctime: auth.ctime,
        cusec: auth.cusec,
        subkey: None,
        seq_number: None,
    };
    let wrong = random_key(18);
    let cipher = find_etype(18)
        .expect("etype")
        .encrypt(
            wrong.key_bytes(),
            12,
            &rasn::der::encode(&enc).expect("encode"),
        )
        .expect("encrypt");
    let rep = ApRep {
        pvno: 5,
        msg_type: 15,
        enc_part: EncryptedData {
            etype: 18,
            kvno: None,
            cipher: OctetString::from(cipher),
        },
    };
    let der = rasn::der::encode(&rep).expect("encode");
    let e = client.rd_rep(&der).unwrap_err();
    assert_ne!(ap_err(e), ApError::MutualFailed);
}

