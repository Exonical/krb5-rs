// --- AP-REQ / rd_req ---------------------------------------------------------

#[test]
fn mk_req_rd_req_roundtrip_sets_context_state() {
    let skey = random_key(18);
    let session = random_key(18);
    let cred = good_cred(&skey, &session);

    let mut client = AuthContext::new();
    client.set_flags(AuthContextFlags::DO_SEQUENCE);
    let mut o = opts();
    o.mutual_required = true;
    o.use_subkey = true;
    let req = client.mk_req(&o, Some(b"appdata"), &cred).expect("mk_req");

    let mut server = AuthContext::new();
    server.set_flags(AuthContextFlags::empty());
    let res = server
        .rd_req(&req, Some(&service()), &OneKey(skey))
        .expect("rd_req");

    assert_eq!(res.ticket.cname, alice());
    assert!(res.ap_options.contains(ApOptions::MUTUAL_REQUIRED));
    let lseq = client.local_seq_number();
    assert_ne!(lseq, 0);
    assert_eq!(server.remote_seq_number(), lseq);
    assert_eq!(
        server.recv_subkey().expect("recv_subkey").key_bytes(),
        client.send_subkey().expect("send_subkey").key_bytes()
    );
    assert_eq!(
        server.session_key().expect("session").key_bytes(),
        session.key_bytes()
    );
    let cksum = res.authenticator.cksum.expect("cksum");
    assert_eq!(cksum.cksumtype, 16);
    find_etype(18)
        .expect("etype")
        .verify_checksum(session.key_bytes(), 10, b"appdata", &cksum.checksum)
        .expect("authenticator checksum");
    assert_eq!(res.authenticator.seq_number, Some(lseq));
}

#[test]
fn mk_req_without_seq_flags_omits_seq_number() {
    let skey = random_key(18);
    let session = random_key(18);
    let cred = good_cred(&skey, &session);

    let mut client = AuthContext::new();
    client.set_flags(AuthContextFlags::empty());
    let req = client.mk_req(&opts(), None, &cred).expect("mk_req");

    let mut server = AuthContext::new();
    server.set_flags(AuthContextFlags::empty());
    let res = server
        .rd_req(&req, Some(&service()), &OneKey(skey))
        .expect("rd_req");
    assert_eq!(res.authenticator.seq_number, None);
    assert_eq!(server.remote_seq_number(), 0);
}

#[test]
fn mk_req_rfc4537_etype_list() {
    let skey = random_key(18);
    let session = random_key(18);
    let cred = good_cred(&skey, &session);

    let mut client = AuthContext::new();
    client.set_permitted_etypes(Some(vec![20, 19, 18, 17]));
    let mut o = opts();
    o.mutual_required = true;
    o.etype_negotiation = true;
    let req = client.mk_req(&o, None, &cred).expect("mk_req");

    let ap_req: ApReq = rasn::der::decode(&req).expect("decode AP-REQ");
    let session_key = decrypt_ticket(&skey, &ap_req.ticket)
        .expect("decrypt ticket")
        .key;
    let plain = find_etype(session_key.keytype)
        .expect("etype")
        .decrypt(session_key.key_bytes(), 11, &ap_req.authenticator.cipher)
        .expect("decrypt authenticator");
    let auth: Authenticator = rasn::der::decode(&plain).expect("decode authenticator");

    let ad = auth.authorization_data.expect("authorization_data");
    assert_eq!(ad.len(), 1);
    assert_eq!(ad[0].ad_type, 1);
    let inner: Vec<AuthorizationDataElement> =
        rasn::der::decode(&ad[0].ad_data).expect("decode AD-IF-RELEVANT contents");
    let neg = inner
        .iter()
        .find(|e| e.ad_type == 129)
        .expect("ETYPE_NEGOTIATION element");
    let etypes: Vec<i32> = rasn::der::decode(&neg.ad_data).expect("decode etype list");
    assert_eq!(etypes, vec![20, 19, 18]);

    // rd_req_dec.c:889-900: the *server's* permitted list is ordered by
    // preference; the first permitted etype that the client desires wins.
    // Default permitted order is [18, 17, 20, 19], so 18 is negotiated.
    let mut server = AuthContext::new();
    server
        .rd_req(&req, Some(&service()), &OneKey(skey.clone()))
        .expect("rd_req");
    assert_eq!(server.negotiated_etype(), 18);

    let mut server_sha2 = AuthContext::new();
    server_sha2.set_permitted_etypes(Some(vec![20, 19, 18, 17]));
    server_sha2
        .rd_req(&req, Some(&service()), &OneKey(skey.clone()))
        .expect("rd_req");
    assert_eq!(server_sha2.negotiated_etype(), 20);

    let mut server2 = AuthContext::new();
    server2.set_permitted_etypes(Some(vec![18]));
    server2
        .rd_req(&req, Some(&service()), &OneKey(skey))
        .expect("rd_req");
    assert_eq!(server2.negotiated_etype(), 18);

    let mut client2 = AuthContext::new();
    client2.set_permitted_etypes(Some(vec![18, 17]));
    let req2 = client2.mk_req(&o, None, &cred).expect("mk_req");
    let ap_req2: ApReq = rasn::der::decode(&req2).expect("decode");
    let plain2 = find_etype(session_key.keytype)
        .expect("etype")
        .decrypt(session_key.key_bytes(), 11, &ap_req2.authenticator.cipher)
        .expect("decrypt");
    let auth2: Authenticator = rasn::der::decode(&plain2).expect("decode");
    assert!(auth2.authorization_data.is_none());
}

#[test]
fn mk_req_etype_negotiation_requires_mutual() {
    let skey = random_key(18);
    let session = random_key(18);
    let cred = good_cred(&skey, &session);
    let mut client = AuthContext::new();
    let mut o = opts();
    o.etype_negotiation = true;
    assert!(client.mk_req(&o, None, &cred).is_err());
}

#[test]
fn mk_req_rejects_expired_credential() {
    let skey = random_key(18);
    let session = random_key(18);

    let expired = mint(
        &skey,
        &session,
        None,
        secs(-600),
        TicketFlags::empty(),
        None,
    );
    let mut client = AuthContext::new();
    let e = client.mk_req(&opts(), None, &expired).unwrap_err();
    assert_eq!(ap_err(e), ApError::TktExpired);

    let recent = mint(
        &skey,
        &session,
        None,
        secs(-120),
        TicketFlags::empty(),
        None,
    );
    client.mk_req(&opts(), None, &recent).expect("within skew");
}

#[test]
fn rd_req_ticket_time_checks() {
    let skey = random_key(18);
    let session = random_key(18);

    // mk_req validates times itself (test 5 covers that), so the expired-
    // ticket request is hand-built; rd_req must hit TktExpired on the ticket
    // before the authenticator skew check (rd_req_dec.c:627-632 ordering).
    let expired = mint(
        &skey,
        &session,
        None,
        secs(-600),
        TicketFlags::empty(),
        None,
    );
    let req = hand_req(&expired, &session);
    let mut server = AuthContext::new();
    let e = server
        .rd_req(&req, Some(&service()), &OneKey(skey.clone()))
        .unwrap_err();
    assert_eq!(ap_err(e), ApError::TktExpired);

    // mk_req also validates times, so the client must believe the ticket is
    // already valid: shift its clock past the starttime; the server (unshifted)
    // must then hit TktNyv on the ticket before the authenticator skew check
    // (rd_req_dec.c:627-632 ordering).
    let nyv = mint(
        &skey,
        &session,
        Some(secs(600)),
        secs(7200),
        TicketFlags::empty(),
        None,
    );
    let mut client = AuthContext::new();
    client.set_time_offset(chrono::Duration::seconds(1200));
    let req = client.mk_req(&opts(), None, &nyv).expect("mk_req");
    let mut server = AuthContext::new();
    let e = server
        .rd_req(&req, Some(&service()), &OneKey(skey.clone()))
        .unwrap_err();
    assert_eq!(ap_err(e), ApError::TktNyv);

    let soon = mint(
        &skey,
        &session,
        Some(secs(120)),
        secs(7200),
        TicketFlags::empty(),
        None,
    );
    let mut client = AuthContext::new();
    let req = client.mk_req(&opts(), None, &soon).expect("mk_req");
    let mut server = AuthContext::new();
    server
        .rd_req(&req, Some(&service()), &OneKey(skey))
        .expect("ok");
}

#[test]
fn rd_req_rejects_clock_skew() {
    let skey = random_key(18);
    let session = random_key(18);
    let cred = good_cred(&skey, &session);

    let mut client = AuthContext::new();
    client.set_time_offset(chrono::Duration::seconds(600));
    let req = client.mk_req(&opts(), None, &cred).expect("mk_req");
    let mut server = AuthContext::new();
    let e = server
        .rd_req(&req, Some(&service()), &OneKey(skey.clone()))
        .unwrap_err();
    assert_eq!(ap_err(e), ApError::Skew);

    let mut client = AuthContext::new();
    client.set_time_offset(chrono::Duration::seconds(120));
    let req = client.mk_req(&opts(), None, &cred).expect("mk_req");
    let mut server = AuthContext::new();
    server
        .rd_req(&req, Some(&service()), &OneKey(skey))
        .expect("ok");
}

#[test]
fn rd_req_rejects_client_mismatch() {
    let skey = random_key(18);
    let session = random_key(18);
    let cred = good_cred(&skey, &session);

    // Hand-build an AP-REQ whose authenticator names "bob".
    let auth = Authenticator {
        authenticator_vno: 5,
        crealm: realm(),
        cname: PrincipalName::new_principal("bob"),
        cksum: None,
        cusec: 0,
        ctime: now(),
        subkey: None,
        seq_number: None,
        authorization_data: None,
    };
    let auth_der = rasn::der::encode(&auth).expect("encode");
    let cipher = find_etype(18)
        .expect("etype")
        .encrypt(session.key_bytes(), 11, &auth_der)
        .expect("encrypt");
    let ap_req = ApReq {
        pvno: 5,
        msg_type: 14,
        ap_options: KerberosFlags::new(ApOptions::empty()),
        ticket: cred.ticket.clone(),
        authenticator: EncryptedData {
            etype: 18,
            kvno: None,
            cipher: OctetString::from(cipher),
        },
    };
    let req = rasn::der::encode(&ap_req).expect("encode AP-REQ");

    let mut server = AuthContext::new();
    let e = server
        .rd_req(&req, Some(&service()), &OneKey(skey))
        .unwrap_err();
    assert_eq!(ap_err(e), ApError::BadMatch);
}

#[test]
fn rd_req_wrong_service_key_is_bad_integrity() {
    let skey = random_key(18);
    let session = random_key(18);
    let cred = good_cred(&skey, &session);
    let mut client = AuthContext::new();
    let req = client.mk_req(&opts(), None, &cred).expect("mk_req");
    let mut server = AuthContext::new();
    let e = server
        .rd_req(&req, Some(&service()), &WrongKey(random_key(18)))
        .unwrap_err();
    assert_eq!(ap_err(e), ApError::BadIntegrity);
}

#[test]
fn rd_req_keysource_error_propagates() {
    let skey = random_key(18);
    let session = random_key(18);
    let cred = good_cred(&skey, &session);
    let mut client = AuthContext::new();
    let req = client.mk_req(&opts(), None, &cred).expect("mk_req");
    let mut server = AuthContext::new();
    let e = server
        .rd_req(&req, Some(&service()), &ErrKey(ApError::BadKeyver))
        .unwrap_err();
    assert_eq!(ap_err(e), ApError::BadKeyver);
}

#[test]
fn rd_req_replay_detection() {
    let skey = random_key(18);
    let session = random_key(18);
    let cred = good_cred(&skey, &session);
    let mut client = AuthContext::new();
    let req = client.mk_req(&opts(), None, &cred).expect("mk_req");

    let mut server = AuthContext::new();
    server.set_flags(AuthContextFlags::DO_TIME);
    server
        .rd_req(&req, Some(&service()), &OneKey(skey.clone()))
        .expect("first");
    let e = server
        .rd_req(&req, Some(&service()), &OneKey(skey.clone()))
        .unwrap_err();
    assert_eq!(ap_err(e), ApError::Repeat);

    let mut server2 = AuthContext::new();
    server2.set_flags(AuthContextFlags::empty());
    server2
        .rd_req(&req, Some(&service()), &OneKey(skey.clone()))
        .expect("first");
    server2
        .rd_req(&req, Some(&service()), &OneKey(skey))
        .expect("second ok");
}

#[test]
fn rd_req_rejects_invalid_ticket() {
    let skey = random_key(18);
    let session = random_key(18);
    let cred = mint(
        &skey,
        &session,
        None,
        secs(3600),
        TicketFlags::INVALID,
        None,
    );
    let mut client = AuthContext::new();
    let req = client.mk_req(&opts(), None, &cred).expect("mk_req");
    let mut server = AuthContext::new();
    let e = server
        .rd_req(&req, Some(&service()), &OneKey(skey))
        .unwrap_err();
    assert_eq!(ap_err(e), ApError::TktInvalid);
}

#[test]
fn rd_req_address_check() {
    let skey = random_key(18);
    let session = random_key(18);

    let cred = mint(
        &skey,
        &session,
        None,
        secs(3600),
        TicketFlags::empty(),
        Some(vec![ipv4(10, 0, 0, 1)]),
    );
    let mut client = AuthContext::new();
    let req = client.mk_req(&opts(), None, &cred).expect("mk_req");
    let mut server = AuthContext::new();
    server.set_addrs(None, Some(ipv4(10, 0, 0, 2)));
    let e = server
        .rd_req(&req, Some(&service()), &OneKey(skey.clone()))
        .unwrap_err();
    assert_eq!(ap_err(e), ApError::BadAddr);

    let cred = mint(
        &skey,
        &session,
        None,
        secs(3600),
        TicketFlags::empty(),
        Some(vec![ipv4(10, 0, 0, 2)]),
    );
    let req = client.mk_req(&opts(), None, &cred).expect("mk_req");
    let mut server = AuthContext::new();
    server.set_addrs(None, Some(ipv4(10, 0, 0, 2)));
    server
        .rd_req(&req, Some(&service()), &OneKey(skey.clone()))
        .expect("matching addr");

    // addr_srch.c:26-31 — NULL addr list returns TRUE (no check).
    let cred = mint(
        &skey,
        &session,
        None,
        secs(3600),
        TicketFlags::empty(),
        None,
    );
    let req = client.mk_req(&opts(), None, &cred).expect("mk_req");
    let mut server = AuthContext::new();
    server.set_addrs(None, Some(ipv4(10, 0, 0, 2)));
    server
        .rd_req(&req, Some(&service()), &OneKey(skey))
        .expect("no caddr ok");
}

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

