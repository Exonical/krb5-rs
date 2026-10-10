// --- KRB-CRED -----------------------------------------------------------------

#[test]
fn cred_roundtrip_encrypted_and_unencrypted() {
    let (mut client, mut server, _skey, _session) = do_exchange(
        AuthContextFlags::DO_SEQUENCE | AuthContextFlags::DO_TIME,
        AuthContextFlags::DO_SEQUENCE | AuthContextFlags::DO_TIME,
        &opts(),
    );
    let fwd = good_cred(&random_key(18), &random_key(18));

    let (msg, _) = client.mk_cred(std::slice::from_ref(&fwd)).expect("mk_cred");
    let (creds, _) = server.rd_cred(&msg).expect("rd_cred");
    assert_eq!(creds.len(), 1);
    let c = &creds[0];
    assert_eq!(c.client, fwd.client);
    assert_eq!(c.server, fwd.server);
    assert_eq!(c.session_key.key_bytes(), fwd.session_key.key_bytes());
    assert_eq!(c.times.endtime, fwd.times.endtime);
    assert_eq!(c.flags, fwd.flags);
    assert_eq!(
        rasn::der::encode(&c.ticket).expect("enc"),
        rasn::der::encode(&fwd.ticket).expect("enc")
    );

    // Wrong expected nonce → BadOrder.
    let (msg2, _) = client.mk_cred(std::slice::from_ref(&fwd)).expect("mk_cred");
    server.set_remote_seq_number(server.remote_seq_number() + 5);
    let e = server.rd_cred(&msg2).unwrap_err();
    assert_eq!(ap_err(e), ApError::BadOrder);

    // Keyless contexts → unencrypted KRB-CRED (RFC 6448).
    let mut sender = AuthContext::new();
    let (plain_msg, _) = sender.mk_cred(std::slice::from_ref(&fwd)).expect("mk_cred");
    let kc: KrbCred = rasn::der::decode(&plain_msg).expect("decode KrbCred");
    assert_eq!(kc.enc_part.etype, 0);
    let mut receiver = AuthContext::new();
    let (creds, _) = receiver.rd_cred(&plain_msg).expect("rd_cred plaintext");
    assert_eq!(creds.len(), 1);
    assert_eq!(
        creds[0].session_key.key_bytes(),
        fwd.session_key.key_bytes()
    );
}

#[test]
fn rd_cred_falls_back_to_session_key() {
    // Server learns a recv_subkey from a subkey-bearing AP-REQ, but the
    // KRB-CRED sender uses the plain session key.
    let skey = random_key(18);
    let session = random_key(18);
    let cred = good_cred(&skey, &session);

    let mut o = opts();
    o.use_subkey = true;
    let mut client1 = AuthContext::new();
    let req = client1.mk_req(&o, None, &cred).expect("mk_req");
    let mut server = AuthContext::new();
    server
        .rd_req(&req, Some(&service()), &OneKey(skey))
        .expect("rd_req");
    assert!(server.recv_subkey().is_some());

    let mut client2 = AuthContext::new();
    client2.set_session_key(session.clone());
    let (msg, _) = client2
        .mk_cred(std::slice::from_ref(&cred))
        .expect("mk_cred");
    let (creds, _) = server.rd_cred(&msg).expect("rd_cred fallback");
    assert_eq!(creds.len(), 1);
}

// --- misc --------------------------------------------------------------------

#[test]
fn seq_number_generation_range() {
    // gen_seqnum.c: mask 0x3fffffff, never 0.
    let skey = random_key(18);
    let session = random_key(18);
    let cred = good_cred(&skey, &session);
    for _ in 0..200 {
        let mut ctx = AuthContext::new();
        ctx.set_flags(AuthContextFlags::DO_SEQUENCE);
        ctx.mk_req(&opts(), None, &cred).expect("mk_req");
        let n = ctx.local_seq_number();
        assert_ne!(n, 0);
        assert!(n <= 0x3fffffff);
    }
}

#[test]
fn decrypt_ticket_roundtrip() {
    let skey = random_key(18);
    let session = random_key(18);
    let cred = good_cred(&skey, &session);
    let part = decrypt_ticket(&skey, &cred.ticket).expect("decrypt_ticket");
    assert_eq!(part.cname, alice());
    assert_eq!(part.key.key_bytes(), session.key_bytes());
}
