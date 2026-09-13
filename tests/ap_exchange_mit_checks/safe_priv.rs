// --- KRB-SAFE -----------------------------------------------------------------

fn safe_pair() -> (AuthContext, AuthContext) {
    let (mut client, mut server, _s, _k) = do_exchange(
        AuthContextFlags::DO_SEQUENCE | AuthContextFlags::DO_TIME | AuthContextFlags::RET_SEQUENCE,
        AuthContextFlags::DO_SEQUENCE | AuthContextFlags::DO_TIME | AuthContextFlags::RET_SEQUENCE,
        &opts(),
    );
    client.set_addrs(Some(ipv4(10, 0, 0, 1)), Some(ipv4(10, 0, 0, 2)));
    server.set_addrs(Some(ipv4(10, 0, 0, 2)), Some(ipv4(10, 0, 0, 1)));
    (client, server)
}

#[test]
fn safe_roundtrip_sequence_and_replay() {
    let (mut client, mut server) = safe_pair();
    let first_seq = client.local_seq_number();

    let (m1, rdata) = client.mk_safe(b"hello").expect("mk_safe");
    assert_eq!(rdata.seq, Some(first_seq));
    let (data, rd) = server.rd_safe(&m1).expect("rd_safe");
    assert_eq!(data, b"hello");
    assert_eq!(rd.seq, Some(first_seq));

    let (m2, _) = client.mk_safe(b"second").expect("mk_safe");
    server.rd_safe(&m2).expect("second");

    let e = server.rd_safe(&m1).unwrap_err();
    assert_eq!(ap_err(e), ApError::Repeat);

    let (_m3, _) = client.mk_safe(b"third").expect("m3");
    let (m4, _) = client.mk_safe(b"fourth").expect("m4");
    let e = server.rd_safe(&m4).unwrap_err();
    assert_eq!(ap_err(e), ApError::BadOrder);
}

#[test]
fn safe_tamper_and_checksum_rules() {
    let (mut client, mut server) = safe_pair();
    let (m1, _) = client.mk_safe(b"hello").expect("mk_safe");

    let mut safe: KrbSafe = rasn::der::decode(&m1).expect("decode");
    let mut ud = safe.safe_body.user_data.to_vec();
    ud[0] ^= 0xff;
    safe.safe_body.user_data = OctetString::from(ud);
    let tampered = rasn::der::encode(&safe).expect("encode");
    let e = server.rd_safe(&tampered).unwrap_err();
    assert_eq!(ap_err(e), ApError::Modified);

    let mut safe: KrbSafe = rasn::der::decode(&m1).expect("decode");
    safe.cksum.cksumtype = 14;
    let tampered = rasn::der::encode(&safe).expect("encode");
    let e = server.rd_safe(&tampered).unwrap_err();
    assert_eq!(ap_err(e), ApError::InappCksum);

    let mut safe: KrbSafe = rasn::der::decode(&m1).expect("decode");
    safe.cksum.cksumtype = 9999;
    let tampered = rasn::der::encode(&safe).expect("encode");
    let e = server.rd_safe(&tampered).unwrap_err();
    assert_eq!(ap_err(e), ApError::SumTypeNoSupp);

    let mut safe: KrbSafe = rasn::der::decode(&m1).expect("decode");
    safe.safe_body.s_address = ipv4(10, 0, 0, 9);
    let tampered = rasn::der::encode(&safe).expect("encode");
    let e = server.rd_safe(&tampered).unwrap_err();
    assert_eq!(ap_err(e), ApError::BadAddr);

    let mut no_addr = AuthContext::new();
    no_addr.set_flags(AuthContextFlags::DO_TIME);
    no_addr.set_session_key(random_key(18));
    let e = no_addr.mk_safe(b"x").unwrap_err();
    assert_eq!(ap_err(e), ApError::LocalAddrRequired);
}

#[test]
fn rd_safe_accepts_rfc1510_body_only_checksum() {
    let (mut client, mut server) = safe_pair();
    let (m1, _) = client.mk_safe(b"hello").expect("mk_safe");

    let mut safe: KrbSafe = rasn::der::decode(&m1).expect("decode");
    let body_der = rasn::der::encode(&safe.safe_body).expect("encode body");
    let session = server.session_key().expect("key").clone();
    let cksum = find_etype(session.keytype)
        .expect("etype")
        .checksum(session.key_bytes(), 15, &body_der)
        .expect("checksum");
    safe.cksum = Checksum {
        cksumtype: find_cksumtype(16).expect("cksumtype").checksum_type(),
        checksum: OctetString::from(cksum),
    };
    let re_der = rasn::der::encode(&safe).expect("encode");
    let (data, _) = server.rd_safe(&re_der).expect("rfc1510 fallback");
    assert_eq!(data, b"hello");
}

// --- KRB-PRIV -----------------------------------------------------------------

#[test]
fn priv_roundtrip_tamper_replay_order() {
    let (mut client, mut server) = safe_pair();

    let (p1, _) = client.mk_priv(b"secret").expect("mk_priv");
    let (data, _) = server.rd_priv(&p1).expect("rd_priv");
    assert_eq!(data, b"secret");

    let mut privmsg: KrbPriv = rasn::der::decode(&p1).expect("decode");
    let mut c = privmsg.enc_part.cipher.to_vec();
    let n = c.len();
    c[n - 1] ^= 0xff;
    privmsg.enc_part.cipher = OctetString::from(c);
    let tampered = rasn::der::encode(&privmsg).expect("encode");
    assert!(server.rd_priv(&tampered).is_err());

    let e = server.rd_priv(&p1).unwrap_err();
    assert_eq!(ap_err(e), ApError::Repeat);

    let (_p2, _) = client.mk_priv(b"two").expect("p2");
    let (p3, _) = client.mk_priv(b"three").expect("p3");
    let e = server.rd_priv(&p3).unwrap_err();
    assert_eq!(ap_err(e), ApError::BadOrder);
}

