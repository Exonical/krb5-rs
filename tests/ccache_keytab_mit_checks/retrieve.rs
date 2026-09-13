// Group 3: creds_match_request + retrieve — cc_retr.c:148-245.

fn mc() -> MatchCred {
    MatchCred::default()
}

#[test]
fn match_client_and_server_principals() {
    let c = cred1();
    // client mismatch → false
    let mut m = mc();
    m.client = Some((princ(&[b"other"], 1), "KRBTEST.COM".into()));
    assert!(!creds_match_request(MatchFlags::empty(), &m, &c));
    // client None matches
    assert!(creds_match_request(MatchFlags::empty(), &mc(), &c));
    // server None → true regardless
    let mut m = mc();
    m.client = Some(test_princ());
    assert!(creds_match_request(MatchFlags::empty(), &m, &c));
    // server realm differs → false without SRV_NAMEONLY, true with it
    let mut m = mc();
    m.server = Some((c.server.clone(), "OTHER.REALM".into()));
    assert!(!creds_match_request(MatchFlags::empty(), &m, &c));
    assert!(creds_match_request(MatchFlags::SRV_NAMEONLY, &m, &c));
    // Name type is not compared (princ_comp.c).
    let mut m = mc();
    m.server = Some((princ(&[b"test", b"host"], 0), "EXAMPLE.COM".into()));
    assert!(creds_match_request(MatchFlags::empty(), &m, &c));
}

#[test]
fn match_is_skey_requires_flag() {
    let c2 = cred2(); // is_skey = true
    let mut m = mc();
    m.is_skey = true;
    // Without MATCH_IS_SKEY the is_skey cred never matches.
    assert!(!creds_match_request(MatchFlags::empty(), &m, &c2));
    assert!(creds_match_request(MatchFlags::IS_SKEY, &m, &c2));
    // And with the flag, a non-skey cred fails against is_skey request.
    assert!(!creds_match_request(MatchFlags::IS_SKEY, &m, &cred1()));
}

#[test]
fn match_flags_subset_vs_exact() {
    let c = cred1(); // 0x40800000
    let mut m = mc();
    m.ticket_flags = 0x4000_0000;
    assert!(creds_match_request(MatchFlags::FLAGS, &m, &c));
    assert!(!creds_match_request(MatchFlags::FLAGS_EXACT, &m, &c));
    m.ticket_flags = 0x4080_0000;
    assert!(creds_match_request(
        MatchFlags::FLAGS | MatchFlags::FLAGS_EXACT,
        &m,
        &c
    ));
}

#[test]
fn match_times() {
    let c = cred1(); // endtime 3333, renew_till 1e9
    let mut m = mc();
    // endtime 0 → ignored
    assert!(creds_match_request(MatchFlags::TIMES, &m, &c));
    m.endtime = 4000;
    assert!(!creds_match_request(MatchFlags::TIMES, &m, &c));
    m.endtime = 3000;
    assert!(creds_match_request(MatchFlags::TIMES, &m, &c));
    m.endtime = 0;
    m.renew_till = 2_000_000_000;
    assert!(!creds_match_request(MatchFlags::TIMES, &m, &c));
    m.renew_till = 0;
    // TIMES_EXACT requires all four equal
    let mut m = mc();
    m.authtime = 11;
    m.starttime = 222;
    m.endtime = 3333;
    m.renew_till = 1_000_000_000;
    assert!(creds_match_request(MatchFlags::TIMES_EXACT, &m, &c));
    m.starttime = 223;
    assert!(!creds_match_request(MatchFlags::TIMES_EXACT, &m, &c));
}

#[test]
fn match_ktype_authdata_second_ticket() {
    let (c1, c2) = (cred1(), cred2());
    let mut m = mc();
    m.etype = 17;
    assert!(creds_match_request(MatchFlags::KTYPE, &m, &c1));
    m.etype = 18;
    assert!(!creds_match_request(MatchFlags::KTYPE, &m, &c1));
    // AUTHDATA: None matches only an empty list (authdata_match,
    // cc_retr.c:82-83). cred2 is is_skey, so IS_SKEY must be set for it
    // to match at all (cc_retr.c:160-163).
    let mut m = mc();
    m.authdata = None;
    m.is_skey = true;
    assert!(!creds_match_request(MatchFlags::AUTHDATA, &m, &c1));
    assert!(creds_match_request(
        MatchFlags::AUTHDATA | MatchFlags::IS_SKEY,
        &m,
        &c2
    ));
    m.authdata = Some(c1.authdata.clone());
    assert!(creds_match_request(MatchFlags::AUTHDATA, &m, &c1));
    m.authdata = Some(vec![AuthorizationDataElement {
        ad_type: 512,
        ad_data: OctetString::from(b"signtickeX".to_vec()),
    }]);
    assert!(!creds_match_request(MatchFlags::AUTHDATA, &m, &c1));
    // SECOND_TKT (same IS_SKEY gate for cred2).
    let mut m = mc();
    m.second_ticket = Some(b"2ticket".to_vec());
    m.is_skey = true;
    assert!(!creds_match_request(MatchFlags::SECOND_TKT, &m, &c1));
    assert!(creds_match_request(
        MatchFlags::SECOND_TKT | MatchFlags::IS_SKEY,
        &m,
        &c2
    ));
}

#[test]
fn retrieve_first_match_and_ktype_preference() {
    let path = tmpdir_file("cc_retr");
    let _ = std::fs::remove_file(&path);
    let mut cc = make_v4_cache(&path);
    // A third cred: same client/server as cred1 but etype 23.
    let mut c3 = cred1();
    c3.keyblock = EncryptionKey::new(23, (0u8..16).rev().collect());
    cc.store(&c3).expect("store c3");

    let m = || MatchCred {
        server: Some((princ(&[b"test", b"host"], 1), "EXAMPLE.COM".into())),
        ..Default::default()
    };
    // Without ktypes → first match in file order (cred1, etype 17).
    let got = cc.retrieve(MatchFlags::empty(), &m(), None).expect("retrieve");
    assert_eq!(got.keyblock.keytype, 17);
    // With ktypes [23,17] → earliest preference wins (the etype-23 entry).
    let got = cc
        .retrieve(MatchFlags::empty(), &m(), Some(&[23, 17]))
        .expect("retrieve");
    assert_eq!(got.keyblock.keytype, 23);
    // Matches exist but none in ktypes → NotKtype.
    assert!(matches!(
        cc.retrieve(MatchFlags::empty(), &m(), Some(&[19])),
        Err(CcError::NotKtype)
    ));
    // No match at all → NotFound.
    let m2 = MatchCred {
        server: Some((princ(&[b"nosuch"], 1), "EXAMPLE.COM".into())),
        ..Default::default()
    };
    assert!(matches!(
        cc.retrieve(MatchFlags::empty(), &m2, None),
        Err(CcError::NotFound)
    ));
}
