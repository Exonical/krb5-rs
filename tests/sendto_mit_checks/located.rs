// ---------------------------------------------------------------------------
// Section 6: LocatedTransport — profile-located KDC + sendto +
// RESPONSE_TOO_BIG no-UDP retry (get_in_tkt.c:566-580)
// ---------------------------------------------------------------------------

fn located_profile(ports: &[(u16, &str)]) -> Profile {
    let mut s = String::from("[realms]\nR = {\n");
    for (p, tag) in ports {
        s.push_str(&format!("kdc = 127.0.0.1:{p}\n"));
        let _ = tag;
    }
    s.push_str("}\n");
    Profile::parse(&s).unwrap()
}

#[tokio::test]
async fn located_response_too_big_retries_tcp() {
    // UDP fake replies KRB-ERROR 52 -> MIT retries once with no_udp -> the
    // TCP fake's reply is returned (get_in_tkt.c:566-580).
    let log = new_log();
    let (port, _) = spawn_udp(log.clone(), "s0", Some(krb_error(52))).await;
    spawn_tcp(
        log.clone(),
        "s0",
        TcpAction::Reply(Duration::ZERO, b"OK".to_vec()),
        port,
    )
    .await;
    let prof = located_profile(&[(port, "x")]);
    let t = LocatedTransport::with_config(Arc::new(prof), None, fast_cfg());
    let r = t.send_recv("R", b"req").await.unwrap();
    assert_eq!(r, b"OK");
    let used = t.kdcs_used();
    assert_eq!(used.len(), 2);
    assert_eq!(used[0].0, "R");
    assert_eq!(used[0].1.transport, Transport::Udp);
    assert_eq!(used[1].0, "R");
    assert_eq!(used[1].1.transport, Transport::Tcp);
    assert_eq!(used[0].1.port, port);
}

#[tokio::test]
async fn located_persistent_52_returned_to_caller() {
    // If the TCP retry also yields KRB-ERROR 52, MIT surfaces the
    // RESPONSE_TOO_BIG to the caller (get_in_tkt.c:583-585 returns the
    // KRB-ERROR from the state machine); send_recv returns the raw bytes.
    let log = new_log();
    let (port, _) = spawn_udp(log.clone(), "s0", Some(krb_error(52))).await;
    spawn_tcp(
        log.clone(),
        "s0",
        TcpAction::Reply(Duration::ZERO, krb_error(52)),
        port,
    )
    .await;
    let prof = located_profile(&[(port, "x")]);
    let t = LocatedTransport::with_config(Arc::new(prof), None, fast_cfg());
    let r = t.send_recv("R", b"req").await.unwrap();
    assert_eq!(r, krb_error(52));
}

#[tokio::test]
async fn located_unknown_realm_errors() {
    let prof = Profile::parse("").unwrap();
    let t = LocatedTransport::new(Arc::new(prof), None);
    let r = t.send_recv("NOSUCH", b"req").await;
    assert!(matches!(r, Err(Krb5Error::Locate(LocateError::RealmUnknown))));
}

#[tokio::test]
async fn any_replicas_detection() {
    // locate_kdc.c:935-1012: entry not on the realm's primary list is a
    // replica; no primary list at all -> nothing is a replica.
    let prof = Profile::parse(
        "[realms]\nR = {\nkdc = a:88\nkdc = b:88\nprimary_kdc = a:88\n}\n",
    )
    .unwrap();
    let t = LocatedTransport::new(Arc::new(prof), None);
    let mk = |h: &str| ServerEntry {
        hostname: h.to_string(),
        port: 88,
        transport: Transport::Udp,
        uri_path: None,
        primary: None,
    };
    t.record_for_test("R", mk("a"));
    assert!(!t.any_replicas());
    t.clear_kdcs();
    t.record_for_test("R", mk("b"));
    assert!(t.any_replicas());
    // Second call: already-marked entries are skipped and the result is
    // stable (locate_kdc.c:948-951).
    assert!(t.any_replicas());
    let prof2 = Profile::parse("[realms]\nR = {\nkdc = a:88\n}\n").unwrap();
    let t2 = LocatedTransport::new(Arc::new(prof2), None);
    t2.record_for_test("R", mk("a"));
    assert!(!t2.any_replicas());
}
