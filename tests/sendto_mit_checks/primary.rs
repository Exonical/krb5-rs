// ---------------------------------------------------------------------------
// Section 7: retry_with_primary (get_in_tkt.c:2005-2050)
// ---------------------------------------------------------------------------

fn replica_transport() -> LocatedTransport {
    // Realm R: kdc = a + b, primary_kdc = a -> a recorded 'b' use is a
    // replica, which enables the primary retry.
    let prof = Profile::parse(
        "[realms]\nR = {\nkdc = a:88\nkdc = b:88\nprimary_kdc = a:88\n}\n",
    )
    .unwrap();
    let t = LocatedTransport::new(Arc::new(prof), None);
    t.record_for_test(
        "R",
        ServerEntry {
            hostname: "b".to_string(),
            port: 88,
            transport: Transport::Udp,
            uri_path: None,
            primary: None,
        },
    );
    t
}

fn nonreplica_transport() -> LocatedTransport {
    let prof = Profile::parse("[realms]\nR = {\nkdc = a:88\n}\n").unwrap();
    let t = LocatedTransport::new(Arc::new(prof), None);
    t.record_for_test(
        "R",
        ServerEntry {
            hostname: "a".to_string(),
            port: 88,
            transport: Transport::Udp,
            uri_path: None,
            primary: None,
        },
    );
    t
}

fn other_err() -> Krb5Error {
    Krb5Error::Protocol("original failure".to_string())
}

#[tokio::test]
async fn primary_success_no_retry() {
    let t = replica_transport();
    let r: Result<i32, Krb5Error> =
        with_primary_fallback(&t, Ok(1), || async move {
            panic!("retry must not be called");
        })
        .await;
    assert_eq!(r.unwrap(), 1);
}

#[tokio::test]
async fn primary_unreach_no_retry() {
    let t = replica_transport();
    let e = Krb5Error::Sendto(SendtoError::KdcUnreach);
    let r: Result<i32, Krb5Error> = with_primary_fallback(&t, Err(e), || async move {
        panic!("retry must not be called");
    })
    .await;
    assert!(matches!(r, Err(Krb5Error::Sendto(SendtoError::KdcUnreach))));
    // use_primary not left set.
    assert!(!t.use_primary());
}

#[tokio::test]
async fn primary_no_replicas_no_retry() {
    let t = nonreplica_transport();
    let r: Result<i32, Krb5Error> =
        with_primary_fallback(&t, Err(other_err()), || async move {
            panic!("retry must not be called");
        })
        .await;
    match r {
        Err(Krb5Error::Protocol(m)) => assert_eq!(m, "original failure"),
        _ => panic!("expected original error"),
    }
}

#[tokio::test]
async fn primary_retry_success() {
    let t = replica_transport();
    let flag = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let f = flag.clone();
    let r: Result<i32, Krb5Error> = with_primary_fallback(&t, Err(other_err()), || async move {
        // use_primary must be set during the retry.
        f.store(true, Ordering::SeqCst);
        Ok(7)
    })
    .await;
    assert_eq!(r.unwrap(), 7);
    assert!(flag.load(Ordering::SeqCst));
    assert!(!t.use_primary());
}

#[tokio::test]
async fn primary_retry_realm_unknown_returns_original() {
    let t = replica_transport();
    let r: Result<i32, Krb5Error> = with_primary_fallback(&t, Err(other_err()), || async move {
        Err(Krb5Error::Locate(LocateError::RealmUnknown))
    })
    .await;
    match r {
        Err(Krb5Error::Protocol(m)) => assert_eq!(m, "original failure"),
        _ => panic!("expected original error"),
    }
}

#[tokio::test]
async fn primary_retry_other_error_returned() {
    let t = replica_transport();
    let r: Result<i32, Krb5Error> = with_primary_fallback(&t, Err(other_err()), || async move {
        Err(Krb5Error::Protocol("primary failed".to_string()))
    })
    .await;
    match r {
        Err(Krb5Error::Protocol(m)) => assert_eq!(m, "primary failed"),
        _ => panic!("expected retry error"),
    }
}

#[tokio::test]
async fn get_tgt_uses_primary_fallback() {
    // First pass (all KDCs) hits the replica, which replies KRB-ERROR 29 ->
    // sendto_kdc gives SvcUnavailable (a non-unreach error); the fallback
    // retries with primary KDCs only and succeeds.
    let log = new_log();
    let (p0, _) = spawn_udp(log.clone(), "replica", Some(krb_error(29))).await;
    let (p1, _) = spawn_udp(log.clone(), "primary", Some(b"AS-REP".to_vec())).await;
    // p1 is listed only as primary_kdc: the first attempt reaches just the
    // replica (p0); the fallback then locates primary KDCs only.
    let prof = Profile::parse(&format!(
        "[realms]\nR = {{\nkdc = 127.0.0.1:{p0}\n\
         primary_kdc = 127.0.0.1:{p1}\n}}\n"
    ))
    .unwrap();
    let t = LocatedTransport::with_config(Arc::new(prof), None, fast_cfg());
    let r = get_tgt(&t, "R", b"as-req").await;
    assert_eq!(r.unwrap(), b"AS-REP");
    let used = t.kdcs_used();
    // First attempt used the replica (port p0); primary retry used p1.
    assert!(used.iter().any(|(_, e)| e.port == p0));
    assert!(used.iter().any(|(_, e)| e.port == p1));
    assert!(!t.use_primary());
}
