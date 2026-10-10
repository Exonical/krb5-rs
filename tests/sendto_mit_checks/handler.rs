// ---------------------------------------------------------------------------
// Section 5: accept callback + sendto_kdc service-unavailable handling
// (sendto_kdc.c:396-417, 446-540)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn accept_false_moves_to_next_server() {
    // accept()==false kills the conn; the next server is contacted and its
    // reply returned.
    let log = new_log();
    let (p0, _) = spawn_udp(log.clone(), "s0", Some(b"BAD".to_vec())).await;
    let (p1, _) = spawn_udp(log.clone(), "s1", Some(b"GOOD".to_vec())).await;
    let servers = vec![entry(p0, Transport::Udp), entry(p1, Transport::Udp)];
    let accept = |b: &[u8]| b == b"GOOD";
    let r = sendto(&servers, b"req", Strategy::UdpFirst, &fast_cfg(), &accept)
        .await
        .unwrap();
    assert_eq!(r.data, b"GOOD");
    assert_eq!(r.server_index, 1);
}

#[tokio::test]
async fn sendto_kdc_svc_unavailable_skips() {
    // check_for_svc_unavailable: KRB-ERROR error 29 is not acceptable; the
    // next KDC is contacted and its reply returned.
    let log = new_log();
    let (p0, _) = spawn_udp(log.clone(), "s0", Some(krb_error(29))).await;
    let (p1, _) = spawn_udp(log.clone(), "s1", Some(b"REAL".to_vec())).await;
    let servers = vec![entry(p0, Transport::Udp), entry(p1, Transport::Udp)];
    let r = sendto_kdc(&servers, b"req", false, &fast_cfg()).await.unwrap();
    assert_eq!(r.data, b"REAL");
    assert_eq!(r.server_index, 1);
}

#[tokio::test]
async fn sendto_kdc_svc_unavailable_propagates() {
    // All KDCs fail, last was svc-unavailable -> SendtoError::SvcUnavailable
    // (sendto_kdc.c:536-540).
    let log = new_log();
    let (p0, _) = spawn_udp(log.clone(), "s0", Some(krb_error(29))).await;
    let (p1, _) = spawn_udp(log.clone(), "s1", None).await;
    let servers = vec![entry(p0, Transport::Udp), entry(p1, Transport::Udp)];
    let r = sendto_kdc(&servers, b"req", false, &fast_cfg()).await;
    assert!(matches!(r, Err(SendtoError::SvcUnavailable)));
}

#[tokio::test]
async fn sendto_kdc_other_errors_accepted() {
    // KRB-ERROR with any code other than 29 IS acceptable and returned.
    let log = new_log();
    let (p0, _) = spawn_udp(log.clone(), "s0", Some(krb_error(25))).await;
    let servers = vec![entry(p0, Transport::Udp)];
    let r = sendto_kdc(&servers, b"req", false, &fast_cfg()).await.unwrap();
    assert_eq!(r.data, krb_error(25));
}

#[tokio::test]
async fn sendto_kdc_non_error_data_accepted() {
    let log = new_log();
    let (p0, _) = spawn_udp(log.clone(), "s0", Some(b"\x6b\x03garbage".to_vec())).await;
    let servers = vec![entry(p0, Transport::Udp)];
    let r = sendto_kdc(&servers, b"req", false, &fast_cfg()).await.unwrap();
    assert_eq!(r.data, b"\x6b\x03garbage");
}
