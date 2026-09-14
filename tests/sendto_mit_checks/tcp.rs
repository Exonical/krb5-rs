// ---------------------------------------------------------------------------
// Section 4: TCP connection behaviour (sendto_kdc.c:1100-1220, 1389-1470)
// ---------------------------------------------------------------------------

fn accept_all2() -> impl Fn(&[u8]) -> bool + Sync {
    |_| true
}

#[tokio::test]
async fn tcp_established_slow_reply_no_retransmit() {
    // any_tcp_connections: while a TCP conn is in WRITING/READING the waits
    // are unbounded, so a slow-but-connected TCP server still replies, and
    // no retransmits or contacts to the other server occur.  UdpLast makes
    // the TCP entry the non-deferred one so it is contacted first.
    let log = new_log();
    let slow = Duration::from_millis(5 * 60);
    let tport = spawn_tcp(
        log.clone(),
        "s0",
        TcpAction::Reply(slow, b"SLOW-OK".to_vec()),
        0,
    )
    .await;
    let (uport, ucnt) = spawn_udp(log.clone(), "s1", Some(b"NO".to_vec())).await;
    let servers = vec![
        entry(tport, Transport::Tcp),
        entry(uport, Transport::Udp),
    ];
    let r = sendto(&servers, b"req", Strategy::UdpLast, &fast_cfg(), &accept_all2())
        .await
        .unwrap();
    assert_eq!(r.data, b"SLOW-OK");
    assert_eq!(r.transport, Transport::Tcp);
    // Second server never contacted while TCP was established.
    assert_eq!(ucnt.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn tcp_close_after_read_falls_through() {
    // TCP server closes after reading the request -> conn killed; server 1
    // (UDP) answers and is returned.
    let log = new_log();
    let tport = spawn_tcp(log.clone(), "s0", TcpAction::CloseAfterRead, 0).await;
    let (uport, _) = spawn_udp(log.clone(), "s1", Some(b"UDP-WIN".to_vec())).await;
    let servers = vec![entry(tport, Transport::Tcp), entry(uport, Transport::Udp)];
    let r = sendto(&servers, b"req", Strategy::UdpFirst, &fast_cfg(), &accept_all2())
        .await
        .unwrap();
    assert_eq!(r.data, b"UDP-WIN");
    assert_eq!((r.server_index, r.transport), (1, Transport::Udp));
}

#[tokio::test]
async fn tcp_oversize_reply_kills_conn() {
    // TCP 4-byte BE length > 1 MiB -> connection killed (sendto_kdc.c
    // MAX_KRB5_MESSAGE_LENGTH); nothing else -> KdcUnreach.
    let log = new_log();
    let tport = spawn_tcp(
        log.clone(),
        "s0",
        TcpAction::HugeLen,
        0,
    )
    .await;
    let servers = vec![entry(tport, Transport::Tcp)];
    let r = sendto(&servers, b"req", Strategy::NoUdp, &fast_cfg(), &accept_all2()).await;
    assert!(matches!(r, Err(SendtoError::KdcUnreach)));
}
