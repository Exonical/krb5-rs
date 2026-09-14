// ---------------------------------------------------------------------------
// Section 3: pass structure and transport strategies (k5_sendto,
// sendto_kdc.c:1537-1600).  Timing: per_server=60ms, tail=120ms,
// backoff=240ms, max_pass=3; tolerance +-50%.
// ---------------------------------------------------------------------------

fn accept_all() -> impl Fn(&[u8]) -> bool + Sync {
    |_| true
}

fn kinds(log: &Log) -> Vec<(String, Kind)> {
    log.lock()
        .unwrap()
        .iter()
        .map(|r| (r.server.clone(), r.kind.clone()))
        .collect()
}

#[tokio::test]
async fn udp_first_udp_answers() {
    // UdpFirst + TcpOrUdp server answering on UDP -> Udp reply; the TCP
    // side is never contacted.
    let log = new_log();
    let (port, _) = spawn_udp(log.clone(), "s0", Some(b"UDP-REPLY".to_vec())).await;
    spawn_tcp(log.clone(), "s0", TcpAction::Reply(Duration::ZERO, b"TCP".to_vec()), port).await;
    let servers = vec![entry(port, Transport::TcpOrUdp)];
    let r = sendto(&servers, b"req", Strategy::UdpFirst, &fast_cfg(), &accept_all())
        .await
        .unwrap();
    assert_eq!(r.data, b"UDP-REPLY");
    assert_eq!((r.server_index, r.transport), (0, Transport::Udp));
    assert_eq!(kinds(&log), vec![("s0".to_string(), Kind::Udp)]);
}

#[tokio::test]
async fn udp_first_tcp_deferred() {
    // Server 0 silent on UDP, answers on TCP: TCP connect happens only after
    // the non-deferred pass completes (>= per_server after the UDP send).
    let log = new_log();
    let (port, _) = spawn_udp(log.clone(), "s0", None).await;
    spawn_tcp(
        log.clone(),
        "s0",
        TcpAction::Reply(Duration::ZERO, b"TCP-REPLY".to_vec()),
        port,
    )
    .await;
    let servers = vec![entry(port, Transport::TcpOrUdp)];
    let r = sendto(&servers, b"req", Strategy::UdpFirst, &fast_cfg(), &accept_all())
        .await
        .unwrap();
    assert_eq!(r.data, b"TCP-REPLY");
    assert_eq!(r.transport, Transport::Tcp);
    let l = log.lock().unwrap();
    let udp_t = l.iter().find(|r| r.kind == Kind::Udp).unwrap().at;
    let tcp_t = l.iter().find(|r| r.kind == Kind::Tcp).unwrap().at;
    assert!(tcp_t.duration_since(udp_t) >= Duration::from_millis(30));
}

#[tokio::test]
async fn udp_retransmit_passes() {
    // Two TcpOrUdp servers, UDP silent and TCP refused: UDP receptions in
    // order s0,s1 | s0,s1 | s0,s1 (3 passes); elapsed ~= 1200ms; KdcUnreach.
    let log = new_log();
    let mut servers = Vec::new();
    for name in ["s0", "s1"] {
        let (port, _) = spawn_udp(log.clone(), name, None).await;
        // No TCP listener -> connect refused quickly.
        servers.push(entry(port, Transport::TcpOrUdp));
    }
    let t0 = Instant::now();
    let r = sendto(&servers, b"req", Strategy::UdpFirst, &fast_cfg(), &accept_all()).await;
    let el = t0.elapsed();
    assert!(matches!(r, Err(SendtoError::KdcUnreach)));
    assert_eq!(
        kinds(&log),
        vec![
            ("s0".to_string(), Kind::Udp),
            ("s1".to_string(), Kind::Udp),
            ("s0".to_string(), Kind::Udp),
            ("s1".to_string(), Kind::Udp),
            ("s0".to_string(), Kind::Udp),
            ("s1".to_string(), Kind::Udp),
        ]
    );
    // 2*60 + 120 + (2*60 + 240) + (2*60 + 480) = 1200ms nominal.
    assert!(
        el >= Duration::from_millis(600) && el <= Duration::from_millis(2400),
        "elapsed {el:?}"
    );
}

#[tokio::test]
async fn udp_last_tcp_contacted_first() {
    // Message over the limit -> UdpLast: TCP attempted before any UDP send;
    // TCP refused -> deferred UDP then answers.
    let log = new_log();
    let (port, cnt) = spawn_udp(log.clone(), "s0", Some(b"UDP-OK".to_vec())).await;
    // No TCP listener on `port`.
    let servers = vec![entry(port, Transport::TcpOrUdp)];
    let r = sendto(&servers, &vec![0u8; 2000], Strategy::UdpLast, &fast_cfg(), &accept_all())
        .await
        .unwrap();
    assert_eq!(r.data, b"UDP-OK");
    assert_eq!(r.transport, Transport::Udp);
    // Exactly one UDP send needed (TCP refused fast, then deferred UDP).
    assert_eq!(cnt.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn no_udp_skips_udp_entries() {
    // NoUdp: Udp-only entry never contacted; TcpOrUdp's TCP used.
    let log = new_log();
    let (uport, ucnt) = spawn_udp(log.clone(), "s0", Some(b"NO".to_vec())).await;
    let tport = spawn_tcp(
        log.clone(),
        "s1",
        TcpAction::Reply(Duration::ZERO, b"TCP-OK".to_vec()),
        0,
    )
    .await;
    let servers = vec![
        entry(uport, Transport::Udp),
        entry(tport, Transport::TcpOrUdp),
    ];
    let r = sendto(&servers, b"req", Strategy::NoUdp, &fast_cfg(), &accept_all())
        .await
        .unwrap();
    assert_eq!(r.data, b"TCP-OK");
    assert_eq!((r.server_index, r.transport), (1, Transport::Tcp));
    assert_eq!(ucnt.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn deferred_conns_contacted_serially() {
    // sendto_kdc.c:1563-1571: deferred conns are contacted one at a time
    // with a per_server wait after each — the second deferred TCP connect
    // trails the first by ~per_server, not simultaneous.
    let log = new_log();
    let mut servers = Vec::new();
    for name in ["s0", "s1"] {
        // Both accept-and-hang; request_timeout bounds the request.
        let port = spawn_tcp(
            log.clone(),
            name,
            TcpAction::Reply(Duration::from_secs(30), b"x".to_vec()),
            0,
        )
        .await;
        servers.push(entry(port, Transport::Tcp));
    }
    let mut cfg = fast_cfg();
    cfg.request_timeout = Some(Duration::from_millis(250));
    // UdpFirst -> both Tcp entries are deferred.
    let r = sendto(&servers, b"req", Strategy::UdpFirst, &cfg, &accept_all()).await;
    assert!(matches!(r, Err(SendtoError::KdcUnreach)));
    // The second conn's task is spawned just before the deadline; give it
    // a moment to complete the connect+accept.
    tokio::time::sleep(Duration::from_millis(100)).await;
    let l = log.lock().unwrap();
    let t0 = l.iter().find(|r| r.server == "s0").unwrap().at;
    let t1 = l.iter().find(|r| r.server == "s1").unwrap().at;
    assert!(t1.duration_since(t0) >= Duration::from_millis(30));
}

#[tokio::test]
async fn request_timeout_clips() {
    // request_timeout=150ms, all silent -> KdcUnreach, elapsed ~=150ms,
    // and at most a couple of UDP sends per server (deadline clips waits).
    let log = new_log();
    let mut servers = Vec::new();
    let mut counts = Vec::new();
    for name in ["s0", "s1"] {
        let (port, c) = spawn_udp(log.clone(), name, None).await;
        servers.push(entry(port, Transport::Udp));
        counts.push(c);
    }
    let mut cfg = fast_cfg();
    cfg.request_timeout = Some(Duration::from_millis(150));
    let t0 = Instant::now();
    let r = sendto(&servers, b"req", Strategy::UdpFirst, &cfg, &accept_all()).await;
    let el = t0.elapsed();
    assert!(matches!(r, Err(SendtoError::KdcUnreach)));
    assert!(
        el >= Duration::from_millis(75) && el <= Duration::from_millis(450),
        "elapsed {el:?}"
    );
    assert!(counts[0].load(Ordering::SeqCst) <= 2);
}
