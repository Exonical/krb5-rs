// ---------------------------------------------------------------------------
// Section 1: strategy selection + udp_preference_limit (sendto_kdc.c:474-495)
// ---------------------------------------------------------------------------

#[test]
fn strategy_selection() {
    assert_eq!(strategy_for(1465, false, 1465), Strategy::UdpFirst);
    assert_eq!(strategy_for(1466, false, 1465), Strategy::UdpLast);
    assert_eq!(strategy_for(1, true, 1465), Strategy::NoUdp);
    assert_eq!(strategy_for(99999, true, 1465), Strategy::NoUdp);
}

#[test]
fn udp_pref_limit_clamps() {
    // sendto_kdc.c:481-488: <0 -> default 1465; >32700 -> 32700.
    assert_eq!(udp_pref_limit(None), 1465);
    assert_eq!(udp_pref_limit(Some(-5)), 1465);
    assert_eq!(udp_pref_limit(Some(40000)), 32700);
    assert_eq!(udp_pref_limit(Some(100)), 100);
}
