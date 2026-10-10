// ---------------------------------------------------------------------------
// Section 4: profile-based KDC location (locate_kdc.c prof_locate_server /
// locate_srv_conf_1; dns disabled via Locator { dns: None })
// ---------------------------------------------------------------------------

fn loc(p: &Profile) -> Locator<'_> {
    Locator::new(p, None)
}

fn hostport(e: &ServerEntry) -> (&str, u16) {
    (e.hostname.as_str(), e.port)
}

#[test]
fn locate_profile_kdcs() {
    // td_krb5.conf: locate_kdc DEFAULT_REALM.TST -> the two kdc entries,
    // port 88, TCP_OR_UDP transport (locate_kdc.c:347).
    let p = td_profile();
    let l = loc(&p);
    let v = l.locate_kdc("DEFAULT_REALM.TST", false, false).unwrap();
    assert_eq!(v.len(), 2);
    assert_eq!(hostport(&v[0]), ("FIRST.KDC.HOST", 88));
    assert_eq!(hostport(&v[1]), ("SECOND.KDC.HOST", 88));
    assert!(v.iter().all(|e| e.transport == Transport::TcpOrUdp));
    assert!(v.iter().all(|e| e.primary.is_none() && e.uri_path.is_none()));

    let v = l.locate_kdc("IGGY.ORG", false, false).unwrap();
    assert_eq!(hostport(&v[0]), ("KERBEROS.IGGY.ORG", 88));
    assert_eq!(hostport(&v[1]), ("KERBEROS-B.IGGY.ORG", 88));
}

#[test]
fn locate_errors() {
    let p = td_profile();
    let l = loc(&p);
    // Empty realm -> KRB5_REALM_CANT_RESOLVE (locate_kdc.c:861-865).
    assert!(matches!(
        l.locate_kdc("", false, false),
        Err(LocateError::RealmCantResolve)
    ));
    // Unknown realm, no DNS -> KRB5_REALM_UNKNOWN (locate_kdc.c:871-876).
    assert!(matches!(
        l.locate_kdc("NO.SUCH.REALM", false, false),
        Err(LocateError::RealmUnknown)
    ));
}

#[test]
fn locate_primary_kdc_master_fallback() {
    // locate_srv_conf_1:278-282 - master_kdc only when primary_kdc absent.
    let p = Profile::parse("[realms]\nR = {\n\tmaster_kdc = m:1088\n}\n").unwrap();
    let v = loc(&p).locate_kdc("R", true, false).unwrap();
    assert_eq!(hostport(&v[0]), ("m", 1088));

    let p = Profile::parse(
        "[realms]\nR = {\n\tprimary_kdc = p:1088\n\tmaster_kdc = m:1088\n}\n",
    )
    .unwrap();
    let v = loc(&p).locate_kdc("R", true, false).unwrap();
    assert_eq!(v.len(), 1);
    assert_eq!(hostport(&v[0]), ("p", 1088));
}

#[test]
fn locate_service_default_ports() {
    // td_krb5 admin_server = FIRST.KDC.HOST -> DEFAULT_KADM5_PORT 749;
    // kpasswd default 464 (locate_kdc.c:559,569).
    let p = td_profile();
    let l = loc(&p);
    let v = l
        .locate_server("DEFAULT_REALM.TST", LocateService::Kadmin, false)
        .unwrap();
    assert_eq!(hostport(&v[0]), ("FIRST.KDC.HOST", 749));

    let p = Profile::parse("[realms]\nR = {\n\tkpasswd_server = kp\n}\n").unwrap();
    let v = loc(&p)
        .locate_server("R", LocateService::Kpasswd, false)
        .unwrap();
    assert_eq!(hostport(&v[0]), ("kp", 464));
}

#[test]
fn locate_profile_entry_forms() {
    // https:// URI: transport HTTPS, default port 443, path split
    // (parse_uri_if_https locate_kdc.c:217-232).
    let p =
        Profile::parse("[realms]\nR = {\n\tkdc = https://proxy.example.com/KdcProxy\n}\n")
            .unwrap();
    let v = loc(&p).locate_kdc("R", false, false).unwrap();
    assert_eq!(v.len(), 1);
    assert_eq!(v[0].transport, Transport::Https);
    assert_eq!(hostport(&v[0]), ("proxy.example.com", 443));
    assert_eq!(v[0].uri_path.as_deref(), Some("/KdcProxy"));

    // Bracketed IPv6 with port.
    let p = Profile::parse("[realms]\nR = {\n\tkdc = [2001:db8::1]:89\n}\n").unwrap();
    let v = loc(&p).locate_kdc("R", false, false).unwrap();
    assert_eq!(hostport(&v[0]), ("2001:db8::1", 89));

    // Numeric-only spec parses to host NULL -> EINVAL
    // (locate_kdc.c:319-321).
    let p = Profile::parse("[realms]\nR = {\n\tkdc = 88\n}\n").unwrap();
    assert!(matches!(
        loc(&p).locate_kdc("R", false, false),
        Err(LocateError::Invalid(_))
    ));

    // UNIX socket path: hostname preserved verbatim
    // (locate_kdc.c:298-313; we represent it as a host entry).
    let p = Profile::parse("[realms]\nR = {\n\tkdc = /var/run/krb5kdc.sock\n}\n").unwrap();
    let v = loc(&p).locate_kdc("R", false, false).unwrap();
    assert_eq!(v[0].hostname, "/var/run/krb5kdc.sock");
}

#[test]
fn locate_no_udp_does_not_filter_profile_entries() {
    // The transport argument sets profile entry transport but does not
    // filter them (locate_kdc.c:801-806 comment).
    let p = td_profile();
    let l = loc(&p);
    let v = l.locate_kdc("DEFAULT_REALM.TST", false, true).unwrap();
    assert_eq!(v.len(), 2);
    assert!(v.iter().all(|e| e.transport == Transport::Tcp));
}
