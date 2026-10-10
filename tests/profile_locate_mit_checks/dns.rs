// ---------------------------------------------------------------------------
// Section 5: DNS URI/SRV discovery (dnssrv.c, locate_kdc.c locate_uri /
// dns_locate_server_srv) with an injected fake resolver.
// ---------------------------------------------------------------------------

use std::collections::HashMap;
use std::sync::Mutex;

struct FakeResolver {
    calls: Mutex<Vec<String>>,
    srv: HashMap<String, Result<Vec<SrvRecord>, ()>>,
    uri: HashMap<String, Result<Vec<UriRecord>, ()>>,
}

impl FakeResolver {
    fn new() -> Self {
        FakeResolver {
            calls: Mutex::new(Vec::new()),
            srv: HashMap::new(),
            uri: HashMap::new(),
        }
    }
    fn calls(&self) -> Vec<String> {
        self.calls.lock().unwrap().clone()
    }
}

fn srvrec(priority: u16, port: u16, target: &str) -> SrvRecord {
    SrvRecord {
        priority,
        weight: 0,
        port,
        target: target.into(),
    }
}

fn urirec(priority: u16, target: &str) -> UriRecord {
    UriRecord {
        priority,
        weight: 0,
        target: target.into(),
    }
}

impl DnsResolver for FakeResolver {
    fn srv(&self, name: &str) -> Result<Vec<SrvRecord>, ()> {
        self.calls.lock().unwrap().push(format!("srv {name}"));
        match self.srv.get(name) {
            Some(Ok(v)) => Ok(v.clone()),
            Some(Err(())) => Err(()),
            None => Ok(vec![]),
        }
    }
    fn uri(&self, name: &str) -> Result<Vec<UriRecord>, ()> {
        self.calls.lock().unwrap().push(format!("uri {name}"));
        match self.uri.get(name) {
            Some(Ok(v)) => Ok(v.clone()),
            Some(Err(())) => Err(()),
            None => Ok(vec![]),
        }
    }
}

#[test]
fn dns_make_lookup_name() {
    // dnssrv.c:50-78.
    assert_eq!(
        make_lookup_name("EXAMPLE.COM", "_kerberos", Some("_udp"), None).as_deref(),
        Some("_kerberos._udp.EXAMPLE.COM.")
    );
    assert_eq!(
        make_lookup_name("EXAMPLE.COM", "_kerberos", Some("_udp"), Some("nyc"))
            .as_deref(),
        Some("_kerberos._udp.nyc._sites.EXAMPLE.COM.")
    );
    // Realm already ending in '.' isn't doubled.
    assert_eq!(
        make_lookup_name("EXAMPLE.COM.", "_kerberos", Some("_udp"), None).as_deref(),
        Some("_kerberos._udp.EXAMPLE.COM.")
    );
    // NUL inside realm -> None (dnssrv.c:56-57).
    assert_eq!(
        make_lookup_name("A\0B", "_kerberos", Some("_udp"), None),
        None
    );
    // URI query name has no protocol component (dnssrv.c:202).
    assert_eq!(
        make_lookup_name("EXAMPLE.COM", "_kerberos", None, None).as_deref(),
        Some("_kerberos.EXAMPLE.COM.")
    );
}

#[test]
fn dns_sort_srv_stable_by_priority() {
    // place_srv_entry (dnssrv.c:82-105): ascending priority, equal
    // priorities keep insertion order.
    let v = sort_srv(vec![
        srvrec(10, 88, "a"),
        srvrec(5, 88, "b"),
        srvrec(10, 88, "c"),
        srvrec(1, 88, "d"),
    ]);
    let order: Vec<&str> = v.iter().map(|r| r.target.as_str()).collect();
    assert_eq!(order, vec!["d", "b", "a", "c"]);
}

#[test]
fn dns_uri_records() {
    // URI query answered -> used, SRV never queried (locate_kdc.c:829-836).
    let p = Profile::parse("[realms]\nEXAMPLE.COM = {\n}\n").unwrap();
    let mut r = FakeResolver::new();
    r.uri.insert(
        "_kerberos.EXAMPLE.COM.".into(),
        Ok(vec![
            urirec(0, "krb5srv:m:tcp:kdc1.example.com:89"),
            urirec(0, "krb5srv::udp:kdc2.example.com"),
            urirec(0, "krb5srv:M:kkdcp:https://proxy.example.com/KdcProxy"),
            urirec(0, "junk"),
            urirec(0, "krb5srv::foo:x"),
        ]),
    );
    let l = Locator::new(&p, Some(&r));
    let v = l.locate_kdc("EXAMPLE.COM", false, false).unwrap();
    assert_eq!(v.len(), 3);
    assert_eq!(v[0].hostname, "kdc1.example.com");
    assert_eq!(v[0].transport, Transport::Tcp);
    assert_eq!(v[0].port, 89);
    assert_eq!(v[0].primary, Some(true));
    assert_eq!(v[1].hostname, "kdc2.example.com");
    assert_eq!(v[1].transport, Transport::Udp);
    assert_eq!(v[1].port, 88);
    assert_eq!(v[1].primary, Some(false));
    assert_eq!(v[2].hostname, "proxy.example.com");
    assert_eq!(v[2].transport, Transport::Https);
    assert_eq!(v[2].port, 443);
    assert_eq!(v[2].uri_path.as_deref(), Some("/KdcProxy"));
    assert_eq!(v[2].primary, Some(true));
    assert_eq!(r.calls(), vec!["uri _kerberos.EXAMPLE.COM.".to_string()]);
}

#[test]
fn dns_srv_fallback() {
    // URI empty -> SRV _udp then _tcp (dns_locate_server_srv
    // locate_kdc.c:787-792); each answer list priority-sorted; SRV targets
    // keep the trailing dot MIT appends (dnssrv.c:332).
    let p = Profile::parse("[realms]\nEXAMPLE.COM = {\n}\n").unwrap();
    let mut r = FakeResolver::new();
    r.srv.insert(
        "_kerberos._udp.EXAMPLE.COM.".into(),
        Ok(vec![srvrec(10, 89, "kdc-b"), srvrec(0, 88, "kdc-a")]),
    );
    r.srv.insert(
        "_kerberos._tcp.EXAMPLE.COM.".into(),
        Ok(vec![srvrec(5, 88, "kdc-c")]),
    );
    let l = Locator::new(&p, Some(&r));
    let v = l.locate_kdc("EXAMPLE.COM", false, false).unwrap();
    let got: Vec<(&str, u16, Transport)> = v
        .iter()
        .map(|e| (e.hostname.as_str(), e.port, e.transport))
        .collect();
    assert_eq!(
        got,
        vec![
            ("kdc-a.", 88, Transport::Udp),
            ("kdc-b.", 89, Transport::Udp),
            ("kdc-c.", 88, Transport::Tcp),
        ]
    );
    assert_eq!(
        r.calls(),
        vec![
            "uri _kerberos.EXAMPLE.COM.".to_string(),
            "srv _kerberos._udp.EXAMPLE.COM.".to_string(),
            "srv _kerberos._tcp.EXAMPLE.COM.".to_string()
        ]
    );
}

#[test]
fn dns_srv_no_service_dot() {
    // Single "." answer -> KRB5_ERR_NO_SERVICE (locate_kdc.c:379-383).
    let p = Profile::parse("[realms]\nEXAMPLE.COM = {\n}\n").unwrap();
    let mut r = FakeResolver::new();
    r.srv.insert(
        "_kerberos._udp.EXAMPLE.COM.".into(),
        Ok(vec![srvrec(0, 0, "")]),
    );
    let l = Locator::new(&p, Some(&r));
    assert!(matches!(
        l.locate_kdc("EXAMPLE.COM", false, false),
        Err(LocateError::NoService)
    ));
}

#[test]
fn dns_disabled_variants() {
    // dns_lookup_kdc = false -> no DNS calls, REALM_UNKNOWN.
    let p = Profile::parse(
        "[libdefaults]\ndns_lookup_kdc = false\n[realms]\nEXAMPLE.COM = {\n}\n",
    )
    .unwrap();
    let r = FakeResolver::new();
    let l = Locator::new(&p, Some(&r));
    assert!(matches!(
        l.locate_kdc("EXAMPLE.COM", false, false),
        Err(LocateError::RealmUnknown)
    ));
    assert!(r.calls().is_empty());

    // dns_lookup_kdc absent + dns_fallback = false -> same
    // (maybe_use_dns, locate_kdc.c:51-73).
    let p =
        Profile::parse("[libdefaults]\ndns_fallback = false\n[realms]\nEXAMPLE.COM = {\n}\n")
            .unwrap();
    let r = FakeResolver::new();
    let l = Locator::new(&p, Some(&r));
    assert!(matches!(
        l.locate_kdc("EXAMPLE.COM", false, false),
        Err(LocateError::RealmUnknown)
    ));
    assert!(r.calls().is_empty());

    // dns_uri_lookup = false -> SRV only (use_dns_uri, locate_kdc.c:76-85).
    let p = Profile::parse(
        "[libdefaults]\ndns_uri_lookup = false\n[realms]\nEXAMPLE.COM = {\n}\n",
    )
    .unwrap();
    let mut r = FakeResolver::new();
    r.srv.insert(
        "_kerberos._udp.EXAMPLE.COM.".into(),
        Ok(vec![srvrec(0, 88, "kdc-a")]),
    );
    let l = Locator::new(&p, Some(&r));
    l.locate_kdc("EXAMPLE.COM", false, false).unwrap();
    assert!(r.calls().iter().all(|c| c.starts_with("srv ")));
}

#[test]
fn dns_sitename_retry() {
    // First query includes sitename; retry without site ONLY on query
    // failure (dnssrv.c:288-294), not on an empty answer.
    let p = Profile::parse("[realms]\nEXAMPLE.COM = {\n\tsitename = nyc\n}\n").unwrap();

    let mut r = FakeResolver::new();
    r.srv.insert(
        "_kerberos._udp.nyc._sites.EXAMPLE.COM.".into(),
        Err(()),
    );
    r.srv.insert(
        "_kerberos._udp.EXAMPLE.COM.".into(),
        Ok(vec![srvrec(0, 88, "kdc-a")]),
    );
    let l = Locator::new(&p, Some(&r));
    let v = l.locate_kdc("EXAMPLE.COM", false, false).unwrap();
    assert!(!v.is_empty());
    assert!(r
        .calls()
        .contains(&"srv _kerberos._udp.nyc._sites.EXAMPLE.COM.".to_string()));
    assert!(r
        .calls()
        .contains(&"srv _kerberos._udp.EXAMPLE.COM.".to_string()));

    // Successful-but-empty answer -> no retry.
    let r = FakeResolver::new();
    let l = Locator::new(&p, Some(&r));
    l.locate_kdc("EXAMPLE.COM", false, false).ok();
    assert!(!r
        .calls()
        .iter()
        .any(|c| c == "srv _kerberos._udp.EXAMPLE.COM."));
}

#[test]
fn dns_no_udp_and_primary() {
    // no_udp -> TCP only (locate_kdc.c:788-792); PrimaryKdc queries
    // _kerberos-master (locate_kdc.c:771-772).
    let p = Profile::parse("[realms]\nEXAMPLE.COM = {\n}\n").unwrap();
    let mut r = FakeResolver::new();
    r.srv.insert(
        "_kerberos._tcp.EXAMPLE.COM.".into(),
        Ok(vec![srvrec(0, 88, "kdc-c")]),
    );
    let l = Locator::new(&p, Some(&r));
    l.locate_kdc("EXAMPLE.COM", false, true).unwrap();
    assert_eq!(r.calls().iter().filter(|c| c.starts_with("srv ")).count(), 1);
    assert!(r.calls().contains(&"srv _kerberos._tcp.EXAMPLE.COM.".to_string()));

    let mut r = FakeResolver::new();
    r.srv.insert(
        "_kerberos-master._udp.EXAMPLE.COM.".into(),
        Ok(vec![srvrec(0, 88, "m")]),
    );
    let l = Locator::new(&p, Some(&r));
    l.locate_kdc("EXAMPLE.COM", true, false).unwrap();
    assert!(r
        .calls()
        .contains(&"srv _kerberos-master._udp.EXAMPLE.COM.".to_string()));
}

#[test]
fn dns_uri_primary_not_filtered() {
    // MIT passes primary_only to locate_uri but never consults it inside
    // the loop (locate_kdc.c:651-711) -- non-primary URI records are still
    // returned for a PrimaryKdc query.
    let p = Profile::parse("[realms]\nEXAMPLE.COM = {\n}\n").unwrap();
    let mut r = FakeResolver::new();
    r.uri.insert(
        "_kerberos.EXAMPLE.COM.".into(),
        Ok(vec![
            urirec(0, "krb5srv:m:tcp:kdc1.example.com:89"),
            urirec(0, "krb5srv::udp:kdc2.example.com"),
        ]),
    );
    let l = Locator::new(&p, Some(&r));
    let v = l.locate_kdc("EXAMPLE.COM", true, false).unwrap();
    assert_eq!(v.len(), 2);
}
