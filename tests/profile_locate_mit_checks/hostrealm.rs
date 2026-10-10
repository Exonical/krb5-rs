// ---------------------------------------------------------------------------
// Section 2: host->realm mapping (hostrealm_profile.c, hostrealm_domain.c;
// oracle = t_std_conf + td_krb5.conf + ref_std_conf.out)
// ---------------------------------------------------------------------------

#[test]
fn hostrealm_default_realm_and_domain() {
    let p = td_profile();
    assert_eq!(default_realm(&p).as_deref(), Some("DEFAULT.REALM.TST"));
    assert_eq!(
        realm_domain(&p, "DEFAULT_REALM.TST").as_deref(),
        Some("MIT.EDU")
    );
    assert_eq!(realm_domain(&p, "NO.SUCH"), None);
}

#[test]
fn hostrealm_domain_realm_lookups() {
    // Expected outputs from ref_std_conf.out.
    let p = td_profile();
    assert_eq!(host_realm(&p, "bad.idea"), vec!["US.GOV"]);
    // Suffix search hits ".bad.idea" first: the loop passes the pointer AT
    // the dot (hostrealm_profile.c:58-62).
    assert_eq!(host_realm(&p, "itar.bad.idea"), vec!["NSA.GOV"]);
    // Case-insensitive + trailing dot stripped (hostrealm.c lowercases).
    assert_eq!(host_realm(&p, "really.BAD.IDEA."), vec!["NSA.GOV"]);
    // Exact match beats suffix match.
    assert_eq!(host_realm(&p, "clipper.bad.idea"), vec!["NIST.GOV"]);
    assert_eq!(host_realm(&p, "KeYEsCrOW.BaD.IDEa"), vec!["NSA.GOV"]);
    // Unmapped -> the referral realm "" shown as '' in ref_std_conf.out
    // (hostrealm.c:391-393).
    assert_eq!(host_realm(&p, "pgp.good.idea"), vec![""]);
    assert_eq!(host_realm(&p, "no_domain"), vec![""]);
    // Numeric addresses never map (hostrealm_profile.c:59-61).
    assert_eq!(host_realm(&p, "10.0.0.1"), vec![""]);
    assert_eq!(host_realm(&p, "1.2.3.4:88"), vec![""]);
    assert_eq!(host_realm(&p, "[2001:db8::1]"), vec![""]);
}

#[test]
fn hostrealm_fallback_realm() {
    // krb5_get_fallback_host_realm (hostrealm.c:401-447): domain module
    // (hostrealm_domain.c:59-104), then the default realm.

    // Default realm_try_domains=-1: suffix search off, but the
    // upper-cased parent domain is always used when the host has a dot.
    let p = Profile::parse("[libdefaults]\ndefault_realm = DFLT\n").unwrap();
    assert_eq!(fallback_host_realm(&p, "pgp.good.idea"), vec!["GOOD.IDEA"]);

    // limit=0: try only the full domain as a realm (locatable -> wins).
    let p = Profile::parse(
        "[libdefaults]\nrealm_try_domains = 0\n[realms]\nPGP.GOOD.IDEA = {\n\tkdc = x\n}\n",
    )
    .unwrap();
    assert_eq!(fallback_host_realm(&p, "pgp.good.idea"), vec!["PGP.GOOD.IDEA"]);

    // limit=1: also tries the parent domain; GOOD.IDEA is locatable.
    let p = Profile::parse(
        "[libdefaults]\nrealm_try_domains = 1\n[realms]\nGOOD.IDEA = {\n\tkdc = x\n}\n",
    )
    .unwrap();
    assert_eq!(fallback_host_realm(&p, "pgp.good.idea"), vec!["GOOD.IDEA"]);

    // Single-label host and numeric address: domain module declines,
    // so the default realm is returned (hostrealm.c:437-441).
    let p = td_profile();
    assert_eq!(fallback_host_realm(&p, "no_domain"), vec!["DEFAULT.REALM.TST"]);
    assert_eq!(fallback_host_realm(&p, "10.0.0.1"), vec!["DEFAULT.REALM.TST"]);
}
