//! The `dns` hostrealm module (MIT lib/krb5/os/hostrealm_dns.c,
//! dnsglue.c k5_try_realm_txt_rr) against a fake resolver.
#![allow(clippy::unwrap_used)]

use std::collections::HashMap;
use std::sync::Mutex;

use krb5_rs::locate::{
    get_default_realm_with_dns, get_fallback_host_realm_with_dns, get_host_realm, DnsResolver,
    SrvRecord, UriRecord,
};
use krb5_rs::profile::Profile;

#[derive(Default)]
struct Txt {
    calls: Mutex<Vec<String>>,
    records: HashMap<String, Vec<String>>,
}

impl Txt {
    fn with(records: &[(&str, &str)]) -> Txt {
        Txt {
            calls: Mutex::default(),
            records: records
                .iter()
                .map(|(n, r)| (n.to_string(), vec![r.to_string()]))
                .collect(),
        }
    }
    fn calls(&self) -> Vec<String> {
        self.calls.lock().unwrap().clone()
    }
}

impl DnsResolver for Txt {
    fn srv(&self, _: &str) -> Result<Vec<SrvRecord>, ()> {
        Ok(vec![])
    }
    fn uri(&self, _: &str) -> Result<Vec<UriRecord>, ()> {
        Ok(vec![])
    }
    fn txt(&self, name: &str) -> Result<Vec<String>, ()> {
        self.calls.lock().unwrap().push(name.to_string());
        self.records.get(name).cloned().ok_or(())
    }
}

fn profile(libdefaults: &str) -> Profile {
    Profile::parse(&format!("[libdefaults]\n{libdefaults}\n")).unwrap()
}

#[test]
fn fallback_walks_parent_domains() {
    // txt_lookup (hostrealm_dns.c:47-60): _kerberos.<host>. and each
    // parent; one trailing dot of the answer is dropped (dnsglue.c:487-489).
    let dns = Txt::with(&[("_kerberos.example.com.", "EXAMPLE.COM.")]);
    let p = profile(" dns_lookup_realm = true");
    let r = get_fallback_host_realm_with_dns(&p, "Host.Sub.Example.COM.", Some(&dns)).unwrap();
    assert_eq!(r, vec!["EXAMPLE.COM".to_string()]);
    assert_eq!(
        dns.calls(),
        [
            "_kerberos.host.sub.example.com.",
            "_kerberos.sub.example.com.",
            "_kerberos.example.com."
        ]
    );
}

#[test]
fn fallback_without_answer_uses_domain_module() {
    let dns = Txt::default();
    let p = profile(" dns_lookup_realm = true");
    let r = get_fallback_host_realm_with_dns(&p, "a.b.c", Some(&dns)).unwrap();
    assert_eq!(r, vec!["B.C".to_string()]);
    assert_eq!(
        dns.calls(),
        ["_kerberos.a.b.c.", "_kerberos.b.c.", "_kerberos.c."]
    );
}

#[test]
fn dns_lookup_realm_setting() {
    // _krb5_use_dns_realm (locate_kdc.c:51-73, 95-99): default false;
    // dns_fallback applies only when dns_lookup_realm is unset.
    let dns = Txt::with(&[("_kerberos.b.c.", "TXT.REALM")]);
    for (conf, used) in [
        ("", false),
        (" dns_lookup_realm = false", false),
        (" dns_fallback = true", true),
        (" dns_lookup_realm = false\n dns_fallback = true", false),
        (" dns_lookup_realm = true\n dns_fallback = false", true),
    ] {
        let r = get_fallback_host_realm_with_dns(&profile(conf), "b.c", Some(&dns)).unwrap();
        let want = if used { "TXT.REALM" } else { "C" };
        assert_eq!(r, vec![want.to_string()], "{conf:?}");
    }
}

#[test]
fn numeric_addresses_are_not_looked_up() {
    let dns = Txt::default();
    let p = profile(" dns_lookup_realm = true\n default_realm = D");
    for host in ["10.0.0.1", "::1"] {
        let r = get_fallback_host_realm_with_dns(&p, host, Some(&dns)).unwrap();
        assert_eq!(r, vec!["D".to_string()]);
    }
    assert!(dns.calls().is_empty());
}

#[test]
fn default_realm_from_local_host_then_global_record() {
    // dns_default_realm (hostrealm_dns.c:83-110): the local host's
    // domains, then the bare "_kerberos" name for the search list.
    let dns = Txt::with(&[("_kerberos", "GLOBAL.REALM")]);
    let p = profile(" dns_lookup_realm = true");
    assert_eq!(
        get_default_realm_with_dns(&p, Some(&dns)).unwrap(),
        "GLOBAL.REALM"
    );
    let calls = dns.calls();
    assert_eq!(calls.last().map(String::as_str), Some("_kerberos"));
    assert!(calls[..calls.len() - 1]
        .iter()
        .all(|c| c.starts_with("_kerberos.") && c.ends_with('.')));

    // default_realm comes from the profile module first.
    let p = profile(" dns_lookup_realm = true\n default_realm = PROFILE");
    let dns = Txt::with(&[("_kerberos", "GLOBAL.REALM")]);
    assert_eq!(
        get_default_realm_with_dns(&p, Some(&dns)).unwrap(),
        "PROFILE"
    );
    assert!(dns.calls().is_empty());
}

#[test]
fn disabled_module_and_no_resolver_decline() {
    let dns = Txt::with(&[("_kerberos.b.c.", "TXT.REALM")]);
    let p = Profile::parse(
        "[libdefaults]\n dns_lookup_realm = true\n\
         [plugins]\n hostrealm = {\n  disable = dns\n }\n",
    )
    .unwrap();
    let r = get_fallback_host_realm_with_dns(&p, "b.c", Some(&dns)).unwrap();
    assert_eq!(r, vec!["C".to_string()]);
    assert!(dns.calls().is_empty());

    let p = profile(" dns_lookup_realm = true");
    let r = get_fallback_host_realm_with_dns(&p, "b.c", None).unwrap();
    assert_eq!(r, vec!["C".to_string()]);
}

#[test]
fn host_realm_has_no_dns_step() {
    // The dns module has no host_realm method (hostrealm_dns.c:123-127).
    let p = profile(" dns_lookup_realm = true");
    assert_eq!(get_host_realm(&p, "a.b.c").unwrap(), vec![String::new()]);
}

/// HickoryResolver's TXT query, outside and inside a tokio runtime.
#[cfg(feature = "dns")]
#[test]
#[ignore = "needs network access to public DNS"]
fn hickory_txt_live() {
    let dns = krb5_rs::locate::HickoryResolver::new().unwrap();
    let p = profile(" dns_lookup_realm = true");
    let r = get_fallback_host_realm_with_dns(&p, "www.mit.edu", Some(&dns)).unwrap();
    assert_eq!(r, vec!["ATHENA.MIT.EDU".to_string()]);
    let rt = tokio::runtime::Runtime::new().unwrap();
    let r = rt.block_on(async { get_fallback_host_realm_with_dns(&p, "mit.edu", Some(&dns)) });
    assert_eq!(r.unwrap(), vec!["ATHENA.MIT.EDU".to_string()]);
}
