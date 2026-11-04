//! Cache selection like MIT krb5_cc_select, ported from MIT
//! tests/gssapi/t_ccselect.py. One test, since `.k5identity` is read from
//! `HOME`.

use krb5_rs::ccache::*;
use krb5_rs::profile::Profile;
use krb5_rs::types::*;
use rasn::types::GeneralString;

fn name(t: i32, parts: &[&str]) -> PrincipalName {
    PrincipalName {
        name_type: t,
        name_string: parts
            .iter()
            .map(|p| GeneralString::from_bytes(p.as_bytes()).unwrap())
            .collect(),
    }
}

fn client(
    cc: &CcContext,
    p: &Profile,
    server: &PrincipalName,
    srealm: &str,
) -> Result<String, CcError> {
    let c = select_cache(cc, Some(p), server, srealm)?;
    let (n, r) = c.principal()?;
    Ok(unparse_name(&n, &r))
}

fn profile(defrealm: &str, extra: &str) -> Profile {
    Profile::parse(&format!(
        "[libdefaults]\n default_realm = {defrealm}\n dns_canonicalize_hostname = false\n{extra}"
    ))
    .unwrap()
}

#[test]
fn ccselect_like_mit_t_ccselect() {
    let base = std::env::temp_dir().join(format!("krb5rs-ccselect-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(&base).unwrap();
    // Use .k5identity from the test directory, not the tester's home.
    std::env::set_var("HOME", &base);
    let cc = CcContext {
        default_name: Some(format!("DIR:{}", base.join("cc").display())),
        ..Default::default()
    };
    let r1 = profile("KRBTEST.COM", "");
    let r2 = profile("KRBTEST2.COM", "");

    let host1 = name(1, &["host", "localhost"]);
    let gss = |h: &str| name(3, &["host", h]);

    // No credentials in the collection.
    assert!(client(&cc, &r1, &host1, "KRBTEST.COM").is_err());
    assert!(matches!(
        cc_select(&cc, Some(&r1), &host1, "KRBTEST.COM"),
        Err(CcError::Code {
            name: "KRB5_CC_NOTFOUND",
            ..
        })
    ));

    // alice in r1, zaphod in r2 (primary).
    let mut alice = new_unique(&cc, "DIR").unwrap();
    alice
        .initialize(&name(1, &["alice"]), "KRBTEST.COM")
        .unwrap();
    let mut zaphod = default_cache(&cc).unwrap();
    zaphod
        .initialize(&name(1, &["zaphod"]), "KRBTEST2.COM")
        .unwrap();

    // Guess a cache from the service realm.
    assert_eq!(
        client(&cc, &r1, &host1, "KRBTEST.COM").unwrap(),
        "alice@KRBTEST.COM"
    );
    let host2 = name(1, &["host", "localhost"]);
    assert_eq!(
        client(&cc, &r2, &host2, "KRBTEST2.COM").unwrap(),
        "zaphod@KRBTEST2.COM"
    );

    // The primary cache is used when the server realm is unknown.
    assert_eq!(client(&cc, &r2, &host1, "").unwrap(), "zaphod@KRBTEST2.COM");
    assert_eq!(client(&cc, &r1, &host1, "").unwrap(), "zaphod@KRBTEST2.COM");

    // Fallback realm: the upper-cased parent domain.
    assert_eq!(
        client(&cc, &r1, &gss("foo.krbtest.com"), "").unwrap(),
        "alice@KRBTEST.COM"
    );
    assert_eq!(
        client(&cc, &r2, &gss("foo.krbtest2.com"), "").unwrap(),
        "zaphod@KRBTEST2.COM"
    );
    // Fallback realm: the default realm for a single-label host.
    assert_eq!(
        client(&cc, &r1, &gss("localhost"), "").unwrap(),
        "alice@KRBTEST.COM"
    );
    assert_eq!(
        client(&cc, &r2, &gss("localhost"), "").unwrap(),
        "zaphod@KRBTEST2.COM"
    );
    // BAR.KRBTEST.COM has no cache; the hostname module picks the longest
    // matching domain.
    assert_eq!(
        client(&cc, &r1, &gss("foo.bar.krbtest.com"), "").unwrap(),
        "alice@KRBTEST.COM"
    );

    // A second r1 user (bob) as the primary cache.
    let mut bob = new_unique(&cc, "DIR").unwrap();
    bob.initialize(&name(1, &["bob"]), "KRBTEST.COM").unwrap();
    bob.switch_to().unwrap();

    std::fs::write(
        base.join(".k5identity"),
        "alice@KRBTEST.COM realm=KRBTEST.COM\n\
         zaphod@KRBTEST2.COM service=ho*t host=localhost\n\
         noprinc service=bogus",
    )
    .unwrap();
    assert_eq!(
        client(&cc, &r1, &host1, "KRBTEST.COM").unwrap(),
        "alice@KRBTEST.COM"
    );
    assert_eq!(
        client(&cc, &r2, &gss("localhost"), "").unwrap(),
        "zaphod@KRBTEST2.COM"
    );
    assert_eq!(client(&cc, &r1, &host1, "").unwrap(), "bob@KRBTEST.COM");
    let err = client(&cc, &r1, &name(3, &["bogus", "foo.krbtest2.com"]), "").unwrap_err();
    assert!(
        err.to_string()
            .contains("Can't find client principal noprinc"),
        "{err}"
    );

    // [plugins] ccselect disable and enable_only, as for every MIT plugin
    // interface.
    let no_k5id = profile(
        "KRBTEST.COM",
        "[plugins]\n ccselect = {\n  disable = k5identity\n }\n",
    );
    assert_eq!(
        client(&cc, &no_k5id, &name(3, &["bogus", "foo.krbtest2.com"]), "").unwrap(),
        "zaphod@KRBTEST2.COM"
    );
    // The hostname module takes the first longest match; the primary
    // cache (bob) comes first in the collection.
    let only_host = profile(
        "KRBTEST.COM",
        "[plugins]\n ccselect = {\n  enable_only = hostname\n }\n",
    );
    assert!(matches!(
        cc_select(&cc, Some(&only_host), &host1, "KRBTEST.COM"),
        Err(CcError::Code {
            name: "KRB5_CC_NOTFOUND",
            ..
        })
    ));
    assert_eq!(
        client(&cc, &only_host, &gss("foo.krbtest.com"), "").unwrap(),
        "bob@KRBTEST.COM"
    );

    let _ = std::fs::remove_dir_all(&base);
}
