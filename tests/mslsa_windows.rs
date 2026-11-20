//! The MSLSA ccache against the Windows LSA (cc_mslsa.c). Run on Windows
//! with `KRB5RS_MSLSA_FIXTURE` naming a FILE ccache (a TGT and a service
//! ticket) and `--ignored`; it replaces the logon session's tickets.
#![cfg(windows)]

use krb5_rs::ccache::{
    new_unique, resolve, unparse_name, AnyCcache, CcContext, CcError, Ccache, FileCcache,
    MatchCred, MatchFlags,
};

fn lsa(ctx: &CcContext) -> AnyCcache {
    resolve(ctx, "MSLSA:").expect("resolve MSLSA")
}

#[test]
#[ignore = "replaces the logon session's LSA tickets"]
fn mslsa_round_trip() {
    let path = std::env::var("KRB5RS_MSLSA_FIXTURE").expect("KRB5RS_MSLSA_FIXTURE");
    let file = FileCcache::new(path);
    let (client, crealm) = file.principal().expect("fixture principal");
    let fixture = file.creds().expect("fixture creds");
    let ctx = CcContext::from_env(None);

    let mut cc = lsa(&ctx);
    assert_eq!(cc.name(), "MSLSA:");
    assert!(new_unique(&ctx, "MSLSA").is_err());
    cc.initialize(&client, &crealm).expect("initialize");
    for c in &fixture {
        cc.store(c).expect("store");
    }

    let cc = lsa(&ctx);
    assert_eq!(
        cc.principal().expect("principal"),
        (client.clone(), crealm.clone())
    );
    let listed = cc.creds().expect("creds");
    for c in &fixture {
        let name = unparse_name(&c.server, &c.srealm);
        let l = listed
            .iter()
            .find(|l| l.server == c.server && l.srealm == c.srealm)
            .unwrap_or_else(|| panic!("{name} not listed"));
        assert_eq!(l.ticket, c.ticket, "{name} ticket");
        assert_eq!(l.keyblock.keytype, c.keyblock.keytype, "{name} enctype");
        assert_eq!(l.endtime, c.endtime, "{name} endtime");
        let m = MatchCred {
            client: Some((client.clone(), crealm.clone())),
            server: Some((c.server.clone(), c.srealm.clone())),
            ..Default::default()
        };
        let r = cc
            .retrieve(MatchFlags::empty(), &m, None)
            .expect("retrieve");
        assert_eq!(r.ticket, c.ticket, "{name} retrieved ticket");
    }

    let mut cc = lsa(&ctx);
    let svc = fixture
        .iter()
        .find(|c| !unparse_name(&c.server, &c.srealm).starts_with("krbtgt/"))
        .expect("service ticket");
    let m = MatchCred {
        client: Some((client.clone(), crealm.clone())),
        server: Some((svc.server.clone(), svc.srealm.clone())),
        ..Default::default()
    };
    cc.remove_cred(MatchFlags::empty(), &m)
        .expect("remove_cred");
    let listed = cc.creds().expect("creds after remove");
    assert!(!listed.iter().any(|l| l.server == svc.server));

    cc.destroy().expect("destroy");
    assert!(matches!(lsa(&ctx).creds(), Err(CcError::NotFound)));
}
