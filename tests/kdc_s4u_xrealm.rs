#![cfg(feature = "kdc")]
//! Cross-realm S4U2Self and S4U2Proxy driven by our client through two
//! in-process KDCs (MIT s4u_creds.c, t_s4u.py "cross-realm S4U2Self"). As in
//! MIT's tests, the user realm resolves the service's enterprise name with a
//! KDB alias to its TGT for the service realm (plugins/kdb/test/kdb_test.c);
//! db2 and LMDB have no such aliases.

use std::collections::BTreeMap;

use krb5_rs::kdc::{
    Kdc, KdcConfig, MemoryStore, PrincipalAttributes, PrincipalEntry, PrincipalStore, StoreError,
    StoreErrorKind,
};
use krb5_rs::profile::Profile;
use krb5_rs::protocol::ap::decrypt_ticket;
use krb5_rs::protocol::{
    AsExchange, AsExchangeConfig, Credential, StepResult, TgsExchange, TgsOptions, TgsStepResult,
};
use krb5_rs::types::{EncryptionKey, PrincipalName};
use krb5_rs::Krb5Error;
use rasn::types::GeneralString;

const SREALM: &str = "S.REALM";
const UREALM: &str = "U.REALM";
const PASSWORD: &str = "s4u-password";
const TRUST_PW: &str = "crosstrust";

fn gs(s: &str) -> GeneralString {
    GeneralString::from_bytes(s.as_bytes()).expect("ascii")
}

fn tgs_name(realm: &str) -> PrincipalName {
    PrincipalName {
        name_type: 2,
        name_string: vec![gs("krbtgt"), gs(realm)],
    }
}

fn host_service(host: &str) -> PrincipalName {
    PrincipalName {
        name_type: 3,
        name_string: vec![gs("HTTP"), gs(host)],
    }
}

fn service() -> PrincipalName {
    host_service("svc.s.realm")
}

fn target() -> PrincipalName {
    host_service("target.u.realm")
}

/// The single-component name `kdb_test.c` aliases are keyed by.
fn enterprise(name: &str) -> PrincipalName {
    PrincipalName {
        name_type: 10,
        name_string: vec![gs(name)],
    }
}

/// A `MemoryStore` with `kdb_test.c`-style aliases (`alias = { name = target }`).
#[derive(Default)]
struct AliasStore {
    inner: MemoryStore,
    /// Alias, target name, target realm (another realm: a client referral).
    aliases: Vec<(PrincipalName, PrincipalName, Option<String>)>,
    /// Whether `lookup_s4u_x509` is implemented (db2/LMDB: no).
    x509: bool,
}

impl PrincipalStore for AliasStore {
    async fn lookup(
        &self,
        name: &PrincipalName,
        realm: &str,
    ) -> Result<Option<PrincipalEntry>, StoreError> {
        match self
            .aliases
            .iter()
            .find(|(alias, _, _)| alias.name_string == name.name_string)
        {
            Some((_, target, r)) => {
                self.inner
                    .lookup(target, r.as_deref().unwrap_or(realm))
                    .await
            }
            None => self.inner.lookup(name, realm).await,
        }
    }

    /// `test_get_s4u_x509_principal` (kdb_test.c:500-556): the
    /// "certificate" is a principal name, parsed as an enterprise name.
    async fn lookup_s4u_x509(
        &self,
        cert: &[u8],
        name: &PrincipalName,
        realm: &str,
        referral_ok: bool,
    ) -> Result<Option<PrincipalEntry>, StoreError> {
        if !self.x509 {
            return Err(StoreError::new(StoreErrorKind::Unsupported, "no x509"));
        }
        let text = String::from_utf8_lossy(cert);
        let (n, r) = text.rsplit_once('@').unwrap_or((&text, realm));
        let Some(entry) = self.lookup(&enterprise(n), r).await? else {
            return Ok(None);
        };
        if referral_ok || name.name_string.is_empty() || entry.name.name_string == name.name_string
        {
            return Ok(Some(entry));
        }
        let alias = self.aliases.iter().any(|(a, t, _)| {
            a.name_string == name.name_string && t.name_string == entry.name.name_string
        });
        if alias {
            Ok(Some(entry))
        } else {
            Err(StoreError::new(StoreErrorKind::NameMismatch, "mismatch"))
        }
    }
}

fn key(store: &MemoryStore, name: &PrincipalName, realm: &str) -> EncryptionKey {
    store.get(name, realm).expect("entry").keys[0].key.clone()
}

struct World {
    kdcs: BTreeMap<String, Kdc<AliasStore>>,
    service_key: EncryptionKey,
    target_key: EncryptionKey,
}

/// S.REALM holds the impersonating service, U.REALM the user and the
/// delegation target; the realms trust each other both ways.
fn world(enterprise_alias: bool, rbcd: bool) -> World {
    world_x509(enterprise_alias, rbcd, true)
}

fn world_x509(enterprise_alias: bool, rbcd: bool, x509: bool) -> World {
    let none = PrincipalAttributes::empty();
    let mut s = AliasStore {
        x509,
        ..AliasStore::default()
    };
    let mut u = AliasStore {
        x509,
        ..AliasStore::default()
    };
    for (store, realm) in [(&mut s, SREALM), (&mut u, UREALM)] {
        store
            .inner
            .add_random_key(tgs_name(realm), realm, 1, &[18, 17], none)
            .expect("krbtgt");
        for (issuing, target) in [(SREALM, UREALM), (UREALM, SREALM)] {
            store
                .inner
                .add_with_password(tgs_name(target), issuing, TRUST_PW, 1, &[18, 17], none)
                .expect("trust");
        }
    }
    s.inner
        .add_with_password(service(), SREALM, PASSWORD, 1, &[18, 17], none)
        .expect("service");
    s.inner
        .add_with_password(
            PrincipalName::new_principal("alice"),
            SREALM,
            PASSWORD,
            1,
            &[18, 17],
            none,
        )
        .expect("alice");
    s.inner
        .add_with_password(
            PrincipalName::new_principal("other"),
            SREALM,
            PASSWORD,
            1,
            &[18, 17],
            PrincipalAttributes::REQUIRES_PRE_AUTH,
        )
        .expect("other");
    let preauth = PrincipalAttributes::REQUIRES_PRE_AUTH;
    for (store, realm) in [(&mut u.inner, UREALM), (&mut s.inner, UREALM)] {
        store
            .add_with_password(
                PrincipalName::new_principal("xuser"),
                realm,
                PASSWORD,
                1,
                &[18, 17],
                preauth,
            )
            .expect("xuser");
    }
    // t_s4u.py "cross-realm S4U2Self with enterprise name": S.REALM refers
    // the enterprise user to U.REALM, which resolves it to xuser.
    s.aliases.push((
        enterprise("enterprise@abc"),
        PrincipalName::new_principal("xuser"),
        Some(UREALM.into()),
    ));
    u.aliases.push((
        enterprise("enterprise@abc"),
        PrincipalName::new_principal("xuser"),
        None,
    ));
    u.inner
        .add_random_key(target(), UREALM, 1, &[18, 17], none)
        .expect("target");
    if rbcd {
        let mut e = u.inner.get(&target(), UREALM).expect("target");
        e.allowed_to_delegate_from = vec![format!("HTTP/svc.s.realm@{SREALM}")];
        u.inner.insert(e);
    }
    if enterprise_alias {
        // t_s4u.py kdcconf2: the service's enterprise name refers to SREALM.
        u.aliases.push((
            enterprise(&format!("HTTP/svc.s.realm@{SREALM}")),
            tgs_name(SREALM),
            None,
        ));
    }
    let service_key = key(&s.inner, &service(), SREALM);
    let target_key = key(&u.inner, &target(), UREALM);
    let mut kdcs = BTreeMap::new();
    for (realm, store, profile) in [
        (SREALM, s, "[domain_realm]\n .u.realm = U.REALM\n"),
        (UREALM, u, "[domain_realm]\n .s.realm = S.REALM\n"),
    ] {
        let mut config = KdcConfig::new(realm);
        config.realm_profile = Some(Profile::parse(profile).expect("profile"));
        kdcs.insert(realm.to_string(), Kdc::new(config, store));
    }
    World {
        kdcs,
        service_key,
        target_key,
    }
}

impl World {
    async fn send(&self, realm: &str, data: &[u8]) -> Vec<u8> {
        self.kdcs
            .get(realm)
            .unwrap_or_else(|| panic!("no KDC for {realm}"))
            .handle(data)
            .await
    }

    async fn login(&self, name: PrincipalName) -> Credential {
        let mut config = AsExchangeConfig::new(name, SREALM);
        config.request_pac = true;
        let mut ex = AsExchange::new(config, PASSWORD);
        let mut reply = Vec::new();
        while let StepResult::SendToKdc { data, .. } | StepResult::RetryTcp { data, .. } =
            ex.step(&reply).expect("AS step")
        {
            reply = self.send(SREALM, &data).await;
        }
        ex.credential().expect("TGT").clone()
    }

    /// Run an exchange, returning its result and the realms it sent to.
    async fn run(&self, mut ex: TgsExchange) -> (Result<Credential, Krb5Error>, Vec<String>) {
        let mut realms = Vec::new();
        let mut reply = Vec::new();
        for _ in 0..32 {
            match ex.step(&reply) {
                Ok(TgsStepResult::SendToKdc { data, realm })
                | Ok(TgsStepResult::RetryTcp { data, realm }) => {
                    reply = self.send(&realm, &data).await;
                    realms.push(realm);
                }
                Ok(TgsStepResult::Complete) => {
                    return (Ok(ex.credential().expect("credential").clone()), realms)
                }
                Err(e) => return (Err(e), realms),
            }
        }
        panic!("exchange did not finish");
    }
}

fn kdc_code(r: &Result<Credential, Krb5Error>) -> i32 {
    match r {
        Err(Krb5Error::KdcError(m)) => m.error_code,
        other => panic!("expected KDC error, got {other:?}"),
    }
}

#[tokio::test]
async fn s4u2self_for_a_foreign_user_gets_the_user_realm_tgt_and_follows_the_referral() {
    let w = world(true, false);
    let tgt = w.login(service()).await;
    let (cred, realms) = w
        .run(TgsExchange::s4u2self(
            tgt,
            PrincipalName::new_principal("xuser"),
            UREALM,
            TgsOptions::default(),
        ))
        .await;
    let cred = cred.expect("cross-realm S4U2Self");
    // krbtgt/U.REALM from S.REALM, the enterprise-name request to U.REALM,
    // then the real service name back in S.REALM (t_s4u.py trace).
    assert_eq!(realms, [SREALM, UREALM, SREALM]);
    assert_eq!(cred.client, PrincipalName::new_principal("xuser"));
    assert_eq!(cred.crealm, UREALM);
    assert_eq!(cred.server.name_string, service().name_string);
    assert_eq!(cred.srealm, SREALM);
    let part = decrypt_ticket(&w.service_key, &cred.ticket).expect("decrypt");
    assert_eq!(part.crealm.as_bytes(), UREALM.as_bytes());
}

#[tokio::test]
async fn s4u2self_with_a_user_realm_tgt_skips_the_tgt_request() {
    let w = world(true, false);
    let tgt = w.login(service()).await;
    let (xtgt, _) = w
        .run(TgsExchange::new(
            tgt,
            tgs_name(UREALM),
            TgsOptions::default(),
        ))
        .await;
    let (cred, realms) = w
        .run(TgsExchange::s4u2self(
            xtgt.expect("cross-realm TGT"),
            PrincipalName::new_principal("xuser"),
            UREALM,
            TgsOptions::default(),
        ))
        .await;
    cred.expect("cross-realm S4U2Self");
    assert_eq!(realms, [UREALM, SREALM]);
}

#[tokio::test]
async fn s4u2self_without_an_enterprise_alias_is_unknown_in_the_user_realm() {
    // A db2/LMDB user realm cannot refer the enterprise name, in MIT as here.
    let w = world(false, false);
    let tgt = w.login(service()).await;
    let (r, realms) = w
        .run(TgsExchange::s4u2self(
            tgt,
            PrincipalName::new_principal("xuser"),
            UREALM,
            TgsOptions::default(),
        ))
        .await;
    assert_eq!(kdc_code(&r), 7);
    assert_eq!(realms, [SREALM, UREALM]);
}

async fn evidence(w: &World) -> (Credential, Credential) {
    let tgt = w.login(service()).await;
    let (evidence, _) = w
        .run(TgsExchange::s4u2self(
            tgt.clone(),
            PrincipalName::new_principal("alice"),
            SREALM,
            TgsOptions::default(),
        ))
        .await;
    (tgt, evidence.expect("S4U2Self"))
}

#[tokio::test]
async fn s4u2proxy_follows_the_proxy_referral_into_the_target_realm() {
    let w = world(false, true);
    let (tgt, evidence) = evidence(&w).await;
    let (cred, realms) = w
        .run(TgsExchange::s4u2proxy(
            tgt,
            evidence,
            target(),
            TgsOptions::default(),
        ))
        .await;
    let cred = cred.expect("cross-realm S4U2Proxy");
    // The proxy referral, the TGT to U.REALM (a referral, then the target
    // ticket it discards), then the final request with the proxy TGT.
    assert_eq!(realms, [SREALM, SREALM, UREALM, UREALM]);
    assert_eq!(cred.client, PrincipalName::new_principal("alice"));
    assert_eq!(cred.crealm, SREALM);
    assert_eq!(cred.server.name_string, target().name_string);
    assert_eq!(cred.srealm, UREALM);
    let part = decrypt_ticket(&w.target_key, &cred.ticket).expect("decrypt");
    assert_eq!(part.crealm.as_bytes(), SREALM.as_bytes());
}

#[tokio::test]
async fn s4u2proxy_into_a_target_without_rbcd_entry_is_refused() {
    let w = world(false, false);
    let (tgt, evidence) = evidence(&w).await;
    let (r, realms) = w
        .run(TgsExchange::s4u2proxy(
            tgt,
            evidence,
            target(),
            TgsOptions::default(),
        ))
        .await;
    assert_eq!(kdc_code(&r), 13);
    assert_eq!(realms, [SREALM, SREALM, UREALM, UREALM]);
}

#[cfg(feature = "client")]
mod client_layer {
    use super::*;
    use krb5_rs::ccache::{CcCredential, CcError, Ccache, MatchCred, MatchFlags, MemoryCcache};
    use krb5_rs::client::{CredsRequest, GcOptions, HostCanonicalization, KerberosClient};
    use krb5_rs::transport::KdcTransport;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    type Log = Arc<std::sync::Mutex<Vec<Vec<u8>>>>;

    struct Route(Arc<World>, Arc<AtomicUsize>, Log);

    impl KdcTransport for Route {
        async fn send_recv(&self, realm: &str, message: &[u8]) -> Result<Vec<u8>, Krb5Error> {
            self.1.fetch_add(1, Ordering::SeqCst);
            self.2.lock().expect("log").push(message.to_vec());
            Ok(self.0.send(realm, message).await)
        }
    }

    fn client(w: &Arc<World>) -> (KerberosClient<Route>, Arc<AtomicUsize>) {
        let (client, sends, _) = logged_client(w);
        (client, sends)
    }

    fn logged_client(w: &Arc<World>) -> (KerberosClient<Route>, Arc<AtomicUsize>, Log) {
        let sends = Arc::new(AtomicUsize::new(0));
        let log = Log::default();
        let route = Route(Arc::clone(w), Arc::clone(&sends), Arc::clone(&log));
        (KerberosClient::new(SREALM, route), sends, log)
    }

    /// (sname components, etypes) of each TGS-REQ in `log`.
    fn tgs_requests(log: &Log) -> Vec<(Vec<String>, Vec<i32>)> {
        log.lock()
            .expect("log")
            .iter()
            .filter_map(|m| rasn::der::decode::<krb5_rs::types::TgsReq>(m).ok())
            .map(|r| {
                let body = r.0.req_body;
                let sname = body
                    .sname
                    .map(|n| {
                        n.name_string
                            .iter()
                            .map(|g| String::from_utf8_lossy(g.as_bytes()).into_owned())
                            .collect()
                    })
                    .unwrap_or_default();
                (sname, body.etype)
            })
            .collect()
    }

    /// The service's ccache, holding its TGT (as after `kinit -k`).
    fn service_ccache(tgt: &Credential) -> MemoryCcache {
        let mut cc = MemoryCcache::new();
        cc.initialize(&service(), SREALM).expect("initialize");
        cc.store(&CcCredential::from(tgt)).expect("store TGT");
        cc
    }

    fn servers(cc: &MemoryCcache) -> Vec<(Vec<String>, String)> {
        cc.creds()
            .expect("creds")
            .iter()
            .map(|c| {
                (
                    c.server
                        .name_string
                        .iter()
                        .map(|g| String::from_utf8_lossy(g.as_bytes()).into_owned())
                        .collect(),
                    c.srealm.clone(),
                )
            })
            .collect()
    }

    fn xuser() -> CredsRequest {
        CredsRequest::new(
            PrincipalName::new_principal("xuser"),
            UREALM,
            service(),
            SREALM,
        )
    }

    #[tokio::test]
    async fn s4u2self_stores_the_user_realm_tgt_and_the_ticket_then_hits_the_cache() {
        let w = Arc::new(world(true, false));
        let mut cc = service_ccache(&w.login(service()).await);
        let (client, sends) = client(&w);
        let cred = client
            .get_credentials_for_user(&mut cc, GcOptions::empty(), &xuser(), None)
            .await
            .expect("S4U2Self");
        assert_eq!(cred.client, PrincipalName::new_principal("xuser"));
        assert_eq!(cred.crealm, UREALM);
        let svc = |n: &PrincipalName| -> Vec<String> {
            n.name_string
                .iter()
                .map(|g| String::from_utf8_lossy(g.as_bytes()).into_owned())
                .collect()
        };
        assert_eq!(
            servers(&cc),
            [
                (svc(&tgs_name(SREALM)), SREALM.to_string()),
                (svc(&tgs_name(UREALM)), SREALM.to_string()),
                (svc(&service()), SREALM.to_string()),
            ]
        );
        let used = sends.load(Ordering::SeqCst);
        let again = client
            .get_credentials_for_user(&mut cc, GcOptions::empty(), &xuser(), None)
            .await
            .expect("cached S4U2Self");
        assert_eq!(sends.load(Ordering::SeqCst), used);
        assert_eq!(again.session_key.key_bytes(), cred.session_key.key_bytes());
        assert_eq!(cc.creds().expect("creds").len(), 3);
    }

    #[tokio::test]
    async fn get_credentials_stores_the_cross_realm_tgt_and_hits_the_cache() {
        let w = Arc::new(world(false, false));
        let mut cc = service_ccache(&w.login(service()).await);
        let (client, sends) = client(&w);
        let req = CredsRequest::new(service(), SREALM, target(), UREALM);
        let r = client
            .get_credentials(&mut cc, GcOptions::CACHED, &req)
            .await;
        assert!(
            matches!(r, Err(Krb5Error::Ccache(CcError::NotFound))),
            "{r:?}"
        );
        assert_eq!(sends.load(Ordering::SeqCst), 0);
        let cred = client
            .get_credentials(&mut cc, GcOptions::empty(), &req)
            .await
            .expect("cross-realm service ticket");
        assert_eq!(cred.srealm, UREALM);
        let svc = |n: &PrincipalName| -> Vec<String> {
            n.name_string
                .iter()
                .map(|g| String::from_utf8_lossy(g.as_bytes()).into_owned())
                .collect()
        };
        // get_creds.c:951-954: the TGT for the server realm is cached.
        assert_eq!(
            servers(&cc),
            [
                (svc(&tgs_name(SREALM)), SREALM.to_string()),
                (svc(&tgs_name(UREALM)), SREALM.to_string()),
                (svc(&target()), UREALM.to_string()),
            ]
        );
        let used = sends.load(Ordering::SeqCst);
        let again = client
            .get_credentials(&mut cc, GcOptions::CACHED, &req)
            .await
            .expect("cached service ticket");
        assert_eq!(again.session_key.key_bytes(), cred.session_key.key_bytes());
        // A second service in U.REALM reuses the cached cross-realm TGT.
        let none = CredsRequest::new(service(), SREALM, target(), UREALM);
        let mut no_store = MemoryCcache::new();
        no_store.initialize(&service(), SREALM).expect("initialize");
        for c in cc.creds().expect("creds").iter().take(2) {
            no_store.store(c).expect("store");
        }
        client
            .get_credentials(&mut no_store, GcOptions::NO_STORE, &none)
            .await
            .expect("from the cached cross-realm TGT");
        assert_eq!(sends.load(Ordering::SeqCst), used + 1);
        assert_eq!(no_store.creds().expect("creds").len(), 2);
    }

    #[tokio::test]
    async fn get_credentials_requests_only_the_requested_enctype() {
        let w = Arc::new(world(false, false));
        let mut cc = service_ccache(&w.login(service()).await);
        let (client, sends) = client(&w);
        let mut req = CredsRequest::new(service(), SREALM, target(), UREALM);
        req.enctype = 17;
        let cred = client
            .get_credentials(&mut cc, GcOptions::empty(), &req)
            .await
            .expect("service ticket");
        assert_eq!(cred.session_key.keytype, 17);
        let used = sends.load(Ordering::SeqCst);
        let again = client
            .get_credentials(&mut cc, GcOptions::CACHED, &req)
            .await
            .expect("cached aes128 ticket");
        assert_eq!(again.session_key.keytype, 17);
        assert_eq!(sends.load(Ordering::SeqCst), used);
    }

    // s4u_creds.c: get_tgt_to_target_realm asks for TGTs without
    // in_creds, so only the proxy requests carry the requested enctype.
    #[tokio::test]
    async fn s4u2proxy_tgt_requests_keep_the_configured_enctypes() {
        let w = Arc::new(world(false, true));
        let (tgt, evidence) = super::evidence(&w).await;
        let mut cc = service_ccache(&tgt);
        let (client, _, log) = logged_client(&w);
        let mut req = CredsRequest::new(evidence.client.clone(), SREALM, target(), UREALM);
        req.enctype = 17;
        client
            .get_credentials_for_proxy(&mut cc, GcOptions::empty(), &req, &evidence)
            .await
            .expect("S4U2Proxy");
        let configured = krb5_rs::protocol::TgsOptions::default().etypes;
        // The proxy request, get_tgt_to_target_realm's referral and the
        // target ticket it discards, then the final proxy request.
        let etypes: Vec<Vec<i32>> = tgs_requests(&log).into_iter().map(|(_, e)| e).collect();
        assert_eq!(etypes, [vec![17], configured.clone(), configured, vec![17]]);
    }

    #[tokio::test]
    async fn s4u_requests_only_the_requested_enctype() {
        let w = Arc::new(world(true, true));
        let mut cc = service_ccache(&w.login(service()).await);
        let (client, _) = client(&w);
        let mut req = xuser();
        req.enctype = 17;
        let evidence = client
            .get_credentials_for_user(&mut cc, GcOptions::empty(), &req, None)
            .await
            .expect("S4U2Self");
        assert_eq!(evidence.session_key.keytype, 17);
        let (_, evidence) = super::evidence(&w).await;
        let mut proxy = CredsRequest::new(evidence.client.clone(), SREALM, target(), UREALM);
        proxy.enctype = 17;
        let cred = client
            .get_credentials_for_proxy(&mut cc, GcOptions::empty(), &proxy, &evidence)
            .await
            .expect("S4U2Proxy");
        assert_eq!(cred.session_key.keytype, 17);
    }

    #[tokio::test]
    async fn get_credentials_requests_authdata_and_matches_it_in_the_cache() {
        use krb5_rs::types::AuthorizationDataElement;
        let w = Arc::new(world(false, false));
        let mut cc = service_ccache(&w.login(service()).await);
        let (client, sends) = client(&w);
        let mut req = CredsRequest::new(service(), SREALM, target(), UREALM);
        let ad = vec![AuthorizationDataElement {
            ad_type: 1,
            ad_data: vec![0x30, 0x00].into(),
        }];
        req.authdata = Some(ad);
        let cred = client
            .get_credentials(&mut cc, GcOptions::empty(), &req)
            .await
            .expect("service ticket with authdata");
        assert_eq!(cred.authdata.as_ref().map(Vec::len), Some(1));
        let used = sends.load(Ordering::SeqCst);
        client
            .get_credentials(&mut cc, GcOptions::CACHED, &req)
            .await
            .expect("matches the requested authdata");
        let plain = CredsRequest::new(service(), SREALM, target(), UREALM);
        let r = client
            .get_credentials(&mut cc, GcOptions::CACHED, &plain)
            .await;
        assert!(
            matches!(r, Err(Krb5Error::Ccache(CcError::NotFound))),
            "{r:?}"
        );
        assert_eq!(sends.load(Ordering::SeqCst), used);
    }

    #[tokio::test]
    async fn s4u2self_cached_only_without_a_cached_ticket_is_not_found() {
        let w = Arc::new(world(true, false));
        let mut cc = service_ccache(&w.login(service()).await);
        let (client, sends) = client(&w);
        let r = client
            .get_credentials_for_user(&mut cc, GcOptions::CACHED, &xuser(), None)
            .await;
        assert!(
            matches!(r, Err(Krb5Error::Ccache(CcError::NotFound))),
            "{r:?}"
        );
        assert_eq!(sends.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn s4u2self_no_store_leaves_the_ccache_unchanged() {
        let w = Arc::new(world(true, false));
        let mut cc = service_ccache(&w.login(service()).await);
        let (client, _) = client(&w);
        client
            .get_credentials_for_user(&mut cc, GcOptions::NO_STORE, &xuser(), None)
            .await
            .expect("S4U2Self");
        assert_eq!(cc.creds().expect("creds").len(), 1);
    }

    fn no_name() -> CredsRequest {
        let mut r = CredsRequest::new(PrincipalName::new_principal(""), "", service(), SREALM);
        r.client.name_string.clear();
        r
    }

    // t_s4u.py "S4U2Self using X509 certificate".
    #[tokio::test]
    async fn s4u2self_by_certificate_alone_names_the_user_from_the_reply() {
        let w = Arc::new(world(false, false));
        let mut cc = service_ccache(&w.login(service()).await);
        let (client, sends) = client(&w);
        let r = client
            .get_credentials_for_user(&mut cc, GcOptions::CACHED, &no_name(), Some(b"other"))
            .await;
        assert!(
            matches!(r, Err(Krb5Error::Ccache(CcError::NotFound))),
            "{r:?}"
        );
        assert_eq!(sends.load(Ordering::SeqCst), 0);
        let cred = client
            .get_credentials_for_user(&mut cc, GcOptions::empty(), &no_name(), Some(b"other"))
            .await
            .expect("S4U2Self by certificate");
        assert_eq!(cred.client, PrincipalName::new_principal("other"));
        assert_eq!(cred.crealm, SREALM);
        let part = decrypt_ticket(&w.service_key, &cred.ticket).expect("decrypt");
        assert_eq!(part.cname.name_string, cred.client.name_string);
        // Stored under the user the certificate identified.
        let named = CredsRequest::new(cred.client.clone(), SREALM, service(), SREALM);
        let used = sends.load(Ordering::SeqCst);
        client
            .get_credentials_for_user(&mut cc, GcOptions::CACHED, &named, None)
            .await
            .expect("cached for other@S.REALM");
        // The KDC is asked again, then the cached credential is returned.
        let again = client
            .get_credentials_for_user(&mut cc, GcOptions::empty(), &no_name(), Some(b"other"))
            .await
            .expect("again by certificate");
        assert!(sends.load(Ordering::SeqCst) > used);
        assert_eq!(again.session_key.key_bytes(), cred.session_key.key_bytes());
        assert_eq!(cc.creds().expect("creds").len(), 2);
    }

    #[tokio::test]
    async fn s4u2self_with_a_name_and_a_certificate_checks_that_they_match() {
        let w = Arc::new(world(false, false));
        let mut cc = service_ccache(&w.login(service()).await);
        let (client, _) = client(&w);
        let other = CredsRequest::new(
            PrincipalName::new_principal("other"),
            SREALM,
            service(),
            SREALM,
        );
        let cred = client
            .get_credentials_for_user(&mut cc, GcOptions::NO_STORE, &other, Some(b"other"))
            .await
            .expect("matching name and certificate");
        assert_eq!(cred.client, PrincipalName::new_principal("other"));
        let alice = CredsRequest::new(
            PrincipalName::new_principal("alice"),
            SREALM,
            service(),
            SREALM,
        );
        let r = client
            .get_credentials_for_user(&mut cc, GcOptions::empty(), &alice, Some(b"other"))
            .await;
        assert_eq!(kdc_code(&r), 75, "{r:?}");
    }

    #[tokio::test]
    async fn s4u2self_by_certificate_of_an_unknown_user_is_client_unknown() {
        let w = Arc::new(world(false, false));
        let mut cc = service_ccache(&w.login(service()).await);
        let (client, _) = client(&w);
        let r = client
            .get_credentials_for_user(&mut cc, GcOptions::empty(), &no_name(), Some(b"nobody"))
            .await;
        assert_eq!(kdc_code(&r), 6, "{r:?}");
    }

    #[tokio::test]
    async fn s4u2self_by_certificate_without_store_support_is_a_generic_error() {
        let w = Arc::new(world_x509(false, false, false));
        let mut cc = service_ccache(&w.login(service()).await);
        let (client, _) = client(&w);
        let r = client
            .get_credentials_for_user(&mut cc, GcOptions::empty(), &no_name(), Some(b"other"))
            .await;
        assert_eq!(kdc_code(&r), 60, "{r:?}");
    }

    // t_s4u.py "cross-realm S4U2Self using X509 certificate".
    #[tokio::test]
    async fn cross_realm_s4u2self_by_certificate_follows_the_client_referral() {
        let w = Arc::new(world(true, false));
        let mut cc = service_ccache(&w.login(service()).await);
        let (client, _) = client(&w);
        let cred = client
            .get_credentials_for_user(
                &mut cc,
                GcOptions::empty(),
                &no_name(),
                Some(b"xuser@U.REALM"),
            )
            .await
            .expect("cross-realm S4U2Self by certificate");
        assert_eq!(cred.client, PrincipalName::new_principal("xuser"));
        assert_eq!(cred.crealm, UREALM);
        let part = decrypt_ticket(&w.service_key, &cred.ticket).expect("decrypt");
        assert_eq!(part.crealm.as_bytes(), UREALM.as_bytes());
        let named = CredsRequest::new(cred.client.clone(), UREALM, service(), SREALM);
        client
            .get_credentials_for_user(&mut cc, GcOptions::CACHED, &named, None)
            .await
            .expect("stored for xuser@U.REALM");
    }

    /// A ccache whose lookups fail with KRB5_CC_FORMAT.
    struct Broken(MemoryCcache);

    impl Ccache for Broken {
        fn initialize(&mut self, client: &PrincipalName, realm: &str) -> Result<(), CcError> {
            self.0.initialize(client, realm)
        }
        fn principal(&self) -> Result<(PrincipalName, String), CcError> {
            self.0.principal()
        }
        fn store(&mut self, cred: &CcCredential) -> Result<(), CcError> {
            self.0.store(cred)
        }
        fn creds(&self) -> Result<Vec<CcCredential>, CcError> {
            self.0.creds()
        }
        fn remove_cred(&mut self, flags: MatchFlags, m: &MatchCred) -> Result<(), CcError> {
            self.0.remove_cred(flags, m)
        }
        fn retrieve(
            &self,
            _: MatchFlags,
            _: &MatchCred,
            _: Option<&[i32]>,
        ) -> Result<CcCredential, CcError> {
            Err(CcError::Format)
        }
        fn set_config(
            &mut self,
            principal: Option<(&PrincipalName, &str)>,
            key: &str,
            data: Option<&[u8]>,
        ) -> Result<(), CcError> {
            self.0.set_config(principal, key, data)
        }
        fn get_config(
            &self,
            principal: Option<(&PrincipalName, &str)>,
            key: &str,
        ) -> Result<Option<Vec<u8>>, CcError> {
            self.0.get_config(principal, key)
        }
    }

    #[tokio::test]
    async fn unexpected_ccache_errors_stop_the_request() {
        let w = Arc::new(world(true, false));
        let mut cc = Broken(service_ccache(&w.login(service()).await));
        let (client, sends) = client(&w);
        let r = client
            .get_credentials_for_user(&mut cc, GcOptions::empty(), &xuser(), None)
            .await;
        assert!(
            matches!(r, Err(Krb5Error::Ccache(CcError::Format))),
            "{r:?}"
        );
        let (_, evidence) = evidence(&w).await;
        let req = CredsRequest::new(evidence.client.clone(), SREALM, target(), UREALM);
        let r = client
            .get_credentials_for_proxy(&mut cc, GcOptions::empty(), &req, &evidence)
            .await;
        assert!(
            matches!(r, Err(Krb5Error::Ccache(CcError::Format))),
            "{r:?}"
        );
        assert_eq!(sends.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn enterprise_user_realm_is_identified_by_client_referral() {
        let w = Arc::new(world(true, false));
        let mut cc = service_ccache(&w.login(service()).await);
        let (client, _) = client(&w);
        let req = CredsRequest::new(enterprise("enterprise@abc"), "NOREALM", service(), SREALM);
        let cred = client
            .get_credentials_for_user(&mut cc, GcOptions::empty(), &req, None)
            .await
            .expect("S4U2Self for an enterprise user");
        // As in t_s4u.py: "TGS reply is for enterprise\@abc@UREALM".
        assert_eq!(
            cred.client.name_string,
            enterprise("enterprise@abc").name_string
        );
        assert_eq!(cred.crealm, UREALM);
        assert_eq!(cred.server.name_string, service().name_string);
        // The post-canonicalization check finds it without a TGS request.
        let tgs_before = cc.creds().expect("creds").len();
        let again = client
            .get_credentials_for_user(&mut cc, GcOptions::empty(), &req, None)
            .await
            .expect("cached enterprise S4U2Self");
        assert_eq!(again.session_key.key_bytes(), cred.session_key.key_bytes());
        assert_eq!(cc.creds().expect("creds").len(), tgs_before);
    }

    #[tokio::test]
    async fn proxy_target_short_name_is_qualified_like_k5_canonprinc() {
        let w = Arc::new(world(false, true));
        let (tgt, evidence) = evidence(&w).await;
        let mut cc = service_ccache(&tgt);
        let (client, sends) = client(&w);
        let client = client.with_host_canonicalization(HostCanonicalization {
            qualify_shortname: Some("u.realm".into()),
            rdns: false,
            ..Default::default()
        });
        let short = PrincipalName::new_srv_hst("HTTP", "target");
        let req = CredsRequest::new(evidence.client.clone(), SREALM, short.clone(), "");
        let cred = client
            .get_credentials_for_proxy(&mut cc, GcOptions::empty(), &req, &evidence)
            .await
            .expect("S4U2Proxy to the qualified name");
        assert_eq!(cred.server, short);
        assert_eq!(cred.srealm, "");
        let part = decrypt_ticket(&w.target_key, &cred.ticket).expect("decrypt");
        assert_eq!(part.crealm.as_bytes(), SREALM.as_bytes());
        // Cached by server and evidence ticket (get_creds.c:96-111).
        let used = sends.load(Ordering::SeqCst);
        let again = client
            .get_credentials_for_proxy(&mut cc, GcOptions::CACHED, &req, &evidence)
            .await
            .expect("cached S4U2Proxy");
        assert_eq!(again.session_key.key_bytes(), cred.session_key.key_bytes());
        assert_eq!(sends.load(Ordering::SeqCst), used);
        // Another evidence ticket does not match.
        let (_, other) = super::evidence(&w).await;
        let r = client
            .get_credentials_for_proxy(&mut cc, GcOptions::CACHED, &req, &other)
            .await;
        assert!(
            matches!(r, Err(Krb5Error::Ccache(CcError::NotFound))),
            "{r:?}"
        );
    }

    #[tokio::test]
    async fn proxy_evidence_for_another_client_is_rejected() {
        let w = Arc::new(world(false, true));
        let (tgt, evidence) = evidence(&w).await;
        let mut cc = service_ccache(&tgt);
        let (client, sends) = client(&w);
        let req = CredsRequest::new(
            PrincipalName::new_principal("bob"),
            SREALM,
            target(),
            UREALM,
        );
        let r = client
            .get_credentials_for_proxy(&mut cc, GcOptions::empty(), &req, &evidence)
            .await;
        assert!(r.is_err());
        assert_eq!(sends.load(Ordering::SeqCst), 0);
    }
}
