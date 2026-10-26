#![cfg(feature = "kdc")]
//! Cross-realm S4U2Self and S4U2Proxy driven by our client through two
//! in-process KDCs (MIT s4u_creds.c, t_s4u.py "cross-realm S4U2Self"). As in
//! MIT's tests, the user realm resolves the service's enterprise name with a
//! KDB alias to its TGT for the service realm (plugins/kdb/test/kdb_test.c);
//! db2 and LMDB have no such aliases.

use std::collections::BTreeMap;

use krb5_rs::kdc::{
    Kdc, KdcConfig, MemoryStore, PrincipalAttributes, PrincipalEntry, PrincipalStore, StoreError,
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
    aliases: Vec<(PrincipalName, PrincipalName)>,
}

impl PrincipalStore for AliasStore {
    async fn lookup(
        &self,
        name: &PrincipalName,
        realm: &str,
    ) -> Result<Option<PrincipalEntry>, StoreError> {
        let name = self
            .aliases
            .iter()
            .find(|(alias, _)| alias.name_string == name.name_string)
            .map_or(name, |(_, target)| target);
        self.inner.lookup(name, realm).await
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
    let none = PrincipalAttributes::empty();
    let mut s = AliasStore::default();
    let mut u = AliasStore::default();
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
    u.inner
        .add_with_password(
            PrincipalName::new_principal("xuser"),
            UREALM,
            PASSWORD,
            1,
            &[18, 17],
            none,
        )
        .expect("xuser");
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
