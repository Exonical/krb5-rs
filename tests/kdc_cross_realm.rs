#![cfg(feature = "kdc")]
//! Cross-realm trust, referrals and transited policy (MIT do_tgs_req.c
//! `search_sprinc` / `find_referral_tgs` / `find_alternate_tgs`,
//! kdc_transit.c, chk_trans.c). Several in-process KDCs with shared trust
//! keys are driven by our real client, routed per realm.

use std::collections::BTreeMap;

use krb5_rs::kdc::{Kdc, KdcConfig, MemoryStore, PrincipalAttributes, PrincipalStore};
use krb5_rs::pac::{ticket_pac, verify_ticket_pac};
use krb5_rs::profile::Profile;
use krb5_rs::protocol::ap::decrypt_ticket;
use krb5_rs::protocol::{
    AsExchange, AsExchangeConfig, Credential, StepResult, TgsExchange, TgsOptions, TgsStepResult,
};
use krb5_rs::types::{EncTicketPart, EncryptionKey, PrincipalName, TgsRep, TicketFlags};
use krb5_rs::Krb5Error;

const PASSWORD: &str = "user-password";
const TRUST_PW: &str = "crosstrust";

fn gs(s: &str) -> rasn::types::GeneralString {
    rasn::types::GeneralString::from_bytes(s.as_bytes()).expect("general string")
}

fn tgs_name(instance: &str) -> PrincipalName {
    PrincipalName {
        name_type: 2,
        name_string: vec![gs("krbtgt"), gs(instance)],
    }
}

fn host_service(host: &str) -> PrincipalName {
    PrincipalName::new_srv_hst("HTTP", host)
}

#[derive(Default)]
struct Builder {
    stores: BTreeMap<String, MemoryStore>,
    configs: BTreeMap<String, KdcConfig>,
    service_keys: BTreeMap<String, EncryptionKey>,
    tgt_keys: BTreeMap<String, EncryptionKey>,
}

impl Builder {
    fn realm(mut self, name: &str, krb5_conf: Option<&str>) -> Self {
        let mut store = MemoryStore::new();
        store
            .add_random_key(
                tgs_name(name),
                name,
                1,
                &[18, 17],
                PrincipalAttributes::empty(),
            )
            .expect("local krbtgt");
        let key = store
            .lookup(&tgs_name(name), name)
            .expect("lookup")
            .expect("entry")
            .keys[0]
            .key
            .clone();
        self.tgt_keys.insert(name.to_string(), key);
        self.stores.insert(name.to_string(), store);
        let mut config = KdcConfig::new(name);
        config.realm_profile = krb5_conf.map(|t| Profile::parse(t).expect("krb5.conf"));
        self.configs.insert(name.to_string(), config);
        self
    }

    fn user(mut self, realm: &str, name: &str) -> Self {
        self.stores
            .get_mut(realm)
            .expect("realm")
            .add_with_password(
                PrincipalName::new_principal(name),
                realm,
                PASSWORD,
                1,
                &[18, 17],
                PrincipalAttributes::empty(),
            )
            .expect("user");
        self
    }

    fn service(mut self, realm: &str, name: PrincipalName) -> Self {
        let store = self.stores.get_mut(realm).expect("realm");
        store
            .add_random_key(
                name.clone(),
                realm,
                1,
                &[18, 17],
                PrincipalAttributes::empty(),
            )
            .expect("service");
        let key = store
            .lookup(&name, realm)
            .expect("lookup")
            .expect("entry")
            .keys[0]
            .key
            .clone();
        self.service_keys.insert(realm.to_string(), key);
        self
    }

    /// `krbtgt/target@issuing` with a password-derived key, stored in
    /// `store_realm` (both ends of a trust must agree on the password).
    fn trust(self, store_realm: &str, issuing: &str, target: &str, password: &str) -> Self {
        self.trust_typed(store_realm, issuing, target, password, 2)
    }

    /// [`Builder::trust`] with an explicit stored name type (kadmin `addprinc`
    /// stores NT-PRINCIPAL, 1).
    fn trust_typed(
        mut self,
        store_realm: &str,
        issuing: &str,
        target: &str,
        password: &str,
        name_type: i32,
    ) -> Self {
        let mut name = tgs_name(target);
        name.name_type = name_type;
        self.stores
            .get_mut(store_realm)
            .expect("realm")
            .add_with_password(
                name,
                issuing,
                password,
                1,
                &[18, 17],
                PrincipalAttributes::empty(),
            )
            .expect("trust key");
        self
    }

    fn tweak(mut self, realm: &str, f: impl FnOnce(&mut KdcConfig)) -> Self {
        f(self.configs.get_mut(realm).expect("realm"));
        self
    }

    fn build(self) -> World {
        let mut configs = self.configs;
        let kdcs = self
            .stores
            .into_iter()
            .map(|(name, store)| {
                let config = configs.remove(&name).expect("config");
                (name, Kdc::new(config, store))
            })
            .collect();
        World {
            kdcs,
            service_keys: self.service_keys,
            tgt_keys: self.tgt_keys,
        }
    }
}

/// (realm, reply) for every KDC exchange.
type Seen = Vec<(String, Vec<u8>)>;

struct World {
    kdcs: BTreeMap<String, Kdc<MemoryStore>>,
    service_keys: BTreeMap<String, EncryptionKey>,
    tgt_keys: BTreeMap<String, EncryptionKey>,
}

impl World {
    fn send(&self, realm: &str, data: &[u8]) -> Vec<u8> {
        self.kdcs
            .get(realm)
            .unwrap_or_else(|| panic!("no KDC for {realm}"))
            .handle(data)
    }

    fn login(&self, realm: &str, user: &str) -> Credential {
        let config = AsExchangeConfig::new(PrincipalName::new_principal(user), realm);
        let mut ex = AsExchange::new(config, PASSWORD);
        let mut reply = Vec::new();
        while let StepResult::SendToKdc { data, .. } | StepResult::RetryTcp { data, .. } =
            ex.step(&reply).expect("AS step")
        {
            reply = self.send(realm, &data);
        }
        ex.credential().expect("TGT").clone()
    }

    /// Run a TGS exchange, returning the credential and every
    /// (realm, reply) pair seen.
    fn tgs(
        &self,
        tgt: &Credential,
        target: PrincipalName,
        options: TgsOptions,
    ) -> (Result<Credential, Krb5Error>, Seen) {
        let mut ex = TgsExchange::new(tgt.clone(), target, options);
        let mut seen = Vec::new();
        let mut reply = Vec::new();
        for _ in 0..16 {
            match ex.step(&reply) {
                Ok(TgsStepResult::SendToKdc { data, realm })
                | Ok(TgsStepResult::RetryTcp { data, realm }) => {
                    reply = self.send(&realm, &data);
                    seen.push((realm, reply.clone()));
                }
                Ok(TgsStepResult::Complete) => {
                    return (Ok(ex.credential().expect("credential").clone()), seen)
                }
                Err(e) => return (Err(e), seen),
            }
        }
        panic!("TGS exchange did not finish");
    }
}

fn kdc_code(e: &Krb5Error) -> i32 {
    match e {
        Krb5Error::KdcError(m) => m.error_code,
        other => panic!("expected KDC error, got {other:?}"),
    }
}

fn flags_of(part: &EncTicketPart) -> TicketFlags {
    *part.flags
}

/// The trust key `krbtgt/target@issuing` as derived from `TRUST_PW`.
fn trust_key(issuing: &str, target: &str, password: &str) -> EncryptionKey {
    let mut s = MemoryStore::new();
    s.add_with_password(
        tgs_name(target),
        issuing,
        password,
        1,
        &[18, 17],
        PrincipalAttributes::empty(),
    )
    .expect("key");
    s.lookup(&tgs_name(target), issuing)
        .expect("lookup")
        .expect("entry")
        .keys[0]
        .key
        .clone()
}

const ALPHA: &str = "ALPHA.COM";
const BETA: &str = "BETA.ORG";

/// ALPHA.COM <-> BETA.ORG with a direct, bidirectional trust.
fn two_realm_builder() -> Builder {
    Builder::default()
        .realm(ALPHA, Some("[domain_realm]\n .beta.org = BETA.ORG\n"))
        .realm(BETA, Some("[domain_realm]\n .alpha.com = ALPHA.COM\n"))
        .user(ALPHA, "alice")
        .user(BETA, "bob")
        .service(BETA, host_service("web.beta.org"))
        .trust(ALPHA, ALPHA, BETA, TRUST_PW)
        .trust(BETA, ALPHA, BETA, TRUST_PW)
        .trust(BETA, BETA, ALPHA, TRUST_PW)
        .trust(ALPHA, BETA, ALPHA, TRUST_PW)
}

#[test]
fn referral_direct_trust_issues_referral_tgt_then_service_ticket() {
    let w = two_realm_builder().build();
    let tgt = w.login(ALPHA, "alice");
    let (res, seen) = w.tgs(&tgt, host_service("web.beta.org"), TgsOptions::default());
    let cred = res.expect("service ticket via referral");

    assert_eq!(seen.len(), 2);
    assert_eq!((seen[0].0.as_str(), seen[1].0.as_str()), (ALPHA, BETA));

    // Referral reply: ticket for krbtgt/BETA.ORG issued by ALPHA.COM,
    // encrypted under the trust key (do_tgs_req.c:1047, 668-671).
    let first: TgsRep = rasn::der::decode(&seen[0].1).expect("referral TGS-REP");
    assert_eq!(first.0.ticket.realm.as_bytes(), ALPHA.as_bytes());
    assert_eq!(first.0.ticket.sname, tgs_name(BETA));
    let part = decrypt_ticket(&trust_key(ALPHA, BETA, TRUST_PW), &first.0.ticket)
        .expect("trust key decrypts the referral TGT");
    assert_eq!(part.crealm.as_bytes(), ALPHA.as_bytes());
    assert_eq!(part.cname, PrincipalName::new_principal("alice"));
    assert!(part.transited.contents.is_empty());
    assert!(flags_of(&part).contains(TicketFlags::TRANSITED_POLICY_CHECKED));

    // Final ticket: for BETA.ORG's service, client from ALPHA.COM.
    assert_eq!(cred.server, host_service("web.beta.org"));
    assert_eq!(cred.crealm, ALPHA);
    let svc = decrypt_ticket(&w.service_keys[BETA], &cred.ticket).expect("service key");
    assert_eq!(svc.crealm.as_bytes(), ALPHA.as_bytes());
    assert_eq!(svc.cname, PrincipalName::new_principal("alice"));
    assert!(svc.transited.contents.is_empty());
    assert!(flags_of(&svc).contains(TicketFlags::TRANSITED_POLICY_CHECKED));
}

#[test]
fn explicit_cross_realm_tgt_request_returns_ticket_encrypted_under_trust_key() {
    let w = two_realm_builder().build();
    let tgt = w.login(ALPHA, "alice");
    let options = TgsOptions {
        canonicalize: false,
        ..TgsOptions::default()
    };
    let (res, seen) = w.tgs(&tgt, tgs_name(BETA), options);
    let cred = res.expect("cross-realm TGT");
    assert_eq!(seen.len(), 1);
    assert_eq!(cred.server, tgs_name(BETA));
    let part = decrypt_ticket(&trust_key(ALPHA, BETA, TRUST_PW), &cred.ticket).expect("trust key");
    assert_eq!(part.cname, PrincipalName::new_principal("alice"));
    assert!(part.transited.contents.is_empty());
}

#[test]
fn referral_reverse_direction_works() {
    let w = Builder::default()
        .realm(ALPHA, Some("[domain_realm]\n .beta.org = BETA.ORG\n"))
        .realm(BETA, Some("[domain_realm]\n .alpha.com = ALPHA.COM\n"))
        .user(BETA, "bob")
        .service(ALPHA, host_service("files.alpha.com"))
        .trust(ALPHA, BETA, ALPHA, TRUST_PW)
        .trust(BETA, BETA, ALPHA, TRUST_PW)
        .build();
    let tgt = w.login(BETA, "bob");
    let (res, _) = w.tgs(&tgt, host_service("files.alpha.com"), TgsOptions::default());
    let cred = res.expect("reverse direction");
    let svc = decrypt_ticket(&w.service_keys[ALPHA], &cred.ticket).expect("service key");
    assert_eq!(svc.crealm.as_bytes(), BETA.as_bytes());
    assert_eq!(svc.cname, PrincipalName::new_principal("bob"));
}

const A_EX: &str = "A.EXAMPLE.COM";
const EX: &str = "EXAMPLE.COM";
const B_EX: &str = "B.EXAMPLE.COM";

/// A.EXAMPLE.COM -> EXAMPLE.COM -> B.EXAMPLE.COM (hierarchical trusts).
fn hierarchy_builder() -> Builder {
    let map = "[domain_realm]\n .b.example.com = B.EXAMPLE.COM\n";
    Builder::default()
        .realm(A_EX, Some(map))
        .realm(EX, Some(map))
        .realm(B_EX, None)
        .user(A_EX, "alice")
        .service(B_EX, host_service("web.b.example.com"))
        .trust(A_EX, A_EX, EX, TRUST_PW)
        .trust(EX, A_EX, EX, TRUST_PW)
        .trust(EX, EX, B_EX, TRUST_PW)
        .trust(B_EX, EX, B_EX, TRUST_PW)
}

#[test]
fn hierarchical_path_records_intermediate_realm_in_transited() {
    let w = hierarchy_builder().build();
    let tgt = w.login(A_EX, "alice");
    let (res, seen) = w.tgs(
        &tgt,
        host_service("web.b.example.com"),
        TgsOptions::default(),
    );
    let cred = res.expect("service ticket across three realms");
    let hops: Vec<&str> = seen.iter().map(|(r, _)| r.as_str()).collect();
    assert_eq!(hops, vec![A_EX, EX, B_EX]);

    // EXAMPLE.COM's referral keeps the (empty) transited list: the client
    // realm equals the header ticket's issuer (do_tgs_req.c:787-790).
    let mid: TgsRep = rasn::der::decode(&seen[1].1).expect("TGS-REP");
    let mid_part = decrypt_ticket(&trust_key(EX, B_EX, TRUST_PW), &mid.0.ticket).expect("key");
    assert!(mid_part.transited.contents.is_empty());

    // The final ticket records EXAMPLE.COM (add_to_transited,
    // kdc_transit.c:105+), and the policy was checked.
    let svc = decrypt_ticket(&w.service_keys[B_EX], &cred.ticket).expect("service key");
    assert_eq!(svc.transited.tr_type, 1);
    assert_eq!(svc.transited.contents.as_ref(), EX.as_bytes());
    assert_eq!(svc.crealm.as_bytes(), A_EX.as_bytes());
    assert!(flags_of(&svc).contains(TicketFlags::TRANSITED_POLICY_CHECKED));
}

#[test]
fn capaths_that_forbid_the_transited_realm_are_rejected_with_policy_error() {
    // B.EXAMPLE.COM requires A -> B to go through HUB.NET, so a ticket that
    // transited EXAMPLE.COM fails the check; reject_bad_transit refuses it
    // (do_tgs_req.c:951-958, KRB5KDC_ERR_POLICY).
    let w = hierarchy_builder()
        .tweak(B_EX, |c| {
            c.realm_profile = Some(
                Profile::parse("[capaths]\n A.EXAMPLE.COM = {\n  B.EXAMPLE.COM = HUB.NET\n }\n")
                    .expect("capaths"),
            );
        })
        .build();
    let tgt = w.login(A_EX, "alice");
    let (res, _) = w.tgs(
        &tgt,
        host_service("web.b.example.com"),
        TgsOptions::default(),
    );
    assert_eq!(kdc_code(&res.expect_err("must fail")), 12);
}

#[test]
fn capaths_allowing_the_transited_realm_are_accepted() {
    let w = hierarchy_builder()
        .tweak(B_EX, |c| {
            c.realm_profile = Some(
                Profile::parse(
                    "[capaths]\n A.EXAMPLE.COM = {\n  B.EXAMPLE.COM = EXAMPLE.COM\n }\n",
                )
                .expect("capaths"),
            );
        })
        .build();
    let tgt = w.login(A_EX, "alice");
    let (res, _) = w.tgs(
        &tgt,
        host_service("web.b.example.com"),
        TgsOptions::default(),
    );
    res.expect("capaths path through EXAMPLE.COM");
}

#[test]
fn reject_bad_transit_off_issues_ticket_without_policy_checked_flag() {
    let w = hierarchy_builder()
        .tweak(B_EX, |c| {
            c.reject_bad_transit = false;
            c.realm_profile = Some(
                Profile::parse("[capaths]\n A.EXAMPLE.COM = {\n  B.EXAMPLE.COM = HUB.NET\n }\n")
                    .expect("capaths"),
            );
        })
        .build();
    let tgt = w.login(A_EX, "alice");
    let (res, _) = w.tgs(
        &tgt,
        host_service("web.b.example.com"),
        TgsOptions::default(),
    );
    let cred = res.expect("ticket without policy flag");
    let svc = decrypt_ticket(&w.service_keys[B_EX], &cred.ticket).expect("service key");
    assert!(!flags_of(&svc).contains(TicketFlags::TRANSITED_POLICY_CHECKED));
    assert_eq!(svc.transited.contents.as_ref(), EX.as_bytes());
}

#[test]
fn cross_realm_tgt_under_wrong_trust_key_returns_bad_integrity() {
    let w = Builder::default()
        .realm(ALPHA, Some("[domain_realm]\n .beta.org = BETA.ORG\n"))
        .realm(BETA, None)
        .user(ALPHA, "alice")
        .service(BETA, host_service("web.beta.org"))
        .trust(ALPHA, ALPHA, BETA, TRUST_PW)
        .trust(BETA, ALPHA, BETA, "a-different-password")
        .build();
    let tgt = w.login(ALPHA, "alice");
    let (res, _) = w.tgs(&tgt, host_service("web.beta.org"), TgsOptions::default());
    assert_eq!(kdc_code(&res.expect_err("must fail")), 31);
}

#[test]
fn local_user_ticket_returning_through_foreign_realm_is_rejected_as_lineage_violation() {
    // A ticket for ALPHA.COM's alice issued by BETA.ORG (the header ticket is
    // krbtgt/ALPHA.COM@BETA.ORG): tgs_policy.c:248-258.
    let w = two_realm_builder()
        .service(ALPHA, host_service("x.alpha.com"))
        .build();
    let tgt = w.login(ALPHA, "alice");
    let options = TgsOptions {
        canonicalize: false,
        ..TgsOptions::default()
    };
    let (res, _) = w.tgs(&tgt, tgs_name(BETA), options.clone());
    let to_beta = res.expect("cross-realm TGT");
    // Ask BETA.ORG for a TGT back to ALPHA.COM, then present it to ALPHA.COM.
    let (res, _) = w.tgs(&to_beta, tgs_name(ALPHA), options.clone());
    let back = res.expect("TGT back to ALPHA.COM");
    let (res, _) = w.tgs(&back, host_service("x.alpha.com"), options);
    assert_eq!(kdc_code(&res.expect_err("must fail")), 12);
}

#[test]
fn unknown_non_host_service_gets_no_referral() {
    let w = two_realm_builder().build();
    let tgt = w.login(ALPHA, "alice");
    let (res, _) = w.tgs(
        &tgt,
        PrincipalName::new_principal("nosuchservice"),
        TgsOptions::default(),
    );
    assert_eq!(kdc_code(&res.expect_err("must fail")), 7);
}

#[test]
fn host_without_domain_realm_mapping_gets_no_referral() {
    let w = two_realm_builder().build();
    let tgt = w.login(ALPHA, "alice");
    let (res, _) = w.tgs(
        &tgt,
        host_service("web.unmapped.net"),
        TgsOptions::default(),
    );
    assert_eq!(kdc_code(&res.expect_err("must fail")), 7);
}

#[test]
fn host_without_dot_gets_no_referral() {
    let w = two_realm_builder().build();
    let tgt = w.login(ALPHA, "alice");
    let (res, _) = w.tgs(&tgt, host_service("web"), TgsOptions::default());
    assert_eq!(kdc_code(&res.expect_err("must fail")), 7);
}

#[test]
fn no_host_referral_blocks_referrals() {
    let w = two_realm_builder()
        .tweak(ALPHA, |c| c.no_host_referral = vec!["HTTP".into()])
        .build();
    let tgt = w.login(ALPHA, "alice");
    let (res, _) = w.tgs(&tgt, host_service("web.beta.org"), TgsOptions::default());
    assert_eq!(kdc_code(&res.expect_err("must fail")), 7);
}

#[test]
fn referral_requires_canonicalize_option() {
    let w = two_realm_builder().build();
    let tgt = w.login(ALPHA, "alice");
    let options = TgsOptions {
        canonicalize: false,
        ..TgsOptions::default()
    };
    let (res, _) = w.tgs(&tgt, host_service("web.beta.org"), options);
    assert_eq!(kdc_code(&res.expect_err("must fail")), 7);
}

fn unknown_type_service() -> PrincipalName {
    PrincipalName {
        name_type: 0,
        name_string: vec![gs("HTTP"), gs("web.beta.org")],
    }
}

#[test]
fn nt_unknown_names_are_referred_only_when_host_based_services_allows() {
    let denied = two_realm_builder().build();
    let tgt = denied.login(ALPHA, "alice");
    let (res, _) = denied.tgs(&tgt, unknown_type_service(), TgsOptions::default());
    assert_eq!(kdc_code(&res.expect_err("must fail")), 7);

    let allowed = two_realm_builder()
        .tweak(ALPHA, |c| c.host_based_services = vec!["HTTP".into()])
        .build();
    let tgt = allowed.login(ALPHA, "alice");
    let (res, seen) = allowed.tgs(&tgt, unknown_type_service(), TgsOptions::default());
    res.expect("NT-UNKNOWN referral");
    assert_eq!(seen.len(), 2);
}

#[test]
fn referral_with_nt_principal_trust_entry_is_followed_by_the_client() {
    // As MIT's `addprinc krbtgt/BETA.ORG@ALPHA.COM` stores the name type
    // NT-PRINCIPAL (tests/kdc/setup-other.sh), the referral TGT carries it.
    let w = Builder::default()
        .realm(ALPHA, Some("[domain_realm]\n .beta.org = BETA.ORG\n"))
        .realm(BETA, None)
        .user(ALPHA, "alice")
        .service(BETA, host_service("web.beta.org"))
        .trust_typed(ALPHA, ALPHA, BETA, TRUST_PW, 1)
        .trust(BETA, ALPHA, BETA, TRUST_PW)
        .build();
    let tgt = w.login(ALPHA, "alice");
    let (res, seen) = w.tgs(&tgt, host_service("web.beta.org"), TgsOptions::default());
    let cred = res.expect("referral with NT-PRINCIPAL trust entry");
    assert_eq!(seen.len(), 2);
    let first: TgsRep = rasn::der::decode(&seen[0].1).expect("TGS-REP");
    assert_eq!(first.0.ticket.sname.name_type, 1);
    assert_eq!(cred.server, host_service("web.beta.org"));
    decrypt_ticket(&w.service_keys[BETA], &cred.ticket).expect("service key");
}

#[test]
fn cross_realm_pac_is_signed_with_trust_key_then_resigned_for_the_service() {
    let w = two_realm_builder().build();
    let tgt = w.login(ALPHA, "alice");
    let (res, seen) = w.tgs(&tgt, host_service("web.beta.org"), TgsOptions::default());
    let cred = res.expect("service ticket via referral");
    let alice = PrincipalName::new_principal("alice");

    // The referral TGT's PAC: server signature under the trust key, KDC
    // signature under ALPHA's krbtgt key (handle_pac: server = the trust
    // principal, privsvr = the local TGT key).
    let first: TgsRep = rasn::der::decode(&seen[0].1).expect("TGS-REP");
    let trust = trust_key(ALPHA, BETA, TRUST_PW);
    let part = decrypt_ticket(&trust, &first.0.ticket).expect("trust key");
    let pac = ticket_pac(&part).expect("parse").expect("PAC");
    pac.verify(
        part.authtime.timestamp(),
        Some((&alice, ALPHA)),
        Some(&trust),
        Some(&w.tgt_keys[ALPHA]),
    )
    .expect("referral PAC verifies");
    assert_eq!(pac.client_info().expect("client info").name, "alice");

    // BETA verified it with the trust key and issued a new PAC for the
    // service, still naming alice (no realm in the client info).
    let svc = decrypt_ticket(&w.service_keys[BETA], &cred.ticket).expect("service key");
    verify_ticket_pac(
        &svc,
        &host_service("web.beta.org"),
        &w.service_keys[BETA],
        Some(&w.tgt_keys[BETA]),
    )
    .expect("service ticket PAC")
    .expect("PAC present");
    let spac = ticket_pac(&svc).expect("parse").expect("PAC");
    assert_eq!(spac.client_info().expect("client info").name, "alice");
}
