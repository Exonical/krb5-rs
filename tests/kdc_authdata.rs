#![cfg(feature = "kdc")]
//! KDC authdata modules (MIT kdc_authdata.c `load_authdata_plugins`,
//! `handle_authdata`) and the `greet` sample module
//! (plugins/authdata/greet_server/greet_auth.c).

use std::sync::{Arc, Mutex};

use krb5_rs::kdc::plugins::greet::{verify_authdata_kdc_issued, Greet, AD_GREET, GREETING};
use krb5_rs::kdc::plugins::{kdb_flags, AuthdataRequest, KdcAuthdata, MSG_AS_REQ, MSG_TGS_REQ};
use krb5_rs::kdc::{Kdc, KdcConfig, MemoryStore, PrincipalAttributes};
use krb5_rs::pac::{AD_IF_RELEVANT, AD_WIN2K_PAC};
use krb5_rs::protocol::ap::{decrypt_ticket, encrypt_ticket_part};
use krb5_rs::protocol::{
    AsExchange, AsExchangeConfig, Credential, StepResult, TgsExchange, TgsOptions, TgsStepResult,
};
use krb5_rs::types::{
    AuthorizationDataElement, EncTicketPart, EncryptionKey, PrincipalName, TicketFlags,
};

const REALM: &str = "AD.REALM";
const PASSWORD: &str = "ad-password";

fn gs(s: &str) -> rasn::types::GeneralString {
    rasn::types::GeneralString::from_bytes(s.as_bytes()).expect("string")
}

fn tgs_name() -> PrincipalName {
    PrincipalName {
        name_type: 2,
        name_string: vec![gs("krbtgt"), gs(REALM)],
    }
}

fn svc() -> PrincipalName {
    PrincipalName::new_srv_hst("HTTP", "server.ad.realm")
}

fn alice() -> PrincipalName {
    PrincipalName::new_principal("alice")
}

struct Fix {
    kdc: Kdc<MemoryStore>,
    tgs_key: EncryptionKey,
    svc_key: EncryptionKey,
}

fn fixture(modules: Vec<Arc<dyn KdcAuthdata>>) -> Fix {
    let mut store = MemoryStore::new();
    let none = PrincipalAttributes::empty();
    store
        .add_random_key(tgs_name(), REALM, 1, &[18, 17], none)
        .expect("krbtgt");
    store
        .add_with_password(alice(), REALM, PASSWORD, 1, &[18, 17], none)
        .expect("alice");
    store
        .add_random_key(svc(), REALM, 1, &[18, 17], none)
        .expect("svc");
    let key = |name: &PrincipalName| store.get(name, REALM).expect("entry").keys[0].key.clone();
    let (tgs_key, svc_key) = (key(&tgs_name()), key(&svc()));
    Fix {
        kdc: Kdc::new(KdcConfig::new(REALM), store).with_kdcauthdata(modules),
        tgs_key,
        svc_key,
    }
}

impl Fix {
    async fn login(&self) -> Credential {
        let mut ex = AsExchange::new(AsExchangeConfig::new(alice(), REALM), PASSWORD);
        let mut reply = Vec::new();
        while let StepResult::SendToKdc { data, .. } | StepResult::RetryTcp { data, .. } =
            ex.step(&reply).expect("AS step")
        {
            reply = self.kdc.handle(&data).await;
        }
        ex.credential().expect("TGT").clone()
    }

    async fn tgs(&self, tgt: &Credential, target: PrincipalName) -> Credential {
        let mut ex = TgsExchange::new(tgt.clone(), target, TgsOptions::default());
        let mut reply = Vec::new();
        loop {
            match ex.step(&reply).expect("TGS step") {
                TgsStepResult::SendToKdc { data, .. } | TgsStepResult::RetryTcp { data, .. } => {
                    reply = self.kdc.handle(&data).await;
                }
                TgsStepResult::Complete => return ex.credential().expect("cred").clone(),
            }
        }
    }
}

fn types(part: &EncTicketPart) -> Vec<i32> {
    part.authorization_data
        .iter()
        .flatten()
        .map(|e| e.ad_type)
        .collect()
}

fn key_of(k: &EncryptionKey) -> (i32, Vec<u8>) {
    (k.keytype, k.key_bytes().to_vec())
}

fn key(k: &Option<EncryptionKey>) -> (i32, Vec<u8>) {
    key_of(k.as_ref().expect("key"))
}

fn unwrap_if_relevant(el: &AuthorizationDataElement) -> Vec<AuthorizationDataElement> {
    assert_eq!(el.ad_type, AD_IF_RELEVANT);
    rasn::der::decode(el.ad_data.as_ref()).expect("IF-RELEVANT")
}

/// Records each call and adds an element of its own type; optionally fails
/// afterwards.
struct Recorder {
    name: &'static str,
    ad_type: i32,
    fail: bool,
    calls: Mutex<Vec<AuthdataRequest>>,
}

impl Recorder {
    fn new(name: &'static str, ad_type: i32, fail: bool) -> Arc<Self> {
        Arc::new(Self {
            name,
            ad_type,
            fail,
            calls: Mutex::new(Vec::new()),
        })
    }
}

impl KdcAuthdata for Recorder {
    fn name(&self) -> &str {
        self.name
    }
    fn handle(&self, req: &AuthdataRequest, reply: &mut EncTicketPart) -> Result<(), i32> {
        self.calls.lock().expect("lock").push(req.clone());
        if self.fail {
            return Err(-1_765_328_324);
        }
        let el = AuthorizationDataElement {
            ad_type: self.ad_type,
            ad_data: self.name.as_bytes().to_vec().into(),
        };
        reply
            .authorization_data
            .get_or_insert_with(Vec::new)
            .push(el);
        Ok(())
    }
}

#[tokio::test]
async fn greet_adds_a_signed_greeting_to_tgs_tickets_only() {
    let f = fixture(vec![Arc::new(Greet)]);
    let tgt = f.login().await;
    let tgt_part = decrypt_ticket(&f.tgs_key, &tgt.ticket).expect("TGT");
    assert!(!types(&tgt_part).is_empty());
    assert!(tgt_part
        .authorization_data
        .iter()
        .flatten()
        .filter(|e| e.ad_type == AD_IF_RELEVANT)
        .flat_map(unwrap_if_relevant)
        .all(|e| e.ad_type != 4));

    let cred = f.tgs(&tgt, svc()).await;
    let part = decrypt_ticket(&f.svc_key, &cred.ticket).expect("service ticket");
    let ad = part.authorization_data.as_deref().expect("authdata");
    // The PAC goes first (krb5_kdc_sign_ticket), then the greeting.
    assert_eq!(ad.len(), 2);
    assert_eq!(unwrap_if_relevant(&ad[0])[0].ad_type, AD_WIN2K_PAC);
    let inner = unwrap_if_relevant(&ad[1]);
    assert_eq!(inner.len(), 1);
    let (issuer, elements) = verify_authdata_kdc_issued(&part.key, &inner[0]).expect("signed");
    assert_eq!(issuer, Some((tgs_name(), REALM.to_string())));
    assert_eq!(elements.len(), 1);
    assert_eq!(elements[0].ad_type, AD_GREET);
    assert_eq!(elements[0].ad_data.as_ref(), GREETING.as_bytes());
    // Not verifiable with another key.
    assert!(verify_authdata_kdc_issued(&f.svc_key, &inner[0]).is_none());
}

#[tokio::test]
async fn modules_get_mit_arguments_in_order_and_errors_do_not_stop_tickets() {
    let a = Recorder::new("a", -100, false);
    let failing = Recorder::new("failing", -101, true);
    let b = Recorder::new("b", -102, false);
    let f = fixture(vec![a.clone(), failing.clone(), b.clone()]);
    let tgt = f.login().await;
    let tgt_part = decrypt_ticket(&f.tgs_key, &tgt.ticket).expect("TGT");
    let t = types(&tgt_part);
    // The PAC goes first (krb5_kdc_sign_ticket), after the modules run.
    assert_eq!(t, [AD_IF_RELEVANT, -100, -102]);

    let calls = a.calls.lock().expect("lock").clone();
    assert_eq!(calls.len(), 1);
    let as_req = &calls[0];
    assert_eq!(as_req.msg_type, MSG_AS_REQ);
    assert_eq!(as_req.flags & kdb_flags::CLIENT, kdb_flags::CLIENT);
    assert_eq!(as_req.client, Some((alice(), REALM.into())));
    assert_eq!(as_req.server, Some((tgs_name(), REALM.into())));
    assert_eq!(key(&as_req.server_key), key_of(&f.tgs_key));
    assert!(as_req.client_key.is_some());
    assert!(as_req.header_server.is_none() && as_req.enc_tkt_req.is_none());
    let name = |e: &Option<krb5_rs::kdc::PrincipalEntry>| e.as_ref().map(|e| e.name.clone());
    assert_eq!(name(&as_req.client_entry), Some(alice()));
    assert_eq!(name(&as_req.server_entry), Some(tgs_name()));
    assert!(as_req.header_server_entry.is_none());
    assert!(!as_req.req_pkt.is_empty());

    let cred = f.tgs(&tgt, svc()).await;
    let part = decrypt_ticket(&f.svc_key, &cred.ticket).expect("service ticket");
    let t = types(&part);
    // The PAC, the modules' data, then the header ticket's (copied after
    // the modules run).
    assert_eq!(t, [AD_IF_RELEVANT, -100, -102, -100, -102]);
    let calls = b.calls.lock().expect("lock").clone();
    assert_eq!(calls.len(), 2);
    let tgs_req = &calls[1];
    assert_eq!(tgs_req.msg_type, MSG_TGS_REQ);
    assert_eq!(tgs_req.flags, 0);
    assert_eq!(tgs_req.client, Some((alice(), REALM.into())));
    assert_eq!(tgs_req.server, Some((svc(), REALM.into())));
    assert_eq!(tgs_req.header_server, Some((tgs_name(), REALM.into())));
    assert_eq!(key(&tgs_req.header_key), key_of(&f.tgs_key));
    assert_eq!(key(&tgs_req.server_key), key_of(&f.svc_key));
    assert_eq!(name(&tgs_req.client_entry), Some(alice()));
    assert_eq!(name(&tgs_req.server_entry), Some(svc()));
    assert_eq!(name(&tgs_req.header_server_entry), Some(tgs_name()));
    // The TGS reply key: the client's subkey here.
    assert!(tgs_req.client_key.is_some());
    assert_eq!(
        tgs_req.enc_tkt_req.as_ref().map(|p| p.authtime),
        Some(tgt_part.authtime)
    );
    assert_eq!(failing.calls.lock().expect("lock").len(), 2);
}

#[tokio::test]
async fn modules_are_skipped_for_anonymous_tickets() {
    let a = Recorder::new("a", -100, false);
    let f = fixture(vec![a.clone()]);
    let tgt = f.login().await;
    let mut part = decrypt_ticket(&f.tgs_key, &tgt.ticket).expect("TGT");
    part.flags.insert(TicketFlags::ANONYMOUS);
    let mut anon = tgt.clone();
    anon.ticket = encrypt_ticket_part(&f.tgs_key, Some(1), REALM, tgt.ticket.sname.clone(), &part)
        .expect("re-encrypt");
    let cred = f.tgs(&anon, tgs_name()).await;
    let out = decrypt_ticket(&f.tgs_key, &cred.ticket).expect("ticket");
    assert!(out.flags.contains(TicketFlags::ANONYMOUS));
    assert_eq!(a.calls.lock().expect("lock").len(), 1);
}

#[cfg(unix)]
#[tokio::test]
async fn greet_over_rpc() {
    use krb5_rs::kdc::plugins::rpc::{kdcauthdata, serve_kdcauthdata};
    use std::os::unix::net::UnixListener;

    let path = std::env::temp_dir().join(format!("krb5rs-greet-{}.sock", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let l = UnixListener::bind(&path).expect("bind");
    std::thread::spawn(move || {
        for s in l.incoming().map_while(Result::ok) {
            std::thread::spawn(move || serve_kdcauthdata(s, &Greet));
        }
    });
    let remote = kdcauthdata("greet", krb5_rs::plugin::connector(path)).expect("connect");
    assert_eq!(remote.name(), "greet");
    let f = fixture(vec![Arc::new(remote)]);
    let tgt = f.login().await;
    let cred = f.tgs(&tgt, svc()).await;
    let part = decrypt_ticket(&f.svc_key, &cred.ticket).expect("service ticket");
    let inner = unwrap_if_relevant(&part.authorization_data.as_deref().expect("authdata")[1]);
    let (issuer, elements) = verify_authdata_kdc_issued(&part.key, &inner[0]).expect("signed");
    assert_eq!(issuer, Some((tgs_name(), REALM.to_string())));
    assert_eq!(elements[0].ad_data.as_ref(), GREETING.as_bytes());
}
