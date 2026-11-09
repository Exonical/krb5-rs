#![cfg(all(feature = "kdc", unix))]
//! SAM-2 pre-authentication (MIT `securid_sam2` KDC module and the `sam2`
//! client module), our client against our KDC, with GRAIL and a fake
//! ACE/Server in place of RSA's.

use std::sync::{Arc, Mutex};

use krb5_rs::kdc::plugins::rpc;
use krb5_rs::kdc::securid_sam2::{acm, AceServer, PinParams, SecuridSam2};
use krb5_rs::kdc::{Kdc, KdcConfig, MemoryStore, PrincipalAttributes};
use krb5_rs::protocol::{AsExchange, AsExchangeConfig, Credential, StepResult};
use krb5_rs::sam2::{Sam2Prompt, Sam2Responder, PA_SAM_RESPONSE_2};
use krb5_rs::types::*;
use krb5_rs::Krb5Error;

const REALM: &str = "EXAMPLE.COM";
const PW: &str = "the-real-password";

fn name(n: &str) -> PrincipalName {
    PrincipalName::new_principal(n)
}

fn store(sam: &[&str]) -> MemoryStore {
    let mut store = MemoryStore::new();
    store
        .add_random_key(
            PrincipalName::new_srv_inst("krbtgt", REALM),
            REALM,
            1,
            &[18, 17],
            PrincipalAttributes::empty(),
        )
        .unwrap();
    store
        .add_with_password(
            name("user"),
            REALM,
            PW,
            1,
            &[18, 17],
            PrincipalAttributes::REQUIRES_PRE_AUTH | PrincipalAttributes::REQUIRES_HW_AUTH,
        )
        .unwrap();
    for inst in sam {
        store
            .add_random_key(
                PrincipalName::new_srv_inst("user", inst),
                REALM,
                1,
                &[18],
                PrincipalAttributes::empty(),
            )
            .unwrap();
    }
    store
}

#[derive(Default)]
struct FakeAce {
    log: Mutex<Vec<String>>,
}

impl AceServer for FakeAce {
    fn init(&self) -> Result<u32, i32> {
        self.log.lock().unwrap().push("init".into());
        Ok(7)
    }
    fn lock(&self, handle: u32, user: &str) -> i32 {
        self.log
            .lock()
            .unwrap()
            .push(format!("lock {handle} {user}"));
        acm::OK
    }
    fn check(&self, handle: u32, passcode: &str, user: &str) -> i32 {
        self.log
            .lock()
            .unwrap()
            .push(format!("check {handle} {passcode} {user}"));
        match passcode {
            "123456" => acm::OK,
            "next" => acm::NEXT_CODE_REQUIRED,
            "newpin" => acm::NEW_PIN_REQUIRED,
            "odd" => 99,
            _ => acm::ACCESS_DENIED,
        }
    }
    fn next(&self, _handle: u32, passcode: &str) -> i32 {
        if passcode == "654321" {
            acm::OK
        } else {
            acm::ACCESS_DENIED
        }
    }
    fn pin(&self, _handle: u32, _pin: &str) -> i32 {
        acm::NEW_PIN_ACCEPTED
    }
    fn close(&self, handle: u32) {
        self.log.lock().unwrap().push(format!("close {handle}"));
    }
    fn pin_params(&self, _handle: u32) -> Option<PinParams> {
        Some(PinParams {
            min: 4,
            max: 8,
            alphanumeric: false,
        })
    }
}

type Prompts = Arc<Mutex<Vec<Sam2Prompt>>>;

fn responder(
    prompts: &Prompts,
    answer: impl Fn(&Sam2Prompt) -> Option<String> + Send + Sync + 'static,
) -> Sam2Responder {
    let prompts = prompts.clone();
    Sam2Responder(Arc::new(move |p: &Sam2Prompt| {
        prompts.lock().unwrap().push(p.clone());
        answer(p)
    }))
}

/// GRAIL's prompt is "Enter <n>" and its answer is n.
fn grail_answer(p: &Sam2Prompt) -> Option<String> {
    p.prompt.strip_prefix("Enter ").map(str::to_string)
}

async fn run(kdc: &Kdc<MemoryStore>, sam2: Option<Sam2Responder>) -> Result<Credential, Krb5Error> {
    let mut cfg = AsExchangeConfig::new(name("user"), REALM);
    cfg.sam2 = sam2;
    let mut ex = AsExchange::new(cfg, PW);
    let mut input = Vec::new();
    loop {
        match ex.step(&input)? {
            StepResult::SendToKdc { data, .. } | StepResult::RetryTcp { data, .. } => {
                input = kdc.handle(&data).await;
            }
            StepResult::Complete => return ex.credential().cloned(),
        }
    }
}

fn grail_kdc(sam: &[&str]) -> Kdc<MemoryStore> {
    Kdc::builder(KdcConfig::new(REALM), store(sam))
        .securid_sam2(SecuridSam2::new(None).with_grail())
        .build()
}

fn securid_kdc(ace: Arc<dyn AceServer>) -> Kdc<MemoryStore> {
    Kdc::builder(KdcConfig::new(REALM), store(&["SECURID"]))
        .securid_sam2(SecuridSam2::new(Some(ace)))
        .build()
}

fn kdc_code(e: &Krb5Error) -> Option<i32> {
    match e {
        Krb5Error::KdcError(m) => Some(m.error_code),
        _ => None,
    }
}

#[tokio::test]
async fn grail_login_gets_hardware_authenticated_ticket() {
    let kdc = grail_kdc(&["GRAIL"]);
    let prompts = Prompts::default();
    let cred = run(&kdc, Some(responder(&prompts, grail_answer)))
        .await
        .expect("GRAIL login");
    assert!(cred.flags.contains(TicketFlags::HW_AUTHENT));
    assert!(cred.flags.contains(TicketFlags::PRE_AUTHENT));
    let p = prompts.lock().unwrap()[0].clone();
    assert_eq!(p.name, "SAM Authentication");
    assert_eq!(p.banner, "Challenge from authentication server");
    assert!(p.prompt.starts_with("Enter "));
}

#[tokio::test]
async fn grail_wrong_answer_is_refused() {
    let kdc = grail_kdc(&["GRAIL"]);
    let prompts = Prompts::default();
    let e = run(&kdc, Some(responder(&prompts, |_| Some("x1".into()))))
        .await
        .expect_err("wrong SAD");
    assert_eq!(kdc_code(&e), Some(24), "{e:?}");
}

#[tokio::test]
async fn without_a_responder_hardware_preauth_is_impossible() {
    let kdc = grail_kdc(&["GRAIL"]);
    assert!(run(&kdc, None).await.is_err());
}

#[tokio::test]
async fn grail_is_off_unless_enabled() {
    let kdc = Kdc::builder(KdcConfig::new(REALM), store(&["GRAIL"]))
        .securid_sam2(SecuridSam2::new(None))
        .build();
    let prompts = Prompts::default();
    assert!(run(&kdc, Some(responder(&prompts, grail_answer)))
        .await
        .is_err());
    assert!(prompts.lock().unwrap().is_empty());
}

#[tokio::test]
async fn no_sam_entry_no_challenge() {
    let kdc = grail_kdc(&[]);
    let prompts = Prompts::default();
    assert!(run(&kdc, Some(responder(&prompts, grail_answer)))
        .await
        .is_err());
    assert!(prompts.lock().unwrap().is_empty());
}

#[tokio::test]
async fn securid_passcode_accepted() {
    let ace = Arc::new(FakeAce::default());
    let kdc = securid_kdc(ace.clone());
    let prompts = Prompts::default();
    let cred = run(&kdc, Some(responder(&prompts, |_| Some("123456".into()))))
        .await
        .expect("SecurID login");
    assert!(cred.flags.contains(TicketFlags::HW_AUTHENT));
    let p = prompts.lock().unwrap()[0].clone();
    assert_eq!(p.prompt, "SecurID Passcode");
    assert_eq!(p.banner, "Challenge for Security Dynamics mechanism");
    assert_eq!(
        *ace.log.lock().unwrap(),
        ["init", "lock 7 user", "check 7 123456 user", "close 7"]
    );
}

#[tokio::test]
async fn securid_access_denied() {
    let kdc = securid_kdc(Arc::new(FakeAce::default()));
    let prompts = Prompts::default();
    let e = run(&kdc, Some(responder(&prompts, |_| Some("000000".into()))))
        .await
        .expect_err("denied");
    assert_eq!(kdc_code(&e), Some(24), "{e:?}");
}

#[tokio::test]
async fn securid_next_code_is_preauth_required_without_a_challenge() {
    // MIT builds a next-code challenge but passes no e-data to respond, so
    // the client sees KDC_ERR_PREAUTH_REQUIRED alone.
    let ace = Arc::new(FakeAce::default());
    let kdc = securid_kdc(ace.clone());
    let prompts = Prompts::default();
    let e = run(&kdc, Some(responder(&prompts, |_| Some("next".into()))))
        .await
        .expect_err("next code");
    assert_eq!(kdc_code(&e), Some(25), "{e:?}");
    // The session can't be resumed, so it is closed (MIT leaks it).
    assert_eq!(
        ace.log.lock().unwrap().last().map(String::as_str),
        Some("close 7")
    );
}

#[tokio::test]
async fn securid_sessions_are_closed_on_every_outcome() {
    for (passcode, code) in [("newpin", 25), ("odd", 24), ("000000", 24)] {
        let ace = Arc::new(FakeAce::default());
        let kdc = securid_kdc(ace.clone());
        let prompts = Prompts::default();
        let pc = passcode.to_string();
        let e = run(&kdc, Some(responder(&prompts, move |_| Some(pc.clone()))))
            .await
            .expect_err(passcode);
        assert_eq!(kdc_code(&e), Some(code), "{passcode}: {e:?}");
        let log = ace.log.lock().unwrap();
        let opened = log.iter().filter(|l| *l == "init").count();
        let closed = log.iter().filter(|l| l.starts_with("close")).count();
        assert_eq!(opened, closed, "{passcode}: {log:?}");
    }
}

#[tokio::test]
async fn securid_over_rpc() {
    let (ours, theirs) = std::os::unix::net::UnixStream::pair().unwrap();
    let ace = Arc::new(FakeAce::default());
    let served = ace.clone();
    std::thread::spawn(move || rpc::serve_securid_ace(theirs, served.as_ref()));
    let slot = Mutex::new(Some(ours));
    let connect: rpc::Connect = Box::new(move || {
        let s = slot
            .lock()
            .unwrap()
            .take()
            .ok_or(std::io::ErrorKind::NotConnected)?;
        Ok(Box::new(s) as Box<dyn rpc::Stream>)
    });
    let remote = rpc::securid_ace("securid_sam2", connect).expect("connect");
    let kdc = securid_kdc(Arc::new(remote));
    let prompts = Prompts::default();
    let cred = run(&kdc, Some(responder(&prompts, |_| Some("123456".into()))))
        .await
        .expect("SecurID over RPC");
    assert!(cred.flags.contains(TicketFlags::HW_AUTHENT));
    assert_eq!(ace.log.lock().unwrap().len(), 4);
}

/// A second store with the same principals and keys as `s`.
fn copy(s: &MemoryStore) -> MemoryStore {
    let mut out = MemoryStore::new();
    for n in [
        PrincipalName::new_srv_inst("krbtgt", REALM),
        name("user"),
        PrincipalName::new_srv_inst("user", "SECURID"),
    ] {
        out.insert(s.get(&n, REALM).expect("entry"));
    }
    out
}

#[tokio::test]
async fn response_with_another_hosts_track_data_is_discarded() {
    // verify_securid_data_2: track data from another host is
    // KRB5KDC_ERR_DISCARD, and the KDC sends no reply.
    let ace = Arc::new(FakeAce::default());
    let s = store(&["SECURID"]);
    let b = Kdc::builder(KdcConfig::new(REALM), copy(&s))
        .securid_sam2(SecuridSam2::new(Some(ace.clone())).with_hostid(2))
        .build();
    let a = Kdc::builder(KdcConfig::new(REALM), s)
        .securid_sam2(SecuridSam2::new(Some(ace.clone())).with_hostid(1))
        .build();
    let mut cfg = AsExchangeConfig::new(name("user"), REALM);
    let prompts = Prompts::default();
    cfg.sam2 = Some(responder(&prompts, |_| Some("123456".into())));
    let mut ex = AsExchange::new(cfg, PW);
    let mut input = Vec::new();
    loop {
        let StepResult::SendToKdc { data, .. } = ex.step(&input).expect("step") else {
            panic!("unexpected step");
        };
        let req: AsReq = rasn::der::decode(&data).expect("AS-REQ");
        if req
            .0
            .padata
            .iter()
            .flatten()
            .any(|p| p.padata_type == PA_SAM_RESPONSE_2)
        {
            assert!(b.handle(&data).await.is_empty());
            assert!(!a.handle(&data).await.is_empty());
            break;
        }
        input = a.handle(&data).await;
    }
    assert!(ace
        .log
        .lock()
        .unwrap()
        .iter()
        .all(|l| !l.starts_with("check") || l.ends_with("user")));
}
