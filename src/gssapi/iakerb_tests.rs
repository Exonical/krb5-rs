//! IAKERB through an in-process KDC, after MIT tests/gssapi/t_gssapi.py:20-46
//! and t_iakerb.c.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::*;
use crate::kdc::{Kdc, KdcConfig, MemoryStore, PrincipalAttributes};
use crate::keytab::{KeytabEntry, MemoryKeytab};
use crate::locate::LocateError;
use crate::transport::sendto::SendtoError;
use rasn::types::GeneralString;

const REALM: &str = "IAKERB.REALM";
const PW: &str = "iakerb-password";

fn gs(s: &str) -> GeneralString {
    GeneralString::from_bytes(s.as_bytes()).unwrap()
}

fn princ(parts: &[&str], nt: i32) -> PrincipalName {
    PrincipalName {
        name_type: nt,
        name_string: parts.iter().map(|p| gs(p)).collect(),
    }
}

fn user() -> PrincipalName {
    princ(&["user"], 1)
}

fn host() -> PrincipalName {
    princ(&["host", "server.example"], 3)
}

struct Fix {
    kdc: Kdc<MemoryStore>,
    entries: Vec<KeytabEntry>,
}

impl Fix {
    fn keytab(&self) -> Box<MemoryKeytab> {
        Box::new(MemoryKeytab::from_entries(self.entries.clone()))
    }
}

fn fixture() -> Fix {
    let mut store = MemoryStore::new();
    let none = PrincipalAttributes::empty();
    store
        .add_random_key(princ(&["krbtgt", REALM], 2), REALM, 1, &[18, 17], none)
        .unwrap();
    store
        .add_with_password(user(), REALM, PW, 1, &[18, 17], none)
        .unwrap();
    store
        .add_random_key(host(), REALM, 1, &[18, 17], none)
        .unwrap();
    let entries: Vec<KeytabEntry> = store
        .get(&host(), REALM)
        .unwrap()
        .keys
        .iter()
        .map(|k| KeytabEntry {
            principal: host(),
            realm: REALM.into(),
            timestamp: 0,
            kvno: 1,
            key: k.key.clone(),
        })
        .collect();
    Fix {
        kdc: Kdc::builder(KdcConfig::new(REALM), store).build(),
        entries,
    }
}

#[derive(Clone, Copy, PartialEq)]
enum Kdcs {
    Up,
    Unreachable,
}

impl Fix {
    fn acceptor(&self, realm: Option<&str>) -> IakerbAcceptor {
        IakerbAcceptor::new(self.keytab(), Some(host()), realm.map(str::to_owned), None)
    }

    fn initiator(&self, cred: IakerbCred, flags: GssFlags) -> IakerbInitiator {
        IakerbInitiator::new(cred, host(), TgsOptions::default(), flags, None)
    }

    /// Run both sides to completion, sending proxied requests to the KDC.
    async fn drive(
        &self,
        init: &mut IakerbInitiator,
        acc: &mut IakerbAcceptor,
        kdcs: Kdcs,
    ) -> Result<usize, Krb5Error> {
        let mut input: Option<Vec<u8>> = None;
        for round in 0..64 {
            let token = match init.step(input.as_deref())? {
                InitStep::Continue(t) => t,
                InitStep::Complete(None) => return Ok(round),
                InitStep::Complete(Some(t)) => {
                    acc.step(&t)?;
                    return Ok(round);
                }
            };
            input = Some(match acc.step(&token)? {
                IakerbAcceptStep::Continue(t) => t,
                IakerbAcceptStep::SendToKdc { realm, data } => {
                    let reply = if kdcs == Kdcs::Unreachable {
                        Err(Krb5Error::Sendto(SendtoError::KdcUnreach))
                    } else if realm != REALM {
                        Err(Krb5Error::Locate(LocateError::RealmUnknown))
                    } else {
                        Ok(self.kdc.handle(&data).await)
                    };
                    acc.kdc_reply(reply)?
                }
                IakerbAcceptStep::Complete { token: Some(t) } => t,
                IakerbAcceptStep::Complete { token: None } => return Ok(round),
            });
        }
        panic!("no completion");
    }

    async fn tgt(&self) -> Credential {
        let mut ex = AsExchange::new(AsExchangeConfig::new(user(), REALM), PW);
        let mut reply = Vec::new();
        while let StepResult::SendToKdc { data, .. } | StepResult::RetryTcp { data, .. } =
            ex.step(&reply).unwrap()
        {
            reply = self.kdc.handle(&data).await;
        }
        ex.credential().unwrap().clone()
    }
}

fn pw_cred(realm: &str) -> IakerbCred {
    IakerbCred {
        client: user(),
        realm: realm.into(),
        password: Some(PW.into()),
        tgt: None,
        service: None,
    }
}

fn mic_roundtrip(init: IakerbInitiator, acc: IakerbAcceptor) {
    let mut i = init.context().unwrap();
    let mut a = acc.context().unwrap();
    let mic = i.get_mic(b"iakerb").unwrap();
    a.verify_mic(b"iakerb", &mic).unwrap();
    let w = a.wrap(true, b"back").unwrap();
    i.unwrap(&w).unwrap();
}

#[tokio::test]
async fn password_acquires_tgt_and_ticket_through_the_acceptor() {
    let f = fixture();
    let mut init = f.initiator(pw_cred(REALM), GssFlags::MUTUAL);
    let mut acc = f.acceptor(Some(REALM));
    f.drive(&mut init, &mut acc, Kdcs::Up).await.unwrap();
    assert!(init.tgt().is_some());
    assert_eq!(
        init.service_ticket().unwrap().server.name_string,
        host().name_string
    );
    mic_roundtrip(init, acc);
}

#[tokio::test]
async fn existing_tgt_starts_with_the_tgs_request() {
    let f = fixture();
    let mut cred = pw_cred(REALM);
    cred.password = None;
    cred.tgt = Some(f.tgt().await);
    let mut init = f.initiator(cred, GssFlags::MUTUAL);
    let mut acc = f.acceptor(Some(REALM));
    f.drive(&mut init, &mut acc, Kdcs::Up).await.unwrap();
    mic_roundtrip(init, acc);
}

#[tokio::test]
async fn non_mutual_completes_with_the_ap_req() {
    let f = fixture();
    let mut init = f.initiator(pw_cred(REALM), GssFlags::empty());
    let mut acc = f.acceptor(Some(REALM));
    f.drive(&mut init, &mut acc, Kdcs::Up).await.unwrap();
    mic_roundtrip(init, acc);
}

#[tokio::test]
async fn realm_discovery_learns_the_acceptor_realm() {
    let f = fixture();
    let mut init = f.initiator(pw_cred(""), GssFlags::MUTUAL);
    let mut acc = f.acceptor(Some(REALM));
    f.drive(&mut init, &mut acc, Kdcs::Up).await.unwrap();
    assert_eq!(init.client_realm(), REALM);
    mic_roundtrip(init, acc);
}

#[tokio::test]
async fn realm_discovery_without_an_acceptor_realm_fails() {
    let f = fixture();
    let mut init = f.initiator(pw_cred(""), GssFlags::MUTUAL);
    let mut acc = f.acceptor(None);
    let err = f.drive(&mut init, &mut acc, Kdcs::Up).await.unwrap_err();
    assert!(
        err.to_string()
            .contains("The IAKERB proxy could not determine its realm"),
        "{err}"
    );
}

#[tokio::test]
async fn wrong_realm_is_kdc_not_found() {
    let f = fixture();
    let mut init = f.initiator(pw_cred("WRONG.REALM"), GssFlags::MUTUAL);
    let mut acc = f.acceptor(Some(REALM));
    match f.drive(&mut init, &mut acc, Kdcs::Up).await {
        Err(Krb5Error::KdcError(e)) => assert_eq!(e.error_code, KRB_AP_ERR_IAKERB_KDC_NOT_FOUND),
        other => panic!("{:?}", other.err()),
    }
}

#[tokio::test]
async fn unreachable_kdc_is_kdc_no_response() {
    let f = fixture();
    let mut init = f.initiator(pw_cred(REALM), GssFlags::MUTUAL);
    let mut acc = f.acceptor(Some(REALM));
    match f.drive(&mut init, &mut acc, Kdcs::Unreachable).await {
        Err(Krb5Error::KdcError(e)) => {
            assert_eq!(e.error_code, KRB_AP_ERR_IAKERB_KDC_NO_RESPONSE)
        }
        other => panic!("{:?}", other.err()),
    }
}

#[tokio::test]
async fn wrong_password_fails_the_as_exchange() {
    let f = fixture();
    let mut cred = pw_cred(REALM);
    cred.password = Some("wrong".into());
    let mut init = f.initiator(cred, GssFlags::MUTUAL);
    let mut acc = f.acceptor(Some(REALM));
    assert!(f.drive(&mut init, &mut acc, Kdcs::Up).await.is_err());
}

#[tokio::test]
async fn cached_service_ticket_skips_iakerb() {
    let f = fixture();
    let mut first = f.initiator(pw_cred(REALM), GssFlags::MUTUAL);
    let mut acc = f.acceptor(Some(REALM));
    f.drive(&mut first, &mut acc, Kdcs::Up).await.unwrap();
    let mut cred = pw_cred(REALM);
    cred.tgt = first.tgt().cloned();
    cred.service = first.service_ticket().cloned();
    let mut init = f.initiator(cred, GssFlags::MUTUAL);
    let mut acc = f.acceptor(Some(REALM));
    // AP-REQ then AP-REP: no proxy tokens, so no FINISHED.
    let rounds = f.drive(&mut init, &mut acc, Kdcs::Up).await.unwrap();
    assert_eq!(rounds, 1);
    mic_roundtrip(init, acc);
}

/// Mismatched transcripts: FINISHED fails to verify; FINISHED missing when
/// the acceptor saw IAKERB tokens is GSS_S_BAD_SIG; FINISHED with no
/// transcript fails (accept_sec_context.c:383-388, 850-853).
#[tokio::test]
async fn finished_checksum_must_cover_the_acceptor_transcript() {
    let f = fixture();
    let mut first = f.initiator(pw_cred(REALM), GssFlags::empty());
    let mut acc = f.acceptor(Some(REALM));
    f.drive(&mut first, &mut acc, Kdcs::Up).await.unwrap();
    let svc = first.service_ticket().unwrap().clone();
    let ap_req = |conv: &[u8]| {
        let mut i = Krb5Initiator::new(svc.clone(), None, GssFlags::empty(), None)
            .unwrap()
            .with_iakerb(conv.to_vec());
        match i.step(None).unwrap() {
            InitStep::Complete(Some(t)) => t,
            _ => panic!("non-mutual AP-REQ"),
        }
    };
    let accept = |tok: &[u8], conv: &[u8]| {
        Krb5Acceptor::new(f.keytab(), Some(host()), None)
            .with_iakerb(conv.to_vec())
            .step(tok)
    };
    assert!(accept(&ap_req(b"conv"), b"conv").is_ok());
    assert!(matches!(
        accept(&ap_req(b"conv"), b"other"),
        Err(Krb5Error::Gss(GssError::Failure))
    ));
    assert!(matches!(
        accept(&ap_req(b""), b"conv"),
        Err(Krb5Error::Gss(GssError::BadSig))
    ));
    assert!(matches!(
        accept(&ap_req(b"conv"), b""),
        Err(Krb5Error::Gss(GssError::Failure))
    ));
}

#[test]
fn token_roundtrip_and_rejection() {
    let tok = make_token("R", Some(b"c"), b"msg").unwrap();
    assert!(is_iakerb_token(&tok));
    let p = parse_token(&tok).unwrap();
    assert_eq!(
        (p.realm.as_str(), p.cookie.as_deref(), p.message),
        ("R", Some(&b"c"[..]), &b"msg"[..])
    );
    let mut bad = tok.clone();
    // 0x60 len 0x06 len <6-byte OID> 05 01 ...
    assert_eq!(&bad[10..12], &[0x05, 0x01]);
    bad[11] = 0x02;
    assert!(!is_iakerb_token(&bad));
    assert!(parse_token(&bad).is_err());
    assert!(parse_token(&tok[..tok.len() - 6]).is_err());
}
