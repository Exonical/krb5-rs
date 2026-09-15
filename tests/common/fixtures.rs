//! Synthetic principals, keys, tickets, and GSS step helpers shared by the
//! mit-checks binaries.

use chrono::{Timelike, Utc};
use krb5_rs::crypto::find_etype;
use krb5_rs::gssapi::krb5::{AcceptStep, InitStep};
use krb5_rs::protocol::ap::encrypt_ticket_part;
use krb5_rs::protocol::{Credential, StepResult, TgsStepResult, TicketTimes};
use krb5_rs::types::{
    EncTicketPart, EncryptionKey, HostAddress, KerberosFlags, KerberosTime, PrincipalName, Realm,
    TicketFlags, TransitedEncoding,
};
use rasn::types::{GeneralString, OctetString};

pub const REALM: &str = "EXAMPLE.COM";

pub fn now() -> KerberosTime {
    let t = Utc::now();
    t.with_nanosecond(0).unwrap_or(t).fixed_offset()
}

pub fn secs(n: i64) -> KerberosTime {
    (Utc::now() + chrono::Duration::seconds(n))
        .fixed_offset()
        .with_nanosecond(0)
        .expect("valid")
}

pub fn realm() -> Realm {
    GeneralString::from_bytes(REALM.as_bytes()).expect("realm")
}

pub fn gs<S: AsRef<[u8]>>(s: S) -> GeneralString {
    GeneralString::from_bytes(s.as_ref()).expect("general string")
}

pub fn alice() -> PrincipalName {
    PrincipalName::new_principal("alice")
}

pub fn service() -> PrincipalName {
    PrincipalName::new_srv_hst("HTTP", "www.example.com")
}

pub fn krbtgt() -> PrincipalName {
    PrincipalName::new_srv_inst("krbtgt", REALM)
}

pub fn random_key(etype: i32) -> EncryptionKey {
    use std::sync::atomic::{AtomicUsize, Ordering};
    static COUNTER: AtomicUsize = AtomicUsize::new(0);
    let profile = find_etype(etype).expect("etype");
    let tag = COUNTER.fetch_add(1, Ordering::Relaxed) as u8;
    let rnd: Vec<u8> = (0..profile.key_bytes())
        .map(|i| (i as u8).wrapping_mul(31).wrapping_add(tag))
        .collect();
    EncryptionKey::new(etype, profile.random_to_key(&rnd).expect("r2k").to_vec())
}

/// Mint a credential the way a KDC would issue it.
pub fn mint_full(
    service_key: &EncryptionKey,
    session_key: &EncryptionKey,
    sname: PrincipalName,
    start: Option<KerberosTime>,
    end: KerberosTime,
    flags: TicketFlags,
    caddr: Option<Vec<HostAddress>>,
) -> Credential {
    let part = EncTicketPart {
        flags: KerberosFlags::new(flags),
        key: session_key.clone(),
        crealm: realm(),
        cname: alice(),
        transited: TransitedEncoding {
            tr_type: 1,
            contents: OctetString::from(Vec::new()),
        },
        authtime: now(),
        starttime: start,
        endtime: end,
        renew_till: None,
        caddr: caddr.clone(),
        authorization_data: None,
    };
    let ticket = encrypt_ticket_part(service_key, Some(1), REALM, sname.clone(), &part)
        .expect("encrypt_ticket_part");
    Credential {
        client: alice(),
        crealm: REALM.to_string(),
        server: sname,
        srealm: REALM.to_string(),
        session_key: session_key.clone(),
        times: TicketTimes {
            authtime: part.authtime,
            starttime: start,
            endtime: end,
            renew_till: None,
        },
        ticket,
        flags: KerberosFlags::new(flags),
        addresses: caddr,
        authdata: None,
    }
}

pub fn mint(
    service_key: &EncryptionKey,
    session_key: &EncryptionKey,
    sname: PrincipalName,
    flags: TicketFlags,
) -> Credential {
    mint_full(
        service_key,
        session_key,
        sname,
        None,
        secs(3600),
        flags,
        None,
    )
}

pub fn svc_cred(service_key: &EncryptionKey, session_etype: i32) -> (Credential, EncryptionKey) {
    let session = random_key(session_etype);
    (
        mint(service_key, &session, service(), TicketFlags::empty()),
        session,
    )
}

pub fn svc_cred2(service_key: &EncryptionKey, session_etype: i32) -> Credential {
    let _ = service_key;
    let _ = session_etype;
    mint(
        &random_key(18),
        &random_key(18),
        krbtgt(),
        TicketFlags::RENEWABLE | TicketFlags::FORWARDABLE,
    )
}

pub fn unwrap_step(s: InitStep) -> Option<Vec<u8>> {
    match s {
        InitStep::Complete(t) => t,
        InitStep::Continue(t) => Some(t),
    }
}

pub fn init_complete(s: InitStep) -> Option<Vec<u8>> {
    match s {
        InitStep::Complete(t) => t,
        other => panic!("expected Complete, got {other:?}"),
    }
}

pub fn accept_complete(s: AcceptStep) -> Option<Vec<u8>> {
    match s {
        AcceptStep::Complete { token } => token,
        other => panic!("expected Complete, got {other:?}"),
    }
}

pub fn unwrap_send(r: StepResult) -> Vec<u8> {
    match r {
        StepResult::SendToKdc { data, .. } | StepResult::RetryTcp { data, .. } => data,
        StepResult::Complete => panic!("expected SendToKdc"),
    }
}

pub fn unwrap_tgs_send(r: TgsStepResult) -> Vec<u8> {
    match r {
        TgsStepResult::SendToKdc { data, .. } | TgsStepResult::RetryTcp { data, .. } => data,
        TgsStepResult::Complete => panic!("expected SendToKdc"),
    }
}
