//! MIT-semantics checks for RFC 4178 SPNEGO over the krb5 mechanism.
//!
//! Grounded in MIT krb5 1.22.2 (krb5-ref): lib/gssapi/spnego/spnego_mech.c
//! (get_negTokenInit:3407, get_negTokenResp:3480, make_spnego_tokenInit_msg:3618,
//! make_spnego_tokenTarg_msg:3702, handle_mic:539, process_mic:601,
//! init_ctx_nego:763, init_ctx_reselect:836, init_ctx_call_init:880,
//! acc_ctx_hints:1227, acc_ctx_new:1283, acc_ctx_cont:1361,
//! acc_ctx_vfy_oid:1424, acc_ctx_call_acc:1471, negotiate_mech:3551,
//! is_kerb_mech:3814 + gss_mech_set_krb5_both in krb5/gssapi_krb5.c:188).

use krb5_rs::crypto::find_etype;
use krb5_rs::gssapi::krb5::{
    AcceptStep, GssFlags, InitStep, Krb5Acceptor, Krb5Initiator, MECH_KRB5,
};
use krb5_rs::gssapi::spnego::{
    decode_neg_token_init, decode_neg_token_resp, encode_neg_token_init, encode_neg_token_resp,
    is_kerb_mech, NegState, SpnegoAcceptor, SpnegoInitiator, MECH_KRB5_OLD, MECH_KRB5_WRONG,
    MECH_NTLMSSP, MECH_SPNEGO,
};
use krb5_rs::gssapi::token::{make_token_header, parse_token_header};
use krb5_rs::gssapi::GssError;
use krb5_rs::protocol::ap::{encrypt_ticket_part, ApError, KeySource};
use krb5_rs::protocol::{Credential, TicketTimes};
use krb5_rs::types::*;
use krb5_rs::Krb5Error;
use rasn::types::{GeneralString, OctetString};

const REALM: &str = "EXAMPLE.COM";
const HINT_NAME: &[u8] = b"not_defined_in_RFC4178@please_ignore";

fn realm() -> Realm {
    GeneralString::from_bytes(REALM.as_bytes()).expect("realm")
}

fn alice() -> PrincipalName {
    PrincipalName::new_principal("alice")
}

fn service() -> PrincipalName {
    PrincipalName::new_srv_hst("HTTP", "www.example.com")
}

fn now() -> KerberosTime {
    use chrono::Timelike;
    let t = chrono::Utc::now();
    t.with_nanosecond(0).unwrap_or(t).fixed_offset()
}

fn secs(n: i64) -> KerberosTime {
    use chrono::Timelike;
    (chrono::Utc::now() + chrono::Duration::seconds(n))
        .with_nanosecond(0)
        .expect("time")
        .fixed_offset()
}

fn random_key(etype: i32) -> EncryptionKey {
    use std::sync::atomic::{AtomicUsize, Ordering};
    static COUNTER: AtomicUsize = AtomicUsize::new(0);
    let profile = find_etype(etype).expect("etype");
    let tag = COUNTER.fetch_add(1, Ordering::Relaxed) as u8;
    let rnd: Vec<u8> = (0..profile.key_bytes())
        .map(|i| (i as u8).wrapping_mul(41).wrapping_add(tag))
        .collect();
    EncryptionKey::new(etype, profile.random_to_key(&rnd).expect("r2k").to_vec())
}

fn mint(
    service_key: &EncryptionKey,
    session_key: &EncryptionKey,
    sname: PrincipalName,
    flags: TicketFlags,
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
        starttime: None,
        endtime: secs(3600),
        renew_till: None,
        caddr: None,
        authorization_data: None,
    };
    let ticket =
        encrypt_ticket_part(service_key, Some(1), REALM, sname.clone(), &part).expect("mint");
    Credential {
        client: alice(),
        crealm: REALM.to_string(),
        server: sname,
        srealm: REALM.to_string(),
        session_key: session_key.clone(),
        times: TicketTimes {
            authtime: part.authtime,
            starttime: None,
            endtime: part.endtime,
            renew_till: None,
        },
        ticket,
        flags: KerberosFlags::new(flags),
        addresses: None,
        authdata: None,
    }
}

struct OneKey(EncryptionKey);
impl KeySource for OneKey {
    fn get_key(
        &self,
        _server: &PrincipalName,
        _realm: &[u8],
        _kvno: Option<i32>,
        _etype: i32,
    ) -> Result<EncryptionKey, ApError> {
        Ok(self.0.clone())
    }
}

fn svc_cred(service_key: &EncryptionKey, session_etype: i32) -> Credential {
    let session = random_key(session_etype);
    mint(service_key, &session, service(), TicketFlags::empty())
}

fn gss_err(e: Krb5Error) -> GssError {
    match e {
        Krb5Error::Gss(g) => g,
        other => panic!("expected Gss error, got {other:?}"),
    }
}

/// `30 len (06 len oid)*` — the contents of the NegTokenInit [0] field
/// (this is also the exact blob mechListMIC is computed over).
fn mech_types_der(mechs: &[&[u8]]) -> Vec<u8> {
    let inner: Vec<u8> = mechs
        .iter()
        .flat_map(|o| {
            let mut v = vec![0x06, o.len() as u8];
            v.extend_from_slice(o);
            v
        })
        .collect();
    let mut out = vec![0x30, inner.len() as u8];
    out.extend_from_slice(&inner);
    out
}

fn cont(s: InitStep) -> Vec<u8> {
    match s {
        InitStep::Continue(t) => t,
        other => panic!("expected Continue, got {other:?}"),
    }
}

fn init_complete(s: InitStep) -> Option<Vec<u8>> {
    match s {
        InitStep::Complete(t) => t,
        other => panic!("expected Complete, got {other:?}"),
    }
}

fn accept_complete(s: AcceptStep) -> Option<Vec<u8>> {
    match s {
        AcceptStep::Complete { token } => token,
        other => panic!("expected Complete, got {other:?}"),
    }
}

fn accept_continue(s: AcceptStep) -> Vec<u8> {
    match s {
        AcceptStep::ContinueNeeded(t) => t,
        other => panic!("expected ContinueNeeded, got {other:?}"),
    }
}

fn new_initiator(cred: Credential, flags: GssFlags, mechs: Vec<Vec<u8>>) -> SpnegoInitiator {
    SpnegoInitiator::new(
        Krb5Initiator::new(cred, None, flags, None).expect("inner"),
        mechs,
    )
}

fn new_acceptor(skey: &EncryptionKey, mechs: Vec<Vec<u8>>) -> SpnegoAcceptor {
    SpnegoAcceptor::new(
        Krb5Acceptor::new(Box::new(OneKey(skey.clone())), Some(service()), None),
        mechs,
    )
}

/// A raw krb5 AP-REQ token (RFC 2743 framed, tok id 0100) from a plain
/// Krb5Initiator, for hand-crafting NegTokenInit/NegTokenResp bodies.
fn raw_ap_req(skey: &EncryptionKey, flags: GssFlags) -> Vec<u8> {
    let cred = svc_cred(skey, 18);
    let mut init = Krb5Initiator::new(cred, None, flags, None).expect("inner");
    match init.step(None).expect("step") {
        InitStep::Continue(t) | InitStep::Complete(Some(t)) => t,
        _ => panic!("no token"),
    }
}

include!("der.rs");
include!("flow.rs");
include!("edge.rs");
