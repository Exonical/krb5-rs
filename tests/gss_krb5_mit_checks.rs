//! MIT-semantics checks for the RFC 4121 GSS-API krb5 mechanism.
//!
//! Grounded in MIT krb5 1.22.2 (krb5-ref): lib/gssapi/krb5/
//! init_sec_context.c, accept_sec_context.c, k5sealv3.c, k5sealv3iov.c,
//! k5unsealiov.c, util_cksum.c, util_crypt.c, wrap_size_limit.c,
//! generic/util_seqstate.c, generic/util_token.c.

use krb5_rs::crypto::find_etype;
use krb5_rs::gssapi::krb5::{
    AcceptStep, ChannelBindings, GssFlags, InitStep, Krb5Acceptor, Krb5Initiator, MECH_KRB5,
};
use krb5_rs::gssapi::seqstate::{SeqState, SeqStatus};
use krb5_rs::gssapi::token::{make_token_header, parse_token_header};
use krb5_rs::gssapi::GssError;
use krb5_rs::protocol::ap::{encrypt_ticket_part, ApError, ApReqOptions, AuthContext, KeySource};
use krb5_rs::protocol::{Credential, TicketTimes};
use krb5_rs::types::*;
use krb5_rs::Krb5Error;
use rasn::types::{GeneralString, OctetString};

const REALM: &str = "EXAMPLE.COM";

fn realm() -> Realm {
    GeneralString::from_bytes(REALM.as_bytes()).expect("realm")
}

fn alice() -> PrincipalName {
    PrincipalName::new_principal("alice")
}

fn service() -> PrincipalName {
    PrincipalName::new_srv_hst("HTTP", "www.example.com")
}

fn krbtgt() -> PrincipalName {
    PrincipalName::new_srv_inst("krbtgt", REALM)
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
        .map(|i| (i as u8).wrapping_mul(31).wrapping_add(tag))
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

/// Service ticket for alice → HTTP/www.example.com.
fn svc_cred(service_key: &EncryptionKey, session_etype: i32) -> (Credential, EncryptionKey) {
    let session = random_key(session_etype);
    (
        mint(service_key, &session, service(), TicketFlags::empty()),
        session,
    )
}

fn tgt_cred(ticket_flags: TicketFlags) -> Credential {
    mint(&random_key(18), &random_key(18), krbtgt(), ticket_flags)
}

/// Decode the AP-REQ out of a context token and return (ap_req, decrypted
/// authenticator) using `session`.
fn decode_auth(token: &[u8], session: &EncryptionKey) -> (ApReq, Authenticator) {
    let (mech, body) = parse_token_header(token).expect("token header");
    assert_eq!(mech, MECH_KRB5);
    assert_eq!(&body[..2], &[0x01, 0x00]);
    let ap_req: ApReq = rasn::der::decode(&body[2..]).expect("AP-REQ");
    let plain = find_etype(session.keytype)
        .expect("etype")
        .decrypt(session.key_bytes(), 11, &ap_req.authenticator.cipher)
        .expect("decrypt authenticator");
    let auth: Authenticator = rasn::der::decode(&plain).expect("auth");
    (ap_req, auth)
}

fn unwrap_step(s: InitStep) -> Option<Vec<u8>> {
    match s {
        InitStep::Complete(t) => t,
        InitStep::Continue(t) => Some(t),
    }
}

fn init_complete(s: InitStep) -> Option<Vec<u8>> {
    match s {
        InitStep::Complete(t) => t,
        _ => panic!("expected Complete"),
    }
}

fn accept_complete(s: AcceptStep) -> Option<Vec<u8>> {
    match s {
        AcceptStep::Complete { token } => token,
        _ => panic!("expected Complete"),
    }
}

fn gss_err(e: Krb5Error) -> GssError {
    match e {
        Krb5Error::Gss(g) => g,
        other => panic!("expected Gss error, got {other:?}"),
    }
}

fn cb(appdata: &[u8]) -> ChannelBindings {
    ChannelBindings {
        initiator_addrtype: 0,
        initiator_address: Vec::new(),
        acceptor_addrtype: 0,
        acceptor_address: Vec::new(),
        application_data: appdata.to_vec(),
    }
}

// --- context token -------------------------------------------------------------

#[test]
fn init_token_framing_and_ap_req() {
    let skey = random_key(18);
    let (cred, session) = svc_cred(&skey, 18);
    let mut init =
        Krb5Initiator::new(cred, None, GssFlags::REPLAY | GssFlags::SEQUENCE, None).expect("new");
    let token = init_complete(init.step(None).expect("step")).expect("token");

    let (ap_req, auth) = decode_auth(&token, &session);
    let cksum = auth.cksum.expect("cksum");
    assert_eq!(cksum.cksumtype, 0x8003);
    let b = cksum.checksum.as_ref();
    assert_eq!(&b[0..4], &16u32.to_le_bytes());
    assert!(b[4..20].iter().all(|&x| x == 0));
    let flags = u32::from_le_bytes(b[20..24].try_into().expect("flags"));
    assert_eq!(
        flags,
        GssFlags::TRANS.bits()
            | GssFlags::CONF.bits()
            | GssFlags::INTEG.bits()
            | GssFlags::REPLAY.bits()
            | GssFlags::SEQUENCE.bits()
    );
    assert!(auth.subkey.is_some());
    assert!(auth.seq_number.expect("seq") != 0);
    assert!(auth.authorization_data.is_none());
    assert!(ap_req.ap_options.contains(ApOptions::empty()));
    drop(ap_req);
}

#[test]
fn init_mutual_sets_ap_options_and_etype_negotiation() {
    let skey = random_key(18);
    // Session etype 17 so the RFC 4537 list is non-trivial: desired
    // [18,17,20,19] truncated right after tkt etype 17 → [18,17]
    // (mk_req_ext.c:345-354).
    let (cred, session) = svc_cred(&skey, 17);
    let mut init = Krb5Initiator::new(cred, None, GssFlags::MUTUAL, None).expect("new");
    let token = match init.step(None).expect("step") {
        InitStep::Continue(t) => t,
        _ => panic!("expected Continue"),
    };
    let (ap_req, auth) = decode_auth(&token, &session);
    assert!(ap_req.ap_options.contains(ApOptions::MUTUAL_REQUIRED));
    let ad = auth.authorization_data.expect("authz");
    assert_eq!(ad.len(), 1);
    assert_eq!(ad[0].ad_type, 1);
    let inner: Vec<AuthorizationDataElement> = rasn::der::decode(&ad[0].ad_data).expect("inner");
    let neg = inner.iter().find(|e| e.ad_type == 129).expect("etype list");
    let etypes: Vec<i32> = rasn::der::decode(&neg.ad_data).expect("etypes");
    assert_eq!(etypes, vec![18, 17]);
}

#[test]
fn channel_bindings_md5() {
    use md5::Digest;
    let skey = random_key(18);
    let (cred, session) = svc_cred(&skey, 18);
    let bindings = cb(b"tls-unique:abc");
    let mut init = Krb5Initiator::new(cred, None, GssFlags::empty(), Some(bindings)).expect("new");
    let token = init_complete(init.step(None).expect("step")).expect("token");
    let (_ap_req, auth) = decode_auth(&token, &session);
    let cksum = auth.cksum.expect("cksum");

    let mut input = Vec::new();
    input.extend_from_slice(&0u32.to_le_bytes()); // initiator_addrtype
    input.extend_from_slice(&0u32.to_le_bytes()); // initiator_address len
    input.extend_from_slice(&0u32.to_le_bytes()); // acceptor_addrtype
    input.extend_from_slice(&0u32.to_le_bytes()); // acceptor_address len
    input.extend_from_slice(&14u32.to_le_bytes()); // appdata len
    input.extend_from_slice(b"tls-unique:abc");
    let expect = md5::Md5::digest(&input);
    assert_eq!(&cksum.checksum[4..20], expect.as_slice());
}

#[test]
fn deleg_flag_embeds_krb_cred_encrypted_with_session_key() {
    let skey = random_key(18);
    let (cred, session) = svc_cred(&skey, 18);
    let tgt = tgt_cred(TicketFlags::FORWARDABLE);
    let mut init = Krb5Initiator::new(cred.clone(), Some(tgt), GssFlags::DELEG, None).expect("new");
    let token = init_complete(init.step(None).expect("step")).expect("token");
    let (_ap_req, auth) = decode_auth(&token, &session);
    let cksum = auth.cksum.expect("cksum");
    let b = cksum.checksum.as_ref();
    let flags = u32::from_le_bytes(b[20..24].try_into().expect("flags"));
    assert!(flags & GssFlags::DELEG.bits() != 0);
    assert_eq!(u16::from_le_bytes(b[24..26].try_into().unwrap()), 1);
    let credlen = u16::from_le_bytes(b[26..28].try_into().unwrap()) as usize;
    let kc: KrbCred = rasn::der::decode(&b[28..28 + credlen]).expect("KRB-CRED");
    // RFC 4121 §4.1.1: encrypted in the session key, usage 14.
    let plain = find_etype(session.keytype)
        .expect("etype")
        .decrypt(session.key_bytes(), 14, &kc.enc_part.cipher)
        .expect("cred decrypt with session key");
    let part: EncKrbCredPart = rasn::der::decode(&plain).expect("EncKrbCredPart");
    assert_eq!(part.ticket_info[0].pname, Some(alice()));
    assert_eq!(part.ticket_info[0].sname, Some(krbtgt()));

    // Without a TGT, DELEG produces no option bytes.
    let mut init2 = Krb5Initiator::new(cred, None, GssFlags::DELEG, None).expect("new");
    let token2 = init_complete(init2.step(None).expect("step")).expect("token");
    let (_a, auth2) = decode_auth(&token2, &session);
    let b2 = auth2.cksum.expect("cksum").checksum;
    let flags2 = u32::from_le_bytes(b2[20..24].try_into().expect("flags"));
    assert_eq!(flags2 & GssFlags::DELEG.bits(), 0);
    assert_eq!(b2.len(), 24);
}

#[test]
fn deleg_policy_requires_ok_as_delegate() {
    let skey = random_key(18);
    let (cred, session) = svc_cred(&skey, 18);
    let tgt = tgt_cred(TicketFlags::FORWARDABLE);
    let mut init =
        Krb5Initiator::new(cred.clone(), Some(tgt), GssFlags::DELEG_POLICY, None).expect("new");
    let token = init_complete(init.step(None).expect("step")).expect("token");
    let (_a, auth) = decode_auth(&token, &session);
    let b = auth.cksum.expect("cksum").checksum;
    let flags = u32::from_le_bytes(b[20..24].try_into().expect("flags"));
    assert_eq!(flags & (GssFlags::DELEG | GssFlags::DELEG_POLICY).bits(), 0);

    // With OK_AS_DELEGATE on the service ticket, both bits appear.
    let cred2 = mint(&skey, &session, service(), TicketFlags::OK_AS_DELEGATE);
    let mut init2 = Krb5Initiator::new(
        cred2,
        Some(tgt_cred(TicketFlags::FORWARDABLE)),
        GssFlags::DELEG_POLICY,
        None,
    )
    .expect("new");
    let token2 = init_complete(init2.step(None).expect("step")).expect("token");
    let (_a, auth2) = decode_auth(&token2, &session);
    let b2 = auth2.cksum.expect("cksum").checksum;
    let flags2 = u32::from_le_bytes(b2[20..24].try_into().expect("flags"));
    assert_eq!(
        flags2 & (GssFlags::DELEG | GssFlags::DELEG_POLICY).bits(),
        (GssFlags::DELEG | GssFlags::DELEG_POLICY).bits()
    );
}

#[test]
fn accept_roundtrip_non_mutual() {
    let skey = random_key(18);
    let (cred, _session) = svc_cred(&skey, 18);
    let mut init =
        Krb5Initiator::new(cred, None, GssFlags::REPLAY | GssFlags::SEQUENCE, None).expect("new");
    let token = init_complete(init.step(None).expect("step")).expect("token");

    let mut acc = Krb5Acceptor::new(Box::new(OneKey(skey)), Some(service()), None);
    let out = accept_complete(acc.step(&token).expect("accept"));
    assert!(out.is_none());
    let ctx = acc.context().expect("context");
    assert_eq!(
        ctx.flags(),
        GssFlags::TRANS | GssFlags::CONF | GssFlags::INTEG | GssFlags::REPLAY | GssFlags::SEQUENCE
    );
    assert_eq!(ctx.initiator(), &alice());
    assert_eq!(ctx.initiator_realm(), REALM);
    assert!(!ctx.is_initiator());
}

#[test]
fn accept_roundtrip_mutual_with_acceptor_subkey() {
    let skey = random_key(18);
    let (cred, session) = svc_cred(&skey, 18);
    let mut init = Krb5Initiator::new(cred, None, GssFlags::MUTUAL, None).expect("new");
    let token = match init.step(None).expect("step") {
        InitStep::Continue(t) => t,
        _ => panic!("expected Continue"),
    };

    let mut acc = Krb5Acceptor::new(Box::new(OneKey(skey)), Some(service()), None);
    let rep = accept_complete(acc.step(&token).expect("accept")).expect("ap-rep token");
    let (mech, body) = parse_token_header(&rep).expect("header");
    assert_eq!(mech, MECH_KRB5);
    assert_eq!(&body[..2], &[0x02, 0x00]);

    // AP-REP carries an acceptor subkey (proto==1 → always generated).
    let ap_rep: ApRep = rasn::der::decode(&body[2..]).expect("AP-REP");
    let plain = find_etype(session.keytype)
        .expect("etype")
        .decrypt(session.key_bytes(), 12, &ap_rep.enc_part.cipher)
        .expect("decrypt");
    let enc: EncApRepPart = rasn::der::decode(&plain).expect("enc");
    assert!(enc.subkey.is_some());

    assert!(init_complete(init.step(Some(&rep)).expect("step2")).is_none());
    let mut ic = init.context().expect("init ctx");
    let mut ac = acc.context().expect("acc ctx");

    // Wrap each way and unwrap.
    let t = ic.wrap(true, b"hello").expect("wrap");
    assert!(t[2] & 0x04 != 0, "acceptor subkey flag on initiator wrap");
    let r = ac.unwrap(&t).expect("unwrap");
    assert_eq!(r.data, b"hello");
    assert!(r.conf);
    let t2 = ac.wrap(true, b"world").expect("wrap");
    assert!(t2[2] & 0x04 != 0, "acceptor subkey flag on acceptor wrap");
    assert!(t2[2] & 0x01 != 0, "sender-is-acceptor flag");
    let r2 = ic.unwrap(&t2).expect("unwrap");
    assert_eq!(r2.data, b"world");
    assert!(r2.conf);
}

#[test]
fn accept_rejects_wrong_mech_and_tokid() {
    let skey = random_key(18);
    let (cred, _s) = svc_cred(&skey, 18);
    let mut init = Krb5Initiator::new(cred, None, GssFlags::empty(), None).expect("new");
    let token = init_complete(init.step(None).expect("step")).expect("token");

    // SPNEGO OID 1.3.6.1.5.5.2 header around the same body.
    let spnego_oid = [0x2b, 0x06, 0x01, 0x05, 0x05, 0x02];
    let (_mech, body) = parse_token_header(&token).expect("header");
    let bad = make_token_header(&spnego_oid, body.len() - 2, Some(0x0100));
    let mut bad_tok = bad;
    bad_tok.extend_from_slice(&body[2..]);
    let mut acc = Krb5Acceptor::new(Box::new(OneKey(skey.clone())), Some(service()), None);
    assert_eq!(
        gss_err(acc.step(&bad_tok).unwrap_err()),
        GssError::DefectiveToken
    );

    // Wrong tok id as first token.
    let mut wrong = make_token_header(MECH_KRB5, body.len() - 2, Some(0x0200));
    wrong.extend_from_slice(&body[2..]);
    let mut acc = Krb5Acceptor::new(Box::new(OneKey(skey.clone())), Some(service()), None);
    assert_eq!(
        gss_err(acc.step(&wrong).unwrap_err()),
        GssError::DefectiveToken
    );

    // Raw AP-REQ without framing (DCE) — unsupported → DefectiveToken.
    let mut acc = Krb5Acceptor::new(Box::new(OneKey(skey)), Some(service()), None);
    assert_eq!(
        gss_err(acc.step(&body[2..]).unwrap_err()),
        GssError::DefectiveToken
    );
}

#[test]
fn accept_channel_bindings_rules() {
    let skey = random_key(18);
    let (cred, session) = svc_cred(&skey, 18);

    // (a) initiator no cb, acceptor cb → ok, no CHANNEL_BOUND flag.
    let mut init = Krb5Initiator::new(cred.clone(), None, GssFlags::empty(), None).expect("new");
    let token = init_complete(init.step(None).expect("step")).expect("token");
    let mut acc = Krb5Acceptor::new(
        Box::new(OneKey(skey.clone())),
        Some(service()),
        Some(cb(b"x")),
    );
    acc.step(&token).expect("accept");
    let ctx = acc.context().expect("ctx");
    assert!(!ctx.flags().contains(GssFlags::CHANNEL_BOUND));

    // (b) both same cb → CHANNEL_BOUND.
    let mut init =
        Krb5Initiator::new(cred.clone(), None, GssFlags::empty(), Some(cb(b"same"))).expect("new");
    let token = init_complete(init.step(None).expect("step")).expect("token");
    let mut acc = Krb5Acceptor::new(
        Box::new(OneKey(skey.clone())),
        Some(service()),
        Some(cb(b"same")),
    );
    acc.step(&token).expect("accept");
    assert!(acc
        .context()
        .expect("ctx")
        .flags()
        .contains(GssFlags::CHANNEL_BOUND));

    // (c) different cb → BadBindings.
    let mut init =
        Krb5Initiator::new(cred.clone(), None, GssFlags::empty(), Some(cb(b"same"))).expect("new");
    let token = init_complete(init.step(None).expect("step")).expect("token");
    let mut acc = Krb5Acceptor::new(
        Box::new(OneKey(skey.clone())),
        Some(service()),
        Some(cb(b"diff")),
    );
    assert_eq!(
        gss_err(acc.step(&token).unwrap_err()),
        GssError::BadBindings
    );

    // (d) CHANNEL_BOUND requested + cb vs different acceptor cb → BadBindings;
    // the AP_OPTIONS authdata (LE 0x4000) is present in the authenticator.
    let mut init = Krb5Initiator::new(
        cred.clone(),
        None,
        GssFlags::CHANNEL_BOUND,
        Some(cb(b"same")),
    )
    .expect("new");
    let token = init_complete(init.step(None).expect("step")).expect("token");
    let (_a, auth) = decode_auth(&token, &session);
    let ad = auth.authorization_data.expect("AP_OPTIONS authdata");
    let inner: Vec<AuthorizationDataElement> = rasn::der::decode(&ad[0].ad_data).expect("inner");
    let apo = inner.iter().find(|e| e.ad_type == 143).expect("AP_OPTIONS");
    assert_eq!(apo.ad_data.as_ref(), &0x4000u32.to_le_bytes());
    let mut acc = Krb5Acceptor::new(
        Box::new(OneKey(skey.clone())),
        Some(service()),
        Some(cb(b"diff")),
    );
    assert_eq!(
        gss_err(acc.step(&token).unwrap_err()),
        GssError::BadBindings
    );

    // (e) CHANNEL_BOUND + cb vs acceptor without cb → Complete.
    let mut acc = Krb5Acceptor::new(Box::new(OneKey(skey)), Some(service()), None);
    acc.step(&token).expect("accept ok");
}

#[test]
fn accept_deleg_stores_creds() {
    let skey = random_key(18);
    let (cred, _session) = svc_cred(&skey, 18);
    let tgt = tgt_cred(TicketFlags::FORWARDABLE);
    let mut init = Krb5Initiator::new(cred, Some(tgt), GssFlags::DELEG, None).expect("new");
    let token = init_complete(init.step(None).expect("step")).expect("token");

    let mut acc = Krb5Acceptor::new(Box::new(OneKey(skey)), Some(service()), None);
    acc.step(&token).expect("accept");
    let creds = acc.delegated_creds().expect("delegated creds");
    assert_eq!(creds.len(), 1);
    assert_eq!(creds[0].client, alice());
    assert_eq!(creds[0].server, krbtgt());
    assert!(acc
        .context()
        .expect("ctx")
        .flags()
        .contains(GssFlags::DELEG));
}

#[test]
fn accept_non_8003_checksum_paths() {
    let skey = random_key(18);
    let session = random_key(18);
    let cred = mint(&skey, &session, service(), TicketFlags::empty());

    // No checksum at all → flags 0 → context flags = TRANS only.
    let mut ac = AuthContext::new();
    let req = ac
        .mk_req(&ApReqOptions::default(), None, &cred)
        .expect("mk_req");
    let mut tok = make_token_header(MECH_KRB5, req.len(), Some(0x0100));
    tok.extend_from_slice(&req);
    let mut acc = Krb5Acceptor::new(Box::new(OneKey(skey.clone())), Some(service()), None);
    acc.step(&tok).expect("accept");
    assert_eq!(acc.context().expect("ctx").flags(), GssFlags::TRANS);

    // Keyed checksum over empty data → REPLAY|SEQUENCE.
    let mut ac = AuthContext::new();
    let req = ac
        .mk_req(&ApReqOptions::default(), Some(b""), &cred)
        .expect("mk_req");
    let mut tok = make_token_header(MECH_KRB5, req.len(), Some(0x0100));
    tok.extend_from_slice(&req);
    let mut acc = Krb5Acceptor::new(Box::new(OneKey(skey.clone())), Some(service()), None);
    acc.step(&tok).expect("accept");
    assert_eq!(
        acc.context().expect("ctx").flags(),
        GssFlags::TRANS | GssFlags::REPLAY | GssFlags::SEQUENCE
    );

    // Keyed checksum over non-empty data → BadSig (acceptor verifies over
    // the empty buffer, accept_sec_context.c:494-516).
    let mut ac = AuthContext::new();
    let req = ac
        .mk_req(&ApReqOptions::default(), Some(b"x"), &cred)
        .expect("mk_req");
    let mut tok = make_token_header(MECH_KRB5, req.len(), Some(0x0100));
    tok.extend_from_slice(&req);
    let mut acc = Krb5Acceptor::new(Box::new(OneKey(skey)), Some(service()), None);
    assert_eq!(gss_err(acc.step(&tok).unwrap_err()), GssError::BadSig);
}

// --- per-message tokens --------------------------------------------------------

fn established_pair(
    mutual: bool,
    req_flags: GssFlags,
) -> (
    krb5_rs::gssapi::krb5::Krb5Context,
    krb5_rs::gssapi::krb5::Krb5Context,
) {
    let skey = random_key(18);
    let (cred, _session) = svc_cred(&skey, 18);
    let flags = if mutual {
        req_flags | GssFlags::MUTUAL
    } else {
        req_flags
    };
    let mut init = Krb5Initiator::new(cred, None, flags, None).expect("new");
    let token = unwrap_step(init.step(None).expect("step")).expect("token");
    let mut acc = Krb5Acceptor::new(Box::new(OneKey(skey)), Some(service()), None);
    let rep = accept_complete(acc.step(&token).expect("accept"));
    if mutual {
        init_complete(init.step(Some(&rep.expect("rep"))).expect("step2"));
    }
    (init.context().expect("ic"), acc.context().expect("ac"))
}

#[test]
fn wrap_conf_token_layout_and_seq() {
    let (mut ic, mut ac) = established_pair(false, GssFlags::REPLAY | GssFlags::SEQUENCE);
    let t1 = ic.wrap(true, b"hello").expect("wrap");
    assert_eq!(&t1[0..2], &[0x05, 0x04]);
    assert_eq!(t1[2], 0x02); // initiator, conf, no acceptor subkey
    assert_eq!(t1[3], 0xff);
    assert_eq!(&t1[4..6], &[0, 0]); // EC = 0
    assert_eq!(&t1[6..8], &[0, 0]); // RRC = 0
    let seq1 = u64::from_be_bytes(t1[8..16].try_into().unwrap());
    let t2 = ic.wrap(true, b"two").expect("wrap2");
    let seq2 = u64::from_be_bytes(t2[8..16].try_into().unwrap());
    assert_eq!(seq2, seq1 + 1);

    let r = ac.unwrap(&t1).expect("unwrap");
    assert_eq!(r.data, b"hello");
    assert!(r.conf);

    let t3 = ac.wrap(true, b"back").expect("wrap3");
    assert!(t3[2] & 0x01 != 0);
    let r3 = ic.unwrap(&t3).expect("unwrap3");
    assert_eq!(r3.data, b"back");
}

#[test]
fn wrap_integ_only_layout() {
    let (mut ic, mut ac) = established_pair(false, GssFlags::REPLAY | GssFlags::SEQUENCE);
    let t = ic.wrap(false, b"hello").expect("wrap");
    assert_eq!(&t[0..2], &[0x05, 0x04]);
    assert_eq!(t[2] & 0x02, 0);
    let ec = u16::from_be_bytes(t[4..6].try_into().unwrap());
    assert_eq!(ec, 12); // hmac-sha1-96
    assert_eq!(t.len(), 16 + 5 + 12);
    assert_eq!(&t[16..21], b"hello");
    let r = ac.unwrap(&t).expect("unwrap");
    assert_eq!(r.data, b"hello");
    assert!(!r.conf);

    let mut bad = t.clone();
    bad[18] ^= 0xff;
    // checksum fails before seq check — re-check on the same acceptor.
    drop({
        let (i2, a2) = established_pair(false, GssFlags::REPLAY | GssFlags::SEQUENCE);
        drop(i2);
        a2
    });
    assert_eq!(gss_err(ac.unwrap(&bad).unwrap_err()), GssError::BadSig);
}

#[test]
fn mic_layout_and_verify() {
    let (mut ic, mut ac) = established_pair(false, GssFlags::REPLAY | GssFlags::SEQUENCE);
    let mic = ic.get_mic(b"m").expect("mic");
    assert_eq!(&mic[0..2], &[0x04, 0x04]);
    assert_eq!(mic[2], 0);
    assert_eq!(mic[3], 0xff);
    assert_eq!(&mic[4..8], &[0xff; 4]);
    ac.verify_mic(b"m", &mic).expect("verify");
    assert_eq!(
        gss_err(ac.verify_mic(b"n", &mic).unwrap_err()),
        GssError::BadSig
    );
    let mut bad = mic.clone();
    bad[0] = 0x05;
    // wrong tok id for MIC → DefectiveToken
    let (ic2, mut ac2) = established_pair(false, GssFlags::REPLAY | GssFlags::SEQUENCE);
    drop(ic2);
    assert_eq!(
        gss_err(ac2.verify_mic(b"m", &bad).unwrap_err()),
        GssError::DefectiveToken
    );
    drop(mic);
}

#[test]
fn unwrap_direction_and_defects() {
    let (mut ic, _ac) = established_pair(false, GssFlags::REPLAY | GssFlags::SEQUENCE);
    let t = ic.wrap(true, b"hello").expect("wrap");
    // Same-role token fed back to the sender: SENDER_IS_ACCEPTOR must equal
    // !our_role (k5sealv3iov.c:314-318) → BadSig.
    assert_eq!(gss_err(ic.unwrap(&t).unwrap_err()), GssError::BadSig);

    let (mut ic, mut ac) = established_pair(false, GssFlags::REPLAY | GssFlags::SEQUENCE);
    let t = ic.wrap(true, b"hello").expect("wrap");
    assert_eq!(
        gss_err(ac.unwrap(&t[..10]).unwrap_err()),
        GssError::DefectiveToken
    );
    let mut bad = t.clone();
    bad[3] = 0x00;
    assert_eq!(
        gss_err(ac.unwrap(&bad).unwrap_err()),
        GssError::DefectiveToken
    );
    // EC field corruption: header is cleartext so decryption/HMAC still
    // passes but the embedded header copy's EC no longer matches
    // (k5sealv3iov.c:402-409) → DefectiveToken; a decrypt failure would give
    // BadSig — either must be an error, assert is_err.
    let mut bad = t.clone();
    bad[5] ^= 0xff;
    assert!(ac.unwrap(&bad).is_err());
}

#[test]
fn rrc_rotation_accepted() {
    let (mut ic, mut ac) = established_pair(false, GssFlags::REPLAY | GssFlags::SEQUENCE);
    let t = ic.wrap(true, b"hello world").expect("wrap");
    // Rotate body right by 7 and set RRC=7; unwrap rotates left by rrc
    // (k5unsealiov.c:471-478 semantics).
    let mut bad = t.clone();
    let body = &mut bad[16..];
    body.rotate_right(7);
    bad[6..8].copy_from_slice(&7u16.to_be_bytes());
    let r = ac.unwrap(&bad).expect("unwrap rotated");
    assert_eq!(r.data, b"hello world");
    assert!(r.conf);
}

#[test]
fn seqstate_matches_util_seqstate() {
    // MIT reports these as supplementary statuses, not errors.
    let mut s = SeqState::new(100, true, true, true);
    assert_eq!(s.check(100), SeqStatus::Complete);
    assert_eq!(s.check(101), SeqStatus::Complete);
    assert_eq!(s.check(103), SeqStatus::Gap);
    assert_eq!(s.check(102), SeqStatus::Unseq);
    assert_eq!(s.check(102), SeqStatus::Duplicate);
    assert_eq!(s.check(100), SeqStatus::Duplicate);

    // Replay-only (no sequence): out-of-order within window is fine.
    let mut s = SeqState::new(5, true, false, true);
    assert_eq!(s.check(5), SeqStatus::Complete);
    assert_eq!(s.check(7), SeqStatus::Complete); // gap allowed without SEQUENCE
    assert_eq!(s.check(6), SeqStatus::Complete);
    assert_eq!(s.check(6), SeqStatus::Duplicate);
    assert_eq!(s.check(100), SeqStatus::Complete); // next = 96 (rel)
                                                   // rel_seqnum 25 is 71 behind next=96 → offset > 64 → Old
                                                   // (util_seqstate.c:105-108).
    assert_eq!(s.check(30), SeqStatus::Old);

    // 32-bit mask wrap-around.
    let mut s = SeqState::new(u32::MAX as u64, true, true, false);
    assert_eq!(s.check(u32::MAX as u64), SeqStatus::Complete);
    assert_eq!(s.check(0), SeqStatus::Complete);
}

#[test]
fn replay_and_sequence_flags_on_context() {
    let (mut ic, mut ac) = established_pair(false, GssFlags::REPLAY | GssFlags::SEQUENCE);
    let t1 = ic.wrap(true, b"m1").expect("w1");
    let _t2 = ic.wrap(true, b"m2").expect("w2");
    let t3 = ic.wrap(true, b"m3").expect("w3");
    ac.unwrap(&t1).expect("u1");
    // Supplementary statuses: the message is still returned (MIT semantics).
    assert_eq!(ac.unwrap(&t1).expect("dup").seq, SeqStatus::Duplicate);
    assert_eq!(ac.unwrap(&t3).expect("gap").seq, SeqStatus::Gap);

    let (mut ic, mut ac) = established_pair(false, GssFlags::empty());
    let t1 = ic.wrap(true, b"m1").expect("w1");
    ac.unwrap(&t1).expect("u1");
    let r = ac.unwrap(&t1).expect("dup ok without REPLAY/SEQUENCE");
    assert_eq!(r.seq, SeqStatus::Complete);
}

#[test]
fn wrap_size_limit_matches_mit() {
    // wrap_size_limit.c:98-150 CFX branch: conf → largest sz with
    // encrypt_size(sz)+16 <= output, minus 16 for the encrypted header copy;
    // aes256-sha1 encrypt_size(n) = n + 16 (confounder) + 12 (hmac trailer).
    // limit(1000) = 956 - 16 = 940.
    let (mut ic, _ac) = established_pair(false, GssFlags::empty());
    assert_eq!(ic.wrap_size_limit(true, 1000), 940);
    let t = ic.wrap(true, &vec![0u8; 940]).expect("wrap max");
    assert!(t.len() <= 1000);
    assert_eq!(t.len(), 1000);
    let t2 = ic.wrap(true, &vec![0u8; 941]).expect("wrap");
    assert!(t2.len() > 1000);
    // integrity-only: output - 16 - cksumlen.
    assert_eq!(ic.wrap_size_limit(false, 1000), 972);
}
