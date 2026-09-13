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

// --- 1. constants and OID classification ---------------------------------------

#[test]
fn oid_constants_and_is_kerb_mech() {
    assert_eq!(MECH_SPNEGO, &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x02]);
    assert_eq!(MECH_KRB5_OLD, &[0x2b, 0x05, 0x01, 0x05, 0x02]);
    assert_eq!(
        MECH_KRB5_WRONG,
        &[0x2a, 0x86, 0x48, 0x82, 0xf7, 0x12, 0x01, 0x02, 0x02]
    );
    assert_eq!(
        MECH_NTLMSSP,
        &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a]
    );
    assert_eq!(
        MECH_KRB5,
        &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02]
    );
    // is_kerb_mech == membership in gss_mech_set_krb5_both
    // (gssapi_krb5.c:178-188 — {krb5, krb5_old, krb5_wrong}).
    assert!(is_kerb_mech(MECH_KRB5));
    assert!(is_kerb_mech(MECH_KRB5_OLD));
    assert!(is_kerb_mech(MECH_KRB5_WRONG));
    assert!(!is_kerb_mech(MECH_NTLMSSP));
    assert!(!is_kerb_mech(MECH_SPNEGO));
}

// --- 2. exact codec vectors ------------------------------------------------------

#[test]
fn codec_neg_token_init_layout() {
    let der = mech_types_der(&[MECH_KRB5, MECH_KRB5_WRONG]);
    let tok = encode_neg_token_init(&der, Some(b"T"), None, false);
    let expected: &[u8] = &[
        0x60, 0x2b, 0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02, // framing
        0xa0, 0x21, 0x30, 0x1f, // [0] SEQUENCE
        0xa0, 0x18, // [0] mechTypes
        0x30, 0x16, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02, 0x06, 0x09,
        0x2a, 0x86, 0x48, 0x82, 0xf7, 0x12, 0x01, 0x02, 0x02, // SEQUENCE OF OIDs
        0xa2, 0x03, 0x04, 0x01, 0x54, // [2] OCTET STRING "T"
    ];
    assert_eq!(tok, expected);

    // Roundtrip: decoded fields and the exact DER mechTypes blob (for MIC).
    let (init, der_back) = decode_neg_token_init(&tok).expect("decode");
    assert_eq!(
        init.mech_types,
        vec![MECH_KRB5.to_vec(), MECH_KRB5_WRONG.to_vec()]
    );
    assert_eq!(init.mech_token.as_deref(), Some(b"T".as_ref()));
    assert!(init.mech_list_mic.is_none());
    assert!(init.req_flags.is_none());
    assert_eq!(der_back, der);

    // With [3] MIC present.
    let tok2 = encode_neg_token_init(&der, None, Some(b"M"), false);
    let (init2, _) = decode_neg_token_init(&tok2).expect("decode");
    assert_eq!(init2.mech_list_mic.as_deref(), Some(b"M".as_ref()));
    assert!(init2.mech_token.is_none());
}

#[test]
fn codec_neg_token_init_req_flags_and_errors() {
    let der = mech_types_der(&[MECH_KRB5]);

    // reqFlags [1] contents must be exactly 03 02 01 <byte> (BIT_STRING,
    // BIT_STRING_LENGTH=2, BIT_STRING_PADDING=1, spnego_mech.c:3393-3401);
    // flags = byte >> 1.
    let mut t = vec![0x60, 0x00];
    let mut inner = vec![0xa0, 0x00, 0x30, 0x00];
    let mut fields = Vec::new();
    fields.extend_from_slice(&[0xa0, der.len() as u8]);
    fields.extend_from_slice(&der);
    fields.extend_from_slice(&[0xa1, 0x04, 0x03, 0x02, 0x01, 0x40]);
    inner[3] = fields.len() as u8;
    inner.extend_from_slice(&fields);
    inner[1] = inner.len() as u8 - 2;
    let framed_len = 8 + inner.len();
    t[1] = framed_len as u8;
    t.extend_from_slice(&[0x06, 0x06]);
    t.extend_from_slice(MECH_SPNEGO);
    t.extend_from_slice(&inner);
    let (init, _) = decode_neg_token_init(&t).expect("decode with reqFlags");
    assert_eq!(init.req_flags, Some(0x40 >> 1));

    // Length-3 reqFlags field contents → DefectiveToken.
    let bad3 = {
        let mut f = Vec::new();
        f.extend_from_slice(&[0xa0, der.len() as u8]);
        f.extend_from_slice(&der);
        f.extend_from_slice(&[0xa1, 0x03, 0x03, 0x02, 0x01]);
        let mut i = vec![0xa0, (f.len() + 2) as u8, 0x30, f.len() as u8];
        i.extend_from_slice(&f);
        let mut o = vec![0x60, (8 + i.len()) as u8, 0x06, 0x06];
        o.extend_from_slice(MECH_SPNEGO);
        o.extend_from_slice(&i);
        o
    };
    assert_eq!(
        decode_neg_token_init(&bad3).unwrap_err(),
        GssError::DefectiveToken
    );

    // Wrong padding byte (0x07 is not BIT_STRING_PADDING=0x01) → Defective.
    let badpad = {
        let mut f = Vec::new();
        f.extend_from_slice(&[0xa0, der.len() as u8]);
        f.extend_from_slice(&der);
        f.extend_from_slice(&[0xa1, 0x04, 0x03, 0x02, 0x07, 0x40]);
        let mut i = vec![0xa0, (f.len() + 2) as u8, 0x30, f.len() as u8];
        i.extend_from_slice(&f);
        let mut o = vec![0x60, (8 + i.len()) as u8, 0x06, 0x06];
        o.extend_from_slice(MECH_SPNEGO);
        o.extend_from_slice(&i);
        o
    };
    assert_eq!(
        decode_neg_token_init(&badpad).unwrap_err(),
        GssError::DefectiveToken
    );

    // Empty mechTypes field → DefectiveToken (get_negTokenInit:3434-3436).
    let empty_mt = {
        let f = vec![0xa0, 0x00];
        let mut i = vec![0xa0, (f.len() + 2) as u8, 0x30, f.len() as u8];
        i.extend_from_slice(&f);
        let mut o = vec![0x60, (8 + i.len()) as u8, 0x06, 0x06];
        o.extend_from_slice(MECH_SPNEGO);
        o.extend_from_slice(&i);
        o
    };
    assert_eq!(
        decode_neg_token_init(&empty_mt).unwrap_err(),
        GssError::DefectiveToken
    );

    // Wrong framing OID → DefectiveToken (verify_token_header:3790-3802).
    let wrong_oid = {
        let mut o = vec![0x60, (8 + 4) as u8, 0x06, 0x06];
        o.extend_from_slice(MECH_KRB5);
        o.extend_from_slice(&[0xa0, 0x02, 0x30, 0x00]);
        o
    };
    assert_eq!(
        decode_neg_token_init(&wrong_oid).unwrap_err(),
        GssError::DefectiveToken
    );

    // Missing [0] choice tag → DefectiveToken.
    let no_choice = {
        let mut o = vec![0x60, 0x0a, 0x06, 0x06];
        o.extend_from_slice(MECH_SPNEGO);
        o.extend_from_slice(&[0x30, 0x00]);
        o
    };
    assert_eq!(
        decode_neg_token_init(&no_choice).unwrap_err(),
        GssError::DefectiveToken
    );
}

#[test]
fn codec_neg_token_resp() {
    let tok = encode_neg_token_resp(
        NegState::AcceptIncomplete,
        Some(MECH_KRB5),
        Some(b"T"),
        Some(b"M"),
    );
    let expected: &[u8] = &[
        0xa1, 0x1e, 0x30, 0x1c, // [1] SEQUENCE
        0xa0, 0x03, 0x0a, 0x01, 0x01, // negState accept-incomplete
        0xa1, 0x0b, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02,
        0x02, // supportedMech
        0xa2, 0x03, 0x04, 0x01, 0x54, // responseToken "T"
        0xa3, 0x03, 0x04, 0x01, 0x4d, // mechListMIC "M"
    ];
    assert_eq!(tok, expected);

    let resp = decode_neg_token_resp(&tok).expect("decode");
    assert_eq!(resp.neg_state, Some(NegState::AcceptIncomplete));
    assert_eq!(resp.supported_mech.as_deref(), Some(MECH_KRB5));
    assert_eq!(resp.response_token.as_deref(), Some(b"T".as_ref()));
    assert_eq!(resp.mech_list_mic.as_deref(), Some(b"M".as_ref()));

    // Zero-length responseToken is omitted entirely
    // (make_spnego_tokenTarg_msg:3737-3738 token->length > 0).
    let tok2 = encode_neg_token_resp(NegState::Reject, None, Some(b""), None);
    let expected2: &[u8] = &[0xa1, 0x07, 0x30, 0x05, 0xa0, 0x03, 0x0a, 0x01, 0x02];
    assert_eq!(tok2, expected2);
    let resp2 = decode_neg_token_resp(&tok2).expect("decode");
    assert_eq!(resp2.neg_state, Some(NegState::Reject));
    assert!(resp2.response_token.is_none());

    // Missing SEQUENCE tag tolerated (get_negTokenResp:3494-3496).
    let no_seq: &[u8] = &[0xa1, 0x05, 0xa0, 0x03, 0x0a, 0x01, 0x00];
    let resp3 = decode_neg_token_resp(no_seq).expect("decode no-seq");
    assert_eq!(resp3.neg_state, Some(NegState::AcceptCompleted));

    // ENUMERATED length != 1 → DefectiveToken (:3500-3502).
    let bad_enum: &[u8] = &[0xa1, 0x06, 0xa0, 0x04, 0x0a, 0x02, 0x00, 0x00];
    assert_eq!(
        decode_neg_token_resp(bad_enum).unwrap_err(),
        GssError::DefectiveToken
    );

    // Windows 2000 quirk (:3525-3536): mechListMIC byte-identical to
    // responseToken is discarded.
    let dup = encode_neg_token_resp(
        NegState::AcceptIncomplete,
        None,
        Some(b"same-bytes"),
        Some(b"same-bytes"),
    );
    let resp4 = decode_neg_token_resp(&dup).expect("decode dup");
    assert_eq!(
        resp4.response_token.as_deref(),
        Some(b"same-bytes".as_ref())
    );
    assert!(resp4.mech_list_mic.is_none());
}

// --- 4. initiator first token ----------------------------------------------------

#[test]
fn init_first_token_is_neg_token_init_with_optimistic_krb5() {
    let skey = random_key(18);
    let cred = svc_cred(&skey, 18);
    // A non-krb5 OID listed first is dropped (init_ctx_call_init:940-960
    // fallback drops the failed first mech and re-encodes DER_mechTypes).
    let mut init = new_initiator(
        cred,
        GssFlags::empty(),
        vec![MECH_NTLMSSP.to_vec(), MECH_KRB5.to_vec()],
    );
    let tok = cont(init.step(None).expect("step"));
    let (ni, der) = decode_neg_token_init(&tok).expect("decode");
    assert_eq!(ni.mech_types, vec![MECH_KRB5.to_vec()]);
    assert_eq!(der, mech_types_der(&[MECH_KRB5]));
    let mechtok = ni.mech_token.expect("mechToken");
    let (mech, body) = parse_token_header(&mechtok).expect("inner framing");
    assert_eq!(mech, MECH_KRB5);
    assert_eq!(&body[..2], &[0x01, 0x00]); // TOK_ID_AP_REQ
                                           // Even with a completed (non-mutual) inner mech, SPNEGO returns
                                           // Continue because negState != ACCEPT_COMPLETE (:1095-1098).
    assert!(init.context().is_err());
}

#[test]
fn init_first_token_mutual_returns_continue() {
    let skey = random_key(18);
    let cred = svc_cred(&skey, 18);
    let mut init = new_initiator(cred, GssFlags::MUTUAL, vec![MECH_KRB5.to_vec()]);
    cont(init.step(None).expect("step"));
    assert!(init.context().is_err());
}

// --- 5. acceptor basic flow -------------------------------------------------------

#[test]
fn spnego_roundtrip_mutual() {
    let skey = random_key(18);
    let cred = svc_cred(&skey, 18);
    let mut init = new_initiator(
        cred,
        GssFlags::MUTUAL | GssFlags::REPLAY | GssFlags::SEQUENCE,
        vec![MECH_KRB5.to_vec()],
    );
    let t1 = cont(init.step(None).expect("init"));

    let mut acc = new_acceptor(&skey, vec![MECH_KRB5.to_vec()]);
    let resp = accept_complete(acc.step(&t1).expect("accept")).expect("resp token");
    let nr = decode_neg_token_resp(&resp).expect("decode resp");
    assert_eq!(nr.neg_state, Some(NegState::AcceptCompleted));
    assert_eq!(nr.supported_mech.as_deref(), Some(MECH_KRB5));
    // First mech in the initiator list → ACCEPT_INCOMPLETE → no MIC required;
    // mutual krb5 completes and returns the AP-REP.
    assert!(nr.response_token.is_some());
    assert!(nr.mech_list_mic.is_none());
    let (mech, body) =
        parse_token_header(nr.response_token.as_deref().expect("tok")).expect("ap-rep framing");
    assert_eq!(mech, MECH_KRB5);
    assert_eq!(&body[..2], &[0x02, 0x00]);

    assert!(init_complete(init.step(Some(&resp)).expect("step2")).is_none());
    assert_eq!(init.negotiated_mech(), Some(MECH_KRB5));
    assert_eq!(acc.negotiated_mech(), Some(MECH_KRB5));

    let mut ic = init.context().expect("init ctx");
    let mut ac = acc.context().expect("acc ctx");
    assert!(!ic.flags().contains(GssFlags::PROT_READY));
    assert!(!ac.flags().contains(GssFlags::PROT_READY));
    let w = ic.wrap(true, b"hello").expect("wrap");
    assert_eq!(ac.unwrap(&w).expect("unwrap").data, b"hello");
    let w2 = ac.wrap(true, b"world").expect("wrap");
    assert_eq!(ic.unwrap(&w2).expect("unwrap").data, b"world");
}

#[test]
fn spnego_roundtrip_non_mutual() {
    let skey = random_key(18);
    let cred = svc_cred(&skey, 18);
    let mut init = new_initiator(
        cred,
        GssFlags::REPLAY | GssFlags::SEQUENCE,
        vec![MECH_KRB5.to_vec()],
    );
    let t1 = cont(init.step(None).expect("init"));

    let mut acc = new_acceptor(&skey, vec![MECH_KRB5.to_vec()]);
    let resp = accept_complete(acc.step(&t1).expect("accept")).expect("resp token");
    let nr = decode_neg_token_resp(&resp).expect("decode resp");
    assert_eq!(nr.neg_state, Some(NegState::AcceptCompleted));
    assert_eq!(nr.supported_mech.as_deref(), Some(MECH_KRB5));
    assert!(nr.response_token.is_none());
    assert!(nr.mech_list_mic.is_none());

    assert!(init_complete(init.step(Some(&resp)).expect("step2")).is_none());
    let ic = init.context().expect("init ctx");
    assert!(!ic.flags().contains(GssFlags::MUTUAL));
}

// --- 6. MIC exchange (REQUEST_MIC path) -------------------------------------------

#[test]
fn request_mic_path() {
    let skey = random_key(18);
    // Initiator advertises [NTLMSSP, KRB5]: the acceptor picks index 1 →
    // REQUEST_MIC (negotiate_mech:3570-3572), and the mechToken is NOT fed
    // to the mech (spnego_gss_accept_sec_context:1663).
    let der = mech_types_der(&[MECH_NTLMSSP, MECH_KRB5]);
    let ap_req1 = raw_ap_req(&skey, GssFlags::empty());
    let t1 = encode_neg_token_init(&der, Some(&ap_req1), None, false);

    let mut acc = new_acceptor(&skey, vec![MECH_KRB5.to_vec()]);
    let r1 = accept_continue(acc.step(&t1).expect("accept1"));
    let nr1 = decode_neg_token_resp(&r1).expect("decode r1");
    assert_eq!(nr1.neg_state, Some(NegState::RequestMic));
    assert_eq!(nr1.supported_mech.as_deref(), Some(MECH_KRB5));
    assert!(nr1.response_token.is_none());
    assert!(nr1.mech_list_mic.is_none());
    // The mechToken is NOT consumed on the REQUEST_MIC path
    // (spnego_gss_accept_sec_context:1663) — proven implicitly when the
    // next step still accepts a fresh AP-REQ (context() takes self, so it
    // cannot be probed mid-exchange).

    // The initiator re-sends a real (mutual) AP-REQ in a NegTokenResp.
    let cred2 = svc_cred(&skey, 18);
    let mut init_b = Krb5Initiator::new(cred2, None, GssFlags::MUTUAL, None).expect("init_b");
    let ap_req2 = cont(init_b.step(None).expect("init_b step"));
    let t2 = encode_neg_token_resp(NegState::AcceptIncomplete, None, Some(&ap_req2), None);

    let r2 = accept_continue(acc.step(&t2).expect("accept2"));
    let nr2 = decode_neg_token_resp(&r2).expect("decode r2");
    assert_eq!(nr2.neg_state, Some(NegState::AcceptIncomplete));
    // supportedMech is only sent with INIT_TOKEN_SEND (first reply).
    assert!(nr2.supported_mech.is_none());
    let ap_rep = nr2.response_token.clone().expect("AP-REP in r2");
    let acc_mic = nr2.mech_list_mic.clone().expect("acceptor MIC in r2");

    // Finish the inner mutual exchange and verify the acceptor MIC over the
    // exact DER mechTypes bytes.
    assert!(init_complete(init_b.step(Some(&ap_rep)).expect("init_b rep")).is_none());
    let mut ctx_b = init_b.context().expect("ctx_b");
    ctx_b
        .verify_mic(&der, &acc_mic)
        .expect("verify acceptor MIC");

    // Initiator's final message: MIC only, no responseToken.
    let init_mic = ctx_b.get_mic(&der).expect("initiator MIC");
    let t3 = encode_neg_token_resp(NegState::AcceptIncomplete, None, None, Some(&init_mic));
    // Both MICs sent and received → ACCEPT_COMPLETE and, since the MIC was
    // already sent on the previous pass, NO_TOKEN_SEND (handle_mic:573-585)
    // → complete with no output token.
    let out3 = accept_complete(acc.step(&t3).expect("accept3"));
    assert!(out3.is_none(), "no token when both MICs already exchanged");
    assert_eq!(acc.negotiated_mech(), Some(MECH_KRB5));
    let mut ctx_a = acc.context().expect("acc ctx");
    ctx_a
        .verify_mic(&der, &init_mic)
        .expect("verify initiator MIC");
}

// --- 7. acceptor rejection/error paths ---------------------------------------------

#[test]
fn acceptor_rejects() {
    let skey = random_key(18);
    let der_k = mech_types_der(&[MECH_KRB5]);

    // No common mechanism → GSS_S_BAD_MECH (acc_ctx_new:1333-1336; MIT also
    // emits a REJECT error token, which our API does not carry).
    let t = encode_neg_token_init(&mech_types_der(&[MECH_NTLMSSP]), None, None, false);
    let mut acc = new_acceptor(&skey, vec![MECH_KRB5.to_vec()]);
    assert_eq!(gss_err(acc.step(&t).unwrap_err()), GssError::BadMech);

    // Inner mechToken framed with the SPNEGO OID: acc_ctx_vfy_oid →
    // GSS_S_BAD_MECH.
    let ap_req = raw_ap_req(&skey, GssFlags::empty());
    let (_m, body) = parse_token_header(&ap_req).expect("hdr");
    let mut framed = make_token_header(MECH_SPNEGO, body.len(), None);
    framed.extend_from_slice(body);
    let t = encode_neg_token_init(&der_k, Some(&framed), None, false);
    let mut acc = new_acceptor(&skey, vec![MECH_KRB5.to_vec()]);
    assert_eq!(gss_err(acc.step(&t).unwrap_err()), GssError::BadMech);

    // MS wrong krb5 OID listed first with a correct-OID krb5 mechToken:
    // negotiate_mech maps WRONG→krb5 (i==0 → ACCEPT_INCOMPLETE) and echoes
    // the wrong OID back verbatim as supportedMech (:3574-3577).
    let der_wk = mech_types_der(&[MECH_KRB5_WRONG, MECH_KRB5]);
    let t = encode_neg_token_init(&der_wk, Some(&ap_req), None, false);
    let mut acc = new_acceptor(&skey, vec![MECH_KRB5.to_vec()]);
    let resp = accept_complete(acc.step(&t).expect("accept wrong-oid")).expect("tok");
    let nr = decode_neg_token_resp(&resp).expect("decode");
    assert_eq!(nr.supported_mech.as_deref(), Some(MECH_KRB5_WRONG));

    // A NegTokenResp as the first token → DefectiveToken (the [1] choice
    // cannot be a NegTokenInit).
    let resp_tok = encode_neg_token_resp(NegState::AcceptIncomplete, None, None, None);
    let mut acc = new_acceptor(&skey, vec![MECH_KRB5.to_vec()]);
    assert_eq!(
        gss_err(acc.step(&resp_tok).unwrap_err()),
        GssError::DefectiveToken
    );

    // After REQUEST_MIC, a subsequent token with neither responseToken nor
    // mechListMIC → DefectiveToken (acc_ctx_cont:1400-1404).
    let der_nk = mech_types_der(&[MECH_NTLMSSP, MECH_KRB5]);
    let t1 = encode_neg_token_init(&der_nk, None, None, false);
    let mut acc = new_acceptor(&skey, vec![MECH_KRB5.to_vec()]);
    accept_continue(acc.step(&t1).expect("req-mic"));
    let empty_resp = encode_neg_token_resp(NegState::AcceptIncomplete, None, None, None);
    assert_eq!(
        gss_err(acc.step(&empty_resp).unwrap_err()),
        GssError::DefectiveToken
    );

    // supportedMech on a subsequent token → DefectiveToken (:1405-1408).
    let mut acc2 = new_acceptor(&skey, vec![MECH_KRB5.to_vec()]);
    accept_continue(acc2.step(&t1).expect("req-mic"));
    let sup_resp = encode_neg_token_resp(
        NegState::AcceptIncomplete,
        Some(MECH_KRB5),
        Some(b"x"),
        None,
    );
    assert_eq!(
        gss_err(acc2.step(&sup_resp).unwrap_err()),
        GssError::DefectiveToken
    );
}

// --- 8. initiator rejection/error paths --------------------------------------------

#[test]
fn initiator_rejects() {
    let skey = random_key(18);

    // First reply REJECT without a responseToken → GSS_S_BAD_MECH
    // (init_ctx_cont:715-724).
    let cred = svc_cred(&skey, 18);
    let mut init = new_initiator(cred, GssFlags::MUTUAL, vec![MECH_KRB5.to_vec()]);
    cont(init.step(None).expect("init"));
    let rej = encode_neg_token_resp(NegState::Reject, None, None, None);
    assert_eq!(
        gss_err(init.step(Some(&rej)).unwrap_err()),
        GssError::BadMech
    );

    // supportedMech not in the initiator's list → DefectiveToken
    // (init_ctx_reselect:847-851).
    let cred = svc_cred(&skey, 18);
    let mut init = new_initiator(cred, GssFlags::MUTUAL, vec![MECH_KRB5.to_vec()]);
    cont(init.step(None).expect("init"));
    let bad = encode_neg_token_resp(NegState::RequestMic, Some(MECH_NTLMSSP), None, None);
    assert_eq!(
        gss_err(init.step(Some(&bad)).unwrap_err()),
        GssError::DefectiveToken
    );

    // ACCEPT_INCOMPLETE with no responseToken while the (mutual) mech is not
    // complete → DefectiveToken (init_ctx_nego:800-809).
    let cred = svc_cred(&skey, 18);
    let mut init = new_initiator(cred, GssFlags::MUTUAL, vec![MECH_KRB5.to_vec()]);
    cont(init.step(None).expect("init"));
    let no_tok = encode_neg_token_resp(NegState::AcceptIncomplete, Some(MECH_KRB5), None, None);
    assert_eq!(
        gss_err(init.step(Some(&no_tok)).unwrap_err()),
        GssError::DefectiveToken
    );

    // A mech token arriving after the mech completed → DefectiveToken
    // (init_ctx_nego:817-820).  Non-mutual krb5 completes on the first call.
    let cred = svc_cred(&skey, 18);
    let mut init = new_initiator(cred, GssFlags::empty(), vec![MECH_KRB5.to_vec()]);
    cont(init.step(None).expect("init"));
    let spurious = encode_neg_token_resp(
        NegState::AcceptIncomplete,
        Some(MECH_KRB5),
        Some(b"x"),
        None,
    );
    assert_eq!(
        gss_err(init.step(Some(&spurious)).unwrap_err()),
        GssError::DefectiveToken
    );

    // A MIC that fails verification → the verify error (BadSig), not a
    // DefectiveToken (process_mic:610-619 propagates gss_verify_mic's ret).
    let cred = svc_cred(&skey, 18);
    let mut init = new_initiator(cred, GssFlags::MUTUAL, vec![MECH_KRB5.to_vec()]);
    let t1 = cont(init.step(None).expect("init"));
    let (ni, _der) = decode_neg_token_init(&t1).expect("decode");
    let mechtok = ni.mech_token.expect("mechtok");
    let mut raw_acc = Krb5Acceptor::new(Box::new(OneKey(skey.clone())), Some(service()), None);
    let ap_rep = accept_complete(raw_acc.step(&mechtok).expect("raw accept")).expect("rep");
    let mut acc_ctx = raw_acc.context().expect("raw ctx");
    let bad_mic = acc_ctx.get_mic(b"not-the-mech-list").expect("mic");
    let resp = encode_neg_token_resp(
        NegState::AcceptIncomplete,
        Some(MECH_KRB5),
        Some(&ap_rep),
        Some(&bad_mic),
    );
    assert_eq!(
        gss_err(init.step(Some(&resp)).unwrap_err()),
        GssError::BadSig
    );
}

// --- 9. initiator MIC request handling ----------------------------------------------

#[test]
fn initiator_mic_when_acceptor_requests() {
    let skey = random_key(18);

    // A crafted RequestMic reselecting the same krb5 mechanism with no
    // responseToken: both OIDs are kerb mechs so this is NOT a counter-
    // proposal; no token while the mech is incomplete → DefectiveToken
    // (init_ctx_nego:800-809).
    let cred = svc_cred(&skey, 18);
    let mut init = new_initiator(cred, GssFlags::MUTUAL, vec![MECH_KRB5.to_vec()]);
    cont(init.step(None).expect("init"));
    let req_mic = encode_neg_token_resp(NegState::RequestMic, Some(MECH_KRB5), None, None);
    assert_eq!(
        gss_err(init.step(Some(&req_mic)).unwrap_err()),
        GssError::DefectiveToken
    );

    // Positive case: mech completes (mutual), acceptor sends
    // ACCEPT_INCOMPLETE + AP-REP + acceptor MIC.  The initiator verifies the
    // MIC, sends its own, and completes with a token (handle_mic:573-585:
    // mic_out present → CONT_TOKEN_SEND; negState ACCEPT_COMPLETE → COMPLETE).
    let cred = svc_cred(&skey, 18);
    let mut init = new_initiator(cred, GssFlags::MUTUAL, vec![MECH_KRB5.to_vec()]);
    let t1 = cont(init.step(None).expect("init"));
    let (ni, der) = decode_neg_token_init(&t1).expect("decode");
    let mut raw_acc = Krb5Acceptor::new(Box::new(OneKey(skey.clone())), Some(service()), None);
    let ap_rep = accept_complete(
        raw_acc
            .step(ni.mech_token.as_deref().expect("mt"))
            .expect("accept"),
    )
    .expect("rep");
    let mut acc_ctx = raw_acc.context().expect("acc ctx");
    let acc_mic = acc_ctx.get_mic(&der).expect("acc mic");

    let resp = encode_neg_token_resp(
        NegState::AcceptIncomplete,
        None,
        Some(&ap_rep),
        Some(&acc_mic),
    );
    let out = init_complete(init.step(Some(&resp)).expect("init step"))
        .expect("initiator must still send its MIC");
    let nr = decode_neg_token_resp(&out).expect("decode initiator resp");
    assert_eq!(nr.neg_state, Some(NegState::AcceptCompleted));
    assert!(nr.supported_mech.is_none());
    assert!(nr.response_token.is_none());
    let init_mic = nr.mech_list_mic.expect("initiator MIC");
    acc_ctx
        .verify_mic(&der, &init_mic)
        .expect("acceptor verifies initiator MIC");

    // A second MIC after one was already received → DefectiveToken
    // (handle_mic:551-555).
    let second_mic = acc_ctx.get_mic(&der).expect("mic2");
    let resp2 = encode_neg_token_resp(NegState::AcceptCompleted, None, None, Some(&second_mic));
    assert_eq!(
        gss_err(init.step(Some(&resp2)).unwrap_err()),
        GssError::DefectiveToken
    );
}

// --- 10. NegHints -------------------------------------------------------------------

#[test]
fn neg_hints() {
    let skey = random_key(18);
    let mut acc = new_acceptor(&skey, vec![MECH_KRB5.to_vec()]);
    let tok = accept_continue(acc.step(b"").expect("hints"));

    // The token is a framed NegTokenInit advertising our mech list, with the
    // [3] mechListMIC slot carrying a SEQUENCE-tagged NegHints blob
    // (make_NegHints:1172-1204 + make_spnego_tokenInit_msg negHintsCompat
    // at :3688-3693): 30 28 a0 26 1b 24 "not_defined_in_RFC4178@please_ignore".
    let mut hint = vec![0x30, 0x28, 0xa0, 0x26, 0x1b, 0x24];
    hint.extend_from_slice(HINT_NAME);
    assert!(
        tok.windows(hint.len()).any(|w| w == hint.as_slice()),
        "NegHints blob not found in token"
    );
    // And the advertised mechTypes blob is present verbatim.
    let mt = mech_types_der(&[MECH_KRB5]);
    assert!(tok.windows(mt.len()).any(|w| w == mt.as_slice()));

    // A normal NegTokenInit then proceeds as usual (the hints context is
    // discarded — internal_mech was never set).
    let cred = svc_cred(&skey, 18);
    let mut init = new_initiator(cred, GssFlags::empty(), vec![MECH_KRB5.to_vec()]);
    let t1 = cont(init.step(None).expect("init"));
    let resp = accept_complete(acc.step(&t1).expect("accept")).expect("resp");
    let nr = decode_neg_token_resp(&resp).expect("decode");
    assert_eq!(nr.neg_state, Some(NegState::AcceptCompleted));
    assert!(init_complete(init.step(Some(&resp)).expect("fin")).is_none());
}
