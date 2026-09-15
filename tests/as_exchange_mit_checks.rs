//! MIT krb5 semantics checks for the AS exchange (krb5-1.22.2 reference):
//! informational padata, PA-FX-COOKIE echo, restart behavior, and
//! PA-REQ-ENC-PA-REP verification. Uses only the public API.

use krb5_rs::crypto::find_etype;
use krb5_rs::protocol::{AsExchange, AsExchangeConfig, StepResult};
use krb5_rs::types::*;
use krb5_rs::Krb5Error;
use rasn::types::{GeneralString, OctetString};

#[path = "common/mod.rs"]
mod common;
use common::fixtures::{now, unwrap_send};
use common::krb_error::krb_error_der;

const PA_ENC_TIMESTAMP: i32 = 2;
const PA_FX_COOKIE: i32 = 133;
const PA_REQ_ENC_PA_REP: i32 = 149;
const PA_AS_FRESHNESS: i32 = 150;
const PA_ETYPE_INFO2: i32 = 19;

const REALM: &str = "EXAMPLE.COM";
const CLIENT: &str = "testuser";
const PASSWORD: &str = "password";
const SALT: &[u8] = b"EXAMPLE.COMtestuser";

fn new_exchange() -> AsExchange {
    let config = AsExchangeConfig::new(PrincipalName::new_principal(CLIENT), REALM);
    AsExchange::new(config, PASSWORD)
}

/// Build a DER-encoded KRB-ERROR for the given realm.
fn krb_error_realm(code: i32, realm: &str, e_data: Option<Vec<u8>>) -> Vec<u8> {
    krb_error_der(code, realm, Some(now()), e_data)
}

/// Build a DER-encoded KRB-ERROR for EXAMPLE.COM.
fn krb_error(code: i32, e_data: Option<Vec<u8>>) -> Vec<u8> {
    krb_error_realm(code, REALM, e_data)
}

/// Build DER-encoded METHOD-DATA (SEQUENCE OF PA-DATA).
fn method_data(etype_info2: bool, cookie: Option<&[u8]>) -> Vec<u8> {
    let mut padata: Vec<PaData> = Vec::new();
    if etype_info2 {
        let entries = vec![EtypeInfo2Entry {
            etype: 18,
            salt: Some(GeneralString::from_bytes(SALT).expect("salt")),
            s2kparams: None,
        }];
        padata.push(PaData {
            padata_type: PA_ETYPE_INFO2,
            padata_value: rasn::der::encode(&entries)
                .expect("encode ETYPE-INFO2")
                .into(),
        });
    }
    // A real KDC offers PA-ENC-TIMESTAMP in METHOD-DATA; MIT's client only
    // answers a real preauth type it was offered (preauth2.c:650-735).
    padata.push(PaData {
        padata_type: PA_ENC_TIMESTAMP,
        padata_value: OctetString::from(Vec::new()),
    });
    if let Some(c) = cookie {
        padata.push(PaData {
            padata_type: PA_FX_COOKIE,
            padata_value: OctetString::from(c.to_vec()),
        });
    }
    rasn::der::encode(&padata).expect("encode METHOD-DATA")
}

/// Decode an AS-REQ and return its padata list.
fn padata_of(as_req_der: &[u8]) -> Vec<PaData> {
    let as_req: AsReq = rasn::der::decode(as_req_der).expect("decode AS-REQ");
    as_req.0.padata.unwrap_or_default()
}

fn count(padata: &[PaData], ty: i32) -> usize {
    padata.iter().filter(|pa| pa.padata_type == ty).count()
}

fn value(padata: &[PaData], ty: i32) -> Option<Vec<u8>> {
    let pa = padata.iter().find(|pa| pa.padata_type == ty)?;
    let bytes: &[u8] = pa.padata_value.as_ref();
    Some(bytes.to_vec())
}

/// Derive the AES-256 reply key used by the mock KDC.
fn reply_key() -> Vec<u8> {
    find_etype(18)
        .expect("etype 18")
        .string_to_key(PASSWORD.as_bytes(), SALT, None)
        .expect("string_to_key")
        .to_vec()
}

/// How the AS-REP should carry PA-REQ-ENC-PA-REP in encrypted_pa_data.
enum EncPaRep {
    /// No encrypted_pa_data at all.
    Absent,
    /// Valid checksum over the last-sent AS-REQ bytes, cksumtype 16.
    Valid,
    /// Valid shape but corrupted checksum bytes.
    Corrupt,
    /// Checksum computed over the given bytes instead of the AS-REQ.
    OverBytes(Vec<u8>),
    /// Valid checksum value but a different cksumtype.
    CksumType(i32),
    /// Undecodable padata value.
    Garbage,
}

/// Build a DER-encoded AS-REP answering `as_req_der`.
fn build_as_rep(
    as_req_der: &[u8],
    flag_enc_pa_rep: bool,
    enc_pa_rep: EncPaRep,
    enc_etype: i32,
) -> Vec<u8> {
    let as_req: AsReq = rasn::der::decode(as_req_der).expect("decode AS-REQ");
    let nonce = as_req.0.req_body.nonce;
    let realm = as_req.0.req_body.realm.clone();

    let profile18 = find_etype(18).expect("etype 18");
    let rkey = reply_key();

    let mut flags = TicketFlags::INITIAL;
    if flag_enc_pa_rep {
        flags |= TicketFlags::ENC_PA_REP;
    }

    let encrypted_pa_data = match enc_pa_rep {
        EncPaRep::Absent => None,
        EncPaRep::Garbage => Some(vec![PaData {
            padata_type: PA_REQ_ENC_PA_REP,
            padata_value: OctetString::from(vec![0x01, 0x02, 0x03]),
        }]),
        _ => {
            let (cksumtype, data) = match &enc_pa_rep {
                EncPaRep::Valid => (16, as_req_der.to_vec()),
                EncPaRep::Corrupt => (16, as_req_der.to_vec()),
                EncPaRep::OverBytes(b) => (16, b.clone()),
                EncPaRep::CksumType(t) => (*t, as_req_der.to_vec()),
                _ => unreachable!(),
            };
            let mut checksum = profile18.checksum(&rkey, 56, &data).expect("checksum");
            if matches!(enc_pa_rep, EncPaRep::Corrupt) {
                let last = checksum.last_mut().expect("nonempty checksum");
                *last ^= 0xFF;
            }
            let cksum = Checksum {
                cksumtype,
                checksum: checksum.into(),
            };
            Some(vec![PaData {
                padata_type: PA_REQ_ENC_PA_REP,
                padata_value: rasn::der::encode(&cksum).expect("encode Checksum").into(),
            }])
        }
    };

    let t = now();
    let enc_kdc_rep = EncKdcRepPart {
        key: EncryptionKey::new(18, rand::random::<[u8; 32]>().to_vec()),
        last_req: vec![LastReqEntry {
            lr_type: 0,
            lr_value: t,
        }],
        nonce,
        key_expiration: None,
        flags: KerberosFlags::new(flags),
        authtime: t,
        starttime: None,
        endtime: t + chrono::Duration::hours(10),
        renew_till: None,
        srealm: GeneralString::from_bytes(REALM.as_bytes()).expect("realm"),
        sname: PrincipalName::new_srv_inst("krbtgt", REALM),
        caddr: None,
        encrypted_pa_data,
    };
    let plaintext = rasn::der::encode(&EncAsRepPart(enc_kdc_rep)).expect("encode EncAsRepPart");

    let (enc_profile, key) = if enc_etype == 18 {
        (profile18, rkey)
    } else {
        let k = find_etype(enc_etype)
            .expect("etype")
            .string_to_key(PASSWORD.as_bytes(), SALT, None)
            .expect("string_to_key")
            .to_vec();
        (find_etype(enc_etype).expect("etype"), k)
    };
    let cipher = enc_profile
        .encrypt(&key, 3, &plaintext)
        .expect("encrypt EncAsRepPart");

    let rep = KdcRep {
        pvno: 5,
        msg_type: 11,
        padata: None,
        crealm: GeneralString::from_bytes(REALM.as_bytes()).expect("realm"),
        cname: PrincipalName::new_principal(CLIENT),
        ticket: Ticket {
            tkt_vno: 5,
            realm,
            sname: PrincipalName::new_srv_inst("krbtgt", REALM),
            enc_part: EncryptedData {
                etype: 18,
                kvno: Some(1),
                cipher: OctetString::from(vec![0xAA; 32]),
            },
        },
        enc_part: EncryptedData {
            etype: enc_etype,
            kvno: None,
            cipher: cipher.into(),
        },
    };
    rasn::der::encode(&AsRep(rep)).expect("encode AS-REP")
}

/// Drive an exchange to the point where it sends a preauthenticated AS-REQ.
fn run_to_preauth_req(exchange: &mut AsExchange) -> Vec<u8> {
    unwrap_send(exchange.step(&[]).expect("initial step"));
    unwrap_send(
        exchange
            .step(&krb_error(25, Some(method_data(true, None))))
            .expect("PREAUTH_REQUIRED step"),
    )
}

// MIT get_in_tkt.c:1365-1372 — every AS-REQ carries empty PA-AS-FRESHNESS
// and PA-REQ-ENC-PA-REP while info_pa_permitted.
#[test]
fn initial_as_req_carries_empty_informational_padata() {
    let mut exchange = new_exchange();
    let data = unwrap_send(exchange.step(&[]).expect("initial step"));
    let padata = padata_of(&data);
    assert_eq!(count(&padata, PA_AS_FRESHNESS), 1);
    assert_eq!(value(&padata, PA_AS_FRESHNESS), Some(Vec::new()));
    assert_eq!(count(&padata, PA_REQ_ENC_PA_REP), 1);
    assert_eq!(value(&padata, PA_REQ_ENC_PA_REP), Some(Vec::new()));
}

#[test]
fn preauth_as_req_also_carries_informational_padata() {
    let mut exchange = new_exchange();
    let data = run_to_preauth_req(&mut exchange);
    let padata = padata_of(&data);
    assert_eq!(count(&padata, PA_ENC_TIMESTAMP), 1);
    assert_eq!(count(&padata, PA_REQ_ENC_PA_REP), 1);
    assert_eq!(value(&padata, PA_REQ_ENC_PA_REP), Some(Vec::new()));
    assert_eq!(count(&padata, PA_AS_FRESHNESS), 1);
    assert_eq!(value(&padata, PA_AS_FRESHNESS), Some(Vec::new()));
}

// MIT preauth2.c:856-884 copy_cookie — PA-FX-COOKIE echoed verbatim.
#[test]
fn cookie_from_preauth_required_is_echoed_verbatim() {
    let mut exchange = new_exchange();
    let initial = unwrap_send(exchange.step(&[]).expect("initial step"));
    assert_eq!(count(&padata_of(&initial), PA_FX_COOKIE), 0);

    let cookie = b"MIT-cookie-\x00\x01\xff";
    let data = unwrap_send(
        exchange
            .step(&krb_error(25, Some(method_data(true, Some(cookie)))))
            .expect("step"),
    );
    let padata = padata_of(&data);
    assert_eq!(count(&padata, PA_FX_COOKIE), 1);
    assert_eq!(value(&padata, PA_FX_COOKIE), Some(cookie.to_vec()));
    assert_eq!(count(&padata, PA_ENC_TIMESTAMP), 1);
}

#[test]
fn no_cookie_sent_when_kdc_sent_none() {
    let mut exchange = new_exchange();
    let data = run_to_preauth_req(&mut exchange);
    assert_eq!(count(&padata_of(&data), PA_FX_COOKIE), 0);
}

#[test]
fn newest_cookie_replaces_older_and_absent_means_none() {
    let mut exchange = new_exchange();
    unwrap_send(exchange.step(&[]).expect("initial step"));
    let data = unwrap_send(
        exchange
            .step(&krb_error(25, Some(method_data(true, Some(b"A1")))))
            .expect("step"),
    );
    assert_eq!(value(&padata_of(&data), PA_FX_COOKIE), Some(b"A1".to_vec()));

    // MORE_PREAUTH_DATA_REQUIRED (91) with no etype-info — cookie B replaces A.
    let data = unwrap_send(
        exchange
            .step(&krb_error(91, Some(method_data(false, Some(b"B22")))))
            .expect("step 91"),
    );
    let padata = padata_of(&data);
    assert_eq!(count(&padata, PA_FX_COOKIE), 1);
    assert_eq!(value(&padata, PA_FX_COOKIE), Some(b"B22".to_vec()));
    assert_eq!(count(&padata, PA_ENC_TIMESTAMP), 1);

    // Next error carries no cookie — none is sent.
    let data = unwrap_send(
        exchange
            .step(&krb_error(25, Some(method_data(true, None))))
            .expect("step"),
    );
    assert_eq!(count(&padata_of(&data), PA_FX_COOKIE), 0);
}

#[test]
fn wrong_realm_restart_drops_cookie_and_preauth() {
    let mut exchange = new_exchange();
    unwrap_send(exchange.step(&[]).expect("initial step"));
    unwrap_send(
        exchange
            .step(&krb_error(25, Some(method_data(true, Some(b"A1")))))
            .expect("step"),
    );

    let result = exchange
        .step(&krb_error_realm(68, "OTHER.REALM", None))
        .expect("WRONG_REALM step");
    match result {
        StepResult::SendToKdc { data, realm } => {
            assert_eq!(realm, "OTHER.REALM");
            let as_req: AsReq = rasn::der::decode(&data).expect("decode AS-REQ");
            assert_eq!(
                as_req.0.req_body.realm,
                GeneralString::from_bytes(b"OTHER.REALM").expect("realm")
            );
            let padata = as_req.0.padata.unwrap_or_default();
            assert_eq!(count(&padata, PA_FX_COOKIE), 0);
            assert_eq!(count(&padata, PA_ENC_TIMESTAMP), 0);
        }
        other => panic!("expected SendToKdc, got: {other:?}"),
    }
}

#[test]
fn preauth_expired_restarts_from_initial() {
    let mut exchange = new_exchange();
    unwrap_send(exchange.step(&[]).expect("initial step"));
    unwrap_send(
        exchange
            .step(&krb_error(25, Some(method_data(true, Some(b"A1")))))
            .expect("step"),
    );

    let data = unwrap_send(exchange.step(&krb_error(90, None)).expect("step 90"));
    let padata = padata_of(&data);
    assert_eq!(count(&padata, PA_FX_COOKIE), 0);
    assert_eq!(count(&padata, PA_ENC_TIMESTAMP), 0);
    assert_eq!(count(&padata, PA_REQ_ENC_PA_REP), 1);
}

// MIT get_in_tkt.c:1709-1715 — PREAUTH_FAILED before any preauth restarts
// the exchange with info_pa_permitted = false.
#[test]
fn preauth_failed_before_preauth_retries_without_informational_padata() {
    let mut exchange = new_exchange();
    unwrap_send(exchange.step(&[]).expect("initial step"));

    let data = unwrap_send(exchange.step(&krb_error(24, None)).expect("step 24"));
    let padata = padata_of(&data);
    assert_eq!(count(&padata, PA_REQ_ENC_PA_REP), 0);
    assert_eq!(count(&padata, PA_AS_FRESHNESS), 0);
    assert_eq!(count(&padata, PA_ENC_TIMESTAMP), 0);

    let data = unwrap_send(
        exchange
            .step(&krb_error(25, Some(method_data(true, None))))
            .expect("step 25"),
    );
    let padata = padata_of(&data);
    assert_eq!(count(&padata, PA_ENC_TIMESTAMP), 1);
    assert_eq!(count(&padata, PA_REQ_ENC_PA_REP), 0);
    assert_eq!(count(&padata, PA_AS_FRESHNESS), 0);

    match exchange.step(&krb_error(24, None)) {
        Err(Krb5Error::KdcError(e)) => assert_eq!(e.error_code, 24),
        other => panic!("expected KdcError(24), got: {other:?}"),
    }
}

// MIT fast.c:634-675 krb5int_fast_verify_nego — PA-REQ-ENC-PA-REP checks.
#[test]
fn as_rep_with_valid_enc_pa_rep_completes() {
    let mut exchange = new_exchange();
    let req = run_to_preauth_req(&mut exchange);
    let result = exchange
        .step(&build_as_rep(&req, true, EncPaRep::Valid, 18))
        .expect("step");
    assert!(matches!(result, StepResult::Complete));
    assert!(exchange
        .credential()
        .expect("credential")
        .flags
        .contains(TicketFlags::ENC_PA_REP));
}

#[test]
fn as_rep_enc_pa_rep_flag_set_but_padata_missing_is_rejected() {
    let mut exchange = new_exchange();
    let req = run_to_preauth_req(&mut exchange);
    match exchange.step(&build_as_rep(&req, true, EncPaRep::Absent, 18)) {
        Err(Krb5Error::ReplyValidation(_)) => {}
        other => panic!("expected ReplyValidation, got: {other:?}"),
    }
}

#[test]
fn as_rep_enc_pa_rep_checksum_mismatch_is_rejected() {
    let mut exchange = new_exchange();
    let req = run_to_preauth_req(&mut exchange);
    match exchange.step(&build_as_rep(&req, true, EncPaRep::Corrupt, 18)) {
        Err(Krb5Error::ReplyValidation(_)) => {}
        other => panic!("expected ReplyValidation, got: {other:?}"),
    }
}

#[test]
fn as_rep_enc_pa_rep_over_wrong_request_bytes_is_rejected() {
    let mut exchange = new_exchange();
    let initial = unwrap_send(exchange.step(&[]).expect("initial step"));
    let req = unwrap_send(
        exchange
            .step(&krb_error(25, Some(method_data(true, None))))
            .expect("step"),
    );
    match exchange.step(&build_as_rep(&req, true, EncPaRep::OverBytes(initial), 18)) {
        Err(Krb5Error::ReplyValidation(_)) => {}
        other => panic!("expected ReplyValidation, got: {other:?}"),
    }
}

#[test]
fn as_rep_enc_pa_rep_wrong_cksumtype_family_is_rejected() {
    let mut exchange = new_exchange();
    let req = run_to_preauth_req(&mut exchange);
    match exchange.step(&build_as_rep(&req, true, EncPaRep::CksumType(15), 18)) {
        Err(Krb5Error::DecryptionFailed) => panic!("must not be DecryptionFailed"),
        Err(_) => {}
        other => panic!("expected error, got: {other:?}"),
    }

    let mut exchange = new_exchange();
    let req = run_to_preauth_req(&mut exchange);
    match exchange.step(&build_as_rep(&req, true, EncPaRep::CksumType(9999), 18)) {
        Err(Krb5Error::DecryptionFailed) => panic!("must not be DecryptionFailed"),
        Err(_) => {}
        other => panic!("expected error, got: {other:?}"),
    }
}

#[test]
fn as_rep_enc_pa_rep_garbage_is_rejected_when_flag_set() {
    let mut exchange = new_exchange();
    let req = run_to_preauth_req(&mut exchange);
    assert!(exchange
        .step(&build_as_rep(&req, true, EncPaRep::Garbage, 18))
        .is_err());
}

#[test]
fn as_rep_without_enc_pa_rep_flag_completes_without_padata() {
    let mut exchange = new_exchange();
    let req = run_to_preauth_req(&mut exchange);
    let result = exchange
        .step(&build_as_rep(&req, false, EncPaRep::Absent, 18))
        .expect("step");
    assert!(matches!(result, StepResult::Complete));
}

#[test]
fn as_rep_without_enc_pa_rep_flag_ignores_enc_padata() {
    let mut exchange = new_exchange();
    let req = run_to_preauth_req(&mut exchange);
    let result = exchange
        .step(&build_as_rep(&req, false, EncPaRep::Garbage, 18))
        .expect("step");
    assert!(matches!(result, StepResult::Complete));
}

// MIT get_in_tkt.c:1411-1425 check_reply_enctype — reply etype must be one
// we requested.
#[test]
fn as_rep_with_unrequested_etype_is_rejected() {
    let mut config = AsExchangeConfig::new(PrincipalName::new_principal(CLIENT), REALM);
    config.etypes = vec![18];
    let mut exchange = AsExchange::new(config, PASSWORD);
    let req = run_to_preauth_req(&mut exchange);
    match exchange.step(&build_as_rep(&req, true, EncPaRep::Valid, 17)) {
        Err(Krb5Error::ReplyValidation(_)) => {}
        Err(Krb5Error::DecryptionFailed) => panic!("must not be DecryptionFailed"),
        other => panic!("expected ReplyValidation, got: {other:?}"),
    }
}

// MIT get_in_tkt.c:1337-1352 — after the KDC rejects the sent preauth with
// PREAUTH_FAILED and no other real mechanism remains, the saved KDC error
// code (24) is restored over k5_preauth's generic KRB5_PREAUTH_FAILED. This
// is what makes kinit print "Password incorrect".
#[test]
fn preauth_failed_exhaustion_surfaces_kdc_error_24() {
    let mut exchange = new_exchange();
    run_to_preauth_req(&mut exchange);
    // KDC rejects the PA-ENC-TIMESTAMP (wrong password) and re-offers the
    // same method data; type 2 is now in the failed-mechanism list.
    let err = krb_error(24, Some(method_data(true, None)));
    match exchange.step(&err) {
        Err(Krb5Error::KdcError(e)) => assert_eq!(e.error_code, 24),
        other => panic!("expected KdcError(24), got: {other:?}"),
    }
}

// Same save/restore path with save.code == 0: PREAUTH_REQUIRED whose method
// data offers no real mechanism we implement (only PKINIT, type 16) → the
// generic KRB5_PREAUTH_FAILED.
#[test]
fn preauth_required_with_no_supported_mech_is_preauth_failed() {
    const PA_PKINIT: i32 = 16;
    let padata = vec![
        PaData {
            padata_type: PA_ETYPE_INFO2,
            padata_value: rasn::der::encode(&vec![EtypeInfo2Entry {
                etype: 18,
                salt: Some(GeneralString::from_bytes(SALT).expect("salt")),
                s2kparams: None,
            }])
            .expect("encode ETYPE-INFO2")
            .into(),
        },
        PaData {
            padata_type: PA_PKINIT,
            padata_value: OctetString::from(Vec::new()),
        },
    ];
    let md = rasn::der::encode(&padata).expect("encode METHOD-DATA");
    let mut exchange = new_exchange();
    unwrap_send(exchange.step(&[]).expect("initial step"));
    match exchange.step(&krb_error(25, Some(md))) {
        Err(Krb5Error::PreauthFailed) => {}
        other => panic!("expected PreauthFailed, got: {other:?}"),
    }
}
