//! Ports of MIT lib/krb5/krb/t_pac.c plus structural tests.

use super::*;
use crate::protocol::ap::decrypt_ticket;
use crate::types::Ticket;

use super::test_data::*;

fn name(parts: &[&str]) -> PrincipalName {
    PrincipalName {
        name_type: 1,
        name_string: parts
            .iter()
            .map(|p| rasn::types::GeneralString::from_bytes(p.as_bytes()).expect("string"))
            .collect(),
    }
}

fn key(etype: i32, byte: u8) -> EncryptionKey {
    let len = find_etype(etype).expect("etype").key_length();
    EncryptionKey::new(etype, vec![byte; len])
}

const AUTHTIME: i64 = 1_120_440_609;

#[test]
fn parse_saved_samba_pac_reads_buffers_and_client_info() {
    let pac = Pac::parse(SAVED_PAC).expect("parse");
    assert_eq!(pac.types(), vec![1, 10, 6, 7]);
    assert_eq!(pac.get_buffer(PAC_LOGON_INFO).expect("type 1").len(), 472);
    let info = pac.client_info().expect("client info");
    assert_eq!(info.authtime, AUTHTIME);
    assert_eq!(info.name, "w2003final$");
    let p = name(&["w2003final$"]);
    pac.verify(AUTHTIME, Some((&p, "WIN2K3.THINKER.LOCAL")), None, None)
        .expect("client info validates");
    assert_eq!(
        pac.verify(AUTHTIME + 1, Some((&p, "X")), None, None),
        Err(PacError::WrongPrinc)
    );
    assert_eq!(
        pac.verify(AUTHTIME, Some((&name(&["other"]), "X")), None, None),
        Err(PacError::WrongPrinc)
    );
}

#[test]
fn parse_saved_pac_round_trips_byte_for_byte() {
    let pac = Pac::parse(SAVED_PAC).expect("parse");
    assert_eq!(pac.encode(), SAVED_PAC);
}

#[test]
fn parse_rejects_fuzzed_inputs() {
    assert!(Pac::parse(FUZZ1).is_err());
    assert!(Pac::parse(FUZZ2).is_err());
    assert!(Pac::parse(&[]).is_err());
}

#[test]
fn parse_rejects_bad_version_zero_buffers_and_unaligned_offsets() {
    let mut p = Pac::new();
    p.add_buffer(1, b"abcdefgh").expect("add");
    let good = p.encode();
    assert!(Pac::parse(&good).is_ok());

    let mut bad = good.clone();
    bad[4] = 1;
    assert_eq!(
        Pac::parse(&bad),
        Err(PacError::Invalid("unsupported version"))
    );
    let mut bad = good.clone();
    bad[0] = 0;
    assert_eq!(Pac::parse(&bad), Err(PacError::Range));
    let mut bad = good.clone();
    bad[16] = 0x1d;
    assert_eq!(Pac::parse(&bad), Err(PacError::Invalid("unaligned buffer")));
    let mut bad = good;
    bad[12] = 0xff;
    assert_eq!(Pac::parse(&bad), Err(PacError::Range));
}

#[test]
fn add_buffer_pads_to_eight_bytes_and_rejects_duplicates() {
    let mut pac = Pac::new();
    pac.add_buffer(1, &[0, 1]).expect("add 1");
    pac.add_buffer(2, &[2, 0]).expect("add 2");
    assert_eq!(pac.get_buffer(1).expect("1"), &[0, 1]);
    assert_eq!(pac.get_buffer(2).expect("2"), &[2, 0]);
    assert_eq!(pac.add_buffer(1, &[9]), Err(PacError::Exists));
    assert_eq!(pac.get_buffer(3), Err(PacError::NoEntry));
    assert_eq!(pac.encode().len(), 8 + 2 * 16 + 8 + 8);
    let reparsed = Pac::parse(&pac.encode()).expect("reparse");
    assert_eq!(reparsed.buffers(), pac.buffers());
}

fn sign_round_trip(etype: i32) {
    let p = name(&["user"]);
    let server = key(etype, 7);
    let privsvr = key(etype, 9);
    let mut pac = Pac::new();
    pac.add_buffer(1, &[1, 2, 3, 4, 5, 6, 7, 8, 9])
        .expect("add");
    pac.add_buffer(12, &[1, 2]).expect("add");
    let bytes = pac
        .sign(AUTHTIME, (&p, "R"), &server, &privsvr)
        .expect("sign");

    let signed = Pac::parse(&bytes).expect("parse signed");
    assert_eq!(signed.types().len(), 5);
    signed
        .verify(AUTHTIME, Some((&p, "R")), Some(&server), Some(&privsvr))
        .expect("verify");
    signed
        .verify(AUTHTIME, None, Some(&server), None)
        .expect("server only");

    assert_eq!(
        signed.verify(AUTHTIME, None, Some(&key(etype, 8)), None),
        Err(PacError::Modified)
    );
    assert_eq!(
        signed.verify(AUTHTIME, None, None, Some(&key(etype, 8))),
        Err(PacError::Modified)
    );
    assert_eq!(
        signed.verify(AUTHTIME, None, Some(&server), Some(&key(etype, 8))),
        Err(PacError::Modified)
    );

    // Any flipped byte in the logon-info buffer breaks the server signature.
    let mut tampered = bytes.clone();
    let off = signed.locate(1).expect("locate").offset as usize;
    tampered[off] ^= 1;
    let tampered = Pac::parse(&tampered).expect("parse tampered");
    assert_eq!(
        tampered.verify(AUTHTIME, None, Some(&server), Some(&privsvr)),
        Err(PacError::Modified)
    );
}

#[test]
fn sign_verify_round_trip_all_enctypes_and_tamper_detection() {
    for etype in [17, 18, 19, 20] {
        sign_round_trip(etype);
    }
}

#[test]
fn sign_with_wrong_key_enctype_pairs_is_rejected_on_verify() {
    let p = name(&["user"]);
    let mut pac = Pac::new();
    let bytes = pac
        .sign(AUTHTIME, (&p, "R"), &key(18, 1), &key(18, 2))
        .expect("sign");
    let signed = Pac::parse(&bytes).expect("parse");
    assert_eq!(
        signed.verify(AUTHTIME, None, Some(&key(17, 1)), None),
        Err(PacError::BadEnctype)
    );
}

#[test]
fn client_info_name_escaping_and_realm_handling_follow_unparse_flags() {
    let server = key(18, 1);
    let privsvr = key(18, 2);
    let enterprise = PrincipalName {
        name_type: 10,
        name_string: vec![rasn::types::GeneralString::from_bytes(b"u@x@R").expect("s")],
    };
    // Without realm, '@' is escaped when writing but verified as display.
    let mut pac = Pac::new();
    let bytes = pac
        .sign(AUTHTIME, (&enterprise, "R"), &server, &privsvr)
        .expect("sign");
    let signed = Pac::parse(&bytes).expect("parse");
    assert_eq!(signed.client_info().expect("ci").name, "u\\@x\\@R");
    assert!(signed
        .verify(AUTHTIME, Some((&enterprise, "R")), None, None)
        .is_err());

    // With a realm the name is verified only with with_realm.
    let p = name(&["user"]);
    let mut pac = Pac::new();
    pac.sign_pac(AUTHTIME, Some((&p, "R")), &server, &privsvr, true, false)
        .expect("sign with realm");
    assert_eq!(pac.client_info().expect("ci").name, "user@R");
    pac.verify_ext(AUTHTIME, Some((&p, "R")), true, None, None)
        .expect("with realm");
    assert!(pac.verify(AUTHTIME, Some((&p, "R")), None, None).is_err());
}

fn ticket_fixture() -> (EncTicketPart, PrincipalName, EncryptionKey, EncryptionKey) {
    let server_key = EncryptionKey::new(18, TICKET_SERVER_KEY.to_vec());
    let krbtgt_key = EncryptionKey::new(18, TICKET_KRBTGT_KEY.to_vec());
    let ticket: Ticket = rasn::der::decode(TICKET_DATA).expect("decode ticket");
    let enc = decrypt_ticket(&server_key, &ticket).expect("decrypt ticket");
    let sprinc = name(&["cifs", "w2022-118.w2022-l7.base"]);
    (enc, sprinc, server_key, krbtgt_key)
}

#[test]
fn kdc_verify_ticket_accepts_windows_issued_ticket_signatures() {
    let (enc, sprinc, server, krbtgt) = ticket_fixture();
    let pac = kdc_verify_ticket(&enc, &sprinc, &server, Some(&krbtgt))
        .expect("verify ticket")
        .expect("PAC present");
    let cprinc = name(&["administrator"]);
    pac.verify(
        enc.authtime.timestamp(),
        Some((&cprinc, "W2022-L7.BASE")),
        None,
        None,
    )
    .expect("client info");
    assert!(pac.types().contains(&PAC_TICKET_CHECKSUM));
    assert!(pac.types().contains(&PAC_FULL_CHECKSUM));

    let wrong = key(18, 5);
    assert!(kdc_verify_ticket(&enc, &sprinc, &server, Some(&wrong)).is_err());
    assert!(kdc_verify_ticket(&enc, &sprinc, &wrong, Some(&krbtgt)).is_err());
}

#[test]
fn kdc_sign_ticket_reproduces_windows_pac_bytes_when_re_signing() {
    let (mut enc, sprinc, server, krbtgt) = ticket_fixture();
    let mut pac = kdc_verify_ticket(&enc, &sprinc, &server, Some(&krbtgt))
        .expect("verify")
        .expect("pac");
    let original = enc.authorization_data.take().expect("authdata");
    assert_eq!(original.len(), 1);
    let cprinc = name(&["administrator"]);
    kdc_sign_ticket(
        &mut enc,
        &mut pac,
        &sprinc,
        Some((&cprinc, "W2022-L7.BASE")),
        &server,
        &krbtgt,
        false,
    )
    .expect("sign ticket");
    let resigned = enc.authorization_data.as_ref().expect("authdata");
    assert_eq!(resigned.len(), 1);
    assert_eq!(resigned[0].ad_data, original[0].ad_data);
}

#[test]
fn kdc_sign_ticket_builds_a_verifiable_pac_from_copied_buffers() {
    let (mut enc, sprinc, server, krbtgt) = ticket_fixture();
    let pac = kdc_verify_ticket(&enc, &sprinc, &server, Some(&krbtgt))
        .expect("verify")
        .expect("pac");
    let mut pac2 = Pac::new();
    for b in pac.buffers() {
        if [
            PAC_SERVER_CHECKSUM,
            PAC_PRIVSVR_CHECKSUM,
            PAC_TICKET_CHECKSUM,
        ]
        .contains(&b.ty)
        {
            continue;
        }
        pac2.add_buffer(b.ty, &b.data).expect("copy buffer");
    }
    enc.authorization_data = None;
    kdc_sign_ticket(&mut enc, &mut pac2, &sprinc, None, &server, &krbtgt, false)
        .expect("sign ticket");
    let verified = kdc_verify_ticket(&enc, &sprinc, &server, Some(&krbtgt))
        .expect("verify new")
        .expect("pac");
    assert_eq!(verified.types().len(), pac.types().len());
}

#[test]
fn kdc_verify_ticket_detects_tampering_with_the_ticket_after_signing() {
    let (mut enc, sprinc, server, krbtgt) = ticket_fixture();
    enc.endtime += chrono::Duration::seconds(1);
    assert_eq!(
        kdc_verify_ticket(&enc, &sprinc, &server, Some(&krbtgt)).err(),
        Some(PacError::Modified)
    );
    // Without the privsvr key only the PAC's own signatures are checked.
    assert!(kdc_verify_ticket(&enc, &sprinc, &server, None).is_ok());
}

#[test]
fn tgs_tickets_carry_no_ticket_or_full_checksum() {
    let server = key(18, 1);
    let privsvr = key(18, 2);
    let tgs = name(&["krbtgt", "R"]);
    let svc = name(&["HTTP", "host"]);
    assert!(!should_have_ticket_signature(&tgs));
    assert!(!should_have_ticket_signature(&name(&[
        "kadmin", "changepw"
    ])));
    assert!(should_have_ticket_signature(&svc));

    let client = name(&["user"]);
    for (princ, expect_service) in [(&tgs, false), (&svc, true)] {
        let (mut enc, ..) = ticket_fixture();
        enc.authorization_data = None;
        let mut pac = Pac::new();
        kdc_sign_ticket(
            &mut enc,
            &mut pac,
            princ,
            Some((&client, "R")),
            &server,
            &privsvr,
            false,
        )
        .expect("sign");
        let verified = kdc_verify_ticket(&enc, princ, &server, Some(&privsvr))
            .expect("verify")
            .expect("pac");
        let types = verified.types();
        assert_eq!(types.contains(&PAC_TICKET_CHECKSUM), expect_service);
        assert_eq!(types.contains(&PAC_FULL_CHECKSUM), expect_service);
        assert!(types.contains(&PAC_SERVER_CHECKSUM) && types.contains(&PAC_PRIVSVR_CHECKSUM));
        // Buffer order matches MIT: ticket checksum first, then client info.
        if expect_service {
            assert_eq!(types[0], PAC_TICKET_CHECKSUM);
            assert_eq!(types[1], PAC_CLIENT_INFO);
        } else {
            assert_eq!(types[0], PAC_CLIENT_INFO);
        }
    }
}

#[test]
fn ticket_pac_returns_none_without_authdata_and_rejects_duplicates() {
    let (mut enc, ..) = ticket_fixture();
    assert!(ticket_pac(&enc).expect("pac").is_some());
    let dup = enc.authorization_data.clone().expect("authdata");
    enc.authorization_data = Some([dup.clone(), dup].concat());
    assert!(ticket_pac(&enc).is_err());
    enc.authorization_data = None;
    assert!(ticket_pac(&enc).expect("none").is_none());
}
