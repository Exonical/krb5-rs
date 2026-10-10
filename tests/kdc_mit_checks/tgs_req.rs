//! TGS exchange against the KDC (do_tgs_req.c, kdc_util.c, tgs_policy.c).

use super::*;
use krb5_rs::keytab::{KeytabEntry, MemoryKeytab};
use krb5_rs::protocol::ap::{ApReqOptions, AuthContext};

const RENEWABLE_TGT: TicketFlags = TicketFlags::INITIAL
    .union(TicketFlags::PRE_AUTHENT)
    .union(TicketFlags::FORWARDABLE)
    .union(TicketFlags::RENEWABLE);

async fn tgs_error_code(f: &Fixture, req: &[u8]) -> i32 {
    krb_error(&f.kdc.handle(req).await).error_code
}

async fn plain_tgs(f: &Fixture, tgt: &Credential) -> Run<Credential> {
    run_tgs(&f.kdc, tgt, service(), TgsOptions::default()).await
}

#[tokio::test]
async fn tgs_exchange_service_ticket_decrypts_with_service_key() {
    let f = fixture().await;
    let tgt = get_tgt(&f).await;
    let run = plain_tgs(&f, &tgt).await;
    let cred = run.result.expect("TGS exchange");

    let part = decrypt_ticket(&f.service_key, &cred.ticket).expect("decrypt service ticket");
    assert_eq!(part.cname, user());
    assert_eq!(part.crealm.as_bytes(), REALM.as_bytes());
    assert_eq!(part.authtime, tgt.times.authtime);
    assert!(part.endtime <= tgt.times.endtime);
    assert_eq!(part.key.key_bytes(), cred.session_key.key_bytes());
    assert_eq!(cred.ticket.enc_part.kvno, Some(1));
    assert_eq!(cred.server, service());
    assert!(!cred.flags.contains(TicketFlags::INITIAL));
    assert!(cred.flags.contains(TicketFlags::PRE_AUTHENT));
    assert!(cred.flags.contains(TicketFlags::FORWARDABLE));
    assert!(part.flags.contains(TicketFlags::TRANSITED_POLICY_CHECKED));
}

#[tokio::test]
async fn tgs_exchange_service_ticket_authenticates_in_ap_exchange() {
    let f = fixture().await;
    let tgt = get_tgt(&f).await;
    let cred = plain_tgs(&f, &tgt).await.result.expect("TGS exchange");

    let mut client = AuthContext::new();
    let ap_req = client
        .mk_req(&ApReqOptions::default(), None, &cred)
        .expect("mk_req");

    let keytab = MemoryKeytab::from_entries(vec![KeytabEntry {
        principal: service(),
        realm: REALM.to_string(),
        timestamp: 0,
        kvno: 1,
        key: f.service_key.clone(),
    }]);
    let mut server = AuthContext::new();
    let rd = server
        .rd_req(&ap_req, None, &keytab)
        .expect("rd_req against service keytab");
    assert_eq!(rd.ticket.cname, user());
    assert_eq!(rd.ticket.authtime, tgt.times.authtime);
    assert_eq!(rd.authenticator.cname, user());
}

#[tokio::test]
async fn tgs_exchange_endtime_is_capped_by_tgt_endtime() {
    let f = fixture().await;
    let tgt = mint_tgt(
        &f,
        RENEWABLE_TGT,
        at(-60),
        at(-60),
        at(1800),
        Some(at(86400)),
    );
    let cred = plain_tgs(&f, &tgt).await.result.expect("TGS exchange");
    assert_eq!(cred.times.endtime, tgt.times.endtime);
}

#[tokio::test]
async fn tgs_exchange_realm_max_life_caps_service_ticket() {
    let f = fixture_with(FixtureOptions {
        max_life: Some(Duration::from_secs(900)),
        ..FixtureOptions::default()
    })
    .await;
    let tgt = mint_tgt(
        &f,
        RENEWABLE_TGT,
        at(-60),
        at(-60),
        at(7200),
        Some(at(86400)),
    );
    let cred = plain_tgs(&f, &tgt).await.result.expect("TGS exchange");
    let start = cred
        .times
        .starttime
        .unwrap_or(cred.times.authtime)
        .timestamp();
    assert_eq!(cred.times.endtime.timestamp() - start, 900);
}

#[tokio::test]
async fn tgs_exchange_unknown_service_returns_s_principal_unknown() {
    let f = fixture().await;
    let tgt = get_tgt(&f).await;
    let options = TgsOptions {
        canonicalize: false,
        ..TgsOptions::default()
    };
    let run = run_tgs(
        &f.kdc,
        &tgt,
        PrincipalName::new_srv_hst("HTTP", "missing.test.realm"),
        options,
    )
    .await;
    assert_eq!(kdc_code(&run.result.expect_err("must fail")), 7);
    let err = krb_error(run.replies.last().expect("reply"));
    assert_eq!(err.cname.as_ref().map(|n| n.to_string()), Some(USER.into()));
}

#[tokio::test]
async fn tgs_req_tampered_body_returns_bad_integrity() {
    let f = fixture().await;
    let tgt = get_tgt(&f).await;
    let mut spec = TgsReqSpec::new(service(), KdcOptions::FORWARDABLE);
    spec.tamper = Some(|b| b.nonce ^= 1);
    let (req, _) = build_tgs_req(&tgt, spec);
    // MIT comp_cksum (kdc_util.c:136-137) reports a failed verify as
    // KRB5KRB_AP_ERR_BAD_INTEGRITY.
    assert_eq!(tgs_error_code(&f, &req).await, 31);
}

#[tokio::test]
async fn tgs_req_tampered_till_returns_bad_integrity() {
    let f = fixture().await;
    let tgt = get_tgt(&f).await;
    let mut spec = TgsReqSpec::new(service(), KdcOptions::empty());
    spec.tamper = Some(|b| b.till += chrono::Duration::hours(5));
    let (req, _) = build_tgs_req(&tgt, spec);
    assert_eq!(tgs_error_code(&f, &req).await, 31);
}

#[tokio::test]
async fn tgs_req_untampered_hand_built_request_succeeds() {
    let f = fixture().await;
    let tgt = get_tgt(&f).await;
    let (req, subkey) = build_tgs_req(&tgt, TgsReqSpec::new(service(), KdcOptions::FORWARDABLE));
    let (rep, enc) = open_tgs_rep(&f.kdc.handle(&req).await, &subkey);
    assert_eq!(enc.nonce, 0x1234_5678);
    assert_eq!(rep.cname, user());
    assert!(rep.padata.is_none());
    assert_eq!(enc.sname, service());
}

#[tokio::test]
async fn tgs_req_unkeyed_checksum_returns_inapp_cksum() {
    let f = fixture().await;
    let tgt = get_tgt(&f).await;
    let mut spec = TgsReqSpec::new(service(), KdcOptions::empty());
    spec.checksum = Some(Some(Checksum {
        cksumtype: 7,
        checksum: OctetString::from(vec![0u8; 16]),
    }));
    let (req, _) = build_tgs_req(&tgt, spec);
    assert_eq!(tgs_error_code(&f, &req).await, 50);
}

#[tokio::test]
async fn tgs_req_missing_checksum_returns_inapp_cksum() {
    let f = fixture().await;
    let tgt = get_tgt(&f).await;
    let mut spec = TgsReqSpec::new(service(), KdcOptions::empty());
    spec.checksum = Some(None);
    let (req, _) = build_tgs_req(&tgt, spec);
    assert_eq!(tgs_error_code(&f, &req).await, 50);
}

#[tokio::test]
async fn tgs_req_corrupt_ticket_ciphertext_returns_bad_integrity() {
    let f = fixture().await;
    let mut tgt = get_tgt(&f).await;
    let mut cipher = tgt.ticket.enc_part.cipher.to_vec();
    let mid = cipher.len() / 2;
    cipher[mid] ^= 0xFF;
    tgt.ticket.enc_part.cipher = OctetString::from(cipher);
    let (req, _) = build_tgs_req(&tgt, TgsReqSpec::new(service(), KdcOptions::empty()));
    assert_eq!(tgs_error_code(&f, &req).await, 31);
}

#[tokio::test]
async fn tgs_req_expired_tgt_returns_tkt_expired() {
    let f = fixture().await;
    let tgt = mint_tgt(
        &f,
        RENEWABLE_TGT,
        at(-2 * 86400),
        at(-2 * 86400),
        at(-2 * 86400 + 3600),
        None,
    );
    let (req, _) = build_tgs_req(&tgt, TgsReqSpec::new(service(), KdcOptions::empty()));
    assert_eq!(tgs_error_code(&f, &req).await, 32);
}

#[tokio::test]
async fn tgs_req_without_pa_tgs_req_returns_padata_type_nosupp() {
    let f = fixture().await;
    let tgt = get_tgt(&f).await;
    let (req, _) = build_tgs_req(&tgt, TgsReqSpec::new(service(), KdcOptions::empty()));
    let mut decoded: TgsReq = rasn::der::decode(&req).expect("decode");
    decoded.0.padata = None;
    let der = rasn::der::encode(&decoded).expect("encode");
    assert_eq!(tgs_error_code(&f, &der).await, 16);
}

#[tokio::test]
async fn tgs_req_service_ticket_as_header_without_options_returns_not_us() {
    let f = fixture().await;
    let st = mint_ticket(
        &f.service_key,
        service(),
        TicketFlags::empty(),
        at(-60),
        at(-60),
        at(3600),
        None,
    );
    let (req, _) = build_tgs_req(&st, TgsReqSpec::new(service(), KdcOptions::empty()));
    assert_eq!(tgs_error_code(&f, &req).await, 35);
}

#[tokio::test]
async fn tgs_req_unsupported_options_return_badoption() {
    let f = fixture().await;
    let tgt = mint_tgt(
        &f,
        RENEWABLE_TGT | TicketFlags::MAY_POSTDATE | TicketFlags::PROXIABLE,
        at(-60),
        at(-60),
        at(3600),
        Some(at(86400)),
    );
    for opt in [
        KdcOptions::POSTDATED,
        KdcOptions::ALLOW_POSTDATE,
        KdcOptions::VALIDATE,
        KdcOptions::ENC_TKT_IN_SKEY,
        KdcOptions::PROXY,
    ] {
        let mut spec = TgsReqSpec::new(service(), opt);
        if opt == KdcOptions::POSTDATED {
            spec.from = Some(at(600));
        }
        let (req, _) = build_tgs_req(&tgt, spec);
        assert_eq!(tgs_error_code(&f, &req).await, 13, "{opt:?}");
    }
}

#[tokio::test]
async fn tgs_req_forwarded_from_non_forwardable_tgt_returns_badoption() {
    let f = fixture().await;
    let tgt = mint_tgt(
        &f,
        TicketFlags::INITIAL | TicketFlags::PRE_AUTHENT,
        at(-60),
        at(-60),
        at(3600),
        None,
    );
    let (req, _) = build_tgs_req(
        &tgt,
        TgsReqSpec::new(krbtgt(), KdcOptions::FORWARDED | KdcOptions::FORWARDABLE),
    );
    assert_eq!(tgs_error_code(&f, &req).await, 13);
}

#[tokio::test]
async fn tgs_req_forwarded_from_forwardable_tgt_copies_request_addresses() {
    let f = fixture().await;
    let tgt = mint_tgt(
        &f,
        RENEWABLE_TGT,
        at(-60),
        at(-60),
        at(3600),
        Some(at(86400)),
    );
    let addr = HostAddress {
        addr_type: 2,
        address: OctetString::from(vec![192, 0, 2, 7]),
    };
    let mut spec = TgsReqSpec::new(krbtgt(), KdcOptions::FORWARDED | KdcOptions::FORWARDABLE);
    spec.addresses = Some(vec![addr.clone()]);
    let (req, subkey) = build_tgs_req(&tgt, spec);
    let (rep, enc) = open_tgs_rep(&f.kdc.handle(&req).await, &subkey);

    assert!(enc
        .flags
        .contains(TicketFlags::FORWARDED | TicketFlags::FORWARDABLE));
    assert!(!enc.flags.contains(TicketFlags::INITIAL));
    assert_eq!(enc.caddr.as_deref(), Some(&[addr.clone()][..]));
    let part = decrypt_ticket(&f.tgs_key, &rep.ticket).expect("decrypt forwarded TGT");
    assert_eq!(part.caddr.as_deref(), Some(&[addr][..]));
    assert_eq!(part.authtime, tgt.times.authtime);
}

#[tokio::test]
async fn tgs_req_renew_non_renewable_tgt_returns_badoption() {
    let f = fixture().await;
    let tgt = mint_tgt(
        &f,
        TicketFlags::INITIAL | TicketFlags::FORWARDABLE,
        at(-60),
        at(-60),
        at(3600),
        None,
    );
    let (req, _) = build_tgs_req(&tgt, TgsReqSpec::new(krbtgt(), KdcOptions::RENEW));
    assert_eq!(tgs_error_code(&f, &req).await, 13);
}

#[tokio::test]
async fn tgs_req_renew_past_renew_till_returns_tkt_expired() {
    let f = fixture().await;
    let tgt = mint_tgt(
        &f,
        RENEWABLE_TGT,
        at(-7200),
        at(-7200),
        at(3600),
        Some(at(-10)),
    );
    let (req, _) = build_tgs_req(
        &tgt,
        TgsReqSpec::new(krbtgt(), KdcOptions::RENEW | KdcOptions::RENEWABLE),
    );
    assert_eq!(tgs_error_code(&f, &req).await, 32);
}

#[tokio::test]
async fn tgs_req_renew_renewable_tgt_keeps_authtime_and_extends_endtime() {
    let f = fixture().await;
    let authtime = at(-3 * 3600);
    let tgt = mint_tgt(
        &f,
        RENEWABLE_TGT,
        authtime,
        authtime,
        at(3600),
        Some(at(24 * 3600)),
    );
    let (req, subkey) = build_tgs_req(
        &tgt,
        TgsReqSpec::new(krbtgt(), KdcOptions::RENEW | KdcOptions::RENEWABLE),
    );
    let (rep, enc) = open_tgs_rep(&f.kdc.handle(&req).await, &subkey);

    assert_eq!(enc.authtime, authtime);
    // New life = original life (4h) from now, capped by renew_till (24h).
    let expected = Utc::now().timestamp() + 4 * 3600;
    assert!((enc.endtime.timestamp() - expected).abs() <= 5);
    assert!(enc.endtime > tgt.times.endtime);
    assert_eq!(enc.renew_till, tgt.times.renew_till);
    assert!(enc
        .flags
        .contains(TicketFlags::RENEWABLE | TicketFlags::INITIAL));
    assert_eq!(enc.sname, krbtgt());
    let part = decrypt_ticket(&f.tgs_key, &rep.ticket).expect("decrypt renewed TGT");
    assert_eq!(part.cname, user());
    assert_eq!(part.authtime, authtime);
    assert_ne!(part.key.key_bytes(), tgt.session_key.key_bytes());
}

#[tokio::test]
async fn tgs_req_renew_endtime_is_capped_by_renew_till() {
    let f = fixture().await;
    let authtime = at(-3 * 3600);
    let renew_till = at(1800);
    let tgt = mint_tgt(
        &f,
        RENEWABLE_TGT,
        authtime,
        authtime,
        at(600),
        Some(renew_till),
    );
    let (req, subkey) = build_tgs_req(
        &tgt,
        TgsReqSpec::new(krbtgt(), KdcOptions::RENEW | KdcOptions::RENEWABLE),
    );
    let (_, enc) = open_tgs_rep(&f.kdc.handle(&req).await, &subkey);
    assert_eq!(enc.endtime, renew_till);
    // RENEWABLE was requested, so MIT keeps it even though renew_till == endtime.
    assert!(enc.flags.contains(TicketFlags::RENEWABLE));
    assert_eq!(enc.renew_till, Some(renew_till));
}

#[tokio::test]
async fn tgs_req_renew_with_renewable_option_keeps_renewable_and_renew_till() {
    let f = fixture().await;
    let authtime = at(-3600);
    let renew_till = at(24 * 3600);
    let tgt = mint_tgt(
        &f,
        RENEWABLE_TGT,
        authtime,
        authtime,
        at(600),
        Some(renew_till),
    );
    let (req, subkey) = build_tgs_req(
        &tgt,
        TgsReqSpec::new(krbtgt(), KdcOptions::RENEW | KdcOptions::RENEWABLE),
    );
    let (rep, enc) = open_tgs_rep(&f.kdc.handle(&req).await, &subkey);
    assert!(enc.flags.contains(TicketFlags::RENEWABLE));
    assert_eq!(enc.renew_till, Some(renew_till));
    assert_eq!(enc.authtime, authtime);
    assert_ne!(enc.key.key_bytes(), tgt.session_key.key_bytes());
    let part = decrypt_ticket(&f.tgs_key, &rep.ticket).expect("decrypt renewed TGT");
    assert_eq!(part.key.key_bytes(), enc.key.key_bytes());
    assert!(part.flags.contains(TicketFlags::RENEWABLE));
    assert_eq!(part.renew_till, Some(renew_till));
}

#[tokio::test]
async fn tgs_req_renew_without_renewable_option_drops_renewable() {
    let f = fixture().await;
    let authtime = at(-3600);
    let tgt = mint_tgt(
        &f,
        RENEWABLE_TGT,
        authtime,
        authtime,
        at(600),
        Some(at(24 * 3600)),
    );
    let (req, subkey) = build_tgs_req(&tgt, TgsReqSpec::new(krbtgt(), KdcOptions::RENEW));
    let (rep, enc) = open_tgs_rep(&f.kdc.handle(&req).await, &subkey);
    assert!(!enc.flags.contains(TicketFlags::RENEWABLE));
    assert!(enc.renew_till.is_none());
    let part = decrypt_ticket(&f.tgs_key, &rep.ticket).expect("decrypt renewed TGT");
    assert!(!part.flags.contains(TicketFlags::RENEWABLE));
    assert!(part.renew_till.is_none());
}

#[tokio::test]
async fn tgs_req_renew_service_ticket_uses_ticket_as_header() {
    let f = fixture().await;
    let authtime = at(-3600);
    let st = mint_ticket(
        &f.service_key,
        service(),
        TicketFlags::RENEWABLE | TicketFlags::PRE_AUTHENT,
        authtime,
        authtime,
        at(600),
        Some(at(86400)),
    );
    let (req, subkey) = build_tgs_req(
        &st,
        TgsReqSpec::new(service(), KdcOptions::RENEW | KdcOptions::RENEWABLE),
    );
    let (rep, enc) = open_tgs_rep(&f.kdc.handle(&req).await, &subkey);
    assert_eq!(enc.sname, service());
    assert_eq!(enc.authtime, authtime);
    let part = decrypt_ticket(&f.service_key, &rep.ticket).expect("decrypt renewed ticket");
    assert!(part.flags.contains(TicketFlags::PRE_AUTHENT));
}

#[tokio::test]
async fn tgs_req_renew_with_mismatched_server_returns_server_nomatch() {
    let f = fixture().await;
    let tgt = mint_tgt(
        &f,
        RENEWABLE_TGT,
        at(-60),
        at(-60),
        at(3600),
        Some(at(86400)),
    );
    let (req, _) = build_tgs_req(
        &tgt,
        TgsReqSpec::new(service(), KdcOptions::RENEW | KdcOptions::RENEWABLE),
    );
    assert_eq!(tgs_error_code(&f, &req).await, 26);
}

#[tokio::test]
async fn tgs_req_disable_transited_check_is_rejected_by_policy() {
    let f = fixture().await;
    let tgt = get_tgt(&f).await;
    let (req, _) = build_tgs_req(
        &tgt,
        TgsReqSpec::new(service(), KdcOptions::DISABLE_TRANSITED_CHECK),
    );
    assert_eq!(tgs_error_code(&f, &req).await, 12);
}

fn pac_in(part: &EncTicketPart) -> krb5_rs::pac::Pac {
    krb5_rs::pac::ticket_pac(part)
        .expect("parse PAC")
        .expect("PAC present")
}

#[tokio::test]
async fn tgs_req_renew_of_tgt_keeps_a_valid_pac() {
    let f = fixture().await;
    let tgt = get_tgt(&f).await;
    let (req, subkey) = build_tgs_req(
        &tgt,
        TgsReqSpec::new(krbtgt(), KdcOptions::RENEW | KdcOptions::RENEWABLE),
    );
    let (rep, enc) = open_tgs_rep(&f.kdc.handle(&req).await, &subkey);
    assert!(enc.flags.contains(TicketFlags::RENEWABLE));
    let part = decrypt_ticket(&f.tgs_key, &rep.ticket).expect("decrypt renewed TGT");
    let pac = pac_in(&part);
    pac.verify(
        part.authtime.timestamp(),
        Some((&user(), REALM)),
        Some(&f.tgs_key),
        Some(&f.tgs_key),
    )
    .expect("renewed TGT PAC verifies");
}

#[tokio::test]
async fn tgs_req_renew_of_service_ticket_resigns_pac_with_ticket_checksums() {
    let f = fixture().await;
    let tgt = get_tgt(&f).await;
    let svc = plain_tgs(&f, &tgt).await.result.expect("service ticket");
    let (req, subkey) = build_tgs_req(&svc, TgsReqSpec::new(service(), KdcOptions::RENEW));
    let (rep, _) = open_tgs_rep(&f.kdc.handle(&req).await, &subkey);
    let part = decrypt_ticket(&f.service_key, &rep.ticket).expect("decrypt renewed ticket");
    krb5_rs::pac::verify_ticket_pac(&part, &service(), &f.service_key, Some(&f.tgs_key))
        .expect("ticket, server, KDC and full checksums")
        .expect("PAC present");
}
