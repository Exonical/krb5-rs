//! AS exchange against the KDC (do_as_req.c, kdc_preauth.c).

use super::*;

fn assert_authoritative_error(run: Run<Credential>, code: i32, status: &str) {
    assert!(run.result.is_err(), "request unexpectedly succeeded");
    let error = krb_error(run.replies.last().expect("KRB-ERROR reply"));
    assert_eq!(error.error_code, code);
    assert_eq!(
        error.e_text.as_ref().map(|text| text.as_bytes()),
        Some(status.as_bytes())
    );
}

fn flags_of(c: &Credential) -> TicketFlags {
    *c.flags
}

#[tokio::test]
async fn as_exchange_preauth_user_completes_after_preauth_required() {
    let f = fixture().await;
    let run = run_as(&f.kdc, as_config(USER), PASSWORD).await;
    let cred = run.result.expect("AS exchange completes");

    assert_eq!(run.replies.len(), 2);
    let err = krb_error(&run.replies[0]);
    assert_eq!(err.error_code, 25);
    assert_eq!(err.stime.timestamp() / 60, Utc::now().timestamp() / 60);
    assert!(err.ctime.is_none() && err.cusec.is_none());
    assert_eq!(err.realm.as_bytes(), REALM.as_bytes());
    assert_eq!(err.cname.as_ref().map(|n| n.to_string()), Some(USER.into()));

    // MIT hint order: PA-ETYPE-INFO2 then an empty PA-ENC-TIMESTAMP.
    let hints = method_data(&err);
    let types: Vec<i32> = hints.iter().map(|p| p.padata_type).collect();
    assert_eq!(types, vec![136, 19, 2, 133]);
    assert!(hints[0].padata_value.is_empty());
    assert!(hints[2].padata_value.is_empty());
    assert_eq!(hints[3].padata_value.as_ref(), b"MIT");
    let info: Vec<EtypeInfo2Entry> =
        rasn::der::decode(hints[1].padata_value.as_ref()).expect("ETYPE-INFO2");
    assert_eq!(info.len(), 1);
    assert_eq!(info[0].etype, 18);
    assert_eq!(
        info[0].salt.as_ref().map(|s| s.as_bytes().to_vec()),
        Some(format!("{REALM}{USER}").into_bytes())
    );

    let flags = flags_of(&cred);
    assert!(flags.contains(
        TicketFlags::INITIAL
            | TicketFlags::PRE_AUTHENT
            | TicketFlags::FORWARDABLE
            | TicketFlags::RENEWABLE
    ));
    assert!(flags.contains(TicketFlags::ENC_PA_REP));
}

#[tokio::test]
async fn as_exchange_ticket_decrypts_with_krbtgt_key_and_matches_credential() {
    let f = fixture().await;
    let cred = get_tgt(&f).await;
    let part = decrypt_ticket(&f.tgs_key, &cred.ticket).expect("decrypt ticket");
    assert_eq!(part.cname, user());
    assert_eq!(part.crealm.as_bytes(), REALM.as_bytes());
    assert_eq!(part.key.key_bytes(), cred.session_key.key_bytes());
    assert_eq!(part.authtime, cred.times.authtime);
    assert_eq!(part.endtime, cred.times.endtime);
    assert!(part.transited.contents.is_empty());
    assert_eq!(cred.ticket.enc_part.kvno, Some(1));
    assert_eq!(cred.ticket.sname, krbtgt());
}

#[tokio::test]
async fn as_exchange_asrep_carries_etype_info2_for_reply_key() {
    let f = fixture().await;
    let run = run_as(&f.kdc, as_config(USER), PASSWORD).await;
    run.result.expect("AS exchange");
    let rep: AsRep = rasn::der::decode(run.replies.last().expect("reply")).expect("AS-REP");
    let padata = rep.0.padata.expect("AS-REP padata");
    assert_eq!(padata.len(), 1);
    assert_eq!(padata[0].padata_type, 19);
    assert!(rep.0.enc_part.kvno.is_none());
}

#[tokio::test]
async fn as_exchange_wrong_password_surfaces_preauth_failed() {
    let f = fixture().await;
    let run = run_as(&f.kdc, as_config(USER), "not-the-password").await;
    let code = kdc_code(&run.result.expect_err("must fail"));
    assert_eq!(code, 24);
    let failed = krb_error(run.replies.last().expect("reply"));
    assert_eq!(failed.error_code, 24);
    let types: Vec<i32> = method_data(&failed).iter().map(|p| p.padata_type).collect();
    assert_eq!(types, vec![136, 19, 2, 133]);
}

#[tokio::test]
async fn as_req_timestamp_outside_clockskew_returns_skew_error() {
    let f = fixture().await;
    let req = build_as_req(
        USER,
        KdcOptions::FORWARDABLE,
        vec![18],
        vec![enc_timestamp_padata(USER, PASSWORD, at(-3600))],
    );
    let err = krb_error(&f.kdc.handle(&req).await);
    assert_eq!(err.error_code, 37);
}

#[tokio::test]
async fn authoritative_client_disable_returns_client_revoked() {
    let f = fixture_with_gate(
        FixtureOptions::default(),
        DenyGate::new(0, 0, AuthoritativeDenial::Disabled),
    )
    .await;

    assert_authoritative_error(
        run_as(&f.kdc, as_config(USER), PASSWORD).await,
        18,
        "AUTHORITATIVE_CLIENT_DISABLED",
    );
}

#[tokio::test]
async fn authoritative_server_disable_returns_server_unknown() {
    let f = fixture_with_gate(
        FixtureOptions::default(),
        DenyGate::new(0, 1, AuthoritativeDenial::Disabled),
    )
    .await;

    assert_authoritative_error(
        run_as(&f.kdc, as_config(USER), PASSWORD).await,
        7,
        "AUTHORITATIVE_SERVER_DISABLED",
    );
}

#[tokio::test]
async fn authoritative_client_deletion_returns_client_unknown() {
    let f = fixture_with_gate(
        FixtureOptions::default(),
        DenyGate::new(0, 0, AuthoritativeDenial::Deleted),
    )
    .await;

    assert_authoritative_error(
        run_as(&f.kdc, as_config(USER), PASSWORD).await,
        6,
        "AUTHORITATIVE_CLIENT_DELETED",
    );
}

#[tokio::test]
async fn as_req_timestamp_shifted_clock_returns_skew_error() {
    let f = fixture().await;
    let req = build_as_req(
        USER,
        KdcOptions::FORWARDABLE,
        vec![18],
        vec![enc_timestamp_padata(USER, PASSWORD, at(0))],
    );
    let later = Utc::now() + chrono::Duration::hours(1);
    let err = krb_error(&f.kdc.handle_at(&req, later).await);
    assert_eq!(err.error_code, 37);
}

#[tokio::test]
async fn as_req_valid_timestamp_without_requirement_sets_pre_authent() {
    let f = fixture().await;
    let req = build_as_req(
        "norenew",
        KdcOptions::empty(),
        vec![18],
        vec![enc_timestamp_padata("norenew", PASSWORD, at(0))],
    );
    let rep: AsRep = rasn::der::decode(&f.kdc.handle(&req).await).expect("AS-REP");
    let part = decrypt_ticket(&f.tgs_key, &rep.0.ticket).expect("ticket");
    assert!(part.flags.contains(TicketFlags::PRE_AUTHENT));
}

#[tokio::test]
async fn as_req_bad_timestamp_without_requirement_is_still_rejected() {
    let f = fixture().await;
    let req = build_as_req(
        "norenew",
        KdcOptions::empty(),
        vec![18],
        vec![enc_timestamp_padata("norenew", "wrong", at(0))],
    );
    assert_eq!(krb_error(&f.kdc.handle(&req).await).error_code, 24);
}

#[tokio::test]
async fn as_exchange_unknown_client_returns_c_principal_unknown() {
    let f = fixture().await;
    let run = run_as(&f.kdc, as_config("nobody"), "x").await;
    assert_eq!(kdc_code(&run.result.expect_err("must fail")), 6);
}

#[tokio::test]
async fn as_exchange_unsupported_etype_returns_etype_nosupp() {
    let f = fixture().await;
    let mut config = as_config(USER);
    config.etypes = vec![23];
    let run = run_as(&f.kdc, config, PASSWORD).await;
    assert_eq!(kdc_code(&run.result.expect_err("must fail")), 14);
}

#[tokio::test]
async fn as_exchange_sha2_user_gets_etype_20_reply_key() {
    let f = fixture().await;
    let run = run_as(&f.kdc, as_config(SHA2_USER), SHA2_PASSWORD).await;
    let cred = run.result.expect("AS exchange");
    let rep: AsRep = rasn::der::decode(run.replies.last().expect("reply")).expect("AS-REP");
    assert_eq!(rep.0.enc_part.etype, 20);
    // MIT select_session_keytype: aes256-sha1 is assumed supported by the
    // krbtgt, so the first requested etype (18) wins the session key.
    assert_eq!(cred.session_key.keytype, 18);
}

#[tokio::test]
async fn as_exchange_sha2_only_request_without_krbtgt_sha2_key_is_etype_nosupp() {
    let f = fixture().await;
    let mut config = as_config(SHA2_USER);
    config.etypes = vec![20, 19];
    let run = run_as(&f.kdc, config, SHA2_PASSWORD).await;
    assert_eq!(kdc_code(&run.result.expect_err("must fail")), 14);
}

#[tokio::test]
async fn as_exchange_sha2_krbtgt_gives_etype_20_session_and_reply_key() {
    let f = fixture_with(FixtureOptions {
        krbtgt_etypes: Some(vec![18, 17, 20, 19]),
        ..FixtureOptions::default()
    })
    .await;
    let mut config = as_config(SHA2_USER);
    config.etypes = vec![20, 19];
    let run = run_as(&f.kdc, config, SHA2_PASSWORD).await;
    let cred = run.result.expect("AS exchange");
    let rep: AsRep = rasn::der::decode(run.replies.last().expect("reply")).expect("AS-REP");
    assert_eq!(rep.0.enc_part.etype, 20);
    assert_eq!(cred.session_key.keytype, 20);
    // The ticket is encrypted with the first (highest-kvno) krbtgt key.
    assert_eq!(cred.ticket.enc_part.etype, 18);
}

#[tokio::test]
async fn as_exchange_realm_max_life_caps_endtime() {
    let f = fixture_with(FixtureOptions {
        max_life: Some(Duration::from_secs(3600)),
        ..FixtureOptions::default()
    })
    .await;
    let cred = get_tgt(&f).await;
    let secs = cred.times.endtime.timestamp() - cred.times.authtime.timestamp();
    assert_eq!(secs, 3600);
}

#[tokio::test]
async fn as_exchange_default_request_keeps_ten_hour_life_and_seven_day_renew() {
    let f = fixture().await;
    let cred = get_tgt(&f).await;
    let auth = cred.times.authtime.timestamp();
    assert_eq!(cred.times.endtime.timestamp() - auth, 10 * 3600);
    let renew = cred.times.renew_till.expect("renew_till");
    assert_eq!(renew.timestamp() - auth, 7 * 24 * 3600);
}

#[tokio::test]
async fn as_exchange_realm_max_renewable_life_caps_renew_till() {
    let f = fixture_with(FixtureOptions {
        max_renewable_life: Some(Duration::from_secs(2 * 24 * 3600)),
        ..FixtureOptions::default()
    })
    .await;
    let cred = get_tgt(&f).await;
    let renew = cred.times.renew_till.expect("renew_till");
    assert_eq!(
        renew.timestamp() - cred.times.authtime.timestamp(),
        2 * 24 * 3600
    );
}

#[tokio::test]
async fn as_exchange_zero_realm_renewable_life_sets_renewable_with_renew_till_at_start() {
    let f = fixture_with(FixtureOptions {
        max_renewable_life: Some(Duration::ZERO),
        ..FixtureOptions::default()
    })
    .await;
    let cred = get_tgt(&f).await;
    assert!(flags_of(&cred).contains(TicketFlags::RENEWABLE));
    assert_eq!(cred.times.renew_till, Some(cred.times.authtime));
}

#[tokio::test]
async fn as_exchange_disallow_renewable_client_gets_no_renewable_flag() {
    let f = fixture().await;
    let run = run_as(&f.kdc, as_config("norenew"), PASSWORD).await;
    let cred = run.result.expect("AS exchange");
    assert!(!flags_of(&cred).contains(TicketFlags::RENEWABLE));
    assert!(cred.times.renew_till.is_none());
    assert!(flags_of(&cred).contains(TicketFlags::INITIAL));
}

#[tokio::test]
async fn as_exchange_disallow_forwardable_client_gets_no_forwardable_flag() {
    let f = fixture().await;
    let cred = run_as(&f.kdc, as_config("nofwd"), PASSWORD)
        .await
        .result
        .expect("AS exchange");
    assert!(!flags_of(&cred).contains(TicketFlags::FORWARDABLE));
}

#[tokio::test]
async fn as_exchange_wrong_realm_returns_wrong_realm() {
    let f = fixture().await;
    let config = AsExchangeConfig::new(PrincipalName::new_principal(USER), "OTHER.REALM");
    let run = run_as(&f.kdc, config, PASSWORD).await;
    assert_eq!(kdc_code(&run.result.expect_err("must fail")), 68);
}

#[tokio::test]
async fn as_req_unsupported_options_return_badoption() {
    let f = fixture().await;
    for opt in [
        KdcOptions::POSTDATED,
        KdcOptions::ALLOW_POSTDATE,
        KdcOptions::VALIDATE,
        KdcOptions::ENC_TKT_IN_SKEY,
        KdcOptions::PROXY,
        KdcOptions::RENEW,
        KdcOptions::FORWARDED,
    ] {
        let req = build_as_req(SHA2_USER, opt, vec![20], vec![]);
        let err = krb_error(&f.kdc.handle(&req).await);
        assert_eq!(err.error_code, 13, "{opt:?}");
    }
}

#[tokio::test]
async fn as_req_unknown_service_returns_s_principal_unknown() {
    let f = fixture().await;
    // Request for a non-krbtgt server through a hand-built request.
    let mut req = rasn::der::decode::<AsReq>(&build_as_req(
        SHA2_USER,
        KdcOptions::empty(),
        vec![20],
        vec![],
    ))
    .expect("decode");
    req.0.req_body.sname = Some(PrincipalName::new_srv_hst("nosuch", "host.test.realm"));
    let der = rasn::der::encode(&req).expect("encode");
    assert_eq!(krb_error(&f.kdc.handle(&der).await).error_code, 7);
}
