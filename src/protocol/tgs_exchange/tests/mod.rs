use super::*;
use crate::types::{
    EncKdcRepPart, EncryptedData, EncryptionKey, Flags, KdcRep, KerberosFlags, KerberosTime,
    KrbErrorMsg, LastReqEntry, PrincipalName, TgsReq, Ticket, TicketFlags,
};
use chrono::{FixedOffset, TimeZone, Utc};
use rasn::types::{GeneralString, OctetString};

mod helpers;
use helpers::*;
#[test]
fn test_tgs_options_default() {
    let opts = TgsOptions::default();
    assert!(opts.canonicalize);
    assert!(opts.forwardable);
    assert!(opts.renewable);
    assert_eq!(opts.etypes, vec![18, 17, 20, 19]);
    assert!(opts.pac_options);
}

#[test]
fn test_new_exchange_initial_step_produces_tgs_req() {
    let tgt = make_tgt("EXAMPLE.COM");
    let target = PrincipalName::new_srv_inst("HTTP", "web.example.com");
    let mut exchange = TgsExchange::new(tgt, target, TgsOptions::default());

    let result = exchange.step(&[]).expect("initial step should succeed");
    match result {
        TgsStepResult::SendToKdc { data, realm } => {
            assert_eq!(realm, "EXAMPLE.COM");
            // Should decode as TGS-REQ
            let tgs_req: TgsReq = rasn::der::decode(&data).expect("should decode as TGS-REQ");
            assert_eq!(tgs_req.0.pvno, 5);
            assert_eq!(tgs_req.0.msg_type, 12);
            // Should have PA-TGS-REQ padata
            let padata = tgs_req.0.padata.expect("should have padata");
            assert!(padata.iter().any(|pa| pa.padata_type == PA_TGS_REQ));
            // Nonce should be set
            assert_ne!(tgs_req.0.req_body.nonce, 0);
            // sname should be the target service
            let sname = tgs_req.0.req_body.sname.expect("should have sname");
            assert_eq!(sname.name_string.len(), 2);
            assert_eq!(sname.name_string[0].as_bytes(), b"HTTP");
            assert_eq!(sname.name_string[1].as_bytes(), b"web.example.com");
            // cname should be absent (per TGS-REQ spec)
            assert!(tgs_req.0.req_body.cname.is_none());
            // KDC options should include CANONICALIZE
            let opts_bytes = tgs_req.0.req_body.kdc_options.to_bytes();
            let opts_u32 = u32::from_be_bytes(opts_bytes);
            assert_ne!(opts_u32 & KdcOptions::CANONICALIZE.bits(), 0);
            assert_ne!(opts_u32 & KdcOptions::RENEWABLE.bits(), 0);
            // PA-PAC-OPTIONS should be present (default pac_options=true)
            assert!(
                padata.iter().any(|pa| pa.padata_type == PA_PAC_OPTIONS),
                "PA-PAC-OPTIONS should be present by default"
            );
        }
        _ => panic!("expected SendToKdc on first step"),
    }

    // Subkey should be generated
    assert!(exchange.subkey.is_some());
}

#[test]
fn test_pac_options_disabled_omits_padata() {
    let tgt = make_tgt("EXAMPLE.COM");
    let target = PrincipalName::new_srv_inst("HTTP", "web.example.com");
    let opts = TgsOptions {
        pac_options: false,
        ..TgsOptions::default()
    };
    let mut exchange = TgsExchange::new(tgt, target, opts);

    let result = exchange.step(&[]).expect("initial step");
    match result {
        TgsStepResult::SendToKdc { data, .. } => {
            let tgs_req: TgsReq = rasn::der::decode(&data).expect("decode TGS-REQ");
            let padata = tgs_req.0.padata.expect("should have padata");
            assert!(
                !padata.iter().any(|pa| pa.padata_type == PA_PAC_OPTIONS),
                "PA-PAC-OPTIONS should be absent when disabled"
            );
        }
        _ => panic!("expected SendToKdc"),
    }
}

#[test]
fn test_exchange_empty_reply_rejected() {
    let tgt = make_tgt("EXAMPLE.COM");
    let target = PrincipalName::new_srv_inst("HTTP", "web.example.com");
    let mut exchange = TgsExchange::new(tgt, target, TgsOptions::default());
    let _ = exchange.step(&[]).expect("initial step");

    let result = exchange.step(&[]);
    assert!(matches!(result, Err(Krb5Error::ReplyValidation(_))));
}

#[test]
fn test_exchange_response_too_big_returns_retry() {
    let tgt = make_tgt("EXAMPLE.COM");
    let target = PrincipalName::new_srv_inst("HTTP", "web.example.com");
    let mut exchange = TgsExchange::new(tgt, target, TgsOptions::default());
    let initial = exchange.step(&[]).expect("initial step");

    let original_data = match &initial {
        TgsStepResult::SendToKdc { data, .. } => data.clone(),
        _ => panic!("expected SendToKdc"),
    };

    let error_reply = build_krb_error(KRB_ERR_RESPONSE_TOO_BIG, "EXAMPLE.COM");
    let result = exchange.step(&error_reply).expect("should return RetryTcp");
    match result {
        TgsStepResult::RetryTcp { data, realm } => {
            assert_eq!(realm, "EXAMPLE.COM");
            assert_eq!(data, original_data);
        }
        other => panic!("expected RetryTcp, got: {other:?}"),
    }
}

#[test]
fn test_exchange_s_principal_unknown_falls_back_to_non_referral() {
    let tgt = make_tgt("EXAMPLE.COM");
    let target = PrincipalName::new_srv_inst("HTTP", "web.example.com");
    let mut exchange = TgsExchange::new(tgt, target, TgsOptions::default());
    let _ = exchange.step(&[]).expect("initial step");

    let error_reply = build_krb_error(KDC_ERR_S_PRINCIPAL_UNKNOWN, "EXAMPLE.COM");
    let result = exchange
        .step(&error_reply)
        .expect("should fallback to non-referral");
    match result {
        TgsStepResult::SendToKdc { data, realm } => {
            assert_eq!(realm, "EXAMPLE.COM");
            // The new TGS-REQ should NOT have CANONICALIZE flag
            let tgs_req: TgsReq = rasn::der::decode(&data).expect("decode TGS-REQ");
            let opts_bytes = tgs_req.0.req_body.kdc_options.to_bytes();
            let opts_u32 = u32::from_be_bytes(opts_bytes);
            assert_eq!(opts_u32 & KdcOptions::CANONICALIZE.bits(), 0);
        }
        _ => panic!("expected SendToKdc"),
    }
}

#[test]
fn test_exchange_s_principal_unknown_no_double_fallback() {
    let tgt = make_tgt("EXAMPLE.COM");
    let target = PrincipalName::new_srv_inst("HTTP", "web.example.com");
    let mut exchange = TgsExchange::new(tgt, target, TgsOptions::default());
    let _ = exchange.step(&[]).expect("initial step");

    // First S_PRINCIPAL_UNKNOWN → falls back
    let error_reply = build_krb_error(KDC_ERR_S_PRINCIPAL_UNKNOWN, "EXAMPLE.COM");
    let _ = exchange.step(&error_reply).expect("fallback");

    // Second S_PRINCIPAL_UNKNOWN → should propagate as error
    let result = exchange.step(&error_reply);
    assert!(matches!(result, Err(Krb5Error::KdcError(_))));
}

#[test]
fn test_exchange_kdc_error_propagated() {
    let tgt = make_tgt("EXAMPLE.COM");
    let target = PrincipalName::new_srv_inst("HTTP", "web.example.com");
    let mut exchange = TgsExchange::new(tgt, target, TgsOptions::default());
    let _ = exchange.step(&[]).expect("initial step");

    // Generic error should propagate
    let error_reply = build_krb_error(60, "EXAMPLE.COM"); // Generic
    let result = exchange.step(&error_reply);
    match result {
        Err(Krb5Error::KdcError(err)) => {
            assert_eq!(err.error_code, 60);
        }
        other => panic!("expected KdcError, got: {other:?}"),
    }
}

#[test]
fn test_non_canonicalize_mode() {
    let tgt = make_tgt("EXAMPLE.COM");
    let target = PrincipalName::new_srv_inst("HTTP", "web.example.com");
    let opts = TgsOptions {
        canonicalize: false,
        ..TgsOptions::default()
    };
    let mut exchange = TgsExchange::new(tgt, target, opts);

    let result = exchange.step(&[]).expect("initial step");
    match result {
        TgsStepResult::SendToKdc { data, .. } => {
            let tgs_req: TgsReq = rasn::der::decode(&data).expect("decode TGS-REQ");
            let opts_bytes = tgs_req.0.req_body.kdc_options.to_bytes();
            let opts_u32 = u32::from_be_bytes(opts_bytes);
            // CANONICALIZE should NOT be set
            assert_eq!(opts_u32 & KdcOptions::CANONICALIZE.bits(), 0);
        }
        _ => panic!("expected SendToKdc"),
    }
}

#[test]
fn test_validate_nonce_mismatch() {
    let tgt = make_tgt("EXAMPLE.COM");
    let target = PrincipalName::new_srv_inst("HTTP", "web.example.com");
    let exchange = TgsExchange::new(tgt, target, TgsOptions::default());

    let now = make_time(1_700_000_000);
    let enc_part = EncKdcRepPart {
        key: make_enc_key(18, 32),
        last_req: vec![LastReqEntry {
            lr_type: 0,
            lr_value: now,
        }],
        nonce: 99999, // wrong nonce
        key_expiration: None,
        flags: KerberosFlags::new(TicketFlags::FORWARDABLE),
        authtime: now,
        starttime: Some(now),
        endtime: make_time(1_700_036_000),
        renew_till: None,
        srealm: make_realm("EXAMPLE.COM"),
        sname: PrincipalName::new_srv_inst("HTTP", "web.example.com"),
        caddr: None,
        encrypted_pa_data: None,
    };

    let rep = KdcRep {
        pvno: 5,
        msg_type: 13,
        padata: None,
        crealm: make_realm("EXAMPLE.COM"),
        cname: PrincipalName::new_principal("user"),
        ticket: Ticket {
            tkt_vno: 5,
            realm: make_realm("EXAMPLE.COM"),
            sname: PrincipalName::new_srv_inst("HTTP", "web.example.com"),
            enc_part: EncryptedData {
                etype: 18,
                kvno: Some(1),
                cipher: OctetString::from(vec![0u8; 32]),
            },
        },
        enc_part: EncryptedData {
            etype: 18,
            kvno: None,
            cipher: OctetString::from(vec![0u8; 32]),
        },
    };

    let result = exchange.validate_tgs_reply(&rep, &enc_part);
    assert!(matches!(
        result,
        Err(Krb5Error::ReplyValidation("nonce mismatch"))
    ));
}

#[test]
fn test_is_referral_tgt() {
    let tgt = make_tgt("EXAMPLE.COM");
    let target = PrincipalName::new_srv_inst("HTTP", "web.example.com");
    let exchange = TgsExchange::new(tgt, target, TgsOptions::default());

    let now = make_time(1_700_000_000);

    // Referral TGT (krbtgt/OTHER.COM)
    let referral_enc = EncKdcRepPart {
        key: make_enc_key(18, 32),
        last_req: vec![],
        nonce: 0,
        key_expiration: None,
        flags: KerberosFlags::new(TicketFlags::FORWARDABLE),
        authtime: now,
        starttime: None,
        endtime: make_time(1_700_036_000),
        renew_till: None,
        srealm: make_realm("EXAMPLE.COM"),
        sname: PrincipalName::new_srv_inst("krbtgt", "OTHER.COM"),
        caddr: None,
        encrypted_pa_data: None,
    };
    assert!(exchange.is_referral_tgt(&referral_enc));

    // Service ticket (HTTP/web.example.com)
    let service_enc = EncKdcRepPart {
        sname: PrincipalName::new_srv_inst("HTTP", "web.example.com"),
        ..referral_enc
    };
    assert!(!exchange.is_referral_tgt(&service_enc));
}

#[test]
fn test_referral_loop_detection() {
    let tgt = make_tgt("EXAMPLE.COM");
    let target = PrincipalName::new_srv_inst("HTTP", "web.other.com");
    let mut exchange = TgsExchange::new(tgt, target, TgsOptions::default());

    let now = make_time(1_700_000_000);
    let rep = make_referral_rep("EXAMPLE.COM");
    let enc_part = make_referral_enc_part(
        "EXAMPLE.COM",
        now,
        KerberosFlags::new(TicketFlags::FORWARDABLE),
    );

    // Simulate referral back to EXAMPLE.COM (already seen)
    let resume = ResumeState::Referrals {
        realms_seen: vec!["EXAMPLE.COM".to_string()],
        referral_count: 1,
    };

    let result = exchange.handle_referral(&rep, &enc_part, resume);
    assert!(matches!(result, Err(Krb5Error::ReferralLoop { .. })));
}

#[test]
fn test_referral_limit_exceeded() {
    let tgt = make_tgt("EXAMPLE.COM");
    let target = PrincipalName::new_srv_inst("HTTP", "web.example.com");
    let mut exchange = TgsExchange::new(tgt, target, TgsOptions::default());

    let now = make_time(1_700_000_000);
    let rep = make_referral_rep("REALM-11");
    let enc_part = make_referral_enc_part(
        "REALM-11",
        now,
        KerberosFlags::new(TicketFlags::FORWARDABLE),
    );

    let resume = ResumeState::Referrals {
        realms_seen: (0..10).map(|i| format!("REALM-{i}")).collect(),
        referral_count: MAX_REFERRAL_HOPS,
    };

    let result = exchange.handle_referral(&rep, &enc_part, resume);
    assert!(matches!(
        result,
        Err(Krb5Error::ReferralLimitExceeded(MAX_REFERRAL_HOPS))
    ));
}

#[test]
fn test_ok_as_delegate_stripped_when_cross_realm_tgt_lacks_it() {
    // When cur_tgt does NOT have OK_AS_DELEGATE, the referral TGT's
    // OK_AS_DELEGATE should be stripped.
    let tgt = make_tgt("EXAMPLE.COM");
    // Verify our test TGT does NOT have OK_AS_DELEGATE
    assert!(!tgt.flags.contains(TicketFlags::OK_AS_DELEGATE));

    let target = PrincipalName::new_srv_inst("HTTP", "web.other.com");
    let mut exchange = TgsExchange::new(tgt, target, TgsOptions::default());

    let now = make_time(1_700_000_000);
    let rep = make_referral_rep("OTHER.COM");

    // Referral TGT has OK_AS_DELEGATE set by the foreign KDC
    let enc_part = make_referral_enc_part(
        "OTHER.COM",
        now,
        KerberosFlags::new(TicketFlags::FORWARDABLE | TicketFlags::OK_AS_DELEGATE),
    );

    let resume = ResumeState::Referrals {
        realms_seen: vec!["EXAMPLE.COM".to_string()],
        referral_count: 0,
    };

    // handle_referral should strip OK_AS_DELEGATE from cur_tgt
    exchange
        .handle_referral(&rep, &enc_part, resume)
        .expect("handle_referral should succeed");
    // After referral handling, cur_tgt should NOT have OK_AS_DELEGATE
    assert!(
        !exchange.cur_tgt.flags.contains(TicketFlags::OK_AS_DELEGATE),
        "OK_AS_DELEGATE should be stripped from referral TGT when cross-realm TGT lacks it"
    );
}

#[test]
fn test_ok_as_delegate_preserved_when_cross_realm_tgt_has_it() {
    // When cur_tgt HAS OK_AS_DELEGATE, the referral TGT should keep it.
    let mut tgt = make_tgt("EXAMPLE.COM");
    *tgt.flags |= TicketFlags::OK_AS_DELEGATE;

    let target = PrincipalName::new_srv_inst("HTTP", "web.other.com");
    let mut exchange = TgsExchange::new(tgt, target, TgsOptions::default());

    let now = make_time(1_700_000_000);
    let rep = make_referral_rep("OTHER.COM");

    let enc_part = make_referral_enc_part(
        "OTHER.COM",
        now,
        KerberosFlags::new(TicketFlags::FORWARDABLE | TicketFlags::OK_AS_DELEGATE),
    );

    let resume = ResumeState::Referrals {
        realms_seen: vec!["EXAMPLE.COM".to_string()],
        referral_count: 0,
    };

    exchange
        .handle_referral(&rep, &enc_part, resume)
        .expect("handle_referral should succeed");
    assert!(
        exchange.cur_tgt.flags.contains(TicketFlags::OK_AS_DELEGATE),
        "OK_AS_DELEGATE should be preserved when cross-realm TGT also has it"
    );
}
