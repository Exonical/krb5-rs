use super::*;
use crate::types::AsReq;

#[test]
fn test_config_defaults() {
    let config = AsExchangeConfig::new(PrincipalName::new_principal("user"), "EXAMPLE.COM");
    assert_eq!(config.realm, "EXAMPLE.COM");
    assert_eq!(config.etypes, vec![18, 17, 20, 19]);
    assert!(config.kdc_options.contains(KdcOptions::FORWARDABLE));
    assert!(config.kdc_options.contains(KdcOptions::RENEWABLE));
    assert!(config.kdc_options.contains(KdcOptions::CANONICALIZE));
    assert!(config.request_pac);
    assert_eq!(config.tkt_lifetime, Duration::from_secs(36000));
    assert_eq!(config.renew_lifetime, Duration::from_secs(604800));
}

#[test]
fn test_config_no_pac() {
    let config = AsExchangeConfig::new_no_pac(PrincipalName::new_principal("user"), "EXAMPLE.COM");
    assert!(!config.request_pac);
}

#[test]
fn test_exchange_initial_step_produces_as_req() {
    let config = AsExchangeConfig::new(PrincipalName::new_principal("testuser"), "EXAMPLE.COM");
    let mut exchange = AsExchange::new(config, "password");

    let result = exchange.step(&[]).expect("initial step should succeed");
    match result {
        StepResult::SendToKdc { data, realm } => {
            assert_eq!(realm, "EXAMPLE.COM");
            // Should be a valid AS-REQ
            let as_req: AsReq = rasn::der::decode(&data).expect("should decode as AS-REQ");
            assert_eq!(as_req.0.pvno, 5);
            assert_eq!(as_req.0.msg_type, 10);
            assert_eq!(
                as_req.0.req_body.realm,
                GeneralString::from_bytes(b"EXAMPLE.COM").expect("realm")
            );
            // Should have PA-PAC-REQUEST in padata
            let padata = as_req.0.padata.expect("should have padata");
            assert!(padata
                .iter()
                .any(|pa| pa.padata_type == PaDataType::PaPacRequest as i32));
            // Nonce should be set
            assert_ne!(as_req.0.req_body.nonce, 0);
            // Etypes should match config
            assert_eq!(as_req.0.req_body.etype, vec![18, 17, 20, 19]);
        }
        StepResult::Complete | StepResult::RetryTcp { .. } => {
            panic!("should not be complete or retry on first step")
        }
    }
}

#[test]
fn test_exchange_preauth_required_produces_enc_timestamp() {
    let config = AsExchangeConfig::new(PrincipalName::new_principal("testuser"), "EXAMPLE.COM");
    let mut exchange = AsExchange::new(config, "password");

    // Initial step
    let _result = exchange.step(&[]).expect("initial step");

    // Build a PREAUTH_REQUIRED error response
    let error_reply = build_preauth_required_error();
    let result = exchange
        .step(&error_reply)
        .expect("should handle PREAUTH_REQUIRED");

    match result {
        StepResult::SendToKdc { data, realm } => {
            assert_eq!(realm, "EXAMPLE.COM");
            // Should be an AS-REQ with PA-ENC-TIMESTAMP
            let as_req: AsReq = rasn::der::decode(&data).expect("should decode as AS-REQ");
            let padata = as_req.0.padata.expect("should have padata");
            assert!(padata
                .iter()
                .any(|pa| pa.padata_type == PaDataType::EncTimestamp as i32));
        }
        StepResult::Complete | StepResult::RetryTcp { .. } => {
            panic!("should not be complete or retry after preauth required")
        }
    }
}

#[test]
fn test_exchange_loop_count_exceeded() {
    let config = AsExchangeConfig::new(PrincipalName::new_principal("testuser"), "EXAMPLE.COM");
    let mut exchange = AsExchange::new(config, "password");
    // Set initial step so we're in AwaitReply
    let _result = exchange.step(&[]).expect("initial step");
    exchange.loop_count = MAX_PREAUTH_LOOPS;

    let error_reply = build_preauth_required_error();
    let result = exchange.step(&error_reply);
    assert!(matches!(result, Err(Krb5Error::PreauthLoopExceeded(_))));
}

#[test]
fn test_exchange_empty_reply_rejected() {
    let config = AsExchangeConfig::new(PrincipalName::new_principal("testuser"), "EXAMPLE.COM");
    let mut exchange = AsExchange::new(config, "password");
    let _result = exchange.step(&[]).expect("initial step");

    let result = exchange.step(&[]);
    assert!(matches!(result, Err(Krb5Error::ReplyValidation(_))));
}

#[test]
fn test_exchange_response_too_big_returns_retry_tcp() {
    let config = AsExchangeConfig::new(PrincipalName::new_principal("testuser"), "EXAMPLE.COM");
    let mut exchange = AsExchange::new(config, "password");
    let initial = exchange.step(&[]).expect("initial step");

    // Capture the original request bytes
    let original_data = match &initial {
        StepResult::SendToKdc { data, .. } => data.clone(),
        _ => panic!("expected SendToKdc"),
    };

    let error_reply = build_krb_error(KRB_ERR_RESPONSE_TOO_BIG, None);
    let result = exchange.step(&error_reply).expect("should return RetryTcp");
    match result {
        StepResult::RetryTcp { data, realm } => {
            assert_eq!(realm, "EXAMPLE.COM");
            // RetryTcp should re-emit the exact same request bytes
            assert_eq!(data, original_data);
        }
        other => panic!("expected RetryTcp, got: {other:?}"),
    }
}

#[test]
fn test_exchange_wrong_realm_redirects() {
    let config = AsExchangeConfig::new(PrincipalName::new_principal("testuser"), "EXAMPLE.COM");
    let mut exchange = AsExchange::new(config, "password");
    let _result = exchange.step(&[]).expect("initial step");

    let error_reply = build_krb_error(KDC_ERR_WRONG_REALM, Some("OTHER.REALM"));
    let result = exchange.step(&error_reply).expect("should redirect");
    match result {
        StepResult::SendToKdc { realm, data } => {
            assert_eq!(realm, "OTHER.REALM");
            // Verify the new AS-REQ targets the new realm
            let as_req: AsReq = rasn::der::decode(&data).expect("decode AS-REQ");
            assert_eq!(
                as_req.0.req_body.realm,
                GeneralString::from_bytes(b"OTHER.REALM").expect("realm")
            );
        }
        StepResult::Complete | StepResult::RetryTcp { .. } => {
            panic!("should redirect, not complete or retry")
        }
    }
    assert_eq!(exchange.config.realm, "OTHER.REALM");
}

#[test]
fn test_exchange_wrong_realm_same_realm_propagates() {
    let config = AsExchangeConfig::new(PrincipalName::new_principal("testuser"), "EXAMPLE.COM");
    let mut exchange = AsExchange::new(config, "password");
    let _result = exchange.step(&[]).expect("initial step");

    // WRONG_REALM but crealm == current realm → propagate error
    let error_reply = build_krb_error(KDC_ERR_WRONG_REALM, Some("EXAMPLE.COM"));
    let result = exchange.step(&error_reply);
    assert!(matches!(result, Err(Krb5Error::KdcError(_))));
}

#[test]
fn test_exchange_kdc_error_propagated() {
    let config = AsExchangeConfig::new(PrincipalName::new_principal("testuser"), "EXAMPLE.COM");
    let mut exchange = AsExchange::new(config, "password");
    let _result = exchange.step(&[]).expect("initial step");

    // C_PRINCIPAL_UNKNOWN (6)
    let error_reply = build_krb_error(6, None);
    let result = exchange.step(&error_reply);
    match result {
        Err(Krb5Error::KdcError(err)) => {
            assert_eq!(err.error_code, 6);
        }
        other => panic!("expected KdcError, got: {other:?}"),
    }
}

/// Helper: build a DER-encoded KRB-ERROR with the given error code.
/// Build a KRB-ERROR. `server_realm` sets the mandatory `realm` field
/// (used for WRONG_REALM redirect target).
fn build_krb_error(error_code: i32, server_realm: Option<&str>) -> Vec<u8> {
    let realm_str = server_realm.unwrap_or("EXAMPLE.COM");
    let now = now_kerberos();
    let krb_error = KrbErrorMsg {
        pvno: 5,
        msg_type: 30,
        ctime: None,
        cusec: None,
        stime: now,
        susec: 0,
        error_code,
        crealm: None,
        cname: None,
        realm: GeneralString::from_bytes(realm_str.as_bytes()).expect("realm"),
        sname: PrincipalName::new_srv_inst("krbtgt", realm_str),
        e_text: None,
        e_data: None,
    };
    rasn::der::encode(&krb_error).expect("encode KRB-ERROR")
}

/// Helper: build a DER-encoded KRB-ERROR with PREAUTH_REQUIRED and PA-ETYPE-INFO2.
fn build_preauth_required_error() -> Vec<u8> {
    use crate::types::EtypeInfo2Entry;

    let entries = vec![EtypeInfo2Entry {
        etype: 18,
        salt: Some(GeneralString::from_bytes(b"EXAMPLE.COMtestuser").expect("salt")),
        s2kparams: None,
    }];
    let etype_info2_der = rasn::der::encode(&entries).expect("encode ETYPE-INFO2");

    let method_data = vec![
        PaData {
            padata_type: PaDataType::EtypeInfo2 as i32,
            padata_value: etype_info2_der.into(),
        },
        // A real KDC offers PA-ENC-TIMESTAMP in METHOD-DATA; MIT's
        // client only answers a real preauth type it was offered.
        PaData {
            padata_type: PaDataType::EncTimestamp as i32,
            padata_value: rasn::types::OctetString::from(Vec::new()),
        },
    ];
    let e_data = rasn::der::encode(&method_data).expect("encode METHOD-DATA");

    let now = now_kerberos();
    let krb_error = KrbErrorMsg {
        pvno: 5,
        msg_type: 30,
        ctime: None,
        cusec: None,
        stime: now,
        susec: 0,
        error_code: KDC_ERR_PREAUTH_REQUIRED,
        crealm: None,
        cname: None,
        realm: GeneralString::from_bytes(b"EXAMPLE.COM").expect("realm"),
        sname: PrincipalName::new_srv_inst("krbtgt", "EXAMPLE.COM"),
        e_text: None,
        e_data: Some(e_data.into()),
    };
    rasn::der::encode(&krb_error).expect("encode KRB-ERROR")
}
