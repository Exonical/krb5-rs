//! Integration tests for the AS exchange against a real MIT KDC.
//!
//! These tests require a running KDC container:
//!   docker compose -f docker-compose.test.yml up -d
//!
//! Run with:
//!   cargo test --test as_exchange_integration -- --ignored
//!
//! The KDC listens on ${KDC_HOST}:10188 with realm TEST.REALM.
//! Set KDC_HOST when the KDC is not on localhost (default: 127.0.0.1) —
//! e.g. `KDC_HOST=<podman-machine-ip>` on Windows/WSL podman setups.
//! Test principals:
//!   - testuser@TEST.REALM (password: testpassword)
//!   - testuser2@TEST.REALM (password: password2)
//!
//! Uses TCP transport (Docker Desktop on macOS doesn't reliably forward UDP).

use krb5_rs::protocol::{AsExchange, AsExchangeConfig, ErrorCode, StepResult};
use krb5_rs::types::PrincipalName;
use krb5_rs::Krb5Error;

#[path = "common/mod.rs"]
mod common;
use common::kdc::kdc_send;

const REALM: &str = "TEST.REALM";

/// Drive the AS exchange state machine to completion using TCP transport.
/// Caps at 32 steps to avoid runaway loops in tests.
fn drive_exchange(exchange: &mut AsExchange) -> Result<(), Krb5Error> {
    let mut kdc_reply = Vec::new();
    for _ in 0..32 {
        match exchange.step(&kdc_reply)? {
            StepResult::SendToKdc { data, .. } | StepResult::RetryTcp { data, .. } => {
                kdc_reply = kdc_send(&data).map_err(Krb5Error::Transport)?;
            }
            StepResult::Complete => return Ok(()),
        }
    }
    Err(Krb5Error::ReplyValidation(
        "exchange did not complete within step limit",
    ))
}

/// Test: acquire TGT with correct password via the two-round AS exchange.
///
/// Verifies the full PREAUTH_REQUIRED → PA-ENC-TIMESTAMP → AS-REP flow.
#[test]
#[ignore = "requires KDC: docker compose -f docker-compose.test.yml up -d"]
fn test_acquire_tgt_with_password() {
    let config = AsExchangeConfig::new(PrincipalName::new_principal("testuser"), REALM);
    let mut exchange = AsExchange::new(config, "testpassword");

    drive_exchange(&mut exchange).expect("AS exchange should succeed");

    let cred = exchange.credential().expect("should have credential");
    assert_eq!(cred.client.to_string(), "testuser");
    assert_eq!(cred.crealm, REALM);
    assert_eq!(cred.server.to_string(), "krbtgt/TEST.REALM");
    assert_eq!(cred.srealm, REALM);
    // Session key should be AES-256 or AES-128
    assert!(
        cred.session_key.keytype == 18 || cred.session_key.keytype == 17,
        "unexpected session key type: {}",
        cred.session_key.keytype
    );
    assert!(!cred.session_key.key_bytes().is_empty());
}

/// Test: acquire TGT for a second user to verify it's not user-specific.
#[test]
#[ignore = "requires KDC: docker compose -f docker-compose.test.yml up -d"]
fn test_acquire_tgt_second_user() {
    let config = AsExchangeConfig::new(PrincipalName::new_principal("testuser2"), REALM);
    let mut exchange = AsExchange::new(config, "password2");

    drive_exchange(&mut exchange).expect("AS exchange should succeed for testuser2");

    let cred = exchange.credential().expect("should have credential");
    assert_eq!(cred.client.to_string(), "testuser2");
}

/// Test: wrong password produces DecryptionFailed or PREAUTH_FAILED error.
#[test]
#[ignore = "requires KDC: docker compose -f docker-compose.test.yml up -d"]
fn test_wrong_password_fails() {
    let config = AsExchangeConfig::new(PrincipalName::new_principal("testuser"), REALM);
    let mut exchange = AsExchange::new(config, "wrongpassword");

    let result = drive_exchange(&mut exchange);
    match result {
        Err(Krb5Error::DecryptionFailed) => {} // Client-side decryption failure
        Err(Krb5Error::KdcError(err)) => {
            assert_eq!(
                err.error_code,
                ErrorCode::PreauthFailed as i32,
                "expected PREAUTH_FAILED"
            );
        }
        Err(other) => panic!("unexpected error: {other}"),
        Ok(()) => panic!("should have failed with wrong password"),
    }
}

/// Test: unknown principal produces KDC_ERR_C_PRINCIPAL_UNKNOWN (6).
#[test]
#[ignore = "requires KDC: docker compose -f docker-compose.test.yml up -d"]
fn test_unknown_principal_fails() {
    let config = AsExchangeConfig::new(PrincipalName::new_principal("nonexistent_user_xyz"), REALM);
    let mut exchange = AsExchange::new(config, "anypassword");

    let result = drive_exchange(&mut exchange);
    match result {
        Err(Krb5Error::KdcError(err)) => {
            assert_eq!(
                err.error_code,
                ErrorCode::CPrincipalUnknown as i32,
                "expected C_PRINCIPAL_UNKNOWN, got {}",
                err.error_code
            );
        }
        Err(other) => panic!("unexpected error: {other}"),
        Ok(()) => panic!("should have failed with unknown principal"),
    }
}
