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

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use krb5_rs::protocol::{AsExchange, AsExchangeConfig, ErrorCode, StepResult};
use krb5_rs::types::PrincipalName;
use krb5_rs::Krb5Error;

/// KDC host — overridable via KDC_HOST for non-local podman/Docker setups.
fn kdc_host() -> String {
    std::env::var("KDC_HOST").unwrap_or_else(|_| "127.0.0.1".into())
}

fn kdc_addr() -> String {
    format!("{}:10188", kdc_host())
}

const REALM: &str = "TEST.REALM";

/// Maximum acceptable KDC response size (1 MiB). Protects against
/// allocating arbitrarily large buffers from an untrusted length prefix.
const MAX_KDC_RESPONSE_SIZE: usize = 1024 * 1024;

/// Send a message to the KDC via TCP (4-byte big-endian length prefix).
fn kdc_send(data: &[u8]) -> std::io::Result<Vec<u8>> {
    let mut stream = TcpStream::connect(kdc_addr())?;
    stream.set_nodelay(true)?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    // Combine 4-byte length prefix + data into a single write to avoid
    // Nagle-related issues with Docker Desktop TCP port forwarding.
    let len_u32: u32 = data.len().try_into().map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("KDC request too large: {} bytes", data.len()),
        )
    })?;
    let mut msg = Vec::with_capacity(4 + data.len());
    msg.extend_from_slice(&len_u32.to_be_bytes());
    msg.extend_from_slice(data);
    stream.write_all(&msg)?;
    stream.flush()?;
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let resp_len = u32::from_be_bytes(len_buf) as usize;
    if resp_len > MAX_KDC_RESPONSE_SIZE {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("KDC response too large: {resp_len} bytes (max {MAX_KDC_RESPONSE_SIZE})"),
        ));
    }
    let mut resp = vec![0u8; resp_len];
    stream.read_exact(&mut resp)?;
    Ok(resp)
}

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
