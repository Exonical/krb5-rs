//! Integration tests for the TGS exchange against a real MIT KDC.
//!
//! These tests require a running KDC container:
//!   docker compose -f docker-compose.test.yml up -d
//!
//! Run with:
//!   cargo test --test tgs_exchange_integration -- --ignored
//!
//! The KDC listens on ${KDC_HOST}:10188 with realm TEST.REALM.
//! A second KDC listens on ${KDC_HOST}:10288 with realm OTHER.REALM.
//! Set KDC_HOST when the KDCs are not on localhost (default: 127.0.0.1) —
//! e.g. `KDC_HOST=<podman-machine-ip>` on Windows/WSL podman setups.
//! Test principals:
//!   - testuser@TEST.REALM (password: testpassword)
//!   - HTTP/server.test.realm@TEST.REALM (keytab, random key)
//!   - HTTP/service.other.realm@OTHER.REALM (keytab, random key)
//!
//! Cross-realm trust: TEST.REALM <-> OTHER.REALM (bidirectional)

use krb5_rs::protocol::ErrorCode;
use krb5_rs::types::PrincipalName;
use krb5_rs::Krb5Error;

#[path = "common/mod.rs"]
mod common;
use common::kdc::{acquire_tgt, get_service_ticket, OTHER_REALM};

const REALM: &str = "TEST.REALM";

/// Test: acquire a service ticket for HTTP/server.test.realm using a TGT.
///
/// Verifies the full AS exchange → TGS exchange flow:
/// 1. Get TGT via password authentication
/// 2. Use TGT to request service ticket
/// 3. Validate the service ticket metadata
#[test]
#[ignore = "requires KDC: docker compose -f docker-compose.test.yml up -d"]
fn test_get_service_ticket() {
    // Step 1: Acquire TGT
    let tgt = acquire_tgt("testuser", "testpassword", REALM).expect("AS exchange should succeed");
    assert_eq!(tgt.server.to_string(), "krbtgt/TEST.REALM");

    // Step 2: Request service ticket
    let target = PrincipalName::new_srv_inst("HTTP", "server.test.realm");
    let service_cred = get_service_ticket(&tgt, target).expect("TGS exchange should succeed");

    // Step 3: Validate service ticket
    assert_eq!(service_cred.server.to_string(), "HTTP/server.test.realm");
    assert_eq!(service_cred.srealm, REALM);
    assert_eq!(service_cred.client.to_string(), "testuser");
    assert_eq!(service_cred.crealm, REALM);
    // Session key should be AES-256 or AES-128
    assert!(
        service_cred.session_key.keytype == 18 || service_cred.session_key.keytype == 17,
        "unexpected session key type: {}",
        service_cred.session_key.keytype
    );
    assert!(!service_cred.session_key.key_bytes().is_empty());
    // Service session key should differ from TGT session key
    assert_ne!(
        service_cred.session_key.key_bytes(),
        tgt.session_key.key_bytes(),
        "service session key should differ from TGT session key"
    );
}

/// Test: requesting krbtgt/REALM via TGS exchange returns a valid TGT.
///
/// Verifies the TGS exchange can retrieve a krbtgt ticket (same pattern
/// used by clients before explicit TGT renewal via RENEW flag).
#[test]
#[ignore = "requires KDC: docker compose -f docker-compose.test.yml up -d"]
fn test_get_tgt_via_tgs() {
    let tgt = acquire_tgt("testuser", "testpassword", REALM).expect("AS exchange should succeed");

    let target = PrincipalName::new_srv_inst("krbtgt", REALM);
    let new_tgt = get_service_ticket(&tgt, target).expect("TGS exchange for krbtgt should succeed");

    assert_eq!(new_tgt.server.to_string(), "krbtgt/TEST.REALM");
    assert_eq!(new_tgt.srealm, REALM);
}

/// Test: requesting a ticket for an unknown service fails.
#[test]
#[ignore = "requires KDC: docker compose -f docker-compose.test.yml up -d"]
fn test_unknown_service_fails() {
    let tgt = acquire_tgt("testuser", "testpassword", REALM).expect("AS exchange should succeed");

    let target = PrincipalName::new_srv_inst("HTTP", "nonexistent.host.example.com");
    let result = get_service_ticket(&tgt, target);

    match result {
        Err(Krb5Error::KdcError(err)) => {
            assert_eq!(
                err.error_code,
                ErrorCode::SPrincipalUnknown as i32,
                "expected S_PRINCIPAL_UNKNOWN, got {}",
                err.error_code
            );
        }
        Err(other) => panic!("unexpected error: {other}"),
        Ok(_) => panic!("should have failed with unknown service principal"),
    }
}

/// Test: cross-realm service ticket — get a ticket for a service in OTHER.REALM.
///
/// MIT KDC does not return automatic referrals for host-based SPNs.
/// Instead, the client must explicitly acquire the cross-realm TGT first
/// (matching MIT krb5's actual behavior).
///
/// Flow:
/// 1. testuser@TEST.REALM gets TGT from TEST.REALM KDC
/// 2. TGS-REQ to TEST.REALM for krbtgt/OTHER.REALM → cross-realm TGT
/// 3. TGS-REQ to OTHER.REALM for HTTP/service.other.realm using cross-realm TGT
/// 4. OTHER.REALM returns service ticket
#[test]
#[ignore = "requires KDC: docker compose -f docker-compose.test.yml up -d"]
fn test_cross_realm_service_ticket() {
    // Step 1: Acquire TGT in home realm
    let tgt = acquire_tgt("testuser", "testpassword", REALM).expect("AS exchange should succeed");

    // Step 2: Explicitly request cross-realm TGT for OTHER.REALM
    let xrealm_target = PrincipalName::new_srv_inst("krbtgt", OTHER_REALM);
    let xrealm_tgt =
        get_service_ticket(&tgt, xrealm_target).expect("cross-realm TGT request should succeed");

    assert_eq!(xrealm_tgt.server.to_string(), "krbtgt/OTHER.REALM");
    assert_eq!(xrealm_tgt.srealm, REALM);

    // Step 3: Use cross-realm TGT to get service ticket from OTHER.REALM
    let target = PrincipalName::new_srv_inst("HTTP", "service.other.realm");
    let service_cred = get_service_ticket(&xrealm_tgt, target)
        .expect("service ticket via cross-realm TGT should succeed");

    // Validate
    assert_eq!(service_cred.server.to_string(), "HTTP/service.other.realm");
    assert_eq!(service_cred.srealm, OTHER_REALM);
    assert_eq!(service_cred.client.to_string(), "testuser");
    assert_eq!(service_cred.crealm, REALM);
    assert!(!service_cred.session_key.key_bytes().is_empty());
    // Service session key should differ from cross-realm TGT session key
    assert_ne!(
        service_cred.session_key.key_bytes(),
        xrealm_tgt.session_key.key_bytes(),
        "service session key should differ from cross-realm TGT session key"
    );
}
