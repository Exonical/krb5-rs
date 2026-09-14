#![cfg(feature = "client")]
//! Live integration test for LocatedTransport + KerberosClient against a
//! real MIT KDC in a container.
//!
//! Run: cargo test --all-features --test sendto_live -- --ignored --nocapture

use krb5_rs::client::KerberosClient;
use krb5_rs::profile::Profile;
use krb5_rs::transport::located::LocatedTransport;
use krb5_rs::transport::sendto::SendtoConfig;
use std::env;
use std::sync::Arc;
use std::time::Instant;

fn kdc_host() -> String {
    env::var("KDC_HOST").unwrap_or_else(|_| "127.0.0.1".into())
}

/// AS exchange through LocatedTransport with a dead KDC listed first:
/// MIT sendto must fall through to the live KDC, which must not be
/// contacted as a replica (it's also the primary).  The profile lists
/// port 1 (unreachable) before the real KDC so the walk can be observed.
#[tokio::test]
#[ignore]
async fn as_exchange_through_located_transport() {
    let host = kdc_host();
    let conf = format!(
        "[realms]\nTEST.REALM = {{\n\
         kdc = {host}:1\n\
         kdc = {host}:10188\n\
         primary_kdc = {host}:10188\n}}\n\
         [libdefaults]\nrequest_timeout = 30\n"
    );
    let profile = Profile::parse(&conf).unwrap();
    let t = LocatedTransport::new(Arc::new(profile), None);
    let client = KerberosClient::new("TEST.REALM", t.clone());
    let start = Instant::now();
    client
        .acquire_tgt("testuser", "testpassword")
        .await
        .expect("AS exchange via LocatedTransport failed");
    let elapsed = start.elapsed();
    // Generous bound: on podman/WSL2 UDP is not forwarded to the host, so
    // each dead UDP send burns a full per-server wait, and Windows takes
    // ~2s to refuse the TCP connect to the dead port — MIT semantics are
    // exercised identically, just slower.
    assert!(
        elapsed < std::time::Duration::from_secs(10),
        "AS exchange took {elapsed:?}"
    );
    let used = t.kdcs_used();
    assert!(
        used.iter()
            .any(|(r, e)| r == "TEST.REALM" && e.port == 10188),
        "kdcs_used {used:?}"
    );
}

/// Single configured KDC -> the exchange succeeds and the used KDC's
/// transport is recorded (UDP where the host can reach it; TCP fallback
/// under podman/WSL2, which does not forward UDP to the host).
#[tokio::test]
#[ignore]
async fn single_kdc_records_transport() {
    let host = kdc_host();
    let conf = format!("[realms]\nTEST.REALM = {{\nkdc = {host}:10188\n}}\n");
    let profile = Profile::parse(&conf).unwrap();
    let cfg = SendtoConfig {
        request_timeout: Some(std::time::Duration::from_secs(10)),
        ..SendtoConfig::default()
    };
    let t = LocatedTransport::with_config(Arc::new(profile), None, cfg);
    let client = KerberosClient::new("TEST.REALM", t.clone());
    client
        .acquire_tgt("testuser", "testpassword")
        .await
        .expect("AS exchange failed");
    let used = t.kdcs_used();
    assert!(
        used.iter().any(|(_, e)| e.port == 10188),
        "kdcs_used {used:?}"
    );
    eprintln!(
        "KDC transport used: {:?}",
        used.last().map(|(_, e)| e.transport)
    );
}
