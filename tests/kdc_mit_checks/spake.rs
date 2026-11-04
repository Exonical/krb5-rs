//! SPAKE pre-authentication against the KDC (spake_kdc.c, spake_client.c).

use super::*;
use krb5_rs::spake::{Group, PaSpake};

async fn spake_fixture(groups: &[Group], challenge: Option<Group>) -> Fixture {
    fixture_with(FixtureOptions {
        spake_groups: groups.to_vec(),
        spake_challenge: challenge,
        ..Default::default()
    })
    .await
}

fn types(pa: &[PaData]) -> Vec<i32> {
    pa.iter().map(|p| p.padata_type).collect()
}

fn challenge_group(pa: &PaData) -> i32 {
    match rasn::der::decode::<PaSpake>(pa.padata_value.as_ref()).expect("PA-SPAKE") {
        PaSpake::Challenge(c) => c.group,
        other => panic!("not a challenge: {other:?}"),
    }
}

fn spake_config(groups: &[Group]) -> AsExchangeConfig {
    let mut config = as_config(USER);
    config.spake_groups = groups.to_vec();
    config
}

#[tokio::test]
async fn spake_support_then_challenge_then_response() {
    let f = spake_fixture(&[Group::Edwards25519], None).await;
    let run = run_as(&f.kdc, as_config(USER), PASSWORD).await;
    let cred = run.result.expect("SPAKE AS exchange");
    assert!(cred.flags.contains(TicketFlags::PRE_AUTHENT));
    assert_eq!(run.replies.len(), 3);

    // MIT hint order: FX-FAST, ETYPE-INFO2, SPAKE, ENC-TIMESTAMP, cookie.
    let err = krb_error(&run.replies[0]);
    assert_eq!(err.error_code, 25);
    let hints = method_data(&err);
    assert_eq!(types(&hints), vec![136, 19, 151, 2, 133]);
    assert!(hints[2].padata_value.is_empty());
    assert_eq!(hints[4].padata_value.as_ref(), b"MIT");

    // The support message gets a challenge and a stateful MIT1 cookie; the
    // request carried a cookie, so no ETYPE-INFO2 is added.
    let err = krb_error(&run.replies[1]);
    assert_eq!(err.error_code, 91);
    let more = method_data(&err);
    assert_eq!(types(&more), vec![151, 133]);
    assert_eq!(challenge_group(&more[0]), 1);
    assert!(more[1].padata_value.as_ref().starts_with(b"MIT1"));
}

#[tokio::test]
async fn spake_optimistic_challenge_answered_directly() {
    let f = spake_fixture(&[Group::P256], Some(Group::P256)).await;
    let run = run_as(&f.kdc, spake_config(&[Group::P256]), PASSWORD).await;
    run.result.expect("SPAKE AS exchange");
    assert_eq!(run.replies.len(), 2);
    let hints = method_data(&krb_error(&run.replies[0]));
    assert_eq!(types(&hints), vec![136, 19, 151, 2, 133]);
    assert_eq!(challenge_group(&hints[2]), 2);
    assert!(hints[4].padata_value.as_ref().starts_with(b"MIT1"));
}

#[tokio::test]
async fn spake_unpermitted_optimistic_group_sends_support() {
    let f = spake_fixture(&[Group::P256, Group::Edwards25519], Some(Group::P256)).await;
    let run = run_as(&f.kdc, as_config(USER), PASSWORD).await;
    run.result.expect("SPAKE AS exchange");
    assert_eq!(run.replies.len(), 3);
    let more = method_data(&krb_error(&run.replies[1]));
    assert_eq!(challenge_group(&more[0]), 1);
}

#[tokio::test]
async fn spake_every_group_completes() {
    for group in Group::ALL {
        let f = spake_fixture(&[group], None).await;
        let run = run_as(&f.kdc, spake_config(&[group]), PASSWORD).await;
        run.result.unwrap_or_else(|e| panic!("{group:?}: {e:?}"));
    }
}

#[tokio::test]
async fn spake_wrong_password_is_preauth_failed() {
    let f = spake_fixture(&[Group::Edwards25519], None).await;
    let run = run_as(&f.kdc, as_config(USER), "wrong").await;
    assert!(run.result.is_err());
    let failed = krb_error(&run.replies[2]);
    assert_eq!(failed.error_code, 24);
    assert_eq!(types(&method_data(&failed))[2], 151);
    assert_eq!(krb_error(run.replies.last().unwrap()).error_code, 24);
}

#[tokio::test]
async fn spake_off_on_client_uses_encrypted_timestamp() {
    let f = spake_fixture(&[Group::Edwards25519], None).await;
    let run = run_as(&f.kdc, spake_config(&[]), PASSWORD).await;
    run.result.expect("AS exchange");
    assert_eq!(run.replies.len(), 2);
}

#[tokio::test]
async fn spake_no_common_group_falls_back() {
    let f = spake_fixture(&[Group::P384], None).await;
    let run = run_as(&f.kdc, as_config(USER), PASSWORD).await;
    run.result.expect("AS exchange");
    // The support message is refused; encrypted timestamp follows.
    assert_eq!(krb_error(&run.replies[1]).error_code, 24);
}
