//! Authentication indicators carried in CAMMAC authdata and checked
//! against a service's `require_auth` (kdc_authdata.c, do_tgs_req.c).

use super::*;
use krb5_rs::spake::Group;

async fn authind_fixture(spake: bool, require_auth: &str) -> Fixture {
    fixture_with(FixtureOptions {
        spake_groups: if spake {
            vec![Group::Edwards25519]
        } else {
            Vec::new()
        },
        spake_indicators: vec!["otp".into(), "strong".into()],
        service_require_auth: Some(require_auth.into()),
        ..Default::default()
    })
    .await
}

#[tokio::test]
async fn spake_indicator_in_tgt_satisfies_require_auth() {
    let f = authind_fixture(true, "strong").await;
    let tgt = get_tgt(&f).await;
    run_tgs(&f.kdc, &tgt, service(), TgsOptions::default())
        .await
        .result
        .expect("TGS with the SPAKE indicator");
}

#[tokio::test]
async fn any_listed_indicator_satisfies_require_auth() {
    let f = authind_fixture(true, "hardware strong").await;
    let tgt = get_tgt(&f).await;
    run_tgs(&f.kdc, &tgt, service(), TgsOptions::default())
        .await
        .result
        .expect("TGS with one of the required indicators");
}

#[tokio::test]
async fn missing_indicator_is_policy_error() {
    let f = authind_fixture(true, "hardware").await;
    let tgt = get_tgt(&f).await;
    let err = run_tgs(&f.kdc, &tgt, service(), TgsOptions::default())
        .await
        .result
        .expect_err("indicator not present");
    assert_eq!(kdc_code(&err), 12);
}

#[tokio::test]
async fn encrypted_timestamp_asserts_no_indicator() {
    let f = authind_fixture(false, "strong").await;
    let tgt = get_tgt(&f).await;
    let err = run_tgs(&f.kdc, &tgt, service(), TgsOptions::default())
        .await
        .result
        .expect_err("no indicators without SPAKE");
    assert_eq!(kdc_code(&err), 12);
}
