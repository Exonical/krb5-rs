#![cfg(feature = "kdc")]
//! Lockout (MIT plugins/kdb/db2/lockout.c), the consistency gate, the TGS
//! client re-check and the `KdcBuilder` defaults.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use chrono::{DateTime, TimeZone, Utc};
use krb5_rs::kdc::{
    AuthState, AuthStateStore, AuthStateUpdate, ConsistencyGate, GateDecision, Kdc, KdcConfig,
    LockoutReport, LockoutReporter, MemoryAuthState, MemoryStore, Policy, PrincipalAttributes,
    PrincipalEntry,
};
use krb5_rs::protocol::{
    AsExchange, AsExchangeConfig, Credential, StepResult, TgsExchange, TgsOptions, TgsStepResult,
};
use krb5_rs::types::{KrbErrorMsg, PrincipalName};

const REALM: &str = "LOCK.TEST";
const PW: &str = "right-password";

fn alice() -> PrincipalName {
    PrincipalName::new_principal("alice")
}

fn bob() -> PrincipalName {
    PrincipalName::new_principal("bob")
}

fn service() -> PrincipalName {
    PrincipalName::new_srv_hst("HTTP", "svc.lock.test")
}

fn t0() -> DateTime<Utc> {
    Utc.timestamp_opt(Utc::now().timestamp(), 0)
        .single()
        .expect("time")
}

fn policy(max_fail: u32, interval: u32, duration: u32) -> Policy {
    Policy {
        name: "lock".into(),
        pw_max_fail: max_fail,
        pw_failcnt_interval: interval,
        pw_lockout_duration: duration,
        ..Policy::default()
    }
}

/// The entries every test starts from: krbtgt, alice (pre-auth required, under
/// policy "lock"), bob (no pre-auth, under the same policy), and a service.
fn entries() -> Vec<PrincipalEntry> {
    let mut store = MemoryStore::new();
    store
        .add_random_key(
            PrincipalName::new_srv_inst("krbtgt", REALM),
            REALM,
            1,
            &[18],
            PrincipalAttributes::empty(),
        )
        .expect("krbtgt");
    store
        .add_with_password(
            alice(),
            REALM,
            PW,
            1,
            &[18],
            PrincipalAttributes::REQUIRES_PRE_AUTH,
        )
        .expect("alice");
    store
        .add_with_password(bob(), REALM, PW, 1, &[18], PrincipalAttributes::empty())
        .expect("bob");
    store
        .add_random_key(service(), REALM, 1, &[18], PrincipalAttributes::empty())
        .expect("service");
    let mut all = Vec::new();
    for n in [
        PrincipalName::new_srv_inst("krbtgt", REALM),
        alice(),
        bob(),
        service(),
    ] {
        let mut e = store.get(&n, REALM).expect("entry");
        if n == alice() || n == bob() {
            e.policy = Some("lock".into());
        }
        all.push(e);
    }
    all
}

fn store_of(entries: &[PrincipalEntry]) -> MemoryStore {
    let mut s = MemoryStore::new();
    for e in entries {
        s.insert(e.clone());
    }
    s
}

fn config() -> KdcConfig {
    let mut c = KdcConfig::new(REALM);
    // Simulated time moves far beyond the real clock.
    c.clockskew = Duration::from_secs(10 * 365 * 24 * 3600);
    c
}

struct Lockout {
    kdc: Kdc<MemoryStore>,
    state: Arc<MemoryAuthState>,
}

fn lockout_kdc(entries: &[PrincipalEntry], p: Policy, config: KdcConfig) -> Lockout {
    let mut policies = MemoryStore::new();
    policies.insert_policy(p);
    let state = Arc::new(MemoryAuthState::new());
    let kdc = Kdc::builder(config, store_of(entries))
        .policies(policies)
        .auth_state(Arc::clone(&state))
        .build();
    Lockout { kdc, state }
}

/// Outcome of one AS attempt: 0 for a ticket, else the KRB-ERROR code and text.
async fn attempt_as<S: krb5_rs::kdc::PrincipalStore>(
    kdc: &Kdc<S>,
    user: &PrincipalName,
    password: &str,
    now: DateTime<Utc>,
) -> (i32, String) {
    let config = AsExchangeConfig::new(user.clone(), REALM);
    let mut exchange = AsExchange::new(config, password);
    let mut reply = Vec::new();
    let mut last_error = (0, String::new());
    for _ in 0..8 {
        match exchange.step(&reply) {
            Ok(StepResult::SendToKdc { data, .. }) | Ok(StepResult::RetryTcp { data, .. }) => {
                reply = kdc.handle_at(&data, now).await;
                if let Ok(e) = rasn::der::decode::<KrbErrorMsg>(&reply) {
                    last_error = (
                        e.error_code,
                        e.e_text
                            .map(|t| String::from_utf8_lossy(t.as_bytes()).to_string())
                            .unwrap_or_default(),
                    );
                }
            }
            Ok(StepResult::Complete) => return (0, String::new()),
            Err(_) => return last_error,
        }
    }
    last_error
}

async fn login<S: krb5_rs::kdc::PrincipalStore>(kdc: &Kdc<S>, user: &PrincipalName) -> Credential {
    let config = AsExchangeConfig::new(user.clone(), REALM);
    let mut exchange = AsExchange::new(config, PW);
    let mut reply = Vec::new();
    loop {
        match exchange.step(&reply).expect("AS step") {
            StepResult::SendToKdc { data, .. } | StepResult::RetryTcp { data, .. } => {
                reply = kdc.handle(&data).await;
            }
            StepResult::Complete => return exchange.credential().expect("TGT").clone(),
        }
    }
}

async fn tgs<S: krb5_rs::kdc::PrincipalStore>(kdc: &Kdc<S>, tgt: &Credential) -> (i32, String) {
    let mut exchange = TgsExchange::new(tgt.clone(), service(), TgsOptions::default());
    let mut reply = Vec::new();
    let mut last_error = (0, String::new());
    for _ in 0..4 {
        match exchange.step(&reply) {
            Ok(TgsStepResult::SendToKdc { data, .. })
            | Ok(TgsStepResult::RetryTcp { data, .. }) => {
                reply = kdc.handle(&data).await;
                if let Ok(e) = rasn::der::decode::<KrbErrorMsg>(&reply) {
                    last_error = (
                        e.error_code,
                        e.e_text
                            .map(|t| String::from_utf8_lossy(t.as_bytes()).to_string())
                            .unwrap_or_default(),
                    );
                }
            }
            Ok(TgsStepResult::Complete) => return (0, String::new()),
            Err(_) => return last_error,
        }
    }
    last_error
}

// ------------------------------------------------------------ lockout

#[tokio::test]
async fn failures_up_to_the_threshold_lock_the_principal_out() {
    let l = lockout_kdc(&entries(), policy(3, 0, 0), config());
    let now = t0();
    for i in 0..3 {
        let (code, _) = attempt_as(
            &l.kdc,
            &alice(),
            "wrong",
            now + chrono::Duration::seconds(i),
        )
        .await;
        assert_eq!(code, 24, "failure {i}");
    }
    // Locked: even the right password gets CLIENT_REVOKED / LOCKED_OUT
    // (kdb_db2.c:1546-1549).
    let (code, text) = attempt_as(&l.kdc, &alice(), PW, now + chrono::Duration::seconds(10)).await;
    assert_eq!((code, text.as_str()), (18, "LOCKED_OUT"));
    let state = l.state.auth_state(&alice(), REALM).await.expect("state");
    assert_eq!(state.fail_count, 3);
    // The count stops growing once locked (lockout.c:160-166).
    attempt_as(
        &l.kdc,
        &alice(),
        "wrong",
        now + chrono::Duration::seconds(11),
    )
    .await;
    assert_eq!(
        l.state
            .auth_state(&alice(), REALM)
            .await
            .expect("state")
            .fail_count,
        3
    );
}

#[tokio::test]
async fn two_failures_do_not_lock_and_a_success_clears_them() {
    let l = lockout_kdc(&entries(), policy(3, 0, 0), config());
    let now = t0();
    for i in 0..2 {
        attempt_as(
            &l.kdc,
            &alice(),
            "wrong",
            now + chrono::Duration::seconds(i),
        )
        .await;
    }
    assert_eq!(
        attempt_as(&l.kdc, &alice(), PW, now + chrono::Duration::seconds(5))
            .await
            .0,
        0
    );
    let state = l.state.auth_state(&alice(), REALM).await.expect("state");
    assert_eq!(state.fail_count, 0);
    assert_eq!(
        state.last_success,
        (now + chrono::Duration::seconds(5)).timestamp()
    );
    // Two more failures after the reset still do not lock.
    for i in 10..12 {
        attempt_as(
            &l.kdc,
            &alice(),
            "wrong",
            now + chrono::Duration::seconds(i),
        )
        .await;
    }
    assert_eq!(
        attempt_as(&l.kdc, &alice(), PW, now + chrono::Duration::seconds(20))
            .await
            .0,
        0
    );
}

#[tokio::test]
async fn the_failure_count_resets_after_the_interval() {
    let l = lockout_kdc(&entries(), policy(3, 60, 0), config());
    let now = t0();
    attempt_as(&l.kdc, &alice(), "wrong", now).await;
    attempt_as(
        &l.kdc,
        &alice(),
        "wrong",
        now + chrono::Duration::seconds(1),
    )
    .await;
    // More than pw_failcnt_interval later: the count restarts at 1.
    attempt_as(
        &l.kdc,
        &alice(),
        "wrong",
        now + chrono::Duration::seconds(100),
    )
    .await;
    assert_eq!(
        l.state
            .auth_state(&alice(), REALM)
            .await
            .expect("state")
            .fail_count,
        1
    );
    assert_eq!(
        attempt_as(&l.kdc, &alice(), PW, now + chrono::Duration::seconds(101))
            .await
            .0,
        0
    );
}

#[tokio::test]
async fn a_lockout_expires_after_the_duration() {
    let l = lockout_kdc(&entries(), policy(2, 0, 100), config());
    let now = t0();
    for i in 0..2 {
        attempt_as(
            &l.kdc,
            &alice(),
            "wrong",
            now + chrono::Duration::seconds(i),
        )
        .await;
    }
    // last_failed = now+1; locked while last_failed + 100 > t.
    assert_eq!(
        attempt_as(&l.kdc, &alice(), PW, now + chrono::Duration::seconds(100))
            .await
            .0,
        18
    );
    assert_eq!(
        attempt_as(&l.kdc, &alice(), PW, now + chrono::Duration::seconds(102))
            .await
            .0,
        0
    );
}

#[tokio::test]
async fn a_zero_duration_locks_until_an_administrator_unlocks() {
    let all = entries();
    let l = lockout_kdc(&all, policy(2, 0, 0), config());
    let now = t0();
    for i in 0..2 {
        attempt_as(
            &l.kdc,
            &alice(),
            "wrong",
            now + chrono::Duration::seconds(i),
        )
        .await;
    }
    let later = now + chrono::Duration::seconds(250);
    assert_eq!(attempt_as(&l.kdc, &alice(), PW, later).await.0, 18);

    // The administrator unlocks (last_admin_unlock after the last failure);
    // the same KDC state, a database that now carries the unlock time.
    let mut unlocked = all.clone();
    for e in &mut unlocked {
        if e.name == alice() {
            e.last_admin_unlock = Some((now + chrono::Duration::seconds(30)).fixed_offset());
        }
    }
    let mut policies = MemoryStore::new();
    policies.insert_policy(policy(2, 0, 0));
    let kdc = Kdc::builder(config(), store_of(&unlocked))
        .policies(policies)
        .auth_state(Arc::clone(&l.state))
        .build();
    assert_eq!(attempt_as(&kdc, &alice(), PW, later).await.0, 0);
}

#[tokio::test]
async fn success_only_resets_principals_that_require_preauth() {
    let l = lockout_kdc(&entries(), policy(5, 0, 0), config());
    let now = t0();
    // bob does not require pre-authentication, so a successful AS proves
    // nothing (lockout.c:168-170): the counter and last_success are untouched.
    l.state
        .apply(
            &bob(),
            REALM,
            &AuthStateUpdate::Failure {
                stamp: now.timestamp(),
                failcnt_interval: 0,
                last_admin_unlock: None,
            },
        )
        .await
        .expect("seed");
    assert_eq!(attempt_as(&l.kdc, &bob(), PW, now).await.0, 0);
    let state = l.state.auth_state(&bob(), REALM).await.expect("state");
    assert_eq!((state.fail_count, state.last_success), (1, 0));
}

#[tokio::test]
async fn a_principal_without_a_policy_never_locks() {
    let mut all = entries();
    for e in &mut all {
        e.policy = None;
    }
    let l = lockout_kdc(&all, policy(1, 0, 0), config());
    let now = t0();
    for i in 0..5 {
        attempt_as(
            &l.kdc,
            &alice(),
            "wrong",
            now + chrono::Duration::seconds(i),
        )
        .await;
    }
    assert_eq!(
        attempt_as(&l.kdc, &alice(), PW, now + chrono::Duration::seconds(9))
            .await
            .0,
        0
    );
    // A dangling policy name counts as no policy.
    let mut dangling = entries();
    for e in &mut dangling {
        e.policy = Some("missing".into());
    }
    let l = lockout_kdc(&dangling, policy(1, 0, 0), config());
    attempt_as(&l.kdc, &alice(), "wrong", now).await;
    assert_eq!(attempt_as(&l.kdc, &alice(), PW, now).await.0, 0);
}

#[tokio::test]
async fn disable_lockout_neither_checks_nor_counts() {
    let mut c = config();
    c.disable_lockout = true;
    let l = lockout_kdc(&entries(), policy(2, 0, 0), c);
    let now = t0();
    for i in 0..4 {
        attempt_as(
            &l.kdc,
            &alice(),
            "wrong",
            now + chrono::Duration::seconds(i),
        )
        .await;
    }
    assert_eq!(
        attempt_as(&l.kdc, &alice(), PW, now + chrono::Duration::seconds(9))
            .await
            .0,
        0
    );
    assert_eq!(
        l.state.auth_state(&alice(), REALM).await.expect("state"),
        AuthState {
            fail_count: 0,
            last_failed: 0,
            // Success is still recorded: only disable_last_success stops it.
            last_success: (now + chrono::Duration::seconds(9)).timestamp(),
        }
    );
}

#[tokio::test]
async fn disable_last_success_keeps_counting_but_does_not_record_successes() {
    let mut c = config();
    c.disable_last_success = true;
    let l = lockout_kdc(&entries(), policy(3, 0, 0), c);
    let now = t0();
    attempt_as(&l.kdc, &alice(), "wrong", now).await;
    assert_eq!(
        attempt_as(&l.kdc, &alice(), PW, now + chrono::Duration::seconds(1))
            .await
            .0,
        0
    );
    let state = l.state.auth_state(&alice(), REALM).await.expect("state");
    assert_eq!((state.fail_count, state.last_success), (0, 0));
}

struct Collect(Mutex<Vec<LockoutReport>>);

impl LockoutReporter for Collect {
    fn report(&self, report: LockoutReport) {
        self.0.lock().expect("lock").push(report);
    }
}

#[tokio::test]
async fn a_tripped_lockout_is_reported_once() {
    let sink = Arc::new(Collect(Mutex::new(Vec::new())));
    let mut policies = MemoryStore::new();
    policies.insert_policy(policy(2, 0, 50));
    let kdc = Kdc::builder(config(), store_of(&entries()))
        .policies(policies)
        .lockout_reporter(Arc::clone(&sink))
        .build();
    let now = t0();
    for i in 0..4 {
        attempt_as(&kdc, &alice(), "wrong", now + chrono::Duration::seconds(i)).await;
    }
    let reports = sink.0.lock().expect("lock");
    assert_eq!(reports.len(), 1, "{reports:?}");
    assert_eq!(reports[0].principal, alice());
    assert_eq!(
        (reports[0].fail_count, reports[0].lockout_duration),
        (2, 50)
    );
}

// ------------------------------------------------- gate and TGS re-check

struct Reject(&'static str);

impl ConsistencyGate for Reject {
    async fn check(&self, _principals: &[&PrincipalEntry]) -> GateDecision {
        GateDecision::Reject {
            reason: self.0.to_string(),
        }
    }
}

struct Record(Arc<Mutex<Vec<Vec<String>>>>);

impl ConsistencyGate for Record {
    async fn check(&self, principals: &[&PrincipalEntry]) -> GateDecision {
        self.0
            .lock()
            .expect("lock")
            .push(principals.iter().map(|p| p.name.to_string()).collect());
        GateDecision::Allow
    }
}

#[tokio::test]
async fn a_rejecting_gate_stops_as_requests_with_svc_unavailable() {
    let kdc = Kdc::builder(config(), store_of(&entries()))
        .consistency(Reject("REPLICA_STALE"))
        .build();
    assert_eq!(
        attempt_as(&kdc, &alice(), PW, t0()).await,
        (29, "REPLICA_STALE".to_string())
    );
    // The summary flags it for a staleness metric.
    let (_, summary) = kdc
        .handle_summarized(&[1, 2, 3], krb5_rs::kdc::Transport::Tcp)
        .await;
    assert!(!summary.gate_rejected);
}

#[tokio::test]
async fn the_gate_sees_client_and_server_on_as_and_tgs() {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let kdc = Kdc::builder(config(), store_of(&entries()))
        .consistency(Record(Arc::clone(&seen)))
        .build();
    let tgt = login(&kdc, &alice()).await;
    assert_eq!(tgs(&kdc, &tgt).await.0, 0);
    let seen = seen.lock().expect("lock");
    assert!(
        seen.iter().any(
            |p| p.contains(&"alice".to_string()) && p.contains(&"krbtgt/LOCK.TEST".to_string())
        ),
        "{seen:?}"
    );
    assert!(
        seen.iter()
            .any(|p| p.contains(&"alice".to_string())
                && p.contains(&"HTTP/svc.lock.test".to_string())),
        "{seen:?}"
    );
}

#[tokio::test]
async fn a_rejecting_gate_stops_tgs_requests_too() {
    let all = entries();
    let tgt = login(&Kdc::new(config(), store_of(&all)), &alice()).await;
    let kdc = Kdc::builder(config(), store_of(&all))
        .consistency(Reject("AUTHORITATIVE_MISMATCH"))
        .build();
    assert_eq!(
        tgs(&kdc, &tgt).await,
        (29, "AUTHORITATIVE_MISMATCH".to_string())
    );
    // The rejection is visible in the request summary.
    let (_, summary) = {
        let mut ex = TgsExchange::new(tgt, service(), TgsOptions::default());
        let TgsStepResult::SendToKdc { data, .. } = ex.step(&[]).expect("step") else {
            panic!("expected a request");
        };
        kdc.handle_summarized(&data, krb5_rs::kdc::Transport::Tcp)
            .await
    };
    assert!(summary.gate_rejected);
}

fn with_entry(
    all: &[PrincipalEntry],
    who: &PrincipalName,
    f: impl Fn(&mut PrincipalEntry),
) -> Vec<PrincipalEntry> {
    let mut all = all.to_vec();
    for e in &mut all {
        if &e.name == who {
            f(e);
        }
    }
    all
}

#[tokio::test]
async fn tgs_refuses_a_client_disabled_expired_or_locked_since_the_tgt_was_issued() {
    let all = entries();
    let tgt = login(&Kdc::new(config(), store_of(&all)), &alice()).await;

    // Control: still fine.
    assert_eq!(tgs(&Kdc::new(config(), store_of(&all)), &tgt).await.0, 0);

    // Disabled (DISALLOW_ALL_TIX): CLIENT_REVOKED, as validate_as_request.
    let disabled = with_entry(&all, &alice(), |e| {
        e.attributes |= PrincipalAttributes::DISALLOW_ALL_TIX;
    });
    assert_eq!(
        tgs(&Kdc::new(config(), store_of(&disabled)), &tgt).await,
        (18, "CLIENT LOCKED OUT".to_string())
    );

    // Expired principal: NAME_EXP.
    let expired = with_entry(&all, &alice(), |e| {
        e.expiration = Some((Utc::now() - chrono::Duration::days(1)).fixed_offset());
    });
    assert_eq!(
        tgs(&Kdc::new(config(), store_of(&expired)), &tgt).await,
        (1, "CLIENT EXPIRED".to_string())
    );

    // The extension can be switched off (MIT's behaviour).
    let mut off = config();
    off.tgs_recheck_client = false;
    assert_eq!(tgs(&Kdc::new(off, store_of(&disabled)), &tgt).await.0, 0);
}

#[tokio::test]
async fn tgs_refuses_a_locked_out_client() {
    let all = entries();
    let tgt = login(&Kdc::new(config(), store_of(&all)), &alice()).await;
    // The same KDC (and failure counters) that locks alice out.
    let l = lockout_kdc(&all, policy(2, 0, 0), KdcConfig::new(REALM));
    assert_eq!(tgs(&l.kdc, &tgt).await.0, 0);
    let now = Utc::now();
    for i in 0..2 {
        attempt_as(
            &l.kdc,
            &alice(),
            "wrong",
            now + chrono::Duration::seconds(i),
        )
        .await;
    }
    assert_eq!(tgs(&l.kdc, &tgt).await, (18, "LOCKED_OUT".to_string()));
}

// ------------------------------------------------------------ builder

#[tokio::test]
async fn the_builder_defaults_behave_like_kdc_new() {
    let all = entries();
    let plain = Kdc::new(config(), store_of(&all));
    let built = Kdc::builder(config(), store_of(&all)).build();
    for kdc in [&plain, &built] {
        // Policies are not injected, so lockout is inert however often it fails.
        for i in 0..6 {
            let (code, _) =
                attempt_as(kdc, &alice(), "wrong", t0() + chrono::Duration::seconds(i)).await;
            assert_eq!(code, 24);
        }
        assert_eq!(attempt_as(kdc, &alice(), PW, t0()).await.0, 0);
        assert_eq!(
            attempt_as(kdc, &PrincipalName::new_principal("nobody"), PW, t0())
                .await
                .0,
            6
        );
        let tgt = login(kdc, &alice()).await;
        assert_eq!(tgs(kdc, &tgt).await.0, 0);
    }
}

// ------------------------------------------------------ store failures

struct Broken(krb5_rs::kdc::StoreError);

impl krb5_rs::kdc::PrincipalStore for Broken {
    async fn lookup(
        &self,
        _name: &PrincipalName,
        _realm: &str,
    ) -> Result<Option<PrincipalEntry>, krb5_rs::kdc::StoreError> {
        Err(self.0.clone())
    }
}

#[tokio::test]
async fn an_unreachable_or_stale_store_is_svc_unavailable_other_failures_are_generic() {
    use krb5_rs::kdc::StoreError;
    for (error, expected) in [
        (StoreError::unavailable("down"), 29),
        (StoreError::stale("old"), 29),
        (StoreError::backend("boom"), 60),
        (StoreError::corrupt("bad"), 60),
    ] {
        let kdc = Kdc::new(config(), Broken(error.clone()));
        let (code, text) = attempt_as(&kdc, &alice(), PW, t0()).await;
        assert_eq!(code, expected, "{error:?}");
        assert_eq!(text, "LOOKING_UP_CLIENT");
    }
}
