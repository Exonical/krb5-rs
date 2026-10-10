//! Principal lockout, following MIT's db2 module (plugins/kdb/db2/lockout.c).
//!
//! A principal under a [`Policy`] with `pw_max_fail` set is locked out after
//! that many consecutive failed pre-authentications within
//! `pw_failcnt_interval`, for `pw_lockout_duration` seconds (0 = until an
//! administrator unlocks it). The KDC checks before pre-authentication
//! (`krb5_db2_lockout_check_policy`, called from `validate_as_request` through
//! `krb5_db_check_policy_as`, kdc_util.c:801) and audits after every outcome
//! (`krb5_db2_lockout_audit`, called from `log_as_req`, kdc_log.c:93).
//!
//! Counters are local to one KDC (docs/architecture/kdb.md §8): they live in
//! the injected [`AuthStateStore`](super::AuthStateStore), which is
//! in-memory for the File and Memory backends and therefore not persisted.

use super::db::PrincipalEntry;
use super::error::KdcError;
use super::store::{AuthState, AuthStateUpdate, LockoutReport};
use super::{Kdc, PrincipalAttributes, PrincipalStore};
use crate::types::error_codes::*;

/// The lockout parameters of a policy (MIT `lookup_lockout_policy`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LockoutPolicy {
    /// `pw_max_fail`: 0 disables lockout.
    pub max_fail: u32,
    /// `pw_failcnt_interval`: 0 never resets the count by time.
    pub failcnt_interval: u32,
    /// `pw_lockout_duration`: 0 locks until an administrator unlocks.
    pub lockout_duration: u32,
}

/// `locked_check_p` (lockout.c:94-113, after draft-behera-ldap-password-policy
/// 7.1): is the principal locked at `now`?
pub fn locked_check_p(
    now: i64,
    policy: &LockoutPolicy,
    state: &AuthState,
    last_admin_unlock: Option<i64>,
) -> bool {
    // Unlocked by an administrator since the last failure.
    if state.last_failed <= last_admin_unlock.unwrap_or(0) {
        return false;
    }
    if policy.max_fail == 0 || state.fail_count < policy.max_fail {
        return false;
    }
    if policy.lockout_duration == 0 {
        return true;
    }
    state
        .last_failed
        .saturating_add(i64::from(policy.lockout_duration))
        > now
}

fn unlock_time(entry: &PrincipalEntry) -> Option<i64> {
    entry
        .last_admin_unlock
        .as_ref()
        .map(|t| t.timestamp())
        .filter(|&t| t != 0)
}

impl<S: PrincipalStore> Kdc<S> {
    /// `lookup_lockout_policy` (lockout.c:41-84): the entry's policy
    /// parameters, all zero without a policy. A policy that cannot be read
    /// is an unavailable service (the KDC fails closed).
    pub(super) async fn lockout_policy(
        &self,
        entry: &PrincipalEntry,
    ) -> Result<LockoutPolicy, KdcError> {
        let Some(name) = entry.policy.as_deref() else {
            return Ok(LockoutPolicy::default());
        };
        match self.policies.policy(name).await {
            Ok(Some(p)) => Ok(LockoutPolicy {
                max_fail: p.pw_max_fail,
                failcnt_interval: p.pw_failcnt_interval,
                lockout_duration: p.pw_lockout_duration,
            }),
            // A dangling policy name is treated as no policy (lockout.c:64-71
            // ignores `krb5_db2_get_policy` failures).
            Ok(None) => Ok(LockoutPolicy::default()),
            Err(_) => Err(KdcError::new(KDC_ERR_SVC_UNAVAILABLE, "LOOKING_UP_POLICY")),
        }
    }

    /// `krb5_db2_lockout_check_policy` (lockout.c:116-141) and the
    /// `LOCKED_OUT` status of `krb5_db2_check_policy_as` (kdb_db2.c:1546-1549).
    pub(super) async fn check_lockout(
        &self,
        client: &PrincipalEntry,
        now: i64,
    ) -> Result<(), KdcError> {
        if self.config.disable_lockout {
            return Ok(());
        }
        let policy = self.lockout_policy(client).await?;
        if policy.max_fail == 0 {
            return Ok(());
        }
        let state = self
            .auth_state
            .auth_state(&client.name, &client.realm)
            .await
            .map_err(|_| KdcError::new(KDC_ERR_SVC_UNAVAILABLE, "LOOKING_UP_AUTH_STATE"))?;
        if locked_check_p(now, &policy, &state, unlock_time(client)) {
            return Err(KdcError::new(KDC_ERR_CLIENT_REVOKED, "LOCKED_OUT"));
        }
        Ok(())
    }

    /// TGS-time re-check of the header ticket's local client (krb5-rs
    /// extension, docs/architecture/kdb.md §7.4; MIT's TGS path never reads
    /// the client entry): the client must not have been disabled, have
    /// expired or been locked out since the TGT was issued. The codes are
    /// those `validate_as_request` uses (kdc_util.c:740-780). The
    /// `security_epoch` is not compared: tickets carry no epoch, so epoch
    /// checks need the authoritative strict mode of the consistency gate.
    pub(super) async fn recheck_tgs_client(
        &self,
        client: &PrincipalEntry,
        now: i64,
    ) -> Result<(), KdcError> {
        if super::policy::expired(&client.expiration, now) {
            return Err(KdcError::new(KDC_ERR_NAME_EXP, "CLIENT EXPIRED"));
        }
        if client
            .attributes
            .contains(PrincipalAttributes::DISALLOW_ALL_TIX)
        {
            return Err(KdcError::new(KDC_ERR_CLIENT_REVOKED, "CLIENT LOCKED OUT"));
        }
        self.check_lockout(client, now).await
    }

    /// `krb5_db2_lockout_audit` (lockout.c:143-216): record the outcome of an
    /// AS request (`code` 0 = success). Errors are ignored, as in MIT's
    /// `krb5_db2_audit_as_req` (kdb_db2.c:1559).
    pub(super) async fn audit_as(&self, client: &PrincipalEntry, now: i64, code: i32) {
        if !matches!(code, 0 | KDC_ERR_PREAUTH_FAILED | KRB_AP_ERR_BAD_INTEGRITY) {
            return;
        }
        let policy = if self.config.disable_lockout {
            LockoutPolicy::default()
        } else {
            match self.lockout_policy(client).await {
                Ok(p) => p,
                Err(_) => return,
            }
        };
        let Ok(state) = self
            .auth_state
            .auth_state(&client.name, &client.realm)
            .await
        else {
            return;
        };
        // Don't modify the state of an already locked account (:160-166).
        if locked_check_p(now, &policy, &state, unlock_time(client)) {
            return;
        }
        let update = if code == 0
            && client
                .attributes
                .contains(PrincipalAttributes::REQUIRES_PRE_AUTH)
        {
            // Only a principal that required pre-authentication proves
            // anything on success (:168-180).
            let clear_failures = !self.config.disable_lockout && state.fail_count != 0;
            let record_success = !self.config.disable_last_success;
            if !clear_failures && !record_success {
                return;
            }
            AuthStateUpdate::Success {
                stamp: now,
                clear_failures,
                record_success,
            }
        } else if !self.config.disable_lockout
            && matches!(code, KDC_ERR_PREAUTH_FAILED | KRB_AP_ERR_BAD_INTEGRITY)
        {
            AuthStateUpdate::Failure {
                stamp: now,
                failcnt_interval: policy.failcnt_interval,
                last_admin_unlock: unlock_time(client),
            }
        } else {
            return;
        };
        let Ok(after) = self
            .auth_state
            .apply(&client.name, &client.realm, &update)
            .await
        else {
            return;
        };
        if matches!(update, AuthStateUpdate::Failure { .. })
            && locked_check_p(now, &policy, &after, unlock_time(client))
        {
            self.reporter.report(LockoutReport {
                principal: client.name.clone(),
                realm: client.realm.clone(),
                stamp: now,
                fail_count: after.fail_count,
                lockout_duration: policy.lockout_duration,
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state(count: u32, last_failed: i64) -> AuthState {
        AuthState {
            fail_count: count,
            last_failed,
            last_success: 0,
        }
    }

    const POLICY: LockoutPolicy = LockoutPolicy {
        max_fail: 3,
        failcnt_interval: 60,
        lockout_duration: 100,
    };

    #[test]
    fn locked_only_at_the_threshold_and_until_the_duration_ends() {
        assert!(!locked_check_p(1000, &POLICY, &state(2, 990), None));
        assert!(locked_check_p(1000, &POLICY, &state(3, 990), None));
        // last_failed + duration > now: 990 + 100 = 1090.
        assert!(locked_check_p(1089, &POLICY, &state(5, 990), None));
        assert!(!locked_check_p(1090, &POLICY, &state(5, 990), None));
    }

    #[test]
    fn zero_duration_is_permanent_and_zero_max_fail_disables() {
        let permanent = LockoutPolicy {
            lockout_duration: 0,
            ..POLICY
        };
        assert!(locked_check_p(
            i64::MAX / 2,
            &permanent,
            &state(3, 990),
            None
        ));
        let off = LockoutPolicy {
            max_fail: 0,
            ..POLICY
        };
        assert!(!locked_check_p(1000, &off, &state(99, 990), None));
    }

    #[test]
    fn an_admin_unlock_after_the_last_failure_unlocks() {
        assert!(!locked_check_p(1000, &POLICY, &state(3, 990), Some(990)));
        assert!(!locked_check_p(1000, &POLICY, &state(3, 990), Some(995)));
        assert!(locked_check_p(1000, &POLICY, &state(3, 990), Some(989)));
    }
}
