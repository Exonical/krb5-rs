//! Store interfaces of the KDC (docs/architecture/kdb.md §3).
//!
//! Every trait is async with native `impl Future` return types (no
//! `async-trait`), `Send + Sync`, and reports structured [`StoreError`]s that
//! carry no backend types. The KDC takes the principal store as a generic
//! parameter and the remaining services as type-erased trait objects built by
//! [`crate::kdc::KdcBuilder`]; the erasure adapters live in this module and are
//! private, so there is exactly one public family of traits.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use super::db::{store_key, PrincipalEntry, StoreKey};
use crate::types::{KerberosTime, PrincipalName};

/// Why a store operation failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreErrorKind {
    /// The entity does not exist.
    NotFound,
    /// The operation conflicts with existing state (duplicate, concurrent
    /// modification).
    Conflict,
    /// The backend cannot be reached or is locked right now.
    Unavailable,
    /// Stored data is damaged or unreadable.
    Corrupt,
    /// The data is older than the caller may accept.
    Stale,
    /// The request violates policy: password quality or history, or a
    /// protected principal (kadm5 `KADM5_PASS_*`, `KADM5_PROTECT_PRINCIPAL`).
    Rejected,
    /// Any other backend failure.
    Backend,
    /// The store does not implement the operation
    /// (`KRB5_PLUGIN_OP_NOTSUPP`).
    Unsupported,
    /// The principal a certificate maps to is not the requested one
    /// (`KRB5KDC_ERR_CLIENT_NAME_MISMATCH`).
    NameMismatch,
}

/// Store error: a [`StoreErrorKind`] plus a message. No backend types.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("principal store error: {message}")]
pub struct StoreError {
    kind: StoreErrorKind,
    message: String,
}

impl StoreError {
    /// An error of `kind`.
    pub fn new(kind: StoreErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }

    /// A [`StoreErrorKind::Backend`] error.
    pub fn backend(message: impl Into<String>) -> Self {
        Self::new(StoreErrorKind::Backend, message)
    }

    /// A [`StoreErrorKind::NotFound`] error.
    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new(StoreErrorKind::NotFound, message)
    }

    /// A [`StoreErrorKind::Conflict`] error.
    pub fn conflict(message: impl Into<String>) -> Self {
        Self::new(StoreErrorKind::Conflict, message)
    }

    /// A [`StoreErrorKind::Unavailable`] error.
    pub fn unavailable(message: impl Into<String>) -> Self {
        Self::new(StoreErrorKind::Unavailable, message)
    }

    /// A [`StoreErrorKind::Corrupt`] error.
    pub fn corrupt(message: impl Into<String>) -> Self {
        Self::new(StoreErrorKind::Corrupt, message)
    }

    /// A [`StoreErrorKind::Stale`] error.
    pub fn stale(message: impl Into<String>) -> Self {
        Self::new(StoreErrorKind::Stale, message)
    }

    /// A [`StoreErrorKind::Rejected`] error.
    pub fn rejected(message: impl Into<String>) -> Self {
        Self::new(StoreErrorKind::Rejected, message)
    }

    /// The failure category.
    pub fn kind(&self) -> StoreErrorKind {
        self.kind
    }

    /// The message.
    pub fn message(&self) -> &str {
        &self.message
    }
}

/// A password/lockout policy (MIT `osa_policy_ent_rec`, kdb.h:213-235;
/// kadmin `add_policy`, kadmin.c:1646-1695). Times are seconds; zero means
/// "not set" as in MIT.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Policy {
    /// Policy name.
    pub name: String,
    /// Minimum password life.
    pub pw_min_life: u32,
    /// Maximum password life.
    pub pw_max_life: u32,
    /// Minimum password length.
    pub pw_min_length: u32,
    /// Minimum number of character classes.
    pub pw_min_classes: u32,
    /// Number of old keys kept.
    pub pw_history_num: u32,
    /// Failures before lockout (`pw_max_fail`, 0 = never lock).
    pub pw_max_fail: u32,
    /// Failure count reset interval (`pw_failcnt_interval`, 0 = never reset).
    pub pw_failcnt_interval: u32,
    /// Lockout duration (`pw_lockout_duration`, 0 = until an admin unlocks).
    pub pw_lockout_duration: u32,
    /// Policy attributes.
    pub attributes: u32,
    /// Maximum ticket life applied by kadmin (0 = none).
    pub max_life: u32,
    /// Maximum renewable life applied by kadmin (0 = none).
    pub max_renewable_life: u32,
    /// Allowed key/salt types (`-allowedkeysalts`).
    pub allowed_keysalts: Option<String>,
    /// Bumped by every change to the policy (krb5-rs; docs/architecture §3).
    pub security_epoch: u64,
}

/// Per-principal authentication state that is local to one KDC and never
/// replicated (MIT `krb5_db_entry` `last_success`, `last_failed`,
/// `fail_auth_count`; docs/architecture §8). Times are Unix seconds, 0 = never.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AuthState {
    /// Consecutive failures counted so far.
    pub fail_count: u32,
    /// Time of the last failed attempt.
    pub last_failed: i64,
    /// Time of the last successful authentication.
    pub last_success: i64,
}

/// A change to an [`AuthState`] (the two branches of MIT
/// `krb5_db2_lockout_audit`, lockout.c:178-208).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthStateUpdate {
    /// A successful authentication of a principal that requires
    /// pre-authentication.
    Success {
        /// Time of the event.
        stamp: i64,
        /// Reset the failure count (lockout enabled).
        clear_failures: bool,
        /// Record `last_success` (`disable_last_success` unset).
        record_success: bool,
    },
    /// A failed pre-authentication or integrity check.
    Failure {
        /// Time of the event.
        stamp: i64,
        /// The policy's `pw_failcnt_interval`.
        failcnt_interval: u32,
        /// The principal's last administrative unlock.
        last_admin_unlock: Option<i64>,
    },
}

impl AuthState {
    /// Apply `update` (lockout.c:186-206). Backends call this under their own
    /// atomicity so concurrent failures are all counted.
    pub fn apply(&mut self, update: &AuthStateUpdate) {
        match *update {
            AuthStateUpdate::Success {
                stamp,
                clear_failures,
                record_success,
            } => {
                if clear_failures && self.fail_count != 0 {
                    self.fail_count = 0;
                }
                if record_success {
                    self.last_success = stamp;
                }
            }
            AuthStateUpdate::Failure {
                stamp,
                failcnt_interval,
                last_admin_unlock,
            } => {
                // Reset after an administrative unlock.
                if last_admin_unlock.is_some_and(|u| self.last_failed <= u) {
                    self.fail_count = 0;
                }
                // Reset after the failure count interval.
                if failcnt_interval != 0
                    && stamp > self.last_failed.saturating_add(i64::from(failcnt_interval))
                {
                    self.fail_count = 0;
                }
                self.last_failed = stamp;
                self.fail_count = self.fail_count.saturating_add(1);
            }
        }
    }
}

/// The authoritative view of a principal's security state, used by the
/// consistency gate in strict mode (docs/architecture §7.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SecurityState {
    /// `security_epoch`.
    pub epoch: u64,
    /// The principal is disabled.
    pub disabled: bool,
    /// The principal is locked out.
    pub locked: bool,
}

/// A lockout that tripped on this KDC, reported to the authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockoutReport {
    /// The locked principal.
    pub principal: PrincipalName,
    /// Its realm.
    pub realm: String,
    /// When the threshold was reached.
    pub stamp: i64,
    /// Failure count at that point.
    pub fail_count: u32,
    /// The policy's lockout duration (0 = permanent).
    pub lockout_duration: u32,
}

/// The role a principal plays in the request being gated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrincipalRole {
    /// The request's client or impersonated subject.
    Client,
    /// The requested service.
    Server,
}

/// A principal the consistency gate must check, together with its role.
#[derive(Debug, Clone, Copy)]
pub struct GateSubject<'a> {
    /// The local principal entry.
    pub entry: &'a PrincipalEntry,
    /// The principal's role in the request.
    pub role: PrincipalRole,
}

/// Why the authority refuses a principal outright.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthoritativeDenial {
    /// The principal is disabled at the authority.
    Disabled,
    /// The client is locked out at the authority.
    LockedOut,
    /// The principal was deleted at the authority.
    Deleted,
}

/// The consistency gate's verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GateDecision {
    /// Issue the ticket.
    Allow,
    /// Refuse with `KDC_ERR_SVC_UNAVAILABLE`; `reason` becomes the status
    /// text (for example `REPLICA_STALE`, `AUTHORITATIVE_MISMATCH`).
    Reject {
        /// Status text.
        reason: String,
    },
    /// The authority's state for `subjects[index]` is final.
    Deny {
        /// The refused subject's index in the checked slice.
        index: usize,
        /// Why the authority refuses the subject.
        denial: AuthoritativeDenial,
    },
}

/// Read access to the principal database.
pub trait PrincipalStore: Send + Sync {
    /// Look up a principal; name comparison ignores the name type (MIT
    /// princ_comp.c).
    fn lookup(
        &self,
        name: &PrincipalName,
        realm: &str,
    ) -> impl Future<Output = Result<Option<PrincipalEntry>, StoreError>> + Send;

    /// The client a certificate identifies (MIT `get_s4u_x509_principal`,
    /// kdb.h): `name@realm` is the requested client, with no components when
    /// only the certificate identifies it. With `referral_ok` (AS requests)
    /// the entry may be in another realm, a client referral; otherwise a
    /// named client that is not the certificate's principal is
    /// [`StoreErrorKind::NameMismatch`]. Stores without certificate lookup,
    /// like MIT db2 and LMDB, return [`StoreErrorKind::Unsupported`].
    fn lookup_s4u_x509(
        &self,
        cert: &[u8],
        name: &PrincipalName,
        realm: &str,
        referral_ok: bool,
    ) -> impl Future<Output = Result<Option<PrincipalEntry>, StoreError>> + Send {
        let _ = (cert, name, realm, referral_ok);
        std::future::ready(Err(StoreError::new(
            StoreErrorKind::Unsupported,
            "get_s4u_x509_principal is not supported",
        )))
    }
}

/// Read access to policies (MIT `krb5_db_get_policy`).
pub trait PolicyStore: Send + Sync {
    /// The policy called `name`, if any.
    fn policy(&self, name: &str)
        -> impl Future<Output = Result<Option<Policy>, StoreError>> + Send;
}

/// Local per-KDC authentication state (docs/architecture §8).
pub trait AuthStateStore: Send + Sync {
    /// The current state (all zero for an unknown principal).
    fn auth_state(
        &self,
        name: &PrincipalName,
        realm: &str,
    ) -> impl Future<Output = Result<AuthState, StoreError>> + Send;

    /// Atomically apply `update` and return the new state.
    fn apply(
        &self,
        name: &PrincipalName,
        realm: &str,
        update: &AuthStateUpdate,
    ) -> impl Future<Output = Result<AuthState, StoreError>> + Send;
}

/// A database record: the principal plus bookkeeping the KDC does not use.
#[derive(Debug, Clone)]
pub struct PrincipalRecord {
    /// The principal as the KDC sees it (keys decrypted).
    pub entry: PrincipalEntry,
    /// Last password change.
    pub last_pwd_change: Option<KerberosTime>,
    /// Last modification (set by the store on every write).
    pub mod_time: Option<KerberosTime>,
    /// MIT unparsed modifier principal bytes from `KRB5_TL_MOD_PRINC`, when
    /// the backend represents it.
    pub mod_by: Option<Vec<u8>>,
    /// kadm5 password history; `None` when the backend does not store it
    /// (the file and CockroachDB stores), which then ignore it on write.
    pub password_history: Option<PasswordHistory>,
}

/// kadm5 password history, the `osa_princ_ent_rec` old-key queue
/// (`lib/kadm5/srv/adb_xdr.c:55-96`, `svr_principal.c:1064-1208`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PasswordHistory {
    /// kvno of the `kadmin/history` key the entries are encrypted in.
    pub admin_history_kvno: u32,
    /// Index in `old_keys` where the next entry is written.
    pub old_key_next: u32,
    /// One entry per old password: its keys as MIT key-data, encrypted in
    /// the `kadmin/history` key.
    pub old_keys: Vec<Vec<crate::kdc::kdb::mit::KeyData>>,
}

/// Administrative access to the authoritative store (docs/architecture §3).
///
/// Every mutation is atomic. The `update_*` operations are a transactional
/// read-modify-write: the closure sees the current state and edits it, and the
/// store commits the result, re-running the closure if the transaction has to
/// be retried (so it must be repeatable). The closure is `Send + 'static` so
/// LMDB can execute the write transaction in `spawn_blocking`. The store sets
/// `mod_time` itself.
pub trait AdminStore: Send + Sync {
    /// The principal's record, if it exists.
    fn get_record(
        &self,
        name: &PrincipalName,
        realm: &str,
    ) -> impl Future<Output = Result<Option<PrincipalRecord>, StoreError>> + Send;

    /// Insert a new principal; [`StoreErrorKind::Conflict`] if it exists.
    fn create_principal(
        &self,
        entry: PrincipalEntry,
        last_pwd_change: Option<KerberosTime>,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;

    /// Read-modify-write one principal; [`StoreErrorKind::NotFound`] if it
    /// does not exist. Returns the stored record.
    fn update_principal<F>(
        &self,
        name: &PrincipalName,
        realm: &str,
        f: F,
    ) -> impl Future<Output = Result<PrincipalRecord, StoreError>> + Send
    where
        F: FnMut(&mut PrincipalRecord) -> Result<(), StoreError> + Send + 'static;

    /// Delete a principal; returns whether it existed.
    fn delete_principal(
        &self,
        name: &PrincipalName,
        realm: &str,
    ) -> impl Future<Output = Result<bool, StoreError>> + Send;

    /// Every principal's record.
    fn list_principals(
        &self,
    ) -> impl Future<Output = Result<Vec<PrincipalRecord>, StoreError>> + Send;

    /// The policy, if it exists.
    fn get_policy(
        &self,
        name: &str,
    ) -> impl Future<Output = Result<Option<Policy>, StoreError>> + Send;

    /// Insert a new policy; [`StoreErrorKind::Conflict`] if it exists.
    fn create_policy(&self, policy: Policy) -> impl Future<Output = Result<(), StoreError>> + Send;

    /// Read-modify-write one policy; [`StoreErrorKind::NotFound`] if missing.
    fn update_policy<F>(
        &self,
        name: &str,
        f: F,
    ) -> impl Future<Output = Result<Policy, StoreError>> + Send
    where
        F: FnMut(&mut Policy) -> Result<(), StoreError> + Send + 'static;

    /// Delete a policy; returns whether it existed.
    fn delete_policy(&self, name: &str) -> impl Future<Output = Result<bool, StoreError>> + Send;

    /// Every policy, sorted by name.
    fn list_policies(&self) -> impl Future<Output = Result<Vec<Policy>, StoreError>> + Send;
}

/// The authority's view of a principal, for strict consistency.
pub trait AuthoritativeState: Send + Sync {
    /// The principal's authoritative security state.
    fn security_state(
        &self,
        name: &PrincipalName,
        realm: &str,
    ) -> impl Future<Output = Result<SecurityState, StoreError>> + Send;
}

/// Reports tripped lockouts to the authority. Fire and forget: `report` must
/// not block and must not fail the request.
pub trait LockoutReporter: Send + Sync {
    /// Queue `report`.
    fn report(&self, report: LockoutReport);
}

/// Liveness/readiness input of a backend.
pub trait HealthCheck: Send + Sync {
    /// `Ok` if the backend is usable.
    fn health(&self) -> impl Future<Output = Result<(), StoreError>> + Send;
}

/// Decides whether the KDC may issue tickets involving `subjects` right
/// now (docs/architecture §7): replica freshness, authoritative epochs.
pub trait ConsistencyGate: Send + Sync {
    /// Check the principals and their roles in a request.
    fn check(&self, subjects: &[GateSubject<'_>]) -> impl Future<Output = GateDecision> + Send;
}

// ----------------------------------------------------------- Arc forwarding

impl<T: PrincipalStore + ?Sized> PrincipalStore for Arc<T> {
    fn lookup(
        &self,
        name: &PrincipalName,
        realm: &str,
    ) -> impl Future<Output = Result<Option<PrincipalEntry>, StoreError>> + Send {
        (**self).lookup(name, realm)
    }

    fn lookup_s4u_x509(
        &self,
        cert: &[u8],
        name: &PrincipalName,
        realm: &str,
        referral_ok: bool,
    ) -> impl Future<Output = Result<Option<PrincipalEntry>, StoreError>> + Send {
        (**self).lookup_s4u_x509(cert, name, realm, referral_ok)
    }
}

impl<T: PolicyStore + ?Sized> PolicyStore for Arc<T> {
    fn policy(
        &self,
        name: &str,
    ) -> impl Future<Output = Result<Option<Policy>, StoreError>> + Send {
        (**self).policy(name)
    }
}

impl<T: AuthStateStore + ?Sized> AuthStateStore for Arc<T> {
    fn auth_state(
        &self,
        name: &PrincipalName,
        realm: &str,
    ) -> impl Future<Output = Result<AuthState, StoreError>> + Send {
        (**self).auth_state(name, realm)
    }

    fn apply(
        &self,
        name: &PrincipalName,
        realm: &str,
        update: &AuthStateUpdate,
    ) -> impl Future<Output = Result<AuthState, StoreError>> + Send {
        (**self).apply(name, realm, update)
    }
}

impl<T: AdminStore + ?Sized> AdminStore for Arc<T> {
    fn get_record(
        &self,
        name: &PrincipalName,
        realm: &str,
    ) -> impl Future<Output = Result<Option<PrincipalRecord>, StoreError>> + Send {
        (**self).get_record(name, realm)
    }

    fn create_principal(
        &self,
        entry: PrincipalEntry,
        last_pwd_change: Option<KerberosTime>,
    ) -> impl Future<Output = Result<(), StoreError>> + Send {
        (**self).create_principal(entry, last_pwd_change)
    }

    fn update_principal<F>(
        &self,
        name: &PrincipalName,
        realm: &str,
        f: F,
    ) -> impl Future<Output = Result<PrincipalRecord, StoreError>> + Send
    where
        F: FnMut(&mut PrincipalRecord) -> Result<(), StoreError> + Send + 'static,
    {
        (**self).update_principal(name, realm, f)
    }

    fn delete_principal(
        &self,
        name: &PrincipalName,
        realm: &str,
    ) -> impl Future<Output = Result<bool, StoreError>> + Send {
        (**self).delete_principal(name, realm)
    }

    fn list_principals(
        &self,
    ) -> impl Future<Output = Result<Vec<PrincipalRecord>, StoreError>> + Send {
        (**self).list_principals()
    }

    fn get_policy(
        &self,
        name: &str,
    ) -> impl Future<Output = Result<Option<Policy>, StoreError>> + Send {
        (**self).get_policy(name)
    }

    fn create_policy(&self, policy: Policy) -> impl Future<Output = Result<(), StoreError>> + Send {
        (**self).create_policy(policy)
    }

    fn update_policy<F>(
        &self,
        name: &str,
        f: F,
    ) -> impl Future<Output = Result<Policy, StoreError>> + Send
    where
        F: FnMut(&mut Policy) -> Result<(), StoreError> + Send + 'static,
    {
        (**self).update_policy(name, f)
    }

    fn delete_policy(&self, name: &str) -> impl Future<Output = Result<bool, StoreError>> + Send {
        (**self).delete_policy(name)
    }

    fn list_policies(&self) -> impl Future<Output = Result<Vec<Policy>, StoreError>> + Send {
        (**self).list_policies()
    }
}

impl<T: AdminStore + ?Sized> AdminStore for &T {
    fn get_record(
        &self,
        name: &PrincipalName,
        realm: &str,
    ) -> impl Future<Output = Result<Option<PrincipalRecord>, StoreError>> + Send {
        (**self).get_record(name, realm)
    }

    fn create_principal(
        &self,
        entry: PrincipalEntry,
        last_pwd_change: Option<KerberosTime>,
    ) -> impl Future<Output = Result<(), StoreError>> + Send {
        (**self).create_principal(entry, last_pwd_change)
    }

    fn update_principal<F>(
        &self,
        name: &PrincipalName,
        realm: &str,
        f: F,
    ) -> impl Future<Output = Result<PrincipalRecord, StoreError>> + Send
    where
        F: FnMut(&mut PrincipalRecord) -> Result<(), StoreError> + Send + 'static,
    {
        (**self).update_principal(name, realm, f)
    }

    fn delete_principal(
        &self,
        name: &PrincipalName,
        realm: &str,
    ) -> impl Future<Output = Result<bool, StoreError>> + Send {
        (**self).delete_principal(name, realm)
    }

    fn list_principals(
        &self,
    ) -> impl Future<Output = Result<Vec<PrincipalRecord>, StoreError>> + Send {
        (**self).list_principals()
    }

    fn get_policy(
        &self,
        name: &str,
    ) -> impl Future<Output = Result<Option<Policy>, StoreError>> + Send {
        (**self).get_policy(name)
    }

    fn create_policy(&self, policy: Policy) -> impl Future<Output = Result<(), StoreError>> + Send {
        (**self).create_policy(policy)
    }

    fn update_policy<F>(
        &self,
        name: &str,
        f: F,
    ) -> impl Future<Output = Result<Policy, StoreError>> + Send
    where
        F: FnMut(&mut Policy) -> Result<(), StoreError> + Send + 'static,
    {
        (**self).update_policy(name, f)
    }

    fn delete_policy(&self, name: &str) -> impl Future<Output = Result<bool, StoreError>> + Send {
        (**self).delete_policy(name)
    }

    fn list_policies(&self) -> impl Future<Output = Result<Vec<Policy>, StoreError>> + Send {
        (**self).list_policies()
    }
}

impl<T: AuthoritativeState + ?Sized> AuthoritativeState for Arc<T> {
    fn security_state(
        &self,
        name: &PrincipalName,
        realm: &str,
    ) -> impl Future<Output = Result<SecurityState, StoreError>> + Send {
        (**self).security_state(name, realm)
    }
}

impl<T: LockoutReporter + ?Sized> LockoutReporter for Arc<T> {
    fn report(&self, report: LockoutReport) {
        (**self).report(report)
    }
}

impl<T: HealthCheck + ?Sized> HealthCheck for Arc<T> {
    fn health(&self) -> impl Future<Output = Result<(), StoreError>> + Send {
        (**self).health()
    }
}

impl<T: ConsistencyGate + ?Sized> ConsistencyGate for Arc<T> {
    fn check(&self, subjects: &[GateSubject<'_>]) -> impl Future<Output = GateDecision> + Send {
        (**self).check(subjects)
    }
}

// ------------------------------------------------------- default services

/// No policies exist: the [`KdcBuilder`](crate::kdc::KdcBuilder) default, which
/// makes lockout inert (MIT `lookup_lockout_policy` without a policy).
#[derive(Debug, Clone, Copy, Default)]
pub struct NoPolicies;

impl PolicyStore for NoPolicies {
    fn policy(
        &self,
        _name: &str,
    ) -> impl Future<Output = Result<Option<Policy>, StoreError>> + Send {
        std::future::ready(Ok(None))
    }
}

/// The gate that always allows (the default).
#[derive(Debug, Clone, Copy, Default)]
pub struct AlwaysAllow;

impl ConsistencyGate for AlwaysAllow {
    fn check(&self, _subjects: &[GateSubject<'_>]) -> impl Future<Output = GateDecision> + Send {
        std::future::ready(GateDecision::Allow)
    }
}

/// A reporter that drops every report (the default).
#[derive(Debug, Clone, Copy, Default)]
pub struct NoopLockoutReporter;

impl LockoutReporter for NoopLockoutReporter {
    fn report(&self, _report: LockoutReport) {}
}

/// In-memory [`AuthStateStore`]: the state of the File and Memory backends. It
/// is **not persisted**: failure counters and `last_success` reset when the
/// process restarts (administrative unlocks and policies are persisted by the
/// principal database and still apply).
#[derive(Debug, Default)]
pub struct MemoryAuthState {
    states: Mutex<HashMap<StoreKey, AuthState>>,
}

impl MemoryAuthState {
    /// An empty state store.
    pub fn new() -> Self {
        Self::default()
    }

    fn with<R>(&self, f: impl FnOnce(&mut HashMap<StoreKey, AuthState>) -> R) -> R {
        f(&mut self.states.lock().unwrap_or_else(|e| e.into_inner()))
    }
}

impl AuthStateStore for MemoryAuthState {
    fn auth_state(
        &self,
        name: &PrincipalName,
        realm: &str,
    ) -> impl Future<Output = Result<AuthState, StoreError>> + Send {
        let state = self.with(|m| m.get(&store_key(name, realm)).copied().unwrap_or_default());
        std::future::ready(Ok(state))
    }

    fn apply(
        &self,
        name: &PrincipalName,
        realm: &str,
        update: &AuthStateUpdate,
    ) -> impl Future<Output = Result<AuthState, StoreError>> + Send {
        let state = self.with(|m| {
            let entry = m.entry(store_key(name, realm)).or_default();
            entry.apply(update);
            *entry
        });
        std::future::ready(Ok(state))
    }
}

// ----------------------------------------------------- erased (private) forms

pub(crate) type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Object-safe adapter over [`PolicyStore`].
pub(crate) trait DynPolicies: Send + Sync {
    fn policy<'a>(&'a self, name: &'a str) -> BoxFuture<'a, Result<Option<Policy>, StoreError>>;
}

impl<T: PolicyStore> DynPolicies for T {
    fn policy<'a>(&'a self, name: &'a str) -> BoxFuture<'a, Result<Option<Policy>, StoreError>> {
        Box::pin(PolicyStore::policy(self, name))
    }
}

/// Object-safe adapter over [`AuthStateStore`].
pub(crate) trait DynAuthState: Send + Sync {
    fn auth_state<'a>(
        &'a self,
        name: &'a PrincipalName,
        realm: &'a str,
    ) -> BoxFuture<'a, Result<AuthState, StoreError>>;

    fn apply<'a>(
        &'a self,
        name: &'a PrincipalName,
        realm: &'a str,
        update: &'a AuthStateUpdate,
    ) -> BoxFuture<'a, Result<AuthState, StoreError>>;
}

impl<T: AuthStateStore> DynAuthState for T {
    fn auth_state<'a>(
        &'a self,
        name: &'a PrincipalName,
        realm: &'a str,
    ) -> BoxFuture<'a, Result<AuthState, StoreError>> {
        Box::pin(AuthStateStore::auth_state(self, name, realm))
    }

    fn apply<'a>(
        &'a self,
        name: &'a PrincipalName,
        realm: &'a str,
        update: &'a AuthStateUpdate,
    ) -> BoxFuture<'a, Result<AuthState, StoreError>> {
        Box::pin(AuthStateStore::apply(self, name, realm, update))
    }
}

/// Object-safe adapter over [`ConsistencyGate`].
pub(crate) trait DynGate: Send + Sync {
    fn check<'a>(&'a self, subjects: &'a [GateSubject<'a>]) -> BoxFuture<'a, GateDecision>;
}

impl<T: ConsistencyGate> DynGate for T {
    fn check<'a>(&'a self, subjects: &'a [GateSubject<'a>]) -> BoxFuture<'a, GateDecision> {
        Box::pin(ConsistencyGate::check(self, subjects))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn store_errors_carry_a_kind_and_the_legacy_text() {
        let e = StoreError::conflict("Principal or policy already exists: a@R");
        assert_eq!(e.kind(), StoreErrorKind::Conflict);
        assert_eq!(
            e.to_string(),
            "principal store error: Principal or policy already exists: a@R"
        );
        assert_eq!(StoreError::backend("x").kind(), StoreErrorKind::Backend);
    }

    #[test]
    fn failures_count_and_reset_per_mit_lockout_audit() {
        let mut s = AuthState::default();
        let fail = |stamp, interval, unlock| AuthStateUpdate::Failure {
            stamp,
            failcnt_interval: interval,
            last_admin_unlock: unlock,
        };
        s.apply(&fail(100, 60, None));
        s.apply(&fail(110, 60, None));
        assert_eq!((s.fail_count, s.last_failed), (2, 110));
        // Within the interval the count keeps growing; past it, it restarts.
        s.apply(&fail(170, 60, None));
        assert_eq!(s.fail_count, 3);
        s.apply(&fail(231, 60, None));
        assert_eq!(s.fail_count, 1);
        // interval 0 never resets.
        s.apply(&fail(1_000_000, 0, None));
        assert_eq!(s.fail_count, 2);
        // An administrative unlock at or after the last failure resets.
        s.apply(&fail(1_000_010, 0, Some(1_000_000)));
        assert_eq!(s.fail_count, 1);
        // An unlock older than the last failure does not.
        s.apply(&fail(1_000_020, 0, Some(1_000_000)));
        assert_eq!(s.fail_count, 2);
        s.apply(&fail(1_000_030, 0, Some(1_000_020)));
        assert_eq!(s.fail_count, 1);
    }

    #[test]
    fn success_clears_failures_and_records_last_success_independently() {
        let mut s = AuthState {
            fail_count: 3,
            last_failed: 5,
            last_success: 0,
        };
        s.apply(&AuthStateUpdate::Success {
            stamp: 50,
            clear_failures: false,
            record_success: true,
        });
        assert_eq!((s.fail_count, s.last_success), (3, 50));
        s.apply(&AuthStateUpdate::Success {
            stamp: 60,
            clear_failures: true,
            record_success: false,
        });
        assert_eq!((s.fail_count, s.last_success), (0, 50));
    }
}
