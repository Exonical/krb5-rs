//! kadm5_hook modules (`lib/kadm5/srv/kadm5_hook.c`, `kadm5_hook_plugin.h`):
//! each principal change is offered to every module before it is committed
//! (`PRECOMMIT`, where a failure aborts the change) and after it is
//! committed (`POSTCOMMIT`, where a failure is only logged).

use super::kadm5::code;
use super::pwqual::{stderr_logger, Logger};
use crate::kdc::store::StoreError;

/// `enum kadm5_hook_stage`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    /// `KADM5_HOOK_STAGE_PRECOMMIT`.
    Precommit = 0,
    /// `KADM5_HOOK_STAGE_POSTCOMMIT`.
    Postcommit = 1,
}

/// The `kadm5_principal_ent_t` fields a create or modify hook sees: the
/// principal as requested, with `mask` naming the fields the request set.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HookPrinc {
    /// The unparsed principal name.
    pub principal: String,
    /// `KADM5_*` principal mask of the request.
    pub mask: i32,
    /// Principal attributes (`KRB5_KDB_*`).
    pub attributes: u32,
    /// Maximum ticket life, seconds.
    pub max_life: u32,
    /// Maximum renewable life, seconds.
    pub max_renewable_life: u32,
    /// Principal expiration, seconds since the epoch.
    pub princ_expire_time: u32,
    /// Password expiration, seconds since the epoch.
    pub pw_expiration: u32,
    /// The password policy, if any.
    pub policy: Option<String>,
}

/// A key/salt pair (`krb5_key_salt_tuple`): MIT enctype and salt type.
pub type KeySaltTuple = (i32, i32);

/// A kadm5_hook module (`kadm5_hook_vftable_1`). Every callback defaults to
/// "not implemented", which MIT treats as success. A failure is a kadm5 or
/// com_err code.
#[allow(unused_variables)]
pub trait Kadm5Hook: Send + Sync {
    /// The module name used by `enable_only` and `disable`.
    fn name(&self) -> &str;

    /// `chpass`: a password change (`password` set) or key randomization.
    fn chpass(
        &self,
        stage: Stage,
        princ: &str,
        keepold: bool,
        ks: &[KeySaltTuple],
        password: Option<&str>,
    ) -> Result<(), u32> {
        Ok(())
    }

    /// `create`: a new principal.
    fn create(
        &self,
        stage: Stage,
        ent: &HookPrinc,
        ks: &[KeySaltTuple],
        password: Option<&str>,
    ) -> Result<(), u32> {
        Ok(())
    }

    /// `modify`: a principal modification.
    fn modify(&self, stage: Stage, ent: &HookPrinc) -> Result<(), u32> {
        Ok(())
    }

    /// `remove`: a principal deletion.
    fn remove(&self, stage: Stage, princ: &str) -> Result<(), u32> {
        Ok(())
    }

    /// `rename`: a principal rename.
    fn rename(&self, stage: Stage, from: &str, to: &str) -> Result<(), u32> {
        Ok(())
    }

    /// `alias`: a new alias for `target`.
    fn alias(&self, stage: Stage, alias: &str, target: &str) -> Result<(), u32> {
        Ok(())
    }
}

/// The enabled kadm5_hook modules, in order.
pub struct Kadm5Hooks {
    modules: Vec<Box<dyn Kadm5Hook>>,
    log: Logger,
}

impl Default for Kadm5Hooks {
    fn default() -> Self {
        Self::new(Vec::new(), stderr_logger())
    }
}

impl std::fmt::Debug for Kadm5Hooks {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_list()
            .entries(self.modules.iter().map(|m| m.name()))
            .finish()
    }
}

impl Kadm5Hooks {
    /// `modules`, in order, logging postcommit failures to `log`.
    #[must_use]
    pub fn new(modules: Vec<Box<dyn Kadm5Hook>>, log: Logger) -> Self {
        Self { modules, log }
    }

    /// The module names, in order.
    #[must_use]
    pub fn names(&self) -> Vec<&str> {
        self.modules.iter().map(|m| m.name()).collect()
    }

    /// `ITERATE` (`kadm5_hook.c:118-133`): call `f` on every module. At
    /// precommit the first failure is returned; at postcommit failures are
    /// logged as `log_failure` does and the rest still run.
    pub fn run(
        &self,
        stage: Stage,
        operation: &str,
        f: impl Fn(&dyn Kadm5Hook) -> Result<(), u32>,
    ) -> Result<(), StoreError> {
        for m in &self.modules {
            if let Err(c) = f(m.as_ref()) {
                let msg = code::message(c);
                if stage == Stage::Precommit {
                    return Err(StoreError::rejected(msg).with_code(c));
                }
                (self.log)(&format!(
                    "kadm5_hook {} failed postcommit {operation}: {msg}",
                    m.name()
                ));
            }
        }
        Ok(())
    }

    /// `k5_kadm5_hook_chpass`.
    pub fn chpass(
        &self,
        stage: Stage,
        princ: &str,
        keepold: bool,
        ks: &[KeySaltTuple],
        password: Option<&str>,
    ) -> Result<(), StoreError> {
        self.run(stage, "chpass", |m| {
            m.chpass(stage, princ, keepold, ks, password)
        })
    }

    /// `k5_kadm5_hook_create`.
    pub fn create(
        &self,
        stage: Stage,
        ent: &HookPrinc,
        ks: &[KeySaltTuple],
        password: Option<&str>,
    ) -> Result<(), StoreError> {
        self.run(stage, "create", |m| m.create(stage, ent, ks, password))
    }

    /// `k5_kadm5_hook_modify`.
    pub fn modify(&self, stage: Stage, ent: &HookPrinc) -> Result<(), StoreError> {
        self.run(stage, "modify", |m| m.modify(stage, ent))
    }

    /// `k5_kadm5_hook_remove`.
    pub fn remove(&self, stage: Stage, princ: &str) -> Result<(), StoreError> {
        self.run(stage, "remove", |m| m.remove(stage, princ))
    }

    /// `k5_kadm5_hook_rename`.
    pub fn rename(&self, stage: Stage, from: &str, to: &str) -> Result<(), StoreError> {
        self.run(stage, "rename", |m| m.rename(stage, from, to))
    }

    /// `k5_kadm5_hook_alias`.
    pub fn alias(&self, stage: Stage, alias: &str, target: &str) -> Result<(), StoreError> {
        self.run(stage, "alias", |m| m.alias(stage, alias, target))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    struct Refuse(&'static str, u32);

    impl Kadm5Hook for Refuse {
        fn name(&self) -> &str {
            self.0
        }
        fn remove(&self, _: Stage, _: &str) -> Result<(), u32> {
            Err(self.1)
        }
    }

    #[test]
    fn precommit_failure_aborts_and_postcommit_failure_is_logged() {
        let logged = Arc::new(Mutex::new(Vec::new()));
        let l = logged.clone();
        let hooks = Kadm5Hooks::new(
            vec![
                Box::new(Refuse("a", code::PASS_Q_DICT)),
                Box::new(Refuse("b", code::FAILURE)),
            ],
            Arc::new(move |m| l.lock().expect("test").push(m.to_string())),
        );
        let e = hooks.remove(Stage::Precommit, "p@R").expect_err("refused");
        assert_eq!(e.code(), Some(code::PASS_Q_DICT));
        assert!(logged.lock().expect("test").is_empty());
        hooks.remove(Stage::Postcommit, "p@R").expect("test");
        assert_eq!(
            *logged.lock().expect("test"),
            [
                "kadm5_hook a failed postcommit remove: Password is in the password dictionary",
                "kadm5_hook b failed postcommit remove: Operation failed for unspecified reason",
            ]
        );
        hooks.rename(Stage::Precommit, "a", "b").expect("test");
    }
}
