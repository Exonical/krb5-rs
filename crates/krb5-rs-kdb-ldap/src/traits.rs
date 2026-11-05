//! The krb5-rs store traits over [`LdapStore`].

use std::collections::HashSet;

use krb5_rs::kdc::{
    AdminStore, AuthState, AuthStateStore, AuthStateUpdate, HealthCheck, Policy, PolicyStore,
    PrincipalEntry, PrincipalRecord, StoreError,
};
use krb5_rs::types::{KerberosTime, PrincipalName};
use ldap3::{Mod, Scope};

use crate::attr::string_time;
use crate::store::{ldap_err, LdapStore};
use crate::write::admin_name;

fn time_value(t: i64) -> HashSet<Vec<u8>> {
    if t <= 0 {
        HashSet::new()
    } else {
        HashSet::from([string_time(t as u32).into_bytes()])
    }
}

impl LdapStore {
    /// The lockout state stored on the entry.
    pub async fn read_auth_state(
        &self,
        name: &PrincipalName,
        realm: &str,
    ) -> Result<Option<(String, AuthState)>, StoreError> {
        Ok(self.search_raw(name, realm).await?.map(|f| {
            (
                f.meta.dn,
                AuthState {
                    fail_count: f.entry.fail_auth_count,
                    last_failed: i64::from(f.entry.last_failed),
                    last_success: i64::from(f.entry.last_success),
                },
            )
        }))
    }
}

impl PolicyStore for LdapStore {
    async fn policy(&self, name: &str) -> Result<Option<Policy>, StoreError> {
        self.get_policy(name).await
    }
}

impl AuthStateStore for LdapStore {
    async fn auth_state(&self, name: &PrincipalName, realm: &str) -> Result<AuthState, StoreError> {
        Ok(self
            .read_auth_state(name, realm)
            .await?
            .map(|(_, s)| s)
            .unwrap_or(AuthState {
                fail_count: 0,
                last_failed: 0,
                last_success: 0,
            }))
    }

    /// `krb5_ldap_lockout_audit` (lockout.c), masked by `disable_lockout`
    /// and `disable_last_success`, writing only what changed.
    async fn apply(
        &self,
        name: &PrincipalName,
        realm: &str,
        update: &AuthStateUpdate,
    ) -> Result<AuthState, StoreError> {
        let Some((dn, old)) = self.read_auth_state(name, realm).await? else {
            return Err(StoreError::not_found(format!(
                "Principal {name}@{realm} does not exist"
            )));
        };
        let mut st = old;
        st.apply(update);
        let cfg = self.config();
        if cfg.disable_lockout && !matches!(update, AuthStateUpdate::Set(_)) {
            st.fail_count = old.fail_count;
            st.last_failed = old.last_failed;
        }
        if cfg.disable_last_success && !matches!(update, AuthStateUpdate::Set(_)) {
            st.last_success = old.last_success;
        }
        let mut mods = Vec::new();
        if st.fail_count != old.fail_count {
            mods.push(Mod::Replace(
                b"krbLoginFailedCount".to_vec(),
                HashSet::from([st.fail_count.to_string().into_bytes()]),
            ));
        }
        if st.last_failed != old.last_failed {
            mods.push(Mod::Replace(
                b"krbLastFailedAuth".to_vec(),
                time_value(st.last_failed),
            ));
        }
        if st.last_success != old.last_success {
            mods.push(Mod::Replace(
                b"krbLastSuccessfulAuth".to_vec(),
                time_value(st.last_success),
            ));
        }
        if !mods.is_empty() {
            let mut h = self.inner.pool.get().await?;
            h.modify(&dn, mods)
                .await
                .and_then(|r| r.success())
                .map_err(|e| ldap_err("lockout update", e))?;
        }
        Ok(st)
    }
}

impl AdminStore for LdapStore {
    async fn get_record(
        &self,
        name: &PrincipalName,
        realm: &str,
    ) -> Result<Option<PrincipalRecord>, StoreError> {
        LdapStore::get_record(self, name, realm).await
    }

    async fn create_principal(
        &self,
        entry: PrincipalEntry,
        last_pwd_change: Option<KerberosTime>,
    ) -> Result<(), StoreError> {
        let modifier = admin_name(&self.inner.realm);
        self.create_principal_as(entry, last_pwd_change, modifier)
            .await
    }

    async fn update_principal<F>(
        &self,
        name: &PrincipalName,
        realm: &str,
        f: F,
    ) -> Result<PrincipalRecord, StoreError>
    where
        F: FnMut(&mut PrincipalRecord) -> Result<(), StoreError> + Send + 'static,
    {
        let modifier = admin_name(&self.inner.realm);
        self.update_principal_as(name, realm, modifier, f).await
    }

    async fn delete_principal(
        &self,
        name: &PrincipalName,
        realm: &str,
    ) -> Result<bool, StoreError> {
        LdapStore::delete_principal(self, name, realm).await
    }

    async fn list_principals(&self) -> Result<Vec<PrincipalRecord>, StoreError> {
        self.list_records().await
    }

    async fn get_policy(&self, name: &str) -> Result<Option<Policy>, StoreError> {
        LdapStore::get_policy(self, name).await
    }

    async fn create_policy(&self, policy: Policy) -> Result<(), StoreError> {
        LdapStore::create_policy(self, policy).await
    }

    async fn update_policy<F>(&self, name: &str, f: F) -> Result<Policy, StoreError>
    where
        F: FnMut(&mut Policy) -> Result<(), StoreError> + Send + 'static,
    {
        LdapStore::update_policy(self, name, f).await
    }

    async fn delete_policy(&self, name: &str) -> Result<bool, StoreError> {
        LdapStore::delete_policy(self, name).await
    }

    async fn list_policies(&self) -> Result<Vec<Policy>, StoreError> {
        LdapStore::list_policies(self).await
    }
}

impl HealthCheck for LdapStore {
    async fn health(&self) -> Result<(), StoreError> {
        let mut h = self.inner.pool.get().await?;
        h.search(
            &self.inner.params.realm_dn,
            Scope::Base,
            "(objectclass=*)",
            vec!["1.1"],
        )
        .await
        .and_then(|r| r.success())
        .map_err(|e| ldap_err("health check", e))?;
        Ok(())
    }
}
