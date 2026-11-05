//! Raw MIT entries for kadmind and `krb5-rs-kdb` (keys still encrypted),
//! and the kadmin client a store writes for.

use std::collections::HashSet;
use std::sync::Arc;

use krb5_rs::kdc::kdb::mit::mkey::MasterKeys;
use krb5_rs::kdc::kdb::mit::{MitEntry, MitPolicy, TlData};
use krb5_rs::kdc::StoreError;
use krb5_rs::types::PrincipalName;
use ldap3::Mod;

use crate::attr::{filter_correct, ldap_unparse_name};
use crate::store::{ldap_err, LdapStore};
use crate::write::admin_name;

/// The kadmin client: `MOD_PRINC` names it and its tl-data is added to the
/// principals it writes (`svr_principal.c`).
#[derive(Debug)]
pub struct Caller {
    modifier: Vec<u8>,
    tl: Vec<TlData>,
}

impl LdapStore {
    /// This store, writing principals for the kadmin client `modifier` with
    /// its tl-data `tl`.
    pub fn as_caller(&self, modifier: Vec<u8>, tl: Vec<TlData>) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
            caller: Some(Arc::new(Caller { modifier, tl })),
        }
    }

    /// `MOD_PRINC`'s writer: the kadmin client, else krb5-rs-kdb as on klmdb.
    pub(crate) fn modifier(&self) -> Vec<u8> {
        self.caller
            .as_ref()
            .map_or_else(|| admin_name(&self.inner.realm), |c| c.modifier.clone())
    }

    pub(crate) fn caller_tl(&self) -> &[TlData] {
        self.caller.as_ref().map_or(&[], |c| &c.tl)
    }

    /// The stored entry, keys still encrypted (`krb5_db_get_principal`).
    pub async fn raw_entry(
        &self,
        name: &PrincipalName,
        realm: &str,
    ) -> Result<Option<MitEntry>, StoreError> {
        Ok(self.search_raw(name, realm).await?.map(|f| f.entry))
    }

    /// The stored policy.
    pub async fn raw_policy(&self, name: &str) -> Result<Option<MitPolicy>, StoreError> {
        self.read_policy(name).await
    }

    /// Store `raw` as a new principal (`krb5_db_put_principal`).
    pub async fn create_raw(&self, raw: &MitEntry) -> Result<(), StoreError> {
        if self.search_raw(&raw.principal, &raw.realm).await?.is_some() {
            return Err(StoreError::conflict(format!(
                "Principal {}@{} already exists",
                raw.principal, raw.realm
            )));
        }
        self.add_entry(raw).await
    }

    /// Change the stored entry with `f`, writing it back when `f` returns
    /// true.
    pub async fn update_raw<F>(
        &self,
        name: &PrincipalName,
        realm: &str,
        mut f: F,
    ) -> Result<bool, StoreError>
    where
        F: FnMut(&mut MitEntry, &MasterKeys) -> Result<bool, StoreError> + Send,
    {
        self.refresh_master().await?;
        let found = self.search_raw(name, realm).await?.ok_or_else(|| {
            StoreError::not_found(format!("Principal {name}@{realm} does not exist"))
        })?;
        let mut raw = found.entry.clone();
        let changed = {
            let keys = self.master_keys();
            f(&mut raw, &keys)?
        };
        if changed {
            self.modify_entry(&found, &raw).await?;
        }
        Ok(changed)
    }

    /// `krb5_ldap_rename_principal`: a standalone entry is moved to the new
    /// name's RDN; otherwise the name value is replaced on the shared entry.
    pub async fn rename_raw<F>(
        &self,
        name: &PrincipalName,
        realm: &str,
        mut f: F,
    ) -> Result<(), StoreError>
    where
        F: FnMut(MitEntry, &MasterKeys) -> Result<MitEntry, StoreError> + Send,
    {
        self.refresh_master().await?;
        let mut found = self.search_raw(name, realm).await?.ok_or_else(|| {
            StoreError::not_found(format!("Principal {name}@{realm} does not exist"))
        })?;
        let renamed = {
            let keys = self.master_keys();
            f(found.entry.clone(), &keys)?
        };
        if self
            .search_raw(&renamed.principal, &renamed.realm)
            .await?
            .is_some()
        {
            return Err(StoreError::conflict(format!(
                "Principal {}@{} already exists",
                renamed.principal, renamed.realm
            )));
        }
        let old = ldap_unparse_name(name, realm);
        let new = ldap_unparse_name(&renamed.principal, &renamed.realm);
        let one = |s: &str| HashSet::from([s.as_bytes().to_vec()]);
        let mut h = self.inner.pool.get().await?;
        if found.meta.standalone && found.meta.names.len() == 1 {
            let rdn = format!("krbPrincipalName={}", filter_correct(&new));
            h.modifydn(&found.meta.dn, &rdn, true, None)
                .await
                .and_then(|r| r.success())
                .map_err(|e| ldap_err("Principal rename failed", e))?;
            let parent = found
                .meta
                .dn
                .char_indices()
                .scan(false, |esc, (i, c)| {
                    let sep = !*esc && c == ',';
                    *esc = !*esc && c == '\\';
                    Some((i, sep))
                })
                .find(|&(_, sep)| sep)
                .map_or(String::new(), |(i, _)| found.meta.dn[i..].to_string());
            found.meta.dn = format!("{rdn}{parent}");
            h.modify(
                &found.meta.dn,
                vec![
                    Mod::Replace(b"krbprincipalname".to_vec(), one(&new)),
                    Mod::Replace(b"krbcanonicalname".to_vec(), one(&new)),
                ],
            )
            .await
            .and_then(|r| r.success())
            .map_err(|e| ldap_err("Principal rename failed", e))?;
        } else {
            let mut mods = vec![
                Mod::Delete(b"krbprincipalname".to_vec(), one(&old)),
                Mod::Add(b"krbprincipalname".to_vec(), one(&new)),
            ];
            if found.meta.present.iter().any(|a| a == "krbcanonicalname") {
                mods.push(Mod::Replace(b"krbcanonicalname".to_vec(), one(&new)));
            }
            h.modify(&found.meta.dn, mods)
                .await
                .and_then(|r| r.success())
                .map_err(|e| ldap_err("Principal rename failed", e))?;
        }
        drop(h);
        self.modify_entry(&found, &renamed).await
    }

    /// Every stored entry, keys still encrypted.
    pub async fn raw_entries(&self) -> Result<Vec<MitEntry>, StoreError> {
        self.list_raw().await
    }

    /// Every entry and policy, for `kdb5_util dump` (`krb5_db_iterate`).
    pub async fn dump_entries(&self) -> Result<(Vec<MitEntry>, Vec<MitPolicy>), StoreError> {
        Ok((self.raw_entries().await?, self.raw_policies().await?))
    }

    /// `kdb5_util load -update`: each policy and entry replaces the stored
    /// one of the same name or is added (`krb5_db_put_principal`).
    pub async fn load_update(
        &self,
        entries: &[MitEntry],
        policies: &[MitPolicy],
    ) -> Result<(), StoreError> {
        for p in policies {
            let policy = krb5_rs::kdc::kdb::mit::policy_from_entry(p);
            if self.read_policy(&p.name).await?.is_some() {
                self.update_policy(&p.name, |x| {
                    *x = policy.clone();
                    Ok(())
                })
                .await?;
            } else {
                self.create_policy(policy).await?;
            }
        }
        for e in entries {
            match self.search_raw(&e.principal, &e.realm).await? {
                Some(found) => self.modify_entry(&found, e).await?,
                None => self.add_entry(e).await?,
            }
        }
        Ok(())
    }
}
