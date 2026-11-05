//! Password policies (`ldap_pwd_policy.c`): `cn=<name>,<realm DN>` entries
//! of class `krbPwdPolicy`.

use std::collections::HashSet;

use krb5_rs::kdc::kdb::mit::{merge_policy, policy_from_entry, policy_to_entry, MitPolicy};
use krb5_rs::kdc::{Policy, StoreError};
use ldap3::{Mod, Scope, SearchEntry};

use crate::attr::filter_correct;
use crate::entry::Attrs;
use crate::realm::SCOPE_ONE;
use crate::store::{attrs_of, ldap_err, LdapStore, FILTER};

/// `password_policy_attributes`.
pub const POLICY_ATTRS: [&str; 13] = [
    "cn",
    "krbmaxpwdlife",
    "krbminpwdlife",
    "krbpwdmindiffchars",
    "krbpwdminlength",
    "krbpwdhistorylength",
    "krbpwdmaxfailure",
    "krbpwdfailurecountinterval",
    "krbpwdlockoutduration",
    "krbpwdattributes",
    "krbpwdmaxlife",
    "krbpwdmaxrenewablelife",
    "krbpwdallowedkeysalts",
];

/// `populate_policy`.
pub fn mit_policy(name: &str, a: &Attrs) -> MitPolicy {
    let u = |n: &str| a.int(n).unwrap_or(0);
    MitPolicy {
        name: name.to_string(),
        pw_max_life: u("krbmaxpwdlife"),
        pw_min_life: u("krbminpwdlife"),
        pw_min_classes: u("krbpwdmindiffchars"),
        pw_min_length: u("krbpwdminlength"),
        pw_history_num: u("krbpwdhistorylength"),
        pw_max_fail: u("krbpwdmaxfailure"),
        pw_failcnt_interval: u("krbpwdfailurecountinterval"),
        pw_lockout_duration: u("krbpwdlockoutduration"),
        attributes: u("krbpwdattributes"),
        max_life: u("krbpwdmaxlife"),
        max_renewable_life: u("krbpwdmaxrenewablelife"),
        allowed_keysalts: a.first("krbpwdallowedkeysalts").map(str::to_string),
        tl_data: Vec::new(),
    }
}

/// `add_policy_mods`.
pub fn policy_values(p: &MitPolicy) -> Vec<(&'static str, HashSet<Vec<u8>>)> {
    let i = |v: u32| HashSet::from([(v as i32).to_string().into_bytes()]);
    let mut out = vec![
        ("krbmaxpwdlife", i(p.pw_max_life)),
        ("krbminpwdlife", i(p.pw_min_life)),
        ("krbpwdmindiffchars", i(p.pw_min_classes)),
        ("krbpwdminlength", i(p.pw_min_length)),
        ("krbpwdhistorylength", i(p.pw_history_num)),
        ("krbpwdmaxfailure", i(p.pw_max_fail)),
        ("krbpwdfailurecountinterval", i(p.pw_failcnt_interval)),
        ("krbpwdlockoutduration", i(p.pw_lockout_duration)),
        ("krbpwdattributes", i(p.attributes)),
        ("krbpwdmaxlife", i(p.max_life)),
        ("krbpwdmaxrenewablelife", i(p.max_renewable_life)),
    ];
    if let Some(ks) = &p.allowed_keysalts {
        out.push((
            "krbpwdallowedkeysalts",
            HashSet::from([ks.clone().into_bytes()]),
        ));
    }
    out
}

impl LdapStore {
    /// The stored policy (`krb5_ldap_get_password_policy_from_dn`).
    pub async fn read_policy(&self, name: &str) -> Result<Option<MitPolicy>, StoreError> {
        let dn = self.policy_dn(name);
        let mut h = self.inner.pool.get().await?;
        match h
            .search(
                &dn,
                Scope::Base,
                "(objectclass=krbPwdPolicy)",
                POLICY_ATTRS.to_vec(),
            )
            .await
            .and_then(|r| r.non_error())
        {
            Ok((rs, _)) => Ok(rs
                .into_iter()
                .next()
                .map(|e| mit_policy(name, &attrs_of(SearchEntry::construct(e))))),
            Err(ldap3::LdapError::LdapResult { result }) if result.rc == 32 => Ok(None),
            Err(e) => Err(ldap_err("policy search", e)),
        }
    }

    /// `krb5_ldap_get_password_policy`.
    pub async fn get_policy(&self, name: &str) -> Result<Option<Policy>, StoreError> {
        Ok(self
            .read_policy(name)
            .await?
            .as_ref()
            .map(policy_from_entry))
    }

    /// `krb5_ldap_create_password_policy`.
    pub async fn create_policy(&self, policy: Policy) -> Result<(), StoreError> {
        let p = policy_to_entry(&policy);
        let dn = self.policy_dn(&p.name);
        let mut attrs: Vec<(Vec<u8>, HashSet<Vec<u8>>)> = vec![
            (b"cn".to_vec(), HashSet::from([p.name.clone().into_bytes()])),
            (
                b"objectclass".to_vec(),
                HashSet::from([b"krbPwdPolicy".to_vec()]),
            ),
        ];
        attrs.extend(
            policy_values(&p)
                .into_iter()
                .map(|(n, v)| (n.as_bytes().to_vec(), v)),
        );
        let mut h = self.inner.pool.get().await?;
        match h.add(&dn, attrs).await.and_then(|r| r.success()) {
            Ok(_) => Ok(()),
            Err(ldap3::LdapError::LdapResult { result }) if result.rc == 68 => Err(
                StoreError::conflict(format!("Policy {} already exists", p.name)),
            ),
            Err(e) => Err(ldap_err("policy add", e)),
        }
    }

    /// `krb5_ldap_put_password_policy` after a read-modify.
    pub async fn update_policy<F>(&self, name: &str, mut f: F) -> Result<Policy, StoreError>
    where
        F: FnMut(&mut Policy) -> Result<(), StoreError>,
    {
        let mut raw = self
            .read_policy(name)
            .await?
            .ok_or_else(|| StoreError::not_found(format!("Policy {name} does not exist")))?;
        let mut policy = policy_from_entry(&raw);
        f(&mut policy)?;
        merge_policy(&mut raw, &policy)?;
        let mods = policy_values(&raw)
            .into_iter()
            .map(|(n, v)| Mod::Replace(n.as_bytes().to_vec(), v))
            .collect();
        let mut h = self.inner.pool.get().await?;
        h.modify(&self.policy_dn(name), mods)
            .await
            .and_then(|r| r.success())
            .map_err(|e| ldap_err("policy modify", e))?;
        Ok(policy_from_entry(&raw))
    }

    /// `krb5_ldap_delete_password_policy`: refused while a principal still
    /// references the policy.
    pub async fn delete_policy(&self, name: &str) -> Result<bool, StoreError> {
        if self.read_policy(name).await?.is_none() {
            return Ok(false);
        }
        let dn = self.policy_dn(name);
        let p = self.inner.params.clone();
        let scope = if p.search_scope == SCOPE_ONE {
            Scope::OneLevel
        } else {
            Scope::Subtree
        };
        let filter = format!(
            "(&{FILTER}*))(krbpwdpolicyreference={}))",
            filter_correct(&dn)
        );
        let mut h = self.inner.pool.get().await?;
        for base in p.search_bases() {
            match h
                .search(&base, scope, &filter, vec!["1.1"])
                .await
                .and_then(|r| r.non_error())
            {
                Ok((rs, _)) if !rs.is_empty() => {
                    return Err(StoreError::rejected(format!(
                        "Cannot delete a policy that is in use: {name}"
                    )));
                }
                Ok(_) => {}
                Err(ldap3::LdapError::LdapResult { result }) if result.rc == 32 => {}
                Err(e) => return Err(ldap_err("policy reference search", e)),
            }
        }
        h.delete(&dn)
            .await
            .and_then(|r| r.success())
            .map_err(|e| ldap_err("policy delete", e))?;
        Ok(true)
    }

    /// `krb5_ldap_iterate_password_policy`.
    pub async fn list_policies(&self) -> Result<Vec<Policy>, StoreError> {
        Ok(self
            .raw_policies()
            .await?
            .iter()
            .map(policy_from_entry)
            .collect())
    }

    /// Every policy below the realm (`krb5_ldap_iterate_password_policy`).
    pub async fn raw_policies(&self) -> Result<Vec<MitPolicy>, StoreError> {
        let mut h = self.inner.pool.get().await?;
        let (rs, _) = h
            .search(
                &self.inner.params.realm_dn,
                Scope::OneLevel,
                "(objectclass=krbpwdpolicy)",
                POLICY_ATTRS.to_vec(),
            )
            .await
            .and_then(|r| r.success())
            .map_err(|e| ldap_err("policy search", e))?;
        Ok(rs
            .into_iter()
            .filter_map(|e| {
                let a = attrs_of(SearchEntry::construct(e));
                let name = a.first("cn")?.to_string();
                Some(mit_policy(&name, &a))
            })
            .collect())
    }
}
