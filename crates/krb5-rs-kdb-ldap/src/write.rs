//! Principal writes (`krb5_ldap_put_principal`, `krb5_ldap_delete_principal`
//! and `krb5_ldap_iterate`, ldap_principal{,2}.c).

use std::collections::{HashMap, HashSet};

use krb5_rs::kdc::kdb::mit::{merge_record, new_entry, record_from_entry, unparse_name, MitEntry};
use krb5_rs::kdc::{kerberos_time, PrincipalEntry, PrincipalRecord, StoreError};
use krb5_rs::types::{KerberosTime, PrincipalName};
use ldap3::{Mod, Scope, SearchEntry};

use crate::attr::{filter_correct, ldap_parse_name, ldap_unparse_name};
use crate::entry::{entry_meta, mit_entry, put_values, Values};
use crate::realm::SCOPE_ONE;
use crate::store::{attrs_of, ldap_err, Found, LdapStore, FILTER, PRINCIPAL_ATTRS};

/// `attributes_set` (ldap_principal.c): what deleting a directory user's
/// last principal removes.
const ATTRIBUTES_SET: [&str; 13] = [
    "krbmaxticketlife",
    "krbmaxrenewableage",
    "krbticketflags",
    "krbprincipalexpiration",
    "krbticketpolicyreference",
    "krbPrincipalAuthInd",
    "krbpwdpolicyreference",
    "krbpasswordexpiration",
    "krbprincipalkey",
    "krblastpwdchange",
    "krbextradata",
    "krbLastSuccessfulAuth",
    "krbLastFailedAuth",
];

pub(crate) fn now_time() -> KerberosTime {
    let seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX));
    kerberos_time(seconds)
}

pub(crate) fn admin_name(realm: &str) -> Vec<u8> {
    unparse_name(&PrincipalName::new_principal("krb5-rs-kdb"), realm)
}

fn b(s: &str) -> Vec<u8> {
    s.as_bytes().to_vec()
}

fn replace_mods(values: Values) -> Vec<Mod<Vec<u8>>> {
    values
        .into_iter()
        .map(|(n, v)| Mod::Replace(b(n), v.unwrap_or_default().into_iter().collect()))
        .collect()
}

impl LdapStore {
    /// `krb5_ldap_name_to_policydn`: `cn=<name>,<realm DN>`, or empty to
    /// remove a reference.
    pub fn policy_dn(&self, name: &str) -> String {
        if name.is_empty() {
            String::new()
        } else {
            format!("cn={},{}", filter_correct(name), self.inner.params.realm_dn)
        }
    }

    /// The DN a new standalone principal gets: under `containerdn`, else
    /// `krbPrincContainerRef`, else the realm.
    pub fn standalone_dn(&self, user: &str, containerdn: Option<&str>) -> String {
        let p = &self.inner.params;
        let sub = containerdn
            .or(p.container_ref.as_deref())
            .unwrap_or(&p.realm_dn);
        format!("krbprincipalname={},{sub}", filter_correct(user))
    }

    /// Add a new standalone entry for `raw`.
    pub async fn add_entry(&self, raw: &MitEntry) -> Result<(), StoreError> {
        let user = ldap_unparse_name(&raw.principal, &raw.realm);
        let dn = self.standalone_dn(&user, None);
        let mut attrs: HashMap<Vec<u8>, HashSet<Vec<u8>>> = HashMap::new();
        attrs.insert(
            b("objectclass"),
            ["krbprincipal", "krbprincipalaux", "krbTicketPolicyAux"]
                .into_iter()
                .map(b)
                .collect(),
        );
        attrs.insert(b("krbprincipalname"), HashSet::from([b(&user)]));
        attrs.insert(b("krbcanonicalname"), HashSet::from([b(&user)]));
        for (n, v) in put_values(raw, |p| self.policy_dn(p))? {
            if let Some(v) = v.filter(|v| !v.is_empty()) {
                attrs.insert(b(n), v.into_iter().collect());
            }
        }
        attrs
            .entry(b("krbLoginFailedCount"))
            .or_insert_with(|| HashSet::from([b("0")]));
        let mut h = self.inner.pool.get().await?;
        h.add(&dn, attrs.into_iter().collect())
            .await
            .and_then(|r| r.success())
            .map_err(|e| ldap_err("Principal add failed", e))?;
        Ok(())
    }

    /// Replace the Kerberos attributes of an existing entry. Ticket values
    /// inherited from a ticket policy or the realm are left unset unless
    /// they changed.
    pub async fn modify_entry(&self, found: &Found, raw: &MitEntry) -> Result<(), StoreError> {
        let read = &found.entry;
        let m = &found.meta;
        let mut values = put_values(raw, |p| self.policy_dn(p))?;
        values.retain(|(n, _)| match *n {
            "krbmaxticketlife" => m.has_max_life || raw.max_life != read.max_life,
            "krbmaxrenewableage" => {
                m.has_max_rlife || raw.max_renewable_life != read.max_renewable_life
            }
            "krbticketflags" => m.has_flags || raw.attributes != read.attributes,
            _ => true,
        });
        let mut h = self.inner.pool.get().await?;
        h.modify(&m.dn, replace_mods(values))
            .await
            .and_then(|r| r.success())
            .map_err(|e| ldap_err("User modification failed", e))?;
        Ok(())
    }

    /// Create a principal as `modifier`.
    pub async fn create_principal_as(
        &self,
        entry: PrincipalEntry,
        last_pwd_change: Option<KerberosTime>,
        modifier: Vec<u8>,
    ) -> Result<(), StoreError> {
        self.refresh_master().await?;
        if self.search_raw(&entry.name, &entry.realm).await?.is_some() {
            return Err(StoreError::conflict(format!(
                "Principal {}@{} already exists",
                entry.name, entry.realm
            )));
        }
        let record = PrincipalRecord {
            unlock: false,
            mod_time: Some(now_time()),
            last_pwd_change,
            mod_by: Some(modifier.clone()),
            password_history: None,
            entry,
        };
        let raw = new_entry(&record, &self.master_keys(), &modifier)?;
        self.add_entry(&raw).await
    }

    /// Read, change and write back a principal as `modifier`.
    pub async fn update_principal_as<F>(
        &self,
        name: &PrincipalName,
        realm: &str,
        modifier: Vec<u8>,
        mut f: F,
    ) -> Result<PrincipalRecord, StoreError>
    where
        F: FnMut(&mut PrincipalRecord) -> Result<(), StoreError>,
    {
        self.refresh_master().await?;
        let found = self.search_raw(name, realm).await?.ok_or_else(|| {
            StoreError::not_found(format!("Principal {name}@{realm} does not exist"))
        })?;
        let keys = self.master_keys();
        let mut raw = found.entry.clone();
        let mut record = record_from_entry(&raw, &keys)?;
        f(&mut record)?;
        record.mod_time = Some(now_time());
        record.mod_by = Some(modifier.clone());
        merge_record(&mut raw, &record, &keys, Some(&modifier))?;
        self.modify_entry(&found, &raw).await?;
        record_from_entry(&raw, &keys)
    }

    /// `krb5_ldap_delete_principal`.
    pub async fn delete_principal(
        &self,
        name: &PrincipalName,
        realm: &str,
    ) -> Result<bool, StoreError> {
        let Some(found) = self.search_raw(name, realm).await? else {
            return Ok(false);
        };
        let m = &found.meta;
        let user = ldap_unparse_name(name, realm);
        let mut h = self.inner.pool.get().await?;
        let same = found.entry.principal == *name && found.entry.realm == realm;
        if m.standalone && (m.names.len() == 1 || same) {
            h.delete(&m.dn)
                .await
                .and_then(|r| r.success())
                .map_err(|e| ldap_err("Principal delete failed", e))?;
            return Ok(true);
        }
        let mut mods = vec![Mod::Delete(
            b("krbprincipalname"),
            HashSet::from([b(&user)]),
        )];
        if m.names.len() == 1 {
            mods.extend(
                ATTRIBUTES_SET
                    .iter()
                    .filter(|a| m.present.iter().any(|p| p.eq_ignore_ascii_case(a)))
                    .map(|a| Mod::Delete(b(a), HashSet::new())),
            );
            let classes: HashSet<Vec<u8>> = ["krbticketpolicyaux", "krbprincipalaux"]
                .into_iter()
                .filter(|c| m.classes.iter().any(|x| x.eq_ignore_ascii_case(c)))
                .map(b)
                .collect();
            if !classes.is_empty() {
                mods.push(Mod::Delete(b("objectclass"), classes));
            }
        }
        h.modify(&m.dn, mods)
            .await
            .and_then(|r| r.success())
            .map_err(|e| ldap_err("User modification failed", e))?;
        Ok(true)
    }

    /// `krb5_ldap_iterate`: every principal name in every search base.
    pub async fn list_raw(&self) -> Result<Vec<MitEntry>, StoreError> {
        let p = self.inner.params.clone();
        let scope = if p.search_scope == SCOPE_ONE {
            Scope::OneLevel
        } else {
            Scope::Subtree
        };
        let filter = format!("{FILTER}*))");
        let mut found = Vec::new();
        for base in p.search_bases() {
            let rs = {
                let mut h = self.inner.pool.get().await?;
                match h
                    .search(&base, scope, &filter, PRINCIPAL_ATTRS.to_vec())
                    .await
                    .and_then(|r| r.non_error())
                {
                    Ok((rs, _)) => rs,
                    Err(ldap3::LdapError::LdapResult { result }) if result.rc == 32 => continue,
                    Err(e) => return Err(ldap_err("search", e)),
                }
            };
            for re in rs {
                let se = SearchEntry::construct(re);
                let dn = se.dn.clone();
                let a = attrs_of(se);
                let meta = entry_meta(&dn, &a);
                for n in &meta.names {
                    let (pname, prealm) = ldap_parse_name(n)?;
                    if prealm != self.inner.realm {
                        continue;
                    }
                    let mut e = mit_entry(&a, pname, prealm)?;
                    self.apply_tkt_policy(&meta, &mut e).await?;
                    found.push(e);
                }
            }
        }
        Ok(found)
    }

    /// Every principal with its keys decrypted.
    pub async fn list_records(&self) -> Result<Vec<PrincipalRecord>, StoreError> {
        let keys = self.master_keys();
        self.list_raw()
            .await?
            .iter()
            .map(|e| record_from_entry(e, &keys))
            .collect()
    }
}
