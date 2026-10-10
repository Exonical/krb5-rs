//! Principal database abstraction for the KDC (MIT kdb.h `krb5_db_entry`).
//!
//! The KDC reads principals through [`PrincipalStore`]; [`MemoryStore`] is
//! an in-memory implementation for tests and embedded use.

use std::collections::HashMap;
use std::time::Duration;

use bitflags::bitflags;

use super::store::{HealthCheck, Policy, PolicyStore, PrincipalStore, StoreError};
use crate::crypto::util::generate_random;
use crate::crypto::{find_etype, SaltType};
use crate::keytab::Keytab;
use crate::protocol::preauth::default_salt;
use crate::types::{EncryptionKey, KerberosTime, PrincipalName};
use crate::Krb5Error;

bitflags! {
    /// Principal attributes (MIT `KRB5_KDB_*`, kdb.h:85-102).
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct PrincipalAttributes: u32 {
        /// Postdated tickets are not allowed.
        const DISALLOW_POSTDATED = 0x0000_0001;
        /// Forwardable tickets are not allowed.
        const DISALLOW_FORWARDABLE = 0x0000_0002;
        /// Service tickets cannot be issued from a TGT.
        const DISALLOW_TGT_BASED = 0x0000_0004;
        /// Renewable tickets are not allowed.
        const DISALLOW_RENEWABLE = 0x0000_0008;
        /// Proxiable tickets are not allowed.
        const DISALLOW_PROXIABLE = 0x0000_0010;
        /// Duplicate-session-key (user-to-user) tickets are not allowed.
        const DISALLOW_DUP_SKEY = 0x0000_0020;
        /// No tickets may be issued to or for this principal.
        const DISALLOW_ALL_TIX = 0x0000_0040;
        /// Pre-authentication is required.
        const REQUIRES_PRE_AUTH = 0x0000_0080;
        /// Hardware pre-authentication is required.
        const REQUIRES_HW_AUTH = 0x0000_0100;
        /// The password must be changed before other service use.
        const REQUIRES_PWCHANGE = 0x0000_0200;
        /// The principal cannot be used as a service.
        const DISALLOW_SVR = 0x0000_1000;
        /// The principal is a password-change service.
        const PWCHANGE_SERVICE = 0x0000_2000;
        /// Tickets for this service are marked ok-as-delegate.
        const OK_AS_DELEGATE = 0x0010_0000;
        /// The service may use S4U2Self.
        const OK_TO_AUTH_AS_DELEGATE = 0x0020_0000;
        /// Authorization data is not required in tickets for this service.
        const NO_AUTH_DATA_REQUIRED = 0x0040_0000;
        /// Keys are locked down against extraction.
        const LOCKDOWN_KEYS = 0x0080_0000;
    }
}

/// One long-term key of a principal (MIT `krb5_key_data`).
#[derive(Debug, Clone)]
pub struct KeyEntry {
    /// Key version number.
    pub kvno: u32,
    /// The key.
    pub key: EncryptionKey,
    /// Explicit salt; `None` is the MIT normal (default) salt: realm plus
    /// name components.
    pub salt: Option<Vec<u8>>,
    /// String-to-key parameters, if any.
    pub s2kparams: Option<Vec<u8>>,
}

/// A principal database entry (MIT `krb5_db_entry`).
#[derive(Debug, Clone)]
pub struct PrincipalEntry {
    /// Principal name.
    pub name: PrincipalName,
    /// Principal realm.
    pub realm: String,
    /// Attribute flags.
    pub attributes: PrincipalAttributes,
    /// Maximum ticket lifetime; `None` (or zero) means no per-principal cap.
    pub max_life: Option<Duration>,
    /// Maximum renewable lifetime; `None` means no per-principal cap (API
    /// difference: MIT's stored `0` is a literal zero).
    pub max_renewable_life: Option<Duration>,
    /// Principal expiration; `None` means never.
    pub expiration: Option<KerberosTime>,
    /// Password expiration; `None` means never.
    pub pw_expiration: Option<KerberosTime>,
    /// Long-term keys.
    pub keys: Vec<KeyEntry>,
    /// Principals this service may delegate to with traditional S4U2Proxy,
    /// as unparsed names (the `krbAllowedToDelegateTo` list that MIT's LDAP
    /// module keeps in `KRB5_TL_CONSTRAINED_DELEGATION_ACL` tl-data).
    pub allowed_to_delegate_to: Vec<String>,
    /// Services allowed to delegate to this one with resource-based
    /// constrained delegation, as unparsed names.
    pub allowed_to_delegate_from: Vec<String>,
    /// The policy this principal is under (kadmin `-policy`), by name.
    pub policy: Option<String>,
    /// Bumped by every security-sensitive administrative change: disable,
    /// password reset, key rotation, unlock, policy assignment
    /// (docs/architecture/kdb.md §3). krb5-rs extension, not in MIT.
    pub security_epoch: u64,
    /// Time of the last administrative unlock (MIT
    /// `KRB5_TL_LAST_ADMIN_UNLOCK`, kdb.h): lockout counting restarts after it.
    pub last_admin_unlock: Option<KerberosTime>,
}

/// Which key version [`PrincipalEntry::find_key`] should match
/// (MIT `krb5_dbe_find_enctype` kvno argument: 0, -1, or a version).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KvnoSel {
    /// Only the highest kvno (MIT kvno 0).
    Highest,
    /// Any kvno, first match in list order (MIT kvno -1).
    Any,
    /// Exactly this kvno.
    Exact(u32),
}

impl PrincipalEntry {
    /// The highest key version number (MIT `current_kvno`).
    pub(crate) fn current_kvno(&self) -> Option<u32> {
        self.keys.iter().map(|k| k.kvno).max()
    }

    /// Find a key by etype and kvno, skipping non-permitted etypes
    /// (MIT `krb5_dbe_def_search_enctype`, kdb_default.c:47-101).
    pub(crate) fn find_key(
        &self,
        etype: Option<i32>,
        kvno: KvnoSel,
        permitted: &dyn Fn(i32) -> bool,
    ) -> Option<&KeyEntry> {
        let want = match kvno {
            KvnoSel::Highest => Some(self.current_kvno()?),
            KvnoSel::Any => None,
            KvnoSel::Exact(k) => Some(k),
        };
        self.keys.iter().find(|k| {
            etype.is_none_or(|e| k.key.keytype == e)
                && want.is_none_or(|w| k.kvno == w)
                && permitted(k.key.keytype)
        })
    }

    /// The salt for `key` (MIT `krb5_dbe_compute_salt`, kdb5.c:2345).
    pub(crate) fn salt_for(&self, key: &KeyEntry) -> Vec<u8> {
        match &key.salt {
            Some(s) => s.clone(),
            None => default_salt(&self.realm, &component_bytes(&self.name)),
        }
    }
}

fn component_bytes(name: &PrincipalName) -> Vec<Vec<u8>> {
    name.name_string
        .iter()
        .map(|c| c.as_bytes().to_vec())
        .collect()
}

/// The salt string for `salt_type` (MIT `krb5_dbe_compute_salt`,
/// kdb5.c:2345-2380): realm and components, components only, or the realm.
pub fn salt_bytes(name: &PrincipalName, realm: &str, salt_type: SaltType) -> Vec<u8> {
    match salt_type {
        SaltType::Normal => default_salt(realm, &component_bytes(name)),
        SaltType::NoRealm => component_bytes(name).concat(),
        SaltType::OnlyRealm => realm.as_bytes().to_vec(),
    }
}

/// Password-derived keys, one per key/salt pair. `Normal` salt is stored
/// as `None`; the other salt types store the explicit salt.
pub fn keys_from_password(
    name: &PrincipalName,
    realm: &str,
    password: &str,
    kvno: u32,
    keysalts: &[(i32, SaltType)],
) -> Result<Vec<KeyEntry>, Krb5Error> {
    let mut keys = Vec::with_capacity(keysalts.len());
    for &(etype, salt_type) in keysalts {
        let profile = find_etype(etype).map_err(|_| Krb5Error::UnsupportedEtype(etype))?;
        let salt = salt_bytes(name, realm, salt_type);
        let key = profile
            .string_to_key(password.as_bytes(), &salt, None)
            .map_err(|e| Krb5Error::Crypto(e.to_string()))?;
        keys.push(KeyEntry {
            kvno,
            key: EncryptionKey::new(etype, key.to_vec()),
            salt: (salt_type != SaltType::Normal).then_some(salt),
            s2kparams: None,
        });
    }
    Ok(keys)
}

/// A random key per etype (MIT `krb5_c_make_random_key`).
pub fn random_keys(kvno: u32, etypes: &[i32]) -> Result<Vec<KeyEntry>, Krb5Error> {
    let mut keys = Vec::with_capacity(etypes.len());
    for &etype in etypes {
        let profile = find_etype(etype).map_err(|_| Krb5Error::UnsupportedEtype(etype))?;
        let key = profile
            .random_to_key(&generate_random(profile.key_bytes()))
            .map_err(|e| Krb5Error::Crypto(e.to_string()))?;
        keys.push(KeyEntry {
            kvno,
            key: EncryptionKey::new(etype, key.to_vec()),
            salt: None,
            s2kparams: None,
        });
    }
    Ok(keys)
}

pub(crate) type StoreKey = (Vec<Vec<u8>>, String);

pub(crate) fn store_key(name: &PrincipalName, realm: &str) -> StoreKey {
    (component_bytes(name), realm.to_string())
}

/// In-memory [`PrincipalStore`].
#[derive(Debug, Default)]
pub struct MemoryStore {
    entries: HashMap<StoreKey, PrincipalEntry>,
    policies: HashMap<String, Policy>,
}

impl MemoryStore {
    /// An empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert an entry, replacing any entry for the same principal.
    ///
    /// Keys are kept in descending kvno order (stable), like MIT key data.
    pub fn insert(&mut self, mut entry: PrincipalEntry) {
        entry.keys.sort_by_key(|k| std::cmp::Reverse(k.kvno));
        self.entries
            .insert(store_key(&entry.name, &entry.realm), entry);
    }

    /// The entry for a principal, without going through the async store
    /// trait (a synchronous convenience for tests and embedding).
    pub fn get(&self, name: &PrincipalName, realm: &str) -> Option<PrincipalEntry> {
        self.entries.get(&store_key(name, realm)).cloned()
    }

    /// Add or replace a policy.
    pub fn insert_policy(&mut self, policy: Policy) {
        self.policies.insert(policy.name.clone(), policy);
    }

    fn new_entry(
        name: PrincipalName,
        realm: &str,
        attributes: PrincipalAttributes,
        keys: Vec<KeyEntry>,
    ) -> PrincipalEntry {
        PrincipalEntry {
            allowed_to_delegate_to: Vec::new(),
            allowed_to_delegate_from: Vec::new(),
            policy: None,
            security_epoch: 0,
            last_admin_unlock: None,
            name,
            realm: realm.to_string(),
            attributes,
            max_life: None,
            max_renewable_life: None,
            expiration: None,
            pw_expiration: None,
            keys,
        }
    }

    /// Add a principal whose keys derive from `password` with the default
    /// salt, one key per etype.
    pub fn add_with_password(
        &mut self,
        name: PrincipalName,
        realm: &str,
        password: &str,
        kvno: u32,
        etypes: &[i32],
        attributes: PrincipalAttributes,
    ) -> Result<(), Krb5Error> {
        let keysalts: Vec<(i32, SaltType)> =
            etypes.iter().map(|&e| (e, SaltType::Normal)).collect();
        let keys = keys_from_password(&name, realm, password, kvno, &keysalts)?;
        self.insert(Self::new_entry(name, realm, attributes, keys));
        Ok(())
    }

    /// Add a principal with a random key per etype.
    pub fn add_random_key(
        &mut self,
        name: PrincipalName,
        realm: &str,
        kvno: u32,
        etypes: &[i32],
        attributes: PrincipalAttributes,
    ) -> Result<(), Krb5Error> {
        let keys = random_keys(kvno, etypes)?;
        self.insert(Self::new_entry(name, realm, attributes, keys));
        Ok(())
    }

    /// Import every keytab entry, grouping entries per principal.
    pub fn import_keytab(
        &mut self,
        keytab: &dyn Keytab,
        attributes: PrincipalAttributes,
    ) -> Result<(), Krb5Error> {
        let mut grouped: Vec<PrincipalEntry> = Vec::new();
        for e in keytab.entries()? {
            let key = KeyEntry {
                kvno: e.kvno,
                key: e.key,
                salt: None,
                s2kparams: None,
            };
            match grouped
                .iter_mut()
                .find(|g| store_key(&g.name, &g.realm) == store_key(&e.principal, &e.realm))
            {
                Some(g) => g.keys.push(key),
                None => grouped.push(Self::new_entry(
                    e.principal,
                    &e.realm,
                    attributes,
                    vec![key],
                )),
            }
        }
        for g in grouped {
            self.insert(g);
        }
        Ok(())
    }
}

impl PrincipalStore for MemoryStore {
    fn lookup(
        &self,
        name: &PrincipalName,
        realm: &str,
    ) -> impl std::future::Future<Output = Result<Option<PrincipalEntry>, StoreError>> + Send {
        std::future::ready(Ok(self.entries.get(&store_key(name, realm)).cloned()))
    }
}

impl PolicyStore for MemoryStore {
    fn policy(
        &self,
        name: &str,
    ) -> impl std::future::Future<Output = Result<Option<Policy>, StoreError>> + Send {
        std::future::ready(Ok(self.policies.get(name).cloned()))
    }
}

impl HealthCheck for MemoryStore {
    fn health(&self) -> impl std::future::Future<Output = Result<(), StoreError>> + Send {
        std::future::ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn permit_all(_: i32) -> bool {
        true
    }

    fn entry(keys: Vec<(u32, i32)>) -> PrincipalEntry {
        PrincipalEntry {
            allowed_to_delegate_to: Vec::new(),
            allowed_to_delegate_from: Vec::new(),
            policy: None,
            security_epoch: 0,
            last_admin_unlock: None,
            name: PrincipalName::new_principal("u"),
            realm: "R".into(),
            attributes: PrincipalAttributes::empty(),
            max_life: None,
            max_renewable_life: None,
            expiration: None,
            pw_expiration: None,
            keys: keys
                .into_iter()
                .map(|(kvno, et)| KeyEntry {
                    kvno,
                    key: EncryptionKey::new(et, vec![0; 16]),
                    salt: None,
                    s2kparams: None,
                })
                .collect(),
        }
    }

    #[test]
    fn find_key_highest_kvno_matches_only_top_version() {
        let e = entry(vec![(2, 18), (1, 17)]);
        assert!(e
            .find_key(Some(17), KvnoSel::Highest, &permit_all)
            .is_none());
        assert_eq!(
            e.find_key(Some(18), KvnoSel::Highest, &permit_all)
                .map(|k| k.kvno),
            Some(2)
        );
    }

    #[test]
    fn find_key_any_kvno_returns_first_in_list_order() {
        let e = entry(vec![(2, 18), (1, 17)]);
        assert_eq!(
            e.find_key(None, KvnoSel::Any, &permit_all).map(|k| k.kvno),
            Some(2)
        );
        assert_eq!(
            e.find_key(Some(17), KvnoSel::Exact(1), &permit_all)
                .map(|k| k.kvno),
            Some(1)
        );
    }

    #[test]
    fn find_key_skips_non_permitted_etypes() {
        let e = entry(vec![(1, 18), (1, 17)]);
        let key = e.find_key(None, KvnoSel::Highest, &|et| et == 17);
        assert_eq!(key.map(|k| k.key.keytype), Some(17));
    }

    #[tokio::test]
    async fn memory_store_lookup_ignores_name_type() {
        let mut store = MemoryStore::new();
        let mut e = entry(vec![(1, 18)]);
        e.name = PrincipalName::new_srv_hst("HTTP", "h.example");
        e.realm = "R".into();
        store.insert(e);
        let probe = PrincipalName::new_srv_inst("HTTP", "h.example");
        assert!(store.lookup(&probe, "R").await.expect("lookup").is_some());
        assert!(store
            .lookup(&probe, "OTHER")
            .await
            .expect("lookup")
            .is_none());
    }

    #[tokio::test]
    async fn insert_orders_keys_by_descending_kvno() {
        let mut store = MemoryStore::new();
        store.insert(entry(vec![(1, 17), (3, 18), (2, 17)]));
        let got = store
            .lookup(&PrincipalName::new_principal("u"), "R")
            .await
            .expect("lookup")
            .expect("present");
        let kvnos: Vec<u32> = got.keys.iter().map(|k| k.kvno).collect();
        assert_eq!(kvnos, vec![3, 2, 1]);
    }

    #[tokio::test]
    async fn add_with_password_uses_default_salt_keys() {
        let mut store = MemoryStore::new();
        store
            .add_with_password(
                PrincipalName::new_principal("u"),
                "R",
                "pw",
                4,
                &[18, 17],
                PrincipalAttributes::REQUIRES_PRE_AUTH,
            )
            .expect("add");
        let got = store
            .lookup(&PrincipalName::new_principal("u"), "R")
            .await
            .expect("lookup")
            .expect("present");
        assert_eq!(got.keys.len(), 2);
        assert!(got.keys.iter().all(|k| k.kvno == 4 && k.salt.is_none()));
        assert_eq!(got.salt_for(&got.keys[0]), b"Ru".to_vec());
    }

    #[test]
    fn add_with_password_unknown_etype_is_rejected() {
        let mut store = MemoryStore::new();
        let err = store.add_with_password(
            PrincipalName::new_principal("u"),
            "R",
            "pw",
            1,
            &[23],
            PrincipalAttributes::empty(),
        );
        assert!(matches!(err, Err(Krb5Error::UnsupportedEtype(23))));
    }
}
