//! The kldap store: principals, policies and lockout state in an LDAP
//! directory laid out as MIT's kldap module does.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use krb5_rs::kdc::kdb::mit::mkey::MasterKeys;
use krb5_rs::kdc::kdb::mit::{record_from_entry, MitEntry};
use krb5_rs::kdc::{
    PrincipalEntry, PrincipalRecord, PrincipalStore, RealmConfig, StoreError, StoreErrorKind,
};
use krb5_rs::types::{EncryptionKey, KerberosString, PrincipalName};
use ldap3::{Scope, SearchEntry};

use crate::attr::{filter_correct, ldap_parse_name, ldap_unparse_name};
use crate::config::{LdapConfig, ServerType};
use crate::conn::Pool;
use crate::entry::{entry_meta, mit_entry, Attrs, EntryMeta};
use crate::realm::{RealmParams, SCOPE_ONE};

/// `principal_attributes` (ldap_principal.c).
pub const PRINCIPAL_ATTRS: [&str; 23] = [
    "krbprincipalname",
    "krbcanonicalname",
    "objectclass",
    "krbprincipalkey",
    "krbmaxrenewableage",
    "krbmaxticketlife",
    "krbticketflags",
    "krbprincipalexpiration",
    "krbticketpolicyreference",
    "krbUpEnabled",
    "krbpwdpolicyreference",
    "krbpasswordexpiration",
    "krbLastFailedAuth",
    "krbLoginFailedCount",
    "krbLastSuccessfulAuth",
    "nsAccountLock",
    "krbLastPwdChange",
    "krbLastAdminUnlock",
    "krbPrincipalAuthInd",
    "krbExtraData",
    "krbObjectReferences",
    "krbAllowedToDelegateTo",
    "krbPwdHistory",
];

/// The principal search filter prefix (ldap_principal.h:61).
pub const FILTER: &str =
    "(&(|(objectclass=krbprincipalaux)(objectclass=krbprincipal))(krbprincipalname=";

pub(crate) fn ldap_err(op: &str, e: impl std::fmt::Display) -> StoreError {
    StoreError::backend(format!("LDAP {op}: {e}"))
}

fn lower<V>(m: HashMap<String, Vec<V>>) -> HashMap<String, Vec<V>> {
    let mut out: HashMap<String, Vec<V>> = HashMap::new();
    for (k, v) in m {
        out.entry(k.to_ascii_lowercase()).or_default().extend(v);
    }
    out
}

pub(crate) fn attrs_of(se: SearchEntry) -> Attrs {
    Attrs {
        text: lower(se.attrs),
        bin: lower(se.bin_attrs),
    }
}

/// A principal as read from the directory.
pub struct Found {
    /// Directory facts about the entry.
    pub meta: EntryMeta,
    /// The entry in MIT form (keys still master-key encrypted).
    pub entry: MitEntry,
}

pub(crate) struct Inner {
    pub(crate) pool: Pool,
    pub(crate) cfg: LdapConfig,
    pub(crate) realm: String,
    pub(crate) params: RealmParams,
    pub(crate) master: RwLock<MasterKeys>,
    pub(crate) supplied_master: EncryptionKey,
}

/// The kldap store.
#[derive(Clone)]
pub struct LdapStore {
    pub(crate) inner: Arc<Inner>,
    pub(crate) caller: Option<Arc<crate::raw::Caller>>,
}

impl LdapStore {
    /// Connect, bind and read the realm container
    /// (`krb5_ldap_open` + `krb5_ldap_read_server_params` +
    /// `krb5_ldap_read_realm_params`), then load the master keys.
    pub async fn open(
        config: &RealmConfig,
        db_args: &[String],
        srv: ServerType,
        master: &EncryptionKey,
    ) -> Result<Self, StoreError> {
        let store = Self::open_without_master(config, db_args, srv, master).await?;
        store.refresh_master().await?;
        Ok(store)
    }

    /// As [`LdapStore::open`] without reading `K/M`.
    pub async fn open_without_master(
        config: &RealmConfig,
        db_args: &[String],
        srv: ServerType,
        master: &EncryptionKey,
    ) -> Result<Self, StoreError> {
        let cfg = LdapConfig::new(&config.db_module, db_args, srv)?;
        let container = cfg.container_dn.clone().ok_or_else(|| {
            StoreError::new(
                StoreErrorKind::Rejected,
                "Error reading container object: Kerberos Container information is missing"
                    .to_string(),
            )
        })?;
        let pool = Pool::open(&cfg).await?;
        let realm = config.kdc.realm.to_string();
        let realm_dn = format!("cn={realm},{container}");
        let params = {
            let mut h = pool.get().await?;
            let (rs, _) = h
                .search(
                    &realm_dn,
                    Scope::Base,
                    "(objectclass=krbRealmContainer)",
                    vec![
                        "krbSubTrees",
                        "krbPrincContainerRef",
                        "krbSearchScope",
                        "krbMaxTicketLife",
                        "krbMaxRenewableAge",
                        "krbTicketFlags",
                    ],
                )
                .await
                .and_then(|r| r.success())
                .map_err(|e| {
                    StoreError::not_found(format!("Realm {realm} not found in LDAP: {e}"))
                })?;
            let a = rs
                .into_iter()
                .next()
                .map(|e| attrs_of(SearchEntry::construct(e)))
                .ok_or_else(|| StoreError::not_found(format!("Realm {realm} not found in LDAP")))?;
            RealmParams::from_attrs(realm_dn, &a)
        };
        Ok(LdapStore {
            caller: None,
            inner: Arc::new(Inner {
                pool,
                cfg,
                realm,
                params,
                master: RwLock::new(MasterKeys::single(master.clone())),
                supplied_master: master.clone(),
            }),
        })
    }

    /// The realm container's parameters.
    pub fn realm_params(&self) -> &RealmParams {
        &self.inner.params
    }

    /// The configuration in effect.
    pub fn config(&self) -> &LdapConfig {
        &self.inner.cfg
    }

    pub(crate) fn master_keys(&self) -> MasterKeys {
        self.inner
            .master
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// `krb5_db_fetch_mkey_list`: reread `K/M` with the supplied key.
    pub async fn refresh_master(&self) -> Result<(), StoreError> {
        let km = PrincipalName {
            name_type: 1,
            name_string: vec![
                KerberosString::from_bytes(b"K").map_err(|e| StoreError::backend(e.to_string()))?,
                KerberosString::from_bytes(b"M").map_err(|e| StoreError::backend(e.to_string()))?,
            ],
        };
        let raw = self
            .search_raw(&km, &self.inner.realm.clone())
            .await?
            .ok_or_else(|| StoreError::backend("LDAP database has no K/M principal"))?;
        let loaded = self.master_keys();
        let keys = match loaded
            .keys
            .iter()
            .find_map(|(_, key)| MasterKeys::fetch(&raw.entry, key).ok())
        {
            Some(k) => k,
            None => MasterKeys::fetch(&raw.entry, &self.inner.supplied_master)?,
        };
        *self
            .inner
            .master
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = keys;
        Ok(())
    }

    /// `search_princ` + `populate_krb5_db_entry` (ldap_principal2.c:105-280).
    pub async fn search_raw(
        &self,
        name: &PrincipalName,
        realm: &str,
    ) -> Result<Option<Found>, StoreError> {
        if realm != self.inner.realm {
            return Ok(None);
        }
        let user = ldap_unparse_name(name, realm);
        let filter = format!("{FILTER}{}))", filter_correct(&user));
        let p = &self.inner.params;
        let scope = if p.search_scope == SCOPE_ONE {
            Scope::OneLevel
        } else {
            Scope::Subtree
        };
        let mut h = self.inner.pool.get().await?;
        for base in p.search_bases() {
            let r = h
                .search(&base, scope, &filter, PRINCIPAL_ATTRS.to_vec())
                .await;
            let (rs, _) = match r.and_then(|r| r.non_error()) {
                Ok(v) => v,
                Err(ldap3::LdapError::LdapResult { result }) if result.rc == 32 => continue,
                Err(e) => {
                    h.discard();
                    return Err(ldap_err("search", e));
                }
            };
            if rs.len() > 1 {
                return Err(StoreError::new(
                    StoreErrorKind::Rejected,
                    format!(
                        "Operation cannot continue; more than one entry with principal name \"{user}\" found"
                    ),
                ));
            }
            let Some(re) = rs.into_iter().next() else {
                continue;
            };
            let se = SearchEntry::construct(re);
            let dn = se.dn.clone();
            let a = attrs_of(se);
            let (pname, prealm) = match a.first("krbcanonicalname") {
                Some(c) => ldap_parse_name(c)?,
                None => (name.clone(), realm.to_string()),
            };
            let meta = entry_meta(&dn, &a);
            let mut entry = mit_entry(&a, pname, prealm)?;
            drop(h);
            self.apply_tkt_policy(&meta, &mut entry).await?;
            return Ok(Some(Found { meta, entry }));
        }
        Ok(None)
    }

    /// `krb5_read_tkt_policy` (ldap_principal2.c:1565-1613).
    pub(crate) async fn apply_tkt_policy(
        &self,
        meta: &EntryMeta,
        e: &mut MitEntry,
    ) -> Result<(), StoreError> {
        if meta.has_max_life && meta.has_max_rlife && meta.has_flags {
            return Ok(());
        }
        let mut pol: Option<Attrs> = None;
        if let Some(dn) = &meta.tkt_policy_dn {
            let mut h = self.inner.pool.get().await?;
            let r = h
                .search(
                    dn,
                    Scope::Base,
                    "(objectclass=krbTicketPolicy)",
                    vec!["krbMaxTicketLife", "krbMaxRenewableAge", "krbTicketFlags"],
                )
                .await
                .and_then(|r| r.non_error());
            match r {
                Ok((rs, _)) => {
                    pol = rs
                        .into_iter()
                        .next()
                        .map(|x| attrs_of(SearchEntry::construct(x)))
                }
                Err(ldap3::LdapError::LdapResult { result }) if result.rc == 32 => {}
                Err(e) => {
                    return Err(ldap_err("Error reading ticket policy", e));
                }
            }
        }
        let pv = |n: &str| -> Option<u32> {
            pol.as_ref()?
                .first(n)
                .and_then(|v| v.trim().parse::<i64>().ok())
                .map(|v| v as u32)
        };
        let rp = &self.inner.params;
        if !meta.has_max_life {
            if let Some(v) = pv("krbmaxticketlife") {
                e.max_life = v;
            } else if rp.max_life != 0 {
                e.max_life = rp.max_life as u32;
            }
        }
        if !meta.has_max_rlife {
            if let Some(v) = pv("krbmaxrenewableage") {
                e.max_renewable_life = v;
            } else if rp.max_renewable_life != 0 {
                e.max_renewable_life = rp.max_renewable_life as u32;
            }
        }
        if !meta.has_flags {
            if let Some(v) = pv("krbticketflags") {
                e.attributes = v;
            } else if rp.tkt_flags != 0 {
                e.attributes |= rp.tkt_flags as u32;
            }
        }
        Ok(())
    }

    /// Read a principal with its keys decrypted.
    pub async fn get_record(
        &self,
        name: &PrincipalName,
        realm: &str,
    ) -> Result<Option<PrincipalRecord>, StoreError> {
        match self.search_raw(name, realm).await? {
            Some(f) => Ok(Some(record_from_entry(&f.entry, &self.master_keys())?)),
            None => Ok(None),
        }
    }
}

impl PrincipalStore for LdapStore {
    async fn lookup(
        &self,
        name: &PrincipalName,
        realm: &str,
    ) -> Result<Option<PrincipalEntry>, StoreError> {
        Ok(self.get_record(name, realm).await?.map(|r| r.entry))
    }
}
