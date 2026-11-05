//! `kdb5_ldap_util create` (`krb5_ldap_create`, ldap_create.c, and
//! `krb5_ldap_create_realm`, ldap_realm.c:580-700).

use std::collections::HashSet;
use std::time::Duration;

use krb5_rs::kdc::kdb::mit::mkey::MasterKeys;
use krb5_rs::kdc::kdb::mit::{new_entry, unparse_name, MitEntry, TlData, ACTKVNO, MKVNO};
use krb5_rs::kdc::{
    random_keys, KeyEntry, PrincipalAttributes, PrincipalEntry, PrincipalRecord, RealmConfig,
    StoreError,
};
use krb5_rs::types::{EncryptionKey, KerberosString, PrincipalName};
use ldap3::Scope;

use crate::config::{LdapConfig, ServerType};
use crate::conn::Pool;
use crate::realm::SCOPE_SUB;
use crate::store::{ldap_err, LdapStore};
use crate::write::now_time;

fn ks(b: &[u8]) -> Result<KerberosString, StoreError> {
    KerberosString::from_bytes(b).map_err(|e| StoreError::backend(e.to_string()))
}

/// The realm options `kdb5_ldap_util create` takes.
#[derive(Debug, Clone, Default)]
pub struct RealmOptions {
    /// `-subtrees`.
    pub subtrees: Vec<String>,
    /// `-containerref`.
    pub containerref: Option<String>,
    /// `-sscope` (1 or 2; 0 for unset).
    pub search_scope: i32,
    /// `-maxtktlife`, `-maxrenewlife`, ticket flags (0 for unset).
    pub max_life: i32,
    /// See [`RealmOptions::max_life`].
    pub max_renewable_life: i32,
    /// See [`RealmOptions::max_life`].
    pub tkt_flags: i32,
}

/// `K/M` and `krbtgt/REALM` as `kdb5_create` makes them.
pub fn initial_entries(
    config: &RealmConfig,
    master: &EncryptionKey,
) -> Result<Vec<MitEntry>, StoreError> {
    let realm = config.kdc.realm.as_str();
    let life = (config.kdc.max_life != Duration::ZERO).then_some(config.kdc.max_life);
    let renewable =
        (config.kdc.max_renewable_life != Duration::ZERO).then_some(config.kdc.max_renewable_life);
    let expiration = config.default_principal_expiration;
    let now = now_time();
    let creator = PrincipalName {
        name_type: 2,
        name_string: vec![ks(b"db_creation")?],
    };
    let creator_key = unparse_name(&creator, realm);
    let record = |name: PrincipalName, attributes, keys| PrincipalRecord {
        unlock: false,
        entry: PrincipalEntry {
            name,
            realm: realm.to_owned(),
            attributes,
            max_life: life,
            max_renewable_life: renewable,
            expiration,
            pw_expiration: None,
            keys,
            allowed_to_delegate_to: Vec::new(),
            allowed_to_delegate_from: Vec::new(),
            require_auth: None,
            otp: None,
            policy: None,
            security_epoch: 0,
            last_admin_unlock: None,
        },
        last_pwd_change: None,
        mod_time: Some(now),
        mod_by: Some(creator_key.clone()),
        password_history: None,
    };
    let single = MasterKeys::single(master.clone());
    let km_name = PrincipalName {
        name_type: 1,
        name_string: vec![ks(b"K")?, ks(b"M")?],
    };
    let km_record = record(
        km_name,
        PrincipalAttributes::DISALLOW_ALL_TIX | PrincipalAttributes::LOCKDOWN_KEYS,
        vec![KeyEntry {
            kvno: 1,
            key: master.clone(),
            salt: None,
            s2kparams: None,
        }],
    );
    let mut km = new_entry(&km_record, &single, &creator_key)?;
    let mkvno_tl = km
        .tl_data
        .iter()
        .position(|tl| tl.kind == MKVNO)
        .map(|at| km.tl_data.remove(at));
    let mut actkvno = Vec::with_capacity(8);
    actkvno.extend_from_slice(&1u16.to_le_bytes());
    actkvno.extend_from_slice(&1u16.to_le_bytes());
    actkvno.extend_from_slice(&0u32.to_le_bytes());
    km.tl_data.push(TlData {
        kind: ACTKVNO,
        data: actkvno,
    });
    km.tl_data.extend(mkvno_tl);
    let mut tgt_keys = Vec::with_capacity(config.supported_keysalts.len());
    for (enctype, _) in &config.supported_keysalts {
        let mut key = random_keys(1, &[*enctype])
            .map_err(|e| StoreError::backend(e.to_string()))?
            .pop()
            .ok_or_else(|| StoreError::backend("no random krbtgt key generated"))?;
        key.salt = None;
        tgt_keys.push(key);
    }
    let tgt_name = PrincipalName {
        name_type: 2,
        name_string: vec![ks(b"krbtgt")?, ks(realm.as_bytes())?],
    };
    let mut tgt = new_entry(
        &record(tgt_name, PrincipalAttributes::LOCKDOWN_KEYS, tgt_keys),
        &single,
        &creator_key,
    )?;
    tgt.tl_data.retain(|tl| tl.kind != MKVNO);
    Ok(vec![km, tgt])
}

/// The first RDN's value (`ldap_explode_dn(dn, 1)[0]`).
fn first_rdn_value(dn: &str) -> String {
    let rdn = dn.split(',').next().unwrap_or(dn);
    rdn.split_once('=')
        .map_or(rdn, |(_, v)| v)
        .trim()
        .to_string()
}

fn set(v: impl Into<String>) -> HashSet<Vec<u8>> {
    HashSet::from([v.into().into_bytes()])
}

impl LdapStore {
    /// `kdb5_ldap_util create`: the Kerberos container if missing, the realm
    /// object, then `K/M` and `krbtgt/REALM`.
    pub async fn create_realm(
        config: &RealmConfig,
        db_args: &[String],
        master: &EncryptionKey,
        opts: &RealmOptions,
    ) -> Result<Self, StoreError> {
        let cfg = LdapConfig::new(&config.db_module, db_args, ServerType::Admin)?;
        let container = cfg
            .container_dn
            .clone()
            .ok_or_else(|| StoreError::rejected("Kerberos Container information is missing"))?;
        let realm = config.kdc.realm.to_string();
        {
            let pool = Pool::open(&cfg).await?;
            let mut h = pool.get().await?;
            let exists = match h
                .search(&container, Scope::Base, "(objectclass=*)", vec!["1.1"])
                .await
                .and_then(|r| r.non_error())
            {
                Ok(_) => true,
                Err(ldap3::LdapError::LdapResult { result }) if result.rc == 32 => false,
                Err(e) => return Err(ldap_err("Error reading container object", e)),
            };
            if !exists {
                h.add(
                    &container,
                    vec![
                        (b"objectclass".to_vec(), set("krbContainer")),
                        (b"cn".to_vec(), set(first_rdn_value(&container))),
                    ],
                )
                .await
                .and_then(|r| r.success())
                .map_err(|e| ldap_err("Kerberos Container create FAILED", e))?;
            }
            let mut attrs = vec![
                (b"cn".to_vec(), set(realm.clone())),
                (
                    b"objectclass".to_vec(),
                    ["top", "krbrealmcontainer", "krbticketpolicyaux"]
                        .into_iter()
                        .map(|s| s.as_bytes().to_vec())
                        .collect(),
                ),
            ];
            if !opts.subtrees.is_empty() {
                attrs.push((
                    b"krbsubtrees".to_vec(),
                    opts.subtrees
                        .iter()
                        .map(|s| s.as_bytes().to_vec())
                        .collect(),
                ));
            }
            if let Some(c) = &opts.containerref {
                attrs.push((b"krbPrincContainerRef".to_vec(), set(c.clone())));
            }
            let scope = if opts.search_scope == 0 {
                SCOPE_SUB
            } else {
                opts.search_scope
            };
            attrs.push((b"krbsearchscope".to_vec(), set(scope.to_string())));
            for (n, v) in [
                ("krbMaxRenewableAge", opts.max_renewable_life),
                ("krbMaxTicketLife", opts.max_life),
                ("krbTicketFlags", opts.tkt_flags),
            ] {
                if v != 0 {
                    attrs.push((n.as_bytes().to_vec(), set(v.to_string())));
                }
            }
            match h
                .add(&format!("cn={realm},{container}"), attrs)
                .await
                .and_then(|r| r.success())
            {
                Ok(_) => {}
                Err(ldap3::LdapError::LdapResult { result }) if result.rc == 68 => {
                    return Err(StoreError::conflict(format!(
                        "Kerberos realm {realm} already exists"
                    )));
                }
                Err(e) => return Err(ldap_err("Creating realm", e)),
            }
        }
        let store =
            LdapStore::open_without_master(config, db_args, ServerType::Admin, master).await?;
        for e in initial_entries(config, master)? {
            store.add_entry(&e).await?;
        }
        store.refresh_master().await?;
        Ok(store)
    }
}
