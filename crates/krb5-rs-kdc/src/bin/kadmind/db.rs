//! The database kadmind administers: klmdb, or CockroachDB when
//! `db_library = krb5-rs-cockroach` (MIT's kadmind goes through whichever
//! KDB module `db_library` names).

use std::future::Future;
use std::sync::Arc;

use krb5_rs::kdc::kdb::mit::mkey::MasterKeys;
use krb5_rs::kdc::kdb::mit::{MitEntry, MitPolicy, TlData};
use krb5_rs::kdc::store::{AdminStore, Policy, PrincipalRecord, StoreError};
use krb5_rs::kdc::PrincipalEntry;
use krb5_rs::types::{KerberosTime, PrincipalName};
#[cfg(feature = "cockroach")]
use krb5_rs_kdb_cockroach::CockroachStore;
use krb5_rs_kdb_lmdb::{CallerStore, LmdbStore};

#[derive(Clone)]
pub enum Db {
    Lmdb(Arc<LmdbStore>),
    #[cfg(feature = "cockroach")]
    Cockroach(CockroachStore),
}

/// Run a CockroachDB call to completion from synchronous code, on the
/// current runtime but off this thread (which may itself be a runtime
/// worker, where `block_on` would panic).
#[cfg(feature = "cockroach")]
fn wait<F>(f: F) -> F::Output
where
    F: Future + Send,
    F::Output: Send,
{
    let handle = tokio::runtime::Handle::current();
    std::thread::scope(|s| {
        s.spawn(|| handle.block_on(f))
            .join()
            .unwrap_or_else(|p| std::panic::resume_unwind(p))
    })
}

impl Db {
    /// The klmdb store, which iprop needs.
    pub fn lmdb(&self) -> Option<&Arc<LmdbStore>> {
        match self {
            Db::Lmdb(s) => Some(s),
            #[cfg(feature = "cockroach")]
            Db::Cockroach(_) => None,
        }
    }

    /// The decrypted entry for a service key (`kdb_get_entry`).
    pub fn principal_sync(
        &self,
        name: &PrincipalName,
        realm: &str,
    ) -> Result<Option<PrincipalEntry>, StoreError> {
        match self {
            Db::Lmdb(s) => s.principal_sync(name, realm),
            #[cfg(feature = "cockroach")]
            Db::Cockroach(s) => {
                wait(AdminStore::get_record(s, name, realm)).map(|r| r.map(|r| r.entry))
            }
        }
    }

    pub fn raw_entry(
        &self,
        name: &PrincipalName,
        realm: &str,
    ) -> Result<Option<MitEntry>, StoreError> {
        match self {
            Db::Lmdb(s) => s.raw_entry(name, realm),
            #[cfg(feature = "cockroach")]
            Db::Cockroach(s) => wait(s.raw_entry(name, realm)),
        }
    }

    pub fn raw_policy(&self, name: &str) -> Result<Option<MitPolicy>, StoreError> {
        match self {
            Db::Lmdb(s) => s.raw_policy(name),
            #[cfg(feature = "cockroach")]
            Db::Cockroach(s) => wait(s.raw_policy(name)),
        }
    }

    pub fn create_raw(&self, raw: &MitEntry) -> Result<(), StoreError> {
        match self {
            Db::Lmdb(s) => s.create_raw(raw),
            #[cfg(feature = "cockroach")]
            Db::Cockroach(s) => wait(s.create_raw(raw)),
        }
    }

    /// `f` may run more than once: CockroachDB retries conflicting
    /// transactions.
    pub fn rename_raw<F>(&self, name: &PrincipalName, realm: &str, f: F) -> Result<(), StoreError>
    where
        F: FnMut(MitEntry, &MasterKeys) -> Result<MitEntry, StoreError> + Send,
    {
        match self {
            Db::Lmdb(s) => s.rename_raw(name, realm, f),
            #[cfg(feature = "cockroach")]
            Db::Cockroach(s) => wait(s.rename_raw(name, realm, f)),
        }
    }

    /// `f` may run more than once, as for [`Db::rename_raw`].
    pub fn update_raw<F>(&self, name: &PrincipalName, realm: &str, f: F) -> Result<bool, StoreError>
    where
        F: FnMut(&mut MitEntry, &MasterKeys) -> Result<bool, StoreError> + Send,
    {
        match self {
            Db::Lmdb(s) => s.update_raw(name, realm, f),
            #[cfg(feature = "cockroach")]
            Db::Cockroach(s) => wait(s.update_raw(name, realm, f)),
        }
    }

    pub fn raw_entries(&self) -> Result<Vec<MitEntry>, StoreError> {
        match self {
            Db::Lmdb(s) => s.raw_entries(),
            #[cfg(feature = "cockroach")]
            Db::Cockroach(s) => wait(s.raw_entries()),
        }
    }

    pub fn policy_names_sync(&self) -> Result<Vec<String>, StoreError> {
        match self {
            Db::Lmdb(s) => s.policy_names_sync(),
            #[cfg(feature = "cockroach")]
            Db::Cockroach(s) => Ok(wait(AdminStore::list_policies(s))?
                .into_iter()
                .map(|p| p.name)
                .collect()),
        }
    }

    pub fn master_key_list(&self) -> Result<MasterKeys, StoreError> {
        match self {
            Db::Lmdb(s) => s.master_key_list(),
            #[cfg(feature = "cockroach")]
            Db::Cockroach(s) => Ok(s.master_keys()),
        }
    }

    /// This database, writing principals for the kadmin client `modifier`.
    pub fn as_caller(&self, modifier: Vec<u8>) -> CallerDb {
        match self {
            Db::Lmdb(s) => CallerDb::Lmdb(s.as_caller(modifier)),
            #[cfg(feature = "cockroach")]
            Db::Cockroach(s) => {
                CallerDb::Cockroach(s.as_caller(modifier.clone(), Vec::new()), modifier)
            }
        }
    }
}

#[derive(Clone)]
pub enum CallerDb {
    Lmdb(CallerStore),
    /// The caller's store and the modifier it was made for.
    #[cfg(feature = "cockroach")]
    Cockroach(CockroachStore, Vec<u8>),
}

impl CallerDb {
    /// Also add the client's tl-data to principals it creates or modifies.
    pub fn with_tl_data(self, tl: Vec<TlData>) -> Self {
        match self {
            CallerDb::Lmdb(s) => CallerDb::Lmdb(s.with_tl_data(tl)),
            #[cfg(feature = "cockroach")]
            CallerDb::Cockroach(s, modifier) => {
                CallerDb::Cockroach(s.as_caller(modifier.clone(), tl), modifier)
            }
        }
    }
}

macro_rules! delegate_admin_store {
    ($ty:ident, $lmdb:pat => $l:expr, $crdb:pat => $c:expr) => {
        impl AdminStore for $ty {
            fn get_record(
                &self,
                name: &PrincipalName,
                realm: &str,
            ) -> impl Future<Output = Result<Option<PrincipalRecord>, StoreError>> + Send {
                async move {
                    match self {
                        $lmdb => $l.get_record(name, realm).await,
                        #[cfg(feature = "cockroach")]
                        $crdb => $c.get_record(name, realm).await,
                    }
                }
            }

            fn create_principal(
                &self,
                entry: PrincipalEntry,
                last_pwd_change: Option<KerberosTime>,
            ) -> impl Future<Output = Result<(), StoreError>> + Send {
                async move {
                    match self {
                        $lmdb => $l.create_principal(entry, last_pwd_change).await,
                        #[cfg(feature = "cockroach")]
                        $crdb => $c.create_principal(entry, last_pwd_change).await,
                    }
                }
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
                async move {
                    match self {
                        $lmdb => $l.update_principal(name, realm, f).await,
                        #[cfg(feature = "cockroach")]
                        $crdb => $c.update_principal(name, realm, f).await,
                    }
                }
            }

            fn delete_principal(
                &self,
                name: &PrincipalName,
                realm: &str,
            ) -> impl Future<Output = Result<bool, StoreError>> + Send {
                async move {
                    match self {
                        $lmdb => $l.delete_principal(name, realm).await,
                        #[cfg(feature = "cockroach")]
                        $crdb => $c.delete_principal(name, realm).await,
                    }
                }
            }

            fn list_principals(
                &self,
            ) -> impl Future<Output = Result<Vec<PrincipalRecord>, StoreError>> + Send {
                async move {
                    match self {
                        $lmdb => $l.list_principals().await,
                        #[cfg(feature = "cockroach")]
                        $crdb => $c.list_principals().await,
                    }
                }
            }

            fn get_policy(
                &self,
                name: &str,
            ) -> impl Future<Output = Result<Option<Policy>, StoreError>> + Send {
                async move {
                    match self {
                        $lmdb => $l.get_policy(name).await,
                        #[cfg(feature = "cockroach")]
                        $crdb => $c.get_policy(name).await,
                    }
                }
            }

            fn create_policy(
                &self,
                policy: Policy,
            ) -> impl Future<Output = Result<(), StoreError>> + Send {
                async move {
                    match self {
                        $lmdb => $l.create_policy(policy).await,
                        #[cfg(feature = "cockroach")]
                        $crdb => $c.create_policy(policy).await,
                    }
                }
            }

            fn update_policy<F>(
                &self,
                name: &str,
                f: F,
            ) -> impl Future<Output = Result<Policy, StoreError>> + Send
            where
                F: FnMut(&mut Policy) -> Result<(), StoreError> + Send + 'static,
            {
                async move {
                    match self {
                        $lmdb => $l.update_policy(name, f).await,
                        #[cfg(feature = "cockroach")]
                        $crdb => $c.update_policy(name, f).await,
                    }
                }
            }

            fn delete_policy(
                &self,
                name: &str,
            ) -> impl Future<Output = Result<bool, StoreError>> + Send {
                async move {
                    match self {
                        $lmdb => $l.delete_policy(name).await,
                        #[cfg(feature = "cockroach")]
                        $crdb => $c.delete_policy(name).await,
                    }
                }
            }

            fn list_policies(
                &self,
            ) -> impl Future<Output = Result<Vec<Policy>, StoreError>> + Send {
                async move {
                    match self {
                        $lmdb => $l.list_policies().await,
                        #[cfg(feature = "cockroach")]
                        $crdb => $c.list_policies().await,
                    }
                }
            }
        }
    };
}

delegate_admin_store!(Db, Db::Lmdb(s) => (**s), Db::Cockroach(s) => s);
delegate_admin_store!(CallerDb, CallerDb::Lmdb(s) => s, CallerDb::Cockroach(s, _) => s);
