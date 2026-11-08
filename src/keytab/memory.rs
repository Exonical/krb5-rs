//! MEMORY keytab (kt_memory.c): in-memory entry list.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError};

use super::{get_entry_in, Keytab, KeytabEntry, KtError};
use crate::protocol::ap::{ApError, KeySource};
use crate::types::{EncryptionKey, PrincipalName};

type Entries = Arc<Mutex<Vec<KeytabEntry>>>;

/// `krb5int_mkt_list`: the process's named MEMORY keytabs.
fn registry() -> MutexGuard<'static, HashMap<String, Entries>> {
    static LIST: OnceLock<Mutex<HashMap<String, Entries>>> = OnceLock::new();
    LIST.get_or_init(Default::default)
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
}

/// An in-memory keytab. Handles from [`MemoryKeytab::resolve`] with the
/// same name share their entries.
#[derive(Default, Clone)]
pub struct MemoryKeytab {
    entries: Entries,
}

impl MemoryKeytab {
    /// An empty, unnamed keytab.
    pub fn new() -> Self {
        Self::default()
    }

    /// A keytab pre-populated with `entries` (test helper).
    pub fn from_entries(entries: Vec<KeytabEntry>) -> Self {
        Self {
            entries: Arc::new(Mutex::new(entries)),
        }
    }

    /// `krb5_mkt_resolve`: the `MEMORY:name` keytab, created empty on
    /// first use. As in MIT, its entries live until the process exits,
    /// after every handle is dropped.
    pub fn resolve(name: &str) -> Self {
        Self {
            entries: Arc::clone(registry().entry(name.to_string()).or_default()),
        }
    }

    fn lock(&self) -> MutexGuard<'_, Vec<KeytabEntry>> {
        self.entries.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl Keytab for MemoryKeytab {
    fn entries(&self) -> Result<Vec<KeytabEntry>, KtError> {
        Ok(self.lock().clone())
    }

    fn get_entry(
        &self,
        principal: &PrincipalName,
        realm: &str,
        kvno: Option<u32>,
        etype: Option<i32>,
    ) -> Result<KeytabEntry, KtError> {
        get_entry_in(&self.lock(), principal, realm, kvno, etype)
    }

    fn add_entry(&mut self, entry: &KeytabEntry) -> Result<(), KtError> {
        self.lock().push(entry.clone());
        Ok(())
    }

    fn remove_entry(&mut self, entry: &KeytabEntry) -> Result<(), KtError> {
        let mut entries = self.lock();
        match entries.iter().position(|e| {
            e.principal.name_string == entry.principal.name_string
                && e.realm == entry.realm
                && e.kvno == entry.kvno
                && e.key.keytype == entry.key.keytype
        }) {
            Some(i) => {
                entries.remove(i);
                Ok(())
            }
            None => Err(KtError::NotFound),
        }
    }
}

impl KeySource for MemoryKeytab {
    fn get_key(
        &self,
        server: &PrincipalName,
        realm: &[u8],
        kvno: Option<i32>,
        etype: i32,
    ) -> Result<EncryptionKey, ApError> {
        super::ap_key_for(self, server, realm, kvno, etype)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(kvno: u32) -> KeytabEntry {
        KeytabEntry {
            principal: PrincipalName::new_principal("p"),
            realm: "R".into(),
            timestamp: 0,
            kvno,
            key: EncryptionKey::new(18, vec![0u8; 32]),
        }
    }

    #[test]
    fn resolve_shares_entries_by_name_like_mit() {
        let mut a = MemoryKeytab::resolve("memory-test-shared");
        a.add_entry(&entry(1)).expect("add");
        drop(a);
        let b = MemoryKeytab::resolve("memory-test-shared");
        assert_eq!(b.entries().expect("entries").len(), 1);
        assert!(MemoryKeytab::resolve("memory-test-other")
            .entries()
            .expect("entries")
            .is_empty());
    }
}
