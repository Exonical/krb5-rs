//! MEMORY keytab (kt_memory.c): in-memory entry list.

use super::{get_entry_in, Keytab, KeytabEntry, KtError};
use crate::protocol::ap::{ApError, KeySource};
use crate::types::{EncryptionKey, PrincipalName};

/// An in-memory keytab.
#[derive(Default)]
pub struct MemoryKeytab {
    entries: Vec<KeytabEntry>,
}

impl MemoryKeytab {
    /// An empty keytab.
    pub fn new() -> Self {
        Self::default()
    }

    /// A keytab pre-populated with `entries` (test helper).
    pub fn from_entries(entries: Vec<KeytabEntry>) -> Self {
        Self { entries }
    }
}

impl Keytab for MemoryKeytab {
    fn entries(&self) -> Result<Vec<KeytabEntry>, KtError> {
        Ok(self.entries.clone())
    }

    fn get_entry(
        &self,
        principal: &PrincipalName,
        realm: &str,
        kvno: Option<u32>,
        etype: Option<i32>,
    ) -> Result<KeytabEntry, KtError> {
        get_entry_in(&self.entries, principal, realm, kvno, etype)
    }

    fn add_entry(&mut self, entry: &KeytabEntry) -> Result<(), KtError> {
        self.entries.push(entry.clone());
        Ok(())
    }

    fn remove_entry(&mut self, entry: &KeytabEntry) -> Result<(), KtError> {
        match self.entries.iter().position(|e| {
            e.principal.name_string == entry.principal.name_string
                && e.realm == entry.realm
                && e.kvno == entry.kvno
                && e.key.keytype == entry.key.keytype
        }) {
            Some(i) => {
                self.entries.remove(i);
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
