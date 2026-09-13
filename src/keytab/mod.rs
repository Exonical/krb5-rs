//! Kerberos keytabs — MIT FILE (v1/v2) and MEMORY formats.
//!
//! File layout follows kt_file.c; entry selection follows
//! krb5_ktfile_get_entry / more_recent.

mod file;
mod memory;

use crate::protocol::ap::ApError;
use crate::types::{EncryptionKey, PrincipalName};

pub use file::FileKeytab;
pub use memory::MemoryKeytab;

/// A keytab entry (MIT `krb5_keytab_entry`).
#[derive(Debug, Clone)]
pub struct KeytabEntry {
    /// Service principal (name type preserved, ignored on compare).
    pub principal: PrincipalName,
    /// Principal realm.
    pub realm: String,
    /// Entry write timestamp (unix seconds).
    pub timestamp: u32,
    /// Key version number (full 32-bit value).
    pub kvno: u32,
    /// The key.
    pub key: EncryptionKey,
}

/// Keytab errors (MIT KRB5_KT_*).
#[derive(Debug, thiserror::Error)]
pub enum KtError {
    /// No entry for the principal (KRB5_KT_NOTFOUND).
    #[error("keytab entry not found")]
    NotFound,
    /// Principal found but not the requested kvno (KRB5_KT_KVNONOTFOUND).
    #[error("keytab kvno not found")]
    KvnoNotFound,
    /// Malformed data (KRB5_KT_FORMAT).
    #[error("keytab format error")]
    Format,
    /// Iteration reached the end (KRB5_KT_END).
    #[error("end of keytab")]
    End,
    /// I/O error.
    #[error("keytab I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// A keytab (MIT `krb5_keytab` operations).
pub trait Keytab {
    /// All entries in the keytab.
    fn entries(&self) -> Result<Vec<KeytabEntry>, KtError>;

    /// Fetch an entry (kt_file.c:286-420). `None` kvno selects the most
    /// recent per `more_recent` wraparound heuristics; an explicit kvno
    /// matches exactly, falling back to the low 8 bits for pre-1.14
    /// keytabs.
    fn get_entry(
        &self,
        principal: &PrincipalName,
        realm: &str,
        kvno: Option<u32>,
        etype: Option<i32>,
    ) -> Result<KeytabEntry, KtError>;

    /// Add an entry (reusing deleted holes, find_slot).  FILE keytabs in
    /// the v1 (0x0501) format are read-only: only v2 records are written,
    /// so mutation of a v1 file fails with `KtError::Format`.
    fn add_entry(&mut self, entry: &KeytabEntry) -> Result<(), KtError>;

    /// Delete the entry matching principal+realm+kvno+etype.  v1 FILE
    /// keytabs are read-only (`KtError::Format`), as for `add_entry`.
    fn remove_entry(&mut self, entry: &KeytabEntry) -> Result<(), KtError>;
}

/// more_recent (kt_file.c:257-276): is k1 more recent than k2, applying
/// kvno wraparound heuristics.
pub(crate) fn more_recent(k1: &KeytabEntry, k2: &KeytabEntry) -> bool {
    // A small kvno written at the same time or later than a large kvno
    // probably wrapped — treat it as more recent.
    if k2.timestamp <= k1.timestamp && k1.kvno < 128 && k2.kvno > 240 {
        return true;
    }
    if k1.timestamp <= k2.timestamp && k1.kvno > 240 && k2.kvno < 128 {
        return false;
    }
    k1.kvno > k2.kvno
}

/// Shared get_entry over an entry list (kt_file.c:322-408).
pub(crate) fn get_entry_in(
    entries: &[KeytabEntry],
    principal: &PrincipalName,
    realm: &str,
    kvno: Option<u32>,
    etype: Option<i32>,
) -> Result<KeytabEntry, KtError> {
    let mut cur: Option<KeytabEntry> = None;
    let mut found_wrong_kvno = false;
    for e in entries {
        // princ_comp.c: name type is not compared.
        if e.principal.name_string != principal.name_string || e.realm != realm {
            continue;
        }
        if let Some(t) = etype {
            if t != e.key.keytype {
                continue;
            }
        }
        match kvno {
            None => {
                // IGNORE_VNO path (also for stored vno 0): keep most recent.
                if cur.as_ref().is_none_or(|c| more_recent(e, c)) {
                    cur = Some(e.clone());
                }
            }
            Some(_) if e.kvno == 0 => {
                if cur.as_ref().is_none_or(|c| more_recent(e, c)) {
                    cur = Some(e.clone());
                }
            }
            Some(k) if e.kvno == k => {
                cur = Some(e.clone());
                break;
            }
            Some(k) if e.kvno == (k & 0xff) && cur.is_none() => {
                cur = Some(e.clone());
            }
            Some(_) => found_wrong_kvno = true,
        }
    }
    match cur {
        Some(e) => Ok(e),
        None if found_wrong_kvno => Err(KtError::KvnoNotFound),
        None => Err(KtError::NotFound),
    }
}

/// Map a keytab lookup error to the AP error used by rd_req_dec.c
/// (NOTFOUND → NOKEY, KVNONOTFOUND → BADKEYVER for the explicit-server
/// path this KeySource serves).
pub(crate) fn kt_to_ap(e: KtError) -> ApError {
    match e {
        KtError::KvnoNotFound => ApError::BadKeyver,
        _ => ApError::NoKey,
    }
}
