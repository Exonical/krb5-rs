//! Persistent principal database and its administration.
//!
//! The database is a single file in this crate's own format (`KRB5RSDB`
//! magic plus DER); it is not compatible with MIT's db2/LMDB databases.
//! Keys are encrypted under the master key as MIT does
//! (lib/kdb/encrypt_key.c), and the master key is kept in a stash file in
//! MIT keytab format (lib/kdb/kdb_default.c).

pub mod admin;
mod file;
mod format;
pub mod master;
#[cfg(feature = "tokio")]
pub mod propagation;

pub use crate::kdc::store::PrincipalRecord;
pub use file::FileStore;
pub use master::{master_key_from_password, read_stash, write_stash};
