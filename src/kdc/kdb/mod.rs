//! Persistent principal database and its administration.
//!
//! [`FileStore`] uses this crate's `KRB5RSDB`/DER file format. [`mit`] contains
//! the pure-Rust record codecs shared with the opt-in MIT klmdb backend in
//! `krb5-rs-kdb-lmdb`. Keys use MIT's master-key encryption layout
//! (`lib/kdb/encrypt_key.c`); the master key stash is MIT keytab format
//! (`lib/kdb/kdb_default.c`).

pub mod acl;
pub mod admin;
mod file;
mod format;
pub mod getdate;
pub mod kadm5;
pub mod kadm5_auth;
pub mod kadm5_hook;
#[cfg(feature = "tokio")]
pub mod kpasswd;
#[cfg(feature = "tokio")]
pub mod kprop;
pub mod master;
pub mod mit;
pub mod pwqual;
pub mod restrictions;
pub mod test;

pub use crate::kdc::store::PrincipalRecord;
pub use file::{FileCaller, FileStore};
pub use master::{
    master_key_from_password, master_key_from_password_named, read_stash, read_stash_named,
    write_stash, write_stash_named,
};
