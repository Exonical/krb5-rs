//! MIT-compatible klmdb backend for krb5-rs.

mod store;

pub use store::{CallerStore, LmdbOptions, LmdbStore};
