//! MIT-compatible db2 backend for krb5-rs: MIT's Berkeley DB
//! `principal.db` read and written in place.

pub mod btree;
pub mod codec;
pub mod env;
pub mod store;

pub use store::{CallerStore, Db2Options, Db2Store};
pub mod hash;
