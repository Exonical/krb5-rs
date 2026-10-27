//! Pure-Rust MIT 1.17+ klmdb record formats.
//!
//! Principal, lockout, and policy values follow `plugins/kdb/lmdb/marshal.c`.
//! This module deliberately keeps the raw tl-data and key-data lists so
//! updates can merge krb5-rs-owned fields without discarding MIT extensions.

mod codec;
pub mod dump;
pub mod mkey;
mod name;
mod tl;
#[cfg(unix)]
pub mod ulog;
mod xdr;

pub use codec::{decode_lockout, encode_lockout, KeyData, MitEntry, MitPolicy, TlData};
pub use name::{parse_name, parse_name_with_default, unparse_name};
pub use tl::{
    constrained_delegation_values, history_entry, history_key_matches, merge_policy, merge_record,
    new_entry, policy_from_entry, policy_to_entry, record_from_entry, record_without_keys,
    set_key_change, set_mod_princ, set_string_attr, string_attributes, update_tl_data,
    StringAttribute, ACTKVNO, CONSTRAINED_DELEGATION_ACL, KADM5_POLICY, KADM_DATA,
    LAST_ADMIN_UNLOCK, LAST_PWD_CHANGE, MKEY_AUX, MKVNO, MOD_PRINC, STRING_ATTRS,
};
pub use xdr::OsaPrincipalData;
