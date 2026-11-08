//! `kdb5_ldap_util` for `db_library = kldap`: realm, ticket policy and
//! service password commands. See `kdb/ldap_util.rs`.

#[allow(dead_code, unused_imports)]
#[path = "krb5-rs-kdb.rs"]
mod kdb;

fn main() {
    kdb::ldap_util::main();
}
