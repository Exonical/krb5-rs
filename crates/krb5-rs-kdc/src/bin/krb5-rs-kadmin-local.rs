//! `kadmin.local` (MIT `src/kadmin/cli` linked with libkadm5srv): the
//! `kadmin` command interpreter run directly on the KDB, with the stashed
//! master key and every privilege, without kadmind.

#[path = "../../../krb5-rs-clients/src/bin/kadmin.rs"]
mod kadmin;
#[expect(dead_code, reason = "only the shared entry points are used")]
#[path = "krb5-rs-kadmind.rs"]
mod kadmind;

use krb5_rs::kdc::kdb::kadm5::code;
use krb5_rs_clients::kadm5::{Error, Handle};

fn main() {
    kadmin::run(Some(&|p: &kadmin::LocalParams<'_>| {
        let mut call =
            kadmind::local_call(p.realm, p.db_args, p.master_password, p.keysalts, p.client)?;
        Handle::local(Box::new(move |proc_, args| {
            call(proc_, args).map_err(|_| Error::Kadm5(code::RPC_ERROR))
        }))
        .map_err(|e| e.to_string())
    }));
}
