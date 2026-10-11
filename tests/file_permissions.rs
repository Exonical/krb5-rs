//! Key and credential files are created private (MIT cc_file.c:342, 483,
//! 869-875; kdb_db2.c:455, 698, 718) and rewriting existing files still
//! round-trips. Mode assertions run on Unix only.

use std::path::PathBuf;

use krb5_rs::ccache::{Ccache, FileCcache};
use krb5_rs::keytab::{FileKeytab, Keytab, KeytabEntry};
use krb5_rs::types::{EncryptionKey, PrincipalName};

fn tmp(name: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!("krb5rs_perm_{}_{name}", std::process::id()));
    let _ = std::fs::remove_file(&p);
    p
}

#[cfg(unix)]
fn mode(p: &std::path::Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(p).expect("metadata").permissions().mode() & 0o777
}

fn entry(kvno: u32) -> KeytabEntry {
    KeytabEntry {
        principal: PrincipalName::new_srv_hst("HTTP", "h.example"),
        realm: "EXAMPLE.COM".into(),
        timestamp: 1,
        kvno,
        key: EncryptionKey::new(18, vec![kvno as u8; 32]),
    }
}

#[test]
fn keytab_rewrite_of_existing_file_round_trips() {
    let path = tmp("rewrite.keytab");
    let mut kt = FileKeytab::new(&path);
    kt.add_entry(&entry(1)).expect("add 1");
    kt.add_entry(&entry(2)).expect("add 2");
    kt.remove_entry(&entry(1)).expect("remove 1");
    kt.add_entry(&entry(3)).expect("add 3");
    let kvnos: Vec<u32> = kt
        .entries()
        .expect("entries")
        .iter()
        .map(|e| e.kvno)
        .collect();
    assert_eq!(kvnos, vec![3, 2]);
    let _ = std::fs::remove_file(&path);
}

#[test]
fn ccache_reinitialize_of_existing_file_round_trips() {
    let path = tmp("rewrite.cc");
    let mut cc = FileCcache::new(&path);
    let alice = PrincipalName::new_principal("alice");
    let bob = PrincipalName::new_principal("bob");
    cc.initialize(&alice, "EXAMPLE.COM").expect("init alice");
    cc.initialize(&bob, "EXAMPLE.COM").expect("init bob");
    assert_eq!(cc.principal().expect("principal").0, bob);
    let _ = std::fs::remove_file(&path);
}

#[cfg(unix)]
#[test]
fn keytab_is_created_mode_0600() {
    let path = tmp("mode.keytab");
    FileKeytab::new(&path).add_entry(&entry(1)).expect("add");
    assert_eq!(mode(&path), 0o600);
    let _ = std::fs::remove_file(&path);
}

#[cfg(unix)]
#[test]
fn keytab_rewrite_keeps_an_administrators_looser_mode() {
    use std::os::unix::fs::PermissionsExt;
    let path = tmp("keep.keytab");
    let mut kt = FileKeytab::new(&path);
    kt.add_entry(&entry(1)).expect("add");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).expect("chmod");
    kt.add_entry(&entry(2)).expect("add again");
    assert_eq!(mode(&path), 0o640);
    let _ = std::fs::remove_file(&path);
}

#[cfg(unix)]
#[test]
fn ccache_initialize_creates_and_tightens_to_mode_0600() {
    use std::os::unix::fs::PermissionsExt;
    let path = tmp("mode.cc");
    let mut cc = FileCcache::new(&path);
    let alice = PrincipalName::new_principal("alice");
    cc.initialize(&alice, "EXAMPLE.COM").expect("init");
    assert_eq!(mode(&path), 0o600);
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).expect("chmod");
    cc.initialize(&alice, "EXAMPLE.COM").expect("re-init");
    assert_eq!(mode(&path), 0o600);
    let _ = std::fs::remove_file(&path);
}

#[cfg(all(unix, feature = "kdc"))]
mod kdc {
    use super::*;
    use krb5_rs::kdc::kdb::{master_key_from_password, write_stash, FileStore};

    #[test]
    fn database_stash_and_tmp_files_are_mode_0600() {
        let db = tmp("principal");
        let stash = tmp("stash");
        let key = master_key_from_password("R", "pw", 18).expect("key");
        let store = FileStore::create(&db, "R", &key).expect("create");
        assert_eq!(mode(&db), 0o600);
        let name = PrincipalName::new_principal("p");
        store
            .put(krb5_rs::kdc::PrincipalEntry {
                allowed_to_delegate_to: Vec::new(),
                allowed_to_delegate_from: Vec::new(),
                policy: None,
                security_epoch: 0,
                last_admin_unlock: None,
                name,
                realm: "R".into(),
                attributes: krb5_rs::kdc::PrincipalAttributes::empty(),
                max_life: None,
                max_renewable_life: None,
                expiration: None,
                pw_expiration: None,
                keys: Vec::new(),
            })
            .expect("put");
        assert_eq!(mode(&db), 0o600);
        write_stash(&stash, "R", &key).expect("stash");
        assert_eq!(mode(&stash), 0o600);
        let _ = std::fs::remove_file(&db);
        let _ = std::fs::remove_file(&stash);
    }
}
