#![cfg(feature = "kdc")]
//! Persistent principal database and admin operations (MIT kdb5_util /
//! kadmin.local semantics), plus end-to-end use through the KDC.

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use krb5_rs::crypto::{find_etype, SaltType};
use krb5_rs::kdc::kdb::admin::{Admin, AttrChange, PrincipalOptions};
use krb5_rs::kdc::kdb::{master_key_from_password, read_stash, write_stash, FileStore};
use krb5_rs::kdc::{Kdc, KdcConfig, PrincipalAttributes, PrincipalStore};
use krb5_rs::keytab::{FileKeytab, Keytab};
use krb5_rs::protocol::ap::{ApReqOptions, AuthContext};
use krb5_rs::protocol::{
    AsExchange, AsExchangeConfig, StepResult, TgsExchange, TgsOptions, TgsStepResult,
};
use krb5_rs::types::PrincipalName;
use krb5_rs::Krb5Error;

const REALM: &str = "DB.REALM";

struct TmpDir(PathBuf);

impl TmpDir {
    fn new() -> Self {
        static N: AtomicUsize = AtomicUsize::new(0);
        let dir = std::env::temp_dir().join(format!(
            "krb5rs_kdb_{}_{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).expect("tmp dir");
        Self(dir)
    }

    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }

    fn files(&self) -> Vec<String> {
        let mut v: Vec<String> = std::fs::read_dir(&self.0)
            .expect("read_dir")
            .map(|e| e.expect("entry").file_name().to_string_lossy().to_string())
            .collect();
        v.sort();
        v
    }
}

impl Drop for TmpDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn master() -> krb5_rs::types::EncryptionKey {
    master_key_from_password(REALM, "master-password", 18).expect("master key")
}

fn keysalts() -> Vec<(i32, SaltType)> {
    vec![(18, SaltType::Normal), (17, SaltType::Normal)]
}

fn name(s: &str) -> PrincipalName {
    PrincipalName::new_principal(s)
}

fn setup() -> (TmpDir, FileStore) {
    let dir = TmpDir::new();
    let store = FileStore::create(&dir.path("principal"), REALM, &master()).expect("create");
    (dir, store)
}

#[test]
fn file_store_create_then_open_round_trips_keys_and_salts() {
    let (dir, store) = setup();
    let admin = Admin::new(
        &store,
        vec![(18, SaltType::NoRealm), (17, SaltType::OnlyRealm)],
    );
    admin
        .add_principal(
            &name("alice"),
            REALM,
            Some("pw"),
            &PrincipalOptions::default(),
        )
        .expect("addprinc");
    let before = store
        .lookup(&name("alice"), REALM)
        .expect("lookup")
        .expect("present");
    assert_eq!(before.keys.len(), 2);
    assert_eq!(before.keys[0].salt.as_deref(), Some(b"alice".as_slice()));
    assert_eq!(before.keys[1].salt.as_deref(), Some(REALM.as_bytes()));
    let expected = find_etype(18)
        .expect("etype")
        .string_to_key(b"pw", b"alice", None)
        .expect("s2k");
    assert_eq!(before.keys[0].key.key_bytes(), expected.as_slice());

    let reopened = FileStore::open(&dir.path("principal"), &master()).expect("open");
    let after = reopened
        .lookup(&name("alice"), REALM)
        .expect("lookup")
        .expect("present");
    for (a, b) in before.keys.iter().zip(&after.keys) {
        assert_eq!(a.key.key_bytes(), b.key.key_bytes());
        assert_eq!(
            (a.kvno, a.key.keytype, &a.salt),
            (b.kvno, b.key.keytype, &b.salt)
        );
    }
    assert_eq!(reopened.realm(), REALM);
    let tgt = PrincipalName::new_srv_inst("krbtgt", REALM);
    assert_eq!(
        reopened
            .lookup(&tgt, REALM)
            .expect("lookup")
            .expect("krbtgt")
            .keys
            .len(),
        2
    );
}

#[test]
fn file_store_open_with_wrong_master_key_fails() {
    let (dir, _store) = setup();
    let wrong = master_key_from_password(REALM, "not-the-password", 18).expect("key");
    let err = FileStore::open(&dir.path("principal"), &wrong)
        .err()
        .expect("must fail");
    assert!(
        err.0.contains("master key") || err.0.contains("decrypt"),
        "{}",
        err.0
    );
}

#[test]
fn file_store_create_refuses_to_overwrite_existing_database() {
    let (dir, _store) = setup();
    assert!(FileStore::create(&dir.path("principal"), REALM, &master()).is_err());
}

#[test]
fn file_store_single_byte_corruption_never_yields_a_wrong_key() {
    let (dir, store) = setup();
    Admin::new(&store, keysalts())
        .add_principal(
            &name("victim"),
            REALM,
            Some("pw"),
            &PrincipalOptions::default(),
        )
        .expect("addprinc");
    let original = store
        .lookup(&name("victim"), REALM)
        .expect("lookup")
        .expect("present");
    let path = dir.path("principal");
    let pristine = std::fs::read(&path).expect("read");

    let mut decrypt_failures = 0;
    for i in 8..pristine.len() {
        let mut bytes = pristine.clone();
        bytes[i] ^= 0x01;
        std::fs::write(&path, &bytes).expect("write corrupted");
        let got = FileStore::open(&path, &master()).and_then(|s| s.lookup(&name("victim"), REALM));
        match got {
            Err(e) => {
                if e.0.contains("cannot decrypt stored key") {
                    decrypt_failures += 1;
                }
            }
            Ok(Some(entry)) => {
                for (a, b) in entry.keys.iter().zip(&original.keys) {
                    assert_eq!(
                        a.key.key_bytes(),
                        b.key.key_bytes(),
                        "garbage key at byte {i}"
                    );
                }
            }
            Ok(None) => {}
        }
    }
    assert!(
        decrypt_failures > 0,
        "corrupted ciphertext must be detected"
    );
}

#[test]
fn file_store_write_by_second_instance_is_seen_by_first() {
    let (dir, first) = setup();
    let second = FileStore::open(&dir.path("principal"), &master()).expect("open");
    assert!(first
        .lookup(&name("late"), REALM)
        .expect("lookup")
        .is_none());
    Admin::new(&second, keysalts())
        .add_principal(
            &name("late"),
            REALM,
            Some("pw"),
            &PrincipalOptions::default(),
        )
        .expect("addprinc");
    assert!(first
        .lookup(&name("late"), REALM)
        .expect("lookup")
        .is_some());
    Admin::new(&second, keysalts())
        .delete_principal(&name("late"), REALM)
        .expect("delprinc");
    assert!(first
        .lookup(&name("late"), REALM)
        .expect("lookup")
        .is_none());
}

#[test]
fn file_store_lock_file_blocks_writes_without_corrupting() {
    let (dir, store) = setup();
    let before = std::fs::read(dir.path("principal")).expect("read");
    std::fs::write(dir.path("principal.lock"), b"").expect("lock");
    let err = Admin::new(&store, keysalts())
        .add_principal(&name("x"), REALM, Some("pw"), &PrincipalOptions::default())
        .expect_err("locked");
    assert!(err.0.contains("locked"), "{}", err.0);
    assert_eq!(std::fs::read(dir.path("principal")).expect("read"), before);
    assert!(!dir.files().iter().any(|f| f.ends_with(".tmp")));
    std::fs::remove_file(dir.path("principal.lock")).expect("unlock");
    assert!(FileStore::open(&dir.path("principal"), &master()).is_ok());
    Admin::new(&store, keysalts())
        .add_principal(&name("x"), REALM, Some("pw"), &PrincipalOptions::default())
        .expect("addprinc after unlock");
}

#[test]
fn file_store_leaves_no_tmp_or_lock_files_after_writes() {
    let (dir, store) = setup();
    Admin::new(&store, keysalts())
        .add_principal(&name("a"), REALM, None, &PrincipalOptions::default())
        .expect("addprinc");
    assert_eq!(dir.files(), vec!["principal".to_string()]);
}

#[test]
fn stash_round_trips_master_key() {
    let dir = TmpDir::new();
    let key = master();
    write_stash(&dir.path("stash"), REALM, &key).expect("write");
    let got = read_stash(&dir.path("stash"), REALM).expect("read");
    assert_eq!(
        (got.keytype, got.key_bytes()),
        (key.keytype, key.key_bytes())
    );
    assert_eq!(dir.files(), vec!["stash".to_string()]);
}

#[test]
fn admin_change_password_bumps_kvno_and_drops_or_keeps_old_keys() {
    let (_dir, store) = setup();
    let admin = Admin::new(&store, keysalts());
    admin
        .add_principal(
            &name("bob"),
            REALM,
            Some("one"),
            &PrincipalOptions::default(),
        )
        .expect("addprinc");
    assert_eq!(
        admin
            .change_password(&name("bob"), REALM, Some("two"), false)
            .expect("cpw"),
        2
    );
    let e = store
        .lookup(&name("bob"), REALM)
        .expect("lookup")
        .expect("present");
    assert!(e.keys.iter().all(|k| k.kvno == 2) && e.keys.len() == 2);

    assert_eq!(
        admin
            .change_password(&name("bob"), REALM, None, true)
            .expect("randkey"),
        3
    );
    let e = store
        .lookup(&name("bob"), REALM)
        .expect("lookup")
        .expect("present");
    let mut kvnos: Vec<u32> = e.keys.iter().map(|k| k.kvno).collect();
    kvnos.sort_unstable();
    assert_eq!(kvnos, vec![2, 2, 3, 3]);
    assert_eq!(e.current_kvno_for_test(), 3);
}

trait CurrentKvno {
    fn current_kvno_for_test(&self) -> u32;
}

impl CurrentKvno for krb5_rs::kdc::PrincipalEntry {
    fn current_kvno_for_test(&self) -> u32 {
        self.keys.iter().map(|k| k.kvno).max().unwrap_or(0)
    }
}

#[test]
fn admin_change_password_clears_requires_pwchange() {
    let (_dir, store) = setup();
    let admin = Admin::new(&store, keysalts());
    let mut opts = PrincipalOptions::default();
    opts.attributes.add_spec("+needchange").expect("spec");
    admin
        .add_principal(&name("c"), REALM, Some("a"), &opts)
        .expect("addprinc");
    admin
        .change_password(&name("c"), REALM, Some("b"), false)
        .expect("cpw");
    let e = store
        .lookup(&name("c"), REALM)
        .expect("lookup")
        .expect("present");
    assert!(!e
        .attributes
        .contains(PrincipalAttributes::REQUIRES_PWCHANGE));
}

#[test]
fn admin_ktadd_randomizes_by_default_and_norandkey_keeps_keys() {
    let (dir, store) = setup();
    let admin = Admin::new(&store, keysalts());
    let svc = PrincipalName::new_srv_hst("HTTP", "host.db.realm");
    admin
        .add_principal(&svc, REALM, None, &PrincipalOptions::default())
        .expect("addprinc");
    let old = store.lookup(&svc, REALM).expect("lookup").expect("present");

    let kt_path = dir.path("svc.keytab");
    assert_eq!(
        admin
            .ktadd(&svc, REALM, &kt_path, false)
            .expect("ktadd -norandkey"),
        1
    );
    let kt = FileKeytab::new(&kt_path);
    let entries = kt.entries().expect("entries");
    assert_eq!(entries.len(), 2);
    for e in &entries {
        let db = old
            .keys
            .iter()
            .find(|k| k.key.keytype == e.key.keytype)
            .expect("key");
        assert_eq!(e.key.key_bytes(), db.key.key_bytes());
    }

    let kt2 = dir.path("svc2.keytab");
    assert_eq!(admin.ktadd(&svc, REALM, &kt2, true).expect("ktadd"), 2);
    let new = store.lookup(&svc, REALM).expect("lookup").expect("present");
    assert!(new.keys.iter().all(|k| k.kvno == 2));
    assert_ne!(new.keys[0].key.key_bytes(), old.keys[0].key.key_bytes());
    let got = FileKeytab::new(&kt2).entries().expect("entries");
    assert!(got.iter().all(|e| e.kvno == 2));
    assert_eq!(got.len(), 2);
}

#[test]
fn admin_modify_principal_applies_attribute_and_lifetime_changes() {
    let (_dir, store) = setup();
    let admin = Admin::new(&store, keysalts());
    admin
        .add_principal(&name("m"), REALM, Some("pw"), &PrincipalOptions::default())
        .expect("addprinc");
    let mut change = AttrChange::default();
    change.add_spec("+requires_preauth").expect("spec");
    change.add_spec("-allow_tix").expect("spec");
    change.add_spec("+allow_forwardable").expect("spec");
    let opts = PrincipalOptions {
        attributes: change,
        max_life: Some(Some(std::time::Duration::from_secs(3600))),
        ..PrincipalOptions::default()
    };
    admin
        .modify_principal(&name("m"), REALM, &opts)
        .expect("modprinc");
    let e = store
        .lookup(&name("m"), REALM)
        .expect("lookup")
        .expect("present");
    assert!(e
        .attributes
        .contains(PrincipalAttributes::REQUIRES_PRE_AUTH));
    assert!(e.attributes.contains(PrincipalAttributes::DISALLOW_ALL_TIX));
    assert!(!e
        .attributes
        .contains(PrincipalAttributes::DISALLOW_FORWARDABLE));
    assert_eq!(e.max_life, Some(std::time::Duration::from_secs(3600)));

    let mut undo = AttrChange::default();
    undo.add_spec("-requires_preauth").expect("spec");
    undo.add_spec("+allow_tix").expect("spec");
    admin
        .modify_principal(
            &name("m"),
            REALM,
            &PrincipalOptions {
                attributes: undo,
                ..PrincipalOptions::default()
            },
        )
        .expect("modprinc");
    let e = store
        .lookup(&name("m"), REALM)
        .expect("lookup")
        .expect("present");
    assert!(e.attributes.is_empty());
}

#[test]
fn admin_attr_change_rejects_unknown_attribute_and_accepts_hex() {
    let mut c = AttrChange::default();
    assert!(c.add_spec("+bogus_flag").is_err());
    c.add_spec("0x80").expect("hex");
    assert_eq!(c.set, 0x80);
}

#[test]
fn admin_add_existing_and_delete_missing_principal_fail() {
    let (_dir, store) = setup();
    let admin = Admin::new(&store, keysalts());
    admin
        .add_principal(
            &name("dup"),
            REALM,
            Some("pw"),
            &PrincipalOptions::default(),
        )
        .expect("addprinc");
    assert!(admin
        .add_principal(
            &name("dup"),
            REALM,
            Some("pw"),
            &PrincipalOptions::default()
        )
        .is_err());
    assert!(admin.delete_principal(&name("ghost"), REALM).is_err());
    let list = admin.list_principals().expect("list");
    assert!(list.contains(&"dup@DB.REALM".to_string()));
    assert!(list.contains(&"K/M@DB.REALM".to_string()));
}

#[test]
fn kdc_over_file_store_serves_as_tgs_and_ktadd_keytab_authenticates() {
    let (dir, store) = setup();
    let store = Arc::new(store);
    let admin = Admin::new(&store, keysalts());
    let mut opts = PrincipalOptions::default();
    opts.attributes.add_spec("+requires_preauth").expect("spec");
    admin
        .add_principal(&name("alice"), REALM, Some("alice-pw"), &opts)
        .expect("addprinc alice");
    let svc = PrincipalName::new_srv_hst("HTTP", "server.db.realm");
    admin
        .add_principal(&svc, REALM, None, &PrincipalOptions::default())
        .expect("addprinc svc");
    let kt_path = dir.path("http.keytab");
    admin.ktadd(&svc, REALM, &kt_path, true).expect("ktadd");

    let kdc = Kdc::new(KdcConfig::new(REALM), Arc::clone(&store));

    let config = AsExchangeConfig::new(name("alice"), REALM);
    let mut as_ex = AsExchange::new(config, "alice-pw");
    let mut reply = Vec::new();
    while let StepResult::SendToKdc { data, .. } | StepResult::RetryTcp { data, .. } =
        as_ex.step(&reply).expect("as step")
    {
        reply = kdc.handle(&data);
    }
    let tgt = as_ex.credential().expect("tgt").clone();

    let mut tgs = TgsExchange::new(tgt, svc.clone(), TgsOptions::default());
    let mut reply = Vec::new();
    let st = loop {
        match tgs.step(&reply).expect("tgs step") {
            TgsStepResult::SendToKdc { data, .. } | TgsStepResult::RetryTcp { data, .. } => {
                reply = kdc.handle(&data);
            }
            TgsStepResult::Complete => break tgs.credential().expect("cred").clone(),
        }
    };
    assert_eq!(
        st.ticket.enc_part.kvno,
        Some(2),
        "ktadd bumped the service kvno"
    );

    let ap = AuthContext::new()
        .mk_req(&ApReqOptions::default(), None, &st)
        .expect("mk_req");
    let rd = AuthContext::new()
        .rd_req(&ap, None, &FileKeytab::new(&kt_path))
        .expect("rd_req with ktadd keytab");
    assert_eq!(rd.ticket.cname, name("alice"));
}

#[test]
fn kdc_over_file_store_rejects_wrong_password() {
    let (_dir, store) = setup();
    let store = Arc::new(store);
    let mut opts = PrincipalOptions::default();
    opts.attributes.add_spec("+requires_preauth").expect("spec");
    Admin::new(&store, keysalts())
        .add_principal(&name("alice"), REALM, Some("right"), &opts)
        .expect("addprinc");
    let kdc = Kdc::new(KdcConfig::new(REALM), store);
    let mut ex = AsExchange::new(AsExchangeConfig::new(name("alice"), REALM), "wrong");
    let mut reply = Vec::new();
    let err = loop {
        match ex.step(&reply) {
            Ok(StepResult::SendToKdc { data, .. }) | Ok(StepResult::RetryTcp { data, .. }) => {
                reply = kdc.handle(&data);
            }
            Ok(StepResult::Complete) => panic!("must fail"),
            Err(e) => break e,
        }
    };
    assert!(
        matches!(&err, Krb5Error::KdcError(m) if m.error_code == 24),
        "{err:?}"
    );
}
