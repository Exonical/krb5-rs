//! MIT 1.22.2 db2 databases (`tests/data`, made with `kdb5_util create` and
//! `kadmin.local`, btree and `-x hash=true`), read and written in place.

use std::path::Path;

use krb5_rs::kdc::kdb::master::read_stash;
use krb5_rs::kdc::kdb::mit::dump::{write_dump, DumpVersion};
use krb5_rs::kdc::store::{AdminStore, AuthStateStore, PrincipalStore};
use krb5_rs::kdc::{AuthStateUpdate, PrincipalAttributes, RealmConfig};
use krb5_rs::profile::Profile;
use krb5_rs::types::PrincipalName;
use krb5_rs_kdb_db2::Db2Store;

const REALM: &str = "FIX.TEST";
const FILES: [&str; 5] = [
    "principal",
    "principal.kadm5",
    "principal.kadm5.lock",
    "principal.ok",
    "stash",
];

fn fixture(kind: &str) -> (tempfile::TempDir, RealmConfig) {
    let dir = tempfile::tempdir().expect("tempdir");
    let src = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/data")
        .join(kind);
    for f in FILES {
        std::fs::copy(src.join(f), dir.path().join(f)).expect("copy fixture");
    }
    let profile = Profile::parse(&format!(
        "[realms]\n {REALM} = {{\n  database_name = {d}/principal\n  key_stash_file = {d}/stash\n }}\n\
         [dbmodules]\n {REALM} = {{\n  db_library = db2\n }}\n",
        d = dir.path().display()
    ))
    .expect("profile");
    let config = RealmConfig::from_profiles(&profile, None, REALM).expect("config");
    (dir, config)
}

fn open(config: &RealmConfig) -> Db2Store {
    let master = read_stash(&config.key_stash_file, REALM).expect("stash");
    Db2Store::open(config, &master).expect("open")
}

fn name(s: &str) -> PrincipalName {
    match s.split_once('/') {
        Some((service, instance)) => PrincipalName::new_srv_inst(service, instance),
        None => PrincipalName::new_principal(s),
    }
}

async fn reads_mit_database(kind: &str) {
    let (dir, config) = fixture(kind);
    let store = open(&config);
    let (entries, policies) = store.dump_entries().expect("dump");
    let expected = std::fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/data")
            .join(kind)
            .join("mit.dump"),
    )
    .expect("mit.dump");
    assert_eq!(
        String::from_utf8_lossy(&write_dump(DumpVersion::R111, &entries, &policies)),
        String::from_utf8_lossy(&expected),
        "dump of the {kind} database differs from kdb5_util dump"
    );
    let big = format!("host/{}.fix.test", "a".repeat(700));
    assert!(store.lookup(&name(&big), REALM).await.unwrap().is_some());
    assert!(store
        .lookup(&name("user30"), REALM)
        .await
        .unwrap()
        .is_none());
    let alice = store.lookup(&name("alice"), REALM).await.unwrap().unwrap();
    assert!(alice
        .attributes
        .contains(PrincipalAttributes::REQUIRES_PRE_AUTH));
    assert_eq!(alice.policy.as_deref(), Some("v2pol"));
    let v3 = store.get_policy("v3pol").await.unwrap().unwrap();
    assert_eq!(v3.pw_max_life, 3600);
    assert_eq!(v3.allowed_keysalts.as_deref(), Some("aes256-cts:normal"));
    drop(dir);
}

async fn writes_mit_database(kind: &str) {
    let (_dir, config) = fixture(kind);
    let store = open(&config);
    let age = store.age().expect("age");
    assert!(store
        .delete_principal(&name("user7"), REALM)
        .await
        .expect("delete"));
    store
        .update_principal(&name("user8"), REALM, |r| {
            r.entry.attributes |= PrincipalAttributes::DISALLOW_FORWARDABLE;
            Ok(())
        })
        .await
        .expect("update");
    let state = store
        .apply(
            &name("alice"),
            REALM,
            &AuthStateUpdate::Failure {
                stamp: 1_800_000_000,
                failcnt_interval: 0,
                last_admin_unlock: None,
            },
        )
        .await
        .expect("auth state");
    assert_eq!(state.fail_count, 1);
    store
        .update_policy("v1pol", |p| {
            p.pw_min_length = 9;
            Ok(())
        })
        .await
        .expect("policy");
    assert!(store.delete_policy("v3pol").await.expect("delete policy"));
    assert!(store.age().expect("age") > age);
    drop(store);

    let store = open(&config);
    assert!(store.lookup(&name("user7"), REALM).await.unwrap().is_none());
    let user8 = store.lookup(&name("user8"), REALM).await.unwrap().unwrap();
    assert!(user8
        .attributes
        .contains(PrincipalAttributes::DISALLOW_FORWARDABLE));
    let alice = store.raw_entry(&name("alice"), REALM).unwrap().unwrap();
    assert_eq!(
        (alice.fail_auth_count, alice.last_failed),
        (1, 1_800_000_000)
    );
    assert_eq!(
        store
            .get_policy("v1pol")
            .await
            .unwrap()
            .unwrap()
            .pw_min_length,
        9
    );
    assert!(store.get_policy("v3pol").await.unwrap().is_none());
    assert_eq!(store.list_principals().await.unwrap().len(), 64);
}

#[tokio::test]
async fn reads_mit_btree_database() {
    reads_mit_database("btree").await;
}

#[tokio::test]
async fn reads_mit_hash_database() {
    reads_mit_database("hash").await;
}

#[tokio::test]
async fn writes_mit_btree_database() {
    writes_mit_database("btree").await;
}

#[tokio::test]
async fn writes_mit_hash_database() {
    writes_mit_database("hash").await;
}
