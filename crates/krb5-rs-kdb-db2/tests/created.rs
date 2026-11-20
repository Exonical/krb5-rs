//! Databases made by `Db2Store::create`, btree and hash.

use krb5_rs::kdc::kdb::master_key_from_password;
use krb5_rs::kdc::store::{AdminStore, PrincipalStore};
use krb5_rs::kdc::{random_keys, PrincipalAttributes, PrincipalEntry, RealmConfig};
use krb5_rs::profile::Profile;
use krb5_rs::types::PrincipalName;
use krb5_rs_kdb_db2::Db2Store;

const REALM: &str = "NEW.TEST";

fn realm_config(dir: &std::path::Path, hash: bool) -> RealmConfig {
    let profile = Profile::parse(&format!(
        "[realms]\n {REALM} = {{\n  database_name = {d}/principal\n }}\n\
         [dbmodules]\n {REALM} = {{\n  db_library = db2\n }}\n",
        d = dir.display()
    ))
    .expect("profile");
    let mut config = RealmConfig::from_profiles(&profile, None, REALM).expect("config");
    if hash {
        config
            .apply_db_args(&["hash=true".into()])
            .expect("db args");
    }
    config
}

fn entry(name: &str) -> PrincipalEntry {
    let mut keys = random_keys(1, &[18]).expect("keys");
    keys[0].salt = None;
    PrincipalEntry {
        name: PrincipalName::new_principal(name),
        realm: REALM.into(),
        attributes: PrincipalAttributes::REQUIRES_PRE_AUTH,
        max_life: None,
        max_renewable_life: None,
        expiration: None,
        pw_expiration: None,
        keys,
        allowed_to_delegate_to: vec![],
        allowed_to_delegate_from: vec![],
        require_auth: None,
        otp: None,
        pkinit_cert_match: None,
        session_enctypes: None,
        policy: None,
        security_epoch: 0,
        last_admin_unlock: None,
    }
}

async fn create_and_reopen(hash: bool) {
    let dir = tempfile::tempdir().expect("tempdir");
    let config = realm_config(dir.path(), hash);
    let master = master_key_from_password(REALM, "masterpw", 18).expect("master");
    let store = Db2Store::create(&config, &master).expect("create");
    for suffix in ["", ".ok", ".kadm5", ".kadm5.lock"] {
        assert!(dir.path().join(format!("principal{suffix}")).exists());
    }
    let header = std::fs::read(dir.path().join("principal")).expect("read");
    // Berkeley DB magic: hash 0x061561, btree 0x053162.
    let magic = if hash { 0x061561u32 } else { 0x053162 };
    assert!(header[..16]
        .windows(4)
        .any(|w| w == magic.to_le_bytes() || w == magic.to_be_bytes()));
    assert!(Db2Store::create(&config, &master).is_err());

    for i in 0..200 {
        store
            .create_principal(entry(&format!("user{i}")), None)
            .await
            .expect("create principal");
    }
    let doomed = store
        .raw_entry(&PrincipalName::new_principal("user5"), REALM)
        .unwrap()
        .unwrap();
    assert!(doomed.key_data[0].fields[0].1.iter().any(|b| *b != 0));
    assert!(store
        .delete_principal(&PrincipalName::new_principal("user5"), REALM)
        .await
        .unwrap());
    drop(store);

    let store = Db2Store::open(&config, &master).expect("reopen");
    assert_eq!(store.list_principals().await.unwrap().len(), 2 + 199);
    assert!(store
        .lookup(&PrincipalName::new_principal("user5"), REALM)
        .await
        .unwrap()
        .is_none());
    assert!(store
        .lookup(&PrincipalName::new_principal("user199"), REALM)
        .await
        .unwrap()
        .is_some());
    assert!(Db2Store::open(
        &config,
        &master_key_from_password(REALM, "wrong", 18).unwrap()
    )
    .is_err());

    let (entries, policies) = store.dump_entries().expect("dump");
    drop(store);
    let copy = tempfile::tempdir().expect("tempdir");
    let copy_config = realm_config(copy.path(), !hash);
    Db2Store::load_dump(&copy_config, &entries, &policies, false, false, 0).expect("load");
    let loaded = Db2Store::open(&copy_config, &master).expect("open loaded");
    assert_eq!(loaded.dump_entries().unwrap().0.len(), entries.len());
    assert!(!copy.path().join("principal~").exists());
}

#[tokio::test]
async fn btree_database_round_trip() {
    create_and_reopen(false).await;
}

#[tokio::test]
async fn hash_database_round_trip() {
    create_and_reopen(true).await;
}
