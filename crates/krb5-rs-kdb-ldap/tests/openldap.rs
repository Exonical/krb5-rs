//! kldap against a real OpenLDAP server with MIT's schema (tests/slapd.sh).

use std::path::Path;
use std::process::Command;

use krb5_rs::kdc::kdb::mit::{policy_from_entry, set_string_attr, MitPolicy};
use krb5_rs::kdc::{
    random_keys, AdminStore, AuthStateStore, AuthStateUpdate, HealthCheck, PolicyStore,
    PrincipalAttributes, RealmConfig,
};
use krb5_rs::profile::Profile;
use krb5_rs::types::{EncryptionKey, KerberosString, PrincipalName};
use krb5_rs_kdb_ldap::config::{stash_line, ServerType};
use krb5_rs_kdb_ldap::create::RealmOptions;
use krb5_rs_kdb_ldap::LdapStore;

const REALM: &str = "LDAP.TEST";

struct Slapd(String);

impl Drop for Slapd {
    fn drop(&mut self) {
        let _ = Command::new("kill").arg(&self.0).status();
    }
}

fn name(parts: &[&str]) -> PrincipalName {
    PrincipalName {
        name_type: 1,
        name_string: parts
            .iter()
            .map(|p| KerberosString::from_bytes(p.as_bytes()).expect("name"))
            .collect(),
    }
}

fn ldapsearch(port: u16, base: &str) -> String {
    let out = Command::new("ldapsearch")
        .args([
            "-x",
            "-LLL",
            "-H",
            &format!("ldap://127.0.0.1:{port}/"),
            "-b",
            base,
        ])
        .args(["-s", "base", "dn"])
        .output()
        .expect("ldapsearch");
    String::from_utf8_lossy(&out.stdout).into_owned()
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs OpenLDAP slapd and ldap-utils"]
async fn kldap_against_openldap() {
    if !Path::new("/usr/sbin/slapd").exists() {
        eprintln!("slapd not installed; skipping");
        return;
    }
    let dir = tempfile::tempdir().expect("tempdir");
    let port = 20000 + (std::process::id() % 20000) as u16;
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/slapd.sh");
    let out = Command::new("sh")
        .arg(&script)
        .arg(dir.path().join("slapd"))
        .arg(port.to_string())
        .output()
        .expect("slapd.sh");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let _slapd = Slapd(String::from_utf8_lossy(&out.stdout).trim().to_string());

    let stash = dir.path().join("service.keyfile");
    std::fs::write(&stash, stash_line("cn=admin,dc=example,dc=com", "secret")).expect("stash");
    let profile = Profile::parse(&format!(
        "[realms]\n {REALM} = {{\n  database_module = ldap\n }}\n\
         [dbmodules]\n ldap = {{\n  db_library = kldap\n\
           ldap_kerberos_container_dn = cn=krbcontainer,dc=example,dc=com\n\
           ldap_kdc_dn = cn=admin,dc=example,dc=com\n\
           ldap_kadmind_dn = cn=admin,dc=example,dc=com\n\
           ldap_service_password_file = {}\n\
           ldap_servers = ldap://127.0.0.1:1/ ldap://127.0.0.1:{port}/\n }}\n",
        stash.display()
    ))
    .expect("profile");
    let config = RealmConfig::from_profiles(&profile, None, REALM).expect("realm config");
    let master = EncryptionKey::new(18, vec![7u8; 32]);

    let opts = RealmOptions {
        subtrees: vec!["ou=people,dc=example,dc=com".into()],
        containerref: Some("ou=people,dc=example,dc=com".into()),
        ..RealmOptions::default()
    };
    let admin = LdapStore::create_realm(&config, &[], &master, &opts)
        .await
        .expect("create realm");
    assert!(LdapStore::create_realm(&config, &[], &master, &opts)
        .await
        .is_err());
    admin.health().await.expect("health");
    assert!(ldapsearch(
        port,
        &format!("cn={REALM},cn=krbcontainer,dc=example,dc=com")
    )
    .contains("dn: cn=LDAP.TEST"));

    let tgt = AdminStore::get_record(&admin, &name(&["krbtgt", REALM]), REALM)
        .await
        .expect("get krbtgt")
        .expect("krbtgt exists");

    let mut p = MitPolicy {
        name: "p1".into(),
        pw_min_life: 0,
        pw_max_life: 0,
        pw_min_length: 8,
        pw_min_classes: 2,
        pw_history_num: 3,
        pw_max_fail: 3,
        pw_failcnt_interval: 0,
        pw_lockout_duration: 0,
        attributes: 0,
        max_life: 0,
        max_renewable_life: 0,
        allowed_keysalts: None,
        tl_data: Vec::new(),
    };
    admin
        .create_policy(policy_from_entry(&p))
        .await
        .expect("create policy");
    assert!(admin.create_policy(policy_from_entry(&p)).await.is_err());
    p.pw_min_length = 12;
    let updated = AdminStore::update_policy(&admin, "p1", |pol| {
        pol.pw_min_length = 12;
        Ok(())
    })
    .await
    .expect("update policy");
    assert_eq!(updated, policy_from_entry(&p));
    assert_eq!(
        PolicyStore::policy(&admin, "p1").await.expect("policy"),
        Some(updated)
    );
    assert_eq!(
        AdminStore::list_policies(&admin).await.expect("list").len(),
        1
    );

    let alice = name(&["alice"]);
    let mut entry = tgt.entry.clone();
    entry.name = alice.clone();
    entry.attributes = PrincipalAttributes::empty();
    entry.keys = random_keys(1, &[18, 17]).expect("keys");
    entry.policy = Some("p1".into());
    admin
        .create_principal(entry.clone(), None)
        .await
        .expect("create alice");
    admin
        .update_raw(&alice, REALM, |raw, _| {
            set_string_attr(raw, b"require_auth", Some(b"otp pkinit"))?;
            Ok(true)
        })
        .await
        .expect("setstr require_auth");
    assert!(admin.create_principal(entry.clone(), None).await.is_err());
    assert!(ldapsearch(
        port,
        "krbPrincipalName=alice@LDAP.TEST,ou=people,dc=example,dc=com"
    )
    .contains("dn: krbPrincipalName=alice@LDAP.TEST"));

    let kdc = LdapStore::open(&config, &[], ServerType::Kdc, &master)
        .await
        .expect("open as KDC");
    let got = AdminStore::get_record(&kdc, &alice, REALM)
        .await
        .expect("get alice")
        .expect("alice exists");
    assert_eq!(got.entry.policy.as_deref(), Some("p1"));
    assert_eq!(got.entry.require_auth.as_deref(), Some("otp pkinit"));
    assert_eq!(got.entry.keys.len(), 2);
    assert_eq!(
        got.entry.keys[0].key.key_bytes(),
        entry.keys[0].key.key_bytes()
    );

    let st = AuthStateStore::apply(
        &kdc,
        &alice,
        REALM,
        &AuthStateUpdate::Failure {
            stamp: 1_700_000_000,
            failcnt_interval: 0,
            last_admin_unlock: None,
        },
    )
    .await
    .expect("failure");
    assert_eq!(st.fail_count, 1);
    let st = kdc.auth_state(&alice, REALM).await.expect("state");
    assert_eq!((st.fail_count, st.last_failed), (1, 1_700_000_000));

    let rec = admin
        .update_principal(&alice, REALM, |r| {
            r.entry.max_life = Some(std::time::Duration::from_secs(3600));
            Ok(())
        })
        .await
        .expect("update alice");
    assert_eq!(
        rec.entry.max_life,
        Some(std::time::Duration::from_secs(3600))
    );
    admin
        .update_raw(&alice, REALM, |raw, _| {
            set_string_attr(raw, b"require_auth", None)?;
            Ok(true)
        })
        .await
        .expect("delstr require_auth");
    let got = AdminStore::get_record(&kdc, &alice, REALM)
        .await
        .expect("get alice")
        .expect("alice exists");
    assert_eq!(got.entry.require_auth, None);
    assert_eq!(
        got.entry.max_life,
        Some(std::time::Duration::from_secs(3600))
    );
    assert_eq!(
        got.entry.keys[0].key.key_bytes(),
        entry.keys[0].key.key_bytes()
    );

    assert_eq!(admin.list_principals().await.expect("list").len(), 3);
    assert!(AdminStore::delete_policy(&admin, "p1").await.is_err());
    assert!(AdminStore::delete_principal(&admin, &alice, REALM)
        .await
        .expect("delete"));
    assert!(AdminStore::get_record(&admin, &alice, REALM)
        .await
        .expect("get")
        .is_none());
    assert!(!AdminStore::delete_principal(&admin, &alice, REALM)
        .await
        .expect("delete"));
    assert!(AdminStore::delete_policy(&admin, "p1")
        .await
        .expect("delete policy"));
    assert_eq!(admin.list_principals().await.expect("list").len(), 2);
}
