//! `KerberosClient::acquire_cred_with_password`: where MIT's
//! gss_acquire_cred_with_password puts the TGT (acquire_cred.c:446-505).
#![cfg(all(feature = "client", feature = "kdc"))]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use krb5_rs::ccache::{resolve, AnyCcache, CcContext, Ccache};
use krb5_rs::client::KerberosClient;
use krb5_rs::kdc::{Kdc, KdcConfig, MemoryStore, PrincipalAttributes};
use krb5_rs::transport::KdcTransport;
use krb5_rs::types::PrincipalName;
use krb5_rs::Krb5Error;
use rasn::types::GeneralString;

const REALM: &str = "PW.REALM";

fn name(s: &str) -> PrincipalName {
    PrincipalName {
        name_type: if s == "krbtgt" { 2 } else { 1 },
        name_string: if s == "krbtgt" {
            vec![
                GeneralString::from_bytes(b"krbtgt").unwrap(),
                GeneralString::from_bytes(REALM.as_bytes()).unwrap(),
            ]
        } else {
            vec![GeneralString::from_bytes(s.as_bytes()).unwrap()]
        },
    }
}

#[derive(Clone)]
struct Local(Arc<Kdc<MemoryStore>>, Arc<AtomicUsize>);

impl KdcTransport for Local {
    async fn send_recv(&self, _realm: &str, message: &[u8]) -> Result<Vec<u8>, Krb5Error> {
        self.1.fetch_add(1, Ordering::SeqCst);
        Ok(self.0.handle(message).await)
    }
}

fn client() -> (KerberosClient<Local>, Arc<AtomicUsize>) {
    let mut store = MemoryStore::new();
    let none = PrincipalAttributes::empty();
    store
        .add_random_key(name("krbtgt"), REALM, 1, &[18, 17], none)
        .unwrap();
    for user in ["alice", "bob"] {
        store
            .add_with_password(name(user), REALM, "pw", 1, &[18, 17], none)
            .unwrap();
    }
    let sends = Arc::new(AtomicUsize::new(0));
    let kdc = Arc::new(Kdc::builder(KdcConfig::new(REALM), store).build());
    (
        KerberosClient::new(REALM, Local(kdc, Arc::clone(&sends))),
        sends,
    )
}

struct TempDir(std::path::PathBuf);

impl TempDir {
    fn new() -> Self {
        static N: AtomicUsize = AtomicUsize::new(0);
        let p = std::env::temp_dir().join(format!(
            "gss-pw-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::SeqCst)
        ));
        std::fs::create_dir_all(&p).unwrap();
        TempDir(p)
    }

    fn path(&self) -> &std::path::Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn ctx(default: String) -> CcContext {
    CcContext {
        default_name: Some(default),
        ..Default::default()
    }
}

fn holder(cache: &AnyCcache) -> String {
    let (p, _) = cache.principal().unwrap();
    String::from_utf8(p.name_string[0].as_bytes().to_vec()).unwrap()
}

#[tokio::test]
async fn empty_default_cache_receives_the_tgt_and_is_reused() {
    let dir = TempDir::new();
    let cc = ctx(format!("FILE:{}", dir.path().join("cc").display()));
    let (client, sends) = client();
    let (cache, tgt) = client
        .acquire_cred_with_password(&cc, name("alice"), "pw")
        .await
        .unwrap();
    assert_eq!(
        cache.name(),
        format!("FILE:{}", dir.path().join("cc").display())
    );
    assert_eq!(holder(&cache), "alice");
    assert_eq!(tgt.server.name_string, name("krbtgt").name_string);
    let used = sends.load(Ordering::SeqCst);
    // A valid TGT in the matching cache needs no AS exchange.
    let (again, _) = client
        .acquire_cred_with_password(&cc, name("alice"), "pw")
        .await
        .unwrap();
    assert_eq!(again.name(), cache.name());
    assert_eq!(sends.load(Ordering::SeqCst), used);
}

#[tokio::test]
async fn occupied_default_file_cache_is_ccache_nomatch() {
    let dir = TempDir::new();
    let cc = ctx(format!("FILE:{}", dir.path().join("cc").display()));
    let (client, _) = client();
    client
        .acquire_cred_with_password(&cc, name("alice"), "pw")
        .await
        .unwrap();
    let Err(err) = client
        .acquire_cred_with_password(&cc, name("bob"), "pw")
        .await
    else {
        panic!("bob stored over alice");
    };
    assert!(
        err.to_string()
            .contains("Principal in credential cache does not match desired name"),
        "{err}"
    );
}

#[tokio::test]
async fn occupied_dir_collection_gets_a_new_cache() {
    let dir = TempDir::new();
    let cc = ctx(format!("DIR:{}", dir.path().display()));
    let (client, _) = client();
    let (first, _) = client
        .acquire_cred_with_password(&cc, name("alice"), "pw")
        .await
        .unwrap();
    let (second, _) = client
        .acquire_cred_with_password(&cc, name("bob"), "pw")
        .await
        .unwrap();
    assert_ne!(first.name(), second.name());
    assert_eq!(holder(&resolve(&cc, &first.name()).unwrap()), "alice");
    assert_eq!(holder(&second), "bob");
}

#[tokio::test]
async fn wrong_password_stores_nothing() {
    let dir = TempDir::new();
    let path = dir.path().join("cc");
    let cc = ctx(format!("FILE:{}", path.display()));
    let (client, _) = client();
    assert!(client
        .acquire_cred_with_password(&cc, name("alice"), "bad")
        .await
        .is_err());
    assert!(!path.exists());
}
