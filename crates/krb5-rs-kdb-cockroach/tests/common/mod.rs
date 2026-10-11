//! Shared setup for the CockroachDB integration tests (all `#[ignore]`d).
//!
//! They expect the cluster of `tests/crdb/cluster.sh`. Environment:
//! `CRDB_HOST` (default 127.0.0.1), `CRDB_PORT` (26257), `CRDB_CERTS`
//! (default `tests/crdb/certs` of the repository).

#![allow(dead_code)]

use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};

use krb5_rs::crypto::SaltType;
use krb5_rs::kdc::kdb::master_key_from_password;
use krb5_rs::types::{EncryptionKey, PrincipalName};
use krb5_rs_kdb_cockroach::{query_text, run_sql, CockroachConfig, CockroachStore, MigrateOptions};

pub const REALM: &str = "CRDB.TEST";

pub fn host() -> String {
    std::env::var("CRDB_HOST").unwrap_or_else(|_| "127.0.0.1".into())
}

pub fn port() -> u16 {
    std::env::var("CRDB_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(26257)
}

pub fn certs() -> PathBuf {
    std::env::var("CRDB_CERTS")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/crdb/certs")
        })
}

pub fn config(user: &str, database: &str) -> CockroachConfig {
    let mut c = CockroachConfig::new(format!(
        "postgresql://{user}@{}:{}/{database}?sslmode=verify-full",
        host(),
        port()
    ));
    let dir = certs();
    c.ca = Some(dir.join("ca.crt"));
    c.cert = Some(dir.join(format!("client.{user}.crt")));
    c.key = Some(dir.join(format!("client.{user}.key")));
    c
}

pub fn master() -> EncryptionKey {
    master_key_from_password(REALM, "master-password", 18).expect("master key")
}

pub fn keysalts() -> Vec<(i32, SaltType)> {
    vec![(18, SaltType::Normal), (17, SaltType::Normal)]
}

pub fn name(s: &str) -> PrincipalName {
    PrincipalName::new_principal(s)
}

/// One scratch database per test, created and migrated as root and dropped at
/// the end by [`TestDb::drop_db`].
pub struct TestDb {
    pub name: String,
}

impl TestDb {
    pub async fn new(tag: &str) -> Self {
        static N: AtomicU32 = AtomicU32::new(0);
        let name = format!(
            "krb5t_{tag}_{}_{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        );
        run_sql(
            &config("root", "defaultdb"),
            &format!("CREATE DATABASE \"{name}\""),
        )
        .await
        .expect("create database");
        Self { name }
    }

    /// Migrate as root, creating the roles.
    pub async fn migrate(&self) {
        CockroachStore::migrate(
            self.root(),
            &MigrateOptions {
                create_roles: true,
                multi_region: None,
            },
        )
        .await
        .expect("migrate");
    }

    pub fn root(&self) -> CockroachConfig {
        config("root", &self.name)
    }

    pub fn admin(&self) -> CockroachConfig {
        config("kdc_admin", &self.name)
    }

    pub fn replica(&self) -> CockroachConfig {
        config("kdc_replica", &self.name)
    }

    /// A migrated database with the realm created, plus its admin store.
    pub async fn with_realm(tag: &str) -> (Self, CockroachStore) {
        let db = Self::new(tag).await;
        db.migrate().await;
        let store = CockroachStore::connect(db.admin(), master(), REALM)
            .await
            .expect("connect");
        store.create_realm(&[18, 17]).await.expect("create realm");
        (db, store)
    }

    pub async fn text(&self, sql: &str) -> Vec<String> {
        query_text(&self.root(), sql).await.expect("query")
    }

    pub async fn drop_db(self) {
        let _ = run_sql(
            &config("root", "defaultdb"),
            &format!("DROP DATABASE \"{}\" CASCADE", self.name),
        )
        .await;
    }
}
