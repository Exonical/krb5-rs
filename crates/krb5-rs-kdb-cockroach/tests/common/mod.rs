//! Shared setup for the CockroachDB integration tests (all `#[ignore]`d).
//!
//! They expect the cluster of `tests/crdb/cluster.sh`. Environment:
//! `CRDB_HOST` (default 127.0.0.1), `CRDB_PORT` (26257), `CRDB_CERTS`
//! (default `tests/crdb/certs` of the repository).
//!
//! The migrated-database pool leaves unused `krb5t_pool_*` databases at
//! process exit; remove them with `tests/crdb/cluster.sh clean`.

#![allow(dead_code)]

use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::sync::{Mutex, OnceLock};

use krb5_rs::crypto::SaltType;
use krb5_rs::kdc::kdb::master_key_from_password;
use krb5_rs::types::{EncryptionKey, PrincipalName};
use krb5_rs_kdb_cockroach::{query_text, run_sql, CockroachConfig, CockroachStore};

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

struct MigratedPool {
    available: Mutex<Receiver<Result<String, String>>>,
    consumed: mpsc::Sender<()>,
}

static MIGRATED_POOL: OnceLock<MigratedPool> = OnceLock::new();

fn migrated_pool() -> &'static MigratedPool {
    MIGRATED_POOL.get_or_init(|| {
        let prefetch = std::env::var("CRDB_TEST_PREFETCH")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(6)
            .max(1);
        let pid = std::process::id();
        let (available_tx, available_rx) = mpsc::sync_channel::<Result<String, String>>(prefetch);
        let (consumed_tx, consumed_rx) = mpsc::channel();

        std::thread::Builder::new()
            .name("crdb-test-db-pool".into())
            .spawn(move || {
                let runtime = tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(prefetch.min(8))
                    .enable_all()
                    .build()
                    .expect("test database pool runtime");
                let mut next = 0u64;
                let mut initial = true;
                loop {
                    let count = if initial {
                        initial = false;
                        prefetch
                    } else {
                        if consumed_rx.recv().is_err() {
                            return;
                        }
                        1 + std::iter::from_fn(|| consumed_rx.try_recv().ok()).count()
                    };
                    runtime.block_on(async {
                        let mut tasks = tokio::task::JoinSet::new();
                        for _ in 0..count {
                            let name = format!("krb5t_pool_{pid}_{}", next);
                            next += 1;
                            tasks.spawn(create_migrated_database(name));
                        }
                        while let Some(result) = tasks.join_next().await {
                            let result = match result {
                                Ok(result) => result,
                                Err(error) => Err(format!("migration task failed: {error}")),
                            };
                            if available_tx.send(result).is_err() {
                                return;
                            }
                        }
                    });
                }
            })
            .expect("spawn test database pool");

        MigratedPool {
            available: Mutex::new(available_rx),
            consumed: consumed_tx,
        }
    })
}

async fn create_migrated_database(name: String) -> Result<String, String> {
    use krb5_rs_kdb_cockroach::{CockroachStore, MigrateOptions};

    let create = async {
        run_sql(
            &config("root", "defaultdb"),
            &format!("DROP DATABASE IF EXISTS \"{name}\" CASCADE"),
        )
        .await
        .map_err(|e| e.to_string())?;
        run_sql(
            &config("root", "defaultdb"),
            &format!("CREATE DATABASE \"{name}\""),
        )
        .await
        .map_err(|e| e.to_string())?;
        CockroachStore::migrate(
            config("root", &name),
            &MigrateOptions {
                create_roles: true,
                multi_region: None,
            },
        )
        .await
        .map_err(|e| e.to_string())?;
        Ok::<_, String>(name.clone())
    }
    .await;
    if create.is_err() {
        let _ = run_sql(
            &config("root", "defaultdb"),
            &format!("DROP DATABASE IF EXISTS \"{name}\" CASCADE"),
        )
        .await;
    }
    create
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

    /// Take an already-migrated isolated database from the background pool.
    pub async fn migrated(_tag: &str) -> Self {
        let pool = migrated_pool();
        let result = tokio::task::spawn_blocking(move || {
            pool.available
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .recv()
                .expect("test database pool stopped")
        })
        .await
        .expect("test database pool task");
        let _ = pool.consumed.send(());
        Self {
            name: result.expect("pre-migrated test database"),
        }
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
        let db = Self::migrated(tag).await;
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
