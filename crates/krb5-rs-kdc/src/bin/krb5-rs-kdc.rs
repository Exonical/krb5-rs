//! KDC daemon, MIT's `krb5kdc`.
//!
//! MIT's options (`-r REALM`, repeatable, and `-d`, `-x`, `-m`, `-M`, `-k`,
//! `-p`, `-P`, `-n`, `-w`, `-T`) work as in `krb5kdc`; one process serves
//! every realm named, each on all the listen addresses. Unless `-n` is given
//! the KDC detaches from the terminal once its sockets are bound.
//!
//! Two modes:
//!
//! * `--config kdc.conf` (or `KRB5_KDC_PROFILE`) serves the persistent
//!   database created with `krb5-rs-kdb`, using the master key stash named in
//!   kdc.conf. `--krb5-config` (or `KRB5_CONFIG`) supplies `[libdefaults]`,
//!   `[domain_realm]` and `[capaths]`; `--listen` replaces the kdc.conf listen
//!   addresses.
//! * `--keytab PATH --realm REALM` serves every principal found in a keytab,
//!   all requiring pre-authentication (a random `krbtgt/REALM` is generated if
//!   the keytab has none). A quick-test mode.
//!
//! Passwords are never accepted on the command line. SIGTERM and SIGINT (ctrl-c
//! on Windows) stop the listeners, wait up to `--shutdown-timeout` seconds
//! for open TCP connections, and exit 0. One log line per request goes to
//! stdout in the style of MIT's `log_as_req` / `log_tgs_req`.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use clap::parser::ValueSource;
use clap::{CommandFactory, FromArgMatches, Parser};
use krb5_rs::kdc::kdb::test::TestStore;
use krb5_rs::kdc::kdb::{master_key_from_password_named, read_stash_named, FileStore};
#[cfg(feature = "cockroach")]
use krb5_rs::kdc::GateSubject;
use krb5_rs::kdc::{
    default_realm, parse_listen_addresses, serve_tcp_with, serve_udp_with, Kdc, KdcConfig,
    KdcRealms, MemoryStore, PrincipalAttributes, PrincipalEntry, PrincipalStore, RealmConfig,
    RequestLogger, ServeOptions, StoreError,
};
use krb5_rs::keytab::FileKeytab;
use krb5_rs::profile::Profile;
use krb5_rs::types::{EncryptionKey, PrincipalName};
#[cfg(feature = "klmdb")]
use krb5_rs_kdb_lmdb::LmdbStore;
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::watch;
use tokio::task::JoinSet;
use tracing::{error, info, warn};

#[cfg(unix)]
#[path = "../daemonize.rs"]
mod daemonize;
#[path = "../kdc_args.rs"]
mod kdc_args;
#[cfg(unix)]
#[path = "../kdc_workers.rs"]
mod kdc_workers;

#[path = "../klog.rs"]
mod klog;
#[path = "../daemon_metrics.rs"]
mod metrics;
#[path = "kdc/plugins.rs"]
mod plugins;

/// MIT's default kdc.conf location (`DEFAULT_KDC_PROFILE`).
const DEFAULT_KDC_PROFILE: &str = "/usr/local/var/krb5kdc/kdc.conf";

#[derive(Parser)]
#[command(
    name = "krb5-rs-kdc",
    version,
    about = "Kerberos V5 KDC (MIT krb5kdc options are also accepted)"
)]
struct Cli {
    /// kdc.conf to read (config mode).
    #[arg(long, env = "KRB5_KDC_PROFILE", value_name = "PATH")]
    config: Option<PathBuf>,

    /// krb5.conf for [libdefaults], [domain_realm] and [capaths].
    #[arg(long, env = "KRB5_CONFIG", value_name = "PATH")]
    krb5_config: Option<PathBuf>,

    /// Realm to serve, after any given with -r (default: the sole realm in
    /// kdc.conf, else krb5.conf).
    #[arg(long, value_name = "REALM")]
    realm: Option<String>,

    /// Listen address (HOST:PORT, [V6]:PORT or PORT), repeatable; replaces
    /// the kdc.conf listen addresses for both UDP and TCP.
    #[arg(long, value_name = "ADDR")]
    listen: Vec<String>,

    /// Derive the master key from the password in this file (first line)
    /// instead of reading the stash.
    #[arg(long, value_name = "PATH")]
    master_password_file: Option<PathBuf>,

    /// Serve the principals of this keytab instead of a database.
    #[arg(long, value_name = "PATH")]
    keytab: Option<PathBuf>,

    /// Maximum ticket lifetime in seconds (keytab mode).
    #[arg(long, value_name = "SECS")]
    max_life: Option<u64>,

    /// Maximum renewable lifetime in seconds (keytab mode).
    #[arg(long, value_name = "SECS")]
    max_renewable_life: Option<u64>,

    /// Seconds to wait for open TCP connections after SIGTERM/SIGINT.
    #[arg(long, value_name = "SECS", default_value_t = 10)]
    shutdown_timeout: u64,

    /// Serve Prometheus metrics and health endpoints on this address.
    #[arg(long, value_name = "ADDR")]
    metrics_listen: Option<SocketAddr>,

    /// Retry opening a missing or unreadable database every second instead of
    /// exiting, binding no listener until it opens (a kpropd replica that has
    /// not received its first propagation).
    #[arg(long)]
    wait_for_database: bool,
}

struct Listen {
    udp: Vec<SocketAddr>,
    tcp: Vec<SocketAddr>,
    /// `kdc_tcp_listen_backlog`.
    backlog: u32,
}

/// MIT `DEFAULT_TCP_LISTEN_BACKLOG`.
const DEFAULT_TCP_LISTEN_BACKLOG: u32 = 5;

/// Bind a TCP listener with `backlog` (net-server.c `setup_tcp_listener`:
/// SO_REUSEADDR, then `listen(sock, tcp_listen_backlog)`).
fn bind_tcp(addr: SocketAddr, backlog: u32) -> std::io::Result<TcpListener> {
    let sock = if addr.is_ipv4() {
        tokio::net::TcpSocket::new_v4()?
    } else {
        tokio::net::TcpSocket::new_v6()?
    };
    #[cfg(unix)]
    sock.set_reuseaddr(true)?;
    sock.bind(addr)?;
    sock.listen(backlog)
}

/// The store this process serves: the bootstrap keytab or the database file.
/// (The store traits use native async, so they are not trait objects; the
/// daemon picks the backend with an enum.)
enum DaemonStore {
    Memory(Arc<MemoryStore>, Arc<metrics::Metrics>),
    File(Arc<FileStore>, Arc<metrics::Metrics>),
    #[cfg(feature = "klmdb")]
    Lmdb(Arc<LmdbStore>, Arc<metrics::Metrics>),
    #[cfg(feature = "turso")]
    Turso(krb5_rs_kdb_turso::TursoReplica, Arc<metrics::Metrics>),
    #[cfg(feature = "kldap")]
    Ldap(krb5_rs_kdb_ldap::LdapStore, Arc<metrics::Metrics>),
    Test(Arc<TestStore>, Arc<metrics::Metrics>),
}

impl PrincipalStore for DaemonStore {
    async fn lookup(
        &self,
        name: &PrincipalName,
        realm: &str,
    ) -> Result<Option<PrincipalEntry>, StoreError> {
        match self {
            DaemonStore::Memory(s, metrics) => {
                let start = std::time::Instant::now();
                let result = s.lookup(name, realm).await;
                metrics.observe_principal_lookup(start.elapsed(), result.is_ok());
                result
            }
            DaemonStore::File(s, metrics) => {
                let start = std::time::Instant::now();
                let result = s.lookup(name, realm).await;
                metrics.observe_principal_lookup(start.elapsed(), result.is_ok());
                result
            }
            #[cfg(feature = "klmdb")]
            DaemonStore::Lmdb(s, metrics) => {
                let start = std::time::Instant::now();
                let result = s.lookup(name, realm).await;
                metrics.observe_principal_lookup(start.elapsed(), result.is_ok());
                result
            }
            #[cfg(feature = "turso")]
            DaemonStore::Turso(s, metrics) => {
                let start = std::time::Instant::now();
                let result = s.lookup(name, realm).await;
                metrics.observe_principal_lookup(start.elapsed(), result.is_ok());
                result
            }
            #[cfg(feature = "kldap")]
            DaemonStore::Ldap(s, metrics) => {
                let start = std::time::Instant::now();
                let result = s.lookup(name, realm).await;
                metrics.observe_principal_lookup(start.elapsed(), result.is_ok());
                result
            }
            DaemonStore::Test(s, metrics) => {
                let start = std::time::Instant::now();
                let result = s.lookup(name, realm).await;
                metrics.observe_principal_lookup(start.elapsed(), result.is_ok());
                result
            }
        }
    }

    async fn lookup_s4u_x509(
        &self,
        cert: &[u8],
        name: &PrincipalName,
        realm: &str,
        referral_ok: bool,
    ) -> Result<Option<PrincipalEntry>, StoreError> {
        match self {
            DaemonStore::Memory(s, _) => s.lookup_s4u_x509(cert, name, realm, referral_ok).await,
            DaemonStore::File(s, _) => s.lookup_s4u_x509(cert, name, realm, referral_ok).await,
            #[cfg(feature = "klmdb")]
            DaemonStore::Lmdb(s, _) => s.lookup_s4u_x509(cert, name, realm, referral_ok).await,
            #[cfg(feature = "turso")]
            DaemonStore::Turso(s, _) => s.lookup_s4u_x509(cert, name, realm, referral_ok).await,
            #[cfg(feature = "kldap")]
            DaemonStore::Ldap(s, _) => s.lookup_s4u_x509(cert, name, realm, referral_ok).await,
            DaemonStore::Test(s, _) => s.lookup_s4u_x509(cert, name, realm, referral_ok).await,
        }
    }

    fn issue_pac(&self, req: krb5_rs::kdc::IssuePac<'_>) -> Result<(), StoreError> {
        match self {
            DaemonStore::Memory(s, _) => s.issue_pac(req),
            DaemonStore::File(s, _) => s.issue_pac(req),
            #[cfg(feature = "klmdb")]
            DaemonStore::Lmdb(s, _) => s.issue_pac(req),
            #[cfg(feature = "turso")]
            DaemonStore::Turso(s, _) => s.issue_pac(req),
            #[cfg(feature = "kldap")]
            DaemonStore::Ldap(s, _) => s.issue_pac(req),
            DaemonStore::Test(s, _) => s.issue_pac(req),
        }
    }
}

type DynKdc = Kdc<DaemonStore>;

fn io_err(msg: impl std::fmt::Display) -> std::io::Error {
    std::io::Error::other(msg.to_string())
}

fn metrics_listen(
    cli: Option<SocketAddr>,
    configured: Option<&str>,
) -> std::io::Result<Option<SocketAddr>> {
    if cli.is_some() {
        return Ok(cli);
    }
    configured
        .map(|value| {
            value
                .parse::<SocketAddr>()
                .map_err(|e| io_err(format!("metrics_listen: {e}")))
        })
        .transpose()
}

async fn keytab_mode(
    cli: &Cli,
    keytab: &Path,
    metrics: Arc<metrics::Metrics>,
) -> std::io::Result<(DynKdc, Listen)> {
    let realm = cli
        .realm
        .clone()
        .ok_or_else(|| io_err("--keytab requires --realm"))?;
    let mut store = MemoryStore::new();
    store
        .import_keytab(
            &FileKeytab::new(keytab),
            PrincipalAttributes::REQUIRES_PRE_AUTH,
        )
        .map_err(|e| io_err(format!("reading keytab {}: {e}", keytab.display())))?;

    let tgs = PrincipalName::new_srv_inst("krbtgt", &realm);
    if store.lookup(&tgs, &realm).await.ok().flatten().is_none() {
        warn!(
            "no krbtgt/{realm}@{realm} in keytab; generated a random one \
             (issued tickets will not survive a restart)"
        );
        store
            .add_random_key(tgs, &realm, 1, &[18, 17], PrincipalAttributes::empty())
            .map_err(io_err)?;
    }

    let mut config = KdcConfig::new(realm);
    if let Some(s) = cli.max_life {
        config.max_life = Duration::from_secs(s);
    }
    if let Some(s) = cli.max_renewable_life {
        config.max_renewable_life = Duration::from_secs(s);
    }
    let spec = if cli.listen.is_empty() {
        "0.0.0.0:88".to_string()
    } else {
        cli.listen.join(",")
    };
    let addrs = parse_listen_addresses(&spec, 88).map_err(io_err)?;
    Ok((
        Kdc::new(config, DaemonStore::Memory(Arc::new(store), metrics)),
        Listen {
            udp: addrs.clone(),
            tcp: addrs,
            backlog: DEFAULT_TCP_LISTEN_BACKLOG,
        },
    ))
}

/// Extra runtime pieces a database mode contributes.
#[derive(Default)]
struct ModeParts {
    metrics_listen: Option<SocketAddr>,
    #[cfg(feature = "cockroach")]
    replication: Option<ReplicationRuntime>,
}

#[cfg(feature = "cockroach")]
struct ReplicationRuntime {
    engine: krb5_rs::kdc::replication::ReplicationEngine<
        krb5_rs_kdb_cockroach::CockroachStore,
        krb5_rs_kdb_turso::TursoReplica,
        krb5_rs_kdb_cockroach::CockroachStore,
    >,
    reporter: krb5_rs_kdb_cockroach::CockroachLockoutReporter,
    status: Arc<std::sync::Mutex<krb5_rs::kdc::replication::StatusSnapshot>>,
    max_staleness: Duration,
}

#[cfg(feature = "cockroach")]
enum RuntimeGate {
    Bounded(krb5_rs::kdc::replication::FreshnessGate),
    Strict(krb5_rs::kdc::replication::StrictGate<krb5_rs_kdb_cockroach::CockroachStore>),
}

#[cfg(feature = "cockroach")]
impl krb5_rs::kdc::ConsistencyGate for RuntimeGate {
    async fn check(&self, subjects: &[GateSubject<'_>]) -> krb5_rs::kdc::GateDecision {
        match self {
            RuntimeGate::Bounded(gate) => gate.check(subjects).await,
            RuntimeGate::Strict(gate) => gate.check(subjects).await,
        }
    }
}

/// Serve from a Turso replica (`db_library = krb5-rs-turso`), read-only.
/// Replication into it is not wired here yet.
#[cfg(feature = "turso")]
async fn turso_mode(
    cli: &Cli,
    cfg: RealmConfig,
    master: krb5_rs::types::EncryptionKey,
    metrics: Arc<metrics::Metrics>,
) -> std::io::Result<(DynKdc, Listen, ModeParts)> {
    use krb5_rs_kdb_turso::{TursoOptions, TursoReplica};

    let path = cfg
        .db_module
        .get("replica_path")
        .ok_or_else(|| io_err("db_library krb5-rs-turso needs replica_path"))?;
    let number = |key: &str| -> std::io::Result<Option<i64>> {
        cfg.db_module
            .get(key)
            .map(|v| {
                v.parse()
                    .map_err(|_| io_err(format!("{key}: not a number")))
            })
            .transpose()
    };
    let mut options = TursoOptions::default();
    if let Some(n) = number("turso_pool_size")? {
        options.pool_size = usize::try_from(n).map_err(|_| io_err("turso_pool_size"))?;
    }
    options.mvcc_checkpoint_threshold = number("turso_checkpoint_threshold")?;
    if let Some(n) = number("turso_max_retries")? {
        options.max_retries = u32::try_from(n).map_err(|_| io_err("turso_max_retries"))?;
    }
    if let Some(v) = cfg.db_module.get("turso_passive_checkpoint") {
        options.passive_checkpoint =
            matches!(v.to_ascii_lowercase().as_str(), "true" | "yes" | "on" | "1");
    }
    options.master_key_name = cfg.master_key_name.clone();
    let replica = TursoReplica::open(path, options, master)
        .await
        .map_err(io_err)?;
    let (udp, tcp) = if cli.listen.is_empty() {
        (cfg.udp_listen, cfg.tcp_listen)
    } else {
        let addrs = parse_listen_addresses(&cli.listen.join(","), 88).map_err(io_err)?;
        (addrs.clone(), addrs)
    };
    let metrics_listen = metrics_listen(cli.metrics_listen, cfg.db_module.get("metrics_listen"))?;
    let kdc = Kdc::builder(cfg.kdc, DaemonStore::Turso(replica.clone(), metrics))
        .policies(replica.clone())
        .auth_state(replica)
        .build();
    Ok((
        kdc,
        Listen {
            udp,
            tcp,
            backlog: cfg.tcp_listen_backlog,
        },
        ModeParts {
            metrics_listen,
            ..ModeParts::default()
        },
    ))
}

#[cfg(not(feature = "turso"))]
async fn turso_mode(
    _cli: &Cli,
    _cfg: RealmConfig,
    _master: krb5_rs::types::EncryptionKey,
    _metrics: Arc<metrics::Metrics>,
) -> std::io::Result<(DynKdc, Listen, ModeParts)> {
    Err(io_err(
        "db_library krb5-rs-turso needs a krb5-rs-kdc built with the `turso` feature",
    ))
}

#[cfg(feature = "cockroach")]
fn module_duration(cfg: &RealmConfig, key: &str, default: Duration) -> std::io::Result<Duration> {
    let Some(s) = cfg.db_module.get(key) else {
        return Ok(default);
    };
    let (n, unit) = if let Some(n) = s.strip_suffix("ms") {
        (n, 1u64)
    } else if let Some(n) = s.strip_suffix('s') {
        (n, 1000)
    } else if let Some(n) = s.strip_suffix('m') {
        (n, 60_000)
    } else if let Some(n) = s.strip_suffix('h') {
        (n, 3_600_000)
    } else {
        (s, 1000)
    };
    let n: u64 = n
        .parse()
        .map_err(|_| io_err(format!("{key}: not a duration")))?;
    let millis = n
        .checked_mul(unit)
        .ok_or_else(|| io_err(format!("{key}: duration out of range")))?;
    Ok(Duration::from_millis(millis))
}

/// One `--wait-for-database` retry: report the first failure, then sleep.
async fn database_wait(waiting: bool, e: &dyn std::fmt::Display) -> bool {
    if !waiting {
        eprintln!("waiting for the database: {e}");
    }
    tokio::time::sleep(Duration::from_secs(1)).await;
    true
}

#[cfg(feature = "klmdb")]
async fn klmdb_mode(
    cli: &Cli,
    cfg: RealmConfig,
    master: EncryptionKey,
    metrics: Arc<metrics::Metrics>,
) -> std::io::Result<(DynKdc, Listen, ModeParts)> {
    let mut waiting = false;
    let store = loop {
        let config = cfg.clone();
        let key = master.clone();
        match tokio::task::spawn_blocking(move || LmdbStore::open(&config, &key))
            .await
            .map_err(io_err)?
        {
            Ok(store) => break store,
            Err(e) if cli.wait_for_database => {
                waiting = database_wait(waiting, &e).await;
            }
            Err(e) => return Err(io_err(e)),
        }
    };
    let store = Arc::new(store);
    let (udp, tcp) = if cli.listen.is_empty() {
        (cfg.udp_listen, cfg.tcp_listen)
    } else {
        let addrs = parse_listen_addresses(&cli.listen.join(","), 88).map_err(io_err)?;
        (addrs.clone(), addrs)
    };
    let metrics_listen = metrics_listen(cli.metrics_listen, cfg.db_module.get("metrics_listen"))?;
    let kdc = Kdc::builder(cfg.kdc, DaemonStore::Lmdb(Arc::clone(&store), metrics))
        .policies(Arc::clone(&store))
        .auth_state(store)
        .build();
    Ok((
        kdc,
        Listen {
            udp,
            tcp,
            backlog: cfg.tcp_listen_backlog,
        },
        ModeParts {
            metrics_listen,
            ..ModeParts::default()
        },
    ))
}

/// Serve from an LDAP directory (`db_library = kldap`).
#[cfg(feature = "kldap")]
async fn kldap_mode(
    cli: &Cli,
    cfg: RealmConfig,
    master: EncryptionKey,
    metrics: Arc<metrics::Metrics>,
) -> std::io::Result<(DynKdc, Listen, ModeParts)> {
    use krb5_rs_kdb_ldap::config::ServerType;
    let mut waiting = false;
    let store = loop {
        match krb5_rs_kdb_ldap::LdapStore::open(&cfg, &[], ServerType::Kdc, &master).await {
            Ok(store) => break store,
            Err(e) if cli.wait_for_database => {
                waiting = database_wait(waiting, &e).await;
            }
            Err(e) => return Err(io_err(e)),
        }
    };
    let (udp, tcp) = if cli.listen.is_empty() {
        (cfg.udp_listen, cfg.tcp_listen)
    } else {
        let addrs = parse_listen_addresses(&cli.listen.join(","), 88).map_err(io_err)?;
        (addrs.clone(), addrs)
    };
    let metrics_listen = metrics_listen(cli.metrics_listen, cfg.db_module.get("metrics_listen"))?;
    let kdc = Kdc::builder(cfg.kdc, DaemonStore::Ldap(store.clone(), metrics))
        .policies(Arc::new(store.clone()))
        .auth_state(Arc::new(store))
        .build();
    Ok((
        kdc,
        Listen {
            udp,
            tcp,
            backlog: cfg.tcp_listen_backlog,
        },
        ModeParts {
            metrics_listen,
            ..ModeParts::default()
        },
    ))
}

#[cfg(not(feature = "kldap"))]
async fn kldap_mode(
    _cli: &Cli,
    _cfg: RealmConfig,
    _master: EncryptionKey,
    _metrics: Arc<metrics::Metrics>,
) -> std::io::Result<(DynKdc, Listen, ModeParts)> {
    Err(io_err(
        "db_library kldap needs a krb5-rs-kdc built with the `kldap` feature",
    ))
}

#[cfg(not(feature = "klmdb"))]
async fn klmdb_mode(
    _cli: &Cli,
    _cfg: RealmConfig,
    _master: EncryptionKey,
    _metrics: Arc<metrics::Metrics>,
) -> std::io::Result<(DynKdc, Listen, ModeParts)> {
    Err(io_err(
        "db_library klmdb needs a krb5-rs-kdc built with the `klmdb` feature",
    ))
}

/// `db_library = test`: MIT's read-only test module (kdb_test.c).
fn test_mode(
    cli: &Cli,
    kdc_conf: &Profile,
    cfg: RealmConfig,
    metrics: Arc<metrics::Metrics>,
) -> std::io::Result<(DynKdc, Listen, ModeParts)> {
    let store = Arc::new(TestStore::new(
        kdc_conf.clone(),
        &cfg.db_module.section,
        &cfg.kdc.realm,
    ));
    let (udp, tcp) = if cli.listen.is_empty() {
        (cfg.udp_listen, cfg.tcp_listen)
    } else {
        let addrs = parse_listen_addresses(&cli.listen.join(","), 88).map_err(io_err)?;
        (addrs.clone(), addrs)
    };
    let parts = ModeParts {
        metrics_listen: metrics_listen(cli.metrics_listen, cfg.db_module.get("metrics_listen"))?,
        ..ModeParts::default()
    };
    Ok((
        Kdc::builder(cfg.kdc, DaemonStore::Test(store, metrics)).build(),
        Listen {
            udp,
            tcp,
            backlog: cfg.tcp_listen_backlog,
        },
        parts,
    ))
}

#[cfg(feature = "cockroach")]
async fn cockroach_mode(
    cli: &Cli,
    cfg: RealmConfig,
    master: EncryptionKey,
    _shutdown: &watch::Receiver<bool>,
    metrics: Arc<metrics::Metrics>,
) -> std::io::Result<Option<(DynKdc, Listen, ModeParts)>> {
    use krb5_rs::kdc::replication::{
        FreshnessGate, RebuildPolicy, ReplicationConfig, ReplicationEngine, StrictGate,
    };
    use krb5_rs_kdb_cockroach::{CockroachConfig, CockroachLockoutReporter, CockroachStore};
    use krb5_rs_kdb_turso::{TursoOptions, TursoReplica};

    let authority_config = CockroachConfig::from_db_module(&cfg.db_module).map_err(io_err)?;
    let replica_path = cfg
        .db_module
        .get("replica_path")
        .ok_or_else(|| io_err("db_library krb5-rs-cockroach needs replica_path"))?;
    let mut turso_options = TursoOptions::default();
    if let Some(v) = cfg.db_module.get("turso_pool_size") {
        turso_options.pool_size = v
            .parse()
            .map_err(|_| io_err("turso_pool_size: not a number"))?;
    }
    if let Some(v) = cfg.db_module.get("turso_checkpoint_threshold") {
        turso_options.mvcc_checkpoint_threshold = Some(
            v.parse()
                .map_err(|_| io_err("turso_checkpoint_threshold: not a number"))?,
        );
    }
    if let Some(v) = cfg.db_module.get("turso_passive_checkpoint") {
        turso_options.passive_checkpoint =
            matches!(v.to_ascii_lowercase().as_str(), "true" | "yes" | "on" | "1");
    }
    if let Some(v) = cfg.db_module.get("turso_max_retries") {
        turso_options.max_retries = v
            .parse()
            .map_err(|_| io_err("turso_max_retries: not a number"))?;
    }

    turso_options.master_key_name = cfg.master_key_name.clone();
    let replica = TursoReplica::open(replica_path, turso_options, master.clone())
        .await
        .map_err(io_err)?;
    let authority = CockroachStore::open_named(
        authority_config,
        master,
        &cfg.kdc.realm,
        &cfg.master_key_name,
    )
    .await
    .map_err(io_err)?;

    let kdc_id = cfg
        .db_module
        .get("kdc_id")
        .map(str::to_string)
        .or_else(|| std::env::var("POD_NAME").ok())
        .or_else(|| std::env::var("HOSTNAME").ok())
        .unwrap_or_else(|| "krb5-rs-kdc".to_string());
    let region = cfg.db_module.get("region").unwrap_or("unknown").to_string();
    let rebuild = match cfg.db_module.get("replication_rebuild") {
        None | Some("auto") => RebuildPolicy::Auto,
        Some("manual") => RebuildPolicy::Manual,
        Some(other) => {
            return Err(io_err(format!(
                "replication_rebuild: invalid value {other:?}"
            )))
        }
    };
    let replication = ReplicationConfig {
        poll_interval: module_duration(&cfg, "replication_poll_interval", Duration::from_secs(1))?,
        batch_limit: cfg
            .db_module
            .get("replication_batch_limit")
            .map(|v| {
                v.parse()
                    .map_err(|_| io_err("replication_batch_limit: not a number"))
            })
            .transpose()?
            .unwrap_or(1000),
        retry_min: module_duration(&cfg, "replication_retry_min", Duration::from_millis(100))?,
        retry_max: module_duration(&cfg, "replication_retry_max", Duration::from_secs(30))?,
        rebuild,
        heartbeat_interval: module_duration(
            &cfg,
            "replication_heartbeat_interval",
            Duration::from_secs(5),
        )?,
        kdc_id: kdc_id.clone(),
        region,
    };
    let max_staleness = module_duration(&cfg, "max_staleness", Duration::from_secs(30))?;
    let authoritative_timeout =
        module_duration(&cfg, "authoritative_timeout", Duration::from_millis(500))?;
    let engine = ReplicationEngine::new(
        authority.clone(),
        replica.clone(),
        authority.clone(),
        replication,
    );

    // A pod without a local database is not ready (and does not bind the KDC)
    // until a snapshot has committed locally.
    let mut retry = Duration::from_millis(100);
    loop {
        tokio::select! {
            _ = termination_signal() => {
                info!("received termination during replica bootstrap");
                return Ok(None);
            }
            result = engine.bootstrap() => match result {
                Ok(()) => break,
                Err(e) => {
                    warn!("replica bootstrap failed: {e}");
                    tokio::select! {
                        _ = tokio::time::sleep(retry) => {}
                        _ = termination_signal() => {
                            info!("received termination during replica bootstrap retry");
                            return Ok(None);
                        }
                    }
                    retry = retry.saturating_mul(2).min(Duration::from_secs(30));
                }
            }
        }
    }

    let status = engine.status_handle();
    let gate = match cfg.db_module.get("consistency_mode").unwrap_or("bounded") {
        "bounded" => RuntimeGate::Bounded(FreshnessGate::new(Arc::clone(&status), max_staleness)),
        "strict" => RuntimeGate::Strict(StrictGate::new(
            Arc::clone(&status),
            max_staleness,
            Arc::new(authority.clone()),
            authoritative_timeout,
        )),
        other => return Err(io_err(format!("consistency_mode: invalid value {other:?}"))),
    };
    let reporter = CockroachLockoutReporter::spawn(authority.clone(), kdc_id, 256);
    let kdc = Kdc::builder(
        cfg.kdc,
        DaemonStore::Turso(replica.clone(), Arc::clone(&metrics)),
    )
    .policies(replica.clone())
    // Lockout counters are realm-wide in CockroachDB, as in MIT's LDAP module.
    .auth_state(krb5_rs::kdc::SharedAuthState::new(
        authority.clone(),
        replica,
    ))
    .consistency(gate)
    .lockout_reporter(reporter.clone())
    .build();
    let (udp, tcp) = if cli.listen.is_empty() {
        (cfg.udp_listen, cfg.tcp_listen)
    } else {
        let addrs = parse_listen_addresses(&cli.listen.join(","), 88).map_err(io_err)?;
        (addrs.clone(), addrs)
    };
    let metrics_listen = metrics_listen(cli.metrics_listen, cfg.db_module.get("metrics_listen"))?;
    let parts = ModeParts {
        metrics_listen,
        replication: Some(ReplicationRuntime {
            engine,
            reporter,
            status,
            max_staleness,
        }),
    };
    Ok(Some((
        kdc,
        Listen {
            udp,
            tcp,
            backlog: cfg.tcp_listen_backlog,
        },
        parts,
    )))
}

#[cfg(not(feature = "cockroach"))]
async fn cockroach_mode(
    _cli: &Cli,
    _cfg: RealmConfig,
    _master: EncryptionKey,
    _shutdown: &watch::Receiver<bool>,
    _metrics: Arc<metrics::Metrics>,
) -> std::io::Result<Option<(DynKdc, Listen, ModeParts)>> {
    Err(io_err(
        "db_library krb5-rs-cockroach needs a krb5-rs-kdc built with the `cockroach` feature",
    ))
}

/// Load kdc.conf and open the database; `None` means shutdown arrived
/// before the KDC could start.
/// `krb5_db_fetch_mkey` with `manual` set (kdb_default.c): MIT's
/// `KRB5_KDC_MKEY_1` prompt, without echo on a terminal.
fn read_master_password() -> std::io::Result<String> {
    use std::io::{BufRead, IsTerminal, Write};
    print!("Enter KDC database master key: ");
    std::io::stdout().flush()?;
    let password = if std::io::stdin().is_terminal() {
        let p = rpassword::read_password()?;
        println!();
        p
    } else {
        let mut line = String::new();
        std::io::stdin().lock().read_line(&mut line)?;
        line.trim_end_matches(['\r', '\n']).to_string()
    };
    if password.is_empty() {
        return Err(io_err("empty master password"));
    }
    Ok(password)
}

async fn config_mode(
    cli: &Cli,
    ra: &kdc_args::RealmArgs,
    krb5_conf_explicit: bool,
    shutdown_rx: &watch::Receiver<bool>,
    metrics: Arc<metrics::Metrics>,
) -> std::io::Result<Option<(DynKdc, Listen, ModeParts)>> {
    let conf = cli
        .config
        .clone()
        .unwrap_or_else(|| PathBuf::from(DEFAULT_KDC_PROFILE));
    let kdc_conf =
        Profile::load(&conf).map_err(|e| io_err(format!("reading {}: {e}", conf.display())))?;
    let krb5 = match &cli.krb5_config {
        Some(p) if krb5_conf_explicit || p.exists() => {
            Some(Profile::load(p).map_err(|e| io_err(format!("reading {}: {e}", p.display())))?)
        }
        _ => None,
    };
    let realm = ra
        .realm
        .clone()
        .or_else(|| default_realm(&kdc_conf, krb5.as_ref()))
        .ok_or_else(|| io_err("no realm given and no default realm found"))?;
    let mut cfg = RealmConfig::from_profiles(&kdc_conf, krb5.as_ref(), &realm).map_err(io_err)?;
    // init_realm (main.c:196-330): kdc.conf's [realms] settings win over
    // the command line's.
    let in_realm = |key: &str| kdc_conf.get_string(&["realms", &realm, key]).is_some();
    if let Some(name) = ra
        .mkey_name
        .as_ref()
        .filter(|_| !in_realm("master_key_name"))
    {
        cfg.master_key_name = name.clone();
    }
    let manual = ra.manual && !in_realm("key_stash_file");
    if manual && !in_realm("master_key_type") {
        cfg.master_key_type = ra.menctype.unwrap_or(18);
    }
    if let Some(ports) = &ra.ports {
        if !in_realm("kdc_listen") && !in_realm("kdc_ports") {
            cfg.udp_listen = parse_listen_addresses(ports, 88).map_err(io_err)?;
        }
        if !in_realm("kdc_tcp_listen") && !in_realm("kdc_tcp_ports") {
            cfg.tcp_listen = parse_listen_addresses(ports, 88).map_err(io_err)?;
        }
    }
    cfg.kdc.time_offset = chrono::Duration::seconds(ra.time_offset);
    if let Some(e) = krb5_rs::kdc::otp_config_error(&kdc_conf, krb5.as_ref()) {
        error!("preauth otp failed to initialize: {e}");
    }
    if cfg.db_module.library.as_deref() == Some("test") {
        // MIT's test module has no master key (kdb_test.c
        // test_fetch_master_key).
        return test_mode(cli, &kdc_conf, cfg, metrics).map(Some);
    }
    cfg.apply_db_args(&ra.db_args).map_err(io_err)?;
    let master = match &cli.master_password_file {
        Some(path) => {
            let text = std::fs::read_to_string(path)
                .map_err(|e| io_err(format!("reading {}: {e}", path.display())))?;
            let password = text.lines().next().unwrap_or("").trim_end_matches('\r');
            if password.is_empty() {
                return Err(io_err(format!("{} is empty", path.display())));
            }
            master_key_from_password_named(
                &realm,
                &cfg.master_key_name,
                password,
                cfg.master_key_type,
            )
            .map_err(io_err)?
        }
        None if manual => {
            let password = read_master_password()?;
            master_key_from_password_named(
                &realm,
                &cfg.master_key_name,
                &password,
                cfg.master_key_type,
            )
            .map_err(io_err)?
        }
        None => {
            read_stash_named(&cfg.key_stash_file, &realm, &cfg.master_key_name).map_err(io_err)?
        }
    };

    match cfg.db_module.library.as_deref() {
        None | Some("krb5-rs-file") => {}
        Some("krb5-rs-turso") => {
            return turso_mode(cli, cfg, master, metrics).await.map(Some);
        }
        Some("klmdb") => {
            return klmdb_mode(cli, cfg, master, metrics).await.map(Some);
        }
        Some("kldap") => {
            return kldap_mode(cli, cfg, master, metrics).await.map(Some);
        }
        Some("krb5-rs-cockroach") => {
            return cockroach_mode(cli, cfg, master, shutdown_rx, metrics).await;
        }
        Some(other) => return Err(io_err(cfg.db_module.unknown_library_error(other))),
    }

    let mut parts = ModeParts::default();
    let mut waiting = false;
    let store = loop {
        match FileStore::open_named(&cfg.database_name, &master, &cfg.master_key_name) {
            Ok(store) => break Arc::new(store),
            Err(e) if cli.wait_for_database => waiting = database_wait(waiting, &e).await,
            Err(e) => return Err(io_err(e)),
        }
    };
    let (udp, tcp) = if cli.listen.is_empty() {
        (cfg.udp_listen, cfg.tcp_listen)
    } else {
        let addrs = parse_listen_addresses(&cli.listen.join(","), 88).map_err(io_err)?;
        (addrs.clone(), addrs)
    };
    parts.metrics_listen = metrics_listen(cli.metrics_listen, cfg.db_module.get("metrics_listen"))?;
    Ok(Some((
        Kdc::builder(cfg.kdc, DaemonStore::File(Arc::clone(&store), metrics))
            .policies(Arc::clone(&store))
            .auth_state(Arc::clone(&store))
            .build(),
        Listen {
            udp,
            tcp,
            backlog: cfg.tcp_listen_backlog,
        },
        parts,
    )))
}

/// Bind failures on an IPv6 address are tolerated: a dual-stack wildcard
/// bind may already be covered by the IPv4 one (MIT sets IPV6_V6ONLY).
fn tolerable(addr: &SocketAddr, e: &std::io::Error) -> bool {
    addr.is_ipv6()
        && matches!(
            e.kind(),
            std::io::ErrorKind::AddrInUse | std::io::ErrorKind::AddrNotAvailable
        )
}

#[cfg(unix)]
async fn termination_signal() -> std::io::Result<&'static str> {
    use tokio::signal::unix::{signal, SignalKind};
    let mut term = signal(SignalKind::terminate())?;
    let mut int = signal(SignalKind::interrupt())?;
    Ok(tokio::select! {
        _ = term.recv() => "SIGTERM",
        _ = int.recv() => "SIGINT",
    })
}

#[cfg(not(unix))]
async fn termination_signal() -> std::io::Result<&'static str> {
    tokio::signal::ctrl_c().await?;
    Ok("ctrl-c")
}

/// The `[plugins] kdcpolicy`, `audit`, `kdcauthdata` and `kdcpreauth` modules from
/// krb5.conf, then
/// kdc.conf, the order MIT's KDC profile and kadmind search them in.
fn load_plugins(cli: &Cli, krb5_conf_explicit: bool) -> std::io::Result<plugins::Modules> {
    let mut profiles = Vec::new();
    let conf = cli
        .config
        .clone()
        .unwrap_or_else(|| PathBuf::from(DEFAULT_KDC_PROFILE));
    if let Some(p) = &cli.krb5_config {
        if krb5_conf_explicit || p.exists() {
            profiles.push(
                Profile::load(p).map_err(|e| io_err(format!("reading {}: {e}", p.display())))?,
            );
        }
    }
    if cli.keytab.is_none() && conf.exists() {
        profiles.push(
            Profile::load(&conf).map_err(|e| io_err(format!("reading {}: {e}", conf.display())))?,
        );
    }
    let refs: Vec<&Profile> = profiles.iter().collect();
    plugins::load(&refs).map_err(io_err)
}

/// What `main` took from MIT's options.
struct Startup {
    realms: Vec<kdc_args::RealmArgs>,
    nofork: bool,
    /// `-n` was given: print "starting..." (main.c:1026-1027).
    announce: bool,
    workers: usize,
    pid_file: Option<PathBuf>,
    /// The sockets inherited from a `-w` supervisor.
    worker_fds: Option<String>,
    progname: String,
    /// Where relative paths on the command line are resolved; workers
    /// start here, since the supervisor has moved to `/`.
    start_dir: Option<PathBuf>,
}

/// Bind every UDP and TCP listen address.
async fn bind_listeners(addrs: &Listen) -> std::io::Result<(Vec<UdpSocket>, Vec<TcpListener>)> {
    let (mut udp, mut tcp) = (Vec::new(), Vec::new());
    for addr in &addrs.udp {
        match UdpSocket::bind(addr).await {
            Ok(sock) => {
                info!("listening on {} (udp)", sock.local_addr()?);
                udp.push(sock);
            }
            Err(e) if tolerable(addr, &e) => info!("skipping udp {addr}: {e}"),
            Err(e) => return Err(io_err(format!("bind udp {addr}: {e}"))),
        }
    }
    for addr in &addrs.tcp {
        match bind_tcp(*addr, addrs.backlog) {
            Ok(l) => {
                info!("listening on {} (tcp)", l.local_addr()?);
                tcp.push(l);
            }
            Err(e) if tolerable(addr, &e) => info!("skipping tcp {addr}: {e}"),
            Err(e) => return Err(io_err(format!("bind tcp {addr}: {e}"))),
        }
    }
    Ok((udp, tcp))
}

async fn run(
    cli: Cli,
    st: Startup,
    krb5_conf_explicit: bool,
    config_explicit: bool,
) -> std::io::Result<()> {
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let metrics = Arc::new(metrics::Metrics::new());
    let mut kdcs = Vec::new();
    let mut addrs = Listen {
        udp: Vec::new(),
        tcp: Vec::new(),
        backlog: DEFAULT_TCP_LISTEN_BACKLOG,
    };
    let mut prop = ModeParts::default();
    match &cli.keytab {
        Some(kt) => {
            if config_explicit {
                return Err(io_err("--keytab and --config are mutually exclusive"));
            }
            if st.realms.len() > 1 {
                return Err(io_err("--keytab serves one realm"));
            }
            let (kdc, a) = keytab_mode(&cli, kt, Arc::clone(&metrics)).await?;
            kdcs.push(kdc);
            addrs = a;
        }
        None => {
            if cli.max_life.is_some() || cli.max_renewable_life.is_some() {
                return Err(io_err(
                    "--max-life/--max-renewable-life come from kdc.conf in config mode",
                ));
            }
            // Every realm is answered on every realm's addresses
            // (main.c:976-990, dispatch.c setup_server_realm).
            for (i, ra) in st.realms.iter().enumerate() {
                let (kdc, a, parts) = match config_mode(
                    &cli,
                    ra,
                    krb5_conf_explicit,
                    &shutdown_rx,
                    Arc::clone(&metrics),
                )
                .await
                {
                    Ok(Some(parts)) => parts,
                    Ok(None) => return Ok(()),
                    Err(e) => {
                        // main.c:694-698, 805-809.
                        error!("{e}");
                        let name = ra.realm.as_deref().unwrap_or("(default)");
                        eprintln!(
                            "{}: cannot initialize realm {name} - see log file for details",
                            st.progname
                        );
                        std::process::exit(1);
                    }
                };
                kdcs.push(kdc);
                if i == 0 {
                    addrs.backlog = a.backlog;
                }
                for x in a.udp {
                    if !addrs.udp.contains(&x) {
                        addrs.udp.push(x);
                    }
                }
                for x in a.tcp {
                    if !addrs.tcp.contains(&x) {
                        addrs.tcp.push(x);
                    }
                }
                prop.metrics_listen = prop.metrics_listen.or(parts.metrics_listen);
                #[cfg(feature = "cockroach")]
                if let Some(r) = parts.replication {
                    if prop.replication.is_some() {
                        return Err(io_err(
                            "only one realm can use krb5-rs-cockroach replication",
                        ));
                    }
                    prop.replication = Some(r);
                }
            }
        }
    }
    let modules = load_plugins(&cli, krb5_conf_explicit)?;
    let audit = modules.1.clone();
    let kdcs = kdcs
        .into_iter()
        .map(|kdc| {
            Arc::new(
                kdc.with_plugins(modules.0.clone(), modules.1.clone())
                    .with_kdcauthdata(modules.2.clone())
                    .with_securid_sam2(modules.3.clone()),
            )
        })
        .collect();
    let kdc = Arc::new(KdcRealms::new(kdcs));

    let request_metrics = Arc::clone(&metrics);
    let logger: RequestLogger = Arc::new(move |summary, peer| {
        request_metrics.record_request(summary);
        info!(target: "request", "{}", summary.log_line(peer));
    });
    let options = ServeOptions {
        logger: Some(logger),
        shutdown: Some(shutdown_rx.clone()),
    };

    let (udp_socks, tcp_socks) = match &st.worker_fds {
        #[cfg(unix)]
        Some(spec) => {
            let socks = kdc_workers::adopt(spec)?;
            // A forked MIT worker shares the detached supervisor's `/`.
            if !st.announce {
                std::env::set_current_dir("/")?;
            }
            socks
        }
        _ => bind_listeners(&addrs).await?,
    };
    if udp_socks.is_empty() && tcp_socks.is_empty() {
        return Err(io_err("no KDC listen address could be bound"));
    }
    // daemon(0, 0), then the PID file (main.c:996-1006).
    #[cfg(unix)]
    if !st.nofork {
        daemonize::detach().map_err(|e| io_err(format!("{e} while detaching from tty")))?;
    }
    if let Some(path) = &st.pid_file {
        std::fs::write(path, format!("{}\n", std::process::id()))
            .map_err(|e| io_err(format!("{e} while creating PID file")))?;
    }
    let supervisor = st.workers > 0;
    let mut tasks = JoinSet::new();
    // Each worker would bind the metrics address again; the supervisor
    // serves it.
    let metrics_listen = match st.worker_fds {
        Some(_) => None,
        None => cli.metrics_listen.or(prop.metrics_listen),
    };
    #[cfg(feature = "cockroach")]
    let replication = if supervisor { None } else { prop.replication };
    #[cfg(feature = "cockroach")]
    let (replica_status, lockout_counters, max_staleness) = match replication {
        Some(replication) => {
            metrics.set_replication(&replication.engine.status());
            let reporter = replication.reporter.clone();
            let lockout_counters: Arc<dyn Fn() -> (u64, u64) + Send + Sync> =
                Arc::new(move || (reporter.reported(), reporter.dropped()));
            let status = Some(Arc::clone(&replication.status));
            let max = replication.max_staleness;
            let rx = shutdown_rx.clone();
            tasks.spawn(async move {
                replication.engine.run(rx).await;
                Ok(())
            });
            (status, Some(lockout_counters), max)
        }
        None => (None, None, Duration::from_secs(30)),
    };
    #[cfg(not(feature = "cockroach"))]
    let (replica_status, lockout_counters, max_staleness) = (None, None, Duration::from_secs(30));
    if let Some(addr) = metrics_listen {
        let listener = TcpListener::bind(addr)
            .await
            .map_err(|e| io_err(format!("bind metrics {addr}: {e}")))?;
        info!("listening on {} (metrics/health)", listener.local_addr()?);
        tasks.spawn(metrics::serve(
            listener,
            Arc::clone(&metrics),
            replica_status,
            lockout_counters,
            max_staleness,
            shutdown_rx.clone(),
        ));
    }

    #[cfg(unix)]
    if supervisor {
        let (spec, fds) = kdc_workers::encode(&udp_socks, &tcp_socks);
        let result = kdc_workers::supervise(st.workers, &spec, &fds, st.start_dir.as_deref()).await;
        let _ = shutdown_tx.send(true);
        return result;
    }
    for sock in udp_socks {
        tasks.spawn(serve_udp_with(Arc::clone(&kdc), sock, options.clone()));
    }
    for listener in tcp_socks {
        tasks.spawn(serve_tcp_with(Arc::clone(&kdc), listener, options.clone()));
    }
    // kau_kdc_start (main.c:1028), in each worker.
    for m in &audit {
        m.kdc_start(true);
    }
    info!("commencing operation");
    if st.announce {
        eprintln!("{}: starting...", st.progname);
    }

    tokio::select! {
        signal = termination_signal() => {
            info!("received {}, shutting down", signal?);
        }
        finished = tasks.join_next() => {
            if let Some(result) = finished {
                let e = match result {
                    Ok(Err(e)) => e,
                    Ok(Ok(())) => io_err("a listener stopped unexpectedly"),
                    Err(e) => io_err(e),
                };
                return Err(e);
            }
        }
    }

    let _ = shutdown_tx.send(true);
    let timeout = Duration::from_secs(cli.shutdown_timeout);
    let drained = tokio::time::timeout(timeout, async {
        while let Some(result) = tasks.join_next().await {
            if let Ok(Err(e)) = result {
                warn!("listener error during shutdown: {e}");
            }
        }
    })
    .await;
    match drained {
        Ok(()) => info!("shutdown complete"),
        Err(_) => warn!(
            "shutdown timeout ({}s) reached; closing remaining connections",
            cli.shutdown_timeout
        ),
    }
    // kau_kdc_stop (main.c:1031), after the last request has been handled.
    for m in &audit {
        m.kdc_stop(true);
    }
    // krb5_free_context: finalize the hostrealm modules lookups opened.
    tokio::task::spawn_blocking(krb5_rs::plugin::finalize_remote)
        .await
        .map_err(io_err)?;
    Ok(())
}

fn main() {
    let progname = std::env::args()
        .next()
        .unwrap_or_else(|| "krb5-rs-kdc".into());
    let (long_args, mit) = match kdc_args::parse(std::env::args_os()) {
        Ok(parsed) => parsed,
        Err(()) => {
            eprint!("{}", kdc_args::usage(&progname));
            std::process::exit(1);
        }
    };
    for w in &mit.warnings {
        eprintln!("{w}");
    }
    let matches = Cli::command().get_matches_from(long_args);
    let cli = Cli::from_arg_matches(&matches).unwrap_or_else(|e| e.exit());
    let from_cli = |id: &str| matches.value_source(id) == Some(ValueSource::CommandLine);
    let (krb5_conf_explicit, config_explicit) = (from_cli("krb5_config"), from_cli("config"));
    #[cfg(unix)]
    let worker_fds = std::env::var(kdc_workers::ENV).ok();
    #[cfg(not(unix))]
    let worker_fds: Option<String> = None;
    if cfg!(not(unix)) && mit.workers > 0 {
        eprintln!("{progname}: worker processes need a Unix system");
        std::process::exit(1);
    }
    let worker = worker_fds.is_some();
    let st = Startup {
        realms: kdc_args::realms(&mit, cli.realm.as_deref()),
        nofork: mit.nofork || worker || cfg!(not(unix)),
        announce: mit.nofork,
        workers: if worker { 0 } else { mit.workers },
        pid_file: if worker { None } else { mit.pid_file.clone() },
        worker_fds,
        progname: progname.clone(),
        start_dir: std::env::current_dir().ok(),
    };
    #[cfg(unix)]
    if !st.nofork {
        if let Err(e) = daemonize::fork() {
            eprintln!("{progname}: {e} while detaching from tty");
            std::process::exit(1);
        }
    }
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap_or_else(|e| {
            eprintln!("{progname}: {e} while creating main loop");
            std::process::exit(1);
        });
    runtime.block_on(daemon_main(cli, st, krb5_conf_explicit, config_explicit));
}

async fn daemon_main(cli: Cli, st: Startup, krb5_conf_explicit: bool, config_explicit: bool) {
    // krb5_klog_init(kcontext, "kdc", argv[0], 1) (kdc/main.c), from the
    // KDC profile: kdc.conf, then krb5.conf.
    let whoami = std::env::args()
        .next()
        .unwrap_or_else(|| "krb5-rs-kdc".into());
    let mut profiles = Vec::new();
    let conf = cli
        .config
        .clone()
        .unwrap_or_else(|| PathBuf::from(DEFAULT_KDC_PROFILE));
    if cli.keytab.is_some() {
        profiles.extend(Profile::load(&conf).ok());
    } else {
        match Profile::load(&conf) {
            Ok(p) => profiles.push(p),
            // As a profile MIT can't read fails krb5_init_context, before
            // logging is set up.
            Err(e) => {
                eprintln!("{whoami}: reading {}: {e}", conf.display());
                std::process::exit(1);
            }
        }
    }
    if let Some(p) = cli.krb5_config.as_ref().filter(|p| p.exists()) {
        match Profile::load(p) {
            Ok(p) => profiles.push(p),
            Err(e) => {
                eprintln!("{whoami}: reading {}: {e}", p.display());
                std::process::exit(1);
            }
        }
    }
    let refs: Vec<&Profile> = profiles.iter().collect();
    klog::install(klog::Klog::init(&refs, "kdc", &whoami));
    #[cfg(unix)]
    tokio::spawn(async {
        use tokio::signal::unix::{signal, SignalKind};
        if let Ok(mut hup) = signal(SignalKind::hangup()) {
            while hup.recv().await.is_some() {
                klog::reopen();
            }
        }
    });

    if let Err(e) = run(cli, st, krb5_conf_explicit, config_explicit).await {
        error!("{e}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::metrics_listen;
    use std::net::SocketAddr;

    #[test]
    fn metrics_cli_address_overrides_the_profile_value() {
        let cli = "127.0.0.1:9001".parse::<SocketAddr>().expect("CLI address");
        assert_eq!(
            metrics_listen(Some(cli), Some("not-an-address")).expect("CLI wins"),
            Some(cli)
        );
    }

    #[test]
    fn invalid_metrics_profile_address_is_an_error() {
        assert!(metrics_listen(None, Some("not-an-address")).is_err());
        assert_eq!(metrics_listen(None, None).expect("not configured"), None);
    }
}
