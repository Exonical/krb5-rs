//! KDC daemon for a single realm.
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

use std::io::IsTerminal;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use clap::parser::ValueSource;
use clap::{CommandFactory, FromArgMatches, Parser};
use krb5_rs::kdc::kdb::admin::parse_principal;
use krb5_rs::kdc::kdb::propagation::{
    initial_pull, run_replica_loop, serve_propagation, PropClientConfig, PropEvent, PropLogger,
    PropSecret, PropServerConfig,
};
use krb5_rs::kdc::kdb::{master_key_from_password, read_stash, FileStore};
use krb5_rs::kdc::{
    default_realm, parse_listen_addresses, serve_tcp_with, serve_udp_with, Kdc, KdcConfig,
    MemoryStore, PrincipalAttributes, PrincipalEntry, PrincipalStore, RealmConfig, RequestLogger,
    ServeOptions, StoreError,
};
use krb5_rs::keytab::FileKeytab;
use krb5_rs::profile::Profile;
use krb5_rs::types::{EncryptionKey, PrincipalName};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::watch;
use tokio::task::JoinSet;
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

#[path = "../daemon_metrics.rs"]
mod metrics;

/// MIT's default kdc.conf location (`DEFAULT_KDC_PROFILE`).
const DEFAULT_KDC_PROFILE: &str = "/usr/local/var/krb5kdc/kdc.conf";

#[derive(Parser)]
#[command(name = "krb5-rs-kdc", version, about = "Kerberos V5 KDC for one realm")]
struct Cli {
    /// kdc.conf to read (config mode).
    #[arg(long, env = "KRB5_KDC_PROFILE", value_name = "PATH")]
    config: Option<PathBuf>,

    /// krb5.conf for [libdefaults], [domain_realm] and [capaths].
    #[arg(long, env = "KRB5_CONFIG", value_name = "PATH")]
    krb5_config: Option<PathBuf>,

    /// Realm to serve (default: the sole realm in kdc.conf, else krb5.conf).
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
}

struct Listen {
    udp: Vec<SocketAddr>,
    tcp: Vec<SocketAddr>,
}

/// The store this process serves: the bootstrap keytab or the database file.
/// (The store traits use native async, so they are not trait objects; the
/// daemon picks the backend with an enum.)
enum DaemonStore {
    Memory(Arc<MemoryStore>, Arc<metrics::Metrics>),
    File(Arc<FileStore>, Arc<metrics::Metrics>),
    #[cfg(feature = "turso")]
    Turso(krb5_rs_kdb_turso::TursoReplica, Arc<metrics::Metrics>),
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
            #[cfg(feature = "turso")]
            DaemonStore::Turso(s, metrics) => {
                let start = std::time::Instant::now();
                let result = s.lookup(name, realm).await;
                metrics.observe_principal_lookup(start.elapsed(), result.is_ok());
                result
            }
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
        },
    ))
}

/// Propagation roles of this process (kdc.conf `kprop_*`).
#[derive(Default)]
struct PropParts {
    server: Option<(Arc<FileStore>, PropServerConfig, Vec<SocketAddr>)>,
    replica: Option<PropClientConfig>,
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
    async fn check(&self, principals: &[&PrincipalEntry]) -> krb5_rs::kdc::GateDecision {
        match self {
            RuntimeGate::Bounded(gate) => gate.check(principals).await,
            RuntimeGate::Strict(gate) => gate.check(principals).await,
        }
    }
}

fn prop_logger() -> PropLogger {
    Arc::new(|event| match event {
        PropEvent::Refused { .. } | PropEvent::PullFailed { .. } => {
            warn!(target: "kprop", "{event}")
        }
        _ => info!(target: "kprop", "{event}"),
    })
}

fn principal(spec: &str, realm: &str) -> std::io::Result<PrincipalName> {
    let (name, r) = parse_principal(spec, realm).map_err(io_err)?;
    if r != realm {
        return Err(io_err(format!("{spec} is not in realm {realm}")));
    }
    Ok(name)
}

fn replica_config(
    cfg: &RealmConfig,
    realm: &str,
    master: &EncryptionKey,
) -> std::io::Result<PropClientConfig> {
    let p = &cfg.propagation;
    let secret = match (&p.keytab, &p.password_file) {
        (Some(k), None) => PropSecret::Keytab(k.clone()),
        (None, Some(f)) => PropSecret::PasswordFile(f.clone()),
        _ => {
            return Err(io_err(
                "a replica needs exactly one of kprop_keytab and kprop_password_file",
            ))
        }
    };
    Ok(PropClientConfig {
        realm: realm.to_string(),
        primary: p
            .primary
            .clone()
            .ok_or_else(|| io_err("kprop_primary is not set"))?,
        kdc: p
            .primary_kdc
            .clone()
            .ok_or_else(|| io_err("kprop_primary_kdc is not set"))?,
        client: principal(&p.client, realm)?,
        service: principal(&p.service, realm)?,
        secret,
        db_path: cfg.database_name.clone(),
        master_key: master.clone(),
        poll_interval: p.poll_interval,
        io_timeout: Duration::from_secs(10),
        logger: Some(prop_logger()),
    })
}

/// Serve from a Turso replica (`db_library = krb5-rs-turso`), read-only.
/// Replication into it is not wired here yet.
#[cfg(feature = "turso")]
async fn turso_mode(
    cli: &Cli,
    cfg: RealmConfig,
    master: krb5_rs::types::EncryptionKey,
    metrics: Arc<metrics::Metrics>,
) -> std::io::Result<(DynKdc, Listen, PropParts)> {
    use krb5_rs_kdb_turso::{TursoOptions, TursoReplica};

    if cfg.propagation.is_replica() || !cfg.propagation.listen.is_empty() {
        return Err(io_err(
            "kprop_* settings cannot be combined with db_library = krb5-rs-turso",
        ));
    }
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
        Listen { udp, tcp },
        PropParts {
            metrics_listen,
            ..PropParts::default()
        },
    ))
}

#[cfg(not(feature = "turso"))]
async fn turso_mode(
    _cli: &Cli,
    _cfg: RealmConfig,
    _master: krb5_rs::types::EncryptionKey,
    _metrics: Arc<metrics::Metrics>,
) -> std::io::Result<(DynKdc, Listen, PropParts)> {
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

#[cfg(feature = "cockroach")]
async fn cockroach_mode(
    cli: &Cli,
    cfg: RealmConfig,
    master: EncryptionKey,
    _shutdown: &watch::Receiver<bool>,
    metrics: Arc<metrics::Metrics>,
) -> std::io::Result<Option<(DynKdc, Listen, PropParts)>> {
    use krb5_rs::kdc::replication::{
        FreshnessGate, RebuildPolicy, ReplicationConfig, ReplicationEngine, StrictGate,
    };
    use krb5_rs_kdb_cockroach::{CockroachConfig, CockroachLockoutReporter, CockroachStore};
    use krb5_rs_kdb_turso::{TursoOptions, TursoReplica};

    if cfg.propagation.is_replica() || !cfg.propagation.listen.is_empty() {
        return Err(io_err(
            "kprop_* cannot be combined with db_library = krb5-rs-cockroach",
        ));
    }
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

    let replica = TursoReplica::open(replica_path, turso_options, master.clone())
        .await
        .map_err(io_err)?;
    let authority = CockroachStore::open(authority_config, master, &cfg.kdc.realm)
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
    .auth_state(replica)
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
    let parts = PropParts {
        metrics_listen,
        replication: Some(ReplicationRuntime {
            engine,
            reporter,
            status,
            max_staleness,
        }),
        ..PropParts::default()
    };
    Ok(Some((kdc, Listen { udp, tcp }, parts)))
}

#[cfg(not(feature = "cockroach"))]
async fn cockroach_mode(
    _cli: &Cli,
    _cfg: RealmConfig,
    _master: EncryptionKey,
    _shutdown: &watch::Receiver<bool>,
    _metrics: Arc<metrics::Metrics>,
) -> std::io::Result<Option<(DynKdc, Listen, PropParts)>> {
    Err(io_err(
        "db_library krb5-rs-cockroach needs a krb5-rs-kdc built with the `cockroach` feature",
    ))
}

/// Load kdc.conf and open the database. A replica without a local database
/// pulls one first (retrying until the primary answers) and only then lets
/// the caller bind its listeners; `None` means shutdown arrived meanwhile.
async fn config_mode(
    cli: &Cli,
    krb5_conf_explicit: bool,
    shutdown_rx: &watch::Receiver<bool>,
    metrics: Arc<metrics::Metrics>,
) -> std::io::Result<Option<(DynKdc, Listen, PropParts)>> {
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
    let realm = cli
        .realm
        .clone()
        .or_else(|| default_realm(&kdc_conf, krb5.as_ref()))
        .ok_or_else(|| io_err("no realm given and no default realm found"))?;
    let cfg = RealmConfig::from_profiles(&kdc_conf, krb5.as_ref(), &realm).map_err(io_err)?;
    let master = match &cli.master_password_file {
        Some(path) => {
            let text = std::fs::read_to_string(path)
                .map_err(|e| io_err(format!("reading {}: {e}", path.display())))?;
            let password = text.lines().next().unwrap_or("").trim_end_matches('\r');
            if password.is_empty() {
                return Err(io_err(format!("{} is empty", path.display())));
            }
            master_key_from_password(&realm, password, cfg.master_key_type).map_err(io_err)?
        }
        None => read_stash(&cfg.key_stash_file, &realm).map_err(io_err)?,
    };

    match cfg.db_module.library.as_deref() {
        None => {}
        Some("krb5-rs-turso") => {
            return turso_mode(cli, cfg, master, metrics).await.map(Some);
        }
        Some("krb5-rs-cockroach") => {
            return cockroach_mode(cli, cfg, master, shutdown_rx, metrics).await;
        }
        Some(other) => return Err(io_err(format!("unknown db_library {other:?}"))),
    }

    let mut parts = PropParts::default();
    if cfg.propagation.is_replica() {
        let client = replica_config(&cfg, &realm, &master)?;
        if !cfg.database_name.exists() {
            info!(
                "no local database {}; pulling from {} before serving",
                cfg.database_name.display(),
                client.primary
            );
            let mut rx = shutdown_rx.clone();
            let pulled = tokio::select! {
                r = initial_pull(&client, &mut rx) => r,
                signal = termination_signal() => {
                    info!("received {}, exiting", signal?);
                    None
                }
            };
            if pulled.is_none() {
                return Ok(None);
            }
        }
        parts.replica = Some(client);
    }

    let store = Arc::new(FileStore::open(&cfg.database_name, &master).map_err(io_err)?);
    if !cfg.propagation.listen.is_empty() {
        let service = principal(&cfg.propagation.service, &realm)?;
        if store
            .lookup(&service, &realm)
            .await
            .map_err(io_err)?
            .is_none()
        {
            return Err(io_err(format!(
                "kprop service principal {} is not in the database",
                cfg.propagation.service
            )));
        }
        let mut server = PropServerConfig::new(service, cfg.propagation.acl.clone());
        server.clockskew = cfg.kdc.clockskew;
        server.logger = Some(prop_logger());
        parts.server = Some((Arc::clone(&store), server, cfg.propagation.listen.clone()));
    }
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
            .build(),
        Listen { udp, tcp },
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

async fn run(cli: Cli, krb5_conf_explicit: bool, config_explicit: bool) -> std::io::Result<()> {
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let metrics = Arc::new(metrics::Metrics::new());
    let (kdc, addrs, prop) = match &cli.keytab {
        Some(kt) => {
            if config_explicit {
                return Err(io_err("--keytab and --config are mutually exclusive"));
            }
            let (kdc, addrs) = keytab_mode(&cli, kt, Arc::clone(&metrics)).await?;
            (kdc, addrs, PropParts::default())
        }
        None => {
            if cli.max_life.is_some() || cli.max_renewable_life.is_some() {
                return Err(io_err(
                    "--max-life/--max-renewable-life come from kdc.conf in config mode",
                ));
            }
            match config_mode(&cli, krb5_conf_explicit, &shutdown_rx, Arc::clone(&metrics)).await? {
                Some(parts) => parts,
                None => return Ok(()),
            }
        }
    };
    let kdc = Arc::new(kdc);

    let request_metrics = Arc::clone(&metrics);
    let logger: RequestLogger = Arc::new(move |summary, peer| {
        request_metrics.record_request(summary);
        info!(target: "request", "{}", summary.log_line(peer));
    });
    let options = ServeOptions {
        logger: Some(logger),
        shutdown: Some(shutdown_rx.clone()),
    };

    let mut tasks = JoinSet::new();
    let mut bound_kdc_listeners = 0usize;
    for addr in &addrs.udp {
        match UdpSocket::bind(addr).await {
            Ok(sock) => {
                info!("listening on {} (udp)", sock.local_addr()?);
                tasks.spawn(serve_udp_with(Arc::clone(&kdc), sock, options.clone()));
                bound_kdc_listeners += 1;
            }
            Err(e) if tolerable(addr, &e) => info!("skipping udp {addr}: {e}"),
            Err(e) => return Err(io_err(format!("bind udp {addr}: {e}"))),
        }
    }
    for addr in &addrs.tcp {
        match TcpListener::bind(addr).await {
            Ok(l) => {
                info!("listening on {} (tcp)", l.local_addr()?);
                tasks.spawn(serve_tcp_with(Arc::clone(&kdc), l, options.clone()));
                bound_kdc_listeners += 1;
            }
            Err(e) if tolerable(addr, &e) => info!("skipping tcp {addr}: {e}"),
            Err(e) => return Err(io_err(format!("bind tcp {addr}: {e}"))),
        }
    }
    if let Some((store, config, addrs)) = prop.server {
        for addr in addrs {
            let listener = TcpListener::bind(addr)
                .await
                .map_err(|e| io_err(format!("bind kprop {addr}: {e}")))?;
            info!("listening on {} (kprop)", listener.local_addr()?);
            tasks.spawn(serve_propagation(
                Arc::clone(&store),
                config.clone(),
                listener,
                Some(shutdown_rx.clone()),
            ));
        }
    }
    let metrics_listen = cli.metrics_listen.or(prop.metrics_listen);
    #[cfg(feature = "cockroach")]
    let replication = prop.replication;
    if let Some(client) = prop.replica {
        info!(
            "replica of {}: polling every {:?}",
            client.primary, client.poll_interval
        );
        let rx = shutdown_rx.clone();
        tasks.spawn(async move {
            run_replica_loop(client, rx).await;
            Ok(())
        });
    }
    if bound_kdc_listeners == 0 {
        return Err(io_err("no KDC listen address could be bound"));
    }
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
    Ok(())
}

#[tokio::main]
async fn main() {
    let matches = Cli::command().get_matches();
    let cli = Cli::from_arg_matches(&matches).unwrap_or_else(|e| e.exit());
    let from_cli = |id: &str| matches.value_source(id) == Some(ValueSource::CommandLine);

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_ansi(std::io::stdout().is_terminal())
        .with_target(false)
        .with_writer(std::io::stdout)
        .init();

    if let Err(e) = run(cli, from_cli("krb5_config"), from_cli("config")).await {
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
