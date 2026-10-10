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
use krb5_rs::kdc::kdb::{read_stash, FileStore};
use krb5_rs::kdc::{
    default_realm, parse_listen_addresses, serve_tcp_with, serve_udp_with, Kdc, KdcConfig,
    MemoryStore, PrincipalAttributes, PrincipalStore, RealmConfig, RequestLogger, ServeOptions,
};
use krb5_rs::keytab::FileKeytab;
use krb5_rs::profile::Profile;
use krb5_rs::types::PrincipalName;
use tokio::net::{TcpListener, UdpSocket};
use tokio::task::JoinSet;
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

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
}

struct Listen {
    udp: Vec<SocketAddr>,
    tcp: Vec<SocketAddr>,
}

type DynKdc = Kdc<Arc<dyn PrincipalStore>>;

fn io_err(msg: impl std::fmt::Display) -> std::io::Error {
    std::io::Error::other(msg.to_string())
}

fn keytab_mode(cli: &Cli, keytab: &Path) -> std::io::Result<(DynKdc, Listen)> {
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
    if store.lookup(&tgs, &realm).ok().flatten().is_none() {
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
    let store: Arc<dyn PrincipalStore> = Arc::new(store);
    Ok((
        Kdc::new(config, store),
        Listen {
            udp: addrs.clone(),
            tcp: addrs,
        },
    ))
}

fn config_mode(cli: &Cli, krb5_conf_explicit: bool) -> std::io::Result<(DynKdc, Listen)> {
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
    let master = read_stash(&cfg.key_stash_file, &realm).map_err(io_err)?;
    let store = FileStore::open(&cfg.database_name, &master).map_err(io_err)?;
    let store: Arc<dyn PrincipalStore> = Arc::new(store);
    let (udp, tcp) = if cli.listen.is_empty() {
        (cfg.udp_listen, cfg.tcp_listen)
    } else {
        let addrs = parse_listen_addresses(&cli.listen.join(","), 88).map_err(io_err)?;
        (addrs.clone(), addrs)
    };
    Ok((Kdc::new(cfg.kdc, store), Listen { udp, tcp }))
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
    let (kdc, addrs) = match &cli.keytab {
        Some(kt) => {
            if config_explicit {
                return Err(io_err("--keytab and --config are mutually exclusive"));
            }
            keytab_mode(&cli, kt)?
        }
        None => {
            if cli.max_life.is_some() || cli.max_renewable_life.is_some() {
                return Err(io_err(
                    "--max-life/--max-renewable-life come from kdc.conf in config mode",
                ));
            }
            config_mode(&cli, krb5_conf_explicit)?
        }
    };
    let kdc = Arc::new(kdc);

    let logger: RequestLogger = Arc::new(|summary, peer| {
        info!(target: "request", "{}", summary.log_line(peer));
    });
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let options = ServeOptions {
        logger: Some(logger),
        shutdown: Some(shutdown_rx),
    };

    let mut tasks = JoinSet::new();
    for addr in &addrs.udp {
        match UdpSocket::bind(addr).await {
            Ok(sock) => {
                info!("listening on {} (udp)", sock.local_addr()?);
                tasks.spawn(serve_udp_with(Arc::clone(&kdc), sock, options.clone()));
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
            }
            Err(e) if tolerable(addr, &e) => info!("skipping tcp {addr}: {e}"),
            Err(e) => return Err(io_err(format!("bind tcp {addr}: {e}"))),
        }
    }
    if tasks.is_empty() {
        return Err(io_err("no listen address could be bound"));
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
