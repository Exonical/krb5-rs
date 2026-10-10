//! KDC daemon for a single realm.
//!
//! Two modes (exactly one must be given):
//!
//! * `--keytab PATH` serves every principal found in a keytab, all
//!   requiring pre-authentication (a random `krbtgt/REALM` is generated if
//!   the keytab has none):
//!   `kdc --realm EXAMPLE.COM --keytab service.keytab [--listen ADDR]...
//!   [--max-life SECS] [--max-renewable-life SECS]`
//! * `--config kdc.conf` serves the persistent database created with the
//!   `kdb` example, using the master key stash named in kdc.conf:
//!   `kdc --config kdc.conf [--krb5-config krb5.conf] [--realm REALM]`
//!
//! Passwords are never accepted on the command line.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use krb5_rs::kdc::kdb::{read_stash, FileStore};
use krb5_rs::kdc::{
    default_realm, parse_listen_addresses, serve_tcp, serve_udp, Kdc, KdcConfig, MemoryStore,
    PrincipalAttributes, PrincipalStore, RealmConfig,
};
use krb5_rs::keytab::FileKeytab;
use krb5_rs::profile::Profile;
use krb5_rs::types::PrincipalName;
use tokio::net::{TcpListener, UdpSocket};

fn usage() -> ! {
    eprintln!(
        "usage: kdc --realm REALM --keytab PATH [--listen ADDR]... [--max-life SECS] \
         [--max-renewable-life SECS]\n       kdc --config kdc.conf [--krb5-config krb5.conf] \
         [--realm REALM]"
    );
    std::process::exit(2);
}

fn fail(msg: impl std::fmt::Display) -> ! {
    eprintln!("kdc: {msg}");
    std::process::exit(1);
}

fn secs(value: Option<String>) -> Duration {
    Duration::from_secs(
        value
            .and_then(|v| v.parse().ok())
            .unwrap_or_else(|| usage()),
    )
}

struct Listen {
    udp: Vec<SocketAddr>,
    tcp: Vec<SocketAddr>,
}

fn keytab_mode(
    realm: String,
    keytab: &str,
    listen: &[String],
    max_life: Option<Duration>,
    max_renewable_life: Option<Duration>,
) -> std::io::Result<(Kdc<Arc<dyn PrincipalStore>>, Listen)> {
    let mut store = MemoryStore::new();
    store
        .import_keytab(
            &FileKeytab::new(keytab),
            PrincipalAttributes::REQUIRES_PRE_AUTH,
        )
        .map_err(|e| std::io::Error::other(format!("reading keytab {keytab}: {e}")))?;

    let tgs = PrincipalName::new_srv_inst("krbtgt", &realm);
    if store.lookup(&tgs, &realm).ok().flatten().is_none() {
        eprintln!(
            "warning: no krbtgt/{realm}@{realm} in keytab; generated a random one \
             (issued tickets will not survive a restart)"
        );
        store
            .add_random_key(tgs, &realm, 1, &[18, 17], PrincipalAttributes::empty())
            .map_err(|e| std::io::Error::other(e.to_string()))?;
    }

    let mut config = KdcConfig::new(realm);
    if let Some(d) = max_life {
        config.max_life = d;
    }
    if let Some(d) = max_renewable_life {
        config.max_renewable_life = d;
    }
    let spec = if listen.is_empty() {
        "0.0.0.0:88".to_string()
    } else {
        listen.join(",")
    };
    let addrs = parse_listen_addresses(&spec, 88).map_err(std::io::Error::other)?;
    let store: Arc<dyn PrincipalStore> = Arc::new(store);
    Ok((
        Kdc::new(config, store),
        Listen {
            udp: addrs.clone(),
            tcp: addrs,
        },
    ))
}

fn config_mode(
    conf: &str,
    krb5_conf: Option<&str>,
    realm: Option<String>,
) -> std::io::Result<(Kdc<Arc<dyn PrincipalStore>>, Listen)> {
    let kdc_conf = Profile::load(Path::new(conf))
        .map_err(|e| std::io::Error::other(format!("reading {conf}: {e}")))?;
    let krb5 = krb5_conf
        .map(|p| Profile::load(Path::new(p)))
        .transpose()
        .map_err(|e| std::io::Error::other(format!("reading krb5.conf: {e}")))?;
    let realm = realm
        .or_else(|| default_realm(&kdc_conf, krb5.as_ref()))
        .ok_or_else(|| std::io::Error::other("no realm given and no default realm found"))?;
    let cfg = RealmConfig::from_profiles(&kdc_conf, krb5.as_ref(), &realm)
        .map_err(std::io::Error::other)?;
    let master = read_stash(&cfg.key_stash_file, &realm).map_err(std::io::Error::other)?;
    let store = FileStore::open(&cfg.database_name, &master).map_err(std::io::Error::other)?;
    let store: Arc<dyn PrincipalStore> = Arc::new(store);
    Ok((
        Kdc::new(cfg.kdc, store),
        Listen {
            udp: cfg.udp_listen,
            tcp: cfg.tcp_listen,
        },
    ))
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

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let mut realm = None;
    let mut keytab = None;
    let mut config = None;
    let mut krb5_config = None;
    let mut listen: Vec<String> = Vec::new();
    let mut max_life = None;
    let mut max_renewable_life = None;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--realm" => realm = args.next(),
            "--keytab" => keytab = args.next(),
            "--config" => config = args.next(),
            "--krb5-config" => krb5_config = args.next(),
            "--listen" => listen.extend(args.next()),
            "--max-life" => max_life = Some(secs(args.next())),
            "--max-renewable-life" => max_renewable_life = Some(secs(args.next())),
            _ => usage(),
        }
    }

    let (kdc, addrs) = match (&keytab, &config) {
        (Some(kt), None) => {
            let realm = realm.unwrap_or_else(|| usage());
            keytab_mode(realm, kt, &listen, max_life, max_renewable_life)?
        }
        (None, Some(conf)) => {
            if !listen.is_empty() || max_life.is_some() || max_renewable_life.is_some() {
                fail(
                    "--listen/--max-life/--max-renewable-life come from kdc.conf in --config mode",
                );
            }
            config_mode(conf, krb5_config.as_deref(), realm)?
        }
        _ => usage(),
    };
    let kdc = Arc::new(kdc);

    let mut tasks = Vec::new();
    for addr in &addrs.udp {
        match UdpSocket::bind(addr).await {
            Ok(sock) => {
                println!("listening on {} (udp)", sock.local_addr()?);
                tasks.push(tokio::spawn(serve_udp(Arc::clone(&kdc), sock)));
            }
            Err(e) if tolerable(addr, &e) => eprintln!("warning: skipping udp {addr}: {e}"),
            Err(e) => fail(format!("bind udp {addr}: {e}")),
        }
    }
    for addr in &addrs.tcp {
        match TcpListener::bind(addr).await {
            Ok(l) => {
                println!("listening on {} (tcp)", l.local_addr()?);
                tasks.push(tokio::spawn(serve_tcp(Arc::clone(&kdc), l)));
            }
            Err(e) if tolerable(addr, &e) => eprintln!("warning: skipping tcp {addr}: {e}"),
            Err(e) => fail(format!("bind tcp {addr}: {e}")),
        }
    }
    for task in tasks {
        task.await.map_err(std::io::Error::other)??;
    }
    Ok(())
}
