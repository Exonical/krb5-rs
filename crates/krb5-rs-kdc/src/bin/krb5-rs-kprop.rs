//! `krb5-rs-kprop`: push a database dump to one replica's kpropd, as MIT
//! krb5 1.22.2 `kprop` (src/kprop/kprop.c) does.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use krb5_rs::kdc::kdb::kprop::{self, ErrorParties, KpropError, KPROP_PORT, KPROP_SERVICE};
use krb5_rs::keytab::{key_for_principal, FileKeytab};
use krb5_rs::profile::Profile;
use krb5_rs::protocol::{AsExchange, AsExchangeConfig, Credential, StepResult};
use krb5_rs::transport::{KdcTransport, LocatedTransport};
use tokio::net::TcpStream;

const DEFAULT_FILE: &str = "/usr/local/var/krb5kdc/replica_datatrans";
const DEFAULT_KEYTAB: &str = "/etc/krb5.keytab";
const CLOCKSKEW: Duration = Duration::from_secs(300);

struct Args {
    realm: Option<String>,
    file: PathBuf,
    debug: bool,
    port: String,
    keytab: Option<String>,
    replica_host: String,
    /// krb5-rs extension: `--interval SECS` dumps and pushes to every host
    /// forever (the cron job MIT's documentation suggests, for images
    /// without a shell).
    interval: Option<u64>,
    kdb: Option<PathBuf>,
    replica_hosts: Vec<String>,
}

fn usage() -> ! {
    eprintln!(
        "\nUsage: kprop [-r realm] [-f file] [-d] [-P port] [-s keytab] replica_host\n       \
         kprop --interval SECS [--kdb PROGRAM] [options] replica_host...\n"
    );
    std::process::exit(1);
}

fn die(msg: impl std::fmt::Display) -> ! {
    eprintln!("kprop: {msg}");
    std::process::exit(1);
}

fn parse_args() -> Args {
    let mut args = Args {
        realm: None,
        file: PathBuf::from(DEFAULT_FILE),
        debug: false,
        port: KPROP_SERVICE.to_string(),
        keytab: None,
        replica_host: String::new(),
        interval: None,
        kdb: None,
        replica_hosts: Vec::new(),
    };
    let mut positional = Vec::new();
    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--interval" => {
                let secs = it.next().and_then(|v| v.parse().ok()).filter(|&v| v > 0);
                args.interval = Some(secs.unwrap_or_else(|| usage()));
                continue;
            }
            "--kdb" => {
                args.kdb = Some(PathBuf::from(it.next().unwrap_or_else(|| usage())));
                continue;
            }
            _ => {}
        }
        let Some(flags) = arg.strip_prefix('-').filter(|f| !f.is_empty()) else {
            positional.push(arg);
            continue;
        };
        for (i, c) in flags.char_indices() {
            if c == 'd' {
                args.debug = true;
                continue;
            }
            let rest = &flags[i + c.len_utf8()..];
            let value = if rest.is_empty() {
                it.next().unwrap_or_else(|| usage())
            } else {
                rest.to_string()
            };
            match c {
                'r' => args.realm = Some(value),
                'f' => args.file = PathBuf::from(value),
                'P' => args.port = value,
                's' => args.keytab = Some(value),
                _ => usage(),
            }
            break;
        }
    }
    if args.interval.is_some() {
        if positional.is_empty() {
            usage();
        }
        args.replica_hosts = positional;
        return args;
    }
    let [host] = <[String; 1]>::try_from(positional).unwrap_or_else(|_| usage());
    args.replica_host = host;
    args
}

/// `--interval`: `krb5-rs-kdb dump FILE`, then one `kprop` run per host, every
/// `secs` seconds. Every host gets the full dump each round, so a replica
/// that lost its database is refilled within one interval.
fn propagate_forever(args: &Args, secs: u64) -> ! {
    let me = std::env::current_exe().unwrap_or_else(|e| die(e));
    let kdb = args.kdb.clone().unwrap_or_else(|| {
        let sibling = me.with_file_name("krb5-rs-kdb");
        if sibling.exists() {
            sibling
        } else {
            PathBuf::from("krb5-rs-kdb")
        }
    });
    let mut common: Vec<String> = Vec::new();
    if let Some(realm) = &args.realm {
        common.extend(["-r".into(), realm.clone()]);
    }
    common.extend(["-P".into(), args.port.clone()]);
    if let Some(keytab) = &args.keytab {
        common.extend(["-s".into(), keytab.clone()]);
    }
    if args.debug {
        common.push("-d".into());
    }
    loop {
        let dumped = std::process::Command::new(&kdb)
            .args(args.realm.iter().flat_map(|r| ["-r", r.as_str()]))
            .arg("dump")
            .arg(&args.file)
            .status();
        match dumped {
            Ok(status) if status.success() => {
                for host in &args.replica_hosts {
                    let pushed = std::process::Command::new(&me)
                        .args(&common)
                        .arg("-f")
                        .arg(&args.file)
                        .arg(host)
                        .status();
                    match pushed {
                        Ok(status) if status.success() => {}
                        Ok(status) => eprintln!("kprop: propagation to {host} failed ({status})"),
                        Err(e) => eprintln!("kprop: {e} while running {}", me.display()),
                    }
                }
            }
            Ok(status) => eprintln!("kprop: {} dump failed ({status})", kdb.display()),
            Err(e) => eprintln!("kprop: {e} while running {}", kdb.display()),
        }
        std::thread::sleep(Duration::from_secs(secs));
    }
}

/// `port` is a number or the `krb5_prop` service name.
fn port_number(port: &str) -> u16 {
    if port == KPROP_SERVICE {
        return services_port(port).unwrap_or(KPROP_PORT);
    }
    port.parse()
        .ok()
        .or_else(|| services_port(port))
        .unwrap_or_else(|| die(format!("{port}: Servname not supported for ai_socktype")))
}

fn services_port(name: &str) -> Option<u16> {
    let services = std::fs::read_to_string("/etc/services").ok()?;
    services.lines().find_map(|line| {
        let line = line.split('#').next()?;
        let mut words = line.split_whitespace();
        let service = words.next()?;
        let (port, proto) = words.next()?.split_once('/')?;
        let named = service == name || words.any(|alias| alias == name);
        (named && proto == "tcp")
            .then(|| port.parse().ok())
            .flatten()
    })
}

fn krb5_profile() -> Profile {
    let path = std::env::var_os("KRB5_CONFIG")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/etc/krb5.conf"));
    if !path.exists() {
        return Profile::parse("").unwrap_or_else(|e| die(e));
    }
    Profile::load(&path).unwrap_or_else(|e| die(format!("{e} while reading {}", path.display())))
}

fn keytab_path(arg: Option<String>) -> PathBuf {
    let name = arg
        .or_else(|| std::env::var("KRB5_KTNAME").ok())
        .unwrap_or_else(|| DEFAULT_KEYTAB.to_string());
    let path = name
        .strip_prefix("FILE:")
        .or_else(|| name.strip_prefix("WRFILE:"))
        .unwrap_or(&name);
    if name.contains(':')
        && !name.starts_with("FILE:")
        && !name.starts_with("WRFILE:")
        && !name.starts_with('/')
    {
        die(format!(
            "{name}: unsupported keytab type while resolving keytab"
        ));
    }
    PathBuf::from(path)
}

/// `get_tickets`: AS exchange straight to `host/<replica>` with the local
/// host key (`krb5_get_init_creds_keytab` with `in_tkt_service`).
async fn get_tickets(profile: Profile, args: &Args, realm: &str) -> Credential {
    let local = kprop::local_hostname()
        .unwrap_or_else(|e| die(format!("{e} while setting client principal name")));
    let client = kprop::host_service(&local);
    let server = kprop::host_service(&args.replica_host);
    let keytab = FileKeytab::new(keytab_path(args.keytab.clone()));
    let key = key_for_principal(&keytab, &client, realm)
        .unwrap_or_else(|e| die(format!("{e} while getting initial credentials\n")));
    let mut config = AsExchangeConfig::new(client, realm);
    config.server = Some(server);
    let mut exchange = AsExchange::with_key(config, key);
    let transport = LocatedTransport::new(Arc::new(profile), None);
    let mut reply = Vec::new();
    loop {
        let step = exchange
            .step(&reply)
            .unwrap_or_else(|e| die(format!("{e} while getting initial credentials\n")));
        match step {
            StepResult::SendToKdc { data, realm } | StepResult::RetryTcp { data, realm } => {
                reply = transport
                    .send_recv(&realm, &data)
                    .await
                    .unwrap_or_else(|e| die(format!("{e} while getting initial credentials\n")));
            }
            StepResult::Complete => {
                return exchange
                    .credential()
                    .cloned()
                    .unwrap_or_else(|e| die(format!("{e} while getting initial credentials\n")))
            }
        }
    }
}

/// `open_database`: the dump must be no newer than its `.dump_ok` stamp.
fn open_database(path: &Path) -> (std::fs::File, u64) {
    let file = std::fs::File::open(path)
        .unwrap_or_else(|e| die(format!("{e} while trying to open {}", path.display())));
    match file.try_lock_shared() {
        Ok(()) => {}
        Err(std::fs::TryLockError::WouldBlock) => die("database locked"),
        Err(std::fs::TryLockError::Error(e)) => {
            die(format!("{e} while trying to lock '{}'", path.display()))
        }
    }
    let meta = file
        .metadata()
        .unwrap_or_else(|e| die(format!("{e} while trying to stat {}", path.display())));
    let mut ok_name = path.as_os_str().to_owned();
    ok_name.push(".dump_ok");
    let ok_path = PathBuf::from(ok_name);
    let ok_meta = std::fs::metadata(&ok_path)
        .unwrap_or_else(|e| die(format!("{e} while trying to stat {}", ok_path.display())));
    let secs = |m: &std::fs::Metadata| {
        m.modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map_or(0, |d| d.as_secs())
    };
    if secs(&meta) > secs(&ok_meta) {
        die(format!(
            "'{}' more recent than '{}'.",
            path.display(),
            ok_path.display()
        ));
    }
    let size = meta.len();
    (file, size)
}

/// `update_last_prop_file`: `<file>.<host>.last_prop` holding one NUL.
fn update_last_prop_file(host: &str, file: &Path) {
    let mut name = file.as_os_str().to_owned();
    name.push(format!(".{host}.last_prop"));
    let path = PathBuf::from(name);
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    std::os::unix::fs::OpenOptionsExt::mode(&mut opts, 0o600);
    if let Err(e) = opts
        .open(&path)
        .and_then(|mut f| std::io::Write::write_all(&mut f, b"\0"))
    {
        eprintln!(
            "kprop: {e} while creating 'last_prop' file, '{}'",
            path.display()
        );
    }
}

fn report(e: &KpropError, context: &str) -> ! {
    eprintln!("kprop: {e} {context}");
    std::process::exit(1);
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let args = parse_args();
    if let Some(secs) = args.interval {
        propagate_forever(&args, secs);
    }
    let profile = krb5_profile();
    let realm = args
        .realm
        .clone()
        .or_else(|| profile.get_string(&["libdefaults", "default_realm"]))
        .unwrap_or_else(|| die("while getting default realm"));
    let cred = get_tickets(profile, &args, &realm).await;
    let (database, size) = open_database(&args.file);
    let port = port_number(&args.port);
    let mut stream = TcpStream::connect((args.replica_host.as_str(), port))
        .await
        .unwrap_or_else(|e| die(format!("{e} while connecting to server")));
    let local = stream
        .local_addr()
        .unwrap_or_else(|e| die(format!("{e} while getting local socket address")));
    let mut ctx = kprop::new_auth_context(&local, CLOCKSKEW);
    if args.debug {
        eprintln!("kprop: authenticating as {}@{}", cred.client, cred.crealm);
    }
    if let Err(e) = kprop::sendauth(&mut stream, &mut ctx, &cred).await {
        report(&e, "while authenticating to server");
    }
    let parties = ErrorParties {
        realm: &realm,
        server: &cred.server,
        client: Some((&cred.client, &cred.crealm)),
    };
    let mut reader = tokio::fs::File::from_std(database);
    if let Err(e) = kprop::xmit_database(&mut stream, &mut ctx, parties, &mut reader, size).await {
        report(&e, "while sending database");
    }
    update_last_prop_file(&args.replica_host, &args.file);
    println!("Database propagation to {}: SUCCEEDED", args.replica_host);
}
