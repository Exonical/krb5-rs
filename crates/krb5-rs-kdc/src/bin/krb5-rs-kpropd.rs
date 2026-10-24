//! `krb5-rs-kpropd`: receive full database propagations from kprop, as MIT
//! krb5 1.22.2 `kpropd` (src/kprop/kpropd.c) does without iprop.

use std::io::Write as _;
use std::net::SocketAddr;
use std::os::fd::AsFd;
use std::os::unix::fs::{FileTypeExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use krb5_rs::kdc::kdb::kprop::{self, ErrorParties, ReplayCache, KPROP_PORT, KPROP_SERVICE};
use krb5_rs::keytab::FileKeytab;
use krb5_rs::profile::Profile;
use krb5_rs::types::PrincipalName;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};

const KDC_DIR: &str = "/usr/local/var/krb5kdc";
const DEFAULT_KEYTAB: &str = "/etc/krb5.keytab";
const CLOCKSKEW: Duration = Duration::from_secs(300);

struct Args {
    file: PathBuf,
    database: Option<String>,
    kdb_util: PathBuf,
    port: String,
    realm: Option<String>,
    keytab: Option<String>,
    acl: PathBuf,
    nodaemon: bool,
    debug: bool,
    runonce: bool,
    pid_file: Option<PathBuf>,
}

struct Server {
    args: Args,
    realm: String,
    server: PrincipalName,
    keytab: FileKeytab,
    replay: ReplayCache,
    temp: PathBuf,
}

fn usage() -> ! {
    eprintln!(
        "\nUsage: kpropd [-r realm] [-s keytab] [-d] [-D] [-S]\n\
         \t[-F kerberos_db_file ] [-p kdb5_util_pathname]\n\
         \t[-x db_args]* [-P port] [-a acl_file]\n\
         \t[-A admin_server] [--pid-file=pid_file]\n"
    );
    std::process::exit(1);
}

fn die(msg: impl std::fmt::Display) -> ! {
    eprintln!("kpropd: {msg}");
    std::process::exit(1);
}

fn default_kdb_util() -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(|dir| dir.join("krb5-rs-kdb")))
        .filter(|p| p.exists())
        .unwrap_or_else(|| PathBuf::from("krb5-rs-kdb"))
}

fn parse_args() -> Args {
    let mut args = Args {
        file: PathBuf::from(format!("{KDC_DIR}/from_master")),
        database: None,
        kdb_util: default_kdb_util(),
        port: KPROP_SERVICE.to_string(),
        realm: None,
        keytab: None,
        acl: PathBuf::from(format!("{KDC_DIR}/kpropd.acl")),
        nodaemon: false,
        debug: false,
        runonce: false,
        pid_file: None,
    };
    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        if let Some(long) = arg.strip_prefix("--") {
            match long.split_once('=') {
                Some(("pid-file", v)) => args.pid_file = Some(PathBuf::from(v)),
                None if long == "pid-file" => {
                    args.pid_file = Some(PathBuf::from(it.next().unwrap_or_else(|| usage())));
                }
                _ => usage(),
            }
            continue;
        }
        let Some(flags) = arg.strip_prefix('-').filter(|f| !f.is_empty()) else {
            usage()
        };
        for (i, c) in flags.char_indices() {
            match c {
                'D' => args.nodaemon = true,
                'd' => args.debug = true,
                // Standalone mode is auto-detected, as in MIT.
                'S' => {}
                't' => args.runonce = true,
                'A' | 'f' | 'F' | 'p' | 'P' | 'r' | 's' | 'a' | 'x' => {
                    let rest = &flags[i + 1..];
                    let value = if rest.is_empty() {
                        it.next().unwrap_or_else(|| usage())
                    } else {
                        rest.to_string()
                    };
                    match c {
                        'f' => args.file = PathBuf::from(value),
                        'F' => args.database = Some(value),
                        'p' => args.kdb_util = PathBuf::from(value),
                        'P' => args.port = value,
                        'r' => args.realm = Some(value),
                        's' => args.keytab = Some(value),
                        'a' => args.acl = PathBuf::from(value),
                        // -A (admin server) and -x (db_args) only affect
                        // iprop, which krb5-rs does not implement.
                        _ => {}
                    }
                    break;
                }
                _ => usage(),
            }
        }
    }
    args
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

fn keytab_path(arg: Option<&str>) -> PathBuf {
    let name = arg
        .map(str::to_string)
        .or_else(|| std::env::var("KRB5_KTNAME").ok())
        .unwrap_or_else(|| DEFAULT_KEYTAB.to_string());
    let path = name
        .strip_prefix("FILE:")
        .or_else(|| name.strip_prefix("WRFILE:"))
        .unwrap_or(&name);
    PathBuf::from(path)
}

fn port_number(port: &str) -> u16 {
    if port == KPROP_SERVICE {
        return KPROP_PORT;
    }
    port.parse()
        .unwrap_or_else(|_| die(format!("getaddrinfo: {port}: Servname not supported")))
}

fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(suffix);
    PathBuf::from(name)
}

fn write_pid_file(path: &Path) {
    let pid = std::process::id();
    if let Err(e) = std::fs::File::create(path).and_then(|mut f| writeln!(f, "{pid}")) {
        die(format!("Could not write pid file {}: {e}", path.display()));
    }
}

/// `true` when started by inetd: stdin is a socket.
fn stdin_socket() -> Option<std::net::TcpStream> {
    let fd = std::io::stdin().as_fd().try_clone_to_owned().ok()?;
    let file = std::fs::File::from(fd);
    if !file.metadata().ok()?.file_type().is_socket() {
        return None;
    }
    Some(std::net::TcpStream::from(std::os::fd::OwnedFd::from(file)))
}

impl Server {
    fn debug(&self, msg: impl std::fmt::Display) {
        if self.args.debug {
            eprintln!("{msg}");
        }
    }

    /// `load_database`: `kdb5_util [-r realm] load [-d db] file`.
    fn load_database(&self) -> Result<(), String> {
        let kdb = &self.args.kdb_util;
        self.debug("calling kdb5_util to load database");
        let mut cmd = Command::new(kdb);
        cmd.arg("-r").arg(&self.realm).arg("load");
        if let Some(db) = &self.args.database {
            cmd.arg("-d").arg(db);
        }
        cmd.arg(&self.args.file);
        let status = cmd
            .status()
            .map_err(|e| format!("{e} while trying to exec {}", kdb.display()))?;
        match status.code() {
            Some(0) => Ok(()),
            Some(code) => Err(format!(
                "{} returned a bad exit status ({code})",
                kdb.display()
            )),
            None => Err(format!("{} load terminated", kdb.display())),
        }
    }

    /// `doit`: authenticate, check the ACL, receive into `<file>.temp`,
    /// rename it over `<file>`, load it, then acknowledge.
    async fn doit(&self, mut stream: TcpStream, from: SocketAddr) -> Result<(), String> {
        self.debug(format!("Connection from {}", from.ip()));
        let mut ctx = kprop::new_auth_context(&from, CLOCKSKEW);
        self.debug(format!(
            "krb5_recvauth({}, {}, {}, ...)",
            from,
            kprop::KPROP_PROT_VERSION,
            self.server
        ));
        let auth = kprop::recvauth(
            &mut stream,
            &mut ctx,
            &self.server,
            &self.realm,
            &self.keytab,
            Some(&self.replay),
        )
        .await
        .map_err(|e| format!("Error in krb5_recvauth: {e}"))?;
        let name = auth.principal();
        self.debug(format!(
            "authenticated client: {name} (etype == {})",
            krb5_rs::crypto::enctype_name(auth.etype)
                .map_or_else(|| auth.etype.to_string(), str::to_string)
        ));
        let acl = std::fs::read_to_string(&self.args.acl).unwrap_or_default();
        if !kprop::authorized_principal(&acl, &name, auth.etype) {
            return Err(format!(
                "Rejected connection from unauthorized principal {name}"
            ));
        }
        let lock = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(&self.temp)
            .map_err(|e| format!("{e} while trying to lock '{}'", self.temp.display()))?;
        lock.try_lock()
            .map_err(|e| format!("{e} while trying to lock '{}'", self.temp.display()))?;
        let out = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&self.temp)
            .map_err(|e| format!("{e} while opening database file, '{}'", self.temp.display()))?;
        let mut out = tokio::fs::File::from_std(out);
        let parties = ErrorParties {
            realm: &self.realm,
            server: &self.server,
            client: Some((&auth.client, &auth.crealm)),
        };
        let (size, ack) = kprop::recv_database(&mut stream, &mut ctx, parties, &mut out)
            .await
            .map_err(|e| e.to_string())?;
        out.sync_all()
            .await
            .map_err(|e| format!("{e} while writing database file"))?;
        drop(out);
        self.debug(format!(
            "Full propagation transfer finished ({size} bytes)."
        ));
        std::fs::rename(&self.temp, &self.args.file).map_err(|e| {
            format!(
                "{e} while renaming {} to {}",
                self.temp.display(),
                self.args.file.display()
            )
        })?;
        lock.lock_shared()
            .map_err(|e| format!("{e} while downgrading lock on '{}'", self.temp.display()))?;
        self.load_database()?;
        lock.unlock()
            .map_err(|e| format!("{e} while unlocking '{}'", self.temp.display()))?;
        drop(lock);
        kprop::write_message(&mut stream, &ack)
            .await
            .map_err(|e| format!("{e} while sending # of received bytes"))?;
        stream
            .shutdown()
            .await
            .map_err(|e| format!("{e} while trying to close database file"))?;
        Ok(())
    }

    async fn serve_one(&self, stream: TcpStream) {
        let from = match stream.peer_addr() {
            Ok(a) => a,
            Err(e) => {
                eprintln!("kpropd: getpeername: {e}");
                return;
            }
        };
        if let Err(e) = self.doit(stream, from).await {
            eprintln!("kpropd: {e}");
        }
    }

    async fn do_standalone(&self) {
        let port = port_number(&self.args.port);
        let listener = match TcpListener::bind(("::", port)).await {
            Ok(l) => l,
            Err(_) => TcpListener::bind(("0.0.0.0", port))
                .await
                .unwrap_or_else(|e| die(format!("{e} while binding listener socket"))),
        };
        if let Ok(addr) = listener.local_addr() {
            self.debug(format!("listening on {addr}"));
        }
        if self.args.debug || self.args.nodaemon {
            println!("ready");
            let _ = std::io::stdout().flush();
        }
        loop {
            self.debug("waiting for a kprop connection");
            let stream = match listener.accept().await {
                Ok((s, _)) => s,
                Err(e) => {
                    eprintln!("kpropd: {e} while accepting connection");
                    continue;
                }
            };
            self.serve_one(stream).await;
            self.debug("Database load process for full propagation completed.");
            if self.args.runonce {
                return;
            }
        }
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let args = parse_args();
    let profile = krb5_profile();
    let realm = args
        .realm
        .clone()
        .or_else(|| profile.get_string(&["libdefaults", "default_realm"]))
        .unwrap_or_else(|| die("Unable to get default realm"));
    let host = kprop::local_hostname().unwrap_or_else(|e| {
        die(format!(
            "{e} while trying to construct host service principal"
        ))
    });
    let server = kprop::host_service(&host);
    let keytab = FileKeytab::new(keytab_path(args.keytab.as_deref()));
    let temp = with_suffix(&args.file, ".temp");
    let inetd = stdin_socket();
    let state = Server {
        args,
        realm,
        server,
        keytab,
        replay: ReplayCache::default(),
        temp,
    };
    if let Some(sock) = inetd {
        let sock = sock
            .set_nonblocking(true)
            .and_then(|()| TcpStream::from_std(sock))
            .unwrap_or_else(|e| die(format!("{e} while using the inetd socket")));
        state.serve_one(sock).await;
        return;
    }
    if let Some(pid_file) = &state.args.pid_file {
        write_pid_file(pid_file);
    }
    state.do_standalone().await;
}
