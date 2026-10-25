//! `krb5-rs-kpropd`: receive full database propagations from kprop, as MIT
//! krb5 1.22.2 `kpropd` (src/kprop/kpropd.c) does without iprop.

use std::io::Write as _;
use std::net::SocketAddr;
use std::os::fd::AsFd;
use std::os::unix::fs::{FileTypeExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use krb5_rs::gssapi::krb5::{GssFlags, Krb5Initiator};
use krb5_rs::kdc::kdb::kprop::{self, ErrorParties, ReplayCache, KPROP_SERVICE};
use krb5_rs::kdc::kdb::mit::ulog::{Last, Ulog, UpdateStatus, XdrReader, XdrWriter};
use krb5_rs::kdc::kdb::read_stash;
use krb5_rs::kdc::RealmConfig;
use krb5_rs::keytab::{key_for_principal, FileKeytab};
use krb5_rs::profile::Profile;
use krb5_rs::protocol::{AsExchange, AsExchangeConfig, StepResult};
use krb5_rs::rpc::gss::{GssClient, Service};
use krb5_rs::rpc::{AcceptStat, RpcError};
use krb5_rs::transport::{KdcTransport, LocatedTransport};
use krb5_rs::types::PrincipalName;
use krb5_rs_kdb_lmdb::LmdbStore;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};

const KDC_DIR: &str = "/usr/local/var/krb5kdc";
const DEFAULT_KEYTAB: &str = "/etc/krb5.keytab";
const CLOCKSKEW: Duration = Duration::from_secs(300);
const IPROP_PROG: u32 = 100_423;
const IPROP_VERS: u32 = 1;
const IPROP_GET_UPDATES: u32 = 1;
const IPROP_FULL_RESYNC: u32 = 2;
const IPROP_FULL_RESYNC_EXT: u32 = 3;
/// `MAX_BACKOFF` (`include/iprop_hdr.h:30`).
const MAX_BACKOFF: u32 = 300;

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
    admin_server: Option<String>,
}

struct Server {
    args: Args,
    realm: String,
    server: PrincipalName,
    /// Every canonical name of our host principal (`k5_sname_compare`).
    servers: Vec<PrincipalName>,
    keytab: FileKeytab,
    replay: ReplayCache,
    temp: PathBuf,
    iprop: Option<Iprop>,
    loaded: tokio::sync::Notify,
}

/// The iprop parameters of `kadm5_get_config_params` (`alt_prof.c`) that
/// `do_iprop` uses.
struct Iprop {
    cfg: RealmConfig,
    profile: Arc<Profile>,
    primary: String,
    port: u16,
    poll: Duration,
    resync_timeout: Duration,
    /// `kiprop/<host>` for each name `k5_canonprinc` tries.
    clients: Vec<PrincipalName>,
    service: PrincipalName,
}

/// `backoff_from_primary` (`kpropd.c:1005-1018`).
fn backoff_from_primary(cnt: &mut u32) -> Duration {
    let mut btime = 2u32.checked_shl(*cnt).unwrap_or(u32::MAX);
    if btime > MAX_BACKOFF {
        btime = MAX_BACKOFF;
        *cnt = cnt.saturating_sub(1);
    }
    Duration::from_secs(btime.into())
}

fn decode_err(e: impl std::fmt::Display) -> String {
    format!("RPC: Can't decode result ({e})")
}

/// `kdb_incr_result_t`: the last entry, the updates and the status.
fn decode_incr(
    res: &[u8],
) -> Result<
    (
        Last,
        Vec<krb5_rs::kdc::kdb::mit::ulog::Update>,
        Option<UpdateStatus>,
    ),
    String,
> {
    let mut r = XdrReader::new(res);
    let last = r.last().map_err(decode_err)?;
    let count = r.u32().map_err(decode_err)?;
    let updates = (0..count)
        .map(|_| r.update())
        .collect::<Result<Vec<_>, _>>()
        .map_err(decode_err)?;
    let status = r.u32().map_err(decode_err)?;
    Ok((last, updates, UpdateStatus::from_u32(status)))
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
        admin_server: None,
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
                        'A' => args.admin_server = Some(value),
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
    kprop::service_port(port)
        .unwrap_or_else(|| die(format!("getaddrinfo: {port}: Servname not supported")))
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
        if self.iprop.is_some() {
            cmd.arg("-i");
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
            &self.servers,
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
            self.loaded.notify_one();
            if self.args.runonce {
                return;
            }
        }
    }
}

impl Server {
    /// `kadm5_init_with_skey` as `kiprop/<host>` to `kiprop/<admin_server>`,
    /// over RPCSEC_GSS with privacy.
    async fn iprop_connect(&self, ip: &Iprop) -> Result<GssClient<TcpStream>, String> {
        let creds = |e: &dyn std::fmt::Display| format!("{e} while getting initial credentials");
        let mut err = None;
        let (client, key) = ip
            .clients
            .iter()
            .find_map(|c| match key_for_principal(&self.keytab, c, &self.realm) {
                Ok(k) => Some((c.clone(), k)),
                Err(e) => {
                    err.get_or_insert_with(|| e.to_string());
                    None
                }
            })
            .ok_or_else(|| creds(&err.unwrap_or_default()))?;
        let mut config = AsExchangeConfig::new(client, &self.realm);
        config.server = Some(ip.service.clone());
        let mut exchange = AsExchange::with_key(config, key);
        let transport = LocatedTransport::new(ip.profile.clone(), None);
        let mut reply = Vec::new();
        let cred = loop {
            match exchange.step(&reply).map_err(|e| creds(&e))? {
                StepResult::SendToKdc { data, realm } | StepResult::RetryTcp { data, realm } => {
                    reply = transport
                        .send_recv(&realm, &data)
                        .await
                        .map_err(|e| creds(&e))?;
                }
                StepResult::Complete => {
                    break exchange.credential().cloned().map_err(|e| creds(&e))?
                }
            }
        };
        let stream = TcpStream::connect((ip.primary.as_str(), ip.port))
            .await
            .map_err(|e| format!("RPC: {e}"))?;
        let init = Krb5Initiator::new(cred, None, GssFlags::MUTUAL | GssFlags::REPLAY, None)
            .map_err(|e| e.to_string())?;
        let xid = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.subsec_nanos())
            ^ std::process::id();
        GssClient::connect(stream, IPROP_PROG, IPROP_VERS, xid, init, Service::Privacy)
            .await
            .map_err(|e| e.to_string())
    }

    /// `full_resync` (`kpropd.c:590-626`): `IPROP_FULL_RESYNC_EXT` version 1,
    /// falling back to `IPROP_FULL_RESYNC` for a primary without it.
    async fn full_resync(
        &self,
        clnt: &mut GssClient<TcpStream>,
    ) -> Result<Option<UpdateStatus>, String> {
        let res = match clnt.call(IPROP_FULL_RESYNC_EXT, &1u32.to_be_bytes()).await {
            Err(RpcError::Accept(AcceptStat::ProcUnavail)) => {
                clnt.call(IPROP_FULL_RESYNC, &[]).await
            }
            r => r,
        }
        .map_err(|e| e.to_string())?;
        let mut r = XdrReader::new(&res);
        r.last().map_err(decode_err)?;
        Ok(UpdateStatus::from_u32(r.u32().map_err(decode_err)?))
    }

    /// `do_iprop` (`kpropd.c:628-1002`). Returns `Err` when the primary
    /// denies or fails a request, after which MIT's kpropd exits.
    async fn do_iprop(&self, ip: &Iprop) -> Result<(), String> {
        self.debug("Incremental propagation enabled");
        let master = read_stash(&ip.cfg.key_stash_file, &self.realm)
            .map_err(|e| format!("{e} while reading master key"))?;
        let ulog = Ulog::map(&ip.cfg.iprop.logfile, ip.cfg.iprop.ulogsize)
            .map_err(|e| format!("{e} while mapping log"))?;
        let client = String::from_utf8_lossy(&krb5_rs::kdc::kdb::mit::unparse_name(
            &ip.clients[0],
            &self.realm,
        ))
        .into_owned();
        let (mut backoff_cnt, mut reinit_cnt) = (0u32, 0u32);
        let mut frrequested: Option<Instant> = None;
        'reinit: loop {
            self.debug(format!("Initializing kadm5 as client {client}"));
            let mut clnt = match self.iprop_connect(ip).await {
                Ok(c) => c,
                Err(e) => {
                    self.debug("kadm5 initialization failed!");
                    reinit_cnt += 1;
                    eprintln!(
                        "kpropd: {e} while attempting to connect to primary KDC ... retrying"
                    );
                    let t = backoff_from_primary(&mut reinit_cnt);
                    self.debug(format!(
                        "Sleeping {} seconds to re-initialize kadm5 (RPC ERROR)",
                        t.as_secs()
                    ));
                    tokio::time::sleep(t).await;
                    continue 'reinit;
                }
            };
            reinit_cnt = 0;
            loop {
                let mylast: Last = ulog
                    .get_last()
                    .map_err(|e| format!("{e} reading update log header"))?;
                self.debug(format!(
                    "Calling iprop_get_updates_1 (sno={} sec={} usec={})",
                    mylast.sno, mylast.time.seconds, mylast.time.useconds
                ));
                let start = Instant::now();
                let mut w = XdrWriter::default();
                w.last(mylast);
                let reply = clnt
                    .call(IPROP_GET_UPDATES, &w.0)
                    .await
                    .map_err(|e| e.to_string())
                    .and_then(|r| decode_incr(&r));
                let (lastentry, updates, status) = match reply {
                    Ok(r) => r,
                    Err(e) => {
                        eprintln!("kpropd: iprop_get_updates call failed: {e}");
                        self.debug("Reinitializing iprop because get updates failed");
                        backoff_cnt += 1;
                        tokio::time::sleep(backoff_from_primary(&mut backoff_cnt)).await;
                        continue 'reinit;
                    }
                };
                match status {
                    Some(UpdateStatus::FullResyncNeeded) => {
                        if frrequested.is_some_and(|t| t.elapsed() < ip.resync_timeout) {
                            self.debug("Still waiting for full resync");
                        } else {
                            frrequested = Some(Instant::now());
                            self.debug("Full resync needed");
                            eprintln!("kpropd: Full resync needed.");
                            match self.full_resync(&mut clnt).await {
                                Err(e) => {
                                    eprintln!("kpropd: iprop_full_resync call failed: {e}");
                                    backoff_cnt += 1;
                                    tokio::time::sleep(backoff_from_primary(&mut backoff_cnt))
                                        .await;
                                    continue 'reinit;
                                }
                                Ok(Some(UpdateStatus::Ok)) => {
                                    self.debug("Full resync request granted");
                                    eprintln!("kpropd: Full resync request granted.");
                                    backoff_cnt = 0;
                                }
                                Ok(Some(UpdateStatus::Busy)) => {
                                    self.debug("Exponential backoff");
                                    backoff_cnt += 1;
                                    // Busy: ask again after the backoff, not
                                    // after iprop_resync_timeout.
                                    frrequested = None;
                                }
                                Ok(Some(UpdateStatus::PermDenied)) => {
                                    return Err("Full resync, permission denied.".into())
                                }
                                Ok(Some(UpdateStatus::Error)) => {
                                    return Err(
                                        "Full resync, error returned from primary KDC.".into()
                                    )
                                }
                                Ok(_) => {
                                    backoff_cnt = 0;
                                    eprintln!(
                                        "kpropd: Full resync, invalid return from primary KDC."
                                    );
                                }
                            }
                        }
                    }
                    Some(UpdateStatus::Ok) => {
                        backoff_cnt = 0;
                        frrequested = None;
                        self.debug(format!(
                            "Got incremental updates (sno={} sec={} usec={})",
                            lastentry.sno, lastentry.time.seconds, lastentry.time.useconds
                        ));
                        let replayed = LmdbStore::open(&ip.cfg, &master)
                            .and_then(|store| store.replay_updates(&updates));
                        match replayed {
                            Ok(()) => self.debug(format!(
                                "Incremental updates: {} updates / {} us",
                                updates.len(),
                                start.elapsed().as_micros()
                            )),
                            Err(e) => eprintln!(
                                "kpropd: ulog_replay failed ({e}), updates not registered."
                            ),
                        }
                    }
                    Some(UpdateStatus::PermDenied) => {
                        return Err("get_updates, permission denied.".into())
                    }
                    Some(UpdateStatus::Error) => {
                        return Err("get_updates, error returned from primary KDC.".into())
                    }
                    Some(UpdateStatus::Busy) => {
                        self.debug("get_updates primary busy; backoff");
                        backoff_cnt += 1;
                    }
                    Some(UpdateStatus::Nil) => {
                        self.debug("KDC is synchronized with primary.");
                        backoff_cnt = 0;
                        frrequested = None;
                    }
                    None => {
                        backoff_cnt = 0;
                        eprintln!("kpropd: get_updates, invalid return from primary KDC.");
                    }
                }
                if self.args.runonce && status != Some(UpdateStatus::FullResyncNeeded) {
                    return Ok(());
                }
                let wait = if backoff_cnt > 0 {
                    let t = backoff_from_primary(&mut backoff_cnt);
                    self.debug(format!(
                        "Busy signal received from primary, backoff for {} secs",
                        t.as_secs()
                    ));
                    t
                } else {
                    self.debug(format!(
                        "Waiting for {} seconds before checking for updates again",
                        ip.poll.as_secs()
                    ));
                    ip.poll
                };
                tokio::select! {
                    () = tokio::time::sleep(wait) => {}
                    () = self.loaded.notified() => {}
                }
            }
        }
    }
}

fn kdc_profile() -> Option<Profile> {
    let path = std::env::var_os("KRB5_KDC_PROFILE")
        .map(PathBuf::from)
        .unwrap_or_else(|| Path::new(KDC_DIR).join("kdc.conf"));
    path.exists().then(|| {
        Profile::load(&path)
            .unwrap_or_else(|e| die(format!("{e} while reading {}", path.display())))
    })
}

fn iprop_params(args: &Args, profile: &Profile, realm: &str, hosts: &[String]) -> Option<Iprop> {
    let kdc_conf = kdc_profile()?;
    let mut cfg = RealmConfig::from_profiles(&kdc_conf, Some(profile), realm)
        .unwrap_or_else(|e| die(format!("{e} while initializing")));
    if !cfg.iprop.enabled {
        return None;
    }
    let r = |key: &str| kdc_conf.get_string(&["realms", realm, key]);
    if let Some(db) = &args.database {
        if r("iprop_logfile").is_none() {
            cfg.iprop.logfile = with_suffix(Path::new(db), ".ulog");
        }
        cfg.database_name = PathBuf::from(db);
    }
    let primary = args
        .admin_server
        .clone()
        .or_else(|| profile.get_string(&["realms", realm, "admin_server"]))
        .map(|a| a.split(':').next().unwrap_or_default().to_string())
        .filter(|a| !a.is_empty())
        .unwrap_or_else(|| {
            die(format!(
                "unable to get kiprop host based service name for realm {realm}"
            ))
        });
    let port = r("iprop_port")
        .map(|p| {
            p.trim()
                .parse::<u16>()
                .unwrap_or_else(|_| die(format!("invalid iprop_port {p}")))
        })
        .unwrap_or_else(|| die("iprop_port must be set when iprop_enable is true"));
    let deltat = |key: &str, default: i32| {
        kdc_conf
            .get_deltat(&["realms", realm, key], default)
            .unwrap_or_else(|e| die(format!("{e} while reading {key}")))
    };
    let mut poll = deltat("iprop_replica_poll", -1);
    if poll == -1 {
        poll = deltat("iprop_slave_poll", 2 * 60);
    }
    if poll == 0 {
        poll = 10;
    }
    let secs = |v: i32| Duration::from_secs(u64::try_from(v).unwrap_or(0));
    Some(Iprop {
        cfg,
        profile: Arc::new(profile.clone()),
        service: PrincipalName::new_srv_hst("kiprop", &primary),
        primary,
        port,
        poll: secs(poll),
        resync_timeout: secs(deltat("iprop_resync_timeout", 60 * 5)),
        clients: hosts
            .iter()
            .map(|h| PrincipalName::new_srv_hst("kiprop", h))
            .collect(),
    })
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
    let servers: Vec<PrincipalName> = kprop::HostCanon::from_profile(&profile)
        .candidates(&host)
        .iter()
        .map(|h| kprop::host_service(h))
        .collect();
    let server = servers
        .first()
        .cloned()
        .unwrap_or_else(|| die("no host name"));
    let keytab = FileKeytab::new(keytab_path(args.keytab.as_deref()));
    let temp = with_suffix(&args.file, ".temp");
    let hosts = kprop::HostCanon::from_profile(&profile).candidates(&host);
    let iprop = iprop_params(&args, &profile, &realm, &hosts);
    let inetd = stdin_socket();
    let state = Server {
        args,
        realm,
        server,
        servers,
        keytab,
        replay: ReplayCache::default(),
        temp,
        iprop,
        loaded: tokio::sync::Notify::new(),
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
    let Some(ip) = &state.iprop else {
        state.do_standalone().await;
        return;
    };
    let listen = async {
        state.do_standalone().await;
        std::future::pending::<()>().await;
    };
    tokio::select! {
        r = state.do_iprop(ip) => {
            if let Err(e) = r {
                eprintln!("kpropd: {e}");
                state.debug("ERROR returned by primary, bailing");
                std::process::exit(1);
            }
        }
        () = listen => {}
    }
}
