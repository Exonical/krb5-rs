//! `krb5-rs-kadmind`: MIT `kadmind` serving the kpasswd service
//! (kadmin/server/schpw.c) and, with `iprop_enable`, the iprop RPC program
//! (ipropd_svc.c); `-proponly` serves only iprop (ovsec_kadmd.c). The
//! kadm5 admin RPC program is not served.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;

use krb5_rs::gssapi::krb5::Krb5Acceptor;
use krb5_rs::kdc::kdb::admin::AdminOps;
use krb5_rs::kdc::kdb::kadm5::{self, code, PrincipalEnt, ReadArgs, KADM_PROG, KADM_VERS};
use krb5_rs::kdc::kdb::kpasswd::{process_request, Service, KPASSWD_PORT};
use krb5_rs::kdc::kdb::kprop::ReplayCache;
use krb5_rs::kdc::kdb::mit::ulog::{Last, Ulog, UpdateStatus, XdrReader, XdrWriter};
use krb5_rs::kdc::kdb::mit::{parse_name_with_default, MitEntry};
use krb5_rs::kdc::kdb::read_stash;
use krb5_rs::kdc::kdb::restrictions::AclRestrictions;
use krb5_rs::kdc::{default_realm, RealmConfig};
use krb5_rs::profile::Profile;
use krb5_rs::protocol::ap::{ApError, KeySource};
use krb5_rs::rpc::gss::{GssServer, ServerStep};
use krb5_rs::rpc::{read_record, write_record, AcceptStat, AuthStat, Call, CallError, Reply};
use krb5_rs::types::{EncryptionKey, PrincipalName};
use krb5_rs_kdb_lmdb::LmdbStore;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

const KDC_DIR: &str = "/usr/local/var/krb5kdc";
const IPROP_PROG: u32 = 100_423;
const IPROP_VERS: u32 = 1;
const IPROP_NULL: u32 = 0;
const IPROP_GET_UPDATES: u32 = 1;
const IPROP_FULL_RESYNC: u32 = 2;
const IPROP_FULL_RESYNC_EXT: u32 = 3;

fn die(msg: impl std::fmt::Display) -> ! {
    eprintln!("krb5-rs-kadmind: {msg}");
    std::process::exit(1);
}

fn usage() -> ! {
    eprintln!(
        "Usage: krb5-rs-kadmind [-proponly] [-r realm] [-nofork] [-port port-number] [-P pid_file] [-p path-to-kdb5_util] [-F dump-file] [-K path-to-kprop] [-k kprop-port]"
    );
    std::process::exit(1);
}

fn sibling(name: &str) -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(|dir| dir.join(name)))
        .filter(|p| p.exists())
        .unwrap_or_else(|| PathBuf::from(name))
}

#[derive(Default)]
struct Args {
    realm: Option<String>,
    proponly: bool,
    pid_file: Option<PathBuf>,
    kdb_util: Option<PathBuf>,
    dump_file: Option<PathBuf>,
    kprop: Option<PathBuf>,
    kprop_port: Option<String>,
    port: Option<u16>,
}

/// MIT's `DEFAULT_KADM5_PORT`.
const KADMIND_PORT: u16 = 749;

fn parse_args() -> Args {
    let mut a = Args {
        kprop_port: std::env::var("KPROP_PORT").ok(),
        ..Args::default()
    };
    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        let mut val = || it.next().unwrap_or_else(|| usage());
        match arg.as_str() {
            "-r" => a.realm = Some(val()),
            "-proponly" => a.proponly = true,
            "-nofork" | "-W" => {}
            "-port" => a.port = Some(val().parse().unwrap_or_else(|_| usage())),
            "-P" => a.pid_file = Some(PathBuf::from(val())),
            "-p" => a.kdb_util = Some(PathBuf::from(val())),
            "-F" => a.dump_file = Some(PathBuf::from(val())),
            "-K" => a.kprop = Some(PathBuf::from(val())),
            "-k" => a.kprop_port = Some(val()),
            "-x" => die("database arguments (-x) are not supported"),
            _ => usage(),
        }
    }
    a
}

const ACL_ADD: u32 = 1;
const ACL_DELETE: u32 = 2;
const ACL_MODIFY: u32 = 4;
const ACL_CHANGEPW: u32 = 8;
const ACL_INQUIRE: u32 = 32;
const ACL_EXTRACT: u32 = 64;
const ACL_LIST: u32 = 128;
const ACL_SETKEY: u32 = 256;
const ACL_IPROP: u32 = 512;
const ACL_ALL_MASK: u32 = ACL_ADD
    | ACL_DELETE
    | ACL_MODIFY
    | ACL_CHANGEPW
    | ACL_INQUIRE
    | ACL_LIST
    | ACL_IPROP
    | ACL_SETKEY;

/// `acl_op_table` (`auth_acl.c:71-84`).
const ACL_OPS: [(char, u32); 11] = [
    ('a', ACL_ADD),
    ('d', ACL_DELETE),
    ('m', ACL_MODIFY),
    ('c', ACL_CHANGEPW),
    ('i', ACL_INQUIRE),
    ('l', ACL_LIST),
    ('p', ACL_IPROP),
    ('s', ACL_SETKEY),
    ('x', ACL_ALL_MASK),
    ('*', ACL_ALL_MASK),
    ('e', ACL_EXTRACT),
];

/// One parsed ACL line (`auth_acl.c` `struct acl_entry`).
struct AclEntry {
    client: Option<(PrincipalName, String)>,
    ops: u32,
    target: Option<(PrincipalName, String)>,
    restrictions: Option<AclRestrictions>,
}

/// `get_line` (`auth_acl.c:103-151`): logical lines with `\` continuations,
/// skipping empty and `#` lines.
fn acl_lines(text: &str) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    let mut buf = String::new();
    let mut start = 1;
    let raw: Vec<&str> = text.split_inclusive('\n').collect();
    for (i, line) in raw.iter().enumerate() {
        if buf.is_empty() {
            start = i + 1;
        }
        let Some(body) = line.strip_suffix('\n') else {
            buf.push_str(line);
            break;
        };
        buf.push_str(body);
        if buf.ends_with('\\') {
            buf.pop();
        } else if buf.is_empty() || buf.starts_with('#') {
            buf.clear();
        } else {
            out.push((start, std::mem::take(&mut buf)));
        }
    }
    if !buf.is_empty() && !buf.starts_with('#') {
        out.push((start, buf));
    }
    out
}

/// `parse_line` and `parse_entry` (`auth_acl.c:261-372`): client,
/// operations, optional target, and the rest of the line as restrictions.
fn parse_acl_line(line: &str, realm: &str) -> Option<AclEntry> {
    let ws = |c: char| matches!(c, '\t' | '\n' | '\x0c' | '\x0b' | '\r' | ' ' | ',');
    let line = line.trim_end_matches(|c: char| c.is_ascii_whitespace() || c == '\x0b');
    fn field(s: &str) -> (&str, &str) {
        let ws = |c: char| matches!(c, '\t' | '\n' | '\x0c' | '\x0b' | '\r' | ' ' | ',');
        let s = s.trim_start_matches(ws);
        let end = s.find(ws).unwrap_or(s.len());
        (&s[..end], &s[end..])
    }
    let (client, rest) = field(line);
    let (op_str, rest) = field(rest);
    let (target, rest) = field(rest);
    let rs = rest.trim_start_matches(ws);
    if client.is_empty() || op_str.is_empty() {
        return None;
    }
    let target = (!target.is_empty()).then_some(target);
    let mut ops = 0;
    for op in op_str.chars() {
        let lower = op.to_ascii_lowercase();
        let Some((_, mask)) = ACL_OPS.iter().find(|(c, _)| *c == lower) else {
            eprintln!("krb5-rs-kadmind: Unrecognized ACL operation '{op}' in {line}");
            return None;
        };
        if lower == op {
            ops |= mask;
        } else {
            ops &= !mask;
        }
    }
    let parse = |name: &str, what: &str| match parse_name_with_default(name, realm) {
        Ok(p) => Some(p),
        Err(_) => {
            eprintln!("krb5-rs-kadmind: Cannot parse {what} principal '{name}'");
            None
        }
    };
    let client = match client {
        "*" => None,
        c => Some(parse(c, "client")?),
    };
    let target = match target {
        None | Some("*") => None,
        Some(t) => Some(parse(t, "target")?),
    };
    let restrictions = match rs {
        "" => None,
        rs => Some(AclRestrictions::parse(rs).or_else(|| {
            eprintln!("krb5-rs-kadmind: invalid restrictions: {rs}");
            None
        })?),
    };
    Some(AclEntry {
        client,
        ops,
        target,
        restrictions,
    })
}

fn load_acl(path: &Path, realm: &str) -> Result<Vec<AclEntry>, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("{e} while opening ACL file {}", path.display()))?;
    acl_lines(&text)
        .into_iter()
        .map(|(n, line)| {
            parse_acl_line(&line, realm).ok_or_else(|| {
                let head: String = line.chars().take(10).collect();
                format!("{}: syntax error at line {n} <{head}...>", path.display())
            })
        })
        .collect()
}

/// `match_data` (`auth_acl.c:439-466`): a client `*` records a
/// back-reference; a target `*1`..`*9` must equal the recorded component.
fn match_data(pattern: &[u8], value: &[u8], target: bool, ws: Option<&mut Vec<Vec<u8>>>) -> bool {
    if pattern == b"*" {
        if let (Some(ws), false) = (ws, target) {
            if ws.len() < 9 {
                ws.push(value.to_vec());
            }
        }
        return true;
    }
    match (ws, pattern) {
        (Some(ws), [b'*', n @ b'1'..=b'9']) if target => {
            ws.get(usize::from(n - b'1')).is_some_and(|b| b == value)
        }
        _ => pattern == value,
    }
}

/// `match_princ` (`auth_acl.c:468-490`).
fn match_princ(
    pattern: &(PrincipalName, String),
    name: &PrincipalName,
    realm: &str,
    target: bool,
    ws: &mut Vec<Vec<u8>>,
) -> bool {
    pattern.0.name_string.len() == name.name_string.len()
        && match_data(pattern.1.as_bytes(), realm.as_bytes(), target, None)
        && pattern
            .0
            .name_string
            .iter()
            .zip(&name.name_string)
            .all(|(p, n)| match_data(p.as_ref(), n.as_ref(), target, Some(ws)))
}

/// `find_entry` and `acl_check` (`auth_acl.c:492-545`): the first entry
/// matching the client and target decides. `Some` grants `op`, with that
/// entry's restrictions.
fn acl_check<'a>(
    acl: &'a [AclEntry],
    op: u32,
    (client, crealm): (&PrincipalName, &str),
    target: Option<(&PrincipalName, &str)>,
) -> Option<Option<&'a AclRestrictions>> {
    acl.iter()
        .find(|e| {
            let mut ws = Vec::new();
            if let Some(p) = &e.client {
                if !match_princ(p, client, crealm, false, &mut ws) {
                    return false;
                }
            }
            match (&e.target, target) {
                (None, _) => true,
                (Some(_), None) => false,
                (Some(p), Some((t, trealm))) => match_princ(p, t, trealm, true, &mut ws),
            }
        })
        .filter(|e| e.ops & op != 0)
        .map(|e| e.restrictions.as_ref())
}

/// `acl_check(ACL_IPROP)` with no target.
fn acl_permits_iprop(acl: &[AclEntry], client: &PrincipalName, realm: &str) -> bool {
    acl_check(acl, ACL_IPROP, (client, realm), None).is_some()
}

/// Service keys read from the database (MIT's `KDB:` keytab).
struct DbKeys {
    store: Arc<LmdbStore>,
    realm: String,
}

impl KeySource for DbKeys {
    fn get_key(
        &self,
        server: &PrincipalName,
        realm: &[u8],
        kvno: Option<i32>,
        etype: i32,
    ) -> Result<EncryptionKey, ApError> {
        if realm != self.realm.as_bytes() {
            return Err(ApError::NoKey);
        }
        let entry = self
            .store
            .principal_sync(server, &self.realm)
            .map_err(|_| ApError::NoKey)?
            .ok_or(ApError::NoKey)?;
        let kvno = match kvno {
            Some(k) => u32::try_from(k).map_err(|_| ApError::BadKeyver)?,
            None => entry
                .keys
                .iter()
                .map(|k| k.kvno)
                .max()
                .ok_or(ApError::NoKey)?,
        };
        entry
            .keys
            .iter()
            .find(|k| k.kvno == kvno && k.key.keytype == etype)
            .map(|k| k.key.clone())
            .ok_or(if entry.keys.is_empty() {
                ApError::NoKey
            } else {
                ApError::BadKeyver
            })
    }
}

struct State {
    realm: String,
    store: Arc<LmdbStore>,
    ulog: Ulog,
    acl: Arc<Vec<AclEntry>>,
    kdb_util: PathBuf,
    kprop: PathBuf,
    kprop_port: Option<String>,
    dump_file: PathBuf,
}

fn unparse(name: &PrincipalName, realm: &str) -> String {
    String::from_utf8_lossy(&krb5_rs::kdc::kdb::mit::unparse_name(name, realm)).into_owned()
}

impl State {
    /// `iprop_get_updates_1_svc` (`ipropd_svc.c`).
    fn get_updates(&self, client: &PrincipalName, crealm: &str, last: &Last) -> Vec<u8> {
        let mut w = XdrWriter::default();
        if !acl_permits_iprop(&self.acl, client, crealm) {
            eprintln!(
                "krb5-rs-kadmind: Unauthorized request: iprop_get_updates_1, client={}",
                unparse(client, crealm)
            );
            w.last(Last::default());
            w.u32(0);
            w.u32(UpdateStatus::PermDenied as u32);
            return w.0;
        }
        let res = self
            .ulog
            .get_entries(last)
            .and_then(|(status, updates, end)| {
                let mut w = XdrWriter::default();
                w.last(end);
                w.u32(u32::try_from(updates.len()).unwrap_or(u32::MAX));
                for u in &updates {
                    w.update(u)?;
                }
                w.u32(status as u32);
                Ok(w.0)
            });
        res.unwrap_or_else(|e| {
            eprintln!("krb5-rs-kadmind: iprop_get_updates_1: {e}");
            w.last(Last::default());
            w.u32(0);
            w.u32(UpdateStatus::Error as u32);
            w.0
        })
    }

    /// `ipropx_resync` (`ipropd_svc.c`): dump with `kdb5_util dump -i<vers>
    /// -c` and send it to the client's host with `kprop`, in the
    /// background.
    fn full_resync(&self, client: &PrincipalName, crealm: &str, vers: u32) -> Vec<u8> {
        let status = if !acl_permits_iprop(&self.acl, client, crealm) {
            eprintln!(
                "krb5-rs-kadmind: Unauthorized request: iprop_full_resync_1, client={}",
                unparse(client, crealm)
            );
            UpdateStatus::PermDenied
        } else if vers > 1 {
            UpdateStatus::Error
        } else if let [kiprop, host] = client.name_string.as_slice() {
            // Only kiprop/<host> clients may trigger a resync to <host>.
            if kiprop.as_slice() != b"kiprop" {
                return Self::resync_reply(UpdateStatus::PermDenied);
            }
            self.spawn_resync(String::from_utf8_lossy(host.as_ref()).into_owned(), vers);
            UpdateStatus::Ok
        } else {
            UpdateStatus::PermDenied
        };
        Self::resync_reply(status)
    }

    fn resync_reply(status: UpdateStatus) -> Vec<u8> {
        let mut w = XdrWriter::default();
        w.last(Last::default());
        w.u32(status as u32);
        w.0
    }

    fn spawn_resync(&self, host: String, vers: u32) {
        let realm = self.realm.clone();
        let kdb_util = self.kdb_util.clone();
        let kprop = self.kprop.clone();
        let port = self.kprop_port.clone();
        let dump = replica_dump_file(&self.dump_file, &host);
        tokio::task::spawn_blocking(move || {
            let flag = if vers == 0 { "-i" } else { "-i1" };
            let dumped = Command::new(&kdb_util)
                .args(["-r", &realm, "dump", flag, "-c"])
                .arg(&dump)
                .status();
            match dumped {
                Ok(s) if s.success() => {}
                Ok(s) => return eprintln!("krb5-rs-kadmind: full resync dump failed: {s}"),
                Err(e) => return eprintln!("krb5-rs-kadmind: {}: {e}", kdb_util.display()),
            }
            let mut cmd = Command::new(&kprop);
            cmd.args(["-r", &realm, "-f"]).arg(&dump);
            if let Some(port) = &port {
                cmd.args(["-P", port]);
            }
            match cmd.arg(&host).status() {
                Ok(s) if s.success() => eprintln!("krb5-rs-kadmind: full resync sent to {host}"),
                Ok(s) => eprintln!("krb5-rs-kadmind: kprop to {host} failed: {s}"),
                Err(e) => eprintln!("krb5-rs-kadmind: {}: {e}", kprop.display()),
            }
        });
    }

    /// `krb5_iprop_prog_1` and `check_iprop_rpcsec_auth`.
    fn dispatch(
        &self,
        gss: &mut GssServer,
        call: &Call,
        proc_: u32,
        args: &[u8],
        seq: u32,
    ) -> Result<Vec<u8>, String> {
        let xid = call.header.xid;
        let err =
            |gss: &mut GssServer, stat| gss.reply_error(xid, seq, stat).map_err(|e| e.to_string());
        if call.header.prog != IPROP_PROG {
            return err(gss, AcceptStat::ProgUnavail);
        }
        if call.header.vers != IPROP_VERS {
            return err(gss, AcceptStat::ProgMismatch(IPROP_VERS, IPROP_VERS));
        }
        let Some(ctx) = gss.context() else {
            return Ok(Reply::AuthError(AuthStat::BadCred).encode(xid));
        };
        let service = ctx.acceptor();
        if !matches!(service.name_string.as_slice(), [s, _] if s.as_slice() == b"kiprop") {
            eprintln!(
                "krb5-rs-kadmind: Unauthorized request: iprop, service={}",
                unparse(service, &self.realm)
            );
            return Ok(Reply::AuthError(AuthStat::TooWeak).encode(xid));
        }
        let client = ctx.initiator().clone();
        let crealm = ctx.initiator_realm().to_string();
        let results = match proc_ {
            IPROP_NULL => Vec::new(),
            IPROP_GET_UPDATES => {
                let mut r = XdrReader::new(args);
                match r.last() {
                    Ok(last) if r.remaining() == 0 => self.get_updates(&client, &crealm, &last),
                    _ => return err(gss, AcceptStat::GarbageArgs),
                }
            }
            IPROP_FULL_RESYNC if args.is_empty() => self.full_resync(&client, &crealm, 0),
            IPROP_FULL_RESYNC_EXT => {
                let mut r = XdrReader::new(args);
                match r.u32() {
                    Ok(vers) if r.remaining() == 0 => self.full_resync(&client, &crealm, vers),
                    _ => return err(gss, AcceptStat::GarbageArgs),
                }
            }
            IPROP_FULL_RESYNC => return err(gss, AcceptStat::GarbageArgs),
            _ => return err(gss, AcceptStat::ProcUnavail),
        };
        gss.reply(xid, seq, &results).map_err(|e| e.to_string())
    }
}

/// One RPC program served over RPCSEC_GSS on TCP.
trait Program: Send + Sync + 'static {
    fn keys(&self) -> (Arc<LmdbStore>, String);
    fn dispatch(
        &self,
        gss: &mut GssServer,
        call: &Call,
        proc_: u32,
        args: &[u8],
        seq: u32,
        from: &SocketAddr,
    ) -> Result<Vec<u8>, String>;
}

impl Program for State {
    fn keys(&self) -> (Arc<LmdbStore>, String) {
        (self.store.clone(), self.realm.clone())
    }

    fn dispatch(
        &self,
        gss: &mut GssServer,
        call: &Call,
        proc_: u32,
        args: &[u8],
        seq: u32,
        _from: &SocketAddr,
    ) -> Result<Vec<u8>, String> {
        State::dispatch(self, gss, call, proc_, args, seq)
    }
}

/// The kadm5 admin RPC program (`kadm_rpc_svc.c`, `server_stubs.c`).
struct Kadm5 {
    realm: String,
    store: Arc<LmdbStore>,
    acl: Arc<Vec<AclEntry>>,
    keysalts: Vec<(i32, krb5_rs::crypto::SaltType)>,
    history_enctype: i32,
}

/// The authenticated caller of one kadm5 call (`stub_setup`).
struct Caller<'a> {
    client: PrincipalName,
    crealm: String,
    client_name: String,
    service_name: String,
    changepw: bool,
    /// The service ticket was an initial ticket (`ticket_is_initial`).
    initial: bool,
    from: &'a SocketAddr,
}

impl Caller<'_> {
    fn log_unauth(&self, op: &str, target: &str) {
        eprintln!(
            "krb5-rs-kadmind: Unauthorized request: {op}, {target}, client={}, service={}, addr={}",
            self.client_name,
            self.service_name,
            self.from.ip()
        );
    }

    fn log_done(&self, op: &str, target: &str, code: u32) {
        let msg = if code == code::OK {
            "success".to_string()
        } else {
            code::message(code)
        };
        eprintln!(
            "krb5-rs-kadmind: Request: {op}, {target}, {msg}, client={}, service={}, addr={}",
            self.client_name,
            self.service_name,
            self.from.ip()
        );
    }

    fn is(&self, name: &PrincipalName, realm: &str) -> bool {
        self.client == *name && self.crealm == realm
    }
}

impl Kadm5 {
    /// The `acl` kadm5_auth module; callers also apply the `self` module
    /// (`auth_self.c`), which grants reading one's own principal, strings
    /// and policy.
    fn acl(&self, caller: &Caller<'_>, op: u32, target: Option<(&PrincipalName, &str)>) -> bool {
        acl_check(&self.acl, op, (&caller.client, &caller.crealm), target).is_some()
    }

    fn parse(&self, name: &str) -> Option<(PrincipalName, String)> {
        parse_name_with_default(name, &self.realm).ok()
    }

    /// `stub_setup` with a principal: the API version, then the entry
    /// (`KADM5_BAD_PRINCIPAL`, `KADM5_UNK_PRINC`).
    fn setup_princ(
        &self,
        api: u32,
        princ: Option<&str>,
    ) -> Result<(u32, PrincipalName, String, MitEntry), (u32, u32)> {
        let c = kadm5::check_api_version(api);
        if c != code::OK {
            return Err((0, c));
        }
        let (name, realm) = princ
            .and_then(|p| self.parse(p))
            .ok_or((api, code::BAD_PRINCIPAL))?;
        match self.store.raw_entry(&name, &realm) {
            Ok(Some(e)) => Ok((api, name, realm, e)),
            Ok(None) => Err((api, code::UNK_PRINC)),
            Err(e) => {
                eprintln!("krb5-rs-kadmind: reading {}: {e}", unparse(&name, &realm));
                Err((api, code::FAILURE))
            }
        }
    }

    fn min_mkvno(&self) -> u16 {
        self.store
            .master_key_list()
            .ok()
            .and_then(|m| m.keys.iter().map(|k| k.0).min())
            .unwrap_or(1)
    }

    fn get_principal(
        &self,
        caller: &Caller<'_>,
        api: u32,
        princ: Option<&str>,
        mask: i32,
    ) -> Vec<u8> {
        let (api, name, realm, entry) = match self.setup_princ(api, princ) {
            Ok(v) => v,
            Err((api, c)) => return kadm5::gprinc_ret(api, c, None),
        };
        let target = unparse(&name, &realm);
        let op = "kadm5_get_principal";
        let own = caller.is(&name, &realm);
        if (caller.changepw && !own)
            || !(own || self.acl(caller, ACL_INQUIRE, Some((&name, &realm))))
        {
            caller.log_unauth(op, &target);
            return kadm5::gprinc_ret(api, code::AUTH_GET, None);
        }
        let ent = PrincipalEnt::from_entry(&entry, mask, self.min_mkvno());
        let c = if ent.is_ok() { code::OK } else { code::FAILURE };
        caller.log_done(op, &target, c);
        kadm5::gprinc_ret(api, c, ent.ok().as_ref())
    }

    fn get_strings(&self, caller: &Caller<'_>, api: u32, princ: Option<&str>) -> Vec<u8> {
        let (api, name, realm, entry) = match self.setup_princ(api, princ) {
            Ok(v) => v,
            Err((api, c)) => return kadm5::gstrings_ret(api, c, &[]),
        };
        let target = unparse(&name, &realm);
        let op = "kadm5_get_strings";
        let own = caller.is(&name, &realm);
        if caller.changepw || !(own || self.acl(caller, ACL_INQUIRE, Some((&name, &realm)))) {
            caller.log_unauth(op, &target);
            return kadm5::gstrings_ret(api, code::AUTH_GET, &[]);
        }
        let (c, strings) = match krb5_rs::kdc::kdb::mit::string_attributes(&entry) {
            Ok(s) => (code::OK, s),
            Err(_) => (code::FAILURE, Vec::new()),
        };
        caller.log_done(op, &target, c);
        kadm5::gstrings_ret(api, c, &strings)
    }

    /// `get_princs_2_svc` / `get_pols_2_svc`.
    fn list(&self, caller: &Caller<'_>, api: u32, exp: Option<&str>, princs: bool) -> Vec<u8> {
        let c = kadm5::check_api_version(api);
        if c != code::OK {
            return kadm5::names_ret(0, c, &[]);
        }
        let op = if princs {
            "kadm5_get_principals"
        } else {
            "kadm5_get_policies"
        };
        let target = exp.unwrap_or("*");
        if caller.changepw || !self.acl(caller, ACL_LIST, None) {
            caller.log_unauth(op, target);
            return kadm5::names_ret(api, code::AUTH_LIST, &[]);
        }
        let names: Result<Vec<Vec<u8>>, String> = if princs {
            self.store
                .raw_entries()
                .map(|es| {
                    es.iter()
                        .map(|e| krb5_rs::kdc::kdb::mit::unparse_name(&e.principal, &e.realm))
                        .collect()
                })
                .map_err(|e| e.to_string())
        } else {
            self.store
                .policy_names_sync()
                .map(|ns| ns.into_iter().map(String::into_bytes).collect())
                .map_err(|e| e.to_string())
        };
        let (c, names) = match (kadm5::Glob::new(exp, princs), names) {
            (None, _) => (code::EINVAL, Vec::new()),
            (Some(_), Err(e)) => {
                eprintln!("krb5-rs-kadmind: {op}: {e}");
                (code::FAILURE, Vec::new())
            }
            (Some(g), Ok(ns)) => (code::OK, ns.into_iter().filter(|n| g.matches(n)).collect()),
        };
        caller.log_done(op, target, c);
        kadm5::names_ret(api, c, &names)
    }

    fn get_policy(&self, caller: &Caller<'_>, api: u32, name: Option<&str>) -> Vec<u8> {
        let c = kadm5::check_api_version(api);
        if c != code::OK {
            return kadm5::gpol_ret(0, c, None);
        }
        let op = "kadm5_get_policy";
        let target = name.unwrap_or("(null)");
        // The caller's own policy, which kadmin/changepw may read.
        let cpolicy = self
            .store
            .raw_entry(&caller.client, &caller.crealm)
            .ok()
            .flatten()
            .and_then(|e| PrincipalEnt::from_entry(&e, kadm5::mask::PRINCIPAL_NORMAL_MASK, 1).ok())
            .and_then(|e| e.policy);
        let own = matches!((&cpolicy, name), (Some(c), Some(n)) if c.as_slice() == n.as_bytes());
        if (caller.changepw && !own) || !(own || self.acl(caller, ACL_INQUIRE, None)) {
            caller.log_unauth(op, target);
            return kadm5::gpol_ret(api, code::AUTH_GET, None);
        }
        let (c, policy) = match name {
            None => (code::EINVAL, None),
            Some("") => (code::BAD_POLICY, None),
            Some(n) => match self.store.raw_policy(n) {
                Ok(Some(p)) => (code::OK, Some(p)),
                Ok(None) => (code::UNK_POLICY, None),
                Err(e) => {
                    eprintln!("krb5-rs-kadmind: {op}: {e}");
                    (code::FAILURE, None)
                }
            },
        };
        caller.log_done(op, target, c);
        kadm5::gpol_ret(api, c, policy.as_ref())
    }
}

impl Program for Kadm5 {
    fn keys(&self) -> (Arc<LmdbStore>, String) {
        (self.store.clone(), self.realm.clone())
    }

    /// `kadm_1` and `check_rpcsec_auth` (`kadm_rpc_svc.c`).
    fn dispatch(
        &self,
        gss: &mut GssServer,
        call: &Call,
        proc_: u32,
        args: &[u8],
        seq: u32,
        from: &SocketAddr,
    ) -> Result<Vec<u8>, String> {
        let xid = call.header.xid;
        let err =
            |gss: &mut GssServer, stat| gss.reply_error(xid, seq, stat).map_err(|e| e.to_string());
        if call.header.prog != KADM_PROG {
            return err(gss, AcceptStat::ProgUnavail);
        }
        if call.header.vers != KADM_VERS {
            return err(gss, AcceptStat::ProgMismatch(KADM_VERS, KADM_VERS));
        }
        let Some(ctx) = gss.context() else {
            return Ok(Reply::AuthError(AuthStat::BadCred).encode(xid));
        };
        let service = ctx.acceptor().clone();
        let service_name = unparse(&service, &self.realm);
        let ok = matches!(service.name_string.as_slice(),
            [k, h] if k.as_slice() == b"kadmin" && h.as_slice() != b"history");
        if !ok {
            eprintln!("krb5-rs-kadmind: bad service principal {service_name}");
            eprintln!(
                "krb5-rs-kadmind: Authentication attempt failed: {}, RPC authentication flavor 6",
                from.ip()
            );
            return Ok(Reply::AuthError(AuthStat::TooWeak).encode(xid));
        }
        let changepw = matches!(service.name_string.as_slice(),
            [_, h] if h.as_slice() == b"changepw");
        let client = ctx.initiator().clone();
        let crealm = ctx.initiator_realm().to_string();
        let caller = Caller {
            client_name: unparse(&client, &crealm),
            client,
            crealm,
            service_name,
            changepw,
            initial: ctx.initial_ticket(),
            from,
        };
        if proc_ == kadm5::proc_::NULL {
            return gss.reply(xid, seq, &[]).map_err(|e| e.to_string());
        }
        let Some(parsed) = ReadArgs::decode(proc_, args) else {
            eprintln!(
                "krb5-rs-kadmind: Invalid KADM5 procedure number: {}, {proc_}",
                from.ip()
            );
            return err(gss, AcceptStat::ProcUnavail);
        };
        let Ok(parsed) = parsed else {
            return err(gss, AcceptStat::GarbageArgs);
        };
        // xdr_krb5_principal fails on names krb5_parse_name rejects.
        if let ReadArgs::GetPrincipal { princ: Some(p), .. } = &parsed {
            if self.parse(p).is_none() {
                return err(gss, AcceptStat::GarbageArgs);
            }
        }
        if let (kadm5::proc_::GET_STRINGS, ReadArgs::Name { name: Some(p), .. }) = (proc_, &parsed)
        {
            if self.parse(p).is_none() {
                return err(gss, AcceptStat::GarbageArgs);
            }
        }
        let results = match (proc_, parsed) {
            (kadm5::proc_::INIT, ReadArgs::Api(api)) => {
                let c = kadm5::check_api_version(api);
                if c != code::OK {
                    kadm5::generic_ret(0, c)
                } else {
                    eprintln!(
                        "krb5-rs-kadmind: Request: kadm5_init, {0}, success, client={0}, service={1}, addr={2}, vers={3}, flavor=6",
                        caller.client_name,
                        caller.service_name,
                        from.ip(),
                        api & !kadm5::API_VERSION_MASK
                    );
                    kadm5::generic_ret(api, code::OK)
                }
            }
            (kadm5::proc_::GET_PRIVS, ReadArgs::Api(api)) => {
                let c = kadm5::check_api_version(api);
                if c != code::OK {
                    kadm5::getprivs_ret(0, c, 0)
                } else {
                    caller.log_done("kadm5_get_privs", &caller.client_name, code::OK);
                    // kadm5_get_privs (server_misc.c) reports every privilege.
                    kadm5::getprivs_ret(api, code::OK, !0)
                }
            }
            (
                _,
                ReadArgs::GetPrincipal {
                    api_version,
                    princ,
                    mask,
                },
            ) => self.get_principal(&caller, api_version, princ.as_deref(), mask),
            (kadm5::proc_::GET_PRINCS, ReadArgs::Name { api_version, name }) => {
                self.list(&caller, api_version, name.as_deref(), true)
            }
            (kadm5::proc_::GET_POLS, ReadArgs::Name { api_version, name }) => {
                self.list(&caller, api_version, name.as_deref(), false)
            }
            (kadm5::proc_::GET_POLICY, ReadArgs::Name { api_version, name }) => {
                self.get_policy(&caller, api_version, name.as_deref())
            }
            (kadm5::proc_::GET_STRINGS, ReadArgs::Name { api_version, name }) => {
                self.get_strings(&caller, api_version, name.as_deref())
            }
            _ => return err(gss, AcceptStat::GarbageArgs),
        };
        gss.reply(xid, seq, &results).map_err(|e| e.to_string())
    }
}

async fn serve<P: Program>(
    state: Arc<P>,
    mut stream: TcpStream,
    from: SocketAddr,
) -> Result<(), String> {
    let keys = state.keys();
    let mut gss = GssServer::new(Box::new(move || {
        let source = DbKeys {
            store: keys.0.clone(),
            realm: keys.1.clone(),
        };
        Krb5Acceptor::new(Box::new(source), None, None)
    }));
    while let Some(record) = read_record(&mut stream).await.map_err(|e| e.to_string())? {
        let out = match Call::decode(&record) {
            Ok(call) => {
                // Service-key and ulog reads hit LMDB; keep them off the
                // event loop.
                let st = state.clone();
                let (back, out) = tokio::task::spawn_blocking(move || {
                    let out = match gss.handle(&call) {
                        ServerStep::Send(r) => Ok(r),
                        ServerStep::Dispatch { proc_, args, seq } => {
                            st.dispatch(&mut gss, &call, proc_, &args, seq, &from)
                        }
                    };
                    (gss, out)
                })
                .await
                .map_err(|e| e.to_string())?;
                gss = back;
                out?
            }
            Err(CallError::RpcMismatch(xid)) => Reply::RpcMismatch(2, 2).encode(xid),
            Err(CallError::Garbage(e)) => return Err(format!("undecodable call: {e:?}")),
        };
        write_record(&mut stream, &out)
            .await
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}

/// The resync dump file for one replica, so concurrent resyncs to different
/// hosts never share a file: a readable, length-bounded prefix of the host
/// plus a digest of the full name keeps distinct hosts apart.
fn replica_dump_file(base: &std::path::Path, host: &str) -> PathBuf {
    use sha2::{Digest, Sha256};
    let safe: String = host
        .chars()
        .take(64)
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect();
    let tag: String = Sha256::digest(host.as_bytes())[..8]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let mut name = base.as_os_str().to_os_string();
    name.push(format!(".{safe}-{tag}"));
    PathBuf::from(name)
}

/// `iprop_listen`, else the wildcard addresses on `iprop_port`
/// (`loop_add_rpc_service`).
fn listen_addrs(listen: Option<String>, port: u16) -> Vec<SocketAddr> {
    let wild = |p: u16| {
        vec![
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), p),
            SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), p),
        ]
    };
    let Some(listen) = listen else {
        return wild(port);
    };
    let mut out = Vec::new();
    for tok in listen
        .split([',', ';', ' ', '\t'])
        .filter(|t| !t.is_empty())
    {
        if let Ok(p) = tok.parse::<u16>() {
            out.extend(wild(p));
        } else if let Ok(a) = tok.parse::<SocketAddr>() {
            out.push(a);
        } else if let Ok(ip) = tok.trim_matches(['[', ']']).parse::<IpAddr>() {
            out.push(SocketAddr::new(ip, port));
        } else {
            let (host, p) = match tok.rsplit_once(':') {
                Some((h, p)) => (
                    h,
                    p.parse()
                        .unwrap_or_else(|_| die(format!("bad iprop_listen entry {tok}"))),
                ),
                None => (tok, port),
            };
            match (host, p).to_socket_addrs() {
                Ok(addrs) => out.extend(addrs),
                Err(e) => die(format!("{e} while resolving iprop_listen entry {tok}")),
            }
        }
    }
    out
}

#[tokio::main]
async fn main() {
    let args = parse_args();
    let config = std::env::var_os("KRB5_KDC_PROFILE")
        .map(PathBuf::from)
        .unwrap_or_else(|| Path::new(KDC_DIR).join("kdc.conf"));
    let kdc_conf = Profile::load(&config)
        .unwrap_or_else(|e| die(format!("reading {}: {e}", config.display())));
    let krb5 = std::env::var_os("KRB5_CONFIG")
        .map(PathBuf::from)
        .or_else(|| Some(PathBuf::from("/etc/krb5.conf")))
        .filter(|p| p.exists())
        .map(|p| {
            Profile::load(&p).unwrap_or_else(|e| die(format!("reading {}: {e}", p.display())))
        });
    let realm = args
        .realm
        .clone()
        .or_else(|| default_realm(&kdc_conf, krb5.as_ref()))
        .unwrap_or_else(|| die("no realm given and no default realm found"));
    let cfg = RealmConfig::from_profiles(&kdc_conf, krb5.as_ref(), &realm)
        .unwrap_or_else(|e| die(format!("while initializing, {e}")));
    if args.proponly && !cfg.iprop.enabled {
        die("-proponly can only be used when iprop_enable is true");
    }
    let r = |key: &str| kdc_conf.get_string(&["realms", &realm, key]);
    let acl_file =
        r("acl_file").map_or_else(|| Path::new(KDC_DIR).join("kadm5.acl"), PathBuf::from);
    let acl = load_acl(&acl_file, &realm).unwrap_or_else(|e| die(e));
    let acl = Arc::new(acl);
    let iprop_port = cfg.iprop.enabled.then(|| match r("iprop_port") {
        Some(p) => p
            .trim()
            .parse::<u16>()
            .unwrap_or_else(|_| die(format!("invalid iprop_port {p}"))),
        None => die("iprop_port must be set when iprop_enable is true"),
    });
    let master = read_stash(&cfg.key_stash_file, &realm)
        .unwrap_or_else(|e| die(format!("{e} while reading master key")));
    let store = Arc::new(
        LmdbStore::open(&cfg, &master)
            .unwrap_or_else(|e| die(format!("{e} while initializing database"))),
    );

    let mut iprop_listeners = Vec::new();
    if let Some(port) = iprop_port {
        bind_tcp(listen_addrs(r("iprop_listen"), port), &mut iprop_listeners).await;
    }
    let mut kpasswd_udp = Vec::new();
    let mut kpasswd_tcp = Vec::new();
    if !args.proponly {
        let port = r("kpasswd_port").map_or(KPASSWD_PORT, |p| {
            p.trim()
                .parse::<u16>()
                .unwrap_or_else(|_| die(format!("invalid kpasswd_port {p}")))
        });
        let addrs = listen_addrs(r("kpasswd_listen"), port);
        bind_udp(addrs.clone(), &mut kpasswd_udp).await;
        bind_tcp(addrs, &mut kpasswd_tcp).await;
    }
    let mut kadm5_listeners = Vec::new();
    if !args.proponly {
        let port = args.port.unwrap_or_else(|| {
            r("kadmind_port").map_or(KADMIND_PORT, |p| {
                p.trim()
                    .parse::<u16>()
                    .unwrap_or_else(|_| die(format!("invalid kadmind_port {p}")))
            })
        });
        bind_tcp(
            listen_addrs(r("kadmind_listen"), port),
            &mut kadm5_listeners,
        )
        .await;
    }
    if iprop_listeners.is_empty()
        && kpasswd_udp.is_empty()
        && kpasswd_tcp.is_empty()
        && kadm5_listeners.is_empty()
    {
        die("no sockets set up?");
    }
    if let Some(pid_file) = &args.pid_file {
        if let Err(e) = std::fs::write(pid_file, format!("{}\n", std::process::id())) {
            die(format!(
                "{e} while creating PID file {}",
                pid_file.display()
            ));
        }
    }
    let local = tokio::task::LocalSet::new();
    let mut tasks = tokio::task::JoinSet::new();
    if iprop_port.is_some() {
        let state = Arc::new(State {
            realm: realm.clone(),
            store: store.clone(),
            ulog: Ulog::map(&cfg.iprop.logfile, cfg.iprop.ulogsize)
                .unwrap_or_else(|e| die(format!("{e} mapping update log"))),
            acl: acl.clone(),
            kdb_util: args.kdb_util.unwrap_or_else(|| sibling("krb5-rs-kdb")),
            kprop: args.kprop.unwrap_or_else(|| sibling("krb5-rs-kprop")),
            kprop_port: args.kprop_port,
            dump_file: args
                .dump_file
                .unwrap_or_else(|| Path::new(KDC_DIR).join("replica_datatrans")),
        });
        spawn_rpc(&mut tasks, &local, &state, iprop_listeners);
    }
    let kadm5 = Arc::new(Kadm5 {
        realm: realm.clone(),
        store: store.clone(),
        acl: acl.clone(),
        keysalts: cfg.supported_keysalts.clone(),
        history_enctype: cfg.master_key_type,
    });
    spawn_rpc(&mut tasks, &local, &kadm5, kadm5_listeners);
    let kpasswd = Rc::new(Kpasswd {
        keys: DbKeys {
            store: store.clone(),
            realm: realm.clone(),
        },
        admin: AdminOps::new(store, cfg.supported_keysalts.clone())
            .with_history_enctype(cfg.master_key_type),
        realm,
        acl,
        replay: ReplayCache::default(),
        clockskew: cfg.kdc.clockskew,
    });
    for socket in kpasswd_udp {
        tasks.spawn_local_on(serve_kpasswd_udp(kpasswd.clone(), socket), &local);
    }
    for listener in kpasswd_tcp {
        tasks.spawn_local_on(serve_kpasswd_tcp(kpasswd.clone(), listener), &local);
    }
    if args.proponly {
        eprintln!("krb5-rs-kadmind: starting, iprop service only");
    } else {
        eprintln!("krb5-rs-kadmind: starting");
    }
    local
        .run_until(async { while tasks.join_next().await.is_some() {} })
        .await;
}

/// Accept RPC connections for `state` on every listener.
fn spawn_rpc<P: Program>(
    tasks: &mut tokio::task::JoinSet<()>,
    local: &tokio::task::LocalSet,
    state: &Arc<P>,
    listeners: Vec<TcpListener>,
) {
    for listener in listeners {
        let state = state.clone();
        tasks.spawn_local_on(
            async move {
                loop {
                    match listener.accept().await {
                        Ok((stream, from)) => {
                            let state = state.clone();
                            tokio::task::spawn_local(async move {
                                if let Err(e) = serve(state, stream, from).await {
                                    eprintln!("krb5-rs-kadmind: {from}: {e}");
                                }
                            });
                        }
                        Err(e) => eprintln!("krb5-rs-kadmind: accept: {e}"),
                    }
                }
            },
            local,
        );
    }
}

/// Bind every address; a failed `[::]` after another socket is only
/// logged (dual-stack hosts), anything else is fatal.
async fn bind_tcp(addrs: Vec<SocketAddr>, out: &mut Vec<TcpListener>) {
    for addr in addrs {
        match TcpListener::bind(addr).await {
            Ok(l) => out.push(l),
            Err(e) if addr.ip().is_unspecified() && addr.is_ipv6() && !out.is_empty() => {
                eprintln!("krb5-rs-kadmind: not listening on {addr}: {e}");
            }
            Err(e) => die(format!("{e} while binding {addr}")),
        }
    }
}

async fn bind_udp(addrs: Vec<SocketAddr>, out: &mut Vec<UdpSocket>) {
    for addr in addrs {
        match UdpSocket::bind(addr).await {
            Ok(l) => out.push(l),
            Err(e) if addr.ip().is_unspecified() && addr.is_ipv6() && !out.is_empty() => {
                eprintln!("krb5-rs-kadmind: not listening on {addr}: {e}");
            }
            Err(e) => die(format!("{e} while binding {addr}")),
        }
    }
}

/// The kpasswd service (`schpw.c` `dispatch`).
struct Kpasswd {
    realm: String,
    admin: AdminOps<Arc<LmdbStore>>,
    keys: DbKeys,
    acl: Arc<Vec<AclEntry>>,
    replay: ReplayCache,
    clockskew: Duration,
}

impl Kpasswd {
    async fn handle(&self, local: &SocketAddr, remote: &SocketAddr, req: &[u8]) -> Option<Vec<u8>> {
        let authorize = |c: &PrincipalName, cr: &str, t: &PrincipalName, tr: &str| {
            acl_check(&self.acl, ACL_CHANGEPW, (c, cr), Some((t, tr))).is_some()
        };
        let svc = Service {
            realm: &self.realm,
            keys: &self.keys,
            replay: Some(&self.replay),
            clockskew: self.clockskew,
            authorize: &authorize,
        };
        let done = process_request(&self.admin, &svc, local, remote, req).await;
        eprintln!("krb5-rs-kadmind: {}", done.log);
        done.reply
    }
}

/// `MAX_DGRAM_SIZE` (`net-server.c`).
const MAX_DGRAM_SIZE: usize = 65536;

async fn serve_kpasswd_udp(kpasswd: Rc<Kpasswd>, socket: UdpSocket) {
    let socket = Rc::new(socket);
    let Ok(local) = socket.local_addr() else {
        return;
    };
    loop {
        let mut buf = vec![0u8; MAX_DGRAM_SIZE];
        let (n, from) = match socket.recv_from(&mut buf).await {
            Ok(r) => r,
            Err(e) => {
                eprintln!("krb5-rs-kadmind: kpasswd recvfrom: {e}");
                continue;
            }
        };
        buf.truncate(n);
        let (kpasswd, socket) = (kpasswd.clone(), socket.clone());
        tokio::task::spawn_local(async move {
            if let Some(reply) = kpasswd.handle(&local, &from, &buf).await {
                if let Err(e) = socket.send_to(&reply, from).await {
                    eprintln!("krb5-rs-kadmind: kpasswd sendto {from}: {e}");
                }
            }
        });
    }
}

async fn serve_kpasswd_tcp(kpasswd: Rc<Kpasswd>, listener: TcpListener) {
    loop {
        let (mut stream, from) = match listener.accept().await {
            Ok(r) => r,
            Err(e) => {
                eprintln!("krb5-rs-kadmind: accept: {e}");
                continue;
            }
        };
        let kpasswd = kpasswd.clone();
        tokio::task::spawn_local(async move {
            let Ok(local) = stream.local_addr() else {
                return;
            };
            let mut len = [0u8; 4];
            if stream.read_exact(&mut len).await.is_err() {
                return;
            }
            let len = u32::from_be_bytes(len) as usize;
            if len > MAX_DGRAM_SIZE {
                return;
            }
            let mut req = vec![0u8; len];
            if stream.read_exact(&mut req).await.is_err() {
                return;
            }
            if let Some(reply) = kpasswd.handle(&local, &from, &req).await {
                let mut out = u32::try_from(reply.len())
                    .unwrap_or(u32::MAX)
                    .to_be_bytes()
                    .to_vec();
                out.extend_from_slice(&reply);
                if stream.write_all(&out).await.is_ok() {
                    let _ = stream.shutdown().await;
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn princ(s: &str) -> (PrincipalName, String) {
        parse_name_with_default(s, "R").expect("name")
    }

    fn permits(acl: &str, client: &str) -> bool {
        let entries: Vec<AclEntry> = acl_lines(acl)
            .iter()
            .map(|(_, l)| parse_acl_line(l, "R").expect("line"))
            .collect();
        let (name, realm) = princ(client);
        acl_permits_iprop(&entries, &name, &realm)
    }

    #[test]
    fn each_replica_gets_its_own_resync_dump_file() {
        let base = std::path::Path::new("/var/krb5kdc/replica_datatrans");
        let a = replica_dump_file(base, "replica-1.example.com");
        let a = a.to_str().unwrap();
        assert!(a.starts_with("/var/krb5kdc/replica_datatrans.replica-1.example.com-"));
        assert_eq!(
            a,
            replica_dump_file(base, "replica-1.example.com")
                .to_str()
                .unwrap()
        );
        assert_ne!(
            replica_dump_file(base, "node_a"),
            replica_dump_file(base, "node+a")
        );
        let evil = replica_dump_file(base, "../evil/x");
        assert_eq!(evil.parent(), base.parent());
        let long = "a".repeat(230);
        let name = replica_dump_file(base, &long);
        let file = name.file_name().unwrap().len();
        assert!(file + ".dump_ok".len() + 16 < 255, "{file}");
        assert_ne!(name, replica_dump_file(base, &"a".repeat(231)));
    }

    #[test]
    fn iprop_acl_matches_like_mit() {
        assert!(permits("kiprop/*@R p\n", "kiprop/replica@R"));
        assert!(!permits("kiprop/*@R p\n", "kiprop/a/b@R"));
        assert!(!permits("kiprop/*@R p\n", "kiprop/replica@OTHER"));
        assert!(permits("*/*@* x\n", "kiprop/replica@OTHER"));
        assert!(!permits("kiprop/replica@R admcils\n", "kiprop/replica@R"));
        assert!(!permits("kiprop/replica@R xP\n", "kiprop/replica@R"));
        assert!(permits("kiprop/replica@R Pp\n", "kiprop/replica@R"));
        assert!(!permits(
            "kiprop/replica@R i\nkiprop/*@R p\n",
            "kiprop/replica@R"
        ));
        assert!(permits(
            "kiprop/replica@R p host/x@R\n* p\n",
            "kiprop/replica@R"
        ));
        assert!(permits(
            "# c\n\nkiprop/replica@R \\\n p\n",
            "kiprop/replica@R"
        ));
        assert!(permits("kiprop/replica,p", "kiprop/replica@R"));
    }

    fn permits_cpw(acl: &str, client: &str, target: &str) -> bool {
        let entries: Vec<AclEntry> = acl_lines(acl)
            .iter()
            .map(|(_, l)| parse_acl_line(l, "R").expect("line"))
            .collect();
        let (c, cr) = princ(client);
        let (t, tr) = princ(target);
        acl_check(&entries, ACL_CHANGEPW, (&c, &cr), Some((&t, &tr))).is_some()
    }

    #[test]
    fn changepw_acl_matches_like_mit() {
        assert!(permits_cpw("admin@R c\n", "admin@R", "alice@R"));
        assert!(permits_cpw("admin@R x\n", "admin@R", "alice@R"));
        assert!(!permits_cpw("admin@R xC\n", "admin@R", "alice@R"));
        assert!(!permits_cpw("admin@R e\n", "admin@R", "alice@R"));
        assert!(permits_cpw("admin@R c alice@R\n", "admin@R", "alice@R"));
        assert!(!permits_cpw("admin@R c alice@R\n", "admin@R", "bob@R"));
        assert!(!permits_cpw("admin@R i\nadmin@R c\n", "admin@R", "alice@R"));
        assert!(permits_cpw(
            "admin@R c alice@R\nadmin@R c\n",
            "admin@R",
            "bob@R"
        ));
        assert!(permits_cpw(
            "*/admin@R c *1@R\n",
            "alice/admin@R",
            "alice@R"
        ));
        assert!(!permits_cpw("*/admin@R c *1@R\n", "alice/admin@R", "bob@R"));
        assert!(!permits_cpw(
            "*/admin@R c *2@R\n",
            "alice/admin@R",
            "alice@R"
        ));
        assert!(permits_cpw("*/*@R c *2/*1@R\n", "a/b@R", "b/a@R"));
        assert!(permits_cpw(
            "admin@R c */root@*\n",
            "admin@R",
            "x/root@OTHER"
        ));
        assert!(!permits_cpw(
            "admin@R c */root@R\n",
            "admin@R",
            "x/y/root@R"
        ));
        assert!(!permits("admin@R c alice@R\n", "admin@R"));
    }

    #[test]
    fn iprop_listen_uses_mit_delimiters() {
        let addrs = listen_addrs(Some("127.0.0.1:1;127.0.0.2,127.0.0.3 2".into()), 9);
        let got: Vec<String> = addrs.iter().map(ToString::to_string).collect();
        assert_eq!(
            got,
            [
                "127.0.0.1:1",
                "127.0.0.2:9",
                "127.0.0.3:9",
                "0.0.0.0:2",
                "[::]:2"
            ]
        );
        assert!(listen_addrs(Some(String::new()), 9).is_empty());
    }

    #[test]
    fn bad_acl_lines_are_syntax_errors() {
        assert!(parse_acl_line("kiprop/replica@R q", "R").is_none());
        assert!(parse_acl_line("kiprop/replica@R", "R").is_none());
        assert!(parse_acl_line("a@R c b@R@", "R").is_none());
        let e = parse_acl_line(
            "admin@R ac *@R -policy std,+requires_preauth\t-maxlife 1h ",
            "R",
        )
        .expect("line");
        let rs = e.restrictions.as_ref().expect("restrictions");
        assert_eq!(rs.policy.as_deref(), Some("std"));
        assert_eq!(rs.max_life, 3_600);
        assert!(parse_acl_line("admin@R c * +new_princ -md5", "R")
            .expect("line")
            .restrictions
            .is_some());
        assert!(parse_acl_line("admin@R a * -policy", "R").is_none());
        assert!(parse_acl_line("admin@R a * -frobnicate 1h", "R").is_none());
        assert!(parse_acl_line("admin@R a *", "R")
            .expect("line")
            .restrictions
            .is_none());
        assert_eq!(acl_lines("a p\\\n b\n# x\n  \nc d").len(), 3);
    }
}
