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
use krb5_rs::kdc::kdb::admin::{AdminOps, AttrChange, PolicyChange, PrincipalOptions};
use krb5_rs::kdc::kdb::kadm5::mask as kmask;
use krb5_rs::kdc::kdb::kadm5::{self, code, PrincipalEnt, ReadArgs, KADM_PROG, KADM_VERS};
use krb5_rs::kdc::kdb::kpasswd::{process_request, Service, KPASSWD_PORT};
use krb5_rs::kdc::kdb::kprop::ReplayCache;
use krb5_rs::kdc::kdb::master::encrypt_key;
use krb5_rs::kdc::kdb::mit::mkey::entry_mkvno;
use krb5_rs::kdc::kdb::mit::ulog::{Last, Ulog, UpdateStatus, XdrReader, XdrWriter};
use krb5_rs::kdc::kdb::mit::{parse_name_with_default, MitEntry};
use krb5_rs::kdc::kdb::mit::{set_mod_princ, set_string_attr, KeyData as MitKeyData, TlData};
use krb5_rs::kdc::kdb::read_stash;
use krb5_rs::kdc::kdb::restrictions::AclRestrictions;
use krb5_rs::kdc::kdb::restrictions::RestrictedEntry;
use krb5_rs::kdc::kerberos_time;
use krb5_rs::kdc::store::{AdminStore, Policy, StoreError, StoreErrorKind};
use krb5_rs::kdc::{default_realm, salt_bytes, PrincipalAttributes, RealmConfig};
use krb5_rs::profile::Profile;
use krb5_rs::protocol::ap::{ApError, KeySource};
use krb5_rs::rpc::gss::{GssServer, ServerStep};
use krb5_rs::rpc::{read_record, write_record, AcceptStat, AuthStat, Call, CallError, Reply};
use krb5_rs::types::{EncryptionKey, PrincipalName};
use krb5_rs_kdb_lmdb::{CallerStore, LmdbStore};
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
    /// Realm `max_life`, `max_renewable_life` and
    /// `default_principal_expiration`, used by create when the mask omits
    /// them (svr_principal.c:410-429).
    max_life: Duration,
    max_rlife: Duration,
    expiration: Option<krb5_rs::types::KerberosTime>,
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

/// The `PrincipalOptions` for a kadm5 principal record and mask, after
/// `impose_restrictions`; also returns the restricted mask.
fn principal_options(
    rec: &kadm5::PrincipalEnt,
    mask: i32,
    restr: Option<&AclRestrictions>,
) -> (PrincipalOptions, u32) {
    use kmask as m;
    let mut ent = RestrictedEntry {
        attributes: rec.attributes,
        policy: rec
            .policy
            .as_deref()
            .map(|p| String::from_utf8_lossy(p).into_owned()),
        princ_expire_time: rec.princ_expire_time as i32,
        pw_expiration: rec.pw_expiration as i32,
        max_life: rec.max_life as i32,
        max_renewable_life: rec.max_renewable_life as i32,
    };
    let mut mask = mask as u32;
    if let Some(r) = restr {
        r.impose(&mut ent, &mut mask, unix_now() as i32);
    }
    let on = |b: i32| mask & b as u32 != 0;
    let time = |t: i32| (t != 0).then(|| kerberos_time(i64::from(t as u32)));
    let life = |t: i32| (t != 0).then(|| Duration::from_secs(u64::from(t as u32)));
    let mut opts = PrincipalOptions::default();
    if on(m::ATTRIBUTES) {
        opts.attributes = AttrChange {
            set: ent.attributes,
            clear: !ent.attributes,
        };
    }
    if on(m::MAX_LIFE) {
        opts.max_life = Some(life(ent.max_life));
    }
    if on(m::MAX_RLIFE) {
        opts.max_renewable_life = Some(life(ent.max_renewable_life));
    }
    if on(m::PRINC_EXPIRE_TIME) {
        opts.expiration = Some(time(ent.princ_expire_time));
    }
    if on(m::PW_EXPIRATION) {
        opts.pw_expiration = Some(time(ent.pw_expiration));
    }
    if on(m::POLICY) {
        opts.policy = Some(ent.policy.clone());
    } else if on(m::POLICY_CLR) {
        opts.policy = Some(None);
    }
    if on(m::FAIL_AUTH_COUNT) {
        opts.unlock = true;
    }
    (opts, mask)
}

/// Normalize the three setkey argument forms to `kadm5_key_data`
/// (`setkey_principal{,3}` in `svr_principal.c` pass kvno 0 and the
/// default or tuple salt type).
fn setkey_data(keys: kadm5::SetKeys) -> Result<Vec<kadm5::KeyData>, u32> {
    let block = |key: kadm5::KeyBlock, salt_type: i16| kadm5::KeyData {
        kvno: 0,
        key,
        salt_type,
        salt: Vec::new(),
    };
    match keys {
        kadm5::SetKeys::V1(blocks) => Ok(blocks.into_iter().map(|b| block(b, 0)).collect()),
        kadm5::SetKeys::V3(ks, blocks) => {
            if ks.len() != blocks.len() || ks.iter().zip(&blocks).any(|(t, b)| t.0 != b.enctype) {
                return Err(code::SETKEY3_ETYPE_MISMATCH);
            }
            ks.iter()
                .zip(blocks)
                .map(|(t, b)| {
                    i16::try_from(t.1)
                        .map(|st| block(b, st))
                        .map_err(|_| code::BAD_KEYSALTS)
                })
                .collect()
        }
        kadm5::SetKeys::V4(data) => Ok(data),
    }
}

/// `KRB5_TL_ALIAS_TARGET` (`kdb.h`).
const ALIAS_TARGET: u16 = 0x000c;

fn tl_bytes(e: &MitEntry, kind: u16) -> Option<&[u8]> {
    e.tl_data
        .iter()
        .find(|t| t.kind == kind)
        .map(|t| t.data.as_slice())
}

/// `krb5_dbe_specialize_salt` (`lib/kdb/kdb5.c:2391-2421`): store every
/// salt explicitly so it survives the rename.
fn specialize_salt(e: &mut MitEntry) {
    use krb5_rs::crypto::SaltType;
    for k in &mut e.key_data {
        let (stype, contents) = k.fields.get(1).cloned().unwrap_or((0, Vec::new()));
        let salt = match (k.ver, stype) {
            (1, _) | (_, 0) => salt_bytes(&e.principal, &e.realm, SaltType::Normal),
            (_, 2) => salt_bytes(&e.principal, &e.realm, SaltType::NoRealm),
            (_, 3) => e.realm.as_bytes().to_vec(),
            _ => contents,
        };
        k.fields.truncate(1);
        k.fields.push((4, salt));
        k.ver = 2;
    }
}

/// `KRB5_KDB_LOCKDOWN_KEYS` (`kdb.h`).
const LOCKDOWN_KEYS: u32 = 0x0080_0000;

fn run<F: std::future::Future>(f: F) -> F::Output {
    // kadm5 calls run on the blocking pool (`serve`).
    tokio::runtime::Handle::current().block_on(f)
}

fn unix_now() -> u32 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u32::try_from(d.as_secs()).unwrap_or(u32::MAX))
}

/// The kadm5 code for a store failure; `unknown` for a missing entry.
fn store_code(e: &StoreError, unknown: u32) -> u32 {
    const REJECTED: [(&str, u32); 4] = [
        ("Password is too short", code::PASS_Q_TOOSHORT),
        (
            "Password does not contain enough character classes",
            code::PASS_Q_CLASS,
        ),
        ("Cannot reuse password", code::PASS_REUSE),
        ("Cannot change protected principal", code::PROTECT_PRINCIPAL),
    ];
    let c = match e.kind() {
        StoreErrorKind::NotFound => unknown,
        StoreErrorKind::Conflict => code::DUP,
        StoreErrorKind::Rejected => REJECTED
            .iter()
            .find(|(t, _)| e.message().contains(t))
            .map_or(code::FAILURE, |(_, c)| *c),
        _ => code::FAILURE,
    };
    if c == code::FAILURE {
        eprintln!("krb5-rs-kadmind: {e}");
    }
    c
}

fn policy_change(rec: &kadm5::PolicyEnt, mask: i32, api: u32) -> PolicyChange {
    let on = |m: i32| mask & m != 0;
    let u = |v: i32| v as u32;
    let v3 = api >= kadm5::API_VERSION_3;
    PolicyChange {
        pw_max_life: on(kmask::PW_MAX_LIFE).then(|| u(rec.pw_max_life)),
        pw_min_life: on(kmask::PW_MIN_LIFE).then(|| u(rec.pw_min_life)),
        pw_min_length: on(kmask::PW_MIN_LENGTH).then(|| u(rec.pw_min_length)),
        pw_min_classes: on(kmask::PW_MIN_CLASSES).then(|| u(rec.pw_min_classes)),
        pw_history_num: on(kmask::PW_HISTORY_NUM).then(|| u(rec.pw_history_num)),
        pw_max_fail: (v3 && on(kmask::PW_MAX_FAILURE)).then_some(rec.pw_max_fail),
        pw_failcnt_interval: (v3 && on(kmask::PW_FAILURE_COUNT_INTERVAL))
            .then(|| u(rec.pw_failcnt_interval)),
        pw_lockout_duration: (v3 && on(kmask::PW_LOCKOUT_DURATION))
            .then(|| u(rec.pw_lockout_duration)),
        allowed_keysalts: (api >= kadm5::API_VERSION_4 && on(kmask::POLICY_ALLOWED_KEYSALTS))
            .then(|| rec.allowed_keysalts.clone()),
    }
}

/// The version 4 policy fields `PolicyChange` does not carry.
fn apply_policy_v4(p: &mut Policy, rec: &kadm5::PolicyEnt, mask: i32, api: u32) {
    if api < kadm5::API_VERSION_4 {
        return;
    }
    if mask & kmask::POLICY_ATTRIBUTES != 0 {
        p.attributes = rec.attributes;
    }
    if mask & kmask::POLICY_MAX_LIFE != 0 {
        p.max_life = rec.max_life as u32;
    }
    if mask & kmask::POLICY_MAX_RLIFE != 0 {
        p.max_renewable_life = rec.max_renewable_life as u32;
    }
}

/// The value checks of `kadm5_create_policy`/`kadm5_modify_policy`
/// (`svr_policy.c`), and `KADM5_BAD_TL_TYPE` for TL data below 256.
fn check_policy(rec: &kadm5::PolicyEnt, mask: i32, max_life: Option<i32>) -> Result<(), u32> {
    let on = |m: i32| mask & m != 0;
    if on(kmask::PW_MIN_LIFE) {
        if let Some(max) = max_life.filter(|&m| m != 0) {
            if rec.pw_min_life > max {
                return Err(code::BAD_MIN_PASS_LIFE);
            }
        }
    }
    if on(kmask::PW_MIN_LENGTH) && rec.pw_min_length < 1 {
        return Err(code::BAD_LENGTH);
    }
    if on(kmask::PW_MIN_CLASSES) && !(1..=5).contains(&rec.pw_min_classes) {
        return Err(code::BAD_CLASS);
    }
    if on(kmask::PW_HISTORY_NUM) && rec.pw_history_num < 1 {
        return Err(code::BAD_HISTORY);
    }
    if on(kmask::POLICY_TL_DATA) && rec.tl_data.iter().any(|t| t.kind < 256) {
        return Err(code::BAD_TL_TYPE);
    }
    Ok(())
}

impl Kadm5 {
    /// Administration as `caller`, who is recorded as the modifier.
    fn admin(&self, caller: &Caller<'_>) -> AdminOps<CallerStore> {
        AdminOps::new(
            self.store
                .as_caller(caller.client_name.clone().into_bytes()),
            self.keysalts.clone(),
        )
        .with_history_enctype(self.history_enctype)
    }

    fn name(&self, princ: Option<&str>) -> Result<(PrincipalName, String, String), u32> {
        let (n, r) = princ
            .and_then(|p| self.parse(p))
            .ok_or(code::BAD_PRINCIPAL)?;
        let t = unparse(&n, &r);
        Ok((n, r, t))
    }

    /// `check_lockdown_by_princ`: whether `name` has `lockdown_keys`.
    fn lockdown(&self, name: &PrincipalName, realm: &str) -> Result<bool, u32> {
        match self.store.raw_entry(name, realm) {
            Ok(Some(e)) => Ok(e.attributes & LOCKDOWN_KEYS != 0),
            Ok(None) => Err(code::UNK_PRINC),
            Err(e) => Err(store_code(&e, code::UNK_PRINC)),
        }
    }

    /// The calls that change the database (`server_stubs.c`).
    fn write(&self, caller: &Caller<'_>, args: kadm5::WriteArgs) -> Vec<u8> {
        use kadm5::WriteArgs as W;
        let api = args.api_version();
        let c = kadm5::check_api_version(api);
        if c != code::OK {
            return match args {
                W::ChrandPrincipal { .. } => kadm5::chrand_ret(0, c, &[]),
                W::ExtractKeys { .. } => kadm5::getpkeys_ret(0, c, &[]),
                _ => kadm5::generic_ret(0, c),
            };
        }
        let c = match args {
            W::ChrandPrincipal { princ, keepold, .. } => {
                let (c, keys) = self.chrand(caller, princ.as_deref(), keepold);
                return kadm5::chrand_ret(api, c, &keys);
            }
            W::ExtractKeys { princ, kvno, .. } => {
                let (c, keys) = self.extract_keys(caller, princ.as_deref(), kvno);
                return kadm5::getpkeys_ret(api, c, &keys);
            }
            W::ChpassPrincipal {
                princ,
                keepold,
                pass,
                ..
            } => self.chpass(caller, princ.as_deref(), keepold, pass.as_deref()),
            W::RenamePrincipal { src, dest, .. } => {
                self.rename_principal(caller, src.as_deref(), dest.as_deref())
            }
            W::CreateAlias { alias, target, .. } => {
                self.create_alias(caller, alias.as_deref(), target.as_deref())
            }
            W::CreatePrincipal {
                rec, mask, passwd, ..
            } => self.create_principal(caller, &rec, mask, passwd.as_deref()),
            W::ModifyPrincipal { rec, mask, .. } => self.modify_principal(caller, &rec, mask),
            W::SetkeyPrincipal {
                princ,
                keepold,
                keys,
                ..
            } => self.setkey(caller, princ.as_deref(), keepold, keys),
            W::Purgekeys {
                princ, keepkvno, ..
            } => self.purgekeys(caller, princ.as_deref(), keepkvno),
            W::DeletePrincipal { princ, .. } => self.delete_principal(caller, princ.as_deref()),
            W::SetString {
                princ, key, value, ..
            } => self.set_string(caller, princ.as_deref(), key.as_deref(), value.as_deref()),
            W::CreatePolicy { rec, mask, .. } => self.create_policy(caller, api, &rec, mask),
            W::ModifyPolicy { rec, mask, .. } => self.modify_policy(caller, api, &rec, mask),
            W::DeletePolicy { name, .. } => self.delete_policy(caller, name.as_deref()),
        };
        kadm5::generic_ret(api, c)
    }

    /// `check_self_keychange` (`server_stubs.c`): a self change needs an
    /// initial ticket and respects the policy's minimum password life.
    fn check_self_keychange(&self, caller: &Caller<'_>, name: &PrincipalName, realm: &str) -> u32 {
        if !caller.is(name, realm) {
            return code::OK;
        }
        if !caller.initial {
            return code::AUTH_INITIAL;
        }
        let admin = self.admin(caller);
        let rec = match run(admin.get_principal(name, realm)) {
            Ok(r) => r,
            Err(e) => return store_code(&e, code::UNK_PRINC),
        };
        let Some(policy) = rec.entry.policy.as_deref() else {
            return code::OK;
        };
        let policy = match run(admin.get_policy(policy)) {
            Ok(p) => p,
            Err(e) if e.kind() == StoreErrorKind::NotFound => return code::OK,
            Err(e) => return store_code(&e, code::UNK_POLICY),
        };
        let last = rec.last_pwd_change.map_or(0, |t| t.timestamp());
        let now = i64::from(unix_now());
        if now - last < i64::from(policy.pw_min_life)
            && !rec
                .entry
                .attributes
                .contains(PrincipalAttributes::REQUIRES_PWCHANGE)
        {
            return code::PASS_TOOSOON;
        }
        code::OK
    }

    /// The shared start of `chpass`/`chrand`: lookup, lockdown, then
    /// `changepw_not_self` and `OP_CPW` (self always allowed).
    fn keychange_auth(
        &self,
        caller: &Caller<'_>,
        op: &str,
        princ: Option<&str>,
    ) -> Result<(PrincipalName, String, String, bool), u32> {
        let (name, realm, target) = self.name(princ)?;
        let locked = self.lockdown(&name, &realm)?;
        let own = caller.is(&name, &realm);
        if (caller.changepw && !own)
            || !(own || self.acl(caller, ACL_CHANGEPW, Some((&name, &realm))))
        {
            caller.log_unauth(op, &target);
            return Err(code::AUTH_CHANGEPW);
        }
        Ok((name, realm, target, locked))
    }

    fn chpass(
        &self,
        caller: &Caller<'_>,
        princ: Option<&str>,
        keepold: bool,
        pass: Option<&str>,
    ) -> u32 {
        let op = "kadm5_chpass_principal";
        let (name, realm, target, locked) = match self.keychange_auth(caller, op, princ) {
            Ok(v) => v,
            Err(c) => return c,
        };
        if locked {
            caller.log_unauth(op, &target);
            return code::AUTH_CHANGEPW;
        }
        let mut c = self.check_self_keychange(caller, &name, &realm);
        if c == code::OK {
            c = match pass {
                None => code::EINVAL,
                Some(pw) => {
                    match run(self
                        .admin(caller)
                        .change_password(&name, &realm, Some(pw), keepold))
                    {
                        Ok(_) => code::OK,
                        Err(e) => store_code(&e, code::UNK_PRINC),
                    }
                }
            };
        }
        caller.log_done(op, &target, c);
        c
    }

    /// The current-kvno keys of `name` as kadm5 keyblocks.
    fn current_keys(
        &self,
        caller: &Caller<'_>,
        name: &PrincipalName,
        realm: &str,
        kvno: u32,
    ) -> Result<Vec<krb5_rs::kdc::KeyEntry>, u32> {
        let rec = run(self.admin(caller).get_principal(name, realm))
            .map_err(|e| store_code(&e, code::UNK_PRINC))?;
        let kvno = if kvno == 0 {
            rec.entry.current_kvno().unwrap_or(0)
        } else {
            kvno
        };
        Ok(rec
            .entry
            .keys
            .into_iter()
            .filter(|k| k.kvno == kvno)
            .collect())
    }

    fn chrand(
        &self,
        caller: &Caller<'_>,
        princ: Option<&str>,
        keepold: bool,
    ) -> (u32, Vec<kadm5::KeyBlock>) {
        let op = "kadm5_randkey_principal";
        let (name, realm, target, locked) = match self.keychange_auth(caller, op, princ) {
            Ok(v) => v,
            Err(c) => return (c, Vec::new()),
        };
        let mut c = self.check_self_keychange(caller, &name, &realm);
        let mut keys = Vec::new();
        if c == code::OK {
            c = match run(self
                .admin(caller)
                .change_password(&name, &realm, None, keepold))
            {
                Ok(kvno) => match self.current_keys(caller, &name, &realm, kvno) {
                    Ok(k) => {
                        keys = k
                            .iter()
                            .map(|k| kadm5::KeyBlock {
                                enctype: k.key.keytype,
                                contents: k.key.key_bytes().to_vec(),
                            })
                            .collect();
                        code::OK
                    }
                    Err(c) => c,
                },
                Err(e) => store_code(&e, code::UNK_PRINC),
            };
        }
        // MIT randomizes a lockdown_keys principal but returns no keys.
        if locked {
            keys.clear();
        }
        caller.log_done(op, &target, c);
        (c, keys)
    }

    fn extract_keys(
        &self,
        caller: &Caller<'_>,
        princ: Option<&str>,
        kvno: u32,
    ) -> (u32, Vec<kadm5::KeyData>) {
        let op = "kadm5_get_principal_keys";
        let (name, realm, target) = match self.name(princ) {
            Ok(v) => v,
            Err(c) => return (c, Vec::new()),
        };
        if caller.changepw || !self.acl(caller, ACL_EXTRACT, Some((&name, &realm))) {
            caller.log_unauth(op, &target);
            return (code::AUTH_EXTRACT, Vec::new());
        }
        // server_stubs.c:1772-1778: lockdown is reported as unauthorized.
        let (c, keys) = match self.lockdown(&name, &realm) {
            Err(c) => (c, Vec::new()),
            Ok(true) => {
                caller.log_unauth(op, &target);
                return (code::AUTH_EXTRACT, Vec::new());
            }
            Ok(false) => match self.current_keys(caller, &name, &realm, kvno) {
                Ok(k) => (
                    code::OK,
                    k.into_iter()
                        .map(|k| kadm5::KeyData {
                            kvno: k.kvno,
                            key: kadm5::KeyBlock {
                                enctype: k.key.keytype,
                                contents: k.key.key_bytes().to_vec(),
                            },
                            salt_type: if k.salt.is_some() { 4 } else { 0 },
                            salt: k.salt.unwrap_or_default(),
                        })
                        .collect(),
                ),
                Err(c) => (c, Vec::new()),
            },
        };
        caller.log_done(op, &target, c);
        (c, keys)
    }

    fn rename_principal(&self, caller: &Caller<'_>, src: Option<&str>, dest: Option<&str>) -> u32 {
        let op = "kadm5_rename_principal";
        let (sname, srealm, starget) = match self.name(src) {
            Ok(v) => v,
            Err(c) => return c,
        };
        let (dname, drealm, dtarget) = match self.name(dest) {
            Ok(v) => v,
            Err(c) => return c,
        };
        let prime = format!("{starget} to {dtarget}");
        if caller.changepw
            || !self.acl(caller, ACL_DELETE, Some((&sname, &srealm)))
            || !self.acl(caller, ACL_ADD, Some((&dname, &drealm)))
        {
            caller.log_unauth(op, &prime);
            return code::AUTH_INSUFFICIENT;
        }
        let c = match self.lockdown(&sname, &srealm) {
            Ok(true) => {
                caller.log_unauth(op, &prime);
                return code::AUTH_INSUFFICIENT;
            }
            Err(c) => c,
            Ok(false) if srealm != drealm => code::FAILURE,
            Ok(false) => {
                let modifier = caller.client_name.clone().into_bytes();
                let res = self.store.rename_raw(&sname, &srealm, |mut e, _| {
                    if tl_bytes(&e, ALIAS_TARGET).is_some() {
                        return Err(StoreError::rejected(
                            "Operation unsupported on alias principal name",
                        ));
                    }
                    specialize_salt(&mut e);
                    e.principal = dname.clone();
                    e.realm = drealm.clone();
                    set_mod_princ(&mut e, unix_now(), &modifier)?;
                    Ok(e)
                });
                match res {
                    Ok(()) => code::OK,
                    Err(e) => store_code(&e, code::UNK_PRINC),
                }
            }
        };
        caller.log_done(op, &prime, c);
        c
    }

    fn create_alias(&self, caller: &Caller<'_>, alias: Option<&str>, target: Option<&str>) -> u32 {
        let op = "kadm5_create_alias";
        let (aname, arealm, atarget) = match self.name(alias) {
            Ok(v) => v,
            Err(c) => return c,
        };
        let (tname, trealm, ttarget) = match self.name(target) {
            Ok(v) => v,
            Err(c) => return c,
        };
        let prime = format!("{atarget} to {ttarget}");
        if caller.changepw
            || !self.acl(caller, ACL_ADD, Some((&aname, &arealm)))
            || !self.acl(caller, ACL_MODIFY, Some((&tname, &trealm)))
        {
            caller.log_unauth(op, &prime);
            return code::AUTH_INSUFFICIENT;
        }
        let c = if arealm != trealm {
            code::ALIAS_REALM
        } else {
            // krb5_dbe_make_alias_entry (lib/kdb/kdb5.c:2826-2870).
            let mut data = ttarget.clone().into_bytes();
            data.push(0);
            let mut e = MitEntry {
                principal: aname.clone(),
                realm: arealm.clone(),
                attributes: PrincipalAttributes::DISALLOW_ALL_TIX.bits(),
                max_life: 0,
                max_renewable_life: 0,
                expiration: 0,
                pw_expiration: 0,
                last_success: 0,
                last_failed: 0,
                fail_auth_count: 0,
                tl_data: vec![TlData {
                    kind: ALIAS_TARGET,
                    data,
                }],
                key_data: Vec::new(),
            };
            match set_mod_princ(&mut e, unix_now(), caller.client_name.as_bytes())
                .and_then(|()| self.store.create_raw(&e))
            {
                Ok(()) => code::OK,
                Err(e) => store_code(&e, code::UNK_PRINC),
            }
        };
        caller.log_done(op, &prime, c);
        c
    }

    /// `stub_auth_restr`: the ACL check that also yields restrictions.
    fn acl_restr(
        &self,
        caller: &Caller<'_>,
        op: u32,
        name: &PrincipalName,
        realm: &str,
    ) -> Option<Option<AclRestrictions>> {
        acl_check(
            &self.acl,
            op,
            (&caller.client, &caller.crealm),
            Some((name, realm)),
        )
        .map(|r| r.cloned())
    }

    fn create_principal(
        &self,
        caller: &Caller<'_>,
        rec: &kadm5::PrincipalEnt,
        mask: i32,
        passwd: Option<&str>,
    ) -> u32 {
        use kmask as m;
        let op = "kadm5_create_principal";
        let princ = rec.principal.as_deref().map(String::from_utf8_lossy);
        let (name, realm, target) = match self.name(princ.as_deref()) {
            Ok(v) => v,
            Err(c) => return c,
        };
        let restr = match self.acl_restr(caller, ACL_ADD, &name, &realm) {
            Some(r) if !caller.changepw => r,
            _ => {
                caller.log_unauth(op, &target);
                return code::AUTH_ADD;
            }
        };
        let forbidden = m::MOD_NAME
            | m::MOD_TIME
            | m::LAST_PWD_CHANGE
            | m::MKVNO
            | m::AUX_ATTRIBUTES
            | m::LAST_SUCCESS
            | m::LAST_FAILED
            | m::FAIL_AUTH_COUNT;
        let c = if mask & m::PRINCIPAL == 0
            || mask & forbidden != 0
            || (mask & m::KEY_DATA != 0 && !rec.key_data.is_empty())
            || (mask & m::POLICY != 0 && rec.policy.is_none())
            || (mask & m::POLICY != 0 && mask & m::POLICY_CLR != 0)
            || mask & !m::ALL_PRINC_MASK != 0
        {
            code::BAD_MASK
        } else if mask & m::TL_DATA != 0 && rec.tl_data.iter().any(|t| t.kind < 256) {
            code::BAD_TL_TYPE
        } else {
            let (mut opts, mask) = principal_options(rec, mask, restr.as_ref());
            let mask = mask as i32;
            if mask & m::MAX_LIFE == 0 {
                opts.max_life = Some((!self.max_life.is_zero()).then_some(self.max_life));
            }
            if mask & m::MAX_RLIFE == 0 {
                opts.max_renewable_life =
                    Some((!self.max_rlife.is_zero()).then_some(self.max_rlife));
            }
            if mask & m::PRINC_EXPIRE_TIME == 0 {
                opts.expiration = Some(self.expiration);
            }
            match run(self
                .admin(caller)
                .add_principal(&name, &realm, passwd, &opts))
            {
                Ok(()) => code::OK,
                Err(e) => store_code(&e, code::UNK_POLICY),
            }
        };
        caller.log_done(op, &target, c);
        c
    }

    fn modify_principal(&self, caller: &Caller<'_>, rec: &kadm5::PrincipalEnt, mask: i32) -> u32 {
        use kmask as m;
        let op = "kadm5_modify_principal";
        let princ = rec.principal.as_deref().map(String::from_utf8_lossy);
        let (name, realm, target) = match self.name(princ.as_deref()) {
            Ok(v) => v,
            Err(c) => return c,
        };
        let restr = match self.acl_restr(caller, ACL_MODIFY, &name, &realm) {
            Some(r) if !caller.changepw => r,
            _ => {
                caller.log_unauth(op, &target);
                return code::AUTH_MODIFY;
            }
        };
        if mask & m::ATTRIBUTES != 0 && rec.attributes & LOCKDOWN_KEYS == 0 {
            match self.lockdown(&name, &realm) {
                Ok(true) => {
                    caller.log_unauth(op, &target);
                    return code::AUTH_MODIFY;
                }
                Ok(false) => {}
                Err(c) => {
                    caller.log_done(op, &target, c);
                    return c;
                }
            }
        }
        let forbidden = m::PRINCIPAL
            | m::LAST_PWD_CHANGE
            | m::MOD_TIME
            | m::MOD_NAME
            | m::MKVNO
            | m::AUX_ATTRIBUTES
            | m::KEY_DATA
            | m::LAST_SUCCESS
            | m::LAST_FAILED;
        let c = if mask & forbidden != 0
            || mask & !m::ALL_PRINC_MASK != 0
            || (mask & m::POLICY != 0 && rec.policy.is_none())
            || (mask & m::POLICY != 0 && mask & m::POLICY_CLR != 0)
        {
            code::BAD_MASK
        } else if mask & m::TL_DATA != 0 && rec.tl_data.iter().any(|t| t.kind < 256) {
            code::BAD_TL_TYPE
        } else if mask & m::FAIL_AUTH_COUNT != 0 && rec.fail_auth_count != 0 {
            code::BAD_SERVER_PARAMS
        } else {
            let (opts, _) = principal_options(rec, mask, restr.as_ref());
            match run(self.admin(caller).modify_principal(&name, &realm, &opts)) {
                Ok(()) => code::OK,
                Err(e) => store_code(&e, code::UNK_PRINC),
            }
        };
        caller.log_done(op, &target, c);
        c
    }

    fn setkey(
        &self,
        caller: &Caller<'_>,
        princ: Option<&str>,
        keepold: bool,
        keys: kadm5::SetKeys,
    ) -> u32 {
        let op = "kadm5_setkey_principal";
        let (name, realm, target) = match self.name(princ) {
            Ok(v) => v,
            Err(c) => return c,
        };
        if caller.changepw || !self.acl(caller, ACL_SETKEY, Some((&name, &realm))) {
            caller.log_unauth(op, &target);
            return code::AUTH_SETKEY;
        }
        match self.lockdown(&name, &realm) {
            Ok(false) => {}
            Ok(true) => {
                caller.log_unauth(op, &target);
                return code::AUTH_SETKEY;
            }
            Err(c) => {
                caller.log_done(op, &target, c);
                return c;
            }
        }
        let c = match setkey_data(keys) {
            _ if target == format!("kadmin/history@{realm}") => code::PROTECT_PRINCIPAL,
            Err(c) => c,
            Ok(keys) => self.setkey_data(caller, &name, &realm, keepold, &keys),
        };
        caller.log_done(op, &target, c);
        c
    }

    /// `kadm5_setkey_principal_4` (`svr_principal.c:2073-2196`).
    fn setkey_data(
        &self,
        caller: &Caller<'_>,
        name: &PrincipalName,
        realm: &str,
        keepold: bool,
        keys: &[kadm5::KeyData],
    ) -> u32 {
        if keys.is_empty() {
            return code::EINVAL;
        }
        let kvno = keys[0].kvno;
        if keys.iter().any(|k| k.kvno != kvno) {
            return code::SETKEY_BAD_KVNO;
        }
        for (i, a) in keys.iter().enumerate() {
            if keys[i + 1..]
                .iter()
                .any(|b| b.key.enctype == a.key.enctype && b.salt_type == a.salt_type)
            {
                return code::SETKEY_DUP_ENCTYPES;
            }
        }
        let modifier = caller.client_name.clone().into_bytes();
        let mut outcome = None;
        let res = self.store.update_raw(name, realm, |e, mk| {
            let kvno = if kvno == 0 {
                e.key_data
                    .iter()
                    .map(|k| u32::from(k.kvno))
                    .max()
                    .unwrap_or(0)
                    + 1
            } else if keepold && e.key_data.iter().any(|k| u32::from(k.kvno) == kvno) {
                outcome = Some(code::SETKEY_BAD_KVNO);
                return Ok(false);
            } else {
                kvno
            };
            let kvno = u16::try_from(kvno)
                .map_err(|_| StoreError::backend("MIT key version exceeds u16"))?;
            let mkvno = entry_mkvno(e)?;
            let master = mk
                .keys
                .iter()
                .find(|(v, _)| *v == mkvno)
                .map(|(_, k)| k)
                .ok_or_else(|| StoreError::backend("master key version not found"))?;
            let mut data = Vec::with_capacity(keys.len() + e.key_data.len());
            for k in keys {
                let etype = i16::try_from(k.key.enctype)
                    .map_err(|_| StoreError::backend("MIT enctype exceeds i16"))?;
                let key = EncryptionKey::new(k.key.enctype, k.key.contents.clone());
                data.push(MitKeyData {
                    ver: 2,
                    kvno,
                    fields: vec![
                        (etype, encrypt_key(master, &key)?),
                        (k.salt_type, k.salt.clone()),
                    ],
                });
            }
            if keepold {
                data.append(&mut e.key_data);
            }
            e.key_data = data;
            set_mod_princ(e, unix_now(), &modifier)?;
            Ok(true)
        });
        match (res, outcome) {
            (_, Some(c)) => c,
            (Ok(true), None) => code::OK,
            (Ok(false), None) => code::UNK_PRINC,
            (Err(e), None) => store_code(&e, code::UNK_PRINC),
        }
    }

    /// `kadm5_purgekeys` (`svr_principal.c:2008-2071`).
    fn purgekeys(&self, caller: &Caller<'_>, princ: Option<&str>, keepkvno: i32) -> u32 {
        let op = "kadm5_purgekeys";
        let (name, realm, target) = match self.name(princ) {
            Ok(v) => v,
            Err(c) => return c,
        };
        if caller.changepw || !self.acl(caller, ACL_MODIFY, Some((&name, &realm))) {
            caller.log_unauth(op, &target);
            return code::AUTH_MODIFY;
        }
        let modifier = caller.client_name.clone().into_bytes();
        let res = self.store.update_raw(&name, &realm, |e, _| {
            let keep = match u16::try_from(keepkvno) {
                Ok(k) if k > 0 => k,
                _ => e.key_data.iter().map(|k| k.kvno).max().unwrap_or(0),
            };
            e.key_data.retain(|k| k.kvno >= keep);
            set_mod_princ(e, unix_now(), &modifier)?;
            Ok(true)
        });
        let c = match res {
            Ok(true) => code::OK,
            Ok(false) => code::UNK_PRINC,
            Err(e) => store_code(&e, code::UNK_PRINC),
        };
        caller.log_done(op, &target, c);
        c
    }

    fn delete_principal(&self, caller: &Caller<'_>, princ: Option<&str>) -> u32 {
        let op = "kadm5_delete_principal";
        let (name, realm, target) = match self.name(princ) {
            Ok(v) => v,
            Err(c) => return c,
        };
        if caller.changepw || !self.acl(caller, ACL_DELETE, Some((&name, &realm))) {
            caller.log_unauth(op, &target);
            return code::AUTH_DELETE;
        }
        let c = match self.lockdown(&name, &realm) {
            Ok(true) => {
                caller.log_unauth(op, &target);
                return code::AUTH_DELETE;
            }
            Err(c) => c,
            Ok(false) => match run(self.admin(caller).delete_principal(&name, &realm)) {
                Ok(()) => code::OK,
                Err(e) => store_code(&e, code::UNK_PRINC),
            },
        };
        caller.log_done(op, &target, c);
        c
    }

    fn set_string(
        &self,
        caller: &Caller<'_>,
        princ: Option<&str>,
        key: Option<&str>,
        value: Option<&str>,
    ) -> u32 {
        let op = "kadm5_mod_strings";
        let (name, realm, target) = match self.name(princ) {
            Ok(v) => v,
            Err(c) => return c,
        };
        if caller.changepw || !self.acl(caller, ACL_MODIFY, Some((&name, &realm))) {
            caller.log_unauth(op, &target);
            return code::AUTH_MODIFY;
        }
        let c = match key {
            None => code::EINVAL,
            Some(key) => {
                let modifier = caller.client_name.clone().into_bytes();
                let key = key.as_bytes().to_vec();
                let value = value.map(|v| v.as_bytes().to_vec());
                let res = self.store.update_raw(&name, &realm, move |e, _| {
                    set_string_attr(e, &key, value.as_deref())?;
                    set_mod_princ(e, unix_now(), &modifier)?;
                    Ok(true)
                });
                match res {
                    Ok(true) => code::OK,
                    Ok(false) => code::UNK_PRINC,
                    Err(e) => store_code(&e, code::UNK_PRINC),
                }
            }
        };
        caller.log_done(op, &target, c);
        c
    }

    fn create_policy(
        &self,
        caller: &Caller<'_>,
        api: u32,
        rec: &kadm5::PolicyEnt,
        mask: i32,
    ) -> u32 {
        let op = "kadm5_create_policy";
        let target = rec.policy.as_deref().unwrap_or("(null)");
        if caller.changepw || !self.acl(caller, ACL_ADD, None) {
            caller.log_unauth(op, target);
            return code::AUTH_ADD;
        }
        let c = (|| {
            let name = rec.policy.as_deref().ok_or(code::EINVAL)?;
            if name.is_empty() {
                return Err(code::BAD_POLICY);
            }
            if mask & kmask::POLICY == 0 || mask & !kmask::ALL_POLICY_MASK != 0 {
                return Err(code::BAD_MASK);
            }
            let max = (mask & kmask::PW_MAX_LIFE != 0).then_some(rec.pw_max_life);
            check_policy(rec, mask, max)?;
            let mut p = policy_change(rec, mask, api).into_policy(name);
            apply_policy_v4(&mut p, rec, mask, api);
            run(self.admin(caller).add_policy(p)).map_err(|e| store_code(&e, code::UNK_POLICY))
        })()
        .map_or_else(|c| c, |()| code::OK);
        caller.log_done(op, target, c);
        c
    }

    fn modify_policy(
        &self,
        caller: &Caller<'_>,
        api: u32,
        rec: &kadm5::PolicyEnt,
        mask: i32,
    ) -> u32 {
        let op = "kadm5_modify_policy";
        let target = rec.policy.as_deref().unwrap_or("(null)");
        if caller.changepw || !self.acl(caller, ACL_MODIFY, None) {
            caller.log_unauth(op, target);
            return code::AUTH_MODIFY;
        }
        let c = (|| {
            let name = rec.policy.as_deref().ok_or(code::EINVAL)?;
            if name.is_empty() {
                return Err(code::BAD_POLICY);
            }
            if mask & kmask::POLICY != 0 || mask & !kmask::ALL_POLICY_MASK != 0 {
                return Err(code::BAD_MASK);
            }
            let current = match self.store.raw_policy(name) {
                Ok(Some(p)) => p,
                Ok(None) => return Err(code::UNK_POLICY),
                Err(e) => return Err(store_code(&e, code::UNK_POLICY)),
            };
            let max = if mask & kmask::PW_MAX_LIFE != 0 {
                rec.pw_max_life
            } else {
                current.pw_max_life as i32
            };
            check_policy(rec, mask, Some(max))?;
            let change = policy_change(rec, mask, api);
            let rec = rec.clone();
            run(self.store.update_policy(name, move |p| {
                change.apply(p);
                apply_policy_v4(p, &rec, mask, api);
                Ok(())
            }))
            .map(|_| ())
            .map_err(|e| store_code(&e, code::UNK_POLICY))
        })()
        .map_or_else(|c| c, |()| code::OK);
        caller.log_done(op, target, c);
        c
    }

    fn delete_policy(&self, caller: &Caller<'_>, name: Option<&str>) -> u32 {
        let op = "kadm5_delete_policy";
        let target = name.unwrap_or("(null)");
        if caller.changepw || !self.acl(caller, ACL_DELETE, None) {
            caller.log_unauth(op, target);
            return code::AUTH_DELETE;
        }
        let c = match name {
            None => code::EINVAL,
            Some("") => code::BAD_POLICY,
            Some(n) => match run(self.admin(caller).delete_policy(n)) {
                Ok(()) => code::OK,
                Err(e) => store_code(&e, code::UNK_POLICY),
            },
        };
        caller.log_done(op, target, c);
        c
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
        if let Some(parsed) = kadm5::WriteArgs::decode(proc_, args) {
            let Ok(parsed) = parsed else {
                return err(gss, AcceptStat::GarbageArgs);
            };
            // xdr_krb5_principal fails on names krb5_parse_name rejects.
            if parsed.principals().iter().any(|p| self.parse(p).is_none()) {
                return err(gss, AcceptStat::GarbageArgs);
            }
            let results = self.write(&caller, parsed);
            return gss.reply(xid, seq, &results).map_err(|e| e.to_string());
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
        max_life: cfg.kdc.max_life,
        max_rlife: cfg.admin_max_renewable_life,
        expiration: cfg.default_principal_expiration,
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
