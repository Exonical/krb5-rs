//! kadmin.local-like administration of the persistent principal database.
//!
//! `krb5-rs-kdb [--config kdc.conf] [--krb5-config krb5.conf] [--realm R] <cmd> args`
//!
//! Commands: `create [-s]`, `stash`, `addprinc`, `delprinc`, `cpw`,
//! `modprinc`, `getprinc`, `listprincs`, `ktadd`, `dump`, `load`. See `usage()`.
//!
//! The master password and principal passwords are read from stdin, one
//! line each; they are never taken from the command line. Master-key
//! prompts go to stdout like MIT's prompter, other prompts to stderr. Input
//! is not hidden when stdin is a terminal. Errors are printed the way
//! `kdb5_util`'s `com_err(progname, ...)` prints them.

#[path = "kadmind/modules.rs"]
mod modules;

#[cfg(feature = "kldap")]
#[allow(dead_code)]
#[path = "kdb/ldap_util.rs"]
pub(crate) mod ldap_util;

use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicI32, Ordering};

use krb5_rs::kdc::kdb::admin::{
    format_policy, format_principal, parse_lifetime, parse_principal, parse_time, AdminModules,
    AdminOps, AttrChange, PolicyChange, PrincipalOptions,
};
use krb5_rs::kdc::kdb::master::{read_stash_kvno, write_stash_list};
use krb5_rs::kdc::kdb::mit::dump::{
    policy_record, principal_record, read_dump, read_records, DumpVersion, IpropHeader,
    LoadFailure, Record,
};
use krb5_rs::kdc::kdb::mit::mkey::MasterKeys;
use krb5_rs::kdc::kdb::mit::ulog::{Last, Time, Ulog, UpdateStatus};
use krb5_rs::kdc::kdb::mit::{unparse_name, MitEntry, MitPolicy};
use krb5_rs::kdc::kdb::pwqual::PwQualModules;
use krb5_rs::kdc::kdb::{master_key_from_password, write_stash, FileStore};
use krb5_rs::kdc::{
    default_realm, AdminStore, IpropConfig, RealmConfig, StoreError, StoreErrorKind,
};
use krb5_rs::profile::Profile;
#[cfg(feature = "klmdb")]
use krb5_rs_kdb_lmdb::LmdbStore;

fn print_usage() {
    eprintln!(
        "usage: krb5-rs-kdb [--config kdc.conf] [--krb5-config krb5.conf] [--realm R] [--master-password-file PATH] [-r REALM] [-d DATABASE] [-x DB_ARG]... <command>\n\
         commands:\n  init [--master-password-file F] [--stash] [--randkey NAME]... [--password NAME=FILE]...\n  create [-s]\n  stash [-f KEYFILE]\n  add_mkey [-e ENCTYPE] [-s]\n  use_mkey KVNO [TIME]\n  list_mkeys\n  purge_mkeys [-f] [-n] [-v]\n  update_princ_encryption [-f] [-n] [-v] [PRINC-PATTERN]\n  \
         addprinc [-randkey] [{{+|-}}attr]... [-maxlife T] [-maxrenewlife T] [-expire T] [-pwexpire T] NAME\n  \
         delprinc NAME\n  cpw [-randkey] [-keepold] NAME\n  \
         modprinc [{{+|-}}attr]... [-maxlife T] [-maxrenewlife T] [-expire T] [-pwexpire T] [-allow_delegate_to P]... [-allow_delegate_from P]... [-clear_delegate_to] [-clear_delegate_from] [-policy P | -clearpolicy] [-unlock] NAME\n  \
         addpol|modpol [-maxlife T] [-minlife T] [-minlength N] [-minclasses N] [-history N] [-maxfailure N] [-failurecountinterval T] [-lockoutduration T] [-allowedkeysalts K] POLICY\n  \
         delpol POLICY\n  getpol [-terse] POLICY\n  listpols\n  \
         database migrate [--create-roles] [--multi-region --primary-region R --regions R1,R2,...]   (CockroachDB)\n  \
         replication status | prune --older-than D | wait-applied --since TS [--timeout D] [--live-within D]   (CockroachDB)\n  \
         getprinc NAME\n  listprincs\n  ktadd -k PATH [-norandkey] NAME...\n  \
         dump [-b7|-r13|-r18] [-verbose] [-mkey_convert] [-new_mkey_file STASH] [FILE [NAME-REGEX]...]\n  load [-b7|-r13|-r18] [-verbose] [-update] [-hash] FILE"
    );
}

fn usage() -> ! {
    print_usage();
    std::process::exit(1);
}

fn help() -> ! {
    print_usage();
    std::process::exit(0);
}

/// `kdb5_util`'s `exit_status`: bumped when a step fails but the command
/// goes on, and added to the exit code of a later failure.
static EXIT_STATUS: AtomicI32 = AtomicI32::new(0);

/// The password quality and kadm5_hook modules of the principal commands,
/// which are kadmin.local's (`kadm5_init`); other commands run none, as
/// `kdb5_util` does.
static ADMIN_MODULES: std::sync::Mutex<Option<AdminModules>> = std::sync::Mutex::new(None);

fn admin_modules() -> std::sync::MutexGuard<'static, Option<AdminModules>> {
    ADMIN_MODULES
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// The principal commands, which run the kadm5 modules.
const KADM5_COMMANDS: [&str; 4] = ["addprinc", "delprinc", "cpw", "modprinc"];

fn exit_status() -> i32 {
    EXIT_STATUS.load(Ordering::Relaxed)
}

fn bump_exit_status() {
    EXIT_STATUS.fetch_add(1, Ordering::Relaxed);
}

/// MIT's `progname`: the base name of argv[0].
fn progname() -> &'static str {
    static NAME: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    NAME.get_or_init(|| {
        std::env::args_os()
            .next()
            .and_then(|a| {
                Path::new(&a)
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
            })
            .unwrap_or_else(|| "krb5-rs-kdb".into())
    })
}

/// `msg` as com_err prints an error code's message: without the
/// `StoreError` prefix and without " (os error N)" after strerror text.
fn com_err_text(msg: &str) -> String {
    const OS: &str = " (os error ";
    let msg = msg.replace("principal store error: ", "");
    let mut out = String::with_capacity(msg.len());
    let mut rest = msg.as_str();
    while let Some(i) = rest.find(OS) {
        out.push_str(&rest[..i]);
        let tail = &rest[i + OS.len()..];
        match tail.find(')') {
            Some(j) if j > 0 && tail[..j].bytes().all(|b| b.is_ascii_digit()) => {
                rest = &tail[j + 1..];
            }
            _ => {
                out.push_str(OS);
                rest = tail;
            }
        }
    }
    out.push_str(rest);
    out
}

/// `com_err(progname, ...)`.
fn com_err(msg: impl std::fmt::Display) {
    eprintln!("{}: {}", progname(), com_err_text(&msg.to_string()));
}

fn fail(msg: impl std::fmt::Display) -> ! {
    com_err(msg);
    std::process::exit(exit_status() + 1);
}

fn ok<T, E: std::fmt::Display>(r: Result<T, E>) -> T {
    r.unwrap_or_else(|e| fail(e))
}

fn read_line(prompt: &str) -> String {
    eprint!("{prompt}");
    let mut line = String::new();
    if std::io::stdin().lock().read_line(&mut line).unwrap_or(0) == 0 {
        fail("unexpected end of input");
    }
    line.trim_end_matches(['\r', '\n']).to_string()
}

/// `krb5_prompter_posix`: the prompt and ": " on stdout, a newline after the
/// answer. `context` completes "Cannot read password while ...".
fn read_password(prompt: &str, context: &str) -> String {
    use std::io::IsTerminal as _;
    print!("{prompt}: ");
    let _ = std::io::stdout().flush();
    if std::io::stdin().is_terminal() {
        // The prompter turns echo off, as MIT's krb5_prompter_posix does.
        let p = rpassword::read_password()
            .unwrap_or_else(|_| fail(format!("Cannot read password while {context}")));
        println!();
        return p;
    }
    let mut line = String::new();
    let read = std::io::stdin().lock().read_line(&mut line).unwrap_or(0);
    println!();
    if read == 0 {
        fail(format!("Cannot read password while {context}"));
    }
    line.trim_end_matches(['\r', '\n']).to_string()
}

/// `kdb5_create` (`kdb5_create.c:196-220`): announce the database, then
/// read the master password twice, or once from the password file (`-P`).
fn create_master_key(
    cfg: &RealmConfig,
    realm: &str,
    master_password_file: Option<&str>,
) -> krb5_rs::types::EncryptionKey {
    println!(
        "Initializing database '{}' for realm '{realm}',",
        cfg.database_name.display()
    );
    println!("master key name 'K/M@{realm}'");
    let password = match master_password_file {
        Some(path) => read_secret_file(path),
        None => {
            println!("You will be prompted for the database Master Password.");
            println!("It is important that you NOT FORGET this password.");
            let context = "reading master key from keyboard";
            let password = read_password("Enter KDC database master key", context);
            let again = read_password("Re-enter KDC database master key to verify", context);
            if password != again {
                fail(format!("Password mismatch while {context}"));
            }
            password
        }
    };
    ok(master_key_from_password(
        realm,
        &password,
        cfg.master_key_type,
    ))
}

/// First line of a secret file; secrets never come from argv.
fn read_secret_file(path: &str) -> String {
    let text = ok(std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}")));
    let line = text.lines().next().unwrap_or("").trim_end_matches('\r');
    if line.is_empty() {
        fail(format!("{path} is empty"));
    }
    line.to_string()
}

/// The master key, or exit after [`fetch_master`]'s warnings.
fn master_key(
    cfg: &RealmConfig,
    realm: &str,
    master_password_file: Option<&str>,
) -> krb5_rs::types::EncryptionKey {
    fetch_master(cfg, realm, master_password_file)
        .unwrap_or_else(|| std::process::exit(exit_status()))
}

fn fetch_master(
    cfg: &RealmConfig,
    realm: &str,
    master_password_file: Option<&str>,
) -> Option<krb5_rs::types::EncryptionKey> {
    fetch_master_kvno(cfg, realm, master_password_file).map(|(_, key)| key)
}

/// `open_db_and_mkey`'s master key (`kdb5_util.c:405-450`), with the stash's
/// kvno: from the password file (`-P`) or the stash. Without either, warns
/// as MIT does and returns `None`.
fn fetch_master_kvno(
    cfg: &RealmConfig,
    realm: &str,
    master_password_file: Option<&str>,
) -> Option<(Option<u32>, krb5_rs::types::EncryptionKey)> {
    if let Some(path) = master_password_file {
        let key = ok(master_key_from_password(
            realm,
            &read_secret_file(path),
            cfg.master_key_type,
        ));
        return Some((None, key));
    }
    let stash = &cfg.key_stash_file;
    let fetched = std::fs::metadata(stash)
        .map_err(|e| com_err_text(&e.to_string()))
        .and_then(|_| read_stash_kvno(stash, realm).map_err(|e| com_err_text(e.message())));
    match fetched {
        Ok((kvno, key)) => Some((Some(kvno), key)),
        Err(reason) => {
            com_err(format!(
                "Can not fetch master key (error: {reason}). while reading master key"
            ));
            com_err("Warning: proceeding without master key");
            bump_exit_status();
            None
        }
    }
}

/// `KRB5_KDB_BADMASTERKEY`, from `krb5_db_fetch_mkey_list`.
const BAD_MASTER: &str = "Unable to decrypt latest master key with the provided master key";

/// Whether opening a store failed only because the master key is wrong:
/// klmdb, FileStore and CockroachDB each word it their own way.
fn wrong_master_key(e: &StoreError) -> bool {
    matches!(
        e.message(),
        BAD_MASTER
            | "incorrect master key"
            | "the master key does not match the database (cannot decrypt K/M)"
    )
}

/// `krb5_db_fetch_mkey_list` failing in `open_db_and_mkey`
/// (`kdb5_util.c:452-458`): warn and go on when `e` is a wrong master key.
fn no_master_list(e: &StoreError) -> bool {
    if !wrong_master_key(e) {
        return false;
    }
    com_err(format!("{BAD_MASTER}\n while getting master key list"));
    com_err("Warning: proceeding without master key list");
    bump_exit_status();
    true
}

/// `kdb5_stash` (`kdb5_stash.c:66-132`): `stash [-f keyfile]` rewrites the
/// stash from the existing one when it opens the database, else prompts once
/// for the master password. `--master-password-file` stands in for `-m`.
fn stash_source<T>(
    args: &[String],
    cfg: &RealmConfig,
    realm: &str,
    master_password_file: Option<&str>,
    open: impl Fn(&krb5_rs::types::EncryptionKey) -> Result<T, StoreError>,
) -> (PathBuf, T) {
    let keyfile = match args {
        [] => cfg.key_stash_file.clone(),
        [flag, path] if flag == "-f" => PathBuf::from(path),
        _ => usage(),
    };
    if master_password_file.is_none() {
        if let Some(key) = fetch_master(cfg, realm, None) {
            match open(&key) {
                Ok(opened) => {
                    println!("Using existing stashed keys to update stash file.");
                    return (keyfile, opened);
                }
                // A stash that no longer opens the database: ask for the
                // password, as MIT's kdb5_stash does without a key list.
                Err(e) if wrong_master_key(&e) => {
                    no_master_list(&e);
                }
                Err(e) => fail(e),
            }
        }
    }
    let password = match master_password_file {
        Some(path) => read_secret_file(path),
        None => read_password("Enter KDC database master key", "reading master key"),
    };
    let key = ok(master_key_from_password(
        realm,
        &password,
        cfg.master_key_type,
    ));
    let opened = match open(&key) {
        Ok(opened) => opened,
        Err(e) if e.message() == BAD_MASTER => {
            fail(format!("{BAD_MASTER}\n while getting master key list"))
        }
        Err(e) => fail(e),
    };
    // kdb5_stash.c:135: a stash written with the password succeeds.
    EXIT_STATUS.store(0, Ordering::Relaxed);
    (keyfile, opened)
}

/// Idempotent bootstrap: create the database (and stash) if missing, then
/// make sure every listed principal exists, leaving existing ones alone.
fn init(
    args: Vec<String>,
    cfg: &RealmConfig,
    realm: &str,
    global_master_password_file: Option<&str>,
) {
    let mut master_file: Option<String> = None;
    let mut stash = false;
    let mut randkeys: Vec<String> = Vec::new();
    let mut passwords: Vec<(String, String)> = Vec::new();
    let mut it = args.into_iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--master-password-file" => master_file = Some(next(&mut it)),
            "--stash" => stash = true,
            "--randkey" => randkeys.push(next(&mut it)),
            "--password" => {
                let spec = next(&mut it);
                let Some((name, file)) = spec.split_once('=') else {
                    fail("--password expects NAME=FILE");
                };
                passwords.push((name.to_string(), file.to_string()));
            }
            _ => usage(),
        }
    }
    let master_file = master_file
        .as_deref()
        .or(global_master_password_file)
        .unwrap_or_else(|| fail("init requires --master-password-file"));
    let key = master_key(cfg, realm, Some(master_file));
    let etypes: Vec<i32> = cfg.supported_keysalts.iter().map(|(e, _)| *e).collect();
    let store = if cfg.database_name.exists() {
        ok(open_file(cfg, &key))
    } else {
        let store = ok(FileStore::create_with(
            &cfg.database_name,
            realm,
            &key,
            &etypes,
        ));
        println!("Database {} created.", cfg.database_name.display());
        store
    };
    if stash && !cfg.key_stash_file.exists() {
        ok(write_stash(&cfg.key_stash_file, realm, &key));
        println!("Stash {} written.", cfg.key_stash_file.display());
    }
    let admin = Blocking::new(
        runtime(),
        store,
        cfg.supported_keysalts.clone(),
        cfg.master_key_type,
    );
    add_admin_princs(&admin, realm);
    ensure_init_principals(&admin, realm, &randkeys, &passwords);
}

/// Parse addpol/modpol options (kadmin.c:1646-1695); the policy name is the
/// last argument.
fn policy_change(args: Vec<String>) -> (PolicyChange, String) {
    let mut change = PolicyChange::default();
    let mut rest = Vec::new();
    let mut it = args.into_iter();
    let interval = |s: String| -> u32 {
        let d = ok(parse_lifetime(&s));
        d.map_or(0, |d| u32::try_from(d.as_secs()).unwrap_or(u32::MAX))
    };
    let number = |s: String| -> u32 {
        s.parse()
            .unwrap_or_else(|_| fail(format!("{s:?} is not a number")))
    };
    while let Some(a) = it.next() {
        match a.as_str() {
            "-maxlife" => change.pw_max_life = Some(interval(next(&mut it))),
            "-minlife" => change.pw_min_life = Some(interval(next(&mut it))),
            "-minlength" => change.pw_min_length = Some(number(next(&mut it))),
            "-minclasses" => change.pw_min_classes = Some(number(next(&mut it))),
            "-history" => change.pw_history_num = Some(number(next(&mut it))),
            "-maxfailure" => change.pw_max_fail = Some(number(next(&mut it))),
            "-failurecountinterval" => change.pw_failcnt_interval = Some(interval(next(&mut it))),
            "-lockoutduration" => change.pw_lockout_duration = Some(interval(next(&mut it))),
            "-allowedkeysalts" => {
                let v = next(&mut it);
                change.allowed_keysalts = Some((v != "-").then_some(v));
            }
            s if s.starts_with('-') => usage(),
            _ => rest.push(a),
        }
    }
    let [name] = rest.as_slice() else { usage() };
    (change, name.clone())
}

fn next(it: &mut std::vec::IntoIter<String>) -> String {
    it.next().unwrap_or_else(|| usage())
}

/// Parse the option words shared by addprinc/modprinc; returns the options
/// and the remaining positional arguments.
fn principal_options(args: Vec<String>, randkey: &mut bool) -> (PrincipalOptions, Vec<String>) {
    let mut opts = PrincipalOptions::default();
    let mut attrs = AttrChange::default();
    let mut rest = Vec::new();
    let mut it = args.into_iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "-randkey" => *randkey = true,
            "-maxlife" => opts.max_life = Some(ok(parse_lifetime(&next(&mut it)))),
            "-maxrenewlife" => opts.max_renewable_life = Some(ok(parse_lifetime(&next(&mut it)))),
            "-expire" => opts.expiration = Some(ok(parse_time(&next(&mut it)))),
            "-pwexpire" => opts.pw_expiration = Some(ok(parse_time(&next(&mut it)))),
            "-allow_delegate_to" => opts.delegate_to.push(next(&mut it)),
            "-allow_delegate_from" => opts.delegate_from.push(next(&mut it)),
            "-clear_delegate_to" => opts.clear_delegate_to = true,
            "-clear_delegate_from" => opts.clear_delegate_from = true,
            "-policy" => opts.policy = Some(Some(next(&mut it))),
            "-clearpolicy" => opts.policy = Some(None),
            "-unlock" => opts.unlock = true,
            s if s.starts_with('+')
                || (s.starts_with('-') && s.len() > 1 && !s.starts_with("-r")) =>
            {
                ok(attrs.add_spec(s))
            }
            _ => rest.push(a),
        }
    }
    opts.attributes = attrs;
    (opts, rest)
}

fn main() {
    run();
    // kadm5_destroy: close the modules (their `fini`) before exiting.
    drop(admin_modules().take());
    std::process::exit(exit_status());
}

fn run() {
    let mut config: Option<PathBuf> = std::env::var_os("KRB5_KDC_PROFILE").map(PathBuf::from);
    let mut krb5_config: Option<PathBuf> = std::env::var_os("KRB5_CONFIG").map(PathBuf::from);
    let mut realm: Option<String> = None;
    let mut master_password_file: Option<String> = None;
    let mut database: Option<PathBuf> = None;
    let mut db_args: Vec<String> = Vec::new();
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    while let Some(first) = args.first().map(String::as_str) {
        match first {
            "--help" | "-h" => help(),
            "--config"
            | "--krb5-config"
            | "--realm"
            | "-r"
            | "-d"
            | "-x"
            | "--master-password-file" => {
                if args.len() < 2 {
                    usage();
                }
                let value = args.remove(1);
                match args.remove(0).as_str() {
                    "--config" => config = Some(PathBuf::from(value)),
                    "--krb5-config" => krb5_config = Some(PathBuf::from(value)),
                    "--realm" | "-r" => realm = Some(value),
                    "-d" => database = Some(PathBuf::from(value)),
                    "-x" => db_args.push(value),
                    _ => master_password_file = Some(value),
                }
            }
            _ => break,
        }
    }
    if args.is_empty() {
        usage();
    }
    let cmd = args.remove(0);
    // MIT kdb5_util takes -r, -d and -x anywhere (kpropd runs `load -d DB`).
    let mut i = 0;
    while i < args.len() {
        if matches!(args[i].as_str(), "-r" | "-d" | "-x") && i + 1 < args.len() {
            let value = args.remove(i + 1);
            match args.remove(i).as_str() {
                "-r" => realm = Some(value),
                "-d" => database = Some(PathBuf::from(value)),
                _ => db_args.push(value),
            }
        } else {
            i += 1;
        }
    }

    let config = config.unwrap_or_else(|| PathBuf::from("/usr/local/var/krb5kdc/kdc.conf"));
    // A missing kdc.conf leaves the defaults, as in MIT's profile library.
    let kdc_conf = if config.exists() {
        ok(Profile::load(&config).map_err(|e| format!("reading {}: {e}", config.display())))
    } else {
        ok(Profile::parse(""))
    };
    let krb5 = krb5_config
        .filter(|p| p.exists())
        .map(|p| ok(Profile::load(&p)));
    let realm = realm
        .or_else(|| default_realm(&kdc_conf, krb5.as_ref()))
        .unwrap_or_else(|| {
            fail("Configuration file does not specify default realm while getting default realm")
        });
    let mut cfg = ok(RealmConfig::from_profiles(&kdc_conf, krb5.as_ref(), &realm));
    if let Some(database) = database {
        if kdc_conf
            .get_string(&["realms", &realm, "iprop_logfile"])
            .is_none()
        {
            let mut log = database.clone().into_os_string();
            log.push(".ulog");
            cfg.iprop.logfile = PathBuf::from(log);
        }
        cfg.database_name = database;
    }
    let raw_db_args = db_args.clone();
    let db_args = cfg
        .apply_db_args(&db_args)
        .unwrap_or_else(|e| fail(format!("{e} while initializing database")));
    if KADM5_COMMANDS.contains(&cmd.as_str()) {
        let profiles: Vec<&Profile> = krb5.iter().chain([&kdc_conf]).collect();
        let dict_file = kdc_conf
            .get_string(&["realms", &realm, "dict_file"])
            .map(PathBuf::from);
        let m = modules::load(
            &profiles,
            dict_file.as_deref(),
            modules::logger("krb5-rs-kdb"),
        )
        .unwrap_or_else(|e| fail(e));
        *admin_modules() = Some(m);
    }

    if cfg.db_module.library.as_deref() == Some("kldap") {
        kldap_command(
            &cmd,
            args,
            &cfg,
            &realm,
            master_password_file.as_deref(),
            &raw_db_args,
        );
        return;
    }

    if cfg.db_module.library.as_deref() == Some("klmdb") {
        klmdb_command(
            &cmd,
            args,
            &cfg,
            &realm,
            master_password_file.as_deref(),
            db_args.merge_nra,
        );
        return;
    }

    match cfg.db_module.library.as_deref() {
        None | Some("krb5-rs-file") => {}
        Some("krb5-rs-cockroach") if matches!(cmd.as_str(), "dump" | "load") => fail(format!(
            "`{cmd}` needs db_library = klmdb or the file store"
        )),
        Some("krb5-rs-cockroach") => {
            cockroach_command(&cmd, args, &cfg, &realm, master_password_file.as_deref());
            return;
        }
        Some(other) => fail(format!("unknown db_library {other:?}")),
    }
    if matches!(cmd.as_str(), "database" | "replication") {
        fail(format!("`{cmd}` needs db_library = krb5-rs-cockroach"));
    }

    let iprop = cfg.iprop.enabled.then_some(&cfg.iprop);
    match cmd.as_str() {
        "init" => {
            init(args, &cfg, &realm, master_password_file.as_deref());
            return;
        }
        "create" => {
            let stash = args.iter().any(|a| a == "-s");
            let key = create_master_key(&cfg, &realm, master_password_file.as_deref());
            let etypes: Vec<i32> = cfg.supported_keysalts.iter().map(|(e, _)| *e).collect();
            let store = FileStore::create_with(&cfg.database_name, &realm, &key, &etypes)
                .unwrap_or_else(|e| {
                    fail(format!(
                        "{e} while creating database '{}'",
                        cfg.database_name.display()
                    ))
                });
            let admin =
                krb5_rs::kdc::kdb::admin::Admin::new(&store, cfg.supported_keysalts.clone());
            for (name, attrs, life) in ADMIN_PRINCS {
                let (name, r) = ok(parse_principal(name, &realm));
                ok(admin.add_principal(&name, &r, None, &admin_princ_options(attrs, life)));
            }
            if stash {
                ok(write_stash(&cfg.key_stash_file, &realm, &key));
            }
            // As for klmdb, the new database's principals are not logged.
            if cfg.iprop.enabled {
                ok(Ulog::map(&cfg.iprop.logfile, cfg.iprop.ulogsize));
            }
            return;
        }
        "stash" => {
            let (keyfile, key) =
                stash_source(&args, &cfg, &realm, master_password_file.as_deref(), |k| {
                    FileStore::open(&cfg.database_name, k)
                });
            let keys = ok(key.master_key_list());
            ok(write_stash_list(&keyfile, &realm, &keys.keys));
            return;
        }
        "add_mkey" | "use_mkey" | "list_mkeys" | "purge_mkeys" | "update_princ_encryption" => {
            mkey_command(
                &cmd,
                args,
                &cfg,
                &realm,
                master_password_file.as_deref(),
                |k| open_file(&cfg, k),
            );
            return;
        }
        "dump" => {
            let etype = cfg.master_key_type;
            dump_command(args, iprop, &realm, etype, |convert| {
                let opened = match fetch_master(&cfg, &realm, master_password_file.as_deref()) {
                    Some(key) => match FileStore::open(&cfg.database_name, &key) {
                        Ok(store) => Some(store),
                        Err(e) if convert && wrong_master_key(&e) => {
                            no_master_list(&e);
                            None
                        }
                        Err(e) => return Err(e),
                    },
                    None if convert => None,
                    None => std::process::exit(exit_status()),
                };
                let store = match opened {
                    Some(store) => store,
                    None => {
                        keyboard_master(&realm, etype, |k| FileStore::open(&cfg.database_name, k))
                    }
                };
                let keys = if convert {
                    Some(store.master_key_list()?)
                } else {
                    None
                };
                Ok((store.dump_entries()?, keys))
            });
            return;
        }
        "load" => {
            // `load -i` and `-x merge_nra` keep the lockout fields of
            // principals already in the database (`dump.c:1498`,
            // `kdb_db2.c:1515`).
            let merge_nra = db_args.merge_nra;
            load_command(
                args,
                iprop,
                |entries, policies, update, iprop_load, log_from| {
                    let master = master_key(&cfg, &realm, master_password_file.as_deref());
                    FileStore::load_dump(
                        &cfg.database_name,
                        &realm,
                        &master,
                        entries,
                        policies,
                        update,
                        iprop_load || merge_nra,
                        iprop.map(|c| (c, log_from)),
                    )
                },
            );
            return;
        }
        _ => {}
    }

    let master = master_key(&cfg, &realm, master_password_file.as_deref());
    let store = ok(open_file(&cfg, &master));
    let admin = Blocking::new(
        runtime(),
        &store,
        cfg.supported_keysalts.clone(),
        cfg.master_key_type,
    );
    run_admin(&admin, &cmd, args, &realm);
}

/// The file store, logging writes to the update log when iprop is enabled.
fn open_file(
    cfg: &RealmConfig,
    master: &krb5_rs::types::EncryptionKey,
) -> Result<FileStore, StoreError> {
    FileStore::open(&cfg.database_name, master)?.with_iprop(&cfg.iprop)
}

type DumpEntries = (Vec<MitEntry>, Vec<MitPolicy>);

/// `kdb5_util dump` (`kadmin/dbutil/dump.c:1137-1362`). `iprop` is set
/// when `iprop_enable` is. `read(mkey_convert)` returns the entries, and
/// with `-mkey_convert` the master-key list. Deviation: `-rev` and
/// `-recurse` are accepted and ignored (klmdb iterates in key order).
fn dump_command(
    args: Vec<String>,
    iprop: Option<&IpropConfig>,
    realm: &str,
    master_key_type: i32,
    read: impl FnOnce(bool) -> Result<(DumpEntries, Option<MasterKeys>), StoreError>,
) {
    use krb5_rs::kdc::kdb::mit::mkey::{add_new_mkey, convert_entry, next_kvno};

    let mut version = DumpVersion::R111;
    let mut verbose = false;
    let (mut mkey_convert, mut new_mkey_file) = (false, None);
    let (mut iprop_dump, mut conditional) = (None, false);
    let mut it = args.into_iter().peekable();
    while let Some(arg) = it.next_if(|a| a.starts_with('-') && a != "-") {
        match arg.as_str() {
            "-b7" => version = DumpVersion::Beta7,
            "-r13" => version = DumpVersion::R13,
            "-r18" => version = DumpVersion::R18,
            "-ov" => fail("OV dump format not supported"),
            "-c" => conditional = true,
            "-rev" | "-recurse" => {}
            "-verbose" => verbose = true,
            "-mkey_convert" => mkey_convert = true,
            "-new_mkey_file" => {
                new_mkey_file = it.next();
                mkey_convert = true;
            }
            a if a.starts_with("-i") => {
                if iprop.is_none() {
                    fail("Iprop not enabled");
                }
                let digits: String = a[2..].chars().take_while(char::is_ascii_digit).collect();
                iprop_dump = Some(digits.parse::<u64>().map_or(!digits.is_empty(), |n| n != 0));
            }
            _ => usage(),
        }
    }
    let file = it.next().filter(|f| f != "-");
    let names: Vec<regex::Regex> = it
        .map(|n| {
            regex::Regex::new(&format!("^(?:{n})$"))
                .unwrap_or_else(|e| fail(format!("regular expression error: {e}")))
        })
        .collect();
    let ulog = iprop_dump
        .and(iprop)
        .map(|c| ok(Ulog::map(&c.logfile, c.ulogsize)));
    if let (Some(file), true) = (&file, conditional) {
        let Some(ulog) = &ulog else {
            fail("Conditional dump is an undocumented option for use only for iprop dumps")
        };
        if dump_is_current(Path::new(file), ulog) {
            return;
        }
    }
    let ((entries, policies), keys) = ok(read(mkey_convert));
    let is_km = |e: &MitEntry| e.principal == km_principal() && e.realm == realm;
    let convert = keys.map(|keys| {
        let new = new_master_key(realm, master_key_type, new_mkey_file.as_deref());
        // `get_next_kvno(master_entry)`, before K/M itself is converted.
        let kvno = entries.iter().find(|e| is_km(e)).map_or(1, next_kvno);
        (keys, new, kvno)
    });
    let (mut out, policy_version) = match (iprop_dump, &ulog) {
        (Some(extensible), Some(ulog)) => {
            let last = ulog
                .get_last()
                .unwrap_or_else(|e| fail(format!("{e} while reading update log header")));
            let header = IpropHeader {
                extensible,
                sno: last.sno,
                seconds: last.time.seconds,
                useconds: last.time.useconds,
            };
            (header.line().into_bytes(), header.policy_version())
        }
        _ => (version.header().as_bytes().to_vec(), version),
    };
    let dump_name = match iprop_dump {
        Some(true) => "Kerberos iprop extensible version",
        Some(false) => "Kerberos iprop version",
        None => version.name(),
    };
    for mut entry in entries {
        let name = unparse_name(&entry.principal, &entry.realm);
        let name = String::from_utf8_lossy(&name).into_owned();
        // `master_key_convert` (`dump.c:83-129`) runs on every entry, before
        // the name match.
        if let Some((keys, new, kvno)) = &convert {
            let converted = if is_km(&entry) {
                add_new_mkey(&mut entry, keys, new).map(drop)
            } else {
                convert_entry(&mut entry, keys, *kvno, new)
            };
            if let Err(e) = converted {
                com_err(format!(
                    "{} while converting {name} to new master key",
                    e.message()
                ));
                if file.is_none() {
                    let _ = std::io::stdout().write_all(&out);
                }
                fail(format!("{} performing {dump_name} dump", e.message()));
            }
        }
        if !names.is_empty() && !names.iter().any(|r| r.is_match(&name)) {
            continue;
        }
        if iprop_dump.is_some() {
            let mut replicated = entry.clone();
            replicated.last_success = 0;
            replicated.last_failed = 0;
            replicated.fail_auth_count = 0;
            out.extend(principal_record(&replicated, DumpVersion::R111));
        } else {
            out.extend(principal_record(&entry, version));
        }
        if verbose {
            eprintln!("{name}");
        }
    }
    if names.is_empty() {
        for policy in &policies {
            out.extend(policy_record(policy, policy_version));
        }
    }
    match file {
        None => ok(std::io::stdout().write_all(&out)),
        Some(file) => ok(write_dump_file(Path::new(&file), &out)
            .map_err(|e| format!("{e} while opening {file} for writing"))),
    }
}

/// `dump -mkey_convert` without a valid master key reads it once from the
/// keyboard (`dump.c:1247-1261`).
fn keyboard_master<T>(
    realm: &str,
    etype: i32,
    open: impl FnOnce(&krb5_rs::types::EncryptionKey) -> Result<T, StoreError>,
) -> T {
    let password = read_password("Enter KDC database master key", "reading master key");
    let key = ok(master_key_from_password(realm, &password, etype));
    open(&key).unwrap_or_else(|e| {
        com_err(format!("{} while verifying master key", e.message()));
        std::process::exit(1)
    })
}

/// `dump -mkey_convert`'s new master key (`dump.c:1263-1290`): the newest
/// key of the `-new_mkey_file` stash, else a password read twice.
fn new_master_key(realm: &str, etype: i32, file: Option<&str>) -> krb5_rs::types::EncryptionKey {
    let Some(file) = file else {
        println!("Please enter new master key....");
        let context = "reading new master key";
        let password = read_password("Enter KDC database master key", context);
        let again = read_password("Re-enter KDC database master key to verify", context);
        if password != again {
            com_err(format!("Password mismatch while {context}"));
            std::process::exit(1);
        }
        return ok(master_key_from_password(realm, &password, etype));
    };
    let fetched = std::fs::metadata(file)
        .map_err(|e| com_err_text(&e.to_string()))
        .and_then(|_| {
            read_stash_kvno(Path::new(file), realm).map_err(|e| com_err_text(e.message()))
        });
    fetched.map(|(_, key)| key).unwrap_or_else(|reason| {
        com_err(format!(
            "Can not fetch master key (error: {reason}). while reading new master key"
        ));
        std::process::exit(1)
    })
}

/// `current_dump_sno_in_ulog` (`kadmin/dbutil/dump.c:1107-1135`).
fn dump_is_current(path: &Path, ulog: &Ulog) -> bool {
    let Ok(file) = std::fs::File::open(path) else {
        return false;
    };
    let mut line = Vec::new();
    if std::io::BufReader::new(std::io::Read::take(file, 8192))
        .read_until(b'\n', &mut line)
        .is_err()
    {
        return false;
    }
    let Ok(header) = IpropHeader::parse(&line) else {
        return false;
    };
    let last = Last {
        sno: header.sno,
        time: Time {
            seconds: header.seconds,
            useconds: header.useconds,
        },
    };
    matches!(
        ulog.get_sno_status(&last),
        UpdateStatus::Ok | UpdateStatus::Nil
    )
}

/// `create_ofile`/`finish_ofile` and the `.dump_ok` stamp
/// (`kadmin/dbutil/dump.c:111-210`).
fn write_dump_file(path: &Path, data: &[u8]) -> std::io::Result<()> {
    let ok_file = appended_path(path, ".dump_ok");
    private_file(&ok_file, false)?;
    let temp = appended_path(path, &format!("-{:06}", std::process::id() % 1_000_000));
    let result = private_file(&temp, true).and_then(|mut f| {
        f.write_all(data)?;
        f.sync_all()?;
        std::fs::rename(&temp, path)
    });
    if result.is_err() {
        let _ = std::fs::remove_file(&temp);
    }
    result?;
    private_file(&ok_file, false)?.write_all(&[0])
}

fn private_file(path: &Path, new: bool) -> std::io::Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true);
    if new {
        options.create_new(true);
    } else {
        options.create(true).truncate(true);
    }
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    options.open(path)
}

/// `kdb5_util load` (`kadmin/dbutil/dump.c:1384-1610`). The whole dump is
/// parsed before the database is touched. `-hash` selects db2's hash
/// format in MIT and is ignored here. With `iprop` set, the ulog is
/// reinitialized after a full load and `-i` records the dump's serial number
/// in it. An `-update` load leaves the ulog to the store, which logs each
/// principal after the dump's last policy (`kdb5.c:981-1051, 2441-2525`).
fn load_command(
    args: Vec<String>,
    iprop: Option<&IpropConfig>,
    store: impl FnOnce(&[MitEntry], &[MitPolicy], bool, bool, usize) -> Result<(), StoreError>,
) {
    let (mut forced, mut verbose, mut update, mut iprop_load) = (None, false, false, false);
    let mut it = args.into_iter();
    while it.len() > 1 {
        match it.next().as_deref() {
            Some("-b7") => forced = Some(DumpVersion::Beta7),
            Some("-r13") => forced = Some(DumpVersion::R13),
            Some("-r18") => forced = Some(DumpVersion::R18),
            Some("-ov") => fail("OV dump format not supported"),
            Some("-i") if iprop.is_some() => iprop_load = true,
            Some("-i") => fail("Iprop not enabled"),
            Some("-verbose") => verbose = true,
            Some("-update") => update = true,
            Some("-hash") => {}
            _ => usage(),
        }
    }
    let Some(file) = it.next() else { usage() };
    let data = std::fs::read(&file).unwrap_or_else(|e| fail(format!("{e} while opening {file}")));
    let mut iprop_header = None;
    let loaded = if iprop_load {
        let end = data
            .iter()
            .position(|b| *b == b'\n')
            .map_or(data.len(), |i| i + 1);
        let (line, body) = data.split_at(end);
        if !line.starts_with(b"iprop") {
            fail(format!("dump header bad in {file}"));
        }
        let header = IpropHeader::parse(line).unwrap_or_else(|message| {
            if !message.is_empty() {
                com_err(message);
            }
            std::process::exit(1)
        });
        iprop_header = Some(header);
        let version = header.policy_version();
        read_records(body, &file, version).map(|(r, w)| (version, r, w))
    } else {
        read_dump(&data, &file, forced)
    };
    let restore_name = |version: DumpVersion| match iprop_header {
        Some(h) if h.extensible => "Kerberos iprop extensible version",
        Some(_) => "Kerberos iprop version",
        None => version.name(),
    };
    let (version, records, warnings) = match loaded {
        Ok(loaded) => loaded,
        Err(LoadFailure::Header(message)) => fail(message),
        Err(LoadFailure::Record {
            version,
            error,
            warnings,
        }) => {
            for line in warnings
                .iter()
                .chain(error.messages.iter().filter(|m| !m.is_empty()))
            {
                eprintln!("{line}");
            }
            com_err(format!("error processing line {} of {file}", error.line));
            fail(format!("{} restore failed", restore_name(version)));
        }
    };
    for line in &warnings {
        eprintln!("{line}");
    }
    let (mut entries, mut policies) = (Vec::new(), Vec::new());
    let mut log_from = 0;
    for record in records {
        match record {
            Record::Principal(entry) => {
                if verbose {
                    let name = unparse_name(&entry.principal, &entry.realm);
                    eprintln!("{}", String::from_utf8_lossy(&name));
                }
                entries.push(entry);
            }
            Record::Policy(policy) => {
                if verbose {
                    eprintln!("created policy {}", policy.name);
                }
                policies.push(policy);
                log_from = entries.len();
            }
        }
    }
    if let Err(e) = store(&entries, &policies, update, iprop_load, log_from) {
        com_err(e);
        fail(format!("{} restore failed", restore_name(version)));
    }
    if let Some(cfg) = iprop.filter(|_| !update) {
        let reset = Ulog::map(&cfg.logfile, cfg.ulogsize).and_then(|ulog| {
            ulog.init_header()?;
            match iprop_header {
                Some(h) => ulog.set_last(Last {
                    sno: h.sno,
                    time: Time {
                        seconds: h.seconds,
                        useconds: h.useconds,
                    },
                }),
                _ => Ok(()),
            }
        });
        if let Err(e) = reset {
            fail(format!("{e} while reinitializing update log"));
        }
    }
}

#[cfg(feature = "klmdb")]
fn klmdb_command(
    cmd: &str,
    args: Vec<String>,
    cfg: &RealmConfig,
    realm: &str,
    global_master_password_file: Option<&str>,
    merge_nra: bool,
) {
    if matches!(cmd, "database" | "replication") {
        fail(format!("`{cmd}` needs db_library = krb5-rs-cockroach"));
    }
    let rt = runtime();
    let iprop = cfg.iprop.enabled.then_some(&cfg.iprop);
    match cmd {
        "init" => {
            let mut master_file = None;
            let mut stash = false;
            let mut randkeys = Vec::new();
            let mut passwords = Vec::new();
            let mut it = args.into_iter();
            while let Some(arg) = it.next() {
                match arg.as_str() {
                    "--master-password-file" => master_file = Some(next(&mut it)),
                    "--stash" => stash = true,
                    "--randkey" => randkeys.push(next(&mut it)),
                    "--password" => {
                        let spec = next(&mut it);
                        let Some((name, file)) = spec.split_once('=') else {
                            fail("--password expects NAME=FILE");
                        };
                        passwords.push((name.to_string(), file.to_string()));
                    }
                    _ => usage(),
                }
            }
            let master_file = master_file
                .as_deref()
                .or(global_master_password_file)
                .unwrap_or_else(|| fail("init requires --master-password-file"));
            let master = master_key(cfg, realm, Some(master_file));
            let mdb = appended_path(&cfg.database_name, ".mdb");
            let store = if mdb.exists() || cfg.database_name.exists() {
                ok(LmdbStore::open(cfg, &master))
            } else {
                create_klmdb(runtime(), cfg, realm, &master);
                println!("Database {}.mdb created.", cfg.database_name.display());
                ok(LmdbStore::open(cfg, &master))
            };
            if stash && !cfg.key_stash_file.exists() {
                ok(write_stash(&cfg.key_stash_file, realm, &master));
                println!("Stash {} written.", cfg.key_stash_file.display());
            }
            let admin = Blocking::new(
                rt,
                store,
                cfg.supported_keysalts.clone(),
                cfg.master_key_type,
            );
            add_admin_princs(&admin, realm);
            ensure_init_principals(&admin, realm, &randkeys, &passwords);
        }
        "create" => {
            let stash = match args.as_slice() {
                [] => false,
                [flag] if flag == "-s" => true,
                _ => usage(),
            };
            let master = create_master_key(cfg, realm, global_master_password_file);
            create_klmdb(rt, cfg, realm, &master);
            if stash {
                ok(write_stash(&cfg.key_stash_file, realm, &master));
            }
        }
        "stash" => {
            require_klmdb(cfg);
            let (keyfile, store) =
                stash_source(&args, cfg, realm, global_master_password_file, |k| {
                    LmdbStore::open(cfg, k)
                });
            let keys = ok(store.master_key_list());
            ok(write_stash_list(&keyfile, realm, &keys.keys));
        }
        "add_mkey" | "use_mkey" | "list_mkeys" | "purge_mkeys" | "update_princ_encryption" => {
            require_klmdb(cfg);
            mkey_command(cmd, args, cfg, realm, global_master_password_file, |k| {
                LmdbStore::open(cfg, k)
            });
        }
        "dump" => {
            require_klmdb(cfg);
            let store = match fetch_master(cfg, realm, global_master_password_file) {
                Some(key) => match LmdbStore::open(cfg, &key) {
                    Ok(store) => Some(store),
                    Err(e) if no_master_list(&e) => None,
                    Err(e) => fail(e),
                },
                None => None,
            };
            let valid_master_key = store.is_some();
            // Without a master key MIT still dumps: the keys stay encrypted.
            let store = store.unwrap_or_else(|| ok(LmdbStore::open_without_master(cfg)));
            let etype = cfg.master_key_type;
            dump_command(args, iprop, realm, etype, |convert| {
                let keys = match (convert, valid_master_key) {
                    (false, _) => None,
                    (true, true) => Some(store.master_key_list()?),
                    // The environment is already open, so verify the key
                    // against its K/M rather than opening it again.
                    (true, false) => Some(keyboard_master(realm, etype, |k| {
                        let km = store
                            .raw_entry(&km_principal(), realm)?
                            .ok_or_else(|| StoreError::backend(BAD_MASTER))?;
                        MasterKeys::fetch(&km, k)
                    })),
                };
                Ok((store.dump_entries()?, keys))
            });
        }
        "load" => load_command(
            args,
            iprop,
            |entries, policies, update, iprop_load, log_from| {
                LmdbStore::load_dump(
                    cfg,
                    entries,
                    policies,
                    update,
                    iprop_load || merge_nra,
                    log_from,
                )
            },
        ),
        _ => {
            require_klmdb(cfg);
            let master = master_key(cfg, realm, global_master_password_file);
            let store = ok(LmdbStore::open(cfg, &master));
            let admin = Blocking::new(
                rt,
                store,
                cfg.supported_keysalts.clone(),
                cfg.master_key_type,
            );
            run_admin(&admin, cmd, args, realm);
        }
    }
}

#[cfg(not(feature = "klmdb"))]
fn klmdb_command(
    _cmd: &str,
    _args: Vec<String>,
    _cfg: &RealmConfig,
    _realm: &str,
    _global_master_password_file: Option<&str>,
    _merge_nra: bool,
) {
    fail("db_library klmdb needs a krb5-rs-kdb built with the `klmdb` feature");
}

/// `krb5_db_open` in `open_db_and_mkey` (`kdb5_util.c:378-383`): the
/// database must exist before the master key is read.
#[cfg(feature = "klmdb")]
fn require_klmdb(cfg: &RealmConfig) {
    let mdb = appended_path(&cfg.database_name, ".mdb");
    if !mdb.exists() && !ok(FileStore::has_database_magic(&cfg.database_name)) {
        fail(format!(
            "LMDB file {} does not exist while initializing database",
            mdb.display()
        ));
    }
}

#[cfg(feature = "klmdb")]
fn appended_path(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(suffix);
    PathBuf::from(name)
}

/// The admin operations, synchronously, over any store: the commands are the
/// same for the file database and for CockroachDB.
struct Blocking<S: AdminStore> {
    rt: tokio::runtime::Runtime,
    ops: AdminOps<S>,
}

impl<S: AdminStore> Blocking<S> {
    /// `rt` must be the runtime the store was opened on: a database
    /// connection's driver task runs on it and only makes progress while it
    /// is being driven.
    fn new(
        rt: tokio::runtime::Runtime,
        store: S,
        keysalts: Vec<(i32, krb5_rs::crypto::SaltType)>,
        master_key_type: i32,
    ) -> Self {
        Self {
            rt,
            ops: AdminOps::new(store, keysalts)
                .with_history_enctype(master_key_type)
                .with_modules(admin_modules().clone().unwrap_or_else(|| AdminModules {
                    pwqual: std::sync::Arc::new(PwQualModules::none()),
                    hooks: std::sync::Arc::default(),
                })),
        }
    }

    fn add_principal(
        &self,
        n: &krb5_rs::types::PrincipalName,
        r: &str,
        pw: Option<&str>,
        o: &PrincipalOptions,
    ) -> Result<(), StoreError> {
        self.rt.block_on(self.ops.add_principal(n, r, pw, o))
    }

    fn delete_principal(
        &self,
        n: &krb5_rs::types::PrincipalName,
        r: &str,
    ) -> Result<(), StoreError> {
        self.rt.block_on(self.ops.delete_principal(n, r))
    }

    fn change_password(
        &self,
        n: &krb5_rs::types::PrincipalName,
        r: &str,
        pw: Option<&str>,
        keep: bool,
    ) -> Result<u32, StoreError> {
        self.rt.block_on(self.ops.change_password(n, r, pw, keep))
    }

    fn modify_principal(
        &self,
        n: &krb5_rs::types::PrincipalName,
        r: &str,
        o: &PrincipalOptions,
    ) -> Result<(), StoreError> {
        self.rt.block_on(self.ops.modify_principal(n, r, o))
    }

    fn add_policy(&self, p: krb5_rs::kdc::Policy) -> Result<(), StoreError> {
        self.rt.block_on(self.ops.add_policy(p))
    }

    fn modify_policy(&self, n: &str, c: &PolicyChange) -> Result<(), StoreError> {
        self.rt.block_on(self.ops.modify_policy(n, c))
    }

    fn delete_policy(&self, n: &str) -> Result<(), StoreError> {
        self.rt.block_on(self.ops.delete_policy(n))
    }

    fn get_policy(&self, n: &str) -> Result<krb5_rs::kdc::Policy, StoreError> {
        self.rt.block_on(self.ops.get_policy(n))
    }

    fn list_policies(&self) -> Result<Vec<String>, StoreError> {
        self.rt.block_on(self.ops.list_policies())
    }

    fn get_principal(
        &self,
        n: &krb5_rs::types::PrincipalName,
        r: &str,
    ) -> Result<krb5_rs::kdc::PrincipalRecord, StoreError> {
        self.rt.block_on(self.ops.get_principal(n, r))
    }

    fn principal_exists(
        &self,
        n: &krb5_rs::types::PrincipalName,
        r: &str,
    ) -> Result<bool, StoreError> {
        match self.rt.block_on(self.ops.get_principal(n, r)) {
            Ok(_) => Ok(true),
            Err(error) if error.kind() == krb5_rs::kdc::StoreErrorKind::NotFound => Ok(false),
            Err(error) => Err(error),
        }
    }

    fn list_principals(&self) -> Result<Vec<String>, StoreError> {
        self.rt.block_on(self.ops.list_principals())
    }

    fn ktadd(
        &self,
        n: &krb5_rs::types::PrincipalName,
        r: &str,
        keytab: &Path,
        randomize: bool,
    ) -> Result<u32, StoreError> {
        self.rt.block_on(self.ops.ktadd(n, r, keytab, randomize))
    }
}

/// `kdb5_util create` for klmdb (`kdb5_create.c:255-335`): `K/M`, `krbtgt`
/// and the `kadm5_create` principals. As in MIT, the update log is left
/// holding only its dummy entry.
#[cfg(feature = "klmdb")]
fn create_klmdb(
    rt: tokio::runtime::Runtime,
    cfg: &RealmConfig,
    realm: &str,
    master: &krb5_rs::types::EncryptionKey,
) {
    let mut unlogged = cfg.clone();
    unlogged.iprop.enabled = false;
    let store = LmdbStore::create(&unlogged, master).unwrap_or_else(|e| {
        fail(format!(
            "{e} while creating database '{}'",
            cfg.database_name.display()
        ))
    });
    add_admin_princs(
        &Blocking::new(
            rt,
            store,
            cfg.supported_keysalts.clone(),
            cfg.master_key_type,
        ),
        realm,
    );
    if cfg.iprop.enabled {
        ok(Ulog::map(&cfg.iprop.logfile, cfg.iprop.ulogsize));
    }
}

/// `add_admin_princs` (`kadmin/dbutil/kadm5_create.c:139-154`): the
/// principals `kdb5_util create` adds after `K/M` and `krbtgt`, with random
/// keys, attributes and max life (`ADMIN_LIFETIME`, `CHANGEPW_LIFETIME`).
const ADMIN_PRINCS: [(&str, u32, u64); 2] = [
    // DISALLOW_TGT_BASED | LOCKDOWN_KEYS
    ("kadmin/admin", 0x0000_0004 | 0x0080_0000, 60 * 60 * 3),
    // DISALLOW_TGT_BASED | PWCHANGE_SERVICE | LOCKDOWN_KEYS
    (
        "kadmin/changepw",
        0x0000_0004 | 0x0000_2000 | 0x0080_0000,
        60 * 5,
    ),
];

/// `add_admin_princ` (`kadm5_create.c:185-222`).
fn admin_princ_options(attrs: u32, life: u64) -> PrincipalOptions {
    PrincipalOptions {
        attributes: AttrChange {
            set: attrs,
            clear: 0,
        },
        max_life: Some(Some(std::time::Duration::from_secs(life))),
        ..PrincipalOptions::default()
    }
}

/// `add_admin_princs`; an existing principal is kept (`KADM5_DUP`).
fn add_admin_princs<S: AdminStore>(admin: &Blocking<S>, realm: &str) {
    for (name, attrs, life) in ADMIN_PRINCS {
        let (name, r) = ok(parse_principal(name, realm));
        match admin.add_principal(&name, &r, None, &admin_princ_options(attrs, life)) {
            Ok(()) => {}
            Err(e) if e.kind() == StoreErrorKind::Conflict => {}
            Err(e) => fail(format!("{e} while creating principal {name}@{r}")),
        }
    }
}

fn ensure_init_principals<S: AdminStore>(
    admin: &Blocking<S>,
    realm: &str,
    randkeys: &[String],
    passwords: &[(String, String)],
) {
    let opts = PrincipalOptions::default();
    let wanted = randkeys.iter().map(|name| (name.as_str(), None)).chain(
        passwords
            .iter()
            .map(|(name, path)| (name.as_str(), Some(path.as_str()))),
    );
    for (spec, password_file) in wanted {
        let (name, realm) = ok(parse_principal(spec, realm));
        if ok(admin.principal_exists(&name, &realm)) {
            println!("Principal \"{name}@{realm}\" already exists.");
            continue;
        }
        let password = password_file.map(read_secret_file);
        match admin.add_principal(&name, &realm, password.as_deref(), &opts) {
            Ok(()) => println!("Principal \"{name}@{realm}\" created."),
            Err(error) if error.kind() == StoreErrorKind::Conflict => {
                // A concurrent init created it. Under contention the re-read can
                // briefly fail, so retry before reporting what it returned.
                let mut last = admin.principal_exists(&name, &realm);
                for attempt in 1..20u64 {
                    if matches!(last, Ok(true)) {
                        break;
                    }
                    std::thread::sleep(std::time::Duration::from_millis((100 * attempt).min(500)));
                    last = admin.principal_exists(&name, &realm);
                }
                if !matches!(last, Ok(true)) {
                    fail(format!(
                        "{error}; re-check after the conflict returned {last:?}"
                    ));
                }
                println!("Principal \"{name}@{realm}\" already exists.");
            }
            Err(error) => fail(error),
        }
    }
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap_or_else(|e| fail(format!("starting the runtime: {e}")))
}

fn run_admin<S: AdminStore>(admin: &Blocking<S>, cmd: &str, args: Vec<String>, realm: &str) {
    let principal = |s: &str| ok(parse_principal(s, realm));

    match cmd {
        "addprinc" => {
            let mut randkey = false;
            let (opts, rest) = principal_options(args, &mut randkey);
            let [name] = rest.as_slice() else { usage() };
            let (name, r) = principal(name);
            // kadmin.c:1271-1276: a missing policy is only a warning.
            if let Some(Some(p)) = &opts.policy {
                if admin.get_policy(p).is_err() {
                    eprintln!("WARNING: policy \"{p}\" does not exist");
                }
            }
            let password = (!randkey)
                .then(|| read_line(&format!("Enter password for principal \"{name}@{r}\": ")));
            ok(admin.add_principal(&name, &r, password.as_deref(), &opts));
            println!("Principal \"{name}@{r}\" created.");
        }
        "delprinc" => {
            let [name] = args.as_slice() else { usage() };
            let (name, r) = principal(name);
            ok(admin.delete_principal(&name, &r));
            println!("Principal \"{name}@{r}\" deleted.");
        }
        "cpw" => {
            let randkey = args.iter().any(|a| a == "-randkey");
            let keepold = args.iter().any(|a| a == "-keepold");
            let names: Vec<&String> = args.iter().filter(|a| !a.starts_with('-')).collect();
            let [name] = names.as_slice() else { usage() };
            let (name, r) = principal(name);
            let password = (!randkey)
                .then(|| read_line(&format!("Enter password for principal \"{name}@{r}\": ")));
            ok(admin.change_password(&name, &r, password.as_deref(), keepold));
            println!("Password for \"{name}@{r}\" changed.");
        }
        "modprinc" => {
            let mut randkey = false;
            let (opts, rest) = principal_options(args, &mut randkey);
            let [name] = rest.as_slice() else { usage() };
            let (name, r) = principal(name);
            // kadmin.c:1271-1276: a missing policy is only a warning.
            if let Some(Some(p)) = &opts.policy {
                if admin.get_policy(p).is_err() {
                    eprintln!("WARNING: policy \"{p}\" does not exist");
                }
            }
            ok(admin.modify_principal(&name, &r, &opts));
            println!("Principal \"{name}@{r}\" modified.");
        }
        "addpol" => {
            let (change, name) = policy_change(args);
            ok(admin.add_policy(change.into_policy(&name)));
            println!("Policy \"{name}\" created.");
        }
        "modpol" => {
            let (change, name) = policy_change(args);
            ok(admin.modify_policy(&name, &change));
            println!("Policy \"{name}\" modified.");
        }
        "delpol" => {
            let [name] = args.as_slice() else { usage() };
            ok(admin.delete_policy(name));
            println!("Policy \"{name}\" deleted.");
        }
        "getpol" => {
            let terse = args.first().is_some_and(|a| a == "-terse");
            let names: Vec<&String> = args.iter().filter(|a| *a != "-terse").collect();
            let [name] = names.as_slice() else { usage() };
            let p = ok(admin.get_policy(name));
            if terse {
                // kadmin.c:1813-1822 (policy_refcnt is always 0).
                println!(
                    "\"{}\"\t{}\t{}\t{}\t{}\t{}\t0\t{}\t{}\t{}\t{}",
                    p.name,
                    p.pw_max_life,
                    p.pw_min_life,
                    p.pw_min_length,
                    p.pw_min_classes,
                    p.pw_history_num,
                    p.pw_max_fail,
                    p.pw_failcnt_interval,
                    p.pw_lockout_duration,
                    p.allowed_keysalts.as_deref().unwrap_or("-")
                );
            } else {
                print!("{}", format_policy(&p));
            }
        }
        "listpols" => {
            for p in ok(admin.list_policies()) {
                println!("{p}");
            }
        }
        "getprinc" => {
            let [name] = args.as_slice() else { usage() };
            let (name, r) = principal(name);
            let rec = ok(admin.get_principal(&name, &r));
            let mut out = format_principal(&rec);
            // kadmin.c:1543-1546; the policy line is the last one.
            if let Some(p) = &rec.entry.policy {
                if admin.get_policy(p).is_err() {
                    out.truncate(out.len() - 1);
                    out += " [does not exist]\n";
                }
            }
            print!("{out}");
        }
        "listprincs" => {
            for p in ok(admin.list_principals()) {
                println!("{p}");
            }
        }
        "ktadd" => {
            let mut keytab: Option<String> = None;
            let mut randomize = true;
            let mut names = Vec::new();
            let mut it = args.into_iter();
            while let Some(a) = it.next() {
                match a.as_str() {
                    "-k" => keytab = Some(next(&mut it)),
                    "-norandkey" => randomize = false,
                    _ => names.push(a),
                }
            }
            let keytab = keytab.unwrap_or_else(|| usage());
            if names.is_empty() {
                usage();
            }
            for n in names {
                let (name, r) = principal(&n);
                let kvno = ok(admin.ktadd(&name, &r, Path::new(&keytab), randomize));
                println!(
                    "Entry for principal {name}@{r} with kvno {kvno} added to keytab {keytab}."
                );
            }
        }
        _ => usage(),
    }
}

/// Commands against CockroachDB (`db_library = krb5-rs-cockroach`): the
/// kadmin commands, plus `create`, `stash`, `database migrate` and
/// `replication status|prune|wait-applied`.
#[cfg(feature = "cockroach")]
fn cockroach_command(
    cmd: &str,
    mut args: Vec<String>,
    cfg: &RealmConfig,
    realm: &str,
    global_master_password_file: Option<&str>,
) {
    use krb5_rs::kdc::replication::ReplicationTs;
    use krb5_rs_kdb_cockroach::{CockroachConfig, CockroachStore, MigrateOptions, MultiRegion};

    let config = ok(CockroachConfig::from_db_module(&cfg.db_module));
    let rt = runtime();
    let flag = |args: &mut Vec<String>, name: &str| -> Option<String> {
        let at = args.iter().position(|a| a == name)?;
        args.remove(at);
        (at < args.len()).then(|| args.remove(at))
    };
    let switch = |args: &mut Vec<String>, name: &str| -> bool {
        match args.iter().position(|a| a == name) {
            Some(at) => {
                args.remove(at);
                true
            }
            None => false,
        }
    };
    match cmd {
        "init" => {
            let mut subcommand_master_file = None;
            let mut stash = false;
            let mut randkeys = Vec::new();
            let mut passwords = Vec::new();
            let mut it = args.into_iter();
            while let Some(arg) = it.next() {
                match arg.as_str() {
                    "--master-password-file" => {
                        subcommand_master_file = Some(next(&mut it));
                    }
                    "--stash" => stash = true,
                    "--randkey" => randkeys.push(next(&mut it)),
                    "--password" => {
                        let spec = next(&mut it);
                        let Some((name, path)) = spec.split_once('=') else {
                            fail("--password expects NAME=FILE");
                        };
                        passwords.push((name.to_string(), path.to_string()));
                    }
                    _ => usage(),
                }
            }
            let master_file = subcommand_master_file
                .as_deref()
                .or(global_master_password_file)
                .unwrap_or_else(|| fail("init requires --master-password-file"));
            let key = master_key(cfg, realm, Some(master_file));
            let store = ok(rt.block_on(CockroachStore::connect(config, key.clone(), realm)));
            let created = match rt.block_on(store.verify_master()) {
                Ok(()) => false,
                Err(error) if error.kind() == StoreErrorKind::NotFound => {
                    let etypes: Vec<i32> = cfg
                        .supported_keysalts
                        .iter()
                        .map(|(etype, _)| *etype)
                        .collect();
                    match rt.block_on(store.create_realm(&etypes)) {
                        Ok(()) => true,
                        Err(error) if error.kind() == StoreErrorKind::Conflict => {
                            ok(rt.block_on(store.verify_master()));
                            false
                        }
                        Err(error) => fail(error),
                    }
                }
                Err(error) => fail(error),
            };
            if created {
                println!("Realm {realm} created.");
            } else {
                println!("Realm {realm} already exists.");
            }
            if stash && !cfg.key_stash_file.exists() {
                ok(write_stash(&cfg.key_stash_file, realm, &key));
                println!("Stash {} written.", cfg.key_stash_file.display());
            }
            let admin = Blocking::new(
                rt,
                store,
                cfg.supported_keysalts.clone(),
                cfg.master_key_type,
            );
            add_admin_princs(&admin, realm);
            ensure_init_principals(&admin, realm, &randkeys, &passwords);
        }
        "database" => {
            if args.first().map(String::as_str) != Some("migrate") {
                usage();
            }
            args.remove(0);
            let create_roles = switch(&mut args, "--create-roles");
            let multi = switch(&mut args, "--multi-region");
            let primary = flag(&mut args, "--primary-region");
            let regions = flag(&mut args, "--regions");
            if !args.is_empty() {
                usage();
            }
            let multi_region = multi.then(|| MultiRegion {
                primary_region: primary
                    .clone()
                    .unwrap_or_else(|| fail("--multi-region needs --primary-region")),
                regions: regions
                    .as_deref()
                    .unwrap_or("")
                    .split(',')
                    .filter(|r| !r.is_empty())
                    .map(str::to_string)
                    .collect(),
            });
            let report = ok(rt.block_on(CockroachStore::migrate(
                config,
                &MigrateOptions {
                    create_roles,
                    multi_region,
                },
            )));
            println!(
                "Schema version {} -> {}{}{}.",
                report.from,
                report.to,
                if report.roles { ", roles created" } else { "" },
                if report.multi_region {
                    ", multi-region applied"
                } else {
                    ""
                },
            );
        }
        "create" => {
            let stash = args.iter().any(|a| a == "-s");
            let password = read_password(
                "Enter KDC database master key",
                "reading master key from keyboard",
            );
            let key = ok(master_key_from_password(
                realm,
                &password,
                cfg.master_key_type,
            ));
            let etypes: Vec<i32> = cfg.supported_keysalts.iter().map(|(e, _)| *e).collect();
            let store = ok(rt.block_on(CockroachStore::connect(config, key.clone(), realm)));
            ok(rt.block_on(store.create_realm(&etypes)));
            if stash {
                ok(write_stash(&cfg.key_stash_file, realm, &key));
            }
        }
        "stash" => {
            let (keyfile, key) =
                stash_source(&args, cfg, realm, global_master_password_file, |k| {
                    rt.block_on(CockroachStore::open(config.clone(), k.clone(), realm))
                });
            ok(write_stash_list(&keyfile, realm, &key.master_keys().keys));
        }
        "add_mkey" | "use_mkey" | "list_mkeys" | "purge_mkeys" | "update_princ_encryption" => {
            mkey_command(cmd, args, cfg, realm, global_master_password_file, |k| {
                let store = rt.block_on(CockroachStore::open(config.clone(), k.clone(), realm))?;
                Ok(CockroachMkey { rt: &rt, store })
            });
        }
        "replication" => {
            let master = master_key(cfg, realm, global_master_password_file);
            let store = ok(rt.block_on(CockroachStore::open(config, master, realm)));
            let sub = if args.is_empty() {
                usage()
            } else {
                args.remove(0)
            };
            match sub.as_str() {
                "status" => {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(0));
                    println!(
                        "{:<24} {:<16} {:<32} {:>8} {:>8}",
                        "KDC", "REGION", "APPLIED", "LAG(s)", "SEEN(s)"
                    );
                    for s in ok(rt.block_on(store.replica_statuses())) {
                        println!(
                            "{:<24} {:<16} {:<32} {:>8} {:>8}",
                            s.kdc_id,
                            s.region,
                            s.applied_ts,
                            (now - s.applied_ts.wall_time().timestamp()).max(0),
                            (now - s.seen_at).max(0)
                        );
                    }
                }
                "prune" => {
                    let older = flag(&mut args, "--older-than").unwrap_or_else(|| usage());
                    let d = ok(parse_lifetime(&older)).unwrap_or_default();
                    let (cutoff, deleted) = ok(rt.block_on(store.prune(d)));
                    println!("Pruned {deleted} log rows; pruned_before is now {cutoff}.");
                }
                "wait-applied" => {
                    let since: ReplicationTs = flag(&mut args, "--since")
                        .unwrap_or_else(|| usage())
                        .parse()
                        .unwrap_or_else(|e| fail(e));
                    let timeout = flag(&mut args, "--timeout")
                        .map_or(std::time::Duration::from_secs(30), |t| {
                            ok(parse_lifetime(&t)).unwrap_or_default()
                        });
                    let live_within_arg = flag(&mut args, "--live-within");
                    let live_within = live_within_arg
                        .as_deref()
                        .map_or(std::time::Duration::from_secs(2 * 60), |d| {
                            ok(parse_lifetime(d)).unwrap_or_default()
                        });
                    let live_within_text = live_within_arg.as_deref().unwrap_or("2m");
                    let out = ok(rt.block_on(store.wait_applied(since, timeout, live_within)));
                    println!(
                        "{} of {} live KDCs are at or past {since} ({} not seen within {} ignored).",
                        out.applied, out.total, out.stale, live_within_text
                    );
                    if !out.complete() {
                        std::process::exit(1);
                    }
                }
                _ => usage(),
            }
        }
        _ => {
            let master = master_key(cfg, realm, global_master_password_file);
            let store = ok(rt.block_on(CockroachStore::open(config, master, realm)));
            let admin = Blocking::new(
                rt,
                store,
                cfg.supported_keysalts.clone(),
                cfg.master_key_type,
            );
            run_admin(&admin, cmd, args, realm);
        }
    }
}

/// Commands against an LDAP directory (`db_library = kldap`): `create`,
/// `stash` and the kadmin commands.
#[cfg(feature = "kldap")]
fn kldap_command(
    cmd: &str,
    mut args: Vec<String>,
    cfg: &RealmConfig,
    realm: &str,
    master_password_file: Option<&str>,
    db_args: &[String],
) {
    use krb5_rs_kdb_ldap::config::ServerType;
    use krb5_rs_kdb_ldap::create::RealmOptions;
    use krb5_rs_kdb_ldap::LdapStore;
    let rt = runtime();
    match cmd {
        "create" => {
            let stash = args.iter().any(|a| a == "-s");
            let key = create_master_key(cfg, realm, master_password_file);
            let store = rt
                .block_on(LdapStore::create_realm(
                    cfg,
                    db_args,
                    &key,
                    &RealmOptions::default(),
                ))
                .unwrap_or_else(|e| fail(format!("{e} while creating realm '{realm}'")));
            let admin = Blocking::new(
                rt,
                store,
                cfg.supported_keysalts.clone(),
                cfg.master_key_type,
            );
            add_admin_princs(&admin, realm);
            if stash {
                ok(write_stash(&cfg.key_stash_file, realm, &key));
            }
        }
        "stash" => {
            let keyfile = match args.iter().position(|a| a == "-f") {
                Some(at) if at + 1 < args.len() => PathBuf::from(args.remove(at + 1)),
                Some(_) => usage(),
                None => cfg.key_stash_file.clone(),
            };
            let key = master_key(cfg, realm, master_password_file);
            // The key must decrypt K/M (`krb5_db_fetch_mkey_list`).
            rt.block_on(LdapStore::open(cfg, db_args, ServerType::Admin, &key))
                .unwrap_or_else(|e| fail(format!("{e} while getting master key list")));
            ok(write_stash(&keyfile, realm, &key));
        }
        "dump" => {
            dump_command(args, None, realm, cfg.master_key_type, |convert| {
                let key = fetch_master(cfg, realm, master_password_file)
                    .unwrap_or_else(|| std::process::exit(exit_status()));
                let store = rt.block_on(LdapStore::open(cfg, db_args, ServerType::Admin, &key))?;
                let entries = rt.block_on(store.dump_entries())?;
                Ok((entries, convert.then(|| store.master_keys())))
            });
        }
        // kldap refuses the "temporary" database a full load creates
        // (ldap_misc.c:215, dump.c:1505).
        "load" if !args.iter().any(|a| a == "-update") => {
            fail("KDB module requires -update argument while creating database")
        }
        "load" => load_command(args, None, |entries, policies, _, _, _| {
            let master = master_key(cfg, realm, master_password_file);
            let store = rt.block_on(LdapStore::open(cfg, db_args, ServerType::Admin, &master))?;
            rt.block_on(store.load_update(entries, policies))
        }),
        // `krb5_ldap_delete_realm_1` returns KRB5_PLUGIN_OP_NOTSUPP.
        "destroy" => fail("LDAP Plugin does not support the operation while destroying database"),
        "ark"
        | "add_mkey"
        | "use_mkey"
        | "list_mkeys"
        | "update_princ_encryption"
        | "purge_mkeys"
        | "tabdump" => fail(format!("`{cmd}` is not supported with db_library = kldap")),
        _ => {
            let master = master_key(cfg, realm, master_password_file);
            let store = rt
                .block_on(LdapStore::open(cfg, db_args, ServerType::Admin, &master))
                .unwrap_or_else(|e| fail(format!("{e} while initializing database")));
            let admin = Blocking::new(
                rt,
                store,
                cfg.supported_keysalts.clone(),
                cfg.master_key_type,
            );
            run_admin(&admin, cmd, args, realm);
        }
    }
}

#[cfg(not(feature = "kldap"))]
fn kldap_command(
    _cmd: &str,
    _args: Vec<String>,
    _cfg: &RealmConfig,
    _realm: &str,
    _master_password_file: Option<&str>,
    _db_args: &[String],
) {
    fail("db_library kldap needs a krb5-rs-kdb built with the `kldap` feature");
}

#[cfg(not(feature = "cockroach"))]
fn cockroach_command(
    _cmd: &str,
    _args: Vec<String>,
    _cfg: &RealmConfig,
    _realm: &str,
    _global_master_password_file: Option<&str>,
) {
    fail("db_library krb5-rs-cockroach needs a krb5-rs-kdb built with the `cockroach` feature");
}

fn km_principal() -> krb5_rs::types::PrincipalName {
    krb5_rs::types::PrincipalName {
        name_type: 1,
        name_string: [b"K", b"M"]
            .iter()
            .map(|s| ok(krb5_rs::types::KerberosString::from_bytes(*s)))
            .collect(),
    }
}

/// MIT `strdate` (`kdb5_mkey.c:29-40`).
#[allow(deprecated)] // libc::time_t on musl
fn strdate(when: u32) -> String {
    let t = libc::time_t::from(when);
    let mut out = [0u8; 40];
    // SAFETY: `tm` is plain data filled by `localtime_r`; `strftime` writes at
    // most `out.len()` bytes and the format is NUL-terminated.
    let n = unsafe {
        let mut tm: libc::tm = std::mem::zeroed();
        if libc::localtime_r(&t, &mut tm).is_null() {
            0
        } else {
            libc::strftime(
                out.as_mut_ptr().cast(),
                out.len(),
                c"%a %b %d %H:%M:%S %Z %Y".as_ptr(),
                &tm,
            )
        }
    };
    if n == 0 {
        "(error)".to_string()
    } else {
        String::from_utf8_lossy(&out[..n]).into_owned()
    }
}

/// MIT `are_you_sure` (`kdb5_mkey.c:805-826`).
fn confirm(question: &str) -> bool {
    print!("{question}\n(type 'yes' to confirm)? ");
    let _ = std::io::stdout().flush();
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line).unwrap_or(0) > 0 && line == "yes\n"
}

/// Shell glob as MIT `glob_to_regexp` converts it: `?`, `*`, `[...]`
/// (regex bracket syntax) and `\\` quoting.
fn glob_match(p: &[u8], s: &[u8]) -> bool {
    match p.first() {
        None => s.is_empty(),
        Some(b'*') => (0..=s.len()).any(|i| glob_match(&p[1..], &s[i..])),
        Some(b'?') => !s.is_empty() && glob_match(&p[1..], &s[1..]),
        Some(b'\\') if p.len() > 1 => s.first() == Some(&p[1]) && glob_match(&p[2..], &s[1..]),
        Some(b'[') => {
            let neg = p.get(1) == Some(&b'^');
            let start = if neg { 2 } else { 1 };
            let mut end = start;
            if p.get(end) == Some(&b']') {
                end += 1;
            }
            while end < p.len() && p[end] != b']' {
                end += 1;
            }
            if end >= p.len() {
                return s.first() == Some(&b'[') && glob_match(&p[1..], &s[1..]);
            }
            let Some(&c) = s.first() else {
                return false;
            };
            let set = &p[start..end];
            let mut hit = false;
            let mut k = 0;
            while k < set.len() {
                if k + 2 < set.len() && set[k + 1] == b'-' {
                    hit |= set[k] <= c && c <= set[k + 2];
                    k += 3;
                } else {
                    hit |= set[k] == c;
                    k += 1;
                }
            }
            hit != neg && glob_match(&p[end + 1..], &s[1..])
        }
        Some(c) => s.first() == Some(c) && glob_match(&p[1..], &s[1..]),
    }
}

fn entry_display_name(entry: &MitEntry) -> String {
    let mut name = unparse_name(&entry.principal, &entry.realm);
    if name.last() == Some(&0) {
        name.pop();
    }
    String::from_utf8_lossy(&name).into_owned()
}

/// Single-letter getopt flags (`-fnv` style); returns the operands.
fn mkey_flags(args: Vec<String>, allowed: &str, flags: &mut [bool]) -> Vec<String> {
    let mut operands = Vec::new();
    for a in args {
        if operands.is_empty() && a.len() > 1 && a.starts_with('-') {
            for c in a[1..].chars() {
                match allowed.find(c) {
                    Some(i) => flags[i] = true,
                    None => usage(),
                }
            }
        } else {
            operands.push(a);
        }
    }
    operands
}

/// The database operations the master-key commands need: MIT's
/// `krb5_db_fetch_mkey_list`, `krb5_db_iterate` and `krb5_db_get_principal`
/// + `krb5_db_put_principal` on entries whose keys stay encrypted.
trait MkeyStore {
    fn master_key_list(&self) -> Result<MasterKeys, StoreError>;
    fn raw_entries(&self) -> Result<Vec<MitEntry>, StoreError>;
    fn update_raw<F>(
        &self,
        name: &krb5_rs::types::PrincipalName,
        realm: &str,
        f: F,
    ) -> Result<bool, StoreError>
    where
        F: FnMut(&mut MitEntry, &MasterKeys) -> Result<bool, StoreError> + Send;
}

#[cfg(feature = "klmdb")]
impl MkeyStore for LmdbStore {
    fn master_key_list(&self) -> Result<MasterKeys, StoreError> {
        LmdbStore::master_key_list(self)
    }
    fn raw_entries(&self) -> Result<Vec<MitEntry>, StoreError> {
        LmdbStore::raw_entries(self)
    }
    fn update_raw<F>(
        &self,
        name: &krb5_rs::types::PrincipalName,
        realm: &str,
        f: F,
    ) -> Result<bool, StoreError>
    where
        F: FnMut(&mut MitEntry, &MasterKeys) -> Result<bool, StoreError> + Send,
    {
        LmdbStore::update_raw(self, name, realm, f)
    }
}

impl MkeyStore for FileStore {
    fn master_key_list(&self) -> Result<MasterKeys, StoreError> {
        FileStore::master_key_list(self)
    }
    fn raw_entries(&self) -> Result<Vec<MitEntry>, StoreError> {
        FileStore::raw_entries(self)
    }
    fn update_raw<F>(
        &self,
        name: &krb5_rs::types::PrincipalName,
        realm: &str,
        f: F,
    ) -> Result<bool, StoreError>
    where
        F: FnMut(&mut MitEntry, &MasterKeys) -> Result<bool, StoreError> + Send,
    {
        FileStore::update_raw(self, name, realm, f)
    }
}

/// A CockroachDB realm driven from the synchronous command code.
#[cfg(feature = "cockroach")]
struct CockroachMkey<'a> {
    rt: &'a tokio::runtime::Runtime,
    store: krb5_rs_kdb_cockroach::CockroachStore,
}

#[cfg(feature = "cockroach")]
impl MkeyStore for CockroachMkey<'_> {
    fn master_key_list(&self) -> Result<MasterKeys, StoreError> {
        self.rt.block_on(self.store.verify_master())?;
        Ok(self.store.master_keys())
    }
    fn raw_entries(&self) -> Result<Vec<MitEntry>, StoreError> {
        self.rt.block_on(self.store.raw_entries())
    }
    fn update_raw<F>(
        &self,
        name: &krb5_rs::types::PrincipalName,
        realm: &str,
        f: F,
    ) -> Result<bool, StoreError>
    where
        F: FnMut(&mut MitEntry, &MasterKeys) -> Result<bool, StoreError> + Send,
    {
        self.rt.block_on(self.store.update_raw(name, realm, f))
    }
}

/// The master-key commands without a master-key list
/// (`kdb5_mkey.c:353-370, 540-545, 866-870, 1020-1027`). MIT's `add_mkey`
/// fails an assertion here instead.
fn no_master_keylist(cmd: &str, args: &[String]) -> ! {
    match cmd {
        "use_mkey" => {
            if args.is_empty() || args.len() > 2 {
                usage();
            }
            let kvno = args[0].trim().parse::<i64>().unwrap_or(0);
            fail(format!("Invalid argument {kvno} is an invalid KVNO value"))
        }
        "purge_mkeys" => fail("Database has not been initialized master keylist not initialized"),
        _ => fail("master keylist not initialized"),
    }
}

/// MIT `kdb5_util` master-key commands (`kadmin/dbutil/kdb5_mkey.c`).
/// `open` opens the database with the key from the stash or password file.
fn mkey_command<S: MkeyStore>(
    cmd: &str,
    args: Vec<String>,
    cfg: &RealmConfig,
    realm: &str,
    global_master_password_file: Option<&str>,
    open: impl FnOnce(&krb5_rs::types::EncryptionKey) -> Result<S, StoreError>,
) {
    use krb5_rs::kdc::kdb::mit::mkey::{
        add_new_mkey, convert_entry, entry_mkvno, lookup_actkvno, now, purge_mkeys, update_actkvno,
        use_mkey,
    };
    use krb5_rs::kdc::kdb::mit::set_mod_princ;

    let opened = fetch_master_kvno(cfg, realm, global_master_password_file).and_then(
        |(stash_kvno, master)| match open(&master) {
            Ok(store) => Some((store, stash_kvno)),
            Err(e) if no_master_list(&e) => None,
            Err(e) => fail(e),
        },
    );
    let Some((store, stash_kvno)) = opened else {
        no_master_keylist(cmd, &args)
    };
    let keys = ok(store.master_key_list());
    let km = km_principal();
    let fullname = format!("K/M@{realm}");
    let modifier = fullname.clone().into_bytes();
    let now = now();
    match cmd {
        "add_mkey" => {
            let mut etype = cfg.master_key_type;
            let mut stash = false;
            let mut it = args.into_iter();
            while let Some(a) = it.next() {
                match a.as_str() {
                    "-e" => {
                        let name = next(&mut it);
                        etype = krb5_rs::crypto::enctype_from_name(&name).unwrap_or_else(|| {
                            fail(format!("Invalid argument {name} is an invalid enctype"))
                        });
                    }
                    "-s" => stash = true,
                    _ => usage(),
                }
            }
            println!("Creating new master key for master key principal '{fullname}'");
            println!("You will be prompted for a new database Master Password.");
            println!("It is important that you NOT FORGET this password.");
            let _ = std::io::stdout().flush();
            let context = "reading new master key from keyboard";
            let password = read_password("Enter KDC database master key", context);
            let again = read_password("Re-enter KDC database master key to verify", context);
            if password != again {
                fail("Password mismatch while reading new master key from keyboard");
            }
            let new = ok(master_key_from_password(realm, &password, etype));
            let mut kvno = 0;
            ok(store.update_raw(&km, realm, |entry, keys| {
                kvno = add_new_mkey(entry, keys, &new)?;
                set_mod_princ(entry, now, &modifier)?;
                Ok(true)
            }));
            if stash {
                if let Err(e) = write_stash_list(&cfg.key_stash_file, realm, &[(kvno, new)]) {
                    com_err(format!("{e} while storing key"));
                    println!("Warning: couldn't stash master key.");
                }
            }
        }
        "use_mkey" => {
            if args.is_empty() || args.len() > 2 {
                usage();
            }
            let requested = args[0].trim().parse::<i64>().unwrap_or(0);
            if requested == 0 {
                fail("Invalid argument 0 is an invalid KVNO value");
            }
            let kvno = u16::try_from(requested)
                .ok()
                .filter(|kvno| keys.get(*kvno).is_some())
                .unwrap_or_else(|| {
                    fail(format!(
                        "Invalid argument {requested} is an invalid KVNO value"
                    ))
                });
            let start = match args.get(1) {
                None => now,
                Some(s) => krb5_rs::kdc::kdb::getdate::get_date(s)
                    .or_else(|| parse_time(s).ok().map(|t| t.map_or(0, |t| t.timestamp())))
                    .and_then(|t| u32::try_from(t).ok())
                    .unwrap_or_else(|| fail(format!("could not parse date-time string '{s}'"))),
            };
            ok(store.update_raw(&km, realm, |entry, _| {
                let mut list = lookup_actkvno(entry)?;
                use_mkey(&mut list, kvno, start, now)?;
                update_actkvno(entry, &list);
                set_mod_princ(entry, now, &modifier)?;
                Ok(true)
            }));
        }
        "list_mkeys" => {
            if !args.is_empty() {
                usage();
            }
            let active = keys.find_actkvno(now);
            println!("Master keys for Principal: {fullname}");
            for (kvno, key) in &keys.keys {
                let enctype = krb5_rs::crypto::enctype_name(key.keytype)
                    .unwrap_or_else(|| fail("while getting enctype description"));
                let act = keys.actkvno.iter().find(|a| a.kvno == *kvno);
                if Some(*kvno) == active {
                    let when = strdate(act.map_or(u32::MAX, |a| a.act_time));
                    println!("KVNO: {kvno}, Enctype: {enctype}, Active on: {when} *");
                } else if let Some(act) = act {
                    let when = strdate(act.act_time);
                    println!("KVNO: {kvno}, Enctype: {enctype}, Active on: {when}");
                } else {
                    println!("KVNO: {kvno}, Enctype: {enctype}, No activate time set");
                }
            }
        }
        "update_princ_encryption" => {
            let mut flags = [false; 3];
            let operands = mkey_flags(args, "fnv", &mut flags);
            let [force, dry_run, verbose] = flags;
            if operands.len() > 1 {
                usage();
            }
            let mut glob = operands.into_iter().next().unwrap_or_else(|| "*".into());
            if glob.ends_with('\\') {
                fail(format!(
                    "converting glob pattern '{glob}' to regular expression"
                ));
            }
            if !glob.contains('@') {
                glob.push_str("@*");
            }
            let (new_kvno, new_key) = ok(keys.active());
            let new_key = new_key.clone();
            if !force
                && !dry_run
                && !confirm(&format!(
                    "Re-encrypt all keys not using master key vno {new_kvno}?"
                ))
            {
                println!("OK, doing nothing.");
                std::process::exit(1);
            }
            if verbose {
                if dry_run {
                    println!(
                        "Principals whose keys WOULD BE re-encrypted to master key vno {new_kvno}:"
                    );
                } else {
                    println!(
                        "Principals whose keys are being re-encrypted to master key vno \
                         {new_kvno} if necessary:"
                    );
                }
            }
            let (mut matched, mut updated, mut current) = (0u32, 0u32, 0u32);
            for entry in ok(store.raw_entries()) {
                if entry.principal.name_string == km.name_string && entry.realm == realm {
                    continue;
                }
                let name = entry_display_name(&entry);
                if !glob_match(glob.as_bytes(), name.as_bytes()) {
                    continue;
                }
                matched += 1;
                let old = ok(entry_mkvno(&entry).map_err(|e| {
                    format!("{e} determining master key used for principal '{name}'")
                }));
                if old == new_kvno {
                    if dry_run && verbose {
                        println!("would skip:   {name}");
                    } else if verbose {
                        println!("skipping: {name}");
                    }
                    current += 1;
                    continue;
                }
                if dry_run {
                    if verbose {
                        println!("would update: {name}");
                    }
                    updated += 1;
                    continue;
                }
                if verbose {
                    println!("updating: {name}");
                }
                ok(store
                    .update_raw(&entry.principal, &entry.realm, |e, keys| {
                        convert_entry(e, keys, new_kvno, &new_key)?;
                        set_mod_princ(e, now, &modifier)?;
                        Ok(true)
                    })
                    .map_err(|e| format!("{e} error re-encrypting key for principal '{name}'")));
                updated += 1;
            }
            if dry_run {
                println!(
                    "{matched} principals processed: {updated} would be updated, {current} already current"
                );
            } else {
                println!(
                    "{matched} principals processed: {updated} updated, {current} already current"
                );
            }
        }
        "purge_mkeys" => {
            let mut flags = [false; 3];
            if !mkey_flags(args, "fnv", &mut flags).is_empty() {
                usage();
            }
            let [mut force, dry_run, verbose] = flags;
            force |= dry_run;
            if !force {
                if !confirm(&format!(
                    "Will purge all unused master keys stored in the '{fullname}' principal, are you sure?"
                )) {
                    std::process::exit(1);
                }
                println!("OK, purging unused master keys from '{fullname}'...");
            }
            let entries = ok(store.raw_entries());
            let km_entry = entries
                .iter()
                .find(|e| e.principal.name_string == km.name_string && e.realm == realm)
                .unwrap_or_else(|| fail(format!("while getting master key principal {fullname}")));
            if km_entry.key_data.len() == 1 {
                if verbose {
                    println!("There is only one master key which can not be purged.");
                }
                return;
            }
            let master_kvno = stash_kvno.unwrap_or_else(|| u32::from(km_entry.key_data[0].kvno));
            let in_use: Vec<u16> = entries
                .iter()
                .map(|e| {
                    ok(entry_mkvno(e).map_err(|e| format!("{e} while finding master keys in use")))
                })
                .collect();
            if dry_run {
                println!("Would purge the following master key(s) from {fullname}:");
            } else {
                println!("Purging the following master key(s) from {fullname}:");
            }
            let mut purged = 0;
            for data in &km_entry.key_data {
                if in_use.contains(&data.kvno) {
                    continue;
                }
                if u32::from(data.kvno) == master_kvno {
                    fail("master key stash file needs updating, command aborting");
                }
                purged += 1;
                println!("KVNO: {}", data.kvno);
            }
            if purged == 0 {
                println!("All keys in use, nothing purged.");
                return;
            }
            if dry_run {
                println!("{purged} key(s) would be purged.");
                return;
            }
            ok(store.update_raw(&km, realm, |entry, _| {
                purge_mkeys(entry, &in_use)?;
                set_mod_princ(entry, now, &modifier)?;
                Ok(true)
            }));
            println!("{purged} key(s) purged.");
        }
        _ => usage(),
    }
}
