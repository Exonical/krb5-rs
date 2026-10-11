//! kadmin.local-like administration of the persistent principal database.
//!
//! `krb5-rs-kdb [--config kdc.conf] [--krb5-config krb5.conf] [--realm R] <cmd> args`
//!
//! Commands: `create [-s]`, `stash`, `addprinc`, `delprinc`, `cpw`,
//! `modprinc`, `getprinc`, `listprincs`, `ktadd`. See `usage()`.
//!
//! The master password and principal passwords are read from stdin, one
//! line each, with prompts on stderr; they are never taken from the command
//! line. Input is not hidden when stdin is a terminal.

use std::io::BufRead;
use std::path::{Path, PathBuf};

use krb5_rs::kdc::kdb::admin::{
    format_policy, format_principal, parse_lifetime, parse_principal, parse_time, Admin, AdminOps,
    AttrChange, PolicyChange, PrincipalOptions,
};
use krb5_rs::kdc::kdb::{master_key_from_password, read_stash, write_stash, FileStore};
use krb5_rs::kdc::{default_realm, AdminStore, RealmConfig, StoreError};
use krb5_rs::profile::Profile;

fn usage() -> ! {
    eprintln!(
        "usage: krb5-rs-kdb [--config kdc.conf] [--krb5-config krb5.conf] [--realm R] [--force] <command>\n\
         commands:\n  init --master-password-file F [--stash] [--randkey NAME]... [--password NAME=FILE]...\n  create [-s]\n  stash\n  \
         addprinc [-randkey] [{{+|-}}attr]... [-maxlife T] [-maxrenewlife T] [-expire T] [-pwexpire T] NAME\n  \
         delprinc NAME\n  cpw [-randkey] [-keepold] NAME\n  \
         modprinc [{{+|-}}attr]... [-maxlife T] [-maxrenewlife T] [-expire T] [-pwexpire T] [-allow_delegate_to P]... [-allow_delegate_from P]... [-clear_delegate_to] [-clear_delegate_from] [-policy P | -clearpolicy] [-unlock] NAME\n  \
         addpol|modpol [-maxlife T] [-minlife T] [-minlength N] [-minclasses N] [-history N] [-maxfailure N] [-failurecountinterval T] [-lockoutduration T] [-allowedkeysalts K] POLICY\n  \
         delpol POLICY\n  getpol [-terse] POLICY\n  listpols\n  \
         database migrate [--create-roles] [--multi-region --primary-region R --regions R1,R2,...]   (CockroachDB)\n  \
         replication status | prune --older-than D | wait-applied --since TS [--timeout D] [--live-within D]   (CockroachDB)\n  \
         getprinc NAME\n  listprincs\n  ktadd -k PATH [-norandkey] NAME..."
    );
    std::process::exit(2);
}

fn fail(msg: impl std::fmt::Display) -> ! {
    eprintln!("krb5-rs-kdb: {msg}");
    std::process::exit(1);
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

/// First line of a secret file; secrets never come from argv.
fn read_secret_file(path: &str) -> String {
    let text = ok(std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}")));
    let line = text.lines().next().unwrap_or("").trim_end_matches('\r');
    if line.is_empty() {
        fail(format!("{path} is empty"));
    }
    line.to_string()
}

/// Idempotent bootstrap: create the database (and stash) if missing, then
/// make sure every listed principal exists, leaving existing ones alone.
fn init(args: Vec<String>, cfg: &RealmConfig, realm: &str) {
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
    let master_file = master_file.unwrap_or_else(|| fail("init requires --master-password-file"));
    let key = ok(master_key_from_password(
        realm,
        &read_secret_file(&master_file),
        cfg.master_key_type,
    ));
    let etypes: Vec<i32> = cfg.supported_keysalts.iter().map(|(e, _)| *e).collect();
    let store = if cfg.database_name.exists() {
        ok(FileStore::open(&cfg.database_name, &key))
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
    let admin = Admin::new(&store, cfg.supported_keysalts.clone());
    let opts = PrincipalOptions::default();
    let wanted = randkeys.iter().map(|n| (n.as_str(), None)).chain(
        passwords
            .iter()
            .map(|(n, f)| (n.as_str(), Some(f.as_str()))),
    );
    for (spec, password_file) in wanted {
        let (name, r) = ok(parse_principal(spec, realm));
        if ok(store.get_record(&name, &r)).is_some() {
            println!("Principal \"{name}@{r}\" already exists.");
            continue;
        }
        let password = password_file.map(read_secret_file);
        ok(admin.add_principal(&name, &r, password.as_deref(), &opts));
        println!("Principal \"{name}@{r}\" created.");
    }
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
    let mut config: Option<PathBuf> = std::env::var_os("KRB5_KDC_PROFILE").map(PathBuf::from);
    let mut krb5_config: Option<PathBuf> = std::env::var_os("KRB5_CONFIG").map(PathBuf::from);
    let mut realm: Option<String> = None;
    let mut force = false;
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    while let Some(first) = args.first().map(String::as_str) {
        match first {
            "--force" => {
                force = true;
                args.remove(0);
            }
            "--config" | "--krb5-config" | "--realm" => {
                if args.len() < 2 {
                    usage();
                }
                let value = args.remove(1);
                match args.remove(0).as_str() {
                    "--config" => config = Some(PathBuf::from(value)),
                    "--krb5-config" => krb5_config = Some(PathBuf::from(value)),
                    _ => realm = Some(value),
                }
            }
            _ => break,
        }
    }
    if args.is_empty() {
        usage();
    }
    let cmd = args.remove(0);

    let config = config.unwrap_or_else(|| PathBuf::from("/usr/local/var/krb5kdc/kdc.conf"));
    let kdc_conf =
        ok(Profile::load(&config).map_err(|e| format!("reading {}: {e}", config.display())));
    let krb5 = krb5_config
        .filter(|p| p.exists())
        .map(|p| ok(Profile::load(&p)));
    let realm = realm
        .or_else(|| default_realm(&kdc_conf, krb5.as_ref()))
        .unwrap_or_else(|| fail("no realm given and no default realm found"));
    let cfg = ok(RealmConfig::from_profiles(&kdc_conf, krb5.as_ref(), &realm));

    let read_only_command = matches!(
        cmd.as_str(),
        "getprinc" | "listprincs" | "getpol" | "listpols" | "stash"
    );
    if cfg.propagation.is_replica() && !read_only_command && !force {
        fail(format!(
            "this is a replica of {} (kprop_primary is set), so its database is read-only; \nrun `{cmd}` on the primary, or pass --force to override",
            cfg.propagation.primary.as_deref().unwrap_or("?")
        ));
    }

    match cfg.db_module.library.as_deref() {
        None => {}
        Some("krb5-rs-cockroach") => {
            cockroach_command(&cmd, args, &cfg, &realm);
            return;
        }
        Some(other) => fail(format!("unknown db_library {other:?}")),
    }
    if matches!(cmd.as_str(), "database" | "replication") {
        fail(format!("`{cmd}` needs db_library = krb5-rs-cockroach"));
    }

    match cmd.as_str() {
        "init" => {
            init(args, &cfg, &realm);
            return;
        }
        "create" => {
            let stash = args.iter().any(|a| a == "-s");
            let password = read_line(&format!("Enter KDC database master key for {realm}: "));
            let key = ok(master_key_from_password(
                &realm,
                &password,
                cfg.master_key_type,
            ));
            let etypes: Vec<i32> = cfg.supported_keysalts.iter().map(|(e, _)| *e).collect();
            ok(FileStore::create_with(
                &cfg.database_name,
                &realm,
                &key,
                &etypes,
            ));
            if stash {
                ok(write_stash(&cfg.key_stash_file, &realm, &key));
            }
            return;
        }
        "stash" => {
            let password = read_line(&format!("Enter KDC database master key for {realm}: "));
            let key = ok(master_key_from_password(
                &realm,
                &password,
                cfg.master_key_type,
            ));
            ok(FileStore::open(&cfg.database_name, &key));
            ok(write_stash(&cfg.key_stash_file, &realm, &key));
            return;
        }
        _ => {}
    }

    let master = ok(read_stash(&cfg.key_stash_file, &realm));
    let store = ok(FileStore::open(&cfg.database_name, &master));
    let admin = Blocking::new(runtime(), &store, cfg.supported_keysalts.clone());
    run_admin(&admin, &cmd, args, &realm);
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
    ) -> Self {
        Self {
            rt,
            ops: AdminOps::new(store, keysalts),
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
            print!("{}", format_principal(&ok(admin.get_principal(&name, &r))));
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
fn cockroach_command(cmd: &str, mut args: Vec<String>, cfg: &RealmConfig, realm: &str) {
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
            let password = read_line(&format!("Enter KDC database master key for {realm}: "));
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
            let password = read_line(&format!("Enter KDC database master key for {realm}: "));
            let key = ok(master_key_from_password(
                realm,
                &password,
                cfg.master_key_type,
            ));
            ok(rt.block_on(CockroachStore::open(config, key.clone(), realm)));
            ok(write_stash(&cfg.key_stash_file, realm, &key));
        }
        "replication" => {
            let master = ok(read_stash(&cfg.key_stash_file, realm));
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
            let master = ok(read_stash(&cfg.key_stash_file, realm));
            let store = ok(rt.block_on(CockroachStore::open(config, master, realm)));
            let admin = Blocking::new(rt, store, cfg.supported_keysalts.clone());
            run_admin(&admin, cmd, args, realm);
        }
    }
}

#[cfg(not(feature = "cockroach"))]
fn cockroach_command(_cmd: &str, _args: Vec<String>, _cfg: &RealmConfig, _realm: &str) {
    fail("db_library krb5-rs-cockroach needs a krb5-rs-kdb built with the `cockroach` feature");
}
