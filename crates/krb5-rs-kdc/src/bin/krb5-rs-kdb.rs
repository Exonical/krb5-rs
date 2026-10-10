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
    format_principal, parse_lifetime, parse_principal, parse_time, Admin, AttrChange,
    PrincipalOptions,
};
use krb5_rs::kdc::kdb::{master_key_from_password, read_stash, write_stash, FileStore};
use krb5_rs::kdc::{default_realm, RealmConfig};
use krb5_rs::profile::Profile;

fn usage() -> ! {
    eprintln!(
        "usage: krb5-rs-kdb [--config kdc.conf] [--krb5-config krb5.conf] [--realm R] [--force] <command>\n\
         commands:\n  create [-s]\n  stash\n  \
         addprinc [-randkey] [{{+|-}}attr]... [-maxlife T] [-maxrenewlife T] [-expire T] [-pwexpire T] NAME\n  \
         delprinc NAME\n  cpw [-randkey] [-keepold] NAME\n  \
         modprinc [{{+|-}}attr]... [-maxlife T] [-maxrenewlife T] [-expire T] [-pwexpire T] [-allow_delegate_to P]... [-allow_delegate_from P]... [-clear_delegate_to] [-clear_delegate_from] NAME\n  \
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

    let read_only_command = matches!(cmd.as_str(), "getprinc" | "listprincs" | "stash");
    if cfg.propagation.is_replica() && !read_only_command && !force {
        fail(format!(
            "this is a replica of {} (kprop_primary is set), so its database is read-only; \nrun `{cmd}` on the primary, or pass --force to override",
            cfg.propagation.primary.as_deref().unwrap_or("?")
        ));
    }

    match cmd.as_str() {
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
    let admin = Admin::new(&store, cfg.supported_keysalts.clone());
    let principal = |s: &str| ok(parse_principal(s, &realm));

    match cmd.as_str() {
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
