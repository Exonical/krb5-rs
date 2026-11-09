//! `kdb5_ldap_util` (MIT 1.22.2 `plugins/kdb/ldap/ldap_util`): realm
//! (`create`, `modify`, `view`, `destroy`, `list`), ticket policy
//! (`create_policy`, `modify_policy`, `view_policy`, `destroy_policy`,
//! `list_policy`) and `stashsrvpw` commands for `db_library = kldap`.

use std::io::{BufRead, Write};
use std::path::PathBuf;

use krb5_rs_kdb_ldap::config::{LdapConfig, ServerType};
use krb5_rs_kdb_ldap::create::RealmOptions;
use krb5_rs_kdb_ldap::util::{stash_service_password, LdapUtil, RealmChanges, TicketPolicy};
use krb5_rs_kdb_ldap::LdapStore;

use super::{
    add_admin_princs, bump_exit_status, com_err, default_realm, exit_status, fail,
    master_key_from_password_named, ok, read_password, read_secret_file, runtime,
    write_stash_named, Blocking, Profile, RealmConfig,
};

const COMMANDS: [&str; 11] = [
    "create",
    "modify",
    "view",
    "destroy",
    "list",
    "stashsrvpw",
    "create_policy",
    "modify_policy",
    "view_policy",
    "destroy_policy",
    "list_policy",
];

/// `get_ticket_policy`'s flag options: name, `KRB5_KDB_*` bit, and whether
/// `+` clears the bit (the `allow_*` ones).
const FLAG_OPTIONS: [(&str, i32, bool); 12] = [
    ("allow_postdated", 0x1, true),
    ("allow_forwardable", 0x2, true),
    ("allow_renewable", 0x8, true),
    ("allow_proxiable", 0x10, true),
    ("allow_dup_skey", 0x20, true),
    ("requires_preauth", 0x80, false),
    ("requires_hwauth", 0x100, false),
    ("allow_svr", 0x1000, true),
    ("allow_tgs_req", 0x4, true),
    ("allow_tix", 0x40, true),
    ("needchange", 0x200, false),
    ("password_changing_service", 0x2000, false),
];

/// The order `print_realm_params` and `print_policy_params` name flags in.
const FLAG_NAMES: [(i32, &str); 12] = [
    (0x1, "DISALLOW_POSTDATED"),
    (0x2, "DISALLOW_FORWARDABLE"),
    (0x8, "DISALLOW_RENEWABLE"),
    (0x10, "DISALLOW_PROXIABLE"),
    (0x20, "DISALLOW_DUP_SKEY"),
    (0x80, "REQUIRES_PRE_AUTH"),
    (0x100, "REQUIRES_HW_AUTH"),
    (0x1000, "DISALLOW_SVR"),
    (0x4, "DISALLOW_TGT_BASED"),
    (0x40, "DISALLOW_ALL_TIX"),
    (0x200, "REQUIRES_PWCHANGE"),
    (0x2000, "PWCHANGE_SERVICE"),
];

const USAGE: &str = "Usage: kdb5_ldap_util [-D user_dn [-w passwd]] [-H ldapuri] [-r realm]\n\
\tcmd [cmd_options]\n\
create          [-subtrees subtree_dn_list] [-sscope search_scope]\n\
\t\t[-containerref container_reference_dn]\n\
\t\t[-m|-P password|-sf stashfilename] [-s]\n\
\t\t[-k mkeytype] [-kv mkeyVNO] [-M mkeyname]\n\
\t\t[-maxtktlife max_ticket_life]\n\
\t\t[-maxrenewlife max_renewable_ticket_life] [ticket_flags]\n\
modify          [-subtrees subtree_dn_list] [-sscope search_scope]\n\
\t\t[-containerref container_reference_dn]\n\
\t\t[-maxtktlife max_ticket_life]\n\
\t\t[-maxrenewlife max_renewable_ticket_life] [ticket_flags]\n\
view\n\
destroy         [-f]\n\
list\n\
stashsrvpw      [-f filename] service_dn\n\
create_policy   [-maxtktlife max_ticket_life]\n\
\t\t[-maxrenewlife max_renewable_ticket_life] [ticket_flags] policy\n\
modify_policy   [-maxtktlife max_ticket_life]\n\
\t\t[-maxrenewlife max_renewable_ticket_life] [ticket_flags] policy\n\
view_policy     policy\n\
destroy_policy  [-force] policy\n\
list_policy\n";

fn usage() -> ! {
    eprint!("{USAGE}");
    std::process::exit(exit_status() + 1);
}

/// The ticket policy options shared by the realm and policy commands.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct TicketOptions {
    max_life: Option<i32>,
    max_renewable_life: Option<i32>,
    flags: Option<i32>,
}

enum Parsed {
    Used,
    NotTicketOption,
    /// A missing value or an unparsable time (already reported).
    Bad,
}

/// `get_ticket_policy`: consume `args[*i]` (and its value) if it is a
/// ticket policy option; flags start from `base`.
fn ticket_option(args: &[String], i: &mut usize, base: i32, t: &mut TicketOptions) -> Parsed {
    let arg = args[*i].as_str();
    if arg == "-maxtktlife" || arg == "-maxrenewlife" {
        *i += 1;
        let Some(v) = args.get(*i) else {
            return Parsed::Bad;
        };
        let Some(d) = duration(v) else {
            com_err("Invalid argument while providing time specification");
            return Parsed::Bad;
        };
        if arg == "-maxtktlife" {
            t.max_life = Some(d);
        } else {
            t.max_renewable_life = Some(d);
        }
        return Parsed::Used;
    }
    let (sign, name) = match arg.split_at_checked(1) {
        Some((s, n)) => (s, n),
        None => return Parsed::NotTicketOption,
    };
    let Some(&(_, bit, allow)) = FLAG_OPTIONS.iter().find(|(n, _, _)| *n == name) else {
        return Parsed::NotTicketOption;
    };
    let set = match sign {
        "+" => !allow,
        "-" => allow,
        _ => return Parsed::NotTicketOption,
    };
    let flags = t.flags.unwrap_or(base);
    t.flags = Some(if set { flags | bit } else { flags & !bit });
    Parsed::Used
}

/// `get_date(s) - now`, as MIT stores `-maxtktlife`.
fn duration(s: &str) -> Option<i32> {
    let date = krb5_rs::kdc::kdb::getdate::get_date(s)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64);
    i32::try_from(date - now).ok()
}

/// `strdur`.
fn strdur(d: i32) -> String {
    let neg = d < 0;
    let d = i64::from(d).abs();
    let days = d / 86400;
    format!(
        "{}{days} {} {:02}:{:02}:{:02}",
        if neg { "-" } else { "" },
        if days == 1 { "day" } else { "days" },
        d % 86400 / 3600,
        d % 3600 / 60,
        d % 60
    )
}

fn flag_names(flags: i32) -> String {
    FLAG_NAMES
        .iter()
        .filter(|(b, _)| flags & b != 0)
        .map(|(_, n)| format!("{n} "))
        .collect()
}

/// The `(type 'yes' to confirm)? ` answer: true only for exactly `yes`.
fn confirmed() -> bool {
    print!("(type 'yes' to confirm)? ");
    let _ = std::io::stdout().flush();
    let mut line = String::new();
    let _ = std::io::stdin().lock().read_line(&mut line);
    line == "yes\n"
}

struct Globals {
    realm: Option<String>,
    mkey_password: Option<String>,
    master_password_file: Option<String>,
    enctype: Option<i32>,
    kvno: Option<u32>,
    mkey_name: Option<String>,
    stash_file: Option<PathBuf>,
    bind_dn: Option<String>,
    bind_pwd: Option<String>,
    server: Option<String>,
    config: Option<PathBuf>,
    krb5_config: Option<PathBuf>,
}

/// `kdb5_ldap_util`'s `main`.
pub(crate) fn main() {
    let mut g = Globals {
        realm: None,
        mkey_password: None,
        master_password_file: None,
        enctype: None,
        kvno: None,
        mkey_name: None,
        stash_file: None,
        bind_dn: None,
        bind_pwd: None,
        server: None,
        config: std::env::var_os("KRB5_KDC_PROFILE").map(PathBuf::from),
        krb5_config: std::env::var_os("KRB5_CONFIG").map(PathBuf::from),
    };
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let mut cmd: Option<String> = None;
    let mut args: Vec<String> = Vec::new();
    let mut help = false;
    let mut it = argv.into_iter().peekable();
    while let Some(a) = it.next() {
        if a == "--help" {
            help = true;
        }
        let takes = matches!(
            a.as_str(),
            "-P" | "-r"
                | "-k"
                | "-kv"
                | "-M"
                | "-sf"
                | "-D"
                | "-w"
                | "-H"
                | "--config"
                | "--krb5-config"
                | "--master-password-file"
        );
        if takes && it.peek().is_some() {
            let v = it.next().unwrap_or_default();
            match a.as_str() {
                "-P" => g.mkey_password = Some(v),
                "-r" => g.realm = Some(v),
                "-k" => match krb5_rs::crypto::enctype_from_name(&v) {
                    Some(e) => g.enctype = Some(e),
                    None => fail(format!("Invalid argument : {v} is an invalid enctype")),
                },
                "-kv" => match v.parse::<u32>() {
                    Ok(k) if k != 0 => g.kvno = Some(k),
                    _ => fail(format!("Invalid argument : {v} is an invalid mkeyVNO")),
                },
                "-M" => g.mkey_name = Some(v),
                "-sf" => g.stash_file = Some(PathBuf::from(v)),
                "-D" => g.bind_dn = Some(v),
                "-w" => g.bind_pwd = Some(v),
                "-H" => g.server = Some(v),
                "--config" => g.config = Some(PathBuf::from(v)),
                "--krb5-config" => g.krb5_config = Some(PathBuf::from(v)),
                _ => g.master_password_file = Some(v),
            }
        } else if a == "-m" {
        } else if COMMANDS.contains(&a.as_str()) {
            if cmd.is_some() {
                usage();
            }
            cmd = Some(a);
        } else {
            args.push(a);
        }
    }
    let Some(cmd) = cmd else { usage() };
    if help {
        usage();
    }
    if let Some(name) = &g.mkey_name {
        if name != "K/M" {
            fail(format!(
                "master key name '{name}' is not supported; kldap uses K/M"
            ));
        }
    }

    let config = g
        .config
        .clone()
        .unwrap_or_else(|| PathBuf::from("/usr/local/var/krb5kdc/kdc.conf"));
    let kdc_conf = if config.exists() {
        ok(Profile::load(&config).map_err(|e| format!("reading {}: {e}", config.display())))
    } else {
        ok(Profile::parse(""))
    };
    let krb5 = g
        .krb5_config
        .clone()
        .filter(|p| p.exists())
        .map(|p| ok(Profile::load(&p)));
    let realm_required = !matches!(cmd.as_str(), "list" | "stashsrvpw");
    let realm = match g
        .realm
        .clone()
        .or_else(|| default_realm(&kdc_conf, krb5.as_ref()))
    {
        Some(r) => r,
        None if realm_required => {
            fail("Configuration file does not specify default realm while getting default realm")
        }
        None => String::new(),
    };
    let mut cfg = ok(RealmConfig::from_profiles(&kdc_conf, krb5.as_ref(), &realm));
    if let Some(e) = g.enctype {
        cfg.master_key_type = e;
    }
    if let Some(sf) = &g.stash_file {
        cfg.key_stash_file = sf.clone();
    }
    let mut lcfg = LdapConfig::new(&cfg.db_module, &[], ServerType::Admin)
        .unwrap_or_else(|e| fail(format!("{e} while reading ldap configuration")));
    if let Some(dn) = &g.bind_dn {
        let pwd = match g.bind_pwd.take() {
            Some(p) => p,
            None => {
                let p = read_password(
                    &format!("Password for \"{dn}\""),
                    "retrieving ldap configuration",
                );
                if p.is_empty() {
                    fail("Cannot allocate memory while retrieving ldap configuration");
                }
                p
            }
        };
        lcfg.bind_dn = Some(dn.clone());
        lcfg.bind_pwd = Some(pwd);
    }
    if let Some(h) = &g.server {
        lcfg.servers = vec![h.clone()];
    }

    match cmd.as_str() {
        "create" => create(&args, &g, &cfg, lcfg, &realm),
        "modify" => modify(&args, &lcfg, &realm),
        "view" => view(&args, &lcfg, &realm),
        "destroy" => destroy(&args, &lcfg, &realm),
        "list" => list(&args, &lcfg),
        "stashsrvpw" => stashsrvpw(&args, &lcfg),
        "create_policy" => create_policy(&args, &lcfg, &realm),
        "modify_policy" => modify_policy(&args, &lcfg, &realm),
        "view_policy" => view_policy(&args, &lcfg, &realm),
        "destroy_policy" => destroy_policy(&args, &lcfg, &realm),
        _ => list_policy(&args, &lcfg, &realm),
    }
    std::process::exit(exit_status());
}

fn connect(rt: &tokio::runtime::Runtime, lcfg: &LdapConfig) -> LdapUtil {
    rt.block_on(LdapUtil::open(lcfg))
        .unwrap_or_else(|e| fail(format!("{e} while initializing database")))
}

/// The realm options of `create` and `modify`.
#[derive(Default)]
struct RealmArgs {
    subtrees: Option<Vec<String>>,
    containerref: Option<String>,
    search_scope: Option<i32>,
    stash: bool,
    tickets: TicketOptions,
}

fn realm_args(
    args: &[String],
    verb: &str,
    realm: &str,
    base_flags: i32,
    create: bool,
) -> RealmArgs {
    let mut r = RealmArgs::default();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-subtrees" => {
                i += 1;
                let v = args.get(i).unwrap_or_else(|| usage());
                if v.is_empty() {
                    fail(format!(
                        "Invalid argument for subtree while {verb} realm '{realm}'"
                    ));
                }
                r.subtrees = Some(
                    v.split(':')
                        .filter(|s| !s.is_empty())
                        .map(str::to_string)
                        .collect(),
                );
            }
            "-containerref" => {
                i += 1;
                let v = args.get(i).unwrap_or_else(|| usage());
                if v.is_empty() {
                    fail(format!(
                        "Invalid argument for container reference while {verb} realm '{realm}'"
                    ));
                }
                r.containerref = Some(v.clone());
            }
            "-sscope" => {
                i += 1;
                let v = args.get(i).unwrap_or_else(|| usage());
                let s = if v.eq_ignore_ascii_case("one") {
                    1
                } else if v.eq_ignore_ascii_case("sub") {
                    2
                } else {
                    v.parse::<i32>().unwrap_or(0)
                };
                if s != 1 && s != 2 {
                    if create {
                        fail(format!(
                            "Invalid argument invalid search scope while creating realm '{realm}'"
                        ));
                    }
                    fail(format!(
                        "Invalid argument specified for search scope while modifying \
                         information of realm '{realm}'"
                    ));
                }
                r.search_scope = Some(s);
            }
            "-s" if create => r.stash = true,
            _ => match ticket_option(args, &mut i, base_flags, &mut r.tickets) {
                Parsed::Used => {}
                _ => {
                    let bad = args.get(i).map_or("", String::as_str);
                    println!("'{bad}' is an invalid option");
                    usage();
                }
            },
        }
        i += 1;
    }
    r
}

/// `kdb5_ldap_create`.
fn create(args: &[String], g: &Globals, cfg: &RealmConfig, mut lcfg: LdapConfig, realm: &str) {
    let r = realm_args(args, "creating", realm, 0, true);
    println!("Initializing database for realm '{realm}'");
    let password = match (&g.mkey_password, &g.master_password_file) {
        (Some(p), _) => p.clone(),
        (None, Some(f)) => read_secret_file(f),
        (None, None) => {
            println!("You will be prompted for the database Master Password.");
            println!("It is important that you NOT FORGET this password.");
            let context = "reading master key from keyboard";
            let p = read_password("Enter KDC database master key", context);
            let again = read_password("Re-enter KDC database master key to verify", context);
            if p != again {
                fail(format!("Password mismatch while {context}"));
            }
            p
        }
    };
    if lcfg.container_dn.is_none() {
        print!("Enter DN of Kerberos container: ");
        let _ = std::io::stdout().flush();
        let mut line = String::new();
        if std::io::stdin().lock().read_line(&mut line).unwrap_or(0) > 0 {
            lcfg.container_dn = Some(line.trim_end_matches(['\r', '\n']).to_string());
        }
    }
    let key =
        master_key_from_password_named(realm, &cfg.master_key_name, &password, cfg.master_key_type)
            .unwrap_or_else(|e| fail(format!("{e} while transforming master key from password")));
    let rt = runtime();
    {
        let util = connect(&rt, &lcfg);
        for s in r.subtrees.iter().flatten() {
            rt.block_on(util.check_subtree_class(s, ""))
                .unwrap_or_else(|e| fail(format!("{e} while creating realm '{realm}'")));
        }
        if let Some(c) = &r.containerref {
            rt.block_on(util.check_subtree_class(c, ""))
                .unwrap_or_else(|e| fail(format!("{e} while creating realm '{realm}'")));
        }
    }
    let opts = RealmOptions {
        subtrees: r.subtrees.clone().unwrap_or_default(),
        containerref: r.containerref.clone(),
        search_scope: r.search_scope.unwrap_or(0),
        max_life: r.tickets.max_life.unwrap_or(0),
        max_renewable_life: r.tickets.max_renewable_life.unwrap_or(0),
        tkt_flags: r.tickets.flags.unwrap_or(0),
    };
    let store = rt
        .block_on(LdapStore::create_realm_with(lcfg, cfg, &key, &opts))
        .unwrap_or_else(|e| fail(format!("{e} while creating realm '{realm}'")));
    let admin = Blocking::new(
        rt,
        store,
        cfg.supported_keysalts.clone(),
        cfg.master_key_type,
    );
    add_admin_princs(&admin, realm);
    if r.stash {
        if let Err(e) = write_stash_named(&cfg.key_stash_file, realm, &cfg.master_key_name, &key) {
            com_err(format!("{e} while storing key"));
            println!("Warning: couldn't stash master key.");
            bump_exit_status();
        }
    }
}

/// `kdb5_ldap_modify`.
fn modify(args: &[String], lcfg: &LdapConfig, realm: &str) {
    let rt = runtime();
    let util = connect(&rt, lcfg);
    let info = rt
        .block_on(util.read_realm(realm))
        .unwrap_or_else(|e| fail(format!("{e} while reading information of realm '{realm}'")));
    let r = realm_args(args, "modifying", realm, info.params.tkt_flags, false);
    let changes = RealmChanges {
        subtrees: r.subtrees,
        containerref: r.containerref,
        search_scope: r.search_scope,
        max_life: r.tickets.max_life,
        max_renewable_life: r.tickets.max_renewable_life,
        tkt_flags: r.tickets.flags,
    };
    rt.block_on(util.modify_realm(realm, &changes))
        .unwrap_or_else(|e| {
            fail(format!(
                "{e} while modifying information of realm '{realm}'"
            ))
        });
}

/// `kdb5_ldap_view` + `print_realm_params`.
fn view(args: &[String], lcfg: &LdapConfig, realm: &str) {
    if !args.is_empty() {
        usage();
    }
    let rt = runtime();
    let util = connect(&rt, lcfg);
    let info = rt
        .block_on(util.read_realm(realm))
        .unwrap_or_else(|e| fail(format!("{e} while reading information of realm '{realm}'")));
    let p = &info.params;
    println!("{:>25}: {:<50}", "Realm Name", realm);
    for s in &p.subtrees {
        println!("{:>25}: {:<50}", "Subtree", s);
    }
    if let Some(c) = &p.container_ref {
        println!("{:>25}: {:<50}", "Principal Container Reference", c);
    }
    if let Some(s) = info.search_scope {
        let v = match s {
            1 => "ONE",
            2 => "SUB",
            _ => "Invalid !",
        };
        println!("{:>25}: {:<50}", "SearchScope", v);
    }
    if let Some(l) = info.max_life {
        println!("{:>25}: {} ", "Maximum Ticket Life", strdur(l));
    }
    if let Some(l) = info.max_renewable_life {
        println!("{:>25}: {} ", "Maximum Renewable Life", strdur(l));
    }
    if let Some(f) = info.tkt_flags {
        println!("{:>25}: {}", "Ticket flags", flag_names(f));
    }
}

/// `kdb5_ldap_list`.
fn list(args: &[String], lcfg: &LdapConfig) {
    if !args.is_empty() {
        usage();
    }
    let rt = runtime();
    let util = connect(&rt, lcfg);
    let realms = rt
        .block_on(util.list_realms())
        .unwrap_or_else(|e| fail(format!("{e} while listing realms")));
    for r in realms {
        println!("{r}");
    }
}

/// `kdb5_ldap_destroy`.
fn destroy(args: &[String], lcfg: &LdapConfig, realm: &str) {
    let mut force = false;
    for a in args {
        match a.as_str() {
            "-f" => force = true,
            _ => usage(),
        }
    }
    if !force {
        println!("Deleting KDC database of '{realm}', are you sure?");
        if !confirmed() {
            bump_exit_status();
            return;
        }
        println!("OK, deleting database of '{realm}'...");
    }
    let rt = runtime();
    let util = connect(&rt, lcfg);
    rt.block_on(util.read_realm(realm))
        .unwrap_or_else(|e| fail(format!("{e} while reading realm information")));
    rt.block_on(util.delete_realm(realm))
        .unwrap_or_else(|e| fail(format!("{e} deleting database of '{realm}'")));
    println!("** Database of '{realm}' destroyed.");
}

/// `kdb5_ldap_stash_service_password`.
fn stashsrvpw(args: &[String], lcfg: &LdapConfig) {
    let (dn, file) = match args {
        [dn] => (dn.clone(), None),
        [f, file, dn] if f == "-f" => (dn.clone(), Some(file.clone())),
        [dn, f, file] if f == "-f" => (dn.clone(), Some(file.clone())),
        _ => usage(),
    };
    let file = file
        .or_else(|| lcfg.service_password_file.clone())
        .unwrap_or_else(|| {
            fail(
                "ldap_service_password_file not configured while getting service password filename",
            )
        });
    let context = "setting service object password";
    let password = read_password(&format!("Password for \"{dn}\""), context);
    let again = read_password(&format!("Re-enter password for \"{dn}\""), context);
    if password != again {
        fail(format!("Password mismatch while {context}"));
    }
    if password.is_empty() {
        println!("{}: Invalid password", super::progname());
        bump_exit_status();
        return;
    }
    if let Err(e) = stash_service_password(std::path::Path::new(&file), &dn, &password) {
        fail(format!("Failed to open file {file}: {e}"));
    }
}

/// The policy commands' realm DN (`init_ldap_realm`).
fn realm_dn(
    rt: &tokio::runtime::Runtime,
    util: &LdapUtil,
    realm: &str,
) -> krb5_rs_kdb_ldap::util::RealmInfo {
    rt.block_on(util.read_realm(realm))
        .unwrap_or_else(|e| fail(format!("{e} while reading realm information")))
}

/// Parse policy options; the one other argument is the policy name.
fn policy_args(args: &[String], base: i32, ctx: &str) -> (String, TicketOptions) {
    let mut name = None;
    let mut t = TicketOptions::default();
    let mut i = 0;
    while i < args.len() {
        match ticket_option(args, &mut i, base, &mut t) {
            Parsed::Used => {}
            Parsed::Bad if args.get(i).is_none() => usage(),
            Parsed::Bad => {
                bump_exit_status();
                std::process::exit(exit_status());
            }
            Parsed::NotTicketOption => {
                if name.is_some() {
                    usage();
                }
                name = Some(args[i].clone());
            }
        }
        i += 1;
    }
    let _ = ctx;
    (name.unwrap_or_else(|| usage()), t)
}

/// `kdb5_ldap_create_policy`.
fn create_policy(args: &[String], lcfg: &LdapConfig, realm: &str) {
    if args.is_empty() || args.len() > 15 {
        usage();
    }
    let (name, t) = policy_args(args, 0, "creating policy object");
    let rt = runtime();
    let util = connect(&rt, lcfg);
    let info = realm_dn(&rt, &util, realm);
    let p = TicketPolicy {
        name,
        max_life: t.max_life,
        max_renewable_life: t.max_renewable_life,
        tkt_flags: t.flags,
    };
    rt.block_on(util.create_tkt_policy(&info.params.realm_dn, &p))
        .unwrap_or_else(|e| fail(format!("{e} while creating policy object")));
}

/// `kdb5_ldap_modify_policy`.
fn modify_policy(args: &[String], lcfg: &LdapConfig, realm: &str) {
    if args.len() < 2 || args.len() > 15 {
        usage();
    }
    let mut name = None;
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        if a == "-maxtktlife" || a == "-maxrenewlife" {
            i += 1;
        } else if !FLAG_OPTIONS.iter().any(|(n, _, _)| a.get(1..) == Some(*n)) {
            if name.is_some() {
                usage();
            }
            name = Some(a.to_string());
        }
        i += 1;
    }
    let name = name.unwrap_or_else(|| usage());
    let rt = runtime();
    let util = connect(&rt, lcfg);
    let info = realm_dn(&rt, &util, realm);
    let old = rt
        .block_on(util.read_tkt_policy(&info.params.realm_dn, &name))
        .unwrap_or_else(|e| fail(format!("{e} while reading information of policy '{name}'")));
    let (_, t) = policy_args(args, old.tkt_flags.unwrap_or(0), "modifying policy object");
    let p = TicketPolicy {
        name,
        max_life: t.max_life,
        max_renewable_life: t.max_renewable_life,
        tkt_flags: t.flags,
    };
    rt.block_on(util.modify_tkt_policy(&info.params.realm_dn, &p))
        .unwrap_or_else(|e| fail(format!("{e} while modifying policy object")));
}

/// `kdb5_ldap_view_policy` + `print_policy_params`.
fn view_policy(args: &[String], lcfg: &LdapConfig, realm: &str) {
    let [name] = args else { usage() };
    let rt = runtime();
    let util = connect(&rt, lcfg);
    let info = realm_dn(&rt, &util, realm);
    let p = rt
        .block_on(util.read_tkt_policy(&info.params.realm_dn, name))
        .unwrap_or_else(|e| fail(format!("{e} while viewing policy '{name}'")));
    println!("{:>25}: {}", "Ticket policy", p.name);
    if let Some(l) = p.max_life {
        println!("{:>25}: {}", "Maximum ticket life", strdur(l));
    }
    if let Some(l) = p.max_renewable_life {
        println!("{:>25}: {}", "Maximum renewable life", strdur(l));
    }
    println!(
        "{:>25}: {}",
        "Ticket flags",
        flag_names(p.tkt_flags.unwrap_or(0))
    );
}

/// `kdb5_ldap_destroy_policy`.
fn destroy_policy(args: &[String], lcfg: &LdapConfig, realm: &str) {
    if args.is_empty() || args.len() > 2 {
        usage();
    }
    let mut force = false;
    let mut name = None;
    for a in args {
        if a == "-force" {
            force = true;
        } else if name.replace(a.clone()).is_some() {
            usage();
        }
    }
    let name = name.unwrap_or_else(|| usage());
    if !force {
        println!("This will delete the policy object '{name}', are you sure?");
        if !confirmed() {
            bump_exit_status();
            return;
        }
    }
    let rt = runtime();
    let util = connect(&rt, lcfg);
    let info = realm_dn(&rt, &util, realm);
    rt.block_on(util.read_tkt_policy(&info.params.realm_dn, &name))
        .unwrap_or_else(|e| fail(format!("{e} while destroying policy object")));
    rt.block_on(util.delete_tkt_policy(&info.params, &name))
        .unwrap_or_else(|e| fail(format!("{e} while destroying policy object")));
    println!("** policy object '{name}' deleted.");
}

/// `kdb5_ldap_list_policies`.
fn list_policy(args: &[String], lcfg: &LdapConfig, realm: &str) {
    if !args.is_empty() && args.len() != 2 {
        usage();
    }
    let rt = runtime();
    let util = connect(&rt, lcfg);
    let info = realm_dn(&rt, &util, realm);
    let names = rt
        .block_on(util.list_tkt_policies(&info.params.realm_dn))
        .unwrap_or_else(|e| fail(format!("{e} while listing policy objects")));
    for n in names {
        println!("{n}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn strdur_matches_mit() {
        assert_eq!(strdur(86400), "1 day 00:00:00");
        assert_eq!(strdur(90061), "1 day 01:01:01");
        assert_eq!(strdur(36000), "0 days 10:00:00");
        assert_eq!(strdur(-172800), "-2 days 00:00:00");
    }

    #[test]
    fn ticket_flags_follow_get_ticket_policy() {
        let args = s(&[
            "-allow_postdated",
            "+requires_preauth",
            "-allow_tix",
            "+allow_svr",
        ]);
        let mut t = TicketOptions::default();
        let mut i = 0;
        while i < args.len() {
            assert!(matches!(
                ticket_option(&args, &mut i, 0x1000, &mut t),
                Parsed::Used
            ));
            i += 1;
        }
        assert_eq!(t.flags, Some(0x1 | 0x80 | 0x40));
        assert_eq!(
            flag_names(0x1 | 0x80 | 0x40),
            "DISALLOW_POSTDATED REQUIRES_PRE_AUTH DISALLOW_ALL_TIX "
        );
        let mut i = 0;
        assert!(matches!(
            ticket_option(&s(&["allow_tix"]), &mut i, 0, &mut t),
            Parsed::NotTicketOption
        ));
        let mut i = 0;
        assert!(matches!(
            ticket_option(&s(&["-maxtktlife"]), &mut i, 0, &mut t),
            Parsed::Bad
        ));
    }

    #[test]
    fn lifetimes_are_relative_to_now() {
        let args = s(&["-maxtktlife", "10 hours", "-maxrenewlife", "7 days"]);
        let mut t = TicketOptions::default();
        let mut i = 0;
        while i < args.len() {
            assert!(matches!(
                ticket_option(&args, &mut i, 0, &mut t),
                Parsed::Used
            ));
            i += 1;
        }
        let life = t.max_life.expect("life");
        assert!((35990..=36000).contains(&life), "{life}");
        let renew = t.max_renewable_life.expect("renew");
        assert!((604790..=604800).contains(&renew), "{renew}");
    }
}
