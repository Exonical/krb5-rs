//! The iprop update log: `krb5-rs-kdb` records admin changes in it,
//! `dump -i`/`load -i` carry its position, and `krb5-rs-kproplog` reads it.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

const REALM: &str = "IPROP.TEST";
const MASTER: &str = "master-password\nmaster-password\n";

struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> TempDir {
        let dir = std::env::temp_dir().join(format!("krb5rs_iprop_{}_{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        TempDir(dir)
    }

    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn slash(p: &Path) -> String {
    p.to_string_lossy().replace('\\', "/")
}

/// A klmdb realm under `dir/name`; primary and replica share the stash.
fn write_conf(dir: &TempDir, name: &str, iprop: bool) -> PathBuf {
    write_conf_for(dir, name, iprop, None)
}

/// [`write_conf`] for the database module `db_library` names.
fn write_conf_for(dir: &TempDir, name: &str, iprop: bool, library: Option<&str>) -> PathBuf {
    let module = library.map_or_else(String::new, |l| {
        format!("  database_module = m\n }}\n[dbmodules]\n m = {{\n  db_library = {l}\n")
    });
    let db = dir.path(name);
    std::fs::create_dir_all(&db).expect("db dir");
    let conf = dir.path(&format!("{name}.conf"));
    std::fs::write(
        &conf,
        format!(
            "[realms]\n {REALM} = {{\n  database_name = {}\n  key_stash_file = {}\n  \
             supported_enctypes = aes256-cts-hmac-sha1-96:normal\n  iprop_enable = {iprop}\n{module} }}\n",
            slash(&db.join("principal")),
            slash(&dir.path("stash")),
        ),
    )
    .expect("kdc.conf");
    conf
}

fn kdb(conf: &Path, args: &[&str], stdin: &str) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_krb5-rs-kdb"))
        .args(["--config", &conf.to_string_lossy(), "--realm", REALM])
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn krb5-rs-kdb");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(stdin.as_bytes())
        .expect("write stdin");
    child.wait_with_output().expect("wait")
}

fn kdb_ok(conf: &Path, args: &[&str], stdin: &str) -> String {
    let out = kdb(conf, args, stdin);
    assert!(
        out.status.success(),
        "{args:?} failed: {}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).to_string()
}

fn kproplog(dir: &TempDir, conf: &Path, args: &[&str]) -> String {
    let krb5 = dir.path("krb5.conf");
    std::fs::write(&krb5, format!("[libdefaults]\n default_realm = {REALM}\n")).expect("krb5.conf");
    let out = Command::new(env!("CARGO_BIN_EXE_krb5-rs-kproplog"))
        .args(args)
        .env("KRB5_KDC_PROFILE", conf)
        .env("KRB5_CONFIG", &krb5)
        .env("TZ", "UTC")
        .output()
        .expect("kproplog");
    assert!(
        out.status.success(),
        "kproplog {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).to_string()
}

fn field(log: &str, name: &str) -> String {
    log.lines()
        .find_map(|l| l.trim().strip_prefix(name))
        .map(|v| v.trim_start_matches(" : ").to_owned())
        .unwrap_or_else(|| panic!("{name} missing from:\n{log}"))
}

#[test]
fn admin_changes_are_logged_and_iprop_dumps_carry_the_serial() {
    admin_changes_are_logged("log", None);
}

#[test]
fn file_store_admin_changes_are_logged_like_db2() {
    admin_changes_are_logged("file_log", Some("krb5-rs-file"));
}

fn admin_changes_are_logged(tag: &str, library: Option<&str>) {
    let dir = TempDir::new(tag);
    let primary = write_conf_for(&dir, "primary", true, library);
    kdb_ok(&primary, &["create", "-s"], MASTER);
    kdb_ok(&primary, &["addprinc", "alice"], "alice-password\n");
    kdb_ok(&primary, &["addprinc", "-randkey", "bob"], "");
    kdb_ok(&primary, &["cpw", "alice"], "alice-password-2\n");
    kdb_ok(&primary, &["delprinc", "bob"], "");

    let header = kproplog(&dir, &primary, &["-h"]);
    assert_eq!(field(&header, "Log state"), "Stable", "{header}");
    let last: u32 = field(&header, "Last serial #").parse().expect("serial");
    let log = kproplog(&dir, &primary, &["-v", "-v"]);
    println!("{log}");
    let ops: Vec<_> = log
        .lines()
        .filter_map(|l| l.trim().strip_prefix("Update principal : "))
        .collect();
    assert_eq!(
        ops,
        [
            format!("alice@{REALM}"),
            format!("bob@{REALM}"),
            format!("alice@{REALM}"),
            format!("bob@{REALM}"),
        ],
        "{log}"
    );
    assert!(log.contains("Update operation : Delete"), "{log}");
    assert!(log.contains("\t\tKey data\n"), "{log}");
    assert!(!log.contains("Last successful auth"), "{log}");
    let tail = kproplog(&dir, &primary, &["-e", "1"]);
    assert_eq!(tail.matches("Update Entry").count(), 1, "{tail}");

    let dump = dir.path("ipropx.dump");
    let dump_s = dump.to_string_lossy().to_string();
    kdb_ok(&primary, &["dump", "-i1", &dump_s], "");
    let text = std::fs::read_to_string(&dump).expect("dump");
    let first = text.lines().next().expect("header");
    assert!(first.starts_with(&format!("ipropx 1 {last} ")), "{first}");
    assert!(text.contains(&format!("alice@{REALM}")));

    std::fs::write(&dump, format!("{first}\nstale\n")).expect("rewrite");
    kdb_ok(&primary, &["dump", "-i1", "-c", &dump_s], "");
    assert!(std::fs::read_to_string(&dump)
        .expect("dump")
        .contains("stale"));
    let legacy = dir.path("iprop.dump");
    kdb_ok(&primary, &["dump", "-i", &legacy.to_string_lossy()], "");
    let legacy_text = std::fs::read_to_string(&legacy).expect("dump");
    assert!(
        legacy_text.starts_with(&format!("iprop {last} ")),
        "{legacy_text}"
    );

    kdb_ok(&primary, &["addprinc", "-randkey", "carol"], "");
    kdb_ok(&primary, &["dump", "-i1", "-c", &dump_s], "");
    assert!(std::fs::read_to_string(&dump)
        .expect("dump")
        .contains("stale"));
    std::fs::write(&dump, "ipropx 1 999 0 0\nstale\n").expect("rewrite");
    kdb_ok(&primary, &["dump", "-i1", "-c", &dump_s], "");
    let fresh = std::fs::read_to_string(&dump).expect("dump");
    assert!(
        fresh.starts_with(&format!("ipropx 1 {} ", last + 1)),
        "{fresh}"
    );
    assert!(fresh.contains(&format!("carol@{REALM}")));

    let replica = write_conf_for(&dir, "replica", true, library);
    kdb_ok(&replica, &["load", "-i", &dump_s], "");
    let replica_header = kproplog(&dir, &replica, &["-h"]);
    assert_eq!(
        field(&replica_header, "Last serial #"),
        (last + 1).to_string(),
        "{replica_header}"
    );
    kdb_ok(&replica, &["getprinc", "carol"], "");

    kdb_ok(&primary, &["addpol", "p1"], "");
    let reset = kproplog(&dir, &primary, &["-h"]);
    assert_eq!(field(&reset, "Last serial #"), "1", "{reset}");
}

#[test]
fn update_loads_log_each_principal_and_policies_reset_the_log() {
    let dir = TempDir::new("update");
    let primary = write_conf(&dir, "primary", true);
    kdb_ok(&primary, &["create", "-s"], MASTER);
    kdb_ok(&primary, &["addprinc", "-randkey", "alice"], "");
    kdb_ok(&primary, &["addprinc", "-randkey", "bob"], "");
    let bob = dir.path("bob.dump").to_string_lossy().to_string();
    kdb_ok(&primary, &["dump", &bob, "bob@IPROP\\.TEST"], "");
    let before: u32 = field(&kproplog(&dir, &primary, &["-h"]), "Last serial #")
        .parse()
        .expect("serial");

    kdb_ok(&primary, &["load", "-update", &bob], "");
    let header = kproplog(&dir, &primary, &["-h"]);
    assert_eq!(
        field(&header, "Last serial #"),
        (before + 1).to_string(),
        "{header}"
    );
    let tail = kproplog(&dir, &primary, &["-v", "-e", "1"]);
    assert!(
        tail.contains(&format!("Update principal : bob@{REALM}")),
        "{tail}"
    );

    kdb_ok(&primary, &["addpol", "p1"], "");
    let full = dir.path("full.dump").to_string_lossy().to_string();
    kdb_ok(&primary, &["dump", &full], "");
    kdb_ok(&primary, &["addprinc", "-randkey", "carol"], "");
    kdb_ok(&primary, &["load", "-update", &full], "");
    let log = kproplog(&dir, &primary, &["-v"]);
    assert!(!log.contains("Update principal"), "{log}");
    kdb_ok(&primary, &["getprinc", "carol"], "");
}

/// A dump of `bob` and `alice` where `bob` carries 80000 bytes of TL data: too
/// large for any ulog block (`kdb_log.c:203-222`).
fn oversized_dump(dir: &TempDir, primary: &Path) -> String {
    let path = dir.path("big.dump");
    kdb_ok(
        primary,
        &["dump", &path.to_string_lossy(), "(alice|bob)@IPROP\\.TEST"],
        "",
    );
    let text = std::fs::read_to_string(&path).expect("dump");
    let lines: Vec<String> = text
        .lines()
        .map(|line| {
            let mut f: Vec<String> = line.split('\t').map(str::to_string).collect();
            if f.len() > 6 && f[0] == "princ" && f[6] == format!("bob@{REALM}") {
                f[3] = (f[3].parse::<u32>().expect("tl count") + 2).to_string();
                for kind in ["32766", "32767"] {
                    let tl = [kind.to_string(), "40000".to_string(), "ab".repeat(40000)];
                    f.splice(15..15, tl);
                }
            }
            f.join("\t")
        })
        .collect();
    std::fs::write(&path, lines.join("\n") + "\n").expect("write dump");
    path.to_string_lossy().to_string()
}

#[test]
fn update_load_too_large_for_the_log_changes_nothing() {
    let dir = TempDir::new("oversized");
    let primary = write_conf(&dir, "primary", true);
    kdb_ok(&primary, &["create", "-s"], MASTER);
    kdb_ok(&primary, &["addprinc", "-randkey", "alice"], "");
    kdb_ok(&primary, &["addprinc", "-randkey", "bob"], "");
    let dump = oversized_dump(&dir, &primary);
    kdb_ok(&primary, &["cpw", "-randkey", "alice"], "");
    let header = kproplog(&dir, &primary, &["-h"]);
    let before = kdb_ok(&primary, &["getprinc", "alice"], "");

    let out = kdb(&primary, &["load", "-update", &dump], "");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !out.status.success() && stderr.contains("ulog overflow"),
        "{stderr}"
    );
    assert_eq!(kdb_ok(&primary, &["getprinc", "alice"], ""), before);
    assert_eq!(
        field(&kproplog(&dir, &primary, &["-h"]), "Last serial #"),
        field(&header, "Last serial #")
    );
}

#[test]
fn iprop_options_need_iprop_enable() {
    let dir = TempDir::new("off");
    let conf = write_conf(&dir, "kdc", false);
    kdb_ok(&conf, &["create", "-s"], MASTER);
    let dump = dir.path("d");
    let out = kdb(&conf, &["dump", "-i1", &dump.to_string_lossy()], "");
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("Iprop not enabled"));
    kdb_ok(&conf, &["dump", &dump.to_string_lossy()], "");
    let out = kdb(&conf, &["load", "-i", &dump.to_string_lossy()], "");
    assert!(String::from_utf8_lossy(&out.stderr).contains("Iprop not enabled"));
    assert!(!dir.path("kdc/principal.ulog").exists());
}

#[test]
fn legacy_iprop_dump_with_policies_loads() {
    let dir = TempDir::new("legacy");
    let primary = write_conf(&dir, "primary", true);
    kdb_ok(&primary, &["create", "-s"], MASTER);
    kdb_ok(&primary, &["addpol", "-maxlife", "1h", "p1"], "");
    kdb_ok(
        &primary,
        &["addprinc", "-randkey", "-policy", "p1", "erin"],
        "",
    );
    let dump = dir.path("iprop.dump");
    let dump_s = dump.to_string_lossy().to_string();
    kdb_ok(&primary, &["dump", "-i", &dump_s], "");
    assert!(std::fs::read_to_string(&dump)
        .expect("dump")
        .starts_with("iprop "));

    let replica = write_conf(&dir, "replica", true);
    kdb_ok(&replica, &["load", "-i", &dump_s], "");
    assert!(kdb_ok(&replica, &["getprinc", "erin"], "").contains("p1"));
}

#[test]
fn database_override_logs_to_its_own_ulog() {
    let dir = TempDir::new("override");
    let conf = write_conf(&dir, "primary", true);
    let alt = dir.path("alt");
    std::fs::create_dir_all(&alt).expect("alt dir");
    let alt_db = alt.join("principal");
    let alt_s = alt_db.to_string_lossy().to_string();
    kdb_ok(&conf, &["-d", &alt_s, "create", "-s"], MASTER);
    kdb_ok(&conf, &["-d", &alt_s, "addprinc", "-randkey", "dave"], "");
    assert!(alt.join("principal.ulog").exists());
    assert!(!dir.path("primary").join("principal.ulog").exists());

    let explicit = dir.path("primary").join("principal.ulog");
    let text = std::fs::read_to_string(&conf).expect("conf");
    std::fs::write(
        &conf,
        text.replace(
            "  iprop_enable = true\n",
            &format!(
                "  iprop_enable = true\n  iprop_logfile = {}\n",
                slash(&explicit)
            ),
        ),
    )
    .expect("conf");
    kdb_ok(&conf, &["-d", &alt_s, "addprinc", "-randkey", "eve"], "");
    assert!(explicit.exists());
}
