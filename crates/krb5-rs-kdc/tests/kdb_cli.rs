//! Runs the built `krb5-rs-kdb` binary end to end.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use krb5_rs::keytab::{FileKeytab, Keytab};

const REALM: &str = "KDB.TEST";

#[test]
fn help_does_not_require_a_database_configuration() {
    let output = Command::new(env!("CARGO_BIN_EXE_krb5-rs-kdb"))
        .arg("--help")
        .output()
        .expect("run help");
    assert!(output.status.success());
    let help = String::from_utf8_lossy(&output.stderr);
    assert!(help.contains("commands:"));
    assert!(help.contains("klmdb") || help.contains("database"));
}

struct Env {
    dir: PathBuf,
    conf: PathBuf,
    remove_dir_on_drop: bool,
}

impl Env {
    fn new(tag: &str) -> Env {
        let dir = std::env::temp_dir().join(format!("krb5rs_kdb_{}_{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        Self::in_directory(&dir, true)
    }

    fn from_tempdir(dir: &Path) -> Env {
        Self::in_directory(dir, false)
    }

    fn in_directory(dir: &Path, remove_dir_on_drop: bool) -> Env {
        let dir = dir.to_path_buf();
        let slash = |p: &Path| p.to_string_lossy().replace('\\', "/");
        let conf = dir.join("kdc.conf");
        std::fs::write(
            &conf,
            format!(
                "[realms]\n {REALM} = {{\n  database_name = {}\n  key_stash_file = {}\n  \
                 supported_enctypes = aes256-cts-hmac-sha1-96:normal\n }}\n",
                slash(&dir.join("principal")),
                slash(&dir.join("stash")),
            ),
        )
        .expect("kdc.conf");
        Env {
            dir,
            conf,
            remove_dir_on_drop,
        }
    }

    fn run(&self, args: &[&str], stdin: &str) -> Output {
        let mut child = Command::new(env!("CARGO_BIN_EXE_krb5-rs-kdb"))
            .args(["--config", &self.conf.to_string_lossy(), "--realm", REALM])
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

    fn ok(&self, args: &[&str], stdin: &str) -> String {
        let out = self.run(args, stdin);
        assert!(
            out.status.success(),
            "{args:?} failed: {}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).to_string()
    }
}

impl Drop for Env {
    fn drop(&mut self) {
        if self.remove_dir_on_drop {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }
}

#[test]
fn create_addprinc_getprinc_ktadd_listprincs_end_to_end() {
    let env = Env::new("e2e");
    env.ok(&["create", "-s"], "master-password\n");
    assert!(env.dir.join("stash").exists(), "create -s writes the stash");

    let out = env.ok(&["addprinc", "alice"], "alice-password\n");
    assert!(
        out.contains(&format!("Principal \"alice@{REALM}\" created.")),
        "{out}"
    );
    env.ok(&["addprinc", "-randkey", "HTTP/host.kdb.test"], "");

    let out = env.ok(&["getprinc", "alice"], "");
    assert!(out.contains(&format!("alice@{REALM}")), "{out}");

    let out = env.ok(&["listprincs"], "");
    assert!(out.contains(&format!("alice@{REALM}")), "{out}");
    assert!(out.contains(&format!("krbtgt/{REALM}@{REALM}")), "{out}");
    assert!(
        out.contains(&format!("HTTP/host.kdb.test@{REALM}")),
        "{out}"
    );

    let keytab = env.dir.join("svc.keytab");
    let out = env.ok(
        &[
            "ktadd",
            "-k",
            &keytab.to_string_lossy(),
            "HTTP/host.kdb.test",
        ],
        "",
    );
    assert!(
        out.contains(&format!(
            "Entry for principal HTTP/host.kdb.test@{REALM} with kvno"
        )),
        "{out}"
    );
    let entries = FileKeytab::new(&keytab).entries().expect("read keytab");
    assert!(
        entries
            .iter()
            .any(|e| e.realm == REALM && e.principal.to_string() == "HTTP/host.kdb.test"),
        "{entries:?}"
    );
}

#[test]
fn modprinc_cpw_and_delprinc_change_the_database() {
    let env = Env::new("mod");
    env.ok(&["create", "-s"], "master\n");
    env.ok(&["addprinc", "bob"], "pw1\n");
    env.ok(&["modprinc", "+requires_preauth", "bob"], "");
    let out = env.ok(&["getprinc", "bob"], "");
    assert!(out.contains("Attributes: REQUIRES_PRE_AUTH"), "{out}");
    env.ok(&["cpw", "bob"], "pw2\n");
    env.ok(&["delprinc", "bob"], "");
    let out = env.run(&["getprinc", "bob"], "");
    assert_eq!(out.status.code(), Some(1));
    assert!(!env.ok(&["listprincs"], "").contains("bob@"));
}

#[test]
fn errors_exit_non_zero() {
    let env = Env::new("err");
    // No database yet.
    assert_eq!(env.run(&["listprincs"], "").status.code(), Some(1));
    env.ok(&["create", "-s"], "master\n");
    assert_eq!(env.run(&["getprinc", "nobody"], "").status.code(), Some(1));
    // Usage errors.
    assert_eq!(env.run(&["bogus"], "").status.code(), Some(2));
    assert_eq!(env.run(&[], "").status.code(), Some(2));
}

#[test]
fn init_is_idempotent_and_reads_secrets_only_from_files() {
    let env = Env::new("init");
    let master = env.dir.join("master");
    let pw = env.dir.join("kprop-pw");
    std::fs::write(&master, "master-secret\n").expect("master file");
    std::fs::write(&pw, "kprop-secret\r\n").expect("password file");
    let args = [
        "init",
        "--master-password-file",
        &master.to_string_lossy(),
        "--stash",
        "--randkey",
        "kprop/primary",
        "--password",
        &format!("kprop/replica={}", pw.display()),
    ];

    let out = env.ok(&args, "");
    assert!(out.contains("Database") && out.contains("created"), "{out}");
    assert!(
        out.contains(&format!("Principal \"kprop/primary@{REALM}\" created.")),
        "{out}"
    );
    assert!(env.dir.join("stash").exists());
    let listed = env.ok(&["listprincs"], "");
    assert!(
        listed.contains(&format!("kprop/replica@{REALM}")),
        "{listed}"
    );
    let before = env.ok(&["getprinc", "kprop/primary"], "");

    // A second run changes nothing and succeeds.
    let out = env.ok(&args, "");
    assert!(!out.contains("created"), "{out}");
    assert_eq!(out.matches("already exists").count(), 2, "{out}");
    assert_eq!(env.ok(&["getprinc", "kprop/primary"], ""), before);

    // A database without the kadm5 service principals (as made by earlier
    // releases) gets them back from init.
    env.ok(&["delprinc", "kadmin/changepw"], "");
    assert!(!env.ok(&["listprincs"], "").contains("kadmin/changepw"));
    env.ok(&args, "");
    let listed = env.ok(&["listprincs"], "");
    assert!(
        listed.contains(&format!("kadmin/changepw@{REALM}")),
        "{listed}"
    );

    // A different master password cannot open the existing database.
    std::fs::write(&master, "other\n").expect("master file");
    assert_eq!(env.run(&args, "").status.code(), Some(1));
    // Missing or empty secret files and missing options are errors.
    assert_eq!(
        env.run(&["init", "--master-password-file", "/nonexistent/x"], "")
            .status
            .code(),
        Some(1)
    );
    assert_eq!(env.run(&["init"], "").status.code(), Some(1));
}

#[test]
fn global_master_password_file_opens_file_database_without_a_stash() {
    let temp = tempfile::tempdir().expect("temp dir");
    let env = Env::from_tempdir(temp.path());
    let master = env.dir.join("master");
    let wrong = env.dir.join("wrong-master");
    std::fs::write(&master, "master-secret\n").expect("master file");
    std::fs::write(&wrong, "not-the-master\n").expect("wrong master file");

    let master_path = master.to_string_lossy().into_owned();
    env.ok(&["create"], "master-secret\n");
    env.ok(
        &["--master-password-file", &master_path, "addprinc", "alice"],
        "alice-password\n",
    );
    assert!(!env.dir.join("stash").exists());

    let listed = env.ok(&["--master-password-file", &master_path, "listprincs"], "");
    assert!(listed.contains(&format!("alice@{REALM}")), "{listed}");

    let wrong_path = wrong.to_string_lossy().into_owned();
    let failed = env.run(&["--master-password-file", &wrong_path, "listprincs"], "");
    assert!(!failed.status.success());
    assert!(
        String::from_utf8_lossy(&failed.stderr).contains("master key"),
        "{}",
        String::from_utf8_lossy(&failed.stderr)
    );
}

#[test]
fn init_falls_back_to_the_global_master_password_file() {
    let temp = tempfile::tempdir().expect("temp dir");
    let env = Env::from_tempdir(temp.path());
    let master = env.dir.join("master");
    std::fs::write(&master, "master-secret\n").expect("master file");
    let master_path = master.to_string_lossy().into_owned();

    let output = env.ok(&["--master-password-file", &master_path, "init"], "");
    assert!(
        output.contains("Database") && output.contains("created"),
        "{output}"
    );
}

#[test]
fn policy_commands_and_principal_policy_options() {
    let env = Env::new("policy");
    env.ok(&["create", "-s"], "master\n");

    let out = env.ok(
        &[
            "addpol",
            "-maxfailure",
            "3",
            "-failurecountinterval",
            "10m",
            "-lockoutduration",
            "1h",
            "-minlength",
            "8",
            "strict",
        ],
        "",
    );
    assert!(out.contains("Policy \"strict\" created."), "{out}");
    let out = env.ok(&["getpol", "strict"], "");
    assert!(out.contains("Policy: strict"), "{out}");
    assert!(
        out.contains("Maximum password failures before lockout: 3"),
        "{out}"
    );
    assert!(
        out.contains("Password failure count reset interval: 0 days 00:10:00"),
        "{out}"
    );
    assert!(
        out.contains("Password lockout duration: 0 days 01:00:00"),
        "{out}"
    );
    assert!(out.contains("Minimum password length: 8"), "{out}");
    // -terse: name, max life, min life, length, classes, history, 0,
    // max failures, interval, duration, keysalts (kadmin.c:1813).
    let terse = env.ok(&["getpol", "-terse", "strict"], "");
    assert_eq!(
        terse.trim(),
        "\"strict\"\t0\t0\t8\t0\t0\t0\t3\t600\t3600\t-"
    );

    env.ok(&["modpol", "-maxfailure", "5", "strict"], "");
    assert!(env
        .ok(&["getpol", "strict"], "")
        .contains("Maximum password failures before lockout: 5"));
    assert!(env.ok(&["listpols"], "").contains("strict"));

    // Duplicate and unknown policies are errors.
    assert_eq!(env.run(&["addpol", "strict"], "").status.code(), Some(1));
    assert_eq!(env.run(&["modpol", "nope"], "").status.code(), Some(1));
    assert_eq!(env.run(&["getpol", "nope"], "").status.code(), Some(1));

    // -policy / -clearpolicy / -unlock.
    assert_eq!(
        env.run(&["addprinc", "-policy", "nope", "bob"], "pw\n")
            .status
            .code(),
        Some(1)
    );
    // The policy's -minlength 8 applies, with MIT's message.
    let short = env.run(&["addprinc", "-policy", "strict", "bob"], "pw\n");
    assert_eq!(short.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&short.stderr).contains("Password is too short"));
    env.ok(
        &["addprinc", "-policy", "strict", "bob"],
        "long-enough-pw\n",
    );
    assert!(env.ok(&["getprinc", "bob"], "").contains("Policy: strict"));
    env.ok(&["modprinc", "-unlock", "bob"], "");
    env.ok(&["modprinc", "-clearpolicy", "bob"], "");
    assert!(env.ok(&["getprinc", "bob"], "").contains("Policy: [none]"));

    env.ok(&["delpol", "strict"], "");
    assert_eq!(env.run(&["delpol", "strict"], "").status.code(), Some(1));
    assert!(!env.ok(&["listpols"], "").contains("strict"));
}
