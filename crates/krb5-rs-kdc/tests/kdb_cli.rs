//! Runs the built `krb5-rs-kdb` binary end to end.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use krb5_rs::keytab::{FileKeytab, Keytab};

const REALM: &str = "KDB.TEST";

struct Env {
    dir: PathBuf,
    conf: PathBuf,
}

impl Env {
    fn new(tag: &str) -> Env {
        let dir = std::env::temp_dir().join(format!("krb5rs_kdb_{}_{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
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
        Env { dir, conf }
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
        let _ = std::fs::remove_dir_all(&self.dir);
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
