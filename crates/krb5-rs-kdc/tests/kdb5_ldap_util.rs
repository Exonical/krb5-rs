//! `krb5-rs-kdb5-ldap-util` against a real OpenLDAP server with MIT's
//! schema (`krb5-rs-kdb-ldap/tests/slapd.sh`).
#![cfg(all(feature = "kldap", feature = "klmdb"))]

use std::io::Write;
use std::path::Path;
use std::process::{Command, Output, Stdio};

const REALM: &str = "LDAP.TEST";
const ADMIN: &str = "cn=admin,dc=example,dc=com";

struct Slapd(String);

impl Drop for Slapd {
    fn drop(&mut self) {
        let _ = Command::new("kill").arg(&self.0).status();
    }
}

struct Util<'a> {
    conf: &'a Path,
}

impl Util<'_> {
    fn run(&self, args: &[&str], stdin: &str) -> Output {
        let mut child = Command::new(env!("CARGO_BIN_EXE_krb5-rs-kdb5-ldap-util"))
            .args(args)
            .env("KRB5_KDC_PROFILE", self.conf)
            .env("KRB5_CONFIG", "/nonexistent")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn");
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
            "{args:?}: {}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).into_owned()
    }
}

fn ldap(tool: &str, port: u16, args: &[&str], stdin: &str) -> String {
    let url = format!("ldap://127.0.0.1:{port}/");
    let mut child = Command::new(tool)
        .args(["-x", "-H", &url, "-D", ADMIN, "-w", "secret"])
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect(tool);
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(stdin.as_bytes())
        .expect("write");
    let out = child.wait_with_output().expect("wait");
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

fn squash(s: &str) -> String {
    s.lines()
        .map(|l| l.split_whitespace().collect::<Vec<_>>().join(" "))
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
#[ignore = "needs OpenLDAP slapd and ldap-utils"]
fn kdb5_ldap_util_against_openldap() {
    if !Path::new("/usr/sbin/slapd").exists() {
        eprintln!("slapd not installed; skipping");
        return;
    }
    let dir = tempfile::tempdir().expect("tempdir");
    let port = free_port();
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("../krb5-rs-kdb-ldap/tests/slapd.sh");
    let out = Command::new("sh")
        .arg(&script)
        .arg(dir.path().join("slapd"))
        .arg(port.to_string())
        .output()
        .expect("slapd.sh");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let _slapd = Slapd(String::from_utf8_lossy(&out.stdout).trim().to_string());

    let service = dir.path().join("service.keyfile");
    let stash = dir.path().join("stash");
    let conf = dir.path().join("kdc.conf");
    std::fs::write(
        &conf,
        format!(
            "[realms]\n {REALM} = {{\n  database_module = ldap\n  key_stash_file = {}\n }}\n\
             [dbmodules]\n ldap = {{\n  db_library = kldap\n\
               ldap_kerberos_container_dn = cn=krbcontainer,dc=example,dc=com\n\
               ldap_kdc_dn = {ADMIN}\n  ldap_kadmind_dn = {ADMIN}\n\
               ldap_service_password_file = {}\n\
               ldap_servers = ldap://127.0.0.1:{port}/\n }}\n",
            stash.display(),
            service.display()
        ),
    )
    .expect("kdc.conf");
    let util = Util { conf: &conf };

    // stashsrvpw: two prompts, then `dn#{HEX}...`; a second run replaces it.
    let out = util.ok(
        &["stashsrvpw", "-f", service.to_str().expect("path"), ADMIN],
        "wrong\nwrong\n",
    );
    assert!(out.contains(&format!("Password for \"{ADMIN}\"")), "{out}");
    util.ok(&["stashsrvpw", ADMIN], "secret\nsecret\n");
    assert_eq!(
        std::fs::read_to_string(&service).expect("service file"),
        format!("{ADMIN}#{{HEX}}736563726574\n")
    );
    let bad = util.run(&["stashsrvpw", ADMIN], "a\nb\n");
    assert!(!bad.status.success());

    let out = util.ok(
        &[
            "-r",
            REALM,
            "create",
            "-subtrees",
            "ou=people,dc=example,dc=com",
            "-sscope",
            "one",
            "-maxtktlife",
            "10 hours",
            "-allow_postdated",
            "+requires_preauth",
            "-s",
            "-P",
            "master",
        ],
        "",
    );
    assert!(
        out.contains("Initializing database for realm 'LDAP.TEST'"),
        "{out}"
    );
    assert!(stash.exists());
    let dup = util.run(&["create", "-P", "master"], "");
    assert!(!dup.status.success());
    let bad = util.run(
        &[
            "create",
            "-subtrees",
            "ou=missing,dc=example,dc=com",
            "-P",
            "m",
        ],
        "",
    );
    assert!(!bad.status.success());
    let bad = util.run(&["create", "-bogus", "-P", "m"], "");
    assert!(String::from_utf8_lossy(&bad.stdout).contains("'-bogus' is an invalid option"));

    assert_eq!(util.ok(&["list"], ""), "LDAP.TEST\n");
    let view = squash(&util.ok(&["view"], ""));
    assert!(view.contains("Realm Name: LDAP.TEST"), "{view}");
    assert!(
        view.contains("Subtree: ou=people,dc=example,dc=com"),
        "{view}"
    );
    assert!(view.contains("SearchScope: ONE"), "{view}");
    assert!(
        view.contains("Maximum Ticket Life: 0 days 10:00:00"),
        "{view}"
    );
    assert!(
        view.contains("Ticket flags: DISALLOW_POSTDATED REQUIRES_PRE_AUTH"),
        "{view}"
    );

    util.ok(
        &[
            "modify",
            "-sscope",
            "sub",
            "+allow_postdated",
            "-allow_tix",
            "-maxrenewlife",
            "2 days",
        ],
        "",
    );
    let view = squash(&util.ok(&["view"], ""));
    assert!(view.contains("SearchScope: SUB"), "{view}");
    assert!(
        view.contains("Maximum Renewable Life: 2 days 00:00:00"),
        "{view}"
    );
    assert!(
        view.contains("Ticket flags: REQUIRES_PRE_AUTH DISALLOW_ALL_TIX"),
        "{view}"
    );

    util.ok(
        &[
            "create_policy",
            "-maxtktlife",
            "1 day",
            "+requires_hwauth",
            "tp1",
        ],
        "",
    );
    util.ok(&["create_policy", "tp2"], "");
    assert!(!util.run(&["create_policy", "tp1"], "").status.success());
    let view = squash(&util.ok(&["view_policy", "tp1"], ""));
    assert!(view.contains("Ticket policy: tp1"), "{view}");
    assert!(
        view.contains("Maximum ticket life: 1 day 00:00:00"),
        "{view}"
    );
    assert!(view.contains("Ticket flags: REQUIRES_HW_AUTH"), "{view}");
    util.ok(
        &[
            "modify_policy",
            "-maxrenewlife",
            "3 days",
            "-requires_hwauth",
            "tp1",
        ],
        "",
    );
    let view = squash(&util.ok(&["view_policy", "tp1"], ""));
    assert!(
        view.contains("Maximum renewable life: 3 days 00:00:00"),
        "{view}"
    );
    assert!(
        view.contains("Maximum ticket life: 1 day 00:00:00"),
        "{view}"
    );
    assert!(!view.contains("REQUIRES_HW_AUTH"), "{view}");
    let mut names: Vec<String> = util
        .ok(&["list_policy"], "")
        .lines()
        .map(String::from)
        .collect();
    names.sort();
    assert_eq!(names, ["tp1", "tp2"]);

    // A policy a principal references is not deleted.
    let krbtgt = format!(
        "krbprincipalname=krbtgt/{REALM}@{REALM},cn={REALM},cn=krbcontainer,dc=example,dc=com"
    );
    let r = ldap(
        "ldapmodify",
        port,
        &[],
        &format!(
            "dn: {krbtgt}\nchangetype: modify\nadd: krbTicketPolicyReference\n\
             krbTicketPolicyReference: cn=tp2,cn={REALM},cn=krbcontainer,dc=example,dc=com\n"
        ),
    );
    assert!(r.contains("modifying entry"), "{r}");
    let out = util.run(&["destroy_policy", "-force", "tp2"], "");
    assert!(
        String::from_utf8_lossy(&out.stderr)
            .contains("Delete Failed: One or more Principals associated with the Ticket Policy"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let out = util.run(&["destroy_policy", "tp1"], "no\n");
    assert!(!out.status.success());
    let out = util.ok(&["destroy_policy", "tp1"], "yes\n");
    assert!(out.contains("** policy object 'tp1' deleted."), "{out}");
    assert_eq!(util.ok(&["list_policy"], ""), "tp2\n");

    let out = util.run(&["destroy"], "nope\n");
    assert!(!out.status.success());
    assert_eq!(util.ok(&["list"], ""), "LDAP.TEST\n");
    let out = util.ok(&["destroy", "-f"], "");
    assert!(
        out.contains("** Database of 'LDAP.TEST' destroyed."),
        "{out}"
    );
    assert_eq!(util.ok(&["list"], ""), "");
    let left = ldap(
        "ldapsearch",
        port,
        &[
            "-LLL",
            "-b",
            "dc=example,dc=com",
            "(krbprincipalname=*)",
            "dn",
        ],
        "",
    );
    assert!(!left.contains("dn:"), "{left}");
}

/// A port that was free a moment ago (the kernel picks it), so slapd
/// doesn't collide with another listener.
fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .and_then(|l| l.local_addr())
        .expect("free port")
        .port()
}
