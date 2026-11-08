//! SASL binds against a real OpenLDAP server (tests/slapd.sh), whose Cyrus
//! SASL checks the mechanisms against `cn=kdcsasl`'s userPassword.

use std::path::Path;
use std::process::Command;

use krb5_rs_kdb_ldap::conn::{connect, Bind};
use ldap3::exop::{WhoAmI, WhoAmIResp};
use ldap3::Scope;

struct Slapd(String);

struct Child(std::process::Child);

impl Drop for Child {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn run(cmd: &mut Command) {
    let out = cmd.output().expect("spawn");
    assert!(
        out.status.success(),
        "{cmd:?}: {}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

fn start_slapd(dir: &Path, port: u16, env: &[(&str, &Path)]) -> Slapd {
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/slapd.sh");
    let mut cmd = Command::new("sh");
    cmd.arg(&script)
        .arg(dir.join("slapd"))
        .arg(port.to_string());
    for (k, v) in env {
        cmd.env(k, v);
    }
    let out = cmd.output().expect("slapd.sh");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    Slapd(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

impl Drop for Slapd {
    fn drop(&mut self) {
        let _ = Command::new("kill").arg(&self.0).status();
    }
}

fn bind(mech: &str, password: &str, authzid: Option<&str>) -> Bind {
    Bind::Sasl {
        mech: mech.into(),
        authcid: Some("kdcsasl".into()),
        authzid: authzid.map(Into::into),
        realm: None,
        password: Some(password.into()),
    }
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs OpenLDAP slapd and Cyrus SASL modules"]
async fn sasl_binds_against_openldap() {
    if !Path::new("/usr/sbin/slapd").exists() {
        eprintln!("slapd not installed; skipping");
        return;
    }
    let dir = tempfile::tempdir().expect("tempdir");
    let port = 20000 + (std::process::id() % 20000) as u16 + 1;
    let _slapd = start_slapd(dir.path(), port, &[]);
    let url = format!("ldap://127.0.0.1:{port}/");

    let mut anon = connect(
        &url,
        &Bind::Simple {
            dn: String::new(),
            password: String::new(),
        },
    )
    .await
    .expect("anonymous bind");
    let (rs, _) = anon
        .search(
            "",
            Scope::Base,
            "(objectClass=*)",
            vec!["supportedSASLMechanisms"],
        )
        .await
        .expect("root DSE")
        .success()
        .expect("root DSE");
    let dse = ldap3::SearchEntry::construct(rs.into_iter().next().expect("root DSE"));
    let offered = dse
        .attrs
        .get("supportedSASLMechanisms")
        .cloned()
        .unwrap_or_default();
    eprintln!("server offers {offered:?}");

    for mech in [
        "PLAIN",
        "LOGIN",
        "CRAM-MD5",
        "DIGEST-MD5",
        "SCRAM-SHA-1",
        "SCRAM-SHA-256",
    ] {
        if !offered.iter().any(|m| m == mech) {
            eprintln!("{mech} not offered; skipping");
            continue;
        }
        let mut ldap = connect(&url, &bind(mech, "saslsecret", None))
            .await
            .unwrap_or_else(|e| panic!("{mech}: {e}"));
        let (exop, _) = ldap
            .extended(WhoAmI)
            .await
            .expect("whoami")
            .success()
            .expect("whoami");
        let who: WhoAmIResp = exop.parse();
        assert_eq!(who.authzid, "dn:cn=kdcsasl,dc=example,dc=com", "{mech}");
        // DIGEST-MD5 negotiates a security layer; the search runs through it.
        let (rs, _) = ldap
            .search(
                "dc=example,dc=com",
                Scope::Subtree,
                "(cn=kdcsasl)",
                vec!["cn"],
            )
            .await
            .expect("search")
            .success()
            .unwrap_or_else(|e| panic!("{mech} search: {e}"));
        assert_eq!(rs.len(), 1, "{mech}");
        ldap.unbind().await.ok();

        let err = connect(&url, &bind(mech, "wrong", None))
            .await
            .expect_err("wrong password accepted");
        let msg = err.to_string();
        assert!(
            msg.contains(&format!("with SASL mechanism '{mech}'")),
            "{mech}: {msg}"
        );
    }

    let err = connect(&url, &bind("NOSUCH-MECH", "x", None))
        .await
        .expect_err("unknown mechanism");
    assert!(err.to_string().contains("NOSUCH-MECH"), "{err}");
}

/// GSSAPI on krb5-rs's GSS-API against slapd's Cyrus GSSAPI (MIT
/// libgssapi), with tickets from MIT's KDC.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs OpenLDAP slapd, Cyrus GSSAPI and MIT krb5kdc"]
async fn gssapi_bind_against_openldap() {
    if !Path::new("/usr/sbin/slapd").exists() || !Path::new("/usr/sbin/krb5kdc").exists() {
        eprintln!("slapd or krb5kdc not installed; skipping");
        return;
    }
    let dir = tempfile::tempdir().expect("tempdir");
    let d = dir.path();
    let base = 20000 + (std::process::id() % 20000) as u16;
    let (port, kport) = (base + 2, base + 3);
    let conf = d.join("krb5.conf");
    std::fs::write(
        &conf,
        format!(
            "[libdefaults]\n default_realm = SASL.TEST\n dns_lookup_kdc = false\n\
             dns_canonicalize_hostname = false\n rdns = false\n\
             ignore_acceptor_hostname = true\n\
             [realms]\n SASL.TEST = {{\n  kdc = 127.0.0.1:{kport}\n }}\n\
             [domain_realm]\n localhost = SASL.TEST\n"
        ),
    )
    .expect("krb5.conf");
    let kdcconf = d.join("kdc.conf");
    std::fs::write(
        &kdcconf,
        format!(
            "[realms]\n SASL.TEST = {{\n  database_name = {db}\n  key_stash_file = {d}/stash\n\
             kdc_ports = {kport}\n  kdc_tcp_ports = {kport}\n }}\n",
            db = d.join("principal").display(),
            d = d.display()
        ),
    )
    .expect("kdc.conf");
    let keytab = d.join("ldap.keytab");
    let ccache = d.join("cc");
    let mit = |prog: &str| {
        let mut c = Command::new(prog);
        c.env("KRB5_CONFIG", &conf)
            .env("KRB5_KDC_PROFILE", &kdcconf);
        c
    };
    run(mit("kdb5_util").args(["-r", "SASL.TEST", "create", "-s", "-P", "masterpw"]));
    for q in [
        "addprinc -pw clientpw kdcsasl".to_string(),
        "addprinc -randkey ldap/localhost".to_string(),
        format!("ktadd -k {} ldap/localhost", keytab.display()),
    ] {
        run(mit("kadmin.local").args(["-r", "SASL.TEST", "-q", &q]));
    }
    let _kdc = Child(mit("krb5kdc").arg("-n").spawn().expect("krb5kdc"));
    std::thread::sleep(std::time::Duration::from_millis(500));
    let mut kinit = mit("kinit");
    kinit
        .env("KRB5CCNAME", format!("FILE:{}", ccache.display()))
        .arg("kdcsasl")
        .stdin(std::process::Stdio::piped());
    let mut child = kinit.spawn().expect("kinit");
    {
        use std::io::Write;
        child
            .stdin
            .take()
            .expect("stdin")
            .write_all(b"clientpw\n")
            .expect("password");
    }
    assert!(child.wait().expect("kinit").success(), "kinit failed");
    let _slapd = start_slapd(d, port, &[("KRB5_KTNAME", &keytab), ("KRB5_CONFIG", &conf)]);

    std::env::set_var("KRB5_CONFIG", &conf);
    std::env::set_var("KRB5CCNAME", format!("FILE:{}", ccache.display()));
    let gss = Bind::Sasl {
        mech: "GSSAPI".into(),
        authcid: None,
        authzid: None,
        realm: None,
        password: None,
    };
    let mut ldap = connect(&format!("ldap://localhost:{port}/"), &gss)
        .await
        .unwrap_or_else(|e| panic!("GSSAPI: {e}"));
    let (exop, _) = ldap
        .extended(WhoAmI)
        .await
        .expect("whoami")
        .success()
        .expect("whoami");
    let who: WhoAmIResp = exop.parse();
    assert_eq!(who.authzid, "dn:cn=kdcsasl,dc=example,dc=com");
    for _ in 0..3 {
        let (rs, _) = ldap
            .search(
                "dc=example,dc=com",
                Scope::Subtree,
                "(cn=kdcsasl)",
                vec!["cn"],
            )
            .await
            .expect("search")
            .success()
            .expect("search through the GSSAPI layer");
        assert_eq!(rs.len(), 1);
    }
    ldap.unbind().await.ok();
}
