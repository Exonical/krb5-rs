//! localauth modules over RPC like MIT, ported from MIT
//! tests/t_localauth.py's test-module cases and plugins/localauth/test/main.c.
#![cfg(unix)]

use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::sync::Arc;

use krb5_rs::localauth::{
    aname_to_localname, kuserok, serve_localauth, LocalauthError, LocalauthModule, LNAME_NOTRANS,
};
use krb5_rs::profile::Profile;
use krb5_rs::types::PrincipalName;
use rasn::types::GeneralString;

const PLUGIN_NO_HANDLE: i32 = -1_765_328_135;
/// `KRB5_ERR_NO_SERVICE`.
const NO_SERVICE: i32 = -1_765_328_384 + 245;

/// main.c `test1`: types `TYPEA` and `TYPEB`; maps `TYPEA` to the residual
/// and `TYPEB` to the principal's first component; allows `user@...`
/// to log in as `alias` and denies `ruser`.
struct Test1;
impl LocalauthModule for Test1 {
    fn name(&self) -> &str {
        "test1"
    }
    fn an2ln_types(&self) -> Vec<String> {
        vec!["TYPEA".into(), "TYPEB".into()]
    }
    fn userok(&self, aname: &str, lname: &str) -> Result<(), i32> {
        match (aname.split('@').next(), lname) {
            (Some("user"), "alias") => Ok(()),
            (_, "ruser") => Err(NO_SERVICE),
            _ => Err(PLUGIN_NO_HANDLE),
        }
    }
    fn an2ln(&self, ty: Option<&str>, residual: Option<&str>, aname: &str) -> Result<String, i32> {
        match ty {
            Some("TYPEA") => Ok(residual.unwrap_or("").to_string()),
            Some("TYPEB") => Ok(aname.split(['/', '@']).next().unwrap().to_string()),
            _ => Err(LNAME_NOTRANS),
        }
    }
}

/// main.c `test2`: type `TYPEA` (conflicts with test1's) and untyped
/// mapping of `rule/...` principals to `rulemapped`; errors on `error`.
struct Test2;
impl LocalauthModule for Test2 {
    fn name(&self) -> &str {
        "test2"
    }
    fn an2ln(&self, _: Option<&str>, _: Option<&str>, aname: &str) -> Result<String, i32> {
        match aname.split(['/', '@']).next() {
            Some("rule") => Ok("rulemapped".into()),
            Some("error") => Err(NO_SERVICE),
            _ => Err(LNAME_NOTRANS),
        }
    }
}

/// A typed module conflicting with test1's `TYPEA`: skipped when after it.
struct Conflict;
impl LocalauthModule for Conflict {
    fn name(&self) -> &str {
        "conflict"
    }
    fn an2ln_types(&self) -> Vec<String> {
        vec!["TYPEA".into()]
    }
    fn an2ln(&self, _: Option<&str>, _: Option<&str>, _: &str) -> Result<String, i32> {
        Ok("conflict".into())
    }
}

fn listen(dir: &std::path::Path, name: &str, m: Arc<dyn LocalauthModule>) -> PathBuf {
    let path = dir.join(format!("{name}.sock"));
    let l = UnixListener::bind(&path).unwrap();
    std::thread::spawn(move || {
        for s in l.incoming().flatten() {
            let m = m.clone();
            std::thread::spawn(move || serve_localauth(s, &*m));
        }
    });
    path
}

fn princ(s: &str) -> (PrincipalName, String) {
    let (name, realm) = s.rsplit_once('@').unwrap();
    let name = PrincipalName {
        name_type: 1,
        name_string: name
            .split('/')
            .map(|c| GeneralString::from_bytes(c.as_bytes()).unwrap())
            .collect(),
    };
    (name, realm.to_string())
}

#[test]
fn t_localauth_modules() {
    let dir = std::env::temp_dir().join(format!("krb5rs-localauth-m-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let t1 = listen(&dir, "test1", Arc::new(Test1));
    let t2 = listen(&dir, "test2", Arc::new(Test2));
    let c = listen(&dir, "conflict", Arc::new(Conflict));
    let conf = |extra: &str| {
        Profile::parse(&format!(
            "[libdefaults]\n default_realm = KRBTEST.COM\n\
             [realms]\n KRBTEST.COM = {{\n  auth_to_local = TYPEA:a\n  auth_to_local = TYPEB\n  auth_to_local = DEFAULT\n }}\n\
             [plugins]\n localauth = {{\n  module = test1:unix:path={}\n  module = test2:unix:path={}\n  module = conflict:unix:path={}\n  disable = k5login\n{extra} }}\n",
            t1.display(),
            t2.display(),
            c.display()
        ))
        .unwrap()
    };
    let p = conf("");
    let an2ln = |p: &Profile, s: &str| {
        let (n, r) = princ(s);
        aname_to_localname(p, &n, &r)
    };
    let userok = |p: &Profile, s: &str, l: &str| {
        let (n, r) = princ(s);
        kuserok(p, &n, &r, l)
    };
    // test2's untyped mapping comes before the built-ins.
    assert_eq!(an2ln(&p, "rule/x@OTHER.COM").as_deref(), Ok("rulemapped"));
    assert_eq!(
        an2ln(&p, "error@KRBTEST.COM"),
        Err(LocalauthError::Code(NO_SERVICE))
    );
    // auth_to_local reaches test1's typed mapping; the conflict module
    // claiming TYPEA after test1 is skipped.
    assert_eq!(an2ln(&p, "user@KRBTEST.COM").as_deref(), Ok("a"));
    // userok: test1 allows user as alias and denies ruser.
    assert!(userok(&p, "user@KRBTEST.COM", "alias"));
    assert!(!userok(&p, "ruser@KRBTEST.COM", "ruser"));
    assert!(userok(&p, "a@KRBTEST.COM", "a"));
    // enable_only reorders: conflict before test1 now owns TYPEA.
    let p = conf("  enable_only = conflict\n  enable_only = test1\n  enable_only = auth_to_local\n  enable_only = an2ln\n");
    assert_eq!(an2ln(&p, "user@KRBTEST.COM").as_deref(), Ok("conflict"));
    // Unreachable modules are skipped.
    let p = Profile::parse(
        "[libdefaults]\n default_realm = KRBTEST.COM\n\
         [plugins]\n localauth = {\n  module = gone:unix:path=/nonexistent/gone.sock\n }\n",
    )
    .unwrap();
    assert_eq!(an2ln(&p, "user@KRBTEST.COM").as_deref(), Ok("user"));
    // A malformed module spec fails like MIT's load_localauth_modules.
    let p = Profile::parse("[plugins]\n localauth = {\n  module = bad\n }\n").unwrap();
    assert!(matches!(
        an2ln(&p, "user@KRBTEST.COM"),
        Err(LocalauthError::Code(_))
    ));
    assert!(!userok(&p, "user@KRBTEST.COM", "user"));
    let _ = std::fs::remove_dir_all(&dir);
}
