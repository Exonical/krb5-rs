//! hostrealm modules over RPC like MIT, ported from MIT tests/t_hostrealm.py
//! and plugins/hostrealm/test/main.c.
#![cfg(unix)]

use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::sync::Arc;

use krb5_rs::locate::{
    get_default_realm, get_fallback_host_realm, get_host_realm, serve_hostrealm, HostRealm,
};
use krb5_rs::profile::Profile;

const PLUGIN_NO_HANDLE: i32 = -1_765_328_135;
/// `KRB5_ERR_NO_SERVICE` ("service not available").
const NO_SERVICE: i32 = -1_765_328_384 + 245;

fn split(host: &str) -> Result<Vec<String>, i32> {
    if host.is_empty() {
        return Err(PLUGIN_NO_HANDLE);
    }
    Ok(host.split('.').map(str::to_string).collect())
}

struct Test1;
impl HostRealm for Test1 {
    fn name(&self) -> &str {
        "test1"
    }
    fn host_realm(&self, host: &str) -> Result<Vec<String>, i32> {
        split(host)
    }
    fn fallback_realm(&self, host: &str) -> Result<Vec<String>, i32> {
        split(host)
    }
    fn default_realm(&self) -> Result<Vec<String>, i32> {
        Ok(vec!["one".into(), "two".into()])
    }
}

struct Test2;
impl HostRealm for Test2 {
    fn name(&self) -> &str {
        "test2"
    }
    fn host_realm(&self, host: &str) -> Result<Vec<String>, i32> {
        match host.as_bytes().first() {
            Some(b'z') => Err(NO_SERVICE),
            Some(b'a') => Ok(vec!["a".into()]),
            _ => Err(PLUGIN_NO_HANDLE),
        }
    }
    fn default_realm(&self) -> Result<Vec<String>, i32> {
        Err(NO_SERVICE)
    }
}

fn listen(dir: &std::path::Path, name: &str, m: Arc<dyn HostRealm>) -> PathBuf {
    let path = dir.join(format!("{name}.sock"));
    let l = UnixListener::bind(&path).unwrap();
    std::thread::spawn(move || {
        for s in l.incoming().flatten() {
            let m = m.clone();
            std::thread::spawn(move || {
                let _ = serve_hostrealm(s, &*m);
            });
        }
    });
    path
}

fn setup() -> (PathBuf, PathBuf, PathBuf) {
    let dir = std::env::temp_dir().join(format!("krb5rs-hostrealm-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let t1 = listen(&dir, "test1", Arc::new(Test1));
    let t2 = listen(&dir, "test2", Arc::new(Test2));
    (dir, t1, t2)
}

fn conf(t1: &std::path::Path, t2: &std::path::Path, libdefaults: &str, extra: &str) -> Profile {
    Profile::parse(&format!(
        "[libdefaults]\n{libdefaults}\n\
         [plugins]\n hostrealm = {{\n  module = test1:unix:path={}\n  module = test2:unix:path={}\n\
         {extra}\n }}\n\
         [domain_realm]\n .x = DOTMATCH\n x = MATCH\n .1 = NUMMATCH\n",
        t1.display(),
        t2.display()
    ))
    .unwrap()
}

fn v(s: &[&str]) -> Vec<String> {
    s.iter().map(|x| (*x).to_string()).collect()
}

#[test]
fn t_hostrealm() {
    let (dir, t1, t2) = setup();
    let order = "  enable_only = test2\n  enable_only = profile\n  enable_only = domain\n  enable_only = test1";
    let realm = conf(&t1, &t2, " default_realm = KRBTEST.COM", order);
    let h = |p: &Profile, host: &str| get_host_realm(p, host);
    let f = |p: &Profile, host: &str| get_fallback_host_realm(p, host);

    // test2 module
    assert_eq!(h(&realm, "zoo"), Err(NO_SERVICE));
    assert_eq!(h(&realm, "abacus"), Ok(v(&["a"])));
    // profile module
    assert_eq!(h(&realm, "x"), Ok(v(&["MATCH"])));
    assert_eq!(h(&realm, ".x"), Ok(v(&["DOTMATCH"])));
    assert_eq!(h(&realm, "b.x"), Ok(v(&["DOTMATCH"])));
    assert_eq!(h(&realm, ".b.c.x"), Ok(v(&["DOTMATCH"])));
    assert_eq!(h(&realm, "b.1"), Ok(v(&["NUMMATCH"])));
    assert_eq!(h(&realm, "4.3.2.1"), Ok(v(&["4", "3", "2", "1"])));
    assert_eq!(h(&realm, "b:c.x"), Ok(v(&["b:c", "x"])));
    assert_eq!(h(&realm, "X."), Ok(v(&["MATCH"])));
    // test1 module
    assert_eq!(h(&realm, "b.c.d"), Ok(v(&["b", "c", "d"])));
    // no result
    assert_eq!(h(&realm, ""), Ok(v(&[""])));

    // fallback: domain module
    assert_eq!(f(&realm, "a.b.c"), Ok(v(&["B.C"])));
    let try_n = |n: i32| {
        conf(
            &t1,
            &t2,
            &format!(
                " default_realm = KRBTEST.COM\n realm_try_domains = {n}\n\
                 [realms]\n KRBTEST.COM = {{\n  kdc = localhost\n }}\n\
                 B.KRBTEST.COM = {{\n  kdc = localhost\n }}\n"
            ),
            order,
        )
    };
    let try0 = try_n(0);
    assert_eq!(f(&try0, "krbtest.com"), Ok(v(&["KRBTEST.COM"])));
    assert_eq!(f(&try0, "a.b.krbtest.com"), Ok(v(&["B.KRBTEST.COM"])));
    assert_eq!(f(&try0, "a.b.c"), Ok(v(&["B.C"])));
    let try2 = try_n(2);
    assert_eq!(f(&try2, "krbtest.com"), Ok(v(&["KRBTEST.COM"])));
    assert_eq!(f(&try2, "a.b.krbtest.com"), Ok(v(&["B.KRBTEST.COM"])));
    assert_eq!(f(&try2, "a.b.c.krbtest.com"), Ok(v(&["B.C.KRBTEST.COM"])));
    // fallback: test1 module
    assert_eq!(f(&realm, "1.2.3.4"), Ok(v(&["1", "2", "3", "4"])));
    // fallback: default realm, which test2 refuses
    assert_eq!(f(&realm, ""), Err(NO_SERVICE));

    // default_realm
    assert_eq!(get_default_realm(&realm), Err(NO_SERVICE));
    let notest2 = conf(
        &t1,
        &t2,
        " default_realm = KRBTEST.COM",
        &format!("{order}\n  disable = test2"),
    );
    assert_eq!(get_default_realm(&notest2).as_deref(), Ok("KRBTEST.COM"));
    let nodefault = conf(&t1, &t2, "", &format!("{order}\n  disable = test2"));
    assert_eq!(get_default_realm(&nodefault).as_deref(), Ok("one"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn unreachable_module_is_skipped() {
    let p = Profile::parse(
        "[libdefaults]\n default_realm = R\n\
         [plugins]\n hostrealm = {\n  module = gone:unix:path=/nonexistent/krb5rs.sock\n }\n",
    )
    .unwrap();
    assert_eq!(get_default_realm(&p).as_deref(), Ok("R"));
    let bad = Profile::parse("[plugins]\n hostrealm = {\n  module = nocolon\n }\n").unwrap();
    assert!(get_host_realm(&bad, "x").is_err());
}

#[derive(Default)]
struct Counting {
    init: std::sync::atomic::AtomicUsize,
    fini: std::sync::atomic::AtomicUsize,
}
impl HostRealm for Counting {
    fn name(&self) -> &str {
        "counting"
    }
    fn init(&self) -> Result<(), i32> {
        self.init.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        std::thread::sleep(std::time::Duration::from_millis(50));
        Ok(())
    }
    fn fini(&self) {
        self.fini.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }
    fn default_realm(&self) -> Result<Vec<String>, i32> {
        Ok(vec!["COUNTED".into()])
    }
}

#[test]
fn concurrent_lookups_initialize_once_and_finalize_remote_finalizes() {
    use std::sync::atomic::Ordering::SeqCst;
    let dir = std::env::temp_dir().join(format!("krb5rs-hostrealm-c-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let m = Arc::new(Counting::default());
    let path = listen(&dir, "counting", m.clone());
    let p = Arc::new(
        Profile::parse(&format!(
            "[plugins]\n hostrealm = {{\n  module = counting:unix:path={}\n }}\n",
            path.display()
        ))
        .unwrap(),
    );
    let threads: Vec<_> = (0..8)
        .map(|_| {
            let p = p.clone();
            std::thread::spawn(move || get_default_realm(&p))
        })
        .collect();
    for t in threads {
        assert_eq!(t.join().unwrap().as_deref(), Ok("COUNTED"));
    }
    assert_eq!(m.init.load(SeqCst), 1);
    assert_eq!(m.fini.load(SeqCst), 0);
    krb5_rs::plugin::finalize_remote();
    for _ in 0..100 {
        if m.fini.load(SeqCst) == 1 {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    assert_eq!(m.fini.load(SeqCst), 1);
    let _ = std::fs::remove_dir_all(&dir);
}
