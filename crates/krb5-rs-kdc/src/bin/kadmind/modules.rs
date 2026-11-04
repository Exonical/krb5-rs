//! Password quality (`lib/kadm5/srv/pwqual.c`) and kadm5_hook
//! (`lib/kadm5/srv/kadm5_hook.c`) modules: MIT's built-in pwqual modules and
//! modules loaded from shared libraries named by
//! `[plugins] pwqual { module = name:path }` and
//! `[plugins] kadm5_hook { module = name:path }`.
//!
//! A shared-library module exports `pwqual_<name>_initvt` or
//! `kadm5_hook_<name>_initvt`, as in MIT, but with this crate's C ABI
//! (`include/krb5-rs/pwqual_plugin.h`, `include/krb5-rs/kadm5_hook_plugin.h`);
//! MIT's ABI passes a `krb5_context` and MIT's own principal structures,
//! which only MIT's library provides.

use std::ffi::{c_char, c_int, c_long, c_void, CStr, CString};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use krb5_rs::kdc::kdb::admin::AdminModules;
use krb5_rs::kdc::kdb::kadm5::code;
use krb5_rs::kdc::kdb::kadm5_auth::module_order;
use krb5_rs::kdc::kdb::kadm5_hook::{HookPrinc, Kadm5Hook, Kadm5Hooks, KeySaltTuple, Stage};
use krb5_rs::kdc::kdb::mit::unparse_name;
use krb5_rs::kdc::kdb::pwqual::{self, refusal, Logger, PwQual, PwQualModules};
use krb5_rs::kdc::store::StoreError;
use krb5_rs::profile::Profile;
use krb5_rs::types::PrincipalName;

/// Held across every call into a shared-library module, so no two module
/// callbacks run at once, as in MIT's single-threaded kadmind.
static CALLS: Mutex<()> = Mutex::new(());

fn calls() -> MutexGuard<'static, ()> {
    CALLS.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A static binary cannot load shared libraries (static musl has no
/// `dlopen`), so configured modules are an error rather than skipped.
const STATIC: bool = cfg!(target_feature = "crt-static");

/// MIT's default `plugin_base_dir` (`$(libdir)/krb5/plugins`).
const PLUGIN_BASE_DIR: &str = "/usr/local/lib/krb5/plugins";

const MSG_LEN: usize = 1024;

fn values(profiles: &[&Profile], iface: &str, key: &str) -> Vec<String> {
    profiles
        .iter()
        .flat_map(|p| p.get_values(&["plugins", iface, key]))
        .collect()
}

fn cstr(s: &str) -> CString {
    CString::new(s.replace('\0', "")).unwrap_or_default()
}

fn opt_cstr(s: Option<&str>) -> Option<CString> {
    s.map(cstr)
}

fn opt_ptr(s: &Option<CString>) -> *const c_char {
    s.as_ref().map_or(std::ptr::null(), |s| s.as_ptr())
}

fn status(rc: c_int) -> Result<(), u32> {
    if rc == 0 {
        Ok(())
    } else {
        Err(rc as u32)
    }
}

/// `krb5_rs_pwqual_vtable`.
#[repr(C)]
pub struct PwQualVtable {
    /// Mandatory module name.
    pub name: *const c_char,
    /// `open(dict_file, &data)`.
    pub open: Option<unsafe extern "C" fn(*const c_char, *mut *mut c_void) -> c_int>,
    /// `check(data, password, policy, princ, msg, msg_len)`.
    pub check: Option<
        unsafe extern "C" fn(
            *mut c_void,
            *const c_char,
            *const c_char,
            *const c_char,
            *mut c_char,
            usize,
        ) -> c_int,
    >,
    /// `close(data)`.
    pub close: Option<unsafe extern "C" fn(*mut c_void)>,
}

type PwQualInitVt = unsafe extern "C" fn(c_int, c_int, *mut PwQualVtable) -> c_int;

struct DynPwQual {
    name: String,
    vt: PwQualVtable,
    data: *mut c_void,
    _lib: libloading::Library,
}

// SAFETY: every use of `data` and the vtable functions holds `CALLS`.
unsafe impl Send for DynPwQual {}
// SAFETY: see `Send`.
unsafe impl Sync for DynPwQual {}

impl Drop for DynPwQual {
    fn drop(&mut self) {
        if let Some(close) = self.vt.close {
            let _calls = calls();
            // SAFETY: close is the module's own function, given its own data.
            unsafe { close(self.data) };
        }
    }
}

impl PwQual for DynPwQual {
    fn name(&self) -> &str {
        &self.name
    }

    fn check(
        &self,
        password: &str,
        policy: Option<&str>,
        princ: &PrincipalName,
        realm: &str,
    ) -> Result<(), StoreError> {
        let Some(check) = self.vt.check else {
            return Ok(());
        };
        let pw = cstr(password);
        let pol = opt_cstr(policy);
        let p = CString::new(unparse_name(princ, realm)).unwrap_or_default();
        let mut msg = [0u8; MSG_LEN];
        let rc = {
            let _calls = calls();
            // SAFETY: the strings are NUL-terminated and msg has MSG_LEN
            // writable bytes.
            unsafe {
                check(
                    self.data,
                    pw.as_ptr(),
                    opt_ptr(&pol),
                    p.as_ptr(),
                    msg.as_mut_ptr().cast(),
                    MSG_LEN,
                )
            }
        };
        let Err(c) = status(rc) else {
            return Ok(());
        };
        msg[MSG_LEN - 1] = 0;
        let text = CStr::from_bytes_until_nul(&msg)
            .map(|m| m.to_string_lossy().into_owned())
            .unwrap_or_default();
        Err(refusal(
            c,
            if text.is_empty() {
                code::message(c)
            } else {
                text
            },
        ))
    }
}

/// `krb5_rs_key_salt_tuple`.
#[repr(C)]
pub struct KsTuple {
    /// Encryption type.
    pub enctype: i32,
    /// Salt type.
    pub salttype: i32,
}

/// `krb5_rs_kadm5_hook_princ`.
#[repr(C)]
pub struct HookPrincC {
    /// Unparsed principal.
    pub principal: *const c_char,
    /// `attributes`.
    pub attributes: i32,
    /// `max_life`.
    pub max_life: i32,
    /// `max_renewable_life`.
    pub max_renewable_life: i32,
    /// `princ_expire_time`.
    pub princ_expire_time: i32,
    /// `pw_expiration`.
    pub pw_expiration: i32,
    /// `policy`, or null.
    pub policy: *const c_char,
}

type Data = *mut c_void;
type Str = *const c_char;

/// `krb5_rs_kadm5_hook_vtable`, minor version 2.
#[repr(C)]
#[allow(clippy::type_complexity)]
pub struct HookVtable {
    /// Mandatory module name.
    pub name: Str,
    /// `init(&data)`.
    pub init: Option<unsafe extern "C" fn(*mut Data) -> c_int>,
    /// `fini(data)`.
    pub fini: Option<unsafe extern "C" fn(Data)>,
    /// `chpass(data, stage, princ, keepold, n_ks, ks, newpass)`.
    pub chpass:
        Option<unsafe extern "C" fn(Data, c_int, Str, c_int, c_int, *const KsTuple, Str) -> c_int>,
    /// `create(data, stage, princ, mask, n_ks, ks, password)`.
    pub create: Option<
        unsafe extern "C" fn(
            Data,
            c_int,
            *const HookPrincC,
            c_long,
            c_int,
            *const KsTuple,
            Str,
        ) -> c_int,
    >,
    /// `modify(data, stage, princ, mask)`.
    pub modify: Option<unsafe extern "C" fn(Data, c_int, *const HookPrincC, c_long) -> c_int>,
    /// `remove(data, stage, princ)`.
    pub remove: Option<unsafe extern "C" fn(Data, c_int, Str) -> c_int>,
    /// `rename(data, stage, oprinc, nprinc)`.
    pub rename: Option<unsafe extern "C" fn(Data, c_int, Str, Str) -> c_int>,
    /// `alias(data, stage, alias, target)`.
    pub alias: Option<unsafe extern "C" fn(Data, c_int, Str, Str) -> c_int>,
}

type HookInitVt = unsafe extern "C" fn(c_int, c_int, *mut HookVtable) -> c_int;

struct DynHook {
    name: String,
    vt: HookVtable,
    data: Data,
    _lib: libloading::Library,
}

// SAFETY: every use of `data` and the vtable functions holds `CALLS`.
unsafe impl Send for DynHook {}
// SAFETY: see `Send`.
unsafe impl Sync for DynHook {}

impl Drop for DynHook {
    fn drop(&mut self) {
        if let Some(fini) = self.vt.fini {
            let _calls = calls();
            // SAFETY: fini is the module's own function, given its own data.
            unsafe { fini(self.data) };
        }
    }
}

fn ks_tuples(ks: &[KeySaltTuple]) -> Vec<KsTuple> {
    ks.iter()
        .map(|&(enctype, salttype)| KsTuple { enctype, salttype })
        .collect()
}

fn clamp(v: u32) -> i32 {
    v as i32
}

impl DynHook {
    fn call(&self, f: impl FnOnce() -> c_int) -> Result<(), u32> {
        let _calls = calls();
        status(f())
    }

    fn with_princ(
        &self,
        ent: &HookPrinc,
        f: impl FnOnce(*const HookPrincC) -> c_int,
    ) -> Result<(), u32> {
        let principal = cstr(&ent.principal);
        let policy = opt_cstr(ent.policy.as_deref());
        let c = HookPrincC {
            principal: principal.as_ptr(),
            attributes: clamp(ent.attributes),
            max_life: clamp(ent.max_life),
            max_renewable_life: clamp(ent.max_renewable_life),
            princ_expire_time: clamp(ent.princ_expire_time),
            pw_expiration: clamp(ent.pw_expiration),
            policy: opt_ptr(&policy),
        };
        self.call(|| f(&c))
    }
}

// SAFETY (all callbacks): the module's own functions, given its own data,
// NUL-terminated strings and arrays of the stated length, while `CALLS` is
// held.
impl Kadm5Hook for DynHook {
    fn name(&self) -> &str {
        &self.name
    }

    fn chpass(
        &self,
        stage: Stage,
        princ: &str,
        keepold: bool,
        ks: &[KeySaltTuple],
        password: Option<&str>,
    ) -> Result<(), u32> {
        let Some(f) = self.vt.chpass else {
            return Ok(());
        };
        let (p, pw, ks) = (cstr(princ), opt_cstr(password), ks_tuples(ks));
        self.call(|| unsafe {
            f(
                self.data,
                stage as c_int,
                p.as_ptr(),
                c_int::from(keepold),
                ks.len() as c_int,
                ks.as_ptr(),
                opt_ptr(&pw),
            )
        })
    }

    fn create(
        &self,
        stage: Stage,
        ent: &HookPrinc,
        ks: &[KeySaltTuple],
        password: Option<&str>,
    ) -> Result<(), u32> {
        let Some(f) = self.vt.create else {
            return Ok(());
        };
        let (pw, ks) = (opt_cstr(password), ks_tuples(ks));
        self.with_princ(ent, |e| unsafe {
            f(
                self.data,
                stage as c_int,
                e,
                c_long::from(ent.mask),
                ks.len() as c_int,
                ks.as_ptr(),
                opt_ptr(&pw),
            )
        })
    }

    fn modify(&self, stage: Stage, ent: &HookPrinc) -> Result<(), u32> {
        let Some(f) = self.vt.modify else {
            return Ok(());
        };
        self.with_princ(ent, |e| unsafe {
            f(self.data, stage as c_int, e, c_long::from(ent.mask))
        })
    }

    fn remove(&self, stage: Stage, princ: &str) -> Result<(), u32> {
        let Some(f) = self.vt.remove else {
            return Ok(());
        };
        let p = cstr(princ);
        self.call(|| unsafe { f(self.data, stage as c_int, p.as_ptr()) })
    }

    fn rename(&self, stage: Stage, from: &str, to: &str) -> Result<(), u32> {
        let Some(f) = self.vt.rename else {
            return Ok(());
        };
        let (a, b) = (cstr(from), cstr(to));
        self.call(|| unsafe { f(self.data, stage as c_int, a.as_ptr(), b.as_ptr()) })
    }

    fn alias(&self, stage: Stage, alias: &str, target: &str) -> Result<(), u32> {
        let Some(f) = self.vt.alias else {
            return Ok(());
        };
        let (a, b) = (cstr(alias), cstr(target));
        self.call(|| unsafe { f(self.data, stage as c_int, a.as_ptr(), b.as_ptr()) })
    }
}

/// Open `path` and find `symbol`, or `None` (logged) when MIT would skip
/// the module.
fn open_lib<F: Copy>(
    log: &Logger,
    iface: &str,
    name: &str,
    path: &Path,
) -> Option<(libloading::Library, F)> {
    // SAFETY: loading a configured module runs its initializers, which the
    // administrator chose to trust, as with MIT's plugins.
    let lib = match unsafe { libloading::Library::new(path) } {
        Ok(l) => l,
        Err(e) => {
            log(&format!("{iface} module {name}: {e}"));
            return None;
        }
    };
    let sym = format!("{iface}_{name}_initvt");
    // SAFETY: the symbol has the interface's documented initvt type.
    let f = match unsafe { lib.get::<F>(sym.as_bytes()) } {
        Ok(f) => *f,
        Err(e) => {
            log(&format!("{iface} module {name}: {e}"));
            return None;
        }
    };
    Some((lib, f))
}

/// Configured `(name, path)` modules of `iface`.
fn specs(profiles: &[&Profile], iface: &str) -> Result<Vec<(String, PathBuf)>, String> {
    let base = profiles
        .iter()
        .find_map(|p| p.get_string(&["libdefaults", "plugin_base_dir"]))
        .unwrap_or_else(|| PLUGIN_BASE_DIR.into());
    let specs = values(profiles, iface, "module");
    if STATIC && !specs.is_empty() {
        return Err(format!(
            "{iface} modules need a dynamically linked program; this one is static"
        ));
    }
    specs
        .iter()
        .map(|m| {
            m.split_once(':')
                .map(|(n, p)| (n.to_string(), Path::new(&base).join(p)))
                .ok_or_else(|| format!("Invalid module specifier {m}"))
        })
        .collect()
}

fn order(
    profiles: &[&Profile],
    iface: &str,
    paths: &[(String, PathBuf)],
    builtin: &[&str],
) -> Vec<String> {
    let names: Vec<String> = paths.iter().map(|(n, _)| n.clone()).collect();
    module_order(
        &names,
        builtin,
        &values(profiles, iface, "enable_only"),
        &values(profiles, iface, "disable"),
    )
}

fn load_pwqual(
    name: &str,
    path: &Path,
    dict_file: Option<&Path>,
    log: &Logger,
) -> Result<Option<DynPwQual>, String> {
    let _calls = calls();
    let Some((lib, initvt)) = open_lib::<PwQualInitVt>(log, "pwqual", name, path) else {
        return Ok(None);
    };
    let mut vt = PwQualVtable {
        name: std::ptr::null(),
        open: None,
        check: None,
        close: None,
    };
    // SAFETY: vt is a valid, writable vtable.
    if unsafe { initvt(1, 0, &mut vt) } != 0 {
        return Ok(None);
    }
    let mut data = std::ptr::null_mut();
    if let Some(open) = vt.open {
        let dict = dict_file.map(|d| cstr(&d.to_string_lossy()));
        // SAFETY: dict is NUL-terminated or null and data is writable.
        let rc = unsafe { open(opt_ptr(&dict), &mut data) };
        if rc != 0 {
            // pwqual.c:110-114: a module that fails to open is fatal.
            return Err(format!(
                "{} while opening password quality module {name}",
                code::message(rc as u32)
            ));
        }
    }
    Ok(Some(DynPwQual {
        name: name.to_string(),
        vt,
        data,
        _lib: lib,
    }))
}

fn load_hook(name: &str, path: &Path, log: &Logger) -> Result<Option<DynHook>, String> {
    let _calls = calls();
    let Some((lib, initvt)) = open_lib::<HookInitVt>(log, "kadm5_hook", name, path) else {
        return Ok(None);
    };
    let mut vt = HookVtable {
        name: std::ptr::null(),
        init: None,
        fini: None,
        chpass: None,
        create: None,
        modify: None,
        remove: None,
        rename: None,
        alias: None,
    };
    // SAFETY: vt is a valid, writable vtable.
    if unsafe { initvt(1, 2, &mut vt) } != 0 {
        return Ok(None);
    }
    let mut data = std::ptr::null_mut();
    if let Some(init) = vt.init {
        // SAFETY: data is writable.
        let rc = unsafe { init(&mut data) };
        if rc != 0 {
            // kadm5_hook.c:94-100: a module that fails to initialize is fatal.
            return Err(format!(
                "{} while initializing kadm5_hook module {name}",
                code::message(rc as u32)
            ));
        }
    }
    Ok(Some(DynHook {
        name: name.to_string(),
        vt,
        data,
        _lib: lib,
    }))
}

/// A [`Logger`] writing `prog: message` to standard error.
pub fn logger(prog: &'static str) -> Logger {
    Arc::new(move |m| eprintln!("{prog}: {m}"))
}

/// `k5_pwqual_load` and `k5_kadm5_hook_load` (`server_init.c:356-372`):
/// the enabled modules in MIT's order, opened with the realm's `dict_file`.
pub fn load(
    profiles: &[&Profile],
    dict_file: Option<&Path>,
    log: Logger,
) -> Result<AdminModules, String> {
    let paths = specs(profiles, "pwqual")?;
    let mut pwq: Vec<Box<dyn PwQual>> = Vec::new();
    for name in order(profiles, "pwqual", &paths, &pwqual::BUILTIN) {
        if let Some((_, path)) = paths.iter().find(|(n, _)| *n == name) {
            if let Some(m) = load_pwqual(&name, path, dict_file, &log)? {
                pwq.push(Box::new(m));
            }
        } else if let Some(m) =
            pwqual::builtin(&name, dict_file, &|m| log(m)).map_err(|e| e.to_string())?
        {
            pwq.push(m);
        }
    }
    let paths = specs(profiles, "kadm5_hook")?;
    let mut hooks: Vec<Box<dyn Kadm5Hook>> = Vec::new();
    for name in order(profiles, "kadm5_hook", &paths, &[]) {
        if let Some((_, path)) = paths.iter().find(|(n, _)| *n == name) {
            if let Some(m) = load_hook(&name, path, &log)? {
                hooks.push(Box::new(m));
            }
        }
    }
    Ok(AdminModules {
        pwqual: Arc::new(PwQualModules::new(pwq, log.clone())),
        hooks: Arc::new(Kadm5Hooks::new(hooks, log)),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use krb5_rs::types::KerberosString;

    /// Build a fixture module from `tests/fixtures/<src>.c`.
    fn module(dir: &Path, src: &str) -> PathBuf {
        let so = dir.join(format!("{src}.so"));
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let out = std::process::Command::new(std::env::var("CC").unwrap_or_else(|_| "cc".into()))
            .args(["-shared", "-fPIC", "-I"])
            .arg(root.join("include"))
            .arg("-o")
            .arg(&so)
            .arg(root.join(format!("tests/fixtures/{src}.c")))
            .output()
            .expect("run cc");
        assert!(out.status.success(), "{out:?}");
        so
    }

    fn princ(parts: &[&str]) -> PrincipalName {
        PrincipalName {
            name_type: 1,
            name_string: parts
                .iter()
                .map(|p| KerberosString::from_bytes(p.as_bytes()).unwrap())
                .collect(),
        }
    }

    fn quiet() -> Logger {
        Arc::new(|_| {})
    }

    fn pwqual_conf(body: &str) -> Profile {
        Profile::parse(&format!("[plugins]\n pwqual = {{\n{body}\n }}\n")).unwrap()
    }

    fn names(conf: &Profile) -> Vec<String> {
        let m = load(&[conf], None, quiet()).unwrap();
        m.pwqual.names().iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn pwqual_module_order_is_mits() {
        let tmp = tempfile::tempdir().unwrap();
        let so = module(tmp.path(), "pwqual_test");
        let so = so.display();
        // t_pwqual.py's order cases, with MIT's built-ins.
        assert_eq!(
            names(&Profile::parse("").unwrap()),
            ["dict", "empty", "hesiod", "princ"]
        );
        let basic = format!("module = dyn3:{so}\nmodule = dyn1:{so}\nmodule = dyn2:{so}");
        assert_eq!(
            names(&pwqual_conf(&basic)),
            ["dyn3", "dyn1", "dyn2", "dict", "empty", "hesiod", "princ"]
        );
        let disable = format!("{basic}\ndisable = dyn1\ndisable = princ");
        assert_eq!(
            names(&pwqual_conf(&disable)),
            ["dyn3", "dyn2", "dict", "empty", "hesiod"]
        );
        let only = format!(
            "{disable}\nenable_only = dyn2\nenable_only = princ\nenable_only = empty\n\
             enable_only = dyn1\nenable_only = dyn3\nenable_only = xxx"
        );
        assert_eq!(names(&pwqual_conf(&only)), ["dyn2", "empty", "dyn3"]);
        let dup = format!("module = dyn3:{so}\nmodule = dyn1:{so}\nmodule = dyn3:{so}");
        assert_eq!(
            names(&pwqual_conf(&dup)),
            ["dyn3", "dyn1", "dict", "empty", "hesiod", "princ"]
        );
        // A module whose vtable fails is skipped; one that fails to open
        // stops the program.
        let novt = format!("module = novt:{so}\nenable_only = novt");
        assert!(names(&pwqual_conf(&novt)).is_empty());
        let bad = pwqual_conf(&format!("module = badopen:{so}"));
        assert!(load(&[&bad], None, quiet()).is_err());
        // A missing library is skipped.
        assert!(names(&pwqual_conf(
            "module = gone:/nonexistent.so\nenable_only = gone"
        ))
        .is_empty());
    }

    #[test]
    fn pwqual_modules_refuse_like_t_pwqual() {
        let tmp = tempfile::tempdir().unwrap();
        let so = module(tmp.path(), "pwqual_test");
        let dict = tmp.path().join("dict");
        std::fs::write(&dict, "birds\nbees\napples\noranges\n").unwrap();
        let conf = pwqual_conf(&format!("module = combo:{}", so.display()));
        let m = load(&[&conf], Some(&dict), quiet()).unwrap();
        let q = &m.pwqual;
        let msg = |pw: &str, pol: Option<&str>, p: &str| {
            q.check(pw, pol, &princ(&[p]), "KRBTEST.COM")
                .err()
                .map(|e| (e.code(), e.message().to_string()))
        };
        assert_eq!(
            msg("", None, "p1"),
            Some((
                Some(code::PASS_Q_TOOSHORT),
                "Empty passwords are not allowed".into()
            ))
        );
        assert_eq!(msg("birds", None, "p2"), None);
        assert_eq!(
            msg("birds", Some("pol"), "p3"),
            Some((
                Some(code::PASS_Q_DICT),
                "Password is in the password dictionary".into()
            ))
        );
        assert_eq!(msg("p4", None, "p4"), None);
        assert_eq!(
            msg("p5", Some("pol"), "p5"),
            Some((
                Some(code::PASS_Q_DICT),
                "Password may not match principal name".into()
            ))
        );
        assert_eq!(
            msg("birdsoranges", None, "p6"),
            Some((
                Some(code::PASS_Q_DICT),
                "Password may not be a pair of dictionary words".into()
            ))
        );
    }

    fn hook_conf(so: &Path, names: &[&str]) -> Profile {
        let mods: String = names
            .iter()
            .map(|n| format!("module = {n}:{}\n", so.display()))
            .collect();
        Profile::parse(&format!("[plugins]\n kadm5_hook = {{\n{mods} }}\n")).unwrap()
    }

    #[test]
    fn hooks_load_refuse_precommit_and_log_postcommit() {
        let tmp = tempfile::tempdir().unwrap();
        let so = module(tmp.path(), "kadm5_hook_test");
        let logged = Arc::new(Mutex::new(Vec::new()));
        let l = logged.clone();
        let log: Logger = Arc::new(move |m| l.lock().unwrap().push(m.to_string()));
        let m = load(&[&hook_conf(&so, &["refuse", "test"])], None, log).unwrap();
        assert_eq!(m.hooks.names(), ["refuse", "test"]);
        let ent = |p: &str| HookPrinc {
            principal: p.into(),
            ..HookPrinc::default()
        };
        let e = m
            .hooks
            .create(Stage::Precommit, &ent("blocked@R"), &[(18, 0)], None)
            .unwrap_err();
        assert_eq!(e.code(), Some(code::FAILURE));
        m.hooks
            .create(Stage::Postcommit, &ent("ok@R"), &[(18, 0)], Some("pw"))
            .unwrap();
        assert_eq!(
            logged.lock().unwrap().last().map(String::as_str),
            Some("kadm5_hook refuse failed postcommit create: Operation failed for unspecified reason")
        );
        m.hooks.rename(Stage::Precommit, "a@R", "b@R").unwrap();
        m.hooks.alias(Stage::Postcommit, "c@R", "a@R").unwrap();
        assert!(load(&[&hook_conf(&so, &["badinit"])], None, quiet()).is_err());
    }
}
