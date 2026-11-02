//! kadmind's kadm5_auth modules (`kadmin/server/auth.c`): the built-in `acl`
//! (`auth_acl.c`) and `self` (`auth_self.c`) modules, and modules loaded from
//! shared libraries named by `[plugins] kadm5_auth { module = name:path }`.
//!
//! A shared-library module exports `kadm5_auth_<name>_initvt`, as in MIT, but
//! with this crate's C ABI ([`Vtable`]); MIT's ABI passes a `krb5_context`
//! and MIT's own principal and entry structures, which only MIT's library
//! provides.

use std::ffi::{c_char, c_int, c_long, c_void, CStr, CString};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use krb5_rs::kdc::kdb::kadm5_auth::{
    module_order, Kadm5Auth, Kadm5AuthModules, Princ, Request, SelfModule, Verdict,
    PLUGIN_NO_HANDLE,
};
use krb5_rs::kdc::kdb::restrictions::AclRestrictions;
use krb5_rs::profile::Profile;

use super::{
    acl_check, acl_permits_iprop, load_acl, unparse, AclEntry, ACL_ADD, ACL_CHANGEPW, ACL_DELETE,
    ACL_EXTRACT, ACL_INQUIRE, ACL_LIST, ACL_MODIFY, ACL_SETKEY,
};

/// The `acl` module (`auth_acl.c:560-735`).
pub struct AclModule(pub Arc<Vec<AclEntry>>);

impl Kadm5Auth for AclModule {
    fn name(&self) -> &str {
        "acl"
    }

    fn authorize(&self, c: Princ<'_>, req: &Request<'_>) -> (Verdict, Option<AclRestrictions>) {
        let chk = |op: u32, t: Option<Princ<'_>>| {
            acl_check(&self.0, op, (c.name, c.realm), t.map(|t| (t.name, t.realm)))
        };
        let pass = |ok: bool| if ok { Verdict::Pass } else { Verdict::NoHandle };
        let simple = |op: u32, t: Option<Princ<'_>>| (pass(chk(op, t).is_some()), None);
        match *req {
            Request::AddPrinc { target, .. } | Request::ModPrinc { target, .. } => {
                let op = if matches!(req, Request::AddPrinc { .. }) {
                    ACL_ADD
                } else {
                    ACL_MODIFY
                };
                match chk(op, Some(target)) {
                    Some(rs) => (Verdict::Pass, rs.cloned()),
                    None => (Verdict::NoHandle, None),
                }
            }
            Request::SetStr { target, .. } | Request::PurgeKeys { target } => {
                simple(ACL_MODIFY, Some(target))
            }
            Request::Cpw { target } | Request::Chrand { target } => {
                simple(ACL_CHANGEPW, Some(target))
            }
            Request::SetKey { target } => simple(ACL_SETKEY, Some(target)),
            Request::DelPrinc { target } => simple(ACL_DELETE, Some(target)),
            Request::RenPrinc { src, dest } => (
                pass(
                    chk(ACL_DELETE, Some(src)).is_some() && chk(ACL_ADD, Some(dest)) == Some(None),
                ),
                None,
            ),
            Request::GetPrinc { target } | Request::GetStrs { target } => {
                simple(ACL_INQUIRE, Some(target))
            }
            Request::Extract { target } => simple(ACL_EXTRACT, Some(target)),
            Request::ListPrincs | Request::ListPols => simple(ACL_LIST, None),
            Request::AddPol { .. } => simple(ACL_ADD, None),
            Request::ModPol { .. } => simple(ACL_MODIFY, None),
            Request::DelPol { .. } => simple(ACL_DELETE, None),
            Request::GetPol { .. } => simple(ACL_INQUIRE, None),
            Request::Iprop => (pass(acl_permits_iprop(&self.0, c.name, c.realm)), None),
            Request::AddAlias { alias, target } => (
                pass(
                    chk(ACL_ADD, Some(alias)) == Some(None)
                        && chk(ACL_MODIFY, Some(target)).is_some(),
                ),
                None,
            ),
        }
    }
}

/// The fields of an `addprinc`/`modprinc` entry a module sees.
#[repr(C)]
pub struct PrincEnt {
    /// `KADM5_*` mask of the request.
    pub mask: c_long,
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

/// The fields of an `addpol`/`modpol` entry a module sees.
#[repr(C)]
pub struct PolEnt {
    /// `KADM5_*` policy mask of the request.
    pub mask: c_long,
    /// `pw_min_life`.
    pub pw_min_life: i32,
    /// `pw_max_life`.
    pub pw_max_life: i32,
    /// `pw_min_length`.
    pub pw_min_length: i32,
    /// `pw_min_classes`.
    pub pw_min_classes: i32,
    /// `pw_history_num`.
    pub pw_history_num: i32,
}

/// `struct kadm5_auth_restrictions`.
#[repr(C)]
pub struct Restrictions {
    /// Which fields apply.
    pub mask: c_long,
    /// Attributes forced on.
    pub require_attrs: i32,
    /// Attributes kept; others are forced off.
    pub forbid_attrs: i32,
    /// `princ_lifetime`.
    pub princ_lifetime: i32,
    /// `pw_lifetime`.
    pub pw_lifetime: i32,
    /// `max_life`.
    pub max_life: i32,
    /// `max_renewable_life`.
    pub max_renewable_life: i32,
    /// `policy`, or null.
    pub policy: *const c_char,
}

/// A module's vtable, filled in by `kadm5_auth_<name>_initvt(1, 0, vt)`.
///
/// `authorize` gets MIT's `OP_*` number, the client, then the arguments of
/// MIT's `call_module` (`auth.c:133-178`): `p1`/`p2` principals (unparsed),
/// `s1`/`s2` strings, and the entry of `addprinc`/`modprinc` or
/// `addpol`/`modpol`; any may be null. It returns 0 to authorize,
/// `KRB5_PLUGIN_NO_HANDLE` for no opinion, or another value to refuse.
#[repr(C)]
pub struct Vtable {
    /// Mandatory module name.
    pub name: *const c_char,
    /// `init(acl_file, &data)`.
    pub init: Option<unsafe extern "C" fn(*const c_char, *mut *mut c_void) -> c_int>,
    /// `fini(data)`.
    pub fini: Option<unsafe extern "C" fn(*mut c_void)>,
    /// `authorize(data, opcode, client, p1, p2, s1, s2, princ, pol, &rs)`.
    #[allow(clippy::type_complexity)]
    pub authorize: Option<
        unsafe extern "C" fn(
            *mut c_void,
            c_int,
            *const c_char,
            *const c_char,
            *const c_char,
            *const c_char,
            *const c_char,
            *const PrincEnt,
            *const PolEnt,
            *mut *mut Restrictions,
        ) -> c_int,
    >,
    /// `end(data)`.
    pub end: Option<unsafe extern "C" fn(*mut c_void)>,
    /// `free_restrictions(data, rs)`.
    pub free_restrictions: Option<unsafe extern "C" fn(*mut c_void, *mut Restrictions)>,
}

type InitVt = unsafe extern "C" fn(c_int, c_int, *mut Vtable) -> c_int;

struct DynModule {
    name: String,
    vt: Vtable,
    data: *mut c_void,
    _lib: libloading::Library,
}

// SAFETY: kadmind serves every request on one thread (a tokio `LocalSet`),
// so a module is never called concurrently, as in MIT's single-threaded
// kadmind.
unsafe impl Send for DynModule {}
// SAFETY: see `Send`.
unsafe impl Sync for DynModule {}

impl Drop for DynModule {
    fn drop(&mut self) {
        if let Some(fini) = self.vt.fini {
            // SAFETY: fini is the module's own function, given its own data.
            unsafe { fini(self.data) };
        }
    }
}

fn cstr(s: &str) -> CString {
    CString::new(s.replace('\0', "")).unwrap_or_default()
}

fn opt_ptr(s: &Option<CString>) -> *const c_char {
    s.as_ref().map_or(std::ptr::null(), |s| s.as_ptr())
}

impl Kadm5Auth for DynModule {
    fn name(&self) -> &str {
        &self.name
    }

    fn authorize(&self, c: Princ<'_>, req: &Request<'_>) -> (Verdict, Option<AclRestrictions>) {
        let Some(f) = self.vt.authorize else {
            return (Verdict::NoHandle, None);
        };
        let p = |p: Princ<'_>| Some(cstr(&unparse(p.name, p.realm)));
        let s = |s: &str| Some(cstr(s));
        let (mut p1, mut p2, mut s1, mut s2) = (None, None, None, None);
        let (mut princ, mut pol) = (None, None);
        let mut policy = None;
        match *req {
            Request::AddPrinc { target, mask, ent } | Request::ModPrinc { target, mask, ent } => {
                p1 = p(target);
                policy = ent
                    .policy
                    .as_ref()
                    .map(|v| cstr(&String::from_utf8_lossy(v)));
                princ = Some(PrincEnt {
                    mask: c_long::from(mask as i32),
                    attributes: ent.attributes as i32,
                    max_life: ent.max_life as i32,
                    max_renewable_life: ent.max_renewable_life as i32,
                    princ_expire_time: ent.princ_expire_time as i32,
                    pw_expiration: ent.pw_expiration as i32,
                    policy: std::ptr::null(),
                });
            }
            Request::SetStr { target, key, value } => {
                p1 = p(target);
                s1 = s(key);
                s2 = value.and_then(s);
            }
            Request::Cpw { target }
            | Request::Chrand { target }
            | Request::SetKey { target }
            | Request::PurgeKeys { target }
            | Request::DelPrinc { target }
            | Request::GetPrinc { target }
            | Request::GetStrs { target }
            | Request::Extract { target } => p1 = p(target),
            Request::RenPrinc { src: a, dest: b }
            | Request::AddAlias {
                alias: a,
                target: b,
            } => {
                p1 = p(a);
                p2 = p(b);
            }
            Request::ListPrincs | Request::ListPols | Request::Iprop => {}
            Request::AddPol { policy, mask, ent } | Request::ModPol { policy, mask, ent } => {
                s1 = s(policy);
                pol = Some(PolEnt {
                    mask: c_long::from(mask as i32),
                    pw_min_life: ent.pw_min_life,
                    pw_max_life: ent.pw_max_life,
                    pw_min_length: ent.pw_min_length,
                    pw_min_classes: ent.pw_min_classes,
                    pw_history_num: ent.pw_history_num,
                });
            }
            Request::DelPol { policy } => s1 = s(policy),
            Request::GetPol {
                policy,
                client_policy,
            } => {
                s1 = s(policy);
                s2 = client_policy.and_then(s);
            }
        }
        if let Some(e) = princ.as_mut() {
            e.policy = opt_ptr(&policy);
        }
        let client = cstr(&unparse(c.name, c.realm));
        let mut rs: *mut Restrictions = std::ptr::null_mut();
        // SAFETY: every pointer is null or points to a value that lives until
        // the call returns; the module owns `rs` until free_restrictions.
        let ret = unsafe {
            f(
                self.data,
                req.opcode(),
                client.as_ptr(),
                opt_ptr(&p1),
                opt_ptr(&p2),
                opt_ptr(&s1),
                opt_ptr(&s2),
                princ
                    .as_ref()
                    .map_or(std::ptr::null(), |e| e as *const PrincEnt),
                pol.as_ref()
                    .map_or(std::ptr::null(), |e| e as *const PolEnt),
                &mut rs,
            )
        };
        let restrictions = (!rs.is_null()).then(|| {
            // SAFETY: the module returned a valid restrictions object.
            let r = unsafe { &*rs };
            let out = AclRestrictions {
                mask: r.mask as u32,
                require_attrs: r.require_attrs as u32,
                forbid_attrs: r.forbid_attrs as u32,
                policy: (!r.policy.is_null()).then(|| {
                    // SAFETY: a non-null policy is a NUL-terminated string.
                    unsafe { CStr::from_ptr(r.policy) }
                        .to_string_lossy()
                        .into_owned()
                }),
                princ_lifetime: r.princ_lifetime,
                pw_lifetime: r.pw_lifetime,
                max_life: r.max_life,
                max_renewable_life: r.max_renewable_life,
            };
            if let Some(free) = self.vt.free_restrictions {
                // SAFETY: rs came from this module.
                unsafe { free(self.data, rs) };
            }
            out
        });
        let verdict = match ret {
            0 => Verdict::Pass,
            PLUGIN_NO_HANDLE => Verdict::NoHandle,
            _ => Verdict::Deny,
        };
        (verdict, restrictions)
    }

    fn end(&self) {
        if let Some(end) = self.vt.end {
            // SAFETY: end is the module's own function, given its own data.
            unsafe { end(self.data) };
        }
    }
}

/// A static binary cannot load shared libraries (static musl has no
/// `dlopen`), so configured modules are an error rather than skipped.
const STATIC: bool = cfg!(target_feature = "crt-static");

/// MIT's default `plugin_base_dir` (`$(libdir)/krb5/plugins`).
const PLUGIN_BASE_DIR: &str = "/usr/local/lib/krb5/plugins";

/// `[plugins] kadm5_auth` values, from krb5.conf then kdc.conf (kadmind's
/// profile is both).
fn plugin_values(profiles: &[&Profile], key: &str) -> Vec<String> {
    profiles
        .iter()
        .flat_map(|p| p.get_values(&["plugins", "kadm5_auth", key]))
        .collect()
}

/// Load a shared-library module, or `Ok(None)` when MIT would skip it.
fn load_dyn(name: &str, path: &Path, acl_file: &Path) -> Result<Option<DynModule>, String> {
    // SAFETY: loading a configured kadm5_auth module runs its initializers,
    // which the administrator chose to trust, as with MIT's plugins.
    let lib = match unsafe { libloading::Library::new(path) } {
        Ok(l) => l,
        Err(e) => {
            eprintln!("krb5-rs-kadmind: kadm5_auth module {name}: {e}");
            return Ok(None);
        }
    };
    let sym = format!("kadm5_auth_{name}_initvt");
    // SAFETY: the symbol has the documented InitVt type.
    let initvt: InitVt = match unsafe { lib.get::<InitVt>(sym.as_bytes()) } {
        Ok(f) => *f,
        Err(e) => {
            eprintln!("krb5-rs-kadmind: kadm5_auth module {name}: {e}");
            return Ok(None);
        }
    };
    let mut vt = Vtable {
        name: std::ptr::null(),
        init: None,
        fini: None,
        authorize: None,
        end: None,
        free_restrictions: None,
    };
    // SAFETY: vt is a valid, writable vtable.
    if unsafe { initvt(1, 0, &mut vt) } != 0 {
        return Ok(None);
    }
    let mut data = std::ptr::null_mut();
    if let Some(init) = vt.init {
        let acl = cstr(&acl_file.to_string_lossy());
        // SAFETY: acl is NUL-terminated and data is writable.
        match unsafe { init(acl.as_ptr(), &mut data) } {
            0 => {}
            PLUGIN_NO_HANDLE => return Ok(None),
            e => {
                return Err(format!(
                    "kadm5_auth module {name} failed to initialize: {e}"
                ))
            }
        }
    }
    Ok(Some(DynModule {
        name: name.to_string(),
        vt,
        data,
        _lib: lib,
    }))
}

/// `auth_init`: the enabled modules in MIT's order.
pub fn load(
    profiles: &[&Profile],
    realm: &str,
    acl_file: &Path,
) -> Result<Kadm5AuthModules, String> {
    let mut paths: Vec<(String, PathBuf)> = Vec::new();
    let base = profiles
        .iter()
        .find_map(|p| p.get_string(&["libdefaults", "plugin_base_dir"]))
        .unwrap_or_else(|| PLUGIN_BASE_DIR.into());
    let specs = plugin_values(profiles, "module");
    if STATIC && !specs.is_empty() {
        return Err(
            "kadm5_auth modules need a dynamically linked krb5-rs-kadmind; this one is static"
                .into(),
        );
    }
    for m in specs {
        let Some((name, path)) = m.split_once(':') else {
            return Err(format!("Invalid module specifier {m}"));
        };
        paths.push((name.to_string(), Path::new(&base).join(path)));
    }
    let names: Vec<String> = paths.iter().map(|(n, _)| n.clone()).collect();
    let order = module_order(
        &names,
        &["acl", "self"],
        &plugin_values(profiles, "enable_only"),
        &plugin_values(profiles, "disable"),
    );
    let mut modules: Vec<Box<dyn Kadm5Auth>> = Vec::new();
    for name in order {
        if let Some((_, path)) = paths.iter().find(|(n, _)| *n == name) {
            if let Some(m) = load_dyn(&name, path, acl_file)? {
                modules.push(Box::new(m));
            }
        } else if name == "acl" {
            modules.push(Box::new(AclModule(Arc::new(load_acl(acl_file, realm)?))));
        } else {
            modules.push(Box::new(SelfModule));
        }
    }
    Ok(Kadm5AuthModules::new(modules))
}

#[cfg(test)]
mod tests {
    use super::*;
    use krb5_rs::kdc::kdb::kadm5::{PolicyEnt, PrincipalEnt};
    use krb5_rs::types::PrincipalName;

    const MAX_LIFE: u32 = 0x20;
    const POLICY: u32 = 0x800;
    const MAX_RLIFE: u32 = 0x2000;
    const PW_MIN_LIFE: u32 = 0x8000;
    const PW_MIN_LENGTH: u32 = 0x1_0000;

    /// Build the test modules (MIT `plugins/kadm5_auth/test/main.c`).
    fn module(dir: &Path) -> PathBuf {
        let so = dir.join("kadm5_auth_test.so");
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let out = std::process::Command::new(std::env::var("CC").unwrap_or_else(|_| "cc".into()))
            .args(["-shared", "-fPIC", "-I"])
            .arg(root.join("include"))
            .arg("-o")
            .arg(&so)
            .arg(root.join("tests/fixtures/kadm5_auth_test.c"))
            .output()
            .expect("run cc");
        assert!(out.status.success(), "{out:?}");
        so
    }

    fn modules(dir: &Path, conf: &str) -> Result<Kadm5AuthModules, String> {
        let so = module(dir);
        let text = conf.replace("$SO", &so.to_string_lossy());
        let profile = Profile::parse(&text).expect("profile");
        let acl = dir.join("kadm5.acl");
        std::fs::write(&acl, "admin@R *\n").expect("acl");
        load(&[&profile], "R", &acl)
    }

    fn name(s: &str) -> PrincipalName {
        crate::parse_name_with_default(s, "R").expect("name").0
    }

    fn p(n: &PrincipalName) -> Princ<'_> {
        Princ {
            name: n,
            realm: "R",
        }
    }

    #[test]
    fn welcomer_and_bouncer_like_mit_t_kadm5_auth() {
        let dir = tempfile::tempdir().expect("tempdir");
        let ends = dir.path().join("ends");
        std::env::set_var("KADM5_AUTH_TEST_ENDS", &ends);
        let m = modules(
            dir.path(),
            "[plugins]\n kadm5_auth = {\n  module = welcomer:$SO\n  module = bouncer:$SO\n  \
             enable_only = welcomer\n  enable_only = bouncer\n }\n",
        )
        .expect("load");
        assert_eq!(m.names().collect::<Vec<_>>(), ["welcomer", "bouncer"]);
        let user = name("user");
        let ok = |req: &Request<'_>| m.authorize(p(&user), req).is_some();

        let (a, ab, dx, dn, x) = (
            name("a"),
            name("a/b"),
            name("dx"),
            name("dnodelete"),
            name("x"),
        );
        let vip = PrincipalEnt {
            policy: Some(b"VIP".to_vec()),
            ..PrincipalEnt::default()
        };
        let add = |mask, ent| Request::AddPrinc {
            target: p(&a),
            mask,
            ent,
        };
        assert!(ok(&add(POLICY, &vip)));
        assert!(!ok(&add(POLICY | MAX_LIFE, &vip)));
        assert!(!ok(&add(0, &PrincipalEnt::default())));

        let none = PrincipalEnt::default();
        assert!(ok(&Request::ModPrinc {
            target: p(&a),
            mask: MAX_RLIFE,
            ent: &none
        }));
        assert!(!ok(&Request::ModPrinc {
            target: p(&ab),
            mask: MAX_RLIFE,
            ent: &none
        }));
        assert!(!ok(&Request::ModPrinc {
            target: p(&a),
            mask: MAX_LIFE,
            ent: &none
        }));

        let setstr = |key, value| Request::SetStr {
            target: p(&a),
            key,
            value,
        };
        assert!(ok(&setstr("note", Some("short"))));
        assert!(!ok(&setstr("note", Some("much too long"))));
        assert!(!ok(&setstr("other", Some("short"))));

        assert!(ok(&Request::DelPrinc { target: p(&dx) }));
        assert!(!ok(&Request::DelPrinc { target: p(&dn) }));
        assert!(!ok(&Request::DelPrinc { target: p(&x) }));

        let (bb, cc, c) = (name("bb"), name("cc"), name("c"));
        assert!(ok(&Request::RenPrinc {
            src: p(&bb),
            dest: p(&cc)
        }));
        assert!(!ok(&Request::RenPrinc {
            src: p(&bb),
            dest: p(&c)
        }));
        assert!(!ok(&Request::RenPrinc {
            src: p(&ab),
            dest: p(&cc)
        }));

        let len3 = PolicyEnt {
            pw_min_length: 3,
            ..PolicyEnt::default()
        };
        let addpol = |policy| Request::AddPol {
            policy,
            mask: PW_MIN_LENGTH,
            ent: &len3,
        };
        assert!(ok(&addpol("pol4")));
        assert!(!ok(&addpol("pol")));

        let life = |n| PolicyEnt {
            pw_min_life: n,
            ..PolicyEnt::default()
        };
        let (l5, l11) = (life(5), life(11));
        assert!(ok(&Request::ModPol {
            policy: "pol4",
            mask: PW_MIN_LIFE,
            ent: &l5
        }));
        assert!(!ok(&Request::ModPol {
            policy: "pol4",
            mask: PW_MIN_LIFE,
            ent: &l11
        }));

        let getpol = |policy, client_policy| Request::GetPol {
            policy,
            client_policy,
        };
        assert!(ok(&getpol("aa", Some("bb"))));
        assert!(!ok(&getpol("xx", Some("bb"))));
        assert!(!ok(&getpol("aa", None)));

        // Neither module answers, and acl/self are not enabled.
        assert!(!ok(&Request::ListPrincs));

        for _ in 0..4 {
            m.end();
        }
        assert_eq!(
            std::fs::read_to_string(&ends).expect("ends"),
            "end\n".repeat(4)
        );
    }

    #[test]
    fn order_restrictions_and_skipped_modules() {
        let dir = tempfile::tempdir().expect("tempdir");
        let m = modules(
            dir.path(),
            "[plugins]\n kadm5_auth = {\n  module = limiter:$SO\n  module = skipped:$SO\n  \
             module = missing:/nonexistent.so\n  disable = self\n }\n",
        )
        .expect("load");
        // Dynamic modules first, then the built-ins; init NO_HANDLE and
        // unloadable modules are skipped.
        assert_eq!(m.names().collect::<Vec<_>>(), ["limiter", "acl"]);
        let (lim, admin, user) = (name("lim1"), name("admin"), name("user"));
        let none = PrincipalEnt::default();
        let req = Request::AddPrinc {
            target: p(&lim),
            mask: 0,
            ent: &none,
        };
        let rs = m.authorize(p(&user), &req).expect("limiter authorizes");
        assert_eq!(rs.len(), 1);
        assert_eq!((rs[0].mask, rs[0].max_life), (MAX_LIFE, 3600));
        // The acl module still authorizes admin.
        assert!(m.authorize(p(&admin), &Request::ListPrincs).is_some());
        // self is disabled.
        assert!(m
            .authorize(p(&user), &Request::GetPrinc { target: p(&user) })
            .is_none());
    }

    #[test]
    fn bad_module_specifier_is_an_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        let r = modules(
            dir.path(),
            "[plugins]\n kadm5_auth = {\n  module = nocolon\n }\n",
        );
        assert!(r.is_err());
    }
}
