//! kdcpolicy, audit and authdata modules (MIT `kdc/policy.c`,
//! `kdc/kdc_audit.c`, `kdc/kdc_authdata.c`),
//! run as separate processes and reached over RPC
//! ([`krb5_rs::kdc::plugins::rpc`]), the way p11-kit remotes PKCS #11
//! modules.

#[cfg(test)]
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;

use krb5_rs::kdc::plugins::rpc::{self, InitError, PLUGIN_NO_HANDLE, PLUGIN_VER_NOTSUPP};
use krb5_rs::kdc::plugins::{Audit, AuthdataRequest, KdcAuthdata, KdcPolicy};
use krb5_rs::kdc::securid_sam2::SecuridSam2;
use krb5_rs::plugin;
use krb5_rs::profile::Profile;
use krb5_rs::types::EncTicketPart;

/// The enabled modules of `iface` in MIT's order, with their sockets.
fn configured(profiles: &[&Profile], iface: &str) -> Result<Vec<(String, PathBuf)>, String> {
    Ok(plugin::configured(profiles, iface, &[])?
        .into_iter()
        .filter_map(|c| match c {
            plugin::Configured::Remote(n, p) => Some((n, p)),
            plugin::Configured::Builtin(_) => None,
        })
        .collect())
}

use plugin::connector;

#[path = "audit_simple.rs"]
mod audit_simple;

/// MIT's `simple` audit module (`k5audit.so`), which krb5-rs builds in.
fn is_simple_audit(name: &str, path: &std::path::Path) -> bool {
    name == "simple" && path.extension().is_some_and(|e| e == "so")
}

/// The configured modules.
pub type Modules = (
    Vec<Arc<dyn KdcPolicy>>,
    Vec<Arc<dyn Audit>>,
    Vec<Arc<dyn KdcAuthdata>>,
    Option<SecuridSam2>,
);

/// An authdata module whose errors are logged, as `handle_authdata` logs
/// them (kdc_authdata.c:607-609).
struct Logged(rpc::RemoteAuthdata);

impl KdcAuthdata for Logged {
    fn name(&self) -> &str {
        self.0.name()
    }
    fn handle(&self, req: &AuthdataRequest, reply: &mut EncTicketPart) -> Result<(), i32> {
        self.0.handle(req, reply).inspect_err(|e| {
            tracing::error!("{e} from authdata module {}", self.0.name());
        })
    }
}

/// `load_kdcpolicy_plugins` and `load_audit_modules`. A module that cannot
/// be reached, or refuses the protocol version, is logged and skipped, as
/// MIT skips one that does not load. A kdcpolicy `init` returning
/// `KRB5_PLUGIN_NO_HANDLE` skips the module; any other `init` or `open`
/// error stops the KDC.
pub fn load(profiles: &[&Profile]) -> Result<Modules, String> {
    let mut policy: Vec<Arc<dyn KdcPolicy>> = Vec::new();
    for (name, path) in configured(profiles, "kdcpolicy")? {
        match rpc::kdcpolicy(&name, connector(path.clone())) {
            Ok(m) => policy.push(Arc::new(m)),
            Err(InitError::Refused((PLUGIN_NO_HANDLE | PLUGIN_VER_NOTSUPP, _))) => {}
            Err(InitError::Unavailable(e)) => {
                tracing::error!("kdcpolicy module {name} ({}): {e}", path.display());
            }
            Err(InitError::Refused((e, _))) => {
                return Err(format!("kdcpolicy module {name} failed to initialize: {e}"));
            }
        }
    }
    let mut audit: Vec<Arc<dyn Audit>> = Vec::new();
    for (name, path) in configured(profiles, "audit")? {
        if is_simple_audit(&name, &path) {
            // au_simple_main.c: open fails with KRB5_PLUGIN_NO_HANDLE when
            // audit_open does, which stops the KDC.
            match audit_simple::SimpleAudit::open() {
                Some(m) => audit.push(Arc::new(m)),
                None => {
                    return Err(format!(
                        "audit plugin {name} failed to open. error={PLUGIN_NO_HANDLE}"
                    ))
                }
            }
            continue;
        }
        match rpc::audit(&name, connector(path.clone())) {
            Ok(m) => audit.push(Arc::new(m)),
            Err(InitError::Refused((PLUGIN_VER_NOTSUPP, _))) => {}
            Err(InitError::Unavailable(e)) => {
                tracing::error!("audit module {name} ({}): {e}", path.display());
            }
            Err(InitError::Refused((e, _))) => {
                return Err(format!("audit plugin {name} failed to open. error={e}"));
            }
        }
    }
    // load_authdata_plugins (kdc_authdata.c:84-155): a module that fails to
    // initialize is logged and skipped.
    let mut authdata: Vec<Arc<dyn KdcAuthdata>> = Vec::new();
    for (name, path) in configured(profiles, "kdcauthdata")? {
        match rpc::kdcauthdata(&name, connector(path.clone())) {
            Ok(m) => authdata.push(Arc::new(Logged(m))),
            Err(InitError::Refused((PLUGIN_VER_NOTSUPP, _))) => {}
            Err(InitError::Unavailable(e)) => {
                tracing::error!("authdata module {name} ({}): {e}", path.display());
            }
            Err(InitError::Refused((e, _))) => {
                tracing::error!("{e} while initializing authdata module {name}");
            }
        }
    }
    // `[plugins] kdcpreauth { module = securid_sam2:<ACE bridge socket> }`:
    // MIT loads securid_sam2 only when configured; a module that does not
    // load is logged and skipped (kdc_preauth.c load_preauth_plugins).
    let mut securid = None;
    for (name, path) in configured(profiles, "kdcpreauth")? {
        if name != "securid_sam2" {
            tracing::error!("unknown kdcpreauth module {name} ({})", path.display());
            continue;
        }
        match rpc::securid_ace(&name, connector(path.clone())) {
            Ok(m) => securid = Some(SecuridSam2::new(Some(Arc::new(m)))),
            Err(InitError::Unavailable(e)) => {
                tracing::error!("kdcpreauth module {name} ({}): {e}", path.display());
            }
            Err(InitError::Refused((e, _))) => {
                tracing::error!("{e} while initializing kdcpreauth module {name}");
            }
        }
    }
    Ok((policy, audit, authdata, securid))
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use krb5_rs::kdc::plugins::{PolicyLimits, PolicyRefusal, PolicyRequest};
    use std::os::unix::net::UnixListener;

    struct Fixed(i64, Result<(), i32>);
    impl KdcPolicy for Fixed {
        fn name(&self) -> &str {
            "fixed"
        }
        fn init(&self) -> Result<(), i32> {
            self.1
        }
        fn check_as(&self, _r: &PolicyRequest) -> Result<PolicyLimits, PolicyRefusal> {
            Ok(PolicyLimits {
                lifetime: self.0,
                renew_lifetime: 0,
            })
        }
    }

    fn listen(dir: &Path, name: &str, life: i64, init: Result<(), i32>) -> PathBuf {
        let path = dir.join(format!("{name}.sock"));
        let l = UnixListener::bind(&path).expect("bind");
        std::thread::spawn(move || {
            for s in l.incoming().map_while(Result::ok) {
                std::thread::spawn(move || rpc::serve_kdcpolicy(s, &Fixed(life, init)));
            }
        });
        path
    }

    fn conf(body: &str) -> Profile {
        Profile::parse(&format!("[plugins]\n kdcpolicy = {{\n{body} }}\n")).expect("profile")
    }

    #[test]
    fn modules_load_in_mit_order_with_enable_only_and_disable() {
        let dir = tempfile::tempdir().expect("tempdir");
        let a = listen(dir.path(), "a", 10, Ok(()));
        let b = listen(dir.path(), "b", 20, Ok(()));
        let skip = listen(dir.path(), "skip", 30, Err(PLUGIN_NO_HANDLE));
        let bad = listen(dir.path(), "bad", 40, Err(5));
        let base = dir.path().display();
        let p = conf(&format!(
            "  module = a:unix:path={}\n  module = b:b.sock\n  module = skip:unix:path={}\n  \
             module = gone:unix:path=/nonexistent.sock\n",
            a.display(),
            skip.display()
        ));
        let lib = Profile::parse(&format!("[libdefaults]\n plugin_base_dir = {base}\n"))
            .expect("profile");
        let (policy, audit, _, _) = load(&[&p, &lib]).expect("load");
        assert!(audit.is_empty());
        let names: Vec<&str> = policy.iter().map(|m| m.name()).collect();
        assert_eq!(names, ["a", "b"]);
        let r = PolicyRequest::default();
        assert_eq!(policy[1].check_as(&r).expect("b").lifetime, 20);
        let _ = b;
        let p = conf(&format!("  module = bad:unix:path={}\n", bad.display()));
        assert_eq!(
            load(&[&p]).err().expect("fatal"),
            "kdcpolicy module bad failed to initialize: 5"
        );
        let p = conf(&format!(
            "  module = a:unix:path={}\n  module = bad:unix:path={}\n  disable = bad\n",
            a.display(),
            bad.display()
        ));
        assert_eq!(load(&[&p]).expect("load").0.len(), 1);
        let p = conf(&format!(
            "  module = a:unix:path={}\n  module = bad:unix:path={}\n  enable_only = a\n",
            a.display(),
            bad.display()
        ));
        assert_eq!(load(&[&p]).expect("load").0.len(), 1);
        assert!(load(&[&conf("  module = a\n")]).is_err());
    }

    struct FailInit;
    impl KdcAuthdata for FailInit {
        fn name(&self) -> &str {
            "bad"
        }
        fn init(&self) -> Result<(), i32> {
            Err(5)
        }
        fn handle(&self, _: &AuthdataRequest, _: &mut EncTicketPart) -> Result<(), i32> {
            Ok(())
        }
    }

    fn listen_authdata(dir: &Path, name: &str, module: &'static dyn KdcAuthdata) -> PathBuf {
        let path = dir.join(format!("{name}.sock"));
        let l = UnixListener::bind(&path).expect("bind");
        std::thread::spawn(move || {
            for s in l.incoming().map_while(Result::ok) {
                std::thread::spawn(move || rpc::serve_kdcauthdata(s, module));
            }
        });
        path
    }

    #[test]
    fn authdata_modules_that_fail_to_initialize_are_skipped() {
        let dir = tempfile::tempdir().expect("tempdir");
        let greet = listen_authdata(dir.path(), "greet", &krb5_rs::kdc::plugins::greet::Greet);
        let bad = listen_authdata(dir.path(), "bad", &FailInit);
        let p = Profile::parse(&format!(
            "[plugins]\n kdcauthdata = {{\n  module = bad:unix:path={}\n  \
             module = greet:unix:path={}\n  module = gone:unix:path=/nonexistent.sock\n }}\n",
            bad.display(),
            greet.display()
        ))
        .expect("profile");
        let (policy, audit, authdata, _) = load(&[&p]).expect("load");
        assert!(policy.is_empty() && audit.is_empty());
        let names: Vec<&str> = authdata.iter().map(|m| m.name()).collect();
        assert_eq!(names, ["greet"]);
    }
}
