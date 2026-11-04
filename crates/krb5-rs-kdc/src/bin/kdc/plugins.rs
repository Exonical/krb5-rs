//! kdcpolicy and audit modules (MIT `kdc/policy.c`, `kdc/kdc_audit.c`),
//! run as separate processes and reached over RPC
//! ([`krb5_rs::kdc::plugins::rpc`]), the way p11-kit remotes PKCS #11
//! modules.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use krb5_rs::kdc::kdb::kadm5_auth::module_order;
use krb5_rs::kdc::plugins::rpc::{self, InitError, PLUGIN_NO_HANDLE, PLUGIN_VER_NOTSUPP};
use krb5_rs::kdc::plugins::{Audit, KdcPolicy};
use krb5_rs::profile::Profile;

/// MIT's default `plugin_base_dir` (`$(libdir)/krb5/plugins`).
const PLUGIN_BASE_DIR: &str = "/usr/local/lib/krb5/plugins";
/// How long one module call may take before the KDC gives up on it.
const TIMEOUT: Duration = Duration::from_secs(30);

fn plugin_values(profiles: &[&Profile], iface: &str, key: &str) -> Vec<String> {
    profiles
        .iter()
        .flat_map(|p| p.get_values(&["plugins", iface, key]))
        .collect()
}

/// A module's socket: `unix:path=/run/x.sock`, as in p11-kit's
/// `P11_KIT_SERVER_ADDRESS`, or a path, relative ones under
/// `plugin_base_dir`.
fn socket_path(base: &str, addr: &str) -> PathBuf {
    match addr.strip_prefix("unix:path=") {
        Some(p) => PathBuf::from(p),
        None => Path::new(base).join(addr),
    }
}

/// The enabled modules of `iface` in MIT's order, with their sockets.
fn configured(profiles: &[&Profile], iface: &str) -> Result<Vec<(String, PathBuf)>, String> {
    let base = profiles
        .iter()
        .find_map(|p| p.get_string(&["libdefaults", "plugin_base_dir"]))
        .unwrap_or_else(|| PLUGIN_BASE_DIR.into());
    let mut socks: Vec<(String, PathBuf)> = Vec::new();
    for m in plugin_values(profiles, iface, "module") {
        let Some((name, addr)) = m.split_once(':') else {
            return Err(format!("Invalid module specifier {m}"));
        };
        socks.push((name.to_string(), socket_path(&base, addr)));
    }
    let names: Vec<String> = socks.iter().map(|(n, _)| n.clone()).collect();
    let order = module_order(
        &names,
        &[],
        &plugin_values(profiles, iface, "enable_only"),
        &plugin_values(profiles, iface, "disable"),
    );
    Ok(order
        .into_iter()
        .filter_map(|n| socks.iter().find(|(p, _)| *p == n).cloned())
        .collect())
}

#[cfg(unix)]
fn connector(path: PathBuf) -> rpc::Connect {
    rpc::unix_connector(path, TIMEOUT)
}

#[cfg(not(unix))]
fn connector(_path: PathBuf) -> rpc::Connect {
    let _ = TIMEOUT;
    Box::new(|| Err(std::io::Error::other("module sockets need Unix")))
}

/// The configured modules.
pub type Modules = (Vec<Arc<dyn KdcPolicy>>, Vec<Arc<dyn Audit>>);

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
    Ok((policy, audit))
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
        let (policy, audit) = load(&[&p, &lib]).expect("load");
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
}
