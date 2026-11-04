//! MIT's plugin framework (lib/krb5/krb/plugin.c) for modules that run as
//! separate processes and are reached over [`rpc`], the way p11-kit remotes
//! PKCS #11 modules.

pub mod rpc;

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use std::time::Duration;

use crate::profile::Profile;

/// MIT's default `plugin_base_dir` (`$(libdir)/krb5/plugins`).
pub const PLUGIN_BASE_DIR: &str = "/usr/local/lib/krb5/plugins";
/// How long one module call may take.
pub const TIMEOUT: Duration = Duration::from_secs(30);

/// The module order of MIT's plugin framework (`plugin.c`
/// `configure_interface`): dynamic `module` entries in profile order, then
/// the built-in modules, dropping later duplicates; then `disable` removes
/// modules, and `enable_only`, if set, keeps only the modules it names, in
/// its order.
#[must_use]
pub fn module_order(
    dynamic: &[String],
    builtin: &[&str],
    enable_only: &[String],
    disable: &[String],
) -> Vec<String> {
    let mut list: Vec<String> = Vec::new();
    for name in dynamic
        .iter()
        .map(String::as_str)
        .chain(builtin.iter().copied())
    {
        if !list.iter().any(|n| n == name) {
            list.push(name.to_string());
        }
    }
    list.retain(|n| !disable.contains(n));
    if enable_only.is_empty() {
        return list;
    }
    enable_only
        .iter()
        .filter(|n| list.contains(n))
        .fold(Vec::new(), |mut out, n| {
            if !out.contains(n) {
                out.push(n.clone());
            }
            out
        })
}

/// All `[plugins] <iface> <key>` values across `profiles`.
pub fn plugin_values(profiles: &[&Profile], iface: &str, key: &str) -> Vec<String> {
    profiles
        .iter()
        .flat_map(|p| p.get_values(&["plugins", iface, key]))
        .collect()
}

/// A module's socket: `unix:path=/run/x.sock`, as in p11-kit's
/// `P11_KIT_SERVER_ADDRESS`, or a path, relative ones under
/// `plugin_base_dir`.
pub fn socket_path(base: &str, addr: &str) -> PathBuf {
    match addr.strip_prefix("unix:path=") {
        Some(p) => PathBuf::from(p),
        None => Path::new(base).join(addr),
    }
}

/// One enabled module.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Configured {
    /// A built-in module.
    Builtin(String),
    /// A `module = name:address` module and its socket.
    Remote(String, PathBuf),
}

/// `configure_interface`: the enabled modules of `iface` in MIT's order,
/// the configured modules before the built-in ones.
pub fn configured(
    profiles: &[&Profile],
    iface: &str,
    builtin: &[&str],
) -> Result<Vec<Configured>, String> {
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
        builtin,
        &plugin_values(profiles, iface, "enable_only"),
        &plugin_values(profiles, iface, "disable"),
    );
    Ok(order
        .into_iter()
        .map(|n| match socks.iter().find(|(p, _)| *p == n) {
            Some((_, path)) => Configured::Remote(n, path.clone()),
            None => Configured::Builtin(n),
        })
        .collect())
}

/// Connect to a module socket, with [`TIMEOUT`] on each read and write.
#[cfg(unix)]
pub fn connector(path: PathBuf) -> rpc::Connect {
    rpc::unix_connector(path, TIMEOUT)
}

/// Module sockets need Unix.
#[cfg(not(unix))]
pub fn connector(_path: PathBuf) -> rpc::Connect {
    Box::new(|| Err(std::io::Error::other("module sockets need Unix")))
}

type ConnKey = (&'static str, String, PathBuf);

/// The connection to a library-side module (hostrealm, localauth), opened
/// once per process like MIT's per-context module handles. A module that
/// can't be reached or refuses `handshake` is skipped (`None`), as MIT
/// skips one that fails to load or initialize, and tried again next time.
pub fn remote(handshake: &'static str, name: &str, path: &Path) -> Option<Arc<rpc::Conn>> {
    static CONNS: OnceLock<Mutex<HashMap<ConnKey, Arc<rpc::Conn>>>> = OnceLock::new();
    let key = (handshake, name.to_string(), path.to_path_buf());
    let conns = CONNS.get_or_init(Default::default);
    if let Some(c) = conns
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .get(&key)
    {
        return Some(c.clone());
    }
    let conn = Arc::new(rpc::Conn::open(name, handshake, connector(path.to_path_buf())).ok()?);
    conns
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .insert(key, conn.clone());
    Some(conn)
}
