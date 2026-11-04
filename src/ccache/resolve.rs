//! Credential cache names and collections (ccbase.c, ccdefname.c,
//! cccursor.c): `TYPE:residual` resolution, the default cache name, and
//! iteration over the cache collection.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

use super::{
    unparse_name, CcCredential, CcError, Ccache, DirCcache, FileCcache, MatchCred, MatchFlags,
    MemoryCcache,
};
use crate::profile::Profile;
use crate::types::PrincipalName;

/// The library's default cache name when nothing else sets one.
pub const DEFAULT_CCNAME: &str = "FILE:/tmp/krb5cc_%{uid}";

type SharedMemory = Arc<Mutex<MemoryCcache>>;

fn memory_registry() -> &'static Mutex<HashMap<String, SharedMemory>> {
    static R: OnceLock<Mutex<HashMap<String, SharedMemory>>> = OnceLock::new();
    R.get_or_init(Default::default)
}

/// Settings that affect resolution (`[libdefaults]`).
#[derive(Clone, Debug, Default)]
pub struct CcContext {
    /// `KRB5CCNAME` or a program's explicit default (`krb5_cc_set_default_name`).
    pub default_name: Option<String>,
    /// `[libdefaults] default_ccache_name`.
    pub profile_default: Option<String>,
    /// `[libdefaults] kcm_socket`.
    pub kcm_socket: Option<String>,
}

impl CcContext {
    /// Settings from the environment and `profile`.
    pub fn from_env(profile: Option<&Profile>) -> Self {
        let get = |k: &str| profile.and_then(|p| p.get_string(&["libdefaults", k]));
        Self {
            default_name: std::env::var("KRB5CCNAME").ok().filter(|s| !s.is_empty()),
            profile_default: get("default_ccache_name"),
            kcm_socket: get("kcm_socket"),
        }
    }

    /// `krb5_cc_default_name`: explicit/`KRB5CCNAME`, then
    /// `default_ccache_name` (path tokens expanded), then
    /// `FILE:/tmp/krb5cc_%{uid}`.
    pub fn default_ccname(&self) -> Result<String, CcError> {
        if let Some(n) = &self.default_name {
            return Ok(n.clone());
        }
        expand_path_tokens(self.profile_default.as_deref().unwrap_or(DEFAULT_CCNAME))
    }

    fn kcm_socket(&self) -> Option<&str> {
        self.kcm_socket.as_deref()
    }
}

/// `k5_expand_path_tokens` for the tokens meaningful in a cache name.
pub fn expand_path_tokens(path: &str) -> Result<String, CcError> {
    let mut out = String::new();
    let mut rest = path;
    while let Some(i) = rest.find("%{") {
        out.push_str(&rest[..i]);
        let after = &rest[i + 2..];
        let end = after
            .find('}')
            .ok_or_else(|| CcError::BadName("Invalid token".into()))?;
        out.push_str(&expand_token(&after[..end])?);
        rest = &after[end + 1..];
    }
    out.push_str(rest);
    Ok(out)
}

#[allow(unsafe_code)]
fn expand_token(tok: &str) -> Result<String, CcError> {
    Ok(match tok {
        #[cfg(unix)]
        // SAFETY: getuid/geteuid have no preconditions.
        "uid" | "USERID" => unsafe { libc::getuid() }.to_string(),
        #[cfg(unix)]
        // SAFETY: as above.
        "euid" => unsafe { libc::geteuid() }.to_string(),
        #[cfg(unix)]
        "username" => std::env::var("USER")
            .ok()
            .or_else(|| std::env::var("LOGNAME").ok())
            .ok_or_else(|| CcError::BadName("Can't find username".into()))?,
        "TEMP" => std::env::var("TMPDIR").unwrap_or_else(|_| "/tmp".into()),
        "null" => String::new(),
        _ => return Err(CcError::BadName("Invalid token".into())),
    })
}

/// Any credential cache type, as returned by [`resolve`].
pub enum AnyCcache {
    /// `FILE:path`.
    File(FileCcache),
    /// `MEMORY:name`, shared by every handle in the process.
    Memory(String, SharedMemory),
    /// `DIR:dir` or `DIR::dir/tkt...`.
    Dir(DirCcache),
    /// `KEYRING:anchor:collection[:subsidiary]` (Linux).
    #[cfg(target_os = "linux")]
    Keyring(super::KeyringCcache),
    /// `KCM:name`.
    #[cfg(unix)]
    Kcm(super::KcmCcache),
}

/// The type prefix and residual of a cache name (`krb5_cc_resolve`). A
/// name without a type, or with a one-letter (drive letter) prefix, is FILE.
pub fn split_name(name: &str) -> (&str, &str) {
    match name.split_once(':') {
        Some((p, _)) if p.len() == 1 && p.as_bytes()[0].is_ascii_alphabetic() => ("FILE", name),
        Some((p, r)) => (p, r),
        None => ("FILE", name),
    }
}

/// `krb5_cc_resolve`.
pub fn resolve(ctx: &CcContext, name: &str) -> Result<AnyCcache, CcError> {
    let (ty, residual) = split_name(name);
    Ok(match ty {
        "FILE" => AnyCcache::File(FileCcache::new(residual)),
        "MEMORY" => {
            let mut r = memory_registry().lock().unwrap_or_else(|e| e.into_inner());
            let m = r.entry(residual.to_string()).or_default().clone();
            AnyCcache::Memory(residual.to_string(), m)
        }
        "DIR" => AnyCcache::Dir(DirCcache::resolve(residual)?),
        #[cfg(target_os = "linux")]
        "KEYRING" => AnyCcache::Keyring(super::KeyringCcache::resolve(residual)?),
        #[cfg(unix)]
        "KCM" => AnyCcache::Kcm(super::KcmCcache::resolve(residual, ctx.kcm_socket())?),
        _ => return Err(CcError::UnknownType),
    })
}

/// `krb5_cc_default`: resolve the default cache name.
pub fn default_cache(ctx: &CcContext) -> Result<AnyCcache, CcError> {
    resolve(ctx, &ctx.default_ccname()?)
}

/// `krb5_cc_new_unique`: a new cache of type `ty`. DIR and KEYRING make it
/// in the default collection.
pub fn new_unique(ctx: &CcContext, ty: &str) -> Result<AnyCcache, CcError> {
    let def = ctx.default_ccname()?;
    Ok(match ty {
        "FILE" => {
            let tmp = expand_path_tokens("%{TEMP}")?;
            let (path, _) = super::dir::create_unique(&std::path::Path::new(&tmp).join("krb5cc_"))?;
            AnyCcache::File(FileCcache::new(path))
        }
        "MEMORY" => loop {
            let name = super::dir::random_string(6);
            let mut r = memory_registry().lock().unwrap_or_else(|e| e.into_inner());
            if !r.contains_key(&name) {
                let m = r.entry(name.clone()).or_default().clone();
                break AnyCcache::Memory(name, m);
            }
        },
        "DIR" => AnyCcache::Dir(DirCcache::gen_new(Some(&def))?),
        #[cfg(target_os = "linux")]
        "KEYRING" => AnyCcache::Keyring(super::KeyringCcache::gen_new(Some(&def))?),
        #[cfg(unix)]
        "KCM" => AnyCcache::Kcm(super::KcmCcache::gen_new(ctx.kcm_socket())?),
        _ => return Err(CcError::UnknownType),
    })
}

/// `krb5_cccol_cursor`: every cache in the collection, by type in MIT's
/// order (KCM, DIR, KEYRING, FILE, MEMORY). Each type contributes caches
/// only when the default cache name has that type.
pub fn collection(ctx: &CcContext) -> Result<Vec<AnyCcache>, CcError> {
    let def = ctx.default_ccname()?;
    let mut out = Vec::new();
    #[cfg(unix)]
    out.extend(
        super::KcmCcache::collection(Some(&def), ctx.kcm_socket())?
            .into_iter()
            .map(AnyCcache::Kcm),
    );
    out.extend(
        DirCcache::collection(Some(&def))
            .into_iter()
            .map(AnyCcache::Dir),
    );
    #[cfg(target_os = "linux")]
    out.extend(
        super::KeyringCcache::collection(Some(&def))?
            .into_iter()
            .map(AnyCcache::Keyring),
    );
    let (ty, residual) = split_name(&def);
    if ty == "FILE" && std::path::Path::new(residual).exists() {
        out.push(resolve(ctx, &def)?);
    }
    if ty == "MEMORY" {
        out.push(resolve(ctx, &def)?);
    }
    Ok(out)
}

/// `krb5_cc_cache_match`: the collection's cache for `client`.
pub fn cache_match(
    ctx: &CcContext,
    client: &PrincipalName,
    realm: &str,
) -> Result<AnyCcache, CcError> {
    for c in collection(ctx)? {
        if let Ok((p, r)) = c.principal() {
            if p.name_string == client.name_string && r == realm {
                return Ok(c);
            }
        }
    }
    Err(CcError::code(
        "KRB5_CC_NOTFOUND",
        format!(
            "Can't find client principal {} in cache collection",
            unparse_name(client, realm)
        ),
    ))
}

/// `krb5_cccol_have_content`.
pub fn have_content(ctx: &CcContext) -> Result<(), CcError> {
    let mut first_err = None;
    match collection(ctx) {
        Ok(caches) => {
            for c in caches {
                match c.principal() {
                    Ok(_) => return Ok(()),
                    Err(CcError::NoFile(_)) => {}
                    Err(e) => {
                        first_err.get_or_insert(e);
                    }
                }
            }
        }
        Err(e) => first_err = Some(e),
    }
    Err(CcError::code(
        "KRB5_CC_NOTFOUND",
        match first_err {
            Some(e) => format!("No Kerberos credentials available: {e}"),
            None => format!(
                "No Kerberos credentials available (default cache: {})",
                ctx.default_ccname().unwrap_or_default()
            ),
        },
    ))
}

macro_rules! each {
    ($self:expr, $c:ident => $e:expr) => {
        match $self {
            AnyCcache::File($c) => $e,
            AnyCcache::Memory(_, m) => {
                #[allow(unused_mut)]
                let mut $c = m.lock().unwrap_or_else(|e| e.into_inner());
                $e
            }
            AnyCcache::Dir($c) => $e,
            #[cfg(target_os = "linux")]
            AnyCcache::Keyring($c) => $e,
            #[cfg(unix)]
            AnyCcache::Kcm($c) => $e,
        }
    };
}

impl AnyCcache {
    /// `krb5_cc_get_full_name`.
    pub fn name(&self) -> String {
        match self {
            Self::File(f) => format!("FILE:{}", f.path().display()),
            Self::Memory(n, _) => format!("MEMORY:{n}"),
            Self::Dir(d) => d.name(),
            #[cfg(target_os = "linux")]
            Self::Keyring(k) => k.name(),
            #[cfg(unix)]
            Self::Kcm(k) => k.name(),
        }
    }

    /// `krb5_cc_destroy`.
    pub fn destroy(self) -> Result<(), CcError> {
        match self {
            Self::File(f) => f.destroy(),
            Self::Memory(n, m) => {
                memory_registry()
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .remove(&n);
                *m.lock().unwrap_or_else(|e| e.into_inner()) = MemoryCcache::new();
                Ok(())
            }
            Self::Dir(d) => d.destroy(),
            #[cfg(target_os = "linux")]
            Self::Keyring(k) => k.destroy(),
            #[cfg(unix)]
            Self::Kcm(k) => k.destroy(),
        }
    }

    /// `krb5_cc_switch`: make this its collection's primary cache. FILE and
    /// MEMORY have no collection, so this is `KRB5_CC_NOSUPP` for them.
    pub fn switch_to(&self) -> Result<(), CcError> {
        match self {
            Self::Dir(d) => d.switch_to(),
            #[cfg(target_os = "linux")]
            Self::Keyring(k) => k.switch_to(),
            #[cfg(unix)]
            Self::Kcm(k) => k.switch_to(),
            _ => Err(CcError::code(
                "KRB5_CC_NOSUPP",
                "Ccache function not supported: not implemented",
            )),
        }
    }
}

impl Ccache for AnyCcache {
    fn initialize(&mut self, client: &PrincipalName, realm: &str) -> Result<(), CcError> {
        each!(self, c => c.initialize(client, realm))
    }
    fn principal(&self) -> Result<(PrincipalName, String), CcError> {
        each!(self, c => c.principal())
    }
    fn store(&mut self, cred: &CcCredential) -> Result<(), CcError> {
        each!(self, c => c.store(cred))
    }
    fn creds(&self) -> Result<Vec<CcCredential>, CcError> {
        each!(self, c => c.creds())
    }
    fn remove_cred(&mut self, flags: MatchFlags, m: &MatchCred) -> Result<(), CcError> {
        each!(self, c => c.remove_cred(flags, m))
    }
    fn retrieve(
        &self,
        flags: MatchFlags,
        m: &MatchCred,
        ktypes: Option<&[i32]>,
    ) -> Result<CcCredential, CcError> {
        each!(self, c => c.retrieve(flags, m, ktypes))
    }
    fn set_config(
        &mut self,
        principal: Option<(&PrincipalName, &str)>,
        key: &str,
        data: Option<&[u8]>,
    ) -> Result<(), CcError> {
        each!(self, c => c.set_config(principal, key, data))
    }
    fn get_config(
        &self,
        principal: Option<(&PrincipalName, &str)>,
        key: &str,
    ) -> Result<Option<Vec<u8>>, CcError> {
        each!(self, c => c.get_config(principal, key))
    }
}
