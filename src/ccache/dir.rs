//! DIR ccache collections (cc_dir.c): `tkt*` FILE caches in a directory,
//! with the primary cache named in `primary`.

use std::path::{Path, PathBuf};

use super::{CcCredential, CcError, Ccache, FileCcache, MatchCred, MatchFlags};
use crate::types::PrincipalName;

/// A DIR cache: one FILE cache within a directory collection.
pub struct DirCcache {
    residual: String,
    file: FileCcache,
}

fn is_cache(filename: &str) -> bool {
    filename.starts_with("tkt")
}

fn subsidiary_residual(dir: &Path, filename: &str) -> String {
    format!(":{}", dir.join(filename).display())
}

/// `split_path`: a subsidiary path's directory and `tkt*` filename.
fn split_path(path: &str) -> Result<(PathBuf, String), CcError> {
    let p = Path::new(path);
    let dir = p.parent().filter(|d| !d.as_os_str().is_empty());
    let file = p.file_name().and_then(|f| f.to_str());
    let Some(dir) = dir else {
        return Err(CcError::BadName(format!(
            "Subsidiary cache path {path} has no parent directory"
        )));
    };
    match file {
        Some(f) if is_cache(f) => Ok((dir.to_path_buf(), f.to_string())),
        _ => Err(CcError::BadName(format!(
            "Subsidiary cache path {path} filename does not begin with \"tkt\""
        ))),
    }
}

/// `verify_dir`: create a missing directory with mode 0700.
fn verify_dir(dir: &Path) -> Result<(), CcError> {
    match std::fs::metadata(dir) {
        Ok(m) if m.is_dir() => Ok(()),
        Ok(_) => Err(CcError::code(
            "KRB5_CC_FORMAT",
            format!(
                "Credential cache directory {} exists but is not a directory",
                dir.display()
            ),
        )),
        Err(e) => {
            if e.kind() == std::io::ErrorKind::NotFound && mkdir_private(dir).is_ok() {
                return Ok(());
            }
            Err(CcError::NoFile(format!(
                "Credential cache directory {} does not exist",
                dir.display()
            )))
        }
    }
}

fn mkdir_private(dir: &Path) -> std::io::Result<()> {
    #[cfg_attr(not(unix), allow(unused_mut))]
    let mut b = std::fs::DirBuilder::new();
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut b, 0o700);
    b.create(dir)
}

/// `read_primary_file`: `None` when `primary` doesn't exist.
fn read_primary(dir: &Path) -> Result<Option<String>, CcError> {
    let path = dir.join("primary");
    let data = match std::fs::read(&path) {
        Ok(d) => d,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => {
            return Err(CcError::code(
                "KRB5_CC_IO",
                "Credentials cache I/O operation failed",
            ))
        }
    };
    // fgets into a 64-byte buffer: the line and its newline fit in 63 bytes.
    let line = &data[..data.len().min(63)];
    let invalid = || {
        CcError::code(
            "KRB5_CC_FORMAT",
            format!("{} contains invalid filename", path.display()),
        )
    };
    let Some(nl) = line.iter().position(|&b| b == b'\n') else {
        return Err(if line.is_empty() {
            CcError::code("KRB5_CC_IO", "Credentials cache I/O operation failed")
        } else {
            invalid()
        });
    };
    let name = std::str::from_utf8(&line[..nl]).map_err(|_| invalid())?;
    if !is_cache(name) || name.contains('/') || name.contains('\\') {
        return Err(invalid());
    }
    Ok(Some(name.to_string()))
}

/// `krb5int_random_string`: `n` random alphanumeric characters.
pub(crate) fn random_string(n: usize) -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut seed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos() as u64)
        ^ (u64::from(std::process::id()) << 32)
        ^ COUNTER
            .fetch_add(1, Ordering::Relaxed)
            .wrapping_mul(0x9E37_79B9_7F4A_7C15);
    let mut out = String::with_capacity(n);
    for _ in 0..n {
        seed = (seed ^ (seed >> 29)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        seed ^= seed >> 32;
        out.push(CHARS[(seed % CHARS.len() as u64) as usize] as char);
    }
    out
}

/// Create a file named `prefix` plus six random characters, like `mkstemp`.
pub(crate) fn create_unique(prefix: &Path) -> std::io::Result<(PathBuf, std::fs::File)> {
    for _ in 0..100 {
        let mut name = prefix.as_os_str().to_owned();
        name.push(random_string(6));
        let path = PathBuf::from(name);
        let mut o = std::fs::OpenOptions::new();
        o.write(true).create_new(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut o, 0o600);
        match o.open(&path) {
            Ok(f) => return Ok((path, f)),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
    Err(std::io::Error::other("could not create a unique file"))
}

/// `write_primary_file`: write through a temporary file and rename it.
fn write_primary(dir: &Path, contents: &str) -> Result<(), CcError> {
    use std::io::Write;
    let primary = dir.join("primary");
    let io = |_| CcError::code("KRB5_CC_IO", "Credentials cache I/O operation failed");
    let (tmp, mut f) = create_unique(&dir.join("primary.")).map_err(io)?;
    let r = writeln!(f, "{contents}")
        .and_then(|()| f.sync_all())
        .and_then(|()| std::fs::rename(&tmp, &primary));
    if r.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    r.map_err(io)
}

impl DirCcache {
    /// `dcc_resolve`: `residual` is a directory (its primary cache) or
    /// `:dir/tkt...` (a subsidiary cache).
    pub fn resolve(residual: &str) -> Result<Self, CcError> {
        let residual = if let Some(path) = residual.strip_prefix(':') {
            let (dir, _) = split_path(path)?;
            verify_dir(&dir)?;
            residual.to_string()
        } else {
            let dir = Path::new(residual);
            verify_dir(dir)?;
            match read_primary(dir)? {
                Some(name) => subsidiary_residual(dir, &name),
                None => {
                    write_primary(dir, "tkt")?;
                    subsidiary_residual(dir, "tkt")
                }
            }
        };
        let file = FileCcache::new(&residual[1..]);
        Ok(Self { residual, file })
    }

    /// `dcc_gen_new`: a new `tkt` cache in the directory named by the
    /// default cache name `DIR:dir`.
    pub fn gen_new(default_name: Option<&str>) -> Result<Self, CcError> {
        let Some(dir) = default_dir(default_name) else {
            return Err(CcError::CannotCreate(
                "Can't create new subsidiary cache because default cache is not a directory \
                 collection"
                    .into(),
            ));
        };
        let dir = Path::new(dir);
        verify_dir(dir)?;
        let (path, _) = create_unique(&dir.join("tkt"))?;
        let residual = format!(":{}", path.display());
        Ok(Self {
            residual,
            file: FileCcache::new(path),
        })
    }

    /// The full name, `DIR::dir/tkt...`.
    pub fn name(&self) -> String {
        format!("DIR:{}", self.residual)
    }

    /// The underlying FILE cache.
    pub fn file(&self) -> &FileCcache {
        &self.file
    }

    /// `dcc_destroy`.
    pub fn destroy(self) -> Result<(), CcError> {
        self.file.destroy()
    }

    /// `dcc_switch_to`: make this the directory's primary cache.
    pub fn switch_to(&self) -> Result<(), CcError> {
        let (dir, file) = split_path(&self.residual[1..])?;
        write_primary(&dir, &file)
    }

    /// `dcc_ptcursor_new` / `dcc_ptcursor_next`: the caches of the default
    /// collection, primary first. Any failure gives no caches.
    pub fn collection(default_name: Option<&str>) -> Vec<Self> {
        let mut out = Vec::new();
        if let Some(sub) = default_name.and_then(|d| d.strip_prefix("DIR::")) {
            let residual = format!(":{sub}");
            if Path::new(sub).exists() {
                if let Ok(c) = Self::resolve(&residual) {
                    out.push(c);
                }
            }
            return out;
        }
        let Some(dir) = default_dir(default_name) else {
            return out;
        };
        let dir = Path::new(dir);
        let Ok(entries) = std::fs::read_dir(dir) else {
            return out;
        };
        let primary = read_primary(dir)
            .ok()
            .flatten()
            .map(|p| subsidiary_residual(dir, &p));
        if let Some(p) = &primary {
            if Path::new(&p[1..]).exists() {
                if let Ok(c) = Self::resolve(p) {
                    out.push(c);
                }
            }
        }
        for e in entries.flatten() {
            let Some(name) = e.file_name().to_str().map(str::to_string) else {
                continue;
            };
            if !is_cache(&name) {
                continue;
            }
            let residual = subsidiary_residual(dir, &name);
            if primary.as_deref() == Some(residual.as_str()) {
                continue;
            }
            match Self::resolve(&residual) {
                Ok(c) => out.push(c),
                Err(_) => break,
            }
        }
        out
    }
}

/// `get_context_default_dir`: `dir` from a default name `DIR:dir`.
fn default_dir(default_name: Option<&str>) -> Option<&str> {
    let d = default_name?.strip_prefix("DIR:")?;
    (!d.is_empty() && !d.starts_with(':')).then_some(d)
}

impl Ccache for DirCcache {
    fn initialize(&mut self, client: &PrincipalName, realm: &str) -> Result<(), CcError> {
        self.file.initialize(client, realm)
    }
    fn principal(&self) -> Result<(PrincipalName, String), CcError> {
        self.file.principal()
    }
    fn store(&mut self, cred: &CcCredential) -> Result<(), CcError> {
        self.file.store(cred)
    }
    fn creds(&self) -> Result<Vec<CcCredential>, CcError> {
        self.file.creds()
    }
    fn remove_cred(&mut self, flags: MatchFlags, m: &MatchCred) -> Result<(), CcError> {
        self.file.remove_cred(flags, m)
    }
    fn retrieve(
        &self,
        flags: MatchFlags,
        m: &MatchCred,
        ktypes: Option<&[i32]>,
    ) -> Result<CcCredential, CcError> {
        self.file.retrieve(flags, m, ktypes)
    }
    fn set_config(
        &mut self,
        principal: Option<(&PrincipalName, &str)>,
        key: &str,
        data: Option<&[u8]>,
    ) -> Result<(), CcError> {
        self.file.set_config(principal, key, data)
    }
    fn get_config(
        &self,
        principal: Option<(&PrincipalName, &str)>,
        key: &str,
    ) -> Result<Option<Vec<u8>>, CcError> {
        self.file.get_config(principal, key)
    }
}
