//! Private file creation for key and credential material.
//!
//! MIT creates ccaches, keytab-style stashes and database files mode 0600
//! regardless of the umask (cc_file.c:342, 483, 869-875; kdb_db2.c:455, 698,
//! 718). On Unix these helpers do the same without `unsafe`; elsewhere they
//! are plain std calls and the files inherit the directory ACL.

use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::Path;

fn options() -> OpenOptions {
    let mut o = OpenOptions::new();
    o.write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    o
}

#[cfg(unix)]
fn force_private(f: &File) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    f.set_permissions(std::fs::Permissions::from_mode(0o600))
}

#[cfg(not(unix))]
fn force_private(_f: &File) -> io::Result<()> {
    Ok(())
}

/// Create or truncate `path` as mode 0600; an existing file is chmod'd to
/// 0600 before anything is written (cc_file.c:869-875).
pub(crate) fn create_private(path: &Path) -> io::Result<File> {
    let f = options().create(true).truncate(true).open(path)?;
    force_private(&f)?;
    Ok(f)
}

/// [`create_private`] followed by writing `data`.
pub(crate) fn write_private(path: &Path, data: &[u8]) -> io::Result<()> {
    create_private(path)?.write_all(data)
}

/// Create `path` as mode 0600, failing if it exists (lock files).
#[cfg(feature = "kdc")]
pub(crate) fn create_new_private(path: &Path) -> io::Result<File> {
    options().create_new(true).open(path)
}

/// Create or truncate `path`, applying 0600 only when the file is newly
/// created; an existing file keeps its mode (an administrator may have
/// loosened it, e.g. a group-readable service keytab).
pub(crate) fn write_keep_mode(path: &Path, data: &[u8]) -> io::Result<()> {
    options()
        .create(true)
        .truncate(true)
        .open(path)?
        .write_all(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("krb5rs_fsutil_{}_{name}", std::process::id()))
    }

    #[test]
    fn write_private_overwrites_existing_content() {
        let p = tmp("overwrite");
        write_private(&p, b"first-longer").expect("write");
        write_private(&p, b"second").expect("rewrite");
        assert_eq!(std::fs::read(&p).expect("read"), b"second");
        let _ = std::fs::remove_file(&p);
    }

    #[cfg(feature = "kdc")]
    #[test]
    fn create_new_private_fails_when_file_exists() {
        let p = tmp("create_new");
        let _ = std::fs::remove_file(&p);
        create_new_private(&p).expect("first");
        assert!(create_new_private(&p).is_err());
        let _ = std::fs::remove_file(&p);
    }

    #[cfg(unix)]
    fn mode(p: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(p).expect("metadata").permissions().mode() & 0o777
    }

    #[cfg(unix)]
    #[test]
    fn helpers_create_files_with_mode_0600_despite_loose_existing_mode() {
        use std::os::unix::fs::PermissionsExt;
        let p = tmp("modes");
        let _ = std::fs::remove_file(&p);
        write_private(&p, b"x").expect("write");
        assert_eq!(mode(&p), 0o600);
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).expect("chmod");
        write_private(&p, b"y").expect("rewrite");
        assert_eq!(mode(&p), 0o600);
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o640)).expect("chmod");
        write_keep_mode(&p, b"z").expect("keep");
        assert_eq!(mode(&p), 0o640);
        #[cfg(feature = "kdc")]
        {
            let _ = std::fs::remove_file(&p);
            create_new_private(&p).expect("create_new");
            assert_eq!(mode(&p), 0o600);
        }
        let _ = std::fs::remove_file(&p);
    }
}
