//! MIT db2's files and locks (`kdb_db2.c` `ctx_lock`/`ctx_unlock`,
//! `adb_openclose.c` `osa_adb_get_lock`): `<name>`, `<name>.ok`,
//! `<name>.kadm5` and `<name>.kadm5.lock`. Locks are fcntl record locks on
//! the `.ok` and `.kadm5.lock` files, which interlock with MIT's OFD locks.

use std::fs::{File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, SystemTime};

use crate::btree::{is_btree, Btree};
use crate::hash::{is_hash, Hash};

pub const SUFFIX_LOCK: &str = ".ok";
pub const SUFFIX_POLICY: &str = ".kadm5";
pub const SUFFIX_POLICY_LOCK: &str = ".kadm5.lock";
const PAGE_SIZE: usize = 4096;

pub fn suffixed(base: &Path, suffix: &str) -> PathBuf {
    let mut name = base.as_os_str().to_owned();
    name.push(suffix);
    PathBuf::from(name)
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Mode {
    Shared,
    Exclusive,
}

#[cfg(unix)]
fn lock_file(file: &File, mode: Option<Mode>) -> io::Result<()> {
    use rustix::fs::{fcntl_lock, FlockOperation};
    let op = match mode {
        Some(Mode::Shared) => FlockOperation::LockShared,
        Some(Mode::Exclusive) => FlockOperation::LockExclusive,
        None => FlockOperation::Unlock,
    };
    fcntl_lock(file, op).map_err(io::Error::from)
}

#[cfg(not(unix))]
fn lock_file(file: &File, mode: Option<Mode>) -> io::Result<()> {
    use fs2::FileExt;
    match mode {
        Some(Mode::Shared) => FileExt::lock_shared(file),
        Some(Mode::Exclusive) => FileExt::lock_exclusive(file),
        None => FileExt::unlock(file),
    }
}

fn cantlock(e: io::Error) -> io::Error {
    match e.raw_os_error() {
        // EBADF: an exclusive lock on a file opened read-only.
        Some(9) | Some(11) | Some(13) => io::Error::new(
            io::ErrorKind::WouldBlock,
            "Cannot lock database (KRB5_KDB_CANTLOCK_DB)",
        ),
        _ => e,
    }
}

/// A principal database in either libdb2 format.
#[allow(clippy::large_enum_variant)]
pub enum Tree {
    Btree(Btree),
    Hash(Hash),
}

impl Tree {
    pub fn get(&mut self, key: &[u8]) -> io::Result<Option<Vec<u8>>> {
        match self {
            Tree::Btree(t) => t.get(key),
            Tree::Hash(t) => t.get(key),
        }
    }
    pub fn put(&mut self, key: &[u8], data: &[u8]) -> io::Result<()> {
        match self {
            Tree::Btree(t) => t.put(key, data),
            Tree::Hash(t) => t.put(key, data),
        }
    }
    pub fn delete(&mut self, key: &[u8]) -> io::Result<bool> {
        match self {
            Tree::Btree(t) => t.delete(key),
            Tree::Hash(t) => t.delete(key),
        }
    }
    pub fn for_each(
        &mut self,
        f: impl FnMut(Vec<u8>, Vec<u8>) -> io::Result<bool>,
    ) -> io::Result<()> {
        match self {
            Tree::Btree(t) => t.for_each(f),
            Tree::Hash(t) => t.for_each(f),
        }
    }
    pub fn entries(&mut self) -> io::Result<Vec<(Vec<u8>, Vec<u8>)>> {
        let mut out = Vec::new();
        self.for_each(|k, v| {
            out.push((k, v));
            Ok(true)
        })?;
        Ok(out)
    }
    pub fn sync(&mut self) -> io::Result<()> {
        match self {
            Tree::Btree(t) => t.sync(),
            Tree::Hash(t) => t.sync(),
        }
    }
    pub fn is_hash(&self) -> bool {
        matches!(self, Tree::Hash(_))
    }
}

/// `open_db`: try the configured type, then the other one.
fn open_tree(path: &Path, write: bool, hash_first: &AtomicBool) -> io::Result<Tree> {
    let file = OpenOptions::new()
        .read(true)
        .write(write)
        .open(path)
        .map_err(|e| {
            io::Error::new(
                e.kind(),
                format!("Cannot open DB2 database '{}': {e}", path.display()),
            )
        })?;
    let first = hash_first.load(Ordering::Relaxed);
    let as_hash = |f: File| Hash::open(f).map(Tree::Hash);
    let as_btree = |f: File| Btree::open(f).map(Tree::Btree);
    if is_hash(&file)? {
        hash_first.store(true, Ordering::Relaxed);
        return as_hash(file);
    }
    if is_btree(&file)? {
        hash_first.store(false, Ordering::Relaxed);
        return as_btree(file);
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        format!(
            "Cannot open DB2 database '{}': Inappropriate file type or format (tried {} first)",
            path.display(),
            if first { "hash" } else { "btree" }
        ),
    ))
}

/// One open db2 database: its lock files and type guess.
pub struct Db2Files {
    base: PathBuf,
    lock: File,
    policy_lock: Mutex<Option<File>>,
    hash_first: AtomicBool,
    serial: Mutex<()>,
}

impl Db2Files {
    pub fn base(&self) -> &Path {
        &self.base
    }

    /// `ctx_init`: open an existing database's lock files.
    pub fn open(base: &Path, hash_first: bool) -> io::Result<Self> {
        let lf = suffixed(base, SUFFIX_LOCK);
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&lf)
            .or_else(|_| File::open(&lf))
            .map_err(|e| {
                io::Error::new(
                    e.kind(),
                    format!("Cannot open DB2 database '{}': {e}", base.display()),
                )
            })?;
        Ok(Db2Files {
            base: base.to_path_buf(),
            lock,
            policy_lock: Mutex::new(Self::open_policy_lock(base)),
            hash_first: AtomicBool::new(hash_first),
            serial: Mutex::new(()),
        })
    }

    fn open_policy_lock(base: &Path) -> Option<File> {
        let p = suffixed(base, SUFFIX_POLICY_LOCK);
        OpenOptions::new()
            .read(true)
            .write(true)
            .open(&p)
            .or_else(|_| File::open(&p))
            .ok()
    }

    /// `ctx_create_db`: create the four files; fails if the database exists.
    pub fn create(base: &Path, hash: bool) -> io::Result<Self> {
        let db = base;
        if db.exists() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("Cannot open DB2 database '{}': File exists", db.display()),
            ));
        }
        let mut opts = OpenOptions::new();
        opts.read(true).write(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut opts, 0o600);
        let lock = opts
            .clone()
            .create(true)
            .truncate(true)
            .open(suffixed(base, SUFFIX_LOCK))?;
        lock_file(&lock, Some(Mode::Exclusive))?;
        let mut excl = opts.clone();
        excl.create_new(true);
        let file = excl.open(db)?;
        let mut tree = if hash {
            Tree::Hash(Hash::create(file, PAGE_SIZE as u32, 40, 1)?)
        } else {
            Tree::Btree(Btree::create(file, PAGE_SIZE)?)
        };
        tree.sync()?;
        let mut pol = Btree::create(excl.open(suffixed(base, SUFFIX_POLICY))?, PAGE_SIZE)?;
        pol.sync()?;
        excl.open(suffixed(base, SUFFIX_POLICY_LOCK))?;
        lock_file(&lock, None)?;
        Self::open(base, hash)
    }

    /// `krb5_db2_destroy`: remove every file of the database.
    pub fn destroy(base: &Path) -> io::Result<()> {
        for s in ["", SUFFIX_LOCK, SUFFIX_POLICY, SUFFIX_POLICY_LOCK] {
            match std::fs::remove_file(suffixed(base, s)) {
                Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(e),
                _ => {}
            }
        }
        Ok(())
    }

    /// `krb5_db2_get_age`: the `.ok` file's modification time.
    pub fn age(&self) -> Option<SystemTime> {
        self.lock.metadata().and_then(|m| m.modified()).ok()
    }

    pub fn read(&self) -> io::Result<Guard<'_>> {
        self.acquire(Mode::Shared)
    }

    pub fn write(&self) -> io::Result<Guard<'_>> {
        self.acquire(Mode::Exclusive)
    }

    /// `ctx_lock`.
    fn acquire(&self, mode: Mode) -> io::Result<Guard<'_>> {
        let serial = self.serial.lock().unwrap_or_else(|p| p.into_inner());
        lock_file(&self.lock, Some(mode)).map_err(cantlock)?;
        let principal = match open_tree(&self.base, mode == Mode::Exclusive, &self.hash_first) {
            Ok(t) => t,
            Err(e) => {
                let _ = lock_file(&self.lock, None);
                return Err(e);
            }
        };
        let mut guard = Guard {
            files: self,
            mode,
            principal,
            policy: None,
            policy_locked: false,
            _serial: serial,
        };
        guard.lock_policy()?;
        Ok(guard)
    }
}

/// A held db2 lock with the principal database open under it.
pub struct Guard<'a> {
    files: &'a Db2Files,
    mode: Mode,
    pub principal: Tree,
    policy: Option<Btree>,
    policy_locked: bool,
    _serial: MutexGuard<'a, ()>,
}

impl Guard<'_> {
    /// `osa_adb_get_lock`.
    fn lock_policy(&mut self) -> io::Result<()> {
        let mut pl = self
            .files
            .policy_lock
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        if pl.is_none() {
            *pl = Db2Files::open_policy_lock(&self.files.base);
        }
        let Some(file) = pl.as_ref() else {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "Cannot lock database (KRB5_KDB_CANTLOCK_DB)",
            ));
        };
        lock_file(file, Some(self.mode)).map_err(cantlock)?;
        if !suffixed(&self.files.base, SUFFIX_POLICY_LOCK).exists() {
            let _ = lock_file(file, None);
            *pl = None;
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "Cannot lock database (KRB5_KDB_CANTLOCK_DB)",
            ));
        }
        self.policy_locked = true;
        Ok(())
    }

    pub fn writable(&self) -> bool {
        self.mode == Mode::Exclusive
    }

    /// `osa_adb_open_and_lock` on the policy database.
    pub fn policy(&mut self) -> io::Result<&mut Btree> {
        if self.policy.is_none() {
            let path = suffixed(&self.files.base, SUFFIX_POLICY);
            let file = OpenOptions::new()
                .read(true)
                .write(self.writable())
                .open(&path)?;
            self.policy = Some(Btree::open(file)?);
        }
        Ok(self.policy.as_mut().unwrap())
    }

    /// Write changes and update the database age, as each MIT write does
    /// (`ctx_update_age`).
    pub fn commit(mut self) -> io::Result<()> {
        self.flush()
    }

    fn flush(&mut self) -> io::Result<()> {
        if self.mode != Mode::Exclusive {
            return Ok(());
        }
        self.principal.sync()?;
        if let Some(p) = self.policy.as_mut() {
            p.sync()?;
        }
        update_age(&self.files.lock);
        Ok(())
    }
}

impl Drop for Guard<'_> {
    /// `ctx_unlock`.
    fn drop(&mut self) {
        let _ = self.flush();
        if self.policy_locked {
            let pl = self
                .files
                .policy_lock
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            if let Some(f) = pl.as_ref() {
                let _ = lock_file(f, None);
            }
        }
        let _ = lock_file(&self.files.lock, None);
    }
}

/// `ctx_update_age`.
fn update_age(lock: &File) {
    let now = SystemTime::now();
    let Ok(mtime) = lock.metadata().and_then(|m| m.modified()) else {
        return;
    };
    let secs = |t: SystemTime| {
        t.duration_since(SystemTime::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs())
    };
    let t = if secs(mtime) >= secs(now) {
        SystemTime::UNIX_EPOCH + Duration::from_secs(secs(mtime) + 1)
    } else {
        now
    };
    let _ = lock.set_times(std::fs::FileTimes::new().set_accessed(t).set_modified(t));
}
