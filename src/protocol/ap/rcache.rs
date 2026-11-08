//! Replay caches (MIT `lib/krb5/rcache`): the `dfl`, `file2` and `none`
//! types, `KRB5RCACHENAME`, `KRB5RCACHETYPE` and `default_rcache_name`.
//!
//! A `file2` cache is MIT's on-disk format, so MIT and krb5-rs servers can
//! share one file: a 16-byte SipHash seed, then hash tables of 16-byte
//! records (a 12-byte tag from the authenticator checksum and a big-endian
//! timestamp), each table twice the size of the one before.

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use siphasher::sip::SipHasher24;

use crate::profile::Profile;

/// Errors from resolving or storing into a replay cache.
#[derive(Debug, thiserror::Error)]
pub enum RcacheError {
    /// `KRB5_RC_PARSE`: the name has no `type:` prefix.
    #[error("replay cache name parse/format error")]
    Parse,
    /// `KRB5_RC_TYPE_NOTFOUND`.
    #[error("replay cache type not found")]
    TypeNotFound,
    /// `KRB5KRB_AP_ERR_REPEAT`.
    #[error("request is a replay")]
    Repeat,
    /// The cache file could not be used.
    #[error("{0}")]
    Io(String),
}

const SEED_LEN: usize = 16;
const MAX_SIZE: u64 = i32::MAX as u64;
const TAG_LEN: usize = 12;
const RECORD_LEN: u64 = TAG_LEN as u64 + 4;
const FIRST_TABLE_RECORDS: u64 = 1023;

#[derive(Debug, Clone, PartialEq, Eq)]
enum Kind {
    Dfl,
    File2(PathBuf),
    None,
}

/// An open replay cache (`krb5_rcache`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rcache {
    name: String,
    kind: Kind,
}

/// `secure_getenv`: ignore the environment in a setuid/setgid process.
pub(crate) fn secure_getenv(name: &str) -> Option<String> {
    #[cfg(unix)]
    {
        use rustix::process::{getegid, geteuid, getgid, getuid};
        if getuid() != geteuid() || getgid() != getegid() {
            return None;
        }
    }
    std::env::var(name).ok()
}

impl Rcache {
    /// `k5_rc_resolve` (rc_base.c:76-118): `type:residual` with type `dfl`,
    /// `file2` or `none`.
    pub fn resolve(name: &str) -> Result<Self, RcacheError> {
        let (ty, residual) = name.split_once(':').ok_or(RcacheError::Parse)?;
        let kind = match ty {
            "dfl" => Kind::Dfl,
            "file2" => Kind::File2(PathBuf::from(residual)),
            "none" => Kind::None,
            _ => return Err(RcacheError::TypeNotFound),
        };
        Ok(Self {
            name: name.to_string(),
            kind,
        })
    }

    /// `k5_rc_default` (rc_base.c:30-60): `KRB5RCACHENAME`, then
    /// `KRB5RCACHETYPE` with an empty residual, then `[libdefaults]
    /// default_rcache_name` with path tokens expanded, then `dfl:`.
    pub fn default(profile: Option<&Profile>) -> Result<Self, RcacheError> {
        if let Some(name) = secure_getenv("KRB5RCACHENAME") {
            return Self::resolve(&name);
        }
        if let Some(ty) = secure_getenv("KRB5RCACHETYPE") {
            return Self::resolve(&format!("{ty}:"));
        }
        if let Some(name) =
            profile.and_then(|p| p.get_string(&["libdefaults", "default_rcache_name"]))
        {
            let name = crate::ccache::expand_path_tokens(&name)
                .map_err(|e| RcacheError::Io(e.to_string()))?;
            return Self::resolve(&name);
        }
        Self::resolve("dfl:")
    }

    /// `krb5_get_server_rcache` (srv_rcache.c:32-41): the default cache;
    /// `piece` is ignored, as in MIT.
    pub fn server(profile: Option<&Profile>, _piece: &[u8]) -> Result<Self, RcacheError> {
        Self::default(profile)
    }

    /// `k5_rc_get_name`.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The `type` of the name (`krb5_rc_get_type`).
    pub fn rc_type(&self) -> &str {
        match self.kind {
            Kind::Dfl => "dfl",
            Kind::File2(_) => "file2",
            Kind::None => "none",
        }
    }

    /// `rcops->store` with a tag from `k5_rc_tag_from_ciphertext`: fail
    /// with [`RcacheError::Repeat`] if `tag` was stored within `clockskew`
    /// seconds of `now`, else record it.
    pub fn store(&self, tag: &[u8], now: u32, clockskew: u32) -> Result<(), RcacheError> {
        let path = match &self.kind {
            Kind::None => return Ok(()),
            Kind::File2(p) => p.clone(),
            Kind::Dfl => dfl_path()?,
        };
        let file = open(&path, matches!(self.kind, Kind::Dfl))?;
        let mut t = [0u8; TAG_LEN];
        let n = tag.len().min(TAG_LEN);
        t[..n].copy_from_slice(&tag[..n]);
        store_locked(file, &t, now, clockskew).map_err(|e| match e {
            StoreError::Repeat => RcacheError::Repeat,
            StoreError::Io(e) => RcacheError::Io(format!("{e} (filename: {})", path.display())),
        })
    }
}

/// `open_file` (rc_dfl.c): `$KRB5RCACHEDIR`, `$TMPDIR` or `/var/tmp`, then
/// `krb5_<euid>.rcache2`; on Windows `%KRB5RCACHEDIR%` or
/// `%LOCALAPPDATA%`, then `krb5.rcache2`.
fn dfl_path() -> Result<PathBuf, RcacheError> {
    #[cfg(unix)]
    {
        let dir = secure_getenv("KRB5RCACHEDIR")
            .or_else(|| secure_getenv("TMPDIR"))
            .unwrap_or_else(|| "/var/tmp".into());
        let euid = rustix::process::geteuid().as_raw();
        Ok(Path::new(&dir).join(format!("krb5_{euid}.rcache2")))
    }
    #[cfg(not(unix))]
    {
        let dir = secure_getenv("KRB5RCACHEDIR")
            .or_else(|| std::env::var("LOCALAPPDATA").ok())
            .ok_or_else(|| RcacheError::Io("no LOCALAPPDATA directory".into()))?;
        Ok(Path::new(&dir).join("krb5.rcache2"))
    }
}

fn open(path: &Path, dfl: bool) -> Result<File, RcacheError> {
    let mut o = OpenOptions::new();
    o.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
        if dfl {
            o.custom_flags(libc::O_NOFOLLOW);
        }
    }
    let file = o
        .open(path)
        .map_err(|e| RcacheError::Io(format!("{e} (filename: {})", path.display())))?;
    #[cfg(unix)]
    if dfl {
        use std::os::unix::fs::MetadataExt;
        let euid = rustix::process::geteuid().as_raw();
        if file.metadata().map(|m| m.uid()).ok() != Some(euid) {
            return Err(RcacheError::Io(format!(
                "Replay cache file {} is not owned by uid {euid}",
                path.display()
            )));
        }
    }
    #[cfg(not(unix))]
    let _ = dfl;
    Ok(file)
}

enum StoreError {
    Repeat,
    Io(io::Error),
}

impl From<io::Error> for StoreError {
    fn from(e: io::Error) -> Self {
        StoreError::Io(e)
    }
}

/// fcntl locks don't exclude threads of one process, so threads also take
/// this lock.
static THREAD_LOCK: Mutex<()> = Mutex::new(());

/// `k5_rcfile2_store` (rc_file2.c:186-210): store under an exclusive lock
/// (a POSIX record lock like MIT's `krb5_lock_file`, so MIT processes
/// sharing the file are excluded too).
fn store_locked(
    mut file: File,
    tag: &[u8; TAG_LEN],
    now: u32,
    skew: u32,
) -> Result<(), StoreError> {
    let _guard = THREAD_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    #[cfg(unix)]
    rustix::fs::fcntl_lock(&file, rustix::fs::FlockOperation::LockExclusive)
        .map_err(io::Error::from)?;
    #[cfg(not(unix))]
    file.lock()?;
    let ret = store(&mut file, tag, now, skew);
    #[cfg(unix)]
    let _ = rustix::fs::fcntl_lock(&file, rustix::fs::FlockOperation::Unlock);
    #[cfg(not(unix))]
    let _ = file.unlock();
    ret
}

/// `next_table` (rc_file2.c:47-67).
fn next_table(offset: &mut Option<u64>, nrecords: &mut u64) -> io::Result<()> {
    match *offset {
        None => {
            *offset = Some(SEED_LEN as u64);
            *nrecords = FIRST_TABLE_RECORDS;
        }
        Some(o) if o == SEED_LEN as u64 => {
            *offset = Some(o + *nrecords * RECORD_LEN);
            *nrecords = (FIRST_TABLE_RECORDS + 1) * 2;
        }
        Some(o) => {
            *offset = Some(o + *nrecords * RECORD_LEN);
            *nrecords *= 2;
        }
    }
    let overflow = || io::Error::from_raw_os_error(libc_eoverflow());
    if *nrecords > MAX_SIZE / RECORD_LEN {
        return Err(overflow());
    }
    if offset.unwrap_or(0) > MAX_SIZE - *nrecords * RECORD_LEN {
        return Err(overflow());
    }
    Ok(())
}

#[cfg(unix)]
fn libc_eoverflow() -> i32 {
    libc::EOVERFLOW
}

#[cfg(not(unix))]
fn libc_eoverflow() -> i32 {
    132
}

/// `ts_after(now, ts_incr(timestamp, skew))`.
fn expired(timestamp: u32, now: u32, skew: u32) -> bool {
    (now.wrapping_sub(timestamp.wrapping_add(skew)) as i32) > 0
}

/// Read up to two records at `offset`.
fn read_records(file: &mut File, offset: u64) -> io::Result<Vec<([u8; TAG_LEN], u32)>> {
    file.seek(SeekFrom::Start(offset))?;
    let mut buf = [0u8; 2 * RECORD_LEN as usize];
    let mut n = 0;
    while n < buf.len() {
        match file.read(&mut buf[n..])? {
            0 => break,
            k => n += k,
        }
    }
    Ok(buf[..n]
        .as_chunks::<{ RECORD_LEN as usize }>()
        .0
        .iter()
        .map(|r| {
            let mut tag = [0u8; TAG_LEN];
            tag.copy_from_slice(&r[..TAG_LEN]);
            (tag, u32::from_be_bytes(r[TAG_LEN..].try_into().expect("4")))
        })
        .collect())
}

fn write_record(file: &mut File, offset: u64, tag: &[u8; TAG_LEN], now: u32) -> io::Result<()> {
    let mut rec = [0u8; RECORD_LEN as usize];
    rec[..TAG_LEN].copy_from_slice(tag);
    rec[TAG_LEN..].copy_from_slice(&now.to_be_bytes());
    file.seek(SeekFrom::Start(offset))?;
    file.write_all(&rec)
}

/// `store` (rc_file2.c:114-184).
fn store(file: &mut File, tag: &[u8; TAG_LEN], now: u32, skew: u32) -> Result<(), StoreError> {
    let mut seed = [0u8; SEED_LEN];
    file.seek(SeekFrom::Start(0))?;
    let mut n = 0;
    while n < SEED_LEN {
        match file.read(&mut seed[n..])? {
            0 => break,
            k => n += k,
        }
    }
    if n < SEED_LEN {
        seed.copy_from_slice(&crate::crypto::util::generate_random(SEED_LEN));
        file.seek(SeekFrom::Start(0))?;
        file.write_all(&seed)?;
    }

    let (mut table, mut nrecords, mut avail) = (None, 0u64, None);
    loop {
        next_table(&mut table, &mut nrecords)?;
        let ind = SipHasher24::new_with_key(&seed).hash(tag) % nrecords;
        let offset = table.unwrap_or(0) + ind * RECORD_LEN;
        let recs = read_records(file, offset)?;
        if recs.iter().any(|(t, ts)| *ts != 0 && t == tag) {
            return Err(StoreError::Repeat);
        }
        let empty = |i: usize| recs.get(i).is_none_or(|r| r.1 == 0);
        if avail.is_none() {
            if empty(0) || expired(recs[0].1, now, skew) {
                avail = Some(offset);
            } else if empty(1) || expired(recs[1].1, now, skew) {
                avail = Some(offset + RECORD_LEN);
            }
        }
        if empty(0) || empty(1) {
            write_record(file, avail.unwrap_or(offset), tag, now)?;
            return Ok(());
        }
        seed[0] = seed[0].wrapping_add(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("krb5rs-rc-{}-{name}", std::process::id()));
        let _ = std::fs::remove_file(&p);
        p
    }

    fn rc(p: &Path) -> Rcache {
        Rcache::resolve(&format!("file2:{}", p.display())).expect("resolve")
    }

    #[test]
    fn test_siphash_matches_reference_vector() {
        let key: [u8; 16] = std::array::from_fn(|i| i as u8);
        let msg: Vec<u8> = (0..15).collect();
        assert_eq!(
            SipHasher24::new_with_key(&key).hash(&msg),
            0xa129ca6149be45e5
        );
    }

    #[test]
    fn test_resolve_names_like_mit() {
        assert!(matches!(Rcache::resolve("dfl"), Err(RcacheError::Parse)));
        assert!(matches!(
            Rcache::resolve("bogus:x"),
            Err(RcacheError::TypeNotFound)
        ));
        assert_eq!(Rcache::resolve("none:").expect("none").rc_type(), "none");
        let r = Rcache::resolve("file2:/x/y").expect("file2");
        assert_eq!((r.name(), r.rc_type()), ("file2:/x/y", "file2"));
        Rcache::resolve("none:")
            .expect("none")
            .store(b"t", 1, 1)
            .expect("none");
        Rcache::resolve("none:")
            .expect("none")
            .store(b"t", 1, 1)
            .expect("none");
    }

    #[test]
    fn test_file2_detects_replay_and_expiry() {
        let p = tmp("replay");
        let c = rc(&p);
        c.store(b"0123456789abcdef", 1000, 100).expect("first");
        assert!(matches!(
            c.store(b"0123456789abcdef", 1050, 100),
            Err(RcacheError::Repeat)
        ));
        // Only the first 12 bytes are compared (TAG_LEN).
        assert!(matches!(
            c.store(b"0123456789abXXXX", 1050, 100),
            Err(RcacheError::Repeat)
        ));
        // A short tag is zero-padded.
        c.store(b"short", 1000, 100).expect("short");
        assert!(matches!(
            c.store(b"short\0\0", 1000, 100),
            Err(RcacheError::Repeat)
        ));
        // Persistence: a new handle on the same file sees the records.
        assert!(matches!(
            rc(&p).store(b"short", 1000, 100),
            Err(RcacheError::Repeat)
        ));
        let _ = std::fs::remove_file(&p);
    }

    /// t_rcfile2.c `expiry_test`: records that expire between stores never
    /// need a second table.
    #[test]
    fn test_file2_expiry_reuses_first_table() {
        let p = tmp("expiry");
        let c = rc(&p);
        let (skew, start) = (5u32, 1000u32);
        for i in 0..2000u32 {
            let h = SipHasher24::new_with_key(&[0; 16]).hash(&i.to_be_bytes());
            c.store(&h.to_be_bytes(), start + i * skew * 2, skew)
                .expect("store");
            let len = std::fs::metadata(&p).expect("stat").len();
            assert!(len <= SEED_LEN as u64 + (FIRST_TABLE_RECORDS + 1) * RECORD_LEN);
        }
        let _ = std::fs::remove_file(&p);
    }

    /// t_rcfile2.c `concurrent`/`race`: many unique tags grow later tables
    /// and are all found again; threads storing one tag succeed once.
    #[test]
    fn test_file2_many_records_and_race() {
        let p = tmp("many");
        let c = rc(&p);
        for i in 0..5000u32 {
            let mut t = [0u8; 12];
            t[..4].copy_from_slice(&i.to_be_bytes());
            c.store(&t, 1000, 100).expect("store");
        }
        for i in 0..5000u32 {
            let mut t = [0u8; 12];
            t[..4].copy_from_slice(&i.to_be_bytes());
            assert!(matches!(c.store(&t, 1000, 100), Err(RcacheError::Repeat)));
        }
        let ok: usize = std::thread::scope(|s| {
            let hs: Vec<_> = (0..8)
                .map(|_| s.spawn(|| c.store(b"race-tag-xxx", 1000, 100).is_ok()))
                .collect();
            hs.into_iter()
                .map(|h| usize::from(h.join().expect("join")))
                .sum()
        });
        assert_eq!(ok, 1);
        let _ = std::fs::remove_file(&p);
    }
}
