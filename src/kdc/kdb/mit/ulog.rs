//! MIT 1.22.2 update log for incremental propagation: the file layout of
//! `include/kdb_log.h`, the log operations of `lib/kdb/kdb_log.c`, the entry
//! conversion of `lib/kdb/kdb_convert.c` and the XDR types of
//! `lib/kdb/iprop.x`. Like MIT's mmap'd file, headers are in host byte order;
//! locking is an `fcntl` lock on the whole file (`lib/krb5/os/lock_file.c`).

use std::fs::{File, OpenOptions};
use std::os::unix::fs::{FileExt, OpenOptionsExt};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use rustix::fs::{fcntl_lock, FlockOperation};

use super::codec::{KeyData, MitEntry, TlData};
use super::name::{parse_name, unparse_name};
use super::tl::{LAST_PWD_CHANGE, MOD_PRINC};
use crate::kdc::store::StoreError;

/// `KDB_VERSION` (`kdb_log.h:24`).
pub const KDB_VERSION: u16 = 1;
/// `KDB_STABLE` (`kdb_log.h:29`).
pub const KDB_STABLE: u16 = 1;
/// `KDB_UNSTABLE` (`kdb_log.h:30`).
pub const KDB_UNSTABLE: u16 = 2;
/// `KDB_CORRUPT` (`kdb_log.h:31`).
pub const KDB_CORRUPT: u16 = 3;
/// `KDB_ULOG_MAGIC` (`kdb_log.h:36`).
pub const KDB_ULOG_MAGIC: u32 = 0x0666_1212;
/// `KDB_ULOG_HDR_MAGIC` (`kdb_log.h:37`).
pub const KDB_ULOG_HDR_MAGIC: u32 = 0x0666_2323;
/// `DEF_ULOGENTRIES` (`kdb_log.h:42`).
pub const DEF_ULOGENTRIES: u32 = 1000;
/// `ULOG_BLOCK` (`kdb_log.h:44`).
pub const ULOG_BLOCK: u16 = 2048;
/// `MAXLOGLEN` (`kdb_log.h:45`).
const MAXLOGLEN: u64 = 0x1000_0000;
/// `sizeof(kdb_hlog_t)`.
pub const HEADER_SIZE: u64 = 40;
/// `sizeof(kdb_ent_header_t)`.
const ENTRY_HEADER_SIZE: u32 = 28;
/// `offsetof(kdb_ent_header_t, entry_data)`.
const ENTRY_DATA_OFFSET: usize = 24;
/// `KV5M_DATA`, the magic of every principal component (`k5-int.h:2236`).
pub const KV5M_DATA: i32 = -1_760_647_422;
/// `KRB5_KDB_V1_BASE_LENGTH`, the `len` of every stored entry (`kdb.h`).
const KRB5_KDB_V1_BASE_LENGTH: i16 = 38;

fn io_error(what: &str, e: std::io::Error) -> StoreError {
    StoreError::backend(format!("{what}: {e}"))
}

/// `kdbe_time_t`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Time {
    /// `seconds`.
    pub seconds: u32,
    /// `useconds`.
    pub useconds: u32,
}

impl Time {
    /// `time_current` (`kdb_log.c:62-70`).
    pub fn now() -> Self {
        let d = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        Self {
            seconds: u32::try_from(d.as_secs()).unwrap_or(u32::MAX),
            useconds: d.subsec_micros(),
        }
    }
}

/// `kdb_last_t`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Last {
    /// `sno`.
    pub sno: u32,
    /// `time`.
    pub time: Time,
}

/// `update_status_t`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpdateStatus {
    /// `Ok`.
    Ok = 0,
    /// `Error`.
    Error = 1,
    /// `FullResyncNeeded`.
    FullResyncNeeded = 2,
    /// `Busy`.
    Busy = 3,
    /// `Nil`.
    Nil = 4,
    /// `PermDenied`.
    PermDenied = 5,
}

impl UpdateStatus {
    /// `from_u32`.
    pub fn from_u32(v: u32) -> Option<Self> {
        Some(match v {
            0 => Self::Ok,
            1 => Self::Error,
            2 => Self::FullResyncNeeded,
            3 => Self::Busy,
            4 => Self::Nil,
            5 => Self::PermDenied,
            _ => return None,
        })
    }
}

/// `kdb_hlog_t`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Header {
    /// `hmagic`.
    pub hmagic: u32,
    /// `db_version_num`.
    pub db_version_num: u16,
    /// `num`.
    pub num: u32,
    /// `first_time`.
    pub first_time: Time,
    /// `last_time`.
    pub last_time: Time,
    /// `first_sno`.
    pub first_sno: u32,
    /// `last_sno`.
    pub last_sno: u32,
    /// `state`.
    pub state: u16,
    /// `block`.
    pub block: u16,
}

fn ne_u32(b: &[u8], at: usize) -> u32 {
    let mut w = [0; 4];
    w.copy_from_slice(&b[at..at + 4]);
    u32::from_ne_bytes(w)
}

fn ne_u16(b: &[u8], at: usize) -> u16 {
    u16::from_ne_bytes([b[at], b[at + 1]])
}

impl Header {
    /// `decode`.
    pub fn decode(b: &[u8; HEADER_SIZE as usize]) -> Self {
        Self {
            hmagic: ne_u32(b, 0),
            db_version_num: ne_u16(b, 4),
            num: ne_u32(b, 8),
            first_time: Time {
                seconds: ne_u32(b, 12),
                useconds: ne_u32(b, 16),
            },
            last_time: Time {
                seconds: ne_u32(b, 20),
                useconds: ne_u32(b, 24),
            },
            first_sno: ne_u32(b, 28),
            last_sno: ne_u32(b, 32),
            state: ne_u16(b, 36),
            block: ne_u16(b, 38),
        }
    }

    /// `encode`.
    pub fn encode(&self) -> [u8; HEADER_SIZE as usize] {
        let mut b = [0; HEADER_SIZE as usize];
        b[0..4].copy_from_slice(&self.hmagic.to_ne_bytes());
        b[4..6].copy_from_slice(&self.db_version_num.to_ne_bytes());
        b[8..12].copy_from_slice(&self.num.to_ne_bytes());
        b[12..16].copy_from_slice(&self.first_time.seconds.to_ne_bytes());
        b[16..20].copy_from_slice(&self.first_time.useconds.to_ne_bytes());
        b[20..24].copy_from_slice(&self.last_time.seconds.to_ne_bytes());
        b[24..28].copy_from_slice(&self.last_time.useconds.to_ne_bytes());
        b[28..32].copy_from_slice(&self.first_sno.to_ne_bytes());
        b[32..36].copy_from_slice(&self.last_sno.to_ne_bytes());
        b[36..38].copy_from_slice(&self.state.to_ne_bytes());
        b[38..40].copy_from_slice(&self.block.to_ne_bytes());
        b
    }
}

/// `kdb_ent_header_t` without its data.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct EntryHeader {
    /// `umagic`.
    pub umagic: u32,
    /// `sno`.
    pub sno: u32,
    /// `time`.
    pub time: Time,
    /// `commit`.
    pub commit: bool,
    /// `entry_size`.
    pub entry_size: u32,
}

impl EntryHeader {
    fn decode(b: &[u8]) -> Self {
        Self {
            umagic: ne_u32(b, 0),
            sno: ne_u32(b, 4),
            time: Time {
                seconds: ne_u32(b, 8),
                useconds: ne_u32(b, 12),
            },
            commit: ne_u32(b, 16) != 0,
            entry_size: ne_u32(b, 20),
        }
    }

    fn encode(&self) -> [u8; ENTRY_DATA_OFFSET] {
        let mut b = [0; ENTRY_DATA_OFFSET];
        b[0..4].copy_from_slice(&self.umagic.to_ne_bytes());
        b[4..8].copy_from_slice(&self.sno.to_ne_bytes());
        b[8..12].copy_from_slice(&self.time.seconds.to_ne_bytes());
        b[12..16].copy_from_slice(&self.time.useconds.to_ne_bytes());
        b[16..20].copy_from_slice(&u32::from(self.commit).to_ne_bytes());
        b[20..24].copy_from_slice(&self.entry_size.to_ne_bytes());
        b
    }
}

/// `kdbe_key_t`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Key {
    /// `ver`.
    pub ver: i32,
    /// `kvno`.
    pub kvno: i32,
    /// `enctypes`.
    pub enctypes: Vec<i32>,
    /// `contents`.
    pub contents: Vec<Vec<u8>>,
}

/// `kdbe_princ_t`; each component is `(k_magic, k_data)`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Princ {
    /// `realm`.
    pub realm: Vec<u8>,
    /// `components`.
    pub components: Vec<(i32, Vec<u8>)>,
    /// `name_type`.
    pub name_type: i32,
}

/// `kdbe_tl_t`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Tl {
    /// `kind`.
    pub kind: i16,
    /// `data`.
    pub data: Vec<u8>,
}

/// `kdbe_val_t`, one changed attribute.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    /// `AttrFlags`.
    AttrFlags(u32),
    /// `MaxLife`.
    MaxLife(u32),
    /// `MaxRenewLife`.
    MaxRenewLife(u32),
    /// `Exp`.
    Exp(u32),
    /// `PwExp`.
    PwExp(u32),
    /// `LastSuccess`.
    LastSuccess(u32),
    /// `LastFailed`.
    LastFailed(u32),
    /// `FailAuthCount`.
    FailAuthCount(u32),
    /// `Princ`.
    Princ(Princ),
    /// `KeyData`.
    KeyData(Vec<Key>),
    /// `TlData`.
    TlData(Vec<Tl>),
    /// `Len`.
    Len(i16),
    /// `ModPrinc`.
    ModPrinc(Princ),
    /// `ModTime`.
    ModTime(u32),
    /// `ModWhere`.
    ModWhere(Vec<u8>),
    /// `PwLastChange`.
    PwLastChange(u32),
    /// `PwPolicy`.
    PwPolicy(Vec<u8>),
    /// `PwPolicySwitch`.
    PwPolicySwitch(bool),
    /// `PwHistKvno`.
    PwHistKvno(u32),
    /// `PwHist`.
    PwHist(Vec<Vec<Key>>),
    /// `Extension`.
    Extension(i32, Vec<u8>),
}

impl Value {
    /// The `kdbe_attr_type_t` discriminant.
    pub fn attr_type(&self) -> i32 {
        match self {
            Self::AttrFlags(_) => 0,
            Self::MaxLife(_) => 1,
            Self::MaxRenewLife(_) => 2,
            Self::Exp(_) => 3,
            Self::PwExp(_) => 4,
            Self::LastSuccess(_) => 5,
            Self::LastFailed(_) => 6,
            Self::FailAuthCount(_) => 7,
            Self::Princ(_) => 8,
            Self::KeyData(_) => 9,
            Self::TlData(_) => 10,
            Self::Len(_) => 11,
            Self::ModPrinc(_) => 12,
            Self::ModTime(_) => 13,
            Self::ModWhere(_) => 14,
            Self::PwLastChange(_) => 15,
            Self::PwPolicy(_) => 16,
            Self::PwPolicySwitch(_) => 17,
            Self::PwHistKvno(_) => 18,
            Self::PwHist(_) => 19,
            Self::Extension(t, _) => *t,
        }
    }
}

/// `kdb_incr_update_t`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Update {
    /// `princ_name`.
    pub princ_name: Vec<u8>,
    /// `sno`.
    pub sno: u32,
    /// `time`.
    pub time: Time,
    /// `values`.
    pub values: Vec<Value>,
    /// `deleted`.
    pub deleted: bool,
    /// `commit`.
    pub commit: bool,
    /// `kdcs_seen_by`.
    pub kdcs_seen_by: Vec<Vec<u8>>,
    /// `futures`.
    pub futures: Vec<u8>,
}

/// An XDR encoder for the iprop types.
#[derive(Default)]
pub struct XdrWriter(pub Vec<u8>);

impl XdrWriter {
    /// `u32`.
    pub fn u32(&mut self, v: u32) {
        self.0.extend_from_slice(&v.to_be_bytes());
    }

    /// `i32`.
    pub fn i32(&mut self, v: i32) {
        self.0.extend_from_slice(&v.to_be_bytes());
    }

    /// `bool`.
    pub fn bool(&mut self, v: bool) {
        self.u32(u32::from(v));
    }

    fn len(&mut self, n: usize) -> Result<(), StoreError> {
        let n = u32::try_from(n).map_err(|_| StoreError::corrupt("XDR array too long"))?;
        self.u32(n);
        Ok(())
    }

    /// `opaque`.
    pub fn opaque(&mut self, v: &[u8]) -> Result<(), StoreError> {
        self.len(v.len())?;
        self.0.extend_from_slice(v);
        self.0.resize((self.0.len() + 3) & !3, 0);
        Ok(())
    }

    /// `time`.
    pub fn time(&mut self, t: Time) {
        self.u32(t.seconds);
        self.u32(t.useconds);
    }

    /// `last`.
    pub fn last(&mut self, l: Last) {
        self.u32(l.sno);
        self.time(l.time);
    }

    fn key(&mut self, k: &Key) -> Result<(), StoreError> {
        self.i32(k.ver);
        self.i32(k.kvno);
        self.len(k.enctypes.len())?;
        for e in &k.enctypes {
            self.i32(*e);
        }
        self.len(k.contents.len())?;
        for c in &k.contents {
            self.opaque(c)?;
        }
        Ok(())
    }

    fn keys(&mut self, keys: &[Key]) -> Result<(), StoreError> {
        self.len(keys.len())?;
        keys.iter().try_for_each(|k| self.key(k))
    }

    fn princ(&mut self, p: &Princ) -> Result<(), StoreError> {
        self.opaque(&p.realm)?;
        self.len(p.components.len())?;
        for (magic, data) in &p.components {
            self.i32(*magic);
            self.opaque(data)?;
        }
        self.i32(p.name_type);
        Ok(())
    }

    fn value(&mut self, v: &Value) -> Result<(), StoreError> {
        self.i32(v.attr_type());
        match v {
            Value::AttrFlags(x)
            | Value::MaxLife(x)
            | Value::MaxRenewLife(x)
            | Value::Exp(x)
            | Value::PwExp(x)
            | Value::LastSuccess(x)
            | Value::LastFailed(x)
            | Value::FailAuthCount(x)
            | Value::ModTime(x)
            | Value::PwLastChange(x)
            | Value::PwHistKvno(x) => self.u32(*x),
            Value::Princ(p) | Value::ModPrinc(p) => self.princ(p)?,
            Value::KeyData(keys) => self.keys(keys)?,
            Value::TlData(tls) => {
                self.len(tls.len())?;
                for tl in tls {
                    self.i32(i32::from(tl.kind));
                    self.opaque(&tl.data)?;
                }
            }
            Value::Len(x) => self.i32(i32::from(*x)),
            Value::ModWhere(s) | Value::PwPolicy(s) | Value::Extension(_, s) => self.opaque(s)?,
            Value::PwPolicySwitch(b) => self.bool(*b),
            Value::PwHist(hist) => {
                self.len(hist.len())?;
                hist.iter().try_for_each(|keys| self.keys(keys))?;
            }
        }
        Ok(())
    }

    /// `update`.
    pub fn update(&mut self, u: &Update) -> Result<(), StoreError> {
        self.opaque(&u.princ_name)?;
        self.u32(u.sno);
        self.time(u.time);
        self.len(u.values.len())?;
        u.values.iter().try_for_each(|v| self.value(v))?;
        self.bool(u.deleted);
        self.bool(u.commit);
        self.len(u.kdcs_seen_by.len())?;
        for s in &u.kdcs_seen_by {
            self.opaque(s)?;
        }
        self.opaque(&u.futures)
    }
}

/// An XDR decoder for the iprop types.
pub struct XdrReader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

fn conv(what: &str) -> StoreError {
    StoreError::corrupt(format!("malformed iprop XDR: {what}"))
}

impl<'a> XdrReader<'a> {
    /// `new`.
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    /// `remaining`.
    pub fn remaining(&self) -> usize {
        self.bytes.len() - self.pos
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], StoreError> {
        let end = self.pos.checked_add(n).ok_or_else(|| conv("length"))?;
        let b = self
            .bytes
            .get(self.pos..end)
            .ok_or_else(|| conv("truncated"))?;
        self.pos = end;
        Ok(b)
    }

    /// `u32`.
    pub fn u32(&mut self) -> Result<u32, StoreError> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// `i32`.
    pub fn i32(&mut self) -> Result<i32, StoreError> {
        Ok(self.u32()? as i32)
    }

    /// `bool`.
    pub fn bool(&mut self) -> Result<bool, StoreError> {
        Ok(self.u32()? != 0)
    }

    fn i16(&mut self) -> Result<i16, StoreError> {
        i16::try_from(self.i32()?).map_err(|_| conv("short out of range"))
    }

    fn count(&mut self) -> Result<usize, StoreError> {
        let n = usize::try_from(self.u32()?).map_err(|_| conv("count"))?;
        if n > self.remaining() / 4 {
            return Err(conv("array count exceeds data"));
        }
        Ok(n)
    }

    /// `opaque`.
    pub fn opaque(&mut self) -> Result<Vec<u8>, StoreError> {
        let n = usize::try_from(self.u32()?).map_err(|_| conv("length"))?;
        let v = self.take(n)?.to_vec();
        self.take((4 - n % 4) % 4)?;
        Ok(v)
    }

    /// `time`.
    pub fn time(&mut self) -> Result<Time, StoreError> {
        Ok(Time {
            seconds: self.u32()?,
            useconds: self.u32()?,
        })
    }

    /// `last`.
    pub fn last(&mut self) -> Result<Last, StoreError> {
        Ok(Last {
            sno: self.u32()?,
            time: self.time()?,
        })
    }

    fn key(&mut self) -> Result<Key, StoreError> {
        let ver = self.i32()?;
        let kvno = self.i32()?;
        let n = self.count()?;
        let enctypes = (0..n).map(|_| self.i32()).collect::<Result<_, _>>()?;
        let n = self.count()?;
        let contents = (0..n).map(|_| self.opaque()).collect::<Result<_, _>>()?;
        Ok(Key {
            ver,
            kvno,
            enctypes,
            contents,
        })
    }

    fn keys(&mut self) -> Result<Vec<Key>, StoreError> {
        let n = self.count()?;
        (0..n).map(|_| self.key()).collect()
    }

    fn princ(&mut self) -> Result<Princ, StoreError> {
        let realm = self.opaque()?;
        let n = self.count()?;
        let components = (0..n)
            .map(|_| Ok((self.i32()?, self.opaque()?)))
            .collect::<Result<_, StoreError>>()?;
        Ok(Princ {
            realm,
            components,
            name_type: self.i32()?,
        })
    }

    fn value(&mut self) -> Result<Value, StoreError> {
        let t = self.i32()?;
        Ok(match t {
            0 => Value::AttrFlags(self.u32()?),
            1 => Value::MaxLife(self.u32()?),
            2 => Value::MaxRenewLife(self.u32()?),
            3 => Value::Exp(self.u32()?),
            4 => Value::PwExp(self.u32()?),
            5 => Value::LastSuccess(self.u32()?),
            6 => Value::LastFailed(self.u32()?),
            7 => Value::FailAuthCount(self.u32()?),
            8 => Value::Princ(self.princ()?),
            9 => Value::KeyData(self.keys()?),
            10 => {
                let n = self.count()?;
                Value::TlData(
                    (0..n)
                        .map(|_| {
                            Ok(Tl {
                                kind: self.i16()?,
                                data: self.opaque()?,
                            })
                        })
                        .collect::<Result<_, StoreError>>()?,
                )
            }
            11 => Value::Len(self.i16()?),
            12 => Value::ModPrinc(self.princ()?),
            13 => Value::ModTime(self.u32()?),
            14 => Value::ModWhere(self.opaque()?),
            15 => Value::PwLastChange(self.u32()?),
            16 => Value::PwPolicy(self.opaque()?),
            17 => Value::PwPolicySwitch(self.bool()?),
            18 => Value::PwHistKvno(self.u32()?),
            19 => {
                let n = self.count()?;
                Value::PwHist((0..n).map(|_| self.keys()).collect::<Result<_, _>>()?)
            }
            other => Value::Extension(other, self.opaque()?),
        })
    }

    /// `update`.
    pub fn update(&mut self) -> Result<Update, StoreError> {
        let princ_name = self.opaque()?;
        let sno = self.u32()?;
        let time = self.time()?;
        let n = self.count()?;
        let values = (0..n).map(|_| self.value()).collect::<Result<_, _>>()?;
        let deleted = self.bool()?;
        let commit = self.bool()?;
        let n = self.count()?;
        let kdcs_seen_by = (0..n).map(|_| self.opaque()).collect::<Result<_, _>>()?;
        Ok(Update {
            princ_name,
            sno,
            time,
            values,
            deleted,
            commit,
            kdcs_seen_by,
            futures: self.opaque()?,
        })
    }
}

impl Update {
    /// `encode`.
    pub fn encode(&self) -> Result<Vec<u8>, StoreError> {
        let mut w = XdrWriter::default();
        w.update(self)?;
        Ok(w.0)
    }

    /// `decode`.
    pub fn decode(bytes: &[u8]) -> Result<Self, StoreError> {
        XdrReader::new(bytes).update()
    }

    /// The deletion record of `krb5_db_delete_principal` (`kdb5.c:1028-1051`).
    pub fn deletion(entry_name: Vec<u8>) -> Self {
        Self {
            princ_name: entry_name,
            deleted: true,
            ..Self::default()
        }
    }
}

fn component(c: &crate::types::KerberosString) -> &[u8] {
    c.as_ref()
}

fn ulog_princ(name: &crate::types::PrincipalName, realm: &str) -> Princ {
    Princ {
        realm: realm.as_bytes().to_vec(),
        components: name
            .name_string
            .iter()
            .map(|c| (KV5M_DATA, component(c).to_vec()))
            .collect(),
        name_type: name.name_type,
    }
}

fn tl(entry: &MitEntry, kind: u16) -> Option<&[u8]> {
    entry
        .tl_data
        .iter()
        .find(|t| t.kind == kind)
        .map(|t| t.data.as_slice())
}

/// `find_changed_attrs` with `exclude_nra` (`kdb_convert.c:46-151`),
/// including MIT's realm comparison, which reports `AT_PRINC` whenever the
/// realms are equal.
fn changed_attrs(current: &MitEntry, new: &MitEntry) -> Vec<i32> {
    let mut attrs = Vec::new();
    if current.attributes != new.attributes {
        attrs.push(0);
    }
    if current.max_life != new.max_life {
        attrs.push(1);
    }
    if current.max_renewable_life != new.max_renewable_life {
        attrs.push(2);
    }
    if current.expiration != new.expiration {
        attrs.push(3);
    }
    if current.pw_expiration != new.pw_expiration {
        attrs.push(4);
    }
    let (cp, np) = (&current.principal, &new.principal);
    let princ_changed =
        if cp.name_type == np.name_type && cp.name_string.len() == np.name_string.len() {
            if current.realm.len() == new.realm.len() && current.realm != new.realm {
                cp.name_string.iter().zip(&np.name_string).any(|(a, b)| {
                    let (a, b) = (component(a), component(b));
                    b.get(..a.len()) != Some(a)
                })
            } else {
                true
            }
        } else {
            true
        };
    if princ_changed {
        attrs.push(8);
    }
    if current.key_data.len() != new.key_data.len()
        || current
            .key_data
            .iter()
            .zip(&new.key_data)
            .any(|(a, b)| a.kvno != b.kvno)
    {
        attrs.push(9);
    }
    if current.tl_data != new.tl_data {
        attrs.push(10);
    }
    attrs
}

fn signed(v: u32) -> bool {
    (v as i32) >= 0
}

/// `ulog_conv_2logentry` (`kdb_convert.c:298-546`) plus the principal name
/// set by `krb5_db_put_principal` (`kdb5.c:980-1011`). `current` is the
/// stored entry, if any.
pub fn update_from_entry(current: Option<&MitEntry>, entry: &MitEntry) -> Update {
    let attrs = match current {
        None => (0..12).collect(),
        Some(cur) => changed_attrs(cur, entry),
    };
    let mut values = Vec::new();
    for attr in attrs {
        match attr {
            0 if signed(entry.attributes) => values.push(Value::AttrFlags(entry.attributes)),
            1 if signed(entry.max_life) => values.push(Value::MaxLife(entry.max_life)),
            2 if signed(entry.max_renewable_life) => {
                values.push(Value::MaxRenewLife(entry.max_renewable_life))
            }
            3 if signed(entry.expiration) => values.push(Value::Exp(entry.expiration)),
            4 if signed(entry.pw_expiration) => values.push(Value::PwExp(entry.pw_expiration)),
            8 if !entry.principal.name_string.is_empty() => {
                values.push(Value::Princ(ulog_princ(&entry.principal, &entry.realm)))
            }
            9 => values.push(Value::KeyData(
                entry
                    .key_data
                    .iter()
                    .map(|k| {
                        let fields = (0..usize::from(k.ver)).map(|i| {
                            k.fields
                                .get(i)
                                .map_or((0, &[][..]), |(t, d)| (*t, d.as_slice()))
                        });
                        let (enctypes, contents) =
                            fields.map(|(t, d)| (i32::from(t), d.to_vec())).unzip();
                        Key {
                            ver: i32::from(k.ver),
                            kvno: i32::from(k.kvno),
                            enctypes,
                            contents,
                        }
                    })
                    .collect(),
            )),
            10 => {
                let stamp = match tl(entry, LAST_PWD_CHANGE) {
                    Some(d) if d.len() == 4 => u32::from_le_bytes([d[0], d[1], d[2], d[3]]),
                    _ => 0,
                };
                values.push(Value::PwLastChange(stamp));
                if let Some(d) = tl(entry, MOD_PRINC) {
                    if d.len() >= 5 && d.last() == Some(&0) {
                        if let Ok((name, realm)) = parse_name(&d[4..d.len() - 1]) {
                            values.push(Value::ModPrinc(ulog_princ(&name, &realm)));
                            values
                                .push(Value::ModTime(u32::from_le_bytes([d[0], d[1], d[2], d[3]])));
                        }
                    }
                }
                let rest: Vec<Tl> = entry
                    .tl_data
                    .iter()
                    .filter(|t| t.kind != LAST_PWD_CHANGE && t.kind != MOD_PRINC)
                    .map(|t| Tl {
                        kind: t.kind as i16,
                        data: t.data.clone(),
                    })
                    .collect();
                if !rest.is_empty() {
                    values.push(Value::TlData(rest));
                }
            }
            11 => values.push(Value::Len(KRB5_KDB_V1_BASE_LENGTH)),
            _ => {}
        }
    }
    Update {
        princ_name: unparse_name(&entry.principal, &entry.realm),
        values,
        ..Update::default()
    }
}

struct Locked<'a>(&'a File);

impl<'a> Locked<'a> {
    fn new(file: &'a File, op: FlockOperation) -> Result<Self, StoreError> {
        fcntl_lock(file, op).map_err(|e| io_error("locking ulog", e.into()))?;
        Ok(Self(file))
    }
}

impl Drop for Locked<'_> {
    fn drop(&mut self) {
        let _ = fcntl_lock(self.0, FlockOperation::Unlock);
    }
}

/// Read `buf.len()` bytes at `offset`, treating bytes past the end of the
/// file as zero like MIT's mmap.
fn princ_name(p: &Princ) -> Result<(crate::types::PrincipalName, String), StoreError> {
    let name_string = p
        .components
        .iter()
        .map(|(_, c)| {
            rasn::types::GeneralString::from_bytes(c)
                .map_err(|_| StoreError::backend("invalid principal component in update"))
        })
        .collect::<Result<_, _>>()?;
    let realm = String::from_utf8(p.realm.clone())
        .map_err(|_| StoreError::backend("invalid principal realm in update"))?;
    Ok((
        crate::types::PrincipalName {
            name_type: p.name_type,
            name_string,
        },
        realm,
    ))
}

/// `krb5_db_update_tl_data` (`kdb5.c:2285-2335`): a new type is prepended.
fn set_tl(entry: &mut MitEntry, kind: u16, data: Vec<u8>) {
    match entry.tl_data.iter_mut().find(|t| t.kind == kind) {
        Some(t) => t.data = data,
        None => entry.tl_data.insert(0, TlData { kind, data }),
    }
}

/// `ulog_conv_2dbentry` (`kdb_convert.c:550-760`) on a replica: apply the
/// attributes of `upd` to the stored entry `current`, or to an empty entry
/// for an add. Lockout attributes are ignored, as on an `IPROP_REPLICA`.
pub fn entry_from_update(current: Option<MitEntry>, upd: &Update) -> Result<MitEntry, StoreError> {
    let mut entry = match current {
        Some(e) => e,
        None => {
            let (principal, realm) = parse_name(&upd.princ_name)?;
            MitEntry {
                principal,
                realm,
                attributes: 0,
                max_life: 0,
                max_renewable_life: 0,
                expiration: 0,
                pw_expiration: 0,
                last_success: 0,
                last_failed: 0,
                fail_auth_count: 0,
                tl_data: Vec::new(),
                key_data: Vec::new(),
            }
        }
    };
    let (mut mod_princ, mut mod_time) = (None, 0);
    for value in &upd.values {
        match value {
            Value::AttrFlags(v) => entry.attributes = *v,
            Value::MaxLife(v) => entry.max_life = *v,
            Value::MaxRenewLife(v) => entry.max_renewable_life = *v,
            Value::Exp(v) => entry.expiration = *v,
            Value::PwExp(v) => entry.pw_expiration = *v,
            Value::Princ(p) => (entry.principal, entry.realm) = princ_name(p)?,
            Value::KeyData(keys) => {
                entry.key_data = keys
                    .iter()
                    .map(|k| {
                        if k.ver > 2 {
                            return Err(StoreError::backend("invalid key data version in update"));
                        }
                        let n = k.ver.max(0) as usize;
                        Ok(KeyData {
                            ver: k.ver as u16,
                            kvno: k.kvno as u16,
                            fields: (0..n)
                                .map(|i| {
                                    (
                                        k.enctypes.get(i).copied().unwrap_or(0) as i16,
                                        k.contents.get(i).cloned().unwrap_or_default(),
                                    )
                                })
                                .collect(),
                        })
                    })
                    .collect::<Result<_, _>>()?;
            }
            Value::TlData(tls) => {
                for t in tls {
                    set_tl(&mut entry, t.kind as u16, t.data.clone());
                }
            }
            Value::PwLastChange(v) => set_tl(&mut entry, LAST_PWD_CHANGE, v.to_le_bytes().to_vec()),
            Value::ModPrinc(p) => mod_princ = Some(princ_name(p)?),
            Value::ModTime(v) => mod_time = *v,
            _ => {}
        }
    }
    if let (Some((name, realm)), true) = (mod_princ, mod_time != 0) {
        let mut data = mod_time.to_le_bytes().to_vec();
        data.extend_from_slice(&unparse_name(&name, &realm));
        data.push(0);
        set_tl(&mut entry, MOD_PRINC, data);
    }
    Ok(entry)
}

fn read_zero_padded(file: &File, buf: &mut [u8], offset: u64) -> Result<(), StoreError> {
    buf.fill(0);
    let mut done = 0;
    while done < buf.len() {
        match file.read_at(&mut buf[done..], offset + done as u64) {
            Ok(0) => break,
            Ok(n) => done += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(io_error("reading ulog", e)),
        }
    }
    Ok(())
}

/// Read the header of a ulog file.
pub fn read_header(file: &File) -> Result<Header, StoreError> {
    let mut b = [0; HEADER_SIZE as usize];
    read_zero_padded(file, &mut b, 0)?;
    Ok(Header::decode(&b))
}

fn entry_offset(index: u32, block: u16) -> u64 {
    HEADER_SIZE + u64::from(index) * u64::from(block)
}

/// Read entry slot `index` of a ulog with block size `block`: its header and
/// its `entry_size` bytes of XDR data.
pub fn read_entry(
    file: &File,
    block: u16,
    index: u32,
) -> Result<(EntryHeader, Vec<u8>), StoreError> {
    let mut b = vec![0; usize::from(block)];
    read_zero_padded(file, &mut b, entry_offset(index, block))?;
    let header = EntryHeader::decode(&b);
    let end = usize::try_from(header.entry_size)
        .ok()
        .and_then(|n| n.checked_add(ENTRY_DATA_OFFSET))
        .filter(|&n| n <= b.len())
        .ok_or_else(|| StoreError::corrupt("ulog entry size exceeds its block"))?;
    Ok((header, b[ENTRY_DATA_OFFSET..end].to_vec()))
}

/// A mapped update log (`kdb_log_context`).
pub struct Ulog {
    file: File,
    entries: u32,
}

impl Ulog {
    /// `ulog_map` (`kdb_log.c:500-575`).
    pub fn map(path: &Path, entries: u32) -> Result<Self, StoreError> {
        if entries == 0 {
            return Err(StoreError::backend("iprop_ulogsize must be positive"));
        }
        let exists = path.exists();
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(!exists)
            .mode(0o600)
            .open(path)
            .map_err(|e| io_error(&format!("opening ulog {}", path.display()), e))?;
        let ulog = Self { file, entries };
        if !exists {
            ulog.extend_to(HEADER_SIZE + u64::from(entries) * u64::from(ULOG_BLOCK))?;
        }
        ulog.check_on_map(path)?;
        Ok(ulog)
    }

    fn check_on_map(&self, path: &Path) -> Result<(), StoreError> {
        let ulog = self;
        let entries = self.entries;
        let _lock = Locked::new(&ulog.file, FlockOperation::LockExclusive)?;
        let mut hdr = read_header(&ulog.file)?;
        if hdr.hmagic != KDB_ULOG_HDR_MAGIC {
            if hdr.hmagic != 0 {
                return Err(StoreError::corrupt(format!(
                    "ulog {} has a corrupt header",
                    path.display()
                )));
            }
            hdr = ulog.reset()?;
        }
        if hdr.num != 0
            && (hdr.num > entries
                || !ulog.check_sno(&hdr, hdr.first_sno, hdr.first_time)?
                || !ulog.check_sno(&hdr, hdr.last_sno, hdr.last_time)?)
        {
            hdr = ulog.reset()?;
        }
        if hdr.num != entries {
            ulog.extend_to(HEADER_SIZE + u64::from(entries) * u64::from(hdr.block))?;
        }
        Ok(())
    }

    /// The `ulogentries` this log was mapped with.
    pub fn entries(&self) -> u32 {
        self.entries
    }

    fn extend_to(&self, size: u64) -> Result<(), StoreError> {
        if size > i32::MAX as u64 {
            return Err(StoreError::backend("ulog too large"));
        }
        let len = self
            .file
            .metadata()
            .map_err(|e| io_error("reading ulog size", e))?
            .len();
        if len < size {
            self.file
                .set_len(size)
                .map_err(|e| io_error("extending ulog", e))?;
        }
        Ok(())
    }

    fn write_at(&self, data: &[u8], offset: u64) -> Result<(), StoreError> {
        self.file
            .write_all_at(data, offset)
            .map_err(|e| io_error("writing ulog", e))
    }

    fn sync(&self) -> Result<(), StoreError> {
        self.file
            .sync_data()
            .map_err(|e| io_error("syncing ulog", e))
    }

    fn write_header(&self, hdr: &Header) -> Result<(), StoreError> {
        self.write_at(&hdr.encode(), 0)
    }

    fn entry_header(&self, hdr: &Header, index: u32) -> Result<EntryHeader, StoreError> {
        let mut b = [0; ENTRY_DATA_OFFSET];
        read_zero_padded(&self.file, &mut b, entry_offset(index, hdr.block))?;
        Ok(EntryHeader::decode(&b))
    }

    /// `check_sno` (`kdb_log.c:117-125`).
    fn check_sno(&self, hdr: &Header, sno: u32, time: Time) -> Result<bool, StoreError> {
        let index = sno.wrapping_sub(1) % self.entries;
        let ent = self.entry_header(hdr, index)?;
        Ok(ent.sno == sno && ent.time == time)
    }

    /// `get_sno_status` (`kdb_log.c:128-150`).
    fn sno_status(&self, hdr: &Header, last: &Last) -> Result<UpdateStatus, StoreError> {
        if last.sno == hdr.last_sno && last.time == hdr.last_time {
            return Ok(UpdateStatus::Nil);
        }
        if hdr.num == 0 || last.sno > hdr.last_sno || last.sno < hdr.first_sno {
            return Ok(UpdateStatus::FullResyncNeeded);
        }
        if !self.check_sno(hdr, last.sno, last.time)? {
            return Ok(UpdateStatus::FullResyncNeeded);
        }
        Ok(UpdateStatus::Ok)
    }

    /// `set_dummy` (`kdb_log.c:248-264`); the caller writes the header.
    fn set_dummy(&self, hdr: &mut Header, sno: u32, time: Time) -> Result<(), StoreError> {
        let index = sno.wrapping_sub(1) % self.entries;
        let mut b = [0; ENTRY_HEADER_SIZE as usize];
        b[..ENTRY_DATA_OFFSET].copy_from_slice(
            &EntryHeader {
                umagic: KDB_ULOG_MAGIC,
                sno,
                time,
                ..EntryHeader::default()
            }
            .encode(),
        );
        self.write_at(&b, entry_offset(index, hdr.block))?;
        self.sync()?;
        hdr.num = 1;
        hdr.first_sno = sno;
        hdr.last_sno = sno;
        hdr.first_time = time;
        hdr.last_time = time;
        Ok(())
    }

    /// `reset_ulog` (`kdb_log.c:267-282`).
    fn reset(&self) -> Result<Header, StoreError> {
        let mut hdr = Header {
            hmagic: KDB_ULOG_HDR_MAGIC,
            db_version_num: KDB_VERSION,
            block: ULOG_BLOCK,
            ..Header::default()
        };
        self.set_dummy(&mut hdr, 1, Time::now())?;
        hdr.state = KDB_STABLE;
        self.write_header(&hdr)?;
        self.sync()?;
        Ok(hdr)
    }

    /// `resize` (`kdb_log.c:196-244`).
    fn resize(&self, hdr: &mut Header, recsize: u32, upd: &Update) -> Result<(), StoreError> {
        let old_block = usize::from(hdr.block);
        let new_block = (recsize / u32::from(ULOG_BLOCK) + 1) * u32::from(ULOG_BLOCK);
        let new_block = u16::try_from(new_block).map_err(|_| {
            StoreError::backend(format!(
                "ulog overflow caused by principal {}",
                String::from_utf8_lossy(&upd.princ_name)
            ))
        })?;
        let new_size = HEADER_SIZE + u64::from(self.entries) * u64::from(new_block);
        if new_size > MAXLOGLEN {
            return Err(StoreError::backend("ulog would exceed its maximum size"));
        }
        self.extend_to(new_size)?;
        let mut buf = vec![0; usize::from(new_block)];
        for i in (0..self.entries).rev() {
            buf.fill(0);
            read_zero_padded(
                &self.file,
                &mut buf[..old_block],
                entry_offset(i, hdr.block),
            )?;
            self.write_at(&buf, entry_offset(i, new_block))?;
        }
        hdr.block = new_block;
        self.write_header(hdr)?;
        self.sync()
    }

    /// `store_update` (`kdb_log.c:302-358`).
    fn store_update(&self, hdr: &mut Header, upd: &Update) -> Result<(), StoreError> {
        let data = upd.encode()?;
        let upd_size =
            u32::try_from(data.len()).map_err(|_| StoreError::backend("ulog update too large"))?;
        let recsize = ENTRY_HEADER_SIZE + upd_size;
        if recsize > u32::from(hdr.block) {
            self.resize(hdr, recsize, upd)?;
        }
        hdr.state = KDB_UNSTABLE;
        self.write_header(hdr)?;
        let index = upd.sno.wrapping_sub(1) % self.entries;
        let offset = entry_offset(index, hdr.block);
        let mut block = vec![0; usize::from(hdr.block)];
        let mut ent = EntryHeader {
            umagic: KDB_ULOG_MAGIC,
            sno: upd.sno,
            time: upd.time,
            commit: false,
            entry_size: upd_size,
        };
        block[..ENTRY_DATA_OFFSET].copy_from_slice(&ent.encode());
        block[ENTRY_DATA_OFFSET..ENTRY_DATA_OFFSET + data.len()].copy_from_slice(&data);
        self.write_at(&block, offset)?;
        ent.commit = true;
        self.write_at(&ent.encode(), offset)?;
        self.sync()?;
        hdr.last_sno = upd.sno;
        hdr.last_time = upd.time;
        if hdr.num == 0 {
            hdr.num = 1;
            hdr.first_sno = upd.sno;
            hdr.first_time = upd.time;
        } else if hdr.num < self.entries {
            hdr.num += 1;
        } else {
            let first = self.entry_header(hdr, upd.sno % self.entries)?;
            hdr.first_sno = first.sno;
            hdr.first_time = first.time;
        }
        hdr.state = KDB_STABLE;
        self.write_header(hdr)?;
        self.sync()
    }

    /// `ulog_add_update` (`kdb_log.c:361-385`): assign the next serial number
    /// and the current time to `upd` and append it.
    pub fn add_update(&self, upd: &mut Update) -> Result<(), StoreError> {
        let _lock = Locked::new(&self.file, FlockOperation::LockExclusive)?;
        let mut hdr = read_header(&self.file)?;
        if hdr.last_sno == u32::MAX {
            hdr = self.reset()?;
        }
        upd.sno = hdr.last_sno + 1;
        upd.time = Time::now();
        self.store_update(&mut hdr, upd)
    }

    /// Append an update received from the primary, keeping its serial number
    /// and time (`ulog_replay`, `kdb_log.c:445-457`).
    pub fn store_replayed(&self, upd: &Update) -> Result<(), StoreError> {
        let _lock = Locked::new(&self.file, FlockOperation::LockExclusive)?;
        let mut hdr = read_header(&self.file)?;
        if hdr.num != 0 && upd.sno != hdr.last_sno.wrapping_add(1) {
            hdr = self.reset()?;
        }
        self.store_update(&mut hdr, upd)
    }

    /// `ulog_init_header` (`kdb_log.c:474-490`).
    pub fn init_header(&self) -> Result<(), StoreError> {
        let _lock = Locked::new(&self.file, FlockOperation::LockExclusive)?;
        self.reset().map(drop)
    }

    /// `ulog_get_last` (`kdb_log.c:672-688`).
    pub fn get_last(&self) -> Result<Last, StoreError> {
        let _lock = Locked::new(&self.file, FlockOperation::LockShared)?;
        let hdr = read_header(&self.file)?;
        Ok(Last {
            sno: hdr.last_sno,
            time: hdr.last_time,
        })
    }

    /// `ulog_set_last` (`kdb_log.c:691-706`).
    pub fn set_last(&self, last: Last) -> Result<(), StoreError> {
        let _lock = Locked::new(&self.file, FlockOperation::LockExclusive)?;
        let mut hdr = read_header(&self.file)?;
        self.set_dummy(&mut hdr, last.sno, last.time)?;
        self.write_header(&hdr)?;
        self.sync()
    }

    /// `ulog_get_sno_status` (`kdb_log.c:658-669`).
    pub fn get_sno_status(&self, last: &Last) -> UpdateStatus {
        let Ok(_lock) = Locked::new(&self.file, FlockOperation::LockShared) else {
            return UpdateStatus::Error;
        };
        read_header(&self.file)
            .and_then(|hdr| self.sno_status(&hdr, last))
            .unwrap_or(UpdateStatus::Error)
    }

    /// `ulog_get_entries` (`kdb_log.c:578-645`): the status, the updates
    /// after `last` and the log's last serial number and time.
    pub fn get_entries(
        &self,
        last: &Last,
    ) -> Result<(UpdateStatus, Vec<Update>, Last), StoreError> {
        let _lock = Locked::new(&self.file, FlockOperation::LockShared)?;
        let mut hdr = read_header(&self.file)?;
        if hdr.state != KDB_STABLE {
            hdr = self.reset()?;
        }
        let status = self.sno_status(&hdr, last)?;
        if status != UpdateStatus::Ok {
            return Ok((status, Vec::new(), Last::default()));
        }
        let mut updates = Vec::new();
        for sno in last.sno..hdr.last_sno {
            let (ent, data) = read_entry(&self.file, hdr.block, sno % self.entries)?;
            let mut upd = Update::decode(&data)?;
            upd.commit = ent.commit;
            updates.push(upd);
        }
        let end = Last {
            sno: hdr.last_sno,
            time: hdr.last_time,
        };
        Ok((UpdateStatus::Ok, updates, end))
    }

    /// The current header.
    pub fn header(&self) -> Result<Header, StoreError> {
        let _lock = Locked::new(&self.file, FlockOperation::LockShared)?;
        read_header(&self.file)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("ulog-test-{}-{name}", std::process::id()));
        let _ = std::fs::remove_file(&dir);
        dir
    }

    fn upd(name: &str) -> Update {
        Update {
            princ_name: name.as_bytes().to_vec(),
            values: vec![Value::AttrFlags(0x80), Value::Len(38)],
            ..Update::default()
        }
    }

    fn mit_entry(name: &[u8]) -> MitEntry {
        MitEntry {
            principal: crate::types::PrincipalName {
                name_type: 1,
                name_string: vec![rasn::types::GeneralString::from_bytes(name).expect("name")],
            },
            realm: "EXAMPLE.COM".into(),
            attributes: 0x80,
            max_life: 36000,
            max_renewable_life: 604800,
            expiration: 0,
            pw_expiration: 1_900_000_000,
            last_success: 0,
            last_failed: 0,
            fail_auth_count: 0,
            tl_data: vec![
                TlData {
                    kind: LAST_PWD_CHANGE,
                    data: 1_700_000_000u32.to_le_bytes().to_vec(),
                },
                TlData {
                    kind: MOD_PRINC,
                    data: [&1_700_000_001u32.to_le_bytes()[..], b"admin@EXAMPLE.COM\0"].concat(),
                },
                TlData {
                    kind: 0x7fff,
                    data: b"x".to_vec(),
                },
            ],
            key_data: vec![KeyData {
                ver: 2,
                kvno: 3,
                fields: vec![(18, vec![7; 34]), (3, b"salt".to_vec())],
            }],
        }
    }

    #[test]
    fn replayed_add_reproduces_the_logged_entry() {
        let mut e = mit_entry(b"alice");
        let upd = update_from_entry(None, &e);
        e.last_success = 5;
        let got = entry_from_update(None, &upd).expect("replay");
        e.last_success = 0;
        e.tl_data = vec![
            e.tl_data[1].clone(),
            e.tl_data[2].clone(),
            e.tl_data[0].clone(),
        ];
        assert_eq!(got, e);
    }

    #[test]
    fn replayed_change_keeps_unlogged_lockout_fields() {
        let old = MitEntry {
            fail_auth_count: 4,
            ..mit_entry(b"bob")
        };
        let mut new = old.clone();
        new.max_life = 7200;
        new.key_data[0].kvno = 4;
        new.tl_data[0].data = 1_700_000_100u32.to_le_bytes().to_vec();
        let upd = update_from_entry(Some(&old), &new);
        assert!(upd
            .values
            .iter()
            .all(|v| !matches!(v, Value::FailAuthCount(_))));
        let got = entry_from_update(Some(old), &upd).expect("replay");
        assert_eq!(got, new);
    }

    #[test]
    fn replay_rejects_key_data_version_above_two() {
        let upd = Update {
            princ_name: b"carol@EXAMPLE.COM".to_vec(),
            values: vec![Value::KeyData(vec![Key {
                ver: 3,
                ..Key::default()
            }])],
            ..Update::default()
        };
        assert!(entry_from_update(None, &upd).is_err());
    }

    #[test]
    fn update_xdr_round_trips_every_attribute_kind() {
        let p = Princ {
            realm: b"EX.COM".to_vec(),
            components: vec![(KV5M_DATA, b"host".to_vec()), (KV5M_DATA, b"a".to_vec())],
            name_type: 1,
        };
        let key = Key {
            ver: 2,
            kvno: 3,
            enctypes: vec![18, 3],
            contents: vec![vec![1; 34], b"salt".to_vec()],
        };
        let u = Update {
            princ_name: b"host/a@EX.COM".to_vec(),
            sno: 7,
            time: Time {
                seconds: 9,
                useconds: 10,
            },
            values: vec![
                Value::MaxLife(1),
                Value::Princ(p.clone()),
                Value::KeyData(vec![key.clone()]),
                Value::TlData(vec![Tl {
                    kind: 3,
                    data: vec![1, 2, 3],
                }]),
                Value::Len(38),
                Value::ModPrinc(p),
                Value::PwPolicySwitch(true),
                Value::PwHist(vec![vec![key]]),
                Value::Extension(42, vec![9]),
            ],
            deleted: false,
            commit: true,
            kdcs_seen_by: vec![b"r".to_vec()],
            futures: vec![],
        };
        let bytes = u.encode().expect("encode");
        assert_eq!(bytes.len() % 4, 0);
        assert_eq!(&bytes[..4], &13u32.to_be_bytes());
        assert_eq!(Update::decode(&bytes).expect("decode"), u);
        assert!(Update::decode(&bytes[..bytes.len() - 4]).is_err());
    }

    #[test]
    fn header_layout_matches_kdb_hlog_t() {
        let h = Header {
            hmagic: KDB_ULOG_HDR_MAGIC,
            db_version_num: 1,
            num: 2,
            first_time: Time {
                seconds: 3,
                useconds: 4,
            },
            last_time: Time {
                seconds: 5,
                useconds: 6,
            },
            first_sno: 7,
            last_sno: 8,
            state: KDB_STABLE,
            block: ULOG_BLOCK,
        };
        let b = h.encode();
        assert_eq!(&b[0..4], &KDB_ULOG_HDR_MAGIC.to_ne_bytes());
        assert_eq!(&b[32..36], &8u32.to_ne_bytes());
        assert_eq!(&b[38..40], &ULOG_BLOCK.to_ne_bytes());
        assert_eq!(Header::decode(&b), h);
    }

    #[test]
    fn map_creates_a_stable_log_with_a_dummy_entry() {
        let path = tmp("create");
        let log = Ulog::map(&path, 4).expect("map");
        let len = std::fs::metadata(&path).expect("stat").len();
        assert_eq!(len, HEADER_SIZE + 4 * u64::from(ULOG_BLOCK));
        let h = log.header().expect("header");
        assert_eq!(
            (h.hmagic, h.state, h.num, h.first_sno, h.last_sno),
            (KDB_ULOG_HDR_MAGIC, KDB_STABLE, 1, 1, 1)
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn serial_numbers_wrap_around_the_ring() {
        let path = tmp("ring");
        let log = Ulog::map(&path, 3).expect("map");
        for i in 0..5 {
            let mut u = upd(&format!("p{i}@EX.COM"));
            log.add_update(&mut u).expect("add");
            assert_eq!(u.sno, i + 2);
        }
        let h = log.header().expect("header");
        assert_eq!((h.num, h.first_sno, h.last_sno), (3, 4, 6));
        let first = Last {
            sno: 4,
            time: h.first_time,
        };
        let (status, updates, end) = log.get_entries(&first).expect("entries");
        assert_eq!(status, UpdateStatus::Ok);
        let names: Vec<_> = updates.iter().map(|u| u.princ_name.clone()).collect();
        assert_eq!(names, vec![b"p3@EX.COM".to_vec(), b"p4@EX.COM".to_vec()]);
        assert!(updates.iter().all(|u| u.commit));
        assert_eq!(end.sno, 6);
        assert_eq!(log.get_sno_status(&end), UpdateStatus::Nil);
        let stale = Last {
            sno: 2,
            time: h.first_time,
        };
        assert_eq!(log.get_sno_status(&stale), UpdateStatus::FullResyncNeeded);
        let wrong_time = Last {
            sno: 5,
            time: Time::default(),
        };
        assert_eq!(
            log.get_sno_status(&wrong_time),
            UpdateStatus::FullResyncNeeded
        );
        drop(log);
        let reopened = Ulog::map(&path, 3).expect("remap");
        assert_eq!(reopened.header().expect("header").last_sno, 6);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn large_updates_grow_the_block_and_keep_older_entries() {
        let path = tmp("resize");
        let log = Ulog::map(&path, 2).expect("map");
        let mut small = upd("small@EX.COM");
        log.add_update(&mut small).expect("add");
        let mut big = upd("big@EX.COM");
        big.values.push(Value::TlData(vec![Tl {
            kind: 3,
            data: vec![7; 3000],
        }]));
        log.add_update(&mut big).expect("add big");
        let h = log.header().expect("header");
        assert_eq!(h.block, 4096);
        let (_, data) = read_entry(&log.file, h.block, 1).expect("entry");
        assert_eq!(
            Update::decode(&data).expect("decode").princ_name,
            b"small@EX.COM"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn set_last_and_init_header_reset_the_log() {
        let path = tmp("last");
        let log = Ulog::map(&path, 5).expect("map");
        let last = Last {
            sno: 41,
            time: Time {
                seconds: 1,
                useconds: 2,
            },
        };
        log.set_last(last).expect("set last");
        assert_eq!(log.get_last().expect("last"), last);
        assert_eq!(log.get_sno_status(&last), UpdateStatus::Nil);
        let mut u = upd("x@EX.COM");
        log.add_update(&mut u).expect("add");
        assert_eq!(u.sno, 42);
        log.init_header().expect("reset");
        let h = log.header().expect("header");
        assert_eq!((h.num, h.last_sno), (1, 1));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn a_nonzero_bad_header_magic_is_corrupt() {
        let path = tmp("corrupt");
        std::fs::write(&path, [1u8; 64]).expect("write");
        assert!(Ulog::map(&path, 2).is_err());
        let _ = std::fs::remove_file(&path);
    }
}
