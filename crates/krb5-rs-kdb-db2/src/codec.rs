//! MIT db2 record formats: principals as `krb5_encode_princ_entry`
//! (`plugins/kdb/db2/kdb_xdr.c`) and policies as XDR
//! `osa_policy_ent_rec` (`plugins/kdb/db2/pol_xdr.c`).

use krb5_rs::kdc::kdb::mit::{parse_name, unparse_name, KeyData, MitEntry, MitPolicy, TlData};
use krb5_rs::kdc::StoreError;

/// `KRB5_KDB_V1_BASE_LENGTH`.
pub const BASE_LENGTH: u16 = 38;
/// `KRB5_KDB_V1_KEY_DATA_ARRAY`.
const KEY_DATA_ARRAY: u16 = 2;
pub const POLICY_VERSION_1: u32 = 0x12345D01;
pub const POLICY_VERSION_2: u32 = 0x12345D02;
pub const POLICY_VERSION_3: u32 = 0x12345D03;

fn truncated() -> StoreError {
    StoreError::backend("db2: truncated principal record (KRB5_KDB_TRUNCATED_RECORD)")
}

fn bad_policy() -> StoreError {
    StoreError::backend("db2: corrupt policy record")
}

/// A database key: the unparsed name and its NUL.
pub fn principal_key(principal: &krb5_rs::types::PrincipalName, realm: &str) -> Vec<u8> {
    let mut key = unparse_name(principal, realm);
    key.push(0);
    key
}

/// A policy database key: the name and its NUL.
pub fn policy_key(name: &str) -> Vec<u8> {
    let mut key = name.as_bytes().to_vec();
    key.push(0);
    key
}

struct Le<'a> {
    b: &'a [u8],
    at: usize,
}

impl<'a> Le<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], StoreError> {
        let end = self.at.checked_add(n).ok_or_else(truncated)?;
        let s = self.b.get(self.at..end).ok_or_else(truncated)?;
        self.at = end;
        Ok(s)
    }
    fn u16(&mut self) -> Result<u16, StoreError> {
        let s = self.take(2)?;
        Ok(u16::from_le_bytes([s[0], s[1]]))
    }
    fn u32(&mut self) -> Result<u32, StoreError> {
        let s = self.take(4)?;
        Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
    }
}

/// `krb5_decode_princ_entry`. Extra base data (`e_data`) is skipped; MIT
/// never writes any.
pub fn decode_entry(value: &[u8]) -> Result<MitEntry, StoreError> {
    if value.len() < BASE_LENGTH as usize {
        return Err(truncated());
    }
    let mut r = Le { b: value, at: 0 };
    let len = r.u16()?;
    let attributes = r.u32()?;
    let max_life = r.u32()?;
    let max_renewable_life = r.u32()?;
    let expiration = r.u32()?;
    let pw_expiration = r.u32()?;
    let last_success = r.u32()?;
    let last_failed = r.u32()?;
    let fail_auth_count = r.u32()?;
    let n_tl = r.u16()? as i16;
    let n_key = r.u16()? as i16;
    if n_tl < 0 || n_key < 0 {
        return Err(truncated());
    }
    if len > BASE_LENGTH {
        r.take((len - BASE_LENGTH) as usize)?;
    }
    let psize = r.u16()? as i16;
    if psize <= 0 {
        return Err(truncated());
    }
    let name = r.take(psize as usize)?;
    if name[name.len() - 1] != 0 || name[..name.len() - 1].contains(&0) {
        return Err(truncated());
    }
    let (principal, realm) = parse_name(&name[..name.len() - 1])?;
    let mut tl_data = Vec::with_capacity(n_tl as usize);
    for _ in 0..n_tl {
        let kind = r.u16()?;
        let n = r.u16()? as usize;
        tl_data.push(TlData {
            kind,
            data: r.take(n)?.to_vec(),
        });
    }
    let mut key_data = Vec::with_capacity(n_key as usize);
    for _ in 0..n_key {
        let ver = r.u16()?;
        let kvno = r.u16()?;
        if ver as i16 > KEY_DATA_ARRAY as i16 || (ver as i16) < 0 {
            return Err(StoreError::backend(
                "db2: bad key-data version (KRB5_KDB_BAD_VERSION)",
            ));
        }
        let mut fields = Vec::with_capacity(ver as usize);
        for _ in 0..ver {
            let kind = r.u16()? as i16;
            let n = r.u16()? as usize;
            fields.push((kind, r.take(n)?.to_vec()));
        }
        key_data.push(KeyData { ver, kvno, fields });
    }
    Ok(MitEntry {
        principal,
        realm,
        attributes,
        max_life,
        max_renewable_life,
        expiration,
        pw_expiration,
        last_success,
        last_failed,
        fail_auth_count,
        tl_data,
        key_data,
    })
}

/// `krb5_encode_princ_entry` and the entry's key.
pub fn encode_entry(entry: &MitEntry) -> Result<(Vec<u8>, Vec<u8>), StoreError> {
    let too_big = || StoreError::backend("db2: principal record field too large");
    let key = principal_key(&entry.principal, &entry.realm);
    let mut w = Vec::with_capacity(64 + key.len());
    w.extend_from_slice(&BASE_LENGTH.to_le_bytes());
    for v in [
        entry.attributes,
        entry.max_life,
        entry.max_renewable_life,
        entry.expiration,
        entry.pw_expiration,
        entry.last_success,
        entry.last_failed,
        entry.fail_auth_count,
    ] {
        w.extend_from_slice(&v.to_le_bytes());
    }
    let n_tl = i16::try_from(entry.tl_data.len()).map_err(|_| too_big())?;
    let n_key = i16::try_from(entry.key_data.len()).map_err(|_| too_big())?;
    w.extend_from_slice(&(n_tl as u16).to_le_bytes());
    w.extend_from_slice(&(n_key as u16).to_le_bytes());
    let psize = i16::try_from(key.len()).map_err(|_| too_big())?;
    w.extend_from_slice(&(psize as u16).to_le_bytes());
    w.extend_from_slice(&key);
    for tl in &entry.tl_data {
        let n = u16::try_from(tl.data.len()).map_err(|_| too_big())?;
        w.extend_from_slice(&tl.kind.to_le_bytes());
        w.extend_from_slice(&n.to_le_bytes());
        w.extend_from_slice(&tl.data);
    }
    for kd in &entry.key_data {
        if kd.ver as usize > kd.fields.len() || kd.ver > KEY_DATA_ARRAY {
            return Err(StoreError::backend("db2: bad key-data version"));
        }
        w.extend_from_slice(&kd.ver.to_le_bytes());
        w.extend_from_slice(&kd.kvno.to_le_bytes());
        for (kind, data) in kd.fields.iter().take(kd.ver as usize) {
            let n = u16::try_from(data.len()).map_err(|_| too_big())?;
            w.extend_from_slice(&kind.to_le_bytes());
            w.extend_from_slice(&n.to_le_bytes());
            w.extend_from_slice(data);
        }
    }
    Ok((key, w))
}

/// The entry with its first key-data contents zeroed, as
/// `krb5_db2_delete_principal` writes it before deleting the record.
pub fn zeroed_keys(mut entry: MitEntry) -> MitEntry {
    for kd in &mut entry.key_data {
        if let Some((_, data)) = kd.fields.first_mut() {
            data.iter_mut().for_each(|b| *b = 0);
        }
    }
    entry
}

struct Xdr<'a> {
    b: &'a [u8],
    at: usize,
}

impl<'a> Xdr<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], StoreError> {
        let padded = n.checked_add(3).ok_or_else(bad_policy)? & !3;
        let end = self.at.checked_add(padded).ok_or_else(bad_policy)?;
        if end > self.b.len() {
            return Err(bad_policy());
        }
        let s = &self.b[self.at..self.at + n];
        self.at = end;
        Ok(s)
    }
    fn u32(&mut self) -> Result<u32, StoreError> {
        let s = self.take(4)?;
        Ok(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
    }
    fn bool(&mut self) -> Result<bool, StoreError> {
        match self.u32()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(bad_policy()),
        }
    }
    fn nullstring(&mut self) -> Result<Option<String>, StoreError> {
        let size = self.u32()? as usize;
        if size == 0 {
            return Ok(None);
        }
        let s = self.take(size)?;
        if s[size - 1] != 0 || s[..size - 1].contains(&0) {
            return Err(bad_policy());
        }
        String::from_utf8(s[..size - 1].to_vec())
            .map(Some)
            .map_err(|_| bad_policy())
    }
}

fn put_u32(w: &mut Vec<u8>, v: u32) {
    w.extend_from_slice(&v.to_be_bytes());
}

fn put_opaque(w: &mut Vec<u8>, b: &[u8]) {
    w.extend_from_slice(b);
    w.resize(w.len() + ((4 - b.len() % 4) % 4), 0);
}

fn put_nullstring(w: &mut Vec<u8>, s: Option<&str>) {
    match s {
        None => put_u32(w, 0),
        Some(s) => {
            put_u32(w, s.len() as u32 + 1);
            let mut b = s.as_bytes().to_vec();
            b.push(0);
            put_opaque(w, &b);
        }
    }
}

/// `osa_policy_min_vers`.
pub fn policy_version(p: &MitPolicy) -> u32 {
    if p.attributes != 0
        || p.max_life != 0
        || p.max_renewable_life != 0
        || p.allowed_keysalts.is_some()
        || !p.tl_data.is_empty()
    {
        POLICY_VERSION_3
    } else if p.pw_max_fail != 0 || p.pw_failcnt_interval != 0 || p.pw_lockout_duration != 0 {
        POLICY_VERSION_2
    } else {
        POLICY_VERSION_1
    }
}

/// XDR-decode `osa_policy_ent_rec`.
pub fn decode_policy(value: &[u8]) -> Result<MitPolicy, StoreError> {
    let mut r = Xdr { b: value, at: 0 };
    let version = r.u32()?;
    if !(POLICY_VERSION_1..=POLICY_VERSION_3).contains(&version) {
        return Err(bad_policy());
    }
    let name = r.nullstring()?.unwrap_or_default();
    let pw_min_life = r.u32()?;
    let pw_max_life = r.u32()?;
    let pw_min_length = r.u32()?;
    let pw_min_classes = r.u32()?;
    let pw_history_num = r.u32()?;
    let _policy_refcnt = r.u32()?;
    let mut p = MitPolicy {
        name,
        pw_min_life,
        pw_max_life,
        pw_min_length,
        pw_min_classes,
        pw_history_num,
        pw_max_fail: 0,
        pw_failcnt_interval: 0,
        pw_lockout_duration: 0,
        attributes: 0,
        max_life: 0,
        max_renewable_life: 0,
        allowed_keysalts: None,
        tl_data: Vec::new(),
    };
    if version > POLICY_VERSION_1 {
        p.pw_max_fail = r.u32()?;
        p.pw_failcnt_interval = r.u32()?;
        p.pw_lockout_duration = r.u32()?;
    }
    if version > POLICY_VERSION_2 {
        p.attributes = r.u32()?;
        p.max_life = r.u32()?;
        p.max_renewable_life = r.u32()?;
        p.allowed_keysalts = r.nullstring()?;
        let _n_tl_data = r.u32()?;
        if !r.bool()? {
            // xdr_krb5_tl_data prepends, so the list comes back reversed.
            while r.bool()? {
                let kind = r.u32()? as u16;
                let n = r.u32()? as usize;
                let data = r.take(n)?.to_vec();
                p.tl_data.insert(0, TlData { kind, data });
            }
        }
    }
    Ok(p)
}

/// XDR-encode `osa_policy_ent_rec`, as `osa_adb_put_policy` stores it.
pub fn encode_policy(p: &MitPolicy) -> Result<Vec<u8>, StoreError> {
    let mut w = Vec::with_capacity(128);
    let version = policy_version(p);
    put_u32(&mut w, version);
    put_nullstring(&mut w, Some(&p.name));
    for v in [
        p.pw_min_life,
        p.pw_max_life,
        p.pw_min_length,
        p.pw_min_classes,
        p.pw_history_num,
        0,
    ] {
        put_u32(&mut w, v);
    }
    if version > POLICY_VERSION_1 {
        for v in [p.pw_max_fail, p.pw_failcnt_interval, p.pw_lockout_duration] {
            put_u32(&mut w, v);
        }
    }
    if version > POLICY_VERSION_2 {
        for v in [p.attributes, p.max_life, p.max_renewable_life] {
            put_u32(&mut w, v);
        }
        put_nullstring(&mut w, p.allowed_keysalts.as_deref());
        let n = i16::try_from(p.tl_data.len())
            .map_err(|_| StoreError::backend("db2: too many policy tl-data items"))?;
        put_u32(&mut w, n as i32 as u32);
        put_u32(&mut w, u32::from(p.tl_data.is_empty()));
        if !p.tl_data.is_empty() {
            for tl in &p.tl_data {
                put_u32(&mut w, 1);
                put_u32(&mut w, tl.kind as i16 as i32 as u32);
                put_u32(&mut w, tl.data.len() as u32);
                put_opaque(&mut w, &tl.data);
            }
            put_u32(&mut w, 0);
        }
    }
    Ok(w)
}
