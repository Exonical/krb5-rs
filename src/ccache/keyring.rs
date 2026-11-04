//! KEYRING ccaches (cc_keyring.c): Linux kernel keyrings.
//!
//! A residual is `anchor:collection[:subsidiary]`, or a bare name for the
//! legacy anchor. The collection keyring `_krb_<collection>` under the
//! anchor holds one keyring per cache and a `krb_ccache:primary` key naming
//! the primary cache. Each cache keyring holds `__krb5_princ__`, optionally
//! `__krb5_time_offsets__`, and one key per credential, all in the FILE v4
//! format.

use std::cell::Cell;
use std::io;

use super::marshal::{marshal_cred, marshal_princ, unmarshal_cred, unmarshal_princ};
use super::retrieve::retrieve_in;
use super::{
    config_cred, config_matches, unparse_name, CcCredential, CcError, Ccache, MatchCred,
    MatchFlags, CONFIG_REALM,
};
use crate::types::PrincipalName;
use sys::Serial;

fn arr4(s: &[u8]) -> [u8; 4] {
    let mut a = [0; 4];
    a.copy_from_slice(&s[..4]);
    a
}

const COLLECTION_PRIMARY: &str = "krb_ccache:primary";
const PRINC_KEYNAME: &str = "__krb5_princ__";
const TIME_OFFSETS: &str = "__krb5_time_offsets__";
const COLLECTION_VERSION: u32 = 1;
const PERSISTENT_KEYRING_NAME: &str = "_krb";
const CCCOL_PREFIX: &str = "_krb_";
const DEFAULT_UNIQUE_COLLECTION: &str = "session:__krb5_unique__";
const NAME_PREFIX: &str = "krb_ccache_";
const NAME_RAND_CHARS: usize = 8;
const LEGACY_ANCHOR: &str = "legacy";
const KEY_TYPE_USER: &str = "user";
const KEY_TYPE_KEYRING: &str = "keyring";
const CRED_KEY_TYPE: &str = "big_key";

#[allow(unsafe_code)]
mod sys {
    use std::ffi::CString;
    use std::io;

    pub type Serial = i32;

    pub const THREAD: Serial = -1;
    pub const PROCESS: Serial = -2;
    pub const SESSION: Serial = -3;
    pub const USER: Serial = -4;
    pub const USER_SESSION: Serial = -5;

    const GET_KEYRING_ID: libc::c_ulong = 0;
    const DESCRIBE: libc::c_ulong = 6;
    const CLEAR: libc::c_ulong = 7;
    const LINK: libc::c_ulong = 8;
    const UNLINK: libc::c_ulong = 9;
    const SEARCH: libc::c_ulong = 10;
    const READ: libc::c_ulong = 11;
    const SET_TIMEOUT: libc::c_ulong = 15;
    const GET_PERSISTENT: libc::c_ulong = 22;

    fn cstr(s: &str) -> io::Result<CString> {
        CString::new(s).map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))
    }

    fn keyctl(op: libc::c_ulong, a: [libc::c_ulong; 4]) -> io::Result<libc::c_long> {
        // SAFETY: keyctl with integer arguments, or pointers valid for the
        // call that the callers pass in `a`.
        let r = unsafe { libc::syscall(libc::SYS_keyctl, op, a[0], a[1], a[2], a[3]) };
        if r == -1 {
            Err(io::Error::last_os_error())
        } else {
            Ok(r)
        }
    }

    fn id(k: Serial) -> libc::c_ulong {
        k as libc::c_long as libc::c_ulong
    }

    pub fn add_key(
        ty: &str,
        desc: &str,
        payload: Option<&[u8]>,
        ring: Serial,
    ) -> io::Result<Serial> {
        let (ty, desc) = (cstr(ty)?, cstr(desc)?);
        let (ptr, len) = payload.map_or((std::ptr::null(), 0), |p| (p.as_ptr(), p.len()));
        // SAFETY: NUL-terminated strings and a payload buffer valid for the call.
        let r = unsafe {
            libc::syscall(
                libc::SYS_add_key,
                ty.as_ptr(),
                desc.as_ptr(),
                ptr,
                len,
                id(ring),
            )
        };
        if r == -1 {
            Err(io::Error::last_os_error())
        } else {
            Ok(r as Serial)
        }
    }

    pub fn search(ring: Serial, ty: &str, desc: &str, dest: Serial) -> io::Result<Serial> {
        let (ty, desc) = (cstr(ty)?, cstr(desc)?);
        keyctl(
            SEARCH,
            [
                id(ring),
                ty.as_ptr() as libc::c_ulong,
                desc.as_ptr() as libc::c_ulong,
                id(dest),
            ],
        )
        .map(|r| r as Serial)
    }

    fn read_buf(op: libc::c_ulong, key: Serial) -> io::Result<Vec<u8>> {
        let mut buf = Vec::new();
        loop {
            let n = keyctl(
                op,
                [
                    id(key),
                    buf.as_mut_ptr() as libc::c_ulong,
                    buf.len() as _,
                    0,
                ],
            )? as usize;
            if n <= buf.len() {
                buf.truncate(n);
                return Ok(buf);
            }
            buf.resize(n, 0);
        }
    }

    pub fn read(key: Serial) -> io::Result<Vec<u8>> {
        read_buf(READ, key)
    }

    pub fn describe(key: Serial) -> io::Result<String> {
        let mut d = read_buf(DESCRIBE, key)?;
        if d.last() == Some(&0) {
            d.pop();
        }
        Ok(String::from_utf8_lossy(&d).into_owned())
    }

    pub fn link(key: Serial, ring: Serial) -> io::Result<()> {
        keyctl(LINK, [id(key), id(ring), 0, 0]).map(drop)
    }

    pub fn unlink(key: Serial, ring: Serial) -> io::Result<()> {
        keyctl(UNLINK, [id(key), id(ring), 0, 0]).map(drop)
    }

    pub fn clear(ring: Serial) -> io::Result<()> {
        keyctl(CLEAR, [id(ring), 0, 0, 0]).map(drop)
    }

    pub fn set_timeout(key: Serial, secs: u32) -> io::Result<()> {
        keyctl(SET_TIMEOUT, [id(key), secs.into(), 0, 0]).map(drop)
    }

    pub fn get_keyring_id(spec: Serial) -> io::Result<Serial> {
        keyctl(GET_KEYRING_ID, [id(spec), 0, 0, 0]).map(|r| r as Serial)
    }

    pub fn get_persistent(uid: libc::uid_t, dest: Serial) -> io::Result<Serial> {
        keyctl(GET_PERSISTENT, [uid.into(), id(dest), 0, 0]).map(|r| r as Serial)
    }

    pub fn geteuid() -> libc::uid_t {
        // SAFETY: geteuid has no preconditions.
        unsafe { libc::geteuid() }
    }
}

fn errno(e: io::Error) -> CcError {
    CcError::Io(e)
}

fn no_key(e: &io::Error) -> bool {
    matches!(
        e.raw_os_error(),
        Some(libc::ENOKEY | libc::EKEYEXPIRED | libc::EKEYREVOKED)
    )
}

/// keyctl_search, with "not found" as `None`.
fn search(ring: Serial, ty: &str, desc: &str) -> Option<Serial> {
    sys::search(ring, ty, desc, 0).ok()
}

/// `parse_residual`.
fn parse_residual(residual: &str) -> (String, String, Option<String>) {
    let (anchor, rest) = match residual.split_once(':') {
        Some((a, r)) => (a.to_string(), r),
        None => (LEGACY_ANCHOR.to_string(), residual),
    };
    match rest.split_once(':') {
        Some((c, s)) => (anchor, c.to_string(), Some(s.to_string())),
        None => (anchor, rest.to_string(), None),
    }
}

/// `is_legacy_cache_name`: `legacy:X:X`.
fn is_legacy_cache_name(residual: &str) -> bool {
    let mut it = residual.splitn(3, ':');
    matches!((it.next(), it.next(), it.next()), (Some(LEGACY_ANCHOR), Some(c), Some(s)) if c == s)
}

/// `session_write_anchor`.
fn session_write_anchor() -> Serial {
    let s = sys::get_keyring_id(sys::SESSION);
    let u = sys::get_keyring_id(sys::USER_SESSION);
    match (s, u) {
        (Ok(s), Ok(u)) if s == u => sys::USER_SESSION,
        _ => sys::SESSION,
    }
}

/// `find_or_create_keyring`.
fn find_or_create_keyring(parent: Serial, possess: Serial, name: &str) -> Result<Serial, CcError> {
    if let Ok(k) = sys::search(parent, KEY_TYPE_KEYRING, name, possess) {
        return Ok(k);
    }
    if possess != 0 {
        let k = sys::add_key(KEY_TYPE_KEYRING, name, None, possess).map_err(errno)?;
        sys::link(k, parent).map_err(errno)?;
        Ok(k)
    } else {
        sys::add_key(KEY_TYPE_KEYRING, name, None, parent).map_err(errno)
    }
}

fn invalid_uid() -> CcError {
    CcError::code(
        "KRB5_KCC_INVALID_UID",
        "Invalid UID in persistent keyring name",
    )
}

/// `get_collection`.
fn get_collection(anchor: &str, collection: &str) -> Result<Serial, CcError> {
    if anchor == "persistent" {
        let uid = if collection.is_empty() {
            sys::geteuid()
        } else {
            collection
                .parse::<libc::uid_t>()
                .map_err(|_| invalid_uid())?
        };
        let persistent = match sys::get_persistent(uid, sys::PROCESS) {
            Ok(k) => k,
            Err(e) if e.raw_os_error() == Some(libc::EOPNOTSUPP) && uid == sys::geteuid() => {
                sys::USER
            }
            Err(_) => return Err(invalid_uid()),
        };
        return find_or_create_keyring(persistent, sys::PROCESS, PERSISTENT_KEYRING_NAME);
    }
    let (anchor_id, possess) = match anchor {
        "process" => (sys::PROCESS, 0),
        "thread" => (sys::THREAD, 0),
        "session" | LEGACY_ANCHOR => (session_write_anchor(), 0),
        // The user keyring does not confer possession; link through the
        // process keyring.
        "user" => (sys::USER, sys::PROCESS),
        _ => {
            return Err(CcError::code(
                "KRB5_KCC_INVALID_ANCHOR",
                "Invalid keyring anchor name",
            ))
        }
    };
    find_or_create_keyring(anchor_id, possess, &format!("{CCCOL_PREFIX}{collection}"))
}

/// `set_primary_name`.
fn set_primary_name(collection_id: Serial, subsidiary: &str) -> Result<(), CcError> {
    let mut payload = Vec::with_capacity(8 + subsidiary.len());
    payload.extend_from_slice(&COLLECTION_VERSION.to_be_bytes());
    payload.extend_from_slice(&(subsidiary.len() as u32).to_be_bytes());
    payload.extend_from_slice(subsidiary.as_bytes());
    sys::add_key(
        KEY_TYPE_USER,
        COLLECTION_PRIMARY,
        Some(&payload),
        collection_id,
    )
    .map(drop)
    .map_err(errno)
}

/// `get_primary_name`.
fn get_primary_name(
    anchor: &str,
    collection: &str,
    collection_id: Serial,
) -> Result<String, CcError> {
    let Some(primary_id) = search(collection_id, KEY_TYPE_USER, COLLECTION_PRIMARY) else {
        let name = if collection.is_empty() {
            "tkt"
        } else {
            collection
        };
        set_primary_name(collection_id, name)?;
        if anchor == LEGACY_ANCHOR {
            // Adopt a cache made by code predating collections.
            if let Some(legacy) = search(sys::SESSION, KEY_TYPE_KEYRING, name) {
                sys::link(legacy, collection_id).map_err(errno)?;
            }
        }
        return Ok(name.to_string());
    };
    let payload = sys::read(primary_id).map_err(errno)?;
    if payload.len() < 8 {
        return Err(CcError::End);
    }
    let version = u32::from_be_bytes(arr4(&payload[0..4]));
    let len = u32::from_be_bytes(arr4(&payload[4..8])) as usize;
    if len > payload.len() - 8 {
        return Err(CcError::End);
    }
    if version != COLLECTION_VERSION {
        return Err(CcError::code(
            "KRB5_KCC_UNKNOWN_VERSION",
            "Unknown keyring collection version",
        ));
    }
    Ok(String::from_utf8_lossy(&payload[8..8 + len]).into_owned())
}

/// A KEYRING cache.
pub struct KeyringCcache {
    /// `anchor:collection:subsidiary`.
    name: String,
    collection_id: Serial,
    cache_id: Serial,
    princ_id: Serial,
    legacy_type: bool,
    time_offset: Cell<Option<(i32, i32)>>,
}

impl KeyringCcache {
    fn make(
        anchor: &str,
        collection: &str,
        subsidiary: &str,
        collection_id: Serial,
        cache_id: Serial,
    ) -> Self {
        let princ_id = if cache_id != 0 {
            search(cache_id, KEY_TYPE_USER, PRINC_KEYNAME).unwrap_or(0)
        } else {
            0
        };
        Self {
            name: format!("{anchor}:{collection}:{subsidiary}"),
            collection_id,
            cache_id,
            princ_id,
            legacy_type: anchor == LEGACY_ANCHOR,
            time_offset: Cell::new(None),
        }
    }

    /// `krcc_resolve`. The cache keyring need not exist yet.
    pub fn resolve(residual: &str) -> Result<Self, CcError> {
        let (anchor, collection, subsidiary) = parse_residual(residual);
        let collection_id = get_collection(&anchor, &collection)?;
        let subsidiary = match subsidiary {
            Some(s) => s,
            None => get_primary_name(&anchor, &collection, collection_id)?,
        };
        let cache_id = search(collection_id, KEY_TYPE_KEYRING, &subsidiary).unwrap_or(0);
        Ok(Self::make(
            &anchor,
            &collection,
            &subsidiary,
            collection_id,
            cache_id,
        ))
    }

    /// `krcc_generate_new`: a new cache in the default collection, or in
    /// `session:__krb5_unique__` when the default isn't a KEYRING name.
    pub fn gen_new(default_name: Option<&str>) -> Result<Self, CcError> {
        let residual = default_name
            .and_then(|d| d.strip_prefix("KEYRING:"))
            .unwrap_or(DEFAULT_UNIQUE_COLLECTION);
        let (anchor, collection, subsidiary) = parse_residual(residual);
        if subsidiary.is_some() {
            return Err(CcError::CannotCreate(
                "Can't create new subsidiary cache because default cache is already a subsidiary"
                    .into(),
            ));
        }
        let collection_id = get_collection(&anchor, &collection)?;
        for _ in 0..100 {
            let name = format!(
                "{NAME_PREFIX}{}",
                super::dir::random_string(NAME_RAND_CHARS)
            );
            if search(collection_id, KEY_TYPE_KEYRING, &name).is_none() {
                let cache_id =
                    sys::add_key(KEY_TYPE_KEYRING, &name, None, collection_id).map_err(errno)?;
                return Ok(Self::make(
                    &anchor,
                    &collection,
                    &name,
                    collection_id,
                    cache_id,
                ));
            }
        }
        Err(CcError::BadName("Credential cache name malformed".into()))
    }

    /// The full name, `KEYRING:anchor:collection:subsidiary`.
    pub fn name(&self) -> String {
        format!("KEYRING:{}", self.name)
    }

    /// The KDC time offset to save at `initialize` (seconds, microseconds).
    pub fn set_time_offset(&mut self, secs: i32, usecs: i32) {
        self.time_offset.set(Some((secs, usecs)));
    }

    /// `get_time_offsets`: the saved KDC time offset.
    pub fn time_offset(&self) -> Option<(i32, i32)> {
        if self.cache_id == 0 {
            return None;
        }
        let key = search(self.cache_id, KEY_TYPE_USER, TIME_OFFSETS)?;
        let p = sys::read(key).ok()?;
        if p.len() < 8 {
            return None;
        }
        Some((
            i32::from_be_bytes(arr4(&p[0..4])),
            i32::from_be_bytes(arr4(&p[4..8])),
        ))
    }

    fn not_found(&self) -> CcError {
        CcError::NoFile(format!(
            "Credentials cache keyring '{}' not found",
            self.name
        ))
    }

    /// `clear_cache_keyring`.
    fn clear(&mut self) -> Result<(), CcError> {
        if self.cache_id != 0 {
            sys::clear(self.cache_id).map_err(errno)?;
        }
        self.princ_id = 0;
        Ok(())
    }

    /// `krcc_destroy`.
    pub fn destroy(mut self) -> Result<(), CcError> {
        let _ = self.clear();
        if self.cache_id != 0 {
            sys::unlink(self.cache_id, self.collection_id).map_err(errno)?;
            if is_legacy_cache_name(&self.name) {
                let _ = sys::unlink(self.cache_id, session_write_anchor());
            }
        }
        Ok(())
    }

    /// `krcc_switch_to`: make this the collection's primary cache.
    pub fn switch_to(&self) -> Result<(), CcError> {
        let (anchor, collection, subsidiary) = parse_residual(&self.name);
        let collection_id = get_collection(&anchor, &collection)?;
        set_primary_name(collection_id, subsidiary.as_deref().unwrap_or_default())
    }

    /// `krcc_ptcursor_new` / `krcc_ptcursor_next`: the caches of the default
    /// collection, primary first.
    pub fn collection(default_name: Option<&str>) -> Result<Vec<Self>, CcError> {
        let mut out = Vec::new();
        let Some(residual) = default_name.and_then(|d| d.strip_prefix("KEYRING:")) else {
            return Ok(out);
        };
        let (anchor, collection, subsidiary) = parse_residual(residual);
        let collection_id = get_collection(&anchor, &collection)?;
        let only_one = subsidiary.is_some();
        let primary = match subsidiary {
            Some(s) => s,
            None => get_primary_name(&anchor, &collection, collection_id)?,
        };
        let keys = sys::read(collection_id).map_err(errno)?;
        if let Some(id) = search(collection_id, KEY_TYPE_KEYRING, &primary) {
            out.push(Self::make(
                &anchor,
                &collection,
                &primary,
                collection_id,
                id,
            ));
        }
        if only_one {
            return Ok(out);
        }
        for chunk in keys.as_chunks::<4>().0 {
            let key = Serial::from_ne_bytes(*chunk);
            // "typename;UID;GID;permissions;description"
            let Ok(desc) = sys::describe(key) else {
                continue;
            };
            let Some((_, sub)) = desc.rsplit_once(';') else {
                continue;
            };
            if !desc.starts_with("keyring;") || sub == primary {
                continue;
            }
            out.push(Self::make(&anchor, &collection, sub, collection_id, key));
        }
        Ok(out)
    }

    /// `krcc_start_seq_get` / `krcc_next_cred`: credentials and their keys.
    fn cred_keys(&self) -> Result<Vec<(Serial, CcCredential)>, CcError> {
        if self.cache_id == 0 {
            return Err(CcError::NoFile("No credentials cache found".into()));
        }
        let keys = sys::read(self.cache_id)
            .map_err(|_| CcError::code("KRB5_CC_IO", "Credentials cache I/O operation failed"))?;
        let offsets_id = search(self.cache_id, KEY_TYPE_USER, TIME_OFFSETS);
        let mut out = Vec::new();
        for chunk in keys.as_chunks::<4>().0 {
            let key = Serial::from_ne_bytes(*chunk);
            if key == self.princ_id || Some(key) == offsets_id {
                continue;
            }
            match sys::read(key) {
                Ok(p) => out.push((key, unmarshal_cred(&p, 4)?)),
                // Unlinked since the list was read, probably by remove_cred.
                Err(e) if no_key(&e) || e.raw_os_error() == Some(libc::EACCES) => {}
                Err(_) => return Err(CcError::NoFile("No credentials cache found".into())),
            }
        }
        Ok(out)
    }

    /// `add_cred_key`: big_key, or user when the kernel lacks big_key.
    fn add_cred_key(&self, name: &str, payload: &[u8]) -> Result<Serial, CcError> {
        if !self.legacy_type {
            match sys::add_key(CRED_KEY_TYPE, name, Some(payload), self.cache_id) {
                Ok(k) => return Ok(k),
                Err(e) if matches!(e.raw_os_error(), Some(libc::EINVAL | libc::ENODEV)) => {}
                Err(e) => return Err(errno(e)),
            }
        }
        sys::add_key(KEY_TYPE_USER, name, Some(payload), self.cache_id).map_err(errno)
    }

    /// `update_keyring_expiration`: expire the cache with its last credential.
    fn update_expiration(&self) {
        let Ok(creds) = self.cred_keys() else {
            return;
        };
        let endtime = creds.iter().map(|(_, c)| c.endtime).max().unwrap_or(0);
        if endtime == 0 {
            return;
        }
        let now = now();
        let timeout = if endtime > now { endtime - now } else { 1 };
        let _ = sys::set_timeout(self.cache_id, timeout);
    }
}

fn now() -> u32 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as u32)
}

impl Ccache for KeyringCcache {
    fn initialize(&mut self, client: &PrincipalName, realm: &str) -> Result<(), CcError> {
        self.clear()?;
        if self.cache_id == 0 {
            let name = self
                .name
                .rsplit(':')
                .next()
                .unwrap_or(&self.name)
                .to_string();
            self.cache_id = find_or_create_keyring(self.collection_id, 0, &name)?;
        }
        if is_legacy_cache_name(&self.name) {
            let _ = sys::link(self.cache_id, session_write_anchor());
        }
        self.princ_id = sys::add_key(
            KEY_TYPE_USER,
            PRINC_KEYNAME,
            Some(&marshal_princ(client, realm, 4)),
            self.cache_id,
        )
        .map_err(errno)?;
        if !is_legacy_cache_name(&self.name) {
            if let Some((secs, usecs)) = self.time_offset.get() {
                let mut p = secs.to_be_bytes().to_vec();
                p.extend_from_slice(&usecs.to_be_bytes());
                sys::add_key(KEY_TYPE_USER, TIME_OFFSETS, Some(&p), self.cache_id)
                    .map_err(errno)?;
            }
        }
        Ok(())
    }

    fn principal(&self) -> Result<(PrincipalName, String), CcError> {
        if self.cache_id == 0 || self.princ_id == 0 {
            return Err(self.not_found());
        }
        let p = sys::read(self.princ_id)
            .map_err(|_| CcError::code("KRB5_CC_IO", "Credentials cache I/O operation failed"))?;
        unmarshal_princ(&p, 4)
    }

    fn store(&mut self, cred: &CcCredential) -> Result<(), CcError> {
        if self.cache_id == 0 {
            return Err(CcError::NoFile("No credentials cache found".into()));
        }
        let name = unparse_name(&cred.server, &cred.srealm);
        let key = self.add_cred_key(&name, &marshal_cred(cred, 4))?;
        let now = now();
        if cred.endtime > now {
            let _ = sys::set_timeout(key, cred.endtime - now);
        }
        self.update_expiration();
        Ok(())
    }

    fn creds(&self) -> Result<Vec<CcCredential>, CcError> {
        Ok(self.cred_keys()?.into_iter().map(|(_, c)| c).collect())
    }

    fn remove_cred(&mut self, flags: MatchFlags, m: &MatchCred) -> Result<(), CcError> {
        for (key, c) in self.cred_keys()? {
            if super::creds_match_request(flags, m, &c) {
                sys::unlink(key, self.cache_id).map_err(errno)?;
            }
        }
        Ok(())
    }

    fn retrieve(
        &self,
        flags: MatchFlags,
        m: &MatchCred,
        ktypes: Option<&[i32]>,
    ) -> Result<CcCredential, CcError> {
        retrieve_in(&self.creds()?, flags, m, ktypes)
    }

    fn set_config(
        &mut self,
        principal: Option<(&PrincipalName, &str)>,
        key: &str,
        data: Option<&[u8]>,
    ) -> Result<(), CcError> {
        let m = MatchCred {
            server: Some((
                super::config_principal(principal, key),
                CONFIG_REALM.to_string(),
            )),
            ..Default::default()
        };
        // krb5_cc_set_config: storing replaces the key of the same name.
        match data {
            None => self.remove_cred(MatchFlags::empty(), &m),
            Some(data) => {
                let (client, realm) = self.principal()?;
                self.store(&config_cred(&client, &realm, principal, key, data))
            }
        }
    }

    fn get_config(
        &self,
        principal: Option<(&PrincipalName, &str)>,
        key: &str,
    ) -> Result<Option<Vec<u8>>, CcError> {
        Ok(self
            .creds()?
            .into_iter()
            .find(|c| config_matches(c, principal, key))
            .map(|c| c.ticket))
    }
}
