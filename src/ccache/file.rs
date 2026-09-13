//! FILE ccache (cc_file.c): versions 1-4.

use std::cell::Cell;
use std::path::PathBuf;

use super::marshal::{marshal_cred, marshal_princ, unmarshal_cred_len, unmarshal_princ_len};
use super::retrieve::retrieve_in;
use super::{
    config_cred, config_matches, CcCredential, CcError, Ccache, MatchCred, MatchFlags,
    CONFIG_REALM, REMOVED_CONFIG_REALM,
};
use crate::types::PrincipalName;

/// (version, header length, KDC time offset) from a parsed file header.
type ParsedHeader = (u8, usize, Option<(u32, u32)>);

/// A FILE credential cache.
pub struct FileCcache {
    path: PathBuf,
    /// Version written by `initialize` (default 4).  Reading uses the
    /// version found in the file.
    version: u8,
    /// KDC time offset from a v4 DELTATIME tag (or set for writing).
    time_offset: Cell<Option<(u32, u32)>>,
}

impl FileCcache {
    /// A cache at `path`; version 4 by default.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            version: 4,
            time_offset: Cell::new(None),
        }
    }

    /// Set the version written by `initialize` (1-4).
    pub fn with_version(mut self, version: u8) -> Self {
        self.version = version;
        self
    }

    /// Set the KDC time offset (secs, usecs); written as a DELTATIME tag
    /// in v4 caches.
    pub fn set_time_offset(&mut self, secs: u32, usecs: u32) {
        self.time_offset.set(Some((secs, usecs)));
    }

    /// The time offset read from (or configured for) this cache.
    pub fn time_offset(&self) -> Option<(u32, u32)> {
        self.time_offset.get()
    }

    /// Parse the file header: returns (version, header length, deltatime).
    fn parse_header(data: &[u8]) -> Result<ParsedHeader, CcError> {
        if data.len() < 2 {
            return Err(CcError::Format);
        }
        let marker = u16::from_be_bytes([data[0], data[1]]);
        if marker >> 8 != 0x05 {
            return Err(CcError::BadVno);
        }
        let version = (marker & 0xFF) as u8;
        if !(1..=4).contains(&version) {
            return Err(CcError::BadVno);
        }
        if version != 4 {
            return Ok((version, 2, None));
        }
        // V4 header: u16 fields_len, then tagged fields (cc_file.c:384-441).
        if data.len() < 4 {
            return Err(CcError::Format);
        }
        let fields_len = u16::from_be_bytes([data[2], data[3]]) as usize;
        if fields_len != 0 && fields_len < 4 {
            return Err(CcError::Format);
        }
        let fields_end = 4usize.checked_add(fields_len).ok_or(CcError::Format)?;
        if data.len() < fields_end {
            return Err(CcError::Format);
        }
        let mut offset = None;
        let mut pos = 4;
        while pos + 4 <= fields_end {
            let tag = u16::from_be_bytes([data[pos], data[pos + 1]]);
            let flen = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
            pos += 4;
            if pos + flen > fields_end {
                return Err(CcError::Format);
            }
            if tag == 1 {
                // FCC_TAG_DELTATIME: u32 secs + u32 usecs.
                if flen != 8 {
                    return Err(CcError::Format);
                }
                let secs = u32::from_be_bytes(data[pos..pos + 4].try_into().expect("4"));
                let usecs = u32::from_be_bytes(data[pos + 4..pos + 8].try_into().expect("4"));
                offset = Some((secs, usecs));
            }
            pos += flen;
        }
        if pos != fields_end {
            return Err(CcError::Format);
        }
        Ok((version, fields_end, offset))
    }

    /// Read the file, returning (data, version, creds-region offset).
    /// Also records any DELTATIME offset found.
    fn read_all(&self) -> Result<(Vec<u8>, u8, usize), CcError> {
        let data = std::fs::read(&self.path)?;
        let (version, hdr_len, offset) = Self::parse_header(&data)?;
        if offset.is_some() {
            self.time_offset.set(offset);
        }
        let (_, _, plen) = unmarshal_princ_len(&data[hdr_len..], version)?;
        Ok((data, version, hdr_len + plen))
    }

    /// Iterate raw credential records: (offset, len, cred).
    fn records(&self) -> Result<Vec<(usize, usize, CcCredential)>, CcError> {
        let (data, version, mut pos) = self.read_all()?;
        let mut out = Vec::new();
        while pos < data.len() {
            let (cred, len) = unmarshal_cred_len(&data[pos..], version)?;
            if len == 0 {
                break;
            }
            out.push((pos, len, cred));
            pos += len;
        }
        Ok(out)
    }

    /// Write header + default principal, truncating the file.
    fn write_header(&self, client: &PrincipalName, realm: &str) -> Result<(), CcError> {
        let mut out = Vec::new();
        let v = self.version;
        out.extend_from_slice(&[0x05, v]);
        if v == 4 {
            if let Some((secs, usecs)) = self.time_offset.get() {
                out.extend_from_slice(&12u16.to_be_bytes());
                out.extend_from_slice(&1u16.to_be_bytes());
                out.extend_from_slice(&8u16.to_be_bytes());
                out.extend_from_slice(&secs.to_be_bytes());
                out.extend_from_slice(&usecs.to_be_bytes());
            } else {
                out.extend_from_slice(&0u16.to_be_bytes());
            }
        }
        out.extend_from_slice(&marshal_princ(client, realm, v));
        std::fs::write(&self.path, &out).map_err(CcError::Io)
    }
}

impl Ccache for FileCcache {
    fn initialize(&mut self, client: &PrincipalName, realm: &str) -> Result<(), CcError> {
        self.write_header(client, realm)
    }

    fn principal(&self) -> Result<(PrincipalName, String), CcError> {
        let (data, version, _) = self.read_all()?;
        let hdr_len = Self::parse_header(&data)?.1;
        let (p, realm, _) = unmarshal_princ_len(&data[hdr_len..], version)?;
        Ok((p, realm))
    }

    fn store(&mut self, cred: &CcCredential) -> Result<(), CcError> {
        let (_, version, _) = self.read_all()?;
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new().append(true).open(&self.path)?;
        f.write_all(&marshal_cred(cred, version))?;
        Ok(())
    }

    fn creds(&self) -> Result<Vec<CcCredential>, CcError> {
        Ok(self
            .records()?
            .into_iter()
            // Skip credentials removed in place (cc_file.c:750-757).
            .filter(|(_, _, c)| !(c.endtime == 0 && c.authtime != 0))
            .map(|(_, _, c)| c)
            .collect())
    }

    fn remove_cred(&mut self, flags: MatchFlags, m: &MatchCred) -> Result<(), CcError> {
        let (mut data, version, _) = self.read_all()?;
        for (off, len, cred) in self.records()? {
            if cred.endtime == 0 && cred.authtime != 0 {
                continue;
            }
            if !super::creds_match_request(flags, m, &cred) {
                continue;
            }
            // cc_file.c:1055-1066: endtime=0, authtime=0xFFFFFFFF; a config
            // cred's realm is rewritten so other implementations ignore it.
            let mut removed = cred;
            removed.authtime = u32::MAX;
            removed.endtime = 0;
            if removed.srealm == CONFIG_REALM {
                removed.srealm = REMOVED_CONFIG_REALM.to_string();
            }
            let bytes = marshal_cred(&removed, version);
            if bytes.len() != len {
                return Err(CcError::Format);
            }
            data[off..off + len].copy_from_slice(&bytes);
            return std::fs::write(&self.path, &data).map_err(CcError::Io);
        }
        Err(CcError::NotFound)
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
        let target = super::config_principal(principal, key);
        let m = MatchCred {
            server: Some((target, CONFIG_REALM.to_string())),
            ..Default::default()
        };
        let _ = self.remove_cred(MatchFlags::empty(), &m);
        if let Some(data) = data {
            let (client, realm) = self.principal()?;
            self.store(&config_cred(&client, &realm, principal, key, data))?;
        }
        Ok(())
    }

    fn get_config(
        &self,
        principal: Option<(&PrincipalName, &str)>,
        key: &str,
    ) -> Result<Option<Vec<u8>>, CcError> {
        for c in self.creds()? {
            if config_matches(&c, principal, key) {
                return Ok(Some(c.ticket));
            }
        }
        Ok(None)
    }
}
