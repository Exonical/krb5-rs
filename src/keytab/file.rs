//! FILE keytab (kt_file.c): reads v1 (0x0501, native order) and v2
//! (0x0502, big-endian); writes v2 only.

use std::path::PathBuf;

use rasn::types::GeneralString;

use super::{get_entry_in, Keytab, KeytabEntry, KtError};
use crate::protocol::ap::{ApError, KeySource};
use crate::types::{EncryptionKey, PrincipalName};

/// A FILE keytab.
pub struct FileKeytab {
    path: PathBuf,
}

impl FileKeytab {
    /// A keytab at `path`.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// All raw records: (offset, size, Option<entry>).  Deleted holes
    /// (negative size) appear as None.
    fn records(&self) -> Result<Vec<(usize, usize, Option<KeytabEntry>)>, KtError> {
        let data = match std::fs::read(&self.path) {
            Ok(d) => d,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(KtError::Io(e)),
        };
        if data.len() < 2 {
            return Err(KtError::Format);
        }
        let vno = u16::from_be_bytes([data[0], data[1]]);
        let v1 = match vno {
            0x0501 => true,
            0x0502 => false,
            _ => return Err(KtError::Format),
        };
        let mut out = Vec::new();
        let mut pos = 2;
        while pos + 4 <= data.len() {
            let raw: [u8; 4] = data[pos..pos + 4].try_into().expect("4");
            let mut size = if v1 {
                i32::from_ne_bytes(raw)
            } else {
                i32::from_be_bytes(raw)
            };
            if size == i32::MIN {
                // INT32_MIN inverts to itself (kt_file.c:925-926).
                return Err(KtError::Format);
            }
            if size == 0 {
                break; // KRB5_KT_END
            }
            let hole = size < 0;
            if hole {
                size = -size;
            }
            if pos + 4 + size as usize > data.len() {
                return Err(KtError::Format);
            }
            let body = &data[pos + 4..pos + 4 + size as usize];
            let entry = if hole {
                None
            } else {
                match parse_entry(body, v1) {
                    Ok(e) => Some(e),
                    Err(KtError::End) => break, // KRB5_KT_END stops iteration
                    Err(e) => return Err(e),
                }
            };
            out.push((pos, size as usize, entry));
            pos += 4 + size as usize;
        }
        Ok(out)
    }

    /// Serialize an entry body in v2 (big-endian) format.
    fn entry_body(e: &KeytabEntry) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&(e.principal.name_string.len() as i16).to_be_bytes());
        b.extend_from_slice(&(e.realm.len() as i16).to_be_bytes());
        b.extend_from_slice(e.realm.as_bytes());
        for c in &e.principal.name_string {
            b.extend_from_slice(&(c.len() as i16).to_be_bytes());
            b.extend_from_slice(c.as_bytes());
        }
        b.extend_from_slice(&e.principal.name_type.to_be_bytes());
        b.extend_from_slice(&e.timestamp.to_be_bytes());
        b.push(e.kvno as u8);
        b.extend_from_slice(&(e.key.keytype as i16).to_be_bytes());
        b.extend_from_slice(&(e.key.key_bytes().len() as i16).to_be_bytes());
        b.extend_from_slice(e.key.key_bytes());
        b.extend_from_slice(&e.kvno.to_be_bytes()); // vno32
        b
    }

    /// Reject writes to a v1 (0x0501) file: we write v2 records only, and
    /// MIT's write_entry/find_slot would use the file's own byte order.
    fn ensure_writable(&self) -> Result<(), KtError> {
        match std::fs::read(&self.path) {
            Ok(d) if d.len() >= 2 => {
                if u16::from_be_bytes([d[0], d[1]]) == 0x0501 {
                    return Err(KtError::Format);
                }
                Ok(())
            }
            Ok(_) => Err(KtError::Format),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(KtError::Io(e)),
        }
    }
}

/// Parse one record body. `v1`: native order, count includes realm, no
/// name type, no vno32.
fn parse_entry(d: &[u8], v1: bool) -> Result<KeytabEntry, KtError> {
    fn take<'a>(d: &'a [u8], pos: &mut usize, n: usize) -> Result<&'a [u8], KtError> {
        if d.len() - *pos < n {
            return Err(KtError::Format);
        }
        let s = &d[*pos..*pos + n];
        *pos += n;
        Ok(s)
    }
    let mut pos = 0usize;
    macro_rules! i16r {
        () => {{
            let b: [u8; 2] = take(d, &mut pos, 2)?
                .try_into()
                .map_err(|_| KtError::Format)?;
            if v1 {
                i16::from_ne_bytes(b)
            } else {
                i16::from_be_bytes(b)
            }
        }};
    }
    macro_rules! i32r {
        () => {{
            let b: [u8; 4] = take(d, &mut pos, 4)?
                .try_into()
                .map_err(|_| KtError::Format)?;
            if v1 {
                i32::from_ne_bytes(b)
            } else {
                i32::from_be_bytes(b)
            }
        }};
    }
    let mut count = i16r!();
    if v1 {
        // V1 counts the realm as a component.
        count -= 1;
    }
    // kt_file.c:949 — `if (!count || count < 0) return KRB5_KT_END`.
    if count <= 0 {
        return Err(KtError::End);
    }
    let realm_len = i16r!();
    if realm_len <= 0 {
        return Err(KtError::End);
    }
    let realm = String::from_utf8_lossy(take(d, &mut pos, realm_len as usize)?).to_string();
    let mut comps = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let len = i16r!();
        if len <= 0 {
            return Err(KtError::End);
        }
        let bytes = take(d, &mut pos, len as usize)?;
        comps.push(GeneralString::from_bytes(bytes).map_err(|_| KtError::Format)?);
    }
    let name_type = if v1 { 0 } else { i32r!() };
    let timestamp = i32r!() as u32;
    let mut kvno = take(d, &mut pos, 1)?[0] as u32;
    let etype = i32::from(i16r!());
    let klen = i16r!();
    if klen <= 0 {
        return Err(KtError::End);
    }
    let key = take(d, &mut pos, klen as usize)?.to_vec();
    // 32-bit kvno extension if four or more bytes remain (kt_file.c:1084-1096).
    if pos + 4 <= d.len() {
        let vno32: [u8; 4] = d[pos..pos + 4].try_into().expect("4");
        let vno32 = if v1 {
            u32::from_ne_bytes(vno32)
        } else {
            u32::from_be_bytes(vno32)
        };
        if vno32 != 0 {
            kvno = vno32;
        }
    }
    Ok(KeytabEntry {
        principal: PrincipalName {
            name_type,
            name_string: comps,
        },
        realm,
        timestamp,
        kvno,
        key: EncryptionKey::new(etype, key),
    })
}

impl Keytab for FileKeytab {
    fn entries(&self) -> Result<Vec<KeytabEntry>, KtError> {
        Ok(self
            .records()?
            .into_iter()
            .filter_map(|(_, _, e)| e)
            .collect())
    }

    fn get_entry(
        &self,
        principal: &PrincipalName,
        realm: &str,
        kvno: Option<u32>,
        etype: Option<i32>,
    ) -> Result<KeytabEntry, KtError> {
        get_entry_in(&self.entries()?, principal, realm, kvno, etype)
    }

    fn add_entry(&mut self, entry: &KeytabEntry) -> Result<(), KtError> {
        self.ensure_writable()?;
        // Create the file with a 0x0502 header if missing.
        if !self.path.exists() {
            std::fs::write(&self.path, [0x05, 0x02])?;
        }
        let body = Self::entry_body(entry);
        let needed = body.len() as i32;
        let mut data = std::fs::read(&self.path)?;
        // find_slot (kt_file.c:1313-1381): reuse a hole ≥ needed, else append.
        let mut pos = 2;
        while pos + 4 <= data.len() {
            let size = i32::from_be_bytes(data[pos..pos + 4].try_into().expect("4"));
            if size == i32::MIN {
                return Err(KtError::Format);
            }
            if size < 0 {
                let hole = (-size) as usize;
                if hole >= needed as usize {
                    // Reuse: committed size is the whole hole.
                    data[pos..pos + 4].copy_from_slice(&(hole as i32).to_be_bytes());
                    data[pos + 4..pos + 4 + body.len()].copy_from_slice(&body);
                    for b in &mut data[pos + 4 + body.len()..pos + 4 + hole] {
                        *b = 0;
                    }
                    return std::fs::write(&self.path, &data).map_err(KtError::Io);
                }
            } else if size == 0 {
                break;
            }
            pos += 4 + size.unsigned_abs() as usize;
        }
        // Append at pos (an existing 0-size placeholder or EOF).
        let mut rec = needed.to_be_bytes().to_vec();
        rec.extend_from_slice(&body);
        if pos + 4 <= data.len() {
            data.splice(pos..pos + 4, rec);
        } else {
            data.extend_from_slice(&rec);
        }
        std::fs::write(&self.path, &data).map_err(KtError::Io)
    }

    fn remove_entry(&mut self, entry: &KeytabEntry) -> Result<(), KtError> {
        self.ensure_writable()?;
        let mut data = std::fs::read(&self.path)?;
        for (off, size, rec) in self.records()? {
            let Some(e) = rec else { continue };
            if e.principal.name_string == entry.principal.name_string
                && e.realm == entry.realm
                && e.kvno == entry.kvno
                && e.key.keytype == entry.key.keytype
            {
                // delete_entry (kt_file.c:837-880): negate size, zero body.
                data[off..off + 4].copy_from_slice(&(-(size as i32)).to_be_bytes());
                for b in &mut data[off + 4..off + 4 + size] {
                    *b = 0;
                }
                return std::fs::write(&self.path, &data).map_err(KtError::Io);
            }
        }
        Err(KtError::NotFound)
    }
}

impl KeySource for FileKeytab {
    fn get_key(
        &self,
        server: &PrincipalName,
        realm: &[u8],
        kvno: Option<i32>,
        etype: i32,
    ) -> Result<EncryptionKey, ApError> {
        super::ap_key_for(self, server, realm, kvno, etype)
    }
}
