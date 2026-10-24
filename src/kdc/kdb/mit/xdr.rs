//! XDR for `KRB5_TL_KADM_DATA` (`lib/kadm5/srv/adb_xdr.c:18-96` and
//! `lib/kadm5/kadm_rpc_xdr.c:37-80`).

use super::codec::KeyData;
use crate::kdc::store::StoreError;

/// `OSA_ADB_PRINC_VERSION_1` (`lib/kadm5/server_internal.h:55`).
const OSA_ADB_PRINC_VERSION_1: u32 = 0x1234_5c01;

fn corrupt(message: impl Into<String>) -> StoreError {
    StoreError::corrupt(message)
}

struct XdrReader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> XdrReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], StoreError> {
        let end = self
            .pos
            .checked_add(len)
            .ok_or_else(|| corrupt("XDR length overflow"))?;
        let bytes = self
            .bytes
            .get(self.pos..end)
            .ok_or_else(|| corrupt("truncated KADM_DATA XDR"))?;
        self.pos = end;
        Ok(bytes)
    }

    fn u32(&mut self) -> Result<u32, StoreError> {
        let bytes = self.take(4)?;
        let mut word = [0; 4];
        word.copy_from_slice(bytes);
        Ok(u32::from_be_bytes(word))
    }

    fn i32(&mut self) -> Result<i32, StoreError> {
        Ok(self.u32()? as i32)
    }

    fn xdr_bytes(&mut self) -> Result<Vec<u8>, StoreError> {
        let len = usize::try_from(self.u32()?).map_err(|_| corrupt("XDR byte length overflow"))?;
        let bytes = self.take(len)?.to_vec();
        let padding = (4 - len % 4) % 4;
        self.take(padding)?;
        Ok(bytes)
    }

    fn nullstring(&mut self) -> Result<Option<Vec<u8>>, StoreError> {
        let bytes = self.xdr_bytes()?;
        if bytes.is_empty() {
            return Ok(None);
        }
        if bytes.last() != Some(&0) || bytes[..bytes.len() - 1].contains(&0) {
            return Err(corrupt("malformed XDR nullstring in KADM_DATA"));
        }
        Ok(Some(bytes[..bytes.len() - 1].to_vec()))
    }

    /// `old_keys`: an array of `osa_pw_hist_ent`, each an array of
    /// `krb5_key_data` (`adb_xdr.c:17-63`). A version-1 key keeps its second
    /// field only if it is not the empty `(0, [])` MIT writes for it, so
    /// re-encoding reproduces the input.
    fn history(&mut self) -> Result<Vec<Vec<KeyData>>, StoreError> {
        let entries = self.u32()?;
        if entries > 1_000_000 {
            return Err(corrupt("unreasonable KADM_DATA history length"));
        }
        let mut history = Vec::new();
        for _ in 0..entries {
            let count = self.u32()?;
            if count > 1_000_000 {
                return Err(corrupt("unreasonable KADM_DATA key-history length"));
            }
            let mut keys = Vec::new();
            for _ in 0..count {
                let ver = self.i32()?;
                if !(1..=2).contains(&ver) {
                    return Err(corrupt("invalid XDR key-data version in KADM_DATA"));
                }
                let kvno = self.u32()?;
                let kind0 = self.i32()?;
                let kind1 = self.i32()?;
                let len0 = self.u32()?;
                let len1 = self.u32()?;
                let bytes0 = self.xdr_bytes()?;
                let bytes1 = self.xdr_bytes()?;
                if kvno > u16::MAX.into()
                    || i16::try_from(kind0).is_err()
                    || i16::try_from(kind1).is_err()
                    || len0 > u16::MAX.into()
                    || len1 > u16::MAX.into()
                    || bytes0.len() != len0 as usize
                    || bytes1.len() != len1 as usize
                {
                    return Err(corrupt("XDR key-data length mismatch in KADM_DATA"));
                }
                let mut fields = vec![(kind0 as i16, bytes0)];
                if ver == 2 || kind1 != 0 || !bytes1.is_empty() {
                    fields.push((kind1 as i16, bytes1));
                }
                keys.push(KeyData {
                    ver: ver as u16,
                    kvno: kvno as u16,
                    fields,
                });
            }
            history.push(keys);
        }
        Ok(history)
    }
}

/// The fields in `osa_princ_ent_rec` (`adb_xdr.c:66-96`), including the
/// password history that kadm5 maintains on password changes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OsaPrincipalData {
    /// The optional policy name as XDR string bytes.
    pub policy: Option<Vec<u8>>,
    /// Kadm5 auxiliary attribute bits.
    pub aux_attributes: i32,
    /// Old-key list next index.
    pub old_key_next: u32,
    /// Password-history kvno.
    pub admin_history_kvno: u32,
    /// Old passwords' keys, encrypted in the `kadmin/history` key.
    pub old_keys: Vec<Vec<KeyData>>,
}

impl OsaPrincipalData {
    /// Decode XDR `osa_princ_ent_rec` (`adb_xdr.c:66-96`).
    pub fn decode(bytes: &[u8]) -> Result<Self, StoreError> {
        let mut reader = XdrReader::new(bytes);
        let version = reader.u32()?;
        if version != OSA_ADB_PRINC_VERSION_1 {
            return Err(corrupt(format!(
                "unsupported OSA principal-data version {version}"
            )));
        }
        let policy = reader.nullstring()?;
        let aux_attributes = reader.i32()?;
        let old_key_next = reader.u32()?;
        let admin_history_kvno = reader.u32()?;
        let old_keys = reader.history()?;
        if reader.pos != bytes.len() {
            return Err(corrupt("trailing bytes in KADM_DATA XDR"));
        }
        Ok(Self {
            policy,
            aux_attributes,
            old_key_next,
            admin_history_kvno,
            old_keys,
        })
    }

    /// Encode XDR `osa_princ_ent_rec`.
    pub fn encode(&self) -> Result<Vec<u8>, StoreError> {
        let mut out = Vec::new();
        out.extend_from_slice(&OSA_ADB_PRINC_VERSION_1.to_be_bytes());
        write_nullstring(&mut out, self.policy.as_deref())?;
        out.extend_from_slice(&(self.aux_attributes as u32).to_be_bytes());
        out.extend_from_slice(&self.old_key_next.to_be_bytes());
        out.extend_from_slice(&self.admin_history_kvno.to_be_bytes());
        write_u32(
            &mut out,
            u32::try_from(self.old_keys.len())
                .map_err(|_| corrupt("too many KADM_DATA password-history entries"))?,
        );
        for entry in &self.old_keys {
            write_u32(
                &mut out,
                u32::try_from(entry.len())
                    .map_err(|_| corrupt("too many KADM_DATA historical keys"))?,
            );
            for key in entry {
                write_history_key(&mut out, key)?;
            }
        }
        Ok(out)
    }
}

fn write_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn write_nullstring(out: &mut Vec<u8>, value: Option<&[u8]>) -> Result<(), StoreError> {
    match value {
        None => write_u32(out, 0),
        Some(value) => {
            if value.contains(&0) {
                return Err(corrupt("NUL in KADM_DATA policy name"));
            }
            let len = value
                .len()
                .checked_add(1)
                .and_then(|n| u32::try_from(n).ok())
                .ok_or_else(|| corrupt("KADM_DATA policy name too long"))?;
            write_u32(out, len);
            out.extend_from_slice(value);
            out.push(0);
            out.resize((out.len() + 3) & !3, 0);
        }
    }
    Ok(())
}

fn write_xdr_bytes(out: &mut Vec<u8>, value: &[u8]) -> Result<(), StoreError> {
    let len = u32::try_from(value.len()).map_err(|_| corrupt("XDR byte string too long"))?;
    write_u32(out, len);
    out.extend_from_slice(value);
    out.resize((out.len() + 3) & !3, 0);
    Ok(())
}

/// `xdr_krb5_key_data` (`adb_xdr.c:17-53`): int16 and ui_2 fields are each
/// a 4-byte XDR int; a missing second field is written as `(0, [])`.
fn write_history_key(out: &mut Vec<u8>, key: &KeyData) -> Result<(), StoreError> {
    if !(1..=2).contains(&key.ver) || key.fields.is_empty() || key.fields.len() > 2 {
        return Err(corrupt("invalid key-data version in KADM_DATA history"));
    }
    let (kind0, data0) = &key.fields[0];
    let (kind1, data1): (i16, &[u8]) = match key.fields.get(1) {
        Some((kind, data)) => (*kind, data),
        None => (0, &[]),
    };
    let len0 = u16::try_from(data0.len()).map_err(|_| corrupt("history key field too large"))?;
    let len1 = u16::try_from(data1.len()).map_err(|_| corrupt("history salt field too large"))?;
    write_u32(out, u32::from(key.ver));
    write_u32(out, u32::from(key.kvno));
    write_u32(out, *kind0 as i32 as u32);
    write_u32(out, kind1 as i32 as u32);
    write_u32(out, u32::from(len0));
    write_u32(out, u32::from(len1));
    write_xdr_bytes(out, data0)?;
    write_xdr_bytes(out, data1)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn osa_record_matches_xdr_layout_and_preserves_history_wire() {
        let record = OsaPrincipalData {
            policy: Some(b"p".to_vec()),
            aux_attributes: 0x800,
            old_key_next: 3,
            admin_history_kvno: 4,
            old_keys: vec![vec![KeyData {
                ver: 1,
                kvno: 5,
                fields: vec![(18, vec![1, 2, 3])],
            }]],
        };
        let encoded = record.encode().expect("encode");
        let decoded = OsaPrincipalData::decode(&encoded).expect("decode");
        assert_eq!(decoded, record);
        assert_eq!(
            &encoded[..12],
            &[0x12, 0x34, 0x5c, 0x01, 0, 0, 0, 2, b'p', 0, 0, 0]
        );
        assert_eq!(
            &encoded[12..],
            &[
                0, 0, 8, 0, 0, 0, 0, 3, 0, 0, 0, 4, 0, 0, 0, 1, // root
                0, 0, 0, 1, // one key
                0, 0, 0, 1, 0, 0, 0, 5, 0, 0, 0, 18, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0,
                3, 1, 2, 3, 0, 0, 0, 0, 0,
            ]
        );
    }

    #[test]
    fn multi_entry_history_round_trips_byte_for_byte() {
        let key = |ver: u16, kvno: u16, fields: Vec<(i16, Vec<u8>)>| KeyData { ver, kvno, fields };
        let record = OsaPrincipalData {
            policy: None,
            aux_attributes: 0,
            old_key_next: 1,
            admin_history_kvno: 2,
            old_keys: vec![
                vec![
                    key(2, 3, vec![(18, vec![9; 5]), (0, Vec::new())]),
                    key(2, 3, vec![(17, vec![8; 4]), (4, b"salt".to_vec())]),
                ],
                vec![
                    key(1, 4, vec![(18, vec![7; 6])]),
                    key(1, 4, vec![(-1, vec![6]), (2, vec![1])]),
                ],
            ],
        };
        let encoded = record.encode().expect("encode");
        let decoded = OsaPrincipalData::decode(&encoded).expect("decode");
        assert_eq!(decoded, record);
        assert_eq!(decoded.encode().expect("re-encode"), encoded);
    }

    #[test]
    fn null_policy_and_empty_history_are_xdr_nullstring_and_array() {
        let bytes = OsaPrincipalData::default().encode().expect("encode");
        assert_eq!(
            bytes,
            vec![
                0x12, 0x34, 0x5c, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
            ]
        );
        assert_eq!(
            OsaPrincipalData::decode(&bytes).expect("decode"),
            OsaPrincipalData::default()
        );
    }
}
