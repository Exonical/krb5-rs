//! klmdb value codecs (`plugins/kdb/lmdb/marshal.c`).

#[cfg(test)]
use rasn::types::GeneralString;

use super::parse_name;
use crate::kdc::store::{AuthState, StoreError};
use crate::types::PrincipalName;

fn corrupt(message: impl Into<String>) -> StoreError {
    StoreError::corrupt(message)
}

/// One principal tl-data item (`marshal.c:38-46`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlData {
    /// MIT `krb5_tl_data.tl_data_type`.
    pub kind: u16,
    /// Opaque bytes, retained exactly unless this module owns the type.
    pub data: Vec<u8>,
}

/// One MIT `krb5_key_data` record (`marshal.c:69-80`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyData {
    /// Number of populated type/length/content fields (1 or 2).
    pub ver: u16,
    /// MIT key version number.
    pub kvno: u16,
    /// Enctype/key bytes, followed by optional salt type/salt bytes.
    pub fields: Vec<(i16, Vec<u8>)>,
}

/// One MIT `krb5_db_entry`. The three lockout fields are read from and written
/// to the separate lockout environment, not the principal value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MitEntry {
    /// Parsed principal components. MIT's unparsed key does not store the
    /// name type; it is inferred according to `bld_princ.c:31-43`.
    pub principal: PrincipalName,
    /// Principal realm, kept separate in the krb5-rs model.
    pub realm: String,
    /// Raw `krb5_db_entry.attributes`; unknown bits are retained.
    pub attributes: u32,
    /// Maximum ticket lifetime in seconds (zero means unlimited).
    pub max_life: u32,
    /// Maximum renewable lifetime in seconds (zero means unlimited).
    pub max_renewable_life: u32,
    /// Principal expiration, zero means never.
    pub expiration: u32,
    /// Password expiration, zero means never.
    pub pw_expiration: u32,
    /// Lockout timestamp, stored in the separate klmdb lockout environment.
    pub last_success: u32,
    /// Lockout timestamp, stored in the separate klmdb lockout environment.
    pub last_failed: u32,
    /// Lockout failure counter, stored in the separate klmdb lockout environment.
    pub fail_auth_count: u32,
    /// MIT tl-data in on-disk order.
    pub tl_data: Vec<TlData>,
    /// MIT key-data in on-disk order.
    pub key_data: Vec<KeyData>,
}

/// One MIT klmdb `osa_policy_ent_rec` (`marshal.c:100-137`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MitPolicy {
    /// Policy key/name.
    pub name: String,
    /// Minimum password life, seconds.
    pub pw_min_life: u32,
    /// Maximum password life, seconds.
    pub pw_max_life: u32,
    /// Minimum password length.
    pub pw_min_length: u32,
    /// Minimum number of character classes.
    pub pw_min_classes: u32,
    /// Number of old keys retained.
    pub pw_history_num: u32,
    /// Maximum authentication failures before lockout.
    pub pw_max_fail: u32,
    /// Failure counter reset interval, seconds.
    pub pw_failcnt_interval: u32,
    /// Lockout duration, seconds.
    pub pw_lockout_duration: u32,
    /// Raw MIT policy attributes.
    pub attributes: u32,
    /// Maximum ticket lifetime, seconds.
    pub max_life: u32,
    /// Maximum renewable ticket lifetime, seconds.
    pub max_renewable_life: u32,
    /// Allowed key/salt list, if present.
    pub allowed_keysalts: Option<String>,
    /// Policy tl-data in on-disk order.
    pub tl_data: Vec<TlData>,
}

#[derive(Default)]
struct Writer(Vec<u8>);

impl Writer {
    fn u16(&mut self, value: u16) {
        self.0.extend_from_slice(&value.to_le_bytes());
    }

    fn u32(&mut self, value: u32) {
        self.0.extend_from_slice(&value.to_le_bytes());
    }

    fn bytes(&mut self, bytes: &[u8]) {
        self.0.extend_from_slice(bytes);
    }

    fn tl_data(&mut self, items: &[TlData]) -> Result<(), StoreError> {
        for item in items {
            let len = u16::try_from(item.data.len())
                .map_err(|_| corrupt("MIT tl-data exceeds u16 length"))?;
            self.u16(item.kind);
            self.u16(len);
            self.bytes(&item.data);
        }
        Ok(())
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], StoreError> {
        let end = self
            .pos
            .checked_add(len)
            .ok_or_else(|| corrupt("MIT record length overflow"))?;
        let value = self
            .bytes
            .get(self.pos..end)
            .ok_or_else(|| corrupt("truncated MIT klmdb record"))?;
        self.pos = end;
        Ok(value)
    }

    fn u16(&mut self) -> Result<u16, StoreError> {
        let bytes = self.take(2)?;
        Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
    }

    fn u32(&mut self) -> Result<u32, StoreError> {
        let bytes = self.take(4)?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn tl_data(&mut self, count: u16) -> Result<Vec<TlData>, StoreError> {
        if usize::from(count) > self.bytes.len().saturating_sub(self.pos) / 4 {
            return Err(corrupt("MIT tl-data count exceeds record length"));
        }
        let mut out = Vec::with_capacity(usize::from(count));
        for _ in 0..count {
            let kind = self.u16()?;
            let len = usize::from(self.u16()?);
            out.push(TlData {
                kind,
                data: self.take(len)?.to_vec(),
            });
        }
        Ok(out)
    }

    fn finish(self) -> Result<(), StoreError> {
        if self.pos != self.bytes.len() {
            return Err(corrupt("trailing bytes in MIT klmdb record"));
        }
        Ok(())
    }
}

impl MitEntry {
    /// The lockout fields represented by this principal view.
    pub fn auth_state(&self) -> AuthState {
        AuthState {
            fail_count: self.fail_auth_count,
            last_failed: i64::from(self.last_failed),
            last_success: i64::from(self.last_success),
        }
    }

    /// Set the principal view's lockout fields (`marshal.c:91-98` stores them
    /// separately from the main principal value).
    pub fn set_auth_state(&mut self, state: AuthState) -> Result<(), StoreError> {
        self.fail_auth_count = state.fail_count;
        self.last_failed = u32::try_from(state.last_failed)
            .map_err(|_| StoreError::backend("last_failed is outside MIT's u32 range"))?;
        self.last_success = u32::try_from(state.last_success)
            .map_err(|_| StoreError::backend("last_success is outside MIT's u32 range"))?;
        Ok(())
    }

    /// Decode a principal using its LMDB key (`marshal.c:165-251`).
    pub fn decode(key: &[u8], value: &[u8]) -> Result<Self, StoreError> {
        let (principal, realm) = parse_name(key)?;
        let mut reader = Reader::new(value);
        let attributes = reader.u32()?;
        let max_life = reader.u32()?;
        let max_renewable_life = reader.u32()?;
        let expiration = reader.u32()?;
        let pw_expiration = reader.u32()?;
        let tl_count = reader.u16()?;
        let key_count = reader.u16()?;
        let tl_data = reader.tl_data(tl_count)?;
        if usize::from(key_count) > value.len().saturating_sub(reader.pos) / 4 {
            return Err(corrupt("MIT key-data count exceeds record length"));
        }
        let mut key_data = Vec::with_capacity(usize::from(key_count));
        for _ in 0..key_count {
            let ver = reader.u16()?;
            let kvno = reader.u16()?;
            if !(1..=2).contains(&ver) {
                return Err(corrupt(format!("invalid MIT key-data version {ver}")));
            }
            let mut fields = Vec::with_capacity(usize::from(ver));
            for _ in 0..ver {
                let kind = reader.u16()? as i16;
                let len = usize::from(reader.u16()?);
                fields.push((kind, reader.take(len)?.to_vec()));
            }
            key_data.push(KeyData { ver, kvno, fields });
        }
        reader.finish()?;
        Ok(Self {
            principal,
            realm,
            attributes,
            max_life,
            max_renewable_life,
            expiration,
            pw_expiration,
            last_success: 0,
            last_failed: 0,
            fail_auth_count: 0,
            tl_data,
            key_data,
        })
    }

    /// Encode a principal value and its LMDB key (`marshal.c:48-89`).
    pub fn encode(&self) -> Result<(Vec<u8>, Vec<u8>), StoreError> {
        let tl_count =
            u16::try_from(self.tl_data.len()).map_err(|_| corrupt("too many MIT tl-data items"))?;
        let key_count = u16::try_from(self.key_data.len())
            .map_err(|_| corrupt("too many MIT key-data items"))?;
        let mut writer = Writer::default();
        writer.u32(self.attributes);
        writer.u32(self.max_life);
        writer.u32(self.max_renewable_life);
        writer.u32(self.expiration);
        writer.u32(self.pw_expiration);
        writer.u16(tl_count);
        writer.u16(key_count);
        writer.tl_data(&self.tl_data)?;
        for key in &self.key_data {
            if !(1..=2).contains(&key.ver)
                || usize::from(key.ver) != key.fields.len()
                || key.fields.len() > 2
            {
                return Err(corrupt("MIT key-data version does not match its fields"));
            }
            writer.u16(key.ver);
            writer.u16(key.kvno);
            for (kind, data) in &key.fields {
                let len = u16::try_from(data.len())
                    .map_err(|_| corrupt("MIT key-data field exceeds u16 length"))?;
                writer.u16(*kind as u16);
                writer.u16(len);
                writer.bytes(data);
            }
        }
        let key = super::unparse_name(&self.principal, &self.realm);
        Ok((key, writer.0))
    }
}

impl MitPolicy {
    /// Decode a policy value (`marshal.c:262-321`).
    pub fn decode(name: &[u8], value: &[u8]) -> Result<Self, StoreError> {
        let name = String::from_utf8(name.to_vec())
            .map_err(|_| corrupt("MIT policy name is not UTF-8"))?;
        let mut reader = Reader::new(value);
        let pw_min_life = reader.u32()?;
        let pw_max_life = reader.u32()?;
        let pw_min_length = reader.u32()?;
        let pw_min_classes = reader.u32()?;
        let pw_history_num = reader.u32()?;
        let pw_max_fail = reader.u32()?;
        let pw_failcnt_interval = reader.u32()?;
        let pw_lockout_duration = reader.u32()?;
        let attributes = reader.u32()?;
        let max_life = reader.u32()?;
        let max_renewable_life = reader.u32()?;
        let keysalt_len = usize::try_from(reader.u32()?)
            .map_err(|_| corrupt("MIT allowed-keysalts length overflow"))?;
        let allowed_keysalts = if keysalt_len == 0 {
            None
        } else {
            Some(
                String::from_utf8(reader.take(keysalt_len)?.to_vec())
                    .map_err(|_| corrupt("MIT allowed-keysalts is not UTF-8"))?,
            )
        };
        let tl_count = reader.u16()?;
        let tl_data = reader.tl_data(tl_count)?;
        reader.finish()?;
        Ok(Self {
            name,
            pw_min_life,
            pw_max_life,
            pw_min_length,
            pw_min_classes,
            pw_history_num,
            pw_max_fail,
            pw_failcnt_interval,
            pw_lockout_duration,
            attributes,
            max_life,
            max_renewable_life,
            allowed_keysalts,
            tl_data,
        })
    }

    /// Encode a policy value (`marshal.c:100-137`).
    pub fn encode(&self) -> Result<Vec<u8>, StoreError> {
        let keysalts = self.allowed_keysalts.as_deref().unwrap_or("").as_bytes();
        let keysalt_len = u32::try_from(keysalts.len())
            .map_err(|_| corrupt("MIT allowed-keysalts exceeds u32 length"))?;
        let tl_count = u16::try_from(self.tl_data.len())
            .map_err(|_| corrupt("too many MIT policy tl-data items"))?;
        let mut writer = Writer::default();
        for value in [
            self.pw_min_life,
            self.pw_max_life,
            self.pw_min_length,
            self.pw_min_classes,
            self.pw_history_num,
            self.pw_max_fail,
            self.pw_failcnt_interval,
            self.pw_lockout_duration,
            self.attributes,
            self.max_life,
            self.max_renewable_life,
        ] {
            writer.u32(value);
        }
        writer.u32(keysalt_len);
        writer.bytes(keysalts);
        writer.u16(tl_count);
        writer.tl_data(&self.tl_data)?;
        Ok(writer.0)
    }
}

/// Encode one lockout record (`marshal.c:91-98`).
pub fn encode_lockout(last_success: u32, last_failed: u32, fail_auth_count: u32) -> [u8; 12] {
    let mut bytes = [0; 12];
    bytes[0..4].copy_from_slice(&last_success.to_le_bytes());
    bytes[4..8].copy_from_slice(&last_failed.to_le_bytes());
    bytes[8..12].copy_from_slice(&fail_auth_count.to_le_bytes());
    bytes
}

/// Decode one lockout record (`marshal.c:253-260`).
pub fn decode_lockout(value: &[u8]) -> Result<(u32, u32, u32), StoreError> {
    if value.len() != 12 {
        return Err(corrupt("MIT lockout record must be exactly 12 bytes"));
    }
    let mut last_success = [0; 4];
    let mut last_failed = [0; 4];
    let mut fail_auth_count = [0; 4];
    last_success.copy_from_slice(&value[0..4]);
    last_failed.copy_from_slice(&value[4..8]);
    fail_auth_count.copy_from_slice(&value[8..12]);
    Ok((
        u32::from_le_bytes(last_success),
        u32::from_le_bytes(last_failed),
        u32::from_le_bytes(fail_auth_count),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::PrincipalName;

    fn name() -> PrincipalName {
        PrincipalName {
            name_type: 1,
            name_string: vec![GeneralString::from_bytes(b"alice").expect("name")],
        }
    }

    #[test]
    fn principal_codec_matches_marshal_c_golden_vector() {
        let entry = MitEntry {
            principal: name(),
            realm: "R".into(),
            attributes: 1,
            max_life: 2,
            max_renewable_life: 3,
            expiration: 4,
            pw_expiration: 5,
            last_success: 0,
            last_failed: 0,
            fail_auth_count: 0,
            tl_data: vec![TlData {
                kind: 1,
                data: vec![0xaa],
            }],
            key_data: vec![KeyData {
                ver: 1,
                kvno: 7,
                fields: vec![(18, vec![0xbb, 0xcc])],
            }],
        };
        let (key, value) = entry.encode().expect("encode");
        assert_eq!(key, b"alice@R");
        assert_eq!(
            value,
            [
                1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 4, 0, 0, 0, 5, 0, 0, 0, 1, 0, 1, 0, 1, 0, 1, 0,
                0xaa, 1, 0, 7, 0, 18, 0, 2, 0, 0xbb, 0xcc
            ]
        );
        let decoded = MitEntry::decode(&key, &value).expect("decode");
        assert_eq!(decoded, entry);
    }

    #[test]
    fn policy_codec_matches_marshal_c_golden_vector() {
        let policy = MitPolicy {
            name: "p".into(),
            pw_min_life: 1,
            pw_max_life: 2,
            pw_min_length: 3,
            pw_min_classes: 4,
            pw_history_num: 5,
            pw_max_fail: 6,
            pw_failcnt_interval: 7,
            pw_lockout_duration: 8,
            attributes: 9,
            max_life: 10,
            max_renewable_life: 11,
            allowed_keysalts: Some("x".into()),
            tl_data: Vec::new(),
        };
        let value = policy.encode().expect("encode");
        let mut expected = Vec::new();
        for n in 1u32..=11 {
            expected.extend_from_slice(&n.to_le_bytes());
        }
        expected.extend_from_slice(&1u32.to_le_bytes());
        expected.extend_from_slice(b"x");
        expected.extend_from_slice(&0u16.to_le_bytes());
        assert_eq!(value, expected);
        assert_eq!(MitPolicy::decode(b"p", &value).expect("decode"), policy);
    }

    #[test]
    fn lockout_codec_is_exactly_three_little_endian_words() {
        let bytes = encode_lockout(1, 0x1122_3344, u32::MAX);
        assert_eq!(
            &bytes,
            &[1, 0, 0, 0, 0x44, 0x33, 0x22, 0x11, 0xff, 0xff, 0xff, 0xff]
        );
        assert_eq!(
            decode_lockout(&bytes).expect("decode"),
            (1, 0x1122_3344, u32::MAX)
        );
        assert!(decode_lockout(&bytes[..11]).is_err());
    }

    #[test]
    fn mit_entry_auth_state_maps_to_the_separate_lockout_record() {
        let mut entry = MitEntry {
            principal: name(),
            realm: "R".into(),
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
        };
        let state = AuthState {
            fail_count: 3,
            last_failed: 42,
            last_success: 24,
        };
        entry.set_auth_state(state).expect("set lockout");
        assert_eq!(entry.auth_state(), state);
        assert_eq!(
            decode_lockout(&encode_lockout(
                entry.last_success,
                entry.last_failed,
                entry.fail_auth_count
            ))
            .expect("decode lockout"),
            (24, 42, 3)
        );
    }

    #[test]
    fn malformed_principal_values_are_corrupt() {
        let key = b"a@R";
        let mut bytes = vec![0; 24];
        bytes[20..22].copy_from_slice(&1u16.to_le_bytes());
        bytes[22..24].copy_from_slice(&0u16.to_le_bytes());
        assert_eq!(
            MitEntry::decode(key, &bytes)
                .expect_err("truncated tl")
                .kind(),
            crate::kdc::store::StoreErrorKind::Corrupt
        );
        let valid = MitEntry {
            principal: name(),
            realm: "R".into(),
            attributes: 0,
            max_life: 0,
            max_renewable_life: 0,
            expiration: 0,
            pw_expiration: 0,
            last_success: 0,
            last_failed: 0,
            fail_auth_count: 0,
            tl_data: vec![],
            key_data: vec![],
        };
        let (key, mut value) = valid.encode().expect("encode");
        value.push(0);
        assert!(MitEntry::decode(&key, &value).is_err());
    }
}
