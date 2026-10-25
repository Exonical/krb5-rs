//! MIT tl-data mapping (`include/kdb.h:250-274`,
//! `lib/kdb/kdb5.c:1537-1559, 1610-1666, 1668-1737, 1897-2052,
//! 2055-2081, 2084-2268`, and `plugins/kdb/ldap/libkdb_ldap/ldap_misc.c:1601-1619`).

use std::time::Duration;

use chrono::Utc;
#[cfg(test)]
use rasn::types::GeneralString;

use super::codec::{KeyData, MitEntry, MitPolicy, TlData};
use super::mkey::{entry_mkvno as mkvno, rewrap_key_data, MasterKeys};
use super::name::parse_name;
#[cfg(test)]
use super::name::unparse_name;
use super::xdr::OsaPrincipalData;
use crate::crypto::SaltType;
use crate::kdc::db::{salt_bytes, KeyEntry, PrincipalAttributes, PrincipalEntry};
use crate::kdc::kdb::master::{decrypt_key, encrypt_key};
use crate::kdc::policy::kerberos_time;
use crate::kdc::store::{PasswordHistory, Policy, PrincipalRecord, StoreError};
use crate::types::{EncryptionKey, KerberosTime, PrincipalName};

/// LE u32 timestamp (`lib/kdb/kdb5.c:2055-2066`).
pub const LAST_PWD_CHANGE: u16 = 0x0001;
/// LE u32 timestamp followed by unparsed principal and NUL
/// (`lib/kdb/kdb5.c:1596-1665`).
pub const MOD_PRINC: u16 = 0x0002;
/// XDR `osa_princ_ent_rec` (`lib/kadm5/srv/adb_xdr.c:66-96`).
pub const KADM_DATA: u16 = 0x0003;
/// LE i16 master-key kvno (`lib/kdb/kdb5.c:1668-1737`).
pub const MKVNO: u16 = 0x0008;
/// Versioned LE tuples (`lib/kdb/kdb5.c:1897-2052`); preserved verbatim.
pub const ACTKVNO: u16 = 0x0009;
/// Versioned master-key auxiliary data (`lib/kdb/kdb5.c:1741-1895`);
/// preserved verbatim.
pub const MKEY_AUX: u16 = 0x000a;
/// NUL-terminated key/value pairs (`lib/kdb/kdb5.c:2084-2268`).
pub const STRING_ATTRS: u16 = 0x000b;
/// Unparsed principal plus a NUL (`plugins/kdb/ldap/libkdb_ldap/ldap_misc.c:1601-1619`).
pub const CONSTRAINED_DELEGATION_ACL: u16 = 0x0400;
/// LE u32 timestamp (`lib/kdb/kdb5.c:2070-2081`).
pub const LAST_ADMIN_UNLOCK: u16 = 0x0700;
/// `osa_princ_ent_rec.aux_attributes` policy bit (`lib/kadm5/admin.h:99`).
pub const KADM5_POLICY: i32 = 0x0000_0800;
/// krb5-rs extension; only LDAP implements the delegation methods
/// (`lib/kdb/kdb5.c:2726-2785`).
const ALLOWED_TO_DELEGATE_FROM: &[u8] = b"krb5rs_allowed_to_delegate_from";

/// A raw MIT string-attribute key/value pair.
pub type StringAttribute = (Vec<u8>, Vec<u8>);

fn corrupt(message: impl Into<String>) -> StoreError {
    StoreError::corrupt(message)
}

fn bytes_tl(entry: &MitEntry, kind: u16) -> Option<&[u8]> {
    entry
        .tl_data
        .iter()
        .find(|tl| tl.kind == kind)
        .map(|tl| tl.data.as_slice())
}

fn get_u32_tl(entry: &MitEntry, kind: u16) -> Result<Option<u32>, StoreError> {
    let Some(bytes) = bytes_tl(entry, kind) else {
        return Ok(None);
    };
    let value: [u8; 4] = bytes
        .try_into()
        .map_err(|_| corrupt(format!("MIT tl-data {kind:#06x} must be 4 bytes")))?;
    Ok(Some(u32::from_le_bytes(value)))
}

fn set_tl(entry: &mut MitEntry, kind: u16, data: Option<Vec<u8>>) {
    let first = entry.tl_data.iter().position(|tl| tl.kind == kind);
    entry.tl_data.retain(|tl| {
        if tl.kind != kind {
            return true;
        }
        false
    });
    if let Some(data) = data {
        let tl = TlData { kind, data };
        if let Some(at) = first {
            entry.tl_data.insert(at.min(entry.tl_data.len()), tl);
        } else {
            entry.tl_data.push(tl);
        }
    }
}

fn timestamp(value: Option<KerberosTime>) -> Result<u32, StoreError> {
    match value {
        None => Ok(0),
        Some(value) => u32::try_from(value.timestamp())
            .map_err(|_| StoreError::backend("MIT timestamp is outside the u32 range")),
    }
}

fn from_timestamp(value: u32) -> Option<KerberosTime> {
    (value != 0).then(|| kerberos_time(i64::from(value)))
}

fn duration(value: Option<Duration>) -> Result<u32, StoreError> {
    match value {
        None => Ok(0),
        Some(value) => u32::try_from(value.as_secs())
            .map_err(|_| StoreError::backend("MIT lifetime is outside the u32 range")),
    }
}

fn attr_pairs(entry: &MitEntry) -> Result<Vec<StringAttribute>, StoreError> {
    let Some(bytes) = bytes_tl(entry, STRING_ATTRS) else {
        return Ok(Vec::new());
    };
    let mut result = Vec::new();
    let mut pos = 0;
    while pos < bytes.len() {
        let key_end = bytes[pos..]
            .iter()
            .position(|byte| *byte == 0)
            .map(|n| pos + n)
            .ok_or_else(|| corrupt("unterminated key in MIT STRING_ATTRS"))?;
        let value_start = key_end + 1;
        let value_end = bytes[value_start..]
            .iter()
            .position(|byte| *byte == 0)
            .map(|n| value_start + n)
            .ok_or_else(|| corrupt("unterminated value in MIT STRING_ATTRS"))?;
        result.push((
            bytes[pos..key_end].to_vec(),
            bytes[value_start..value_end].to_vec(),
        ));
        pos = value_end + 1;
    }
    Ok(result)
}

fn put_attr_pairs(entry: &mut MitEntry, pairs: &[(Vec<u8>, Vec<u8>)]) {
    if !pairs.is_empty() || bytes_tl(entry, STRING_ATTRS).is_some() {
        let mut data = Vec::new();
        for (key, value) in pairs {
            data.extend_from_slice(key);
            data.push(0);
            data.extend_from_slice(value);
            data.push(0);
        }
        set_tl(entry, STRING_ATTRS, Some(data));
    }
}

fn set_string_attr(
    entry: &mut MitEntry,
    key: &[u8],
    value: Option<&[u8]>,
) -> Result<(), StoreError> {
    let mut pairs = attr_pairs(entry)?;
    let mut found = false;
    for pair in &mut pairs {
        if pair.0 == key {
            found = true;
            if let Some(value) = value {
                pair.1 = value.to_vec();
            }
        }
    }
    match value {
        None => pairs.retain(|(old_key, _)| old_key != key),
        Some(value) if !found => pairs.push((key.to_vec(), value.to_vec())),
        Some(_) => {}
    }
    put_attr_pairs(entry, &pairs);
    Ok(())
}

/// Decode the NUL-terminated key/value list in `STRING_ATTRS`.
pub fn string_attributes(entry: &MitEntry) -> Result<Vec<StringAttribute>, StoreError> {
    attr_pairs(entry)
}

/// Decode one constrained-delegation ACL name per `tl_data` item.
pub fn constrained_delegation_values(entry: &MitEntry) -> Result<Vec<String>, StoreError> {
    entry
        .tl_data
        .iter()
        .filter(|tl| tl.kind == CONSTRAINED_DELEGATION_ACL)
        .map(|tl| {
            let Some(name) = tl.data.strip_suffix(&[0]) else {
                return Err(corrupt(
                    "MIT constrained-delegation ACL lacks a NUL terminator",
                ));
            };
            if name.contains(&0) {
                return Err(corrupt("embedded NUL in MIT constrained-delegation ACL"));
            }
            String::from_utf8(name.to_vec())
                .map_err(|_| corrupt("MIT constrained-delegation name is not UTF-8"))
        })
        .collect()
}

fn mod_principal_data(entry: &MitEntry) -> Result<Option<(u32, Vec<u8>)>, StoreError> {
    let Some(bytes) = bytes_tl(entry, MOD_PRINC) else {
        return Ok(None);
    };
    if bytes.len() < 5 || bytes.last() != Some(&0) || bytes[4..bytes.len() - 1].contains(&0) {
        return Err(corrupt("malformed MIT MOD_PRINC tl-data"));
    }
    let mut timestamp = [0; 4];
    timestamp.copy_from_slice(&bytes[..4]);
    let timestamp = u32::from_le_bytes(timestamp);
    Ok(Some((timestamp, bytes[4..bytes.len() - 1].to_vec())))
}

fn policy_and_history_from_tl(
    entry: &MitEntry,
) -> Result<(Option<String>, PasswordHistory), StoreError> {
    let Some(bytes) = bytes_tl(entry, KADM_DATA) else {
        return Ok((None, PasswordHistory::default()));
    };
    let osa = OsaPrincipalData::decode(bytes)?;
    let history = PasswordHistory {
        admin_history_kvno: osa.admin_history_kvno,
        old_key_next: osa.old_key_next,
        old_keys: osa.old_keys,
    };
    if osa.aux_attributes & KADM5_POLICY == 0 {
        return Ok((None, history));
    }
    let name = osa
        .policy
        .ok_or_else(|| corrupt("MIT KADM_DATA policy bit set without a policy name"))?;
    let name =
        String::from_utf8(name).map_err(|_| corrupt("MIT KADM_DATA policy name is not UTF-8"))?;
    Ok((Some(name), history))
}

/// A kadm5 password-history entry for `entry`'s current password: each key
/// of the highest kvno, re-encrypted in the history key with its salt
/// (`create_history_entry`, `lib/kadm5/srv/svr_principal.c:1003-1062`). MIT
/// passes a keysalt there, so every entry is key-data version 2.
pub fn history_entry(
    entry: &PrincipalEntry,
    hist_key: &EncryptionKey,
) -> Result<Vec<KeyData>, StoreError> {
    let Some(kvno) = entry.current_kvno() else {
        return Ok(Vec::new());
    };
    entry
        .keys
        .iter()
        .filter(|key| key.kvno == kvno)
        .map(|key| {
            let mut data = key_data_from_entry(entry, key, hist_key)?;
            if data.fields.len() == 1 {
                data.fields.push((0, Vec::new()));
            }
            data.ver = 2;
            Ok(data)
        })
        .collect()
}

/// Whether a history key-data decrypts, with any of `hist_keys`, to `key`
/// (`check_pw_reuse`, `svr_principal.c:925-969`; keys that fail to decrypt
/// are skipped).
pub fn history_key_matches(
    data: &KeyData,
    hist_keys: &[EncryptionKey],
    key: &EncryptionKey,
) -> bool {
    let Some((etype, ciphertext)) = data.fields.first() else {
        return false;
    };
    i32::from(*etype) == key.keytype
        && hist_keys.iter().any(|hist_key| {
            decrypt_key(hist_key, key.keytype, ciphertext)
                .is_ok_and(|old| old.key_bytes() == key.key_bytes())
        })
}

/// Map MIT's key-data salt rules (`lib/kdb/kdb5.c:2345-2376`).
///
/// MIT computes NORMAL, NOREALM, and ONLYREALM salts from the principal.
/// SPECIAL stores its bytes. V4, AFS3, and other salt types remain available
/// verbatim; MIT reports `KRB5_KDB_BAD_SALTTYPE` only when asked to compute one.
fn key_salt_from_data(
    data: &KeyData,
    principal: &PrincipalName,
    realm: &str,
) -> Result<Option<Vec<u8>>, StoreError> {
    match data.ver {
        1 => Ok(None),
        2 => {
            let Some((salt_type, contents)) = data.fields.get(1) else {
                return Err(corrupt("MIT version-2 key-data has no salt field"));
            };
            match *salt_type {
                0 => Ok(None),
                2 => Ok(Some(salt_bytes(principal, realm, SaltType::NoRealm))),
                3 => Ok(Some(realm.as_bytes().to_vec())),
                _ => Ok(Some(contents.clone())),
            }
        }
        _ => Err(corrupt("unsupported MIT key-data version")),
    }
}

/// Decrypt MIT key-data and map the salt using `krb5_dbe_compute_salt`
/// (`lib/kdb/decrypt_key.c:58-116`, `lib/kdb/kdb5.c:2345-2376`).
fn key_from_data(
    data: &KeyData,
    principal: &PrincipalName,
    realm: &str,
    master: &EncryptionKey,
) -> Result<KeyEntry, StoreError> {
    let Some((etype, ciphertext)) = data.fields.first() else {
        return Err(corrupt("MIT key-data record has no key field"));
    };
    let etype = i32::from(*etype);
    let key = decrypt_key(master, etype, ciphertext)?;
    let salt = key_salt_from_data(data, principal, realm)?;
    Ok(KeyEntry {
        kvno: u32::from(data.kvno),
        key,
        salt,
        s2kparams: None,
    })
}

/// Encrypt a key using MIT's one-field/version-1 or two-field/version-2
/// layout (`lib/kdb/encrypt_key.c:60-111`).
fn key_data_from_entry(
    entry: &PrincipalEntry,
    key: &KeyEntry,
    master: &EncryptionKey,
) -> Result<KeyData, StoreError> {
    let kvno =
        u16::try_from(key.kvno).map_err(|_| StoreError::backend("MIT key version exceeds u16"))?;
    let etype = i16::try_from(key.key.keytype)
        .map_err(|_| StoreError::backend("MIT enctype exceeds i16"))?;
    let encrypted = encrypt_key(master, &key.key)?;
    let (ver, salt_field) = match &key.salt {
        None => (1, None),
        Some(salt) if *salt == salt_bytes(&entry.name, &entry.realm, SaltType::Normal) => (1, None),
        Some(salt) if *salt == salt_bytes(&entry.name, &entry.realm, SaltType::NoRealm) => {
            (2, Some((2, salt.clone())))
        }
        Some(salt) if *salt == salt_bytes(&entry.name, &entry.realm, SaltType::OnlyRealm) => {
            (2, Some((3, salt.clone())))
        }
        Some(salt) => (2, Some((4, salt.clone()))),
    };
    let mut fields = vec![(etype, encrypted)];
    if let Some(salt) = salt_field {
        fields.push(salt);
    }
    Ok(KeyData { ver, kvno, fields })
}

fn reusable_key_data(
    old: &KeyData,
    key: &KeyEntry,
    entry: &PrincipalEntry,
    master: &EncryptionKey,
) -> bool {
    let Some((etype, ciphertext)) = old.fields.first() else {
        return false;
    };
    let Ok(old_salt) = key_salt_from_data(old, &entry.name, &entry.realm) else {
        return false;
    };
    if old.kvno != u16::try_from(key.kvno).unwrap_or(u16::MAX)
        || i32::from(*etype) != key.key.keytype
        || old_salt != key.salt
    {
        return false;
    }
    decrypt_key(master, key.key.keytype, ciphertext)
        .is_ok_and(|decoded| decoded.key_bytes() == key.key.key_bytes())
}

fn update_keys(
    entry: &mut MitEntry,
    record: &PrincipalRecord,
    keys: &MasterKeys,
) -> Result<bool, StoreError> {
    let (active_kvno, active) = keys.active()?;
    let old_mkvno = mkvno(entry)?;
    let old_master = keys.get(old_mkvno);
    let mut remaining = entry.key_data.clone();
    let mut updated = Vec::with_capacity(record.entry.keys.len());
    let mut reencrypted = false;
    let mut retained = Vec::new();
    for key in &record.entry.keys {
        let reused = old_master.and_then(|master| {
            remaining
                .iter()
                .position(|old| reusable_key_data(old, key, &record.entry, master))
        });
        if let Some(index) = reused {
            retained.push(updated.len());
            updated.push(remaining.remove(index));
        } else {
            reencrypted = true;
            updated.push(key_data_from_entry(&record.entry, key, active)?);
        }
    }
    if reencrypted && old_mkvno != active_kvno {
        // Every key must be wrapped by the master key named in MKVNO; retained
        // key data keeps its version and salt field (`master_key_convert`).
        if let Some(old) = old_master {
            for at in retained {
                rewrap_key_data(&mut updated[at], old, active)?;
            }
        }
    }
    entry.key_data = updated;
    Ok(reencrypted)
}

/// `krb5_dbe_update_mod_princ_data`: set `KRB5_TL_MOD_PRINC`.
pub fn set_mod_princ(entry: &mut MitEntry, seconds: u32, mod_by: &[u8]) -> Result<(), StoreError> {
    update_mod_principal(
        entry,
        Some(kerberos_time(i64::from(seconds))),
        Some(mod_by),
        None,
    )
}

fn update_mod_principal(
    entry: &mut MitEntry,
    stamp: Option<KerberosTime>,
    mod_by: Option<&[u8]>,
    creator: Option<&[u8]>,
) -> Result<(), StoreError> {
    let stamp = match stamp {
        Some(stamp) => stamp,
        None if creator.is_some() => kerberos_time(Utc::now().timestamp()),
        None => return Ok(()),
    };
    let seconds = u32::try_from(stamp.timestamp())
        .map_err(|_| StoreError::backend("MIT MOD_PRINC timestamp outside u32 range"))?;
    let bytes = if let Some(existing) = bytes_tl(entry, MOD_PRINC) {
        if existing.len() < 5
            || existing.last() != Some(&0)
            || existing[4..existing.len() - 1].contains(&0)
        {
            return Err(corrupt("malformed MIT MOD_PRINC tl-data"));
        }
        let mut updated = existing.to_vec();
        updated[..4].copy_from_slice(&seconds.to_le_bytes());
        if let Some(mod_by) = mod_by {
            if mod_by.contains(&0) {
                return Err(StoreError::backend("NUL in MIT modifier principal"));
            }
            updated.truncate(4);
            updated.extend_from_slice(mod_by);
            updated.push(0);
        }
        updated
    } else {
        let creator = mod_by
            .or(creator)
            .ok_or_else(|| corrupt("new MIT record has no creator principal"))?;
        let mut data = seconds.to_le_bytes().to_vec();
        data.extend_from_slice(creator);
        data.push(0);
        data
    };
    set_tl(entry, MOD_PRINC, Some(bytes));
    Ok(())
}

/// Map an MIT entry to the KDC model. `security_epoch` and key
/// `s2kparams` are krb5-rs extensions with no klmdb representation, so reads
/// return zero and `None`; lockout values come from the separate lockout record.
pub fn record_from_entry(
    entry: &MitEntry,
    keys: &MasterKeys,
) -> Result<PrincipalRecord, StoreError> {
    let mkvno = mkvno(entry)?;
    let master = keys.get(mkvno).ok_or_else(|| {
        StoreError::backend(format!(
            "No matching key in entry (master key version {mkvno})"
        ))
    })?;
    let keys = entry
        .key_data
        .iter()
        .map(|data| key_from_data(data, &entry.principal, &entry.realm, master))
        .collect::<Result<Vec<_>, _>>()?;
    let mut allowed_to_delegate_from = Vec::new();
    if let Some((_, value)) = attr_pairs(entry)?
        .into_iter()
        .find(|(key, _)| key == ALLOWED_TO_DELEGATE_FROM)
    {
        let value = String::from_utf8(value)
            .map_err(|_| corrupt("krb5rs delegation attribute is not UTF-8"))?;
        if !value.is_empty() {
            allowed_to_delegate_from.extend(value.split(',').map(str::to_owned));
        }
    }
    let last_pwd_change =
        get_u32_tl(entry, LAST_PWD_CHANGE)?.map(|time| kerberos_time(i64::from(time)));
    let (mod_time, mod_by) = match mod_principal_data(entry)? {
        Some((time, principal)) => {
            let _ = parse_name(&principal)?;
            (Some(kerberos_time(i64::from(time))), Some(principal))
        }
        None => (None, None),
    };
    let last_admin_unlock =
        get_u32_tl(entry, LAST_ADMIN_UNLOCK)?.map(|time| kerberos_time(i64::from(time)));
    let (policy, password_history) = policy_and_history_from_tl(entry)?;
    Ok(PrincipalRecord {
        entry: PrincipalEntry {
            name: entry.principal.clone(),
            realm: entry.realm.clone(),
            attributes: PrincipalAttributes::from_bits_retain(entry.attributes),
            max_life: (entry.max_life != 0).then(|| Duration::from_secs(u64::from(entry.max_life))),
            max_renewable_life: (entry.max_renewable_life != 0)
                .then(|| Duration::from_secs(u64::from(entry.max_renewable_life))),
            expiration: from_timestamp(entry.expiration),
            pw_expiration: from_timestamp(entry.pw_expiration),
            keys,
            allowed_to_delegate_to: constrained_delegation_values(entry)?,
            allowed_to_delegate_from,
            policy,
            security_epoch: 0,
            last_admin_unlock,
        },
        last_pwd_change,
        mod_time,
        mod_by,
        password_history: Some(password_history),
    })
}

/// Write the policy and, when given, the password history into
/// `KRB5_TL_KADM_DATA`, keeping its other fields.
fn update_kadm_data(
    entry: &mut MitEntry,
    policy: Option<&str>,
    history: Option<&PasswordHistory>,
) -> Result<(), StoreError> {
    let old = bytes_tl(entry, KADM_DATA);
    let empty_history = history.is_none_or(|h| *h == PasswordHistory::default());
    if old.is_none() && policy.is_none() && empty_history {
        return Ok(());
    }
    let mut osa = match old {
        Some(bytes) => OsaPrincipalData::decode(bytes)?,
        None => OsaPrincipalData::default(),
    };
    match policy {
        Some(name) => {
            if name.as_bytes().contains(&0) {
                return Err(StoreError::backend("NUL in MIT policy name"));
            }
            osa.policy = Some(name.as_bytes().to_vec());
            osa.aux_attributes |= KADM5_POLICY;
        }
        None => {
            osa.policy = None;
            osa.aux_attributes &= !KADM5_POLICY;
        }
    }
    if let Some(history) = history {
        osa.admin_history_kvno = history.admin_history_kvno;
        osa.old_key_next = history.old_key_next;
        osa.old_keys = history.old_keys.clone();
    }
    set_tl(entry, KADM_DATA, Some(osa.encode()?));
    Ok(())
}

fn update_string_attrs(entry: &mut MitEntry, names: &[String]) -> Result<(), StoreError> {
    let value = if names.is_empty() {
        None
    } else {
        let mut joined = Vec::new();
        for (i, name) in names.iter().enumerate() {
            if i != 0 {
                joined.push(b',');
            }
            if name.as_bytes().contains(&0) {
                return Err(StoreError::backend("NUL in delegation principal"));
            }
            joined.extend_from_slice(name.as_bytes());
        }
        Some(joined)
    };
    set_string_attr(entry, ALLOWED_TO_DELEGATE_FROM, value.as_deref())
}

/// Merge supported krb5-rs fields into an existing raw MIT entry. MIT fields
/// not represented in `PrincipalRecord` remain in the raw tl-data/key-data.
/// Unchanged key records are reused verbatim, retaining their salt type;
/// regenerated keys use the supported krb5-rs salt types.
pub fn merge_record(
    entry: &mut MitEntry,
    record: &PrincipalRecord,
    keys: &MasterKeys,
    new_record_creator: Option<&[u8]>,
) -> Result<(), StoreError> {
    entry.principal = record.entry.name.clone();
    entry.realm = record.entry.realm.clone();
    entry.attributes = record.entry.attributes.bits();
    entry.max_life = duration(record.entry.max_life)?;
    entry.max_renewable_life = duration(record.entry.max_renewable_life)?;
    entry.expiration = timestamp(record.entry.expiration)?;
    entry.pw_expiration = timestamp(record.entry.pw_expiration)?;

    set_tl(
        entry,
        LAST_PWD_CHANGE,
        record
            .last_pwd_change
            .map(|time| timestamp(Some(time)))
            .transpose()?
            .map(u32::to_le_bytes)
            .map(Vec::from),
    );
    update_mod_principal(
        entry,
        record.mod_time,
        record.mod_by.as_deref(),
        new_record_creator,
    )?;
    set_tl(
        entry,
        LAST_ADMIN_UNLOCK,
        record
            .entry
            .last_admin_unlock
            .map(|time| timestamp(Some(time)))
            .transpose()?
            .map(u32::to_le_bytes)
            .map(Vec::from),
    );

    entry
        .tl_data
        .retain(|tl| tl.kind != CONSTRAINED_DELEGATION_ACL);
    for principal in &record.entry.allowed_to_delegate_to {
        if principal.as_bytes().contains(&0) {
            return Err(StoreError::backend("NUL in constrained-delegation name"));
        }
        let mut data = principal.as_bytes().to_vec();
        data.push(0);
        entry.tl_data.push(TlData {
            kind: CONSTRAINED_DELEGATION_ACL,
            data,
        });
    }
    update_string_attrs(entry, &record.entry.allowed_to_delegate_from)?;
    update_kadm_data(
        entry,
        record.entry.policy.as_deref(),
        record.password_history.as_ref(),
    )?;
    let reencrypted_keys = update_keys(entry, record, keys)?;
    if reencrypted_keys {
        let (active_kvno, _) = keys.active()?;
        set_tl(entry, MKVNO, Some(active_kvno.to_le_bytes().to_vec()));
    } else {
        let _ = mkvno(entry)?;
    }
    Ok(())
}

/// Make a new MIT entry from a store record.
pub fn new_entry(
    record: &PrincipalRecord,
    keys: &MasterKeys,
    creator: &[u8],
) -> Result<MitEntry, StoreError> {
    let mut entry = MitEntry {
        principal: record.entry.name.clone(),
        realm: record.entry.realm.clone(),
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
    merge_record(&mut entry, record, keys, Some(creator))?;
    Ok(entry)
}

/// Merge the exposed `Policy` fields, keeping MIT's policy tl-data.
pub fn merge_policy(entry: &mut MitPolicy, policy: &Policy) -> Result<(), StoreError> {
    entry.name = policy.name.clone();
    entry.pw_min_life = policy.pw_min_life;
    entry.pw_max_life = policy.pw_max_life;
    entry.pw_min_length = policy.pw_min_length;
    entry.pw_min_classes = policy.pw_min_classes;
    entry.pw_history_num = policy.pw_history_num;
    entry.pw_max_fail = policy.pw_max_fail;
    entry.pw_failcnt_interval = policy.pw_failcnt_interval;
    entry.pw_lockout_duration = policy.pw_lockout_duration;
    entry.attributes = policy.attributes;
    entry.max_life = policy.max_life;
    entry.max_renewable_life = policy.max_renewable_life;
    entry.allowed_keysalts = policy.allowed_keysalts.clone();
    Ok(())
}

/// Map MIT policy fields to the krb5-rs KDC policy model.
pub fn policy_from_entry(entry: &MitPolicy) -> Policy {
    Policy {
        name: entry.name.clone(),
        pw_min_life: entry.pw_min_life,
        pw_max_life: entry.pw_max_life,
        pw_min_length: entry.pw_min_length,
        pw_min_classes: entry.pw_min_classes,
        pw_history_num: entry.pw_history_num,
        pw_max_fail: entry.pw_max_fail,
        pw_failcnt_interval: entry.pw_failcnt_interval,
        pw_lockout_duration: entry.pw_lockout_duration,
        attributes: entry.attributes,
        max_life: entry.max_life,
        max_renewable_life: entry.max_renewable_life,
        allowed_keysalts: entry.allowed_keysalts.clone(),
        security_epoch: 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kdc::db::KeyEntry;
    use crate::kdc::kdb::master::{encrypt_key, master_key_from_password};
    use crate::kdc::kdb::mit::codec::encode_lockout;

    fn principal_entry(principal: PrincipalName, realm: &str) -> PrincipalEntry {
        PrincipalEntry {
            name: principal,
            realm: realm.to_owned(),
            attributes: PrincipalAttributes::empty(),
            max_life: None,
            max_renewable_life: None,
            expiration: None,
            pw_expiration: None,
            keys: Vec::new(),
            allowed_to_delegate_to: Vec::new(),
            allowed_to_delegate_from: Vec::new(),
            policy: None,
            security_epoch: 0,
            last_admin_unlock: None,
        }
    }

    fn encrypted_key_data(
        master: &EncryptionKey,
        key: &EncryptionKey,
        ver: u16,
        salt_type: i16,
        salt: &[u8],
    ) -> KeyData {
        let mut fields = vec![(
            key.keytype as i16,
            encrypt_key(master, key).expect("encrypt"),
        )];
        if ver == 2 {
            fields.push((salt_type, salt.to_vec()));
        }
        KeyData {
            ver,
            kvno: 1,
            fields,
        }
    }

    fn name(component: &[u8]) -> PrincipalName {
        PrincipalName {
            name_type: 1,
            name_string: vec![GeneralString::from_bytes(component).expect("principal")],
        }
    }

    fn test_entry(master: &EncryptionKey) -> MitEntry {
        let key = EncryptionKey::new(18, vec![0x45; 32]);
        let osa = OsaPrincipalData {
            policy: Some(b"old-policy".to_vec()),
            aux_attributes: KADM5_POLICY | 0x40,
            old_key_next: 17,
            admin_history_kvno: 9,
            old_keys: vec![vec![KeyData {
                ver: 1,
                kvno: 4,
                fields: vec![(18, vec![0x11, 0x22])],
            }]],
        };
        let mut mod_princ = 20u32.to_le_bytes().to_vec();
        mod_princ.extend_from_slice(b"db_creation@R\0");
        let mut strings = b"foreign\0keep-me\0".to_vec();
        strings.extend_from_slice(ALLOWED_TO_DELEGATE_FROM);
        strings.extend_from_slice(b"\0HTTP/client@R,host/a@R\0");
        MitEntry {
            principal: name(b"alice"),
            realm: "R".into(),
            attributes: 0x4000_0040,
            max_life: 3600,
            max_renewable_life: 7200,
            expiration: 0,
            pw_expiration: 50,
            last_success: 1,
            last_failed: 2,
            fail_auth_count: 3,
            tl_data: vec![
                TlData {
                    kind: 0x7777,
                    data: vec![1, 2, 3],
                },
                TlData {
                    kind: LAST_PWD_CHANGE,
                    data: 10u32.to_le_bytes().to_vec(),
                },
                TlData {
                    kind: MOD_PRINC,
                    data: mod_princ,
                },
                TlData {
                    kind: LAST_ADMIN_UNLOCK,
                    data: 30u32.to_le_bytes().to_vec(),
                },
                TlData {
                    kind: CONSTRAINED_DELEGATION_ACL,
                    data: b"HTTP/service@R\0".to_vec(),
                },
                TlData {
                    kind: STRING_ATTRS,
                    data: strings,
                },
                TlData {
                    kind: KADM_DATA,
                    data: osa.encode().expect("KADM_DATA"),
                },
                TlData {
                    kind: 0x0009,
                    data: vec![1, 0, 4, 0, 0, 0],
                },
                TlData {
                    kind: 0x000a,
                    data: vec![4, 3, 2, 1],
                },
            ],
            key_data: vec![KeyData {
                ver: 1,
                kvno: 5,
                fields: vec![(18, encrypt_key(master, &key).expect("key encryption"))],
            }],
        }
    }

    #[test]
    fn record_mapping_and_modify_preserve_unowned_mit_data() {
        let master = master_key_from_password("R", "master", 18).expect("master key");
        let mut entry = test_entry(&master);
        let original_unknown = entry
            .tl_data
            .iter()
            .find(|tl| tl.kind == 0x7777)
            .expect("unknown tl-data")
            .clone();
        let original_actkvno = bytes_tl(&entry, 0x0009).expect("ACTKVNO").to_vec();
        let original_mkey_aux = bytes_tl(&entry, 0x000a).expect("MKEY_AUX").to_vec();
        let original_mod_by = mod_principal_data(&entry)
            .expect("MOD_PRINC")
            .expect("MOD_PRINC exists")
            .1;
        let original_osa =
            OsaPrincipalData::decode(bytes_tl(&entry, KADM_DATA).expect("KADM_DATA")).expect("OSA");

        let mut record =
            record_from_entry(&entry, &MasterKeys::single(master.clone())).expect("map record");
        assert_eq!(record.entry.attributes.bits(), 0x4000_0040);
        assert_eq!(record.entry.policy.as_deref(), Some("old-policy"));
        assert_eq!(record.entry.keys[0].key.key_bytes(), &[0x45; 32]);
        assert_eq!(
            record.entry.allowed_to_delegate_to,
            vec!["HTTP/service@R".to_owned()]
        );
        assert_eq!(
            record.entry.allowed_to_delegate_from,
            vec!["HTTP/client@R".to_owned(), "host/a@R".to_owned()]
        );
        assert_eq!(record.mod_time, Some(kerberos_time(20)));
        assert_eq!(record.last_pwd_change, Some(kerberos_time(10)));
        assert_eq!(record.entry.last_admin_unlock, Some(kerberos_time(30)));

        record.entry.attributes |= PrincipalAttributes::LOCKDOWN_KEYS;
        record.entry.max_life = Some(Duration::from_secs(123));
        record.entry.policy = Some("new-policy".into());
        record.mod_time = Some(kerberos_time(99));
        merge_record(
            &mut entry,
            &record,
            &MasterKeys::single(master.clone()),
            None,
        )
        .expect("merge");

        assert_eq!(entry.attributes, 0x4080_0040);
        assert_eq!(entry.max_life, 123);
        assert_eq!(
            entry.tl_data.iter().find(|tl| tl.kind == 0x7777),
            Some(&original_unknown)
        );
        assert_eq!(bytes_tl(&entry, 0x0009), Some(original_actkvno.as_slice()));
        assert_eq!(bytes_tl(&entry, 0x000a), Some(original_mkey_aux.as_slice()));
        assert_eq!(
            mod_principal_data(&entry)
                .expect("MOD_PRINC")
                .expect("MOD_PRINC exists")
                .0,
            99
        );
        assert_eq!(
            mod_principal_data(&entry)
                .expect("MOD_PRINC")
                .expect("MOD_PRINC exists")
                .1,
            original_mod_by
        );

        let updated_osa = OsaPrincipalData::decode(bytes_tl(&entry, KADM_DATA).expect("KADM_DATA"))
            .expect("updated OSA");
        assert_eq!(
            updated_osa.policy.as_deref(),
            Some(b"new-policy".as_slice())
        );
        assert_eq!(updated_osa.aux_attributes, original_osa.aux_attributes);
        assert_eq!(updated_osa.old_key_next, original_osa.old_key_next);
        assert_eq!(
            updated_osa.admin_history_kvno,
            original_osa.admin_history_kvno
        );
        assert_eq!(updated_osa.old_keys, original_osa.old_keys);
        assert!(string_attributes(&entry)
            .expect("string attributes")
            .contains(&(b"foreign".to_vec(), b"keep-me".to_vec())));
        assert_eq!(
            encode_lockout(entry.last_success, entry.last_failed, entry.fail_auth_count),
            [1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0]
        );
        assert_eq!(entry.key_data[0].kvno, 5);
    }

    #[test]
    fn mapping_documents_the_non_persisted_extensions() {
        let master = master_key_from_password("R", "master", 18).expect("master key");
        let entry = test_entry(&master);
        let record =
            record_from_entry(&entry, &MasterKeys::single(master.clone())).expect("map record");
        assert_eq!(record.entry.security_epoch, 0);
        assert!(record.entry.keys.iter().all(|key| key.s2kparams.is_none()));
    }

    #[test]
    fn retained_keys_keep_their_salt_fields_when_the_master_key_changes() {
        use crate::kdc::kdb::mit::mkey::ActKvno;
        let m1 = master_key_from_password("R", "master", 18).expect("m1");
        let m2 = master_key_from_password("R", "second", 18).expect("m2");
        let keys = MasterKeys {
            keys: vec![(2, m2.clone()), (1, m1.clone())],
            actkvno: vec![
                ActKvno {
                    kvno: 1,
                    act_time: 0,
                },
                ActKvno {
                    kvno: 2,
                    act_time: 0,
                },
            ],
        };
        let mut entry = test_entry(&m1);
        entry.key_data = vec![encrypted_key_data(
            &m1,
            &EncryptionKey::new(18, vec![0x5a; 32]),
            2,
            5,
            b"x",
        )];
        let mut record = record_from_entry(&entry, &keys).expect("record");
        let mut added = record.entry.keys[0].clone();
        added.kvno += 1;
        added.key = EncryptionKey::new(18, vec![0x6b; 32]);
        record.entry.keys.insert(0, added);
        merge_record(&mut entry, &record, &keys, None).expect("merge");
        assert_eq!(mkvno(&entry).expect("mkvno"), 2);
        let retained = entry
            .key_data
            .iter()
            .find(|k| k.fields.get(1) == Some(&(5, b"x".to_vec())))
            .expect("salt type 5 kept");
        let key = decrypt_key(&m2, 18, &retained.fields[0].1).expect("rewrapped");
        assert_eq!(key.key_bytes(), &[0x5a; 32][..]);
    }

    #[test]
    fn mit_salt_types_read_and_write_using_kdb_compute_salt_rules() {
        let master = master_key_from_password("R", "master", 18).expect("master");
        let name = name(b"alice");
        let principal = principal_entry(name.clone(), "R");
        let key = EncryptionKey::new(18, vec![0x5a; 32]);
        let normal = salt_bytes(&name, "R", SaltType::Normal);
        let no_realm = salt_bytes(&name, "R", SaltType::NoRealm);
        let only_realm = b"R".to_vec();
        let special = vec![0, 0xff, 0x42];

        let v1 = encrypted_key_data(&master, &key, 1, 0, &[]);
        assert_eq!(
            key_from_data(&v1, &name, "R", &master)
                .expect("v1 key")
                .salt,
            None
        );
        for (salt_type, contents, expected) in [
            (0, vec![], None),
            (0, vec![7], None),
            (1, vec![1, 2], Some(vec![1, 2])),
            (2, vec![7], Some(no_realm.clone())),
            (3, vec![7], Some(only_realm.clone())),
            (4, special.clone(), Some(special.clone())),
            (5, vec![5, 6], Some(vec![5, 6])),
            (99, vec![9], Some(vec![9])),
        ] {
            let raw = encrypted_key_data(&master, &key, 2, salt_type, &contents);
            let decoded = key_from_data(&raw, &name, "R", &master).expect("salt mapping");
            assert_eq!(decoded.salt, expected, "salt type {salt_type}");
            assert!(
                reusable_key_data(&raw, &decoded, &principal, &master),
                "raw salt type {salt_type} should be reusable"
            );
        }

        let with_key = principal.clone();
        let make_key = |salt| KeyEntry {
            kvno: 1,
            key: key.clone(),
            salt,
            s2kparams: None,
        };
        let cases = [
            (None, 1, None),
            (Some(normal.clone()), 1, None),
            (Some(no_realm.clone()), 2, Some((2, no_realm))),
            (Some(only_realm.clone()), 2, Some((3, only_realm))),
            (Some(special.clone()), 2, Some((4, special))),
        ];
        for (salt, expected_ver, expected_salt_field) in cases {
            let encoded =
                key_data_from_entry(&with_key, &make_key(salt), &master).expect("salt encoding");
            assert_eq!(encoded.ver, expected_ver);
            assert_eq!(encoded.fields.len(), usize::from(expected_ver));
            if let Some(expected) = expected_salt_field {
                assert_eq!(encoded.fields[1], expected);
            }
        }
    }

    #[test]
    fn new_principal_uses_the_requested_creator_and_all_known_key_salts() {
        let master = master_key_from_password("R", "master", 18).expect("master key");
        let entry = PrincipalEntry {
            name: name(b"svc"),
            realm: "R".into(),
            attributes: PrincipalAttributes::empty(),
            max_life: None,
            max_renewable_life: None,
            expiration: None,
            pw_expiration: None,
            keys: vec![KeyEntry {
                kvno: 1,
                key: EncryptionKey::new(18, vec![7; 32]),
                salt: Some(salt_bytes(&name(b"svc"), "R", SaltType::NoRealm)),
                s2kparams: None,
            }],
            allowed_to_delegate_to: Vec::new(),
            allowed_to_delegate_from: Vec::new(),
            policy: None,
            security_epoch: 0,
            last_admin_unlock: None,
        };
        let record = PrincipalRecord {
            entry,
            last_pwd_change: None,
            mod_time: Some(kerberos_time(42)),
            mod_by: None,
            password_history: None,
        };
        let creator = unparse_name(&name(b"db_creation"), "R");
        let entry =
            new_entry(&record, &MasterKeys::single(master.clone()), &creator).expect("new entry");
        assert_eq!(entry.key_data[0].ver, 2);
        assert_eq!(entry.key_data[0].fields[1].0, 2);
        assert_eq!(
            mod_principal_data(&entry)
                .expect("MOD_PRINC")
                .expect("MOD_PRINC exists")
                .1,
            creator
        );
    }
}
