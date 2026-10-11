//! Master key handling: password derivation, key encryption for storage and
//! the stash file.

use std::path::{Path, PathBuf};

use rasn::types::GeneralString;

use crate::crypto::find_etype;
use crate::kdc::store::StoreError;
use crate::keytab::{FileKeytab, Keytab, KeytabEntry};
use crate::protocol::preauth::default_salt;
use crate::types::{EncryptionKey, PrincipalName};

/// MIT `KRB5_KDB_M_NAME`.
const MASTER_NAME: &str = "K/M";

fn err(msg: impl Into<String>) -> StoreError {
    StoreError::backend(msg)
}

/// The master principal `K/M@REALM` name components.
pub(super) fn master_principal() -> Result<PrincipalName, StoreError> {
    let part = |s: &str| GeneralString::from_bytes(s.as_bytes()).map_err(|_| err("bad name"));
    Ok(PrincipalName {
        name_type: 1,
        name_string: MASTER_NAME.split('/').map(part).collect::<Result<_, _>>()?,
    })
}

/// Master key from the master password: `string_to_key` with the normal
/// salt of `K/M@REALM` (MIT `krb5_db_fetch_mkey`, kdb5.c:1246-1251, i.e.
/// `krb5_principal2salt`: `REALMKM`).
pub fn master_key_from_password(
    realm: &str,
    password: &str,
    etype: i32,
) -> Result<EncryptionKey, StoreError> {
    let profile =
        find_etype(etype).map_err(|_| err(format!("unsupported master key enctype {etype}")))?;
    let salt = default_salt(realm, &[b"K".as_slice(), b"M".as_slice()]);
    let key = profile
        .string_to_key(password.as_bytes(), &salt, None)
        .map_err(|e| err(e.to_string()))?;
    Ok(EncryptionKey::new(etype, key.to_vec()))
}

/// Encrypt a key for storage under the master key (MIT
/// `krb5_dbe_def_encrypt_key_data`,
/// encrypt_key.c:36-95): 2-byte little-endian key length, then the key
/// encrypted under the master key with usage 0.
pub fn encrypt_key(master: &EncryptionKey, key: &EncryptionKey) -> Result<Vec<u8>, StoreError> {
    let profile = find_etype(master.keytype).map_err(|_| err("unsupported master key enctype"))?;
    let len = u16::try_from(key.key_bytes().len()).map_err(|_| err("key too long"))?;
    let cipher = profile
        .encrypt(master.key_bytes(), 0, key.key_bytes())
        .map_err(|e| err(e.to_string()))?;
    let mut out = len.to_le_bytes().to_vec();
    out.extend_from_slice(&cipher);
    Ok(out)
}

/// Inverse of [`encrypt_key`] (MIT decrypt_key.c); integrity failure means
/// a wrong master key or a damaged database.
pub fn decrypt_key(
    master: &EncryptionKey,
    enctype: i32,
    blob: &[u8],
) -> Result<EncryptionKey, StoreError> {
    let profile = find_etype(master.keytype).map_err(|_| err("unsupported master key enctype"))?;
    if blob.len() < 2 {
        return Err(err("stored key too short"));
    }
    let want = usize::from(u16::from_le_bytes([blob[0], blob[1]]));
    let plain = profile
        .decrypt(master.key_bytes(), 0, &blob[2..])
        .map_err(|_| err("cannot decrypt stored key: wrong master key or corrupt database"))?;
    if plain.len() < want {
        return Err(err("stored key length mismatch"));
    }
    Ok(EncryptionKey::new(enctype, plain[..want].to_vec()))
}

fn tmp_path(path: &Path) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push("_tmp");
    PathBuf::from(s)
}

/// Write the stash file: a keytab holding `K/M@REALM`, replaced atomically
/// (MIT `krb5_def_store_mkey_list`, kdb_default.c:111-212).
pub fn write_stash(path: &Path, realm: &str, key: &EncryptionKey) -> Result<(), StoreError> {
    let tmp = tmp_path(path);
    let _ = std::fs::remove_file(&tmp);
    let mut kt = FileKeytab::new(&tmp);
    kt.add_entry(&KeytabEntry {
        principal: master_principal()?,
        realm: realm.to_string(),
        timestamp: u32::try_from(chrono::Utc::now().timestamp()).unwrap_or(0),
        kvno: 1,
        key: key.clone(),
    })
    .map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        err(format!("writing stash: {e}"))
    })?;
    std::fs::rename(&tmp, path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        err(format!("renaming stash into place: {e}"))
    })
}

/// Read the master key from a stash file: the keytab format written by
/// [`write_stash`] and MIT 1.22 (kdb_default.c:262-330), or MIT's old raw
/// format (`u16` enctype, `u32` length, key bytes, host byte order — read
/// as little-endian) (kdb_default.c:216-259).
pub fn read_stash(path: &Path, realm: &str) -> Result<EncryptionKey, StoreError> {
    let bytes =
        std::fs::read(path).map_err(|e| err(format!("reading stash {}: {e}", path.display())))?;
    if bytes.first() == Some(&5) {
        let kt = FileKeytab::new(path);
        let entry = kt
            .get_entry(&master_principal()?, realm, None, None)
            .map_err(|e| err(format!("stash has no K/M@{realm}: {e}")))?;
        return Ok(entry.key);
    }
    if bytes.len() < 6 {
        return Err(err("stash file too short"));
    }
    let etype = i32::from(u16::from_le_bytes([bytes[0], bytes[1]]));
    let len = u32::from_le_bytes([bytes[2], bytes[3], bytes[4], bytes[5]]) as usize;
    if len == 0 || len > 1024 || bytes.len() < 6 + len {
        return Err(err("bad stored master key"));
    }
    Ok(EncryptionKey::new(etype, bytes[6..6 + len].to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_key_round_trips_and_detects_wrong_master() {
        let master = master_key_from_password("R", "pw", 18).expect("master");
        let other = master_key_from_password("R", "other", 18).expect("other");
        let key = EncryptionKey::new(17, vec![7; 16]);
        let blob = encrypt_key(&master, &key).expect("encrypt");
        assert_eq!(&blob[..2], &[16, 0]);
        let back = decrypt_key(&master, 17, &blob).expect("decrypt");
        assert_eq!(back.key_bytes(), key.key_bytes());
        assert!(decrypt_key(&other, 17, &blob).is_err());
    }

    #[test]
    fn decrypt_key_rejects_tampered_ciphertext() {
        let master = master_key_from_password("R", "pw", 18).expect("master");
        let mut blob = encrypt_key(&master, &EncryptionKey::new(18, vec![1; 32])).expect("encrypt");
        let last = blob.len() - 1;
        blob[last] ^= 1;
        assert!(decrypt_key(&master, 18, &blob).is_err());
    }

    #[test]
    fn master_key_from_password_uses_realm_km_salt() {
        let key = master_key_from_password("EX.COM", "pw", 18).expect("key");
        let expected = find_etype(18)
            .expect("etype")
            .string_to_key(b"pw", b"EX.COMKM", None)
            .expect("s2k");
        assert_eq!(key.key_bytes(), expected.as_slice());
    }

    #[test]
    fn stash_round_trips_and_reads_old_raw_format() {
        let dir = std::env::temp_dir().join(format!("krb5rs_stash_{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("dir");
        let key = master_key_from_password("R", "pw", 18).expect("key");
        let path = dir.join("stash");
        write_stash(&path, "R", &key).expect("write");
        assert_eq!(
            read_stash(&path, "R").expect("read").key_bytes(),
            key.key_bytes()
        );
        assert!(!tmp_path(&path).exists());

        let mut raw = 18u16.to_le_bytes().to_vec();
        raw.extend_from_slice(&32u32.to_le_bytes());
        raw.extend_from_slice(key.key_bytes());
        let old = dir.join("old");
        std::fs::write(&old, raw).expect("write old");
        let got = read_stash(&old, "R").expect("read old");
        assert_eq!((got.keytype, got.key_bytes()), (18, key.key_bytes()));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
