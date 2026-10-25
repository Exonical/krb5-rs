//! Master-key list, `KRB5_TL_ACTKVNO` and `KRB5_TL_MKEY_AUX` (MIT
//! `lib/kdb/kdb5.c:1145-2060`, `lib/kdb/kdb_default.c:396-470`).

use super::{MitEntry, TlData, ACTKVNO, MKEY_AUX};
use crate::kdc::kdb::master::{decrypt_key, encrypt_key};
use crate::kdc::store::StoreError;
use crate::types::EncryptionKey;

const TL_VERSION: u16 = 1;

fn corrupt(msg: impl Into<String>) -> StoreError {
    StoreError::corrupt(msg)
}

fn tl(entry: &MitEntry, kind: u16) -> Option<&[u8]> {
    entry
        .tl_data
        .iter()
        .find(|tl| tl.kind == kind)
        .map(|tl| tl.data.as_slice())
}

fn put_tl(entry: &mut MitEntry, kind: u16, data: Option<Vec<u8>>) {
    let at = entry.tl_data.iter().position(|tl| tl.kind == kind);
    entry.tl_data.retain(|tl| tl.kind != kind);
    if let Some(data) = data {
        let tl = TlData { kind, data };
        match at {
            Some(at) => entry.tl_data.insert(at.min(entry.tl_data.len()), tl),
            None => entry.tl_data.push(tl),
        }
    }
}

fn u16_at(bytes: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([bytes[at], bytes[at + 1]])
}

/// One `krb5_actkvno_node`: master key `kvno` is active from `act_time`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ActKvno {
    /// Master key version.
    pub kvno: u16,
    /// Activation time, seconds since the epoch.
    pub act_time: u32,
}

/// `krb5_dbe_lookup_actkvno` (`kdb5.c:1908-1996`). Without the tl-data the
/// earliest master key (the last key-data record) is active from time 0.
pub fn lookup_actkvno(entry: &MitEntry) -> Result<Vec<ActKvno>, StoreError> {
    let Some(bytes) = tl(entry, ACTKVNO) else {
        let kvno = entry
            .key_data
            .last()
            .ok_or_else(|| corrupt("K/M has no key"))?
            .kvno;
        return Ok(vec![ActKvno { kvno, act_time: 0 }]);
    };
    if bytes.len() < 2 {
        return Err(corrupt("short KRB5_TL_ACTKVNO"));
    }
    let version = u16_at(bytes, 0);
    if version != TL_VERSION {
        return Err(StoreError::backend(format!(
            "Illegal version number for KRB5_TL_ACTKVNO {version}"
        )));
    }
    if bytes.len() < 8 {
        return Err(corrupt("short KRB5_TL_ACTKVNO"));
    }
    Ok(bytes[2..]
        .as_chunks::<6>()
        .0
        .iter()
        .map(|t| ActKvno {
            kvno: u16_at(t, 0),
            act_time: u32::from_le_bytes([t[2], t[3], t[4], t[5]]),
        })
        .collect())
}

/// `krb5_dbe_update_actkvno` (`kdb5.c:1998-2060`).
pub fn update_actkvno(entry: &mut MitEntry, list: &[ActKvno]) {
    if list.is_empty() {
        put_tl(entry, ACTKVNO, None);
        return;
    }
    let mut data = TL_VERSION.to_le_bytes().to_vec();
    for node in list {
        data.extend_from_slice(&node.kvno.to_le_bytes());
        data.extend_from_slice(&node.act_time.to_le_bytes());
    }
    put_tl(entry, ACTKVNO, Some(data));
}

/// One `krb5_mkey_aux_node`: the latest master key encrypted in master key
/// `mkey_kvno`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MkeyAux {
    /// Version of the master key the latest key is encrypted in.
    pub mkey_kvno: u16,
    /// Version of the latest master key.
    pub latest_kvno: u16,
    /// Enctype of the latest master key.
    pub enctype: i16,
    /// `key_data_contents[0]`: the encrypted latest key.
    pub contents: Vec<u8>,
}

/// `krb5_dbe_lookup_mkey_aux` (`kdb5.c:1741-1821`).
pub fn lookup_mkey_aux(entry: &MitEntry) -> Result<Vec<MkeyAux>, StoreError> {
    let Some(bytes) = tl(entry, MKEY_AUX) else {
        return Ok(Vec::new());
    };
    if bytes.len() < 2 {
        return Err(corrupt("short KRB5_TL_MKEY_AUX"));
    }
    let version = u16_at(bytes, 0);
    if version != TL_VERSION {
        return Err(StoreError::backend(format!(
            "Illegal version number for KRB5_TL_MKEY_AUX {version}"
        )));
    }
    if bytes.len() < 10 {
        return Err(corrupt("short KRB5_TL_MKEY_AUX"));
    }
    let mut out = Vec::new();
    let mut at = 2;
    while at < bytes.len() {
        if bytes.len() - at < 8 {
            return Err(corrupt("truncated KRB5_TL_MKEY_AUX"));
        }
        let len = usize::from(u16_at(bytes, at + 6));
        let start = at + 8;
        let contents = bytes
            .get(start..start + len)
            .ok_or_else(|| corrupt("truncated KRB5_TL_MKEY_AUX"))?
            .to_vec();
        out.push(MkeyAux {
            mkey_kvno: u16_at(bytes, at),
            latest_kvno: u16_at(bytes, at + 2),
            enctype: u16_at(bytes, at + 4) as i16,
            contents,
        });
        at = start + len;
    }
    Ok(out)
}

/// `krb5_dbe_update_mkey_aux` (`kdb5.c:1823-1906`).
pub fn update_mkey_aux(entry: &mut MitEntry, list: &[MkeyAux]) -> Result<(), StoreError> {
    if list.is_empty() {
        put_tl(entry, MKEY_AUX, None);
        return Ok(());
    }
    let mut data = TL_VERSION.to_le_bytes().to_vec();
    for node in list {
        let len = u16::try_from(node.contents.len())
            .map_err(|_| StoreError::backend("master key auxiliary data too long"))?;
        data.extend_from_slice(&node.mkey_kvno.to_le_bytes());
        data.extend_from_slice(&node.latest_kvno.to_le_bytes());
        data.extend_from_slice(&(node.enctype as u16).to_le_bytes());
        data.extend_from_slice(&len.to_le_bytes());
        data.extend_from_slice(&node.contents);
    }
    put_tl(entry, MKEY_AUX, Some(data));
    Ok(())
}

/// The decrypted master-key list (`krb5_keylist_node`), in `K/M` key-data
/// order (newest first), with the `K/M` activation list.
#[derive(Debug, Clone)]
pub struct MasterKeys {
    /// `(kvno, key)` pairs.
    pub keys: Vec<(u16, EncryptionKey)>,
    /// `KRB5_TL_ACTKVNO`, sorted by activation time.
    pub actkvno: Vec<ActKvno>,
}

impl MasterKeys {
    /// A database with only master key version 1, active from time 0.
    pub fn single(key: EncryptionKey) -> Self {
        Self {
            keys: vec![(1, key)],
            actkvno: vec![ActKvno {
                kvno: 1,
                act_time: 0,
            }],
        }
    }

    /// `krb5_def_fetch_mkey_list` (`kdb_default.c:396-470`): `mkey` decrypts
    /// the newest `K/M` key directly or through `KRB5_TL_MKEY_AUX`, and the
    /// newest key decrypts the rest.
    pub fn fetch(km: &MitEntry, mkey: &EncryptionKey) -> Result<Self, StoreError> {
        let first = km
            .key_data
            .first()
            .ok_or_else(|| corrupt("K/M has no key"))?;
        let field = |i: usize| {
            km.key_data[i]
                .fields
                .first()
                .ok_or_else(|| corrupt("K/M key-data record has no key field"))
        };
        let (etype, blob) = field(0)?;
        let mut current = None;
        if i32::from(*etype) == mkey.keytype {
            current = decrypt_key(mkey, mkey.keytype, blob).ok();
        }
        if current.is_none() {
            current = lookup_mkey_aux(km)?
                .iter()
                .find_map(|aux| decrypt_key(mkey, i32::from(aux.enctype), &aux.contents).ok());
        }
        let current = current.ok_or_else(|| {
            StoreError::backend("Unable to decrypt latest master key with the provided master key")
        })?;
        let mut keys = vec![(first.kvno, current.clone())];
        for (i, data) in km.key_data.iter().enumerate().skip(1) {
            let (etype, blob) = field(i)?;
            keys.push((data.kvno, decrypt_key(&current, i32::from(*etype), blob)?));
        }
        Ok(Self {
            keys,
            actkvno: lookup_actkvno(km)?,
        })
    }

    /// The master key with version `kvno`.
    pub fn get(&self, kvno: u16) -> Option<&EncryptionKey> {
        self.keys.iter().find(|(v, _)| *v == kvno).map(|(_, k)| k)
    }

    /// `find_actkvno` (`kdb5.c:1333-1345`): the last entry whose activation
    /// time is not after `now`, or the first entry if all are in the future.
    pub fn find_actkvno(&self, now: u32) -> Option<u16> {
        let mut nodes = self.actkvno.iter();
        let mut kvno = nodes.next()?.kvno;
        for node in nodes {
            if node.act_time > now {
                break;
            }
            kvno = node.kvno;
        }
        Some(kvno)
    }

    /// `krb5_dbe_find_act_mkey` (`kdb5.c:1367-1410`).
    pub fn active_at(&self, now: u32) -> Result<(u16, &EncryptionKey), StoreError> {
        let kvno = self
            .find_actkvno(now)
            .ok_or_else(|| corrupt("K/M has no active master key"))?;
        let key = self.get(kvno).ok_or_else(|| {
            StoreError::backend(format!(
                "No matching key in entry (master key version {kvno})"
            ))
        })?;
        Ok((kvno, key))
    }

    /// The master key active now.
    pub fn active(&self) -> Result<(u16, &EncryptionKey), StoreError> {
        self.active_at(now())
    }
}

/// The current time as a MIT `krb5_timestamp`.
pub fn now() -> u32 {
    u32::try_from(chrono::Utc::now().timestamp()).unwrap_or(u32::MAX)
}

/// `get_next_kvno` (`kdb5_mkey.c:44-55`).
pub fn next_kvno(km: &MitEntry) -> u16 {
    match km.key_data.first().map_or(0, |k| k.kvno).wrapping_add(1) {
        0 => 1,
        kvno => kvno,
    }
}

/// `add_new_mkey` (`kdb5_mkey.c:60-150`): the new key, encrypted in itself,
/// becomes `K/M`'s first key; every existing master key is re-encrypted in it
/// and `KRB5_TL_MKEY_AUX` holds the new key encrypted in each old one.
pub fn add_new_mkey(
    km: &mut MitEntry,
    keys: &MasterKeys,
    new: &EncryptionKey,
) -> Result<u16, StoreError> {
    let kvno = next_kvno(km);
    let data = |under: &EncryptionKey, key: &EncryptionKey, kvno: u16| {
        let etype = i16::try_from(key.keytype)
            .map_err(|_| StoreError::backend("MIT enctype exceeds i16"))?;
        Ok::<_, StoreError>(super::KeyData {
            ver: 1,
            kvno,
            fields: vec![(etype, encrypt_key(under, key)?)],
        })
    };
    let mut key_data = vec![data(new, new, kvno)?];
    let mut aux = Vec::with_capacity(keys.keys.len());
    for (old_kvno, old) in &keys.keys {
        key_data.push(data(new, old, *old_kvno)?);
        let latest = data(old, new, kvno)?;
        let (enctype, contents) = latest.fields.into_iter().next().expect("one field");
        aux.push(MkeyAux {
            mkey_kvno: *old_kvno,
            latest_kvno: kvno,
            enctype,
            contents,
        });
    }
    km.key_data = key_data;
    put_tl(km, super::MKVNO, Some(kvno.to_le_bytes().to_vec()));
    update_mkey_aux(km, &aux)?;
    Ok(kvno)
}

/// `krb5_dbe_get_mkvno` (`kdb5.c:1669-1737`): `KRB5_TL_MKVNO`, default 1.
pub fn entry_mkvno(entry: &MitEntry) -> Result<u16, StoreError> {
    match tl(entry, super::MKVNO) {
        None => Ok(1),
        Some(bytes) => {
            let bytes: [u8; 2] = bytes
                .try_into()
                .map_err(|_| corrupt("MIT MKVNO tl-data must be 2 bytes"))?;
            Ok(u16::from_le_bytes(bytes))
        }
    }
}

/// `kdb5_use_mkey` activation-list edit (`kdb5_mkey.c:420-495`): drop any
/// existing entry for `kvno` (or retime it if it is the only one), insert it
/// sorted by activation time, and require a key active at `now`.
pub fn use_mkey(
    list: &mut Vec<ActKvno>,
    kvno: u16,
    start: u32,
    now: u32,
) -> Result<(), StoreError> {
    let mut inserted = false;
    if let Some(at) = list.iter().position(|a| a.kvno == kvno) {
        if list.len() == 1 {
            list[0].act_time = start;
            inserted = true;
        } else {
            list.remove(at);
        }
    }
    if !inserted {
        let at = list
            .iter()
            .position(|a| a.act_time > start)
            .unwrap_or(list.len());
        list.insert(
            at,
            ActKvno {
                kvno,
                act_time: start,
            },
        );
    }
    if list.first().is_some_and(|a| a.act_time > now) {
        return Err(StoreError::backend(
            "there must be one master key currently active",
        ));
    }
    Ok(())
}

/// `kdb5_purge_mkeys` (`kdb5_mkey.c:1166-1240`): keep the `K/M` keys whose
/// version is in `in_use`, dropping the others' `ACTKVNO` and `MKEY_AUX`
/// entries. Returns the purged versions in key-data order.
pub fn purge_mkeys(km: &mut MitEntry, in_use: &[u16]) -> Result<Vec<u16>, StoreError> {
    let purged: Vec<u16> = km
        .key_data
        .iter()
        .map(|k| k.kvno)
        .filter(|kvno| !in_use.contains(kvno))
        .collect();
    if purged.is_empty() {
        return Ok(purged);
    }
    let mut actkvno = lookup_actkvno(km)?;
    let mut aux = lookup_mkey_aux(km)?;
    for kvno in &purged {
        if let Some(at) = actkvno.iter().position(|a| a.kvno == *kvno) {
            actkvno.remove(at);
        }
        if let Some(at) = aux.iter().position(|a| a.mkey_kvno == *kvno) {
            aux.remove(at);
        }
    }
    km.key_data.retain(|k| in_use.contains(&k.kvno));
    update_actkvno(km, &actkvno);
    update_mkey_aux(km, &aux)?;
    Ok(purged)
}

/// Rewrap one key-data record's key from master key `from` to `to`, keeping
/// its version and salt field.
pub fn rewrap_key_data(
    data: &mut super::KeyData,
    from: &EncryptionKey,
    to: &EncryptionKey,
) -> Result<(), StoreError> {
    let (etype, blob) = data
        .fields
        .first_mut()
        .ok_or_else(|| corrupt("key-data record has no key field"))?;
    let key = decrypt_key(from, i32::from(*etype), blob)?;
    *blob = encrypt_key(to, &key)?;
    Ok(())
}

/// `master_key_convert` (`dump.c:83-129`) for a non-`K/M` entry: rewrap
/// every key in `new` (version `new_kvno`), keeping each key's version and
/// salt, and set `KRB5_TL_MKVNO`.
pub fn convert_entry(
    entry: &mut MitEntry,
    keys: &MasterKeys,
    new_kvno: u16,
    new: &EncryptionKey,
) -> Result<(), StoreError> {
    let old_kvno = entry_mkvno(entry)?;
    let old = keys.get(old_kvno).ok_or_else(|| {
        StoreError::backend(format!(
            "No matching key in entry (master key version {old_kvno})"
        ))
    })?;
    for data in &mut entry.key_data {
        rewrap_key_data(data, old, new)?;
    }
    put_tl(entry, super::MKVNO, Some(new_kvno.to_le_bytes().to_vec()));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kdc::kdb::master::master_key_from_password;
    use crate::kdc::kdb::mit::KeyData;
    use crate::types::PrincipalName;

    fn entry(key_data: Vec<KeyData>) -> MitEntry {
        MitEntry {
            principal: PrincipalName {
                name_type: 1,
                name_string: Vec::new(),
            },
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
            key_data,
        }
    }

    fn km(master: &EncryptionKey) -> MitEntry {
        entry(vec![KeyData {
            ver: 1,
            kvno: 1,
            fields: vec![(18, encrypt_key(master, master).expect("encrypt"))],
        }])
    }

    fn same(a: &EncryptionKey, b: &EncryptionKey) -> bool {
        a.keytype == b.keytype && a.key_bytes() == b.key_bytes()
    }

    #[test]
    fn actkvno_defaults_to_the_oldest_key_and_round_trips() {
        let m1 = master_key_from_password("R", "one", 18).expect("key");
        let mut km = km(&m1);
        assert_eq!(
            lookup_actkvno(&km).expect("default"),
            vec![ActKvno {
                kvno: 1,
                act_time: 0
            }]
        );
        let list = vec![
            ActKvno {
                kvno: 1,
                act_time: 0,
            },
            ActKvno {
                kvno: 2,
                act_time: 100,
            },
        ];
        update_actkvno(&mut km, &list);
        assert_eq!(
            tl(&km, ACTKVNO).expect("tl"),
            [1, 0, 1, 0, 0, 0, 0, 0, 2, 0, 100, 0, 0, 0]
        );
        assert_eq!(lookup_actkvno(&km).expect("parse"), list);
        update_actkvno(&mut km, &[]);
        assert!(tl(&km, ACTKVNO).is_none());
    }

    #[test]
    fn mkey_aux_round_trips_and_rejects_truncation() {
        let mut km = km(&master_key_from_password("R", "one", 18).expect("key"));
        let aux = vec![MkeyAux {
            mkey_kvno: 1,
            latest_kvno: 2,
            enctype: 18,
            contents: vec![9; 5],
        }];
        update_mkey_aux(&mut km, &aux).expect("encode");
        assert_eq!(
            tl(&km, MKEY_AUX).expect("tl"),
            [1, 0, 1, 0, 2, 0, 18, 0, 5, 0, 9, 9, 9, 9, 9]
        );
        assert_eq!(lookup_mkey_aux(&km).expect("parse"), aux);
        km.tl_data[0].data.pop();
        assert!(lookup_mkey_aux(&km).is_err());
    }

    #[test]
    fn add_new_mkey_is_readable_with_the_new_or_an_old_key() {
        let m1 = master_key_from_password("R", "one", 18).expect("key");
        let m2 = master_key_from_password("R", "two", 17).expect("key");
        let mut km = km(&m1);
        let keys = MasterKeys::fetch(&km, &m1).expect("fetch");
        assert_eq!(add_new_mkey(&mut km, &keys, &m2).expect("add"), 2);
        assert_eq!(
            km.key_data.iter().map(|k| k.kvno).collect::<Vec<_>>(),
            [2, 1]
        );
        assert_eq!(entry_mkvno(&km).expect("mkvno"), 2);
        for supplied in [&m2, &m1] {
            let keys = MasterKeys::fetch(&km, supplied).expect("fetch");
            assert_eq!(keys.keys.len(), 2);
            assert!(same(keys.get(2).expect("kvno 2"), &m2));
            assert!(same(keys.get(1).expect("kvno 1"), &m1));
            // add_mkey leaves the new key inactive.
            assert_eq!(keys.active_at(1000).expect("active").0, 1);
        }
        let wrong = master_key_from_password("R", "three", 18).expect("key");
        assert!(MasterKeys::fetch(&km, &wrong).is_err());
    }

    #[test]
    fn active_key_follows_activation_times() {
        let m1 = master_key_from_password("R", "one", 18).expect("key");
        let mut keys = MasterKeys::single(m1);
        keys.actkvno = vec![
            ActKvno {
                kvno: 1,
                act_time: 0,
            },
            ActKvno {
                kvno: 2,
                act_time: 100,
            },
        ];
        assert_eq!(keys.find_actkvno(99), Some(1));
        assert_eq!(keys.find_actkvno(100), Some(2));
        keys.actkvno.remove(0);
        assert_eq!(keys.find_actkvno(0), Some(2));
        assert!(keys.active_at(0).is_err(), "kvno 2 is not in the key list");
    }

    #[test]
    fn use_mkey_edits_the_activation_list_like_mit() {
        let one = ActKvno {
            kvno: 1,
            act_time: 0,
        };
        let mut list = vec![one];
        use_mkey(&mut list, 2, 300, 200).expect("future key");
        assert_eq!(
            list,
            [
                one,
                ActKvno {
                    kvno: 2,
                    act_time: 300
                }
            ]
        );
        use_mkey(&mut list, 2, 100, 200).expect("move earlier");
        assert_eq!(list[1].act_time, 100);
        use_mkey(&mut list, 1, 150, 200).expect("reorder");
        assert_eq!(list.iter().map(|a| a.kvno).collect::<Vec<_>>(), [2, 1]);
        let mut single = vec![one];
        assert!(use_mkey(&mut single, 1, 500, 200).is_err());
    }

    #[test]
    fn purge_and_convert_keep_principal_key_versions_and_salts() {
        let m1 = master_key_from_password("R", "one", 18).expect("key");
        let m2 = master_key_from_password("R", "two", 18).expect("key");
        let mut km = km(&m1);
        let keys = MasterKeys::fetch(&km, &m1).expect("fetch");
        add_new_mkey(&mut km, &keys, &m2).expect("add");
        let mut list = lookup_actkvno(&km).expect("actkvno");
        use_mkey(&mut list, 2, 10, 20).expect("use");
        update_actkvno(&mut km, &list);
        let keys = MasterKeys::fetch(&km, &m2).expect("fetch");
        assert_eq!(keys.active_at(20).expect("active").0, 2);

        let user = master_key_from_password("R", "user", 18).expect("key");
        let mut princ = entry(vec![KeyData {
            ver: 2,
            kvno: 5,
            fields: vec![
                (18, encrypt_key(&m1, &user).expect("encrypt")),
                (3, b"salt".to_vec()),
            ],
        }]);
        convert_entry(&mut princ, &keys, 2, &m2).expect("convert");
        assert_eq!(entry_mkvno(&princ).expect("mkvno"), 2);
        let data = &princ.key_data[0];
        assert_eq!((data.ver, data.kvno), (2, 5));
        assert_eq!(data.fields[1], (3, b"salt".to_vec()));
        assert!(same(
            &decrypt_key(&m2, 18, &data.fields[0].1).expect("decrypt"),
            &user
        ));

        assert_eq!(purge_mkeys(&mut km, &[2]).expect("purge"), [1]);
        assert_eq!(km.key_data.iter().map(|k| k.kvno).collect::<Vec<_>>(), [2]);
        assert!(lookup_mkey_aux(&km).expect("aux").is_empty());
        assert_eq!(lookup_actkvno(&km).expect("actkvno")[0].kvno, 2);
        assert!(purge_mkeys(&mut km, &[2]).expect("noop").is_empty());
    }
}
