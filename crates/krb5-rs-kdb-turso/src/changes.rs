//! Applying replicated changes and the row codecs. Everything here runs
//! inside a caller-owned transaction on one connection.

use krb5_rs::kdc::replication::{
    Change, LockoutRecord, ReplicaCheckpoint, ReplicationTs, StoredKey, StoredPolicy,
    StoredPrincipal,
};
use krb5_rs::kdc::StoreError;
use turso::{Connection, Row, Value};

use crate::db::{blob, exec, int, now_unix, opt_blob, opt_int, opt_text, query, text, TxError};
use krb5_rs::types::PrincipalName;

pub(crate) use krb5_rs::kdc::replication::{
    decode_principal_key as decode_name, encode_principal_key as encode_name,
};

fn u(n: u64) -> Result<Value, StoreError> {
    i64::try_from(n)
        .map(Value::Integer)
        .map_err(|_| StoreError::conflict("value out of range"))
}

fn opt_u(n: Option<u64>) -> Result<Value, StoreError> {
    n.map_or(Ok(Value::Null), u)
}

fn opt_i(n: Option<i64>) -> Value {
    n.map_or(Value::Null, Value::Integer)
}

fn opt_t(s: &Option<String>) -> Value {
    s.clone().map_or(Value::Null, Value::Text)
}

fn opt_b(b: &Option<Vec<u8>>) -> Value {
    b.clone().map_or(Value::Null, Value::Blob)
}

pub(crate) fn join_list(list: &[String]) -> String {
    list.join("\n")
}

pub(crate) fn split_list(s: &str) -> Vec<String> {
    if s.is_empty() {
        Vec::new()
    } else {
        s.split('\n').map(str::to_string).collect()
    }
}

/// The version stored in a row's `version_wall`, `version_logical` columns.
pub(crate) fn read_version(row: &Row, wall: usize) -> Result<ReplicationTs, StoreError> {
    let logical = int(row, wall + 1)?;
    Ok(ReplicationTs::new(
        int(row, wall)?,
        u32::try_from(logical).map_err(|_| StoreError::corrupt("logical version out of range"))?,
    ))
}

fn version_params(v: ReplicationTs) -> [Value; 2] {
    [
        Value::Integer(v.wall_nanos),
        Value::Integer(i64::from(v.logical)),
    ]
}

/// What happened to one change.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Applied {
    Yes,
    Stale,
}

/// Apply `changes` in order. With `versioned`, a change whose version is not
/// newer than the stored one is skipped; a rebuild writes into an empty
/// database and needs no such check.
pub(crate) async fn apply_changes(
    conn: &Connection,
    changes: &[Change],
    fail_point: &crate::FailPoint,
) -> Result<(usize, usize), TxError> {
    let (mut applied, mut stale) = (0, 0);
    for (i, change) in changes.iter().enumerate() {
        match apply_change(conn, change).await? {
            Applied::Yes => applied += 1,
            Applied::Stale => stale += 1,
        }
        fail_point.hit(&format!("apply:after_change:{i}"));
    }
    Ok((applied, stale))
}

async fn apply_change(conn: &Connection, change: &Change) -> Result<Applied, TxError> {
    match change {
        Change::UpsertPrincipal { principal, version } => {
            upsert_principal(conn, principal, *version).await
        }
        Change::DeletePrincipal {
            realm,
            name,
            version,
        } => delete_principal(conn, realm, name, *version).await,
        Change::UpsertPolicy { policy, version } => upsert_policy(conn, policy, *version).await,
        Change::DeletePolicy { name, version } => delete_policy(conn, name, *version).await,
        Change::UpsertLockout { record, version } => upsert_lockout(conn, record, *version).await,
        Change::DeleteLockout {
            realm,
            name,
            version,
        } => delete_lockout(conn, realm, name, *version).await,
    }
}

async fn upsert_principal(
    conn: &Connection,
    p: &StoredPrincipal,
    version: ReplicationTs,
) -> Result<Applied, TxError> {
    let name = encode_name(&p.name)?;
    let existing = query(
        conn,
        "SELECT id, version_wall, version_logical FROM principals WHERE realm = ? AND name = ?",
        vec![Value::Text(p.realm.clone()), Value::Text(name.clone())],
    )
    .await?;
    let id = match existing.first() {
        Some(row) => {
            if read_version(row, 1)? >= version {
                return Ok(Applied::Stale);
            }
            Some(int(row, 0)?)
        }
        None => None,
    };
    let mut fields = vec![
        Value::Integer(i64::from(p.name.name_type)),
        Value::Integer(i64::from(p.attributes)),
        opt_u(p.max_life)?,
        opt_u(p.max_renewable_life)?,
        opt_i(p.expiration),
        opt_i(p.pw_expiration),
        opt_i(p.last_pwd_change),
        opt_i(p.mod_time),
        opt_t(&p.policy),
        u(p.security_epoch)?,
        opt_i(p.last_admin_unlock),
        Value::Text(join_list(&p.allowed_to_delegate_to)),
        Value::Text(join_list(&p.allowed_to_delegate_from)),
    ];
    fields.extend(version_params(version));
    let id = match id {
        Some(id) => {
            fields.push(Value::Integer(id));
            exec(
                conn,
                "UPDATE principals SET name_type = ?, attributes = ?, max_life = ?, \
                 max_renewable_life = ?, expiration = ?, pw_expiration = ?, last_pwd_change = ?, \
                 mod_time = ?, policy = ?, security_epoch = ?, last_admin_unlock = ?, \
                 delegate_to = ?, delegate_from = ?, version_wall = ?, version_logical = ?, \
                 deleted = 0 WHERE id = ?",
                fields,
            )
            .await?;
            exec(
                conn,
                "DELETE FROM principal_keys WHERE principal_id = ?",
                vec![Value::Integer(id)],
            )
            .await?;
            id
        }
        None => {
            let mut all = vec![Value::Text(p.realm.clone()), Value::Text(name.clone())];
            all.extend(fields);
            exec(
                conn,
                "INSERT INTO principals (realm, name, name_type, attributes, max_life, \
                 max_renewable_life, expiration, pw_expiration, last_pwd_change, mod_time, \
                 policy, security_epoch, last_admin_unlock, delegate_to, delegate_from, \
                 version_wall, version_logical, deleted) \
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)",
                all,
            )
            .await?;
            let rows = query(
                conn,
                "SELECT id FROM principals WHERE realm = ? AND name = ?",
                vec![Value::Text(p.realm.clone()), Value::Text(name)],
            )
            .await?;
            int(
                rows.first()
                    .ok_or_else(|| StoreError::backend("inserted principal vanished"))?,
                0,
            )?
        }
    };
    for k in &p.keys {
        exec(
            conn,
            "INSERT INTO principal_keys (principal_id, kvno, enctype, mkvno, enc_key, salt, \
             s2kparams) VALUES (?, ?, ?, ?, ?, ?, ?)",
            vec![
                Value::Integer(id),
                Value::Integer(i64::from(k.kvno)),
                Value::Integer(i64::from(k.enctype)),
                Value::Integer(i64::from(k.mkvno)),
                Value::Blob(k.enc_key.clone()),
                opt_b(&k.salt),
                opt_b(&k.s2kparams),
            ],
        )
        .await?;
    }
    Ok(Applied::Yes)
}

async fn delete_principal(
    conn: &Connection,
    realm: &str,
    name: &PrincipalName,
    version: ReplicationTs,
) -> Result<Applied, TxError> {
    let key = encode_name(name)?;
    let existing = query(
        conn,
        "SELECT id, version_wall, version_logical FROM principals WHERE realm = ? AND name = ?",
        vec![Value::Text(realm.to_string()), Value::Text(key.clone())],
    )
    .await?;
    let [w, l] = version_params(version);
    match existing.first() {
        Some(row) => {
            if read_version(row, 1)? >= version {
                return Ok(Applied::Stale);
            }
            let id = int(row, 0)?;
            exec(
                conn,
                "DELETE FROM principal_keys WHERE principal_id = ?",
                vec![Value::Integer(id)],
            )
            .await?;
            exec(
                conn,
                "UPDATE principals SET deleted = 1, version_wall = ?, version_logical = ? \
                 WHERE id = ?",
                vec![w, l, Value::Integer(id)],
            )
            .await?;
        }
        None => {
            exec(
                conn,
                "INSERT INTO principals (realm, name, name_type, attributes, security_epoch, \
                 delegate_to, delegate_from, version_wall, version_logical, deleted) \
                 VALUES (?, ?, ?, 0, 0, '', '', ?, ?, 1)",
                vec![
                    Value::Text(realm.to_string()),
                    Value::Text(key),
                    Value::Integer(i64::from(name.name_type)),
                    w,
                    l,
                ],
            )
            .await?;
        }
    }
    Ok(Applied::Yes)
}

fn policy_fields(p: &StoredPolicy) -> Result<Vec<Value>, StoreError> {
    Ok(vec![
        Value::Integer(i64::from(p.pw_min_life)),
        Value::Integer(i64::from(p.pw_max_life)),
        Value::Integer(i64::from(p.pw_min_length)),
        Value::Integer(i64::from(p.pw_min_classes)),
        Value::Integer(i64::from(p.pw_history_num)),
        Value::Integer(i64::from(p.pw_max_fail)),
        Value::Integer(i64::from(p.pw_failcnt_interval)),
        Value::Integer(i64::from(p.pw_lockout_duration)),
        Value::Integer(i64::from(p.attributes)),
        Value::Integer(i64::from(p.max_life)),
        Value::Integer(i64::from(p.max_renewable_life)),
        opt_t(&p.allowed_keysalts),
        Value::Integer(i64::try_from(p.security_epoch).unwrap_or(i64::MAX)),
        if p.tl_data.is_empty() {
            Value::Null
        } else {
            Value::Blob(p.tl_data_bytes()?)
        },
    ])
}

async fn upsert_policy(
    conn: &Connection,
    p: &StoredPolicy,
    version: ReplicationTs,
) -> Result<Applied, TxError> {
    let existing = query(
        conn,
        "SELECT id, version_wall, version_logical FROM policies WHERE name = ?",
        vec![Value::Text(p.name.clone())],
    )
    .await?;
    let mut fields = policy_fields(p)?;
    fields.extend(version_params(version));
    match existing.first() {
        Some(row) => {
            if read_version(row, 1)? >= version {
                return Ok(Applied::Stale);
            }
            fields.push(Value::Integer(int(row, 0)?));
            exec(
                conn,
                "UPDATE policies SET pw_min_life = ?, pw_max_life = ?, pw_min_length = ?, \
                 pw_min_classes = ?, pw_history_num = ?, pw_max_fail = ?, \
                 pw_failcnt_interval = ?, pw_lockout_duration = ?, attributes = ?, \
                 max_life = ?, max_renewable_life = ?, allowed_keysalts = ?, \
                 security_epoch = ?, tl_data = ?, version_wall = ?, version_logical = ?, \
                 deleted = 0 WHERE id = ?",
                fields,
            )
            .await?;
        }
        None => {
            let mut all = vec![Value::Text(p.name.clone())];
            all.extend(fields);
            exec(
                conn,
                "INSERT INTO policies (name, pw_min_life, pw_max_life, pw_min_length, \
                 pw_min_classes, pw_history_num, pw_max_fail, pw_failcnt_interval, \
                 pw_lockout_duration, attributes, max_life, max_renewable_life, \
                 allowed_keysalts, security_epoch, tl_data, version_wall, version_logical, \
                 deleted) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)",
                all,
            )
            .await?;
        }
    }
    Ok(Applied::Yes)
}

async fn delete_policy(
    conn: &Connection,
    name: &str,
    version: ReplicationTs,
) -> Result<Applied, TxError> {
    let existing = query(
        conn,
        "SELECT id, version_wall, version_logical FROM policies WHERE name = ?",
        vec![Value::Text(name.to_string())],
    )
    .await?;
    let [w, l] = version_params(version);
    match existing.first() {
        Some(row) => {
            if read_version(row, 1)? >= version {
                return Ok(Applied::Stale);
            }
            exec(
                conn,
                "UPDATE policies SET deleted = 1, version_wall = ?, version_logical = ? \
                 WHERE id = ?",
                vec![w, l, Value::Integer(int(row, 0)?)],
            )
            .await?;
        }
        None => {
            exec(
                conn,
                "INSERT INTO policies (name, pw_min_life, pw_max_life, pw_min_length, \
                 pw_min_classes, pw_history_num, pw_max_fail, pw_failcnt_interval, \
                 pw_lockout_duration, attributes, max_life, max_renewable_life, \
                 security_epoch, version_wall, version_logical, deleted) \
                 VALUES (?, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, ?, ?, 1)",
                vec![Value::Text(name.to_string()), w, l],
            )
            .await?;
        }
    }
    Ok(Applied::Yes)
}

async fn upsert_lockout(
    conn: &Connection,
    r: &LockoutRecord,
    version: ReplicationTs,
) -> Result<Applied, TxError> {
    let key = encode_name(&r.name)?;
    let existing = query(
        conn,
        "SELECT id, version_wall, version_logical FROM lockouts WHERE realm = ? AND name = ?",
        vec![Value::Text(r.realm.clone()), Value::Text(key.clone())],
    )
    .await?;
    let mut fields = vec![
        Value::Integer(i64::from(r.name.name_type)),
        Value::Integer(r.locked_at),
        opt_i(r.unlock_at),
        Value::Text(r.source_kdc.clone()),
    ];
    fields.extend(version_params(version));
    match existing.first() {
        Some(row) => {
            if read_version(row, 1)? >= version {
                return Ok(Applied::Stale);
            }
            fields.push(Value::Integer(int(row, 0)?));
            exec(
                conn,
                "UPDATE lockouts SET name_type = ?, locked_at = ?, unlock_at = ?, \
                 source_kdc = ?, version_wall = ?, version_logical = ?, deleted = 0 \
                 WHERE id = ?",
                fields,
            )
            .await?;
        }
        None => {
            let mut all = vec![Value::Text(r.realm.clone()), Value::Text(key)];
            all.extend(fields);
            exec(
                conn,
                "INSERT INTO lockouts (realm, name, name_type, locked_at, unlock_at, \
                 source_kdc, version_wall, version_logical, deleted) \
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0)",
                all,
            )
            .await?;
        }
    }
    Ok(Applied::Yes)
}

async fn delete_lockout(
    conn: &Connection,
    realm: &str,
    name: &PrincipalName,
    version: ReplicationTs,
) -> Result<Applied, TxError> {
    let key = encode_name(name)?;
    let existing = query(
        conn,
        "SELECT id, version_wall, version_logical FROM lockouts WHERE realm = ? AND name = ?",
        vec![Value::Text(realm.to_string()), Value::Text(key.clone())],
    )
    .await?;
    let [w, l] = version_params(version);
    match existing.first() {
        Some(row) => {
            if read_version(row, 1)? >= version {
                return Ok(Applied::Stale);
            }
            exec(
                conn,
                "UPDATE lockouts SET deleted = 1, version_wall = ?, version_logical = ? \
                 WHERE id = ?",
                vec![w, l, Value::Integer(int(row, 0)?)],
            )
            .await?;
        }
        None => {
            exec(
                conn,
                "INSERT INTO lockouts (realm, name, name_type, locked_at, source_kdc, \
                 version_wall, version_logical, deleted) VALUES (?, ?, ?, 0, '', ?, ?, 1)",
                vec![
                    Value::Text(realm.to_string()),
                    Value::Text(key),
                    Value::Integer(i64::from(name.name_type)),
                    w,
                    l,
                ],
            )
            .await?;
        }
    }
    Ok(Applied::Yes)
}

/// Read the checkpoint row, if any.
pub(crate) async fn read_checkpoint(
    conn: &Connection,
) -> Result<Option<ReplicaCheckpoint>, StoreError> {
    let rows = query(
        conn,
        "SELECT checkpoint_wall, checkpoint_logical, snapshot_wall, snapshot_logical, \
         last_success_unix FROM replication_state WHERE id = 1",
        Vec::new(),
    )
    .await
    .map_err(crate::db::map_err)?;
    let Some(row) = rows.first() else {
        return Ok(None);
    };
    let logical = |v: i64| {
        u32::try_from(v).map_err(|_| StoreError::corrupt("checkpoint logical part out of range"))
    };
    let snapshot_ts = match (opt_int(row, 2)?, opt_int(row, 3)?) {
        (Some(w), Some(l)) => Some(ReplicationTs::new(w, logical(l)?)),
        _ => None,
    };
    Ok(Some(ReplicaCheckpoint {
        ts: ReplicationTs::new(int(row, 0)?, logical(int(row, 1)?)?),
        snapshot_ts,
        applied_at: int(row, 4)?,
    }))
}

/// Move the checkpoint to `ts` (never backwards) and record the apply time.
/// `snapshot` sets the bootstrap snapshot timestamp.
pub(crate) async fn write_checkpoint(
    conn: &Connection,
    ts: ReplicationTs,
    snapshot: Option<ReplicationTs>,
) -> Result<(), TxError> {
    let current = read_checkpoint(conn).await?;
    let now = Value::Integer(now_unix());
    match current {
        None => {
            let (sw, sl) = snapshot.map_or((Value::Null, Value::Null), |s| {
                (
                    Value::Integer(s.wall_nanos),
                    Value::Integer(i64::from(s.logical)),
                )
            });
            exec(
                conn,
                "INSERT INTO replication_state (id, checkpoint_wall, checkpoint_logical, \
                 snapshot_wall, snapshot_logical, last_success_unix, status) \
                 VALUES (1, ?, ?, ?, ?, ?, 'ok')",
                vec![
                    Value::Integer(ts.wall_nanos),
                    Value::Integer(i64::from(ts.logical)),
                    sw,
                    sl,
                    now,
                ],
            )
            .await?;
        }
        Some(cur) => {
            let ts = ts.max(cur.ts);
            exec(
                conn,
                "UPDATE replication_state SET checkpoint_wall = ?, checkpoint_logical = ?, \
                 last_success_unix = ?, status = 'ok' WHERE id = 1",
                vec![
                    Value::Integer(ts.wall_nanos),
                    Value::Integer(i64::from(ts.logical)),
                    now,
                ],
            )
            .await?;
        }
    }
    Ok(())
}

/// Rows of a lookup: the principal columns repeat per key.
pub(crate) const LOOKUP_SQL: &str = "SELECT p.name_type, p.attributes, p.max_life, \
    p.max_renewable_life, p.expiration, p.pw_expiration, p.last_pwd_change, p.mod_time, \
    p.policy, p.security_epoch, p.last_admin_unlock, p.delegate_to, p.delegate_from, \
    k.kvno, k.enctype, k.mkvno, k.enc_key, k.salt, k.s2kparams \
    FROM principals p LEFT JOIN principal_keys k ON k.principal_id = p.id \
    WHERE p.realm = ? AND p.name = ? AND p.deleted = 0 \
    ORDER BY k.kvno DESC, k.enctype ASC";

/// Build a [`StoredPrincipal`] from lookup rows (the keys stay encrypted).
pub(crate) fn principal_from_rows(
    realm: &str,
    name_key: &str,
    rows: &[Row],
) -> Result<Option<StoredPrincipal>, StoreError> {
    let Some(first) = rows.first() else {
        return Ok(None);
    };
    let to_u64 = |v: i64| u64::try_from(v).map_err(|_| StoreError::corrupt("negative value"));
    let name_type =
        i32::try_from(int(first, 0)?).map_err(|_| StoreError::corrupt("name type out of range"))?;
    let mut keys = Vec::new();
    for row in rows {
        if opt_int(row, 13)?.is_none() {
            continue;
        }
        keys.push(StoredKey {
            kvno: u32::try_from(int(row, 13)?).map_err(|_| StoreError::corrupt("kvno"))?,
            enctype: i32::try_from(int(row, 14)?).map_err(|_| StoreError::corrupt("enctype"))?,
            mkvno: u32::try_from(int(row, 15)?).map_err(|_| StoreError::corrupt("mkvno"))?,
            enc_key: blob(row, 16)?,
            salt: opt_blob(row, 17)?,
            s2kparams: opt_blob(row, 18)?,
        });
    }
    Ok(Some(StoredPrincipal {
        name: decode_name(name_key, name_type)?,
        realm: realm.to_string(),
        attributes: u32::try_from(int(first, 1)?).map_err(|_| StoreError::corrupt("attributes"))?,
        max_life: opt_int(first, 2)?.map(to_u64).transpose()?,
        max_renewable_life: opt_int(first, 3)?.map(to_u64).transpose()?,
        expiration: opt_int(first, 4)?,
        pw_expiration: opt_int(first, 5)?,
        last_pwd_change: opt_int(first, 6)?,
        mod_time: opt_int(first, 7)?,
        keys,
        allowed_to_delegate_to: split_list(&text(first, 11)?),
        allowed_to_delegate_from: split_list(&text(first, 12)?),
        policy: opt_text(first, 8)?,
        security_epoch: to_u64(int(first, 9)?)?,
        last_admin_unlock: opt_int(first, 10)?,
    }))
}

/// Policy columns after `name` for `SELECT ... FROM policies`.
pub(crate) const POLICY_SQL: &str = "SELECT name, pw_min_life, pw_max_life, pw_min_length, \
    pw_min_classes, pw_history_num, pw_max_fail, pw_failcnt_interval, pw_lockout_duration, \
    attributes, max_life, max_renewable_life, allowed_keysalts, security_epoch, tl_data \
    FROM policies WHERE name = ? AND deleted = 0";

pub(crate) fn policy_from_row(row: &Row) -> Result<StoredPolicy, StoreError> {
    let n = |i: usize| -> Result<u32, StoreError> {
        u32::try_from(int(row, i)?).map_err(|_| StoreError::corrupt("policy field out of range"))
    };
    Ok(StoredPolicy {
        name: text(row, 0)?,
        pw_min_life: n(1)?,
        pw_max_life: n(2)?,
        pw_min_length: n(3)?,
        pw_min_classes: n(4)?,
        pw_history_num: n(5)?,
        pw_max_fail: n(6)?,
        pw_failcnt_interval: n(7)?,
        pw_lockout_duration: n(8)?,
        attributes: n(9)?,
        max_life: n(10)?,
        max_renewable_life: n(11)?,
        allowed_keysalts: opt_text(row, 12)?,
        security_epoch: u64::try_from(int(row, 13)?)
            .map_err(|_| StoreError::corrupt("negative epoch"))?,
        tl_data: StoredPolicy::tl_data_from_bytes(&opt_blob(row, 14)?.unwrap_or_default())?,
    })
}
