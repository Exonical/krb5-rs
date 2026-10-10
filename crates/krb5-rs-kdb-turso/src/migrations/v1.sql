CREATE TABLE principals (
    id INTEGER PRIMARY KEY,
    realm TEXT NOT NULL,
    name TEXT NOT NULL,
    name_type INTEGER NOT NULL,
    attributes INTEGER NOT NULL,
    max_life INTEGER,
    max_renewable_life INTEGER,
    expiration INTEGER,
    pw_expiration INTEGER,
    last_pwd_change INTEGER,
    mod_time INTEGER,
    policy TEXT,
    security_epoch INTEGER NOT NULL,
    last_admin_unlock INTEGER,
    delegate_to TEXT NOT NULL,
    delegate_from TEXT NOT NULL,
    version_wall INTEGER NOT NULL,
    version_logical INTEGER NOT NULL,
    deleted INTEGER NOT NULL
);
CREATE UNIQUE INDEX principals_realm_name ON principals (realm, name);
CREATE TABLE principal_keys (
    id INTEGER PRIMARY KEY,
    principal_id INTEGER NOT NULL,
    kvno INTEGER NOT NULL,
    enctype INTEGER NOT NULL,
    mkvno INTEGER NOT NULL,
    enc_key BLOB NOT NULL,
    salt BLOB,
    s2kparams BLOB
);
CREATE UNIQUE INDEX principal_keys_unique ON principal_keys (principal_id, kvno, enctype);
CREATE TABLE policies (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    pw_min_life INTEGER NOT NULL,
    pw_max_life INTEGER NOT NULL,
    pw_min_length INTEGER NOT NULL,
    pw_min_classes INTEGER NOT NULL,
    pw_history_num INTEGER NOT NULL,
    pw_max_fail INTEGER NOT NULL,
    pw_failcnt_interval INTEGER NOT NULL,
    pw_lockout_duration INTEGER NOT NULL,
    attributes INTEGER NOT NULL,
    max_life INTEGER NOT NULL,
    max_renewable_life INTEGER NOT NULL,
    allowed_keysalts TEXT,
    security_epoch INTEGER NOT NULL,
    version_wall INTEGER NOT NULL,
    version_logical INTEGER NOT NULL,
    deleted INTEGER NOT NULL
);
CREATE UNIQUE INDEX policies_name ON policies (name);
CREATE TABLE lockouts (
    id INTEGER PRIMARY KEY,
    realm TEXT NOT NULL,
    name TEXT NOT NULL,
    name_type INTEGER NOT NULL,
    locked_at INTEGER NOT NULL,
    unlock_at INTEGER,
    source_kdc TEXT NOT NULL,
    version_wall INTEGER NOT NULL,
    version_logical INTEGER NOT NULL,
    deleted INTEGER NOT NULL
);
CREATE UNIQUE INDEX lockouts_realm_name ON lockouts (realm, name);
CREATE TABLE replication_state (
    id INTEGER PRIMARY KEY,
    checkpoint_wall INTEGER NOT NULL,
    checkpoint_logical INTEGER NOT NULL,
    snapshot_wall INTEGER,
    snapshot_logical INTEGER,
    last_success_unix INTEGER NOT NULL,
    status TEXT NOT NULL
);
CREATE TABLE auth_state (
    id INTEGER PRIMARY KEY,
    realm TEXT NOT NULL,
    name TEXT NOT NULL,
    fail_count INTEGER NOT NULL,
    last_failed INTEGER NOT NULL,
    last_success INTEGER NOT NULL
);
CREATE UNIQUE INDEX auth_state_realm_name ON auth_state (realm, name);
