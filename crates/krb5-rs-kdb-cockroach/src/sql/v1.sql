CREATE TABLE realms (
    name STRING NOT NULL PRIMARY KEY,
    master_kvno INT8 NOT NULL,
    master_enctype INT8 NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE principals (
    realm STRING NOT NULL,
    name STRING NOT NULL,
    name_type INT8 NOT NULL,
    attributes INT8 NOT NULL,
    max_life INT8,
    max_renewable_life INT8,
    expiration INT8,
    pw_expiration INT8,
    last_pwd_change INT8,
    mod_time INT8,
    policy STRING,
    security_epoch INT8 NOT NULL DEFAULT 0,
    last_admin_unlock INT8,
    delegate_to STRING[] NOT NULL DEFAULT '{}',
    delegate_from STRING[] NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    mod_by STRING,
    version DECIMAL NOT NULL,
    PRIMARY KEY (realm, name)
);
CREATE TABLE principal_keys (
    realm STRING NOT NULL,
    name STRING NOT NULL,
    kvno INT8 NOT NULL,
    enctype INT8 NOT NULL,
    mkvno INT8 NOT NULL,
    enc_key BYTES NOT NULL,
    salt BYTES,
    s2kparams BYTES,
    PRIMARY KEY (realm, name, kvno, enctype)
);
CREATE TABLE policies (
    name STRING NOT NULL PRIMARY KEY,
    pw_min_life INT8 NOT NULL,
    pw_max_life INT8 NOT NULL,
    pw_min_length INT8 NOT NULL,
    pw_min_classes INT8 NOT NULL,
    pw_history_num INT8 NOT NULL,
    pw_max_fail INT8 NOT NULL,
    pw_failcnt_interval INT8 NOT NULL,
    pw_lockout_duration INT8 NOT NULL,
    attributes INT8 NOT NULL,
    max_life INT8 NOT NULL,
    max_renewable_life INT8 NOT NULL,
    allowed_keysalts STRING,
    security_epoch INT8 NOT NULL,
    version DECIMAL NOT NULL
);
CREATE TABLE lockouts (
    realm STRING NOT NULL,
    name STRING NOT NULL,
    name_type INT8 NOT NULL,
    locked_at INT8 NOT NULL,
    unlock_at INT8,
    source_kdc STRING NOT NULL,
    version DECIMAL NOT NULL,
    PRIMARY KEY (realm, name)
);
CREATE TABLE replication_log (
    commit_ts DECIMAL NOT NULL,
    entity STRING NOT NULL,
    realm STRING NOT NULL,
    "key" STRING NOT NULL,
    op STRING NOT NULL,
    version DECIMAL NOT NULL,
    PRIMARY KEY (commit_ts, entity, realm, "key")
);
CREATE TABLE replication_meta (
    id INT8 NOT NULL PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    pruned_before DECIMAL NOT NULL DEFAULT 0
);
INSERT INTO replication_meta (id, pruned_before) VALUES (1, 0);
CREATE TABLE replica_status (
    kdc_id STRING NOT NULL PRIMARY KEY,
    region STRING NOT NULL,
    applied_ts DECIMAL NOT NULL,
    seen_at TIMESTAMPTZ NOT NULL
);
