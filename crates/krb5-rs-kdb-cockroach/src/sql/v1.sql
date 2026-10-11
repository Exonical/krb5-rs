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
    deleted BOOL NOT NULL DEFAULT false,
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
    deleted BOOL NOT NULL DEFAULT false
);
CREATE TABLE lockouts (
    realm STRING NOT NULL,
    name STRING NOT NULL,
    name_type INT8 NOT NULL,
    locked_at INT8 NOT NULL,
    unlock_at INT8,
    source_kdc STRING NOT NULL,
    deleted BOOL NOT NULL DEFAULT false,
    PRIMARY KEY (realm, name)
);
CREATE TABLE replication_meta (
    id INT8 NOT NULL PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    pruned_before DECIMAL NOT NULL DEFAULT 0,
    bucket_width_seconds INT8 NOT NULL DEFAULT 10,
    transaction_timeout_ms INT8 NOT NULL DEFAULT 30000
);
INSERT INTO replication_meta (id, pruned_before) VALUES (1, 0);
CREATE TABLE replica_status (
    kdc_id STRING NOT NULL PRIMARY KEY,
    region STRING NOT NULL,
    applied_ts DECIMAL NOT NULL,
    seen_at TIMESTAMPTZ NOT NULL
);
CREATE TABLE transaction_markers (
    id STRING NOT NULL PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    logical_id STRING NOT NULL DEFAULT ''
);
CREATE INDEX transaction_markers_logical_id ON transaction_markers (logical_id);
CREATE TABLE replication_log (
    bucket INT8 NOT NULL,
    id UUID NOT NULL,
    entity STRING NOT NULL,
    realm STRING NOT NULL,
    "key" STRING NOT NULL,
    op STRING NOT NULL,
    txn_id UUID NOT NULL,
    PRIMARY KEY (bucket, id)
);
CREATE INDEX replication_log_txn_id ON replication_log (txn_id);
CREATE INDEX replication_log_entity_key ON replication_log (entity, realm, "key", bucket, id);
