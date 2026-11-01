CREATE TABLE IF NOT EXISTS auth_state (
    realm STRING NOT NULL,
    name STRING NOT NULL,
    fail_count INT8 NOT NULL DEFAULT 0,
    last_failed INT8 NOT NULL DEFAULT 0,
    last_success INT8 NOT NULL DEFAULT 0,
    PRIMARY KEY (realm, name)
);
