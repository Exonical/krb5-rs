-- Roles and grants (applied by `krb5-rs-kdb database migrate --create-roles`;
-- {db} is the database name). The users authenticate with client certificates
-- whose CN is the user name.
--
-- kdc_replica (every KDC): read the replicated data; write only what a KDC
-- must: its heartbeat, and lockout reports with their replication-log row. It
-- never writes principals, keys or policies.
-- kdc_admin: everything (administration and migrations).
CREATE USER IF NOT EXISTS kdc_replica;
CREATE USER IF NOT EXISTS kdc_admin;
GRANT CONNECT ON DATABASE {db} TO kdc_replica;
GRANT ALL ON DATABASE {db} TO kdc_admin;
GRANT SELECT ON TABLE realms, principals, principal_keys, policies, lockouts,
    replication_log, replication_meta, replica_status, schema_migrations,
    transaction_markers TO kdc_replica;
GRANT INSERT, UPDATE ON TABLE lockouts, replica_status TO kdc_replica;
GRANT INSERT ON TABLE replication_log TO kdc_replica;
GRANT INSERT ON TABLE transaction_markers TO kdc_replica;
GRANT ALL ON TABLE realms, principals, principal_keys, policies, lockouts,
    replication_log, replication_meta, replica_status, schema_migrations,
    transaction_markers TO kdc_admin;
