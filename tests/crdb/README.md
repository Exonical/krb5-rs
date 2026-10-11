# CockroachDB test cluster

`cluster.sh` starts a secure 3-node CockroachDB cluster (image pinned by tag and
digest) with localities `region=california`, `region=ohio` and
`region=washington-dc`, creates the CA, node and client certificates (root,
`kdc_admin`, `kdc_replica`) and the two database users.

```
CRDB_HOST=<address that reaches published ports> tests/crdb/cluster.sh up
CRDB_HOST=<same> cargo test -p krb5-rs-kdb-cockroach -- --ignored --test-threads=1
CRDB_HOST=<same> cargo test -p krb5-rs-kdc --features cockroach --test cockroach_cli -- --ignored
tests/crdb/cluster.sh down     # keep volumes and certs
tests/crdb/cluster.sh nuke     # remove everything
```

- Node 1's SQL port is published on `CRDB_PORT` (default 26257), nodes 2 and 3
  on the next two ports. Client certificates are copied to `tests/crdb/certs/`
  (git-ignored). `CRDB_HOST` goes into the node certificates, so set it before
  the first `up` (or `nuke` and start again).
- `CONTAINER_CLI=docker` selects Docker instead of podman (CI does).
- **Licensing:** the image is CockroachDB under the CockroachDB Software
  License. A cluster without a license key has a 7-day grace period from
  initialisation, after which it is throttled (concurrent open transactions
  limited to 5) unless an Enterprise Free or Trial license is installed
  (`SET CLUSTER SETTING enterprise.license = '...'`). Test clusters are meant
  to be recreated (`nuke`, `up`) rather than kept for weeks.
- Facts the replication design depends on are checked by
  `crates/krb5-rs-kdb-cockroach/tests/facts.rs` (run with `--nocapture`).
