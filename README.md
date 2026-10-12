# krb5-rs

Pure Rust Kerberos V5 implementation. GSSAPI, SPNEGO, PKINIT.

**The core library has no C FFI, system krb5 or libgssapi.** The deployable
daemon and admin tool include LMDB (C); the CockroachDB-enabled image also
builds aws-lc and simsimd.

## Features

- **Kerberos V5 Client** — AS/TGS exchanges (TGT acquisition, service ticket requests), krb5.conf parsing, KDC discovery
- **KDC** — AS/TGS request processing, FAST, UDP/TCP serving (`kdc` feature; the deployable daemon is `krb5-rs-kdc` in `crates/krb5-rs-kdc`)
- **GSSAPI/SPNEGO** — HTTP Negotiate authentication
- **PKINIT** — X.509 certificate-based authentication, client and KDC (`pkinit` feature; DH/ECDH replies, MIT 1.22 parity)
- **FAST** — Flexible Authentication via Secure Tunneling
- **Credential Cache** — Read/write ccache and keytab formats

## Why?

MIT Kerberos and Heimdal are massive C codebases (~450K and ~620K SLOC respectively) with decades of CVEs. Every Rust project needing Kerberos auth depends on FFI bindings to these C libraries, inheriting their build complexity and security risks.

`krb5-rs` is a ground-up Rust implementation using `rasn` (ASN.1) + RustCrypto.
The core library is pure Rust and cross-compiles to musl.

## Status

**Pre-release.** API is unstable. Not ready for production use.

## RFCs

| RFC | Description | Status |
|-----|-------------|--------|
| [RFC 4120](https://www.rfc-editor.org/rfc/rfc4120) | Kerberos V5 core | Client + KDC |
| [RFC 4121](https://www.rfc-editor.org/rfc/rfc4121) | GSSAPI mechanism | Implemented |
| [RFC 4178](https://www.rfc-editor.org/rfc/rfc4178) | SPNEGO | Implemented |
| [RFC 3961](https://www.rfc-editor.org/rfc/rfc3961) | Encryption specs | Implemented |
| [RFC 3962](https://www.rfc-editor.org/rfc/rfc3962) | AES encryption | Implemented |
| [RFC 8009](https://www.rfc-editor.org/rfc/rfc8009) | AES-SHA2 encryption | Implemented |
| [RFC 6113](https://www.rfc-editor.org/rfc/rfc6113) | FAST | Client + KDC |
| [RFC 6806](https://www.rfc-editor.org/rfc/rfc6806) | Enc-pa-rep / FAST negotiation | Client + KDC |
| [RFC 4556](https://www.rfc-editor.org/rfc/rfc4556) | PKINIT (Diffie-Hellman and ECDH) | Client + KDC |
| [RFC 8636](https://www.rfc-editor.org/rfc/rfc8636) | PKINIT algorithm agility (KDFs, ECDH groups) | Client + KDC |
| [RFC 8070](https://www.rfc-editor.org/rfc/rfc8070) | PKINIT freshness | Client + KDC |

**Feature `test-pki`** (TESTING ONLY): embeds fixed RSA private keys and a certificate issuer used by the PKINIT tests and `examples/gen_pkinit_pki.rs`. Never enable it in production builds.

**Not yet supported:** PAC/authorization data, S4U, PKINIT RSA key transport and anonymous PKINIT, DES/RC4/Camellia enctypes.

## Running the KDC

The `crates/krb5-rs-kdc` workspace member builds two binaries (not published to crates.io):

- `krb5-rs-kdb` administers the persistent database (`create -s`, `addprinc`, `ktadd`, ...; passwords come from stdin).
- `krb5-rs-kdc` serves it over UDP and TCP, driven by `kdc.conf` (`--config` / `KRB5_KDC_PROFILE`, `--krb5-config` / `KRB5_CONFIG`, optional `--listen` overrides), logs one MIT-style line per request to stdout (`RUST_LOG` controls verbosity) and shuts down gracefully on SIGTERM/SIGINT (`--shutdown-timeout`).

```sh
krb5-rs-kdb --config kdc.conf create -s
echo secret | krb5-rs-kdb --config kdc.conf addprinc alice
krb5-rs-kdc --config kdc.conf
```

`deploy/docker/Dockerfile` builds a static, distroless, nonroot image with both binaries (`podman build -f deploy/docker/Dockerfile .`). The container user cannot bind port 88: configure `kdc_ports = 8888` and map 88 to 8888 outside.

### Store interfaces, policies and lockout

The KDC reads its data through async store traits in `krb5_rs::kdc::store` (`PrincipalStore`, `PolicyStore`, `AuthStateStore`, `AdminStore`, `AuthoritativeState`, `LockoutReporter`, `HealthCheck`, `ConsistencyGate`; design in `docs/architecture/kdb.md`). `Kdc::handle*` are therefore `async`. `Kdc::new(config, store)` keeps its old behaviour; `Kdc::builder(config, store)` injects policies, authentication state, a consistency gate and a lockout reporter.

`krb5-rs-kdb` has MIT kadmin policy commands (`addpol`, `modpol`, `delpol`, `getpol [-terse]`, `listpols`; `-maxfailure`, `-failurecountinterval`, `-lockoutduration`, ...) and `addprinc`/`modprinc` `-policy NAME`, `-clearpolicy`, `-unlock`. A principal under a policy with `pw_max_fail` set is locked out after that many failed pre-authentications, following MIT's db2 lockout (`KDC_ERR_CLIENT_REVOKED`, status `LOCKED_OUT`). File and Memory lockout counters are in-memory; klmdb keeps them in its separate lockout environment. Policies and administrative unlocks are persisted. `disable_lockout` / `disable_last_success` in `[dbmodules]` work as in MIT. Not in MIT: the KDC re-checks a local client at TGS time (disabled, expired, locked out), controllable with `KdcConfig::tgs_recheck_client`.

### MIT-compatible klmdb module

The deployable `krb5-rs-kdc`/`krb5-rs-kdb` binaries compile the pure-Rust
KDB codecs and the `krb5-rs-kdb-lmdb` backend by default. The backend is opt-in:
an unset `db_library` continues to use the existing krb5-rs file store, while
`db_library = klmdb` uses the same LMDB files as MIT krb5 1.17+:

```ini
[realms]
    EXAMPLE.COM = {
        database_name = /var/lib/krb5kdc/principal
        database_module = lmdb
        default_principal_expiration = never
    }
[dbmodules]
    lmdb = {
        db_library = klmdb
        # database_name may also be set here, overriding the realm value.
        mapsize = 128
        max_readers = 0
        nosync = false
        disable_lockout = false
        disable_last_success = false
    }
```

The principal/policy environment is `<database_name>.mdb`; lockout records
live separately in `<database_name>.lockout.mdb` and are always unsynced. A
krb5-rs file database is automatically converted when klmdb is selected and
the `.mdb` file is absent; the original is retained as
`<database_name>.krb5rs-file.bak`.
The optional realm `default_principal_expiration` value is applied to the
initial `K/M` and `krbtgt` records; it defaults to `never`.
Bootstrap records use MIT's `db_creation@REALM` modifier; later mutations
through `krb5-rs-kdb` use `krb5-rs-kdb@REALM` because the admin-store API does
not carry an authenticated modifier identity.

MIT's klmdb files use `MDB_DATA_VERSION` 1, the same as bundled LMDB 0.9.x.
The bundled LMDB lock-file version is 2, versus version 1 in some distro
0.9.x builds. Do not run an MIT and a krb5-rs process on the same environment
at the same time; sequential use is supported. MIT extensions in tl-data, string attributes,
password history, and unmodeled attribute bits are preserved on updates.
`security_epoch` and key `s2kparams` are krb5-rs-only and are not persisted by
MIT klmdb; reads return epoch zero and no s2kparams.
KRB5RS-PROP-1 `kprop_*` settings are rejected with klmdb in this change;
MIT-compatible kprop is a later step.
Master-key rotation through `kdb5_util add_mkey` / `use_mkey` is not
supported; opening a database whose `K/M` has multiple key-data entries fails
with an explicit error.

### Turso replica module (optional)

`crates/krb5-rs-kdb-turso` is an optional plug-in (not built into the daemon unless
`krb5-rs-kdc` is built with `--features turso`). `TursoReplica` implements
`PrincipalStore`, `PolicyStore`, `AuthStateStore`, `HealthCheck` and the
replication `ReplicaSink` over a local Turso database in MVCC mode (MVCC is
enforced on create and every open; there is no WAL fallback). kdc.conf:

```
[realms]
    EXAMPLE.COM = { database_module = replica }
[dbmodules]
    replica = {
        db_library = krb5-rs-turso
        replica_path = /var/lib/krb5-rs/replica   # a directory
        turso_pool_size = 8
        turso_checkpoint_threshold = 4120000      # logical-log bytes, -1 disables
        turso_passive_checkpoint = false          # experimental in Turso 0.8.1
    }
```

The daemon serves from the replica read-only; filling it (replication from
CockroachDB) arrives in a later change. Turso 0.8.1 pulls C code through its
`simsimd` dependency (compiled with `cc`); the module is the only place that
does, and it is off by default.

### CockroachDB authoritative module (optional)

`crates/krb5-rs-kdb-cockroach` stores the realm (principals, keys encrypted under the master key, policies, lockouts) in CockroachDB and is the authority a fleet of replicas follows. It is an optional plug-in: `krb5-rs-kdb` includes it only when built with `--features cockroach` (it brings rustls with the aws-lc-rs provider, which is C code; the `fips` feature of rustls can later select the FIPS-validated aws-lc build).

```
[realms]
    EXAMPLE.COM = { database_module = crdb }
[dbmodules]
    crdb = {
        db_library = krb5-rs-cockroach
        cockroach_url = postgresql://kdc_admin@crdb-public:26257/krb5?sslmode=verify-full
        cockroach_ca = /etc/krb5-rs/crdb/ca.crt
        cockroach_cert = /etc/krb5-rs/crdb/client.kdc_admin.crt
        cockroach_key = /etc/krb5-rs/crdb/client.kdc_admin.key
        cockroach_pool_size = 8
        cockroach_connect_timeout = 5s
        cockroach_statement_timeout = 10s
        cockroach_transaction_timeout = 30s
        replication_read = follower     # or present
        replica_path = /var/lib/krb5-rs/replica
        replication_poll_interval = 1s
        replication_batch_limit = 1000
        replication_retry_min = 100ms
        replication_retry_max = 30s
        replication_rebuild = auto      # or manual
        replication_heartbeat_interval = 5s
        kdc_id = kdc-0                  # defaults to POD_NAME, then HOSTNAME
        region = california
        consistency_mode = bounded      # or strict
        max_staleness = 30s
        authoritative_timeout = 500ms
    }
```

Connections are TLS only and verify the server (`sslmode=verify-full`); password authentication over TLS works too (put the password in the URL). `sslmode=disable` is refused unless `cockroach_insecure = true`, for tests only.

`krb5-rs-kdb` runs the usual commands against it, plus:

```
krb5-rs-kdb database migrate [--create-roles] [--multi-region --primary-region R --regions R1,R2,...]
krb5-rs-kdb replication status
krb5-rs-kdb replication prune --older-than 7d
krb5-rs-kdb replication wait-applied --since TS [--timeout 30s]
```

`database migrate` applies the embedded, versioned schema; migration to the MVCC-versioned bucket log advances `pruned_before`, so existing replicas automatically rebuild rather than missing updates while the old log is replaced. `--create-roles` creates the `kdc_admin` and `kdc_replica` users with their grants (a KDC's `kdc_replica` can read replicated data, report lockouts, heartbeat and insert replication-log rows, but cannot modify principals, keys or policies); `--multi-region` is the opt-in step that sets the database regions, GLOBAL locality on the replicated tables and REGIONAL BY ROW on `replica_status`. The `realms` table remains regional.

Admin writes never call `cluster_logical_timestamp()`. Entity versions come
from `crdb_internal_mvcc_timestamp` at the replication read timestamp; writes
also emit UUID log rows into 10-second `now()` buckets. `cockroach_transaction_timeout`
(default 30s) is set as the server-side `transaction_timeout` on every pooled
connection and must match the duration stored in `replication_meta`. Bucket
scans include the D-sized overlap and filter log-row MVCC timestamps, so
long-running transactions are not missed.

`replication_poll_interval` defaults to 1s, `replication_batch_limit` to 1000, retry backoff defaults to 100ms–30s, and heartbeat interval to 5s. `replication_rebuild` is `auto` (default) or `manual`. `kdc_id` defaults to `POD_NAME`, then `HOSTNAME`; `region` defaults to `unknown`. `consistency_mode` is `bounded` by default (fail closed when source-clock freshness exceeds `max_staleness`, default 30s) or `strict` (also checks each local principal's authoritative epoch/disabled/lockout state, with 500ms `authoritative_timeout`). The clock-safe freshness is source HLC lag plus monotonic time since the read; it never compares KDC wall time to the HLC.

When `replica_path` is set, the daemon opens Turso (MVCC only), bootstraps it from CockroachDB before binding KDC listeners, and then runs the incremental engine. `replication_rebuild = manual` fails readiness if the source pruned past the local checkpoint; `auto` builds a new Turso file and atomically switches to it. Replication freshness uses the source HLC and a monotonic elapsed-time clock, never the KDC's wall clock. `consistency_mode = bounded` (default, fail closed) refuses AS/TGS once freshness exceeds `max_staleness`; `strict` also asks CockroachDB for each involved principal's authoritative epoch/disabled/lockout state and fails closed after `authoritative_timeout`.

`--metrics-listen HOST:PORT` enables the GET-only HTTP endpoints `/metrics`, `/healthz` and `/readyz`. Readiness requires bound KDC listeners, a bootstrapped replica and freshness within bounds. Metrics have low-cardinality labels only; principal names, keys and connection secrets are not included. The HTTP server is a small Tokio HTTP/1.1 implementation; no Hyper dependency is added.

The integration tests need a cluster: `tests/crdb/cluster.sh up` starts a secure 3-node one (localities california, ohio, washington-dc); see `tests/crdb/README.md`.

### Replicas (database propagation)

For HA, one primary keeps the writable database and any number of stateless replicas pull it. This is MIT kprop/kpropd's idea reversed into a pull model (protocol `KRB5RS-PROP-1`, documented in `src/kdc/kdb/propagation.rs`): a replica authenticates to the primary's `kprop/primary` service with a Kerberos ticket (AP-REQ with mutual authentication), asks for the database naming the serial it already has, and receives the raw database file in KRB-PRIV blocks protected by the negotiated subkeys, unless it is current. The replica verifies size, SHA-256, format, realm and its master key, and only then renames the file over its database.

The settings below go in the kdc.conf realm section. They are krb5-rs extensions with no MIT counterpart.

| Option | Role | Meaning |
| --- | --- | --- |
| `kprop_listen` | primary | Listen address(es) of the propagation server (default port 754); unset = off |
| `kprop_service` | both | Service principal (default `kprop/primary`); needs a key in the primary's database |
| `kprop_acl` | primary | Principals allowed to pull (default: `kprop_client`) |
| `kprop_primary` | replica | `host:port` of the primary's propagation server; setting it makes this KDC a replica |
| `kprop_primary_kdc` | replica | `host:port` of the primary's KDC, used for the ticket (default: the `kprop_primary` host, port 88) |
| `kprop_client` | replica | The replica's principal (default `kprop/replica`) |
| `kprop_keytab` / `kprop_password_file` | replica | Exactly one: where the replica's key comes from |
| `kprop_poll_interval` | replica | Time between pulls (deltat, default 60s, ±10% jitter; failures back off from 1s up to this value) |

`kprop_listen` and `kprop_primary` together are a configuration error. A replica needs the same master key stash as the primary. With no local database, or a damaged one, it pulls before binding its KDC listeners, retrying with backoff; with a valid one it serves immediately and syncs in the background. `krb5-rs-kdb` refuses to modify a replica's database unless given `--force`.

File-mode replicas have no freshness bound, as with MIT kpropd. Use
CockroachDB mode for bounded staleness.

### Deployment

- **Kubernetes** (`deploy/helm/krb5-rs-kdc`): `database.mode=file` (default)
  runs one primary (StatefulSet with a PVC) plus replicas that pull the database
  from it. `database.mode=cockroach` runs a CockroachDB-backed KDC StatefulSet
  with a PVC per pod and a local Turso replica. `realm` is required:

  ```sh
  helm install kdc deploy/helm/krb5-rs-kdc --set realm=EXAMPLE.COM
  ```

  File mode generates and retains its master and kprop Secrets unless
  `secrets.existingSecret` is supplied. CockroachDB mode requires an existing
  master Secret and the kdc_replica TLS Secret; enable the bootstrap Job in
  exactly one release per database. `helm install` prints how to find the
  address and administer the database. File replicas keep serving while their
  primary is down; CockroachDB replicas fail closed when stale. The KDC
  StatefulSet uses a PVC per pod for its local Turso replica. Enable the prune
  CronJob in exactly one release, and give administration a separate
  `kdc_admin` URL and TLS Secret. When NetworkPolicy is enabled, set
  `metrics.networkPolicy.from` to admit Prometheus scrapes. See
  [`deploy/helm/krb5-rs-kdc/examples/multi-region`](deploy/helm/krb5-rs-kdc/examples/multi-region)
  for three regional values files.
- **Podman** (`deploy/podman`): a single pod via `podman kube play` or a Quadlet unit (no replicas). See `deploy/podman/README.md`.
- **Image**: `ghcr.io/exonical/krb5-rs-kdc:<tag>` is the pure Rust image;
  `ghcr.io/exonical/krb5-rs-kdc:<tag>-cockroach` includes the CockroachDB and
  Turso modules. Both are built from `deploy/docker/Dockerfile` and published
  from `main` and `v*` tags; linux/amd64 for now, arm64 needs an
  aarch64-musl build. Bootstrap helpers for shell-less containers:
  `krb5-rs-kdb init` (idempotent database/stash/principal creation from secret
  files) and `krb5-rs-kdc --master-password-file` (derive the master key
  instead of reading a stash).

## License

Apache-2.0
