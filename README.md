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
| [RFC 8062](https://www.rfc-editor.org/rfc/rfc8062) | Anonymous PKINIT (DH/ECDH only, PA-PKINIT-KX) | Client + KDC |

**Feature `test-pki`** (TESTING ONLY): embeds fixed RSA private keys and a certificate issuer used by the PKINIT tests and `examples/gen_pkinit_pki.rs`. Never enable it in production builds.

**Not yet supported:** DES/RC4/Camellia enctypes. PKINIT RSA key transport is rejected, as in MIT 1.22, which removed it.

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
KDB codecs and the `krb5-rs-kdb-lmdb` backend by default. klmdb is the default
backend: an unset `db_library` (or `db_library = klmdb`) uses the same LMDB
files as MIT krb5 1.17+, and `db_library = krb5-rs-file` selects the krb5-rs
file store:

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
`<database_name>.krb5rs-file.bak`. An interrupted conversion is redone or
finished on the next start.

`krb5-rs-kdb` enforces password policies (minimum length and character
classes, no reuse of the current password, password expiration from
`pw_max_life`) for every database. With klmdb it also keeps MIT's password
history, so a password refused by MIT's `kadmin.local` is refused by
`krb5-rs-kdb` and vice versa; the file and CockroachDB databases keep no
history beyond the current password.
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
Master-key rotation matches MIT 1.22.2 on klmdb, FileStore and CockroachDB: `krb5-rs-kdb add_mkey
[-e ENCTYPE] [-s]`, `use_mkey KVNO [TIME]`, `list_mkeys`,
`update_princ_encryption [-f] [-n] [-v] [PATTERN]` and `purge_mkeys [-f] [-n]
[-v]` read and write the same `K/M` key data, `KRB5_TL_MKVNO`,
`KRB5_TL_ACTKVNO` and `KRB5_TL_MKEY_AUX` as `kdb5_util`, and `stash` writes
every master key version. MIT and krb5-rs can take turns on one rotation.

`krb5-rs-kdb dump [-b7|-r13|-r18] [-verbose] [FILE [NAME-REGEX]...]` and
`krb5-rs-kdb load [-b7|-r13|-r18] [-verbose] [-update] [-hash] FILE` read and
write MIT `kdb5_util` dump formats 4-7 (default 7) for klmdb and the file
store, so databases move between MIT and krb5-rs in both directions. A klmdb
dump is byte-identical to MIT's. Deviations are listed in
[`docs/architecture/kdb.md`](docs/architecture/kdb.md#mit-dumpload).

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

`replication_poll_interval` defaults to 1s, `replication_batch_limit` to 1000, retry backoff defaults to 100ms–30s, and heartbeat interval to 5s. `replication_rebuild` is `auto` (default) or `manual`. `kdc_id` defaults to `POD_NAME`, then `HOSTNAME`; `region` defaults to `unknown`. `consistency_mode` is `bounded` by default (fail closed when source-clock freshness exceeds `max_staleness`, default 30s) or `strict` (also checks each local principal's authoritative epoch/disabled/lockout state, with 500ms `authoritative_timeout`). Strict mode returns MIT's client/server error codes for authoritative denials; stale epochs and unavailable authorities remain `KDC_ERR_SVC_UNAVAILABLE`. The clock-safe freshness is source HLC lag plus monotonic time since the read; it never compares KDC wall time to the HLC.

When `replica_path` is set, the daemon opens Turso (MVCC only), bootstraps it from CockroachDB before binding KDC listeners, and then runs the incremental engine. `replication_rebuild = manual` fails readiness if the source pruned past the local checkpoint; `auto` builds a new Turso file and atomically switches to it. Replication freshness uses the source HLC and a monotonic elapsed-time clock, never the KDC's wall clock. `consistency_mode = bounded` (default, fail closed) refuses AS/TGS once freshness exceeds `max_staleness`; strict mode also asks CockroachDB for each involved principal's authoritative epoch/disabled/lockout state. Authoritative denials return the corresponding MIT client/server error; an epoch mismatch or unavailable authority returns `KDC_ERR_SVC_UNAVAILABLE` after `authoritative_timeout`.

`--metrics-listen HOST:PORT` enables the GET-only HTTP endpoints `/metrics`, `/healthz` and `/readyz`. Readiness requires bound KDC listeners, a bootstrapped replica and freshness within bounds. Metrics have low-cardinality labels only; principal names, keys and connection secrets are not included. The HTTP server is a small Tokio HTTP/1.1 implementation; no Hyper dependency is added.

The integration tests need a cluster: `tests/crdb/cluster.sh up` starts a secure 3-node one (localities california, ohio, washington-dc); see `tests/crdb/README.md`.

### Replicas (database propagation)

`krb5-rs-kprop` and `krb5-rs-kpropd` implement MIT krb5 1.22.2's full
propagation (`src/kprop/kprop.c`, `kpropd.c`, `kprop_util.c`) and interoperate
with MIT `kprop`/`kpropd` in both directions. The primary pushes: after
administrative changes (and on a schedule) it runs

```sh
krb5-rs-kdb dump /usr/local/var/krb5kdc/replica_datatrans
krb5-rs-kprop -f /usr/local/var/krb5kdc/replica_datatrans replica.example.com
```

`krb5-rs-kprop [-r realm] [-f file] [-d] [-P port] [-s keytab] replica_host`
gets a ticket for `host/replica_host` with the local `host/` key from the
keytab, refuses a dump newer than its `.dump_ok` stamp, and sends it on TCP 754
(`krb5_prop`): `kprop5_01` sendauth with mutual authentication, the size in
KRB-SAFE, the dump in 32 KiB KRB-PRIV blocks with MIT's chained cipher state,
then waits for the replica's KRB-SAFE acknowledgement and writes
`<file>.<host>.last_prop`.

Each replica runs `krb5-rs-kpropd` (options `-r -s -a -f -F -p -P -d -D -S -t`
and `--pid-file`, as in MIT; inetd mode when stdin is a socket). It
authenticates `host/<its hostname>` from the keytab, checks the client against
`kpropd.acl` (one principal per line, optionally followed by the required
ticket enctype), receives into `<file>.temp` under a lock, renames it to
`<file>` (default `/usr/local/var/krb5kdc/from_master`), runs
`krb5-rs-kdb -r REALM load [-d DB] <file>` (`-p` selects the program), and only
then acknowledges. The replica needs the same master key stash as the primary.

With `iprop_enable = true`, klmdb principal changes are also written to MIT's
iprop update log (`<database_name>.ulog`); `krb5-rs-kdb dump -i1 [-c]`,
`load -i` and `krb5-rs-kproplog` work on it as their MIT counterparts do.

`krb5-rs-kadmind -proponly` serves that log to MIT kpropd in iprop mode
(iprop RPC over RPCSEC_GSS as `kiprop/<host>`, the `p` permission in
`acl_file`, full resyncs through `krb5-rs-kdb dump -i1 -c` and
`krb5-rs-kprop`). Without `-proponly` it also serves kpasswd (RFC 3244,
`kpasswd_port`/`kpasswd_listen`, default 464 on UDP and TCP) for MIT
`kpasswd` and `krb5_set_password`, and MIT's kadm5 admin RPC (program 2112,
`kadmind_port`, default 749) for remote MIT `kadmin`: principal, policy,
string, alias and key reads and changes, `ktadd` (with `-norandkey`), checked
against `acl_file` with MIT's ACL restrictions and written to the update log.

With `iprop_enable = true` in the replica's kdc.conf, `krb5-rs-kpropd` also
polls the primary's iprop service like MIT kpropd: every `iprop_replica_poll`
it asks for the updates after its log's last serial as `kiprop/<its hostname>`
(to `kiprop/<admin_server>`, `-A` overrides `admin_server`), applies them to
the klmdb database and its own update log, and asks for a full resync, which
arrives as a normal kprop push, when the primary no longer has them. The
primary can be MIT `kadmind` or `krb5-rs-kadmind -proponly`. Push-only
replication stays the default.

Deliberate deviations: kpropd `-x` is accepted and ignored and iprop needs
`iprop_port` (no portmapper lookup);
`krb5-rs-kpropd` never forks into the background (use `-D` or a supervisor).
The `kprop_*` kdc.conf keys of the earlier krb5-rs pull protocol
(`KRB5RS-PROP-1`) were removed; configurations that still set them fail with
an error pointing at `krb5-rs-kprop`/`krb5-rs-kpropd`.

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
  `metrics.networkPolicy.from` to admit Prometheus scrapes.
  `kadmin.enabled=true` (file mode) runs `krb5-rs-kadmind` on the primary
  for remote MIT `kadmin` and `kpasswd` through the `<release>-kadmin`
  Service (TCP 749, UDP/TCP 464), with `kadmin.acl` as its `kadm5.acl`. See
  [`deploy/helm/krb5-rs-kdc/examples/multi-region`](deploy/helm/krb5-rs-kdc/examples/multi-region)
  for three regional values files.
- **Podman** (`deploy/podman`): a primary pod (KDC, kprop and a
  `krb5-rs-kadmind` for remote `kadmin` on 749 and `kpasswd` on 464) and an
  optional kpropd replica pod via `podman kube play`, or a Quadlet unit. See
  `deploy/podman/README.md`.
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
