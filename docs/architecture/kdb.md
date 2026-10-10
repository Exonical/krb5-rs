# Pluggable KDC database architecture

Status: design accepted. It is implemented incrementally in PRs 4 to 8. Sections marked
**(to verify)** are assumptions that the implementing PR must confirm against
real CockroachDB and Turso before relying on them.

## 1. Goals and non-goals

- The authentication path (AS-REQ/TGS-REQ) is served from a local embedded
  database, with no routine network database round trip.
- CockroachDB is the authoritative, multi-region source of truth for all
  administrative state.
- Each KDC instance owns its local Turso database (MVCC journal mode) and its
  storage. Two processes or pods never share one database file.
- Consistency is **fail closed** by default. A KDC that cannot show its
  replica is fresh enough stops authenticating; it does not quietly serve stale
  security state.
- Kerberos protocol code never sees SQL, CockroachDB types or Turso types.
- Not a goal: immediate revocation of tickets that were already issued (§7.4).

The existing `FileStore` + kprop-style propagation (PR 2) stays as the
standalone backend. Nothing in this design removes it.

## 2. Components and crates

| Crate | Contents | Default build |
|---|---|---|
| `krb5-rs` (library) | Store traits and domain models (`kdc::store`), lockout policy logic, replication engine (`kdc::replication`), consistency gate | yes |
| `crates/krb5-rs-kdb-turso` | Turso replica: `PrincipalStore`, `PolicyStore`, `AuthStateStore`, `ReplicaSink`, migrations | optional module |
| `crates/krb5-rs-kdb-cockroach` | CockroachDB: `AdminStore`, `ReplicationSource`, `AuthoritativeState`, lockout reporter, replica status registry, migrations, TLS | optional module |
| `crates/krb5-rs-kdc` | Daemon and admin CLI. Cargo features `turso` and `cockroach` select modules; metrics/health HTTP | modules off by default |

The database modules are **pluggable and optional**: they are not compiled
into the KDC unless their feature is enabled, so the core stays pure Rust. The
CockroachDB module uses `tokio-postgres` (pgwire) with `rustls`. Its crypto
provider is `aws-lc-rs`, chosen for the FIPS 140-3 path. That is the only C
dependency, and only in that module.

Module selection mirrors MIT's `[dbmodules]` / `database_module`:

```
[realms]
    EXAMPLE.COM = { database_module = crdb }
[dbmodules]
    crdb = {
        db_library = krb5-rs-cockroach
        # authoritative store + replication source
        cockroach_url = postgresql://kdc@crdb-public:26257/krb5?sslmode=verify-full
        cockroach_ca = /etc/krb5-rs/crdb/ca.crt
        cockroach_cert = /etc/krb5-rs/crdb/client.kdc.crt
        cockroach_key = /etc/krb5-rs/crdb/client.kdc.key
        # local replica
        # local replica (PR 5 reads the replica from its own dbmodules section:
        # db_library = krb5-rs-turso, replica_path = a directory)
        replica_library = krb5-rs-turso
        replica_path = /var/lib/krb5-rs/replica
    }
```

`db_library = db2` (the default) keeps the existing `FileStore`.

## 3. Store interfaces (library, `krb5_rs::kdc::store`)

All of these are async (`fn …(&self, …) -> impl Future<Output = …> + Send`),
`Send + Sync`, and return structured errors (`StoreError` with a kind:
`NotFound`, `Conflict`, `Unavailable`, `Corrupt`, `Stale`, `Backend`). No
backend types appear in the signatures.

| Trait | Used by | Responsibility | Implementations |
|---|---|---|---|
| `PrincipalStore` | KDC hot path | `lookup(name, realm) -> Option<PrincipalEntry>`, including encrypted-at-rest keys decrypted with the master key | Memory, File, Turso |
| `PolicyStore` | KDC | `policy(name) -> Option<Policy>` (lockout parameters and other KDC-relevant fields) | Memory, File, Turso |
| `AuthStateStore` | KDC | per-principal failure counters, last success/failure, local lock (§8) | Memory, Turso |
| `AdminStore` | admin CLI | transactional create/modify/delete/rekey/policy operations | File, Cockroach |
| `ReplicationSource` | replication engine | `snapshot()` and `changes_since(ts, limit)` | Cockroach |
| `ReplicaSink` | replication engine | `checkpoint()`, `apply(batch)`, `replace_all(snapshot)` (atomic with the checkpoint), replica status | Turso |
| `AuthoritativeState` | consistency gate (strict mode) | `security_state(principal) -> SecurityState { epoch, disabled, locked }` | Cockroach |
| `LockoutReporter` | KDC | best-effort async report of a tripped lockout to the authority | Cockroach, no-op |
| `HealthCheck` | daemon | liveness and readiness inputs | all |

`Kdc` receives these through dependency injection, using a builder with no-op
defaults so that existing `Kdc::new(config, store)` callers behave exactly as
before. The principal store is a generic parameter of `Kdc` (native async traits
are not dyn-compatible); the other services are type-erased inside the builder.
`LockoutReporter` is synchronous and non-blocking (it queues), so it is object
safe as is. Making `PrincipalStore` async makes `Kdc::handle*` async. That is the
one intentional API break.

### Domain model additions

- `PrincipalEntry` gains:
  - `policy: Option<String>`.
  - `security_epoch: u64`. It is bumped by every security-sensitive change: disable, password reset, key rotation or revocation, compromise flag, lockout and unlock, and restrictive policy assignment.
  - `last_admin_unlock`: the time of the last administrative unlock (MIT `KRB5_TL_LAST_ADMIN_UNLOCK`). Lockout counting restarts after it, so it is replicated administrative state.

  `last_success`, `last_failed` and `fail_auth_count` are local auth state, not replicated (§8). They are **not** fields of `PrincipalEntry`: they live behind `AuthStateStore` as `AuthState`.
- `Policy` covers the MIT kadm5 policy fields relevant to the KDC: `pw_max_fail`, `pw_failcnt_interval` and `pw_lockout_duration`, plus `max_life`, `max_renewable_life` and `allowed_keysalts`, which kadmin applies. A policy also has its own `security_epoch`.
- Keys stay `KeyEntry` (kvno, enctype, salt, s2kparams). At rest, both backends
  store only the MIT `encrypt_key.c` layout under the master key. Plaintext keys
  exist only in memory after lookup, as today. The master-key abstraction
  (`kdb::master`) is unchanged, so an HSM or FIPS provider can replace it later.

## 4. Data model

### CockroachDB (authoritative)

All mutations run in one SERIALIZABLE transaction with the CockroachDB
client-side retry protocol (`SAVEPOINT cockroach_restart`).

| Table | Key | Notes |
|---|---|---|
| `realms` | `name` | Realm parameters and master key kvno |
| `principals` | `(realm, name)` | Attributes, policy, lifetimes, expirations, delegation lists, `security_epoch`, `version`, admin metadata (`created_at`, `mod_time`, `mod_by`, `last_pwd_change`) |
| `principal_keys` | `(realm, name, kvno, enctype)` | Master-key-encrypted key, salt, s2kparams, mkvno. Old kvnos are kept for key history |
| `policies` | `name` | Policy fields, `security_epoch`, `version` |
| `lockouts` | `(realm, name)` | Replicated lockout records written by KDCs (§8) |
| `replication_log` | `(commit_ts, entity, realm, key)` | One row per changed entity per transaction. `commit_ts` is the transaction's HLC timestamp (`cluster_logical_timestamp()`), indexed |
| `replication_meta` | singleton | `pruned_before`, the low watermark of retained log rows |
| `replica_status` | `kdc_id` | Heartbeats: region, applied checkpoint, last seen. `REGIONAL BY ROW` |
| `schema_migrations` | `version` | Versioned migrations |

`version` on an entity row is the commit HLC timestamp of the transaction
that last changed it. It is monotonic per entity and needs no application
counter.

**Multi-region.** The database has `PRIMARY REGION` plus the regions
California, Ohio and Washington DC. `principals`, `principal_keys`, `policies`,
`lockouts`, `replication_log` and `replication_meta` are `LOCALITY GLOBAL`:
reads are served consistently by the local region, and writes pay commit-wait.
That suits rarely written administrative data. Multi-region DDL is a separate,
opt-in migration step.

### Turso (local replica)

Same entities, plus the replica's own tables:

| Table | Notes |
|---|---|
| `principals`, `principal_keys`, `policies`, `lockouts` | Mirror of the authoritative rows plus `version_wall`/`version_logical` (the HLC split into two integers, compared in Rust) and `deleted` (a delete keeps a versioned tombstone row, so an older re-create cannot resurrect it). Rowid tables with unique indexes, because MVCC does not support indexes on `WITHOUT ROWID` tables |
| `replication_state` | singleton: `checkpoint_ts`, `snapshot_ts`, `last_success_unix`, `status` |
| `auth_state` | `(realm, name)`: `fail_count`, `last_failed`, `last_success`. Local only, never replicated. The lock end is derived from the policy's duration (MIT `locked_check_p`); a replicated `lockouts` row folds into the state as `fail_count = u32::MAX`, `last_failed = locked_at` while active |
| `schema_migrations` | |

The database is opened in MVCC journal mode (`PRAGMA journal_mode = 'mvcc'`).
Open fails if the mode is not MVCC; there is no WAL fallback. Turso is pinned
to an exact version (`=0.8.1`, with every `turso_*` crate pinned the same) and upgrades are deliberate. The replica's `path` is a directory holding `replica-<snapshot_ts>.db` files and a `CURRENT` pointer (a rebuild writes a new file and switches the pointer). Known limits,
which are documented and benchmarked:
- row versions live in memory;
- `wal_checkpoint(TRUNCATE)` blocks readers (passive checkpointing is still experimental);
- isolation is snapshot isolation, not serializable.

## 5. Replication: why the log, not changefeeds

| | CockroachDB changefeeds | Application-managed log (chosen) |
|---|---|---|
| Production shape | Needs a sink (Kafka, webhook, cloud storage) and a changefeed job. CockroachDB documents sinkless changefeeds as for prototyping | Plain SQL reads by each KDC |
| Jobs | One per consumer, or a fan-out through Kafka | None |
| Ordering | Per key only; resolved timestamps give a watermark | Total order by commit HLC; read timestamp gives a watermark |
| Delivery | At least once, duplicates after restarts | Re-reading is idempotent |
| Resume | `cursor`, limited by the GC window | Checkpoint timestamp, limited by log retention (explicit `pruned_before`) |
| Bootstrap | `initial_scan` | `AS OF SYSTEM TIME` snapshot at T0 |
| Region traffic | Rangefeeds from leaseholders | GLOBAL tables are read locally in each region |
| Latency | Sub-second | Poll interval (default 1s) plus read timestamp lag |

The log wins on operational simplicity, recoverability and correctness that
can be reasoned about. It needs no extra infrastructure. The cost is a few
seconds of propagation latency, which the consistency policy (§7) accounts for.

### Correctness argument **(to verify)**

1. Every admin transaction writes its entity rows and one `replication_log`
   row per changed entity, with `commit_ts = cluster_logical_timestamp()`.
   This pins the commit timestamp: if the transaction is pushed, it restarts
   rather than committing with a stale value.
2. A KDC reads in a read-only transaction at a fixed historical timestamp T
   (`AS OF SYSTEM TIME`). CockroachDB's timestamp cache guarantees that once a
   span has been read at T, no transaction can later commit a write into that
   span at a timestamp ≤ T. So the set of log rows with `commit_ts ∈ (ckpt, T]`
   is complete and final once read.
3. For each batch, the KDC reads the current state of every affected entity at
   the same T. Absent means deleted, which is the tombstone. It applies them in
   one Turso transaction that also sets `checkpoint_ts = T`. Every row from one
   admin transaction shares a `commit_ts`, so logically related changes land
   together.
4. Rows are applied only if the incoming `version` is greater than the local
   `version`. This makes the process idempotent, handles duplicates and
   out-of-order re-reads, and stops stale overwrites. Deletes carry the log
   row's version, and a later re-create has a higher version.
5. A checkpoint advances only in the same Turso transaction that commits the
   data, so a crash never moves it ahead of durable state.

### Bootstrap and rebuild

- **Bootstrap** (no local checkpoint): read every table `AS OF SYSTEM TIME T0`
  and stream it into a new Turso file (MVCC). Commit with `checkpoint_ts = T0`,
  fsync, then atomically swap it in. Incremental polling starts from T0, so
  there is no gap.
- **Rebuild:** if `checkpoint_ts < pruned_before`, the log rows needed are gone.
  Do a bootstrap into a new file and swap it in. Readers keep the old database
  until the swap.
- **Pruning:** an operator job (`krb5-rs-kdb replication prune --older-than 7d`)
  deletes old log rows and raises `pruned_before` in the same transaction.

### Heartbeats and lag

Every KDC upserts `replica_status(kdc_id, region, applied_ts, seen_at)` every
few seconds. Lag is `now - applied_ts`, exported as a metric (§9). The admin CLI
can wait on these heartbeats (`krb5-rs-kdb wait-applied --since <ts>`) to report
how many KDCs have applied a change. A committed transaction is **not** treated
as applied anywhere until the heartbeats show it.

### Transport security

KDC↔CockroachDB uses TLS with certificate authentication
(`sslmode=verify-full`, client certificates). The KDC's database user has only
these privileges:
- SELECT on replicated tables;
- INSERT/UPDATE on `lockouts` and `replica_status`;
- nothing else.
Admin users are separate. Key material is master-key-encrypted in both
databases, never logged, and never exported in metrics.

## 6. Authentication hot path

AS/TGS requests read only from Turso:
- a principal lookup (principal row plus keys in one short read transaction);
- an optional policy lookup;
- a local auth-state read and write.
The consistency gate check is in-memory: it reads the replica status held by
the replication task. Prepared statements are reused per connection, and a
small fixed pool of Turso connections avoids per-request setup. Read
transactions stay short to limit MVCC version retention. Replication applies
small batches in `BEGIN CONCURRENT` transactions and retries on conflict.
There is no extra cache layer unless benchmarks justify one.

## 7. Consistency policy

### 7.1 Freshness

`freshness = now - checkpoint_ts`, using HLC wall time, refreshed on every
successful poll even when nothing changed. The poll advances T, and the
checkpoint follows it.

### 7.2 Modes (`consistency_mode`)

| Mode | Behaviour |
|---|---|
| `bounded` (**default**, fail closed) | Serve from Turso while `freshness ≤ max_staleness` (default 30s). Beyond that, reject with `KDC_ERR_SVC_UNAVAILABLE`, so clients fail over to another KDC, and report not-ready |
| `strict` | Same as `bounded`, plus a per-request `AuthoritativeState` check of the client's `security_epoch` (and the server's for TGS). A local epoch below the authoritative one, or the authority being unreachable within `authoritative_timeout`, rejects the request |

There is no availability-first mode. Partitions never silently weaken the
configured guarantee.

### 7.3 Partitions

A KDC cut off from CockroachDB cannot advance its checkpoint. After
`max_staleness` it fails closed (bounded) or immediately fails closed (strict).
Within the window, a KDC may authenticate a principal that was disabled less
than `max_staleness` ago. That window is the explicit, configured bound.
Regional failures are handled by clients failing over to KDCs in other regions.

### 7.4 Tickets already issued

Disabling a principal does not invalidate tickets already issued; they stay
valid until they expire. The enforcement we add (MIT does not do this: its TGS path never reads the
header ticket's client entry, so it is a krb5-rs extension, `tgs_recheck_client`,
default on): TGS requests re-check the local client principal's state (disabled,
expired, locked out) and pass it through the consistency gate. Tickets carry no
`security_epoch`, so epoch comparison happens only in the gate's strict mode,
against the authoritative state. An existing TGT therefore cannot obtain new service tickets
once the change has replicated. Service tickets already issued remain valid
until their endtime. Ticket lifetimes are the remaining bound and should be set
accordingly.

## 8. Authentication and lockout state

| Strategy | Guarantee | Cost |
|---|---|---|
| Local per KDC | Threshold exact per KDC; globally up to `pw_max_fail × N_kdc` attempts | None |
| Regional aggregation | Exact per region | A regional write per failure |
| Global counters | Exact everywhere | A cross-region write per failure; a hot row under attack |

**Chosen: local counters plus replicated lockouts.** Counters follow MIT
`lockout.c` semantics (`pw_max_fail`, `pw_failcnt_interval`,
`pw_lockout_duration`). They live in Turso `auth_state` and are never
replicated. When a KDC trips the threshold, it locks locally at once and
reports the lockout to CockroachDB `lockouts` asynchronously, with retries and
a bounded queue. The report replicates to every KDC and bumps the principal's
`security_epoch`.

Global guarantee: an attacker gets at most about `pw_max_fail × N_kdc`
attempts, plus whatever fits in the replication delay, before every KDC
enforces the lockout. Admin unlock deletes the lockout record and bumps the
epoch.

## 9. Operations

- **Config.** CockroachDB URL, TLS files, pool size and timeouts; Turso path
  and checkpoint threshold; replication poll interval, read-timestamp lag,
  batch size, retry/backoff and rebuild policy; `consistency_mode`,
  `max_staleness`, `authoritative_timeout`; heartbeat interval.
- **Health and readiness** (HTTP, unprivileged port):
  - `/healthz`: the process is alive;
  - `/readyz`: listeners are bound, the replica is bootstrapped, and freshness
    is within bounds;
  - `/metrics`: Prometheus.
- **Metrics:**
  - lookup latency;
  - AS/TGS database time;
  - replication lag and applied checkpoint;
  - poll failures and retries;
  - snapshot duration;
  - local database errors;
  - requests rejected for staleness or strict-mode mismatch;
  - lockout reports.
  No principal names in high-cardinality labels and no secrets.
- **Shutdown.** Stop the listeners, finish the in-flight apply transaction,
  then exit. The checkpoint is durable with the data, so a restart resumes
  exactly.
- **Kubernetes.** KDCs run as a StatefulSet per region, each pod with its own
  PVC for Turso. No two pods share a database file.

## 10. Testing

These run against real CockroachDB (a multi-node cluster in containers, with
localities california, ohio and washington-dc, secure mode) and real Turso
files:
- bootstrap;
- authentication from the local replica;
- concurrent reads during apply;
- create, delete, password change, rotation and KVNO changes;
- duplicate and out-of-order batches;
- interruption and reconnect via a cuttable TCP proxy;
- restart;
- crash during apply (kill between steps);
- stale-replica rejection;
- a partition producing fail-closed behaviour;
- concurrent admin transactions (retries);
- lag across regions;
- Turso MVCC conflicts and retries.

Criterion benchmarks cover:
- concurrent lookups;
- lookups under replication writes;
- apply throughput.

No performance claims are made without benchmark numbers.
