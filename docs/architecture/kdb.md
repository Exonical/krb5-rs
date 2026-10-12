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
into the KDC unless their feature is enabled, so the default KDC stays pure
Rust. The CockroachDB module uses `tokio-postgres` (pgwire) with `rustls`. Its
crypto provider is `aws-lc-rs`, chosen for the FIPS 140-3 path. The CockroachDB
and Turso modules both contain C dependencies: aws-lc-rs and `turso_core`'s
`simsimd`, respectively.

Module selection mirrors MIT's `[dbmodules]` / `database_module`:

```
[realms]
    EXAMPLE.COM = { database_module = crdb }
[dbmodules]
    crdb = {
        db_library = krb5-rs-cockroach
        # authoritative store, replication source and KDC heartbeat
        cockroach_url = postgresql://kdc_replica@crdb-public:26257/krb5?sslmode=verify-full
        cockroach_ca = /etc/krb5-rs/crdb/ca.crt
        cockroach_cert = /etc/krb5-rs/crdb/tls.crt
        cockroach_key = /etc/krb5-rs/crdb/tls.key
        cockroach_pool_size = 8
        cockroach_connect_timeout = 5s
        cockroach_statement_timeout = 10s
        cockroach_transaction_timeout = 30s
        replication_read = follower
        # local replica owned by this KDC
        replica_path = /var/lib/krb5-rs/replica
        turso_pool_size = 8
        region = california
        consistency_mode = bounded
        max_staleness = 30s
        authoritative_timeout = 500ms
        replication_poll_interval = 1s
        replication_batch_limit = 1000
        replication_retry_min = 100ms
        replication_retry_max = 30s
        replication_rebuild = auto
        replication_heartbeat_interval = 5s
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
| `principals` | `(realm, name)` | Attributes, policy, lifetimes, expirations, delegation lists, `security_epoch`, `deleted` (tombstone), admin metadata (`created_at`, `mod_time`, `mod_by`, `last_pwd_change`) |
| `principal_keys` | `(realm, name, kvno, enctype)` | Master-key-encrypted key, salt, s2kparams, mkvno. Old kvnos are kept for key history |
| `policies` | `name` | Policy fields, `security_epoch`, `deleted` (tombstone) |
| `lockouts` | `(realm, name)` | Replicated lockout records written by KDCs (§8), `deleted` (tombstone) |
| `replication_log` | `(bucket, id)` | One row per changed entity per transaction: `entity`, `realm`, `key`, `op`, `txn_id`. `bucket = floor(now() / bucket_width)`, where `now()` is the transaction's start timestamp, which does not pin the commit timestamp. Polling scans from `bucket(since − D − margin)` and pruning retains the same margin. Rows are ordered by their own MVCC commit timestamp (`crdb_internal_mvcc_timestamp`) |
| `transaction_markers` | per-attempt `id` | Stable logical transaction id plus a fresh physical attempt id, for SQLSTATE 40003 resolution |
| `replication_meta` | singleton | `pruned_before`, the low watermark of retained log rows; `bucket_width_seconds` (10 by default) and `transaction_timeout_ms` (D) shared by writers/readers |
| `replica_status` | `kdc_id` | Heartbeats: region, applied checkpoint, last seen. `REGIONAL BY ROW` |
| `schema_migrations` | `version` | Versioned migrations |

An entity's `version` is not stored. It is the entity row's MVCC commit
timestamp (`crdb_internal_mvcc_timestamp`), read together with the row at the
replication read timestamp T. CockroachDB assigns it at commit, so it is
monotonic per row and needs no application counter and no timestamp pinning.

Rules that make this sufficient:
- Any transaction that changes a principal's keys also updates the
  `principals` row (`mod_time`). The principal row's version therefore covers
  its keys.
- Deletes are tombstones (`deleted = true`, keys removed), so a delete has a
  version and a later re-create has a higher one.
- Tombstones are pruned together with the log: they are only removed below
  `pruned_before`, and a replica behind `pruned_before` rebuilds anyway.

Admin transactions must **never** call `cluster_logical_timestamp()`.
Calling it freezes the transaction's timestamp, so the transaction can no
longer be moved forward. A SERIALIZABLE read-modify-write is then
restart-only: on GLOBAL tables writes must land at a future timestamp, and
any uncertainty or timestamp-cache push forces a restart. That livelocked in
PR 7.

**Multi-region.** The database has `PRIMARY REGION` plus the regions
California, Ohio and Washington DC. `principals`, `principal_keys`, `policies`,
`lockouts`, `replication_log` and `replication_meta` are `LOCALITY GLOBAL`:
reads are served consistently by the local region, and writes pay commit-wait.
`realms` remains regional: it holds bootstrap metadata and making realm
initialization a GLOBAL transaction adds commit-wait without improving the
per-principal replication model. Multi-region DDL is a separate, opt-in
migration step.

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

### Correctness argument (verified against CockroachDB v26.3.2, PR 6)

1. **What each admin transaction writes.** An ordinary SERIALIZABLE
   transaction that never pins its timestamp writes:
   - its entity rows, as tombstones for deletes;
   - one `replication_log` row per changed entity, in
     `bucket = floor(now() / bucket_width)`;
   - a transaction marker for resolving SQLSTATE 40003.
   On 40001 it retries normally. On 40003 it reads the logical transaction
   marker at the present before deciding whether to replay.
2. **Bounded transaction duration.** The server enforces a maximum transaction
   duration D (CockroachDB `transaction_timeout`). The commit MVCC timestamp
   can be ahead of the transaction's start time because of GLOBAL commit-wait
   and gateway HLC skew. A 5s `COMMIT_SKEW_MARGIN` covers the approximately 1s
   closed-timestamp lead plus the 500ms maximum HLC offset, so the oldest
   possible start bucket for a commit at C is `bucket(C - D - margin)`.
   Pruning uses this same overlap.
3. **The read.** A KDC reads in a read-only transaction at a fixed timestamp T
   (`AS OF SYSTEM TIME`, with T taken from inside that transaction). It scans
   buckets `bucket(ckpt - D - margin) ..= bucket(T)` and keeps rows whose
   `crdb_internal_mvcc_timestamp ∈ (ckpt, T]`.
   - **Complete:** the timestamp cache and closed timestamps guarantee that
     nothing can later commit into those spans at a timestamp ≤ T.
   - **Cheap:** the scan is limited to D plus the poll window.
4. **Applying a batch.** For an untruncated poll, the KDC reads every affected
   entity row, including tombstones, at T, with the row's MVCC timestamp as
   its version. For a truncated poll, it selects the log rows and cutoff in
   the T1 read at T, then materializes the entity state in a second read-only
   transaction `AS OF SYSTEM TIME cutoff`. Both paths apply changes in one
   Turso transaction that also sets the checkpoint to the batch's `upto`.
   All rows of one admin transaction share its commit timestamp, so logically
   related changes land together. A truncated batch never splits one commit
   timestamp.
5. **Version check.** Rows are applied only if the incoming version is greater
   than the local version. This makes apply idempotent, handles duplicates and
   out-of-order re-reads, and stops stale overwrites.
6. A checkpoint advances only in the same Turso transaction that commits the
   data, so a crash never moves it ahead of durable state.

**Verified facts (`crates/krb5-rs-kdb-cockroach/tests/facts.rs`, CockroachDB v26.3.2, 3 nodes):**

- `cluster_logical_timestamp()` returns `wall_nanos.logical` with a 10-digit logical part.
- Inside `BEGIN READ ONLY AS OF SYSTEM TIME t` it returns the AOST timestamp, not the present: the replication read gets its `T` from inside the read-only transaction (`follower_read_timestamp()` or the present). An explicit decimal `T` is accepted by AOST and returned unchanged.
- In a write transaction the value read is the commit timestamp: the row's `crdb_internal_mvcc_timestamp` equals it. A transaction that pinned it and is then pushed (a newer committed value on a key it writes) fails with SQLSTATE 40001 instead of committing at the stale value.
- The timestamp cache: a writer into a span another transaction already read commits above that reader's timestamp.
- GLOBAL (non-blocking) write transactions: the pinned timestamp still equals the commit timestamp (difference 0 ms in four runs), and commit-wait on the local test cluster was 2 to 23 ms.
- Licensing: without a license key a cluster has a 7-day grace period from initialisation, then is throttled (5 concurrent open transactions) unless an Enterprise Free/Trial license is installed (docs.cockroachlabs.com/docs/stable/licensing-faqs; `pkg/server/license/enforcer.go`). Multi-region features worked on the unlicensed cluster inside the grace period.
- `transaction_timeout` is the v26.3 server-side transaction-duration bound.
  With `statement_timeout=0` and `transaction_timeout=1s` supplied as startup
  connection options, an explicit transaction with an uncommitted insert was
  left idle for 1.5s. `COMMIT` returned a closed connection and a new session
  found no inserted row. Thus the server, not a client future deadline,
  aborted it. The production pool sets this option on every connection; the
  configured D must equal `replication_meta.transaction_timeout_ms`.
- `crdb_internal_mvcc_timestamp` was read inside AOST on a GLOBAL row after an
  insert and two updates. Each AOST timestamp matched the selected row version,
  and the versions increased monotonically across all three writes.
- With D=3s and the default 10s bucket width, a long-running writer began in
  bucket B, then a reader completed an AOST scan at checkpoint T in the next
  bucket before the writer inserted its log row. After the writer committed,
  the row was found in `bucket(ckpt-D-margin)..=bucket(T2)` with MVCC timestamp
  in `(ckpt,T2]`. The observed start bucket was included by the D-plus-margin
  overlap, and pruning uses the same lower bound.
- Sequential GLOBAL `modprinc` hunts completed **50/50 and 200/200** with zero
  failures. A separate 50-operation regional hunt with a concurrent
  present-time replication reader also completed with zero failures.
- The cuttable-proxy test exercises an actual network partition; the ambiguous
  commit test is explicitly simulated: the database transaction commits, then
  a failpoint synthesizes a lost COMMIT response and verifies the marker. No
  real SQLSTATE 40003 was observed.
- Licensing: this unlicensed CCL v26.3.2 cluster was inside its 7-day grace
  period (initialised 2026-10-10); `enterprise.license` was empty. It was not
  yet subject to the documented 5-open-transaction throttle.

**Caveats found while building it:**

- A follower read is about 4.2 s in the past, so right after a database, its tables, columns or grants are created they do not exist at the read timestamp (SQLSTATE 3D000, 42P01, 42501, 42703). `changes_since` and `snapshot` then read once at the present; a real error repeats there and is returned. A batch whose read timestamp is not above the caller's checkpoint is empty, so the checkpoint never goes backwards after such a fallback.
- When `changes_since` truncates at `limit`, it materializes every entity at the batch's `upto` in a second read-only transaction. Entity versions therefore cannot be newer than the batch checkpoint, even when a later commit changed an entity also present in the truncated batch.
- The `kdc_replica` role inserts log rows with UUID ids and transaction ids; it has no UPDATE or DELETE privilege on the log. Transaction markers are local per-attempt rows indexed by logical transaction id.

### Replication engine and consistency gates

`ReplicationEngine` bootstraps from a streamed snapshot before daemon listener
binding, then polls bounded `ChangeBatch`es and atomically applies each batch
with the checkpoint. It polls immediately after a truncated batch, retries
failures with bounded exponential backoff/jitter, and heartbeats independently.
If `pruned_before` passes the checkpoint, `auto` rebuilds and switches Turso
files; `manual` marks the replica unready.

Freshness is clock-skew safe: the source returns `source_now` and its read
timestamp T together; the KDC stores `source_now - T` and a local monotonic
observation instant, then computes `freshness = source_lag + elapsed`. It never
subtracts the KDC's wall clock from the HLC. `FreshnessGate` is fail-closed
when the replica is unbootstrapped or stale. `StrictGate` additionally checks
every involved principal against `AuthoritativeState`, rejecting a greater
epoch, disabled/locked state, or unavailable authority. Defaults are bounded
mode, 30 s maximum staleness and 500 ms authoritative timeout. Bounded mode may
serve a newly disabled principal until its change replicates; strict mode
rejects it as soon as CockroachDB reports the disable.

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
can wait on these heartbeats to report how many live KDCs have applied a
change; use `krb5-rs-kdb replication wait-applied --since <ts> --live-within 2m`
to choose a 2m live window (the default). For all serving KDCs to be represented, use
`live_within >= max_staleness + heartbeat_interval`. A KDC unable to reach
CockroachDB for that long has already failed closed. A KDC whose heartbeats
fail while its replication polls succeed is excluded from the live count, but
it still converges within `max_staleness`. A committed transaction is **not**
treated as applied anywhere until the heartbeats show it.

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
| `strict` | Same freshness bound as `bounded`, plus a per-request `AuthoritativeState` check of every client/subject and server. Authoritative denials use MIT's client/server error codes; a greater authoritative epoch or unavailable authority rejects with `KDC_ERR_SVC_UNAVAILABLE` |

The strict gate checks freshness first and denies only when the authority is
stricter than the local state. A newly disabled principal is denied only when
the local entry is not already disabled; an authoritative client lockout or
deletion is final. A local entry already disabled is allowed through the gate
so the KDC's normal MIT checks return the appropriate code. Stale epochs,
authority failures, and stale replicas remain failover errors.

| Role | Authoritative denial | KDC error | Status |
|---|---|---|---|
| Client | Disabled | `KDC_ERR_CLIENT_REVOKED` (18) | `AUTHORITATIVE_CLIENT_DISABLED` |
| Client | Locked out | `KDC_ERR_CLIENT_REVOKED` (18) | `AUTHORITATIVE_CLIENT_LOCKED_OUT` |
| Client | Deleted (`NotFound`) | `KDC_ERR_C_PRINCIPAL_UNKNOWN` (6) | `AUTHORITATIVE_CLIENT_DELETED` |
| Server | Disabled | `KDC_ERR_S_PRINCIPAL_UNKNOWN` (7) | `AUTHORITATIVE_SERVER_DISABLED` |
| Server | Deleted (`NotFound`) | `KDC_ERR_S_PRINCIPAL_UNKNOWN` (7) | `AUTHORITATIVE_SERVER_DELETED` |

Servers are not subject to lockout. An authority epoch above the local entry's
epoch is not a final denial: the local keys may be stale, so strict mode
rejects with `KDC_ERR_SVC_UNAVAILABLE` / `AUTHORITATIVE_MISMATCH`. Authority
timeouts and errors other than `NotFound` use
`KDC_ERR_SVC_UNAVAILABLE` / `AUTHORITY_UNAVAILABLE`.

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
a bounded queue. The report replicates to every KDC. The KDC does not touch
`principals` (least privilege), so the report does not bump the principal's
`security_epoch`; `AuthoritativeState` reports the lockout from the `lockouts`
table (an active row means locked), and an administrative unlock deletes the
row in the same transaction that bumps the epoch.

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
  - `/readyz`: the replica is bootstrapped, not rebuilding or marked for
    rebuild, and freshness is within bounds;
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
- **Kubernetes.** The Helm chart supports file/kprop mode (one primary plus
  replicas) and CockroachDB mode. In CockroachDB mode, each region runs a KDC
  StatefulSet with a PVC per pod, an idempotent bootstrap Job as a
  pre-install/pre-upgrade hook, and an optional prune CronJob; startup,
  readiness and liveness use the HTTP probes. Use the `-cockroach` image
  variant. See
  [`deploy/helm/krb5-rs-kdc/examples/multi-region`](../../deploy/helm/krb5-rs-kdc/examples/multi-region)
  for regional values.

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
- `strict_mode_rejects_authoritative_security_changes_the_replica_has_not_applied`:
  strict rejects an unapplied disable, epoch change and unavailable authority,
  while bounded mode serves during its documented replication window;
- `an_engine_restarted_on_existing_turso_state_resumes_without_a_snapshot`:
  restart resumes an existing checkpoint without rebuilding;
- `shutdown_during_an_apply_waits_for_it_and_leaves_no_partial_batch`:
  shutdown waits for the active atomic apply, then restart catches up;
- `a_lagging_kdc_fails_closed_while_a_current_kdc_serves_and_heartbeats_show_progress`:
  delayed-link lag is local to one KDC, regional progress is reported
  independently, and the replica recovers;
- crash during apply (kill between steps);
- shutdown during an apply, verifying it completes before the engine exits;
- stale-replica rejection;
- a partition producing fail-closed behaviour;
- concurrent admin transactions (retries);
- Turso MVCC conflicts and retries.

Criterion benchmarks cover:
- concurrent lookups;
- lookups under replication writes;
- apply throughput.

No performance claims are made without benchmark numbers.

### Recorded results

These are from `cargo bench -p krb5-rs-kdb-turso` (criterion, release
build). They were run on one Windows development machine against a replica
with 1000 principals, Turso 0.8.1 in MVCC mode. Each iteration is N
concurrent tasks doing 20 lookups each. Variance between runs is large, so
treat these as indicative.

| Case | Throughput |
|---|---|
| Lookup, 1 task | ~43.6K lookups/s |
| Lookup, 8 tasks | ~149K lookups/s |
| Lookup, 64 tasks | ~150K lookups/s |
| Lookup while apply runs flat out, 1 task | ~2.6K lookups/s |
| Lookup while apply runs flat out, 8 tasks | ~13.9K lookups/s |
| Lookup while apply runs flat out, 64 tasks | ~52.4K lookups/s |
| Apply, batch of 1 principal | ~255 principals/s |
| Apply, batch of 10 | ~770 principals/s |
| Apply, batch of 100 | ~235 principals/s |
| Apply, batch of 1000 | ~181 principals/s |

The continuous-apply run above used a writer loop that did not match production
traffic. A second harness applies a batch of 10 principals either every second
or every 100ms and records per-lookup p50/p99 over two-second windows. Results
are microseconds, from the same single Windows development machine and
1000-principal Turso 0.8.1 MVCC fixture.

| Replication rate | Pool | Concurrency | Lookup p50 | Lookup p99 |
|---|---:|---:|---:|---:|
| Idle | 8 | 1 | 33.2 | 173.8 |
| Idle | 8 | 8 | 49.0 | 307.3 |
| Idle | 8 | 64 | 50.1 | 2163.0 |
| 10 principals/s | 8 | 1 | 34.9 | 167.4 |
| 10 principals/s | 8 | 8 | 48.6 | 303.1 |
| 10 principals/s | 8 | 64 | 48.2 | 1687.9 |
| 10 principals/100ms | 8 | 1 | 35.9 | 177.2 |
| 10 principals/100ms | 8 | 8 | 49.1 | 282.8 |
| 10 principals/100ms | 8 | 64 | 447.2 | 2705.8 |

At concurrency 64, the default 8-connection pool showed a p50 rise under
10-principals/100ms traffic. Repeating the same harness with a 64-connection
pool produced idle p50/p99 of 48.6/1582.5us and 10-principals/100ms p50/p99
of 45.7/1618.8us. The pool uses a semaphore in `Inner::conn()`; increasing
the pool removed the p50 regression in this experiment, supporting pool
checkout contention as the cause rather than a long writer/checkpoint lock.
This is a local-machine diagnostic, not a cross-region performance claim.
With the 64-connection pool the 10-principals/100ms apply latency was p50
3.8ms and p99 6.7ms at concurrency 64 (19 batches).

- **Apply is slow per principal.** The older continuous benchmark applies
  about 5 statements per upsert, and throughput does not improve with batch
  size. This puts the bootstrap of large realms in the minutes range, so the
  bulk rebuild path still needs optimizing.
- **Turso 0.8.1 drops autocommit writes in MVCC mode.** In our probe, an
  autocommit `INSERT` was not visible after reopening the database; the
  same insert inside an explicit `BEGIN CONCURRENT … COMMIT` was. Every write
  in the module therefore uses an explicit transaction.
