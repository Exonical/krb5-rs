# Pluggable KDC database architecture

Status: design accepted. It is implemented incrementally in PRs 4 to 8 and the
MIT-compatible klmdb follow-up. Sections marked
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

The standalone backends, klmdb (the default) and `FileStore`, with MIT
kprop/kpropd push propagation stay. Nothing in this design removes them.

## 2. Components and crates

| Crate | Contents | Default build |
|---|---|---|
| `krb5-rs` (library) | Store traits and domain models (`kdc::store`), lockout policy logic, replication engine (`kdc::replication`), consistency gate | yes |
| `crates/krb5-rs-kdb-lmdb` | MIT klmdb-compatible principal, policy and lockout store | default module in daemon/admin binaries |
| `crates/krb5-rs-kdb-turso` | Turso replica: `PrincipalStore`, `PolicyStore`, `AuthStateStore`, `ReplicaSink`, migrations | optional module |
| `crates/krb5-rs-kdb-cockroach` | CockroachDB: `AdminStore`, `ReplicationSource`, `AuthoritativeState`, lockout reporter, replica status registry, migrations, TLS | optional module |
| `crates/krb5-rs-kdb-ldap` | MIT kldap-compatible store: principals, ticket and password policies and lockout state in an LDAP directory, MIT's schema in `schema/` | default module in daemon/admin binaries |
| `crates/krb5-rs-kdc` | Daemon and admin CLI. Cargo features `klmdb`, `kldap`, `turso` and `cockroach` compile modules; metrics/health HTTP | klmdb and kldap on by default |

The database modules are **pluggable**. The klmdb backend is compiled in by
default for the daemon and admin binaries and is the default backend: an
unset `db_library` selects klmdb, and `db_library = krb5-rs-file` selects the
krb5-rs file store and `db_library = kldap` the LDAP store. Turso and
CockroachDB are optional features. The core
library remains pure Rust; the daemon/admin binaries include LMDB C code, and
the CockroachDB build adds aws-lc-rs and `turso_core`'s `simsimd`.

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

When `db_library` is unset, klmdb is used; `db_library = krb5-rs-file`
selects `FileStore`.

### MIT klmdb-compatible environment

`db_library = klmdb` selects `krb5-rs-kdb-lmdb`. It mirrors MIT 1.17+
`plugins/kdb/lmdb/kdb_lmdb.c:366-398, 492-547, 554-619`:

- `<database_name>.mdb` has named databases `principal` and `policy`,
  `MDB_NOSUBDIR`, `MDB_NOTLS`, `maxdbs = 2`, and sync enabled unless `nosync`.
- `<database_name>.lockout.mdb` has named database `lockout`, `maxdbs = 1`,
  and `MDB_NOSYNC` unconditionally. It is created but not opened when both
  `disable_lockout` and `disable_last_success` are enabled.
- Both environments use the `mapsize` value in MiB (128 by default), file
  permissions 0600, and LMDB's default reader count when `max_readers = 0`.
- `krb5-rs-kdb create` / `init` seed `K/M` and `krbtgt` with the realm's
  `max_life`, `max_renewable_life`, and optional
  `default_principal_expiration` values. The entries are built in memory,
  written to `<database_name>.create.tmp.*` environments, verified, and only
  then renamed into place (main `.mdb` last), so a failed `create` leaves
  nothing behind and can simply be rerun.
- Creating a principal commits its zeroed lockout record before the
  principal itself. MIT's `klmdb_put_principal` commits the principal first
  and then reports a lockout failure (`plugins/kdb/lmdb/kdb_lmdb.c:747-816`),
  leaving a principal a retried create refuses; here a lockout failure aborts
  the create. Deleting a principal ignores lockout errors, as MIT does
  (`kdb_lmdb.c:833-834`).
- Initial records use MIT's `db_creation` modifier. Later krb5-rs admin
  mutations use `krb5-rs-kdb@REALM`; the `AdminStore` API has no authenticated
  modifier identity.
- The daemon and admin tool read/write synchronously memory-mapped records;
  backend mutations run through `spawn_blocking`. Reads are kept inline
  because each is a short memory-mapped read transaction.

Principal, lockout and policy value formats are the little-endian layouts in
`plugins/kdb/lmdb/marshal.c:48-138, 165-321`. Principal keys are the exact
unparsed names from `lib/krb5/krb/unparse.c:61-134`; parsing and inferred name
types follow `lib/krb5/krb/parse.c:40-172` and `bld_princ.c:31-43`. TL-data
uses the MIT encodings in `lib/kdb/kdb5.c`, `lib/kdb/kdb_default.c`, and
`lib/kadm5/srv/adb_xdr.c`. Updates merge krb5-rs fields into the existing
record; unknown tl-data and string attributes, password history, ACTKVNO,
MKEY_AUX, and unmodeled attribute bits survive.

MIT klmdb and the bundled LMDB 0.9.x use `MDB_DATA_VERSION` 1. The bundled
LMDB lock-file version is 2, versus version 1 in some distro 0.9.x builds. Do
not run MIT and krb5-rs processes on the same environment concurrently;
sequential use is supported. When klmdb is
selected and `<database_name>.mdb` is absent, a legacy krb5-rs file database
is converted under `<database_name>.convert.lock`; the original is retained
as `<database_name>.krb5rs-file.bak`. Conversion writes and verifies temporary
environments before renaming them into place, the main `.mdb` last, so its
presence marks a complete set: if a conversion stops before that rename, the
next open converts again from scratch; if it stops between that rename and the
backup rename, the next open finishes the backup rename (and refuses, naming
both, if a backup already exists). Conversion also holds the file store's own
write lock (`<database_name>.lock`) from export to backup, so it fails with
"retry" rather than lose writes from a process still using the file backend. A
crash leaves that lock file behind, exactly as a crashed file-store writer
does; remove it once no file-store writer is running.

### MIT kldap (LDAP directory)

`db_library = kldap` selects `krb5-rs-kdb-ldap`, which follows MIT 1.22.2's
`plugins/kdb/ldap`. The directory needs MIT's Kerberos schema, shipped in
`crates/krb5-rs-kdb-ldap/schema/` (`kerberos.schema` for slapd.conf,
`kerberos.openldap.ldif` for cn=config, `kerberos.ldif` for other servers).

- **Configuration:** the `[dbmodules]` keys `ldap_kerberos_container_dn`,
  `ldap_kdc_dn`, `ldap_kadmind_dn`, `ldap_kdc_sasl_mech`,
  `ldap_kadmind_sasl_mech` (and the `_sasl_authcid`, `_sasl_authzid` and
  `_sasl_realm` keys), `ldap_service_password_file`, `ldap_servers` and
  `ldap_conns_per_server`, and the `-x` arguments `binddn`, `bindpwd`,
  `nconns`, `sasl_mech`, `sasl_authcid`, `sasl_authzid`, `sasl_realm`,
  `host` and `debug`, as in MIT. The KDC
  binds with the KDC DN and kadmind and `krb5-rs-kdb` with the kadmind DN.
  Unknown arguments fail; `temporary` fails with `KDB module requires
  -update argument`.
- **Service password stash:** `name#{HEX}hex` lines, `!` and `#` comments,
  read as MIT's `kdb5_ldap_util stashsrvpw` writes them.
- **Entries:** MIT's DNs, object classes, search filter
  (`krbprincipalname`, escaped as `ldap_filter_correct`), search scope and
  subtrees, `krbCanonicalName`, the duplicate-entry error, the
  `krbPrincipalKey` ASN.1 key sequence, `krbExtraData`, password history,
  `krbPrincipalAuthInd`, `krbAllowedToDelegateTo` and `nsAccountLock`.
  Ticket lifetimes and flags missing from an entry come from its
  `krbTicketPolicyReference` and then the realm, as in
  `krb5_read_tkt_policy`; `addprinc` without `-maxlife`/`-maxrenewlife`
  leaves them unset.
- **Lockout:** `krbLoginFailedCount`, `krbLastFailedAuth` and
  `krbLastSuccessfulAuth`, with `disable_lockout` and
  `disable_last_success`, as in `krb5_ldap_lockout_audit`.
- **`krb5-rs-kdb`:** `create` makes the realm container, `K/M`, `krbtgt` and
  the kadmin principals as `kdb5_ldap_util create` does; `stash`, `dump`,
  `load -update` and the principal and policy commands work. A load without
  `-update` fails like MIT, and `destroy` fails with MIT's
  `KRB5_PLUGIN_OP_NOTSUPP` message.
- **`krb5-rs-kdb5-ldap-util`:** MIT's `kdb5_ldap_util` (`ldap_util/`):
  `create`, `modify`, `view`, `destroy`, `list`, `stashsrvpw` and the ticket
  policy commands (`create_policy`, `modify_policy`, `view_policy`,
  `destroy_policy`, `list_policy`), with MIT's `-D`/`-w`/`-H`/`-r`/`-P`/`-k`
  /`-sf` options, ticket flag options, prompts and output. `destroy` deletes
  the realm's principals, policies and realm object; a ticket policy that a
  principal's `krbTicketPolicyReference` names is not deleted.
- **Replication:** the directory replicates itself. As in MIT there is no
  update log, so `iprop_enable` with kldap stops kadmind at startup.

SASL binds follow libldap and Cyrus SASL 2.1.28's client plugins.
`EXTERNAL`, `PLAIN`, `LOGIN`, `ANONYMOUS`, `SCRAM-SHA-1`, `SCRAM-SHA-256` and
`OAUTHBEARER` (the token is the bind secret) come from rsasl; `CRAM-MD5`,
`DIGEST-MD5` (with the `auth-int`/`auth-conf` layers: rc4, rc4-56, rc4-40,
des, 3des), `NTLM` (NTLMv1, as Cyrus without `ntlm_v2`), `GSSAPI`,
`GSS-SPNEGO`, `GS2-KRB5` and `GS2-IAKERB` are written for krb5-rs, the GSS
ones on its own GSS-API. As in libldap:

- `SASL_SECPROPS` and `SASL_NOCANON` are read from `ldap.conf`, `ldaprc`,
  `.ldaprc`, `LDAPCONF`, `LDAPRC` and the `LDAPSASL_*` variables, in
  libldap's order; `LDAPNOINIT` skips them. The defaults are
  `noplain,noanonymous`, `minssf` 0, `maxssf` unlimited and `maxbufsize`
  65536, so PLAIN, LOGIN and OAUTHBEARER need TLS or `SASL_SECPROPS none`.
- Mechanisms are filtered by `minssf` and the security flags as in
  `sasl_client_start`, counting the TLS cipher's strength (71 for
  `ldapi://`) as the external SSF. DIGEST-MD5 and GSSAPI pick their layer
  from `minssf`, `maxssf` and `maxbufsize` the way Cyrus does; GSS-SPNEGO
  takes it from the context's flags.
- The SASL host is the local host name for `ldapi://`, the URL's host with
  `SASL_NOCANON`, and otherwise the reverse-DNS name of the connected
  address (the local host name for loopback).

Differences from MIT:

- `krb5-rs-kdb5-ldap-util create` accepts `-kv` and `-M`, but the master key
  is always `K/M` with kvno 1, as `krb5-rs-kdb create` makes it; another `-M`
  name is refused.
- The master-key commands (`add_mkey`, `use_mkey`, `list_mkeys`,
  `purge_mkeys`, `update_princ_encryption`), `ark` and `tabdump` are refused
  on kldap.
- The integration tests (`cargo test -p krb5-rs-kdb-ldap --test openldap --
  --ignored` and `cargo test -p krb5-rs-kdc --test kdb5_ldap_util --
  --ignored`, `cargo test -p krb5-rs-kdb-ldap --test sasl -- --ignored`)
  need `slapd`; `tests/slapd.sh` starts a private instance. The GSSAPI bind
  test also needs MIT's `krb5kdc`.

### Password policy

`krb5-rs-kdb` applies kadm5's password rules for every backend:
`addprinc` with a password and `cpw` check the policy's minimum length and
character classes (`lib/kadm5/srv/server_misc.c:73-102`); `cpw` refuses the
current password, and `addprinc`, `cpw`, randkey and `modprinc -policy` /
`-clearpolicy` set the password expiration from the policy's `pw_max_life` as
MIT does (`lib/kadm5/srv/svr_principal.c:364-412, 601-634, 1219-1497`).
Rejections use MIT's messages ("Password is too short", "Password does not
contain enough character classes", "Cannot reuse password").

Deeper history is kept in `KRB5_TL_KADM_DATA` by every store (klmdb, the
file store and CockroachDB): `cpw` also refuses the passwords kept by
`pw_history_num` and adds the old password to the queue exactly as MIT's
`add_to_history` (`svr_principal.c:1091-1208`), so MIT and krb5-rs tools
share one history. History keys are encrypted in the `kadmin/history`
principal's key, created on first use like MIT's `create_hist`
(`lib/kadm5/srv/server_kdb.c:141-223`), including MIT's 64-second `max_life`
(it stores `KRB5_KDB_DISALLOW_ALL_TIX` there) and initial kvno 2;
`kadmin/history` itself cannot be given a password.

`security_epoch` is a krb5-rs extension and is not persisted in MIT klmdb;
loaded principals and policies use epoch zero. MIT key-data has no
`s2kparams` field, so that krb5-rs key metadata is not persisted either.
`allowed_to_delegate_from` uses the krb5-rs string attribute
`krb5rs_allowed_to_delegate_from`; MIT db2/klmdb do not define a native field
for resource-based delegation. klmdb is the default `db_library`;
`db_library = krb5-rs-file` selects `FileStore`. MIT dump/load is described below.

### MIT master-key rotation

`krb5_rs::kdc::kdb::mit::mkey` mirrors `lib/kdb/kdb5.c`,
`lib/kdb/kdb_default.c` and `kadmin/dbutil/kdb5_mkey.c`:

- **Key list.** `MasterKeys::fetch` is `krb5_def_fetch_mkey_list`: the
  supplied key (stash or password) decrypts `K/M`'s first key-data record
  directly or through a `KRB5_TL_MKEY_AUX` entry, and that newest key
  decrypts the older records. klmdb keeps the list and selects each entry's
  wrapping key by its `KRB5_TL_MKVNO` (default 1).
- **Active key.** `KRB5_TL_ACTKVNO` (default: oldest key active from 0)
  picks the key for new and rekeyed principals (`find_actkvno`). A rekey under
  a different active key rewraps all of the entry's keys and sets `MKVNO`;
  unchanged entries keep their wrapping key.
- **Commands** (klmdb, FileStore and CockroachDB; same output and messages as
  `kdb5_util`):
  - `add_mkey [-e ENCTYPE] [-s]` prompts twice for the new password, adds the
    key as the next `K/M` version (inactive), rewraps the old keys in it and
    adds `MKEY_AUX` entries; `-s` stashes only the new key.
  - `use_mkey KVNO [TIME]` edits `ACTKVNO` as MIT does and requires a key
    active now.
  - `list_mkeys` prints MIT's list, `*` marking the active key.
  - `update_princ_encryption [-f] [-n] [-v] [PATTERN]` rewraps every matching
    principal not on the active key, keeping each key's kvno and salt.
  - `purge_mkeys [-f] [-n] [-v]` drops keys no principal's `MKVNO` uses, with
    their `ACTKVNO`/`MKEY_AUX` entries, and refuses to drop the stashed key.
  - `stash [-f keyfile]` writes every master key version, like `kdb5_util
    stash`. It reuses the existing stash when that opens the database
    ("Using existing stashed keys to update stash file.") and otherwise
    prompts once; `--master-password-file` takes the place of `-m`.
- **Running services** reread `K/M` when an entry names a master key they
  have not loaded, and admin writes reread it first, so `use_mkey` and
  `update_princ_encryption` need no restart.
- **Live test:** `crates/krb5-rs-kdc/tests/mkey_live.rs` runs one rotation
  with MIT `kdb5_util` and finishes it with krb5-rs, then the reverse, and
  compares `list_mkeys`, `update_princ_encryption` and `purge_mkeys` output
  and the decrypted principal keys.

`use_mkey` TIME is parsed by `krb5_rs::kdc::kdb::getdate`, a port of MIT's
`get_date` (`src/kadmin/cli/getdate.y`); as an extension, unix seconds and
RFC 3339 are accepted when `get_date` fails.

FileStore and CockroachDB keep the same model: `K/M` holds every master key
version with `KRB5_TL_ACTKVNO` and `KRB5_TL_MKEY_AUX` (FileStore record field
15, CockroachDB `principals.tl_data`, schema version 3), each principal key
records its `mkvno`, new keys are wrapped under the active master key, and
unchanged keys keep the wrapping they have. The same `krb5-rs-kdb` commands
run against both, and their dumps carry each entry's master key version.

Errors are printed like `kdb5_util`'s `com_err`: the program's base name,
the error text (strerror text for system errors), then the context, for
example `krb5-rs-kdb: LMDB file /var/krb5kdc/principal.mdb does not exist
while initializing database`. As in `open_db_and_mkey`, klmdb commands open
the database before reading the master key; without a stash or with a wrong
master key they warn ("proceeding without master key") and go on, so `dump`
still writes the (still encrypted) dump and exits 1, the master-key commands
report "master keylist not initialized" and exit 2, and `stash` asks for the
password. `create` announces the database and asks for the password twice;
usage errors exit 1. `crates/krb5-rs-kdc/tests/kdb_com_err_live.rs` compares
these messages and exit codes with MIT `kdb5_util`.

Deviations: `add_mkey` without a master key list fails with "master keylist
not initialized" where MIT 1.22.2 aborts on an assertion
(`kdb5_mkey.c:167`). The `krb5-rs-kdb`-only commands (`addprinc`,
`getprinc`, ...) and the FileStore and CockroachDB modules keep their own
messages after the common prefix. Without `-r`, a kdc.conf with a single
realm names the realm even when krb5.conf has no `default_realm`, as for
the other krb5-rs daemons; MIT then fails "while getting default realm".

### MIT dump/load

`krb5-rs-kdb dump` and `load` implement `kdb5_util dump`/`load`
(`src/kadmin/dbutil/dump.c`) for klmdb and the file store. The writer emits
format version 7 by default and versions 6, 5 and 4 with `-r18`, `-r13` and
`-b7`; the reader accepts all four and, for version 7, both policy record
forms (`dump.c:1001-1043`). Records are parsed byte for byte like MIT
(lowercase hex, `-1` for empty octets, length and range checks, `unknown
record type`), the whole file is parsed before the database is touched, and
klmdb output is byte-identical to MIT 1.22.2 (checked-in fixtures in
`tests/fixtures/mit-dump` and the live test). Dump output goes to a
`<file>-<pid>` temporary that is renamed over the target, followed by the
`<file>.dump_ok` stamp; trailing name arguments are anchored regular
expressions as in MIT.

Deviations:

- klmdb non-`-update` loads follow MIT's klmdb module rather than the db2
  `~`-rename: principal and policy databases are cleared and refilled in one
  write transaction that commits only after every record is stored
  (`plugins/kdb/lmdb/kdb_lmdb.c:62-76, 635-647, 1004-1020`). Lockout rows are
  staged in a second transaction that commits right after it (MIT writes
  them per record without a transaction), so a load that fails before the
  main commit changes nothing; stale lockout rows of principals that were
  not reloaded stay, as in MIT. The file store uses `<db>~` plus rename like
  db2 (`plugins/kdb/db2/kdb_db2.c:298, 1419`).
- `-hash` is accepted and ignored; `-rev` and `-recurse` are accepted and
  ignored on dump. `-mkey_convert` and `-new_mkey_file` rewrap every
  dumped key under a new master key, as `master_key_convert` does
  (`dump.c:83-129`); the database itself is unchanged. `-i`/`-c` are described in
  §MIT iprop update log.
- `e_data` is always written empty, as klmdb never stores it
  (`plugins/kdb/lmdb/marshal.c`).
- The file store keeps each principal's keys as dumped and its MIT tl-data
  (string attributes, password history, `MOD_PRINC`, aliases) and, as db2
  does, the lockout fields `last_success`, `last_failed` and
  `fail_auth_count` in the entry: they are dumped and loaded. `load -i` and
  `-x merge_nra` keep the lockout fields of principals already in the
  database (`ctx_merge_nra`, `kdb_db2.c:1404-1412`).

### MIT iprop update log

With `iprop_enable = true` in the realm, every principal change made through
the klmdb store or the file store is appended to MIT's update log
(`src/lib/kdb/kdb_log.c`, `kdb_log.h`, `iprop.x`; code in
`src/kdc/kdb/mit/ulog.rs`). The file is `iprop_logfile` (default
`<database_name>.ulog`) and holds `iprop_ulogsize` entries (default 1000;
`iprop_master_ulogsize` is the older name), byte-compatible with MIT: a
40-byte host-endian `kdb_hlog_t` header, then `ULOG_BLOCK`-sized slots
indexed by `(serial - 1) % entries`, each an XDR `kdb_incr_update_t`. Writes
take MIT's exclusive `fcntl` lock and mark the log unstable around the
update; a record larger than the block grows every slot to the next 2048-byte
multiple; a full ring advances `kdb_first_sno`; serial `u32::MAX` resets the
log. Updates are built like `kdb_convert.c`: a new principal sends every
attribute, a modified one only the changed attributes, and `last_success`,
`last_failed` and `fail_auth_count` are never sent. Policy changes reset the
log, as in MIT.

- `krb5-rs-kdb dump -i` writes the `iprop` format and `dump -i1` the
  `ipropx 1` format, headed by the log's last serial and time and with the
  lockout fields zeroed; `-c` skips the dump when the serial in the existing
  file is still in the log (`dump.c:current_dump_sno_in_ulog`).
- `load -i` reads either header, keeps the replica's lockout state
  (`merge_nra` in `kdb_lmdb.c`), reinitializes the log and sets its last
  serial and time from the header (`ulog_set_last`).
- `krb5-rs-kproplog [-h] [-v] [-v] [-e num]` and `-R` print or reset the log
  like MIT `kproplog`; the two print identical output for the same log.
- Without `iprop_enable`, `dump -i` and `load -i` fail with "Iprop not
  enabled" and no log is written; `-c` without `-i` is refused, as in MIT.

With iprop enabled, `load -update` logs each loaded principal as an update
against its current entry, as `krb5_db_put_principal` does
(`kdb5.c:981-1051`). Each loaded policy reinitializes the log
(`kdb5.c:2441-2525`), so only principals after the dump's last policy stay
logged. A full load reinitializes the log.

The file store logs like MIT's db2 module, which goes through the same
`kdb5.c` calls: each write logs the principals it changed (a rename as a put
of the new name, then a deletion), a policy change reinitializes the log,
and `dump -i`, `load -i`, `load -update`, `krb5-rs-kpropd` replay and
`krb5-rs-kadmind -proponly` work on it as on klmdb. A write the log can't
record is refused before the database changes. Deviation: CockroachDB never
writes a log; it replicates to its KDCs itself.

Deliberate deviations from MIT's log handling (MIT 1.22.2 behaves
otherwise):

- A klmdb principal write and its log entry happen under one exclusive log
  lock (taken before the LMDB write transaction, held by thread and process;
  every `Ulog` handle to the same file in one process shares one descriptor
  and one per-thread gate, since `fcntl` locks only exclude other processes),
  so concurrent writers cannot log changes in a different order than they
  were committed.
- A key change that keeps the same kvno (e.g. `ktadd -norandkey` style
  rewrites or a master-key rewrap) is logged; MIT compares only key versions.
- A log found unstable by a reader is reset only under the exclusive lock.
- An invalid or non-positive `iprop_ulogsize` is a configuration error
  instead of silently falling back to 1000 entries.

### kpropd iprop mode

With `iprop_enable = true` in the replica's kdc.conf realm, `krb5-rs-kpropd`
also runs MIT's `do_iprop` loop (`src/kprop/kpropd.c:628-1018`) next to its
kprop listener. It gets an initial ticket from the `-s` keytab as
`kiprop/<host>` for `kiprop/<admin_server>` (`-A` overrides the krb5.conf
`admin_server`), connects to `iprop_port` with RPCSEC_GSS privacy and calls
`IPROP_GET_UPDATES` with its log's last serial every `iprop_replica_poll`
(else `iprop_slave_poll`, default 2m; 0 means 10s). Updates are applied as
`ulog_replay` does (`kdb_log.c:401-476`, `kdb_convert.c:550-760`): lockout
attributes are ignored, new tl-data types are prepended, each update is
stored in the replica's log under the primary's serial and a failed replay
reinitializes the log. `UPDATE_FULL_RESYNC_NEEDED` sends
`IPROP_FULL_RESYNC_EXT` (falling back to `IPROP_FULL_RESYNC`) at most once
per `iprop_resync_timeout` (default 5m); the primary then pushes with kprop
and kpropd loads it with `load -i`. Busy replies and connection failures
back off `2 << n` seconds up to `MAX_BACKOFF` (300s); permission-denied and
error replies end kpropd with status 1, like MIT. With iprop disabled,
kpropd only receives kprop pushes, the default.
`crates/krb5-rs-kdc/tests/kpropd_iprop_live.rs` has it follow MIT 1.22.2
`kadmind -proponly`.

Without `iprop_port`, kpropd connects to port 0, which fails and backs off,
as in MIT: the default `iprop_port` is 0 (`alt_prof.c:699`) and kadm5's
`connect_to_server` uses it as is, with no portmapper lookup. `-x` takes
klmdb `db_args` (`dbname=PATH`, `temporary`, `merge_nra`; anything else is
`Unsupported argument "..." for LMDB`) for the database the update log is
replayed into, as MIT passes them to `ulog_replay` (`kpropd.c:891`).
`krb5-rs-kadmind -x` and `krb5-rs-kdb -x` take the same arguments. With
`db_library = krb5-rs-file` they take db2's instead (`kdb_db2.c:222-247`):
`dbname=PATH`, `temporary`, `merge_nra`, `hash=...`, `unlockiter` and
`lockiter`; anything else is `Unsupported argument "..." for db2`. The file
store has no db2 access methods, so `hash` and the iteration locks change
nothing; `merge_nra` keeps the current lockout fields on a full load, as
db2's `krb5_db2_promote_db` does.
Deliberate retry deviations from MIT `do_iprop`: a failed
`IPROP_GET_UPDATES` or `IPROP_FULL_RESYNC[_EXT]` call waits the same
`2 << n` backoff before reconnecting instead of reconnecting at once, and a
Busy reply to a resync request clears the resync timer, so the next
`UPDATE_FULL_RESYNC_NEEDED` asks again after the backoff rather than after
`iprop_resync_timeout`.

### kadmind iprop service

`krb5-rs-kadmind -proponly` serves the log like MIT `kadmind -proponly`
(`src/kadmin/server/ovsec_kadmd.c`, `ipropd_svc.c`): `-proponly` refuses to
start without `iprop_enable`; without `-proponly` the iprop service runs
alongside kpasswd when `iprop_enable` is set. Without `iprop_port` (MIT's default of 0)
the system picks the iprop port, as with MIT; `iprop_listen` overrides
both. Program 100423 version 1 runs over
RPCSEC_GSS (§ONC RPC and RPCSEC_GSS) with service keys read from the klmdb
database; calls whose service principal is not `kiprop/<host>@REALM` are
rejected as too weak. The client must hold the `p` permission in `acl_file`
(default `/usr/local/var/krb5kdc/kadm5.acl`), parsed like `auth_acl.c`:
whitespace or comma separated fields, `\` continuation, `*` wildcards in
components and realm, `x`/`*` for every permission, an uppercase letter
removing one, the first matching entry deciding, and entries with a target
not applying to iprop. `IPROP_GET_UPDATES` returns the log entries after the
replica's serial (`ulog_get_entries`); `IPROP_FULL_RESYNC[_EXT]` runs
`krb5-rs-kdb -r REALM dump -i[1] -c FILE` (`-p`, `-F`) and then
`krb5-rs-kprop -r REALM -f FILE [-P PORT] <host>` (`-K`, `-k`). The live test
`crates/krb5-rs-kdc/tests/kadmind_live.rs` has MIT 1.22.2 kpropd follow it
through a full resync and then incremental updates.

kadmind forks into the background once its sockets and ACL are set up, as
MIT does (`ovsec_kadmd.c:507`), unless `-nofork` is given; `-P` then writes
the daemon's pid. Startup errors before that point still reach the
terminal, and the command exits with the daemon's status.

kadmind administers klmdb, kldap, the file store (`db_library =
krb5-rs-file`, as MIT's kadmind does db2) and CockroachDB. On the file store, principals keep
their MIT tl-data, so the modifier in `MOD_PRINC`, string attributes and
aliases read back as on klmdb.

ACL restrictions (the fourth `kadm5.acl` field) are parsed and validated like
`auth_acl.c` `parse_restrictions`: `[+-]flag`, `-clearpolicy`, `-policy POL`
and `-expire`/`-pwexpire`/`-maxlife`/`-maxrenewlife DELTAT`. An invalid
restriction makes the ACL file a syntax error, as in MIT.
`krb5_rs::kdc::kdb::restrictions::AclRestrictions::impose` applies them the way
`auth.c` `impose_restrictions` does. MIT only applies restrictions to kadm5
`create_principal` and `modify_principal`, so they have no effect on iprop,
kpasswd or the read-only kadm5 calls; the kadm5 admin RPC service applies them
to remote `create_principal` and `modify_principal`.

Deliberate iprop-service deviations from MIT `ipropd_svc.c`:

- `IPROP_FULL_RESYNC[_EXT]` is only honored for `kiprop/<host>` clients; any
  other principal with the `p` permission gets `UPDATE_PERM_DENIED`.
- Each replica's resync dump goes to `<dump-file>.<host>-<digest>`: up to
  64 characters of the host (characters outside `[A-Za-z0-9.-]` become `_`)
  and the first 8 bytes of the host's SHA-256 in hex, so concurrent resyncs
  never share one file and long hostnames stay within filename limits.
- `iprop_listen` entries may also be separated by tabs.
- RPCSEC_GSS handling and each iprop call (service-key and ulog reads from
  LMDB) run on Tokio's blocking pool, so a slow read never stalls other
  connections or the kpasswd service; MIT's kadmind is single-threaded.

### kpasswd service

Without `-proponly`, `krb5-rs-kadmind` serves MIT's password-change protocol
(`src/kadmin/server/schpw.c`, RFC 3244) on UDP and TCP at `kpasswd_listen`,
or at `kpasswd_port` (default 464) on every address. Requests of version 1
and `0xff80` are authenticated with an AP-REQ for `kadmin/changepw@REALM`
(service keys from the klmdb database, replay cache, `clockskew`) and carry
the new password, plus an optional target principal for version `0xff80`, in
KRB-PRIV. As in `schpw_util_wrapper` (`misc.c`), a change to the client's own
password needs an initial ticket and respects the policy's `minlife`; any
other target needs the `c` permission in `acl_file`, matched like
`auth_acl.c` (targets with `*1`..`*9` back-references to the client's `*`
components, the first matching entry deciding). The change goes through the
same admin layer as `krb5-rs-kdb` (`kadm5_chpass_principal_util`), so policy,
password history and the update log behave the same. The reply is an AP-REP
and a KRB-PRIV result, or a KRB-ERROR carrying the result in `e-data`, with
MIT's result codes (access denied, initial ticket needed, soft error for
password quality, reuse and `minlife`, hard error otherwise) and
`chpass_util` messages. Database creation adds `kadmin/admin` and
`kadmin/changepw` like `kadm5_create.c`, and `krb5-rs-kdb init` adds any that
are missing from an existing database (one created by an earlier krb5-rs
release), so rerun `init` after upgrading before starting kadmind. The live test
`crates/krb5-rs-kdc/tests/kpasswd_live.rs` runs MIT 1.22.2 `kpasswd` over UDP
and TCP and `krb5_set_password_using_ccache` against it.

Authorization goes through the kadm5_auth modules as `OP_CPW`, as in MIT
`schpw.c`.
Like the admin RPC service below, it runs on klmdb or CockroachDB.

### kadm5 admin RPC service

Without `-proponly`, `krb5-rs-kadmind` serves MIT's kadm5 admin protocol
(ONC RPC program 2112 version 2, `src/lib/kadm5/kadm_rpc_xdr.c`,
`src/kadmin/server/server_stubs.c`) over RPCSEC_GSS on TCP at
`kadmind_listen`, or at `-port`, `kadmind_port` (default 749) on every
address. As in `kadm_rpc_svc.c` `check_rpcsec_auth`, the service principal
must be `kadmin/<instance>@REALM` other than `kadmin/history`, so
`kadmin/admin`, `kadmin/<fqdn>` and `kadmin/changepw` tickets are accepted;
anything else is rejected as too weak. `INIT` negotiates the API version like
`server_stubs.c` (`KADM5_API_VERSION_2`..`4`; MIT clients fall back from 4).

The read-only calls are implemented: `get_principal`, `get_principals`,
`get_policy`, `get_policies`, `get_privs` and `get_strings`, with records
encoded like `kadm_rpc_xdr.c` for the negotiated API version and
`get_principals`/`get_policies` globbing like `svr_iters.c` (an expression
without `@` matches the default realm). The glob is turned into the same
anchored POSIX regular expression as `glob_to_regexp`, so bracket sets accept
`[:class:]` names and, as in MIT, a `^`, `.` or `$` inside brackets is a
literal member together with `\` (there is no bracket negation); it is then
matched in linear time per `*`. Escapes that MIT's BRE would read as groups,
intervals or back-references (`\(`, `\{`, `\1`) are taken as literals.
`get_principal` reports the live `last_success`, `last_failed` and failure
count from `lockout.mdb`, as `krb5_db_get_principal` does. Authorization goes
through the kadm5_auth modules (see below); by default these are MIT's `acl`
(`acl_file`, the `i` and `l` permissions) and `self` (`auth_self.c`: one's own
principal and strings, and one's own policy). A `kadmin/changepw` ticket may only read its own principal and
policy, as in `server_stubs.c`. Requests and denials are logged in MIT's
`Request: ...` / `Unauthorized request: ...` format. The live test
`crates/krb5-rs-kdc/tests/kadmin_live.rs` checks that MIT 1.22.2 `kadmin`
prints the same `getprinc`, `listprincs`, `getpol`, `listpols`, `getstrs` and
`getprivs` output as `kadmin.local` on the same database, MIT's denial
messages, and the `kadmin/changepw` limits through libkadm5clnt at API
versions 2, 3 and 4.

The changing calls are implemented too: `create_principal[3]`,
`delete_principal`, `modify_principal`, `rename_principal`,
`chpass_principal[3]`, `chrand_principal[3]`, `setkey_principal[3,4]`,
`purgekeys`, `set_string`, `create_alias`, `create_policy`, `modify_policy`,
`delete_policy` and `get_principal_keys` (`ktadd -norandkey`). Each needs the
`acl_file` permission `server_stubs.c` asks for (`a`, `d`, `m`, `c`, `s`, `e`;
rename needs `d` on the source and `a` on the target, an alias `a` on the
alias and `m` on the target), and a `kadmin/changepw` ticket may only change
its own password or keys. Changing one's own password or random key is always
allowed with an initial ticket and respects the policy's `minlife`
(`auth_self.c`, `check_min_life`). `create_principal` and `modify_principal`
apply the granting entry's ACL restrictions, and create fills in the realm's
`max_life`, `max_renewable_life` (default 0, as kadmind reads it in
`alt_prof.c`), `default_principal_expiration` and `default_principal_flags`
when the client's mask omits them. As in MIT 1.22, a `-policy` naming a policy
that does not exist is stored and counts as no policy. Also kept from MIT:
`stub_setup` looks up the target of the key, string and modify calls before
authorization, so a missing principal is `KADM5_UNK_PRINC` even for callers
without permission; `setkey_principal[3,4]` with `keepold` refuses a kvno
already present but then drops the old keys anyway (`svr_principal.c` copies
them without counting them); and `-keepold` on one's own principal keeps at
most four old key versions (`clamp_self_keepold`). Principals with
`+lockdown_keys` refuse `get_principal_keys` with the `e` permission error and
key changes other than random keys with `KADM5_PROTECT_KEYS`. Every change
records the caller as the modifier and is appended to the update log while the
update-log lock taken for the database write is still held, so iprop replicas
follow (a crash between the commit and the append leaves the log behind the
database, which the next `kpropd` poll repairs with a full resync, as in MIT).
Client `KADM5_TL_DATA` on create and modify is merged into the principal in
the same write, as `krb5_dbe_update_tl_data` does. Policy `KADM5_POLICY_TL_DATA`
is stored like MIT's: `create_policy` keeps the list as decoded (MIT's
`xdr_krb5_tl_data` reverses it) without checking types, `modify_policy`
refuses types below 256 and applies `krb5_db_update_tl_data` per
element (svr_policy.c:153-159, 349-356), and `get_policy` returns it. klmdb
keeps it in MIT's policy record, FileStore in the policy record and
CockroachDB/Turso in a `tl_data` column (schema version 2), all in MIT LMDB's
`put_tl_data` encoding. `create_policy` also sets MIT's minimum length,
character classes and history of 1 when the client leaves them out
(svr_policy.c:113-134). The live test
`crates/krb5-rs-kdc/tests/kadmin_write_live.rs` runs the same MIT 1.22.2
`kadmin` session against MIT kadmind and against krb5-rs-kadmind (policies,
principals with dates in `get_date` syntax, passwords, random keys with
`-keepold`, `purgekeys`, strings, rename, aliases, `ktadd` with and without
`-norandkey`, lockdown, ACL restrictions, denials and self-service password
changes) and checks that every command prints the same output, that the
resulting principals read back the same through `kadmin.local`, and that both
update logs hold the same number of entries.

With `db_library = krb5-rs-cockroach`, kadmind administers the CockroachDB
realm through the module's `[dbmodules]` connection (the `kdc_admin` role),
the way MIT's kadmind goes through whichever KDB module `db_library` names.
The master key comes from `key_stash_file`, as in MIT. Principals keep their
MIT tl-data in the `principals.tl_data` column, so the modifier in
`MOD_PRINC`, string attributes, client-supplied tl-data and alias entries
(`KRB5_TL_ALIAS_TARGET`, no keys) read back as on klmdb; renaming an alias
fails with `KRB5_KDB_ALIAS_UNSUPPORTED`, as in `kdb5.c`. Every write reads
`K/M` and the principal in one serializable transaction, retried on conflict.
iprop needs klmdb or the file store: kadmind refuses `iprop_enable` with CockroachDB, which
replicates to the KDCs itself. The live test
`crates/krb5-rs-kdc/tests/kadmin_cockroach_live.rs` runs MIT 1.22.2 `kadmin`
(principals, strings, policies, aliases, rename, `cpw`, `delprinc`) and
`kpasswd` against it, and `kinit` against a CockroachDB KDC reading the same
realm.

#### kadm5_auth modules

Every kadm5 call, kpasswd change and iprop request asks the kadm5_auth modules,
as MIT's `kadmin/server/auth.c` does. The built-in modules are `acl`
(`auth_acl.c`) and `self` (`auth_self.c`). Shared-library modules are
configured in krb5.conf or kdc.conf like MIT's:

```
[plugins]
    kadm5_auth = {
        module = mymod:/usr/local/lib/krb5/plugins/kadm5_auth/mymod.so
        enable_only = mymod
        enable_only = acl
        disable = self
    }
```

- `module = name:path` loads `path` (relative paths are under
  `[libdefaults] plugin_base_dir`, default `/usr/local/lib/krb5/plugins`) and
  calls its `kadm5_auth_<name>_initvt`. A module that fails to load, or whose
  `init` returns `KRB5_PLUGIN_NO_HANDLE`, is skipped; any other `init` error
  stops kadmind.
- Configured modules come first, then `acl` and `self`; the first module of
  a name wins. `disable` removes modules, and `enable_only` keeps and orders
  only the modules it names (`lib/krb5/krb/plugin.c`).
- A module authorizes (0), has no opinion (`KRB5_PLUGIN_NO_HANDLE`) or
  refuses (anything else). One refusal denies the request; otherwise at least
  one module must authorize it (`auth.c:182-202`).
- For `addprinc` and `modprinc`, every module's restrictions are imposed, as
  `auth_restrict` does (`auth.c:268-305`).
- Each module's `end` runs after every kadm5 call (`stub_cleanup`).
- As in MIT's single-threaded kadmind, module callbacks never run at once,
  and once a shared-library module is loaded kadmind handles one kadm5,
  kpasswd or iprop request at a time. As in MIT, `end` runs only after kadm5
  calls, not after kpasswd (`misc.c`) or iprop (`ipropd_svc.c`).
- kpasswd asks the modules (`OP_CPW`) for self-changes too, after the
  initial-ticket and minimum-life checks (`misc.c:13-57`).
- The operations and their arguments are MIT's `OP_*` (`auth.h`).

Deviations:

- The module ABI is krb5-rs's own, in
  `crates/krb5-rs-kdc/include/krb5-rs/kadm5_auth_plugin.h`: principals are
  unparsed strings and there is no `krb5_context`, so modules built against
  MIT's `kadm5_auth_plugin.h` do not load. The callbacks, opcodes, return
  codes and restrictions are MIT's.
- Modules need a dynamically linked krb5-rs-kadmind, as MIT's kadmind is.
  The container image (`deploy/docker/Dockerfile`) links glibc dynamically and
  loads them; static musl builds cannot load shared libraries, so
  configuring a module there stops kadmind at startup.

The test modules in `crates/krb5-rs-kdc/tests/fixtures/kadm5_auth_test.c`
port MIT's `plugins/kadm5_auth/test/main.c` (`welcomer`, `bouncer`) and run
MIT's `t_kadm5_auth.py` cases.

#### Password quality and kadm5_hook modules

kadmind (remote kadmin and kpasswd) and `krb5-rs-kdb`'s principal commands
(`addprinc`, `cpw`, `modprinc`, `delprinc`, like `kadmin.local`) run MIT's
password quality (`lib/kadm5/srv/pwqual.c`) and kadm5_hook
(`lib/kadm5/srv/kadm5_hook.c`) modules. Other `krb5-rs-kdb` commands run
none, as `kdb5_util` does.

```
[realms]
    EXAMPLE.COM = {
        dict_file = /usr/share/dict/words
    }
[plugins]
    pwqual = {
        module = mymod:pwqual/mymod.so
        disable = hesiod
    }
    kadm5_hook = {
        module = myhook:kadm5_hook/myhook.so
    }
```

- Passwords pass the policy's length and character-class checks first, then
  each password quality module in order; the first refusal is returned and
  logged with the module and principal (`server_misc.c:73-130`).
- The built-in modules are MIT's, in MIT's order: `dict` refuses, for
  principals with a policy, a password in `dict_file` (one word per
  newline-terminated line, compared case-insensitively; a missing file is
  logged and ignored), `empty` refuses an empty password for every principal,
  `hesiod` does nothing (MIT built without Hesiod), and `princ` refuses, for
  principals with a policy, the realm or any component of the principal name.
  Refusals use MIT's codes (`KADM5_PASS_Q_DICT`, `KADM5_PASS_Q_TOOSHORT`) and
  messages, and kpasswd reports them as MIT's soft errors.
- `module = name:path` loads `pwqual_<name>_initvt` or
  `kadm5_hook_<name>_initvt`; configured modules come before the built-ins,
  and `disable` and `enable_only` apply as for kadm5_auth. A module that fails
  to load or whose `initvt` fails is skipped; a pwqual module whose `open`
  fails or a kadm5_hook module whose `init` fails stops the program.
- Hooks run before (`PRECOMMIT`) and after (`POSTCOMMIT`) addprinc, modprinc,
  delprinc, cpw, randkey, renprinc and alias creation. A precommit error
  aborts the operation with the module's code; a postcommit error is logged
  and ignored (`svr_principal.c`). `fini` and `close` run when the program
  exits, and module callbacks never run at once.

Deviations: the module ABIs are krb5-rs's own, in
`crates/krb5-rs-kdc/include/krb5-rs/pwqual_plugin.h` and
`kadm5_hook_plugin.h` (unparsed principal strings, no `krb5_context`, a
pwqual module writes its message into a buffer), so modules built against
MIT's headers do not load; as with kadm5_auth, static builds cannot load
modules. The test modules in `tests/fixtures/pwqual_test.c` and
`kadm5_hook_test.c` port MIT's `plugins/pwqual/test` (`combo`) and
`plugins/kadm5_hook/test` and run `t_pwqual.py` and `t_kadm5_hook.py`'s cases.

### ONC RPC and RPCSEC_GSS

`krb5_rs::rpc` (feature `tokio`) is ONC RPC version 2 over TCP with MIT's
record marking (`src/lib/rpc/xdr_rec.c`, records capped at 16 MiB) and
RPCSEC_GSS version 1 (RFC 2203; `auth_gss.c`, `svc_auth_gss.c`,
`authgss_prot.c`) on the krb5 GSS mechanism. `GssClient` establishes the
context through `NULLPROC` with `RPCSEC_GSS_INIT`/`CONTINUE_INIT`, checks the
MIC over the sequence window, signs each call header and protects arguments
with the `none`, `integrity` or `privacy` service. `GssServer` returns MIT's
context handle `"xxxx"` and 32-entry window, checks the header MIC, the
replay window and the inner sequence number, and answers bad credentials,
services and procedures with MIT's `auth_stat` values. The live test
`crates/krb5-rs-kdc/tests/oncrpc_live.rs` calls MIT `kadmind -proponly`'s
iprop program (100423, version 1) as `kiprop/<host>` with privacy.

TCP only, one GSS context per connection and the default QOP are what MIT
1.22.2 does too: kadmind's RPC listeners are stream sockets
(`lib/apputils/net-server.c:696-699`) and the kadm5 client uses
`clnttcp_create` (`lib/kadm5/clnt/client_init.c:282`); `svc_auth_gss.c`
keeps one context per transport (`xp_auth`, lines 405-419) and signs and
wraps with `GSS_C_QOP_DEFAULT` (line 230), ignoring the QOP of verified MICs.

Deliberate RPCSEC_GSS server deviations from MIT `svc_auth_gss.c`:

- The replay window advances only after the call header's MIC verifies, so a
  forged call with a high sequence number cannot make valid calls stale.
- Once a context is established, a further `INIT`/`CONTINUE_INIT` on the
  connection is refused with `AUTH_BADCRED` instead of replacing the identity.
- `DATA` and `DESTROY` must carry the server's context handle and the service
  (none, integrity, privacy) agreed at `INIT`; any other value is
  `AUTH_BADCRED`.

### MIT kprop/kpropd

`krb5-rs-kprop` and `krb5-rs-kpropd` follow MIT 1.22.2 `src/kprop`
(`kprop.c`, `kpropd.c`, `kprop_util.c`); the wire code is
`src/kdc/kdb/kprop.rs`. The primary pushes a `krb5-rs-kdb dump` file:
sendauth (`KRB5_SENDAUTH_V1.0`, application version `kprop5_01`, AP-REQ with
mutual authentication as `host/<primary FQDN>` to `host/<replica FQDN>`), the
database size in KRB-SAFE (4 bytes, or 12 with a zero first word for zero and
sizes above `u32::MAX`), the file in 32 KiB KRB-PRIV blocks whose AES cipher
state chains across messages as in MIT's `krb5_mk_priv`, and the replica's
KRB-SAFE echo of the size. Both sides use sequence numbers; only the local
address is set, as in MIT, so NAT works. kpropd checks `kpropd.acl` (a line
starting with the client principal, followed by whitespace and an optional
enctype name that must equal the ticket's), receives into `<file>.temp` under
an exclusive lock, renames it to `<file>`, runs
`krb5-rs-kdb -r REALM load [-d DB] <file>` (a full load, §MIT dump/load) and
acknowledges only after the load succeeds, so a failed load is a failed
propagation on the primary.

Standalone kpropd forks into the background unless `-d` or `-D` is given, as
MIT does (`kpropd.c:276-288`), and `--pid-file` writes the daemon's pid.

Deviations: iprop mode is described in §kpropd iprop mode.
krb5-rs-only additions: `krb5-rs-kprop --interval SECS [--watch PATH] [--kdb PROGRAM]
host...` dumps and pushes forever (the cron job, for shell-less images), and
`krb5-rs-kdc --wait-for-database` lets a replica start before its first push.
The previous krb5-rs pull protocol (`KRB5RS-PROP-1`) and its `kprop_*`
kdc.conf keys are gone; the keys are rejected with a migration error.

## 3. Store interfaces (library, `krb5_rs::kdc::store`)

All of these are async (`fn …(&self, …) -> impl Future<Output = …> + Send`),
`Send + Sync`, and return structured errors (`StoreError` with a kind:
`NotFound`, `Conflict`, `Unavailable`, `Corrupt`, `Stale`, `Rejected`,
`Backend`). No
backend types appear in the signatures.

| Trait | Used by | Responsibility | Implementations |
|---|---|---|---|
| `PrincipalStore` | KDC hot path | `lookup(name, realm) -> Option<PrincipalEntry>`, including encrypted-at-rest keys decrypted with the master key | Memory, File, klmdb, Turso |
| `PolicyStore` | KDC | `policy(name) -> Option<Policy>` (lockout parameters and other KDC-relevant fields) | Memory, File, klmdb, Turso |
| `AuthStateStore` | KDC | per-principal failure counters, last success/failure, local lock (§8) | Memory, klmdb, Turso, Cockroach (realm-wide, through `SharedAuthState`) |
| `AdminStore` | admin CLI | transactional create/modify/delete/rekey/policy operations | File, klmdb, Cockroach |
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

  `last_success`, `last_failed` and `fail_auth_count` are auth state (§8): local to each KDC with klmdb, File and Memory, shared by every KDC in CockroachDB mode. They are **not** fields of `PrincipalEntry`: they live behind `AuthStateStore` as `AuthState`.
- `PrincipalRecord` carries modification metadata (`mod_time`, plus raw MIT
  unparsed `mod_by` bytes when a backend represents them). The file backend
  has no `mod_by` field in its legacy DER image.
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
| `auth_state` | `(realm, name)` | Realm-wide lockout counters written by every KDC (§8): `fail_count`, `last_failed`, `last_success` (MIT `fail_auth_count`, `last_failed`, `last_success`). No row means all zero |
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
`lockouts`, `auth_state`, `replication_log` and `replication_meta` are `LOCALITY GLOBAL`:
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
| `auth_state` | `(realm, name)`: `fail_count`, `last_failed`, `last_success`. Local only, never replicated: the fallback while the KDC cannot reach CockroachDB (§8). The lock end is derived from the policy's duration (MIT `locked_check_p`); a replicated `lockouts` row folds into the state as `fail_count = u32::MAX`, `last_failed = locked_at` while active |
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
- INSERT/UPDATE on `lockouts`, `auth_state` and `replica_status`;
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

### hostrealm, localauth and certauth modules

hostrealm (client and KDC, `krb5_rs::locate`), localauth
(`krb5_rs::localauth`) and certauth (PKINIT KDC,
`krb5_rs::pkinit::certauth`) modules use the same socket RPC and
configuration as kdcpolicy, with MIT's built-in modules after the configured
ones, as in MIT's plugin order:

- **hostrealm:** built-ins `profile`, `dns` and `domain`.
  `krb5_get_host_realm`, `krb5_get_fallback_host_realm` and
  `krb5_get_default_realm` ask each module in turn, as in `hostrealm.c`.
  `PLUGIN_NO_HANDLE` defers to the next module, and any other code stops
  the lookup. The handshake is `KRB5RS-HOSTREALM-V-1`. Calls 3, 4 and 5 are
  `host_realm`, `fallback_realm` and `default_realm`, each answered with
  `as` realms. The connection is opened once per process, like MIT's
  per-context module handles.
- **localauth:** built-ins `default`, `rule`, `names`, `auth_to_local`,
  `k5login` and `an2ln`. The handshake is `KRB5RS-LOCALAUTH-V-1`. Call 3
  is `an2ln_types` (answered with `as` types; empty for an untyped module),
  call 4 is `userok` (`s` principal, `s` local name; success allows,
  `PLUGIN_NO_HANDLE` has no opinion, any other code denies) and call 5 is
  `an2ln` (`s` type, `s` residual, `s` principal; answered with `s` local
  name, or `KRB5_LNAME_NOTRANS`). As in `localauth.c`, typed modules are
  reached only through `auth_to_local`, a module whose types conflict with
  an earlier module's is skipped, and a malformed module spec makes
  `krb5_aname_to_localname` fail and `krb5_kuserok` deny.
- **certauth:** built-ins `pkinit_san`, `pkinit_eku` and `dbmatch`.
  `authorize` (call 3: `ay` certificate, `s` client principal) is answered
  with `i` result code and `as` indicators. At least one module must
  authorize, and none may refuse. `KRB5_CERTAUTH_HWAUTH` and
  `KRB5_CERTAUTH_HWAUTH_PASS` set the hw-authent ticket flag, and module
  indicators come before `pkinit_indicator`, as in `authorize_cert`. The
  handshake is `KRB5RS-CERTAUTH-V-1`.

Differences from MIT:
- Modules run as separate processes, so certauth modules don't get the
  client's database entry.
- The `dns` hostrealm module looks up `_kerberos` TXT records only in
  builds with the `dns` feature, which is MIT's KRB5_DNS_LOOKUP; without
  it the module declines. The Windows `registry` module isn't
  implemented.
- `dbmatch` checks the client certificate against the principal's
  `pkinit_cert_match` string attribute as MIT does; with no attribute it
  declines.

### kdcpolicy and audit modules

krb5-rs-kdc runs MIT's KDC policy (`kdc/policy.c`) and audit
(`kdc/kdc_audit.c`) modules. Each module is a separate process that listens
on a Unix socket, and the KDC sends it each callback over RPC, the way p11-kit
remotes PKCS #11 modules (see
[go-p11-kit](https://github.com/smallstep/go-p11-kit)). They are configured as
in MIT, with a socket in place of the shared library:

```
[plugins]
    kdcpolicy = {
        module = mypolicy:unix:path=/run/krb5/mypolicy.sock
    }
    audit = {
        module = myaudit:myaudit.sock
    }
```

- **Loading:** `module = name:address`, where the address is
  `unix:path=/path` (as in p11-kit's `P11_KIT_SERVER_ADDRESS`) or a socket
  path, relative ones under `plugin_base_dir`. `enable_only` and `disable`
  follow MIT's plugin order; neither interface has built-in modules. A module
  that can't be reached, or refuses the protocol or handshake (MIT's vtable
  version check), is logged and skipped, as MIT skips a module that does not
  load. A kdcpolicy `init` returning `KRB5_PLUGIN_NO_HANDLE` skips the module;
  any other `init` error, or any audit `open` error, stops the KDC. `fini` and
  `close` are sent at shutdown.
- **Protocol** (`krb5_rs::kdc::plugins::rpc`): p11-kit's framing. One version
  byte each way, then messages of `id`, options length and buffer length
  (big-endian `u32`), with a call number, a type signature and the fields. The
  first call is `INITIALIZE` with `KRB5RS-KDCPOLICY-V-1` or
  `KRB5RS-AUDIT-V-1`; errors carry MIT com_err codes. `serve_kdcpolicy` and
  `serve_audit` run a module written in Rust on any stream, and the module
  docs specify the calls for other languages.
- **kdcpolicy:** `check_as` runs after the AS ticket times are computed and
  `check_tgs` after the TGS ones, for every module in order. The first error
  refuses the request with that code and status (MIT's test module returns
  `KRB5KDC_ERR_POLICY`, "LOCAL_POLICY"). Each module's lifetime and renewable
  lifetime cap the end and renew-till times at the KDC time plus that many
  seconds (`update_ticket_times`). TGS checks also get the header ticket's
  client. Both get the request's authentication indicators (below).
- **audit:** `kdc_start` runs when the KDC starts serving and `kdc_stop` on
  shutdown, after open connections finish. Every decoded AS or TGS request
  reports `as_req` or `tgs_req` with its outcome, describing the inner request
  for FAST. TGS requests with PA-FOR-USER or PA-S4U-X509-USER also report
  `s4u2self`, `cname-in-addl-tkt` ones `s4u2proxy` and `enc-tkt-in-skey` ones
  `u2u`, before `tgs_req`. The state carries:
  - a random 31-character request ID, as in MIT;
  - the client address and port;
  - the status string;
  - the S4U2Self user;
  - MIT's ticket IDs (upper-case hex SHA-256 of the ticket ciphertext) for the
    header, evidence and issued tickets;
  - `LOCAL_POLICY` as the violation for a policy refusal.

  Callback results are ignored, as in MIT.
- **Concurrency and failures:** each module gets one connection, and calls on
  it run one at a time. A broken connection is opened again (and the module
  initialized again) on the next call. A kdcpolicy call that fails or times
  out (30 s) refuses the request with `KRB_ERR_GENERIC`; a failed audit call
  is ignored. Module calls block like MIT's, but on the multi-threaded Tokio
  runtime they run through `block_in_place`, so other requests keep being
  served.

Deviations:
- Modules are processes reached over RPC, not MIT shared libraries, so modules
  built for MIT do not load. Static (musl) builds run modules the same way.
- Principals are unparsed strings, and the audit state replaces MIT's
  `krb5_kdc_req`/`krb5_kdc_rep` pointers with strings and the reply error
  code.
- Audit events are reported once per request, from the request and reply,
  rather than at each of MIT's intermediate stages. Requests that do not
  decode are not reported.
- Unix sockets only; on other platforms a configured module is skipped as
  unreachable.

The tests port MIT's `plugins/kdcpolicy/test/main.c` and
`plugins/audit/test/au_test.c` and run the `t_kdcpolicy.py` and `t_audit.py`
cases against the daemon.

### KDC authdata modules

MIT's `kdcauthdata` interface (`kdcauthdata_plugin.h`, `kdc/kdc_authdata.c`)
is `krb5_rs::kdc::plugins::KdcAuthdata`. Modules run in another process and
are reached over the same socket RPC as kdcpolicy (`KRB5RS-KDCAUTHDATA-V-1`,
`plugins::rpc::serve_kdcauthdata`), configured the same way:

```text
[plugins]
    kdcauthdata = {
        module = greet:unix:path=/run/krb5-rs/greet.sock
    }
```

- **Loading:** as `load_authdata_plugins`, a module that cannot be reached,
  refuses the version, or fails `init` is logged and skipped.
- **Arguments:** `handle` gets MIT's `flags` (`KRB5_KDB_FLAG_*`), the client,
  server and header/evidence server, the client (or TGS reply), server and
  header keys, the DER request, the S4U client and the header ticket, and
  may change the reply ticket's authorization data.
- **Order:** as `handle_authdata`: for TGS after the request's authdata is
  copied and before the header ticket's; for AS and TGS before the PAC is
  added; never for an anonymous ticket. A module error is logged as
  `... from authdata module NAME` and the ticket is still issued.
- **`greet`:** `plugins::greet::Greet`, served by
  `cargo run --example kdcauthdata_greet -- SOCKET`, adds to TGS tickets an
  AD-IF-RELEVANT holding an AD-KDC-ISSUED type -42 greeting
  (`Hello, KDC issued acceptor world!`), checksummed with the ticket session
  key (key usage 19) and naming the header ticket's server.
  `make_authdata_kdc_issued` and `verify_authdata_kdc_issued` are MIT's
  `krb5_make_authdata_kdc_issued` and `krb5_verify_authdata_kdc_issued`.

### OTP pre-authentication

As in MIT (`plugins/preauth/otp/main.c`, `otp_state.c`, `lib/krad`,
`lib/krb5/krb/preauth_otp.c`):
- **When offered:** the KDC sends PA-OTP-CHALLENGE (141) only for a
  principal with an `otp` string attribute, in a FAST-armored request
  that is not hardware-only. The nonce is a 4-byte timestamp and random
  bytes as long as the armor key; the challenge has one empty token info.
- **Verification:** PA-OTP-REQUEST (142) `encData` is decrypted with the
  armor key (usage 45); the nonce, or failing that a PA-ENC-TS-ENC
  timestamp, must be within the clock skew. The `otp` attribute is a JSON
  array of tokens (`type`, `username`, `indicators`); `[]` means one
  `DEFAULT` token. Each token is tried in turn with an Access-Request
  (User-Name, User-Password, Service-Type Authenticate-Only, NAS-Identifier
  = the host name); the first Access-Accept succeeds.
- **Token types:** `[otp]` relations `server`, `secret` (a file relative to
  the KDC directory, first line, trimmed), `timeout` (5), `retries` (3),
  `strip_realm` (true) and `indicator`. `DEFAULT` is built in: the Unix
  socket `KDC_RUN_DIR/DEFAULT.socket`, an empty secret and no realm
  stripping. Unix sockets get no retries; UDP is tried `retries + 1` times.
- **Reply key:** the armor key replaces the reply key, and the token's
  indicators (or else its type's) are asserted.
- **Client:** token infos MIT can't handle are dropped; the PIN is
  prepended to the OTP value unless `SEPARATE_PIN`; the nonce is encrypted
  back with the armor key, which becomes the AS reply key. A failed OTP is
  not retried.

Differences: the client has no prompter or responder; the token choice,
OTP value and PIN come from `AsExchangeConfig::otp` (`OtpAnswer`). The
host name sent as NAS-Identifier is `uname`'s node name.

The tests (`tests/kdc_otp.rs`) port MIT's `tests/t_otp.py` cases against
fake UDP and Unix-socket RADIUS servers.

### SecurID SAM-2 pre-authentication

MIT's `securid_sam2` kdcpreauth module (`plugins/preauth/securid_sam2`) and
its `sam2` client module (`lib/krb5/krb/preauth_sam2.c`):
- **When offered:** the KDC sends PA-SAM-CHALLENGE-2 (30) for a client with
  a `<client>/SECURID` principal, else a `<client>/GRAIL` one, and a client
  key. The challenge body carries the client key's mandatory checksum (key
  usage 25), and its track ID is encrypted with the SAM principal's newest
  key (key usage 26). The module is PA_HARDWARE, so the challenge is also
  offered to `requires_hwauth` principals.
- **Verification:** PA-SAM-RESPONSE-2 (31) is decrypted with the client key
  it names (key usage 27); its nonce must match and its SAD must not be
  empty. Success sets HW-AUTHENT and PRE-AUTHENT on the ticket.
- **SecurID:** the passcode goes to the ACE/Server as MIT's `securid2.c`
  sends it: `SD_Init`, `SD_Lock` and `SD_Check` with the client name before
  the `@`; next-code and new-PIN states travel in the track data, which
  holds a host ID. Track data from another host is `KRB5KDC_ERR_DISCARD`,
  and the KDC sends no reply. When the ACE/Server asks for the next code or
  a new PIN, MIT builds a further challenge but passes no e-data to
  `respond`, so the client gets KDC_ERR_PREAUTH_REQUIRED alone; this is
  kept.
- **GRAIL:** MIT's test mechanism ("Enter <n>", answered with n), compiled
  in by MIT only with `GRAIL_PREAUTH`; here it is on only with
  `SecuridSam2::with_grail`.
- **Client:** checks the challenge as MIT does (`KRB5_SAM_NO_CHECKSUM`,
  `KRB5_SAM_UNSUPPORTED` for `MUST_PK_ENCRYPT_SAD` or neither SAD flag,
  `KRB5_SAM_INVALID_ETYPE`), prompts with MIT's name, banner and prompt,
  verifies the keyed checksums with the password key (or the SAD-derived
  key for `USE_SAD_AS_KEY`, which then becomes the reply key) and answers
  with the encrypted nonce and SAD.

The ACE/Server calls go through `kdc::securid_sam2::AceServer`. The
`krb5-rs-kdc` binary loads it like MIT loads the module, from
`[plugins] kdcpreauth`, as a bridge process reached over the module RPC
(`plugins::rpc::serve_securid_ace`):

    [plugins]
        kdcpreauth = {
            module = securid_sam2:unix:path=/run/krb5kdc/securid.sock
        }

Differences: RSA's ACE/Server SDK is proprietary, so it is not linked in;
a deployment runs a bridge that calls it. The host ID is glibc's
`gethostid()` source (`/etc/hostid`, else derived from the host name), and
the track data layout is our own, so a response is only accepted by a
krb5-rs KDC. The client's answer comes from `AsExchangeConfig::sam2`
(`Sam2Responder`); `krb5-rs-kinit` prompts as MIT's `krb5_prompter_posix`
does.

The tests (`tests/kdc_sam2.rs`) run GRAIL and a fake ACE/Server, in
process and over the RPC. Nothing was tested against RSA's ACE/Server or
MIT binaries.

### Authentication indicators

As in MIT (`kdc/authind.c`, `kdc/cammac.c`, `kdc_authdata.c`):
- **Sources:** a successful pre-authentication asserts its configured
  indicators: SPAKE `spake_preauth_indicator`, encrypted challenge
  `[realms] encrypted_challenge_indicator`, and PKINIT `pkinit_indicator`
  for signed (not anonymous) requests, and OTP token or `[otp]` type
  `indicator`s. Encrypted timestamp asserts none.
  Duplicates are dropped.
- **In tickets:** the indicators are encoded as AD-AUTHENTICATION-INDICATOR
  (97, a SEQUENCE OF UTF8String) inside an AD-CAMMAC (96) inside
  AD-IF-RELEVANT. The CAMMAC carries a KDC verifier (key usage 64, the
  current krbtgt key, over the ticket's DER EncTicketPart with the CAMMAC
  elements as its authorization data) and a service verifier (the
  ticket's key, over the elements). They are added before the PAC is
  signed, also when no PAC is issued, and not for `NO_AUTH_DATA_REQUIRED`
  services.
- **TGS:** indicators come from CAMMACs in the header (or evidence) ticket
  whose KDC verifier checks out against the local krbtgt key of the
  verifier's kvno; others are ignored. They go into the new ticket.
  S4U2Self tickets carry none, since the user did not authenticate.
- **`require_auth`:** a service's `require_auth` string attribute
  (`kadmin setstr`) lists indicators separated by spaces. AS and TGS
  requests for it need one of them in the ticket, otherwise
  `KDC_ERR_POLICY` "Required auth indicators not present in ticket".
- **Modules:** kdcpolicy `check_as`/`check_tgs` get the same indicators.

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

**Chosen: MIT's two models, by backend.** Counters follow MIT
`lockout.c` semantics (`pw_max_fail`, `pw_failcnt_interval`,
`pw_lockout_duration`, `disable_lockout`, `disable_last_success`). MIT keeps
them per KDC under kprop and iprop, and in the shared directory with the LDAP
module (`doc/admin/lockout.rst` "KDC replication and account lockout").

- **klmdb, File, Memory (MIT kprop model).** In standalone klmdb mode the
  three fields live in the per-environment `lockout` database. The file
  store keeps them in each principal's entry, as db2 does
  (`plugins/kdb/db2/lockout.c`): the KDC rewrites the file on each counted
  failure and, unless `disable_last_success` is set, each preauthenticated
  success, waiting up to 2 s for another writer's lock; these writes are not
  logged for iprop. A password or key change and `modprinc -unlock` zero
  `fail_auth_count` (`svr_principal.c:677, 1344, 1474, 1736`). The Memory
  backend keeps them in memory. They are never propagated.
- **CockroachDB (MIT LDAP model).** The counters live in CockroachDB
  `auth_state`, and every KDC updates them as `krb5_ldap_lockout_audit` does
  (`plugins/kdb/ldap/libkdb_ldap/lockout.c`): a failed preauthentication or
  bad integrity counts, a preauthenticated success clears the count and
  records `last_success`, and a locked principal is not touched. Each update
  is one read-modify-write transaction, so concurrent failures on different
  KDCs are all counted and the threshold holds realm-wide. Cost: a GLOBAL
  CockroachDB write per failed login, and per preauthenticated success unless
  `disable_last_success` is set. `kadmin getprinc` reads the counters back; `modprinc -unlock` and a password or key change zero
  `fail_auth_count` (`svr_principal.c:677`), and rename and delete move and
  remove the row; an audit racing a delete writes nothing. While CockroachDB
  is unreachable, a KDC counts in its Turso `auth_state` instead
  (`SharedAuthState`), as under kprop. Each shared read or update is copied
  into Turso, so an outage starts from the last shared counters. Any other
  CockroachDB error (permissions, schema) is returned rather than counted
  locally: the lockout check then refuses the login.

When a KDC trips the threshold it also reports the lockout to CockroachDB
`lockouts` asynchronously, with retries and a bounded queue. The report
replicates to every KDC, so a KDC that fell back to local counters still
enforces it. The KDC does not touch `principals` (least privilege), so the
report does not bump the principal's `security_epoch`; `AuthoritativeState`
reports the lockout from the `lockouts` table (an active row means locked),
and an administrative unlock deletes the row in the same transaction that
bumps the epoch and zeroes the counter.

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
- **Kubernetes.** The Helm chart supports file mode (one primary whose kprop
  sidecar pushes to kpropd replicas) and CockroachDB mode. In file mode,
  `kadmin.enabled` runs `krb5-rs-kadmind` beside the primary KDC (without
  `-proponly`; it also serves iprop when `propagation.iprop.enabled` is set)
  for remote MIT `kadmin` and `kpasswd` through the `<release>-kadmin`
  Service, port 749 and 464 mapped to unprivileged container ports, with
  `kadmin.acl` as its `kadm5.acl`; `krb5-rs-kdb init` creates `kadmin/admin`
  and `kadmin/changepw`, whose keys kadmind reads from the database, so no
  keytab is needed. Replicas run no kadmind, as with MIT. In CockroachDB
  mode, `kadmin.enabled` runs a `<release>-kadmin` Deployment
  (`kadmin.replicaCount`, default 1) behind the same Service: an init
  container writes the stash from the master password and kadmind connects as
  `cockroach.admin` (required). In CockroachDB mode, each region runs a KDC
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
