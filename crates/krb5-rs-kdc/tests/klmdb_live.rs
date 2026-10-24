//! MIT 1.22.2 klmdb interoperability. Build the static Linux binaries with
//! `CARGO_TARGET_DIR=/tmp/klmdb-target` in a Rust 1.92 container, copy them to
//! a host directory, and set `KLMDB_LIVE_BIN_DIR` before running this ignored
//! test. All MIT and krb5-rs database users are sequenced, never concurrent.

#![cfg(feature = "klmdb")]

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const DEFAULT_CONTAINER: &str = "krb5-rs-kdc-1";

fn container_cli() -> String {
    std::env::var("CONTAINER_CLI").unwrap_or_else(|_| "podman".into())
}

fn mit_container() -> String {
    std::env::var("KLMDB_LIVE_CONTAINER").unwrap_or_else(|_| DEFAULT_CONTAINER.into())
}

fn output(args: &[&str]) -> std::process::Output {
    Command::new(container_cli())
        .args(args)
        .output()
        .expect("run container CLI")
}

fn run_script(script: &str) {
    let mut child = Command::new(container_cli())
        .args(["exec", "-i", &mit_container(), "bash", "-s"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start MIT container shell");
    child
        .stdin
        .take()
        .expect("script stdin")
        .write_all(script.as_bytes())
        .expect("write script");
    let result = child.wait_with_output().expect("wait for MIT script");
    assert!(
        result.status.success(),
        "klmdb interop script failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(
        String::from_utf8_lossy(&result.stdout).contains("KLMDB_LIVE_OK"),
        "interop script did not reach its final assertion"
    );
}

fn binary_directory() -> PathBuf {
    std::env::var_os("KLMDB_LIVE_BIN_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/klmdb-live")
        })
}

fn copy_binary(source: &Path, destination: &str) {
    assert!(
        source.is_file(),
        "missing Linux musl binary {}; build it in rust:1.92 and set KLMDB_LIVE_BIN_DIR",
        source.display()
    );
    let source = source.to_string_lossy().into_owned();
    let destination = format!("{}:{destination}", mit_container());
    let result = output(&["cp", &source, &destination]);
    assert!(
        result.status.success(),
        "podman cp failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
}

#[test]
#[ignore = "requires the MIT klmdb container and static Linux musl binaries"]
fn mit_and_krb5_rs_share_mit_klmdb_files() {
    let bins = binary_directory();
    copy_binary(&bins.join("krb5-rs-kdb"), "/usr/local/bin/krb5-rs-kdb");
    copy_binary(&bins.join("krb5-rs-kdc"), "/usr/local/bin/krb5-rs-kdc");
    let chmod = output(&[
        "exec",
        &mit_container(),
        "chmod",
        "0755",
        "/usr/local/bin/krb5-rs-kdb",
        "/usr/local/bin/krb5-rs-kdc",
    ]);
    assert!(
        chmod.status.success(),
        "chmod copied binaries failed: {}",
        String::from_utf8_lossy(&chmod.stderr)
    );

    run_script(
        r#"
set -euo pipefail
umask 077
BASE="/tmp/krb5rs-klmdb-live-$$"
REALM=KLMDB.LIVE
MASTER='master-password-for-live-test'
MIT_PORT=18888
RS_PORT=18888
RS_KDB=/usr/local/bin/krb5-rs-kdb
RS_KDC=/usr/local/bin/krb5-rs-kdc
MIT_KDB=$(command -v kdb5_util)
KADMIN=$(command -v kadmin.local)
MIT_KDC_BIN=$(command -v krb5kdc)
ACTIVE_PID=

stop_server() {
  if [ -n "${ACTIVE_PID:-}" ]; then
    kill "$ACTIVE_PID" 2>/dev/null || true
    wait "$ACTIVE_PID" 2>/dev/null || true
    ACTIVE_PID=
  fi
}
cleanup() {
  stop_server
  rm -rf "$BASE"
}
trap cleanup EXIT

write_profile() {
  local dir=$1 port=$2
  mkdir -p "$dir"
  printf '%s\n' "$MASTER" > "$dir/master"
  chmod 0600 "$dir/master"
  cat > "$dir/kdc.conf" <<EOF
[kdcdefaults]
    kdc_ports = $port
    kdc_tcp_ports = $port
[realms]
    $REALM = {
        database_module = lmdb
        database_name = $dir/principal
        key_stash_file = $dir/.k5.$REALM
        master_key_type = aes256-cts-hmac-sha1-96
        supported_enctypes = aes256-cts-hmac-sha1-96:normal aes128-cts-hmac-sha1-96:normal
        max_life = 10h
        max_renewable_life = 7d
    }
[dbmodules]
    lmdb = {
        db_library = klmdb
        database_name = $dir/principal
        mapsize = 32
        max_readers = 32
        nosync = false
        disable_lockout = false
        disable_last_success = false
    }
EOF
  cat > "$dir/krb5.conf" <<EOF
[libdefaults]
    default_realm = $REALM
    dns_lookup_kdc = false
    dns_lookup_realm = false
[realms]
    $REALM = {
        kdc = 127.0.0.1:$port
    }
EOF
}

mit_env() {
  local dir=$1
  shift
  env KRB5_KDC_PROFILE="$dir/kdc.conf" KRB5_CONFIG="$dir/krb5.conf" "$@"
}

mit_create() {
  local dir=$1
  printf '%s\n%s\n' "$MASTER" "$MASTER" |
    env KRB5_KDC_PROFILE="$dir/kdc.conf" KRB5_CONFIG="$dir/krb5.conf" \
      "$MIT_KDB" create -s -r "$REALM" >/dev/null 2>&1
}

mit_admin() {
  local dir=$1
  shift
  env KRB5_KDC_PROFILE="$dir/kdc.conf" KRB5_CONFIG="$dir/krb5.conf" \
    "$KADMIN" -r "$REALM" -q "$*"
}

mit_addprinc() {
  local dir=$1 name=$2 password=$3
  printf '%s\n%s\n' "$password" "$password" |
    env KRB5_KDC_PROFILE="$dir/kdc.conf" KRB5_CONFIG="$dir/krb5.conf" \
      "$KADMIN" -r "$REALM" -q "addprinc +requires_preauth $name" >/dev/null 2>&1
}

mit_addprinc_keysalt() {
  local dir=$1 name=$2 password=$3 salt_type=$4
  printf '%s\n%s\n' "$password" "$password" |
    env KRB5_KDC_PROFILE="$dir/kdc.conf" KRB5_CONFIG="$dir/krb5.conf" \
      "$KADMIN" -r "$REALM" -q \
      "addprinc +requires_preauth -e aes256-cts-hmac-sha1-96:$salt_type $name" \
      >/dev/null 2>&1
}

mit_cpw() {
  local dir=$1 name=$2 password=$3
  printf '%s\n%s\n' "$password" "$password" |
    env KRB5_KDC_PROFILE="$dir/kdc.conf" KRB5_CONFIG="$dir/krb5.conf" \
      "$KADMIN" -r "$REALM" -q "cpw -keepold $name" >/dev/null 2>&1
}

rs_kdb() {
  local dir=$1
  shift
  "$RS_KDB" --config "$dir/kdc.conf" --krb5-config "$dir/krb5.conf" \
    --realm "$REALM" --master-password-file "$dir/master" "$@"
}

rs_addprinc() {
  local dir=$1 name=$2 password=$3
  printf '%s\n' "$password" | rs_kdb "$dir" addprinc +requires_preauth "$name" >/dev/null
}

kinit_try() {
  local dir=$1 name=$2 password=$3 label=$4
  rm -f "$dir/$label.cc"
  printf '%s\n' "$password" |
    env KRB5_CONFIG="$dir/krb5.conf" KRB5CCNAME="FILE:$dir/$label.cc" \
      timeout 12 kinit "$name@$REALM" > "$dir/$label.log" 2>&1
}

mit_kdc_start() {
  local dir=$1
  env KRB5_KDC_PROFILE="$dir/kdc.conf" "$MIT_KDC_BIN" -n -r "$REALM" \
    > "$dir/mit-kdc.log" 2>&1 &
  ACTIVE_PID=$!
  sleep 1
  kill -0 "$ACTIVE_PID"
}

rs_kdc_start() {
  local dir=$1
  "$RS_KDC" --config "$dir/kdc.conf" --krb5-config "$dir/krb5.conf" \
    --realm "$REALM" --listen "127.0.0.1:$RS_PORT" \
    > "$dir/rs-kdc.log" 2>&1 &
  ACTIVE_PID=$!
  sleep 1
  kill -0 "$ACTIVE_PID"
}

expect_locked() {
  local dir=$1 name=$2 password=$3 label=$4
  if kinit_try "$dir" "$name" "$password" "$label"; then
    echo "$name unexpectedly authenticated after lockout" >&2
    exit 1
  fi
  if ! grep -qi 'revok' "$dir/$label.log"; then
    cat "$dir/$label.log" >&2
    echo "$name failed for a reason other than authoritative lockout" >&2
    exit 1
  fi
}

INIT_DIR="$BASE/init"
write_profile "$INIT_DIR" "$MIT_PORT"
"$RS_KDB" --config "$INIT_DIR/kdc.conf" --krb5-config "$INIT_DIR/krb5.conf" \
  --realm "$REALM" --master-password-file "$INIT_DIR/master" \
  init --stash --randkey init_user >/dev/null
"$RS_KDB" --config "$INIT_DIR/kdc.conf" --krb5-config "$INIT_DIR/krb5.conf" \
  --realm "$REALM" getprinc init_user > "$INIT_DIR/init-getprinc.log"
grep -q 'init_user@KLMDB.LIVE' "$INIT_DIR/init-getprinc.log"
test -f "$INIT_DIR/.k5.$REALM"

MIT_DIR="$BASE/mit"
write_profile "$MIT_DIR" "$MIT_PORT"
mit_create "$MIT_DIR"
mit_admin "$MIT_DIR" 'add_policy -minlength 8 -history 3 -maxfailure 1 -failurecountinterval 1h -lockoutduration 1h live-policy'
mit_addprinc "$MIT_DIR" alice 'Alice-Initial-Password'
mit_admin "$MIT_DIR" 'modprinc -policy live-policy -maxlife 10m alice'
mit_admin "$MIT_DIR" 'setstr alice klmdb_live_marker preserved' >/dev/null 2>&1
mit_cpw "$MIT_DIR" alice 'Alice-Second-Password'
mit_addprinc_keysalt "$MIT_DIR" salt_norealm 'Salt-NoRealm-Password' norealm
mit_addprinc_keysalt "$MIT_DIR" salt_onlyrealm 'Salt-OnlyRealm-Password' onlyrealm
mit_addprinc_keysalt "$MIT_DIR" salt_special 'Salt-Special-Password' special

RS_OUTPUT=$(rs_kdb "$MIT_DIR" getprinc alice)
printf '%s\n' "$RS_OUTPUT" | grep -q 'alice@KLMDB.LIVE'
printf '%s\n' "$RS_OUTPUT" | grep -q '00:10:00'
RS_POLICY=$(rs_kdb "$MIT_DIR" getpol live-policy)
printf '%s\n' "$RS_POLICY" | grep -q 'Number of old keys kept: 3'
printf '%s\n' "$RS_POLICY" | grep -q 'Minimum password length: 8'
printf '%s\n' "$RS_OUTPUT" >/dev/null
RS_LIST=$(rs_kdb "$MIT_DIR" listprincs)
printf '%s\n' "$RS_LIST" | grep -q 'alice@KLMDB.LIVE'

rs_kdb "$MIT_DIR" modprinc -maxlife 20m alice
MIT_STRINGS=$(mit_admin "$MIT_DIR" 'getstrs alice' 2>&1 || true)
printf '%s\n' "$MIT_STRINGS" | grep -q 'klmdb_live_marker.*preserved'
MIT_MODIFIED=$(mit_admin "$MIT_DIR" 'getprinc alice')
printf '%s\n' "$MIT_MODIFIED" | grep -q '00:20:00'
env KRB5_KDC_PROFILE="$MIT_DIR/kdc.conf" KRB5_CONFIG="$MIT_DIR/krb5.conf" \
  "$KADMIN" -r "$REALM" -q 'cpw -pw Alice-Initial-Password alice' \
  > "$MIT_DIR/history.log" 2>&1 || true
grep -qi 'Cannot reuse password' "$MIT_DIR/history.log"

# Password policy: krb5-rs applies MIT's quality rules and shares MIT's
# password history in both directions.
rs_cpw() {
  printf '%s\n' "$3" | rs_kdb "$1" cpw "$2" >/dev/null
}
rs_cpw_fails() {
  local dir=$1 name=$2 password=$3 text=$4
  if printf '%s\n' "$password" | rs_kdb "$dir" cpw "$name" > "$dir/rs-cpw.log" 2>&1; then
    echo "krb5-rs accepted password $password for $name" >&2
    exit 1
  fi
  if ! grep -q "$text" "$dir/rs-cpw.log"; then
    cat "$dir/rs-cpw.log" >&2
    exit 1
  fi
}
mit_admin "$MIT_DIR" 'add_policy -minlength 8 -minclasses 2 -history 3 -maxlife 1d strict-policy' >/dev/null
mit_addprinc "$MIT_DIR" carol 'Carol-Password-0'
mit_admin "$MIT_DIR" 'modprinc -policy strict-policy carol' >/dev/null
rs_cpw_fails "$MIT_DIR" carol 'Sh0rt' 'Password is too short'
rs_cpw_fails "$MIT_DIR" carol 'alllowercase' 'Password does not contain enough character classes'
rs_cpw "$MIT_DIR" carol 'Carol-Password-A'
rs_cpw "$MIT_DIR" carol 'Carol-Password-B'
mit_admin "$MIT_DIR" 'cpw -pw Carol-Password-A carol' > "$MIT_DIR/carol-mit.log" 2>&1 || true
if ! grep -qi 'Cannot reuse password' "$MIT_DIR/carol-mit.log"; then
  cat "$MIT_DIR/carol-mit.log" >&2
  echo "MIT accepted a password krb5-rs put in the history" >&2
  exit 1
fi
mit_admin "$MIT_DIR" 'cpw -pw Carol-Password-X carol' >/dev/null 2>&1
mit_admin "$MIT_DIR" 'cpw -pw Carol-Password-Y carol' >/dev/null 2>&1
rs_cpw_fails "$MIT_DIR" carol 'Carol-Password-X' 'Cannot reuse password'
rs_cpw "$MIT_DIR" carol 'Carol-Password-Z'
mit_admin "$MIT_DIR" 'getprinc carol' > "$MIT_DIR/carol-getprinc.log"
if ! grep 'Password expiration date' "$MIT_DIR/carol-getprinc.log" | grep -vq '\[never\]'; then
  cat "$MIT_DIR/carol-getprinc.log" >&2
  echo "krb5-rs cpw did not set the policy's password expiration" >&2
  exit 1
fi

rs_kdc_start "$MIT_DIR"
authenticated=0
for attempt in $(seq 1 12); do
  if kinit_try "$MIT_DIR" alice 'Alice-Second-Password' rs-alice; then
    authenticated=1
    break
  fi
  sleep 1
done
test "$authenticated" = 1
for spec in \
  'salt_norealm:Salt-NoRealm-Password' \
  'salt_onlyrealm:Salt-OnlyRealm-Password' \
  'salt_special:Salt-Special-Password'; do
  name=${spec%%:*}
  password=${spec#*:}
  if ! kinit_try "$MIT_DIR" "$name" "$password" "rs-$name"; then
    cat "$MIT_DIR/rs-$name.log" >&2
    exit 1
  fi
done
stop_server
for name in salt_norealm salt_onlyrealm salt_special; do
  rs_kdb "$MIT_DIR" modprinc -maxlife 30m "$name"
done
mit_kdc_start "$MIT_DIR"
for spec in \
  'salt_norealm:Salt-NoRealm-Password' \
  'salt_onlyrealm:Salt-OnlyRealm-Password' \
  'salt_special:Salt-Special-Password'; do
  name=${spec%%:*}
  password=${spec#*:}
  if ! kinit_try "$MIT_DIR" "$name" "$password" "mit-$name"; then
    cat "$MIT_DIR/mit-$name.log" >&2
    exit 1
  fi
done
stop_server

mit_addprinc "$MIT_DIR" mit_lock 'Mit-Lockout-Password'
mit_admin "$MIT_DIR" 'modprinc -policy live-policy mit_lock'
mit_kdc_start "$MIT_DIR"
if kinit_try "$MIT_DIR" mit_lock 'wrong-password' mit-lock-fail; then
  echo "MIT KDC accepted a wrong lockout password" >&2
  exit 1
fi
stop_server
rs_kdc_start "$MIT_DIR"
expect_locked "$MIT_DIR" mit_lock 'Mit-Lockout-Password' rs-reads-mit-lockout
stop_server

RS_DIR="$BASE/rs"
write_profile "$RS_DIR" "$MIT_PORT"
printf '%s\n' "$MASTER" | "$RS_KDB" --config "$RS_DIR/kdc.conf" \
  --krb5-config "$RS_DIR/krb5.conf" --realm "$REALM" create -s >/dev/null
rs_addprinc "$RS_DIR" bob 'Bob-Initial-Password'
printf '%s\n' "$MASTER" >/dev/null
rs_kdb "$RS_DIR" addpol -minlength 8 -history 3 -maxfailure 1 \
  -failurecountinterval 1h -lockoutduration 1h rs-policy >/dev/null
rs_kdb "$RS_DIR" modprinc -policy rs-policy bob
mit_env "$RS_DIR" "$KADMIN" -r "$REALM" -q 'getprinc bob' > "$RS_DIR/mit-getprinc.log"
grep -q 'bob@KLMDB.LIVE' "$RS_DIR/mit-getprinc.log"
grep -q 'Policy: rs-policy' "$RS_DIR/mit-getprinc.log"
mit_env "$RS_DIR" "$KADMIN" -r "$REALM" -q 'getpol rs-policy' > "$RS_DIR/mit-getpol.log"
grep -q 'Number of old keys kept: 3' "$RS_DIR/mit-getpol.log"

mit_kdc_start "$RS_DIR"
authenticated=0
for attempt in $(seq 1 12); do
  if kinit_try "$RS_DIR" bob 'Bob-Initial-Password' mit-bob; then
    authenticated=1
    break
  fi
  sleep 1
done
test "$authenticated" = 1
stop_server

rs_addprinc "$RS_DIR" rs_lock 'Rs-Lockout-Password'
rs_kdb "$RS_DIR" modprinc -policy rs-policy rs_lock
rs_kdc_start "$RS_DIR"
if kinit_try "$RS_DIR" rs_lock 'wrong-password' rs-lock-fail; then
  echo "krb5-rs KDC accepted a wrong lockout password" >&2
  exit 1
fi
stop_server
mit_kdc_start "$RS_DIR"
expect_locked "$RS_DIR" rs_lock 'Rs-Lockout-Password' mit-reads-rs-lockout
stop_server

MIT_DUMP="$RS_DIR/ours.dump"
env KRB5_KDC_PROFILE="$RS_DIR/kdc.conf" KRB5_CONFIG="$RS_DIR/krb5.conf" \
  "$MIT_KDB" dump -r "$REALM" "$MIT_DUMP" >/dev/null
LOAD_DIR="$BASE/load"
write_profile "$LOAD_DIR" "$MIT_PORT"
mit_create "$LOAD_DIR"
env KRB5_KDC_PROFILE="$LOAD_DIR/kdc.conf" KRB5_CONFIG="$LOAD_DIR/krb5.conf" \
  "$MIT_KDB" load -r "$REALM" "$MIT_DUMP" >/dev/null
mit_env "$LOAD_DIR" "$KADMIN" -r "$REALM" -q 'getprinc bob' > "$LOAD_DIR/getprinc.log"
grep -q 'bob@KLMDB.LIVE' "$LOAD_DIR/getprinc.log"

terse_all() {
  local dir=$1
  mit_admin "$dir" listprincs 2>/dev/null | grep "@$REALM\$" | sort | while read -r name; do
    mit_admin "$dir" "getprinc -terse $name" 2>/dev/null | grep -v '^Authenticating'
  done
  mit_admin "$dir" listpols 2>/dev/null | grep -v '^Authenticating' | sort | while read -r name; do
    mit_admin "$dir" "getpol -terse $name" 2>/dev/null | grep -v '^Authenticating'
  done
}

RS_DUMP="$RS_DIR/rs.dump"
rs_kdb "$RS_DIR" dump "$RS_DUMP"
test "$(head -n 1 "$RS_DUMP")" = 'kdb5_util load_dump version 7'
test -f "$RS_DUMP.dump_ok"
cmp "$MIT_DUMP" "$RS_DUMP"
terse_all "$RS_DIR" > "$BASE/source.terse"
grep -q 'bob@KLMDB.LIVE' "$BASE/source.terse"

MIT_LOAD="$BASE/mit-load"
write_profile "$MIT_LOAD" "$MIT_PORT"
mit_create "$MIT_LOAD"
mit_env "$MIT_LOAD" "$MIT_KDB" load -r "$REALM" "$RS_DUMP" >/dev/null
terse_all "$MIT_LOAD" > "$BASE/mit-load.terse"
diff "$BASE/source.terse" "$BASE/mit-load.terse"

RS_LOAD="$BASE/rs-load"
write_profile "$RS_LOAD" "$RS_PORT"
mit_create "$RS_LOAD"
mit_addprinc "$RS_LOAD" only-before-load 'Only-Before-Load-1'
rs_kdb "$RS_LOAD" load "$MIT_DUMP"
terse_all "$RS_LOAD" > "$BASE/rs-load.terse"
diff "$BASE/source.terse" "$BASE/rs-load.terse"
rs_kdb "$RS_LOAD" dump "$RS_LOAD/again.dump"
cmp "$MIT_DUMP" "$RS_LOAD/again.dump"
mit_env "$RS_LOAD" "$MIT_KDB" dump -r "$REALM" "$RS_LOAD/mit-again.dump" >/dev/null
cmp "$MIT_DUMP" "$RS_LOAD/mit-again.dump"
rs_kdc_start "$RS_LOAD"
authenticated=0
for attempt in $(seq 1 12); do
  if kinit_try "$RS_LOAD" bob 'Bob-Initial-Password' rs-load-bob; then
    authenticated=1
    break
  fi
  sleep 1
done
test "$authenticated" = 1
stop_server

rs_kdb "$RS_DIR" dump "$BASE/bob.dump" 'bob@KLMDB\.LIVE'
test "$(grep -c '^princ' "$BASE/bob.dump")" = 1
if grep -q '^policy' "$BASE/bob.dump"; then
  echo "name-filtered dump included policies" >&2
  exit 1
fi
mit_addprinc "$RS_LOAD" extra 'Extra-Password-1'
rs_kdb "$RS_LOAD" load -update -hash -verbose "$BASE/bob.dump" 2> "$BASE/update.log"
grep -qx 'bob@KLMDB.LIVE' "$BASE/update.log"
mit_admin "$RS_LOAD" 'getprinc extra' | grep -q 'extra@KLMDB.LIVE'
rs_kdb "$RS_LOAD" dump "$BASE/before-bad.dump"
printf 'kdb5_util load_dump version 9\n' > "$BASE/bad-header.dump"
head -c 700 "$MIT_DUMP" > "$BASE/truncated.dump"
printf 'kdb5_util load_dump version 7\nbogus\t1\n' > "$BASE/bad-type.dump"
for bad in bad-header truncated bad-type; do
  if mit_env "$MIT_LOAD" "$MIT_KDB" load -r "$REALM" "$BASE/$bad.dump" 2> "$BASE/$bad.mit.err"; then
    echo "MIT accepted $bad" >&2
    exit 1
  fi
  if rs_kdb "$RS_LOAD" load "$BASE/$bad.dump" 2> "$BASE/$bad.rs.err"; then
    echo "krb5-rs accepted $bad" >&2
    exit 1
  fi
done
grep -q "dump header bad in $BASE/bad-header.dump" "$BASE/bad-header.mit.err"
grep -q "dump header bad in $BASE/bad-header.dump" "$BASE/bad-header.rs.err"
grep -q 'unknown record type "bogus"' "$BASE/bad-type.mit.err"
grep -q 'unknown record type "bogus"' "$BASE/bad-type.rs.err"
grep -q 'restore failed' "$BASE/truncated.mit.err"
grep -q 'restore failed' "$BASE/truncated.rs.err"
rs_kdb "$RS_LOAD" dump "$BASE/after-bad.dump"
cmp "$BASE/before-bad.dump" "$BASE/after-bad.dump"
rs_kdb "$RS_DIR" dump "$BASE/two.dump" 'K/M@.*' 'bob@KLMDB\.LIVE'
rs_kdb "$RS_LOAD" load "$BASE/two.dump"
rs_kdb "$RS_LOAD" dump "$BASE/replaced.dump"
cmp "$BASE/two.dump" "$BASE/replaced.dump"
mit_admin "$RS_LOAD" 'getprinc bob' | grep -q 'bob@KLMDB.LIVE'
if mit_admin "$RS_LOAD" 'getprinc extra' | grep -q '^Principal: extra@KLMDB.LIVE'; then
  echo "non-update load kept a principal missing from the dump" >&2
  exit 1
fi

echo KLMDB_LIVE_OK
"#,
    );
}
