//! MIT 1.22.2 master-key rotation interoperability (`kdb5_util add_mkey`,
//! `use_mkey`, `list_mkeys`, `update_princ_encryption`, `purge_mkeys`) on
//! shared klmdb files. Setup is the same as `klmdb_live.rs`.

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
fn mit_and_krb5_rs_rotate_master_keys_interchangeably() {
    let bins = binary_directory();
    copy_binary(&bins.join("krb5-rs-kdb"), "/usr/local/bin/krb5-rs-kdb");
    let chmod = output(&[
        "exec",
        &mit_container(),
        "chmod",
        "0755",
        "/usr/local/bin/krb5-rs-kdb",
    ]);
    assert!(
        chmod.status.success(),
        "chmod copied binary failed: {}",
        String::from_utf8_lossy(&chmod.stderr)
    );

    run_script(
        r#"
set -euo pipefail
umask 077
export TZ=UTC
BASE="/tmp/krb5rs-mkey-live-$$"
REALM=KLMDB.LIVE
MASTER='master-password-for-live-test'
SECOND='second-master-password-live'
RS_KDB=/usr/local/bin/krb5-rs-kdb
MIT_KDB=$(command -v kdb5_util)
KADMIN=$(command -v kadmin.local)
trap 'rm -rf "$BASE"' EXIT

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

# Stash-based (no --master-password-file), like MIT kdb5_util without -m.
rs_util() {
  local dir=$1
  shift
  "$RS_KDB" --config "$dir/kdc.conf" --krb5-config "$dir/krb5.conf" --realm "$REALM" "$@"
}
mit_util() {
  local dir=$1
  shift
  env KRB5_KDC_PROFILE="$dir/kdc.conf" KRB5_CONFIG="$dir/krb5.conf" "$MIT_KDB" -r "$REALM" "$@"
}
same() {
  if ! diff -u "$1" "$2"; then
    echo "outputs differ: $1 $2" >&2
    exit 1
  fi
}
keys_of() {
  local dir=$1 name=$2 kt=$3
  rm -f "$kt"
  mit_admin "$dir" "ktadd -norandkey -k $kt $name" >/dev/null
  klist -kK "$kt" | tail -n +4
}

# --- MIT rotates, krb5-rs reads and finishes the rotation ---------------
A="$BASE/mit"
write_profile "$A" 18888
mit_create "$A"
mit_addprinc "$A" alice alice-password-1
mit_addprinc "$A" bob bob-password-1
printf '%s\n%s\n' "$SECOND" "$SECOND" | mit_util "$A" add_mkey -s >/dev/null
mit_util "$A" list_mkeys > "$BASE/a.mit.list"
rs_util "$A" list_mkeys > "$BASE/a.rs.list"
same "$BASE/a.mit.list" "$BASE/a.rs.list"
grep -q 'KVNO: 2, Enctype: aes256-cts-hmac-sha1-96, No activate time set' "$BASE/a.rs.list"

n=0
for when in "2030-01-15 10:30" "jan 15, 2030 10pm est" "15-jan-2030" \
  "1/15/2030 22:30:05 gmt" "next monday" "(soon) 2030-06-01 12am" never; do
  n=$((n + 1))
  mit_util "$A" use_mkey 2 "$when"
  mit_util "$A" list_mkeys > "$BASE/date$n.mit.list"
  rs_util "$A" use_mkey 2 "$when"
  rs_util "$A" list_mkeys > "$BASE/date$n.rs.list"
  same "$BASE/date$n.mit.list" "$BASE/date$n.rs.list"
done
if rs_util "$A" use_mkey 2 "10:30 11:30" 2>/dev/null; then
  echo "use_mkey accepted a date MIT rejects" >&2
  exit 1
fi

rs_util "$A" use_mkey 2
mit_util "$A" list_mkeys > "$BASE/a2.mit.list"
rs_util "$A" list_mkeys > "$BASE/a2.rs.list"
same "$BASE/a2.mit.list" "$BASE/a2.rs.list"
grep -q '^KVNO: 2, .* \*$' "$BASE/a2.mit.list"

mit_util "$A" update_princ_encryption -n -v > "$BASE/a.mit.upe"
rs_util "$A" update_princ_encryption -n -v > "$BASE/a.rs.upe"
same "$BASE/a.mit.upe" "$BASE/a.rs.upe"
mit_util "$A" purge_mkeys -n -v > "$BASE/a.mit.purge-n"
rs_util "$A" purge_mkeys -n -v > "$BASE/a.rs.purge-n"
same "$BASE/a.mit.purge-n" "$BASE/a.rs.purge-n"

keys_of "$A" alice "$BASE/alice-before.kt" > "$BASE/alice-before.keys"
rs_util "$A" update_princ_encryption -f -v 'alice*' > "$BASE/a.rs.upe-alice"
grep -q '^updating: alice@KLMDB.LIVE$' "$BASE/a.rs.upe-alice"
mit_admin "$A" 'getprinc alice' | grep -q 'MKey: vno 2'
mit_admin "$A" 'getprinc bob' | grep -q 'MKey: vno 1'
keys_of "$A" alice "$BASE/alice-after.kt" > "$BASE/alice-after.keys"
same "$BASE/alice-before.keys" "$BASE/alice-after.keys"
mit_util "$A" update_princ_encryption -f > /dev/null
mit_util "$A" purge_mkeys -n -v > "$BASE/a.mit.purge2-n"
rs_util "$A" purge_mkeys -n -v > "$BASE/a.rs.purge2-n"
same "$BASE/a.mit.purge2-n" "$BASE/a.rs.purge2-n"
grep -q '^KVNO: 1$' "$BASE/a.rs.purge2-n"
rs_util "$A" purge_mkeys -f -v > "$BASE/a.rs.purge"
grep -q '^1 key(s) purged.$' "$BASE/a.rs.purge"
mit_util "$A" list_mkeys > "$BASE/a3.mit.list"
test "$(grep -c '^KVNO' "$BASE/a3.mit.list")" = 1
keys_of "$A" bob "$BASE/bob.kt" > /dev/null

# --- krb5-rs rotates, MIT reads and finishes the rotation ---------------
B="$BASE/rs"
write_profile "$B" 18889
printf '%s\n' "$MASTER" | rs_util "$B" create -s >/dev/null
printf '%s\n' carol-password-1 | rs_util "$B" addprinc carol >/dev/null
printf '%s\n' dave-password-1 | rs_util "$B" addprinc dave >/dev/null
printf '%s\n%s\n' "$SECOND" "$SECOND" | rs_util "$B" add_mkey -s > "$BASE/b.rs.add"
printf '%s\n' "Creating new master key for master key principal 'K/M@$REALM'" \
  'You will be prompted for a new database Master Password.' \
  'It is important that you NOT FORGET this password.' > "$BASE/b.expected.add"
same "$BASE/b.expected.add" "$BASE/b.rs.add"
mit_util "$B" list_mkeys > "$BASE/b.mit.list"
rs_util "$B" list_mkeys > "$BASE/b.rs.list"
same "$BASE/b.mit.list" "$BASE/b.rs.list"
mit_util "$B" use_mkey 2
rs_util "$B" list_mkeys > "$BASE/b2.rs.list"
mit_util "$B" list_mkeys > "$BASE/b2.mit.list"
same "$BASE/b2.mit.list" "$BASE/b2.rs.list"
keys_of "$B" carol "$BASE/carol-before.kt" > "$BASE/carol-before.keys"
rs_util "$B" update_princ_encryption -f -v > "$BASE/b.rs.upe"
mit_admin "$B" 'getprinc carol' | grep -q 'MKey: vno 2'
keys_of "$B" carol "$BASE/carol-after.kt" > "$BASE/carol-after.keys"
same "$BASE/carol-before.keys" "$BASE/carol-after.keys"
mit_util "$B" update_princ_encryption -f > "$BASE/b.mit.upe2"
rs_util "$B" update_princ_encryption -f > "$BASE/b.rs.upe2"
same "$BASE/b.mit.upe2" "$BASE/b.rs.upe2"
mit_util "$B" purge_mkeys -f -v > "$BASE/b.mit.purge"
grep -q '^1 key(s) purged.$' "$BASE/b.mit.purge"
rs_util "$B" list_mkeys > "$BASE/b3.rs.list"
test "$(grep -c '^KVNO' "$BASE/b3.rs.list")" = 1
printf '%s\n' "$MASTER" > "$BASE/purged.pw"
if rs_util "$B" --master-password-file "$BASE/purged.pw" stash 2>/dev/null; then
  echo "purged master password still opened the database" >&2
  exit 1
fi
mit_util "$B" stash > "$BASE/b.mit.stash"
rs_util "$B" stash > "$BASE/b.rs.stash"
same "$BASE/b.mit.stash" "$BASE/b.rs.stash"
rs_util "$B" getprinc dave | grep -q 'dave@KLMDB.LIVE'
keys_of "$B" dave "$BASE/dave.kt" > /dev/null

echo KLMDB_LIVE_OK
"#,
    );
}
