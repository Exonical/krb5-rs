//! MIT 1.22.2 iprop update-log interoperability: MIT and krb5-rs append to
//! one ulog, each `kproplog` prints the other's entries identically, and the
//! `dump -i1` output matches. Uses the same container and `KLMDB_LIVE_BIN_DIR`
//! musl binaries as `klmdb_live`.

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
        "iprop interop script failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(
        String::from_utf8_lossy(&result.stdout).contains("IPROP_LIVE_OK"),
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
fn mit_and_krb5_rs_share_the_iprop_ulog() {
    let bins = binary_directory();
    for bin in ["krb5-rs-kdb", "krb5-rs-kproplog"] {
        copy_binary(&bins.join(bin), &format!("/usr/local/bin/{bin}"));
    }
    let chmod = output(&[
        "exec",
        &mit_container(),
        "chmod",
        "0755",
        "/usr/local/bin/krb5-rs-kdb",
        "/usr/local/bin/krb5-rs-kproplog",
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
export TZ=UTC
BASE="/tmp/krb5rs-iprop-live-$$"
REALM=IPROP.LIVE
MASTER='master-password-for-iprop-test'
RS_KDB=/usr/local/bin/krb5-rs-kdb
RS_KPROPLOG=/usr/local/bin/krb5-rs-kproplog
MIT_KDB=$(command -v kdb5_util)
KADMIN=$(command -v kadmin.local)
MIT_KPROPLOG=$(command -v kproplog)
trap 'rm -rf "$BASE"' EXIT
n=0

write_profile() {
  local dir=$1
  mkdir -p "$dir"
  printf '%s\n' "$MASTER" > "$dir/master"
  cat > "$dir/kdc.conf" <<EOF
[realms]
    $REALM = {
        database_module = lmdb
        database_name = $dir/principal
        key_stash_file = $dir/.k5.$REALM
        master_key_type = aes256-cts-hmac-sha1-96
        supported_enctypes = aes256-cts-hmac-sha1-96:normal aes128-cts-hmac-sha1-96:normal
        iprop_enable = true
        iprop_ulogsize = 8
        iprop_port = 18754
    }
[dbmodules]
    lmdb = {
        db_library = klmdb
    }
EOF
  cat > "$dir/krb5.conf" <<EOF
[libdefaults]
    default_realm = $REALM
EOF
}

in_realm() {
  local dir=$1
  shift
  env KRB5_KDC_PROFILE="$dir/kdc.conf" KRB5_CONFIG="$dir/krb5.conf" "$@"
}

rs_kdb() {
  local dir=$1
  shift
  "$RS_KDB" --config "$dir/kdc.conf" --krb5-config "$dir/krb5.conf" \
    --realm "$REALM" --master-password-file "$dir/master" "$@"
}

same_kproplog() {
  local dir=$1 tag=$2
  shift 2
  in_realm "$dir" "$MIT_KPROPLOG" "$@" > "$BASE/$tag.mit"
  in_realm "$dir" "$RS_KPROPLOG" "$@" > "$BASE/$tag.rs"
  diff -u "$BASE/$tag.mit" "$BASE/$tag.rs"
}

last_serial() {
  in_realm "$1" "$MIT_KPROPLOG" -h | sed -n 's/^\s*Last serial # : //p'
}

P="$BASE/primary"
write_profile "$P"
printf '%s\n%s\n' "$MASTER" "$MASTER" | in_realm "$P" "$MIT_KDB" create -s -r "$REALM" >/dev/null
printf 'alice-pw\nalice-pw\n' | in_realm "$P" "$KADMIN" -r "$REALM" -q "addprinc +requires_preauth alice" >/dev/null
in_realm "$P" "$KADMIN" -r "$REALM" -q "addprinc -randkey -maxlife 1h bob" >/dev/null
in_realm "$P" "$KADMIN" -r "$REALM" -q "setstr bob color blue" >/dev/null
in_realm "$P" "$KADMIN" -r "$REALM" -q "delprinc -force bob" >/dev/null
for v in "" -v "-v -v" -h "-e 2"; do
  n=$((n + 1))
  # shellcheck disable=SC2086
  same_kproplog "$P" "step$n" $v
done

grep -q 'Update principal : alice@IPROP.LIVE' "$BASE/step3.rs"
grep -q 'Update operation : Delete' "$BASE/step3.rs"
printf 'carol-pw\n' | rs_kdb "$P" addprinc carol >/dev/null
rs_kdb "$P" modprinc -maxlife 2h carol >/dev/null
rs_kdb "$P" cpw -randkey alice >/dev/null
rs_kdb "$P" delprinc carol >/dev/null
for v in "" -v "-v -v"; do
  n=$((n + 1))
  # shellcheck disable=SC2086
  same_kproplog "$P" "step$n" $v
done
grep -q 'Update principal : carol@IPROP.LIVE' "$BASE/step$n.mit"

for i in 1 2 3 4 5 6; do
  rs_kdb "$P" addprinc -randkey "wrap$i" >/dev/null
done
same_kproplog "$P" wrap -v -v

grep -q 'Update principal : wrap6@IPROP.LIVE' "$BASE/wrap.rs"
grep -q 'Number of entries : 8' "$BASE/wrap.rs"
in_realm "$P" "$MIT_KDB" dump -i1 "$BASE/mit.ipropx"
rs_kdb "$P" dump -i1 "$BASE/rs.ipropx"
cmp "$BASE/mit.ipropx" "$BASE/rs.ipropx"
grep -q '^ipropx 1 ' "$BASE/rs.ipropx"
in_realm "$P" "$MIT_KDB" dump -i "$BASE/mit.iprop"
rs_kdb "$P" dump -i "$BASE/rs.iprop"
cmp "$BASE/mit.iprop" "$BASE/rs.iprop"
SNO=$(last_serial "$P")

M="$BASE/mit-replica"
write_profile "$M"
printf '%s\n%s\n' "$MASTER" "$MASTER" | in_realm "$M" "$MIT_KDB" create -s -r "$REALM" >/dev/null
in_realm "$M" "$MIT_KDB" load -i "$BASE/rs.ipropx"
test "$(last_serial "$M")" = "$SNO"

R="$BASE/rs-replica"
write_profile "$R"
printf '%s\n%s\n' "$MASTER" "$MASTER" | in_realm "$R" "$MIT_KDB" create -s -r "$REALM" >/dev/null
rs_kdb "$R" load -i "$BASE/mit.ipropx"
test "$(last_serial "$R")" = "$SNO"
same_kproplog "$R" replica
rs_kdb "$R" dump -i1 "$BASE/replica.ipropx"
cmp "$BASE/mit.ipropx" "$BASE/replica.ipropx"

echo IPROP_LIVE_OK
"#,
    );
}
