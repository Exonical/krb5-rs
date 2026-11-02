//! MIT 1.22.2 `kdb5_util` error text: the same failing commands run with
//! MIT `kdb5_util` and with `krb5-rs-kdb` (installed as `kdb5_util`, so
//! `progname` matches) on the same klmdb paths, and their stdout, stderr and
//! exit codes are compared. Setup is the same as `klmdb_live.rs`.

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
        "container cp failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
}

#[test]
#[ignore = "requires the MIT klmdb container and static Linux musl binaries"]
fn krb5_rs_kdb_errors_match_mit_kdb5_util() {
    copy_binary(
        &binary_directory().join("krb5-rs-kdb"),
        "/tmp/krb5-rs-kdb-com-err",
    );
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
        .write_all(SCRIPT.as_bytes())
        .expect("write script");
    let result = child.wait_with_output().expect("wait for MIT script");
    let stdout = String::from_utf8_lossy(&result.stdout);
    assert!(
        result.status.success() && stdout.contains("COM_ERR_LIVE_OK"),
        "MIT and krb5-rs output differ\nstdout:\n{stdout}\nstderr:\n{}",
        String::from_utf8_lossy(&result.stderr)
    );
}

const SCRIPT: &str = r#"
set -uo pipefail
export TZ=UTC
BASE="/tmp/krb5rs-com-err-live-$$"
REALM=COMERR.LIVE
mkdir -p "$BASE/rs"
install -m 0755 /tmp/krb5-rs-kdb-com-err "$BASE/rs/kdb5_util"
trap 'rm -rf "$BASE" /tmp/krb5-rs-kdb-com-err' EXIT

# Run each step with one kdb5_util; output goes to $BASE/out-<label>.
run_all() {
  local label=$1 tool=$2 db="$BASE/db" out="$BASE/out-$1"
  rm -rf "$db"
  mkdir -p "$db" "$out"
  printf '[libdefaults]\n    default_realm = %s\n' "$REALM" > "$db/krb5.conf"
  : > "$db/empty.conf"
  printf 'wrong-master\n' > "$db/wrong"
  cat > "$db/kdc.conf" <<EOF
[realms]
    $REALM = {
        database_module = lmdb
        database_name = $db/principal
        key_stash_file = $db/stash
        master_key_type = aes256-cts-hmac-sha1-96
        supported_enctypes = aes256-cts-hmac-sha1-96:normal
    }
[dbmodules]
    lmdb = {
        db_library = klmdb
        database_name = $db/principal
    }
EOF
  export KRB5_CONFIG="$db/krb5.conf" KRB5_KDC_PROFILE="$db/kdc.conf"
  step() {
    local name=$1 input=$2
    shift 2
    printf '%b' "$input" | "$@" > "$out/$name.out" 2> "$out/$name.err"
    echo $? > "$out/$name.rc"
  }
  # krb5-rs-kdb takes the realm from a kdc.conf with one realm, so give it two.
  { cat "$db/kdc.conf"; printf '[realms]\n    OTHER.LIVE = {\n    }\n'; } > "$db/two.conf"
  KRB5_CONFIG="$db/empty.conf" KRB5_KDC_PROFILE="$db/two.conf" \
    step no_default_realm '' "$tool" list_mkeys
  step no_db_dump '' "$tool" dump "$db/d0"
  step no_db_list_mkeys '' "$tool" list_mkeys
  step no_db_stash '' "$tool" stash
  step create_mismatch 'a\nb\n' "$tool" create -s
  step create_eof '' "$tool" create -s
  step create 'master\nmaster\n' "$tool" create -s
  step create_exists 'master\nmaster\n' "$tool" create -s
  step load_missing '' "$tool" load "$db/missing"
  printf 'junk\n' > "$db/junk"
  step load_bad_header '' "$tool" load "$db/junk"
  step use_mkey_0 '' "$tool" use_mkey 0
  step use_mkey_9 '' "$tool" use_mkey 9
  step add_mkey_enctype '' "$tool" add_mkey -e bogus
  step add_mkey_mismatch 'a\nb\n' "$tool" add_mkey
  step stash_existing '' "$tool" stash
  mv "$db/stash" "$db/stash.saved"
  step no_stash_dump '' "$tool" dump "$db/d1"
  if [ -s "$db/d1" ]; then echo dumped; else echo none; fi > "$out/no_stash_dump.file"
  step no_stash_list_mkeys '' "$tool" list_mkeys
  step no_stash_use_mkey '' "$tool" use_mkey 1
  step no_stash_purge_mkeys '' "$tool" purge_mkeys -f
  step no_stash_update '' "$tool" update_princ_encryption -f
  step no_stash_stash_eof '' "$tool" stash
  step no_stash_stash_wrong 'wrong-master\n' "$tool" stash
  step no_stash_stash 'master\n' "$tool" stash
  if [ "$label" = mit ]; then
    step wrong_master '' "$tool" -P wrong-master list_mkeys
  else
    step wrong_master '' "$tool" --master-password-file "$db/wrong" list_mkeys
  fi
  # Usage text differs (krb5-rs-kdb has more commands); compare the code.
  step usage '' "$tool" frob
  rm -f "$out/usage.out" "$out/usage.err"
}

run_all mit "$(command -v kdb5_util)"
run_all rs "$BASE/rs/kdb5_util"
if diff -r "$BASE/out-mit" "$BASE/out-rs"; then
  echo COM_ERR_LIVE_OK
else
  for f in "$BASE"/out-mit/*; do
    n=$(basename "$f")
    cmp -s "$f" "$BASE/out-rs/$n" || { echo "--- $n"; echo "MIT:"; cat "$f"; echo "krb5-rs:"; cat "$BASE/out-rs/$n"; }
  done
  exit 1
fi
"#;
