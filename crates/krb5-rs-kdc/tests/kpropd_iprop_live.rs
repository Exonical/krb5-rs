//! Live interop: `krb5-rs-kpropd` in iprop mode follows MIT 1.22.2
//! `kadmind -proponly` (full resync, then incremental updates).
//! Runs in the MIT container of the Compose stack (`KPROP_LIVE_CONTAINER`,
//! default `krb5-rs-kdc-1`; `CONTAINER_CLI`, default `podman`) with the
//! Linux musl binaries from `KLMDB_LIVE_BIN_DIR`, like `iprop_live`.
#![cfg(feature = "klmdb")]

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

fn container_cli() -> String {
    std::env::var("CONTAINER_CLI").unwrap_or_else(|_| "podman".into())
}

fn container() -> String {
    std::env::var("KPROP_LIVE_CONTAINER").unwrap_or_else(|_| "krb5-rs-kdc-1".into())
}

fn container_run(args: &[&str], stdin: &str) -> std::process::Output {
    let mut child = Command::new(container_cli())
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("run container CLI");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(stdin.as_bytes())
        .expect("write stdin");
    child.wait_with_output().expect("wait")
}

fn binary_directory() -> PathBuf {
    std::env::var_os("KLMDB_LIVE_BIN_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/klmdb-live")
        })
}

#[test]
#[ignore = "requires the MIT container of the Compose stack"]
fn krb5_rs_kpropd_follows_mit_kadmind() {
    let c = container();
    let mkdir = container_run(
        &["exec", &c, "mkdir", "-p", "/tmp/kpropd-iprop-live/bin"],
        "",
    );
    assert!(mkdir.status.success(), "{mkdir:?}");
    for name in ["krb5-rs-kpropd", "krb5-rs-kdb", "krb5-rs-kproplog"] {
        let path = binary_directory().join(name);
        assert!(
            path.is_file(),
            "missing Linux musl binary {}; build it in rust:1.92 and set KLMDB_LIVE_BIN_DIR",
            path.display()
        );
        let path = path.to_string_lossy().into_owned();
        let dest = format!("{c}:/tmp/kpropd-iprop-live/bin/{name}");
        let out = container_run(&["cp", &path, &dest], "");
        assert!(out.status.success(), "cp {name}: {out:?}");
    }
    let out = container_run(&["exec", "-i", &c, "bash", "-s"], SCRIPT);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success() && stdout.contains("KPROPD_IPROP_LIVE_OK"),
        "kpropd iprop interop script failed\nstdout:\n{stdout}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

const SCRIPT: &str = r#"
set -euo pipefail
B=/tmp/kpropd-iprop-live
BIN=$B/bin
R=KPROPD.LIVE
stop() { pkill -f "$B/(p|r).conf|$BIN/krb5-rs-kpropd" 2>/dev/null || true; for f in kdc kadmind kpropd; do [ -f $B/$f.pid ] && kill "$(cat $B/$f.pid)" 2>/dev/null || true; done; }
stop
sleep 0.5
trap stop EXIT
rm -rf "$B/p" "$B/r" "$B"/*.conf "$B"/*.log "$B"/*.acl "$B/kt" "$B/stash" "$B"/*.pid "$B"/*.dump
mkdir -p "$B/p" "$B/r"
H=$(hostname | tr 'A-Z' 'a-z')
realm_conf() { # file dbdir
  cat > "$1" <<EOF
[kdcdefaults]
 kdc_ports = 18890
 kdc_tcp_ports = 18890
[realms]
 $R = {
  database_name = $2/principal
  key_stash_file = $B/stash
  acl_file = $B/kadm5.acl
  kadmind_port = 18751
  kpasswd_port = 18465
  supported_enctypes = aes256-cts-hmac-sha1-96:normal
  iprop_enable = true
  iprop_port = 18756
  iprop_ulogsize = 100
  iprop_replica_poll = 1s
 }
[dbmodules]
 $R = {
  db_library = klmdb
  database_name = $2/principal
 }
[logging]
 admin_server = FILE:$B/kadmind-mit.log
EOF
}
realm_conf "$B/p.conf" "$B/p"
realm_conf "$B/r.conf" "$B/r"
cat > "$B/krb5.conf" <<EOF
[libdefaults]
 default_realm = $R
 dns_lookup_kdc = false
 dns_canonicalize_hostname = false
 rdns = false
 udp_preference_limit = 1
[realms]
 $R = {
  kdc = 127.0.0.1:18890
  admin_server = $H
 }
EOF
export KRB5_CONFIG=$B/krb5.conf
p() { KRB5_KDC_PROFILE=$B/p.conf "$@"; }
r() { KRB5_KDC_PROFILE=$B/r.conf "$@"; }
wait_port() { for _ in $(seq 1 100); do (exec 3<>/dev/tcp/127.0.0.1/$1) 2>/dev/null && return 0; sleep 0.1; done; return 1; }
fail() { echo "FAIL: $*"; for l in "$B"/*.log; do echo "== $l"; cat "$l"; done; exit 1; }
rdump() { r $BIN/krb5-rs-kdb -r $R dump "$B/r.dump" >/dev/null 2>&1 && cat "$B/r.dump"; }
synced() { rdump | grep -qP "\t$1@$R\t"; }

p kdb5_util create -r $R -s -P master-password >/dev/null
for n in kiprop/$H host/$H alice; do p kadmin.local -r $R -q "addprinc -randkey $n" >/dev/null; done
p kadmin.local -r $R -q "ktadd -k $B/kt kiprop/$H host/$H" >/dev/null
echo "kiprop/$H@$R p" > "$B/kadm5.acl"
echo "host/$H@$R" > "$B/kpropd.acl"
p krb5kdc -n -r $R -P $B/kdc.pid > "$B/kdc.log" 2>&1 &
wait_port 18890 || fail "kdc did not start"
p env KRB5_KTNAME=FILE:$B/kt kadmind -nofork -proponly -r $R -P $B/kadmind.pid \
  -p "$(command -v kdb5_util)" -K "$(command -v kprop)" -k 17561 -F $B/p/replica_datatrans \
  > "$B/kadmind.log" 2>&1 &
wait_port 18756 || fail "kadmind did not start"

r env KRB5_KTNAME=FILE:$B/kt $BIN/krb5-rs-kpropd -D -d -P 17561 -r $R -s $B/kt -a "$B/kpropd.acl" \
  -f "$B/r/from_master" -p $BIN/krb5-rs-kdb > "$B/kpropd.log" 2>&1 &
echo $! > $B/kpropd.pid

for _ in $(seq 1 300); do synced alice && break; sleep 0.1; done
synced alice || fail "no full resync"
echo "full resync ok"

p kadmin.local -r $R -q "addprinc -randkey bob" >/dev/null
p kadmin.local -r $R -q "modprinc -maxlife 2h -requires_preauth bob" >/dev/null
p kadmin.local -r $R -q "cpw -randkey -keepold bob" >/dev/null
p kadmin.local -r $R -q "setstr bob color blue" >/dev/null
p kadmin.local -r $R -q "delprinc -force alice" >/dev/null
P=$(p kproplog -h | awk '/Last serial #/ {print $NF}')
R2=
for _ in $(seq 1 300); do
  R2=$(r $BIN/krb5-rs-kproplog -h | awk '/Last serial #/ {print $NF}')
  [ "$P" = "$R2" ] && break; sleep 0.1
done
[ "$P" = "$R2" ] || fail "serials differ: primary $P replica $R2"
synced bob || { p kproplog -h; r $BIN/krb5-rs-kproplog -h; rdump; fail "bob not propagated (P=$P R2=$R2)"; }
! synced alice || fail "alice deletion not propagated"
test "$(grep -c 'Full propagation transfer finished' "$B/kpropd.log")" -eq 1 || fail "unexpected extra full resync"
grep -q 'Got incremental updates' "$B/kpropd.log" || fail "no incremental updates"
p kdb5_util dump "$B/p.dump"
rdump >/dev/null
# ulog_replay prepends tl-data types the replica lacks, so compare tl-data
# as a set.
norm() {
  grep -v -e "kiprop/" -e "host/" "$1" | awk -F'\t' '$1 != "princ" { print; next }
    { n = $4; head = ""; for (i = 1; i <= 15; i++) head = head $i "\t"
      for (i = 0; i < n; i++) print $7, "tl", $(16 + 3 * i), $(17 + 3 * i), $(18 + 3 * i)
      rest = ""; for (i = 16 + 3 * n; i <= NF; i++) rest = rest "\t" $i
      print head rest }' | sort
}
diff <(norm "$B/p.dump") <(norm "$B/r.dump") || fail "replica dump differs from primary"
echo "incremental ok (serial $P)"

echo KPROPD_IPROP_LIVE_OK
"#;
