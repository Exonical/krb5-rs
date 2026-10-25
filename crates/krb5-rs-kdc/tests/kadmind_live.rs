//! Live interop: MIT 1.22.2 `kpropd` in iprop mode follows
//! `krb5-rs-kadmind -proponly` (full resync, then incremental updates).
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
fn mit_kpropd_follows_krb5_rs_kadmind() {
    let c = container();
    let mkdir = container_run(&["exec", &c, "mkdir", "-p", "/tmp/kadmind-live/bin"], "");
    assert!(mkdir.status.success(), "{mkdir:?}");
    for name in [
        "krb5-rs-kadmind",
        "krb5-rs-kdc",
        "krb5-rs-kdb",
        "krb5-rs-kprop",
    ] {
        let path = binary_directory().join(name);
        assert!(
            path.is_file(),
            "missing Linux musl binary {}; build it in rust:1.92 and set KLMDB_LIVE_BIN_DIR",
            path.display()
        );
        let path = path.to_string_lossy().into_owned();
        let dest = format!("{c}:/tmp/kadmind-live/bin/{name}");
        let out = container_run(&["cp", &path, &dest], "");
        assert!(out.status.success(), "cp {name}: {out:?}");
    }
    let out = container_run(&["exec", "-i", &c, "bash", "-s"], SCRIPT);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success() && stdout.contains("KADMIND_LIVE_OK"),
        "kadmind interop script failed\nstdout:\n{stdout}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

const SCRIPT: &str = r#"
set -euo pipefail
B=/tmp/kadmind-live
BIN=$B/bin
R=KADMIND.LIVE
stop() { pkill -f "$BIN/|kpropd -D -d -P 17560" 2>/dev/null || true; }
stop
sleep 0.5
trap stop EXIT
rm -rf "$B/p" "$B/r" "$B"/*.conf "$B"/*.log "$B"/*.acl "$B/kt" "$B/stash" "$B"/*.pid
mkdir -p "$B/p" "$B/r"
H=$(hostname | tr 'A-Z' 'a-z')
realm_conf() { # file dbdir
  cat > "$1" <<EOF
[kdcdefaults]
 kdc_ports = 18889
 kdc_tcp_ports = 18889
[realms]
 $R = {
  database_name = $2/principal
  key_stash_file = $B/stash
  acl_file = $B/kadm5.acl
  supported_enctypes = aes256-cts-hmac-sha1-96:normal
  iprop_enable = true
  iprop_port = 18755
  iprop_ulogsize = 100
  iprop_replica_poll = 1s
 }
[dbmodules]
 $R = {
  db_library = klmdb
  database_name = $2/principal
 }
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
  kdc = 127.0.0.1:18889
  admin_server = $H
 }
EOF
export KRB5_CONFIG=$B/krb5.conf
p() { KRB5_KDC_PROFILE=$B/p.conf "$@"; }
r() { KRB5_KDC_PROFILE=$B/r.conf "$@"; }
wait_port() { for _ in $(seq 1 100); do (exec 3<>/dev/tcp/127.0.0.1/$1) 2>/dev/null && return 0; sleep 0.1; done; return 1; }
fail() { echo "FAIL: $*"; for l in "$B"/*.log; do echo "== $l"; cat "$l"; done; exit 1; }

p kdb5_util create -r $R -s -P master-password >/dev/null
for n in kiprop/$H host/$H alice; do p kadmin.local -r $R -q "addprinc -randkey $n" >/dev/null; done
p kadmin.local -r $R -q "ktadd -k $B/kt kiprop/$H host/$H" >/dev/null
echo "kiprop/$H@$R p" > "$B/kadm5.acl"
echo "host/$H@$R" > "$B/kpropd.acl"
p $BIN/krb5-rs-kdc --realm $R > "$B/kdc.log" 2>&1 &
echo $! > $B/kdc.pid
wait_port 18889 || fail "kdc did not start"

p env KRB5_KTNAME=FILE:$B/kt $BIN/krb5-rs-kadmind -proponly -nofork -r $R -P $B/kadmind.pid \
  -p $BIN/krb5-rs-kdb -K $BIN/krb5-rs-kprop -k 17560 -F $B/p/replica_datatrans > "$B/kadmind.log" 2>&1 &
wait_port 18755 || fail "kadmind did not start"

r kpropd -D -d -P 17560 -r $R -s $B/kt -a "$B/kpropd.acl" -f "$B/r/from_master" \
  -p "$(command -v kdb5_util)" > "$B/kpropd.log" 2>&1 &
echo $! > $B/kpropd.pid

synced() { r kadmin.local -r $R -q "getprinc $1" 2>/dev/null | grep -q "Principal: $1@$R"; }
for _ in $(seq 1 300); do synced alice && break; sleep 0.1; done
synced alice || fail "no full resync"
grep -q "full resync sent to $H" "$B/kadmind.log" || fail "kadmind did not run kprop"
echo "full resync ok"

p $BIN/krb5-rs-kdb -r $R addprinc -randkey bob >/dev/null
p $BIN/krb5-rs-kdb -r $R delprinc alice >/dev/null
for _ in $(seq 1 300); do synced bob && ! synced alice && break; sleep 0.1; done
synced bob || fail "bob not propagated"
! synced alice || fail "alice deletion not propagated"
test "$(grep -c 'Full propagation transfer finished' "$B/kpropd.log")" -eq 1 || fail "unexpected extra full resync"
P=$(p kproplog -h | awk '/Last serial #/ {print $NF}')
R2=$(r kproplog -h | awk '/Last serial #/ {print $NF}')
[ "$P" = "$R2" ] || fail "serials differ: primary $P replica $R2"
echo "incremental ok (serial $P)"

echo KADMIND_LIVE_OK
"#;
