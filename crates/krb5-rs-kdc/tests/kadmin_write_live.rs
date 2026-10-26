//! Live interop: the kadm5 calls that change the database, sent by MIT
//! 1.22.2 `kadmin` to MIT `kadmind` and to `krb5-rs-kadmind`. Runs in the MIT
//! container of the Compose stack (`KPROP_LIVE_CONTAINER`, default
//! `krb5-rs-kdc-1`; `CONTAINER_CLI`, default `podman`) with the Linux musl
//! binaries from `KLMDB_LIVE_BIN_DIR`, like `kadmind_live`.
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
fn mit_kadmin_changes_match_mit_kadmind() {
    let c = container();
    let mkdir = container_run(&["exec", &c, "mkdir", "-p", "/tmp/kadmin-write-live/bin"], "");
    assert!(mkdir.status.success(), "{mkdir:?}");
    for name in ["krb5-rs-kadmind", "krb5-rs-kdc"] {
        let path = binary_directory().join(name);
        assert!(
            path.is_file(),
            "missing Linux musl binary {}; build it in rust:1.92 and set KLMDB_LIVE_BIN_DIR",
            path.display()
        );
        let path = path.to_string_lossy().into_owned();
        let dest = format!("{c}:/tmp/kadmin-write-live/bin/{name}");
        let out = container_run(&["cp", &path, &dest], "");
        assert!(out.status.success(), "cp {name}: {out:?}");
    }
    let out = container_run(&["exec", "-i", &c, "bash", "-s"], SCRIPT);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success() && stdout.contains("KADMIN_WRITE_LIVE_OK"),
        "kadmin write interop script failed\nstdout:\n{stdout}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

// The same kadmin commands run against MIT kadmind and against ours, on
// identically created databases; every reply, and the databases as read
// back by kadmin.local, must match.
const SCRIPT: &str = r#"
set -euo pipefail
B=/tmp/kadmin-write-live
BIN=$B/bin
R=KADMIN.WRITE
stop() { pkill -f "$BIN/" 2>/dev/null || true; pkill -f "krb5kdc -r $R" 2>/dev/null || true; pkill -f "kadmind -r $R" 2>/dev/null || true; }
stop
sleep 0.5
trap stop EXIT
rm -rf "$B/mit" "$B/rs"
fail() { echo "FAIL: $*"; for l in "$B"/*/*.log; do echo "== $l"; cat "$l"; done; exit 1; }
wait_port() { for _ in $(seq 1 100); do (exec 3<>/dev/tcp/127.0.0.1/$1) 2>/dev/null && return 0; sleep 0.1; done; return 1; }

# setup SIDE KDC_PORT KADMIN_PORT KPASSWD_PORT IPROP_PORT
setup() {
  local D=$B/$1
  mkdir -p "$D/db"
  cat > "$D/kdc.conf" <<EOF
[kdcdefaults]
 kdc_ports = $2
 kdc_tcp_ports = $2
[realms]
 $R = {
  database_name = $D/db/principal
  key_stash_file = $D/stash
  acl_file = $D/kadm5.acl
  supported_enctypes = aes256-cts-hmac-sha1-96:normal aes128-cts-hmac-sha1-96:normal
  kpasswd_listen = 127.0.0.1:$4
  kadmind_port = $3
  iprop_enable = true
  iprop_port = $5
 }
[dbmodules]
 $R = {
  db_library = klmdb
  database_name = $D/db/principal
 }
EOF
  cat > "$D/krb5.conf" <<EOF
[libdefaults]
 default_realm = $R
 dns_lookup_kdc = false
 rdns = false
[realms]
 $R = {
  kdc = 127.0.0.1:$2
  admin_server = 127.0.0.1:$3
 }
EOF
  cat > "$D/kadm5.acl" <<EOF
admin@$R *
keyadmin@$R *e
limited@$R a */lim@$R +requires_preauth -maxlife 2h
EOF
  (
    export KRB5_CONFIG=$D/krb5.conf KRB5_KDC_PROFILE=$D/kdc.conf
    kdb5_util create -r $R -s -P master-password >/dev/null
    kl() { kadmin.local -r $R -q "$1" >/dev/null; }
    kl "addpol plain"
    for p in admin keyadmin limited nobody bob; do kl "addprinc -pw $p-pw $p"; done
  )
}
setup mit 18894 18752 18467 18754
setup rs 18893 18751 18466 18753

(
  export KRB5_CONFIG=$B/mit/krb5.conf KRB5_KDC_PROFILE=$B/mit/kdc.conf
  krb5kdc -r $R -n > "$B/mit/kdc.log" 2>&1 &
  kadmind -r $R -nofork > "$B/mit/kadmind.log" 2>&1 &
)
(
  export KRB5_CONFIG=$B/rs/krb5.conf KRB5_KDC_PROFILE=$B/rs/kdc.conf
  $BIN/krb5-rs-kdc --realm $R > "$B/rs/kdc.log" 2>&1 &
  $BIN/krb5-rs-kadmind -r $R -nofork > "$B/rs/kadmind.log" 2>&1 &
)
for p in 18894 18752 18893 18751; do wait_port $p || fail "port $p did not open"; done

# USER<TAB>COMMAND; @ becomes the side's directory.
cat > "$B/cmds" <<'EOF'
admin	addpol -minlength 6 -history 2 newpol
admin	modpol -maxlife 10d -minclasses 2 newpol
admin	getpol newpol
admin	addpol newpol
admin	addprinc -pw carol-pw-1 -policy plain -maxlife 4h -expire "2041-02-03 04:05:06 UTC" +requires_preauth carol
admin	addprinc -pw carol-pw-1 carol
admin	addprinc -pw short -policy newpol weak
admin	modprinc -maxrenewlife 2d -allow_forwardable -pwexpire "2042-01-01 00:00:00 UTC" carol
admin	modprinc -policy nosuch carol
admin	cpw -pw carol-pw-2 carol
admin	cpw -randkey -keepold carol
admin	getprinc carol
admin	purgekeys -keepkvno 3 carol
admin	getprinc carol
admin	setstr carol team red
admin	setstr carol tmp x
admin	delstr carol tmp
admin	getstrs carol
admin	renprinc -force carol dave
admin	getprinc dave
admin	add_alias dalias dave
admin	add_alias dalias dave
admin	ktadd -k @/kt1 -norandkey dave
keyadmin	ktadd -k @/kt2 -norandkey dave
admin	ktadd -k @/kt3 dave
admin	getprinc dave
admin	addprinc -randkey +lockdown_keys locked
admin	modprinc -lockdown_keys locked
keyadmin	ktadd -k @/kt4 -norandkey locked
admin	cpw -randkey locked
limited	addprinc -pw limx-pw-1 -maxlife 10h limx/lim
admin	getprinc limx/lim
limited	addprinc -pw other-pw-1 other
nobody	delprinc -force dave
nobody	addpol x
nobody	cpw -pw nobody-pw-2 bob
bob	cpw -pw bob-pw-2 bob
admin	delpol -force newpol
admin	delprinc -force dave
admin	getprinc dave
admin	listprincs
EOF

norm() {
  sed -E -e "s#$B/(mit|rs)#@#g" \
    -e 's/^(Last modified): .* \((.*)\)$/\1: X (\2)/' \
    -e 's/^(Last password change): .*/\1: X/' \
    -e '/^Authenticating as/d'
}
run() {
  local D=$B/$1 i=0
  export KRB5_CONFIG=$D/krb5.conf
  while IFS=$'\t' read -r u cmd; do
    cmd=${cmd//@/$D}
    kadmin -r $R -p "$u" -w "$u-pw" -q "$cmd" 2>&1 | norm > "$D/$i.out" || true
    i=$((i+1))
  done < "$B/cmds"
}
run mit
run rs
i=0
while IFS=$'\t' read -r u cmd; do
  diff -u "$B/mit/$i.out" "$B/rs/$i.out" || fail "$u: kadmin '$cmd' differs from MIT kadmind"
  i=$((i+1))
done < "$B/cmds"

for s in mit rs; do
  klist -ke "$B/$s/kt3" | norm | tail -n +4 > "$B/$s/kt3.list" || true
done
diff -u "$B/mit/kt3.list" "$B/rs/kt3.list" || fail "ktadd keytab differs"

stop
sleep 0.5
# Read both databases back with MIT's kadmin.local and kproplog.
for s in mit rs; do
  export KRB5_CONFIG=$B/$s/krb5.conf KRB5_KDC_PROFILE=$B/$s/kdc.conf
  for p in limx/lim locked bob weak; do
    kadmin.local -r $R -q "getprinc $p" 2>&1 | norm
  done > "$B/$s/final.out"
  kproplog -h -p "$B/$s/db/principal.ulog" 2>&1 | grep -E "Last serial|Entry count|Update log" > "$B/$s/ulog.out" || true
done
diff -u "$B/mit/final.out" "$B/rs/final.out" || fail "databases differ"
diff -u "$B/mit/ulog.out" "$B/rs/ulog.out" || fail "update logs differ"
echo KADMIN_WRITE_LIVE_OK
"#;
