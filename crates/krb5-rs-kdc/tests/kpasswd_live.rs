//! Live interop: MIT 1.22.2 `kpasswd` and `krb5_set_password` against the
//! kpasswd service of `krb5-rs-kadmind` (UDP and TCP). Runs in the MIT
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
fn mit_kpasswd_changes_passwords_through_krb5_rs_kadmind() {
    let c = container();
    let mkdir = container_run(&["exec", &c, "mkdir", "-p", "/tmp/kpasswd-live/bin"], "");
    assert!(mkdir.status.success(), "{mkdir:?}");
    for name in ["krb5-rs-kadmind", "krb5-rs-kdc"] {
        let path = binary_directory().join(name);
        assert!(
            path.is_file(),
            "missing Linux musl binary {}; build it in rust:1.92 and set KLMDB_LIVE_BIN_DIR",
            path.display()
        );
        let path = path.to_string_lossy().into_owned();
        let dest = format!("{c}:/tmp/kpasswd-live/bin/{name}");
        let out = container_run(&["cp", &path, &dest], "");
        assert!(out.status.success(), "cp {name}: {out:?}");
    }
    let out = container_run(&["exec", "-i", &c, "bash", "-s"], SCRIPT);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success() && stdout.contains("KPASSWD_LIVE_OK"),
        "kpasswd interop script failed\nstdout:\n{stdout}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

const SCRIPT: &str = r#"
set -euo pipefail
B=/tmp/kpasswd-live
BIN=$B/bin
R=KPASSWD.LIVE
stop() { pkill -f "$BIN/" 2>/dev/null || true; }
stop
sleep 0.5
trap stop EXIT
rm -rf "$B/db" "$B"/*.conf "$B"/*.log "$B"/*.acl "$B/stash" "$B"/cc* "$B/setpw"*
mkdir -p "$B/db"
cat > "$B/kdc.conf" <<EOF
[kdcdefaults]
 kdc_ports = 18890
 kdc_tcp_ports = 18890
[realms]
 $R = {
  database_name = $B/db/principal
  key_stash_file = $B/stash
  acl_file = $B/kadm5.acl
  supported_enctypes = aes256-cts-hmac-sha1-96:normal
  kpasswd_listen = 127.0.0.1:18464
 }
[dbmodules]
 $R = {
  db_library = klmdb
  database_name = $B/db/principal
 }
EOF
krb5_conf() { # file udp_preference_limit
  cat > "$1" <<EOF
[libdefaults]
 default_realm = $R
 dns_lookup_kdc = false
 rdns = false
 udp_preference_limit = $2
[realms]
 $R = {
  kdc = 127.0.0.1:18890
  kpasswd_server = 127.0.0.1:18464
 }
EOF
}
krb5_conf "$B/udp.conf" 65535
krb5_conf "$B/tcp.conf" 1
export KRB5_CONFIG=$B/udp.conf KRB5_KDC_PROFILE=$B/kdc.conf
wait_port() { for _ in $(seq 1 100); do (exec 3<>/dev/tcp/127.0.0.1/$1) 2>/dev/null && return 0; sleep 0.1; done; return 1; }
fail() { echo "FAIL: $*"; for l in "$B"/*.log; do echo "== $l"; cat "$l"; done; exit 1; }
kl() { kadmin.local -r $R -q "$1" >/dev/null; }

kdb5_util create -r $R -s -P master-password >/dev/null
kl "addpol -minlength 12 long"
kl "addprinc -pw alice-old-pw alice"
kl "addprinc -pw admin-pw admin"
kl "addprinc -pw bob-old-pw bob"
kl "addprinc -pw carol-old-pw carol"
kl "addprinc -pw dave-old-password -policy long dave"
echo "admin@$R c bob@$R" > "$B/kadm5.acl"
start() {
  $BIN/krb5-rs-kdc --realm $R >> "$B/kdc.log" 2>&1 &
  $BIN/krb5-rs-kadmind -r $R -nofork >> "$B/kadmind.log" 2>&1 &
  wait_port 18890 || fail "kdc did not start"
  wait_port 18464 || fail "kadmind did not start"
}
start

# Self change over UDP, then over TCP.
printf 'alice-old-pw\nalice-new-pw\nalice-new-pw\n' | kpasswd alice > "$B/k1.out" 2>&1 \
  || { cat "$B/k1.out"; fail "kpasswd over UDP"; }
grep -q "Password changed." "$B/k1.out" || fail "no success message: $(cat $B/k1.out)"
echo alice-new-pw | kinit -c "$B/cc1" alice >/dev/null || fail "new password rejected"
printf 'alice-new-pw\nalice-tcp-pw\nalice-tcp-pw\n' \
  | KRB5_CONFIG=$B/tcp.conf kpasswd alice > "$B/k2.out" 2>&1 \
  || { cat "$B/k2.out"; fail "kpasswd over TCP"; }
echo alice-tcp-pw | kinit -c "$B/cc2" alice >/dev/null || fail "TCP password rejected"
grep -q "chpw request from 127.0.0.1 for alice@$R: success" "$B/kadmind.log" \
  || fail "no MIT-style log line"

# Password quality is a soft error with chpass_util's message.
if printf 'dave-old-password\nshort\nshort\n' | kpasswd dave > "$B/k3.out" 2>&1; then
  fail "short password accepted"
fi
grep -q "Password change rejected: New password is too short." "$B/k3.out" \
  || fail "soft error: $(cat $B/k3.out)"
grep -q "at least 12 characters long" "$B/k3.out" || fail "min length: $(cat $B/k3.out)"

# RFC 3244 set-password: allowed by ACL for bob, denied for carol.
cat > "$B/setpw.c" <<'EOF'
#include <krb5.h>
#include <stdio.h>
int main(int argc, char **argv) {
    krb5_context ctx; krb5_ccache cc; krb5_principal target;
    int code; krb5_data cstr, str;
    if (krb5_init_context(&ctx) || krb5_cc_resolve(ctx, argv[1], &cc) ||
        krb5_parse_name(ctx, argv[2], &target)) return 2;
    krb5_error_code ret = krb5_set_password_using_ccache(ctx, cc, argv[3], target,
                                                         &code, &cstr, &str);
    if (ret) { printf("error %s\n", krb5_get_error_message(ctx, ret)); return 3; }
    printf("result %d %.*s: %.*s\n", code, (int)cstr.length, cstr.data,
           (int)str.length, str.data);
    return 0;
}
EOF
gcc -o "$B/setpw" "$B/setpw.c" -lkrb5 -lcom_err
echo admin-pw | kinit -c "$B/cc3" -S kadmin/changepw admin >/dev/null || fail "admin kinit"
"$B/setpw" "$B/cc3" bob@$R bob-set-pw > "$B/s1.out" || fail "setpw bob: $(cat $B/s1.out)"
grep -q "^result 0 " "$B/s1.out" || fail "setpw bob: $(cat $B/s1.out)"
echo bob-set-pw | kinit -c "$B/cc4" bob >/dev/null || fail "set password rejected"
echo admin-pw | kinit -c "$B/cc5" -S kadmin/changepw admin >/dev/null || fail "admin kinit"
"$B/setpw" "$B/cc5" carol@$R carol-set-pw > "$B/s2.out" || fail "setpw carol: $(cat $B/s2.out)"
grep -q "^result 5 " "$B/s2.out" || fail "setpw carol: $(cat $B/s2.out)"
grep -q "Unauthorized request" "$B/s2.out" || fail "denial text: $(cat $B/s2.out)"
grep -q "setpw request from 127.0.0.1 by admin@$R for carol@$R: Unauthorized request" \
  "$B/kadmind.log" || fail "no setpw log line"

# A self change needs an initial ticket.
echo alice-tcp-pw | kinit -c "$B/cc6" alice >/dev/null
if kvno -c "$B/cc6" kadmin/changepw >/dev/null 2>&1; then
  fail "TGS ticket issued for kadmin/changepw despite DISALLOW_TGT_BASED"
fi
# MIT's liblmdb cannot open the environment while ours hold it.
stop
sleep 0.5
kl "modprinc +allow_tgs_req kadmin/changepw"
start
kvno -c "$B/cc6" kadmin/changepw >/dev/null || fail "service ticket"
"$B/setpw" "$B/cc6" alice@$R alice-tgs-pw > "$B/s3.out" || true
grep -q "^result 7 " "$B/s3.out" || fail "initial flag: $(cat $B/s3.out)"
echo KPASSWD_LIVE_OK
"#;
