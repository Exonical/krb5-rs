//! Live interop: MIT 1.22.2 `kadmin` and libkadm5clnt against the kadm5
//! admin RPC service of `krb5-rs-kadmind` (read-only calls). Runs in the MIT
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
fn mit_kadmin_reads_through_krb5_rs_kadmind() {
    let c = container();
    let mkdir = container_run(&["exec", &c, "mkdir", "-p", "/tmp/kadmin-live/bin"], "");
    assert!(mkdir.status.success(), "{mkdir:?}");
    for name in ["krb5-rs-kadmind", "krb5-rs-kdc"] {
        let path = binary_directory().join(name);
        assert!(
            path.is_file(),
            "missing Linux musl binary {}; build it in rust:1.92 and set KLMDB_LIVE_BIN_DIR",
            path.display()
        );
        let path = path.to_string_lossy().into_owned();
        let dest = format!("{c}:/tmp/kadmin-live/bin/{name}");
        let out = container_run(&["cp", &path, &dest], "");
        assert!(out.status.success(), "cp {name}: {out:?}");
    }
    let out = container_run(&["exec", "-i", &c, "bash", "-s"], SCRIPT);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success() && stdout.contains("KADMIN_LIVE_OK"),
        "kadmin interop script failed\nstdout:\n{stdout}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

const SCRIPT: &str = r#"
set -euo pipefail
B=/tmp/kadmin-live
BIN=$B/bin
R=KADMIN.LIVE
stop() { pkill -f "$BIN/" 2>/dev/null || true; }
stop
sleep 0.5
trap stop EXIT
rm -rf "$B/db" "$B"/*.conf "$B"/*.log "$B"/*.acl "$B/stash" "$B"/*.out "$B"/*.exp "$B/cpw"*
mkdir -p "$B/db"
cat > "$B/kdc.conf" <<EOF
[kdcdefaults]
 kdc_ports = 18891
 kdc_tcp_ports = 18891
[realms]
 $R = {
  database_name = $B/db/principal
  key_stash_file = $B/stash
  acl_file = $B/kadm5.acl
  supported_enctypes = aes256-cts-hmac-sha1-96:normal aes128-cts-hmac-sha1-96:normal
  kpasswd_listen = 127.0.0.1:18465
  kadmind_port = 18749
 }
[dbmodules]
 $R = {
  db_library = klmdb
  database_name = $B/db/principal
 }
EOF
cat > "$B/krb5.conf" <<EOF
[libdefaults]
 default_realm = $R
 dns_lookup_kdc = false
 rdns = false
[realms]
 $R = {
  kdc = 127.0.0.1:18891
  admin_server = 127.0.0.1:18749
 }
EOF
export KRB5_CONFIG=$B/krb5.conf KRB5_KDC_PROFILE=$B/kdc.conf
wait_port() { for _ in $(seq 1 100); do (exec 3<>/dev/tcp/127.0.0.1/$1) 2>/dev/null && return 0; sleep 0.1; done; return 1; }
fail() { echo "FAIL: $*"; for l in "$B"/*.log; do echo "== $l"; cat "$l"; done; exit 1; }
kl() { kadmin.local -r $R -q "$1" >/dev/null; }

kdb5_util create -r $R -s -P master-password >/dev/null
kl "addpol -minlength 8 -minclasses 2 -maxlife 30d -history 3 -maxfailure 5 -failurecountinterval 1h -lockoutduration 10m -allowedkeysalts aes256-cts-hmac-sha1-96:normal strict"
kl "addpol plain"
for p in admin reader nobody bob; do kl "addprinc -pw $p-pw $p"; done
kl "addprinc -pw alice-pw-1 -policy strict -maxlife 8h -expire 2040-01-01 +requires_preauth alice"
kl "setstr alice color blue"
kl "setstr alice size large"
cat > "$B/kadm5.acl" <<EOF
admin@$R *
reader@$R il
EOF

# The same commands through kadmin.local, before our daemons hold the
# database (MIT's liblmdb cannot open it while they do).
CMDS=("getprinc alice" "getprinc -terse alice" "getprinc kadmin/admin" "listprincs"
      "listprincs k*" "listprincs *@OTHER" "getpol strict" "getpol -terse strict"
      "getpol plain" "listpols" "listpols s*" "getstrs alice" "getstrs bob" "getprivs")
i=0
for cmd in "${CMDS[@]}"; do
  kadmin.local -r $R -q "$cmd" 2>&1 | { grep -v '^Authenticating as' || true; } > "$B/$i.exp"
  i=$((i+1))
done

$BIN/krb5-rs-kdc --realm $R >> "$B/kdc.log" 2>&1 &
$BIN/krb5-rs-kadmind -r $R -nofork >> "$B/kadmind.log" 2>&1 &
wait_port 18891 || fail "kdc did not start"
wait_port 18749 || fail "kadmind did not start"

ka() { kadmin -r $R -p "$1" -w "$1-pw" -q "$2" 2>&1 | { grep -v '^Authenticating as' || true; }; }
i=0
for cmd in "${CMDS[@]}"; do
  ka admin "$cmd" > "$B/$i.out"
  diff -u "$B/$i.exp" "$B/$i.out" || fail "kadmin '$cmd' differs from kadmin.local"
  i=$((i+1))
done
grep -q "Request: kadm5_init, admin@$R, success, client=admin@$R, service=kadmin/admin@$R, addr=127.0.0.1, vers=4, flavor=6" \
  "$B/kadmind.log" || fail "no init log line"
grep -q "Request: kadm5_get_principal, alice@$R, success, client=admin@$R" "$B/kadmind.log" \
  || fail "no get_principal log line"

ka admin "getprinc nosuch" > "$B/unk.out"
grep -q "Principal does not exist while retrieving \"nosuch@$R\"" "$B/unk.out" \
  || fail "unknown principal: $(cat $B/unk.out)"
ka admin "getpol nosuch" > "$B/unkpol.out"
grep -q "Policy does not exist while retrieving policy \"nosuch\"" "$B/unkpol.out" \
  || fail "unknown policy: $(cat $B/unkpol.out)"

# reader has i and l only; nobody has nothing.
ka reader "getprinc alice" | grep -q "^Principal: alice@$R" || fail "reader getprinc"
ka reader "listprincs" | grep -q "^alice@$R" || fail "reader listprincs"
ka nobody "getprinc alice" > "$B/d1.out"
grep -q "Operation requires \`\`get'' privilege while retrieving \"alice@$R\"" "$B/d1.out" \
  || fail "get denial: $(cat $B/d1.out)"
ka nobody "listprincs" > "$B/d2.out"
grep -q "Operation requires \`\`list'' privilege while retrieving list" "$B/d2.out" \
  || fail "list denial: $(cat $B/d2.out)"
ka nobody "getpol strict" > "$B/d3.out"
grep -q "Operation requires \`\`get'' privilege" "$B/d3.out" || fail "getpol denial: $(cat $B/d3.out)"
grep -q "Unauthorized request: kadm5_get_principal, alice@$R, client=nobody@$R, service=kadmin/admin@$R, addr=127.0.0.1" \
  "$B/kadmind.log" || fail "no unauthorized log line"

# The kadmin/changepw service may only read the caller itself (MIT's
# `self` kadm5_auth module), at API v2, v3 and v4.
cat > "$B/cpw.c" <<'EOF'
#include <kadm5/admin.h>
#include <stdio.h>
#include <stdlib.h>
int main(int argc, char **argv) {
    krb5_context ctx; void *h; kadm5_config_params params = {0};
    kadm5_principal_ent_rec ent; kadm5_policy_ent_rec pol;
    krb5_principal p = NULL; char **names; int n; krb5_string_attr *strs;
    if (krb5_init_context(&ctx)) return 2;
    long ret = kadm5_init_with_password(ctx, argv[1], argv[2], KADM5_CHANGEPW_SERVICE,
                                        &params, KADM5_STRUCT_VERSION,
                                        strtoul(argv[3], NULL, 0), NULL, &h);
    printf("init %ld\n", ret);
    if (ret) return 0;
    for (int i = 4; i < argc; i++) {
        krb5_parse_name(ctx, argv[i], &p);
        printf("get %s %ld\n", argv[i], (long)kadm5_get_principal(h, p, &ent,
               KADM5_PRINCIPAL_NORMAL_MASK));
    }
    printf("getpol strict %ld\n", (long)kadm5_get_policy(h, "strict", &pol));
    printf("getpol plain %ld\n", (long)kadm5_get_policy(h, "plain", &pol));
    printf("list %ld\n", (long)kadm5_get_principals(h, "*", &names, &n));
    printf("getstrs %ld\n", (long)kadm5_get_strings(h, p, &strs, &n));
    return 0;
}
EOF
gcc -o "$B/cpw" "$B/cpw.c" $(krb5-config --libs kadm-client) 2>"$B/cc.log" \
  || fail "building cpw: $(cat $B/cc.log)"
for v in 0x12345702 0x12345703 0x12345704; do
  "$B/cpw" alice@$R alice-pw-1 $v alice@$R bob@$R > "$B/cpw.out" || fail "cpw $v"
  printf '%s\n' "init 0" "get alice@$R 0" "get bob@$R 43787521" "getpol strict 0" \
    "getpol plain 43787521" "list 43787564" "getstrs 43787521" | diff -u - "$B/cpw.out" \
    || fail "changepw service at $v"
done
grep -q "Request: kadm5_init, alice@$R, success, client=alice@$R, service=kadmin/changepw@$R, addr=127.0.0.1, vers=2, flavor=6" \
  "$B/kadmind.log" || fail "no v2 init log line"
echo KADMIN_LIVE_OK
"#;
