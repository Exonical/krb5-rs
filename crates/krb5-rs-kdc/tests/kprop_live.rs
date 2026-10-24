//! MIT 1.22.2 kprop/kpropd interoperability in both directions, inside the MIT
//! container of the Compose stack (`KPROP_LIVE_CONTAINER`, default
//! `krb5-rs-kdc-1`; `CONTAINER_CLI`, default `podman`). The krb5-rs binaries
//! are copied in, so they must run on the container's libc (or be static).

use std::io::Write;
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

#[test]
#[ignore = "requires the MIT container of the Compose stack"]
fn mit_and_krb5_rs_kprop_interoperate_both_ways() {
    let c = container();
    let mkdir = container_run(&["exec", &c, "mkdir", "-p", "/tmp/kprop-live/bin"], "");
    assert!(mkdir.status.success(), "{mkdir:?}");
    for (name, path) in [
        ("krb5-rs-kdb", env!("CARGO_BIN_EXE_krb5-rs-kdb")),
        ("krb5-rs-kprop", env!("CARGO_BIN_EXE_krb5-rs-kprop")),
        ("krb5-rs-kpropd", env!("CARGO_BIN_EXE_krb5-rs-kpropd")),
    ] {
        let dest = format!("{c}:/tmp/kprop-live/bin/{name}");
        let out = container_run(&["cp", path, &dest], "");
        assert!(out.status.success(), "cp {name}: {out:?}");
    }
    let out = container_run(&["exec", "-i", &c, "bash", "-s"], SCRIPT);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success() && stdout.contains("KPROP_LIVE_OK"),
        "kprop interop script failed\nstdout:\n{stdout}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

const SCRIPT: &str = r#"
set -euo pipefail
B=/tmp/kprop-live
BIN=$B/bin
R=KPROP.LIVE
pkill -f "krb5kdc -r $R" 2>/dev/null || true
rm -rf "$B/mit" "$B/mitrep" "$B/rsrep" "$B"/*.conf "$B"/*.log "$B"/*.keytab "$B"/*.acl "$B"/dump* "$B/stash"
mkdir -p "$B/mit" "$B/mitrep" "$B/rsrep"
H=$(hostname | tr 'A-Z' 'a-z')
realm_conf() { # file dbdir db_library
  cat > "$1" <<EOF
[kdcdefaults]
 kdc_ports = 18888
 kdc_tcp_ports = 18888
[realms]
 $R = {
  database_name = $2/principal
  key_stash_file = $B/stash
  supported_enctypes = aes256-cts-hmac-sha1-96:normal
 }
[dbmodules]
 $R = {
  db_library = $3
  database_name = $2/principal
 }
EOF
}
realm_conf "$B/mit.conf" "$B/mit" db2
realm_conf "$B/mitrep.conf" "$B/mitrep" db2
realm_conf "$B/rsrep.conf" "$B/rsrep" klmdb
cat > "$B/krb5.conf" <<EOF
[libdefaults]
 default_realm = $R
 dns_lookup_kdc = false
 dns_canonicalize_hostname = false
 rdns = false
 udp_preference_limit = 1
[realms]
 $R = {
  kdc = 127.0.0.1:18888
 }
EOF
export KRB5_CONFIG=$B/krb5.conf
mit() { KRB5_KDC_PROFILE=$B/$1.conf "${@:2}"; }
wait_listen() { local hex; hex=$(printf '%04X' "$1"); for _ in $(seq 1 100); do grep -Eq ":$hex [0-9A-F]+:0000 0A" /proc/net/tcp /proc/net/tcp6 && return 0; sleep 0.1; done; return 1; }
wait_port() { for _ in $(seq 1 100); do (exec 3<>/dev/tcp/127.0.0.1/$1) 2>/dev/null && return 0; sleep 0.1; done; return 1; }
mit mit kdb5_util create -r $R -s -P master-password >/dev/null
mit mit kadmin.local -r $R -q "addprinc -pw alice-pw alice" >/dev/null
mit mit kadmin.local -r $R -q "addprinc -randkey host/$H" >/dev/null
mit mit kadmin.local -r $R -q "ktadd -k $B/host.keytab host/$H" >/dev/null
for i in $(seq 1 60); do echo "addprinc -randkey filler$i"; done | mit mit kadmin.local -r $R >/dev/null
mit mit kdb5_util -r $R dump "$B/dump"
mit mit krb5kdc -r $R -n > "$B/kdc.log" 2>&1 &
wait_port 18888
echo "host/$H@$R" > "$B/ok.acl"
echo "host/other@$R" > "$B/bad.acl"

mit mitrep kpropd -D -t -P 17540 -r $R -s "$B/host.keytab" -a "$B/ok.acl" \
  -f "$B/mitrep/from_master" -p "$(command -v kdb5_util)" > "$B/mitkpropd.log" 2>&1 &
P=$!
wait_listen 17540
$BIN/krb5-rs-kprop -r $R -f "$B/dump" -P 17540 -s "$B/host.keytab" "$H" | grep -q "Database propagation to $H: SUCCEEDED"
wait $P
cmp "$B/dump" "$B/mitrep/from_master"
mit mitrep kadmin.local -r $R -q "getprinc alice" | grep -q "Principal: alice@$R"
test -f "$B/dump.$H.last_prop"
echo "rs kprop -> MIT kpropd ok"

KRB5_KDC_PROFILE=$B/rsrep.conf $BIN/krb5-rs-kpropd -D -t -P 17541 -r $R -s "$B/host.keytab" \
  -a "$B/ok.acl" -f "$B/rsrep/from_master" -p $BIN/krb5-rs-kdb > "$B/rskpropd.log" 2>&1 &
P=$!
wait_listen 17541
kprop -r $R -f "$B/dump" -P 17541 -s "$B/host.keytab" "$H" | grep -q "SUCCEEDED"
wait $P
cmp "$B/dump" "$B/rsrep/from_master"
$BIN/krb5-rs-kdb --config "$B/rsrep.conf" --realm $R getprinc alice | grep -q "alice@$R"
echo "MIT kprop -> rs kpropd ok"

rm -rf "$B/rsrep"/* "$B/mitrep/from_master"
KRB5_KDC_PROFILE=$B/rsrep.conf $BIN/krb5-rs-kpropd -D -t -P 17542 -r $R -s "$B/host.keytab" \
  -a "$B/bad.acl" -f "$B/rsrep/from_master" -p $BIN/krb5-rs-kdb > "$B/rsbad.log" 2>&1 &
P=$!
wait_listen 17542
if kprop -r $R -f "$B/dump" -P 17542 -s "$B/host.keytab" "$H" > "$B/mitkprop-bad.log" 2>&1; then
  echo "MIT kprop succeeded against a denying ACL" >&2; exit 1
fi
wait $P || true
grep -q "Rejected connection from unauthorized principal host/$H@$R" "$B/rsbad.log"
test ! -e "$B/rsrep/from_master"
mit mitrep kpropd -D -t -P 17543 -r $R -s "$B/host.keytab" -a "$B/bad.acl" \
  -f "$B/mitrep/from_master" -p "$(command -v kdb5_util)" > "$B/mitbad.log" 2>&1 &
P=$!
wait_listen 17543
if $BIN/krb5-rs-kprop -r $R -f "$B/dump" -P 17543 -s "$B/host.keytab" "$H" > "$B/rskprop-bad.log" 2>&1; then
  echo "krb5-rs kprop succeeded against a denying MIT ACL" >&2; exit 1
fi
wait $P || true
test ! -e "$B/mitrep/from_master"
echo "unauthorized rejected both ways"

cat > "$B/probe.py" <<'PROBE'
import socket, struct, sys
s = socket.create_connection(("127.0.0.1", int(sys.argv[1])))
for v in sys.argv[2:4]:
    m = v.encode() + b"\0"
    s.sendall(struct.pack(">I", len(m)) + m)
b = s.recv(1)
print(b[0] if b else "eof")
PROBE
probe() { # port sendauth-version appl-version expected-byte server
  if [ "$5" = mit ]; then
    mit mitrep kpropd -D -t -P $1 -r $R -s "$B/host.keytab" -a "$B/ok.acl" \
      -f "$B/mitrep/from_master" -p "$(command -v kdb5_util)" > "$B/probe$1.log" 2>&1 &
  else
    KRB5_KDC_PROFILE=$B/rsrep.conf $BIN/krb5-rs-kpropd -D -t -P $1 -r $R -s "$B/host.keytab" \
      -a "$B/ok.acl" -f "$B/rsrep/from_master" -p $BIN/krb5-rs-kdb > "$B/probe$1.log" 2>&1 &
  fi
  local p=$!
  wait_listen $1
  test "$(python3 "$B/probe.py" $1 "$2" "$3")" = "$4"
  wait $p || true
}
probe 17546 KRB5_SENDAUTH_V9.9 kprop5_01 1 rs
probe 17547 KRB5_SENDAUTH_V1.0 kprop5_99 2 rs
probe 17548 KRB5_SENDAUTH_V9.9 kprop5_01 1 mit
probe 17549 KRB5_SENDAUTH_V1.0 kprop5_99 2 mit
test ! -e "$B/rsrep/from_master"
test ! -e "$B/mitrep/from_master"
echo "bad versions rejected by both"

cat > "$B/badsize.c" <<'BADSIZE'
#include <krb5.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static void check(krb5_context ctx, krb5_error_code ret, const char *what)
{
    if (ret) {
        const char *m = krb5_get_error_message(ctx, ret);
        fprintf(stderr, "%s: %s\n", what, m);
        exit(1);
    }
}

int main(int argc, char **argv)
{
    krb5_context ctx;
    krb5_principal me, server;
    krb5_keytab kt;
    krb5_creds creds;
    krb5_auth_context ac = NULL;
    krb5_error *err = NULL;
    krb5_ap_rep_enc_part *rep = NULL;
    krb5_get_init_creds_opt *opt;
    struct sockaddr_in sin, local;
    socklen_t len = sizeof(local);
    krb5_address addr, *addrs[2];
    unsigned char zeros[12] = { 0 }, nonzero[12] = { 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1 };
    krb5_data in, out;
    char *sname;
    int fd;

    if (argc != 6) {
        fprintf(stderr, "usage: badsize port client server keytab short|nonzero12|unsafe\n");
        return 2;
    }
    check(ctx, krb5_init_context(&ctx), "init");
    check(ctx, krb5_parse_name(ctx, argv[2], &me), "parse client");
    check(ctx, krb5_parse_name(ctx, argv[3], &server), "parse server");
    check(ctx, krb5_kt_resolve(ctx, argv[4], &kt), "keytab");
    check(ctx, krb5_unparse_name(ctx, server, &sname), "unparse");
    check(ctx, krb5_get_init_creds_opt_alloc(ctx, &opt), "opt");
    check(ctx, krb5_get_init_creds_keytab(ctx, &creds, me, kt, 0, sname, opt), "get creds");

    fd = socket(AF_INET, SOCK_STREAM, 0);
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = htons(atoi(argv[1]));
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (connect(fd, (struct sockaddr *)&sin, sizeof(sin)) < 0 ||
        getsockname(fd, (struct sockaddr *)&local, &len) < 0) {
        perror("connect");
        return 1;
    }
    addr.magic = KV5M_ADDRESS;
    addr.addrtype = ADDRTYPE_INET;
    addr.length = 4;
    addr.contents = (krb5_octet *)&local.sin_addr;
    addrs[0] = &addr;
    addrs[1] = NULL;

    check(ctx, krb5_auth_con_init(ctx, &ac), "auth_con_init");
    krb5_auth_con_setflags(ctx, ac, KRB5_AUTH_CONTEXT_DO_SEQUENCE);
    check(ctx, krb5_auth_con_setaddrs(ctx, ac, &addr, NULL), "setaddrs");
    check(ctx, krb5_sendauth(ctx, &ac, &fd, "kprop5_01", me, server,
                             AP_OPTS_MUTUAL_REQUIRED, NULL, &creds, NULL,
                             &err, &rep, NULL), "sendauth");

    if (strcmp(argv[5], "unsafe") == 0) {
        out.data = "not a KRB-SAFE message";
        out.length = strlen(out.data);
    } else {
        in.data = (char *)(strcmp(argv[5], "short") == 0 ? zeros : nonzero);
        in.length = strcmp(argv[5], "short") == 0 ? 5 : 12;
        check(ctx, krb5_mk_safe(ctx, ac, &in, &out, NULL), "mk_safe");
    }
    check(ctx, krb5_write_message(ctx, &fd, &out), "write");
    check(ctx, krb5_read_message(ctx, &fd, &in), "read reply");
    check(ctx, krb5_rd_error(ctx, &in, &err), "rd_error");
    printf("error=%d text=%.*s\n", (int)err->error, (int)err->text.length, err->text.data);
    (void)addrs;
    return 0;
}
BADSIZE
gcc -o "$B/badsize" "$B/badsize.c" -lkrb5 -lcom_err
badsize() { # port mit|rs mode
  if [ "$2" = mit ]; then
    mit mitrep kpropd -D -t -P $1 -r $R -s "$B/host.keytab" -a "$B/ok.acl" \
      -f "$B/mitrep/from_master" -p "$(command -v kdb5_util)" > "$B/badsize$1.log" 2>&1 &
  else
    KRB5_KDC_PROFILE=$B/rsrep.conf $BIN/krb5-rs-kpropd -D -t -P $1 -r $R -s "$B/host.keytab" \
      -a "$B/ok.acl" -f "$B/rsrep/from_master" -p $BIN/krb5-rs-kdb > "$B/badsize$1.log" 2>&1 &
  fi
  local p=$!
  wait_listen $1
  "$B/badsize" $1 "host/$H@$R" "host/$H@$R" "$B/host.keytab" $3
  wait $p || true
}
port=17554
for mode in short nonzero12 unsafe; do
  rs=$(badsize $port rs $mode)
  ref=$(badsize $((port + 1)) mit $mode)
  port=$((port + 2))
  echo "$mode: krb5-rs [$rs] MIT [$ref]"
  test "$rs" = "$ref"
  if [ $mode != unsafe ]; then
    test "$rs" = "error=60 text=malformed database size message"
  fi
done
test ! -e "$B/rsrep/from_master"
test ! -e "$B/mitrep/from_master"
echo "malformed database sizes rejected by both"

cat > "$B/cut.py" <<'CUT'
import socket, sys, threading
lport, dhost, dport, cap = int(sys.argv[1]), sys.argv[2], int(sys.argv[3]), int(sys.argv[4])
l = socket.socket()
l.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
l.bind(("0.0.0.0", lport))
l.listen(1)
c, _ = l.accept()
d = socket.create_connection((dhost, dport))
def back():
    try:
        while True:
            x = d.recv(65536)
            if not x:
                break
            c.sendall(x)
    except OSError:
        pass
threading.Thread(target=back, daemon=True).start()
sent = 0
while sent < cap:
    x = c.recv(min(65536, cap - sent))
    if not x:
        break
    d.sendall(x)
    sent += len(x)
d.shutdown(socket.SHUT_RDWR)
d.close()
c.close()
CUT
test "$(stat -c %s "$B/dump")" -gt 12000
KRB5_KDC_PROFILE=$B/rsrep.conf $BIN/krb5-rs-kpropd -D -t -P 17550 -r $R -s "$B/host.keytab" \
  -a "$B/ok.acl" -f "$B/rsrep/from_master" -p $BIN/krb5-rs-kdb > "$B/rscut.log" 2>&1 &
P=$!
wait_listen 17550
python3 "$B/cut.py" 17551 "$H" 17550 6000 &
C=$!
wait_listen 17551
if kprop -r $R -f "$B/dump" -P 17551 -s "$B/host.keytab" "$H" > "$B/mitkprop-cut.log" 2>&1; then
  echo "MIT kprop succeeded over a truncated stream" >&2; exit 1
fi
wait $C || true
wait $P || true
test ! -e "$B/rsrep/from_master"
mit mitrep kpropd -D -t -P 17552 -r $R -s "$B/host.keytab" -a "$B/ok.acl" \
  -f "$B/mitrep/from_master" -p "$(command -v kdb5_util)" > "$B/mitcut.log" 2>&1 &
P=$!
wait_listen 17552
python3 "$B/cut.py" 17553 "$H" 17552 6000 &
C=$!
wait_listen 17553
if $BIN/krb5-rs-kprop -r $R -f "$B/dump" -P 17553 -s "$B/host.keytab" "$H" > "$B/rskprop-cut.log" 2>&1; then
  echo "krb5-rs kprop succeeded over a truncated stream" >&2; exit 1
fi
wait $C || true
wait $P || true
test ! -e "$B/mitrep/from_master"
echo "truncated transfers rejected both ways"

pkill -f "krb5kdc -r $R" || true
echo KPROP_LIVE_OK
"#;
