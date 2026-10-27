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
    let mkdir = container_run(
        &["exec", &c, "mkdir", "-p", "/tmp/kadmin-write-live/bin"],
        "",
    );
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
admin	addprinc -e aes128-cts-hmac-sha1-96:normal -pw ks-pw-1 kst
admin	cpw -e aes256-cts-hmac-sha1-96:norealm -pw ks-pw-2 kst
admin	cpw -randkey -keepold -e aes128-cts-hmac-sha1-96:onlyrealm kst
admin	getprinc kst
admin	cpw -e aes128-cts-hmac-sha1-96:afs3 -pw ks-pw-3 kst
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
admin	addprinc -randkey skey
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

# kadmin has no setkey command; call setkey_principal{,_3,_4} directly.
cat > "$B/setkey.c" <<'CEOF'
#include <kadm5/admin.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static krb5_context ctx;
static krb5_principal P(const char *s) {
    krb5_principal p = NULL; krb5_parse_name(ctx, s, &p); return p;
}
static krb5_keyblock kb(krb5_enctype e, int len, int fill) {
    krb5_keyblock k = {0};
    k.enctype = e; k.length = len; k.contents = malloc(len);
    memset(k.contents, fill, len);
    return k;
}
int main(int argc, char **argv) {
    void *h; kadm5_config_params params = {0};
    if (krb5_init_context(&ctx)) return 2;
    long r = kadm5_init_with_password(ctx, argv[1], argv[2], KADM5_ADMIN_SERVICE,
                                      &params, KADM5_STRUCT_VERSION,
                                      KADM5_API_VERSION_4, NULL, &h);
    printf("init %ld\n", r);
    if (r) return 0;
    krb5_keyblock k1[2] = {kb(18, 32, 1), kb(17, 16, 2)};
    printf("setkey %ld\n", (long)kadm5_setkey_principal(h, P("skey"), k1, 2));
    printf("setkey empty %ld\n", (long)kadm5_setkey_principal(h, P("skey"), k1, 0));
    krb5_key_salt_tuple ks[2] = {{18, KRB5_KDB_SALTTYPE_NORMAL},
                                 {18, KRB5_KDB_SALTTYPE_NORMAL}};
    krb5_keyblock k3[2] = {kb(18, 32, 3), kb(18, 32, 4)};
    printf("setkey3 dup %ld\n",
           (long)kadm5_setkey_principal_3(h, P("skey"), TRUE, 2, ks, k3, 2));
    printf("setkey3 %ld\n",
           (long)kadm5_setkey_principal_3(h, P("skey"), TRUE, 1, ks, k3, 1));
    kadm5_key_data kd[2];
    memset(kd, 0, sizeof(kd));
    kd[0].kvno = 7; kd[0].key = kb(18, 32, 5);
    kd[0].salt.type = KRB5_KDB_SALTTYPE_SPECIAL;
    kd[0].salt.data.data = "weird"; kd[0].salt.data.length = 5;
    kd[1].kvno = 7; kd[1].key = kb(17, 16, 6);
    kd[1].salt.type = KRB5_KDB_SALTTYPE_NORMAL;
    printf("setkey4 %ld\n", (long)kadm5_setkey_principal_4(h, P("skey"), TRUE, kd, 2));
    printf("setkey4 again %ld\n",
           (long)kadm5_setkey_principal_4(h, P("skey"), TRUE, kd, 2));
    kd[1].kvno = 8;
    printf("setkey4 mixed %ld\n",
           (long)kadm5_setkey_principal_4(h, P("skey"), FALSE, kd, 2));
    printf("setkey history %ld\n",
           (long)kadm5_setkey_principal(h, P("kadmin/history"), k1, 2));
    printf("setkey locked %ld\n", (long)kadm5_setkey_principal(h, P("locked"), k1, 2));
    printf("setkey missing %ld\n", (long)kadm5_setkey_principal(h, P("nosuch"), k1, 2));
    return 0;
}
CEOF
gcc -o "$B/setkey" "$B/setkey.c" $(krb5-config --libs kadm-client) 2>"$B/cc.log" \
  || fail "building setkey: $(cat $B/cc.log)"
for s in mit rs; do
  for u in nobody admin; do
    KRB5_CONFIG=$B/$s/krb5.conf "$B/setkey" $u@$R $u-pw
  done > "$B/$s/setkey.out" 2>&1
done
diff -u "$B/mit/setkey.out" "$B/rs/setkey.out" || fail "setkey differs"
grep -q "^setkey4 0$" "$B/rs/setkey.out" || fail "setkey4 failed: $(cat $B/rs/setkey.out)"

# kadmin has no policy TL data option; call create/modify/get_policy directly.
cat > "$B/poltl.c" <<'CEOF'
#include <kadm5/admin.h>
#include <stdio.h>
#include <string.h>
static void tl(krb5_tl_data *t, krb5_int16 type, const char *s, krb5_tl_data *next) {
    t->tl_data_type = type; t->tl_data_length = strlen(s);
    t->tl_data_contents = (krb5_octet *)s; t->tl_data_next = next;
}
static void show(void *h, char *name) {
    kadm5_policy_ent_rec e;
    long r = kadm5_get_policy(h, name, &e);
    printf("get %s %ld", name, r);
    if (!r) {
        printf(" n=%d", e.n_tl_data);
        for (krb5_tl_data *t = e.tl_data; t; t = t->tl_data_next)
            printf(" %d:%.*s", t->tl_data_type, t->tl_data_length, t->tl_data_contents);
        kadm5_free_policy_ent(h, &e);
    }
    printf("\n");
}
int main(int argc, char **argv) {
    krb5_context ctx; void *h; kadm5_config_params params = {0};
    krb5_tl_data a, b, c, d, e;
    if (krb5_init_context(&ctx)) return 2;
    long r = kadm5_init_with_password(ctx, argv[1], argv[2], KADM5_ADMIN_SERVICE,
                                      &params, KADM5_STRUCT_VERSION,
                                      KADM5_API_VERSION_4, NULL, &h);
    printf("init %ld\n", r);
    if (r) return 0;
    kadm5_policy_ent_rec p;
    memset(&p, 0, sizeof(p));
    p.policy = "tlpol";
    tl(&c, 300, "c", NULL); tl(&b, 301, "bb", &c); tl(&a, 300, "a", &b);
    p.n_tl_data = 3; p.tl_data = &a;
    printf("create %ld\n", (long)kadm5_create_policy(h, &p, KADM5_POLICY | KADM5_POLICY_TL_DATA));
    show(h, "tlpol");
    tl(&e, 302, "new", NULL); tl(&d, 301, "XX", &e);
    p.n_tl_data = 2; p.tl_data = &d;
    printf("modify %ld\n", (long)kadm5_modify_policy(h, &p, KADM5_POLICY_TL_DATA));
    show(h, "tlpol");
    printf("modify maxlife %ld\n", (long)kadm5_modify_policy(h, &p, KADM5_PW_MAX_LIFE));
    show(h, "tlpol");
    tl(&a, 100, "low", NULL);
    p.policy = "lowpol"; p.n_tl_data = 1; p.tl_data = &a;
    printf("create low %ld\n", (long)kadm5_create_policy(h, &p, KADM5_POLICY | KADM5_POLICY_TL_DATA));
    p.policy = "plain";
    printf("modify low %ld\n", (long)kadm5_modify_policy(h, &p, KADM5_POLICY_TL_DATA));
    show(h, "plain");
    return 0;
}
CEOF
gcc -o "$B/poltl" "$B/poltl.c" $(krb5-config --libs kadm-client) 2>"$B/cc.log" \
  || fail "building poltl: $(cat $B/cc.log)"
for s in mit rs; do
  KRB5_CONFIG=$B/$s/krb5.conf "$B/poltl" admin@$R admin-pw > "$B/$s/poltl.out" 2>&1
done
diff -u "$B/mit/poltl.out" "$B/rs/poltl.out" || fail "policy TL data differs"
grep -q "^get tlpol 0 n=4 300:a 301:XX 300:c 302:new$" "$B/rs/poltl.out" \
  || fail "policy TL data not stored: $(cat $B/rs/poltl.out)"

stop
sleep 0.5
# Read both databases back with MIT's kadmin.local and kproplog.
for s in mit rs; do
  export KRB5_CONFIG=$B/$s/krb5.conf KRB5_KDC_PROFILE=$B/$s/kdc.conf
  for p in limx/lim locked bob weak skey; do
    kadmin.local -r $R -q "getprinc $p" 2>&1 | norm
  done > "$B/$s/final.out"
  kproplog -h -p "$B/$s/db/principal.ulog" 2>&1 | grep -E "Last serial|Entry count|Update log" > "$B/$s/ulog.out" || true
  kdb5_util -r $R dump "$B/$s/final.dump" && grep "^policy" "$B/$s/final.dump" > "$B/$s/policies.out"
done
diff -u "$B/mit/policies.out" "$B/rs/policies.out" || fail "dumped policies differ"
diff -u "$B/mit/final.out" "$B/rs/final.out" || fail "databases differ"
diff -u "$B/mit/ulog.out" "$B/rs/ulog.out" || fail "update logs differ"
echo KADMIN_WRITE_LIVE_OK
"#;
