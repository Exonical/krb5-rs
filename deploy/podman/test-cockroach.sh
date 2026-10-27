#!/usr/bin/env bash
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
CLI="${CONTAINER_CLI:-podman}"
NETWORK="${PODMAN_NETWORK:-krb5rs-crdb}"
DB=krb5_podman_e2e
REALM="${PODMAN_E2E_REALM:-PODMAN.E2E}"
REGION="${PODMAN_E2E_REGION:-california}"
CRDB_HOST="${PODMAN_CRDB_HOST:-crdb1}"
CRDB_IMAGE=docker.io/cockroachdb/cockroach:v26.3.2@sha256:84f0c929fdd4284b40a0c4afb1f284573fb281abc0323f8329e4e5f1650a3e00
KDC_IMAGE="${KDC_IMAGE:-localhost/krb5-rs-kdc:e2e-cockroach}"
MIT_IMAGE="${MIT_IMAGE:-docker.io/library/krb5-rs-mit-test:1.22.2}"
KDC_HOST="${PODMAN_KDC_HOST:-172.30.251.165}"
KDC_PORT="${PODMAN_KDC_PORT:-18888}"
METRICS_PORT="${PODMAN_METRICS_PORT:-19100}"
KADMIN_PORT="${PODMAN_KADMIN_PORT:-17749}"
KPASSWD_PORT="${PODMAN_KPASSWD_PORT:-17464}"
TEST_PREFIX=krb5-rs-kdc-podman-e2e
MASTER_SECRET="${TEST_PREFIX}-master"
TLS_SECRET="${TEST_PREFIX}-replica-tls"
DATA_VOLUME="${TEST_PREFIX}-data"
CONFIG_VOLUME="${TEST_PREFIX}-config"
MASTER_VOLUME="$MASTER_SECRET"
TLS_VOLUME="$TLS_SECRET"
CERTS_DIR="$ROOT/tests/crdb/certs"
TEMP_DIR="$(mktemp -d)"
CONFIG_DIR="$TEMP_DIR/config"
MANIFEST="$TEMP_DIR/krb5-rs-kdc-cockroach.yaml"
MANIFEST_HOST=""
MANIFEST_FILLED=0
MASTER_PASSWORD="$TEMP_DIR/master-password"
DB_CREATED=0

export MSYS_NO_PATHCONV=1

host_path() {
  if command -v cygpath >/dev/null 2>&1; then
    cygpath -m "$1"
  else
    realpath "$1"
  fi
}

run_crdb_sql() {
  "$CLI" run --rm --network "$NETWORK" \
    -v "$(host_path "$CERTS_DIR"):/certs:ro" \
    --entrypoint /cockroach/cockroach "$CRDB_IMAGE" sql \
    --certs-dir=/certs --host="${CRDB_HOST}:26257" "$@"
}

run_kdb() {
  local config=$1
  shift
  "$CLI" run --rm -i --network "$NETWORK" --user 0 \
    -v "$(host_path "$CONFIG_DIR"):/config:ro" \
    -v "$(host_path "$CERTS_DIR"):/crdb:ro" \
    -v "$(host_path "$TEMP_DIR"):/secrets:ro" \
    --entrypoint /usr/local/bin/krb5-rs-kdb "$KDC_IMAGE" \
    --config "/config/${config}" \
    --krb5-config /config/krb5.conf \
    --realm "$REALM" "$@"
}

base64_file() {
  base64 < "$1" | tr -d '\r\n'
}

placeholder() {
  printf '%s' "$1" | base64 | tr -d '\r\n'
}

replace_manifest() {
  local marker=$1
  local value=$2
  local escaped
  escaped="$(printf '%s' "$value" | sed 's/[&|]/\\&/g')"
  sed -i "s|${marker}|${escaped}|g" "$MANIFEST"
}

podman_kube_down() {
  if [ "$MANIFEST_FILLED" = 1 ]; then
    "$CLI" kube down --force "$MANIFEST_HOST" >/dev/null 2>&1 || true
  fi
}

drop_database() {
  run_crdb_sql -e "DROP DATABASE IF EXISTS \"${DB}\" CASCADE" >/dev/null 2>&1 || true
}

cleanup() {
  podman_kube_down
  "$CLI" pod rm -f "$TEST_PREFIX" >/dev/null 2>&1 || true
  "$CLI" secret rm "$MASTER_SECRET" "$TLS_SECRET" >/dev/null 2>&1 || true
  "$CLI" volume rm "$DATA_VOLUME" "$CONFIG_VOLUME" "$MASTER_VOLUME" "$TLS_VOLUME" \
    >/dev/null 2>&1 || true
  if [ "$DB_CREATED" = 1 ]; then
    drop_database
  fi
  rm -rf "$TEMP_DIR"
}

on_exit() {
  result=$?
  cleanup
  exit "$result"
}
trap on_exit EXIT

for file in ca.crt client.root.crt client.root.key \
  client.kdc_admin.crt client.kdc_admin.key \
  client.kdc_replica.crt client.kdc_replica.key; do
  [ -r "$CERTS_DIR/$file" ] || {
    echo "missing CockroachDB test certificate: $CERTS_DIR/$file" >&2
    exit 1
  }
done
[ -r "$ROOT/tests/crdb/cluster.sh" ] || {
  echo "missing CockroachDB test-cluster script" >&2
  exit 1
}

step() { printf '\n=== %s\n' "$*"; }

step "clean leftover CockroachDB test databases"
CRDB_HOST="${CRDB_HOST:-172.30.251.165}" CONTAINER_CLI="$CLI" \
  bash "$ROOT/tests/crdb/cluster.sh" clean

mkdir -p "$CONFIG_DIR"
chmod 0700 "$TEMP_DIR" "$CONFIG_DIR"
openssl rand -hex 24 > "$MASTER_PASSWORD"
chmod 0644 "$MASTER_PASSWORD"

write_db_config() {
  local path=$1
  local user=$2
  local cert_user=$3
  cat > "$path" <<EOF
[realms]
 ${REALM} = {
  database_module = crdb
  key_stash_file = /tmp/stash
  supported_enctypes = aes256-cts-hmac-sha1-96:normal aes128-cts-hmac-sha1-96:normal
 }

[dbmodules]
 crdb = {
  db_library = krb5-rs-cockroach
  cockroach_url = postgresql://${user}@${CRDB_HOST}:26257/${DB}?sslmode=verify-full
  cockroach_ca = /crdb/ca.crt
  cockroach_cert = /crdb/client.${cert_user}.crt
  cockroach_key = /crdb/client.${cert_user}.key
  cockroach_pool_size = 8
  cockroach_pool_idle_timeout = 0s
  cockroach_connect_timeout = 5s
  cockroach_statement_timeout = 10s
  cockroach_transaction_timeout = 30s
  replication_read = follower
  replica_path = /var/lib/krb5-rs/replica
  turso_pool_size = 8
  region = ${REGION}
  consistency_mode = bounded
  max_staleness = 30s
  authoritative_timeout = 500ms
  replication_poll_interval = 1s
  replication_batch_limit = 1000
  replication_retry_min = 100ms
  replication_retry_max = 30s
  replication_rebuild = auto
  replication_heartbeat_interval = 5s
 }
EOF
}

cat > "$CONFIG_DIR/krb5.conf" <<EOF
[libdefaults]
 default_realm = ${REALM}
 dns_lookup_kdc = false
 dns_lookup_realm = false
EOF
write_db_config "$CONFIG_DIR/migrator.conf" root root
write_db_config "$CONFIG_DIR/admin.conf" kdc_admin kdc_admin

step "create the scratch database and migrate with the root certificate"
drop_database
DB_CREATED=1
run_crdb_sql -e "CREATE DATABASE IF NOT EXISTS \"${DB}\""
run_kdb migrator.conf database migrate --create-roles

step "initialize the realm with the kdc_admin certificate"
run_kdb admin.conf --master-password-file /secrets/master-password init

step "fill a temporary Podman manifest with the test values"
cp "$HERE/krb5-rs-kdc-cockroach.yaml" "$MANIFEST"
HOST_NAME="$(hostname | tr -c '[:alnum:].-' '-')"
POD_NAME="${REGION}-${HOST_NAME}"
sed -i "s/krb5-rs-kdc-cockroach/${TEST_PREFIX}/g" "$MANIFEST"
replace_manifest ghcr.io/exonical/krb5-rs-kdc:CHANGE-ME-tag-cockroach "$KDC_IMAGE"
replace_manifest CHANGE-ME-REGION-CHANGE-ME-HOST "$POD_NAME"
replace_manifest CHANGE-ME-REALM "$REALM"
replace_manifest CHANGE-ME-CRDB-HOST "$CRDB_HOST"
replace_manifest CHANGE-ME-DATABASE "$DB"
replace_manifest CHANGE-ME-REGION "$REGION"
MASTER_PLACEHOLDER="$(placeholder CHANGE-ME-MASTER-PASSWORD)"
CA_PLACEHOLDER="$(placeholder CHANGE-ME-CA-CERTIFICATE)"
CERT_PLACEHOLDER="$(placeholder CHANGE-ME-REPLICA-CERTIFICATE)"
KEY_PLACEHOLDER="$(placeholder CHANGE-ME-REPLICA-PRIVATE-KEY)"
ADMIN_CERT_PLACEHOLDER="$(placeholder CHANGE-ME-ADMIN-CERTIFICATE)"
ADMIN_KEY_PLACEHOLDER="$(placeholder CHANGE-ME-ADMIN-PRIVATE-KEY)"
replace_manifest "$MASTER_PLACEHOLDER" "$(base64_file "$MASTER_PASSWORD")"
replace_manifest "$CA_PLACEHOLDER" "$(base64_file "$CERTS_DIR/ca.crt")"
replace_manifest "$CERT_PLACEHOLDER" "$(base64_file "$CERTS_DIR/client.kdc_replica.crt")"
replace_manifest "$KEY_PLACEHOLDER" "$(base64_file "$CERTS_DIR/client.kdc_replica.key")"
replace_manifest "$ADMIN_CERT_PLACEHOLDER" "$(base64_file "$CERTS_DIR/client.kdc_admin.crt")"
replace_manifest "$ADMIN_KEY_PLACEHOLDER" "$(base64_file "$CERTS_DIR/client.kdc_admin.key")"
sed -i "s/hostPort: 88/hostPort: ${KDC_PORT}/g" "$MANIFEST"
sed -i "s/hostPort: 19100/hostPort: ${METRICS_PORT}/g" "$MANIFEST"
sed -i "s/hostPort: 749/hostPort: ${KADMIN_PORT}/g" "$MANIFEST"
sed -i "s/hostPort: 464/hostPort: ${KPASSWD_PORT}/g" "$MANIFEST"
if grep -q 'CHANGE-ME' "$MANIFEST"; then
  grep -n 'CHANGE-ME' "$MANIFEST" >&2 || true
  echo "unfilled CHANGE-ME value remains in the temporary Podman manifest" >&2
  exit 1
fi
for marker in "$MASTER_PLACEHOLDER" "$CA_PLACEHOLDER" "$CERT_PLACEHOLDER" "$KEY_PLACEHOLDER" \
  "$ADMIN_CERT_PLACEHOLDER" "$ADMIN_KEY_PLACEHOLDER"; do
  if grep -Fq "$marker" "$MANIFEST"; then
    echo "unfilled base64 Secret placeholder remains in the temporary Podman manifest" >&2
    exit 1
  fi
done
MANIFEST_FILLED=1
MANIFEST_HOST="$(host_path "$MANIFEST")"

step "start the CockroachDB-backed KDC Pod on the test network"
podman_kube_down
"$CLI" kube play --network "$NETWORK" "$MANIFEST_HOST"

KDC_CONTAINER="${TEST_PREFIX}-kdc"
tmpfs_mounts=$("$CLI" inspect "$KDC_CONTAINER" --format '{{json .HostConfig.Tmpfs}}')
[[ "$tmpfs_mounts" == *'"/tmp"'* ]] || {
  echo "expected the KDC /tmp emptyDir to be a tmpfs mount; inspect reports:"
  printf '%s\n' "$tmpfs_mounts"
  exit 1
}

step "wait for KDC readiness"
ready=0
for _ in $(seq 1 90); do
  if "$CLI" run --rm --network host "$MIT_IMAGE" python3 -c \
    "import urllib.request; urllib.request.urlopen('http://${KDC_HOST}:${METRICS_PORT}/readyz', timeout=2).read()" \
    >/dev/null 2>&1
  then
    ready=1
    break
  fi
  sleep 2
done
if [ "$ready" != 1 ]; then
  "$CLI" ps -a --filter name="$TEST_PREFIX" --format '{{.Names}} {{.Status}}' || true
  "$CLI" logs "$KDC_CONTAINER" 2>&1 | tail -80 || true
  echo "KDC /readyz did not become healthy"
  exit 1
fi
if [ "${PODMAN_TEST_FAIL_AFTER_READY:-0}" = 1 ]; then
  echo "intentional failure after KDC readiness for cleanup verification"
  exit 1
fi

step "add a principal with a one-off kdc_admin container"
printf 'alice-password\n' | run_kdb admin.conf \
  --master-password-file /secrets/master-password addprinc alice

cat > "$CONFIG_DIR/mit-krb5.conf" <<EOF
[libdefaults]
 default_realm = ${REALM}
 dns_lookup_kdc = false
 dns_lookup_realm = false
[realms]
 ${REALM} = {
  kdc = ${KDC_HOST}:${KDC_PORT}
  admin_server = ${KDC_HOST}:${KADMIN_PORT}
  kpasswd_server = ${KDC_HOST}:${KPASSWD_PORT}
 }
EOF

step "authenticate with MIT against the Podman-published KDC port"
mit_kinit() {
  printf 'alice-password\n' | "$CLI" run --rm -i --network host \
    -v "$(host_path "$CONFIG_DIR/mit-krb5.conf"):/tmp/krb5.conf:ro" \
    "$MIT_IMAGE" bash -c \
    "export KRB5_CONFIG=/tmp/krb5.conf KRB5CCNAME=FILE:/tmp/cc_\$RANDOM; timeout 20 kinit alice@${REALM} && klist"
}
authenticated=0
for _ in $(seq 1 30); do
  if mit_kinit > "$TEMP_DIR/kinit-output" 2>&1; then
    authenticated=1
    break
  fi
  sleep 1
done
if [ "$authenticated" != 1 ]; then
  cat "$TEMP_DIR/kinit-output" >&2 || true
  "$CLI" logs "$KDC_CONTAINER" 2>&1 | tail -80 || true
  echo "MIT kinit did not obtain credentials through the Podman-published KDC within 30 seconds"
  exit 1
fi
echo "MIT kinit succeeded against ${KDC_HOST}:${KDC_PORT}"

step "administer with MIT kadmin and kpasswd through the Podman-published kadmind"
printf 'admin-password\n' | run_kdb admin.conf \
  --master-password-file /secrets/master-password addprinc admin/admin
mit_run() {
  "$CLI" run --rm -i --network host \
    -v "$(host_path "$CONFIG_DIR/mit-krb5.conf"):/tmp/krb5.conf:ro" \
    "$MIT_IMAGE" bash -c "export KRB5_CONFIG=/tmp/krb5.conf KRB5CCNAME=FILE:/tmp/cc_\$RANDOM; $1"
}
administered=0
for _ in $(seq 1 30); do
  if mit_run "timeout 30 kadmin -p admin/admin -w admin-password -q 'addprinc -pw carol-password carol'" \
    > "$TEMP_DIR/kadmin-output" 2>&1 && grep -q "Principal \"carol@${REALM}\" created." "$TEMP_DIR/kadmin-output"
  then
    administered=1
    break
  fi
  sleep 1
done
if [ "$administered" != 1 ]; then
  cat "$TEMP_DIR/kadmin-output" >&2 || true
  "$CLI" logs "${TEST_PREFIX}-kadmind" 2>&1 | tail -80 || true
  echo "MIT kadmin did not add carol through the Podman-published kadmind"
  exit 1
fi
changed=0
for _ in $(seq 1 30); do
  if printf 'carol-password\ncarol-new-password\ncarol-new-password\n' \
    | mit_run "timeout 30 kpasswd carol@${REALM}" > "$TEMP_DIR/kpasswd-output" 2>&1 \
    && grep -q "Password changed." "$TEMP_DIR/kpasswd-output"
  then
    changed=1
    break
  fi
  sleep 1
done
if [ "$changed" != 1 ]; then
  cat "$TEMP_DIR/kpasswd-output" >&2 || true
  echo "MIT kpasswd did not change carol's password through the Podman-published kadmind"
  exit 1
fi
echo "MIT kadmin and kpasswd succeeded against ${KDC_HOST}:${KADMIN_PORT}/${KPASSWD_PORT}"

step "tear down the Pod and drop the scratch database"
podman_kube_down
drop_database
DB_CREATED=0
echo "Podman CockroachDB E2E passed"
