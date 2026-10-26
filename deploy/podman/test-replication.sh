#!/usr/bin/env bash
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CLI="${CONTAINER_CLI:-podman}"
KDC_IMAGE="${KDC_IMAGE:-localhost/krb5-rs-kdc:e2e}"
MIT_IMAGE="${MIT_IMAGE:-krb5-rs-mit-test:1.22.2}"
NETWORK="${PODMAN_NETWORK:-krb5rs-prop}"
TEMP_DIR="$(mktemp -d)"
PRIMARY="$TEMP_DIR/primary.yaml"
REPLICA="$TEMP_DIR/replica.yaml"
MASTER="$(openssl rand -hex 24)"
KPROP="$(openssl rand -hex 24)"
PASSWORD="E2e-$(openssl rand -hex 8)"
ADMIN_PASSWORD="E2e-$(openssl rand -hex 8)"
NEW_PASSWORD="E2e-$(openssl rand -hex 8)"

cleanup() {
  local status=$?
  if [ "$status" -ne 0 ]; then
    for c in krb5-rs-kdc-kprop krb5-rs-kdc-kadmind krb5-rs-kdc-kdc krb5-rs-kdc-replica-kpropd krb5-rs-kdc-replica-kdc; do
      echo "--- logs $c"
      "$CLI" logs "$c" 2>&1 | tail -n 50 || true
    done
  fi
  "$CLI" kube play --down "$PRIMARY" >/dev/null 2>&1 || true
  "$CLI" kube play --down "$REPLICA" >/dev/null 2>&1 || true
  "$CLI" volume rm -f krb5-rs-kdc-data krb5-rs-kdc-replica-data >/dev/null 2>&1 || true
  "$CLI" network rm -f "$NETWORK" >/dev/null 2>&1 || true
  rm -rf "$TEMP_DIR"
  exit "$status"
}
trap cleanup EXIT

step() { echo "==> $*"; }

fill() {
  sed -e "s/CHANGE-ME-master/$MASTER/" -e "s/CHANGE-ME-kprop/$KPROP/" \
    -e "s#ghcr.io/exonical/krb5-rs-kdc:latest#$KDC_IMAGE#" -e '/hostPort:/d' "$1" > "$2"
}

kdb() {
  local pod=$1
  shift
  "$CLI" exec -i "$pod-kdc" /usr/local/bin/krb5-rs-kdb --config /etc/krb5-rs/kdc.conf \
    --krb5-config /etc/krb5-rs/krb5.conf --realm EXAMPLE.COM \
    --master-password-file /secrets/master-password "$@"
}

retry() {
  local tries=$1
  shift
  for _ in $(seq "$tries"); do
    if "$@" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  "$@"
}

fill "$HERE/krb5-rs-kdc-replica.yaml" "$REPLICA"
fill "$HERE/krb5-rs-kdc.yaml" "$PRIMARY"
"$CLI" network create "$NETWORK" >/dev/null

step "start the replica (kpropd + KDC waiting for its first database)"
"$CLI" kube play --network "$NETWORK" "$REPLICA"
infra="$("$CLI" pod inspect krb5-rs-kdc-replica --format '{{.InfraContainerID}}')"
ip="$("$CLI" inspect "$infra" --format "{{(index .NetworkSettings.Networks \"$NETWORK\").IPAddress}}")"
test -n "$ip"
sed -i "s/^  hostname: kdc1.example.com$/&\n  hostAliases:\n    - ip: \"$ip\"\n      hostnames:\n        - kdc2.example.com/" "$PRIMARY"

step "start the primary (KDC + kprop pushing to kdc2.example.com at $ip)"
"$CLI" kube play --network "$NETWORK" "$PRIMARY"

step "the first push loads the replica"
retry 120 kdb krb5-rs-kdc-replica getprinc host/kdc1.example.com

step "an admin change on the primary reaches the replica before the 60s interval"
printf '%s\n%s\n' "$PASSWORD" "$PASSWORD" | kdb krb5-rs-kdc addprinc e2e-user
retry 30 kdb krb5-rs-kdc-replica getprinc e2e-user

step "MIT kinit against the replica KDC"
cat > "$TEMP_DIR/krb5.conf" <<EOF
[libdefaults]
 default_realm = EXAMPLE.COM
 dns_lookup_kdc = false
 dns_lookup_realm = false
 udp_preference_limit = 1
[realms]
 EXAMPLE.COM = {
  kdc = $ip:8888
 }
EOF
echo "$PASSWORD" | "$CLI" run --rm -i --network "$NETWORK" \
  -v "$TEMP_DIR/krb5.conf:/etc/krb5.conf:ro" -e KRB5_CONFIG=/etc/krb5.conf \
  --entrypoint kinit "$MIT_IMAGE" e2e-user@EXAMPLE.COM

step "MIT kadmin and kpasswd against the primary's kadmind"
infra="$("$CLI" pod inspect krb5-rs-kdc --format '{{.InfraContainerID}}')"
pip="$("$CLI" inspect "$infra" --format "{{(index .NetworkSettings.Networks \"$NETWORK\").IPAddress}}")"
test -n "$pip"
printf '%s\n%s\n' "$ADMIN_PASSWORD" "$ADMIN_PASSWORD" | kdb krb5-rs-kdc addprinc admin/admin
cat > "$TEMP_DIR/admin-krb5.conf" <<EOF
[libdefaults]
 default_realm = EXAMPLE.COM
 dns_lookup_kdc = false
 dns_lookup_realm = false
[realms]
 EXAMPLE.COM = {
  kdc = $pip:8888
  admin_server = $pip:7490
  kpasswd_server = $pip:4640
 }
EOF
mit() { # tool args...
  "$CLI" run --rm -i --network "$NETWORK" \
    -v "$TEMP_DIR/admin-krb5.conf:/etc/krb5.conf:ro" -e KRB5_CONFIG=/etc/krb5.conf \
    --entrypoint "$1" "$MIT_IMAGE" "${@:2}"
}
retry 30 mit kadmin -p admin/admin -w "$ADMIN_PASSWORD" -q "getprinc kadmin/admin"
out="$(mit kadmin -p admin/admin -w "$ADMIN_PASSWORD" -q "addprinc -pw $PASSWORD e2e-remote" 2>&1)"
echo "$out"
grep -q 'Principal "e2e-remote@EXAMPLE.COM" created.' <<<"$out"
retry 30 kdb krb5-rs-kdc-replica getprinc e2e-remote
out="$(printf '%s\n%s\n%s\n' "$PASSWORD" "$NEW_PASSWORD" "$NEW_PASSWORD" | mit kpasswd e2e-remote@EXAMPLE.COM 2>&1)"
echo "$out"
grep -q "Password changed." <<<"$out"
echo "$NEW_PASSWORD" | mit kinit e2e-remote@EXAMPLE.COM

echo "podman replication e2e passed"
