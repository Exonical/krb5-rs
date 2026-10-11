#!/usr/bin/env bash
# A secure 3-node CockroachDB cluster for the krb5-rs-kdb-cockroach tests.
#
#   tests/crdb/cluster.sh up      create certs, start the nodes, init, create the users
#   tests/crdb/cluster.sh down    remove the containers (keeps volumes and certs)
#   tests/crdb/cluster.sh nuke    remove containers, volumes, network and certs
#   tests/crdb/cluster.sh status
#   tests/crdb/cluster.sh sql 'SELECT 1'   run SQL as root on node 1
#
# Environment:
#   CRDB_HOST   address the host uses to reach the published ports; it is put in
#               the node certificates (default 127.0.0.1, set the podman VM IP
#               when the host cannot reach published ports on loopback)
#   CRDB_PORT   host port of node 1 (nodes 2 and 3 use PORT+1 and PORT+2)
#   CONTAINER_CLI  podman (default) or docker
#
# Localities: region=california (crdb1), region=ohio (crdb2),
# region=washington-dc (crdb3). Client certs for root, kdc_admin and
# kdc_replica are copied to tests/crdb/certs/.
set -euo pipefail
export MSYS_NO_PATHCONV=1

CLI="${CONTAINER_CLI:-podman}"
IMAGE="docker.io/cockroachdb/cockroach:v26.3.2@sha256:84f0c929fdd4284b40a0c4afb1f284573fb281abc0323f8329e4e5f1650a3e00"
NET=krb5rs-crdb
CERTS_VOL=krb5rs-crdb-certs
CAKEY_VOL=krb5rs-crdb-cakey
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HOST_CERTS="$HERE/certs"
CRDB_HOST="${CRDB_HOST:-127.0.0.1}"
CRDB_PORT="${CRDB_PORT:-26257}"
NODES=(crdb1 crdb2 crdb3)
REGIONS=(california ohio washington-dc)

certs() {
  if "$CLI" volume inspect "$CERTS_VOL" >/dev/null 2>&1; then return; fi
  "$CLI" volume create "$CERTS_VOL" >/dev/null
  "$CLI" volume create "$CAKEY_VOL" >/dev/null
  "$CLI" run --rm -v "$CERTS_VOL:/certs" -v "$CAKEY_VOL:/cakey" --entrypoint /bin/sh "$IMAGE" -c "
    set -e
    cockroach cert create-ca --certs-dir=/certs --ca-key=/cakey/ca.key
    cockroach cert create-node localhost 127.0.0.1 $CRDB_HOST crdb1 crdb2 crdb3 \
      --certs-dir=/certs --ca-key=/cakey/ca.key
    for u in root kdc_admin kdc_replica; do
      cockroach cert create-client \$u --certs-dir=/certs --ca-key=/cakey/ca.key
    done
    chmod 0644 /certs/*.crt
  "
  rm -rf "$HOST_CERTS"
  mkdir -p "$HOST_CERTS"
  local tmp
  tmp=$("$CLI" create -v "$CERTS_VOL:/certs" --entrypoint /bin/true "$IMAGE")
  "$CLI" cp "$tmp:/certs/." "$(cygpath -m "$HOST_CERTS" 2>/dev/null || echo "$HOST_CERTS")/"
  "$CLI" rm "$tmp" >/dev/null
  rm -f "$HOST_CERTS/node.key" "$HOST_CERTS/node.crt"
}

up() {
  certs
  "$CLI" network inspect "$NET" >/dev/null 2>&1 || "$CLI" network create "$NET" >/dev/null
  for i in 0 1 2; do
    n=${NODES[$i]}
    if "$CLI" container inspect "$n" >/dev/null 2>&1; then "$CLI" start "$n" >/dev/null || true; continue; fi
    "$CLI" run -d --name "$n" --hostname "$n" --network "$NET" \
      -p "$((CRDB_PORT + i)):26257" \
      -v "$CERTS_VOL:/certs:ro" \
      "$IMAGE" start \
      --certs-dir=/certs --listen-addr=0.0.0.0:26257 --advertise-addr="$n:26257" \
      --http-addr=0.0.0.0:8080 \
      --join=crdb1:26257,crdb2:26257,crdb3:26257 \
      --locality="region=${REGIONS[$i]}" --cache=256MiB --max-sql-memory=256MiB >/dev/null
  done
  sleep 3
  "$CLI" exec crdb1 ./cockroach init --certs-dir=/certs --host=crdb1:26257 2>&1 | grep -v "already been initialized" || true
  for _ in $(seq 1 60); do
    if "$CLI" exec crdb1 ./cockroach sql --certs-dir=/certs --host=crdb1:26257 -e 'SELECT 1' >/dev/null 2>&1; then break; fi
    sleep 1
  done
  sql "CREATE USER IF NOT EXISTS kdc_admin; CREATE USER IF NOT EXISTS kdc_replica;" >/dev/null
  echo "CockroachDB is up: $CRDB_HOST:$CRDB_PORT (nodes on +0, +1, +2); client certs in $HOST_CERTS"
}

sql() {
  "$CLI" exec crdb1 ./cockroach sql --certs-dir=/certs --host=crdb1:26257 -e "$1"
}

down() {
  for n in "${NODES[@]}"; do "$CLI" rm -f "$n" >/dev/null 2>&1 || true; done
}

case "${1:-}" in
  up) up ;;
  down) down ;;
  nuke)
    down
    "$CLI" network rm "$NET" >/dev/null 2>&1 || true
    "$CLI" volume rm "$CERTS_VOL" "$CAKEY_VOL" >/dev/null 2>&1 || true
    rm -rf "$HOST_CERTS" ;;
  status) "$CLI" ps -a --filter name=crdb --format '{{.Names}} {{.Status}} {{.Ports}}'
          sql "SELECT node_id, address, locality FROM crdb_internal.gossip_nodes" ;;
  sql) sql "${2:?usage: cluster.sh sql 'SQL'}" ;;
  *) sed -n 2,19p "$0"; exit 2 ;;
esac
