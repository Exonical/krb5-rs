#!/usr/bin/env bash
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../../../.." && pwd)"
CLI="${CONTAINER_CLI:-docker}"
KUBECTL="${KUBECTL:-kubectl}"
KUBECONFIG="${KUBECONFIG:-$HOME/.kube/config}"
HELM="${HELM:-helm}"
HELM_IMAGE=docker.io/alpine/helm:3.22.0
CRDB_PINNED_IMAGE=docker.io/cockroachdb/cockroach:v26.3.2@sha256:84f0c929fdd4284b40a0c4afb1f284573fb281abc0323f8329e4e5f1650a3e00
CRDB_IMAGE="${CRDB_IMAGE:-$CRDB_PINNED_IMAGE}"
KDC_IMAGE="${KDC_IMAGE:-localhost/krb5-rs-kdc:e2e-cockroach}"
MIT_IMAGE="${MIT_IMAGE:-docker.io/library/krb5-rs-mit-test:1.22.2}"
REL="${REL:-e2e-cockroach}"
NS="${NAMESPACE:-default}"
REALM=E2E.TEST
FULL="${REL}-krb5-rs-kdc"
MASTER_SECRET="${REL}-master"
REPLICA_TLS_SECRET="${REL}-replica-tls"
ADMIN_TLS_SECRET="${REL}-admin-tls"
MIGRATE_TLS_SECRET="${REL}-migrate-tls"
CERT_DIR="$(mktemp -d)"
CERTS_VOLUME="${REL}-certs"
MANIFEST="$HERE/cockroach-e2e.yaml"

host_path() {
  if command -v cygpath >/dev/null 2>&1; then
    cygpath -m "$1"
  else
    realpath "$1"
  fi
}

if command -v "${HELM%% *}" >/dev/null 2>&1; then
  CHART="${CHART:-$ROOT/deploy/helm/krb5-rs-kdc}"
  HELM_IN_CONTAINER=0
else
  CHART="${CHART:-/workspace/deploy/helm/krb5-rs-kdc}"
  HELM_IN_CONTAINER=1
fi

KUBECONFIG="$(host_path "$KUBECONFIG")"
MANIFEST_HOST_PATH="$(host_path "$MANIFEST")"
export KUBECONFIG MSYS_NO_PATHCONV=1

run_helm() {
  if [ "$HELM_IN_CONTAINER" -eq 1 ]; then
    "$CLI" run --rm --network host \
      -v "$(host_path "$KUBECONFIG"):/root/.kube/config:ro" \
      -v "$(host_path "$ROOT"):/workspace:ro" \
      --workdir /workspace \
      "$HELM_IMAGE" "$@"
  else
    $HELM "$@"
  fi
}

diagnostics() {
  echo "--- CockroachDB E2E diagnostics"
  "$KUBECTL" get pods,svc,jobs -n "$NS" -o wide || true
  "$KUBECTL" get events -n "$NS" --sort-by=.lastTimestamp | tail -40 || true
  for pod in $("$KUBECTL" get pods -n "$NS" -o name | grep -E "$FULL|crdb|mit-client" || true); do
    echo "--- logs $pod"
    "$KUBECTL" logs -n "$NS" "$pod" --all-containers --tail=80 || true
  done
}

cleanup() {
  run_helm uninstall "$REL" --namespace "$NS" >/dev/null 2>&1 || true
  "$KUBECTL" delete jobs,configmaps -n "$NS" \
    -l "app.kubernetes.io/instance=${REL}" --ignore-not-found >/dev/null 2>&1 || true
  "$KUBECTL" delete pod mit-client -n "$NS" --ignore-not-found >/dev/null 2>&1 || true
  "$KUBECTL" delete -f "$MANIFEST_HOST_PATH" -n "$NS" --ignore-not-found >/dev/null 2>&1 || true
  "$KUBECTL" delete pvc -n "$NS" \
    -l "app.kubernetes.io/instance=${REL}" --ignore-not-found >/dev/null 2>&1 || true
  "$KUBECTL" delete pvc -n "$NS" \
    -l krb5-rs-e2e=cockroach --ignore-not-found >/dev/null 2>&1 || true
  "$KUBECTL" delete secret -n "$NS" \
    cockroach-node-certs "$MASTER_SECRET" "$REPLICA_TLS_SECRET" \
    "$ADMIN_TLS_SECRET" "$MIGRATE_TLS_SECRET" --ignore-not-found >/dev/null 2>&1 || true
  "$CLI" volume rm "$CERTS_VOLUME" >/dev/null 2>&1 || true
  rm -rf "$CERT_DIR"
}

on_exit() {
  result=$?
  if [ "$result" -ne 0 ]; then
    diagnostics
  fi
  cleanup
  exit "$result"
}
trap on_exit EXIT

cleanup
mkdir -p "$CERT_DIR"

step() { printf '\n=== %s\n' "$*"; }

step "generate CockroachDB certificates"
"$CLI" pull "$CRDB_PINNED_IMAGE"
"$CLI" volume create "$CERTS_VOLUME" >/dev/null
"$CLI" run --rm -v "$CERTS_VOLUME:/certs" \
  --entrypoint /bin/sh "$CRDB_PINNED_IMAGE" -c '
    set -e
    umask 077
    /cockroach/cockroach cert create-ca --certs-dir=/certs --ca-key=/certs/ca.key
    /cockroach/cockroach cert create-node \
      crdb-0.crdb crdb crdb-public \
      crdb-0.crdb.default.svc.cluster.local \
      crdb.default.svc.cluster.local \
      crdb-public.default.svc.cluster.local \
      localhost 127.0.0.1 \
      --certs-dir=/certs --ca-key=/certs/ca.key
    for user in root kdc_admin kdc_replica; do
      /cockroach/cockroach cert create-client "$user" \
        --certs-dir=/certs --ca-key=/certs/ca.key
    done
    chmod 0644 /certs/*.crt
    chmod 0600 /certs/*.key
  '
"$CLI" run --rm -v "$CERTS_VOLUME:/certs:ro" \
  -v "$(host_path "$CERT_DIR"):/out" \
  --entrypoint /bin/sh "$CRDB_PINNED_IMAGE" -c 'cp /certs/* /out/'

step "create CockroachDB and client TLS Secrets"
"$KUBECTL" delete secret -n "$NS" cockroach-node-certs "$MASTER_SECRET" \
  "$REPLICA_TLS_SECRET" "$ADMIN_TLS_SECRET" "$MIGRATE_TLS_SECRET" \
  --ignore-not-found >/dev/null
"$KUBECTL" create secret generic cockroach-node-certs -n "$NS" \
  --from-file=ca.crt="$(host_path "$CERT_DIR/ca.crt")" \
  --from-file=node.crt="$(host_path "$CERT_DIR/node.crt")" \
  --from-file=node.key="$(host_path "$CERT_DIR/node.key")" \
  --from-file=client.root.crt="$(host_path "$CERT_DIR/client.root.crt")" \
  --from-file=client.root.key="$(host_path "$CERT_DIR/client.root.key")"
make_client_secret() {
  secret=$1
  user=$2
  "$KUBECTL" create secret generic "$secret" -n "$NS" \
    --from-file=ca.crt="$(host_path "$CERT_DIR/ca.crt")" \
    --from-file=tls.crt="$(host_path "$CERT_DIR/client.${user}.crt")" \
    --from-file=tls.key="$(host_path "$CERT_DIR/client.${user}.key")"
}
make_client_secret "$REPLICA_TLS_SECRET" kdc_replica
make_client_secret "$ADMIN_TLS_SECRET" kdc_admin
make_client_secret "$MIGRATE_TLS_SECRET" root
head -c 32 /dev/urandom | base64 | tr -d '\n' > "$CERT_DIR/master-password"
"$KUBECTL" create secret generic "$MASTER_SECRET" -n "$NS" \
  --from-file=master-password="$(host_path "$CERT_DIR/master-password")"

if [ -n "${K3S_PODMAN_CONTAINER:-}" ]; then
  import_image() {
    local image=$1
    local archive="$CERT_DIR/image.tar"
    local archive_host
    archive_host="$(host_path "$archive")"
    "$CLI" save -o "$archive_host" "$image"
    "$CLI" cp "$archive_host" "$K3S_PODMAN_CONTAINER:/tmp/krb5-e2e-image.tar"
    "$CLI" exec "$K3S_PODMAN_CONTAINER" ctr images import /tmp/krb5-e2e-image.tar
    "$CLI" exec "$K3S_PODMAN_CONTAINER" rm -f /tmp/krb5-e2e-image.tar
    rm -f "$archive"
  }
  import_image "$KDC_IMAGE"
  import_image "$MIT_IMAGE"
  import_image "$CRDB_PINNED_IMAGE"
fi

step "start the single-node CockroachDB"
"$KUBECTL" apply -n "$NS" -f "$MANIFEST_HOST_PATH"
"$KUBECTL" rollout status statefulset/crdb -n "$NS" --timeout=180s
"$KUBECTL" exec -n "$NS" crdb-0 -- /cockroach/cockroach sql \
  --certs-dir=/cockroach/certs --host=crdb-0.crdb:26257 \
  -e 'CREATE DATABASE IF NOT EXISTS krb5'

step "start MIT client"
"$KUBECTL" run mit-client -n "$NS" --image="$MIT_IMAGE" \
  --image-pull-policy=Never --restart=Never --command -- sleep 3600
"$KUBECTL" wait --for=condition=Ready pod/mit-client -n "$NS" --timeout=120s

step "install CockroachDB-backed KDCs"
run_helm upgrade --install "$REL" "$CHART" --namespace "$NS" \
  --set-string realm="$REALM" \
  --set database.mode=cockroach \
  --set-string image.repository="${KDC_IMAGE%:*}" \
  --set-string image.tag="${KDC_IMAGE##*:}" \
  --set image.pullPolicy=Never \
  --set service.type=ClusterIP \
  --set-string secrets.existingSecret="$MASTER_SECRET" \
  --set-string cockroach.url="postgresql://kdc_replica@crdb-public:26257/krb5?sslmode=verify-full" \
  --set-string cockroach.tlsSecret="$REPLICA_TLS_SECRET" \
  --set-string cockroach.region=e2e \
  --set-string cockroach.admin.url="postgresql://kdc_admin@crdb-public:26257/krb5?sslmode=verify-full" \
  --set-string cockroach.admin.tlsSecret="$ADMIN_TLS_SECRET" \
  --set-string cockroach.bootstrap.migrateUrl="postgresql://root@crdb-public:26257/krb5?sslmode=verify-full" \
  --set-string cockroach.bootstrap.migrateTlsSecret="$MIGRATE_TLS_SECRET" \
  --set cockroach.bootstrap.enabled=true \
  --set cockroach.bootstrap.multiRegion.enabled=false \
  --set cockroach.prune.enabled=false \
  --set kdcs.replicaCount=2 \
  --set-string cockroach.maxStaleness=10s \
  --set-string cockroach.replication.pollInterval=1s \
  --wait --timeout=15m
"$KUBECTL" wait --for=condition=complete "job/${FULL}-bootstrap" -n "$NS" --timeout=900s
"$KUBECTL" rollout status "statefulset/${FULL}-kdc" -n "$NS" --timeout=900s
for ordinal in 0 1; do
  "$KUBECTL" wait --for=condition=Ready "pod/${FULL}-kdc-${ordinal}" -n "$NS" --timeout=900s
done

mit() {
  "$KUBECTL" exec -n "$NS" mit-client -- bash -c "$1"
}

write_krb5_conf() {
  kdc=$1
  mit "cat > /tmp/krb5.conf <<'EOF'
[libdefaults]
 default_realm = ${REALM}
 dns_lookup_kdc = false
 dns_lookup_realm = false
[realms]
 ${REALM} = {
  kdc = ${kdc}
 }
EOF"
}

kinit_alice() {
  printf 'alice-password\n' | "$KUBECTL" exec -i -n "$NS" mit-client -- \
    bash -c 'KRB5_CONFIG=/tmp/krb5.conf KRB5CCNAME=FILE:/tmp/cc_$RANDOM timeout 20 kinit alice@E2E.TEST'
}

admin_run() {
  local pod="${FULL}-kdb"
  local overrides
  overrides=$(cat <<EOF
{"apiVersion":"v1","spec":{"securityContext":{"runAsNonRoot":true,"runAsUser":65532,"runAsGroup":65532,"fsGroup":65532,"seccompProfile":{"type":"RuntimeDefault"}},"containers":[{"name":"${pod}","image":"${KDC_IMAGE}","imagePullPolicy":"Never","securityContext":{"allowPrivilegeEscalation":false,"readOnlyRootFilesystem":true,"capabilities":{"drop":["ALL"]}},"volumeMounts":[{"name":"config","mountPath":"/etc/krb5-rs","readOnly":true},{"name":"secrets","mountPath":"/secrets","readOnly":true},{"name":"cockroach-admin","mountPath":"/crdb-admin","readOnly":true},{"name":"tmp","mountPath":"/tmp"}]}],"volumes":[{"name":"config","configMap":{"name":"${FULL}"}},{"name":"secrets","secret":{"secretName":"${MASTER_SECRET}","defaultMode":288}},{"name":"cockroach-admin","secret":{"secretName":"${ADMIN_TLS_SECRET}","defaultMode":288}},{"name":"tmp","emptyDir":{}}]}}
EOF
  )
  "$KUBECTL" run "$pod" -n "$NS" --rm -i --attach --restart=Never \
    --image="$KDC_IMAGE" --image-pull-policy=Never --overrides="$overrides" \
    --override-type=strategic \
    --command -- krb5-rs-kdb \
    --config /etc/krb5-rs/admin-kdc.conf \
    --krb5-config /etc/krb5-rs/krb5.conf \
    --realm "$REALM" --master-password-file /secrets/master-password "$@"
}

step "bootstrap, administer, and authenticate"
"$KUBECTL" wait --for=condition=complete "job/${FULL}-bootstrap" -n "$NS" --timeout=900s
printf 'alice-password\n' | admin_run addprinc alice
write_krb5_conf "${FULL}-kdc.${NS}.svc:88"
service_seen=0
for _ in $(seq 1 30); do
  if kinit_alice >/dev/null 2>&1; then
    service_seen=1
    break
  fi
  sleep 1
done
[ "$service_seen" = 1 ] || { echo "KDC Service did not serve alice within 30 seconds"; exit 1; }

for ordinal in 0 1; do
  pod="${FULL}-kdc-${ordinal}"
  ip=$("$KUBECTL" get pod "$pod" -n "$NS" -o jsonpath='{.status.podIP}')
  write_krb5_conf "${ip}:8888"
  seen=0
  for _ in $(seq 1 30); do
    if kinit_alice >/dev/null 2>&1; then
      seen=1
      break
    fi
    sleep 1
  done
  [ "$seen" = 1 ] || { echo "KDC pod $pod did not replicate alice within 30 seconds"; exit 1; }
  echo "$pod serves alice from its local replica"
done

step "replica status lists each regional KDC id"
status_file="$CERT_DIR/replication-status"
admin_run replication status > "$status_file"
status=$(cat "$status_file")
printf '%s\n' "$status"
for ordinal in 0 1; do
  pod="${FULL}-kdc-${ordinal}"
  grep -F "e2e-${pod}" <<<"$status" >/dev/null || {
    echo "replication status does not list e2e-${pod}"
    echo "$status"
    exit 1
  }
done

step "restart one KDC pod and verify checkpoint reuse"
pod="${FULL}-kdc-0"
"$KUBECTL" delete pod "$pod" -n "$NS" --wait=true
"$KUBECTL" wait --for=condition=Ready "pod/${pod}" -n "$NS" --timeout=180s
ip=$("$KUBECTL" get pod "$pod" -n "$NS" -o jsonpath='{.status.podIP}')
write_krb5_conf "${ip}:8888"
kinit_alice
metrics=$("$KUBECTL" get --raw "/api/v1/namespaces/${NS}/pods/${pod}:9100/proxy/metrics")
rebuilds=$(awk '$1 ~ /^krb5_replication_rebuilds_total(_total)?$/ { print $2; exit }' <<<"$metrics")
[ "$rebuilds" = "0" ] || {
  grep -E 'rebuild|snapshot' <<<"$metrics" || true
  echo "expected no snapshot/rebuild after checkpoint restart; saw ${rebuilds:-missing}"
  exit 1
}

step "partition CockroachDB and require fail-closed readiness"
"$KUBECTL" scale statefulset/crdb -n "$NS" --replicas=0
"$KUBECTL" wait --for=delete pod/crdb-0 -n "$NS" --timeout=120s
not_ready=0
for _ in $(seq 1 60); do
  all_not_ready=1
  for ordinal in 0 1; do
    pod="${FULL}-kdc-${ordinal}"
    ready=$("$KUBECTL" get pod "$pod" -n "$NS" \
      -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}')
    [ "$ready" = "True" ] && all_not_ready=0
  done
  if [ "$all_not_ready" = 1 ]; then
    not_ready=1
    break
  fi
  sleep 1
done
[ "$not_ready" = 1 ] || { echo "KDC pods stayed Ready with CockroachDB unavailable"; exit 1; }
write_krb5_conf "${FULL}-kdc.${NS}.svc:88"
if kinit_alice >/dev/null 2>&1; then
  echo "kinit unexpectedly succeeded while CockroachDB was unavailable"
  exit 1
fi

step "restore CockroachDB and verify KDC recovery"
"$KUBECTL" scale statefulset/crdb -n "$NS" --replicas=1
"$KUBECTL" rollout status statefulset/crdb -n "$NS" --timeout=180s
for ordinal in 0 1; do
  "$KUBECTL" wait --for=condition=Ready "pod/${FULL}-kdc-${ordinal}" -n "$NS" --timeout=180s
done
kinit_alice
echo "CockroachDB chart E2E passed"
