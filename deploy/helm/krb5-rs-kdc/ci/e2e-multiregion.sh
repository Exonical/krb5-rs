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
KDC_IMAGE="${KDC_IMAGE:-localhost/krb5-rs-kdc:e2e-cockroach}"
MIT_IMAGE="${MIT_IMAGE:-docker.io/library/krb5-rs-mit-test:1.22.2}"
NS="${NAMESPACE:-default}"
REALM=E2E.TEST
REL_CA=krb5-ca
REL_OH=krb5-oh
REL_DC=krb5-dc
FULL_CA="${REL_CA}-krb5-rs-kdc"
FULL_OH="${REL_OH}-krb5-rs-kdc"
FULL_DC="${REL_DC}-krb5-rs-kdc"
FULL="$FULL_CA"
MASTER_SECRET=e2e-multiregion-master
REPLICA_TLS_SECRET=e2e-multiregion-replica-tls
ADMIN_TLS_SECRET=e2e-multiregion-admin-tls
MIGRATE_TLS_SECRET=e2e-multiregion-migrate-tls
CERT_DIR="$(mktemp -d)"
CERTS_VOLUME=e2e-multiregion-certs
CERTS_CONTAINER=""
MANIFEST="$HERE/cockroach-multiregion-e2e.yaml"
MULTI_REGION_CERTS=1

export MSYS_NO_PATHCONV=1

if command -v "${HELM%% *}" >/dev/null 2>&1; then
  CHART="${CHART:-$ROOT/deploy/helm/krb5-rs-kdc}"
  HELM_IN_CONTAINER=0
else
  CHART="${CHART:-/workspace/deploy/helm/krb5-rs-kdc}"
  HELM_IN_CONTAINER=1
fi

source "$HERE/e2e-lib.sh"

diagnostics() {
  echo "--- Multi-region CockroachDB E2E diagnostics"
  "$KUBECTL" get pods,svc,jobs,networkpolicies -n "$NS" -o wide || true
  "$KUBECTL" get events -n "$NS" --sort-by=.lastTimestamp | tail -50 || true
  for pod in $("$KUBECTL" get pods -n "$NS" -o name | grep -E 'krb5-(ca|oh|dc)|crdb|mit-client' || true); do
    echo "--- logs $pod"
    "$KUBECTL" logs -n "$NS" "$pod" --all-containers --tail=100 || true
  done
}

cleanup() {
  for release in "$REL_DC" "$REL_OH" "$REL_CA"; do
    run_helm uninstall "$release" --namespace "$NS" >/dev/null 2>&1 || true
    "$KUBECTL" delete jobs,configmaps -n "$NS" \
      -l "app.kubernetes.io/instance=${release}" --ignore-not-found >/dev/null 2>&1 || true
  done
  "$KUBECTL" delete networkpolicy e2e-ohio-egress -n "$NS" \
    --ignore-not-found >/dev/null 2>&1 || true
  "$KUBECTL" delete pod mit-client -n "$NS" \
    --ignore-not-found >/dev/null 2>&1 || true
  "$KUBECTL" delete -f "$MANIFEST_HOST_PATH" -n "$NS" \
    --ignore-not-found >/dev/null 2>&1 || true
  "$KUBECTL" delete pvc -n "$NS" \
    -l krb5-rs-e2e=cockroach-multi --ignore-not-found >/dev/null 2>&1 || true
  "$KUBECTL" delete pvc -n "$NS" \
    "data-${FULL_CA}-kdc-0" "data-${FULL_OH}-kdc-0" "data-${FULL_DC}-kdc-0" \
    --ignore-not-found >/dev/null 2>&1 || true
  "$KUBECTL" delete secret -n "$NS" \
    cockroach-node-certs "$MASTER_SECRET" "$REPLICA_TLS_SECRET" \
    "$ADMIN_TLS_SECRET" "$MIGRATE_TLS_SECRET" --ignore-not-found >/dev/null 2>&1 || true
  cleanup_cert_artifacts
}

on_exit() {
  result=$?
  if [ "$result" -ne 0 ]; then
    diagnostics
  fi
  cleanup
  exit "$result"
}

KUBECONFIG="$(host_path "$KUBECONFIG")"
MANIFEST_HOST_PATH="$(host_path "$MANIFEST")"
export KUBECONFIG
trap on_exit EXIT
cleanup
mkdir -p "$CERT_DIR"
chmod 0700 "$CERT_DIR"

step() { printf '\n=== %s\n' "$*"; }

step "generate multi-region CockroachDB certificates"
generate_certificates

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
make_client_secret "$REPLICA_TLS_SECRET" kdc_replica
make_client_secret "$ADMIN_TLS_SECRET" kdc_admin
make_client_secret "$MIGRATE_TLS_SECRET" root
head -c 32 /dev/urandom | base64 | tr -d '\n' > "$CERT_DIR/master-password"
"$KUBECTL" create secret generic "$MASTER_SECRET" -n "$NS" \
  --from-file=master-password="$(host_path "$CERT_DIR/master-password")"

if [ -n "${K3S_PODMAN_CONTAINER:-}" ]; then
  import_image "$KDC_IMAGE"
  import_image "$MIT_IMAGE"
  import_image "$CRDB_PINNED_IMAGE"
fi

step "start the three region-tagged CockroachDB nodes"
"$KUBECTL" apply -n "$NS" -f "$MANIFEST_HOST_PATH"
for ordinal in 0 1 2; do
  "$KUBECTL" wait --for=jsonpath='{.status.phase}'=Running \
    "pod/crdb-${ordinal}" -n "$NS" --timeout=180s
done
sleep 5
"$KUBECTL" exec -n "$NS" crdb-0 -- /cockroach/cockroach init \
  --certs-dir=/cockroach/certs --host=crdb-0.crdb:26257
for ordinal in 0 1 2; do
  "$KUBECTL" wait --for=condition=Ready "pod/crdb-${ordinal}" \
    -n "$NS" --timeout=180s
done
"$KUBECTL" exec -n "$NS" crdb-0 -- /cockroach/cockroach sql \
  --certs-dir=/cockroach/certs --host=crdb-0.crdb:26257 \
  -e 'CREATE DATABASE IF NOT EXISTS krb5'

crdb_sql() {
  "$KUBECTL" exec -n "$NS" crdb-0 -- /cockroach/cockroach sql \
    --certs-dir=/cockroach/certs --host=crdb-0.crdb:26257 \
    --format=tsv "$@"
}

step "start MIT client"
"$KUBECTL" run mit-client -n "$NS" --image="$MIT_IMAGE" \
  --image-pull-policy=Never --restart=Never --command -- sleep 3600
"$KUBECTL" wait --for=condition=Ready pod/mit-client -n "$NS" --timeout=120s

install_region() {
  local release=$1
  local region=$2
  local values=$3
  local values_file="$CHART/examples/multi-region/values-${values}.yaml"
  local replica_url="postgresql://kdc_replica@crdb-${region}:26257/krb5?sslmode=verify-full"
  local admin_url="postgresql://kdc_admin@crdb-${region}:26257/krb5?sslmode=verify-full"
  local args=(
    upgrade --install "$release" "$CHART" --namespace "$NS"
    -f "$values_file"
    --set-string "realm=$REALM"
    --set database.mode=cockroach
    --set-string "image.repository=${KDC_IMAGE%:*}"
    --set-string "image.tag=${KDC_IMAGE##*:}"
    --set image.pullPolicy=Never
    --set service.type=ClusterIP
    --set-string "secrets.existingSecret=$MASTER_SECRET"
    --set-string "cockroach.url=$replica_url"
    --set-string "cockroach.tlsSecret=$REPLICA_TLS_SECRET"
    --set-string "cockroach.region=$region"
    --set-string "cockroach.admin.url=$admin_url"
    --set-string "cockroach.admin.tlsSecret=$ADMIN_TLS_SECRET"
    --set kdcs.replicaCount=1
    --set-string cockroach.poolIdleTimeout=1s
    --set-string cockroach.maxStaleness=10s
    --set-string cockroach.replication.pollInterval=1s
    --set cockroach.prune.enabled=false
  )
  if [ "$region" = california ]; then
    args+=(
      --set-string "cockroach.bootstrap.migrateUrl=postgresql://root@crdb-california:26257/krb5?sslmode=verify-full"
      --set-string "cockroach.bootstrap.migrateTlsSecret=$MIGRATE_TLS_SECRET"
      --set cockroach.bootstrap.enabled=true
      --set cockroach.bootstrap.multiRegion.enabled=true
      --set-string cockroach.bootstrap.multiRegion.primaryRegion=california
      --set 'cockroach.bootstrap.multiRegion.regions={california,ohio,washington-dc}'
    )
  fi
  run_helm "${args[@]}" --wait --timeout=15m
}

step "install California first, then Ohio and Washington DC"
install_region "$REL_CA" california california
step "verify database regions and table localities"
regions=$(crdb_sql -e "SHOW REGIONS FROM DATABASE krb5")
printf '%s\n' "$regions"
for region in california ohio washington-dc; do
  grep -F "$region" <<<"$regions" >/dev/null || {
    echo "SHOW REGIONS did not list $region"
    exit 1
  }
done
primary_region=$(
  crdb_sql -e 'SELECT region FROM [SHOW REGIONS FROM DATABASE krb5] WHERE "primary"' |
    tail -1 | tr -d '\r'
)
[ "$primary_region" = california ] || {
  echo "expected california as primary region, saw $primary_region"
  exit 1
}
for table in principals principal_keys policies lockouts replication_log replication_meta; do
  ddl=$(crdb_sql -e "SHOW CREATE TABLE krb5.public.${table}")
  grep -q 'LOCALITY GLOBAL' <<<"$ddl" || {
    echo "expected krb5.${table} to be LOCALITY GLOBAL"
    echo "$ddl"
    exit 1
  }
done
status_ddl=$(crdb_sql -e 'SHOW CREATE TABLE krb5.public.replica_status')
grep -q 'LOCALITY REGIONAL BY ROW' <<<"$status_ddl" || {
  echo "expected krb5.replica_status to be REGIONAL BY ROW"
  echo "$status_ddl"
  exit 1
}
for release_region in "$REL_OH:ohio:ohio" "$REL_DC:washington-dc:washington-dc"; do
  IFS=: read -r release region values <<<"$release_region"
  install_region "$release" "$region" "$values"
done
for pod in "${FULL_CA}-kdc-0" "${FULL_OH}-kdc-0" "${FULL_DC}-kdc-0"; do
  "$KUBECTL" wait --for=condition=Ready "pod/${pod}" -n "$NS" --timeout=900s
done

step "add alice and authenticate through each region"
FULL="$FULL_CA"
printf 'alice-password\n' | admin_run addprinc alice
wait_kinit_user() {
  local user=$1
  local password=$2
  local full=$3
  local deadline=$4
  write_krb5_conf "${full}-kdc.${NS}.svc:88"
  for _ in $(seq 1 "$deadline"); do
    if kinit_user "$user" "$password" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  echo "$full did not serve $user within ${deadline} seconds"
  return 1
}
for full in "$FULL_CA" "$FULL_OH" "$FULL_DC"; do
  wait_kinit_user alice alice-password "$full" 30
  echo "$full serves alice from its local Turso replica"
done

step "verify unique region-prefixed KDC ids and localities"
status=$(crdb_sql -e 'SELECT kdc_id, region, crdb_region FROM krb5.replica_status ORDER BY region')
for _ in $(seq 1 30); do
  row_count=$(printf '%s\n' "$status" | awk 'NR > 1 && NF { count++ } END { print count + 0 }')
  [ "$row_count" -ge 3 ] && break
  sleep 1
  status=$(crdb_sql -e 'SELECT kdc_id, region, crdb_region FROM krb5.replica_status ORDER BY region')
done
printf '%s\n' "$status"
for region in california ohio washington-dc; do
  row=$(printf '%s\n' "$status" | awk -F '\t' -v region="$region" 'NR > 1 && $2 == region { print; exit }')
  [ -n "$row" ] || { echo "replica_status is missing region $region"; exit 1; }
  IFS=$'\t' read -r kdc_id row_region crdb_region <<<"$row"
  [[ "$kdc_id" == "$region-"* ]] || { echo "unexpected KDC id: $kdc_id"; exit 1; }
  [ "$crdb_region" = "$region" ] || {
    echo "KDC $kdc_id reports CockroachDB region $crdb_region instead of $region"
    exit 1
  }
done

step "partition Ohio and require only Ohio to fail closed"
cat > "$CERT_DIR/deny-ohio-egress.yaml" <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: e2e-ohio-egress
  namespace: ${NS}
spec:
  podSelector:
    matchLabels:
      app.kubernetes.io/instance: ${REL_OH}
      app.kubernetes.io/component: kdc
  policyTypes: [Egress]
  egress: []
EOF
"$KUBECTL" apply -f "$(host_path "$CERT_DIR/deny-ohio-egress.yaml")"
ohio_pod="${FULL_OH}-kdc-0"
ohio_not_ready=0
for _ in $(seq 1 60); do
  ready=$("$KUBECTL" get pod "$ohio_pod" -n "$NS" \
    -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}')
  if [ "$ready" != True ]; then
    ohio_not_ready=1
    break
  fi
  sleep 1
done
[ "$ohio_not_ready" = 1 ] || { echo "Ohio KDC remained Ready during its egress partition"; exit 1; }
write_krb5_conf "${FULL_OH}-kdc.${NS}.svc:88"
if kinit_user alice alice-password >/dev/null 2>&1; then
  echo "kinit unexpectedly succeeded through Ohio while partitioned"
  exit 1
fi
for full in "$FULL_CA" "$FULL_DC"; do
  wait_kinit_user alice alice-password "$full" 30
done
FULL="$FULL_CA"
printf 'bob-password\n' | admin_run addprinc bob
for full in "$FULL_CA" "$FULL_DC"; do
  write_krb5_conf "${full}-kdc.${NS}.svc:88"
  served=0
  for _ in $(seq 1 30); do
    if kinit_user bob bob-password >/dev/null 2>&1; then
      served=1
      break
    fi
    sleep 1
  done
  [ "$served" = 1 ] || { echo "$full did not serve bob within 30 seconds"; exit 1; }
done

step "heal Ohio and verify it catches up"
"$KUBECTL" delete networkpolicy e2e-ohio-egress -n "$NS"
"$KUBECTL" wait --for=condition=Ready "pod/${ohio_pod}" -n "$NS" --timeout=120s
write_krb5_conf "${FULL_OH}-kdc.${NS}.svc:88"
served=0
for _ in $(seq 1 30); do
  if kinit_user bob bob-password >/dev/null 2>&1; then
    served=1
    break
  fi
  sleep 1
done
[ "$served" = 1 ] || { echo "Ohio did not serve bob after healing"; exit 1; }
echo "multi-region CockroachDB chart E2E passed"
