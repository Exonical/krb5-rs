#!/usr/bin/env bash
# End-to-end check of the chart on a throwaway cluster (k3d in CI, k3s in
# podman locally): install, add a principal, log in with MIT kinit through the
# kdc Service, lose the primary, and confirm replicas keep serving and pick up
# later changes.
#
# Required: a kubectl context for the cluster, the KDC image and the MIT test
# image already loaded into it. Overridable via the environment:
#   HELM (default: helm)   CHART (default: deploy/helm/krb5-rs-kdc)
#   REL, KDC_IMAGE_REPO, KDC_IMAGE_TAG, MIT_IMAGE
set -euo pipefail

REL=${REL:-kdc}
HELM=${HELM:-helm}
CHART=${CHART:-deploy/helm/krb5-rs-kdc}
KDC_IMAGE_REPO=${KDC_IMAGE_REPO:-localhost/krb5-rs-kdc}
KDC_IMAGE_TAG=${KDC_IMAGE_TAG:-e2e}
MIT_IMAGE=${MIT_IMAGE:-docker.io/library/krb5-rs-mit-test:1.22.2}
REALM=E2E.TEST
FULL=${REL}-krb5-rs-kdc
PRIMARY=${FULL}-primary
KDB="krb5-rs-kdb --config /etc/krb5-rs/kdc.conf --krb5-config /etc/krb5-rs/krb5.conf --realm ${REALM}"

step() { printf '\n=== %s\n' "$*"; }

cleanup() {
  $HELM uninstall "$REL" >/dev/null 2>&1 || true
  kubectl delete pvc -l "app.kubernetes.io/instance=${REL}" --ignore-not-found >/dev/null 2>&1 || true
  kubectl delete secret "$FULL" --ignore-not-found >/dev/null 2>&1 || true
  kubectl delete pod mit-client --ignore-not-found >/dev/null 2>&1 || true
}

diagnostics() {
  echo "--- diagnostics"
  kubectl get pods,svc -o wide || true
  for p in $(kubectl get pods -o name | grep "$FULL" || true); do
    echo "--- logs $p"; kubectl logs "$p" --all-containers --tail=40 || true
  done
}
trap 'rc=$?; if [ $rc -ne 0 ]; then diagnostics; fi; exit $rc' EXIT

addprinc() { # name password
  printf '%s\n' "$2" | kubectl exec -i "statefulset/${PRIMARY}" -c kdc -- ${KDB} addprinc "$1"
}

mit() { # run a shell snippet in the MIT client pod
  kubectl exec mit-client -- bash -c "export KRB5_CONFIG=/tmp/krb5.conf; $1"
}

kinit_ok() { # user password count [conf]
  mit "ok=0; for i in \$(seq 1 $3); do if echo '$2' | KRB5CCNAME=/tmp/cc_\$RANDOM timeout 20 kinit $1@${REALM} >/dev/null 2>&1; then ok=\$((ok+1)); fi; done; echo \$ok" | tail -1
}

step "install"
cleanup
$HELM upgrade --install "$REL" "$CHART" \
  --set realm="$REALM" \
  --set image.repository="$KDC_IMAGE_REPO" --set image.tag="$KDC_IMAGE_TAG" \
  --set image.pullPolicy=Never \
  --set propagation.pollInterval=5s \
  --wait --timeout 5m
kubectl rollout status "statefulset/${PRIMARY}" --timeout=120s
kubectl rollout status "deployment/${FULL}-replicas" --timeout=120s
[ "$(kubectl get pods -l app.kubernetes.io/component=replica --no-headers | grep -c Running)" -eq 2 ]

step "MIT client pod"
kubectl run mit-client --image="$MIT_IMAGE" --image-pull-policy=Never --restart=Never --command -- sleep 3600
kubectl wait --for=condition=Ready pod/mit-client --timeout=120s
kubectl exec mit-client -- bash -c "cat > /tmp/krb5.conf <<EOF
[libdefaults]
 default_realm = ${REALM}
 dns_lookup_kdc = false
[realms]
 ${REALM} = {
  kdc = ${FULL}-kdc:88
 }
EOF"

step "addprinc on the primary, kinit through the kdc Service"
addprinc alice alice-pw
kinit_ready=0
for _ in $(seq 1 30); do
  if [ "$(kinit_ok alice alice-pw 1)" = 1 ]; then
    kinit_ready=1
    break
  fi
  sleep 1
done
[ "$kinit_ready" = 1 ]
echo "kinit through the Service works"

for ip in $(kubectl get pods -l app.kubernetes.io/component=replica -o jsonpath='{.items[*].status.podIP}'); do
  seen=0
  for _ in $(seq 1 30); do
    mit "cat > /tmp/r.conf <<EOF
[libdefaults]
 default_realm = ${REALM}
 dns_lookup_kdc = false
[realms]
 ${REALM} = {
  kdc = ${ip}:8888
 }
EOF
echo alice-pw | KRB5_CONFIG=/tmp/r.conf KRB5CCNAME=/tmp/cca kinit alice@${REALM} >/dev/null 2>&1" && { seen=1; break; }
    sleep 1
  done
  [ "$seen" = 1 ] || { echo "replica $ip never learned alice"; exit 1; }
done

step "primary down: replicas keep serving"
kubectl scale "statefulset/${PRIMARY}" --replicas=0
kubectl wait --for=delete "pod/${PRIMARY}-0" --timeout=120s
ok=$(kinit_ok alice alice-pw 10)
echo "kinit with the primary down: ${ok}/10 succeeded"
[ "$ok" = 10 ]

step "primary back, change propagates to every replica"
kubectl scale "statefulset/${PRIMARY}" --replicas=1
kubectl wait --for=condition=Ready "pod/${PRIMARY}-0" --timeout=180s
addprinc bob bob-pw
for ip in $(kubectl get pods -l app.kubernetes.io/component=replica -o jsonpath='{.items[*].status.podIP}'); do
  seen=0
  for _ in $(seq 1 30); do
    mit "cat > /tmp/r.conf <<EOF
[libdefaults]
 default_realm = ${REALM}
 dns_lookup_kdc = false
[realms]
 ${REALM} = {
  kdc = ${ip}:8888
 }
EOF
echo bob-pw | KRB5_CONFIG=/tmp/r.conf KRB5CCNAME=/tmp/ccb kinit bob@${REALM} >/dev/null 2>&1" && { seen=1; break; }
    sleep 2
  done
  [ "$seen" = 1 ] || { echo "replica $ip never learned bob"; exit 1; }
  echo "replica $ip serves bob"
done

step "primary pod deletion (StatefulSet restart) keeps the database"
kubectl delete pod "${PRIMARY}-0" --wait=true
kubectl wait --for=condition=Ready "pod/${PRIMARY}-0" --timeout=180s
[ "$(kinit_ok bob bob-pw 3)" = 3 ]

step "cleanup"
cleanup
echo "e2e passed"
