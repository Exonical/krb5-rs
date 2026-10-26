#!/usr/bin/env bash
# End-to-end check of the chart on a throwaway cluster (k3d in CI, k3s in
# podman locally): install, add a principal, log in with MIT kinit through the
# kdc Service, lose the primary, confirm replicas keep serving and pick up
# later changes, and administer the realm with MIT kadmin and kpasswd through
# the kadmin Service.
#
# Required: a kubectl context for the cluster, the KDC image and the MIT test
# image already loaded into it. Overridable via the environment:
#   HELM (default: helm)   CHART (default: deploy/helm/krb5-rs-kdc)
#   REL, KDC_IMAGE_REPO, KDC_IMAGE_TAG, MIT_IMAGE
#   E2E_IPROP=1 enables propagation.iprop (MIT incremental propagation)
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
IPROP_SET=()
if [ "${E2E_IPROP:-}" = 1 ]; then
  IPROP_SET=(--set propagation.iprop.enabled=true --set propagation.iprop.pollInterval=2s)
fi

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

replicas_serve() { # user password: every replica KDC issues the user a TGT
  local ip seen
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
echo '$2' | KRB5_CONFIG=/tmp/r.conf KRB5CCNAME=/tmp/cc_r kinit $1@${REALM} >/dev/null 2>&1" && { seen=1; break; }
      sleep 2
    done
    [ "$seen" = 1 ] || { echo "replica $ip never learned $1"; exit 1; }
    echo "replica $ip serves $1"
  done
}

kadm() { # principal password query
  mit "KRB5CCNAME=/tmp/cc_kadm timeout 30 kadmin -p $1 -w '$2' -q \"$3\" 2>&1"
}

step "install"
cleanup
$HELM upgrade --install "$REL" "$CHART" \
  --set realm="$REALM" \
  --set image.repository="$KDC_IMAGE_REPO" --set image.tag="$KDC_IMAGE_TAG" \
  --set image.pullPolicy=Never \
  --set propagation.interval=5 \
  --set kadmin.enabled=true --set "kadmin.acl[0]=admin/admin@${REALM} *" \
  "${IPROP_SET[@]}" \
  --wait --timeout 5m
kubectl rollout status "statefulset/${PRIMARY}" --timeout=120s
kubectl rollout status "statefulset/${FULL}-replicas" --timeout=120s
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
  admin_server = ${FULL}-kadmin:749
  kpasswd_server = ${FULL}-kadmin:464
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

replicas_serve alice alice-pw

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
replicas_serve bob bob-pw

step "MIT kadmin through the kadmin Service"
addprinc admin/admin admin-pw
# kadmin gets its kadmin/admin ticket through the kdc Service, which also
# routes to replicas; wait until every replica has the new principal.
replicas_serve admin/admin admin-pw
ready=0
for _ in $(seq 1 30); do
  if kadm admin/admin admin-pw "getprinc kadmin/admin" | grep -q "Principal: kadmin/admin@${REALM}"; then
    ready=1
    break
  fi
  sleep 2
done
[ "$ready" = 1 ] || { kadm admin/admin admin-pw "getprinc kadmin/admin"; exit 1; }
out=$(kadm admin/admin admin-pw "addprinc -pw carol-pw +requires_preauth carol")
echo "$out"
grep -q "Principal \"carol@${REALM}\" created." <<<"$out"
out=$(kadm admin/admin admin-pw "getprinc carol")
grep -q "Principal: carol@${REALM}" <<<"$out"
grep -q "Attributes: REQUIRES_PRE_AUTH" <<<"$out"
kadm admin/admin admin-pw "listprincs" | grep -qx "carol@${REALM}"
out=$(kadm alice alice-pw "addprinc -pw dave-pw dave")
echo "$out"
grep -q "Operation requires \`\`add'' privilege" <<<"$out"
replicas_serve carol carol-pw

step "MIT kpasswd through the kadmin Service"
out=$(mit "printf 'carol-pw\ncarol-new-pw\ncarol-new-pw\n' | KRB5CCNAME=/tmp/cc_kpw timeout 30 kpasswd carol@${REALM} 2>&1")
echo "$out"
grep -q "Password changed." <<<"$out"
replicas_serve carol carol-new-pw

if [ "${E2E_IPROP:-}" = 1 ]; then
  step "iprop: every replica reaches the primary's update log serial"
  serial() { # pod container
    kubectl exec "$1" -c "$2" -- krb5-rs-kproplog -h |
      awk '/Last serial #/ {print $NF}'
  }
  want=$(serial "${PRIMARY}-0" kadmind)
  for pod in $(kubectl get pods -l app.kubernetes.io/component=replica -o name); do
    got=
    for _ in $(seq 1 30); do
      got=$(serial "${pod#pod/}" kpropd) && [ "$got" = "$want" ] && break
      sleep 2
    done
    [ "$got" = "$want" ] || { echo "${pod}: serial ${got}, primary ${want}"; exit 1; }
    echo "${pod} at serial ${want}"
  done
fi

step "primary pod deletion (StatefulSet restart) keeps the database"
kubectl delete pod "${PRIMARY}-0" --wait=true
kubectl wait --for=condition=Ready "pod/${PRIMARY}-0" --timeout=180s
[ "$(kinit_ok bob bob-pw 3)" = 3 ]

step "cleanup"
cleanup
echo "e2e passed"
