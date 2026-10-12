host_path() {
  if command -v cygpath >/dev/null 2>&1; then
    cygpath -m "$1"
  else
    realpath "$1"
  fi
}

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

cleanup_cert_artifacts() {
  if [ -n "$CERTS_CONTAINER" ]; then
    "$CLI" rm -f "$CERTS_CONTAINER" >/dev/null 2>&1 || true
    CERTS_CONTAINER=""
  fi
  "$CLI" volume rm "$CERTS_VOLUME" >/dev/null 2>&1 || true
  rm -rf "$CERT_DIR"
}

generate_certificates() {
  "$CLI" pull "$CRDB_PINNED_IMAGE"
  "$CLI" volume create "$CERTS_VOLUME" >/dev/null
  "$CLI" run --rm -e "NS=$NS" -e "MULTI_REGION_CERTS=${MULTI_REGION_CERTS:-0}" \
    -v "$CERTS_VOLUME:/certs" --entrypoint /bin/sh "$CRDB_PINNED_IMAGE" -c '
      set -e
      umask 077
      /cockroach/cockroach cert create-ca --certs-dir=/certs --ca-key=/certs/ca.key
      if [ "$MULTI_REGION_CERTS" = "1" ]; then
        /cockroach/cockroach cert create-node \
          crdb-0.crdb crdb-1.crdb crdb-2.crdb crdb crdb-public \
          crdb-california crdb-ohio crdb-washington-dc \
          crdb-0.crdb.${NS}.svc.cluster.local \
          crdb-1.crdb.${NS}.svc.cluster.local \
          crdb-2.crdb.${NS}.svc.cluster.local \
          crdb.${NS}.svc.cluster.local \
          crdb-public.${NS}.svc.cluster.local \
          crdb-california.${NS}.svc.cluster.local \
          crdb-ohio.${NS}.svc.cluster.local \
          crdb-washington-dc.${NS}.svc.cluster.local \
          localhost 127.0.0.1 \
          --certs-dir=/certs --ca-key=/certs/ca.key
      else
        /cockroach/cockroach cert create-node \
          crdb-0.crdb crdb crdb-public \
          crdb-0.crdb.${NS}.svc.cluster.local \
          crdb.${NS}.svc.cluster.local \
          crdb-public.${NS}.svc.cluster.local \
          localhost 127.0.0.1 \
          --certs-dir=/certs --ca-key=/certs/ca.key
      fi
      for user in root kdc_admin kdc_replica; do
        /cockroach/cockroach cert create-client "$user" \
          --certs-dir=/certs --ca-key=/certs/ca.key
      done
      chmod 0644 /certs/*.crt
      chmod 0600 /certs/*.key
    '
  CERTS_CONTAINER=$("$CLI" create -v "$CERTS_VOLUME:/certs:ro" "$CRDB_PINNED_IMAGE")
  "$CLI" cp "$CERTS_CONTAINER:/certs/." "$(host_path "$CERT_DIR")"
  "$CLI" rm "$CERTS_CONTAINER" >/dev/null
  CERTS_CONTAINER=""
  chmod 0700 "$CERT_DIR"
  chmod 0600 "$CERT_DIR"/*.key
}

make_client_secret() {
  local secret=$1
  local user=$2
  "$KUBECTL" create secret generic "$secret" -n "$NS" \
    --from-file=ca.crt="$(host_path "$CERT_DIR/ca.crt")" \
    --from-file=tls.crt="$(host_path "$CERT_DIR/client.${user}.crt")" \
    --from-file=tls.key="$(host_path "$CERT_DIR/client.${user}.key")"
}

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

mit() {
  "$KUBECTL" exec -n "$NS" mit-client -- bash -c "$1"
}

write_krb5_conf() {
  local kdc=$1
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

kinit_user() {
  local user=$1
  local password=$2
  printf '%s\n' "$password" | "$KUBECTL" exec -i -n "$NS" mit-client -- \
    bash -c 'KRB5_CONFIG=/tmp/krb5.conf KRB5CCNAME=FILE:/tmp/cc_$RANDOM timeout 20 kinit "$1@$2"' \
    _ "$user" "$REALM"
}

kinit_alice() {
  kinit_user alice alice-password
}
