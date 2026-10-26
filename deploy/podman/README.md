# krb5-rs KDC on Podman

A primary pod (`krb5-rs-kdc.yaml`, host `kdc1.example.com`) and an optional
replica pod (`krb5-rs-kdc-replica.yaml`, host `kdc2.example.com`). Each
database lives in a named volume, so it survives restarts. The primary's
`kprop` container pushes the database with MIT kprop to the replica's
`krb5-rs-kpropd` (TCP 7540) after every admin change and every 60s; the
replica's KDC starts once the first push is loaded. The primary's `kadmind`
container (`krb5-rs-kadmind`) serves remote MIT `kadmin` (host TCP 749) and
`kpasswd` (host UDP and TCP 464).

`krb5-rs-kdc.yaml` is a self-contained `podman kube play` file with a Secret
(master and kprop passwords), a ConfigMap (`kdc.conf`, `krb5.conf`), a
PersistentVolumeClaim (a podman volume) and the Pod. An init container runs the
idempotent `krb5-rs-kdb init` (creates the database and stash on first start),
then the daemon starts. The container user is uid 65532, so it cannot bind port
88: the daemon listens on 8888 and the pod publishes host port 88 to it.

## Prepare the file

Choose your realm and generate the master password, then write your copy:

```sh
sed -e 's/EXAMPLE\.COM/MY.REALM/g' \
    -e "s/CHANGE-ME-master/$(openssl rand -hex 24)/" \
    -e "s/CHANGE-ME-kprop/$(openssl rand -hex 24)/" \
    krb5-rs-kdc.yaml > my-kdc.yaml
```

Write `my-kdc-replica.yaml` from `krb5-rs-kdc-replica.yaml` with the same
realm and the same two passwords; also replace `kdc1.example.com` and
`kdc2.example.com` in both files with the hosts' DNS names. `kprop-password`
is the password of the two `host/` principals kprop authenticates with. Without
a replica, drop the `kprop` container from `my-kdc.yaml`. Keep `my-kdc.yaml`
private: it contains the master password. Pin the image tag or digest in the
file if you do not want `:latest`; to test a local build
(`podman build -f deploy/docker/Dockerfile -t krb5-rs-kdc .`) replace
`ghcr.io/exonical/krb5-rs-kdc:latest` with `localhost/krb5-rs-kdc`.

Changing the master password later does not re-key an existing database.

## Run

```sh
podman kube play my-kdc.yaml        # creates secret, volume, pod; starts it
podman kube play my-kdc-replica.yaml  # on the replica host
podman pod ps
podman logs krb5-rs-kdc-kdc         # one log line per request
```

The pod and container names come from the YAML (`krb5-rs-kdc`,
`krb5-rs-kdc-kdc`). Restart policy is `always`. Podman 6 `kube play` handles the
Secret, ConfigMap, PVC and init container inline; no extra `--configmap` or
`podman secret create` is needed.

### Ports

`hostPort: 88` is in the YAML. **Rootless podman cannot bind ports below 1024
by default.** Either lower the limit once:

```sh
sudo sysctl -w net.ipv4.ip_unprivileged_port_start=88
echo 'net.ipv4.ip_unprivileged_port_start=88' | sudo tee /etc/sysctl.d/90-krb5-rs.conf
```

or publish another host port (this overrides the YAML's `hostPort`):

```sh
podman kube play --publish 8088:8888/udp --publish 8088:8888/tcp my-kdc.yaml
```

and point clients at `host:8088` in `krb5.conf` (`kdc = host:8088`).

### Incremental propagation (opt-in)

To use MIT iprop instead of full pushes, add to the realm in both files'
`kdc.conf`:

```
  acl_file = /etc/krb5-rs/kadm5.acl
  iprop_enable = true
  iprop_port = 7550
  iprop_replica_poll = 2m
```

On the primary, add `kiprop/kdc1.example.com` and `kiprop/kdc2.example.com`
to the `init-database` `--password` list (with `/secrets/kprop-password`),
`kiprop/kdc1.example.com` to the `init-keytab` principals, a `kadm5.acl`
entry `kiprop/kdc2.example.com@EXAMPLE.COM p` to the ConfigMap, drop the
`kprop` container and add
`-p /usr/local/bin/krb5-rs-kdb -K /usr/local/bin/krb5-rs-kprop -k 7540
-F /var/lib/krb5-rs/replica_datatrans` to the `kadmind` arguments (with
`KRB5_KTNAME=FILE:/var/lib/krb5-rs/krb5.keytab` and
`KRB5_CONFIG=/etc/krb5-rs/kprop-krb5.conf` in its environment; publish TCP
7550). On the
replica, add `kiprop/kdc2.example.com` to its keytab database and keytab and
`-A kdc1.example.com` to the kpropd arguments. kpropd authenticates to the primary's
KDC, so the replica's `krb5.conf` needs
`[realms] EXAMPLE.COM = { kdc = kdc1.example.com }`, and it reads the
replica's `key_stash_file`, so write it before kpropd starts (`krb5-rs-kdb
--master-password-file /secrets/master-password stash` with a config whose
`database_name` is the keytab database and whose `key_stash_file` is the
replica's). Set `shareProcessNamespace: true` in
the replica pod as the primary already does: kpropd and the KDC then open the
LMDB database at the same time, and LMDB's reader locks need distinct process
IDs. kpropd then polls for updates
and the primary pushes a full dump only when the replica falls behind the
update log. The Helm chart does all of this with
`propagation.iprop.enabled=true`.

## Administer

The tools are inside the container; secrets come from stdin, never from argv
(use `-i`):

```sh
printf 'alice-password\n' | podman exec -i krb5-rs-kdc-kdc \
  krb5-rs-kdb --config /etc/krb5-rs/kdc.conf --realm MY.REALM addprinc alice
podman exec krb5-rs-kdc-kdc \
  krb5-rs-kdb --config /etc/krb5-rs/kdc.conf --realm MY.REALM listprincs
```

Test with an MIT client (`/etc/krb5.conf` with `default_realm = MY.REALM` and
`kdc = host:88`):

```sh
kinit alice@MY.REALM && klist
```

### Remote kadmin and kpasswd

`kadm5.acl` in the ConfigMap grants every `*/admin` principal all permissions
(MIT's sample ACL); edit it before playing the file. Create an admin principal
inside the container, then administer from any MIT client whose `krb5.conf`
realm has `admin_server = host:749` and `kpasswd_server = host:464`:

```sh
printf 'admin-password\n' | podman exec -i krb5-rs-kdc-kdc \
  krb5-rs-kdb --config /etc/krb5-rs/kdc.conf --realm MY.REALM addprinc admin/admin
kadmin -p admin/admin -q 'addprinc bob'
kpasswd bob
```

The ports below 1024 need the same rootless setting as port 88 (lower
`net.ipv4.ip_unprivileged_port_start` to 464) or `--publish` to higher host
ports. Remove the `kadmind` container to run without remote administration.

## External CockroachDB

`krb5-rs-kdc-cockroach.yaml` runs the CockroachDB-enabled image and gives this
KDC its own persistent Turso replica. It does not run CockroachDB. Before
playing the Pod, create the database and schema with a CockroachDB SQL
administrator, then initialize the realm with `kdc_admin`. Use a database
name and realm consistently in the client profiles and URLs:

```sh
IMAGE=ghcr.io/exonical/krb5-rs-kdc:<version>-cockroach
NETWORK=krb5rs-crdb
DB=krb5
REALM=MY.REALM
CERTS="$PWD/tests/crdb/certs"
umask 077
openssl rand -hex 24 > master-password
```

The profile passed to the one-off `database migrate` command should use
`kdc_replica`'s CockroachDB module and the `root` client certificate for the
migrator:

```ini
[realms]
    MY.REALM = {
        database_module = crdb
        key_stash_file = /tmp/stash
        supported_enctypes = aes256-cts-hmac-sha1-96:normal aes128-cts-hmac-sha1-96:normal
    }
[dbmodules]
    crdb = {
        db_library = krb5-rs-cockroach
        cockroach_url = postgresql://root@crdb1:26257/krb5?sslmode=verify-full
        cockroach_ca = /crdb/ca.crt
        cockroach_cert = /crdb/client.root.crt
        cockroach_key = /crdb/client.root.key
        cockroach_pool_size = 8
        cockroach_pool_idle_timeout = 0s
        cockroach_connect_timeout = 5s
        cockroach_statement_timeout = 10s
        cockroach_transaction_timeout = 30s
    }
```

Run migration with the CockroachDB-enabled image. For a multi-region database,
append `--multi-region --primary-region california --regions
california,ohio,washington-dc`:

```sh
podman run --rm --network "$NETWORK" --user 0 \
  -v "$PWD/migrator.conf:/config/kdc.conf:ro" \
  -v "$PWD/krb5.conf:/config/krb5.conf:ro" \
  -v "$CERTS:/crdb:ro" \
  --entrypoint /usr/local/bin/krb5-rs-kdb "$IMAGE" \
  --config /config/kdc.conf --krb5-config /config/krb5.conf \
  --realm "$REALM" database migrate --create-roles
```

Use the same profile shape for `init` and day-to-day administration, but set
the URL and certificate paths to `kdc_admin`:

```ini
cockroach_url = postgresql://kdc_admin@crdb1:26257/krb5?sslmode=verify-full
cockroach_cert = /crdb/client.kdc_admin.crt
cockroach_key = /crdb/client.kdc_admin.key
```

Mount the master-password file; do not put its contents in command arguments:

```sh
podman run --rm --network "$NETWORK" --user 0 \
  -v "$PWD/admin.conf:/config/kdc.conf:ro" \
  -v "$PWD/krb5.conf:/config/krb5.conf:ro" \
  -v "$CERTS:/crdb:ro" \
  -v "$PWD/master-password:/secrets/master-password:ro" \
  --entrypoint /usr/local/bin/krb5-rs-kdb "$IMAGE" \
  --config /config/kdc.conf --krb5-config /config/krb5.conf \
  --realm "$REALM" --master-password-file /secrets/master-password init

printf 'alice-password\n' | podman run --rm -i --network "$NETWORK" --user 0 \
  -v "$PWD/admin.conf:/config/kdc.conf:ro" \
  -v "$PWD/krb5.conf:/config/krb5.conf:ro" \
  -v "$CERTS:/crdb:ro" \
  -v "$PWD/master-password:/secrets/master-password:ro" \
  --entrypoint /usr/local/bin/krb5-rs-kdb "$IMAGE" \
  --config /config/kdc.conf --krb5-config /config/krb5.conf \
  --realm "$REALM" --master-password-file /secrets/master-password addprinc alice
```

`replication status` uses the same admin profile and master-password file:

```sh
podman run --rm --network "$NETWORK" --user 0 \
  -v "$PWD/admin.conf:/config/kdc.conf:ro" \
  -v "$PWD/krb5.conf:/config/krb5.conf:ro" \
  -v "$CERTS:/crdb:ro" \
  -v "$PWD/master-password:/secrets/master-password:ro" \
  --entrypoint /usr/local/bin/krb5-rs-kdb "$IMAGE" \
  --config /config/kdc.conf --krb5-config /config/krb5.conf \
  --realm "$REALM" --master-password-file /secrets/master-password replication status
```

Before use, edit the clearly marked realm, region, CockroachDB URL, image tag
and `POD_NAME` in `krb5-rs-kdc-cockroach.yaml`. Replace the sample base64 Secret
data with the master password and `kdc_replica`'s `ca.crt`, client certificate
and key. Set `POD_NAME` to a unique `<region>-<host>` value, for example
`california-podman-1`, so each KDC heartbeat has a unique identity. Then run:

```sh
podman kube play --network krb5rs-crdb krb5-rs-kdc-cockroach.yaml
```

`krb5-rs-kdc-cockroach.kube` is the matching Quadlet unit. Install it beside
the edited YAML under `~/.config/containers/systemd/` (or
`/etc/containers/systemd/` for a system service); ensure its `Network=` names
the Podman network that can resolve the CockroachDB host.

The Pod exposes `/healthz` for liveness and `/readyz` for readiness. Readiness
waits for the local replica to bootstrap and remain within `max_staleness`;
when CockroachDB is unavailable or the replica becomes stale, the KDC fails
closed with `KDC_ERR_SVC_UNAVAILABLE`. Each KDC Pod must have its **own**
`/var/lib/krb5-rs` volume; never share a Turso replica volume between Pods.
`test-cockroach.sh` runs the local end-to-end flow against the scratch
`krb5_podman_e2e` database on the existing `krb5rs-crdb` network. The daemon
listens for metrics and health checks on container port 9100; the sample maps
it to host port 19100.

`PODMAN_TEST_FAIL_AFTER_READY=1 bash deploy/podman/test-cockroach.sh` is an
intentional cleanup smoke test: it exits nonzero after `/readyz` succeeds and
still removes the test Pod, Secrets, volumes and scratch database.

The sample publishes host port 88. Rootless Podman cannot bind ports below
1024 by default; either raise `net.ipv4.ip_unprivileged_port_start` as shown
above or publish a higher port and set that port in the clients' `krb5.conf`.

## Stop and remove

```sh
podman kube down my-kdc.yaml            # stops and removes the pod; the data volume is kept
podman kube down --force my-kdc.yaml    # also removes the volume (all principals!)
```

## Run under systemd with Quadlet

`krb5-rs-kdc.kube` runs the same YAML as a systemd service
(`Restart=always`, starts on boot). Rootless, per user:

```sh
mkdir -p ~/.config/containers/systemd
cp krb5-rs-kdc.kube ~/.config/containers/systemd/
cp my-kdc.yaml ~/.config/containers/systemd/krb5-rs-kdc.yaml   # your edited copy
systemctl --user daemon-reload
systemctl --user start krb5-rs-kdc.service
loginctl enable-linger "$USER"        # keep it running without a login session
```

System-wide, copy both files to `/etc/containers/systemd/` and use
`systemctl daemon-reload && systemctl start krb5-rs-kdc.service`. The unit
publishes host ports 88, 749 and 464 itself (`PublishPort=`), so the rootless
port notes above apply; edit `PublishPort=` to use other host ports, and drop
the 749 and 464 lines if you remove the `kadmind` container.

## Verified

`podman kube play` (podman 6.0.2) with a locally built image: the pod starts,
`krb5-rs-kdb addprinc` through `podman exec` works, MIT `kinit` from the 1.22.2
test image succeeds against it, `podman pod restart` keeps the principals, and
`podman kube down` / `--force` behave as above. Quadlet itself needs systemd and
was not run here.

`test-replication.sh` (CI job `podman-e2e`, podman 4.9) plays the replica and
the primary on one Podman network with the placeholder hostnames, and checks
that the first push loads the replica, that a new principal reaches it through
`--watch` before the 60 s interval, and that MIT `kinit` succeeds against the
replica KDC. It then creates a principal with MIT `kadmin` through the
primary's kadmind, waits for it on the replica, changes its password with MIT
`kpasswd` and logs in with the new one. Host ports are not published in that
test.
