# krb5-rs KDC on Podman

A single pod running one KDC (the "primary"): the database lives in a named
volume, so it survives restarts. Podman has no replicas; high availability is
Kubernetes-only (see `deploy/helm`).

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

(`kprop-password` is unused in the single-pod setup.) Keep `my-kdc.yaml`
private: it contains the master password. Pin the image tag or digest in the
file if you do not want `:latest`; to test a local build
(`podman build -f deploy/docker/Dockerfile -t krb5-rs-kdc .`) replace
`ghcr.io/exonical/krb5-rs-kdc:latest` with `localhost/krb5-rs-kdc`.

Changing the master password later does not re-key an existing database.

## Run

```sh
podman kube play my-kdc.yaml        # creates secret, volume, pod; starts it
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
publishes host port 88 itself (`PublishPort=`), so the rootless port note above
applies; edit `PublishPort=` to use another host port.

## Verified

`podman kube play` (podman 6.0.2) with a locally built image: the pod starts,
`krb5-rs-kdb addprinc` through `podman exec` works, MIT `kinit` from the 1.22.2
test image succeeds against it, `podman pod restart` keeps the principals, and
`podman kube down` / `--force` behave as above. Quadlet itself needs systemd and
was not run here.
