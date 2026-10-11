# CockroachDB multi-region KDC example

These values install one CockroachDB-backed KDC release in each CockroachDB
region. They do not deploy CockroachDB. Each KDC pod has its own persistent
Turso replica, and every release uses the same master-password Secret.

## Prerequisites

- One CockroachDB cluster whose nodes are started with
  `--locality=region=<name>` in each region. This can be a CockroachDB
  operator-managed or hosted cluster.
- A database named `krb5`:

  ```sql
  CREATE DATABASE krb5;
  ```

- Client certificates whose CN matches the SQL user. Create Secrets containing
  `ca.crt`, `tls.crt`, and `tls.key` for the migrator (a user with the admin
  role, such as `root`), `kdc_admin`, and `kdc_replica`. For example, with
  cert-manager:

  ```yaml
  apiVersion: cert-manager.io/v1
  kind: Certificate
  metadata:
    name: kdc-replica
  spec:
    secretName: krb5-kdc-replica-tls
    issuerRef:
      name: cockroach-ca
      kind: ClusterIssuer
    commonName: kdc_replica
    usages: [client auth]
  ```

  Repeat with the SQL username and Secret name for `kdc_admin` and the
  migrator. The referenced certificate Secrets must also contain `ca.crt`.
- The same Secret, containing `master-password`, must be present in every
  region.

## Install order

Install California first. Its idempotent pre-install/pre-upgrade bootstrap
hook runs the migration with `--multi-region`, sets California as the primary
region, adds Ohio and Washington DC, and creates the realm. Then install the
other releases:

```sh
helm upgrade --install krb5-ca deploy/helm/krb5-rs-kdc --kube-context california-context \
  -f deploy/helm/krb5-rs-kdc/examples/multi-region/values-california.yaml
helm upgrade --install krb5-oh deploy/helm/krb5-rs-kdc --kube-context ohio-context \
  -f deploy/helm/krb5-rs-kdc/examples/multi-region/values-ohio.yaml
helm upgrade --install krb5-dc deploy/helm/krb5-rs-kdc --kube-context washington-dc-context \
  -f deploy/helm/krb5-rs-kdc/examples/multi-region/values-washington-dc.yaml
```

Bootstrap and pruning are enabled only in the California release. All KDC
releases must use the same `cockroach.transactionTimeout`.

## Client configuration

Clients are outside the Kubernetes clusters, so configure each region's
external KDC address and list the local region first. Give each regional
LoadBalancer Service a DNS record, for example
`kdc.california.example.com`, `kdc.ohio.example.com`, and
`kdc.washington-dc.example.com`. The clusters' `*.svc` names are
cluster-local and do not resolve from clients or the other clusters.

```ini
[libdefaults]
    default_realm = EXAMPLE.COM
    dns_lookup_kdc = false

[realms]
    EXAMPLE.COM = {
        kdc = kdc.california.example.com:88
        kdc = kdc.ohio.example.com:88
        kdc = kdc.washington-dc.example.com:88
    }
```

## Failure behavior

- A partitioned region's KDCs fail closed after `maxStaleness`: `/readyz`
  returns 503 and they are removed from the Service, while healthy regions
  keep serving.
- Administration needs CockroachDB quorum.
- Tickets already issued remain valid until they expire (see
  [kdb.md §7.4](../../../../../docs/architecture/kdb.md#74-tickets-already-issued)).

These values files are render-validated examples. They have not been run on
real multi-region infrastructure.
