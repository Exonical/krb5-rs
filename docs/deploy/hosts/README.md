# Deploying krb5-rs on hosts

These guides set up a Kerberos realm with krb5-rs on Linux hosts, in the
style of Red Hat's Kerberos server documentation. krb5-rs reads MIT's
configuration files and speaks MIT's protocols, so MIT and Red Hat
documentation mostly applies as written.

| Guide | Covers |
|---|---|
| [Configuring the primary KDC](primary-kdc.md) | krb5.conf, kdc.conf, the database, kadm5.acl, kadmind, firewall |
| [Setting up secondary KDCs](secondary-kdc.md) | host keytabs, kpropd.acl, full `kprop` propagation, incremental propagation (iprop) |
| [Adjusting the performance of the KDC](tuning.md) | listen backlog, per-realm settings, worker processes |
| [Configuring a KDC proxy (KKDCP)](kkdcp-proxy.md) | Kerberos and kpasswd over HTTPS, `kdcproxy.conf`, client settings |

Kubernetes deployment is covered separately; see [`deploy/helm`](../../../deploy/helm)
and [`deploy/podman`](../../../deploy/podman).

## Packages

| Package | Contents |
|---|---|
| `krb5-workstation-rs` | client tools: `kinit`, `klist`, `kdestroy`, `kvno`, `kswitch`, `kpasswd`, `kadmin`, `ktutil`, `ksu`, `k5srvutil` and more |
| `krb5-server-rs` | `krb5kdc`, `kadmind`, `kdb5_util`, `kprop`, `kpropd`, `kproplog` and their systemd units |
| `krb5-server-ldap-rs` | `kdb5_ldap_util` |
| `krb5-kdcproxy-rs` | `kdcproxy`, the KDC proxy, and its systemd unit |

## Encryption types

krb5-rs supports only the AES enctypes. It has no DES, des3, RC4 or
Camellia. Remove those from `supported_enctypes`, `permitted_enctypes` and
similar settings before moving an MIT configuration to krb5-rs. Principals
that only have keys of those types need new keys (`cpw -randkey`, or a new
password) first.
