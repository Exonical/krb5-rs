# Configuring the primary KDC

This guide sets up a primary (master) KDC and kadmind for one realm on a
Linux host. It follows Red Hat's "Configuring the Master KDC Server", with
krb5-rs in place of MIT krb5.

The examples use realm `EXAMPLE.COM` and host `kdc1.example.com`.

## Binary names and paths

The `krb5-server-rs` and `krb5-workstation-rs` RPMs install the programs
under MIT's names. A source build (`cargo build --release`) names them
`krb5-rs-*` instead:

| MIT / RPM name | Source-build name |
|---|---|
| `krb5kdc` | `krb5-rs-kdc` |
| `kadmind` | `krb5-rs-kadmind` |
| `kdb5_util` | `krb5-rs-kdb` |
| `kprop`, `kpropd`, `kproplog` | `krb5-rs-kprop`, `krb5-rs-kpropd`, `krb5-rs-kproplog` |
| `kinit`, `klist`, `kadmin` | `krb5-rs-kinit`, `krb5-rs-klist`, `krb5-rs-kadmin` |

There is no `kadmin.local`. `kdb5_util` also takes its principal and
policy commands (`addprinc`, `ktadd`, `listprincs`, `addpol` and so on),
and opens the database directly, as `kadmin.local` does.

The RPMs keep the KDC files in `/var/kerberos/krb5kdc`, as RHEL does. A
source build reads `/usr/local/var/krb5kdc/kdc.conf`, MIT's default. Either
way, `KRB5_KDC_PROFILE` and `KRB5_CONFIG` override the kdc.conf and
krb5.conf paths.

## Before you start

- The KDC host keeps the realm's keys. Run nothing else on it, and limit
  who can log in.
- Clocks must agree within `clockskew` (5 minutes by default). Run
  `chronyd` on every host.
- Forward and reverse DNS must resolve for the KDC and for every service
  host.

## Procedure

1. Install the server and client packages:

   ```
   # dnf install krb5-server-rs krb5-workstation-rs
   ```

2. Edit `/etc/krb5.conf`. Set the default realm and map your DNS domain to
   it:

   ```
   [libdefaults]
       default_realm = EXAMPLE.COM
       dns_lookup_realm = false
       dns_lookup_kdc = false
       rdns = false
       ticket_lifetime = 24h
       renew_lifetime = 7d
       forwardable = true

   [realms]
       EXAMPLE.COM = {
           kdc = kdc1.example.com
           admin_server = kdc1.example.com
       }

   [domain_realm]
       .example.com = EXAMPLE.COM
       example.com = EXAMPLE.COM
   ```

   Don't list legacy enctypes (`des3-*`, `arcfour-*`, `camellia*`).
   krb5-rs supports only the AES enctypes:
   `aes256-cts-hmac-sha384-192`, `aes128-cts-hmac-sha256-128`,
   `aes256-cts-hmac-sha1-96` and `aes128-cts-hmac-sha1-96`.

3. Edit `/var/kerberos/krb5kdc/kdc.conf`:

   ```
   [kdcdefaults]
       kdc_ports = 88
       kdc_tcp_ports = 88

   [realms]
       EXAMPLE.COM = {
           database_name = /var/kerberos/krb5kdc/principal
           acl_file = /var/kerberos/krb5kdc/kadm5.acl
           key_stash_file = /var/kerberos/krb5kdc/.k5.EXAMPLE.COM
           max_life = 24h
           max_renewable_life = 7d
           master_key_type = aes256-cts-hmac-sha384-192
           supported_enctypes = aes256-cts-hmac-sha384-192:normal aes128-cts-hmac-sha256-128:normal aes256-cts-hmac-sha1-96:normal
       }

   [dbmodules]
       EXAMPLE.COM = {
           db_library = klmdb
       }
   ```

   `db_library` chooses the database backend:

   | `db_library` | Backend |
   |---|---|
   | `klmdb` (default) | LMDB, the same files as MIT's klmdb |
   | `db2` | MIT's Berkeley DB 1.85 files (`principal.db`), read and written in place |
   | `kldap` | LDAP, like MIT's kldap |
   | `krb5-rs-cockroach` | CockroachDB or Turso, with replication |

   Use `db2` only to take over an existing MIT database. For a new realm,
   use `klmdb`.

4. Create the database and the stash file. `-s` stores the master key in
   `key_stash_file`, so the KDC can start without asking for it:

   ```
   # kdb5_util create -s -r EXAMPLE.COM
   Enter KDC database master key:
   Re-enter KDC database master key to verify:
   ```

   Keep the master password somewhere safe. You need it to recover the
   database if the stash file is lost.

5. Edit `/var/kerberos/krb5kdc/kadm5.acl`. This line gives every principal
   with an `/admin` instance full access:

   ```
   */admin@EXAMPLE.COM    *
   ```

   The file uses MIT's format, including permission letters such as
   `admcil`, target principals and restrictions.

6. Create the first admin principal. `kdb5_util addprinc` opens the
   database directly, like `kadmin.local`, and reads the password from
   standard input:

   ```
   # kdb5_util addprinc admin/admin
   ```

7. Start the KDC and kadmind, and enable them at boot:

   ```
   # systemctl enable --now krb5kdc kadmin
   ```

   Like MIT's, both daemons go into the background unless they get `-n`
   (`krb5kdc`) or `-nofork` (`kadmind`). The systemd units start them in
   the foreground.

8. Open the Kerberos ports in the firewall:

   ```
   # firewall-cmd --permanent --add-service=kerberos --add-service=kadmin --add-service=kpasswd
   # firewall-cmd --reload
   ```

   | Port | Protocol | Used by |
   |---|---|---|
   | 88 | UDP, TCP | KDC |
   | 464 | UDP, TCP | kpasswd (served by kadmind) |
   | 749 | TCP | kadmin |
   | 754 | TCP | kprop, from the primary to secondaries |

9. Check that it works:

   ```
   $ kinit admin/admin
   $ klist
   $ kadmin -p admin/admin -q "listprincs"
   ```

## Adding principals and keytabs

- **A user:** `kadmin -q "addprinc alice"`
- **A service host:** create the host principal and write its keytab on
  the service host itself:

  ```
  # kadmin -p admin/admin -q "addprinc -randkey host/web1.example.com"
  # kadmin -p admin/admin -q "ktadd host/web1.example.com"
  ```

  `ktadd` writes to `/etc/krb5.keytab` by default. `klist -k` lists what a
  keytab holds.

## Next steps

- [Secondary KDCs](secondary-kdc.md): replicate the database with `kprop`
  or incremental propagation.
- [KDC tuning](tuning.md): listen backlog, per-realm settings and worker
  processes.
