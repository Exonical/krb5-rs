# Setting up secondary KDCs

A secondary (replica) KDC holds a read-only copy of the realm database, so
clients can still get tickets when the primary is down. This guide follows
Red Hat's "Setting up Secondary KDCs", with krb5-rs in place of MIT krb5.

Secondaries can be kept up to date in two ways:

- **Full propagation:** the primary dumps the whole database and sends it
  with `kprop`, for example every few minutes from a timer.
- **Incremental propagation (iprop):** kadmind on the primary logs each
  change, and `kpropd` on each secondary pulls new changes as they happen.
  It falls back to a full dump when a secondary falls too far behind.

Both use MIT's wire protocol, so krb5-rs and MIT KDCs can replicate to
each other in either direction.

The examples use primary `kdc1.example.com` and secondary
`kdc2.example.com`. Program names are the RPM's MIT names; see
[Binary names and paths](primary-kdc.md#binary-names-and-paths).

## Prerequisites

- A working [primary KDC](primary-kdc.md).
- The same `/etc/krb5.conf` on every KDC, listing every KDC:

  ```
  [realms]
      EXAMPLE.COM = {
          kdc = kdc1.example.com
          kdc = kdc2.example.com
          admin_server = kdc1.example.com
      }
  ```

## Procedure

1. On the primary, create host principals for both KDCs:

   ```
   # kadmin -p admin/admin -q "addprinc -randkey host/kdc1.example.com"
   # kadmin -p admin/admin -q "addprinc -randkey host/kdc2.example.com"
   ```

2. Write each KDC's own host key to its `/etc/krb5.keytab`. On the
   primary:

   ```
   # kadmin -p admin/admin -q "ktadd host/kdc1.example.com"
   ```

   On the secondary:

   ```
   # kadmin -p admin/admin -s kdc1.example.com -q "ktadd host/kdc2.example.com"
   ```

3. Copy these files from the primary to the same paths on the secondary:
   - `/var/kerberos/krb5kdc/kdc.conf`
   - `/var/kerberos/krb5kdc/kadm5.acl`
   - the stash file (`key_stash_file`, for example
     `/var/kerberos/krb5kdc/.k5.EXAMPLE.COM`)

   Use a secure channel such as `scp`. The stash file holds the master
   key.

4. On the secondary, create `/var/kerberos/krb5kdc/kpropd.acl`. List the
   host principal of every KDC that may send it the database:

   ```
   host/kdc1.example.com@EXAMPLE.COM
   host/kdc2.example.com@EXAMPLE.COM
   ```

   Listing both KDCs lets you swap roles later without editing the file.

5. On the secondary, let the KDC start before it has a database. Until
   its first propagation the secondary has none, so set this in
   `/etc/sysconfig/krb5kdc`:

   ```
   KRB5KDC_ARGS=--wait-for-database
   ```

   The KDC then keeps retrying until the database arrives instead of
   exiting.

6. On the secondary, start `kpropd` and the KDC, and open the Kerberos and
   kprop ports:

   ```
   # systemctl enable --now kprop krb5kdc
   # firewall-cmd --permanent --add-service=kerberos --add-port=754/tcp
   # firewall-cmd --reload
   ```

7. Do a first full propagation from the primary:

   ```
   # kdb5_util dump /var/kerberos/krb5kdc/replica_datatrans
   # kprop -f /var/kerberos/krb5kdc/replica_datatrans kdc2.example.com
   Database propagation to kdc2.example.com: SUCCEEDED
   ```

8. Check the secondary. Put only `kdc2` in a test krb5.conf and get a
   ticket:

   ```
   $ cat > /tmp/kdc2.conf <<'END'
   [libdefaults]
       default_realm = EXAMPLE.COM
   [realms]
       EXAMPLE.COM = {
           kdc = kdc2.example.com
       }
   END
   $ KRB5_CONFIG=/tmp/kdc2.conf kinit admin/admin
   ```

## Keeping secondaries current with full propagation

Run the dump and `kprop` from a systemd timer on the primary. For example,
`/etc/systemd/system/kprop-push.service`:

```
[Unit]
Description=Propagate the Kerberos database to secondary KDCs

[Service]
Type=oneshot
ExecStart=/usr/sbin/kdb5_util dump /var/kerberos/krb5kdc/replica_datatrans
ExecStart=/usr/sbin/kprop -f /var/kerberos/krb5kdc/replica_datatrans kdc2.example.com
```

and `/etc/systemd/system/kprop-push.timer`:

```
[Unit]
Description=Propagate the Kerberos database every 5 minutes

[Timer]
OnBootSec=1min
OnUnitActiveSec=5min

[Install]
WantedBy=timers.target
```

```
# systemctl enable --now kprop-push.timer
```

Add one `ExecStart=/usr/sbin/kprop ...` line per secondary.

## Incremental propagation (iprop)

With iprop, changes reach the secondaries within seconds, and the timer
above isn't needed.

1. On the primary, add these settings to the realm in `kdc.conf`, then
   restart kadmind:

   ```
   [realms]
       EXAMPLE.COM = {
           ...
           iprop_enable = true
           iprop_port = 2121
           iprop_master_ulogsize = 1000
       }
   ```

   ```
   # firewall-cmd --permanent --add-port=2121/tcp
   # firewall-cmd --reload
   ```

   `iprop_master_ulogsize` is how many changes the update log keeps. A
   secondary that falls further behind gets a full dump instead.

2. On the primary, create a `kiprop` principal for the primary itself and
   one for each secondary. Secondaries request tickets for the primary's
   `kiprop` principal. kadmind reads that key from the database, like
   MIT's `KDB:` keytab, so it needs no keytab entry:

   ```
   # kadmin -p admin/admin -q "addprinc -randkey kiprop/kdc1.example.com"
   # kadmin -p admin/admin -q "addprinc -randkey kiprop/kdc2.example.com"
   ```

   Give each secondary's `kiprop` principal the `p` (propagate)
   permission in `kadm5.acl`:

   ```
   kiprop/kdc2.example.com@EXAMPLE.COM    p
   ```

   Then restart kadmind, which reads `kdc.conf` and `kadm5.acl` only at
   startup:

   ```
   # systemctl restart kadmin
   ```

3. On the secondary, add the same `iprop_enable` and `iprop_port` settings
   to `kdc.conf`. `iprop_replica_poll` sets how often it asks for changes
   (2 minutes by default):

   ```
   [realms]
       EXAMPLE.COM = {
           ...
           iprop_enable = true
           iprop_port = 2121
           iprop_replica_poll = 30s
       }
   ```

4. On the secondary, add the `kiprop` key to `/etc/krb5.keytab`, then
   restart `kpropd`:

   ```
   # kadmin -p admin/admin -s kdc1.example.com -q "ktadd kiprop/kdc2.example.com"
   # systemctl restart kprop
   ```

5. Check it. Change a principal on the primary, then compare update
   serial numbers on both KDCs:

   ```
   # kproplog -h
   ```

   `kill -USR1` on `kpropd` makes it ask for changes right away instead of
   waiting for the next poll, as in MIT.

## Promoting a secondary

If the primary is lost:

1. Stop `kpropd` on the secondary you're promoting.
2. Start kadmind there, and point `admin_server` in every host's
   krb5.conf at it.
3. If the old primary comes back, make it a secondary: give it a
   `kpropd.acl` and start `kpropd` there instead of kadmind.

## Differences from MIT

- A secondary's KDC uses `--wait-for-database` (step 5). MIT's KDC exits if the database is missing.
- With `db_library = krb5-rs-cockroach`, every KDC reads one replicated
  CockroachDB or Turso database, so kprop and iprop aren't needed.
