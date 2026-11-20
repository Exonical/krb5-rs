# Adjusting the performance of the KDC

This guide follows Red Hat's "Adjusting the performance of the KDC", for
the krb5-rs KDC. The settings and options are MIT's, so the same tuning
works for both.

## Adjusting the length of the KDC listen queue

`kdc_tcp_listen_backlog` sets the queue length for TCP connections waiting
to be accepted. The default is 5, as in MIT. Under heavy TCP load (large
tickets with a PAC or PKINIT replies don't fit in UDP), raise it in
`kdc.conf`:

```
[kdcdefaults]
    kdc_tcp_listen_backlog = 10
```

The kernel caps it at `net.core.somaxconn`. Restart the KDC to apply it:

```
# systemctl restart krb5kdc
```

## Options controlling KDC behavior per realm

These `kdc.conf` settings affect how much work each request costs. As in
MIT, `disable_last_success` and `disable_lockout` go in the realm's
`[dbmodules]` block, and the others in `[realms]`:

| Setting | Effect |
|---|---|
| `disable_last_success` | Don't record each principal's last successful login. This saves a database write on every AS request that requires preauthentication. |
| `disable_lockout` | Don't record failed logins or enforce lockout policies. This saves a database write on every failed request. |
| `max_life`, `max_renewable_life` | Longer ticket lifetimes mean fewer requests. |
| `kdc_listen`, `kdc_tcp_listen` | Addresses and ports to listen on. |
| `restrict_anonymous_to_tgt` | Allow anonymous principals only to get a TGT. |

Turning off `last_success` and lockout recording removes database writes
from the request path. That matters most with replicated backends.
`disable_lockout` also turns off lockout protection, so only use it if
password guessing is limited some other way.

## Adjusting KDC settings per realm

Set them in `kdc.conf`, then restart the KDC:

```
[realms]
    EXAMPLE.COM = {
        max_life = 10h
    }

[dbmodules]
    EXAMPLE.COM = {
        disable_last_success = true
        disable_lockout = false
    }
```

The `[dbmodules]` block is named by the realm's `database_module`
setting, which defaults to the realm name.

One KDC process can serve several realms. Repeat `-r` once per realm, and
each realm uses its own settings:

```
krb5kdc -r EXAMPLE.COM -r LAB.EXAMPLE.COM
```

## Adjusting the number of KDC processes

By default the KDC serves requests from one process. `-w N` starts `N`
worker processes that share the listening sockets, as MIT's `krb5kdc -w`
does. Use about one worker per CPU core.

Set it in a systemd drop-in:

```
# systemctl edit krb5kdc
```

```
[Service]
ExecStart=
ExecStart=/usr/sbin/krb5kdc -n -w 4
```

```
# systemctl daemon-reload
# systemctl restart krb5kdc
```

The krb5-rs KDC is multi-threaded, so a single process already uses
several cores. Workers mainly help when one process is limited by the
database backend's locking.

Differences from MIT:

- Workers are new copies of the binary that inherit the sockets. MIT forks
  instead.
- With `--metrics-listen`, only the supervisor process serves the metrics
  endpoint.
- `-w` can't be combined with the `krb5-rs-cockroach` backend's
  replication. The KDC refuses to start.

## Monitoring

`--metrics-listen ADDR` serves Prometheus metrics and health endpoints, so
you can see request rates and latency before and after a change. MIT's KDC
has no equivalent.
