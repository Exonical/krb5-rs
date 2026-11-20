# Configuring a KDC proxy (KKDCP)

A KDC proxy lets clients reach the KDC over HTTPS (MS-KKDCP) when ports 88
and 464 are blocked, for example from the internet or a restrictive network.
`kdcproxy` from the `krb5-kdcproxy-rs` package is a native replacement for
python-kdcproxy, the proxy Red Hat ships with IdM. It reads the same
`/etc/kdcproxy.conf` and behaves the same way.

The proxy takes each request POSTed to it and forwards it to the realm's
KDC (AS-REQ and TGS-REQ) or kpasswd server (password changes) over TCP or
UDP, then returns the reply. It holds no keys and cannot read tickets.

This guide uses `proxy.example.com` for the proxy and the `EXAMPLE.COM`
realm from [the primary KDC guide](primary-kdc.md).

## Setting up the proxy

1. Install the package:

   ```
   # dnf install krb5-kdcproxy-rs
   ```

2. Install a TLS certificate for `proxy.example.com`, signed by a CA the
   clients trust. The systemd unit loads these two files:

   ```
   /etc/pki/tls/certs/kdcproxy.pem     certificate chain (PEM)
   /etc/pki/tls/private/kdcproxy.key   private key (PEM)
   ```

3. Tell the proxy where the realm's servers are, in `/etc/kdcproxy.conf`.
   Either use the `[realms]` entries of the proxy host's `/etc/krb5.conf`
   (`kdc` for tickets; `kpasswd_server` and `admin_server` for password
   changes):

   ```
   [global]
   configs = mit
   ```

   or list them per realm:

   ```
   [EXAMPLE.COM]
   kerberos = kerberos://kdc1.example.com kerberos://kdc2.example.com
   kpasswd = kpasswd://kdc1.example.com
   ```

   `kerberos+tcp://` and `kerberos+udp://` (and the same for `kpasswd`)
   limit a server to one transport. The ports default to 88 and 464.

   If neither source lists the realm, the proxy uses DNS SRV records, but
   only for realms named in a section of `kdcproxy.conf`, or for every realm
   with `dns_realm_discovery = true` in `[global]`. Set `use_dns = false` in
   a realm section, a `*.suffix` wildcard section or `[global]` to turn DNS
   off.

4. Start the proxy and open HTTPS:

   ```
   # systemctl enable --now kdcproxy
   # firewall-cmd --permanent --add-service=https
   # firewall-cmd --reload
   ```

   By default the proxy listens on `0.0.0.0:443`. To listen elsewhere, or on
   IPv6, set `KDCPROXY_ARGS` in `/etc/sysconfig/kdcproxy`, for example
   `KDCPROXY_ARGS=--listen [::]:443`. The unit runs the proxy as an
   unprivileged dynamic user, so it can only read what it has to.

### Behind a web server

To serve the proxy under an existing Apache or nginx site, as Red Hat's
IdM does, run it on plain HTTP on the loopback address and let the web
server terminate TLS. For Apache, add this to `/etc/sysconfig/kdcproxy`:

```
KDCPROXY_ARGS=--http --listen 127.0.0.1:8088
```

Then remove the `--cert` and `--key` options with a drop-in:

```
# systemctl edit kdcproxy
[Service]
ExecStart=
ExecStart=/usr/sbin/kdcproxy $KDCPROXY_ARGS
```

and forward the path in the Apache configuration:

```
ProxyPass /KdcProxy http://127.0.0.1:8088/KdcProxy
```

## Configuring clients

Point the realm's `kdc` and `kpasswd_server` at the proxy in each client's
`/etc/krb5.conf`:

```
[realms]
    EXAMPLE.COM = {
        kdc = https://proxy.example.com/KdcProxy
        kpasswd_server = https://proxy.example.com/KdcProxy
    }
```

If the certificate isn't signed by a CA in the system trust store, add
`http_anchors = FILE:/etc/pki/tls/certs/example-ca.pem` to the realm.

Check it from a client:

```
$ kinit admin/admin
$ klist
```

Windows clients find the proxy through the Group Policy setting "Specify
KDC proxy servers for Kerberos clients".

## Differences from python-kdcproxy

- The proxy is a standalone server and needs no WSGI host. `--http` runs it
  behind a web server instead.
- It accepts requests on any URL path, as python-kdcproxy does wherever it
  is mounted. Clients conventionally use `/KdcProxy`.
- It answers one request per connection and closes it.
