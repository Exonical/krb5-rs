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
   a realm section, a wildcard section such as `[*EXAMPLE.COM]` (that realm and every realm ending in it) or `[global]` to turn DNS
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
server terminate TLS. Add this to `/etc/sysconfig/kdcproxy`:

```
KDCPROXY_ARGS=--http --listen 127.0.0.1:8088
```

Then remove the `--cert` and `--key` options, and the certificate files the unit loads, with a drop-in:

```
# systemctl edit kdcproxy
[Service]
LoadCredential=
ExecStart=
ExecStart=/usr/sbin/kdcproxy $KDCPROXY_ARGS
```

and let the web server connect to it under SELinux:

```
# setsebool -P httpd_can_network_connect on
```

#### Apache

Install `mod_ssl`, and add the path to the HTTPS virtual host for
`proxy.example.com`, for example in `/etc/httpd/conf.d/kdcproxy.conf`:

```
<Location "/KdcProxy">
    ProxyPass "http://127.0.0.1:8088/KdcProxy" keepalive=On
    LimitRequestBody 131072
</Location>
```

```
# systemctl restart httpd
```

#### nginx

Add a server block, for example `/etc/nginx/conf.d/kdcproxy.conf`:

```
upstream kdcproxy {
    server 127.0.0.1:8088;
    keepalive 16;
}

server {
    listen 443 ssl;
    listen [::]:443 ssl;
    server_name proxy.example.com;

    ssl_certificate     /etc/pki/tls/certs/kdcproxy.pem;
    ssl_certificate_key /etc/pki/tls/private/kdcproxy.key;

    location /KdcProxy {
        proxy_pass http://kdcproxy;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        client_max_body_size 128k;
    }
}
```

```
# nginx -t
# systemctl restart nginx
```

In both cases the web server reads the certificate and key, so the files
need its SELinux label and permissions rather than the proxy's.

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

## Windows clients

Windows implements the client side of Microsoft's
[MS-KKDCP](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kkdcp/)
protocol, which this proxy implements on the server side. A Windows
machine uses the proxy when it can't reach a domain controller directly,
for example:

- an Entra ID-joined (cloud-only) device signing in to on-premises
  servers with a password or smart card (PKINIT);
- Azure Virtual Desktop sessions, where the host pool's **KDC proxy
  name** RDP property names the proxy;
- remote users reaching Active Directory resources, such as Azure Files
  shares with AD DS identities, from outside the network.

1. Point the proxy at the domain controllers. For an Active Directory
   domain `CORP.EXAMPLE.COM`, either list them:

   ```
   [CORP.EXAMPLE.COM]
   kerberos = kerberos://dc1.corp.example.com kerberos://dc2.corp.example.com
   kpasswd = kpasswd://dc1.corp.example.com
   ```

   or let the proxy find them through the `_kerberos._tcp` and
   `_kpasswd._tcp` SRV records that Active Directory registers, by adding
   an empty `[CORP.EXAMPLE.COM]` section or `dns_realm_discovery = true`
   in `[global]`.

2. Configure the clients, through Group Policy or Intune: **Computer
   Configuration > Administrative Templates > System > Kerberos > Specify
   KDC proxy servers for Kerberos clients**. Add the domain as the value
   name and the proxy as the value:

   ```
   corp.example.com    <https proxy.example.com:443:KdcProxy />
   ```

   For Azure Virtual Desktop, set the host pool's **KDC proxy name** to
   `proxy.example.com` instead.

3. Windows checks the proxy's certificate against the machine's trusted
   roots and checks its revocation, so the CA's CRL or OCSP responder must
   be reachable from the client. The client side of the KDC proxy runs in
   the IP Helper service (`iphlpsvc`), which must be running.

Windows may send the domain name in lower case. As MS-KKDCP requires, the
proxy matches realm sections and krb5.conf realms without regard to case.
It ignores the DC locator hint Windows sends, and finds servers as
described in [Setting up the proxy](#setting-up-the-proxy).

## Differences from python-kdcproxy

- The proxy is a standalone server and needs no WSGI host. `--http` runs it
  behind a web server instead.
- It accepts requests on any URL path, as python-kdcproxy does wherever it
  is mounted. Clients conventionally use `/KdcProxy`.
- Realm names in `kdcproxy.conf` and krb5.conf match the request's realm
  without regard to case, as MS-KKDCP requires.
- A request with no realm gets 400 (Bad Request), as MS-KKDCP's
  ERROR_BAD_FORMAT, instead of an internal server error.
