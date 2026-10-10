# krb5-rs

Pure Rust Kerberos V5 implementation. GSSAPI, SPNEGO, PKINIT.

**No C FFI. No system krb5. No libgssapi. Just `cargo add krb5-rs`.**

## Features

- **Kerberos V5 Client** — AS/TGS exchanges (TGT acquisition, service ticket requests), krb5.conf parsing, KDC discovery
- **KDC** — AS/TGS request processing, FAST, UDP/TCP serving (`kdc` feature; the deployable daemon is `krb5-rs-kdc` in `crates/krb5-rs-kdc`)
- **GSSAPI/SPNEGO** — HTTP Negotiate authentication
- **PKINIT** — X.509 certificate-based authentication, client and KDC (`pkinit` feature; DH/ECDH replies, MIT 1.22 parity)
- **FAST** — Flexible Authentication via Secure Tunneling
- **Credential Cache** — Read/write ccache and keytab formats

## Why?

MIT Kerberos and Heimdal are massive C codebases (~450K and ~620K SLOC respectively) with decades of CVEs. Every Rust project needing Kerberos auth depends on FFI bindings to these C libraries, inheriting their build complexity and security risks.

`krb5-rs` is a ground-up Rust implementation using `rasn` (ASN.1) + RustCrypto. Pure Rust, single binary, cross-compiles to musl.

## Status

**Pre-release.** API is unstable. Not ready for production use.

## RFCs

| RFC | Description | Status |
|-----|-------------|--------|
| [RFC 4120](https://www.rfc-editor.org/rfc/rfc4120) | Kerberos V5 core | Client + KDC |
| [RFC 4121](https://www.rfc-editor.org/rfc/rfc4121) | GSSAPI mechanism | Implemented |
| [RFC 4178](https://www.rfc-editor.org/rfc/rfc4178) | SPNEGO | Implemented |
| [RFC 3961](https://www.rfc-editor.org/rfc/rfc3961) | Encryption specs | Implemented |
| [RFC 3962](https://www.rfc-editor.org/rfc/rfc3962) | AES encryption | Implemented |
| [RFC 8009](https://www.rfc-editor.org/rfc/rfc8009) | AES-SHA2 encryption | Implemented |
| [RFC 6113](https://www.rfc-editor.org/rfc/rfc6113) | FAST | Client + KDC |
| [RFC 6806](https://www.rfc-editor.org/rfc/rfc6806) | Enc-pa-rep / FAST negotiation | Client + KDC |
| [RFC 4556](https://www.rfc-editor.org/rfc/rfc4556) | PKINIT (Diffie-Hellman and ECDH) | Client + KDC |
| [RFC 8636](https://www.rfc-editor.org/rfc/rfc8636) | PKINIT algorithm agility (KDFs, ECDH groups) | Client + KDC |
| [RFC 8070](https://www.rfc-editor.org/rfc/rfc8070) | PKINIT freshness | Client + KDC |

**Feature `test-pki`** (TESTING ONLY): embeds fixed RSA private keys and a certificate issuer used by the PKINIT tests and `examples/gen_pkinit_pki.rs`. Never enable it in production builds.

**Not yet supported:** PAC/authorization data, S4U, PKINIT RSA key transport and anonymous PKINIT, DES/RC4/Camellia enctypes.

## Running the KDC

The `crates/krb5-rs-kdc` workspace member builds two binaries (not published to crates.io):

- `krb5-rs-kdb` administers the persistent database (`create -s`, `addprinc`, `ktadd`, ...; passwords come from stdin).
- `krb5-rs-kdc` serves it over UDP and TCP, driven by `kdc.conf` (`--config` / `KRB5_KDC_PROFILE`, `--krb5-config` / `KRB5_CONFIG`, optional `--listen` overrides), logs one MIT-style line per request to stdout (`RUST_LOG` controls verbosity) and shuts down gracefully on SIGTERM/SIGINT (`--shutdown-timeout`).

```sh
krb5-rs-kdb --config kdc.conf create -s
echo secret | krb5-rs-kdb --config kdc.conf addprinc alice
krb5-rs-kdc --config kdc.conf
```

`deploy/docker/Dockerfile` builds a static, distroless, nonroot image with both binaries (`podman build -f deploy/docker/Dockerfile .`). The container user cannot bind port 88: configure `kdc_ports = 8888` and map 88 to 8888 outside.

### Replicas (database propagation)

For HA, one primary keeps the writable database and any number of stateless replicas pull it. This is MIT kprop/kpropd's idea reversed into a pull model (protocol `KRB5RS-PROP-1`, documented in `src/kdc/kdb/propagation.rs`): a replica authenticates to the primary's `kprop/primary` service with a Kerberos ticket (AP-REQ with mutual authentication), asks for the database naming the serial it already has, and receives the raw database file in KRB-PRIV blocks protected by the negotiated subkeys, unless it is current. The replica verifies size, SHA-256, format, realm and its master key, and only then renames the file over its database.

The settings below go in the kdc.conf realm section. They are krb5-rs extensions with no MIT counterpart.

| Option | Role | Meaning |
| --- | --- | --- |
| `kprop_listen` | primary | Listen address(es) of the propagation server (default port 754); unset = off |
| `kprop_service` | both | Service principal (default `kprop/primary`); needs a key in the primary's database |
| `kprop_acl` | primary | Principals allowed to pull (default: `kprop_client`) |
| `kprop_primary` | replica | `host:port` of the primary's propagation server; setting it makes this KDC a replica |
| `kprop_primary_kdc` | replica | `host:port` of the primary's KDC, used for the ticket (default: the `kprop_primary` host, port 88) |
| `kprop_client` | replica | The replica's principal (default `kprop/replica`) |
| `kprop_keytab` / `kprop_password_file` | replica | Exactly one: where the replica's key comes from |
| `kprop_poll_interval` | replica | Time between pulls (deltat, default 60s, ±10% jitter; failures back off from 1s up to this value) |

`kprop_listen` and `kprop_primary` together are a configuration error. A replica needs the same master key stash as the primary. With no local database it pulls before binding its KDC listeners, retrying with backoff; with one it serves immediately and syncs in the background. `krb5-rs-kdb` refuses to modify a replica's database unless given `--force`.

### Deployment

- **Kubernetes** (`deploy/helm/krb5-rs-kdc`): one primary (StatefulSet with a PVC) plus two replicas that pull the database from it, behind a `LoadBalancer` Service on UDP+TCP 88. `realm` is required:

  ```sh
  helm install kdc deploy/helm/krb5-rs-kdc --set realm=EXAMPLE.COM
  ```

  Secrets (master and kprop passwords) are generated on first install and kept; use `secrets.existingSecret` to supply your own. `helm install` prints how to find the address and administer the database. Replicas keep serving while the primary is down; administrative changes wait for it.
- **Podman** (`deploy/podman`): a single pod via `podman kube play` or a Quadlet unit (no replicas). See `deploy/podman/README.md`.
- **Image**: `ghcr.io/exonical/krb5-rs-kdc` (built from `deploy/docker/Dockerfile`, published from `main` and `v*` tags; linux/amd64 for now, arm64 needs an aarch64 musl build). Bootstrap helpers for shell-less containers: `krb5-rs-kdb init` (idempotent database/stash/principal creation from secret files) and `krb5-rs-kdc --master-password-file` (derive the master key instead of reading a stash).

## License

Apache-2.0
