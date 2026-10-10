# krb5-rs

Pure Rust Kerberos V5 implementation. GSSAPI, SPNEGO, PKINIT.

**No C FFI. No system krb5. No libgssapi. Just `cargo add krb5-rs`.**

## Features

- **Kerberos V5 Client** — AS/TGS exchanges (TGT acquisition, service ticket requests), krb5.conf parsing, KDC discovery
- **KDC** — AS/TGS request processing, FAST, UDP/TCP serving (`kdc` feature; see `examples/kdc.rs`)
- **GSSAPI/SPNEGO** — HTTP Negotiate authentication
- **PKINIT** — X.509 certificate-based authentication (planned)
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
| [RFC 4556](https://www.rfc-editor.org/rfc/rfc4556) | PKINIT | Planned |

**Not yet supported:** cross-realm, PAC/authorization data, S4U, PKINIT, DES/RC4/Camellia enctypes.

## License

Apache-2.0
