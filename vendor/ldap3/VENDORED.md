# Vendored ldap3 0.12.1

Copied from crates.io `ldap3` 0.12.1 (MIT/Apache-2.0) for krb5-rs's LDAP KDB
module. Changes from upstream:

- `Ldap::sasl_bind_step` sends one SASL Bind request for any mechanism and
  returns the server's challenge, so SASL mechanisms can be driven from
  outside the crate (MIT's kldap uses Cyrus SASL's interactive bind for this).
- `Ldap::install_sasl_layer` and the `SaslSecurityLayer` trait replace the
  `cross-krb5` GSSAPI security layer, so any negotiated SASL layer (GSSAPI,
  DIGEST-MD5) wraps later PDUs.
- The `gssapi` and `ntlm` features, which link C GSSAPI / SSPI, are removed.
- The `tls`/`tls-native` (native-tls) and `tls-rustls-aws-lc-rs` features are
  removed; only `tls-rustls-ring` remains, so `--all-features` builds in the
  krb5-rs workspace (the vendored crate is a workspace member as a path
  dependency). Their `cfg`s are rewritten to `any()`.
- Examples are removed, and clippy is silenced for the vendored code.
