# PKINIT test PKI

TEST-ONLY certificates and private keys for the PKINIT interop tests
(`tests/kdc_pkinit_live.rs`). The private keys are unprotected and are
committed on purpose: **never trust `ca.pem` or reuse any of these keys
outside the test containers.**

| File | Purpose |
| --- | --- |
| `ca.pem` | Trust anchor ("krb5-rs PKINIT Test CA") |
| `rogue-ca.pem` | A second CA nobody trusts; signs the `rogue-*` certificates |
| `kdc-test-realm.pem`, `kdc-pki-realm.pem`, `kdc-key.pem` | KDC certificates (SAN `krbtgt/REALM@REALM`, id-pkinit-KPKdc) for MIT's TEST.REALM and for our KDC's PKI.REALM |
| `testuser-rsa.pem`, `testuser-ec.pem` | Client certificates for `testuser@TEST.REALM` (MIT KDC) |
| `pkiuser-rsa.pem`, `pkiuser-ec.pem`, `pkiuser-upn-rsa.pem` | Client certificates for `pkiuser@PKI.REALM` (our KDC); the last has only a UPN SAN |
| `otheruser-rsa.pem`, `otheruser-pki-rsa.pem` | Certificates for another principal, to provoke CLIENT_NAME_MISMATCH |
| `rogue-testuser-rsa.pem`, `rogue-pkiuser-rsa.pem` | Valid-looking certificates from the untrusted CA |
| `client-rsa-key.pem`, `client-ec-key.pem` | Keys shared by all RSA / EC client certificates |

All certificates are valid for 20 years from generation. The directory is
mounted at `/pki` in the `kdc` compose service, whose `setup.sh` points
TEST.REALM's `pkinit_identity` and `pkinit_anchors` at it.

## Regenerating

```sh
cargo run --features test-pki --example gen_pkinit_pki -- tests/kdc/pki
```

RSA keys are fixed in the source (`src/pkinit/pki_keys.rs`); the EC key is new
on every run. Recreate the containers afterwards
(`podman compose -p krb5-rs -f docker-compose.test.yml up -d --force-recreate kdc`).
