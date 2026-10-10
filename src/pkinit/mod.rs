//! PKINIT (RFC 4556, RFC 8636, RFC 8070) following MIT krb5 1.22
//! src/plugins/preauth/pkinit/.
//!
//! Like MIT 1.22 this implements only the Diffie-Hellman/ECDH reply
//! (`dhInfo`, groups MODP 2/14/16 and P-256/384/521); the RSA key-transport
//! reply (`encKeyPack`, "Unsupported PKINIT RSA request") and the draft-9
//! PA-PK-AS-REQ-OLD/REP-OLD types (14/15) do not exist in 1.22 either.
//!
//! Modules: [`kex`] (groups, key agreement, octetstring2key and the RFC 8636
//! KDFs), [`x509`] (certificates, keys, OpenSSL-style path validation with
//! CRLs), [`cms`] (SignedData), [`server`] and [`client`] (the protocol
//! halves). A test-only certificate issuer (`pki`, feature `test-pki`) is
//! not part of normal builds.
//!
//! Not implemented, as in or beyond MIT: `pkinit_cert_match` and the
//! `dbmatch` certauth module, anonymous PKINIT (RFC 6112), OCSP (MIT has none
//! either), PKCS#11 and PKCS#12 identities, encrypted private keys, CRLs
//! carried inside the CMS message, X.509 name constraints, attribute
//! certificates, and authentication indicators (`pkinit_indicator` is stored
//! but not asserted). Certificate names are compared by their DER encoding.

pub mod asn1;
pub mod client;
pub mod cms;
mod der;
mod groups_data;
pub mod kex;
mod pem;
#[cfg(any(test, feature = "test-pki"))]
#[doc(hidden)]
pub mod pki;
#[cfg(any(test, feature = "test-pki"))]
mod pki_keys;
pub mod server;
pub mod x509;

pub use kex::{Group, Kdf, KexError};
