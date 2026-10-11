//! TLS for the CockroachDB connection: rustls with the aws-lc-rs provider.
//!
//! aws-lc-rs is chosen for the FIPS 140-3 path: building this crate with
//! rustls's `fips` feature (and the `aws-lc-fips-sys` provider) would switch
//! the module to the validated library. That feature is not enabled here.

use std::sync::Arc;

use krb5_rs::kdc::StoreError;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{ClientConfig, RootCertStore};
use tokio_postgres_rustls::MakeRustlsConnect;

use crate::config::CockroachConfig;

fn tls_err(what: &str, e: impl std::fmt::Display) -> StoreError {
    StoreError::backend(format!("{what}: {e}"))
}

/// A connector verifying the server against `ca` (and presenting the client
/// certificate, if configured).
pub(crate) fn connector(cfg: &CockroachConfig) -> Result<MakeRustlsConnect, StoreError> {
    let mut roots = RootCertStore::empty();
    match &cfg.ca {
        Some(path) => {
            for cert in CertificateDer::pem_file_iter(path)
                .map_err(|e| tls_err("reading cockroach_ca", e))?
            {
                roots
                    .add(cert.map_err(|e| tls_err("parsing cockroach_ca", e))?)
                    .map_err(|e| tls_err("cockroach_ca", e))?;
            }
        }
        None => {
            return Err(StoreError::backend(
                "cockroach_ca is required for a TLS connection",
            ))
        }
    }
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let builder = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| tls_err("TLS protocol versions", e))?
        .with_root_certificates(roots);
    let config = match (&cfg.cert, &cfg.key) {
        (Some(cert), Some(key)) => {
            let chain = CertificateDer::pem_file_iter(cert)
                .map_err(|e| tls_err("reading cockroach_cert", e))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| tls_err("parsing cockroach_cert", e))?;
            let key = PrivateKeyDer::from_pem_file(key)
                .map_err(|e| tls_err("reading cockroach_key", e))?;
            builder
                .with_client_auth_cert(chain, key)
                .map_err(|e| tls_err("client certificate", e))?
        }
        (None, None) => builder.with_no_client_auth(),
        _ => {
            return Err(StoreError::backend(
                "cockroach_cert and cockroach_key must be set together",
            ))
        }
    };
    Ok(MakeRustlsConnect::new(config))
}
