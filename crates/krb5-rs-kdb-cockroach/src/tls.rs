//! TLS for the CockroachDB connection: rustls with the aws-lc-rs provider.
//!
//! aws-lc-rs is chosen for the FIPS 140-3 path: building this crate with
//! rustls's `fips` feature (and the `aws-lc-fips-sys` provider) would switch
//! the module to the validated library. That feature is not enabled here.

use std::path::Path;
use std::sync::Arc;

use krb5_rs::kdc::StoreError;
use rustls::pki_types::pem::{Error as PemError, PemObject};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{ClientConfig, RootCertStore};
use tokio_postgres_rustls::MakeRustlsConnect;

use crate::config::CockroachConfig;

fn tls_err(what: &str, e: impl std::fmt::Display) -> StoreError {
    StoreError::backend(format!("{what}: {e}"))
}

fn read_certificates(path: &Path, name: &str) -> Result<Vec<CertificateDer<'static>>, StoreError> {
    let certs = CertificateDer::pem_file_iter(path)
        .map_err(|e| cert_file_error(name, path, e))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| cert_file_error(name, path, e))?;
    if certs.is_empty() {
        return Err(StoreError::backend(format!(
            "reading {name} {}: no PEM certificate found",
            path.display()
        )));
    }
    Ok(certs)
}

fn cert_file_error(name: &str, path: &Path, error: PemError) -> StoreError {
    if matches!(&error, PemError::Io(_)) {
        tls_err(&format!("reading {name} {}", path.display()), error)
    } else {
        StoreError::backend(format!(
            "reading {name} {}: no PEM certificate found: {error}",
            path.display()
        ))
    }
}

fn read_private_key(path: &Path) -> Result<PrivateKeyDer<'static>, StoreError> {
    PrivateKeyDer::from_pem_file(path).map_err(|error| match error {
        PemError::NoItemsFound => StoreError::backend(format!(
            "reading cockroach_key {}: no PEM private key found (expected PKCS#8, PKCS#1 or SEC1 \"-----BEGIN … PRIVATE KEY-----\")",
            path.display()
        )),
        error => tls_err(
            &format!("reading cockroach_key {}", path.display()),
            error,
        ),
    })
}

/// A connector verifying the server against `ca` (and presenting the client
/// certificate, if configured).
pub(crate) fn connector(cfg: &CockroachConfig) -> Result<MakeRustlsConnect, StoreError> {
    let mut roots = RootCertStore::empty();
    match &cfg.ca {
        Some(path) => {
            for cert in read_certificates(path, "cockroach_ca")? {
                roots
                    .add(cert)
                    .map_err(|e| tls_err(&format!("cockroach_ca {}", path.display()), e))?;
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
            let chain = read_certificates(cert, "cockroach_cert")?;
            let private_key = read_private_key(key)?;
            builder
                .with_client_auth_cert(chain, private_key)
                .map_err(|e| {
                    tls_err(
                        &format!(
                            "client certificate {} with key {}",
                            cert.display(),
                            key.display()
                        ),
                        e,
                    )
                })?
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn garbage_private_key_reports_path_and_accepted_pem_formats() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("garbage.key");
        std::fs::write(&path, b"not a private key").expect("write key");

        let error = match read_private_key(&path) {
            Err(error) => error.to_string(),
            Ok(_) => panic!("garbage key accepted"),
        };
        assert!(error.contains(&path.display().to_string()));
        assert!(error.contains(
            "no PEM private key found (expected PKCS#8, PKCS#1 or SEC1 \"-----BEGIN … PRIVATE KEY-----\")"
        ));
        assert!(!error.contains("not a private key"));
    }

    #[test]
    fn garbage_ca_and_client_certificates_report_the_path_and_pem_hint() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("garbage.crt");
        std::fs::write(&path, b"not a certificate").expect("write certificate");

        for name in ["cockroach_ca", "cockroach_cert"] {
            let error = match read_certificates(&path, name) {
                Err(error) => error.to_string(),
                Ok(_) => panic!("garbage certificate accepted"),
            };
            assert!(error.contains(&path.display().to_string()));
            assert!(error.contains(&format!(
                "reading {name} {}: no PEM certificate found",
                path.display()
            )));
            assert!(!error.contains("not a certificate"));
        }
    }
}
