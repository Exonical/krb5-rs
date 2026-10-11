//! Connection settings, read from a kdc.conf `[dbmodules]` section.
//!
//! ```text
//! [dbmodules]
//!     crdb = {
//!         db_library = krb5-rs-cockroach
//!         cockroach_url = postgresql://kdc_replica@crdb:26257/krb5?sslmode=verify-full
//!         cockroach_ca = /etc/krb5-rs/crdb/ca.crt
//!         cockroach_cert = /etc/krb5-rs/crdb/client.kdc_replica.crt
//!         cockroach_key = /etc/krb5-rs/crdb/client.kdc_replica.key
//!         cockroach_pool_size = 8
//!         cockroach_connect_timeout = 5s
//!         cockroach_statement_timeout = 10s
//!         replication_read = follower
//!     }
//! ```

use std::path::PathBuf;
use std::time::Duration;

use krb5_rs::kdc::{DbModuleConfig, StoreError};

/// Which timestamp replication reads use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ReplicationRead {
    /// `follower_read_timestamp()` (about 4.2 s behind): served by the nearest
    /// replica, so cheap in other regions.
    #[default]
    Follower,
    /// The present time: may wait for in-flight writes, and may be served by
    /// the leaseholder in another region.
    Present,
}

/// How to reach CockroachDB.
#[derive(Clone)]
pub struct CockroachConfig {
    /// `postgresql://user[:password]@host:port/database[?sslmode=...]`.
    /// `sslmode` is `verify-full` (the default), `verify-ca` or `require`
    /// (all verify the server certificate chain and name); `disable` needs
    /// `insecure`.
    pub url: String,
    /// PEM CA certificate(s) trusted for the server.
    pub ca: Option<PathBuf>,
    /// PEM client certificate chain.
    pub cert: Option<PathBuf>,
    /// PEM client private key.
    pub key: Option<PathBuf>,
    /// Pooled connections.
    pub pool_size: usize,
    /// Time to connect or to wait for a pooled connection.
    pub connect_timeout: Duration,
    /// Server-side statement timeout, also bounding point reads.
    pub statement_timeout: Duration,
    /// Server-side transaction duration limit (`transaction_timeout`).
    pub transaction_timeout: Duration,
    /// Replication read timestamp.
    pub replication_read: ReplicationRead,
    /// Allow a plaintext connection (`sslmode=disable`). For tests only; a
    /// warning is logged by the callers that open it.
    pub insecure: bool,
}

impl std::fmt::Debug for CockroachConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CockroachConfig")
            .field("url", &redact_url(&self.url))
            .field("ca", &self.ca)
            .field("cert", &self.cert)
            .field("key", &self.key)
            .field("pool_size", &self.pool_size)
            .field("replication_read", &self.replication_read)
            .field("transaction_timeout", &self.transaction_timeout)
            .field("insecure", &self.insecure)
            .finish_non_exhaustive()
    }
}

/// `url` with any password replaced by `***`.
pub fn redact_url(url: &str) -> String {
    let Some((scheme, rest)) = url.split_once("://") else {
        return "<url>".into();
    };
    let Some((auth, host)) = rest.split_once('@') else {
        return url.to_string();
    };
    match auth.split_once(':') {
        Some((user, _)) => format!("{scheme}://{user}:***@{host}"),
        None => url.to_string(),
    }
}

impl CockroachConfig {
    /// Settings for `url` with defaults for the rest.
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            ca: None,
            cert: None,
            key: None,
            pool_size: 8,
            connect_timeout: Duration::from_secs(5),
            statement_timeout: Duration::from_secs(10),
            transaction_timeout: Duration::from_secs(30),
            replication_read: ReplicationRead::Follower,
            insecure: false,
        }
    }

    /// Read the `cockroach_*` and `replication_read` options of a
    /// `[dbmodules]` section.
    pub fn from_db_module(m: &DbModuleConfig) -> Result<Self, StoreError> {
        let mut c = Self::new(
            m.get("cockroach_url")
                .ok_or_else(|| StoreError::backend("cockroach_url is not set"))?,
        );
        c.ca = m.get("cockroach_ca").map(PathBuf::from);
        c.cert = m.get("cockroach_cert").map(PathBuf::from);
        c.key = m.get("cockroach_key").map(PathBuf::from);
        let duration = |key: &str| -> Result<Option<Duration>, StoreError> {
            m.get(key)
                .map(|v| {
                    krb5_rs::profile::string_to_deltat(v)
                        .ok()
                        .and_then(|s| u64::try_from(s).ok())
                        .map(Duration::from_secs)
                        .ok_or_else(|| StoreError::backend(format!("{key}: not a duration")))
                })
                .transpose()
        };
        if let Some(n) = m.get("cockroach_pool_size") {
            c.pool_size = n
                .parse()
                .map_err(|_| StoreError::backend("cockroach_pool_size: not a number"))?;
        }
        if let Some(d) = duration("cockroach_connect_timeout")? {
            c.connect_timeout = d;
        }
        if let Some(d) = duration("cockroach_statement_timeout")? {
            c.statement_timeout = d;
        }
        if let Some(d) = duration("cockroach_transaction_timeout")? {
            c.transaction_timeout = d;
        }
        c.replication_read = match m.get("replication_read") {
            None | Some("follower") => ReplicationRead::Follower,
            Some("present") => ReplicationRead::Present,
            Some(other) => {
                return Err(StoreError::backend(format!(
                    "replication_read: {other:?} is neither follower nor present"
                )))
            }
        };
        c.insecure = matches!(
            m.get("cockroach_insecure")
                .map(str::to_ascii_lowercase)
                .as_deref(),
            Some("true" | "yes" | "on" | "1")
        );
        Ok(c)
    }
}

/// The URL split into what `tokio_postgres` parses and the TLS mode.
pub(crate) struct ParsedUrl {
    pub pg: tokio_postgres::Config,
    pub tls: bool,
}

pub(crate) fn parse_url(cfg: &CockroachConfig) -> Result<ParsedUrl, StoreError> {
    let (base, query) = match cfg.url.split_once('?') {
        Some((b, q)) => (b, q),
        None => (cfg.url.as_str(), ""),
    };
    let mut mode = "verify-full".to_string();
    let mut kept = Vec::new();
    for pair in query.split('&').filter(|p| !p.is_empty()) {
        match pair.split_once('=') {
            Some(("sslmode", v)) => mode = v.to_string(),
            _ => kept.push(pair),
        }
    }
    let tls = match mode.as_str() {
        "verify-full" | "verify-ca" | "require" => true,
        "disable" if cfg.insecure => false,
        "disable" => {
            return Err(StoreError::backend(
                "sslmode=disable is refused; set cockroach_insecure = true for tests only",
            ))
        }
        other => {
            return Err(StoreError::backend(format!(
                "unsupported sslmode {other:?}"
            )))
        }
    };
    if !tls && !cfg.insecure {
        return Err(StoreError::backend("plaintext connections are refused"));
    }
    let url = if kept.is_empty() {
        base.to_string()
    } else {
        format!("{base}?{}", kept.join("&"))
    };
    let mut pg: tokio_postgres::Config = url.parse().map_err(|e: tokio_postgres::Error| {
        StoreError::backend(format!("bad cockroach_url: {e}"))
    })?;
    pg.connect_timeout(cfg.connect_timeout);
    pg.application_name("krb5-rs");
    pg.options(format!(
        "-c statement_timeout={} -c transaction_timeout={}",
        cfg.statement_timeout.as_millis(),
        cfg.transaction_timeout.as_millis(),
    ));
    pg.ssl_mode(if tls {
        tokio_postgres::config::SslMode::Require
    } else {
        tokio_postgres::config::SslMode::Disable
    });
    Ok(ParsedUrl { pg, tls })
}

#[cfg(test)]
mod tests {
    use super::*;
    use krb5_rs::kdc::RealmConfig;
    use krb5_rs::profile::Profile;

    fn module(text: &str) -> DbModuleConfig {
        let kdc = Profile::parse(&format!(
            "[realms]\n R = {{\n  database_module = m\n }}\n[dbmodules]\n m = {{\n{text}\n }}\n"
        ))
        .expect("kdc.conf");
        RealmConfig::from_profiles(&kdc, None, "R")
            .expect("config")
            .db_module
    }

    #[test]
    fn passwords_are_redacted_from_the_url() {
        assert_eq!(
            redact_url("postgresql://kdc:s3cret@crdb:26257/krb5?sslmode=verify-full"),
            "postgresql://kdc:***@crdb:26257/krb5?sslmode=verify-full"
        );
        assert_eq!(
            redact_url("postgresql://kdc@crdb:26257/krb5"),
            "postgresql://kdc@crdb:26257/krb5"
        );
        let c = CockroachConfig::new("postgresql://kdc:s3cret@h:1/d");
        assert!(!format!("{c:?}").contains("s3cret"));
    }

    #[test]
    fn options_come_from_the_dbmodules_section() {
        let m = module(
            "  db_library = krb5-rs-cockroach\n  cockroach_url = postgresql://kdc@crdb:26257/krb5?sslmode=verify-full\n  \
             cockroach_ca = /ca.crt\n  cockroach_pool_size = 3\n  cockroach_connect_timeout = 2s\n  \
             cockroach_statement_timeout = 1m\n  cockroach_transaction_timeout = 30s\n  \
             replication_read = present",
        );
        let c = CockroachConfig::from_db_module(&m).expect("config");
        assert_eq!(c.pool_size, 3);
        assert_eq!(c.connect_timeout, Duration::from_secs(2));
        assert_eq!(c.statement_timeout, Duration::from_secs(60));
        assert_eq!(c.transaction_timeout, Duration::from_secs(30));
        assert_eq!(c.replication_read, ReplicationRead::Present);
        assert!(!c.insecure);
        assert!(CockroachConfig::from_db_module(&module("  db_library = x")).is_err());
        assert!(CockroachConfig::from_db_module(&module(
            "  cockroach_url = postgresql://h/d\n  replication_read = sometimes"
        ))
        .is_err());
    }

    #[test]
    fn plaintext_needs_an_explicit_opt_in_and_unknown_modes_are_refused() {
        let mut c = CockroachConfig::new("postgresql://kdc@h:26257/krb5?sslmode=disable");
        let err = parse_url(&c).err().expect("refused");
        assert!(err.message().contains("refused"), "{err}");
        c.insecure = true;
        assert!(!parse_url(&c).expect("allowed").tls);
        for mode in ["verify-full", "verify-ca", "require"] {
            let c = CockroachConfig::new(format!("postgresql://kdc@h:26257/krb5?sslmode={mode}"));
            assert!(parse_url(&c).expect(mode).tls);
        }
        // No sslmode means verify-full.
        assert!(
            parse_url(&CockroachConfig::new("postgresql://kdc@h:26257/krb5"))
                .expect("default")
                .tls
        );
        assert!(parse_url(&CockroachConfig::new(
            "postgresql://kdc@h/krb5?sslmode=allow"
        ))
        .is_err());
    }
}
