//! Real DNS resolver for KDC discovery, backed by hickory-resolver on a
//! tokio runtime (feature `dns`).
//!
//! The URI RR type (256) is not modeled by hickory-resolver's typed API, so
//! `uri()` returns an empty answer — matching MIT's behavior on platforms
//! that can't issue URI queries (dnssrv.c:111-120, the _WIN32 stub).

use std::sync::Mutex;

use hickory_resolver::Resolver;

use super::dns::{DnsResolver, SrvRecord, UriRecord};

/// A `DnsResolver` that performs real DNS lookups through hickory-resolver,
/// using the system resolver configuration.
pub struct HickoryResolver {
    /// One current-thread runtime shared by all queries.  The hickory
    /// resolver and its lookups must live on the same executor.
    rt: tokio::runtime::Runtime,
    inner: Mutex<Option<Resolver<hickory_resolver::name_server::TokioConnectionProvider>>>,
}

impl HickoryResolver {
    /// Create a resolver using the system DNS configuration.
    pub fn new() -> std::io::Result<HickoryResolver> {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        Ok(HickoryResolver {
            rt,
            inner: Mutex::new(None),
        })
    }

    fn with_resolver<R>(
        &self,
        f: impl FnOnce(&Resolver<hickory_resolver::name_server::TokioConnectionProvider>) -> R,
    ) -> Result<R, ()> {
        let mut guard = self.inner.lock().map_err(|_| ())?;
        if guard.is_none() {
            let r = Resolver::builder_tokio().map_err(|_| ())?.build();
            *guard = Some(r);
        }
        match guard.as_ref() {
            Some(r) => Ok(f(r)),
            None => Err(()),
        }
    }
}

impl Default for HickoryResolver {
    fn default() -> Self {
        Self::new().expect("tokio runtime")
    }
}

impl DnsResolver for HickoryResolver {
    fn srv(&self, name: &str) -> Result<Vec<SrvRecord>, ()> {
        self.with_resolver(|r| {
            self.rt.block_on(async {
                match r.srv_lookup(name).await {
                    Ok(lookup) => Ok(lookup
                        .iter()
                        .map(|s| SrvRecord {
                            priority: s.priority(),
                            weight: s.weight(),
                            port: s.port(),
                            target: s.target().to_utf8(),
                        })
                        .collect()),
                    Err(_) => Err(()),
                }
            })
        })?
    }

    fn uri(&self, _name: &str) -> Result<Vec<UriRecord>, ()> {
        // URI (type 256) isn't representable in hickory-resolver's typed
        // lookup API; behave like MIT on Windows (dnssrv.c:111-120).
        Ok(Vec::new())
    }
}
