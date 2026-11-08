//! Real DNS resolver for KDC discovery and TXT realm lookups, backed by hickory-resolver on a
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
    /// Always `Some` until `drop`.
    rt: Option<tokio::runtime::Runtime>,
    inner: Mutex<Option<Resolver<hickory_resolver::name_server::TokioConnectionProvider>>>,
}

/// Dropping a runtime inside another runtime's async context panics, so
/// shut it down without waiting for its blocking pool.
impl Drop for HickoryResolver {
    fn drop(&mut self) {
        if let Some(rt) = self.rt.take() {
            rt.shutdown_background();
        }
    }
}

impl HickoryResolver {
    /// Create a resolver using the system DNS configuration.
    pub fn new() -> std::io::Result<HickoryResolver> {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        Ok(HickoryResolver {
            rt: Some(rt),
            inner: Mutex::new(None),
        })
    }

    /// Run `fut` to completion on this resolver's runtime.  Inside another
    /// tokio runtime `block_on` would panic, so the query then runs on a
    /// scoped thread, blocking the caller as MIT's res_nsearch does.
    fn block_on<F: std::future::Future + Send>(&self, fut: F) -> F::Output
    where
        F::Output: Send,
    {
        if tokio::runtime::Handle::try_current().is_ok() {
            std::thread::scope(|s| {
                s.spawn(|| self.rt().block_on(fut))
                    .join()
                    .unwrap_or_else(|p| std::panic::resume_unwind(p))
            })
        } else {
            self.rt().block_on(fut)
        }
    }

    #[allow(clippy::expect_used)]
    fn rt(&self) -> &tokio::runtime::Runtime {
        self.rt.as_ref().expect("runtime present until drop")
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
            self.block_on(async {
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

    fn txt(&self, name: &str) -> Result<Vec<String>, ()> {
        self.with_resolver(|r| {
            self.block_on(async {
                match r.txt_lookup(name).await {
                    Ok(lookup) => Ok(lookup
                        .iter()
                        .filter_map(|t| t.txt_data().first())
                        .map(|d| String::from_utf8_lossy(d).into_owned())
                        .collect()),
                    Err(_) => Err(()),
                }
            })
        })?
    }
}
