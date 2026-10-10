//! MIT "retry with primary KDCs" rule (get_in_tkt.c:2005-2050).
//!
//! After a non-successful AS/TGS result that is *not* a reachability
//! error, if any contacted KDC was a replica the request is retried once
//! using only primary KDCs.  If the retry itself fails with an
//! unreachability/realm error, the *original* error is returned.

use std::future::Future;

use crate::error::Krb5Error;
use crate::locate::LocateError;
use crate::transport::located::LocatedTransport;
use crate::transport::sendto::SendtoError;
use crate::transport::KdcTransport;

/// get_in_tkt.c:2030-2034: errors for which the primary retry is *not*
/// attempted — KDC_UNREACH and REALM_CANT_RESOLVE (the MIT list also has
/// password-interruption codes that do not exist here).
pub fn is_unreach(e: &Krb5Error) -> bool {
    matches!(
        e,
        Krb5Error::Sendto(SendtoError::KdcUnreach)
            | Krb5Error::Locate(LocateError::RealmCantResolve)
    )
}

/// Retry `retry` against primary KDCs only when `first` failed with a
/// non-unreachability error and the transport's recorded KDCs include a
/// replica.
///
/// get_in_tkt.c:2035-2044: if the retry returns KDC_UNREACH,
/// REALM_CANT_RESOLVE or REALM_UNKNOWN the original error is returned;
/// otherwise the retry's result (success or error) wins.
pub async fn with_primary_fallback<F, Fut, T>(
    transport: &LocatedTransport,
    first: Result<T, Krb5Error>,
    retry: F,
) -> Result<T, Krb5Error>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = Result<T, Krb5Error>>,
{
    let orig = match first {
        Ok(v) => return Ok(v),
        Err(e) if is_unreach(&e) => return Err(e),
        Err(e) => e,
    };
    if !transport.any_replicas() {
        return Err(orig);
    }
    transport.set_use_primary(true);
    let r = retry().await;
    transport.set_use_primary(false);
    match r {
        Err(
            Krb5Error::Sendto(SendtoError::KdcUnreach)
            | Krb5Error::Locate(LocateError::RealmCantResolve)
            | Krb5Error::Locate(LocateError::RealmUnknown),
        ) => Err(orig),
        r => r,
    }
}

/// Single request/response against a realm's KDCs with the MIT primary
/// fallback applied.
pub async fn get_tgt(
    transport: &LocatedTransport,
    realm: &str,
    message: &[u8],
) -> Result<Vec<u8>, Krb5Error> {
    let first = transport.send_recv(realm, message).await;
    with_primary_fallback(transport, first, || transport.send_recv(realm, message)).await
}

impl crate::client::KerberosClient<LocatedTransport> {
    /// `acquire_tgt` with the MIT "retry with primary KDCs" rule applied to
    /// the whole AS exchange (get_in_tkt.c:2005-2050).
    pub async fn acquire_tgt_primary(
        &self,
        principal: &str,
        password: &str,
    ) -> Result<crate::protocol::Credential, Krb5Error> {
        let first = self.acquire_tgt(principal, password).await;
        with_primary_fallback(&self.transport, first, || {
            self.acquire_tgt(principal, password)
        })
        .await
    }
}
