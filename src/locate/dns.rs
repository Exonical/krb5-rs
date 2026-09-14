//! DNS SRV/URI KDC discovery (dnssrv.c, locate_kdc.c locate_uri /
//! dns_locate_server_srv) behind an injectable resolver.

use super::{LocateError, ServerEntry, Transport};

/// A DNS SRV answer.
#[derive(Debug, Clone)]
pub struct SrvRecord {
    /// SRV priority (lower wins).
    pub priority: u16,
    /// SRV weight (unused by MIT's ordering).
    pub weight: u16,
    /// SRV port.
    pub port: u16,
    /// SRV target hostname.
    pub target: String,
}

/// A DNS URI answer (RR type 256).
#[derive(Debug, Clone)]
pub struct UriRecord {
    /// URI priority (lower wins).
    pub priority: u16,
    /// URI weight.
    pub weight: u16,
    /// URI target (e.g. "krb5srv:m:tcp:host:port").
    pub target: String,
}

/// Injectable DNS resolver.  `Err` = query failed (triggers the sitename
/// retry); `Ok(vec![])` = successful empty answer (no retry).
#[allow(clippy::result_unit_err)]
pub trait DnsResolver {
    /// SRV query for `name` (already fully formed, e.g.
    /// "_kerberos._udp.EXAMPLE.COM.").
    fn srv(&self, name: &str) -> Result<Vec<SrvRecord>, ()>;
    /// URI query for `name` (e.g. "_kerberos.EXAMPLE.COM.").
    fn uri(&self, name: &str) -> Result<Vec<UriRecord>, ()>;
}

/// make_lookup_name (dnssrv.c:50-78): `service.[protocol.][site._sites.]realm.`
/// Realm containing NUL -> None; a realm already ending in '.' isn't doubled.
pub fn make_lookup_name(
    realm: &str,
    service: &str,
    protocol: Option<&str>,
    sitename: Option<&str>,
) -> Option<String> {
    if realm.contains('\0') {
        return None;
    }
    let mut s = format!("{service}.");
    if let Some(p) = protocol {
        s.push_str(p);
        s.push('.');
    }
    if let Some(site) = sitename {
        s.push_str(site);
        s.push_str("._sites.");
    }
    s.push_str(realm);
    if !s.ends_with('.') {
        s.push('.');
    }
    Some(s)
}

/// place_srv_entry ordering (dnssrv.c:82-105): ascending priority, entries
/// with equal priority keep insertion order.
pub fn sort_srv(mut records: Vec<SrvRecord>) -> Vec<SrvRecord> {
    records.sort_by_key(|r| r.priority);
    records
}

fn sort_uri(mut records: Vec<UriRecord>) -> Vec<UriRecord> {
    records.sort_by_key(|r| r.priority);
    records
}

/// krb5int_make_srv_query_realm wrapper: query `service.protocol.realm` with
/// the sitename form first, retrying without the site only when the query
/// itself fails (dnssrv.c:288-294).  A successful empty answer does not
/// retry.  Returns the priority-sorted record list.
pub(crate) fn srv_query_realm(
    resolver: &dyn DnsResolver,
    realm: &str,
    service: &str,
    protocol: &str,
    sitename: Option<&str>,
) -> Vec<SrvRecord> {
    if let Some(site) = sitename {
        if let Some(name) = make_lookup_name(realm, service, Some(protocol), Some(site)) {
            if let Ok(v) = resolver.srv(&name) {
                return sort_srv(v);
            }
        }
        // Query failure (or unbuildable name): retry without the site.
    }
    match make_lookup_name(realm, service, Some(protocol), None) {
        Some(n) => resolver.srv(&n).map(sort_srv).unwrap_or_default(),
        None => Vec::new(),
    }
}

/// k5_make_uri_query wrapper: same sitename-retry rule, priority-sorted.
pub(crate) fn uri_query_realm(
    resolver: &dyn DnsResolver,
    realm: &str,
    service: &str,
    sitename: Option<&str>,
) -> Vec<UriRecord> {
    if let Some(site) = sitename {
        if let Some(name) = make_lookup_name(realm, service, None, Some(site)) {
            if let Ok(v) = resolver.uri(&name) {
                return sort_uri(v);
            }
        }
    }
    match make_lookup_name(realm, service, None, None) {
        Some(n) => resolver.uri(&n).map(sort_uri).unwrap_or_default(),
        None => Vec::new(),
    }
}

/// locate_uri (locate_kdc.c:650-711): parse krb5srv: URI answers into
/// server entries.  Problematic entries are skipped; `primary_only` is
/// accepted but, as in MIT 1.22.2, never consulted inside the loop.
pub(crate) fn locate_uri(
    resolver: &dyn DnsResolver,
    realm: &str,
    service: &str,
    sitename: Option<&str>,
    req_transport: Transport,
    default_port: u16,
) -> Vec<ServerEntry> {
    let answers = uri_query_realm(resolver, realm, service, sitename);
    let mut out = Vec::new();
    for ans in answers {
        let (transport, host_field, primary) = match super::uri::parse_uri_fields(&ans.target) {
            Some(t) => t,
            None => continue,
        };
        // TCP_OR_UDP accepts all; otherwise require a transport match.
        if req_transport != Transport::TcpOrUdp && req_transport != transport {
            continue;
        }
        let mut def_port = default_port;
        let mut host_s = host_field;
        let mut path = None;
        if transport == Transport::Https {
            def_port = 443;
            let (t, h, p) = super::uri::parse_uri_if_https(host_field);
            if t != Some(Transport::Https) {
                continue;
            }
            host_s = h;
            path = p;
        }
        let (host, port) = match super::uri::parse_host_string(host_s, def_port) {
            Ok((Some(h), p)) => (h, p),
            _ => continue,
        };
        out.push(ServerEntry {
            hostname: host,
            port,
            transport,
            uri_path: path.map(str::to_string),
            primary: Some(primary),
        });
    }
    out
}

/// locate_srv_dns_1 (locate_kdc.c:357-396): SRV answers for one protocol.
/// Single "."-target answer -> NoService.  SRV hostnames keep the trailing
/// dot MIT appends (dnssrv.c:332).
pub(crate) fn locate_srv_dns(
    resolver: &dyn DnsResolver,
    realm: &str,
    service: &str,
    protocol: &str,
    sitename: Option<&str>,
) -> Result<Vec<ServerEntry>, LocateError> {
    let records = srv_query_realm(resolver, realm, service, protocol, sitename);
    if records.is_empty() {
        return Ok(Vec::new());
    }
    // The "." answer indicating the realm offers no service
    // (locate_kdc.c:379-383): a single empty/root target.
    if records.len() == 1 && (records[0].target.is_empty() || records[0].target == ".") {
        return Err(LocateError::NoService);
    }
    let transport = if protocol == "_tcp" {
        Transport::Tcp
    } else {
        Transport::Udp
    };
    Ok(records
        .into_iter()
        .map(|r| ServerEntry {
            hostname: format!("{}.", r.target.trim_end_matches('.')),
            port: r.port,
            transport,
            uri_path: None,
            primary: None,
        })
        .collect())
}
