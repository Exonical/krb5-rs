//! KDC/service location (MIT lib/krb5/os/locate_kdc.c): profile entries,
//! then DNS URI records, then SRV records.

mod dns;
#[cfg(feature = "dns")]
mod hickory;
mod hostrealm;
mod uri;

pub use dns::{make_lookup_name, sort_srv, DnsResolver, SrvRecord, UriRecord};
#[cfg(feature = "dns")]
pub use hickory::HickoryResolver;
pub use hostrealm::{default_realm, fallback_host_realm, host_realm, realm_domain};
pub use uri::{is_string_numeric, parse_host_string, parse_uri_fields, parse_uri_if_https};

use crate::profile::Profile;

/// Transport of a located server (k5_transport).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    /// UDP only.
    Udp,
    /// TCP only.
    Tcp,
    /// Profile entries carry the requested transport (TCP_OR_UDP).
    TcpOrUdp,
    /// MS-KKDCP over HTTPS.
    Https,
}

/// One located server (struct server_entry).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerEntry {
    /// Hostname (SRV-derived names keep MIT's trailing dot).
    pub hostname: String,
    /// Port number.
    pub port: u16,
    /// Transport.
    pub transport: Transport,
    /// KKDCP path (e.g. "/KdcProxy") for HTTPS entries.
    pub uri_path: Option<String>,
    /// MIT `primary` field: -1 maps to None, 0/1 to Some(false/true).
    pub primary: Option<bool>,
}

/// Which service to locate (enum locate_service_type).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocateService {
    /// _kerberos / `kdc` profile key, port 88.
    Kdc,
    /// _kerberos-master / `primary_kdc` (falls back to `master_kdc` when the
    /// relation is absent, locate_kdc.c:278-282).
    PrimaryKdc,
    /// _kerberos-adm / `admin_server`, port 749.
    Kadmin,
    /// _kpasswd / `kpasswd_server`, port 464.
    Kpasswd,
}

/// Location errors (k5_locate_server codes).
#[derive(Debug, PartialEq, Eq)]
pub enum LocateError {
    /// Empty realm (KRB5_REALM_CANT_RESOLVE, locate_kdc.c:861-865).
    RealmCantResolve,
    /// No servers found (KRB5_REALM_UNKNOWN, locate_kdc.c:871-877).
    RealmUnknown,
    /// SRV "." answer: realm advertises no service (KRB5_ERR_NO_SERVICE).
    NoService,
    /// Malformed profile entry etc. (EINVAL).
    Invalid(String),
}

impl std::fmt::Display for LocateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LocateError::RealmCantResolve => write!(f, "cannot resolve realm"),
            LocateError::RealmUnknown => write!(f, "unknown realm"),
            LocateError::NoService => write!(f, "no service"),
            LocateError::Invalid(m) => write!(f, "invalid server spec: {m}"),
        }
    }
}

impl std::error::Error for LocateError {}

/// Profile key + default port + DNS service name per service.
fn service_info(svc: LocateService) -> (&'static str, u16, &'static str) {
    match svc {
        LocateService::Kdc => ("kdc", 88, "_kerberos"),
        LocateService::PrimaryKdc => ("primary_kdc", 88, "_kerberos-master"),
        LocateService::Kadmin => ("admin_server", 749, "_kerberos-adm"),
        LocateService::Kpasswd => ("kpasswd_server", 464, "_kpasswd"),
    }
}

/// KDC locator bound to a profile and an optional injected DNS resolver.
pub struct Locator<'a> {
    profile: &'a Profile,
    dns: Option<&'a dyn DnsResolver>,
}

impl<'a> Locator<'a> {
    /// Create a locator; `dns` None disables all DNS discovery.
    pub fn new(profile: &'a Profile, dns: Option<&'a dyn DnsResolver>) -> Locator<'a> {
        Locator { profile, dns }
    }

    /// maybe_use_dns (locate_kdc.c:51-73): named key, else dns_fallback,
    /// else `default`.
    fn use_dns(&self, name: &str, default: bool) -> bool {
        let v = self
            .profile
            .get_string(&["libdefaults", name])
            .or_else(|| self.profile.get_string(&["libdefaults", "dns_fallback"]));
        match v.as_deref().and_then(crate::profile::conf_boolean) {
            Some(b) => b,
            None => default,
        }
    }

    /// use_dns_uri (locate_kdc.c:76-85): dns_uri_lookup only, default TRUE.
    fn use_dns_uri(&self) -> bool {
        self.profile
            .get_boolean(&["libdefaults", "dns_uri_lookup"], true)
            .unwrap_or(true)
    }

    fn sitename(&self, realm: &str) -> Option<String> {
        self.profile.get_string(&["realms", realm, "sitename"])
    }

    /// locate_srv_conf_1 (locate_kdc.c:254-338): profile entries for the
    /// service.  '/'-prefixed entries are UNIX sockets — represented as a
    /// host entry with port 0/Tcp per the settled interface.
    fn profile_servers(
        &self,
        realm: &str,
        key: &str,
        transport: Transport,
        udpport: u16,
    ) -> Result<Vec<ServerEntry>, LocateError> {
        let mut specs = self.profile.get_values(&["realms", realm, key]);
        if specs.is_empty() && key == "primary_kdc" {
            // master_kdc only when primary_kdc is absent
            // (locate_kdc.c:278-282).
            specs = self.profile.get_values(&["realms", realm, "master_kdc"]);
        }
        let mut out = Vec::new();
        for spec in specs {
            if spec.starts_with('/') {
                out.push(ServerEntry {
                    hostname: spec.clone(),
                    port: 0,
                    transport: Transport::Tcp,
                    uri_path: None,
                    primary: None,
                });
                continue;
            }
            let (t, host_field, path) = uri::parse_uri_if_https(&spec);
            let this_transport = t.unwrap_or(transport);
            let default_port = if this_transport == Transport::Https {
                443
            } else {
                udpport
            };
            let (host, port) = uri::parse_host_string(host_field, default_port)?;
            let host = host.ok_or_else(|| LocateError::Invalid(spec.clone()))?;
            out.push(ServerEntry {
                hostname: host,
                port,
                transport: this_transport,
                uri_path: path.map(str::to_string),
                primary: None,
            });
        }
        Ok(out)
    }

    /// locate_server + k5_locate_server (locate_kdc.c:801-879): profile
    /// first; if empty and DNS enabled, URI records, then SRV _udp/_tcp.
    pub fn locate_server(
        &self,
        realm: &str,
        svc: LocateService,
        no_udp: bool,
    ) -> Result<Vec<ServerEntry>, LocateError> {
        if realm.is_empty() {
            return Err(LocateError::RealmCantResolve);
        }
        let transport = if no_udp {
            Transport::Tcp
        } else {
            Transport::TcpOrUdp
        };
        let (key, dfl_port, dnsname) = service_info(svc);

        let mut list = self.profile_servers(realm, key, transport, dfl_port)?;

        if list.is_empty() {
            if let Some(resolver) = self.dns {
                let site = self.sitename(realm);
                if self.use_dns("dns_lookup_kdc", true) {
                    // URI first when enabled (dns_locate_server_uri).
                    let uri_svc = match svc {
                        LocateService::Kdc | LocateService::PrimaryKdc => "_kerberos",
                        LocateService::Kadmin => "_kerberos-adm",
                        LocateService::Kpasswd => "_kpasswd",
                    };
                    if self.use_dns_uri() {
                        list = dns::locate_uri(
                            resolver,
                            realm,
                            uri_svc,
                            site.as_deref(),
                            transport,
                            dfl_port,
                        );
                    }
                    if list.is_empty() {
                        // SRV: _udp then _tcp (locate_kdc.c:787-792).
                        if transport != Transport::Tcp {
                            list = dns::locate_srv_dns(
                                resolver,
                                realm,
                                dnsname,
                                "_udp",
                                site.as_deref(),
                            )?;
                        }
                        if transport != Transport::Udp {
                            let mut tcp = dns::locate_srv_dns(
                                resolver,
                                realm,
                                dnsname,
                                "_tcp",
                                site.as_deref(),
                            )?;
                            list.append(&mut tcp);
                        }
                    }
                }
            }
        }

        if list.is_empty() {
            return Err(LocateError::RealmUnknown);
        }
        Ok(list)
    }

    /// k5_locate_kdc (locate_kdc.c:881-890).
    pub fn locate_kdc(
        &self,
        realm: &str,
        get_primaries: bool,
        no_udp: bool,
    ) -> Result<Vec<ServerEntry>, LocateError> {
        let svc = if get_primaries {
            LocateService::PrimaryKdc
        } else {
            LocateService::Kdc
        };
        self.locate_server(realm, svc, no_udp)
    }
}
