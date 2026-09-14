//! Host-to-realm mapping: `host_realm` mirrors krb5_get_host_realm (the
//! profile module's `[domain_realm]` suffix search, hostrealm_profile.c —
//! the domain module has no host_realm method), and `fallback_host_realm`
//! mirrors krb5_get_fallback_host_realm (the domain module's
//! realm_try_domains / parent-domain heuristics, hostrealm_domain.c, then
//! the default realm, hostrealm.c:437-441).

use crate::profile::Profile;

/// clean_hostname (hostrealm.c:301-310): fold to lowercase, strip one
/// trailing dot.
fn clean(host: &str) -> String {
    let mut h = host.to_lowercase();
    if h.ends_with('.') {
        h.pop();
    }
    h
}

/// k5_is_numeric_address (hostrealm.c:318-339): digits+dots with exactly
/// three dots, or any colon.
fn is_numeric_address(name: &str) -> bool {
    if name.bytes().all(|b| b.is_ascii_digit() || b == b'.')
        && name.bytes().filter(|&b| b == b'.').count() == 3
    {
        return true;
    }
    name.contains(':')
}

/// Locate `suffix` as a realm (profile KDC lookup; the domain module uses
/// k5_locate_kdc, which falls back to DNS — our host_realm API is
/// profile-only, so only profile-configured realms count).
fn realm_is_locatable(profile: &Profile, realm: &str) -> bool {
    !profile.get_values(&["realms", realm, "kdc"]).is_empty()
}

/// krb5_get_host_realm: profile `[domain_realm]` suffix search
/// (hostrealm_profile.c:63-74 — try the host, then each suffix, with the
/// pointer landing AT each dot so ".dom" keys match; first match wins).
/// Unmapped hosts return `[""]`, MIT's referral realm (hostrealm.c:391-393).
pub fn host_realm(profile: &Profile, host: &str) -> Vec<String> {
    let host = clean(host);
    if !is_numeric_address(&host) {
        let bytes = host.as_bytes();
        let mut p: Option<usize> = Some(0);
        while let Some(i) = p {
            let suffix = &host[i..];
            if let Some(r) = profile.get_string(&["domain_realm", suffix]) {
                return vec![r];
            }
            p = if bytes[i] == b'.' {
                Some(i + 1)
            } else {
                host[i..].find('.').map(|d| i + d)
            };
        }
    }
    vec![String::new()]
}

/// krb5_get_fallback_host_realm (hostrealm.c:401-447): the domain module's
/// domain_fallback_realm (hostrealm_domain.c:59-104 — the profile module has
/// no fallback method), then the default realm.
pub fn fallback_host_realm(profile: &Profile, host: &str) -> Vec<String> {
    let host = clean(host);

    if !is_numeric_address(&host) {
        let limit = profile
            .get_integer(&["libdefaults", "realm_try_domains"], -1)
            .unwrap_or(-1);
        let uhost = host.to_uppercase();
        // Try progressively shorter suffixes as realms: -1 means no search,
        // 0 means only the full domain, etc.  Stop at a single label.
        let mut suffix = uhost.as_str();
        let mut limit = limit;
        while limit >= 0 {
            limit -= 1;
            let dot = match suffix.find('.') {
                Some(d) => d,
                None => break,
            };
            if realm_is_locatable(profile, suffix) {
                return vec![suffix.to_string()];
            }
            suffix = &suffix[dot + 1..];
        }
        // Upper-cased parent domain, regardless of locatability.
        if let Some(d) = uhost.find('.') {
            return vec![uhost[d + 1..].to_string()];
        }
    }

    // No module handled it: return the default realm.
    default_realm(profile).into_iter().collect()
}

/// `[libdefaults]` default_realm (hostrealm_profile.c:80-97).
pub fn default_realm(profile: &Profile) -> Option<String> {
    profile.get_string(&["libdefaults", "default_realm"])
}

/// `[realms]` `<realm>` default_domain (krb5_get_realm_domain).
pub fn realm_domain(profile: &Profile, realm: &str) -> Option<String> {
    profile.get_string(&["realms", realm, "default_domain"])
}
