//! Host-string and krb5srv URI field parsing.
//! Mirrors lib/krb5/krb/parse_host_string.c and the URI helpers in
//! lib/krb5/os/locate_kdc.c (parse_uri_fields, parse_uri_if_https).

use super::{LocateError, Transport};

/// k5_is_string_numeric (parse_host_string.c:36-49): all digits, nonempty.
pub fn is_string_numeric(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
}

fn parse_port(s: &str) -> Result<u16, LocateError> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return Err(LocateError::Invalid(format!("bad port {s:?}")));
    }
    s.parse::<u16>()
        .map_err(|_| LocateError::Invalid(format!("port out of range {s:?}")))
}

/// k5_parse_host_string (parse_host_string.c:51-123).
///
/// Grammar: `host[:port]`, numeric-only `port`, or `[v6host][:port]`.
/// A numeric-only string is a port with no host; `host` is bounded by the
/// first space, tab, or colon.  Empty string, leading ':', and bad or
/// out-of-range ports are errors.
pub fn parse_host_string(s: &str, default_port: u16) -> Result<(Option<String>, u16), LocateError> {
    let invalid = |m: &str| LocateError::Invalid(m.to_string());
    if s.is_empty() || s.starts_with(':') {
        return Err(invalid("empty or missing host"));
    }
    if is_string_numeric(s) {
        let port = parse_port(s)?;
        return Ok((None, port));
    }
    let (host, rest) = if let Some(after) = s.strip_prefix('[') {
        let close = after.find(']').ok_or_else(|| invalid("unclosed '['"))?;
        let host = &after[..close];
        let rest = &after[close + 1..];
        if !(rest.is_empty() || rest.starts_with(':')) {
            return Err(invalid("garbage after ']'"));
        }
        (host, rest)
    } else {
        match s.find([' ', '\t', ':']) {
            Some(i) => (&s[..i], &s[i..]),
            None => (s, ""),
        }
    };
    let port = if let Some(p) = rest.strip_prefix(':') {
        parse_port(p)?
    } else if rest.is_empty() {
        default_port
    } else {
        return Err(invalid("garbage after host"));
    };
    if host.is_empty() {
        return Err(invalid("empty host"));
    }
    Ok((Some(host.to_string()), port))
}

/// parse_uri_fields (locate_kdc.c:589-644): `krb5srv:flags:udp|tcp|kkdcp:host`,
/// scheme and transport case-insensitive, 'm'/'M' flag marks primary.
/// Returns (transport, host_field, primary); None on any parse failure.
pub fn parse_uri_fields(uri: &str) -> Option<(Transport, &str, bool)> {
    let rest = uri.get(..7).filter(|p| p.eq_ignore_ascii_case("krb5srv"))?;
    let uri = &uri[rest.len()..];
    let uri = uri.strip_prefix(':')?;
    if uri.is_empty() {
        return None;
    }
    // Flags field: any 'm'/'M' before the next ':' -> primary.
    let colon = uri.find(':')?;
    let primary = uri[..colon].contains(['m', 'M']);
    let uri = &uri[colon + 1..];

    let (transport, uri) = if uri.len() >= 3 && uri[..3].eq_ignore_ascii_case("udp") {
        (Transport::Udp, &uri[3..])
    } else if uri.len() >= 3 && uri[..3].eq_ignore_ascii_case("tcp") {
        (Transport::Tcp, &uri[3..])
    } else if uri.len() >= 5 && uri[..5].eq_ignore_ascii_case("kkdcp") {
        (Transport::Https, &uri[5..])
    } else {
        return None;
    };
    let host = uri.strip_prefix(':')?;
    Some((transport, host, primary))
}

/// parse_uri_if_https (locate_kdc.c:217-232): if `s` starts with
/// "https://", return (Some(Https), host, Some(path)) where host is the part
/// after the scheme up to the first '/', and path is the remainder starting
/// at '/'.  Otherwise (None, s, None).
pub fn parse_uri_if_https(s: &str) -> (Option<Transport>, &str, Option<&str>) {
    if let Some(rest) = s.strip_prefix("https://") {
        match rest.find('/') {
            Some(i) => (Some(Transport::Https), &rest[..i], Some(&rest[i..])),
            None => (Some(Transport::Https), rest, None),
        }
    } else {
        (None, s, None)
    }
}
