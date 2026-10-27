//! KDC request policy: validation, ticket flags and times
//! (MIT kdc_util.c validate_as_request / get_ticket_flags /
//! kdc_get_ticket_endtime / kdc_get_ticket_renewtime /
//! select_session_keytype, tgs_policy.c).
//!
//! Timestamps are `i64` seconds; `0` means "absent" and [`KDC_INFINITY`]
//! mirrors MIT's `kdc_infinity` (the largest 32-bit timestamp).

use std::time::Duration;

use chrono::{DateTime, Utc};

use super::db::{KvnoSel, PrincipalAttributes, PrincipalEntry};
use super::error::KdcError;
use crate::crypto::find_etype;
use crate::types::error_codes::*;
use crate::types::{KdcOptions, KerberosTime, TicketFlags};

/// MIT `kdc_infinity` (extern.c:43, compared as an unsigned timestamp).
pub(crate) const KDC_INFINITY: i64 = u32::MAX as i64;

/// Options that only make sense in TGS requests, plus S4U2Proxy
/// (MIT kdc_util.h `AS_INVALID_OPTIONS`).
pub(crate) const AS_INVALID_OPTIONS: KdcOptions = KdcOptions::FORWARDED
    .union(KdcOptions::PROXY)
    .union(KdcOptions::RENEW)
    .union(KdcOptions::VALIDATE)
    .union(KdcOptions::ENC_TKT_IN_SKEY)
    .union(KdcOptions::CNAME_IN_ADDL_TKT);

/// Options this KDC milestone does not implement; rejected with
/// `KDC_ERR_BADOPTION` instead of being silently ignored.
pub(crate) const UNSUPPORTED_OPTIONS: KdcOptions = KdcOptions::ALLOW_POSTDATE
    .union(KdcOptions::POSTDATED)
    .union(KdcOptions::VALIDATE)
    .union(KdcOptions::PROXY);

/// Realm-wide lifetime limits (MIT `realm_maxlife` / `realm_maxrlife`).
#[derive(Debug, Clone, Copy)]
pub(crate) struct RealmLimits {
    /// Maximum ticket life in seconds; `0` = unlimited.
    pub max_life: i64,
    /// Maximum renewable life in seconds (literal; `0` allows none).
    pub max_renewable_life: i64,
}

/// Ticket times in seconds; `starttime` and `renew_till` are `0` when absent.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Times {
    pub authtime: i64,
    pub starttime: i64,
    pub endtime: i64,
    pub renew_till: i64,
}

/// Seconds in `d`, saturating.
pub(crate) fn secs(d: Duration) -> i64 {
    i64::try_from(d.as_secs()).unwrap_or(i64::MAX)
}

/// Seconds since the epoch of a Kerberos time.
pub(crate) fn ts(t: &KerberosTime) -> i64 {
    t.timestamp()
}

/// Kerberos time from epoch seconds (epoch on out-of-range input).
/// Convert unix seconds to the KDC's Kerberos time representation.
pub fn kerberos_time(ts: i64) -> KerberosTime {
    DateTime::<Utc>::from_timestamp(ts, 0)
        .unwrap_or_default()
        .fixed_offset()
}

fn lifetime_cap(d: Option<Duration>) -> Option<i64> {
    d.map(secs).filter(|&s| s != 0)
}

/// `kdc_get_ticket_endtime` (MIT kdc_util.c:1676-1704).
pub(crate) fn get_ticket_endtime(
    limits: &RealmLimits,
    starttime: i64,
    endtime: i64,
    till: i64,
    client: Option<&PrincipalEntry>,
    server: &PrincipalEntry,
) -> i64 {
    let till = if till <= 0 {
        KDC_INFINITY
    } else {
        till.min(KDC_INFINITY)
    };
    let until = till.min(endtime);
    let mut life = (until - starttime).max(i64::from(i32::MIN));
    if until > starttime {
        life = life.min(i64::from(i32::MAX));
    }
    if let Some(cap) = client.and_then(|c| lifetime_cap(c.max_life)) {
        life = life.min(cap);
    }
    if let Some(cap) = lifetime_cap(server.max_life) {
        life = life.min(cap);
    }
    if limits.max_life != 0 {
        life = life.min(limits.max_life);
    }
    starttime + life
}

/// Header-ticket facts `kdc_get_ticket_renewtime` needs for TGS requests.
#[derive(Debug, Clone, Copy)]
pub(crate) struct HeaderRenewal {
    /// Header ticket flags.
    pub flags: TicketFlags,
    /// Header ticket renew-till (`0` if absent).
    pub renew_till: i64,
}

/// `kdc_get_ticket_renewtime` (MIT kdc_util.c:1712-1757).
///
/// `req_rtime` / `req_till` are the raw request values (`0` if absent).
///
/// `PrincipalEntry::max_renewable_life` of `None` means no per-principal cap
/// (API difference: MIT's stored `0` is a literal zero here). The realm limit
/// is literal, so `0` yields `renew_till == starttime`.
#[expect(
    clippy::too_many_arguments,
    reason = "mirrors the MIT kdc_get_ticket_renewtime parameter list"
)]
pub(crate) fn get_ticket_renewtime(
    limits: &RealmLimits,
    opts: KdcOptions,
    req_rtime: i64,
    req_till: i64,
    tgt: Option<HeaderRenewal>,
    client: Option<&PrincipalEntry>,
    server: &PrincipalEntry,
    flags: &mut TicketFlags,
    times: &mut Times,
) {
    flags.remove(TicketFlags::RENEWABLE);
    times.renew_till = 0;

    if server
        .attributes
        .contains(PrincipalAttributes::DISALLOW_RENEWABLE)
    {
        return;
    }
    if client.is_some_and(|c| {
        c.attributes
            .contains(PrincipalAttributes::DISALLOW_RENEWABLE)
    }) {
        return;
    }
    if tgt.is_some_and(|t| !t.flags.contains(TicketFlags::RENEWABLE)) {
        return;
    }

    let mut rtime = if opts.contains(KdcOptions::RENEWABLE) {
        if req_rtime > 0 {
            req_rtime.min(KDC_INFINITY)
        } else {
            KDC_INFINITY
        }
    } else if opts.contains(KdcOptions::RENEWABLE_OK) && req_till > times.endtime {
        req_till.min(KDC_INFINITY)
    } else {
        return;
    };

    if let Some(t) = tgt {
        rtime = rtime.min(t.renew_till);
    }
    let mut max_rlife = limits.max_renewable_life;
    if let Some(s) = server.max_renewable_life {
        max_rlife = max_rlife.min(secs(s));
    }
    if let Some(c) = client.and_then(|c| c.max_renewable_life) {
        max_rlife = max_rlife.min(secs(c));
    }
    rtime = rtime.min(times.starttime.saturating_add(max_rlife));

    if !opts.contains(KdcOptions::RENEWABLE) && rtime <= times.endtime {
        return;
    }
    flags.insert(TicketFlags::RENEWABLE);
    times.renew_till = rtime;
}

pub(crate) fn expired(limit: &Option<KerberosTime>, now: i64) -> bool {
    limit.as_ref().map(ts).is_some_and(|l| l != 0 && now > l)
}

/// `validate_as_request` (MIT kdc_util.c:715-804) plus the milestone's
/// unsupported-option rejection.
pub(crate) fn validate_as_request(
    opts: KdcOptions,
    client: &PrincipalEntry,
    server: &PrincipalEntry,
    now: i64,
) -> Result<(), KdcError> {
    if opts.intersects(AS_INVALID_OPTIONS | UNSUPPORTED_OPTIONS) {
        return Err(KdcError::new(KDC_ERR_BADOPTION, "INVALID AS OPTIONS"));
    }
    if expired(&client.expiration, now) {
        return Err(KdcError::new(KDC_ERR_NAME_EXP, "CLIENT EXPIRED"));
    }
    if expired(&client.pw_expiration, now)
        && !server
            .attributes
            .contains(PrincipalAttributes::PWCHANGE_SERVICE)
    {
        return Err(KdcError::new(KDC_ERR_KEY_EXPIRED, "CLIENT KEY EXPIRED"));
    }
    if expired(&server.expiration, now) {
        return Err(KdcError::new(KDC_ERR_SERVICE_EXP, "SERVICE EXPIRED"));
    }
    if client
        .attributes
        .contains(PrincipalAttributes::REQUIRES_PWCHANGE)
        && !server
            .attributes
            .contains(PrincipalAttributes::PWCHANGE_SERVICE)
    {
        return Err(KdcError::new(KDC_ERR_KEY_EXPIRED, "REQUIRED PWCHANGE"));
    }
    if client
        .attributes
        .contains(PrincipalAttributes::DISALLOW_ALL_TIX)
    {
        return Err(KdcError::new(KDC_ERR_CLIENT_REVOKED, "CLIENT LOCKED OUT"));
    }
    if server
        .attributes
        .contains(PrincipalAttributes::DISALLOW_ALL_TIX)
    {
        return Err(KdcError::new(
            KDC_ERR_S_PRINCIPAL_UNKNOWN,
            "SERVICE LOCKED OUT",
        ));
    }
    if server
        .attributes
        .contains(PrincipalAttributes::DISALLOW_SVR)
    {
        return Err(KdcError::new(
            KDC_ERR_MUST_USE_USER2USER,
            "SERVICE NOT ALLOWED",
        ));
    }
    Ok(())
}

/// `get_ticket_flags` (MIT kdc_util.c:812-858). `header` is the header
/// ticket's flags for TGS requests.
pub(crate) fn get_ticket_flags(
    opts: KdcOptions,
    client: Option<&PrincipalEntry>,
    server: &PrincipalEntry,
    header: Option<TicketFlags>,
) -> TicketFlags {
    if opts.intersects(KdcOptions::VALIDATE | KdcOptions::RENEW) {
        if let Some(h) = header {
            return h & !TicketFlags::INVALID;
        }
    }

    // Every new ticket advertises encrypted-padata support (RFC 6806,
    // kdc_util.c:822-824), whether or not the client sent PA-REQ-ENC-PA-REP.
    let mut flags = TicketFlags::ENC_PA_REP;
    for (opt, flag) in [
        (KdcOptions::FORWARDABLE, TicketFlags::FORWARDABLE),
        (KdcOptions::FORWARDED, TicketFlags::FORWARDED),
        (KdcOptions::PROXIABLE, TicketFlags::PROXIABLE),
        (KdcOptions::PROXY, TicketFlags::PROXY),
        (KdcOptions::ALLOW_POSTDATE, TicketFlags::MAY_POSTDATE),
        (KdcOptions::POSTDATED, TicketFlags::POSTDATED),
        (KdcOptions::REQUEST_ANONYMOUS, TicketFlags::ANONYMOUS),
    ] {
        if opts.contains(opt) {
            flags |= flag;
        }
    }
    match header {
        Some(h) => {
            flags |= h
                & (TicketFlags::FORWARDED
                    | TicketFlags::PROXY
                    | TicketFlags::PRE_AUTHENT
                    | TicketFlags::HW_AUTHENT
                    | TicketFlags::ANONYMOUS);
            if server
                .attributes
                .contains(PrincipalAttributes::OK_AS_DELEGATE)
            {
                flags |= TicketFlags::OK_AS_DELEGATE;
            }
        }
        None => flags |= TicketFlags::INITIAL,
    }

    let denies = |attr: PrincipalAttributes| {
        client.is_some_and(|c| c.attributes.contains(attr)) || server.attributes.contains(attr)
    };
    if denies(PrincipalAttributes::DISALLOW_PROXIABLE)
        || header.is_some_and(|h| !h.contains(TicketFlags::PROXIABLE))
    {
        flags.remove(TicketFlags::PROXIABLE);
    }
    if denies(PrincipalAttributes::DISALLOW_FORWARDABLE)
        || header.is_some_and(|h| !h.contains(TicketFlags::FORWARDABLE))
    {
        flags.remove(TicketFlags::FORWARDABLE);
    }
    // Anonymous tickets are not issued from non-anonymous ones
    // (kdc_util.c:852-855).
    if header.is_some_and(|h| !h.contains(TicketFlags::ANONYMOUS)) {
        flags.remove(TicketFlags::ANONYMOUS);
    }
    flags
}

/// `dbentry_supports_enctype` + `select_session_keytype`
/// (MIT kdc_util.c:1040-1112): the first requested etype that is valid,
/// permitted and supported by the server (aes256-sha1 is assumed
/// supported; otherwise the server needs a key of that etype).
pub(crate) fn select_session_keytype(
    server: &PrincipalEntry,
    requested: &[i32],
    permitted: &dyn Fn(i32) -> bool,
) -> Option<i32> {
    requested.iter().copied().find(|&etype| {
        find_etype(etype).is_ok()
            && permitted(etype)
            && (etype == 18
                || server
                    .find_key(Some(etype), KvnoSel::Highest, permitted)
                    .is_some())
    })
}

/// `check_tgs_opts` (MIT tgs_policy.c:81-105).
pub(crate) fn check_tgs_opts(opts: KdcOptions, header_flags: TicketFlags) -> Result<(), KdcError> {
    let rules = [
        (
            KdcOptions::FORWARDED,
            TicketFlags::FORWARDABLE,
            "TGT NOT FORWARDABLE",
        ),
        (
            KdcOptions::PROXY,
            TicketFlags::PROXIABLE,
            "TGT NOT PROXIABLE",
        ),
        (
            KdcOptions::ALLOW_POSTDATE.union(KdcOptions::POSTDATED),
            TicketFlags::MAY_POSTDATE,
            "TGT NOT POSTDATABLE",
        ),
        (
            KdcOptions::VALIDATE,
            TicketFlags::INVALID,
            "VALIDATE VALID TICKET",
        ),
        (
            KdcOptions::RENEW,
            TicketFlags::RENEWABLE,
            "TICKET NOT RENEWABLE",
        ),
    ];
    for (req, check, status) in rules {
        if opts.intersects(req) && !header_flags.intersects(check) {
            return Err(KdcError::new(KDC_ERR_BADOPTION, status));
        }
    }
    if header_flags.contains(TicketFlags::INVALID) && !opts.contains(KdcOptions::VALIDATE) {
        return Err(KdcError::new(KRB_AP_ERR_TKT_NYV, "TICKET NOT VALID"));
    }
    Ok(())
}

/// `check_tgs_times` renew_till check (MIT tgs_policy.c:220-245).
pub(crate) fn check_tgs_times(
    opts: KdcOptions,
    header_renew_till: i64,
    now: i64,
) -> Result<(), KdcError> {
    if opts.contains(KdcOptions::RENEW) && now > header_renew_till {
        return Err(KdcError::new(KRB_AP_ERR_TKT_EXPIRED, "TKT_EXPIRED"));
    }
    Ok(())
}

/// `check_tgs_svc_policy` (MIT tgs_policy.c:107-215).
pub(crate) fn check_tgs_svc_policy(
    opts: KdcOptions,
    server: &PrincipalEntry,
    header_flags: TicketFlags,
    header_is_tgs: bool,
    now: i64,
) -> Result<(), KdcError> {
    let attrs = server.attributes;
    if opts.contains(KdcOptions::RENEWABLE)
        && attrs.contains(PrincipalAttributes::DISALLOW_RENEWABLE)
    {
        return Err(KdcError::new(KDC_ERR_POLICY, "NON-RENEWABLE TICKET"));
    }
    if opts.contains(KdcOptions::ENC_TKT_IN_SKEY)
        && attrs.contains(PrincipalAttributes::DISALLOW_DUP_SKEY)
    {
        return Err(KdcError::new(KDC_ERR_POLICY, "DUP_SKEY DISALLOWED"));
    }
    if attrs.contains(PrincipalAttributes::DISALLOW_ALL_TIX) {
        return Err(KdcError::new(
            KDC_ERR_S_PRINCIPAL_UNKNOWN,
            "SERVER LOCKED OUT",
        ));
    }
    if attrs.contains(PrincipalAttributes::DISALLOW_SVR)
        && !opts.contains(KdcOptions::ENC_TKT_IN_SKEY)
    {
        return Err(KdcError::new(
            KDC_ERR_MUST_USE_USER2USER,
            "SERVER NOT ALLOWED",
        ));
    }
    if attrs.contains(PrincipalAttributes::DISALLOW_TGT_BASED) && header_is_tgs {
        return Err(KdcError::new(KDC_ERR_POLICY, "TGT BASED NOT ALLOWED"));
    }
    if attrs.contains(PrincipalAttributes::REQUIRES_HW_AUTH)
        && !header_flags.contains(TicketFlags::HW_AUTHENT)
    {
        return Err(KdcError::generic("NO HW PREAUTH"));
    }
    if attrs.contains(PrincipalAttributes::REQUIRES_PRE_AUTH)
        && !header_flags.contains(TicketFlags::PRE_AUTHENT)
    {
        return Err(KdcError::generic("NO PREAUTH"));
    }
    if expired(&server.expiration, now) {
        return Err(KdcError::new(KDC_ERR_SERVICE_EXP, "SERVICE EXPIRED"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::PrincipalName;

    const START: i64 = 1_700_000_000;
    const HOUR: i64 = 3600;

    fn entry() -> PrincipalEntry {
        PrincipalEntry {
            allowed_to_delegate_to: Vec::new(),
            allowed_to_delegate_from: Vec::new(),
            policy: None,
            security_epoch: 0,
            last_admin_unlock: None,
            name: PrincipalName::new_principal("p"),
            realm: "R".into(),
            attributes: PrincipalAttributes::empty(),
            max_life: None,
            max_renewable_life: None,
            expiration: None,
            pw_expiration: None,
            keys: Vec::new(),
        }
    }

    fn limits(max_life: i64, max_renewable_life: i64) -> RealmLimits {
        RealmLimits {
            max_life,
            max_renewable_life,
        }
    }

    #[test]
    fn endtime_request_within_limits_is_honoured() {
        let end = get_ticket_endtime(
            &limits(24 * HOUR, 0),
            START,
            KDC_INFINITY,
            START + 10 * HOUR,
            None,
            &entry(),
        );
        assert_eq!(end, START + 10 * HOUR);
    }

    #[test]
    fn endtime_realm_max_life_caps_request() {
        let end = get_ticket_endtime(
            &limits(HOUR, 0),
            START,
            KDC_INFINITY,
            START + 10 * HOUR,
            None,
            &entry(),
        );
        assert_eq!(end, START + HOUR);
    }

    #[test]
    fn endtime_client_and_server_max_life_cap_request() {
        let mut client = entry();
        client.max_life = Some(Duration::from_secs(1800));
        let mut server = entry();
        server.max_life = Some(Duration::from_secs(900));
        let end = get_ticket_endtime(
            &limits(0, 0),
            START,
            KDC_INFINITY,
            START + 10 * HOUR,
            Some(&client),
            &server,
        );
        assert_eq!(end, START + 900);
    }

    #[test]
    fn endtime_zero_till_means_infinity_capped_by_policy() {
        let end = get_ticket_endtime(&limits(2 * HOUR, 0), START, KDC_INFINITY, 0, None, &entry());
        assert_eq!(end, START + 2 * HOUR);
    }

    #[test]
    fn endtime_header_ticket_endtime_caps_request() {
        let end = get_ticket_endtime(
            &limits(24 * HOUR, 0),
            START,
            START + HOUR,
            START + 10 * HOUR,
            None,
            &entry(),
        );
        assert_eq!(end, START + HOUR);
    }

    #[test]
    fn endtime_zero_max_life_means_unlimited_up_to_i32_max() {
        let end = get_ticket_endtime(&limits(0, 0), START, KDC_INFINITY, 0, None, &entry());
        assert_eq!(end, START + i64::from(i32::MAX));
    }

    fn renew(
        opts: KdcOptions,
        rtime: i64,
        till: i64,
        endtime: i64,
        limits: &RealmLimits,
        server: &PrincipalEntry,
    ) -> (TicketFlags, Times) {
        let mut flags = TicketFlags::RENEWABLE;
        let mut times = Times {
            authtime: START,
            starttime: START,
            endtime,
            renew_till: 0,
        };
        get_ticket_renewtime(
            limits, opts, rtime, till, None, None, server, &mut flags, &mut times,
        );
        (flags, times)
    }

    #[test]
    fn renewtime_requested_renewable_is_capped_by_realm_limit() {
        let (flags, times) = renew(
            KdcOptions::RENEWABLE,
            START + 30 * 24 * HOUR,
            START + 10 * HOUR,
            START + 10 * HOUR,
            &limits(0, 7 * 24 * HOUR),
            &entry(),
        );
        assert!(flags.contains(TicketFlags::RENEWABLE));
        assert_eq!(times.renew_till, START + 7 * 24 * HOUR);
    }

    #[test]
    fn renewtime_zero_realm_limit_sets_renewable_with_renew_till_at_start() {
        let (flags, times) = renew(
            KdcOptions::RENEWABLE,
            0,
            START + HOUR,
            START + HOUR,
            &limits(0, 0),
            &entry(),
        );
        assert!(flags.contains(TicketFlags::RENEWABLE));
        assert_eq!(times.renew_till, START);
    }

    #[test]
    fn renewtime_server_disallow_renewable_drops_renewable() {
        let mut server = entry();
        server.attributes = PrincipalAttributes::DISALLOW_RENEWABLE;
        let (flags, _) = renew(
            KdcOptions::RENEWABLE,
            START + 24 * HOUR,
            START + HOUR,
            START + HOUR,
            &limits(0, 7 * 24 * HOUR),
            &server,
        );
        assert!(!flags.contains(TicketFlags::RENEWABLE));
    }

    #[test]
    fn renewtime_renewable_ok_requires_till_beyond_endtime() {
        let l = limits(0, 7 * 24 * HOUR);
        let (flags, _) = renew(
            KdcOptions::RENEWABLE_OK,
            0,
            START + HOUR,
            START + HOUR,
            &l,
            &entry(),
        );
        assert!(!flags.contains(TicketFlags::RENEWABLE));
        let (flags, times) = renew(
            KdcOptions::RENEWABLE_OK,
            0,
            START + 48 * HOUR,
            START + HOUR,
            &l,
            &entry(),
        );
        assert!(flags.contains(TicketFlags::RENEWABLE));
        assert_eq!(times.renew_till, START + 48 * HOUR);
    }

    #[test]
    fn renewtime_non_renewable_header_drops_renewable() {
        let mut flags = TicketFlags::empty();
        let mut times = Times {
            authtime: START,
            starttime: START,
            endtime: START + HOUR,
            renew_till: 0,
        };
        get_ticket_renewtime(
            &limits(0, 7 * 24 * HOUR),
            KdcOptions::RENEWABLE,
            0,
            0,
            Some(HeaderRenewal {
                flags: TicketFlags::empty(),
                renew_till: START + 24 * HOUR,
            }),
            None,
            &entry(),
            &mut flags,
            &mut times,
        );
        assert!(!flags.contains(TicketFlags::RENEWABLE));
    }

    #[test]
    fn ticket_flags_as_request_sets_initial_and_honours_disallow() {
        let mut client = entry();
        client.attributes = PrincipalAttributes::DISALLOW_FORWARDABLE;
        let f = get_ticket_flags(
            KdcOptions::FORWARDABLE | KdcOptions::PROXIABLE,
            Some(&client),
            &entry(),
            None,
        );
        assert!(f.contains(TicketFlags::INITIAL | TicketFlags::PROXIABLE));
        assert!(!f.contains(TicketFlags::FORWARDABLE));
    }

    #[test]
    fn ticket_flags_tgs_requires_forwardable_header_and_copies_preauth() {
        let header = TicketFlags::PRE_AUTHENT | TicketFlags::INITIAL;
        let f = get_ticket_flags(KdcOptions::FORWARDABLE, None, &entry(), Some(header));
        assert!(f.contains(TicketFlags::PRE_AUTHENT));
        assert!(!f.contains(TicketFlags::FORWARDABLE | TicketFlags::INITIAL));
    }

    #[test]
    fn ticket_flags_tgs_copies_anonymous_only_from_an_anonymous_header() {
        // TGS_COPIED_FLAGS_MASK (kdc_util.h:523-526), kdc_util.c:852-855.
        let anon = Some(TicketFlags::ANONYMOUS | TicketFlags::PRE_AUTHENT);
        let f = get_ticket_flags(KdcOptions::empty(), None, &entry(), anon);
        assert!(f.contains(TicketFlags::ANONYMOUS));
        let named = Some(TicketFlags::PRE_AUTHENT);
        let f = get_ticket_flags(KdcOptions::REQUEST_ANONYMOUS, None, &entry(), named);
        assert!(!f.contains(TicketFlags::ANONYMOUS));
    }

    #[test]
    fn new_tickets_always_advertise_enc_pa_rep() {
        // kdc_util.c:822-824; Windows' klist shows this bit as
        // "name_canonicalize".
        let as_flags = get_ticket_flags(KdcOptions::empty(), Some(&entry()), &entry(), None);
        assert!(as_flags.contains(TicketFlags::ENC_PA_REP | TicketFlags::INITIAL));
        let tgs_flags = get_ticket_flags(
            KdcOptions::empty(),
            None,
            &entry(),
            Some(TicketFlags::PRE_AUTHENT),
        );
        assert!(tgs_flags.contains(TicketFlags::ENC_PA_REP));
        // Renewal keeps the header's flags instead (:818-820).
        let renewed = get_ticket_flags(
            KdcOptions::RENEW,
            None,
            &entry(),
            Some(TicketFlags::RENEWABLE),
        );
        assert!(!renewed.contains(TicketFlags::ENC_PA_REP));
    }

    #[test]
    fn ticket_flags_renew_preserves_header_flags_minus_invalid() {
        let header = TicketFlags::RENEWABLE | TicketFlags::INVALID | TicketFlags::INITIAL;
        let f = get_ticket_flags(KdcOptions::RENEW, None, &entry(), Some(header));
        assert_eq!(f, TicketFlags::RENEWABLE | TicketFlags::INITIAL);
    }

    #[test]
    fn ticket_flags_tgs_sets_ok_as_delegate_from_server() {
        let mut server = entry();
        server.attributes = PrincipalAttributes::OK_AS_DELEGATE;
        let f = get_ticket_flags(
            KdcOptions::empty(),
            None,
            &server,
            Some(TicketFlags::empty()),
        );
        assert!(f.contains(TicketFlags::OK_AS_DELEGATE));
    }

    #[test]
    fn validate_as_request_unsupported_option_is_badoption() {
        for opt in [
            KdcOptions::POSTDATED,
            KdcOptions::ALLOW_POSTDATE,
            KdcOptions::VALIDATE,
            KdcOptions::ENC_TKT_IN_SKEY,
            KdcOptions::PROXY,
            KdcOptions::RENEW,
            KdcOptions::FORWARDED,
        ] {
            let err = validate_as_request(opt, &entry(), &entry(), START).expect_err("reject");
            assert_eq!(err.code, KDC_ERR_BADOPTION);
        }
    }

    #[test]
    fn validate_as_request_expired_client_is_name_exp() {
        let mut client = entry();
        client.expiration = Some(kerberos_time(START - 1));
        let err = validate_as_request(KdcOptions::empty(), &client, &entry(), START)
            .expect_err("expired");
        assert_eq!(err.code, KDC_ERR_NAME_EXP);
    }

    #[test]
    fn validate_as_request_expired_password_is_key_expired_unless_pwchange_service() {
        let mut client = entry();
        client.pw_expiration = Some(kerberos_time(START - 1));
        let err = validate_as_request(KdcOptions::empty(), &client, &entry(), START)
            .expect_err("expired");
        assert_eq!(err.code, KDC_ERR_KEY_EXPIRED);
        let mut server = entry();
        server.attributes = PrincipalAttributes::PWCHANGE_SERVICE;
        assert!(validate_as_request(KdcOptions::empty(), &client, &server, START).is_ok());
    }

    #[test]
    fn validate_as_request_server_flags_map_to_mit_codes() {
        let mut server = entry();
        server.expiration = Some(kerberos_time(START - 1));
        assert_eq!(
            validate_as_request(KdcOptions::empty(), &entry(), &server, START)
                .expect_err("e")
                .code,
            KDC_ERR_SERVICE_EXP
        );
        let mut server = entry();
        server.attributes = PrincipalAttributes::DISALLOW_SVR;
        assert_eq!(
            validate_as_request(KdcOptions::empty(), &entry(), &server, START)
                .expect_err("e")
                .code,
            KDC_ERR_MUST_USE_USER2USER
        );
        let mut client = entry();
        client.attributes = PrincipalAttributes::DISALLOW_ALL_TIX;
        assert_eq!(
            validate_as_request(KdcOptions::empty(), &client, &entry(), START)
                .expect_err("e")
                .code,
            KDC_ERR_CLIENT_REVOKED
        );
        let mut client = entry();
        client.attributes = PrincipalAttributes::REQUIRES_PWCHANGE;
        assert_eq!(
            validate_as_request(KdcOptions::empty(), &client, &entry(), START)
                .expect_err("e")
                .code,
            KDC_ERR_KEY_EXPIRED
        );
    }

    #[test]
    fn select_session_keytype_assumes_aes256_and_requires_key_otherwise() {
        let permit = |_: i32| true;
        assert_eq!(select_session_keytype(&entry(), &[18], &permit), Some(18));
        assert_eq!(select_session_keytype(&entry(), &[20, 19], &permit), None);
        assert_eq!(select_session_keytype(&entry(), &[23], &permit), None);
    }

    #[test]
    fn check_tgs_opts_renew_without_renewable_flag_is_badoption() {
        let err = check_tgs_opts(KdcOptions::RENEW, TicketFlags::empty()).expect_err("reject");
        assert_eq!(err.code, KDC_ERR_BADOPTION);
        assert!(check_tgs_opts(KdcOptions::RENEW, TicketFlags::RENEWABLE).is_ok());
    }

    #[test]
    fn check_tgs_times_renew_after_renew_till_is_expired() {
        let err = check_tgs_times(KdcOptions::RENEW, START, START + 1).expect_err("expired");
        assert_eq!(err.code, KRB_AP_ERR_TKT_EXPIRED);
        assert!(check_tgs_times(KdcOptions::RENEW, START, START).is_ok());
    }
}
