//! Value formats kldap uses in directory attributes (ldap_misc.c,
//! ldap_principal.c, ldap_realm.c).

use krb5_rs::kdc::kdb::mit::{parse_name, unparse_name, TlData};
use krb5_rs::kdc::store::StoreError;
use krb5_rs::types::PrincipalName;

/// `ldap_filter_correct` (ldap_realm.c:75-93): escape filter and RDN
/// specials as `\xx`.
pub fn filter_correct(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if "*()\\ #\"+,;<>".contains(c) {
            out.push_str(&format!("\\{:2x}", c as u32));
        } else {
            out.push(c);
        }
    }
    out
}

/// `krb5_ldap_unparse_name` (ldap_principal.c:589-607): the unparsed name
/// without backslashes before `@`.
pub fn ldap_unparse_name(name: &PrincipalName, realm: &str) -> String {
    let s = String::from_utf8_lossy(&unparse_name(name, realm)).into_owned();
    s.replace("\\@", "@")
}

/// `krb5_ldap_parse_name` (ldap_principal.c:611-646): escape every `@`
/// but the last, then parse.
pub fn ldap_parse_name(s: &str) -> Result<(PrincipalName, String), StoreError> {
    let princ = match s.rfind('@') {
        None => s.to_string(),
        Some(at) => format!("{}{}", s[..at].replace('@', "\\@"), &s[at..]),
    };
    parse_name(princ.as_bytes())
}

fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (m + if m > 2 { -3 } else { 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// `getstringtime` (ldap_principal2.c:1809-1826): `%Y%m%d%H%M%SZ` in UTC.
pub fn string_time(t: u32) -> String {
    let secs = i64::from(t);
    let (days, rem) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}{m:02}{d:02}{:02}{:02}{:02}Z",
        rem / 3600,
        rem / 60 % 60,
        rem % 60
    )
}

/// `getepochtime` (ldap_misc.c:912-926).
pub fn epoch_time(s: &str) -> Result<u32, StoreError> {
    let bad = || StoreError::corrupt(format!("invalid generalized time {s:?}"));
    let b = s.as_bytes();
    if b.len() < 15 || b[14] != b'Z' || !b[..14].iter().all(u8::is_ascii_digit) {
        return Err(bad());
    }
    let n = |r: std::ops::Range<usize>| s[r].parse::<i64>().map_err(|_| bad());
    let days = days_from_civil(n(0..4)?, n(4..6)?, n(6..8)?);
    let t = days * 86_400 + n(8..10)? * 3600 + n(10..12)? * 60 + n(12..14)?;
    u32::try_from(t).map_err(|_| bad())
}

/// `tl_data2berval` (ldap_principal2.c:626-646): big-endian type, then data.
pub fn tl_to_value(tl: &TlData) -> Vec<u8> {
    let mut v = tl.kind.to_be_bytes().to_vec();
    v.extend_from_slice(&tl.data);
    v
}

/// `berval2tl_data` (ldap_principal2.c:81-100).
pub fn tl_from_value(v: &[u8]) -> Result<TlData, StoreError> {
    if v.len() < 2 {
        return Err(StoreError::corrupt("krbExtraData value too short"));
    }
    Ok(TlData {
        kind: u16::from_be_bytes([v[0], v[1]]),
        data: v[2..].to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn times() {
        assert_eq!(string_time(0), "19700101000000Z");
        assert_eq!(string_time(1_700_000_000), "20231114221320Z");
        assert_eq!(epoch_time("20231114221320Z").unwrap(), 1_700_000_000);
        assert_eq!(epoch_time("20000229123456Z").unwrap(), 951_827_696);
        assert!(epoch_time("2023").is_err());
    }

    #[test]
    fn filter_escaping() {
        assert_eq!(
            filter_correct("a*b(c)\\ d#e\"f+g,h;i<j>"),
            "a\\2ab\\28c\\29\\5c\\20d\\23e\\22f\\2bg\\2ch\\3bi\\3cj\\3e"
        );
    }

    #[test]
    fn names() {
        let (p, r) = ldap_parse_name("a@b@EXAMPLE.COM").unwrap();
        assert_eq!(r, "EXAMPLE.COM");
        assert_eq!(ldap_unparse_name(&p, &r), "a@b@EXAMPLE.COM");
    }

    #[test]
    fn extra_data() {
        let tl = TlData {
            kind: 0x0102,
            data: vec![9, 8],
        };
        assert_eq!(tl_to_value(&tl), vec![1, 2, 9, 8]);
        assert_eq!(tl_from_value(&tl_to_value(&tl)).unwrap(), tl);
    }
}
