//! `pkinit_cert_match` rules (MIT plugins/preauth/pkinit/pkinit_matching.c):
//! client certificate selection and the KDC's `dbmatch` certauth module.

use super::cms::Identity;
use super::der;
use super::x509::{Cert, San};
use crate::localauth::Regex;
use crate::profile::Profile;

/// `PKINIT_KU_DIGITALSIGNATURE`.
pub const KU_DIGITALSIGNATURE: u32 = 0x8000_0000;
/// `PKINIT_KU_KEYENCIPHERMENT`.
pub const KU_KEYENCIPHERMENT: u32 = 0x4000_0000;
/// `PKINIT_EKU_PKINIT`.
pub const EKU_PKINIT: u32 = 0x8000_0000;
/// `PKINIT_EKU_MSSCLOGIN`.
pub const EKU_MSSCLOGIN: u32 = 0x4000_0000;
/// `PKINIT_EKU_CLIENTAUTH`.
pub const EKU_CLIENTAUTH: u32 = 0x2000_0000;
/// `PKINIT_EKU_EMAILPROTECTION`.
pub const EKU_EMAILPROTECTION: u32 = 0x1000_0000;

/// `MAX_CREDS_ALLOWED`: the most certificates a DIR identity loads.
pub const MAX_CREDS_ALLOWED: usize = 20;

const OID_CLIENT_AUTH: &[u8] = &[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02];
const OID_EMAIL_PROTECT: &[u8] = &[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x04];

const KU_KEYWORDS: &[(&str, u32)] = &[
    ("digitalSignature", KU_DIGITALSIGNATURE),
    ("keyEncipherment", KU_KEYENCIPHERMENT),
];
const EKU_KEYWORDS: &[(&str, u32)] = &[
    ("pkinit", EKU_PKINIT),
    ("msScLogin", EKU_MSSCLOGIN),
    ("clientAuth", EKU_CLIENTAUTH),
    ("emailProtection", EKU_EMAILPROTECTION),
];

/// Why a rule could not be used.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleError {
    /// `EINVAL`: an empty value or an unknown KU/EKU name. A client skips
    /// the rule and tries the next one.
    Invalid,
    /// `ENOENT`: the rule does not start with a keyword.
    NoKeyword,
    /// The regular expression did not compile.
    Regex(String),
}

impl RuleError {
    /// The errno MIT returns.
    pub fn errno(&self) -> i32 {
        match self {
            Self::Invalid => libc_errno::EINVAL,
            Self::NoKeyword => libc_errno::ENOENT,
            Self::Regex(_) => libc_errno::REG_ERROR,
        }
    }
}

mod libc_errno {
    pub const ENOENT: i32 = 2;
    pub const EINVAL: i32 = 22;
    /// regcomp's codes are small positive integers; MIT returns them as is.
    pub const REG_ERROR: i32 = 1;
}

impl std::fmt::Display for RuleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid => f.write_str("invalid pkinit_cert_match rule"),
            Self::NoKeyword => f.write_str("pkinit_cert_match rule has no keyword"),
            Self::Regex(r) => write!(f, "bad regular expression {r:?}"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Relation {
    None,
    And,
    Or,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Keyword {
    Subject,
    Issuer,
    San,
    Eku,
    Ku,
}

const KEYWORDS: &[(&str, Keyword)] = &[
    ("<KU>", Keyword::Ku),
    ("<EKU>", Keyword::Eku),
    ("<SAN>", Keyword::San),
    ("<ISSUER>", Keyword::Issuer),
    ("<SUBJECT>", Keyword::Subject),
];

enum Value {
    Regex(Regex),
    Bits(u32),
}

struct Component {
    kw: Keyword,
    value: Value,
}

/// A parsed `pkinit_cert_match` rule (`rule_set`).
pub struct RuleSet {
    relation: Relation,
    components: Vec<Component>,
}

/// What a rule is checked against (`pkinit_cert_matching_data`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MatchingData {
    /// The subject as `X509_NAME_print_ex(..., XN_FLAG_SEP_COMMA_PLUS)`.
    pub subject_dn: Vec<u8>,
    /// The issuer, formatted the same way.
    pub issuer_dn: Vec<u8>,
    /// id-pkinit-san principals, unparsed.
    pub sans: Vec<String>,
    /// Microsoft UPN SANs.
    pub upns: Vec<String>,
    /// `PKINIT_KU_*` bits.
    pub ku_bits: u32,
    /// `PKINIT_EKU_*` bits.
    pub eku_bits: u32,
}

impl MatchingData {
    /// `get_matching_data` (pkinit_crypto_openssl.c).
    pub fn from_cert(cert: &Cert) -> Self {
        let mut md = MatchingData {
            subject_dn: rfc2253_name(cert.subject_der()),
            issuer_dn: rfc2253_name(cert.issuer_der()),
            ..Default::default()
        };
        for san in cert.sans() {
            match san {
                San::Pkinit(p, realm) => md.sans.push(crate::ccache::unparse_name(&p, &realm)),
                San::Upn(u) => md.upns.push(u),
                San::Dns(_) => {}
            }
        }
        // crypto_retrieve_X509_key_usage.
        for oid in cert.eku().unwrap_or_default() {
            md.eku_bits |= if oid == super::asn1::ID_PKINIT_KP_CLIENT_AUTH {
                EKU_PKINIT
            } else if oid == super::asn1::ID_MS_KP_SC_LOGON {
                EKU_MSSCLOGIN
            } else if oid == OID_CLIENT_AUTH {
                EKU_CLIENTAUTH
            } else if oid == OID_EMAIL_PROTECT {
                EKU_EMAILPROTECTION
            } else {
                0
            };
        }
        if let Some(b) = cert.key_usage_byte() {
            if b & 0x80 != 0 {
                md.ku_bits |= KU_DIGITALSIGNATURE;
            }
            if b & 0x20 != 0 {
                md.ku_bits |= KU_KEYENCIPHERMENT;
            }
        }
        md
    }
}

/// `OBJ_nid2sn` for the attribute types OpenSSL names.
fn short_name(oid: &str) -> Option<&'static str> {
    Some(match oid {
        "2.5.4.3" => "CN",
        "2.5.4.4" => "SN",
        "2.5.4.5" => "serialNumber",
        "2.5.4.6" => "C",
        "2.5.4.7" => "L",
        "2.5.4.8" => "ST",
        "2.5.4.9" => "street",
        "2.5.4.10" => "O",
        "2.5.4.11" => "OU",
        "2.5.4.12" => "title",
        "2.5.4.13" => "description",
        "2.5.4.15" => "businessCategory",
        "2.5.4.17" => "postalCode",
        "2.5.4.41" => "name",
        "2.5.4.42" => "GN",
        "2.5.4.43" => "initials",
        "2.5.4.44" => "generationQualifier",
        "2.5.4.46" => "dnQualifier",
        "2.5.4.65" => "pseudonym",
        "1.2.840.113549.1.9.1" => "emailAddress",
        "0.9.2342.19200300.100.1.1" => "UID",
        "0.9.2342.19200300.100.1.25" => "DC",
        _ => return None,
    })
}

/// Dotted form of OID content bytes (`OBJ_obj2txt` with no_name).
fn dotted(oid: &[u8]) -> String {
    let mut arcs: Vec<u128> = Vec::new();
    let mut v: u128 = 0;
    for &b in oid {
        v = (v << 7) | u128::from(b & 0x7f);
        if b & 0x80 == 0 {
            if arcs.is_empty() {
                let first = (v / 40).min(2);
                arcs.push(first);
                arcs.push(v - first * 40);
            } else {
                arcs.push(v);
            }
            v = 0;
        }
    }
    arcs.iter()
        .map(u128::to_string)
        .collect::<Vec<_>>()
        .join(".")
}

/// `do_esc_char` with no escaping flags.
fn push_char(out: &mut Vec<u8>, c: u32) {
    if c > 0xffff {
        out.extend(format!("\\W{c:08X}").bytes());
    } else if c > 0xff {
        out.extend(format!("\\U{c:04X}").bytes());
    } else {
        out.push(c as u8);
    }
}

/// `do_print_ex` with no `ASN1_STRFLGS` flags: the string's characters by
/// its type's width, unescaped.
fn push_value(out: &mut Vec<u8>, tag: u8, content: &[u8]) {
    match tag {
        0x0C => {
            for ch in String::from_utf8_lossy(content).chars() {
                push_char(out, u32::from(ch));
            }
        }
        0x1E => content
            .chunks(2)
            .for_each(|c| push_char(out, c.iter().fold(0, |a, &b| (a << 8) | u32::from(b)))),
        0x1C => content
            .chunks(4)
            .for_each(|c| push_char(out, c.iter().fold(0, |a, &b| (a << 8) | u32::from(b)))),
        _ => out.extend_from_slice(content),
    }
}

/// `rfc2253_name`: `X509_NAME_print_ex(b, name, 0, XN_FLAG_SEP_COMMA_PLUS)`,
/// RDNs in certificate order separated by `,`, multi-valued RDN parts by
/// `+`, short attribute names, values unescaped.
pub fn rfc2253_name(name_der: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let Some((name, _)) = der::read(name_der) else {
        return out;
    };
    let mut first = true;
    for rdn in der::children(name.content).unwrap_or_default() {
        for (i, atv) in der::children(rdn.content)
            .unwrap_or_default()
            .into_iter()
            .enumerate()
        {
            let parts = der::children(atv.content).unwrap_or_default();
            let (Some(oid), Some(val)) = (parts.first(), parts.get(1)) else {
                continue;
            };
            if !first {
                out.push(if i == 0 { b',' } else { b'+' });
            }
            first = false;
            let d = dotted(oid.content);
            out.extend(short_name(&d).unwrap_or(&d).bytes());
            out.push(b'=');
            push_value(&mut out, val.tag, val.content);
        }
    }
    out
}

/// `parse_list_value`: comma-separated KU or EKU names, each compared
/// case-insensitively over its own length as MIT's `strncasecmp` does.
fn parse_list_value(kw: Keyword, value: &str) -> Result<u32, RuleError> {
    let table = if kw == Keyword::Eku {
        EKU_KEYWORDS
    } else {
        KU_KEYWORDS
    };
    if value.is_empty() {
        return Err(RuleError::Invalid);
    }
    let mut bits = 0;
    let mut v = value.as_bytes();
    loop {
        let len = v.iter().position(|&b| b == b',').unwrap_or(v.len());
        let (name, bit) = table
            .iter()
            .find(|(name, _)| {
                // strncasecmp(value, name, len): a mismatch at name's NUL
                // when the token is longer.
                len <= name.len() && v[..len].eq_ignore_ascii_case(&name.as_bytes()[..len])
            })
            .ok_or(RuleError::Invalid)?;
        bits |= bit;
        v = &v[name.len().min(v.len())..];
        if v.first() == Some(&b',') {
            v = &v[1..];
        }
        if v.is_empty() {
            return Ok(bits);
        }
    }
}

/// `parse_rule_set`.
pub fn parse_rule_set(rule: &str) -> Result<RuleSet, RuleError> {
    let mut rest = rule;
    let relation = if let Some(r) = rest.strip_prefix("&&") {
        rest = r;
        Relation::And
    } else if let Some(r) = rest.strip_prefix("||") {
        rest = r;
        Relation::Or
    } else {
        Relation::None
    };
    let mut rs = RuleSet {
        relation,
        components: Vec::new(),
    };
    while !rest.is_empty() {
        if rs.relation == Relation::None && !rs.components.is_empty() {
            rs.relation = Relation::And;
        }
        let &(kwname, kw) = KEYWORDS
            .iter()
            .find(|(k, _)| rest.starts_with(k))
            .ok_or(RuleError::NoKeyword)?;
        rest = &rest[kwname.len()..];
        // The value runs to the next keyword or the end of the rule.
        let end = rest
            .match_indices('<')
            .map(|(i, _)| i)
            .find(|&i| KEYWORDS.iter().any(|(k, _)| rest[i..].starts_with(k)))
            .unwrap_or(rest.len());
        if end == 0 {
            return Err(RuleError::Invalid);
        }
        let value = &rest[..end];
        rest = &rest[end..];
        let value = match kw {
            Keyword::Subject | Keyword::Issuer | Keyword::San => Value::Regex(
                Regex::new(value.as_bytes()).ok_or_else(|| RuleError::Regex(value.into()))?,
            ),
            Keyword::Eku | Keyword::Ku => Value::Bits(parse_list_value(kw, value)?),
        };
        rs.components.push(Component { kw, value });
    }
    Ok(rs)
}

/// `component_match`.
fn component_match(c: &Component, md: &MatchingData) -> bool {
    match (&c.value, c.kw) {
        (Value::Regex(re), Keyword::Subject) => re.find(&md.subject_dn).is_some(),
        (Value::Regex(re), Keyword::Issuer) => re.find(&md.issuer_dn).is_some(),
        (Value::Regex(re), Keyword::San) => md
            .sans
            .iter()
            .chain(&md.upns)
            .any(|s| re.find(s.as_bytes()).is_some()),
        (Value::Bits(b), Keyword::Eku) => md.eku_bits & b == *b,
        (Value::Bits(b), Keyword::Ku) => md.ku_bits & b == *b,
        _ => false,
    }
}

impl RuleSet {
    /// Whether one certificate satisfies the rule (the loop body of
    /// `check_all_certs` and `pkinit_client_cert_match`).
    pub fn matches(&self, md: &MatchingData) -> bool {
        let mut m = false;
        for c in &self.components {
            m = component_match(c, md);
            if (m && self.relation == Relation::Or) || (!m && self.relation == Relation::And) {
                break;
            }
        }
        m
    }
}

/// `pkinit_client_cert_match`: the KDC's `dbmatch` check of the client's
/// certificate against its `pkinit_cert_match` string attribute.
pub fn client_cert_match(rule: &str, cert: &Cert) -> Result<bool, RuleError> {
    Ok(parse_rule_set(rule)?.matches(&MatchingData::from_cert(cert)))
}

/// Why no certificate was selected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SelectError {
    /// No rule matched exactly one certificate (`ENOENT`).
    NoMatch,
    /// A rule other than an `EINVAL` one failed to parse.
    Rule(RuleError),
}

impl std::fmt::Display for SelectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoMatch => f.write_str("No matching certificate found"),
            Self::Rule(e) => e.fmt(f),
        }
    }
}

/// `pkinit_cert_matching`: the index of the certificate to use. With no
/// rules this is the first (`crypto_cert_select_default`); otherwise it is
/// the only certificate the first rule matching exactly one selects. Rules
/// that are `EINVAL` are skipped.
pub fn cert_matching(rules: &[String], certs: &[&Cert]) -> Result<usize, SelectError> {
    if rules.is_empty() {
        return if certs.is_empty() {
            Err(SelectError::NoMatch)
        } else {
            Ok(0)
        };
    }
    let mut md: Option<Vec<MatchingData>> = None;
    for rule in rules {
        let rs = match parse_rule_set(rule) {
            Ok(rs) => rs,
            Err(RuleError::Invalid) => continue,
            Err(e) => return Err(SelectError::Rule(e)),
        };
        let md =
            md.get_or_insert_with(|| certs.iter().map(|c| MatchingData::from_cert(c)).collect());
        let hits: Vec<usize> = md
            .iter()
            .enumerate()
            .filter(|(_, d)| rs.matches(d))
            .map(|(i, _)| i)
            .collect();
        if let [i] = hits[..] {
            return Ok(i);
        }
    }
    Err(SelectError::NoMatch)
}

/// `pkinit_libdefault_strings(..., "pkinit_cert_match")`: `[libdefaults]
/// REALM = { pkinit_cert_match }`, then `[realms] REALM`, then
/// `[libdefaults]`.
pub fn cert_match_rules(profile: &Profile, realm: &str) -> Vec<String> {
    const OPT: &str = "pkinit_cert_match";
    [
        vec!["libdefaults", realm, OPT],
        vec!["realms", realm, OPT],
        vec!["libdefaults", OPT],
    ]
    .iter()
    .map(|path| profile.get_values(path))
    .find(|v| !v.is_empty())
    .unwrap_or_default()
}

/// `crypto_load_certs` followed by `pkinit_cert_matching`: load every
/// candidate of a `FILE:` or `DIR:` identity and select one with `rules`.
pub fn select_identity(spec: &str, rules: &[String]) -> Result<Identity, String> {
    let mut ids = Identity::load_all(spec)?;
    let certs: Vec<&Cert> = ids.iter().map(Identity::cert).collect();
    let i = cert_matching(rules, &certs).map_err(|e| e.to_string())?;
    Ok(ids.swap_remove(i))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut v = vec![tag, content.len() as u8];
        v.extend_from_slice(content);
        v
    }

    fn atv(oid: &[u8], tag: u8, value: &[u8]) -> Vec<u8> {
        tlv(0x30, &[tlv(0x06, oid), tlv(tag, value)].concat())
    }

    /// `O=KRBTEST.COM,CN=user+UID=u1,CN=\U00E9t\U4E2D` in certificate order.
    fn name() -> Vec<u8> {
        let o = tlv(0x31, &atv(&[0x55, 4, 10], 0x13, b"KRBTEST.COM"));
        let multi = tlv(
            0x31,
            &[
                atv(&[0x55, 4, 3], 0x0C, b"user"),
                atv(
                    &[0x09, 0x92, 0x26, 0x89, 0x93, 0xF2, 0x2C, 0x64, 0x01, 0x01],
                    0x0C,
                    b"u1",
                ),
            ]
            .concat(),
        );
        let utf = tlv(
            0x31,
            &atv(&[0x55, 4, 3], 0x0C, "\u{e9}t\u{4e2d}".as_bytes()),
        );
        let odd = tlv(0x31, &atv(&[0x2A, 0x03], 0x1E, &[0x00, b'x', 0x01, 0x00]));
        tlv(0x30, &[o, multi, utf, odd].concat())
    }

    #[test]
    fn names_print_like_openssl_sep_comma_plus() {
        assert_eq!(
            rfc2253_name(&name()),
            b"O=KRBTEST.COM,CN=user+UID=u1,CN=\xe9t\\U4E2D,1.2.3=x\\U0100".to_vec()
        );
    }

    fn md() -> MatchingData {
        MatchingData {
            subject_dn: b"C=US,O=KRBTEST.COM,CN=user".to_vec(),
            issuer_dn: b"C=US,ST=Massachusetts,L=Cambridge,O=MIT,CN=CA".to_vec(),
            sans: vec!["user@KRBTEST.COM".into()],
            upns: vec!["user@krbtest.com".into()],
            ku_bits: KU_DIGITALSIGNATURE | KU_KEYENCIPHERMENT,
            eku_bits: EKU_PKINIT,
        }
    }

    fn m(rule: &str) -> bool {
        parse_rule_set(rule).expect(rule).matches(&md())
    }

    /// The `pkinit_cert_match` rules of MIT's tests/t_pkinit.py.
    #[test]
    fn mit_t_pkinit_rules() {
        assert!(m("<SAN>^user@KRBTEST.COM$"));
        assert!(m("<SAN>^user@krbtest.com$"));
        assert!(m("<SUBJECT>CN=user$<KU>digitalSignature,keyEncipherment"));
        assert!(!m("&&<SUBJECT>O=OTHER.COM<SAN>^user@KRBTEST.COM$"));
        assert!(m("||<SUBJECT>O=KRBTEST.COM<SAN>^otheruser@KRBTEST.COM$"));
        assert!(!m("||<SUBJECT>O=OTHER.COM<SAN>^otheruser@KRBTEST.COM$"));
        assert!(m("&&<SUBJECT>CN=user$<ISSUER>O=MIT,"));
        assert!(m("<EKU>pkinit"));
        assert!(!m("<EKU>pkinit,clientAuth"));
        assert!(!m("<SAN>^otheruser@"));
    }

    #[test]
    fn parsing_follows_mit() {
        // An implicit second component means AND.
        assert!(!m("<SUBJECT>CN=user$<SAN>^nobody$"));
        // A '<' that starts no keyword is part of the value.
        assert!(!m("<SUBJECT>a<b"));
        // Unknown or empty list values, and empty values, are EINVAL.
        for bad in ["<KU>nope", "<EKU>", "<SUBJECT><SAN>x"] {
            assert_eq!(parse_rule_set(bad).err(), Some(RuleError::Invalid), "{bad}");
        }
        // MIT skips one comma after each name, so a trailing one is fine.
        assert!(m("<KU>digitalSignature,"));
        // strncasecmp over the token's length: a prefix matches.
        assert!(m("<KU>DIGITAL"));
        assert_eq!(parse_rule_set("CN=x").err(), Some(RuleError::NoKeyword));
        assert!(matches!(parse_rule_set("<SAN>("), Err(RuleError::Regex(_))));
    }

    #[test]
    fn selection_skips_invalid_rules_and_needs_exactly_one_match() {
        let rules = |r: &[&str]| r.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let data = [md(), MatchingData::default()];
        let pick = |rules: &[String]| -> Result<usize, SelectError> {
            for rule in rules {
                let rs = match parse_rule_set(rule) {
                    Ok(rs) => rs,
                    Err(RuleError::Invalid) => continue,
                    Err(e) => return Err(SelectError::Rule(e)),
                };
                let hits: Vec<_> = (0..2).filter(|&i| rs.matches(&data[i])).collect();
                if let [i] = hits[..] {
                    return Ok(i);
                }
            }
            Err(SelectError::NoMatch)
        };
        assert_eq!(pick(&rules(&["<KU>bogus", "<SAN>user@"])), Ok(0));
        assert_eq!(pick(&rules(&["<SUBJECT>.*", "<SAN>user@"])), Ok(0));
        assert_eq!(pick(&rules(&["<SAN>nobody"])), Err(SelectError::NoMatch));
        assert_eq!(cert_matching(&[], &[]), Err(SelectError::NoMatch));
    }
}
