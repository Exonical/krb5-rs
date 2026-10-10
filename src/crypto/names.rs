//! Enctype and key-salt name parsing (MIT lib/crypto/krb/etypes.c,
//! lib/krb5/krb/init_ctx.c `krb5int_parse_enctype_list`,
//! lib/kadm5/str_conv.c `krb5_string_to_keysalts`).

use super::ETYPE_REGISTRY;

/// MIT enctype table (etypes.c:36-145): number, primary name, aliases.
/// Includes enctypes this crate cannot use, since they are valid MIT names.
const NAMES: &[(i32, &str, &[&str])] = &[
    (6, "des3-cbc-raw", &[]),
    (16, "des3-cbc-sha1", &["des3-hmac-sha1", "des3-cbc-sha1-kd"]),
    (23, "arcfour-hmac", &["rc4-hmac", "arcfour-hmac-md5"]),
    (
        24,
        "arcfour-hmac-exp",
        &["rc4-hmac-exp", "arcfour-hmac-md5-exp"],
    ),
    (
        17,
        "aes128-cts-hmac-sha1-96",
        &["aes128-cts", "aes128-sha1"],
    ),
    (
        18,
        "aes256-cts-hmac-sha1-96",
        &["aes256-cts", "aes256-sha1"],
    ),
    (25, "camellia128-cts-cmac", &["camellia128-cts"]),
    (26, "camellia256-cts-cmac", &["camellia256-cts"]),
    (19, "aes128-cts-hmac-sha256-128", &["aes128-sha2"]),
    (20, "aes256-cts-hmac-sha384-192", &["aes256-sha2"]),
];

/// Enctype number for an MIT name or alias (case-insensitive,
/// `krb5_string_to_enctype`), or a decimal number.
pub fn enctype_from_name(s: &str) -> Option<i32> {
    NAMES
        .iter()
        .find(|(_, name, aliases)| {
            name.eq_ignore_ascii_case(s) || aliases.iter().any(|a| a.eq_ignore_ascii_case(s))
        })
        .map(|(n, _, _)| *n)
        .or_else(|| {
            (!s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
                .then(|| s.parse().ok())
                .flatten()
        })
}

/// MIT primary name for an enctype number.
pub fn enctype_name(etype: i32) -> Option<&'static str> {
    NAMES
        .iter()
        .find(|(n, _, _)| *n == etype)
        .map(|(_, n, _)| *n)
}

fn mod_list(list: &mut Vec<i32>, etype: i32, add: bool) {
    if add {
        if !list.contains(&etype) {
            list.push(etype);
        }
    } else {
        list.retain(|&e| e != etype);
    }
}

/// `krb5int_parse_enctype_list` (init_ctx.c:447-503): words separated by
/// space/tab/CR/LF/comma, each optionally prefixed `+` (add, default) or `-`
/// (remove); `DEFAULT` expands to `defaults`; family words are `des3`, `aes`,
/// `rc4` and `camellia`; anything else is looked up as an enctype name and
/// unknown words are ignored. Only enctypes this crate implements are kept,
/// so an empty result means no usable enctype (MIT: KRB5_CONFIG_ETYPE_NOSUPP).
pub fn parse_enctype_list(s: &str, defaults: &[i32]) -> Vec<i32> {
    let mut list: Vec<i32> = Vec::new();
    for raw in s
        .split([' ', '\t', '\r', '\n', ','])
        .filter(|t| !t.is_empty())
    {
        let (add, token) = match raw.as_bytes()[0] {
            b'+' => (true, &raw[1..]),
            b'-' => (false, &raw[1..]),
            _ => (true, raw),
        };
        let lower = token.to_ascii_lowercase();
        let expanded: Vec<i32> = match lower.as_str() {
            "default" => defaults.to_vec(),
            "des3" => vec![16],
            "aes" => vec![18, 17, 20, 19],
            "rc4" => vec![23],
            "camellia" => vec![26, 25],
            _ => match enctype_from_name(token) {
                Some(e) => vec![e],
                None => continue,
            },
        };
        for e in expanded {
            mod_list(&mut list, e, add);
        }
    }
    list.retain(|e| ETYPE_REGISTRY.contains_key(e));
    list
}

/// Key salt type (MIT `KRB5_KDB_SALTTYPE_*`, kdb.h:76-82).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SaltType {
    /// Realm plus all name components.
    Normal,
    /// All name components without the realm.
    NoRealm,
    /// Only the realm.
    OnlyRealm,
}

/// Error from [`parse_keysalt_list`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("unsupported salt type {0:?}")]
pub struct KeysaltError(pub String);

/// `krb5_string_to_keysalts` (kadm5/str_conv.c:285-335) with the default
/// separators: tuples split on `,` space or tab, `enctype[:salttype]`, salt
/// defaulting to `normal`. Tuples with an unrecognised enctype or salt name
/// are discarded (as MIT does), duplicates are dropped, and enctypes this
/// crate does not implement are dropped. The MIT salt types `special`, and
/// the legacy `v4` and `afs3`, are rejected with an error.
pub fn parse_keysalt_list(s: &str) -> Result<Vec<(i32, SaltType)>, KeysaltError> {
    let mut out: Vec<(i32, SaltType)> = Vec::new();
    for tuple in s.split([',', ' ', '\t']).filter(|t| !t.is_empty()) {
        let (etype_s, salt_s) = match tuple.split_once(':') {
            Some((e, s)) => (e, Some(s)),
            None => (tuple, None),
        };
        let Some(etype) = enctype_from_name(etype_s) else {
            continue;
        };
        let salt = match salt_s.map(str::to_ascii_lowercase).as_deref() {
            None | Some("normal") => SaltType::Normal,
            Some("norealm") => SaltType::NoRealm,
            Some("onlyrealm") => SaltType::OnlyRealm,
            Some(bad @ ("special" | "v4" | "afs3")) => return Err(KeysaltError(bad.to_string())),
            Some(_) => continue,
        };
        if !ETYPE_REGISTRY.contains_key(&etype) || out.contains(&(etype, salt)) {
            continue;
        }
        out.push((etype, salt));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enctype_from_name_accepts_names_aliases_case_and_numbers() {
        assert_eq!(enctype_from_name("aes256-cts-hmac-sha1-96"), Some(18));
        assert_eq!(enctype_from_name("AES256-CTS"), Some(18));
        assert_eq!(enctype_from_name("aes128-sha2"), Some(19));
        assert_eq!(enctype_from_name("rc4-hmac"), Some(23));
        assert_eq!(enctype_from_name("camellia256-cts"), Some(26));
        assert_eq!(enctype_from_name("des3-hmac-sha1"), Some(16));
        assert_eq!(enctype_from_name("17"), Some(17));
        assert_eq!(enctype_from_name("bogus"), None);
        assert_eq!(enctype_from_name(""), None);
    }

    #[test]
    fn enctype_name_returns_primary_name() {
        assert_eq!(enctype_name(18), Some("aes256-cts-hmac-sha1-96"));
        assert_eq!(enctype_name(99), None);
    }

    #[test]
    fn parse_enctype_list_expands_families_in_mit_order() {
        assert_eq!(parse_enctype_list("aes", &[]), vec![18, 17, 20, 19]);
        assert_eq!(
            parse_enctype_list("aes256-sha1,aes128-cts aes256-sha2", &[]),
            vec![18, 17, 20]
        );
    }

    #[test]
    fn parse_enctype_list_default_and_removal() {
        assert_eq!(parse_enctype_list("DEFAULT", &[18, 17]), vec![18, 17]);
        assert_eq!(
            parse_enctype_list("DEFAULT -aes128-cts", &[18, 17]),
            vec![18]
        );
        assert_eq!(
            parse_enctype_list("+aes256-cts -aes256-cts", &[]),
            Vec::<i32>::new()
        );
    }

    #[test]
    fn parse_enctype_list_ignores_unknown_and_unimplemented() {
        assert_eq!(
            parse_enctype_list("bogus rc4 des3 camellia aes128-cts", &[]),
            vec![17]
        );
        assert!(parse_enctype_list("rc4-hmac", &[]).is_empty());
    }

    #[test]
    fn parse_enctype_list_duplicates_collapse() {
        assert_eq!(parse_enctype_list("aes256-cts aes256-sha1", &[]), vec![18]);
    }

    #[test]
    fn parse_keysalt_list_defaults_to_normal_salt() {
        assert_eq!(
            parse_keysalt_list("aes256-cts-hmac-sha1-96:normal aes128-cts-hmac-sha1-96")
                .expect("ok"),
            vec![(18, SaltType::Normal), (17, SaltType::Normal)]
        );
    }

    #[test]
    fn parse_keysalt_list_supports_norealm_and_onlyrealm() {
        assert_eq!(
            parse_keysalt_list("aes256-cts:norealm,aes256-cts:onlyrealm").expect("ok"),
            vec![(18, SaltType::NoRealm), (18, SaltType::OnlyRealm)]
        );
    }

    #[test]
    fn parse_keysalt_list_drops_duplicates_unknown_and_unimplemented() {
        assert_eq!(
            parse_keysalt_list(
                "aes256-cts aes256-sha1:normal bogus:normal rc4-hmac:normal aes128-cts:nonsense"
            )
            .expect("ok"),
            vec![(18, SaltType::Normal)]
        );
    }

    #[test]
    fn parse_keysalt_list_rejects_special_v4_and_afs3_salts() {
        for salt in ["special", "v4", "afs3"] {
            let err = parse_keysalt_list(&format!("aes256-cts:{salt}")).expect_err("reject");
            assert_eq!(err.0, salt);
        }
    }
}
