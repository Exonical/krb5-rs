//! MIT principal-name key encoding.
//!
//! The codec follows `krb5_unparse_name()` in `unparse.c:61-134` and
//! `krb5_parse_name()` in `parse.c:40-172`. Name type inference is
//! `k5_infer_principal_type()` in `bld_princ.c:31-43`, called from
//! `parse.c:221-222`.

use rasn::types::GeneralString;

use crate::kdc::store::StoreError;
use crate::types::PrincipalName;

fn corrupt(message: impl Into<String>) -> StoreError {
    StoreError::corrupt(message)
}

fn append_component(out: &mut Vec<u8>, component: &[u8]) {
    for byte in component {
        match byte {
            b'/' | b'@' | b'\\' => {
                out.push(b'\\');
                out.push(*byte);
            }
            b'\t' => out.extend_from_slice(b"\\t"),
            b'\n' => out.extend_from_slice(b"\\n"),
            b'\x08' => out.extend_from_slice(b"\\b"),
            b'\0' => out.extend_from_slice(b"\\0"),
            _ => out.push(*byte),
        }
    }
}

/// Return the LMDB key used by MIT's `krb5_unparse_name()`, excluding its
/// terminating C NUL.
pub fn unparse_name(name: &PrincipalName, realm: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for (i, component) in name.name_string.iter().enumerate() {
        if i != 0 {
            out.push(b'/');
        }
        append_component(&mut out, component.as_ref());
    }
    out.push(b'@');
    append_component(&mut out, realm.as_bytes());
    out
}

/// Parse an unparsed MIT principal key. LMDB keys are always produced by
/// `krb5_unparse_name()`, so a realm separator is required and the C NUL is
/// not part of `key`.
pub fn parse_name(key: &[u8]) -> Result<(PrincipalName, String), StoreError> {
    parse_name_inner(key, None)
}

/// Parse a principal with `krb5_parse_name()` default-realm behavior.
pub fn parse_name_with_default(
    name: &str,
    default_realm: &str,
) -> Result<(PrincipalName, String), StoreError> {
    parse_name_inner(name.as_bytes(), Some(default_realm.as_bytes()))
}

fn parse_name_inner(
    key: &[u8],
    default_realm: Option<&[u8]>,
) -> Result<(PrincipalName, String), StoreError> {
    if key.contains(&0) {
        return Err(corrupt("MIT principal key contains an unescaped NUL"));
    }

    let mut components = vec![Vec::new()];
    let mut realm = Vec::new();
    let mut in_realm = false;
    let mut has_realm = false;
    let mut pos = 0;

    while pos < key.len() {
        let byte = key[pos];
        pos += 1;
        if byte == b'\\' {
            let escaped = *key
                .get(pos)
                .ok_or_else(|| corrupt("MIT principal key ends in a quote character"))?;
            pos += 1;
            let decoded = match escaped {
                b'n' => b'\n',
                b't' => b'\t',
                b'b' => b'\x08',
                b'0' => b'\0',
                other => other,
            };
            if in_realm {
                realm.push(decoded);
            } else {
                let component = components
                    .last_mut()
                    .ok_or_else(|| corrupt("MIT principal has no components"))?;
                component.push(decoded);
            }
        } else {
            match byte {
                b'/' if in_realm => {
                    return Err(corrupt("unescaped component separator in MIT realm"));
                }
                b'/' => components.push(Vec::new()),
                b'@' if in_realm => {
                    return Err(corrupt("multiple unescaped realm separators in MIT key"));
                }
                b'@' => {
                    in_realm = true;
                    has_realm = true;
                }
                other if in_realm => realm.push(other),
                other => {
                    let component = components
                        .last_mut()
                        .ok_or_else(|| corrupt("MIT principal has no components"))?;
                    component.push(other);
                }
            }
        }
    }

    if !has_realm {
        let Some(default_realm) = default_realm else {
            return Err(corrupt("MIT principal key has no realm separator"));
        };
        realm.extend_from_slice(default_realm);
    }
    let realm =
        String::from_utf8(realm).map_err(|_| corrupt("MIT principal realm is not UTF-8"))?;
    let name_type = if components.len() == 2 && components[0] == b"krbtgt" {
        2
    } else if components.len() >= 2 && components[0] == b"WELLKNOWN" {
        11
    } else {
        1
    };
    let name_string = components
        .into_iter()
        .map(|component| {
            GeneralString::from_bytes(&component)
                .map_err(|_| corrupt("invalid MIT principal component"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok((
        PrincipalName {
            name_type,
            name_string,
        },
        realm,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn component(bytes: &[u8]) -> GeneralString {
        GeneralString::from_bytes(bytes).expect("component")
    }

    #[test]
    fn names_match_mit_quoting_and_round_trip() {
        let name = PrincipalName {
            name_type: 7,
            name_string: vec![component(b"a/b@c\\d\t\n\x08\0"), component(b"host")],
        };
        let key = unparse_name(&name, "R/LM@X");
        assert_eq!(key, b"a\\/b\\@c\\\\d\\t\\n\\b\\0/host@R\\/LM\\@X");
        let (parsed, realm) = parse_name(&key).expect("parse");
        assert_eq!(parsed.name_string, name.name_string);
        assert_eq!(parsed.name_type, 1);
        assert_eq!(realm, "R/LM@X");
    }

    #[test]
    fn mit_t_kerb_parse_unparse_vectors_round_trip() {
        // The explicit-realm vectors are from lib/krb5/krb/Makefile.in:478-484
        // and t_ref_kerb.out:3-9.
        for key in [
            b"tytso/root@VEGGIE.COM".as_slice(),
            b"tytso/tuber/carrot@VEGGIE.COM",
            b"tytso/a/b/c/d/e/f/g/h/i/j/k/l/m/n/o/p/q/r/s/t@FOO",
            b"tytso\\\\0/\\0@B\\n\\t\\\\GAG",
            b"tytso/\\n/\\b\\t@B\\0hacky-test",
            b"\\/slash/\\@atsign/octa\\/thorpe@\\/slash\\@at\\/sign",
        ] {
            let (principal, realm) = parse_name(key).expect("MIT test-vector parse");
            assert_eq!(unparse_name(&principal, &realm), key);
        }
    }

    #[test]
    fn mit_name_type_inference_matches_krb5_parse_name() {
        let (tgs, _) = parse_name(b"krbtgt/EXAMPLE@EXAMPLE").expect("TGS");
        assert_eq!(tgs.name_type, 2);
        let (anonymous, _) =
            parse_name(b"WELLKNOWN/ANONYMOUS@WELLKNOWN:ANONYMOUS").expect("anonymous");
        assert_eq!(anonymous.name_type, 11);
        let (ordinary, _) = parse_name(b"a/b/c@R").expect("ordinary");
        assert_eq!(ordinary.name_type, 1);
        let (defaulted, realm) =
            parse_name_with_default(r"alice\/service", "EXAMPLE.COM").expect("default realm");
        assert_eq!(realm, "EXAMPLE.COM");
        assert_eq!(defaulted.name_string.len(), 1);
        assert_eq!(defaulted.name_string[0].as_slice(), b"alice/service");
    }

    #[test]
    fn malformed_names_are_rejected() {
        for key in [b"a@R@X".as_slice(), b"a@R/X", b"a\\", b"a\0@R", b"a"] {
            assert!(parse_name(key).is_err(), "{key:?}");
        }
    }
}
