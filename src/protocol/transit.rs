//! Transited-realm encoding, realm-tree walking and transit checking.
//!
//! Ports of MIT `add_to_transited` (kdc/kdc_transit.c:105-340),
//! `krb5_walk_realm_tree` (lib/krb5/krb/walk_rtree.c) and
//! `krb5_check_transited_list` (lib/krb5/krb/chk_trans.c). The encoding is
//! DOMAIN-X500-COMPRESS (RFC 4120 §3.3.3.2, `tr-type` 1). Realms are handled
//! as bytes, as MIT does.

use crate::profile::Profile;

/// MIT `MAX_REALM_LN` (kdc_transit.c:36).
const MAX_REALM_LN: usize = 500;
/// MIT `MAXLEN` (chk_trans.c:44).
const MAXLEN: usize = 512;
/// MIT `KRB5_REALM_BRANCH_CHAR`.
pub(crate) const REALM_BRANCH_CHAR: u8 = b'.';
/// `krb5_anonymous_realm()`.
const ANONYMOUS_REALM: &[u8] = b"WELLKNOWN:ANONYMOUS";

/// Transit processing failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TransitError {
    /// `KRB5KRB_AP_ERR_ILL_CR_TKT` (43).
    IllCrTkt,
    /// `KRB5_NO_TKT_IN_RLM`: no path between identical realms.
    NoTktInRealm,
}

type Result<T> = std::result::Result<T, TransitError>;

fn subrealm(r1: &[u8], r2: &[u8]) -> i64 {
    let (l1, l2) = (r1.len(), r2.len());
    if l2 <= l1 {
        return 0;
    }
    let (i1, i2) = (l1 as i64, l2 as i64);
    let (s1, s2) = (r1.first() == Some(&b'/'), r2.first() == Some(&b'/'));
    if s1 && s2 && r2.starts_with(r1) {
        return i1 - i2;
    }
    if !s1 && !s2 && r2.ends_with(r1) {
        return i2 - i1;
    }
    0
}

fn read_field(otrans: &[u8], pos: &mut usize) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    while *pos < otrans.len() {
        let c = otrans[*pos];
        if c == b'\\' {
            *pos += 1;
            if *pos >= otrans.len() {
                break;
            }
            continue;
        }
        if c == b',' {
            *pos += 1;
            break;
        }
        out.push(c);
        *pos += 1;
        if out.len() >= MAX_REALM_LN {
            return Err(TransitError::IllCrTkt);
        }
    }
    Ok(out)
}

fn append_piece(dst: &mut Vec<u8>, src: &[u8], pl: i64) {
    let n = pl.unsigned_abs() as usize;
    if pl > 0 {
        dst.extend_from_slice(&src[..n.min(src.len())]);
    } else {
        dst.extend_from_slice(&src[src.len().saturating_sub(n)..]);
    }
}

/// Add the realm that issued the header TGT (`tgs_realm`) to the
/// compressed transited list `tgt_trans` of a ticket for `client_realm`
/// requesting `server_realm` (kdc_transit.c:105-340).
pub(crate) fn add_to_transited(
    tgt_trans: &[u8],
    tgs_realm: &[u8],
    client_realm: &[u8],
    server_realm: &[u8],
) -> Result<Vec<u8>> {
    let realm = tgs_realm;
    let bufsize = (realm.len() + tgt_trans.len() + 3).min(MAX_REALM_LN);
    let mut trans: Vec<u8> = Vec::new();
    let strlcat = |trans: &mut Vec<u8>, s: &[u8]| -> Result<()> {
        if trans.len() + s.len() >= bufsize {
            return Err(TransitError::IllCrTkt);
        }
        trans.extend_from_slice(s);
        Ok(())
    };

    let mut pos = 0usize;
    let mut prev: Vec<u8> = Vec::new();
    let mut current = read_field(tgt_trans, &mut pos)?;
    let mut added = client_realm == realm || server_realm == realm;

    while !current.is_empty() {
        let exp: Vec<u8> = if current[0] == b' ' {
            current[1..].to_vec()
        } else if current[0] == b'/' && prev.first() == Some(&b'/') {
            if prev.len() + current.len() + 1 >= MAX_REALM_LN {
                return Err(TransitError::IllCrTkt);
            }
            let mut e = prev.clone();
            e.extend_from_slice(&current);
            e
        } else if current.last() == Some(&b'.') {
            if current.len() + prev.len() + 1 >= MAX_REALM_LN {
                return Err(TransitError::IllCrTkt);
            }
            let mut e = current.clone();
            e.extend_from_slice(&prev);
            e
        } else {
            current.clone()
        };

        let next = read_field(tgt_trans, &mut pos)?;

        if exp == realm {
            added = true;
        }

        if !added {
            let next_ok = next.is_empty() || next.last() != Some(&b'.');
            let pl = if next_ok && next.first() != Some(&b'/') {
                subrealm(&exp, realm)
            } else {
                0
            };
            if pl != 0 {
                added = true;
                if current.len() + pl.unsigned_abs() as usize + 2 >= MAX_REALM_LN {
                    return Err(TransitError::IllCrTkt);
                }
                current.push(b',');
                append_piece(&mut current, realm, pl);
            } else {
                let pl = subrealm(realm, &exp);
                if pl != 0 {
                    added = true;
                    current.clear();
                    let pl1 = subrealm(&prev, realm);
                    if pl1 != 0 {
                        if pl1.unsigned_abs() as usize + 1 >= MAX_REALM_LN {
                            return Err(TransitError::IllCrTkt);
                        }
                        append_piece(&mut current, realm, pl1);
                    } else {
                        if realm.first() == Some(&b'/') && !prev.is_empty() {
                            current.push(b' ');
                        }
                        if current.len() + realm.len() + 1 >= MAX_REALM_LN {
                            return Err(TransitError::IllCrTkt);
                        }
                        current.extend_from_slice(realm);
                    }
                    if current.len() + pl.unsigned_abs() as usize + 2 >= MAX_REALM_LN {
                        return Err(TransitError::IllCrTkt);
                    }
                    current.push(b',');
                    append_piece(&mut current, &exp, pl);
                }
            }
        }

        if !trans.is_empty() {
            strlcat(&mut trans, b",")?;
        }
        strlcat(&mut trans, &current)?;

        prev = exp;
        current = next;
    }

    if !added {
        if !trans.is_empty() {
            strlcat(&mut trans, b",")?;
        }
        if realm.first() == Some(&b'/') && !trans.is_empty() {
            strlcat(&mut trans, b" ")?;
        }
        strlcat(&mut trans, realm)?;
    }
    Ok(trans)
}

fn process_intermediates(
    f: &mut dyn FnMut(&[u8]) -> Result<()>,
    n1: &[u8],
    n2: &[u8],
) -> Result<()> {
    let (n1, n2) = if n1.len() > n2.len() {
        (n2, n1)
    } else {
        (n1, n2)
    };
    let (len1, len2) = (n1.len(), n2.len());
    if len1 == len2 {
        return if n1 == n2 {
            Ok(())
        } else {
            Err(TransitError::IllCrTkt)
        };
    }
    if len1 == 0 {
        return Err(TransitError::IllCrTkt);
    }
    if n1[0] == b'/' {
        if n2[0] != b'/' || n2[..len1] != *n1 {
            return Err(TransitError::IllCrTkt);
        }
        for i in len1 + 1..len2 {
            if n2[i] == b'/' {
                f(&n2[..i])?;
            }
        }
    } else {
        if n2[0] == b'/' || n2[len2 - len1..] != *n1 {
            return Err(TransitError::IllCrTkt);
        }
        let mut i = len2 - len1 - 1;
        while i > 0 {
            if n2[i - 1] == b'.' {
                f(&n2[i..])?;
            }
            i -= 1;
        }
    }
    Ok(())
}

fn maybe_join(last: &[u8], buf: &mut Vec<u8>) -> Result<()> {
    if buf.is_empty() {
        return Ok(());
    }
    if buf[0] == b'/' {
        if last.len() + buf.len() > MAXLEN {
            return Err(TransitError::IllCrTkt);
        }
        let mut joined = last.to_vec();
        joined.extend_from_slice(buf);
        *buf = joined;
    } else if buf.last() == Some(&b'.') {
        if last.len() + buf.len() > MAXLEN {
            return Err(TransitError::IllCrTkt);
        }
        buf.extend_from_slice(last);
    }
    Ok(())
}

/// Call `f` for each realm named (explicitly or by compression) in the
/// encoded transited list (chk_trans.c:164-266).
fn foreach_realm(
    f: &mut dyn FnMut(&[u8]) -> Result<()>,
    crealm: &[u8],
    srealm: &[u8],
    transit: &[u8],
) -> Result<()> {
    if transit.is_empty() {
        return Ok(());
    }
    let mut buf: Vec<u8> = Vec::new();
    let mut last: Vec<u8> = Vec::new();
    let mut next_lit = false;
    let mut intermediates = false;

    for (idx, &c) in transit.iter().enumerate() {
        if next_lit {
            buf.push(c);
            if buf.len() == MAXLEN {
                return Err(TransitError::IllCrTkt);
            }
            next_lit = false;
        } else if c == b'\\' {
            next_lit = true;
        } else if c == b',' {
            if !buf.is_empty() {
                maybe_join(&last, &mut buf)?;
                f(&buf)?;
                if intermediates {
                    if idx == 0 {
                        process_intermediates(f, &buf, crealm)?;
                    } else {
                        process_intermediates(f, &buf, &last)?;
                    }
                }
                intermediates = false;
                last = std::mem::take(&mut buf);
            } else {
                intermediates = true;
                if idx == 0 {
                    if crealm.len() >= MAXLEN {
                        return Err(TransitError::IllCrTkt);
                    }
                    last = crealm.to_vec();
                }
            }
        } else if c == b' ' && buf.is_empty() {
            last.clear();
        } else {
            buf.push(c);
            if buf.len() == MAXLEN {
                return Err(TransitError::IllCrTkt);
            }
        }
    }
    if buf.is_empty() {
        process_intermediates(f, &last, srealm)
    } else {
        maybe_join(&last, &mut buf)?;
        f(&buf)?;
        if intermediates {
            process_intermediates(f, &buf, &last)?;
        }
        Ok(())
    }
}

/// The realms named by an encoded transited list, in encoded order
/// (`t_expand -x`, chk_trans.c:283-310).
#[cfg_attr(not(test), expect(dead_code, reason = "used by tests and diagnostics"))]
pub(crate) fn decode_transited(
    crealm: &[u8],
    srealm: &[u8],
    transit: &[u8],
) -> Result<Vec<Vec<u8>>> {
    let mut out = Vec::new();
    foreach_realm(
        &mut |r| {
            out.push(r.to_vec());
            Ok(())
        },
        crealm,
        srealm,
        transit,
    )?;
    Ok(out)
}

/// One `krbtgt/instance@realm` hop of a realm walk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TgsHop {
    /// The principal's realm (the realm that issues the TGT).
    pub realm: Vec<u8>,
    /// The principal's second component (the realm the TGT is for).
    pub instance: Vec<u8>,
}

fn hop(instance: &[u8], realm: &[u8]) -> TgsHop {
    TgsHop {
        realm: realm.to_vec(),
        instance: instance.to_vec(),
    }
}

/// `krb5_walk_realm_tree` (walk_rtree.c:98-122): the `[capaths]` path from
/// `client` to `server` if configured, else the hierarchical path. The first
/// hop is always `krbtgt/client@client`.
pub(crate) fn walk_realm_tree(
    client: &[u8],
    server: &[u8],
    capaths: Option<&Profile>,
    sep: u8,
) -> Result<Vec<TgsHop>> {
    if client.is_empty() || server.is_empty() || client == server {
        return Err(TransitError::NoTktInRealm);
    }
    let vals = capaths
        .map(|p| {
            p.get_values(&[
                "capaths",
                &String::from_utf8_lossy(client),
                &String::from_utf8_lossy(server),
            ])
        })
        .filter(|v| !v.is_empty());
    match vals {
        Some(vals) => Ok(capath_tree(client, server, &vals)),
        None => Ok(hier_tree(client, server, sep)),
    }
}

/// walk_rtree.c:225-275 `rtree_capath_tree`.
fn capath_tree(client: &[u8], server: &[u8], vals: &[String]) -> Vec<TgsHop> {
    let links: &[String] = if vals[0].starts_with('.') { &[] } else { vals };
    let mut tree = vec![hop(client, client)];
    let mut src = client.to_vec();
    for v in links {
        let dst: Vec<u8> = v
            .bytes()
            .take_while(|b| *b != b'\t' && *b != b' ')
            .collect();
        tree.push(hop(&dst, &src));
        src = dst;
    }
    tree.push(hop(server, &src));
    tree
}

/// walk_rtree.c:372-470 hierarchical traversal.
fn hier_tree(client: &[u8], server: &[u8], sep: u8) -> Vec<TgsHop> {
    let (mut c_tail, mut s_tail, mut c_dot, mut s_dot) = (None, None, None, None);
    comtail(
        client,
        server,
        sep,
        &mut c_tail,
        &mut s_tail,
        &mut c_dot,
        &mut s_dot,
    );
    adjtail(client, server, sep, &mut c_tail, &mut s_tail, c_dot, s_dot);
    let mut realms: Vec<Vec<u8>> = tweens(client, c_tail, true, sep);
    let mut st = tweens(server, s_tail, false, sep);
    st.reverse();
    realms.extend(st);
    let mut tree = Vec::new();
    let mut src: &[u8] = client;
    for dst in &realms {
        tree.push(hop(dst, src));
        src = dst;
    }
    tree
}

fn tweens(r: &[u8], rtail: Option<usize>, dotail: bool, sep: u8) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut lp = 0usize;
    for p in 0..r.len() {
        if r[p] != sep && p + 1 != r.len() {
            continue;
        }
        if Some(lp) == rtail && !dotail {
            break;
        }
        out.push(r[lp..].to_vec());
        if Some(lp) == rtail {
            break;
        }
        lp = p + 1;
    }
    out
}

fn adjtail(
    c: &[u8],
    s: &[u8],
    sep: u8,
    c_tail: &mut Option<usize>,
    s_tail: &mut Option<usize>,
    c_dot: Option<usize>,
    s_dot: Option<usize>,
) {
    let (Some(cp), Some(sp)) = (*c_tail, *s_tail) else {
        return;
    };
    let cfull = cp == 0 || c[cp - 1] == sep;
    let sfull = sp == 0 || s[sp - 1] == sep;
    if cfull && sfull {
        return;
    }
    if let (Some(cd), Some(sd)) = (c_dot, s_dot) {
        let (ncp, nsp) = (cd + 1, sd + 1);
        if ncp >= c.len() || nsp >= s.len() {
            *c_tail = None;
            *s_tail = None;
        } else {
            *c_tail = Some(ncp);
            *s_tail = Some(nsp);
        }
    } else {
        *c_tail = None;
        *s_tail = None;
    }
}

fn comtail(
    c: &[u8],
    s: &[u8],
    sep: u8,
    c_tail: &mut Option<usize>,
    s_tail: &mut Option<usize>,
    c_dot: &mut Option<usize>,
    s_dot: &mut Option<usize>,
) {
    if c.is_empty() || s.is_empty() {
        return;
    }
    let (mut cp, mut sp) = (c.len(), s.len());
    let (mut cdot, mut sdot) = (None, None);
    while cp > 0 && sp > 0 {
        cp -= 1;
        sp -= 1;
        if c[cp] != s[sp] {
            cp += 1;
            sp += 1;
            break;
        }
        if c[cp] == sep {
            cdot = Some(cp);
            sdot = Some(sp);
        }
    }
    if cp == c.len() {
        return;
    }
    *c_tail = Some(cp);
    *s_tail = Some(sp);
    *c_dot = cdot;
    *s_dot = sdot;
}

/// `krb5_check_transited_list` (chk_trans.c:268-310): every realm in the
/// encoded list must be on the capaths or hierarchical path from `crealm`
/// to `srealm`.
pub(crate) fn check_transited_list(
    trans: &[u8],
    crealm: &[u8],
    srealm: &[u8],
    capaths: Option<&Profile>,
) -> Result<()> {
    let trans = match trans.split_last() {
        Some((0, rest)) => rest,
        _ => trans,
    };
    if trans.is_empty() || crealm == ANONYMOUS_REALM {
        return Ok(());
    }
    let tgs = walk_realm_tree(crealm, srealm, capaths, REALM_BRANCH_CHAR)?;
    foreach_realm(
        &mut |realm| {
            if tgs.iter().any(|h| h.realm == realm) {
                Ok(())
            } else {
                Err(TransitError::IllCrTkt)
            }
        },
        crealm,
        srealm,
        trans,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn expand(c: &str, s: &str, t: &str) -> Result<Vec<String>> {
        let mut v: Vec<String> = decode_transited(c.as_bytes(), s.as_bytes(), t.as_bytes())?
            .into_iter()
            .map(|r| String::from_utf8_lossy(&r).to_string())
            .collect();
        v.sort();
        Ok(v)
    }

    fn sorted(items: &[&str]) -> Vec<String> {
        let mut v: Vec<String> = items.iter().map(|s| s.to_string()).collect();
        v.sort();
        v
    }

    // lib/krb5/krb/transit-tests (t_expand -x).
    #[test]
    fn decode_transited_matches_mit_transit_tests() {
        assert_eq!(
            expand("ATHENA.MIT.EDU", "HACK.FOOBAR.COM", ",EDU,BLORT.COM,COM,").expect("ok"),
            sorted(&["MIT.EDU", "EDU", "BLORT.COM", "COM", "FOOBAR.COM"])
        );
        assert_eq!(
            expand("ATHENA.MIT.EDU", "EDU", ",").expect("ok"),
            sorted(&["MIT.EDU"])
        );
        assert_eq!(
            expand("EDU", "ATHENA.MIT.EDU", ",").expect("ok"),
            sorted(&["MIT.EDU"])
        );
        assert_eq!(
            expand("x", "x", "/COM,/HP,/APOLLO, /COM/DEC").expect("ok"),
            sorted(&["/COM", "/COM/HP", "/COM/HP/APOLLO", "/COM/DEC"])
        );
        assert_eq!(
            expand("x", "x", "EDU,MIT.,ATHENA.,WASHINGTON.EDU,CS.").expect("ok"),
            sorted(&[
                "EDU",
                "MIT.EDU",
                "ATHENA.MIT.EDU",
                "WASHINGTON.EDU",
                "CS.WASHINGTON.EDU"
            ])
        );
        assert!(expand("ATHENA.MIT.EDU", "/COM/HP/APOLLO", ",EDU,/COM,").is_err());
        assert_eq!(
            expand("ATHENA.MIT.EDU", "/COM/HP/APOLLO", ",EDU, /COM,").expect("ok"),
            sorted(&["EDU", "MIT.EDU", "/COM", "/COM/HP"])
        );
        assert_eq!(
            expand("ATHENA.MIT.EDU", "CS.CMU.EDU", ",EDU,").expect("ok"),
            sorted(&["EDU", "MIT.EDU", "CMU.EDU"])
        );
        assert_eq!(
            expand("XYZZY.ATHENA.MIT.EDU", "XYZZY.CS.CMU.EDU", ",EDU,").expect("ok"),
            sorted(&["EDU", "MIT.EDU", "ATHENA.MIT.EDU", "CMU.EDU", "CS.CMU.EDU"])
        );
    }

    fn walk(c: &str, s: &str) -> Vec<String> {
        walk_realm_tree(c.as_bytes(), s.as_bytes(), None, b'.')
            .expect("walk")
            .iter()
            .map(|h| {
                format!(
                    "krbtgt/{}@{}",
                    String::from_utf8_lossy(&h.instance),
                    String::from_utf8_lossy(&h.realm)
                )
            })
            .collect()
    }

    #[test]
    fn walk_realm_tree_hierarchical_paths() {
        assert_eq!(
            walk("A.EXAMPLE.COM", "B.EXAMPLE.COM"),
            vec![
                "krbtgt/A.EXAMPLE.COM@A.EXAMPLE.COM",
                "krbtgt/EXAMPLE.COM@A.EXAMPLE.COM",
                "krbtgt/B.EXAMPLE.COM@EXAMPLE.COM"
            ]
        );
        assert_eq!(
            walk("ATHENA.MIT.EDU", "CS.CMU.EDU"),
            vec![
                "krbtgt/ATHENA.MIT.EDU@ATHENA.MIT.EDU",
                "krbtgt/MIT.EDU@ATHENA.MIT.EDU",
                "krbtgt/EDU@MIT.EDU",
                "krbtgt/CMU.EDU@EDU",
                "krbtgt/CS.CMU.EDU@CMU.EDU"
            ]
        );
        assert_eq!(
            walk("TEST.REALM", "OTHER.REALM"),
            vec![
                "krbtgt/TEST.REALM@TEST.REALM",
                "krbtgt/REALM@TEST.REALM",
                "krbtgt/OTHER.REALM@REALM"
            ]
        );
        assert_eq!(
            walk("ABC.EXAMPLE.COM", "BC.EXAMPLE.COM"),
            vec![
                "krbtgt/ABC.EXAMPLE.COM@ABC.EXAMPLE.COM",
                "krbtgt/EXAMPLE.COM@ABC.EXAMPLE.COM",
                "krbtgt/BC.EXAMPLE.COM@EXAMPLE.COM"
            ]
        );
    }

    #[test]
    fn walk_realm_tree_same_realm_is_an_error() {
        assert_eq!(
            walk_realm_tree(b"A", b"A", None, b'.'),
            Err(TransitError::NoTktInRealm)
        );
    }

    #[test]
    fn walk_realm_tree_prefers_capaths() {
        let p = Profile::parse("[capaths]\n A.COM = {\n  B.COM = HUB.NET\n  C.COM = .\n }\n")
            .expect("p");
        let tree = walk_realm_tree(b"A.COM", b"B.COM", Some(&p), b'.').expect("walk");
        let names: Vec<(String, String)> = tree
            .iter()
            .map(|h| {
                (
                    String::from_utf8_lossy(&h.instance).to_string(),
                    String::from_utf8_lossy(&h.realm).to_string(),
                )
            })
            .collect();
        assert_eq!(
            names,
            vec![
                ("A.COM".into(), "A.COM".into()),
                ("HUB.NET".into(), "A.COM".into()),
                ("B.COM".into(), "HUB.NET".into())
            ]
        );
        let direct = walk_realm_tree(b"A.COM", b"C.COM", Some(&p), b'.').expect("walk");
        assert_eq!(direct.len(), 2);
    }

    fn add(old: &str, tgs: &str, c: &str, s: &str) -> String {
        String::from_utf8(
            add_to_transited(old.as_bytes(), tgs.as_bytes(), c.as_bytes(), s.as_bytes())
                .expect("add"),
        )
        .expect("utf8")
    }

    #[test]
    fn add_to_transited_leaves_list_alone_when_tgs_realm_is_client_or_server() {
        assert_eq!(add("", "A.COM", "A.COM", "B.COM"), "");
        assert_eq!(add("", "B.COM", "A.COM", "B.COM"), "");
    }

    #[test]
    fn add_to_transited_appends_intermediate_realm() {
        assert_eq!(
            add("", "EXAMPLE.COM", "A.EXAMPLE.COM", "B.EXAMPLE.COM"),
            "EXAMPLE.COM"
        );
        assert_eq!(add("", "HUB.NET", "A.COM", "B.COM"), "HUB.NET");
    }

    #[test]
    fn add_to_transited_compresses_subrealms() {
        assert_eq!(
            add("EDU", "MIT.EDU", "ATHENA.MIT.EDU", "CS.CMU.EDU"),
            "EDU,MIT."
        );
        assert_eq!(
            add("EDU,MIT.", "ATHENA.MIT.EDU", "XYZZY.COM", "CS.CMU.EDU"),
            "EDU,MIT.,ATHENA."
        );
    }

    #[test]
    fn add_to_transited_round_trips_through_decode() {
        let t = add("EDU", "MIT.EDU", "ATHENA.MIT.EDU", "CS.CMU.EDU");
        let realms = expand("ATHENA.MIT.EDU", "CS.CMU.EDU", &t).expect("decode");
        assert_eq!(realms, sorted(&["EDU", "MIT.EDU"]));
    }

    #[test]
    fn check_transited_list_accepts_hierarchical_path() {
        assert!(
            check_transited_list(b"EXAMPLE.COM", b"A.EXAMPLE.COM", b"B.EXAMPLE.COM", None).is_ok()
        );
        assert!(check_transited_list(b"", b"A.COM", b"B.COM", None).is_ok());
    }

    #[test]
    fn check_transited_list_rejects_realm_off_the_path() {
        assert_eq!(
            check_transited_list(b"EVIL.NET", b"A.EXAMPLE.COM", b"B.EXAMPLE.COM", None),
            Err(TransitError::IllCrTkt)
        );
    }

    #[test]
    fn check_transited_list_uses_capaths_when_configured() {
        let p = Profile::parse("[capaths]\n A.COM = {\n  B.COM = HUB.NET\n }\n").expect("p");
        assert!(check_transited_list(b"HUB.NET", b"A.COM", b"B.COM", Some(&p)).is_ok());
        assert!(check_transited_list(b"OTHER.NET", b"A.COM", b"B.COM", Some(&p)).is_err());
    }

    #[test]
    fn check_transited_list_skips_anonymous_client() {
        assert!(check_transited_list(b"X", b"WELLKNOWN:ANONYMOUS", b"B.COM", None).is_ok());
    }
}
