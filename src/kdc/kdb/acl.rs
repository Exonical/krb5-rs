//! MIT `kadm5.acl` parsing and checks (`lib/kadm5/srv/server_acl.c`).

use std::path::Path;

use crate::kdc::kdb::mit::parse_name_with_default;
use crate::kdc::kdb::restrictions::AclRestrictions;
use crate::types::PrincipalName;

/// `ACL_ADD` permission bit.
pub const ACL_ADD: u32 = 1;
/// `ACL_DELETE` permission bit.
pub const ACL_DELETE: u32 = 2;
/// `ACL_MODIFY` permission bit.
pub const ACL_MODIFY: u32 = 4;
/// `ACL_CHANGEPW` permission bit.
pub const ACL_CHANGEPW: u32 = 8;
/// `ACL_INQUIRE` permission bit.
pub const ACL_INQUIRE: u32 = 32;
/// `ACL_EXTRACT` permission bit.
pub const ACL_EXTRACT: u32 = 64;
/// `ACL_LIST` permission bit.
pub const ACL_LIST: u32 = 128;
/// `ACL_SETKEY` permission bit.
pub const ACL_SETKEY: u32 = 256;
/// `ACL_IPROP` permission bit.
pub const ACL_IPROP: u32 = 512;
/// `ACL_ALL_MASK` permission bit.
pub const ACL_ALL_MASK: u32 = ACL_ADD
    | ACL_DELETE
    | ACL_MODIFY
    | ACL_CHANGEPW
    | ACL_INQUIRE
    | ACL_LIST
    | ACL_IPROP
    | ACL_SETKEY;

/// `acl_op_table` (`auth_acl.c:71-84`).
pub const ACL_OPS: [(char, u32); 11] = [
    ('a', ACL_ADD),
    ('d', ACL_DELETE),
    ('m', ACL_MODIFY),
    ('c', ACL_CHANGEPW),
    ('i', ACL_INQUIRE),
    ('l', ACL_LIST),
    ('p', ACL_IPROP),
    ('s', ACL_SETKEY),
    ('x', ACL_ALL_MASK),
    ('*', ACL_ALL_MASK),
    ('e', ACL_EXTRACT),
];

/// One parsed ACL line (`auth_acl.c` `struct acl_entry`).
pub struct AclEntry {
    /// Client pattern; `None` matches any client.
    pub client: Option<(PrincipalName, String)>,
    /// Granted `ACL_*` bits.
    pub ops: u32,
    /// Target pattern; `None` matches any target.
    pub target: Option<(PrincipalName, String)>,
    /// Restrictions imposed when the entry grants access.
    pub restrictions: Option<AclRestrictions>,
}

/// `get_line` (`auth_acl.c:103-151`): logical lines with `\` continuations,
/// skipping empty and `#` lines.
pub fn acl_lines(text: &str) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    let mut buf = String::new();
    let mut start = 1;
    let raw: Vec<&str> = text.split_inclusive('\n').collect();
    for (i, line) in raw.iter().enumerate() {
        if buf.is_empty() {
            start = i + 1;
        }
        let Some(body) = line.strip_suffix('\n') else {
            buf.push_str(line);
            break;
        };
        buf.push_str(body);
        if buf.ends_with('\\') {
            buf.pop();
        } else if buf.is_empty() || buf.starts_with('#') {
            buf.clear();
        } else {
            out.push((start, std::mem::take(&mut buf)));
        }
    }
    if !buf.is_empty() && !buf.starts_with('#') {
        out.push((start, buf));
    }
    out
}

/// `parse_line` and `parse_entry` (`auth_acl.c:261-372`): client,
/// operations, optional target, and the rest of the line as restrictions.
pub fn parse_acl_line(line: &str, realm: &str) -> Option<AclEntry> {
    let ws = |c: char| matches!(c, '\t' | '\n' | '\x0c' | '\x0b' | '\r' | ' ' | ',');
    let line = line.trim_end_matches(|c: char| c.is_ascii_whitespace() || c == '\x0b');
    fn field(s: &str) -> (&str, &str) {
        let ws = |c: char| matches!(c, '\t' | '\n' | '\x0c' | '\x0b' | '\r' | ' ' | ',');
        let s = s.trim_start_matches(ws);
        let end = s.find(ws).unwrap_or(s.len());
        (&s[..end], &s[end..])
    }
    let (client, rest) = field(line);
    let (op_str, rest) = field(rest);
    let (target, rest) = field(rest);
    let rs = rest.trim_start_matches(ws);
    if client.is_empty() || op_str.is_empty() {
        return None;
    }
    let target = (!target.is_empty()).then_some(target);
    let mut ops = 0;
    for op in op_str.chars() {
        let lower = op.to_ascii_lowercase();
        let (_, mask) = ACL_OPS.iter().find(|(c, _)| *c == lower)?;
        if lower == op {
            ops |= mask;
        } else {
            ops &= !mask;
        }
    }
    let parse = |name: &str| parse_name_with_default(name, realm).ok();
    let client = match client {
        "*" => None,
        c => Some(parse(c)?),
    };
    let target = match target {
        None | Some("*") => None,
        Some(t) => Some(parse(t)?),
    };
    let restrictions = match rs {
        "" => None,
        rs => Some(AclRestrictions::parse(rs)?),
    };
    Some(AclEntry {
        client,
        ops,
        target,
        restrictions,
    })
}

/// Parse `kadm5.acl` text; errors name the offending line.
pub fn parse_acl(text: &str, realm: &str) -> Result<Vec<AclEntry>, String> {
    acl_lines(text)
        .into_iter()
        .map(|(n, line)| {
            parse_acl_line(&line, realm).ok_or_else(|| {
                let head: String = line.chars().take(10).collect();
                format!("syntax error at line {n} <{head}...>")
            })
        })
        .collect()
}

/// Read and parse a `kadm5.acl` file.
pub fn load_acl(path: &Path, realm: &str) -> Result<Vec<AclEntry>, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("{e} while opening ACL file {}", path.display()))?;
    parse_acl(&text, realm).map_err(|e| format!("{}: {e}", path.display()))
}

/// `match_data` (`auth_acl.c:439-466`): a client `*` records a
/// back-reference; a target `*1`..`*9` must equal the recorded component.
pub fn match_data(
    pattern: &[u8],
    value: &[u8],
    target: bool,
    ws: Option<&mut Vec<Vec<u8>>>,
) -> bool {
    if pattern == b"*" {
        if let (Some(ws), false) = (ws, target) {
            if ws.len() < 9 {
                ws.push(value.to_vec());
            }
        }
        return true;
    }
    match (ws, pattern) {
        (Some(ws), [b'*', n @ b'1'..=b'9']) if target => {
            ws.get(usize::from(n - b'1')).is_some_and(|b| b == value)
        }
        _ => pattern == value,
    }
}

/// `match_princ` (`auth_acl.c:468-490`).
pub fn match_princ(
    pattern: &(PrincipalName, String),
    name: &PrincipalName,
    realm: &str,
    target: bool,
    ws: &mut Vec<Vec<u8>>,
) -> bool {
    pattern.0.name_string.len() == name.name_string.len()
        && match_data(pattern.1.as_bytes(), realm.as_bytes(), target, None)
        && pattern
            .0
            .name_string
            .iter()
            .zip(&name.name_string)
            .all(|(p, n)| match_data(p.as_ref(), n.as_ref(), target, Some(ws)))
}

/// `find_entry` and `acl_check` (`auth_acl.c:492-545`): the first entry
/// matching the client and target decides. `Some` grants `op`, with that
/// entry's restrictions.
pub fn acl_check<'a>(
    acl: &'a [AclEntry],
    op: u32,
    (client, crealm): (&PrincipalName, &str),
    target: Option<(&PrincipalName, &str)>,
) -> Option<Option<&'a AclRestrictions>> {
    acl.iter()
        .find(|e| {
            let mut ws = Vec::new();
            if let Some(p) = &e.client {
                if !match_princ(p, client, crealm, false, &mut ws) {
                    return false;
                }
            }
            match (&e.target, target) {
                (None, _) => true,
                (Some(_), None) => false,
                (Some(p), Some((t, trealm))) => match_princ(p, t, trealm, true, &mut ws),
            }
        })
        .filter(|e| e.ops & op != 0)
        .map(|e| e.restrictions.as_ref())
}
