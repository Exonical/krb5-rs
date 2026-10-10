//! RFC 2743 generic token framing, per MIT generic/util_token.c.

/// DER-encode a tag + length, appending to `out`.
pub(crate) fn der_taglen(out: &mut Vec<u8>, tag: u8, len: usize) {
    out.push(tag);
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let mut n = 0usize;
        let mut l = len;
        while l > 0 {
            n += 1;
            l >>= 8;
        }
        out.push(0x80 | n as u8);
        for i in (0..n).rev() {
            out.push((len >> (8 * i)) as u8);
        }
    }
}

pub(crate) fn der_value_len(len: usize) -> usize {
    1 + len
        + if len < 0x80 {
            1
        } else if len <= 0xff {
            2
        } else if len <= 0xffff {
            3
        } else {
            4
        }
}

/// Build the generic token framing: `0x60` application tag wrapping
/// `0x06`-tagged mechanism OID, followed by an optional two-byte big-endian
/// RFC 4121 token identifier.  Mirrors g_make_token_header
/// (generic/util_token.c:51-62).
pub fn make_token_header(mech: &[u8], body_len: usize, tok_id: Option<u16>) -> Vec<u8> {
    let tok_len = if tok_id.is_some() { 2 } else { 0 };
    let seq_len = der_value_len(mech.len()) + body_len + tok_len;
    let mut out = Vec::new();
    der_taglen(&mut out, 0x60, seq_len);
    der_taglen(&mut out, 0x06, mech.len());
    out.extend_from_slice(mech);
    if let Some(id) = tok_id {
        out.extend_from_slice(&id.to_be_bytes());
    }
    out
}

fn der_read_len(tok: &[u8], pos: &mut usize) -> Option<usize> {
    let b = *tok.get(*pos)?;
    *pos += 1;
    if b < 0x80 {
        Some(b as usize)
    } else {
        let n = (b & 0x7f) as usize;
        if n == 0 || n > 4 {
            return None;
        }
        let mut len = 0usize;
        for _ in 0..n {
            len = (len << 8) | (*tok.get(*pos)? as usize);
            *pos += 1;
        }
        Some(len)
    }
}

/// Parse a generic token header, returning the mechanism OID bytes and the
/// token body (everything after the framing).  Returns None if the framing
/// is malformed or the indicated token length does not equal `tok.len()`
/// (the total-length check MIT applies in parse_init_token /
/// g_verify_token_header, generic/util_token.c:75-116).
pub fn parse_token_header(tok: &[u8]) -> Option<(&[u8], &[u8])> {
    if tok.first() != Some(&0x60) {
        return None;
    }
    let mut pos = 1;
    let len = der_read_len(tok, &mut pos)?;
    let header_len = pos;
    if header_len + len != tok.len() {
        return None;
    }
    if tok.get(pos) != Some(&0x06) {
        return None;
    }
    pos += 1;
    let oid_len = der_read_len(tok, &mut pos)?;
    let mech = tok.get(pos..pos + oid_len)?;
    Some((mech, &tok[pos + oid_len..]))
}
