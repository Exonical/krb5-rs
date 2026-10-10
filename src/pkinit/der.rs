//! Minimal DER walking and building, for the places where PKINIT needs the
//! original bytes of a structure (certificate TBS, CMS signed attributes) or
//! the loosely typed parts of X.509 (otherName).

/// One decoded TLV: `tag`, its `content`, and the `whole` encoding.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Tlv<'a> {
    pub tag: u8,
    pub content: &'a [u8],
    pub whole: &'a [u8],
}

/// Read the TLV at the start of `b`; returns it and the remaining bytes.
/// Single-byte tags only.
pub(crate) fn read(b: &[u8]) -> Option<(Tlv<'_>, &[u8])> {
    let tag = *b.first()?;
    if tag & 0x1f == 0x1f {
        return None;
    }
    let first = *b.get(1)? as usize;
    let (hdr, len) = if first < 0x80 {
        (2, first)
    } else {
        let n = first & 0x7f;
        if n == 0 || n > 4 {
            return None;
        }
        let mut v = 0usize;
        for i in 0..n {
            v = (v << 8) | *b.get(2 + i)? as usize;
        }
        (2 + n, v)
    };
    let end = hdr.checked_add(len)?;
    let whole = b.get(..end)?;
    Some((
        Tlv {
            tag,
            content: &b[hdr..end],
            whole,
        },
        &b[end..],
    ))
}

/// All TLVs in `b` (a constructed value's content).
pub(crate) fn children(b: &[u8]) -> Option<Vec<Tlv<'_>>> {
    let mut out = Vec::new();
    let mut rest = b;
    while !rest.is_empty() {
        let (t, r) = read(rest)?;
        out.push(t);
        rest = r;
    }
    Some(out)
}

/// Encode a TLV.
pub(crate) fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let len = content.len();
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let bytes = len.to_be_bytes();
        let skip = bytes.iter().take_while(|b| **b == 0).count();
        out.push(0x80 | (bytes.len() - skip) as u8);
        out.extend_from_slice(&bytes[skip..]);
    }
    out.extend_from_slice(content);
    out
}

/// DER INTEGER of a non-negative big-endian magnitude.
pub(crate) fn uint(magnitude: &[u8]) -> Vec<u8> {
    let trimmed: &[u8] = {
        let skip = magnitude.iter().take_while(|b| **b == 0).count();
        if skip == magnitude.len() {
            &[0]
        } else {
            &magnitude[skip..]
        }
    };
    let mut c = Vec::with_capacity(trimmed.len() + 1);
    if trimmed[0] & 0x80 != 0 {
        c.push(0);
    }
    c.extend_from_slice(trimmed);
    tlv(0x02, &c)
}

/// The magnitude bytes of a DER INTEGER's content (leading zero removed).
pub(crate) fn uint_magnitude(content: &[u8]) -> &[u8] {
    let skip = content
        .iter()
        .take_while(|b| **b == 0)
        .count()
        .min(content.len().saturating_sub(1));
    &content[skip..]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tlv_round_trips_short_and_long_lengths() {
        for len in [0usize, 5, 127, 128, 300, 70_000] {
            let body = vec![7u8; len];
            let enc = tlv(0x04, &body);
            let (t, rest) = read(&enc).expect("read");
            assert!(rest.is_empty());
            assert_eq!((t.tag, t.content), (0x04, body.as_slice()));
            assert_eq!(t.whole, enc.as_slice());
        }
        assert!(read(&[0x30, 0x05, 1]).is_none());
        assert!(read(&[0x1f, 0x01, 0]).is_none());
    }

    #[test]
    fn uint_is_minimal_and_sign_safe() {
        assert_eq!(uint(&[0, 0, 5]), [0x02, 0x01, 0x05]);
        assert_eq!(uint(&[0x80]), [0x02, 0x02, 0x00, 0x80]);
        assert_eq!(uint(&[]), [0x02, 0x01, 0x00]);
        assert_eq!(uint_magnitude(&[0, 0x80]), [0x80]);
        assert_eq!(uint_magnitude(&[0]), [0]);
    }

    #[test]
    fn children_splits_a_sequence_body() {
        let mut body = tlv(0x02, &[1]);
        body.extend(tlv(0x04, b"ab"));
        let kids = children(&body).expect("children");
        assert_eq!(kids.len(), 2);
        assert_eq!(kids[1].content, b"ab");
    }
}
