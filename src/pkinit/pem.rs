//! Tiny PEM reader/writer (RFC 7468) so no base64 crate is needed.

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn b64_value(c: u8) -> Option<u8> {
    match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

fn b64_decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let mut acc = 0u32;
    let mut bits = 0;
    for c in s.bytes() {
        if c == b'=' || c.is_ascii_whitespace() {
            continue;
        }
        acc = (acc << 6) | u32::from(b64_value(c)?);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    Some(out)
}

/// Every PEM block in `text` as (label, DER).
pub fn decode_all(text: &str) -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find("-----BEGIN ") {
        let after = &rest[start + 11..];
        let Some(label_end) = after.find("-----") else {
            break;
        };
        let label = &after[..label_end];
        let body_start = &after[label_end + 5..];
        let end_marker = format!("-----END {label}-----");
        let Some(end) = body_start.find(&end_marker) else {
            break;
        };
        if let Some(der) = b64_decode(&body_start[..end]) {
            out.push((label.to_string(), der));
        }
        rest = &body_start[end + end_marker.len()..];
    }
    out
}

/// Encode `der` as a PEM block with the given label.
pub fn encode(label: &str, der: &[u8]) -> String {
    let mut body = String::new();
    for chunk in der.chunks(3) {
        let n = match chunk.len() {
            3 => (u32::from(chunk[0]) << 16) | (u32::from(chunk[1]) << 8) | u32::from(chunk[2]),
            2 => (u32::from(chunk[0]) << 16) | (u32::from(chunk[1]) << 8),
            _ => u32::from(chunk[0]) << 16,
        };
        for i in 0..4 {
            if i <= chunk.len() {
                body.push(ALPHABET[((n >> (18 - 6 * i)) & 0x3f) as usize] as char);
            } else {
                body.push('=');
            }
        }
    }
    let mut out = format!("-----BEGIN {label}-----\n");
    for line in body.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(line).expect("ascii"));
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----\n"));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_all_lengths_and_multiple_blocks() {
        let mut text = String::new();
        for n in 0..70usize {
            let der: Vec<u8> = (0..n).map(|i| (i * 7 + n) as u8).collect();
            text.push_str(&encode("CERTIFICATE", &der));
            text.push_str("garbage between blocks\n");
        }
        let blocks = decode_all(&text);
        assert_eq!(blocks.len(), 70);
        for (n, (label, der)) in blocks.iter().enumerate() {
            assert_eq!(label, "CERTIFICATE");
            let want: Vec<u8> = (0..n).map(|i| (i * 7 + n) as u8).collect();
            assert_eq!(der, &want);
        }
    }

    #[test]
    fn known_vector_and_bad_input() {
        let blocks = decode_all("-----BEGIN X-----\nTWFu\n-----END X-----\n");
        assert_eq!(blocks[0].1, b"Man");
        assert!(decode_all("-----BEGIN X-----\n!!!!\n-----END X-----\n").is_empty());
        assert!(decode_all("no pem here").is_empty());
    }
}
