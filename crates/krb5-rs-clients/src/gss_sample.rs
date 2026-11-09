//! gss-misc.c: token framing and display helpers shared by
//! krb5-rs-gss-client and krb5-rs-gss-server.

use std::io::{Read, Write};

use krb5_rs::gssapi::GssFlags;

/// No data; ends a message exchange.
pub const TOKEN_NOOP: u8 = 1 << 0;
/// A context-establishment token.
pub const TOKEN_CONTEXT: u8 = 1 << 1;
/// A message.
pub const TOKEN_DATA: u8 = 1 << 2;
/// A MIC over the last message.
pub const TOKEN_MIC: u8 = 1 << 3;
/// Context-establishment tokens follow.
pub const TOKEN_CONTEXT_NEXT: u8 = 1 << 4;
/// The message is wrapped.
pub const TOKEN_WRAPPED: u8 = 1 << 5;
/// The message is encrypted.
pub const TOKEN_ENCRYPTED: u8 = 1 << 6;
/// The peer wants a MIC back.
pub const TOKEN_SEND_MIC: u8 = 1 << 7;

/// `send_token`: a flags byte (omitted when zero, the version 1 format), a
/// four-byte big-endian length and the token.
pub fn send_token(s: &mut impl Write, flags: u8, tok: &[u8]) -> std::io::Result<()> {
    let len = u32::try_from(tok.len())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "token too long"))?;
    let mut buf = Vec::with_capacity(5 + tok.len());
    if flags != 0 {
        buf.push(flags);
    }
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(tok);
    s.write_all(&buf)?;
    s.flush()
}

/// `recv_token`: a zero flags byte is the first byte of a version 1
/// four-byte length.
pub fn recv_token(s: &mut impl Read) -> Result<(u8, Vec<u8>), String> {
    let mut flags = [0u8; 1];
    match s.read(&mut flags) {
        Ok(0) => return Err("reading token flags: 0 bytes read".into()),
        Ok(_) => {}
        Err(e) => return Err(format!("reading token flags: {e}")),
    }
    let mut len = [0u8; 4];
    let lenbuf = if flags[0] == 0 {
        &mut len[1..]
    } else {
        &mut len[..]
    };
    let want = lenbuf.len();
    s.read_exact(lenbuf)
        .map_err(|_| format!("reading token length: fewer than {want} bytes read"))?;
    let n = u32::from_be_bytes(len) as usize;
    let mut tok = vec![0u8; n];
    s.read_exact(&mut tok)
        .map_err(|_| format!("reading token data: fewer than {n} bytes read"))?;
    Ok((flags[0], tok))
}

/// `display_status`.
pub fn display_status(out: &mut dyn Write, msg: &str, e: &krb5_rs::Krb5Error) {
    let _ = writeln!(out, "GSS-API error {msg}: {}", crate::krb5_message(e));
}

/// `display_ctx_flags`.
pub fn display_ctx_flags(out: &mut dyn Write, flags: GssFlags) {
    for (f, name) in [
        (GssFlags::DELEG, "GSS_C_DELEG_FLAG"),
        (GssFlags::MUTUAL, "GSS_C_MUTUAL_FLAG"),
        (GssFlags::REPLAY, "GSS_C_REPLAY_FLAG"),
        (GssFlags::SEQUENCE, "GSS_C_SEQUENCE_FLAG"),
        (GssFlags::CONF, "GSS_C_CONF_FLAG "),
        (GssFlags::INTEG, "GSS_C_INTEG_FLAG "),
    ] {
        if flags.contains(f) {
            let _ = writeln!(out, "context flag: {name}");
        }
    }
}

/// `print_token`: hex, sixteen bytes per line.
pub fn print_token(out: &mut dyn Write, tok: &[u8]) {
    for (i, b) in tok.iter().enumerate() {
        let _ = write!(out, "{b:02x} ");
        if i % 16 == 15 {
            let _ = writeln!(out);
        }
    }
    let _ = writeln!(out);
    let _ = out.flush();
}

/// `gss_oid_to_str`: `{ 1 2 840 113554 1 2 2 }`.
pub fn oid_to_str(oid: &[u8]) -> String {
    let mut arcs: Vec<u64> = Vec::new();
    let mut v = 0u64;
    for (i, b) in oid.iter().enumerate() {
        v = (v << 7) | u64::from(b & 0x7f);
        if b & 0x80 == 0 {
            if arcs.is_empty() {
                let first = (v / 40).min(2);
                arcs.push(first);
                arcs.push(v - first * 40);
            } else {
                arcs.push(v);
            }
            v = 0;
        } else if i == oid.len() - 1 {
            break;
        }
    }
    let body: Vec<String> = arcs.iter().map(u64::to_string).collect();
    format!("{{ {} }}", body.join(" "))
}

/// `gss_str_to_oid`: parse `{ 1 2 840 ... }` or `1.2.840...`.
pub fn str_to_oid(s: &str) -> Option<Vec<u8>> {
    let s = s.trim().trim_start_matches('{').trim_end_matches('}');
    let arcs: Vec<u64> = s
        .split(|c: char| c == '.' || c.is_whitespace())
        .filter(|a| !a.is_empty())
        .map(str::parse)
        .collect::<Result<_, _>>()
        .ok()?;
    if arcs.len() < 2 || arcs[0] > 2 {
        return None;
    }
    let mut out = Vec::new();
    let mut push = |mut v: u64| {
        let mut tmp = vec![(v & 0x7f) as u8];
        v >>= 7;
        while v > 0 {
            tmp.push(((v & 0x7f) as u8) | 0x80);
            v >>= 7;
        }
        tmp.reverse();
        out.extend_from_slice(&tmp);
    };
    push(arcs[0] * 40 + arcs[1]);
    for a in &arcs[2..] {
        push(*a);
    }
    Some(out)
}

/// The mechanism OID in an RFC 2743 initial context token.
pub fn token_mech(tok: &[u8]) -> Option<&[u8]> {
    if *tok.first()? != 0x60 {
        return None;
    }
    let mut i = 2usize;
    let l = *tok.get(1)?;
    if l & 0x80 != 0 {
        i += usize::from(l & 0x7f);
    }
    if *tok.get(i)? != 0x06 {
        return None;
    }
    let n = usize::from(*tok.get(i + 1)?);
    tok.get(i + 2..i + 2 + n)
}

/// krb5_gss_inquire_names_for_mech (inq_names.c).
pub const KRB5_NAME_TYPES: &[&[u8]] = &[
    b"\x2a\x86\x48\x86\xf7\x12\x01\x02\x01\x01",
    b"\x2a\x86\x48\x86\xf7\x12\x01\x02\x01\x02",
    b"\x2a\x86\x48\x86\xf7\x12\x01\x02\x01\x03",
    b"\x2a\x86\x48\x86\xf7\x12\x01\x02\x01\x04",
    b"\x2b\x06\x01\x05\x06\x02",
    b"\x2b\x06\x01\x05\x06\x04",
    b"\x2a\x86\x48\x86\xf7\x12\x01\x02\x02\x01",
    b"\x2b\x06\x01\x05\x06\x06",
    b"\x2a\x86\x48\x86\xf7\x12\x01\x02\x02\x02",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oid_strings() {
        let krb5 = krb5_rs::gssapi::krb5::MECH_KRB5;
        assert_eq!(oid_to_str(krb5), "{ 1 2 840 113554 1 2 2 }");
        assert_eq!(str_to_oid("{ 1 2 840 113554 1 2 2 }").unwrap(), krb5);
        assert_eq!(
            str_to_oid("1.3.6.1.5.2.5").unwrap(),
            krb5_rs::gssapi::krb5::MECH_IAKERB
        );
    }

    #[test]
    fn framing() {
        let mut v = Vec::new();
        send_token(&mut v, TOKEN_DATA, b"abc").unwrap();
        assert_eq!(
            recv_token(&mut v.as_slice()).unwrap(),
            (TOKEN_DATA, b"abc".to_vec())
        );
        let mut v = Vec::new();
        send_token(&mut v, 0, b"xy").unwrap();
        assert_eq!(v, b"\0\0\0\x02xy");
        assert_eq!(recv_token(&mut v.as_slice()).unwrap(), (0, b"xy".to_vec()));
    }
}
