//! Raw KDC-REQ-BODY extraction (MIT `fetch_asn1_field(pkt, 1, 4, ...)`,
//! asn1_get.c): authenticator and PA-REQ-ENC-PA-REP checksums cover the
//! bytes exactly as received, never a re-encoding of the decoded body.

use crate::Krb5Error;

const TAG_AS_REQ: u8 = 0x6A;
const TAG_TGS_REQ: u8 = 0x6C;
const TAG_SEQUENCE: u8 = 0x30;
const TAG_BODY: u8 = 0xA4;

fn bad(msg: &str) -> Krb5Error {
    Krb5Error::Protocol(format!("malformed KDC-REQ: {msg}"))
}

/// Parse one definite-length TLV at the start of `buf` (single-byte tags).
/// Returns `(tag, header_len, content_len)`; the caller checks `buf` holds
/// the whole element.
fn read_tlv(buf: &[u8]) -> Result<(u8, usize, usize), Krb5Error> {
    let tag = *buf.first().ok_or_else(|| bad("truncated tag"))?;
    if tag & 0x1F == 0x1F {
        return Err(bad("multi-byte tag"));
    }
    let first = *buf.get(1).ok_or_else(|| bad("truncated length"))?;
    let (header, len) = match first {
        0x80 => return Err(bad("indefinite length")),
        0x00..=0x7F => (2, usize::from(first)),
        0x81..=0x84 => {
            let n = usize::from(first & 0x7F);
            let bytes = buf.get(2..2 + n).ok_or_else(|| bad("truncated length"))?;
            let len = bytes.iter().fold(0usize, |a, &b| (a << 8) | usize::from(b));
            (2 + n, len)
        }
        _ => return Err(bad("unsupported length form")),
    };
    let total = header
        .checked_add(len)
        .ok_or_else(|| bad("length overflow"))?;
    if buf.len() < total {
        return Err(bad("truncated element"));
    }
    Ok((tag, header, len))
}

/// Return the exact KDC-REQ-BODY TLV bytes from a DER AS-REQ/TGS-REQ:
/// APPLICATION(10|12) → SEQUENCE → `[4]` EXPLICIT → inner TLV.
pub(crate) fn raw_req_body(req_der: &[u8]) -> Result<&[u8], Krb5Error> {
    let (tag, hdr, len) = read_tlv(req_der)?;
    if tag != TAG_AS_REQ && tag != TAG_TGS_REQ {
        return Err(bad("not an AS-REQ or TGS-REQ"));
    }
    if hdr + len != req_der.len() {
        return Err(bad("trailing bytes after request"));
    }
    let app_content = &req_der[hdr..];

    let (tag, hdr, len) = read_tlv(app_content)?;
    if tag != TAG_SEQUENCE {
        return Err(bad("expected SEQUENCE"));
    }
    if hdr + len != app_content.len() {
        return Err(bad("trailing bytes after SEQUENCE"));
    }
    let mut fields = &app_content[hdr..];

    while !fields.is_empty() {
        let (tag, hdr, len) = read_tlv(fields)?;
        let content = &fields[hdr..hdr + len];
        if tag == TAG_BODY {
            let (_, ihdr, ilen) = read_tlv(content)?;
            if ihdr + ilen != content.len() {
                return Err(bad("trailing bytes in req-body field"));
            }
            return Ok(content);
        }
        fields = &fields[hdr + len..];
    }
    Err(bad("req-body field missing"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        match content.len() {
            n if n < 0x80 => out.push(n as u8),
            n if n < 0x100 => out.extend([0x81, n as u8]),
            n => out.extend([0x82, (n >> 8) as u8, n as u8]),
        }
        out.extend_from_slice(content);
        out
    }

    fn request_with_body(body: &[u8]) -> Vec<u8> {
        let mut fields = tlv(0xA1, &tlv(0x02, &[5]));
        fields.extend(tlv(0xA2, &tlv(0x02, &[10])));
        fields.extend(tlv(TAG_BODY, body));
        tlv(TAG_AS_REQ, &tlv(TAG_SEQUENCE, &fields))
    }

    #[test]
    fn raw_req_body_short_form_returns_body_tlv() {
        let body = tlv(TAG_SEQUENCE, &[0xA0, 0x00]);
        let req = request_with_body(&body);
        assert_eq!(raw_req_body(&req).expect("body"), body.as_slice());
    }

    #[test]
    fn raw_req_body_long_form_lengths_return_full_body() {
        let body = tlv(TAG_SEQUENCE, &vec![0x04; 300]);
        assert_eq!(body[1], 0x82);
        let req = request_with_body(&body);
        assert_eq!(req[1], 0x82);
        assert_eq!(raw_req_body(&req).expect("body"), body.as_slice());
    }

    #[test]
    fn raw_req_body_one_byte_long_form_length_is_accepted() {
        let body = tlv(TAG_SEQUENCE, &[0x04; 130]);
        assert_eq!(body[1], 0x81);
        let req = request_with_body(&body);
        assert_eq!(raw_req_body(&req).expect("body"), body.as_slice());
    }

    #[test]
    fn raw_req_body_tgs_req_tag_is_accepted() {
        let body = tlv(TAG_SEQUENCE, &[]);
        let mut req = request_with_body(&body);
        req[0] = TAG_TGS_REQ;
        assert_eq!(raw_req_body(&req).expect("body"), body.as_slice());
    }

    #[test]
    fn raw_req_body_truncated_input_is_rejected() {
        let req = request_with_body(&tlv(TAG_SEQUENCE, &[1, 2, 3]));
        for cut in [0, 1, 2, 5, req.len() - 1] {
            assert!(raw_req_body(&req[..cut]).is_err(), "cut at {cut}");
        }
    }

    #[test]
    fn raw_req_body_indefinite_length_is_rejected() {
        let req = [TAG_AS_REQ, 0x80, TAG_SEQUENCE, 0x80, 0x00, 0x00, 0x00, 0x00];
        assert!(raw_req_body(&req).is_err());
    }

    #[test]
    fn raw_req_body_trailing_bytes_are_rejected() {
        let mut req = request_with_body(&tlv(TAG_SEQUENCE, &[1]));
        req.push(0);
        assert!(raw_req_body(&req).is_err());
    }

    #[test]
    fn raw_req_body_wrong_application_tag_is_rejected() {
        let mut req = request_with_body(&tlv(TAG_SEQUENCE, &[1]));
        req[0] = 0x6E;
        assert!(raw_req_body(&req).is_err());
    }

    #[test]
    fn raw_req_body_missing_body_field_is_rejected() {
        let req = tlv(TAG_AS_REQ, &tlv(TAG_SEQUENCE, &tlv(0xA1, &tlv(0x02, &[5]))));
        assert!(raw_req_body(&req).is_err());
    }

    #[test]
    fn raw_req_body_matches_real_encoding() {
        use crate::types::*;
        let body = KdcReqBody {
            kdc_options: KerberosFlags::new(KdcOptions::FORWARDABLE),
            cname: None,
            realm: rasn::types::GeneralString::from_bytes(b"R").expect("realm"),
            sname: None,
            from: None,
            till: chrono::DateTime::from_timestamp(1_000_000, 0)
                .expect("time")
                .fixed_offset(),
            rtime: None,
            nonce: 7,
            etype: vec![18],
            addresses: None,
            enc_authorization_data: None,
            additional_tickets: None,
        };
        let body_der = rasn::der::encode(&body).expect("encode body");
        let req = AsReq(KdcReq {
            pvno: 5,
            msg_type: 10,
            padata: None,
            req_body: body,
        });
        let der = rasn::der::encode(&req).expect("encode req");
        assert_eq!(raw_req_body(&der).expect("body"), body_der.as_slice());
    }
}
