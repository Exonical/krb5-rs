//! SPNEGO DER codec (spnego_mech.c get/put_negToken*).

use super::*;

pub(super) const TAG_HEADER: u8 = 0x60;
const TAG_OID: u8 = 0x06;
const TAG_OCTET_STRING: u8 = 0x04;
const TAG_SEQUENCE: u8 = 0x30;
const TAG_ENUMERATED: u8 = 0x0a;
pub(super) const TAG_GENERAL_STRING: u8 = 0x1b;
const TAG_BIT_STRING: u8 = 0x03;
const BIT_STRING_LENGTH: u8 = 0x02;
const BIT_STRING_PADDING: u8 = 0x01;
pub(super) const CTX: u8 = 0xa0;

/// Cursor over a DER buffer mirroring MIT's `struct k5input`
/// (k5-der.h): `bad` is the sticky error status set when a read runs past
/// the end or a matched tag has an invalid length.
struct In<'a> {
    buf: &'a [u8],
    bad: bool,
}

impl<'a> In<'a> {
    fn new(buf: &'a [u8]) -> Self {
        In { buf, bad: false }
    }

    /// k5_der_get_taglen + k5_input_get_bytes: if the next byte matches
    /// `tag` and the definite length is valid and in-bounds, consume and
    /// return the contents.  On tag mismatch, return None *without*
    /// consuming or erroring (k5-der.h:118-120).  A matched tag with a
    /// truncated length/value sets `bad` (k5-der.h:123-143).
    fn value(&mut self, tag: u8) -> Option<&'a [u8]> {
        if self.bad || self.buf.first() != Some(&tag) {
            return None;
        }
        self.buf = &self.buf[1..];
        let lenbyte = *self.buf.first().unwrap_or(&0);
        if self.buf.is_empty() {
            self.bad = true;
            return None;
        }
        self.buf = &self.buf[1..];
        let len = if lenbyte < 0x80 {
            lenbyte as usize
        } else {
            let n = (lenbyte & 0x7f) as usize;
            let mut len: usize = 0;
            for _ in 0..n {
                match self.buf.first() {
                    Some(&b) => {
                        match len.checked_mul(256).and_then(|l| l.checked_add(b as usize)) {
                            Some(l) => len = l,
                            None => {
                                self.bad = true;
                                return None;
                            }
                        }
                        self.buf = &self.buf[1..];
                    }
                    None => {
                        self.bad = true;
                        return None;
                    }
                }
            }
            len
        };
        if len > self.buf.len() {
            self.bad = true;
            return None;
        }
        let (v, rest) = self.buf.split_at(len);
        self.buf = rest;
        Some(v)
    }

    fn status(&self) -> bool {
        self.bad
    }
}

/// put_mech_set (:3353-3380): `SEQUENCE OF OID` — the contents of the
/// NegTokenInit [0] field, and the exact blob mechListMIC covers.
pub(super) fn put_mech_set(mechs: &[Vec<u8>]) -> Vec<u8> {
    let ilen: usize = mechs.iter().map(|o| der_value_len(o.len())).sum();
    let mut out = Vec::new();
    der_taglen(&mut out, TAG_SEQUENCE, ilen);
    for o in mechs {
        der_taglen(&mut out, TAG_OID, o.len());
        out.extend_from_slice(o);
    }
    out
}

/// Decode a `SEQUENCE OF OID` into OID contents vectors.  Mirrors
/// get_mech_set (:3320-3350): the SEQUENCE OF tag is required; every
/// element must be an OID TLV; anything else fails the whole decode
/// (GSS_S_FAILURE in MIT).
fn get_mech_set(field: &[u8]) -> Option<Vec<Vec<u8>>> {
    let mut input = In::new(field);
    let mut seq = In::new(input.value(TAG_SEQUENCE)?);
    let mut mechs = Vec::new();
    while !seq.status() && !seq.buf.is_empty() {
        mechs.push(seq.value(TAG_OID)?.to_vec());
    }
    if seq.status() {
        return None;
    }
    Some(mechs)
}

/// make_spnego_tokenInit_msg (:3618-3700): RFC 2743 framing with
/// MECH_SPNEGO around `[0] { SEQUENCE { [0] mechTypes, [2] mechToken,
/// [3] mechListMIC } }`.  `der_mech_types` is the contents of [0], i.e.
/// the `SEQUENCE OF OID` TLV.  reqFlags is never emitted.  When
/// `neg_hints_compat` is set, the [3] value uses a SEQUENCE tag instead
/// of OCTET STRING (:3688-3693).
pub fn encode_neg_token_init(
    der_mech_types: &[u8],
    mech_token: Option<&[u8]>,
    mic: Option<&[u8]>,
    neg_hints_compat: bool,
) -> Vec<u8> {
    let mut fields = Vec::new();
    der_taglen(&mut fields, CTX, der_mech_types.len());
    fields.extend_from_slice(der_mech_types);
    if let Some(tok) = mech_token {
        der_taglen(&mut fields, CTX | 0x02, der_value_len(tok.len()));
        der_taglen(&mut fields, TAG_OCTET_STRING, tok.len());
        fields.extend_from_slice(tok);
    }
    if let Some(m) = mic {
        der_taglen(&mut fields, CTX | 0x03, der_value_len(m.len()));
        let id = if neg_hints_compat {
            TAG_SEQUENCE
        } else {
            TAG_OCTET_STRING
        };
        der_taglen(&mut fields, id, m.len());
        fields.extend_from_slice(m);
    }
    let mut choice = Vec::new();
    der_taglen(&mut choice, TAG_SEQUENCE, fields.len());
    choice.extend_from_slice(&fields);

    let mut body = Vec::new();
    der_taglen(&mut body, CTX, choice.len());
    body.extend_from_slice(&choice);

    let mut out = Vec::new();
    der_taglen(
        &mut out,
        TAG_HEADER,
        der_value_len(MECH_SPNEGO.len()) + body.len(),
    );
    der_taglen(&mut out, TAG_OID, MECH_SPNEGO.len());
    out.extend_from_slice(MECH_SPNEGO);
    out.extend_from_slice(&body);
    out
}

/// make_spnego_tokenTarg_msg (:3702-3786): unframed
/// `[1] { SEQUENCE { [0] ENUMERATED negState, [1] OID supportedMech,
/// [2] OCTET STRING responseToken, [3] OCTET STRING mechListMIC } }`.
/// supportedMech is emitted only when given (callers pass it on the
/// INIT_TOKEN_SEND reply); an empty responseToken is omitted (:3737).
pub fn encode_neg_token_resp(
    state: NegState,
    supported_mech: Option<&[u8]>,
    token: Option<&[u8]>,
    mic: Option<&[u8]>,
) -> Vec<u8> {
    let mut fields = Vec::new();
    der_taglen(&mut fields, CTX, der_value_len(1));
    der_taglen(&mut fields, TAG_ENUMERATED, 1);
    fields.push(state as u8);
    if let Some(m) = supported_mech {
        der_taglen(&mut fields, CTX | 0x01, der_value_len(m.len()));
        der_taglen(&mut fields, TAG_OID, m.len());
        fields.extend_from_slice(m);
    }
    if let Some(t) = token {
        if !t.is_empty() {
            der_taglen(&mut fields, CTX | 0x02, der_value_len(t.len()));
            der_taglen(&mut fields, TAG_OCTET_STRING, t.len());
            fields.extend_from_slice(t);
        }
    }
    if let Some(m) = mic {
        der_taglen(&mut fields, CTX | 0x03, der_value_len(m.len()));
        der_taglen(&mut fields, TAG_OCTET_STRING, m.len());
        fields.extend_from_slice(m);
    }
    let mut out = Vec::new();
    der_taglen(&mut out, CTX | 0x01, der_value_len(fields.len()));
    der_taglen(&mut out, TAG_SEQUENCE, fields.len());
    out.extend_from_slice(&fields);
    out
}

/// get_negTokenInit (:3407-3478).  `tok` must carry RFC 2743 framing with
/// the SPNEGO OID.  Returns the decoded token plus the exact contents of
/// the [0] mechTypes field (the `SEQUENCE OF` TLV — the MIC input).
pub fn decode_neg_token_init(tok: &[u8]) -> Result<(NegTokenInit, Vec<u8>), GssError> {
    let mut input = In::new(tok);
    // verify_token_header (:3790-3805): framing + thisMech == SPNEGO.
    let mut framed = In::new(input.value(TAG_HEADER).ok_or(GssError::DefectiveToken)?);
    if input.status() {
        return Err(GssError::DefectiveToken);
    }
    let oid = framed.value(TAG_OID).ok_or(GssError::DefectiveToken)?;
    if oid != MECH_SPNEGO {
        return Err(GssError::DefectiveToken);
    }

    let mut seq = In::new(framed.value(CTX).ok_or(GssError::DefectiveToken)?);
    let mut seq = In::new(seq.value(TAG_SEQUENCE).ok_or(GssError::DefectiveToken)?);

    let field = seq.value(CTX).ok_or(GssError::DefectiveToken)?;
    if field.is_empty() {
        return Err(GssError::DefectiveToken);
    }
    let der_mech_types = field.to_vec();
    // get_mech_set failure is GSS_S_FAILURE in MIT (:3448-3451).
    let mech_types = get_mech_set(field).ok_or(GssError::Failure)?;

    let mut req_flags = None;
    if let Some(f) = seq.value(CTX | 0x01) {
        // get_req_flags (:3393-3401): contents are exactly
        // 03 02 01 <flags-byte>; flags = byte >> 1.
        if f.len() != 4
            || f[0] != TAG_BIT_STRING
            || f[1] != BIT_STRING_LENGTH
            || f[2] != BIT_STRING_PADDING
        {
            return Err(GssError::DefectiveToken);
        }
        req_flags = Some(f[3] >> 1);
    }
    let mut mech_token = None;
    if let Some(f) = seq.value(CTX | 0x02) {
        // get_octet_string failure is GSS_S_FAILURE here (:3457-3460).
        mech_token = Some(
            In::new(f)
                .value(TAG_OCTET_STRING)
                .ok_or(GssError::Failure)?
                .to_vec(),
        );
    }
    let mut mech_list_mic = None;
    if let Some(f) = seq.value(CTX | 0x03) {
        mech_list_mic = Some(
            In::new(f)
                .value(TAG_OCTET_STRING)
                .ok_or(GssError::Failure)?
                .to_vec(),
        );
    }
    if seq.status() {
        return Err(GssError::DefectiveToken);
    }
    Ok((
        NegTokenInit {
            mech_types,
            req_flags,
            mech_token,
            mech_list_mic,
        },
        der_mech_types,
    ))
}

/// get_negTokenResp (:3480-3548).  `body` is the unframed NegTokenResp
/// (the `[1]` choice); callers strip optional RFC 2743 framing first.
pub fn decode_neg_token_resp(body: &[u8]) -> Result<NegTokenResp, GssError> {
    let mut input = In::new(body);
    let mut seq = In::new(input.value(CTX | 0x01).ok_or(GssError::DefectiveToken)?);
    // Historically the SEQUENCE tag may be missing (:3494-3496).
    if let Some(inner) = seq.value(TAG_SEQUENCE) {
        seq = In::new(inner);
    }

    let mut neg_state = None;
    if let Some(f) = seq.value(CTX) {
        let en = In::new(f)
            .value(TAG_ENUMERATED)
            .ok_or(GssError::DefectiveToken)?;
        if en.len() != 1 {
            return Err(GssError::DefectiveToken);
        }
        neg_state = Some(match en[0] {
            0 => NegState::AcceptCompleted,
            1 => NegState::AcceptIncomplete,
            2 => NegState::Reject,
            3 => NegState::RequestMic,
            // MIT stores the raw byte and only compares it; we reject
            // out-of-range values at the decoder (documented divergence).
            _ => return Err(GssError::DefectiveToken),
        });
    }
    let mut supported_mech = None;
    if let Some(f) = seq.value(CTX | 0x01) {
        supported_mech = Some(
            In::new(f)
                .value(TAG_OID)
                .ok_or(GssError::DefectiveToken)?
                .to_vec(),
        );
    }
    let mut response_token = None;
    if let Some(f) = seq.value(CTX | 0x02) {
        response_token = Some(
            In::new(f)
                .value(TAG_OCTET_STRING)
                .ok_or(GssError::DefectiveToken)?
                .to_vec(),
        );
    }
    let mut mech_list_mic = None;
    if let Some(f) = seq.value(CTX | 0x03) {
        // MIT dereferences the NULL result here when responseToken is
        // present (:3527-3530); we return DefectiveToken instead.
        match In::new(f).value(TAG_OCTET_STRING) {
            Some(m) => mech_list_mic = Some(m.to_vec()),
            None if response_token.is_some() => return Err(GssError::DefectiveToken),
            None => {}
        }
    }
    // Windows 2000 duplicate-response-token quirk (:3525-3536).
    if let (Some(tok_v), Some(mic_v)) = (&response_token, &mech_list_mic) {
        if tok_v == mic_v {
            mech_list_mic = None;
        }
    }
    if seq.status() {
        return Err(GssError::DefectiveToken);
    }
    Ok(NegTokenResp {
        neg_state,
        supported_mech,
        response_token,
        mech_list_mic,
    })
}
