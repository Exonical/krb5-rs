//! Address, sequence-number, and authdata helpers shared by the AP
//! request/reply and safe/priv paths (mk_faddr.c, addr_srch.c,
//! privsafe.c, rd_req_dec.c, mk_req_ext.c).

use super::*;

/// Combine an address and port address into an ADDRTYPE_ADDRPORT
/// "full address" (os/mk_faddr.c:38-85 `krb5_make_fulladdr`).
pub(super) fn make_fulladdr(addr: &HostAddress, port: &HostAddress) -> HostAddress {
    let mut contents = Vec::with_capacity(addr.address.len() + port.address.len() + 16);
    contents.extend_from_slice(&[0, 0]);
    contents.extend_from_slice(&(addr.addr_type as i16).to_le_bytes());
    contents.extend_from_slice(&(addr.address.len() as i32).to_le_bytes());
    contents.extend_from_slice(&addr.address);
    contents.extend_from_slice(&[0, 0]);
    contents.extend_from_slice(&(port.addr_type as i16).to_le_bytes());
    contents.extend_from_slice(&(port.address.len() as i32).to_le_bytes());
    contents.extend_from_slice(&port.address);
    HostAddress {
        addr_type: ADDRTYPE_ADDRPORT,
        address: OctetString::from(contents),
    }
}

pub(super) fn address_compare(a: &HostAddress, b: &HostAddress) -> bool {
    a.addr_type == b.addr_type && a.address == b.address
}

/// MIT `krb5_address_search` (addr_srch.c): a NULL list matches anything;
/// a list containing only a NetBIOS address counts as empty.
pub(super) fn address_search(addr: &HostAddress, list: Option<&[HostAddress]>) -> bool {
    match list {
        None => true,
        Some(l) if l.len() == 1 && l[0].addr_type == ADDRTYPE_NETBIOS => true,
        Some(l) => l.iter().any(|a| address_compare(addr, a)),
    }
}

/// privsafe.c:206-223 `chk_heimdal_seqnum`.
pub(super) fn chk_heimdal_seqnum(exp_seq: u32, in_seq: u32) -> bool {
    ((exp_seq & 0xFF800000) == 0x00800000
        && (in_seq & 0xFF800000) == 0xFF800000
        && (in_seq & 0x00FFFFFF) == exp_seq)
        || ((exp_seq & 0xFFFF8000) == 0x00008000
            && (in_seq & 0xFFFF8000) == 0xFFFF8000
            && (in_seq & 0x0000FFFF) == exp_seq)
        || ((exp_seq & 0xFFFFFF80) == 0x00000080
            && (in_seq & 0xFFFFFF80) == 0xFFFFFF80
            && (in_seq & 0x000000FF) == exp_seq)
}

/// Extract the RFC 4537 etype list from authenticator authdata
/// (rd_req_dec.c:906-960 `decode_etype_list`): AD-IF_RELEVANT(1) is
/// unwrapped; a bare KRB5_AUTHDATA_ETYPE_NEGOTIATION(129) element is
/// also accepted.
pub(super) fn decode_etype_list(auth: &Authenticator) -> Vec<i32> {
    let Some(ad) = &auth.authorization_data else {
        return Vec::new();
    };
    for el in ad {
        match el.ad_type {
            1 => {
                if let Ok(inner) = rasn::der::decode::<Vec<AuthorizationDataElement>>(&el.ad_data) {
                    for e in inner {
                        if e.ad_type == 129 {
                            if let Ok(list) = rasn::der::decode::<Vec<i32>>(&e.ad_data) {
                                return list;
                            }
                        }
                    }
                }
            }
            129 => {
                if let Ok(list) = rasn::der::decode::<Vec<i32>>(&el.ad_data) {
                    return list;
                }
            }
            _ => {}
        }
    }
    Vec::new()
}

/// `negotiate_etype` (rd_req_dec.c:855-904): the mandatory segment
/// (from `mandatory_index` on — subkey and session etypes) must each be
/// permitted, then `permitted` is iterated in preference order and the
/// first permitted etype present anywhere in `desired` is negotiated.
///
/// `permitted == None` means PERMIT_ALL. MIT's own PERMIT_ALL path always
/// returns KRB5_NOPERM_ETYPE because the empty permitted list fails the
/// mandatory check (no MIT client relies on it), so we diverge there:
/// first desired wins, no mandatory check.
pub(super) fn negotiate_etype(
    desired: &[i32],
    mandatory_index: usize,
    permitted: Option<&[i32]>,
) -> Result<i32, ApError> {
    let Some(permitted) = permitted else {
        return desired.first().copied().ok_or(ApError::NoPermEtype);
    };
    for e in &desired[mandatory_index.min(desired.len())..] {
        if !permitted.contains(e) {
            return Err(ApError::NoPermEtype);
        }
    }
    for p in permitted {
        if desired.contains(p) {
            return Ok(*p);
        }
    }
    Err(ApError::NoPermEtype)
}

/// mk_req_ext.c:332-405 `make_ap_authdata` + `make_etype_list`: build the
/// AD-IF-RELEVANT element holding ETYPE_NEGOTIATION(129) and/or
/// AP_OPTIONS(143) entries.
pub(super) fn make_ap_authdata(
    desired: Option<&[i32]>,
    tkt_etype: i32,
    cbt: bool,
) -> Result<Option<AuthorizationDataElement>, Krb5Error> {
    let mut inner: Vec<AuthorizationDataElement> = Vec::new();
    if let Some(desired) = desired {
        if desired.first() != Some(&tkt_etype) {
            let mut count = desired.len();
            for (i, _) in desired.iter().enumerate() {
                if i > 0 && desired[i - 1] == tkt_etype {
                    count = i;
                    break;
                }
            }
            let list: Vec<i32> = desired[..count].to_vec();
            inner.push(AuthorizationDataElement {
                ad_type: 129,
                ad_data: OctetString::from(rasn::der::encode(&list)?),
            });
        }
    }
    if cbt {
        inner.push(AuthorizationDataElement {
            ad_type: 143,
            ad_data: OctetString::from(0x4000u32.to_le_bytes().to_vec()),
        });
    }
    if inner.is_empty() {
        return Ok(None);
    }
    Ok(Some(AuthorizationDataElement {
        ad_type: 1,
        ad_data: OctetString::from(rasn::der::encode(&inner)?),
    }))
}
