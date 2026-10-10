//! Ccache credential (un)marshalling — ccmarshal.c.
//!
//! Versions 1-2 use native byte order; versions 3-4 use big-endian.
//! Version 1 omits the principal name type and counts the realm in the
//! component count.  Version 3 writes the keyblock enctype twice.

use rasn::types::{GeneralString, OctetString};

use super::{CcCredential, CcError};
use crate::types::{AuthorizationDataElement, EncryptionKey, HostAddress, PrincipalName};

/// Buffer writer honoring the version's byte order.
struct W {
    buf: Vec<u8>,
    be: bool,
}

impl W {
    fn new(version: u8) -> Self {
        Self {
            buf: Vec::new(),
            be: version >= 3,
        }
    }
    fn u8(&mut self, v: u8) {
        self.buf.push(v);
    }
    fn i16(&mut self, v: i16) {
        if self.be {
            self.buf.extend_from_slice(&v.to_be_bytes());
        } else {
            self.buf.extend_from_slice(&v.to_ne_bytes());
        }
    }
    fn i32(&mut self, v: i32) {
        if self.be {
            self.buf.extend_from_slice(&v.to_be_bytes());
        } else {
            self.buf.extend_from_slice(&v.to_ne_bytes());
        }
    }
    /// i32 length + bytes.
    fn data(&mut self, v: &[u8]) {
        self.i32(v.len() as i32);
        self.buf.extend_from_slice(v);
    }
}

/// Reader over a byte slice; any short read is Format.
struct R<'a> {
    d: &'a [u8],
    pos: usize,
    be: bool,
}

impl<'a> R<'a> {
    fn new(d: &'a [u8], version: u8) -> Self {
        Self {
            d,
            pos: 0,
            be: version >= 3,
        }
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], CcError> {
        if self.d.len() - self.pos < n {
            return Err(CcError::Format);
        }
        let s = &self.d[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }
    fn u8(&mut self) -> Result<u8, CcError> {
        Ok(self.take(1)?[0])
    }
    fn i16(&mut self) -> Result<i16, CcError> {
        let b: [u8; 2] = self.take(2)?.try_into().map_err(|_| CcError::Format)?;
        Ok(if self.be {
            i16::from_be_bytes(b)
        } else {
            i16::from_ne_bytes(b)
        })
    }
    fn i32(&mut self) -> Result<i32, CcError> {
        let b: [u8; 4] = self.take(4)?.try_into().map_err(|_| CcError::Format)?;
        Ok(if self.be {
            i32::from_be_bytes(b)
        } else {
            i32::from_ne_bytes(b)
        })
    }
    /// i32 length + bytes; negative length or length past the end → Format.
    fn data(&mut self) -> Result<&'a [u8], CcError> {
        let len = self.i32()?;
        if len < 0 {
            return Err(CcError::Format);
        }
        self.take(len as usize)
    }
    fn gs(&mut self) -> Result<GeneralString, CcError> {
        GeneralString::from_bytes(self.data()?).map_err(|_| CcError::Format)
    }
}

fn marshal_princ_w(w: &mut W, p: &PrincipalName, realm: &str, version: u8) {
    if version == 1 {
        // ncomps includes the realm; no name type.
        w.i32(p.name_string.len() as i32 + 1);
    } else {
        w.i32(p.name_type);
        w.i32(p.name_string.len() as i32);
    }
    w.data(realm.as_bytes());
    for c in &p.name_string {
        w.data(c.as_bytes());
    }
}

/// Marshal a principal (k5_marshal_princ).
pub fn marshal_princ(p: &PrincipalName, realm: &str, version: u8) -> Vec<u8> {
    let mut w = W::new(version);
    marshal_princ_w(&mut w, p, realm, version);
    w.buf
}

fn unmarshal_princ_r(r: &mut R<'_>, version: u8) -> Result<(PrincipalName, String), CcError> {
    let (name_type, ncomps) = if version == 1 {
        (0i32, r.i32()?)
    } else {
        (r.i32()?, r.i32()?)
    };
    // Sanity check (ccmarshal.c:175): ncomps cannot exceed remaining input.
    if ncomps < 0 || ncomps as usize > r.d.len() - r.pos {
        return Err(CcError::Format);
    }
    let realm_bytes = r.data()?.to_vec();
    let realm = String::from_utf8_lossy(&realm_bytes).to_string();
    let n = if version == 1 { ncomps - 1 } else { ncomps };
    let mut name_string = Vec::with_capacity(n.max(0) as usize);
    for _ in 0..n {
        name_string.push(r.gs()?);
    }
    Ok((
        PrincipalName {
            name_type,
            name_string,
        },
        realm,
    ))
}

/// Unmarshal a principal (k5_unmarshal_princ). Returns the principal and
/// its realm; trailing bytes are left for the caller.
pub fn unmarshal_princ(data: &[u8], version: u8) -> Result<(PrincipalName, String), CcError> {
    let (p, realm, _) = unmarshal_princ_len(data, version)?;
    Ok((p, realm))
}

/// Unmarshal a principal, also returning the consumed length.
pub(crate) fn unmarshal_princ_len(
    data: &[u8],
    version: u8,
) -> Result<(PrincipalName, String, usize), CcError> {
    let mut r = R::new(data, version);
    let (p, realm) = unmarshal_princ_r(&mut r, version)?;
    Ok((p, realm, r.pos))
}

fn marshal_keyblock(w: &mut W, k: &EncryptionKey, version: u8) {
    w.i16(k.keytype as i16);
    if version == 3 {
        // V3 writes the enctype twice (ccmarshal.c).
        w.i16(k.keytype as i16);
    }
    w.i32(k.key_bytes().len() as i32);
    w.buf.extend_from_slice(k.key_bytes());
}

fn unmarshal_keyblock(r: &mut R<'_>, version: u8) -> Result<EncryptionKey, CcError> {
    let etype = i32::from(r.i16()?);
    if version == 3 {
        let _ignored = r.i16()?;
    }
    let len = r.i32()?;
    if len < 0 {
        return Err(CcError::Format);
    }
    let key = r.take(len as usize)?.to_vec();
    Ok(EncryptionKey::new(etype, key))
}

fn marshal_addrs(w: &mut W, addrs: &[HostAddress]) {
    w.i32(addrs.len() as i32);
    for a in addrs {
        w.i16(a.addr_type as i16);
        w.i32(a.address.len() as i32);
        w.buf.extend_from_slice(&a.address);
    }
}

fn unmarshal_addrs(r: &mut R<'_>) -> Result<Vec<HostAddress>, CcError> {
    let count = r.i32()?;
    if count < 0 || count as usize > r.d.len() - r.pos {
        return Err(CcError::Format);
    }
    let mut out = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let addr_type = i32::from(r.i16()?);
        let len = r.i32()?;
        if len < 0 {
            return Err(CcError::Format);
        }
        let address = OctetString::from(r.take(len as usize)?.to_vec());
        out.push(HostAddress { addr_type, address });
    }
    Ok(out)
}

fn marshal_authdata(w: &mut W, ad: &[AuthorizationDataElement]) {
    w.i32(ad.len() as i32);
    for a in ad {
        // ad_type is sign-extended i16 (ccmarshal.c).
        w.i16(a.ad_type as i16);
        w.i32(a.ad_data.len() as i32);
        w.buf.extend_from_slice(&a.ad_data);
    }
}

fn unmarshal_authdata(r: &mut R<'_>) -> Result<Vec<AuthorizationDataElement>, CcError> {
    let count = r.i32()?;
    if count < 0 || count as usize > r.d.len() - r.pos {
        return Err(CcError::Format);
    }
    let mut out = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let ad_type = i32::from(r.i16()?);
        let len = r.i32()?;
        if len < 0 {
            return Err(CcError::Format);
        }
        let ad_data = OctetString::from(r.take(len as usize)?.to_vec());
        out.push(AuthorizationDataElement { ad_type, ad_data });
    }
    Ok(out)
}

/// Marshal a credential (k5_marshal_cred).
pub fn marshal_cred(c: &CcCredential, version: u8) -> Vec<u8> {
    let mut w = W::new(version);
    marshal_princ_w(&mut w, &c.client, &c.crealm, version);
    marshal_princ_w(&mut w, &c.server, &c.srealm, version);
    marshal_keyblock(&mut w, &c.keyblock, version);
    w.i32(c.authtime as i32);
    w.i32(c.starttime as i32);
    w.i32(c.endtime as i32);
    w.i32(c.renew_till as i32);
    w.u8(u8::from(c.is_skey));
    w.i32(c.ticket_flags as i32);
    marshal_addrs(&mut w, &c.addresses);
    marshal_authdata(&mut w, &c.authdata);
    w.data(&c.ticket);
    w.data(&c.second_ticket);
    w.buf
}

/// Unmarshal a credential, returning it and the consumed length.
pub(crate) fn unmarshal_cred_len(
    data: &[u8],
    version: u8,
) -> Result<(CcCredential, usize), CcError> {
    let mut r = R::new(data, version);
    let (client, crealm) = unmarshal_princ_r(&mut r, version)?;
    let (server, srealm) = unmarshal_princ_r(&mut r, version)?;
    let keyblock = unmarshal_keyblock(&mut r, version)?;
    let authtime = r.i32()? as u32;
    let starttime = r.i32()? as u32;
    let endtime = r.i32()? as u32;
    let renew_till = r.i32()? as u32;
    let is_skey = r.u8()? != 0;
    let ticket_flags = r.i32()? as u32;
    let addresses = unmarshal_addrs(&mut r)?;
    let authdata = unmarshal_authdata(&mut r)?;
    let ticket = r.data()?.to_vec();
    let second_ticket = r.data()?.to_vec();
    Ok((
        CcCredential {
            client,
            crealm,
            server,
            srealm,
            keyblock,
            authtime,
            starttime,
            endtime,
            renew_till,
            is_skey,
            ticket_flags,
            addresses,
            authdata,
            ticket,
            second_ticket,
        },
        r.pos,
    ))
}

/// Unmarshal a credential (k5_unmarshal_cred). Trailing bytes are ignored.
pub fn unmarshal_cred(data: &[u8], version: u8) -> Result<CcCredential, CcError> {
    Ok(unmarshal_cred_len(data, version)?.0)
}
