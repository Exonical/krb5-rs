//! gss_export_sec_context / gss_import_sec_context for the krb5 mechanism
//! (export_sec_context.c, import_sec_context.c, ser_sctx.c).  The token is
//! the mechglue form (g_exp_sec_context.c): a four-byte big-endian mech OID
//! length, the OID, then the mechanism's context.

use super::*;
use crate::gssapi::seqstate::SeqState;

/// Marks the start and end of a serialized context (ser_sctx.c `KG_CONTEXT`).
const CONTEXT_MAGIC: u32 = 0x4b35_4743;
/// 2 adds the client authdata modules' state; 1 is still imported.
const VERSION: u32 = 2;

struct Writer(Vec<u8>);

impl Writer {
    fn u32(&mut self, v: u32) {
        self.0.extend_from_slice(&v.to_be_bytes());
    }
    fn u64(&mut self, v: u64) {
        self.0.extend_from_slice(&v.to_be_bytes());
    }
    fn bool(&mut self, v: bool) {
        self.u32(u32::from(v));
    }
    fn bytes(&mut self, b: &[u8]) {
        self.u32(b.len() as u32);
        self.0.extend_from_slice(b);
    }
    fn der<T: rasn::Encode>(&mut self, v: &T) -> Result<(), Krb5Error> {
        let b = rasn::der::encode(v).map_err(|_| defective())?;
        self.bytes(&b);
        Ok(())
    }
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], Krb5Error> {
        if self.0.len() < n {
            return Err(defective());
        }
        let (a, b) = self.0.split_at(n);
        self.0 = b;
        Ok(a)
    }
    fn u32(&mut self) -> Result<u32, Krb5Error> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }
    fn u64(&mut self) -> Result<u64, Krb5Error> {
        Ok((u64::from(self.u32()?) << 32) | u64::from(self.u32()?))
    }
    fn bool(&mut self) -> Result<bool, Krb5Error> {
        match self.u32()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(defective()),
        }
    }
    fn bytes(&mut self) -> Result<&'a [u8], Krb5Error> {
        let n = self.u32()? as usize;
        self.take(n)
    }
    fn der<T: rasn::Decode>(&mut self) -> Result<T, Krb5Error> {
        rasn::der::decode(self.bytes()?).map_err(|_| defective())
    }
}

fn defective() -> Krb5Error {
    Krb5Error::Gss(GssError::DefectiveToken)
}

impl Krb5Context {
    /// `gss_export_sec_context`: serialize the context into an
    /// interprocess token, consuming it as MIT deletes the exported context.
    pub fn export_sec_context(self) -> Result<Vec<u8>, Krb5Error> {
        let mut w = Writer(Vec::new());
        w.u32(CONTEXT_MAGIC);
        w.u32(VERSION);
        w.u32(self.flags.bits());
        w.bool(self.initiate);
        w.der(&self.initiator)?;
        w.bytes(self.crealm.as_bytes());
        w.der(&self.acceptor)?;
        w.der(&self.endtime)?;
        w.der(&self.key)?;
        w.bool(self.acceptor_subkey.is_some());
        if let Some(k) = &self.acceptor_subkey {
            w.der(k)?;
        }
        w.u64(self.seq_send);
        let s = &self.seqstate;
        w.bool(s.do_replay);
        w.bool(s.do_sequence);
        w.u64(s.seqmask);
        w.u64(s.base);
        w.u64(s.next);
        w.u64(s.recvmap);
        w.bool(self.initial_ticket);
        w.der(&self.authtime)?;
        w.der(&self.ticket_flags)?;
        w.u32(self.authdata.len() as u32);
        for ad in &self.authdata {
            w.der(ad)?;
        }
        w.der(&self.ticket_key)?;
        let n = &self.name_attrs;
        w.bool(n.pac.is_some());
        if let Some(p) = &n.pac {
            w.bytes(&p.encode());
        }
        w.bool(n.pac_verified);
        w.u32(n.indicators.len() as u32);
        for i in &n.indicators {
            w.bytes(i.as_bytes());
        }
        let loaded = n.modules.externalize(crate::authdata::AD_USAGE_MASK);
        w.u32(loaded.len() as u32);
        for (name, body) in &loaded {
            w.bytes(name.as_bytes());
            w.bytes(body);
        }
        w.u32(CONTEXT_MAGIC);

        let mut out = Vec::with_capacity(4 + self.mech.len() + w.0.len());
        out.extend_from_slice(&(self.mech.len() as u32).to_be_bytes());
        out.extend_from_slice(self.mech);
        out.extend_from_slice(&w.0);
        Ok(out)
    }

    /// `gss_import_sec_context`.
    pub fn import_sec_context(token: &[u8]) -> Result<Self, Krb5Error> {
        let mut r = Reader(token);
        let oid = r.bytes()?;
        let mech = [MECH_KRB5, MECH_IAKERB]
            .into_iter()
            .find(|m| *m == oid)
            .ok_or(Krb5Error::Gss(GssError::BadMech))?;
        if r.u32()? != CONTEXT_MAGIC {
            return Err(defective());
        }
        let version = r.u32()?;
        if !(1..=VERSION).contains(&version) {
            return Err(defective());
        }
        let flags = GssFlags::from_bits(r.u32()?).ok_or_else(defective)?;
        let initiate = r.bool()?;
        let initiator = r.der()?;
        let crealm = String::from_utf8(r.bytes()?.to_vec()).map_err(|_| defective())?;
        let acceptor = r.der()?;
        let endtime = r.der()?;
        let key = r.der()?;
        let acceptor_subkey = if r.bool()? { Some(r.der()?) } else { None };
        let seq_send = r.u64()?;
        let seqstate = SeqState {
            do_replay: r.bool()?,
            do_sequence: r.bool()?,
            seqmask: r.u64()?,
            base: r.u64()?,
            next: r.u64()?,
            recvmap: r.u64()?,
        };
        let initial_ticket = r.bool()?;
        let authtime = r.der()?;
        let ticket_flags = r.der()?;
        let count = r.u32()?;
        let mut authdata = Vec::new();
        for _ in 0..count {
            authdata.push(r.der()?);
        }
        let ticket_key = r.der()?;
        let pac = if r.bool()? {
            Some(crate::pac::Pac::parse(r.bytes()?).map_err(|_| defective())?)
        } else {
            None
        };
        let pac_verified = r.bool()?;
        let count = r.u32()?;
        let mut indicators = Vec::new();
        for _ in 0..count {
            indicators.push(String::from_utf8(r.bytes()?.to_vec()).map_err(|_| defective())?);
        }
        let mut modules = crate::authdata::AuthdataContext::new();
        let n = if version >= 2 { r.u32()? } else { 0 };
        for _ in 0..n {
            let name = std::str::from_utf8(r.bytes()?).map_err(|_| defective())?;
            let mut body = r.bytes()?;
            // k5_ad_internalize: an unknown module is an error.
            match modules.internalize(crate::authdata::AD_USAGE_MASK, name, &mut body) {
                Ok(true) if body.is_empty() => {}
                _ => return Err(defective()),
            }
        }
        if r.u32()? != CONTEXT_MAGIC || !r.0.is_empty() {
            return Err(defective());
        }
        Ok(Krb5Context {
            flags,
            initiate,
            initiator,
            crealm,
            acceptor,
            endtime,
            key,
            acceptor_subkey,
            seq_send,
            seqstate,
            initial_ticket,
            mech,
            authtime,
            ticket_flags,
            authdata,
            ticket_key,
            name_attrs: super::name_attrs::NameAttrs {
                pac,
                pac_verified,
                indicators,
                modules,
            },
        })
    }
}
