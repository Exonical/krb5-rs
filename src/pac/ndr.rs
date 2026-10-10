//! NDR encoding of S4U_DELEGATION_INFO (MS-PAC 2.9), MIT kdc/ndr.c.

use super::PacError;

/// Decoded S4U_DELEGATION_INFO (`struct pac_s4u_delegation_info`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DelegationInfo {
    /// The S4U2Proxy target, without realm.
    pub proxy_target: String,
    /// Services the evidence passed through, each with realm.
    pub transited_services: Vec<String>,
}

struct Input<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Input<'a> {
    fn bytes(&mut self, n: usize) -> Result<&'a [u8], PacError> {
        let end = self
            .pos
            .checked_add(n)
            .filter(|e| *e <= self.data.len())
            .ok_or(PacError::Invalid("short delegation info"))?;
        let out = &self.data[self.pos..end];
        self.pos = end;
        Ok(out)
    }

    fn u16(&mut self) -> Result<u16, PacError> {
        let b = self.bytes(2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }

    fn u32(&mut self) -> Result<u32, PacError> {
        let b = self.bytes(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// `dec_wchar_pointer` (ndr.c:68-96).
    fn wchar_pointer(&mut self) -> Result<String, PacError> {
        self.u32()?;
        self.u32()?;
        let count = self.u32()? as usize;
        if count > (u32::MAX / 2) as usize {
            return Err(PacError::Range);
        }
        let raw = self.bytes(count * 2)?;
        let units: Vec<u16> = raw
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        let s = String::from_utf16(&units).map_err(|_| PacError::Invalid("bad UTF-16"))?;
        if count % 2 == 1 {
            self.u16()?;
        }
        Ok(s)
    }
}

impl DelegationInfo {
    /// `ndr_dec_delegation_info` (ndr.c:134-230).
    pub fn decode(data: &[u8]) -> Result<Self, PacError> {
        let mut i = Input { data, pos: 0 };
        let version = i.bytes(1)?[0];
        let endianness = i.bytes(1)?[0];
        let header_len = i.u16()?;
        i.u32()?;
        if version != 1 || endianness != 0x10 || header_len != 8 {
            return Err(PacError::Invalid("bad NDR common header"));
        }
        let object_len = i.u32()? as usize;
        if data.len() < 16 || object_len != data.len() - 16 {
            return Err(PacError::Invalid("bad NDR object length"));
        }
        i.u32()?;
        i.u32()?;
        i.u16()?;
        i.u16()?;
        i.u32()?;
        i.u32()?;
        i.u32()?;
        let proxy_target = i.wchar_pointer()?;
        let n = i.u32()? as usize;
        if n > data.len() / 8 {
            return Err(PacError::Range);
        }
        i.bytes(8 * n)?;
        let transited_services = (0..n)
            .map(|_| i.wchar_pointer())
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            proxy_target,
            transited_services,
        })
    }

    /// `ndr_enc_delegation_info` (ndr.c:259-336).
    pub fn encode(&self) -> Vec<u8> {
        fn wchars(s: &str) -> (usize, Vec<u8>) {
            let units: Vec<u16> = s.encode_utf16().collect();
            let n = units.len();
            let mut out = Vec::new();
            out.extend_from_slice(&((n + 1) as u32).to_le_bytes());
            out.extend_from_slice(&0u32.to_le_bytes());
            out.extend_from_slice(&(n as u32).to_le_bytes());
            out.extend(units.iter().flat_map(|u| u.to_le_bytes()));
            if n % 2 == 1 {
                out.extend_from_slice(&0u16.to_le_bytes());
            }
            (n, out)
        }
        let mut pointer = 0u32;
        let mut ptr = |b: &mut Vec<u8>| {
            if pointer == 0 {
                pointer = 0x0002_0000;
            }
            b.extend_from_slice(&pointer.to_le_bytes());
            pointer += 4;
        };
        let (pt_n, pt_enc) = wchars(&self.proxy_target);
        let svcs: Vec<(usize, Vec<u8>)> =
            self.transited_services.iter().map(|s| wchars(s)).collect();

        let mut b = Vec::new();
        b.extend_from_slice(&[0x01, 0x10, 0x08, 0x00]);
        b.extend_from_slice(&0xcccc_cccc_u32.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes());
        ptr(&mut b);
        b.extend_from_slice(&((2 * pt_n) as u16).to_le_bytes());
        b.extend_from_slice(&((2 * (pt_n + 1)) as u16).to_le_bytes());
        ptr(&mut b);
        b.extend_from_slice(&(svcs.len() as u32).to_le_bytes());
        ptr(&mut b);
        b.extend_from_slice(&pt_enc);
        b.extend_from_slice(&(svcs.len() as u32).to_le_bytes());
        for (n, _) in &svcs {
            b.extend_from_slice(&((2 * n) as u16).to_le_bytes());
            b.extend_from_slice(&((2 * (n + 1)) as u16).to_le_bytes());
            ptr(&mut b);
        }
        for (_, enc) in &svcs {
            b.extend_from_slice(enc);
        }
        if b.len() % 8 != 0 {
            b.extend_from_slice(&0u32.to_le_bytes());
        }
        let payload = (b.len() - 0x10) as u32;
        b[8..12].copy_from_slice(&payload.to_le_bytes());
        b
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_and_uses_ms_pointer_numbering() {
        let di = DelegationInfo {
            proxy_target: "HTTP/target.example.com".into(),
            transited_services: vec!["HTTP/front.example.com@EXAMPLE.COM".into(), "a/b@R".into()],
        };
        let der = di.encode();
        assert_eq!(&der[..8], &[0x01, 0x10, 0x08, 0x00, 0xcc, 0xcc, 0xcc, 0xcc]);
        assert_eq!(der.len() % 8, 0);
        assert_eq!(&der[16..20], &[0x00, 0x00, 0x02, 0x00]);
        assert_eq!(DelegationInfo::decode(&der).expect("decode"), di);
    }

    #[test]
    fn empty_service_list_and_odd_lengths_round_trip() {
        for target in ["a", "ab", "abc"] {
            let di = DelegationInfo {
                proxy_target: target.into(),
                transited_services: Vec::new(),
            };
            assert_eq!(DelegationInfo::decode(&di.encode()).expect("decode"), di);
        }
    }

    #[test]
    fn malformed_inputs_are_rejected() {
        let good = DelegationInfo {
            proxy_target: "t".into(),
            transited_services: vec!["s@R".into()],
        }
        .encode();
        assert!(DelegationInfo::decode(&good[..good.len() - 4]).is_err());
        let mut bad = good.clone();
        bad[0] = 2;
        assert!(DelegationInfo::decode(&bad).is_err());
        assert!(DelegationInfo::decode(&[]).is_err());
    }
}
