//! The XDR primitives (RFC 4506) used by ONC RPC and RPCSEC_GSS.

use std::fmt;

/// A malformed XDR message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct XdrError(pub &'static str);

impl fmt::Display for XdrError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "malformed XDR: {}", self.0)
    }
}

impl std::error::Error for XdrError {}

/// An XDR encoder.
#[derive(Clone, Debug, Default)]
pub struct XdrWriter(pub Vec<u8>);

impl XdrWriter {
    /// `unsigned int`.
    pub fn u32(&mut self, v: u32) {
        self.0.extend_from_slice(&v.to_be_bytes());
    }

    /// `int`.
    pub fn i32(&mut self, v: i32) {
        self.0.extend_from_slice(&v.to_be_bytes());
    }

    /// `bool`.
    pub fn bool(&mut self, v: bool) {
        self.u32(u32::from(v));
    }

    /// Fixed-length `opaque[n]`, padded to four bytes.
    pub fn fixed(&mut self, v: &[u8]) {
        self.0.extend_from_slice(v);
        self.0.resize(self.0.len() + (4 - v.len() % 4) % 4, 0);
    }

    /// Variable-length `opaque<>`. Lengths above `u32::MAX` cannot occur for
    /// in-memory RPC messages and are truncated to the encodable maximum.
    pub fn opaque(&mut self, v: &[u8]) {
        self.u32(u32::try_from(v.len()).unwrap_or(u32::MAX));
        self.fixed(v);
    }
}

/// An XDR decoder over a byte slice.
#[derive(Clone, Debug)]
pub struct XdrReader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> XdrReader<'a> {
    /// Decode from `bytes`.
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], XdrError> {
        let end = self
            .pos
            .checked_add(n)
            .filter(|&e| e <= self.bytes.len())
            .ok_or(XdrError("truncated"))?;
        let out = &self.bytes[self.pos..end];
        self.pos = end;
        Ok(out)
    }

    /// `unsigned int`.
    pub fn u32(&mut self) -> Result<u32, XdrError> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// `int`.
    pub fn i32(&mut self) -> Result<i32, XdrError> {
        let b = self.take(4)?;
        Ok(i32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// `bool`.
    pub fn bool(&mut self) -> Result<bool, XdrError> {
        match self.u32()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(XdrError("bad bool")),
        }
    }

    /// Fixed-length `opaque[n]`.
    pub fn fixed(&mut self, n: usize) -> Result<&'a [u8], XdrError> {
        let out = self.take(n)?;
        self.take((4 - n % 4) % 4)?;
        Ok(out)
    }

    /// Variable-length `opaque<max>`.
    pub fn opaque_max(&mut self, max: usize) -> Result<&'a [u8], XdrError> {
        let n = usize::try_from(self.u32()?).map_err(|_| XdrError("length"))?;
        if n > max {
            return Err(XdrError("opaque too long"));
        }
        self.fixed(n)
    }

    /// Variable-length `opaque<>`.
    pub fn opaque(&mut self) -> Result<&'a [u8], XdrError> {
        self.opaque_max(usize::MAX)
    }

    /// The undecoded remainder.
    pub fn rest(&mut self) -> &'a [u8] {
        let out = &self.bytes[self.pos..];
        self.pos = self.bytes.len();
        out
    }

    /// Fail unless every byte was consumed.
    pub fn finish(&self) -> Result<(), XdrError> {
        if self.pos == self.bytes.len() {
            Ok(())
        } else {
            Err(XdrError("trailing bytes"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opaque_is_padded_and_round_trips() {
        let mut w = XdrWriter::default();
        w.opaque(b"abcde");
        w.u32(7);
        assert_eq!(w.0, b"\0\0\0\x05abcde\0\0\0\0\0\0\x07");
        let mut r = XdrReader::new(&w.0);
        assert_eq!(r.opaque().expect("opaque"), b"abcde");
        assert_eq!(r.u32().expect("u32"), 7);
        r.finish().expect("finish");
        assert!(XdrReader::new(&w.0).opaque_max(4).is_err());
        assert!(XdrReader::new(&w.0[..6]).opaque().is_err());
    }
}
