//! MS-PAC (Privilege Attribute Certificate) parsing, signing and
//! verification, following MIT krb5 1.22 lib/krb5/krb/pac.c and pac_sign.c.
//!
//! A [`Pac`] keeps the encoded bytes exactly as MIT does, so checksums are
//! computed over (and verified against) the original layout. Only the client
//! info and the signature buffers are interpreted; other buffers are opaque.

use crate::crypto::{find_cksumtype, find_etype};
use crate::types::{AuthorizationDataElement, EncTicketPart, EncryptionKey, PrincipalName};

/// KERB_VALIDATION_INFO (logon information).
pub const PAC_LOGON_INFO: u32 = 1;
/// Server signature (`KRB5_PAC_SERVER_CHECKSUM`).
pub const PAC_SERVER_CHECKSUM: u32 = 6;
/// KDC (privsvr) signature (`KRB5_PAC_PRIVSVR_CHECKSUM`).
pub const PAC_PRIVSVR_CHECKSUM: u32 = 7;
/// Client name and authentication time (`KRB5_PAC_CLIENT_INFO`).
pub const PAC_CLIENT_INFO: u32 = 10;
/// S4U2Proxy delegation info.
pub const PAC_DELEGATION_INFO: u32 = 11;
/// UPN and DNS information.
pub const PAC_UPN_DNS_INFO: u32 = 12;
/// Client claims.
pub const PAC_CLIENT_CLAIMS_INFO: u32 = 13;
/// Device information.
pub const PAC_DEVICE_INFO: u32 = 14;
/// Device claims.
pub const PAC_DEVICE_CLAIMS_INFO: u32 = 15;
/// Ticket signature (`KRB5_PAC_TICKET_CHECKSUM`).
pub const PAC_TICKET_CHECKSUM: u32 = 16;
/// PAC attributes.
pub const PAC_ATTRIBUTES_INFO: u32 = 17;
/// Requester SID.
pub const PAC_REQUESTER_SID: u32 = 18;
/// Full KDC checksum (`KRB5_PAC_FULL_CHECKSUM`).
pub const PAC_FULL_CHECKSUM: u32 = 19;

/// AD-IF-RELEVANT.
pub const AD_IF_RELEVANT: i32 = 1;
/// AD-WIN2K-PAC.
pub const AD_WIN2K_PAC: i32 = 128;

const PACTYPE_LENGTH: usize = 8;
const PAC_INFO_BUFFER_LENGTH: usize = 16;
const PAC_ALIGNMENT: usize = 8;
const PAC_SIGNATURE_DATA_LENGTH: usize = 4;
const PAC_CLIENT_INFO_LENGTH: usize = 10;
const MAX_BUFFERS: usize = 4096;
/// Seconds between 1601-01-01 and 1970-01-01 (`NT_TIME_EPOCH`).
const NT_TIME_EPOCH: u64 = 11_644_473_600;
/// `KRB5_KEYUSAGE_APP_DATA_CKSUM`.
const KEYUSAGE_APP_DATA_CKSUM: i32 = 17;
/// `KRB5_NT_ENTERPRISE_PRINCIPAL`.
const NT_ENTERPRISE: i32 = 10;

/// PAC processing failure. Variants mirror the MIT error each condition
/// returns.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PacError {
    /// `EINVAL`: malformed structure or duplicate buffer.
    #[error("invalid PAC: {0}")]
    Invalid(&'static str),
    /// `ERANGE`: length or offset out of range.
    #[error("PAC value out of range")]
    Range,
    /// `ENOENT`: buffer not present.
    #[error("PAC buffer not found")]
    NoEntry,
    /// `EEXIST`: buffer already present.
    #[error("PAC buffer already exists")]
    Exists,
    /// `KRB5_BAD_MSIZE`: buffer too small.
    #[error("PAC buffer has the wrong size")]
    BadMsize,
    /// `KRB5KRB_AP_ERR_MODIFIED`: a signature does not verify.
    #[error("PAC signature mismatch")]
    Modified,
    /// `KRB5KRB_AP_WRONG_PRINC`: client info does not match the ticket.
    #[error("PAC client info does not match the ticket")]
    WrongPrinc,
    /// `KRB5KDC_ERR_SUMTYPE_NOSUPP`.
    #[error("unsupported PAC checksum type")]
    SumtypeNoSupp,
    /// `KRB5_BAD_ENCTYPE`: the key does not suit the checksum type.
    #[error("key enctype does not match the PAC checksum type")]
    BadEnctype,
    /// `KRB5KRB_ERR_GENERIC` and other failures.
    #[error("PAC error: {0}")]
    Generic(String),
}

impl PacError {
    /// The KRB-ERROR code the KDC reports for this failure (MIT returns the
    /// protocol codes unchanged and maps everything else to GENERIC).
    #[cfg_attr(not(feature = "kdc"), expect(dead_code, reason = "used by the KDC"))]
    pub(crate) fn kdc_code(&self) -> i32 {
        match self {
            PacError::Modified => 41,
            PacError::SumtypeNoSupp => 15,
            _ => 60,
        }
    }
}

type Result<T> = std::result::Result<T, PacError>;

/// One PAC buffer: type and contents.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacBuffer {
    /// Buffer type (`PAC_*`).
    pub ty: u32,
    /// Buffer contents without padding.
    pub data: Vec<u8>,
}

/// Decoded PAC_CLIENT_INFO.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacClientInfo {
    /// Authentication time, seconds since 1970.
    pub authtime: i64,
    /// Client name as the KDC wrote it (no realm unless it asked for one).
    pub name: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Info {
    ty: u32,
    size: u32,
    offset: u64,
}

/// A parsed or under-construction PAC (MIT `krb5_pac`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pac {
    data: Vec<u8>,
    buffers: Vec<Info>,
}

impl Default for Pac {
    fn default() -> Self {
        Self::new()
    }
}

fn le32(b: &[u8]) -> u32 {
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

impl Pac {
    /// An empty PAC (`krb5_pac_init`, pac.c:196-219).
    pub fn new() -> Self {
        Self {
            data: vec![0; PACTYPE_LENGTH],
            buffers: Vec::new(),
        }
    }

    /// Parse an encoded PAC (`krb5_pac_parse`, pac.c:249-335).
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < PACTYPE_LENGTH {
            return Err(PacError::Invalid("short header"));
        }
        let nbuffers = le32(&bytes[0..4]) as usize;
        let version = le32(&bytes[4..8]);
        if version != 0 {
            return Err(PacError::Invalid("unsupported version"));
        }
        if !(1..=MAX_BUFFERS).contains(&nbuffers) {
            return Err(PacError::Range);
        }
        let header_len = PACTYPE_LENGTH + nbuffers * PAC_INFO_BUFFER_LENGTH;
        if bytes.len() < header_len {
            return Err(PacError::Range);
        }
        let mut buffers = Vec::with_capacity(nbuffers);
        for i in 0..nbuffers {
            let p = &bytes[PACTYPE_LENGTH + i * PAC_INFO_BUFFER_LENGTH..];
            let info = Info {
                ty: le32(&p[0..4]),
                size: le32(&p[4..8]),
                offset: u64::from_le_bytes([p[8], p[9], p[10], p[11], p[12], p[13], p[14], p[15]]),
            };
            if !info.offset.is_multiple_of(PAC_ALIGNMENT as u64) {
                return Err(PacError::Invalid("unaligned buffer"));
            }
            let len = bytes.len() as u64;
            if info.offset < header_len as u64
                || info.offset > len
                || u64::from(info.size) > len - info.offset
            {
                return Err(PacError::Range);
            }
            buffers.push(info);
        }
        Ok(Self {
            data: bytes.to_vec(),
            buffers,
        })
    }

    /// The encoded PAC.
    pub fn encode(&self) -> Vec<u8> {
        self.data.clone()
    }

    /// Buffer types in encoded order (`krb5_pac_get_types`).
    pub fn types(&self) -> Vec<u32> {
        self.buffers.iter().map(|b| b.ty).collect()
    }

    /// Every buffer with its contents.
    pub fn buffers(&self) -> Vec<PacBuffer> {
        self.buffers
            .iter()
            .map(|b| PacBuffer {
                ty: b.ty,
                data: self.slice(b).to_vec(),
            })
            .collect()
    }

    fn slice(&self, b: &Info) -> &[u8] {
        let start = b.offset as usize;
        &self.data[start..start + b.size as usize]
    }

    fn locate(&self, ty: u32) -> Result<&Info> {
        let mut found = None;
        for b in &self.buffers {
            if b.ty == ty {
                if found.is_some() {
                    return Err(PacError::Invalid("duplicate buffer"));
                }
                found = Some(b);
            }
        }
        found.ok_or(PacError::NoEntry)
    }

    /// Contents of the buffer of type `ty` (`k5_pac_locate_buffer`,
    /// pac.c:121-147): `NoEntry` if absent, `Invalid` if duplicated.
    pub fn get_buffer(&self, ty: u32) -> Result<&[u8]> {
        self.locate(ty).map(|b| self.slice(b))
    }

    fn sync_header(&mut self) {
        let n = self.buffers.len() as u32;
        self.data[0..4].copy_from_slice(&n.to_le_bytes());
        self.data[4..8].copy_from_slice(&0u32.to_le_bytes());
        for (i, b) in self.buffers.iter().enumerate() {
            let p = PACTYPE_LENGTH + i * PAC_INFO_BUFFER_LENGTH;
            self.data[p..p + 4].copy_from_slice(&b.ty.to_le_bytes());
            self.data[p + 4..p + 8].copy_from_slice(&b.size.to_le_bytes());
            self.data[p + 8..p + 16].copy_from_slice(&b.offset.to_le_bytes());
        }
    }

    /// Add a buffer (`krb5_pac_add_buffer`, pac.c:44-97).
    pub fn add_buffer(&mut self, ty: u32, data: &[u8]) -> Result<()> {
        self.add_inner(ty, data.len(), Some(data))
    }

    fn add_inner(&mut self, ty: u32, len: usize, data: Option<&[u8]>) -> Result<()> {
        if self.locate(ty).is_ok() {
            return Err(PacError::Exists);
        }
        if self.buffers.len() >= MAX_BUFFERS {
            return Err(PacError::Range);
        }
        let header_len = PACTYPE_LENGTH + self.buffers.len() * PAC_INFO_BUFFER_LENGTH;
        let pad = (PAC_ALIGNMENT - len % PAC_ALIGNMENT) % PAC_ALIGNMENT;
        for b in &mut self.buffers {
            b.offset += PAC_INFO_BUFFER_LENGTH as u64;
        }
        let tail = self.data.split_off(header_len);
        self.data.extend_from_slice(&[0; PAC_INFO_BUFFER_LENGTH]);
        self.data.extend_from_slice(&tail);
        let offset = self.data.len();
        match data {
            Some(d) => self.data.extend_from_slice(d),
            None => self.data.resize(offset + len, 0),
        }
        self.data.resize(offset + len + pad, 0);
        self.buffers.push(Info {
            ty,
            size: len as u32,
            offset: offset as u64,
        });
        self.sync_header();
        Ok(())
    }

    /// PAC_CLIENT_INFO (`krb5_pac_get_client_info`, pac.c:360-410).
    pub fn client_info(&self) -> Result<PacClientInfo> {
        let ci = self.get_buffer(PAC_CLIENT_INFO)?;
        if ci.len() < PAC_CLIENT_INFO_LENGTH {
            return Err(PacError::Range);
        }
        let nt = u64::from_le_bytes([ci[0], ci[1], ci[2], ci[3], ci[4], ci[5], ci[6], ci[7]]);
        let name_len = usize::from(u16::from_le_bytes([ci[8], ci[9]]));
        let abstime = (nt / 10_000_000).wrapping_sub(NT_TIME_EPOCH);
        if abstime > u64::from(u32::MAX) {
            return Err(PacError::Range);
        }
        if ci.len() < PAC_CLIENT_INFO_LENGTH + name_len || !name_len.is_multiple_of(2) {
            return Err(PacError::Range);
        }
        let units: Vec<u16> = ci[PAC_CLIENT_INFO_LENGTH..PAC_CLIENT_INFO_LENGTH + name_len]
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_le_bytes(*c))
            .collect();
        let name = String::from_utf16(&units)
            .map_err(|_| PacError::Generic("client name is not valid UTF-16".into()))?;
        Ok(PacClientInfo {
            authtime: abstime as i64,
            name,
        })
    }

    /// `k5_pac_validate_client` (pac.c:412-441).
    fn validate_client(
        &self,
        authtime: i64,
        principal: (&PrincipalName, &str),
        with_realm: bool,
    ) -> Result<()> {
        let info = self.client_info()?;
        let want = unparse_name(principal.0, principal.1, true, with_realm);
        if info.authtime != authtime || info.name != want {
            return Err(PacError::WrongPrinc);
        }
        Ok(())
    }

    fn zero_signature(&self, ty: u32, data: &mut [u8]) -> Result<()> {
        let b = self
            .buffers
            .iter()
            .find(|b| b.ty == ty)
            .ok_or(PacError::NoEntry)?;
        if (b.size as usize) < PAC_SIGNATURE_DATA_LENGTH {
            return Err(PacError::BadMsize);
        }
        let start = b.offset as usize + PAC_SIGNATURE_DATA_LENGTH;
        let end = b.offset as usize + b.size as usize;
        data[start..end].fill(0);
        Ok(())
    }

    /// `verify_checksum` (pac.c:477-515).
    fn verify_checksum(&self, ty: u32, key: &EncryptionKey, data: &[u8]) -> Result<()> {
        let buf = self.get_buffer(ty)?;
        if buf.len() < PAC_SIGNATURE_DATA_LENGTH {
            return Err(PacError::BadMsize);
        }
        let cksumtype = le32(buf);
        if ty == PAC_SERVER_CHECKSUM && cksumtype == 14 {
            return Err(PacError::SumtypeNoSupp);
        }
        let len = match cksumtype {
            15 | 16 => 12,
            19 => 16,
            20 => 24,
            // Keyed types this crate cannot compute (hmac-sha1-des3, hmac-md5).
            12 | 0xFFFF_FF76 => return Err(PacError::SumtypeNoSupp),
            _ => return Err(PacError::Generic("unkeyed PAC checksum type".into())),
        };
        if len > buf.len() - PAC_SIGNATURE_DATA_LENGTH {
            return Err(PacError::BadMsize);
        }
        let profile = find_cksumtype(cksumtype as i32).map_err(|_| PacError::SumtypeNoSupp)?;
        if profile.etype() != key.keytype {
            return Err(PacError::BadEnctype);
        }
        profile
            .verify_checksum(
                key.key_bytes(),
                KEYUSAGE_APP_DATA_CKSUM,
                data,
                &buf[PAC_SIGNATURE_DATA_LENGTH..PAC_SIGNATURE_DATA_LENGTH + len],
            )
            .map_err(|_| PacError::Modified)
    }

    /// `verify_pac_checksums` (pac.c:517-575).
    ///
    /// Deviation: MIT overwrites the server-checksum result when a privsvr
    /// key is also given (it never tests `ret` after pac.c:535-541); here a
    /// bad server checksum always fails.
    fn verify_checksums(
        &self,
        expect_full: bool,
        server: Option<&EncryptionKey>,
        privsvr: Option<&EncryptionKey>,
    ) -> Result<()> {
        let mut copy = self.data.clone();
        self.zero_signature(PAC_SERVER_CHECKSUM, &mut copy)?;
        self.zero_signature(PAC_PRIVSVR_CHECKSUM, &mut copy)?;
        if let Some(s) = server {
            self.verify_checksum(PAC_SERVER_CHECKSUM, s, &copy)?;
        }
        if let (Some(p), true) = (privsvr, expect_full) {
            self.zero_signature(PAC_FULL_CHECKSUM, &mut copy)?;
            self.verify_checksum(PAC_FULL_CHECKSUM, p, &copy)?;
        }
        if let Some(p) = privsvr {
            let sc = self.get_buffer(PAC_SERVER_CHECKSUM)?;
            if sc.len() < PAC_SIGNATURE_DATA_LENGTH {
                return Err(PacError::BadMsize);
            }
            self.verify_checksum(PAC_PRIVSVR_CHECKSUM, p, &sc[PAC_SIGNATURE_DATA_LENGTH..])?;
        }
        Ok(())
    }

    /// `krb5_pac_verify` (pac.c:660-690): check the server and/or privsvr
    /// signatures when keys are given, and the client info against `client`
    /// (name without realm) when given. A service ticket's PAC also carries
    /// ticket and full checksums; those are checked by
    /// [`kdc_verify_ticket`].
    pub fn verify(
        &self,
        authtime: i64,
        client: Option<(&PrincipalName, &str)>,
        server: Option<&EncryptionKey>,
        privsvr: Option<&EncryptionKey>,
    ) -> Result<()> {
        self.verify_ext(authtime, client, false, server, privsvr)
    }

    /// `krb5_pac_verify_ext`: like [`Pac::verify`], expecting the realm in
    /// the client info when `with_realm`.
    pub fn verify_ext(
        &self,
        authtime: i64,
        client: Option<(&PrincipalName, &str)>,
        with_realm: bool,
        server: Option<&EncryptionKey>,
        privsvr: Option<&EncryptionKey>,
    ) -> Result<()> {
        if server.is_some() || privsvr.is_some() {
            self.verify_checksums(false, server, privsvr)?;
        }
        if let Some(c) = client {
            self.validate_client(authtime, c, with_realm)?;
        }
        Ok(())
    }

    /// `insert_client_info` (pac_sign.c:34-95).
    fn insert_client_info(
        &mut self,
        authtime: i64,
        principal: (&PrincipalName, &str),
        with_realm: bool,
    ) -> Result<()> {
        if self.locate(PAC_CLIENT_INFO).is_ok() {
            return self.validate_client(authtime, principal, with_realm);
        }
        let display = with_realm && principal.0.name_type == NT_ENTERPRISE;
        let name = unparse_name(principal.0, principal.1, display, with_realm);
        let utf16: Vec<u8> = name.encode_utf16().flat_map(u16::to_le_bytes).collect();
        let mut body = Vec::with_capacity(PAC_CLIENT_INFO_LENGTH + utf16.len());
        let nt = (u64::from(authtime as u32) + NT_TIME_EPOCH) * 10_000_000;
        body.extend_from_slice(&nt.to_le_bytes());
        body.extend_from_slice(&(utf16.len() as u16).to_le_bytes());
        body.extend_from_slice(&utf16);
        self.add_buffer(PAC_CLIENT_INFO, &body)
    }

    /// `insert_checksum` (pac_sign.c:97-135): a zero-filled signature buffer
    /// for `key`'s mandatory checksum type.
    fn insert_checksum(&mut self, ty: u32, key: &EncryptionKey) -> Result<(u32, usize)> {
        let profile = find_etype(key.keytype).map_err(|_| PacError::BadEnctype)?;
        let cksumtype = profile.checksum_type() as u32;
        let len = match cksumtype {
            15 | 16 => 12,
            19 => 16,
            20 => 24,
            _ => return Err(PacError::SumtypeNoSupp),
        };
        match self.locate(ty) {
            Ok(b) => {
                if b.size as usize != PAC_SIGNATURE_DATA_LENGTH + len {
                    return Err(PacError::Range);
                }
                let (start, end) = (b.offset as usize, b.offset as usize + b.size as usize);
                self.data[start..end].fill(0);
            }
            Err(_) => self.add_inner(ty, PAC_SIGNATURE_DATA_LENGTH + len, None)?,
        }
        let start = self.locate(ty)?.offset as usize;
        self.data[start..start + 4].copy_from_slice(&cksumtype.to_le_bytes());
        Ok((cksumtype, len))
    }

    /// `compute_pac_checksum` (pac_sign.c:160-185): write a checksum of
    /// `over` into the signature buffer `ty`.
    fn write_checksum(
        &mut self,
        ty: u32,
        key: &EncryptionKey,
        cksumtype: u32,
        over: &[u8],
    ) -> Result<()> {
        let profile = find_cksumtype(cksumtype as i32).map_err(|_| PacError::SumtypeNoSupp)?;
        let sum = profile
            .checksum(key.key_bytes(), KEYUSAGE_APP_DATA_CKSUM, over)
            .map_err(|e| PacError::Generic(e.to_string()))?;
        let b = *self.locate(ty)?;
        let start = b.offset as usize + PAC_SIGNATURE_DATA_LENGTH;
        let room = b.size as usize - PAC_SIGNATURE_DATA_LENGTH;
        if sum.len() != room {
            return Err(PacError::Range);
        }
        self.data[start..start + room].copy_from_slice(&sum);
        Ok(())
    }

    /// `sign_pac` (pac_sign.c:187-262): add client info (when `principal` is
    /// given), the server/privsvr (and, for service tickets, full)
    /// signatures, and return the encoded PAC.
    pub(crate) fn sign_pac(
        &mut self,
        authtime: i64,
        principal: Option<(&PrincipalName, &str)>,
        server_key: &EncryptionKey,
        privsvr_key: &EncryptionKey,
        with_realm: bool,
        is_service_tkt: bool,
    ) -> Result<Vec<u8>> {
        if let Some(p) = principal {
            self.insert_client_info(authtime, p, with_realm)?;
        }
        let (server_type, _) = self.insert_checksum(PAC_SERVER_CHECKSUM, server_key)?;
        let (privsvr_type, _) = self.insert_checksum(PAC_PRIVSVR_CHECKSUM, privsvr_key)?;
        if is_service_tkt {
            self.insert_checksum(PAC_FULL_CHECKSUM, privsvr_key)?;
        }
        self.sync_header();
        if is_service_tkt {
            let whole = self.data.clone();
            self.write_checksum(PAC_FULL_CHECKSUM, privsvr_key, privsvr_type, &whole)?;
        }
        let whole = self.data.clone();
        self.write_checksum(PAC_SERVER_CHECKSUM, server_key, server_type, &whole)?;
        let sc = self.get_buffer(PAC_SERVER_CHECKSUM)?[PAC_SIGNATURE_DATA_LENGTH..].to_vec();
        self.write_checksum(PAC_PRIVSVR_CHECKSUM, privsvr_key, privsvr_type, &sc)?;
        Ok(self.data.clone())
    }

    /// `krb5_pac_sign` (pac_sign.c:264-272): sign a standalone PAC.
    pub fn sign(
        &mut self,
        authtime: i64,
        client: (&PrincipalName, &str),
        server_key: &EncryptionKey,
        privsvr_key: &EncryptionKey,
    ) -> Result<Vec<u8>> {
        self.sign_pac(
            authtime,
            Some(client),
            server_key,
            privsvr_key,
            false,
            false,
        )
    }
}

/// `krb5_unparse_name_flags`: components joined by `/`, escaping `\`, `/`
/// and `@` (and control characters) unless `display`; the realm follows `@`
/// unless `no_realm`.
pub(crate) fn unparse_name(
    name: &PrincipalName,
    realm: &str,
    display: bool,
    with_realm: bool,
) -> String {
    let esc = |s: &str| -> String {
        if display {
            return s.to_string();
        }
        let mut out = String::new();
        for c in s.chars() {
            match c {
                '\\' => out.push_str("\\\\"),
                '/' => out.push_str("\\/"),
                '@' => out.push_str("\\@"),
                '\n' => out.push_str("\\n"),
                '\t' => out.push_str("\\t"),
                '\u{8}' => out.push_str("\\b"),
                '\0' => out.push_str("\\0"),
                c => out.push(c),
            }
        }
        out
    };
    let comps: Vec<String> = name
        .name_string
        .iter()
        .map(|c| esc(&String::from_utf8_lossy(c.as_bytes())))
        .collect();
    let mut s = comps.join("/");
    if with_realm {
        s.push('@');
        s.push_str(&esc(realm));
    }
    s
}

fn decode_if_relevant(el: &AuthorizationDataElement) -> Result<Vec<AuthorizationDataElement>> {
    rasn::der::decode(el.ad_data.as_ref())
        .map_err(|e| PacError::Generic(format!("decoding AD-IF-RELEVANT: {e}")))
}

/// Verify the PAC of a decrypted ticket (`krb5_kdc_verify_ticket`,
/// pac.c:590-675): the server signature with `server_key`, and with a
/// `privsvr` (KDC) key also the KDC signature and, for service tickets, the
/// ticket and full checksums. `server_princ` is the principal the ticket is
/// for. `Ok(None)` if the ticket carries no PAC.
pub fn verify_ticket_pac(
    enc_part: &EncTicketPart,
    server_princ: &PrincipalName,
    server_key: &EncryptionKey,
    privsvr: Option<&EncryptionKey>,
) -> Result<Option<Pac>> {
    kdc_verify_ticket(enc_part, server_princ, server_key, privsvr)
}

/// The PAC carried by a decrypted ticket, parsed but not verified; use
/// [`Pac::verify`] with the service key (and the KDC key if known).
/// `Ok(None)` if the ticket has none; more than one PAC is an error.
pub fn ticket_pac(enc_part: &EncTicketPart) -> Result<Option<Pac>> {
    let Some(authdata) = enc_part.authorization_data.as_deref() else {
        return Ok(None);
    };
    let mut found: Option<Pac> = None;
    for el in authdata {
        let candidates = match el.ad_type {
            AD_IF_RELEVANT => decode_if_relevant(el)?,
            AD_WIN2K_PAC => vec![el.clone()],
            _ => continue,
        };
        for c in candidates.iter().filter(|c| c.ad_type == AD_WIN2K_PAC) {
            if found.is_some() {
                return Err(PacError::Invalid("multiple PACs"));
            }
            found = Some(Pac::parse(c.ad_data.as_ref())?);
        }
    }
    Ok(found)
}

mod ndr;
mod ticket;
pub use ndr::DelegationInfo;
#[cfg(any(feature = "kdc", test))]
pub(crate) use ticket::kdc_sign_ticket;
pub(crate) use ticket::kdc_verify_ticket;
#[cfg(test)]
pub(crate) use ticket::should_have_ticket_signature;

#[cfg(test)]
mod test_data;
#[cfg(test)]
mod tests;
