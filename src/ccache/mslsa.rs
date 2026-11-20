//! `MSLSA:`, the Windows LSA Kerberos ticket cache (cc_mslsa.c).
//!
//! The cache is the current logon session's ticket cache in the LSA
//! Kerberos package. Reads go through `LsaCallAuthenticationPackage`;
//! stores submit a KRB-CRED, and removals purge LSA entries.

#![cfg_attr(not(windows), allow(dead_code))]

use super::{parse_principal, CcError};
use crate::types::PrincipalName;

/// `KERB_TICKET_FLAGS_*` (ntsecapi.h); the same bits as the KDC options.
const KERB_TICKET_FLAGS_FORWARDABLE: u32 = 0x4000_0000;
const KERB_TICKET_FLAGS_FORWARDED: u32 = 0x2000_0000;
const KERB_TICKET_FLAGS_PROXIABLE: u32 = 0x1000_0000;
const KERB_TICKET_FLAGS_RENEWABLE: u32 = 0x0080_0000;
const KERB_TICKET_FLAGS_INITIAL: u32 = 0x0040_0000;
/// `KDC_OPT_*` (krb5.h).
const KDC_OPT_FORWARDABLE: u32 = 0x4000_0000;
const KDC_OPT_FORWARDED: u32 = 0x2000_0000;
const KDC_OPT_PROXIABLE: u32 = 0x1000_0000;
const KDC_OPT_RENEWABLE: u32 = 0x0080_0000;

fn code(name: &'static str, msg: &str) -> CcError {
    CcError::Code {
        name,
        msg: msg.to_string(),
    }
}

/// `KRB5_CC_READONLY`.
fn readonly() -> CcError {
    code(
        "KRB5_CC_READONLY",
        "Ccache function not supported: read-only ccache type",
    )
}

/// `KRB5_FCC_INTERNAL`.
fn internal() -> CcError {
    code("KRB5_FCC_INTERNAL", "Internal credentials cache error")
}

/// `KRB5_FCC_NOFILE`.
fn nofile() -> CcError {
    CcError::NoFile("No credentials cache found".to_string())
}

/// `FileTimeToUnixTime`, truncated to a `krb5_timestamp`.
fn filetime_to_unix(ft: i64) -> u32 {
    let t = ft / 10_000_000 - 11_644_473_600;
    let [a, b, c, d, ..] = t.to_le_bytes();
    u32::from_le_bytes([a, b, c, d])
}

/// The KDC options `GetMSCacheTicketFromCacheInfoEx{,2}` asks for, from a
/// cache entry's ticket flags.
fn retrieve_flags(ticket_flags: u32) -> u32 {
    [
        (KERB_TICKET_FLAGS_FORWARDABLE, KDC_OPT_FORWARDABLE),
        (KERB_TICKET_FLAGS_FORWARDED, KDC_OPT_FORWARDED),
        (KERB_TICKET_FLAGS_PROXIABLE, KDC_OPT_PROXIABLE),
        (KERB_TICKET_FLAGS_RENEWABLE, KDC_OPT_RENEWABLE),
    ]
    .iter()
    .filter(|(f, _)| ticket_flags & f != 0)
    .fold(0, |acc, (_, o)| acc | o)
}

/// `IsMSSessionKeyNull`.
fn session_key_null(key_type: i32, value: &[u8]) -> bool {
    key_type == 0 || value.iter().all(|b| *b == 0)
}

/// `UnicodeStringToMITPrinc`: `name@realm`, parsed.
fn name_at_realm(name: &str, realm: &str) -> Option<(PrincipalName, String)> {
    parse_principal(&format!("{name}@{realm}"), None)
}

/// `KerbExternalNameToMITPrinc`: the components joined with `/`, at `realm`.
fn external_name(components: &[String], realm: &str) -> Option<(PrincipalName, String)> {
    name_at_realm(&components.join("/"), realm)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filetime_converts_like_mit() {
        assert_eq!(filetime_to_unix(116_444_736_000_000_000), 0);
        assert_eq!(
            filetime_to_unix(116_444_736_000_000_000 + 10_000_000 * 86_400),
            86_400
        );
    }

    #[test]
    fn retrieve_flags_maps_four_bits() {
        let all = KERB_TICKET_FLAGS_FORWARDABLE
            | KERB_TICKET_FLAGS_FORWARDED
            | KERB_TICKET_FLAGS_PROXIABLE
            | KERB_TICKET_FLAGS_RENEWABLE
            | KERB_TICKET_FLAGS_INITIAL;
        assert_eq!(
            retrieve_flags(all),
            KDC_OPT_FORWARDABLE | KDC_OPT_FORWARDED | KDC_OPT_PROXIABLE | KDC_OPT_RENEWABLE
        );
        assert_eq!(retrieve_flags(KERB_TICKET_FLAGS_INITIAL), 0);
    }

    #[test]
    fn null_session_keys() {
        assert!(session_key_null(0, &[1, 2]));
        assert!(session_key_null(18, &[0; 32]));
        assert!(!session_key_null(18, &[0, 1]));
    }

    #[test]
    fn names_parse_like_mit() {
        let (p, r) =
            external_name(&["krbtgt".into(), "EXAMPLE.COM".into()], "EXAMPLE.COM").expect("parse");
        assert_eq!(r, "EXAMPLE.COM");
        assert_eq!(
            super::super::unparse_name(&p, &r),
            "krbtgt/EXAMPLE.COM@EXAMPLE.COM"
        );
        let (p, r) = name_at_realm("alice", "EXAMPLE.COM").expect("parse");
        assert_eq!(super::super::unparse_name(&p, &r), "alice@EXAMPLE.COM");
    }
}

/// The LSA calls (cc_mslsa.c), with owned results.
#[cfg(windows)]
#[allow(unsafe_code)]
mod sys {
    use std::ffi::c_void;
    use std::ptr::null_mut;
    use std::sync::OnceLock;

    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::Security::Authentication::Identity::{
        KerbPurgeTicketCacheExMessage, KerbPurgeTicketCacheMessage, KerbQueryTicketCacheEx2Message,
        KerbQueryTicketCacheExMessage, KerbRetrieveEncodedTicketMessage, KerbRetrieveTicketMessage,
        KerbSubmitTicketMessage, LsaCallAuthenticationPackage, LsaConnectUntrusted,
        LsaDeregisterLogonProcess, LsaFreeReturnBuffer, LsaGetLogonSessionData,
        LsaLookupAuthenticationPackage, KERB_EXTERNAL_NAME, KERB_PURGE_TKT_CACHE_EX_REQUEST,
        KERB_PURGE_TKT_CACHE_REQUEST, KERB_QUERY_TKT_CACHE_EX2_RESPONSE,
        KERB_QUERY_TKT_CACHE_EX_RESPONSE, KERB_QUERY_TKT_CACHE_REQUEST, KERB_RETRIEVE_TKT_REQUEST,
        KERB_RETRIEVE_TKT_RESPONSE, KERB_SUBMIT_TKT_REQUEST, KERB_TICKET_CACHE_INFO_EX,
        KERB_TICKET_CACHE_INFO_EX2, LSA_STRING, LSA_UNICODE_STRING, SECURITY_LOGON_SESSION_DATA,
    };
    use windows_sys::Win32::Security::{
        GetTokenInformation, TokenStatistics, TOKEN_QUERY, TOKEN_STATISTICS,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    /// `SEC_E_NO_CREDENTIALS`.
    pub const SEC_E_NO_CREDENTIALS: i32 = i32::from_ne_bytes(0x8009_030E_u32.to_ne_bytes());

    fn failed(status: i32) -> bool {
        status < 0
    }

    /// A `KERB_TICKET_CACHE_INFO_EX{,2}` entry.
    pub struct CacheInfo {
        pub client: String,
        pub client_realm: String,
        /// The UTF-16 server name, for retrieval requests.
        pub server_utf16: Vec<u16>,
        pub etype: i32,
        pub flags: u32,
        /// `SessionKeyType`, for EX2 entries.
        pub session_key_type: Option<u32>,
    }

    /// A `KERB_EXTERNAL_TICKET`.
    pub struct ExternalTicket {
        pub service: Vec<String>,
        pub client: Vec<String>,
        pub domain: String,
        pub target_domain: Vec<u16>,
        pub key_type: i32,
        pub key: zeroize::Zeroizing<Vec<u8>>,
        pub flags: u32,
        pub start: i64,
        pub end: i64,
        pub renew: i64,
        pub encoded: Vec<u8>,
    }

    fn utf16_of(u: &LSA_UNICODE_STRING) -> Vec<u16> {
        if u.Buffer.is_null() || u.Length == 0 {
            return Vec::new();
        }
        // SAFETY: the LSA returns `Length` bytes of UTF-16 at `Buffer`.
        unsafe { std::slice::from_raw_parts(u.Buffer, usize::from(u.Length / 2)) }.to_vec()
    }

    fn string_of(u: &LSA_UNICODE_STRING) -> String {
        String::from_utf16_lossy(&utf16_of(u))
    }

    fn bytes_of(p: *const u8, n: u32) -> Vec<u8> {
        let n = usize::try_from(n).unwrap_or(0);
        if p.is_null() || n == 0 {
            return Vec::new();
        }
        // SAFETY: the LSA returns `n` bytes at `p`.
        unsafe { std::slice::from_raw_parts(p, n) }.to_vec()
    }

    fn names_of(n: *const KERB_EXTERNAL_NAME) -> Vec<String> {
        if n.is_null() {
            return Vec::new();
        }
        // SAFETY: a KERB_EXTERNAL_NAME holds `NameCount` strings.
        unsafe {
            let count = usize::from((*n).NameCount);
            std::slice::from_raw_parts((&raw const (*n).Names).cast::<LSA_UNICODE_STRING>(), count)
        }
        .iter()
        .map(string_of)
        .collect()
    }

    /// A request buffer: a header struct, then string or byte data.
    struct Request {
        buf: Vec<u64>,
        len: usize,
    }

    impl Drop for Request {
        fn drop(&mut self) {
            zeroize::Zeroize::zeroize(&mut self.buf);
        }
    }

    impl Request {
        fn new<T>(tail: usize) -> Self {
            let len = size_of::<T>() + tail;
            Self {
                buf: vec![0; len.div_ceil(8)],
                len,
            }
        }

        fn head<T>(&mut self) -> *mut T {
            self.buf.as_mut_ptr().cast()
        }

        fn put(&mut self, off: usize, data: &[u8]) {
            assert!(off + data.len() <= self.len);
            // SAFETY: in bounds by the assertion.
            unsafe {
                std::ptr::copy_nonoverlapping(
                    data.as_ptr(),
                    self.buf.as_mut_ptr().cast::<u8>().add(off),
                    data.len(),
                );
            }
        }

        /// A string at `off` with room for `max` bytes; one that does not
        /// fit is left empty, as `MITPrincToMSPrinc` does.
        fn put_str(&mut self, off: usize, s: &[u16], max: usize) -> LSA_UNICODE_STRING {
            let bytes: Vec<u8> = if s.len() * 2 <= max {
                s.iter().flat_map(|c| c.to_ne_bytes()).collect()
            } else {
                Vec::new()
            };
            self.put(off, &bytes);
            LSA_UNICODE_STRING {
                Length: u16::try_from(bytes.len()).unwrap_or(0),
                MaximumLength: u16::try_from(max).unwrap_or(u16::MAX),
                // SAFETY: `off` is within the buffer (checked by `put`).
                Buffer: unsafe { self.buf.as_mut_ptr().cast::<u8>().add(off) }.cast(),
            }
        }

        fn len32(&self) -> u32 {
            u32::try_from(self.len).unwrap_or(u32::MAX)
        }
    }

    /// An LSA return buffer.
    struct Buf(*mut c_void);

    impl Drop for Buf {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: returned by the LSA and freed once.
                unsafe { LsaFreeReturnBuffer(self.0) };
            }
        }
    }

    /// A connection to the LSA Kerberos package (`PackageConnectLookup`).
    pub struct Lsa {
        handle: HANDLE,
        package: u32,
    }

    // SAFETY: LSA handles may be used from any thread.
    unsafe impl Send for Lsa {}
    // SAFETY: as above; every call is independent.
    unsafe impl Sync for Lsa {}

    impl Drop for Lsa {
        fn drop(&mut self) {
            // SAFETY: the handle came from LsaConnectUntrusted.
            unsafe { LsaDeregisterLogonProcess(self.handle) };
        }
    }

    impl Lsa {
        pub fn connect() -> Option<Self> {
            let mut handle: HANDLE = null_mut();
            // SAFETY: plain call with an out pointer.
            if failed(unsafe { LsaConnectUntrusted(&mut handle) }) {
                return None;
            }
            let mut lsa = Self { handle, package: 0 };
            let name = b"Kerberos\0";
            let s = LSA_STRING {
                Length: 8,
                MaximumLength: 9,
                Buffer: name.as_ptr().cast_mut(),
            };
            // SAFETY: `s` points at a live NUL-terminated name.
            if failed(unsafe { LsaLookupAuthenticationPackage(handle, &s, &mut lsa.package) }) {
                return None;
            }
            Some(lsa)
        }

        fn call(&self, req: &mut Request, want: bool) -> Result<Buf, (i32, i32)> {
            let mut out: *mut c_void = null_mut();
            let mut outlen = 0u32;
            let mut sub = 0i32;
            // SAFETY: the request buffer is live and `len` bytes long.
            let status = unsafe {
                LsaCallAuthenticationPackage(
                    self.handle,
                    self.package,
                    req.buf.as_ptr().cast(),
                    req.len32(),
                    if want { &mut out } else { null_mut() },
                    if want { &mut outlen } else { null_mut() },
                    &mut sub,
                )
            };
            let buf = Buf(out);
            if failed(status) || failed(sub) {
                Err((status, sub))
            } else {
                Ok(buf)
            }
        }

        fn simple(&self, message: i32) -> Result<Buf, (i32, i32)> {
            let mut req = Request::new::<KERB_QUERY_TKT_CACHE_REQUEST>(0);
            // SAFETY: the header is in bounds and zeroed.
            unsafe { (*req.head::<KERB_QUERY_TKT_CACHE_REQUEST>()).MessageType = message };
            self.call(&mut req, true)
        }

        /// `GetQueryTktCacheResponseEx{,2}`.
        pub fn query_cache(&self, ex2: bool) -> Option<Vec<CacheInfo>> {
            let message = if ex2 {
                KerbQueryTicketCacheEx2Message
            } else {
                KerbQueryTicketCacheExMessage
            };
            let buf = self.simple(message).ok()?;
            if buf.0.is_null() {
                return Some(Vec::new());
            }
            // SAFETY: the response holds `CountOfTickets` entries.
            let out = unsafe {
                if ex2 {
                    let r = buf.0.cast::<KERB_QUERY_TKT_CACHE_EX2_RESPONSE>();
                    let n = usize::try_from((*r).CountOfTickets).unwrap_or(0);
                    std::slice::from_raw_parts(
                        (&raw const (*r).Tickets).cast::<KERB_TICKET_CACHE_INFO_EX2>(),
                        n,
                    )
                    .iter()
                    .map(|t| CacheInfo {
                        client: string_of(&t.ClientName),
                        client_realm: string_of(&t.ClientRealm),
                        server_utf16: utf16_of(&t.ServerName),
                        etype: t.EncryptionType,
                        flags: t.TicketFlags,
                        session_key_type: Some(t.SessionKeyType),
                    })
                    .collect()
                } else {
                    let r = buf.0.cast::<KERB_QUERY_TKT_CACHE_EX_RESPONSE>();
                    let n = usize::try_from((*r).CountOfTickets).unwrap_or(0);
                    std::slice::from_raw_parts(
                        (&raw const (*r).Tickets).cast::<KERB_TICKET_CACHE_INFO_EX>(),
                        n,
                    )
                    .iter()
                    .map(|t| CacheInfo {
                        client: string_of(&t.ClientName),
                        client_realm: string_of(&t.ClientRealm),
                        server_utf16: utf16_of(&t.ServerName),
                        etype: t.EncryptionType,
                        flags: t.TicketFlags,
                        session_key_type: None,
                    })
                    .collect()
                }
            };
            Some(out)
        }

        fn ticket_of(buf: &Buf) -> Option<ExternalTicket> {
            if buf.0.is_null() {
                return None;
            }
            // SAFETY: a KERB_RETRIEVE_TKT_RESPONSE from the LSA.
            let t = unsafe { &(*buf.0.cast::<KERB_RETRIEVE_TKT_RESPONSE>()).Ticket };
            Some(ExternalTicket {
                service: names_of(t.ServiceName),
                client: names_of(t.ClientName),
                domain: string_of(&t.DomainName),
                target_domain: utf16_of(&t.TargetDomainName),
                key_type: t.SessionKey.KeyType,
                key: zeroize::Zeroizing::new(bytes_of(t.SessionKey.Value, t.SessionKey.Length)),
                flags: t.TicketFlags,
                start: t.StartTime,
                end: t.EndTime,
                renew: t.RenewUntil,
                encoded: bytes_of(t.EncodedTicket, t.EncodedTicketSize),
            })
        }

        /// `KerbRetrieveTicketMessage`: the logon session's TGT.
        pub fn retrieve_tgt(&self) -> Result<ExternalTicket, (i32, i32)> {
            let buf = self.simple(KerbRetrieveTicketMessage)?;
            Self::ticket_of(&buf).ok_or((0, -1))
        }

        /// `KerbRetrieveEncodedTicketMessage` for `target`, with room for
        /// `max` bytes of name.
        pub fn retrieve_encoded(
            &self,
            target: &[u16],
            max: usize,
            cache_options: u32,
            ticket_flags: u32,
            etype: i32,
        ) -> Result<ExternalTicket, (i32, i32)> {
            let off = size_of::<KERB_RETRIEVE_TKT_REQUEST>();
            let mut req = Request::new::<KERB_RETRIEVE_TKT_REQUEST>(max);
            let name = req.put_str(off, target, max);
            let h = req.head::<KERB_RETRIEVE_TKT_REQUEST>();
            // SAFETY: the header is in bounds and zeroed.
            unsafe {
                (*h).MessageType = KerbRetrieveEncodedTicketMessage;
                (*h).TargetName = name;
                (*h).CacheOptions = cache_options;
                (*h).TicketFlags = ticket_flags;
                (*h).EncryptionType = etype;
            }
            let buf = self.call(&mut req, true)?;
            Self::ticket_of(&buf).ok_or((0, -1))
        }

        /// `PurgeAllTickets`.
        pub fn purge_all(&self) -> bool {
            let mut req = Request::new::<KERB_PURGE_TKT_CACHE_REQUEST>(0);
            // SAFETY: the header is in bounds and zeroed.
            unsafe {
                (*req.head::<KERB_PURGE_TKT_CACHE_REQUEST>()).MessageType =
                    KerbPurgeTicketCacheMessage
            };
            self.call(&mut req, false).is_ok()
        }

        /// `PurgeTicketEx`: the full client and server names, their realms,
        /// the session key enctype and the match flags.
        pub fn purge_ex(&self, names: [&str; 4], etype: i32, flags: u32) -> bool {
            const SLOT: usize = 512;
            let off = size_of::<KERB_PURGE_TKT_CACHE_EX_REQUEST>();
            let mut req = Request::new::<KERB_PURGE_TKT_CACHE_EX_REQUEST>(4 * SLOT);
            let [cname, crealm, sname, srealm] =
                names.map(|n| n.encode_utf16().collect::<Vec<_>>());
            let cname = req.put_str(off, &cname, SLOT);
            let crealm = req.put_str(off + SLOT, &crealm, SLOT);
            let sname = req.put_str(off + 2 * SLOT, &sname, SLOT);
            let srealm = req.put_str(off + 3 * SLOT, &srealm, SLOT);
            let h = req.head::<KERB_PURGE_TKT_CACHE_EX_REQUEST>();
            // SAFETY: the header is in bounds and zeroed.
            unsafe {
                (*h).MessageType = KerbPurgeTicketCacheExMessage;
                (*h).TicketTemplate.ClientName = cname;
                (*h).TicketTemplate.ClientRealm = crealm;
                (*h).TicketTemplate.ServerName = sname;
                (*h).TicketTemplate.ServerRealm = srealm;
                (*h).TicketTemplate.EncryptionType = etype;
                (*h).TicketTemplate.TicketFlags = flags;
            }
            self.call(&mut req, false).is_ok()
        }

        /// `KerbSubmitTicket`: a KRB-CRED and the key it is encrypted in.
        pub fn submit(&self, krb_cred: &[u8], key_type: i32, key: &[u8]) -> bool {
            let off = size_of::<KERB_SUBMIT_TKT_REQUEST>();
            let mut req = Request::new::<KERB_SUBMIT_TKT_REQUEST>(krb_cred.len() + key.len());
            req.put(off, krb_cred);
            req.put(off + krb_cred.len(), key);
            let h = req.head::<KERB_SUBMIT_TKT_REQUEST>();
            let n = |v: usize| u32::try_from(v).unwrap_or(u32::MAX);
            // SAFETY: the header is in bounds and zeroed.
            unsafe {
                (*h).MessageType = KerbSubmitTicketMessage;
                (*h).Key.KeyType = key_type;
                (*h).Key.Length = n(key.len());
                (*h).Key.Offset = n(off + krb_cred.len());
                (*h).KerbCredSize = n(krb_cred.len());
                (*h).KerbCredOffset = n(off);
            }
            self.call(&mut req, false).is_ok()
        }
    }

    /// `GetSecurityLogonSessionData`: the logon session's DNS domain.
    pub fn logon_dns_domain() -> Option<Vec<u16>> {
        let mut token: HANDLE = null_mut();
        // SAFETY: plain calls with out pointers.
        unsafe {
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
                return None;
            }
            let mut stats: TOKEN_STATISTICS = std::mem::zeroed();
            let mut len = 0u32;
            let ok = GetTokenInformation(
                token,
                TokenStatistics,
                (&raw mut stats).cast(),
                u32::try_from(size_of::<TOKEN_STATISTICS>()).unwrap_or(0),
                &mut len,
            );
            CloseHandle(token);
            if ok == 0 {
                return None;
            }
            let mut data: *mut SECURITY_LOGON_SESSION_DATA = null_mut();
            if failed(LsaGetLogonSessionData(&stats.AuthenticationId, &mut data)) || data.is_null()
            {
                return None;
            }
            let buf = Buf(data.cast());
            let d = &(*data).DnsDomainName;
            let out = (!d.Buffer.is_null()).then(|| utf16_of(d));
            drop(buf);
            out
        }
    }

    /// `does_query_ticket_cache_ex2`.
    pub fn ex2_supported() -> bool {
        static EX2: OnceLock<bool> = OnceLock::new();
        *EX2.get_or_init(|| {
            Lsa::connect().is_some_and(|l| l.simple(KerbQueryTicketCacheEx2Message).is_ok())
        })
    }
}

#[cfg(windows)]
pub use imp::MslsaCcache;

#[cfg(windows)]
mod imp {
    use super::sys::{self, CacheInfo, ExternalTicket, Lsa, SEC_E_NO_CREDENTIALS};
    use super::*;
    use crate::ccache::retrieve::retrieve_in;
    use crate::ccache::{
        creds_match_request, is_config_principal, unparse_name, CcCredential, Ccache, MatchCred,
        MatchFlags,
    };
    use crate::crypto::find_etype;
    use crate::crypto::util::generate_random;
    use crate::protocol::ap::AuthContext;
    use crate::types::EncryptionKey;

    const KERB_RETRIEVE_TICKET_DONT_USE_CACHE: u32 = 1;
    const KERB_RETRIEVE_TICKET_CACHE_TICKET: u32 = 32;
    /// `GetMSCacheTicketFromMITCred`'s target name room.
    const TARGET_MAX: usize = 1024;
    /// The KRB-CRED key for `KerbSubmitTicket`; MIT uses RC4, which
    /// krb5-rs does not support.
    const SUBMIT_ETYPE: i32 = 18;

    fn tgs_ktypes() -> Vec<i32> {
        crate::protocol::TgsOptions::default().etypes
    }

    /// `krb5_is_permitted_tgs_enctype`.
    fn permitted(etype: i32) -> bool {
        tgs_ktypes().contains(&etype)
    }

    fn krbtgt(domain: &[u16]) -> Vec<u16> {
        let mut v: Vec<u16> = "krbtgt/".encode_utf16().collect();
        v.extend_from_slice(domain);
        v
    }

    /// `MSCredToMITCred`. MIT's `MSFlagsToMITFlags` sets no flags, and
    /// the authtime is not available.
    fn to_cred(t: &ExternalTicket, client_realm: &str) -> Option<CcCredential> {
        let (client, crealm) = external_name(&t.client, client_realm)?;
        let (server, srealm) = external_name(&t.service, &t.domain)?;
        Some(CcCredential {
            client,
            crealm,
            server,
            srealm,
            keyblock: EncryptionKey::new(t.key_type, t.key.to_vec()),
            authtime: 0,
            starttime: filetime_to_unix(t.start),
            endtime: filetime_to_unix(t.end),
            renew_till: filetime_to_unix(t.renew),
            is_skey: false,
            ticket_flags: 0,
            addresses: Vec::new(),
            authdata: Vec::new(),
            ticket: t.encoded.clone(),
            second_ticket: Vec::new(),
        })
    }

    /// The current logon session's LSA ticket cache (`krb5_lcc_ops`).
    pub struct MslsaCcache {
        residual: String,
        lsa: Lsa,
        princ: Option<(PrincipalName, String)>,
    }

    impl MslsaCcache {
        /// `krb5_lcc_resolve`.
        pub fn resolve(residual: &str) -> Result<Self, CcError> {
            let lsa = Lsa::connect().ok_or_else(nofile)?;
            let mut cc = Self {
                residual: residual.to_string(),
                lsa,
                princ: None,
            };
            cc.princ = cc.first_client();
            Ok(cc)
        }

        /// `krb5_lcc_generate_new`.
        pub fn gen_new() -> Result<Self, CcError> {
            Err(readonly())
        }

        /// `krb5_lcc_get_name`, with the type prefix.
        pub fn name(&self) -> String {
            format!("MSLSA:{}", self.residual)
        }

        /// `krb5_lcc_destroy`.
        pub fn destroy(self) -> Result<(), CcError> {
            if self.lsa.purge_all() {
                Ok(())
            } else {
                Err(internal())
            }
        }

        fn first_client(&self) -> Option<(PrincipalName, String)> {
            self.lsa
                .query_cache(false)?
                .iter()
                .find_map(|t| name_at_realm(&t.client, &t.client_realm))
        }

        /// `GetMSTGT`.
        fn ms_tgt(&self, enforce: bool) -> Option<ExternalTicket> {
            let target = match self.lsa.retrieve_tgt() {
                Ok(t) => {
                    if !enforce || session_key_null(t.key_type, &t.key) || permitted(t.key_type) {
                        return Some(t);
                    }
                    krbtgt(&t.target_domain)
                }
                Err((status, _)) if status < 0 => return None,
                Err((_, sub)) if sub != SEC_E_NO_CREDENTIALS => return None,
                Err(_) => krbtgt(&sys::logon_dns_domain()?),
            };
            let max = target.len() * 2;
            let mut t = self
                .lsa
                .retrieve_encoded(&target, max, KERB_RETRIEVE_TICKET_DONT_USE_CACHE, 0, 0)
                .ok()?;
            if !enforce || permitted(t.key_type) {
                return Some(t);
            }
            for etype in tgs_ktypes() {
                t = self
                    .lsa
                    .retrieve_encoded(&target, max, KERB_RETRIEVE_TICKET_CACHE_TICKET, 0, etype)
                    .ok()?;
                if t.key_type == etype && permitted(etype) {
                    break;
                }
            }
            Some(t)
        }

        /// `GetMSCacheTicketFromCacheInfoEx{,2}`.
        fn fetch_info(&self, i: &CacheInfo) -> Option<ExternalTicket> {
            let (options, etype) = match i.session_key_type {
                Some(k) => (
                    KERB_RETRIEVE_TICKET_CACHE_TICKET,
                    i32::try_from(k).unwrap_or(0),
                ),
                None => (0, i.etype),
            };
            let target = &i.server_utf16;
            let mut t = self
                .lsa
                .retrieve_encoded(
                    target,
                    target.len() * 2,
                    options,
                    retrieve_flags(i.flags),
                    etype,
                )
                .ok()?;
            if i.flags & KERB_TICKET_FLAGS_INITIAL != 0 {
                t.flags |= KERB_TICKET_FLAGS_INITIAL;
            }
            Some(t)
        }

        /// `GetMSCacheTicketFromMITCred`.
        fn fetch_server(&self, server: &str, flags: u32, etype: i32) -> Option<ExternalTicket> {
            let target: Vec<u16> = server.encode_utf16().collect();
            self.lsa
                .retrieve_encoded(
                    &target,
                    TARGET_MAX,
                    KERB_RETRIEVE_TICKET_CACHE_TICKET,
                    flags,
                    etype,
                )
                .ok()
        }

        /// `krb5_lcc_start_seq_get` and `krb5_lcc_next_cred`.
        fn all(&self) -> Result<Vec<CcCredential>, CcError> {
            self.ms_tgt(true).ok_or(CcError::NotFound)?;
            let infos = self
                .lsa
                .query_cache(sys::ex2_supported())
                .ok_or_else(internal)?;
            Ok(infos
                .iter()
                .filter_map(|i| {
                    let t = self.fetch_info(i)?;
                    if session_key_null(t.key_type, &t.key) {
                        return None;
                    }
                    to_cred(&t, &i.client_realm)
                })
                .collect())
        }

        /// `KerbSubmitTicket`.
        fn submit(&self, cred: &CcCredential) -> Option<()> {
            let profile = find_etype(SUBMIT_ETYPE).ok()?;
            let key = zeroize::Zeroizing::new(
                profile
                    .random_to_key(&generate_random(profile.key_bytes()))
                    .ok()?
                    .to_vec(),
            );
            let mut actx = AuthContext::new();
            actx.set_session_key(EncryptionKey::new(SUBMIT_ETYPE, key.to_vec()));
            let credential = crate::protocol::Credential::try_from(cred).ok()?;
            let (packet, _) = actx.mk_cred(&[credential]).ok()?;
            self.lsa.submit(&packet, SUBMIT_ETYPE, &key).then_some(())
        }

        fn default_retrieve(
            &self,
            flags: MatchFlags,
            m: &MatchCred,
            ktypes: Option<&[i32]>,
        ) -> Option<CcCredential> {
            let creds = self.all().ok()?;
            retrieve_in(&creds, flags, m, ktypes)
                .ok()
                .filter(|c| !c.ticket.is_empty())
        }
    }

    fn unparse(name: Option<&(PrincipalName, String)>) -> String {
        name.map(|(n, r)| unparse_name(n, r)).unwrap_or_default()
    }

    fn purge_name(principal: Option<&(PrincipalName, String)>) -> (String, &str) {
        principal.map_or_else(
            || (String::new(), ""),
            |(name, realm)| {
                let mut name = unparse_name(name, "");
                name.pop();
                (name, realm.as_str())
            },
        )
    }

    impl Ccache for MslsaCcache {
        /// `krb5_lcc_initialize`: purge the client's tickets.
        fn initialize(&mut self, client: &PrincipalName, realm: &str) -> Result<(), CcError> {
            self.princ = Some((client.clone(), realm.to_string()));
            let creds = match self.all() {
                Ok(c) => c,
                Err(CcError::NotFound) => return Ok(()),
                Err(e) => return Err(e),
            };
            for c in creds
                .iter()
                .filter(|c| c.client.name_string == client.name_string && c.crealm == realm)
            {
                let m = MatchCred {
                    client: Some((c.client.clone(), c.crealm.clone())),
                    server: Some((c.server.clone(), c.srealm.clone())),
                    etype: c.keyblock.keytype,
                    ..Default::default()
                };
                let _ = self.remove_cred(MatchFlags::empty(), &m);
            }
            Ok(())
        }

        /// `krb5_lcc_get_principal`.
        fn principal(&self) -> Result<(PrincipalName, String), CcError> {
            self.princ
                .clone()
                .or_else(|| self.first_client())
                .ok_or(CcError::NotFound)
        }

        /// `krb5_lcc_store`.
        fn store(&mut self, cred: &CcCredential) -> Result<(), CcError> {
            if is_config_principal(&cred.server, &cred.srealm) || self.submit(cred).is_some() {
                return Ok(());
            }
            if cred.ticket_flags != 0 && cred.keyblock.keytype != 0 {
                let server = unparse_name(&cred.server, &cred.srealm);
                if self.fetch_server(&server, 0, 0).is_some()
                    || self
                        .fetch_server(&server, cred.ticket_flags, cred.keyblock.keytype)
                        .is_some()
                {
                    return Ok(());
                }
            }
            Err(readonly())
        }

        fn creds(&self) -> Result<Vec<CcCredential>, CcError> {
            self.all()
        }

        /// `krb5_lcc_remove_cred` (`PurgeTicketEx`).
        fn remove_cred(&mut self, flags: MatchFlags, m: &MatchCred) -> Result<(), CcError> {
            let (client, crealm) = purge_name(m.client.as_ref());
            let (server, srealm) = purge_name(m.server.as_ref());
            if self
                .lsa
                .purge_ex([&client, crealm, &server, srealm], m.etype, flags.bits())
            {
                Ok(())
            } else {
                Err(readonly())
            }
        }

        /// `krb5_lcc_retrieve`: the iterated cache, else a ticket the LSA
        /// fetches for the server.
        fn retrieve(
            &self,
            flags: MatchFlags,
            m: &MatchCred,
            ktypes: Option<&[i32]>,
        ) -> Result<CcCredential, CcError> {
            if let Some(c) = self.default_retrieve(flags, m, ktypes) {
                return Ok(c);
            }
            let server = unparse(m.server.as_ref());
            self.fetch_server(&server, 0, 0).ok_or(CcError::NotFound)?;
            if let Some(c) = self.default_retrieve(flags, m, ktypes) {
                return Ok(c);
            }
            let t = self
                .fetch_server(&server, m.ticket_flags, m.etype)
                .ok_or(CcError::NotFound)?;
            let infos = self.lsa.query_cache(false).ok_or_else(internal)?;
            let realm = infos
                .iter()
                .find(|i| self.fetch_info(i).is_some_and(|x| x.encoded == t.encoded))
                .map_or(t.domain.clone(), |i| i.client_realm.clone());
            let c = to_cred(&t, &realm).ok_or_else(internal)?;
            if creds_match_request(flags, m, &c) {
                Ok(c)
            } else {
                Err(CcError::NotFound)
            }
        }

        /// Config entries are not kept (`krb5_lcc_store` ignores them).
        fn set_config(
            &mut self,
            _principal: Option<(&PrincipalName, &str)>,
            _key: &str,
            _data: Option<&[u8]>,
        ) -> Result<(), CcError> {
            Ok(())
        }

        fn get_config(
            &self,
            _principal: Option<(&PrincipalName, &str)>,
            _key: &str,
        ) -> Result<Option<Vec<u8>>, CcError> {
            Ok(None)
        }
    }
}
