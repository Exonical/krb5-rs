//! NegoEx (MS-NEGOEX) under SPNEGO, like MIT 1.22.2
//! lib/gssapi/spnego/negoex_ctx.c and negoex_util.c.
//!
//! NegoEx negotiates among mechanisms identified by 16-byte auth-scheme
//! GUIDs. Each mechanism implements [`NegoexMech`], the Rust form of MIT's
//! `gssspi_query_mechanism_info`, `gssspi_query_meta_data`,
//! `gssspi_exchange_meta_data`, `gss_init_sec_context`,
//! `gss_accept_sec_context` and the `GSS_C_INQ_NEGOEX_KEY` /
//! `GSS_C_INQ_NEGOEX_VERIFY_KEY` queries.

use crate::crypto::{find_cksumtype, find_etype};
use crate::error::Krb5Error;

use super::GssError;

/// NegoEx mechanism OID 1.3.6.1.4.1.311.2.2.30 (gssapiP_negoex.h:34-35).
pub const MECH_NEGOEX: &[u8] = &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x1e];

const MESSAGE_SIGNATURE: u64 = 0x535458454F47454E;
const EXTENSION_LENGTH: usize = 12;
const EXTENSION_FLAG_CRITICAL: u32 = 0x8000_0000;
const CHECKSUM_SCHEME_RFC3961: u32 = 1;
/// Key usage of the initiator's VERIFY checksum, as the spec names it.
pub const KEYUSAGE_INITIATOR_CHECKSUM: i32 = 23;
/// Key usage of the acceptor's VERIFY checksum, as the spec names it.
pub const KEYUSAGE_ACCEPTOR_CHECKSUM: i32 = 25;
const CHECKSUM_HEADER_LENGTH: u32 = 20;
/// Length of an auth scheme or conversation ID.
pub const GUID_LENGTH: usize = 16;
const MESSAGE_HEADER_LENGTH: usize = 40;
const NEGO_MESSAGE_HEADER_LENGTH: u32 = 96;
const EXCHANGE_MESSAGE_HEADER_LENGTH: u32 = 64;
const VERIFY_MESSAGE_HEADER_LENGTH: u32 = 80;
const ALERT_MESSAGE_HEADER_LENGTH: u32 = 72;
const ALERT_LENGTH: u32 = 12;
const ALERT_PULSE_LENGTH: u32 = 8;
const ALERT_TYPE_PULSE: u32 = 1;
const ALERT_VERIFY_NO_KEY: u32 = 1;

/// A NegoEx auth scheme GUID.
pub type AuthScheme = [u8; GUID_LENGTH];

/// NegoEx message types (gssapiP_negoex.h:70-79).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum MessageType {
    /// INITIATOR_NEGO
    InitiatorNego = 0,
    /// ACCEPTOR_NEGO
    AcceptorNego = 1,
    /// INITIATOR_META_DATA
    InitiatorMetaData = 2,
    /// ACCEPTOR_META_DATA
    AcceptorMetaData = 3,
    /// CHALLENGE
    Challenge = 4,
    /// AP_REQUEST
    ApRequest = 5,
    /// VERIFY
    Verify = 6,
    /// ALERT
    Alert = 7,
}

impl MessageType {
    fn from_u32(v: u32) -> Option<Self> {
        use MessageType::*;
        Some(match v {
            0 => InitiatorNego,
            1 => AcceptorNego,
            2 => InitiatorMetaData,
            3 => AcceptorMetaData,
            4 => Challenge,
            5 => ApRequest,
            6 => Verify,
            7 => Alert,
            _ => return None,
        })
    }

    /// `typestr` (negoex_util.c:120-141).
    pub fn name(self) -> &'static str {
        use MessageType::*;
        match self {
            InitiatorNego => "INITIATOR_NEGO",
            AcceptorNego => "ACCEPTOR_NEGO",
            InitiatorMetaData => "INITIATOR_META_DATA",
            AcceptorMetaData => "ACCEPTOR_META_DATA",
            Challenge => "CHALLENGE",
            ApRequest => "AP_REQUEST",
            Verify => "VERIFY",
            Alert => "ALERT",
        }
    }

    fn header_len(self) -> u32 {
        use MessageType::*;
        match self {
            InitiatorNego | AcceptorNego => NEGO_MESSAGE_HEADER_LENGTH,
            InitiatorMetaData | AcceptorMetaData | Challenge | ApRequest => {
                EXCHANGE_MESSAGE_HEADER_LENGTH
            }
            Verify => VERIFY_MESSAGE_HEADER_LENGTH,
            Alert => ALERT_MESSAGE_HEADER_LENGTH,
        }
    }
}

/// MIT's `ERR_NEGOEX_*` minor codes and their text (spnego_mech.c:1759-1786).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum NegoexError {
    /// ERR_NEGOEX_INVALID_MESSAGE_SIGNATURE
    #[error("Invalid NegoEx signature")]
    InvalidMessageSignature,
    /// ERR_NEGOEX_INVALID_MESSAGE_TYPE
    #[error("Invalid NegoEx message type")]
    InvalidMessageType,
    /// ERR_NEGOEX_INVALID_MESSAGE_SIZE
    #[error("Invalid NegoEx message size")]
    InvalidMessageSize,
    /// ERR_NEGOEX_INVALID_CONVERSATION_ID
    #[error("Invalid NegoEx conversation ID")]
    InvalidConversationId,
    /// ERR_NEGOEX_MISSING_NEGO_MESSAGE
    #[error("Missing NegoEx negotiate message")]
    MissingNegoMessage,
    /// ERR_NEGOEX_MISSING_AP_REQUEST_MESSAGE
    #[error("Missing NegoEx authentication protocol request message")]
    MissingApRequestMessage,
    /// ERR_NEGOEX_NO_AVAILABLE_MECHS
    #[error("No mutually supported NegoEx authentication schemes")]
    NoAvailableMechs,
    /// ERR_NEGOEX_NO_VERIFY_KEY
    #[error("No NegoEx verify key")]
    NoVerifyKey,
    /// ERR_NEGOEX_UNKNOWN_CHECKSUM_SCHEME
    #[error("Unknown NegoEx checksum scheme")]
    UnknownChecksumScheme,
    /// ERR_NEGOEX_INVALID_CHECKSUM
    #[error("Invalid NegoEx checksum")]
    InvalidChecksum,
    /// ERR_NEGOEX_UNSUPPORTED_CRITICAL_EXTENSION
    #[error("Unsupported critical NegoEx extension")]
    UnsupportedCriticalExtension,
    /// ERR_NEGOEX_UNSUPPORTED_VERSION
    #[error("Unsupported NegoEx version")]
    UnsupportedVersion,
    /// ERR_NEGOEX_MESSAGE_OUT_OF_SEQUENCE
    #[error("NegoEx message out of sequence")]
    MessageOutOfSequence,
}

impl NegoexError {
    /// The GSS major status MIT returns with this minor code.
    pub fn major(self) -> GssError {
        use NegoexError::*;
        match self {
            NoAvailableMechs => GssError::Failure,
            NoVerifyKey
            | UnknownChecksumScheme
            | UnsupportedCriticalExtension
            | UnsupportedVersion => GssError::Unavailable,
            InvalidChecksum => GssError::BadSig,
            _ => GssError::DefectiveToken,
        }
    }
}

/// A NegoEx checksum key: contents and enctype (`buffer_set_to_key`).
#[derive(Clone, PartialEq, Eq)]
pub struct NegoexKey {
    /// Kerberos enctype.
    pub etype: i32,
    /// Key contents.
    pub key: Vec<u8>,
}

impl std::fmt::Debug for NegoexKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NegoexKey")
            .field("etype", &self.etype)
            .finish_non_exhaustive()
    }
}

/// One step of a mechanism's context exchange.
#[derive(Debug, Clone, Default)]
pub struct MechOutput {
    /// Output token; empty for none.
    pub token: Vec<u8>,
    /// GSS_S_COMPLETE rather than GSS_S_CONTINUE_NEEDED.
    pub complete: bool,
}

/// An acceptor failure, with the error token MIT still sends.
#[derive(Debug)]
pub struct MechFailure {
    /// The failure.
    pub error: Krb5Error,
    /// Error token for the initiator; empty for none.
    pub token: Vec<u8>,
}

/// A NegoEx-negotiable mechanism, one context per instance.
pub trait NegoexMech: Send {
    /// `gssspi_query_mechanism_info`: the auth scheme GUID.
    fn auth_scheme(&self) -> AuthScheme;
    /// `gssspi_query_meta_data`; empty for none. An error removes the
    /// mechanism from the negotiation.
    fn query_meta_data(&mut self, initiator: bool) -> Result<Vec<u8>, Krb5Error>;
    /// `gssspi_exchange_meta_data` with the peer's metadata. An error
    /// removes the mechanism from the negotiation.
    fn exchange_meta_data(&mut self, initiator: bool, meta_data: &[u8]) -> Result<(), Krb5Error>;
    /// `gss_init_sec_context`.
    fn init_sec_context(&mut self, input: Option<&[u8]>) -> Result<MechOutput, Krb5Error>;
    /// `gss_accept_sec_context`.
    fn accept_sec_context(&mut self, input: &[u8]) -> Result<MechOutput, MechFailure>;
    /// `gss_delete_sec_context`: discard the context so the next call
    /// starts a new one.
    fn delete_sec_context(&mut self);
    /// `GSS_C_INQ_NEGOEX_KEY`.
    fn key(&self) -> Option<NegoexKey>;
    /// `GSS_C_INQ_NEGOEX_VERIFY_KEY`.
    fn verify_key(&self) -> Option<NegoexKey>;
}

/// `struct negoex_auth_mech` (gssapiP_negoex.h:115-139).
struct AuthMech {
    mech: Box<dyn NegoexMech>,
    scheme: AuthScheme,
    metadata: Vec<u8>,
    key: Option<NegoexKey>,
    verify_key: Option<NegoexKey>,
    has_context: bool,
    complete: bool,
    sent_checksum: bool,
    verified_checksum: bool,
}

impl AuthMech {
    /// `get_session_keys` (negoex_ctx.c:98-125).
    fn get_session_keys(&mut self) {
        if let Some(k) = self.mech.key() {
            self.key = Some(k);
        }
        if let Some(k) = self.mech.verify_key() {
            self.verify_key = Some(k);
        }
    }

    fn restart(&mut self) {
        self.mech.delete_sec_context();
        self.has_context = false;
        self.key = None;
        self.verify_key = None;
        self.complete = false;
        self.sent_checksum = false;
    }
}

#[derive(Debug)]
enum Body {
    Nego {
        schemes: Vec<AuthScheme>,
    },
    Exchange {
        scheme: AuthScheme,
        token: Vec<u8>,
    },
    Verify {
        scheme: AuthScheme,
        cksum_type: i32,
        cksum: Vec<u8>,
        offset_in_token: usize,
    },
    Alert {
        scheme: AuthScheme,
        verify_no_key: bool,
    },
}

#[derive(Debug)]
struct Message {
    ty: MessageType,
    body: Body,
}

/// One NegoEx step: the token to send and whether the context is
/// established.
#[derive(Debug, Clone)]
pub struct NegoexStep {
    /// Output token; empty for none.
    pub token: Vec<u8>,
    /// GSS_S_COMPLETE rather than GSS_S_CONTINUE_NEEDED.
    pub complete: bool,
}

/// The NegoEx fields of MIT's SPNEGO context and `negoex_init` /
/// `negoex_accept`.
pub struct Negoex {
    initiator: bool,
    mechs: Vec<AuthMech>,
    step: u32,
    seqnum: u32,
    conv_id: AuthScheme,
    transcript: Vec<u8>,
    optimistic: bool,
    trace: Vec<String>,
}

fn err(e: NegoexError) -> Krb5Error {
    Krb5Error::Negoex(e)
}

/// `guid_to_string` (negoex_util.c:153-164).
pub fn guid_to_string(g: &AuthScheme) -> String {
    format!(
        "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        u32::from_le_bytes([g[0], g[1], g[2], g[3]]),
        u16::from_le_bytes([g[4], g[5]]),
        u16::from_le_bytes([g[6], g[7]]),
        g[8],
        g[9],
        g[10],
        g[11],
        g[12],
        g[13],
        g[14],
        g[15]
    )
}

/// `k5input`: reads past the end set an error and return zeros.
struct Input<'a> {
    data: &'a [u8],
    failed: bool,
}

impl<'a> Input<'a> {
    fn new(data: &'a [u8]) -> Self {
        Input {
            data,
            failed: false,
        }
    }

    fn bytes(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.failed || self.data.len() < n {
            self.failed = true;
            return None;
        }
        let (h, t) = self.data.split_at(n);
        self.data = t;
        Some(h)
    }

    fn guid(&mut self) -> AuthScheme {
        let mut g = [0; GUID_LENGTH];
        if let Some(b) = self.bytes(GUID_LENGTH) {
            g.copy_from_slice(b);
        }
        g
    }

    fn u16(&mut self) -> u16 {
        self.bytes(2)
            .map_or(0, |b| u16::from_le_bytes([b[0], b[1]]))
    }

    fn u32(&mut self) -> u32 {
        self.bytes(4)
            .map_or(0, |b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn u64(&mut self) -> u64 {
        self.bytes(8).map_or(0, |b| {
            let mut a = [0; 8];
            a.copy_from_slice(b);
            u64::from_le_bytes(a)
        })
    }
}

/// `vector_base` (negoex_util.c:166-175).
fn vector_base(offset: usize, count: usize, width: usize, msg: &[u8]) -> Option<&[u8]> {
    if offset > msg.len() || count > (msg.len() - offset) / width {
        return None;
    }
    Some(&msg[offset..offset + count * width])
}

impl Negoex {
    /// A NegoEx context over `mechs` in preference order
    /// (`get_negotiable_mechs`, spnego_mech.c:3158-3240).
    pub fn new(initiator: bool, mechs: Vec<Box<dyn NegoexMech>>) -> Self {
        let mechs = mechs
            .into_iter()
            .map(|mech| AuthMech {
                scheme: mech.auth_scheme(),
                mech,
                metadata: Vec::new(),
                key: None,
                verify_key: None,
                has_context: false,
                complete: false,
                sent_checksum: false,
                verified_checksum: false,
            })
            .collect();
        Negoex {
            initiator,
            mechs,
            step: 0,
            seqnum: 0,
            conv_id: [0; GUID_LENGTH],
            transcript: Vec::new(),
            optimistic: std::env::var_os("NEGOEX_NO_OPTIMISTIC_TOKEN").is_none(),
            trace: Vec::new(),
        }
    }

    /// Send no optimistic token, as MIT does with
    /// `NEGOEX_NO_OPTIMISTIC_TOKEN` set.
    pub fn without_optimistic_token(mut self) -> Self {
        self.optimistic = false;
        self
    }

    /// The selected mechanism once negotiation has narrowed to one.
    pub fn mech(&self) -> Option<&dyn NegoexMech> {
        self.mechs.first().map(|m| m.mech.as_ref())
    }

    /// The selected mechanism, consuming the context.
    pub fn into_mech(self) -> Option<Box<dyn NegoexMech>> {
        self.mechs.into_iter().next().map(|m| m.mech)
    }

    /// Trace lines (MIT's `TRACE_NEGOEX_INCOMING`/`OUTGOING` text without
    /// the "NegoEx " prefix) since the last call.
    pub fn take_trace(&mut self) -> Vec<String> {
        std::mem::take(&mut self.trace)
    }

    fn log(&mut self, dir: &str, seq: u32, ty: MessageType, info: String) {
        crate::k5trace!("NegoEx {} [{}]{}: {}", dir, seq, ty.name(), info);
        self.trace
            .push(format!("{dir} [{seq}]{}: {info}", ty.name()));
    }

    fn locate(&self, scheme: &AuthScheme) -> Option<usize> {
        self.mechs.iter().position(|m| &m.scheme == scheme)
    }

    fn select(&mut self, i: usize) {
        let m = self.mechs.swap_remove(i);
        self.mechs.clear();
        self.mechs.push(m);
    }

    /// `parse_message` (negoex_util.c:377-451).
    fn parse_message(&mut self, token: &[u8], pos: usize) -> Result<(Message, usize), Krb5Error> {
        let rest = &token[pos..];
        let mut inp = Input::new(rest);
        let signature = inp.u64();
        let ty = inp.u32();
        let seqnum = inp.u32();
        let header_len = inp.u32() as usize;
        let msg_len = inp.u32() as usize;
        let conv_id = inp.guid();
        if inp.failed
            || msg_len > rest.len()
            || header_len > msg_len
            || header_len < MESSAGE_HEADER_LENGTH
        {
            return Err(err(NegoexError::InvalidMessageSize));
        }
        if signature != MESSAGE_SIGNATURE {
            return Err(err(NegoexError::InvalidMessageSignature));
        }
        if seqnum != self.seqnum {
            return Err(err(NegoexError::MessageOutOfSequence));
        }
        if seqnum == 0 {
            self.conv_id = conv_id;
        } else if conv_id != self.conv_id {
            return Err(err(NegoexError::InvalidConversationId));
        }
        let msg = &rest[..msg_len];
        let mut h = Input::new(&rest[MESSAGE_HEADER_LENGTH..header_len]);
        let ty = MessageType::from_u32(ty).ok_or(err(NegoexError::InvalidMessageType))?;
        let body = match ty {
            MessageType::InitiatorNego | MessageType::AcceptorNego => {
                let _random = h.bytes(32);
                if h.u64() != 0 {
                    return Err(err(NegoexError::UnsupportedVersion));
                }
                let off = h.u32() as usize;
                let count = h.u16() as usize;
                let schemes = vector_base(off, count, GUID_LENGTH, msg)
                    .ok_or(err(NegoexError::InvalidMessageSize))?
                    .chunks_exact(GUID_LENGTH)
                    .map(|c| {
                        let mut g = [0; GUID_LENGTH];
                        g.copy_from_slice(c);
                        g
                    })
                    .collect();
                let off = h.u32() as usize;
                let count = h.u16() as usize;
                let exts = vector_base(off, count, EXTENSION_LENGTH, msg)
                    .ok_or(err(NegoexError::InvalidMessageSize))?;
                for e in exts.chunks_exact(EXTENSION_LENGTH) {
                    let t = u32::from_le_bytes([e[0], e[1], e[2], e[3]]);
                    if t & EXTENSION_FLAG_CRITICAL != 0 {
                        return Err(err(NegoexError::UnsupportedCriticalExtension));
                    }
                }
                Body::Nego { schemes }
            }
            MessageType::InitiatorMetaData
            | MessageType::AcceptorMetaData
            | MessageType::Challenge
            | MessageType::ApRequest => {
                let scheme = h.guid();
                let off = h.u32() as usize;
                let len = h.u32() as usize;
                let token = vector_base(off, len, 1, msg)
                    .ok_or(err(NegoexError::InvalidMessageSize))?
                    .to_vec();
                Body::Exchange { scheme, token }
            }
            MessageType::Verify => {
                let scheme = h.guid();
                if h.u32() != CHECKSUM_HEADER_LENGTH {
                    return Err(err(NegoexError::InvalidMessageSize));
                }
                if h.u32() != CHECKSUM_SCHEME_RFC3961 {
                    return Err(err(NegoexError::UnknownChecksumScheme));
                }
                let cksum_type = h.u32() as i32;
                let off = h.u32() as usize;
                let len = h.u32() as usize;
                let cksum = vector_base(off, len, 1, msg)
                    .ok_or(err(NegoexError::InvalidMessageSize))?
                    .to_vec();
                Body::Verify {
                    scheme,
                    cksum_type,
                    cksum,
                    offset_in_token: pos,
                }
            }
            MessageType::Alert => {
                let scheme = h.guid();
                let _error_code = h.u32();
                let off = h.u32() as usize;
                let nalerts = h.u32() as usize;
                let alerts = vector_base(off, nalerts, ALERT_LENGTH as usize, msg)
                    .ok_or(err(NegoexError::InvalidMessageSize))?;
                let mut verify_no_key = false;
                let mut a = Input::new(alerts);
                for _ in 0..nalerts {
                    let atype = a.u32();
                    let voff = a.u32() as usize;
                    let vlen = a.u32() as usize;
                    let v = vector_base(voff, vlen, 1, msg)
                        .ok_or(err(NegoexError::InvalidMessageSize))?;
                    if atype == ALERT_TYPE_PULSE && vlen >= ALERT_PULSE_LENGTH as usize {
                        let mut p = Input::new(v);
                        let _len = p.u32();
                        if p.u32() == ALERT_VERIFY_NO_KEY {
                            verify_no_key = true;
                        }
                    }
                }
                Body::Alert {
                    scheme,
                    verify_no_key,
                }
            }
        };
        if h.failed {
            return Err(err(NegoexError::InvalidMessageSize));
        }
        let info = match &body {
            Body::Nego { schemes } => schemes
                .iter()
                .map(guid_to_string)
                .collect::<Vec<_>>()
                .join(" "),
            Body::Exchange { scheme, .. }
            | Body::Verify { scheme, .. }
            | Body::Alert { scheme, .. } => guid_to_string(scheme),
        };
        self.log("received", seqnum, ty, info);
        self.seqnum += 1;
        Ok((Message { ty, body }, pos + msg_len))
    }

    /// `negoex_parse_token` (negoex_util.c:453-496).
    fn parse_token(&mut self, token: &[u8]) -> Result<Vec<Message>, Krb5Error> {
        let mut out = Vec::new();
        let mut pos = 0;
        while pos < token.len() {
            let (m, next) = self.parse_message(token, pos)?;
            out.push(m);
            pos = next;
        }
        Ok(out)
    }

    /// `put_message_header` (negoex_util.c:553-579).
    fn put_header(&mut self, ty: MessageType, payload_len: u32) -> u32 {
        let header_len = ty.header_len();
        let t = &mut self.transcript;
        t.extend_from_slice(&MESSAGE_SIGNATURE.to_le_bytes());
        t.extend_from_slice(&(ty as u32).to_le_bytes());
        t.extend_from_slice(&self.seqnum.to_le_bytes());
        t.extend_from_slice(&header_len.to_le_bytes());
        t.extend_from_slice(&(header_len + payload_len).to_le_bytes());
        t.extend_from_slice(&self.conv_id);
        self.seqnum += 1;
        header_len
    }

    /// `negoex_add_nego_message` (negoex_util.c:581-621).
    fn add_nego_message(&mut self, ty: MessageType) {
        let seq = self.seqnum;
        let random = crate::crypto::util::generate_random(32);
        let schemes: Vec<AuthScheme> = self.mechs.iter().map(|m| m.scheme).collect();
        let start = self.put_header(ty, (schemes.len() * GUID_LENGTH) as u32);
        let t = &mut self.transcript;
        t.extend_from_slice(&random);
        t.extend_from_slice(&0u64.to_le_bytes());
        t.extend_from_slice(&start.to_le_bytes());
        t.extend_from_slice(&(schemes.len() as u16).to_le_bytes());
        t.extend_from_slice(&start.to_le_bytes());
        t.extend_from_slice(&0u16.to_le_bytes());
        t.extend_from_slice(&[0; 4]);
        for s in &schemes {
            t.extend_from_slice(s);
        }
        let info = schemes
            .iter()
            .map(guid_to_string)
            .collect::<Vec<_>>()
            .join(" ");
        self.log("sending", seq, ty, info);
    }

    /// `negoex_add_exchange_message` (negoex_util.c:623-638).
    fn add_exchange_message(&mut self, ty: MessageType, scheme: AuthScheme, token: &[u8]) {
        let seq = self.seqnum;
        let start = self.put_header(ty, token.len() as u32);
        let t = &mut self.transcript;
        t.extend_from_slice(&scheme);
        t.extend_from_slice(&start.to_le_bytes());
        t.extend_from_slice(&(token.len() as u32).to_le_bytes());
        t.extend_from_slice(token);
        self.log("sending", seq, ty, guid_to_string(&scheme));
    }

    /// `negoex_add_verify_message` (negoex_util.c:640-663).
    fn add_verify_message(&mut self, scheme: AuthScheme, cksum_type: i32, cksum: &[u8]) {
        let seq = self.seqnum;
        let start = self.put_header(MessageType::Verify, cksum.len() as u32);
        let t = &mut self.transcript;
        t.extend_from_slice(&scheme);
        t.extend_from_slice(&CHECKSUM_HEADER_LENGTH.to_le_bytes());
        t.extend_from_slice(&CHECKSUM_SCHEME_RFC3961.to_le_bytes());
        t.extend_from_slice(&(cksum_type as u32).to_le_bytes());
        t.extend_from_slice(&start.to_le_bytes());
        t.extend_from_slice(&(cksum.len() as u32).to_le_bytes());
        t.extend_from_slice(&[0; 4]);
        t.extend_from_slice(cksum);
        self.log("sending", seq, MessageType::Verify, guid_to_string(&scheme));
    }

    /// `negoex_add_verify_no_key_alert` (negoex_util.c:665-691).
    fn add_verify_no_key_alert(&mut self, scheme: AuthScheme) {
        let seq = self.seqnum;
        let start = self.put_header(MessageType::Alert, ALERT_LENGTH + ALERT_PULSE_LENGTH);
        let t = &mut self.transcript;
        t.extend_from_slice(&scheme);
        t.extend_from_slice(&0u32.to_le_bytes());
        t.extend_from_slice(&start.to_le_bytes());
        t.extend_from_slice(&1u16.to_le_bytes());
        t.extend_from_slice(&[0; 6]);
        t.extend_from_slice(&ALERT_TYPE_PULSE.to_le_bytes());
        t.extend_from_slice(&(start + ALERT_LENGTH).to_le_bytes());
        t.extend_from_slice(&ALERT_PULSE_LENGTH.to_le_bytes());
        t.extend_from_slice(&ALERT_PULSE_LENGTH.to_le_bytes());
        t.extend_from_slice(&ALERT_VERIFY_NO_KEY.to_le_bytes());
        self.log("sending", seq, MessageType::Alert, guid_to_string(&scheme));
    }

    fn find(msgs: &[Message], ty: MessageType) -> Option<&Message> {
        msgs.iter().find(|m| m.ty == ty)
    }

    fn exchange_token(msgs: &[Message], ty: MessageType) -> Option<(AuthScheme, &[u8])> {
        match Self::find(msgs, ty).map(|m| &m.body) {
            Some(Body::Exchange { scheme, token }) => Some((*scheme, token)),
            _ => None,
        }
    }

    fn nego_schemes(msgs: &[Message], ty: MessageType) -> Result<Vec<AuthScheme>, Krb5Error> {
        match Self::find(msgs, ty).map(|m| &m.body) {
            Some(Body::Nego { schemes }) => Ok(schemes.clone()),
            _ => Err(err(NegoexError::MissingNegoMessage)),
        }
    }

    /// `query_meta_data` (negoex_ctx.c:191-206).
    fn query_meta_data(&mut self) {
        let initiator = self.initiator;
        self.mechs
            .retain_mut(|m| match m.mech.query_meta_data(initiator) {
                Ok(md) => {
                    m.metadata = md;
                    true
                }
                Err(_) => false,
            });
    }

    /// `exchange_meta_data` (negoex_ctx.c:207-242).
    fn exchange_meta_data(&mut self, msgs: &[Message]) {
        let ty = if self.initiator {
            MessageType::AcceptorMetaData
        } else {
            MessageType::InitiatorMetaData
        };
        for m in msgs.iter().filter(|m| m.ty == ty) {
            let Body::Exchange { scheme, token } = &m.body else {
                continue;
            };
            let Some(i) = self.locate(scheme) else {
                continue;
            };
            if self.mechs[i]
                .mech
                .exchange_meta_data(self.initiator, token)
                .is_err()
            {
                self.mechs.remove(i);
            }
        }
    }

    /// `check_optimistic_result` (negoex_ctx.c:243-274).
    fn check_optimistic_result(&mut self, msgs: &[Message]) {
        let Some(mech) = self.mechs.first_mut() else {
            return;
        };
        if !mech.has_context {
            return;
        }
        if Self::find(msgs, MessageType::Challenge).is_some()
            || Self::find(msgs, MessageType::Verify).is_some()
        {
            self.select(0);
        } else {
            mech.restart();
        }
    }

    /// `process_alerts` (negoex_ctx.c:519-536).
    fn process_alerts(&mut self, msgs: &[Message]) {
        if let Some(Body::Alert {
            scheme,
            verify_no_key: true,
        }) = Self::find(msgs, MessageType::Alert).map(|m| &m.body)
        {
            if let Some(i) = self.locate(scheme) {
                let m = &mut self.mechs[i];
                m.sent_checksum = false;
                m.key = None;
                m.verify_key = None;
            }
        }
    }

    /// `mech_init` (negoex_ctx.c:275-350).
    fn mech_init(&mut self, msgs: &[Message]) -> Result<Vec<u8>, Krb5Error> {
        if self.step == 1 && !self.optimistic {
            return Ok(Vec::new());
        }
        let Some(first) = self.mechs.first() else {
            return Err(err(NegoexError::NoAvailableMechs));
        };
        let mut input = Self::exchange_token(msgs, MessageType::Challenge)
            .filter(|(s, _)| *s == first.scheme)
            .map(|(_, t)| t.to_vec());
        if first.complete {
            return Ok(Vec::new());
        }
        let mut first_err = None;
        while let Some(mech) = self.mechs.first_mut() {
            match mech.mech.init_sec_context(input.as_deref()) {
                Ok(out) => {
                    mech.has_context = true;
                    if out.complete {
                        mech.complete = true;
                    }
                    mech.get_session_keys();
                    return Ok(out.token);
                }
                Err(e) => {
                    first_err.get_or_insert(e);
                    self.mechs.remove(0);
                    input = None;
                }
            }
        }
        Err(first_err.unwrap_or(err(NegoexError::NoAvailableMechs)))
    }

    /// `mech_accept` (negoex_ctx.c:351-419).
    fn mech_accept(&mut self, msgs: &[Message]) -> (Result<(), Krb5Error>, Vec<u8>) {
        let Some((scheme, token)) = Self::exchange_token(msgs, MessageType::ApRequest) else {
            if self.step == 1 || self.mechs[0].complete {
                return (Ok(()), Vec::new());
            }
            return (Err(err(NegoexError::MissingApRequestMessage)), Vec::new());
        };
        if self.step == 1 {
            if scheme != self.mechs[0].scheme {
                return (Ok(()), Vec::new());
            }
        } else {
            let Some(i) = self.locate(&scheme) else {
                return (Err(err(NegoexError::NoAvailableMechs)), Vec::new());
            };
            self.select(i);
        }
        let step = self.step;
        let mech = &mut self.mechs[0];
        if mech.complete {
            return (Ok(()), Vec::new());
        }
        match mech.mech.accept_sec_context(token) {
            Ok(out) => {
                mech.has_context = true;
                if out.complete {
                    mech.complete = true;
                }
                mech.get_session_keys();
                (Ok(()), out.token)
            }
            Err(_) if step == 1 => {
                mech.restart();
                (Ok(()), Vec::new())
            }
            Err(f) => {
                mech.has_context = true;
                (Err(f.error), f.token)
            }
        }
    }

    /// `verify_keyusage` (negoex_ctx.c:420-427); the spec has the names
    /// the wrong way around.
    fn keyusage(&self, make: bool) -> i32 {
        if self.initiator ^ !make {
            KEYUSAGE_ACCEPTOR_CHECKSUM
        } else {
            KEYUSAGE_INITIATOR_CHECKSUM
        }
    }

    /// `verify_checksum` (negoex_ctx.c:428-481); true to send a
    /// VERIFY_NO_KEY alert.
    fn verify_checksum(&mut self, msgs: &[Message], input: &[u8]) -> Result<bool, Krb5Error> {
        let usage = self.keyusage(false);
        let mech = &self.mechs[0];
        let Some(Body::Verify {
            scheme,
            cksum_type,
            cksum,
            offset_in_token,
        }) = Self::find(msgs, MessageType::Verify).map(|m| &m.body)
        else {
            return Ok(false);
        };
        if *scheme != mech.scheme {
            return Ok(false);
        }
        let Some(key) = &mech.verify_key else {
            return Ok(true);
        };
        let profile = find_cksumtype(*cksum_type).map_err(|e| Krb5Error::Crypto(e.to_string()))?;
        let mut data = self.transcript.clone();
        data.extend_from_slice(&input[..*offset_in_token]);
        if profile
            .verify_checksum(&key.key, usage, &data, cksum)
            .is_err()
        {
            return Err(err(NegoexError::InvalidChecksum));
        }
        self.mechs[0].verified_checksum = true;
        Ok(false)
    }

    /// `make_checksum` (negoex_ctx.c:482-517).
    fn make_checksum(&mut self) -> Result<(), Krb5Error> {
        let usage = self.keyusage(true);
        let mech = &self.mechs[0];
        let Some(key) = &mech.key else {
            if mech.complete {
                return Err(err(NegoexError::NoVerifyKey));
            }
            return Ok(());
        };
        let profile = find_etype(key.etype).map_err(|e| Krb5Error::Crypto(e.to_string()))?;
        let sum = profile
            .checksum(&key.key, usage, &self.transcript)
            .map_err(|e| Krb5Error::Crypto(e.to_string()))?;
        let scheme = mech.scheme;
        self.add_verify_message(scheme, profile.checksum_type(), &sum);
        self.mechs[0].sent_checksum = true;
        Ok(())
    }

    /// `make_output_token` (negoex_ctx.c:537-609).
    fn make_output_token(&mut self, mech_out: &[u8], alert: bool) -> Result<Vec<u8>, Krb5Error> {
        let old = self.transcript.len();
        if mech_out.is_empty() && self.mechs[0].sent_checksum {
            return Ok(Vec::new());
        }
        if self.step == 1 {
            let (nego, meta) = if self.initiator {
                (MessageType::InitiatorNego, MessageType::InitiatorMetaData)
            } else {
                (MessageType::AcceptorNego, MessageType::AcceptorMetaData)
            };
            self.add_nego_message(nego);
            let md: Vec<(AuthScheme, Vec<u8>)> = self
                .mechs
                .iter()
                .filter(|m| !m.metadata.is_empty())
                .map(|m| (m.scheme, m.metadata.clone()))
                .collect();
            for (s, d) in md {
                self.add_exchange_message(meta, s, &d);
            }
        }
        let scheme = self.mechs[0].scheme;
        if !mech_out.is_empty() {
            let ty = if self.initiator {
                MessageType::ApRequest
            } else {
                MessageType::Challenge
            };
            self.add_exchange_message(ty, scheme, mech_out);
        }
        if alert {
            self.add_verify_no_key_alert(scheme);
        }
        if !self.mechs[0].sent_checksum {
            self.make_checksum()?;
        }
        Ok(self.transcript[old..].to_vec())
    }

    fn done(&self) -> bool {
        self.mechs[0].complete && self.mechs[0].verified_checksum
    }

    /// `negoex_init` (negoex_ctx.c:610-703).
    pub fn init(&mut self, input: Option<&[u8]>) -> Result<NegoexStep, Krb5Error> {
        let input = input.filter(|t| !t.is_empty());
        if !self.initiator || (self.step == 0 && input.is_some()) {
            return Err(Krb5Error::Gss(GssError::DefectiveToken));
        }
        self.step += 1;
        let msgs = match input {
            Some(t) => self.parse_token(t)?,
            None => Vec::new(),
        };
        self.process_alerts(&msgs);
        if self.step == 1 {
            self.conv_id
                .copy_from_slice(&crate::crypto::util::generate_random(GUID_LENGTH));
            self.query_meta_data();
        } else if self.step == 2 {
            self.check_optimistic_result(&msgs);
            self.exchange_meta_data(&msgs);
            let schemes = Self::nego_schemes(&msgs, MessageType::AcceptorNego)?;
            // negoex_common_auth_schemes: the acceptor's order.
            let mut list = Vec::new();
            for s in &schemes {
                if let Some(i) = self.locate(s) {
                    list.push(self.mechs.remove(i));
                }
            }
            self.mechs = list;
        }
        let out = self.mech_init(&msgs)?;
        if self.mechs.is_empty() {
            return Err(err(NegoexError::NoAvailableMechs));
        }
        if self.step == 2 {
            self.select(0);
        }
        let alert = self.verify_checksum(&msgs, input.unwrap_or_default())?;
        if let Some(t) = input {
            self.transcript.extend_from_slice(t);
        }
        let token = self.make_output_token(&out, alert)?;
        Ok(NegoexStep {
            token,
            complete: self.done(),
        })
    }

    /// `negoex_accept` (negoex_ctx.c:704-788).
    pub fn accept(&mut self, input: &[u8]) -> Result<NegoexStep, Krb5Error> {
        if self.initiator || input.is_empty() {
            return Err(Krb5Error::Gss(GssError::DefectiveToken));
        }
        self.step += 1;
        let msgs = self.parse_token(input)?;
        self.process_alerts(&msgs);
        if self.step == 1 {
            // negoex_restrict_auth_schemes: our order.
            let schemes = Self::nego_schemes(&msgs, MessageType::InitiatorNego)?;
            self.mechs.retain(|m| schemes.contains(&m.scheme));
            self.exchange_meta_data(&msgs);
            self.query_meta_data();
            if self.mechs.is_empty() {
                return Err(err(NegoexError::NoAvailableMechs));
            }
        }
        let (res, out) = self.mech_accept(&msgs);
        let mut alert = false;
        match res {
            Err(e) if out.is_empty() => return Err(e),
            Err(_) => {}
            Ok(()) => alert = self.verify_checksum(&msgs, input)?,
        }
        self.transcript.extend_from_slice(input);
        let token = self.make_output_token(&out, alert)?;
        Ok(NegoexStep {
            token,
            complete: self.done(),
        })
    }
}

#[cfg(test)]
#[path = "negoex_tests.rs"]
mod tests;
