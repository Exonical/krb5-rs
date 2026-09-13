//! RFC 4121 (CFX) GSS-API Kerberos 5 mechanism.
//!
//! Modelled on MIT krb5 1.22.2: lib/gssapi/krb5/init_sec_context.c,
//! accept_sec_context.c, k5sealv3.c, k5sealv3iov.c, util_cksum.c,
//! util_crypt.c, wrap_size_limit.c.  Only CFX (proto 1) tokens are
//! produced and accepted; all registered enctypes are "newer" enctypes
//! per util_crypt.c:123-125 `kg_setup_keys`.

use std::time::Duration;

use crate::crypto::util::generate_random;
use crate::crypto::{find_cksumtype, find_etype};
use crate::error::Krb5Error;
use crate::protocol::ap::{ApReqOptions, AuthContext, AuthContextFlags, KeySource};
use crate::protocol::Credential;
use crate::types::*;

use super::seqstate::{SeqState, SeqStatus};
use super::token::{make_token_header, parse_token_header};
use super::GssError;
pub use super::GssFlags;

/// DER encoding of the krb5 mechanism OID 1.2.840.113554.1.2.2.
pub const MECH_KRB5: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02];

const TOK_AP_REQ: u16 = 0x0100;
const TOK_AP_REP: u16 = 0x0200;
const TOK_CTX_ERROR: u16 = 0x0300;
const TOK_MIC: u16 = 0x0404;
const TOK_WRAP: u16 = 0x0504;

const FLAG_SENDER_IS_ACCEPTOR: u8 = 0x01;
const FLAG_WRAP_CONFIDENTIAL: u8 = 0x02;
const FLAG_ACCEPTOR_SUBKEY: u8 = 0x04;

/// GSS key usages (gssapiP_krb5.h:144-147).
const USAGE_ACCEPTOR_SEAL: i32 = 22;
const USAGE_ACCEPTOR_SIGN: i32 = 23;
const USAGE_INITIATOR_SEAL: i32 = 24;
const USAGE_INITIATOR_SIGN: i32 = 25;

/// CKSUMTYPE_GSS_CBINDINGS (accept_sec_context.c).
const CKSUM_GSS_CBINDINGS: i32 = 0x8003;
/// KRB5_GSS_FOR_CREDS_OPTION.
const KRB5_GSS_FOR_CREDS_OPTION: u16 = 1;
/// KERB_AP_OPTIONS_CBT (MS-KILE), stored little-endian in authdata.
const AP_OPTIONS_CBT: u32 = 0x4000;
const AD_AP_OPTIONS: i32 = 143;

/// Channel bindings (gss_channel_bindings_struct).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelBindings {
    /// Initiator address family.
    pub initiator_addrtype: u32,
    /// Initiator address bytes.
    pub initiator_address: Vec<u8>,
    /// Acceptor address family.
    pub acceptor_addrtype: u32,
    /// Acceptor address bytes.
    pub acceptor_address: Vec<u8>,
    /// Application-supplied data.
    pub application_data: Vec<u8>,
}

/// util_cksum.c:31-80 `kg_checksum_channel_bindings` — plain MD5 over the
/// little-endian serialization.
fn cb_checksum(cb: &ChannelBindings) -> [u8; 16] {
    use md5::Digest;
    let mut input = Vec::new();
    input.extend_from_slice(&cb.initiator_addrtype.to_le_bytes());
    input.extend_from_slice(&(cb.initiator_address.len() as u32).to_le_bytes());
    input.extend_from_slice(&cb.initiator_address);
    input.extend_from_slice(&cb.acceptor_addrtype.to_le_bytes());
    input.extend_from_slice(&(cb.acceptor_address.len() as u32).to_le_bytes());
    input.extend_from_slice(&cb.acceptor_address);
    input.extend_from_slice(&(cb.application_data.len() as u32).to_le_bytes());
    input.extend_from_slice(&cb.application_data);
    md5::Md5::digest(&input).into()
}

fn gss(e: GssError) -> Krb5Error {
    Krb5Error::Gss(e)
}

/// Result of an initiator step.
#[derive(Debug)]
pub enum InitStep {
    /// Send this token and wait for the peer's reply.
    Continue(Vec<u8>),
    /// Context established; the inner token (if any) still needs sending.
    /// `Complete(Some)` is reserved for DCE-style third-leg output, which is
    /// not implemented, so normal completion is always `Complete(None)` —
    /// except that a *non-mutual* first step completes with its AP-REQ token.
    Complete(Option<Vec<u8>>),
}

/// Result of an acceptor step.
#[derive(Debug)]
pub enum AcceptStep {
    /// Context established; `token` carries the AP-REP when mutual.
    Complete {
        /// Token to send to the initiator (AP-REP), if any.
        token: Option<Vec<u8>>,
    },
    /// Send this token and wait for more input (unused without DCE style).
    ContinueNeeded(Vec<u8>),
}

mod acceptor;
mod context;
mod initiator;

pub use acceptor::Krb5Acceptor;
pub use context::{Krb5Context, Unwrapped};
pub use initiator::Krb5Initiator;
