//! GSS-API (RFC 2743) support, with the RFC 4121 Kerberos 5 mechanism.

pub mod krb5;
pub mod seqstate;
pub mod spnego;
pub mod token;

use thiserror::Error;

/// GSS major-status-equivalent errors, modeled on MIT's GSS_S_* codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum GssError {
    /// Malformed or incorrectly framed token (GSS_S_DEFECTIVE_TOKEN).
    #[error("defective token")]
    DefectiveToken,
    /// Signature/decryption verification failed (GSS_S_BAD_SIG).
    #[error("bad signature")]
    BadSig,
    /// Channel bindings mismatch (GSS_S_BAD_BINDINGS).
    #[error("channel bindings mismatch")]
    BadBindings,
    /// No usable credential (GSS_S_NO_CRED).
    #[error("no credential")]
    NoCred,
    /// Context has expired (GSS_S_CONTEXT_EXPIRED).
    #[error("context expired")]
    ContextExpired,
    /// General failure (GSS_S_FAILURE).
    #[error("general failure")]
    Failure,
    /// Unsupported mechanism (GSS_S_BAD_MECH).
    #[error("unsupported mechanism")]
    BadMech,
    /// No context established (GSS_S_NO_CONTEXT).
    #[error("no context")]
    NoContext,
    /// Credential unusable (GSS_S_DEFECTIVE_CREDENTIAL).
    #[error("defective credential")]
    DefectiveCredential,
    /// Credentials expired (GSS_S_CREDENTIALS_EXPIRED).
    #[error("credentials expired")]
    CredentialsExpired,
    /// Malformed name (GSS_S_BAD_NAME).
    #[error("bad name")]
    BadName,
    /// Context already fully established.
    #[error("context already established")]
    ContextEstablished,
}

bitflags::bitflags! {
    /// GSS context flags (gssapi.h / gssapi_ext.h values).
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct GssFlags: u32 {
        /// Delegation (GSS_C_DELEG_FLAG).
        const DELEG = 0x1;
        /// Mutual authentication (GSS_C_MUTUAL_FLAG).
        const MUTUAL = 0x2;
        /// Replay detection (GSS_C_REPLAY_FLAG).
        const REPLAY = 0x4;
        /// Strict sequencing (GSS_C_SEQUENCE_FLAG).
        const SEQUENCE = 0x8;
        /// Confidentiality (GSS_C_CONF_FLAG).
        const CONF = 0x10;
        /// Integrity (GSS_C_INTEG_FLAG).
        const INTEG = 0x20;
        /// Anonymous initiator (GSS_C_ANON_FLAG).
        const ANON = 0x40;
        /// Per-message ops ready before establishment (GSS_C_PROT_READY_FLAG).
        const PROT_READY = 0x80;
        /// Mechanism is transferable (GSS_C_TRANS_FLAG).
        const TRANS = 0x100;
        /// Channel bindings verified (GSS_C_CHANNEL_BOUND_FLAG).
        const CHANNEL_BOUND = 0x800;
        /// DCE-style framing (GSS_C_DCE_STYLE).
        const DCE_STYLE = 0x1000;
        /// Identify-versus-delegation naming (GSS_C_IDENTIFY_FLAG).
        const IDENTIFY = 0x2000;
        /// Extended error info wanted (GSS_C_EXTENDED_ERROR_FLAG).
        const EXTENDED_ERROR = 0x4000;
        /// Delegate only with OK_AS_DELEGATE (GSS_C_DELEG_POLICY_FLAG).
        const DELEG_POLICY = 0x8000;
    }
}
