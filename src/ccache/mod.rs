//! Kerberos credential caches — MIT FILE (v1-4) and MEMORY formats.
//!
//! Wire layout follows ccmarshal.c / cc_file.c; retrieval follows
//! cc_retr.c; config entries follow ccfns.c.

mod file;
pub mod marshal;
mod memory;
mod retrieve;

use bitflags::bitflags;
use rasn::types::GeneralString;

use crate::protocol::{Credential, TicketTimes};
use crate::types::{
    AuthorizationDataElement, EncryptionKey, HostAddress, KerberosFlags, KerberosTime,
    PrincipalName, Ticket, TicketFlags,
};

pub use file::FileCcache;
pub use memory::MemoryCcache;
pub use retrieve::creds_match_request;

/// The realm used for ccache config entries (ccfns.c:212-228).
pub const CONFIG_REALM: &str = "X-CACHECONF:";
/// The realm a removed config entry is rewritten to (cc_file.c:1062).
pub const REMOVED_CONFIG_REALM: &str = "X-RMED-CONF:";
/// First component of every config entry server principal.
pub const CONFIG_PRINC: &str = "krb5_ccache_conf_data";

/// A credential as stored in a ccache (MIT `krb5_creds`).
#[derive(Debug, Clone)]
pub struct CcCredential {
    /// Client principal.
    pub client: PrincipalName,
    /// Client realm.
    pub crealm: String,
    /// Server principal.
    pub server: PrincipalName,
    /// Server realm.
    pub srealm: String,
    /// Session key (etype 0 + empty key = ENCTYPE_NULL).
    pub keyblock: EncryptionKey,
    /// Time of initial authentication (unix seconds).
    pub authtime: u32,
    /// Start of validity; 0 = none.
    pub starttime: u32,
    /// Expiration time.
    pub endtime: u32,
    /// Renew-till; 0 = none.
    pub renew_till: u32,
    /// Ticket is encrypted in the session key (user-to-user).
    pub is_skey: bool,
    /// MIT TKT_FLG_* value: big-endian u32 of the ASN.1 BIT STRING.
    pub ticket_flags: u32,
    /// Client addresses.
    pub addresses: Vec<HostAddress>,
    /// Authorization data.
    pub authdata: Vec<AuthorizationDataElement>,
    /// DER-encoded Ticket.
    pub ticket: Vec<u8>,
    /// Second ticket (user-to-user TGT).
    pub second_ticket: Vec<u8>,
}

impl From<&Credential> for CcCredential {
    fn from(c: &Credential) -> Self {
        let to_u32 = |t: KerberosTime| u32::try_from(t.timestamp()).unwrap_or(u32::MAX);
        let to_opt_u32 = |t: Option<KerberosTime>| t.map(to_u32).unwrap_or(0);
        Self {
            client: c.client.clone(),
            crealm: c.crealm.clone(),
            server: c.server.clone(),
            srealm: c.srealm.clone(),
            keyblock: c.session_key.clone(),
            authtime: to_u32(c.times.authtime),
            starttime: to_opt_u32(c.times.starttime),
            endtime: to_u32(c.times.endtime),
            renew_till: to_opt_u32(c.times.renew_till),
            is_skey: false,
            ticket_flags: c.flags.into_inner().bits(),
            addresses: c.addresses.clone().unwrap_or_default(),
            authdata: c.authdata.clone().unwrap_or_default(),
            ticket: rasn::der::encode(&c.ticket).unwrap_or_default(),
            second_ticket: Vec::new(),
        }
    }
}

impl TryFrom<&CcCredential> for Credential {
    type Error = CcError;

    fn try_from(c: &CcCredential) -> Result<Self, CcError> {
        let ticket: Ticket = rasn::der::decode(&c.ticket).map_err(|_| CcError::Format)?;
        let to_time = |u: u32| -> KerberosTime {
            chrono::DateTime::from_timestamp(i64::from(u), 0)
                .unwrap_or_default()
                .fixed_offset()
        };
        let opt_time = |u: u32| -> Option<KerberosTime> { (u != 0).then(|| to_time(u)) };
        Ok(Self {
            client: c.client.clone(),
            crealm: c.crealm.clone(),
            server: c.server.clone(),
            srealm: c.srealm.clone(),
            session_key: c.keyblock.clone(),
            times: TicketTimes {
                authtime: to_time(c.authtime),
                starttime: opt_time(c.starttime),
                endtime: to_time(c.endtime),
                renew_till: opt_time(c.renew_till),
            },
            ticket,
            flags: KerberosFlags::new(TicketFlags::from_bits_truncate(c.ticket_flags)),
            addresses: (!c.addresses.is_empty()).then(|| c.addresses.clone()),
            authdata: (!c.authdata.is_empty()).then(|| c.authdata.clone()),
        })
    }
}

/// Ccache errors (MIT KRB5_CC_*).
#[derive(Debug, thiserror::Error)]
pub enum CcError {
    /// Malformed data (KRB5_CC_FORMAT).
    #[error("ccache format error")]
    Format,
    /// Unknown file version (KRB5_CCACHE_BADVNO).
    #[error("bad ccache version")]
    BadVno,
    /// Iteration reached the end (KRB5_CC_END).
    #[error("end of ccache")]
    End,
    /// No matching credential (KRB5_CC_NOTFOUND).
    #[error("credential not found")]
    NotFound,
    /// Match found but with an unsupported enctype (KRB5_CC_NOT_KTYPE).
    #[error("no credential with a supported enctype")]
    NotKtype,
    /// I/O error.
    #[error("ccache I/O error: {0}")]
    Io(#[from] std::io::Error),
}

bitflags! {
    /// Match flags controlling credential retrieval (MIT KRB5_TC_*).
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    pub struct MatchFlags: u32 {
        /// Expiration must be no later than requested.
        const TIMES = 1;
        /// Match is_skey exactly.
        const IS_SKEY = 2;
        /// Requested flag bits must be set.
        const FLAGS = 4;
        /// All four times must match exactly.
        const TIMES_EXACT = 8;
        /// All flag bits must match exactly.
        const FLAGS_EXACT = 0x10;
        /// Authorization data must match.
        const AUTHDATA = 0x20;
        /// Server comparison ignores realm.
        const SRV_NAMEONLY = 0x40;
        /// Second ticket must match.
        const SECOND_TKT = 0x80;
        /// Session key enctype must match.
        const KTYPE = 0x100;
        /// Restrict to the given list of supported enctypes.
        const SUPPORTED_KTYPES = 0x200;
    }
}

/// A credential match request (MIT `mcreds`).
#[derive(Debug, Default)]
pub struct MatchCred {
    /// Client principal + realm (None = any).
    pub client: Option<(PrincipalName, String)>,
    /// Server principal + realm (None = any).
    pub server: Option<(PrincipalName, String)>,
    /// Required session key enctype (with KTYPE).
    pub etype: i32,
    /// Required authtime (TIMES_EXACT).
    pub authtime: u32,
    /// Required starttime (TIMES_EXACT).
    pub starttime: u32,
    /// Maximum endtime (TIMES) / exact endtime (TIMES_EXACT).
    pub endtime: u32,
    /// Maximum renew_till (TIMES) / exact renew_till (TIMES_EXACT).
    pub renew_till: u32,
    /// Required is_skey value (with IS_SKEY).
    pub is_skey: bool,
    /// Required ticket flags (FLAGS/FLAGS_EXACT).
    pub ticket_flags: u32,
    /// Required authdata (AUTHDATA); None = empty list.
    pub authdata: Option<Vec<AuthorizationDataElement>>,
    /// Required second ticket (SECOND_TKT); None = empty.
    pub second_ticket: Option<Vec<u8>>,
}

/// A credential cache (MIT `krb5_ccache` operations).
pub trait Ccache {
    /// Initialize the cache, discarding contents (writes header+principal).
    fn initialize(&mut self, client: &PrincipalName, realm: &str) -> Result<(), CcError>;

    /// The cache's default principal.
    fn principal(&self) -> Result<(PrincipalName, String), CcError>;

    /// Store a credential.
    fn store(&mut self, cred: &CcCredential) -> Result<(), CcError>;

    /// All credentials, skipping entries removed in place
    /// (endtime==0 && authtime!=0, cc_file.c:750-757).
    fn creds(&self) -> Result<Vec<CcCredential>, CcError>;

    /// Remove the first credential matching `m` under `flags`.
    fn remove_cred(&mut self, flags: MatchFlags, m: &MatchCred) -> Result<(), CcError>;

    /// Retrieve a credential (cc_retr.c:194-245). With `ktypes`, the
    /// earliest-listed supported enctype wins; a match with no listed
    /// enctype yields [`CcError::NotKtype`].
    fn retrieve(
        &self,
        flags: MatchFlags,
        m: &MatchCred,
        ktypes: Option<&[i32]>,
    ) -> Result<CcCredential, CcError>;

    /// Store a config value (ccfns.c:184-260). `data` of None removes the
    /// entry.
    fn set_config(
        &mut self,
        principal: Option<(&PrincipalName, &str)>,
        key: &str,
        data: Option<&[u8]>,
    ) -> Result<(), CcError>;

    /// Fetch a config value, or None if absent.
    fn get_config(
        &self,
        principal: Option<(&PrincipalName, &str)>,
        key: &str,
    ) -> Result<Option<Vec<u8>>, CcError>;
}

/// Whether `name`/`realm` names a ccache config entry (ccfns.c:212-228).
pub fn is_config_principal(name: &PrincipalName, realm: &str) -> bool {
    realm == CONFIG_REALM
        && name
            .name_string
            .first()
            .is_some_and(|c| c.as_bytes() == CONFIG_PRINC.as_bytes())
}

/// Build the server principal for a config entry
/// (krb5_ccache_conf_data/<key>[/<unparsed principal>]@X-CACHECONF:).
pub(crate) fn config_principal(
    principal: Option<(&PrincipalName, &str)>,
    key: &str,
) -> PrincipalName {
    let mut comps = vec![
        GeneralString::from_bytes(CONFIG_PRINC.as_bytes()).unwrap_or_default(),
        GeneralString::from_bytes(key.as_bytes()).unwrap_or_default(),
    ];
    if let Some((p, realm)) = principal {
        comps
            .push(GeneralString::from_bytes(unparse_name(p, realm).as_bytes()).unwrap_or_default());
    }
    PrincipalName {
        name_type: 0,
        name_string: comps,
    }
}

/// Unparse a principal (unparse.c): '/' in components and '@' in the
/// realm are separators; these plus '\\', tab, newline, backspace and
/// NUL are backslash-escaped.
pub fn unparse_name(name: &PrincipalName, realm: &str) -> String {
    fn escape(s: &[u8], out: &mut String) {
        for &b in s {
            match b {
                b'/' => out.push_str("\\/"),
                b'@' => out.push_str("\\@"),
                b'\\' => out.push_str("\\\\"),
                b'\t' => out.push_str("\\t"),
                b'\n' => out.push_str("\\n"),
                0x08 => out.push_str("\\b"),
                0 => out.push_str("\\0"),
                _ => out.push(b as char),
            }
        }
    }
    let mut out = String::new();
    let mut first = true;
    for c in &name.name_string {
        if !first {
            out.push('/');
        }
        first = false;
        escape(c.as_bytes(), &mut out);
    }
    out.push('@');
    escape(realm.as_bytes(), &mut out);
    out
}

/// Shared set_config/get_config implementation (ccfns.c).
pub(crate) fn config_cred(
    client: &PrincipalName,
    crealm: &str,
    principal: Option<(&PrincipalName, &str)>,
    key: &str,
    data: &[u8],
) -> CcCredential {
    CcCredential {
        client: client.clone(),
        crealm: crealm.to_string(),
        server: config_principal(principal, key),
        srealm: CONFIG_REALM.to_string(),
        keyblock: EncryptionKey::new(0, Vec::new()),
        authtime: 0,
        starttime: 0,
        endtime: 0,
        renew_till: 0,
        is_skey: false,
        ticket_flags: 0,
        addresses: Vec::new(),
        authdata: Vec::new(),
        ticket: data.to_vec(),
        second_ticket: Vec::new(),
    }
}

/// Whether a config credential matches key+principal (for get_config and
/// set_config's remove-old step).
pub(crate) fn config_matches(
    cred: &CcCredential,
    principal: Option<(&PrincipalName, &str)>,
    key: &str,
) -> bool {
    if !is_config_principal(&cred.server, &cred.srealm) {
        return false;
    }
    let comps = &cred.server.name_string;
    if comps.get(1).is_none_or(|c| c.as_bytes() != key.as_bytes()) {
        return false;
    }
    match principal {
        None => comps.len() == 2,
        Some((p, realm)) => {
            comps.len() == 3 && comps[2].as_bytes() == unparse_name(p, realm).as_bytes()
        }
    }
}
