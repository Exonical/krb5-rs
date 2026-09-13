//! AP exchange and KRB-SAFE/PRIV/CRED — MIT krb5 semantics.
//!
//! Modelled on MIT krb5 1.22.2: mk_req_ext.c, rd_req_dec.c, mk_rep.c,
//! rd_rep.c, mk_safe.c, rd_safe.c, privsafe.c, mk_priv.c, rd_priv.c,
//! mk_cred.c, rd_cred.c, gen_seqnum.c, valid_times.c, os/timeofday.c,
//! addr_srch.c, os/mk_faddr.c, rcache/rc_base.c.

mod cred;
mod req_rep;
mod safe_priv;

use std::collections::HashSet;
use std::time::Duration;

use bitflags::bitflags;
use chrono::{Timelike, Utc};
use rasn::types::{GeneralString, OctetString};

use crate::crypto::util::generate_random;
use crate::crypto::{find_cksumtype, find_etype, key_usage};
use crate::error::Krb5Error;
use crate::types::*;

use super::credential::Credential;

bitflags! {
    /// Auth-context flags (MIT `KRB5_AUTH_CONTEXT_*`, include/krb5/krb5.hin).
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct AuthContextFlags: u32 {
        /// Use timestamps / detect replays.
        const DO_TIME = 0x01;
        /// Return timestamps to the caller.
        const RET_TIME = 0x02;
        /// Use sequence numbers.
        const DO_SEQUENCE = 0x04;
        /// Return sequence numbers to the caller.
        const RET_SEQUENCE = 0x08;
        /// Permit any enctype during RFC 4537 negotiation.
        const PERMIT_ALL = 0x10;
        /// Generate a subkey in AP-REP (server side).
        const USE_SUBKEY = 0x20;
    }
}

/// AP-layer errors; names mirror MIT `KRB5KRB_AP_ERR_*` / `KRB5_*` codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ApError {
    /// Ticket/authenticator decrypt or integrity failure.
    #[error("decrypt integrity check failed")]
    BadIntegrity,
    /// Ticket expired.
    #[error("ticket expired")]
    TktExpired,
    /// Ticket not yet valid.
    #[error("ticket not yet valid")]
    TktNyv,
    /// Request is a replay.
    #[error("request is a replay")]
    Repeat,
    /// Ticket isn't for us.
    #[error("ticket is not for us")]
    NotUs,
    /// Clock skew too great.
    #[error("clock skew too great")]
    Skew,
    /// Client/server address mismatch.
    #[error("incorrect net address")]
    BadAddr,
    /// Bad protocol version.
    #[error("bad protocol version")]
    BadVersion,
    /// Bad message type.
    #[error("bad message type")]
    MsgType,
    /// Message stream modified.
    #[error("message stream modified")]
    Modified,
    /// Message out of order.
    #[error("message out of order")]
    BadOrder,
    /// Incorrect key version.
    #[error("incorrect kvno")]
    BadKeyver,
    /// No key available.
    #[error("no key available")]
    NoKey,
    /// Mutual authentication failed.
    #[error("mutual authentication failed")]
    MutualFailed,
    /// Client name mismatch.
    #[error("bad client name")]
    BadMatch,
    /// Ticket is invalid.
    #[error("ticket is invalid")]
    TktInvalid,
    /// Inappropriate checksum type.
    #[error("inappropriate checksum type")]
    InappCksum,
    /// Checksum type not supported.
    #[error("checksum type not supported")]
    SumTypeNoSupp,
    /// Illegal cross-realm ticket.
    #[error("illegal cross-realm ticket")]
    IllCrTkt,
    /// Enctype not permitted.
    #[error("enctype not permitted")]
    NoPermEtype,
    /// Local address required but not set.
    #[error("local address required")]
    LocalAddrRequired,
    /// No ticket supplied to mk_req.
    #[error("no ticket supplied")]
    NoTktSupplied,
}

/// Replay/timing data returned by mk_safe/mk_priv/mk_cred-style calls
/// when RET_TIME/RET_SEQUENCE are set (MIT `krb5_replay_data`).
#[derive(Debug, Clone, Default)]
pub struct ReplayData {
    /// Timestamp included in the message.
    pub timestamp: Option<KerberosTime>,
    /// Microseconds included in the message.
    pub usec: Option<i32>,
    /// Sequence number included in the message.
    pub seq: Option<u32>,
}

/// Source of long-term service keys (keytab abstraction).
///
/// Mirrors rd_req_dec.c:207-275: implementations should return
/// [`ApError::NoKey`] (no entry), [`ApError::BadKeyver`] (kvno mismatch),
/// or [`ApError::NotUs`] (principal not ours).
pub trait KeySource {
    /// Fetch the key for `server` in `realm` matching `kvno`/`etype`.
    fn get_key(
        &self,
        server: &PrincipalName,
        realm: &[u8],
        kvno: Option<i32>,
        etype: i32,
    ) -> Result<EncryptionKey, ApError>;
}

/// AP-REQ options (MIT `AP_OPTS_*`).
#[derive(Debug, Clone, Default)]
pub struct ApReqOptions {
    /// Request mutual authentication (AP_OPTS_MUTUAL_REQUIRED).
    pub mutual_required: bool,
    /// Use the session key for the ticket encryption (user-to-user).
    pub use_session_key: bool,
    /// Generate and send a subkey in the authenticator.
    pub use_subkey: bool,
    /// Send an RFC 4537 enctype-negotiation list.
    pub etype_negotiation: bool,
    /// Channel-bindings awareness (KERB_AP_OPTIONS_CBT authdata).
    pub cbt: bool,
}

/// Result of a successful rd_req (MIT `krb5_rd_req` outputs).
#[derive(Debug)]
pub struct RdReqResult {
    /// Decrypted ticket.
    pub ticket: EncTicketPart,
    /// AP options from the request (wire mask only).
    pub ap_options: KerberosFlags<ApOptions>,
    /// Decoded authenticator.
    pub authenticator: Authenticator,
}

/// ADDRTYPE_ADDRPORT — combined address+port (os/mk_faddr.c).
const ADDRTYPE_ADDRPORT: i32 = 0x0100;
/// ADDRTYPE_NETBIOS — a lone NetBIOS address list counts as empty
/// (addr_srch.c).
const ADDRTYPE_NETBIOS: i32 = 0x0014;

const AP_OPTS_WIRE: u32 = ApOptions::USE_SESSION_KEY.bits() | ApOptions::MUTUAL_REQUIRED.bits();

const DEFAULT_ETYPES: [i32; 4] = [18, 17, 20, 19];

/// Combine an address and port address into an ADDRTYPE_ADDRPORT
/// "full address" (os/mk_faddr.c:38-85 `krb5_make_fulladdr`).
fn make_fulladdr(addr: &HostAddress, port: &HostAddress) -> HostAddress {
    let mut contents = Vec::with_capacity(addr.address.len() + port.address.len() + 16);
    contents.extend_from_slice(&[0, 0]);
    contents.extend_from_slice(&(addr.addr_type as i16).to_le_bytes());
    contents.extend_from_slice(&(addr.address.len() as i32).to_le_bytes());
    contents.extend_from_slice(&addr.address);
    contents.extend_from_slice(&[0, 0]);
    contents.extend_from_slice(&(port.addr_type as i16).to_le_bytes());
    contents.extend_from_slice(&(port.address.len() as i32).to_le_bytes());
    contents.extend_from_slice(&port.address);
    HostAddress {
        addr_type: ADDRTYPE_ADDRPORT,
        address: OctetString::from(contents),
    }
}

fn address_compare(a: &HostAddress, b: &HostAddress) -> bool {
    a.addr_type == b.addr_type && a.address == b.address
}

/// MIT `krb5_address_search` (addr_srch.c): a NULL list matches anything;
/// a list containing only a NetBIOS address counts as empty.
fn address_search(addr: &HostAddress, list: Option<&[HostAddress]>) -> bool {
    match list {
        None => true,
        Some(l) if l.len() == 1 && l[0].addr_type == ADDRTYPE_NETBIOS => true,
        Some(l) => l.iter().any(|a| address_compare(addr, a)),
    }
}

/// Decrypt a ticket's enc-part with `key` (MIT `krb5_decrypt_tkt_part`,
/// key usage 2).
pub fn decrypt_ticket(key: &EncryptionKey, ticket: &Ticket) -> Result<EncTicketPart, Krb5Error> {
    let profile =
        find_etype(ticket.enc_part.etype).map_err(|_| Krb5Error::Ap(ApError::BadIntegrity))?;
    let plain = profile
        .decrypt(key.key_bytes(), key_usage::TICKET, &ticket.enc_part.cipher)
        .map_err(|_| Krb5Error::Ap(ApError::BadIntegrity))?;
    Ok(rasn::der::decode::<EncTicketPart>(&plain)?)
}

/// Build a Ticket from an EncTicketPart (test/keytab-side helper; the
/// mirror of [`decrypt_ticket`], key usage 2).
pub fn encrypt_ticket_part(
    key: &EncryptionKey,
    kvno: Option<i32>,
    realm: &str,
    sname: PrincipalName,
    part: &EncTicketPart,
) -> Result<Ticket, Krb5Error> {
    let plain = rasn::der::encode(part)?;
    let profile = find_etype(key.keytype).map_err(|e| Krb5Error::Crypto(e.to_string()))?;
    let cipher = profile
        .encrypt(key.key_bytes(), key_usage::TICKET, &plain)
        .map_err(|e| Krb5Error::Crypto(e.to_string()))?;
    Ok(Ticket {
        tkt_vno: 5,
        realm: GeneralString::from_bytes(realm.as_bytes())
            .map_err(|_| Krb5Error::ReplyValidation("invalid realm"))?,
        sname,
        enc_part: EncryptedData {
            etype: key.keytype,
            kvno,
            cipher: OctetString::from(cipher),
        },
    })
}

/// Authentication context — MIT `krb5_auth_context`.
pub struct AuthContext {
    flags: AuthContextFlags,
    clockskew: Duration,
    time_offset: chrono::Duration,
    local_addr: Option<HostAddress>,
    remote_addr: Option<HostAddress>,
    local_port: Option<HostAddress>,
    remote_port: Option<HostAddress>,
    permitted_etypes: Option<Vec<i32>>,
    req_cksumtype: i32,
    key: Option<EncryptionKey>,
    /// User-to-user ticket-decryption key; consumed by one rd_req
    /// (rd_req_dec.c:494-504 frees it after use).
    tkt_key: Option<EncryptionKey>,
    send_subkey: Option<EncryptionKey>,
    recv_subkey: Option<EncryptionKey>,
    local_seq: u32,
    remote_seq: u32,
    negotiated_etype: i32,
    authentp: Option<Authenticator>,
    rcache: HashSet<Vec<u8>>,
    conn_sane_seq: bool,
    conn_heimdal_seq: bool,
}

impl Default for AuthContext {
    fn default() -> Self {
        Self::new()
    }
}

impl AuthContext {
    /// MIT `krb5_auth_con_init`: flags = DO_TIME, clockskew 300s.
    pub fn new() -> Self {
        Self {
            flags: AuthContextFlags::DO_TIME,
            clockskew: Duration::from_secs(300),
            time_offset: chrono::Duration::zero(),
            local_addr: None,
            remote_addr: None,
            local_port: None,
            remote_port: None,
            permitted_etypes: None,
            req_cksumtype: 0,
            key: None,
            tkt_key: None,
            send_subkey: None,
            recv_subkey: None,
            local_seq: 0,
            remote_seq: 0,
            negotiated_etype: 0,
            authentp: None,
            rcache: HashSet::new(),
            conn_sane_seq: false,
            conn_heimdal_seq: false,
        }
    }

    /// Set the auth-context flags.
    pub fn set_flags(&mut self, f: AuthContextFlags) {
        self.flags = f;
    }

    /// Current auth-context flags.
    pub fn flags(&self) -> AuthContextFlags {
        self.flags
    }

    /// Set local/remote addresses used in SAFE/PRIV/CRED and rd_req checks.
    pub fn set_addrs(&mut self, local: Option<HostAddress>, remote: Option<HostAddress>) {
        self.local_addr = local;
        self.remote_addr = remote;
    }

    /// Set local/remote ports; when set, address comparisons and generated
    /// addresses use combined fulladdr form (privsafe.c:70-105).
    pub fn set_ports(&mut self, local: Option<HostAddress>, remote: Option<HostAddress>) {
        self.local_port = local;
        self.remote_port = remote;
    }

    /// Set the permitted enctypes for RFC 4537 negotiation; `None`
    /// restores the default list.
    pub fn set_permitted_etypes(&mut self, e: Option<Vec<i32>>) {
        self.permitted_etypes = e;
    }

    /// Set the accepted clock skew (default 300 s).
    pub fn set_clockskew(&mut self, d: Duration) {
        self.clockskew = d;
    }

    /// Set a time offset added to every clock read (MIT os_ctx time_offset).
    pub fn set_time_offset(&mut self, d: chrono::Duration) {
        self.time_offset = d;
    }

    /// Set the checksum type for authenticator checksums; `0x8003` stores
    /// the raw `in_data` bytes (GSS-API path, mk_req_ext.c:165-169);
    /// `0` uses the etype's mandatory checksum.
    pub fn set_req_cksumtype(&mut self, t: i32) {
        self.req_cksumtype = t;
    }

    /// Pre-set the context key (user-to-user rd_req path,
    /// rd_req_dec.c:494-505). The key also decrypts the ticket on the next
    /// rd_req; it is consumed by that call, mirroring MIT.
    pub fn set_session_key(&mut self, k: EncryptionKey) {
        self.tkt_key = Some(k.clone());
        self.key = Some(k);
    }

    /// Set the local (outgoing) sequence number.
    pub fn set_local_seq_number(&mut self, n: u32) {
        self.local_seq = n;
    }

    /// Set the remote (incoming) sequence number.
    pub fn set_remote_seq_number(&mut self, n: u32) {
        self.remote_seq = n;
    }

    /// The context protocol/session key.
    pub fn session_key(&self) -> Option<&EncryptionKey> {
        self.key.as_ref()
    }

    /// Subkey for outgoing messages.
    pub fn send_subkey(&self) -> Option<&EncryptionKey> {
        self.send_subkey.as_ref()
    }

    /// Subkey for incoming messages.
    pub fn recv_subkey(&self) -> Option<&EncryptionKey> {
        self.recv_subkey.as_ref()
    }

    /// Current local sequence number.
    pub fn local_seq_number(&self) -> u32 {
        self.local_seq
    }

    /// Current remote sequence number.
    pub fn remote_seq_number(&self) -> u32 {
        self.remote_seq
    }

    /// Enctype negotiated via RFC 4537 (0 = none).
    pub fn negotiated_etype(&self) -> i32 {
        self.negotiated_etype
    }

    /// The last stored authenticator.
    pub fn authenticator(&self) -> Option<&Authenticator> {
        self.authentp.as_ref()
    }

    fn now(&self) -> (KerberosTime, i32) {
        let t = Utc::now() + self.time_offset;
        let usec = t.timestamp_subsec_micros() as i32;
        let whole = t.with_nanosecond(0).unwrap_or(t);
        (whole.fixed_offset(), usec)
    }

    /// `krb5int_validate_times` (valid_times.c:36-57).
    fn validate_times(
        &self,
        authtime: KerberosTime,
        starttime: Option<KerberosTime>,
        endtime: KerberosTime,
    ) -> Result<(), ApError> {
        let skew = chrono::Duration::from_std(self.clockskew).map_err(|_| ApError::BadVersion)?;
        let now = Utc::now() + self.time_offset;
        let start = starttime.unwrap_or(authtime).with_timezone(&Utc);
        let end = endtime.with_timezone(&Utc);
        if start > now + skew {
            return Err(ApError::TktNyv);
        }
        if now > end + skew {
            return Err(ApError::TktExpired);
        }
        Ok(())
    }

    /// `krb5_check_clockskew` (os/timeofday.c:55-67).
    fn check_clockskew(&self, date: KerberosTime) -> Result<(), ApError> {
        let now = Utc::now() + self.time_offset;
        let skew = chrono::Duration::from_std(self.clockskew).map_err(|_| ApError::Skew)?;
        let d = date.with_timezone(&Utc);
        if d < now - skew || d > now + skew {
            return Err(ApError::Skew);
        }
        Ok(())
    }

    /// `krb5_generate_seq_number` (gen_seqnum.c): random, masked to
    /// 0x3fffffff, never 0.
    fn gen_seq_number(&mut self) {
        let mut n = u32::from_be_bytes(generate_random(4).try_into().expect("4 bytes"));
        n &= 0x3fffffff;
        if n == 0 {
            n = 1;
        }
        self.local_seq = n;
    }

    /// `k5_generate_and_save_subkey` (gen_save_subkey.c): random key of the
    /// given etype, stored as BOTH send and recv subkey.
    fn generate_and_save_subkey(&mut self, etype: i32) -> Result<(), Krb5Error> {
        let profile = find_etype(etype).map_err(|e| Krb5Error::Crypto(e.to_string()))?;
        let rnd = generate_random(profile.key_bytes());
        let kb = profile
            .random_to_key(&rnd)
            .map_err(|e| Krb5Error::Crypto(e.to_string()))?;
        let key = EncryptionKey::new(etype, kb.to_vec());
        self.send_subkey = Some(key.clone());
        self.recv_subkey = Some(key);
        Ok(())
    }

    /// Comparison addresses with ports folded in (privsafe.c:70-105
    /// `k5_privsafe_gen_addrs` / k5_privsafe_check_addrs).
    fn effective_local_addr(&self) -> Option<HostAddress> {
        match (&self.local_addr, &self.local_port) {
            (Some(a), Some(p)) => Some(make_fulladdr(a, p)),
            (a, _) => a.clone(),
        }
    }

    fn effective_remote_addr(&self) -> Option<HostAddress> {
        match (&self.remote_addr, &self.remote_port) {
            (Some(a), Some(p)) => Some(make_fulladdr(a, p)),
            (a, _) => a.clone(),
        }
    }

    /// `k5_privsafe_check_addrs` (privsafe.c:311-382).
    ///
    /// Deviation: when our local address is unset and the message carries a
    /// receiver address, MIT compares against the OS local address list;
    /// we cannot enumerate interfaces here, so we accept (documented).
    fn check_addrs(
        &self,
        msg_s_addr: Option<&HostAddress>,
        msg_r_addr: Option<&HostAddress>,
    ) -> Result<(), ApError> {
        if let Some(remote) = self.effective_remote_addr() {
            match msg_s_addr {
                Some(s) if address_compare(&remote, s) => {}
                _ => return Err(ApError::BadAddr),
            }
        }
        if let Some(r) = msg_r_addr {
            if let Some(local) = self.effective_local_addr() {
                if !address_compare(&local, r) {
                    return Err(ApError::BadAddr);
                }
            }
        }
        Ok(())
    }

    /// Replay-cache check (privsafe.c:107-141 `k5_privsafe_check_replay`
    /// plus the rd_req path rd_req_dec.c:620-625). Tag semantics follow
    /// rc_base.c:147-163 `k5_rc_tag_from_ciphertext` / the checksum tag.
    fn check_replay(
        &mut self,
        rdata_time: Option<KerberosTime>,
        tag: Vec<u8>,
    ) -> Result<(), ApError> {
        if !self.flags.contains(AuthContextFlags::DO_TIME) {
            return Ok(());
        }
        if let Some(t) = rdata_time {
            self.check_clockskew(t)?;
        }
        if !self.rcache.insert(tag) {
            return Err(ApError::Repeat);
        }
        Ok(())
    }

    /// `k5_privsafe_check_seqnum` (privsafe.c:206-304), including the
    /// Heimdal-counter heuristics.
    fn check_seqnum(&mut self, in_seq: u32) -> bool {
        let exp_seq = self.remote_seq;
        if self.conn_sane_seq {
            return in_seq == exp_seq;
        }
        if (in_seq & 0xFF800000) == 0xFF800000 {
            if (exp_seq & 0xFF800000) == 0xFF800000 && in_seq == exp_seq {
                return true;
            }
            if !self.conn_heimdal_seq && in_seq == exp_seq {
                return true;
            }
            if chk_heimdal_seqnum(exp_seq, in_seq) {
                self.conn_heimdal_seq = true;
                return true;
            }
            return false;
        }
        if in_seq == exp_seq {
            if (exp_seq & 0xFFFFFF80) == 0x00000080
                || (exp_seq & 0xFFFF8000) == 0x00008000
                || (exp_seq & 0xFF800000) == 0x00800000
            {
                self.conn_sane_seq = true;
            }
            return true;
        }
        if exp_seq == 0 && !self.conn_heimdal_seq {
            match in_seq {
                0x100 | 0x10000 | 0x1000000 => {
                    self.conn_heimdal_seq = true;
                    self.remote_seq = in_seq;
                    return true;
                }
                _ => return false,
            }
        }
        false
    }

    /// privsafe.c:37-68 `k5_privsafe_gen_rdata`.
    fn gen_rdata(&self) -> (Option<KerberosTime>, Option<i32>, Option<u32>) {
        let f = self.flags;
        let (ts, usec) = if f.intersects(AuthContextFlags::DO_TIME | AuthContextFlags::RET_TIME) {
            let (t, u) = self.now();
            (Some(t), Some(u))
        } else {
            (None, None)
        };
        let seq = if f.intersects(AuthContextFlags::DO_SEQUENCE | AuthContextFlags::RET_SEQUENCE) {
            Some(self.local_seq)
        } else {
            None
        };
        (ts, usec, seq)
    }

    fn ret_rdata(
        &self,
        ts: Option<KerberosTime>,
        usec: Option<i32>,
        seq: Option<u32>,
    ) -> ReplayData {
        let f = self.flags;
        ReplayData {
            timestamp: if f.contains(AuthContextFlags::RET_TIME) {
                ts
            } else {
                None
            },
            usec: if f.contains(AuthContextFlags::RET_TIME) {
                usec
            } else {
                None
            },
            seq: if f.contains(AuthContextFlags::RET_SEQUENCE) {
                seq
            } else {
                None
            },
        }
    }
}

/// privsafe.c:206-223 `chk_heimdal_seqnum`.
fn chk_heimdal_seqnum(exp_seq: u32, in_seq: u32) -> bool {
    ((exp_seq & 0xFF800000) == 0x00800000
        && (in_seq & 0xFF800000) == 0xFF800000
        && (in_seq & 0x00FFFFFF) == exp_seq)
        || ((exp_seq & 0xFFFF8000) == 0x00008000
            && (in_seq & 0xFFFF8000) == 0xFFFF8000
            && (in_seq & 0x0000FFFF) == exp_seq)
        || ((exp_seq & 0xFFFFFF80) == 0x00000080
            && (in_seq & 0xFFFFFF80) == 0xFFFFFF80
            && (in_seq & 0x000000FF) == exp_seq)
}

/// Extract the RFC 4537 etype list from authenticator authdata
/// (rd_req_dec.c:906-960 `decode_etype_list`): AD-IF_RELEVANT(1) is
/// unwrapped; a bare KRB5_AUTHDATA_ETYPE_NEGOTIATION(129) element is
/// also accepted.
fn decode_etype_list(auth: &Authenticator) -> Vec<i32> {
    let Some(ad) = &auth.authorization_data else {
        return Vec::new();
    };
    for el in ad {
        match el.ad_type {
            1 => {
                if let Ok(inner) = rasn::der::decode::<Vec<AuthorizationDataElement>>(&el.ad_data) {
                    for e in inner {
                        if e.ad_type == 129 {
                            if let Ok(list) = rasn::der::decode::<Vec<i32>>(&e.ad_data) {
                                return list;
                            }
                        }
                    }
                }
            }
            129 => {
                if let Ok(list) = rasn::der::decode::<Vec<i32>>(&el.ad_data) {
                    return list;
                }
            }
            _ => {}
        }
    }
    Vec::new()
}

/// `negotiate_etype` (rd_req_dec.c:855-904): the mandatory segment
/// (from `mandatory_index` on — subkey and session etypes) must each be
/// permitted, then `permitted` is iterated in preference order and the
/// first permitted etype present anywhere in `desired` is negotiated.
///
/// `permitted == None` means PERMIT_ALL. MIT's own PERMIT_ALL path always
/// returns KRB5_NOPERM_ETYPE because the empty permitted list fails the
/// mandatory check (no MIT client relies on it), so we diverge there:
/// first desired wins, no mandatory check.
fn negotiate_etype(
    desired: &[i32],
    mandatory_index: usize,
    permitted: Option<&[i32]>,
) -> Result<i32, ApError> {
    let Some(permitted) = permitted else {
        return desired.first().copied().ok_or(ApError::NoPermEtype);
    };
    for e in &desired[mandatory_index.min(desired.len())..] {
        if !permitted.contains(e) {
            return Err(ApError::NoPermEtype);
        }
    }
    for p in permitted {
        if desired.contains(p) {
            return Ok(*p);
        }
    }
    Err(ApError::NoPermEtype)
}

/// mk_req_ext.c:332-405 `make_ap_authdata` + `make_etype_list`: build the
/// AD-IF-RELEVANT element holding ETYPE_NEGOTIATION(129) and/or
/// AP_OPTIONS(143) entries.
fn make_ap_authdata(
    desired: Option<&[i32]>,
    tkt_etype: i32,
    cbt: bool,
) -> Result<Option<AuthorizationDataElement>, Krb5Error> {
    let mut inner: Vec<AuthorizationDataElement> = Vec::new();
    if let Some(desired) = desired {
        if desired.first() != Some(&tkt_etype) {
            let mut count = desired.len();
            for (i, _) in desired.iter().enumerate() {
                if i > 0 && desired[i - 1] == tkt_etype {
                    count = i;
                    break;
                }
            }
            let list: Vec<i32> = desired[..count].to_vec();
            inner.push(AuthorizationDataElement {
                ad_type: 129,
                ad_data: OctetString::from(rasn::der::encode(&list)?),
            });
        }
    }
    if cbt {
        inner.push(AuthorizationDataElement {
            ad_type: 143,
            ad_data: OctetString::from(0x4000u32.to_le_bytes().to_vec()),
        });
    }
    if inner.is_empty() {
        return Ok(None);
    }
    Ok(Some(AuthorizationDataElement {
        ad_type: 1,
        ad_data: OctetString::from(rasn::der::encode(&inner)?),
    }))
}

fn now_kerberos() -> KerberosTime {
    let t = Utc::now();
    t.with_nanosecond(0).unwrap_or(t).fixed_offset()
}
