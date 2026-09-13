//! AP exchange and KRB-SAFE/PRIV/CRED — MIT krb5 semantics.
//!
//! Modelled on MIT krb5 1.22.2: mk_req_ext.c, rd_req_dec.c, mk_rep.c,
//! rd_rep.c, mk_safe.c, rd_safe.c, privsafe.c, mk_priv.c, rd_priv.c,
//! mk_cred.c, rd_cred.c, gen_seqnum.c, valid_times.c, os/timeofday.c,
//! addr_srch.c, os/mk_faddr.c, rcache/rc_base.c.

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

    /// Build an AP-REQ (mk_req_ext.c:104-254).
    pub fn mk_req(
        &mut self,
        opts: &ApReqOptions,
        in_data: Option<&[u8]>,
        cred: &Credential,
    ) -> Result<Vec<u8>, Krb5Error> {
        if cred.ticket.enc_part.cipher.is_empty() {
            return Err(ApError::NoTktSupplied.into());
        }
        if opts.etype_negotiation && !opts.mutual_required {
            return Err(Krb5Error::ReplyValidation(
                "etype negotiation requires mutual auth",
            ));
        }
        self.validate_times(
            cred.times.authtime,
            cred.times.starttime,
            cred.times.endtime,
        )?;

        self.key = Some(cred.session_key.clone());
        let session = cred.session_key.clone();
        let session_profile =
            find_etype(session.keytype).map_err(|e| Krb5Error::Crypto(e.to_string()))?;

        if self
            .flags
            .intersects(AuthContextFlags::DO_SEQUENCE | AuthContextFlags::RET_SEQUENCE)
            && self.local_seq == 0
        {
            self.gen_seq_number();
        }

        if opts.use_subkey && self.send_subkey.is_none() {
            self.generate_and_save_subkey(session.keytype)?;
        }

        let cksum = if let Some(data) = in_data {
            if self.req_cksumtype == 0x8003 {
                Some(Checksum {
                    cksumtype: 0x8003,
                    checksum: OctetString::from(data.to_vec()),
                })
            } else {
                Some(Checksum {
                    cksumtype: session_profile.checksum_type(),
                    checksum: OctetString::from(
                        session_profile
                            .checksum(session.key_bytes(), key_usage::AP_REQ_AUTH_CKSUM, data)
                            .map_err(|e| Krb5Error::Crypto(e.to_string()))?,
                    ),
                })
            }
        } else {
            None
        };

        let desired: Option<Vec<i32>> = if opts.etype_negotiation {
            Some(
                self.permitted_etypes
                    .clone()
                    .unwrap_or_else(|| DEFAULT_ETYPES.to_vec()),
            )
        } else {
            None
        };

        let (ctime, cusec) = self.now();
        let mut authdata: Vec<AuthorizationDataElement> = Vec::new();
        if let Some(inner) = make_ap_authdata(desired.as_deref(), session.keytype, opts.cbt)? {
            authdata.push(inner);
        }
        if let Some(cred_ad) = &cred.authdata {
            authdata.extend(cred_ad.iter().cloned());
        }

        let auth = Authenticator {
            authenticator_vno: 5,
            crealm: GeneralString::from_bytes(cred.crealm.as_bytes())
                .map_err(|_| Krb5Error::ReplyValidation("invalid crealm"))?,
            cname: cred.client.clone(),
            cksum,
            cusec,
            ctime,
            subkey: self.send_subkey.clone(),
            // MIT asn1_k_encode.c omits seq-number when zero.
            seq_number: if self.local_seq != 0 {
                Some(self.local_seq)
            } else {
                None
            },
            authorization_data: if authdata.is_empty() {
                None
            } else {
                Some(authdata)
            },
        };
        let auth_der = rasn::der::encode(&auth)?;
        let cipher = session_profile
            .encrypt(session.key_bytes(), key_usage::AP_REQ_AUTH, &auth_der)
            .map_err(|e| Krb5Error::Crypto(e.to_string()))?;

        let mut ap_options = ApOptions::empty();
        if opts.mutual_required {
            ap_options |= ApOptions::MUTUAL_REQUIRED;
        }
        if opts.use_session_key {
            ap_options |= ApOptions::USE_SESSION_KEY;
        }

        let req = ApReq {
            pvno: 5,
            msg_type: 14,
            ap_options: KerberosFlags::new(ap_options),
            ticket: cred.ticket.clone(),
            authenticator: EncryptedData {
                etype: session.keytype,
                kvno: None,
                cipher: OctetString::from(cipher),
            },
        };
        self.authentp = Some(auth);
        Ok(rasn::der::encode(&req)?)
    }

    /// Read and verify an AP-REQ (rd_req_dec.c:472-787).
    pub fn rd_req(
        &mut self,
        ap_req: &[u8],
        server: Option<&PrincipalName>,
        keys: &dyn KeySource,
    ) -> Result<RdReqResult, Krb5Error> {
        // krb5_is_ap_req: first byte must be APPLICATION 14 (0x6E).
        if ap_req.first() != Some(&0x6E) {
            return Err(ApError::MsgType.into());
        }
        let req: ApReq = rasn::der::decode(ap_req)?;
        if req.msg_type != 14 {
            return Err(ApError::MsgType.into());
        }
        if req.pvno != 5 {
            return Err(ApError::BadVersion.into());
        }

        let enc_part = if let Some(key) = self.tkt_key.take() {
            decrypt_ticket(&key, &req.ticket)?
        } else {
            let sname = server.unwrap_or(&req.ticket.sname);
            let key = keys.get_key(
                sname,
                req.ticket.realm.as_bytes(),
                req.ticket.enc_part.kvno,
                req.ticket.enc_part.etype,
            )?;
            decrypt_ticket(&key, &req.ticket)?
        };

        let session = enc_part.key.clone();
        let session_profile =
            find_etype(session.keytype).map_err(|e| Krb5Error::Crypto(e.to_string()))?;

        let plain = session_profile
            .decrypt(
                session.key_bytes(),
                key_usage::AP_REQ_AUTH,
                &req.authenticator.cipher,
            )
            .map_err(|_| Krb5Error::Ap(ApError::BadIntegrity))?;
        let auth: Authenticator =
            rasn::der::decode(&plain).map_err(|_| Krb5Error::Ap(ApError::BadIntegrity))?;

        // rd_req_dec.c:530-534 — principal compare incl. realm.
        if auth.cname.name_string != enc_part.cname.name_string || auth.crealm != enc_part.crealm {
            return Err(ApError::BadMatch.into());
        }

        if let Some(remote) = self.effective_remote_addr() {
            if !address_search(&remote, enc_part.caddr.as_deref()) {
                return Err(ApError::BadAddr.into());
            }
        }

        // Hierarchical cross-realm check, rd_req_dec.c:606-610.
        // Deviation: MIT calls krb5_check_transited_list (capaths); with no
        // capaths support any non-empty unchecked transited list is rejected.
        if !enc_part
            .flags
            .contains(TicketFlags::TRANSITED_POLICY_CHECKED)
            && !enc_part.transited.contents.is_empty()
        {
            return Err(ApError::IllCrTkt.into());
        }

        if self.flags.contains(AuthContextFlags::DO_TIME) {
            // rc_base.c:147-163: tag = trailing checksum-length bytes of the
            // authenticator ciphertext.
            let tag_len = session_profile
                .checksum(session.key_bytes(), 0, &[])
                .map_err(|e| Krb5Error::Crypto(e.to_string()))?
                .len();
            let cipher = &req.authenticator.cipher;
            if cipher.len() < tag_len {
                return Err(ApError::BadIntegrity.into());
            }
            let tag = cipher[cipher.len() - tag_len..].to_vec();
            if !self.rcache.insert(tag) {
                return Err(ApError::Repeat.into());
            }
        }

        self.validate_times(enc_part.authtime, enc_part.starttime, enc_part.endtime)?;
        self.check_clockskew(auth.ctime)?;

        if enc_part.flags.contains(TicketFlags::INVALID) {
            return Err(ApError::TktInvalid.into());
        }

        // RFC 4537, rd_req_dec.c:652-727.
        let rfc4537 = decode_etype_list(&auth);
        let mandatory_index = rfc4537.len();
        let mut desired = rfc4537;
        if let Some(sub) = &auth.subkey {
            desired.push(sub.keytype);
        }
        desired.push(session.keytype);

        let permitted: Option<Vec<i32>> = if self.flags.contains(AuthContextFlags::PERMIT_ALL) {
            None
        } else {
            Some(
                self.permitted_etypes
                    .clone()
                    .unwrap_or_else(|| DEFAULT_ETYPES.to_vec()),
            )
        };
        self.negotiated_etype = negotiate_etype(&desired, mandatory_index, permitted.as_deref())?;

        self.remote_seq = auth.seq_number.unwrap_or(0);
        if let Some(sub) = &auth.subkey {
            self.recv_subkey = Some(sub.clone());
            self.send_subkey = Some(sub.clone());
        } else {
            self.recv_subkey = None;
            self.send_subkey = None;
        }
        self.key = Some(session);

        // rd_req_dec.c:757-761 — without mutual auth, local_seq becomes the
        // complement of the remote seq number.
        if !req.ap_options.contains(ApOptions::MUTUAL_REQUIRED) && self.remote_seq != 0 {
            self.local_seq ^= self.remote_seq;
        }

        self.authentp = Some(auth);
        Ok(RdReqResult {
            ticket: enc_part,
            ap_options: KerberosFlags::new(ApOptions::from_bits_truncate(
                req.ap_options.bits() & AP_OPTS_WIRE,
            )),
            authenticator: self.authentp.clone().expect("just stored"),
        })
    }

    /// Build an AP-REP (mk_rep.c:67-140 `k5_mk_rep`, non-DCE).
    pub fn mk_rep(&mut self) -> Result<Vec<u8>, Krb5Error> {
        let auth = self
            .authentp
            .clone()
            .ok_or(Krb5Error::ReplyValidation("no authenticator"))?;
        let key = self
            .key
            .clone()
            .ok_or(Krb5Error::ReplyValidation("no key"))?;

        if self
            .flags
            .intersects(AuthContextFlags::DO_SEQUENCE | AuthContextFlags::RET_SEQUENCE)
            && self.local_seq == 0
        {
            self.gen_seq_number();
        }

        let subkey = if self.flags.contains(AuthContextFlags::USE_SUBKEY) {
            if self.negotiated_etype == 0 {
                return Err(Krb5Error::ReplyValidation("no negotiated etype"));
            }
            self.generate_and_save_subkey(self.negotiated_etype)?;
            self.send_subkey.clone()
        } else {
            auth.subkey.clone()
        };

        let enc = EncApRepPart {
            ctime: auth.ctime,
            cusec: auth.cusec,
            subkey,
            seq_number: if self.local_seq != 0 {
                Some(self.local_seq)
            } else {
                None
            },
        };
        let der = rasn::der::encode(&enc)?;
        let profile = find_etype(key.keytype).map_err(|e| Krb5Error::Crypto(e.to_string()))?;
        let cipher = profile
            .encrypt(key.key_bytes(), key_usage::AP_REP_ENCPART, &der)
            .map_err(|e| Krb5Error::Crypto(e.to_string()))?;
        let rep = ApRep {
            pvno: 5,
            msg_type: 15,
            enc_part: EncryptedData {
                etype: key.keytype,
                kvno: None,
                cipher: OctetString::from(cipher),
            },
        };
        Ok(rasn::der::encode(&rep)?)
    }

    /// Read and verify an AP-REP (rd_rep.c:68-145).
    pub fn rd_rep(&mut self, ap_rep: &[u8]) -> Result<EncApRepPart, Krb5Error> {
        // krb5_is_ap_rep: first byte APPLICATION 15 (0x6F).
        if ap_rep.first() != Some(&0x6F) {
            return Err(ApError::MsgType.into());
        }
        let rep: ApRep = rasn::der::decode(ap_rep).map_err(|_| Krb5Error::Ap(ApError::MsgType))?;
        let key = self
            .key
            .clone()
            .ok_or(Krb5Error::ReplyValidation("no key"))?;
        let profile =
            find_etype(rep.enc_part.etype).map_err(|e| Krb5Error::Crypto(e.to_string()))?;
        let plain = profile
            .decrypt(
                key.key_bytes(),
                key_usage::AP_REP_ENCPART,
                &rep.enc_part.cipher,
            )
            .map_err(|_| Krb5Error::Ap(ApError::BadIntegrity))?;
        let enc: EncApRepPart =
            rasn::der::decode(&plain).map_err(|_| Krb5Error::Ap(ApError::BadIntegrity))?;

        let auth = self
            .authentp
            .as_ref()
            .ok_or(Krb5Error::ReplyValidation("no authenticator"))?;
        if enc.ctime != auth.ctime || enc.cusec != auth.cusec {
            return Err(ApError::MutualFailed.into());
        }
        if let Some(sub) = &enc.subkey {
            self.recv_subkey = Some(sub.clone());
            self.send_subkey = Some(sub.clone());
            self.negotiated_etype = sub.keytype;
        }
        self.remote_seq = enc.seq_number.unwrap_or(0);
        Ok(enc)
    }

    /// Build a KRB-SAFE message (mk_safe.c:44-174).
    pub fn mk_safe(&mut self, user_data: &[u8]) -> Result<(Vec<u8>, ReplayData), Krb5Error> {
        if self.local_addr.is_none() {
            return Err(ApError::LocalAddrRequired.into());
        }
        let (ts, usec, seq) = self.gen_rdata();
        let local = self.effective_local_addr();
        let remote = self.effective_remote_addr();
        let key = self
            .send_subkey
            .clone()
            .or_else(|| self.key.clone())
            .ok_or(Krb5Error::ReplyValidation("no key"))?;
        let profile = find_etype(key.keytype).map_err(|e| Krb5Error::Crypto(e.to_string()))?;
        let body = KrbSafeBody {
            user_data: OctetString::from(user_data.to_vec()),
            timestamp: ts,
            usec,
            seq_number: seq,
            s_address: local.expect("checked above"),
            r_address: remote,
        };
        // mk_safe.c:66-70 — zero-length type-0 checksum for the first pass.
        let zero = Checksum {
            cksumtype: 0,
            checksum: OctetString::from(Vec::new()),
        };
        let mut safe = KrbSafe {
            pvno: 5,
            msg_type: 20,
            safe_body: body,
            cksum: zero.clone(),
        };
        let zerosafe_der = rasn::der::encode(&safe)?;
        let sum = profile
            .checksum(key.key_bytes(), key_usage::KRB_SAFE_CKSUM, &zerosafe_der)
            .map_err(|e| Krb5Error::Crypto(e.to_string()))?;
        safe.cksum = Checksum {
            cksumtype: profile.checksum_type(),
            checksum: OctetString::from(sum),
        };
        let der = rasn::der::encode(&safe)?;
        self.check_replay(None, safe.cksum.checksum.to_vec())?;
        if self
            .flags
            .intersects(AuthContextFlags::DO_SEQUENCE | AuthContextFlags::RET_SEQUENCE)
        {
            self.local_seq = self.local_seq.wrapping_add(1);
        }
        Ok((der, self.ret_rdata(ts, usec, seq)))
    }

    /// Read and verify a KRB-SAFE message (rd_safe.c:43-178).
    pub fn rd_safe(&mut self, msg: &[u8]) -> Result<(Vec<u8>, ReplayData), Krb5Error> {
        if msg.first() != Some(&0x74) {
            return Err(ApError::MsgType.into());
        }
        let safe: KrbSafe = rasn::der::decode(msg).map_err(|_| Krb5Error::Ap(ApError::MsgType))?;
        if safe.pvno != 5 || safe.msg_type != 20 {
            return Err(ApError::MsgType.into());
        }
        let profile = match find_cksumtype(safe.cksum.cksumtype) {
            Ok(p) => p,
            Err(_) => {
                // Known unkeyed collision-proof types → InappCksum
                // (krb5_c_is_keyed_cksum false); unknown → SumTypeNoSupp.
                return Err(match safe.cksum.cksumtype {
                    1..=8 | 12 | 14 => ApError::InappCksum.into(),
                    _ => ApError::SumTypeNoSupp.into(),
                });
            }
        };
        self.check_addrs(
            Some(&safe.safe_body.s_address),
            safe.safe_body.r_address.as_ref(),
        )?;
        let key = self
            .recv_subkey
            .clone()
            .or_else(|| self.key.clone())
            .ok_or(Krb5Error::ReplyValidation("no key"))?;

        // Re-encode with the zero checksum and verify (rd_safe.c:76-99).
        let mut zerosafe = safe.clone();
        zerosafe.cksum = Checksum {
            cksumtype: 0,
            checksum: OctetString::from(Vec::new()),
        };
        let zerosafe_der = rasn::der::encode(&zerosafe)?;
        let mut valid = profile
            .verify_checksum(
                key.key_bytes(),
                key_usage::KRB_SAFE_CKSUM,
                &zerosafe_der,
                &safe.cksum.checksum,
            )
            .is_ok();
        if !valid {
            // RFC 1510 fallback: checksum over the KRB-SAFE-BODY alone.
            let body_der = rasn::der::encode(&safe.safe_body)?;
            valid = profile
                .verify_checksum(
                    key.key_bytes(),
                    key_usage::KRB_SAFE_CKSUM,
                    &body_der,
                    &safe.cksum.checksum,
                )
                .is_ok();
        }
        if !valid {
            return Err(ApError::Modified.into());
        }

        let rdata = (
            safe.safe_body.timestamp,
            safe.safe_body.usec,
            safe.safe_body.seq_number,
        );
        self.check_replay(rdata.0, safe.cksum.checksum.to_vec())?;
        if self.flags.contains(AuthContextFlags::DO_SEQUENCE) {
            if !self.check_seqnum(rdata.2.unwrap_or(0)) {
                return Err(ApError::BadOrder.into());
            }
            self.remote_seq = self.remote_seq.wrapping_add(1);
        }
        Ok((
            safe.safe_body.user_data.to_vec(),
            self.ret_rdata(rdata.0, rdata.1, rdata.2),
        ))
    }

    /// Build a KRB-PRIV message (mk_priv.c:88-150).
    pub fn mk_priv(&mut self, user_data: &[u8]) -> Result<(Vec<u8>, ReplayData), Krb5Error> {
        if self.local_addr.is_none() {
            return Err(ApError::LocalAddrRequired.into());
        }
        let (ts, usec, seq) = self.gen_rdata();
        let local = self.effective_local_addr();
        let remote = self.effective_remote_addr();
        let key = self
            .send_subkey
            .clone()
            .or_else(|| self.key.clone())
            .ok_or(Krb5Error::ReplyValidation("no key"))?;
        let profile = find_etype(key.keytype).map_err(|e| Krb5Error::Crypto(e.to_string()))?;
        let encpart = EncKrbPrivPart {
            user_data: OctetString::from(user_data.to_vec()),
            timestamp: ts,
            usec,
            seq_number: seq,
            s_address: local.expect("checked above"),
            r_address: remote,
        };
        let der = rasn::der::encode(&encpart)?;
        let cipher = profile
            .encrypt(key.key_bytes(), key_usage::KRB_PRIV_ENCPART, &der)
            .map_err(|e| Krb5Error::Crypto(e.to_string()))?;
        let privmsg = KrbPriv {
            pvno: 5,
            msg_type: 21,
            enc_part: EncryptedData {
                etype: key.keytype,
                kvno: None,
                cipher: OctetString::from(cipher),
            },
        };
        let out = rasn::der::encode(&privmsg)?;
        // Tag = trailing checksum-length bytes of ciphertext (rc_base.c:147).
        let tag_len = profile
            .checksum(key.key_bytes(), 0, &[])
            .map_err(|e| Krb5Error::Crypto(e.to_string()))?
            .len();
        let tag = privmsg.enc_part.cipher[privmsg.enc_part.cipher.len() - tag_len..].to_vec();
        self.check_replay(None, tag)?;
        if self
            .flags
            .intersects(AuthContextFlags::DO_SEQUENCE | AuthContextFlags::RET_SEQUENCE)
        {
            self.local_seq = self.local_seq.wrapping_add(1);
        }
        Ok((out, self.ret_rdata(ts, usec, seq)))
    }

    /// Read and verify a KRB-PRIV message (rd_priv.c:88-150).
    pub fn rd_priv(&mut self, msg: &[u8]) -> Result<(Vec<u8>, ReplayData), Krb5Error> {
        if msg.first() != Some(&0x75) {
            return Err(ApError::MsgType.into());
        }
        let privmsg: KrbPriv =
            rasn::der::decode(msg).map_err(|_| Krb5Error::Ap(ApError::MsgType))?;
        if privmsg.pvno != 5 || privmsg.msg_type != 21 {
            return Err(ApError::MsgType.into());
        }
        let key = self
            .recv_subkey
            .clone()
            .or_else(|| self.key.clone())
            .ok_or(Krb5Error::ReplyValidation("no key"))?;
        let profile =
            find_etype(privmsg.enc_part.etype).map_err(|e| Krb5Error::Crypto(e.to_string()))?;
        let plain = profile
            .decrypt(
                key.key_bytes(),
                key_usage::KRB_PRIV_ENCPART,
                &privmsg.enc_part.cipher,
            )
            .map_err(|_| Krb5Error::Ap(ApError::BadIntegrity))?;
        let encpart: EncKrbPrivPart =
            rasn::der::decode(&plain).map_err(|_| Krb5Error::Ap(ApError::BadIntegrity))?;
        self.check_addrs(Some(&encpart.s_address), encpart.r_address.as_ref())?;
        let tag_len = profile
            .checksum(key.key_bytes(), 0, &[])
            .map_err(|e| Krb5Error::Crypto(e.to_string()))?
            .len();
        let tag = privmsg.enc_part.cipher[privmsg.enc_part.cipher.len() - tag_len..].to_vec();
        self.check_replay(encpart.timestamp, tag)?;
        if self.flags.contains(AuthContextFlags::DO_SEQUENCE) {
            if !self.check_seqnum(encpart.seq_number.unwrap_or(0)) {
                return Err(ApError::BadOrder.into());
            }
            self.remote_seq = self.remote_seq.wrapping_add(1);
        }
        Ok((
            encpart.user_data.to_vec(),
            self.ret_rdata(encpart.timestamp, encpart.usec, encpart.seq_number),
        ))
    }

    /// Build a KRB-CRED message (mk_cred.c:37-212; unencrypted form per
    /// RFC 6448 when no key is available).
    pub fn mk_cred(&mut self, creds: &[Credential]) -> Result<(Vec<u8>, ReplayData), Krb5Error> {
        let (mut ts, mut usec, seq) = self.gen_rdata();
        // mk_cred.c:176-181 — historically the timestamp is always set.
        if ts.is_none() {
            let (t, u) = self.now();
            ts = Some(t);
            usec = Some(u);
        }
        let local = self.effective_local_addr();
        let remote = self.effective_remote_addr();
        let key = self.send_subkey.clone().or_else(|| self.key.clone());

        let mut tickets = Vec::with_capacity(creds.len());
        let mut infos = Vec::with_capacity(creds.len());
        for c in creds {
            tickets.push(c.ticket.clone());
            infos.push(KrbCredInfo {
                key: c.session_key.clone(),
                prealm: Some(
                    GeneralString::from_bytes(c.crealm.as_bytes())
                        .map_err(|_| Krb5Error::ReplyValidation("invalid crealm"))?,
                ),
                pname: Some(c.client.clone()),
                flags: Some(c.flags),
                authtime: Some(c.times.authtime),
                starttime: c.times.starttime,
                endtime: Some(c.times.endtime),
                renew_till: c.times.renew_till,
                srealm: Some(
                    GeneralString::from_bytes(c.srealm.as_bytes())
                        .map_err(|_| Krb5Error::ReplyValidation("invalid srealm"))?,
                ),
                sname: Some(c.server.clone()),
                caddr: c.addresses.clone(),
            });
        }
        let encpart = EncKrbCredPart {
            ticket_info: infos,
            nonce: seq,
            timestamp: ts,
            usec,
            s_address: local,
            r_address: remote,
        };
        let der = rasn::der::encode(&encpart)?;
        let enc_data = if let Some(key) = &key {
            let profile = find_etype(key.keytype).map_err(|e| Krb5Error::Crypto(e.to_string()))?;
            let cipher = profile
                .encrypt(key.key_bytes(), key_usage::KRB_CRED_ENCPART, &der)
                .map_err(|e| Krb5Error::Crypto(e.to_string()))?;
            EncryptedData {
                etype: key.keytype,
                kvno: None,
                cipher: OctetString::from(cipher),
            }
        } else {
            EncryptedData {
                etype: 0,
                kvno: None,
                cipher: OctetString::from(der),
            }
        };
        let cred_msg = KrbCred {
            pvno: 5,
            msg_type: 22,
            tickets,
            enc_part: enc_data.clone(),
        };
        let out = rasn::der::encode(&cred_msg)?;
        if let Some(key) = &key {
            let profile = find_etype(key.keytype).map_err(|e| Krb5Error::Crypto(e.to_string()))?;
            let tag_len = profile
                .checksum(key.key_bytes(), 0, &[])
                .map_err(|e| Krb5Error::Crypto(e.to_string()))?
                .len();
            let tag = enc_data.cipher[enc_data.cipher.len() - tag_len..].to_vec();
            self.check_replay(None, tag)?;
        }
        if self
            .flags
            .intersects(AuthContextFlags::DO_SEQUENCE | AuthContextFlags::RET_SEQUENCE)
        {
            self.local_seq = self.local_seq.wrapping_add(1);
        }
        Ok((out, self.ret_rdata(ts, usec, seq)))
    }

    /// Read and verify a KRB-CRED message (rd_cred.c:42-204).
    pub fn rd_cred(&mut self, msg: &[u8]) -> Result<(Vec<Credential>, ReplayData), Krb5Error> {
        if msg.first() != Some(&0x76) {
            return Err(ApError::MsgType.into());
        }
        let cred_msg: KrbCred =
            rasn::der::decode(msg).map_err(|_| Krb5Error::Ap(ApError::MsgType))?;
        if cred_msg.pvno != 5 || cred_msg.msg_type != 22 {
            return Err(ApError::MsgType.into());
        }
        let cipher = cred_msg.enc_part.cipher.to_vec();
        let encpart: EncKrbCredPart = if self.recv_subkey.is_none() && self.key.is_none() {
            rasn::der::decode(&cipher)?
        } else {
            let mut plain = None;
            for key in [self.recv_subkey.as_ref(), self.key.as_ref()]
                .into_iter()
                .flatten()
            {
                if let Ok(profile) = find_etype(cred_msg.enc_part.etype) {
                    if let Ok(p) =
                        profile.decrypt(key.key_bytes(), key_usage::KRB_CRED_ENCPART, &cipher)
                    {
                        plain = Some(p);
                        break;
                    }
                }
            }
            let plain = plain.ok_or(Krb5Error::Ap(ApError::BadIntegrity))?;
            rasn::der::decode(&plain).map_err(|_| Krb5Error::Ap(ApError::BadIntegrity))?
        };

        let mut out = Vec::with_capacity(cred_msg.tickets.len());
        for (i, ticket) in cred_msg.tickets.iter().enumerate() {
            let info = encpart
                .ticket_info
                .get(i)
                .ok_or(Krb5Error::Ap(ApError::Modified))?;
            out.push(Credential {
                client: info.pname.clone().unwrap_or_else(|| PrincipalName {
                    name_type: 0,
                    name_string: Vec::new(),
                }),
                crealm: info
                    .prealm
                    .as_ref()
                    .map(|r| String::from_utf8_lossy(r.as_ref()).to_string())
                    .unwrap_or_default(),
                server: info.sname.clone().unwrap_or_else(|| PrincipalName {
                    name_type: 0,
                    name_string: Vec::new(),
                }),
                srealm: info
                    .srealm
                    .as_ref()
                    .map(|r| String::from_utf8_lossy(r.as_ref()).to_string())
                    .unwrap_or_default(),
                session_key: info.key.clone(),
                times: super::credential::TicketTimes {
                    authtime: info.authtime.unwrap_or_else(now_kerberos),
                    starttime: info.starttime,
                    endtime: info.endtime.unwrap_or_else(now_kerberos),
                    renew_till: info.renew_till,
                },
                ticket: ticket.clone(),
                flags: info.flags.unwrap_or_default(),
                addresses: info.caddr.clone(),
                authdata: None,
            });
        }

        if self.recv_subkey.is_some() || self.key.is_some() {
            let profile = find_etype(cred_msg.enc_part.etype)
                .map_err(|e| Krb5Error::Crypto(e.to_string()))?;
            let tag_len = profile
                .checksum(
                    self.recv_subkey
                        .as_ref()
                        .or(self.key.as_ref())
                        .expect("keyed")
                        .key_bytes(),
                    0,
                    &[],
                )
                .map_err(|e| Krb5Error::Crypto(e.to_string()))?
                .len();
            let tag = cipher[cipher.len() - tag_len..].to_vec();
            self.check_replay(encpart.timestamp, tag)?;
        }
        if self.flags.contains(AuthContextFlags::DO_SEQUENCE) {
            if encpart.nonce.unwrap_or(0) != self.remote_seq {
                return Err(ApError::BadOrder.into());
            }
            self.remote_seq = self.remote_seq.wrapping_add(1);
        }
        Ok((
            out,
            self.ret_rdata(encpart.timestamp, encpart.usec, encpart.nonce),
        ))
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
