//! S4U2Self and S4U2Proxy in the KDC (MS-SFU; MIT kdc/kdc_util.c:1233-1645,
//! kdc/tgs_policy.c:296-572, kdc/do_tgs_req.c `decrypt_2ndtkt` and the S4U
//! parts of `gather_tgs_req_info`).
//!
//! Scope: S4U2Self and S4U2Proxy (traditional and resource-based), within one
//! realm and across realms (referral chains, PAC `verify_deleg_pac`).
//! Certificate-only S4U2Self returns the MIT error for a database without
//! certificate lookup.

use std::str::FromStr;

use super::db::KvnoSel;
use super::error::{general_string, KdcError};
use super::policy::{validate_as_request, AS_INVALID_OPTIONS};
use super::preauth::find_padata;
use super::tgs_req::NON_TGT_OPTION;
use super::PrincipalStore;
use super::{is_tgs_principal, names_equal, Kdc, PrincipalAttributes, PrincipalEntry};
use crate::crypto::{find_cksumtype, hmac_md5_checksum};
use crate::pac::{unparse_name, Pac};
use crate::protocol::ap::decrypt_ticket;
use crate::types::error_codes::*;
use crate::types::{
    Checksum, EncTicketPart, EncryptionKey, KdcOptions, KdcReq, PaData, PaDataType, PaForUser,
    PaPacOptions, PaS4uX509User, PrincipalName, S4uUserId, Ticket, TicketFlags,
    PA_PAC_OPTIONS_RBCD, S4U_OPTS_USE_REPLY_KEY_USAGE,
};

/// `KRB5_PADATA_FOR_USER`.
pub(crate) const PA_FOR_USER: i32 = 129;
/// `KRB5_PADATA_S4U_X509_USER`.
pub(crate) const PA_S4U_X509_USER: i32 = 130;
/// `KRB5_KEYUSAGE_APP_DATA_CKSUM`.
const KEYUSAGE_APP_DATA_CKSUM: i32 = 17;
/// `KRB5_KEYUSAGE_PA_S4U_X509_USER_REQUEST`.
pub(crate) const KEYUSAGE_S4U_REQUEST: i32 = 26;
/// `KRB5_KEYUSAGE_PA_S4U_X509_USER_REPLY`.
pub(crate) const KEYUSAGE_S4U_REPLY: i32 = 27;
/// `CKSUMTYPE_HMAC_MD5_ARCFOUR`.
pub(crate) const CKSUMTYPE_HMAC_MD5: i32 = -138;

fn text(g: &rasn::types::GeneralString) -> String {
    String::from_utf8_lossy(g.as_bytes()).to_string()
}

/// Whether `entry` is the principal `(name, realm)` (`is_client_db_alias`,
/// kdc_util.c:1546-1560, without KDB alias maps).
pub(super) fn is_client_db_alias(
    entry: &PrincipalEntry,
    name: &PrincipalName,
    realm: &str,
) -> bool {
    names_equal(&entry.name, name) && entry.realm == realm
}

/// A decoded S4U2Self request (MIT `krb5_pa_s4u_x509_user` plus the looked-up
/// client).
pub(super) struct S4u2Self {
    pub user: PrincipalName,
    pub user_realm: String,
    pub nonce: u32,
    pub options: u32,
    pub cksum_type: i32,
    /// The request carried PA-S4U-X509-USER (only then is a reply padata
    /// returned, do_tgs_req.c:1065-1067).
    pub x509: bool,
    /// The DB entry of the impersonated user, when it belongs to this realm.
    pub client: Option<PrincipalEntry>,
}

/// The second (evidence) ticket of an S4U2Proxy request, decrypted
/// (`decrypt_2ndtkt`, do_tgs_req.c:253-299).
pub(super) struct EvidenceTicket {
    pub part: EncTicketPart,
    pub server: PrincipalEntry,
    pub pac: Option<Pac>,
    pub sname: PrincipalName,
    pub realm: String,
}

fn raw_checksum(cksum_type: i32, key: &EncryptionKey, usage: i32, data: &[u8]) -> Option<Vec<u8>> {
    if cksum_type == CKSUMTYPE_HMAC_MD5 {
        return hmac_md5_checksum(key.key_bytes(), usage, data)
            .ok()
            .map(|c| c.to_vec());
    }
    let profile = find_cksumtype(cksum_type).ok()?;
    (profile.etype() == key.keytype)
        .then(|| profile.checksum(key.key_bytes(), usage, data).ok())
        .flatten()
}

/// Whether `cksum_type` is a keyed type this KDC can compute
/// (`krb5_c_is_keyed_cksum`).
fn is_keyed(cksum_type: i32) -> bool {
    matches!(cksum_type, CKSUMTYPE_HMAC_MD5 | 15 | 16 | 19 | 20)
}

fn verify_raw(cksum: &Checksum, key: &EncryptionKey, usage: i32, data: &[u8]) -> bool {
    raw_checksum(cksum.cksumtype, key, usage, data)
        .is_some_and(|c| c.as_slice() == cksum.checksum.as_ref())
}

/// `verify_for_user_checksum` (kdc_util.c:1233-1305): checksum over the name
/// type (LE), name components, realm and auth package.
fn verify_for_user(key: &EncryptionKey, req: &PaForUser) -> Result<(), KdcError> {
    if !is_keyed(req.cksum.cksumtype) {
        return Err(KdcError::new(
            KRB_AP_ERR_INAPP_CKSUM,
            "INVALID_S4U2SELF_CHECKSUM",
        ));
    }
    let mut data = req.user_name.name_type.to_le_bytes().to_vec();
    for c in &req.user_name.name_string {
        data.extend_from_slice(c.as_bytes());
    }
    data.extend_from_slice(req.user_realm.as_bytes());
    data.extend_from_slice(req.auth_package.as_bytes());
    if verify_raw(&req.cksum, key, KEYUSAGE_APP_DATA_CKSUM, &data) {
        Ok(())
    } else {
        Err(KdcError::new(
            KRB_AP_ERR_MODIFIED,
            "INVALID_S4U2SELF_CHECKSUM",
        ))
    }
}

/// The contents of the first context-specific field of the outer SEQUENCE
/// (`fetch_asn1_field(data, 1, 0, ..)`), the encoded S4UUserID as sent.
fn first_field(der: &[u8]) -> Option<&[u8]> {
    fn header(b: &[u8]) -> Option<(usize, usize)> {
        let len = *b.get(1)? as usize;
        if len < 0x80 {
            return Some((2, len));
        }
        let n = len & 0x7f;
        if n == 0 || n > 4 {
            return None;
        }
        let mut v = 0usize;
        for i in 0..n {
            v = (v << 8) | *b.get(2 + i)? as usize;
        }
        Some((2 + n, v))
    }
    let (h, l) = header(der)?;
    let inner = der.get(h..h.checked_add(l)?)?;
    let (h2, l2) = header(inner)?;
    inner.get(h2..h2.checked_add(l2)?)
}

/// `verify_s4u_x509_user_checksum` (kdc_util.c:1307-1365).
fn verify_s4u_x509_user(
    key: &EncryptionKey,
    raw: &[u8],
    req_nonce: u32,
    pa: &PaS4uX509User,
) -> Result<(), KdcError> {
    const STATUS: &str = "INVALID_S4U2SELF_CHECKSUM";
    if !is_keyed(pa.cksum.cksumtype) {
        return Err(KdcError::new(KRB_AP_ERR_INAPP_CKSUM, STATUS));
    }
    if pa.user_id.nonce != req_nonce {
        return Err(KdcError::new(KRB_AP_ERR_MODIFIED, STATUS));
    }
    let scratch = first_field(raw).ok_or_else(|| KdcError::generic(STATUS))?;
    if verify_raw(&pa.cksum, key, KEYUSAGE_S4U_REQUEST, scratch) {
        return Ok(());
    }
    let re = rasn::der::encode(&pa.user_id).map_err(|_| KdcError::generic(STATUS))?;
    if verify_raw(&pa.cksum, key, KEYUSAGE_S4U_REQUEST, &re) {
        Ok(())
    } else {
        Err(KdcError::new(KRB_AP_ERR_MODIFIED, STATUS))
    }
}

/// PA-PAC-OPTIONS bits sent by the client (`kdc_get_pa_pac_options`,
/// kdc_util.c:1810-1822).
fn pac_options_bits(padata: Option<&[PaData]>) -> Result<u32, KdcError> {
    let Some(pa) = find_padata(padata, PaDataType::PacOptions) else {
        return Ok(0);
    };
    let opts: PaPacOptions = rasn::der::decode(pa.padata_value.as_ref())
        .map_err(|_| KdcError::generic("DECODE_PA_PAC_OPTIONS"))?;
    let mut bits = 0u32;
    for (i, b) in opts.flags.iter().by_vals().take(32).enumerate() {
        if b {
            bits |= 0x8000_0000 >> i;
        }
    }
    Ok(bits)
}

/// `kdc_get_pa_pac_rbcd` (kdc_util.c:1865-1880).
pub(super) fn supports_rbcd(padata: Option<&[PaData]>) -> Result<bool, KdcError> {
    Ok(pac_options_bits(padata)? & PA_PAC_OPTIONS_RBCD != 0)
}

/// `kdc_add_pa_pac_options` (kdc_util.c:1832-1862): echo only the RBCD bit.
pub(super) fn pac_options_reply(padata: Option<&[PaData]>) -> Result<Option<PaData>, KdcError> {
    if pac_options_bits(padata)? & PA_PAC_OPTIONS_RBCD == 0 {
        return Ok(None);
    }
    let flags = rasn::types::BitString::from_slice(&PA_PAC_OPTIONS_RBCD.to_be_bytes());
    let der = rasn::der::encode(&PaPacOptions { flags })?;
    Ok(Some(PaData {
        padata_type: PaDataType::PacOptions as i32,
        padata_value: der.into(),
    }))
}

/// Whether the stored principal string `entry` names `(name, realm)`; names
/// are compared as parsed principals, ignoring the name type.
fn list_names(entry: &str, default_realm: &str, name: &PrincipalName, realm: &str) -> bool {
    let (n, r) = match entry.rsplit_once('@') {
        Some((n, r)) => (n, r),
        None => (entry, default_realm),
    };
    PrincipalName::from_str(n).is_ok_and(|p| names_equal(&p, name)) && r == realm
}

impl<S: PrincipalStore> Kdc<S> {
    /// `kdc_process_s4u2self_req` (kdc_util.c:1580-1645). `session` is the
    /// header ticket session key and `subkey` the authenticator subkey.
    pub(super) async fn process_s4u2self_req(
        &self,
        req: &KdcReq,
        server: &PrincipalEntry,
        subkey: Option<&EncryptionKey>,
        session: &EncryptionKey,
    ) -> Result<Option<S4u2Self>, KdcError> {
        let padata = req.padata.as_deref();
        let find = |t: i32| padata.into_iter().flatten().find(|p| p.padata_type == t);
        let (user, user_realm, nonce, options, cksum_type, x509, cert);
        if let Some(pa) = find(PA_S4U_X509_USER) {
            let raw = pa.padata_value.as_ref();
            let x: PaS4uX509User =
                rasn::der::decode(raw).map_err(|_| KdcError::generic("DECODE_PA_S4U_X509_USER"))?;
            verify_s4u_x509_user(subkey.unwrap_or(session), raw, req.req_body.nonce, &x)?;
            cert = x
                .user_id
                .subject_certificate
                .as_ref()
                .is_some_and(|c| !c.is_empty());
            let name = x.user_id.cname.clone();
            if name.as_ref().is_none_or(|u| u.name_string.is_empty()) && !cert {
                return Err(KdcError::new(
                    KDC_ERR_C_PRINCIPAL_UNKNOWN,
                    "INVALID_S4U2SELF_REQUEST",
                ));
            }
            user = name.unwrap_or(PrincipalName {
                name_type: 1,
                name_string: Vec::new(),
            });
            user_realm = text(&x.user_id.crealm);
            nonce = x.user_id.nonce;
            options = x.user_id.options.as_ref().map_or(0, bits_to_u32);
            cksum_type = x.cksum.cksumtype;
            x509 = true;
        } else if let Some(pa) = find(PA_FOR_USER) {
            let f: PaForUser = rasn::der::decode(pa.padata_value.as_ref())
                .map_err(|_| KdcError::generic("DECODE_PA_FOR_USER"))?;
            verify_for_user(session, &f)?;
            user = f.user_name;
            user_realm = text(&f.user_realm);
            nonce = 0;
            options = 0;
            cksum_type = f.cksum.cksumtype;
            x509 = false;
            cert = false;
        } else {
            return Ok(None);
        }

        let mut client = None;
        if user_realm == server.realm {
            if cert {
                // get_s4u_x509_principal is not provided by this database
                // (KRB5_PLUGIN_OP_NOTSUPP, reported as a generic error).
                return Err(KdcError::generic("LOOKING_UP_S4U2SELF_PRINCIPAL"));
            }
            let mut entry = self
                .lookup(&user, &user_realm, "LOOKING_UP_S4U2SELF_PRINCIPAL")
                .await?
                .ok_or_else(|| {
                    KdcError::new(KDC_ERR_C_PRINCIPAL_UNKNOWN, "UNKNOWN_S4U2SELF_PRINCIPAL")
                })?;
            // S4U2Self is not password authentication (kdc_util.c:1634-1636).
            entry.pw_expiration = None;
            entry.attributes &= !PrincipalAttributes::REQUIRES_PWCHANGE;
            client = Some(entry);
        }
        Ok(Some(S4u2Self {
            user,
            user_realm,
            nonce,
            options,
            cksum_type,
            x509,
            client,
        }))
    }

    /// `check_tgs_s4u2self` (tgs_policy.c:262-355), including the
    /// cross-realm cases 2-4 of the MIT comment.
    #[expect(clippy::too_many_arguments, reason = "mirrors check_tgs_s4u2self")]
    pub(super) fn check_tgs_s4u2self(
        &self,
        s4u: &S4u2Self,
        opts: KdcOptions,
        server: &PrincipalEntry,
        header: &EncTicketPart,
        header_pac: Option<&Pac>,
        is_crossrealm: bool,
        is_referral: bool,
        kdc_time: i64,
    ) -> Result<(), KdcError> {
        let crealm = text(&header.crealm);
        if !is_referral && !is_client_db_alias(server, &header.cname, &crealm) {
            return Err(KdcError::new(
                KRB_AP_ERR_BADMATCH,
                "INVALID_S4U2SELF_REQUEST_SERVER_MISMATCH",
            ));
        }
        if opts.intersects(AS_INVALID_OPTIONS) {
            return Err(KdcError::new(KDC_ERR_BADOPTION, "INVALID S4U2SELF OPTIONS"));
        }
        if !is_crossrealm && is_referral {
            return Err(KdcError::new(
                KDC_ERR_S_PRINCIPAL_UNKNOWN,
                "LOOKING_UP_SERVER",
            ));
        }
        if s4u.client.is_some() && is_crossrealm && !is_referral {
            return Err(KdcError::new(
                KDC_ERR_C_PRINCIPAL_UNKNOWN,
                "NOT_CROSS_REALM_REQUEST",
            ));
        }
        if s4u.client.is_none() && !is_crossrealm {
            return Err(KdcError::new(KDC_ERR_POLICY, "S4U2SELF_CLIENT_NOT_OURS"));
        }
        if s4u.client.is_none() && s4u.user.name_string.is_empty() {
            return Err(KdcError::new(
                KDC_ERR_POLICY,
                "INVALID_XREALM_S4U2SELF_REQUEST",
            ));
        }
        let pac =
            header_pac.ok_or_else(|| KdcError::new(KDC_ERR_TGT_REVOKED, "S4U2SELF_NO_PAC"))?;
        let Some(client) = s4u.client.as_ref() else {
            // The header ticket PAC is for the subject, with realm.
            return pac
                .verify_ext(
                    header.authtime.timestamp(),
                    Some((&s4u.user, &s4u.user_realm)),
                    true,
                    None,
                    None,
                )
                .map_err(|_| KdcError::new(KDC_ERR_BADOPTION, "S4U2SELF_FOREIGN_PAC_CLIENT"));
        };
        if pac
            .verify(
                header.authtime.timestamp(),
                Some((&header.cname, &crealm)),
                None,
                None,
            )
            .is_err()
        {
            return Err(KdcError::new(
                KDC_ERR_BADOPTION,
                "S4U2SELF_LOCAL_PAC_CLIENT",
            ));
        }
        // An empty server bypasses the server checks of validate_as_request.
        let empty = PrincipalEntry {
            name: PrincipalName {
                name_type: 1,
                name_string: Vec::new(),
            },
            realm: String::new(),
            attributes: PrincipalAttributes::empty(),
            max_life: None,
            max_renewable_life: None,
            expiration: None,
            pw_expiration: None,
            keys: Vec::new(),
            allowed_to_delegate_to: Vec::new(),
            allowed_to_delegate_from: Vec::new(),
            policy: None,
            security_epoch: 0,
            last_admin_unlock: None,
        };
        validate_as_request(opts, client, &empty, kdc_time)
    }

    /// `kdc_make_s4u2self_rep` (kdc_util.c:1431-1500): the reply
    /// PA-S4U-X509-USER, checksummed with the subkey (or session key).
    pub(super) fn make_s4u2self_rep(
        &self,
        s4u: &S4u2Self,
        subkey: Option<&EncryptionKey>,
        session: &EncryptionKey,
    ) -> Result<PaData, KdcError> {
        let status = "MAKE_S4U2SELF_REP";
        let key = subkey.unwrap_or(session);
        let options = s4u.options & S4U_OPTS_USE_REPLY_KEY_USAGE;
        let user_id = S4uUserId {
            nonce: s4u.nonce,
            cname: Some(s4u.user.clone()),
            crealm: general_string(&s4u.user_realm)?,
            subject_certificate: None,
            options: (options != 0)
                .then(|| rasn::types::BitString::from_slice(&options.to_be_bytes())),
        };
        let der = rasn::der::encode(&user_id).map_err(|_| KdcError::generic(status))?;
        let usage = if options != 0 {
            KEYUSAGE_S4U_REPLY
        } else {
            KEYUSAGE_S4U_REQUEST
        };
        let sum = raw_checksum(s4u.cksum_type, key, usage, &der)
            .ok_or_else(|| KdcError::generic(status))?;
        let pa = PaS4uX509User {
            user_id,
            cksum: Checksum {
                cksumtype: s4u.cksum_type,
                checksum: sum.into(),
            },
        };
        Ok(PaData {
            padata_type: PA_S4U_X509_USER,
            padata_value: rasn::der::encode(&pa)
                .map_err(|_| KdcError::generic(status))?
                .into(),
        })
    }

    /// `s4u2self_forwardable` (kdc_util.c:1626-1644): keep FORWARDABLE only
    /// for services with ok-to-auth-as-delegate or without any delegation
    /// targets ([MS-SFU] 3.2.5.1.2).
    pub(super) fn s4u2self_forwardable(server: &PrincipalEntry, flags: &mut TicketFlags) {
        if server
            .attributes
            .contains(PrincipalAttributes::OK_TO_AUTH_AS_DELEGATE)
        {
            return;
        }
        if !server.allowed_to_delegate_to.is_empty() {
            flags.remove(TicketFlags::FORWARDABLE);
        }
    }

    /// `decrypt_2ndtkt` (do_tgs_req.c:253-299) for S4U2Proxy: the evidence
    /// ticket is decrypted with its server's key and its PAC verified like a
    /// header ticket's (statuses 2ND_TKT_SERVER / 2ND_TKT_DECRYPT /
    /// 2ND_TKT_PAC).
    pub(super) async fn decrypt_2ndtkt(
        &self,
        ticket: &Ticket,
        local_tgt: &PrincipalEntry,
    ) -> Result<EvidenceTicket, KdcError> {
        let permitted = self.permitted();
        let realm = text(&ticket.realm);
        let server = self
            .lookup(&ticket.sname, &realm, "2ND_TKT_SERVER")
            .await
            .ok()
            .flatten()
            .filter(|s| {
                !s.attributes.intersects(
                    PrincipalAttributes::DISALLOW_SVR | PrincipalAttributes::DISALLOW_ALL_TIX,
                )
            })
            .ok_or_else(|| KdcError::new(KDC_ERR_S_PRINCIPAL_UNKNOWN, "2ND_TKT_SERVER"))?;
        let local_tgs = is_tgs_principal(&ticket.sname)
            && ticket.sname.name_string[1].as_bytes() == ticket.realm.as_bytes();
        let etype = (!local_tgs).then_some(ticket.enc_part.etype);
        let kvno = match ticket.enc_part.kvno {
            Some(k) if k != 0 => {
                KvnoSel::Exact(u32::try_from(k).map_err(|_| KdcError::generic("2ND_TKT_SERVER"))?)
            }
            _ => KvnoSel::Any,
        };
        let key = server
            .find_key(etype, kvno, &permitted)
            .ok_or_else(|| KdcError::generic("2ND_TKT_SERVER"))?
            .key
            .clone();
        let part = decrypt_ticket(&key, ticket)
            .map_err(|_| KdcError::new(KRB_AP_ERR_BAD_INTEGRITY, "2ND_TKT_DECRYPT"))?;
        let pac = self
            .verify_header_pac(&part, &ticket.sname, &key, local_tgt)
            .map_err(|e| KdcError::new(e.code, "2ND_TKT_PAC"))?;
        Ok(EvidenceTicket {
            part,
            server,
            pac,
            sname: ticket.sname.clone(),
            realm,
        })
    }

    /// `check_tgs_s4u2proxy` (tgs_policy.c:418-518).
    #[expect(clippy::too_many_arguments, reason = "mirrors check_tgs_s4u2proxy")]
    pub(super) fn check_tgs_s4u2proxy(
        &self,
        opts: KdcOptions,
        req_server: &PrincipalName,
        header: &EncTicketPart,
        header_pac: Option<&Pac>,
        stkt: Option<&EvidenceTicket>,
        is_crossrealm: bool,
        is_referral: bool,
    ) -> Result<(), KdcError> {
        let stkt = stkt.ok_or_else(|| KdcError::new(KDC_ERR_BADOPTION, "NO_2ND_TKT"))?;
        if !stkt.part.flags.contains(TicketFlags::FORWARDABLE) {
            return Err(KdcError::new(
                KDC_ERR_BADOPTION,
                "EVIDENCE_TKT_NOT_FORWARDABLE",
            ));
        }
        if opts.intersects(NON_TGT_OPTION | KdcOptions::ENC_TKT_IN_SKEY) {
            return Err(KdcError::new(
                KDC_ERR_BADOPTION,
                "INVALID_S4U2PROXY_OPTIONS",
            ));
        }
        if is_tgs_principal(req_server) {
            return Err(KdcError::new(KDC_ERR_POLICY, "NOT_ALLOWED_TO_DELEGATE"));
        }
        let crealm = text(&header.crealm);
        let pac = header_pac
            .ok_or_else(|| KdcError::new(KDC_ERR_TGT_REVOKED, "S4U2PROXY_NO_HEADER_PAC"))?;
        if pac
            .verify(
                header.authtime.timestamp(),
                Some((&header.cname, &crealm)),
                None,
                None,
            )
            .is_err()
        {
            return Err(KdcError::new(KDC_ERR_BADOPTION, "S4U2PROXY_HEADER_PAC"));
        }
        let stkt_pac = stkt
            .pac
            .as_ref()
            .ok_or_else(|| KdcError::new(KRB_AP_ERR_MODIFIED, "S4U2PROXY_NO_STKT_PAC"))?;
        if is_crossrealm {
            // The evidence ticket is a cross-realm TGT to this realm with the
            // impersonator as client, and the target is local.
            let sn = &stkt.server.name;
            let cross_to_us = is_tgs_principal(sn)
                && sn.name_string[1].as_bytes() != stkt.server.realm.as_bytes()
                && sn.name_string[1].as_bytes() == self.config.realm.as_bytes();
            if is_referral
                || !cross_to_us
                || !names_equal(&stkt.part.cname, &header.cname)
                || stkt.part.crealm != header.crealm
            {
                return Err(KdcError::new(
                    KDC_ERR_BADOPTION,
                    "XREALM_EVIDENCE_TICKET_MISMATCH",
                ));
            }
            if verify_deleg_pac(stkt_pac, &stkt.part, Some(req_server)).is_err() {
                return Err(KdcError::new(KDC_ERR_BADOPTION, "S4U2PROXY_CROSS_STKT_PAC"));
            }
            return Ok(());
        }
        if !is_client_db_alias(&stkt.server, &header.cname, &crealm) {
            return Err(KdcError::new(
                KDC_ERR_SERVER_NOMATCH,
                "EVIDENCE_TICKET_MISMATCH",
            ));
        }
        let screalm = text(&stkt.part.crealm);
        if stkt_pac
            .verify(
                stkt.part.authtime.timestamp(),
                Some((&stkt.part.cname, &screalm)),
                None,
                None,
            )
            .is_err()
        {
            return Err(KdcError::new(KDC_ERR_BADOPTION, "S4U2PROXY_LOCAL_STKT_PAC"));
        }
        Ok(())
    }

    /// `check_s4u2proxy_policy` (tgs_policy.c:520-570) over this database's
    /// delegation lists: RBCD (`allowed_to_delegate_from` on the resource,
    /// naming the impersonator) when the client sent the RBCD PA-PAC-OPTIONS
    /// bit, then the traditional list (`allowed_to_delegate_to` on the
    /// impersonator, naming the resource, compared with realm as MIT's LDAP
    /// `krb5_ldap_check_allowed_to_delegate` does).
    #[expect(clippy::too_many_arguments, reason = "mirrors check_s4u2proxy_policy")]
    pub(super) fn check_s4u2proxy_policy(
        &self,
        req: &KdcReq,
        impersonator_name: (&PrincipalName, &str),
        impersonator: &PrincipalEntry,
        resource_name: (&PrincipalName, &str),
        resource: &PrincipalEntry,
        is_crossrealm: bool,
        is_referral: bool,
    ) -> Result<(), KdcError> {
        let rbcd = supports_rbcd(req.padata.as_deref())?;
        if is_referral {
            // Policy is checked in the resource realm; a referral is only
            // useful to an RBCD client.
            return if rbcd {
                Ok(())
            } else {
                Err(KdcError::new(
                    KDC_ERR_BADOPTION,
                    "UNSUPPORTED_S4U2PROXY_REQUEST",
                ))
            };
        }
        let mut denied = false;
        if rbcd {
            if resource
                .allowed_to_delegate_from
                .iter()
                .any(|e| list_names(e, &resource.realm, impersonator_name.0, impersonator_name.1))
            {
                return Ok(());
            }
            denied = true;
        }
        if !is_crossrealm {
            if impersonator
                .allowed_to_delegate_to
                .iter()
                .any(|e| list_names(e, &impersonator.realm, resource_name.0, resource_name.1))
            {
                return Ok(());
            }
            denied = true;
        }
        Err(KdcError::new(
            KDC_ERR_BADOPTION,
            if denied {
                "NOT_ALLOWED_TO_DELEGATE"
            } else {
                "UNSUPPORTED_S4U2PROXY_REQUEST"
            },
        ))
    }
}

fn bits_to_u32(b: &rasn::types::BitString) -> u32 {
    let mut v = 0u32;
    for (i, bit) in b.iter().by_vals().take(32).enumerate() {
        if bit {
            v |= 0x8000_0000 >> i;
        }
    }
    v
}

/// `krb5_unparse_name` of the evidence ticket's server, for the PAC
/// transited-services list.
pub(super) fn impersonator_string(name: &PrincipalName, realm: &str) -> String {
    unparse_name(name, realm, false, true)
}

/// `get_pac_princ_with_realm` (kdc_util.c): the PAC client info name, which
/// must carry a realm, and its authtime.
pub(super) fn pac_princ_with_realm(pac: &Pac) -> Option<(PrincipalName, String, i64)> {
    let info = pac.client_info().ok()?;
    let (name, realm) = crate::kdc::kdb::mit::parse_name(info.name.as_bytes()).ok()?;
    (!realm.is_empty() && info.name.contains('@')).then_some((name, realm, info.authtime))
}

/// `verify_deleg_pac` (tgs_policy.c:357-416): `pac` is an S4U2Proxy subject
/// PAC inside a cross-realm TGT, naming `target_server` (when given) as its
/// proxy target and the TGT client as its last transited service.
pub(super) fn verify_deleg_pac(
    pac: &Pac,
    enc_tkt: &EncTicketPart,
    target_server: Option<&PrincipalName>,
) -> Result<(), ()> {
    let (_, _, authtime) = pac_princ_with_realm(pac).ok_or(())?;
    if authtime != enc_tkt.authtime.timestamp() {
        return Err(());
    }
    let di = crate::pac::DelegationInfo::decode(
        pac.get_buffer(crate::pac::PAC_DELEGATION_INFO)
            .map_err(|_| ())?,
    )
    .map_err(|_| ())?;
    if target_server.is_some_and(|t| proxy_target_string(t) != di.proxy_target) {
        return Err(());
    }
    let client = impersonator_string(&enc_tkt.cname, &text(&enc_tkt.crealm));
    match di.transited_services.last() {
        Some(last) if *last == client => Ok(()),
        _ => Err(()),
    }
}

/// The S4U2Proxy target without realm (`KRB5_PRINCIPAL_UNPARSE_DISPLAY |
/// NO_REALM`).
pub(super) fn proxy_target_string(name: &PrincipalName) -> String {
    unparse_name(name, "", true, false)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gs(s: &str) -> rasn::types::GeneralString {
        rasn::types::GeneralString::from_bytes(s.as_bytes()).expect("string")
    }

    #[test]
    fn first_field_is_the_user_id_as_encoded_by_the_sender() {
        let user_id = S4uUserId {
            nonce: 7,
            cname: Some(PrincipalName::new_principal("alice")),
            crealm: gs("R"),
            subject_certificate: None,
            options: None,
        };
        let pa = PaS4uX509User {
            user_id: user_id.clone(),
            cksum: Checksum {
                cksumtype: 16,
                checksum: vec![1; 12].into(),
            },
        };
        let der = rasn::der::encode(&pa).expect("encode");
        assert_eq!(
            first_field(&der).expect("field"),
            rasn::der::encode(&user_id).expect("user id")
        );
        assert!(first_field(&[0x30]).is_none());
    }

    #[test]
    fn delegation_list_names_ignore_name_type_and_default_the_realm() {
        let host = PrincipalName::new_srv_hst("HTTP", "t.example.com");
        assert!(list_names("HTTP/t.example.com", "R", &host, "R"));
        assert!(list_names("HTTP/t.example.com@R", "X", &host, "R"));
        assert!(!list_names("HTTP/t.example.com@OTHER", "R", &host, "R"));
        assert!(!list_names("HTTP/u.example.com", "R", &host, "R"));
    }

    #[test]
    fn for_user_checksum_covers_name_type_components_realm_and_package() {
        let key = EncryptionKey::new(18, vec![5; 32]);
        let user = PrincipalName::new_principal("alice");
        let mut data = 1i32.to_le_bytes().to_vec();
        data.extend_from_slice(b"aliceR");
        data.extend_from_slice(b"Kerberos");
        let sum = hmac_md5_checksum(key.key_bytes(), 17, &data).expect("sum");
        let req = PaForUser {
            user_name: user.clone(),
            user_realm: gs("R"),
            cksum: Checksum {
                cksumtype: CKSUMTYPE_HMAC_MD5,
                checksum: sum.to_vec().into(),
            },
            auth_package: gs("Kerberos"),
        };
        assert!(verify_for_user(&key, &req).is_ok());
        let mut bad = req.clone();
        bad.user_name = PrincipalName::new_principal("bob");
        assert_eq!(
            verify_for_user(&key, &bad).expect_err("modified").code,
            KRB_AP_ERR_MODIFIED
        );
        let mut unkeyed = req;
        unkeyed.cksum.cksumtype = 7;
        assert_eq!(
            verify_for_user(&key, &unkeyed).expect_err("inapp").code,
            KRB_AP_ERR_INAPP_CKSUM
        );
    }

    fn client_info(name: &str, authtime: i64) -> Vec<u8> {
        let nt = (u64::try_from(authtime).expect("time") + 11_644_473_600) * 10_000_000;
        let utf16: Vec<u8> = name.encode_utf16().flat_map(u16::to_le_bytes).collect();
        let mut b = nt.to_le_bytes().to_vec();
        b.extend_from_slice(&u16::try_from(utf16.len()).expect("len").to_le_bytes());
        b.extend(utf16);
        b
    }

    fn deleg_pac(client: &str, authtime: i64, deleg: Option<(&str, &[&str])>) -> Pac {
        let mut pac = Pac::new();
        pac.add_buffer(crate::pac::PAC_CLIENT_INFO, &client_info(client, authtime))
            .expect("client info");
        if let Some((target, transited)) = deleg {
            let di = crate::pac::DelegationInfo {
                proxy_target: target.into(),
                transited_services: transited.iter().map(|s| s.to_string()).collect(),
            };
            pac.add_buffer(crate::pac::PAC_DELEGATION_INFO, &di.encode())
                .expect("delegation info");
        }
        pac
    }

    fn cross_tgt(cname: PrincipalName, crealm: &str, authtime: i64) -> EncTicketPart {
        let t = chrono::DateTime::from_timestamp(authtime, 0)
            .expect("time")
            .fixed_offset();
        EncTicketPart {
            flags: crate::types::KerberosFlags::new(TicketFlags::empty()),
            key: EncryptionKey::new(18, vec![1; 32]),
            crealm: gs(crealm),
            cname,
            transited: crate::types::TransitedEncoding {
                tr_type: 1,
                contents: Vec::new().into(),
            },
            authtime: t,
            starttime: None,
            endtime: t,
            renew_till: None,
            caddr: None,
            authorization_data: None,
        }
    }

    #[test]
    fn pac_client_must_carry_a_realm() {
        let (name, realm, t) =
            pac_princ_with_realm(&deleg_pac("alice@R1", 100, None)).expect("with realm");
        assert_eq!(
            name.name_string,
            PrincipalName::new_principal("alice").name_string
        );
        assert_eq!((realm.as_str(), t), ("R1", 100));
        assert!(pac_princ_with_realm(&deleg_pac("alice", 100, None)).is_none());
    }

    #[test]
    fn verify_deleg_pac_checks_authtime_target_and_last_transited_service() {
        let imp = PrincipalName::new_srv_hst("HTTP", "imp.example.com");
        let target = PrincipalName::new_srv_hst("HTTP", "rbcd.example.com");
        let good: &[&str] = &["svc/a@R0", "HTTP/imp.example.com@R2"];
        let tkt = cross_tgt(imp.clone(), "R2", 100);
        let pac = deleg_pac("alice@R1", 100, Some(("HTTP/rbcd.example.com", good)));
        assert!(verify_deleg_pac(&pac, &tkt, Some(&target)).is_ok());
        assert!(verify_deleg_pac(&pac, &tkt, None).is_ok());
        let other = PrincipalName::new_srv_hst("HTTP", "other.example.com");
        assert!(verify_deleg_pac(&pac, &tkt, Some(&other)).is_err());
        assert!(verify_deleg_pac(&pac, &cross_tgt(imp.clone(), "R2", 101), None).is_err());
        assert!(verify_deleg_pac(&pac, &cross_tgt(imp.clone(), "R3", 100), None).is_err());
        let stale: &[&str] = &["HTTP/imp.example.com@R2", "svc/a@R0"];
        let pac = deleg_pac("alice@R1", 100, Some(("HTTP/rbcd.example.com", stale)));
        assert!(verify_deleg_pac(&pac, &tkt, None).is_err());
        let pac = deleg_pac("alice@R1", 100, Some(("HTTP/rbcd.example.com", &[])));
        assert!(verify_deleg_pac(&pac, &tkt, None).is_err());
        assert!(verify_deleg_pac(&deleg_pac("alice@R1", 100, None), &tkt, None).is_err());
        let pac = deleg_pac("alice", 100, Some(("HTTP/rbcd.example.com", good)));
        assert!(verify_deleg_pac(&pac, &tkt, None).is_err());
    }
}
