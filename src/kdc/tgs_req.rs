//! TGS-REQ processing (MIT do_tgs_req.c `process_tgs_req`,
//! kdc_util.c `kdc_process_tgs_req` / `kdc_rd_ap_req`, tgs_policy.c).

use chrono::{DateTime, Utc};
use rasn::types::OctetString;

use super::db::KvnoSel;
use super::error::{ap_error_code, ErrorContext, KdcError};
use super::policy::{
    check_tgs_opts, check_tgs_svc_policy, check_tgs_times, get_ticket_endtime, get_ticket_flags,
    get_ticket_renewtime, kerberos_time, select_session_keytype, ts, HeaderRenewal, Times,
    UNSUPPORTED_OPTIONS,
};
use super::preauth::{enc_pa_rep_padata, find_padata};
use super::reqbody::raw_req_body;
use super::{is_tgs_principal, names_equal, random_key, Kdc, PrincipalStore};
use crate::crypto::{find_cksumtype, find_etype, key_usage};
use crate::protocol::ap::{encrypt_ticket_part, ApError, AuthContext, AuthContextFlags, KeySource};
use crate::types::error_codes::*;
use crate::types::{
    ApOptions, ApReq, AuthorizationDataElement, Checksum, EncKdcRepPart, EncTgsRepPart,
    EncryptedData, EncryptionKey, KdcOptions, KdcRep, KdcReq, KerberosFlags, KerberosTime,
    LastReqEntry, PaDataType, PrincipalName, TgsRep, TicketFlags,
};
use crate::Krb5Error;

/// KRB5_AUTHDATA_FX_ARMOR.
const AUTHDATA_FX_ARMOR: i32 = 71;
/// KRB5_AUTHDATA_IF_RELEVANT.
const AUTHDATA_IF_RELEVANT: i32 = 1;

/// Options that make the header ticket's server the requested server
/// (MIT kdc_util.h `NON_TGT_OPTION`).
const NON_TGT_OPTION: KdcOptions = KdcOptions::FORWARDED
    .union(KdcOptions::PROXY)
    .union(KdcOptions::RENEW)
    .union(KdcOptions::VALIDATE);

/// Key source holding the already-selected header-ticket server key
/// (`krb5_auth_con_setuseruserkey`, kdc_util.c:333).
struct FixedKey(EncryptionKey);

impl KeySource for FixedKey {
    fn get_key(
        &self,
        _server: &PrincipalName,
        _realm: &[u8],
        _kvno: Option<i32>,
        _etype: i32,
    ) -> Result<EncryptionKey, ApError> {
        Ok(self.0.clone())
    }
}

fn has_fast_armor(authdata: Option<&[AuthorizationDataElement]>) -> bool {
    authdata.is_some_and(|list| {
        list.iter().any(|el| match el.ad_type {
            AUTHDATA_FX_ARMOR => true,
            AUTHDATA_IF_RELEVANT => rasn::der::decode::<Vec<AuthorizationDataElement>>(&el.ad_data)
                .is_ok_and(|inner| has_fast_armor(Some(&inner))),
            _ => false,
        })
    })
}

/// `comp_cksum` (MIT kdc_util.c:116-140): the checksum must be a keyed
/// type matching the header session key.
///
/// Deviation: legacy/unkeyed checksum types (1-14) are all reported as
/// KRB_AP_ERR_INAPP_CKSUM; MIT verifies collision-proof unkeyed types.
fn comp_cksum(session: &EncryptionKey, body: &[u8], cksum: &Checksum) -> Result<(), KdcError> {
    const STATUS: &str = "PROCESS_TGS";
    match cksum.cksumtype {
        15 | 16 | 19 | 20 => {}
        1..=14 => return Err(KdcError::new(KRB_AP_ERR_INAPP_CKSUM, STATUS)),
        _ => return Err(KdcError::new(KDC_ERR_SUMTYPE_NOSUPP, STATUS)),
    }
    let profile = find_cksumtype(cksum.cksumtype)
        .map_err(|_| KdcError::new(KDC_ERR_SUMTYPE_NOSUPP, STATUS))?;
    if profile.etype() != session.keytype {
        return Err(KdcError::generic(STATUS));
    }
    profile
        .verify_checksum(
            session.key_bytes(),
            key_usage::TGS_REQ_AUTH_CKSUM,
            body,
            cksum.checksum.as_ref(),
        )
        .map_err(|_| KdcError::new(KRB_AP_ERR_BAD_INTEGRITY, STATUS))
}

fn optional_time(t: i64) -> Option<KerberosTime> {
    (t != 0).then(|| kerberos_time(t))
}

fn realm_string(g: &rasn::types::GeneralString) -> String {
    String::from_utf8_lossy(g.as_bytes()).to_string()
}

impl<S: PrincipalStore> Kdc<S> {
    /// MIT `process_tgs_req` (do_tgs_req.c:1163-1229).
    pub(super) fn process_tgs_req(
        &self,
        req: &KdcReq,
        raw: &[u8],
        now: DateTime<Utc>,
        ctx: &mut ErrorContext,
    ) -> Result<Vec<u8>, KdcError> {
        const STATUS: &str = "PROCESS_TGS";
        let kdc_time = now.timestamp();
        if req.msg_type != 12 {
            return Err(KdcError::generic("VALIDATE_MESSAGE_TYPE"));
        }
        let permitted = self.permitted();

        // kdc_process_tgs_req (kdc_util.c:143-280).
        let pa_tgs = find_padata(req.padata.as_deref(), PaDataType::TgsReq)
            .ok_or_else(|| KdcError::new(KDC_ERR_PADATA_TYPE_NOSUPP, STATUS))?;
        let ap_bytes = pa_tgs.padata_value.as_ref();
        let ap: ApReq = rasn::der::decode(ap_bytes).map_err(|_| KdcError::generic(STATUS))?;
        if ap
            .ap_options
            .intersects(ApOptions::USE_SESSION_KEY | ApOptions::MUTUAL_REQUIRED)
        {
            return Err(KdcError::new(KDC_ERR_POLICY, "SESSION KEY or MUTUAL"));
        }

        // kdc_rd_ap_req / kdc_get_server_key / find_server_key
        // (kdc_util.c:293-457).
        let tkt_realm = realm_string(&ap.ticket.realm);
        let header_server = self
            .lookup(&ap.ticket.sname, &tkt_realm, STATUS)
            .ok()
            .flatten()
            .filter(|s| {
                !s.attributes.intersects(
                    super::PrincipalAttributes::DISALLOW_SVR
                        | super::PrincipalAttributes::DISALLOW_ALL_TIX,
                )
            })
            .ok_or_else(|| KdcError::new(KDC_ERR_S_PRINCIPAL_UNKNOWN, "UNKNOWN_SERVER"))?;
        let local_tgs = is_tgs_principal(&ap.ticket.sname)
            && ap.ticket.sname.name_string[1].as_bytes() == ap.ticket.realm.as_bytes();
        let etype = (!local_tgs).then_some(ap.ticket.enc_part.etype);
        let kvno = match ap.ticket.enc_part.kvno {
            Some(k) if k != 0 => {
                KvnoSel::Exact(u32::try_from(k).map_err(|_| KdcError::generic(STATUS))?)
            }
            _ => KvnoSel::Any,
        };
        let header_key = header_server
            .find_key(etype, kvno, &permitted)
            .ok_or_else(|| KdcError::generic(STATUS))?
            .key
            .clone();

        // Don't use a replay cache (kdc_util.c:190). rd_req reads the wall
        // clock; carry the injected clock as an offset.
        let mut auth_ctx = AuthContext::new();
        auth_ctx.set_flags(AuthContextFlags::empty());
        auth_ctx.set_tgs_req(true);
        auth_ctx.set_clockskew(self.config.clockskew);
        auth_ctx.set_time_offset(now - Utc::now());
        auth_ctx.set_permitted_etypes(Some(self.config.supported_enctypes.clone()));
        let rd = auth_ctx
            .rd_req(ap_bytes, Some(&ap.ticket.sname), &FixedKey(header_key))
            .map_err(|e| match e {
                Krb5Error::Ap(a) => KdcError::new(ap_error_code(a), STATUS),
                _ => KdcError::generic(STATUS),
            })?;
        let header = rd.ticket;
        let auth = rd.authenticator;
        ctx.crealm = Some(realm_string(&header.crealm));
        ctx.cname = Some(header.cname.clone());

        if has_fast_armor(header.authorization_data.as_deref())
            || has_fast_armor(auth.authorization_data.as_deref())
        {
            return Err(KdcError::new(
                KDC_ERR_POLICY,
                "ticket valid only as FAST armor",
            ));
        }

        let cksum = auth
            .cksum
            .as_ref()
            .ok_or_else(|| KdcError::new(KRB_AP_ERR_INAPP_CKSUM, STATUS))?;
        let raw_body = raw_req_body(raw).map_err(|_| KdcError::generic(STATUS))?;
        comp_cksum(&header.key, raw_body, cksum)?;

        // FAST: handled in kdc::fast (next milestone); kdc_find_fast
        // (do_tgs_req.c:634) would replace `req` with the inner request.
        let body = &req.req_body;
        let opts: KdcOptions = *body.kdc_options;
        let sname = body
            .sname
            .as_ref()
            .ok_or_else(|| KdcError::new(KDC_ERR_S_PRINCIPAL_UNKNOWN, "NULL_SERVER"))?;
        let realm = &self.config.realm;

        self.require_local_tgt()?;

        // search_sprinc (do_tgs_req.c:541-581): no referrals.
        let server = self
            .lookup(sname, realm, "LOOKING_UP_SERVER")
            .ok()
            .flatten()
            .ok_or_else(|| KdcError::new(KDC_ERR_S_PRINCIPAL_UNKNOWN, "LOOKING_UP_SERVER"))?;

        // NO_AUTH_DATA_REQUIRED servers skip the client lookup
        // (do_tgs_req.c:771-779).
        let client = if server
            .attributes
            .contains(super::PrincipalAttributes::NO_AUTH_DATA_REQUIRED)
        {
            None
        } else {
            self.lookup(&header.cname, &realm_string(&header.crealm), STATUS)
                .ok()
                .flatten()
        };

        // check_tgs_constraints (tgs_policy.c:668-730).
        if opts.intersects(UNSUPPORTED_OPTIONS) {
            return Err(KdcError::new(KDC_ERR_BADOPTION, "UNSUPPORTED OPTION"));
        }
        let header_flags: TicketFlags = *header.flags;
        let header_renew_till = header.renew_till.as_ref().map(ts).unwrap_or(0);
        check_tgs_opts(opts, header_flags)?;
        check_tgs_times(opts, header_renew_till, kdc_time)?;
        if opts.intersects(NON_TGT_OPTION) {
            if !names_equal(&ap.ticket.sname, sname) || ap.ticket.realm != body.realm {
                return Err(KdcError::new(
                    KDC_ERR_SERVER_NOMATCH,
                    "SERVER DIDN'T MATCH TICKET FOR RENEW/FORWARD/ETC",
                ));
            }
        } else {
            if !is_tgs_principal(&ap.ticket.sname) {
                return Err(KdcError::new(KRB_AP_ERR_NOT_US, "BAD TGS SERVER NAME"));
            }
            if ap.ticket.sname.name_string[1].as_bytes() != body.realm.as_bytes() {
                return Err(KdcError::new(KRB_AP_ERR_NOT_US, "BAD TGS SERVER INSTANCE"));
            }
        }

        // check_tgs_policy (tgs_policy.c:732-771).
        check_tgs_svc_policy(
            opts,
            &server,
            header_flags,
            is_tgs_principal(&ap.ticket.sname),
            kdc_time,
        )?;

        // get_ticket_flags / compute_ticket_times (do_tgs_req.c:809-852).
        let mut flags = get_ticket_flags(opts, client.as_ref(), &server, Some(header_flags));
        let limits = self.limits();
        let req_till = ts(&body.till);
        let req_rtime = body.rtime.as_ref().map(ts).unwrap_or(0);
        let header_end = ts(&header.endtime);
        let header_start = header
            .starttime
            .as_ref()
            .map(ts)
            .unwrap_or(ts(&header.authtime));
        let mut times = Times {
            authtime: ts(&header.authtime),
            starttime: kdc_time,
            endtime: 0,
            renew_till: 0,
        };
        times.endtime = if opts.contains(KdcOptions::RENEW) {
            header_renew_till.min(kdc_time + (header_end - header_start))
        } else {
            get_ticket_endtime(
                &limits,
                times.starttime,
                header_end,
                req_till,
                client.as_ref(),
                &server,
            )
        };
        get_ticket_renewtime(
            &limits,
            opts,
            req_rtime,
            req_till,
            Some(HeaderRenewal {
                flags: header_flags,
                renew_till: header_renew_till,
            }),
            client.as_ref(),
            &server,
            &mut flags,
            &mut times,
        );
        if times.starttime == times.authtime {
            times.starttime = 0;
        }

        // Transited-path check (do_tgs_req.c:924-948): with no capaths
        // support only an empty transited list can be verified, and a
        // request that disables the check cannot set the policy flag, which
        // reject_bad_transit (MIT default) refuses.
        if opts.contains(KdcOptions::DISABLE_TRANSITED_CHECK)
            || !header.transited.contents.is_empty()
        {
            return Err(KdcError::new(KDC_ERR_POLICY, "BAD_TRANSIT"));
        }
        flags |= TicketFlags::TRANSITED_POLICY_CHECKED;

        // tgs_issue_ticket (do_tgs_req.c:955-1139).
        let session_etype = select_session_keytype(&server, &body.etype, &permitted)
            .ok_or_else(|| KdcError::new(KDC_ERR_ETYPE_NOSUPP, "BAD_ENCRYPTION_TYPE"))?;
        let session_key = random_key(session_etype)?;
        let server_key = server
            .find_key(None, KvnoSel::Highest, &permitted)
            .ok_or_else(|| KdcError::generic("FINDING_SERVER_KEY"))?;

        let reply_key = auth.subkey.clone().unwrap_or_else(|| header.key.clone());
        let reply_usage = if auth.subkey.is_some() {
            key_usage::TGS_REP_ENCPART_SUBKEY
        } else {
            key_usage::TGS_REP_ENCPART_SESSKEY
        };

        let mut enc_padata = Vec::new();
        if find_padata(req.padata.as_deref(), PaDataType::ReqEncPaRep).is_some() {
            flags |= TicketFlags::ENC_PA_REP;
            enc_padata.push(enc_pa_rep_padata(&reply_key, raw)?);
        }

        let (ticket_caddr, reply_caddr) = if !opts.contains(KdcOptions::RENEW)
            && opts.intersects(KdcOptions::FORWARDED | KdcOptions::PROXY)
        {
            (body.addresses.clone(), body.addresses.clone())
        } else {
            (header.caddr.clone(), None)
        };

        let tkt_flags = KerberosFlags::new(flags);
        let part = crate::types::EncTicketPart {
            flags: tkt_flags,
            key: session_key.clone(),
            crealm: header.crealm.clone(),
            cname: header.cname.clone(),
            transited: header.transited.clone(),
            authtime: kerberos_time(times.authtime),
            starttime: optional_time(times.starttime),
            endtime: kerberos_time(times.endtime),
            renew_till: optional_time(times.renew_till),
            caddr: ticket_caddr,
            authorization_data: None,
        };
        let kvno =
            i32::try_from(server_key.kvno).map_err(|_| KdcError::generic("FINDING_SERVER_KEY"))?;
        let ticket_sname = if opts.contains(KdcOptions::RENEW) {
            ap.ticket.sname.clone()
        } else {
            sname.clone()
        };
        let ticket = encrypt_ticket_part(
            &server_key.key,
            Some(kvno),
            realm,
            ticket_sname.clone(),
            &part,
        )?;

        let enc = EncTgsRepPart(EncKdcRepPart {
            key: session_key,
            last_req: vec![LastReqEntry {
                lr_type: 0,
                lr_value: kerberos_time(0),
            }],
            nonce: body.nonce,
            key_expiration: None,
            flags: tkt_flags,
            authtime: part.authtime,
            starttime: part.starttime,
            endtime: part.endtime,
            renew_till: part.renew_till,
            srealm: body.realm.clone(),
            sname: ticket_sname,
            caddr: reply_caddr,
            encrypted_pa_data: (!enc_padata.is_empty()).then_some(enc_padata),
        });
        let profile = find_etype(reply_key.keytype)
            .map_err(|_| KdcError::new(KDC_ERR_ETYPE_NOSUPP, "BAD_ETYPE"))?;
        let cipher = profile
            .encrypt(
                reply_key.key_bytes(),
                reply_usage,
                &rasn::der::encode(&enc)?,
            )
            .map_err(|_| KdcError::generic("ENCRYPT_REPLY"))?;

        let rep = TgsRep(KdcRep {
            pvno: 5,
            msg_type: 13,
            padata: None,
            crealm: header.crealm.clone(),
            cname: header.cname.clone(),
            ticket,
            enc_part: EncryptedData {
                etype: reply_key.keytype,
                kvno: None,
                cipher: OctetString::from(cipher),
            },
        });
        Ok(rasn::der::encode(&rep)?)
    }
}
