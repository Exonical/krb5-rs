//! TGS-REQ processing (MIT do_tgs_req.c `process_tgs_req`,
//! kdc_util.c `kdc_process_tgs_req` / `kdc_rd_ap_req`, tgs_policy.c).

use chrono::{DateTime, Utc};
use rasn::types::OctetString;

use super::authdata::S4uPac;
use super::db::KvnoSel;
use super::error::{
    ap_error_code, general_string, krbtgt_name, ErrorContext, KdcError, KRB_AP_ERR_ILL_CR_TKT,
};
use super::fast::{anonymous_client, FastInputs};
use super::policy::{
    check_tgs_opts, check_tgs_svc_policy, check_tgs_times, get_ticket_endtime, get_ticket_flags,
    get_ticket_renewtime, kerberos_time, select_session_keytype, ts, HeaderRenewal, Times,
    UNSUPPORTED_OPTIONS,
};
use super::preauth::{enc_pa_rep_padata, find_padata};
use super::reqbody::raw_req_body;
use super::s4u::{impersonator_string, pac_options_reply};
use super::{is_tgs_principal, names_equal, random_key, Kdc, PrincipalEntry, PrincipalStore};
use crate::crypto::{find_cksumtype, find_etype, key_usage};
use crate::locate::host_realm;
use crate::protocol::ap::{encrypt_ticket_part, ApError, AuthContext, AuthContextFlags, KeySource};
use crate::protocol::transit::{
    add_to_transited, check_transited_list, walk_realm_tree, REALM_BRANCH_CHAR,
};
use crate::types::error_codes::*;
use crate::types::{
    ApOptions, ApReq, AuthorizationDataElement, Checksum, EncKdcRepPart, EncTgsRepPart,
    EncryptedData, EncryptionKey, KdcOptions, KdcRep, KdcReq, KerberosFlags, KerberosTime,
    LastReqEntry, PaDataType, PrincipalName, TgsRep, TicketFlags, TransitedEncoding,
};
use crate::Krb5Error;

/// KRB5_AUTHDATA_FX_ARMOR.
const AUTHDATA_FX_ARMOR: i32 = 71;
/// KRB5_AUTHDATA_IF_RELEVANT.
const AUTHDATA_IF_RELEVANT: i32 = 1;

/// Options that make the header ticket's server the requested server
/// (MIT kdc_util.h `NON_TGT_OPTION`).
pub(super) const NON_TGT_OPTION: KdcOptions = KdcOptions::FORWARDED
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

/// MIT `is_cross_tgs_principal` (kdc_util.c:98-103): a TGS principal whose
/// instance is not its own realm.
fn is_cross_tgs(name: &PrincipalName, realm: &str) -> bool {
    is_tgs_principal(name) && name.name_string[1].as_bytes() != realm.as_bytes()
}

/// Whether `list` names `item` or `*` (MIT `in_list`, do_tgs_req.c:420-435).
fn in_list(list: &[String], item: &str) -> bool {
    list.iter().any(|l| l == item || l == "*")
}

impl<S: PrincipalStore> Kdc<S> {
    /// `is_referral_req` (do_tgs_req.c:437-478).
    fn is_referral_req(&self, opts: KdcOptions, sname: &PrincipalName) -> bool {
        if !opts.contains(KdcOptions::CANONICALIZE)
            || opts.contains(KdcOptions::ENC_TKT_IN_SKEY)
            || sname.name_string.len() != 2
        {
            return false;
        }
        let stype = String::from_utf8_lossy(sname.name_string[0].as_bytes()).to_string();
        match sname.name_type {
            0 if !in_list(&self.config.host_based_services, &stype) => return false,
            0 | 2 | 3 => {}
            _ => return false,
        }
        !in_list(&self.config.no_host_referral, &stype)
    }

    /// `find_referral_tgs` (do_tgs_req.c:480-519): `krbtgt/<host realm>@realm`
    /// for an FQDN host in another realm; `[domain_realm]` comes from the
    /// KDC's krb5.conf.
    fn find_referral_tgs(
        &self,
        opts: KdcOptions,
        sname: &PrincipalName,
        realm: &str,
    ) -> Option<PrincipalName> {
        if !self.is_referral_req(opts, sname) {
            return None;
        }
        let hostname = String::from_utf8_lossy(sname.name_string[1].as_bytes()).to_string();
        if !hostname.contains('.') {
            return None;
        }
        let profile = self.config.realm_profile.as_ref()?;
        let host_realm = host_realm(profile, &hostname).into_iter().next()?;
        if host_realm.is_empty() || host_realm == realm {
            return None;
        }
        let name = PrincipalName {
            name_type: 2,
            name_string: vec![
                general_string("krbtgt").ok()?,
                general_string(&host_realm).ok()?,
            ],
        };
        Some(name)
    }

    /// `find_alternate_tgs` (do_tgs_req.c:371-418): the cross-realm TGT
    /// nearest the target on the realm path, trying the target first and
    /// skipping the local-realm entry.
    async fn find_alternate_tgs(
        &self,
        princ: &PrincipalName,
        realm: &str,
    ) -> Option<PrincipalEntry> {
        let target = princ.name_string[1].as_bytes();
        let hops = walk_realm_tree(
            realm.as_bytes(),
            target,
            self.config.realm_profile.as_ref(),
            REALM_BRANCH_CHAR,
        )
        .ok()?;
        for hop in hops.iter().skip(1).rev() {
            let Ok(name) = krbtgt_name(&String::from_utf8_lossy(&hop.instance)) else {
                continue;
            };
            if let Some(found) = self
                .lookup(&name, realm, "LOOKING_UP_SERVER")
                .await
                .ok()
                .flatten()
            {
                return Some(found);
            }
        }
        None
    }

    /// `search_sprinc` (do_tgs_req.c:541-581): the requested server, else a
    /// referral TGT, else an alternate cross-realm TGT. Returns whether a
    /// referral/alternate TGT is being issued (:668-671).
    async fn search_sprinc(
        &self,
        opts: KdcOptions,
        sname: &PrincipalName,
        realm: &str,
    ) -> Result<(PrincipalEntry, bool), KdcError> {
        let unknown = || KdcError::new(KDC_ERR_S_PRINCIPAL_UNKNOWN, "LOOKING_UP_SERVER");
        if let Some(found) = self
            .lookup(sname, realm, "LOOKING_UP_SERVER")
            .await
            .ok()
            .flatten()
        {
            return Ok((found, false));
        }
        if opts.intersects(NON_TGT_OPTION | KdcOptions::ENC_TKT_IN_SKEY) {
            return Err(unknown());
        }
        let mut princ = sname.clone();
        if !is_cross_tgs(sname, realm) {
            let reftgs = self
                .find_referral_tgs(opts, sname, realm)
                .ok_or_else(unknown)?;
            if let Some(found) = self
                .lookup(&reftgs, realm, "LOOKING_UP_SERVER")
                .await
                .ok()
                .flatten()
            {
                return Ok((found, true));
            }
            princ = reftgs;
        }
        let found = self
            .find_alternate_tgs(&princ, realm)
            .await
            .ok_or_else(unknown)?;
        Ok((found, true))
    }

    /// MIT `process_tgs_req` (do_tgs_req.c:1163-1229).
    pub(super) async fn process_tgs_req(
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
            .await
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
            .rd_req(
                ap_bytes,
                Some(&ap.ticket.sname),
                &FixedKey(header_key.clone()),
            )
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

        // kdc_find_fast (do_tgs_req.c:631-639): implicit or AP-REQ armor, the
        // inner request replaces the outer one.
        let inner = self
            .find_fast(
                req,
                FastInputs {
                    checksummed: ap_bytes,
                    tgs_subkey: auth.subkey.as_ref(),
                    tgs_session: Some(&header.key),
                },
                now,
                &mut ctx.fast,
            )
            .await
            .map_err(|e| KdcError {
                e_text: Some("FIND_FAST".into()),
                ..e
            })?;
        let req = inner.as_ref().unwrap_or(req);
        let body = &req.req_body;
        let fast_ctx = ctx.fast.take();
        let (crealm, cname) = (ctx.crealm.take(), ctx.cname.take());
        *ctx = self.request_context(req, false);
        ctx.crealm = crealm;
        ctx.cname = cname;
        ctx.fast = fast_ctx;
        let opts: KdcOptions = *body.kdc_options;
        let sname = body
            .sname
            .as_ref()
            .ok_or_else(|| KdcError::new(KDC_ERR_S_PRINCIPAL_UNKNOWN, "NULL_SERVER"))?;
        let realm = &self.config.realm;

        let local_tgt = self.require_local_tgt().await?;

        // get_verified_pac (do_tgs_req.c:636-644): HEADER_PAC.
        let header_pac =
            self.verify_header_pac(&header, &ap.ticket.sname, &header_key, &local_tgt)?;

        let (mut server, is_referral) = self.search_sprinc(opts, sname, realm).await?;

        // The request is cross-realm if the header ticket server is not from
        // this realm (do_tgs_req.c:693-695).
        let client_realm = realm_string(&header.crealm);
        let is_crossrealm = tkt_realm != *realm;

        // S4U2Self padata names the requested client; S4U2Proxy takes the
        // evidence ticket (do_tgs_req.c:692-756).
        let s4u2self = self
            .process_s4u2self_req(req, &server, auth.subkey.as_ref(), &header.key)
            .await?;
        if s4u2self.is_some() {
            // Authorization data stays enabled for S4U2Self (:712-717).
            server
                .attributes
                .remove(super::PrincipalAttributes::NO_AUTH_DATA_REQUIRED);
        }
        let proxy = opts.contains(KdcOptions::CNAME_IN_ADDL_TKT);
        let stkt = if proxy {
            match body.additional_tickets.as_ref().and_then(|t| t.first()) {
                Some(t) => Some(self.decrypt_2ndtkt(t, &local_tgt).await?),
                None => None,
            }
        } else {
            None
        };
        let subject_tkt: &crate::types::EncTicketPart = stkt.as_ref().map_or(&header, |e| &e.part);
        let (tkt_cname, tkt_crealm) = match (&s4u2self, &stkt) {
            (Some(s), _) if !is_referral => (s.user.clone(), general_string(&s.user_realm)?),
            (None, Some(e)) if !is_referral => (e.part.cname.clone(), e.part.crealm.clone()),
            _ => (header.cname.clone(), header.crealm.clone()),
        };
        let tkt_realm_str = realm_string(&tkt_crealm);
        let subject_realm = realm_string(&subject_tkt.crealm);
        let (subject_client_name, subject_client_realm) = match &s4u2self {
            Some(s) => (s.user.clone(), s.user_realm.clone()),
            None => (subject_tkt.cname.clone(), subject_realm.clone()),
        };

        // The client is looked up only when it belongs to this realm, and
        // NO_AUTH_DATA_REQUIRED servers skip the lookup (do_tgs_req.c:757-779).
        let client = if let Some(s) = &s4u2self {
            s.client.clone()
        } else if server
            .attributes
            .contains(super::PrincipalAttributes::NO_AUTH_DATA_REQUIRED)
            || subject_realm != *realm
        {
            None
        } else {
            self.lookup(&subject_tkt.cname, &subject_realm, STATUS)
                .await
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

        // check_tgs_s4u2self, or check_tgs_lineage (tgs_policy.c:248-258): no
        // local user tickets issued by a foreign realm.
        if let Some(s) = &s4u2self {
            self.check_tgs_s4u2self(
                s,
                opts,
                &server,
                &header,
                header_pac.as_ref(),
                is_crossrealm,
                is_referral,
                kdc_time,
            )?;
        } else if is_crossrealm && client_realm == *realm {
            return Err(KdcError::new(KDC_ERR_POLICY, "INVALID LINEAGE"));
        }

        if proxy {
            self.check_tgs_s4u2proxy(
                opts,
                sname,
                &header,
                header_pac.as_ref(),
                stkt.as_ref(),
                is_crossrealm,
                is_referral,
            )?;
        }

        // check_normal_tgs_pac (tgs_policy.c:600-625): the PAC client info
        // must match the header ticket's client (no realm).
        if let (Some(pac), false) = (&header_pac, proxy || s4u2self.is_some()) {
            let authtime = header.authtime.timestamp();
            if pac
                .verify(authtime, Some((&header.cname, &client_realm)), None, None)
                .is_err()
            {
                return Err(KdcError::new(KDC_ERR_BADOPTION, "HEADER_PAC"));
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
        if let Some(e) = &stkt {
            self.check_s4u2proxy_policy(
                req,
                (&header.cname, &client_realm),
                &e.server,
                (sname, &realm_string(&body.realm)),
                &server,
                is_crossrealm,
                is_referral,
            )?;
        }

        let s4u_subject_client = if (s4u2self.is_some() || proxy) && subject_client_realm == *realm
        {
            match &client {
                Some(c) => Some(c.clone()),
                None => {
                    self.lookup(
                        &subject_client_name,
                        &subject_client_realm,
                        "LOOKING_UP_CLIENT",
                    )
                    .await?
                }
            }
        } else {
            None
        };

        // Not in MIT: re-check the header ticket's local client
        // (docs/architecture/kdb.md §7.4).
        let header_client = if client_realm == *realm {
            match (&client, &s4u2self, proxy) {
                (Some(c), None, false) => Some(c.clone()),
                _ => {
                    self.lookup(&header.cname, &client_realm, "LOOKING_UP_CLIENT")
                        .await?
                }
            }
        } else {
            None
        };
        // MIT ignores a missing result from this lookup (do_tgs_req.c:774-778); this
        // extension rejects a missing local client only when re-checking is on.
        if client_realm == *realm && self.config.tgs_recheck_client && header_client.is_none() {
            return Err(KdcError::new(
                KDC_ERR_C_PRINCIPAL_UNKNOWN,
                "CLIENT_NOT_FOUND",
            ));
        }
        if let Some(c) = &header_client {
            if self.config.tgs_recheck_client {
                self.recheck_tgs_client(c, kdc_time).await?;
            }
        }
        if proxy {
            self.recheck_s4u2proxy_subject(
                s4u_subject_client.as_ref(),
                subject_client_realm == *realm,
                kdc_time,
            )
            .await?;
        }
        self.gate_tgs_principals(header_client.as_ref(), s4u_subject_client.as_ref(), &server)
            .await?;

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
            authtime: ts(&subject_tkt.authtime),
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
        if s4u2self.is_some() && !is_referral {
            Self::s4u2self_forwardable(&server, &mut flags);
        }

        // The transited list implied by the request (do_tgs_req.c:787-806):
        // unchanged unless this is a cross-realm request for a client of
        // another realm than the header ticket's issuer.
        let transited = if !is_crossrealm || tkt_realm == tkt_realm_str {
            header.transited.clone()
        } else {
            if header.transited.tr_type != 1 {
                return Err(KdcError::new(
                    KDC_ERR_TRTYPE_NOSUPP,
                    "VALIDATE_TRANSIT_TYPE",
                ));
            }
            let contents = add_to_transited(
                header.transited.contents.as_ref(),
                tkt_realm.as_bytes(),
                tkt_realm_str.as_bytes(),
                body.realm.as_bytes(),
            )
            .map_err(|_| KdcError::new(KRB_AP_ERR_ILL_CR_TKT, "ADD_TO_TRANSITED_LIST"))?;
            TransitedEncoding {
                tr_type: 1,
                contents: OctetString::from(contents),
            }
        };

        // Transited-path check (do_tgs_req.c:924-948): skipped when the
        // request disables it; otherwise a failure only withholds
        // TRANSITED_POLICY_CHECKED. reject_bad_transit then refuses an
        // unchecked path (:951-958, KRB5KDC_ERR_POLICY).
        if !opts.contains(KdcOptions::DISABLE_TRANSITED_CHECK)
            && check_transited_list(
                transited.contents.as_ref(),
                subject_realm.as_bytes(),
                body.realm.as_bytes(),
                self.config.realm_profile.as_ref(),
            )
            .is_ok()
        {
            flags |= TicketFlags::TRANSITED_POLICY_CHECKED;
        }
        if self.config.reject_bad_transit && !flags.contains(TicketFlags::TRANSITED_POLICY_CHECKED)
        {
            return Err(KdcError::new(KDC_ERR_POLICY, "BAD_TRANSIT"));
        }

        // tgs_issue_ticket (do_tgs_req.c:955-1139).
        let session_etype = select_session_keytype(&server, &body.etype, &permitted)
            .ok_or_else(|| KdcError::new(KDC_ERR_ETYPE_NOSUPP, "BAD_ENCRYPTION_TYPE"))?;
        let session_key = random_key(session_etype)?;
        let server_key = server
            .find_key(None, KvnoSel::Highest, &permitted)
            .ok_or_else(|| KdcError::generic("FINDING_SERVER_KEY"))?;

        let initial_reply_key = auth.subkey.clone().unwrap_or_else(|| header.key.clone());
        let reply_usage = if auth.subkey.is_some() {
            key_usage::TGS_REP_ENCPART_SUBKEY
        } else {
            key_usage::TGS_REP_ENCPART_SESSKEY
        };

        let want_enc_pa_rep = find_padata(req.padata.as_deref(), PaDataType::ReqEncPaRep).is_some();
        if want_enc_pa_rep {
            flags |= TicketFlags::ENC_PA_REP;
        }

        let (ticket_caddr, reply_caddr) = if !opts.contains(KdcOptions::RENEW)
            && opts.intersects(KdcOptions::FORWARDED | KdcOptions::PROXY)
        {
            (body.addresses.clone(), body.addresses.clone())
        } else {
            (header.caddr.clone(), None)
        };

        let tkt_flags = KerberosFlags::new(flags);
        let mut part = crate::types::EncTicketPart {
            flags: tkt_flags,
            key: session_key.clone(),
            crealm: tkt_crealm.clone(),
            cname: tkt_cname.clone(),
            transited,
            authtime: kerberos_time(times.authtime),
            starttime: optional_time(times.starttime),
            endtime: kerberos_time(times.endtime),
            renew_till: optional_time(times.renew_till),
            caddr: ticket_caddr,
            authorization_data: None,
        };
        self.issue_tgs_authdata(
            &mut part,
            &server,
            &server_key.key,
            &local_tgt,
            body.enc_authorization_data
                .as_ref()
                .map(|e| (e, &subject_tkt.key, auth.subkey.as_ref())),
            subject_tkt,
            stkt.as_ref()
                .map_or(header_pac.as_ref(), |e| e.pac.as_ref()),
            match (&s4u2self, &stkt) {
                (Some(_), _) => S4uPac::SelfReq,
                (None, Some(e)) => S4uPac::Proxy {
                    target: sname,
                    impersonator: impersonator_string(&e.sname, &e.realm),
                },
                (None, None) => S4uPac::None,
            },
        )?;
        let kvno =
            i32::try_from(server_key.kvno).map_err(|_| KdcError::generic("FINDING_SERVER_KEY"))?;
        let ticket_sname = if opts.contains(KdcOptions::RENEW) {
            ap.ticket.sname.clone()
        } else if is_referral {
            server.name.clone()
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

        // kdc_fast_response_handle_padata / kdc_fast_handle_reply_key
        // (do_tgs_req.c:1090-1097).
        let mut outer_cname = tkt_cname.clone();
        let mut outer_crealm = tkt_crealm.clone();
        let s4u_rep: Vec<crate::types::PaData> = match &s4u2self {
            Some(s) if s.x509 => {
                vec![self.make_s4u2self_rep(s, auth.subkey.as_ref(), &header.key)?]
            }
            _ => Vec::new(),
        };
        let (outer_padata, reply_key) = match ctx.fast.as_mut().filter(|f| f.armor_key.is_some()) {
            Some(fast) => {
                let outer = fast.wrap_reply(
                    s4u_rep,
                    &ticket,
                    (&tkt_realm_str, &tkt_cname),
                    initial_reply_key.keytype,
                    now,
                )?;
                if fast.hide_client() {
                    let (r, n) = anonymous_client()?;
                    outer_crealm = general_string(&r)?;
                    outer_cname = n;
                }
                (Some(outer), fast.reply_key(&initial_reply_key)?)
            }
            None => ((!s4u_rep.is_empty()).then_some(s4u_rep), initial_reply_key),
        };
        let mut enc_padata = if want_enc_pa_rep {
            enc_pa_rep_padata(&reply_key, raw)?
        } else {
            Vec::new()
        };
        enc_padata.extend(pac_options_reply(req.padata.as_deref())?);

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
            padata: outer_padata,
            crealm: outer_crealm,
            cname: outer_cname,
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

impl<S: PrincipalStore> Kdc<S> {
    async fn recheck_s4u2proxy_subject(
        &self,
        subject: Option<&PrincipalEntry>,
        is_local: bool,
        now: i64,
    ) -> Result<(), KdcError> {
        if !is_local || !self.config.tgs_recheck_client {
            return Ok(());
        }
        let subject = subject
            .ok_or_else(|| KdcError::new(KDC_ERR_C_PRINCIPAL_UNKNOWN, "CLIENT_NOT_FOUND"))?;
        self.recheck_tgs_client(subject, now).await
    }

    async fn gate_tgs_principals(
        &self,
        header_client: Option<&PrincipalEntry>,
        subject_client: Option<&PrincipalEntry>,
        server: &PrincipalEntry,
    ) -> Result<(), KdcError> {
        let mut involved = Vec::new();
        involved.extend(header_client);
        involved.extend(subject_client);
        involved.push(server);
        self.consistency_gate(&involved).await
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;
    use crate::kdc::{ConsistencyGate, GateDecision, KdcConfig, MemoryStore};

    struct RecordingGate(Arc<Mutex<Vec<PrincipalName>>>);

    impl ConsistencyGate for RecordingGate {
        async fn check(&self, principals: &[&PrincipalEntry]) -> GateDecision {
            self.0
                .lock()
                .expect("gate record lock")
                .extend(principals.iter().map(|principal| principal.name.clone()));
            GateDecision::Allow
        }
    }

    fn principal(name: &str, attributes: super::super::PrincipalAttributes) -> PrincipalEntry {
        let mut store = MemoryStore::new();
        let name = PrincipalName::new_principal(name);
        store
            .add_random_key(name.clone(), "R", 1, &[18], attributes)
            .expect("principal");
        store.get(&name, "R").expect("entry")
    }

    #[tokio::test]
    async fn tgs_gate_receives_a_local_s4u_subject() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let kdc = Kdc::builder(KdcConfig::new("R"), MemoryStore::new())
            .consistency(RecordingGate(Arc::clone(&seen)))
            .build();
        let subject = principal("impersonated", super::super::PrincipalAttributes::empty());
        let server = principal("service", super::super::PrincipalAttributes::empty());

        kdc.gate_tgs_principals(None, Some(&subject), &server)
            .await
            .expect("gate");

        assert!(seen
            .lock()
            .expect("gate record lock")
            .contains(&subject.name));
    }

    #[tokio::test]
    async fn s4u2proxy_recheck_rejects_a_disabled_subject() {
        let subject = principal(
            "disabled",
            super::super::PrincipalAttributes::DISALLOW_ALL_TIX,
        );
        let kdc = Kdc::new(KdcConfig::new("R"), MemoryStore::new());
        let error = kdc
            .recheck_s4u2proxy_subject(Some(&subject), true, chrono::Utc::now().timestamp())
            .await
            .expect_err("disabled subject must be rejected");
        assert_eq!(error.code, KDC_ERR_CLIENT_REVOKED);
    }

    #[tokio::test]
    async fn s4u2proxy_recheck_rejects_a_missing_local_subject() {
        let kdc = Kdc::new(KdcConfig::new("R"), MemoryStore::new());
        let error = kdc
            .recheck_s4u2proxy_subject(None, true, chrono::Utc::now().timestamp())
            .await
            .expect_err("missing subject must be rejected");
        assert_eq!(error.code, KDC_ERR_C_PRINCIPAL_UNKNOWN);
    }
}
