//! S4U2Self and S4U2Proxy client requests (MIT lib/krb5/krb/s4u_creds.c).
//!
//! S4U2Self follows `krb5_get_self_cred_from_kdc` (s4u_creds.c:530-651):
//! get a TGT to the user's realm, then follow referral TGTs back to the
//! service realm, naming the service by its enterprise name in foreign
//! realms. S4U2Proxy follows `get_proxy_cred_from_kdc` (s4u_creds.c:985-1132):
//! on a proxy referral, get a TGT to the target realm and a proxy TGT in it,
//! then make the final request with the proxy TGT as the evidence ticket.

use super::*;
use crate::crypto::hmac_md5_checksum;
use crate::types::{
    KdcRep, PaForUser, PaPacOptions, PaS4uX509User, S4uUserId, Ticket, PA_PAC_OPTIONS_RBCD,
    S4U_OPTS_USE_REPLY_KEY_USAGE,
};

/// `KRB5_PADATA_FOR_USER`.
const PA_FOR_USER: i32 = 129;
/// `KRB5_PADATA_S4U_X509_USER`.
const PA_S4U_X509_USER: i32 = 130;
/// `KRB5_KEYUSAGE_APP_DATA_CKSUM`.
const KEYUSAGE_APP_DATA_CKSUM: i32 = 17;
/// `KRB5_KEYUSAGE_PA_S4U_X509_USER_REQUEST`.
const KEYUSAGE_S4U_REQUEST: i32 = 26;
/// `KRB5_KEYUSAGE_PA_S4U_X509_USER_REPLY`.
const KEYUSAGE_S4U_REPLY: i32 = 27;
/// `CKSUMTYPE_HMAC_MD5_ARCFOUR`.
const CKSUMTYPE_HMAC_MD5: i32 = -138;
/// `KRB5_NT_SRV_INST`.
const NT_SRV_INST: i32 = 2;
/// `KRB5_NT_ENTERPRISE_PRINCIPAL`.
const NT_ENTERPRISE: i32 = 10;
/// `KDC_TKT_COMMON_MASK` (krb5.hin), the ticket flags `FLAGS2OPTS` copies
/// into the request options (get_creds.c:244).
const KDC_TKT_COMMON_MASK: u32 = 0x5480_0000;
/// `KRB5_KDCREP_MODIFIED`.
const MODIFIED: Krb5Error = Krb5Error::ReplyValidation("S4U reply was modified");
/// `KRB5KRB_AP_WRONG_PRINC`.
const WRONG_PRINC: Krb5Error = Krb5Error::ReplyValidation("S4U reply names the wrong server");
/// `KRB5_ERR_HOST_REALM_UNKNOWN`: a referral to the realm that issued it.
const HOST_REALM_UNKNOWN: Krb5Error =
    Krb5Error::ReplyValidation("S4U referral to the issuing realm");
/// `KRB5KDC_ERR_PADATA_TYPE_NOSUPP` from the final S4U2Self hop
/// (gc_via_tkt.c:257-260).
const NO_S4U2SELF: Krb5Error = Krb5Error::ReplyValidation("KDC does not support S4U2Self");
/// `KRB5KDC_ERR_PADATA_TYPE_NOSUPP` from `check_rbcd_support`.
const NO_RBCD: Krb5Error =
    Krb5Error::ReplyValidation("KDC does not support resource-based constrained delegation");

/// Which S4U operation an exchange performs.
pub(super) enum S4uMode {
    /// An ordinary TGS exchange.
    None,
    /// S4U2Self: a ticket to the TGT holder itself for a user.
    SelfReq(Box<SelfState>),
    /// S4U2Proxy: a ticket to a target with an evidence ticket as subject.
    Proxy(Box<ProxyState>),
}

/// `krb5_get_self_cred_from_kdc` state.
pub(super) struct SelfState {
    /// The requesting service (`in_creds->server`).
    service: PrincipalName,
    service_realm: String,
    /// `s4u_user.user_id.user`, canonicalized by the first reply.
    user: PrincipalName,
    user_realm: String,
    /// The exchange getting `krbtgt/<user realm>@<service realm>`.
    user_tgt: Option<Box<TgsExchange>>,
    /// Servers of the referral TGTs received (`referral_tgts`).
    referrals: Vec<(PrincipalName, String)>,
    /// `s4u_user.user_id.subject_cert`, sent in the first request only.
    subject_cert: Option<Vec<u8>>,
}

/// Steps of `get_proxy_cred_from_kdc`.
#[derive(Clone, Copy)]
enum ProxyPhase {
    /// The request with the evidence ticket to the service's realm.
    First,
    /// `get_tgt_to_target_realm`.
    TargetTgt,
    /// `get_target_realm_proxy_tgt`.
    ProxyTgt,
    /// The request with the proxy TGT in the target realm.
    Final,
}

/// `get_proxy_cred_from_kdc` state.
pub(super) struct ProxyState {
    evidence: Credential,
    /// The requested server.
    server: PrincipalName,
    phase: ProxyPhase,
    /// The proxy referral TGT, then the proxy TGT for the target realm.
    proxy_tgt: Option<Credential>,
    /// The service's TGT to the target realm.
    target_tgt: Option<Credential>,
    target_realm: String,
    /// TGTs used so far by `chase_referrals`.
    referrals: Vec<(PrincipalName, String)>,
}

fn name_str(g: &GeneralString) -> String {
    String::from_utf8_lossy(g.as_bytes()).to_string()
}

fn checksum_over(
    cksum_type: i32,
    key: &EncryptionKey,
    usage: i32,
    data: &[u8],
) -> Result<Vec<u8>, Krb5Error> {
    if cksum_type == CKSUMTYPE_HMAC_MD5 {
        return hmac_md5_checksum(key.key_bytes(), usage, data)
            .map(|c| c.to_vec())
            .map_err(|e| Krb5Error::Crypto(e.to_string()));
    }
    let profile = find_etype(key.keytype).map_err(|_| Krb5Error::UnsupportedEtype(key.keytype))?;
    if profile.checksum_type() != cksum_type {
        return Err(Krb5Error::ReplyValidation("S4U checksum type mismatch"));
    }
    profile
        .checksum(key.key_bytes(), usage, data)
        .map_err(|e| Krb5Error::Crypto(e.to_string()))
}

fn bits(options: u32) -> rasn::types::BitString {
    rasn::types::BitString::from_slice(&options.to_be_bytes())
}

fn bits_value(b: &rasn::types::BitString) -> u32 {
    let mut v = 0u32;
    for (i, bit) in b.iter().by_vals().take(32).enumerate() {
        if bit {
            v |= 0x8000_0000 >> i;
        }
    }
    v
}

/// `krb5_principal_compare`: realm and components, not the name type.
fn same_principal(a: &PrincipalName, a_realm: &str, b: &PrincipalName, b_realm: &str) -> bool {
    a_realm == b_realm && a.name_string == b.name_string
}

fn tgs_name(realm: &str) -> Result<PrincipalName, Krb5Error> {
    Ok(PrincipalName {
        name_type: NT_SRV_INST,
        name_string: vec![
            GeneralString::from_bytes(b"krbtgt").expect("ascii"),
            GeneralString::from_bytes(realm.as_bytes())
                .map_err(|_| Krb5Error::ReplyValidation("invalid realm string"))?,
        ],
    })
}

/// The realm a TGT grants access to (`tgt->server->data[1]`).
fn tgt_realm_of(tgt: &Credential) -> String {
    if is_tgs_principal(&tgt.server) {
        name_str(&tgt.server.name_string[1])
    } else {
        tgt.srealm.clone()
    }
}

/// `convert_to_enterprise` (s4u_creds.c:401-418): unparse the name and parse
/// it back with `KRB5_PRINCIPAL_PARSE_ENTERPRISE |
/// KRB5_PRINCIPAL_PARSE_IGNORE_REALM`. The enterprise parse keeps '/' and
/// the first unescaped '@' in its single component (parse.c:60-160); the
/// only unescaped '@' unparse.c emits is the realm separator, so the
/// component is the components joined by '/', '@', and the realm.
fn convert_to_enterprise(name: &PrincipalName, realm: &str) -> Result<PrincipalName, Krb5Error> {
    let mut comp = Vec::new();
    for (i, c) in name.name_string.iter().enumerate() {
        if i > 0 {
            comp.push(b'/');
        }
        comp.extend_from_slice(c.as_bytes());
    }
    comp.push(b'@');
    comp.extend_from_slice(realm.as_bytes());
    Ok(PrincipalName {
        name_type: NT_ENTERPRISE,
        name_string: vec![GeneralString::from_bytes(&comp)
            .map_err(|_| Krb5Error::ReplyValidation("invalid principal name"))?],
    })
}

/// `FLAGS2OPTS` (get_creds.c:244).
fn flags2opts(tgt: &Credential) -> KdcOptions {
    KdcOptions::from_bits_truncate(tgt.flags.bits() & KDC_TKT_COMMON_MASK)
}

/// `check_rbcd_support` (s4u_creds.c:740-762): the KDC must echo
/// PA-PAC-OPTIONS with the RBCD bit in the encrypted padata.
fn check_rbcd_support(enc_part: &EncKdcRepPart) -> Result<(), Krb5Error> {
    let pa = enc_part
        .encrypted_pa_data
        .iter()
        .flatten()
        .find(|p| p.padata_type == PA_PAC_OPTIONS)
        .ok_or(NO_RBCD)?;
    let options: PaPacOptions = rasn::der::decode(pa.padata_value.as_ref())?;
    if bits_value(&options.flags) & PA_PAC_OPTIONS_RBCD == 0 {
        return Err(NO_RBCD);
    }
    Ok(())
}

/// One reply of `chase_referrals` (s4u_creds.c:859-927) that is not the
/// requested server: it must be a TGT to a new realm not already visited.
fn chase_referral(
    referrals: &mut Vec<(PrincipalName, String)>,
    tgt: &Credential,
    enc_part: &EncKdcRepPart,
) -> Result<(), Krb5Error> {
    if !is_tgs_principal(&enc_part.sname) {
        return Err(WRONG_PRINC);
    }
    let realm = name_str(&enc_part.sname.name_string[1]);
    if realm == tgt_realm_of(tgt) {
        return Err(HOST_REALM_UNKNOWN);
    }
    let srealm = name_str(&enc_part.srealm);
    if referrals
        .iter()
        .any(|(n, r)| same_principal(n, r, &enc_part.sname, &srealm))
    {
        return Err(Krb5Error::ReferralLoop { realm });
    }
    referrals.push((tgt.server.clone(), tgt.srealm.clone()));
    if referrals.len() >= MAX_REFERRAL_HOPS as usize {
        return Err(MODIFIED);
    }
    Ok(())
}

/// `verify_s4u2self_reply` (s4u_creds.c:266-380): when the KDC returns
/// PA-S4U-X509-USER, check the nonce and its checksum and require a keyed
/// checksum. With `update_req_user` adopt the KDC's (canonical) user name,
/// otherwise require it unchanged. A reply without the padata is accepted
/// only if it also lacks the encrypted copy.
fn verify_s4u2self_reply(
    nonce: u32,
    subkey: Option<&EncryptionKey>,
    st: &mut SelfState,
    padata: Option<&[PaData]>,
    enc_part: &EncKdcRepPart,
    update_req_user: bool,
) -> Result<(), Krb5Error> {
    let find = |list: Option<&[PaData]>| {
        list.into_iter()
            .flatten()
            .find(|p| p.padata_type == PA_S4U_X509_USER)
            .cloned()
    };
    let Some(rep_pa) = find(padata) else {
        return if find(enc_part.encrypted_pa_data.as_deref()).is_some() {
            Err(MODIFIED)
        } else {
            Ok(())
        };
    };
    let rep: PaS4uX509User = rasn::der::decode(rep_pa.padata_value.as_ref())?;
    if rep.user_id.nonce != nonce {
        return Err(MODIFIED);
    }
    let options = rep.user_id.options.as_ref().map_or(0, bits_value);
    let usage = if options & S4U_OPTS_USE_REPLY_KEY_USAGE != 0 {
        KEYUSAGE_S4U_REPLY
    } else {
        KEYUSAGE_S4U_REQUEST
    };
    let subkey = subkey.ok_or(MODIFIED)?;
    let der = rasn::der::encode(&rep.user_id)?;
    let want = checksum_over(rep.cksum.cksumtype, subkey, usage, &der).map_err(|_| MODIFIED)?;
    if want != rep.cksum.checksum.as_ref() {
        return Err(MODIFIED);
    }
    let user = match rep.user_id.cname {
        Some(u) if !u.name_string.is_empty() => u,
        _ => return Err(MODIFIED),
    };
    if !matches!(rep.cksum.cksumtype, 15 | 16 | 19 | 20 | CKSUMTYPE_HMAC_MD5) {
        return Err(Krb5Error::ReplyValidation("S4U checksum is not keyed"));
    }
    let realm = name_str(&rep.user_id.crealm);
    if update_req_user {
        st.user = user;
        st.user_realm = realm;
    } else if !same_principal(&user, &realm, &st.user, &st.user_realm) {
        return Err(MODIFIED);
    }
    Ok(())
}

impl TgsExchange {
    /// S4U2Self (`krb5_get_credentials_for_user`, s4u_creds.c:653-720): the
    /// service holding `tgt` (its TGT, as from its ccache) asks for a ticket
    /// to itself on behalf of `user` in `user_realm`. A TGT to the user's
    /// realm is obtained first unless `tgt` already is one
    /// (s4u_creds.c:530-541). Each request carries PA-S4U-X509-USER and
    /// PA-FOR-USER (s4u_creds.c:178-235, 88-135) and each reply's
    /// PA-S4U-X509-USER is verified; the reply client must be the
    /// checksum-protected user.
    pub fn s4u2self(
        tgt: Credential,
        user: PrincipalName,
        user_realm: impl Into<String>,
        options: TgsOptions,
    ) -> Self {
        let service = tgt.client.clone();
        let service_realm = tgt.crealm.clone();
        let mut ex = Self::new(tgt, service.clone(), options);
        ex.first_referral_attempt = false;
        ex.s4u = S4uMode::SelfReq(Box::new(SelfState {
            service,
            service_realm,
            user,
            user_realm: user_realm.into(),
            user_tgt: None,
            referrals: Vec::new(),
            subject_cert: None,
        }));
        ex
    }

    /// Identify the S4U2Self user by `cert` (`subject_cert`): it is sent in
    /// PA-S4U-X509-USER of the first request to the user's realm only
    /// (s4u_creds.c:592-593). With a user name without components the
    /// certificate alone identifies the user, PA-FOR-USER is omitted
    /// (s4u_creds.c:518-531) and the KDC's checksummed reply names it.
    #[must_use]
    pub fn with_subject_certificate(mut self, cert: Option<Vec<u8>>) -> Self {
        if let S4uMode::SelfReq(st) = &mut self.s4u {
            st.subject_cert = cert.filter(|c| !c.is_empty());
        }
        self
    }

    /// S4U2Proxy (`krb5_get_credentials_for_proxy`, s4u_creds.c:1195-1250):
    /// `tgt` is the impersonating service's TGT for its own realm and
    /// `evidence` the S4U2Self (or forwardable) ticket for the user, issued
    /// to that service. `target` is looked up in the service's realm. Each
    /// request with an evidence ticket sets CNAME-IN-ADDL-TKT and carries
    /// PA-PAC-OPTIONS with the RBCD bit (s4u_creds.c:763-781); the reply
    /// client must be the evidence client.
    pub fn s4u2proxy(
        tgt: Credential,
        evidence: Credential,
        target: PrincipalName,
        options: TgsOptions,
    ) -> Self {
        let mut ex = Self::new(tgt, target.clone(), options);
        ex.first_referral_attempt = false;
        ex.s4u = S4uMode::Proxy(Box::new(ProxyState {
            evidence,
            server: target,
            phase: ProxyPhase::First,
            proxy_tgt: None,
            target_tgt: None,
            target_realm: String::new(),
            referrals: Vec::new(),
        }));
        ex
    }

    pub(super) fn is_s4u(&self) -> bool {
        !matches!(self.s4u, S4uMode::None)
    }

    /// Get `krbtgt/<user realm>` before the first S4U2Self request
    /// (s4u_creds.c:530-541). Returns `None` once the exchange has it.
    pub(super) fn s4u_user_tgt_step(
        &mut self,
        kdc_reply: &[u8],
    ) -> Result<Option<TgsStepResult>, Krb5Error> {
        if !matches!(self.state, TgsState::Begin) {
            return Ok(None);
        }
        let S4uMode::SelfReq(st) = &mut self.s4u else {
            return Ok(None);
        };
        let inner = match &mut st.user_tgt {
            Some(inner) => inner,
            None if is_tgs_principal(&self.cur_tgt.server)
                && tgt_realm_of(&self.cur_tgt) == st.user_realm =>
            {
                return Ok(None)
            }
            None => st.user_tgt.insert(Box::new(TgsExchange::new(
                self.cur_tgt.clone(),
                tgs_name(&st.user_realm)?,
                self.options.clone(),
            ))),
        };
        match inner.step(kdc_reply)? {
            TgsStepResult::Complete => {
                let tgt = inner.credential()?.clone();
                st.user_tgt = None;
                self.cur_tgt = tgt;
                Ok(None)
            }
            step => Ok(Some(step)),
        }
    }

    /// The server named in the next request.
    pub(super) fn s4u_request_server(&self) -> Result<Option<PrincipalName>, Krb5Error> {
        match &self.s4u {
            S4uMode::None => Ok(None),
            // s4u_creds.c:584-594: the real principal when asking the
            // server realm, else the enterprise principal.
            S4uMode::SelfReq(st) => {
                if tgt_realm_of(&self.cur_tgt) == st.service_realm {
                    Ok(Some(st.service.clone()))
                } else {
                    convert_to_enterprise(&st.service, &st.service_realm).map(Some)
                }
            }
            S4uMode::Proxy(st) => match st.phase {
                ProxyPhase::ProxyTgt => tgs_name(&st.target_realm).map(Some),
                _ => Ok(Some(st.server.clone())),
            },
        }
    }

    /// KDC options for the next S4U request: the caller's options, the
    /// TGT's `FLAGS2OPTS`, and CANONICALIZE (plus CNAME-IN-ADDL-TKT) on the
    /// S4U requests themselves (s4u_creds.c:597-600, 1029-1037, 1086-1087).
    pub(super) fn s4u_kdc_options(&self) -> Option<KdcOptions> {
        let mut opts = flags2opts(&self.cur_tgt);
        if self.options.forwardable {
            opts |= KdcOptions::FORWARDABLE;
        }
        if self.options.canonicalize {
            opts |= KdcOptions::CANONICALIZE;
        }
        if self.options.disable_transited_check {
            opts |= KdcOptions::DISABLE_TRANSITED_CHECK;
        }
        match &self.s4u {
            S4uMode::None => return None,
            S4uMode::SelfReq(_) => opts |= KdcOptions::CANONICALIZE,
            S4uMode::Proxy(st) => {
                if matches!(st.phase, ProxyPhase::First | ProxyPhase::Final) {
                    opts |= KdcOptions::CNAME_IN_ADDL_TKT | KdcOptions::CANONICALIZE;
                }
            }
        }
        Some(opts)
    }

    pub(super) fn s4u_additional_tickets(&self) -> Option<Vec<Ticket>> {
        match &self.s4u {
            S4uMode::Proxy(st) => match st.phase {
                ProxyPhase::First => Some(vec![st.evidence.ticket.clone()]),
                ProxyPhase::Final => st.proxy_tgt.as_ref().map(|t| vec![t.ticket.clone()]),
                _ => None,
            },
            _ => None,
        }
    }

    /// Request padata for the next S4U request, given its fresh subkey and
    /// nonce (`build_pa_s4u_x509_user`, s4u_creds.c:178-235). The referral
    /// chases of S4U2Proxy send none (`krb5_get_cred_via_tkt`).
    pub(super) fn s4u_request_padata(
        &self,
        subkey: &EncryptionKey,
    ) -> Result<Vec<PaData>, Krb5Error> {
        match &self.s4u {
            S4uMode::None => Ok(Vec::new()),
            S4uMode::Proxy(st) => {
                if !matches!(st.phase, ProxyPhase::First | ProxyPhase::Final) {
                    return Ok(Vec::new());
                }
                let der = rasn::der::encode(&PaPacOptions {
                    flags: bits(PA_PAC_OPTIONS_RBCD),
                })?;
                Ok(vec![PaData {
                    padata_type: PA_PAC_OPTIONS,
                    padata_value: der.into(),
                }])
            }
            S4uMode::SelfReq(st) => {
                let (user, realm) = (&st.user, &st.user_realm);
                let crealm = GeneralString::from_bytes(realm.as_bytes())
                    .map_err(|_| Krb5Error::ReplyValidation("invalid user realm"))?;
                let user_id = S4uUserId {
                    nonce: self.nonce,
                    cname: Some(user.clone()),
                    crealm: crealm.clone(),
                    subject_certificate: st
                        .subject_cert
                        .as_ref()
                        .filter(|_| st.referrals.is_empty())
                        .map(|c| c.clone().into()),
                    options: Some(bits(S4U_OPTS_USE_REPLY_KEY_USAGE)),
                };
                let profile = find_etype(subkey.keytype)
                    .map_err(|_| Krb5Error::UnsupportedEtype(subkey.keytype))?;
                let cksum_type = profile.checksum_type();
                let sum = checksum_over(
                    cksum_type,
                    subkey,
                    KEYUSAGE_S4U_REQUEST,
                    &rasn::der::encode(&user_id)?,
                )?;
                let x509 = PaS4uX509User {
                    user_id,
                    cksum: Checksum {
                        cksumtype: cksum_type,
                        checksum: sum.into(),
                    },
                };
                let x509 = PaData {
                    padata_type: PA_S4U_X509_USER,
                    padata_value: rasn::der::encode(&x509)?.into(),
                };
                if user.name_string.is_empty() {
                    return Ok(vec![x509]);
                }

                // PA-FOR-USER: hmac-md5 over name type, components, realm
                // and "Kerberos", keyed with the TGT session key
                // (make_pa_for_user_checksum, s4u_creds.c:88-135).
                let package = GeneralString::from_bytes(b"Kerberos").expect("ascii");
                let mut data = user.name_type.to_le_bytes().to_vec();
                for c in &user.name_string {
                    data.extend_from_slice(c.as_bytes());
                }
                data.extend_from_slice(realm.as_bytes());
                data.extend_from_slice(package.as_bytes());
                let sum = checksum_over(
                    CKSUMTYPE_HMAC_MD5,
                    &self.cur_tgt.session_key,
                    KEYUSAGE_APP_DATA_CKSUM,
                    &data,
                )?;
                let for_user = PaForUser {
                    user_name: user.clone(),
                    user_realm: crealm,
                    cksum: Checksum {
                        cksumtype: CKSUMTYPE_HMAC_MD5,
                        checksum: sum.into(),
                    },
                    auth_package: package,
                };
                Ok(vec![
                    x509,
                    PaData {
                        padata_type: PA_FOR_USER,
                        padata_value: rasn::der::encode(&for_user)?.into(),
                    },
                ])
            }
        }
    }

    /// Send the next S4U request to the realm of the current TGT.
    fn s4u_send(&mut self) -> Result<TgsStepResult, Krb5Error> {
        let realm = self.tgt_target_realm();
        let data = self.build_tgs_req(true)?;
        self.state = TgsState::AwaitReply {
            resume: ResumeState::NonReferral,
        };
        self.last_realm = realm.clone();
        Ok(TgsStepResult::SendToKdc { data, realm })
    }

    fn s4u_complete(&mut self, rep: &KdcRep, enc_part: &EncKdcRepPart) -> TgsStepResult {
        self.credential = Some(crate::protocol::kdc_rep::credential_from_rep(rep, enc_part));
        self.state = TgsState::Complete;
        TgsStepResult::Complete
    }

    /// Handle a decrypted S4U TGS-REP.
    pub(super) fn s4u_reply(
        &mut self,
        rep: &KdcRep,
        enc_part: &EncKdcRepPart,
    ) -> Result<TgsStepResult, Krb5Error> {
        match self.s4u {
            S4uMode::SelfReq(_) => self.s4u2self_reply(rep, enc_part),
            S4uMode::Proxy(_) => self.s4u2proxy_reply(rep, enc_part),
            S4uMode::None => Err(Krb5Error::ReplyValidation("not an S4U exchange")),
        }
    }

    /// One iteration of the `krb5_get_self_cred_from_kdc` referral loop
    /// (s4u_creds.c:602-651).
    fn s4u2self_reply(
        &mut self,
        rep: &KdcRep,
        enc_part: &EncKdcRepPart,
    ) -> Result<TgsStepResult, Krb5Error> {
        let S4uMode::SelfReq(st) = &mut self.s4u else {
            return Err(Krb5Error::ReplyValidation("not an S4U2Self exchange"));
        };
        let crealm = name_str(&rep.crealm);
        let is_tgs = is_tgs_principal(&enc_part.sname);
        // gc_via_tkt.c:257-270.
        if !is_tgs {
            if same_principal(&rep.cname, &crealm, &st.service, &st.service_realm) {
                return Err(NO_S4U2SELF);
            }
        } else if !same_principal(
            &rep.cname,
            &crealm,
            &self.cur_tgt.client,
            &self.cur_tgt.crealm,
        ) {
            return Err(MODIFIED);
        }
        let first = st.referrals.is_empty();
        verify_s4u2self_reply(
            self.nonce,
            self.subkey.as_ref(),
            st,
            rep.padata.as_deref(),
            enc_part,
            first,
        )?;
        if enc_part.sname.name_string == st.service.name_string {
            if !same_principal(&rep.cname, &crealm, &st.user, &st.user_realm) {
                return Err(MODIFIED);
            }
            return Ok(self.s4u_complete(rep, enc_part));
        }
        if !is_tgs {
            return Err(WRONG_PRINC);
        }
        let realm = name_str(&enc_part.sname.name_string[1]);
        if realm == tgt_realm_of(&self.cur_tgt) {
            return Err(HOST_REALM_UNKNOWN);
        }
        let srealm = name_str(&enc_part.srealm);
        if st
            .referrals
            .iter()
            .any(|(n, r)| same_principal(n, r, &enc_part.sname, &srealm))
        {
            return Err(Krb5Error::ReferralLoop { realm });
        }
        st.referrals.push((enc_part.sname.clone(), srealm));
        if st.referrals.len() >= MAX_REFERRAL_HOPS as usize {
            return Err(Krb5Error::ReferralLimitExceeded(MAX_REFERRAL_HOPS));
        }
        self.cur_tgt = crate::protocol::kdc_rep::credential_from_rep(rep, enc_part);
        self.authdata = None;
        self.s4u_send()
    }

    /// One reply of `get_proxy_cred_from_kdc` (s4u_creds.c:985-1132).
    fn s4u2proxy_reply(
        &mut self,
        rep: &KdcRep,
        enc_part: &EncKdcRepPart,
    ) -> Result<TgsStepResult, Krb5Error> {
        let S4uMode::Proxy(st) = &mut self.s4u else {
            return Err(Krb5Error::ReplyValidation("not an S4U2Proxy exchange"));
        };
        let crealm = name_str(&rep.crealm);
        let srealm = name_str(&enc_part.srealm);
        let is_tgs = is_tgs_principal(&enc_part.sname);
        // gc_via_tkt.c:261-270: the evidence client is checked at the end;
        // referral TGTs name the header ticket client.
        let cname_in_addl = matches!(st.phase, ProxyPhase::First | ProxyPhase::Final);
        if (!cname_in_addl || is_tgs)
            && !same_principal(
                &rep.cname,
                &crealm,
                &self.cur_tgt.client,
                &self.cur_tgt.crealm,
            )
        {
            return Err(MODIFIED);
        }
        let reply = || crate::protocol::kdc_rep::credential_from_rep(rep, enc_part);
        match st.phase {
            ProxyPhase::First => {
                if enc_part.sname.name_string == st.server.name_string {
                    return self.s4u2proxy_done(rep, enc_part);
                }
                if !is_tgs {
                    return Err(WRONG_PRINC);
                }
                check_rbcd_support(enc_part)?;
                st.proxy_tgt = Some(reply());
                self.authdata = None;
                st.phase = ProxyPhase::TargetTgt;
                st.referrals.clear();
            }
            ProxyPhase::TargetTgt => {
                if enc_part.sname.name_string != st.server.name_string {
                    chase_referral(&mut st.referrals, &self.cur_tgt, enc_part)?;
                    self.cur_tgt = reply();
                    return self.s4u_send();
                }
                // get_tgt_to_target_realm keeps the TGT, not the ticket.
                st.target_realm = tgt_realm_of(&self.cur_tgt);
                st.referrals.clear();
                let proxy = st.proxy_tgt.clone().ok_or(MODIFIED)?;
                if tgt_realm_of(&proxy) == st.target_realm {
                    st.phase = ProxyPhase::Final;
                } else {
                    st.target_tgt = Some(std::mem::replace(&mut self.cur_tgt, proxy));
                    st.phase = ProxyPhase::ProxyTgt;
                }
            }
            ProxyPhase::ProxyTgt => {
                let want = tgs_name(&st.target_realm)?;
                if enc_part.sname.name_string != want.name_string {
                    chase_referral(&mut st.referrals, &self.cur_tgt, enc_part)?;
                    self.cur_tgt = reply();
                    return self.s4u_send();
                }
                st.proxy_tgt = Some(reply());
                self.cur_tgt = st.target_tgt.take().ok_or(MODIFIED)?;
                st.phase = ProxyPhase::Final;
            }
            ProxyPhase::Final => {
                check_rbcd_support(enc_part)?;
                if enc_part.sname.name_string != st.server.name_string || srealm != st.target_realm
                {
                    return Err(WRONG_PRINC);
                }
                return self.s4u2proxy_done(rep, enc_part);
            }
        }
        self.s4u_send()
    }

    /// `krb5_get_credentials_for_proxy` (s4u_creds.c:1236-1243): the ticket
    /// must be for the evidence ticket's client.
    fn s4u2proxy_done(
        &mut self,
        rep: &KdcRep,
        enc_part: &EncKdcRepPart,
    ) -> Result<TgsStepResult, Krb5Error> {
        let S4uMode::Proxy(st) = &self.s4u else {
            return Err(Krb5Error::ReplyValidation("not an S4U2Proxy exchange"));
        };
        let crealm = name_str(&rep.crealm);
        if !same_principal(
            &rep.cname,
            &crealm,
            &st.evidence.client,
            &st.evidence.crealm,
        ) {
            return Err(MODIFIED);
        }
        Ok(self.s4u_complete(rep, enc_part))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enterprise_name_holds_the_raw_components_like_mit() {
        // MIT 1.22.2: unparse gives a\/b/h\@x\\y\tz@R, and the enterprise
        // parse decodes it back to one raw component.
        let gs = |s: &str| GeneralString::from_bytes(s.as_bytes()).expect("ascii");
        let name = PrincipalName {
            name_type: 3,
            name_string: vec![gs("a/b"), gs("h@x\\y\tz")],
        };
        let e = convert_to_enterprise(&name, "R").expect("enterprise");
        assert_eq!(e.name_type, NT_ENTERPRISE);
        assert_eq!(e.name_string.len(), 1);
        assert_eq!(e.name_string[0].as_bytes(), b"a/b/h@x\\y\tz@R");
    }
}
