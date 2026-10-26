//! Ticket authorization data and the MS-PAC (MIT kdc/kdc_authdata.c:
//! `handle_authdata`, `handle_pac`, `copy_tgt_authdata`,
//! `copy_request_authdata`; kdc/kdc_util.c `get_verified_pac`).
//!
//! The KDB module that would normally contribute logon information
//! (`krb5_db_issue_pac`) is absent for the default database, as in MIT's
//! db2: a PAC issued here holds the client info and signatures, plus
//! delegation info carried over from an incoming PAC.

use super::db::KvnoSel;
use super::error::KdcError;
use super::{PrincipalAttributes, PrincipalEntry, PrincipalStore};
use crate::crypto::find_etype;
use crate::pac::{
    kdc_sign_ticket, kdc_verify_ticket, DelegationInfo, Pac, PacError, PAC_CLIENT_INFO,
    PAC_DELEGATION_INFO,
};
use crate::types::error_codes::*;
use crate::types::{
    AuthorizationDataElement, EncTicketPart, EncryptedData, EncryptionKey, PaData, PaDataType,
    PaPacRequest, PrincipalName, TicketFlags,
};

/// AD-MANDATORY-FOR-KDC.
const AD_MANDATORY_FOR_KDC: i32 = 8;
/// AD-KDC-ISSUED.
const AD_KDC_ISSUED: i32 = 4;
/// AD-CAMMAC.
const AD_CAMMAC: i32 = 96;
/// AD-AUTH-INDICATOR.
const AD_AUTH_INDICATOR: i32 = 97;
/// KRB5_AUTHDATA_SIGNTICKET.
const AD_SIGNTICKET: i32 = 512;
/// `KRB5_KEYUSAGE_TGS_REQ_AD_SESSKEY`.
const TGS_REQ_AD_SESSKEY: i32 = 4;
/// `KRB5_KEYUSAGE_TGS_REQ_AD_SUBKEY`.
const TGS_REQ_AD_SUBKEY: i32 = 5;

fn is_kdc_issued_type(t: i32) -> bool {
    matches!(
        t,
        AD_SIGNTICKET | AD_KDC_ISSUED | crate::pac::AD_WIN2K_PAC | AD_CAMMAC | AD_AUTH_INDICATOR
    )
}

/// `is_kdc_issued_authdatum` (kdc_authdata.c:106-148): authdata that must
/// not be copied from untrusted sources. An AD-IF-RELEVANT container is
/// KDC-issued if it holds any such element; one that cannot be decoded is
/// not.
fn is_kdc_issued(el: &AuthorizationDataElement) -> bool {
    if el.ad_type == crate::pac::AD_IF_RELEVANT {
        return rasn::der::decode::<Vec<AuthorizationDataElement>>(el.ad_data.as_ref())
            .is_ok_and(|inner| inner.iter().any(|e| is_kdc_issued_type(e.ad_type)));
    }
    is_kdc_issued_type(el.ad_type)
}

/// `add_filtered_authdata` (kdc_authdata.c:187-216).
fn filtered(list: &[AuthorizationDataElement]) -> Vec<AuthorizationDataElement> {
    list.iter().filter(|e| !is_kdc_issued(e)).cloned().collect()
}

fn has_mandatory_for_kdc(list: &[AuthorizationDataElement]) -> bool {
    list.iter().any(|e| e.ad_type == AD_MANDATORY_FOR_KDC)
}

/// `include_pac_p` (kdc_preauth.c:1582-1608): PA-PAC-REQUEST decides; the
/// default (and an undecodable value) is to include a PAC.
pub(super) fn include_pac_p(padata: Option<&[PaData]>) -> bool {
    padata
        .into_iter()
        .flatten()
        .find(|p| p.padata_type == PaDataType::PaPacRequest as i32)
        .and_then(|p| rasn::der::decode::<PaPacRequest>(p.padata_value.as_ref()).ok())
        .is_none_or(|r| r.include_pac)
}

/// The kind of S4U request a ticket is issued for (`KRB5_KDB_FLAGS_S4U`).
pub(super) enum S4uPac<'a> {
    /// An ordinary TGS request.
    None,
    /// S4U2Self: a new PAC for the impersonated user.
    SelfReq {
        /// The subject (with realm) when issuing a referral.
        referral_subject: Option<(&'a PrincipalName, &'a str)>,
    },
    /// S4U2Proxy: the evidence PAC with its delegation info extended.
    Proxy {
        /// The requested target service.
        target: &'a PrincipalName,
        /// The impersonating service, unparsed with realm.
        impersonator: String,
        /// A final cross-realm request: the evidence is a cross-realm TGT
        /// whose delegation info is copied, not extended.
        crossrealm: bool,
        /// The subject (with realm) when issuing a referral.
        referral_subject: Option<(&'a PrincipalName, &'a str)>,
    },
}

fn pac_failure(e: PacError) -> KdcError {
    KdcError::new(e.kdc_code(), "HANDLE_AUTHDATA")
}

impl<S: PrincipalStore> super::Kdc<S> {
    /// The local TGT's current key, used as the privsvr key
    /// (`pac_privsvr_key`, kdc_util.c:528-565, without the
    /// `pac_privsvr_enctype` string attribute).
    pub(super) fn privsvr_key(
        &self,
        local_tgt: &PrincipalEntry,
    ) -> Result<EncryptionKey, KdcError> {
        local_tgt
            .find_key(None, KvnoSel::Highest, &self.permitted())
            .map(|k| k.key.clone())
            .ok_or_else(|| KdcError::generic("GET_LOCAL_TGT"))
    }

    /// `get_verified_pac` (kdc_util.c:588-640): verify the PAC of a header
    /// ticket. A TGT (local or cross-realm) is checked against its server
    /// signature only; any other ticket also against the KDC signatures,
    /// trying the two previous local-TGT kvnos since PAC signatures carry
    /// no kvno.
    pub(super) fn verify_header_pac(
        &self,
        header: &EncTicketPart,
        header_sname: &PrincipalName,
        header_key: &EncryptionKey,
        local_tgt: &PrincipalEntry,
    ) -> Result<Option<Pac>, KdcError> {
        let fail = |e: PacError| KdcError::new(e.kdc_code(), "HEADER_PAC");
        if super::is_tgs_principal(header_sname) {
            return kdc_verify_ticket(header, header_sname, header_key, None).map_err(fail);
        }
        let tgt_key = self.privsvr_key(local_tgt)?;
        match kdc_verify_ticket(header, header_sname, header_key, Some(&tgt_key)) {
            Err(PacError::Modified | PacError::BadEnctype) => {}
            other => return other.map_err(fail),
        }
        let current = local_tgt.current_kvno().unwrap_or(0);
        for kvno in (1..current).rev().take(2) {
            let Some(old) = local_tgt.find_key(None, KvnoSel::Exact(kvno), &self.permitted())
            else {
                break;
            };
            if let Ok(pac) = kdc_verify_ticket(header, header_sname, header_key, Some(&old.key)) {
                return Ok(pac);
            }
        }
        Err(KdcError::new(KRB_AP_ERR_MODIFIED, "HEADER_PAC"))
    }

    /// `handle_pac` for an AS request (kdc_authdata.c:462-575).
    pub(super) fn issue_as_pac(
        &self,
        part: &mut EncTicketPart,
        server: &PrincipalEntry,
        server_key: &EncryptionKey,
        local_tgt: &PrincipalEntry,
        include_pac: bool,
    ) -> Result<(), KdcError> {
        if server
            .attributes
            .contains(PrincipalAttributes::NO_AUTH_DATA_REQUIRED)
            || self.config.disable_pac
            || part.flags.contains(TicketFlags::ANONYMOUS)
            || !include_pac
        {
            return Ok(());
        }
        let privsvr = self.privsvr_key(local_tgt)?;
        let crealm = String::from_utf8_lossy(part.crealm.as_bytes()).to_string();
        let cname = part.cname.clone();
        kdc_sign_ticket(
            part,
            &mut Pac::new(),
            &server.name,
            Some((&cname, &crealm)),
            server_key,
            &privsvr,
            false,
        )
        .map_err(pac_failure)
    }

    /// Authorization data for a TGS ticket and its PAC: the request's
    /// (`copy_request_authdata`, kdc_authdata.c:236-283) and the header
    /// ticket's (`copy_tgt_authdata`, :289-296) non-KDC-issued elements in
    /// that order, then a new PAC first (`handle_pac` with a subject PAC).
    #[expect(clippy::too_many_arguments, reason = "mirrors handle_authdata")]
    pub(super) fn issue_tgs_authdata(
        &self,
        part: &mut EncTicketPart,
        server: &PrincipalEntry,
        server_key: &EncryptionKey,
        local_tgt: &PrincipalEntry,
        request_authdata: Option<(&EncryptedData, &EncryptionKey, Option<&EncryptionKey>)>,
        subject_tkt: &EncTicketPart,
        subject_pac: Option<&Pac>,
        s4u: S4uPac<'_>,
    ) -> Result<(), KdcError> {
        let mut list: Vec<AuthorizationDataElement> = Vec::new();
        if let Some((enc, session, subkey)) = request_authdata {
            let decoded = decrypt_request_authdata(enc, session, subkey)?;
            if has_mandatory_for_kdc(&decoded) {
                return Err(KdcError::new(KDC_ERR_POLICY, "HANDLE_AUTHDATA"));
            }
            list.extend(filtered(&decoded));
        }
        if let Some(tgt_authdata) = subject_tkt.authorization_data.as_deref() {
            if has_mandatory_for_kdc(tgt_authdata) {
                return Err(KdcError::new(KDC_ERR_POLICY, "HANDLE_AUTHDATA"));
            }
            list.extend(filtered(tgt_authdata));
        }
        part.authorization_data = (!list.is_empty()).then_some(list);

        let Some(subject) = subject_pac else {
            return Ok(());
        };
        if server
            .attributes
            .contains(PrincipalAttributes::NO_AUTH_DATA_REQUIRED)
            || self.config.disable_pac
            || part.flags.contains(TicketFlags::ANONYMOUS)
        {
            return Ok(());
        }
        let mut pac = Pac::new();
        if let S4uPac::Proxy {
            target,
            impersonator,
            crossrealm: false,
            ..
        } = &s4u
        {
            // update_delegation_info (kdc_authdata.c:355-420).
            let mut di = match subject.get_buffer(PAC_DELEGATION_INFO) {
                Ok(d) => DelegationInfo::decode(d).map_err(pac_failure)?,
                Err(PacError::NoEntry) => DelegationInfo {
                    proxy_target: String::new(),
                    transited_services: Vec::new(),
                },
                Err(e) => return Err(pac_failure(e)),
            };
            di.proxy_target = super::s4u::proxy_target_string(target);
            di.transited_services.push(impersonator.clone());
            pac.add_buffer(PAC_DELEGATION_INFO, &di.encode())
                .map_err(pac_failure)?;
        } else {
            match subject.get_buffer(PAC_DELEGATION_INFO) {
                Ok(d) => pac
                    .add_buffer(PAC_DELEGATION_INFO, d)
                    .map_err(pac_failure)?,
                Err(PacError::NoEntry) => {}
                Err(e) => return Err(pac_failure(e)),
            }
        }
        // Client info (kdc_authdata.c:534-557): an S4U referral names the
        // subject with realm; a final S4U ticket names the ticket client
        // without realm; otherwise the subject's is copied.
        let crealm = String::from_utf8_lossy(part.crealm.as_bytes()).to_string();
        let cname = part.cname.clone();
        let (pac_client, with_realm) = match s4u {
            S4uPac::None => {
                let client_info = subject.get_buffer(PAC_CLIENT_INFO).map_err(pac_failure)?;
                pac.add_buffer(PAC_CLIENT_INFO, client_info)
                    .map_err(pac_failure)?;
                (None, false)
            }
            S4uPac::SelfReq {
                referral_subject: Some(subject),
            }
            | S4uPac::Proxy {
                referral_subject: Some(subject),
                ..
            } => (Some(subject), true),
            _ => (Some((&cname, crealm.as_str())), false),
        };
        let privsvr = self.privsvr_key(local_tgt)?;
        kdc_sign_ticket(
            part,
            &mut pac,
            &server.name,
            pac_client,
            server_key,
            &privsvr,
            with_realm,
        )
        .map_err(pac_failure)
    }
}

/// Decrypt the TGS-REQ body authorization data: first with the session key
/// and usage 4 (the pre-1.7 behaviour), then with the subkey and usage 5
/// (kdc_authdata.c:253-266).
fn decrypt_request_authdata(
    enc: &EncryptedData,
    session: &EncryptionKey,
    subkey: Option<&EncryptionKey>,
) -> Result<Vec<AuthorizationDataElement>, KdcError> {
    const STATUS: &str = "HANDLE_AUTHDATA";
    let profile = find_etype(enc.etype).map_err(|_| KdcError::new(KDC_ERR_ETYPE_NOSUPP, STATUS))?;
    let try_key = |key: &EncryptionKey, usage: i32| {
        (key.keytype == enc.etype)
            .then(|| {
                profile
                    .decrypt(key.key_bytes(), usage, enc.cipher.as_ref())
                    .ok()
            })
            .flatten()
    };
    let plain = try_key(session, TGS_REQ_AD_SESSKEY)
        .or_else(|| subkey.and_then(|k| try_key(k, TGS_REQ_AD_SUBKEY)))
        .ok_or_else(|| KdcError::new(KRB_AP_ERR_BAD_INTEGRITY, STATUS))?;
    rasn::der::decode(&plain).map_err(|_| KdcError::generic(STATUS))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn el(t: i32, data: &[u8]) -> AuthorizationDataElement {
        AuthorizationDataElement {
            ad_type: t,
            ad_data: data.to_vec().into(),
        }
    }

    fn container(inner: &[AuthorizationDataElement]) -> AuthorizationDataElement {
        el(1, &rasn::der::encode(&inner.to_vec()).expect("encode"))
    }

    #[test]
    fn filtered_drops_kdc_issued_elements_and_containers_holding_them() {
        let keep = container(&[el(77, b"x")]);
        let pac = container(&[el(128, b"pac")]);
        let mixed = container(&[el(77, b"x"), el(97, b"ind")]);
        let list = vec![
            el(512, b""),
            keep.clone(),
            pac,
            mixed,
            el(4, b""),
            el(88, b"y"),
        ];
        let kept = filtered(&list);
        assert_eq!(kept.len(), 2);
        assert_eq!(kept[0].ad_data, keep.ad_data);
        assert_eq!(kept[1].ad_type, 88);
    }

    #[test]
    fn undecodable_if_relevant_container_is_kept() {
        assert!(!is_kdc_issued(&el(1, &[0xff, 0x00])));
    }

    #[test]
    fn mandatory_for_kdc_is_detected_at_top_level_only() {
        assert!(has_mandatory_for_kdc(&[el(8, b"")]));
        assert!(!has_mandatory_for_kdc(&[container(&[el(8, b"")])]));
    }

    #[test]
    fn include_pac_p_follows_pa_pac_request_and_defaults_to_true() {
        let req = |include| PaData {
            padata_type: PaDataType::PaPacRequest as i32,
            padata_value: rasn::der::encode(&PaPacRequest {
                include_pac: include,
            })
            .expect("encode")
            .into(),
        };
        assert!(include_pac_p(None));
        assert!(include_pac_p(Some(&[req(true)])));
        assert!(!include_pac_p(Some(&[req(false)])));
        let garbage = PaData {
            padata_type: PaDataType::PaPacRequest as i32,
            padata_value: vec![1, 2, 3].into(),
        };
        assert!(include_pac_p(Some(&[garbage])));
    }

    #[test]
    fn request_authdata_decrypts_with_session_key_then_subkey() {
        let session = EncryptionKey::new(18, vec![1; 32]);
        let subkey = EncryptionKey::new(18, vec![2; 32]);
        let plain = rasn::der::encode(&vec![el(88, b"z")]).expect("encode");
        let profile = find_etype(18).expect("etype");
        let enc = |key: &EncryptionKey, usage| EncryptedData {
            etype: 18,
            kvno: None,
            cipher: profile
                .encrypt(key.key_bytes(), usage, &plain)
                .expect("encrypt")
                .into(),
        };
        let a = decrypt_request_authdata(&enc(&session, 4), &session, Some(&subkey)).expect("a");
        assert_eq!(a[0].ad_type, 88);
        let b = decrypt_request_authdata(&enc(&subkey, 5), &session, Some(&subkey)).expect("b");
        assert_eq!(b[0].ad_type, 88);
        let bad = decrypt_request_authdata(&enc(&subkey, 5), &session, None);
        assert_eq!(bad.err().map(|e| e.code), Some(KRB_AP_ERR_BAD_INTEGRITY));
    }
}
