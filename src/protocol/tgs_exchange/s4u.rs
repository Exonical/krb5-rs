//! S4U2Self and S4U2Proxy client requests (MIT lib/krb5/krb/s4u_creds.c).
//!
//! Single-realm flows: the request goes to the realm of the supplied TGT and
//! a referral reply is rejected. MIT's cross-realm chains
//! (`krb5_get_self_cred_from_kdc` referral loop, the proxy-TGT dance in
//! `get_proxy_cred_from_kdc`) are not implemented.

use super::*;
use crate::crypto::hmac_md5_checksum;
use crate::types::{
    PaForUser, PaPacOptions, PaS4uX509User, S4uUserId, Ticket, PA_PAC_OPTIONS_RBCD,
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
/// `KRB5_KDCREP_MODIFIED`-style failure.
const MODIFIED: Krb5Error = Krb5Error::ReplyValidation("S4U reply was modified");

/// Which S4U operation an exchange performs.
#[derive(Debug, Clone)]
pub(super) enum S4uMode {
    /// An ordinary TGS exchange.
    None,
    /// S4U2Self: a ticket to the TGT holder itself for `user`.
    SelfReq { user: PrincipalName, realm: String },
    /// S4U2Proxy: a ticket to the target using `evidence` as the subject.
    Proxy { evidence: Box<Credential> },
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

impl TgsExchange {
    /// S4U2Self (`krb5_get_credentials_for_user`, s4u_creds.c:560-720): a
    /// service holding `tgt` asks for a ticket to itself on behalf of `user`
    /// (in `user_realm`). The request carries PA-S4U-X509-USER and
    /// PA-FOR-USER (s4u_creds.c:455-481); the reply's PA-S4U-X509-USER is
    /// verified (`verify_s4u2self_reply`, s4u_creds.c:289-380) and the
    /// reply client must be the checksum-protected user.
    pub fn s4u2self(
        tgt: Credential,
        user: PrincipalName,
        user_realm: impl Into<String>,
        options: TgsOptions,
    ) -> Self {
        let target = tgt.client.clone();
        let mut ex = Self::new(tgt, target, options);
        ex.s4u = S4uMode::SelfReq {
            user,
            realm: user_realm.into(),
        };
        ex
    }

    /// S4U2Proxy (`krb5_get_credentials_for_proxy`, s4u_creds.c:1195-1250):
    /// `tgt` belongs to the impersonating service and `evidence` is the
    /// S4U2Self (or forwardable) ticket for the user, issued to that service.
    /// The request sets CNAME-IN-ADDL-TKT, carries the evidence ticket as the
    /// additional ticket and PA-PAC-OPTIONS with the RBCD bit
    /// (s4u_creds.c:763-781); the reply client must be the evidence client.
    pub fn s4u2proxy(
        tgt: Credential,
        evidence: Credential,
        target: PrincipalName,
        options: TgsOptions,
    ) -> Self {
        let mut ex = Self::new(tgt, target, options);
        ex.s4u = S4uMode::Proxy {
            evidence: Box::new(evidence),
        };
        ex
    }

    pub(super) fn s4u_kdc_options(&self) -> KdcOptions {
        match self.s4u {
            S4uMode::Proxy { .. } => KdcOptions::CNAME_IN_ADDL_TKT,
            _ => KdcOptions::empty(),
        }
    }

    pub(super) fn s4u_additional_tickets(&self) -> Option<Vec<Ticket>> {
        match &self.s4u {
            S4uMode::Proxy { evidence } => Some(vec![evidence.ticket.clone()]),
            _ => None,
        }
    }

    /// Whether the default PA-PAC-OPTIONS (branch aware) is replaced by an
    /// S4U-specific one.
    pub(super) fn s4u_replaces_pac_options(&self) -> bool {
        matches!(self.s4u, S4uMode::Proxy { .. })
    }

    /// Request padata for the S4U operation, given the request's fresh
    /// subkey and nonce (`build_pa_s4u_x509_user`, s4u_creds.c:178-235).
    pub(super) fn s4u_request_padata(
        &self,
        subkey: &EncryptionKey,
    ) -> Result<Vec<PaData>, Krb5Error> {
        match &self.s4u {
            S4uMode::None => Ok(Vec::new()),
            S4uMode::Proxy { .. } => {
                let der = rasn::der::encode(&PaPacOptions {
                    flags: bits(PA_PAC_OPTIONS_RBCD),
                })?;
                Ok(vec![PaData {
                    padata_type: PA_PAC_OPTIONS,
                    padata_value: der.into(),
                }])
            }
            S4uMode::SelfReq { user, realm } => {
                let crealm = GeneralString::from_bytes(realm.as_bytes())
                    .map_err(|_| Krb5Error::ReplyValidation("invalid user realm"))?;
                let user_id = S4uUserId {
                    nonce: self.nonce,
                    cname: Some(user.clone()),
                    crealm: crealm.clone(),
                    subject_certificate: None,
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
                    PaData {
                        padata_type: PA_S4U_X509_USER,
                        padata_value: rasn::der::encode(&x509)?.into(),
                    },
                    PaData {
                        padata_type: PA_FOR_USER,
                        padata_value: rasn::der::encode(&for_user)?.into(),
                    },
                ])
            }
        }
    }

    /// The client name and realm the reply must carry.
    pub(super) fn expected_client(&self) -> (PrincipalName, String) {
        match &self.s4u {
            S4uMode::None => (self.cur_tgt.client.clone(), self.cur_tgt.crealm.clone()),
            S4uMode::SelfReq { user, realm } => (user.clone(), realm.clone()),
            S4uMode::Proxy { evidence } => (evidence.client.clone(), evidence.crealm.clone()),
        }
    }

    pub(super) fn is_s4u(&self) -> bool {
        !matches!(self.s4u, S4uMode::None)
    }

    /// `verify_s4u2self_reply` (s4u_creds.c:289-380) for the initial request
    /// to the user's realm: when the KDC returns PA-S4U-X509-USER, check the
    /// nonce and its checksum, adopt the KDC's (canonical) user name, and
    /// require a keyed checksum for AES keys. A reply without it is accepted
    /// only if it also lacks the encrypted copy (`return enc ? MODIFIED : 0`).
    pub(super) fn verify_s4u2self_reply(
        &mut self,
        padata: Option<&[PaData]>,
        enc_part: &EncKdcRepPart,
    ) -> Result<(), Krb5Error> {
        if !matches!(self.s4u, S4uMode::SelfReq { .. }) {
            return Ok(());
        }
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
        if rep.user_id.nonce != self.nonce {
            return Err(MODIFIED);
        }
        let options = rep.user_id.options.as_ref().map_or(0, bits_value);
        let usage = if options & S4U_OPTS_USE_REPLY_KEY_USAGE != 0 {
            KEYUSAGE_S4U_REPLY
        } else {
            KEYUSAGE_S4U_REQUEST
        };
        let subkey = self.subkey.clone().ok_or(MODIFIED)?;
        let der = rasn::der::encode(&rep.user_id)?;
        let want =
            checksum_over(rep.cksum.cksumtype, &subkey, usage, &der).map_err(|_| MODIFIED)?;
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
        self.s4u = S4uMode::SelfReq { user, realm };
        Ok(())
    }

    /// The final credential's client must be the verified user
    /// (s4u_creds.c:496-501) / the evidence client (s4u_creds.c:1236-1243).
    pub(super) fn s4u_check_credential(&self, cred: &Credential) -> Result<(), Krb5Error> {
        let (name, realm) = self.expected_client();
        if cred.client.name_string != name.name_string || cred.crealm != realm {
            return Err(MODIFIED);
        }
        Ok(())
    }
}
