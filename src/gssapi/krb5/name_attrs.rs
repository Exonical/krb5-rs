//! Name attributes of the initiator name on an accepted context:
//! gss_inquire_name, gss_get_name_attribute, gss_set_name_attribute,
//! gss_delete_name_attribute (naming_exts.c), backed by MIT's built-in
//! authdata modules in their order (authdata.c `authdata_systems`): mspac
//! (pac.c) then auth-indicators (ai_authdata.c).  Also gss_localname and
//! gss_authorize_localname (gssapi_krb5.c:738-800).

use super::*;
use crate::pac::{Pac, AD_WIN2K_PAC, PAC_CLIENT_INFO, PAC_DELEGATION_INFO, PAC_LOGON_INFO};
use crate::pac::{PAC_PRIVSVR_CHECKSUM, PAC_SERVER_CHECKSUM, PAC_UPN_DNS_INFO};
use crate::profile::Profile;
use crate::types::{find_authdata, Cammac, AD_AUTH_INDICATOR, AD_CAMMAC, KEYUSAGE_CAMMAC};

/// KRB5_PAC_CREDENTIALS_INFO.
const PAC_CREDENTIALS_INFO: u32 = 2;
const AUTH_INDICATORS: &str = "auth-indicators";
const MSPAC_PREFIX: &str = "urn:mspac:";

/// pac.c `mspac_attribute_types`; `None` is the whole PAC.
const MSPAC_ATTRS: &[(Option<u32>, &str)] = &[
    (None, "urn:mspac:"),
    (Some(PAC_LOGON_INFO), "urn:mspac:logon-info"),
    (Some(PAC_CREDENTIALS_INFO), "urn:mspac:credentials-info"),
    (Some(PAC_SERVER_CHECKSUM), "urn:mspac:server-checksum"),
    (Some(PAC_PRIVSVR_CHECKSUM), "urn:mspac:privsvr-checksum"),
    (Some(PAC_CLIENT_INFO), "urn:mspac:client-info"),
    (Some(PAC_DELEGATION_INFO), "urn:mspac:delegation-info"),
    (Some(PAC_UPN_DNS_INFO), "urn:mspac:upn-dns-info"),
];

/// One value of a name attribute (gss_get_name_attribute outputs).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NameAttrValue {
    /// value.
    pub value: Vec<u8>,
    /// display_value (always empty for the built-in modules).
    pub display_value: Vec<u8>,
    /// authenticated.
    pub authenticated: bool,
    /// complete.
    pub complete: bool,
}

/// The authdata context of a name (`krb5_authdata_context`).
#[derive(Debug, Clone, Default)]
pub(super) struct NameAttrs {
    pub(super) pac: Option<Pac>,
    pub(super) pac_verified: bool,
    pub(super) indicators: Vec<String>,
}

/// mspac_attr2type: `Some(None)` is the whole PAC.
fn mspac_attr2type(attr: &str) -> Option<Option<u32>> {
    if let Some((t, _)) = MSPAC_ATTRS
        .iter()
        .find(|(_, name)| name.eq_ignore_ascii_case(attr))
    {
        return Some(*t);
    }
    let prefix = attr.get(..MSPAC_PREFIX.len())?;
    let rest = &attr[MSPAC_PREFIX.len()..];
    if !prefix.eq_ignore_ascii_case(MSPAC_PREFIX) || rest.is_empty() {
        return None;
    }
    // strtoul with nothing after the digits; a value of 0 is refused.
    match rest.parse::<u32>() {
        Ok(t) if t != 0 => Some(Some(t)),
        _ => None,
    }
}

fn unavailable() -> Krb5Error {
    gss(GssError::Unavailable)
}

impl NameAttrs {
    /// krb5int_authdata_verify (authdata.c:613-725) for the mspac and
    /// auth-indicators modules, with `key` the ticket's service key.
    pub(super) fn import(ticket: &EncTicketPart, key: &EncryptionKey) -> Result<Self, Krb5Error> {
        let failure = || gss(GssError::Failure);
        let ticket_ad = ticket.authorization_data.as_deref().unwrap_or(&[]);
        let mut attrs = NameAttrs::default();

        // get_cammac_authdata / extract_cammacs: CAMMACs whose service
        // verifier fails are ignored; undecodable ones or ones without a
        // service verifier fail the request.
        let mut cammacs = Vec::new();
        find_authdata(ticket_ad, AD_CAMMAC, &mut cammacs);
        let mut verified = Vec::new();
        for der in cammacs {
            let cammac = rasn::der::decode::<Cammac>(&der).map_err(|_| failure())?;
            let ver = cammac.svc_verifier.as_ref().ok_or_else(failure)?;
            let data = rasn::der::encode(&cammac.elements).map_err(|_| failure())?;
            let profile = find_etype(key.keytype).map_err(|_| failure())?;
            if ver.mac.cksumtype == profile.checksum_type()
                && profile
                    .verify_checksum(
                        key.key_bytes(),
                        KEYUSAGE_CAMMAC,
                        &data,
                        ver.mac.checksum.as_ref(),
                    )
                    .is_ok()
            {
                verified.extend(cammac.elements);
            }
        }

        // mspac (AD_USAGE_TGS_REQ): the first PAC in the ticket.
        let mut pacs = Vec::new();
        find_authdata(ticket_ad, AD_WIN2K_PAC, &mut pacs);
        if let Some(der) = pacs.first() {
            let pac = Pac::parse(der).map_err(|_| failure())?;
            // mspac_verify: a failed check only leaves the PAC unverified.
            let crealm = String::from_utf8_lossy(ticket.crealm.as_bytes()).into_owned();
            attrs.pac_verified = pac
                .verify(
                    ticket.authtime.timestamp(),
                    Some((&ticket.cname, &crealm)),
                    Some(key),
                    None,
                )
                .is_ok();
            attrs.pac = Some(pac);
        }

        // auth-indicators (AD_CAMMAC_PROTECTED): k5_authind_decode.
        let mut inds = Vec::new();
        find_authdata(&verified, AD_AUTH_INDICATOR, &mut inds);
        for der in inds {
            let list =
                rasn::der::decode::<Vec<rasn::types::Utf8String>>(&der).map_err(|_| failure())?;
            attrs
                .indicators
                .extend(list.into_iter().map(|s| s.to_string()));
        }
        Ok(attrs)
    }
}

impl NameAttrs {
    /// k5_ad_externalize over the mspac and authentication-indicators
    /// modules (authdata.c, pac.c mspac_externalize, ai_authdata.c
    /// authind_externalize).
    fn externalize(&self) -> Vec<u8> {
        let mut out = 2u32.to_be_bytes().to_vec();
        let mut module = |name: &str, body: Vec<u8>| {
            out.extend_from_slice(&(name.len() as u32).to_be_bytes());
            out.extend_from_slice(name.as_bytes());
            out.extend_from_slice(&body);
        };
        let mut pac = Vec::new();
        match &self.pac {
            Some(p) => {
                let data = p.encode();
                pac.extend_from_slice(&(data.len() as u32).to_be_bytes());
                pac.extend_from_slice(&data);
                pac.extend_from_slice(&u32::from(self.pac_verified).to_be_bytes());
            }
            None => pac.extend_from_slice(&[0; 8]),
        }
        module("mspac", pac);
        let mut ind = (self.indicators.len() as u32).to_be_bytes().to_vec();
        for i in &self.indicators {
            ind.extend_from_slice(&(i.len() as u32).to_be_bytes());
            ind.extend_from_slice(i.as_bytes());
        }
        module("authentication-indicators", ind);
        out
    }
}

impl Krb5Context {
    /// gss_export_name_composite (naming_exts.c:583-666) for the
    /// initiator name: `04 02`, the krb5 mech OID, the principal and the
    /// externalized name attributes (none for a locally initiated context,
    /// whose name has no authdata context).
    pub fn export_name_composite(&self) -> Vec<u8> {
        let princ = crate::ccache::unparse_name(&self.initiator, &self.crealm);
        let attrs = if self.initiate {
            Vec::new()
        } else {
            self.name_attrs.externalize()
        };
        let mech = super::MECH_KRB5;
        let mut out = vec![0x04, 0x02];
        out.extend_from_slice(&((mech.len() + 2) as u16).to_be_bytes());
        out.extend_from_slice(&[0x06, mech.len() as u8]);
        out.extend_from_slice(mech);
        out.extend_from_slice(&(princ.len() as u32).to_be_bytes());
        out.extend_from_slice(princ.as_bytes());
        out.extend_from_slice(&(attrs.len() as u32).to_be_bytes());
        out.extend_from_slice(&attrs);
        out
    }

    /// gss_inquire_name: the attribute names of the initiator name
    /// (krb5_authdata_get_attribute_types).
    pub fn inquire_name(&self) -> Vec<String> {
        let mut out = Vec::new();
        if let Some(pac) = &self.name_attrs.pac {
            out.push(MSPAC_PREFIX.to_string());
            for t in pac.types() {
                match MSPAC_ATTRS.iter().find(|(ty, _)| *ty == Some(t)) {
                    Some((_, name)) => out.push(name.to_string()),
                    None => out.push(format!("{MSPAC_PREFIX}{t}")),
                }
            }
        }
        if !self.name_attrs.indicators.is_empty() {
            out.push(AUTH_INDICATORS.to_string());
        }
        out
    }

    /// gss_get_name_attribute, all values at once (the `more` loop).
    /// A missing attribute, or a PAC that did not verify, is
    /// `GssError::Unavailable`.
    pub fn get_name_attribute(&self, attr: &str) -> Result<Vec<NameAttrValue>, Krb5Error> {
        let attrs = &self.name_attrs;
        if let (Some(pac), true) = (&attrs.pac, attrs.pac_verified) {
            if let Some(ty) = mspac_attr2type(attr) {
                let value = match ty {
                    None => Some(pac.encode()),
                    Some(t) => pac.get_buffer(t).ok().map(<[u8]>::to_vec),
                };
                if let Some(value) = value {
                    return Ok(vec![NameAttrValue {
                        value,
                        display_value: Vec::new(),
                        authenticated: true,
                        complete: true,
                    }]);
                }
            }
        }
        if attr.as_bytes() == AUTH_INDICATORS.as_bytes() && !attrs.indicators.is_empty() {
            return Ok(attrs
                .indicators
                .iter()
                .map(|i| NameAttrValue {
                    value: i.as_bytes().to_vec(),
                    display_value: Vec::new(),
                    authenticated: true,
                    complete: true,
                })
                .collect());
        }
        Err(unavailable())
    }

    /// gss_set_name_attribute (krb5_authdata_set_attribute): only PAC
    /// attributes can be set, and only when the name has a PAC; a new
    /// whole PAC is unverified.  `auth-indicators` is refused.
    pub fn set_name_attribute(
        &mut self,
        _complete: bool,
        attr: &str,
        value: &[u8],
    ) -> Result<(), Krb5Error> {
        let attrs = &mut self.name_attrs;
        let mut found = false;
        if let Some(pac) = &mut attrs.pac {
            match mspac_attr2type(attr) {
                Some(None) => {
                    *pac = Pac::parse(value).map_err(|_| gss(GssError::Failure))?;
                    attrs.pac_verified = false;
                    found = true;
                }
                Some(Some(t)) => {
                    pac.add_buffer(t, value)
                        .map_err(|_| gss(GssError::Failure))?;
                    // k5_pac_add_buffer clears the verified flag (pac.c:102).
                    attrs.pac_verified = false;
                    found = true;
                }
                None => {}
            }
        }
        if attr.as_bytes() == AUTH_INDICATORS.as_bytes() {
            return Err(unavailable());
        }
        if found {
            Ok(())
        } else {
            Err(unavailable())
        }
    }

    /// gss_delete_name_attribute: neither built-in module deletes
    /// attributes, so this is always `GssError::Unavailable`.
    pub fn delete_name_attribute(&mut self, _attr: &str) -> Result<(), Krb5Error> {
        Err(unavailable())
    }

    /// gss_localname for the initiator name (krb5_aname_to_localname).
    pub fn localname(&self, profile: &Profile) -> Result<String, Krb5Error> {
        crate::localauth::aname_to_localname(profile, &self.initiator, &self.crealm)
            .map_err(|_| gss(GssError::Failure))
    }

    /// gss_authorize_localname for the initiator name (krb5_kuserok).
    pub fn authorize_localname(&self, profile: &Profile, user: &str) -> bool {
        crate::localauth::kuserok(profile, &self.initiator, &self.crealm, user)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::util::generate_random;
    use crate::types::{Checksum, Realm as GeneralString, TransitedEncoding, VerifierMac};

    fn gs(s: &str) -> GeneralString {
        GeneralString::from_bytes(s.as_bytes()).expect("gs")
    }

    fn ticket(ad: Vec<AuthorizationDataElement>) -> EncTicketPart {
        let now = chrono::Utc::now().fixed_offset();
        EncTicketPart {
            flags: Default::default(),
            key: EncryptionKey::new(18, vec![0; 32]),
            crealm: gs("R"),
            cname: PrincipalName::new_principal("u"),
            transited: TransitedEncoding {
                tr_type: 1,
                contents: Vec::new().into(),
            },
            authtime: now,
            starttime: None,
            endtime: now,
            renew_till: None,
            caddr: None,
            authorization_data: Some(ad),
        }
    }

    fn cammac(key: &EncryptionKey, inds: &[&str]) -> AuthorizationDataElement {
        let strings: Vec<rasn::types::Utf8String> = inds.iter().map(|s| s.to_string()).collect();
        let elements = vec![AuthorizationDataElement {
            ad_type: AD_AUTH_INDICATOR,
            ad_data: rasn::der::encode(&strings).expect("enc").into(),
        }];
        let p = find_etype(key.keytype).expect("etype");
        let mac = p
            .checksum(
                key.key_bytes(),
                KEYUSAGE_CAMMAC,
                &rasn::der::encode(&elements).expect("enc"),
            )
            .expect("mac");
        let c = Cammac {
            elements,
            kdc_verifier: None,
            svc_verifier: Some(VerifierMac {
                identifier: None,
                kvno: None,
                enctype: None,
                mac: Checksum {
                    cksumtype: p.checksum_type(),
                    checksum: mac.into(),
                },
            }),
            other_verifiers: None,
        };
        let inner = vec![AuthorizationDataElement {
            ad_type: AD_CAMMAC,
            ad_data: rasn::der::encode(&c).expect("enc").into(),
        }];
        AuthorizationDataElement {
            ad_type: 1,
            ad_data: rasn::der::encode(&inner).expect("enc").into(),
        }
    }

    fn ctx_with(attrs: NameAttrs) -> Krb5Context {
        let none = PrincipalName::new_principal("u");
        let mut c = Krb5Context::partial(
            GssFlags::empty(),
            false,
            none.clone(),
            "R".into(),
            none,
            chrono::Utc::now().fixed_offset(),
            EncryptionKey::new(18, vec![0; 32]),
            0,
        );
        c.name_attrs = attrs;
        c
    }

    #[test]
    fn indicators_need_a_valid_service_verifier() {
        let key = EncryptionKey::new(18, generate_random(32));
        let other = EncryptionKey::new(18, generate_random(32));
        let t = ticket(vec![
            cammac(&key, &["otp", "hw"]),
            cammac(&other, &["forged"]),
        ]);
        let c = ctx_with(NameAttrs::import(&t, &key).expect("import"));
        assert_eq!(c.inquire_name(), vec!["auth-indicators"]);
        let vals = c.get_name_attribute("auth-indicators").expect("attr");
        let got: Vec<&[u8]> = vals.iter().map(|v| v.value.as_slice()).collect();
        assert_eq!(got, vec![&b"otp"[..], &b"hw"[..]]);
        assert!(vals.iter().all(|v| v.authenticated && v.complete));
        let mut c = c;
        assert!(matches!(
            c.set_name_attribute(true, "auth-indicators", b"x"),
            Err(Krb5Error::Gss(GssError::Unavailable))
        ));
        assert!(c.delete_name_attribute("auth-indicators").is_err());
        assert!(c.get_name_attribute("urn:mspac:").is_err());
    }

    #[test]
    fn pac_attributes_only_when_verified() {
        let key = EncryptionKey::new(18, generate_random(32));
        let kdc = EncryptionKey::new(18, generate_random(32));
        let t0 = ticket(Vec::new());
        let mut pac = Pac::new();
        let crealm = "R";
        let signed = pac
            .sign(t0.authtime.timestamp(), (&t0.cname, crealm), &key, &kdc)
            .expect("sign");
        let ad = |data: Vec<u8>| {
            let inner = vec![AuthorizationDataElement {
                ad_type: AD_WIN2K_PAC,
                ad_data: data.into(),
            }];
            AuthorizationDataElement {
                ad_type: 1,
                ad_data: rasn::der::encode(&inner).expect("enc").into(),
            }
        };
        let c =
            ctx_with(NameAttrs::import(&ticket(vec![ad(signed.clone())]), &key).expect("import"));
        let names = c.inquire_name();
        assert_eq!(names[0], "urn:mspac:");
        assert!(names.contains(&"urn:mspac:client-info".to_string()));
        assert_eq!(
            c.get_name_attribute("URN:MSPAC:").expect("pac")[0].value,
            signed
        );
        assert!(c.get_name_attribute("urn:mspac:client-info").is_ok());
        assert!(c.get_name_attribute("urn:mspac:logon-info").is_err());
        // Verified with the wrong key: present but hidden.
        let c = ctx_with(NameAttrs::import(&ticket(vec![ad(signed)]), &kdc).expect("import"));
        assert!(!c.inquire_name().is_empty());
        assert!(c.get_name_attribute("urn:mspac:").is_err());
        assert_eq!(mspac_attr2type("urn:mspac:42"), Some(Some(42)));
        assert_eq!(mspac_attr2type("urn:mspac:0"), None);
        assert_eq!(mspac_attr2type("urn:mspac:4x"), None);
    }
}
