//! Client authdata modules: MIT's `krb5plugin_authdata_client_ftable_v0`
//! (include/krb5/authdata_plugin.h) and the `krb5_authdata_context` that
//! runs them (lib/krb5/krb/authdata.c), plus `krb5_make_authdata_kdc_issued`
//! and `krb5_verify_authdata_kdc_issued` (authdata_enc.c).
//!
//! MIT loads client modules from `plugin_base_dir/authdata`; here a module
//! is installed with [`register_module`]. Installed modules run after the
//! built-in mspac and auth-indicators modules, in installation order.

use std::sync::{Arc, RwLock};

use subtle::ConstantTimeEq;

use crate::crypto::find_etype;
use crate::pac::{AD_IF_RELEVANT, AD_WIN2K_PAC};
use crate::types::{
    AdKdcIssued, AuthorizationDataElement, Checksum, EncTicketPart, EncryptionKey, PrincipalName,
    AD_AUTH_INDICATOR, AD_CAMMAC, AD_KDC_ISSUED, KEYUSAGE_AD_KDCISSUED_CKSUM,
};

pub mod greet;

/// `AD_USAGE_AS_REQ`.
pub const AD_USAGE_AS_REQ: u32 = 0x01;
/// `AD_USAGE_TGS_REQ`.
pub const AD_USAGE_TGS_REQ: u32 = 0x02;
/// `AD_USAGE_AP_REQ`.
pub const AD_USAGE_AP_REQ: u32 = 0x04;
/// `AD_USAGE_KDC_ISSUED`.
pub const AD_USAGE_KDC_ISSUED: u32 = 0x08;
/// `AD_INFORMATIONAL`: errors from the module are ignored.
pub const AD_INFORMATIONAL: u32 = 0x10;
/// `AD_CAMMAC_PROTECTED`.
pub const AD_CAMMAC_PROTECTED: u32 = 0x20;
/// `AD_USAGE_MASK`.
pub const AD_USAGE_MASK: u32 = 0x2F;

/// `ENOENT`: the module has no such attribute.
pub const ENOENT: i32 = 2;
/// `EPERM`.
pub const EPERM: i32 = 1;
/// `EEXIST`.
pub const EEXIST: i32 = 17;
/// `EINVAL`.
pub const EINVAL: i32 = 22;
/// `KRB5_AUTHDATA_SIGNTICKET`.
const AD_SIGNTICKET: i32 = 512;
/// `ASN1_BAD_FORMAT` (asn1_err.et).
const ASN1_BAD_FORMAT: i32 = 1_859_794_440;

/// A principal and its realm.
pub type Principal = (PrincipalName, String);

/// One value of a name attribute (`krb5_authdata_get_attribute` outputs).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NameAttrValue {
    /// value.
    pub value: Vec<u8>,
    /// display_value.
    pub display_value: Vec<u8>,
    /// authenticated.
    pub authenticated: bool,
    /// complete.
    pub complete: bool,
}

/// A client authdata module: the plugin-wide callbacks of
/// `krb5plugin_authdata_client_ftable_v0`.
pub trait AuthdataModule: Send + Sync {
    /// `name`.
    fn name(&self) -> &str;
    /// `ad_type_list`.
    fn ad_types(&self) -> &[i32];
    /// `init`.
    fn init(&self) -> Result<(), i32> {
        Ok(())
    }
    /// `fini`.
    fn fini(&self) {}
    /// `flags`: the `AD_USAGE_*` and `AD_*` flags for `ad_type`.
    fn flags(&self, ad_type: i32) -> u32;
    /// `request_init`: the per-context state.
    fn request_init(&self) -> Result<Box<dyn AuthdataRequestContext>, i32>;
}

/// The per-context callbacks of `krb5plugin_authdata_client_ftable_v0`
/// (`request_fini` is `Drop`). Every default is MIT's behavior for a
/// missing callback.
pub trait AuthdataRequestContext: Send + Sync {
    /// `import_authdata`: `authdata` holds the elements of the module's type;
    /// `kdc_issued` is whether they came from verified AD-KDC-ISSUED or
    /// CAMMAC data, signed by `issuer`.
    fn import_authdata(
        &mut self,
        authdata: &[AuthorizationDataElement],
        kdc_issued: bool,
        issuer: Option<&Principal>,
    ) -> Result<(), i32> {
        let _ = (authdata, kdc_issued, issuer);
        Ok(())
    }
    /// `verify`, after a successful import, with the ticket, the key that
    /// decrypted it and the authenticator's authorization data.
    fn verify(
        &mut self,
        ticket: &EncTicketPart,
        key: &EncryptionKey,
        authenticator_authdata: &[AuthorizationDataElement],
    ) -> Result<(), i32> {
        let _ = (ticket, key, authenticator_authdata);
        Ok(())
    }
    /// `get_attribute_types`.
    fn get_attribute_types(&self) -> Result<Vec<String>, i32> {
        Err(ENOENT)
    }
    /// `get_attribute`, all values (the `more` loop).
    fn get_attribute(&self, attribute: &str) -> Result<Vec<NameAttrValue>, i32> {
        let _ = attribute;
        Err(ENOENT)
    }
    /// `set_attribute`.
    fn set_attribute(&mut self, complete: bool, attribute: &str, value: &[u8]) -> Result<(), i32> {
        let _ = (complete, attribute, value);
        Err(ENOENT)
    }
    /// `delete_attribute`.
    fn delete_attribute(&mut self, attribute: &str) -> Result<(), i32> {
        let _ = attribute;
        Err(ENOENT)
    }
    /// `export_authdata` for `usage`; `None` is a missing callback.
    fn export_authdata(&self, usage: u32) -> Option<Result<Vec<AuthorizationDataElement>, i32>> {
        let _ = usage;
        None
    }
    /// `size` and `externalize`; `None` is a missing callback.
    fn externalize(&self) -> Option<Vec<u8>> {
        None
    }
    /// `internalize`, consuming its bytes from the front of `buf`.
    fn internalize(&mut self, buf: &mut &[u8]) -> Result<(), i32> {
        let _ = buf;
        Err(EINVAL)
    }
    /// `copy`; `None` copies through externalize and internalize.
    fn copy(&self) -> Option<Box<dyn AuthdataRequestContext>> {
        None
    }
}

static MODULES: RwLock<Vec<Arc<dyn AuthdataModule>>> = RwLock::new(Vec::new());

/// Install a client authdata module, as placing it in MIT's
/// `plugin_base_dir/authdata` does. As in MIT, a module whose `init`
/// fails is not used; installing a module name twice keeps the first.
pub fn register_module(module: Arc<dyn AuthdataModule>) -> Result<(), i32> {
    let mut list = MODULES.write().unwrap_or_else(|e| e.into_inner());
    if list.iter().any(|m| m.name() == module.name()) {
        return Ok(());
    }
    module.init()?;
    list.push(module);
    Ok(())
}

/// The installed client authdata modules, in order.
pub fn modules() -> Vec<Arc<dyn AuthdataModule>> {
    MODULES.read().unwrap_or_else(|e| e.into_inner()).clone()
}

/// One module instance (one per authdata type, sharing the module's
/// request context, as `k5_ad_init_modules`).
struct Instance {
    module: Arc<dyn AuthdataModule>,
    ad_type: i32,
    flags: u32,
    primary: bool,
    req: usize,
}

/// The installed modules' part of a `krb5_authdata_context`.
#[derive(Default)]
pub struct AuthdataContext {
    instances: Vec<Instance>,
    reqs: Vec<Box<dyn AuthdataRequestContext>>,
}

impl std::fmt::Debug for AuthdataContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_list()
            .entries(self.instances.iter().map(|i| (i.module.name(), i.ad_type)))
            .finish()
    }
}

impl Clone for AuthdataContext {
    /// `k5_copy_ad_module_data`: `copy`, else externalize then
    /// internalize into a new request context. A module that cannot be
    /// copied starts empty.
    fn clone(&self) -> Self {
        let mut reqs = Vec::new();
        for (i, req) in self.reqs.iter().enumerate() {
            let module = self
                .instances
                .iter()
                .find(|inst| inst.req == i)
                .map(|inst| &inst.module);
            let copied = req.copy().or_else(|| {
                let module = module?;
                let mut new = module.request_init().ok()?;
                let data = req.externalize()?;
                new.internalize(&mut data.as_slice()).ok()?;
                Some(new)
            });
            match copied.or_else(|| module.and_then(|m| m.request_init().ok())) {
                Some(r) => reqs.push(r),
                None => return Self::default(),
            }
        }
        let instances = self
            .instances
            .iter()
            .map(|i| Instance {
                module: Arc::clone(&i.module),
                ad_type: i.ad_type,
                flags: i.flags,
                primary: i.primary,
                req: i.req,
            })
            .collect();
        Self { instances, reqs }
    }
}

fn find_authdata_1(
    list: &[AuthorizationDataElement],
    ad_type: i32,
    from_ap_req: bool,
    out: &mut Vec<AuthorizationDataElement>,
) -> Result<(), i32> {
    for ad in list {
        match ad.ad_type {
            AD_IF_RELEVANT => {
                let inner: Vec<AuthorizationDataElement> =
                    rasn::der::decode(ad.ad_data.as_ref()).map_err(|_| ASN1_BAD_FORMAT)?;
                find_authdata_1(&inner, ad_type, from_ap_req, out)?;
            }
            AD_SIGNTICKET | AD_KDC_ISSUED | AD_WIN2K_PAC | AD_CAMMAC | AD_AUTH_INDICATOR
                if from_ap_req => {}
            t if t == ad_type => out.push(ad.clone()),
            _ => {}
        }
    }
    Ok(())
}

/// `krb5_find_authdata`: the elements of `ad_type` in the ticket's and
/// the authenticator's authorization data, looking inside AD-IF-RELEVANT.
/// Types only the KDC may issue are ignored in the authenticator.
pub fn find_authdata(
    ticket: Option<&[AuthorizationDataElement]>,
    ap_req: Option<&[AuthorizationDataElement]>,
    ad_type: i32,
) -> Result<Vec<AuthorizationDataElement>, i32> {
    let mut out = Vec::new();
    if let Some(t) = ticket {
        find_authdata_1(t, ad_type, false, &mut out)?;
    }
    if let Some(a) = ap_req {
        find_authdata_1(a, ad_type, true, &mut out)?;
    }
    Ok(out)
}

fn kdc_issued_checksum(
    key: &EncryptionKey,
    elements: &[AuthorizationDataElement],
) -> Result<Checksum, i32> {
    let generic = crate::plugin::rpc::ERROR_TABLE_BASE_KRB5 + crate::plugin::rpc::KRB_ERR_GENERIC;
    let profile = find_etype(key.keytype).map_err(|_| generic)?;
    let data = rasn::der::encode(&elements.to_vec()).map_err(|_| generic)?;
    let mac = profile
        .checksum(key.key_bytes(), KEYUSAGE_AD_KDCISSUED_CKSUM, &data)
        .map_err(|_| generic)?;
    Ok(Checksum {
        cksumtype: profile.checksum_type(),
        checksum: mac.into(),
    })
}

/// `krb5_make_authdata_kdc_issued`: an AD-KDC-ISSUED element holding
/// `elements`, checksummed with `key` and naming `issuer`.
pub fn make_authdata_kdc_issued(
    key: &EncryptionKey,
    issuer: Option<(&PrincipalName, &str)>,
    elements: &[AuthorizationDataElement],
) -> Result<AuthorizationDataElement, i32> {
    let generic = crate::plugin::rpc::ERROR_TABLE_BASE_KRB5 + crate::plugin::rpc::KRB_ERR_GENERIC;
    let ad = AdKdcIssued {
        ad_checksum: kdc_issued_checksum(key, elements)?,
        i_realm: issuer
            .map(|(_, r)| rasn::types::GeneralString::try_from(r.as_bytes().to_vec()))
            .transpose()
            .map_err(|_| generic)?,
        i_sname: issuer.map(|(n, _)| n.clone()),
        elements: elements.to_vec(),
    };
    Ok(AuthorizationDataElement {
        ad_type: AD_KDC_ISSUED,
        ad_data: rasn::der::encode(&ad).map_err(|_| generic)?.into(),
    })
}

/// `krb5_verify_authdata_kdc_issued`: the issuer and elements of an
/// AD-KDC-ISSUED element. `Ok(None)` is a checksum that `key` does not
/// verify (the errors `k5_get_kdc_issued_authdata` ignores); `Err` is an
/// element that is not AD-KDC-ISSUED or does not decode.
#[allow(clippy::type_complexity)]
pub fn verify_authdata_kdc_issued(
    key: &EncryptionKey,
    el: &AuthorizationDataElement,
) -> Result<Option<(Option<Principal>, Vec<AuthorizationDataElement>)>, i32> {
    if el.ad_type != AD_KDC_ISSUED {
        return Err(EINVAL);
    }
    let ad: AdKdcIssued = rasn::der::decode(el.ad_data.as_ref()).map_err(|_| ASN1_BAD_FORMAT)?;
    let Ok(want) = kdc_issued_checksum(key, &ad.elements) else {
        return Ok(None);
    };
    if want.cksumtype != ad.ad_checksum.cksumtype
        || !bool::from(
            want.checksum
                .as_ref()
                .ct_eq(ad.ad_checksum.checksum.as_ref()),
        )
    {
        return Ok(None);
    }
    let issuer = match (ad.i_sname, ad.i_realm) {
        (Some(n), Some(r)) => Some((n, String::from_utf8_lossy(r.as_bytes()).into_owned())),
        _ => None,
    };
    Ok(Some((issuer, ad.elements)))
}

/// `k5_get_kdc_issued_authdata`: the first AD-KDC-ISSUED element of the
/// ticket, verified with the ticket session key.
#[allow(clippy::type_complexity)]
pub fn get_kdc_issued_authdata(
    ticket: &EncTicketPart,
) -> Result<Option<(Option<Principal>, Vec<AuthorizationDataElement>)>, i32> {
    let ad = find_authdata(ticket.authorization_data.as_deref(), None, AD_KDC_ISSUED)?;
    match ad.first() {
        Some(el) => verify_authdata_kdc_issued(&ticket.key, el),
        None => Ok(None),
    }
}

impl AuthdataContext {
    /// `krb5_authdata_context_init` over the installed modules. A module
    /// whose `request_init` fails is left out.
    pub fn new() -> Self {
        let mut ctx = Self::default();
        for module in modules() {
            let Ok(req) = module.request_init() else {
                continue;
            };
            let idx = ctx.reqs.len();
            ctx.reqs.push(req);
            for (n, &ad_type) in module.ad_types().iter().enumerate() {
                ctx.instances.push(Instance {
                    module: Arc::clone(&module),
                    ad_type,
                    flags: module.flags(ad_type),
                    primary: n == 0,
                    req: idx,
                });
            }
        }
        ctx
    }

    /// `krb5int_authdata_verify` for the installed modules, given the
    /// ticket's verified AD-KDC-ISSUED and CAMMAC contents.
    #[allow(clippy::type_complexity)]
    pub fn verify(
        &mut self,
        usage: u32,
        ticket: &EncTicketPart,
        key: &EncryptionKey,
        authenticator_authdata: Option<&[AuthorizationDataElement]>,
        kdc_issued: Option<&(Option<Principal>, Vec<AuthorizationDataElement>)>,
        cammac: Option<&[AuthorizationDataElement]>,
    ) -> Result<(), i32> {
        let ticket_ad = ticket.authorization_data.as_deref();
        for inst in &self.instances {
            if inst.flags & usage == 0 {
                continue;
            }
            let mut authdata = None;
            let mut kdc_issued_flag = false;
            if let Some((_, ad)) = kdc_issued.filter(|_| inst.flags & AD_USAGE_KDC_ISSUED != 0) {
                authdata = Some(find_authdata(Some(ad), None, inst.ad_type)?);
                kdc_issued_flag = true;
            }
            if let Some(ad) = cammac.filter(|_| inst.flags & AD_CAMMAC_PROTECTED != 0) {
                authdata = Some(find_authdata(Some(ad), None, inst.ad_type)?);
                kdc_issued_flag = true;
            }
            let authdata = match authdata.filter(|a| !a.is_empty()) {
                Some(a) => a,
                None => {
                    let ticket_usage = inst.flags & (AD_USAGE_AS_REQ | AD_USAGE_TGS_REQ) != 0;
                    let authen_usage = inst.flags & AD_USAGE_AP_REQ != 0;
                    find_authdata(
                        ticket_ad.filter(|_| ticket_usage),
                        authenticator_authdata.filter(|_| authen_usage),
                        inst.ad_type,
                    )?
                }
            };
            if authdata.is_empty() {
                continue;
            }
            let req = &mut self.reqs[inst.req];
            let issuer = kdc_issued.and_then(|(i, _)| i.as_ref());
            let mut code = req.import_authdata(&authdata, kdc_issued_flag, issuer);
            if code.is_ok() {
                code = req.verify(ticket, key, authenticator_authdata.unwrap_or_default());
            }
            if code.is_err() && inst.flags & AD_INFORMATIONAL != 0 {
                code = Ok(());
            }
            code?;
        }
        Ok(())
    }

    /// `krb5_authdata_get_attribute_types`: modules that fail are skipped.
    pub fn get_attribute_types(&self) -> Vec<String> {
        self.instances
            .iter()
            .filter_map(|i| self.reqs[i.req].get_attribute_types().ok())
            .flatten()
            .collect()
    }

    /// `krb5_authdata_get_attribute`: the first module that has it.
    pub fn get_attribute(&self, attribute: &str) -> Result<Vec<NameAttrValue>, i32> {
        let mut code = Err(ENOENT);
        for i in &self.instances {
            code = self.reqs[i.req].get_attribute(attribute);
            if code.is_ok() {
                break;
            }
        }
        code
    }

    /// `krb5_authdata_set_attribute`: the number of modules that set it,
    /// or the first error other than `ENOENT`.
    pub fn set_attribute(
        &mut self,
        complete: bool,
        attribute: &str,
        value: &[u8],
    ) -> Result<usize, i32> {
        let mut found = 0;
        for i in &self.instances {
            match self.reqs[i.req].set_attribute(complete, attribute, value) {
                Ok(()) => found += 1,
                Err(ENOENT) => {}
                Err(e) => return Err(e),
            }
        }
        Ok(found)
    }

    /// `krb5_authdata_delete_attribute`: as [`Self::set_attribute`].
    pub fn delete_attribute(&mut self, attribute: &str) -> Result<usize, i32> {
        let mut found = 0;
        for i in &self.instances {
            match self.reqs[i.req].delete_attribute(attribute) {
                Ok(()) => found += 1,
                Err(ENOENT) => {}
                Err(e) => return Err(e),
            }
        }
        Ok(found)
    }

    /// `krb5_authdata_export_authdata`: the authdata of the modules whose
    /// flags match `usage`.
    pub fn export_authdata(&self, usage: u32) -> Result<Vec<AuthorizationDataElement>, i32> {
        let mut out = Vec::new();
        for i in self.instances.iter().filter(|i| i.flags & usage != 0) {
            if let Some(ad) = self.reqs[i.req].export_authdata(usage) {
                out.extend(ad?);
            }
        }
        Ok(out)
    }

    /// The per-module part of `k5_ad_externalize`: each primary instance
    /// matching `flags` that externalizes, as its name and bytes.
    pub fn externalize(&self, flags: u32) -> Vec<(String, Vec<u8>)> {
        self.instances
            .iter()
            .filter(|i| i.flags & flags != 0 && i.primary)
            .filter_map(|i| {
                let data = self.reqs[i.req].externalize()?;
                Some((i.module.name().to_string(), data))
            })
            .collect()
    }

    /// The per-module part of `k5_ad_internalize`: internalize `buf` into
    /// the module `name` (`k5_ad_find_module`). `Ok(false)` is no such
    /// module.
    pub fn internalize(&mut self, flags: u32, name: &str, buf: &mut &[u8]) -> Result<bool, i32> {
        let Some(i) = self
            .instances
            .iter()
            .find(|i| i.flags & flags != 0 && i.primary && i.module.name() == name)
        else {
            return Ok(false);
        };
        self.reqs[i.req].internalize(buf)?;
        Ok(true)
    }
}
