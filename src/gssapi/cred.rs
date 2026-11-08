//! krb5 mechanism credential handles (`krb5_gss_cred_id_rec`): export and
//! import (export_cred.c, import_cred.c, the "K5C1" JSON form), inquire
//! (inq_cred.c), store (store_cred.c), reading a ccache (acquire_cred.c
//! `scan_ccache`) and S4U proxy credentials (s4u_gss_glue.c
//! `kg_compose_deleg_cred`).

use std::time::Duration;

use super::GssError;
use crate::ccache::{
    cache_match, default_cache, is_config_principal, new_unique, resolve, split_name, unparse_name,
    CcContext, CcCredential, CcError, Ccache, MemoryCcache,
};
use crate::error::Krb5Error;
use crate::types::{AuthorizationDataElement, EncryptionKey, HostAddress, PrincipalName};

/// CRED_EXPORT_MAGIC.
const CRED_EXPORT_MAGIC: &str = "K5C1";
/// KRB5_CC_CONF_PROXY_IMPERSONATOR.
pub const CONF_PROXY_IMPERSONATOR: &str = "proxy_impersonator";
/// KRB5_CC_CONF_REFRESH_TIME.
pub const CONF_REFRESH_TIME: &str = "refresh_time";

/// gss_cred_usage_t.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredUsage {
    /// GSS_C_BOTH (0).
    Both,
    /// GSS_C_INITIATE (1).
    Initiate,
    /// GSS_C_ACCEPT (2).
    Accept,
}

impl CredUsage {
    fn code(self) -> i64 {
        match self {
            CredUsage::Both => 0,
            CredUsage::Initiate => 1,
            CredUsage::Accept => 2,
        }
    }

    fn from_code(n: i64) -> Option<Self> {
        match n {
            0 => Some(CredUsage::Both),
            1 => Some(CredUsage::Initiate),
            2 => Some(CredUsage::Accept),
            _ => None,
        }
    }
}

/// A principal and its realm.
pub type Principal = (PrincipalName, String);

/// `krb5_gss_name_rec` as exported: principal, service and host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GssName {
    /// Principal (null for a host-based name not yet canonicalized).
    pub princ: Option<Principal>,
    /// Service of a host-based name.
    pub service: Option<String>,
    /// Host of a host-based name.
    pub host: Option<String>,
}

impl GssName {
    /// A name for `princ`.
    pub fn principal(name: PrincipalName, realm: impl Into<String>) -> Self {
        GssName {
            princ: Some((name, realm.into())),
            service: None,
            host: None,
        }
    }
}

/// The credential's ccache: a named cache, or the contents of a MEMORY
/// cache (as export_cred.c carries it).
#[derive(Debug, Clone)]
pub enum CredCache {
    /// A cache name such as `FILE:/tmp/krb5cc_1000`.
    Named(String),
    /// Principal and credentials of a MEMORY cache.
    Memory {
        /// Cache principal.
        principal: Principal,
        /// Credentials, config entries included.
        creds: Vec<CcCredential>,
    },
}

/// A krb5 mechanism credential (`krb5_gss_cred_id_rec`).
#[derive(Debug, Clone)]
pub struct GssCred {
    /// usage.
    pub usage: CredUsage,
    /// name.
    pub name: Option<GssName>,
    /// S4U2Proxy impersonator.
    pub impersonator: Option<Principal>,
    /// default_identity.
    pub default_identity: bool,
    /// iakerb_mech.
    pub iakerb_mech: bool,
    /// Acceptor keytab name.
    pub keytab: Option<String>,
    /// Replay cache name.
    pub rcache: Option<String>,
    /// Initiator ccache.
    pub ccache: Option<CredCache>,
    /// Client keytab name.
    pub client_keytab: Option<String>,
    /// have_tgt.
    pub have_tgt: bool,
    /// Expiry (unix seconds; 0 = indefinite).
    pub expire: i64,
    /// refresh_time.
    pub refresh_time: i64,
    /// req_enctypes.
    pub req_enctypes: Option<Vec<i32>>,
    /// password.
    pub password: Option<String>,
}

/// gss_inquire_cred results.
#[derive(Debug, Clone)]
pub struct CredInfo {
    /// Credential name.
    pub name: Option<GssName>,
    /// Remaining lifetime; `None` is GSS_C_INDEFINITE, zero is
    /// GSS_S_CREDENTIALS_EXPIRED.
    pub lifetime: Option<Duration>,
    /// Usage.
    pub usage: CredUsage,
}

fn gss(e: GssError) -> Krb5Error {
    Krb5Error::Gss(e)
}

fn cc(_: CcError) -> Krb5Error {
    gss(GssError::Failure)
}

fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

impl GssCred {
    fn empty(usage: CredUsage) -> Self {
        GssCred {
            usage,
            name: None,
            impersonator: None,
            default_identity: false,
            iakerb_mech: false,
            keytab: None,
            rcache: None,
            ccache: None,
            client_keytab: None,
            have_tgt: false,
            expire: 0,
            refresh_time: 0,
            req_enctypes: None,
            password: None,
        }
    }

    /// An initiator credential for the cache `name` (acquire_cred.c
    /// `scan_ccache`): the cache principal names it, the local TGT (else
    /// the first credential) gives the expiry, and the config entries give
    /// the impersonator and refresh time.
    pub fn from_ccache(ctx: &CcContext, name: &str) -> Result<Self, Krb5Error> {
        let cache = resolve(ctx, name).map_err(|_| gss(GssError::NoCred))?;
        let principal = cache.principal().map_err(|_| gss(GssError::NoCred))?;
        let creds = cache.creds().map_err(cc)?;
        let mut cred = GssCred::empty(CredUsage::Initiate);
        cred.ccache = Some(CredCache::Named(cache.name()));
        cred.scan(principal, &creds)?;
        Ok(cred)
    }

    fn scan(&mut self, principal: Principal, creds: &[CcCredential]) -> Result<(), Krb5Error> {
        let realm = principal.1.clone();
        for c in creds {
            if is_config_principal(&c.server, &c.srealm) {
                let key = c.server.name_string.get(1).map(|k| k.as_bytes().to_vec());
                let value = String::from_utf8_lossy(&c.ticket).into_owned();
                match key.as_deref() {
                    Some(k)
                        if k == CONF_PROXY_IMPERSONATOR.as_bytes()
                            && self.impersonator.is_none() =>
                    {
                        self.impersonator = Some(
                            crate::ccache::parse_principal(&value, None)
                                .ok_or(gss(GssError::Failure))?,
                        );
                    }
                    Some(k) if k == CONF_REFRESH_TIME.as_bytes() && self.refresh_time == 0 => {
                        self.refresh_time = value.trim().parse().unwrap_or(0);
                    }
                    _ => {}
                }
                continue;
            }
            let is_tgt = c.srealm == realm
                && c.server.name_string.len() == 2
                && c.server.name_string[0].as_bytes() == b"krbtgt"
                && c.server.name_string[1].as_bytes() == realm.as_bytes();
            if is_tgt {
                self.have_tgt = true;
            }
            if is_tgt || self.expire == 0 {
                self.expire = i64::from(c.endtime);
            }
        }
        self.name = Some(GssName::principal(principal.0, principal.1));
        if self.expire == 0 && self.password.is_none() && self.client_keytab.is_none() {
            return Err(gss(GssError::NoCred));
        }
        Ok(())
    }

    /// The principal of the credential name.
    pub fn principal(&self) -> Option<&Principal> {
        self.name.as_ref().and_then(|n| n.princ.as_ref())
    }

    /// The cache principal and credentials (a MEMORY cache's contents or
    /// those of the named cache).
    pub fn cache_contents(
        &self,
        ctx: &CcContext,
    ) -> Result<(Principal, Vec<CcCredential>), Krb5Error> {
        match &self.ccache {
            None => Err(gss(GssError::DefectiveCredential)),
            Some(CredCache::Memory { principal, creds }) => Ok((principal.clone(), creds.clone())),
            Some(CredCache::Named(name)) => {
                let cache = resolve(ctx, name).map_err(cc)?;
                Ok((cache.principal().map_err(cc)?, cache.creds().map_err(cc)?))
            }
        }
    }

    /// gss_inquire_cred (inq_cred.c:77-196).
    pub fn inquire(&self) -> CredInfo {
        let lifetime = (self.expire != 0)
            .then(|| Duration::from_secs(u64::try_from(self.expire - now()).unwrap_or(0)));
        CredInfo {
            name: self.name.clone(),
            lifetime,
            usage: self.usage,
        }
    }

    /// gss_store_cred_into (store_cred.c): copy an initiator credential
    /// into the default cache, or the cred store's `ccache`.  With a
    /// collection cache type the client's existing cache is replaced, or a
    /// new one made (and made primary when `default_cred`); otherwise the
    /// default cache itself is overwritten.  An occupied target without
    /// `overwrite` is GSS_S_DUPLICATE_ELEMENT.
    pub fn store_into(
        &self,
        ctx: &CcContext,
        usage: CredUsage,
        ccache_name: Option<&str>,
        overwrite: bool,
        default_cred: bool,
    ) -> Result<CredUsage, Krb5Error> {
        if usage == CredUsage::Accept {
            return Err(gss(GssError::Failure));
        }
        let info = self.inquire();
        if info.lifetime == Some(Duration::ZERO) {
            return Err(gss(GssError::CredentialsExpired));
        }
        if self.usage == CredUsage::Accept {
            return Err(gss(GssError::Failure));
        }
        let (_, creds) = self.cache_contents(ctx)?;
        let princ = self
            .principal()
            .ok_or(gss(GssError::DefectiveCredential))?
            .clone();
        let ctx = CcContext {
            default_name: ccache_name
                .map(str::to_string)
                .or_else(|| ctx.default_name.clone()),
            profile_default: ctx.profile_default.clone(),
            kcm_socket: ctx.kcm_socket.clone(),
        };
        let defcache = default_cache(&ctx).map_err(cc)?;
        let defname = defcache.name();
        let deftype = split_name(&defname).0.to_string();
        let (mut cache, switch) = if matches!(deftype.as_str(), "DIR" | "KEYRING" | "KCM") {
            match cache_match(&ctx, &princ.0, &princ.1) {
                Ok(_) if !overwrite => return Err(gss(GssError::DuplicateElement)),
                Ok(c) => (c, default_cred),
                Err(CcError::Code {
                    name: "KRB5_CC_NOTFOUND",
                    ..
                }) => (new_unique(&ctx, &deftype).map_err(cc)?, default_cred),
                Err(e) => return Err(cc(e)),
            }
        } else {
            if defcache.principal().is_ok() && !overwrite {
                return Err(gss(GssError::DuplicateElement));
            }
            (defcache, false)
        };
        cache.initialize(&princ.0, &princ.1).map_err(cc)?;
        for c in &creds {
            cache.store(c).map_err(cc)?;
        }
        if switch {
            cache.switch_to().map_err(cc)?;
        }
        Ok(CredUsage::Initiate)
    }

    /// kg_compose_deleg_cred (s4u_gss_glue.c:203-277): an S4U2Proxy
    /// initiator credential for the client of `subject`, whose MEMORY cache
    /// holds this (impersonator) credential's cache, a
    /// `proxy_impersonator` config entry and `subject`.
    pub fn compose_deleg_cred(
        &self,
        ctx: &CcContext,
        subject: &CcCredential,
    ) -> Result<GssCred, Krb5Error> {
        let imp = self.principal().cloned();
        let initiator =
            matches!(self.usage, CredUsage::Initiate | CredUsage::Both) && self.ccache.is_some();
        let (Some(imp), true, None) = (imp, initiator, &self.impersonator) else {
            return Err(gss(GssError::Failure));
        };
        let (_, imp_creds) = self.cache_contents(ctx)?;
        let mut mem = MemoryCcache::new();
        mem.initialize(&subject.client, &subject.crealm)
            .map_err(cc)?;
        for c in &imp_creds {
            mem.store(c).map_err(cc)?;
        }
        let unparsed = unparse_name(&imp.0, &imp.1);
        mem.set_config(None, CONF_PROXY_IMPERSONATOR, Some(unparsed.as_bytes()))
            .map_err(cc)?;
        mem.store(subject).map_err(cc)?;
        let mut cred = GssCred::empty(CredUsage::Initiate);
        cred.expire = i64::from(subject.endtime);
        cred.name = Some(GssName::principal(
            subject.client.clone(),
            subject.crealm.clone(),
        ));
        cred.impersonator = Some(imp);
        cred.ccache = Some(CredCache::Memory {
            principal: (subject.client.clone(), subject.crealm.clone()),
            creds: mem.creds().map_err(cc)?,
        });
        Ok(cred)
    }

    /// gss_export_cred (export_cred.c): `["K5C1", [...]]` as MIT's k5_json
    /// encodes it.
    pub fn export(&self, ctx: &CcContext) -> Result<Vec<u8>, Krb5Error> {
        let ccache = match &self.ccache {
            None => Json::Null,
            Some(CredCache::Named(n)) if split_name(n).0 != "MEMORY" => Json::Str(n.clone()),
            Some(_) => {
                let (p, creds) = self.cache_contents(ctx)?;
                let mut arr = vec![json_principal(Some(&p))];
                arr.extend(creds.iter().map(json_creds));
                Json::Arr(arr)
            }
        };
        let name = match &self.name {
            None => Json::Null,
            Some(n) => Json::Arr(vec![
                json_principal(n.princ.as_ref()),
                json_opt_str(&n.service),
                json_opt_str(&n.host),
            ]),
        };
        let kg = Json::Arr(vec![
            Json::Num(self.usage.code()),
            name,
            json_principal(self.impersonator.as_ref()),
            Json::Bool(self.default_identity),
            Json::Bool(self.iakerb_mech),
            json_opt_str(&self.keytab),
            json_opt_str(&self.rcache),
            ccache,
            json_opt_str(&self.client_keytab),
            Json::Bool(self.have_tgt),
            Json::Num(self.expire),
            Json::Num(self.refresh_time),
            match &self.req_enctypes {
                None => Json::Null,
                Some(e) => Json::Arr(e.iter().map(|&e| Json::Num(i64::from(e))).collect()),
            },
            json_opt_str(&self.password),
        ]);
        let mut out = String::new();
        Json::Arr(vec![Json::Str(CRED_EXPORT_MAGIC.into()), kg]).encode(&mut out);
        Ok(out.into_bytes())
    }

    /// gss_import_cred (import_cred.c): anything malformed is
    /// GSS_S_DEFECTIVE_TOKEN.
    pub fn import(token: &[u8]) -> Result<Self, Krb5Error> {
        Self::import_inner(token).ok_or(gss(GssError::DefectiveToken))
    }

    fn import_inner(token: &[u8]) -> Option<Self> {
        let text = std::str::from_utf8(token).ok()?;
        let v = Json::decode(text)?;
        let outer = v.arr()?;
        if outer.len() != 2 || outer[0].str()? != CRED_EXPORT_MAGIC {
            return None;
        }
        let a = outer[1].arr()?;
        if a.len() != 14 {
            return None;
        }
        let name = match &a[1] {
            Json::Null => None,
            Json::Arr(n) if n.len() == 3 => Some(GssName {
                princ: to_principal(&n[0])?,
                service: to_opt_str(&n[1])?,
                host: to_opt_str(&n[2])?,
            }),
            _ => return None,
        };
        let ccache = match &a[7] {
            Json::Null => None,
            Json::Str(s) => Some(CredCache::Named(s.clone())),
            Json::Arr(c) if !c.is_empty() => Some(CredCache::Memory {
                principal: to_principal(&c[0])??,
                creds: c[1..].iter().map(to_creds).collect::<Option<_>>()?,
            }),
            _ => return None,
        };
        Some(GssCred {
            usage: CredUsage::from_code(a[0].num()?)?,
            name,
            impersonator: to_principal(&a[2])?,
            default_identity: a[3].bool()?,
            iakerb_mech: a[4].bool()?,
            keytab: to_opt_str(&a[5])?,
            rcache: to_opt_str(&a[6])?,
            ccache,
            client_keytab: to_opt_str(&a[8])?,
            have_tgt: a[9].bool()?,
            expire: a[10].num()?,
            refresh_time: a[11].num()?,
            req_enctypes: match &a[12] {
                Json::Null => None,
                Json::Arr(e) => Some(
                    e.iter()
                        .map(|n| n.num().and_then(|n| i32::try_from(n).ok()))
                        .collect::<Option<_>>()?,
                ),
                _ => return None,
            },
            password: to_opt_str(&a[13])?,
        })
    }
}

fn json_opt_str(s: &Option<String>) -> Json {
    s.as_ref().map_or(Json::Null, |s| Json::Str(s.clone()))
}

fn json_principal(p: Option<&Principal>) -> Json {
    p.map_or(Json::Null, |(n, r)| Json::Str(unparse_name(n, r)))
}

fn json_typed(t: i64, data: &[u8]) -> Json {
    Json::Arr(vec![Json::Num(t), Json::Str(base64_encode(data))])
}

fn json_creds(c: &CcCredential) -> Json {
    let addrs = if c.addresses.is_empty() {
        Json::Null
    } else {
        Json::Arr(
            c.addresses
                .iter()
                .map(|a| json_typed(i64::from(a.addr_type), a.address.as_ref()))
                .collect(),
        )
    };
    let authdata = if c.authdata.is_empty() {
        Json::Null
    } else {
        Json::Arr(
            c.authdata
                .iter()
                .map(|a| json_typed(i64::from(a.ad_type), a.ad_data.as_ref()))
                .collect(),
        )
    };
    Json::Arr(vec![
        Json::Str(unparse_name(&c.client, &c.crealm)),
        Json::Str(unparse_name(&c.server, &c.srealm)),
        json_typed(i64::from(c.keyblock.keytype), c.keyblock.key_bytes()),
        Json::Num(i64::from(c.authtime as i32)),
        Json::Num(i64::from(c.starttime as i32)),
        Json::Num(i64::from(c.endtime as i32)),
        Json::Num(i64::from(c.renew_till as i32)),
        Json::Bool(c.is_skey),
        Json::Num(i64::from(c.ticket_flags as i32)),
        addrs,
        Json::Str(base64_encode(&c.ticket)),
        Json::Str(base64_encode(&c.second_ticket)),
        authdata,
    ])
}

fn to_opt_str(v: &Json) -> Option<Option<String>> {
    match v {
        Json::Null => Some(None),
        Json::Str(s) => Some(Some(s.clone())),
        _ => None,
    }
}

fn to_principal(v: &Json) -> Option<Option<Principal>> {
    match v {
        Json::Null => Some(None),
        Json::Str(s) => crate::ccache::parse_principal(s, None).map(Some),
        _ => None,
    }
}

fn to_typed(v: &Json) -> Option<(i64, Vec<u8>)> {
    let a = v.arr()?;
    if a.len() != 2 {
        return None;
    }
    Some((a[0].num()?, base64_decode(a[1].str()?)?))
}

fn to_typed_list(v: &Json) -> Option<Vec<(i64, Vec<u8>)>> {
    match v {
        Json::Null => Some(Vec::new()),
        Json::Arr(a) => a.iter().map(to_typed).collect(),
        _ => None,
    }
}

fn to_creds(v: &Json) -> Option<CcCredential> {
    let a = v.arr()?;
    if a.len() != 13 {
        return None;
    }
    let (client, crealm) = to_principal(&a[0])??;
    let (server, srealm) = to_principal(&a[1])??;
    let (kt, key) = to_typed(&a[2])?;
    let num32 = |v: &Json| v.num().map(|n| n as i32 as u32);
    Some(CcCredential {
        client,
        crealm,
        server,
        srealm,
        keyblock: EncryptionKey::new(i32::try_from(kt).ok()?, key),
        authtime: num32(&a[3])?,
        starttime: num32(&a[4])?,
        endtime: num32(&a[5])?,
        renew_till: num32(&a[6])?,
        is_skey: a[7].bool()?,
        ticket_flags: num32(&a[8])?,
        addresses: to_typed_list(&a[9])?
            .into_iter()
            .map(|(t, d)| {
                Some(HostAddress {
                    addr_type: i32::try_from(t).ok()?,
                    address: d.into(),
                })
            })
            .collect::<Option<_>>()?,
        ticket: base64_decode(a[10].str()?)?,
        second_ticket: base64_decode(a[11].str()?)?,
        authdata: to_typed_list(&a[12])?
            .into_iter()
            .map(|(t, d)| {
                Some(AuthorizationDataElement {
                    ad_type: i32::try_from(t).ok()?,
                    ad_data: d.into(),
                })
            })
            .collect::<Option<_>>()?,
    })
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// k5_base64_encode.
fn base64_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(B64[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// k5_base64_decode: groups of four characters, `=` padding only at the
/// end.
fn base64_decode(s: &str) -> Option<Vec<u8>> {
    let s = s.as_bytes();
    if !s.len().is_multiple_of(4) {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 4 * 3);
    for (gi, g) in s.chunks(4).enumerate() {
        let last = gi == s.len() / 4 - 1;
        let pad = g.iter().rev().take_while(|&&c| c == b'=').count();
        if pad > 2 || (pad > 0 && !last) {
            return None;
        }
        let mut n = 0u32;
        for &c in &g[..4 - pad] {
            let v = B64.iter().position(|&b| b == c)? as u32;
            n = (n << 6) | v;
        }
        n <<= 6 * pad as u32;
        let bytes = [(n >> 16) as u8, (n >> 8) as u8, n as u8];
        out.extend_from_slice(&bytes[..3 - pad]);
    }
    Some(out)
}

/// The subset of k5_json values the export format uses.
#[derive(Debug, Clone, PartialEq)]
enum Json {
    Null,
    Bool(bool),
    Num(i64),
    Str(String),
    Arr(Vec<Json>),
}

impl Json {
    fn arr(&self) -> Option<&[Json]> {
        match self {
            Json::Arr(a) => Some(a),
            _ => None,
        }
    }

    fn str(&self) -> Option<&str> {
        match self {
            Json::Str(s) => Some(s),
            _ => None,
        }
    }

    fn num(&self) -> Option<i64> {
        match self {
            Json::Num(n) => Some(*n),
            _ => None,
        }
    }

    fn bool(&self) -> Option<bool> {
        match self {
            Json::Bool(b) => Some(*b),
            _ => None,
        }
    }

    /// json.c encode_value / encode_string.
    fn encode(&self, out: &mut String) {
        match self {
            Json::Null => out.push_str("null"),
            Json::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
            Json::Num(n) => out.push_str(&n.to_string()),
            Json::Str(s) => {
                out.push('"');
                for c in s.chars() {
                    match c {
                        '"' => out.push_str("\\\""),
                        '\\' => out.push_str("\\\\"),
                        '\u{8}' => out.push_str("\\b"),
                        '\u{c}' => out.push_str("\\f"),
                        '\n' => out.push_str("\\n"),
                        '\r' => out.push_str("\\r"),
                        '\t' => out.push_str("\\t"),
                        c if (c as u32) < 0x20 => out.push_str(&format!("\\u00{:02X}", c as u32)),
                        c => out.push(c),
                    }
                }
                out.push('"');
            }
            Json::Arr(a) => {
                out.push('[');
                for (i, v) in a.iter().enumerate() {
                    if i != 0 {
                        out.push(',');
                    }
                    v.encode(out);
                }
                out.push(']');
            }
        }
    }

    fn decode(s: &str) -> Option<Json> {
        let mut p = Parser {
            s: s.as_bytes(),
            i: 0,
        };
        let v = p.value(0)?;
        p.ws();
        (p.i == p.s.len()).then_some(v)
    }
}

struct Parser<'a> {
    s: &'a [u8],
    i: usize,
}

impl Parser<'_> {
    fn ws(&mut self) {
        while self.s.get(self.i).is_some_and(|c| b" \t\r\n".contains(c)) {
            self.i += 1;
        }
    }

    fn lit(&mut self, word: &str, v: Json) -> Option<Json> {
        let end = self.i + word.len();
        (self.s.get(self.i..end)? == word.as_bytes()).then(|| {
            self.i = end;
            v
        })
    }

    fn value(&mut self, depth: usize) -> Option<Json> {
        if depth > 64 {
            return None;
        }
        self.ws();
        match *self.s.get(self.i)? {
            b'n' => self.lit("null", Json::Null),
            b't' => self.lit("true", Json::Bool(true)),
            b'f' => self.lit("false", Json::Bool(false)),
            b'"' => self.string().map(Json::Str),
            b'[' => {
                self.i += 1;
                let mut a = Vec::new();
                self.ws();
                if self.s.get(self.i) == Some(&b']') {
                    self.i += 1;
                    return Some(Json::Arr(a));
                }
                loop {
                    a.push(self.value(depth + 1)?);
                    self.ws();
                    match *self.s.get(self.i)? {
                        b',' => self.i += 1,
                        b']' => {
                            self.i += 1;
                            return Some(Json::Arr(a));
                        }
                        _ => return None,
                    }
                }
            }
            b'-' | b'0'..=b'9' => {
                let start = self.i;
                if self.s[self.i] == b'-' {
                    self.i += 1;
                }
                let digits = self.i;
                while self.s.get(self.i).is_some_and(u8::is_ascii_digit) {
                    self.i += 1;
                }
                if self.i == digits {
                    return None;
                }
                std::str::from_utf8(&self.s[start..self.i])
                    .ok()?
                    .parse()
                    .ok()
                    .map(Json::Num)
            }
            _ => None,
        }
    }

    fn string(&mut self) -> Option<String> {
        self.i += 1;
        let mut out = Vec::new();
        loop {
            let c = *self.s.get(self.i)?;
            self.i += 1;
            match c {
                b'"' => return String::from_utf8(out).ok(),
                b'\\' => {
                    let e = *self.s.get(self.i)?;
                    self.i += 1;
                    let ch = match e {
                        b'"' => '"',
                        b'\\' => '\\',
                        b'/' => '/',
                        b'b' => '\u{8}',
                        b'f' => '\u{c}',
                        b'n' => '\n',
                        b'r' => '\r',
                        b't' => '\t',
                        b'u' => {
                            let hex = std::str::from_utf8(self.s.get(self.i..self.i + 4)?).ok()?;
                            self.i += 4;
                            char::from_u32(u32::from_str_radix(hex, 16).ok()?)?
                        }
                        _ => return None,
                    };
                    let mut buf = [0u8; 4];
                    out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
                }
                c if c < 0x20 => return None,
                c => out.push(c),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cred(server: &str, end: u32) -> CcCredential {
        CcCredential {
            client: PrincipalName::new_principal("u"),
            crealm: "R".into(),
            server: server.parse().expect("server"),
            srealm: "R".into(),
            keyblock: EncryptionKey::new(18, vec![7; 32]),
            authtime: 100,
            starttime: 0,
            endtime: end,
            renew_till: 0,
            is_skey: false,
            ticket_flags: 0x4080_0000,
            addresses: Vec::new(),
            authdata: vec![AuthorizationDataElement {
                ad_type: 1,
                ad_data: b"ad".to_vec().into(),
            }],
            ticket: b"tkt".to_vec(),
            second_ticket: Vec::new(),
        }
    }

    #[test]
    fn base64_matches_rfc4648() {
        for (raw, enc) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(base64_encode(raw.as_bytes()), enc);
            assert_eq!(base64_decode(enc).expect("dec"), raw.as_bytes());
        }
        assert!(base64_decode("Zg=").is_none());
        assert!(base64_decode("Zg==Zg==").is_none());
    }

    #[test]
    fn export_import_round_trip_and_format() {
        let ctx = CcContext::default();
        let mut c = GssCred::empty(CredUsage::Initiate);
        c.name = Some(GssName::principal(PrincipalName::new_principal("u"), "R"));
        c.ccache = Some(CredCache::Memory {
            principal: (PrincipalName::new_principal("u"), "R".into()),
            creds: vec![cred("krbtgt/R", 2000)],
        });
        c.expire = 2000;
        c.req_enctypes = Some(vec![18, 17]);
        c.password = Some("p\"w".into());
        let tok = c.export(&ctx).expect("export");
        let s = String::from_utf8(tok.clone()).expect("utf8");
        assert!(s.starts_with("[\"K5C1\",[1,[\"u@R\",null,null],null,false,false,null,null,[\"u@R\",[\"u@R\",\"krbtgt/R@R\",[18,\""), "{s}");
        assert!(s.ends_with(",false,2000,0,[18,17],\"p\\\"w\"]]"), "{s}");
        let back = GssCred::import(&tok).expect("import");
        assert_eq!(back.export(&ctx).expect("export"), tok);
        assert!(matches!(
            GssCred::import(b"[\"K5C2\",[]]"),
            Err(Krb5Error::Gss(GssError::DefectiveToken))
        ));
        assert!(GssCred::import(&tok[..tok.len() - 1]).is_err());
    }

    #[test]
    fn compose_deleg_cred_and_scan() {
        let ctx = CcContext::default();
        let mut imp = GssCred::empty(CredUsage::Both);
        imp.name = Some(GssName::principal("svc/host".parse().expect("p"), "R"));
        imp.ccache = Some(CredCache::Memory {
            principal: ("svc/host".parse().expect("p"), "R".into()),
            creds: vec![cred("krbtgt/R", 5000)],
        });
        let subject = cred("svc/host", 3000);
        let d = imp.compose_deleg_cred(&ctx, &subject).expect("deleg");
        assert_eq!(d.expire, 3000);
        assert_eq!(
            d.impersonator.as_ref().map(|p| unparse_name(&p.0, &p.1)),
            Some("svc/host@R".into())
        );
        assert!(d.compose_deleg_cred(&ctx, &subject).is_err());
        let (_, creds) = d.cache_contents(&ctx).expect("contents");
        let mut scanned = GssCred::empty(CredUsage::Initiate);
        scanned
            .scan(("u".parse().expect("p"), "R".into()), &creds)
            .expect("scan");
        let unparse = |p: &Option<Principal>| p.as_ref().map(|p| unparse_name(&p.0, &p.1));
        assert_eq!(unparse(&scanned.impersonator), unparse(&d.impersonator));
        let tok = d.export(&ctx).expect("export");
        assert_eq!(
            GssCred::import(&tok)
                .expect("import")
                .export(&ctx)
                .expect("e"),
            tok
        );
    }
}
