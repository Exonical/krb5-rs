//! SASL binds (MIT: `ldap_sasl_interactive_bind_s` with the `interact`
//! callback, kdb_ldap_conn.c:95-150, which hands the mechanism to Cyrus
//! SASL).
//!
//! PLAIN, LOGIN, ANONYMOUS, SCRAM-SHA-1/256 and OAUTHBEARER come from
//! `rsasl`; CRAM-MD5, DIGEST-MD5, NTLM, GSSAPI, GSS-SPNEGO, GS2-KRB5 and
//! GS2-IAKERB follow Cyrus SASL 2.1.28's client plugins, the GSS ones on
//! krb5-rs's own GSS-API.  The security properties and server host name are
//! libldap's ([`Params`]).

use std::io;
use std::sync::Arc;

use hmac::{Hmac, KeyInit, Mac};
use ldap3::{Ldap, SaslSecurityLayer};
use md5::{Digest, Md5};

use crate::ldapconf::{self, LdapOptions, SecProps};

mod gs2;
mod ntlm;

const MAXBUF: u32 = 65536;
const SASL_BIND_IN_PROGRESS: u32 = 14;

/// The values MIT's `interact` callback supplies.
#[derive(Debug, Clone, Default)]
pub struct Interact {
    /// `sasl_authcid` (`SASL_CB_AUTHNAME`).
    pub authcid: Option<String>,
    /// `sasl_authzid` (`SASL_CB_USER`).
    pub authzid: Option<String>,
    /// `sasl_realm` (`SASL_CB_GETREALM`).
    pub realm: Option<String>,
    /// The secret (`SASL_CB_PASS`).
    pub password: Option<String>,
}

type Layer = (Box<dyn SaslSecurityLayer>, u32);

trait Mech: Send {
    /// The initial response, if the mechanism is client-first.
    fn start(&mut self) -> Result<Option<Vec<u8>>, String>;
    /// Answer one server challenge.
    fn step(&mut self, challenge: &[u8]) -> Result<Vec<u8>, String>;
    /// The bind succeeded, with optional final server data.
    fn success(&mut self, data: Option<&[u8]>) -> Result<Option<Layer>, String>;
}

/// What libldap gives Cyrus besides the callbacks (cyrus.c:480-560).
#[derive(Debug, Clone)]
pub struct Params {
    /// `serverFQDN`.
    pub host: String,
    /// `SASL_SSF_EXTERNAL`: the TLS cipher strength, or
    /// `LDAP_PVT_SASL_LOCAL_SSF` for `ldapi://`.
    pub external_ssf: u32,
    /// `SASL_SECPROPS`.
    pub props: SecProps,
}

const LOCAL_SSF: u32 = 71;

impl Params {
    /// The host is the local host name for `ldapi://`, the URL's host with
    /// `SASL_NOCANON`, else the connected peer's name (cyrus.c:509-534).
    pub fn new(ldap: &Ldap, url: &str, opts: &LdapOptions) -> Self {
        let ldapi = url
            .split_once("://")
            .is_some_and(|(s, _)| s.eq_ignore_ascii_case("ldapi"));
        let host = if ldapi {
            local_hostname()
        } else if opts.nocanon {
            url_host(url)
        } else {
            host_connected_to(ldap.peer_addr())
        };
        Params {
            host,
            external_ssf: if ldapi { LOCAL_SSF } else { ldap.tls_ssf() },
            props: opts.secprops,
        }
    }

    fn need(&self) -> u32 {
        self.props.min_ssf.saturating_sub(self.external_ssf)
    }

    fn allowed(&self) -> u32 {
        self.props.max_ssf.saturating_sub(self.external_ssf)
    }
}

/// `ldap_int_hostname` (`ldap_pvt_get_fqdn(NULL)`, util-int.c:678-708).
fn local_hostname() -> String {
    let Ok(name) = dns_lookup::get_hostname() else {
        return "localhost".into();
    };
    let hints = dns_lookup::AddrInfoHints {
        flags: libc::AI_CANONNAME,
        address: 0,
        socktype: 0,
        protocol: 0,
    };
    dns_lookup::getaddrinfo(Some(&name), None, Some(hints))
        .ok()
        .and_then(|mut it| it.next())
        .and_then(Result::ok)
        .and_then(|a| a.canonname)
        .filter(|c| !c.is_empty())
        .unwrap_or(name)
}

/// The host part of an LDAP URL.
fn url_host(url: &str) -> String {
    let rest = url.split_once("://").map_or(url, |(_, r)| r);
    let hostport = rest.split('/').next().unwrap_or("");
    let host = match hostport.strip_prefix('[') {
        Some(v6) => v6.split(']').next().unwrap_or(""),
        None => hostport.rsplit_once(':').map_or(hostport, |(h, _)| h),
    };
    if host.is_empty() {
        "localhost".into()
    } else {
        host.to_string()
    }
}

/// `ldap_host_connected_to` (os-ip.c:1170-1240): the peer's reverse-DNS
/// name; the local host name for loopback and unspecified addresses.
fn host_connected_to(peer: Option<std::net::SocketAddr>) -> String {
    use std::net::{IpAddr, Ipv4Addr};
    let Some(peer) = peer else {
        return local_hostname();
    };
    let ip = peer.ip();
    let local = match ip {
        IpAddr::V4(v4) => v4.is_unspecified() || v4 == Ipv4Addr::LOCALHOST,
        IpAddr::V6(v6) => v6.is_unspecified() || v6.is_loopback(),
    };
    if local {
        return local_hostname();
    }
    dns_lookup::lookup_addr(&ip)
        .ok()
        .filter(|h| !h.is_empty())
        .unwrap_or_else(|| "localhost".into())
}

/// `max_ssf` and `security_flags` of each client plugin.
fn mech_props(mech: &str) -> Option<(u32, u32)> {
    use ldapconf::{MUTUAL_AUTH, NOACTIVE, NOANONYMOUS, NOPLAINTEXT, PASS_CREDENTIALS};
    const GSS: u32 = NOPLAINTEXT | NOACTIVE | NOANONYMOUS | MUTUAL_AUTH | PASS_CREDENTIALS;
    Some(match mech {
        "PLAIN" | "LOGIN" => (0, NOANONYMOUS | PASS_CREDENTIALS),
        "ANONYMOUS" => (0, NOPLAINTEXT),
        "CRAM-MD5" | "NTLM" => (0, NOPLAINTEXT | NOANONYMOUS),
        "DIGEST-MD5" => (128, NOPLAINTEXT | NOANONYMOUS | MUTUAL_AUTH),
        "SCRAM-SHA-1" | "SCRAM-SHA-256" => (0, NOPLAINTEXT | NOACTIVE | NOANONYMOUS | MUTUAL_AUTH),
        "GSSAPI" | "GSS-SPNEGO" => (256, GSS),
        // gs2.c:1337-1357 with MIT krb5's mechanism attributes.
        "GS2-KRB5" | "GS2-IAKERB" => (0, GSS),
        "OAUTHBEARER" => (0, NOANONYMOUS),
        _ => return None,
    })
}

/// The mechanism filter of `sasl_client_start` (client.c:520-600).
fn check_mech(mech: &str, p: &Params) -> Result<(), String> {
    let Some((max_ssf, flags)) = mech_props(mech) else {
        return Err(format!(
            "SASL(-4): no mechanism available: {mech} is not supported"
        ));
    };
    let mut want = p.props.flags;
    if p.props.min_ssf <= p.external_ssf && p.external_ssf > 1 {
        want &= !ldapconf::NOPLAINTEXT;
    }
    if p.need() > max_ssf || ((want ^ flags) & want) != 0 {
        return Err("SASL(-4): no mechanism available: No worthy mechs found".into());
    }
    Ok(())
}

pub async fn bind(ldap: &mut Ldap, mech: &str, p: &Params, i: &Interact) -> Result<(), String> {
    let upper = mech.to_ascii_uppercase();
    if upper == "EXTERNAL" {
        let authz = i.authzid.as_deref().unwrap_or("").as_bytes();
        let (res, _) = ldap
            .sasl_bind_step("EXTERNAL", Some(authz))
            .await
            .map_err(|e| e.to_string())?;
        return res.success().map(|_| ()).map_err(|e| e.to_string());
    }
    check_mech(&upper, p)?;
    let mut m: Box<dyn Mech> = match upper.as_str() {
        "CRAM-MD5" => Box::new(CramMd5(i.clone())),
        "DIGEST-MD5" => Box::new(DigestMd5::new(i.clone(), p)),
        "NTLM" => Box::new(ntlm::Ntlm::new(i.clone())),
        "GSSAPI" => Box::new(Gssapi::new(i.clone(), p, false).await?),
        "GSS-SPNEGO" => Box::new(Gssapi::new(i.clone(), p, true).await?),
        "GS2-KRB5" => Box::new(gs2::Gs2::krb5(i.clone(), p).await?),
        "GS2-IAKERB" => Box::new(gs2::Gs2::iakerb(i.clone(), p)?),
        _ => Box::new(Rsasl::new(&upper, i)?),
    };
    let mut out = m.start()?;
    loop {
        let (res, creds) = ldap
            .sasl_bind_step(&upper, out.as_deref())
            .await
            .map_err(|e| e.to_string())?;
        match res.rc {
            0 => {
                if let Some((layer, max)) = m.success(creds.as_deref())? {
                    ldap.install_sasl_layer(layer, max);
                }
                return Ok(());
            }
            SASL_BIND_IN_PROGRESS => {
                out = Some(m.step(creds.as_deref().unwrap_or(b""))?);
            }
            _ => return res.success().map(|_| ()).map_err(|e| e.to_string()),
        }
    }
}

// ---------------------------------------------------------------- rsasl

struct Creds(Interact);

impl rsasl::callback::SessionCallback for Creds {
    fn callback(
        &self,
        _data: &rsasl::callback::SessionData,
        _ctx: &rsasl::callback::Context,
        req: &mut rsasl::callback::Request<'_>,
    ) -> Result<(), rsasl::prelude::SessionError> {
        use rsasl::property::{AuthId, AuthzId, Password};
        if let Some(a) = &self.0.authcid {
            req.satisfy::<AuthId>(a.as_str())?;
        }
        if let Some(p) = &self.0.password {
            req.satisfy::<Password>(p.as_bytes())?;
        }
        if let Some(z) = &self.0.authzid {
            req.satisfy::<AuthzId>(z.as_str())?;
        }
        if let Some(t) = &self.0.password {
            req.satisfy::<rsasl::property::OAuthBearerToken>(t.as_str())?;
        }
        Ok(())
    }
}

struct Rsasl {
    session: rsasl::prelude::Session,
    done: bool,
}

impl Rsasl {
    fn new(mech: &str, i: &Interact) -> Result<Self, String> {
        use rsasl::prelude::*;
        let config = SASLConfig::builder()
            .with_defaults()
            .with_callback(Creds(i.clone()))
            .map_err(|e| e.to_string())?;
        let name = Mechname::parse(mech.as_bytes()).map_err(|e| e.to_string())?;
        let session = SASLClient::new(config)
            .start_suggested(&[name])
            .map_err(|_| format!("SASL mechanism {mech} is not supported"))?;
        Ok(Rsasl {
            session,
            done: false,
        })
    }

    fn run(&mut self, input: Option<&[u8]>) -> Result<Vec<u8>, String> {
        let mut out = Vec::new();
        let state = self
            .session
            .step(input, &mut out)
            .map_err(|e| e.to_string())?;
        self.done = !state.is_running();
        Ok(out)
    }
}

impl Mech for Rsasl {
    fn start(&mut self) -> Result<Option<Vec<u8>>, String> {
        if !self.session.are_we_first() {
            return Ok(None);
        }
        self.run(None).map(Some)
    }

    fn step(&mut self, challenge: &[u8]) -> Result<Vec<u8>, String> {
        if self.done {
            return Err("unexpected server challenge".into());
        }
        self.run(Some(challenge))
    }

    fn success(&mut self, data: Option<&[u8]>) -> Result<Option<Layer>, String> {
        if !self.done {
            match data {
                Some(d) => {
                    self.run(Some(d))?;
                }
                None => return Err("server did not finish the SASL exchange".into()),
            }
        }
        Ok(None)
    }
}

// ---------------------------------------------------------------- CRAM-MD5

fn hmac_md5(key: &[u8], parts: &[&[u8]]) -> [u8; 16] {
    let mut m = <Hmac<Md5> as KeyInit>::new_from_slice(key).expect("HMAC takes any key length");
    for p in parts {
        m.update(p);
    }
    m.finalize().into_bytes().into()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn md5(parts: &[&[u8]]) -> [u8; 16] {
    let mut h = Md5::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

fn need<'a>(v: &'a Option<String>, what: &str) -> Result<&'a str, String> {
    v.as_deref()
        .ok_or_else(|| format!("SASL {what} is required for this mechanism"))
}

/// cram.c:418-545 `crammd5_client_mech_step`.
struct CramMd5(Interact);

impl Mech for CramMd5 {
    fn start(&mut self) -> Result<Option<Vec<u8>>, String> {
        Ok(None)
    }

    fn step(&mut self, challenge: &[u8]) -> Result<Vec<u8>, String> {
        let user = need(&self.0.authcid, "authcid")?;
        let pass = need(&self.0.password, "password")?;
        let d = hmac_md5(pass.as_bytes(), &[challenge]);
        Ok(format!("{user} {}", hex(&d)).into_bytes())
    }

    fn success(&mut self, _data: Option<&[u8]>) -> Result<Option<Layer>, String> {
        Ok(None)
    }
}

// ---------------------------------------------------------------- DIGEST-MD5

/// Parse a digest-challenge (digestmd5.c `get_pair`).
fn parse_pairs(s: &str) -> Result<Vec<(String, String)>, String> {
    let b = s.as_bytes();
    let mut i = 0;
    let mut out = Vec::new();
    let skip = |i: &mut usize| {
        while *i < b.len() && (b[*i] == b' ' || b[*i] == b'\t' || b[*i] == b',') {
            *i += 1;
        }
    };
    loop {
        skip(&mut i);
        if i >= b.len() {
            return Ok(out);
        }
        let start = i;
        while i < b.len() && b[i] != b'=' {
            i += 1;
        }
        if i >= b.len() {
            return Err("Parse error".into());
        }
        let name = s[start..i].trim().to_ascii_lowercase();
        i += 1;
        let mut value = Vec::new();
        if i < b.len() && b[i] == b'"' {
            i += 1;
            while i < b.len() && b[i] != b'"' {
                if b[i] == b'\\' && i + 1 < b.len() {
                    i += 1;
                }
                value.push(b[i]);
                i += 1;
            }
            if i >= b.len() {
                return Err("Parse error".into());
            }
            i += 1;
        } else {
            while i < b.len() && b[i] != b',' {
                value.push(b[i]);
                i += 1;
            }
        }
        let value = String::from_utf8_lossy(&value).trim().to_string();
        out.push((name, value));
    }
}

fn quote(v: &str) -> String {
    let mut s = String::from("\"");
    for c in v.chars() {
        if c == '"' || c == '\\' {
            s.push('\\');
        }
        s.push(c);
    }
    s.push('"');
    s
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Cipher {
    Rc4_40,
    Rc4_56,
    Rc4,
    Des,
    TripleDes,
}

impl Cipher {
    /// digestmd5.c:1407-1418 `available_ciphers`.
    const ALL: [(Cipher, &'static str, u32, usize); 5] = [
        (Cipher::Rc4_40, "rc4-40", 40, 5),
        (Cipher::Rc4_56, "rc4-56", 56, 7),
        (Cipher::Rc4, "rc4", 128, 16),
        (Cipher::Des, "des", 55, 16),
        (Cipher::TripleDes, "3des", 112, 16),
    ];
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Protection {
    None,
    Integrity,
    Privacy(Cipher),
}

const SIGN_C2S: &[u8] = b"Digest session key to client-to-server signing key magic constant";
const SIGN_S2C: &[u8] = b"Digest session key to server-to-client signing key magic constant";
const SEAL_C2S: &[u8] = b"Digest H(A1) to client-to-server sealing key magic constant";
const SEAL_S2C: &[u8] = b"Digest H(A1) to server-to-client sealing key magic constant";

struct DigestMd5 {
    i: Interact,
    service: &'static str,
    host: String,
    ha1: [u8; 16],
    props: SecProps,
    external_ssf: u32,
    protection: Protection,
    server_maxbuf: u32,
    rspauth: Option<String>,
    verified: bool,
}

impl DigestMd5 {
    fn new(i: Interact, p: &Params) -> Self {
        DigestMd5 {
            i,
            service: "ldap",
            host: p.host.clone(),
            props: p.props,
            external_ssf: p.external_ssf,
            ha1: [0; 16],
            protection: Protection::None,
            server_maxbuf: MAXBUF,
            rspauth: None,
            verified: false,
        }
    }

    fn a2_suffix(&self) -> &'static str {
        match self.protection {
            Protection::None => "",
            _ => ":00000000000000000000000000000000",
        }
    }

    /// digestmd5.c:3762-4140 `parse_server_challenge` and
    /// :3481-3720 `make_client_response`.
    fn respond(&mut self, challenge: &str, cnonce: &str) -> Result<Vec<u8>, String> {
        let pairs = parse_pairs(challenge)?;
        let mut realms = Vec::new();
        let mut nonce = None;
        let mut qops = Vec::new();
        let mut ciphers = Vec::new();
        let mut utf8 = false;
        for (n, v) in &pairs {
            match n.as_str() {
                "realm" => realms.push(v.clone()),
                "nonce" => {
                    if nonce.replace(v.clone()).is_some() {
                        return Err("Server tries multiple nonce values!".into());
                    }
                }
                "qop" => qops.extend(v.split(',').map(|q| q.trim().to_ascii_lowercase())),
                "cipher" => ciphers.extend(v.split(',').map(|c| c.trim().to_ascii_lowercase())),
                "maxbuf" => {
                    self.server_maxbuf = v
                        .parse()
                        .ok()
                        .filter(|&m: &u32| m > 16)
                        .ok_or("invalid maxbuf parameter")?;
                }
                "charset" => {
                    if !v.eq_ignore_ascii_case("utf-8") {
                        return Err("Charset must be UTF-8".into());
                    }
                    utf8 = true;
                }
                "algorithm" if !v.eq_ignore_ascii_case("md5-sess") => {
                    return Err("'algorithm' isn't 'md5-sess'".into());
                }
                _ => {}
            }
        }
        let nonce = nonce.ok_or("Don't have nonce.")?;
        if qops.is_empty() {
            qops.push("auth".into());
        }
        // digestmd5.c:4063-4140.
        let (limit, musthave) = if self.props.maxbufsize == 0 {
            (0, 0)
        } else {
            (
                self.props.max_ssf.saturating_sub(self.external_ssf),
                self.props.min_ssf.saturating_sub(self.external_ssf),
            )
        };
        self.protection = Protection::None;
        if limit > 1 && qops.iter().any(|q| q == "auth-conf") {
            if let Some(c) = Cipher::ALL
                .iter()
                .filter(|c| limit >= c.2 && musthave <= c.2 && ciphers.iter().any(|n| n == c.1))
                .max_by_key(|c| c.2)
            {
                self.protection = Protection::Privacy(c.0);
            }
        }
        if self.protection == Protection::None {
            if limit >= 1 && musthave <= 1 && qops.iter().any(|q| q == "auth-int") {
                self.protection = Protection::Integrity;
            } else if musthave == 0 {
                if !qops.iter().any(|q| q == "auth") {
                    return Err("Server doesn't support \"no layer\"".into());
                }
            } else {
                return Err("Can't find an acceptable layer".into());
            }
        }
        let user = need(&self.i.authcid, "authcid")?.to_string();
        let pass = need(&self.i.password, "password")?.to_string();
        let realm = self
            .i
            .realm
            .clone()
            .or_else(|| realms.first().cloned())
            .unwrap_or_else(|| self.host.clone());
        let authzid = self.i.authzid.clone().filter(|z| *z != user);
        let nc = "00000001";
        let qop = match self.protection {
            Protection::None => "auth",
            Protection::Integrity => "auth-int",
            Protection::Privacy(_) => "auth-conf",
        };
        let uri = format!("{}/{}", self.service, self.host);
        let secret = md5(&[
            user.as_bytes(),
            b":",
            realm.as_bytes(),
            b":",
            pass.as_bytes(),
        ]);
        let mut a1: Vec<&[u8]> = vec![&secret, b":", nonce.as_bytes(), b":", cnonce.as_bytes()];
        if let Some(z) = &authzid {
            a1.push(b":");
            a1.push(z.as_bytes());
        }
        self.ha1 = md5(&a1);
        let ha1 = hex(&self.ha1);
        let resp = |a2: &str| {
            let ha2 = hex(&md5(&[a2.as_bytes()]));
            hex(&md5(&[
                ha1.as_bytes(),
                b":",
                nonce.as_bytes(),
                b":",
                nc.as_bytes(),
                b":",
                cnonce.as_bytes(),
                b":",
                qop.as_bytes(),
                b":",
                ha2.as_bytes(),
            ]))
        };
        let response = resp(&format!("AUTHENTICATE:{uri}{}", self.a2_suffix()));
        self.rspauth = Some(resp(&format!(":{uri}{}", self.a2_suffix())));
        let mut out = vec![
            format!("username={}", quote(&user)),
            format!("realm={}", quote(&realm)),
        ];
        if let Some(z) = &authzid {
            out.push(format!("authzid={}", quote(z)));
        }
        out.push(format!("nonce={}", quote(&nonce)));
        out.push(format!("cnonce={}", quote(cnonce)));
        out.push(format!("nc={nc}"));
        out.push(format!("qop={qop}"));
        if let Protection::Privacy(c) = self.protection {
            let name = Cipher::ALL.iter().find(|x| x.0 == c).map_or("", |x| x.1);
            out.push(format!("cipher={name}"));
        }
        if self.props.maxbufsize != 0 {
            out.push(format!("maxbuf={}", self.props.maxbufsize));
        }
        if utf8 {
            out.push("charset=utf-8".into());
        }
        out.push(format!("digest-uri={}", quote(&uri)));
        out.push(format!("response={response}"));
        Ok(out.join(",").into_bytes())
    }

    fn check_rspauth(&mut self, data: &[u8]) -> Result<(), String> {
        let s = String::from_utf8_lossy(data);
        let pairs = parse_pairs(&s)?;
        let got = pairs
            .iter()
            .find(|(n, _)| n == "rspauth")
            .map(|(_, v)| v.as_str())
            .ok_or("Server didn't send rspauth")?;
        if Some(got) != self.rspauth.as_deref() {
            return Err("Server authentication failed".into());
        }
        self.verified = true;
        Ok(())
    }

    fn layer(&self) -> Option<Layer> {
        let ki_send = md5(&[&self.ha1, SIGN_C2S]);
        let ki_recv = md5(&[&self.ha1, SIGN_S2C]);
        let cipher = match self.protection {
            Protection::None => return None,
            Protection::Integrity => None,
            Protection::Privacy(c) => {
                let n = Cipher::ALL.iter().find(|x| x.0 == c).map_or(16, |x| x.3);
                let kcc = md5(&[&self.ha1[..n], SEAL_C2S]);
                let kcs = md5(&[&self.ha1[..n], SEAL_S2C]);
                Some(DigestCipher::new(c, &kcc, &kcs))
            }
        };
        let overhead = if cipher.is_some() {
            4 + 10 + 8 + 6
        } else {
            4 + 10 + 6
        };
        Some((
            Box::new(DigestLayer {
                ki_send,
                ki_recv,
                seq: 0,
                rseq: 0,
                cipher,
            }),
            self.server_maxbuf.saturating_sub(overhead),
        ))
    }
}

fn base64_encode(b: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut s = String::new();
    for c in b.chunks(3) {
        let n = (u32::from(c[0]) << 16)
            | (u32::from(*c.get(1).unwrap_or(&0)) << 8)
            | u32::from(*c.get(2).unwrap_or(&0));
        for k in 0..4 {
            if k <= c.len() {
                s.push(T[(n >> (18 - 6 * k) & 63) as usize] as char);
            } else {
                s.push('=');
            }
        }
    }
    s
}

impl Mech for DigestMd5 {
    fn start(&mut self) -> Result<Option<Vec<u8>>, String> {
        Ok(None)
    }

    fn step(&mut self, challenge: &[u8]) -> Result<Vec<u8>, String> {
        if self.rspauth.is_none() {
            let s = String::from_utf8_lossy(challenge).into_owned();
            let mut raw = [0u8; 32];
            rand::fill(&mut raw[..]);
            return self.respond(&s, &base64_encode(&raw));
        }
        self.check_rspauth(challenge)?;
        Ok(Vec::new())
    }

    fn success(&mut self, data: Option<&[u8]>) -> Result<Option<Layer>, String> {
        if !self.verified {
            self.check_rspauth(data.ok_or("Server didn't send rspauth")?)?;
        }
        Ok(self.layer())
    }
}

/// slidebits (digestmd5.c:866-876).
fn slidebits(i: &[u8]) -> [u8; 8] {
    [
        i[0],
        (i[0] << 7) | (i[1] >> 1),
        (i[1] << 6) | (i[2] >> 2),
        (i[2] << 5) | (i[3] >> 3),
        (i[3] << 4) | (i[4] >> 4),
        (i[4] << 3) | (i[5] >> 5),
        (i[5] << 2) | (i[6] >> 6),
        i[6] << 1,
    ]
}

enum BlockKey {
    Des(des::Des),
    Ede2(des::TdesEde2),
}

impl BlockKey {
    fn enc(&self, b: &mut [u8]) {
        use des::cipher::BlockEncrypt;
        let b = des::cipher::generic_array::GenericArray::from_mut_slice(b);
        match self {
            BlockKey::Des(k) => k.encrypt_block(b),
            BlockKey::Ede2(k) => k.encrypt_block(b),
        }
    }

    fn dec(&self, b: &mut [u8]) {
        use des::cipher::BlockDecrypt;
        let b = des::cipher::generic_array::GenericArray::from_mut_slice(b);
        match self {
            BlockKey::Des(k) => k.decrypt_block(b),
            BlockKey::Ede2(k) => k.decrypt_block(b),
        }
    }
}

struct Cbc {
    key: BlockKey,
    iv: [u8; 8],
}

impl Cbc {
    fn new(c: Cipher, k: &[u8; 16]) -> Self {
        use des::cipher::KeyInit as _;
        let key = if c == Cipher::Des {
            BlockKey::Des(des::Des::new_from_slice(&slidebits(&k[..7])).expect("8-byte key"))
        } else {
            let mut kk = [0u8; 16];
            kk[..8].copy_from_slice(&slidebits(&k[..7]));
            kk[8..].copy_from_slice(&slidebits(&k[7..14]));
            BlockKey::Ede2(des::TdesEde2::new_from_slice(&kk).expect("16-byte key"))
        };
        let mut iv = [0u8; 8];
        iv.copy_from_slice(&k[8..16]);
        Cbc { key, iv }
    }

    fn encrypt(&mut self, data: &mut [u8]) {
        for blk in data.chunks_mut(8) {
            for (b, v) in blk.iter_mut().zip(self.iv) {
                *b ^= v;
            }
            self.key.enc(blk);
            self.iv.copy_from_slice(blk);
        }
    }

    fn decrypt(&mut self, data: &mut [u8]) {
        for blk in data.chunks_mut(8) {
            let mut next = [0u8; 8];
            next.copy_from_slice(blk);
            self.key.dec(blk);
            for (b, v) in blk.iter_mut().zip(self.iv) {
                *b ^= v;
            }
            self.iv = next;
        }
    }
}

enum DigestCipher {
    Rc4(
        Box<rc4::Rc4<rc4::consts::U16>>,
        Box<rc4::Rc4<rc4::consts::U16>>,
    ),
    Block(Box<Cbc>, Box<Cbc>),
}

impl DigestCipher {
    fn new(c: Cipher, kcc: &[u8; 16], kcs: &[u8; 16]) -> Self {
        use rc4::KeyInit as _;
        match c {
            Cipher::Rc4 | Cipher::Rc4_40 | Cipher::Rc4_56 => DigestCipher::Rc4(
                Box::new(rc4::Rc4::new(kcc.into())),
                Box::new(rc4::Rc4::new(kcs.into())),
            ),
            _ => DigestCipher::Block(Box::new(Cbc::new(c, kcc)), Box::new(Cbc::new(c, kcs))),
        }
    }
}

impl std::fmt::Debug for DigestCipher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DigestCipher")
    }
}

/// The DIGEST-MD5 security layer (digestmd5.c:1491-1720).
#[derive(Debug)]
struct DigestLayer {
    ki_send: [u8; 16],
    ki_recv: [u8; 16],
    seq: u32,
    rseq: u32,
    cipher: Option<DigestCipher>,
}

fn bad(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.to_string())
}

impl SaslSecurityLayer for DigestLayer {
    fn wrap(&mut self, msg: &[u8]) -> io::Result<Vec<u8>> {
        let seq = self.seq.to_be_bytes();
        let mac = hmac_md5(&self.ki_send, &[&seq, msg]);
        let mut out = msg.to_vec();
        match &mut self.cipher {
            None => out.extend_from_slice(&mac[..10]),
            Some(DigestCipher::Rc4(enc, _)) => {
                use rc4::StreamCipher;
                out.extend_from_slice(&mac[..10]);
                enc.apply_keystream(&mut out);
            }
            Some(DigestCipher::Block(enc, _)) => {
                let pad = 8 - ((msg.len() + 10) % 8);
                out.extend(std::iter::repeat_n(pad as u8, pad));
                out.extend_from_slice(&mac[..10]);
                enc.encrypt(&mut out);
            }
        }
        out.extend_from_slice(&1u16.to_be_bytes());
        out.extend_from_slice(&seq);
        self.seq = self.seq.wrapping_add(1);
        Ok(out)
    }

    fn unwrap(&mut self, input: &[u8]) -> io::Result<Vec<u8>> {
        if input.len() < 16 {
            return Err(bad("DIGEST-MD5 packet too short"));
        }
        let (body, tail) = input.split_at(input.len() - 6);
        if tail[..2] != 1u16.to_be_bytes() {
            return Err(bad("Wrong Version"));
        }
        let seq = u32::from_be_bytes([tail[2], tail[3], tail[4], tail[5]]);
        if seq != self.rseq {
            return Err(bad("Incorrect Sequence Number"));
        }
        let mut plain = body.to_vec();
        let len = match &mut self.cipher {
            None => plain.len() - 10,
            Some(DigestCipher::Rc4(_, dec)) => {
                use rc4::StreamCipher;
                dec.apply_keystream(&mut plain);
                plain.len() - 10
            }
            Some(DigestCipher::Block(_, dec)) => {
                if plain.len() % 8 != 0 {
                    return Err(bad("DIGEST-MD5 packet not block-aligned"));
                }
                dec.decrypt(&mut plain);
                let n = plain.len();
                let pad = usize::from(plain[n - 11]);
                if !(1..=8).contains(&pad)
                    || n < 10 + pad
                    || plain[n - 10 - pad..n - 10]
                        .iter()
                        .any(|&p| usize::from(p) != pad)
                {
                    return Err(bad("DIGEST-MD5 bad padding"));
                }
                n - 10 - pad
            }
        };
        let mac = hmac_md5(&self.ki_recv, &[&seq.to_be_bytes(), &plain[..len]]);
        let got_off = plain.len() - 10;
        if mac[..10] != plain[got_off..] {
            return Err(bad("CMAC doesn't match"));
        }
        self.rseq = self.rseq.wrapping_add(1);
        plain.truncate(len);
        Ok(plain)
    }
}

// ---------------------------------------------------------------- GSSAPI

use krb5_rs::gssapi::krb5::{GssFlags, InitStep, Krb5Context, Krb5Initiator, MECH_KRB5};
use krb5_rs::gssapi::spnego::SpnegoInitiator;

const LAYER_NONE: u8 = 1;
const LAYER_INTEGRITY: u8 = 2;
const LAYER_CONFIDENTIALITY: u8 = 4;

fn krb5_profile() -> Result<krb5_rs::profile::Profile, String> {
    let paths = std::env::var("KRB5_CONFIG").unwrap_or_else(|_| "/etc/krb5.conf".into());
    let mut text = String::new();
    for p in paths.split(':').filter(|p| !p.is_empty()) {
        if let Ok(t) = std::fs::read_to_string(p) {
            text.push_str(&t);
            text.push('\n');
        }
    }
    krb5_rs::profile::Profile::parse(&text).map_err(|e| e.to_string())
}

/// gssapi.c:1643-2170 `gssapi_client_mech_step`.
enum GssInit {
    Krb5(Krb5Initiator),
    Spnego(SpnegoInitiator),
}

impl GssInit {
    fn step(&mut self, input: Option<&[u8]>) -> Result<InitStep, String> {
        match self {
            GssInit::Krb5(i) => i.step(input),
            GssInit::Spnego(i) => i.step(input),
        }
        .map_err(|e| e.to_string())
    }

    fn context(self) -> Result<Krb5Context, String> {
        match self {
            GssInit::Krb5(i) => i.context(),
            GssInit::Spnego(i) => i.context(),
        }
        .map_err(|e| e.to_string())
    }
}

/// The krb5 initiator for `ldap@host`, from the default ccache.
async fn krb5_initiator(host: &str, flags: GssFlags) -> Result<Krb5Initiator, String> {
    use krb5_rs::client::{GcOptions, HostCanonicalization, KerberosClient};
    use krb5_rs::types::PrincipalName;
    let profile = krb5_profile()?;
    let srealm = krb5_rs::locate::host_realm(&profile, host)
        .into_iter()
        .next()
        .unwrap_or_default();
    let defrealm = profile
        .get_string(&["libdefaults", "default_realm"])
        .unwrap_or_else(|| srealm.clone());
    let canon = HostCanonicalization::from_profile(&profile);
    let profile = Arc::new(profile);
    let transport = krb5_rs::transport::located::LocatedTransport::new(profile.clone(), None);
    let client = KerberosClient::new(defrealm, transport).with_host_canonicalization(canon);
    let ctx = krb5_rs::ccache::CcContext::from_env(Some(&profile));
    let server = PrincipalName::new_srv_hst("ldap", host);
    let (_, cred) = client
        .get_default_credentials(&ctx, Some(&profile), GcOptions::empty(), server, &srealm)
        .await
        .map_err(|e| e.to_string())?;
    Krb5Initiator::new(cred, None, flags, None).map_err(|e| e.to_string())
}

/// Cyrus's GSSAPI and GSS-SPNEGO client (gssapi.c:1640-2120).
struct Gssapi {
    authzid: Option<String>,
    init: Option<GssInit>,
    ctx: Option<Krb5Context>,
    layer: Option<Layer>,
    spnego: bool,
    need: u32,
    allowed: u32,
    maxbuf: u32,
    done: bool,
}

impl Gssapi {
    async fn new(i: Interact, p: &Params, spnego: bool) -> Result<Self, String> {
        // gssapi.c:1762-1782.
        let mut flags = GssFlags::MUTUAL | GssFlags::SEQUENCE;
        if p.props.max_ssf > p.external_ssf {
            flags |= GssFlags::INTEG;
            if p.props.max_ssf - p.external_ssf > 1 {
                flags |= GssFlags::CONF;
            }
        }
        if p.props.flags & ldapconf::PASS_CREDENTIALS != 0 {
            flags |= GssFlags::DELEG;
        }
        let inner = krb5_initiator(&p.host, flags).await?;
        let init = if spnego {
            GssInit::Spnego(SpnegoInitiator::new(inner, vec![MECH_KRB5.to_vec()]))
        } else {
            GssInit::Krb5(inner)
        };
        Ok(Gssapi {
            authzid: i.authzid,
            init: Some(init),
            ctx: None,
            layer: None,
            spnego,
            need: p.need(),
            allowed: p.allowed(),
            maxbuf: p.props.maxbufsize.min(0xFF_FFFF),
            done: false,
        })
    }

    fn ctx_step(&mut self, input: Option<&[u8]>) -> Result<Vec<u8>, String> {
        let init = self
            .init
            .as_mut()
            .ok_or("GSSAPI context already established")?;
        match init.step(input)? {
            InitStep::Continue(t) => Ok(t),
            InitStep::Complete(t) => {
                let init = self.init.take().ok_or("GSSAPI context missing")?;
                let ctx = init.context()?;
                if self.spnego {
                    self.spnego_ssf(ctx);
                } else {
                    self.ctx = Some(ctx);
                }
                Ok(t.unwrap_or_default())
            }
        }
    }

    /// `gssapi_spnego_ssf` (gssapi.c:742-780): the context's flags pick the
    /// layer; there is no security-layer negotiation.
    fn spnego_ssf(&mut self, ctx: Krb5Context) {
        let f = ctx.flags();
        if f.contains(GssFlags::INTEG) {
            let conf = f.contains(GssFlags::CONF);
            let limit = ctx.wrap_size_limit(conf, 0xFF_FFFF) as u32;
            self.layer = Some((Box::new(GssLayer { ctx, conf }), limit));
        }
        self.done = true;
    }

    /// `SASL_GSSAPI_STATE_SSFCAP` (gssapi.c:1960-2090).
    fn ssfcap(&mut self, challenge: &[u8]) -> Result<Vec<u8>, String> {
        let mut ctx = self.ctx.take().ok_or("GSSAPI context missing")?;
        let caps = ctx.unwrap(challenge).map_err(|e| e.to_string())?.data;
        if caps.len() != 4 {
            return Err("token wrong length".into());
        }
        let serverhas = caps[0];
        let server_max = u32::from_be_bytes([0, caps[1], caps[2], caps[3]]);
        let f = ctx.flags();
        let integ = f.contains(GssFlags::INTEG);
        let conf = integ && f.contains(GssFlags::CONF);
        let mech_ssf = ctx.sasl_ssf().unwrap_or(56);
        let (need, allowed) = (self.need, self.allowed);
        let choice = if conf
            && allowed >= mech_ssf
            && need <= mech_ssf
            && serverhas & LAYER_CONFIDENTIALITY != 0
        {
            LAYER_CONFIDENTIALITY
        } else if integ && allowed >= 1 && need <= 1 && serverhas & LAYER_INTEGRITY != 0 {
            LAYER_INTEGRITY
        } else if need == 0 && serverhas & LAYER_NONE != 0 {
            LAYER_NONE
        } else {
            return Err("SASL(-15): mechanism too weak for this user".into());
        };
        let mut reply = vec![choice];
        let max = if choice > LAYER_NONE { self.maxbuf } else { 0 };
        reply.extend_from_slice(&max.to_be_bytes()[1..]);
        if let Some(z) = &self.authzid {
            reply.extend_from_slice(z.as_bytes());
        }
        let token = ctx.wrap(false, &reply).map_err(|e| e.to_string())?;
        if choice > LAYER_NONE {
            let conf = choice == LAYER_CONFIDENTIALITY;
            let limit = ctx.wrap_size_limit(conf, server_max as usize) as u32;
            self.layer = Some((Box::new(GssLayer { ctx, conf }), limit));
        }
        self.done = true;
        Ok(token)
    }
}

impl Mech for Gssapi {
    fn start(&mut self) -> Result<Option<Vec<u8>>, String> {
        self.ctx_step(None).map(Some)
    }

    fn step(&mut self, challenge: &[u8]) -> Result<Vec<u8>, String> {
        if self.done {
            return Err("unexpected server challenge".into());
        }
        if self.init.is_some() {
            return self.ctx_step(Some(challenge));
        }
        self.ssfcap(challenge)
    }

    fn success(&mut self, data: Option<&[u8]>) -> Result<Option<Layer>, String> {
        if !self.done && self.init.is_some() {
            if let Some(d) = data.filter(|d| !d.is_empty()) {
                self.ctx_step(Some(d))?;
            }
        }
        if !self.done {
            return Err("server did not finish the SASL exchange".into());
        }
        Ok(self.layer.take())
    }
}

struct GssLayer {
    ctx: Krb5Context,
    conf: bool,
}

impl std::fmt::Debug for GssLayer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GssLayer")
            .field("conf", &self.conf)
            .finish()
    }
}

impl SaslSecurityLayer for GssLayer {
    fn wrap(&mut self, msg: &[u8]) -> io::Result<Vec<u8>> {
        self.ctx
            .wrap(self.conf, msg)
            .map_err(|e| io::Error::other(format!("gss_wrap error: {e}")))
    }

    fn unwrap(&mut self, msg: &[u8]) -> io::Result<Vec<u8>> {
        let u = self
            .ctx
            .unwrap(msg)
            .map_err(|e| io::Error::other(format!("gss_unwrap error: {e}")))?;
        if self.conf && !u.conf {
            return Err(bad("GSSAPI message not encrypted"));
        }
        Ok(u.data)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn params(host: &str, external_ssf: u32, secprops: &str) -> Params {
        let mut props = SecProps::default();
        if !secprops.is_empty() {
            props.apply(secprops).unwrap();
        }
        Params {
            host: host.into(),
            external_ssf,
            props,
        }
    }

    fn interact(user: &str, pass: &str) -> Interact {
        Interact {
            authcid: Some(user.into()),
            password: Some(pass.into()),
            ..Interact::default()
        }
    }

    #[test]
    fn host_from_url() {
        assert_eq!(url_host("ldap://kdc.example.com:389/"), "kdc.example.com");
        assert_eq!(url_host("ldaps://[::1]:636"), "::1");
        assert_eq!(url_host("ldap://h"), "h");
    }

    /// RFC 2195 section 2 example.
    #[test]
    fn connected_host() {
        let local = local_hostname();
        assert!(!local.is_empty());
        assert_eq!(host_connected_to(None), local);
        assert_eq!(
            host_connected_to(Some("127.0.0.1:389".parse().unwrap())),
            local
        );
        assert_eq!(host_connected_to(Some("[::1]:389".parse().unwrap())), local);
    }

    #[test]
    fn mechanism_filter() {
        let worthy = |m: &str, ext: u32, sp: &str| check_mech(m, &params("h", ext, sp)).is_ok();
        // libldap's defaults: noplain,noanonymous.
        assert!(!worthy("PLAIN", 0, ""));
        assert!(!worthy("LOGIN", 0, ""));
        assert!(!worthy("ANONYMOUS", 0, ""));
        assert!(!worthy("OAUTHBEARER", 0, ""));
        for m in [
            "CRAM-MD5",
            "DIGEST-MD5",
            "NTLM",
            "SCRAM-SHA-256",
            "GSSAPI",
            "GS2-KRB5",
        ] {
            assert!(worthy(m, 0, ""), "{m}");
        }
        // TLS lifts noplain.
        assert!(worthy("PLAIN", 128, ""));
        assert!(worthy("OAUTHBEARER", 256, ""));
        assert!(!worthy("PLAIN", 128, "minssf=256"));
        assert!(worthy("PLAIN", 0, "none"));
        assert!(worthy("ANONYMOUS", 0, "none"));
        // minssf beyond a mechanism's max_ssf.
        assert!(!worthy("CRAM-MD5", 0, "minssf=1"));
        assert!(worthy("DIGEST-MD5", 0, "minssf=128"));
        assert!(!worthy("DIGEST-MD5", 0, "minssf=129"));
        assert!(worthy("DIGEST-MD5", 64, "minssf=129"));
        assert!(worthy("GSSAPI", 0, "minssf=256"));
        // noactive, nodict, forwardsec.
        assert!(!worthy("DIGEST-MD5", 0, "noactive"));
        assert!(worthy("SCRAM-SHA-1", 0, "noactive"));
        assert!(!worthy("GSSAPI", 0, "forwardsec"));
        assert!(!worthy("NOSUCH", 0, "none"));
    }

    #[test]
    fn digest_layer_choice() {
        let ch = r#"realm="r",nonce="n",qop="auth,auth-int,auth-conf",cipher="rc4-40,rc4-56,rc4,des,3des",maxbuf=1000,algorithm=md5-sess"#;
        let pick = |ext: u32, sp: &str| {
            let mut m = DigestMd5::new(interact("u", "p"), &params("h", ext, sp));
            m.step(ch.as_bytes())
                .map(|r| (m.protection, String::from_utf8(r).unwrap()))
        };
        let (prot, resp) = pick(0, "").unwrap();
        assert_eq!(prot, Protection::Privacy(Cipher::Rc4));
        assert!(resp.contains("maxbuf=65536"));
        assert_eq!(
            pick(0, "maxssf=112").unwrap().0,
            Protection::Privacy(Cipher::TripleDes)
        );
        assert_eq!(
            pick(0, "maxssf=56").unwrap().0,
            Protection::Privacy(Cipher::Rc4_56)
        );
        assert_eq!(pick(0, "maxssf=1").unwrap().0, Protection::Integrity);
        assert_eq!(pick(0, "maxssf=0").unwrap().0, Protection::None);
        // TLS's SSF counts against maxssf.
        assert_eq!(pick(128, "").unwrap().0, Protection::Privacy(Cipher::Rc4));
        assert_eq!(pick(i32::MAX as u32, "").unwrap().0, Protection::None);
        let (prot, resp) = pick(0, "maxbufsize=0").unwrap();
        assert_eq!(prot, Protection::None);
        assert!(!resp.contains("maxbuf="));
        assert!(pick(0, "minssf=129").is_err());
        let only_auth = r#"realm="r",nonce="n",qop="auth-int",algorithm=md5-sess"#;
        let mut m = DigestMd5::new(interact("u", "p"), &params("h", 0, "maxssf=0"));
        assert!(m.step(only_auth.as_bytes()).is_err());
    }

    #[test]
    fn cram_md5_rfc2195() {
        let mut m = CramMd5(interact("tim", "tanstaaftanstaaf"));
        let r = m
            .step(b"<1896.697170952@postoffice.reston.mci.net>")
            .unwrap();
        assert_eq!(r, b"tim b913a602c7eda7a495b4e6e7334d3890");
    }

    /// RFC 2831 section 4 example (IMAP).
    #[test]
    fn digest_md5_rfc2831() {
        let mut m = DigestMd5::new(
            interact("chris", "secret"),
            &params("elwood.innosoft.com", 0, ""),
        );
        m.service = "imap";
        let ch = r#"realm="elwood.innosoft.com",nonce="OA6MG9tEQGm2hh",qop="auth",algorithm=md5-sess,charset=utf-8"#;
        let r = String::from_utf8(m.respond(ch, "OA6MHXh6VqTrRk").unwrap()).unwrap();
        assert!(
            r.contains("response=d388dad90d4bbd760a152321f2143af7"),
            "{r}"
        );
        assert!(
            r.contains(r#"digest-uri="imap/elwood.innosoft.com""#),
            "{r}"
        );
        m.step(b"rspauth=ea40f60335c427b5527b84dbabcdfffd").unwrap();
        assert!(m.success(None).unwrap().is_none());
        let mut bad = DigestMd5::new(
            interact("chris", "secret"),
            &params("elwood.innosoft.com", 0, ""),
        );
        bad.respond(ch, "x").unwrap();
        assert!(bad.success(Some(b"rspauth=00")).is_err());
    }

    fn peer(c: Cipher) -> (DigestLayer, DigestLayer) {
        let ha1 = [7u8; 16];
        let n = Cipher::ALL.iter().find(|x| x.0 == c).unwrap().3;
        let kcc = md5(&[&ha1[..n], SEAL_C2S]);
        let kcs = md5(&[&ha1[..n], SEAL_S2C]);
        let client = DigestLayer {
            ki_send: md5(&[&ha1, SIGN_C2S]),
            ki_recv: md5(&[&ha1, SIGN_S2C]),
            seq: 0,
            rseq: 0,
            cipher: Some(DigestCipher::new(c, &kcc, &kcs)),
        };
        let server = DigestLayer {
            ki_send: md5(&[&ha1, SIGN_S2C]),
            ki_recv: md5(&[&ha1, SIGN_C2S]),
            seq: 0,
            rseq: 0,
            cipher: Some(DigestCipher::new(c, &kcs, &kcc)),
        };
        (client, server)
    }

    #[test]
    fn digest_layers_round_trip() {
        for (c, ..) in Cipher::ALL {
            let (mut a, mut b) = peer(c);
            for msg in [&b""[..], b"x", b"0123456789abcdef-ldap-message"] {
                let w = a.wrap(msg).unwrap();
                if !msg.is_empty() {
                    assert_ne!(&w[..msg.len()], msg);
                }
                assert_eq!(b.unwrap(&w).unwrap(), msg, "{c:?}");
                let back = b.wrap(msg).unwrap();
                assert_eq!(a.unwrap(&back).unwrap(), msg, "{c:?}");
            }
            let w = a.wrap(b"replay").unwrap();
            b.unwrap(&w).unwrap();
            assert!(b.unwrap(&w).is_err(), "{c:?} replay accepted");
        }
        let mut i = DigestLayer {
            ki_send: [1; 16],
            ki_recv: [1; 16],
            seq: 0,
            rseq: 0,
            cipher: None,
        };
        let mut w = i.wrap(b"hello").unwrap();
        assert_eq!(&w[..5], b"hello");
        w[0] ^= 1;
        assert!(i.unwrap(&w).is_err());
    }

    #[test]
    fn digest_challenge_parsing() {
        let p = parse_pairs(r#"realm="a\"b",qop="auth,auth-int",maxbuf=1024 , x=y"#).unwrap();
        assert_eq!(p[0], ("realm".into(), "a\"b".into()));
        assert_eq!(p[1].1, "auth,auth-int");
        assert_eq!(p[2], ("maxbuf".into(), "1024".into()));
        assert!(parse_pairs("nonce=\"open").is_err());
    }
}
