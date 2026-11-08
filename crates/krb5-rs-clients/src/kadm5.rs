//! The kadm5 client handle (MIT `lib/kadm5/clnt`): RPCSEC_GSS calls to
//! kadmind, sharing the server's XDR definitions.

use std::fmt;

use krb5_rs::ccache::{parse_principal, AnyCcache, Ccache};
use krb5_rs::client::canonprinc::canonicalize_hostname;
use krb5_rs::client::vfy::{default_keytab_name, resolve_keytab};
use krb5_rs::client::HostCanonicalization;
use krb5_rs::gssapi::krb5::{GssFlags, Krb5Initiator};
use krb5_rs::kdc::kdb::kadm5::{
    code, decode_chrand_ret, decode_generic_ret, decode_getpkeys_ret, decode_getprivs_ret,
    decode_gpol_ret, decode_gprinc_ret, decode_gstrings_ret, decode_names_ret, proc_, KeyBlock,
    KeyData, KeySalt, PolicyEnt, PrincipalEnt, ReadArgs, Ret, WriteArgs, API_VERSION_2,
    API_VERSION_4, KADM_PROG, KADM_VERS,
};
use krb5_rs::profile::Profile;
use krb5_rs::protocol::{AsExchangeConfig, Credential};
use krb5_rs::rpc::gss::{GssClient, Service};
use krb5_rs::rpc::xdr::XdrError;
use krb5_rs::types::{KdcOptions, KerberosFlags, PrincipalName};
use krb5_rs::Krb5Error;
use tokio::net::TcpStream;
use tokio::runtime::Runtime;

/// `KADM5_ADMIN_SERVICE`.
pub const ADMIN_SERVICE: &str = "kadmin/admin";
/// `DEFAULT_KADM5_PORT`.
pub const DEFAULT_PORT: u16 = 749;
const KDC_ERR_S_PRINCIPAL_UNKNOWN: i32 = 7;

/// A kadm5 client error, displayed with its `com_err` text.
#[derive(Debug)]
pub enum Error {
    /// A `kadm_err.et` (or errno) code.
    Kadm5(u32),
    /// A Kerberos library error.
    Krb(Krb5Error),
    /// `KRB5_CC_NOTFOUND`.
    CcNotFound,
    /// Any other message (e.g. a socket error).
    Msg(String),
}

impl Error {
    /// The kadm5 code, when it is one.
    pub fn code(&self) -> Option<u32> {
        match self {
            Error::Kadm5(c) => Some(*c),
            _ => None,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Kadm5(c) => f.write_str(&code::message(*c)),
            Error::Krb(e) => f.write_str(&crate::krb5_message(e)),
            Error::CcNotFound => f.write_str("Matching credential not found"),
            Error::Msg(m) => f.write_str(m),
        }
    }
}

/// `strerror` text without Rust's ` (os error N)` suffix.
pub fn io_message(e: &std::io::Error) -> String {
    let s = e.to_string();
    match s.find(" (os error ") {
        Some(i) => s[..i].to_string(),
        None => s,
    }
}

/// How `kadm5_init` gets its credentials.
pub enum Auth {
    /// `kadm5_init_with_creds`: an existing service ticket in the cache.
    Ccache(AnyCcache),
    /// `kadm5_init_with_password`.
    Password(String),
    /// `kadm5_init_with_skey`: the keytab name, or the default keytab.
    Keytab(Option<String>),
    /// `kadm5_init_anonymous`.
    Anonymous,
}

/// `parse_admin_server_port` (alt_prof.c:390-417).
pub fn parse_admin_server_port(server: &str) -> (String, Option<u16>) {
    if let Some(rest) = server.strip_prefix('[') {
        if let Some(end) = rest.find(']') {
            let port = rest[end + 1..].strip_prefix(':').map(atoi_port);
            return (rest[..end].to_string(), port);
        }
    }
    match server.split_once(':') {
        Some((h, p)) => (h.to_string(), Some(atoi_port(p))),
        None => (server.to_string(), None),
    }
}

fn atoi_port(s: &str) -> u16 {
    let digits: String = s.chars().take_while(char::is_ascii_digit).collect();
    digits.parse().unwrap_or(0)
}

/// The admin server and port for `realm` (`kadm5_get_config_params`):
/// `-s` first, then `[realms] admin_server`, with `kadmind_port` or 749.
pub fn admin_server(
    profile: &Profile,
    realm: &str,
    server_arg: Option<&str>,
) -> Result<(String, u16), Error> {
    let server = server_arg
        .map(str::to_string)
        .or_else(|| profile.get_string(&["realms", realm, "admin_server"]))
        .ok_or(Error::Kadm5(code::MISSING_KRB5_CONF_PARAMS))?;
    let (host, port) = parse_admin_server_port(&server);
    let port = port.unwrap_or_else(|| {
        profile
            .get_integer(&["realms", realm, "kadmind_port"], i64::from(DEFAULT_PORT))
            .ok()
            .and_then(|p| u16::try_from(p).ok())
            .unwrap_or(DEFAULT_PORT)
    });
    Ok((host, port))
}

/// `pkinit_libdefault_strings`.
fn pkinit_strings(profile: &Profile, realm: &str, name: &str) -> Vec<String> {
    for path in [
        vec!["realms", realm, name],
        vec!["libdefaults", realm, name],
        vec!["libdefaults", name],
    ] {
        let v = profile.get_values(&path);
        if !v.is_empty() {
            return v;
        }
    }
    Vec::new()
}

fn is_fallback(e: &Error) -> bool {
    match e {
        Error::CcNotFound => true,
        Error::Krb(Krb5Error::KdcError(m)) => m.error_code == KDC_ERR_S_PRINCIPAL_UNKNOWN,
        _ => false,
    }
}

/// An open kadm5 connection (`kadm5_server_handle_t`).
pub struct Handle {
    rt: Runtime,
    rpc: GssClient<TcpStream>,
    /// The negotiated `KADM5_API_VERSION_*`.
    pub api: u32,
}

/// The parameters `kadm5_init` needs.
pub struct InitParams<'a> {
    /// The profile.
    pub profile: &'a std::sync::Arc<Profile>,
    /// The client principal and realm.
    pub client: (&'a PrincipalName, &'a str),
    /// The realm of the admin server.
    pub realm: &'a str,
    /// The admin server host and port.
    pub server: (&'a str, u16),
    /// An explicit service name; the default is `kadmin/admin` with the
    /// host-based fallback.
    pub service: Option<&'a str>,
}

impl Handle {
    /// `kadm5_init_*` (client_init.c:190-330).
    pub fn init(p: &InitParams<'_>, auth: &Auth) -> Result<Handle, Error> {
        let rt = crate::runtime();
        let rpc = rt.block_on(Self::connect(p, auth))?;
        let mut h = Handle {
            rt,
            rpc,
            api: API_VERSION_4,
        };
        loop {
            let reply = h.call(proc_::INIT, &ReadArgs::Api(h.api).encode())?;
            match h.check(decode_generic_ret(&reply)) {
                Err(Error::Kadm5(c))
                    if c == code::NEW_SERVER_API_VERSION && h.api > API_VERSION_2 =>
                {
                    h.api -= 1;
                }
                Err(e) => return Err(e),
                Ok(_) => return Ok(h),
            }
        }
    }

    async fn connect(p: &InitParams<'_>, auth: &Auth) -> Result<GssClient<TcpStream>, Error> {
        let cred = Self::get_init_creds(p, auth).await?;
        let stream = TcpStream::connect(p.server)
            .await
            .map_err(|e| Error::Msg(io_message(&e)))?;
        let init = Krb5Initiator::new(cred, None, GssFlags::MUTUAL | GssFlags::REPLAY, None)
            .map_err(Error::Krb)?;
        let xid = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(1, |d| d.subsec_nanos() ^ (d.as_secs() as u32));
        GssClient::connect(stream, KADM_PROG, KADM_VERS, xid, init, Service::Privacy)
            .await
            .map_err(|_| Error::Kadm5(code::GSS_ERROR))
    }

    /// `get_init_creds` (client_init.c:350-430).
    async fn get_init_creds(p: &InitParams<'_>, auth: &Auth) -> Result<Credential, Error> {
        let svc = p.service.unwrap_or(ADMIN_SERVICE);
        let mut r = Self::gic_iter(p, auth, svc).await;
        if p.service.is_none() && r.as_ref().err().is_some_and(is_fallback) {
            let hc = HostCanonicalization::from_profile(p.profile);
            let host = canonicalize_hostname(&hc, p.server.0, true).await;
            r = Self::gic_iter(p, auth, &format!("kadmin/{host}")).await;
        }
        r.map_err(|e| match e {
            Error::Krb(Krb5Error::DecryptionFailed) => Error::Kadm5(code::BAD_PASSWORD),
            Error::Krb(Krb5Error::KdcError(m)) if m.error_code == KDC_ERR_S_PRINCIPAL_UNKNOWN => {
                Error::Kadm5(code::SECURE_PRINC_MISSING)
            }
            e => e,
        })
    }

    /// `gic_iter` (client_init.c:433-510).
    async fn gic_iter(p: &InitParams<'_>, auth: &Auth, svcname: &str) -> Result<Credential, Error> {
        let (server, _) = parse_principal(svcname, Some(p.realm))
            .ok_or_else(|| Error::Msg("Malformed representation of principal".into()))?;
        let (me, crealm) = p.client;
        if let Auth::Ccache(cc) = auth {
            let found = cc
                .creds()
                .map_err(|e| Error::Msg(e.to_string()))?
                .into_iter()
                .find(|c| {
                    c.client.name_string == me.name_string
                        && c.crealm == crealm
                        && c.server.name_string == server.name_string
                        && c.srealm == p.realm
                })
                .ok_or(Error::CcNotFound)?;
            return Credential::try_from(&found).map_err(|e| Error::Msg(e.to_string()));
        }
        let client = crate::kerberos_client(p.profile, crealm);
        let mut config = AsExchangeConfig::new(me.clone(), crealm);
        config.server = Some(server);
        config.kdc_options = KerberosFlags::new(KdcOptions::empty());
        match auth {
            Auth::Password(pw) => client
                .acquire_tgt_with_config(config, pw)
                .await
                .map_err(Error::Krb),
            Auth::Anonymous => {
                use krb5_rs::pkinit::client::ClientConfig;
                use krb5_rs::pkinit::x509::TrustStore;
                let mut store = TrustStore::default();
                for a in pkinit_strings(p.profile, crealm, "pkinit_anchors") {
                    store.load(&a, true).map_err(Error::Msg)?;
                }
                config.pkinit = Some(ClientConfig::anonymous(store).shared());
                client
                    .acquire_tgt_with_config(config, "")
                    .await
                    .map_err(Error::Krb)
            }
            Auth::Keytab(name) => {
                let name = name
                    .clone()
                    .unwrap_or_else(|| default_keytab_name(Some(p.profile)));
                let kt = resolve_keytab(&name).map_err(Error::Krb)?;
                let entries: Vec<_> = kt
                    .entries()
                    .unwrap_or_default()
                    .into_iter()
                    .filter(|e| {
                        e.principal.name_string == me.name_string
                            && e.realm == crealm
                            && krb5_rs::crypto::find_etype(e.key.keytype).is_ok()
                    })
                    .collect();
                let max = entries
                    .iter()
                    .map(|e| e.kvno)
                    .max()
                    .ok_or_else(|| Error::Msg("Keytab contains no suitable keys".into()))?;
                let keys = entries
                    .into_iter()
                    .filter(|e| e.kvno == max)
                    .map(|e| e.key)
                    .collect();
                client
                    .acquire_tgt_with_keys(config, keys)
                    .await
                    .map_err(Error::Krb)
            }
            Auth::Ccache(_) => unreachable!(),
        }
    }

    fn call(&mut self, proc_: u32, args: &[u8]) -> Result<Vec<u8>, Error> {
        self.rt
            .block_on(self.rpc.call(proc_, args))
            .map_err(|_| Error::Kadm5(code::RPC_ERROR))
    }

    fn check<T>(&self, r: Result<Ret<T>, XdrError>) -> Result<Option<T>, Error> {
        let (_, c, v) = r.map_err(|_| Error::Kadm5(code::RPC_ERROR))?;
        if c == code::OK {
            Ok(v)
        } else {
            Err(Error::Kadm5(c))
        }
    }

    fn need<T>(&self, r: Result<Ret<T>, XdrError>) -> Result<T, Error> {
        self.check(r)?.ok_or(Error::Kadm5(code::RPC_ERROR))
    }

    fn write(&mut self, a: WriteArgs) -> Result<(), Error> {
        let (p, b) = a.encode();
        let reply = self.call(p, &b)?;
        self.check(decode_generic_ret(&reply)).map(|_| ())
    }

    fn read(&mut self, proc_: u32, a: ReadArgs) -> Result<Vec<u8>, Error> {
        self.call(proc_, &a.encode())
    }

    /// `kadm5_create_principal` / `_3`.
    pub fn create_principal(
        &mut self,
        rec: PrincipalEnt,
        mask: i32,
        ks_tuple: Option<Vec<KeySalt>>,
        passwd: Option<String>,
    ) -> Result<(), Error> {
        let api_version = self.api;
        self.write(WriteArgs::CreatePrincipal {
            api_version,
            rec: Box::new(rec),
            mask,
            ks_tuple,
            passwd,
        })
    }

    /// `kadm5_delete_principal`.
    pub fn delete_principal(&mut self, princ: &str) -> Result<(), Error> {
        let api_version = self.api;
        self.write(WriteArgs::DeletePrincipal {
            api_version,
            princ: Some(princ.into()),
        })
    }

    /// `kadm5_modify_principal`.
    pub fn modify_principal(&mut self, rec: PrincipalEnt, mask: i32) -> Result<(), Error> {
        let api_version = self.api;
        self.write(WriteArgs::ModifyPrincipal {
            api_version,
            rec: Box::new(rec),
            mask,
        })
    }

    /// `kadm5_rename_principal`.
    pub fn rename_principal(&mut self, src: &str, dest: &str) -> Result<(), Error> {
        let api_version = self.api;
        self.write(WriteArgs::RenamePrincipal {
            api_version,
            src: Some(src.into()),
            dest: Some(dest.into()),
        })
    }

    /// `kadm5_chpass_principal` / `_3`.
    pub fn chpass_principal(
        &mut self,
        princ: &str,
        pass: &str,
        keepold: bool,
        ks_tuple: Option<Vec<KeySalt>>,
    ) -> Result<(), Error> {
        let api_version = self.api;
        let v3 = keepold || ks_tuple.is_some();
        self.write(WriteArgs::ChpassPrincipal {
            api_version,
            princ: Some(princ.into()),
            v3,
            keepold,
            ks_tuple: ks_tuple.unwrap_or_default(),
            pass: Some(pass.into()),
        })
    }

    fn chrand(
        &mut self,
        princ: &str,
        v3: bool,
        keepold: bool,
        ks: &[KeySalt],
    ) -> Result<Vec<KeyBlock>, Error> {
        let (p, b) = WriteArgs::ChrandPrincipal {
            api_version: self.api,
            princ: Some(princ.into()),
            v3,
            keepold,
            ks_tuple: ks.to_vec(),
        }
        .encode();
        let reply = self.call(p, &b)?;
        Ok(self.check(decode_chrand_ret(&reply))?.unwrap_or_default())
    }

    /// `randkey_princ` (kadmin.c:256-275): `_3` first, then the old call.
    pub fn randkey_principal(
        &mut self,
        princ: &str,
        keepold: bool,
        ks_tuple: Option<&[KeySalt]>,
    ) -> Result<Vec<KeyBlock>, Error> {
        match self.chrand(princ, true, keepold, ks_tuple.unwrap_or(&[])) {
            Err(Error::Kadm5(code::RPC_ERROR)) if !keepold && ks_tuple.is_none() => {
                self.chrand(princ, false, false, &[])
            }
            r => r,
        }
    }

    /// `kadm5_get_principal`.
    pub fn get_principal(&mut self, princ: &str, mask: i32) -> Result<PrincipalEnt, Error> {
        let a = ReadArgs::GetPrincipal {
            api_version: self.api,
            princ: Some(princ.into()),
            mask,
        };
        let reply = self.read(proc_::GET_PRINCIPAL, a)?;
        self.need(decode_gprinc_ret(&reply))
    }

    /// `kadm5_get_principals`.
    pub fn get_principals(&mut self, exp: Option<&str>) -> Result<Vec<String>, Error> {
        let a = ReadArgs::Name {
            api_version: self.api,
            name: exp.map(str::to_string),
        };
        let reply = self.read(proc_::GET_PRINCS, a)?;
        Ok(self.check(decode_names_ret(&reply))?.unwrap_or_default())
    }

    /// `kadm5_create_policy`.
    pub fn create_policy(&mut self, rec: PolicyEnt, mask: i32) -> Result<(), Error> {
        let api_version = self.api;
        self.write(WriteArgs::CreatePolicy {
            api_version,
            rec: Box::new(rec),
            mask,
        })
    }

    /// `kadm5_modify_policy`.
    pub fn modify_policy(&mut self, rec: PolicyEnt, mask: i32) -> Result<(), Error> {
        let api_version = self.api;
        self.write(WriteArgs::ModifyPolicy {
            api_version,
            rec: Box::new(rec),
            mask,
        })
    }

    /// `kadm5_delete_policy`.
    pub fn delete_policy(&mut self, name: &str) -> Result<(), Error> {
        let api_version = self.api;
        self.write(WriteArgs::DeletePolicy {
            api_version,
            name: Some(name.into()),
        })
    }

    /// `kadm5_get_policy`.
    pub fn get_policy(&mut self, name: &str) -> Result<PolicyEnt, Error> {
        let a = ReadArgs::Name {
            api_version: self.api,
            name: Some(name.into()),
        };
        let reply = self.read(proc_::GET_POLICY, a)?;
        self.need(decode_gpol_ret(&reply))
    }

    /// `kadm5_get_policies`.
    pub fn get_policies(&mut self, exp: Option<&str>) -> Result<Vec<String>, Error> {
        let a = ReadArgs::Name {
            api_version: self.api,
            name: exp.map(str::to_string),
        };
        let reply = self.read(proc_::GET_POLS, a)?;
        Ok(self.check(decode_names_ret(&reply))?.unwrap_or_default())
    }

    /// `kadm5_get_privs`.
    pub fn get_privs(&mut self) -> Result<i32, Error> {
        let reply = self.read(proc_::GET_PRIVS, ReadArgs::Api(self.api))?;
        let (_, c, privs) =
            decode_getprivs_ret(&reply).map_err(|_| Error::Kadm5(code::RPC_ERROR))?;
        if c == code::OK {
            Ok(privs)
        } else {
            Err(Error::Kadm5(c))
        }
    }

    /// `kadm5_purgekeys`.
    pub fn purgekeys(&mut self, princ: &str, keepkvno: i32) -> Result<(), Error> {
        let api_version = self.api;
        self.write(WriteArgs::Purgekeys {
            api_version,
            princ: Some(princ.into()),
            keepkvno,
        })
    }

    /// `kadm5_get_strings`.
    pub fn get_strings(&mut self, princ: &str) -> Result<Vec<(String, String)>, Error> {
        let a = ReadArgs::Name {
            api_version: self.api,
            name: Some(princ.into()),
        };
        let reply = self.read(proc_::GET_STRINGS, a)?;
        Ok(self.check(decode_gstrings_ret(&reply))?.unwrap_or_default())
    }

    /// `kadm5_set_string` (a `None` value deletes the attribute).
    pub fn set_string(&mut self, princ: &str, key: &str, value: Option<&str>) -> Result<(), Error> {
        let api_version = self.api;
        self.write(WriteArgs::SetString {
            api_version,
            princ: Some(princ.into()),
            key: Some(key.into()),
            value: value.map(str::to_string),
        })
    }

    /// `kadm5_get_principal_keys`.
    pub fn get_principal_keys(&mut self, princ: &str, kvno: u32) -> Result<Vec<KeyData>, Error> {
        let (p, b) = WriteArgs::ExtractKeys {
            api_version: self.api,
            princ: Some(princ.into()),
            kvno,
        }
        .encode();
        let reply = self.call(p, &b)?;
        Ok(self.check(decode_getpkeys_ret(&reply))?.unwrap_or_default())
    }

    /// `kadm5_create_alias`.
    pub fn create_alias(&mut self, alias: &str, target: &str) -> Result<(), Error> {
        let api_version = self.api;
        self.write(WriteArgs::CreateAlias {
            api_version,
            alias: Some(alias.into()),
            target: Some(target.into()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admin_server_port_forms() {
        assert_eq!(
            parse_admin_server_port("kdc.example.com"),
            ("kdc.example.com".into(), None)
        );
        assert_eq!(
            parse_admin_server_port("kdc:7490"),
            ("kdc".into(), Some(7490))
        );
        assert_eq!(
            parse_admin_server_port("[::1]:750"),
            ("::1".into(), Some(750))
        );
        assert_eq!(parse_admin_server_port("[::1]"), ("::1".into(), None));
    }

    #[test]
    fn admin_server_from_profile() {
        let p = Profile::parse(
            "[realms]\n R = {\n  admin_server = a.example:900\n }\n S = {\n  admin_server = b\n  kadmind_port = 7000\n }\n",
        )
        .unwrap();
        assert_eq!(
            admin_server(&p, "R", None).unwrap(),
            ("a.example".into(), 900)
        );
        assert_eq!(admin_server(&p, "S", None).unwrap(), ("b".into(), 7000));
        assert_eq!(
            admin_server(&p, "S", Some("c")).unwrap(),
            ("c".into(), 7000)
        );
        assert!(matches!(
            admin_server(&p, "T", None),
            Err(Error::Kadm5(code::MISSING_KRB5_CONF_PARAMS))
        ));
    }
}
