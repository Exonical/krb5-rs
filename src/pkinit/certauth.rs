//! certauth modules like MIT's (`krb5_certauth_vtable`,
//! plugins/preauth/pkinit/pkinit_srv.c `authorize_cert`): the built-in
//! `pkinit_san`, `pkinit_eku` and `dbmatch`, and modules configured as
//! `[plugins] certauth { module = name:unix:path=... }`, run as separate
//! processes over [`crate::plugin::rpc`].

use std::io::{self, Read, Write};
use std::sync::Arc;

use crate::plugin::rpc::{self, Message, ERROR_TABLE_BASE_KRB5, PLUGIN_NO_HANDLE};
use crate::plugin::{self as plugins, Configured};
use crate::profile::Profile;

/// `KRB5_CERTAUTH_HWAUTH`: authorize and set the hw-authent flag.
pub const CERTAUTH_HWAUTH: i32 = -1_750_600_192 + 12;
/// `KRB5_CERTAUTH_HWAUTH_PASS`: set hw-authent if another module authorizes.
pub const CERTAUTH_HWAUTH_PASS: i32 = -1_750_600_192 + 13;
/// [`rpc::call::INITIALIZE`]'s string for a certauth module.
pub const CERTAUTH_HANDSHAKE: &str = "KRB5RS-CERTAUTH-V-1";

/// certauth call numbers.
pub mod call {
    pub use crate::plugin::rpc::call::{FINALIZE, INITIALIZE};
    /// `authorize`: `ay` DER certificate and `s` client principal; answered
    /// with `i` result code and `as` authentication indicators.
    pub const AUTHORIZE: u32 = 3;
}

/// A certauth module. `authorize` returns 0 or [`CERTAUTH_HWAUTH`] to
/// authorize, `PLUGIN_NO_HANDLE` or [`CERTAUTH_HWAUTH_PASS`] for no
/// opinion, or a com_err refusal such as `KRB5KDC_ERR_CLIENT_NAME_MISMATCH`,
/// with authentication indicators to assert.
pub trait Certauth: Send + Sync {
    /// The module name.
    fn name(&self) -> &str;
    /// `init`: an error skips the module, as in MIT.
    fn init(&self) -> Result<(), i32> {
        Ok(())
    }
    /// `fini`.
    fn fini(&self) {}
    /// `authorize`.
    fn authorize(&self, cert: &[u8], client: &str) -> (i32, Vec<String>);
}

/// One enabled certauth module.
#[derive(Clone)]
pub enum CertauthModule {
    /// `pkinit_san`.
    PkinitSan,
    /// `pkinit_eku`.
    PkinitEku,
    /// `dbmatch`: passes, as `pkinit_cert_match` is not implemented.
    Dbmatch,
    /// Another module.
    Module(Arc<dyn Certauth>),
}

impl std::fmt::Debug for CertauthModule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PkinitSan => f.write_str("pkinit_san"),
            Self::PkinitEku => f.write_str("pkinit_eku"),
            Self::Dbmatch => f.write_str("dbmatch"),
            Self::Module(m) => f.write_str(m.name()),
        }
    }
}

/// MIT's default list.
pub fn builtin_modules() -> Vec<CertauthModule> {
    vec![
        CertauthModule::PkinitSan,
        CertauthModule::PkinitEku,
        CertauthModule::Dbmatch,
    ]
}

/// A certauth module reached over RPC; a call that fails refuses the
/// certificate.
pub struct RemoteCertauth(rpc::Conn);

impl Certauth for RemoteCertauth {
    fn name(&self) -> &str {
        &self.0.name
    }
    fn authorize(&self, cert: &[u8], client: &str) -> (i32, Vec<String>) {
        let mut m = Message::new(call::AUTHORIZE);
        m.put_bytes(cert).put_str(Some(client));
        let failed = (ERROR_TABLE_BASE_KRB5 + rpc::KRB_ERR_GENERIC, Vec::new());
        match self.0.call(&m) {
            Ok(Ok(mut a)) => {
                let r = (|| -> io::Result<(i32, Vec<String>)> {
                    let code = a.get_i32()?;
                    let inds = a.get_strs()?;
                    a.finish()?;
                    Ok((code, inds))
                })();
                r.unwrap_or(failed)
            }
            Ok(Err((code, _))) => (code, Vec::new()),
            Err(_) => failed,
        }
    }
}

/// `load_certauth_plugins`: the enabled modules of `profiles` in MIT's
/// order. A module that can't be reached or initialized is skipped, as MIT
/// skips one that fails to load or initialize.
pub fn load(profiles: &[&Profile]) -> Result<Vec<CertauthModule>, String> {
    let list = plugins::configured(
        profiles,
        "certauth",
        &["pkinit_san", "pkinit_eku", "dbmatch"],
    )?;
    Ok(list
        .into_iter()
        .filter_map(|c| match c {
            Configured::Builtin(n) => match n.as_str() {
                "pkinit_san" => Some(CertauthModule::PkinitSan),
                "pkinit_eku" => Some(CertauthModule::PkinitEku),
                "dbmatch" => Some(CertauthModule::Dbmatch),
                _ => None,
            },
            Configured::Remote(n, path) => {
                rpc::Conn::open(&n, CERTAUTH_HANDSHAKE, plugins::connector(path))
                    .ok()
                    .map(|c| CertauthModule::Module(Arc::new(RemoteCertauth(c))))
            }
        })
        .collect())
}

/// Serve a certauth module on `stream`.
pub fn serve_certauth<S: Read + Write>(stream: S, module: &dyn Certauth) -> io::Result<()> {
    rpc::serve(stream, CERTAUTH_HANDSHAKE, |req| {
        let mut answer = Message::new(req.call);
        Ok(match req.call {
            call::INITIALIZE => module.init().map(|()| answer).map_err(|c| (c, None)),
            call::FINALIZE => {
                module.fini();
                Ok(answer)
            }
            call::AUTHORIZE => {
                let cert = req.get_bytes()?;
                let client = req.get_str()?.unwrap_or_default();
                req.finish()?;
                let (code, inds) = module.authorize(&cert, &client);
                answer.put_i32(code).put_strs(&inds);
                Ok(answer)
            }
            _ => Err((PLUGIN_NO_HANDLE, None)),
        })
    })
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::net::UnixListener;

    /// MIT's plugins/certauth/test `test1` and `test3`, keyed on the
    /// principal instead of the database entry.
    struct Test;
    impl Certauth for Test {
        fn name(&self) -> &str {
            "test"
        }
        fn authorize(&self, cert: &[u8], client: &str) -> (i32, Vec<String>) {
            match client {
                "hw@R" => (CERTAUTH_HWAUTH, vec!["hwauth:ok".into()]),
                "pass@R" => (CERTAUTH_HWAUTH_PASS, vec![]),
                "bad@R" => (ERROR_TABLE_BASE_KRB5 + 66, vec![]),
                _ => (PLUGIN_NO_HANDLE, vec![format!("test1 {}", cert.len())]),
            }
        }
    }

    #[test]
    fn remote_certauth_round_trips_and_loads_in_mit_order() {
        let dir = std::env::temp_dir().join(format!("krb5rs-certauth-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("dir");
        let path = dir.join("test.sock");
        let l = UnixListener::bind(&path).expect("bind");
        std::thread::spawn(move || {
            for s in l.incoming().flatten() {
                std::thread::spawn(move || {
                    let _ = serve_certauth(s, &Test);
                });
            }
        });
        let conf = |extra: &str| {
            Profile::parse(&format!(
                "[plugins]\n certauth = {{\n  module = test:unix:path={}\n{extra} }}\n",
                path.display()
            ))
            .expect("conf")
        };
        let p = conf("");
        let mods = load(&[&p]).expect("load");
        assert_eq!(
            format!("{mods:?}"),
            "[test, pkinit_san, pkinit_eku, dbmatch]"
        );
        let CertauthModule::Module(m) = &mods[0] else {
            panic!("remote first");
        };
        assert_eq!(
            m.authorize(b"abc", "u@R"),
            (PLUGIN_NO_HANDLE, vec!["test1 3".to_string()])
        );
        assert_eq!(
            m.authorize(b"", "hw@R"),
            (CERTAUTH_HWAUTH, vec!["hwauth:ok".to_string()])
        );
        assert_eq!(m.authorize(b"", "pass@R").0, CERTAUTH_HWAUTH_PASS);
        assert_eq!(m.authorize(b"", "bad@R").0, ERROR_TABLE_BASE_KRB5 + 66);
        let p = conf("  enable_only = pkinit_eku\n  enable_only = test\n");
        assert_eq!(
            format!("{:?}", load(&[&p]).expect("load")),
            "[pkinit_eku, test]"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
