//! Cyrus SASL 2.1.28's GS2 client (gs2.c:686-875, RFC 5801) for GS2-KRB5
//! and GS2-IAKERB: no channel bindings, no security layer.

use krb5_rs::ccache::{Ccache, MatchCred, MatchFlags};
use krb5_rs::gssapi::iakerb::{IakerbCred, IakerbInitiator};
use krb5_rs::gssapi::krb5::{GssFlags, InitStep, Krb5Context, Krb5Initiator};
use krb5_rs::gssapi::token::parse_token_header;
use krb5_rs::types::PrincipalName;

use super::{Interact, Layer, Mech, Params};

const REQ: GssFlags = GssFlags::MUTUAL.union(GssFlags::SEQUENCE);

enum Init {
    Krb5(Box<Krb5Initiator>),
    Iakerb(Box<IakerbInitiator>),
}

impl Init {
    fn step(&mut self, input: Option<&[u8]>) -> Result<InitStep, String> {
        match self {
            Init::Krb5(i) => i.step(input),
            Init::Iakerb(i) => i.step(input),
        }
        .map_err(|e| e.to_string())
    }

    fn context(self) -> Result<Krb5Context, String> {
        match self {
            Init::Krb5(i) => i.context(),
            Init::Iakerb(i) => i.context(),
        }
        .map_err(|e| e.to_string())
    }
}

/// `gs2_make_header` with `n` (no channel bindings): the krb5 mechanisms
/// frame their tokens, so there is no `F,`.
pub(super) fn header(authzid: Option<&str>) -> Vec<u8> {
    let mut h = b"n,".to_vec();
    if let Some(z) = authzid.filter(|z| !z.is_empty()) {
        h.extend_from_slice(b"a=");
        h.extend_from_slice(z.replace('=', "=3D").replace(',', "=2C").as_bytes());
    }
    h.push(b',');
    h
}

pub(super) struct Gs2 {
    header: Option<Vec<u8>>,
    init: Option<Init>,
    done: bool,
}

impl Gs2 {
    pub(super) async fn krb5(i: Interact, p: &Params) -> Result<Self, String> {
        let init = super::krb5_initiator(&p.host, REQ).await?;
        Ok(Self::with(Init::Krb5(Box::new(init)), &i))
    }

    /// `iakerb_get_initial_state`'s inputs from the selected ccache: a cached
    /// ticket for the server, else the local TGT; the KDC exchanges go
    /// through the LDAP server.
    pub(super) fn iakerb(i: Interact, p: &Params) -> Result<Self, String> {
        let profile = super::krb5_profile()?;
        let srealm = krb5_rs::locate::host_realm(&profile, &p.host)
            .into_iter()
            .next()
            .unwrap_or_default();
        let ctx = krb5_rs::ccache::CcContext::from_env(Some(&profile));
        let server = PrincipalName::new_srv_hst("ldap", &p.host);
        let cache = krb5_rs::ccache::select_cache(&ctx, Some(&profile), &server, &srealm)
            .map_err(|e| e.to_string())?;
        let (client, crealm) = cache.principal().map_err(|e| e.to_string())?;
        let get = |name: PrincipalName, realm: &str| {
            let m = MatchCred {
                client: Some((client.clone(), crealm.clone())),
                server: Some((name, realm.to_string())),
                ..MatchCred::default()
            };
            cache
                .retrieve(MatchFlags::empty(), &m, None)
                .ok()
                .and_then(|c| TryFrom::try_from(&c).ok())
        };
        let service = get(server.clone(), &srealm);
        let tgt = get(PrincipalName::new_srv_inst("krbtgt", &crealm), &crealm);
        let cred = IakerbCred {
            client: client.clone(),
            realm: crealm.clone(),
            password: None,
            tgt,
            service,
        };
        let init = IakerbInitiator::new(cred, server, Default::default(), REQ, None);
        Ok(Self::with(Init::Iakerb(Box::new(init)), &i))
    }

    fn with(init: Init, i: &Interact) -> Self {
        Gs2 {
            header: Some(header(i.authzid.as_deref())),
            init: Some(init),
            done: false,
        }
    }

    fn run(&mut self, input: Option<&[u8]>) -> Result<Vec<u8>, String> {
        let init = self
            .init
            .as_mut()
            .ok_or("GS2 context already established")?;
        let (tok, complete) = match init.step(input)? {
            InitStep::Continue(t) => (t, false),
            InitStep::Complete(t) => (t.unwrap_or_default(), true),
        };
        let out = match self.header.take() {
            // gs2_make_message: gss_decapsulate_token on the first token.
            Some(mut h) => {
                let (_, body) = parse_token_header(&tok).ok_or("GS2 Failure: defective token")?;
                h.extend_from_slice(body);
                h
            }
            None => tok,
        };
        if complete {
            let ctx = self.init.take().ok_or("GS2 context missing")?.context()?;
            if !ctx.flags().contains(REQ) {
                return Err("GS2 Failure: mutual authentication or sequencing not provided".into());
            }
            self.done = true;
        }
        Ok(out)
    }
}

impl Mech for Gs2 {
    fn start(&mut self) -> Result<Option<Vec<u8>>, String> {
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
            if let Some(d) = data.filter(|d| !d.is_empty()) {
                self.run(Some(d))?;
            }
        }
        if !self.done {
            return Err("server did not finish the SASL exchange".into());
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn header() {
        assert_eq!(super::header(None), b"n,,");
        assert_eq!(super::header(Some("")), b"n,,");
        assert_eq!(super::header(Some("u=a,b")), b"n,a=u=3Da=2Cb,");
    }
}
