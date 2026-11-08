//! Client password changes over kpasswd (MIT `lib/krb5/os/changepw.c`).

use std::net::SocketAddr;
use std::time::Duration;

use rasn::types::OctetString;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

use super::{CredsRequest, GcOptions, KerberosClient};
use crate::ccache::Ccache;
use crate::error::Krb5Error;
use crate::locate::{LocateError, LocateService, Locator, ServerEntry, Transport};
use crate::protocol::ap::{ApReqOptions, AuthContext};
use crate::protocol::kpasswd::{self, KPASSWD_PORT};
use crate::protocol::Credential;
use crate::transport::sendto::SendtoError;
use crate::transport::KdcTransport;
use crate::types::{HostAddress, PrincipalName};

const TCP_TIMEOUT: Duration = Duration::from_secs(10);
const UDP_TIMEOUT: Duration = Duration::from_secs(3);
const MAX_REPLY: usize = 64 * 1024;

/// The outcome of a password change (`result_code`,
/// `result_code_string` and `result_string` of
/// `krb5_change_password`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChpwResult {
    /// `KRB5_KPASSWD_*` result code.
    pub result_code: u16,
    /// `krb5_chpw_result_code_string` for the code.
    pub result_code_string: &'static str,
    /// The server's result string; see [`ChpwResult::message`].
    pub result_string: Vec<u8>,
}

impl ChpwResult {
    /// `krb5_chpw_message` for the server's result string.
    pub fn message(&self) -> String {
        kpasswd::chpw_message(&self.result_string)
    }
}

/// `kadmin/changepw@realm`, typed as `krb5_build_principal` does.
pub fn changepw_principal() -> PrincipalName {
    let mut p = PrincipalName::new_srv_inst("kadmin", "changepw");
    p.name_type = 1;
    p
}

/// `locate_kpasswd` (changepw.c:59-87): kpasswd servers, else the admin
/// servers on the kpasswd port over TCP or UDP.
fn locate_kpasswd(locator: &Locator<'_>, realm: &str) -> Result<Vec<ServerEntry>, Krb5Error> {
    match locator.locate_server(realm, LocateService::Kpasswd, false) {
        Err(LocateError::RealmUnknown | LocateError::RealmCantResolve) => {
            let mut list = locator.locate_server(realm, LocateService::Kadmin, true)?;
            for s in &mut list {
                if s.transport == Transport::Tcp {
                    s.transport = Transport::TcpOrUdp;
                }
                s.port = KPASSWD_PORT;
            }
            Ok(list)
        }
        r => Ok(r?),
    }
}

fn local_address(local: &SocketAddr) -> HostAddress {
    match local {
        SocketAddr::V4(a) => HostAddress {
            addr_type: 2,
            address: OctetString::from(a.ip().octets().to_vec()),
        },
        SocketAddr::V6(a) => HostAddress {
            addr_type: 24,
            address: OctetString::from(a.ip().octets().to_vec()),
        },
    }
}

/// The request for one connection (`kpasswd_sendto_msg_callback`,
/// changepw.c:89-143): the auth context's local address is the
/// connection's.
fn build(
    base: &AuthContext,
    ap_req: &[u8],
    local: &SocketAddr,
    newpw: &[u8],
    target: Option<(&PrincipalName, &str)>,
) -> Result<(AuthContext, Vec<u8>), Krb5Error> {
    let mut ctx = base.clone();
    ctx.set_addrs(Some(local_address(local)), None);
    let msg = match target {
        Some((p, r)) => kpasswd::mk_setpw_req(&mut ctx, ap_req, p, r, newpw)?,
        None => kpasswd::mk_chpw_req(&mut ctx, ap_req, newpw)?,
    };
    Ok((ctx, msg))
}

async fn try_tcp(
    addr: SocketAddr,
    base: &AuthContext,
    ap_req: &[u8],
    newpw: &[u8],
    target: Option<(&PrincipalName, &str)>,
) -> Result<(AuthContext, Vec<u8>), Krb5Error> {
    let io = async {
        let mut s = TcpStream::connect(addr).await?;
        let (ctx, msg) = build(base, ap_req, &s.local_addr()?, newpw, target)?;
        let len = u32::try_from(msg.len())
            .map_err(|_| Krb5Error::Protocol("kpasswd request too long".into()))?;
        s.write_all(&len.to_be_bytes()).await?;
        s.write_all(&msg).await?;
        let mut lb = [0u8; 4];
        s.read_exact(&mut lb).await?;
        let n = u32::from_be_bytes(lb) as usize;
        if n > MAX_REPLY {
            return Err(Krb5Error::Protocol("kpasswd reply too long".into()));
        }
        let mut reply = vec![0u8; n];
        s.read_exact(&mut reply).await?;
        Ok::<_, Krb5Error>((ctx, reply))
    };
    tokio::time::timeout(TCP_TIMEOUT, io)
        .await
        .map_err(|_| Krb5Error::Sendto(SendtoError::KdcUnreach))?
}

async fn try_udp(
    addr: SocketAddr,
    base: &AuthContext,
    ap_req: &[u8],
    newpw: &[u8],
    target: Option<(&PrincipalName, &str)>,
) -> Result<(AuthContext, Vec<u8>), Krb5Error> {
    let bind: SocketAddr = if addr.is_ipv4() {
        "0.0.0.0:0".parse().expect("addr")
    } else {
        "[::]:0".parse().expect("addr")
    };
    let s = UdpSocket::bind(bind).await?;
    s.connect(addr).await?;
    let (ctx, msg) = build(base, ap_req, &s.local_addr()?, newpw, target)?;
    s.send(&msg).await?;
    let mut buf = vec![0u8; MAX_REPLY];
    let n = tokio::time::timeout(UDP_TIMEOUT, s.recv(&mut buf))
        .await
        .map_err(|_| Krb5Error::Sendto(SendtoError::KdcUnreach))??;
    buf.truncate(n);
    Ok((ctx, buf))
}

/// Send to each server in turn over the protocols `udp` selects,
/// returning the first reply.
async fn send(
    servers: &[ServerEntry],
    udp: bool,
    base: &AuthContext,
    ap_req: &[u8],
    newpw: &[u8],
    target: Option<(&PrincipalName, &str)>,
) -> Result<(AuthContext, Vec<u8>), Krb5Error> {
    for srv in servers {
        let usable = match srv.transport {
            Transport::Udp => udp,
            Transport::Tcp => !udp,
            Transport::TcpOrUdp => true,
            Transport::Https => false,
        };
        if !usable {
            continue;
        }
        let Ok(addrs) = tokio::net::lookup_host((srv.hostname.as_str(), srv.port)).await else {
            continue;
        };
        for addr in addrs {
            let r = if udp {
                try_udp(addr, base, ap_req, newpw, target).await
            } else {
                try_tcp(addr, base, ap_req, newpw, target).await
            };
            match r {
                Ok(v) => return Ok(v),
                Err(Krb5Error::Transport(_) | Krb5Error::Sendto(SendtoError::KdcUnreach)) => {}
                Err(e) => return Err(e),
            }
        }
    }
    Err(Krb5Error::Sendto(SendtoError::KdcUnreach))
}

/// `change_set_password` (changepw.c:145-306).
async fn change_set_password(
    locator: &Locator<'_>,
    creds: &Credential,
    newpw: &str,
    target: Option<(&PrincipalName, &str)>,
) -> Result<ChpwResult, Krb5Error> {
    let mut base = AuthContext::new();
    let opts = ApReqOptions {
        use_subkey: true,
        ..Default::default()
    };
    let ap_req = base.mk_req(&opts, None, creds)?;
    let realm = &creds.srealm;
    let newpw = newpw.as_bytes();

    // Non-UDP first, then UDP only when every server was unreachable
    // (changepw.c:233-262).
    let servers = locate_kpasswd(locator, realm)?;
    let mut r = send(&servers, false, &base, &ap_req, newpw, target).await;
    if matches!(r, Err(Krb5Error::Sendto(SendtoError::KdcUnreach))) {
        r = send(&servers, true, &base, &ap_req, newpw, target).await;
    }
    let (mut ctx, reply) = r?;
    let (code, result_string) = kpasswd::rd_chpw_rep(&mut ctx, &reply)?;
    Ok(ChpwResult {
        result_code: code,
        result_code_string: kpasswd::result_code_string(code),
        result_string,
    })
}

/// `krb5_change_password`: change the password of `creds`' client,
/// using a `kadmin/changepw` ticket.
pub async fn change_password(
    locator: &Locator<'_>,
    creds: &Credential,
    newpw: &str,
) -> Result<ChpwResult, Krb5Error> {
    change_set_password(locator, creds, newpw, None).await
}

/// `krb5_set_password`: set the password of `target` (`name`, `realm`),
/// or of `creds`' client when `target` is `None`, with the RFC 3244
/// protocol.
pub async fn set_password(
    locator: &Locator<'_>,
    creds: &Credential,
    newpw: &str,
    target: Option<(&PrincipalName, &str)>,
) -> Result<ChpwResult, Krb5Error> {
    let target = target.unwrap_or((&creds.client, &creds.crealm));
    change_set_password(locator, creds, newpw, Some(target)).await
}

impl<T: KdcTransport> KerberosClient<T> {
    /// `krb5_set_password_using_ccache`: get `kadmin/changepw` in
    /// `target`'s realm with the cache's client, then set `target`'s
    /// password.
    pub async fn set_password_using_ccache<C: Ccache>(
        &self,
        locator: &Locator<'_>,
        ccache: &mut C,
        newpw: &str,
        target: (&PrincipalName, &str),
    ) -> Result<ChpwResult, Krb5Error> {
        let (client, crealm) = ccache.principal()?;
        let req = CredsRequest::new(client, crealm, changepw_principal(), target.1);
        let creds = self
            .get_credentials(ccache, GcOptions::empty(), &req)
            .await?;
        set_password(locator, &creds, newpw, Some(target)).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::Profile;

    #[test]
    fn kpasswd_falls_back_to_admin_server_on_port_464() {
        let p = Profile::parse("[realms]\nR = {\n admin_server = adm.r:749\n}\n").expect("profile");
        let loc = Locator::new(&p, None);
        let l = locate_kpasswd(&loc, "R").expect("servers");
        assert_eq!(l.len(), 1);
        assert_eq!((l[0].hostname.as_str(), l[0].port), ("adm.r", KPASSWD_PORT));
        assert_eq!(l[0].transport, Transport::TcpOrUdp);
        let p = Profile::parse(
            "[realms]\nR = {\n kpasswd_server = pw.r:1464\n admin_server = adm.r\n}\n",
        )
        .expect("profile");
        let loc = Locator::new(&p, None);
        let l = locate_kpasswd(&loc, "R").expect("servers");
        assert_eq!((l[0].hostname.as_str(), l[0].port), ("pw.r", 1464));
        assert!(locate_kpasswd(&Locator::new(&Profile::parse("").expect("p"), None), "R").is_err());
    }
}
