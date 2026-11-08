#![cfg(all(feature = "kdc", feature = "client"))]
//! Client password changes over kpasswd (MIT changepw.c/chpw.c) against
//! the krb5-rs kpasswd service, and krb5_verify_init_creds
//! (vfy_increds.c) against an in-process KDC.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

use krb5_rs::ccache::{Ccache, MemoryCcache};
use krb5_rs::client::chpw::{change_password, changepw_principal, set_password};
use krb5_rs::client::vfy::VerifyInitCredsOptions;
use krb5_rs::client::KerberosClient;
use krb5_rs::crypto::SaltType;
use krb5_rs::kdc::kdb::admin::{Admin, AdminOps, PrincipalOptions};
use krb5_rs::kdc::kdb::kpasswd::{process_request, Service};
use krb5_rs::kdc::kdb::kprop::ReplayCache;
use krb5_rs::kdc::kdb::{master_key_from_password, FileStore};
use krb5_rs::kdc::{Kdc, KdcConfig};
use krb5_rs::keytab::FileKeytab;
use krb5_rs::locate::Locator;
use krb5_rs::profile::Profile;
use krb5_rs::protocol::kpasswd::{KPASSWD_ACCESSDENIED, KPASSWD_SUCCESS};
use krb5_rs::protocol::{AsExchange, AsExchangeConfig, Credential, StepResult};
use krb5_rs::transport::KdcTransport;
use krb5_rs::types::PrincipalName;
use krb5_rs::Krb5Error;

const REALM: &str = "CHPW.REALM";

struct TmpDir(PathBuf);

impl TmpDir {
    fn new() -> Self {
        static N: AtomicUsize = AtomicUsize::new(0);
        let dir = std::env::temp_dir().join(format!(
            "krb5rs_chpw_{}_{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).expect("tmp dir");
        Self(dir)
    }

    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for TmpDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn keysalts() -> Vec<(i32, SaltType)> {
    vec![(18, SaltType::Normal), (17, SaltType::Normal)]
}

fn name(s: &str) -> PrincipalName {
    PrincipalName::new_principal(s)
}

struct Realm {
    dir: TmpDir,
    store: Arc<FileStore>,
    kdc: Arc<Kdc<Arc<FileStore>>>,
}

fn realm() -> Realm {
    let dir = TmpDir::new();
    let master = master_key_from_password(REALM, "master-password", 18).expect("master");
    let store =
        Arc::new(FileStore::create(&dir.path("principal"), REALM, &master).expect("create"));
    let admin = Admin::new(&store, keysalts());
    let none = PrincipalOptions::default();
    admin
        .add_principal(&name("alice"), REALM, Some("old-pw"), &none)
        .expect("alice");
    admin
        .add_principal(&name("bob"), REALM, Some("bob-pw"), &none)
        .expect("bob");
    let mut changepw = PrincipalOptions::default();
    changepw
        .attributes
        .add_spec("+pwchange_service")
        .expect("spec");
    admin
        .add_principal(&changepw_principal(), REALM, None, &changepw)
        .expect("changepw");
    admin
        .ktadd(&changepw_principal(), REALM, &dir.path("changepw.kt"), true)
        .expect("ktadd");
    let kdc = Arc::new(Kdc::new(KdcConfig::new(REALM), Arc::clone(&store)));
    Realm { dir, store, kdc }
}

impl Realm {
    async fn as_req(&self, client: &str, pw: &str, server: Option<PrincipalName>) -> Credential {
        self.try_as_req(client, pw, server).await.expect("as")
    }

    async fn try_as_req(
        &self,
        client: &str,
        pw: &str,
        server: Option<PrincipalName>,
    ) -> Result<Credential, Krb5Error> {
        let mut config = AsExchangeConfig::new(name(client), REALM);
        config.server = server;
        let mut ex = AsExchange::new(config, pw);
        let mut reply = Vec::new();
        while let StepResult::SendToKdc { data, .. } | StepResult::RetryTcp { data, .. } =
            ex.step(&reply)?
        {
            reply = self.kdc.handle(&data).await;
        }
        Ok(ex.credential().expect("cred").clone())
    }

    fn service_args(&self) -> (FileKeytab, Arc<ReplayCache>) {
        (
            FileKeytab::new(self.dir.path("changepw.kt")),
            Arc::new(ReplayCache::default()),
        )
    }
}

async fn serve_one(
    store: &Arc<FileStore>,
    keys: &FileKeytab,
    replay: &ReplayCache,
    allow: bool,
    local: SocketAddr,
    remote: SocketAddr,
    req: &[u8],
) -> Option<Vec<u8>> {
    let admin = AdminOps::new(Arc::clone(store), keysalts());
    let authorize = move |_: &PrincipalName, _: &str, _: &PrincipalName, _: &str| allow;
    let svc = Service {
        realm: REALM,
        keys,
        replay: Some(replay),
        clockskew: Duration::from_secs(300),
        authorize: &authorize,
    };
    process_request(&admin, &svc, &local, &remote, req)
        .await
        .reply
}

/// The kadmind kpasswd TCP listener: 4-byte length-prefixed messages.
/// Run `f` on its own thread and runtime: the service borrows
/// non-`Sync` state, as kadmind's single-threaded loop does.
fn spawn_server<F: std::future::Future<Output = ()> + 'static>(
    f: impl FnOnce() -> F + Send + 'static,
) {
    std::thread::spawn(move || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime")
            .block_on(f());
    });
}

async fn tcp_server(r: &Realm, allow: bool) -> u16 {
    let std_l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    std_l.set_nonblocking(true).expect("nonblocking");
    let port = std_l.local_addr().expect("addr").port();
    let store = Arc::clone(&r.store);
    let (keys, replay) = r.service_args();
    spawn_server(move || async move {
        let l = TcpListener::from_std(std_l).expect("listener");
        while let Ok((mut s, remote)) = l.accept().await {
            let local = s.local_addr().expect("local");
            let mut lb = [0u8; 4];
            if s.read_exact(&mut lb).await.is_err() {
                continue;
            }
            let mut req = vec![0u8; u32::from_be_bytes(lb) as usize];
            if s.read_exact(&mut req).await.is_err() {
                continue;
            }
            if let Some(reply) = serve_one(&store, &keys, &replay, allow, local, remote, &req).await
            {
                let n = u32::try_from(reply.len()).expect("len").to_be_bytes();
                let _ = s.write_all(&n).await;
                let _ = s.write_all(&reply).await;
            }
        }
    });
    port
}

async fn udp_server(r: &Realm) -> u16 {
    let std_s = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind");
    std_s.set_nonblocking(true).expect("nonblocking");
    let local = std_s.local_addr().expect("addr");
    let store = Arc::clone(&r.store);
    let (keys, replay) = r.service_args();
    spawn_server(move || async move {
        let s = UdpSocket::from_std(std_s).expect("socket");
        let mut buf = vec![0u8; 65536];
        while let Ok((n, remote)) = s.recv_from(&mut buf).await {
            if let Some(reply) =
                serve_one(&store, &keys, &replay, true, local, remote, &buf[..n]).await
            {
                let _ = s.send_to(&reply, remote).await;
            }
        }
    });
    local.port()
}

fn profile(port: u16) -> Profile {
    Profile::parse(&format!(
        "[realms]\n{REALM} = {{\n kpasswd_server = 127.0.0.1:{port}\n}}\n"
    ))
    .expect("profile")
}

#[tokio::test]
async fn change_password_over_tcp_like_mit_kpasswd() {
    let r = realm();
    let port = tcp_server(&r, true).await;
    let p = profile(port);
    let loc = Locator::new(&p, None);
    let creds = r
        .as_req("alice", "old-pw", Some(changepw_principal()))
        .await;
    let res = change_password(&loc, &creds, "new-pw").await.expect("chpw");
    assert_eq!(res.result_code, KPASSWD_SUCCESS, "{}", res.message());
    assert_eq!(res.result_code_string, "Success");
    r.as_req("alice", "new-pw", None).await;
    assert!(r.try_as_req("alice", "old-pw", None).await.is_err());
}

#[tokio::test]
async fn change_password_falls_back_to_udp_when_tcp_is_unreachable() {
    let r = realm();
    let port = udp_server(&r).await;
    let p = profile(port);
    let loc = Locator::new(&p, None);
    let creds = r
        .as_req("alice", "old-pw", Some(changepw_principal()))
        .await;
    let res = change_password(&loc, &creds, "udp-pw").await.expect("chpw");
    assert_eq!(res.result_code, KPASSWD_SUCCESS, "{}", res.message());
    r.as_req("alice", "udp-pw", None).await;
}

#[tokio::test]
async fn set_password_for_another_principal_like_rfc3244() {
    let r = realm();
    let p = profile(tcp_server(&r, true).await);
    let allow = Locator::new(&p, None);
    let creds = r
        .as_req("alice", "old-pw", Some(changepw_principal()))
        .await;
    let res = set_password(&allow, &creds, "bob-new", Some((&name("bob"), REALM)))
        .await
        .expect("setpw");
    assert_eq!(res.result_code, KPASSWD_SUCCESS, "{}", res.message());
    r.as_req("bob", "bob-new", None).await;

    // Without the ACL the server refuses (schpw.c:213-227).
    let p2 = profile(tcp_server(&r, false).await);
    let deny = Locator::new(&p2, None);
    let res = set_password(&deny, &creds, "bob-other", Some((&name("bob"), REALM)))
        .await
        .expect("setpw");
    assert_eq!(res.result_code, KPASSWD_ACCESSDENIED);
    assert_eq!(res.result_code_string, "Access denied");
    r.as_req("bob", "bob-new", None).await;

    // No target sets the caller's own password; the server still asks
    // kadm5_auth, where MIT's `self` module allows it (misc.c:33-56).
    let res = set_password(&allow, &creds, "self-pw", None)
        .await
        .expect("setpw");
    assert_eq!(res.result_code, KPASSWD_SUCCESS, "{}", res.message());
    r.as_req("alice", "self-pw", None).await;
}

#[tokio::test]
async fn change_password_with_no_server_is_unreachable() {
    let r = realm();
    // A port nothing listens on, for TCP or UDP.
    let port = {
        let s = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind");
        s.local_addr().expect("addr").port()
    };
    let p = profile(port);
    let loc = Locator::new(&p, None);
    let creds = r
        .as_req("alice", "old-pw", Some(changepw_principal()))
        .await;
    assert!(change_password(&loc, &creds, "x").await.is_err());
}

struct InProcess(Arc<Kdc<Arc<FileStore>>>);

impl KdcTransport for InProcess {
    async fn send_recv(&self, _realm: &str, message: &[u8]) -> Result<Vec<u8>, Krb5Error> {
        Ok(self.0.handle(message).await)
    }
}

#[tokio::test]
async fn verify_init_creds_uses_host_keys_like_mit() {
    let r = realm();
    let admin = Admin::new(&r.store, keysalts());
    let host = PrincipalName::new_srv_hst("host", "h.chpw.realm");
    admin
        .add_principal(&host, REALM, None, &PrincipalOptions::default())
        .expect("host");
    let kt_path = r.dir.path("host.kt");
    admin.ktadd(&host, REALM, &kt_path, true).expect("ktadd");
    let kt = FileKeytab::new(&kt_path);
    let client = KerberosClient::new(REALM, InProcess(Arc::clone(&r.kdc)));
    let tgt = r.as_req("alice", "old-pw", None).await;
    let opts = VerifyInitCredsOptions::default();

    // Host principals come from the keytab; the host ticket lands in the
    // output cache and the TGT does not.
    let mut out = MemoryCcache::new();
    client
        .verify_init_creds(&tgt, None, Some(&kt), Some(&mut out), &opts)
        .await
        .expect("verify");
    assert_eq!(out.principal().expect("principal").0, name("alice"));
    let creds = out.creds().expect("creds");
    assert_eq!(creds.len(), 1);
    assert_eq!(creds[0].server.name_string, host.name_string);

    // An explicit server works too.
    client
        .verify_init_creds(&tgt, Some((&host, REALM)), Some(&kt), None, &opts)
        .await
        .expect("verify server");

    // A keytab whose key no longer matches the KDC's fails.
    let stale = r.dir.path("stale.kt");
    std::fs::copy(&kt_path, &stale).expect("copy");
    admin.ktadd(&host, REALM, &kt_path, true).expect("rekey");
    let stale_kt = FileKeytab::new(&stale);
    let tgt2 = r.as_req("alice", "old-pw", None).await;
    // Rekey again so the stale keytab holds no key of the current kvno.
    admin.ktadd(&host, REALM, &kt_path, true).expect("rekey");
    assert!(client
        .verify_init_creds(&tgt2, None, Some(&stale_kt), None, &opts)
        .await
        .is_err());
}

#[tokio::test]
async fn verify_init_creds_without_keys_succeeds_unless_nofail() {
    let r = realm();
    let client = KerberosClient::new(REALM, InProcess(Arc::clone(&r.kdc)));
    let tgt = r.as_req("alice", "old-pw", None).await;
    let missing = FileKeytab::new(r.dir.path("missing.kt"));
    let opts = VerifyInitCredsOptions::default();
    client
        .verify_init_creds(&tgt, None, Some(&missing), None, &opts)
        .await
        .expect("no keys is success");
    let host = PrincipalName::new_srv_hst("host", "absent");
    client
        .verify_init_creds(&tgt, Some((&host, REALM)), Some(&missing), None, &opts)
        .await
        .expect("no key for server is success");

    let nofail = VerifyInitCredsOptions {
        ap_req_nofail: Some(true),
        ..Default::default()
    };
    assert!(client
        .verify_init_creds(&tgt, None, Some(&missing), None, &nofail)
        .await
        .is_err());

    // verify_ap_req_nofail from the profile, per realm first.
    let p = Profile::parse(&format!(
        "[libdefaults]\n verify_ap_req_nofail = false\n {REALM} = {{\n  verify_ap_req_nofail = true\n }}\n"
    ))
    .expect("profile");
    let from_profile = VerifyInitCredsOptions {
        profile: Some(&p),
        ..Default::default()
    };
    assert!(client
        .verify_init_creds(&tgt, None, Some(&missing), None, &from_profile)
        .await
        .is_err());
}
