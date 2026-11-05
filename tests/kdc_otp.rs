#![cfg(all(feature = "kdc", unix))]
//! OTP pre-authentication over RADIUS, our client against our KDC, modeled
//! on MIT krb5 1.22.2 `tests/t_otp.py` (plugins/preauth/otp/main.c,
//! otp_state.c, lib/krb5/krb/preauth_otp.c, lib/krad).

use std::sync::{Arc, Mutex};
use std::time::Duration;

use krb5_rs::kdc::{Kdc, KdcConfig, MemoryStore, OtpTokenType, PrincipalAttributes};
use krb5_rs::krad::{self, attr, code};
use krb5_rs::otp::OtpAnswer;
use krb5_rs::protocol::fast::FastMode;
use krb5_rs::protocol::{AsExchange, AsExchangeConfig, Credential, StepResult};
use krb5_rs::types::*;
use krb5_rs::Krb5Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const REALM: &str = "EXAMPLE.COM";
const PW: &str = "the-real-password";
const SECRET: &str = "radius-secret";

fn name(n: &str) -> PrincipalName {
    PrincipalName::new_principal(n)
}

type Log = Arc<Mutex<Vec<(String, String)>>>;

/// Answer one Access-Request: accept when the password is `accept` and the
/// user is not `bad`, as MIT's `RadiusDaemon` in t_otp.py does.
fn answer(secret: &str, buf: &[u8], log: &Log) -> Option<Vec<u8>> {
    let req = krad::decode_request(secret, buf).ok()?;
    let user = String::from_utf8(req.attr(attr::USER_NAME, 0)?.to_vec()).ok()?;
    // krad_packet_decode_request already decoded User-Password.
    let pw = String::from_utf8(req.attr(attr::USER_PASSWORD, 0)?.to_vec()).ok()?;
    let ok = pw == "accept" && user != "bad";
    log.lock().unwrap().push((user, pw));
    let c = if ok {
        code::ACCESS_ACCEPT
    } else {
        code::ACCESS_REJECT
    };
    Some(krad::new_response(secret, c, &[], &req).ok()?.raw)
}

async fn udp_server(log: Log) -> String {
    let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = sock.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        loop {
            let Ok((n, peer)) = sock.recv_from(&mut buf).await else {
                return;
            };
            if let Some(rsp) = answer(SECRET, &buf[..n], &log) {
                let _ = sock.send_to(&rsp, peer).await;
            }
        }
    });
    addr.to_string()
}

async fn unix_server(dir: &std::path::Path, log: Log) -> String {
    let path = dir.join("DEFAULT.socket");
    let listener = tokio::net::UnixListener::bind(&path).unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = listener.accept().await else {
                return;
            };
            let log = log.clone();
            tokio::spawn(async move {
                loop {
                    let mut hdr = [0u8; 4];
                    if s.read_exact(&mut hdr).await.is_err() {
                        return;
                    }
                    let len = usize::from(u16::from_be_bytes([hdr[2], hdr[3]]));
                    let mut buf = hdr.to_vec();
                    buf.resize(len.max(4), 0);
                    if s.read_exact(&mut buf[4..]).await.is_err() {
                        return;
                    }
                    match answer("", &buf, &log) {
                        Some(rsp) => {
                            let _ = s.write_all(&rsp).await;
                        }
                        None => return,
                    }
                }
            });
        }
    });
    path.to_string_lossy().into_owned()
}

struct TempDir(std::path::PathBuf);

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct World {
    kdc: Kdc<MemoryStore>,
    log: Log,
    _dir: TempDir,
}

/// The KDC with a `udp` token type (indicator `typeind`) and a `DEFAULT`
/// type on a Unix socket; `user` carries the `otp` attribute `otp`, and
/// `host/strong` requires the indicators in `require`.
async fn world(otp: &str, require: Option<&str>) -> World {
    let log: Log = Arc::default();
    static N: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let dir = TempDir(std::env::temp_dir().join(format!("kdc-otp-{}-{n}", std::process::id())));
    std::fs::create_dir_all(&dir.0).unwrap();
    let udp = udp_server(log.clone()).await;
    let unix = unix_server(&dir.0, log.clone()).await;
    let mut store = MemoryStore::new();
    store
        .add_random_key(
            PrincipalName::new_srv_inst("krbtgt", REALM),
            REALM,
            1,
            &[18, 17],
            PrincipalAttributes::empty(),
        )
        .unwrap();
    let strong = PrincipalName::new_srv_inst("host", "strong");
    store
        .add_random_key(
            strong.clone(),
            REALM,
            1,
            &[18, 17],
            PrincipalAttributes::empty(),
        )
        .unwrap();
    let mut e = store.get(&strong, REALM).unwrap();
    e.require_auth = require.map(Into::into);
    store.insert(e);
    for user in ["armoruser", "user"] {
        store
            .add_with_password(
                name(user),
                REALM,
                PW,
                1,
                &[18, 17],
                PrincipalAttributes::REQUIRES_PRE_AUTH,
            )
            .unwrap();
    }
    let mut e = store.get(&name("user"), REALM).unwrap();
    e.otp = Some(otp.into());
    store.insert(e);
    let mut config = KdcConfig::new(REALM);
    let ty = |n: &str, server: String, secret: &str, strip: bool, ind: &[&str]| OtpTokenType {
        name: n.into(),
        server,
        secret: secret.into(),
        timeout: Duration::from_secs(2),
        retries: 1,
        strip_realm: strip,
        indicators: ind.iter().map(|s| s.to_string()).collect(),
    };
    config.otp_token_types = Some(vec![
        ty("DEFAULT", unix, "", false, &[]),
        ty("udp", udp, SECRET, true, &["typeind"]),
    ]);
    World {
        kdc: Kdc::new(config, store),
        log,
        _dir: dir,
    }
}

async fn run(
    kdc: &Kdc<MemoryStore>,
    config: AsExchangeConfig,
    password: &str,
) -> Result<Credential, Krb5Error> {
    let mut ex = AsExchange::new(config, password);
    let mut input = Vec::new();
    loop {
        match ex.step(&input)? {
            StepResult::SendToKdc { data, .. } | StepResult::RetryTcp { data, .. } => {
                input = kdc.handle(&data).await;
            }
            StepResult::Complete => return ex.credential().cloned(),
        }
    }
}

async fn otp_login(
    w: &World,
    value: &str,
    server: Option<PrincipalName>,
) -> Result<Credential, Krb5Error> {
    let armor = run(&w.kdc, AsExchangeConfig::new(name("armoruser"), REALM), PW)
        .await
        .expect("armor TGT");
    let mut cfg = AsExchangeConfig::new(name("user"), REALM);
    cfg.fast = FastMode::Required(armor);
    cfg.server = server;
    cfg.otp = Some(OtpAnswer {
        tokeninfo: 0,
        value: Some(value.into()),
        pin: None,
    });
    // A wrong password: only the OTP reply key (the armor key) can work.
    run(&w.kdc, cfg, "wrong-password").await
}

fn log(w: &World) -> Vec<(String, String)> {
    w.log.lock().unwrap().clone()
}

fn pair(u: &str, p: &str) -> (String, String) {
    (u.into(), p.into())
}

#[tokio::test]
async fn udp_token_logs_in_with_the_realm_stripped() {
    let w = world(r#"[{"type":"udp"}]"#, None).await;
    let cred = otp_login(&w, "accept", None).await.expect("OTP login");
    assert_eq!(cred.client, name("user"));
    assert_eq!(log(&w), vec![pair("user", "accept")]);
}

#[tokio::test]
async fn wrong_otp_is_preauth_failed() {
    let w = world(r#"[{"type":"udp"}]"#, None).await;
    match otp_login(&w, "reject", None).await {
        Err(Krb5Error::KdcError(m)) => assert_eq!(m.error_code, 24),
        other => panic!("expected PREAUTH_FAILED, got {other:?}"),
    }
    assert_eq!(log(&w), vec![pair("user", "reject")]);
}

#[tokio::test]
async fn default_token_type_uses_the_unix_socket_and_keeps_the_realm() {
    let w = world("[]", None).await;
    otp_login(&w, "accept", None).await.expect("OTP login");
    assert_eq!(log(&w), vec![pair("user@EXAMPLE.COM", "accept")]);
}

#[tokio::test]
async fn username_overrides_the_principal() {
    let w = world(r#"[{"type":"udp","username":"custom"}]"#, None).await;
    otp_login(&w, "accept", None).await.expect("OTP login");
    assert_eq!(log(&w), vec![pair("custom", "accept")]);
}

#[tokio::test]
async fn a_rejected_token_falls_back_to_the_next() {
    let w = world(
        r#"[{"type":"udp","username":"bad"},{"type":"udp","username":"good"}]"#,
        None,
    )
    .await;
    otp_login(&w, "accept", None).await.expect("OTP login");
    assert_eq!(log(&w), vec![pair("bad", "accept"), pair("good", "accept")]);
}

#[tokio::test]
async fn without_fast_no_otp_challenge_is_offered() {
    let w = world(r#"[{"type":"udp"}]"#, None).await;
    let mut cfg = AsExchangeConfig::new(name("user"), REALM);
    cfg.otp = Some(OtpAnswer {
        tokeninfo: 0,
        value: Some("accept".into()),
        pin: None,
    });
    assert!(run(&w.kdc, cfg, "wrong-password").await.is_err());
    assert!(log(&w).is_empty());
}

#[tokio::test]
async fn type_and_token_indicators_meet_require_auth() {
    let strong = || Some(PrincipalName::new_srv_inst("host", "strong"));
    let w = world(r#"[{"type":"udp"}]"#, Some("typeind")).await;
    otp_login(&w, "accept", strong())
        .await
        .expect("type indicator");
    let w = world(
        r#"[{"type":"udp","indicators":["tokind"]}]"#,
        Some("typeind"),
    )
    .await;
    assert!(otp_login(&w, "accept", strong()).await.is_err());
    let w = world(
        r#"[{"type":"udp","indicators":["tokind"]}]"#,
        Some("tokind"),
    )
    .await;
    otp_login(&w, "accept", strong())
        .await
        .expect("token indicator");
    let w = world("[]", Some("typeind")).await;
    assert!(otp_login(&w, "accept", strong()).await.is_err());
}
