#![cfg(all(feature = "kdc", feature = "tokio"))]
//! Primary-to-replica propagation (`KRB5RS-PROP-1`) in process over
//! 127.0.0.1: a primary FileStore with a KDC and a propagation server, and
//! replicas pulling into their own FileStore.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use krb5_rs::crypto::SaltType;
use krb5_rs::kdc::kdb::admin::{parse_principal, Admin, PrincipalOptions};
use krb5_rs::kdc::kdb::propagation::{
    initial_pull, pull_once, run_replica_loop, serve_propagation, PropClientConfig, PropError,
    PropEvent, PropSecret, PropServerConfig, PullOutcome,
};
use krb5_rs::kdc::kdb::{master_key_from_password, FileStore};
use krb5_rs::kdc::{serve_tcp, Kdc, KdcConfig};
use krb5_rs::keytab::{key_for_principal, FileKeytab, Keytab, KeytabEntry};
use krb5_rs::protocol::ap::{ApReqOptions, AuthContext, AuthContextFlags};
use krb5_rs::protocol::{
    AsExchange, AsExchangeConfig, Credential, StepResult, TgsExchange, TgsOptions, TgsStepResult,
};
use krb5_rs::transport::{KdcTransport, TcpTransport};
use krb5_rs::types::{EncryptionKey, HostAddress, KrbErrorMsg, PrincipalName};
use krb5_rs::Krb5Error;
use rasn::prelude::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;

const REALM: &str = "PROP.TEST";
const REPLICA: &str = "kprop/replica@PROP.TEST";

struct Dir(PathBuf);

impl Dir {
    fn new(tag: &str) -> Dir {
        let dir = std::env::temp_dir().join(format!("krb5rs_prop_{}_{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        Dir(dir)
    }

    fn join(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn master() -> EncryptionKey {
    master_key_from_password(REALM, "master-password", 18).expect("master key")
}

fn name(s: &str) -> PrincipalName {
    parse_principal(s, REALM).expect("principal").0
}

fn add(store: &FileStore, who: &str, password: Option<&str>, opts: &PrincipalOptions) {
    Admin::new(store, vec![(18, SaltType::Normal)])
        .add_principal(&name(who), REALM, password, opts)
        .expect("addprinc");
}

struct Env {
    dir: Dir,
    primary: Arc<FileStore>,
    kdc_addr: SocketAddr,
    prop_addr: SocketAddr,
    shutdown: watch::Sender<bool>,
    events: Arc<Mutex<Vec<PropEvent>>>,
    keytab: PathBuf,
}

impl Drop for Env {
    fn drop(&mut self) {
        let _ = self.shutdown.send(true);
    }
}

async fn start(tag: &str, acl: &[&str]) -> Env {
    let dir = Dir::new(tag);
    let primary = Arc::new(
        FileStore::create(&dir.join("primary.db"), REALM, &master()).expect("create database"),
    );
    let opts = PrincipalOptions::default();
    add(&primary, "kprop/primary", None, &opts);
    add(&primary, "kprop/replica", None, &opts);
    add(&primary, "alice", Some("alice-password"), &opts);

    let keytab = dir.join("replica.keytab");
    Admin::new(&primary, vec![(18, SaltType::Normal)])
        .ktadd(&name("kprop/replica"), REALM, &keytab, false)
        .expect("ktadd");

    let (shutdown, rx) = watch::channel(false);

    let kdc_store = primary.clone();
    let kdc = Arc::new(Kdc::new(KdcConfig::new(REALM), kdc_store));
    let kdc_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let kdc_addr = kdc_listener.local_addr().expect("addr");
    tokio::spawn(serve_tcp(kdc, kdc_listener));

    let events = Arc::new(Mutex::new(Vec::new()));
    let log = Arc::clone(&events);
    let mut config = PropServerConfig::new(
        name("kprop/primary"),
        acl.iter().map(ToString::to_string).collect(),
    );
    config.io_timeout = Duration::from_secs(5);
    config.logger = Some(Arc::new(move |e| log.lock().expect("lock").push(e.clone())));
    let prop_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let prop_addr = prop_listener.local_addr().expect("addr");
    tokio::spawn(serve_propagation(
        Arc::clone(&primary),
        config,
        prop_listener,
        Some(rx),
    ));

    Env {
        dir,
        primary,
        kdc_addr,
        prop_addr,
        shutdown,
        events,
        keytab,
    }
}

impl Env {
    fn replica_db(&self, tag: &str) -> PathBuf {
        self.dir.join(&format!("replica-{tag}.db"))
    }

    fn client(&self, tag: &str) -> PropClientConfig {
        PropClientConfig {
            realm: REALM.into(),
            primary: self.prop_addr.to_string(),
            kdc: self.kdc_addr.to_string(),
            client: name("kprop/replica"),
            service: name("kprop/primary"),
            secret: PropSecret::Keytab(self.keytab.clone()),
            db_path: self.replica_db(tag),
            master_key: master(),
            poll_interval: Duration::from_secs(2),
            io_timeout: Duration::from_secs(5),
            logger: None,
        }
    }

    /// Served events, waiting up to 2 s for at least `at_least` of them.
    async fn wait_served(&self, at_least: usize) -> Vec<(u64, u64, bool)> {
        for _ in 0..40 {
            if self.served().len() >= at_least {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        self.served()
    }

    fn served(&self) -> Vec<(u64, u64, bool)> {
        self.events
            .lock()
            .expect("lock")
            .iter()
            .filter_map(|e| match e {
                PropEvent::Served {
                    serial,
                    bytes,
                    acknowledged,
                    ..
                } => Some((*serial, *bytes, *acknowledged)),
                _ => None,
            })
            .collect()
    }

    fn refused(&self) -> Vec<String> {
        self.events
            .lock()
            .expect("lock")
            .iter()
            .filter_map(|e| match e {
                PropEvent::Refused { reason, .. } => Some(reason.clone()),
                _ => None,
            })
            .collect()
    }
}

/// An AS exchange against `addr` for `user`; returns the credential.
async fn login(addr: SocketAddr, user: &str, password: &str) -> Result<Credential, Krb5Error> {
    let kdc = TcpTransport::new(addr);
    let config = AsExchangeConfig::new(name(user), REALM);
    let mut exchange = AsExchange::new(config, password);
    let mut reply = Vec::new();
    loop {
        match exchange.step(&reply)? {
            StepResult::SendToKdc { data, realm } | StepResult::RetryTcp { data, realm } => {
                reply = kdc.send_recv(&realm, &data).await?;
            }
            StepResult::Complete => return exchange.credential().cloned(),
        }
    }
}

/// A KDC (on the replica's database) that answers over TCP.
async fn replica_kdc(db: &Path) -> SocketAddr {
    let store = FileStore::open(db, &master()).expect("replica database opens");
    let store = Arc::new(store);
    let kdc = Arc::new(Kdc::new(KdcConfig::new(REALM), store));
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(serve_tcp(kdc, listener));
    addr
}

fn code_of(e: &Krb5Error) -> i32 {
    match e {
        Krb5Error::KdcError(m) => m.error_code,
        other => panic!("expected a KDC error, got {other:?}"),
    }
}

// ------------------------------------------------------------ key-based AS

#[tokio::test]
async fn as_exchange_with_a_long_term_key_logs_in_against_our_kdc() {
    let env = start("withkey", &[REPLICA]).await;
    let mut opts = PrincipalOptions::default();
    opts.attributes.add_spec("+requires_preauth").expect("attr");
    add(&env.primary, "svc", None, &opts);
    let key = {
        let kt = env.dir.join("svc.keytab");
        Admin::new(&env.primary, vec![(18, SaltType::Normal)])
            .ktadd(&name("svc"), REALM, &kt, false)
            .expect("ktadd");
        key_for_principal(&FileKeytab::new(&kt), &name("svc"), REALM).expect("key")
    };
    let kdc = TcpTransport::new(env.kdc_addr);
    let run = |key: EncryptionKey| {
        let kdc = kdc.clone();
        async move {
            let mut exchange = AsExchange::with_key(AsExchangeConfig::new(name("svc"), REALM), key);
            let mut reply = Vec::new();
            loop {
                match exchange.step(&reply)? {
                    StepResult::SendToKdc { data, realm }
                    | StepResult::RetryTcp { data, realm } => {
                        reply = kdc.send_recv(&realm, &data).await?;
                    }
                    StepResult::Complete => return exchange.credential().cloned(),
                }
            }
        }
    };
    let cred = run(key.clone()).await.expect("login with the key");
    assert_eq!(cred.client, name("svc"));
    let mut wrong = key.clone();
    let mut bytes = wrong.key_bytes().to_vec();
    bytes[0] ^= 1;
    wrong = EncryptionKey::new(wrong.keytype, bytes);
    assert!(run(wrong).await.is_err());
}

// ------------------------------------------------------------------- pulls

#[tokio::test]
async fn first_sync_then_up_to_date_with_no_transfer() {
    let env = start("sync", &[REPLICA]).await;
    let cfg = env.client("a");
    let serial = env.primary.serial();
    assert_eq!(
        pull_once(&cfg).await.expect("first pull"),
        PullOutcome::Updated { serial }
    );
    assert_eq!(
        std::fs::read(&cfg.db_path).expect("replica"),
        std::fs::read(env.primary.path()).expect("primary")
    );
    assert_eq!(
        pull_once(&cfg).await.expect("second"),
        PullOutcome::UpToDate
    );
    let served = env.wait_served(2).await;
    assert_eq!(served.len(), 2, "{served:?}");
    assert!(served[0].1 > 0 && served[0].2);
    assert_eq!(served[1], (serial, 0, true));
}

#[tokio::test]
async fn a_primary_change_propagates_and_the_replica_kdc_issues_for_it() {
    let env = start("change", &[REPLICA]).await;
    let cfg = env.client("a");
    pull_once(&cfg).await.expect("first pull");
    let replica = replica_kdc(&cfg.db_path).await;
    login(replica, "alice", "alice-password")
        .await
        .expect("alice known");
    let err = login(replica, "bob", "bob-password")
        .await
        .expect_err("bob unknown");
    assert_eq!(code_of(&err), 6);

    add(
        &env.primary,
        "bob",
        Some("bob-password"),
        &PrincipalOptions::default(),
    );
    let serial = env.primary.serial();
    assert_eq!(
        pull_once(&cfg).await.expect("pull"),
        PullOutcome::Updated { serial }
    );
    // The replica KDC (same FileStore, reloading on change) now knows bob.
    let cred = login(replica, "bob", "bob-password")
        .await
        .expect("bob known");
    assert_eq!(cred.client, name("bob"));
}

#[tokio::test]
async fn a_database_of_several_blocks_transfers_intact() {
    let env = start("big", &[REPLICA]).await;
    let opts = PrincipalOptions {
        delegate_to: (0..500)
            .map(|i| format!("HTTP/host{i:04}.some-long-padding-name.example.com@{REALM}"))
            .collect(),
        ..PrincipalOptions::default()
    };
    for n in 0..4 {
        add(&env.primary, &format!("big{n}"), None, &opts);
    }
    let size = std::fs::metadata(env.primary.path()).expect("meta").len();
    assert!(size > 3 * 32 * 1024, "database is {size} bytes");
    let cfg = env.client("a");
    pull_once(&cfg).await.expect("pull");
    assert_eq!(
        std::fs::read(&cfg.db_path).expect("replica"),
        std::fs::read(env.primary.path()).expect("primary")
    );
    let served = env.wait_served(1).await;
    assert_eq!(served[0].1, size);
}

// ------------------------------------------------------------ rejections

#[tokio::test]
async fn an_unauthorized_client_principal_is_rejected() {
    let env = start("acl", &["kprop/someone-else@PROP.TEST"]).await;
    let cfg = env.client("a");
    match pull_once(&cfg).await {
        Err(PropError::Rejected { code, text }) => {
            assert_eq!(code, 12);
            assert_eq!(text, "UNAUTHORIZED");
        }
        other => panic!("expected a rejection, got {other:?}"),
    }
    assert!(!cfg.db_path.exists());
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(env.refused().iter().any(|r| r.contains("kprop_acl")));
}

#[tokio::test]
async fn a_wrong_client_key_fails_and_writes_nothing() {
    let env = start("wrongkey", &[REPLICA]).await;
    let mut cfg = env.client("a");
    let bad = env.dir.join("bad.keytab");
    let mut kt = FileKeytab::new(&bad);
    let good = key_for_principal(&FileKeytab::new(&env.keytab), &name("kprop/replica"), REALM)
        .expect("key");
    let mut bytes = good.key_bytes().to_vec();
    bytes[3] ^= 0x55;
    kt.add_entry(&KeytabEntry {
        principal: name("kprop/replica"),
        realm: REALM.into(),
        timestamp: 0,
        kvno: 1,
        key: EncryptionKey::new(good.keytype, bytes),
    })
    .expect("keytab");
    cfg.secret = PropSecret::Keytab(bad);
    let err = pull_once(&cfg).await.expect_err("must fail");
    assert!(matches!(err, PropError::Kerberos(_)), "{err:?}");
    assert!(!cfg.db_path.exists());
    assert!(env.served().is_empty());
}

#[tokio::test]
async fn the_password_file_secret_works_too() {
    let env = start("pwfile", &[REPLICA]).await;
    // A replica principal with a known password.
    add(
        &env.primary,
        "kprop/pwreplica",
        Some("replica-password"),
        &PrincipalOptions::default(),
    );
    let mut cfg = env.client("a");
    cfg.client = name("kprop/pwreplica");
    let file = env.dir.join("pw");
    std::fs::write(&file, "replica-password\n").expect("write");
    cfg.secret = PropSecret::PasswordFile(file);
    // Not on the ACL yet.
    assert!(matches!(
        pull_once(&cfg).await,
        Err(PropError::Rejected { code: 12, .. })
    ));
    drop(env);

    let env = start("pwfile2", &["kprop/pwreplica@PROP.TEST"]).await;
    add(
        &env.primary,
        "kprop/pwreplica",
        Some("replica-password"),
        &PrincipalOptions::default(),
    );
    let mut cfg = env.client("a");
    cfg.client = name("kprop/pwreplica");
    let file = env.dir.join("pw");
    std::fs::write(&file, "replica-password\r\n").expect("write");
    cfg.secret = PropSecret::PasswordFile(file);
    assert!(matches!(
        pull_once(&cfg).await.expect("pull"),
        PullOutcome::Updated { .. }
    ));
}

#[tokio::test]
async fn a_replica_with_the_wrong_master_key_rejects_the_database_and_keeps_the_old_one() {
    let env = start("master", &[REPLICA]).await;
    let cfg = env.client("a");
    pull_once(&cfg).await.expect("first pull");
    let before = std::fs::read(&cfg.db_path).expect("replica");
    add(
        &env.primary,
        "carol",
        Some("pw"),
        &PrincipalOptions::default(),
    );

    let mut wrong = env.client("a");
    wrong.master_key = master_key_from_password(REALM, "some-other-master", 18).expect("key");
    let err = pull_once(&wrong).await.expect_err("must reject");
    assert!(matches!(err, PropError::Validation(_)), "{err:?}");
    assert_eq!(std::fs::read(&cfg.db_path).expect("replica"), before);
    assert!(!PathBuf::from(format!("{}.prop", cfg.db_path.display())).exists());
    // The primary saw a failed install.
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(env.served().iter().any(|(_, _, ack)| !ack));
}

// --------------------------------------------------- an interposed proxy

type Mutator = Arc<dyn Fn(usize, &mut Vec<u8>) + Send + Sync>;

/// A TCP proxy that forwards client to server untouched and passes each
/// length-prefixed frame from the server through `mutate(index, frame)`.
async fn proxy(target: SocketAddr, mutate: Mutator) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        loop {
            let Ok((client, _)) = listener.accept().await else {
                return;
            };
            let mutate = Arc::clone(&mutate);
            tokio::spawn(async move {
                let Ok(server) = TcpStream::connect(target).await else {
                    return;
                };
                let (mut cr, mut cw) = client.into_split();
                let (mut sr, mut sw) = server.into_split();
                tokio::spawn(async move {
                    let _ = tokio::io::copy(&mut cr, &mut sw).await;
                    let _ = sw.shutdown().await;
                });
                let mut index = 0usize;
                loop {
                    let mut len = [0u8; 4];
                    if sr.read_exact(&mut len).await.is_err() {
                        break;
                    }
                    let mut frame = vec![0u8; u32::from_be_bytes(len) as usize];
                    if sr.read_exact(&mut frame).await.is_err() {
                        break;
                    }
                    mutate(index, &mut frame);
                    index += 1;
                    let mut out = (frame.len() as u32).to_be_bytes().to_vec();
                    out.extend_from_slice(&frame);
                    if cw.write_all(&out).await.is_err() {
                        break;
                    }
                }
                let _ = cw.shutdown().await;
            });
        }
    });
    addr
}

fn flip_middle(frame: &mut [u8]) {
    let at = frame.len() / 2;
    frame[at] ^= 0x40;
}

#[tokio::test]
async fn a_tampered_krb_priv_frame_is_rejected_and_no_database_is_installed() {
    let env = start("tamper", &[REPLICA]).await;
    // Server frames: 0 AP-REP, 1 KRB-SAFE reply, 2.. KRB-PRIV blocks.
    let addr = proxy(
        env.prop_addr,
        Arc::new(|i, f| {
            if i == 3 {
                flip_middle(f);
            }
        }),
    )
    .await;
    let mut cfg = env.client("a");
    cfg.primary = addr.to_string();
    let opts = PrincipalOptions {
        delegate_to: (0..400)
            .map(|i| format!("HTTP/h{i:04}.padding-padding-padding.example.com@{REALM}"))
            .collect(),
        ..PrincipalOptions::default()
    };
    for n in 0..3 {
        add(&env.primary, &format!("pad{n}"), None, &opts);
    }
    let err = pull_once(&cfg).await.expect_err("tampering is detected");
    assert!(matches!(err, PropError::Kerberos(_)), "{err:?}");
    assert!(!cfg.db_path.exists());
    assert!(!PathBuf::from(format!("{}.prop", cfg.db_path.display())).exists());
}

#[tokio::test]
async fn a_tampered_reply_or_forged_ap_rep_is_rejected() {
    let env = start("forge", &[REPLICA]).await;
    for (index, what) in [(0usize, "AP-REP"), (1, "KRB-SAFE reply")] {
        let addr = proxy(
            env.prop_addr,
            Arc::new(move |i, f| {
                if i == index {
                    flip_middle(f);
                }
            }),
        )
        .await;
        let mut cfg = env.client(what);
        cfg.primary = addr.to_string();
        let err = pull_once(&cfg).await.expect_err(what);
        assert!(matches!(err, PropError::Kerberos(_)), "{what}: {err:?}");
        assert!(!cfg.db_path.exists());
    }
    // A completely forged AP-REP (right tag, garbage inside).
    let addr = proxy(
        env.prop_addr,
        Arc::new(|i, f| {
            if i == 0 {
                *f = vec![0x6F, 0x03, 0x02, 0x01, 0x05];
            }
        }),
    )
    .await;
    let mut cfg = env.client("forged");
    cfg.primary = addr.to_string();
    assert!(pull_once(&cfg).await.is_err());
    assert!(!cfg.db_path.exists());
}

// ------------------------------------------- raw protocol-level server tests

#[derive(AsnType, Encode, Decode)]
struct RawRequest {
    #[rasn(tag(explicit(context, 0)))]
    realm: GeneralString,
    #[rasn(tag(explicit(context, 1)))]
    have_serial: Option<u64>,
}

async fn raw_write(s: &mut TcpStream, data: &[u8]) {
    let mut out = (data.len() as u32).to_be_bytes().to_vec();
    out.extend_from_slice(data);
    s.write_all(&out).await.expect("write");
}

async fn raw_read(s: &mut TcpStream) -> Vec<u8> {
    let mut len = [0u8; 4];
    s.read_exact(&mut len).await.expect("read length");
    let mut data = vec![0u8; u32::from_be_bytes(len) as usize];
    s.read_exact(&mut data).await.expect("read frame");
    data
}

fn error_code(frame: &[u8]) -> i32 {
    assert_eq!(frame[0], 0x7E, "expected a KRB-ERROR");
    rasn::der::decode::<KrbErrorMsg>(frame)
        .expect("KRB-ERROR")
        .error_code
}

async fn service_credential(env: &Env) -> Credential {
    let key = key_for_principal(&FileKeytab::new(&env.keytab), &name("kprop/replica"), REALM)
        .expect("key");
    let kdc = TcpTransport::new(env.kdc_addr);
    let mut as_ex = AsExchange::with_key(AsExchangeConfig::new(name("kprop/replica"), REALM), key);
    let mut reply = Vec::new();
    let tgt = loop {
        match as_ex.step(&reply).expect("AS") {
            StepResult::SendToKdc { data, realm } | StepResult::RetryTcp { data, realm } => {
                reply = kdc.send_recv(&realm, &data).await.expect("KDC");
            }
            StepResult::Complete => break as_ex.credential().expect("TGT").clone(),
        }
    };
    let mut tgs = TgsExchange::new(tgt, name("kprop/primary"), TgsOptions::default());
    let mut reply = Vec::new();
    loop {
        match tgs.step(&reply).expect("TGS") {
            TgsStepResult::SendToKdc { data, realm } | TgsStepResult::RetryTcp { data, realm } => {
                reply = kdc.send_recv(&realm, &data).await.expect("KDC");
            }
            TgsStepResult::Complete => return tgs.credential().expect("ticket").clone(),
        }
    }
}

fn raw_context() -> AuthContext {
    let mut ctx = AuthContext::new();
    ctx.set_flags(
        AuthContextFlags::DO_TIME | AuthContextFlags::DO_SEQUENCE | AuthContextFlags::USE_SUBKEY,
    );
    let any = HostAddress {
        addr_type: 2,
        address: vec![0, 0, 0, 0].into(),
    };
    ctx.set_addrs(Some(any.clone()), Some(any));
    ctx
}

fn ap_req(ctx: &mut AuthContext, cred: &Credential) -> Vec<u8> {
    ctx.mk_req(
        &ApReqOptions {
            mutual_required: true,
            use_subkey: true,
            ..ApReqOptions::default()
        },
        None,
        cred,
    )
    .expect("AP-REQ")
}

#[tokio::test]
async fn protocol_violations_get_kerberos_errors() {
    let env = start("raw", &[REPLICA]).await;

    // Unknown version string.
    let mut s = TcpStream::connect(env.prop_addr).await.expect("connect");
    raw_write(&mut s, b"KRB5RS-PROP-9").await;
    assert_eq!(error_code(&raw_read(&mut s).await), 39);

    // Garbage instead of an AP-REQ.
    let mut s = TcpStream::connect(env.prop_addr).await.expect("connect");
    raw_write(&mut s, b"KRB5RS-PROP-1").await;
    raw_write(&mut s, &[1, 2, 3]).await;
    assert_eq!(error_code(&raw_read(&mut s).await), 40);

    // A frame larger than the limit ends the connection.
    let mut s = TcpStream::connect(env.prop_addr).await.expect("connect");
    s.write_all(&(2u32 * 1024 * 1024).to_be_bytes())
        .await
        .expect("write");
    let mut rest = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(3), s.read_to_end(&mut rest)).await;
    assert!(rest.is_empty());

    // A realm the primary does not serve, after a valid authentication.
    let cred = service_credential(&env).await;
    let mut ctx = raw_context();
    let mut s = TcpStream::connect(env.prop_addr).await.expect("connect");
    raw_write(&mut s, b"KRB5RS-PROP-1").await;
    raw_write(&mut s, &ap_req(&mut ctx, &cred)).await;
    ctx.rd_rep(&raw_read(&mut s).await).expect("mutual auth");
    let request = rasn::der::encode(&RawRequest {
        realm: GeneralString::from_bytes(b"OTHER.REALM").expect("realm"),
        have_serial: None,
    })
    .expect("encode");
    let (safe, _) = ctx.mk_safe(&request).expect("safe");
    raw_write(&mut s, &safe).await;
    assert_eq!(error_code(&raw_read(&mut s).await), 68);
    assert!(
        env.refused().iter().any(|r| r.contains("OTHER.REALM")) || {
            tokio::time::sleep(Duration::from_millis(200)).await;
            env.refused().iter().any(|r| r.contains("OTHER.REALM"))
        }
    );
}

#[tokio::test]
async fn a_replayed_ap_req_is_rejected_by_the_servers_replay_cache() {
    let env = start("replay", &[REPLICA]).await;
    let cred = service_credential(&env).await;
    let mut ctx = raw_context();
    let request = ap_req(&mut ctx, &cred);

    let mut first = TcpStream::connect(env.prop_addr).await.expect("connect");
    raw_write(&mut first, b"KRB5RS-PROP-1").await;
    raw_write(&mut first, &request).await;
    assert_eq!(raw_read(&mut first).await[0], 0x6F, "first use is accepted");

    let mut second = TcpStream::connect(env.prop_addr).await.expect("connect");
    raw_write(&mut second, b"KRB5RS-PROP-1").await;
    raw_write(&mut second, &request).await;
    assert_eq!(error_code(&raw_read(&mut second).await), 34);
}

// ----------------------------------------------------------- availability

#[tokio::test]
async fn with_the_primary_down_the_replica_keeps_serving_and_backs_off() {
    let env = start("down", &[REPLICA]).await;
    let mut cfg = env.client("a");
    pull_once(&cfg).await.expect("first pull");
    let replica = replica_kdc(&cfg.db_path).await;

    // Point at a port nothing listens on.
    let dead = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    cfg.primary = dead.local_addr().expect("addr").to_string();
    drop(dead);
    assert!(matches!(
        pull_once(&cfg).await,
        Err(PropError::Io(_) | PropError::Kerberos(_))
    ));

    let events = Arc::new(Mutex::new(Vec::new()));
    let log = Arc::clone(&events);
    cfg.poll_interval = Duration::from_secs(3);
    cfg.logger = Some(Arc::new(move |e| log.lock().expect("lock").push(e.clone())));
    let (tx, rx) = watch::channel(false);
    let looped = tokio::spawn(run_replica_loop(cfg.clone(), rx));
    // The old database serves meanwhile.
    login(replica, "alice", "alice-password")
        .await
        .expect("replica still serves");
    tokio::time::sleep(Duration::from_millis(3600)).await;
    tx.send(true).expect("signal");
    tokio::time::timeout(Duration::from_secs(5), looped)
        .await
        .expect("loop stops")
        .expect("join");
    let delays: Vec<Duration> = events
        .lock()
        .expect("lock")
        .iter()
        .filter_map(|e| match e {
            PropEvent::PullFailed { retry_in, .. } => Some(*retry_in),
            _ => None,
        })
        .collect();
    assert!(delays.len() >= 2, "{delays:?}");
    assert_eq!(delays[0], Duration::from_secs(1));
    assert_eq!(delays[1], Duration::from_secs(2));
}

#[tokio::test]
async fn the_replica_loop_picks_up_primary_changes_and_initial_pull_waits_for_the_primary() {
    let env = start("loop", &[REPLICA]).await;
    let mut cfg = env.client("a");
    cfg.poll_interval = Duration::from_secs(1);

    // initial_pull retries until the primary answers.
    let mut dead_cfg = cfg.clone();
    let dead = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let dead_addr = dead.local_addr().expect("addr");
    drop(dead);
    dead_cfg.primary = dead_addr.to_string();
    let (_tx0, mut rx0) = watch::channel(false);
    let waiting = tokio::spawn(async move { initial_pull(&dead_cfg, &mut rx0).await });
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(!waiting.is_finished());
    waiting.abort();

    let (_tx1, mut rx1) = watch::channel(false);
    assert!(matches!(
        initial_pull(&cfg, &mut rx1).await,
        Some(PullOutcome::Updated { .. })
    ));

    let (tx, rx) = watch::channel(false);
    let looped = tokio::spawn(run_replica_loop(cfg.clone(), rx));
    let replica = replica_kdc(&cfg.db_path).await;
    add(
        &env.primary,
        "dave",
        Some("dave-pw"),
        &PrincipalOptions::default(),
    );
    let mut ok = false;
    for _ in 0..40 {
        if login(replica, "dave", "dave-pw").await.is_ok() {
            ok = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    assert!(ok, "replica never picked up the new principal");
    tx.send(true).expect("signal");
    tokio::time::timeout(Duration::from_secs(5), looped)
        .await
        .expect("loop stops")
        .expect("join");
}

#[tokio::test]
async fn the_server_stops_on_shutdown() {
    let env = start("shutdown", &[REPLICA]).await;
    env.shutdown.send(true).expect("signal");
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(TcpStream::connect(env.prop_addr).await.is_err());
}
