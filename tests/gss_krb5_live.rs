#![cfg(feature = "client")]
//! Live interop tests: krb5-rs GSS-API (RFC 4121) against MIT's
//! libgssapi_krb5 via the python3-gssapi oracle (tests/kdc/gss_oracle.py).
//!
//! Requires the KDC + oracle containers:
//!   docker compose -f docker-compose.test.yml up -d
//! Run with:
//!   cargo test --features client --test gss_krb5_live -- --ignored
//!
//! `KDC_HOST` overrides the KDC host (default 127.0.0.1, port 10188);
//! `GSS_ORACLE_ADDR` overrides the oracle (default 127.0.0.1:10189).
//! One GSS context per TCP connection.

use std::net::SocketAddr;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use krb5_rs::client::KerberosClient;
use krb5_rs::crypto::find_etype;
use krb5_rs::gssapi::krb5::{
    AcceptStep, ChannelBindings, GssFlags, InitStep, Krb5Acceptor, Krb5Initiator,
};
use krb5_rs::gssapi::seqstate::SeqStatus;
use krb5_rs::gssapi::GssError;
use krb5_rs::protocol::ap::{ApError, KeySource};
use krb5_rs::protocol::Credential;
use krb5_rs::types::{EncryptionKey, PrincipalName};
use krb5_rs::Krb5Error;

const REALM: &str = "TEST.REALM";
const SERVICE: &str = "HTTP/server.test.realm";
const HTTP_PASSWORD: &str = "httpsecret";
/// Service salt = realm + principal components joined with no separator
/// (MIT default: realm || principal name, kadmin "normal" keysalts).
const HTTP_SALT: &str = "TEST.REALMHTTPserver.test.realm";

fn kdc_addr() -> SocketAddr {
    let host = std::env::var("KDC_HOST").unwrap_or_else(|_| "127.0.0.1".into());
    format!("{host}:10188").parse().expect("parse KDC address")
}

fn oracle_addr() -> SocketAddr {
    std::env::var("GSS_ORACLE_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:10189".into())
        .parse()
        .expect("parse oracle address")
}

fn service() -> PrincipalName {
    PrincipalName::new_srv_hst("HTTP", "server.test.realm")
}

fn krbtgt() -> PrincipalName {
    PrincipalName::new_srv_inst("krbtgt", REALM)
}

fn testuser() -> PrincipalName {
    PrincipalName::new_principal("testuser")
}

/// Service-key keytab equivalent: derive the HTTP key with string-to-key
/// (setup.sh uses `addprinc ... -norandkey`, kvno 1).
struct HttpKeys;
impl KeySource for HttpKeys {
    fn get_key(
        &self,
        _server: &PrincipalName,
        _realm: &[u8],
        kvno: Option<i32>,
        etype: i32,
    ) -> Result<EncryptionKey, ApError> {
        if kvno != Some(1) {
            return Err(ApError::BadKeyver);
        }
        let profile = find_etype(etype).map_err(|_| ApError::NoKey)?;
        let kb = profile
            .string_to_key(HTTP_PASSWORD.as_bytes(), HTTP_SALT.as_bytes(), None)
            .map_err(|_| ApError::NoKey)?;
        Ok(EncryptionKey::new(etype, kb.to_vec()))
    }
}

/// Fresh service ticket + forwardable TGT for testuser via the real KDC.
async fn creds() -> (Credential, Credential) {
    let transport = krb5_rs::transport::TcpTransport::new(kdc_addr());
    let client = KerberosClient::new(REALM, transport);
    let tgt = client
        .acquire_tgt("testuser", "testpassword")
        .await
        .expect("TGT");
    let svc = client
        .get_service_ticket(&tgt, SERVICE)
        .await
        .expect("service ticket");
    (svc, tgt)
}

/// One oracle connection == one GSS context.
struct Oracle(TcpStream);

impl Oracle {
    async fn connect() -> Self {
        let s = TcpStream::connect(oracle_addr())
            .await
            .expect("oracle connect");
        Oracle(s)
    }

    async fn send(&mut self, payload: &[u8]) -> Vec<u8> {
        let n = payload.len() as u32;
        self.0.write_all(&n.to_be_bytes()).await.expect("write len");
        self.0.write_all(payload).await.expect("write");
        let mut len = [0u8; 4];
        self.0.read_exact(&mut len).await.expect("read len");
        let n = u32::from_be_bytes(len) as usize;
        let mut buf = vec![0u8; n];
        self.0.read_exact(&mut buf).await.expect("read");
        buf
    }

    /// Split a context-step reply: status, u32be token len, token, JSON.
    /// "E" replies carry no token field — just the error text.
    fn ctx_reply(reply: &[u8]) -> (u8, Vec<u8>, String) {
        let status = reply[0];
        if status != b'C' && status != b'N' {
            return (
                status,
                Vec::new(),
                String::from_utf8_lossy(&reply[1..]).into_owned(),
            );
        }
        let n = u32::from_be_bytes(reply[1..5].try_into().unwrap()) as usize;
        let token = reply[5..5 + n].to_vec();
        let json = String::from_utf8_lossy(&reply[5 + n..]).into_owned();
        (status, token, json)
    }

    /// "A" token — accept step (MIT accepts our AP-REQ).
    async fn accept(&mut self, token: &[u8]) -> (u8, Vec<u8>, String) {
        let mut p = vec![b'A'];
        p.extend_from_slice(token);
        Self::ctx_reply(&self.send(&p).await)
    }

    /// "B" appdata token — accept step with channel bindings.
    async fn accept_cb(&mut self, appdata: &[u8], token: &[u8]) -> (u8, Vec<u8>, String) {
        let mut p = vec![b'B'];
        p.extend_from_slice(&(appdata.len() as u32).to_be_bytes());
        p.extend_from_slice(appdata);
        p.extend_from_slice(token);
        Self::ctx_reply(&self.send(&p).await)
    }

    /// "I" flagbyte — MIT initiates.
    async fn init_start(&mut self, flagbyte: u8) -> (u8, Vec<u8>, String) {
        Self::ctx_reply(&self.send(&[b'I', flagbyte]).await)
    }

    /// "R" token — feed our acceptor reply into MIT's initiator.
    async fn init_step(&mut self, token: &[u8]) -> (u8, Vec<u8>, String) {
        let mut p = vec![b'R'];
        p.extend_from_slice(token);
        Self::ctx_reply(&self.send(&p).await)
    }

    /// "W"/"P" data — MIT wraps; returns the token.
    async fn wrap(&mut self, data: &[u8], conf: bool) -> Vec<u8> {
        let mut p = vec![if conf { b'W' } else { b'P' }];
        p.extend_from_slice(data);
        let r = self.send(&p).await;
        assert_eq!(r[0], b'C', "oracle wrap failed: {:?}", r);
        r[1..].to_vec()
    }

    /// "U" token — MIT unwraps; returns confbyte + data.
    async fn unwrap(&mut self, token: &[u8]) -> (u8, Vec<u8>) {
        let mut p = vec![b'U'];
        p.extend_from_slice(token);
        let r = self.send(&p).await;
        assert_eq!(r[0], b'C', "oracle unwrap failed: {:?}", r);
        (r[1], r[2..].to_vec())
    }

    /// "M" data — MIT get_mic.
    async fn get_mic(&mut self, data: &[u8]) -> Vec<u8> {
        let mut p = vec![b'M'];
        p.extend_from_slice(data);
        let r = self.send(&p).await;
        assert_eq!(r[0], b'C', "oracle mic failed: {:?}", r);
        r[1..].to_vec()
    }

    /// "V" data mic — MIT verify_mic; true = accepted.
    async fn verify_mic(&mut self, data: &[u8], mic: &[u8]) -> bool {
        let mut p = vec![b'V'];
        p.extend_from_slice(&(data.len() as u32).to_be_bytes());
        p.extend_from_slice(data);
        p.extend_from_slice(mic);
        self.send(&p).await[0] == b'C'
    }
}

/// Extract a JSON string field's value (flat oracle JSON, no escaping).
fn json_str<'a>(json: &'a str, key: &str) -> Option<&'a str> {
    let pat = format!("\"{key}\": \"");
    let start = json.find(&pat)? + pat.len();
    let end = json[start..].find('"')? + start;
    Some(&json[start..end])
}

fn json_int(json: &str, key: &str) -> Option<u32> {
    let pat = format!("\"{key}\": ");
    let start = json.find(&pat)? + pat.len();
    let end = json[start..]
        .find(|c: char| !(c.is_ascii_digit() || c == '-'))
        .map(|i| i + start)
        .unwrap_or(json.len());
    json[start..end].parse().ok()
}

fn unwrap_step(s: InitStep) -> Option<Vec<u8>> {
    match s {
        InitStep::Complete(t) => t,
        InitStep::Continue(t) => Some(t),
    }
}

fn init_complete(s: InitStep) -> Option<Vec<u8>> {
    match s {
        InitStep::Complete(t) => t,
        _ => panic!("expected Complete"),
    }
}

fn accept_complete(s: AcceptStep) -> Option<Vec<u8>> {
    match s {
        AcceptStep::Complete { token } => token,
        _ => panic!("expected Complete"),
    }
}

/// (a) Rust initiator → MIT acceptor, non-mutual.
#[tokio::test]
#[ignore = "requires KDC + oracle: docker compose -f docker-compose.test.yml up -d"]
async fn rust_init_mit_accept_non_mutual() {
    let (svc, _tgt) = creds().await;
    let mut init =
        Krb5Initiator::new(svc, None, GssFlags::REPLAY | GssFlags::SEQUENCE, None).expect("new");
    let token = init_complete(init.step(None).expect("step")).expect("token");
    let mut ic = init.context().expect("init ctx");

    let mut orc = Oracle::connect().await;
    let (status, out, json) = orc.accept(&token).await;
    assert_eq!(status, b'C', "MIT rejected our AP-REQ: {json}");
    assert!(out.is_empty(), "non-mutual accept emits no token");
    let flags = json_int(&json, "flags").expect("flags");
    for (bit, name) in [
        (0x10, "conf"),
        (0x20, "integ"),
        (0x4, "replay"),
        (0x8, "sequence"),
    ] {
        assert!(flags & bit != 0, "MIT flags {flags:#x} lack {name}");
    }
    assert_eq!(json_str(&json, "src"), Some("testuser@TEST.REALM"));

    // Rust → MIT per-message ops.
    let t = ic.wrap(true, b"hi").expect("wrap");
    let (conf, data) = orc.unwrap(&t).await;
    assert_eq!(conf, 1);
    assert_eq!(data, b"hi");

    let t = ic.wrap(false, b"plain").expect("wrap integ");
    let (conf, data) = orc.unwrap(&t).await;
    assert_eq!(conf, 0);
    assert_eq!(data, b"plain");

    let mic = ic.get_mic(b"msg").expect("mic");
    assert!(orc.verify_mic(b"msg", &mic).await, "MIT rejected our MIC");

    // MIT → Rust.
    let t = orc.wrap(b"from-mit", true).await;
    let r = ic.unwrap(&t).expect("unwrap");
    assert_eq!(r.data, b"from-mit");
    assert!(r.conf);
    assert_eq!(r.seq, SeqStatus::Complete);

    let mic = orc.get_mic(b"mm").await;
    assert_eq!(
        ic.verify_mic(b"mm", &mic).expect("verify"),
        SeqStatus::Complete
    );
    let mut bad = mic.clone();
    *bad.last_mut().expect("mic") ^= 0xff;
    assert!(matches!(
        ic.verify_mic(b"mm", &bad),
        Err(Krb5Error::Gss(GssError::BadSig))
    ));

    // Replaying MIT's wrap token into our unwrap → Duplicate (REPLAY on).
    let r = ic.unwrap(&t).expect("dup unwrap still returns data");
    assert_eq!(r.seq, SeqStatus::Duplicate);
}

/// (b) Rust initiator → MIT acceptor, mutual + delegation.
#[tokio::test]
#[ignore = "requires KDC + oracle: docker compose -f docker-compose.test.yml up -d"]
async fn rust_init_mit_accept_mutual_deleg() {
    let (svc, tgt) = creds().await;
    let mut init = Krb5Initiator::new(
        svc,
        Some(tgt),
        GssFlags::MUTUAL | GssFlags::DELEG | GssFlags::REPLAY | GssFlags::SEQUENCE,
        None,
    )
    .expect("new");
    let token = unwrap_step(init.step(None).expect("step")).expect("token");

    let mut orc = Oracle::connect().await;
    let (status, rep, json) = orc.accept(&token).await;
    assert_eq!(status, b'C', "MIT rejected our AP-REQ: {json}");
    assert!(!rep.is_empty(), "mutual accept emits AP-REP");
    assert_eq!(
        json_str(&json, "deleg_name"),
        Some("testuser@TEST.REALM"),
        "deleg_name in {json}"
    );

    assert!(init_complete(init.step(Some(&rep)).expect("step2")).is_none());
    let mut ic = init.context().expect("init ctx");

    // Both directions wrap/unwrap + MIC; both sides' wrap tokens must
    // carry the acceptor-subkey flag (proto==1 → MIT always generates).
    let t = ic.wrap(true, b"to-mit").expect("wrap");
    assert!(t[2] & 0x04 != 0, "our wrap lacks acceptor-subkey flag");
    let (conf, data) = orc.unwrap(&t).await;
    assert_eq!(conf, 1);
    assert_eq!(data, b"to-mit");

    let t = orc.wrap(b"from-mit", true).await;
    assert!(t[2] & 0x04 != 0, "MIT wrap lacks acceptor-subkey flag");
    let r = ic.unwrap(&t).expect("unwrap");
    assert_eq!(r.data, b"from-mit");
    assert!(r.conf);

    let mic = ic.get_mic(b"m1").expect("mic");
    assert!(orc.verify_mic(b"m1", &mic).await);
    let mic = orc.get_mic(b"m2").await;
    ic.verify_mic(b"m2", &mic).expect("verify");
}

/// (c) Rust initiator channel bindings.
#[tokio::test]
#[ignore = "requires KDC + oracle: docker compose -f docker-compose.test.yml up -d"]
async fn rust_init_channel_bindings() {
    // Matching bindings → complete + channel-bound flag.
    let (svc, _tgt) = creds().await;
    let cb = |d: &[u8]| ChannelBindings {
        initiator_addrtype: 0,
        initiator_address: Vec::new(),
        acceptor_addrtype: 0,
        acceptor_address: Vec::new(),
        application_data: d.to_vec(),
    };
    let mut init =
        Krb5Initiator::new(svc.clone(), None, GssFlags::empty(), Some(cb(b"abc"))).expect("new");
    let token = init_complete(init.step(None).expect("step")).expect("token");
    let mut orc = Oracle::connect().await;
    let (status, _out, json) = orc.accept_cb(b"abc", &token).await;
    assert_eq!(status, b'C', "{json}");
    let flags = json_int(&json, "flags").expect("flags");
    assert!(flags & 0x800 != 0, "channel-bound not reported: {flags:#x}");

    // CHANNEL_BOUND requested, bindings differ → MIT: bad bindings.
    let mut init = Krb5Initiator::new(svc.clone(), None, GssFlags::CHANNEL_BOUND, Some(cb(b"abc")))
        .expect("new");
    let token = init_complete(init.step(None).expect("step")).expect("token");
    let mut orc = Oracle::connect().await;
    let (status, _out, json) = orc.accept_cb(b"xyz", &token).await;
    assert_eq!(status, b'E', "expected bad-bindings error: {json}");

    // Initiator without bindings, acceptor with bindings → MIT accepts
    // (accept_sec_context.c:541-546: absent initiator cb isn't a mismatch).
    let mut init = Krb5Initiator::new(svc, None, GssFlags::empty(), None).expect("new");
    let token = init_complete(init.step(None).expect("step")).expect("token");
    let mut orc = Oracle::connect().await;
    let (status, _out, json) = orc.accept_cb(b"abc", &token).await;
    assert_eq!(status, b'C', "{json}");
}

/// (d) MIT initiator → Rust acceptor.
#[tokio::test]
#[ignore = "requires KDC + oracle: docker compose -f docker-compose.test.yml up -d"]
async fn mit_init_rust_accept() {
    let mut orc = Oracle::connect().await;
    let (status, token, json) = orc.init_start(0).await;
    assert_eq!(status, b'N', "MIT should need continue: {json}");

    let mut acc = Krb5Acceptor::new(Box::new(HttpKeys), Some(service()), None);
    // MIT always requests mutual → AP-REP.
    let rep = accept_complete(acc.step(&token).expect("accept")).expect("ap-rep");
    let (status, _out, json) = orc.init_step(&rep).await;
    assert_eq!(status, b'C', "MIT init rejected our AP-REP: {json}");

    let mut ctx = acc.context().expect("ctx");
    assert_eq!(ctx.initiator(), &testuser());
    assert_eq!(ctx.initiator_realm(), REALM);
    assert!(ctx.flags().contains(GssFlags::MUTUAL));

    // Rust → MIT.
    let t = ctx.wrap(true, b"to-mit").expect("wrap");
    assert!(
        t[2] & 0x04 != 0,
        "acceptor wrap must carry acceptor-subkey flag"
    );
    let (conf, data) = orc.unwrap(&t).await;
    assert_eq!(conf, 1);
    assert_eq!(data, b"to-mit");

    // MIT → Rust.
    let t = orc.wrap(b"from-mit", true).await;
    let r = ctx.unwrap(&t).expect("unwrap");
    assert_eq!(r.data, b"from-mit");
    assert!(r.conf);

    let mic = ctx.get_mic(b"m1").expect("mic");
    assert!(orc.verify_mic(b"m1", &mic).await);
    let mic = orc.get_mic(b"m2").await;
    ctx.verify_mic(b"m2", &mic).expect("verify");
}

/// (e) MIT initiator delegates → Rust acceptor stores the credential.
#[tokio::test]
#[ignore = "requires KDC + oracle: docker compose -f docker-compose.test.yml up -d"]
async fn mit_init_rust_accept_deleg() {
    let mut orc = Oracle::connect().await;
    let (status, token, json) = orc.init_start(1).await;
    assert_eq!(status, b'N', "{json}");

    let mut acc = Krb5Acceptor::new(Box::new(HttpKeys), Some(service()), None);
    let rep = accept_complete(acc.step(&token).expect("accept")).expect("ap-rep");
    let (status, _out, json) = orc.init_step(&rep).await;
    assert_eq!(status, b'C', "{json}");

    let creds = acc.delegated_creds().expect("delegated creds");
    assert_eq!(creds.len(), 1);
    assert_eq!(creds[0].client, testuser());
    // MIT forwards its TGT: sname krbtgt/TEST.REALM.
    assert_eq!(creds[0].server, krbtgt());
    assert!(acc
        .context()
        .expect("ctx")
        .flags()
        .contains(GssFlags::DELEG));
}

/// (f) MIT initiator asserts CHANNEL_BOUND with no bindings of its own.
///
/// Verified against the wire: python-gssapi does not forward the
/// non-standard GSS_C_CHANNEL_BOUND_FLAG (0x800) into gss_init_sec_context,
/// so MIT's AP-REQ carries a zero cb hash *and no AP_OPTIONS CBT authdata*
/// (decoded the live token: authorization_data is absent).  MIT acceptor
/// semantics (accept_sec_context.c:541-546 + check_cbt :424-449): absent
/// initiator bindings are not a mismatch and no CBT marker means check_cbt
/// passes → plain accept, no CHANNEL_BOUND flag.  Assert exactly that.
#[tokio::test]
#[ignore = "requires KDC + oracle: docker compose -f docker-compose.test.yml up -d"]
async fn mit_init_rust_accept_channel_bound() {
    let mut orc = Oracle::connect().await;
    let (status, token, _json) = orc.init_start(4).await;
    assert_eq!(status, b'N');

    let cb = ChannelBindings {
        initiator_addrtype: 0,
        initiator_address: Vec::new(),
        acceptor_addrtype: 0,
        acceptor_address: Vec::new(),
        application_data: b"abc".to_vec(),
    };
    let mut acc = Krb5Acceptor::new(Box::new(HttpKeys), Some(service()), Some(cb));
    let rep = accept_complete(acc.step(&token).expect("accept")).expect("ap-rep");
    let (status, _out, json) = orc.init_step(&rep).await;
    assert_eq!(status, b'C', "{json}");
    assert!(!acc
        .context()
        .expect("ctx")
        .flags()
        .contains(GssFlags::CHANNEL_BOUND));
}
