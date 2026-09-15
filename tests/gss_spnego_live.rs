#![cfg(feature = "client")]
//! Live interop tests: krb5-rs SPNEGO (RFC 4178) against MIT's
//! libgssapi via the python3-gssapi oracle (tests/kdc/gss_oracle.py).
//!
//! Requires the KDC + oracle containers:
//!   docker compose -f docker-compose.test.yml up -d
//! Run with:
//!   cargo test --features client --test gss_spnego_live -- --ignored
//!
//! `KDC_HOST` overrides the KDC host (default 127.0.0.1, port 10188);
//! `GSS_ORACLE_ADDR` overrides the oracle (default 127.0.0.1:10189).

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use krb5_rs::client::KerberosClient;
use krb5_rs::crypto::find_etype;
use krb5_rs::gssapi::krb5::{
    AcceptStep, GssFlags, InitStep, Krb5Acceptor, Krb5Initiator, MECH_KRB5,
};
use krb5_rs::gssapi::spnego::{
    decode_neg_token_init, decode_neg_token_resp, NegState, SpnegoAcceptor, SpnegoInitiator,
    MECH_KRB5_WRONG, MECH_SPNEGO,
};
use krb5_rs::protocol::ap::{ApError, KeySource};
use krb5_rs::protocol::Credential;
use krb5_rs::types::{EncryptionKey, PrincipalName};

const REALM: &str = "TEST.REALM";
const SERVICE: &str = "HTTP/server.test.realm";
const HTTP_PASSWORD: &str = "httpsecret";
const HTTP_SALT: &str = "TEST.REALMHTTPserver.test.realm";

#[path = "common/mod.rs"]
mod common;
use common::kdc::{kdc_addr, oracle_addr};

fn service() -> PrincipalName {
    PrincipalName::new_srv_hst("HTTP", "server.test.realm")
}

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

    async fn accept(&mut self, token: &[u8]) -> (u8, Vec<u8>, String) {
        let mut p = vec![b'A'];
        p.extend_from_slice(token);
        Self::ctx_reply(&self.send(&p).await)
    }

    async fn init_start(&mut self, flagbyte: u8) -> (u8, Vec<u8>, String) {
        Self::ctx_reply(&self.send(&[b'I', flagbyte]).await)
    }

    async fn init_step(&mut self, token: &[u8]) -> (u8, Vec<u8>, String) {
        let mut p = vec![b'R'];
        p.extend_from_slice(token);
        Self::ctx_reply(&self.send(&p).await)
    }

    async fn wrap(&mut self, data: &[u8], conf: bool) -> Vec<u8> {
        let mut p = vec![if conf { b'W' } else { b'P' }];
        p.extend_from_slice(data);
        let r = self.send(&p).await;
        assert_eq!(r[0], b'C', "oracle wrap failed: {:?}", r);
        r[1..].to_vec()
    }

    async fn unwrap(&mut self, token: &[u8]) -> (u8, Vec<u8>) {
        let mut p = vec![b'U'];
        p.extend_from_slice(token);
        let r = self.send(&p).await;
        assert_eq!(r[0], b'C', "oracle unwrap failed: {:?}", r);
        (r[1], r[2..].to_vec())
    }

    async fn get_mic(&mut self, data: &[u8]) -> Vec<u8> {
        let mut p = vec![b'M'];
        p.extend_from_slice(data);
        let r = self.send(&p).await;
        assert_eq!(r[0], b'C', "oracle mic failed: {:?}", r);
        r[1..].to_vec()
    }

    async fn verify_mic(&mut self, data: &[u8], mic: &[u8]) -> bool {
        let mut p = vec![b'V'];
        p.extend_from_slice(&(data.len() as u32).to_be_bytes());
        p.extend_from_slice(data);
        p.extend_from_slice(mic);
        self.send(&p).await[0] == b'C'
    }
}

fn json_str<'a>(json: &'a str, key: &str) -> Option<&'a str> {
    let pat = format!("\"{key}\": \"");
    let start = json.find(&pat)? + pat.len();
    let end = json[start..].find('"')? + start;
    Some(&json[start..end])
}

fn init_continue(s: InitStep) -> Vec<u8> {
    match s {
        InitStep::Continue(t) => t,
        other => panic!("expected Continue, got {other:?}"),
    }
}

/// L1: Rust SPNEGO initiator → MIT acceptor (mutual + delegation).
#[tokio::test]
#[ignore = "requires KDC + oracle: docker compose -f docker-compose.test.yml up -d"]
async fn rust_spnego_init_mit_accept() {
    let (svc, tgt) = creds().await;
    let inner = Krb5Initiator::new(
        svc,
        Some(tgt),
        GssFlags::MUTUAL | GssFlags::DELEG | GssFlags::REPLAY | GssFlags::SEQUENCE,
        None,
    )
    .expect("inner");
    let mut init = SpnegoInitiator::new(inner, vec![MECH_KRB5.to_vec()]);
    let t1 = init_continue(init.step(None).expect("init"));

    let mut orc = Oracle::connect().await;
    let (status, rep, json) = orc.accept(&t1).await;
    assert_eq!(status, b'C', "MIT SPNEGO rejected our NegTokenInit: {json}");
    assert!(!rep.is_empty(), "mutual accept must emit a NegTokenResp");
    assert_eq!(
        json_str(&json, "mech"),
        Some("1.2.840.113554.1.2.2"),
        "negotiated mech in {json}"
    );
    assert_eq!(
        json_str(&json, "deleg_name"),
        Some("testuser@TEST.REALM"),
        "deleg_name in {json}"
    );

    let nr = decode_neg_token_resp(&rep).expect("decode MIT NegTokenResp");
    assert_eq!(nr.neg_state, Some(NegState::AcceptCompleted));
    assert_eq!(nr.supported_mech.as_deref(), Some(MECH_KRB5));
    assert!(nr.response_token.is_some(), "AP-REP expected");
    assert!(nr.mech_list_mic.is_none());

    match init.step(Some(&rep)).expect("step2") {
        InitStep::Complete(None) => {}
        other => panic!("expected Complete(None), got {other:?}"),
    }
    assert_eq!(init.negotiated_mech(), Some(MECH_KRB5));
    let mut ic = init.context().expect("init ctx");

    // Per-message ops both ways.
    let t = ic.wrap(true, b"to-mit").expect("wrap");
    let (conf, data) = orc.unwrap(&t).await;
    assert_eq!(conf, 1);
    assert_eq!(data, b"to-mit");
    let t = orc.wrap(b"from-mit", true).await;
    let r = ic.unwrap(&t).expect("unwrap");
    assert_eq!(r.data, b"from-mit");
    assert!(r.conf);
    let mic = ic.get_mic(b"m1").expect("mic");
    assert!(orc.verify_mic(b"m1", &mic).await);
    let mic = orc.get_mic(b"m2").await;
    ic.verify_mic(b"m2", &mic).expect("verify");
}

/// L2: MIT SPNEGO initiator → Rust acceptor.
///
/// MIT's NegTokenInit (decoded live) advertises exactly
/// [1.2.840.113554.1.2.2] — the canonical krb5 OID only — so the Rust
/// acceptor's default [MECH_KRB5] list matches index 0 →
/// ACCEPT_INCOMPLETE, no MIC exchange.
#[tokio::test]
#[ignore = "requires KDC + oracle: docker compose -f docker-compose.test.yml up -d"]
async fn mit_spnego_init_rust_accept() {
    let mut orc = Oracle::connect().await;
    let (status, token, json) = orc.init_start(2).await;
    assert_eq!(status, b'N', "MIT SPNEGO init should need a reply: {json}");

    let (ni, _der) = decode_neg_token_init(&token).expect("decode MIT NegTokenInit");
    eprintln!("MIT SPNEGO mech list: {:?}", ni.mech_types);
    assert_eq!(ni.mech_types, vec![MECH_KRB5.to_vec()]);
    assert!(ni.mech_token.is_some(), "MIT sends an optimistic AP-REQ");

    let mut acc = SpnegoAcceptor::new(
        Krb5Acceptor::new(Box::new(HttpKeys), Some(service()), None),
        vec![MECH_KRB5.to_vec()],
    );
    let rep = match acc.step(&token).expect("accept") {
        AcceptStep::Complete { token: Some(t) } => t,
        other => panic!("expected Complete with token, got {other:?}"),
    };
    assert_eq!(acc.negotiated_mech(), Some(MECH_KRB5));
    let (status, _out, json) = orc.init_step(&rep).await;
    assert_eq!(status, b'C', "MIT rejected our NegTokenResp: {json}");

    let mut ctx = acc.context().expect("ctx");
    let t = ctx.wrap(true, b"to-mit").expect("wrap");
    let (conf, data) = orc.unwrap(&t).await;
    assert_eq!(conf, 1);
    assert_eq!(data, b"to-mit");
    let t = orc.wrap(b"from-mit", true).await;
    assert_eq!(ctx.unwrap(&t).expect("unwrap").data, b"from-mit");
    let mic = ctx.get_mic(b"m1").expect("mic");
    assert!(orc.verify_mic(b"m1", &mic).await);
    let mic = orc.get_mic(b"m2").await;
    ctx.verify_mic(b"m2", &mic).expect("verify");
}

/// L3: MIT accepts a Rust NegTokenInit advertising [KRB5_WRONG, KRB5]
/// with a canonical-OID krb5 mechToken (negotiate_mech maps the MS wrong
/// OID to krb5 and echoes it back; acc_ctx_vfy_oid accepts the canonical
/// inner OID as a krb5 alias).
#[tokio::test]
#[ignore = "requires KDC + oracle: docker compose -f docker-compose.test.yml up -d"]
async fn rust_spnego_wrong_oid_mit_accept() {
    let (svc, _tgt) = creds().await;
    let inner = Krb5Initiator::new(svc, None, GssFlags::MUTUAL, None).expect("inner");
    let mut init = SpnegoInitiator::new(inner, vec![MECH_KRB5_WRONG.to_vec(), MECH_KRB5.to_vec()]);
    let t1 = init_continue(init.step(None).expect("init"));
    // Sanity: the first advertised OID is the wrong one, and the inner
    // token keeps canonical krb5 framing.
    let (ni, _der) = decode_neg_token_init(&t1).expect("decode own init");
    assert_eq!(
        ni.mech_types,
        vec![MECH_KRB5_WRONG.to_vec(), MECH_KRB5.to_vec()]
    );
    let (mech, _b) =
        krb5_rs::gssapi::token::parse_token_header(ni.mech_token.as_deref().expect("mt"))
            .expect("inner framing");
    assert_eq!(mech, MECH_KRB5);
    assert_ne!(mech, MECH_SPNEGO);

    let mut orc = Oracle::connect().await;
    let (status, rep, json) = orc.accept(&t1).await;
    assert_eq!(status, b'C', "MIT rejected wrong-OID NegTokenInit: {json}");
    assert_eq!(
        json_str(&json, "mech"),
        Some("1.2.840.113554.1.2.2"),
        "negotiated mech in {json}"
    );
    // MIT echoes the wrong OID verbatim as supportedMech.
    let nr = decode_neg_token_resp(&rep).expect("decode resp");
    assert_eq!(nr.supported_mech.as_deref(), Some(MECH_KRB5_WRONG));
    match init.step(Some(&rep)).expect("step2") {
        InitStep::Complete(None) => {}
        other => panic!("expected Complete(None), got {other:?}"),
    }
    let mut ic = init.context().expect("ctx");
    let t = ic.wrap(true, b"hi").expect("wrap");
    let (conf, data) = orc.unwrap(&t).await;
    assert_eq!(conf, 1);
    assert_eq!(data, b"hi");
}
