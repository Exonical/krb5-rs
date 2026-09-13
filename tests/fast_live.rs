//! Live FAST (RFC 6113) tests against the MIT KDC container.
//!
//! Requires the KDC + oracle containers (docker-compose.test.yml /
//! podman). The KDC listens on ${KDC_HOST}:10188 (default 127.0.0.1),
//! realm TEST.REALM; the GSS oracle is ${GSS_ORACLE_ADDR}
//! (default 127.0.0.1:10189).
//!
//! Run with:
//!   cargo test --all-features --test fast_live -- --ignored --nocapture

#![cfg(feature = "client")]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

use krb5_rs::crypto::{find_etype, fx_cf2, key_usage};
use krb5_rs::gssapi::krb5::{GssFlags, InitStep, Krb5Initiator};
use krb5_rs::protocol::fast::FastMode;
use krb5_rs::protocol::{
    AsExchange, AsExchangeConfig, Credential, StepResult, TgsExchange, TgsOptions, TgsStepResult,
};
use krb5_rs::types::{
    ApReq, AsRep, AsReq, Authenticator, KrbFastReq, PaData, PaFxFastRequest, PrincipalName, TgsRep,
};
use krb5_rs::Krb5Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const REALM: &str = "TEST.REALM";
const PA_ENC_TIMESTAMP: i32 = 2;
const PA_FX_FAST: i32 = 136;
const PA_ENCRYPTED_CHALLENGE: i32 = 138;

fn kdc_addr() -> String {
    let host = std::env::var("KDC_HOST").unwrap_or_else(|_| "127.0.0.1".into());
    format!("{host}:10188")
}

fn oracle_addr() -> SocketAddr {
    std::env::var("GSS_ORACLE_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:10189".into())
        .parse()
        .expect("parse oracle address")
}

const MAX_KDC_RESPONSE_SIZE: usize = 1024 * 1024;

/// Send a message to the KDC via TCP (4-byte big-endian length prefix).
fn kdc_send(data: &[u8]) -> std::io::Result<Vec<u8>> {
    let mut stream = TcpStream::connect(kdc_addr())?;
    stream.set_nodelay(true)?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    let len_u32: u32 = data.len().try_into().map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "KDC request too large")
    })?;
    let mut msg = Vec::with_capacity(4 + data.len());
    msg.extend_from_slice(&len_u32.to_be_bytes());
    msg.extend_from_slice(data);
    stream.write_all(&msg)?;
    stream.flush()?;
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let resp_len = u32::from_be_bytes(len_buf) as usize;
    if resp_len > MAX_KDC_RESPONSE_SIZE {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("KDC response too large: {resp_len}"),
        ));
    }
    let mut resp = vec![0u8; resp_len];
    stream.read_exact(&mut resp)?;
    Ok(resp)
}

/// Drive an AS exchange, returning (sent requests, last KDC reply).
fn drive_as(exchange: &mut AsExchange) -> Result<(Vec<Vec<u8>>, Vec<u8>), Krb5Error> {
    let mut kdc_reply = Vec::new();
    let mut sent = Vec::new();
    for _ in 0..32 {
        match exchange.step(&kdc_reply)? {
            StepResult::SendToKdc { data, .. } | StepResult::RetryTcp { data, .. } => {
                kdc_reply = kdc_send(&data).map_err(Krb5Error::Transport)?;
                sent.push(data);
            }
            StepResult::Complete => return Ok((sent, kdc_reply)),
        }
    }
    Err(Krb5Error::ReplyValidation("AS exchange did not complete"))
}

/// Drive a TGS exchange, returning (sent requests, last KDC reply).
fn drive_tgs(exchange: &mut TgsExchange) -> Result<(Vec<Vec<u8>>, Vec<u8>), Krb5Error> {
    let mut kdc_reply = Vec::new();
    let mut sent = Vec::new();
    for _ in 0..32 {
        match exchange.step(&kdc_reply)? {
            TgsStepResult::SendToKdc { data, .. } | TgsStepResult::RetryTcp { data, .. } => {
                kdc_reply = kdc_send(&data).map_err(Krb5Error::Transport)?;
                sent.push(data);
            }
            TgsStepResult::Complete => return Ok((sent, kdc_reply)),
        }
    }
    Err(Krb5Error::ReplyValidation("TGS exchange did not complete"))
}

/// Acquire a normal (unarmored) TGT for `user`/`password`.
fn plain_tgt(user: &str, password: &str) -> Credential {
    let config = AsExchangeConfig::new(PrincipalName::new_principal(user), REALM);
    let mut exchange = AsExchange::new(config, password);
    drive_as(&mut exchange).expect("armor TGT AS exchange");
    exchange.credential().expect("armor TGT").clone()
}

/// Derive the armor key from an armored AS-REQ: decrypt the armor AP-REQ
/// authenticator with the armor TGT session key, then FX-CF2.
fn as_armor_key(as_req_der: &[u8], tgt: &Credential) -> krb5_rs::types::EncryptionKey {
    let as_req: AsReq = rasn::der::decode(as_req_der).expect("decode AS-REQ");
    let pa = as_req
        .0
        .padata
        .as_deref()
        .expect("padata")
        .iter()
        .find(|pa| pa.padata_type == PA_FX_FAST)
        .expect("PA-FX-FAST");
    let fx: PaFxFastRequest = rasn::der::decode(pa.padata_value.as_ref()).expect("fx request");
    let PaFxFastRequest::ArmoredData(armored) = fx;
    let armor = armored.armor.expect("armor");
    assert_eq!(armor.armor_type, 1);
    let ap_req: ApReq = rasn::der::decode(armor.armor_value.as_ref()).expect("AP-REQ");
    let profile = find_etype(tgt.session_key.keytype).expect("etype");
    let plain = profile
        .decrypt(
            tgt.session_key.key_bytes(),
            key_usage::AP_REQ_AUTH,
            ap_req.authenticator.cipher.as_ref(),
        )
        .expect("armor authenticator");
    let auth: Authenticator = rasn::der::decode(&plain).expect("authenticator");
    let subkey = auth.subkey.expect("subkey");
    fx_cf2(&subkey, b"subkeyarmor", &tgt.session_key, b"ticketarmor").expect("cf2")
}

/// Decrypt the inner KrbFastReq of the last armored AS-REQ.
fn inner_fast_req(as_req_der: &[u8], armor_key: &krb5_rs::types::EncryptionKey) -> KrbFastReq {
    let as_req: AsReq = rasn::der::decode(as_req_der).expect("decode AS-REQ");
    let pa = as_req
        .0
        .padata
        .as_deref()
        .expect("padata")
        .iter()
        .find(|pa| pa.padata_type == PA_FX_FAST)
        .expect("PA-FX-FAST");
    let fx: PaFxFastRequest = rasn::der::decode(pa.padata_value.as_ref()).expect("fx request");
    let PaFxFastRequest::ArmoredData(armored) = fx;
    let profile = find_etype(armor_key.keytype).expect("etype");
    let plain = profile
        .decrypt(
            armor_key.key_bytes(),
            key_usage::FAST_ENC,
            armored.enc_fast_req.cipher.as_ref(),
        )
        .expect("decrypt fast req");
    rasn::der::decode(&plain).expect("KrbFastReq")
}

fn padata_types(padata: &[PaData]) -> Vec<i32> {
    padata.iter().map(|pa| pa.padata_type).collect()
}

/// L1 — FastMode::Required completes; the final request carries an
/// encrypted challenge (138) and no PA-ENC-TIMESTAMP (2); the reply is
/// FAST-armored and the KDC challenge verifies.
#[test]
#[ignore = "requires KDC: podman compose up"]
fn as_required_enc_challenge() {
    let armor_tgt = plain_tgt("testuser", "testpassword");

    let mut config = AsExchangeConfig::new(PrincipalName::new_principal("testuser"), REALM);
    config.fast = FastMode::Required(armor_tgt.clone());
    let mut exchange = AsExchange::new(config, "testpassword");
    let (sent, last_reply) = drive_as(&mut exchange).expect("required FAST AS exchange");
    assert!(exchange.credential().is_ok());

    // Every request after the first is armored; the last one carries the
    // encrypted challenge inside the FAST tunnel.
    let last_req = sent.last().expect("sent requests");
    let as_req: AsReq = rasn::der::decode(last_req).expect("decode last AS-REQ");
    assert_eq!(
        padata_types(as_req.0.padata.as_deref().expect("padata")),
        vec![PA_FX_FAST],
        "armored outer AS-REQ carries only PA-FX-FAST"
    );
    let armor_key = as_armor_key(last_req, &armor_tgt);
    let inner = inner_fast_req(last_req, &armor_key);
    let inner_types = padata_types(&inner.padata);
    assert!(
        inner_types.contains(&PA_ENCRYPTED_CHALLENGE),
        "inner padata {inner_types:?} must contain 138"
    );
    assert!(
        !inner_types.contains(&PA_ENC_TIMESTAMP),
        "KDC refuses PA-ENC-TIMESTAMP under FAST (kdc_preauth_encts.c:30-44)"
    );

    // Final reply is FAST-armored.
    let rep: AsRep = rasn::der::decode(&last_reply).expect("decode AS-REP");
    assert!(rep
        .0
        .padata
        .as_deref()
        .unwrap_or(&[])
        .iter()
        .any(|pa| pa.padata_type == PA_FX_FAST));
    assert!(exchange.fast_avail(), "ENC_PA_REP + FAST ⇒ fast_avail");
    assert!(exchange.kdc_verified(), "KDC challenge verified");

    println!("L1: required FAST completed in {} send(s)", sent.len());
    println!("    inspect KDC log for: preauth (encrypted_challenge) verify success");
    println!("    e.g. podman logs krb5-rs-kdc-1 | tail");
}

/// L2 — FastMode::Opportunistic starts unarmored and upgrades on the KDC's
/// FAST advertisement. MIT request flow: unarmored initial request →
/// PREAUTH_REQUIRED advertising PA-FX-FAST → armored restart → inner
/// PREAUTH_REQUIRED offering encrypted challenge → armored challenge
/// request → AS-REP. Exactly 3 sends.
#[test]
#[ignore = "requires KDC: podman compose up"]
fn as_opportunistic_upgrade() {
    let armor_tgt = plain_tgt("testuser", "testpassword");

    let mut config = AsExchangeConfig::new(PrincipalName::new_principal("testuser"), REALM);
    config.fast = FastMode::Opportunistic(armor_tgt.clone());
    let mut exchange = AsExchange::new(config, "testpassword");
    let (sent, _reply) = drive_as(&mut exchange).expect("opportunistic FAST AS exchange");

    assert_eq!(
        sent.len(),
        3,
        "MIT flow: unarmored + armored restart + armored challenge"
    );

    // First request unarmored.
    let first: AsReq = rasn::der::decode(&sent[0]).expect("req1");
    assert!(!padata_types(first.0.padata.as_deref().expect("padata")).contains(&PA_FX_FAST));

    // Requests 2 and 3 armored; the last carries the challenge.
    for req in &sent[1..] {
        let as_req: AsReq = rasn::der::decode(req).expect("decode");
        assert!(padata_types(as_req.0.padata.as_deref().expect("padata")).contains(&PA_FX_FAST));
    }
    let armor_key = as_armor_key(&sent[2], &armor_tgt);
    let inner = inner_fast_req(&sent[2], &armor_key);
    assert!(padata_types(&inner.padata).contains(&PA_ENCRYPTED_CHALLENGE));

    println!("L2: opportunistic upgrade completed in 3 sends");
}

/// L3 — a corrupted armor TGT session key makes the armor AP-REQ
/// undecryptable at the KDC; the outer error (AP_ERR_BAD_INTEGRITY or
/// equivalent) surfaces.
#[test]
#[ignore = "requires KDC: podman compose up"]
fn as_wrong_armor_rejected() {
    let mut armor_tgt = plain_tgt("testuser", "testpassword");
    armor_tgt.session_key = krb5_rs::types::EncryptionKey::new(
        armor_tgt.session_key.keytype,
        rand::random::<[u8; 32]>().to_vec(),
    );

    let mut config = AsExchangeConfig::new(PrincipalName::new_principal("testuser"), REALM);
    config.fast = FastMode::Required(armor_tgt);
    let mut exchange = AsExchange::new(config, "testpassword");
    match drive_as(&mut exchange) {
        Err(Krb5Error::KdcError(e)) => {
            println!("L3: KDC rejected bad armor with error {}", e.error_code);
            assert_eq!(
                e.error_code, 31,
                "expected KRB_AP_ERR_BAD_INTEGRITY (31), got {}",
                e.error_code
            );
        }
        other => panic!("expected KdcError, got: {other:?}"),
    }
}

/// L4 — TGS-REQ is always FAST-armored; the MIT KDC answers with a FAST
/// reply (padata 136), and the resulting credential works against the MIT
/// acceptor oracle.
#[tokio::test]
#[ignore = "requires KDC + oracle: podman compose up"]
async fn tgs_fast_strengthen() {
    let tgt = plain_tgt("testuser", "testpassword");

    let target = PrincipalName::new_srv_hst("HTTP", "server.test.realm");
    let mut exchange = TgsExchange::new(tgt, target, TgsOptions::default());
    let (_sent, last_reply) = drive_tgs(&mut exchange).expect("TGS exchange");

    let rep: TgsRep = rasn::der::decode(&last_reply).expect("decode TGS-REP");
    assert!(
        rep.0
            .padata
            .as_deref()
            .unwrap_or(&[])
            .iter()
            .any(|pa| pa.padata_type == PA_FX_FAST),
        "MIT KDC answers an armored TGS-REQ with a FAST reply"
    );

    // The credential works: AP-REQ via GSS init token accepted by MIT.
    let svc = exchange.credential().expect("service cred").clone();
    let mut init =
        Krb5Initiator::new(svc, None, GssFlags::REPLAY | GssFlags::SEQUENCE, None).expect("init");
    let token = match init.step(None).expect("init step") {
        InitStep::Complete(Some(t)) | InitStep::Continue(t) => t,
        _ => panic!("expected token"),
    };

    let mut stream = tokio::net::TcpStream::connect(oracle_addr())
        .await
        .expect("oracle connect");
    let mut payload = vec![b'A'];
    payload.extend_from_slice(&token);
    let n = payload.len() as u32;
    stream.write_all(&n.to_be_bytes()).await.expect("write len");
    stream.write_all(&payload).await.expect("write");
    let mut len = [0u8; 4];
    stream.read_exact(&mut len).await.expect("read len");
    let mut buf = vec![0u8; u32::from_be_bytes(len) as usize];
    stream.read_exact(&mut buf).await.expect("read");
    assert_eq!(buf[0], b'C', "MIT oracle rejected AP-REQ: {:?}", buf);

    println!("L4: FAST TGS completed; MIT acceptor validated the service ticket");
}

/// L5 — required FAST for sha2user (aes-sha2 only principal): exercises
/// FX-CF2 and the challenge derivation over the SHA-2 profiles.
#[test]
#[ignore = "requires KDC: podman compose up"]
fn sha2user_fast() {
    // Armor TGT for sha2user. The MIT KDC issues session keys with
    // aes256-sha1 (etype 18) regardless of the long-term key enctype, so the
    // armor key derivation runs through SHA-1 while the as_key and the
    // challenge derivations run through the SHA-2 profile.
    let armor_tgt = plain_tgt("sha2user", "sha2pass");

    let mut config = AsExchangeConfig::new(PrincipalName::new_principal("sha2user"), REALM);
    config.fast = FastMode::Required(armor_tgt.clone());
    let mut exchange = AsExchange::new(config, "sha2pass");
    let (sent, _reply) = drive_as(&mut exchange).expect("sha2 FAST AS exchange");
    let cred = exchange.credential().expect("credential");
    assert_eq!(cred.client.to_string(), "sha2user");
    assert!(exchange.kdc_verified());

    println!(
        "L5: sha2user required FAST completed in {} send(s)",
        sent.len()
    );
}
