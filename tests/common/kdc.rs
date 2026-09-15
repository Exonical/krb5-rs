//! Live-KDC helpers shared by the `#[ignore]`d interop test binaries.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::process::Command;
use std::time::Duration;

use krb5_rs::protocol::{
    AsExchange, AsExchangeConfig, Credential, StepResult, TgsExchange, TgsOptions, TgsStepResult,
};
use krb5_rs::types::PrincipalName;
use krb5_rs::Krb5Error;

pub const KDC_CONTAINER: &str = "krb5-rs-kdc-1";
pub const TEST_REALM: &str = "TEST.REALM";
pub const OTHER_REALM: &str = "OTHER.REALM";
/// Maximum acceptable KDC response size (1 MiB). Protects against
/// allocating arbitrarily large buffers from an untrusted length prefix.
pub const MAX_KDC_RESPONSE_SIZE: usize = 1024 * 1024;

/// KDC host — overridable via KDC_HOST for non-local podman/Docker setups.
pub fn kdc_host() -> String {
    std::env::var("KDC_HOST").unwrap_or_else(|_| "127.0.0.1".into())
}

pub fn kdc_addr_str() -> String {
    format!("{}:10188", kdc_host())
}

pub fn kdc_addr() -> SocketAddr {
    kdc_addr_str().parse().expect("parse KDC address")
}

pub fn kdc_other_addr_str() -> String {
    format!("{}:10288", kdc_host())
}

/// Python gssapi oracle address — overridable via GSS_ORACLE_ADDR.
pub fn oracle_addr() -> SocketAddr {
    std::env::var("GSS_ORACLE_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:10189".into())
        .parse()
        .expect("parse oracle address")
}

/// Send a message to a KDC via TCP (4-byte big-endian length prefix).
pub fn kdc_send_to(addr: &str, data: &[u8]) -> std::io::Result<Vec<u8>> {
    // TcpStream::connect is acceptable here — tests are #[ignore]'d and only
    // run when Docker KDC is explicitly started. The read timeout below
    // bounds the overall wait if the KDC is unresponsive.
    let mut stream = TcpStream::connect(addr)?;
    stream.set_nodelay(true)?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    // Combine 4-byte length prefix + data into a single write to avoid
    // Nagle-related issues with Docker Desktop TCP port forwarding.
    let len_u32: u32 = data.len().try_into().map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("KDC request too large: {} bytes", data.len()),
        )
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
            format!("KDC response too large: {resp_len} bytes (max {MAX_KDC_RESPONSE_SIZE})"),
        ));
    }
    let mut resp = vec![0u8; resp_len];
    stream.read_exact(&mut resp)?;
    Ok(resp)
}

/// Send to the default (TEST.REALM) KDC.
pub fn kdc_send(data: &[u8]) -> std::io::Result<Vec<u8>> {
    kdc_send_to(&kdc_addr_str(), data)
}

/// Route a TGS request to the correct KDC based on realm.
pub fn kdc_send_for_realm(realm: &str, data: &[u8]) -> std::io::Result<Vec<u8>> {
    let addr = match realm {
        TEST_REALM => kdc_addr_str(),
        OTHER_REALM => kdc_other_addr_str(),
        _ => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("unexpected realm routing target: {realm}"),
            ));
        }
    };
    kdc_send_to(&addr, data)
}

/// Drive the AS exchange to completion and return the TGT credential.
/// Caps at 32 steps to avoid runaway loops in tests.
pub fn acquire_tgt(principal: &str, password: &str, realm: &str) -> Result<Credential, Krb5Error> {
    let config = AsExchangeConfig::new(PrincipalName::new_principal(principal), realm);
    let mut exchange = AsExchange::new(config, password);
    let mut kdc_reply = Vec::new();
    for _ in 0..32 {
        match exchange.step(&kdc_reply)? {
            StepResult::SendToKdc { data, .. } | StepResult::RetryTcp { data, .. } => {
                kdc_reply = kdc_send(&data).map_err(Krb5Error::Transport)?;
            }
            StepResult::Complete => return exchange.credential().cloned(),
        }
    }
    Err(Krb5Error::ReplyValidation(
        "AS exchange did not complete within step limit",
    ))
}

/// Drive the TGS exchange to completion, routing to correct KDC per realm.
pub fn get_service_ticket(
    tgt: &Credential,
    target: PrincipalName,
) -> Result<Credential, Krb5Error> {
    let mut exchange = TgsExchange::new(tgt.clone(), target, TgsOptions::default());
    let mut kdc_reply = Vec::new();
    for _ in 0..32 {
        match exchange.step(&kdc_reply)? {
            TgsStepResult::SendToKdc { data, realm } | TgsStepResult::RetryTcp { data, realm } => {
                kdc_reply = kdc_send_for_realm(&realm, &data).map_err(Krb5Error::Transport)?;
            }
            TgsStepResult::Complete => return exchange.credential().cloned(),
        }
    }
    Err(Krb5Error::ReplyValidation(
        "TGS exchange did not complete within step limit",
    ))
}

// ---------------------------------------------------------------------------
// podman wrappers (ccache_keytab_live)

pub fn pod(args: &[&str]) -> std::process::Output {
    Command::new("podman").args(args).output().expect("podman")
}

pub fn exec_kdc(cmd: &str) -> String {
    let out = pod(&["exec", KDC_CONTAINER, "bash", "-c", cmd]);
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

pub fn tmp(name: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!("krb5rs_live_{}_{}", std::process::id(), name))
}

pub fn cp_out(cpath: &str, name: &str) -> std::path::PathBuf {
    let local = tmp(name);
    let _ = std::fs::remove_file(&local);
    let out = pod(&[
        "cp",
        &format!("{KDC_CONTAINER}:{cpath}"),
        &local.to_string_lossy(),
    ]);
    assert!(out.status.success(), "podman cp out failed");
    local
}

pub fn cp_in(local: &std::path::Path, cpath: &str) {
    let out = pod(&[
        "cp",
        &local.to_string_lossy(),
        &format!("{KDC_CONTAINER}:{cpath}"),
    ]);
    assert!(out.status.success(), "podman cp in failed");
}
