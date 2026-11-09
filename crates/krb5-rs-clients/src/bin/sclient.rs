//! `sclient` (MIT `appl/sample/sclient/sclient.c`): authenticate to
//! `sserver` with `krb5_sendauth` and print its reply.

use std::net::ToSocketAddrs;
use std::sync::Arc;

use krb5_rs::ccache::{default_cache, CcContext, Ccache};
use krb5_rs::client::{CredsRequest, GcOptions};
use krb5_rs::kdc::kdb::kprop::service_port;
use krb5_rs::protocol::ap::{ApReqOptions, AuthContext};
use krb5_rs::protocol::sendauth::{error_text, sendauth, SendauthError};
use krb5_rs_clients::{krb5_message, sname_to_principal};
use tokio::io::AsyncReadExt;

/// sample.h.
const SAMPLE_SERVICE: &str = "sample";
const SAMPLE_PORT: &str = "sample";
const SAMPLE_VERSION: &str = "KRB5_sample_protocol_v1.0";

fn die(argv0: &str, msg: impl std::fmt::Display, context: &str) -> ! {
    eprintln!("{argv0}: {msg} {context}");
    std::process::exit(1)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let argv0 = args[0].as_str();
    if !(2..=4).contains(&args.len()) {
        eprintln!("usage: {argv0} <hostname> [port] [service]");
        std::process::exit(1);
    }
    let host = args[1].as_str();
    let portstr = args.get(2).map_or(SAMPLE_PORT, String::as_str);
    let service = args.get(3).map_or(SAMPLE_SERVICE, String::as_str);

    let profile = Arc::new(krb5_rs_clients::profile());
    let rt = krb5_rs_clients::runtime();

    let lookup = |why: &str| -> ! {
        eprintln!("{argv0}: error looking up host '{host}' port '{portstr}'/tcp: {why}");
        std::process::exit(1)
    };
    let Some(port) = service_port(portstr) else {
        lookup("Servname not supported for ai_socktype")
    };
    let addrs: Vec<_> = match (host, port).to_socket_addrs() {
        Ok(a) => a.collect(),
        Err(e) => lookup(&e.to_string()),
    };
    if addrs.is_empty() {
        lookup("no addresses returned?");
    }

    let (server, srealm) = sname_to_principal(&rt, &profile, Some(host), service);

    let mut stream = None;
    for addr in &addrs {
        match rt.block_on(tokio::net::TcpStream::connect(addr)) {
            Ok(s) => {
                stream = Some(s);
                break;
            }
            Err(e) => eprintln!("{} {}: connect: {e}", addr.ip(), addr.port()),
        }
    }
    let Some(mut stream) = stream else {
        std::process::exit(1)
    };
    println!("connected");

    let ctx = CcContext::from_env(Some(&profile));
    let mut cc =
        default_cache(&ctx).unwrap_or_else(|e| die(argv0, e, "while getting default ccache"));
    let (client, crealm) = cc
        .principal()
        .unwrap_or_else(|e| die(argv0, e, "while getting client principal name"));

    let kc = krb5_rs_clients::kerberos_client(&profile, &crealm);
    let req = CredsRequest {
        client,
        crealm,
        server,
        srealm,
        enctype: 0,
        authdata: None,
        second_ticket: None,
    };
    let cred = rt
        .block_on(kc.get_credentials(&mut cc, GcOptions::empty(), &req))
        .unwrap_or_else(|e| die(argv0, krb5_message(&e), "while using sendauth"));

    let mut actx = AuthContext::new();
    let opts = ApReqOptions {
        mutual_required: true,
        ..Default::default()
    };
    let res = rt.block_on(sendauth(
        &mut stream,
        &mut actx,
        SAMPLE_VERSION,
        &opts,
        Some(host.as_bytes()),
        &cred,
    ));
    match res {
        Err(SendauthError::Rejected(err)) => {
            println!(
                "sendauth rejected, error reply is:\n\t\"{}\"",
                error_text(&err)
            );
        }
        Err(e) => die(argv0, e, "while using sendauth"),
        Ok(()) => {
            println!("sendauth succeeded, reply is:");
            let reply = rt.block_on(async {
                let len = stream.read_u16().await? as usize;
                let mut buf = vec![0u8; len];
                stream.read_exact(&mut buf).await?;
                Ok::<_, std::io::Error>(buf)
            });
            let buf = reply.unwrap_or_else(|e| die(argv0, e, "while reading data from server"));
            println!(
                "reply len {}, contents:\n{}",
                buf.len(),
                String::from_utf8_lossy(&buf)
            );
        }
    }
}
