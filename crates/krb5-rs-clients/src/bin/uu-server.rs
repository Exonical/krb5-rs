//! `uu-server` (MIT `appl/user_user/server.c`): get a user-to-user ticket
//! for the client with its TGT and prove it with a KRB-SAFE message. With a
//! port argument it listens there (MIT's `DEBUG` build); otherwise it uses
//! the connection inetd passed on descriptor 0.

use std::sync::Arc;

use krb5_rs::ccache::{default_cache, parse_principal, CcContext, Ccache};
use krb5_rs::client::{CredsRequest, GcOptions};
use krb5_rs::kdc::kdb::kprop::service_port;
use krb5_rs::protocol::ap::{ApReqOptions, AuthContext, AuthContextFlags};
use krb5_rs::protocol::sendauth::{read_message, write_message};
use krb5_rs::types::Ticket;
use krb5_rs_clients::{krb5_message, set_full_addrs};

const MESSAGE: &[u8] = b"Hello, other end of connection.\0";

fn fail(who: &str, msg: impl std::fmt::Display, context: &str, code: i32) -> ! {
    eprintln!("{who}: {msg} {context}");
    std::process::exit(code)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let profile = Arc::new(krb5_rs_clients::profile());
    let rt = krb5_rs_clients::runtime();
    let s = "uu-server";

    let std_stream = if args.len() > 1 {
        let port = args[1].trim().parse().unwrap_or(0);
        let port = if port != 0 {
            port
        } else {
            service_port("uu-sample")
                .unwrap_or_else(|| fail(s, "", "can't find uu-sample/tcp service", 3))
        };
        let listener = std::net::TcpListener::bind(("0.0.0.0", port))
            .unwrap_or_else(|e| fail(s, e, "binding socket", 3));
        println!("Server started");
        let _ = std::io::Write::flush(&mut std::io::stdout());
        listener
            .accept()
            .map(|(c, _)| c)
            .unwrap_or_else(|e| fail(s, e, "accepting", 3))
    } else {
        inetd_stream().unwrap_or_else(|e| fail(s, e, "getting client address", 6))
    };
    let _ = std_stream.set_nonblocking(true);

    let code = rt.block_on(async {
        let mut stream = tokio::net::TcpStream::from_std(std_stream)
            .unwrap_or_else(|e| fail(s, e, "getting client address", 6));
        let pname = read_message(&mut stream)
            .await
            .ok()
            .filter(|p| p.last() == Some(&0))
            .unwrap_or_else(|| fail(s, "", "reading pname", 2));
        let tkt = read_message(&mut stream)
            .await
            .unwrap_or_else(|e| fail(s, e, "reading ticket data", 2));

        let ctx = CcContext::from_env(Some(&profile));
        let mut cc =
            default_cache(&ctx).unwrap_or_else(|e| fail(s, e, "getting credentials cache", 4));
        let (me, myrealm) = cc
            .principal()
            .unwrap_or_else(|e| fail("uu-client", e, "getting principal name", 6));

        let pname = String::from_utf8_lossy(&pname[..pname.len() - 1]).to_string();
        println!("uu-server: client principal is \"{pname}\".");
        let (server, srealm) = parse_principal(&pname, Some(&myrealm)).unwrap_or_else(|| {
            fail(
                s,
                "Malformed representation of principal",
                "parsing client name",
                3,
            )
        });
        println!("uu-server: client ticket is {} bytes.", tkt.len());
        let second: Ticket =
            rasn::der::decode(&tkt).unwrap_or_else(|e| fail(s, e, "getting user-user ticket", 5));

        let kc = krb5_rs_clients::kerberos_client(&profile, &myrealm);
        let req = CredsRequest {
            client: me,
            crealm: myrealm,
            server,
            srealm,
            enctype: 0,
            authdata: None,
            second_ticket: Some(second),
        };
        let cred = kc
            .get_credentials(&mut cc, GcOptions::USER_USER, &req)
            .await
            .unwrap_or_else(|e| fail(s, krb5_message(&e), "getting user-user ticket", 5));

        let local = stream
            .local_addr()
            .unwrap_or_else(|e| fail(s, e, "getting local address", 6));
        let remote = stream
            .peer_addr()
            .unwrap_or_else(|e| fail(s, e, "getting client address", 6));
        let mut actx = AuthContext::new();
        actx.set_flags(AuthContextFlags::DO_SEQUENCE);
        set_full_addrs(&mut actx, &local, &remote);
        let opts = ApReqOptions {
            use_session_key: true,
            ..Default::default()
        };
        let ap_req = actx
            .mk_req(&opts, None, &cred)
            .unwrap_or_else(|e| fail(s, krb5_message(&e), "making AP_REQ", 8));
        if write_message(&mut stream, &ap_req).await.is_err() {
            return 7;
        }
        let (safe, _) = actx
            .mk_safe(MESSAGE)
            .unwrap_or_else(|e| fail(s, krb5_message(&e), "encoding message to client", 6));
        if let Err(e) = write_message(&mut stream, &safe).await {
            fail(s, e, "writing message to client", 7);
        }
        0
    });
    std::process::exit(code)
}

/// Descriptor 0 as the connection inetd handed over.
#[cfg(unix)]
fn inetd_stream() -> std::io::Result<std::net::TcpStream> {
    use std::os::fd::AsFd;
    let fd = std::io::stdin().as_fd().try_clone_to_owned()?;
    Ok(std::net::TcpStream::from(fd))
}

#[cfg(not(unix))]
fn inetd_stream() -> std::io::Result<std::net::TcpStream> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "inetd mode needs a Unix socket on descriptor 0",
    ))
}
