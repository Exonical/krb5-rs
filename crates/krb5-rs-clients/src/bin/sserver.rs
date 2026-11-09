//! `sserver` (MIT `appl/sample/sserver/sserver.c`): accept one
//! `krb5_sendauth` connection, standalone with `-p` or from inetd on
//! descriptor 0, and tell the client who it is.

use std::sync::Arc;

use krb5_rs::ccache::unparse_name;
use krb5_rs::client::vfy::{default_keytab, resolve_keytab, VerifyKeytab};
use krb5_rs::protocol::ap::AuthContext;
use krb5_rs::protocol::sendauth::recvauth;
use krb5_rs_clients::{krb5_message, sname_to_principal, syslog, Getopt, LOG_DAEMON_ERR};
use tokio::io::AsyncWriteExt;

/// sample.h.
const SAMPLE_SERVICE: &str = "sample";
const SAMPLE_VERSION: &str = "KRB5_sample_protocol_v1.0";

fn log_exit(msg: &str, code: i32) -> ! {
    syslog("sserver", LOG_DAEMON_ERR, msg);
    std::process::exit(code)
}

fn usage(progname: &str) -> ! {
    eprintln!("usage: {progname} [-p port] [-s service] [-S keytab]");
    std::process::exit(1)
}

/// `atoi`.
fn atoi(s: &str) -> u16 {
    let digits: String = s
        .trim_start()
        .chars()
        .take_while(char::is_ascii_digit)
        .collect();
    digits.parse().unwrap_or(0)
}

fn main() {
    let progname = std::env::args().next().unwrap_or_default();
    let profile = Arc::new(krb5_rs_clients::profile());
    let rt = krb5_rs_clients::runtime();

    let mut port = 0u16;
    let mut service = SAMPLE_SERVICE.to_string();
    let mut keytab: Option<Box<dyn VerifyKeytab>> = None;
    let mut opts = Getopt::new("p:S:s:");
    for (ch, arg) in opts.by_ref() {
        let arg = arg.unwrap_or_default();
        match ch {
            'p' => port = atoi(&arg),
            's' => service = arg,
            'S' => match resolve_keytab(&arg) {
                Ok(kt) => keytab = Some(kt),
                Err(e) => {
                    eprintln!(
                        "{progname}: {} while resolving keytab file {arg}",
                        krb5_message(&e)
                    );
                    std::process::exit(2)
                }
            },
            _ => usage(&progname),
        }
    }
    // Backwards compatibility: the port may also follow the options.
    if let Some(p) = opts.rest().get(1) {
        port = atoi(p);
    }

    let (server, realm) = sname_to_principal(&rt, &profile, None, &service);
    let realm = if realm.is_empty() {
        profile
            .get_string(&["libdefaults", "default_realm"])
            .unwrap_or_default()
    } else {
        realm
    };
    let keytab = match keytab {
        Some(kt) => kt,
        None => default_keytab(Some(&profile)).unwrap_or_else(|e| {
            log_exit(
                &format!(
                    "while generating service name ({service}): {}",
                    krb5_message(&e)
                ),
                1,
            )
        }),
    };

    let std_stream = if port != 0 {
        let listener = std::net::TcpListener::bind(("0.0.0.0", port))
            .unwrap_or_else(|e| log_exit(&format!("bind: {e}"), 3));
        println!("starting...");
        let _ = std::io::Write::flush(&mut std::io::stdout());
        listener
            .accept()
            .map(|(s, _)| s)
            .unwrap_or_else(|e| log_exit(&format!("accept: {e}"), 3))
    } else {
        inetd_stream().unwrap_or_else(|e| log_exit(&format!("getpeername: {e}"), 1))
    };
    if let Err(e) = std_stream.peer_addr() {
        log_exit(&format!("getpeername: {e}"), 1);
    }

    rt.block_on(async {
        let _ = std_stream.set_nonblocking(true);
        let mut stream = tokio::net::TcpStream::from_std(std_stream)
            .unwrap_or_else(|e| log_exit(&format!("getpeername: {e}"), 1));
        let mut actx = AuthContext::new();
        let auth = recvauth(
            &mut stream,
            &mut actx,
            SAMPLE_VERSION,
            Some(&server),
            &realm,
            keytab.key_source(),
        )
        .await
        .unwrap_or_else(|e| log_exit(&format!("recvauth failed--{e}"), 1));
        let cname = unparse_name(
            &auth.ticket.cname,
            &String::from_utf8_lossy(auth.ticket.crealm.as_bytes()),
        );
        let repbuf = format!("You are {cname}\n");
        let len = u16::try_from(repbuf.len()).unwrap_or(u16::MAX);
        if let Err(e) = stream.write_all(&len.to_be_bytes()).await {
            log_exit(&format!("{e}: while writing len to client"), 1);
        }
        if let Err(e) = stream.write_all(repbuf.as_bytes()).await {
            log_exit(&format!("{e}: while writing data to client"), 1);
        }
        let _ = stream.flush().await;
    });
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
