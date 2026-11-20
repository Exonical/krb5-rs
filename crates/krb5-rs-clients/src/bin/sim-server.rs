//! MIT `sim_server` (src/appl/simple/server/sim_server.c): reads one
//! client's AP-REQ, KRB_SAFE and KRB_PRIV messages over UDP.

use std::net::UdpSocket;
use std::sync::Arc;

use krb5_rs::ccache::unparse_name;
use krb5_rs::client::vfy::{default_keytab, resolve_keytab, VerifyKeytab};
use krb5_rs::kdc::kdb::kprop::{host_address, service_port};
use krb5_rs::protocol::ap::AuthContext;
use krb5_rs_clients::{ipport_address, krb5_message, sname_to_principal, Getopt};

/// simple.h.
const SIMPLE_SERVICE: &str = "sample";
const SIMPLE_PORT: &str = "sample";
/// `BUFSIZ`.
const BUFSIZ: usize = 8192;

fn usage(name: &str) -> ! {
    eprintln!("usage: {name} [-p port] [-s service] [-S keytab]");
    std::process::exit(1)
}

fn die(progname: &str, msg: impl std::fmt::Display, context: &str) -> ! {
    eprintln!("{progname}: {msg} {context}");
    std::process::exit(1)
}

/// `(short) atoi`.
fn atoi_short(s: &str) -> u16 {
    let s = s.trim_start();
    let (neg, digits) = match s.as_bytes().first() {
        Some(b'-') => (true, &s[1..]),
        Some(b'+') => (false, &s[1..]),
        _ => (false, s),
    };
    let n = digits
        .bytes()
        .take_while(u8::is_ascii_digit)
        .fold(0u64, |n, d| {
            n.wrapping_mul(10).wrapping_add(u64::from(d - b'0'))
        });
    let n = if neg { n.wrapping_neg() } else { n };
    let [a, b, ..] = n.to_le_bytes();
    u16::from_le_bytes([a, b])
}

fn main() {
    let progname = std::env::args().next().unwrap_or_default();
    let profile = Arc::new(krb5_rs_clients::profile());
    let rt = krb5_rs_clients::runtime();

    let mut port = 0u16;
    let mut service = SIMPLE_SERVICE.to_string();
    let mut keytab: Option<Box<dyn VerifyKeytab>> = None;
    for (ch, arg) in Getopt::new("p:s:S:") {
        let arg = arg.unwrap_or_default();
        match ch {
            'p' => port = atoi_short(&arg),
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

    let (sprinc, _) = sname_to_principal(&rt, &profile, None, &service);
    if port == 0 {
        match service_port(SIMPLE_PORT) {
            Some(p) => port = p,
            None => {
                eprintln!("service unknown: {SIMPLE_PORT}/udp");
                std::process::exit(1);
            }
        }
    }
    let sock = UdpSocket::bind(("0.0.0.0", port)).unwrap_or_else(|e| {
        eprintln!("binding datagram socket: {e}");
        std::process::exit(1)
    });
    println!("starting...");
    let keytab = match keytab {
        Some(kt) => kt,
        None => default_keytab(Some(&profile))
            .unwrap_or_else(|e| die(&progname, krb5_message(&e), "while reading request")),
    };

    let mut pktbuf = [0u8; BUFSIZ];
    let mut recv = || {
        let (n, from) = sock.recv_from(&mut pktbuf).unwrap_or_else(|e| {
            eprintln!("receiving datagram: {e}");
            std::process::exit(1)
        });
        println!("Received {n} bytes");
        (pktbuf[..n].to_vec(), from)
    };

    let (packet, c_sock) = recv();
    let mut actx = AuthContext::new();
    let res = actx
        .rd_req(&packet, Some(&sprinc), keytab.key_source())
        .unwrap_or_else(|e| die(&progname, krb5_message(&e), "while reading request"));
    let cname = unparse_name(
        &res.ticket.cname,
        &String::from_utf8_lossy(res.ticket.crealm.as_bytes()),
    );
    println!("Got authentication info from {cname}");
    actx.set_addrs(None, Some(host_address(&c_sock)));
    actx.set_ports(None, Some(ipport_address(c_sock.port())));

    let (packet, _) = recv();
    let (message, _) = actx
        .rd_safe(&packet)
        .unwrap_or_else(|e| die(&progname, krb5_message(&e), "while verifying SAFE message"));
    println!("Safe message is: '{}'", String::from_utf8_lossy(&message));

    let (packet, _) = recv();
    let (message, _) = actx
        .rd_priv(&packet)
        .unwrap_or_else(|e| die(&progname, krb5_message(&e), "while verifying PRIV message"));
    println!(
        "Decrypted message is: '{}'",
        String::from_utf8_lossy(&message)
    );
}
