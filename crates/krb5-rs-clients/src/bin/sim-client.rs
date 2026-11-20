//! MIT `sim_client` (src/appl/simple/client/sim_client.c): sends an
//! AP-REQ, a KRB_SAFE and a KRB_PRIV message over UDP.

use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::sync::Arc;

use krb5_rs::ccache::{default_cache, CcContext, Ccache};
use krb5_rs::client::{CredsRequest, GcOptions};
use krb5_rs::kdc::kdb::kprop::{host_address, service_port};
use krb5_rs::protocol::ap::{ApReqOptions, AuthContext};
use krb5_rs_clients::{ipport_address, krb5_message, sname_to_principal};

/// simple.h.
const SIMPLE_SERVICE: &str = "sample";
const SIMPLE_PORT: &str = "sample";
const MSG: &str = "hi there!";

fn usage(name: &str) {
    eprintln!("usage: {name} [-p port] [-h host] [-m message] [-s service] [host]");
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
    let args: Vec<String> = std::env::args().collect();
    let progname = args.first().cloned().unwrap_or_default();
    let mut port = 0u16;
    let mut message = MSG.to_string();
    let mut hostname: Option<String> = None;
    let mut service = SIMPLE_SERVICE.to_string();

    // getopt(argc, argv, "p:m:h:s:") with opterr = 0.
    let mut i = 1;
    while i < args.len() {
        let a = &args[i];
        if a == "--" {
            i += 1;
            break;
        }
        if !a.starts_with('-') || a == "-" {
            break;
        }
        // Every option takes an argument.
        let c = a[1..].chars().next().unwrap_or('?');
        if !matches!(c, 'p' | 'm' | 'h' | 's') {
            usage(&progname);
            std::process::exit(1);
        }
        let rest = &a[1 + c.len_utf8()..];
        let val = if !rest.is_empty() {
            rest.to_string()
        } else {
            i += 1;
            match args.get(i) {
                Some(v) => v.clone(),
                None => {
                    usage(&progname);
                    std::process::exit(1);
                }
            }
        };
        match c {
            'p' => port = atoi_short(&val),
            'm' => message = val,
            'h' => hostname = Some(val),
            _ => service = val,
        }
        i += 1;
    }
    if let Some(h) = args.get(i) {
        if hostname.is_some() {
            usage(&progname);
        }
        hostname = Some(h.clone());
    }
    let Some(hostname) = hostname else {
        eprintln!("You must specify a hostname to contact.\n");
        usage(&progname);
        std::process::exit(1);
    };

    // gethostbyname: the first IPv4 address.
    let ip = (hostname.as_str(), 0)
        .to_socket_addrs()
        .ok()
        .and_then(|mut a| a.find(SocketAddr::is_ipv4))
        .map(|a| a.ip());
    let Some(ip) = ip else {
        eprintln!("{hostname}: unknown host");
        std::process::exit(1);
    };
    if port == 0 {
        match service_port(SIMPLE_PORT) {
            Some(p) => port = p,
            None => {
                eprintln!("service unknown: {SIMPLE_PORT}/udp");
                std::process::exit(1);
            }
        }
    }
    let s_sock = SocketAddr::new(ip, port);

    let sock = UdpSocket::bind("0.0.0.0:0")
        .unwrap_or_else(|e| die(&progname, e, "while binding datagram socket"));

    let profile = Arc::new(krb5_rs_clients::profile());
    let rt = krb5_rs_clients::runtime();
    let ctx = CcContext::from_env(Some(&profile));
    let mut cc =
        default_cache(&ctx).unwrap_or_else(|e| die(&progname, e, "while getting default ccache"));
    // krb5_mk_req: sname_to_principal, then the default cache's client.
    let (server, srealm) = sname_to_principal(&rt, &profile, Some(&hostname), &service);
    let (client, crealm) = cc
        .principal()
        .unwrap_or_else(|e| die(&progname, e, "while preparing AP_REQ"));
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
        .unwrap_or_else(|e| die(&progname, krb5_message(&e), "while preparing AP_REQ"));
    let mut actx = AuthContext::new();
    let opts = ApReqOptions {
        use_subkey: true,
        ..Default::default()
    };
    let packet = actx
        .mk_req(&opts, Some(hostname.as_bytes()), &cred)
        .unwrap_or_else(|e| die(&progname, krb5_message(&e), "while preparing AP_REQ"));
    println!("Got credentials for {service}.");

    sock.connect(s_sock)
        .unwrap_or_else(|e| die(&progname, e, "while connecting to server"));
    let send = |data: &[u8], context: &str| -> i64 {
        match sock.send(data) {
            Ok(n) => i64::try_from(n).unwrap_or(i64::MAX),
            Err(e) => {
                eprintln!("{progname}: {e} {context}");
                -1
            }
        }
    };
    let n = send(&packet, "while sending KRB_AP_REQ message");
    println!("Sent authentication data: {n} bytes");

    let local = sock
        .local_addr()
        .unwrap_or_else(|e| die(&progname, e, "while getting socket name"));
    actx.set_ports(Some(ipport_address(local.port())), None);
    actx.set_addrs(Some(host_address(&local)), None);

    let (packet, _) = actx
        .mk_safe(message.as_bytes())
        .unwrap_or_else(|e| die(&progname, krb5_message(&e), "while making KRB_SAFE message"));
    let n = send(&packet, "while sending SAFE message");
    println!("Sent checksummed message: {n} bytes");

    let (packet, _) = actx
        .mk_priv(message.as_bytes())
        .unwrap_or_else(|e| die(&progname, krb5_message(&e), "while making KRB_PRIV message"));
    let n = send(&packet, "while sending PRIV message");
    println!("Sent encrypted message: {n} bytes");
}
