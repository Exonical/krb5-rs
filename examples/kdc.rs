//! Minimal KDC daemon for a single realm, serving principals from a keytab.
//!
//! Usage: cargo run --example kdc --features kdc,tokio -- \
//!   --realm EXAMPLE.COM --keytab service.keytab [--listen 0.0.0.0:88]... \
//!   [--max-life SECS] [--max-renewable-life SECS]
//!
//! Every keytab entry becomes a principal that requires pre-authentication.
//! Passwords are never accepted on the command line.

use std::sync::Arc;
use std::time::Duration;

use krb5_rs::kdc::{
    serve_tcp, serve_udp, Kdc, KdcConfig, MemoryStore, PrincipalAttributes, PrincipalStore,
};
use krb5_rs::keytab::FileKeytab;
use krb5_rs::types::PrincipalName;
use tokio::net::{TcpListener, UdpSocket};

fn usage() -> ! {
    eprintln!(
        "usage: kdc --realm REALM --keytab PATH [--listen ADDR]... \
         [--max-life SECS] [--max-renewable-life SECS]"
    );
    std::process::exit(2);
}

fn secs(value: Option<String>) -> Duration {
    Duration::from_secs(
        value
            .and_then(|v| v.parse().ok())
            .unwrap_or_else(|| usage()),
    )
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let mut realm = None;
    let mut keytab = None;
    let mut listen: Vec<String> = Vec::new();
    let mut max_life = None;
    let mut max_renewable_life = None;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--realm" => realm = args.next(),
            "--keytab" => keytab = args.next(),
            "--listen" => listen.extend(args.next()),
            "--max-life" => max_life = Some(secs(args.next())),
            "--max-renewable-life" => max_renewable_life = Some(secs(args.next())),
            _ => usage(),
        }
    }
    let (Some(realm), Some(keytab)) = (realm, keytab) else {
        usage()
    };
    if listen.is_empty() {
        listen.push("0.0.0.0:88".to_string());
    }

    let mut store = MemoryStore::new();
    store
        .import_keytab(
            &FileKeytab::new(&keytab),
            PrincipalAttributes::REQUIRES_PRE_AUTH,
        )
        .map_err(|e| std::io::Error::other(format!("reading keytab {keytab}: {e}")))?;

    let tgs = PrincipalName::new_srv_inst("krbtgt", &realm);
    if store.lookup(&tgs, &realm).ok().flatten().is_none() {
        eprintln!(
            "warning: no krbtgt/{realm}@{realm} in keytab; generated a random one \
             (issued tickets will not survive a restart)"
        );
        store
            .add_random_key(tgs, &realm, 1, &[18, 17], PrincipalAttributes::empty())
            .map_err(|e| std::io::Error::other(e.to_string()))?;
    }

    let mut config = KdcConfig::new(realm);
    if let Some(d) = max_life {
        config.max_life = d;
    }
    if let Some(d) = max_renewable_life {
        config.max_renewable_life = d;
    }
    let kdc = Arc::new(Kdc::new(config, store));

    let mut tasks = Vec::new();
    for addr in &listen {
        let udp = UdpSocket::bind(addr).await?;
        let tcp = TcpListener::bind(addr).await?;
        println!("listening on {} (udp+tcp)", tcp.local_addr()?);
        tasks.push(tokio::spawn(serve_udp(Arc::clone(&kdc), udp)));
        tasks.push(tokio::spawn(serve_tcp(Arc::clone(&kdc), tcp)));
    }
    for task in tasks {
        task.await.map_err(std::io::Error::other)??;
    }
    Ok(())
}
