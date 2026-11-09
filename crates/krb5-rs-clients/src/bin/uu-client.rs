//! `uu-client` (MIT `appl/user_user/client.c`): send our TGT to
//! `uu-server`, then check its user-to-user AP-REQ and KRB-SAFE message.

use std::sync::Arc;

use krb5_rs::ccache::{default_cache, unparse_name, CcContext, Ccache};
use krb5_rs::client::{CredsRequest, GcOptions};
use krb5_rs::kdc::kdb::kprop::service_port;
use krb5_rs::protocol::ap::{ApError, AuthContext, AuthContextFlags, KeySource};
use krb5_rs::protocol::sendauth::{read_message, write_message};
use krb5_rs::types::{EncryptionKey, PrincipalName};
use krb5_rs_clients::{krb5_message, set_full_addrs};

/// The TGT session key (`krb5_auth_con_setuseruserkey`).
struct UserUserKey(EncryptionKey);

impl KeySource for UserUserKey {
    fn get_key(
        &self,
        _server: &PrincipalName,
        _realm: &[u8],
        _kvno: Option<i32>,
        _etype: i32,
    ) -> Result<EncryptionKey, ApError> {
        Ok(self.0.clone())
    }
}

fn die(msg: impl std::fmt::Display, context: &str) -> ! {
    eprintln!("uu-client: {msg} {context}");
    std::process::exit(1)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 || args.len() > 4 {
        eprintln!("usage: uu-client <hostname> [message [port]]");
        std::process::exit(1);
    }
    let host = args[1].as_str();
    let port = match args.get(3) {
        Some(p) => p.trim().parse().unwrap_or(0),
        None => service_port("uu-sample").unwrap_or_else(|| {
            eprintln!("uu-client: unknown service \"uu-sample/tcp\"");
            std::process::exit(2)
        }),
    };
    let profile = Arc::new(krb5_rs_clients::profile());
    let rt = krb5_rs_clients::runtime();

    let addr = std::net::ToSocketAddrs::to_socket_addrs(&(host, port))
        .ok()
        .and_then(|mut a| a.find(std::net::SocketAddr::is_ipv4))
        .unwrap_or_else(|| {
            eprintln!("uu-client: can't get address of host \"{host}\".");
            std::process::exit(3)
        });
    let mut stream = rt
        .block_on(tokio::net::TcpStream::connect(addr))
        .unwrap_or_else(|e| die(e, &format!("connecting to \"{host}\" ({addr}).")));

    let ctx = CcContext::from_env(Some(&profile));
    let mut cc = default_cache(&ctx).unwrap_or_else(|e| die(e, "getting credentials cache"));
    let (client, crealm) = cc
        .principal()
        .unwrap_or_else(|e| die(e, "getting principal name"));
    let princ = unparse_name(&client, &crealm);
    eprintln!("uu-client: client principal is \"{princ}\".");

    let kc = krb5_rs_clients::kerberos_client(&profile, &crealm);
    let req = CredsRequest {
        client: client.clone(),
        crealm: crealm.clone(),
        server: PrincipalName::new_srv_inst("krbtgt", &crealm),
        srealm: crealm.clone(),
        enctype: 0,
        authdata: None,
        second_ticket: None,
    };
    let tgt = rt
        .block_on(kc.get_credentials(&mut cc, GcOptions::CACHED, &req))
        .unwrap_or_else(|e| die(krb5_message(&e), "getting TGT"));
    let ticket = rasn::der::encode(&tgt.ticket).unwrap_or_else(|e| die(e, "getting TGT"));

    eprintln!(
        "uu-client: sending {} bytes",
        ticket.len() + princ.len() + 1
    );
    let mut pname = princ.into_bytes();
    pname.push(0);
    rt.block_on(async {
        write_message(&mut stream, &pname)
            .await
            .unwrap_or_else(|e| die(e, "sending principal name to server"));
        write_message(&mut stream, &ticket)
            .await
            .unwrap_or_else(|e| die(e, "sending ticket to server"));
        let ap_req = read_message(&mut stream)
            .await
            .unwrap_or_else(|e| die(e, "reading reply from server"));

        let mut actx = AuthContext::new();
        actx.set_flags(AuthContextFlags::DO_SEQUENCE);
        let local = stream
            .local_addr()
            .unwrap_or_else(|e| die(e, "generating addrs for auth_context"));
        let remote = stream
            .peer_addr()
            .unwrap_or_else(|e| die(e, "generating addrs for auth_context"));
        set_full_addrs(&mut actx, &local, &remote);
        let key = UserUserKey(tgt.session_key.clone());
        let auth = actx
            .rd_req(&ap_req, None, &key)
            .unwrap_or_else(|e| die(krb5_message(&e), "reading AP_REQ from server"));
        let crealm = String::from_utf8_lossy(auth.ticket.crealm.as_bytes()).to_string();
        println!(
            "server is named \"{}\"",
            unparse_name(&auth.ticket.cname, &crealm)
        );

        let safe = read_message(&mut stream)
            .await
            .unwrap_or_else(|e| die(e, "reading reply from server"));
        let (msg, _) = actx
            .rd_safe(&safe)
            .unwrap_or_else(|e| die(krb5_message(&e), "decoding reply from server"));
        let text = msg.split(|&b| b == 0).next().unwrap_or_default();
        println!(
            "uu-client: server says \"{}\".",
            String::from_utf8_lossy(text)
        );
    });
}
