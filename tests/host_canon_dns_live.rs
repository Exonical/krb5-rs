#![cfg(all(feature = "client", feature = "kdc"))]
//! The DNS step of host-name canonicalization (MIT os/sn2princ.c
//! `expand_hostname`) against a real resolver. Inside the MIT 1.22.2 test
//! image, with no network, a DNS server answers on 127.0.0.1:53 and
//! `/etc/hosts` has an alias; MIT's `krb5_sname_to_principal` and ours
//! must produce the same names, with and without `rdns`.

use std::net::{Ipv4Addr, UdpSocket};
use std::process::Command;
use std::sync::{Arc, Mutex};

use hickory_proto::op::{Message, MessageType, ResponseCode};
use hickory_proto::rr::rdata::{A, CNAME, PTR};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use krb5_rs::ccache::{CcCredential, Ccache, MemoryCcache};
use krb5_rs::client::{CanonHost, CredsRequest, GcOptions, HostCanonicalization, KerberosClient};
use krb5_rs::kdc::kdb::kprop::{CanonMode, HostCanon};
use krb5_rs::protocol::{Credential, TicketTimes};
use krb5_rs::transport::KdcTransport;
use krb5_rs::types::{
    EncryptedData, EncryptionKey, KerberosFlags, KrbErrorMsg, PrincipalName, Ticket, TicketFlags,
};
use krb5_rs::Krb5Error;
use rasn::types::{GeneralString, OctetString};

const INSIDE: &str = "KRB5RS_HOST_CANON_DNS_INSIDE";
const REALM: &str = "EXAMPLE.TEST";
const HOSTS: &[&str] = &[
    "web.example.test",
    "chain.example.test",
    "Mixed.Example.Test",
    "plain.example.test",
    "hostsalias",
    "web",
    "missing.example.test",
];

#[test]
#[ignore = "needs docker or podman and the MIT test image (CONTAINER_CLI, MIT_IMAGE)"]
fn mit_and_krb5_rs_canonicalize_host_names_alike_through_dns() {
    if std::env::var_os(INSIDE).is_some() {
        return;
    }
    let cli = std::env::var("CONTAINER_CLI").unwrap_or_else(|_| "podman".into());
    let image = std::env::var("MIT_IMAGE").unwrap_or_else(|_| "krb5-rs-mit-test:1.22.2".into());
    let exe = std::env::current_exe().expect("test binary");
    // The test binary runs on the host's glibc (its loader and libraries
    // mounted at /hostlib), which may be newer than the image's, and reads
    // the container's resolv.conf, nsswitch.conf and hosts.
    let loader = std::fs::canonicalize("/lib64/ld-linux-x86-64.so.2").expect("host loader");
    let libdir = loader.parent().expect("loader dir");
    let out = Command::new(cli)
        .args(["run", "--rm", "--network", "none", "-e"])
        .arg(format!("{INSIDE}=1"))
        .arg("-v")
        .arg(format!("{}:/t/test:ro", exe.display()))
        .arg("-v")
        .arg(format!("{}:/hostlib:ro", libdir.display()))
        .args(["--entrypoint", "/hostlib/ld-linux-x86-64.so.2", &image])
        .args(["--library-path", "/hostlib", "/t/test"])
        .args([
            "--ignored",
            "--exact",
            "--nocapture",
            "inside_the_container",
        ])
        .output()
        .expect("run the container");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(out.status.success(), "{text}");
    assert!(text.contains("1 passed"), "{text}");
}

#[test]
#[ignore = "run inside the MIT image by the test above"]
fn inside_the_container() {
    if std::env::var_os(INSIDE).is_none() {
        return;
    }
    let mut hosts = std::fs::read_to_string("/etc/hosts").expect("hosts");
    hosts.push_str("10.0.0.7 hostsreal.example.test hostsalias\n");
    std::fs::write("/etc/hosts", hosts).expect("write hosts");
    std::fs::write(
        "/etc/resolv.conf",
        "nameserver 127.0.0.1\noptions timeout:1 attempts:1\n",
    )
    .expect("write resolv.conf");
    let socket = UdpSocket::bind("127.0.0.1:53").expect("bind :53");
    std::thread::spawn(move || serve(&socket));

    build_mit_sn2princ();
    let rt = tokio::runtime::Runtime::new().expect("runtime");
    for rdns in [false, true] {
        let mit = mit_names(rdns);
        assert_eq!(mit.len(), HOSTS.len(), "{mit:?}");
        let expected: Vec<&str> = if rdns {
            vec![
                "rev.example.test",
                "rev.example.test",
                "rev.example.test",
                "plain.example.test",
                "hostsreal.example.test",
                "web.example.test",
                "missing.example.test",
            ]
        } else {
            vec![
                "real.example.test",
                "real.example.test",
                "real.example.test",
                "plain.example.test",
                "hostsreal.example.test",
                "web.example.test",
                "missing.example.test",
            ]
        };
        assert_eq!(mit, expected, "MIT krb5_sname_to_principal, rdns = {rdns}");
        for (host, mit) in HOSTS.iter().zip(&mit) {
            let kprop = HostCanon {
                mode: CanonMode::True,
                rdns,
                qualify: Some("example.test".into()),
            };
            assert_eq!(
                kprop.candidates(host),
                std::slice::from_ref(mit),
                "kprop {host} rdns={rdns}"
            );
            let tried = rt.block_on(client_candidates(host, rdns));
            // Each name is a referral request, then a non-referral retry
            // (get_creds.c try_fallback).
            let mut want = vec![non_dns(host); 2];
            if *mit != want[0] {
                want.extend([mit.clone(), mit.clone()]);
            }
            assert_eq!(tried, want, "client {host} rdns={rdns}");
        }
    }
}

/// `expand_hostname` without DNS: qualified, lowercased.
fn non_dns(host: &str) -> String {
    let host = host.to_ascii_lowercase();
    if host.contains('.') {
        host
    } else {
        format!("{host}.example.test")
    }
}

fn build_mit_sn2princ() {
    std::fs::write(
        "/tmp/sn2princ.c",
        r#"#include <krb5.h>
#include <stdio.h>
int main(int argc, char **argv) {
    krb5_context ctx;
    krb5_principal p;
    char *s;
    int i;
    if (krb5_init_context(&ctx))
        return 1;
    for (i = 1; i < argc; i++) {
        if (krb5_sname_to_principal(ctx, argv[i], "host", KRB5_NT_SRV_HST, &p) ||
            krb5_unparse_name(ctx, p, &s))
            return 2;
        printf("%s\n", s);
        krb5_free_unparsed_name(ctx, s);
        krb5_free_principal(ctx, p);
    }
    return 0;
}
"#,
    )
    .expect("write sn2princ.c");
    let out = Command::new("sh")
        .args([
            "-c",
            "gcc -o /tmp/sn2princ /tmp/sn2princ.c $(krb5-config --cflags --libs krb5)",
        ])
        .output()
        .expect("gcc");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

fn mit_names(rdns: bool) -> Vec<String> {
    std::fs::write(
        "/tmp/krb5.conf",
        format!(
            "[libdefaults]\n default_realm = {REALM}\n dns_canonicalize_hostname = true\n \
             rdns = {rdns}\n qualify_shortname = example.test\n"
        ),
    )
    .expect("write krb5.conf");
    let out = Command::new("/tmp/sn2princ")
        .args(HOSTS)
        .env("KRB5_CONFIG", "/tmp/krb5.conf")
        .output()
        .expect("sn2princ");
    assert!(out.status.success(), "{out:?}");
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(|l| {
            l.strip_prefix("host/")
                .and_then(|l| l.split('@').next())
                .expect("host/name@realm")
                .to_string()
        })
        .collect()
}

/// The TGS-REQ server names our client tries for `host/<host>` with
/// `dns_canonicalize_hostname = fallback`, when the KDC knows none of them.
async fn client_candidates(host: &str, rdns: bool) -> Vec<String> {
    let log = Arc::new(Mutex::new(Vec::new()));
    let client = KerberosClient::new(REALM, Unknown(Arc::clone(&log))).with_host_canonicalization(
        HostCanonicalization {
            dns_canonicalize_hostname: CanonHost::Fallback,
            rdns,
            qualify_shortname: Some("example.test".into()),
        },
    );
    let user = PrincipalName::new_principal("alice");
    let mut cc = MemoryCcache::new();
    cc.initialize(&user, REALM).expect("initialize");
    cc.store(&CcCredential::from(&tgt(&user)))
        .expect("store TGT");
    let req = CredsRequest::new(user, REALM, PrincipalName::new_srv_hst("host", host), REALM);
    let r = client
        .get_credentials(&mut cc, GcOptions::empty(), &req)
        .await;
    assert!(
        matches!(r, Err(Krb5Error::KdcError(ref m)) if m.error_code == 7),
        "{r:?}"
    );
    let tried = log.lock().expect("log").clone();
    tried
}

fn gs(s: &str) -> GeneralString {
    GeneralString::from_bytes(s.as_bytes()).expect("ascii")
}

fn tgt(user: &PrincipalName) -> Credential {
    let now = chrono::Utc::now().fixed_offset();
    let krbtgt = PrincipalName::new_srv_inst("krbtgt", REALM);
    Credential {
        client: user.clone(),
        crealm: REALM.into(),
        server: krbtgt.clone(),
        srealm: REALM.into(),
        session_key: EncryptionKey::new(18, vec![7; 32]),
        times: TicketTimes {
            authtime: now,
            starttime: Some(now),
            endtime: now + chrono::Duration::hours(1),
            renew_till: None,
        },
        ticket: Ticket {
            tkt_vno: 5,
            realm: gs(REALM),
            sname: krbtgt,
            enc_part: EncryptedData {
                etype: 18,
                kvno: Some(1),
                cipher: OctetString::from(vec![0u8; 64]),
            },
        },
        flags: KerberosFlags::new(TicketFlags::INITIAL),
        addresses: None,
        authdata: None,
    }
}

/// A KDC that logs each TGS-REQ's second sname component and answers
/// KDC_ERR_S_PRINCIPAL_UNKNOWN.
struct Unknown(Arc<Mutex<Vec<String>>>);

impl KdcTransport for Unknown {
    async fn send_recv(&self, realm: &str, message: &[u8]) -> Result<Vec<u8>, Krb5Error> {
        let req = rasn::der::decode::<krb5_rs::types::TgsReq>(message).expect("TGS-REQ");
        let sname = req.0.req_body.sname.expect("sname");
        self.0
            .lock()
            .expect("log")
            .push(String::from_utf8_lossy(sname.name_string[1].as_bytes()).into_owned());
        let err = KrbErrorMsg {
            pvno: 5,
            msg_type: 30,
            ctime: None,
            cusec: None,
            stime: chrono::Utc::now().fixed_offset(),
            susec: 0,
            error_code: 7,
            crealm: None,
            cname: None,
            realm: gs(realm),
            sname,
            e_text: None,
            e_data: None,
        };
        Ok(rasn::der::encode(&err).expect("KRB-ERROR"))
    }
}

fn name(s: &str) -> Name {
    Name::from_ascii(s).expect("name")
}

/// A one-zone DNS server: CNAME chains, A records and PTRs.
fn serve(socket: &UdpSocket) {
    let cnames = [
        ("web.example.test.", "Real.Example.Test."),
        ("chain.example.test.", "web.example.test."),
        ("mixed.example.test.", "web.example.test."),
    ];
    let addrs = [
        ("real.example.test.", Ipv4Addr::new(10, 0, 0, 5)),
        ("plain.example.test.", Ipv4Addr::new(10, 0, 0, 6)),
    ];
    let ptrs = [("5.0.0.10.in-addr.arpa.", "rev.example.test.")];
    let mut buf = [0u8; 1500];
    loop {
        let Ok((n, peer)) = socket.recv_from(&mut buf) else {
            continue;
        };
        let Ok(query) = Message::from_vec(&buf[..n]) else {
            continue;
        };
        let mut reply = Message::new();
        reply
            .set_id(query.id())
            .set_message_type(MessageType::Response)
            .set_op_code(query.op_code())
            .set_recursion_desired(query.recursion_desired())
            .set_recursion_available(true)
            .set_authoritative(true);
        let mut found = false;
        if let Some(q) = query.queries().first() {
            reply.add_query(q.clone());
            let mut owner = q.name().to_ascii().to_ascii_lowercase();
            while let Some((_, target)) = cnames.iter().find(|(from, _)| *from == owner) {
                reply.add_answer(Record::from_rdata(
                    name(&owner),
                    60,
                    RData::CNAME(CNAME(name(target))),
                ));
                owner = target.to_ascii_lowercase();
                found = true;
            }
            if let Some((_, ip)) = addrs.iter().find(|(n, _)| *n == owner) {
                found = true;
                if q.query_type() == RecordType::A {
                    reply.add_answer(Record::from_rdata(name(&owner), 60, RData::A(A(*ip))));
                }
            }
            if let Some((_, target)) = ptrs.iter().find(|(n, _)| *n == owner) {
                found = true;
                if q.query_type() == RecordType::PTR {
                    reply.add_answer(Record::from_rdata(
                        name(&owner),
                        60,
                        RData::PTR(PTR(name(target))),
                    ));
                }
            }
        }
        reply.set_response_code(if found {
            ResponseCode::NoError
        } else {
            ResponseCode::NXDomain
        });
        if let Ok(bytes) = reply.to_vec() {
            let _ = socket.send_to(&bytes, peer);
        }
    }
}
