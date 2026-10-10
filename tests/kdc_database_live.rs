#![cfg(all(feature = "kdc", feature = "tokio"))]
//! Live checks of the persistent database against real MIT artefacts.
//!
//! Requires podman + the compose container (`podman compose -f
//! docker-compose.test.yml up -d kdc`). Run with:
//!   cargo test --all-features --test kdc_database_live -- --ignored --test-threads=1

use std::io::Write;
use std::process::{Command, Stdio};
use std::sync::Arc;

use krb5_rs::kdc::kdb::admin::{Admin, AttrChange, PrincipalOptions};
use krb5_rs::kdc::kdb::{master_key_from_password, read_stash, write_stash, FileStore};
use krb5_rs::kdc::{serve_tcp, serve_udp, Kdc, RealmConfig};
use krb5_rs::profile::Profile;
use krb5_rs::types::PrincipalName;
use tokio::net::{TcpListener, UdpSocket};

#[path = "common/mod.rs"]
mod common;
use common::kdc::{cp_out, KDC_CONTAINER};

const MIT_STASH: &str = "/etc/krb5kdc/stash";
const REALM: &str = "DBLIVE.REALM";
const PORT: u16 = 10390;
const PASSWORD: &str = "db-live-password";

fn host() -> String {
    std::env::var("KDC_LIVE_HOST").unwrap_or_else(|_| "192.168.127.254".into())
}

fn run(cmd: &str, stdin: Option<&str>) -> (i32, String) {
    let mut child = Command::new(common::kdc::container_cli())
        .args(["exec", "-i", KDC_CONTAINER, "bash", "-c", cmd])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("podman exec");
    {
        let mut pipe = child.stdin.take().expect("stdin");
        if let Some(s) = stdin {
            pipe.write_all(s.as_bytes()).expect("write stdin");
        }
    }
    let out = child.wait_with_output().expect("wait");
    (
        out.status.code().unwrap_or(-1),
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ),
    )
}

#[test]
#[ignore = "requires podman + MIT client container"]
fn mit_stash_file_matches_master_key_derived_from_password() {
    let local = cp_out(MIT_STASH, "mit_stash");
    let from_stash = read_stash(&local, "TEST.REALM").expect("read MIT stash");
    let derived = master_key_from_password("TEST.REALM", "masterkey", 18).expect("derive");
    assert_eq!(from_stash.keytype, derived.keytype);
    assert_eq!(from_stash.key_bytes(), derived.key_bytes());

    // Our writer produces a stash our reader (and MIT's keytab format) accepts.
    let ours = common::kdc::tmp("our_stash");
    let _ = std::fs::remove_file(&ours);
    write_stash(&ours, "TEST.REALM", &derived).expect("write stash");
    assert_eq!(
        read_stash(&ours, "TEST.REALM")
            .expect("read back")
            .key_bytes(),
        derived.key_bytes()
    );
    let _ = std::fs::remove_file(&ours);
}

#[test]
#[ignore = "requires podman + MIT client container"]
fn mit_kinit_succeeds_against_kdc_backed_by_file_store_from_kdc_conf() {
    let dir = common::kdc::tmp("dblive");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("dir");
    let d = dir.to_string_lossy().replace('\\', "/");
    let conf_text = format!(
        "[realms]\n {REALM} = {{\n  database_name = {d}/principal\n  \
         key_stash_file = {d}/stash\n  kdc_listen = {PORT}\n  max_renewable_life = 7d\n }}\n"
    );
    let cfg =
        RealmConfig::from_profiles(&Profile::parse(&conf_text).expect("kdc.conf"), None, REALM)
            .expect("realm config");

    let master = master_key_from_password(REALM, "master-pw", cfg.master_key_type).expect("master");
    let etypes: Vec<i32> = cfg.supported_keysalts.iter().map(|(e, _)| *e).collect();
    FileStore::create_with(&cfg.database_name, REALM, &master, &etypes).expect("create db");
    write_stash(&cfg.key_stash_file, REALM, &master).expect("stash");

    let store = FileStore::open(
        &cfg.database_name,
        &read_stash(&cfg.key_stash_file, REALM).expect("read stash"),
    )
    .expect("open db");
    let store = Arc::new(store);
    let admin = Admin::new(&store, cfg.supported_keysalts.clone());
    let mut opts = PrincipalOptions::default();
    let mut attrs = AttrChange::default();
    attrs.add_spec("+requires_preauth").expect("spec");
    opts.attributes = attrs;
    admin
        .add_principal(
            &PrincipalName::new_principal("alice"),
            REALM,
            Some(PASSWORD),
            &opts,
        )
        .expect("addprinc");

    let kdc = Arc::new(Kdc::new(cfg.kdc.clone(), Arc::clone(&store)));
    let addrs = cfg.udp_listen.clone();
    let tcp_addrs = cfg.tcp_listen.clone();
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().expect("runtime");
        rt.block_on(async move {
            for addr in addrs {
                if let Ok(s) = UdpSocket::bind(addr).await {
                    tokio::spawn(serve_udp(Arc::clone(&kdc), s));
                }
            }
            for addr in tcp_addrs {
                if let Ok(l) = TcpListener::bind(addr).await {
                    tokio::spawn(serve_tcp(Arc::clone(&kdc), l));
                }
            }
            ready_tx.send(()).expect("ready");
            std::future::pending::<()>().await;
        });
    });
    ready_rx.recv().expect("servers started");

    let conf = "/tmp/rust-krb5-dblive.conf";
    let krb5 = format!(
        "[libdefaults]\n default_realm = {REALM}\n dns_lookup_kdc = false\n \
         dns_lookup_realm = false\n[realms]\n {REALM} = {{\n  kdc = {}:{PORT}\n }}\n",
        host()
    );
    let (code, out) = run(&format!("cat > {conf}"), Some(&krb5));
    assert_eq!(code, 0, "write krb5.conf: {out}");

    let env = format!("KRB5_CONFIG={conf} KRB5CCNAME=/tmp/cc_dblive");
    let (code, out) = run(
        &format!("{env} kinit alice@{REALM}"),
        Some(&format!("{PASSWORD}\n")),
    );
    assert_eq!(code, 0, "kinit: {out}");
    let (code, klist) = run(&format!("{env} klist"), None);
    assert_eq!(code, 0, "klist: {klist}");
    assert!(
        klist.contains(&format!("krbtgt/{REALM}@{REALM}")),
        "{klist}"
    );

    let (code, out) = run(
        &format!("{env} kinit alice@{REALM}"),
        Some("wrong-password\n"),
    );
    assert_ne!(code, 0, "{out}");
    assert!(out.contains("Password incorrect"), "{out}");
    let _ = std::fs::remove_dir_all(&dir);
}
