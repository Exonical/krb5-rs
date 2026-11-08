#![cfg(all(feature = "client", unix))]
//! MIT interop for client password changes and verify_init_creds: our
//! client against MIT 1.22's krb5kdc and kadmind in the Compose stack's
//! KDC container (`KRB5_LIVE_CONTAINER`, default `krb5-rs-kdc-1`).
//! Run with `cargo test --test client_chpw_live -- --ignored`.

use std::net::SocketAddr;
use std::process::Command;

use krb5_rs::client::chpw::{change_password, changepw_principal, set_password};
use krb5_rs::client::vfy::VerifyInitCredsOptions;
use krb5_rs::client::KerberosClient;
use krb5_rs::keytab::FileKeytab;
use krb5_rs::locate::Locator;
use krb5_rs::profile::Profile;
use krb5_rs::protocol::kpasswd::{KPASSWD_ACCESSDENIED, KPASSWD_SUCCESS};
use krb5_rs::protocol::{AsExchangeConfig, Credential};
use krb5_rs::transport::UdpTcpTransport;
use krb5_rs::types::PrincipalName;

const REALM: &str = "TEST.REALM";

fn cli() -> String {
    std::env::var("CONTAINER_CLI").unwrap_or_else(|_| "docker".into())
}

fn container() -> String {
    std::env::var("KRB5_LIVE_CONTAINER").unwrap_or_else(|_| "krb5-rs-kdc-1".into())
}

fn sh(script: &str) -> String {
    let out = Command::new(cli())
        .args(["exec", &container(), "sh", "-c", script])
        .output()
        .expect("container exec");
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn kadmin_local(q: &str) {
    sh(&format!("kadmin.local -q '{q}' >/dev/null 2>&1"));
}

fn host() -> String {
    let out = Command::new(cli())
        .args([
            "inspect",
            "-f",
            "{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}",
            &container(),
        ])
        .output()
        .expect("inspect");
    String::from_utf8_lossy(&out.stdout)
        .split_whitespace()
        .next()
        .expect("container address")
        .to_string()
}

/// Start MIT kadmind with `chpwadmin` allowed everything.
fn setup(tag: &str) -> (String, Profile) {
    sh("echo 'chpwadmin@TEST.REALM *' > /etc/krb5kdc/kadm5.acl; \
        pgrep kadmind >/dev/null || kadmind; sleep 1");
    kadmin_local("addprinc -pw admin-pw chpwadmin");
    for p in ["user", "target"] {
        kadmin_local(&format!("delprinc -force chpw{p}{tag}"));
        kadmin_local(&format!("addprinc -pw {p}-old chpw{p}{tag}"));
    }
    let h = host();
    let profile = Profile::parse(&format!(
        "[realms]\n{REALM} = {{\n kdc = {h}:88\n kpasswd_server = {h}:464\n}}\n"
    ))
    .expect("profile");
    (h, profile)
}

fn client(h: &str) -> KerberosClient<UdpTcpTransport> {
    let addr: SocketAddr = format!("{h}:88").parse().expect("addr");
    KerberosClient::new(REALM, UdpTcpTransport::new(addr))
}

async fn as_req(
    h: &str,
    who: &str,
    pw: &str,
    server: Option<PrincipalName>,
) -> Result<Credential, krb5_rs::Krb5Error> {
    let mut config = AsExchangeConfig::new(PrincipalName::new_principal(who), REALM);
    config.server = server;
    client(h).acquire_tgt_with_config(config, pw).await
}

#[tokio::test]
#[ignore = "needs the MIT KDC container"]
async fn change_and_set_password_against_mit_kadmind() {
    let (h, p) = setup("a");
    let loc = Locator::new(&p, None);

    let creds = as_req(&h, "chpwusera", "user-old", Some(changepw_principal()))
        .await
        .expect("changepw ticket");
    let res = change_password(&loc, &creds, "user-new-1")
        .await
        .expect("chpw");
    assert_eq!(res.result_code, KPASSWD_SUCCESS, "{}", res.message());
    as_req(&h, "chpwusera", "user-new-1", None)
        .await
        .expect("new password works");

    // MIT kadmind refuses a non-self set without the ACL.
    let creds = as_req(&h, "chpwusera", "user-new-1", Some(changepw_principal()))
        .await
        .expect("changepw ticket");
    let target = PrincipalName::new_principal("chpwtargeta");
    let res = set_password(&loc, &creds, "target-new", Some((&target, REALM)))
        .await
        .expect("setpw");
    assert_eq!(res.result_code, KPASSWD_ACCESSDENIED, "{}", res.message());

    // An admin with the ACL may set it (RFC 3244).
    let creds = as_req(&h, "chpwadmin", "admin-pw", Some(changepw_principal()))
        .await
        .expect("admin changepw ticket");
    let res = set_password(&loc, &creds, "target-new", Some((&target, REALM)))
        .await
        .expect("setpw");
    assert_eq!(res.result_code, KPASSWD_SUCCESS, "{}", res.message());
    as_req(&h, "chpwtargeta", "target-new", None)
        .await
        .expect("target password set");
}

#[tokio::test]
#[ignore = "needs the MIT KDC container"]
async fn verify_init_creds_against_mit_kdc() {
    let (h, _) = setup("b");
    kadmin_local("addprinc -randkey host/vfy.test.realm");
    sh("rm -f /tmp/vfy.kt");
    kadmin_local("ktadd -k /tmp/vfy.kt host/vfy.test.realm");
    let dir = std::env::temp_dir().join(format!("krb5rs_vfy_live_{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("dir");
    let kt = dir.join("vfy.kt");
    let st = Command::new(cli())
        .args(["cp", &format!("{}:/tmp/vfy.kt", container())])
        .arg(&kt)
        .status()
        .expect("cp");
    assert!(st.success());

    let tgt = as_req(&h, "chpwuserb", "user-old", None)
        .await
        .expect("tgt");
    let keytab = FileKeytab::new(&kt);
    client(&h)
        .verify_init_creds(
            &tgt,
            None,
            Some(&keytab),
            None,
            &VerifyInitCredsOptions::default(),
        )
        .await
        .expect("verify against MIT-issued host ticket");

    // A rekeyed host principal no longer matches our keytab.
    kadmin_local("cpw -randkey host/vfy.test.realm");
    assert!(client(&h)
        .verify_init_creds(
            &tgt,
            None,
            Some(&keytab),
            None,
            &VerifyInitCredsOptions::default()
        )
        .await
        .is_err());
    let _ = std::fs::remove_dir_all(&dir);
}
