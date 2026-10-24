//! MIT 1.22.2 ONC RPC/RPCSEC_GSS interoperability: the krb5-rs RPC client
//! authenticates to MIT `kadmind -proponly` as `kiprop/<host>` and calls the
//! iprop program (`ipropd_svc.c`). Uses the MIT container of `klmdb_live`.

use std::io::Write;
use std::net::{IpAddr, SocketAddr};
use std::process::{Command, Stdio};
use std::sync::Arc;

use krb5_rs::gssapi::krb5::{GssFlags, Krb5Initiator};
use krb5_rs::kdc::kdb::mit::ulog::{Last, Time, XdrReader as UlogReader};
use krb5_rs::keytab::{key_for_principal, FileKeytab};
use krb5_rs::profile::Profile;
use krb5_rs::protocol::{AsExchange, AsExchangeConfig, Credential, StepResult};
use krb5_rs::rpc::gss::{GssClient, Service};
use krb5_rs::rpc::{AuthStat, RpcError};
use krb5_rs::transport::{KdcTransport, LocatedTransport};
use krb5_rs::types::PrincipalName;
use tokio::net::TcpStream;

const DEFAULT_CONTAINER: &str = "krb5-rs-kdc-1";
const REALM: &str = "IPROP.RPC";
const BASE: &str = "/tmp/krb5rs-oncrpc-live";
const KDC_PORT: u16 = 18788;
const IPROP_PORT: u16 = 18754;
const IPROP_PROG: u32 = 100_423;
const IPROP_VERS: u32 = 1;
const UPDATE_OK: u32 = 0;
const UPDATE_FULL_RESYNC_NEEDED: u32 = 2;
const UPDATE_NIL: u32 = 4;
const UPDATE_PERM_DENIED: u32 = 5;

fn container_cli() -> String {
    std::env::var("CONTAINER_CLI").unwrap_or_else(|_| "podman".into())
}

fn mit_container() -> String {
    std::env::var("KLMDB_LIVE_CONTAINER").unwrap_or_else(|_| DEFAULT_CONTAINER.into())
}

fn cli(args: &[&str]) -> String {
    let out = Command::new(container_cli())
        .args(args)
        .output()
        .expect("run container CLI");
    assert!(
        out.status.success(),
        "{args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn script(body: &str) -> String {
    let mut child = Command::new(container_cli())
        .args(["exec", "-i", &mit_container(), "bash", "-s"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start MIT container shell");
    let prelude = format!(
        "set -euo pipefail\nB={BASE}\nREALM={REALM}\n\
         export KRB5_CONFIG=$B/krb5.conf KRB5_KDC_PROFILE=$B/kdc.conf\n"
    );
    child
        .stdin
        .take()
        .expect("script stdin")
        .write_all(format!("{prelude}{body}").as_bytes())
        .expect("write script");
    let out = child.wait_with_output().expect("wait for MIT script");
    assert!(
        out.status.success(),
        "MIT script failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

const SETUP: &str = r#"
for p in kdc kadmind; do [ -f $B/$p.pid ] && kill "$(cat $B/$p.pid)" 2>/dev/null || true; done
rm -rf $B && mkdir -p $B && cd $B
cat > kdc.conf <<EOF
[kdcdefaults]
    kdc_listen = 18788
    kdc_tcp_listen = 18788
[realms]
    $REALM = {
        database_module = lmdb
        database_name = $B/principal
        key_stash_file = $B/stash
        acl_file = $B/kadm5.acl
        master_key_type = aes256-cts-hmac-sha1-96
        supported_enctypes = aes256-cts-hmac-sha1-96:normal
        iprop_enable = true
        iprop_ulogsize = 100
        iprop_port = 18754
        kadmind_port = 18749
        kpasswd_port = 18464
        kdc_listen = 18788
        kdc_tcp_listen = 18788
    }
[dbmodules]
    lmdb = {
        db_library = klmdb
    }
[logging]
    kdc = FILE:$B/kdc.log
    admin_server = FILE:$B/kadmind.log
EOF
cat > krb5.conf <<EOF
[libdefaults]
    default_realm = $REALM
[realms]
    $REALM = {
        kdc = 127.0.0.1:18788
    }
EOF
echo "kiprop/replica.iprop@$REALM p" > kadm5.acl
kdb5_util create -s -P master-password-for-oncrpc >/dev/null
for p in kiprop/kdc.test.realm kiprop/replica.iprop kiprop/rogue.iprop; do
  kadmin.local -q "getprinc $p" 2>/dev/null | grep -q '^Principal:' || kadmin.local -q "addprinc -randkey $p" >/dev/null
done
kadmin.local -q "ktadd -k $B/client.keytab kiprop/replica.iprop kiprop/rogue.iprop" >/dev/null
chmod 0644 $B/client.keytab
setsid nohup krb5kdc -n -P $B/kdc.pid >$B/kdc.out 2>&1 < /dev/null &
setsid nohup kadmind -nofork -proponly -P $B/kadmind.pid >$B/kadmind.out 2>&1 < /dev/null &
for i in $(seq 100); do
  (echo > /dev/tcp/127.0.0.1/18754) 2>/dev/null && (echo > /dev/tcp/127.0.0.1/18788) 2>/dev/null && break
  sleep 0.1
done
(echo > /dev/tcp/127.0.0.1/18754) 2>/dev/null || { cat $B/kadmind.out $B/kadmind.log >&2; exit 1; }
"#;

const MARK: &str = r#"
cd $B
kdb5_util dump -i1 $B/mark >/dev/null
head -1 $B/mark
"#;

const CHANGES: &str = r#"
kadmin.local -q "addprinc -randkey alice" >/dev/null
kadmin.local -q "addprinc -randkey bob" >/dev/null
"#;

const TEARDOWN: &str = r#"
for p in kdc kadmind; do [ -f $B/$p.pid ] && kill "$(cat $B/$p.pid)" 2>/dev/null || true; done
rm -rf $B
"#;

fn mark(header: &str) -> Last {
    let f: Vec<u32> = header
        .split_whitespace()
        .skip(2)
        .map(|v| v.parse().expect("ipropx header field"))
        .collect();
    assert_eq!(f.len(), 3, "ipropx header: {header}");
    Last {
        sno: f[0],
        time: Time {
            seconds: f[1],
            useconds: f[2],
        },
    }
}

fn principal(name: &str) -> PrincipalName {
    let (service, host) = name.split_once('/').expect("service/host");
    PrincipalName::new_srv_hst(service, host)
}

async fn ticket(
    transport: &LocatedTransport,
    keytab: &FileKeytab,
    client: &str,
    server: &str,
) -> Credential {
    let client = principal(client);
    let key = key_for_principal(keytab, &client, REALM).expect("client key");
    let mut config = AsExchangeConfig::new(client, REALM);
    config.server = Some(principal(server));
    let mut exchange = AsExchange::with_key(config, key);
    let mut reply = Vec::new();
    loop {
        match exchange.step(&reply).expect("AS exchange") {
            StepResult::SendToKdc { data, realm } | StepResult::RetryTcp { data, realm } => {
                reply = transport.send_recv(&realm, &data).await.expect("KDC");
            }
            StepResult::Complete => return exchange.credential().cloned().expect("credential"),
        }
    }
}

async fn connect(addr: SocketAddr, cred: Credential) -> Result<GssClient<TcpStream>, RpcError> {
    let stream = TcpStream::connect(addr).await.expect("connect to kadmind");
    let init = Krb5Initiator::new(cred, None, GssFlags::MUTUAL | GssFlags::REPLAY, None)
        .expect("initiator");
    GssClient::connect(
        stream,
        IPROP_PROG,
        IPROP_VERS,
        0x1234,
        init,
        Service::Privacy,
    )
    .await
}

fn last_args(last: &Last) -> Vec<u8> {
    let mut v = Vec::new();
    for n in [last.sno, last.time.seconds, last.time.useconds] {
        v.extend_from_slice(&n.to_be_bytes());
    }
    v
}

fn incr_result(bytes: &[u8]) -> (Last, Vec<Vec<u8>>, u32) {
    let mut r = UlogReader::new(bytes);
    let last = r.last().expect("lastentry");
    let n = r.u32().expect("update count");
    let names = (0..n)
        .map(|_| r.update().expect("update").princ_name)
        .collect();
    let ret = r.u32().expect("ret");
    assert_eq!(r.remaining(), 0, "trailing result bytes");
    (last, names, ret)
}

#[tokio::test]
#[ignore = "requires the MIT 1.22.2 container"]
async fn krb5_rs_rpc_client_calls_mit_kadmind_iprop() {
    script(SETUP);
    let ip: IpAddr = cli(&[
        "inspect",
        "-f",
        "{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}",
        &mit_container(),
    ])
    .split_whitespace()
    .next()
    .expect("container address")
    .parse()
    .expect("container IP");
    let dir = tempfile::tempdir().expect("tempdir");
    let keytab_path = dir.path().join("client.keytab");
    cli(&[
        "cp",
        &format!("{}:{BASE}/client.keytab", mit_container()),
        &keytab_path.to_string_lossy(),
    ]);
    let keytab = FileKeytab::new(keytab_path);
    let profile = Profile::parse(&format!(
        "[realms]\n    {REALM} = {{\n        kdc = {ip}:{KDC_PORT}\n    }}\n"
    ))
    .expect("profile");
    let transport = LocatedTransport::new(Arc::new(profile), None);
    let iprop = SocketAddr::new(ip, IPROP_PORT);
    let target = "kiprop/kdc.test.realm";

    let before = mark(&script(MARK));
    script(CHANGES);
    let after = mark(&script(MARK));
    assert_eq!(after.sno, before.sno + 2);

    let cred = ticket(&transport, &keytab, "kiprop/replica.iprop", target).await;
    let mut client = connect(iprop, cred).await.expect("RPCSEC_GSS context");
    assert!(client.call(0, &[]).await.expect("IPROP_NULL").is_empty());

    let res = client
        .call(1, &last_args(&before))
        .await
        .expect("get updates");
    let (last, names, ret) = incr_result(&res);
    assert_eq!(ret, UPDATE_OK);
    assert_eq!(last.sno, after.sno);
    assert_eq!(
        names,
        [
            format!("alice@{REALM}").into_bytes(),
            format!("bob@{REALM}").into_bytes()
        ]
    );

    let res = client.call(1, &last_args(&after)).await.expect("nil");
    let (_, names, ret) = incr_result(&res);
    assert_eq!((ret, names.len()), (UPDATE_NIL, 0));

    let stale = Last {
        sno: after.sno + 50,
        time: after.time,
    };
    let res = client.call(1, &last_args(&stale)).await.expect("resync");
    assert_eq!(incr_result(&res).2, UPDATE_FULL_RESYNC_NEEDED);
    client.destroy().await.expect("destroy");

    let cred = ticket(&transport, &keytab, "kiprop/rogue.iprop", target).await;
    let mut rogue = connect(iprop, cred).await.expect("rogue context");
    let res = rogue.call(1, &last_args(&before)).await.expect("denied");
    let (_, names, ret) = incr_result(&res);
    assert_eq!((ret, names.len()), (UPDATE_PERM_DENIED, 0));

    let cred = ticket(&transport, &keytab, "kiprop/replica.iprop", "kadmin/admin").await;
    let mut wrong = connect(iprop, cred).await.expect("kadmin/admin context");
    let err = wrong
        .call(1, &last_args(&before))
        .await
        .expect_err("weak auth");
    assert!(
        matches!(err, RpcError::Auth(AuthStat::TooWeak)),
        "unexpected {err:?}"
    );

    script(TEARDOWN);
    println!("ONCRPC_LIVE_OK");
}
