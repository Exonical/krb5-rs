#![cfg(feature = "tokio")]
//! ONC RPC and RPCSEC_GSS client/server, checked against MIT's
//! `src/lib/rpc/auth_gss.c`, `svc_auth_gss.c` and `authgss_prot.c`.

use krb5_rs::gssapi::krb5::{GssFlags, Krb5Acceptor, Krb5Initiator};
use krb5_rs::protocol::ap::{ApError, KeySource};
use krb5_rs::rpc::gss::{
    proc_, wrap_body, Cred, GssClient, GssServer, InitRes, ServerStep, Service, SEQ_WINDOW,
    SERVER_HANDLE,
};
use krb5_rs::rpc::xdr::{XdrReader, XdrWriter};
use krb5_rs::rpc::{
    read_record, write_record, AcceptStat, AuthStat, Call, CallHeader, OpaqueAuth, Reply, RpcError,
    RPCSEC_GSS,
};
use krb5_rs::types::*;

#[path = "common/mod.rs"]
mod common;
use common::fixtures::{random_key, svc_cred};

const PROG: u32 = 100_423;
const VERS: u32 = 1;

struct OneKey(EncryptionKey);

impl KeySource for OneKey {
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

fn pair() -> (Krb5Initiator, GssServer) {
    let skey = random_key(18);
    let (cred, _) = svc_cred(&skey, 18);
    let init = Krb5Initiator::new(cred, None, GssFlags::MUTUAL | GssFlags::REPLAY, None)
        .expect("initiator");
    let server = GssServer::new(Box::new(move || {
        Krb5Acceptor::new(Box::new(OneKey(skey.clone())), None, None)
    }));
    (init, server)
}

async fn serve<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    mut stream: S,
    mut server: GssServer,
) {
    while let Ok(Some(record)) = read_record(&mut stream).await {
        let call = Call::decode(&record).expect("call");
        let out = match server.handle(&call) {
            ServerStep::Send(r) => r,
            ServerStep::Dispatch { proc_, args, seq } => {
                let mut res = args;
                res.reverse();
                res.extend_from_slice(&proc_.to_be_bytes());
                server.reply(call.header.xid, seq, &res).expect("reply")
            }
        };
        write_record(&mut stream, &out).await.expect("write");
    }
}

#[tokio::test]
async fn client_and_server_exchange_calls_with_every_service() {
    for service in [Service::None, Service::Integrity, Service::Privacy] {
        let (init, server) = pair();
        let (a, b) = tokio::io::duplex(1 << 16);
        let client = async move {
            let mut client = GssClient::connect(a, PROG, VERS, 7, init, service)
                .await
                .expect("connect");
            for i in 0..40u32 {
                let args = i.to_be_bytes();
                let got = client.call(1, &args).await.expect("call");
                let mut want = args.to_vec();
                want.reverse();
                want.extend_from_slice(&1u32.to_be_bytes());
                assert_eq!(got, want, "{service:?} call {i}");
            }
            client.destroy().await.expect("destroy");
        };
        tokio::join!(serve(b, server), client);
    }
}

#[test]
fn cred_and_init_res_match_the_rfc_2203_layout() {
    let cred = Cred {
        version: 1,
        proc_: proc_::DATA,
        seq: 5,
        service: Service::Privacy as u32,
        handle: SERVER_HANDLE.to_vec(),
    };
    let bytes = cred.encode();
    assert_eq!(
        bytes,
        [0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 5, 0, 0, 0, 3, 0, 0, 0, 4, b'x', b'x', b'x', b'x']
    );
    assert_eq!(Cred::decode(&bytes).expect("cred"), cred);
    let res = InitRes {
        handle: b"ab".to_vec(),
        major: 1,
        minor: 2,
        window: 32,
        token: b"tok".to_vec(),
    };
    let bytes = res.encode();
    assert_eq!(
        bytes,
        [
            0, 0, 0, 2, b'a', b'b', 0, 0, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 32, 0, 0, 0, 3, b't',
            b'o', b'k', 0
        ]
    );
    assert_eq!(InitRes::decode(&bytes).expect("res"), res);
}

#[tokio::test]
async fn records_may_arrive_in_several_fragments() {
    let (mut a, mut b) = tokio::io::duplex(1024);
    use tokio::io::AsyncWriteExt;
    a.write_all(&[0, 0, 0, 2, 1, 2, 0x80, 0, 0, 1, 3])
        .await
        .expect("write");
    assert_eq!(
        read_record(&mut b).await.expect("read"),
        Some(vec![1, 2, 3])
    );
    write_record(&mut a, b"xyz").await.expect("write");
    drop(a);
    assert_eq!(
        read_record(&mut b).await.expect("read"),
        Some(b"xyz".to_vec())
    );
    assert_eq!(read_record(&mut b).await.expect("eof"), None);
    let (mut a, mut b) = tokio::io::duplex(64);
    a.write_all(&[0xff, 0xff, 0xff, 0xff]).await.expect("write");
    assert!(read_record(&mut b).await.is_err());
}

fn header(xid: u32, proc_: u32, cred: &Cred) -> CallHeader {
    CallHeader {
        xid,
        prog: PROG,
        vers: VERS,
        proc_,
        cred: OpaqueAuth {
            flavor: RPCSEC_GSS,
            body: cred.encode(),
        },
        verf: OpaqueAuth::none(),
    }
}

fn sent(step: ServerStep) -> Reply {
    match step {
        ServerStep::Send(r) => Reply::decode(&r).expect("reply").1,
        ServerStep::Dispatch { .. } => panic!("unexpected dispatch"),
    }
}

fn cred(proc_: u32, seq: u32) -> Cred {
    Cred {
        version: 1,
        proc_,
        seq,
        service: Service::Integrity as u32,
        handle: SERVER_HANDLE.to_vec(),
    }
}

fn establish() -> (krb5_rs::gssapi::krb5::Krb5Context, GssServer) {
    let (mut init, mut server) = pair();
    let token = match init.step(None).expect("step") {
        krb5_rs::gssapi::krb5::InitStep::Continue(t) => t,
        krb5_rs::gssapi::krb5::InitStep::Complete(_) => panic!("mutual"),
    };
    let mut args = XdrWriter::default();
    args.opaque(&token);
    let mut c = cred(proc_::INIT, 0);
    c.handle.clear();
    let call = Call {
        header: header(1, 0, &c),
        args: args.0,
    };
    let Reply::Accepted {
        verf,
        stat: AcceptStat::Success,
        results,
    } = sent(server.handle(&call))
    else {
        panic!("init rejected");
    };
    let res = InitRes::decode(&results).expect("res");
    assert_eq!(res.major, 0);
    assert_eq!(res.window, SEQ_WINDOW);
    assert_eq!(res.handle, SERVER_HANDLE);
    init.step(Some(&res.token)).expect("ap-rep");
    let mut ctx = init.context().expect("ctx");
    ctx.verify_mic(&SEQ_WINDOW.to_be_bytes(), &verf.body)
        .expect("window verifier");
    (ctx, server)
}

fn data_call(
    ctx: &mut krb5_rs::gssapi::krb5::Krb5Context,
    xid: u32,
    c: &Cred,
    args: &[u8],
) -> Call {
    let mut h = header(xid, 1, c);
    h.verf = OpaqueAuth {
        flavor: RPCSEC_GSS,
        body: ctx.get_mic(&h.signed_part()).expect("mic"),
    };
    Call {
        header: h,
        args: wrap_body(ctx, Service::Integrity, c.seq, args).expect("wrap"),
    }
}

#[test]
fn server_rejects_bad_credentials_like_mit() {
    let (mut ctx, mut server) = establish();
    let mut c = cred(proc_::DATA, 1);
    let mut none = data_call(&mut ctx, 2, &c, b"");
    none.header.cred.flavor = 0;
    assert_eq!(
        sent(server.handle(&none)),
        Reply::AuthError(AuthStat::BadCred)
    );
    c.version = 2;
    let call = data_call(&mut ctx, 3, &c, b"");
    assert_eq!(
        sent(server.handle(&call)),
        Reply::AuthError(AuthStat::BadCred)
    );
    c.version = 1;
    c.service = 4;
    let call = data_call(&mut ctx, 4, &c, b"");
    assert_eq!(
        sent(server.handle(&call)),
        Reply::AuthError(AuthStat::BadCred)
    );
    let call = data_call(&mut ctx, 5, &cred(9, 2), b"");
    assert_eq!(
        sent(server.handle(&call)),
        Reply::AuthError(AuthStat::RejectedCred)
    );
    let mut call = data_call(&mut ctx, 6, &cred(proc_::DATA, 3), b"");
    call.header.verf.body[0] ^= 1;
    assert_eq!(
        sent(server.handle(&call)),
        Reply::AuthError(AuthStat::GssCredProblem)
    );
    let mut init = Call {
        header: header(7, 1, &cred(proc_::INIT, 0)),
        args: Vec::new(),
    };
    assert_eq!(
        sent(server.handle(&init)),
        Reply::AuthError(AuthStat::Failed)
    );
    init.header.proc_ = 0;
    assert_eq!(
        sent(server.handle(&init)),
        Reply::AuthError(AuthStat::GssCtxProblem)
    );
    let (_, mut fresh) = pair();
    init.args = vec![0, 0, 0, 1, 0x60, 0, 0, 0];
    assert_eq!(
        sent(fresh.handle(&init)),
        Reply::AuthError(AuthStat::RejectedCred)
    );
}

#[test]
fn server_enforces_the_sequence_window() {
    let (mut ctx, mut server) = establish();
    let call = data_call(&mut ctx, 2, &cred(proc_::DATA, 40), b"a");
    assert!(matches!(
        server.handle(&call),
        ServerStep::Dispatch { seq: 40, .. }
    ));
    assert_eq!(
        sent(server.handle(&call)),
        Reply::AuthError(AuthStat::GssCtxProblem)
    );
    let old = data_call(&mut ctx, 3, &cred(proc_::DATA, 8), b"a");
    assert_eq!(
        sent(server.handle(&old)),
        Reply::AuthError(AuthStat::GssCtxProblem)
    );
    let in_window = data_call(&mut ctx, 4, &cred(proc_::DATA, 9), b"a");
    assert!(matches!(
        server.handle(&in_window),
        ServerStep::Dispatch { seq: 9, .. }
    ));
    let huge = data_call(&mut ctx, 5, &cred(proc_::DATA, 0x8000_0001), b"a");
    assert_eq!(
        sent(server.handle(&huge)),
        Reply::AuthError(AuthStat::GssCtxProblem)
    );
}

#[test]
fn server_checks_the_inner_sequence_number_and_protection() {
    let (mut ctx, mut server) = establish();
    let c = cred(proc_::DATA, 1);
    let mut call = data_call(&mut ctx, 2, &c, b"args");
    call.args = wrap_body(&mut ctx, Service::Integrity, 2, b"args").expect("wrap");
    assert_eq!(
        sent(server.handle(&call)),
        Reply::Accepted {
            verf: OpaqueAuth::none(),
            stat: AcceptStat::GarbageArgs,
            results: Vec::new()
        }
    );
    let mut call = data_call(&mut ctx, 3, &cred(proc_::DATA, 2), b"args");
    let n = call.args.len();
    call.args[n - 1] ^= 1;
    assert!(matches!(
        sent(server.handle(&call)),
        Reply::Accepted {
            stat: AcceptStat::GarbageArgs,
            ..
        }
    ));
    let call = data_call(&mut ctx, 4, &cred(proc_::DATA, 3), b"args");
    let ServerStep::Dispatch { args, seq, .. } = server.handle(&call) else {
        panic!("dispatch");
    };
    assert_eq!((args.as_slice(), seq), (&b"args"[..], 3));
    let reply = server.reply(4, 3, b"res").expect("reply");
    let Reply::Accepted { verf, results, .. } = Reply::decode(&reply).expect("decode").1 else {
        panic!("accepted");
    };
    ctx.verify_mic(&3u32.to_be_bytes(), &verf.body)
        .expect("verf");
    let mut r = XdrReader::new(&results);
    let body = r.opaque().expect("body").to_vec();
    let mic = r.opaque().expect("mic");
    ctx.verify_mic(&body, mic).expect("mic");
    assert_eq!(body, [0, 0, 0, 3, b'r', b'e', b's']);
}

#[test]
fn calls_after_destroy_have_no_context() {
    let (mut ctx, mut server) = establish();
    let destroy = {
        let c = cred(proc_::DESTROY, 1);
        let mut h = header(9, 0, &c);
        h.verf = OpaqueAuth {
            flavor: RPCSEC_GSS,
            body: ctx.get_mic(&h.signed_part()).expect("mic"),
        };
        Call {
            header: h,
            args: Vec::new(),
        }
    };
    assert!(matches!(
        sent(server.handle(&destroy)),
        Reply::Accepted {
            stat: AcceptStat::Success,
            ..
        }
    ));
    assert!(server.context().is_none());
    let call = data_call(&mut ctx, 10, &cred(proc_::DATA, 2), b"");
    assert_eq!(
        sent(server.handle(&call)),
        Reply::AuthError(AuthStat::GssCredProblem)
    );
    let err = RpcError::Auth(AuthStat::GssCredProblem);
    assert!(err.to_string().contains("GssCredProblem"));
}
