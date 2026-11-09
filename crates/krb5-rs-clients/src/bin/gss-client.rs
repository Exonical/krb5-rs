//! gss-client (appl/gss-sample/gss-client.c).

use std::io::Write;
use std::net::TcpStream;
use std::process::exit;
use std::sync::Arc;

use krb5_rs::ccache::{default_cache, parse_principal, unparse_name, CcContext, Ccache};
use krb5_rs::client::{CredStore, CredsRequest, GcOptions, KerberosClient};
use krb5_rs::gssapi::cred::CredUsage;
use krb5_rs::gssapi::iakerb::{IakerbCred, IakerbInitiator};
use krb5_rs::gssapi::krb5::{InitStep, Krb5Context, Krb5Initiator, MECH_IAKERB, MECH_KRB5};
use krb5_rs::gssapi::spnego::SpnegoInitiator;
use krb5_rs::gssapi::GssFlags;
use krb5_rs::profile::Profile;
use krb5_rs::protocol::Credential;
use krb5_rs::transport::LocatedTransport;
use krb5_rs::types::PrincipalName;
use krb5_rs::Krb5Error;
use krb5_rs_clients::gss_sample::*;
use krb5_rs_clients::{kerberos_client, profile, runtime, sname_to_principal};

fn num<T: std::str::FromStr>(a: Option<String>) -> T {
    a.and_then(|v| v.parse().ok()).unwrap_or_else(|| usage())
}

fn usage() -> ! {
    eprint!("Usage: gss-client [-port port] [-mech mechanism] [-spnego] [-d]");
    eprintln!("\n       [-seq] [-noreplay] [-nomutual] [-user user] [-pass pw]");
    eprintln!("       [-f] [-q] [-ccount count] [-mcount count]");
    eprintln!("       [-v1] [-na] [-nw] [-nx] [-nm] host service msg");
    exit(1);
}

#[derive(PartialEq)]
enum Mech {
    Krb5,
    Iakerb,
}

struct Opts {
    port: u16,
    mech: Mech,
    spnego: bool,
    flags: GssFlags,
    user: Option<String>,
    pass: Option<String>,
    verbose: bool,
    v1: bool,
    auth: bool,
    wrap: bool,
    encrypt: bool,
    mic: bool,
    host: String,
    service: String,
    msg: Vec<u8>,
}

struct Env {
    profile: Arc<Profile>,
    rt: tokio::runtime::Runtime,
    ctx: CcContext,
}

fn main() {
    let mut args = std::env::args().skip(1).peekable();
    let mut o = Opts {
        port: 4444,
        mech: Mech::Krb5,
        spnego: false,
        flags: GssFlags::MUTUAL | GssFlags::REPLAY,
        user: None,
        pass: None,
        verbose: true,
        v1: false,
        auth: true,
        wrap: true,
        encrypt: true,
        mic: true,
        host: String::new(),
        service: String::new(),
        msg: Vec::new(),
    };
    let (mut use_file, mut ccount, mut mcount) = (false, 1u32, 1u32);
    while let Some(a) = args.next_if(|a| a.starts_with('-')) {
        match a.as_str() {
            "-port" => o.port = num(args.next()),
            "-mech" => {
                let m = args.next().unwrap_or_else(|| usage());
                o.mech = match str_to_oid(&m) {
                    Some(oid) if oid == MECH_KRB5 => Mech::Krb5,
                    Some(oid) if oid == MECH_IAKERB => Mech::Iakerb,
                    _ => {
                        println!(
                            "GSS-API error str_to_oid: An unsupported mechanism was requested"
                        );
                        exit(1);
                    }
                };
            }
            "-iakerb" => o.mech = Mech::Iakerb,
            "-krb5" => o.mech = Mech::Krb5,
            "-spnego" => o.spnego = true,
            "-d" => o.flags |= GssFlags::DELEG,
            "-seq" => o.flags |= GssFlags::SEQUENCE,
            "-noreplay" => o.flags.remove(GssFlags::REPLAY),
            "-nomutual" => o.flags.remove(GssFlags::MUTUAL),
            "-dce" => o.flags |= GssFlags::DCE_STYLE,
            "-user" => o.user = Some(args.next().unwrap_or_else(|| usage())),
            "-pass" => o.pass = Some(args.next().unwrap_or_else(|| usage())),
            "-f" => use_file = true,
            "-q" => o.verbose = false,
            "-ccount" => {
                ccount = num(args.next());
                if ccount == 0 {
                    usage();
                }
            }
            "-mcount" => mcount = num(args.next()),
            "-v1" => o.v1 = true,
            "-na" => (o.auth, o.wrap, o.encrypt, o.mic) = (false, false, false, false),
            "-nw" => o.wrap = false,
            "-nx" => o.encrypt = false,
            "-nm" => o.mic = false,
            _ => usage(),
        }
    }
    let rest: Vec<String> = args.collect();
    let [host, service, msg] = rest.as_slice() else {
        usage();
    };
    o.host = host.clone();
    o.service = service.clone();
    o.msg = if use_file {
        std::fs::read(msg).unwrap_or_else(|_| {
            eprintln!("Couldn't open file {msg}");
            exit(1);
        })
    } else {
        msg.as_bytes().to_vec()
    };
    let profile = Arc::new(profile());
    let env = Env {
        ctx: CcContext::from_env(Some(&profile)),
        rt: runtime(),
        profile,
    };
    for _ in 0..ccount {
        if call_server(&o, &env, mcount).is_err() {
            exit(1);
        }
    }
}

enum Init {
    Krb5(Box<Krb5Initiator>),
    Spnego(Box<SpnegoInitiator>),
    Iakerb(Box<IakerbInitiator>),
}

impl Init {
    fn step(&mut self, input: Option<&[u8]>) -> Result<InitStep, Krb5Error> {
        match self {
            Init::Krb5(i) => i.step(input),
            Init::Spnego(i) => i.step(input),
            Init::Iakerb(i) => i.step(input),
        }
    }

    fn context(self) -> Result<Krb5Context, Krb5Error> {
        match self {
            Init::Krb5(i) => i.context(),
            Init::Spnego(i) => i.context(),
            Init::Iakerb(i) => i.context(),
        }
    }
}

fn out() -> std::io::Stdout {
    std::io::stdout()
}

fn fail(msg: &str, e: &Krb5Error) {
    display_status(&mut out(), msg, e);
}

/// The client principal: `-user`, else the default cache's.
fn client_name(o: &Opts, env: &Env) -> Option<(PrincipalName, String)> {
    match &o.user {
        Some(u) => {
            let realm = env.profile.get_string(&["libdefaults", "default_realm"]);
            parse_principal(u, realm.as_deref())
        }
        None => default_cache(&env.ctx).ok()?.principal().ok(),
    }
}

/// The client's TGT from the default cache, for delegation and IAKERB.
fn cached_tgt(env: &Env, client: &PrincipalName, crealm: &str) -> Option<Credential> {
    let mut cc = default_cache(&env.ctx).ok()?;
    let kc = kerberos_client(&env.profile, crealm);
    let req = CredsRequest {
        client: client.clone(),
        crealm: crealm.to_string(),
        server: PrincipalName::new_srv_inst("krbtgt", crealm),
        srealm: crealm.to_string(),
        enctype: 0,
        authdata: None,
        second_ticket: None,
    };
    env.rt
        .block_on(kc.get_credentials(&mut cc, GcOptions::CACHED, &req))
        .ok()
}

fn initiator(o: &Opts, env: &Env, server: PrincipalName, srealm: &str) -> Result<Init, ()> {
    if o.mech == Mech::Iakerb {
        let Some((client, realm)) = client_name(o, env) else {
            fail(
                "acquiring creds",
                &Krb5Error::Gss(krb5_rs::gssapi::GssError::NoCred),
            );
            return Err(());
        };
        let tgt = o
            .pass
            .is_none()
            .then(|| cached_tgt(env, &client, &realm))
            .flatten();
        let cred = IakerbCred {
            client,
            realm,
            password: o.pass.clone(),
            tgt,
            service: None,
        };
        let init = IakerbInitiator::new(cred, server, Default::default(), o.flags, None);
        return Ok(Init::Iakerb(Box::new(init)));
    }
    let name = match &o.user {
        Some(_) => match client_name(o, env) {
            Some(n) => Some(n.0),
            None => {
                fail(
                    "parsing client name",
                    &Krb5Error::Gss(krb5_rs::gssapi::GssError::BadName),
                );
                return Err(());
            }
        },
        None => None,
    };
    let realm = client_name(o, env).map_or_else(|| srealm.to_string(), |n| n.1);
    let kc: KerberosClient<LocatedTransport> = kerberos_client(&env.profile, &realm);
    let store = CredStore {
        password: o.pass.clone(),
        ..Default::default()
    };
    let mut cred = env
        .rt
        .block_on(kc.acquire_cred_from(
            &env.ctx,
            Some(&env.profile),
            name.as_ref(),
            CredUsage::Initiate,
            &store,
            false,
        ))
        .map_err(|e| fail("acquiring creds", &e))?;
    let svc = env
        .rt
        .block_on(kc.gss_service_cred(&env.ctx, &mut cred, server, srealm))
        .map_err(|e| fail("initializing context", &e))?;
    let tgt = if o.flags.contains(GssFlags::DELEG) {
        cached_tgt(env, &svc.client, &svc.crealm)
    } else {
        None
    };
    let init = Krb5Initiator::new(svc, tgt, o.flags, None)
        .map_err(|e| fail("initializing context", &e))?;
    Ok(if o.spnego {
        Init::Spnego(Box::new(SpnegoInitiator::new(
            init,
            vec![MECH_KRB5.to_vec()],
        )))
    } else {
        Init::Krb5(Box::new(init))
    })
}

/// client_establish_context.
fn establish(o: &Opts, env: &Env, s: &mut TcpStream) -> Result<(Krb5Context, String), ()> {
    let (hostpart, svc) = match o.service.split_once('@') {
        Some((svc, host)) => (Some(host), svc),
        None => (None, o.service.as_str()),
    };
    let (server, srealm) = sname_to_principal(&env.rt, &env.profile, hostpart, svc);
    let mut init = initiator(o, env, server.clone(), &srealm)?;
    if !o.v1 {
        send_token(s, TOKEN_NOOP | TOKEN_CONTEXT_NEXT, &[]).map_err(|_| ())?;
    }
    let ctx_flag = if o.v1 { 0 } else { TOKEN_CONTEXT };
    let mut input: Option<Vec<u8>> = None;
    loop {
        let step = init.step(input.as_deref());
        let (tok, cont) = match step {
            Ok(InitStep::Continue(t)) => (Some(t), true),
            Ok(InitStep::Complete(t)) => (t, false),
            Err(e) => {
                fail("initializing context", &e);
                return Err(());
            }
        };
        if let Some(t) = tok {
            if o.verbose {
                print!("Sending init_sec_context token (size={})...", t.len());
                let _ = out().flush();
            }
            send_token(s, ctx_flag, &t).map_err(|_| ())?;
        }
        if !cont {
            if o.verbose {
                println!();
            }
            break;
        }
        if o.verbose {
            print!("continue needed...");
            let _ = out().flush();
        }
        let (_, t) = recv_token(s).map_err(|e| println!("{e}"))?;
        input = Some(t);
        if o.verbose {
            println!();
        }
    }
    let ctx = init
        .context()
        .map_err(|e| fail("initializing context", &e))?;
    if o.verbose {
        display_ctx_flags(&mut out(), ctx.flags());
    }
    let target = unparse_name(&server, &srealm);
    Ok((ctx, target))
}

/// call_server.
fn call_server(o: &Opts, env: &Env, mcount: u32) -> Result<(), ()> {
    let mut s = match TcpStream::connect((o.host.as_str(), o.port)) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("connecting to server: {e}");
            return Err(());
        }
    };
    let mut ctx = None;
    if o.auth {
        let (c, target) = establish(o, env, &mut s)?;
        if o.verbose {
            let src = unparse_name(c.initiator(), c.initiator_realm());
            println!(
                "\"{src}\" to \"{target}\", lifetime {}, flags {:x}, locally initiated, open",
                c.lifetime().as_secs(),
                c.flags().bits()
            );
            println!(
                "Name type of source name is {}.",
                oid_to_str(b"\x2a\x86\x48\x86\xf7\x12\x01\x02\x02\x01")
            );
            println!(
                "Mechanism {} supports {} names",
                oid_to_str(c.mech()),
                KRB5_NAME_TYPES.len()
            );
            for (i, t) in KRB5_NAME_TYPES.iter().enumerate() {
                println!("  {i}: {}", oid_to_str(t));
            }
        }
        ctx = Some(c);
    } else if send_token(&mut s, TOKEN_NOOP, &[]).is_err() {
        return Err(());
    }
    for _ in 0..mcount {
        let body = match (&mut ctx, o.wrap) {
            (Some(c), true) => c
                .wrap(o.encrypt, &o.msg)
                .map_err(|e| fail("wrapping message", &e))?,
            _ => o.msg.clone(),
        };
        let mut flags = TOKEN_DATA;
        if o.wrap {
            flags |= TOKEN_WRAPPED;
        }
        if o.encrypt {
            flags |= TOKEN_ENCRYPTED;
        }
        if o.mic {
            flags |= TOKEN_SEND_MIC;
        }
        send_token(&mut s, if o.v1 { 0 } else { flags }, &body).map_err(|_| ())?;
        let (_, reply) = recv_token(&mut s).map_err(|e| println!("{e}"))?;
        match (&mut ctx, o.mic) {
            (Some(c), true) => {
                c.verify_mic(&o.msg, &reply)
                    .map_err(|e| fail("verifying signature", &e))?;
                if o.verbose {
                    println!("Signature verified.");
                }
            }
            _ => {
                if o.verbose {
                    println!("Response received.");
                }
            }
        }
    }
    if !o.v1 {
        let _ = send_token(&mut s, TOKEN_NOOP, &[]);
    }
    Ok(())
}
