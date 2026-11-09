//! gss-server (appl/gss-sample/gss-server.c).

use std::io::Write;
use std::net::{TcpListener, TcpStream};
use std::process::exit;
use std::sync::Arc;
use std::time::Instant;

use krb5_rs::ccache::unparse_name;
use krb5_rs::client::vfy::{default_keytab_name, resolve_keytab};
use krb5_rs::gssapi::iakerb::{IakerbAcceptStep, IakerbAcceptor};
use krb5_rs::gssapi::krb5::{AcceptStep, Krb5Acceptor, Krb5Context, MECH_IAKERB, MECH_KRB5};
use krb5_rs::gssapi::spnego::{SpnegoAcceptor, MECH_SPNEGO};
use krb5_rs::profile::Profile;
use krb5_rs::protocol::ap::{ApError, KeySource};
use krb5_rs::transport::{KdcTransport, LocatedTransport};
use krb5_rs::types::{EncryptionKey, PrincipalName};
use krb5_rs::Krb5Error;
use krb5_rs_clients::gss_sample::*;
use krb5_rs_clients::{profile, runtime, sname_to_principal};

fn usage() -> ! {
    eprint!("Usage: gss-server [-port port] [-verbose] [-once]");
    eprint!(" [-inetd]");
    eprintln!();
    eprintln!("       [-export] [-logfile file] [-keytab keytab] service_name");
    exit(1);
}

/// The acceptor keytab, opened by name for each key lookup as MIT's
/// keytab-backed acceptor credential does.
struct NamedKeytab(String);

impl KeySource for NamedKeytab {
    fn get_key(
        &self,
        server: &PrincipalName,
        realm: &[u8],
        kvno: Option<i32>,
        etype: i32,
    ) -> Result<EncryptionKey, ApError> {
        let kt = resolve_keytab(&self.0).map_err(|_| ApError::NoKey)?;
        kt.key_source().get_key(server, realm, kvno, etype)
    }
}

struct Server {
    profile: Arc<Profile>,
    rt: tokio::runtime::Runtime,
    keytab: String,
    server: PrincipalName,
    realm: String,
    verbose: bool,
    export: bool,
    log: Box<dyn Write>,
}

enum Accept {
    Krb5(Box<Krb5Acceptor>),
    Spnego(Box<SpnegoAcceptor>),
    Iakerb(Box<IakerbAcceptor>),
}

fn main() {
    let mut args = std::env::args().skip(1).peekable();
    let (mut port, mut once, mut inetd) = (4444u16, false, false);
    let (mut verbose, mut export) = (false, false);
    let mut logfile: Option<String> = None;
    let mut keytab: Option<String> = None;
    while let Some(a) = args.next_if(|a| a.starts_with('-')) {
        match a.as_str() {
            "-port" => {
                port = args
                    .next()
                    .and_then(|p| p.parse().ok())
                    .unwrap_or_else(|| usage())
            }
            "-verbose" => verbose = true,
            "-once" => once = true,
            "-inetd" => inetd = true,
            "-export" => export = true,
            "-iakerb" => {}
            "-logfile" => logfile = Some(args.next().unwrap_or_else(|| usage())),
            "-keytab" => keytab = Some(args.next().unwrap_or_else(|| usage())),
            _ => usage(),
        }
    }
    let rest: Vec<String> = args.collect();
    let [service_name] = rest.as_slice() else {
        usage();
    };
    let log: Box<dyn Write> = match &logfile {
        Some(f) if f != "-" => match std::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(f)
        {
            Ok(f) => Box::new(f),
            Err(e) => {
                eprintln!("{f}: {e}");
                exit(1);
            }
        },
        _ => Box::new(std::io::stdout()),
    };
    let profile = Arc::new(profile());
    let rt = runtime();
    let (svc, host) = match service_name.split_once('@') {
        Some((s, h)) => (s, Some(h)),
        None => (service_name.as_str(), None),
    };
    let (server, realm) = sname_to_principal(&rt, &profile, host, svc);
    let keytab = keytab.unwrap_or_else(|| default_keytab_name(Some(&profile)));
    if let Err(e) = resolve_keytab(&keytab) {
        display_status(&mut std::io::stdout(), "acquiring credentials", &e);
        exit(1);
    }
    let mut srv = Server {
        profile,
        rt,
        keytab,
        server,
        realm,
        verbose,
        export,
        log,
    };
    if inetd {
        match inetd_stream() {
            Ok(mut s) => {
                let _ = srv.sign_server(&mut s);
            }
            Err(e) => {
                eprintln!("{e}");
                exit(1);
            }
        }
        return;
    }
    let listener = match TcpListener::bind(("0.0.0.0", port)) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("binding socket: {e}");
            exit(1);
        }
    };
    eprintln!("starting...");
    loop {
        let mut s = match listener.accept() {
            Ok((s, _)) => s,
            Err(e) => {
                eprintln!("accepting connection: {e}");
                continue;
            }
        };
        let _ = srv.sign_server(&mut s);
        if once {
            break;
        }
    }
}

impl Server {
    fn status(&mut self, msg: &str, e: &Krb5Error) {
        display_status(&mut std::io::stdout(), msg, e);
    }

    fn acceptor(&self, first: &[u8]) -> Accept {
        let keys = || Box::new(NamedKeytab(self.keytab.clone()));
        let server = Some(self.server.clone());
        match token_mech(first) {
            Some(m) if m == MECH_SPNEGO => Accept::Spnego(Box::new(SpnegoAcceptor::new(
                Krb5Acceptor::new(keys(), server, None),
                vec![MECH_KRB5.to_vec()],
            ))),
            Some(m) if m == MECH_IAKERB => Accept::Iakerb(Box::new(IakerbAcceptor::new(
                keys(),
                server,
                Some(self.realm.clone()),
                None,
            ))),
            _ => Accept::Krb5(Box::new(Krb5Acceptor::new(keys(), server, None))),
        }
    }

    /// One acceptor step: the token to send and whether more are needed.
    fn step(&self, acc: &mut Accept, tok: &[u8]) -> Result<(Option<Vec<u8>>, bool), Krb5Error> {
        let krb5 = |r: AcceptStep| match r {
            AcceptStep::Complete { token } => (token, false),
            AcceptStep::ContinueNeeded(t) => (Some(t), true),
        };
        Ok(match acc {
            Accept::Krb5(a) => krb5(a.step(tok)?),
            Accept::Spnego(a) => krb5(a.step(tok)?),
            Accept::Iakerb(a) => match a.step(tok)? {
                IakerbAcceptStep::Continue(t) => (Some(t), true),
                IakerbAcceptStep::Complete { token } => (token, false),
                IakerbAcceptStep::SendToKdc { realm, data } => {
                    let transport = LocatedTransport::new(self.profile.clone(), None);
                    let reply = self.rt.block_on(transport.send_recv(&realm, &data));
                    (Some(a.kdc_reply(reply)?), true)
                }
            },
        })
    }

    /// server_establish_context.
    fn establish(&mut self, s: &mut TcpStream) -> Result<Option<(Krb5Context, String)>, ()> {
        let (flags, _) = recv_token(s).map_err(|e| {
            let _ = writeln!(self.log, "{e}");
        })?;
        if flags & TOKEN_NOOP == 0 {
            let _ = writeln!(self.log, "Expected NOOP token, got {flags} token instead");
            return Err(());
        }
        if flags & TOKEN_CONTEXT_NEXT == 0 {
            return Ok(None);
        }
        let mut acc: Option<Accept> = None;
        loop {
            let (_, tok) = recv_token(s).map_err(|e| {
                let _ = writeln!(self.log, "{e}");
            })?;
            if self.verbose {
                let _ = writeln!(self.log, "Received token (size={}): ", tok.len());
                print_token(&mut self.log, &tok);
            }
            let a = acc.get_or_insert_with(|| self.acceptor(&tok));
            let res = self.step(a, &tok);
            let (out, cont) = match res {
                Ok(r) => r,
                Err(e) => {
                    self.status("accepting context", &e);
                    return Err(());
                }
            };
            if let Some(t) = out {
                if self.verbose {
                    let _ = writeln!(
                        self.log,
                        "Sending accept_sec_context token (size={}):",
                        t.len()
                    );
                    print_token(&mut self.log, &t);
                }
                if send_token(s, TOKEN_CONTEXT, &t).is_err() {
                    let _ = writeln!(self.log, "failure sending token");
                    return Err(());
                }
            }
            if self.verbose {
                let _ = writeln!(self.log, "{}", if cont { "continue needed..." } else { "" });
            }
            if !cont {
                break;
            }
        }
        let ctx = match acc.map(|a| match a {
            Accept::Krb5(a) => a.context(),
            Accept::Spnego(a) => a.context(),
            Accept::Iakerb(a) => a.context(),
        }) {
            Some(Ok(c)) => c,
            Some(Err(e)) => {
                self.status("accepting context", &e);
                return Err(());
            }
            None => return Err(()),
        };
        if self.verbose {
            display_ctx_flags(&mut self.log, ctx.flags());
            let _ = writeln!(
                self.log,
                "Accepted connection using mechanism OID {}.",
                oid_to_str(ctx.mech())
            );
        }
        let name = unparse_name(ctx.initiator(), ctx.initiator_realm());
        Ok(Some((ctx, name)))
    }

    /// test_import_export_context.
    fn reimport(&mut self, ctx: Krb5Context) -> Result<Krb5Context, ()> {
        let start = Instant::now();
        let tok = ctx
            .export_sec_context()
            .map_err(|e| self.status("exporting context", &e))?;
        if self.verbose {
            let _ = writeln!(
                self.log,
                "Exported context: {} bytes, {:7.4} seconds",
                tok.len(),
                start.elapsed().as_secs_f64()
            );
        }
        let start = Instant::now();
        let ctx = Krb5Context::import_sec_context(&tok)
            .map_err(|e| self.status("importing context", &e))?;
        if self.verbose {
            let _ = writeln!(
                self.log,
                "Importing context: {:7.4} seconds",
                start.elapsed().as_secs_f64()
            );
        }
        Ok(ctx)
    }

    /// sign_server.
    fn sign_server(&mut self, s: &mut TcpStream) -> Result<(), ()> {
        let mut ctx = match self.establish(s)? {
            Some((ctx, name)) => {
                println!("Accepted connection: \"{name}\"");
                Some(ctx)
            }
            None => {
                println!("Accepted unauthenticated connection.");
                None
            }
        };
        let _ = std::io::stdout().flush();
        if self.export {
            if let Some(mut c) = ctx.take() {
                for _ in 0..3 {
                    c = self.reimport(c)?;
                }
                ctx = Some(c);
            }
        }
        loop {
            let (flags, tok) = recv_token(s).map_err(|e| {
                let _ = writeln!(self.log, "{e}");
            })?;
            if flags & TOKEN_NOOP != 0 {
                if self.verbose {
                    let _ = writeln!(self.log, "NOOP token");
                }
                break;
            }
            if self.verbose {
                let _ = writeln!(self.log, "Message token (flags={flags}):");
                print_token(&mut self.log, &tok);
            }
            if ctx.is_none() && flags & (TOKEN_WRAPPED | TOKEN_ENCRYPTED | TOKEN_SEND_MIC) != 0 {
                let _ = writeln!(
                    self.log,
                    "Unauthenticated client requested authenticated services!"
                );
                return Err(());
            }
            let msg = match &mut ctx {
                Some(c) if flags & TOKEN_WRAPPED != 0 => {
                    let u = c
                        .unwrap(&tok)
                        .map_err(|e| self.status("unsealing message", &e))?;
                    if !u.conf && flags & TOKEN_ENCRYPTED != 0 {
                        eprintln!("Warning!  Message not encrypted.");
                    }
                    u.data
                }
                _ => tok,
            };
            let _ = write!(self.log, "Received message: ");
            if msg.iter().all(|b| b.is_ascii_graphic() || *b == b' ') {
                let _ = writeln!(self.log, "\"{}\"", String::from_utf8_lossy(&msg));
            } else {
                let _ = writeln!(self.log);
                print_token(&mut self.log, &msg);
            }
            let _ = self.log.flush();
            match &mut ctx {
                Some(c) if flags & TOKEN_SEND_MIC != 0 => {
                    let mic = c
                        .get_mic(&msg)
                        .map_err(|e| self.status("signing message", &e))?;
                    send_token(s, TOKEN_MIC, &mic).map_err(|_| ())?;
                }
                _ => send_token(s, TOKEN_NOOP, &[]).map_err(|_| ())?,
            }
        }
        Ok(())
    }
}

/// Descriptor 0 as the connection inetd handed over.
#[cfg(unix)]
fn inetd_stream() -> std::io::Result<TcpStream> {
    use std::os::fd::AsFd;
    let fd = std::io::stdin().as_fd().try_clone_to_owned()?;
    Ok(TcpStream::from(fd))
}

#[cfg(not(unix))]
fn inetd_stream() -> std::io::Result<TcpStream> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "inetd mode needs a Unix socket on descriptor 0",
    ))
}
