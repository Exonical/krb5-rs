//! Port of MIT's t_negoex.py over the negoextest mechanism
//! (plugins/gssapi/negoextest/main.c).
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use super::*;

/// `negoextest` mechanism OIDs 2.25.1414534758 and 2.25.1175737388.
fn oid(arc: u64) -> Vec<u8> {
    let mut b = vec![(arc & 0x7f) as u8];
    let mut v = arc >> 7;
    while v > 0 {
        b.push(0x80 | (v & 0x7f) as u8);
        v >>= 7;
    }
    b.push(0x69);
    b.reverse();
    b
}

#[derive(Default, Clone)]
struct Env {
    hops: Option<u8>,
    key: Option<&'static str>,
    init_query_fail: Option<u8>,
    accept_query_fail: Option<u8>,
    init_exchange_fail: Option<u8>,
    accept_exchange_fail: Option<u8>,
    init_fail: Option<u8>,
    accept_fail: Option<u8>,
}

struct Fake {
    oid: Vec<u8>,
    env: Arc<Env>,
    initiator: bool,
    hops: Option<u8>,
}

impl Fake {
    fn last(&self) -> u8 {
        *self.oid.last().unwrap()
    }

    fn get_key(&self, verify: bool) -> Option<NegoexKey> {
        let mode = self.env.key;
        if mode == Some("never") {
            return None;
        }
        let hops = self.hops?;
        if hops > 0 {
            match mode {
                None => return None,
                Some("init-always") if !self.initiator => return None,
                Some("accept-always") if self.initiator => return None,
                _ => {}
            }
        }
        let mut key = vec![0; 32];
        key[0] = u8::from(verify ^ self.initiator);
        Some(NegoexKey { etype: 18, key })
    }
}

impl NegoexMech for Fake {
    fn auth_scheme(&self) -> AuthScheme {
        let mut s = [0; 16];
        s[..self.oid.len()].copy_from_slice(&self.oid);
        s
    }

    fn query_meta_data(&mut self, initiator: bool) -> Result<Vec<u8>, Krb5Error> {
        let fail = if initiator {
            self.env.init_query_fail
        } else {
            self.env.accept_query_fail
        };
        if fail == Some(self.last()) {
            return Err(Krb5Error::Gss(GssError::Failure));
        }
        Ok(b"X".to_vec())
    }

    fn exchange_meta_data(&mut self, initiator: bool, md: &[u8]) -> Result<(), Krb5Error> {
        let fail = if initiator {
            self.env.init_exchange_fail
        } else {
            self.env.accept_exchange_fail
        };
        if fail == Some(self.last()) {
            return Err(Krb5Error::Gss(GssError::Failure));
        }
        assert_eq!(md, b"X");
        Ok(())
    }

    fn init_sec_context(&mut self, input: Option<&[u8]>) -> Result<MechOutput, Krb5Error> {
        let hops = match input {
            None | Some([]) => self.env.hops.unwrap_or(1),
            Some(b"fail") => return Err(Krb5Error::Protocol("failure from acceptor".into())),
            Some(t) => t[0],
        };
        if self.env.init_fail == Some(self.last()) {
            return Err(Krb5Error::Gss(GssError::Failure));
        }
        let mut h = match self.hops {
            None => hops,
            Some(h) => {
                assert_eq!(h - 1, hops);
                hops
            }
        };
        let mut token = Vec::new();
        if h > 0 {
            h -= 1;
            // gss_encapsulate_token: [APPLICATION 0] { OID, hops }.
            token = vec![0x60, (self.oid.len() + 3) as u8, 0x06, self.oid.len() as u8];
            token.extend_from_slice(&self.oid);
            token.push(h);
        }
        self.hops = Some(h);
        Ok(MechOutput {
            token,
            complete: h == 0,
        })
    }

    fn accept_sec_context(&mut self, input: &[u8]) -> Result<MechOutput, MechFailure> {
        assert!(input.len() >= 2);
        let hops = input[input.len() - 1];
        if self.env.accept_fail == Some(input[input.len() - 2]) {
            return Err(MechFailure {
                error: Krb5Error::Gss(GssError::Failure),
                token: b"fail".to_vec(),
            });
        }
        let mut h = match self.hops {
            None => hops,
            Some(h) => {
                assert_eq!(h - 1, hops);
                hops
            }
        };
        let mut token = Vec::new();
        if h > 0 {
            h -= 1;
            token.push(h);
        }
        self.hops = Some(h);
        Ok(MechOutput {
            token,
            complete: h == 0,
        })
    }

    fn delete_sec_context(&mut self) {
        self.hops = None;
    }

    fn key(&self) -> Option<NegoexKey> {
        self.get_key(false)
    }

    fn verify_key(&self) -> Option<NegoexKey> {
        self.get_key(true)
    }
}

fn mechs(initiator: bool, env: &Arc<Env>) -> Vec<Box<dyn NegoexMech>> {
    [1414534758, 1175737388]
        .into_iter()
        .map(|a| {
            Box::new(Fake {
                oid: oid(a),
                env: Arc::clone(env),
                initiator,
                hops: None,
            }) as Box<dyn NegoexMech>
        })
        .collect()
}

/// t_context's loop; returns the combined trace.
fn run(env: Env, optimistic: bool) -> Result<Vec<String>, Krb5Error> {
    let env = Arc::new(env);
    let mut i = Negoex::new(true, mechs(true, &env));
    if !optimistic {
        i = i.without_optimistic_token();
    }
    let mut a = Negoex::new(false, mechs(false, &env));
    let mut trace = Vec::new();
    let mut out = i.init(None);
    trace.extend(i.take_trace());
    let mut s = out?;
    let mut acc_complete = false;
    for _ in 0..20 {
        if s.token.is_empty() {
            break;
        }
        let r = a.accept(&s.token);
        trace.extend(a.take_trace());
        let r = r?;
        acc_complete = r.complete;
        if r.token.is_empty() {
            break;
        }
        out = i.init(Some(&r.token));
        trace.extend(i.take_trace());
        s = out?;
    }
    assert!(s.complete && acc_complete, "{trace:#?}");
    Ok(trace)
}

/// k5test expected_trace: each item is a substring of a later line.
fn assert_trace(trace: &[String], expected: &[&str]) {
    let mut it = trace.iter();
    for e in expected {
        assert!(it.any(|l| l.contains(e)), "missing {e:?} in {trace:#?}");
    }
}

fn env() -> Env {
    Env::default()
}

fn hops(n: u8) -> Env {
    Env {
        hops: Some(n),
        ..env()
    }
}

#[test]
fn oids_and_guids() {
    assert_eq!(*oid(1414534758).last().unwrap(), 102);
    assert_eq!(*oid(1175737388).last().unwrap(), 44);
    let f = &mechs(true, &Arc::new(env()))[0];
    assert!(guid_to_string(&f.auth_scheme()).starts_with("c0a28569-66ac-0000"));
}

#[test]
fn one_hop() {
    let t = run(hops(1), true).unwrap();
    assert_trace(
        &t,
        &[
            "sending [0]INITIATOR_NEGO: c0a28569-66ac-0000-0000-000000000000 d1b08469-2ca8-0000-0000-000000000000",
            "sending [1]INITIATOR_META_DATA: c0a28569-66ac",
            "sending [2]INITIATOR_META_DATA: d1b08469-2ca8",
            "sending [3]AP_REQUEST: c0a28569-66ac",
            "sending [4]VERIFY: c0a28569-66ac",
            "received [0]INITIATOR_NEGO: c0a28569-66ac-0000-0000-000000000000 d1b08469-2ca8-0000-0000-000000000000",
            "received [1]INITIATOR_META_DATA: c0a28569-66ac",
            "received [2]INITIATOR_META_DATA: d1b08469-2ca8",
            "received [3]AP_REQUEST: c0a28569-66ac",
            "received [4]VERIFY: c0a28569-66ac",
            "sending [5]ACCEPTOR_NEGO: c0a28569-66ac-0000-0000-000000000000 d1b08469-2ca8-0000-0000-000000000000",
            "sending [6]ACCEPTOR_META_DATA: c0a28569-66ac",
            "sending [7]ACCEPTOR_META_DATA: d1b08469-2ca8",
            "sending [8]VERIFY: c0a28569-66ac",
            "received [5]ACCEPTOR_NEGO",
            "received [6]ACCEPTOR_META_DATA: c0a28569-66ac",
            "received [7]ACCEPTOR_META_DATA: d1b08469-2ca8",
            "received [8]VERIFY: c0a28569-66ac",
        ],
    );
}

#[test]
fn two_to_four_hops() {
    let t = run(hops(2), true).unwrap();
    assert_trace(
        &t,
        &[
            "sending [7]CHALLENGE",
            "sending [8]VERIFY",
            "received [8]VERIFY",
            "sending [9]VERIFY",
        ],
    );
    let t = run(hops(3), true).unwrap();
    assert_trace(
        &t,
        &[
            "sending [8]AP_REQUEST",
            "sending [9]VERIFY",
            "received [8]AP_REQUEST",
            "sending [10]VERIFY",
        ],
    );
    let t = run(hops(4), true).unwrap();
    assert_trace(
        &t,
        &[
            "sending [9]CHALLENGE",
            "sending [10]VERIFY",
            "received [9]CHALLENGE",
            "sending [11]VERIFY",
        ],
    );
}

#[test]
fn early_keys() {
    let t = run(
        Env {
            key: Some("always"),
            ..hops(3)
        },
        true,
    )
    .unwrap();
    assert_trace(
        &t,
        &[
            "sending [4]VERIFY",
            "sending [9]VERIFY",
            "sending [10]AP_REQUEST",
        ],
    );
    let t = run(
        Env {
            key: Some("always"),
            ..hops(4)
        },
        true,
    )
    .unwrap();
    assert_trace(
        &t,
        &[
            "sending [4]VERIFY",
            "sending [9]VERIFY",
            "sending [10]AP_REQUEST",
            "sending [11]CHALLENGE",
        ],
    );
}

#[test]
fn no_keys() {
    let e = run(
        Env {
            key: Some("never"),
            ..env()
        },
        true,
    )
    .unwrap_err();
    assert_eq!(e.to_string(), "No NegoEx verify key");
}

#[test]
fn no_optimistic_token() {
    let t = run(env(), false).unwrap();
    assert_trace(
        &t,
        &[
            "sending [3]ACCEPTOR_NEGO",
            "sending [6]AP_REQUEST",
            "sending [7]VERIFY",
            "sending [8]VERIFY",
        ],
    );
}

#[test]
fn first_mech_initiator_query_fail() {
    let t = run(
        Env {
            init_query_fail: Some(102),
            ..env()
        },
        true,
    )
    .unwrap();
    assert_trace(
        &t,
        &[
            "sending [0]INITIATOR_NEGO: d1b08469-2ca8-0000-0000-000000000000",
            "sending [2]AP_REQUEST",
            "sending [3]VERIFY",
            "sending [4]ACCEPTOR_NEGO: d1b08469-2ca8-0000-0000-000000000000",
            "sending [6]VERIFY",
        ],
    );
}

#[test]
fn first_mech_acceptor_query_or_exchange_fail() {
    let msgs = [
        "sending [0]INITIATOR_NEGO: c0a28569-66ac-0000-0000-000000000000 d1b08469-2ca8-0000-0000-000000000000",
        "sending [3]AP_REQUEST: c0a28569-66ac",
        "sending [4]VERIFY: c0a28569-66ac",
        "sending [5]ACCEPTOR_NEGO: d1b08469-2ca8-0000-0000-000000000000",
        "sending [7]AP_REQUEST: d1b08469-2ca8",
        "sending [8]VERIFY: d1b08469-2ca8",
        "sending [9]VERIFY: d1b08469-2ca8",
    ];
    assert_trace(
        &run(
            Env {
                accept_query_fail: Some(102),
                ..env()
            },
            true,
        )
        .unwrap(),
        &msgs,
    );
    assert_trace(
        &run(
            Env {
                accept_exchange_fail: Some(102),
                ..env()
            },
            true,
        )
        .unwrap(),
        &msgs,
    );
}

#[test]
fn first_mech_initiator_exchange_fail() {
    for e in [
        Env {
            init_exchange_fail: Some(102),
            ..hops(1)
        },
        Env {
            init_exchange_fail: Some(102),
            key: Some("always"),
            ..hops(2)
        },
        Env {
            init_exchange_fail: Some(102),
            ..hops(2)
        },
    ] {
        let err = run(e, true).unwrap_err();
        assert_eq!(
            err.to_string(),
            "No mutually supported NegoEx authentication schemes"
        );
        assert!(matches!(err, Krb5Error::Negoex(n) if n.major() == GssError::Failure));
    }
}

#[test]
fn first_mech_init_sec_context_fail() {
    let t = run(
        Env {
            init_fail: Some(102),
            ..env()
        },
        true,
    )
    .unwrap();
    assert_trace(
        &t,
        &[
            "sending [0]INITIATOR_NEGO: d1b08469-2ca8-0000-0000-000000000000",
            "sending [2]AP_REQUEST",
            "sending [3]VERIFY",
            "sending [6]VERIFY",
        ],
    );
}

#[test]
fn first_mech_accept_sec_context_fail() {
    let e = run(
        Env {
            accept_fail: Some(102),
            ..hops(2)
        },
        true,
    )
    .unwrap_err();
    assert_eq!(
        e.to_string(),
        "Protocol error: failure from acceptor".replace("Protocol error: ", &protocol_prefix())
    );
}

fn protocol_prefix() -> String {
    Krb5Error::Protocol(String::new()).to_string()
}

#[test]
fn alert_from_acceptor_to_initiator() {
    let t = run(
        Env {
            key: Some("init-always"),
            ..hops(3)
        },
        true,
    )
    .unwrap();
    assert_trace(
        &t,
        &[
            "sending [3]AP_REQUEST",
            "sending [4]VERIFY",
            "sending [8]CHALLENGE",
            "sending [9]ALERT",
            "received [9]ALERT",
            "sending [10]AP_REQUEST",
            "sending [11]VERIFY",
            "sending [12]VERIFY",
        ],
    );
}

#[test]
fn alert_from_initiator_to_acceptor() {
    let t = run(
        Env {
            key: Some("accept-always"),
            ..hops(4)
        },
        true,
    )
    .unwrap();
    assert_trace(
        &t,
        &[
            "sending [3]AP_REQUEST",
            "sending [7]CHALLENGE",
            "sending [8]VERIFY",
            "sending [9]AP_REQUEST",
            "sending [10]ALERT",
            "received [10]ALERT",
            "sending [11]CHALLENGE",
            "sending [12]VERIFY",
            "sending [13]VERIFY",
        ],
    );
}

fn first_token() -> (Vec<u8>, Arc<Env>) {
    let env = Arc::new(hops(2));
    let mut i = Negoex::new(true, mechs(true, &env));
    (i.init(None).unwrap().token, env)
}

fn accept_err(tok: &[u8], env: &Arc<Env>) -> Krb5Error {
    Negoex::new(false, mechs(false, env))
        .accept(tok)
        .unwrap_err()
}

#[test]
fn malformed_tokens() {
    let (tok, env) = first_token();
    let mut bad = tok.clone();
    bad[0] ^= 1;
    assert!(matches!(
        accept_err(&bad, &env),
        Krb5Error::Negoex(NegoexError::InvalidMessageSignature)
    ));
    let mut bad = tok.clone();
    bad[12] = 1; // seqnum of the first message
    assert!(matches!(
        accept_err(&bad, &env),
        Krb5Error::Negoex(NegoexError::MessageOutOfSequence)
    ));
    let mut bad = tok.clone();
    bad[8] = 9; // type
    assert!(matches!(
        accept_err(&bad, &env),
        Krb5Error::Negoex(NegoexError::InvalidMessageType)
    ));
    assert!(matches!(
        accept_err(&tok[..tok.len() - 1], &env),
        Krb5Error::Negoex(NegoexError::InvalidMessageSize)
    ));
    let mut bad = tok.clone();
    bad[72] = 1; // protocol version
    let e = accept_err(&bad, &env);
    assert!(matches!(
        e,
        Krb5Error::Negoex(NegoexError::UnsupportedVersion)
    ));
    assert!(matches!(e, Krb5Error::Negoex(n) if n.major() == GssError::Unavailable));
    // Conversation ID of the second message.
    let len = u32::from_le_bytes(tok[20..24].try_into().unwrap()) as usize;
    let mut bad = tok.clone();
    bad[len + 24] ^= 1;
    assert!(matches!(
        accept_err(&bad, &env),
        Krb5Error::Negoex(NegoexError::InvalidConversationId)
    ));
    // A critical extension in INITIATOR_NEGO.
    let mut ext = tok[..len].to_vec();
    let total = (len + 12) as u32;
    ext[20..24].copy_from_slice(&total.to_le_bytes());
    ext[86..90].copy_from_slice(&(len as u32).to_le_bytes());
    ext[90..92].copy_from_slice(&1u16.to_le_bytes());
    ext.extend_from_slice(&EXTENSION_FLAG_CRITICAL.to_le_bytes());
    ext.extend_from_slice(&[0; 8]);
    ext.extend_from_slice(&tok[len..]);
    assert!(matches!(
        accept_err(&ext, &env),
        Krb5Error::Negoex(NegoexError::UnsupportedCriticalExtension)
    ));
    // A message other than INITIATOR_NEGO first.
    let mut bad = tok.clone();
    bad[8] = 1;
    assert!(matches!(
        accept_err(&bad, &env),
        Krb5Error::Negoex(NegoexError::MissingNegoMessage)
    ));
}

#[test]
fn bad_checksum() {
    let (_, env) = first_token();
    // HOPS=2 with early keys so the initiator's VERIFY is checked.
    let env2 = Arc::new(Env {
        key: Some("always"),
        ..(*env).clone()
    });
    let mut i = Negoex::new(true, mechs(true, &env2));
    let mut tok = i.init(None).unwrap().token;
    let n = tok.len();
    tok[n - 1] ^= 1;
    let e = Negoex::new(false, mechs(false, &env2))
        .accept(&tok)
        .unwrap_err();
    assert_eq!(e.to_string(), "Invalid NegoEx checksum");
    assert!(matches!(e, Krb5Error::Negoex(n) if n.major() == GssError::BadSig));
}

#[test]
fn checksum_key_usages() {
    let i = Negoex::new(true, Vec::new());
    let a = Negoex::new(false, Vec::new());
    assert_eq!(i.keyusage(true), KEYUSAGE_ACCEPTOR_CHECKSUM);
    assert_eq!(i.keyusage(false), KEYUSAGE_INITIATOR_CHECKSUM);
    assert_eq!(a.keyusage(true), KEYUSAGE_INITIATOR_CHECKSUM);
    assert_eq!(a.keyusage(false), KEYUSAGE_ACCEPTOR_CHECKSUM);
}

fn spnego_run(env: Env) -> (Vec<u8>, Vec<u8>) {
    use crate::gssapi::krb5::{AcceptStep, InitStep};
    use crate::gssapi::spnego::{SpnegoAcceptor, SpnegoInitiator};
    let env = Arc::new(env);
    let list = vec![MECH_NEGOEX.to_vec()];
    let mut i = SpnegoInitiator::negoex(Negoex::new(true, mechs(true, &env)), list.clone());
    let mut a = SpnegoAcceptor::negoex(Negoex::new(false, mechs(false, &env)), list);
    let mut tok = match i.step(None).unwrap() {
        InitStep::Continue(t) => t,
        InitStep::Complete(_) => panic!("complete before the acceptor answered"),
    };
    for _ in 0..20 {
        let reply = match a.step(&tok).unwrap() {
            AcceptStep::Complete { token: None } => break,
            AcceptStep::Complete { token: Some(t) } | AcceptStep::ContinueNeeded(t) => t,
        };
        match i.step(Some(&reply)).unwrap() {
            InitStep::Complete(None) => break,
            InitStep::Complete(Some(t)) | InitStep::Continue(t) => tok = t,
        }
    }
    let im = i.negoex_mech().unwrap().auth_scheme().to_vec();
    let am = a.negoex_mech().unwrap().auth_scheme().to_vec();
    (im, am)
}

#[test]
fn spnego_negotiates_negoex() {
    for e in [
        hops(1),
        hops(2),
        hops(3),
        Env {
            init_query_fail: Some(102),
            ..env()
        },
    ] {
        let first = e.init_query_fail.is_none();
        let (im, am) = spnego_run(e);
        assert_eq!(im, am);
        assert_eq!(
            *im.iter().rfind(|&&b| b != 0).unwrap(),
            if first { 102 } else { 44 }
        );
    }
}
