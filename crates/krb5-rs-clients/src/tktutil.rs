//! Shared code of MIT `kcpytkt` and `kdeltkt` (src/clients/kcpytkt,
//! src/clients/kdeltkt), which differ only in what they do with each
//! retrieved credential.

use krb5_rs::ccache::{
    default_cache, parse_principal, resolve, AnyCcache, CcContext, CcCredential, CcError, Ccache,
    MatchCred, MatchFlags,
};

use crate::{fail, profile, Getopt};

/// Parsed `-c`, `-e`, `-f` and `-q` options and the operands.
pub struct TktOpts {
    /// `-c` cache name.
    pub ccache: Option<String>,
    /// `-e` enctype name.
    pub etype: Option<String>,
    /// `-f` flags, as `atoi` reads them.
    pub flags: i32,
    /// `-q`.
    pub quiet: bool,
    /// The operands.
    pub names: Vec<String>,
}

/// C `atoi`: leading whitespace, an optional sign and digits; anything else
/// stops the number.
fn atoi(s: &str) -> i32 {
    let s = s.trim_start();
    let (neg, digits) = match s.as_bytes().first() {
        Some(b'-') => (true, &s[1..]),
        Some(b'+') => (false, &s[1..]),
        _ => (false, s),
    };
    let n = digits
        .bytes()
        .take_while(u8::is_ascii_digit)
        .fold(0i64, |n, d| (n * 10 + i64::from(d - b'0')).min(1 << 32));
    (if neg { -n } else { n }) as i32
}

/// `getopt(argc, argv, "c:e:f:hq")`; fewer than `min` operands is a usage
/// error.
pub fn parse_args(min: usize, xusage: fn() -> !) -> TktOpts {
    let mut o = TktOpts {
        ccache: None,
        etype: None,
        flags: 0,
        quiet: false,
        names: Vec::new(),
    };
    let mut g = Getopt::new("c:e:f:hq");
    for (c, v) in g.by_ref() {
        match (c, v) {
            ('c', v) => o.ccache = v,
            ('e', v) => o.etype = v,
            ('f', Some(v)) => o.flags = atoi(&v),
            ('q', _) => o.quiet = true,
            _ => xusage(),
        }
    }
    o.names = g.rest().to_vec();
    if o.names.len() < min {
        xusage();
    }
    o
}

fn die(msg: impl std::fmt::Display, context: &str) -> ! {
    fail(msg, context, 1)
}

/// `error_message` for the ccache errors these tools print.
pub fn cc_message(e: &CcError) -> String {
    match e {
        CcError::NotFound => "Matching credential not found".into(),
        CcError::NotKtype => "No credentials found with supported encryption types".into(),
        // error_message() has no "(filename: ...)" extended message.
        CcError::NoFile(_) => "No credentials cache found".into(),
        other => other.to_string(),
    }
}

/// The opened source cache, its client, the retrieval flags and the
/// supported enctypes `-e` asks for.
pub struct Source {
    /// The cache named by `-c`, or the default cache.
    pub cache: AnyCcache,
    /// The context it was resolved in.
    pub ctx: CcContext,
    client: (krb5_rs::types::PrincipalName, String),
    defrealm: Option<String>,
    retflags: MatchFlags,
    ktypes: Option<Vec<i32>>,
}

/// Open the source cache as `do_kcpytkt`/`do_kdeltkt` do.
pub fn open_source(o: &TktOpts, open_msg: &str) -> Source {
    let profile = profile();
    let ctx = CcContext::from_env(Some(&profile));
    // KRB5_TC_SUPPORTED_KTYPES ranks matches by the TGS enctypes
    // (cc_retr.c:262-271); the -e enctype itself is only validated.
    let (retflags, ktypes) = match &o.etype {
        Some(s) => {
            if krb5_rs::crypto::enctype_from_name(s).is_none() {
                // krb5_string_to_enctype returns EINVAL.
                die("Invalid argument", "while converting etype");
            }
            (
                MatchFlags::SRV_NAMEONLY | MatchFlags::SUPPORTED_KTYPES,
                Some(krb5_rs::protocol::TgsOptions::default().etypes),
            )
        }
        None => (MatchFlags::SRV_NAMEONLY, None),
    };
    let cache = match &o.ccache {
        Some(n) => resolve(&ctx, n),
        None => default_cache(&ctx),
    }
    .unwrap_or_else(|e| die(cc_message(&e), open_msg));
    let client = cache
        .principal()
        .unwrap_or_else(|e| die(cc_message(&e), "while getting client principal name"));
    Source {
        cache,
        ctx,
        client,
        defrealm: krb5_rs::locate::default_realm(&profile),
        retflags,
        ktypes,
    }
}

impl Source {
    /// Parse `name` and retrieve its credential, printing MIT's message and
    /// returning None on failure.
    pub fn retrieve(&self, name: &str, quiet: bool) -> Option<(String, CcCredential)> {
        let Some(server) = parse_principal(name, self.defrealm.as_deref()) else {
            if !quiet {
                eprintln!(
                    "{name}: Malformed representation of principal while parsing principal name"
                );
            }
            return None;
        };
        let princ = krb5_rs::ccache::unparse_name(&server.0, &server.1);
        let m = MatchCred {
            client: Some(self.client.clone()),
            server: Some(server),
            ..Default::default()
        };
        match self
            .cache
            .retrieve(self.retflags, &m, self.ktypes.as_deref())
        {
            Ok(c) => Some((princ, c)),
            Err(e) => {
                eprintln!("{princ}: {} while retrieving credentials", cc_message(&e));
                None
            }
        }
    }
}

/// The retrieved credential as a match request with every field set, as
/// `krb5_cc_remove_cred` receives `out_creds`.
pub fn match_of(c: &CcCredential) -> MatchCred {
    MatchCred {
        client: Some((c.client.clone(), c.crealm.clone())),
        server: Some((c.server.clone(), c.srealm.clone())),
        etype: c.keyblock.keytype,
        authtime: c.authtime,
        starttime: c.starttime,
        endtime: c.endtime,
        renew_till: c.renew_till,
        is_skey: c.is_skey,
        ticket_flags: c.ticket_flags,
        authdata: Some(c.authdata.clone()),
        second_ticket: Some(c.second_ticket.clone()),
    }
}
