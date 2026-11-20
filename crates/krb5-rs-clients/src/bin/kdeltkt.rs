//! MIT `kdeltkt` (src/clients/kdeltkt/kdeltkt.c).

#![forbid(unsafe_code)]

use krb5_rs::ccache::{Ccache, MatchFlags};
use krb5_rs_clients::progname;
use krb5_rs_clients::tktutil::{cc_message, match_of, open_source, parse_args};

fn xusage() -> ! {
    eprintln!(
        "xusage: {} [-c ccache] [-e etype] [-f flags] service1 service2 ...",
        progname()
    );
    std::process::exit(1)
}

fn main() {
    let o = parse_args(1, xusage);
    let mut src = open_source(&o, "while opening ccache");
    let flags = MatchFlags::from_bits_retain(u32::from_ne_bytes(o.flags.to_ne_bytes()));
    let mut errors = 0;
    for name in &o.names {
        let Some((princ, creds)) = src.retrieve(name, o.quiet) else {
            errors += 1;
            continue;
        };
        if let Err(e) = src.cache.remove_cred(flags, &match_of(&creds)) {
            eprintln!("{princ}: {} while removing credentials", cc_message(&e));
            errors += 1;
        }
    }
    std::process::exit(i32::from(errors > 0));
}
