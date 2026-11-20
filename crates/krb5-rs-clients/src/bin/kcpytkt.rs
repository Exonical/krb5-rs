//! MIT `kcpytkt` (src/clients/kcpytkt/kcpytkt.c).

#![forbid(unsafe_code)]

use krb5_rs::ccache::{resolve, Ccache};
use krb5_rs_clients::tktutil::{cc_message, open_source, parse_args};
use krb5_rs_clients::{fail, progname};

fn xusage() -> ! {
    eprintln!(
        "xusage: {} [-c from_ccache] [-e etype] [-f flags] dest_ccache service1 service2 ...",
        progname()
    );
    std::process::exit(1)
}

fn main() {
    let o = parse_args(2, xusage);
    let src = open_source(&o, "while opening source ccache");
    let mut dest = resolve(&src.ctx, &o.names[0])
        .unwrap_or_else(|e| fail(cc_message(&e), "while opening destination cache", 1));
    let mut errors = 0;
    for name in &o.names[1..] {
        let Some((princ, creds)) = src.retrieve(name, o.quiet) else {
            errors += 1;
            continue;
        };
        if let Err(e) = dest.store(&creds) {
            // kcpytkt.c:150-156 says "removing" here.
            eprintln!("{princ}: {} while removing credentials", cc_message(&e));
            errors += 1;
        }
    }
    std::process::exit(i32::from(errors > 0));
}
