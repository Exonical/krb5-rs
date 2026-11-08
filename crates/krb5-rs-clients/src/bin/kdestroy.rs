//! MIT `kdestroy` (src/clients/kdestroy/kdestroy.c).

#![forbid(unsafe_code)]

use krb5_rs::ccache::{
    cache_match, collection, default_cache, parse_principal, CcContext, CcError,
};
use krb5_rs_clients::{com_err, fail, profile, progname, Getopt};

fn usage() -> ! {
    eprintln!(
        "Usage: {} [-A] [-q] [-c cache_name] [-p princ_name]",
        progname()
    );
    eprintln!("\t-A destroy all credential caches in collection");
    eprintln!("\t-q quiet mode");
    eprintln!("\t-c specify name of credentials cache");
    eprintln!("\t-p specify principal name within collection");
    std::process::exit(2)
}

/// kdestroy.c `print_remaining_cc_warning`.
fn print_remaining_cc_warning(ctx: &CcContext) {
    let caches = collection(ctx).unwrap_or_else(|e| fail(e, "while listing credential caches", 1));
    if !caches.is_empty() {
        eprintln!("Other credential caches present, use -A to destroy all");
    }
}

fn main() {
    let (mut quiet, mut all, mut errflg) = (false, false, 0);
    let (mut cache_name, mut princ_name) = (None::<String>, None::<String>);
    let mut g = Getopt::new("54Aqc:p:");
    for (c, v) in g.by_ref() {
        match c {
            'A' => all = true,
            'q' => quiet = true,
            'c' if cache_name.is_some() => {
                eprintln!("Only one -c option allowed");
                errflg += 1;
            }
            'c' => cache_name = v,
            'p' if princ_name.is_some() => {
                eprintln!("Only one -p option allowed");
                errflg += 1;
            }
            'p' => princ_name = v,
            '4' => {
                eprintln!("Kerberos 4 is no longer supported");
                std::process::exit(3);
            }
            '5' => {}
            _ => errflg += 1,
        }
    }
    if all && princ_name.is_some() {
        eprintln!("-A option is exclusive with -p option");
        errflg += 1;
    }
    if !g.rest().is_empty() {
        errflg += 1;
    }
    if errflg > 0 {
        usage();
    }
    let profile = profile();
    let mut ctx = CcContext::from_env(Some(&profile));
    if cache_name.is_some() {
        ctx.default_name = cache_name;
    }
    if all {
        let caches =
            collection(&ctx).unwrap_or_else(|e| fail(e, "while listing credential caches", 1));
        for c in caches {
            let name = c.name();
            match c.destroy() {
                Ok(()) | Err(CcError::NoFile(_)) => {}
                Err(e) => com_err(e, &format!("while destroying cache {name}")),
            }
        }
        return;
    }
    let cache = if let Some(name) = &princ_name {
        let defrealm = profile.get_string(&["libdefaults", "default_realm"]);
        let Some((p, r)) = parse_principal(name, defrealm.as_deref()) else {
            fail(
                "Malformed representation of principal",
                &format!("while parsing principal name {name}"),
                1,
            )
        };
        cache_match(&ctx, &p, &r)
            .unwrap_or_else(|e| fail(e, &format!("while finding cache for {name}"), 1))
    } else {
        default_cache(&ctx).unwrap_or_else(|e| fail(e, "while resolving ccache", 1))
    };
    let mut failed = false;
    if let Err(e) = cache.destroy() {
        let nofile = matches!(e, CcError::NoFile(_));
        com_err(e, "while destroying cache");
        if !nofile {
            if quiet {
                eprintln!("Ticket cache NOT destroyed!");
            } else {
                eprintln!("Ticket cache \x07NOT\x07 destroyed!");
            }
            failed = true;
        }
    }
    if !quiet && !failed && princ_name.is_none() {
        print_remaining_cc_warning(&ctx);
    }
    std::process::exit(i32::from(failed));
}
