//! MIT `kswitch` (src/clients/kswitch/kswitch.c).

#![forbid(unsafe_code)]

use krb5_rs::ccache::{cache_match, parse_principal, resolve, CcContext};
use krb5_rs_clients::{fail, profile, progname, Getopt};

fn usage() -> ! {
    eprintln!("Usage: {} {{-c cache_name | -p principal}}", progname());
    eprintln!("\t-c specify name of credentials cache");
    eprintln!("\t-p specify name of principal");
    std::process::exit(2)
}

fn main() {
    let (mut cache_name, mut princ_name, mut errflag) = (None, None, false);
    let mut g = Getopt::new("c:p:");
    for (c, v) in g.by_ref() {
        match c {
            'c' | 'p' => {
                if cache_name.is_some() || princ_name.is_some() {
                    eprintln!("Only one -c or -p option allowed");
                    errflag = true;
                } else if c == 'c' {
                    cache_name = v;
                } else {
                    princ_name = v;
                }
            }
            _ => errflag = true,
        }
    }
    if !g.rest().is_empty() {
        errflag = true;
    }
    if cache_name.is_none() && princ_name.is_none() {
        eprintln!("One of -c or -p must be specified");
        errflag = true;
    }
    if errflag {
        usage();
    }
    let profile = profile();
    let ctx = CcContext::from_env(Some(&profile));
    let cache = if let Some(name) = &cache_name {
        resolve(&ctx, name).unwrap_or_else(|e| fail(e, &format!("while resolving {name}"), 1))
    } else {
        let name = princ_name.unwrap_or_default();
        let defrealm = profile.get_string(&["libdefaults", "default_realm"]);
        let Some((p, r)) = parse_principal(&name, defrealm.as_deref()) else {
            fail(
                "Malformed representation of principal",
                &format!("while parsing principal name {name}"),
                1,
            )
        };
        cache_match(&ctx, &p, &r)
            .unwrap_or_else(|e| fail(e, &format!("while searching for ccache for {name}"), 1))
    };
    if let Err(e) = cache.switch_to() {
        fail(e, "while switching to credential cache", 1);
    }
}
