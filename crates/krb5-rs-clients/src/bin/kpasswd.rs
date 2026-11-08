//! `kpasswd` (MIT krb5 1.22.2 `src/clients/kpasswd/kpasswd.c`).

#![forbid(unsafe_code)]

use std::sync::Arc;
use std::time::Duration;

use krb5_rs::ccache::{default_cache, parse_principal, unparse_name, CcContext, CcError, Ccache};
use krb5_rs::client::chpw::change_password;
use krb5_rs::locate::{DnsResolver, HickoryResolver, Locator};
use krb5_rs::protocol::{AsExchangeConfig, Credential, FastMode};
use krb5_rs::types::{KdcOptions, KerberosFlags, PrincipalName};
use krb5_rs::Krb5Error;
use krb5_rs_clients::{com_err, fail, krb5_message};

/// `krb5_read_password` (read_pwd.c): prompt twice; the entries must match.
fn read_password(p1: &str, p2: &str) -> Result<String, &'static str> {
    let a = rpassword::prompt_password(format!("{p1}: ")).map_err(|_| "Cannot read password")?;
    let b = rpassword::prompt_password(format!("{p2}: ")).map_err(|_| "Cannot read password")?;
    if a != b {
        return Err("Password mismatch");
    }
    Ok(a)
}

/// The armor TGT for `krb5_get_init_creds_opt_set_fast_ccache`.
fn armor(cc: &impl Ccache, realm: &str) -> FastMode {
    cc.creds()
        .ok()
        .and_then(|cs| {
            cs.into_iter().find(|c| {
                c.server.name_string.len() == 2
                    && c.server.name_string[0].as_bytes() == b"krbtgt"
                    && c.srealm == realm
            })
        })
        .and_then(|c| Credential::try_from(&c).ok())
        .map_or(FastMode::Disabled, FastMode::Opportunistic)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let argv0 = args.first().cloned().unwrap_or_else(|| "kpasswd".into());
    if args.len() > 2 {
        eprintln!("usage: {argv0} [principal]");
        std::process::exit(1);
    }
    let pname = args.get(1);
    let profile = Arc::new(krb5_rs_clients::profile());
    let ctx = CcContext::from_env(Some(&profile));
    let ccache = default_cache(&ctx).unwrap_or_else(|e| fail(e, "opening default ccache", 1));
    let mut princ = match ccache.principal() {
        Ok(p) => Some(p),
        Err(CcError::NotFound | CcError::NoFile(_)) => None,
        Err(e) => fail(e, "getting principal from ccache", 1),
    };
    let fast = princ
        .as_ref()
        .map_or(FastMode::Disabled, |(_, r)| armor(&ccache, r));
    let defrealm = krb5_rs::locate::default_realm(&profile);
    if let Some(n) = pname {
        princ = Some(parse_principal(n, defrealm.as_deref()).unwrap_or_else(|| {
            fail(
                "Malformed representation of principal",
                "parsing client name",
                1,
            )
        }));
    }
    let (me, realm) = princ.unwrap_or_else(|| {
        let Some(user) = ["USER", "LOGNAME"]
            .iter()
            .find_map(|v| std::env::var(v).ok().filter(|u| !u.is_empty()))
        else {
            eprintln!("Unable to identify user from password file");
            std::process::exit(1);
        };
        parse_principal(&user, defrealm.as_deref()).unwrap_or_else(|| {
            fail(
                "Malformed representation of principal",
                &format!("when parsing name {user}"),
                1,
            )
        })
    });

    let mut config = AsExchangeConfig::new(me.clone(), realm.clone());
    config.tkt_lifetime = Duration::from_secs(5 * 60);
    config.renew_lifetime = Duration::ZERO;
    config.kdc_options = KerberosFlags::new(KdcOptions::empty());
    config.server = Some(PrincipalName::new_srv_inst("kadmin", "changepw"));
    config.fast = fast;
    let rt = krb5_rs_clients::runtime();
    let client = krb5_rs_clients::kerberos_client(&profile, &realm);
    let name = unparse_name(&me, &realm);
    let pw = rpassword::prompt_password(format!("Password for {name}: "))
        .unwrap_or_else(|_| fail("Cannot read password", "getting initial ticket", 1));
    let creds = match rt.block_on(client.acquire_tgt_with_config(config, &pw)) {
        Ok(c) => c,
        Err(Krb5Error::DecryptionFailed) => {
            eprintln!("{argv0}: Password incorrect while getting initial ticket");
            std::process::exit(1);
        }
        Err(e) => {
            com_err(krb5_message(&e), "getting initial ticket");
            std::process::exit(1);
        }
    };
    let newpw = read_password("Enter new password", "Enter it again")
        .unwrap_or_else(|e| fail(e, "while reading password", 1));
    let dns = HickoryResolver::new().ok();
    let locator = Locator::new(&profile, dns.as_ref().map(|d| d as &dyn DnsResolver));
    let res = rt
        .block_on(change_password(&locator, &creds, &newpw))
        .unwrap_or_else(|e| fail(krb5_message(&e), "changing password", 1));
    if res.result_code != 0 {
        let message = krb5_rs::protocol::kpasswd::chpw_message(&res.result_string);
        if message.is_empty() {
            println!("{}", res.result_code_string);
        } else {
            println!("{}: {message}", res.result_code_string);
        }
        std::process::exit(2);
    }
    println!("Password changed.");
}
