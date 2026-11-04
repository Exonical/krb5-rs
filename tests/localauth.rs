//! krb5_aname_to_localname and krb5_kuserok like MIT, ported from MIT
//! tests/t_localauth.py, plus the k5login module (which t_localauth.py
//! can't test).

use krb5_rs::localauth::{aname_to_localname, kuserok, LocalauthError};
use krb5_rs::profile::Profile;
use krb5_rs::types::PrincipalName;
use rasn::types::GeneralString;

fn princ(s: &str) -> (PrincipalName, String) {
    let (name, realm) = s.rsplit_once('@').unwrap_or((s, "KRBTEST.COM"));
    let name = PrincipalName {
        name_type: 1,
        name_string: name
            .split('/')
            .map(|c| GeneralString::from_bytes(c.as_bytes()).unwrap())
            .collect(),
    };
    (name, realm.to_string())
}

fn conf(extra: &str) -> Profile {
    Profile::parse(&format!(
        "[libdefaults]\n default_realm = KRBTEST.COM\n\
         [plugins]\n localauth = {{\n  disable = k5login\n }}\n{extra}"
    ))
    .unwrap()
}

fn a2l(values: &[&str]) -> Profile {
    let lines: String = values
        .iter()
        .map(|v| format!("  auth_to_local = {v}\n"))
        .collect();
    conf(&format!("[realms]\n KRBTEST.COM = {{\n{lines} }}\n"))
}

fn an2ln(p: &Profile, s: &str) -> Result<String, LocalauthError> {
    let (n, r) = princ(s);
    aname_to_localname(p, &n, &r)
}

fn ok(p: &Profile, s: &str, want: &str) {
    assert_eq!(an2ln(p, s).as_deref(), Ok(want), "{s}");
}

fn err(p: &Profile, s: &str, want: LocalauthError) {
    assert_eq!(an2ln(p, s), Err(want.clone()), "{s}");
}

fn userok(p: &Profile, s: &str, lname: &str) -> bool {
    let (n, r) = princ(s);
    kuserok(p, &n, &r, lname)
}

use LocalauthError::{BadFormat, NoTranslation};

#[test]
fn default_method() {
    let p = conf("");
    ok(&p, "user@KRBTEST.COM", "user");
    ok(&p, "user/KRBTEST.COM@KRBTEST.COM", "user");
    err(&p, "user/KRBTEST.COM/x@KRBTEST.COM", NoTranslation);
    err(&p, "user/X@KRBTEST.COM", NoTranslation);
    err(&p, "user@X", NoTranslation);
    assert_eq!(
        NoTranslation.to_string(),
        "No translation available for requested principal"
    );
}

#[test]
fn auth_to_local_names() {
    let p =
        conf("[realms]\n KRBTEST.COM = {\n  auth_to_local_names = {\n   user = abcd\n  }\n }\n");
    ok(&p, "user@KRBTEST.COM", "abcd");
    ok(&p, "user@X", "abcd");
    ok(&p, "x@KRBTEST.COM", "x");
    ok(&p, "User@KRBTEST.COM", "User");
    let p = conf("[realms]\n X = {\n  auth_to_local_names = {\n   user = abcd\n  }\n }\n");
    err(&p, "user@X", NoTranslation);
}

#[test]
fn auth_to_local_rules() {
    ok(&a2l(&["DEFAULT"]), "user@KRBTEST.COM", "user");
    err(&a2l(&["RULE"]), "user@X", BadFormat);
    err(&a2l(&["UNRECOGNIZED:stuff"]), "user@X", BadFormat);
    assert_eq!(
        BadFormat.to_string(),
        "Improper format of Kerberos configuration file"
    );

    let rule1 = a2l(&["RULE:"]);
    ok(&rule1, "user@KRBTEST.COM", "user");
    ok(&rule1, "user@X", "user");
    ok(&rule1, "a/b/c@X", "a/b/c");

    let rule2 = a2l(&["RULE:[2:$0.$2.$1]"]);
    ok(&rule2, "aaron/burr@REALM", "REALM.burr.aaron");
    err(&rule2, "user@KRBTEST.COM", NoTranslation);

    let rule3 = a2l(&["RULE:(.*tail)"]);
    ok(&rule3, "withtail@X", "withtail");
    ok(&rule3, "x/withtail@X", "x/withtail");
    err(&rule3, "tails@X", NoTranslation);

    ok(
        &a2l(&["RULE:s/birds/bees/"]),
        "thebirdsbirdsbirds@X",
        "thebeesbirdsbirds",
    );
    ok(
        &a2l(&["RULE:s/birds/bees/g  s/bees/birds/"]),
        "the/birdsbirdsbirds@x",
        "the/birdsbeesbees",
    );

    let combo = a2l(&[
        "RULE:[1:$1-$0](fred.*)s/-/ /g",
        "DEFAULT",
        "RULE:[3:$1](z.*z)",
    ]);
    ok(&combo, "fred@X", "fred X");
    ok(&combo, "fred-too@X", "fred too X");
    ok(&combo, "fred@KRBTEST.COM", "fred KRBTEST.COM");
    ok(&combo, "user@KRBTEST.COM", "user");
    ok(&combo, "zazz/b/c@X", "zazz");
    err(&combo, "a/b@KRBTEST.COM", NoTranslation);

    assert!(userok(&combo, "fred@X", "fred X"));
    assert!(userok(&combo, "user@KRBTEST.COM", "user"));
    assert!(!userok(&combo, "user@KRBTEST.COM", "X"));
    assert!(!userok(&combo, "a/b@KRBTEST.COM", "a/b"));
}

#[test]
fn rule_edge_cases_like_mit() {
    // Anything after a substitution must be another substitution.
    err(&a2l(&["RULE:s/a/b/g x"]), "a@X", BadFormat);
    // An unterminated selection string or match.
    err(&a2l(&["RULE:[1:$1"]), "a@X", BadFormat);
    err(&a2l(&["RULE:(a"]), "a@X", BadFormat);
    // A bad regexp is "no translation".
    err(&a2l(&["RULE:(a[)"]), "a@X", NoTranslation);
    // POSIX leftmost-longest alternation.
    #[cfg(unix)]
    ok(&a2l(&["RULE:s/a|ab/X/"]), "abc@X", "Xc");
    // A global empty match stops instead of looping forever.
    ok(&a2l(&["RULE:s/x*/-/g"]), "ab@X", "-ab");
}

#[test]
fn enable_only_and_disable() {
    let p = Profile::parse(
        "[libdefaults]\n default_realm = KRBTEST.COM\n\
         [plugins]\n localauth = {\n  enable_only = names\n }\n",
    )
    .unwrap();
    err(&p, "user@KRBTEST.COM", NoTranslation);
    assert!(!userok(&p, "user@KRBTEST.COM", "user"));
    // auth_to_local naming a disabled typed module is a format error.
    let p = Profile::parse(
        "[libdefaults]\n default_realm = KRBTEST.COM\n\
         [plugins]\n localauth = {\n  disable = rule\n }\n\
         [realms]\n KRBTEST.COM = {\n  auth_to_local = RULE:\n }\n",
    )
    .unwrap();
    err(&p, "user@KRBTEST.COM", BadFormat);
}

#[cfg(unix)]
#[test]
fn k5login_like_mit() {
    let out = std::process::Command::new("id")
        .arg("-un")
        .output()
        .unwrap();
    let me = String::from_utf8(out.stdout).unwrap().trim().to_string();
    let dir = std::env::temp_dir().join(format!("krb5rs-k5login-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let profile = |extra: &str| {
        Profile::parse(&format!(
            "[libdefaults]\n default_realm = KRBTEST.COM\n k5login_directory = {}\n{extra}",
            dir.display()
        ))
        .unwrap()
    };
    let p = profile("");
    let mine = format!("{me}@KRBTEST.COM");

    // No .k5login: the an2ln module decides.
    assert!(userok(&p, &mine, &me));
    assert!(!userok(&p, "alice@KRBTEST.COM", &me));

    std::fs::write(dir.join(&me), "alice@KRBTEST.COM\nbob/admin@KRBTEST.COM").unwrap();
    assert!(userok(&p, "alice@KRBTEST.COM", &me));
    assert!(userok(&p, "bob/admin@KRBTEST.COM", &me));
    assert!(!userok(&p, "alice@X", &me));
    // An authoritative .k5login without the principal denies, even where
    // an2ln would accept.
    assert!(!userok(&p, &mine, &me));
    let p2 = profile(" k5login_authoritative = false\n");
    assert!(userok(&p2, &mine, &me));
    assert!(!userok(&p2, "carol@KRBTEST.COM", &me));
    // An unknown local user is denied.
    assert!(!userok(&p, "alice@KRBTEST.COM", "no-such-user-krb5rs"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn utf8_principals_match_auth_to_local_names() {
    let p = conf(
        "[realms]\n KRBTEST.COM = {\n  auth_to_local_names = {\n   jos\u{e9} = jose\n  }\n }\n",
    );
    ok(&p, "jos\u{e9}@KRBTEST.COM", "jose");
    ok(&p, "\u{fc}ser@KRBTEST.COM", "\u{fc}ser");
}
