//! Option parsing, diagnostics and exit codes, checked against MIT 1.22's
//! tools run with the same arguments.

use std::process::{Command, Stdio};

fn run(bin: &str, args: &[&str]) -> (String, i32) {
    let out = Command::new(bin)
        .args(args)
        .env("KRB5_CONFIG", "/dev/null")
        .env("KRB5CCNAME", "FILE:/nonexistent/krb5-rs-cli-test")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    let mut s = String::from_utf8(out.stdout).unwrap();
    s.push_str(&String::from_utf8(out.stderr).unwrap());
    (s, out.status.code().unwrap())
}

const KINIT: &str = env!("CARGO_BIN_EXE_krb5-rs-kinit");
const KLIST: &str = env!("CARGO_BIN_EXE_krb5-rs-klist");
const KDESTROY: &str = env!("CARGO_BIN_EXE_krb5-rs-kdestroy");
const KSWITCH: &str = env!("CARGO_BIN_EXE_krb5-rs-kswitch");
const KVNO: &str = env!("CARGO_BIN_EXE_krb5-rs-kvno");

#[test]
fn kinit_conflicting_options() {
    for (args, msg) in [
        (&["-f", "-F", "x"][..], "Only one of -f and -F allowed\n"),
        (&["-p", "-P", "x"], "Only one of -p and -P allowed\n"),
        (&["-a", "-A", "x"], "Only one of -a and -A allowed\n"),
        (
            &["--request-pac", "--no-request-pac", "x"],
            "Only one of --request-pac and --no-request-pac allowed\n",
        ),
        (
            &["-t", "kt", "-i", "x"],
            "Only one of -t and -i allowed\nkeytab specified, forcing -k\n",
        ),
        (&["a", "b"], "Extra arguments (starting with \"b\").\n"),
    ] {
        let (out, rc) = run(KINIT, args);
        assert!(out.starts_with(msg), "{args:?}: {out}");
        assert!(out.contains("\n\t--{,no}-request-pac request KDC include/exclude a PAC\n"));
        assert_eq!(rc, 2, "{args:?}");
    }
}

#[test]
fn kinit_v4_refused() {
    assert_eq!(
        run(KINIT, &["-4"]),
        ("Kerberos 4 is no longer supported\n".into(), 3)
    );
}

#[test]
fn kswitch_usage() {
    let usage = "\t-c specify name of credentials cache\n\t-p specify name of principal\n";
    let (out, rc) = run(KSWITCH, &[]);
    assert!(
        out.starts_with("One of -c or -p must be specified\nUsage: "),
        "{out}"
    );
    assert!(out.ends_with(usage));
    assert_eq!(rc, 2);
    let (out, rc) = run(KSWITCH, &["-c", "a", "-p", "b"]);
    assert!(
        out.starts_with("Only one -c or -p option allowed\n"),
        "{out}"
    );
    assert_eq!(rc, 2);
}

#[test]
fn missing_file_cache() {
    // kdestroy has no com_err hook, so the line ends in "\r\n"; a missing
    // cache is not a failure (kdestroy.c:209-218).
    for args in [
        &["-c", "FILE:/nonexistent/x"][..],
        &["-q", "-c", "FILE:/nonexistent/x"],
    ] {
        let (out, rc) = run(KDESTROY, args);
        assert!(
            out.ends_with(": No credentials cache found while destroying cache\r\n"),
            "{out:?}"
        );
        assert_eq!(rc, 0);
    }
    // klist installs extended_com_err_fn: "\n".
    let (out, rc) = run(KLIST, &["-c", "FILE:/nonexistent/x"]);
    assert!(
        out.ends_with(": No credentials cache found (filename: /nonexistent/x)\n"),
        "{out:?}"
    );
    assert_eq!(rc, 1);
    assert_eq!(
        run(KLIST, &["-s", "-c", "FILE:/nonexistent/x"]),
        (String::new(), 1)
    );
}

#[test]
fn kvno_usage() {
    let (out, rc) = run(KVNO, &[]);
    assert!(out.starts_with("usage: "), "{out}");
    assert!(out.ends_with("[--cached-only] [--no-store] [--out-cache] service1 service2 ...\n"));
    assert_eq!(rc, 1);
}
