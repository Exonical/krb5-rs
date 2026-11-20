//! MIT `k5srvutil` (src/kadmin/cli/k5srvutil.sh), which drives `klist -k`
//! and `kadmin -k`. The krb5-rs tools next to this binary are used, else the
//! ones on `PATH`.

#![forbid(unsafe_code)]

use std::io::{BufRead, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};

fn usage(argv0: &str) {
    println!("Usage: {argv0} [-i] [-f file] [-e keysalts] list|change|delete|delold");
}

/// The sibling `krb5-rs-<name>`, or `name` from `PATH`.
fn tool(name: &str) -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|e| e.parent().map(|d| d.join(format!("krb5-rs-{name}"))))
        .filter(|p| p.is_file())
        .unwrap_or_else(|| PathBuf::from(name))
}

/// Run a command, returning its exit status as the shell reports it.
fn status(cmd: &mut Command) -> i32 {
    match cmd.status() {
        Ok(s) => s.code().unwrap_or(128),
        Err(_) => 127,
    }
}

/// `list_princs`: `klist -k $keytab | awk '(NR > 3) {print $2}' | sort | uniq`.
fn list_princs(keytab: &str) -> Vec<String> {
    let out = Command::new(tool("klist"))
        .args(["-k", keytab])
        .stderr(Stdio::inherit())
        .output()
        .map(|o| o.stdout)
        .unwrap_or_default();
    let mut princs: Vec<String> = String::from_utf8_lossy(&out)
        .lines()
        .skip(3)
        .map(|l| l.split_whitespace().nth(1).unwrap_or("").to_string())
        .collect();
    princs.sort();
    princs.dedup();
    princs
}

/// `interactive_prompt`: anything but an answer starting with n/N acts.
fn interactive_prompt(interactive: bool, what: &str, princ: &str) -> bool {
    if !interactive {
        return true;
    }
    print!("{what} for {princ}? [yn]");
    let _ = std::io::stdout().flush();
    let mut ans = String::new();
    let _ = std::io::stdin().lock().read_line(&mut ans);
    !matches!(ans.as_bytes().first(), Some(b'n' | b'N'))
}

/// Run `query` through `kadmin -k -t keytab -p princ` for each principal;
/// the result is the last iteration's status, as for a shell `for` loop.
fn each_princ(keytab: &str, interactive: bool, what: &str, query: impl Fn(&str) -> String) -> i32 {
    let mut rc = 0;
    for princ in list_princs(keytab) {
        rc = 0;
        if interactive_prompt(interactive, what, &princ) {
            rc = status(Command::new(tool("kadmin")).args([
                "-k",
                "-t",
                keytab,
                "-p",
                &princ,
                "-q",
                &query(&princ),
            ]));
        }
    }
    rc
}

fn main() {
    let mut args = std::env::args();
    let argv0 = args.next().unwrap_or_else(|| "k5srvutil".into());
    let (mut keytab, mut interactive, mut keysalts) =
        ("/etc/krb5.keytab".to_string(), false, String::new());
    let mut command: Option<String> = None;
    while let Some(opt) = args.next() {
        match opt.as_str() {
            "-f" => keytab = args.next().unwrap_or_default(),
            "-i" => interactive = true,
            "-e" => {
                let ks = args.next().unwrap_or_default();
                keysalts = format!("{keysalts} -e \"{ks}\"");
            }
            "change" | "delold" | "delete" | "list" => {
                if command.is_some() {
                    println!("Only one command can be specified");
                    usage(&argv0);
                    std::process::exit(1);
                }
                command = Some(opt);
            }
            _ => {
                println!("Illegal option: {opt}");
                usage(&argv0);
                std::process::exit(1);
            }
        }
    }
    let rc = match command.as_deref() {
        Some("change") => each_princ(&keytab, interactive, "Change key ", |p| {
            format!("ktadd -k {keytab} {keysalts} {p}")
        }),
        Some("delold") => each_princ(&keytab, interactive, "Delete old keys ", |p| {
            format!("ktrem -k {keytab} {p} old")
        }),
        Some("delete") => each_princ(&keytab, true, "Delete all keys ", |p| {
            format!("ktrem -k {keytab} {p} all")
        }),
        Some(_) => status(Command::new(tool("klist")).args(["-k", &keytab])),
        None => {
            usage(&argv0);
            0
        }
    };
    std::process::exit(rc);
}
