//! `KRB5_TRACE` names a file that trace lines are appended to, as in MIT
//! k5_init_trace. One test, since the variable is read once per process.

use krb5_rs::ccache::*;
use krb5_rs::types::*;
use rasn::types::GeneralString;

#[test]
fn krb5_trace_appends_mit_lines() {
    let dir = std::env::temp_dir().join(format!("krb5rs-trace-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("trace.log");
    std::env::set_var("KRB5_TRACE", &path);
    std::env::set_var("HOME", &dir);

    let cc = CcContext {
        default_name: Some(format!("MEMORY:trace-{}", std::process::id())),
        ..Default::default()
    };
    let server = PrincipalName {
        name_type: 1,
        name_string: ["host", "h.example.com"]
            .iter()
            .map(|p| GeneralString::from_bytes(p.as_bytes()).unwrap())
            .collect(),
    };
    assert!(cc_select(&cc, None, &server, "EXAMPLE.COM").is_err());
    std::fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .map(|mut f| std::io::Write::write_all(&mut f, b"marker\n"))
        .unwrap()
        .unwrap();
    assert!(cc_select(&cc, None, &server, "EXAMPLE.COM").is_err());

    let text = std::fs::read_to_string(&path).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    let want = "ccselect can't find appropriate cache for server principal \
                host/h.example.com@EXAMPLE.COM";
    assert_eq!(lines.len(), 3, "{text}");
    assert_eq!(lines[1], "marker");
    let prefix = format!("[{}] ", std::process::id());
    for l in [lines[0], lines[2]] {
        assert!(
            l.starts_with(&prefix) && l.ends_with(&format!(": {want}")),
            "{l}"
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode & 0o077, 0, "{mode:o}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}
