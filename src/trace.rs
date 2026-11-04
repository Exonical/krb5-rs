//! MIT-compatible library tracing (lib/krb5/os/trace.c, include/k5-trace.h).
//!
//! When `KRB5_TRACE` names a file, trace messages are appended to it in
//! MIT's format, `[pid] sec.usec: message`. [`set_trace_callback`] and
//! [`set_trace_filename`] replace the destination, as
//! `krb5_set_trace_callback` and `krb5_set_trace_filename` do. MIT keeps the
//! callback in each `krb5_context`; this crate has no context, so the
//! destination is process-wide.

use std::fmt::Write as _;
use std::io::Write as _;
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use sha1::{Digest, Sha1};

use crate::types::PrincipalName;

/// A trace callback; it receives each complete line, ending in `\n`.
pub type TraceCallback = Arc<dyn Fn(&str) + Send + Sync>;

fn slot() -> &'static RwLock<Option<TraceCallback>> {
    static SLOT: OnceLock<RwLock<Option<TraceCallback>>> = OnceLock::new();
    SLOT.get_or_init(|| {
        // k5_init_trace: KRB5_TRACE names the trace file.
        let cb = std::env::var_os("KRB5_TRACE").and_then(|f| file_callback(f.as_ref()).ok());
        RwLock::new(cb)
    })
}

fn file_callback(path: &std::path::Path) -> std::io::Result<TraceCallback> {
    let mut opts = std::fs::OpenOptions::new();
    opts.append(true).create(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut opts, 0o600);
    let file = Mutex::new(opts.open(path)?);
    Ok(Arc::new(move |msg: &str| {
        let mut f = file.lock().unwrap_or_else(|e| e.into_inner());
        let _ = f.write_all(msg.as_bytes());
    }))
}

/// `krb5_set_trace_callback`: send trace lines to `cb`, or stop tracing
/// with `None`.
pub fn set_trace_callback(cb: Option<TraceCallback>) {
    *slot().write().unwrap_or_else(|e| e.into_inner()) = cb;
}

/// `krb5_set_trace_filename`: append trace lines to `path` (created mode
/// 0600).
pub fn set_trace_filename(path: impl AsRef<std::path::Path>) -> std::io::Result<()> {
    let cb = file_callback(path.as_ref())?;
    set_trace_callback(Some(cb));
    Ok(())
}

/// Whether a trace destination is set; trace points skip formatting
/// otherwise.
pub fn enabled() -> bool {
    slot().read().map(|s| s.is_some()).unwrap_or(false)
}

/// `krb5int_trace`: emit `msg` with MIT's `[pid] sec.usec: ` prefix.
pub fn emit(msg: &str) {
    let cb = match slot().read() {
        Ok(s) => match s.as_ref() {
            Some(cb) => cb.clone(),
            None => return,
        },
        Err(_) => return,
    };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    cb(&format!(
        "[{}] {}.{:06}: {}\n",
        std::process::id(),
        now.as_secs(),
        now.subsec_micros(),
        msg
    ));
}

/// Emit a trace message built with `format!` arguments, formatting it only
/// when tracing is enabled.
#[macro_export]
#[doc(hidden)]
macro_rules! k5trace {
    ($($arg:tt)*) => {
        if $crate::trace::enabled() {
            $crate::trace::emit(&format!($($arg)*));
        }
    };
}

/// `{str}`/`{data}`/`{lenstr}`: printable bytes as-is, others as `\xNN`.
pub fn data(d: &[u8]) -> String {
    let mut s = String::with_capacity(d.len());
    for &b in d {
        if (32..=126).contains(&b) {
            s.push(b as char);
        } else {
            let _ = write!(s, "\\x{b:02x}");
        }
    }
    s
}

/// `{hexlenstr}`/`{hexdata}`: upper-case hex.
pub fn hex(d: &[u8]) -> String {
    d.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02X}");
        s
    })
}

/// `{hashlenstr}`: the first two bytes of the SHA-1 of `d`, in hex.
pub fn hash(d: &[u8]) -> String {
    hex(&Sha1::digest(d)[..2])
}

/// `{princ}`: the unparsed principal.
pub fn princ(name: &PrincipalName, realm: &str) -> String {
    crate::ccache::unparse_name(name, realm)
}

/// `{creds}`: `client -> server`.
pub fn creds(client: &PrincipalName, crealm: &str, server: &PrincipalName, srealm: &str) -> String {
    format!("{} -> {}", princ(client, crealm), princ(server, srealm))
}

/// `{etype}`: the shortest MIT name, else the number.
pub fn etype(e: i32) -> String {
    crate::crypto::enctype_short_name(e).map_or_else(|| e.to_string(), str::to_string)
}

/// `{etypes}`: comma-separated, or `(empty)`.
pub fn etypes(list: &[i32]) -> String {
    if list.is_empty() {
        return "(empty)".into();
    }
    list.iter()
        .map(|&e| etype(e))
        .collect::<Vec<_>>()
        .join(", ")
}

/// `{keyblock}`: `etype/hash`.
pub fn keyblock(etype_num: i32, key: &[u8]) -> String {
    format!("{}/{}", etype(etype_num), hash(key))
}

/// `{kerr}`: `code/message`, `0/Success` for 0.
pub fn kerr(code: i64, msg: &str) -> String {
    if code == 0 {
        "0/Success".into()
    } else {
        format!("{code}/{msg}")
    }
}

/// `{ptype}` (trace.c `principal_type_string`).
pub fn ptype(t: i32) -> &'static str {
    match t {
        0 => "unknown",
        1 => "principal",
        2 => "service instance",
        3 => "service with host as instance",
        4 => "service with host as components",
        5 => "unique ID",
        6 => "X.509",
        7 => "SMTP email",
        10 => "Windows 2000 UPN",
        11 => "well-known",
        -128 => "Windows 2000 UPN and SID",
        -129 => "NT 4 style name",
        -130 => "NT 4 style name and SID",
        _ => "?",
    }
}

/// trace.c `padata_type_string`.
fn padata_type_name(t: i32) -> Option<&'static str> {
    Some(match t {
        1 => "PA-TGS-REQ",
        2 => "PA-ENC-TIMESTAMP",
        3 => "PA-PW-SALT",
        5 => "PA-ENC-UNIX-TIME",
        6 => "PA-SANDIA-SECUREID",
        7 => "PA-SESAME",
        8 => "PA-OSF-DCE",
        9 => "PA-CYBERSAFE-SECUREID",
        10 => "PA-AFS3-SALT",
        11 => "PA-ETYPE-INFO",
        12 => "PA-SAM-CHALLENGE",
        13 => "PA-SAM-RESPONSE",
        14 => "PA-PK-AS-REQ_OLD",
        15 => "PA-PK-AS-REP_OLD",
        16 => "PA-PK-AS-REQ",
        17 => "PA-PK-AS-REP",
        19 => "PA-ETYPE-INFO2",
        20 => "PA-SVR-REFERRAL-INFO",
        21 => "PA-SAM-REDIRECT",
        22 => "PA-GET-FROM-TYPED-DATA",
        30 => "PA-SAM-CHALLENGE2",
        31 => "PA-SAM-RESPONSE2",
        128 => "PA-PAC-REQUEST",
        129 => "PA-FOR_USER",
        130 => "PA-FOR-X509-USER",
        132 => "PA-AS-CHECKSUM",
        133 => "PA-FX-COOKIE",
        136 => "PA-FX-FAST",
        137 => "PA-FX-ERROR",
        138 => "PA-ENCRYPTED-CHALLENGE",
        141 => "PA-OTP-CHALLENGE",
        142 => "PA-OTP-REQUEST",
        144 => "PA-OTP-PIN-CHANGE",
        147 => "PA-PKINIT-KX",
        149 => "PA-REQ-ENC-PA-REP",
        150 => "PA_AS_FRESHNESS",
        151 => "PA-SPAKE",
        152 => "PA-REDHAT-IDP-OAUTH2",
        153 => "PA-REDHAT-PASSKEY",
        _ => return None,
    })
}

/// `{patype}`: `NAME (n)`, else `n`.
pub fn patype(t: i32) -> String {
    padata_type_name(t).map_or_else(|| t.to_string(), |n| format!("{n} ({t})"))
}

/// `{patypes}`: comma-separated, or `(empty)`.
pub fn patypes(list: &[i32]) -> String {
    if list.is_empty() {
        return "(empty)".into();
    }
    list.iter()
        .map(|&t| patype(t))
        .collect::<Vec<_>>()
        .join(", ")
}

/// `{raddr}`: socket type and address (`k5_print_addr_port`).
pub fn raddr(tcp: bool, addr: &std::net::SocketAddr) -> String {
    format!(
        "{} {}",
        if tcp { "stream" } else { "dgram" },
        addr_port(addr)
    )
}

/// `k5_print_addr_port`: `a.b.c.d:port`, `[v6]:port`.
pub fn addr_port(addr: &std::net::SocketAddr) -> String {
    match addr {
        std::net::SocketAddr::V4(a) => format!("{}:{}", a.ip(), a.port()),
        std::net::SocketAddr::V6(a) => format!("[{}]:{}", a.ip(), a.port()),
    }
}

/// `{errno}`: `n/strerror`.
pub fn errno(e: &std::io::Error) -> String {
    match e.raw_os_error() {
        Some(n) => {
            let s = e.to_string();
            let msg = s.split(" (os error").next().unwrap_or(&s);
            format!("{n}/{msg}")
        }
        None => format!("0/{e}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Lines from MIT lib/krb5/os/t_trace.ref.
    #[test]
    fn formats_match_t_trace_ref() {
        assert_eq!(data(b"example.data"), "example.data");
        assert_eq!(hex(b"example.data"), "6578616D706C652E64617461");
        assert_eq!(hash(b"example.data"), "7B9A");
        assert_eq!(keyblock(511, b"example.data"), "511/7B9A");
        assert_eq!(kerr(0, ""), "0/Success");
        assert_eq!(etype(17), "aes128-cts");
        assert_eq!(etypes(&[5, 24, 511]), "5, rc4-hmac-exp, 511");
        assert_eq!(etypes(&[]), "(empty)");
        assert_eq!(patypes(&[3, 0]), "PA-PW-SALT (3), 0");
        assert_eq!(patypes(&[]), "(empty)");
        assert_eq!(ptype(1), "principal");
        assert_eq!(ptype(-130), "NT 4 style name and SID");
        assert_eq!(ptype(99), "?");
        let a = "0.0.0.0:88".parse().expect("addr");
        assert_eq!(raddr(true, &a), "stream 0.0.0.0:88");
        assert_eq!(raddr(false, &a), "dgram 0.0.0.0:88");
        #[cfg(unix)]
        {
            let e = std::io::Error::from_raw_os_error(2);
            assert_eq!(errno(&e), "2/No such file or directory");
        }
        assert_eq!(data(b"a\x01b"), "a\\x01b");
    }

    #[test]
    fn emit_uses_mit_line_format() {
        let lines = Arc::new(Mutex::new(Vec::<String>::new()));
        let l = lines.clone();
        set_trace_callback(Some(Arc::new(move |m: &str| {
            l.lock().expect("lock").push(m.to_string());
        })));
        crate::k5trace!("simple {}", "format");
        set_trace_callback(None);
        crate::k5trace!("dropped");
        let got = lines.lock().expect("lock").clone();
        let ours: Vec<_> = got
            .iter()
            .filter(|l| l.ends_with(": simple format\n"))
            .collect();
        assert_eq!(ours.len(), 1, "{got:?}");
        let l = ours[0];
        let pid = format!("[{}] ", std::process::id());
        assert!(l.starts_with(&pid), "{l}");
        let ts = &l[pid.len()..l.len() - ": simple format\n".len()];
        let (sec, usec) = ts.split_once('.').expect("sec.usec");
        assert!(sec.parse::<u64>().is_ok() && usec.len() == 6, "{l}");
    }
}
