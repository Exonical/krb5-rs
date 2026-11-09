//! MIT's `[logging]` relations (`lib/kadm5/logger.c`, `krb5_klog_init`):
//! the KDC logs under `kdc`, kadmind under `admin_server`, each falling back
//! to `default`, then to syslog with facility `AUTH`. Every `tracing` event
//! of the daemon is written to each configured destination.

use std::fmt::Write as _;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock};

use krb5_rs::profile::Profile;
use tracing::field::{Field, Visit};
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::layer::{Context, Layer, SubscriberExt};
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;

/// `KRB5_KLOG_MAX_ERRMSG_SIZE`: a line, with its header, is cut to this.
const MAX_LINE: usize = 2047;

const LOG_ERR: u8 = 3;
const LOG_WARNING: u8 = 4;
const LOG_NOTICE: u8 = 5;
const LOG_INFO: u8 = 6;
const LOG_DEBUG: u8 = 7;
const LOG_AUTH: u8 = 4 << 3;

/// Syslog facilities by name, as in `krb5_klog_init`.
const FACILITIES: &[(&str, u8)] = &[
    ("AUTH", LOG_AUTH),
    ("AUTHPRIV", 10 << 3),
    ("KERN", 0),
    ("USER", 1 << 3),
    ("MAIL", 2 << 3),
    ("DAEMON", 3 << 3),
    ("FTP", 11 << 3),
    ("LPR", 6 << 3),
    ("NEWS", 7 << 3),
    ("UUCP", 8 << 3),
    ("CRON", 9 << 3),
    ("LOCAL0", 16 << 3),
    ("LOCAL1", 17 << 3),
    ("LOCAL2", 18 << 3),
    ("LOCAL3", 19 << 3),
    ("LOCAL4", 20 << 3),
    ("LOCAL5", 21 << 3),
    ("LOCAL6", 22 << 3),
    ("LOCAL7", 23 << 3),
];

/// One parsed logging specification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Spec {
    /// `FILE=path` (`append` false) or `FILE:path` (`append` true).
    File {
        path: PathBuf,
        append: bool,
    },
    /// `SYSLOG[:severity[:facility]]`.
    Syslog {
        facility: u8,
    },
    Stderr,
    Console,
    /// `DEVICE=path`.
    Device(PathBuf),
}

/// Parse `spec` as `krb5_klog_init` does, or `None` for a syntax error.
pub fn parse_spec(spec: &str) -> Option<Spec> {
    let cp = spec.trim();
    let upper = |n: usize| cp.get(..n).map(str::to_ascii_uppercase);
    if upper(4).as_deref() == Some("FILE") {
        return match cp.as_bytes().get(4) {
            Some(b':') => Some(Spec::File {
                path: cp[5..].into(),
                append: true,
            }),
            Some(b'=') => Some(Spec::File {
                path: cp[5..].into(),
                append: false,
            }),
            _ => None,
        };
    }
    if upper(6).as_deref() == Some("SYSLOG") {
        let mut facility = LOG_AUTH;
        if cp.as_bytes().get(6) == Some(&b':') {
            // The severity is ignored; the facility follows the second ':'.
            if let Some((_, name)) = cp[7..].split_once(':') {
                if let Some((_, f)) = FACILITIES
                    .iter()
                    .find(|(n, _)| n.eq_ignore_ascii_case(name))
                {
                    facility = *f;
                }
            }
        }
        return Some(Spec::Syslog { facility });
    }
    if cp.eq_ignore_ascii_case("STDERR") {
        return Some(Spec::Stderr);
    }
    if cp.eq_ignore_ascii_case("CONSOLE") {
        return Some(Spec::Console);
    }
    if upper(6).as_deref() == Some("DEVICE") && cp.as_bytes().get(6) == Some(&b'=') {
        return Some(Spec::Device(cp[7..].into()));
    }
    None
}

enum Dest {
    /// A `FILE` entry; `None` once a reopen failed.
    File {
        path: PathBuf,
        file: Option<File>,
    },
    Stderr,
    Device {
        name: String,
        file: File,
    },
    Syslog,
}

/// Where a syslog message goes; replaced in tests.
pub trait SyslogSink: Send + Sync {
    fn send(&self, priority: u8, ident: &str, msg: &str);
}

/// The logging state of one daemon (`log_control`).
pub struct Klog {
    whoami: String,
    hostname: String,
    debug: bool,
    facility: u8,
    dests: Mutex<Vec<Dest>>,
    syslog: Box<dyn SyslogSink>,
    stderr: Box<dyn Fn(&str) + Send + Sync>,
}

/// The values of `[logging] name`, from every profile in order, as
/// `profile_get_values` returns them.
fn values(profiles: &[&Profile], name: &str) -> Vec<String> {
    profiles
        .iter()
        .flat_map(|p| p.get_values(&["logging", name]))
        .collect()
}

fn open_file(path: &PathBuf, append: bool) -> std::io::Result<File> {
    let mut o = OpenOptions::new();
    o.create(true);
    if append {
        o.append(true);
    } else {
        // MIT opens `FILE=` without O_TRUNC: it overwrites from the start.
        o.write(true);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o640);
    }
    o.open(path)
}

fn hostname() -> String {
    ["/proc/sys/kernel/hostname", "/etc/hostname"]
        .iter()
        .find_map(|p| std::fs::read_to_string(p).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .or_else(|| std::env::var("HOSTNAME").ok())
        .unwrap_or_default()
}

impl Klog {
    /// `krb5_klog_init(context, ename, whoami, 1)`. `profiles` is in MIT's
    /// order: kdc.conf, then krb5.conf.
    pub fn init(profiles: &[&Profile], ename: &str, whoami: &str) -> Klog {
        Self::init_with(
            profiles,
            ename,
            whoami,
            Box::new(UnixSyslog::default()),
            Box::new(|m| eprint!("{m}")),
        )
    }

    pub fn init_with(
        profiles: &[&Profile],
        ename: &str,
        whoami: &str,
        syslog: Box<dyn SyslogSink>,
        stderr: Box<dyn Fn(&str) + Send + Sync>,
    ) -> Klog {
        let debug = profiles
            .iter()
            .find_map(|p| p.get_string(&["logging", "debug"]))
            .is_some_and(|v| {
                matches!(
                    v.to_ascii_lowercase().as_str(),
                    "y" | "yes" | "true" | "t" | "1" | "on"
                )
            });
        let mut specs = values(profiles, ename);
        if specs.is_empty() {
            specs = values(profiles, "default");
        }
        let mut dests = Vec::new();
        let mut facility = LOG_AUTH;
        for raw in &specs {
            let cp = raw.trim();
            let dest = match parse_spec(cp) {
                Some(Spec::File { path, append }) => match open_file(&path, append) {
                    Ok(file) => Some(Dest::File {
                        path,
                        file: Some(file),
                    }),
                    Err(e) => {
                        stderr(&format!("Couldn't open log file {}: {e}\n", path.display()));
                        continue;
                    }
                },
                Some(Spec::Syslog { facility: f }) => {
                    facility = f;
                    Some(Dest::Syslog)
                }
                Some(Spec::Stderr) => Some(Dest::Stderr),
                Some(Spec::Console) => OpenOptions::new()
                    .append(true)
                    .open("/dev/console")
                    .ok()
                    .map(|file| Dest::Device {
                        name: "console".into(),
                        file,
                    }),
                Some(Spec::Device(path)) => OpenOptions::new()
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .open(&path)
                    .ok()
                    .map(|file| Dest::Device {
                        name: path.display().to_string(),
                        file,
                    }),
                None => None,
            };
            match dest {
                Some(d) => dests.push(d),
                None => {
                    stderr(&format!("{whoami}: cannot parse <{cp}>\n"));
                    stderr(&format!("{whoami}: warning - logging entry syntax error\n"));
                }
            }
        }
        if dests.is_empty() {
            facility = LOG_AUTH;
            dests.push(Dest::Syslog);
        }
        Klog {
            whoami: whoami.to_string(),
            hostname: hostname(),
            debug,
            facility,
            dests: Mutex::new(dests),
            syslog,
            stderr,
        }
    }

    /// Whether debug messages reach any destination.
    pub fn wants_debug(&self) -> bool {
        self.debug
            || self
                .dests
                .lock()
                .map(|d| d.iter().any(|d| matches!(d, Dest::Syslog)))
                .unwrap_or(false)
    }

    /// `krb5_klog_syslog(priority, msg)`.
    pub fn log(&self, priority: u8, msg: &str) {
        let sev = match priority {
            0 => "EMERGENCY",
            1 => "ALERT",
            2 => "CRITICAL",
            LOG_ERR => "Error",
            LOG_WARNING => "Warning",
            LOG_NOTICE => "Notice",
            LOG_INFO => "info",
            LOG_DEBUG => "debug",
            _ => "???",
        };
        let mut line = format!(
            "{} {} {}[{}]({sev}): ",
            chrono::Local::now().format("%b %d %H:%M:%S"),
            self.hostname,
            self.whoami,
            std::process::id()
        );
        let header = line.len();
        line.push_str(msg);
        if line.len() > MAX_LINE {
            let mut end = MAX_LINE;
            while !line.is_char_boundary(end) {
                end -= 1;
            }
            line.truncate(end);
        }
        let body = line.get(header..).unwrap_or("");
        let Ok(mut dests) = self.dests.lock() else {
            return;
        };
        for d in dests.iter_mut() {
            if priority == LOG_DEBUG && !self.debug && !matches!(d, Dest::Syslog) {
                continue;
            }
            match d {
                Dest::File { path, file } => {
                    if let Some(f) = file {
                        if writeln!(f, "{line}").and_then(|()| f.flush()).is_err() {
                            (self.stderr)(&format!(
                                "{}: error writing to {}\n",
                                self.whoami,
                                path.display()
                            ));
                        }
                    }
                }
                Dest::Stderr => (self.stderr)(&format!("{line}\n")),
                Dest::Device { name, file } => {
                    if write!(file, "{line}\r\n")
                        .and_then(|()| file.flush())
                        .is_err()
                    {
                        (self.stderr)(&format!(
                            "{}: error writing to {name} device\n",
                            self.whoami
                        ));
                    }
                }
                Dest::Syslog => self
                    .syslog
                    .send(self.facility | priority, &self.whoami, body),
            }
        }
    }

    /// `krb5_klog_reopen`: reopen every `FILE` entry for appending, as on
    /// SIGHUP.
    pub fn reopen(&self) {
        let Ok(mut dests) = self.dests.lock() else {
            return;
        };
        for d in dests.iter_mut() {
            if let Dest::File { path, file } = d {
                *file = None;
                match open_file(path, true) {
                    Ok(f) => *file = Some(f),
                    Err(e) => {
                        (self.stderr)(&format!("Couldn't open log file {}: {e}\n", path.display()))
                    }
                }
            }
        }
    }
}

/// Syslog over the local socket, as `openlog(whoami, LOG_NDELAY|LOG_PID)`
/// and `syslog()`.
#[derive(Default)]
pub struct UnixSyslog {
    #[cfg(unix)]
    sock: Mutex<Option<std::os::unix::net::UnixDatagram>>,
}

#[cfg(unix)]
impl UnixSyslog {
    fn connect() -> Option<std::os::unix::net::UnixDatagram> {
        let sock = std::os::unix::net::UnixDatagram::unbound().ok()?;
        ["/dev/log", "/var/run/syslog", "/var/run/log"]
            .iter()
            .find(|p| sock.connect(p).is_ok())
            .map(|_| sock)
    }
}

impl SyslogSink for UnixSyslog {
    #[cfg(unix)]
    fn send(&self, priority: u8, ident: &str, msg: &str) {
        let packet = format!(
            "<{priority}>{} {ident}[{}]: {msg}",
            chrono::Local::now().format("%b %e %H:%M:%S"),
            std::process::id()
        );
        let Ok(mut sock) = self.sock.lock() else {
            return;
        };
        for _ in 0..2 {
            if sock.is_none() {
                *sock = Self::connect();
            }
            match sock.as_ref() {
                Some(s) if s.send(packet.as_bytes()).is_ok() => return,
                Some(_) => *sock = None,
                None => return,
            }
        }
    }

    #[cfg(not(unix))]
    fn send(&self, _priority: u8, _ident: &str, _msg: &str) {}
}

static KLOG: OnceLock<Arc<Klog>> = OnceLock::new();

/// Whether `install` has run.
#[allow(dead_code)]
pub fn installed() -> bool {
    KLOG.get().is_some()
}

/// The installed logger's program name.
#[allow(dead_code)]
pub fn whoami() -> String {
    KLOG.get().map(|k| k.whoami.clone()).unwrap_or_default()
}

/// Reopen the installed logger's files (SIGHUP).
pub fn reopen() {
    if let Some(k) = KLOG.get() {
        k.reopen();
    }
}

/// Collects an event's message and other fields.
#[derive(Default)]
struct Fields {
    message: String,
    rest: String,
}

impl Visit for Fields {
    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "message" {
            self.message.push_str(value);
        } else {
            let _ = write!(self.rest, " {}={value}", field.name());
        }
    }

    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            let _ = write!(self.message, "{value:?}");
        } else {
            let _ = write!(self.rest, " {}={value:?}", field.name());
        }
    }
}

struct KlogLayer(Arc<Klog>);

impl<S: Subscriber> Layer<S> for KlogLayer {
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let priority = match *event.metadata().level() {
            _ if event.metadata().target() == "notice" => LOG_NOTICE,
            Level::ERROR => LOG_ERR,
            Level::WARN => LOG_WARNING,
            Level::INFO => LOG_INFO,
            _ => LOG_DEBUG,
        };
        let mut f = Fields::default();
        event.record(&mut f);
        f.message.push_str(&f.rest);
        self.0.log(priority, &f.message);
    }
}

/// Install `klog` as the process's `tracing` subscriber. `RUST_LOG`, when
/// set, chooses the events; otherwise info and above, plus this project's
/// debug events when a destination takes them.
pub fn install(klog: Klog) -> Arc<Klog> {
    let klog = Arc::new(klog);
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        EnvFilter::new(if klog.wants_debug() {
            "info,krb5_rs=debug,krb5_rs_kdc=debug,krb5_rs_kadmind=debug"
        } else {
            "info"
        })
    });
    let _ = tracing_subscriber::registry()
        .with(filter)
        .with(KlogLayer(Arc::clone(&klog)))
        .try_init();
    let _ = KLOG.set(Arc::clone(&klog));
    klog
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[derive(Default, Clone)]
    struct Capture(Arc<Mutex<Vec<String>>>);

    impl SyslogSink for Capture {
        fn send(&self, priority: u8, ident: &str, msg: &str) {
            self.0
                .lock()
                .unwrap()
                .push(format!("<{priority}>{ident}: {msg}"));
        }
    }

    fn klog(conf: &str, ename: &str) -> (Klog, Capture, Capture) {
        let p = Profile::parse(conf).unwrap();
        let (sys, err) = (Capture::default(), Capture::default());
        let e = err.clone();
        let k = Klog::init_with(
            &[&p],
            ename,
            "kdc-test",
            Box::new(sys.clone()),
            Box::new(move |m| e.0.lock().unwrap().push(m.to_string())),
        );
        (k, sys, err)
    }

    #[test]
    fn parses_specs_like_mit() {
        assert_eq!(
            parse_spec("FILE:/a"),
            Some(Spec::File {
                path: "/a".into(),
                append: true
            })
        );
        assert_eq!(
            parse_spec(" file=/b "),
            Some(Spec::File {
                path: "/b".into(),
                append: false
            })
        );
        assert_eq!(parse_spec("FILE/a"), None);
        assert_eq!(
            parse_spec("SYSLOG"),
            Some(Spec::Syslog { facility: LOG_AUTH })
        );
        assert_eq!(
            parse_spec("SYSLOG:INFO:local3"),
            Some(Spec::Syslog { facility: 19 << 3 })
        );
        assert_eq!(
            parse_spec("SYSLOG:INFO:BOGUS"),
            Some(Spec::Syslog { facility: LOG_AUTH })
        );
        assert_eq!(
            parse_spec("SYSLOG:ERR"),
            Some(Spec::Syslog { facility: LOG_AUTH })
        );
        assert_eq!(parse_spec("stderr"), Some(Spec::Stderr));
        assert_eq!(parse_spec("CONSOLE"), Some(Spec::Console));
        assert_eq!(
            parse_spec("DEVICE=/dev/tty9"),
            Some(Spec::Device("/dev/tty9".into()))
        );
        assert_eq!(parse_spec("DEVICE:/dev/tty9"), None);
        assert_eq!(parse_spec("nonsense"), None);
    }

    #[test]
    fn daemon_entry_overrides_default_and_files_append_or_overwrite() {
        let dir = tempfile::tempdir().unwrap();
        let (a, b, c) = (
            dir.path().join("a.log"),
            dir.path().join("b.log"),
            dir.path().join("c.log"),
        );
        std::fs::write(&a, "old line one\n").unwrap();
        std::fs::write(&b, "0123456789012345678901234567890123456789\n").unwrap();
        let conf = format!(
            "[logging]\n kdc = FILE:{}\n kdc = FILE={}\n default = FILE:{}\n",
            a.display(),
            b.display(),
            c.display()
        );
        let (k, sys, _) = klog(&conf, "kdc");
        k.log(LOG_INFO, "hello");
        let a = std::fs::read_to_string(&a).unwrap();
        assert!(a.starts_with("old line one\n"), "{a}");
        assert!(a.contains("(info): hello\n"), "{a}");
        let b = std::fs::read_to_string(&b).unwrap();
        // Overwritten from the start, not truncated.
        assert!(b.contains("(info): hello\n"), "{b}");
        assert!(!b.starts_with("0123"), "{b}");
        assert!(!c.exists());
        assert!(sys.0.lock().unwrap().is_empty());

        let (k, _, _) = klog(&conf, "admin_server");
        k.log(LOG_ERR, "boom");
        assert!(std::fs::read_to_string(&c)
            .unwrap()
            .contains("(Error): boom\n"));
    }

    #[test]
    fn line_format_matches_mit() {
        let (k, _, err) = klog("[logging]\n default = STDERR\n", "kdc");
        k.log(LOG_WARNING, "careful");
        let lines = err.0.lock().unwrap();
        let l = &lines[0];
        let pid = format!("kdc-test[{}](Warning): careful\n", std::process::id());
        assert!(l.ends_with(&pid), "{l}");
        // "%b %d %H:%M:%S " then the host name.
        assert_eq!(l.as_bytes()[15], b' ', "{l}");
        assert_eq!(l.as_bytes()[3], b' ', "{l}");
    }

    #[test]
    fn no_entries_or_only_bad_ones_fall_back_to_syslog_auth() {
        let (k, sys, err) = klog("[libdefaults]\n x = 1\n", "kdc");
        k.log(LOG_INFO, "m");
        assert_eq!(*sys.0.lock().unwrap(), ["<38>kdc-test: m"]);
        assert!(err.0.lock().unwrap().is_empty());

        let (k, sys, err) = klog("[logging]\n kdc = BOGUS\n", "kdc");
        k.log(LOG_ERR, "m");
        assert_eq!(*sys.0.lock().unwrap(), ["<35>kdc-test: m"]);
        assert_eq!(
            *err.0.lock().unwrap(),
            [
                "kdc-test: cannot parse <BOGUS>\n",
                "kdc-test: warning - logging entry syntax error\n"
            ]
        );
    }

    #[test]
    fn unopenable_file_is_reported_and_skipped() {
        let (k, sys, err) = klog(
            "[logging]\n kdc = FILE:/nonexistent-dir/x.log\n kdc = SYSLOG:INFO:DAEMON\n",
            "kdc",
        );
        k.log(LOG_INFO, "m");
        assert_eq!(*sys.0.lock().unwrap(), ["<30>kdc-test: m"]);
        let err = err.0.lock().unwrap();
        assert_eq!(err.len(), 1);
        assert!(err[0].starts_with("Couldn't open log file /nonexistent-dir/x.log: "));
    }

    #[test]
    fn debug_goes_to_syslog_and_elsewhere_only_with_debug_true() {
        let conf = "[logging]\n kdc = STDERR\n kdc = SYSLOG\n";
        let (k, sys, err) = klog(conf, "kdc");
        assert!(k.wants_debug());
        k.log(LOG_DEBUG, "d");
        assert_eq!(sys.0.lock().unwrap().len(), 1);
        assert!(err.0.lock().unwrap().is_empty());

        let (k, _, _) = klog("[logging]\n kdc = STDERR\n", "kdc");
        assert!(!k.wants_debug());

        let (k, _, err) = klog("[logging]\n debug = true\n kdc = STDERR\n", "kdc");
        assert!(k.wants_debug());
        k.log(LOG_DEBUG, "d");
        assert!(err.0.lock().unwrap()[0].contains("(debug): d"));
    }

    #[test]
    fn device_lines_end_with_crlf_and_reopen_appends() {
        let dir = tempfile::tempdir().unwrap();
        let dev = dir.path().join("dev");
        let file = dir.path().join("f.log");
        let conf = format!(
            "[logging]\n kdc = DEVICE={}\n kdc = FILE={}\n",
            dev.display(),
            file.display()
        );
        let (k, _, _) = klog(&conf, "kdc");
        k.log(LOG_INFO, "one");
        assert!(std::fs::read_to_string(&dev)
            .unwrap()
            .ends_with("(info): one\r\n"));
        std::fs::rename(&file, dir.path().join("f.log.1")).unwrap();
        k.reopen();
        k.log(LOG_INFO, "two");
        let f = std::fs::read_to_string(&file).unwrap();
        assert!(f.contains("(info): two\n") && !f.contains("one"), "{f}");
    }

    #[test]
    fn values_come_from_every_profile_in_order() {
        let kdc = Profile::parse("[logging]\n kdc = STDERR\n").unwrap();
        let krb5 = Profile::parse("[logging]\n kdc = SYSLOG:INFO:USER\n").unwrap();
        assert_eq!(
            values(&[&kdc, &krb5], "kdc"),
            ["STDERR", "SYSLOG:INFO:USER"]
        );
    }
}
