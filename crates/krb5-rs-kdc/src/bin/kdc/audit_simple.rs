//! MIT's `plugins/audit/simple` (`au_simple_main.c`): each KDC event, encoded
//! as JSON by [`krb5_rs::kdc::plugins::jenc`], goes to the Linux audit
//! subsystem the way libaudit's `audit_log_user_message` sends it.

use krb5_rs::kdc::plugins::{jenc, Audit, AuditState};

/// `AUDIT_USER_AUTH`.
const AUDIT_USER_AUTH: u16 = 1100;
/// `AUDIT_USER_START`.
const AUDIT_USER_START: u16 = 1105;
/// `AUDIT_USER_END`.
const AUDIT_USER_END: u16 = 1106;
/// libaudit's `MAX_AUDIT_MESSAGE_LENGTH`.
const MAX_AUDIT_MESSAGE_LENGTH: usize = 8970;

/// libaudit's `audit_value_needs_encoding`.
fn needs_encoding(s: &[u8]) -> bool {
    s.iter().any(|&c| c == b'"' || !(0x21..=0x7e).contains(&c))
}

/// The `exe=` field of `audit_log_user_message` (`_get_exename`).
fn exe_field(path: &[u8]) -> String {
    if needs_encoding(path) {
        path.iter().map(|b| format!("{b:02X}")).collect()
    } else {
        format!("\"{}\"", String::from_utf8_lossy(path))
    }
}

/// The text `audit_log_user_message(fd, type, message, NULL, NULL, NULL,
/// result)` sends.
pub fn user_message(json: &[u8], exe: &str, tty: Option<&str>, success: bool) -> Vec<u8> {
    let mut m = json.to_vec();
    m.extend_from_slice(
        format!(
            " exe={exe} hostname=? addr=? terminal={} res={}",
            tty.unwrap_or("?"),
            if success { "success" } else { "failed" }
        )
        .as_bytes(),
    );
    // snprintf into a MAX_AUDIT_MESSAGE_LENGTH buffer.
    m.truncate(MAX_AUDIT_MESSAGE_LENGTH - 1);
    m
}

/// `audit_simple`: `fd` is the `audit_open` socket.
pub struct SimpleAudit {
    #[cfg(target_os = "linux")]
    sock: linux::Netlink,
    exe: String,
}

impl SimpleAudit {
    /// `audit_open`; `None` (`KRB5_PLUGIN_NO_HANDLE`) when the kernel has no
    /// audit support.
    pub fn open() -> Option<Self> {
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::ffi::OsStrExt;
            let exe = std::fs::read_link("/proc/self/exe")
                .map(|p| exe_field(p.as_os_str().as_bytes()))
                .unwrap_or_else(|_| "\"?\"".into());
            Some(Self {
                sock: linux::Netlink::open()?,
                exe,
            })
        }
        #[cfg(not(target_os = "linux"))]
        None
    }

    fn log(&self, kind: u16, json: &[u8], success: bool) {
        let tty = tty();
        let msg = user_message(json, &self.exe, tty.as_deref(), success);
        #[cfg(target_os = "linux")]
        if let Err(e) = self.sock.send(kind, &msg) {
            tracing::debug!("audit_log_user_message: {e}");
        }
        #[cfg(not(target_os = "linux"))]
        let _ = (kind, msg);
    }
}

/// libaudit's `_get_tty`: standard input's terminal, without `/dev/`.
fn tty() -> Option<String> {
    use std::io::IsTerminal;
    if !std::io::stdin().is_terminal() {
        return None;
    }
    let p = std::fs::read_link("/proc/self/fd/0").ok()?;
    let p = p.to_string_lossy();
    Some(p.strip_prefix("/dev/").unwrap_or(&p).to_owned())
}

impl Audit for SimpleAudit {
    fn name(&self) -> &str {
        "simple"
    }
    fn kdc_start(&self, ok: bool) {
        self.log(AUDIT_USER_START, &jenc::kdc_start(ok), ok);
    }
    fn kdc_stop(&self, ok: bool) {
        self.log(AUDIT_USER_END, &jenc::kdc_stop(ok), ok);
    }
    fn as_req(&self, ok: bool, st: &AuditState) {
        self.log(AUDIT_USER_AUTH, &jenc::as_req(ok, st), ok);
    }
    fn tgs_req(&self, ok: bool, st: &AuditState) {
        self.log(AUDIT_USER_AUTH, &jenc::tgs_req(ok, st), ok);
    }
    fn s4u2self(&self, ok: bool, st: &AuditState) {
        self.log(AUDIT_USER_AUTH, &jenc::s4u2self(ok, st), ok);
    }
    fn s4u2proxy(&self, ok: bool, st: &AuditState) {
        self.log(AUDIT_USER_AUTH, &jenc::s4u2proxy(ok, st), ok);
    }
    fn u2u(&self, ok: bool, st: &AuditState) {
        self.log(AUDIT_USER_AUTH, &jenc::u2u(ok, st), ok);
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::io;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Mutex;

    const NETLINK_AUDIT: libc::c_int = 9;
    const NLMSG_ERROR: u16 = 2;
    const NLMSG_HDRLEN: usize = 16;
    /// How long `check_ack` waits for the kernel's answer.
    const ACK_TIMEOUT_MS: libc::c_int = 500;

    /// An `audit_open` socket. Sends are serialized so each waits for its
    /// own acknowledgement, as libaudit's `audit_send` does.
    pub struct Netlink {
        fd: Mutex<OwnedFd>,
        seq: AtomicU32,
    }

    impl Netlink {
        pub fn open() -> Option<Self> {
            // SAFETY: socket(2) with constant arguments.
            let fd = unsafe {
                libc::socket(
                    libc::AF_NETLINK,
                    libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                    NETLINK_AUDIT,
                )
            };
            if fd < 0 {
                return None;
            }
            // SAFETY: fd is a new descriptor owned by nothing else.
            let fd = unsafe { OwnedFd::from_raw_fd(fd) };
            Some(Self {
                fd: Mutex::new(fd),
                seq: AtomicU32::new(1),
            })
        }

        /// `audit_send_user_message`: the text and its NUL, with
        /// `NLM_F_REQUEST | NLM_F_ACK`, then `check_ack`.
        pub fn send(&self, kind: u16, text: &[u8]) -> io::Result<()> {
            let seq = self.seq.fetch_add(1, Ordering::Relaxed);
            let len = NLMSG_HDRLEN + text.len() + 1;
            let mut buf = Vec::with_capacity((len + 3) & !3);
            buf.extend_from_slice(&(len as u32).to_ne_bytes());
            buf.extend_from_slice(&kind.to_ne_bytes());
            buf.extend_from_slice(&((libc::NLM_F_REQUEST | libc::NLM_F_ACK) as u16).to_ne_bytes());
            buf.extend_from_slice(&seq.to_ne_bytes());
            buf.extend_from_slice(&0u32.to_ne_bytes());
            buf.extend_from_slice(text);
            buf.push(0);
            buf.resize((len + 3) & !3, 0);
            let fd = self.fd.lock().unwrap_or_else(|e| e.into_inner());
            let raw = fd.as_raw_fd();
            // SAFETY: an all-zero sockaddr_nl addresses the kernel.
            let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
            addr.nl_family = libc::AF_NETLINK as libc::sa_family_t;
            // SAFETY: buf and addr outlive the call; the lengths match them.
            let n = unsafe {
                libc::sendto(
                    raw,
                    buf.as_ptr().cast(),
                    buf.len(),
                    0,
                    (&raw const addr).cast(),
                    std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
                )
            };
            if n < 0 {
                return Err(io::Error::last_os_error());
            }
            Self::check_ack(raw, seq)
        }

        fn check_ack(fd: libc::c_int, seq: u32) -> io::Result<()> {
            let mut reply = [0u8; 8192];
            loop {
                let mut pfd = libc::pollfd {
                    fd,
                    events: libc::POLLIN,
                    revents: 0,
                };
                // SAFETY: one valid pollfd.
                let r = unsafe { libc::poll(&raw mut pfd, 1, ACK_TIMEOUT_MS) };
                if r < 0 {
                    return Err(io::Error::last_os_error());
                }
                if r == 0 {
                    // libaudit treats a missing acknowledgement as success.
                    return Ok(());
                }
                // SAFETY: reply is writable for its whole length.
                let n = unsafe {
                    libc::recv(
                        fd,
                        reply.as_mut_ptr().cast(),
                        reply.len(),
                        libc::MSG_DONTWAIT,
                    )
                };
                if n < 0 {
                    return Err(io::Error::last_os_error());
                }
                let r = &reply[..n as usize];
                if r.len() < NLMSG_HDRLEN + 4 {
                    continue;
                }
                let kind = u16::from_ne_bytes([r[4], r[5]]);
                let rseq = u32::from_ne_bytes([r[8], r[9], r[10], r[11]]);
                if kind != NLMSG_ERROR || rseq != seq {
                    continue;
                }
                let err = i32::from_ne_bytes([r[16], r[17], r[18], r[19]]);
                return if err == 0 {
                    Ok(())
                } else {
                    Err(io::Error::from_raw_os_error(-err))
                };
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_message_is_audit_log_user_message_text() {
        let m = user_message(
            br#"{"event_name":"KDC_START","event_success":true}"#,
            "\"/usr/sbin/krb5kdc\"",
            None,
            true,
        );
        assert_eq!(
            String::from_utf8(m).expect("utf8"),
            r#"{"event_name":"KDC_START","event_success":true} exe="/usr/sbin/krb5kdc" hostname=? addr=? terminal=? res=success"#
        );
        let m = user_message(b"{}", "x", Some("pts/1"), false);
        assert!(m.ends_with(b"terminal=pts/1 res=failed"));
        assert_eq!(user_message(&[b'a'; 10000], "x", None, true).len(), 8969);
    }

    #[test]
    fn exe_is_hex_encoded_when_it_needs_encoding() {
        assert_eq!(exe_field(b"/usr/sbin/krb5kdc"), "\"/usr/sbin/krb5kdc\"");
        assert_eq!(exe_field(b"/a b"), "2F612062");
    }
}
