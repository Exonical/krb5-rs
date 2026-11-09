//! MIT `krb5kdc -w` (kdc/main.c `create_workers`, main.c:469-578). The
//! supervisor binds the sockets and runs that many workers that serve them;
//! when one worker exits, or the supervisor gets SIGTERM or SIGINT, it stops
//! them all. SIGHUP is passed on to the workers. MIT forks the workers; here
//! the binary runs itself again with the sockets inherited.

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::process::ExitStatusExt;

use tokio::net::{TcpListener, UdpSocket};
use tokio::signal::unix::{signal, SignalKind};
use tokio::task::JoinSet;
use tracing::{error, info};

/// Tells a worker which inherited descriptors are its sockets (`u3,t5`).
pub const ENV: &str = "KRB5RS_KDC_WORKER_FDS";

/// The [`ENV`] value for these sockets, and their descriptors.
pub fn encode(udp: &[UdpSocket], tcp: &[TcpListener]) -> (String, Vec<RawFd>) {
    let fds: Vec<(char, RawFd)> = udp
        .iter()
        .map(|s| ('u', s.as_raw_fd()))
        .chain(tcp.iter().map(|l| ('t', l.as_raw_fd())))
        .collect();
    let spec = fds
        .iter()
        .map(|(k, fd)| format!("{k}{fd}"))
        .collect::<Vec<_>>()
        .join(",");
    (spec, fds.into_iter().map(|(_, fd)| fd).collect())
}

/// In a worker: take over the sockets [`ENV`] names.
pub fn adopt(spec: &str) -> io::Result<(Vec<UdpSocket>, Vec<TcpListener>)> {
    let bad = || io::Error::new(io::ErrorKind::InvalidInput, format!("bad {ENV} {spec:?}"));
    let (mut udp, mut tcp) = (Vec::new(), Vec::new());
    for item in spec.split(',').filter(|s| !s.is_empty()) {
        let fd: RawFd = item.get(1..).and_then(|n| n.parse().ok()).ok_or_else(bad)?;
        match item.as_bytes()[0] {
            b'u' => {
                // SAFETY: the supervisor passed this bound UDP socket to us
                // alone, and nothing else in this process owns it.
                let s = unsafe { std::net::UdpSocket::from_raw_fd(fd) };
                s.set_nonblocking(true)?;
                udp.push(UdpSocket::from_std(s)?);
            }
            b't' => {
                // SAFETY: as above, for a listening TCP socket.
                let l = unsafe { std::net::TcpListener::from_raw_fd(fd) };
                l.set_nonblocking(true)?;
                tcp.push(TcpListener::from_std(l)?);
            }
            _ => return Err(bad()),
        }
    }
    Ok((udp, tcp))
}

fn kill(pids: &[u32], sig: libc::c_int) {
    for &pid in pids {
        if let Ok(pid) = libc::pid_t::try_from(pid) {
            // SAFETY: plain kill(2) on a worker we started and haven't reaped.
            unsafe { libc::kill(pid, sig) };
        }
    }
}

type Waits = JoinSet<(u32, io::Result<std::process::ExitStatus>)>;

/// `terminate_workers` (main.c:447-467).
async fn terminate(pids: &[u32], waits: &mut Waits) {
    kill(pids, libc::SIGTERM);
    while waits.join_next().await.is_some() {}
}

/// Run `num` workers on the sockets `fds` and supervise them.
pub async fn supervise(
    num: usize,
    spec: &str,
    fds: &[RawFd],
    dir: Option<&std::path::Path>,
) -> io::Result<()> {
    info!("creating {num} worker processes");
    let exe = std::env::current_exe()?;
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let mut pids = Vec::new();
    let mut waits = Waits::new();
    for _ in 0..num {
        let mut cmd = tokio::process::Command::new(&exe);
        cmd.args(&args).env(ENV, spec);
        if let Some(dir) = dir {
            cmd.current_dir(dir);
        }
        let keep = fds.to_vec();
        // SAFETY: the hook only calls fcntl(2), which is async-signal-safe.
        unsafe {
            cmd.pre_exec(move || {
                for &fd in &keep {
                    let flags = libc::fcntl(fd, libc::F_GETFD);
                    if flags == -1
                        || libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) == -1
                    {
                        return Err(io::Error::last_os_error());
                    }
                }
                Ok(())
            });
        }
        match cmd.spawn() {
            Ok(mut child) => {
                let pid = child.id().unwrap_or(0);
                pids.push(pid);
                waits.spawn(async move { (pid, child.wait().await) });
            }
            Err(e) => {
                terminate(&pids, &mut waits).await;
                return Err(e);
            }
        }
    }
    let mut term = signal(SignalKind::terminate())?;
    let mut int = signal(SignalKind::interrupt())?;
    let mut hup = signal(SignalKind::hangup())?;
    loop {
        tokio::select! {
            Some(done) = waits.join_next() => {
                if let Ok((pid, status)) = done {
                    let status = status.map(|s| s.into_raw()).unwrap_or(-1);
                    error!("worker {pid} exited with status {status}");
                    pids.retain(|&p| p != pid);
                }
                break;
            }
            _ = term.recv() => {
                info!("signal {} received in supervisor", libc::SIGTERM);
                break;
            }
            _ = int.recv() => {
                info!("signal {} received in supervisor", libc::SIGINT);
                break;
            }
            _ = hup.recv() => kill(&pids, libc::SIGHUP),
        }
    }
    terminate(&pids, &mut waits).await;
    Ok(())
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn sockets_round_trip_through_the_spec() {
        let u = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let t = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (spec, fds) = super::encode(&[u], &[t]);
        assert_eq!(fds.len(), 2);
        assert!(spec.starts_with('u') && spec.contains(",t"));
        assert!(super::adopt("x3").is_err());
    }
}
