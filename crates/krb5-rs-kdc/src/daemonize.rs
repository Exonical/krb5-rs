//! MIT's `daemon(0, 0)` for kadmind and kpropd.
//!
//! The fork has to happen before the Tokio runtime starts threads, but MIT
//! daemonizes only after startup, so startup errors still reach the
//! terminal. [`fork`] forks at once and the parent waits: it exits 0 when the
//! child calls [`detach`] (MIT's `daemon()` call), or with the child's status
//! if the child exits first.

use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::sync::Mutex;

static READY: Mutex<Option<File>> = Mutex::new(None);

fn check(ret: libc::c_int) -> io::Result<libc::c_int> {
    match ret {
        -1 => Err(io::Error::last_os_error()),
        n => Ok(n),
    }
}

/// Fork; only the child returns.
pub fn fork() -> io::Result<()> {
    let mut fds = [0; 2];
    // SAFETY: `fds` has room for the two descriptors `pipe` writes.
    check(unsafe { libc::pipe(fds.as_mut_ptr()) })?;
    // SAFETY: `pipe` just returned these descriptors and nothing else owns them.
    let (mut read, write) = unsafe { (File::from_raw_fd(fds[0]), File::from_raw_fd(fds[1])) };
    for fd in fds {
        // SAFETY: plain fcntl on descriptors owned above.
        check(unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) })?;
    }
    // SAFETY: called before the runtime or any other thread exists.
    match check(unsafe { libc::fork() })? {
        0 => {
            drop(read);
            *READY.lock().unwrap_or_else(|e| e.into_inner()) = Some(write);
            Ok(())
        }
        pid => {
            drop(write);
            let mut byte = [0];
            if matches!(read.read(&mut byte), Ok(1)) {
                std::process::exit(0);
            }
            let mut status = 0;
            // SAFETY: `pid` is our child and `status` is a valid out pointer.
            while unsafe { libc::waitpid(pid, &mut status, 0) } == -1
                && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted
            {}
            std::process::exit(if libc::WIFEXITED(status) {
                libc::WEXITSTATUS(status)
            } else {
                1
            });
        }
    }
}

/// Finish daemonizing after [`fork`]: new session, `/` as the working
/// directory, stdio on `/dev/null`, and let the parent exit. Does nothing
/// without a prior [`fork`].
pub fn detach() -> io::Result<()> {
    let Some(mut ready) = READY.lock().unwrap_or_else(|e| e.into_inner()).take() else {
        return Ok(());
    };
    // SAFETY: setsid takes no arguments; the child is not a group leader.
    check(unsafe { libc::setsid() })?;
    std::env::set_current_dir("/")?;
    let null = File::options().read(true).write(true).open("/dev/null")?;
    for fd in 0..3 {
        // SAFETY: duplicates an owned descriptor onto stdio.
        check(unsafe { libc::dup2(null.as_raw_fd(), fd) })?;
    }
    ready.write_all(b"1")
}
