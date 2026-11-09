//! MIT's sample KDC authdata module, `greet`
//! (plugins/authdata/greet_server), served on a Unix socket.
//!
//! ```text
//! cargo run --example kdcauthdata_greet -- /run/krb5-rs/greet.sock
//! ```
//!
//! and in kdc.conf:
//!
//! ```text
//! [plugins]
//!     kdcauthdata = {
//!         module = greet:unix:path=/run/krb5-rs/greet.sock
//!     }
//! ```

#[cfg(unix)]
fn main() -> std::io::Result<()> {
    use krb5_rs::kdc::plugins::{greet::Greet, rpc::serve_kdcauthdata};
    use std::os::unix::net::UnixListener;

    let Some(path) = std::env::args_os().nth(1) else {
        eprintln!("usage: kdcauthdata_greet SOCKET");
        std::process::exit(2);
    };
    let _ = std::fs::remove_file(&path);
    let listener = UnixListener::bind(&path)?;
    for stream in listener.incoming() {
        let stream = stream?;
        std::thread::spawn(move || serve_kdcauthdata(stream, &Greet));
    }
    Ok(())
}

#[cfg(not(unix))]
fn main() {
    eprintln!("kdcauthdata_greet needs Unix sockets");
}
