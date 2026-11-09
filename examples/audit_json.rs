//! An audit module that appends each KDC event to a file as JSON, as MIT's
//! `plugins/audit/test/au_test.c` appends `kdc_j_encode.c` output to
//! `au.log`.
//!
//! ```text
//! cargo run --example audit_json --features kdc -- /run/audit.sock /var/log/kdc-audit.log
//! ```
//!
//! and in `kdc.conf`:
//!
//! ```ini
//! [plugins]
//!     audit = {
//!         module = json:/run/audit.sock
//!     }
//! ```

#[cfg(unix)]
fn main() -> std::io::Result<()> {
    use krb5_rs::kdc::plugins::{jenc, rpc::serve_audit, Audit, AuditState};
    use std::fs::{File, OpenOptions};
    use std::io::Write;
    use std::os::unix::net::UnixListener;
    use std::sync::{Arc, Mutex};

    struct Json(Mutex<File>);

    impl Json {
        fn write(&self, json: Vec<u8>) {
            let mut f = self.0.lock().unwrap_or_else(|e| e.into_inner());
            let _ = f.write_all(&json).and_then(|()| f.write_all(b"\n"));
        }
    }

    impl Audit for Json {
        fn name(&self) -> &str {
            "json"
        }
        fn kdc_start(&self, ok: bool) {
            self.write(jenc::kdc_start(ok));
        }
        fn kdc_stop(&self, ok: bool) {
            self.write(jenc::kdc_stop(ok));
        }
        fn as_req(&self, ok: bool, st: &AuditState) {
            self.write(jenc::as_req(ok, st));
        }
        fn tgs_req(&self, ok: bool, st: &AuditState) {
            self.write(jenc::tgs_req(ok, st));
        }
        fn s4u2self(&self, ok: bool, st: &AuditState) {
            self.write(jenc::s4u2self(ok, st));
        }
        fn s4u2proxy(&self, ok: bool, st: &AuditState) {
            self.write(jenc::s4u2proxy(ok, st));
        }
        fn u2u(&self, ok: bool, st: &AuditState) {
            self.write(jenc::u2u(ok, st));
        }
    }

    let mut args = std::env::args_os().skip(1);
    let (Some(sock), Some(log)) = (args.next(), args.next()) else {
        eprintln!("usage: audit_json SOCKET LOGFILE");
        std::process::exit(2);
    };
    let log = OpenOptions::new().create(true).append(true).open(log)?;
    let module = Arc::new(Json(Mutex::new(log)));
    let listener = UnixListener::bind(&sock)?;
    for stream in listener.incoming() {
        let stream = stream?;
        let module = module.clone();
        std::thread::spawn(move || serve_audit(stream, &*module));
    }
    Ok(())
}

#[cfg(not(unix))]
fn main() {
    eprintln!("audit_json needs Unix sockets");
}
