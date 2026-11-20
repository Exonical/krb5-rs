//! `ksu`: MIT builds it only on Unix, since it relies on setuid.

#[cfg(unix)]
mod unix;

#[cfg(unix)]
fn main() {
    unix::main();
}

#[cfg(not(unix))]
fn main() {
    eprintln!("ksu: not supported on this platform");
    std::process::exit(1);
}
