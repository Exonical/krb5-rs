//! Modules as separate processes, reached over RPC the way p11-kit remotes
//! PKCS #11 modules (as in <https://github.com/smallstep/go-p11-kit>): the
//! library connects to a module's socket, agrees on a protocol version,
//! and sends each callback as a request; the module answers each in turn.
//!
//! Framing follows p11-kit's RPC: one version byte each way (the module
//! answers the lower of the client's and its own), then messages of
//! `id u32, options_len u32, buffer_len u32` (big-endian) followed by
//! `options_len` ignored bytes and a buffer of `call u32`, a signature
//! (`u32` length and bytes) and the fields. Field types: `i` is an `i32`,
//! `s` a string (`u32` length, `0xFFFFFFFF` for none, UTF-8 bytes), `as`
//! a `u32` count of strings and `ay` bytes (`u32` length). A failed call is
//! answered with call [`call::ERROR`] and `is`: an MIT com_err code and an
//! optional status. The first request is [`call::INITIALIZE`] with the
//! interface's handshake string, and the last [`call::FINALIZE`].

use std::io::{self, Read, Write};
use std::sync::{Mutex, MutexGuard, PoisonError};

/// The RPC protocol version.
pub const PROTOCOL_VERSION: u8 = 1;
/// `KRB5_PLUGIN_NO_HANDLE`.
pub const PLUGIN_NO_HANDLE: i32 = -1_765_328_135;
/// `KRB5_PLUGIN_VER_NOTSUPP`.
pub const PLUGIN_VER_NOTSUPP: i32 = -1_765_328_136;
/// `ERROR_TABLE_BASE_krb5`: protocol error `n` is com_err code base + `n`.
pub const ERROR_TABLE_BASE_KRB5: i32 = -1_765_328_384;
pub(crate) const KRB_ERR_GENERIC: i32 = 60;
const MAX_MESSAGE: u32 = 1 << 20;

/// Call numbers every interface shares; interfaces number theirs from 3.
pub mod call {
    /// A failed call's answer.
    pub const ERROR: u32 = 0;
    /// `init` / `open`: `s` handshake.
    pub const INITIALIZE: u32 = 1;
    /// `fini` / `close`.
    pub const FINALIZE: u32 = 2;
}

pub(crate) fn bad(m: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, m.into())
}

/// A request or answer.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Message {
    /// The call number.
    pub call: u32,
    sig: String,
    buf: Vec<u8>,
    pos: usize,
}

impl Message {
    /// An empty message for `call`.
    pub fn new(call: u32) -> Self {
        Self {
            call,
            ..Self::default()
        }
    }

    /// Append an `i`.
    pub fn put_i32(&mut self, v: i32) -> &mut Self {
        self.sig.push('i');
        self.buf.extend(v.to_be_bytes());
        self
    }

    fn raw_str(&mut self, s: Option<&str>) {
        match s {
            Some(s) => {
                // A string over 4 GiB makes the message too long to send.
                let n = u32::try_from(s.len()).unwrap_or(u32::MAX - 1);
                self.buf.extend(n.to_be_bytes());
                self.buf.extend(s.as_bytes());
            }
            None => self.buf.extend(u32::MAX.to_be_bytes()),
        }
    }

    /// Append an `s`.
    pub fn put_str(&mut self, s: Option<&str>) -> &mut Self {
        self.sig.push('s');
        self.raw_str(s);
        self
    }

    /// Append an `as`.
    pub fn put_strs(&mut self, v: &[String]) -> &mut Self {
        self.sig.push_str("as");
        let n = u32::try_from(v.len()).unwrap_or(u32::MAX);
        self.buf.extend(n.to_be_bytes());
        for s in v {
            self.raw_str(Some(s));
        }
        self
    }

    /// Append an `ay`.
    pub fn put_bytes(&mut self, v: &[u8]) -> &mut Self {
        self.sig.push_str("ay");
        let n = u32::try_from(v.len()).unwrap_or(u32::MAX - 1);
        self.buf.extend(n.to_be_bytes());
        self.buf.extend(v);
        self
    }

    fn expect(&mut self, want: &str) -> io::Result<()> {
        if self.sig.starts_with(want) {
            self.sig.drain(..want.len());
            Ok(())
        } else {
            Err(bad(format!("expected '{want}', have '{}'", self.sig)))
        }
    }

    fn take(&mut self, n: usize) -> io::Result<&[u8]> {
        let end = self
            .pos
            .checked_add(n)
            .filter(|&e| e <= self.buf.len())
            .ok_or_else(|| bad("truncated message"))?;
        let s = &self.buf[self.pos..end];
        self.pos = end;
        Ok(s)
    }

    fn raw_u32(&mut self) -> io::Result<u32> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// Read an `i`.
    pub fn get_i32(&mut self) -> io::Result<i32> {
        self.expect("i")?;
        let b = self.take(4)?;
        Ok(i32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn raw_string(&mut self) -> io::Result<Option<String>> {
        let n = self.raw_u32()?;
        if n == u32::MAX {
            return Ok(None);
        }
        let b = self.take(n as usize)?.to_vec();
        String::from_utf8(b)
            .map(Some)
            .map_err(|_| bad("string is not UTF-8"))
    }

    /// Read an `s`.
    pub fn get_str(&mut self) -> io::Result<Option<String>> {
        self.expect("s")?;
        self.raw_string()
    }

    /// Read an `as`.
    pub fn get_strs(&mut self) -> io::Result<Vec<String>> {
        self.expect("as")?;
        let n = self.raw_u32()?;
        let mut v = Vec::new();
        for _ in 0..n {
            v.push(
                self.raw_string()?
                    .ok_or_else(|| bad("missing string in array"))?,
            );
        }
        Ok(v)
    }

    /// Read an `ay`.
    pub fn get_bytes(&mut self) -> io::Result<Vec<u8>> {
        self.expect("ay")?;
        let n = self.raw_u32()?;
        Ok(self.take(n as usize)?.to_vec())
    }

    /// Fail if fields are left unread.
    pub fn finish(&self) -> io::Result<()> {
        if !self.sig.is_empty() || self.pos != self.buf.len() {
            return Err(bad(format!("trailing elements '{}'", self.sig)));
        }
        Ok(())
    }
}

fn be32(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}

/// Send `m` as message `id`.
pub fn write_message(w: &mut impl Write, id: u32, m: &Message) -> io::Result<()> {
    let sig_len = u32::try_from(m.sig.len()).map_err(|_| bad("message too long"))?;
    let len = u32::try_from(8 + m.sig.len() + m.buf.len())
        .ok()
        .filter(|&l| l <= MAX_MESSAGE)
        .ok_or_else(|| bad("message too long"))?;
    let mut out = Vec::with_capacity(12 + len as usize);
    out.extend(id.to_be_bytes());
    out.extend(0u32.to_be_bytes());
    out.extend(len.to_be_bytes());
    out.extend(m.call.to_be_bytes());
    out.extend(sig_len.to_be_bytes());
    out.extend(m.sig.as_bytes());
    out.extend(&m.buf);
    w.write_all(&out)?;
    w.flush()
}

/// Receive a message and its id.
pub fn read_message(r: &mut impl Read) -> io::Result<(u32, Message)> {
    let mut h = [0u8; 12];
    r.read_exact(&mut h)?;
    let (id, opts, len) = (be32(&h[0..4]), be32(&h[4..8]), be32(&h[8..12]));
    let total = opts
        .checked_add(len)
        .filter(|&t| t <= MAX_MESSAGE)
        .ok_or_else(|| bad("message too long"))?;
    let mut b = vec![0; total as usize];
    r.read_exact(&mut b)?;
    let mut m = Message {
        buf: b.split_off(opts as usize),
        ..Message::default()
    };
    m.call = m.raw_u32()?;
    let n = m.raw_u32()?;
    let sig = m.take(n as usize)?.to_vec();
    m.sig = String::from_utf8(sig).map_err(|_| bad("signature is not UTF-8"))?;
    Ok((id, m))
}

/// An error answer: com_err code and status.
pub type CallError = (i32, Option<String>);

fn error_message(code: i32, status: Option<&str>) -> Message {
    let mut m = Message::new(call::ERROR);
    m.put_i32(code).put_str(status);
    m
}

/// The KDC end of a module connection.
pub struct Client<S> {
    stream: S,
    next_id: u32,
}

impl<S: Read + Write> Client<S> {
    /// Agree on the protocol version and initialize the module.
    pub fn handshake(mut stream: S, handshake: &str) -> io::Result<Result<Self, CallError>> {
        stream.write_all(&[PROTOCOL_VERSION])?;
        stream.flush()?;
        let mut v = [0u8];
        stream.read_exact(&mut v)?;
        if v[0] != PROTOCOL_VERSION {
            return Err(bad(format!("module speaks protocol version {}", v[0])));
        }
        let mut c = Self { stream, next_id: 0 };
        let mut m = Message::new(call::INITIALIZE);
        m.put_str(Some(handshake));
        Ok(c.call(&m)?.map(|_| c))
    }

    /// Send `m` and wait for its answer.
    pub fn call(&mut self, m: &Message) -> io::Result<Result<Message, CallError>> {
        self.next_id = self.next_id.wrapping_add(1);
        write_message(&mut self.stream, self.next_id, m)?;
        let (id, mut r) = read_message(&mut self.stream)?;
        if id != self.next_id {
            return Err(bad("answer to another request"));
        }
        if r.call == call::ERROR {
            let code = r.get_i32()?;
            let status = r.get_str()?;
            r.finish()?;
            return Ok(Err((code, status)));
        }
        if r.call != m.call {
            return Err(bad("answer to another call"));
        }
        Ok(Ok(r))
    }
}

/// Serve the module end of a connection: `handle` answers every request
/// after the handshake, including [`call::INITIALIZE`] and
/// [`call::FINALIZE`], after which the connection ends.
pub fn serve<S: Read + Write>(
    mut stream: S,
    handshake: &str,
    mut handle: impl FnMut(&mut Message) -> io::Result<Result<Message, CallError>>,
) -> io::Result<()> {
    let mut v = [0u8];
    stream.read_exact(&mut v)?;
    stream.write_all(&[v[0].min(PROTOCOL_VERSION)])?;
    stream.flush()?;
    loop {
        let (id, mut req) = match read_message(&mut stream) {
            Ok(r) => r,
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(e) => return Err(e),
        };
        let done = req.call == call::FINALIZE;
        let answer = if req.call == call::INITIALIZE
            && req.get_str().ok().flatten().as_deref() != Some(handshake)
        {
            Err((PLUGIN_VER_NOTSUPP, None))
        } else {
            // A request that doesn't decode is answered, as p11-kit does,
            // so the connection stays in step.
            handle(&mut req).unwrap_or_else(|e| {
                Err((ERROR_TABLE_BASE_KRB5 + KRB_ERR_GENERIC, Some(e.to_string())))
            })
        };
        let m = match answer {
            Ok(m) => m,
            Err((code, status)) => error_message(code, status.as_deref()),
        };
        write_message(&mut stream, id, &m)?;
        if done {
            return Ok(());
        }
    }
}

/// A connection the KDC can read and write.
pub trait Stream: Read + Write + Send {}
impl<T: Read + Write + Send> Stream for T {}

/// Opens a new connection to a module.
pub type Connect = Box<dyn Fn() -> io::Result<Box<dyn Stream>> + Send + Sync>;

/// Why a module was not loaded.
#[derive(Debug)]
pub enum InitError {
    /// The module could not be reached; MIT skips a module that does not load.
    Unavailable(io::Error),
    /// The module's `init`/`open` failed with this code.
    Refused(CallError),
}

impl std::fmt::Display for InitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unavailable(e) => write!(f, "{e}"),
            Self::Refused((code, _)) => write!(f, "{code}"),
        }
    }
}

/// One module connection: calls run one at a time, and a broken
/// connection is opened again on the next call.
pub struct Conn {
    pub(crate) name: String,
    handshake: &'static str,
    connect: Connect,
    client: Mutex<Option<Client<Box<dyn Stream>>>>,
}

impl Conn {
    /// Connect and initialize the module with `handshake`.
    pub fn open(name: &str, handshake: &'static str, connect: Connect) -> Result<Self, InitError> {
        let stream = connect().map_err(InitError::Unavailable)?;
        let client = Client::handshake(stream, handshake)
            .map_err(InitError::Unavailable)?
            .map_err(InitError::Refused)?;
        Ok(Self {
            name: name.into(),
            handshake,
            connect,
            client: Mutex::new(Some(client)),
        })
    }

    fn lock(&self) -> MutexGuard<'_, Option<Client<Box<dyn Stream>>>> {
        self.client.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// One call; calls run one at a time, and a broken connection is
    /// opened again (and the module initialized again) on the next call.
    pub fn call(&self, m: &Message) -> io::Result<Result<Message, CallError>> {
        off_runtime(|| self.call_blocking(m))
    }

    fn call_blocking(&self, m: &Message) -> io::Result<Result<Message, CallError>> {
        let mut client = self.lock();
        if client.is_none() {
            match Client::handshake((self.connect)()?, self.handshake)? {
                Ok(c) => *client = Some(c),
                Err((code, _)) => {
                    return Err(io::Error::other(format!(
                        "module {} failed to initialize: {code}",
                        self.name
                    )))
                }
            }
        }
        let Some(c) = client.as_mut() else {
            return Err(io::Error::other("no connection"));
        };
        let r = c.call(m);
        if r.is_err() {
            *client = None;
        }
        r
    }
}

impl Drop for Conn {
    fn drop(&mut self) {
        if let Some(c) = self.lock().as_mut() {
            let _ = c.call(&Message::new(call::FINALIZE));
        }
    }
}

/// Run blocking module I/O without stalling a multi-threaded Tokio runtime's
/// other tasks.
fn off_runtime<T>(f: impl FnOnce() -> T) -> T {
    #[cfg(feature = "tokio")]
    if let Ok(h) = tokio::runtime::Handle::try_current() {
        if h.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread {
            return tokio::task::block_in_place(f);
        }
    }
    f()
}

/// Connect to a Unix socket, with `timeout` on each read and write.
#[cfg(unix)]
pub fn unix_connector(path: std::path::PathBuf, timeout: std::time::Duration) -> Connect {
    Box::new(move || {
        let s = std::os::unix::net::UnixStream::connect(&path)?;
        s.set_read_timeout(Some(timeout))?;
        s.set_write_timeout(Some(timeout))?;
        Ok(Box::new(s) as Box<dyn Stream>)
    })
}
