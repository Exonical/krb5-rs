//! The KDC's replay lookaside cache (MIT `kdc/replay.c`): a repeated request
//! packet gets the reply already sent for it, or is dropped while the first
//! copy is still being processed.

use std::collections::{BTreeMap, HashMap};
use std::sync::Mutex;

/// Entries older than this are purged (`STALE_TIME`, replay.c:59).
const STALE_TIME: i64 = 2 * 60;
/// Bound on the cache's rough memory use (`LOOKASIDE_MAX_SIZE`, replay.c:44).
const MAX_SIZE: usize = 10 * 1024 * 1024;

/// What a repeated request got from the lookaside cache.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LookasideHit {
    /// The previous reply was sent again.
    Resent,
    /// The first copy was still being processed; nothing was sent.
    Dropped,
}

struct Entry {
    seq: u64,
    timein: i64,
    reply: Option<Vec<u8>>,
}

#[derive(Default)]
struct Inner {
    entries: HashMap<Vec<u8>, Entry>,
    /// Insertion order (the expiration queue).
    queue: BTreeMap<u64, Vec<u8>>,
    next_seq: u64,
    total_size: usize,
}

/// `entry_size` (replay.c:63-69).
fn entry_size(req: &[u8], rep: Option<&[u8]>) -> usize {
    std::mem::size_of::<Entry>() + req.len() + rep.map_or(0, <[u8]>::len)
}

impl Inner {
    fn discard(&mut self, req: &[u8]) {
        if let Some(e) = self.entries.remove(req) {
            self.queue.remove(&e.seq);
            self.total_size -= entry_size(req, e.reply.as_deref());
        }
    }
}

/// The lookaside cache (`kdc_init_lookaside` .. `kdc_free_lookaside`).
#[derive(Default)]
pub(crate) struct Lookaside(Mutex<Inner>);

impl Lookaside {
    /// `kdc_check_lookaside` (replay.c:165-186): `Some(None)` for a request
    /// still being processed.
    pub(crate) fn check(&self, req: &[u8]) -> Option<Option<Vec<u8>>> {
        let inner = self.0.lock().unwrap_or_else(|e| e.into_inner());
        inner.entries.get(req).map(|e| e.reply.clone())
    }

    /// `kdc_insert_lookaside` (replay.c:196-218): purge stale entries and
    /// keep the total size bounded, then add `req`; `reply` is `None` while
    /// the request is being processed.
    pub(crate) fn insert(&self, req: &[u8], reply: Option<&[u8]>, now: i64) {
        let mut inner = self.0.lock().unwrap_or_else(|e| e.into_inner());
        let esize = entry_size(req, reply);
        while let Some((_, key)) = inner.queue.first_key_value() {
            let e = &inner.entries[key];
            if now <= e.timein + STALE_TIME && inner.total_size + esize <= MAX_SIZE {
                break;
            }
            let key = key.clone();
            inner.discard(&key);
        }
        if inner.entries.contains_key(req) {
            return;
        }
        let seq = inner.next_seq;
        inner.next_seq += 1;
        inner.queue.insert(seq, req.to_vec());
        inner.entries.insert(
            req.to_vec(),
            Entry {
                seq,
                timein: now,
                reply: reply.map(<[u8]>::to_vec),
            },
        );
        inner.total_size += esize;
    }

    /// `kdc_remove_lookaside` (replay.c:150-159).
    pub(crate) fn remove(&self, req: &[u8]) {
        self.0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .discard(req);
    }
}

/// Removes a request's in-progress entry if processing is abandoned (a
/// dropped TCP connection), so its retransmissions are not dropped until
/// the entry goes stale.
pub(crate) struct InProgress<'a> {
    cache: &'a Lookaside,
    req: &'a [u8],
}

impl<'a> InProgress<'a> {
    pub(crate) fn start(cache: &'a Lookaside, req: &'a [u8], now: i64) -> Self {
        cache.insert(req, None, now);
        Self { cache, req }
    }

    /// `finish_dispatch_cache` (dispatch.c:69-85): replace the in-progress
    /// entry with the reply.
    pub(crate) fn finish(self, reply: &[u8], now: i64) {
        self.cache.remove(self.req);
        self.cache.insert(self.req, Some(reply), now);
        std::mem::forget(self);
    }
}

impl InProgress<'_> {
    /// Keep the null entry: the request was discarded.
    pub(crate) fn discard(self, now: i64) {
        self.cache.remove(self.req);
        self.cache.insert(self.req, None, now);
        std::mem::forget(self);
    }
}

impl Drop for InProgress<'_> {
    fn drop(&mut self) {
        self.cache.remove(self.req);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lookaside_hit_and_in_progress() {
        let c = Lookaside::default();
        assert_eq!(c.check(b"req"), None);
        let p = InProgress::start(&c, b"req", 100);
        assert_eq!(c.check(b"req"), Some(None));
        p.finish(b"rep", 101);
        assert_eq!(c.check(b"req"), Some(Some(b"rep".to_vec())));
        assert_eq!(c.check(b"other"), None);
    }

    #[test]
    fn test_lookaside_abandoned_request() {
        let c = Lookaside::default();
        drop(InProgress::start(&c, b"req", 100));
        assert_eq!(c.check(b"req"), None);
    }

    #[test]
    fn test_lookaside_stale_entries_purged() {
        let c = Lookaside::default();
        c.insert(b"a", Some(b"1"), 100);
        c.insert(b"b", Some(b"2"), 150);
        c.insert(b"c", Some(b"3"), 100 + STALE_TIME);
        assert!(c.check(b"a").is_some());
        c.insert(b"d", Some(b"4"), 101 + STALE_TIME);
        assert_eq!(c.check(b"a"), None);
        assert!(c.check(b"b").is_some());
    }

    #[test]
    fn test_lookaside_size_limit() {
        let c = Lookaside::default();
        let big = vec![0u8; MAX_SIZE / 2];
        c.insert(b"a", Some(&big), 100);
        c.insert(b"b", Some(&big), 100);
        assert_eq!(c.check(b"a"), None);
        assert!(c.check(b"b").is_some());
    }
}
