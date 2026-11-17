//! Berkeley DB 1.85 btree files as written by MIT's libdb2
//! (`plugins/kdb/db2/libdb2/btree`), read and updated in place.
//!
//! Pages are stored in the byte order recorded by the metadata magic, so a
//! file written on a big-endian host is used as-is (`B_NEEDSWAP`).

use std::collections::HashMap;
use std::fs::File;
use std::io;
use std::path::Path;

#[cfg(unix)]
use std::os::unix::fs::FileExt;
#[cfg(windows)]
use std::os::windows::fs::FileExt;

pub const BTREEMAGIC: u32 = 0x053162;
pub const BTREEVERSION: u32 = 3;
const P_INVALID: u32 = 0;
const P_META: u32 = 0;
const P_ROOT: u32 = 1;
const P_BINTERNAL: u32 = 0x01;
const P_BLEAF: u32 = 0x02;
const P_OVERFLOW: u32 = 0x04;
const P_TYPE: u32 = 0x1f;
const P_PRESERVE: u32 = 0x20;
const P_BIGDATA: u8 = 0x01;
const P_BIGKEY: u8 = 0x02;
/// `B_NODUPS`, the only persistent flag a btree opened by db2 carries.
const B_NODUPS: u32 = 0x20;
const SAVEMETA: u32 = 0x20 | 0x80;
/// `BTDATAOFF`: pgno, prevpg, nextpg, flags, lower, upper.
const BTDATAOFF: usize = 20;
const NOVFLSIZE: usize = 8;
const DEFMINKEYPAGE: usize = 2;

fn lalign(n: usize) -> usize {
    (n + 3) & !3
}

fn nbleafdbt(ksize: usize, dsize: usize) -> usize {
    lalign(9 + ksize + dsize)
}

fn nbinternal(ksize: usize) -> usize {
    lalign(9 + ksize)
}

fn bad(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.into())
}

/// Byte order of a database file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Order {
    Little,
    Big,
}

impl Order {
    pub fn native() -> Self {
        if cfg!(target_endian = "big") {
            Order::Big
        } else {
            Order::Little
        }
    }

    pub fn u32(self, b: &[u8], off: usize) -> u32 {
        let a = [b[off], b[off + 1], b[off + 2], b[off + 3]];
        match self {
            Order::Little => u32::from_le_bytes(a),
            Order::Big => u32::from_be_bytes(a),
        }
    }

    pub fn u16(self, b: &[u8], off: usize) -> u16 {
        let a = [b[off], b[off + 1]];
        match self {
            Order::Little => u16::from_le_bytes(a),
            Order::Big => u16::from_be_bytes(a),
        }
    }

    pub fn put_u32(self, b: &mut [u8], off: usize, v: u32) {
        let a = match self {
            Order::Little => v.to_le_bytes(),
            Order::Big => v.to_be_bytes(),
        };
        b[off..off + 4].copy_from_slice(&a);
    }

    pub fn put_u16(self, b: &mut [u8], off: usize, v: u16) {
        let a = match self {
            Order::Little => v.to_le_bytes(),
            Order::Big => v.to_be_bytes(),
        };
        b[off..off + 2].copy_from_slice(&a);
    }
}

/// Whether `file` starts with a btree metadata page.
pub fn is_btree(file: &File) -> io::Result<bool> {
    let mut magic = [0u8; 4];
    match file.read_exact_at(&mut magic, 0) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(false),
        Err(e) => return Err(e),
    }
    Ok(u32::from_le_bytes(magic) == BTREEMAGIC || u32::from_be_bytes(magic) == BTREEMAGIC)
}

#[cfg(windows)]
trait ReadExactAt {
    fn read_exact_at(&self, buf: &mut [u8], off: u64) -> io::Result<()>;
    fn write_all_at(&self, buf: &[u8], off: u64) -> io::Result<()>;
}

#[cfg(windows)]
impl ReadExactAt for File {
    fn read_exact_at(&self, mut buf: &mut [u8], mut off: u64) -> io::Result<()> {
        while !buf.is_empty() {
            match self.seek_read(buf, off)? {
                0 => return Err(io::ErrorKind::UnexpectedEof.into()),
                n => {
                    buf = &mut buf[n..];
                    off += n as u64;
                }
            }
        }
        Ok(())
    }

    fn write_all_at(&self, mut buf: &[u8], mut off: u64) -> io::Result<()> {
        while !buf.is_empty() {
            let n = self.seek_write(buf, off)?;
            buf = &buf[n..];
            off += n as u64;
        }
        Ok(())
    }
}

/// One page buffer with its file byte order.
#[derive(Clone)]
struct Page {
    b: Vec<u8>,
    o: Order,
}

impl Page {
    fn new(psize: usize, o: Order, pgno: u32, flags: u32) -> Self {
        let mut p = Page {
            b: vec![0; psize],
            o,
        };
        p.set_pgno(pgno);
        p.set_flags(flags);
        p.set_lower(BTDATAOFF as u16);
        p.set_upper(psize as u16);
        p
    }
    fn pgno(&self) -> u32 {
        self.o.u32(&self.b, 0)
    }
    fn prevpg(&self) -> u32 {
        self.o.u32(&self.b, 4)
    }
    fn nextpg(&self) -> u32 {
        self.o.u32(&self.b, 8)
    }
    fn flags(&self) -> u32 {
        self.o.u32(&self.b, 12)
    }
    fn lower(&self) -> usize {
        usize::from(self.o.u16(&self.b, 16))
    }
    fn upper(&self) -> usize {
        // A full 64 KiB page records `upper` as 0.
        match self.o.u16(&self.b, 18) {
            0 if self.lower() != 0 => self.b.len(),
            u => usize::from(u),
        }
    }
    fn set_pgno(&mut self, v: u32) {
        self.o.put_u32(&mut self.b, 0, v)
    }
    fn set_prevpg(&mut self, v: u32) {
        self.o.put_u32(&mut self.b, 4, v)
    }
    fn set_nextpg(&mut self, v: u32) {
        self.o.put_u32(&mut self.b, 8, v)
    }
    fn set_flags(&mut self, v: u32) {
        self.o.put_u32(&mut self.b, 12, v)
    }
    fn set_lower(&mut self, v: u16) {
        self.o.put_u16(&mut self.b, 16, v)
    }
    fn set_upper(&mut self, v: u16) {
        self.o.put_u16(&mut self.b, 18, v)
    }
    fn is_leaf(&self) -> bool {
        self.flags() & P_TYPE == P_BLEAF
    }
    fn nent(&self) -> usize {
        self.lower().saturating_sub(BTDATAOFF) / 2
    }
    fn linp(&self, i: usize) -> usize {
        usize::from(self.o.u16(&self.b, BTDATAOFF + 2 * i))
    }
    fn set_linp(&mut self, i: usize, v: usize) {
        self.o.put_u16(&mut self.b, BTDATAOFF + 2 * i, v as u16)
    }
    fn check(&self) -> io::Result<()> {
        let (lower, upper) = (self.lower(), self.upper());
        if lower < BTDATAOFF || lower > upper || upper > self.b.len() {
            return Err(bad(format!("btree page {} is corrupt", self.pgno())));
        }
        for i in 0..self.nent() {
            let off = self.linp(i);
            if off < upper || off + 9 > self.b.len() {
                return Err(bad(format!("btree page {} is corrupt", self.pgno())));
            }
        }
        Ok(())
    }
    /// The whole on-page item at index `i` (a `BLEAF` or `BINTERNAL`).
    fn item(&self, i: usize) -> io::Result<&[u8]> {
        let off = self.linp(i);
        let len = if self.is_leaf() {
            let k = self.o.u32(&self.b, off) as usize;
            let d = self.o.u32(&self.b, off + 4) as usize;
            nbleafdbt(k, d)
        } else {
            nbinternal(self.o.u32(&self.b, off) as usize)
        };
        self.b
            .get(off..off + len)
            .ok_or_else(|| bad(format!("btree page {} item overruns", self.pgno())))
    }
    /// Replace the items of the page with `items`, keeping the header.
    fn fill(&mut self, items: &[Vec<u8>]) {
        let psize = self.b.len();
        let mut upper = psize;
        for (i, it) in items.iter().enumerate() {
            upper -= it.len();
            self.b[upper..upper + it.len()].copy_from_slice(it);
            self.set_linp(i, upper);
        }
        self.set_lower((BTDATAOFF + 2 * items.len()) as u16);
        self.set_upper(upper as u16);
    }
    fn items(&self) -> io::Result<Vec<Vec<u8>>> {
        (0..self.nent())
            .map(|i| self.item(i).map(<[u8]>::to_vec))
            .collect()
    }
    fn free_space(&self) -> usize {
        self.upper() - self.lower()
    }
}

/// A decoded item: the key or data, either inline or an overflow chain.
#[derive(Clone, Copy)]
enum Ref<'a> {
    Inline(&'a [u8]),
    Overflow { pgno: u32, size: usize },
}

/// An open btree file. All page changes are kept in memory until
/// [`Btree::sync`], which writes them out (`mpool_sync`).
pub struct Btree {
    file: File,
    order: Order,
    psize: usize,
    free: u32,
    npages: u32,
    meta_flags: u32,
    meta_dirty: bool,
    cache: HashMap<u32, Page>,
    dirty: std::collections::BTreeSet<u32>,
    ovflsize: usize,
}

impl Btree {
    /// Open an existing btree, as `__bt_open` does.
    pub fn open(file: File) -> io::Result<Self> {
        let mut m = [0u8; 24];
        file.read_exact_at(&mut m, 0)?;
        let order = if u32::from_le_bytes([m[0], m[1], m[2], m[3]]) == BTREEMAGIC {
            Order::Little
        } else if u32::from_be_bytes([m[0], m[1], m[2], m[3]]) == BTREEMAGIC {
            Order::Big
        } else {
            return Err(io::Error::other("EFTYPE: not a btree file"));
        };
        if order.u32(&m, 4) != BTREEVERSION {
            return Err(io::Error::other("EFTYPE: unsupported btree version"));
        }
        let psize = order.u32(&m, 8) as usize;
        let meta_flags = order.u32(&m, 20);
        if !(512..=65536).contains(&psize)
            || psize & (psize - 1) != 0
            || meta_flags & !SAVEMETA != 0
        {
            return Err(io::Error::other("EFTYPE: bad btree metadata"));
        }
        let len = file.metadata()?.len();
        let npages = u32::try_from(len / psize as u64).map_err(|_| bad("btree file too large"))?;
        Ok(Self::new(
            file,
            order,
            psize,
            order.u32(&m, 12),
            npages,
            meta_flags,
        ))
    }

    /// Create an empty btree, as `__bt_open` does on an empty file with
    /// db2's settings (4096-byte pages, host order, no duplicates).
    pub fn create(file: File, psize: usize) -> io::Result<Self> {
        let order = Order::native();
        let mut t = Self::new(file, order, psize, P_INVALID, 2, B_NODUPS);
        t.meta_dirty = true;
        let root = Page::new(psize, order, P_ROOT, P_BLEAF);
        t.cache.insert(P_ROOT, root);
        t.dirty.insert(P_ROOT);
        Ok(t)
    }

    fn new(
        file: File,
        order: Order,
        psize: usize,
        free: u32,
        npages: u32,
        meta_flags: u32,
    ) -> Self {
        let mut ovflsize = (psize - BTDATAOFF) / DEFMINKEYPAGE - (2 + nbleafdbt(0, 0));
        if ovflsize < nbleafdbt(NOVFLSIZE, NOVFLSIZE) + 2 {
            ovflsize = nbleafdbt(NOVFLSIZE, NOVFLSIZE) + 2;
        }
        Btree {
            file,
            order,
            psize,
            free,
            npages,
            meta_flags,
            meta_dirty: false,
            cache: HashMap::new(),
            dirty: Default::default(),
            ovflsize,
        }
    }

    pub fn order(&self) -> Order {
        self.order
    }

    pub fn file(&self) -> &File {
        &self.file
    }

    fn page(&mut self, pgno: u32) -> io::Result<&Page> {
        self.page_mut_inner(pgno, false).map(|p| &*p)
    }

    fn page_mut(&mut self, pgno: u32) -> io::Result<&mut Page> {
        self.page_mut_inner(pgno, true)
    }

    fn page_mut_inner(&mut self, pgno: u32, dirty: bool) -> io::Result<&mut Page> {
        if pgno == P_META || pgno >= self.npages {
            return Err(bad(format!("btree page {pgno} is out of range")));
        }
        if !self.cache.contains_key(&pgno) {
            let mut b = vec![0; self.psize];
            self.file
                .read_exact_at(&mut b, u64::from(pgno) * self.psize as u64)?;
            let p = Page { b, o: self.order };
            if p.flags() & P_TYPE != P_OVERFLOW {
                p.check()?;
            }
            self.cache.insert(pgno, p);
        }
        if dirty {
            self.dirty.insert(pgno);
        }
        Ok(self.cache.get_mut(&pgno).expect("cached page"))
    }

    /// `__bt_new`: reuse a free page or extend the file.
    fn new_page(&mut self, flags: u32) -> io::Result<u32> {
        let pgno = if self.free != P_INVALID {
            let pgno = self.free;
            self.free = self.page(pgno)?.nextpg();
            self.meta_dirty = true;
            pgno
        } else {
            let pgno = self.npages;
            self.npages = self
                .npages
                .checked_add(1)
                .ok_or_else(|| bad("btree file too large"))?;
            pgno
        };
        let p = Page::new(self.psize, self.order, pgno, flags);
        self.cache.insert(pgno, p);
        self.dirty.insert(pgno);
        Ok(pgno)
    }

    /// `__bt_free`.
    fn free_page(&mut self, pgno: u32) -> io::Result<()> {
        let free = self.free;
        let p = self.page_mut(pgno)?;
        p.set_prevpg(P_INVALID);
        p.set_nextpg(free);
        self.free = pgno;
        self.meta_dirty = true;
        Ok(())
    }

    fn split_ref<'a>(&self, bytes: &'a [u8], big: bool) -> Ref<'a> {
        if big {
            Ref::Overflow {
                pgno: self.order.u32(bytes, 0),
                size: self.order.u32(bytes, 4) as usize,
            }
        } else {
            Ref::Inline(bytes)
        }
    }

    /// `__ovfl_get`.
    fn ovfl_get(&mut self, mut pgno: u32, size: usize) -> io::Result<Vec<u8>> {
        let plen = self.psize - BTDATAOFF;
        let mut out = Vec::with_capacity(size);
        let mut seen = 0u32;
        while out.len() < size {
            if pgno == P_INVALID || seen > self.npages {
                return Err(bad("btree overflow chain is truncated"));
            }
            seen += 1;
            let p = self.page(pgno)?;
            if p.flags() & P_TYPE != P_OVERFLOW {
                return Err(bad("btree overflow chain is corrupt"));
            }
            let n = plen.min(size - out.len());
            out.extend_from_slice(&p.b[BTDATAOFF..BTDATAOFF + n]);
            pgno = p.nextpg();
        }
        Ok(out)
    }

    /// `__ovfl_put`: store `data` in a new overflow chain.
    fn ovfl_put(&mut self, data: &[u8]) -> io::Result<u32> {
        let plen = self.psize - BTDATAOFF;
        let mut first = P_INVALID;
        let mut last = P_INVALID;
        for chunk in data.chunks(plen) {
            let pgno = self.new_page(P_OVERFLOW)?;
            let p = self.page_mut(pgno)?;
            p.set_lower(0);
            p.set_upper(0);
            p.b[BTDATAOFF..BTDATAOFF + chunk.len()].copy_from_slice(chunk);
            if last == P_INVALID {
                first = pgno;
            } else {
                self.page_mut(last)?.set_nextpg(pgno);
            }
            last = pgno;
        }
        Ok(first)
    }

    /// `__ovfl_delete`: free a chain unless it is shared with an internal
    /// page (`P_PRESERVE`).
    fn ovfl_delete(&mut self, mut pgno: u32, size: usize) -> io::Result<()> {
        if pgno == P_INVALID || size == 0 {
            return Err(bad("btree overflow reference is corrupt"));
        }
        if self.page(pgno)?.flags() & P_PRESERVE != 0 {
            return Ok(());
        }
        let plen = self.psize - BTDATAOFF;
        let mut left = size;
        loop {
            let next = self.page(pgno)?.nextpg();
            self.free_page(pgno)?;
            left = left.saturating_sub(plen);
            if left == 0 {
                return Ok(());
            }
            pgno = next;
        }
    }

    fn resolve(&mut self, r: Ref<'_>) -> io::Result<Vec<u8>> {
        match r {
            Ref::Inline(b) => Ok(b.to_vec()),
            Ref::Overflow { pgno, size } => self.ovfl_get(pgno, size),
        }
    }

    /// The key bytes of item `i` on `page`, plus the raw item.
    fn key_at(&mut self, pgno: u32, i: usize) -> io::Result<Vec<u8>> {
        let (raw, leaf) = {
            let p = self.page(pgno)?;
            (p.item(i)?.to_vec(), p.is_leaf())
        };
        let o = self.order;
        let ksize = o.u32(&raw, 0) as usize;
        let (flags, start) = (raw[8], 9);
        let kbytes = raw
            .get(start..start + ksize)
            .ok_or_else(|| bad("btree key overruns"))?;
        let _ = leaf;
        let r = self.split_ref(kbytes, flags & P_BIGKEY != 0);
        self.resolve(r)
    }

    fn leaf_data(&mut self, raw: &[u8]) -> io::Result<Vec<u8>> {
        let o = self.order;
        let ksize = o.u32(raw, 0) as usize;
        let dsize = o.u32(raw, 4) as usize;
        let d = raw
            .get(9 + ksize..9 + ksize + dsize)
            .ok_or_else(|| bad("btree data overruns"))?;
        let r = self.split_ref(d, raw[8] & P_BIGDATA != 0);
        self.resolve(r)
    }

    /// `__bt_search`: the leaf for `key`, the index where it is or would
    /// go, whether it was found, and the internal-page path.
    #[allow(clippy::type_complexity)]
    fn search(&mut self, key: &[u8]) -> io::Result<(u32, usize, bool, Vec<(u32, usize)>)> {
        let mut pgno = P_ROOT;
        let mut path = Vec::new();
        for _ in 0..64 {
            let (n, leaf, leftmost) = {
                let p = self.page(pgno)?;
                (p.nent(), p.is_leaf(), p.prevpg() == P_INVALID)
            };
            let (mut base, mut lim) = (0usize, n);
            let mut exact = None;
            while lim != 0 {
                let idx = base + (lim >> 1);
                let ord = if !leaf && idx == 0 && leftmost {
                    std::cmp::Ordering::Greater
                } else {
                    key.cmp(&self.key_at(pgno, idx)?[..])
                };
                match ord {
                    std::cmp::Ordering::Equal => {
                        exact = Some(idx);
                        break;
                    }
                    std::cmp::Ordering::Greater => {
                        base = idx + 1;
                        lim -= 1;
                    }
                    std::cmp::Ordering::Less => {}
                }
                lim >>= 1;
            }
            if leaf {
                return Ok(match exact {
                    Some(i) => (pgno, i, true, path),
                    None => (pgno, base, false, path),
                });
            }
            let idx = match exact {
                Some(i) => i,
                None if base == 0 => 0,
                None => base - 1,
            };
            if n == 0 {
                return Err(bad(format!("btree internal page {pgno} is empty")));
            }
            path.push((pgno, idx));
            let raw = self.page(pgno)?.item(idx)?.to_vec();
            pgno = self.order.u32(&raw, 4);
        }
        Err(bad("btree is too deep"))
    }

    /// Look up `key` (`__bt_get`).
    pub fn get(&mut self, key: &[u8]) -> io::Result<Option<Vec<u8>>> {
        let (pgno, i, found, _) = self.search(key)?;
        if !found {
            return Ok(None);
        }
        let raw = self.page(pgno)?.item(i)?.to_vec();
        self.leaf_data(&raw).map(Some)
    }

    /// Every key/data pair in key order (`R_FIRST`/`R_NEXT`).
    pub fn entries(&mut self) -> io::Result<Vec<(Vec<u8>, Vec<u8>)>> {
        let mut out = Vec::new();
        self.for_each(|k, v| {
            out.push((k, v));
            Ok(true)
        })?;
        Ok(out)
    }

    /// Visit every pair in key order until `f` returns `false`.
    pub fn for_each(
        &mut self,
        mut f: impl FnMut(Vec<u8>, Vec<u8>) -> io::Result<bool>,
    ) -> io::Result<()> {
        let mut pgno = P_ROOT;
        let o = self.order;
        for _ in 0..64 {
            let p = self.page(pgno)?;
            if p.is_leaf() {
                break;
            }
            if p.nent() == 0 {
                return Err(bad(format!("btree internal page {pgno} is empty")));
            }
            let raw = p.item(0)?;
            pgno = o.u32(raw, 4);
        }
        let mut seen = 0u32;
        while pgno != P_INVALID {
            seen += 1;
            if seen > self.npages {
                return Err(bad("btree leaf chain loops"));
            }
            let (n, next) = {
                let p = self.page(pgno)?;
                if !p.is_leaf() {
                    return Err(bad("btree leaf chain is corrupt"));
                }
                (p.nent(), p.nextpg())
            };
            for i in 0..n {
                let raw = self.page(pgno)?.item(i)?.to_vec();
                let k = self.key_at(pgno, i)?;
                let v = self.leaf_data(&raw)?;
                if !f(k, v)? {
                    return Ok(());
                }
            }
            pgno = next;
        }
        Ok(())
    }

    /// Free the overflow chains of a leaf item (`__bt_dleaf`).
    fn free_leaf_item(&mut self, raw: &[u8]) -> io::Result<()> {
        let o = self.order;
        let ksize = o.u32(raw, 0) as usize;
        if raw[8] & P_BIGKEY != 0 {
            self.ovfl_delete(o.u32(raw, 9), o.u32(raw, 13) as usize)?;
        }
        if raw[8] & P_BIGDATA != 0 {
            let d = 9 + ksize;
            self.ovfl_delete(o.u32(raw, d), o.u32(raw, d + 4) as usize)?;
        }
        Ok(())
    }

    /// Remove item `i` from a page, compacting it.
    fn remove_item(&mut self, pgno: u32, i: usize) -> io::Result<()> {
        let p = self.page_mut(pgno)?;
        let mut items = p.items()?;
        items.remove(i);
        p.fill(&items);
        Ok(())
    }

    /// Store `data` under `key`, replacing an existing pair (`__bt_put`).
    pub fn put(&mut self, key: &[u8], data: &[u8]) -> io::Result<()> {
        let o = self.order;
        let mut flags = 0u8;
        let mut kbuf = key.to_vec();
        let mut dbuf = data.to_vec();
        if kbuf.len() + dbuf.len() > self.ovflsize {
            if kbuf.len() > self.ovflsize {
                kbuf = self.ovfl_ref(key)?;
                flags |= P_BIGKEY;
            }
            if kbuf.len() + dbuf.len() > self.ovflsize {
                dbuf = self.ovfl_ref(data)?;
                flags |= P_BIGDATA;
            }
            if kbuf.len() + dbuf.len() > self.ovflsize && flags & P_BIGKEY == 0 {
                kbuf = self.ovfl_ref(key)?;
                flags |= P_BIGKEY;
            }
        }
        // __bt_put searches with the stored key, so a key moved to an
        // overflow chain is positioned by its 8-byte reference, as in libdb2.
        let (pgno, idx, found, path) = self.search(&kbuf)?;
        if found {
            let raw = self.page(pgno)?.item(idx)?.to_vec();
            self.free_leaf_item(&raw)?;
            self.remove_item(pgno, idx)?;
        }
        let mut item = vec![0u8; nbleafdbt(kbuf.len(), dbuf.len())];
        o.put_u32(&mut item, 0, kbuf.len() as u32);
        o.put_u32(&mut item, 4, dbuf.len() as u32);
        item[8] = flags;
        item[9..9 + kbuf.len()].copy_from_slice(&kbuf);
        item[9 + kbuf.len()..9 + kbuf.len() + dbuf.len()].copy_from_slice(&dbuf);
        self.insert(pgno, idx, item, path)
    }

    fn ovfl_ref(&mut self, data: &[u8]) -> io::Result<Vec<u8>> {
        let pg = self.ovfl_put(data)?;
        let mut r = vec![0u8; NOVFLSIZE];
        self.order.put_u32(&mut r, 0, pg);
        self.order.put_u32(&mut r, 4, data.len() as u32);
        Ok(r)
    }

    /// Insert `item` at `idx` on `pgno`, splitting up the path as needed
    /// (`__bt_split`).
    fn insert(
        &mut self,
        mut pgno: u32,
        mut idx: usize,
        mut item: Vec<u8>,
        mut path: Vec<(u32, usize)>,
    ) -> io::Result<()> {
        loop {
            let p = self.page_mut(pgno)?;
            if p.free_space() >= item.len() + 2 {
                let mut items = p.items()?;
                items.insert(idx, item);
                p.fill(&items);
                return Ok(());
            }
            let leaf = p.is_leaf();
            let mut items = p.items()?;
            let tail = p.nextpg() == P_INVALID && idx == items.len();
            items.insert(idx, item);
            let (left, right) = if tail && pgno != P_ROOT {
                // bt_page: appending past the last page starts a new page.
                let last = items.pop().expect("inserted item");
                (items, vec![last])
            } else {
                split_items(&items, self.psize)
            };
            if pgno == P_ROOT {
                return self.split_root(left, right, leaf);
            }
            let flags = self.page(pgno)?.flags() & P_TYPE;
            let r = self.new_page(flags)?;
            let next = self.page(pgno)?.nextpg();
            {
                let rp = self.page_mut(r)?;
                rp.set_prevpg(pgno);
                rp.set_nextpg(next);
                rp.fill(&right);
            }
            if next != P_INVALID {
                self.page_mut(next)?.set_prevpg(r);
            }
            {
                let lp = self.page_mut(pgno)?;
                lp.set_nextpg(r);
                lp.fill(&left);
            }
            let sep = self.separator(left.last(), &right[0], leaf, r)?;
            let (parent, pidx) = path
                .pop()
                .ok_or_else(|| bad("btree split lost its parent"))?;
            pgno = parent;
            idx = pidx + 1;
            item = sep;
        }
    }

    /// The parent entry for a new right page (`bt_page` / `bt_broot`).
    fn separator(
        &mut self,
        last_left: Option<&Vec<u8>>,
        first_right: &[u8],
        leaf: bool,
        rpgno: u32,
    ) -> io::Result<Vec<u8>> {
        let o = self.order;
        if !leaf {
            let mut b = first_right.to_vec();
            o.put_u32(&mut b, 4, rpgno);
            return Ok(b);
        }
        let rk = o.u32(first_right, 0) as usize;
        let rflags = first_right[8];
        let rbytes = &first_right[9..9 + rk];
        let (kbytes, flags): (Vec<u8>, u8) = if rflags & P_BIGKEY != 0 {
            let pg = o.u32(rbytes, 0);
            let p = self.page_mut(pg)?;
            let f = p.flags() | P_PRESERVE;
            p.set_flags(f);
            (rbytes.to_vec(), P_BIGKEY)
        } else {
            match last_left {
                Some(l) if l[8] & P_BIGKEY == 0 => {
                    let lk = o.u32(l, 0) as usize;
                    let a = &l[9..9 + lk];
                    (rbytes[..prefix(a, rbytes)].to_vec(), 0)
                }
                _ => (rbytes.to_vec(), 0),
            }
        };
        Ok(binternal(o, &kbytes, rpgno, flags))
    }

    /// `bt_root` and `bt_broot`: the root keeps page 1 and gets two new
    /// children.
    fn split_root(
        &mut self,
        left: Vec<Vec<u8>>,
        right: Vec<Vec<u8>>,
        leaf: bool,
    ) -> io::Result<()> {
        let flags = if leaf { P_BLEAF } else { P_BINTERNAL };
        let l = self.new_page(flags)?;
        let r = self.new_page(flags)?;
        {
            let lp = self.page_mut(l)?;
            lp.set_nextpg(r);
            lp.fill(&left);
        }
        {
            let rp = self.page_mut(r)?;
            rp.set_prevpg(l);
            rp.fill(&right);
        }
        let o = self.order;
        let first = binternal(o, &[], l, 0);
        let second = if leaf {
            let rk = o.u32(&right[0], 0) as usize;
            let bytes = right[0][9..9 + rk].to_vec();
            let big = right[0][8] & P_BIGKEY;
            if big != 0 {
                let p = self.page_mut(o.u32(&bytes, 0))?;
                let f = p.flags() | P_PRESERVE;
                p.set_flags(f);
            }
            binternal(o, &bytes, r, big)
        } else {
            let mut b = right[0].clone();
            o.put_u32(&mut b, 4, r);
            b
        };
        let root = self.page_mut(P_ROOT)?;
        root.set_flags((root.flags() & !P_TYPE) | P_BINTERNAL);
        root.fill(&[first, second]);
        Ok(())
    }

    /// Delete `key` (`__bt_bdelete` with `B_NODUPS`).
    pub fn delete(&mut self, key: &[u8]) -> io::Result<bool> {
        let (pgno, idx, found, mut path) = self.search(key)?;
        if !found {
            return Ok(false);
        }
        let raw = self.page(pgno)?.item(idx)?.to_vec();
        self.free_leaf_item(&raw)?;
        self.remove_item(pgno, idx)?;
        if self.page(pgno)?.nent() == 0 {
            self.pdelete(pgno, &mut path)?;
        }
        Ok(true)
    }

    /// `__bt_pdelete`: drop an empty page and its parent entries.
    fn pdelete(&mut self, pgno: u32, path: &mut Vec<(u32, usize)>) -> io::Result<()> {
        if pgno == P_ROOT {
            return Ok(());
        }
        while let Some((parent, idx)) = path.pop() {
            let raw = self.page(parent)?.item(idx)?.to_vec();
            if raw[8] & P_BIGKEY != 0 {
                let o = self.order;
                self.ovfl_delete(o.u32(&raw, 9), o.u32(&raw, 13) as usize)?;
            }
            if self.page(parent)?.nent() == 1 {
                if parent == P_ROOT {
                    let psize = self.psize;
                    let p = self.page_mut(parent)?;
                    p.set_lower(BTDATAOFF as u16);
                    p.set_upper(psize as u16);
                    p.set_flags(P_BLEAF);
                } else {
                    self.relink(parent)?;
                    self.free_page(parent)?;
                    continue;
                }
            } else {
                self.remove_item(parent, idx)?;
            }
            break;
        }
        self.relink(pgno)?;
        self.free_page(pgno)
    }

    /// `__bt_relink`.
    fn relink(&mut self, pgno: u32) -> io::Result<()> {
        let (prev, next) = {
            let p = self.page(pgno)?;
            (p.prevpg(), p.nextpg())
        };
        if next != P_INVALID {
            self.page_mut(next)?.set_prevpg(prev);
        }
        if prev != P_INVALID {
            self.page_mut(prev)?.set_nextpg(next);
        }
        Ok(())
    }

    /// Write dirty pages and the metadata page (`__bt_sync`).
    pub fn sync(&mut self) -> io::Result<()> {
        for pgno in std::mem::take(&mut self.dirty) {
            let p = &self.cache[&pgno];
            self.file
                .write_all_at(&p.b, u64::from(pgno) * self.psize as u64)?;
        }
        if self.meta_dirty {
            let mut m = vec![0u8; self.psize];
            let o = self.order;
            o.put_u32(&mut m, 0, BTREEMAGIC);
            o.put_u32(&mut m, 4, BTREEVERSION);
            o.put_u32(&mut m, 8, self.psize as u32);
            o.put_u32(&mut m, 12, self.free);
            o.put_u32(&mut m, 16, 0);
            o.put_u32(&mut m, 20, self.meta_flags & SAVEMETA);
            self.file.write_all_at(&m, 0)?;
            self.meta_dirty = false;
        }
        self.file.sync_data()
    }
}

fn binternal(o: Order, key: &[u8], pgno: u32, flags: u8) -> Vec<u8> {
    let mut b = vec![0u8; nbinternal(key.len())];
    o.put_u32(&mut b, 0, key.len() as u32);
    o.put_u32(&mut b, 4, pgno);
    b[8] = flags;
    b[9..9 + key.len()].copy_from_slice(key);
    b
}

/// `__bt_defpfx`: the length of the shortest prefix of `b` greater than `a`.
fn prefix(a: &[u8], b: &[u8]) -> usize {
    let len = a.len().min(b.len());
    for i in 0..len {
        if a[i] != b[i] {
            return i + 1;
        }
    }
    if a.len() < b.len() {
        a.len() + 1
    } else {
        b.len()
    }
}

/// Split `items` roughly in half by bytes (`bt_psplit`), keeping at least
/// one item on each side.
fn split_items(items: &[Vec<u8>], psize: usize) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
    let half = (psize - BTDATAOFF) / 2;
    let mut used = 0;
    let mut cut = items.len() - 1;
    for (i, it) in items.iter().enumerate() {
        used += it.len() + 2;
        if used >= half || i == items.len() - 2 {
            cut = i + 1;
            break;
        }
    }
    let cut = cut.clamp(1, items.len() - 1);
    (items[..cut].to_vec(), items[cut..].to_vec())
}

/// Open `path` read-only and return its btree pairs.
pub fn read_all(path: &Path) -> io::Result<Vec<(Vec<u8>, Vec<u8>)>> {
    Btree::open(File::open(path)?)?.entries()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp() -> (tempfile::TempDir, std::path::PathBuf) {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("t.db");
        (d, p)
    }

    fn rw(p: &Path) -> File {
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(p)
            .unwrap()
    }

    #[test]
    fn insert_split_delete_round_trip() {
        let (_d, p) = tmp();
        let mut t = Btree::create(rw(&p), 4096).unwrap();
        let mut model = std::collections::BTreeMap::new();
        let mut seed = 1u64;
        for i in 0..3000u32 {
            seed = seed
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            let klen = if i % 97 == 0 {
                1500
            } else {
                5 + (seed >> 59) as usize
            };
            let key: Vec<u8> = format!("{:08x}", seed >> 32)
                .bytes()
                .cycle()
                .take(klen)
                .collect();
            let dlen = if i % 31 == 0 {
                9000
            } else {
                (seed >> 52) as usize % 600
            };
            let data = vec![(i % 251) as u8; dlen];
            t.put(&key, &data).unwrap();
            model.insert(key, data);
        }
        t.sync().unwrap();
        let mut t = Btree::open(rw(&p)).unwrap();
        assert_eq!(
            t.entries().unwrap(),
            model.clone().into_iter().collect::<Vec<_>>()
        );
        let keys: Vec<_> = model.keys().cloned().collect();
        for (n, k) in keys.iter().enumerate() {
            if n % 3 != 0 {
                assert!(t.delete(k).unwrap());
                model.remove(k);
            }
        }
        for k in keys.iter().take(50) {
            t.put(k, b"again").unwrap();
            model.insert(k.clone(), b"again".to_vec());
        }
        t.sync().unwrap();
        let mut t = Btree::open(rw(&p)).unwrap();
        assert_eq!(
            t.entries().unwrap(),
            model.clone().into_iter().collect::<Vec<_>>()
        );
        for (k, v) in &model {
            assert_eq!(t.get(k).unwrap().as_ref(), Some(v));
        }
        for k in &keys {
            t.delete(k).unwrap();
        }
        t.sync().unwrap();
        assert!(Btree::open(rw(&p)).unwrap().entries().unwrap().is_empty());
    }
}
