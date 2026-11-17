//! MIT libdb2 hash files (`hash=true`), read and written in place with
//! libdb2's own algorithms so MIT's tools keep working on the result.

use std::collections::{BTreeSet, HashMap};
use std::fs::File;
use std::io;

use crate::btree::Order;

pub const HASHMAGIC: u32 = 0x061561;
pub const HASHVERSION: u32 = 3;
const OLDHASHVERSION: u32 = 1;
const CHARKEY: &[u8] = b"%$sniglet^&\0";
const NCACHED: usize = 32;
const HDRSIZE: usize = 14 * 4 + NCACHED * 4 + NCACHED * 2;
const HEADER_OVERHEAD: u32 = 4;
const SPLITSHIFT: u32 = 11;
const SPLITMASK: u32 = 0x7ff;
const BYTE_SHIFT: u32 = 3;
const BITS_PER_MAP: u32 = 32;
const ALL_SET: u32 = 0xffff_ffff;
const DEF_FFACTOR: u32 = 65536;
const MIN_FFACTOR: u32 = 4;
const INVALID_PGNO: u32 = 0xffff_ffff;
const BIGPAIR: u16 = 0;
const PAGE_OVERHEAD: usize = 14;
const PAIR_OVERHEAD: usize = 4;
const HASH_PAGE: u8 = 2;
const HASH_BIGPAGE: u8 = 3;
const HASH_OVFLPAGE: u8 = 4;

fn bad(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!("db2 hash: {msg}"))
}

/// libdb2's default hash function (`hash4`).
pub fn hash4(key: &[u8]) -> u32 {
    key.iter()
        .fold(0u32, |h, &b| (h << 5).wrapping_add(h).wrapping_add(b as u32))
}

fn log2(num: u32) -> u32 {
    let mut i = 0;
    let mut limit: u64 = 1;
    while limit < num as u64 {
        limit <<= 1;
        i += 1;
    }
    i
}

fn oaddr_of(s: u32, o: u32) -> u32 {
    (s << SPLITSHIFT) + o
}

#[derive(Clone, Debug, Default)]
struct Header {
    magic: u32,
    version: u32,
    lorder: u32,
    bsize: u32,
    bshift: u32,
    ovfl_point: u32,
    last_freed: u32,
    max_bucket: u32,
    high_mask: u32,
    low_mask: u32,
    ffactor: u32,
    nkeys: u32,
    hdrpages: u32,
    h_charkey: u32,
    spares: [u32; NCACHED],
    bitmaps: [u16; NCACHED],
}

impl Header {
    fn parse(b: &[u8]) -> Self {
        let o = Order::Big;
        let w = |i: usize| o.u32(b, i * 4);
        let mut h = Header {
            magic: w(0),
            version: w(1),
            lorder: w(2),
            bsize: w(3),
            bshift: w(4),
            ovfl_point: w(5),
            last_freed: w(6),
            max_bucket: w(7),
            high_mask: w(8),
            low_mask: w(9),
            ffactor: w(10),
            nkeys: w(11),
            hdrpages: w(12),
            h_charkey: w(13),
            ..Default::default()
        };
        for i in 0..NCACHED {
            h.spares[i] = w(14 + i);
            h.bitmaps[i] = o.u16(b, 56 + NCACHED * 4 + i * 2);
        }
        h
    }

    fn write(&self) -> Vec<u8> {
        let o = Order::Big;
        let mut b = vec![0u8; HDRSIZE];
        let vals = [
            self.magic,
            self.version,
            self.lorder,
            self.bsize,
            self.bshift,
            self.ovfl_point,
            self.last_freed,
            self.max_bucket,
            self.high_mask,
            self.low_mask,
            self.ffactor,
            self.nkeys,
            self.hdrpages,
            self.h_charkey,
        ];
        for (i, v) in vals.iter().enumerate() {
            o.put_u32(&mut b, i * 4, *v);
        }
        for i in 0..NCACHED {
            o.put_u32(&mut b, 56 + i * 4, self.spares[i]);
            o.put_u16(&mut b, 56 + NCACHED * 4 + i * 2, self.bitmaps[i]);
        }
        b
    }
}

/// Whether `file` starts with a libdb2 hash header.
pub fn is_hash(file: &File) -> io::Result<bool> {
    let mut b = [0u8; 4];
    match read_at(file, &mut b, 0)? {
        4 => Ok(u32::from_be_bytes(b) == HASHMAGIC),
        _ => Ok(false),
    }
}

fn read_at(file: &File, buf: &mut [u8], off: u64) -> io::Result<usize> {
    let mut done = 0;
    while done < buf.len() {
        #[cfg(unix)]
        let n = std::os::unix::fs::FileExt::read_at(file, &mut buf[done..], off + done as u64)?;
        #[cfg(windows)]
        let n = std::os::windows::fs::FileExt::seek_read(file, &mut buf[done..], off + done as u64)?;
        if n == 0 {
            break;
        }
        done += n;
    }
    Ok(done)
}

fn write_at(file: &File, buf: &[u8], off: u64) -> io::Result<()> {
    let mut done = 0;
    while done < buf.len() {
        #[cfg(unix)]
        let n = std::os::unix::fs::FileExt::write_at(file, &buf[done..], off + done as u64)?;
        #[cfg(windows)]
        let n = std::os::windows::fs::FileExt::seek_write(file, &buf[done..], off + done as u64)?;
        if n == 0 {
            return Err(io::ErrorKind::WriteZero.into());
        }
        done += n;
    }
    Ok(())
}

enum NumItems {
    NoExpand,
    Unknown,
    Count(u32),
}

#[derive(Default)]
struct ItemInfo {
    pgno: u32,
    pgndx: u32,
    bucket: u32,
    seek_found_page: u32,
    caused_expand: bool,
}

struct Found {
    pgno: u32,
    ndx: u16,
}

/// An open libdb2 hash database.
pub struct Hash {
    file: File,
    o: Order,
    hdr: Header,
    nmaps: u32,
    pages: HashMap<u32, Vec<u8>>,
    dirty: BTreeSet<u32>,
    modified: bool,
    max_chain: usize,
}

impl Hash {
    pub fn open(file: File) -> io::Result<Self> {
        let mut b = vec![0u8; HDRSIZE];
        if read_at(&file, &mut b, 0)? != HDRSIZE {
            return Err(bad("short header"));
        }
        let hdr = Header::parse(&b);
        if hdr.magic != HASHMAGIC
            || (hdr.version != HASHVERSION && hdr.version != OLDHASHVERSION)
            || hash4(CHARKEY) != hdr.h_charkey
        {
            return Err(bad("not a hash database"));
        }
        let o = match hdr.lorder {
            1234 => Order::Little,
            4321 => Order::Big,
            _ => return Err(bad("bad byte order")),
        };
        if !(512..=65536).contains(&hdr.bsize)
            || hdr.bsize != 1 << hdr.bshift
            || hdr.ovfl_point as usize >= NCACHED
            || hdr.hdrpages == 0
        {
            return Err(bad("bad header"));
        }
        let nmaps = ((hdr.spares[hdr.ovfl_point as usize] as u64
            + ((hdr.bsize as u64) << BYTE_SHIFT)
            - 1)
            >> (hdr.bshift + BYTE_SHIFT)) as u32;
        let max_chain = (file.metadata()?.len() / hdr.bsize as u64) as usize + 2;
        Ok(Hash {
            file,
            o,
            hdr,
            nmaps,
            pages: HashMap::new(),
            dirty: BTreeSet::new(),
            modified: false,
            max_chain,
        })
    }

    /// A new database laid out as libdb2's `init_htab` does.
    pub fn create(file: File, bsize: u32, ffactor: u32, nelem: u32) -> io::Result<Self> {
        let bshift = log2(bsize);
        let mut hdr = Header {
            magic: HASHMAGIC,
            version: HASHVERSION,
            lorder: if Order::native() == Order::Big { 4321 } else { 1234 },
            bsize: 1 << bshift,
            bshift,
            ffactor: if ffactor == 0 { DEF_FFACTOR } else { ffactor },
            h_charkey: hash4(CHARKEY),
            ..Default::default()
        };
        let nelem = (nelem.max(1) - 1) / hdr.ffactor + 1;
        let l2 = log2(nelem.max(2));
        let nbuckets = 1u32 << l2;
        hdr.spares[l2 as usize] = l2 + 1;
        hdr.spares[l2 as usize + 1] = l2 + 1;
        hdr.ovfl_point = l2;
        hdr.last_freed = 2;
        hdr.max_bucket = nbuckets - 1;
        hdr.low_mask = nbuckets - 1;
        hdr.high_mask = (nbuckets << 1) - 1;
        let usable = hdr.bsize - HEADER_OVERHEAD;
        hdr.hdrpages = HDRSIZE as u32 / usable + u32::from(!(HDRSIZE as u32).is_multiple_of(usable));
        file.set_len(0)?;
        let mut h = Hash {
            file,
            o: Order::native(),
            hdr,
            nmaps: 0,
            pages: HashMap::new(),
            dirty: BTreeSet::new(),
            modified: true,
            max_chain: usize::MAX,
        };
        for i in 0..nbuckets {
            let p = h.bucket_to_page(i);
            h.new_page(p, HASH_PAGE);
        }
        h.ibitmap(oaddr_of(l2, 1), l2 + 1, 0)?;
        h.sync()?;
        Ok(h)
    }

    pub fn order(&self) -> Order {
        self.o
    }

    pub fn file(&self) -> &File {
        &self.file
    }

    fn bsize(&self) -> usize {
        self.hdr.bsize as usize
    }

    fn bucket_to_page(&self, b: u32) -> u32 {
        let mut r = b.wrapping_add(self.hdr.hdrpages);
        if b != 0 {
            let i = (log2(b.wrapping_add(1)) as usize).wrapping_sub(1) % NCACHED;
            r = r.wrapping_add(self.hdr.spares[i]);
        }
        r
    }

    fn oaddr_to_page(&self, a: u32) -> u32 {
        let s = (a >> SPLITSHIFT).min(31);
        self.bucket_to_page((1u32 << s) - 1).wrapping_add(a & SPLITMASK)
    }

    fn page_to_oaddr(&self, pgno: u32) -> u32 {
        let pgno = pgno.wrapping_sub(self.hdr.hdrpages);
        let sp_ = &self.hdr.spares;
        let mut sp = 0usize;
        while sp < NCACHED - 1 {
            if (1u32 << sp).wrapping_add(sp_[sp]) < pgno
                && (1u32 << (sp + 1)).wrapping_add(sp_[sp + 1]) > pgno
            {
                break;
            }
            sp += 1;
        }
        let sp1 = (sp + 1).min(NCACHED - 1);
        oaddr_of(
            sp1 as u32,
            pgno.wrapping_sub(((1u32 << sp1) - 1).wrapping_add(sp_[sp])),
        ) & 0xffff
    }

    fn is_bitmap_pgno(&self, pgno: u32) -> bool {
        (0..self.nmaps.min(NCACHED as u32) as usize)
            .any(|i| self.oaddr_to_page(self.hdr.bitmaps[i] as u32) == pgno)
    }

    fn page_init(&self, p: &mut [u8], pgno: u32, typ: u8) {
        let o = self.o;
        o.put_u16(p, 8, 0);
        o.put_u32(p, 4, INVALID_PGNO);
        p[10] = typ;
        o.put_u16(p, 12, (self.hdr.bsize - 1) as u16);
        o.put_u32(p, 0, pgno);
    }

    fn load(&mut self, pgno: u32) -> io::Result<()> {
        if self.pages.contains_key(&pgno) {
            return Ok(());
        }
        let bs = self.bsize();
        let mut p = vec![0u8; bs];
        read_at(&self.file, &mut p, pgno as u64 * bs as u64)?;
        if !self.is_bitmap_pgno(pgno) && self.o.u16(&p, 8) == 0 && self.o.u32(&p, 4) == 0 {
            self.page_init(&mut p, pgno, HASH_PAGE);
        }
        self.pages.insert(pgno, p);
        Ok(())
    }

    fn pg(&mut self, pgno: u32) -> io::Result<Vec<u8>> {
        self.load(pgno)?;
        Ok(self.pages[&pgno].clone())
    }

    fn pgm(&mut self, pgno: u32) -> io::Result<&mut Vec<u8>> {
        self.load(pgno)?;
        self.dirty.insert(pgno);
        self.modified = true;
        Ok(self.pages.get_mut(&pgno).unwrap())
    }

    fn new_page(&mut self, pgno: u32, typ: u8) {
        let mut p = vec![0u8; self.bsize()];
        self.page_init(&mut p, pgno, typ);
        self.pages.insert(pgno, p);
        self.dirty.insert(pgno);
        self.modified = true;
    }

    fn delete_page(&mut self, pgno: u32, ovfl: bool) -> io::Result<()> {
        if ovfl {
            self.free_ovflpage(pgno)?;
        }
        // mpool_delete drops the buffer without writing it.
        self.pages.remove(&pgno);
        self.dirty.remove(&pgno);
        Ok(())
    }

    // Page field accessors.
    fn nent(&self, p: &[u8]) -> u16 {
        self.o.u16(p, 8)
    }
    fn next(&self, p: &[u8]) -> u32 {
        self.o.u32(p, 4)
    }
    fn offset(&self, p: &[u8]) -> u16 {
        self.o.u16(p, 12)
    }
    fn key_off(&self, p: &[u8], i: usize) -> io::Result<u16> {
        let at = PAGE_OVERHEAD + i * PAIR_OVERHEAD;
        if at + 4 > p.len() {
            return Err(bad("index past page"));
        }
        Ok(self.o.u16(p, at))
    }
    fn data_off(&self, p: &[u8], i: usize) -> io::Result<u16> {
        let at = PAGE_OVERHEAD + i * PAIR_OVERHEAD + 2;
        if at + 2 > p.len() {
            return Err(bad("index past page"));
        }
        Ok(self.o.u16(p, at))
    }
    fn set_key_off(&self, p: &mut [u8], i: usize, v: u16) {
        self.o.put_u16(p, PAGE_OVERHEAD + i * PAIR_OVERHEAD, v)
    }
    fn set_data_off(&self, p: &mut [u8], i: usize, v: u16) {
        self.o.put_u16(p, PAGE_OVERHEAD + i * PAIR_OVERHEAD + 2, v)
    }
    fn freespace(&self, p: &[u8]) -> i64 {
        self.offset(p) as i64 + 1 - PAGE_OVERHEAD as i64 - self.nent(p) as i64 * PAIR_OVERHEAD as i64
    }
    fn isbig(&self, n: usize) -> bool {
        n as f64 > self.hdr.bsize as f64 * 0.75
    }

    fn prev_realkey(&self, p: &[u8], n: usize) -> io::Result<usize> {
        for i in (0..n).rev() {
            if self.key_off(p, i)? != BIGPAIR {
                return Ok(i);
            }
        }
        Ok(n)
    }

    /// Key and data ranges of a normal pair, as `__get_item` computes them.
    fn pair(&self, p: &[u8], i: usize) -> io::Result<(std::ops::Range<usize>, std::ops::Range<usize>)> {
        let ko = self.key_off(p, i)? as usize;
        let dof = self.data_off(p, i)? as usize;
        let j = self.prev_realkey(p, i)?;
        let kend = if j == i { self.bsize() } else { self.data_off(p, j)? as usize };
        if dof > ko || ko > kend || kend > p.len() {
            return Err(bad("bad pair offsets"));
        }
        Ok((ko..kend, dof..ko))
    }

    fn call_hash(&self, key: &[u8]) -> u32 {
        let mut b = hash4(key) & self.hdr.high_mask;
        if b > self.hdr.max_bucket {
            b &= self.hdr.low_mask;
        }
        b
    }

    /// The pages of a big pair's chain, starting at overflow address `oaddr`.
    fn big_chain(&mut self, oaddr: u32) -> io::Result<Vec<u32>> {
        let mut out = Vec::new();
        let mut pgno = self.oaddr_to_page(oaddr);
        loop {
            if out.len() > self.max_chain {
                return Err(bad("big pair chain loop"));
            }
            out.push(pgno);
            let next = {
                let p = self.pg(pgno)?;
                self.next(&p)
            };
            if next == INVALID_PGNO {
                return Ok(out);
            }
            pgno = next;
        }
    }

    fn big_parts(&mut self, pgno: u32) -> io::Result<(Vec<u8>, Vec<u8>)> {
        let p = self.pg(pgno)?;
        let kl = self.key_off(&p, 0)? as usize;
        let dl = self.data_off(&p, 0)? as usize;
        let s = PAGE_OVERHEAD + PAIR_OVERHEAD;
        if s + kl + dl > p.len() {
            return Err(bad("bad big page"));
        }
        Ok((p[s..s + kl].to_vec(), p[s + kl..s + kl + dl].to_vec()))
    }

    /// `collect_key` and `__big_return`.
    fn big_keydata(&mut self, oaddr: u32) -> io::Result<(Vec<u8>, Vec<u8>)> {
        let chain = self.big_chain(oaddr)?;
        let mut key = Vec::new();
        let mut data = Vec::new();
        let mut key_done = false;
        let mut in_data = false;
        for pg in chain {
            let (k, d) = self.big_parts(pg)?;
            if !key_done {
                if !d.is_empty() {
                    key.extend_from_slice(&k);
                    key_done = true;
                } else if k.is_empty() {
                    key_done = true;
                } else {
                    key.extend_from_slice(&k);
                }
            }
            if !d.is_empty() {
                in_data = true;
            }
            if in_data {
                data.extend_from_slice(&d);
            }
        }
        Ok((key, data))
    }

    /// `__find_bigpair`.
    fn find_bigpair(&mut self, oaddr: u32, key: &[u8]) -> io::Result<bool> {
        let mut pgno = self.oaddr_to_page(oaddr);
        let mut ks = key.len();
        let mut kp = 0;
        for _ in 0..=self.max_chain.saturating_mul(2) {
            let (bkl, part, next) = {
                let p = self.pg(pgno)?;
                let bkl = self.key_off(&p, 0)? as usize;
                let s = PAGE_OVERHEAD + PAIR_OVERHEAD;
                let part = p.get(s..s + bkl).ok_or_else(|| bad("bad big page"))?.to_vec();
                (bkl, part, self.next(&p))
            };
            if ks == 0 || bkl == 0 {
                return Ok(ks == 0);
            }
            if ks < bkl || key[kp..kp + bkl] != part[..] {
                return Ok(false);
            }
            kp += bkl;
            ks -= bkl;
            if next != INVALID_PGNO {
                pgno = next;
            }
        }
        Err(bad("big key loop"))
    }

    /// Walk `bucket` as `hash_access` does.
    fn access(&mut self, key: &[u8], seek_size: i64) -> io::Result<(Option<Found>, u32, ItemInfo)> {
        let bucket = self.call_hash(key);
        let mut info = ItemInfo { bucket, ..Default::default() };
        let mut cur = self.bucket_to_page(bucket);
        let mut pgndx: usize = 0;
        let mut num_items = 0u32;
        for _ in 0..=self.max_chain.saturating_mul(4096) {
            let p = self.pg(cur)?;
            if seek_size != 0 && self.freespace(&p) > seek_size {
                info.seek_found_page = cur;
            }
            let p = if pgndx == self.nent(&p) as usize {
                let next = self.next(&p);
                if next == INVALID_PGNO {
                    return Ok((None, num_items, info));
                }
                cur = next;
                pgndx = 0;
                self.pg(cur)?
            } else {
                p
            };
            info.pgno = cur;
            info.pgndx = pgndx as u32;
            num_items += 1;
            let ko = self.key_off(&p, pgndx)?;
            let hit = if ko == BIGPAIR {
                let oaddr = self.data_off(&p, pgndx)? as u32;
                self.find_bigpair(oaddr, key)?
            } else {
                let (kr, _) = self.pair(&p, pgndx)?;
                p[kr] == *key
            };
            if hit {
                return Ok((Some(Found { pgno: cur, ndx: pgndx as u16 }), num_items, info));
            }
            pgndx += 1;
        }
        Err(bad("bucket chain loop"))
    }

    pub fn get(&mut self, key: &[u8]) -> io::Result<Option<Vec<u8>>> {
        let (found, _, _) = self.access(key, 0)?;
        let Some(f) = found else { return Ok(None) };
        let p = self.pg(f.pgno)?;
        let i = f.ndx as usize;
        if self.key_off(&p, i)? == BIGPAIR {
            let oaddr = self.data_off(&p, i)? as u32;
            Ok(Some(self.big_keydata(oaddr)?.1))
        } else {
            let (_, dr) = self.pair(&p, i)?;
            Ok(Some(p[dr].to_vec()))
        }
    }

    /// Every pair in libdb2's sequential order.
    pub fn for_each(&mut self, mut f: impl FnMut(Vec<u8>, Vec<u8>) -> io::Result<bool>) -> io::Result<()> {
        for bucket in 0..=self.hdr.max_bucket {
            let mut pgno = self.bucket_to_page(bucket);
            for _ in 0..=self.max_chain {
                let p = self.pg(pgno)?;
                for i in 0..self.nent(&p) as usize {
                    let (k, d) = if self.key_off(&p, i)? == BIGPAIR {
                        let oaddr = self.data_off(&p, i)? as u32;
                        self.big_keydata(oaddr)?
                    } else {
                        let (kr, dr) = self.pair(&p, i)?;
                        (p[kr].to_vec(), p[dr].to_vec())
                    };
                    if !f(k, d)? {
                        return Ok(());
                    }
                }
                let next = self.next(&p);
                if next == INVALID_PGNO {
                    break;
                }
                pgno = next;
            }
        }
        Ok(())
    }

    pub fn entries(&mut self) -> io::Result<Vec<(Vec<u8>, Vec<u8>)>> {
        let mut out = Vec::new();
        self.for_each(|k, d| {
            out.push((k, d));
            Ok(true)
        })?;
        Ok(out)
    }

    pub fn put(&mut self, key: &[u8], data: &[u8]) -> io::Result<()> {
        if key.len() > u16::MAX as usize * 64 || data.len() > u32::MAX as usize / 2 {
            return Err(bad("item too large"));
        }
        let seek = if self.isbig(key.len() + data.len()) {
            PAIR_OVERHEAD as i64
        } else {
            (key.len() + data.len()) as i64
        };
        let (found, num_items, mut info) = self.access(key, seek)?;
        match found {
            None => self.addel(&mut info, key, data, NumItems::Count(num_items), false)?,
            Some(f) => {
                self.delpair(f.pgno, f.ndx as usize, &mut info)?;
                self.addel(&mut info, key, data, NumItems::Unknown, false)?;
            }
        }
        if info.caused_expand {
            self.expand_table()?;
        }
        Ok(())
    }

    pub fn delete(&mut self, key: &[u8]) -> io::Result<bool> {
        let (found, _, mut info) = self.access(key, 0)?;
        match found {
            None => Ok(false),
            Some(f) => {
                self.delpair(f.pgno, f.ndx as usize, &mut info)?;
                Ok(true)
            }
        }
    }

    fn putpair(&self, p: &mut [u8], key: &[u8], val: &[u8]) {
        let n = self.nent(p) as usize;
        let mut off = self.offset(p) as usize + 1 - key.len();
        p[off..off + key.len()].copy_from_slice(key);
        self.set_key_off(p, n, off as u16);
        off -= val.len();
        p[off..off + val.len()].copy_from_slice(val);
        self.set_data_off(p, n, off as u16);
        self.o.put_u16(p, 8, n as u16 + 1);
        self.o.put_u16(p, 12, (off - 1) as u16);
    }

    fn fits(&self, p: &[u8], big: bool, psize: usize) -> bool {
        if big {
            self.freespace(p) >= PAIR_OVERHEAD as i64
        } else {
            psize as i64 <= self.freespace(p)
        }
    }

    /// `__addel`.
    fn addel(&mut self, info: &mut ItemInfo, key: &[u8], val: &[u8], num: NumItems, expanding: bool) -> io::Result<()> {
        let psize = PAIR_OVERHEAD + key.len() + val.len();
        let big = self.isbig(psize);
        let mut do_expand = false;
        let mut pgno = if info.seek_found_page != 0 { info.seek_found_page } else { info.pgno };
        for _ in 0..=self.max_chain.saturating_add(4096) {
            let p = self.pg(pgno)?;
            if self.nent(&p) == 0 || self.next(&p) == INVALID_PGNO || self.fits(&p, big, psize) {
                break;
            }
            pgno = self.next(&p);
        }
        if !{ let p = self.pg(pgno)?; self.fits(&p, big, psize) } {
            do_expand = true;
            pgno = self.add_ovflpage(pgno)?;
            if !{ let p = self.pg(pgno)?; self.fits(&p, big, psize) } {
                return Err(bad("pair does not fit"));
            }
        }
        if big {
            self.big_insert(pgno, key, val)?;
        } else {
            let mut p = std::mem::take(self.pgm(pgno)?);
            self.putpair(&mut p, key, val);
            self.pages.insert(pgno, p);
        }
        info.pgno = pgno;
        if !expanding {
            self.hdr.nkeys = self.hdr.nkeys.wrapping_add(1);
        }
        if expanding {
            info.caused_expand = false;
        } else {
            match num {
                NumItems::NoExpand => info.caused_expand = false,
                NumItems::Unknown => {
                    info.caused_expand |= self.hdr.max_bucket != 0
                        && self.hdr.nkeys / self.hdr.max_bucket > self.hdr.ffactor
                        || info.pgndx > self.hdr.ffactor;
                }
                NumItems::Count(n) => {
                    info.caused_expand = n > self.hdr.ffactor || do_expand;
                }
            }
        }
        Ok(())
    }

    /// `__big_insert`.
    fn big_insert(&mut self, base: u32, key: &[u8], val: &[u8]) -> io::Result<()> {
        let o = self.o;
        let n = {
            let p = self.pgm(base)?;
            let n = o.u16(p, 8) + 1;
            o.put_u16(p, 8, n);
            n
        };
        let (mut k, mut v) = (key, val);
        let mut pgno = base;
        let mut base_page = true;
        while !k.is_empty() || !v.is_empty() {
            pgno = self.add_bigpage(pgno, n as usize - 1, base_page)?;
            let free = {
                let p = self.pgm(pgno)?;
                o.put_u16(p, 8, 1);
                o.u16(p, 12) as usize + 1 - PAGE_OVERHEAD - PAIR_OVERHEAD
            };
            let km = free.min(k.len());
            let vm = (free - km).min(v.len());
            let mut p = std::mem::take(self.pgm(pgno)?);
            self.set_key_off(&mut p, 0, km as u16);
            self.set_data_off(&mut p, 0, vm as u16);
            let s = PAGE_OVERHEAD + PAIR_OVERHEAD;
            p[s..s + km].copy_from_slice(&k[..km]);
            p[s + km..s + km + vm].copy_from_slice(&v[..vm]);
            self.pages.insert(pgno, p);
            k = &k[km..];
            v = &v[vm..];
            base_page = false;
        }
        Ok(())
    }

    /// `__add_bigpage`.
    fn add_bigpage(&mut self, pgno: u32, ndx: usize, is_base: bool) -> io::Result<u32> {
        let ovfl = self.overflow_page()?;
        let np = self.oaddr_to_page(ovfl as u32);
        self.new_page(np, HASH_PAGE);
        let mut p = std::mem::take(self.pgm(pgno)?);
        if is_base {
            self.set_key_off(&mut p, ndx, BIGPAIR);
            self.set_data_off(&mut p, ndx, ovfl);
        } else {
            self.o.put_u32(&mut p, 4, np);
        }
        self.pages.insert(pgno, p);
        self.pgm(np)?[10] = HASH_BIGPAGE;
        Ok(np)
    }

    /// `__add_ovflpage`.
    fn add_ovflpage(&mut self, pgno: u32) -> io::Result<u32> {
        if self.hdr.ffactor == DEF_FFACTOR {
            let n = { let p = self.pg(pgno)?; self.nent(&p) as u32 };
            self.hdr.ffactor = (n >> 1).max(MIN_FFACTOR);
        }
        let ovfl = self.overflow_page()?;
        let np = self.oaddr_to_page(ovfl as u32);
        self.new_page(np, HASH_PAGE);
        let o = self.o;
        o.put_u32(self.pgm(pgno)?, 4, np);
        self.pgm(np)?[10] = HASH_OVFLPAGE;
        Ok(np)
    }

    /// `__delpair`.
    fn delpair(&mut self, pgno: u32, ndx: usize, info: &mut ItemInfo) -> io::Result<()> {
        let o = self.o;
        let bs = self.bsize();
        let mut p = self.pg(pgno)?;
        let nent = self.nent(&p) as usize;
        if ndx >= nent {
            return Err(bad("bad delete index"));
        }
        let delta: i32 = if self.key_off(&p, ndx)? == BIGPAIR {
            let oaddr = self.data_off(&p, ndx)? as u32;
            for pg in self.big_chain(oaddr)? {
                self.delete_page(pg, true)?;
            }
            0
        } else {
            let mut check: isize = ndx as isize - 1;
            while check >= 0 && self.key_off(&p, check as usize)? == BIGPAIR {
                check -= 1;
            }
            let dof = self.data_off(&p, ndx)? as usize;
            let top = if check < 0 { bs } else { self.data_off(&p, check as usize)? as usize };
            let delta = top as i32 - dof as i32;
            if ndx != nent - 1 {
                let src = self.offset(&p) as usize + 1;
                let len = dof.checked_sub(src).ok_or_else(|| bad("bad offsets"))?;
                let dest = top - len;
                p.copy_within(src..src + len, dest);
            }
            delta
        };
        for n in ndx..nent - 1 {
            let k = self.key_off(&p, n + 1)?;
            let d = self.data_off(&p, n + 1)?;
            if k != BIGPAIR {
                self.set_key_off(&mut p, n, (k as i32 + delta) as u16);
                self.set_data_off(&mut p, n, (d as i32 + delta) as u16);
            } else {
                self.set_key_off(&mut p, n, k);
                self.set_data_off(&mut p, n, d);
            }
        }
        let off = self.offset(&p) as i32 + delta;
        o.put_u16(&mut p, 12, off as u16);
        o.put_u16(&mut p, 8, (nent - 1) as u16);
        self.hdr.nkeys = self.hdr.nkeys.wrapping_sub(1);
        self.pages.insert(pgno, p);
        self.dirty.insert(pgno);
        self.modified = true;
        let (typ, now, link) = {
            let p = &self.pages[&pgno];
            (p[10], self.nent(p), self.next(p))
        };
        if typ == HASH_OVFLPAGE && now == 0 {
            let mut prev = self.bucket_to_page(info.bucket);
            for _ in 0..=self.max_chain {
                let next = { let p = self.pg(prev)?; self.next(&p) };
                if next == pgno {
                    break;
                }
                if next == INVALID_PGNO {
                    return Err(bad("overflow page not in its bucket"));
                }
                prev = next;
            }
            o.put_u32(self.pgm(prev)?, 4, link);
            if info.pgno == pgno {
                info.pgno = prev;
                info.pgndx = { let p = self.pg(prev)?; self.nent(&p) as u32 };
                info.seek_found_page = prev;
            }
            self.delete_page(pgno, true)?;
        }
        Ok(())
    }

    /// `__expand_table`.
    fn expand_table(&mut self) -> io::Result<()> {
        self.hdr.max_bucket += 1;
        let nb = self.hdr.max_bucket;
        let ob = nb & self.hdr.low_mask;
        let np = self.bucket_to_page(nb);
        self.new_page(np, HASH_PAGE);
        let spare_ndx = log2(nb + 1);
        if spare_ndx > self.hdr.ovfl_point {
            if spare_ndx as usize >= NCACHED {
                return Err(bad("table full"));
            }
            self.hdr.spares[spare_ndx as usize] = self.hdr.spares[self.hdr.ovfl_point as usize];
            self.hdr.ovfl_point = spare_ndx;
        }
        if nb > self.hdr.high_mask {
            self.hdr.low_mask = self.hdr.high_mask;
            self.hdr.high_mask = nb | self.hdr.low_mask;
        }
        self.split_page(ob, nb)
    }

    /// `__split_page`.
    fn split_page(&mut self, ob: u32, nb: u32) -> io::Result<()> {
        let opg = self.bucket_to_page(ob);
        let mut temp = self.pg(opg)?;
        {
            let mut p = std::mem::take(self.pgm(opg)?);
            let addr = self.o.u32(&p, 0);
            self.page_init(&mut p, addr, HASH_PAGE);
            self.pages.insert(opg, p);
        }
        let mut old_ii = ItemInfo { pgno: opg, bucket: ob, ..Default::default() };
        let mut new_ii = ItemInfo { pgno: self.bucket_to_page(nb), bucket: nb, ..Default::default() };
        let mut base_page = true;
        let mut temp_pgno = opg;
        for _ in 0..=self.max_chain.saturating_add(4096) {
            for n in 0..self.nent(&temp) as usize {
                if self.key_off(&temp, n)? == BIGPAIR {
                    let oaddr = self.data_off(&temp, n)?;
                    let (k, _) = self.big_keydata(oaddr as u32)?;
                    if self.call_hash(&k) == ob {
                        self.add_bigptr(ob, oaddr)?;
                    } else {
                        self.add_bigptr(nb, oaddr)?;
                    }
                } else {
                    let (kr, dr) = self.pair(&temp, n)?;
                    let (k, v) = (temp[kr].to_vec(), temp[dr].to_vec());
                    let ii = if self.call_hash(&k) == ob { &mut old_ii } else { &mut new_ii };
                    self.addel(ii, &k, &v, NumItems::NoExpand, true)?;
                }
            }
            let next = self.next(&temp);
            if !base_page {
                self.delete_page(temp_pgno, true)?;
            }
            base_page = false;
            if next == INVALID_PGNO {
                return Ok(());
            }
            temp_pgno = next;
            temp = self.pg(next)?;
        }
        Err(bad("split chain loop"))
    }

    /// `add_bigptr`.
    fn add_bigptr(&mut self, bucket: u32, oaddr: u16) -> io::Result<()> {
        let mut pgno = self.bucket_to_page(bucket);
        for _ in 0..=self.max_chain.saturating_add(4096) {
            let p = self.pg(pgno)?;
            if self.nent(&p) == 0 || self.next(&p) == INVALID_PGNO || self.freespace(&p) >= PAIR_OVERHEAD as i64 {
                break;
            }
            pgno = self.next(&p);
        }
        if { let p = self.pg(pgno)?; self.freespace(&p) } < PAIR_OVERHEAD as i64 {
            pgno = self.add_ovflpage(pgno)?;
        }
        let mut p = std::mem::take(self.pgm(pgno)?);
        let n = self.nent(&p) as usize;
        self.set_key_off(&mut p, n, BIGPAIR);
        self.set_data_off(&mut p, n, oaddr);
        self.o.put_u16(&mut p, 8, n as u16 + 1);
        self.pages.insert(pgno, p);
        Ok(())
    }

    fn bitmap_pgno(&mut self, ndx: u32) -> io::Result<Option<u32>> {
        if ndx >= self.nmaps || ndx as usize >= NCACHED {
            return Ok(None);
        }
        let pg = self.oaddr_to_page(self.hdr.bitmaps[ndx as usize] as u32);
        self.load(pg)?;
        Ok(Some(pg))
    }

    fn map_word(&self, pg: u32, j: u32) -> io::Result<u32> {
        let p = &self.pages[&pg];
        let at = j as usize * 4;
        if at + 4 > p.len() {
            return Err(bad("bitmap index"));
        }
        Ok(self.o.u32(p, at))
    }

    fn set_bit(&mut self, pg: u32, bit: u32, on: bool) -> io::Result<()> {
        let o = self.o;
        let at = (bit / BITS_PER_MAP) as usize * 4;
        let p = self.pgm(pg)?;
        if at + 4 > p.len() {
            return Err(bad("bitmap index"));
        }
        let mut w = o.u32(p, at);
        if on {
            w |= 1 << (bit % BITS_PER_MAP);
        } else {
            w &= !(1 << (bit % BITS_PER_MAP));
        }
        o.put_u32(p, at, w);
        Ok(())
    }

    /// `__ibitmap`.
    fn ibitmap(&mut self, pnum: u32, nbits: u32, ndx: u32) -> io::Result<()> {
        let pg = self.oaddr_to_page(pnum);
        let bs = self.bsize();
        let o = self.o;
        let mut p = vec![0u8; bs];
        let clearints = ((nbits - 1) >> 5) + 1;
        let clearbytes = (clearints << 2) as usize;
        p[clearbytes..].fill(0xff);
        o.put_u32(&mut p, (clearints as usize - 1) * 4, ALL_SET << (nbits & 31));
        let w = o.u32(&p, 0) | 1;
        o.put_u32(&mut p, 0, w);
        self.pages.insert(pg, p);
        self.dirty.insert(pg);
        self.modified = true;
        self.nmaps += 1;
        self.hdr.bitmaps[ndx as usize] = pnum as u16;
        Ok(())
    }

    /// `overflow_page`: allocate an overflow address.
    fn overflow_page(&mut self) -> io::Result<u16> {
        let full = || bad("out of overflow pages");
        let bits = self.hdr.bsize << BYTE_SHIFT;
        let shift = self.hdr.bshift + BYTE_SHIFT;
        let mut splitnum = self.hdr.ovfl_point;
        let max_free = self.hdr.spares[splitnum as usize];
        let mut free_page = max_free.wrapping_sub(1) >> shift;
        let mut free_bit = max_free.wrapping_sub(1) & (bits - 1);
        let first_page = self.hdr.last_freed >> shift;
        let mut freep = None;
        let mut i = first_page;
        while i <= free_page {
            let Some(pg) = self.bitmap_pgno(i)? else { return Err(full()) };
            freep = Some(pg);
            let in_use_bits = if i == free_page { free_bit } else { bits - 1 };
            let (mut bit, mut j) = if i == first_page {
                let b = self.hdr.last_freed & (bits - 1);
                (b & !(BITS_PER_MAP - 1), b / BITS_PER_MAP)
            } else {
                (0, 0)
            };
            while bit <= in_use_bits {
                let w = self.map_word(pg, j)?;
                if w != ALL_SET {
                    // found:
                    let bit = bit + (!w).trailing_zeros().min(BITS_PER_MAP);
                    self.set_bit(pg, bit, true)?;
                    let bit = 1 + bit + i * bits;
                    if bit >= self.hdr.last_freed {
                        self.hdr.last_freed = bit - 1;
                    }
                    let mut s = 0;
                    while s < splitnum && bit > self.hdr.spares[s as usize] {
                        s += 1;
                    }
                    let offset = if s != 0 { bit - self.hdr.spares[s as usize - 1] } else { bit };
                    if offset >= SPLITMASK {
                        return Err(full());
                    }
                    self.modified = true;
                    return Ok(oaddr_of(s, offset) as u16);
                }
                j += 1;
                bit += BITS_PER_MAP;
            }
            i += 1;
        }
        self.modified = true;
        self.hdr.last_freed = self.hdr.spares[splitnum as usize];
        self.hdr.spares[splitnum as usize] += 1;
        let mut offset = self.hdr.spares[splitnum as usize]
            - if splitnum != 0 { self.hdr.spares[splitnum as usize - 1] } else { 0 };
        if offset > SPLITMASK {
            splitnum += 1;
            if splitnum as usize >= NCACHED {
                return Err(full());
            }
            self.hdr.ovfl_point = splitnum;
            self.hdr.spares[splitnum as usize] = self.hdr.spares[splitnum as usize - 1];
            self.hdr.spares[splitnum as usize - 1] -= 1;
            offset = 1;
        }
        if free_bit == bits - 1 {
            free_page += 1;
            if free_page as usize >= NCACHED {
                return Err(full());
            }
            self.ibitmap(oaddr_of(splitnum, offset), 1, free_page)?;
            self.hdr.spares[splitnum as usize] += 1;
            offset += 1;
            if offset > SPLITMASK {
                splitnum += 1;
                if splitnum as usize >= NCACHED {
                    return Err(full());
                }
                self.hdr.ovfl_point = splitnum;
                self.hdr.spares[splitnum as usize] = self.hdr.spares[splitnum as usize - 1];
                self.hdr.spares[splitnum as usize - 1] -= 1;
                offset = 0;
            }
        } else {
            free_bit += 1;
            let Some(pg) = freep else { return Err(full()) };
            self.set_bit(pg, free_bit, true)?;
        }
        Ok(oaddr_of(splitnum, offset) as u16)
    }

    /// `__free_ovflpage`.
    fn free_ovflpage(&mut self, pgno: u32) -> io::Result<()> {
        let addr = self.page_to_oaddr(pgno);
        let ndx = addr >> SPLITSHIFT;
        let base = if ndx != 0 { self.hdr.spares[(ndx as usize - 1) % NCACHED] } else { 0 };
        let bit_address = (base + (addr & SPLITMASK)).wrapping_sub(1);
        if bit_address < self.hdr.last_freed {
            self.hdr.last_freed = bit_address;
        }
        let shift = self.hdr.bshift + BYTE_SHIFT;
        let free_page = bit_address >> shift;
        let free_bit = bit_address & ((self.hdr.bsize << BYTE_SHIFT) - 1);
        let Some(pg) = self.bitmap_pgno(free_page)? else {
            return Err(bad("overflow page outside the bitmaps"));
        };
        self.modified = true;
        self.set_bit(pg, free_bit, false)
    }

    /// Write dirty pages and the header (`hash_sync`).
    pub fn sync(&mut self) -> io::Result<()> {
        if !self.modified {
            return Ok(());
        }
        let bs = self.bsize() as u64;
        for pgno in std::mem::take(&mut self.dirty) {
            if let Some(p) = self.pages.get(&pgno) {
                write_at(&self.file, p, pgno as u64 * bs)?;
            }
        }
        self.hdr.magic = HASHMAGIC;
        self.hdr.version = HASHVERSION;
        self.hdr.h_charkey = hash4(CHARKEY);
        write_at(&self.file, &self.hdr.write(), 0)?;
        self.file.sync_all()?;
        self.modified = false;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn charkey_hash() {
        // h_charkey of MIT-created files.
        assert_ne!(hash4(CHARKEY), 0);
    }

    #[test]
    fn insert_expand_delete_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("h.db");
        let open = || std::fs::OpenOptions::new().read(true).write(true).create(true).truncate(false).open(&path).unwrap();
        let mut h = Hash::create(open(), 4096, 40, 1).unwrap();
        let mut model = std::collections::BTreeMap::new();
        let mut seed = 0x1234_5678_9abc_def0u64;
        for i in 0..3000u32 {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            let klen = if i % 97 == 0 { 5000 } else { 5 + (seed >> 59) as usize };
            let dlen = if i % 89 == 0 { 9000 } else { (seed >> 40) as usize % 400 };
            let mut k = format!("k{i:05}-").into_bytes();
            k.resize(klen.max(k.len()), b'a' + (i % 26) as u8);
            let d = vec![(i % 251) as u8; dlen];
            h.put(&k, &d).unwrap();
            model.insert(k, d);
        }
        h.sync().unwrap();
        let mut h = Hash::open(open()).unwrap();
        let mut got: Vec<_> = h.entries().unwrap();
        got.sort();
        assert_eq!(got, model.clone().into_iter().collect::<Vec<_>>());
        for (k, v) in &model {
            assert_eq!(h.get(k).unwrap().as_ref(), Some(v));
        }
        let keys: Vec<_> = model.keys().cloned().collect();
        for (i, k) in keys.iter().enumerate() {
            if i % 3 != 0 {
                assert!(h.delete(k).unwrap());
                model.remove(k);
            } else if i % 2 == 0 {
                let d = vec![7u8; i % 700];
                h.put(k, &d).unwrap();
                model.insert(k.clone(), d);
            }
        }
        h.sync().unwrap();
        let mut h = Hash::open(open()).unwrap();
        let mut got: Vec<_> = h.entries().unwrap();
        got.sort();
        assert_eq!(got, model.clone().into_iter().collect::<Vec<_>>());
        for k in model.keys() {
            assert!(h.delete(k).unwrap());
        }
        h.sync().unwrap();
        let mut h = Hash::open(open()).unwrap();
        assert!(h.entries().unwrap().is_empty());
        assert_eq!(h.hdr.nkeys, 0);
    }
}
