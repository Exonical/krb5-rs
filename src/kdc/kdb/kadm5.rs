//! MIT kadm5 admin RPC (program 2112, version 2): the wire types of
//! `lib/kadm5/kadm_rpc_xdr.c`, the error codes of `kadm_err.et`, and the
//! read-only server logic of `svr_principal.c`, `svr_policy.c` and
//! `svr_iters.c`.

use crate::kdc::kdb::mit::{
    unparse_name, MitEntry, MitPolicy, OsaPrincipalData, TlData, KADM5_POLICY, KADM_DATA,
    LAST_PWD_CHANGE, MKVNO, MOD_PRINC,
};
use crate::kdc::store::StoreError;
use crate::rpc::xdr::{XdrError, XdrReader, XdrWriter};

/// `KADM` (`kadm_rpc.h`).
pub const KADM_PROG: u32 = 2112;
/// `KADMVERS`.
pub const KADM_VERS: u32 = 2;

/// Procedure numbers (`kadm_rpc.h`).
pub mod proc_ {
    #![allow(missing_docs)]
    pub const NULL: u32 = 0;
    pub const CREATE_PRINCIPAL: u32 = 1;
    pub const DELETE_PRINCIPAL: u32 = 2;
    pub const MODIFY_PRINCIPAL: u32 = 3;
    pub const RENAME_PRINCIPAL: u32 = 4;
    pub const GET_PRINCIPAL: u32 = 5;
    pub const CHPASS_PRINCIPAL: u32 = 6;
    pub const CHRAND_PRINCIPAL: u32 = 7;
    pub const CREATE_POLICY: u32 = 8;
    pub const DELETE_POLICY: u32 = 9;
    pub const MODIFY_POLICY: u32 = 10;
    pub const GET_POLICY: u32 = 11;
    pub const GET_PRIVS: u32 = 12;
    pub const INIT: u32 = 13;
    pub const GET_PRINCS: u32 = 14;
    pub const GET_POLS: u32 = 15;
    pub const SETKEY_PRINCIPAL: u32 = 16;
    pub const CREATE_PRINCIPAL3: u32 = 18;
    pub const CHPASS_PRINCIPAL3: u32 = 19;
    pub const CHRAND_PRINCIPAL3: u32 = 20;
    pub const SETKEY_PRINCIPAL3: u32 = 21;
    pub const PURGEKEYS: u32 = 22;
    pub const GET_STRINGS: u32 = 23;
    pub const SET_STRING: u32 = 24;
    pub const SETKEY_PRINCIPAL4: u32 = 25;
    pub const EXTRACT_KEYS: u32 = 26;
    pub const CREATE_ALIAS: u32 = 27;
}

/// `KADM5_API_VERSION_MASK` (`admin.h`).
pub const API_VERSION_MASK: u32 = 0x1234_5700;
/// `KADM5_API_VERSION_2`.
pub const API_VERSION_2: u32 = API_VERSION_MASK | 2;
/// `KADM5_API_VERSION_3`.
pub const API_VERSION_3: u32 = API_VERSION_MASK | 3;
/// `KADM5_API_VERSION_4`.
pub const API_VERSION_4: u32 = API_VERSION_MASK | 4;
const MASK_BITS: u32 = 0xffff_ff00;

/// `kadm_err.et` codes (table `ovk`) and the errno values kadm5 returns.
pub mod code {
    #![allow(missing_docs)]
    const BASE: u32 = 43_787_520;
    pub const OK: u32 = 0;
    pub const EINVAL: u32 = 22;
    pub const FAILURE: u32 = BASE;
    pub const AUTH_GET: u32 = BASE + 1;
    pub const AUTH_ADD: u32 = BASE + 2;
    pub const AUTH_MODIFY: u32 = BASE + 3;
    pub const AUTH_DELETE: u32 = BASE + 4;
    pub const AUTH_INSUFFICIENT: u32 = BASE + 5;
    pub const DUP: u32 = BASE + 7;
    pub const UNK_PRINC: u32 = BASE + 12;
    pub const UNK_POLICY: u32 = BASE + 13;
    pub const BAD_MASK: u32 = BASE + 14;
    pub const BAD_POLICY: u32 = BASE + 17;
    pub const BAD_PRINCIPAL: u32 = BASE + 18;
    pub const BAD_API_VERSION: u32 = BASE + 35;
    pub const OLD_SERVER_API_VERSION: u32 = BASE + 37;
    pub const NEW_SERVER_API_VERSION: u32 = BASE + 39;
    pub const AUTH_LIST: u32 = BASE + 44;
    pub const AUTH_CHANGEPW: u32 = BASE + 45;
    pub const AUTH_SETKEY: u32 = BASE + 50;
    pub const AUTH_EXTRACT: u32 = BASE + 60;
    pub const PROTECT_KEYS: u32 = BASE + 61;
    pub const ALIAS_REALM: u32 = BASE + 63;

    /// The `kadm_err.et` text for `code`, as kadmind logs it.
    pub fn message(code: u32) -> String {
        match code {
            EINVAL => "Invalid argument".into(),
            FAILURE => "Operation failed for unspecified reason".into(),
            UNK_PRINC => "Principal does not exist".into(),
            UNK_POLICY => "Policy does not exist".into(),
            BAD_POLICY => "Illegal policy name".into(),
            BAD_PRINCIPAL => "Illegal principal name".into(),
            _ => format!("error {code}"),
        }
    }
}

/// `kadm5_principal_ent_rec` mask bits (`admin.h`).
pub mod mask {
    #![allow(missing_docs)]
    pub const PRINCIPAL: i32 = 0x00_0001;
    pub const PRINC_EXPIRE_TIME: i32 = 0x00_0002;
    pub const PW_EXPIRATION: i32 = 0x00_0004;
    pub const LAST_PWD_CHANGE: i32 = 0x00_0008;
    pub const ATTRIBUTES: i32 = 0x00_0010;
    pub const MAX_LIFE: i32 = 0x00_0020;
    pub const MOD_TIME: i32 = 0x00_0040;
    pub const MOD_NAME: i32 = 0x00_0080;
    pub const KVNO: i32 = 0x00_0100;
    pub const MKVNO: i32 = 0x00_0200;
    pub const AUX_ATTRIBUTES: i32 = 0x00_0400;
    pub const POLICY: i32 = 0x00_0800;
    pub const MAX_RLIFE: i32 = 0x00_2000;
    pub const LAST_SUCCESS: i32 = 0x00_4000;
    pub const LAST_FAILED: i32 = 0x00_8000;
    pub const FAIL_AUTH_COUNT: i32 = 0x01_0000;
    pub const KEY_DATA: i32 = 0x02_0000;
    pub const TL_DATA: i32 = 0x04_0000;
    pub const PRINCIPAL_NORMAL_MASK: i32 = 0x41_ffff;
}

/// `CHECK_VERSIONS` (`admin_internal.h`) for a client's API version.
pub fn check_api_version(api_version: u32) -> u32 {
    if api_version & MASK_BITS != API_VERSION_MASK {
        code::BAD_API_VERSION
    } else if api_version < API_VERSION_2 {
        code::OLD_SERVER_API_VERSION
    } else if api_version > API_VERSION_4 {
        code::NEW_SERVER_API_VERSION
    } else {
        code::OK
    }
}

/// `xdr_nullstring`: a NUL-terminated string, or 0 for NULL.
pub fn read_nullstring(r: &mut XdrReader<'_>) -> Result<Option<String>, XdrError> {
    let size = usize::try_from(r.u32()?).map_err(|_| XdrError("length"))?;
    if size == 0 {
        return Ok(None);
    }
    let bytes = r.fixed(size)?;
    let (last, body) = bytes.split_last().ok_or(XdrError("length"))?;
    if *last != 0 || body.contains(&0) {
        return Err(XdrError("not a C string"));
    }
    String::from_utf8(body.to_vec())
        .map(Some)
        .map_err(|_| XdrError("not UTF-8"))
}

/// `xdr_nullstring` encoding.
pub fn write_nullstring(w: &mut XdrWriter, s: Option<&[u8]>) {
    match s {
        None => w.u32(0),
        Some(s) => {
            let mut v = s.to_vec();
            v.push(0);
            w.opaque(&v);
        }
    }
}

fn write_tl_list(w: &mut XdrWriter, tl: &[TlData]) {
    // xdr_nulltype: "is NULL" first.
    w.bool(tl.is_empty());
    if tl.is_empty() {
        return;
    }
    for t in tl {
        w.bool(true);
        w.i32(i32::from(t.kind as i16));
        w.opaque(&t.data);
    }
    w.bool(false);
}

fn len_i32(n: usize) -> i32 {
    i32::try_from(n).unwrap_or(i32::MAX)
}

/// The arguments of the read-only calls.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReadArgs {
    /// `INIT`, `GET_PRIVS`: just the API version.
    Api(u32),
    /// `gprinc_arg`.
    GetPrincipal {
        /// `api_version`.
        api_version: u32,
        /// The unparsed principal.
        princ: Option<String>,
        /// `mask`.
        mask: i32,
    },
    /// `gprincs_arg`, `gpols_arg`, `gpol_arg`, `gstrings_arg`: a version and
    /// one nullable string.
    Name {
        /// `api_version`.
        api_version: u32,
        /// `exp`, `name` or the unparsed `princ`.
        name: Option<String>,
    },
}

impl ReadArgs {
    /// Decode the arguments of `proc_`; `None` for other procedures.
    pub fn decode(proc_: u32, args: &[u8]) -> Option<Result<Self, XdrError>> {
        let mut r = XdrReader::new(args);
        let parsed = match proc_ {
            proc_::INIT | proc_::GET_PRIVS => r.u32().map(Self::Api),
            proc_::GET_PRINCIPAL => (|| {
                Ok(Self::GetPrincipal {
                    api_version: r.u32()?,
                    princ: read_nullstring(&mut r)?,
                    mask: r.i32()?,
                })
            })(),
            proc_::GET_PRINCS | proc_::GET_POLS | proc_::GET_POLICY | proc_::GET_STRINGS => {
                (|| {
                    Ok(Self::Name {
                        api_version: r.u32()?,
                        name: read_nullstring(&mut r)?,
                    })
                })()
            }
            _ => return None,
        };
        Some(parsed.and_then(|a| r.finish().map(|()| a)))
    }
}

/// `generic_ret`, the reply to `INIT`.
pub fn generic_ret(api_version: u32, code: u32) -> Vec<u8> {
    let mut w = XdrWriter::default();
    w.u32(api_version);
    w.u32(code);
    w.0
}

/// `gprincs_ret` / `gpols_ret`.
pub fn names_ret(api_version: u32, code: u32, names: &[Vec<u8>]) -> Vec<u8> {
    let mut w = XdrWriter::default();
    w.u32(api_version);
    w.u32(code);
    if code == code::OK {
        w.i32(len_i32(names.len()));
        w.u32(u32::try_from(names.len()).unwrap_or(u32::MAX));
        for n in names {
            write_nullstring(&mut w, Some(n));
        }
    }
    w.0
}

/// `getprivs_ret`.
pub fn getprivs_ret(api_version: u32, code: u32, privs: i32) -> Vec<u8> {
    let mut w = XdrWriter::default();
    w.u32(api_version);
    w.u32(code);
    w.i32(privs);
    w.0
}

/// `gstrings_ret`.
pub fn gstrings_ret(api_version: u32, code: u32, strings: &[(Vec<u8>, Vec<u8>)]) -> Vec<u8> {
    let mut w = XdrWriter::default();
    w.u32(api_version);
    w.u32(code);
    if code == code::OK {
        w.i32(len_i32(strings.len()));
        w.u32(u32::try_from(strings.len()).unwrap_or(u32::MAX));
        for (k, v) in strings {
            write_nullstring(&mut w, Some(k));
            write_nullstring(&mut w, Some(v));
        }
    }
    w.0
}

/// `gpol_ret`, with the policy record shaped by `api_version` like
/// `kadm5_get_policy` and `_xdr_kadm5_policy_ent_rec`.
pub fn gpol_ret(api_version: u32, code: u32, policy: Option<&MitPolicy>) -> Vec<u8> {
    let mut w = XdrWriter::default();
    w.u32(api_version);
    w.u32(code);
    if let (code::OK, Some(p)) = (code, policy) {
        let long = |w: &mut XdrWriter, v: u32| w.i32(v as i32);
        write_nullstring(&mut w, Some(p.name.as_bytes()));
        long(&mut w, p.pw_min_life);
        long(&mut w, p.pw_max_life);
        long(&mut w, p.pw_min_length);
        long(&mut w, p.pw_min_classes);
        long(&mut w, p.pw_history_num);
        // policy_refcnt: kadm5_get_policy leaves it zero.
        long(&mut w, 0);
        if api_version >= API_VERSION_3 {
            w.u32(p.pw_max_fail);
            long(&mut w, p.pw_failcnt_interval);
            long(&mut w, p.pw_lockout_duration);
        }
        if api_version >= API_VERSION_4 {
            w.u32(p.attributes);
            long(&mut w, p.max_life);
            long(&mut w, p.max_renewable_life);
            write_nullstring(&mut w, p.allowed_keysalts.as_deref().map(str::as_bytes));
            w.i32(len_i32(p.tl_data.len()));
            write_tl_list(&mut w, &p.tl_data);
        }
    }
    w.0
}

/// A `kadm5_principal_ent_rec` as `kadm5_get_principal` fills it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PrincipalEnt {
    /// `principal`, unparsed.
    pub principal: Option<Vec<u8>>,
    /// `princ_expire_time`.
    pub princ_expire_time: u32,
    /// `last_pwd_change`.
    pub last_pwd_change: u32,
    /// `pw_expiration`.
    pub pw_expiration: u32,
    /// `max_life`.
    pub max_life: u32,
    /// `mod_name`, unparsed.
    pub mod_name: Option<Vec<u8>>,
    /// `mod_date`.
    pub mod_date: u32,
    /// `attributes`.
    pub attributes: u32,
    /// `kvno`.
    pub kvno: u32,
    /// `mkvno`.
    pub mkvno: u32,
    /// `policy`.
    pub policy: Option<Vec<u8>>,
    /// `aux_attributes`.
    pub aux_attributes: i32,
    /// `max_renewable_life`.
    pub max_renewable_life: u32,
    /// `last_success`.
    pub last_success: u32,
    /// `last_failed`.
    pub last_failed: u32,
    /// `fail_auth_count`.
    pub fail_auth_count: u32,
    /// `tl_data`, most recent first as MIT builds the list.
    pub tl_data: Vec<TlData>,
    /// `key_data` versions, kvnos and types (contents never go on the wire).
    pub key_data: Vec<(u16, u16, i16, i16)>,
}

fn tl(entry: &MitEntry, kind: u16) -> Option<&[u8]> {
    entry
        .tl_data
        .iter()
        .find(|t| t.kind == kind)
        .map(|t| t.data.as_slice())
}

fn strip_nul(s: &[u8]) -> Vec<u8> {
    s.strip_suffix(&[0]).unwrap_or(s).to_vec()
}

impl PrincipalEnt {
    /// `kadm5_get_principal` (`svr_principal.c`) on a stored entry;
    /// `min_mkvno` is the lowest master key version, used when the entry
    /// has no `KRB5_TL_MKVNO` (`krb5_dbe_get_mkvno`).
    pub fn from_entry(entry: &MitEntry, mask: i32, min_mkvno: u16) -> Result<Self, StoreError> {
        let has = |bit: i32| mask & bit != 0;
        let mut ent = Self::default();
        let adb = tl(entry, KADM_DATA)
            .map(OsaPrincipalData::decode)
            .transpose()?;
        if let Some(adb) = &adb {
            if has(mask::POLICY) && adb.aux_attributes & KADM5_POLICY != 0 {
                ent.policy = adb.policy.as_deref().map(strip_nul);
            }
            if has(mask::AUX_ATTRIBUTES) {
                ent.aux_attributes = adb.aux_attributes;
            }
        }
        if has(mask::PRINCIPAL) {
            ent.principal = Some(unparse_name(&entry.principal, &entry.realm));
        }
        if has(mask::PRINC_EXPIRE_TIME) {
            ent.princ_expire_time = entry.expiration;
        }
        if has(mask::LAST_PWD_CHANGE) {
            ent.last_pwd_change = match tl(entry, LAST_PWD_CHANGE) {
                Some([a, b, c, d, ..]) => u32::from_le_bytes([*a, *b, *c, *d]),
                Some(_) => return Err(StoreError::corrupt("short KRB5_TL_LAST_PWD_CHANGE")),
                None => 0,
            };
        }
        if has(mask::PW_EXPIRATION) {
            ent.pw_expiration = entry.pw_expiration;
        }
        if has(mask::MAX_LIFE) {
            ent.max_life = entry.max_life;
        }
        if has(mask::MOD_NAME) || has(mask::MOD_TIME) {
            if let Some(data) = tl(entry, MOD_PRINC) {
                let [a, b, c, d, name @ ..] = data else {
                    return Err(StoreError::corrupt("short KRB5_TL_MOD_PRINC"));
                };
                if has(mask::MOD_TIME) {
                    ent.mod_date = u32::from_le_bytes([*a, *b, *c, *d]);
                }
                if has(mask::MOD_NAME) {
                    ent.mod_name = Some(strip_nul(name));
                }
            }
        }
        if has(mask::ATTRIBUTES) {
            ent.attributes = entry.attributes;
        }
        if has(mask::KVNO) {
            ent.kvno = entry
                .key_data
                .iter()
                .map(|k| u32::from(k.kvno))
                .max()
                .unwrap_or(0);
        }
        if has(mask::MKVNO) {
            ent.mkvno = match tl(entry, MKVNO) {
                Some([a, b, ..]) if u16::from_le_bytes([*a, *b]) != 0 => {
                    u32::from(u16::from_le_bytes([*a, *b]))
                }
                Some([_]) => return Err(StoreError::corrupt("short KRB5_TL_MKVNO")),
                _ => u32::from(min_mkvno),
            };
        }
        if has(mask::MAX_RLIFE) {
            ent.max_renewable_life = entry.max_renewable_life;
        }
        if has(mask::LAST_SUCCESS) {
            ent.last_success = entry.last_success;
        }
        if has(mask::LAST_FAILED) {
            ent.last_failed = entry.last_failed;
        }
        if has(mask::FAIL_AUTH_COUNT) {
            ent.fail_auth_count = entry.fail_auth_count;
        }
        if has(mask::TL_DATA) {
            ent.tl_data = entry
                .tl_data
                .iter()
                .rev()
                .filter(|t| t.kind > 255)
                .cloned()
                .collect();
        }
        if has(mask::KEY_DATA) {
            ent.key_data = entry
                .key_data
                .iter()
                .map(|k| {
                    let ty = |i: usize| k.fields.get(i).map_or(0, |f| f.0);
                    (k.ver, k.kvno, ty(0), ty(1))
                })
                .collect();
        }
        Ok(ent)
    }

    /// `_xdr_kadm5_principal_ent_rec`.
    pub fn encode(&self, w: &mut XdrWriter) {
        write_nullstring(w, self.principal.as_deref());
        w.u32(self.princ_expire_time);
        w.u32(self.last_pwd_change);
        w.u32(self.pw_expiration);
        w.u32(self.max_life);
        w.bool(self.mod_name.is_none());
        if let Some(n) = &self.mod_name {
            write_nullstring(w, Some(n));
        }
        w.u32(self.mod_date);
        w.u32(self.attributes);
        w.u32(self.kvno);
        w.u32(self.mkvno);
        write_nullstring(w, self.policy.as_deref());
        w.i32(self.aux_attributes);
        w.u32(self.max_renewable_life);
        w.u32(self.last_success);
        w.u32(self.last_failed);
        w.u32(self.fail_auth_count);
        w.i32(len_i32(self.key_data.len()));
        w.i32(len_i32(self.tl_data.len()));
        write_tl_list(w, &self.tl_data);
        w.u32(u32::try_from(self.key_data.len()).unwrap_or(u32::MAX));
        for &(ver, kvno, t0, t1) in &self.key_data {
            w.i32(i32::from(ver as i16));
            w.u32(u32::from(kvno));
            w.i32(i32::from(t0));
            if ver > 1 {
                w.i32(i32::from(t1));
            }
        }
    }
}

/// `gprinc_ret`.
pub fn gprinc_ret(api_version: u32, code: u32, ent: Option<&PrincipalEnt>) -> Vec<u8> {
    let mut w = XdrWriter::default();
    w.u32(api_version);
    w.u32(code);
    if let (code::OK, Some(ent)) = (code, ent) {
        ent.encode(&mut w);
    }
    w.0
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Tok {
    Any,
    Star,
    Byte(u8),
    Set { negate: bool, items: Vec<SetItem> },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SetItem {
    Range(u8, u8),
    /// A POSIX `[:name:]` class, in the C locale.
    Class(&'static str),
}

impl SetItem {
    const CLASSES: [&'static str; 12] = [
        "alpha", "digit", "alnum", "upper", "lower", "space", "blank", "punct", "print", "graph",
        "cntrl", "xdigit",
    ];

    fn contains(self, c: u8) -> bool {
        match self {
            Self::Range(lo, hi) => lo <= c && c <= hi,
            Self::Class("alpha") => c.is_ascii_alphabetic(),
            Self::Class("digit") => c.is_ascii_digit(),
            Self::Class("alnum") => c.is_ascii_alphanumeric(),
            Self::Class("upper") => c.is_ascii_uppercase(),
            Self::Class("lower") => c.is_ascii_lowercase(),
            Self::Class("space") => matches!(c, b' ' | b'\t'..=b'\r'),
            Self::Class("blank") => matches!(c, b' ' | b'\t'),
            Self::Class("punct") => c.is_ascii_punctuation(),
            Self::Class("print") => (b' '..=b'~').contains(&c),
            Self::Class("graph") => c.is_ascii_graphic(),
            Self::Class("cntrl") => c.is_ascii_control(),
            Self::Class(_) => c.is_ascii_hexdigit(),
        }
    }

    fn class(name: &[u8]) -> Option<Self> {
        Self::CLASSES
            .into_iter()
            .find(|c| c.as_bytes() == name)
            .map(Self::Class)
    }
}

/// A `kadm5_get_principals` / `kadm5_get_policies` expression: the shell
/// glob `glob_to_regexp` (`svr_iters.c`) turns into an anchored POSIX
/// basic regular expression.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Glob(Vec<Tok>);

impl Glob {
    /// Compile `exp` (`None` is `*`); with `realm_default`, an expression
    /// without `@` matches any realm, as for principals. `None` where MIT
    /// returns `EINVAL` (a trailing `\` or an unterminated `[`).
    pub fn new(exp: Option<&str>, realm_default: bool) -> Option<Self> {
        let glob = exp.unwrap_or("*").as_bytes();
        if glob.last() == Some(&b'\\') {
            return None;
        }
        // `glob_to_regexp`: `.`, `^` and `$` are quoted even inside
        // brackets, so `[^...]` is a set containing `\` and `^`, not a
        // negation, exactly as MIT's `regcomp` sees it.
        let mut re = Vec::with_capacity(glob.len() * 2 + 3);
        let mut i = 0;
        while i < glob.len() {
            match glob[i] {
                b'?' => re.push(b'.'),
                b'*' => re.extend_from_slice(b".*"),
                c @ (b'.' | b'^' | b'$') => re.extend_from_slice(&[b'\\', c]),
                b'\\' => {
                    i += 1;
                    re.extend_from_slice(&[b'\\', glob[i]]);
                }
                c => re.push(c),
            }
            i += 1;
        }
        if realm_default && !glob.contains(&b'@') {
            re.extend_from_slice(b"@.*");
        }
        Self::compile(&re)
    }

    /// The anchored POSIX basic regular expression `glob_to_regexp` builds.
    /// `\X` is taken as a literal `X` (MIT's BRE would treat `\(`, `\{` and
    /// `\1`..`\9` as groups, intervals and back-references).
    fn compile(re: &[u8]) -> Option<Self> {
        let mut toks = Vec::new();
        let mut i = 0;
        while i < re.len() {
            match re[i] {
                b'\\' => {
                    toks.push(Tok::Byte(*re.get(i + 1)?));
                    i += 2;
                }
                b'.' if re.get(i + 1) == Some(&b'*') => {
                    toks.push(Tok::Star);
                    i += 2;
                }
                b'.' => {
                    toks.push(Tok::Any);
                    i += 1;
                }
                b'[' => {
                    let (tok, next) = Self::bracket(re, i + 1)?;
                    toks.push(tok);
                    i = next;
                }
                c => {
                    toks.push(Tok::Byte(c));
                    i += 1;
                }
            }
        }
        Some(Self(toks))
    }

    /// A POSIX bracket expression starting after `[` (`regcomp` in
    /// `svr_iters.c`); `None` for an unknown `[:class:]`.
    fn bracket(glob: &[u8], mut i: usize) -> Option<(Tok, usize)> {
        let negate = glob.get(i) == Some(&b'^');
        if negate {
            i += 1;
        }
        let mut items = Vec::new();
        let mut first = true;
        loop {
            let c = *glob.get(i)?;
            if c == b']' && !first {
                return Some((Tok::Set { negate, items }, i + 1));
            }
            first = false;
            if c == b'[' && glob.get(i + 1) == Some(&b':') {
                let name_start = i + 2;
                let len = glob[name_start..].windows(2).position(|w| w == b":]")?;
                items.push(SetItem::class(&glob[name_start..name_start + len])?);
                i = name_start + len + 2;
                continue;
            }
            match (glob.get(i + 1), glob.get(i + 2)) {
                (Some(b'-'), Some(&hi)) if hi != b']' => {
                    items.push(SetItem::Range(c, hi));
                    i += 3;
                }
                _ => {
                    items.push(SetItem::Range(c, c));
                    i += 1;
                }
            }
        }
    }

    /// Whether `name` matches, in O(pattern * name) time: every token but
    /// `*` consumes one byte, so on a mismatch only the latest `*` needs to
    /// absorb one more byte.
    pub fn matches(&self, name: &[u8]) -> bool {
        let one = |t: &Tok, c: u8| match t {
            Tok::Any => true,
            Tok::Byte(b) => *b == c,
            Tok::Set { negate, items } => items.iter().any(|i| i.contains(c)) != *negate,
            Tok::Star => false,
        };
        let toks = &self.0;
        let (mut t, mut n) = (0, 0);
        let mut star: Option<(usize, usize)> = None;
        while n < name.len() {
            if matches!(toks.get(t), Some(Tok::Star)) {
                star = Some((t, n));
                t += 1;
            } else if toks.get(t).is_some_and(|tok| one(tok, name[n])) {
                t += 1;
                n += 1;
            } else if let Some((st, sn)) = star {
                star = Some((st, sn + 1));
                t = st + 1;
                n = sn + 1;
            } else {
                return false;
            }
        }
        toks[t..].iter().all(|tok| matches!(tok, Tok::Star))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kdc::kdb::mit::KeyData;

    #[test]
    fn api_versions_are_checked_like_check_versions() {
        assert_eq!(check_api_version(API_VERSION_2), code::OK);
        assert_eq!(check_api_version(API_VERSION_4), code::OK);
        assert_eq!(
            check_api_version(API_VERSION_MASK | 5),
            code::NEW_SERVER_API_VERSION
        );
        assert_eq!(
            check_api_version(API_VERSION_MASK | 1),
            code::OLD_SERVER_API_VERSION
        );
        assert_eq!(check_api_version(4), code::BAD_API_VERSION);
    }

    #[test]
    fn error_codes_match_the_ovk_table() {
        // et/com_err: "ovk" hashes to 43787520; kadm5 clients print these.
        assert_eq!(code::FAILURE, 43_787_520);
        assert_eq!(code::UNK_PRINC, 43_787_532);
        assert_eq!(code::AUTH_LIST, 43_787_564);
    }

    #[test]
    fn nullstrings_round_trip_and_reject_non_c_strings() {
        let mut w = XdrWriter::default();
        write_nullstring(&mut w, Some(b"abc"));
        write_nullstring(&mut w, None);
        assert_eq!(w.0, [0, 0, 0, 4, b'a', b'b', b'c', 0, 0, 0, 0, 0]);
        let mut r = XdrReader::new(&w.0);
        assert_eq!(
            read_nullstring(&mut r).expect("abc").as_deref(),
            Some("abc")
        );
        assert_eq!(read_nullstring(&mut r).expect("null"), None);
        for bad in [
            &[0, 0, 0, 3, b'a', b'b', b'c', 0][..],
            &[0, 0, 0, 3, b'a', 0, b'c', 0],
        ] {
            assert!(read_nullstring(&mut XdrReader::new(bad)).is_err());
        }
    }

    #[test]
    fn read_args_decode_and_reject_trailing_bytes() {
        let mut w = XdrWriter::default();
        w.u32(API_VERSION_4);
        write_nullstring(&mut w, Some(b"alice"));
        w.i32(mask::PRINCIPAL_NORMAL_MASK);
        let args = ReadArgs::decode(proc_::GET_PRINCIPAL, &w.0)
            .expect("known")
            .expect("ok");
        assert_eq!(
            args,
            ReadArgs::GetPrincipal {
                api_version: API_VERSION_4,
                princ: Some("alice".into()),
                mask: mask::PRINCIPAL_NORMAL_MASK
            }
        );
        w.u32(0);
        assert!(ReadArgs::decode(proc_::GET_PRINCIPAL, &w.0)
            .expect("known")
            .is_err());
        assert!(ReadArgs::decode(proc_::CREATE_PRINCIPAL, &[]).is_none());
    }

    #[test]
    fn globs_follow_glob_to_regexp() {
        let g = |e: &str, realm: bool| Glob::new(Some(e), realm).expect("valid");
        assert!(g("*", true).matches(b"alice@R"));
        assert!(g("al?ce", true).matches(b"alice@R"));
        assert!(!g("alice", false).matches(b"alice@R"));
        assert!(g("alice@R", true).matches(b"alice@R"));
        assert!(!g("alice@R", true).matches(b"alice@S"));
        assert!(g("k[a-m]*/*", true).matches(b"kadmin/admin@R"));
        // MIT has no bracket negation: `^` is quoted into the set.
        assert!(g("k[^a-m]*", true).matches(b"kadmin/admin@R"));
        assert!(g("a\\*", false).matches(b"a*"));
        assert!(!g("a\\*", false).matches(b"ab"));
        assert!(g("a.b", false).matches(b"a.b") && !g("a.b", false).matches(b"axb"));
        assert!(g("[]x]", false).matches(b"]"));
        assert!(Glob::new(Some("a\\"), true).is_none());
        assert!(Glob::new(Some("[ab"), true).is_none());
        assert!(Glob::new(None, false).expect("star").matches(b"anything"));
    }

    #[test]
    fn glob_posix_classes_and_linear_time() {
        let g = |e: &str| Glob::new(Some(e), true);
        let digit = g("[[:digit:]]*").expect("valid");
        assert!(digit.matches(b"1alice@R"));
        assert!(!digit.matches(b"alice@R"));
        // MIT quotes `^` inside brackets too: a set of `\`, `^`, letters, `_`.
        let caret = g("[^[:alpha:]_]x").expect("valid");
        assert!(!caret.matches(b"9x@R"));
        for name in [&b"ax@R"[..], b"_x@R", b"^x@R", b"\\x@R"] {
            assert!(caret.matches(name));
        }
        let dot = g("[.]").expect("valid");
        assert!(dot.matches(b".@R") && dot.matches(b"\\@R") && !dot.matches(b"a@R"));
        assert!(g("[[:upper:]a-c]").expect("valid").matches(b"Q@R"));
        assert!(g("[[:bogus:]]").is_none());
        assert!(g("[[:digit:").is_none());
        let stars = g(&"*a".repeat(30)).expect("valid");
        assert!(!stars.matches(&[b'a'; 4000]));
        assert!(g("a*b*c").expect("valid").matches(b"aXbYbc@R"));
        assert!(!g("a*b*c").expect("valid").matches(b"aXbYb@R"));
    }

    fn entry() -> MitEntry {
        let adb = OsaPrincipalData {
            policy: Some(b"pol".to_vec()),
            aux_attributes: KADM5_POLICY,
            old_key_next: 0,
            admin_history_kvno: 0,
            old_keys: Vec::new(),
        };
        let mut mod_princ = 1_700_000_100u32.to_le_bytes().to_vec();
        mod_princ.extend_from_slice(b"admin@R\0");
        MitEntry {
            principal: crate::kdc::kdb::mit::parse_name(b"alice@R")
                .expect("name")
                .0,
            realm: "R".into(),
            attributes: 0x80,
            max_life: 36000,
            max_renewable_life: 0,
            expiration: 0,
            pw_expiration: 7,
            last_success: 5,
            last_failed: 6,
            fail_auth_count: 2,
            tl_data: vec![
                TlData {
                    kind: LAST_PWD_CHANGE,
                    data: 1_700_000_000u32.to_le_bytes().to_vec(),
                },
                TlData {
                    kind: MOD_PRINC,
                    data: mod_princ,
                },
                TlData {
                    kind: KADM_DATA,
                    data: adb.encode().expect("adb"),
                },
                TlData {
                    kind: 0x300,
                    data: b"x".to_vec(),
                },
            ],
            key_data: vec![
                KeyData {
                    ver: 2,
                    kvno: 3,
                    fields: vec![(18, vec![1; 16]), (0, Vec::new())],
                },
                KeyData {
                    ver: 1,
                    kvno: 2,
                    fields: vec![(17, vec![1; 16])],
                },
            ],
        }
    }

    #[test]
    fn principal_ent_follows_kadm5_get_principal() {
        let e = entry();
        let ent = PrincipalEnt::from_entry(&e, mask::PRINCIPAL_NORMAL_MASK, 1).expect("ent");
        assert_eq!(ent.principal.as_deref(), Some(&b"alice@R"[..]));
        assert_eq!(ent.last_pwd_change, 1_700_000_000);
        assert_eq!(ent.mod_date, 1_700_000_100);
        assert_eq!(ent.mod_name.as_deref(), Some(&b"admin@R"[..]));
        assert_eq!(ent.policy.as_deref(), Some(&b"pol"[..]));
        assert_eq!((ent.kvno, ent.mkvno), (3, 1));
        assert!(
            ent.tl_data.is_empty(),
            "KADM5_TL_DATA is not in the normal mask"
        );
        assert!(ent.key_data.is_empty(), "keys only with KADM5_KEY_DATA");
        let with_tl = PrincipalEnt::from_entry(&e, mask::TL_DATA, 1).expect("ent");
        assert_eq!(with_tl.tl_data.len(), 1, "only types above 255");
        let with_keys =
            PrincipalEnt::from_entry(&e, mask::PRINCIPAL_NORMAL_MASK | mask::KEY_DATA, 1)
                .expect("ent");
        assert_eq!(with_keys.key_data, [(2, 3, 18, 0), (1, 2, 17, 0)]);
        let bare = PrincipalEnt::from_entry(&e, mask::PRINCIPAL, 1).expect("ent");
        assert_eq!(bare.policy, None);
        assert_eq!(bare.mod_name, None);
    }

    #[test]
    fn principal_ent_wire_layout() {
        let ent =
            PrincipalEnt::from_entry(&entry(), mask::PRINCIPAL | mask::KEY_DATA, 1).expect("ent");
        let mut w = XdrWriter::default();
        ent.encode(&mut w);
        let mut r = XdrReader::new(&w.0);
        assert_eq!(
            read_nullstring(&mut r).expect("p").as_deref(),
            Some("alice@R")
        );
        for _ in 0..4 {
            r.u32().expect("times");
        }
        assert!(r.bool().expect("mod_name is null"));
        for _ in 0..4 {
            r.u32().expect("fields");
        }
        assert_eq!(read_nullstring(&mut r).expect("policy"), None);
        for _ in 0..5 {
            r.u32().expect("fields");
        }
        assert_eq!((r.i32().expect("n_key"), r.i32().expect("n_tl")), (2, 0));
        assert!(r.bool().expect("tl is null"));
        assert_eq!(r.u32().expect("array"), 2);
        assert_eq!(
            [r.i32(), r.i32(), r.i32(), r.i32()].map(|v| v.expect("k")),
            [2, 3, 18, 0]
        );
        assert_eq!(
            [r.i32(), r.i32(), r.i32()].map(|v| v.expect("k")),
            [1, 2, 17]
        );
        r.finish().expect("no trailing bytes");
    }

    #[test]
    fn policy_records_depend_on_the_api_version() {
        let p = MitPolicy {
            name: "p".into(),
            pw_min_life: 1,
            pw_max_life: 2,
            pw_min_length: 3,
            pw_min_classes: 4,
            pw_history_num: 5,
            pw_max_fail: 6,
            pw_failcnt_interval: 7,
            pw_lockout_duration: 8,
            attributes: 9,
            max_life: 10,
            max_renewable_life: 11,
            allowed_keysalts: None,
            tl_data: Vec::new(),
        };
        let v2 = gpol_ret(API_VERSION_2, 0, Some(&p));
        let v3 = gpol_ret(API_VERSION_3, 0, Some(&p));
        let v4 = gpol_ret(API_VERSION_4, 0, Some(&p));
        assert_eq!(v2.len(), 8 + 8 + 6 * 4);
        assert_eq!(v3.len(), v2.len() + 12);
        assert_eq!(v4.len(), v3.len() + 12 + 4 + 4 + 4);
        assert_eq!(gpol_ret(API_VERSION_4, code::UNK_POLICY, Some(&p)).len(), 8);
    }
}
