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
    pub const ENOMEM: u32 = 12;
    pub const EINVAL: u32 = 22;
    pub const FAILURE: u32 = BASE;
    pub const AUTH_GET: u32 = BASE + 1;
    pub const AUTH_ADD: u32 = BASE + 2;
    pub const AUTH_MODIFY: u32 = BASE + 3;
    pub const AUTH_DELETE: u32 = BASE + 4;
    pub const AUTH_INSUFFICIENT: u32 = BASE + 5;
    pub const BAD_DB: u32 = BASE + 6;
    pub const DUP: u32 = BASE + 7;
    pub const RPC_ERROR: u32 = BASE + 8;
    pub const NO_SRV: u32 = BASE + 9;
    pub const BAD_HIST_KEY: u32 = BASE + 10;
    pub const NOT_INIT: u32 = BASE + 11;
    pub const UNK_PRINC: u32 = BASE + 12;
    pub const UNK_POLICY: u32 = BASE + 13;
    pub const BAD_MASK: u32 = BASE + 14;
    pub const BAD_CLASS: u32 = BASE + 15;
    pub const BAD_LENGTH: u32 = BASE + 16;
    pub const BAD_POLICY: u32 = BASE + 17;
    pub const BAD_PRINCIPAL: u32 = BASE + 18;
    pub const BAD_AUX_ATTR: u32 = BASE + 19;
    pub const BAD_HISTORY: u32 = BASE + 20;
    pub const BAD_MIN_PASS_LIFE: u32 = BASE + 21;
    pub const PASS_Q_TOOSHORT: u32 = BASE + 22;
    pub const PASS_Q_CLASS: u32 = BASE + 23;
    pub const PASS_Q_DICT: u32 = BASE + 24;
    pub const PASS_REUSE: u32 = BASE + 25;
    pub const PASS_TOOSOON: u32 = BASE + 26;
    pub const POLICY_REF: u32 = BASE + 27;
    pub const INIT: u32 = BASE + 28;
    pub const BAD_PASSWORD: u32 = BASE + 29;
    pub const PROTECT_PRINCIPAL: u32 = BASE + 30;
    pub const BAD_SERVER_HANDLE: u32 = BASE + 31;
    pub const BAD_STRUCT_VERSION: u32 = BASE + 32;
    pub const OLD_STRUCT_VERSION: u32 = BASE + 33;
    pub const NEW_STRUCT_VERSION: u32 = BASE + 34;
    pub const BAD_API_VERSION: u32 = BASE + 35;
    pub const OLD_LIB_API_VERSION: u32 = BASE + 36;
    pub const OLD_SERVER_API_VERSION: u32 = BASE + 37;
    pub const NEW_LIB_API_VERSION: u32 = BASE + 38;
    pub const NEW_SERVER_API_VERSION: u32 = BASE + 39;
    pub const SECURE_PRINC_MISSING: u32 = BASE + 40;
    pub const NO_RENAME_SALT: u32 = BASE + 41;
    pub const BAD_CLIENT_PARAMS: u32 = BASE + 42;
    pub const BAD_SERVER_PARAMS: u32 = BASE + 43;
    pub const AUTH_LIST: u32 = BASE + 44;
    pub const AUTH_CHANGEPW: u32 = BASE + 45;
    pub const GSS_ERROR: u32 = BASE + 46;
    pub const BAD_TL_TYPE: u32 = BASE + 47;
    pub const MISSING_CONF_PARAMS: u32 = BASE + 48;
    pub const BAD_SERVER_NAME: u32 = BASE + 49;
    pub const AUTH_SETKEY: u32 = BASE + 50;
    pub const SETKEY_DUP_ENCTYPES: u32 = BASE + 51;
    pub const SETV4KEY_INVAL_ENCTYPE: u32 = BASE + 52;
    pub const SETKEY3_ETYPE_MISMATCH: u32 = BASE + 53;
    pub const MISSING_KRB5_CONF_PARAMS: u32 = BASE + 54;
    pub const XDR_FAILURE: u32 = BASE + 55;
    pub const CANT_RESOLVE: u32 = BASE + 56;
    pub const PASS_Q_GENERIC: u32 = BASE + 57;
    pub const BAD_KEYSALTS: u32 = BASE + 58;
    pub const SETKEY_BAD_KVNO: u32 = BASE + 59;
    pub const AUTH_EXTRACT: u32 = BASE + 60;
    pub const PROTECT_KEYS: u32 = BASE + 61;
    pub const AUTH_INITIAL: u32 = BASE + 62;
    pub const ALIAS_REALM: u32 = BASE + 63;

    const MESSAGES: [&str; 64] = [
        "Operation failed for unspecified reason",
        "Operation requires ``get'' privilege",
        "Operation requires ``add'' privilege",
        "Operation requires ``modify'' privilege",
        "Operation requires ``delete'' privilege",
        "Insufficient authorization for operation",
        "Database inconsistency detected",
        "Principal or policy already exists",
        "Communication failure with server",
        "No administration server found for realm",
        "Password history entry (kadmin/history) contains unsupported key type",
        "Connection to server not initialized",
        "Principal does not exist",
        "Policy does not exist",
        "Invalid field mask for operation",
        "Invalid number of character classes",
        "Invalid password length",
        "Illegal policy name",
        "Illegal principal name",
        "Invalid auxiliary attributes",
        "Invalid password history count",
        "Password minimum life is greater than password maximum life",
        "Password is too short",
        "Password does not contain enough character classes",
        "Password is in the password dictionary",
        "Cannot reuse password",
        "Current password's minimum life has not expired",
        "Policy is in use",
        "Connection to server already initialized",
        "Incorrect password",
        "Cannot change protected principal",
        "Programmer error!  Bad Admin server handle",
        "Programmer error!  Bad API structure version",
        "API structure version specified by application is no longer supported (to fix, recompile application against current KADM5 API header files and libraries)",
        "API structure version specified by application is unknown to libraries (to fix, obtain current KADM5 API header files and libraries and recompile application)",
        "Programmer error!  Bad API version",
        "API version specified by application is no longer supported by libraries (to fix, update application to adhere to current API version and recompile)",
        "API version specified by application is no longer supported by server (to fix, update application to adhere to current API version and recompile)",
        "API version specified by application is unknown to libraries (to fix, obtain current KADM5 API header files and libraries and recompile application)",
        "API version specified by application is unknown to server (to fix, obtain and install newest KADM5 Admin Server)",
        "Database error! Required KADM5 principal missing",
        "The salt type of the specified principal does not support renaming",
        "Illegal configuration parameter for remote KADM5 client",
        "Illegal configuration parameter for local KADM5 client",
        "Operation requires ``list'' privilege",
        "Operation requires ``change-password'' privilege",
        "GSS-API (or Kerberos) error",
        "Programmer error!  Illegal tagged data list type",
        "Required parameters in kdc.conf missing",
        "Bad krb5 admin server hostname",
        "Operation requires ``set-key'' privilege",
        "Multiple values for single or folded enctype",
        "Invalid enctype for setv4key",
        "Mismatched enctypes for setkey3",
        "Missing parameters in krb5.conf required for kadmin client",
        "XDR encoding error",
        "Cannot resolve network address for admin server in requested realm",
        "Unspecified password quality failure",
        "Invalid key/salt tuples",
        "Invalid multiple or duplicate kvnos in setkey operation",
        "Operation requires ``extract-keys'' privilege",
        "Principal keys are locked down",
        "Operation requires initial ticket",
        "Alias target must be within the same realm",
    ];

    /// The `kadm_err.et` text for `code`, as kadmind logs it.
    pub fn message(code: u32) -> String {
        match code {
            ENOMEM => "Cannot allocate memory".into(),
            EINVAL => "Invalid argument".into(),
            _ => code
                .checked_sub(BASE)
                .and_then(|i| MESSAGES.get(i as usize))
                .map_or_else(|| format!("error {code}"), |m| (*m).to_string()),
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
    pub const POLICY_CLR: i32 = 0x00_1000;
    pub const KEY_HIST: i32 = 0x40_0000;
    /// `ALL_PRINC_MASK` (`server_internal.h`).
    pub const ALL_PRINC_MASK: i32 = PRINCIPAL
        | PRINC_EXPIRE_TIME
        | PW_EXPIRATION
        | LAST_PWD_CHANGE
        | ATTRIBUTES
        | MAX_LIFE
        | MOD_TIME
        | MOD_NAME
        | KVNO
        | MKVNO
        | AUX_ATTRIBUTES
        | POLICY_CLR
        | POLICY
        | MAX_RLIFE
        | TL_DATA
        | KEY_DATA
        | FAIL_AUTH_COUNT;
    pub const PW_MAX_LIFE: i32 = 0x0000_4000;
    pub const PW_MIN_LIFE: i32 = 0x0000_8000;
    pub const PW_MIN_LENGTH: i32 = 0x0001_0000;
    pub const PW_MIN_CLASSES: i32 = 0x0002_0000;
    pub const PW_HISTORY_NUM: i32 = 0x0004_0000;
    pub const REF_COUNT: i32 = 0x0008_0000;
    pub const PW_MAX_FAILURE: i32 = 0x0010_0000;
    pub const PW_FAILURE_COUNT_INTERVAL: i32 = 0x0020_0000;
    pub const PW_LOCKOUT_DURATION: i32 = 0x0040_0000;
    pub const POLICY_ATTRIBUTES: i32 = 0x0080_0000;
    pub const POLICY_MAX_LIFE: i32 = 0x0100_0000;
    pub const POLICY_MAX_RLIFE: i32 = 0x0200_0000;
    pub const POLICY_ALLOWED_KEYSALTS: i32 = 0x0400_0000;
    pub const POLICY_TL_DATA: i32 = 0x0800_0000;
    /// `ALL_POLICY_MASK` (`server_internal.h`).
    pub const ALL_POLICY_MASK: i32 = POLICY
        | PW_MAX_LIFE
        | PW_MIN_LIFE
        | PW_MIN_LENGTH
        | PW_MIN_CLASSES
        | PW_HISTORY_NUM
        | REF_COUNT
        | PW_MAX_FAILURE
        | PW_FAILURE_COUNT_INTERVAL
        | PW_LOCKOUT_DURATION
        | POLICY_ATTRIBUTES
        | POLICY_MAX_LIFE
        | POLICY_MAX_RLIFE
        | POLICY_ALLOWED_KEYSALTS
        | POLICY_TL_DATA;
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

enum BracketAtom {
    Byte(u8),
    Item(SetItem),
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
    fn bracket(re: &[u8], mut i: usize) -> Option<(Tok, usize)> {
        let negate = re.get(i) == Some(&b'^');
        if negate {
            i += 1;
        }
        // glibc `regcomp` rejects a `-` that would start a range right after
        // a range (`[a-c-z]`) or from or to a class (`[[:digit:]-a]`), and a
        // reversed range (`[z-a]`); a `-` before `]` is literal.
        let range_dash = |re: &[u8], i: usize| {
            re.get(i) == Some(&b'-') && re.get(i + 1).is_some_and(|&c| c != b']')
        };
        let mut items = Vec::new();
        let mut first = true;
        loop {
            if re.get(i) == Some(&b']') && !first {
                return Some((Tok::Set { negate, items }, i + 1));
            }
            first = false;
            let (atom, next) = Self::bracket_atom(re, i)?;
            i = next;
            if !range_dash(re, i) {
                items.push(match atom {
                    BracketAtom::Byte(b) => SetItem::Range(b, b),
                    BracketAtom::Item(item) => item,
                });
                continue;
            }
            let BracketAtom::Byte(lo) = atom else {
                return None;
            };
            let (BracketAtom::Byte(hi), next) = Self::bracket_atom(re, i + 1)? else {
                return None;
            };
            if hi < lo || range_dash(re, next) {
                return None;
            }
            items.push(SetItem::Range(lo, hi));
            i = next;
        }
    }

    /// One bracket member: `[:class:]`, `[=c=]` (neither may bound a range),
    /// `[.c.]` or a byte. Only single-byte collating elements exist in the
    /// C locale.
    fn bracket_atom(re: &[u8], i: usize) -> Option<(BracketAtom, usize)> {
        let c = *re.get(i)?;
        let delim = match re.get(i + 1) {
            Some(&d @ (b':' | b'.' | b'=')) if c == b'[' => d,
            _ => return Some((BracketAtom::Byte(c), i + 1)),
        };
        let start = i + 2;
        let len = re
            .get(start..)?
            .windows(2)
            .position(|w| w == [delim, b']'])?;
        let name = &re[start..start + len];
        let atom = match (delim, name) {
            (b':', _) => BracketAtom::Item(SetItem::class(name)?),
            (b'.', &[b]) => BracketAtom::Byte(b),
            (b'=', &[b]) => BracketAtom::Item(SetItem::Range(b, b)),
            _ => return None,
        };
        Some((atom, start + len + 2))
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

fn read_count(r: &mut XdrReader<'_>) -> Result<usize, XdrError> {
    let n = usize::try_from(r.u32()?).map_err(|_| XdrError("length"))?;
    // Every element takes at least four bytes.
    if n > r.remaining() / 4 {
        return Err(XdrError("array length"));
    }
    Ok(n)
}

fn read_array<T>(
    r: &mut XdrReader<'_>,
    mut f: impl FnMut(&mut XdrReader<'_>) -> Result<T, XdrError>,
) -> Result<Vec<T>, XdrError> {
    let n = read_count(r)?;
    (0..n).map(|_| f(r)).collect()
}

/// `xdr_krb5_int16`: an XDR int that must fit in 16 bits.
fn read_i16(r: &mut XdrReader<'_>) -> Result<i16, XdrError> {
    i16::try_from(r.i32()?).map_err(|_| XdrError("int16"))
}

/// `xdr_krb5_tl_data` behind `xdr_nulltype`.
fn read_tl_list(r: &mut XdrReader<'_>) -> Result<Vec<TlData>, XdrError> {
    let mut out = Vec::new();
    if r.bool()? {
        return Ok(out);
    }
    while r.bool()? {
        let kind = read_i16(r)? as u16;
        let data = r.opaque()?.to_vec();
        out.push(TlData { kind, data });
    }
    Ok(out)
}

impl PrincipalEnt {
    /// `_xdr_kadm5_principal_ent_rec` decoding.
    pub fn decode(r: &mut XdrReader<'_>) -> Result<Self, XdrError> {
        let principal = read_nullstring(r)?.map(String::into_bytes);
        let princ_expire_time = r.u32()?;
        let last_pwd_change = r.u32()?;
        let pw_expiration = r.u32()?;
        let max_life = r.u32()?;
        let mod_name = if r.bool()? {
            None
        } else {
            read_nullstring(r)?.map(String::into_bytes)
        };
        let mod_date = r.u32()?;
        let attributes = r.u32()?;
        let kvno = r.u32()?;
        let mkvno = r.u32()?;
        let policy = read_nullstring(r)?.map(String::into_bytes);
        let aux_attributes = r.i32()?;
        let max_renewable_life = r.u32()?;
        let last_success = r.u32()?;
        let last_failed = r.u32()?;
        let fail_auth_count = r.u32()?;
        let n_key_data = read_i16(r)?;
        if n_key_data < 0 {
            return Err(XdrError("n_key_data"));
        }
        let _n_tl_data = read_i16(r)?;
        let tl_data = read_tl_list(r)?;
        let key_data = read_array(r, |r| {
            let ver = read_i16(r)?;
            let kvno = u16::try_from(r.u32()?).map_err(|_| XdrError("ui_2"))?;
            let t0 = read_i16(r)?;
            let t1 = if ver > 1 { read_i16(r)? } else { 0 };
            Ok((ver as u16, kvno, t0, t1))
        })?;
        if key_data.len() != n_key_data as usize {
            return Err(XdrError("key_data count"));
        }
        Ok(Self {
            principal,
            princ_expire_time,
            last_pwd_change,
            pw_expiration,
            max_life,
            mod_name,
            mod_date,
            attributes,
            kvno,
            mkvno,
            policy,
            aux_attributes,
            max_renewable_life,
            last_success,
            last_failed,
            fail_auth_count,
            tl_data,
            key_data,
        })
    }

    /// The principal as a string (decoding already checked it is UTF-8).
    pub fn principal_str(&self) -> Option<&str> {
        self.principal
            .as_deref()
            .and_then(|p| std::str::from_utf8(p).ok())
    }

    /// The policy as a string.
    pub fn policy_str(&self) -> Option<&str> {
        self.policy
            .as_deref()
            .and_then(|p| std::str::from_utf8(p).ok())
    }
}

/// A `kadm5_policy_ent_rec` as the client sends it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[allow(missing_docs)]
pub struct PolicyEnt {
    pub policy: Option<String>,
    pub pw_min_life: i32,
    pub pw_max_life: i32,
    pub pw_min_length: i32,
    pub pw_min_classes: i32,
    pub pw_history_num: i32,
    pub policy_refcnt: i32,
    pub pw_max_fail: u32,
    pub pw_failcnt_interval: i32,
    pub pw_lockout_duration: i32,
    pub attributes: u32,
    pub max_life: i32,
    pub max_renewable_life: i32,
    pub allowed_keysalts: Option<String>,
    pub tl_data: Vec<TlData>,
}

impl PolicyEnt {
    /// `_xdr_kadm5_policy_ent_rec` decoding at `api_version`.
    pub fn decode(r: &mut XdrReader<'_>, api_version: u32) -> Result<Self, XdrError> {
        let mut p = Self {
            policy: read_nullstring(r)?,
            pw_min_life: r.i32()?,
            pw_max_life: r.i32()?,
            pw_min_length: r.i32()?,
            pw_min_classes: r.i32()?,
            pw_history_num: r.i32()?,
            policy_refcnt: r.i32()?,
            ..Self::default()
        };
        if api_version >= API_VERSION_3 {
            p.pw_max_fail = r.u32()?;
            p.pw_failcnt_interval = r.i32()?;
            p.pw_lockout_duration = r.i32()?;
        }
        if api_version >= API_VERSION_4 {
            p.attributes = r.u32()?;
            p.max_life = r.i32()?;
            p.max_renewable_life = r.i32()?;
            p.allowed_keysalts = read_nullstring(r)?;
            let _n_tl_data = read_i16(r)?;
            p.tl_data = read_tl_list(r)?;
        }
        Ok(p)
    }
}

/// `krb5_keyblock` on the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyBlock {
    /// `enctype`.
    pub enctype: i32,
    /// `contents`.
    pub contents: Vec<u8>,
}

impl KeyBlock {
    fn decode(r: &mut XdrReader<'_>) -> Result<Self, XdrError> {
        Ok(Self {
            enctype: r.i32()?,
            contents: r.opaque()?.to_vec(),
        })
    }

    fn encode(&self, w: &mut XdrWriter) {
        w.i32(self.enctype);
        w.opaque(&self.contents);
    }
}

/// `kadm5_key_data` on the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyData {
    /// `kvno`.
    pub kvno: u32,
    /// `key`.
    pub key: KeyBlock,
    /// `salt.type`.
    pub salt_type: i16,
    /// `salt.data`.
    pub salt: Vec<u8>,
}

impl KeyData {
    fn decode(r: &mut XdrReader<'_>) -> Result<Self, XdrError> {
        Ok(Self {
            kvno: r.u32()?,
            key: KeyBlock::decode(r)?,
            salt_type: read_i16(r)?,
            salt: r.opaque()?.to_vec(),
        })
    }

    fn encode(&self, w: &mut XdrWriter) {
        w.u32(self.kvno);
        self.key.encode(w);
        w.i32(i32::from(self.salt_type));
        w.opaque(&self.salt);
    }
}

/// `krb5_key_salt_tuple`: (enctype, salttype).
pub type KeySalt = (i32, i32);

fn read_ks(r: &mut XdrReader<'_>) -> Result<Vec<KeySalt>, XdrError> {
    read_array(r, |r| Ok((r.i32()?, r.i32()?)))
}

/// The keys of the three setkey calls.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SetKeys {
    /// `setkey_arg`: one keyblock per enctype, default salt.
    V1(Vec<KeyBlock>),
    /// `setkey3_arg`: keyblocks paired with key/salt tuples.
    V3(Vec<KeySalt>, Vec<KeyBlock>),
    /// `setkey4_arg`: full key data.
    V4(Vec<KeyData>),
}

/// The arguments of the calls that change the database.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum WriteArgs {
    /// `cprinc_arg` (`ks_tuple` `None`) and `cprinc3_arg`.
    CreatePrincipal {
        api_version: u32,
        rec: Box<PrincipalEnt>,
        mask: i32,
        ks_tuple: Option<Vec<KeySalt>>,
        passwd: Option<String>,
    },
    /// `dprinc_arg`.
    DeletePrincipal {
        api_version: u32,
        princ: Option<String>,
    },
    /// `mprinc_arg`.
    ModifyPrincipal {
        api_version: u32,
        rec: Box<PrincipalEnt>,
        mask: i32,
    },
    /// `rprinc_arg`.
    RenamePrincipal {
        api_version: u32,
        src: Option<String>,
        dest: Option<String>,
    },
    /// `chpass_arg` (`v3` false) and `chpass3_arg`.
    ChpassPrincipal {
        api_version: u32,
        princ: Option<String>,
        v3: bool,
        keepold: bool,
        ks_tuple: Vec<KeySalt>,
        pass: Option<String>,
    },
    /// `chrand_arg` (`v3` false) and `chrand3_arg`.
    ChrandPrincipal {
        api_version: u32,
        princ: Option<String>,
        v3: bool,
        keepold: bool,
        ks_tuple: Vec<KeySalt>,
    },
    /// `setkey_arg`, `setkey3_arg`, `setkey4_arg`.
    SetkeyPrincipal {
        api_version: u32,
        princ: Option<String>,
        keepold: bool,
        keys: SetKeys,
    },
    /// `cpol_arg`.
    CreatePolicy {
        api_version: u32,
        rec: Box<PolicyEnt>,
        mask: i32,
    },
    /// `dpol_arg`.
    DeletePolicy {
        api_version: u32,
        name: Option<String>,
    },
    /// `mpol_arg`.
    ModifyPolicy {
        api_version: u32,
        rec: Box<PolicyEnt>,
        mask: i32,
    },
    /// `purgekeys_arg`.
    Purgekeys {
        api_version: u32,
        princ: Option<String>,
        keepkvno: i32,
    },
    /// `sstring_arg`.
    SetString {
        api_version: u32,
        princ: Option<String>,
        key: Option<String>,
        value: Option<String>,
    },
    /// `getpkeys_arg`.
    ExtractKeys {
        api_version: u32,
        princ: Option<String>,
        kvno: u32,
    },
    /// `calias_arg`.
    CreateAlias {
        api_version: u32,
        alias: Option<String>,
        target: Option<String>,
    },
}

impl WriteArgs {
    /// Decode the arguments of `proc_`; `None` for other procedures.
    pub fn decode(proc_: u32, args: &[u8]) -> Option<Result<Self, XdrError>> {
        if !Self::handles(proc_) {
            return None;
        }
        let mut r = XdrReader::new(args);
        Some(Self::decode_body(proc_, &mut r).and_then(|a| r.finish().map(|()| a)))
    }

    fn decode_body(proc_: u32, r: &mut XdrReader<'_>) -> Result<Self, XdrError> {
        let ns = read_nullstring;
        let v = r.u32()?;
        {
            Ok(match proc_ {
                proc_::CREATE_PRINCIPAL | proc_::CREATE_PRINCIPAL3 => {
                    let rec = Box::new(PrincipalEnt::decode(r)?);
                    let mask = r.i32()?;
                    let ks_tuple = if proc_ == proc_::CREATE_PRINCIPAL3 {
                        Some(read_ks(r)?)
                    } else {
                        None
                    };
                    Self::CreatePrincipal {
                        api_version: v,
                        rec,
                        mask,
                        ks_tuple,
                        passwd: ns(r)?,
                    }
                }
                proc_::DELETE_PRINCIPAL => Self::DeletePrincipal {
                    api_version: v,
                    princ: ns(r)?,
                },
                proc_::MODIFY_PRINCIPAL => Self::ModifyPrincipal {
                    api_version: v,
                    rec: Box::new(PrincipalEnt::decode(r)?),
                    mask: r.i32()?,
                },
                proc_::RENAME_PRINCIPAL => Self::RenamePrincipal {
                    api_version: v,
                    src: ns(r)?,
                    dest: ns(r)?,
                },
                proc_::CHPASS_PRINCIPAL => Self::ChpassPrincipal {
                    api_version: v,
                    princ: ns(r)?,
                    v3: false,
                    keepold: false,
                    ks_tuple: Vec::new(),
                    pass: ns(r)?,
                },
                proc_::CHPASS_PRINCIPAL3 => Self::ChpassPrincipal {
                    api_version: v,
                    princ: ns(r)?,
                    v3: true,
                    keepold: r.bool()?,
                    ks_tuple: read_ks(r)?,
                    pass: ns(r)?,
                },
                proc_::CHRAND_PRINCIPAL => Self::ChrandPrincipal {
                    api_version: v,
                    princ: ns(r)?,
                    v3: false,
                    keepold: false,
                    ks_tuple: Vec::new(),
                },
                proc_::CHRAND_PRINCIPAL3 => Self::ChrandPrincipal {
                    api_version: v,
                    princ: ns(r)?,
                    v3: true,
                    keepold: r.bool()?,
                    ks_tuple: read_ks(r)?,
                },
                proc_::SETKEY_PRINCIPAL => Self::SetkeyPrincipal {
                    api_version: v,
                    princ: ns(r)?,
                    keepold: false,
                    keys: SetKeys::V1(read_array(r, KeyBlock::decode)?),
                },
                proc_::SETKEY_PRINCIPAL3 => {
                    let princ = ns(r)?;
                    let keepold = r.bool()?;
                    let ks = read_ks(r)?;
                    Self::SetkeyPrincipal {
                        api_version: v,
                        princ,
                        keepold,
                        keys: SetKeys::V3(ks, read_array(r, KeyBlock::decode)?),
                    }
                }
                proc_::SETKEY_PRINCIPAL4 => Self::SetkeyPrincipal {
                    api_version: v,
                    princ: ns(r)?,
                    keepold: r.bool()?,
                    keys: SetKeys::V4(read_array(r, KeyData::decode)?),
                },
                proc_::CREATE_POLICY | proc_::MODIFY_POLICY => {
                    let rec = Box::new(PolicyEnt::decode(r, v)?);
                    let mask = r.i32()?;
                    if proc_ == proc_::CREATE_POLICY {
                        Self::CreatePolicy {
                            api_version: v,
                            rec,
                            mask,
                        }
                    } else {
                        Self::ModifyPolicy {
                            api_version: v,
                            rec,
                            mask,
                        }
                    }
                }
                proc_::DELETE_POLICY => Self::DeletePolicy {
                    api_version: v,
                    name: ns(r)?,
                },
                proc_::PURGEKEYS => Self::Purgekeys {
                    api_version: v,
                    princ: ns(r)?,
                    keepkvno: r.i32()?,
                },
                proc_::SET_STRING => Self::SetString {
                    api_version: v,
                    princ: ns(r)?,
                    key: ns(r)?,
                    value: ns(r)?,
                },
                proc_::EXTRACT_KEYS => Self::ExtractKeys {
                    api_version: v,
                    princ: ns(r)?,
                    kvno: r.u32()?,
                },
                proc_::CREATE_ALIAS => Self::CreateAlias {
                    api_version: v,
                    alias: ns(r)?,
                    target: ns(r)?,
                },
                _ => return Err(XdrError("unknown")),
            })
        }
    }

    /// Whether `proc_` is one of these calls.
    pub fn handles(proc_: u32) -> bool {
        matches!(
            proc_,
            proc_::CREATE_PRINCIPAL
                | proc_::DELETE_PRINCIPAL
                | proc_::MODIFY_PRINCIPAL
                | proc_::RENAME_PRINCIPAL
                | proc_::CHPASS_PRINCIPAL
                | proc_::CHRAND_PRINCIPAL
                | proc_::CREATE_POLICY
                | proc_::DELETE_POLICY
                | proc_::MODIFY_POLICY
                | proc_::SETKEY_PRINCIPAL
                | proc_::CREATE_PRINCIPAL3
                | proc_::CHPASS_PRINCIPAL3
                | proc_::CHRAND_PRINCIPAL3
                | proc_::SETKEY_PRINCIPAL3
                | proc_::PURGEKEYS
                | proc_::SET_STRING
                | proc_::SETKEY_PRINCIPAL4
                | proc_::EXTRACT_KEYS
                | proc_::CREATE_ALIAS
        )
    }

    /// The principal names the arguments carry, which `xdr_krb5_principal`
    /// parses (a name `krb5_parse_name` rejects fails decoding).
    pub fn principals(&self) -> Vec<&str> {
        let mut v: Vec<Option<&str>> = Vec::new();
        match self {
            Self::CreatePrincipal { rec, .. } | Self::ModifyPrincipal { rec, .. } => {
                v.push(rec.principal_str());
                if let Some(m) = rec.mod_name.as_deref() {
                    v.push(std::str::from_utf8(m).ok());
                }
            }
            Self::RenamePrincipal { src, dest, .. } => {
                v.extend([src.as_deref(), dest.as_deref()]);
            }
            Self::CreateAlias { alias, target, .. } => {
                v.extend([alias.as_deref(), target.as_deref()]);
            }
            Self::DeletePrincipal { princ, .. }
            | Self::ChpassPrincipal { princ, .. }
            | Self::ChrandPrincipal { princ, .. }
            | Self::SetkeyPrincipal { princ, .. }
            | Self::Purgekeys { princ, .. }
            | Self::SetString { princ, .. }
            | Self::ExtractKeys { princ, .. } => v.push(princ.as_deref()),
            Self::CreatePolicy { .. } | Self::DeletePolicy { .. } | Self::ModifyPolicy { .. } => {}
        }
        v.into_iter().flatten().collect()
    }

    /// `api_version`.
    pub fn api_version(&self) -> u32 {
        match self {
            Self::CreatePrincipal { api_version, .. }
            | Self::DeletePrincipal { api_version, .. }
            | Self::ModifyPrincipal { api_version, .. }
            | Self::RenamePrincipal { api_version, .. }
            | Self::ChpassPrincipal { api_version, .. }
            | Self::ChrandPrincipal { api_version, .. }
            | Self::SetkeyPrincipal { api_version, .. }
            | Self::CreatePolicy { api_version, .. }
            | Self::DeletePolicy { api_version, .. }
            | Self::ModifyPolicy { api_version, .. }
            | Self::Purgekeys { api_version, .. }
            | Self::SetString { api_version, .. }
            | Self::ExtractKeys { api_version, .. }
            | Self::CreateAlias { api_version, .. } => *api_version,
        }
    }
}

/// `chrand_ret`: the new keys follow only on success.
pub fn chrand_ret(api_version: u32, code: u32, keys: &[KeyBlock]) -> Vec<u8> {
    let mut w = XdrWriter::default();
    w.u32(api_version);
    w.u32(code);
    if code == code::OK {
        w.u32(u32::try_from(keys.len()).unwrap_or(u32::MAX));
        for k in keys {
            k.encode(&mut w);
        }
    }
    w.0
}

/// `getpkeys_ret`: the key data follows only on success.
pub fn getpkeys_ret(api_version: u32, code: u32, keys: &[KeyData]) -> Vec<u8> {
    let mut w = XdrWriter::default();
    w.u32(api_version);
    w.u32(code);
    if code == code::OK {
        w.u32(u32::try_from(keys.len()).unwrap_or(u32::MAX));
        for k in keys {
            k.encode(&mut w);
        }
    }
    w.0
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
    fn write_args_reject_malformed_xdr() {
        assert!(WriteArgs::decode(proc_::GET_PRINCIPAL, &[]).is_none());
        let mut w = XdrWriter::default();
        w.u32(API_VERSION_4);
        write_nullstring(&mut w, Some(b"old"));
        write_nullstring(&mut w, Some(b"new"));
        let args = WriteArgs::decode(proc_::RENAME_PRINCIPAL, &w.0)
            .expect("known")
            .expect("ok");
        assert_eq!(
            args,
            WriteArgs::RenamePrincipal {
                api_version: API_VERSION_4,
                src: Some("old".into()),
                dest: Some("new".into()),
            }
        );
        let mut trailing = w.0.clone();
        trailing.extend_from_slice(&[0, 0, 0, 0]);
        assert!(WriteArgs::decode(proc_::RENAME_PRINCIPAL, &trailing)
            .expect("known")
            .is_err());
        for len in 0..w.0.len() {
            assert!(
                WriteArgs::decode(proc_::RENAME_PRINCIPAL, &w.0[..len])
                    .expect("known")
                    .is_err(),
                "truncated to {len}"
            );
        }
        for p in [
            proc_::CREATE_PRINCIPAL,
            proc_::CREATE_PRINCIPAL3,
            proc_::MODIFY_PRINCIPAL,
            proc_::CHPASS_PRINCIPAL3,
            proc_::CHRAND_PRINCIPAL3,
            proc_::SETKEY_PRINCIPAL,
            proc_::SETKEY_PRINCIPAL3,
            proc_::SETKEY_PRINCIPAL4,
            proc_::CREATE_POLICY,
            proc_::MODIFY_POLICY,
            proc_::PURGEKEYS,
            proc_::SET_STRING,
            proc_::EXTRACT_KEYS,
            proc_::CREATE_ALIAS,
        ] {
            let mut w = XdrWriter::default();
            w.u32(API_VERSION_4);
            assert!(
                WriteArgs::decode(p, &w.0).expect("known").is_err(),
                "proc {p}"
            );
        }
        // A key array longer than the remaining bytes is refused.
        let mut w = XdrWriter::default();
        w.u32(API_VERSION_4);
        write_nullstring(&mut w, Some(b"p"));
        w.u32(0x7fff_ffff);
        assert!(WriteArgs::decode(proc_::SETKEY_PRINCIPAL, &w.0)
            .expect("known")
            .is_err());
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
        for bad in [
            "[[:digit:]-a]",
            "[a-[:digit:]]",
            "[z-a]",
            "[a-c-z]",
            "[[=a=]-c]",
        ] {
            assert!(g(bad).is_none(), "{bad}");
        }
        let h = |e: &str| Glob::new(Some(e), false).expect("valid");
        assert!(h("[[:digit:]-]").matches(b"-") && h("[[:digit:]-]").matches(b"7"));
        assert!(h("[a-]").matches(b"-") && h("[-a]").matches(b"-"));
        assert!(h("[]-a]").matches(b"]") && h("[]-a]").matches(b"_"));
        assert!(h("[[=a=]]").matches(b"a") && !h("[[=a=]]").matches(b"b"));
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
