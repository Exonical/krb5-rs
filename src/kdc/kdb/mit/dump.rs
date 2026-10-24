//! MIT `kdb5_util dump`/`load` text format (`kadmin/dbutil/dump.c`).

use std::io::Write;

use super::{parse_name, unparse_name, KeyData, MitEntry, MitPolicy, TlData, KADM_DATA};

/// `KRB5_KDB_V1_BASE_LENGTH` (`include/kdb.h:245`), set by klmdb's decoder
/// (`plugins/kdb/lmdb/marshal.c:243`).
const BASE_LENGTH: u32 = 38;
/// `KRB5_KDB_MAX_ALLOWED_KS_LEN` (`include/kdb.h:247`).
const MAX_ALLOWED_KS_LEN: usize = 512;

/// A dump format (`dump.c:1001-1043`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DumpVersion {
    /// `-b7`: no policy reference tl-data, short policies.
    Beta7,
    /// `-r13`.
    R13,
    /// `-r18`: lockout policy fields.
    R18,
    /// The 1.11+ default.
    R111,
}

impl DumpVersion {
    /// The header line, including its newline.
    pub fn header(self) -> &'static str {
        match self {
            Self::Beta7 => "kdb5_util load_dump version 4\n",
            Self::R13 => "kdb5_util load_dump version 5\n",
            Self::R18 => "kdb5_util load_dump version 6\n",
            Self::R111 => "kdb5_util load_dump version 7\n",
        }
    }

    /// The name MIT prints in errors.
    pub fn name(self) -> &'static str {
        match self {
            Self::Beta7 => "Kerberos version 5",
            Self::R13 => "Kerberos version 5 release 1.3",
            Self::R18 => "Kerberos version 5 release 1.8",
            Self::R111 => "Kerberos version 5 release 1.11",
        }
    }

    /// Auto-detect from a header line (`dump.c:1450-1464`).
    pub fn from_header(line: &[u8]) -> Option<Self> {
        [Self::Beta7, Self::R13, Self::R18, Self::R111]
            .into_iter()
            .find(|v| v.header().as_bytes() == line)
    }
}

/// `dump_octets_or_minus1` (`dump.c:260-270`).
fn octets(out: &mut Vec<u8>, data: &[u8]) {
    if data.is_empty() {
        out.extend_from_slice(b"-1");
    }
    for byte in data {
        let _ = write!(out, "{byte:02x}");
    }
}

/// `dump_tl_data` (`dump.c:278-289`).
fn tl_list(out: &mut Vec<u8>, tl_data: &[TlData], filter_kadm: bool) {
    for tl in tl_data {
        if filter_kadm && tl.kind == KADM_DATA {
            continue;
        }
        let _ = write!(out, "\t{}\t{}\t", tl.kind as i16, tl.data.len());
        octets(out, &tl.data);
    }
}

/// One `princ` record (`k5beta7_common`, `dump.c:293-375`). Like klmdb,
/// entries carry no `e_data`, so it is always written as `-1`.
pub fn principal_record(entry: &MitEntry, version: DumpVersion) -> Vec<u8> {
    let kadm = version != DumpVersion::Beta7;
    let name = unparse_name(&entry.principal, &entry.realm);
    let tl_count = entry
        .tl_data
        .iter()
        .filter(|tl| kadm || tl.kind != KADM_DATA)
        .count();
    let mut out = Vec::new();
    let _ = write!(
        out,
        "princ\t{BASE_LENGTH}\t{}\t{tl_count}\t{}\t0\t",
        name.len(),
        entry.key_data.len()
    );
    out.extend_from_slice(&name);
    let _ = write!(
        out,
        "\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
        entry.attributes as i32,
        entry.max_life as i32,
        entry.max_renewable_life as i32,
        entry.expiration,
        entry.pw_expiration,
        entry.last_success,
        entry.last_failed,
        entry.fail_auth_count as i32
    );
    tl_list(&mut out, &entry.tl_data, !kadm);
    out.push(b'\t');
    for key in &entry.key_data {
        let _ = write!(out, "{}\t{}\t", key.ver as i16, key.kvno);
        for (kind, data) in &key.fields {
            let _ = write!(out, "{kind}\t{}\t", data.len());
            octets(&mut out, data);
            out.push(b'\t');
        }
    }
    out.extend_from_slice(b"-1;\n");
    out
}

/// One `policy` record (`dump.c:393-431`).
pub fn policy_record(policy: &MitPolicy, version: DumpVersion) -> Vec<u8> {
    let p = policy;
    let mut out = Vec::new();
    let _ = write!(
        out,
        "policy\t{}\t{}\t{}\t{}\t{}\t{}\t0",
        p.name,
        p.pw_min_life as i32,
        p.pw_max_life as i32,
        p.pw_min_length as i32,
        p.pw_min_classes as i32,
        p.pw_history_num as i32
    );
    if matches!(version, DumpVersion::R18 | DumpVersion::R111) {
        let _ = write!(
            out,
            "\t{}\t{}\t{}",
            p.pw_max_fail as i32, p.pw_failcnt_interval as i32, p.pw_lockout_duration as i32
        );
    }
    if version == DumpVersion::R111 {
        let _ = write!(
            out,
            "\t{}\t{}\t{}\t{}\t{}",
            p.attributes as i32,
            p.max_life as i32,
            p.max_renewable_life as i32,
            p.allowed_keysalts.as_deref().unwrap_or("-"),
            p.tl_data.len()
        );
        tl_list(&mut out, &p.tl_data, false);
    }
    out.push(b'\n');
    out
}

/// A dump: header, principals, then policies (`dump.c:1307-1325`).
pub fn write_dump(version: DumpVersion, entries: &[MitEntry], policies: &[MitPolicy]) -> Vec<u8> {
    let mut out = version.header().as_bytes().to_vec();
    for entry in entries {
        out.extend(principal_record(entry, version));
    }
    for policy in policies {
        out.extend(policy_record(policy, version));
    }
    out
}

/// A loaded record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Record {
    /// `princ`.
    Principal(MitEntry),
    /// `policy`.
    Policy(MitPolicy),
}

/// A load failure: the diagnostics MIT prints before
/// `error processing line N` (`dump.c:1365-1380`), and that line number.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadError {
    /// Diagnostic lines, without newlines (may be empty).
    pub messages: Vec<String>,
    /// The line being processed.
    pub line: usize,
}

/// Parses records after the header with `fscanf` semantics: a tab in MIT's
/// formats skips any whitespace (`dump.c:470-1068`).
pub struct Loader<'a> {
    data: &'a [u8],
    pos: usize,
    fname: String,
    version: DumpVersion,
    /// The current line (the header is line 1).
    pub line: usize,
    /// `ignoring trash at end of line` warnings, already formatted.
    pub warnings: Vec<String>,
}

enum Step<T> {
    Eof,
    Ok(T),
}

impl<'a> Loader<'a> {
    /// `data` is the input after the header line.
    pub fn new(data: &'a [u8], fname: &str, version: DumpVersion) -> Self {
        Self {
            data,
            pos: 0,
            fname: fname.to_owned(),
            version,
            line: 1,
            warnings: Vec::new(),
        }
    }

    fn skip_ws(&mut self) {
        while self
            .data
            .get(self.pos)
            .is_some_and(|b| b.is_ascii_whitespace() || *b == 0x0b)
        {
            self.pos += 1;
        }
    }

    fn at_eof(&mut self) -> bool {
        self.skip_ws();
        self.pos >= self.data.len()
    }

    /// `%d`/`%u`; `None` if no number could be read.
    fn num(&mut self) -> Option<i64> {
        self.skip_ws();
        let start = self.pos;
        if matches!(self.data.get(self.pos), Some(b'-' | b'+')) {
            self.pos += 1;
        }
        let digits = self.pos;
        while self.data.get(self.pos).is_some_and(u8::is_ascii_digit) {
            self.pos += 1;
        }
        if self.pos == digits {
            self.pos = start;
            return None;
        }
        std::str::from_utf8(&self.data[start..self.pos])
            .ok()?
            .parse::<i64>()
            .ok()
    }

    /// `%u` stores with C unsigned wraparound.
    fn unsigned(&mut self) -> Option<u32> {
        self.num().map(|n| n as u32)
    }

    /// `%Ns`.
    fn token(&mut self, max: usize) -> Option<&'a [u8]> {
        self.skip_ws();
        let start = self.pos;
        while self.pos - start < max
            && self
                .data
                .get(self.pos)
                .is_some_and(|b| !b.is_ascii_whitespace() && *b != 0x0b)
        {
            self.pos += 1;
        }
        (self.pos > start).then(|| &self.data[start..self.pos])
    }

    /// `read_octets_or_minus1` (`dump.c:543-563`).
    fn octets(&mut self, len: usize) -> Option<Vec<u8>> {
        if len == 0 {
            return (self.num()? == -1).then(Vec::new);
        }
        let mut out = Vec::with_capacity(len);
        for _ in 0..len {
            self.skip_ws();
            let start = self.pos;
            while self.pos - start < 2 && self.data.get(self.pos).is_some_and(u8::is_ascii_hexdigit)
            {
                self.pos += 1;
            }
            let hex = std::str::from_utf8(&self.data[start..self.pos]).ok()?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
        }
        Some(out)
    }

    fn load_err(&self, msg: &str) -> LoadError {
        LoadError {
            messages: vec![format!("{}({}): {msg}", self.fname, self.line)],
            line: self.line,
        }
    }

    fn fail(&self, msg: impl Into<String>) -> LoadError {
        LoadError {
            messages: vec![msg.into()],
            line: self.line,
        }
    }

    /// The next record, `None` at end of input (`process_tagged`,
    /// `dump.c:958-980`).
    pub fn next_record(&mut self) -> Result<Option<Record>, LoadError> {
        if self.at_eof() {
            return Ok(None);
        }
        let Some(tag) = self.token(99) else {
            return Err(self.fail(""));
        };
        match tag {
            b"princ" => match self.principal()? {
                Step::Ok(entry) => Ok(Some(Record::Principal(entry))),
                _ => Ok(None),
            },
            b"policy" => match self.policy()? {
                Step::Ok(policy) => Ok(Some(Record::Policy(policy))),
                _ => Ok(None),
            },
            b"End" => Ok(None),
            other => Err(self.fail(format!(
                "unknown record type \"{}\"",
                String::from_utf8_lossy(other)
            ))),
        }
    }

    fn tl_data(&mut self, count: usize) -> Result<Vec<TlData>, LoadError> {
        let mut out = Vec::with_capacity(count.min(1024));
        for _ in 0..count {
            let (Some(kind), Some(len)) = (self.num(), self.num()) else {
                return Err(self.load_err("cannot read tagged data type and length"));
            };
            let len = len as u32;
            let (Ok(kind), Ok(len)) = (i16::try_from(kind), u16::try_from(len)) else {
                return Err(self.load_err("data type or length overflowed"));
            };
            let Some(data) = self.octets(usize::from(len)) else {
                return Err(self.load_err("cannot read tagged data contents"));
            };
            out.push(TlData {
                kind: kind as u16,
                data,
            });
        }
        Ok(out)
    }

    /// `process_k5beta7_princ` (`dump.c:598-794`).
    fn principal(&mut self) -> Result<Step<MitEntry>, LoadError> {
        self.line += 1;
        if self.at_eof() {
            return Ok(Step::Eof);
        }
        let mut sizes = [0u32; 5];
        for size in &mut sizes {
            *size = self
                .unsigned()
                .ok_or_else(|| self.load_err("cannot match size tokens"))?;
        }
        let [_len, name_len, tl_count, key_count, e_length] = sizes;
        if name_len > u32::MAX / 2 {
            return Err(self.load_err("cannot allocate principal (too large)"));
        }
        if tl_count > u32::from(u16::MAX) {
            return Err(self.load_err("cannot allocate tl_data (too large)"));
        }
        if key_count > i16::MAX as u32 {
            return Err(self.load_err("invalid key_data size"));
        }
        if e_length > u32::from(u16::MAX) {
            return Err(self.load_err("invalid principal extra data size"));
        }
        self.skip_ws();
        let end = self.pos.saturating_add(name_len as usize);
        let Some(name) = self.data.get(self.pos..end) else {
            self.pos = self.data.len();
            return Err(self.load_err("cannot read name string"));
        };
        self.pos = end;
        self.line += name.iter().filter(|b| **b == b'\n').count();
        let (principal, realm) = parse_name(name).map_err(|e| {
            self.fail(format!(
                "{e} while parsing name {}",
                String::from_utf8_lossy(name)
            ))
        })?;
        let mut fixed = [0u32; 8];
        for field in &mut fixed {
            *field = self
                .unsigned()
                .ok_or_else(|| self.load_err("cannot read principal attributes"))?;
        }
        let tl_data = self.tl_data(tl_count as usize)?;
        let mut key_data = Vec::with_capacity(key_count as usize);
        for _ in 0..key_count {
            let (Some(ver), Some(kvno)) = (self.num(), self.num()) else {
                return Err(self.load_err("cannot read key size and version"));
            };
            if ver > 2 {
                return Err(self.load_err("unsupported key_data_ver version"));
            }
            let Ok(kvno) = u16::try_from(kvno) else {
                return Err(self.load_err("invalid kvno"));
            };
            let mut fields = Vec::new();
            for _ in 0..ver.max(0) {
                let (Some(kind), Some(Ok(len))) = (self.num(), self.num().map(u16::try_from))
                else {
                    return Err(self.load_err("cannot read key type and length"));
                };
                let Some(data) = self.octets(usize::from(len)) else {
                    return Err(self.load_err("cannot read key data"));
                };
                fields.push((kind as i16, data));
            }
            key_data.push(KeyData {
                ver: ver as u16,
                kvno,
                fields,
            });
        }
        if self.octets(e_length as usize).is_none() {
            return Err(self.load_err("cannot read extra data"));
        }
        self.record_end();
        let [attributes, max_life, max_renewable_life, expiration, pw_expiration, last_success, last_failed, fail_auth_count] =
            fixed;
        Ok(Step::Ok(MitEntry {
            principal,
            realm,
            attributes,
            max_life,
            max_renewable_life,
            expiration,
            pw_expiration,
            last_success,
            last_failed,
            fail_auth_count,
            tl_data,
            key_data,
        }))
    }

    /// `read_record_end` (`dump.c:508-523`): trash is reported, not fatal.
    fn record_end(&mut self) {
        if self.data.get(self.pos..self.pos + 2) == Some(b";\n") {
            self.pos += 2;
            return;
        }
        let rest = &self.data[self.pos..];
        let end = rest
            .iter()
            .position(|b| *b == b'\n')
            .map_or(rest.len(), |i| i + 1);
        self.warnings.push(format!(
            "{}({}): ignoring trash at end of line: {}",
            self.fname,
            self.line,
            String::from_utf8_lossy(&rest[..end]).trim_end_matches('\n')
        ));
        self.pos += end;
    }

    /// `process_k5beta7_policy`, `process_r1_8_policy` and
    /// `process_r1_11_policy` (`dump.c:796-956`).
    fn policy(&mut self) -> Result<Step<MitPolicy>, LoadError> {
        self.line += 1;
        let Some(name) = self.token(1023) else {
            if self.at_eof() {
                return Ok(Step::Eof);
            }
            return Err(self.fail("cannot parse policy (0 read)"));
        };
        let name = String::from_utf8_lossy(name).into_owned();
        let wanted = if self.version == DumpVersion::Beta7 || self.version == DumpVersion::R13 {
            6
        } else {
            9
        };
        let mut fields = [0u32; 9];
        for (read, field) in fields.iter_mut().take(wanted).enumerate() {
            *field = self
                .unsigned()
                .ok_or_else(|| self.fail(format!("cannot parse policy ({} read)", read + 1)))?;
        }
        let [pw_min_life, pw_max_life, pw_min_length, pw_min_classes, pw_history_num, _refcnt, pw_max_fail, pw_failcnt_interval, pw_lockout_duration] =
            fields;
        let mut policy = MitPolicy {
            name,
            pw_min_life,
            pw_max_life,
            pw_min_length,
            pw_min_classes,
            pw_history_num,
            pw_max_fail,
            pw_failcnt_interval,
            pw_lockout_duration,
            attributes: 0,
            max_life: 0,
            max_renewable_life: 0,
            allowed_keysalts: None,
            tl_data: Vec::new(),
        };
        if self.version != DumpVersion::R111 {
            return Ok(Step::Ok(policy));
        }
        let Some(&next) = self.data.get(self.pos) else {
            return Ok(Step::Eof);
        };
        self.pos += 1;
        if next == b'\n' {
            return Ok(Step::Ok(policy));
        }
        let mut extra = [0u32; 3];
        for (read, field) in extra.iter_mut().enumerate() {
            *field = self
                .unsigned()
                .ok_or_else(|| self.fail(format!("cannot parse policy ({read} read)")))?;
        }
        [
            policy.attributes,
            policy.max_life,
            policy.max_renewable_life,
        ] = extra;
        let keysalts = self
            .token(MAX_ALLOWED_KS_LEN)
            .ok_or_else(|| self.fail("cannot parse policy (3 read)"))?;
        if keysalts != b"-" {
            policy.allowed_keysalts = Some(String::from_utf8_lossy(keysalts).into_owned());
        }
        let count = self
            .num()
            .and_then(|n| i16::try_from(n).ok())
            .ok_or_else(|| self.fail("cannot parse policy (4 read)"))?;
        policy.tl_data = self.tl_data(usize::try_from(count).unwrap_or(0))?;
        Ok(Step::Ok(policy))
    }
}

/// Split a dump into its version and the input after the header, with
/// `kdb5_util load`'s messages (`dump.c:1432-1465`). `forced` is the version
/// given with `-b7`/`-r13`/`-r18`, checked as a header prefix.
pub fn read_header<'a>(
    data: &'a [u8],
    fname: &str,
    forced: Option<DumpVersion>,
) -> Result<(DumpVersion, &'a [u8]), String> {
    let end = data
        .iter()
        .position(|b| *b == b'\n')
        .map_or(data.len(), |i| i + 1);
    if end == 0 {
        return Err(format!("can't read dump header in {fname}"));
    }
    let (header, rest) = data.split_at(end);
    let version = match forced {
        Some(v) if header.starts_with(v.header().as_bytes()) => Some(v),
        Some(_) => None,
        None => DumpVersion::from_header(header),
    };
    version
        .map(|v| (v, rest))
        .ok_or_else(|| format!("dump header bad in {fname}"))
}

/// Load every record of a dump, `fname` naming it in diagnostics.
pub fn read_dump(
    data: &[u8],
    fname: &str,
    forced: Option<DumpVersion>,
) -> Result<(DumpVersion, Vec<Record>, Vec<String>), LoadFailure> {
    let (version, body) = read_header(data, fname, forced).map_err(LoadFailure::Header)?;
    let mut loader = Loader::new(body, fname, version);
    let mut records = Vec::new();
    loop {
        match loader.next_record() {
            Ok(Some(record)) => records.push(record),
            Ok(None) => return Ok((version, records, loader.warnings)),
            Err(error) => {
                return Err(LoadFailure::Record {
                    version,
                    error,
                    warnings: loader.warnings,
                })
            }
        }
    }
}

/// Why [`read_dump`] failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoadFailure {
    /// Unreadable or unknown header.
    Header(String),
    /// A record could not be parsed.
    Record {
        /// The dump's version.
        version: DumpVersion,
        /// Where and why.
        error: LoadError,
        /// Warnings before the failure.
        warnings: Vec<String>,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(name: &str) -> Vec<u8> {
        std::fs::read(format!(
            "{}/tests/fixtures/mit-dump/{name}.dump",
            env!("CARGO_MANIFEST_DIR")
        ))
        .expect("read MIT fixture")
    }

    fn split(records: Vec<Record>) -> (Vec<MitEntry>, Vec<MitPolicy>) {
        let mut entries = Vec::new();
        let mut policies = Vec::new();
        for record in records {
            match record {
                Record::Principal(e) => entries.push(e),
                Record::Policy(p) => policies.push(p),
            }
        }
        (entries, policies)
    }

    #[test]
    fn mit_fixtures_round_trip_byte_for_byte() {
        for (name, version) in [
            ("v7", DumpVersion::R111),
            ("r18", DumpVersion::R18),
            ("r13", DumpVersion::R13),
            ("b7", DumpVersion::Beta7),
        ] {
            let data = fixture(name);
            let (found, records, warnings) = read_dump(&data, name, None).expect("load fixture");
            assert_eq!(found, version, "{name} header");
            assert!(warnings.is_empty(), "{name}: {warnings:?}");
            let (entries, policies) = split(records);
            assert_eq!(entries.len(), 11, "{name} principal count");
            assert_eq!(policies.len(), 3, "{name} policy count");
            assert_eq!(
                String::from_utf8_lossy(&write_dump(version, &entries, &policies)),
                String::from_utf8_lossy(&data),
                "{name} differs from MIT's dump"
            );
        }
    }

    #[test]
    fn v7_fixture_keeps_lockout_strings_and_policy_fields() {
        let (_, records, _) = read_dump(&fixture("v7"), "v7", None).expect("load");
        let (entries, policies) = split(records);
        let find = |n: &str| {
            entries
                .iter()
                .find(|e| unparse_name(&e.principal, &e.realm) == n.as_bytes())
                .expect(n)
        };
        let locked = find("locked@DUMP.TEST");
        assert_eq!(locked.fail_auth_count, 1, "fail_auth_count");
        assert_ne!(locked.last_failed, 0, "last_failed");
        assert_ne!(find("alice@DUMP.TEST").last_success, 0, "last_success");
        assert!(find("alice@DUMP.TEST")
            .tl_data
            .iter()
            .any(|tl| tl.kind == super::super::STRING_ATTRS));
        assert!(find("nokey@DUMP.TEST").key_data.is_empty());
        let ks = policies.iter().find(|p| p.name == "ks-policy").expect("ks");
        assert_eq!(
            ks.allowed_keysalts.as_deref(),
            Some("aes256-cts-hmac-sha1-96:normal,aes128-cts-hmac-sha1-96:normal")
        );
        let full = policies
            .iter()
            .find(|p| p.name == "full-policy")
            .expect("full");
        assert_eq!(
            (
                full.pw_max_fail,
                full.pw_failcnt_interval,
                full.pw_lockout_duration
            ),
            (2, 3600, 1800)
        );
    }

    #[test]
    fn v7_reader_accepts_r18_policy_lines() {
        let data = b"kdb5_util load_dump version 7\npolicy\tp\t1\t2\t3\t4\t5\t0\t6\t7\t8\n";
        let (_, records, _) = read_dump(data, "d", None).expect("load");
        let Record::Policy(p) = &records[0] else {
            panic!("not a policy")
        };
        assert_eq!(
            (p.pw_max_fail, p.pw_lockout_duration, p.attributes),
            (6, 8, 0)
        );
    }

    #[test]
    fn unknown_header_is_rejected_with_mit_message() {
        let err = read_dump(b"kdb5_util load_dump version 8\n", "f", None).expect_err("rejected");
        assert_eq!(err, LoadFailure::Header("dump header bad in f".into()));
        let err = read_dump(b"", "f", None).expect_err("rejected");
        assert_eq!(
            err,
            LoadFailure::Header("can't read dump header in f".into())
        );
        let err = read_dump(&fixture("v7"), "f", Some(DumpVersion::R18)).expect_err("rejected");
        assert_eq!(err, LoadFailure::Header("dump header bad in f".into()));
    }

    #[test]
    fn unknown_record_type_fails_on_its_line() {
        let data =
            b"kdb5_util load_dump version 7\npolicy\tp\t1\t2\t3\t4\t5\t0\t6\t7\t8\nbogus\t1\n";
        let Err(LoadFailure::Record { error, .. }) = read_dump(data, "d", None) else {
            panic!("bogus record accepted")
        };
        assert_eq!(
            error.messages,
            vec!["unknown record type \"bogus\"".to_string()]
        );
        assert_eq!(error.line, 2);
    }

    #[test]
    fn truncated_principal_reports_mit_load_error() {
        let data = fixture("v7");
        let policies = data
            .windows(8)
            .position(|w| w == b"\npolicy\t")
            .expect("policy section");
        let cut = &data[..policies - 20];
        let Err(LoadFailure::Record { error, .. }) = read_dump(cut, "d", None) else {
            panic!("truncated dump accepted")
        };
        assert!(
            error.messages[0].starts_with("d(") && error.messages[0].contains("cannot read"),
            "{:?}",
            error.messages
        );
    }

    #[test]
    fn trailing_trash_is_a_warning() {
        let data = fixture("v7");
        let text = String::from_utf8(data)
            .expect("utf8")
            .replacen("-1;\n", "-1;x\n", 1);
        let (_, records, warnings) = read_dump(text.as_bytes(), "d", None).expect("load");
        assert_eq!(records.len(), 14);
        assert_eq!(
            warnings,
            vec!["d(2): ignoring trash at end of line: ;x".to_string()]
        );
    }
}
