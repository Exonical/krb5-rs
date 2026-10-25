//! MIT's `get_date` (`src/kadmin/cli/getdate.y`), the free-form date parser
//! behind `kdb5_util use_mkey` and kadmin's date options: `2030-01-15
//! 10:30`, `jan 15, 2030 10pm est`, `next monday`, `2 weeks ago`, `never`.
//! Ported faithfully, including its quirks (`next` means the second, `12am`
//! is noon, leap years before the target year use the target year's
//! century rule).

/// The `struct tm` fields `get_date` reads.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Tm {
    /// Seconds.
    pub sec: i64,
    /// Minutes.
    pub min: i64,
    /// Hours.
    pub hour: i64,
    /// Day of the month.
    pub mday: i64,
    /// Month, 0-11.
    pub mon: i64,
    /// Years since 1900.
    pub year: i64,
    /// Day of the week, 0 is Sunday.
    pub wday: i64,
    /// Day of the year, 0-365.
    pub yday: i64,
    /// Daylight saving time in effect.
    pub isdst: bool,
}

/// `get_date`: parse relative to the current time in the local time zone.
/// `None` where MIT returns -1.
pub fn get_date(s: &str) -> Option<i64> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_secs()).ok())?;
    get_date_rel(s, now)
}

/// `get_date_rel` in the local time zone.
pub fn get_date_rel(s: &str, now: i64) -> Option<i64> {
    get_date_in(s, now, &localtime)
}

/// UTC broken-down time (`gmtime`).
pub fn gmtime(t: i64) -> Option<Tm> {
    use chrono::{Datelike, Timelike};
    let d = chrono::DateTime::from_timestamp(t, 0)?;
    Some(Tm {
        sec: i64::from(d.second()),
        min: i64::from(d.minute()),
        hour: i64::from(d.hour()),
        mday: i64::from(d.day()),
        mon: i64::from(d.month0()),
        year: i64::from(d.year()) - 1900,
        wday: i64::from(d.weekday().num_days_from_sunday()),
        yday: i64::from(d.ordinal0()),
        isdst: false,
    })
}

#[cfg(unix)]
#[expect(unsafe_code, reason = "std has no localtime_r")]
fn localtime(t: i64) -> Option<Tm> {
    #[allow(
        clippy::useless_conversion,
        reason = "time_t is 32-bit on some targets"
    )]
    let t = TryFrom::try_from(t).ok()?;
    // SAFETY: an all-zero tm is valid storage for localtime_r to fill.
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    // SAFETY: both pointers refer to live locals for the whole call.
    if unsafe { libc::localtime_r(&t, &mut tm) }.is_null() {
        return None;
    }
    Some(Tm {
        sec: i64::from(tm.tm_sec),
        min: i64::from(tm.tm_min),
        hour: i64::from(tm.tm_hour),
        mday: i64::from(tm.tm_mday),
        mon: i64::from(tm.tm_mon),
        year: i64::from(tm.tm_year),
        wday: i64::from(tm.tm_wday),
        yday: i64::from(tm.tm_yday),
        isdst: tm.tm_isdst > 0,
    })
}

#[cfg(not(unix))]
fn localtime(t: i64) -> Option<Tm> {
    gmtime(t)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mer {
    Am,
    Pm,
    H24,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Dst {
    On,
    Off,
    Maybe,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tok {
    U(i64),
    S(i64),
    Merid(Mer),
    Month(i64),
    Day(i64),
    Zone(i64),
    DayZone(i64),
    Dst,
    MinUnit(i64),
    SecUnit(i64),
    MonthUnit(i64),
    Ago,
    Never,
    Id,
    Ch(u8),
    End,
}

const MONTH_DAY: &[(&str, Tok)] = &[
    ("january", Tok::Month(1)),
    ("february", Tok::Month(2)),
    ("march", Tok::Month(3)),
    ("april", Tok::Month(4)),
    ("may", Tok::Month(5)),
    ("june", Tok::Month(6)),
    ("july", Tok::Month(7)),
    ("august", Tok::Month(8)),
    ("september", Tok::Month(9)),
    ("sept", Tok::Month(9)),
    ("october", Tok::Month(10)),
    ("november", Tok::Month(11)),
    ("december", Tok::Month(12)),
    ("sunday", Tok::Day(0)),
    ("monday", Tok::Day(1)),
    ("tuesday", Tok::Day(2)),
    ("tues", Tok::Day(2)),
    ("wednesday", Tok::Day(3)),
    ("wednes", Tok::Day(3)),
    ("thursday", Tok::Day(4)),
    ("thur", Tok::Day(4)),
    ("thurs", Tok::Day(4)),
    ("friday", Tok::Day(5)),
    ("saturday", Tok::Day(6)),
];

const UNITS: &[(&str, Tok)] = &[
    ("year", Tok::MonthUnit(12)),
    ("month", Tok::MonthUnit(1)),
    ("fortnight", Tok::MinUnit(14 * 24 * 60)),
    ("week", Tok::MinUnit(7 * 24 * 60)),
    ("day", Tok::MinUnit(24 * 60)),
    ("hour", Tok::MinUnit(60)),
    ("minute", Tok::MinUnit(1)),
    ("min", Tok::MinUnit(1)),
    ("second", Tok::SecUnit(1)),
    ("sec", Tok::SecUnit(1)),
];

const OTHER: &[(&str, Tok)] = &[
    ("tomorrow", Tok::MinUnit(24 * 60)),
    ("yesterday", Tok::MinUnit(-24 * 60)),
    ("today", Tok::MinUnit(0)),
    ("now", Tok::MinUnit(0)),
    ("last", Tok::U(-1)),
    ("this", Tok::MinUnit(0)),
    ("next", Tok::U(2)),
    ("first", Tok::U(1)),
    ("third", Tok::U(3)),
    ("fourth", Tok::U(4)),
    ("fifth", Tok::U(5)),
    ("sixth", Tok::U(6)),
    ("seventh", Tok::U(7)),
    ("eighth", Tok::U(8)),
    ("ninth", Tok::U(9)),
    ("tenth", Tok::U(10)),
    ("eleventh", Tok::U(11)),
    ("twelfth", Tok::U(12)),
    ("ago", Tok::Ago),
    ("never", Tok::Never),
];

/// Minutes west of UTC; `DayZone` entries are daylight zones.
const ZONES: &[(&str, Tok)] = &[
    ("gmt", Tok::Zone(0)),
    ("ut", Tok::Zone(0)),
    ("utc", Tok::Zone(0)),
    ("wet", Tok::Zone(0)),
    ("bst", Tok::DayZone(0)),
    ("wat", Tok::Zone(60)),
    ("at", Tok::Zone(120)),
    ("ast", Tok::Zone(240)),
    ("adt", Tok::DayZone(240)),
    ("est", Tok::Zone(300)),
    ("edt", Tok::DayZone(300)),
    ("cst", Tok::Zone(360)),
    ("cdt", Tok::DayZone(360)),
    ("mst", Tok::Zone(420)),
    ("mdt", Tok::DayZone(420)),
    ("pst", Tok::Zone(480)),
    ("pdt", Tok::DayZone(480)),
    ("yst", Tok::Zone(540)),
    ("ydt", Tok::DayZone(540)),
    ("hst", Tok::Zone(600)),
    ("hdt", Tok::DayZone(600)),
    ("cat", Tok::Zone(600)),
    ("ahst", Tok::Zone(600)),
    ("nt", Tok::Zone(660)),
    ("idlw", Tok::Zone(720)),
    ("cet", Tok::Zone(-60)),
    ("met", Tok::Zone(-60)),
    ("mewt", Tok::Zone(-60)),
    ("mest", Tok::DayZone(-60)),
    ("swt", Tok::Zone(-60)),
    ("sst", Tok::DayZone(-60)),
    ("fwt", Tok::Zone(-60)),
    ("fst", Tok::DayZone(-60)),
    ("eet", Tok::Zone(-120)),
    ("bt", Tok::Zone(-180)),
    ("zp4", Tok::Zone(-240)),
    ("zp5", Tok::Zone(-300)),
    ("zp6", Tok::Zone(-360)),
    ("wast", Tok::Zone(-420)),
    ("wadt", Tok::DayZone(-420)),
    ("cct", Tok::Zone(-480)),
    ("jst", Tok::Zone(-540)),
    ("kst", Tok::Zone(-540)),
    ("east", Tok::Zone(-600)),
    ("eadt", Tok::DayZone(-600)),
    ("gst", Tok::Zone(-600)),
    ("kdt", Tok::Zone(-600)),
    ("nzt", Tok::Zone(-720)),
    ("nzst", Tok::Zone(-720)),
    ("nzdt", Tok::DayZone(-720)),
    ("idle", Tok::Zone(-720)),
];

fn find(table: &[(&str, Tok)], word: &str) -> Option<Tok> {
    table.iter().find(|(n, _)| *n == word).map(|(_, t)| *t)
}

/// `LookupWord`.
fn lookup_word(word: &str) -> Tok {
    let mut buff = word.to_ascii_lowercase();
    match buff.as_str() {
        "am" | "a.m." => return Tok::Merid(Mer::Am),
        "pm" | "p.m." => return Tok::Merid(Mer::Pm),
        _ => {}
    }
    let abbrev = buff.len() == 3 || (buff.len() == 4 && buff.as_bytes()[3] == b'.');
    if abbrev {
        buff.truncate(3);
    }
    for (name, tok) in MONTH_DAY {
        if (abbrev && name.as_bytes()[..3] == *buff.as_bytes()) || *name == buff {
            return *tok;
        }
    }
    if let Some(t) = find(ZONES, &buff) {
        return t;
    }
    if buff == "dst" {
        return Tok::Dst;
    }
    if let Some(t) = find(UNITS, &buff) {
        return t;
    }
    if let Some(t) = buff.strip_suffix('s').and_then(|b| find(UNITS, b)) {
        return t;
    }
    if let Some(t) = find(OTHER, &buff) {
        return t;
    }
    if buff.contains('.') {
        if let Some(t) = find(ZONES, &buff.replace('.', "")) {
            return t;
        }
    }
    Tok::Id
}

/// `yylex`.
fn lex(s: &str) -> Vec<Tok> {
    let b = s.as_bytes();
    let at = |i: usize| b.get(i).copied().unwrap_or(0);
    let mut i = 0;
    let mut out = Vec::new();
    loop {
        while matches!(at(i), b' ' | b'\t' | b'\n' | b'\x0b' | b'\x0c' | b'\r') {
            i += 1;
        }
        let c = at(i);
        if c.is_ascii_digit() || c == b'-' || c == b'+' {
            let sign = match c {
                b'-' => -1,
                b'+' => 1,
                _ => 0,
            };
            if sign != 0 {
                i += 1;
                if !at(i).is_ascii_digit() {
                    continue;
                }
            }
            let mut n: i64 = 0;
            while at(i).is_ascii_digit() {
                n = n.wrapping_mul(10).wrapping_add(i64::from(at(i) - b'0'));
                i += 1;
            }
            if sign < 0 {
                n = -n;
            }
            out.push(if sign != 0 { Tok::S(n) } else { Tok::U(n) });
        } else if c.is_ascii_alphabetic() {
            let start = i;
            while at(i).is_ascii_alphabetic() || at(i) == b'.' {
                i += 1;
            }
            out.push(lookup_word(&s[start..i.min(start + 19)]));
        } else if c == 0 {
            out.push(Tok::End);
            return out;
        } else if c != b'(' {
            out.push(Tok::Ch(c));
            i += 1;
        } else {
            let mut depth = 0;
            loop {
                let c = at(i);
                i += 1;
                match c {
                    0 => {
                        out.push(Tok::End);
                        return out;
                    }
                    b'(' => depth += 1,
                    b')' => depth -= 1,
                    _ => {}
                }
                if depth <= 0 {
                    break;
                }
            }
        }
    }
}

struct State {
    dst: Dst,
    day_ordinal: i64,
    day_number: i64,
    have_date: u32,
    have_day: u32,
    have_rel: u32,
    have_time: u32,
    have_zone: u32,
    timezone: i64,
    day: i64,
    hour: i64,
    minutes: i64,
    month: i64,
    seconds: i64,
    year: i64,
    meridian: Mer,
    rel_month: i64,
    rel_seconds: i64,
}

impl State {
    fn time(&mut self, h: i64, m: i64, s: i64, mer: Mer) {
        (self.hour, self.minutes, self.seconds, self.meridian) = (h, m, s, mer);
        self.have_time += 1;
    }

    fn time_zone(&mut self, h: i64, m: i64, s: i64, z: i64) {
        self.time(h, m, s, Mer::H24);
        self.dst = Dst::Off;
        self.timezone = -(z % 100 + (z / 100) * 60);
    }

    fn date(&mut self, month: i64, day: i64, year: Option<i64>) {
        (self.month, self.day) = (month, day);
        if let Some(y) = year {
            self.year = y;
        }
        self.have_date += 1;
    }

    /// One `item`; returns the tokens consumed, or `None` on a syntax error.
    fn item(&mut self, t: &[Tok]) -> Option<usize> {
        use Tok::{Ch, Day, DayZone, Merid, Month, Zone, S, U};
        let g = |i: usize| t.get(i).copied().unwrap_or(Tok::End);
        let used = match (g(0), g(1), g(2)) {
            (U(h), Merid(m), _) => {
                self.time(h, 0, 0, m);
                2
            }
            (U(h), Ch(b':'), U(mi)) => match (g(3), g(4), g(5)) {
                (Ch(b':'), U(s), Merid(m)) => {
                    self.time(h, mi, s, m);
                    6
                }
                (Ch(b':'), U(s), S(z)) => {
                    self.time_zone(h, mi, s, z);
                    6
                }
                (Ch(b':'), U(s), _) => {
                    self.time(h, mi, s, Mer::H24);
                    5
                }
                (Merid(m), _, _) => {
                    self.time(h, mi, 0, m);
                    4
                }
                (S(z), _, _) => {
                    self.time_zone(h, mi, 0, z);
                    4
                }
                _ => {
                    self.time(h, mi, 0, Mer::H24);
                    3
                }
            },
            (U(m), Ch(b'/'), U(d)) => match (g(3), g(4)) {
                (Ch(b'/'), U(y)) => {
                    self.date(m, d, Some(y));
                    5
                }
                _ => {
                    self.date(m, d, None);
                    3
                }
            },
            (U(y), S(m), S(d)) => {
                self.date(-m, -d, Some(y));
                3
            }
            (U(d), Month(m), S(y)) => {
                self.date(m, d, Some(-y));
                3
            }
            (U(d), Month(m), U(y)) => {
                self.date(m, d, Some(y));
                3
            }
            (U(d), Month(m), _) => {
                self.date(m, d, None);
                2
            }
            (Month(m), U(d), _) => match (g(2), g(3)) {
                (Ch(b','), U(y)) => {
                    self.date(m, d, Some(y));
                    4
                }
                _ => {
                    self.date(m, d, None);
                    2
                }
            },
            (U(n), Day(d), _) => {
                (self.day_ordinal, self.day_number) = (n, d);
                self.have_day += 1;
                2
            }
            (Day(d), next, _) => {
                (self.day_ordinal, self.day_number) = (1, d);
                self.have_day += 1;
                if next == Ch(b',') {
                    2
                } else {
                    1
                }
            }
            (Zone(z), next, _) => {
                self.timezone = z;
                self.have_zone += 1;
                if next == Tok::Dst {
                    self.dst = Dst::On;
                    2
                } else {
                    self.dst = Dst::Off;
                    1
                }
            }
            (DayZone(z), _, _) => {
                self.timezone = z;
                self.dst = Dst::On;
                self.have_zone += 1;
                1
            }
            _ => return self.rel(t),
        };
        Some(used)
    }

    /// `rel : relunit tAGO | relunit`.
    fn rel(&mut self, t: &[Tok]) -> Option<usize> {
        use Tok::{MinUnit, MonthUnit, SecUnit, S, U};
        let g = |i: usize| t.get(i).copied().unwrap_or(Tok::End);
        let used = match (g(0), g(1)) {
            (U(n) | S(n), MinUnit(u)) => {
                self.rel_seconds += n * u * 60;
                2
            }
            (U(n) | S(n), SecUnit(_)) => {
                self.rel_seconds += n;
                2
            }
            (U(n) | S(n), MonthUnit(u)) => {
                self.rel_month += n * u;
                2
            }
            (MinUnit(u), _) => {
                self.rel_seconds += u * 60;
                1
            }
            (SecUnit(_), _) => {
                self.rel_seconds += 1;
                1
            }
            (MonthUnit(u), _) => {
                self.rel_month += u;
                1
            }
            _ => return None,
        };
        self.have_rel += 1;
        if g(used) == Tok::Ago {
            self.rel_seconds = -self.rel_seconds;
            self.rel_month = -self.rel_month;
            return Some(used + 1);
        }
        Some(used)
    }
}

/// `ToSeconds`.
fn to_seconds(h: i64, m: i64, s: i64, mer: Mer) -> Option<i64> {
    if !(0..=59).contains(&m) || !(0..=59).contains(&s) {
        return None;
    }
    let h = match mer {
        Mer::H24 if (0..=23).contains(&h) => h,
        Mer::Am if (1..=12).contains(&h) => h,
        Mer::Pm if (1..=12).contains(&h) => h + 12,
        _ => return None,
    };
    Some((h * 60 + m) * 60 + s)
}

type Local<'a> = &'a dyn Fn(i64) -> Option<Tm>;

/// `Convert`.
#[expect(clippy::too_many_arguments, reason = "mirrors MIT's Convert")]
fn convert(
    month: i64,
    day: i64,
    year: i64,
    (h, mi, s): (i64, i64, i64),
    mer: Mer,
    dst: Dst,
    timezone: i64,
    local: Local<'_>,
) -> Option<i64> {
    let mut year = year.abs();
    if year < 1900 {
        year += 1900;
    }
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    if !(1970..=2106).contains(&year) || !(1..=12).contains(&month) {
        return None;
    }
    let month = usize::try_from(month - 1).ok()?;
    if day < 1 || day > days[month] {
        return None;
    }
    let mut julian = day - 1 + days[..month].iter().sum::<i64>();
    for i in 1970..year {
        julian += 365 + i64::from(i % 4 == 0 && (year % 100 != 0 || year % 400 == 0));
    }
    julian *= 24 * 60 * 60;
    julian += timezone * 60;
    julian += to_seconds(h, mi, s, mer)?;
    match dst {
        Dst::On => julian -= 3600,
        Dst::Maybe if local(julian)?.isdst => julian -= 3600,
        _ => {}
    }
    Some(julian)
}

/// `DSTcorrect`.
fn dst_correct(start: i64, future: i64, local: Local<'_>) -> Option<i64> {
    let start_day = (local(start)?.hour + 1) % 24;
    let future_day = (local(future)?.hour + 1) % 24;
    Some((future - start) + (start_day - future_day) * 3600)
}

/// `difftm`: seconds `a` is ahead of `b`.
fn difftm(a: &Tm, b: &Tm) -> i64 {
    let ay = a.year + 1899;
    let by = b.year + 1899;
    let days = a.yday - b.yday + ((ay >> 2) - (by >> 2)) - (ay / 100 - by / 100)
        + (((ay / 100) >> 2) - ((by / 100) >> 2))
        + (ay - by) * 365;
    ((days * 24 + (a.hour - b.hour)) * 60 + (a.min - b.min)) * 60 + (a.sec - b.sec)
}

/// `get_date_rel` with an explicit local-time conversion.
pub fn get_date_in(s: &str, now: i64, local: Local<'_>) -> Option<i64> {
    let gmt = gmtime(now)?;
    let tm = local(now)?;
    let mut st = State {
        dst: Dst::Maybe,
        day_ordinal: 0,
        day_number: 0,
        have_date: 0,
        have_day: 0,
        have_rel: 0,
        have_time: 0,
        have_zone: 0,
        timezone: difftm(&gmt, &tm) / 60,
        day: tm.mday,
        hour: 0,
        minutes: 0,
        seconds: 0,
        month: tm.mon + 1,
        year: tm.year,
        meridian: Mer::H24,
        rel_month: 0,
        rel_seconds: 0,
    };
    let toks = lex(s);
    let mut pos = 0;
    if toks.first() == Some(&Tok::Never) {
        (st.year, st.month, st.day) = (1970, 1, 1);
        (st.hour, st.minutes, st.seconds) = (0, 0, 0);
        st.dst = Dst::Off;
        st.timezone = 0;
        st.have_date += 1;
        pos = 1;
    }
    while toks.get(pos).is_some_and(|t| *t != Tok::End) {
        pos += st.item(&toks[pos..])?;
    }
    if st.have_time > 1 || st.have_zone > 1 || st.have_date > 1 || st.have_day > 1 {
        return None;
    }
    let mut start = if st.have_date > 0 || st.have_time > 0 || st.have_day > 0 {
        let start = convert(
            st.month,
            st.day,
            st.year,
            (st.hour, st.minutes, st.seconds),
            st.meridian,
            st.dst,
            st.timezone,
            local,
        )?;
        if start < 0 {
            return None;
        }
        start
    } else if st.have_rel == 0 {
        now - ((tm.hour * 60 + tm.min) * 60 + tm.sec)
    } else {
        now
    };
    start += st.rel_seconds;
    if st.rel_month != 0 {
        let t = local(start)?;
        let months = 12 * t.year + t.mon + st.rel_month;
        let target = convert(
            months % 12 + 1,
            t.mday,
            months / 12,
            (t.hour, t.min, t.sec),
            Mer::H24,
            Dst::Maybe,
            st.timezone,
            local,
        )?;
        start += dst_correct(start, target, local)?;
    }
    if st.have_day > 0 && st.have_date == 0 {
        let t = local(start)?;
        let mut then = start + 86_400 * ((st.day_number - t.wday + 7) % 7);
        then += 7
            * 86_400
            * if st.day_ordinal <= 0 {
                st.day_ordinal
            } else {
                st.day_ordinal - 1
            };
        start += dst_correct(start, then, local)?;
    }
    Some(if start == -1 { 0 } else { start })
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{NaiveDate, TimeZone, Utc};

    /// Saturday 2026-10-24 08:00:00 UTC.
    const NOW: i64 = 1_792_828_800;

    fn utc(s: &str) -> Option<i64> {
        get_date_in(s, NOW, &gmtime)
    }

    fn at(y: i32, m: u32, d: u32, h: u32, mi: u32, s: u32) -> i64 {
        Utc.from_utc_datetime(
            &NaiveDate::from_ymd_opt(y, m, d)
                .and_then(|d| d.and_hms_opt(h, mi, s))
                .expect("valid date"),
        )
        .timestamp()
    }

    #[test]
    fn now_is_what_the_tests_assume() {
        assert_eq!(NOW, at(2026, 10, 24, 8, 0, 0));
    }

    #[test]
    fn absolute_forms() {
        let jan15 = at(2030, 1, 15, 0, 0, 0);
        for s in [
            "2030-01-15",
            "1/15/2030",
            "15-jan-2030",
            "jan 15, 2030",
            "15 January 2030",
        ] {
            assert_eq!(utc(s), Some(jan15), "{s}");
        }
        assert_eq!(utc("2030-01-15 10:30"), Some(jan15 + 37_800));
        assert_eq!(utc("Jan. 15, 2030 10:30pm"), Some(jan15 + 81_000));
        assert_eq!(utc("1/15/2030 22:30:05 gmt"), Some(jan15 + 81_005));
        assert_eq!(utc("2030-01-15 10:30 -0500"), Some(jan15 + 55_800));
        assert_eq!(utc("2030-01-15 10:30 est"), Some(jan15 + 55_800));
        assert_eq!(utc("2030-01-15 10:30 edt"), Some(jan15 + 52_200));
        assert_eq!(utc("(a comment) 2030-01-15"), Some(jan15));
        assert_eq!(utc("Sept 1"), Some(at(2026, 9, 1, 0, 0, 0)));
        assert_eq!(utc("10am"), Some(at(2026, 10, 24, 10, 0, 0)));
        assert_eq!(utc("12am"), Some(at(2026, 10, 24, 12, 0, 0)), "MIT quirk");
        assert_eq!(utc("never"), Some(0));
    }

    #[test]
    fn relative_forms() {
        assert_eq!(utc("now"), Some(NOW));
        assert_eq!(utc("tomorrow"), Some(NOW + 86_400));
        assert_eq!(utc("2 weeks ago"), Some(NOW - 14 * 86_400));
        assert_eq!(utc("+3 hours"), Some(NOW + 3 * 3_600));
        assert_eq!(utc("1 month"), Some(at(2026, 11, 24, 8, 0, 0)));
        assert_eq!(utc("1 year ago"), Some(at(2025, 10, 24, 8, 0, 0)));
        assert_eq!(utc("monday"), Some(at(2026, 10, 26, 0, 0, 0)));
        assert_eq!(
            utc("next monday"),
            Some(at(2026, 11, 2, 0, 0, 0)),
            "next = 2nd"
        );
        assert_eq!(utc("monday 5pm"), Some(at(2026, 10, 26, 17, 0, 0)));
        assert_eq!(
            utc("est"),
            Some(at(2026, 10, 24, 0, 0, 0)),
            "a zone alone is today"
        );
    }

    #[test]
    fn rejects_what_mit_rejects() {
        for s in [
            "garbage",
            "1792828800",
            "10:30 11:30",
            "13pm",
            "2/30/2030",
            "2030-01-15T10:30:00Z",
            "1/1/1960",
            "5 -3 days",
            "monday tuesday",
        ] {
            assert_eq!(utc(s), None, "{s}");
        }
    }

    #[test]
    fn local_zone_shifts_dates_without_a_zone() {
        let est = |t: i64| gmtime(t - 5 * 3_600);
        assert_eq!(
            get_date_in("2030-01-15", NOW, &est),
            Some(at(2030, 1, 15, 5, 0, 0))
        );
    }
}
