//! `krb5_string_to_deltat` — MIT str_conv.c / x-deltat.y grammar.
//!
//! Accepted forms:
//! - `N` — bare seconds (optionally signed).
//! - `Nd`, `Nh`, `Nm`, `Ns` — components in strictly decreasing unit order
//!   (d > h > m > s), each signed, separated by optional whitespace.
//! - `H:M`, `H:M:S` — hours/minutes[/seconds], no whitespace, minute and
//!   second fields at most two digits.
//! - `D-H:M:S` — days-hours:minutes:seconds.
//!
//! The accumulated value must fit `krb5_deltat` (i32); overflow is an
//! error (x-deltat.y `MAX_DELTA` checks).

use super::ProfileError;

const DAY: i64 = 24 * 3600;
const HOUR: i64 = 3600;
const MIN: i64 = 60;

fn bad(s: &str) -> ProfileError {
    ProfileError::BadDeltat(s.to_string())
}

fn is_ws(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c)
}

/// Parse `[ws] [-] digits` starting at `*i`.  Whitespace is consumed before
/// but not after the number.
fn num(b: &[u8], i: &mut usize, s: &str) -> Result<i64, ProfileError> {
    while *i < b.len() && is_ws(b[*i]) {
        *i += 1;
    }
    let neg = if *i < b.len() && b[*i] == b'-' {
        *i += 1;
        true
    } else {
        false
    };
    let start = *i;
    let mut v: i64 = 0;
    while *i < b.len() && b[*i].is_ascii_digit() {
        v = v
            .checked_mul(10)
            .and_then(|v| v.checked_add((b[*i] - b'0') as i64))
            .ok_or_else(|| bad(s))?;
        *i += 1;
    }
    if *i == start {
        return Err(bad(s));
    }
    Ok(if neg { -v } else { v })
}

/// Parse exactly 1-2 digits with no whitespace or sign (num2 in x-deltat.y).
fn num2(b: &[u8], i: &mut usize, s: &str) -> Result<i64, ProfileError> {
    let start = *i;
    let mut v: i64 = 0;
    while *i < b.len() && b[*i].is_ascii_digit() && *i - start < 2 {
        v = v * 10 + (b[*i] - b'0') as i64;
        *i += 1;
    }
    if *i == start || (*i < b.len() && b[*i].is_ascii_digit()) {
        // Empty, or more than two digits.
        return Err(bad(s));
    }
    Ok(v)
}

fn unit_rank(b: u8) -> Option<(u8, i64)> {
    match b {
        b'd' => Some((3, DAY)),
        b'h' => Some((2, HOUR)),
        b'm' => Some((1, MIN)),
        b's' => Some((0, 1)),
        _ => None,
    }
}

fn finish(v: i64, s: &str) -> Result<i32, ProfileError> {
    i32::try_from(v).map_err(|_| bad(s))
}

/// `krb5_string_to_deltat` (str_conv.c): parse a delta-time string.
pub fn string_to_deltat(s: &str) -> Result<i32, ProfileError> {
    let b = s.as_bytes();
    let mut i = 0usize;
    let n = num(b, &mut i, s)?;
    let mut total: i64;

    if i < b.len() && b[i] == b':' {
        // H:M[:S]
        i += 1;
        let m = num2(b, &mut i, s)?;
        let sec = if i < b.len() && b[i] == b':' {
            i += 1;
            num2(b, &mut i, s)?
        } else {
            0
        };
        total = n
            .checked_mul(HOUR)
            .and_then(|v| v.checked_add(m * MIN))
            .and_then(|v| v.checked_add(sec))
            .ok_or_else(|| bad(s))?;
    } else if i < b.len() && b[i] == b'-' {
        // Could be D-H:M:S or (after a unitless number) invalid.
        i += 1;
        let mut j = i;
        let d2 = num2(b, &mut j, s);
        if d2.is_ok() && j < b.len() && b[j] == b':' {
            // D-H:M:S
            let h = d2?;
            i = j + 1;
            let m = num2(b, &mut i, s)?;
            if i >= b.len() || b[i] != b':' {
                return Err(bad(s));
            }
            i += 1;
            let sec = num2(b, &mut i, s)?;
            total = n
                .checked_mul(DAY)
                .and_then(|v| v.checked_add(h * HOUR))
                .and_then(|v| v.checked_add(m * MIN))
                .and_then(|v| v.checked_add(sec))
                .ok_or_else(|| bad(s))?;
        } else {
            return Err(bad(s));
        }
    } else if i < b.len() && unit_rank(b[i]).is_some() {
        // Component list: first component already parsed.
        let (rank, mul) = unit_rank(b[i]).unwrap_or((0, 1));
        i += 1;
        let mut prev_rank = rank;
        total = n.checked_mul(mul).ok_or_else(|| bad(s))?;
        loop {
            while i < b.len() && is_ws(b[i]) {
                i += 1;
            }
            if i >= b.len() {
                break;
            }
            let v = num(b, &mut i, s)?;
            if i >= b.len() {
                return Err(bad(s));
            }
            let (r, m) = match unit_rank(b[i]) {
                Some(x) => x,
                None => return Err(bad(s)),
            };
            i += 1;
            if r >= prev_rank {
                // Units must appear in strictly decreasing order d,h,m,s.
                return Err(bad(s));
            }
            prev_rank = r;
            total = total
                .checked_add(v.checked_mul(m).ok_or_else(|| bad(s))?)
                .ok_or_else(|| bad(s))?;
        }
        return finish(total, s);
    } else {
        // Bare number = seconds; only trailing whitespace may follow.
        total = n;
    }

    while i < b.len() && is_ws(b[i]) {
        i += 1;
    }
    if i != b.len() {
        return Err(bad(s));
    }
    finish(total, s)
}
