// ---------------------------------------------------------------------------
// Section 2: krb5_string_to_deltat — t_deltat.c vectors verbatim
// ---------------------------------------------------------------------------

const DAY: i32 = 24 * 3600;
const HOUR: i32 = 3600;
const MIN: i32 = 60;

fn good(s: &str, v: i32) {
    assert_eq!(
        string_to_deltat(s).unwrap_or_else(|e| panic!("{s:?} -> {e}")),
        v,
        "{s:?}"
    );
}

fn bad(s: &str) {
    assert!(string_to_deltat(s).is_err(), "{s:?} should fail");
}

#[test]
fn deltat_vectors() {
    good("3d", 3 * DAY);
    good("3h", 3 * HOUR);
    good("3m", 3 * MIN);
    good("3s", 3);
    bad("3dd");
    good("3d4m    42s", 3 * DAY + 4 * MIN + 42);
    good("3d-1h", 3 * DAY - HOUR);
    good("3d -1h", 3 * DAY - HOUR);
    good("3d4h5m6s", 3 * DAY + 4 * HOUR + 5 * MIN + 6);
    bad("3d4m5h");
    good("12345s", 12345);
    good("1m 12345s", MIN + 12345);
    good("1m12345s", MIN + 12345);
    good("3d 0m", 3 * DAY);
    good("3d 0m  ", 3 * DAY);
    good("3d \n\t 0m  ", 3 * DAY);
    good("42-13:42:47", 42 * DAY + 13 * HOUR + 42 * MIN + 47);
    bad("3: 4");
    bad("13:0003");
    good("12:34", 12 * HOUR + 34 * MIN);
    good("1:02:03", HOUR + 2 * MIN + 3);
    bad("3:-4");
    good("3:4", 3 * HOUR + 4 * MIN);
    good("42", 42);
    bad("1-2");
    good("2147483647s", 2147483647);
    bad("2147483648s");
    good("24855d", 24855 * DAY);
    bad("24856d");
    bad("24855d 100000000h");
    good("24855d 3h", 24855 * DAY + 3 * HOUR);
    bad("24855d 4h");
    good("24855d 11647s", 24855 * DAY + 11647);
    bad("24855d 11648s");
    good("24855d 194m 7s", 24855 * DAY + 194 * MIN + 7);
    bad("24855d 194m 8s");
    bad("24855d 195m");
    bad("24855d 19500000000m");
    good("24855d 3h 14m 7s", 24855 * DAY + 3 * HOUR + 14 * MIN + 7);
    bad("24855d 3h 14m 8s");
    good("596523h", 596523 * HOUR);
    bad("596524h");
    good("596523h 847s", 596523 * HOUR + 847);
    bad("596523h 848s");
    good("596523h 14m 7s", 596523 * HOUR + 14 * MIN + 7);
    bad("596523h 14m 8s");
    good("35791394m", 35791394 * MIN);
    good("35791394m7s", 35791394 * MIN + 7);
    bad("35791394m8s");
    good("-2147483647s", -2147483647);
    good("-24855d", -24855 * DAY);
    bad("-24856d");
    bad("-24855d -100000000h");
    good("-24855d -3h", -24855 * DAY - 3 * HOUR);
    bad("-24855d -4h");
    good("-24855d -11647s", -24855 * DAY - 11647);
    bad("-24855d -11649s");
    good("-24855d -194m -7s", -24855 * DAY - 194 * MIN - 7);
    bad("-24855d -194m -9s");
    bad("-24855d -195m");
    bad("-24855d -19500000000m");
    good("-24855d -3h -14m -7s", -24855 * DAY - 3 * HOUR - 14 * MIN - 7);
    bad("-24855d -3h -14m -9s");
    good("-596523h", -596523 * HOUR);
    bad("-596524h");
    good("-596523h -847s", -596523 * HOUR - 847);
    good("-596523h -848s", -596523 * HOUR - 848);
    bad("-596523h -849s");
    good("-596523h -14m -8s", -596523 * HOUR - 14 * MIN - 8);
    bad("-596523h -14m -9s");
    good("-35791394m", -35791394 * MIN);
    good("-35791394m7s", -35791394 * MIN + 7);
    bad("-35791394m-9s");
}

#[test]
fn profile_get_deltat() {
    let p = Profile::parse("[libdefaults]\nrequest_timeout = 10\n").unwrap();
    assert_eq!(p.get_deltat(&["libdefaults", "request_timeout"], 0).unwrap(), 10);
    assert_eq!(p.get_deltat(&["libdefaults", "absent"], 7).unwrap(), 7);
    let p = Profile::parse("[libdefaults]\nr = bogus\n").unwrap();
    assert!(p.get_deltat(&["libdefaults", "r"], 0).is_err());
}
