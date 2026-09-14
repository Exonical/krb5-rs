// ---------------------------------------------------------------------------
// Section 3: host-string parsing (lib/krb5/krb/t_parse_host_string.c verbatim)
// ---------------------------------------------------------------------------

fn phs(s: &str, dfl: u16) -> Result<(Option<String>, u16), LocateError> {
    parse_host_string(s, dfl)
}

fn ok(s: &str, dfl: u16, e_host: Option<&str>, e_port: u16) {
    let (h, p) = phs(s, dfl).unwrap_or_else(|e| panic!("{s:?} -> {e:?}"));
    assert_eq!(h.as_deref(), e_host, "{s:?} host");
    assert_eq!(p, e_port, "{s:?} port");
}

#[test]
fn host_string_valid_vectors() {
    // t_parse_host_string.c:67-131, verbatim.
    ok("test.example", 50, Some("test.example"), 50);
    ok("test.example:75", 0, Some("test.example"), 75);
    ok("192.168.1.1", 100, Some("192.168.1.1"), 100);
    ok("192.168.1.1:150", 0, Some("192.168.1.1"), 150);
    ok(
        "[BEEF:CAFE:FEED:FACE:DEAD:BEEF:DEAF:BABE]",
        200,
        Some("BEEF:CAFE:FEED:FACE:DEAD:BEEF:DEAF:BABE"),
        200,
    );
    ok(
        "[BEEF:CAFE:FEED:FACE:DEAD:BEEF:DEAF:BABE]:250",
        0,
        Some("BEEF:CAFE:FEED:FACE:DEAD:BEEF:DEAF:BABE"),
        250,
    );
    ok(
        "[BEEF:CAFE:FEED:FACE:DEAD:BEEF:DEAF:BABE%eth0]",
        275,
        Some("BEEF:CAFE:FEED:FACE:DEAD:BEEF:DEAF:BABE%eth0"),
        275,
    );
    ok("350", 0, None, 350);
}

#[test]
fn host_string_invalid_vectors() {
    // t_parse_host_string.c:115-162, verbatim. Our API takes &str, so the
    // NULL case is covered by the empty-string and check() paths.
    assert!(phs("BEEF:CAFE:FEED:FACE:DEAD:BEEF:DEAF:BABE", 1).is_err());
    assert!(phs(":300", 0).is_err());
    assert!(phs("", 450).is_err());
    assert!(phs("70000", 1).is_err());
    assert!(phs("test.example:F101", 1).is_err());
}

#[test]
fn host_string_numeric_helper() {
    // t_parse_host_string.c:167-205, verbatim.
    assert!(is_string_numeric("0"));
    assert!(is_string_numeric("0123456789"));
    assert!(!is_string_numeric("012345F6789"));
    assert!(!is_string_numeric("123.456"));
    assert!(!is_string_numeric("-123"));
    assert!(!is_string_numeric(""));
    assert!(!is_string_numeric("123 456"));
}
