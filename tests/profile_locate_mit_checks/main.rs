//! MIT krb5 1.22.2 profile + KDC-location semantics checks: krb5.conf
//! parsing (prof_parse.c/prof_get.c vectors incl. test.ini verbatim),
//! host→realm mapping (hostrealm_profile.c, hostrealm_domain.c,
//! ref_std_conf.out oracle), host-string parsing (t_parse_host_string.c
//! verbatim), and KDC location order (locate_kdc.c, dnssrv.c).

use krb5_rs::locate::*;
use krb5_rs::profile::*;

include!("profile.rs");
include!("hostrealm.rs");
include!("host_string.rs");
include!("locate.rs");
include!("dns.rs");

// ---------------------------------------------------------------------------
// Shared fixtures
// ---------------------------------------------------------------------------

/// util/profile/test.ini verbatim.
const TEST_INI: &str = "this is a comment.  Everything up to the first square brace is ignored.

[test section 2]
\ttest_child = \"foo\\nbar\"
\tchild_section2 = \"one\"
\tchild_section2 = {
\t\tchild = slick
\t\tchild = harry
\t\tchild = \"john\\tb \"
\t}
\tchild_section2 = foo

[test section 2]
\tchild_section2 = {
\t\tchild = ron
\t\tchores = cleaning
\t}

[realms]
ATHENA.MIT.EDU = {
\tserver = KERBEROS.MIT.EDU:88
\tserver = KERBEROS1.MIT.EDU
\tserver = KERBEROS2.MIT.EDU
\tadmin = KERBEROS.MIT.EDU
\tetype = DES-MD5
}
\t


[test section 1]
    foo = \"bar \"

[test section 2]
\tquux = \"bar\"
\tfrep = bar
\tkappa = alpha
\tbeta = epsilon

[test section 1]
    bar = foo
\tfoo = bar2
    quux = zap
\tfoo = bar3
\tchild_section = {
\t\tchild = slick
\t\tchild = harry
\t\tchild = john
\t}
\tchild_section = foo
";

/// lib/krb5/os/td_krb5.conf verbatim (the t_std_conf oracle input).
const TD_KRB5_CONF: &str = "[libdefaults]
\tdefault_realm = DEFAULT.REALM.TST

[realms]
\tDEFAULT_REALM.TST = {
\t\tkdc = FIRST.KDC.HOST
\t\tkdc = SECOND.KDC.HOST:88
\t\tadmin_server = FIRST.KDC.HOST
\t\tdefault_domain = MIT.EDU
\t}
\tIGGY.ORG = {
\t\tkdc = KERBEROS.IGGY.ORG
\t\tkdc = KERBEROS-B.IGGY.ORG
\t}

[domain_realm]
\tbad.idea = US.GOV
\t.bad.idea = NSA.GOV
\tclipper.bad.idea = NIST.GOV
";

fn td_profile() -> Profile {
    Profile::parse(TD_KRB5_CONF).expect("td_krb5.conf parses")
}

fn tmpdir() -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("krb5rs_prof_{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("mkdir");
    dir
}
