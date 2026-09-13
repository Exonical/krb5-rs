//! MIT krb5 1.22.2 ccache/keytab semantics checks: FILE v1-4 ccache
//! marshalling (t_marshal.c vectors verbatim), file/memory ccache
//! behavior (cc_file.c, ccfns.c, cc_retr.c), and keytab file v1/v2
//! behavior (t_keytab.c, kt_file.c). Uses only the public API.

use krb5_rs::ccache::marshal::*;
use krb5_rs::ccache::*;
use krb5_rs::keytab::*;
use krb5_rs::protocol::ap::{ApReqOptions, AuthContext};
use krb5_rs::protocol::{Credential, TicketTimes};
use krb5_rs::types::*;
use krb5_rs::Krb5Error;
use rasn::types::{GeneralString, OctetString};

include!("marshal.rs");
include!("file_cc.rs");
include!("retrieve.rs");
include!("keytab.rs");

// ---------------------------------------------------------------------------
// t_marshal.c test vectors (verbatim, little-endian host for v1/v2)
// ---------------------------------------------------------------------------

const V1_HEADER: &[u8] = b"\x05\x01";
const V1_PRINC: &[u8] = b"\x02\x00\x00\x00\x0B\x00\x00\x00KRBTEST.COM\x0A\x00\x00\x00testclient";
const V1_CRED1: &[u8] = b"\x02\x00\x00\x00\x0B\x00\x00\x00KRBTEST.COM\x0A\x00\x00\x00testclient\x03\x00\x00\x00\x0B\x00\x00\x00EXAMPLE.COM\x04\x00\x00\x00test\x04\x00\x00\x00host\x11\x00\x10\x00\x00\x00\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x0B\x00\x00\x00\xDE\x00\x00\x00\x05\x0D\x00\x00\x00\xCA\x9A\x3B\x00\x00\x00\x80\x40\x01\x00\x00\x00\x02\x00\x04\x00\x00\x00\x0A\x00\x00\x01\x02\x00\x00\x00\x00\x02\x0A\x00\x00\x00signticket\x9C\xFF\x00\x00\x00\x00\x06\x00\x00\x00ticket\x00\x00\x00\x00";
const V1_CRED2: &[u8] = b"\x02\x00\x00\x00\x0B\x00\x00\x00\x4B\x52\x42\x54\x45\x53\x54\x2E\x43\x4F\x4D\x0A\x00\x00\x00\x74\x65\x73\x74\x63\x6C\x69\x65\x6E\x74\x01\x00\x00\x00\x00\x00\x00\x00\x17\x00\x10\x00\x00\x00\x0F\x0E\x0D\x0C\x0B\x0A\x09\x08\x07\x06\x05\x04\x03\x02\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x06\x00\x00\x00\x74\x69\x63\x6B\x65\x74\x07\x00\x00\x00\x32\x74\x69\x63\x6B\x65\x74";

const V2_HEADER: &[u8] = b"\x05\x02";
const V2_PRINC: &[u8] =
    b"\x01\x00\x00\x00\x01\x00\x00\x00\x0B\x00\x00\x00KRBTEST.COM\x0A\x00\x00\x00testclient";
const V2_CRED1: &[u8] = b"\x01\x00\x00\x00\x01\x00\x00\x00\x0B\x00\x00\x00KRBTEST.COM\x0A\x00\x00\x00testclient\x01\x00\x00\x00\x02\x00\x00\x00\x0B\x00\x00\x00EXAMPLE.COM\x04\x00\x00\x00test\x04\x00\x00\x00host\x11\x00\x10\x00\x00\x00\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x0B\x00\x00\x00\xDE\x00\x00\x00\x05\x0D\x00\x00\x00\xCA\x9A\x3B\x00\x00\x00\x80\x40\x01\x00\x00\x00\x02\x00\x04\x00\x00\x00\x0A\x00\x00\x01\x02\x00\x00\x00\x00\x02\x0A\x00\x00\x00signticket\x9C\xFF\x00\x00\x00\x00\x06\x00\x00\x00ticket\x00\x00\x00\x00";
const V2_CRED2: &[u8] = b"\x01\x00\x00\x00\x01\x00\x00\x00\x0B\x00\x00\x00\x4B\x52\x42\x54\x45\x53\x54\x2E\x43\x4F\x4D\x0A\x00\x00\x00\x74\x65\x73\x74\x63\x6C\x69\x65\x6E\x74\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x17\x00\x10\x00\x00\x00\x0F\x0E\x0D\x0C\x0B\x0A\x09\x08\x07\x06\x05\x04\x03\x02\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x06\x00\x00\x00\x74\x69\x63\x6B\x65\x74\x07\x00\x00\x00\x32\x74\x69\x63\x6B\x65\x74";

const V3_HEADER: &[u8] = b"\x05\x03";
const V3_PRINC: &[u8] =
    b"\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x0BKRBTEST.COM\x00\x00\x00\x0Atestclient";
const V3_CRED1: &[u8] = b"\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x0BKRBTEST.COM\x00\x00\x00\x0Atestclient\x00\x00\x00\x01\x00\x00\x00\x02\x00\x00\x00\x0BEXAMPLE.COM\x00\x00\x00\x04test\x00\x00\x00\x04host\x00\x11\x00\x11\x00\x00\x00\x10\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x00\x00\x00\x0B\x00\x00\x00\xDE\x00\x00\x0D\x05\x3B\x9A\xCA\x00\x00\x40\x80\x00\x00\x00\x00\x00\x01\x00\x02\x00\x00\x00\x04\x0A\x00\x00\x01\x00\x00\x00\x02\x02\x00\x00\x00\x00\x0Asignticket\xFF\x9C\x00\x00\x00\x00\x00\x00\x00\x06ticket\x00\x00\x00\x00";
const V3_CRED2: &[u8] = b"\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x0B\x4B\x52\x42\x54\x45\x53\x54\x2E\x43\x4F\x4D\x00\x00\x00\x0A\x74\x65\x73\x74\x63\x6C\x69\x65\x6E\x74\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x17\x00\x17\x00\x00\x00\x10\x0F\x0E\x0D\x0C\x0B\x0A\x09\x08\x07\x06\x05\x04\x03\x02\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x06\x74\x69\x63\x6B\x65\x74\x00\x00\x00\x07\x32\x74\x69\x63\x6B\x65\x74";

const V4_HEADER: &[u8] = b"\x05\x04\x00\x0C\x00\x01\x00\x08\x00\x00\x01\x2C\x00\x00\xD4\x31";
const V4_PRINC: &[u8] =
    b"\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x0BKRBTEST.COM\x00\x00\x00\x0Atestclient";
const V4_CRED1: &[u8] = b"\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x0BKRBTEST.COM\x00\x00\x00\x0Atestclient\x00\x00\x00\x01\x00\x00\x00\x02\x00\x00\x00\x0BEXAMPLE.COM\x00\x00\x00\x04test\x00\x00\x00\x04host\x00\x11\x00\x00\x00\x10\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x00\x00\x00\x0B\x00\x00\x00\xDE\x00\x00\x0D\x05\x3B\x9A\xCA\x00\x00\x40\x80\x00\x00\x00\x00\x00\x01\x00\x02\x00\x00\x00\x04\x0A\x00\x00\x01\x00\x00\x00\x02\x02\x00\x00\x00\x00\x0Asignticket\xFF\x9C\x00\x00\x00\x00\x00\x00\x00\x06ticket\x00\x00\x00\x00";
const V4_CRED2: &[u8] = b"\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x0B\x4B\x52\x42\x54\x45\x53\x54\x2E\x43\x4F\x4D\x00\x00\x00\x0A\x74\x65\x73\x74\x63\x6C\x69\x65\x6E\x74\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x17\x00\x00\x00\x10\x0F\x0E\x0D\x0C\x0B\x0A\x09\x08\x07\x06\x05\x04\x03\x02\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x06\x74\x69\x63\x6B\x65\x74\x00\x00\x00\x07\x32\x74\x69\x63\x6B\x65\x74";

const HEADERS: [&[u8]; 4] = [V1_HEADER, V2_HEADER, V3_HEADER, V4_HEADER];
const PRINCS: [&[u8]; 4] = [V1_PRINC, V2_PRINC, V3_PRINC, V4_PRINC];
const CRED1S: [&[u8]; 4] = [V1_CRED1, V2_CRED1, V3_CRED1, V4_CRED1];
const CRED2S: [&[u8]; 4] = [V1_CRED2, V2_CRED2, V3_CRED2, V4_CRED2];

// ---------------------------------------------------------------------------
// Shared fixture builders
// ---------------------------------------------------------------------------

fn gs(b: &[u8]) -> GeneralString {
    GeneralString::from_bytes(b).expect("general string")
}

/// testclient@KRBTEST.COM (the default principal of the test caches).
fn test_princ() -> (PrincipalName, String) {
    (
        PrincipalName {
            name_type: 1,
            name_string: vec![gs(b"testclient")],
        },
        "KRBTEST.COM".to_string(),
    )
}

fn princ(comps: &[&[u8]], name_type: i32) -> PrincipalName {
    PrincipalName {
        name_type,
        name_string: comps.iter().map(|c| gs(c)).collect(),
    }
}

/// The credential matching t_marshal.c `verify_cred1`.
fn cred1() -> CcCredential {
    let (client, crealm) = test_princ();
    CcCredential {
        client,
        crealm,
        server: princ(&[b"test", b"host"], 1),
        srealm: "EXAMPLE.COM".to_string(),
        keyblock: EncryptionKey::new(17, (0u8..16).collect()),
        authtime: 11,
        starttime: 222,
        endtime: 3333,
        renew_till: 1_000_000_000,
        is_skey: false,
        ticket_flags: 0x4080_0000,
        addresses: vec![HostAddress {
            addr_type: 2,
            address: OctetString::from(vec![10, 0, 0, 1]),
        }],
        authdata: vec![
            AuthorizationDataElement {
                ad_type: 512,
                ad_data: OctetString::from(b"signticket".to_vec()),
            },
            AuthorizationDataElement {
                ad_type: -100,
                ad_data: OctetString::from(Vec::new()),
            },
        ],
        ticket: b"ticket".to_vec(),
        second_ticket: Vec::new(),
    }
}

/// The credential matching t_marshal.c `verify_cred2`.
fn cred2() -> CcCredential {
    let (client, crealm) = test_princ();
    CcCredential {
        client,
        crealm,
        server: princ(&[], 1),
        srealm: String::new(),
        keyblock: EncryptionKey::new(23, (0u8..16).rev().collect()),
        authtime: 0,
        starttime: 0,
        endtime: 0,
        renew_till: 0,
        is_skey: true,
        ticket_flags: 0,
        addresses: Vec::new(),
        authdata: Vec::new(),
        ticket: b"ticket".to_vec(),
        second_ticket: b"2ticket".to_vec(),
    }
}

/// verify_princ: testclient@KRBTEST.COM (one component, name type 1).
fn verify_princ(p: &PrincipalName, realm: &str) {
    assert_eq!(p.name_string.len(), 1);
    assert_eq!(realm, "KRBTEST.COM");
    assert_eq!(p.name_string[0].as_bytes(), b"testclient");
}

/// t_marshal.c verify_cred1, field for field.
fn verify_cred1(c: &CcCredential) {
    verify_princ(&c.client, &c.crealm);
    assert_eq!(c.server.name_string.len(), 2);
    assert_eq!(c.srealm, "EXAMPLE.COM");
    assert_eq!(c.server.name_string[0].as_bytes(), b"test");
    assert_eq!(c.server.name_string[1].as_bytes(), b"host");
    assert_eq!(c.keyblock.keytype, 17); // ENCTYPE_AES128_CTS_HMAC_SHA1_96
    assert_eq!(c.keyblock.key_bytes(), &(0u8..16).collect::<Vec<u8>>()[..]);
    assert_eq!(c.authtime, 11);
    assert_eq!(c.starttime, 222);
    assert_eq!(c.endtime, 3333);
    assert_eq!(c.renew_till, 1_000_000_000);
    assert!(!c.is_skey);
    // TKT_FLG_FORWARDABLE | TKT_FLG_RENEWABLE
    assert_eq!(c.ticket_flags, 0x4080_0000);
    assert_eq!(c.addresses.len(), 1);
    assert_eq!(c.addresses[0].addr_type, 2); // ADDRTYPE_INET
    assert_eq!(c.addresses[0].address.as_ref(), &[10, 0, 0, 1]);
    assert_eq!(c.authdata.len(), 2);
    assert_eq!(c.authdata[0].ad_type, 512); // KRB5_AUTHDATA_SIGNTICKET
    assert_eq!(c.authdata[0].ad_data.as_ref(), b"signticket");
    assert_eq!(c.authdata[1].ad_type, -100);
    assert_eq!(c.authdata[1].ad_data.len(), 0);
    assert_eq!(c.ticket, b"ticket");
    assert!(c.second_ticket.is_empty());
}

/// t_marshal.c verify_cred2, field for field.
fn verify_cred2(c: &CcCredential) {
    verify_princ(&c.client, &c.crealm);
    assert_eq!(c.server.name_string.len(), 0);
    assert_eq!(c.srealm, "");
    assert_eq!(c.keyblock.keytype, 23); // ENCTYPE_ARCFOUR_HMAC
    assert_eq!(
        c.keyblock.key_bytes(),
        &(0u8..16).rev().collect::<Vec<u8>>()[..]
    );
    assert_eq!(c.authtime, 0);
    assert_eq!(c.starttime, 0);
    assert_eq!(c.endtime, 0);
    assert_eq!(c.renew_till, 0);
    assert!(c.is_skey);
    assert_eq!(c.ticket_flags, 0);
    assert!(c.addresses.is_empty());
    assert!(c.authdata.is_empty());
    assert_eq!(c.ticket, b"ticket");
    assert_eq!(c.second_ticket, b"2ticket");
}

fn tmpdir_file(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("krb5rs_test_{}_{}", std::process::id(), name));
    std::fs::create_dir_all(&dir).expect("mkdir");
    dir.join(name)
}

/// Write `data` to a fresh temp file and return the path.
fn write_tmp(name: &str, data: &[u8]) -> std::path::PathBuf {
    let path = tmpdir_file(name);
    std::fs::write(&path, data).expect("write");
    path
}
