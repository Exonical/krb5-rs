//! Round-trip DER encode/decode tests for all Kerberos ASN.1 types.
//!
//! Each test constructs a value, encodes it to DER, decodes it back,
//! re-encodes, and verifies the bytes match (canonical DER property).

use rasn::prelude::*;
use rasn::{ber, der};

use chrono::{TimeZone, Utc};
use krb5_rs::types::*;
use zeroize::Zeroize;

/// Helper: encode to DER, decode back, re-encode, assert bytes match.
fn roundtrip<T: rasn::Encode + rasn::Decode + core::fmt::Debug>(value: &T) {
    let encoded = der::encode(value).expect("DER encode failed");
    let decoded: T = der::decode(&encoded).expect("DER decode failed");
    let re_encoded = der::encode(&decoded).expect("DER re-encode failed");
    assert_eq!(encoded, re_encoded, "Round-trip mismatch for {:?}", decoded);
}

/// Helper: roundtrip with semantic equality check for types implementing PartialEq.
fn roundtrip_eq<T: rasn::Encode + rasn::Decode + core::fmt::Debug + PartialEq>(value: &T) {
    let encoded = der::encode(value).expect("DER encode failed");
    let decoded: T = der::decode(&encoded).expect("DER decode failed");
    assert_eq!(&decoded, value, "Semantic mismatch after decode");
    let re_encoded = der::encode(&decoded).expect("DER re-encode failed");
    assert_eq!(encoded, re_encoded, "Round-trip mismatch for {:?}", decoded);
}

fn make_realm() -> Realm {
    GeneralString::from_bytes(b"EXAMPLE.COM").expect("valid realm")
}

fn make_principal() -> PrincipalName {
    PrincipalName::new_principal("testuser")
}

fn make_srv_principal() -> PrincipalName {
    PrincipalName::new_srv_inst("krbtgt", "EXAMPLE.COM")
}

fn make_encrypted_data() -> EncryptedData {
    EncryptedData {
        etype: 18, // AES256
        kvno: Some(2),
        cipher: OctetString::from(vec![0x01, 0x02, 0x03, 0x04]),
    }
}

fn make_encryption_key() -> EncryptionKey {
    EncryptionKey::new(18, vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])
}

fn make_checksum() -> Checksum {
    Checksum {
        cksumtype: 16,
        checksum: OctetString::from(vec![0x11, 0x22, 0x33]),
    }
}

fn make_time() -> KerberosTime {
    Utc.with_ymd_and_hms(2026, 3, 15, 12, 0, 0)
        .unwrap()
        .fixed_offset()
}

fn make_kdc_options() -> KerberosFlags<KdcOptions> {
    KerberosFlags::from(KdcOptions::FORWARDABLE | KdcOptions::RENEWABLE)
}

fn make_ticket_flags() -> KerberosFlags<TicketFlags> {
    KerberosFlags::from(TicketFlags::FORWARDABLE | TicketFlags::RENEWABLE)
}

fn make_ap_options() -> KerberosFlags<ApOptions> {
    KerberosFlags::from(ApOptions::MUTUAL_REQUIRED)
}

include!("basic.rs");
include!("messages.rs");
include!("misc.rs");
