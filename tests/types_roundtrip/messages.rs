// --- KRB-ERROR test ---

#[test]
fn test_krb_error_msg_roundtrip() {
    let err = KrbErrorMsg {
        pvno: 5,
        msg_type: 30,
        ctime: None,
        cusec: None,
        stime: make_time(),
        susec: 0,
        error_code: 25, // PREAUTH_REQUIRED
        crealm: None,
        cname: None,
        realm: make_realm(),
        sname: make_srv_principal(),
        e_text: Some(GeneralString::from_bytes(b"Need preauth").expect("valid text")),
        e_data: Some(OctetString::from(vec![0x30, 0x00])),
    };
    roundtrip(&err);
}

#[test]
fn test_krb_error_application_tag() {
    let err = KrbErrorMsg {
        pvno: 5,
        msg_type: 30,
        ctime: None,
        cusec: None,
        stime: make_time(),
        susec: 0,
        error_code: 6,
        crealm: None,
        cname: None,
        realm: make_realm(),
        sname: make_srv_principal(),
        e_text: None,
        e_data: None,
    };
    let encoded = der::encode(&err).unwrap();
    // APPLICATION 30 = 0x7e (constructed)
    assert_eq!(
        encoded[0], 0x7e,
        "KRB-ERROR should have APPLICATION 30 tag (0x7e)"
    );
}

// --- Safe/Priv/Cred tests ---

#[test]
fn test_krb_safe_roundtrip() {
    let safe = KrbSafe {
        pvno: 5,
        msg_type: 20,
        safe_body: KrbSafeBody {
            user_data: OctetString::from(b"hello".to_vec()),
            timestamp: Some(make_time()),
            usec: Some(100),
            seq_number: Some(1),
            s_address: HostAddress {
                addr_type: 2,
                address: OctetString::from(vec![10, 0, 0, 1]),
            },
            r_address: None,
        },
        cksum: make_checksum(),
    };
    roundtrip(&safe);
}

#[test]
fn test_krb_cred_roundtrip() {
    let cred = KrbCred {
        pvno: 5,
        msg_type: 22,
        tickets: vec![Ticket {
            tkt_vno: 5,
            realm: make_realm(),
            sname: make_srv_principal(),
            enc_part: make_encrypted_data(),
        }],
        enc_part: make_encrypted_data(),
    };
    roundtrip(&cred);
}

// --- FAST type tests ---

#[test]
fn test_krb_fast_armor_roundtrip() {
    let armor = KrbFastArmor {
        armor_type: 1,
        armor_value: OctetString::from(vec![0xde, 0xad, 0xbe, 0xef]),
    };
    roundtrip(&armor);
}

#[test]
fn test_pa_fx_fast_request_roundtrip() {
    let req = PaFxFastRequest::ArmoredData(KrbFastArmoredReq {
        armor: Some(KrbFastArmor {
            armor_type: 1,
            armor_value: OctetString::from(vec![0x01]),
        }),
        req_checksum: make_checksum(),
        enc_fast_req: make_encrypted_data(),
    });
    roundtrip(&req);
}

#[test]
fn test_kdc_proxy_message_roundtrip() {
    let msg = KdcProxyMessage {
        kerb_message: OctetString::from(vec![0x6a, 0x10, 0x00]),
        target_domain: Some(make_realm()),
        dclocator_hint: None,
    };
    roundtrip(&msg);
}

// --- Flags tests ---

#[test]
fn test_kdc_options_flags() {
    let opts = KdcOptions::FORWARDABLE | KdcOptions::RENEWABLE | KdcOptions::CANONICALIZE;
    let bytes = Flags::to_bytes(&opts);
    let restored = KdcOptions::from_bytes(&bytes);
    assert_eq!(opts, restored);
    assert!(restored.contains(KdcOptions::FORWARDABLE));
    assert!(restored.contains(KdcOptions::RENEWABLE));
    assert!(restored.contains(KdcOptions::CANONICALIZE));
    assert!(!restored.contains(KdcOptions::PROXIABLE));
}

#[test]
fn test_ticket_flags() {
    let flags = TicketFlags::FORWARDABLE | TicketFlags::INITIAL | TicketFlags::PRE_AUTHENT;
    let bytes = Flags::to_bytes(&flags);
    let restored = TicketFlags::from_bytes(&bytes);
    assert_eq!(flags, restored);
}

#[test]
fn test_ap_options_flags() {
    let opts = ApOptions::MUTUAL_REQUIRED;
    let bytes = Flags::to_bytes(&opts);
    let restored = ApOptions::from_bytes(&bytes);
    assert_eq!(opts, restored);
    assert!(restored.contains(ApOptions::MUTUAL_REQUIRED));
    assert!(!restored.contains(ApOptions::USE_SESSION_KEY));
}

#[test]
fn test_kerberos_flags_wrapper_roundtrip() {
    // KerberosFlags<T> should round-trip through DER as BIT STRING
    let kdc_flags = KerberosFlags::from(
        KdcOptions::FORWARDABLE | KdcOptions::RENEWABLE | KdcOptions::CANONICALIZE,
    );
    roundtrip_eq(&kdc_flags);

    let ticket_flags = KerberosFlags::from(
        TicketFlags::INITIAL | TicketFlags::PRE_AUTHENT | TicketFlags::FORWARDABLE,
    );
    roundtrip_eq(&ticket_flags);

    let ap_flags = KerberosFlags::from(ApOptions::MUTUAL_REQUIRED);
    roundtrip_eq(&ap_flags);
}

#[test]
fn test_kerberos_flags_deref() {
    // Deref allows direct bitflags operations on the wrapper
    let flags = KerberosFlags::from(KdcOptions::FORWARDABLE | KdcOptions::RENEWABLE);
    assert!(flags.contains(KdcOptions::FORWARDABLE));
    assert!(flags.contains(KdcOptions::RENEWABLE));
    assert!(!flags.contains(KdcOptions::PROXIABLE));
}

#[test]
fn test_kerberos_flags_deref_mut() {
    // DerefMut allows in-place modification
    let mut flags = KerberosFlags::from(KdcOptions::FORWARDABLE);
    flags.insert(KdcOptions::RENEWABLE);
    assert!(flags.contains(KdcOptions::FORWARDABLE));
    assert!(flags.contains(KdcOptions::RENEWABLE));
}

#[test]
fn test_kerberos_flags_default_is_empty() {
    let flags = KerberosFlags::<KdcOptions>::default();
    assert!(flags.is_empty());
}

#[test]
fn test_kerberos_flags_type_safety() {
    // KerberosFlags<KdcOptions> and KerberosFlags<TicketFlags> are distinct types.
    // This test verifies the typed wrapper encodes correctly for each flag type.
    let kdc = KerberosFlags::from(KdcOptions::FORWARDABLE);
    let ticket = KerberosFlags::from(TicketFlags::FORWARDABLE);

    let kdc_encoded = der::encode(&kdc).unwrap();
    let ticket_encoded = der::encode(&ticket).unwrap();

    // Both FORWARDABLE are bit 1 (same position), so encoding should match
    assert_eq!(kdc_encoded, ticket_encoded);

    // But you cannot accidentally assign one to the other at compile time:
    // let _bad: KerberosFlags<KdcOptions> = ticket;  // won't compile
}

#[test]
fn test_kerberos_flags_rejects_oversized_bitstring() {
    // A BIT STRING longer than 32 bits must be rejected during decode
    let oversized = BitString::from_slice(&[0x40, 0x00, 0x00, 0x00, 0x01]);
    let encoded = der::encode(&oversized).unwrap();
    let result = der::decode::<KerberosFlags<KdcOptions>>(&encoded);
    assert!(result.is_err());
}

// --- Enum conversion tests ---

#[test]
fn test_name_type_conversion() {
    assert_eq!(NameType::try_from(1), Ok(NameType::Principal));
    assert_eq!(NameType::try_from(10), Ok(NameType::Enterprise));
    assert_eq!(NameType::try_from(999), Err(999));
}

#[test]
fn test_enc_type_conversion() {
    assert_eq!(EncType::try_from(18), Ok(EncType::Aes256CtsHmacSha196));
    assert_eq!(EncType::try_from(23), Ok(EncType::Rc4Hmac));
    assert_eq!(EncType::try_from(-1), Err(-1));
}

#[test]
fn test_cksum_type_conversion() {
    assert_eq!(CksumType::try_from(-138), Ok(CksumType::HmacMd5));
    assert_eq!(CksumType::try_from(16), Ok(CksumType::HmacSha196Aes256));
}

