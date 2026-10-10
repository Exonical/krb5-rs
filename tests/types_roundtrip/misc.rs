// --- Cross-decode test: verify BER decoder can read DER output ---

#[test]
fn test_ber_can_decode_der_ticket() {
    let ticket = Ticket {
        tkt_vno: 5,
        realm: make_realm(),
        sname: make_srv_principal(),
        enc_part: make_encrypted_data(),
    };
    let der_bytes = der::encode(&ticket).unwrap();
    let ber_decoded: Ticket = ber::decode(&der_bytes).unwrap();
    let re_encoded = der::encode(&ber_decoded).unwrap();
    assert_eq!(der_bytes, re_encoded);
}

// --- EncryptionKey zeroize test ---

#[test]
fn test_encryption_key_zeroize() {
    let mut key = make_encryption_key();
    assert_eq!(key.key_bytes().len(), 6);
    assert_ne!(
        key.key_bytes(),
        &[0u8; 6],
        "key should not be zero before zeroize"
    );
    key.zeroize();
    assert_eq!(key.keytype, 0, "keytype must be zeroed");
    // Vec::zeroize() zeroes bytes in-place then clears the vec (len=0).
    // This is correct — key material was wiped before truncation,
    // and clearing length prevents leaking even the key size.
    assert!(
        key.key_bytes().is_empty(),
        "key_bytes must be empty after zeroize (zeroed then cleared)"
    );
}

#[test]
fn test_encryption_key_debug_redacted() {
    let key = make_encryption_key();
    let debug_output = format!("{:?}", key);
    assert!(
        debug_output.contains("redacted"),
        "Debug output must redact key bytes, got: {debug_output}"
    );
    assert!(
        !debug_output.contains("\\xaa"),
        "Debug output must not contain escaped hex key bytes"
    );
    assert!(
        !debug_output.to_lowercase().contains("0xaa"),
        "Debug output must not contain hex key bytes"
    );
}

// --- FromStr tests for PrincipalName ---

#[test]
fn test_principal_from_str_simple() {
    let p: PrincipalName = "testuser".parse().expect("parse simple principal");
    assert_eq!(p.name_type, 1); // NT_PRINCIPAL
    assert_eq!(p.name_string.len(), 1);
    assert_eq!(p.to_string(), "testuser");
}

#[test]
fn test_principal_from_str_service() {
    let p: PrincipalName = "krbtgt/EXAMPLE.COM"
        .parse()
        .expect("parse service principal");
    // FromStr uses NT_SRV_HST (3) for two-component principals.
    // Use new_srv_inst() directly for NT_SRV_INST (2) krbtgt-style.
    assert_eq!(p.name_type, 3); // NT_SRV_HST
    assert_eq!(p.name_string.len(), 2);
    assert_eq!(p.to_string(), "krbtgt/EXAMPLE.COM");
}

#[test]
fn test_principal_from_str_with_realm() {
    let p: PrincipalName = "user@EXAMPLE.COM"
        .parse()
        .expect("parse principal with realm");
    assert_eq!(p.name_type, 1); // NT_PRINCIPAL
    assert_eq!(p.name_string.len(), 1);
    assert_eq!(p.to_string(), "user"); // realm stripped
}

#[test]
fn test_principal_from_str_service_with_realm() {
    let p: PrincipalName = "HTTP/web.example.com@EXAMPLE.COM"
        .parse()
        .expect("parse SPN with realm");
    assert_eq!(p.name_type, 3); // NT_SRV_HST — consistent with new_srv_hst()
    assert_eq!(p.name_string.len(), 2);
    assert_eq!(p.to_string(), "HTTP/web.example.com");
}

#[test]
fn test_principal_from_str_empty() {
    let result = "".parse::<PrincipalName>();
    assert!(result.is_err());
}

#[test]
fn test_principal_from_str_at_only() {
    let result = "@REALM".parse::<PrincipalName>();
    assert!(result.is_err());
}

#[test]
fn test_principal_from_str_multiple_at() {
    let result = "user@REALM@EXTRA".parse::<PrincipalName>();
    assert!(result.is_err());
}

#[test]
fn test_principal_from_str_trailing_slash() {
    let result = "service/".parse::<PrincipalName>();
    assert!(result.is_err());
}

#[test]
fn test_principal_from_str_leading_slash() {
    let result = "/host".parse::<PrincipalName>();
    assert!(result.is_err());
}

#[test]
fn test_principal_from_str_double_slash() {
    let result = "a//b".parse::<PrincipalName>();
    assert!(result.is_err());
}

#[test]
fn test_principal_from_str_roundtrip() {
    // Parse and re-display should be consistent
    let original = "HTTP/host.example.com";
    let p: PrincipalName = original.parse().expect("parse");
    assert_eq!(p.to_string(), original);
    roundtrip_eq(&p);
}

// --- Type alias tests ---

#[test]
fn test_method_data_roundtrip() {
    let md: MethodData = vec![
        PaData {
            padata_type: 19,
            padata_value: OctetString::from(vec![0x30, 0x00]),
        },
        PaData {
            padata_type: 2,
            padata_value: OctetString::from(vec![0x30, 0x03]),
        },
    ];
    // MethodData is Vec<PaData> — encode as SEQUENCE OF
    let encoded = der::encode(&md).expect("encode MethodData");
    let decoded: MethodData = der::decode(&encoded).expect("decode MethodData");
    assert_eq!(decoded.len(), 2);
    assert_eq!(decoded[0].padata_type, 19);
    assert_eq!(decoded[1].padata_type, 2);
}

#[test]
fn test_etype_info2_roundtrip() {
    let info: EtypeInfo2 = vec![
        EtypeInfo2Entry {
            etype: 18,
            salt: Some(GeneralString::from_bytes(b"EXAMPLE.COMuser").expect("valid")),
            s2kparams: None,
        },
        EtypeInfo2Entry {
            etype: 17,
            salt: None,
            s2kparams: None,
        },
    ];
    let encoded = der::encode(&info).expect("encode EtypeInfo2");
    let decoded: EtypeInfo2 = der::decode(&encoded).expect("decode EtypeInfo2");
    assert_eq!(decoded.len(), 2);
    assert_eq!(decoded[0].etype, 18);
    assert_eq!(decoded[1].etype, 17);
}

// --- EncTicketPart roundtrip (complex type with many optional fields) ---

#[test]
fn test_enc_ticket_part_roundtrip() {
    let etp = EncTicketPart {
        flags: make_ticket_flags(),
        key: make_encryption_key(),
        crealm: make_realm(),
        cname: make_principal(),
        transited: TransitedEncoding {
            tr_type: 1,
            contents: OctetString::from(b"".to_vec()),
        },
        authtime: make_time(),
        starttime: Some(make_time()),
        endtime: make_time(),
        renew_till: Some(make_time()),
        caddr: None,
        authorization_data: Some(vec![AuthorizationDataElement {
            ad_type: 1,
            ad_data: OctetString::from(vec![0x30, 0x00]),
        }]),
    };
    roundtrip(&etp);
}

// --- KrbCredInfo roundtrip ---

#[test]
fn test_krb_cred_info_roundtrip() {
    let info = KrbCredInfo {
        key: make_encryption_key(),
        prealm: Some(make_realm()),
        pname: Some(make_principal()),
        flags: Some(make_ticket_flags()),
        authtime: Some(make_time()),
        starttime: None,
        endtime: Some(make_time()),
        renew_till: None,
        srealm: Some(make_realm()),
        sname: Some(make_srv_principal()),
        caddr: None,
    };
    roundtrip(&info);
}

// --- EncKrbCredPart roundtrip ---

#[test]
fn test_enc_krb_cred_part_roundtrip() {
    let part = EncKrbCredPart {
        ticket_info: vec![KrbCredInfo {
            key: make_encryption_key(),
            prealm: None,
            pname: None,
            flags: None,
            authtime: None,
            starttime: None,
            endtime: None,
            renew_till: None,
            srealm: None,
            sname: None,
            caddr: None,
        }],
        nonce: Some(42),
        timestamp: Some(make_time()),
        usec: Some(0),
        s_address: None,
        r_address: None,
    };
    roundtrip(&part);
}

// --- KrbFastResponse roundtrip ---

#[test]
fn test_krb_fast_response_roundtrip() {
    let resp = KrbFastResponse {
        padata: vec![PaData {
            padata_type: 136,
            padata_value: OctetString::from(vec![0x01]),
        }],
        strengthen_key: Some(make_encryption_key()),
        finished: Some(KrbFastFinished {
            timestamp: make_time(),
            usec: 0,
            crealm: make_realm(),
            cname: make_principal(),
            ticket_checksum: make_checksum(),
        }),
        nonce: 99,
    };
    roundtrip(&resp);
}

// --- Additional enum conversion tests ---

#[test]
fn test_message_type_conversion() {
    assert_eq!(MessageType::try_from(10), Ok(MessageType::AsReq));
    assert_eq!(MessageType::try_from(30), Ok(MessageType::KrbError));
    assert_eq!(MessageType::try_from(99), Err(99));
}

#[test]
fn test_pa_data_type_conversion() {
    assert_eq!(PaDataType::try_from(2), Ok(PaDataType::EncTimestamp));
    assert_eq!(PaDataType::try_from(19), Ok(PaDataType::EtypeInfo2));
    assert_eq!(PaDataType::try_from(128), Ok(PaDataType::PaPacRequest));
    assert_eq!(PaDataType::try_from(999), Err(999));
}

#[test]
fn test_auth_data_type_conversion() {
    assert_eq!(AuthDataType::try_from(1), Ok(AuthDataType::IfRelevant));
    assert_eq!(AuthDataType::try_from(128), Ok(AuthDataType::Win2kPac));
}

#[test]
fn test_lr_type_conversion() {
    assert_eq!(LrType::try_from(6), Ok(LrType::PasswordExpires));
    assert_eq!(LrType::try_from(100), Err(100));
}
