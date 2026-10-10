// --- Primitive/Basic type tests ---

#[test]
fn test_principal_name_roundtrip() {
    roundtrip_eq(&make_principal());
}

#[test]
fn test_principal_name_srv_inst_roundtrip() {
    roundtrip(&make_srv_principal());
}

#[test]
fn test_principal_name_srv_hst_roundtrip() {
    let p = PrincipalName::new_srv_hst("HTTP", "web.example.com");
    roundtrip_eq(&p);
    assert_eq!(p.to_string(), "HTTP/web.example.com");
}

#[test]
fn test_principal_name_display() {
    let p = PrincipalName::new_principal("user");
    assert_eq!(p.to_string(), "user");

    let s = PrincipalName::new_srv_inst("krbtgt", "EXAMPLE.COM");
    assert_eq!(s.to_string(), "krbtgt/EXAMPLE.COM");
}

#[test]
fn test_host_address_roundtrip() {
    let addr = HostAddress {
        addr_type: 2, // IPv4
        address: OctetString::from(vec![192, 168, 1, 1]),
    };
    roundtrip_eq(&addr);
}

#[test]
fn test_encrypted_data_roundtrip() {
    roundtrip(&make_encrypted_data());
}

#[test]
fn test_encrypted_data_no_kvno() {
    let ed = EncryptedData {
        etype: 17,
        kvno: None,
        cipher: OctetString::from(vec![0xaa]),
    };
    roundtrip(&ed);
}

#[test]
fn test_encryption_key_roundtrip() {
    roundtrip(&make_encryption_key());
}

#[test]
fn test_checksum_roundtrip() {
    roundtrip(&make_checksum());
}

#[test]
fn test_authorization_data_element_roundtrip() {
    let ade = AuthorizationDataElement {
        ad_type: 1,
        ad_data: OctetString::from(vec![0x00, 0x01]),
    };
    roundtrip(&ade);
}

#[test]
fn test_transited_encoding_roundtrip() {
    let te = TransitedEncoding {
        tr_type: 1,
        contents: OctetString::from(b"REALM-A,REALM-B".to_vec()),
    };
    roundtrip(&te);
}

#[test]
fn test_last_req_entry_roundtrip() {
    let lre = LastReqEntry {
        lr_type: 6,
        lr_value: make_time(),
    };
    roundtrip(&lre);
}

// --- Ticket tests ---

#[test]
fn test_ticket_roundtrip() {
    let ticket = Ticket {
        tkt_vno: 5,
        realm: make_realm(),
        sname: make_srv_principal(),
        enc_part: make_encrypted_data(),
    };
    roundtrip(&ticket);
}

#[test]
fn test_ticket_application_tag() {
    // Ticket has APPLICATION 1 tag. Verify encoding starts with 0x61 (constructed APPLICATION 1).
    let ticket = Ticket {
        tkt_vno: 5,
        realm: make_realm(),
        sname: make_srv_principal(),
        enc_part: make_encrypted_data(),
    };
    let encoded = der::encode(&ticket).unwrap();
    assert_eq!(
        encoded[0], 0x61,
        "Ticket should have APPLICATION 1 tag (0x61)"
    );
}

// --- Pre-auth tests ---

#[test]
fn test_pa_data_roundtrip() {
    let pad = PaData {
        padata_type: 2,
        padata_value: OctetString::from(vec![0x30, 0x05]),
    };
    roundtrip(&pad);
}

#[test]
fn test_pa_enc_ts_enc_roundtrip() {
    let ts = PaEncTsEnc {
        patimestamp: make_time(),
        pausec: Some(123456),
    };
    roundtrip(&ts);
}

#[test]
fn test_pa_enc_ts_enc_no_usec() {
    let ts = PaEncTsEnc {
        patimestamp: make_time(),
        pausec: None,
    };
    roundtrip(&ts);
}

#[test]
fn test_pa_pac_request_roundtrip() {
    let pac = PaPacRequest { include_pac: true };
    roundtrip(&pac);
    let pac_false = PaPacRequest { include_pac: false };
    roundtrip(&pac_false);
}

#[test]
fn test_etype_info2_entry_roundtrip() {
    let entry = EtypeInfo2Entry {
        etype: 18,
        salt: Some(GeneralString::from_bytes(b"EXAMPLE.COMtestuser").expect("valid salt")),
        s2kparams: None,
    };
    roundtrip(&entry);
}

// --- KDC exchange tests ---

#[test]
fn test_kdc_req_body_roundtrip() {
    let body = KdcReqBody {
        kdc_options: make_kdc_options(),
        cname: Some(make_principal()),
        realm: make_realm(),
        sname: Some(make_srv_principal()),
        from: None,
        till: make_time(),
        rtime: None,
        nonce: 12345678,
        etype: vec![18, 17],
        addresses: None,
        enc_authorization_data: None,
        additional_tickets: None,
    };
    roundtrip(&body);
}

#[test]
fn test_as_req_roundtrip() {
    let req = AsReq(KdcReq {
        pvno: 5,
        msg_type: 10,
        padata: None,
        req_body: KdcReqBody {
            kdc_options: make_kdc_options(),
            cname: Some(make_principal()),
            realm: make_realm(),
            sname: Some(make_srv_principal()),
            from: None,
            till: make_time(),
            rtime: None,
            nonce: 42,
            etype: vec![18, 17],
            addresses: None,
            enc_authorization_data: None,
            additional_tickets: None,
        },
    });
    roundtrip(&req);
}

#[test]
fn test_as_req_application_tag() {
    let req = AsReq(KdcReq {
        pvno: 5,
        msg_type: 10,
        padata: None,
        req_body: KdcReqBody {
            kdc_options: make_kdc_options(),
            cname: Some(make_principal()),
            realm: make_realm(),
            sname: Some(make_srv_principal()),
            from: None,
            till: make_time(),
            rtime: None,
            nonce: 42,
            etype: vec![18],
            addresses: None,
            enc_authorization_data: None,
            additional_tickets: None,
        },
    });
    let encoded = der::encode(&req).unwrap();
    // APPLICATION 10 = 0x6a (constructed)
    assert_eq!(
        encoded[0], 0x6a,
        "AS-REQ should have APPLICATION 10 tag (0x6a)"
    );
}

#[test]
fn test_tgs_req_application_tag() {
    let req = TgsReq(KdcReq {
        pvno: 5,
        msg_type: 12,
        padata: None,
        req_body: KdcReqBody {
            kdc_options: make_kdc_options(),
            cname: None,
            realm: make_realm(),
            sname: Some(PrincipalName::new_srv_hst("HTTP", "web.example.com")),
            from: None,
            till: make_time(),
            rtime: None,
            nonce: 99,
            etype: vec![18],
            addresses: None,
            enc_authorization_data: None,
            additional_tickets: None,
        },
    });
    let encoded = der::encode(&req).unwrap();
    // APPLICATION 12 = 0x6c (constructed)
    assert_eq!(
        encoded[0], 0x6c,
        "TGS-REQ should have APPLICATION 12 tag (0x6c)"
    );
}

#[test]
fn test_as_rep_roundtrip() {
    let rep = AsRep(KdcRep {
        pvno: 5,
        msg_type: 11,
        padata: None,
        crealm: make_realm(),
        cname: make_principal(),
        ticket: Ticket {
            tkt_vno: 5,
            realm: make_realm(),
            sname: make_srv_principal(),
            enc_part: make_encrypted_data(),
        },
        enc_part: make_encrypted_data(),
    });
    roundtrip(&rep);
}

#[test]
fn test_enc_kdc_rep_part_roundtrip() {
    let part = EncKdcRepPart {
        key: make_encryption_key(),
        last_req: vec![LastReqEntry {
            lr_type: 0,
            lr_value: make_time(),
        }],
        nonce: 42,
        key_expiration: None,
        flags: make_ticket_flags(),
        authtime: make_time(),
        starttime: None,
        endtime: make_time(),
        renew_till: None,
        srealm: make_realm(),
        sname: make_srv_principal(),
        caddr: None,
        encrypted_pa_data: None,
    };
    roundtrip(&part);
}

// --- AP exchange tests ---

#[test]
fn test_ap_req_roundtrip() {
    let req = ApReq {
        pvno: 5,
        msg_type: 14,
        ap_options: make_ap_options(),
        ticket: Ticket {
            tkt_vno: 5,
            realm: make_realm(),
            sname: make_srv_principal(),
            enc_part: make_encrypted_data(),
        },
        authenticator: make_encrypted_data(),
    };
    roundtrip(&req);
}

#[test]
fn test_ap_req_application_tag() {
    let req = ApReq {
        pvno: 5,
        msg_type: 14,
        ap_options: make_ap_options(),
        ticket: Ticket {
            tkt_vno: 5,
            realm: make_realm(),
            sname: make_srv_principal(),
            enc_part: make_encrypted_data(),
        },
        authenticator: make_encrypted_data(),
    };
    let encoded = der::encode(&req).unwrap();
    // APPLICATION 14 = 0x6e (constructed)
    assert_eq!(
        encoded[0], 0x6e,
        "AP-REQ should have APPLICATION 14 tag (0x6e)"
    );
}

#[test]
fn test_authenticator_roundtrip() {
    let auth = Authenticator {
        authenticator_vno: 5,
        crealm: make_realm(),
        cname: make_principal(),
        cksum: Some(make_checksum()),
        cusec: 123,
        ctime: make_time(),
        subkey: Some(make_encryption_key()),
        seq_number: Some(1),
        authorization_data: None,
    };
    roundtrip(&auth);
}

#[test]
fn test_authenticator_minimal() {
    let auth = Authenticator {
        authenticator_vno: 5,
        crealm: make_realm(),
        cname: make_principal(),
        cksum: None,
        cusec: 0,
        ctime: make_time(),
        subkey: None,
        seq_number: None,
        authorization_data: None,
    };
    roundtrip(&auth);
}

#[test]
fn test_enc_ap_rep_part_roundtrip() {
    let part = EncApRepPart {
        ctime: make_time(),
        cusec: 456,
        subkey: Some(make_encryption_key()),
        seq_number: Some(2),
    };
    roundtrip(&part);
}

