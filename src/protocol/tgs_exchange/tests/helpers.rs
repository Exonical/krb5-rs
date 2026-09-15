use super::*;

pub(super) fn make_time(secs: i64) -> KerberosTime {
    let utc = FixedOffset::east_opt(0).expect("UTC");
    Utc.timestamp_opt(secs, 0)
        .single()
        .expect("valid")
        .with_timezone(&utc)
}

pub(super) fn make_realm(s: &str) -> GeneralString {
    GeneralString::from_bytes(s.as_bytes()).expect("valid realm")
}

pub(super) fn make_enc_key(etype: i32, len: usize) -> EncryptionKey {
    EncryptionKey::new(etype, vec![0xABu8; len])
}

pub(super) fn make_tgt(realm: &str) -> Credential {
    Credential {
        client: PrincipalName::new_principal("user"),
        crealm: realm.to_string(),
        server: PrincipalName::new_srv_inst("krbtgt", realm),
        srealm: realm.to_string(),
        session_key: make_enc_key(18, 32),
        times: TicketTimes {
            authtime: make_time(1_700_000_000),
            starttime: Some(make_time(1_700_000_000)),
            endtime: make_time(1_700_036_000),
            renew_till: None,
        },
        ticket: Ticket {
            tkt_vno: 5,
            realm: make_realm(realm),
            sname: PrincipalName::new_srv_inst("krbtgt", realm),
            enc_part: EncryptedData {
                etype: 18,
                kvno: Some(1),
                cipher: OctetString::from(vec![0u8; 64]),
            },
        },
        flags: KerberosFlags::new(
            TicketFlags::FORWARDABLE | TicketFlags::RENEWABLE | TicketFlags::INITIAL,
        ),
        addresses: None,
        authdata: None,
    }
}

/// Helper: a TGS-REP `KdcRep` for user@EXAMPLE.COM carrying a
/// `krbtgt/<realm>` referral ticket (dummy ciphertext).
pub(super) fn make_referral_rep(realm: &str) -> KdcRep {
    KdcRep {
        pvno: 5,
        msg_type: 13,
        padata: None,
        crealm: make_realm("EXAMPLE.COM"),
        cname: PrincipalName::new_principal("user"),
        ticket: Ticket {
            tkt_vno: 5,
            realm: make_realm("EXAMPLE.COM"),
            sname: PrincipalName::new_srv_inst("krbtgt", realm),
            enc_part: EncryptedData {
                etype: 18,
                kvno: Some(1),
                cipher: OctetString::from(vec![0u8; 64]),
            },
        },
        enc_part: EncryptedData {
            etype: 18,
            kvno: None,
            cipher: OctetString::from(vec![0u8; 64]),
        },
    }
}

/// Helper: referral TGT enc-part (srealm EXAMPLE.COM,
/// sname krbtgt/<realm>).
pub(super) fn make_referral_enc_part(
    realm: &str,
    now: KerberosTime,
    flags: KerberosFlags<TicketFlags>,
) -> EncKdcRepPart {
    EncKdcRepPart {
        key: make_enc_key(18, 32),
        last_req: vec![],
        nonce: 0,
        key_expiration: None,
        flags,
        authtime: now,
        starttime: None,
        endtime: make_time(1_700_036_000),
        renew_till: None,
        srealm: make_realm("EXAMPLE.COM"),
        sname: PrincipalName::new_srv_inst("krbtgt", realm),
        caddr: None,
        encrypted_pa_data: None,
    }
}

/// Helper: build a DER-encoded KRB-ERROR.
pub(super) fn build_krb_error(error_code: i32, realm: &str) -> Vec<u8> {
    let now = now_kerberos();
    let krb_error = KrbErrorMsg {
        pvno: 5,
        msg_type: 30,
        ctime: None,
        cusec: None,
        stime: now,
        susec: 0,
        error_code,
        crealm: None,
        cname: None,
        realm: make_realm(realm),
        sname: PrincipalName::new_srv_inst("krbtgt", realm),
        e_text: None,
        e_data: None,
    };
    rasn::der::encode(&krb_error).expect("encode KRB-ERROR")
}
