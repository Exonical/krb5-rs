// Group 4: keytab — t_keytab.c get_entry semantics, kt_file.c on-disk
// format (v1 read + v2 read/write), find_slot hole reuse, delete_entry,
// and the rd_req_dec.c KeySource error mapping.

const E1: i32 = 19; // ENCTYPE_AES128_CTS_HMAC_SHA256_128
const E2: i32 = 20; // ENCTYPE_AES256_CTS_HMAC_SHA384_192

fn kt_princ() -> (PrincipalName, String) {
    (princ(&[b"test", b"test2"], 1), "KRBTEST.COM".into())
}

fn kt_entry(kvno: u32, etype: i32, key: &[u8]) -> KeytabEntry {
    let (p, realm) = kt_princ();
    KeytabEntry {
        principal: p,
        realm,
        timestamp: 1000,
        kvno,
        key: EncryptionKey::new(etype, key.to_vec()),
    }
}

/// The exact on-disk record MIT writes for kt_entry(1, E1, b"1") in v2:
/// i32 size, i16 count(2), i16 len+realm, i16 len+comp x2, i32 type,
/// i32 timestamp, u8 vno, i16 etype, i16 keylen, key, i32 vno32.
fn expected_v2_record(e: &KeytabEntry) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&2i16.to_be_bytes()); // count excludes realm
    body.extend_from_slice(&11i16.to_be_bytes());
    body.extend_from_slice(b"KRBTEST.COM");
    for c in &e.principal.name_string {
        body.extend_from_slice(&(c.len() as i16).to_be_bytes());
        body.extend_from_slice(c.as_bytes());
    }
    body.extend_from_slice(&1i32.to_be_bytes()); // NT_PRINCIPAL
    body.extend_from_slice(&1000i32.to_be_bytes()); // timestamp
    body.push(e.kvno as u8);
    body.extend_from_slice(&(e.key.keytype as i16).to_be_bytes());
    body.extend_from_slice(&(e.key.key_bytes().len() as i16).to_be_bytes());
    body.extend_from_slice(e.key.key_bytes());
    body.extend_from_slice(&e.kvno.to_be_bytes()); // vno32
    let mut rec = (body.len() as i32).to_be_bytes().to_vec();
    rec.extend_from_slice(&body);
    rec
}

fn new_file_kt(name: &str) -> (std::path::PathBuf, FileKeytab) {
    let path = tmpdir_file(name);
    let _ = std::fs::remove_file(&path);
    (path.clone(), FileKeytab::new(&path))
}

#[test]
fn keytab_v2_record_bytes_exact() {
    let (path, mut kt) = new_file_kt("kt_bytes");
    kt.add_entry(&kt_entry(1, E1, b"1")).expect("add");
    let raw = std::fs::read(&path).expect("read");
    let mut expected = vec![0x05, 0x02];
    expected.extend_from_slice(&expected_v2_record(&kt_entry(1, E1, b"1")));
    assert_eq!(raw, expected);
}

/// Three entries as in t_keytab.c: e1/kvno1/"1", e2/kvno1/"1", e1/kvno2/"2".
fn populate(kt: &mut impl Keytab) {
    kt.add_entry(&kt_entry(1, E1, b"1")).expect("add1");
    kt.add_entry(&kt_entry(1, E2, b"1")).expect("add2");
    kt.add_entry(&kt_entry(2, E1, b"2")).expect("add3");
}

/// t_keytab.c:230-345 get_entry assertions.
fn get_entry_semantics(kt: &impl Keytab) {
    let (p, realm) = kt_princ();
    let get = |kvno, etype| kt.get_entry(&p, &realm, kvno, etype);

    // No enctype, no kvno → any of the three (t_keytab.c accepts vno 1|2).
    let e = get(None, None).expect("any");
    assert!(e.kvno == 1 || e.kvno == 2);
    // etype e1, no kvno → max kvno = 2.
    let e = get(None, Some(E1)).expect("e1 any kvno");
    assert_eq!(e.kvno, 2);
    assert_eq!(e.key.key_bytes(), b"2");
    // kvno 2, no etype → the e1 entry.
    let e = get(Some(2), None).expect("kvno 2");
    assert_eq!(e.key.keytype, E1);
    // Exact kvno+etype.
    assert_eq!(get(Some(1), Some(E1)).expect("kvno1 e1").key.key_bytes(), b"1");
    assert_eq!(get(Some(1), Some(E2)).expect("kvno1 e2").key.keytype, E2);
    // kvno 3 with e1: t_keytab.c:337-345 expects KRB5_KT_KVNONOTFOUND.
    assert!(matches!(get(Some(3), Some(E1)), Err(KtError::KvnoNotFound)));
    // Unknown principal → NotFound.
    let other = princ(&[b"test3", b"test2"], 1);
    assert!(matches!(
        kt.get_entry(&other, &realm, None, None),
        Err(KtError::NotFound)
    ));
    // Wrong etype, kvno unspecified → NotFound (enctype filter leaves
    // nothing, and no wrong-kvno was seen).
    assert!(matches!(get(None, Some(17)), Err(KtError::NotFound)));
}

#[test]
fn file_keytab_get_entry_semantics() {
    let (_path, mut kt) = new_file_kt("kt_get");
    populate(&mut kt);
    assert_eq!(kt.entries().expect("entries").len(), 3);
    get_entry_semantics(&kt);
}

#[test]
fn memory_keytab_get_entry_semantics() {
    let mut kt = MemoryKeytab::new();
    populate(&mut kt);
    get_entry_semantics(&kt);
}

#[test]
fn keytab_more_recent_wraparound() {
    // more_recent (kt_file.c:258-283): small kvno written at same-or-later
    // time beats large kvno ≥241; large kvno loses only below 128.
    let kt2 = |a: KeytabEntry, b: KeytabEntry| MemoryKeytab::from_entries(vec![a, b]);
    let (p, realm) = kt_princ();

    let mut a = kt_entry(250, E1, b"x");
    a.timestamp = 100;
    let mut b = kt_entry(3, E1, b"y");
    b.timestamp = 100;
    let e = kt2(a, b).get_entry(&p, &realm, None, None).expect("wrap");
    assert_eq!(e.kvno, 3);

    let mut a = kt_entry(3, E1, b"y");
    a.timestamp = 50;
    let mut b = kt_entry(250, E1, b"x");
    b.timestamp = 100;
    let e = kt2(a, b).get_entry(&p, &realm, None, None).expect("older wrap");
    assert_eq!(e.kvno, 250);

    // No wrap heuristic between 128..240: plain max wins.
    let mut a = kt_entry(5, E1, b"y");
    a.timestamp = 100;
    let mut b = kt_entry(200, E1, b"x");
    b.timestamp = 100;
    let e = kt2(a, b).get_entry(&p, &realm, None, None).expect("no wrap");
    assert_eq!(e.kvno, 200);
}

#[test]
fn keytab_vno32_extension_and_low8_fallback() {
    // Record with vno byte 1 and vno32=257 → kvno 257 (kt_file.c:~1093).
    let e = kt_entry(1, E1, b"1");
    let mut body = Vec::new();
    body.extend_from_slice(&2i16.to_be_bytes());
    body.extend_from_slice(&11i16.to_be_bytes());
    body.extend_from_slice(b"KRBTEST.COM");
    for c in e.principal.name_string.iter() {
        body.extend_from_slice(&(c.len() as i16).to_be_bytes());
        body.extend_from_slice(c.as_bytes());
    }
    body.extend_from_slice(&1i32.to_be_bytes());
    body.extend_from_slice(&1000i32.to_be_bytes());
    body.push(1u8);
    body.extend_from_slice(&(E1 as i16).to_be_bytes());
    body.extend_from_slice(&1i16.to_be_bytes());
    body.extend_from_slice(b"1");
    // vno32 = 257
    let mut with_vno32 = body.clone();
    with_vno32.extend_from_slice(&257u32.to_be_bytes());
    // vno32 = 0 (legacy zero-fill) → kvno stays 1
    let mut with_zero = body.clone();
    with_zero.extend_from_slice(&0u32.to_be_bytes());

    let build = |rec_body: &[u8]| {
        let mut f = vec![0x05, 0x02];
        f.extend_from_slice(&(rec_body.len() as i32).to_be_bytes());
        f.extend_from_slice(rec_body);
        f
    };
    let (p, realm) = kt_princ();
    let path = write_tmp("kt_vno32", &build(&with_vno32));
    let kt = FileKeytab::new(&path);
    let e = kt
        .get_entry(&p, &realm, Some(257), Some(E1))
        .expect("vno32 entry");
    assert_eq!(e.kvno, 257);

    // Legacy record: asking for kvno 257 matches low-8-bit fallback (1).
    let path = write_tmp("kt_vno0", &build(&with_zero));
    let kt = FileKeytab::new(&path);
    let e = kt
        .get_entry(&p, &realm, Some(257), Some(E1))
        .expect("low8 fallback");
    assert_eq!(e.kvno, 1);
}

#[test]
fn keytab_remove_negates_size_and_reuses_hole() {
    let (path, mut kt) = new_file_kt("kt_del");
    populate(&mut kt);
    let len_before = std::fs::metadata(&path).expect("meta").len();

    // Remove the kvno-2/e1 entry (t_keytab.c:347-380).
    let (p, realm) = kt_princ();
    let e = kt.get_entry(&p, &realm, Some(2), Some(E1)).expect("get kvno2");
    kt.remove_entry(&e).expect("remove");

    // Size field of that record is negative, body zeroed.
    let raw = std::fs::read(&path).expect("read");
    assert_eq!(raw.len() as u64, len_before);
    let rec_len = expected_v2_record(&e).len() - 4;
    // The kvno-2 record is the third record.
    let off = 2 + 2 * (4 + rec_len);
    assert_eq!(
        i32::from_be_bytes(raw[off..off + 4].try_into().unwrap()),
        -(rec_len as i32)
    );
    assert!(raw[off + 4..off + 4 + rec_len].iter().all(|b| *b == 0));

    // get_entry(None, e1) now returns kvno 1.
    let e = kt.get_entry(&p, &realm, None, Some(E1)).expect("after del");
    assert_eq!(e.kvno, 1);
    assert_eq!(e.key.key_bytes(), b"1");

    // Re-add a same-size entry → hole reused, file length unchanged.
    kt.add_entry(&kt_entry(2, E1, b"2")).expect("readd");
    assert_eq!(
        std::fs::metadata(&path).expect("meta").len(),
        len_before
    );
    assert_eq!(kt.entries().expect("entries").len(), 3);

    // An entry too big for the hole is appended.
    kt.remove_entry(&kt_entry(2, E1, b"2")).expect("remove again");
    let mut big = kt_entry(9, E1, b"9");
    big.key = EncryptionKey::new(E1, vec![0u8; 64]);
    kt.add_entry(&big).expect("add big");
    assert!(std::fs::metadata(&path).expect("meta").len() > len_before);
}

#[test]
fn keytab_v1_read() {
    // 0x0501 header, native (LE) order, count includes realm, no name
    // type, no vno32.
    let mut f = vec![0x05, 0x01];
    let mut body = Vec::new();
    body.extend_from_slice(&3i16.to_ne_bytes()); // 2 comps + realm
    body.extend_from_slice(&11i16.to_ne_bytes());
    body.extend_from_slice(b"KRBTEST.COM");
    for c in [&b"test"[..], &b"test2"[..]] {
        body.extend_from_slice(&(c.len() as i16).to_ne_bytes());
        body.extend_from_slice(c);
    }
    body.extend_from_slice(&1000u32.to_ne_bytes()); // timestamp, native
    body.push(7u8); // kvno
    body.extend_from_slice(&(E1 as i16).to_ne_bytes()); // etype
    body.extend_from_slice(&1i16.to_ne_bytes());
    body.extend_from_slice(b"7");
    f.extend_from_slice(&(body.len() as i32).to_ne_bytes());
    f.extend_from_slice(&body);
    let path = write_tmp("kt_v1", &f);
    let kt = FileKeytab::new(&path);
    let entries = kt.entries().expect("entries");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].principal.name_string[0].as_bytes(), b"test");
    assert_eq!(entries[0].realm, "KRBTEST.COM");
    assert_eq!(entries[0].kvno, 7);
    assert_eq!(entries[0].key.keytype, E1);
    assert_eq!(entries[0].key.key_bytes(), b"7");
    assert_eq!(entries[0].timestamp, 1000);
}

#[test]
fn keytab_bad_records() {
    // size == i32::MIN → Format (kt_file.c: INT32_MIN inverts to itself).
    let mut f = vec![0x05, 0x02];
    f.extend_from_slice(&i32::MIN.to_be_bytes());
    let path = write_tmp("kt_intmin", &f);
    assert!(matches!(
        FileKeytab::new(&path).entries(),
        Err(KtError::Format)
    ));
    // size 0 → end of entries (empty list, not an error).
    let mut f = vec![0x05, 0x02];
    f.extend_from_slice(&0i32.to_be_bytes());
    let path = write_tmp("kt_zero", &f);
    assert_eq!(FileKeytab::new(&path).entries().expect("entries").len(), 0);
}

#[test]
fn keytab_zero_count_record_ends_iteration() {
    // kt_file.c:949 `if (!count || count < 0) return KRB5_KT_END` — a
    // record whose component count is 0 stops iteration like size 0.
    let e = kt_entry(1, E1, b"1");
    let mut f = vec![0x05, 0x02];
    f.extend_from_slice(&expected_v2_record(&e));
    // Bogus record: count field 0, rest of the body garbage.
    let mut bogus = Vec::new();
    bogus.extend_from_slice(&0i16.to_be_bytes()); // count = 0
    bogus.extend_from_slice(&[0xAA; 10]);
    f.extend_from_slice(&(bogus.len() as i32).to_be_bytes());
    f.extend_from_slice(&bogus);
    let path = write_tmp("kt_zerocount", &f);
    let entries = FileKeytab::new(&path).entries().expect("entries");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].key.key_bytes(), b"1");
}

#[test]
fn keytab_v1_is_read_only() {
    // We only ever write v2; MIT's write_entry/find_slot would write
    // native-order fields into a v1 file, so v1 files reject mutation
    // (documented on the Keytab trait).
    let mut f = vec![0x05, 0x01];
    let mut body = Vec::new();
    body.extend_from_slice(&3i16.to_ne_bytes());
    body.extend_from_slice(&11i16.to_ne_bytes());
    body.extend_from_slice(b"KRBTEST.COM");
    for c in [&b"test"[..], &b"test2"[..]] {
        body.extend_from_slice(&(c.len() as i16).to_ne_bytes());
        body.extend_from_slice(c);
    }
    body.extend_from_slice(&1000u32.to_ne_bytes());
    body.push(7u8);
    body.extend_from_slice(&(E1 as i16).to_ne_bytes());
    body.extend_from_slice(&1i16.to_ne_bytes());
    body.extend_from_slice(b"7");
    f.extend_from_slice(&(body.len() as i32).to_ne_bytes());
    f.extend_from_slice(&body);
    let path = write_tmp("kt_v1_ro", &f);
    let before = std::fs::read(&path).expect("read");
    let mut kt = FileKeytab::new(&path);
    assert!(matches!(
        kt.add_entry(&kt_entry(2, E1, b"2")),
        Err(KtError::Format)
    ));
    assert!(matches!(
        kt.remove_entry(&kt_entry(7, E1, b"7")),
        Err(KtError::Format)
    ));
    assert_eq!(std::fs::read(&path).expect("read"), before);
}

#[test]
fn file_keytab_as_keysource() {
    // rd_req_dec.c:120-146 — KeySource mapping: NotFound → NoKey,
    // KvnoNotFound → BadKeyver.
    let (_path, mut kt) = new_file_kt("kt_keysource");
    let (p, realm) = (princ(&[b"HTTP", b"server.test.realm"], 2), "TEST.REALM".to_string());
    let skey = EncryptionKey::new(18, rand::random::<[u8; 32]>().to_vec());
    kt.add_entry(&KeytabEntry {
        principal: p.clone(),
        realm: realm.clone(),
        timestamp: 1000,
        kvno: 1,
        key: skey.clone(),
    })
    .expect("add");

    // Build a live credential: ticket encrypted under skey kvno 1.
    let session = EncryptionKey::new(18, rand::random::<[u8; 32]>().to_vec());
    let t: KerberosTime = chrono::Utc::now().fixed_offset();
    let enc_part = EncTicketPart {
        flags: KerberosFlags::new(TicketFlags::empty()),
        key: session.clone(),
        crealm: GeneralString::from_bytes(b"TEST.REALM").unwrap(),
        cname: PrincipalName::new_principal("testuser"),
        transited: TransitedEncoding {
            tr_type: 0,
            contents: OctetString::from(Vec::new()),
        },
        authtime: t,
        starttime: None,
        endtime: t + chrono::Duration::hours(1),
        renew_till: None,
        caddr: None,
        authorization_data: None,
    };
    let ticket = krb5_rs::protocol::ap::encrypt_ticket_part(&skey, Some(1), &realm, p.clone(), &enc_part)
        .expect("encrypt ticket");
    let cred = Credential {
        client: PrincipalName::new_principal("testuser"),
        crealm: "TEST.REALM".into(),
        server: p.clone(),
        srealm: realm.clone(),
        session_key: session,
        times: TicketTimes {
            authtime: t,
            starttime: None,
            endtime: t + chrono::Duration::hours(1),
            renew_till: None,
        },
        ticket,
        flags: KerberosFlags::new(TicketFlags::empty()),
        addresses: None,
        authdata: None,
    };

    let mut client_ctx = AuthContext::new();
    let ap_req = client_ctx
        .mk_req(&ApReqOptions::default(), None, &cred)
        .expect("mk_req");
    let mut server_ctx = AuthContext::new();
    server_ctx.rd_req(&ap_req, Some(&p), &kt).expect("rd_req");

    // kvno mismatch → BadKeyver (rd_req_dec.c:137-145 KVNONOTFOUND→BADKEYVER).
    let ticket2 = {
        let mut t2 = cred.ticket.clone();
        t2.enc_part.kvno = Some(2);
        t2
    };
    let cred2 = Credential { ticket: ticket2, ..cred.clone() };
    let mut client_ctx = AuthContext::new();
    let ap_req = client_ctx
        .mk_req(&ApReqOptions::default(), None, &cred2)
        .expect("mk_req2");
    let mut server_ctx = AuthContext::new();
    match server_ctx.rd_req(&ap_req, Some(&p), &kt) {
        Err(Krb5Error::Ap(krb5_rs::protocol::ap::ApError::BadKeyver)) => {}
        other => panic!("expected BadKeyver, got: {other:?}"),
    }

    // Unknown server → NoKey (explicit server, rd_req_dec.c:131-132).
    let wrong = princ(&[b"HTTP", b"other.test.realm"], 2);
    let cred3 = Credential { server: wrong.clone(), ..cred.clone() };
    let mut client_ctx = AuthContext::new();
    let ap_req = client_ctx
        .mk_req(&ApReqOptions::default(), None, &cred3)
        .expect("mk_req3");
    let mut server_ctx = AuthContext::new();
    match server_ctx.rd_req(&ap_req, Some(&wrong), &kt) {
        Err(Krb5Error::Ap(krb5_rs::protocol::ap::ApError::NoKey)) => {}
        other => panic!("expected NoKey, got: {other:?}"),
    }
}

#[test]
fn keysource_etype_mismatch_is_badkeyver() {
    // rd_req_dec.c:255-265: server+kvno present but not with the ticket's
    // enctype → the retry without an enctype succeeds → BADKEYVER.
    for file_kt in [true, false] {
        let (p, realm) = (
            princ(&[b"HTTP", b"server.test.realm"], 2),
            "TEST.REALM".to_string(),
        );
        let entry = KeytabEntry {
            principal: p.clone(),
            realm: realm.clone(),
            timestamp: 1000,
            kvno: 1,
            // Keytab holds etype 17; the ticket below is encrypted with 18.
            key: EncryptionKey::new(17, rand::random::<[u8; 16]>().to_vec()),
        };
        let mut mem = MemoryKeytab::new();
        mem.add_entry(&entry).expect("add");
        let path = tmpdir_file(if file_kt { "kt_badkeyver_f" } else { "kt_badkeyver_m" });
        let _ = std::fs::remove_file(&path);
        let mut fk = FileKeytab::new(&path);
        fk.add_entry(&entry).expect("add");

        // Ticket encrypted under a random etype-18 key, kvno 1.
        let skey = EncryptionKey::new(18, rand::random::<[u8; 32]>().to_vec());
        let session = EncryptionKey::new(18, rand::random::<[u8; 32]>().to_vec());
        let t: KerberosTime = chrono::Utc::now().fixed_offset();
        let enc_part = EncTicketPart {
            flags: KerberosFlags::new(TicketFlags::empty()),
            key: session.clone(),
            crealm: GeneralString::from_bytes(b"TEST.REALM").unwrap(),
            cname: PrincipalName::new_principal("testuser"),
            transited: TransitedEncoding {
                tr_type: 0,
                contents: OctetString::from(Vec::new()),
            },
            authtime: t,
            starttime: None,
            endtime: t + chrono::Duration::hours(1),
            renew_till: None,
            caddr: None,
            authorization_data: None,
        };
        let ticket =
            krb5_rs::protocol::ap::encrypt_ticket_part(&skey, Some(1), &realm, p.clone(), &enc_part)
                .expect("encrypt ticket");
        let cred = Credential {
            client: PrincipalName::new_principal("testuser"),
            crealm: "TEST.REALM".into(),
            server: p.clone(),
            srealm: realm.clone(),
            session_key: session,
            times: TicketTimes {
                authtime: t,
                starttime: None,
                endtime: t + chrono::Duration::hours(1),
                renew_till: None,
            },
            ticket,
            flags: KerberosFlags::new(TicketFlags::empty()),
            addresses: None,
            authdata: None,
        };
        let mut client_ctx = AuthContext::new();
        let ap_req = client_ctx
            .mk_req(&ApReqOptions::default(), None, &cred)
            .expect("mk_req");
        let mut server_ctx = AuthContext::new();
        let res = if file_kt {
            server_ctx.rd_req(&ap_req, Some(&p), &fk)
        } else {
            server_ctx.rd_req(&ap_req, Some(&p), &mem)
        };
        match res {
            Err(Krb5Error::Ap(krb5_rs::protocol::ap::ApError::BadKeyver)) => {}
            other => panic!("expected BadKeyver (file_kt={file_kt}), got: {other:?}"),
        }
    }
}
