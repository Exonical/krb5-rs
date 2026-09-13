// Group 1: ccmarshal.c byte-level marshal/unmarshal against t_marshal.c
// vectors (verbatim from MIT).

/// Public marshal API roundtrip on tests[3].cred1 (t_marshal.c:284-294).
#[test]
fn marshal_public_roundtrip_v4_cred1() {
    let cred = unmarshal_cred(V4_CRED1, 4).expect("unmarshal cred1 v4");
    verify_cred1(&cred);
    let out = marshal_cred(&cred, 4);
    assert_eq!(out, V4_CRED1);
}

#[test]
fn marshal_princ_roundtrip_all_versions() {
    for (v, expected) in PRINCS.iter().enumerate() {
        let version = (v + 1) as u8;
        let (p, realm) = unmarshal_princ(expected, version).expect("unmarshal princ");
        verify_princ(&p, &realm);
        // Version 1 does not store the name type.
        if version == 1 {
            assert_eq!(p.name_type, 0); // KRB5_NT_UNKNOWN
        } else {
            assert_eq!(p.name_type, 1);
        }
        assert_eq!(marshal_princ(&p, &realm, version), *expected);
    }
}

#[test]
fn marshal_creds_roundtrip_all_versions() {
    for v in 1..=4u8 {
        let i = (v - 1) as usize;
        let c = unmarshal_cred(CRED1S[i], v).expect("unmarshal cred1");
        verify_cred1(&c);
        assert_eq!(marshal_cred(&c, v), CRED1S[i]);

        let c = unmarshal_cred(CRED2S[i], v).expect("unmarshal cred2");
        verify_cred2(&c);
        assert_eq!(marshal_cred(&c, v), CRED2S[i]);
    }
}

#[test]
fn marshal_truncated_cred_is_format_error() {
    let short = &V4_CRED1[..V4_CRED1.len() - 1];
    assert!(matches!(
        unmarshal_cred(short, 4),
        Err(CcError::Format)
    ));
}

#[test]
fn marshal_huge_ncomps_is_format_error() {
    // Sanity check: ncomps > remaining input length (ccmarshal.c:175).
    let mut bogus = Vec::new();
    bogus.extend_from_slice(&0x7FFF_FFFFu32.to_be_bytes()); // ncomps
    bogus.extend_from_slice(&11u32.to_be_bytes());
    bogus.extend_from_slice(b"KRBTEST.COM");
    assert!(matches!(
        unmarshal_princ(&bogus, 4),
        Err(CcError::Format)
    ));
}

#[test]
fn ccache_bad_versions_rejected() {
    for vno in [0x0500u16, 0x0505] {
        let path = write_tmp(&format!("badvno_{vno}"), &vno.to_be_bytes());
        let cc = FileCcache::new(&path);
        assert!(matches!(cc.principal(), Err(CcError::BadVno)));
    }
}

#[test]
fn ccache_v4_header_unknown_tag_and_bad_lengths() {
    // Unknown tag (2) before DELTATIME: skipped; offset still applied.
    let mut header = Vec::new();
    header.extend_from_slice(&0x0504u16.to_be_bytes());
    let fields: &[u8] = &[
        0x00, 0x02, 0x00, 0x03, 0xAA, 0xBB, 0xCC, // unknown tag 2, len 3
        0x00, 0x01, 0x00, 0x08, 0x00, 0x00, 0x01, 0x2C, 0x00, 0x00, 0xD4, 0x31,
    ];
    header.extend_from_slice(&(fields.len() as u16).to_be_bytes());
    header.extend_from_slice(fields);
    let mut file = header.clone();
    file.extend_from_slice(V4_PRINC);
    let path = write_tmp("unknown_tag", &file);
    let cc = FileCcache::new(&path);
    let (p, realm) = cc.principal().expect("principal");
    verify_princ(&p, &realm);
    assert_eq!(cc.time_offset(), Some((300, 54321)));

    // fields_len < 4 → Format.
    let mut bad = vec![0x05, 0x04, 0x00, 0x02];
    bad.extend_from_slice(V4_PRINC);
    let path = write_tmp("short_fields", &bad);
    assert!(matches!(
        FileCcache::new(&path).principal(),
        Err(CcError::Format)
    ));

    // DELTATIME with flen != 8 → Format.
    let mut bad = vec![0x05, 0x04, 0x00, 0x05, 0x00, 0x01, 0x00, 0x01, 0x00];
    bad.extend_from_slice(V4_PRINC);
    let path = write_tmp("bad_deltatime", &bad);
    assert!(matches!(
        FileCcache::new(&path).principal(),
        Err(CcError::Format)
    ));
}
