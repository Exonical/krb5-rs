// Group 2: FILE ccache on-disk behavior (cc_file.c, ccfns.c) and
// MemoryCcache parity (cc_memory.c).

/// Write a ccache holding princ+cred1+cred2 for `version` and assert the
/// whole file equals the t_marshal.c vectors (t_marshal.c:333-370).
fn write_and_verify_file(version: u8) {
    let path = tmpdir_file(&format!("cc_v{version}"));
    let _ = std::fs::remove_file(&path);
    let mut cc = FileCcache::new(&path).with_version(version);
    let (p, realm) = test_princ();
    if version == 4 {
        cc.set_time_offset(300, 54321);
    }
    cc.initialize(&p, &realm).expect("initialize");
    cc.store(&cred1()).expect("store cred1");
    cc.store(&cred2()).expect("store cred2");
    let i = (version - 1) as usize;
    let mut expected = Vec::new();
    expected.extend_from_slice(HEADERS[i]);
    expected.extend_from_slice(PRINCS[i]);
    expected.extend_from_slice(CRED1S[i]);
    expected.extend_from_slice(CRED2S[i]);
    assert_eq!(std::fs::read(&path).expect("read"), expected);
}

#[test]
fn file_ccache_write_matches_vectors_all_versions() {
    for v in 1..=4u8 {
        write_and_verify_file(v);
    }
}

#[test]
fn file_ccache_read_back_vectors() {
    // Read a v4 file assembled from the vectors (t_marshal.c read half).
    let mut file = Vec::new();
    file.extend_from_slice(V4_HEADER);
    file.extend_from_slice(V4_PRINC);
    file.extend_from_slice(V4_CRED1);
    file.extend_from_slice(V4_CRED2);
    let path = write_tmp("read_v4", &file);
    let cc = FileCcache::new(&path);
    let (p, realm) = cc.principal().expect("principal");
    verify_princ(&p, &realm);
    assert_eq!(cc.time_offset(), Some((300, 54321)));
    let creds = cc.creds().expect("creds");
    assert_eq!(creds.len(), 2);
    verify_cred1(&creds[0]);
    verify_cred2(&creds[1]);
}

/// Build a v4 cache file at `path` containing cred1 and cred2.
fn make_v4_cache(path: &std::path::Path) -> FileCcache {
    let mut cc = FileCcache::new(path);
    cc.set_time_offset(300, 54321);
    let (p, realm) = test_princ();
    cc.initialize(&p, &realm).expect("initialize");
    cc.store(&cred1()).expect("store cred1");
    cc.store(&cred2()).expect("store cred2");
    cc
}

#[test]
fn file_ccache_remove_cred_marks_in_place() {
    let path = tmpdir_file("cc_remove");
    let _ = std::fs::remove_file(&path);
    let mut cc = make_v4_cache(&path);
    let len_before = std::fs::metadata(&path).expect("meta").len();

    let m = MatchCred {
        server: Some((princ(&[b"test", b"host"], 1), "EXAMPLE.COM".into())),
        ..Default::default()
    };
    cc.remove_cred(MatchFlags::empty(), &m).expect("remove");

    // Same length; cred1's slot now has endtime 0 and authtime 0xFFFFFFFF
    // (cc_file.c:1055-1066).
    let data = std::fs::read(&path).expect("read");
    assert_eq!(data.len() as u64, len_before);
    let slot = V4_HEADER.len() + V4_PRINC.len();
    assert_eq!(
        &data[..slot],
        &[V4_HEADER, V4_PRINC].concat()
    );
    let mut removed = V4_CRED1.to_vec();
    // cred layout: client(37) server(4+4+4+11+8+8=39) keyblock(2+4+16)
    // then 4 times.
    let times_off = 37 + 39 + 22;
    removed[times_off..times_off + 4].copy_from_slice(&0xFFFF_FFFFu32.to_be_bytes());
    removed[times_off + 8..times_off + 12].copy_from_slice(&0u32.to_be_bytes());
    assert_eq!(&data[slot..slot + removed.len()], &removed[..]);

    let creds = cc.creds().expect("creds");
    assert_eq!(creds.len(), 1);
    verify_cred2(&creds[0]);
}

#[test]
fn file_ccache_config_entries_not_skipped() {
    // endtime==0 && authtime==0 entries (config creds) are returned by
    // creds(); only endtime==0 && authtime!=0 are removed markers
    // (cc_file.c:750-757).
    let mut file = Vec::new();
    file.extend_from_slice(V4_HEADER);
    file.extend_from_slice(V4_PRINC);
    file.extend_from_slice(V4_CRED1);
    file.extend_from_slice(V4_CRED2);
    let path = write_tmp("cc_cfg_read", &file);
    let cc = FileCcache::new(&path);
    // cred2 has all times 0 and is NOT skipped.
    assert_eq!(cc.creds().expect("creds").len(), 2);
}

#[test]
fn set_config_and_get_config() {
    let path = tmpdir_file("cc_config");
    let _ = std::fs::remove_file(&path);
    let mut cc = make_v4_cache(&path);
    let (p, realm) = test_princ();
    let tgt = princ(&[b"krbtgt", b"KRBTEST.COM"], 2);

    cc.set_config(None, "fast_avail", Some(b"yes")).expect("set");
    let creds = cc.creds().expect("creds");
    let conf = creds
        .iter()
        .find(|c| is_config_principal(&c.server, &c.srealm))
        .expect("config cred present");
    assert_eq!(
        conf.server.name_string[0].as_bytes(),
        b"krb5_ccache_conf_data"
    );
    assert_eq!(conf.server.name_string[1].as_bytes(), b"fast_avail");
    assert_eq!(conf.srealm, "X-CACHECONF:");
    assert_eq!(conf.client, p);
    assert_eq!(conf.crealm, realm);
    assert_eq!(conf.ticket, b"yes");
    assert_eq!(
        (conf.authtime, conf.starttime, conf.endtime, conf.renew_till),
        (0, 0, 0, 0)
    );
    assert_eq!(conf.ticket_flags, 0);
    assert!(!conf.is_skey);

    // With a principal: third component is the unparsed name.
    cc.set_config(Some((&tgt, "KRBTEST.COM")), "pa_type", Some(b"2"))
        .expect("set pa_type");
    assert_eq!(
        cc.get_config(Some((&tgt, "KRBTEST.COM")), "pa_type")
            .expect("get"),
        Some(b"2".to_vec())
    );
    assert_eq!(cc.get_config(None, "nonsuch").expect("get"), None);

    // Removing: set_config(.., None) → remove_cred, rewrites realm to
    // X-RMED-CONF: (cc_file.c:1062-1065).
    cc.set_config(Some((&tgt, "KRBTEST.COM")), "pa_type", None)
        .expect("unset");
    assert_eq!(
        cc.get_config(Some((&tgt, "KRBTEST.COM")), "pa_type")
            .expect("get"),
        None
    );
    let raw = std::fs::read(&path).expect("read");
    let text = String::from_utf8_lossy(&raw);
    // The removed pa_type entry's realm was rewritten (cc_file.c:1062-1065);
    // the surviving fast_avail entry still uses X-CACHECONF:.
    assert!(text.contains("X-RMED-CONF:"));
    let c2 = cc.creds().expect("creds");
    assert!(!c2.iter().any(|c| {
        is_config_principal(&c.server, &c.srealm)
            && c.server.name_string.get(1).is_some_and(|c| c.as_bytes() == b"pa_type")
    }));
}

#[test]
fn config_principal_recognition() {
    let conf = princ(&[b"krb5_ccache_conf_data", b"x"], 1);
    assert!(is_config_principal(&conf, "X-CACHECONF:"));
    assert!(!is_config_principal(&conf, "KRBTEST.COM"));
    assert!(!is_config_principal(&princ(&[], 1), "X-CACHECONF:"));
    assert!(!is_config_principal(
        &princ(&[b"krb5_ccache_conf_dat", b"x"], 1),
        "X-CACHECONF:"
    ));
}

#[test]
fn unparse_name_quoting() {
    // unparse.c: '/', '@', '\', '\t', '\n', '\b', '\0' are backslash-escaped.
    let p = princ(&[b"a/b", b"c@d"], 1);
    assert_eq!(unparse_name(&p, "R\\E"), "a\\/b/c\\@d@R\\\\E");
    assert_eq!(
        unparse_name(&PrincipalName::new_principal("testuser"), "TEST.REALM"),
        "testuser@TEST.REALM"
    );
}

#[test]
fn memory_ccache_parity() {
    let mut cc = MemoryCcache::new();
    let (p, realm) = test_princ();
    cc.initialize(&p, &realm).expect("initialize");
    cc.store(&cred1()).expect("store1");
    cc.store(&cred2()).expect("store2");
    assert_eq!(cc.principal().expect("principal"), (p.clone(), realm.clone()));

    let creds = cc.creds().expect("creds");
    assert_eq!(creds.len(), 2);
    verify_cred1(&creds[0]);
    verify_cred2(&creds[1]);

    // remove_cred: MEMORY deletes outright (cc_memory.c).
    let m = MatchCred {
        server: Some((princ(&[b"test", b"host"], 1), "EXAMPLE.COM".into())),
        ..Default::default()
    };
    cc.remove_cred(MatchFlags::empty(), &m).expect("remove");
    assert_eq!(cc.creds().expect("creds").len(), 1);
    verify_cred2(&cc.creds().expect("creds")[0]);

    // Config entries work the same way.
    let tgt = princ(&[b"krbtgt", b"KRBTEST.COM"], 2);
    cc.set_config(Some((&tgt, "KRBTEST.COM")), "pa_type", Some(b"2"))
        .expect("set");
    assert_eq!(
        cc.get_config(Some((&tgt, "KRBTEST.COM")), "pa_type")
            .expect("get"),
        Some(b"2".to_vec())
    );
    cc.set_config(Some((&tgt, "KRBTEST.COM")), "pa_type", None)
        .expect("unset");
    assert_eq!(
        cc.get_config(Some((&tgt, "KRBTEST.COM")), "pa_type")
            .expect("get"),
        None
    );
}
