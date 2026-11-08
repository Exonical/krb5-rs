// --- per-message tokens --------------------------------------------------------

fn established_pair(
    mutual: bool,
    req_flags: GssFlags,
) -> (
    krb5_rs::gssapi::krb5::Krb5Context,
    krb5_rs::gssapi::krb5::Krb5Context,
) {
    let skey = random_key(18);
    let (cred, _session) = svc_cred(&skey, 18);
    let flags = if mutual {
        req_flags | GssFlags::MUTUAL
    } else {
        req_flags
    };
    let mut init = Krb5Initiator::new(cred, None, flags, None).expect("new");
    let token = unwrap_step(init.step(None).expect("step")).expect("token");
    let mut acc = Krb5Acceptor::new(Box::new(OneKey(skey)), Some(service()), None);
    let rep = accept_complete(acc.step(&token).expect("accept"));
    if mutual {
        init_complete(init.step(Some(&rep.expect("rep"))).expect("step2"));
    }
    (init.context().expect("ic"), acc.context().expect("ac"))
}

#[test]
fn wrap_conf_token_layout_and_seq() {
    let (mut ic, mut ac) = established_pair(false, GssFlags::REPLAY | GssFlags::SEQUENCE);
    let t1 = ic.wrap(true, b"hello").expect("wrap");
    assert_eq!(&t1[0..2], &[0x05, 0x04]);
    assert_eq!(t1[2], 0x02); // initiator, conf, no acceptor subkey
    assert_eq!(t1[3], 0xff);
    assert_eq!(&t1[4..6], &[0, 0]); // EC = 0
    assert_eq!(&t1[6..8], &[0, 0]); // RRC = 0
    let seq1 = u64::from_be_bytes(t1[8..16].try_into().unwrap());
    let t2 = ic.wrap(true, b"two").expect("wrap2");
    let seq2 = u64::from_be_bytes(t2[8..16].try_into().unwrap());
    assert_eq!(seq2, seq1 + 1);

    let r = ac.unwrap(&t1).expect("unwrap");
    assert_eq!(r.data, b"hello");
    assert!(r.conf);

    let t3 = ac.wrap(true, b"back").expect("wrap3");
    assert!(t3[2] & 0x01 != 0);
    let r3 = ic.unwrap(&t3).expect("unwrap3");
    assert_eq!(r3.data, b"back");
}

#[test]
fn wrap_integ_only_layout() {
    let (mut ic, mut ac) = established_pair(false, GssFlags::REPLAY | GssFlags::SEQUENCE);
    let t = ic.wrap(false, b"hello").expect("wrap");
    assert_eq!(&t[0..2], &[0x05, 0x04]);
    assert_eq!(t[2] & 0x02, 0);
    let ec = u16::from_be_bytes(t[4..6].try_into().unwrap());
    assert_eq!(ec, 12); // hmac-sha1-96
    assert_eq!(t.len(), 16 + 5 + 12);
    assert_eq!(&t[16..21], b"hello");
    let r = ac.unwrap(&t).expect("unwrap");
    assert_eq!(r.data, b"hello");
    assert!(!r.conf);

    let mut bad = t.clone();
    bad[18] ^= 0xff;
    // checksum fails before seq check — re-check on the same acceptor.
    drop({
        let (i2, a2) = established_pair(false, GssFlags::REPLAY | GssFlags::SEQUENCE);
        drop(i2);
        a2
    });
    assert_eq!(gss_err(ac.unwrap(&bad).unwrap_err()), GssError::BadSig);
}

#[test]
fn mic_layout_and_verify() {
    let (mut ic, mut ac) = established_pair(false, GssFlags::REPLAY | GssFlags::SEQUENCE);
    let mic = ic.get_mic(b"m").expect("mic");
    assert_eq!(&mic[0..2], &[0x04, 0x04]);
    assert_eq!(mic[2], 0);
    assert_eq!(mic[3], 0xff);
    assert_eq!(&mic[4..8], &[0xff; 4]);
    ac.verify_mic(b"m", &mic).expect("verify");
    assert_eq!(
        gss_err(ac.verify_mic(b"n", &mic).unwrap_err()),
        GssError::BadSig
    );
    let mut bad = mic.clone();
    bad[0] = 0x05;
    // wrong tok id for MIC → DefectiveToken
    let (ic2, mut ac2) = established_pair(false, GssFlags::REPLAY | GssFlags::SEQUENCE);
    drop(ic2);
    assert_eq!(
        gss_err(ac2.verify_mic(b"m", &bad).unwrap_err()),
        GssError::DefectiveToken
    );
    drop(mic);
}

#[test]
fn unwrap_direction_and_defects() {
    let (mut ic, _ac) = established_pair(false, GssFlags::REPLAY | GssFlags::SEQUENCE);
    let t = ic.wrap(true, b"hello").expect("wrap");
    // Same-role token fed back to the sender: SENDER_IS_ACCEPTOR must equal
    // !our_role (k5sealv3iov.c:314-318) → BadSig.
    assert_eq!(gss_err(ic.unwrap(&t).unwrap_err()), GssError::BadSig);

    let (mut ic, mut ac) = established_pair(false, GssFlags::REPLAY | GssFlags::SEQUENCE);
    let t = ic.wrap(true, b"hello").expect("wrap");
    assert_eq!(
        gss_err(ac.unwrap(&t[..10]).unwrap_err()),
        GssError::DefectiveToken
    );
    let mut bad = t.clone();
    bad[3] = 0x00;
    assert_eq!(
        gss_err(ac.unwrap(&bad).unwrap_err()),
        GssError::DefectiveToken
    );
    // EC field corruption: header is cleartext so decryption/HMAC still
    // passes but the embedded header copy's EC no longer matches
    // (k5sealv3iov.c:402-409) → DefectiveToken; a decrypt failure would give
    // BadSig — either must be an error, assert is_err.
    let mut bad = t.clone();
    bad[5] ^= 0xff;
    assert!(ac.unwrap(&bad).is_err());
}

#[test]
fn rrc_rotation_accepted() {
    let (mut ic, mut ac) = established_pair(false, GssFlags::REPLAY | GssFlags::SEQUENCE);
    let t = ic.wrap(true, b"hello world").expect("wrap");
    // Rotate body right by 7 and set RRC=7; unwrap rotates left by rrc
    // (k5unsealiov.c:471-478 semantics).
    let mut bad = t.clone();
    let body = &mut bad[16..];
    body.rotate_right(7);
    bad[6..8].copy_from_slice(&7u16.to_be_bytes());
    let r = ac.unwrap(&bad).expect("unwrap rotated");
    assert_eq!(r.data, b"hello world");
    assert!(r.conf);
}

#[test]
fn seqstate_matches_util_seqstate() {
    // MIT reports these as supplementary statuses, not errors.
    let mut s = SeqState::new(100, true, true, true);
    assert_eq!(s.check(100), SeqStatus::Complete);
    assert_eq!(s.check(101), SeqStatus::Complete);
    assert_eq!(s.check(103), SeqStatus::Gap);
    assert_eq!(s.check(102), SeqStatus::Unseq);
    assert_eq!(s.check(102), SeqStatus::Duplicate);
    assert_eq!(s.check(100), SeqStatus::Duplicate);

    // Replay-only (no sequence): out-of-order within window is fine.
    let mut s = SeqState::new(5, true, false, true);
    assert_eq!(s.check(5), SeqStatus::Complete);
    assert_eq!(s.check(7), SeqStatus::Complete); // gap allowed without SEQUENCE
    assert_eq!(s.check(6), SeqStatus::Complete);
    assert_eq!(s.check(6), SeqStatus::Duplicate);
    assert_eq!(s.check(100), SeqStatus::Complete); // next = 96 (rel)
                                                   // rel_seqnum 25 is 71 behind next=96 → offset > 64 → Old
                                                   // (util_seqstate.c:105-108).
    assert_eq!(s.check(30), SeqStatus::Old);

    // 32-bit mask wrap-around.
    let mut s = SeqState::new(u32::MAX as u64, true, true, false);
    assert_eq!(s.check(u32::MAX as u64), SeqStatus::Complete);
    assert_eq!(s.check(0), SeqStatus::Complete);
}

#[test]
fn replay_and_sequence_flags_on_context() {
    let (mut ic, mut ac) = established_pair(false, GssFlags::REPLAY | GssFlags::SEQUENCE);
    let t1 = ic.wrap(true, b"m1").expect("w1");
    let _t2 = ic.wrap(true, b"m2").expect("w2");
    let t3 = ic.wrap(true, b"m3").expect("w3");
    ac.unwrap(&t1).expect("u1");
    // Supplementary statuses: the message is still returned (MIT semantics).
    assert_eq!(ac.unwrap(&t1).expect("dup").seq, SeqStatus::Duplicate);
    assert_eq!(ac.unwrap(&t3).expect("gap").seq, SeqStatus::Gap);

    let (mut ic, mut ac) = established_pair(false, GssFlags::empty());
    let t1 = ic.wrap(true, b"m1").expect("w1");
    ac.unwrap(&t1).expect("u1");
    let r = ac.unwrap(&t1).expect("dup ok without REPLAY/SEQUENCE");
    assert_eq!(r.seq, SeqStatus::Complete);
}

#[test]
fn wrap_size_limit_matches_mit() {
    // wrap_size_limit.c:98-150 CFX branch: conf → largest sz with
    // encrypt_size(sz)+16 <= output, minus 16 for the encrypted header copy;
    // aes256-sha1 encrypt_size(n) = n + 16 (confounder) + 12 (hmac trailer).
    // limit(1000) = 956 - 16 = 940.
    let (mut ic, _ac) = established_pair(false, GssFlags::empty());
    assert_eq!(ic.wrap_size_limit(true, 1000), 940);
    let t = ic.wrap(true, &vec![0u8; 940]).expect("wrap max");
    assert!(t.len() <= 1000);
    assert_eq!(t.len(), 1000);
    let t2 = ic.wrap(true, &vec![0u8; 941]).expect("wrap");
    assert!(t2.len() > 1000);
    // integrity-only: output - 16 - cksumlen.
    assert_eq!(ic.wrap_size_limit(false, 1000), 972);
}

// --- IOV (k5sealv3iov.c, k5unsealiov.c) ---------------------------------------

use krb5_rs::gssapi::krb5::{GssIov, IovType};

fn iov(kinds: &[(IovType, &[u8])]) -> Vec<GssIov> {
    kinds.iter().map(|(k, b)| GssIov::new(*k, *b)).collect()
}

#[test]
fn wrap_iov_without_trailer_is_a_flat_token() {
    for conf in [true, false] {
        let (mut ic, mut ac) = established_pair(true, GssFlags::empty());
        let mut v = iov(&[(IovType::Header, b""), (IovType::Data, b"hello iov")]);
        assert_eq!(ic.wrap_iov(conf, &mut v).expect("wrap"), conf);
        let mut flat = v[0].buf.clone();
        flat.extend_from_slice(&v[1].buf);
        let out = ac.unwrap(&flat).expect("unwrap");
        assert_eq!((out.data.as_slice(), out.conf), (&b"hello iov"[..], conf));
        // And a flat token unwraps through a STREAM buffer.
        let token = ac.wrap(conf, b"stream me").expect("wrap");
        let mut s = iov(&[(IovType::Stream, &token), (IovType::Data, b"")]);
        let (c, _) = ic.unwrap_iov(&mut s).expect("stream");
        assert_eq!((s[1].buf.as_slice(), c), (&b"stream me"[..], conf));
    }
}

#[test]
fn wrap_iov_sign_only_and_trailer_round_trip() {
    for conf in [true, false] {
        let (mut ic, mut ac) = established_pair(true, GssFlags::empty());
        let mut v = iov(&[
            (IovType::Header, b""),
            (IovType::SignOnly, b"assoc"),
            (IovType::Data, b"secret"),
            (IovType::Padding, b""),
            (IovType::Trailer, b""),
        ]);
        let mut sized = v.clone();
        ic.wrap_iov_length(conf, &mut sized).expect("length");
        ic.wrap_iov(conf, &mut v).expect("wrap");
        assert_eq!(sized[0].buf.len(), v[0].buf.len());
        assert_eq!(sized[4].buf.len(), v[4].buf.len());
        assert_eq!(v[1].buf, b"assoc");
        assert_eq!(v[2].buf == b"secret", !conf);
        let mut tampered = v.clone();
        let (c, _) = ac.unwrap_iov(&mut v).expect("unwrap");
        assert_eq!((v[2].buf.as_slice(), c), (&b"secret"[..], conf));
        tampered[1].buf[0] ^= 1;
        assert!(matches!(
            ac.unwrap_iov(&mut tampered),
            Err(Krb5Error::Gss(GssError::BadSig))
        ));
    }
}

#[test]
fn wrap_iov_without_data_is_integrity_only() {
    let (mut ic, mut ac) = established_pair(true, GssFlags::empty());
    let mut v = iov(&[(IovType::Header, b""), (IovType::SignOnly, b"only")]);
    assert!(!ic.wrap_iov(true, &mut v).expect("wrap"));
    assert_eq!(v[0].buf[2] & 0x02, 0);
    assert!(!ac.unwrap_iov(&mut v).expect("unwrap").0);
}

#[test]
fn mic_iov_matches_flat_mic() {
    let (mut ic, mut ac) = established_pair(true, GssFlags::empty());
    let mut v = iov(&[
        (IovType::Data, b"part one, "),
        (IovType::Data, b"part two"),
        (IovType::MicToken, b""),
    ]);
    let mut sized = v.clone();
    ic.get_mic_iov_length(&mut sized).expect("length");
    ic.get_mic_iov(&mut v).expect("mic");
    assert_eq!(sized[2].buf.len(), v[2].buf.len());
    ac.verify_mic(b"part one, part two", &v[2].buf).expect("flat verify");
    let mic = ac.get_mic(b"back").expect("mic");
    let mut w = iov(&[(IovType::Data, b"back"), (IovType::MicToken, &mic)]);
    ic.verify_mic_iov(&mut w).expect("iov verify");
    w[0].buf[0] ^= 1;
    assert!(ic.verify_mic_iov(&mut w).is_err());
}
