//! MIT krb5 known-answer vectors for PRF, PRF+, KRB-FX-CF2, key derivation,
//! string-to-key, checksums and decryption — covering aes-sha1 (17/18) and
//! RFC 8009 aes-sha2 (19/20) enctypes.
//!
//! All vectors copied verbatim from krb5-1.22.2:
//!   src/lib/crypto/crypto_tests/{t_prf.c,t_cf2.in,t_cf2.expected,t_derive.c,
//!   t_str2key.c,t_cksums.c,t_decrypt.c,t_short.c}

use krb5_rs::crypto::{
    derive_prfplus, find_cksumtype, find_etype, fx_cf2, prf_plus, CryptoError, EtypeProfile,
    KeyPurpose,
};
use krb5_rs::protocol::{AsExchangeConfig, TgsOptions};
use krb5_rs::types::{EncryptionKey, PrincipalName};

fn hex(s: &str) -> Vec<u8> {
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

// ---------------------------------------------------------------------------
// t_prf.c:41-115 — PRF vectors
// ---------------------------------------------------------------------------

struct PrfVec {
    etype: i32,
    key: &'static str,
    input: &'static [u8],
    expected: &'static str,
}

const PRF_VECTORS: &[PrfVec] = &[
    PrfVec {
        etype: 17,
        key: "AE272E7CDEC86AC5138CDB196D8E297D",
        input: b"\x01\x61",
        expected: "77B39A37A868920F2A51F9DD150C5717",
    },
    PrfVec {
        etype: 17,
        key: "67AB1CFEF35E4C27FFDEAC60385A3E9C",
        input: b"\x01\x62",
        expected: "E06C0DD31FF02091994F2EF5178BFE3D",
    },
    PrfVec {
        etype: 18,
        key: "C01F157211F7B77EAAF457C3E156690127EE127D810BA6392E97BAA243EB0616",
        input: b"\x01\x61",
        expected: "B2628C788E2E9C4A9BB4644678C29F2F",
    },
    PrfVec {
        etype: 18,
        key: "C01F157211F7B77EAAF457C3E156690127EE127D810BA6392E97BAA243EB0616",
        input: b"\x02\x61",
        expected: "B406373350CEE8A6126F4A9B65A0CD21",
    },
    PrfVec {
        etype: 18,
        key: "9D520D2D980AA7CB6B693682B62DA258B333867951642CE647AE62B1E5E0B5E9",
        input: b"\x01\x62",
        expected: "FF0E289EA756C0559A0E911856961A49",
    },
    PrfVec {
        etype: 18,
        key: "9D520D2D980AA7CB6B693682B62DA258B333867951642CE647AE62B1E5E0B5E9",
        input: b"\x02\x62",
        expected: "0D674DD0F9A6806525A4D92E828BD15A",
    },
    PrfVec {
        etype: 19,
        key: "3705D96080C17728A0E800EAB6E0D23C",
        input: b"test",
        expected: "9D188616F63852FE86915BB840B4A886FF3E6BB0F819B49B893393D393854295",
    },
    PrfVec {
        etype: 20,
        key: "6D404D37FAF79F9DF0D33568D320669800EB4836472EA8A026D16B7182460C52",
        input: b"test",
        expected: "9801F69A368C2BF675E59521E177D9A07F67EFE1CFDE8D3C8D6F6A0256E3B17DB3C1B62AD1B8553360D17367EB1514D2",
    },
];

#[test]
fn prf_vectors_t_prf() {
    for (i, v) in PRF_VECTORS.iter().enumerate() {
        let profile = find_etype(v.etype).expect("etype");
        let expected = hex(v.expected);
        assert_eq!(
            profile.prf_length(),
            expected.len(),
            "vector {i} prf_length"
        );
        let out = profile.prf(&hex(v.key), v.input).expect("prf");
        assert_eq!(out.as_slice(), expected.as_slice(), "vector {i} prf");
    }
}

// ---------------------------------------------------------------------------
// t_cf2.in / t_cf2.expected — KRB-FX-CF2 vectors (rows 1,2,5,6)
// ---------------------------------------------------------------------------

#[test]
fn cf2_vectors_t_cf2() {
    // k1 = string_to_key(etype, "key1", salt "key1"), k2 likewise for "key2";
    // peppers "a" / "b".
    let cases: &[(i32, &str)] = &[
        (17, "97df97e4b798b29eb31ed7280287a92a"),
        (
            18,
            "4d6ca4e629785c1f01baf55e2e548566b9617ae3a96868c337cb93b5e72b1c7b",
        ),
        (19, "edd02a39d2dbde31611c16e610be062c"),
        (
            20,
            "67f6ea530aea85a37dcbb23349ea52dcc61ca8493ff557252327fd8304341584",
        ),
    ];
    for &(etype, expected) in cases {
        let profile = find_etype(etype).expect("etype");
        let k1 = EncryptionKey::new(
            etype,
            profile
                .string_to_key(b"key1", b"key1", None)
                .expect("s2k k1")
                .to_vec(),
        );
        let k2 = EncryptionKey::new(
            etype,
            profile
                .string_to_key(b"key2", b"key2", None)
                .expect("s2k k2")
                .to_vec(),
        );
        let out = fx_cf2(&k1, b"a", &k2, b"b").expect("fx_cf2");
        assert_eq!(out.keytype, etype);
        assert_eq!(out.key_bytes(), hex(expected).as_slice(), "etype {etype}");
    }
}

#[test]
fn cf2_output_uses_k1_enctype() {
    let p18 = find_etype(18).expect("18");
    let p17 = find_etype(17).expect("17");
    let k18 = EncryptionKey::new(
        18,
        p18.string_to_key(b"key1", b"key1", None)
            .expect("s2k")
            .to_vec(),
    );
    let k17 = EncryptionKey::new(
        17,
        p17.string_to_key(b"key2", b"key2", None)
            .expect("s2k")
            .to_vec(),
    );

    let out = fx_cf2(&k18, b"a", &k17, b"b").expect("fx_cf2");
    assert_eq!(out.keytype, 18);
    assert_eq!(out.key_bytes().len(), 32);

    let out = fx_cf2(&k17, b"a", &k18, b"b").expect("fx_cf2");
    assert_eq!(out.keytype, 17);
    assert_eq!(out.key_bytes().len(), 16);
}

// ---------------------------------------------------------------------------
// cf2.c:38-79 — PRF+ is counter-prefixed PRF concatenation
// ---------------------------------------------------------------------------

#[test]
fn prf_plus_is_counter_prefixed_prf_concatenation() {
    let p18 = find_etype(18).expect("18");
    let key = hex("C01F157211F7B77EAAF457C3E156690127EE127D810BA6392E97BAA243EB0616");
    let mut expected = hex("B2628C788E2E9C4A9BB4644678C29F2F");
    expected.extend_from_slice(&hex("B406373350CEE8A6126F4A9B65A0CD21"));

    let out = prf_plus(p18, &key, b"a", 32).expect("prf_plus");
    assert_eq!(out.as_slice(), expected.as_slice());
    let out = prf_plus(p18, &key, b"a", 20).expect("prf_plus");
    assert_eq!(out.as_slice(), &expected[..20]);

    let key = hex("9D520D2D980AA7CB6B693682B62DA258B333867951642CE647AE62B1E5E0B5E9");
    let mut expected = hex("FF0E289EA756C0559A0E911856961A49");
    expected.extend_from_slice(&hex("0D674DD0F9A6806525A4D92E828BD15A"));
    let out = prf_plus(p18, &key, b"b", 32).expect("prf_plus");
    assert_eq!(out.as_slice(), expected.as_slice());

    // nblocks > 255 must be an error
    let p17 = find_etype(17).expect("17");
    let key17 = vec![0u8; 16];
    assert!(prf_plus(p17, &key17, b"x", 16 * 256).is_err());
}

// ---------------------------------------------------------------------------
// t_derive.c:206-262 — aes-sha2 KDF-HMAC-SHA2 derivation vectors
// (constant is BE32(usage=2) || purpose byte)
// ---------------------------------------------------------------------------

#[test]
fn sha2_derive_vectors_t_derive() {
    let cases: &[(i32, &str, KeyPurpose, &str)] = &[
        (
            19,
            "3705D96080C17728A0E800EAB6E0D23C",
            KeyPurpose::Checksum, // 0x99
            "B31A018A48F54776F403E9A396325DC3",
        ),
        (
            19,
            "3705D96080C17728A0E800EAB6E0D23C",
            KeyPurpose::Encryption, // 0xAA
            "9B197DD1E8C5609D6E67C3E37C62C72E",
        ),
        (
            19,
            "3705D96080C17728A0E800EAB6E0D23C",
            KeyPurpose::Integrity, // 0x55
            "9FDA0E56AB2D85E1569A688696C26A6C",
        ),
        (
            20,
            "6D404D37FAF79F9DF0D33568D320669800EB4836472EA8A026D16B7182460C52",
            KeyPurpose::Checksum,
            "EF5718BE86CC84963D8BBB5031E9F5C4BA41F28FAF69E73D",
        ),
        (
            20,
            "6D404D37FAF79F9DF0D33568D320669800EB4836472EA8A026D16B7182460C52",
            KeyPurpose::Encryption,
            "56AB22BEE63D82D7BC5227F6773F8EA7A5EB1C825160C38312980C442E5C7E49",
        ),
        (
            20,
            "6D404D37FAF79F9DF0D33568D320669800EB4836472EA8A026D16B7182460C52",
            KeyPurpose::Integrity,
            "69B16514E3CD8E56B82010D5C73012B622C4D00FFC23ED1F",
        ),
    ];
    for &(etype, base, purpose, expected) in cases {
        let profile = find_etype(etype).expect("etype");
        let out = profile
            .derive_key(&hex(base), 2, purpose)
            .expect("derive_key");
        assert_eq!(out.as_slice(), hex(expected).as_slice(), "etype {etype}");
    }
}

// ---------------------------------------------------------------------------
// t_str2key.c:415-440 — aes-sha2 string-to-key vectors
// salt = 16 bytes || "ATHENA.MIT.EDUraeburn", params = 0x00008000
// ---------------------------------------------------------------------------

#[test]
fn sha2_string_to_key_vectors_t_str2key() {
    let mut salt = hex("10DF9DD783E5BC8ACEA1730E74355F61");
    salt.extend_from_slice(b"ATHENA.MIT.EDUraeburn");
    let params = 0x8000u32.to_be_bytes();

    let cases: &[(i32, &str)] = &[
        (19, "089BCA48B105EA6EA77CA5D2F39DC5E7"),
        (
            20,
            "45BD806DBF6A833A9CFFC1C94589A222367A79BC21C413718906E9F578A78467",
        ),
    ];
    for &(etype, expected) in cases {
        let profile = find_etype(etype).expect("etype");
        let out = profile
            .string_to_key(b"password", &salt, Some(&params))
            .expect("string_to_key");
        assert_eq!(out.as_slice(), hex(expected).as_slice(), "etype {etype}");
    }
}

// ---------------------------------------------------------------------------
// t_cksums.c:143-165 — aes-sha2 checksum vectors (usage 2, plaintext 00..14)
// ---------------------------------------------------------------------------

#[test]
fn sha2_checksum_vectors_t_cksums() {
    let plaintext = hex("000102030405060708090A0B0C0D0E0F1011121314");
    let cases: &[(i32, &str, &str)] = &[
        (
            19,
            "3705D96080C17728A0E800EAB6E0D23C",
            "D78367186643D67B411CBA9139FC1DEE",
        ),
        (
            20,
            "6D404D37FAF79F9DF0D33568D320669800EB4836472EA8A026D16B7182460C52",
            "45EE791567EEFCA37F4AC1E0222DE80D43C3BFA06699672A",
        ),
    ];
    for &(etype, key, expected) in cases {
        let profile = find_etype(etype).expect("etype");
        let key = hex(key);
        let cksum = profile.checksum(&key, 2, &plaintext).expect("checksum");
        assert_eq!(cksum, hex(expected), "etype {etype}");
        profile
            .verify_checksum(&key, 2, &plaintext, &cksum)
            .expect("verify_checksum");
        let mut bad = cksum.clone();
        let last = bad.last_mut().expect("nonempty");
        *last ^= 0xFF;
        assert!(matches!(
            profile.verify_checksum(&key, 2, &plaintext, &bad),
            Err(CryptoError::ChecksumMismatch)
        ));
    }
}

// ---------------------------------------------------------------------------
// t_decrypt.c:411-505 — aes-sha2 decryption vectors (usage 2)
// ---------------------------------------------------------------------------

#[test]
fn sha2_decrypt_vectors_t_decrypt() {
    let cases: &[(i32, &[u8], &str, &str)] = &[
        (
            19,
            b"",
            "3705D96080C17728A0E800EAB6E0D23C",
            "EF85FB890BB8472F4DAB20394DCA781DAD877EDA39D50C870C0D5A0A8E48C718",
        ),
        (
            19,
            &hex("000102030405"),
            "3705D96080C17728A0E800EAB6E0D23C",
            "84D7F30754ED987BAB0BF3506BEB09CFB55402CEF7E6877CE99E247E52D16ED4421DFDF8976C",
        ),
        (
            19,
            &hex("000102030405060708090A0B0C0D0E0F"),
            "3705D96080C17728A0E800EAB6E0D23C",
            "3517D640F50DDC8AD3628722B3569D2AE07493FA8263254080EA65C1008E8FC295FB4852E7D83E1E7C48C37EEBE6B0D3",
        ),
        (
            19,
            &hex("000102030405060708090A0B0C0D0E0F1011121314"),
            "3705D96080C17728A0E800EAB6E0D23C",
            "720F73B18D9859CD6CCB4346115CD336C70F58EDC0C4437C5573544C31C813BCE1E6D072C186B39A413C2F92CA9B8334A287FFCBFC",
        ),
        (
            20,
            b"",
            "6D404D37FAF79F9DF0D33568D320669800EB4836472EA8A026D16B7182460C52",
            "41F53FA5BFE7026D91FAF9BE959195A058707273A96A40F0A01960621AC612748B9BBFBE7EB4CE3C",
        ),
        (
            20,
            &hex("000102030405"),
            "6D404D37FAF79F9DF0D33568D320669800EB4836472EA8A026D16B7182460C52",
            "4ED7B37C2BCAC8F74F23C1CF07E62BC7B75FB3F637B9F559C7F664F69EAB7B6092237526EA0D1F61CB20D69D10F2",
        ),
        (
            20,
            &hex("000102030405060708090A0B0C0D0E0F"),
            "6D404D37FAF79F9DF0D33568D320669800EB4836472EA8A026D16B7182460C52",
            "BC47FFEC7998EB91E8115CF8D19DAC4BBBE2E163E87DD37F49BECA92027764F68CF51F14D798C2273F35DF574D1F932E40C4FF255B36A266",
        ),
        (
            20,
            &hex("000102030405060708090A0B0C0D0E0F1011121314"),
            "6D404D37FAF79F9DF0D33568D320669800EB4836472EA8A026D16B7182460C52",
            "40013E2DF58E8751957D2878BCD2D6FE101CCFD556CB1EAE79DB3C3EE86429F2B2A602AC86FEF6ECB647D6295FAE077A1FEB517508D2C16B4192E01F62",
        ),
    ];
    for &(etype, plain, key, ct) in cases {
        let profile = find_etype(etype).expect("etype");
        let key = hex(key);
        let ct = hex(ct);
        let out = profile.decrypt(&key, 2, &ct).expect("decrypt");
        assert_eq!(out, plain, "etype {etype}");

        let mut bad = ct.clone();
        let last = bad.last_mut().expect("nonempty");
        *last ^= 0xFF;
        assert!(matches!(
            profile.decrypt(&key, 2, &bad),
            Err(CryptoError::IntegrityFailure)
        ));
    }
}

#[test]
fn sha2_encrypt_decrypt_roundtrip() {
    for etype in [19, 20] {
        let profile = find_etype(etype).expect("etype");
        let hmac_len = if etype == 19 { 16 } else { 24 };
        let key = profile
            .random_to_key(&rand::random::<[u8; 32]>()[..profile.key_bytes()])
            .expect("random_to_key");
        for len in 0..=64usize {
            let plain: Vec<u8> = (0..len).map(|i| i as u8).collect();
            let ct = profile.encrypt(&key, 2, &plain).expect("encrypt");
            assert_eq!(ct.len(), 16 + len + hmac_len, "etype {etype} len {len}");
            let dec = profile.decrypt(&key, 2, &ct).expect("decrypt");
            assert_eq!(dec, plain, "etype {etype} len {len}");
        }
    }
}

// t_short.c semantics: any ciphertext shorter than the minimum must be an
// error, never a panic.
#[test]
fn sha2_short_ciphertext_rejected() {
    for etype in [19, 20] {
        let profile = find_etype(etype).expect("etype");
        let hmac_len = if etype == 19 { 16 } else { 24 };
        let key = profile
            .random_to_key(&[0x42u8; 32][..profile.key_bytes()])
            .expect("random_to_key");
        for len in 0..(16 + hmac_len) {
            let ct = vec![0u8; len];
            assert!(
                profile.decrypt(&key, 2, &ct).is_err(),
                "etype {etype} accepted {len}-byte ciphertext"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Registry / checksum-type lookup / default etype preference
// ---------------------------------------------------------------------------

#[test]
fn registry_and_cksumtype_lookup() {
    for &(etype, cktype, key_len, prf_len) in &[(19, 19, 16, 32), (20, 20, 32, 48)] {
        let p: &'static dyn EtypeProfile = find_etype(etype).expect("etype");
        assert_eq!(p.etype(), etype);
        assert_eq!(p.checksum_type(), cktype);
        assert_eq!(p.key_length(), key_len);
        assert_eq!(p.prf_length(), prf_len);
    }
    for &(cksumtype, etype) in &[(15, 17), (16, 18), (19, 19), (20, 20)] {
        assert_eq!(find_cksumtype(cksumtype).expect("ck").etype(), etype);
    }
    assert!(find_cksumtype(7).is_err());
    assert!(find_cksumtype(14).is_err());
}

#[test]
fn default_etype_preference_matches_mit() {
    let config = AsExchangeConfig::new(PrincipalName::new_principal("u"), "R");
    assert_eq!(config.etypes, vec![18, 17, 20, 19]);
    assert_eq!(TgsOptions::default().etypes, vec![18, 17, 20, 19]);
}

#[test]
fn sha2_s2k_default_iterations_is_32768() {
    for etype in [19, 20] {
        let profile = find_etype(etype).expect("etype");
        let a = profile
            .string_to_key(b"password", b"EXAMPLE.COMuser", None)
            .expect("s2k default");
        let b = profile
            .string_to_key(
                b"password",
                b"EXAMPLE.COMuser",
                Some(&32768u32.to_be_bytes()),
            )
            .expect("s2k 32768");
        assert_eq!(*a, *b, "etype {etype} default iterations");
        assert!(matches!(
            profile.string_to_key(b"password", b"salt", Some(&0u32.to_be_bytes())),
            Err(CryptoError::BadParams)
        ));
        assert!(matches!(
            profile.string_to_key(b"password", b"salt", Some(&[1, 2, 3])),
            Err(CryptoError::BadParams)
        ));
    }
}

// derive_prfplus smoke check (cf2.c:81-121): output key takes the requested
// etype; etype 0 keeps the input key's etype.
#[test]
fn derive_prfplus_etypes() {
    let p18 = find_etype(18).expect("18");
    let k = EncryptionKey::new(
        18,
        p18.string_to_key(b"key1", b"key1", None)
            .expect("s2k")
            .to_vec(),
    );
    let out = derive_prfplus(&k, b"input", 19).expect("derive_prfplus");
    assert_eq!(out.keytype, 19);
    assert_eq!(out.key_bytes().len(), 16);
    let out = derive_prfplus(&k, b"input", 0).expect("derive_prfplus");
    assert_eq!(out.keytype, 18);
    assert_eq!(out.key_bytes().len(), 32);
}
