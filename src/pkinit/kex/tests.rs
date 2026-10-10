//! RFC 8636 appendix test vectors (MIT pkinit_kdf_test.c:40-213) and group
//! behaviour.

use super::*;

fn party(name: &str, realm: &str) -> (PrincipalName, String) {
    let comps: Vec<_> = name.split('/').collect();
    let mut n = PrincipalName::new_principal(comps[0]);
    for c in &comps[1..] {
        n.name_string
            .push(rasn::types::GeneralString::from_bytes(c.as_bytes()).expect("component"));
    }
    (n, realm.to_string())
}

type Party = (PrincipalName, String);
type VectorInputs = (Vec<u8>, Party, Party, Vec<u8>, Vec<u8>);

fn vector_inputs() -> VectorInputs {
    (
        vec![0u8; 256],
        party("lha", "SU.SE"),
        party("krbtgt/SU.SE", "SU.SE"),
        vec![0xaa; 10],
        vec![0xbb; 9],
    )
}

#[test]
fn rfc8636_vector_sha1_aes256() {
    let (secret, u, v, req, rep) = vector_inputs();
    let key = pkinit_kdf(
        &secret,
        Some(Kdf::Sha1),
        18,
        (&u.0, &u.1),
        (&v.0, &v.1),
        &req,
        &rep,
    )
    .expect("kdf");
    assert_eq!(
        key.key_bytes(),
        [
            0xe6, 0xAB, 0x38, 0xC9, 0x41, 0x3E, 0x03, 0x5B, 0xB0, 0x79, 0x20, 0x1E, 0xD0, 0xB6,
            0xB7, 0x3D, 0x8D, 0x49, 0xA8, 0x14, 0xA7, 0x37, 0xC0, 0x4E, 0xE6, 0x64, 0x96, 0x14,
            0x20, 0x6F, 0x73, 0xAD
        ]
    );
}

#[test]
fn rfc8636_vector_sha256_aes256() {
    let (secret, u, v, req, rep) = vector_inputs();
    let key = pkinit_kdf(
        &secret,
        Some(Kdf::Sha256),
        18,
        (&u.0, &u.1),
        (&v.0, &v.1),
        &req,
        &rep,
    )
    .expect("kdf");
    assert_eq!(
        key.key_bytes(),
        [
            0x77, 0xEF, 0x4E, 0x48, 0xC4, 0x20, 0xAE, 0x3F, 0xEC, 0x75, 0x10, 0x9D, 0x79, 0x81,
            0x69, 0x7E, 0xED, 0x5D, 0x29, 0x5C, 0x90, 0xc6, 0x25, 0x64, 0xF7, 0xBF, 0xD1, 0x01,
            0xFA, 0x9b, 0xC1, 0xD5
        ]
    );
}

#[test]
fn rfc8636_vector_sha512_des3_material_matches() {
    // des3-cbc-sha1 is not supported here; the 21 bytes of KDF output must
    // be the 56 significant bits of each byte of the expected 24-byte key.
    let (secret, u, v, req, rep) = vector_inputs();
    let material = sskdf_material(
        &secret,
        Kdf::Sha512,
        16,
        (&u.0, &u.1),
        (&v.0, &v.1),
        &req,
        &rep,
        21,
    )
    .expect("sskdf");
    let key3 = [
        0xD3u8, 0xC7, 0x8A, 0x79, 0xD6, 0x52, 0x13, 0xEF, 0xE9, 0xA8, 0x26, 0xF7, 0x5D, 0xFB, 0x01,
        0xF7, 0x23, 0x62, 0xFB, 0x16, 0xFB, 0x01, 0xDA, 0xD6,
    ];
    // RFC 3961 DES3 random-to-key: the eighth byte of each block carries the
    // low bits of the first seven.
    let mut packed = Vec::new();
    for block in key3.chunks(8) {
        for i in 0..7 {
            packed.push((block[i] & 0xfe) | ((block[7] >> (i + 1)) & 1));
        }
    }
    assert_eq!(&material[..], &packed[..]);
}

#[test]
fn octetstring2key_expands_with_counter_prefixed_sha1() {
    let key = octetstring2key(18, &[7u8; 256]).expect("os2k");
    assert_eq!(key.key_bytes().len(), 32);
    let again = octetstring2key(18, &[7u8; 256]).expect("os2k");
    assert_eq!(key.key_bytes(), again.key_bytes());
    assert_ne!(
        key.key_bytes(),
        octetstring2key(18, &[8u8; 256]).expect("os2k").key_bytes()
    );
    assert!(pkinit_kdf(
        &[1; 128],
        None,
        18,
        (&party("a", "R").0, "R"),
        (&party("b", "R").0, "R"),
        b"",
        b""
    )
    .is_ok());
}

#[test]
fn every_group_agrees_and_round_trips_through_spki() {
    for group in Group::ALL {
        let a = KeyPair::generate(group);
        let b = KeyPair::generate(group);
        let (g, raw) = decode_spki(&b.spki()).expect("decode spki");
        assert_eq!(g, group);
        assert_eq!(raw, b.public_value());
        let s1 = a.agree(b.public_value()).expect("agree");
        let s2 = b.agree(a.public_value()).expect("agree");
        assert_eq!(s1.as_slice(), s2.as_slice(), "{}", group.name());
        let expected_len = match group {
            Group::Modp1024 => 128,
            Group::Modp2048 => 256,
            Group::Modp4096 => 512,
            Group::P256 => 32,
            Group::P384 => 48,
            Group::P521 => 66,
        };
        assert_eq!(s1.len(), expected_len, "{}", group.name());
        let spki_der = rasn::der::encode(&a.spki()).expect("encode");
        let back: SubjectPublicKeyInfo = rasn::der::decode(&spki_der).expect("decode");
        assert_eq!(decode_spki(&back).expect("group").0, group);
    }
}

#[test]
fn td_parameters_algorithm_identifiers_identify_their_group() {
    for group in Group::ALL {
        let id = group.algorithm_identifier();
        assert_eq!(Group::from_algorithm_identifier(&id), Some(group));
        assert_eq!(Group::from_bits(group.bits()), Some(group));
    }
    let bogus = AlgorithmIdentifier {
        algorithm: asn1::oid(asn1::SHA256_WITH_RSA),
        parameters: None,
    };
    assert_eq!(Group::from_algorithm_identifier(&bogus), None);
}

#[test]
fn dh_public_values_outside_the_subgroup_are_rejected() {
    let kp = KeyPair::generate(Group::Modp2048);
    let p = modp(Group::Modp2048).p_bytes.clone();
    let mut p_minus_1 = p.clone();
    *p_minus_1.last_mut().expect("byte") -= 1;
    for bad in [vec![0u8], vec![1u8], p_minus_1, p.clone()] {
        let err = kp.agree(&der::uint(&bad)).expect_err("must reject");
        assert!(matches!(err, KexError::BadParameters(_)), "{bad:?}");
    }
    assert!((3u8..20).any(|y| kp.agree(&der::uint(&[y])).is_err()));
    assert!(kp.agree(&[0x04, 0x00]).is_err());
    let ec = KeyPair::generate(Group::P256);
    assert!(ec.agree(&[4; 65]).is_err());
}

#[test]
fn kdf_selection_follows_the_server_preference_order() {
    assert_eq!(Kdf::SUPPORTED, [Kdf::Sha256, Kdf::Sha1, Kdf::Sha512]);
    for k in Kdf::SUPPORTED {
        assert_eq!(Kdf::from_oid(&asn1::oid(k.oid_bytes())), Some(k));
    }
}

#[test]
fn parse_dh_min_bits_follows_mit() {
    assert_eq!(parse_dh_min_bits(None), 2048);
    assert_eq!(parse_dh_min_bits(Some("1024")), 1024);
    assert_eq!(parse_dh_min_bits(Some("1500")), 2048);
    assert_eq!(parse_dh_min_bits(Some("2049")), 4096);
    assert_eq!(parse_dh_min_bits(Some("4096")), 4096);
    assert_eq!(parse_dh_min_bits(Some("4097")), 2048);
    assert_eq!(parse_dh_min_bits(Some("512")), 2048);
    assert_eq!(parse_dh_min_bits(Some("p-256")), DH_P256_BITS);
    assert_eq!(parse_dh_min_bits(Some("P-384")), DH_P384_BITS);
    assert_eq!(parse_dh_min_bits(Some("P-521")), DH_P521_BITS);
    assert_eq!(parse_dh_min_bits(Some("bogus")), 2048);
}
