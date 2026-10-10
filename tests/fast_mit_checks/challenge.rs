#[test]
fn encrypted_challenge_client_direction_roundtrips() {
    let armor_key = EncryptionKey::new(18, rand::random::<[u8; 32]>().to_vec());
    let akey = as_key();
    let ts = now();
    let pa =
        build_pa_encrypted_challenge(&armor_key, &akey, ts, Some(42)).expect("build challenge");
    assert_eq!(pa.padata_type, PA_ENCRYPTED_CHALLENGE);

    let enc: EncryptedData = rasn::der::decode(pa.padata_value.as_ref()).expect("enc-data");
    assert_eq!(enc.etype, akey.keytype);
    let ckey = fx_cf2(
        &armor_key,
        b"clientchallengearmor",
        &akey,
        b"challengelongterm",
    )
    .expect("cf2");
    let plain = profile18()
        .decrypt(
            ckey.key_bytes(),
            key_usage::ENC_CHALLENGE_CLIENT,
            enc.cipher.as_ref(),
        )
        .expect("decrypt");
    let decoded: PaEncTsEnc = rasn::der::decode(&plain).expect("ts");
    assert_eq!(decoded.pausec, Some(42));
}

#[test]
fn kdc_challenge_verifies_and_rejects_client_direction() {
    let armor_key = EncryptionKey::new(18, rand::random::<[u8; 32]>().to_vec());
    let akey = as_key();

    // Build a KDC-direction challenge by hand (usage 55, kdc derivation).
    let kkey = fx_cf2(
        &armor_key,
        b"kdcchallengearmor",
        &akey,
        b"challengelongterm",
    )
    .expect("cf2");
    let ts = rasn::der::encode(&PaEncTsEnc {
        patimestamp: now(),
        pausec: Some(1),
    })
    .expect("ts");
    let cipher = profile18()
        .encrypt(kkey.key_bytes(), key_usage::ENC_CHALLENGE_KDC, &ts)
        .expect("enc");
    let enc = EncryptedData {
        etype: kkey.keytype,
        kvno: None,
        cipher: cipher.into(),
    };
    let enc_der = rasn::der::encode(&enc).expect("enc der");
    verify_kdc_challenge(&armor_key, &akey, &enc_der).expect("kdc challenge verifies");

    // A client-direction ciphertext must not verify as a KDC challenge.
    let client_pa =
        build_pa_encrypted_challenge(&armor_key, &akey, now(), Some(1)).expect("client challenge");
    assert!(verify_kdc_challenge(&armor_key, &akey, client_pa.padata_value.as_ref()).is_err());
}
