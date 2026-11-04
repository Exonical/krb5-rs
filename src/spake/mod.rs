//! SPAKE pre-authentication (MIT `plugins/preauth/spake`, RFC 9xxx
//! draft-ietf-kitten-krb-spake-preauth): group arithmetic, transcript hash
//! and key derivation shared by the client and the KDC.

mod asn1;
mod groups;
mod iana;
#[cfg(test)]
mod vectors;

pub use asn1::{PaSpake, SpakeChallenge, SpakeFactor, SpakeResponse, SpakeSupport};
pub use groups::{Group, InvalidElement};

use crate::crypto::{find_etype, fx_cf2, prf_plus, CryptoError};
use crate::types::EncryptionKey;
use zeroize::Zeroizing;

/// `KRB5_PADATA_SPAKE`.
pub const PA_SPAKE: i32 = 151;
/// `KRB5_KEYUSAGE_SPAKE`.
pub const KEYUSAGE_SPAKE: i32 = 65;
/// `SPAKE_SF_NONE`.
pub const SF_NONE: i32 = 1;

/// `parse_groups` (groups.c): words separated by spaces, tabs, newlines or
/// commas; unknown names and repeats are skipped.
pub fn parse_groups(s: &str) -> Vec<Group> {
    let mut out = Vec::new();
    for word in s
        .split([' ', '\t', '\r', '\n', ','])
        .filter(|w| !w.is_empty())
    {
        if let Some(g) = Group::from_name(word) {
            if !out.contains(&g) {
                out.push(g);
            }
        }
    }
    out
}

/// `update_thash` (util.c): `thash = H(thash || d1 || d2)`, starting from
/// all zeros the length of the group's hash.
pub fn update_thash(group: Group, thash: &mut Vec<u8>, d1: &[u8], d2: &[u8]) {
    if thash.is_empty() {
        thash.resize(group.hash_len(), 0);
    }
    let out = group.hash(&[thash.as_slice(), d1, d2]);
    *thash = out;
}

/// `derive_wbytes` (util.c): PRF+(ikey, "SPAKEsecret" || group) of the
/// group's multiplier length.
pub fn derive_wbytes(
    group: Group,
    ikey: &EncryptionKey,
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let mut input = b"SPAKEsecret".to_vec();
    input.extend_from_slice(&group.id().to_be_bytes());
    prf_plus(
        find_etype(ikey.keytype)?,
        ikey.key_bytes(),
        &input,
        group.mult_len(),
    )
}

/// `derive_key` (util.c): K'[n].
pub fn derive_key(
    group: Group,
    ikey: &EncryptionKey,
    wbytes: &[u8],
    spakeresult: &[u8],
    thash: &[u8],
    der_req: &[u8],
    n: u32,
) -> Result<EncryptionKey, CryptoError> {
    let profile = find_etype(ikey.keytype)?;
    let seedlen = profile.key_bytes();
    let hashlen = group.hash_len();
    let nblocks = seedlen.div_ceil(hashlen);
    let groupn = group.id().to_be_bytes();
    let etypen = ikey.keytype.to_be_bytes();
    let nn = n.to_be_bytes();
    let mut seed = Zeroizing::new(Vec::with_capacity(nblocks * hashlen));
    for i in 0..nblocks {
        let bcount = [(i + 1) as u8];
        seed.extend_from_slice(&group.hash(&[
            b"SPAKEkey",
            &groupn,
            &etypen,
            wbytes,
            spakeresult,
            thash,
            der_req,
            &nn,
            &bcount,
        ]));
    }
    let hkey = profile.random_to_key(&seed[..seedlen])?;
    let hkey = EncryptionKey::new(ikey.keytype, hkey.to_vec());
    fx_cf2(ikey, b"SPAKE", &hkey, b"keyderiv")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("test"))
            .collect()
    }

    #[test]
    fn mit_t_vectors() {
        let mut ran = 0;
        for v in vectors::VECTORS {
            if find_etype(v.enctype).is_err() {
                continue; // DES3 is not implemented.
            }
            ran += 1;
            let group = Group::from_id(v.group).expect("test");
            let ikey = EncryptionKey::new(v.enctype, hex(v.ikey));
            let w = derive_wbytes(group, &ikey).expect("test");
            assert_eq!(&w[..], &hex(v.w)[..], "w {}/{}", v.enctype, v.group);
            let k = hex(v.k);
            assert_eq!(
                group.result(&w, &hex(v.x), &hex(v.s), true).expect("test"),
                k
            );
            assert_eq!(
                group.result(&w, &hex(v.y), &hex(v.t), false).expect("test"),
                k
            );
            let mut thash = Vec::new();
            let support = v.support.map(hex).unwrap_or_default();
            update_thash(group, &mut thash, &support, &hex(v.challenge));
            update_thash(group, &mut thash, &hex(v.s), &[]);
            assert_eq!(thash, hex(v.thash));
            for (n, want) in [v.k0, v.k1, v.k2, v.k3].into_iter().enumerate() {
                let kn =
                    derive_key(group, &ikey, &w, &k, &thash, &hex(v.body), n as u32).expect("test");
                assert_eq!(kn.key_bytes(), &hex(want)[..], "K'[{n}]");
            }
        }
        assert!(ran >= 7);
    }

    #[test]
    fn keygen_result_agree() {
        let ikey = EncryptionKey::new(18, vec![7; 32]);
        for group in [Group::Edwards25519, Group::P256, Group::P384, Group::P521] {
            let w = derive_wbytes(group, &ikey).expect("test");
            let (kpriv, kpub) = group.keygen(&w, true).expect("test");
            let (cpriv, cpub) = group.keygen(&w, false).expect("test");
            assert_eq!(kpub.len(), group.elem_len());
            let a = group.result(&w, &kpriv, &cpub, true).expect("test");
            let b = group.result(&w, &cpriv, &kpub, false).expect("test");
            assert_eq!(a, b);
            if group != Group::Edwards25519 {
                // SEC1 tag 0x05 is not a point encoding.
                let bad = vec![0x05; group.elem_len()];
                let r = group.result(&w, &kpriv, &bad, true);
                assert!(r.is_err(), "{group:?} {r:?}");
            }
        }
    }
}
