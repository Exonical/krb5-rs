//! Cyrus SASL 2.1.28's NTLM client (ntlm.c:1829-2160). libldap gives Cyrus
//! no `getopt` callback, so `ntlm_v2` is off and the response is NTLMv1 (or
//! LM when the server doesn't offer NTLM).

use super::{need, Interact, Layer, Mech};

const SIGNATURE: &[u8; 8] = b"NTLMSSP\0";
const USE_UNICODE: u32 = 0x0001;
const USE_ASCII: u32 = 0x0002;
const ASK_TARGET: u32 = 0x0004;
const AUTH_NTLM: u32 = 0x0200;
const FLAGS_MASK: u32 = 0xffff;
const TYPE2_MINSIZE: usize = 32;

fn le32(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

fn to_unicode(s: &[u8]) -> Vec<u8> {
    s.iter().flat_map(|&c| [c, 0]).collect()
}

/// `E` (ntlm.c:356-373): `data` encrypted under each 7-byte piece of `key`.
fn des_e(key: &[u8], data: &[u8; 8]) -> Vec<u8> {
    use des::cipher::{BlockEncrypt, KeyInit};
    key.chunks(7)
        .flat_map(|k| {
            let des = des::Des::new_from_slice(&super::slidebits(k)).expect("8-byte DES key");
            let mut b = *data;
            des.encrypt_block(des::cipher::generic_array::GenericArray::from_mut_slice(
                &mut b,
            ));
            b
        })
        .collect()
}

/// `P16_nt`: MD4 of the UCS-2 password.
fn p16_nt(pw: &[u8]) -> [u8; 16] {
    use md4::{Digest, Md4};
    Md4::digest(to_unicode(pw)).into()
}

/// `P16_lm`: the upper-cased password, NUL-padded to 14, encrypts "KGS!@#$%".
fn p16_lm(pw: &[u8]) -> [u8; 16] {
    let mut p14 = [0u8; 14];
    for (d, s) in p14.iter_mut().zip(pw.iter().take_while(|&&c| c != 0)) {
        *d = s.to_ascii_uppercase();
    }
    let mut out = [0u8; 16];
    out.copy_from_slice(&des_e(&p14, b"KGS!@#$%"));
    out
}

/// `P24(P21(P16))`: the 24-byte response to `chal`.
fn p24(p16: [u8; 16], chal: &[u8; 8]) -> Vec<u8> {
    let mut p21 = [0u8; 21];
    p21[..16].copy_from_slice(&p16);
    des_e(&p21, chal)
}

/// `load_buffer`: a security buffer header at `hdr` and its data at the end.
fn load(out: &mut Vec<u8>, hdr: usize, data: &[u8]) {
    let len = data.len() as u16;
    let off = out.len() as u32;
    out[hdr..hdr + 2].copy_from_slice(&len.to_le_bytes());
    out[hdr + 2..hdr + 4].copy_from_slice(&len.to_le_bytes());
    out[hdr + 4..hdr + 8].copy_from_slice(&off.to_le_bytes());
    out.extend_from_slice(data);
}

/// `create_request`: a type 1 message with no domain or workstation.
pub(super) fn type1() -> Vec<u8> {
    let mut out = vec![0u8; 32];
    out[..8].copy_from_slice(SIGNATURE);
    out[8..12].copy_from_slice(&1u32.to_le_bytes());
    out[12..16].copy_from_slice(&(USE_UNICODE | USE_ASCII | ASK_TARGET | AUTH_NTLM).to_le_bytes());
    load(&mut out, 16, &[]);
    load(&mut out, 24, &[]);
    out
}

/// `ntlm_client_mech_step2` and `create_response`.
pub(super) fn type3(challenge: &[u8], user: &str, password: &str) -> Result<Vec<u8>, String> {
    if challenge.len() < TYPE2_MINSIZE || &challenge[..8] != SIGNATURE || le32(challenge, 8) != 2 {
        return Err("server didn't issue valid NTLM challenge".into());
    }
    let flags = le32(challenge, 20) & FLAGS_MASK;
    let unicode = flags & USE_UNICODE != 0;
    let tlen = u16::from_le_bytes([challenge[12], challenge[13]]) as usize;
    let toff = le32(challenge, 16) as usize;
    let target = challenge
        .get(toff..toff.saturating_add(tlen))
        .ok_or("NTLM buffer is out of bounds")?;
    let domain: Vec<u8> = if unicode {
        target.chunks(2).map(|c| c[0]).collect()
    } else {
        target.to_vec()
    };
    let mut chal = [0u8; 8];
    chal.copy_from_slice(&challenge[24..32]);
    let (lm, nt) = if flags & AUTH_NTLM != 0 {
        (Vec::new(), p24(p16_nt(password.as_bytes()), &chal))
    } else {
        (p24(p16_lm(password.as_bytes()), &chal), Vec::new())
    };
    let enc = |s: &[u8]| if unicode { to_unicode(s) } else { s.to_vec() };
    let mut out = vec![0u8; 64];
    out[..8].copy_from_slice(SIGNATURE);
    out[8..12].copy_from_slice(&3u32.to_le_bytes());
    load(&mut out, 12, &lm);
    load(&mut out, 20, &nt);
    load(&mut out, 28, &enc(&domain.to_ascii_uppercase()));
    load(&mut out, 36, &enc(user.as_bytes()));
    load(&mut out, 44, &[]);
    load(&mut out, 52, &[]);
    out[60..64].copy_from_slice(&flags.to_le_bytes());
    Ok(out)
}

pub(super) struct Ntlm {
    i: Interact,
    done: bool,
}

impl Ntlm {
    pub(super) fn new(i: Interact) -> Self {
        Ntlm { i, done: false }
    }
}

impl Mech for Ntlm {
    fn start(&mut self) -> Result<Option<Vec<u8>>, String> {
        Ok(Some(type1()))
    }

    fn step(&mut self, challenge: &[u8]) -> Result<Vec<u8>, String> {
        if self.done {
            return Err("unexpected server challenge".into());
        }
        let user = need(&self.i.authcid, "authcid")?;
        let pass = need(&self.i.password, "password")?;
        self.done = true;
        type3(challenge, user, pass)
    }

    fn success(&mut self, _data: Option<&[u8]>) -> Result<Option<Layer>, String> {
        if !self.done {
            return Err("server did not finish the SASL exchange".into());
        }
        Ok(None)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    const CHAL: [u8; 8] = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];

    /// MS-NLMP 4.2.2.
    #[test]
    fn v1_vectors() {
        assert_eq!(
            p16_nt(b"Password").to_vec(),
            hex("a4f49c406510bdcab6824ee7c30fd852")
        );
        assert_eq!(
            p16_lm(b"Password").to_vec(),
            hex("e52cac67419a9a224a3b108f3fa6cb6d")
        );
        assert_eq!(
            p24(p16_nt(b"Password"), &CHAL),
            hex("67c43011f30298a2ad35ece64f16331c44bdbed927841f94")
        );
        assert_eq!(
            p24(p16_lm(b"Password"), &CHAL),
            hex("98def7b87f88aa5dafe2df779688a172def11c7d5ccdef13")
        );
    }

    #[test]
    fn messages() {
        let t1 = type1();
        assert_eq!(t1.len(), 32);
        assert_eq!(le32(&t1, 12), 0x207);
        let mut t2 = vec![0u8; 48];
        t2[..8].copy_from_slice(SIGNATURE);
        t2[8] = 2;
        t2[12] = 12;
        t2[14] = 12;
        t2[16] = 48;
        t2[20..24].copy_from_slice(&(USE_UNICODE | AUTH_NTLM | 0x10000).to_le_bytes());
        t2[24..32].copy_from_slice(&CHAL);
        t2.extend_from_slice(&to_unicode(b"domain"));
        let t3 = type3(&t2, "User", "Password").unwrap();
        assert_eq!(le32(&t3, 60), USE_UNICODE | AUTH_NTLM);
        let buf = |h: usize| {
            let len = u16::from_le_bytes([t3[h], t3[h + 1]]) as usize;
            let off = le32(&t3, h + 4) as usize;
            t3[off..off + len].to_vec()
        };
        assert!(buf(12).is_empty());
        assert_eq!(
            buf(20),
            hex("67c43011f30298a2ad35ece64f16331c44bdbed927841f94")
        );
        assert_eq!(buf(28), to_unicode(b"DOMAIN"));
        assert_eq!(buf(36), to_unicode(b"User"));
        assert!(type3(&t2[..20], "u", "p").is_err());
    }
}
