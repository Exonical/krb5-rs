//! SPAKE groups (MIT `groups.c`, `edwards25519.c`, `openssl.c`).

use super::iana;
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar as EdScalar;
use sha2::{Digest, Sha256, Sha384, Sha512};
use zeroize::Zeroizing;

/// A SPAKE group (IANA "Kerberos SPAKE Groups").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Group {
    /// `edwards25519` (1).
    Edwards25519,
    /// `P-256` (2).
    P256,
    /// `P-384` (3).
    P384,
    /// `P-521` (4).
    P521,
}

/// The peer's public value is not a valid group element (MIT `EINVAL`).
#[derive(Debug, PartialEq, Eq)]
pub struct InvalidElement;

impl Group {
    /// Every group, in IANA number order.
    pub const ALL: [Group; 4] = [Group::Edwards25519, Group::P256, Group::P384, Group::P521];

    /// IANA group number.
    pub fn id(self) -> i32 {
        match self {
            Group::Edwards25519 => 1,
            Group::P256 => 2,
            Group::P384 => 3,
            Group::P521 => 4,
        }
    }

    /// Group with IANA number `id`.
    pub fn from_id(id: i32) -> Option<Group> {
        Group::ALL.into_iter().find(|g| g.id() == id)
    }

    /// IANA name, as in `spake_preauth_groups`.
    pub fn name(self) -> &'static str {
        match self {
            Group::Edwards25519 => "edwards25519",
            Group::P256 => "P-256",
            Group::P384 => "P-384",
            Group::P521 => "P-521",
        }
    }

    /// `find_gnum` (groups.c): case-insensitive IANA name.
    pub fn from_name(s: &str) -> Option<Group> {
        Group::ALL
            .into_iter()
            .find(|g| g.name().eq_ignore_ascii_case(s))
    }

    /// Length of a marshalled multiplier (scalar).
    pub fn mult_len(self) -> usize {
        match self {
            Group::Edwards25519 | Group::P256 => 32,
            Group::P384 => 48,
            Group::P521 => 66,
        }
    }

    /// Length of a marshalled group element.
    pub fn elem_len(self) -> usize {
        match self {
            Group::Edwards25519 => 32,
            Group::P256 => 33,
            Group::P384 => 49,
            Group::P521 => 67,
        }
    }

    /// Output length of the group's hash.
    pub fn hash_len(self) -> usize {
        match self {
            Group::Edwards25519 | Group::P256 => 32,
            Group::P384 => 48,
            Group::P521 => 64,
        }
    }

    /// The group's hash over the concatenation of `parts`.
    pub fn hash(self, parts: &[&[u8]]) -> Vec<u8> {
        fn h<D: Digest>(parts: &[&[u8]]) -> Vec<u8> {
            let mut d = D::new();
            for p in parts {
                d.update(p);
            }
            d.finalize().to_vec()
        }
        match self {
            Group::Edwards25519 | Group::P256 => h::<Sha256>(parts),
            Group::P384 => h::<Sha384>(parts),
            Group::P521 => h::<Sha512>(parts),
        }
    }

    /// `group_keygen`: a private multiplier and the masked public element
    /// `priv*G + w*M` (KDC, `use_m`) or `priv*G + w*N` (client).
    pub fn keygen(
        self,
        wbytes: &[u8],
        use_m: bool,
    ) -> Result<(Zeroizing<Vec<u8>>, Vec<u8>), InvalidElement> {
        match self {
            Group::Edwards25519 => ed_keygen(wbytes, use_m),
            Group::P256 => nist_keygen::<p256::NistP256>(self, wbytes, use_m),
            Group::P384 => nist_keygen::<p384::NistP384>(self, wbytes, use_m),
            Group::P521 => nist_keygen::<p521::NistP521>(self, wbytes, use_m),
        }
    }

    /// `group_result`: `ourpriv*(theirpub - w*C)`, where `C` is the peer's
    /// constant (`N` when `kdc`, else `M`).
    pub fn result(
        self,
        wbytes: &[u8],
        ourpriv: &[u8],
        theirpub: &[u8],
        kdc: bool,
    ) -> Result<Vec<u8>, InvalidElement> {
        let use_m = !kdc;
        if theirpub.len() != self.elem_len() || ourpriv.len() != self.mult_len() {
            return Err(InvalidElement);
        }
        match self {
            Group::Edwards25519 => ed_result(wbytes, ourpriv, theirpub, use_m),
            Group::P256 => nist_result::<p256::NistP256>(self, wbytes, ourpriv, theirpub, use_m),
            Group::P384 => nist_result::<p384::NistP384>(self, wbytes, ourpriv, theirpub, use_m),
            Group::P521 => nist_result::<p521::NistP521>(self, wbytes, ourpriv, theirpub, use_m),
        }
    }

    fn constants(self) -> (&'static [u8], &'static [u8]) {
        match self {
            Group::Edwards25519 => (&iana::EDWARDS25519_M, &iana::EDWARDS25519_N),
            Group::P256 => (&iana::P256_M, &iana::P256_N),
            Group::P384 => (&iana::P384_M, &iana::P384_N),
            Group::P521 => (&iana::P521_M, &iana::P521_N),
        }
    }
}

fn ed_point(bytes: &[u8]) -> Result<EdwardsPoint, InvalidElement> {
    let b: [u8; 32] = bytes.try_into().map_err(|_| InvalidElement)?;
    CompressedEdwardsY(b).decompress().ok_or(InvalidElement)
}

fn ed_w(wbytes: &[u8]) -> EdScalar {
    let mut w = [0u8; 32];
    w.copy_from_slice(&wbytes[..32]);
    EdScalar::from_bytes_mod_order(w)
}

fn ed_constant(use_m: bool) -> EdwardsPoint {
    let (m, n) = Group::Edwards25519.constants();
    #[allow(clippy::expect_used)]
    ed_point(if use_m { m } else { n }).expect("IANA constant")
}

/// MIT's edwards25519 private value is `8*r` (`r` uniform mod l) as a
/// 32-byte little-endian integer; `r` is recovered by shifting right 3.
fn ed_r(private: &[u8]) -> EdScalar {
    let mut r = [0u8; 32];
    for i in 0..32 {
        let hi = private.get(i + 1).copied().unwrap_or(0);
        r[i] = (private[i] >> 3) | (hi << 5);
    }
    EdScalar::from_bytes_mod_order(r)
}

fn ed_keygen(wbytes: &[u8], use_m: bool) -> Result<(Zeroizing<Vec<u8>>, Vec<u8>), InvalidElement> {
    let mut wide = Zeroizing::new([0u8; 64]);
    rand::fill(&mut wide[..32]);
    let r = EdScalar::from_bytes_mod_order_wide(&wide);
    // left_shift_3 of the reduced scalar: an integer below 2^256.
    let rb = r.to_bytes();
    let mut private = Zeroizing::new(vec![0u8; 32]);
    let mut carry = 0u8;
    for i in 0..32 {
        private[i] = (rb[i] << 3) | carry;
        carry = rb[i] >> 5;
    }
    let p = EdwardsPoint::mul_base(&r).mul_by_cofactor() + ed_constant(use_m) * ed_w(wbytes);
    Ok((private, p.compress().to_bytes().to_vec()))
}

fn ed_result(
    wbytes: &[u8],
    ourpriv: &[u8],
    theirpub: &[u8],
    use_m: bool,
) -> Result<Vec<u8>, InvalidElement> {
    let q = ed_point(theirpub)? - ed_constant(use_m) * ed_w(wbytes);
    let k = (q * ed_r(ourpriv)).mul_by_cofactor();
    Ok(k.compress().to_bytes().to_vec())
}

use p256::elliptic_curve::group::{Curve as _, Group as _, GroupEncoding};
use p256::elliptic_curve::ops::Reduce;
use p256::elliptic_curve::{CurveArithmetic, FieldBytes, PrimeField};

fn bytes_ref<R: AsRef<[u8]>>(r: &R) -> &[u8] {
    r.as_ref()
}

fn bytes_mut<R: AsMut<[u8]>>(r: &mut R) -> &mut [u8] {
    r.as_mut()
}

type Affine<C> = <C as CurveArithmetic>::AffinePoint;
type Proj<C> = <C as CurveArithmetic>::ProjectivePoint;
type Sc<C> = <C as CurveArithmetic>::Scalar;

fn nist_point<C: CurveArithmetic>(bytes: &[u8]) -> Result<Proj<C>, InvalidElement> {
    let mut repr = <Affine<C> as GroupEncoding>::Repr::default();
    // Compressed SEC1 only, as MIT marshals; the sec1 crate also accepts
    // tag 0x05 (compact), which OpenSSL rejects.
    if bytes_ref(&repr).len() != bytes.len() || !matches!(bytes.first(), Some(2 | 3)) {
        return Err(InvalidElement);
    }
    bytes_mut(&mut repr).copy_from_slice(bytes);
    Option::<Affine<C>>::from(Affine::<C>::from_bytes(&repr))
        .map(Into::into)
        .ok_or(InvalidElement)
}

fn nist_constant<C: CurveArithmetic>(g: Group, use_m: bool) -> Proj<C> {
    let (m, n) = g.constants();
    #[allow(clippy::expect_used)]
    nist_point::<C>(if use_m { m } else { n }).expect("IANA constant")
}

fn nist_w<C: CurveArithmetic>(wbytes: &[u8]) -> Sc<C>
where
    Sc<C>: Reduce<FieldBytes<C>>,
{
    let mut fb = FieldBytes::<C>::default();
    fb.copy_from_slice(wbytes);
    <Sc<C> as Reduce<FieldBytes<C>>>::reduce(&fb)
}

fn nist_keygen<C: CurveArithmetic>(
    g: Group,
    wbytes: &[u8],
    use_m: bool,
) -> Result<(Zeroizing<Vec<u8>>, Vec<u8>), InvalidElement>
where
    Sc<C>: Reduce<FieldBytes<C>>,
{
    // BN_rand_range(order): rejection-sample a canonical scalar.
    let priv_scalar = loop {
        let mut repr = <Sc<C> as PrimeField>::Repr::default();
        let b = bytes_mut(&mut repr);
        rand::fill(&mut *b);
        if g == Group::P521 {
            b[0] &= 0x01;
        }
        if let Some(s) = Option::<Sc<C>>::from(Sc::<C>::from_repr(repr)) {
            break s;
        }
    };
    let p =
        Proj::<C>::generator() * priv_scalar + nist_constant::<C>(g, use_m) * nist_w::<C>(wbytes);
    let private = Zeroizing::new(bytes_ref(&priv_scalar.to_repr()).to_vec());
    Ok((private, bytes_ref(&p.to_affine().to_bytes()).to_vec()))
}

fn nist_result<C: CurveArithmetic>(
    g: Group,
    wbytes: &[u8],
    ourpriv: &[u8],
    theirpub: &[u8],
    use_m: bool,
) -> Result<Vec<u8>, InvalidElement>
where
    Sc<C>: Reduce<FieldBytes<C>>,
{
    let mut repr = <Sc<C> as PrimeField>::Repr::default();
    if bytes_mut(&mut repr).len() != ourpriv.len() {
        return Err(InvalidElement);
    }
    bytes_mut(&mut repr).copy_from_slice(ourpriv);
    let priv_scalar = Option::<Sc<C>>::from(Sc::<C>::from_repr(repr)).ok_or(InvalidElement)?;
    let q = nist_point::<C>(theirpub)? - nist_constant::<C>(g, use_m) * nist_w::<C>(wbytes);
    Ok(bytes_ref(&(q * priv_scalar).to_affine().to_bytes()).to_vec())
}
