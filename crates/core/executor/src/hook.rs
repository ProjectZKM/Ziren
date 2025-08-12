use core::fmt::Debug;

use std::sync::{Arc, RwLock, RwLockWriteGuard};

use hashbrown::HashMap;
use zkm_curves::{BigUint, One, Zero};

use crate::Executor;

pub use zkm_primitives::consts::fd::*;

/// A runtime hook, wrapped in a smart pointer.
pub type BoxedHook<'a> = Arc<RwLock<dyn Hook + Send + Sync + 'a>>;

/// A runtime hook. May be called during execution by writing to a specified file descriptor,
/// accepting and returning arbitrary data.
pub trait Hook {
    /// Invoke the runtime hook with a standard environment and arbitrary data.
    /// Returns the computed data.
    fn invoke_hook(&mut self, env: HookEnv, buf: &[u8]) -> Vec<Vec<u8>>;
}

impl<F: FnMut(HookEnv, &[u8]) -> Vec<Vec<u8>>> Hook for F {
    /// Invokes the function `self` as a hook.
    fn invoke_hook(&mut self, env: HookEnv, buf: &[u8]) -> Vec<Vec<u8>> {
        self(env, buf)
    }
}

/// Wrap a function in a smart pointer so it may be placed in a `HookRegistry`.
///
/// Note: the Send + Sync requirement may be logically extraneous. Requires further investigation.
pub fn hookify<'a>(
    f: impl FnMut(HookEnv, &[u8]) -> Vec<Vec<u8>> + Send + Sync + 'a,
) -> BoxedHook<'a> {
    Arc::new(RwLock::new(f))
}

/// A registry of hooks to call, indexed by the file descriptors through which they are accessed.
#[derive(Clone)]
pub struct HookRegistry<'a> {
    /// Table of registered hooks. Prefer using `Runtime::hook`, ` Runtime::hook_env`,
    /// and `HookRegistry::get` over interacting with this field directly.
    pub(crate) table: HashMap<u32, BoxedHook<'a>>,
}

impl<'a> HookRegistry<'a> {
    /// Create a default [`HookRegistry`].
    #[must_use]
    pub fn new() -> Self {
        HookRegistry::default()
    }

    /// Create an empty [`HookRegistry`].
    #[must_use]
    pub fn empty() -> Self {
        Self { table: HashMap::default() }
    }

    /// Get a hook with exclusive write access, if it exists.
    ///
    /// Note: This function should not be called in async contexts, unless you know what you are
    /// doing.
    #[must_use]
    pub fn get(&self, fd: u32) -> Option<RwLockWriteGuard<'_, dyn Hook + Send + Sync + 'a>> {
        // Calling `.unwrap()` panics on a poisoned lock. Should never happen normally.
        self.table.get(&fd).map(|x| x.write().unwrap())
    }
}

impl Default for HookRegistry<'_> {
    fn default() -> Self {
        // When `LazyCell` gets stabilized (1.81.0), we can use it to avoid unnecessary allocations.
        let table = HashMap::from([
            // Note: To ensure any `fd` value is synced with `zkvm/precompiles/src/io.rs`,
            // add an assertion to the test `hook_fds_match` below.
            (FD_ECRECOVER_HOOK, hookify(hook_ecrecover)),
            (FD_FP_SQRT, hookify(fp_ops::hook_fp_sqrt)),
            (FD_FP_INV, hookify(fp_ops::hook_fp_inverse)),
            (FD_BLS12_381_SQRT, hookify(bls::hook_bls12_381_sqrt)),
            (FD_BLS12_381_INVERSE, hookify(bls::hook_bls12_381_inverse)),
        ]);

        Self { table }
    }
}

impl Debug for HookRegistry<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut keys = self.table.keys().collect::<Vec<_>>();
        keys.sort_unstable();
        f.debug_struct("HookRegistry")
            .field(
                "table",
                &format_args!("{{{} hooks registered at {:?}}}", self.table.len(), keys),
            )
            .finish()
    }
}

/// Environment that a hook may read from.
pub struct HookEnv<'a, 'b: 'a> {
    /// The runtime.
    pub runtime: &'a Executor<'b>,
}

/// The hook for the `ecrecover` patches.
///
/// The input should be of the form [(`curve_id_u8` | `r_is_y_odd_u8` << 7) || `r` || `alpha`]
/// where:
/// * `curve_id` is 1 for secp256k1 and 2 for secp256r1
/// * `r_is_y_odd` is 0 if r is even and 1 if r is is odd
/// * r is the x-coordinate of the point, which should be 32 bytes,
/// * alpha := r * r * r * (a * r) + b, which should be 32 bytes.
///
/// Returns vec![vec![1], `y`, `r_inv`] if the point is decompressable
/// and vec![vec![0],`nqr_hint`] if not.
#[must_use]
pub fn hook_ecrecover(_: HookEnv, buf: &[u8]) -> Vec<Vec<u8>> {
    assert!(buf.len() == 64 + 1, "ecrecover should have length 65");

    let curve_id = buf[0] & 0b0111_1111;
    let r_is_y_odd = buf[0] & 0b1000_0000 != 0;

    let r_bytes: [u8; 32] = buf[1..33].try_into().unwrap();
    let alpha_bytes: [u8; 32] = buf[33..65].try_into().unwrap();

    match curve_id {
        1 => ecrecover::handle_secp256k1(r_bytes, alpha_bytes, r_is_y_odd),
        2 => ecrecover::handle_secp256r1(r_bytes, alpha_bytes, r_is_y_odd),
        _ => unimplemented!("Unsupported curve id: {}", curve_id),
    }
}

mod ecrecover {
    use zkm_curves::{k256, p256};

    /// The non-quadratic residue for the curve for secp256k1 and secp256r1.
    const NQR: [u8; 32] = {
        let mut nqr = [0; 32];
        nqr[31] = 3;
        nqr
    };

    pub(super) fn handle_secp256k1(r: [u8; 32], alpha: [u8; 32], r_y_is_odd: bool) -> Vec<Vec<u8>> {
        use k256::{
            elliptic_curve::ff::PrimeField, FieldBytes as K256FieldBytes,
            FieldElement as K256FieldElement, Scalar as K256Scalar,
        };

        let r = K256FieldElement::from_bytes(K256FieldBytes::from_slice(&r)).unwrap();
        debug_assert!(!bool::from(r.is_zero()), "r should not be zero");

        let alpha = K256FieldElement::from_bytes(K256FieldBytes::from_slice(&alpha)).unwrap();
        assert!(!bool::from(alpha.is_zero()), "alpha should not be zero");

        // normalize the y-coordinate always to be consistent.
        if let Some(mut y_coord) = alpha.sqrt().into_option().map(|y| y.normalize()) {
            let r = K256Scalar::from_repr(r.to_bytes()).unwrap();
            let r_inv = r.invert().expect("Non zero r scalar");

            if r_y_is_odd != bool::from(y_coord.is_odd()) {
                y_coord = y_coord.negate(1);
                y_coord = y_coord.normalize();
            }

            vec![vec![1], y_coord.to_bytes().to_vec(), r_inv.to_bytes().to_vec()]
        } else {
            let nqr_field = K256FieldElement::from_bytes(K256FieldBytes::from_slice(&NQR)).unwrap();
            let qr = alpha * nqr_field;
            let root = qr.sqrt().expect("if alpha is not a square, then qr should be a square");

            vec![vec![0], root.to_bytes().to_vec()]
        }
    }

    pub(super) fn handle_secp256r1(r: [u8; 32], alpha: [u8; 32], r_y_is_odd: bool) -> Vec<Vec<u8>> {
        use p256::{
            elliptic_curve::ff::PrimeField, FieldBytes as P256FieldBytes,
            FieldElement as P256FieldElement, Scalar as P256Scalar,
        };

        let r = P256FieldElement::from_bytes(P256FieldBytes::from_slice(&r)).unwrap();
        debug_assert!(!bool::from(r.is_zero()), "r should not be zero");

        let alpha = P256FieldElement::from_bytes(P256FieldBytes::from_slice(&alpha)).unwrap();
        debug_assert!(!bool::from(alpha.is_zero()), "alpha should not be zero");

        if let Some(mut y_coord) = alpha.sqrt().into_option() {
            let r = P256Scalar::from_repr(r.to_bytes()).unwrap();
            let r_inv = r.invert().expect("Non zero r scalar");

            if r_y_is_odd != bool::from(y_coord.is_odd()) {
                y_coord = -y_coord;
            }

            vec![vec![1], y_coord.to_bytes().to_vec(), r_inv.to_bytes().to_vec()]
        } else {
            let nqr_field = P256FieldElement::from_bytes(P256FieldBytes::from_slice(&NQR)).unwrap();
            let qr = alpha * nqr_field;
            let root = qr.sqrt().expect("if alpha is not a square, then qr should be a square");

            vec![vec![0], root.to_bytes().to_vec()]
        }
    }
}

/// Pads a big uint to the given length in big endian.
fn pad_to_be(val: &BigUint, len: usize) -> Vec<u8> {
    // First take the byes in little endian
    let mut bytes = val.to_bytes_le();
    // Resize so we get the full padding correctly.
    bytes.resize(len, 0);
    // Convert back to big endian.
    bytes.reverse();

    bytes
}

mod fp_ops {
    use super::{pad_to_be, BigUint, HookEnv, One, Zero};

    /// Compute the inverse of a field element.
    ///
    /// # Arguments:
    /// * `buf` - The buffer containing the data needed to compute the inverse.
    ///     - [ len || Element || Modulus ]
    ///     - len is the u32 length of the element and modulus in big endian.
    ///     - Element is the field element to compute the inverse of, interpreted as a big endian
    ///       integer of `len` bytes.
    ///
    /// # Returns:
    /// A single 32 byte vector containing the inverse.
    ///
    /// # Panics:
    /// - If the buffer length is not valid.
    /// - If the element is zero.
    pub fn hook_fp_inverse(_: HookEnv, buf: &[u8]) -> Vec<Vec<u8>> {
        let len: usize = u32::from_be_bytes(buf[0..4].try_into().unwrap()) as usize;

        assert!(buf.len() == 4 + 2 * len, "FpOp: Invalid buffer length");

        let buf = &buf[4..];
        let element = BigUint::from_bytes_be(&buf[..len]);
        let modulus = BigUint::from_bytes_be(&buf[len..2 * len]);

        assert!(!element.is_zero(), "FpOp: Inverse called with zero");

        let inverse = element.modpow(&(&modulus - BigUint::from(2u64)), &modulus);

        vec![pad_to_be(&inverse, len)]
    }

    /// Compute the square root of a field element.
    ///
    /// # Arguments:
    /// * `buf` - The buffer containing the data needed to compute the square root.
    ///     - [ len || Element || Modulus || NQR ]
    ///     - len is the length of the element, modulus, and nqr in big endian.
    ///     - Element is the field element to compute the square root of, interpreted as a big
    ///       endian integer of `len` bytes.
    ///     - Modulus is the modulus of the field, interpreted as a big endian integer of `len`
    ///       bytes.
    ///     - NQR is the non-quadratic residue of the field, interpreted as a big endian integer of
    ///       `len` bytes.
    ///
    /// # Assumptions
    /// - NQR is a non-quadratic residue of the field.
    ///
    /// # Returns:
    /// [ `status_u8` || `root_bytes` ]
    ///
    /// If the status is 0, this is the root of NQR * element.
    /// If the status is 1, this is the root of element.
    ///
    /// # Panics:
    /// - If the buffer length is not valid.
    /// - If the element is not less than the modulus.
    /// - If the nqr is not less than the modulus.
    /// - If the element is zero.
    pub fn hook_fp_sqrt(_: HookEnv, buf: &[u8]) -> Vec<Vec<u8>> {
        let len: usize = u32::from_be_bytes(buf[0..4].try_into().unwrap()) as usize;

        assert!(buf.len() == 4 + 3 * len, "FpOp: Invalid buffer length");

        let buf = &buf[4..];
        let element = BigUint::from_bytes_be(&buf[..len]);
        let modulus = BigUint::from_bytes_be(&buf[len..2 * len]);
        let nqr = BigUint::from_bytes_be(&buf[2 * len..3 * len]);

        assert!(
            element < modulus,
            "Element is not less than modulus, the hook only accepts canonical representations"
        );
        assert!(
            nqr < modulus,
            "NQR is zero or non-canonical, the hook only accepts canonical representations"
        );

        // The sqrt of zero is zero.
        if element.is_zero() {
            return vec![vec![1], vec![0; len]];
        }

        // Compute the square root of the element using the general Tonelli-Shanks algorithm.
        // The implementation can be used for any field as it is field-agnostic.
        if let Some(root) = sqrt_fp(&element, &modulus, &nqr) {
            vec![vec![1], pad_to_be(&root, len)]
        } else {
            let qr = (&nqr * &element) % &modulus;
            let root = sqrt_fp(&qr, &modulus, &nqr).unwrap();

            vec![vec![0], pad_to_be(&root, len)]
        }
    }

    /// Compute the square root of a field element for some modulus.
    ///
    /// Requires a known non-quadratic residue of the field.
    fn sqrt_fp(element: &BigUint, modulus: &BigUint, nqr: &BigUint) -> Option<BigUint> {
        // If the prime field is of the form p = 3 mod 4, and `x` is a quadratic residue modulo `p`,
        // then one square root of `x` is given by `x^(p+1 / 4) mod p`.
        if modulus % BigUint::from(4u64) == BigUint::from(3u64) {
            let maybe_root =
                element.modpow(&((modulus + BigUint::from(1u64)) / BigUint::from(4u64)), modulus);

            return Some(maybe_root).filter(|root| root * root % modulus == *element);
        }

        tonelli_shanks(element, modulus, nqr)
    }

    /// Compute the square root of a field element using the Tonelli-Shanks algorithm.
    ///
    /// # Arguments:
    /// * `element` - The field element to compute the square root of.
    /// * `modulus` - The modulus of the field.
    /// * `nqr` - The non-quadratic residue of the field.
    ///
    /// # Assumptions:
    /// - The element is a quadratic residue modulo the modulus.
    ///
    /// Ref: <https://en.wikipedia.org/wiki/Tonelli%E2%80%93Shanks_algorithm>
    #[allow(clippy::many_single_char_names)]
    fn tonelli_shanks(element: &BigUint, modulus: &BigUint, nqr: &BigUint) -> Option<BigUint> {
        // First, compute the Legendre symbol of the element.
        // If the symbol is not 1, then the element is not a quadratic residue.
        if legendre_symbol(element, modulus) != BigUint::one() {
            return None;
        }

        // Find the values of Q and S such that modulus - 1 = Q * 2^S.
        let mut s = BigUint::zero();
        let mut q = modulus - BigUint::one();
        while &q % &BigUint::from(2u64) == BigUint::zero() {
            s += BigUint::from(1u64);
            q /= BigUint::from(2u64);
        }

        let z = nqr;
        let mut c = z.modpow(&q, modulus);
        let mut r = element.modpow(&((&q + BigUint::from(1u64)) / BigUint::from(2u64)), modulus);
        let mut t = element.modpow(&q, modulus);
        let mut m = s;

        while t != BigUint::one() {
            let mut i = BigUint::zero();
            let mut tt = t.clone();
            while tt != BigUint::one() {
                tt = &tt * &tt % modulus;
                i += BigUint::from(1u64);

                if i == m {
                    return None;
                }
            }

            let b_pow =
                BigUint::from(2u64).pow((&m - &i - BigUint::from(1u64)).try_into().unwrap());
            let b = c.modpow(&b_pow, modulus);

            r = &r * &b % modulus;
            c = &b * &b % modulus;
            t = &t * &c % modulus;
            m = i;
        }

        Some(r)
    }

    /// Compute the Legendre symbol of a field element.
    ///
    /// This indicates if the element is a quadratic in the prime field.
    ///
    /// Ref: <https://en.wikipedia.org/wiki/Legendre_symbol>
    fn legendre_symbol(element: &BigUint, modulus: &BigUint) -> BigUint {
        assert!(!element.is_zero(), "FpOp: Legendre symbol of zero called.");

        element.modpow(&((modulus - BigUint::one()) / BigUint::from(2u64)), modulus)
    }

    #[cfg(test)]
    mod test {
        use super::*;
        use std::str::FromStr;

        #[test]
        fn test_legendre_symbol() {
            // The modulus of the secp256k1 base field.
            let modulus = BigUint::from_str(
                "115792089237316195423570985008687907853269984665640564039457584007908834671663",
            )
            .unwrap();
            let neg_1 = &modulus - BigUint::one();

            let fixtures = [
                (BigUint::from(4u64), BigUint::from(1u64)),
                (BigUint::from(2u64), BigUint::from(1u64)),
                (BigUint::from(3u64), neg_1.clone()),
            ];

            for (element, expected) in fixtures {
                let result = legendre_symbol(&element, &modulus);
                assert_eq!(result, expected);
            }
        }

        #[test]
        fn test_tonelli_shanks() {
            // The modulus of the secp256k1 base field.
            let p = BigUint::from_str(
                "115792089237316195423570985008687907853269984665640564039457584007908834671663",
            )
            .unwrap();

            let nqr = BigUint::from_str("3").unwrap();

            let large_element = &p - BigUint::from(u16::MAX);
            let square = &large_element * &large_element % &p;

            let fixtures = [
                (BigUint::from(2u64), true),
                (BigUint::from(3u64), false),
                (BigUint::from(4u64), true),
                (square, true),
            ];

            for (element, expected) in fixtures {
                let result = tonelli_shanks(&element, &p, &nqr);
                if expected {
                    assert!(result.is_some());

                    let result = result.unwrap();
                    assert!((&result * &result) % &p == element);
                } else {
                    assert!(result.is_none());
                }
            }
        }
    }
}

mod bls {
    use super::{pad_to_be, BigUint, HookEnv};
    use zkm_curves::{params::FieldParameters, weierstrass::bls12_381::Bls12381BaseField, Zero};

    /// A non-quadratic residue for the `12_381` base field in big endian.
    pub const NQR_BLS12_381: [u8; 48] = {
        let mut nqr = [0; 48];
        nqr[47] = 2;
        nqr
    };

    /// The base field modulus for the `12_381` curve, in little endian.
    pub const BLS12_381_MODULUS: &[u8] = Bls12381BaseField::MODULUS;

    /// Given a field element, in big endian, this function computes the square root.
    ///
    /// - If the field element is the additive identity, this function returns `vec![vec![1],
    ///   vec![0; 48]]`.
    /// - If the field element is a quadratic residue, this function returns `vec![vec![1],
    ///   vec![sqrt(fe)]  ]`.
    /// - If the field element (fe) is not a quadratic residue, this function returns `vec![vec![0],
    ///   vec![sqrt(``NQR_BLS12_381`` * fe)]]`.
    pub fn hook_bls12_381_sqrt(_: HookEnv, buf: &[u8]) -> Vec<Vec<u8>> {
        let field_element = BigUint::from_bytes_be(&buf[..48]);

        // This should be checked in the VM as its easier than dispatching a hook call.
        // But for completeness we include this happy path also.
        if field_element.is_zero() {
            return vec![vec![1], vec![0; 48]];
        }

        let modulus = BigUint::from_bytes_le(BLS12_381_MODULUS);

        // Since `BLS12_381_MODULUS` == 3 mod 4,. we can use shanks methods.
        // This means we only need to exponentiate by `(modulus + 1) / 4`.
        let exp = (&modulus + BigUint::from(1u64)) / BigUint::from(4u64);
        let sqrt = field_element.modpow(&exp, &modulus);

        // Shanks methods only works if the field element is a quadratic residue.
        // So we need to check if the square of the sqrt is equal to the field element.
        let square = (&sqrt * &sqrt) % &modulus;
        if square != field_element {
            let nqr = BigUint::from_bytes_be(&NQR_BLS12_381);
            let qr = (&nqr * &field_element) % &modulus;

            // By now, the product of two non-quadratic residues is a quadratic residue.
            // So we can use shanks methods again to get its square root.
            //
            // We pass this root back to the VM to constrain the "failure" case.
            let root = qr.modpow(&exp, &modulus);

            assert!((&root * &root) % &modulus == qr, "NQR sanity check failed, this is a bug.");

            return vec![vec![0], pad_to_be(&root, 48)];
        }

        vec![vec![1], pad_to_be(&sqrt, 48)]
    }

    /// Given a field element, in big endian, this function computes the inverse.
    ///
    /// This function will panic if the additive identity is passed in.
    pub fn hook_bls12_381_inverse(_: HookEnv, buf: &[u8]) -> Vec<Vec<u8>> {
        let field_element = BigUint::from_bytes_be(&buf[..48]);

        // Zero is not invertible, and we don't want to have to return a status from here.
        assert!(!field_element.is_zero(), "Field element is the additive identity");

        let modulus = BigUint::from_bytes_le(BLS12_381_MODULUS);

        // Compute the inverse using Fermat's little theorem, ie, a^(p-2) = a^-1 mod p.
        let inverse = field_element.modpow(&(&modulus - BigUint::from(2u64)), &modulus);

        vec![pad_to_be(&inverse, 48)]
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    #[test]
    pub fn registry_new_is_inhabited() {
        assert_ne!(HookRegistry::new().table.len(), 0);
        println!("{:?}", HookRegistry::new());
    }

    #[test]
    pub fn registry_empty_is_empty() {
        assert_eq!(HookRegistry::empty().table.len(), 0);
    }
}
