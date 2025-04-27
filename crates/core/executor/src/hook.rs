use core::fmt::Debug;

use std::sync::{Arc, RwLock, RwLockWriteGuard};

use hashbrown::HashMap;
use zkm_curves::k256::{Invert, RecoveryId, Signature, VerifyingKey};
use zkm_curves::p256::Signature as p256Signature;
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
    pub fn get(&self, fd: u32) -> Option<RwLockWriteGuard<dyn Hook + Send + Sync + 'a>> {
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
            (K1_ECRECOVER_HOOK, hookify(hook_k1_ecrecover)),
            (R1_ECRECOVER_HOOK, hookify(hook_r1_ecrecover)),
            (FD_FP_SQRT, hookify(fp_ops::hook_fp_sqrt)),
            (FD_FP_INV, hookify(fp_ops::hook_fp_inverse)),
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

/// Recovers the public key from the signature and message hash using the k256 crate.
///
/// # Arguments
///
/// * `env` - The environment in which the hook is invoked.
/// * `buf` - The buffer containing the signature and message hash.
///     - The signature is 65 bytes, the first 64 bytes are the signature and the last byte is the
///       recovery ID.
///     - The message hash is 32 bytes.
///
/// The result is returned as a pair of bytes, where the first 32 bytes are the X coordinate
/// and the second 32 bytes are the Y coordinate of the decompressed point.
///
/// WARNING: This function is used to recover the public key outside of the zkVM context. These
/// values must be constrained by the zkVM for correctness.
#[must_use]
pub fn hook_k1_ecrecover(_: HookEnv, buf: &[u8]) -> Vec<Vec<u8>> {
    assert_eq!(buf.len(), 65 + 32, "ecrecover input should have length 65 + 32");
    let (sig, msg_hash) = buf.split_at(65);
    let sig: &[u8; 65] = sig.try_into().unwrap();
    let msg_hash: &[u8; 32] = msg_hash.try_into().unwrap();

    let mut recovery_id = sig[64];
    let mut sig = Signature::from_slice(&sig[..64]).unwrap();

    if let Some(sig_normalized) = sig.normalize_s() {
        sig = sig_normalized;
        recovery_id ^= 1;
    };
    let recid = RecoveryId::from_byte(recovery_id).expect("Computed recovery ID is invalid!");

    let recovered_key = VerifyingKey::recover_from_prehash(&msg_hash[..], &sig, recid).unwrap();
    let bytes = recovered_key.to_sec1_bytes();

    let (_, s) = sig.split_scalars();
    let s_inverse = s.invert();

    vec![bytes.to_vec(), s_inverse.to_bytes().to_vec()]
}

/// Recovers s inverse from the signature using the secp256r1 crate.
///
/// # Arguments
///
/// * `env` - The environment in which the hook is invoked.
/// * `buf` - The buffer containing the signature.
///     - The signature is 64 bytes.
///
/// The result is a single 32 byte vector containing s inverse.
#[must_use]
pub fn hook_r1_ecrecover(_: HookEnv, buf: &[u8]) -> Vec<Vec<u8>> {
    assert_eq!(buf.len(), 64, "ecrecover input should have length 64");
    let sig: &[u8; 64] = buf.try_into().unwrap();
    let sig = p256Signature::from_slice(sig).unwrap();

    let (_, s) = sig.split_scalars();
    let s_inverse = s.invert();

    vec![s_inverse.to_bytes().to_vec()]
}

#[cfg(test)]
pub mod tests {
    use super::*;

    // #[test]
    // pub fn hook_fds_match() {
    //     use zkm_zkvm::io;
    //     assert_eq!(K1_ECRECOVER_HOOK, io::K1_ECRECOVER_HOOK);
    //     assert_eq!(R1_ECRECOVER_HOOK, io::R1_ECRECOVER_HOOK);
    // }

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
