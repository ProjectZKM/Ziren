//! Multilinear STARK verifier for WHIR PCS.
//!
//! Verifies proofs produced by the multilinear prover using sumcheck-based
//! PCS verification.
//!
//! # Status
//!
//! This is a scaffold. The TODO markers indicate where integration with the
//! existing chip/AIR constraint verification infrastructure is needed.

use alloc::vec::Vec;

use p3_field::Field;

use super::multilinear_prover::{eq_eval, multilinear_vanishing_eval};

/// Verify constraint evaluation at a random point.
///
/// Given the opened constraint evaluation C(zeta) and quotient Q(zeta),
/// check that C(zeta) == Q(zeta) * Z_H(zeta).
pub fn verify_quotient_relationship<F: Field>(
    constraint_eval: F,
    quotient_eval: F,
    zeta: &[F],
) -> bool {
    let z_h = multilinear_vanishing_eval(zeta);
    constraint_eval == quotient_eval * z_h
}
