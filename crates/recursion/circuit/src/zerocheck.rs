//! In-circuit zerocheck verifier helpers.
//!
//! Hosts the small, self-contained helpers used by the BaseFold-
//! pipeline shard verifier's zerocheck phase:
//!
//!   - [`full_geq`]: in-circuit "≥" indicator for one boolean point
//!     versus an extension-field point.  Used to compute the padded-
//!     row mask that gates the zerocheck constraint outside the
//!     real-data window of each chip.
//!   - [`eq_eval`]: full Lagrange equality evaluation for two
//!     extension-field points of the same dimension.  Used to check
//!     the GKR-evaluation point matches the sumcheck-reduced point.
//!
//! The full `verify_zerocheck` orchestrator (which composes these
//! helpers with [`crate::sumcheck::verify_sumcheck`], constraint
//! folding, and per-chip openings batching) lands in a subsequent
//! step of the in-circuit BaseFold verifier rewrite — see
//! [`docs/recursion_verifier_port.md`](../../../../docs/recursion_verifier_port.md).
//!
//! # Reference
//!
//! Mirrors helper portions of the upstream
//! [`zerocheck.rs`](file:///tmp/sp1/crates/recursion/circuit/src/zerocheck.rs)
//! and supporting `slop_multilinear` MLE helpers (`full_geq`,
//! `Mle::full_lagrange_eval`).

use std::marker::PhantomData;

use p3_air::{Air, BaseAir};
use p3_field::PrimeCharacteristicRing;
use zkm_recursion_compiler::ir::{Builder, Ext, Felt, SymbolicExt};
use zkm_stark::{air::MachineAir, ChipOpenedValues, MachineChip, OpeningShapeError};
use zkm_stark::folder::PairWindow;

use crate::basefold_constraint_folder::BasefoldConstraintFolder;
use crate::CircuitConfig;

/// In-circuit "≥" indicator for `eval_point` ≥ `threshold` in
/// lexicographic order, where `threshold` is a boolean point and
/// `eval_point` is an extension-field point.
///
/// Both points must have the same dimension.  Output is `1` if
/// `eval_point` lexicographically dominates `threshold`, `0`
/// otherwise (when both are boolean), and a soft interpolation
/// when `eval_point` is a non-boolean extension element.
///
/// Used by the zerocheck verifier to mask out the padded-row
/// region of each chip: constraints fire only for real rows
/// (indices below the chip's height), so the padded-row adjustment
/// gets multiplied by `geq(degree, sumcheck_point)` to zero it out
/// for in-range positions.
///
/// # Reference
///
/// Mirrors [`slop_multilinear::full_geq`](file:///tmp/sp1/slop/crates/multilinear/src/mle.rs:398-407).
/// Iterates MSB-first (matching the upstream convention) — note
/// this differs from the LSB-first `partial_lagrange` convention
/// used elsewhere in Ziren's BaseFold port.
pub fn full_geq<C: CircuitConfig>(
    threshold: &[SymbolicExt<C::F, C::EF>],
    eval_point: &[SymbolicExt<C::F, C::EF>],
) -> SymbolicExt<C::F, C::EF> {
    assert_eq!(
        threshold.len(),
        eval_point.len(),
        "full_geq: threshold and eval_point must have equal dimension"
    );
    threshold
        .iter()
        .rev()
        .zip(eval_point.iter().rev())
        .fold(SymbolicExt::ONE, |acc, (x, y)| {
            // Lifted from the upstream:
            //   ((1-y)(1-x) + y*x) * acc + y*(1-x)
            // → the eq term carries forward when the bits agree,
            //   then a "step-up" term fires whenever y is 1 and x
            //   is 0 (i.e., eval_point > threshold at this bit).
            let one = SymbolicExt::ONE;
            ((one - *y) * (one - *x) + *y * *x) * acc + *y * (one - *x)
        })
}

/// Full Lagrange equality evaluation for two extension-field points.
/// Computes
///
/// ```text
///   eq(a, b) = Π_k ((1 - a_k)(1 - b_k) + a_k · b_k)
/// ```
///
/// — the indicator that a == b on the boolean hypercube, lifted to
/// the extension field via the standard multilinear extension.
///
/// Used by the zerocheck verifier to check that the GKR-emitted
/// evaluation point matches the sumcheck-reduced point.
///
/// # Reference
///
/// Mirrors [`slop_multilinear::Mle::full_lagrange_eval`].
pub fn eq_eval<C: CircuitConfig>(
    a: &[SymbolicExt<C::F, C::EF>],
    b: &[SymbolicExt<C::F, C::EF>],
) -> SymbolicExt<C::F, C::EF> {
    assert_eq!(
        a.len(),
        b.len(),
        "eq_eval: points must have equal dimension"
    );
    let one = SymbolicExt::<C::F, C::EF>::ONE;
    a.iter()
        .zip(b.iter())
        .fold(one, |acc, (ai, bi)| {
            acc * ((one - *ai) * (one - *bi) + *ai * *bi)
        })
}

/// Verify that a chip's opening has the expected per-batch widths.
///
/// Returns `Ok(())` if the preprocessed and main widths match the
/// chip's expected dimensions; otherwise returns an
/// [`OpeningShapeError`].  Called by the zerocheck verifier
/// before evaluating the chip's constraints to catch shape
/// mismatches early.
///
/// # Reference
///
/// Mirrors [`verify_opening_shape`](file:///tmp/sp1/crates/recursion/circuit/src/zerocheck.rs:88-109).
pub fn verify_opening_shape<C, A>(
    chip: &MachineChip<zkm_stark::koala_bear_poseidon2::KoalaBearPoseidon2, A>,
    opening: &ChipOpenedValues<Felt<C::F>, Ext<C::F, C::EF>>,
) -> Result<(), OpeningShapeError>
where
    C: CircuitConfig,
    A: MachineAir<p3_koala_bear::KoalaBear>,
{
    if opening.preprocessed.local.len() != chip.preprocessed_width() {
        return Err(OpeningShapeError::PreprocessedWidthMismatch(
            chip.preprocessed_width(),
            opening.preprocessed.local.len(),
        ));
    }
    if opening.main.local.len() != chip.width() {
        return Err(OpeningShapeError::MainWidthMismatch(
            chip.width(),
            opening.main.local.len(),
        ));
    }
    Ok(())
}

/// Evaluate a chip's constraint polynomial at the sumcheck point
/// implied by `opening` (the chip's preprocessed and main local
/// values), returning the constraint accumulator as a single Ext
/// value.
///
/// # Status
///
/// Signature complete; body deferred.  The full implementation
/// requires the [`crate::basefold_constraint_folder::BasefoldConstraintFolder`]
/// to additionally implement [`zkm_stark::air::MultiTableAirBuilder`]
/// — which carries `local_cumulative_sum` and `global_cumulative_sum`
/// references that the per-chip permutation-constraint code path
/// reads.  In the BaseFold pipeline these sums live in the
/// LogUp-GKR sumcheck output rather than as per-chip Air-side
/// fields, so the implementation needs a bridging strategy:
/// either (a) adapt the folder to carry placeholder sums that
/// trip-no-op through `eval_permutation_constraints`, or (b)
/// invoke `chip.air.eval(&mut folder)` directly, bypassing the
/// permutation-emit wrapper around `Chip::eval`.
///
/// # Reference
///
/// Mirrors [`eval_constraints`](file:///tmp/sp1/crates/recursion/circuit/src/zerocheck.rs:37-58).
pub fn eval_constraints<C, A>(
    _builder: &mut Builder<C>,
    _chip: &MachineChip<zkm_stark::koala_bear_poseidon2::KoalaBearPoseidon2, A>,
    _opening: &ChipOpenedValues<Felt<C::F>, Ext<C::F, C::EF>>,
    _alpha: Ext<C::F, C::EF>,
    _public_values: &[Felt<C::F>],
) -> Ext<C::F, C::EF>
where
    C: CircuitConfig,
    A: MachineAir<p3_koala_bear::KoalaBear>
        + for<'b> Air<BasefoldConstraintFolder<'b, C>>,
    SymbolicExt<C::F, C::EF>: p3_field::Algebra<C::EF>,
{
    let _ = (PhantomData::<()>, PairWindow::<Ext<C::F, C::EF>> { local: &[], next: &[] });
    unimplemented!(
        "eval_constraints: chip.eval bridging requires MultiTableAirBuilder \
         on BasefoldConstraintFolder + cumulative-sum field plumbing. See \
         module-level note + docs/recursion_verifier_port.md."
    )
}

/// Compute the "padded row adjustment" — the constraint-folder
/// accumulator that a chip's eval would produce if invoked on a
/// dummy all-zero row.  Used by the zerocheck verifier to subtract
/// the constraint contribution from out-of-range padded rows.
///
/// # Status
///
/// Signature complete; body deferred for the same reason as
/// [`eval_constraints`].
///
/// # Reference
///
/// Mirrors [`compute_padded_row_adjustment`](file:///tmp/sp1/crates/recursion/circuit/src/zerocheck.rs:61-85).
pub fn compute_padded_row_adjustment<C, A>(
    _builder: &mut Builder<C>,
    _chip: &MachineChip<zkm_stark::koala_bear_poseidon2::KoalaBearPoseidon2, A>,
    _alpha: Ext<C::F, C::EF>,
    _public_values: &[Felt<C::F>],
) -> Ext<C::F, C::EF>
where
    C: CircuitConfig,
    A: MachineAir<p3_koala_bear::KoalaBear>
        + for<'b> Air<BasefoldConstraintFolder<'b, C>>,
    SymbolicExt<C::F, C::EF>: p3_field::Algebra<C::EF>,
{
    unimplemented!(
        "compute_padded_row_adjustment: same chip.eval bridging \
         deferral as eval_constraints"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_field::PrimeCharacteristicRing;
    use zkm_recursion_compiler::circuit::AsmBuilder;
    use zkm_recursion_compiler::config::InnerConfig;
    use zkm_recursion_compiler::ir::Ext;
    use zkm_stark::{InnerChallenge, InnerVal};

    type C = InnerConfig;
    type F = InnerVal;
    type EF = InnerChallenge;

    /// Construction smoke test: full_geq builds a symbolic
    /// expression from two same-length point vectors without
    /// panicking.
    #[test]
    fn full_geq_constructs() {
        let mut builder = AsmBuilder::<F, EF>::default();
        let threshold: Vec<SymbolicExt<F, EF>> = (0..3)
            .map(|_| {
                let e: Ext<F, EF> = builder.constant(EF::ZERO);
                e.into()
            })
            .collect();
        let eval_point: Vec<SymbolicExt<F, EF>> = (0..3)
            .map(|_| {
                let e: Ext<F, EF> = builder.constant(EF::ONE);
                e.into()
            })
            .collect();
        let _result = full_geq::<C>(&threshold, &eval_point);
    }

    /// Construction smoke test: eq_eval builds a symbolic
    /// expression for two same-length point vectors.
    #[test]
    fn eq_eval_constructs() {
        let mut builder = AsmBuilder::<F, EF>::default();
        let a: Vec<SymbolicExt<F, EF>> = (0..4)
            .map(|_| {
                let e: Ext<F, EF> = builder.constant(EF::ZERO);
                e.into()
            })
            .collect();
        let b: Vec<SymbolicExt<F, EF>> = (0..4)
            .map(|_| {
                let e: Ext<F, EF> = builder.constant(EF::ONE);
                e.into()
            })
            .collect();
        let _result = eq_eval::<C>(&a, &b);
    }
}
