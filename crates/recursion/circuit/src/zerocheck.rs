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
use p3_field::{Algebra, PrimeCharacteristicRing, TwoAdicField};
use zkm_recursion_compiler::ir::{Builder, Ext, Felt, SymbolicExt};
use zkm_stark::{air::MachineAir, ChipOpenedValues, MachineChip, OpeningShapeError};
use zkm_stark::folder::PairWindow;
use zkm_stark::septic_digest::SepticDigest;

use crate::basefold_constraint_folder::BasefoldConstraintFolder;
use crate::{CircuitConfig, KoalaBearFriParametersVariable};

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
pub fn verify_opening_shape<C, SC, A>(
    chip: &MachineChip<SC, A>,
    opening: &ChipOpenedValues<Felt<C::F>, Ext<C::F, C::EF>>,
) -> Result<(), OpeningShapeError>
where
    C: CircuitConfig<F = SC::Val>,
    SC: KoalaBearFriParametersVariable<C>,
    A: MachineAir<C::F>,
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

/// Zerocheck verifier wrapper that threads the trait bounds needed
/// for [`MachineChip::eval`] dispatch through a [`BasefoldConstraintFolder`].
///
/// Methods are gathered on this zero-sized struct so the
/// `where SymbolicExt: Algebra<EF>` + `for<'a> Air<...>` bounds
/// can be declared once at impl level rather than repeated at every
/// function signature — the same pattern Ziren's existing
/// [`crate::stark::StarkVerifier`] uses for the legacy verifier.
///
/// `SC` is generic for the same reason the legacy verifier is:
/// keeping `MachineChip<SC, A>` opaque lets the compiler elaborate
/// `MachineChip<SC, A>::F = SC::Val = C::F` (via the
/// `C: CircuitConfig<F = SC::Val>` bound) so the `Chip::eval` impl's
/// `ZKMAirBuilder<F = chip.F>` requirement unifies with the folder's
/// `AirBuilder::F = C::F`.  Pinning `SC` to `KoalaBearPoseidon2`
/// up front sounds cleaner but trips a normalisation gap where the
/// compiler doesn't see `Chip<KoalaBear, A>::F` and `C::F` as the
/// same type even with `C::F = KoalaBear` declared.
pub struct BasefoldZerocheckVerifier<C, SC, A>(PhantomData<(C, SC, A)>);

impl<C, SC, A> BasefoldZerocheckVerifier<C, SC, A>
where
    C::F: TwoAdicField,
    SC: KoalaBearFriParametersVariable<C>,
    C: CircuitConfig<F = SC::Val>,
    A: MachineAir<C::F> + for<'b> Air<BasefoldConstraintFolder<'b, C>>,
    SymbolicExt<C::F, C::EF>: Algebra<C::EF>,
{
    /// Evaluate a chip's constraint polynomial at the sumcheck point
    /// implied by `opening` (the chip's preprocessed and main local
    /// values), returning the constraint accumulator as a single Ext
    /// value.
    ///
    /// `local_cumulative_sum` and `global_cumulative_sum` thread
    /// through to the `MultiTableAirBuilder` impl on the folder so
    /// chips that read them via that trait see consistent values
    /// (in the BaseFold pipeline these come from the LogUp-GKR
    /// sumcheck output, not a per-chip permutation column).
    #[allow(clippy::too_many_arguments)]
    pub fn eval_constraints<'a>(
        builder: &mut Builder<C>,
        chip: &MachineChip<SC, A>,
        opening: &'a ChipOpenedValues<Felt<C::F>, Ext<C::F, C::EF>>,
        alpha: Ext<C::F, C::EF>,
        public_values: &'a [Felt<C::F>],
        local_cumulative_sum: &'a Ext<C::F, C::EF>,
        global_cumulative_sum: &'a SepticDigest<Felt<C::F>>,
    ) -> Ext<C::F, C::EF> {
        let preprocessed = PairWindow {
            local: &opening.preprocessed.local,
            next: &opening.preprocessed.local,
        };
        let main = PairWindow {
            local: &opening.main.local,
            next: &opening.main.local,
        };
        let mut folder = BasefoldConstraintFolder::<C> {
            preprocessed,
            main,
            alpha,
            accumulator: SymbolicExt::ZERO,
            public_values,
            local_cumulative_sum,
            global_cumulative_sum,
            _marker: PhantomData,
        };
        chip.eval(&mut folder);
        builder.eval(folder.accumulator)
    }

    /// Compute the "padded row adjustment" — the constraint-folder
    /// accumulator that a chip's eval would produce if invoked on a
    /// dummy all-zero row.  Used by the zerocheck verifier to subtract
    /// the constraint contribution from out-of-range padded rows.
    ///
    /// The padded-row mask returned by [`full_geq`] gates this value
    /// to fire only outside the chip's real-data window; inside the
    /// real window the mask is zero and this adjustment cancels.
    #[allow(clippy::too_many_arguments)]
    pub fn compute_padded_row_adjustment<'a>(
        builder: &mut Builder<C>,
        chip: &MachineChip<SC, A>,
        alpha: Ext<C::F, C::EF>,
        public_values: &'a [Felt<C::F>],
        local_cumulative_sum: &'a Ext<C::F, C::EF>,
        global_cumulative_sum: &'a SepticDigest<Felt<C::F>>,
    ) -> Ext<C::F, C::EF> {
        let main_width = chip.width();
        let preproc_width = chip.preprocessed_width();
        let zero_ext: Ext<C::F, C::EF> = builder.eval(SymbolicExt::ZERO);
        let preproc_row: Vec<Ext<C::F, C::EF>> = vec![zero_ext; preproc_width];
        let main_row: Vec<Ext<C::F, C::EF>> = vec![zero_ext; main_width];
        let mut folder = BasefoldConstraintFolder::<C> {
            preprocessed: PairWindow { local: &preproc_row, next: &preproc_row },
            main: PairWindow { local: &main_row, next: &main_row },
            alpha,
            accumulator: SymbolicExt::ZERO,
            public_values,
            local_cumulative_sum,
            global_cumulative_sum,
            _marker: PhantomData,
        };
        chip.eval(&mut folder);
        builder.eval(folder.accumulator)
    }
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
