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
//! crates/recursion/circuit/src/zerocheck.rs
//! and supporting `slop_multilinear` MLE helpers (`full_geq`,
//! `Mle::full_lagrange_eval`).

use std::marker::PhantomData;

use p3_air::{Air, BaseAir};
use p3_field::{Algebra, PrimeCharacteristicRing, TwoAdicField};
use zkm_recursion_compiler::ir::{Builder, Ext, Felt, SymbolicExt};
use zkm_pcs::{
    air::MachineAir, ChipOpenedValues, MachineChip, OpeningShapeError,
};
use zkm_pcs::folder::PairWindow;
use zkm_pcs::septic_digest::SepticDigest;

use crate::basefold_chip_opened_values::BasefoldShardOpenedValuesVariable;
use crate::basefold_constraint_folder::BasefoldConstraintFolder;
use crate::challenger::FieldChallengerVariable;
use crate::logup_gkr::observe_ext_slice;
use crate::logup_proof::LogUpEvaluations;
use crate::partial_sumcheck::PartialSumcheckProof;
use crate::sumcheck::verify_sumcheck;
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
/// Mirrors `slop_multilinear::full_geq` (slop/crates/multilinear/src/mle.rs).
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
/// Mirrors `verify_opening_shape` (crates/recursion/circuit/src/zerocheck.rs).
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

/// Verify a chip's BaseFold-pipeline opening has the expected
/// per-batch widths.  Mirrors [`verify_opening_shape`] but
/// consumes the BaseFold-shape opening type.
pub fn verify_opening_shape_basefold<C, SC, A>(
    chip: &MachineChip<SC, A>,
    opening: &crate::basefold_chip_opened_values::BasefoldChipOpenedValuesVariable<C>,
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
    /// Variant of [`Self::eval_constraints`] consuming a
    /// [`BasefoldChipOpenedValuesVariable`] (with the cumulative
    /// sums and degree bundled into the opening).
    #[allow(clippy::too_many_arguments)]
    pub fn eval_constraints_basefold<'a>(
        builder: &mut Builder<C>,
        chip: &MachineChip<SC, A>,
        opening: &'a crate::basefold_chip_opened_values::BasefoldChipOpenedValuesVariable<C>,
        alpha: Ext<C::F, C::EF>,
        public_values: &'a [Felt<C::F>],
    ) -> Ext<C::F, C::EF> {
        let preprocessed = PairWindow {
            local: &opening.preprocessed.local,
            next: &opening.preprocessed.local,
        };
        let main = PairWindow {
            local: &opening.main.local,
            next: &opening.main.local,
        };
        // SP1's `VerifierConstraintFolder` (verifier/shard.rs:243) carries NO
        // cumulative sums, and the Ziren host zeroes them in the zerocheck
        // constraint eval (`eval_air_constraints_at_row`, zerocheck_poly.rs:661
        // — "lookup soundness rides on LogUp-GKR, not this zerocheck"). Feed
        // the same zeros here instead of the witnessed per-chip sums: any AIR
        // term that references the cumulative sum must contribute exactly what
        // the host reduced into `evals[i]`, else the per-chip zerocheck term
        // diverges (the all-zero-row padded-row adjustment otherwise picks up
        // `-local_cumulative_sum`, so the in-circuit `pra` came out 0 while
        // the host's was non-zero — dropping the `-pra*geq` correction).
        let (zero_lcs, zero_gcs) = Self::zero_cumulative_sums(builder);
        let mut folder = BasefoldConstraintFolder::<C> {
            preprocessed,
            main,
            alpha,
            accumulator: SymbolicExt::ZERO,
            public_values,
            local_cumulative_sum: &zero_lcs,
            global_cumulative_sum: &zero_gcs,
            _marker: PhantomData,
        };
        chip.eval(&mut folder);
        builder.eval(folder.accumulator)
    }

    /// Zero `(local_cumulative_sum, global_cumulative_sum)` for the
    /// zerocheck constraint folder, matching the host
    /// (`eval_air_constraints_at_row`) and SP1's
    /// `VerifierConstraintFolder` (which omits the sums entirely).
    fn zero_cumulative_sums(
        builder: &mut Builder<C>,
    ) -> (Ext<C::F, C::EF>, SepticDigest<Felt<C::F>>) {
        use zkm_pcs::septic_curve::SepticCurve;
        use zkm_pcs::septic_extension::SepticExtension;
        let zero_lcs: Ext<C::F, C::EF> = builder.constant(C::EF::ZERO);
        let zero_felt: Felt<C::F> = builder.constant(C::F::ZERO);
        let zero_gcs: SepticDigest<Felt<C::F>> = SepticDigest(SepticCurve {
            x: SepticExtension(core::array::from_fn(|_| zero_felt)),
            y: SepticExtension(core::array::from_fn(|_| zero_felt)),
        });
        (zero_lcs, zero_gcs)
    }

    /// Variant of [`Self::compute_padded_row_adjustment`]
    /// consuming a [`BasefoldChipOpenedValuesVariable`] (so the
    /// per-chip cumulative-sum references come from the opening
    /// rather than parallel slices).
    #[allow(clippy::too_many_arguments)]
    pub fn compute_padded_row_adjustment_basefold<'a>(
        builder: &mut Builder<C>,
        chip: &MachineChip<SC, A>,
        opening: &'a crate::basefold_chip_opened_values::BasefoldChipOpenedValuesVariable<C>,
        alpha: Ext<C::F, C::EF>,
        public_values: &'a [Felt<C::F>],
    ) -> Ext<C::F, C::EF> {
        let main_width = chip.width();
        let preproc_width = chip.preprocessed_width();
        let zero_ext: Ext<C::F, C::EF> = builder.eval(SymbolicExt::ZERO);
        let preproc_row: Vec<Ext<C::F, C::EF>> = vec![zero_ext; preproc_width];
        let main_row: Vec<Ext<C::F, C::EF>> = vec![zero_ext; main_width];
        // Zero cumulative sums — match the host pra (`compute_padded_row_
        // adjustment` → `eval_air_constraints_at_row`, zero sums) and SP1.
        let (zero_lcs, zero_gcs) = Self::zero_cumulative_sums(builder);
        let mut folder = BasefoldConstraintFolder::<C> {
            preprocessed: PairWindow { local: &preproc_row, next: &preproc_row },
            main: PairWindow { local: &main_row, next: &main_row },
            alpha,
            accumulator: SymbolicExt::ZERO,
            public_values,
            local_cumulative_sum: &zero_lcs,
            global_cumulative_sum: &zero_gcs,
            _marker: PhantomData,
        };
        chip.eval(&mut folder);
        builder.eval(folder.accumulator)
    }

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

    /// Full zerocheck-phase verifier for a single shard.
    ///
    /// Replays the BaseFold zerocheck IOP on the in-circuit
    /// transcript: samples the per-chip constraint-folding scalar,
    /// the GKR-batch-open challenge, and the chip-RLC scalar; for
    /// each chip, batches the constraint accumulator with the
    /// padded-row mask and the chip's main+preprocessed openings;
    /// asserts the cross-chip RLC matches the prover's claimed
    /// evaluation; reduces the GKR-side modifier into the zerocheck
    /// `claimed_sum`; runs [`verify_sumcheck`]; and observes the
    /// per-chip openings into the transcript so the next phase
    /// (jagged PCS opening) sees a consistent challenger state.
    ///
    /// # Arguments
    ///
    ///   * `shard_chips` — ordered slice of chips active in this
    ///     shard, parallel to `opened_values.chips`.
    ///   * `opened_values` — per-chip preprocessed/main openings
    ///     at the sumcheck-reduced point.
    ///   * `chip_degrees` — per-chip "degree point" (big-endian
    ///     boolean coordinates of the chip's height); used by
    ///     [`full_geq`] to compute the padded-row mask.  In the
    ///     SP1 reference these live on `ChipOpenedValues::degree`;
    ///     in Ziren they're passed separately until a
    ///     `BasefoldChipOpenedValues` type is introduced.
    ///   * `cumulative_sums` — per-chip local cumulative-sum value
    ///     from the LogUp-GKR sumcheck output (the BaseFold
    ///     pipeline replaced the legacy permutation-column opening
    ///     with this).
    ///   * `global_cumulative_sums` — per-chip global
    ///     cumulative-sum digest references; same source as
    ///     `cumulative_sums`.
    ///   * `gkr_evaluations` — output of [`verify_logup_gkr`]:
    ///     the GKR-emitted evaluation point + per-chip column
    ///     evaluations the zerocheck reduction targets.
    ///   * `zerocheck_proof` — the zerocheck sumcheck proof
    ///     itself.
    ///   * `pcs_max_log_row_count` — the PCS verifier's
    ///     `max_log_row_count` parameter; the zerocheck reduced
    ///     point's dimension is asserted equal to this.
    ///   * `public_values` — shard public values (passed through
    ///     to per-chip constraint folders).
    ///   * `challenger` — in-circuit transcript.
    ///
    /// # Reference
    ///
    /// Mirrors `StarkVerifier::verify_zerocheck`
    /// (crates/recursion/circuit/src/zerocheck.rs).
    /// Substitutions:
    ///   - `BTreeSet<Chip>` → ordered `&[&MachineChip<SC, A>]`.
    ///   - `openings.degree` (SP1's per-opening field) →
    ///     separate `chip_degrees` parameter (Ziren's
    ///     `ChipOpenedValues` doesn't yet carry this BaseFold-
    ///     pipeline field; introduce
    ///     `BasefoldChipOpenedValues` in a follow-up step).
    ///   - `Mle::full_lagrange_eval` → [`eq_eval`].
    ///   - `Point::add_dimension` → `Vec::push`.
    ///   - `observe_variable_length_extension_slice` →
    ///     [`observe_ext_slice`] (Ziren's variable-length
    ///     observation helper).
    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::type_complexity)]
    pub fn verify_zerocheck<'a, FC>(
        builder: &mut Builder<C>,
        shard_chips: &[&MachineChip<SC, A>],
        opened_values: &'a BasefoldShardOpenedValuesVariable<C>,
        gkr_evaluations: &LogUpEvaluations<Ext<C::F, C::EF>>,
        zerocheck_proof: &PartialSumcheckProof<Ext<C::F, C::EF>>,
        pcs_max_log_row_count: usize,
        public_values: &'a [Felt<C::F>],
        challenger: &mut FC,
    ) where
        FC: FieldChallengerVariable<C, C::Bit>,
    {
        assert_eq!(
            shard_chips.len(),
            opened_values.chips.len(),
            "verify_zerocheck: chip count mismatch (chips={}, openings={})",
            shard_chips.len(),
            opened_values.chips.len(),
        );

        let zero_ext: Ext<C::F, C::EF> = builder.eval(SymbolicExt::ZERO);
        let one_ext: Ext<C::F, C::EF> = builder.eval(SymbolicExt::ONE);

        // (1) Sample per-phase challenges from the transcript.
        let alpha = challenger.sample_ext(builder);
        let gkr_batch_open_ext = challenger.sample_ext(builder);
        let gkr_batch_open_challenge: SymbolicExt<C::F, C::EF> = gkr_batch_open_ext.into();
        let lambda = challenger.sample_ext(builder);

        // (2) eq(zerocheck reduced point, GKR-emitted point).
        let point_symbolic: Vec<SymbolicExt<C::F, C::EF>> = zerocheck_proof
            .point_and_eval
            .0
            .iter()
            .map(|x| (*x).into())
            .collect();
        let gkr_point_symbolic: Vec<SymbolicExt<C::F, C::EF>> =
            gkr_evaluations.point.iter().map(|x| (*x).into()).collect();
        let zerocheck_eq_val = eq_eval::<C>(&gkr_point_symbolic, &point_symbolic);

        // (3) Pre-compute the GKR-batch-open challenge powers,
        // sized for the widest chip's combined preprocessed+main
        // width — those powers index across both opening vectors.
        let max_elements = shard_chips
            .iter()
            .map(|chip| chip.width() + chip.preprocessed_width())
            .max()
            .unwrap_or(0);
        let gkr_batch_open_challenge_powers: Vec<SymbolicExt<C::F, C::EF>> =
            std::iter::successors(Some(SymbolicExt::ONE), |prev| {
                Some(*prev * gkr_batch_open_challenge)
            })
            .skip(1)
            .take(max_elements)
            .collect();

        // (4) Per-chip RLC accumulator.  After the loop this
        // equals zerocheck_proof.point_and_eval.1 (the prover's
        // claimed evaluation at the sumcheck-reduced point).
        let mut rlc_eval: Ext<C::F, C::EF> = zero_ext;

        for (idx, (chip, opening)) in
            shard_chips.iter().zip(opened_values.chips.iter()).enumerate()
        {
            let degree = &opening.degree;

            // (4a) Shape sanity check on the chip's openings.
            verify_opening_shape_basefold::<C, SC, A>(chip, opening)
                .expect("verify_zerocheck: chip opening shape mismatch");

            // (4b) Sumcheck point dimension == PCS max_log_row_count.
            let dimension = zerocheck_proof.point_and_eval.0.len();
            assert_eq!(
                dimension, pcs_max_log_row_count,
                "verify_zerocheck: zerocheck point dimension {} != pcs max_log_row_count {}",
                dimension, pcs_max_log_row_count,
            );

            // (4c) Build the extended sumcheck point (one extra
            // zero coordinate) for the geq comparison.  FRONT-insert
            // (SP1 `Point::add_dimension` = `values.insert(0, ..)`),
            // NOT back-append: `full_geq` iterates MSB-first and
            // `degree` is big-endian (MSB at index 0), so the extra
            // high coordinate must pair with `degree`'s extra high bit.
            // A back-append shifted every degree bit one slot vs `z`,
            // giving the wrong padded-row mask on every padded chip.
            let mut proof_point_extended = point_symbolic.clone();
            proof_point_extended.insert(0, SymbolicExt::ZERO);

            // (4d) Assert each degree coordinate is boolean and
            // that all-but-the-first coordinates are zero unless
            // the first is also zero (the BaseFold-pipeline
            // big-endian-degree convention).
            let degree_symbolic: Vec<SymbolicExt<C::F, C::EF>> =
                degree.iter().map(|x| (*x).into()).collect();
            for (i, x) in degree_symbolic.iter().enumerate() {
                builder.assert_ext_eq(*x * (*x - SymbolicExt::ONE), SymbolicExt::ZERO);
                if i >= 1 {
                    builder.assert_ext_eq(
                        *x * *degree_symbolic.first().unwrap(),
                        SymbolicExt::ZERO,
                    );
                }
            }

            // (4e) Padded-row mask + adjustment.
            let geq_val = full_geq::<C>(&degree_symbolic, &proof_point_extended);
            let padded_row_adjustment = Self::compute_padded_row_adjustment_basefold(
                builder,
                chip,
                opening,
                alpha,
                public_values,
            );

            // (4f) Constraint accumulator at the sumcheck point
            // minus the padded-row contribution.
            let constraint_eval_ext = Self::eval_constraints_basefold(
                builder,
                chip,
                opening,
                alpha,
                public_values,
            );
            let pra_sym: SymbolicExt<C::F, C::EF> = padded_row_adjustment.into();
            let ce_sym: SymbolicExt<C::F, C::EF> = constraint_eval_ext.into();
            let constraint_eval: SymbolicExt<C::F, C::EF> = ce_sym - pra_sym * geq_val.clone();

            // (4g) Batch the chip's openings (main first, then
            // preprocessed) by the pre-computed challenge powers.
            let openings_batch: SymbolicExt<C::F, C::EF> = opening
                .main
                .local
                .iter()
                .chain(opening.preprocessed.local.iter())
                .copied()
                .zip(
                    gkr_batch_open_challenge_powers
                        .iter()
                        .take(
                            opening.main.local.len()
                                + opening.preprocessed.local.len(),
                        )
                        .copied(),
                )
                .map(|(opening, power)| {
                    let o_sym: SymbolicExt<C::F, C::EF> = opening.into();
                    o_sym * power
                })
                .sum();

            // (4h) Fold this chip's contribution into the cross-
            // chip RLC.
            let rlc_sym: SymbolicExt<C::F, C::EF> = rlc_eval.into();
            let lambda_sym: SymbolicExt<C::F, C::EF> = lambda.into();
            let new_rlc: SymbolicExt<C::F, C::EF> = rlc_sym * lambda_sym
                + zerocheck_eq_val * (constraint_eval + openings_batch);
            rlc_eval = builder.eval(new_rlc);
        }

        // (5) Assert the cross-chip RLC matches the prover's
        // claimed evaluation at the sumcheck-reduced point.
        builder.assert_ext_eq(rlc_eval, zerocheck_proof.point_and_eval.1);

        // (6) Reduce the GKR-side openings into the zerocheck
        // claimed_sum modifier (lambda-RLC across chips).  Each chip's
        // batch is scaled by the MIXED-HEIGHT EMBEDDING FACTOR
        // Π_high(1 − zeta[k]) over the zeta coords ABOVE the chip's own
        // height — the prover's claim carries it (zerocheck_prover.rs) but
        // the trailing-log_h GKR opening does not.  zeta = gkr_evaluations
        // .point; the "high" coords are those before the chip's degree
        // one-hot, selected via the running prefix of `opening.degree`
        // (big-endian one-hot at index `dim − log_h`): is_high[k] =
        // 1 − Σ_{j≤k} degree[j], so factor = Π_k (1 − is_high[k]·zeta[k]).
        // (Mirrors the host verifier verifier.rs step (G2-b).)
        let zerocheck_sum_modifications_from_gkr: Vec<SymbolicExt<C::F, C::EF>> = gkr_evaluations
            .chip_openings
            .values()
            .zip(opened_values.chips.iter())
            .map(|(chip_evaluation, opening)| {
                let raw: SymbolicExt<C::F, C::EF> = chip_evaluation
                    .main_trace_evaluations
                    .iter()
                    .copied()
                    .chain(
                        chip_evaluation
                            .preprocessed_trace_evaluations
                            .as_ref()
                            .map(|v| v.as_slice())
                            .unwrap_or(&[])
                            .iter()
                            .copied(),
                    )
                    .zip(gkr_batch_open_challenge_powers.iter().copied())
                    .map(|(opening, power)| {
                        let o_sym: SymbolicExt<C::F, C::EF> = opening.into();
                        o_sym * power
                    })
                    .sum::<SymbolicExt<C::F, C::EF>>();

                // Embedding factor from the degree one-hot prefix.
                // SP1-faithful deferred materialization: keep the
                // per-coordinate prefix/factor accumulation in
                // SymbolicExt (NO builder.eval inside the k-loop) and
                // let the DSL CSE the products. The degree one-hot
                // (degree[k] ∈ {0,1}, Σ ≤ 1, asserted in section (4d))
                // keeps `prefix` a 0/1 step function so each factor
                // term `(1 − is_high·zeta)` stays effectively linear.
                // is_high[k] = 1 − Σ_{j≤k} degree[k]; factor = Π_k (1 −
                // is_high[k]·zeta[k]). Value-identical to the prior
                // per-coordinate builder.eval form (host verifier.rs
                // step (G2-b)), just one materialization per chip.
                let mut prefix: SymbolicExt<C::F, C::EF> = SymbolicExt::ZERO;
                let mut factor: SymbolicExt<C::F, C::EF> = SymbolicExt::ONE;
                for (k, zk) in gkr_evaluations.point.iter().enumerate() {
                    let dk: SymbolicExt<C::F, C::EF> = opening.degree[k].into();
                    prefix = prefix + dk;
                    let is_high: SymbolicExt<C::F, C::EF> = SymbolicExt::ONE - prefix.clone();
                    let zk_sym: SymbolicExt<C::F, C::EF> = (*zk).into();
                    factor = factor * (SymbolicExt::ONE - is_high * zk_sym);
                }
                raw * factor
            })
            .collect();

        let zero_sym: SymbolicExt<C::F, C::EF> = zero_ext.into();
        let lambda_sym: SymbolicExt<C::F, C::EF> = lambda.into();
        let zerocheck_sum_modification: SymbolicExt<C::F, C::EF> =
            zerocheck_sum_modifications_from_gkr
                .iter()
                .fold(zero_sym, |acc, modification| lambda_sym * acc + *modification);

        // (7) Assert the prover's zerocheck claimed_sum equals
        // the GKR-derived modification.
        builder.assert_ext_eq(zerocheck_proof.claimed_sum, zerocheck_sum_modification);

        // Silence the `one_ext` unused-binding lint (kept for
        // parity with the SP1 reference, which threads it
        // through future intermediate values).
        let _ = one_ext;

        // (8) Verify the zerocheck sumcheck proof itself.
        verify_sumcheck::<C, FC>(builder, challenger, zerocheck_proof);

        // (9) Observe the per-chip openings into the transcript
        // so subsequent phases (jagged PCS opening) replay a
        // consistent challenger state.
        let len_felt: Felt<C::F> =
            builder.constant(C::F::from_canonical_usize(shard_chips.len()));
        challenger.observe(builder, len_felt);
        // Observe the GKR CHIP-OPENINGS (NOT opened_values) — the host
        // verify_zerocheck_host (verifier.rs:862-885) iterates
        // `gkr_evaluations.chip_openings` (BTreeMap name order) and observes,
        // per chip, preprocessed_trace_evaluations (if present) THEN
        // main_trace_evaluations. The previous body observed
        // `opened_values.chips[].{preprocessed,main}.local` (the trace@z
        // openings), but the GKR openings are evaluated @z_gkr (≠ z*), so the
        // VALUES differ and the in-circuit challenger desynced from the prover
        // — invisible to the zerocheck's own asserts, surfacing only as the
        // jagged-PCS z_col mismatch (gnark wrap step4 = round-0 identity
        // failure). The host comment at verifier.rs:866-871 documents exactly
        // this failure mode. Mirror the host source + order to stay in lockstep.
        for chip_evaluation in gkr_evaluations.chip_openings.values() {
            if let Some(prep) =
                chip_evaluation.preprocessed_trace_evaluations.as_ref()
            {
                observe_ext_slice::<C, FC>(builder, challenger, prep);
            }
            observe_ext_slice::<C, FC>(
                builder,
                challenger,
                &chip_evaluation.main_trace_evaluations,
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_field::PrimeCharacteristicRing;
    use zkm_recursion_compiler::circuit::AsmBuilder;
    use zkm_recursion_compiler::config::InnerConfig;
    use zkm_recursion_compiler::ir::Ext;
    use zkm_pcs::{InnerChallenge, InnerVal};

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
