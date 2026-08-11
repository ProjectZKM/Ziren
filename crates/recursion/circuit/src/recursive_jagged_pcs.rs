//! In-circuit jagged-PCS verifier orchestrator.
//!
//! The jagged PCS layers a per-chip-evaluation reduction on top of
//! the stacked-BaseFold PCS.  This module hosts the top-level
//! orchestrator that composes the four subroutines of the jagged
//! verifier:
//!
//!   1. **Sample `z_col`** — the challenges the jagged sumcheck
//!      reduces over (one per log-column-count bit).
//!   2. **Reduce per-chip claims** — flatten the per-chip
//!      evaluation-claim matrix into a single 1D Mle, assert its
//!      evaluation at `z_col` equals the sumcheck proof's claimed
//!      sum.
//!   3. **Verify sumcheck** — call
//!      [`crate::sumcheck::verify_sumcheck`] on the jagged sumcheck
//!      proof.
//!   4. **Jagged-eval sub-protocol** — the caller-supplied
//!      `jagged_evaluator_fn` closure runs the jagged-poly evaluation
//!      sub-protocol (isolated here so this module doesn't depend
//!      on the ~200 LOC jagged-eval machinery).
//!   5. **Check prefix-sum consistency** — accumulate the per-chip
//!      row counts and assert each prefix matches the jagged-eval
//!      output's `prefix_sum_felts`.
//!   6. **Verify the dense-trace opening** — the final identity
//!      `jagged_eval * expected_eval == sumcheck.eval` ties the
//!      jagged-poly evaluation back to the committed trace.
//!   7. **Forward to stacked PCS** — call
//!      [`crate::recursive_stacked_pcs::RecursiveStackedPcsVerifier::verify_untrusted_evaluation`]
//!      to close the soundness chain.
//!
//! # Reference
//!
//! Mirrors `RecursiveJaggedPcsVerifier::verify_trusted_evaluations` (crates/recursion/circuit/src/jagged/verifier.rs)
//! from the upstream BaseFold verifier reference.
//! Substitutions:
//!   - `Point<Ext>` → `&[Ext<C::F, C::EF>]`.
//!   - `MleEval<Ext>` → `Vec<Ext<C::F, C::EF>>` (flat).
//!   - `Mle::from(col_claims)` → flat Vec passed to
//!     [`crate::logup_gkr::evaluate_mle_ext`].
//!   - `self.jagged_evaluator.jagged_evaluation(...)` → closure
//!     parameter `jagged_evaluator_fn` (decouples from the
//!     `RecursiveJaggedEvalSumcheckConfig`).
//!   - SP1's `SC::hash` / `SC::compress` chip-info mix-in is not
//!     recomputed here; the main commitment is bound in the shard-level
//!     prologue, and `commitments` / `original_commitments` carry the
//!     digest only for the per-round Merkle-binding checks.
//!
//! The jagged-eval sub-protocol is abstracted behind the
//! `jagged_evaluator_fn` closure parameter, decoupling the
//! orchestrator from the full `RecursiveJaggedEvalSumcheckConfig`.
//! Construction smoke tests cover the type composition.

use p3_field::PrimeCharacteristicRing;
use zkm_recursion_compiler::ir::{Builder, Ext, Felt, SymbolicExt};

use crate::challenger::FieldChallengerVariable;
use crate::jagged_circuit::{JaggedPcsProofVariable, JaggedSumcheckEvalProof};
use crate::logup_gkr::evaluate_mle_ext;
use crate::recursive_stacked_pcs::{
    RecursiveMultilinearPcsVerifier, RecursiveStackedPcsVerifier,
};
use crate::sumcheck::verify_sumcheck;
use crate::CircuitConfig;

/// In-circuit jagged-PCS verifier.
///
/// Generic over the underlying multilinear PCS verifier `P` — in
/// production, [`crate::basefold_verifier::RecursiveBasefoldVerifier`].
/// Holds the stacked-PCS wrapper + `max_log_row_count` bound used
/// to size per-chip height-bit representations.
#[derive(Clone)]
pub struct RecursiveJaggedPcsVerifier<P> {
    /// Stacked-PCS verifier wrapping the underlying multilinear
    /// PCS.  Drives the inner BaseFold opening once the jagged
    /// reduction finishes.
    pub stacked_pcs_verifier: RecursiveStackedPcsVerifier<P>,
    /// Maximum log row count across shards verified by this
    /// verifier — bounds the per-chip row-count bit-decomposition
    /// length.
    pub max_log_row_count: usize,
}

impl<P> RecursiveJaggedPcsVerifier<P> {
    pub const fn new(
        stacked_pcs_verifier: RecursiveStackedPcsVerifier<P>,
        max_log_row_count: usize,
    ) -> Self {
        Self { stacked_pcs_verifier, max_log_row_count }
    }
}

impl<P> RecursiveJaggedPcsVerifier<P> {
    /// Verify trusted jagged-PCS evaluations.
    ///
    /// "Trusted" here means `evaluation_claims` were observed into
    /// the transcript by the caller before invoking this method —
    /// the shard verifier's phase 3 (zerocheck) does that as part
    /// of closing the per-chip RLC assertion, so the phase-4 call
    /// site satisfies the contract.
    ///
    /// # Arguments
    ///
    ///   * `commitments` — per-round modified commitment digests
    ///     (the chip-info-hash-mixed variants; the raw commits live
    ///     on `proof.original_commitments`).
    ///   * `point` — the evaluation point from the zerocheck
    ///     reduction (`zerocheck_proof.point_and_eval.0`).
    ///   * `evaluation_claims` — per-round per-chip evaluation
    ///     claims; flattened to column-claims inside this method.
    ///   * `proof` — the jagged-PCS opening proof (sumcheck +
    ///     jagged-eval + stacked-PCS).
    ///   * `insertion_points` — column-index insertion positions
    ///     for the artificial zero-column padding the prover adds
    ///     to hit the stacked-PCS stripe-size alignment.  Computed
    ///     by [`RecursiveMachineJaggedPcsVerifier`] from its
    ///     per-round column-count table.
    ///   * `challenger` — the in-circuit transcript.
    ///   * `jagged_evaluator_fn` — closure that runs the jagged-
    ///     eval sub-protocol.  Returns `(jagged_eval, prefix_sum_felts)`
    ///     where `jagged_eval` is the extension-field evaluation of
    ///     the jagged polynomial at the sumcheck point and
    ///     `prefix_sum_felts` is the per-column prefix-sum witness
    ///     the verifier checks against the proof's `row_counts`.
    ///
    /// Returns the `prefix_sum_felts` so the caller can observe
    /// them into the transcript if the next phase depends on
    /// prefix-sum consistency.
    ///
    /// # Reference
    ///
    /// Mirrors `RecursiveJaggedPcsVerifier::verify_trusted_evaluations` (crates/recursion/circuit/src/jagged/verifier.rs).
    #[allow(clippy::too_many_arguments)]
    pub fn verify_trusted_evaluations<C, FC, JE>(
        &self,
        builder: &mut Builder<C>,
        commitments: &[P::Commitment],
        point: &[Ext<C::F, C::EF>],
        evaluation_claims: &[Vec<Ext<C::F, C::EF>>],
        proof: &JaggedPcsProofVariable<P::Proof, P::Commitment, C::F, C::EF>,
        insertion_points: &[usize],
        challenger: &mut FC,
        jagged_evaluator_fn: JE,
    ) -> Vec<Felt<C::F>>
    where
        C: CircuitConfig,
        FC: FieldChallengerVariable<C, C::Bit>,
        P: RecursiveMultilinearPcsVerifier<C, FC>,
        P::Commitment: Copy,
        JE: FnOnce(
            &mut Builder<C>,
            &crate::jagged_circuit::JaggedDimensionMetadata<Felt<C::F>>,
            &[Ext<C::F, C::EF>], // z_row
            &[Ext<C::F, C::EF>], // z_col
            &[Ext<C::F, C::EF>], // sumcheck reduced point
            &JaggedSumcheckEvalProof<Ext<C::F, C::EF>>,
            &mut FC,
        ) -> (Ext<C::F, C::EF>, Vec<Felt<C::F>>),
    {
        // The main jagged-PCS
        // commitment is bound in the SHARD-LEVEL Phase-1 prologue
        // (shard_basefold.rs observes the 8-felt main_commitment digest),
        // matching the host shard verifier (shard_level/verifier.rs:168).
        // The host therefore drives the jagged BaseFold open with
        // skip_commit_observe=true (outer_verify, recursion-core
        // config.rs:619), i.e. it does NOT re-observe the commitment
        // here.  So neither does the circuit — `commitments` /
        // `original_commitments` carry the digest only for the per-round
        // Merkle-binding checks inside the basefold open, not the FS
        // transcript.
        let _ = commitments;
        let JaggedPcsProofVariable {
            pcs_proof,
            sumcheck_proof,
            jagged_eval_proof,
            params,
            column_counts,
            row_counts,
            padding_row_heights,
            original_commitments,
            expected_eval,
            // `JaggedPcsProofVariable` carries no baked numeric
            // `row_counts_usize` / `padding_column_counts` height fields
            // (which would bake per-chip HEIGHT VALUES into the recursion
            // program bytes and make the VK program-length-dependent).  The
            // per-chip height soundness is carried entirely by WITNESSED binds:
            //   * each per-chip `row_count` (reconstructed from the opened
            //     `degree`, which zerocheck/GKR consume) is bounded
            //     `<= 2^cube_log` by `assert_row_count_le_cube` (step 6.5);
            //   * the step-(7) prefix-sum / final-area chain ties the witnessed
            //     `row_counts` to the in-circuit-reconstructed
            //     `col_prefix_sums` (so heights cannot be picked freely); and
            //   * the SP1 main-padding-column bit-bound below
            //     (step 6.6) rejects an area-preserving over-claim that inflates
            //     one chip's height past the cube while shrinking another.
            // `..` swallows the remaining `params`/digest bookkeeping fields.
            ..
        } = proof;

        // (1) Sample column-index challenges `z_col` of dimension
        // `log2_ceil(num_columns)`.  `col_prefix_sums.len() - 1`
        // is the number of columns; take the next-power-of-two log.
        let num_cols = params.col_prefix_sums.len() - 1;
        let num_col_variables = num_cols.next_power_of_two().trailing_zeros() as usize;
        let z_col: Vec<Ext<C::F, C::EF>> = (0..num_col_variables)
            .map(|_| challenger.sample_ext(builder))
            .collect();

        let z_row: &[Ext<C::F, C::EF>] = point;

        // (2) Flatten per-round evaluation claims into a single
        // column-claim vector.
        let mut column_claims: Vec<Ext<C::F, C::EF>> = evaluation_claims
            .iter()
            .flat_map(|round| round.iter().copied())
            .collect();

        // Each opening round is padded out to its committed area by ONE
        // stacking-padding column of zeros (`<stacking-pad:*>` in
        // `crates/pcs/src/jagged_pcs.rs`), which the host weighs into the
        // column claim with `y = 0`.  Those columns carry no chip, so they are
        // absent from `evaluation_claims` and have to be spliced back in at the
        // round boundaries — exactly SP1's `column_claims.insert` loop
        // (sp1 crates/recursion/circuit/src/jagged/verifier.rs:88).
        //
        // With a single round the pad lands past the last real claim, where the
        // power-of-two `resize` below already supplied a zero, so this is a
        // no-op; with the preprocessed round in front, round 0's pad sits
        // BETWEEN the rounds and shifts every later column by one, which is what
        // `insertion_points` is for.  Splicing also makes `column_claims.len()`
        // equal the packing's real column count, so the `next_power_of_two`
        // below agrees with the `num_col_variables` drawn from
        // `col_prefix_sums` — otherwise a round total that lands exactly on a
        // power of two samples one challenge too few.
        //
        // The host's pad loop is bounded by the row cube (`2^z_row.len()`), but
        // an area is a whole number of stacking stripes, so the gap is always
        // below one stripe (`2^log_stacking_height` < the cube) and the loop
        // emits exactly one column per round — the same one the lift lays out in
        // `col_prefix_sums`.
        let zero_ext: Ext<C::F, C::EF> = builder.eval(SymbolicExt::ZERO);
        for (round_idx, insertion_point) in insertion_points.iter().enumerate().rev() {
            let pad_cols =
                padding_row_heights.get(round_idx).map(|p| p.len()).unwrap_or(0);
            for _ in 0..pad_cols {
                column_claims.insert(*insertion_point, zero_ext);
            }
        }

        // (3) Pad the column claims to the next power of two so
        // the MLE evaluation is well-defined.
        let padded_len = column_claims.len().next_power_of_two();
        column_claims.resize(padded_len, zero_ext);

        // (4) The jagged sumcheck's claimed sum equals the column
        // MLE evaluated at `z_col`.
        let sumcheck_claim = evaluate_mle_ext::<C>(builder, &column_claims, &z_col);
        builder.assert_ext_eq(sumcheck_claim, sumcheck_proof.claimed_sum);


        // (5) Verify the jagged sumcheck.
        // The jagged REDUCTION binds the stride-1 (LSB) variable, as SP1 does, so
        // its point is recorded in SAMPLE order.  LogUp-GKR and jagged-eval still
        // bind the MSB and keep `PointOrder::Reversed`.
        crate::sumcheck::verify_sumcheck_with_order::<C, FC>(
            builder,
            challenger,
            sumcheck_proof,
            crate::sumcheck::PointOrder::Sample,
        );

        // (6) Run the caller-supplied jagged-eval sub-protocol.
        let sumcheck_point = &sumcheck_proof.point_and_eval.0;
        let (jagged_eval, prefix_sum_felts) = jagged_evaluator_fn(
            builder,
            params,
            z_row,
            &z_col,
            sumcheck_point.as_slice(),
            jagged_eval_proof,
            challenger,
        );

        // (6.5) HEIGHT-BINDING SOUNDNESS GUARD (in-circuit analog of the
        // host `evaluate_trace_columns_at_point` `assert!(height <= domain)`,
        // logup_gkr_prover.rs).
        //
        // Once the recursion is height-agnostic (heights witnessed via
        // `row_counts` / `col_prefix_sums` rather than pinned by `fix_shape`),
        // a malicious prover could WITNESS A PER-CHIP ROW COUNT LARGER THAN THE
        // OPENED CUBE DOMAIN (`2^point.len()`, where `point` = z_row is the
        // shared zerocheck-reduced point the dense trace is opened over).  The
        // step-(7) prefix-sum check below only ties the row counts to
        // `col_prefix_sums` (an INTERNAL consistency check); it does NOT bound
        // any individual row count against the cube, so an over-claimed height
        // (compensated by a smaller height elsewhere to keep the total area
        // consistent) would pass step (7) while making the per-chip trace MLE
        // evaluate over a cube SMALLER than the claimed height — silently
        // dropping real rows ⇒ soundness break.
        //
        // Bind each DISTINCT witnessed `row_count` to `row_count <= 2^L`,
        // L = point.len(), via a sound in-circuit bit-decomposition:
        //   * `num2bits(row_count, L+1)` sound-binds row_count = Σ b_i 2^i with
        //     each b_i boolean ⇒ row_count < 2^{L+1};
        //   * `low = bits2num(low L bits) = row_count - b_L·2^L`;
        //   * assert `(row_count - low) · low == 0`  ( = b_L·2^L·low ), which
        //     forces `b_L = 1 ⇒ low = 0`, i.e. row_count ∈ {0,…,2^L}.
        // The tallest honest chip fills the cube exactly (row_count == 2^L), so
        // the bound is INCLUSIVE; honest power-of-two heights ≤ 2^L are a
        // no-op.  Any over-claim 2^L < row_count < 2^{L+1} trips the product
        // assert; row_count ≥ 2^{L+1} fails `num2bits`.
        let cube_log = z_row.len();
        for round in row_counts.iter() {
            for &row_count in round.iter() {
                Self::assert_row_count_le_cube::<C>(builder, row_count, cube_log);
            }
        }

        // (6.6) MAIN-PADDING-COLUMN HEIGHT BIT-BOUND.
        //
        // Ported from SP1's jagged shard verifier
        // (crates/recursion/circuit/src/shard.rs:363-378):
        // the "main padding column" is the final jagged column whose height fills
        // the last real prefix sum up to the committed total area.  Its height
        // equals the gap between the last two `col_prefix_sums` entries
        // (= `total_values − offset(last real column)`), which is exactly the
        // tallest real per-chip height when there is one round.  Bounding it to
        // `[0, 2^max_log_row_count]` rejects an AREA-PRESERVING height forgery
        // (inflate one chip past the cube, shrink another to keep total_values
        // fixed) that would otherwise slip past the step-(7) prefix-sum / area
        // consistency check — that check only ties the witnessed `row_counts` to
        // the (self-derived) `col_prefix_sums`, it does NOT bound the per-chip
        // height against the opened cube the trace MLE is evaluated over.
        //
        // SP1 idiom: `num2bits(height, L+1)` proves `height < 2^{L+1}`; then if
        // the top bit is 1 every lower bit must be 0, excluding the open
        // interval `(2^L, 2^{L+1})` ⇒ height ∈ `[0, 2^L]`.  Config-generic (Felt
        // arithmetic works for both the inner KoalaBear and outer BN254 rings);
        // value-independent (it reads only the WITNESSED `col_prefix_sums`, no
        // baked height), so it is identical between dummy and real for a given
        // chip-set.
        //
        // `L = cube_log = z_row.len()` — the SAME bound the step-(6.5)
        // `assert_row_count_le_cube` uses for every per-chip height (SP1 uses
        // its `max_log_row_count`, which IS its opened cube).  Using the opened
        // cube here (not the verifier's nominal `max_log_row_count`) keeps the
        // padding bound provably consistent with the per-chip bound that already
        // verifies honest proofs, so this is redundant-on-honest, additive only
        // as a forgery catch.
        {
            use p3_field::PrimeCharacteristicRing;
            let cps = &params.col_prefix_sums;
            // The main padding column height = recompose(last) − recompose(prev).
            // Need at least the [.., prev, last] pair; a degenerate bundle with
            // <2 entries carries no padding column → skip (no-op, dummy mirrors).
            if cps.len() >= 2 {
                let two_felt: Felt<C::F> = builder.constant(C::F::ONE + C::F::ONE);
                // Forward big-endian Horner recompose (same convention as
                // step-(7)'s final-area decode below and the jagged evaluator's
                // `prefix_sum_felts`).
                let recompose = |b: &mut Builder<C>, bits: &[Felt<C::F>]| -> Felt<C::F> {
                    let mut acc: Felt<C::F> = b.constant(C::F::ZERO);
                    for bit in bits.iter() {
                        acc = b.eval(*bit + two_felt * acc);
                    }
                    acc
                };
                let last_ps = recompose(builder, cps[cps.len() - 1].as_slice());
                let prev_ps = recompose(builder, cps[cps.len() - 2].as_slice());
                let main_padding_col_height: Felt<C::F> = builder.eval(last_ps - prev_ps);
                // L+1-bit sound decomposition (boolean + sum-binding inside
                // num2bits for every production config).
                let bits = C::num2bits(builder, main_padding_col_height, cube_log + 1);
                // low = value of the low `cube_log` bits.
                let low: Felt<C::F> =
                    C::bits2num(builder, bits.iter().take(cube_log).copied());
                let high_part: Felt<C::F> = builder.eval(main_padding_col_height - low);
                let prod: Felt<C::F> = builder.eval(high_part * low);
                builder.assert_felt_eq(prod, C::F::ZERO);
            }
        }

        // (7) Check prefix-sum consistency: accumulating the
        // per-chip row counts must match the per-column prefix
        // sums the jagged-eval protocol emitted.
        // One entry per REAL column, in packing order: each round's chips, then
        // that round's stacking-padding column (one column, its own height).
        // `prefix_sum_felts` is indexed by the same column space, so the pads
        // have to be spliced in at the round boundaries or the walk falls a
        // column behind from the first boundary on.
        let mut repeated_row_counts: Vec<Felt<C::F>> = Vec::new();
        for (round_idx, (round_rows, round_cols)) in
            row_counts.iter().zip(column_counts.iter()).enumerate()
        {
            for (row, col) in round_rows.iter().zip(round_cols.iter()) {
                repeated_row_counts.extend(core::iter::repeat(*row).take(*col));
            }
            if let Some(pads) = padding_row_heights.get(round_idx) {
                repeated_row_counts.extend(pads.iter().copied());
            }
        }
        let mut acc: Felt<C::F> = builder.constant(C::F::ZERO);
        for (row_count, expected) in
            repeated_row_counts.iter().zip(prefix_sum_felts.iter())
        {
            builder.assert_felt_eq(acc, *expected);
            acc = builder.eval(acc + *row_count);
        }

        // Final area — Horner-recompose the last `col_prefix_sums`
        // vector into a single felt and assert `acc` equals it.
        let two: Felt<C::F> = builder.constant(C::F::ONE + C::F::ONE);
        let last_sum = params.col_prefix_sums.last().expect(
            "jagged-pcs: col_prefix_sums must have at least one entry",
        );
        // Horner-recompose SYMBOLICALLY (SP1 jagged/verifier.rs:158-162:
        // final_area = SymbolicFelt::zero(); `*bit + two*final_area` with NO
        // per-bit eval).  Materialization is deferred to the single
        // `assert_felt_eq` below — value-identical, fewer eval ops per area.
        let mut final_area: zkm_recursion_compiler::ir::SymbolicFelt<C::F> =
            zkm_recursion_compiler::ir::SymbolicFelt::<C::F>::ZERO;
        for bit in last_sum.iter() {
            final_area = *bit + two * final_area;
        }
        builder.assert_felt_eq(acc, final_area);

        // (8) Close the chain: jagged_eval * expected_eval must
        // equal the sumcheck's evaluation.
        let jagged_eval_sym: SymbolicExt<C::F, C::EF> = jagged_eval.into();
        let expected_eval_sym_for_lhs: SymbolicExt<C::F, C::EF> = (*expected_eval).into();
        let lhs: Ext<C::F, C::EF> = builder.eval(jagged_eval_sym * expected_eval_sym_for_lhs);
        builder.assert_ext_eq(lhs, sumcheck_proof.point_and_eval.1);


        // (9) Verify the dense-trace opening via the stacked PCS.
        let evaluation_point = sumcheck_proof.point_and_eval.0.clone();
        let expected_eval_sym: SymbolicExt<C::F, C::EF> = (*expected_eval).into();
        self.stacked_pcs_verifier.verify_untrusted_evaluation::<C, FC>(
            builder,
            original_commitments,
            &evaluation_point,
            pcs_proof,
            expected_eval_sym,
            challenger,
        );

        prefix_sum_felts
    }

    /// In-circuit height-binding guard: assert `row_count <= 2^cube_log`.
    ///
    /// `cube_log = point.len()` is the number of variables in the opened
    /// cube (z_row).  This is the in-circuit analog of the host's
    /// `assert!(height <= domain)` in `evaluate_trace_columns_at_point`
    /// (crates/pcs/src/shard_level/logup_gkr_prover.rs) — it prevents a
    /// height-agnostic prover from witnessing a `row_count` larger than the
    /// cube the trace MLE is actually opened over.
    ///
    /// Soundness of the decomposition: [`CircuitConfig::num2bits`] emits the
    /// bits as a hint and (for every production config) re-binds them by
    /// asserting each bit boolean and the weighted sum equals `row_count`, so
    /// the prover cannot supply a lying decomposition.  Requesting
    /// `cube_log + 1` bits proves `row_count < 2^{cube_log+1}`; the
    /// `(row_count - low)·low == 0` product then forbids the open interval
    /// `(2^cube_log, 2^{cube_log+1})`, leaving exactly `row_count ∈
    /// [0, 2^cube_log]` (inclusive — the tallest chip fills the cube).
    ///
    /// Config-generic: `row_count` and `low` are `Felt<C::F>`, so the closing
    /// `assert_felt_eq` works for both the inner (KoalaBear) and outer
    /// (BN254) recursion configs.
    fn assert_row_count_le_cube<C>(
        builder: &mut Builder<C>,
        row_count: Felt<C::F>,
        cube_log: usize,
    ) where
        C: CircuitConfig,
    {
        use p3_field::PrimeCharacteristicRing;
        // L+1-bit sound decomposition of row_count (boolean + sum-binding
        // happen inside num2bits for production configs).
        let bits = C::num2bits(builder, row_count, cube_log + 1);
        // low = value of the low `cube_log` bits = row_count - b_{cube_log}·2^L.
        let low: Felt<C::F> =
            C::bits2num(builder, bits.iter().take(cube_log).copied());
        // (row_count - low) is b_{cube_log}·2^L ∈ {0, 2^L}; multiplying by
        // `low` and asserting zero forces low == 0 whenever the high bit is
        // set, i.e. row_count ≤ 2^L.
        let high_part: Felt<C::F> = builder.eval(row_count - low);
        let prod: Felt<C::F> = builder.eval(high_part * low);
        builder.assert_felt_eq(prod, C::F::ZERO);
    }
}

/// Convenience wrapper that derives `insertion_points` from a
/// per-round column-count table before delegating to the base
/// [`RecursiveJaggedPcsVerifier::verify_trusted_evaluations`].
///
/// Mirrors `RecursiveMachineJaggedPcsVerifier`
/// (crates/recursion/circuit/src/jagged/verifier.rs) from the SP1 reference.
pub struct RecursiveMachineJaggedPcsVerifier<'a, P> {
    pub jagged_pcs_verifier: &'a RecursiveJaggedPcsVerifier<P>,
    pub column_counts_by_round: Vec<Vec<usize>>,
}

impl<'a, P> RecursiveMachineJaggedPcsVerifier<'a, P> {
    pub fn new(
        jagged_pcs_verifier: &'a RecursiveJaggedPcsVerifier<P>,
        column_counts_by_round: Vec<Vec<usize>>,
    ) -> Self {
        Self { jagged_pcs_verifier, column_counts_by_round }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn verify_trusted_evaluations<C, FC, JE>(
        &self,
        builder: &mut Builder<C>,
        commitments: &[P::Commitment],
        point: &[Ext<C::F, C::EF>],
        evaluation_claims: &[Vec<Ext<C::F, C::EF>>],
        proof: &JaggedPcsProofVariable<P::Proof, P::Commitment, C::F, C::EF>,
        challenger: &mut FC,
        jagged_evaluator_fn: JE,
    ) -> Vec<Felt<C::F>>
    where
        C: CircuitConfig,
        FC: FieldChallengerVariable<C, C::Bit>,
        P: RecursiveMultilinearPcsVerifier<C, FC>,
        P::Commitment: Copy,
        JE: FnOnce(
            &mut Builder<C>,
            &crate::jagged_circuit::JaggedDimensionMetadata<Felt<C::F>>,
            &[Ext<C::F, C::EF>],
            &[Ext<C::F, C::EF>],
            &[Ext<C::F, C::EF>],
            &JaggedSumcheckEvalProof<Ext<C::F, C::EF>>,
            &mut FC,
        ) -> (Ext<C::F, C::EF>, Vec<Felt<C::F>>),
    {
        // Derive insertion points via running sum of per-round
        // column-count sums (matches the SP1 scan pattern).
        let insertion_points: Vec<usize> = self
            .column_counts_by_round
            .iter()
            .scan(0usize, |state, round_cols| {
                *state += round_cols.iter().sum::<usize>();
                Some(*state)
            })
            .collect();

        self.jagged_pcs_verifier.verify_trusted_evaluations::<C, FC, JE>(
            builder,
            commitments,
            point,
            evaluation_claims,
            proof,
            &insertion_points,
            challenger,
            jagged_evaluator_fn,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::basefold_verifier::{BasefoldVerifierParams, RecursiveBasefoldVerifier};
    use crate::challenger::DuplexChallengerVariable;
    use zkm_recursion_compiler::config::InnerConfig;

    type C = InnerConfig;

    /// Construction smoke test: the jagged-PCS verifier composes
    /// with the production RecursiveBasefoldVerifier + stacked-PCS
    /// wrapper without requiring any circuit-compiler wiring.
    #[test]
    fn jagged_pcs_verifier_constructs() {
        let basefold_params = BasefoldVerifierParams::production_default(21);
        let basefold_verifier = RecursiveBasefoldVerifier::<zkm_pcs::koala_bear_poseidon2::KoalaBearPoseidon2>::new(basefold_params);
        let stacked = RecursiveStackedPcsVerifier::new(basefold_verifier, 21);
        let jagged = RecursiveJaggedPcsVerifier::new(stacked, 21);
        assert_eq!(jagged.max_log_row_count, 21);
        // Silence the `C` type alias — the purpose is type
        // composition, not runtime behavior.
        let _phantom: std::marker::PhantomData<C> = std::marker::PhantomData;
    }

    /// Construction smoke test: the per-shard machine wrapper
    /// derives insertion points from a column-count table.
    #[test]
    fn machine_jagged_pcs_verifier_constructs() {
        let basefold_params = BasefoldVerifierParams::production_default(21);
        let basefold_verifier = RecursiveBasefoldVerifier::<zkm_pcs::koala_bear_poseidon2::KoalaBearPoseidon2>::new(basefold_params);
        let stacked = RecursiveStackedPcsVerifier::new(basefold_verifier, 21);
        let jagged = RecursiveJaggedPcsVerifier::new(stacked, 21);
        let machine_jagged =
            RecursiveMachineJaggedPcsVerifier::new(&jagged, vec![vec![3, 4, 5], vec![2, 6]]);
        assert_eq!(machine_jagged.column_counts_by_round.len(), 2);
    }

    // ── HEIGHT-BINDING GUARD executed-circuit tests ──
    //
    // These compile + RUN the DSL through the recursion runtime
    // (`run_test_recursion`), so the in-circuit `assert_felt_eq` in
    // `assert_row_count_le_cube` actually fires.  An over-claimed height
    // makes the runtime panic (the asserted product is non-zero), which the
    // negative test captures via `#[should_panic]`; honest heights run clean.

    use p3_field::PrimeCharacteristicRing;
    use zkm_recursion_compiler::ir::{Builder, Felt};
    use zkm_pcs::InnerVal;

    /// Run the height guard against a single `row_count` over a cube of
    /// `2^cube_log` rows, executing the resulting circuit end-to-end.
    fn run_guard(row_count: u64, cube_log: usize) {
        use crate::utils::tests::run_test_recursion;
        let mut builder = Builder::<InnerConfig>::default();
        let rc: Felt<InnerVal> = builder.constant(InnerVal::from_u64(row_count));
        RecursiveJaggedPcsVerifier::<()>::assert_row_count_le_cube::<InnerConfig>(
            &mut builder,
            rc,
            cube_log,
        );
        run_test_recursion(builder.into_operations(), std::iter::empty());
    }

    /// POSITIVE: honest heights `<= 2^cube_log` (including 0, a sub-cube
    /// power of two, and the full cube `== 2^cube_log`) all verify.
    #[test]
    fn height_guard_accepts_valid_row_counts() {
        let cube_log = 4; // domain = 16
        run_guard(0, cube_log);
        run_guard(1, cube_log);
        run_guard(8, cube_log); // sub-cube power of two
        run_guard(16, cube_log); // full cube: row_count == 2^cube_log (inclusive)
    }

    /// NEGATIVE: an over-claimed height just past the cube
    /// (`row_count = 2^cube_log + 1 = 17 > 16`) is REJECTED — the runtime
    /// trips the `(row_count - low)*low == 0` assert.
    #[test]
    #[should_panic]
    fn height_guard_rejects_overclaimed_row_count_just_above_cube() {
        run_guard(17, 4);
    }

    /// NEGATIVE: a grossly over-claimed height (`row_count = 2*2^cube_log =
    /// 32 > 16`) is also REJECTED.
    #[test]
    #[should_panic]
    fn height_guard_rejects_overclaimed_row_count_double_cube() {
        run_guard(32, 4);
    }

    // ── MAIN-PADDING-COLUMN BIT-BOUND tests ──
    //
    // Forgery-rejection at the recursion-circuit level.  The soundness role
    // of the main (padding) column height bound is carried by the SP1-ported
    // bit-bound: decode the padding column height =
    // `recompose(col_prefix_sums.last()) −
    // recompose(col_prefix_sums[last-1])`, bit-decompose to `L+1` bits, and
    // assert the high bit forces the low bits to zero ⇒ height ∈ [0, 2^L].
    //
    // This is the bind that catches an AREA-PRESERVING height forgery: a
    // prover that inflates the last real column's height past the opened cube
    // `2^L` (while shrinking another column to keep `total_values` constant —
    // so the step-(7) prefix-sum / area consistency check still passes) trips
    // this bit-bound.  These tests run the EXACT in-circuit logic end-to-end
    // through the recursion runtime; `#[should_panic]` captures the rejection,
    // proving the constraint is real (not vacuous).

    /// Run the main-padding-column bit-bound against a single witnessed
    /// padding-column `height` over a cube of `2^max_log` rows — mirrors the
    /// exact step-(6.6) logic in `verify_trusted_evaluations`, executing the
    /// resulting circuit end-to-end.
    fn run_padding_bit_bound(height: u64, max_log: usize) {
        use crate::utils::tests::run_test_recursion;
        use crate::CircuitConfig;
        let mut builder = Builder::<InnerConfig>::default();
        let h: Felt<InnerVal> = builder.constant(InnerVal::from_u64(height));
        let bits = <InnerConfig as CircuitConfig>::num2bits(&mut builder, h, max_log + 1);
        let low: Felt<InnerVal> =
            <InnerConfig as CircuitConfig>::bits2num(&mut builder, bits.iter().take(max_log).copied());
        let high_part: Felt<InnerVal> = builder.eval(h - low);
        let prod: Felt<InnerVal> = builder.eval(high_part * low);
        builder.assert_felt_eq(prod, InnerVal::ZERO);
        run_test_recursion(builder.into_operations(), std::iter::empty());
    }

    /// POSITIVE: honest padding-column heights `<= 2^max_log` (including 0, a
    /// sub-cube power of two, and the full cube `== 2^max_log`) all verify —
    /// the bit-bound is a no-op on honest proofs.
    #[test]
    fn padding_bit_bound_accepts_valid_heights() {
        let max_log = 4; // cube = 16
        run_padding_bit_bound(0, max_log);
        run_padding_bit_bound(8, max_log); // sub-cube power of two
        run_padding_bit_bound(16, max_log); // full cube == 2^max_log (inclusive)
    }

    /// NEGATIVE: an AREA-PRESERVING over-claim that inflates the main
    /// padding column past the cube (`height = 2^max_log + 1 = 17 > 16`, the
    /// open interval the bit-bound forbids) is REJECTED — the runtime trips the
    /// `(height - low)*low == 0` assert.  Total area can be kept constant by a
    /// compensating shrink elsewhere, so the step-(7) area check would pass;
    /// THIS bit-bound is the catch.
    #[test]
    #[should_panic]
    fn padding_bit_bound_rejects_area_preserving_overclaim_just_above_cube() {
        run_padding_bit_bound(17, 4);
    }

    /// NEGATIVE: a doubled over-claim (`height = 2*2^max_log = 32 >
    /// 16`) — the boundary case where the high bit is exactly set with nonzero
    /// low bits absent — note `32 == 2^{max_log+1}` would overflow num2bits;
    /// `24 = 16 + 8` is inside `(2^L, 2^{L+1})` with low bits set, the sharp
    /// rejection case.
    #[test]
    #[should_panic]
    fn padding_bit_bound_rejects_overclaim_mid_interval() {
        run_padding_bit_bound(24, 4); // 11000b: high bit + a low bit set
    }
}
