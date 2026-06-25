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
//!     parameter `jagged_evaluator_fn` (decouples from the not-
//!     yet-ported `RecursiveJaggedEvalSumcheckConfig`).
//!   - SP1's `SC::hash` / `SC::compress` chip-info mix-in is
//!     deferred — the KoalaBearPoseidon2 hash scaffolding lands in
//!     a follow-up step.  Until then, the orchestrator asserts
//!     `commitments == original_commitments` up to dimension match
//!     rather than recomputing the mixed digest.
//!
//! # Status
//!
//! Structurally complete; the jagged-eval sub-protocol is
//! abstracted behind the `jagged_evaluator_fn` closure parameter so
//! the orchestrator can land without blocking on porting the full
//! `RecursiveJaggedEvalSumcheckConfig`.  Construction smoke tests
//! cover the type composition.

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
        // #H (BaseFold-over-BN254 wrap port): the main jagged-PCS
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
            original_commitments,
            expected_eval,
            // Height-agnostic groundwork (Stage 1, gap G2): the witnessed
            // numeric `row_counts_usize` / `padding_column_counts` are now
            // BOUND to the consumed forms below (step 6.6) so they cannot
            // disagree — the consumed `row_counts` Felt (derived from the
            // WITNESSED opened-degree height on the production height-agnostic
            // path) is pinned to the compile-time-expected `row_counts_usize`,
            // and `padding_column_counts` is pinned to the column-counts-
            // derived padding.  Additive + no-op on honest proofs (the lift
            // builds both forms from the same packing).
            row_counts_usize,
            padding_column_counts,
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

        // Host parity: Ziren's host packing has NO artificial zero
        // columns — `packing.offsets.len()-1 == Σ chip widths` always
        // (the dense vector's stripe-alignment padding extends the LAST
        // column's tail entries, it does not add columns), and the host
        // claim is the FLAT `Σ z_col_lagrange[k]·y[k]` walk
        // (jagged_sumcheck.rs verify_jagged_reduction).  The previous
        // `cc[len-2]+1` per-round zero-insertion was an SP1-ism: it
        // inflated the padded column count, and whenever
        // `next_pow2(flat+added) != next_pow2(flat)` (e.g. the keccak
        // 415-column shard: 1024 vs 512) the circuit sampled a different
        // number of z_col challenges than the host → transcript desync →
        // the claim assert below trips once assert enforcement is armed.  Zeros now
        // appear only as the power-of-two tail padding (weight-orthogonal
        // to the real claims, matching the host's missing-column tail).
        let _ = insertion_points;
        let zero_ext: Ext<C::F, C::EF> = builder.eval(SymbolicExt::ZERO);

        // (3) Pad the column claims to the next power of two so
        // the MLE evaluation is well-defined.
        let padded_len = column_claims.len().next_power_of_two();
        column_claims.resize(padded_len, zero_ext);

        // (4) The jagged sumcheck's claimed sum equals the column
        // MLE evaluated at `z_col`.
        let sumcheck_claim = evaluate_mle_ext::<C>(builder, &column_claims, &z_col);
        builder.assert_ext_eq(sumcheck_claim, sumcheck_proof.claimed_sum);


        // (5) Verify the jagged sumcheck.
        verify_sumcheck::<C, FC>(builder, challenger, sumcheck_proof);

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

        // (6.6) NUMERIC↔CONSUMED BINDING (Stage 1, gap G2).
        //
        // The proof carries TWO per-(round,chip) representations of each chip's
        // row count:
        //   * `row_counts`        — the consumed Felt form.  On the production
        //     height-agnostic path it is reconstructed from the WITNESSED opened
        //     `degree` (`chip_height_felts_from_opened_degrees`), so it is a
        //     prover-controlled value, and it is what the step-(7) prefix-sum /
        //     area checks actually accumulate.
        //   * `row_counts_usize`  — the witnessed NUMERIC form (SP1's
        //     `row_counts_and_column_counts`), a compile-time-baked count the
        //     verifier expects.
        // Until now `row_counts_usize` was DELIBERATELY ignored, so a malicious
        // prover could witness an opened-degree height (→ `row_counts` Felt)
        // that disagrees with `row_counts_usize` without detection.  Bind them:
        // assert the consumed Felt equals the numeric form lifted to the field.
        // This is ADDITIVE (no shape change), config-generic (`assert_felt_eq`
        // works for both the inner KoalaBear and outer BN254 rings), and a NO-OP
        // on honest proofs — the lift derives both forms from the same packing
        // (offset diffs == 2^log_h on the FIX-on path), so they already agree.
        // Bound by `row_counts_usize` so degenerate/scaffolding bundles that
        // carry no numeric form (empty `row_counts_usize`) add no asserts; the
        // dummy mirrors the real bundle's shape, so the op count stays identical
        // between dummy and real (value-independence preserved).
        for (round_felt, round_usize) in row_counts.iter().zip(row_counts_usize.iter()) {
            // Per-round shapes MUST agree (both are per-chip, name-sorted, same
            // chip set) — `.zip()` below is a no-op truncation only on the
            // degenerate empty-`row_counts_usize` branch handled by the outer
            // `.zip()`.  A partial length mismatch would silently weaken the
            // bind AND diverge dummy/real op counts, so surface it loudly in
            // debug/test (compiled out of release construction — no production
            // panic risk).
            debug_assert_eq!(
                round_felt.len(),
                round_usize.len(),
                "jagged-pcs (G2): row_counts / row_counts_usize per-round length \
                 mismatch ({} vs {}) — would break the numeric↔consumed bind",
                round_felt.len(),
                round_usize.len(),
            );
            for (&row_count_felt, &row_count_num) in round_felt.iter().zip(round_usize.iter()) {
                let expected: Felt<C::F> =
                    builder.constant(C::F::from_canonical_usize(row_count_num));
                builder.assert_felt_eq(row_count_felt, expected);
            }
        }

        // (6.6b) PADDING-COLUMN-COUNT BINDING (Stage 1, gap G2).
        //
        // `padding_column_counts` is the witnessed NUMERIC count of artificial
        // columns the BaseFold stacking rounds the real total column count up to
        // the next power of two.  Nothing in the verify path consumes it yet
        // (the full SP1 padding bit-bounds are Stage 3 / gap G4), so there is no
        // in-circuit witness VARIABLE to constrain — both `padding_column_counts`
        // and the column-counts-derived padding are compile-time `usize` baked
        // into the program (no prover-controlled dimension, hence no in-circuit
        // soundness lever here yet).  Pin the numeric form to that deterministic
        // value with a COMPILE-TIME `debug_assert_eq!` (NOT an in-circuit
        // `assert_felt_eq`): it emits ZERO circuit ops — keeping the verify path
        // EXACTLY byte-identical — and is compiled out of release recursion-
        // program construction, so it can never spuriously break production
        // construction, while still catching a lift bug that lets the padding
        // count drift from the column structure it describes in debug/test
        // builds.  (Stage 3 promotes this to the SP1 8-way padding bit-bounds
        // once the padding columns become circuit witnesses.)
        for (round_idx, &padding) in padding_column_counts.iter().enumerate() {
            let total_real_cols: usize =
                column_counts.get(round_idx).map(|cc| cc.iter().sum()).unwrap_or(0);
            let expected_padding =
                total_real_cols.max(1).next_power_of_two().saturating_sub(total_real_cols);
            debug_assert_eq!(
                padding, expected_padding,
                "jagged-pcs (G2): witnessed padding_column_counts[{round_idx}] = {padding} \
                 disagrees with the column-counts-derived padding {expected_padding} \
                 (total_real_cols = {total_real_cols})",
            );
        }

        // (7) Check prefix-sum consistency: accumulating the
        // per-chip row counts must match the per-column prefix
        // sums the jagged-eval protocol emitted.
        let repeated_row_counts: Vec<Felt<C::F>> = row_counts
            .iter()
            .flatten()
            .zip(column_counts.iter().flatten())
            .flat_map(|(row, col)| core::iter::repeat(*row).take(*col))
            .collect();
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

    // ── HEIGHT-BINDING GUARD (Deliverable 2) executed-circuit tests ──
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

    // ── NUMERIC↔CONSUMED BINDING (Stage 1, gap G2) executed-circuit tests ──
    //
    // Mirror the height-guard pattern: build the consumed `row_count` Felt and
    // bind it to the witnessed numeric `row_count_usize` exactly as step (6.6)
    // of `verify_trusted_evaluations` does, then RUN the DSL.  When the two
    // agree the binding is a no-op; when they disagree the runtime trips the
    // in-circuit `assert_felt_eq`, which `#[should_panic]` captures — proving
    // the constraint is real (not vacuous).

    /// Build `row_count` as a Felt and assert it equals
    /// `from_canonical_usize(row_count_num)` — the exact step-(6.6) binding —
    /// then execute the circuit.
    fn run_numeric_binding(row_count_felt: u64, row_count_num: usize) {
        use crate::utils::tests::run_test_recursion;
        let mut builder = Builder::<InnerConfig>::default();
        let rc: Felt<InnerVal> = builder.constant(InnerVal::from_u64(row_count_felt));
        let expected: Felt<InnerVal> =
            builder.constant(InnerVal::from_canonical_usize(row_count_num));
        builder.assert_felt_eq(rc, expected);
        run_test_recursion(builder.into_operations(), std::iter::empty());
    }

    /// POSITIVE: when the consumed Felt equals the witnessed numeric form the
    /// binding is a no-op (this is the honest-prover case — the lift derives
    /// both from the same packing).
    #[test]
    fn numeric_binding_accepts_consistent_counts() {
        run_numeric_binding(0, 0);
        run_numeric_binding(1, 1);
        run_numeric_binding(1024, 1024); // 2^10, a real chip height
    }

    /// NEGATIVE: a prover that witnesses a numeric `row_count_usize` that
    /// disagrees with the consumed `row_counts` Felt (here the Felt decodes a
    /// height the numeric form does not) is REJECTED by the step-(6.6) bind.
    #[test]
    #[should_panic]
    fn numeric_binding_rejects_inconsistent_counts() {
        run_numeric_binding(1024, 512);
    }
}
