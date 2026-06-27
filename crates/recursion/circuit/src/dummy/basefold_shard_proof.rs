//! Zero-fill allocator for [`BasefoldShardProof`].
//!
//! Port of SP1's `dummy_shard_proof` (crates/recursion/circuit/src/dummy/shard_proof.rs)
//! adapted for Ziren's `BasefoldShardProof<F, EF>` struct.  Every
//! field is zero-filled — no real prove call, no AIR evaluation,
//! microseconds per invocation instead of seconds.
//!
//! # Shape mirror
//!
//! Outputs match what
//! [`zkm_pcs::shard_level::prover::prove_shard_to_basefold`]
//! produces at the same `(shape, max_log_row_count)` input pair,
//! so downstream consumers walk identical felt counts.

use std::collections::BTreeMap;

use p3_air::BaseAir;
use p3_field::{ExtensionField, Field, PrimeCharacteristicRing};

use zkm_pcs::{
    air::{LookupScope, MachineAir},
    septic_digest::SepticDigest,
    shard_level::{
        shard_proof::{BasefoldShardProof, ChipCumulativeSums, FoldOrientation},
        types::{
            ChipEvaluation, LogUpEvaluations, LogUpGkrOutput, LogupGkrProof, LogupGkrRoundProof,
            PartialSumcheckProof, UnivariatePolynomial,
        },
    },
    AirOpenedValues, Chip, ChipOpenedValues, ShardOpenedValues, PROOF_MAX_NUM_PVS,
};

/// Allocator for [`PartialSumcheckProof`] — zero-filled.
///
/// Mirror of SP1's `dummy_sumcheck_proof`
/// (crates/recursion/circuit/src/dummy/sumcheck.rs).
///
/// * `num_variables` — number of sumcheck rounds (= number of
///   univariate polys, = dimension of `point_and_eval.0`)
/// * `degree` — per-round polynomial degree (each poly carries
///   `degree + 1` coefficients).  SP1 uses 4 for zerocheck and 3
///   for LogUp-GKR rounds.
pub fn dummy_partial_sumcheck_proof<EF: Field + Copy + PrimeCharacteristicRing>(
    num_variables: usize,
    degree: usize,
) -> PartialSumcheckProof<EF> {
    let univariate_polys: Vec<UnivariatePolynomial<EF>> = (0..num_variables)
        .map(|_| UnivariatePolynomial::new(vec![EF::ZERO; degree + 1]))
        .collect();
    PartialSumcheckProof {
        univariate_polys,
        claimed_sum: EF::ZERO,
        point_and_eval: (vec![EF::ZERO; num_variables], EF::ZERO),
    }
}

/// Allocator for [`LogupGkrProof`] — zero-filled, structurally
/// SP1-shaped.
///
/// Mirror of SP1's `dummy_gkr_proof`
/// (crates/recursion/circuit/src/dummy/logup_gkr.rs).
///
/// Key shape rules (mirror SP1 exactly):
///
///   * `round_proofs.len() == log_max_row_height - 1`
///   * per-round sumcheck dimension `i + log_interactions + 1`
///     where `log_interactions = log2_ceil(Σ chip.num_lookups.next_pow2())`
///   * `logup_evaluations.point.dimension() == log_max_row_height`
///   * `circuit_output.numerator.len() == 1 << (log_interactions + 1)`
///     (per-chip-padded sum — matches host prover + in-circuit verifier)
///   * per-chip `main_trace_evaluations.len() == chip.air.width()`
///   * per-chip `preprocessed_trace_evaluations` is `Some(...)` only
///     when `chip.preprocessed_width() > 0`
pub fn dummy_logup_gkr_proof<F, EF, A>(
    chips: &[&Chip<F, A>],
    log_max_row_height: usize,
) -> LogupGkrProof<F, EF>
where
    F: Field + Copy + PrimeCharacteristicRing,
    EF: ExtensionField<F> + Copy + PrimeCharacteristicRing,
    A: MachineAir<F>,
{
    // Ziren's per-chip "interaction count" = sends + receives, exposed
    // as `Chip::num_lookups()` (see `crates/pcs/src/chip.rs:99`).
    //
    // **Sizing convention** (matches host prover + in-circuit verifier):
    //
    // Both the host prover (`first_layer.rs:507-508`) and the recursion
    // verifier (`shard_basefold.rs::chip_metadata_from_chips`) compute
    // `num_interaction_variables` as
    //   `log2_ceil(Σ chip.num_lookups().next_power_of_two())`
    // — per-chip-padded sum, then log-ceil.  SP1 uses raw sum + log-ceil
    // instead, but Ziren diverged at `shard_basefold.rs:232-244` ("BUG
    // FIX") to align with the host's column-width padding pattern.
    //
    // This dummy MUST mirror the verifier's expectation, otherwise the
    // recursion-circuit `evaluate_mle_ext` assertion at
    // `logup_gkr.rs:105` panics with `mle_evals.len() != 1 << dim`
    // during VK regen / VERIFY_VK=true on shapes where any chip has
    // a non-power-of-two interaction count (e.g. Recursion shape 0
    // with [9,9,9]-style chips: raw-sum gives 2^14, padded-sum gives
    // 2^15 → 16384 vs 32768 left/right mismatch).
    let total_padded_interactions: usize = chips
        .iter()
        .map(|chip| chip.num_lookups().max(1).next_power_of_two())
        .sum();
    let log_interactions = log2_ceil_usize(total_padded_interactions);
    let output_size = 1usize << (log_interactions + 1);

    let circuit_output = LogUpGkrOutput {
        numerator: vec![EF::ZERO; output_size],
        denominator: vec![EF::ZERO; output_size],
    };

    // SP1 emits `log_max_row_height - 1` rounds — guard against
    // underflow in degenerate single-row shapes (would never happen
    // in production, but the saturating sub keeps the allocator
    // total since it can be called with any shape during fixture
    // generation / probing).
    let round_count = log_max_row_height.saturating_sub(1);
    let round_proofs: Vec<LogupGkrRoundProof<EF>> = (0..round_count)
        .map(|i| LogupGkrRoundProof {
            numerator_0: EF::ZERO,
            numerator_1: EF::ZERO,
            denominator_0: EF::ZERO,
            denominator_1: EF::ZERO,
            // SP1: round i sumcheck has `i + log2_ceil(interactions) + 1`
            // rounds, degree 3.
            sumcheck_proof: dummy_partial_sumcheck_proof::<EF>(
                i + log_interactions + 1,
                3,
            ),
        })
        .collect();

    let logup_evaluations = LogUpEvaluations {
        point: vec![EF::ZERO; log_max_row_height],
        chip_openings: chips
            .iter()
            .map(|chip| {
                let name = MachineAir::<F>::name(*chip);
                // Chip<F, A> delegates BaseAir<F> via its inner `air` field.
                let main_width = <_ as BaseAir<F>>::width(&chip.air);
                let preprocessed_width =
                    MachineAir::<F>::preprocessed_width(*chip);
                (
                    name,
                    ChipEvaluation {
                        main_trace_evaluations: vec![EF::ZERO; main_width],
                        preprocessed_trace_evaluations: if preprocessed_width > 0 {
                            Some(vec![EF::ZERO; preprocessed_width])
                        } else {
                            None
                        },
                        // log_degree placeholder — per-chip
                        // log_height is carried separately by
                        // `BasefoldShardProof.chip_log_heights`
                        // (see [`dummy_basefold_shard_proof`]).
                        log_degree: 0,
                        // #88 Stage 3b: SP1-parity FULL-POINT openings.  The
                        // VK-enumeration dummy MUST carry these with the SAME
                        // shape the real prover emits (top_level.rs:517-538) so
                        // the recursion AIR / witness layout (and thus the
                        // regenerated VK) matches real proofs.  The real prover
                        // emits `main_trace_evaluations_full = Some(width)` for
                        // every host/device chip and `preprocessed_*_full =
                        // Some(preprocessed_width)` only when prep_width > 0.
                        main_trace_evaluations_full: Some(vec![EF::ZERO; main_width]),
                        preprocessed_trace_evaluations_full: if preprocessed_width > 0 {
                            Some(vec![EF::ZERO; preprocessed_width])
                        } else {
                            None
                        },
                    },
                )
            })
            .collect(),
    };

    LogupGkrProof {
        circuit_output,
        round_proofs,
        logup_evaluations,
        witness: F::ZERO,
    }
}

/// Allocator for [`BasefoldShardProof`] — zero-filled, no real
/// prove call.  Top-level entry replacing the previous slow
/// `prove_shard_to_basefold` path inside
/// [`crate::stark::dummy_basefold_vk_and_shard_proof`].
///
/// # Inputs
///
/// * `chips` — per-chip references resolved from the input shape
///   (caller does the shape → machine.chips() join).
/// * `chip_log_heights_pairs` — per-chip (name, log_height) pairs
///   matching the shape order.  Used to populate both
///   `chip_log_heights` and `chip_cumulative_sums` maps with one
///   entry per chip (the shape-stability invariant the parity
///   test guards).
/// * `max_log_row_count` — shard-level upper bound on per-chip
///   log-row-count.  Drives `logup_gkr_proof.round_proofs.len()` and
///   `zerocheck_proof.univariate_polys.len()`.
///
/// # Field summary
///
/// | field                  | value                                  |
/// |------------------------|----------------------------------------|
/// | `public_values`        | `vec![ZERO; PROOF_MAX_NUM_PVS]`        |
/// | `main_commitment`      | `[ZERO; 8]`                            |
/// | `logup_gkr_proof`      | [`dummy_logup_gkr_proof`]              |
/// | `zerocheck_proof`      | `dummy_partial_sumcheck_proof(max_log_row_count, 4)` |
/// | `opened_values`        | `ShardOpenedValues { chips: Vec::new() }` (matches real prover at `prover.rs:365`) |
/// | `chip_log_heights`     | one entry per chip from input shape    |
/// | `chip_cumulative_sums` | one entry per chip (local=ZERO, global=ZERO) |
/// | `evaluation_proof`     | `EvaluationProof::Empty` — lift adapter handles the Empty arm |
pub fn dummy_basefold_shard_proof<F, EF, A>(
    chips: &[&Chip<F, A>],
    chip_log_heights_pairs: &[(String, u8)],
    max_log_row_count: usize,
) -> BasefoldShardProof<F, EF>
where
    F: Field + Copy + PrimeCharacteristicRing,
    EF: ExtensionField<F> + Copy + PrimeCharacteristicRing,
    A: MachineAir<F>,
{
    let public_values = vec![F::ZERO; PROOF_MAX_NUM_PVS];
    let main_commitment: [F; 8] = std::array::from_fn(|_| F::ZERO);

    let logup_gkr_proof =
        dummy_logup_gkr_proof::<F, EF, A>(chips, max_log_row_count);

    // SP1 uses degree 4 for zerocheck rounds (max_log_row_count
    // rounds total).
    let zerocheck_proof =
        dummy_partial_sumcheck_proof::<EF>(max_log_row_count, 4);

    // The real prover (`shard_level/prover.rs:438-498`)
    // now populates one `ChipOpenedValues` per chip (name-sorted) with
    // the per-chip trace@z openings — `main.local` of `width` Exts,
    // `preprocessed.local` of `preprocessed_width` Exts, and `quotient`
    // = the `max_log_row_count + 1` big-endian height-bit `degree`.  The
    // VK-regen shape-compiled program (`program_from_shape_basefold`)
    // allocates witness slots from THIS dummy, so its `opened_values`
    // shape MUST match the real proof's per-chip column counts — an
    // empty `chips` Vec here would allocate zero opened_values slots
    // against N written felts and desync the witness stream during
    // vk_map regeneration.  The values are zero (shape-only fixture).
    let opened_values = {
        let bit_len = max_log_row_count + 1;
        let heights_map: BTreeMap<String, u8> =
            chip_log_heights_pairs.iter().cloned().collect();
        let mut name_sorted: Vec<&&Chip<F, A>> = chips.iter().collect();
        name_sorted
            .sort_by(|a, b| MachineAir::<F>::name(**a).cmp(&MachineAir::<F>::name(**b)));
        let chips_ov: Vec<ChipOpenedValues<F, EF>> = name_sorted
            .iter()
            .map(|chip| {
                let prep_w = MachineAir::<F>::preprocessed_width(**chip);
                let main_w = <_ as BaseAir<F>>::width(&chip.air);
                let name = MachineAir::<F>::name(**chip);
                let log_h = heights_map.get(&name).copied().unwrap_or(0) as usize;
                // quotient[0] carries the big-endian bits
                // of the chip HEIGHT (2^log_h, the VirtualGeq threshold), MSB at
                // index 0 — the SAME encoding the real prover emits
                // (shard_level/prover.rs:486-507).  Zeroing it (the old dummy)
                // made the recursion program's full_geq emit fewer ops than the
                // real-input program (the 452B tail residual).
                let height: u64 = 1u64 << log_h;
                let degree_bits: Vec<EF> = (0..bit_len)
                    .map(|i| {
                        let shift = bit_len - 1 - i;
                        let bit = if shift < u64::BITS as usize {
                            (height >> shift) & 1
                        } else {
                            0
                        };
                        if bit == 1 {
                            EF::ONE
                        } else {
                            EF::ZERO
                        }
                    })
                    .collect();
                ChipOpenedValues {
                    preprocessed: AirOpenedValues {
                        local: vec![EF::ZERO; prep_w],
                        next: Vec::new(),
                    },
                    main: AirOpenedValues {
                        local: vec![EF::ZERO; main_w],
                        next: Vec::new(),
                    },
                    permutation: AirOpenedValues { local: Vec::new(), next: Vec::new() },
                    quotient: vec![degree_bits],
                    global_cumulative_sum: SepticDigest::<F>::zero(),
                    local_cumulative_sum: EF::ZERO,
                    log_degree: log_h,
                }
            })
            .collect();
        ShardOpenedValues { chips: chips_ov }
    };

    let chip_log_heights: BTreeMap<String, u8> = chip_log_heights_pairs
        .iter()
        .map(|(name, log_h)| (name.clone(), *log_h))
        .collect();

    // Per-chip cumulative-sums map: one entry per chip with
    // both `local` and `global` zeroed.  Real prover at
    // `shard_level/prover.rs:401-428` derives `global` from the
    // last 14 elements of the main trace when scope != Local; for
    // zero-trace dummies that derivation produces a zero digest
    // too, so zero-fill is byte-identical to the real-prove output
    // on zero traces (the path this dummy replaces).
    //
    // The local-scope chips also emit `SepticDigest::zero()` in
    // the real prover (line 410), so the unconditional zero here
    // is exact.
    let chip_cumulative_sums: BTreeMap<String, ChipCumulativeSums<F, EF>> =
        chips
            .iter()
            .map(|chip| {
                let name = MachineAir::<F>::name(*chip);
                // commit_scope() inspection kept here to document
                // the equivalence with the real-prover code path —
                // both arms produce the same zero digest on zero
                // traces.
                let _scope_documented = chip.commit_scope() == LookupScope::Local;
                (
                    name,
                    ChipCumulativeSums {
                        local: EF::ZERO,
                        global: SepticDigest::<F>::zero(),
                    },
                )
            })
            .collect();

    // Build a shape-faithful jagged-basefold Bundle (zero values) so the
    // dummy's witness stream matches the real prover's byte-for-byte.  Chip
    // dims in NAME-SORTED order (matches the lift's name-sorted
    // `column_counts_by_round`); width = main trace width, height = 2^log_h.
    let evaluation_proof = {
        let heights: BTreeMap<String, u8> =
            chip_log_heights_pairs.iter().cloned().collect();
        let mut name_sorted: Vec<&&Chip<F, A>> = chips.iter().collect();
        name_sorted
            .sort_by(|a, b| MachineAir::<F>::name(**a).cmp(&MachineAir::<F>::name(**b)));
        let chip_dims: Vec<(usize, u32)> = name_sorted
            .iter()
            .map(|chip| {
                let name = MachineAir::<F>::name(**chip);
                let w = <_ as BaseAir<F>>::width(&chip.air);
                let log_h = heights.get(&name).copied().unwrap_or(0) as u32;
                (w, log_h)
            })
            .collect();
        zkm_pcs::shard_level::shard_proof::EvaluationProof::Bundle(
            dummy_jagged_basefold_bundle(&chip_dims, max_log_row_count),
        )
    };

    // ── Height-agnostic groundwork (Stage 3): dummy emits the SAME
    // numeric row_counts / padding_column_counts the real prover does
    // for this shape, derived from the SAME jagged packing
    // (`dummy_jagged_basefold_bundle` builds it via `pack_traces_jagged`
    // on zero matrices -> exact offsets/column_counts/total_values), so
    // dummy == real on the new fields by construction.  PURE DATA.
    let (row_counts, padding_column_counts): (Vec<Vec<usize>>, Vec<usize>) =
        match &evaluation_proof {
            zkm_pcs::shard_level::shard_proof::EvaluationProof::Bundle(bundle) => {
                let (rc, pcc) =
                    zkm_pcs::jagged::derive_row_and_padding_counts(
                        &bundle.packing.column_counts,
                        &bundle.packing.offsets,
                        bundle.packing.total_values,
                    );
                (vec![rc], vec![pcc])
            }
            _ => (Vec::new(), Vec::new()),
        };

    #[allow(clippy::needless_update)]
    BasefoldShardProof {
        public_values,
        main_commitment,
        logup_gkr_proof,
        zerocheck_proof,
        opened_values,
        chip_log_heights,
        chip_cumulative_sums,
        evaluation_proof,
        // The verifier-simulation dummy emits MSB-folded proofs
        // (host-CPU convention — matches the CpuProver call site).
        fold_orientation: FoldOrientation::Msb,
        row_counts,
        padding_column_counts,
        // Hash-bind: value-independent (the recursion program is built from the
        // dummy; only the witness-stream LENGTH — 8 felts — must match real).
        jagged_original_commitment: std::array::from_fn(|_| F::ZERO),
    }
}

/// Build a SHAPE-FAITHFUL (zero-VALUE) [`JaggedBasefoldBundle`] for the
/// dummy shard proof, so the witness stream the recursion program reads from a
/// dummy matches the real prover's byte-for-byte (the recursion program is now
/// value-independent — only field LENGTHS matter).  Replaces the prior
/// `EvaluationProof::Empty`, which produced a tiny zero placeholder lift and
/// made the dummy program diverge from the real one at byte 24.
///
/// `chip_dims` = per-chip `(main_width, log_height)` in the SAME order the
/// jagged packing uses (name-sorted — matches the lift's `column_counts_by_round`
/// AND the lift's `bundle.commit.chip_dims` row-count derivation).
/// `max_log_row_count` = M (the BaseFold stacking height / verifier num_variables).
///
/// Field LENGTHS (all derived from the shape; see
/// `ref_p2c_witness_the_bundle_plan` for the full law derivation):
/// * packing via [`pack_traces_jagged`] on zero matrices → offsets,
///   total_values, log_dense_size (L), column_counts.
/// * basefold proof: M rounds (uni_poly `[EF;2]` + 1-cap root); M query rounds
///   × Q (= `lb_fri_config().num_queries`) leaves × (sibling `[lo,hi]` +
///   `(M-r)`-digest path); batch_evaluations = one vec of `2^(L-M)`.
/// * reduction: L rounds (`evals=[EF;3]`), eval_point len L.
/// * jagged_eval: `n = 2*(log_m+1)` rounds (`log_m =
///   trailing_zeros(np2(total_values-1))`), each poly 3 coeffs (degree-2).
pub fn dummy_jagged_basefold_bundle(
    chip_dims: &[(usize, u32)],
    max_log_row_count: usize,
) -> zkm_pcs::jagged_pcs::jagged::JaggedBasefoldBundle {
    use p3_matrix::dense::RowMajorMatrix;
    use p3_symmetric::MerkleCap;
    use zkm_pcs::basefold::proof::{BasefoldProof, LeafOpening, MerkleOpening};
    use zkm_pcs::basefold::stacked::StackedBasefoldProof;
    use zkm_pcs::jagged::pack_traces_jagged;
    use zkm_pcs::jagged_eval_sumcheck::JaggedSumcheckEvalProof;
    use zkm_pcs::jagged_pcs::jagged::{JaggedBasefoldBundle, PackingMeta};
    use zkm_pcs::jagged_pcs::{
        lb_fri_config, pick_log_stacking_height, BasefoldLateBindingCommit, JaggedMmcs,
    };
    use zkm_pcs::jagged_sumcheck::{JaggedReductionProof, JaggedReductionRound};
    use zkm_pcs::shard_level::types::{PartialSumcheckProof, UnivariatePolynomial};
    use zkm_pcs::{InnerChallenge, InnerVal};

    type F = InnerVal;
    type EF = InnerChallenge;
    const D: usize = 4; // InnerChallenge = BinomialExtensionField<InnerVal, 4>

    // ── HEIGHT-AGNOSTIC RECURSION (step 5a): build the JAGGED shape at the
    // PASSED per-chip heights.  In the VK enumeration these are the cluster
    // MAXIMAL-shape heights (normalize via `maximal_core_shapes`, compress via
    // `RecursionShapeConfig::allowed_shapes`), so the dummy is already built at
    // the per-chip-set cluster-max — the correct, BOUNDED max (caps ≤21, never
    // overflows num2bits).  Step 4's blanket `1 << max_log_row_count` for EVERY
    // chip was WRONG: it over-padded the wide COMPRESS chip-set to
    // total_values > 2^31 → the `num2bits` 31-bit panic in `ZKMProver::new()`.
    // The real prover pads its jagged commit to the SAME cluster-max via
    // `CoreShapeConfig::find_core_shape` (step 5b), so vk_real == vk_dummy with
    // the core STARK still proving at the ACTUAL heights.
    //
    // pack_traces_jagged uses only height/width, so zero data gives the exact
    // offsets / total_values / log_dense_size / column_counts.
    let _ = max_log_row_count;
    let traces: Vec<(String, RowMajorMatrix<F>)> = chip_dims
        .iter()
        .enumerate()
        .map(|(i, (width, log_h))| {
            let w = (*width).max(1);
            let h = 1usize << *log_h;
            (
                format!("chip{i}"),
                RowMajorMatrix::new(vec![F::ZERO; w * h], w),
            )
        })
        .collect();
    let packing = pack_traces_jagged::<F>(&traces);
    let total_values = packing.total_values;
    // ── RECURSION-LAYER AREA PIN (#88/#82 Stage 2 DUMMY MIRROR) ──
    // Mirror EXACTLY the host pin in
    // `zkm_pcs::jagged_pcs::precompute_jagged_basefold_commit_generic`:
    // when the recursion (`compress`) prover has installed the area pin on
    // this thread (via `RecursionAreaPinGuard`, read with
    // `current_recursion_area_pin()`), raise `log_dense_size` (= L) to the pin
    // floor so the dummy commits at the FIXED area `2^pin` — giving constant
    // `num_stripes = 2^(L - log_stacking) = 2^(27-21) = 64`, constant reduction
    // rounds / eval_point (= L), and `commit.chip_dims = [(1, L)]` — IDENTICAL
    // to the real PINNED recursion proof regardless of the child's natural
    // heights.  CORE children (normalize) leave the carrier UNSET (`None`) →
    // NATURAL own-area packing (byte-identical to the unpinned dummy).
    //
    // `offsets` / `column_counts` / `total_values` stay NATURAL — the host pin
    // raises only the committed dense AREA (`log_dense_size`), never the column
    // geometry; the recursion verifier reads these WITNESSED offsets directly.
    // The jagged-eval sub-sumcheck dimension `jagged_n` IS pinned, though (see
    // the `log_m` note below) — it tracks the PINNED dense, mirroring the real
    // prover's pinned `prove_jagged_evaluation` (`half = z_trace.len() + 1`).
    let recursion_pin = zkm_pcs::shard_level::band_cap::current_recursion_area_pin();
    let mut log_dense_size = packing.log_dense_size;
    if let Some(target) = recursion_pin {
        if log_dense_size < target {
            log_dense_size = target;
        }
    }
    let column_counts: Vec<usize> =
        packing.chip_infos.iter().map(|ci| ci.column_count).collect();
    let packing_meta = PackingMeta {
        offsets: packing.offsets.clone(),
        total_values,
        log_dense_size,
        column_counts,
    };

    // ── Derived sub-lengths ──
    let l = log_dense_size;
    // The BaseFold is over the STACKED poly: its rounds / query path lengths /
    // batch width all key off log_stacking_height (the prover's clamped value),
    // NOT max_log_row_count.  pick_log_stacking_height = min(21, log2(np2(total))-1).
    //
    // ★ HEIGHT-AGNOSTIC-RECURSION (step 2b): this CLAMP is THE source of the
    // recursion program's clamp-dependence — `log_stacking` (hence the
    // BaseFold round count = `fri_commitments` len, the query/Merkle path
    // lengths, and `num_stripes`) varies with `total_values`, which varies
    // with chip HEIGHTS for a FIXED chip-set.  The dummy faithfully mirrors
    // the prover's clamp (it MUST, to match a real proof's shape), so the
    // program built from this dummy is clamp-shaped.  Making the recursion
    // program clamp-INDEPENDENT requires removing the clamp at the host commit
    // (`pick_log_stacking_height` → fixed `DEFAULT_LOG_STACKING_HEIGHT`),
    // which this dummy would then track automatically.  See the scoping note
    // at `machine/core_basefold.rs` (the per-proof verifier rebuild) for why
    // masking-to-MAX in the verifier alone is unsound (Fiat-Shamir desync).
    let log_stacking = pick_log_stacking_height(total_values) as usize;
    let num_stripes = 1usize << l.saturating_sub(log_stacking); // batch_evaluations width
    let inner_fri = lb_fri_config();
    let num_queries = inner_fri.num_queries;
    // #57: the component-opening Merkle path length keys off the codeword
    // height = 2^(log_stacking + log_blowup).  At the SP1-faithful inner
    // default this is blowup=2 (was 1), so the dummy path length must track
    // the config, not a hardcoded `+1`.
    let inner_log_blowup = inner_fri.log_blowup();
    // jagged-eval sub-sumcheck dimension `jagged_n = 2*(log_m+1)`.
    //
    // RECURSION-LAYER AREA PIN (#88/#82 Stage 2): when the area pin is active,
    // the real prover's `prove_jagged_evaluation` runs the jagged-eval over the
    // PINNED dense (it sets `half = z_trace.len() + 1` where `z_trace` is the
    // reduction's eval_point of the pinned `2^log_dense_size` dense), so
    // `jagged_n = 2*(log_dense_size + 1)` regardless of the child's NATURAL
    // `total_values`.  Mirror that here (`log_m = log_dense_size`, the pinned L)
    // so the dummy child's `jagged_n` equals the real pinned child's — the LAST
    // height-dependent length, collapsing the compose VK to f(chip-set, arity).
    // CORE children (`None`) keep the NATURAL derivation (byte-identical).
    let log_m = match recursion_pin {
        Some(_) => log_dense_size,
        None => {
            if total_values <= 1 {
                0
            } else {
                (total_values - 1).next_power_of_two().trailing_zeros() as usize
            }
        }
    };
    let jagged_n = 2 * (log_m + 1);

    let zero_cap = || MerkleCap::<F, [F; 8]>::new(vec![[F::ZERO; 8]]);

    // ── BaseFold proof (log_stacking rounds; query openings drive the stream) ──
    let univariate_messages: Vec<[EF; 2]> = vec![[EF::ZERO; 2]; log_stacking];
    let fri_commitments: Vec<_> = (0..log_stacking).map(|_| zero_cap()).collect();
    // query_phase_openings_and_proofs: log_stacking rounds, each Q leaves; round
    // r leaf has its Merkle path against the commit-phase round-r codeword.
    //
    // FAITHFUL PATH LENGTH (validated against the real prover by digest match —
    // `zkm_prover::tests::multishard_normalize_arity_faithful`): the real
    // BaseFold prover (crates/pcs/src/basefold/prover.rs:455-470) folds the
    // codeword once per round; commit-phase round `r` (0-indexed) opens at a
    // codeword of height 2^(num_variables + log_blowup - 1 - r), so its Merkle
    // path length is `num_variables + log_blowup - 1 - r` where
    // `num_variables == log_stacking`.  The previous `log_stacking - r` assumed
    // `log_blowup == 1`; the SP1-faithful inner default is `log_blowup == 2`
    // (#57 soundness), so each path was ONE level too short.  In-circuit the
    // path Select-loop count = `leaf.proof.len()`
    // (basefold_verifier.rs:555-561 via the lift's
    // `merkle_path_digests = leaf.proof.clone()`), so this under-count emitted
    // `log_stacking * (log_blowup-1) * num_queries` fewer Merkle Select+Poseidon2
    // ops than the real program (measured 46872-instr deficit at log_blowup=2,
    // log_stacking=21, num_queries=124 → the normalize VK diverged from the real
    // proof's VK).  Tracking `inner_log_blowup` makes the dummy faithful.
    let query_phase_openings_and_proofs: Vec<MerkleOpening<F, JaggedMmcs>> = (0..log_stacking)
        .map(|r| {
            let path_len = log_stacking + inner_log_blowup - 1 - r;
            let leaves: Vec<LeafOpening<F, JaggedMmcs>> = (0..num_queries)
                .map(|_| LeafOpening {
                    values: vec![vec![F::ZERO; 2 * D]],
                    proof: vec![[F::ZERO; 8]; path_len],
                })
                .collect();
            MerkleOpening { leaves }
        })
        .collect();
    // Component openings are now WITNESSED + consumed (the
    // bound initial_eval + the component Merkle binding), so the dummy
    // must carry the shape-correct zero-filled structure: ONE round (the
    // single stacked commit), `num_queries` leaves, each leaf = one
    // matrix row of `num_stripes` values with a full-height Merkle path
    // (codeword height = 2^(log_stacking + log_blowup); #57 default
    // log_blowup = 2).
    let component_openings_dummy: Vec<MerkleOpening<F, JaggedMmcs>> = vec![MerkleOpening {
        leaves: (0..num_queries)
            .map(|_| LeafOpening {
                values: vec![vec![F::ZERO; num_stripes]],
                proof: vec![[F::ZERO; 8]; log_stacking + inner_log_blowup],
            })
            .collect(),
    }];
    let bf_proof = BasefoldProof::<F, EF, JaggedMmcs> {
        univariate_messages,
        fri_commitments,
        component_polynomials_query_openings_and_proofs: component_openings_dummy,
        query_phase_openings_and_proofs,
        final_poly: EF::ZERO,
        pow_witness: F::ZERO,
        batch_grinding_witness: F::ZERO,
    };
    let stacked = StackedBasefoldProof::<F, EF, JaggedMmcs> {
        basefold_proof: bf_proof,
        batch_evaluations: vec![vec![EF::ZERO; num_stripes]],
    };

    // ── Reduction sumcheck (L rounds, degree-2 → evals=[EF;3]) ──
    let reduction = JaggedReductionProof::<EF> {
        rounds: vec![JaggedReductionRound { evals: [EF::ZERO; 3] }; l.max(1)],
        eval_point: vec![EF::ZERO; l.max(1)],
        q_at_z: EF::ZERO,
    };

    // ── Jagged-eval sub-sumcheck (n rounds, degree-2 → 3 coeffs) ──
    let jagged_eval = JaggedSumcheckEvalProof::<EF> {
        partial_sumcheck_proof: PartialSumcheckProof {
            univariate_polys: vec![
                UnivariatePolynomial { coefficients: vec![EF::ZERO; 3] };
                jagged_n
            ],
            claimed_sum: EF::ZERO,
            point_and_eval: (vec![EF::ZERO; jagged_n], EF::ZERO),
        },
    };

    JaggedBasefoldBundle {
        reduction,
        basefold_proof: stacked,
        // y_per_chip / commit.chip_dims / commit.area are NOT read by the inner
        // lift or the witness stream, so leave them empty/zero.
        y_per_chip: Vec::new(),
        commit: BasefoldLateBindingCommit {
            commitment: zero_cap(),
            // The late-binding commit is over the DENSE stacked poly as a
            // single column: chip_dims = [(width=1, log_h=log_dense_size)] (NOT
            // the per-chip dims).  The lift derives row_counts from this single
            // entry (heights = [2^log_dense_size]) when the machine passes
            // row_counts_by_round=None.  (Real fib: [(1, 27)].)
            chip_dims: vec![(1, l as u32)],
            area: 0,
            log_stacking_height: log_stacking as u32,
        },
        packing: packing_meta,
        jagged_eval,
        // Per-round split (Architecture A) is single-group (G==1) for the
        // dummy/probe path: empty extra-group Vecs + empty group map (the
        // verifier treats an empty map as the identity single-group cover).
        extra_reduction: Vec::new(),
        extra_basefold_proof: Vec::new(),
        extra_commit: Vec::new(),
        extra_packing: Vec::new(),
        extra_jagged_eval: Vec::new(),
        groups: Vec::new(),
    }
}

/// ceil(log2(n)) for `n >= 1`.  Returns 0 for n == 0 (degenerate
/// input — only reachable from probing with empty chip sets).
///
/// Mirror of slop's `log2_ceil_usize` used by SP1's dummy helpers.
#[inline]
fn log2_ceil_usize(n: usize) -> usize {
    if n <= 1 {
        return 0;
    }
    let leading = (n - 1).leading_zeros() as usize;
    (usize::BITS as usize) - leading
}

#[cfg(test)]
mod tests {
    use super::*;

    use p3_field::extension::BinomialExtensionField;
    use p3_koala_bear::KoalaBear;

    type F = KoalaBear;
    type EF = BinomialExtensionField<F, 4>;

    /// `log2_ceil_usize` matches the canonical SP1 / slop semantics
    /// across the n=0,1,2,3,4,5,8,1024 spectrum.
    #[test]
    fn log2_ceil_canonical_values() {
        assert_eq!(log2_ceil_usize(0), 0);
        assert_eq!(log2_ceil_usize(1), 0);
        assert_eq!(log2_ceil_usize(2), 1);
        assert_eq!(log2_ceil_usize(3), 2);
        assert_eq!(log2_ceil_usize(4), 2);
        assert_eq!(log2_ceil_usize(5), 3);
        assert_eq!(log2_ceil_usize(8), 3);
        assert_eq!(log2_ceil_usize(1024), 10);
    }

    /// `dummy_partial_sumcheck_proof(N, D)` emits exactly N
    /// univariate polynomials each with D+1 coefficients, and an
    /// N-dimensional point.
    #[test]
    fn partial_sumcheck_shape_matches_contract() {
        let proof: PartialSumcheckProof<EF> =
            dummy_partial_sumcheck_proof(7, 4);
        assert_eq!(proof.univariate_polys.len(), 7);
        for poly in proof.univariate_polys.iter() {
            assert_eq!(poly.coefficients.len(), 5);
            assert!(poly.coefficients.iter().all(|c| *c == EF::ZERO));
        }
        assert_eq!(proof.point_and_eval.0.len(), 7);
        assert_eq!(proof.claimed_sum, EF::ZERO);
    }

    /// Edge case: zero rounds (degenerate) produces empty vecs
    /// without panicking.
    #[test]
    fn partial_sumcheck_zero_rounds_no_panic() {
        let proof: PartialSumcheckProof<EF> =
            dummy_partial_sumcheck_proof(0, 4);
        assert_eq!(proof.univariate_polys.len(), 0);
        assert_eq!(proof.point_and_eval.0.len(), 0);
    }

    /// Height-agnostic groundwork (Stages 1-3) ROUND-TRIP: the dummy's
    /// witnessed `row_counts` / `padding_column_counts` must EQUAL the
    /// real prover's for the same chip-set shape.  Both derive from the
    /// SAME `pack_traces_jagged` packing via
    /// `derive_row_and_padding_counts`, so dummy == real by construction.
    /// The dummy packs ZERO matrices at the given dims; the "real"
    /// reference packs full-VALUE matrices at the SAME dims — the
    /// derivation is value-independent (offsets/column_counts only), so
    /// the numeric counts must match exactly.
    #[test]
    fn dummy_row_padding_counts_equal_real_prover() {
        use p3_field::PrimeCharacteristicRing;
        use p3_matrix::dense::RowMajorMatrix;
        use zkm_pcs::jagged::{derive_row_and_padding_counts, pack_traces_jagged};
        use zkm_pcs::InnerVal;

        // A representative mixed-height, mixed-width chip set
        // (name-sorted, as the packer / lift see it).
        let chip_dims: Vec<(usize, u32)> =
            vec![(3, 4), (7, 2), (1, 6), (12, 5)];
        let max_log_row_count = 6usize;

        // ── DUMMY side: derive from the dummy bundle's packing. ──
        let dummy_bundle =
            dummy_jagged_basefold_bundle(&chip_dims, max_log_row_count);
        let (dummy_rc, dummy_pcc) = derive_row_and_padding_counts(
            &dummy_bundle.packing.column_counts,
            &dummy_bundle.packing.offsets,
            dummy_bundle.packing.total_values,
        );

        // ── REAL side: pack full-VALUE matrices at the SAME dims (what
        // the real prover's host commit does), then derive identically. ──
        let real_traces: Vec<(String, RowMajorMatrix<InnerVal>)> = chip_dims
            .iter()
            .enumerate()
            .map(|(i, (w, log_h))| {
                let h = 1usize << *log_h;
                // Non-zero values: ((r*w+c) mod p) — proves value-independence.
                let vals: Vec<InnerVal> = (0..(*w * h))
                    .map(|k| InnerVal::from_u32((k as u32) % 17 + 1))
                    .collect();
                (format!("chip{i}"), RowMajorMatrix::new(vals, *w))
            })
            .collect();
        let real_packing = pack_traces_jagged::<InnerVal>(&real_traces);
        let real_column_counts: Vec<usize> = real_packing
            .chip_infos
            .iter()
            .map(|ci| ci.column_count)
            .collect();
        let (real_rc, real_pcc) = derive_row_and_padding_counts(
            &real_column_counts,
            &real_packing.offsets,
            real_packing.total_values,
        );

        // ── dummy == real on the new fields. ──
        assert_eq!(dummy_rc, real_rc, "row_counts dummy != real");
        assert_eq!(dummy_pcc, real_pcc, "padding_column_count dummy != real");
        // Sanity: row_counts ARE the chip heights, in dim order.
        let expected_heights: Vec<usize> =
            chip_dims.iter().map(|(_w, log_h)| 1usize << *log_h).collect();
        assert_eq!(dummy_rc, expected_heights, "row_counts != chip heights");
        // Sanity: padding rounds total real cols (3+7+1+12=23) up to 32 -> 9.
        assert_eq!(dummy_pcc, 32 - 23, "padding_column_count value");
    }
}
