//! Zero-fill allocator for [`BasefoldShardProof`].
//!
//! Every
//! field is zero-filled — no real prove call, no AIR evaluation,
//! microseconds per invocation instead of seconds.
//!
//! # Shape mirror
//!
//! Outputs match what
//! [`zkm_pcs::shard_level::prover::prove_shard_with_data`]
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
/// * `num_variables` — number of sumcheck rounds (= number of
///   univariate polys, = dimension of `point_and_eval.0`)
/// * `degree` — per-round polynomial degree (each poly carries
///   `degree + 1` coefficients).  4 for zerocheck and 3
///   for LogUp-GKR rounds.
pub fn dummy_partial_sumcheck_proof<EF: Field + Copy + PrimeCharacteristicRing>(
    num_variables: usize,
    degree: usize,
) -> PartialSumcheckProof<EF> {
    let univariate_polys: Vec<UnivariatePolynomial<EF>> =
        (0..num_variables).map(|_| UnivariatePolynomial::new(vec![EF::ZERO; degree + 1])).collect();
    PartialSumcheckProof {
        univariate_polys,
        claimed_sum: EF::ZERO,
        point_and_eval: (vec![EF::ZERO; num_variables], EF::ZERO),
    }
}

/// Allocator for [`LogupGkrProof`] — zero-filled, structurally
/// identical to the real prover's output.
///
/// Key shape rules (must match the prover + verifier):
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
    // Both the host prover (`first_layer::generate_first_layer`) and the
    // recursion verifier (`shard_basefold.rs::chip_metadata_from_chips`) size
    // the global interaction axis as
    //   `log2_ceil(Σ chip.num_lookups())`
    // — chips pack raw-contiguously into it, with all padding in one run at
    // the trailing end.
    //
    // This dummy MUST mirror the verifier's expectation, otherwise the
    // recursion-circuit `evaluate_mle_ext` assertion at
    // `logup_gkr.rs:105` panics with `mle_evals.len() != 1 << dim`
    // during VK regen / VERIFY_VK=true.
    let total_chip_interactions: usize = chips.iter().map(|chip| chip.num_lookups()).sum();
    let log_interactions = log2_ceil_usize(total_chip_interactions);
    let output_size = 1usize << (log_interactions + 1);

    let circuit_output = LogUpGkrOutput {
        numerator: vec![EF::ZERO; output_size],
        denominator: vec![EF::ZERO; output_size],
    };

    // The GKR walk emits `log_max_row_height - 1` rounds — guard against
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
            // Round i's sumcheck has `i + log2_ceil(interactions) + 1`
            // rounds, degree 3.
            sumcheck_proof: dummy_partial_sumcheck_proof::<EF>(i + log_interactions + 1, 3),
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
                let preprocessed_width = MachineAir::<F>::preprocessed_width(*chip);
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
                        // height is carried separately by
                        // `BasefoldShardProof.chip_heights`
                        // (see [`dummy_basefold_shard_proof`]).
                        log_degree: 0,
                        // FULL-POINT openings.  The
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

    LogupGkrProof { circuit_output, round_proofs, logup_evaluations, witness: F::ZERO }
}

/// Allocator for [`BasefoldShardProof`] — zero-filled, no real
/// prove call.  Top-level entry used by
/// [`crate::stark::dummy_basefold_vk_and_shard_proof`] in place of
/// the slow `prove_shard_with_data` path.
///
/// # Inputs
///
/// * `chips` — per-chip references resolved from the input shape
///   (caller does the shape → machine.chips() join).
/// * `chip_log_heights_pairs` — per-chip (name, log_height) pairs
///   matching the shape order (shapes stay LOG-keyed).  Used to
///   populate both `chip_heights` (raw `2^log` heights) and
///   `chip_cumulative_sums` maps with one entry per chip (the
///   shape-stability invariant the parity test guards).
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
/// | `chip_heights`         | one entry per chip from input shape (raw `2^log`) |
/// | `chip_cumulative_sums` | one entry per chip (local=ZERO, global=ZERO) |
/// | `evaluation_proof`     | `EvaluationProof::Empty` — lift adapter handles the Empty arm |
pub fn dummy_basefold_shard_proof<F, EF, A>(
    chips: &[&Chip<F, A>],
    chip_log_heights_pairs: &[(String, u8)],
    max_log_row_count: usize,
    // The recursion-layer AREA PIN this dummy must mirror.
    // `Some(_)` for a RECURSION (compress) child (pinned `jagged_n` / stripes);
    // `None` for CORE/normalize (NATURAL, byte-identical).
    recursion_area_pin: Option<usize>,
) -> BasefoldShardProof<F, EF>
where
    F: Field + Copy + PrimeCharacteristicRing,
    EF: ExtensionField<F> + Copy + PrimeCharacteristicRing,
    A: MachineAir<F>,
{
    let public_values = vec![F::ZERO; PROOF_MAX_NUM_PVS];
    let main_commitment: [F; 8] = std::array::from_fn(|_| F::ZERO);

    let logup_gkr_proof = dummy_logup_gkr_proof::<F, EF, A>(chips, max_log_row_count);

    // Zerocheck rounds are degree 4 (max_log_row_count
    // rounds total).
    let zerocheck_proof = dummy_partial_sumcheck_proof::<EF>(max_log_row_count, 4);

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
        let heights_map: BTreeMap<String, u8> = chip_log_heights_pairs.iter().cloned().collect();
        let mut name_sorted: Vec<&&Chip<F, A>> = chips.iter().collect();
        name_sorted.sort_by(|a, b| MachineAir::<F>::name(**a).cmp(&MachineAir::<F>::name(**b)));
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
                // (shard_level/prover.rs:486-507).  Zeroing it would make the
                // recursion program's full_geq emit fewer ops than the
                // real-input program.
                let height: u64 = 1u64 << log_h;
                let degree_bits: Vec<EF> = (0..bit_len)
                    .map(|i| {
                        let shift = bit_len - 1 - i;
                        let bit =
                            if shift < u64::BITS as usize { (height >> shift) & 1 } else { 0 };
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
                    main: AirOpenedValues { local: vec![EF::ZERO; main_w], next: Vec::new() },
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

    // The proof carries RAW heights (the felt the prologue
    // observes); the dummy's chips sit at exactly `2^log_h`, matching the
    // `quotient[0]` degree bits above.
    let chip_heights: BTreeMap<String, usize> = chip_log_heights_pairs
        .iter()
        .map(|(name, log_h)| (name.clone(), 1usize << *log_h))
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
    let chip_cumulative_sums: BTreeMap<String, ChipCumulativeSums<F, EF>> = chips
        .iter()
        .map(|chip| {
            let name = MachineAir::<F>::name(*chip);
            // commit_scope() inspection kept here to document
            // the equivalence with the real-prover code path —
            // both arms produce the same zero digest on zero
            // traces.
            let _scope_documented = chip.commit_scope() == LookupScope::Local;
            (name, ChipCumulativeSums { local: EF::ZERO, global: SepticDigest::<F>::zero() })
        })
        .collect();

    // Build a shape-faithful jagged-basefold Bundle (zero values) so the
    // dummy's witness stream matches the real prover's byte-for-byte.  Chip
    // dims in NAME-SORTED order (matches the lift's name-sorted
    // `column_counts_by_round`); width = main trace width, height = 2^log_h.
    let evaluation_proof = {
        let heights: BTreeMap<String, u8> = chip_log_heights_pairs.iter().cloned().collect();
        let mut name_sorted: Vec<&&Chip<F, A>> = chips.iter().collect();
        name_sorted.sort_by(|a, b| MachineAir::<F>::name(**a).cmp(&MachineAir::<F>::name(**b)));
        let chip_dims: Vec<(usize, u32)> = name_sorted
            .iter()
            .map(|chip| {
                let name = MachineAir::<F>::name(**chip);
                let w = <_ as BaseAir<F>>::width(&chip.air);
                let log_h = heights.get(&name).copied().unwrap_or(0) as u32;
                (w, log_h)
            })
            .collect();
        // The PREPROCESSED round.  Its chip set is a property of the MACHINE —
        // `setup` asserts a chip generates a preprocessed trace iff
        // `preprocessed_width() > 0` — and it commits them in chip-NAME order,
        // so the same walk reproduces the committed round.  Heights are the
        // shape's: a preprocessed trace is padded to `fixed_log2_rows`, which is
        // the shape written onto the program.
        let prep_dims: Vec<(usize, u32)> = name_sorted
            .iter()
            .filter_map(|chip| {
                let w = MachineAir::<F>::preprocessed_width(**chip);
                if w == 0 {
                    return None;
                }
                let name = MachineAir::<F>::name(**chip);
                let log_h = heights.get(&name).copied().unwrap_or(0) as u32;
                Some((w, log_h))
            })
            .collect();
        zkm_pcs::shard_level::shard_proof::EvaluationProof::Bundle(dummy_jagged_basefold_bundle(
            &prep_dims,
            &chip_dims,
            max_log_row_count,
            recursion_area_pin,
        ))
    };

    // ── Dummy emits the SAME numeric row_counts / padding_column_counts
    // the real prover does for this shape, derived from the SAME jagged
    // packing (`dummy_jagged_basefold_bundle` builds it via
    // `pack_traces_jagged` on zero matrices -> exact
    // offsets/column_counts/total_values), so dummy == real on these
    // fields by construction.  PURE DATA.
    let (row_counts, padding_column_counts): (Vec<Vec<usize>>, Vec<usize>) = match &evaluation_proof
    {
        zkm_pcs::shard_level::shard_proof::EvaluationProof::Bundle(bundle) => {
            let (rc, pcc) = zkm_pcs::jagged::derive_row_and_padding_counts(
                &bundle.packing.column_counts,
                &bundle.packing.offsets,
                bundle.packing.total_values,
            );
            (vec![rc], vec![pcc])
        }
        _ => (Vec::new(), Vec::new()),
    };

    // The PREPROCESSED round's witnessed inputs.  The recursion program's read
    // count is what has to match the real proof, so the LENGTH is what matters
    // here: one height per preprocessed chip of this machine plus the round's
    // single padding column.  The VALUES are zero, like every other dummy
    // field.
    let n_prep =
        chips.iter().filter(|c| <A as MachineAir<F>>::preprocessed_width(&c.air) > 0).count();
    let preprocessed_row_counts: Vec<F> =
        if n_prep == 0 { Vec::new() } else { vec![F::ZERO; n_prep] };
    let preprocessed_original_commitment: [F; 8] = std::array::from_fn(|_| F::ZERO);
    // Each round's padding COLUMN COUNT.  A round's gap is `area - real`, with
    // `area` the committed length the prover's commit lands on
    // (`zkm_pcs::jagged::committed_dense_len`, raised to the pin floor for a
    // recursion round), split into columns no taller than the row cube.  Only
    // the LENGTH matters here — the values are witnessed from the real proof —
    // but it has to be the real count or the program lays out the wrong column
    // space.
    let cube = 1usize << max_log_row_count;
    let log_stack = zkm_pcs::jagged_pcs::DEFAULT_LOG_STACKING_HEIGHT as usize;
    let pad_columns = |real: usize, pin: Option<usize>| -> usize {
        if real == 0 {
            return 1;
        }
        let mut area = zkm_pcs::jagged::committed_dense_len(real, log_stack);
        if let Some(target) = pin {
            area = area.max(1usize << target);
        }
        area.saturating_sub(real).div_ceil(cube).max(1)
    };
    let heights_by_name: BTreeMap<String, u8> = chip_log_heights_pairs.iter().cloned().collect();
    let round_real = |preprocessed: bool| -> usize {
        chips
            .iter()
            .map(|c| {
                let w = if preprocessed {
                    <A as MachineAir<F>>::preprocessed_width(&c.air)
                } else {
                    <_ as BaseAir<F>>::width(&c.air)
                };
                let log_h =
                    heights_by_name.get(&MachineAir::<F>::name(*c)).copied().unwrap_or(0) as usize;
                w * (1usize << log_h)
            })
            .sum()
    };
    let mut padding_row_heights: Vec<Vec<F>> = Vec::new();
    if n_prep > 0 {
        // The preprocessed round is committed by `setup`, never area-pinned.
        padding_row_heights.push(vec![F::ZERO; pad_columns(round_real(true), None)]);
    }
    padding_row_heights.push(vec![F::ZERO; pad_columns(round_real(false), recursion_area_pin)]);

    #[allow(clippy::needless_update)]
    BasefoldShardProof {
        public_values,
        main_commitment,
        preprocessed_original_commitment,
        preprocessed_row_counts,
        padding_row_heights,
        logup_gkr_proof,
        zerocheck_proof,
        opened_values,
        chip_heights,
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
    // The PREPROCESSED opening round's per-chip `(preprocessed_width,
    // log_height)`, name-sorted — the order `setup` commits them in.  Empty for
    // a machine with no preprocessed chips, which is the single-round shape.
    //
    // A real proof opens preprocessed as its own round ahead of main,
    // so a dummy that models
    // one round disagrees with it on the round count, the per-round stripe
    // multiples, the concatenated column space and the reduction dimension —
    // every one of them a witness-stream LENGTH, and so a different program.
    prep_dims: &[(usize, u32)],
    chip_dims: &[(usize, u32)],
    max_log_row_count: usize,
    // The recursion-layer AREA PIN.  `Some(target_log)` when
    // this dummy mirrors a RECURSION (compress) child (pin `log_dense_size` +
    // `jagged_n` to the pinned L); `None` for CORE/normalize (NATURAL derivation,
    // byte-identical).
    recursion_area_pin: Option<usize>,
) -> zkm_pcs::jagged_pcs::jagged::JaggedBasefoldBundle {
    use p3_matrix::dense::RowMajorMatrix;
    use p3_symmetric::MerkleCap;
    use zkm_pcs::basefold::proof::{BasefoldProof, LeafOpening, MerkleOpening};
    use zkm_pcs::basefold::stacked::StackedBasefoldProof;
    use zkm_pcs::jagged::pack_traces_jagged;
    use zkm_pcs::jagged_eval_sumcheck::JaggedSumcheckEvalProof;
    use zkm_pcs::jagged_pcs::jagged::{JaggedBasefoldBundle, PackingMeta};
    use zkm_pcs::jagged_pcs::{lb_fri_config, pick_log_stacking_height, JaggedCommit, JaggedMmcs};
    use zkm_pcs::jagged_sumcheck::{JaggedReductionProof, JaggedReductionRound};
    use zkm_pcs::shard_level::types::{PartialSumcheckProof, UnivariatePolynomial};
    use zkm_pcs::{InnerChallenge, InnerVal};

    type F = InnerVal;
    type EF = InnerChallenge;
    const D: usize = 4; // InnerChallenge = BinomialExtensionField<InnerVal, 4>

    // ── Build the JAGGED shape at the PASSED per-chip heights.  In the VK
    // enumeration these are the cluster MAXIMAL-shape heights (normalize via
    // `maximal_core_shapes`, compress via `RecursionShapeConfig::allowed_shapes`),
    // so the dummy is already built at the per-chip-set cluster-max — the
    // correct, BOUNDED max (caps ≤21, never overflows num2bits).  A blanket
    // `1 << max_log_row_count` for EVERY chip would be WRONG: it would over-pad
    // the wide COMPRESS chip-set to total_values > 2^31 → the `num2bits` 31-bit
    // panic in `ZKMProver::new()`.  The real prover pads its jagged commit to
    // the SAME cluster-max via `CoreShapeConfig::find_core_shape`, so
    // vk_real == vk_dummy with the core STARK still proving at the ACTUAL
    // heights.
    //
    // pack_traces_jagged uses only height/width, so zero data gives the exact
    // offsets / total_values / log_dense_size / column_counts.
    // ── The opening ROUNDS, as the prover lays them out ──────────────────
    //
    // `prove_jagged_basefold_rounds_generic` concatenates the rounds into ONE
    // column space: each round contributes its real columns rebased onto the
    // running total, then the stacking-padding columns that close it out to its
    // committed area, and the next round starts at that area.  Mirror it
    // exactly — every length below falls out of this layout.
    let round_dims: Vec<&[(usize, u32)]> =
        if prep_dims.is_empty() { vec![chip_dims] } else { vec![prep_dims, chip_dims] };

    // pack_traces_jagged uses only height/width, so zero data gives the exact
    // offsets / total_values / column_counts for a round.
    let pack_round = |dims: &[(usize, u32)]| {
        let traces: Vec<(String, RowMajorMatrix<F>)> = dims
            .iter()
            .enumerate()
            .map(|(i, (width, log_h))| {
                let w = (*width).max(1);
                let h = 1usize << *log_h;
                (format!("chip{i}"), RowMajorMatrix::new(vec![F::ZERO; w * h], w))
            })
            .collect();
        pack_traces_jagged::<F>(&traces)
    };
    let packings: Vec<_> = round_dims.iter().map(|d| pack_round(d)).collect();

    // The batched open runs at the FIRST round's stacking height — the prover
    // reads it off `rounds[0].precomputed.prover_data`.
    let log_stacking = pick_log_stacking_height(packings[0].total_values) as usize;

    // Each round's committed area.  The preprocessed round is committed by
    // `setup` and is never area-pinned; only the main round takes the
    // RECURSION-LAYER AREA PIN.
    let areas: Vec<usize> = packings
        .iter()
        .enumerate()
        .map(|(r, pk)| {
            let mut area = zkm_pcs::jagged::committed_dense_len(pk.total_values, log_stacking);
            if r + 1 == packings.len() {
                if let Some(target) = recursion_area_pin {
                    area = area.max(1usize << target);
                }
            }
            area
        })
        .collect();

    // Walk the rounds, building the concatenated column space.
    let cube = 1usize << max_log_row_count;
    let mut offsets: Vec<usize> = Vec::new();
    let mut column_counts: Vec<usize> = Vec::new();
    let mut round_counts: Vec<Vec<(usize, usize)>> = Vec::with_capacity(packings.len());
    let mut padding_heights: Vec<Vec<usize>> = Vec::with_capacity(packings.len());
    let mut base = 0usize;
    for (pk, area) in packings.iter().zip(areas.iter()) {
        let n_cols = pk.offsets.len().saturating_sub(1);
        offsets.extend(pk.offsets.iter().take(n_cols).map(|o| o + base));
        column_counts.extend(pk.chip_infos.iter().map(|ci| ci.column_count));
        round_counts.push(pk.chip_infos.iter().map(|ci| (ci.row_count, ci.column_count)).collect());

        // The gap between the round's real cells and its committed area, split
        // into columns no taller than the row cube — ALWAYS at least one, even
        // when the round lands on a stripe boundary (the `.max(1)`).
        let pad = area.saturating_sub(pk.total_values);
        let mut this_round_pads: Vec<usize> = Vec::new();
        let mut done = 0usize;
        let mut pad_off = base + pk.total_values;
        loop {
            let h = core::cmp::min(cube, pad - done);
            this_round_pads.push(h);
            offsets.push(pad_off);
            column_counts.push(1);
            done += h;
            pad_off += h;
            if done >= pad {
                break;
            }
        }
        padding_heights.push(this_round_pads);
        base += area;
    }
    let total_values = base;
    offsets.push(total_values);

    // The rounds' areas are already carried as explicit padding columns, so the
    // concatenated instance's committed length IS its column space, and the
    // sumcheck hypercube is the power of two enclosing it.
    let log_dense_size = if total_values == 0 {
        0
    } else {
        total_values.next_power_of_two().trailing_zeros() as usize
    };
    // The commitment the bundle carries is the LAST round's, so its single
    // dense column is that round's area, not the concatenation's.
    let main_area = *areas.last().expect("at least one round");
    let main_log_dense =
        if main_area == 0 { 0 } else { main_area.next_power_of_two().trailing_zeros() as usize };

    let packing_meta = PackingMeta {
        offsets,
        total_values,
        log_dense_size,
        column_counts: column_counts.clone(),
        round_counts,
        padding_heights,
    };

    // ── Derived sub-lengths ──
    let l = log_dense_size;
    // Per-round stripe counts.  They size the batched
    // open's per-round component openings and batch evaluations.
    let round_stripes: Vec<usize> = areas.iter().map(|a| a >> log_stacking).collect();
    let inner_fri = lb_fri_config();
    let num_queries = inner_fri.num_queries;
    // The component-opening Merkle path length keys off the codeword
    // height = 2^(log_stacking + log_blowup).  At the inner
    // default this is blowup=2, so the dummy path length must track
    // the config, not a hardcoded `+1`.
    let inner_log_blowup = inner_fri.log_blowup();
    // jagged-eval sub-sumcheck dimension `jagged_n = 2*(log_m+1)`.
    //
    // RECURSION-LAYER AREA PIN: when the area pin is active,
    // the real prover's `prove_jagged_evaluation` runs the jagged-eval over the
    // PINNED dense (it sets `half = z_trace.len() + 1` where `z_trace` is the
    // reduction's eval_point of the pinned `2^log_dense_size` dense), so
    // `jagged_n = 2*(log_dense_size + 1)` regardless of the child's NATURAL
    // `total_values`.  Mirror that here (`log_m = log_dense_size`, the pinned L)
    // so the dummy child's `jagged_n` equals the real pinned child's — the LAST
    // height-dependent length, collapsing the compose VK to f(chip-set, arity).
    // CORE children (`None`) keep the NATURAL derivation (byte-identical).
    let log_m = match recursion_area_pin {
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
    // `num_variables == log_stacking`.  A `log_stacking - r` length would
    // assume `log_blowup == 1`; the inner default is
    // `log_blowup == 2`, so such a path would be ONE level too short.
    // In-circuit the path Select-loop count = `leaf.proof.len()`
    // (basefold_verifier.rs:555-561 via the lift's
    // `merkle_path_digests = leaf.proof.clone()`), so an under-count would
    // emit `log_stacking * (log_blowup-1) * num_queries` fewer Merkle
    // Select+Poseidon2 ops than the real program, diverging the normalize VK
    // from the real proof's VK.  Tracking `inner_log_blowup` keeps the dummy
    // faithful.
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
    // Component openings are WITNESSED + consumed (the
    // bound initial_eval + the component Merkle binding), so the dummy
    // must carry the shape-correct zero-filled structure: ONE ROUND PER
    // COMMITTED ROUND, `num_queries` leaves each, and a leaf = one matrix row
    // of that round's stripe count with a full-height Merkle path (codeword
    // height = 2^(log_stacking + log_blowup); default log_blowup = 2).
    let component_openings_dummy: Vec<MerkleOpening<F, JaggedMmcs>> = round_stripes
        .iter()
        .map(|stripes| MerkleOpening {
            leaves: (0..num_queries)
                .map(|_| LeafOpening {
                    values: vec![vec![F::ZERO; *stripes]],
                    proof: vec![[F::ZERO; 8]; log_stacking + inner_log_blowup],
                })
                .collect(),
        })
        .collect();
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
        // One entry per committed round, each of that round's stripe count.
        batch_evaluations: round_stripes.iter().map(|stripes| vec![EF::ZERO; *stripes]).collect(),
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
        // One claim vector per COLUMN GROUP — the real chips of every round
        // followed by that round's stacking-padding columns, each carrying one
        // claim per column (a padding column carries a single zero claim).
        y_per_chip: column_counts.iter().map(|c| vec![EF::ZERO; *c]).collect(),
        commit: JaggedCommit {
            original_commitment: zero_cap(),
            // The jagged BaseFold commit is over the DENSE stacked poly as a
            // single column: chip_dims = [(width=1, log_h)] (NOT the per-chip
            // dims).  The bundle carries the LAST round's commit, so the height
            // is that round's own committed area — not the concatenation's.
            // The lift derives row_counts from this single entry when the
            // machine passes row_counts_by_round=None.
            chip_dims: vec![(1, main_log_dense as u32)],
            area: 0,
            log_stacking_height: log_stacking as u32,
        },
        packing: packing_meta,
        jagged_eval,
        // The RAW root of every round before the last, as the prover carries
        // them.  Value-independent — only the
        // COUNT reaches the program.
        preceding_commits: (0..round_stripes.len().saturating_sub(1)).map(|_| zero_cap()).collect(),
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

    /// `log2_ceil_usize` matches the canonical ceil-log2 semantics
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
        let proof: PartialSumcheckProof<EF> = dummy_partial_sumcheck_proof(7, 4);
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
        let proof: PartialSumcheckProof<EF> = dummy_partial_sumcheck_proof(0, 4);
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
        let chip_dims: Vec<(usize, u32)> = vec![(3, 4), (7, 2), (1, 6), (12, 5)];
        let max_log_row_count = 6usize;

        // ── DUMMY side: derive from the dummy bundle's packing. ──
        let dummy_bundle = dummy_jagged_basefold_bundle(&[], &chip_dims, max_log_row_count, None);
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
                let vals: Vec<InnerVal> =
                    (0..(*w * h)).map(|k| InnerVal::from_u32((k as u32) % 17 + 1)).collect();
                (format!("chip{i}"), RowMajorMatrix::new(vals, *w))
            })
            .collect();
        let real_packing = pack_traces_jagged::<InnerVal>(&real_traces);
        // The prover does not stop at the packing: a committed round is closed
        // out to a whole number of stacking blocks by explicit padding COLUMNS,
        // each no taller than the row cube and always at least one
        // (`prove_jagged_basefold_rounds_generic`).  Those columns are part of
        // the column space the recursion lift walks, so the reference has to
        // carry them too — without them this compares against a layout no
        // prover produces.
        let log_stack = zkm_pcs::jagged_pcs::DEFAULT_LOG_STACKING_HEIGHT as usize;
        let area = zkm_pcs::jagged::committed_dense_len(real_packing.total_values, log_stack);
        let cube = 1usize << max_log_row_count;
        let mut real_column_counts: Vec<usize> =
            real_packing.chip_infos.iter().map(|ci| ci.column_count).collect();
        let mut real_offsets: Vec<usize> =
            real_packing.offsets.iter().take(real_packing.offsets.len() - 1).copied().collect();
        let pad = area.saturating_sub(real_packing.total_values);
        let mut done = 0usize;
        let mut pad_off = real_packing.total_values;
        loop {
            let h = core::cmp::min(cube, pad - done);
            real_offsets.push(pad_off);
            real_column_counts.push(1);
            done += h;
            pad_off += h;
            if done >= pad {
                break;
            }
        }
        real_offsets.push(area);
        let (real_rc, real_pcc) =
            derive_row_and_padding_counts(&real_column_counts, &real_offsets, area);

        // ── dummy == real on the new fields. ──
        assert_eq!(dummy_rc, real_rc, "row_counts dummy != real");
        assert_eq!(dummy_pcc, real_pcc, "padding_column_count dummy != real");
        // Sanity: the real chips' row counts ARE the chip heights, in dim
        // order; the padding columns follow them.
        let expected_heights: Vec<usize> =
            chip_dims.iter().map(|(_w, log_h)| 1usize << *log_h).collect();
        assert_eq!(dummy_rc[..chip_dims.len()], expected_heights[..], "row_counts != chip heights",);
    }
}
