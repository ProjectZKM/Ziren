//! Zero-fill allocator for [`JaggedShardProof`].
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
        shard_proof::{ChipCumulativeSums, FoldOrientation, JaggedShardProof},
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
    let total_chip_interactions: usize = chips.iter().map(|chip| chip.num_lookups()).sum();
    let log_interactions = log2_ceil_usize(total_chip_interactions);
    let output_size = 1usize << (log_interactions + 1);

    let circuit_output = LogUpGkrOutput {
        numerator: vec![EF::ZERO; output_size],
        denominator: vec![EF::ZERO; output_size],
    };

    let round_count = log_max_row_height.saturating_sub(1);
    let round_proofs: Vec<LogupGkrRoundProof<EF>> = (0..round_count)
        .map(|i| LogupGkrRoundProof {
            numerator_0: EF::ZERO,
            numerator_1: EF::ZERO,
            denominator_0: EF::ZERO,
            denominator_1: EF::ZERO,
            sumcheck_proof: dummy_partial_sumcheck_proof::<EF>(i + log_interactions + 1, 3),
        })
        .collect();

    let logup_evaluations = LogUpEvaluations {
        point: vec![EF::ZERO; log_max_row_height],
        chip_openings: chips
            .iter()
            .map(|chip| {
                let name = MachineAir::<F>::name(*chip);
                let main_width = <_ as BaseAir<F>>::width(&chip.air);
                let preprocessed_width = MachineAir::<F>::preprocessed_width(*chip);
                (
                    name,
                    ChipEvaluation {
                        log_degree: 0,
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

/// A zero-filled [`JaggedShardProof`] with the shape a real proof of `chips`
/// has, for [`crate::stark::dummy_basefold_vk_and_shard_proof`]: a program
/// build reads only the shape.
///
/// # Inputs
///
/// * `chips` — the chips of the input shape (the caller joins the shape to
///   `machine.chips()`).
/// * `chip_heights_pairs` — per chip, (name, rows): exact row counts as the
///   prover pads them (`next_multiple_of_32_rows` of the shape's rows), not
///   log2 heights. They fill `chip_heights` and `chip_cumulative_sums`, one
///   entry per chip.
/// * `max_log_row_count` — m, the cube: it sets the number of LogUp-GKR
///   rounds and of zerocheck polynomials.
/// * `pins` — the child's area pins (`StarkMachine::recursion_pins`):
///   `Some` for a compress-machine child, both rounds at a fixed area and
///   padding-column count; `None` for a core child, at natural areas.
///
/// # Field summary
///
/// | field                  | value                                  |
/// |------------------------|----------------------------------------|
/// | `public_values`        | `vec![ZERO; PROOF_MAX_NUM_PVS]`        |
/// | `main_commitment`      | `[ZERO; 8]`                            |
/// | `logup_gkr_proof`      | [`dummy_logup_gkr_proof`]              |
/// | `zerocheck_proof`      | `dummy_partial_sumcheck_proof(max_log_row_count, 4)` |
/// | `opened_values`        | one zero entry per chip, shaped as the prover's |
/// | `chip_heights`         | one entry per chip from input shape (raw `2^log`) |
/// | `chip_cumulative_sums` | one entry per chip (local=ZERO, global=ZERO) |
/// | `evaluation_proof`     | `EvaluationProof::Empty` — lift adapter handles the Empty arm |
pub fn dummy_jagged_shard_proof<F, EF, A>(
    chips: &[&Chip<F, A>],
    chip_heights_pairs: &[(String, usize)],
    max_log_row_count: usize,
    pins: Option<zkm_pcs::jagged::RecursionPins>,
) -> JaggedShardProof<F, EF>
where
    F: Field + Copy + PrimeCharacteristicRing,
    EF: ExtensionField<F> + Copy + PrimeCharacteristicRing,
    A: MachineAir<F>,
{
    let public_values = vec![F::ZERO; PROOF_MAX_NUM_PVS];
    let main_commitment: [F; 8] = std::array::from_fn(|_| F::ZERO);

    let logup_gkr_proof = dummy_logup_gkr_proof::<F, EF, A>(chips, max_log_row_count);

    let zerocheck_proof = dummy_partial_sumcheck_proof::<EF>(max_log_row_count, 4);

    let opened_values = {
        let bit_len = max_log_row_count + 1;
        let heights_map: BTreeMap<String, usize> = chip_heights_pairs.iter().cloned().collect();
        let mut name_sorted: Vec<&&Chip<F, A>> = chips.iter().collect();
        name_sorted.sort_by_key(|a| MachineAir::<F>::name(**a));
        let chips_ov: Vec<ChipOpenedValues<F, EF>> = name_sorted
            .iter()
            .map(|chip| {
                let prep_w = MachineAir::<F>::preprocessed_width(**chip);
                let main_w = <_ as BaseAir<F>>::width(&chip.air);
                let name = MachineAir::<F>::name(**chip);
                let rows = heights_map.get(&name).copied().unwrap_or(0);
                let log_h = zkm_pcs::shard_level::ceil_log2(rows);
                let height: u64 = rows as u64;
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

    let chip_heights: BTreeMap<String, usize> =
        chip_heights_pairs.iter().map(|(name, rows)| (name.clone(), *rows)).collect();

    let chip_cumulative_sums: BTreeMap<String, ChipCumulativeSums<F, EF>> = chips
        .iter()
        .map(|chip| {
            let name = MachineAir::<F>::name(*chip);
            let _scope_documented = chip.commit_scope() == LookupScope::Local;
            (name, ChipCumulativeSums { local: EF::ZERO, global: SepticDigest::<F>::zero() })
        })
        .collect();

    let evaluation_proof =
        {
            let heights: BTreeMap<String, usize> = chip_heights_pairs.iter().cloned().collect();
            let mut name_sorted: Vec<&&Chip<F, A>> = chips.iter().collect();
            name_sorted.sort_by_key(|a| MachineAir::<F>::name(**a));
            let chip_dims: Vec<(usize, usize)> = name_sorted
                .iter()
                .map(|chip| {
                    let name = MachineAir::<F>::name(**chip);
                    let w = <_ as BaseAir<F>>::width(&chip.air);
                    let rows = heights.get(&name).copied().unwrap_or(0);
                    (w, rows)
                })
                .collect();
            let prep_dims: Vec<(usize, usize)> = name_sorted
                .iter()
                .filter_map(|chip| {
                    let w = MachineAir::<F>::preprocessed_width(**chip);
                    if w == 0 {
                        return None;
                    }
                    let name = MachineAir::<F>::name(**chip);
                    let rows = heights.get(&name).copied().unwrap_or(0);
                    Some((w, rows))
                })
                .collect();
            zkm_pcs::shard_level::shard_proof::EvaluationProof::Bundle(
                dummy_jagged_basefold_bundle(&prep_dims, &chip_dims, max_log_row_count, pins),
            )
        };

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

    let n_prep =
        chips.iter().filter(|c| <A as MachineAir<F>>::preprocessed_width(&c.air) > 0).count();
    let preprocessed_row_counts: Vec<F> =
        if n_prep == 0 { Vec::new() } else { vec![F::ZERO; n_prep] };
    let preprocessed_original_commitment: [F; 8] = std::array::from_fn(|_| F::ZERO);
    let cube = 1usize << max_log_row_count;
    let log_stack = zkm_pcs::jagged_pcs::DEFAULT_LOG_STACKING_HEIGHT as usize;
    let pad_columns = |real: usize, pin: Option<zkm_pcs::jagged::AreaPin>| -> usize {
        if let Some(pin) = pin {
            return pin.pad_columns;
        }
        if real == 0 {
            return 1;
        }
        let area = zkm_pcs::jagged::committed_dense_len(real, log_stack);
        area.saturating_sub(real).div_ceil(cube).max(1)
    };
    let heights_by_name: BTreeMap<String, usize> = chip_heights_pairs.iter().cloned().collect();
    let round_real = |preprocessed: bool| -> usize {
        chips
            .iter()
            .map(|c| {
                let w = if preprocessed {
                    <A as MachineAir<F>>::preprocessed_width(&c.air)
                } else {
                    <_ as BaseAir<F>>::width(&c.air)
                };
                let rows = heights_by_name.get(&MachineAir::<F>::name(*c)).copied().unwrap_or(0);
                w * rows
            })
            .sum()
    };
    let mut padding_row_heights: Vec<Vec<F>> = Vec::new();
    if n_prep > 0 {
        padding_row_heights
            .push(vec![F::ZERO; pad_columns(round_real(true), pins.map(|p| p.prep))]);
    }
    padding_row_heights.push(vec![F::ZERO; pad_columns(round_real(false), pins.map(|p| p.main))]);

    #[allow(clippy::needless_update)]
    JaggedShardProof {
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
        fold_orientation: FoldOrientation::Msb,
        row_counts,
        padding_column_counts,
        jagged_original_commitment: std::array::from_fn(|_| F::ZERO),
    }
}

/// Build a SHAPE-FAITHFUL (zero-VALUE) [`JaggedPcsProof`] for the
/// dummy shard proof, so the witness stream the recursion program reads from a
/// dummy matches the real prover's byte-for-byte (the recursion program is now
/// value-independent — only field LENGTHS matter).  Replaces the prior
/// `EvaluationProof::Empty`, which produced a tiny zero placeholder lift and
/// made the dummy program diverge from the real one at byte 24.
///
/// `chip_dims` = per-chip `(main_width, rows)` in the SAME order the
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
///
/// `prep_dims` are the preprocessed round's per-chip (preprocessed width,
/// rows), in name order — the order `setup` commits them; empty for a machine
/// without preprocessed chips, the single-round shape. A real proof opens the
/// preprocessed round ahead of main, so a one-round dummy would differ in the
/// round count, the per-round stripe multiples, the column space and the
/// reduction dimension, every one a witness length and so a different
/// program. `pins` are the child's machine pins (`None` = natural areas): the
/// preprocessed round takes `pins.prep`, the main round `pins.main`.
pub fn dummy_jagged_basefold_bundle(
    prep_dims: &[(usize, usize)],
    chip_dims: &[(usize, usize)],
    max_log_row_count: usize,
    pins: Option<zkm_pcs::jagged::RecursionPins>,
) -> zkm_pcs::jagged_pcs::jagged::JaggedPcsProof {
    use p3_matrix::dense::RowMajorMatrix;
    use p3_symmetric::MerkleCap;
    use zkm_pcs::basefold::proof::{BasefoldProof, LeafOpening, MerkleOpening};
    use zkm_pcs::basefold::stacked::StackedBasefoldProof;
    use zkm_pcs::jagged::pack_traces_jagged;
    use zkm_pcs::jagged_eval_sumcheck::JaggedSumcheckEvalProof;
    use zkm_pcs::jagged_pcs::jagged::{JaggedPcsProof, PackingMeta};
    use zkm_pcs::jagged_pcs::{lb_fri_config, pick_log_stacking_height, JaggedCommit, JaggedMmcs};
    use zkm_pcs::jagged_sumcheck::{JaggedReductionProof, JaggedReductionRound};
    use zkm_pcs::shard_level::types::{PartialSumcheckProof, UnivariatePolynomial};
    use zkm_pcs::{InnerChallenge, InnerVal};

    type F = InnerVal;
    type EF = InnerChallenge;
    const D: usize = 4;

    let round_dims: Vec<&[(usize, usize)]> =
        if prep_dims.is_empty() { vec![chip_dims] } else { vec![prep_dims, chip_dims] };

    let pack_round = |dims: &[(usize, usize)]| {
        let traces: Vec<(String, RowMajorMatrix<F>)> = dims
            .iter()
            .enumerate()
            .map(|(i, (width, rows))| {
                let w = (*width).max(1);
                let h = *rows;
                (format!("chip{i}"), RowMajorMatrix::new(vec![F::ZERO; w * h], w))
            })
            .collect();
        pack_traces_jagged::<F>(&traces)
    };
    let packings: Vec<_> = round_dims.iter().map(|d| pack_round(d)).collect();

    let log_stacking = pick_log_stacking_height(packings[0].total_values) as usize;

    let round_pin = |r: usize, n_rounds: usize| -> Option<zkm_pcs::jagged::AreaPin> {
        let pins = pins?;
        if r + 1 == n_rounds {
            Some(pins.main)
        } else {
            Some(pins.prep)
        }
    };
    let areas: Vec<usize> = packings
        .iter()
        .enumerate()
        .map(|(r, pk)| {
            let natural = zkm_pcs::jagged::committed_dense_len(pk.total_values, log_stacking);
            match round_pin(r, packings.len()) {
                Some(pin) => pin.apply(natural),
                None => natural,
            }
        })
        .collect();

    let cube = 1usize << max_log_row_count;
    let mut offsets: Vec<usize> = Vec::new();
    let mut column_counts: Vec<usize> = Vec::new();
    let mut round_counts: Vec<Vec<(usize, usize)>> = Vec::with_capacity(packings.len());
    let mut padding_heights: Vec<Vec<usize>> = Vec::with_capacity(packings.len());
    let mut base = 0usize;
    for (r, (pk, area)) in packings.iter().zip(areas.iter()).enumerate() {
        let n_cols = pk.offsets.len().saturating_sub(1);
        offsets.extend(pk.offsets.iter().take(n_cols).map(|o| o + base));
        column_counts.extend(pk.chip_infos.iter().map(|ci| ci.column_count));
        round_counts.push(pk.chip_infos.iter().map(|ci| (ci.row_count, ci.column_count)).collect());

        let pad = area.saturating_sub(pk.total_values);
        let pad_heights: Vec<usize> = match round_pin(r, packings.len()) {
            Some(pin) => zkm_pcs::jagged::AreaPin::split_padding(pad, pin.pad_columns, cube),
            None => {
                let mut v = Vec::new();
                let mut done = 0usize;
                loop {
                    let h = core::cmp::min(cube, pad - done);
                    v.push(h);
                    done += h;
                    if done >= pad {
                        break;
                    }
                }
                v
            }
        };
        let mut this_round_pads: Vec<usize> = Vec::new();
        let mut pad_off = base + pk.total_values;
        for h in pad_heights {
            this_round_pads.push(h);
            offsets.push(pad_off);
            column_counts.push(1);
            pad_off += h;
        }
        padding_heights.push(this_round_pads);
        base += area;
    }
    let total_values = base;
    offsets.push(total_values);

    let log_dense_size = if total_values == 0 {
        0
    } else {
        total_values.next_power_of_two().trailing_zeros() as usize
    };
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

    let l = log_dense_size;
    let round_stripes: Vec<usize> = areas.iter().map(|a| a >> log_stacking).collect();
    let inner_fri = lb_fri_config();
    let num_queries = inner_fri.num_queries;
    let inner_log_blowup = inner_fri.log_blowup();
    let inner_log_folding_arity = inner_fri.log_folding_arity();
    let log_m = {
        {
            if total_values <= 1 {
                0
            } else {
                (total_values - 1).next_power_of_two().trailing_zeros() as usize
            }
        }
    };
    let jagged_n = 2 * (log_m + 1);

    let zero_cap = || MerkleCap::<F, [F; 8]>::new(vec![[F::ZERO; 8]]);

    let round_arities: Vec<usize> = {
        let k = inner_log_folding_arity.max(1);
        let mut out = Vec::new();
        let mut v = 0usize;
        while v < log_stacking {
            let g = core::cmp::min(k, log_stacking - v);
            out.push(g);
            v += g;
        }
        out
    };
    let univariate_messages: Vec<[EF; 2]> = vec![[EF::ZERO; 2]; log_stacking];
    let fri_commitments: Vec<_> = round_arities.iter().map(|_| zero_cap()).collect();
    let query_phase_openings_and_proofs: Vec<MerkleOpening<F, JaggedMmcs>> = {
        let mut consumed = 0usize;
        round_arities
            .iter()
            .map(|&arity| {
                consumed += arity;
                let path_len = log_stacking + inner_log_blowup - consumed;
                let leaves: Vec<LeafOpening<F, JaggedMmcs>> = (0..num_queries)
                    .map(|_| LeafOpening {
                        values: vec![vec![F::ZERO; (1usize << arity) * D]],
                        proof: vec![[F::ZERO; 8]; path_len],
                    })
                    .collect();
                MerkleOpening { leaves }
            })
            .collect()
    };
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
        batch_evaluations: round_stripes.iter().map(|stripes| vec![EF::ZERO; *stripes]).collect(),
    };

    let whir_mode =
        <zkm_pcs::koala_bear_poseidon2::KoalaBearPoseidon2 as zkm_pcs::BasefoldRing>::WHIR_INNER_PCS;
    let (stacked, whir_proof) = if whir_mode {
        let empty = StackedBasefoldProof::<F, EF, JaggedMmcs> {
            basefold_proof: BasefoldProof::<F, EF, JaggedMmcs> {
                univariate_messages: Vec::new(),
                fri_commitments: Vec::new(),
                component_polynomials_query_openings_and_proofs: Vec::new(),
                query_phase_openings_and_proofs: Vec::new(),
                final_poly: EF::ZERO,
                pow_witness: F::ZERO,
                batch_grinding_witness: F::ZERO,
            },
            batch_evaluations: Vec::new(),
        };
        (empty, Some(dummy_stacked_whir_proof(log_stacking, &round_stripes)))
    } else {
        (stacked, None)
    };

    let reduction = JaggedReductionProof::<EF> {
        rounds: vec![JaggedReductionRound { evals: [EF::ZERO; 3] }; l.max(1)],
        eval_point: vec![EF::ZERO; l.max(1)],
        q_at_z: EF::ZERO,
    };

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

    JaggedPcsProof {
        reduction,
        basefold_proof: stacked,
        whir_proof,
        y_per_chip: column_counts.iter().map(|c| vec![EF::ZERO; *c]).collect(),
        commit: JaggedCommit {
            original_commitment: zero_cap(),
            chip_dims: vec![(1, main_log_dense as u32)],
            area: 0,
            log_stacking_height: log_stacking as u32,
        },
        packing: packing_meta,
        jagged_eval,
        preceding_commits: (0..round_stripes.len().saturating_sub(1)).map(|_| zero_cap()).collect(),
        extra_reduction: Vec::new(),
        extra_basefold_proof: Vec::new(),
        extra_commit: Vec::new(),
        extra_packing: Vec::new(),
        extra_jagged_eval: Vec::new(),
        groups: Vec::new(),
    }
}

/// A zero-filled `StackedWhirProof` with the lengths the stacked WHIR
/// prover emits for a stack of height `2^log_stacking` whose rounds carry
/// `round_stripes` stripes each, under the production
/// [`zkm_pcs::whir::jagged::core_whir_config`] schedule.
///
/// Every length is the one
/// `StackedWhirProver::prove_trusted_evaluation_with_engine` emits; the lift
/// and `hash_stacked_whir` read all of them. With `R = round_parameters.len()`
/// and `ff_r` round r's fold:
/// * `round_sumcheck_polys[r]`, `r < R-1`: `ff_r` degree-2 polys (3 coeffs);
///   the LAST round's polys are popped into `final_sumcheck_polys`.
/// * `round_ood_answers[r]` / `round_commitments[r]`, `r < R-1`: the folded
///   poly is committed and OOD-sampled after every round but the last.
/// * `round_query_openings[r]`, `r < R-1`: `num_queries_r` queries into the
///   PREVIOUS codeword.  Round 0 opens the stripe trees: one `LeafOpening`
///   per committed round per query, holding that round's every stripe row
///   (`2^ff_0` felts, the interleave width), against the tree of height
///   `log_stacking + starting_log_inv_rate - ff_0`.  Round `r >= 1` opens the
///   single EF codeword committed by round `r-1`: one leaf of `2^ff_r * D`
///   felts against `(rem_{r-1} - ff_r) + log_inv_rate_{r-1}` levels, where
///   `rem_{r-1} = log_stacking - sum(ff_0..=ff_{r-1})`.
/// * a final `MerkleOpening` of `final_queries` leaves into the last
///   committed codeword (round `R-2`'s), same leaf/path law as round `R-1`.
/// * `final_poly`: `2^(log_stacking - sum ff)` coefficients.
/// * `folding_pow`: one per folded variable plus one query grind per
///   committed round, `sum ff + (R - 1)`.
/// * `batch_evaluations[r]`: `round_stripes[r]` claims, then one batching
///   grind witness.
fn dummy_stacked_whir_proof(
    log_stacking: usize,
    round_stripes: &[usize],
) -> zkm_pcs::whir::stacked::StackedWhirProof<
    zkm_pcs::InnerVal,
    zkm_pcs::InnerChallenge,
    zkm_pcs::jagged_pcs::JaggedMmcs,
> {
    use p3_symmetric::MerkleCap;
    use zkm_pcs::basefold::proof::{LeafOpening, MerkleOpening};
    use zkm_pcs::jagged_pcs::JaggedMmcs;
    use zkm_pcs::whir::proof::{ProofOfWork, SumcheckPoly, WhirProof};
    use zkm_pcs::whir::stacked::StackedWhirProof;
    use zkm_pcs::{InnerChallenge, InnerVal};

    type F = InnerVal;
    type EF = InnerChallenge;
    const D: usize = 4;

    let config = zkm_pcs::whir::jagged::core_whir_config(log_stacking);
    let rounds = &config.round_parameters;
    let num_rounds = rounds.len();
    let ff0 = rounds[0].folding_factor;
    let zero_cap = || MerkleCap::<F, [F; 8]>::new(vec![[F::ZERO; 8]]);
    let poly = || SumcheckPoly(vec![EF::ZERO; 3]);

    let mut round_sumcheck_polys: Vec<Vec<SumcheckPoly<EF>>> = Vec::new();
    let mut round_ood_answers: Vec<Vec<EF>> = Vec::new();
    let mut round_commitments = Vec::new();
    let mut round_query_openings: Vec<MerkleOpening<F, JaggedMmcs>> = Vec::new();
    let mut folding_pow: Vec<ProofOfWork<F>> = Vec::new();

    let mut prev_domain_log = (log_stacking - ff0) + config.starting_log_inv_rate;
    let mut prev_leaf: Option<usize> = None;
    let mut rem = log_stacking;
    for (r, rc) in rounds.iter().enumerate() {
        round_sumcheck_polys.push((0..rc.folding_factor).map(|_| poly()).collect());
        folding_pow.extend((0..rc.folding_factor).map(|_| ProofOfWork(F::ZERO)));
        rem -= rc.folding_factor;
        if r + 1 == num_rounds {
            break;
        }
        let next_ff = rounds[r + 1].folding_factor;
        round_commitments.push(zero_cap());
        round_ood_answers.push(vec![EF::ZERO; rc.ood_samples]);
        folding_pow.push(ProofOfWork(F::ZERO));
        let leaves: Vec<LeafOpening<F, JaggedMmcs>> = (0..rc.num_queries)
            .flat_map(|_| match prev_leaf {
                None => round_stripes
                    .iter()
                    .map(|stripes| LeafOpening {
                        values: vec![vec![F::ZERO; 1 << ff0]; *stripes],
                        proof: vec![[F::ZERO; 8]; prev_domain_log],
                    })
                    .collect::<Vec<_>>(),
                Some(width) => vec![LeafOpening {
                    values: vec![vec![F::ZERO; width]],
                    proof: vec![[F::ZERO; 8]; prev_domain_log],
                }],
            })
            .collect();
        round_query_openings.push(MerkleOpening { leaves });
        prev_domain_log = (rem - next_ff) + rc.log_inv_rate;
        prev_leaf = Some((1 << next_ff) * D);
    }
    let final_leaves: Vec<LeafOpening<F, JaggedMmcs>> = (0..config.final_queries)
        .flat_map(|_| match prev_leaf {
            None => round_stripes
                .iter()
                .map(|stripes| LeafOpening {
                    values: vec![vec![F::ZERO; 1 << ff0]; *stripes],
                    proof: vec![[F::ZERO; 8]; prev_domain_log],
                })
                .collect::<Vec<_>>(),
            Some(width) => vec![LeafOpening {
                values: vec![vec![F::ZERO; width]],
                proof: vec![[F::ZERO; 8]; prev_domain_log],
            }],
        })
        .collect();
    round_query_openings.push(MerkleOpening { leaves: final_leaves });
    let final_sumcheck_polys = round_sumcheck_polys.pop().unwrap_or_default();

    StackedWhirProof {
        whir_proof: WhirProof {
            round_sumcheck_polys,
            round_ood_answers,
            round_commitments,
            round_query_openings,
            final_poly: vec![EF::ZERO; 1 << rem],
            final_sumcheck_polys,
            folding_pow,
            final_pow: ProofOfWork(F::ZERO),
        },
        batch_evaluations: round_stripes.iter().map(|s| vec![EF::ZERO; *s]).collect(),
        batch_grinding_witness: F::ZERO,
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
        check_row_padding_counts(&[(3, 16), (7, 4), (1, 64), (12, 32)]);
        check_row_padding_counts(&[(3, 96), (7, 32), (1, 160), (12, 224)]);
    }

    fn check_row_padding_counts(chip_dims: &[(usize, usize)]) {
        use p3_field::PrimeCharacteristicRing;
        use p3_matrix::dense::RowMajorMatrix;
        use zkm_pcs::jagged::{derive_row_and_padding_counts, pack_traces_jagged};
        use zkm_pcs::InnerVal;

        let max_log_row_count = 8usize;

        let dummy_bundle = dummy_jagged_basefold_bundle(&[], chip_dims, max_log_row_count, None);
        let (dummy_rc, dummy_pcc) = derive_row_and_padding_counts(
            &dummy_bundle.packing.column_counts,
            &dummy_bundle.packing.offsets,
            dummy_bundle.packing.total_values,
        );

        let real_traces: Vec<(String, RowMajorMatrix<InnerVal>)> = chip_dims
            .iter()
            .enumerate()
            .map(|(i, (w, rows))| {
                let h = *rows;
                let vals: Vec<InnerVal> =
                    (0..(*w * h)).map(|k| InnerVal::from_u32((k as u32) % 17 + 1)).collect();
                (format!("chip{i}"), RowMajorMatrix::new(vals, *w))
            })
            .collect();
        let real_packing = pack_traces_jagged::<InnerVal>(&real_traces);
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

        assert_eq!(dummy_rc, real_rc, "row_counts dummy != real");
        assert_eq!(dummy_pcc, real_pcc, "padding_column_count dummy != real");
        let expected_heights: Vec<usize> = chip_dims.iter().map(|(_w, rows)| *rows).collect();
        assert_eq!(dummy_rc[..chip_dims.len()], expected_heights[..], "row_counts != chip heights",);
    }
}
