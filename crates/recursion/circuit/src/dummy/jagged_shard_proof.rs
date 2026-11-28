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
    air::MachineAir,
    shard_level::{
        shard_proof::{FoldOrientation, JaggedShardProof},
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

/// Zero-filled zerocheck proof in the univariate-skip shape: one
/// [`SKIP_POLY_LEN`]-coefficient skip message, then `num_variables − 4`
/// degree-4 rounds; the point keeps all `num_variables` coordinates.
///
/// [`SKIP_POLY_LEN`]: zkm_pcs::shard_level::univariate_skip::SKIP_POLY_LEN
pub fn dummy_zerocheck_skip_proof<EF: Field + Copy + PrimeCharacteristicRing>(
    num_variables: usize,
) -> PartialSumcheckProof<EF> {
    use zkm_pcs::shard_level::univariate_skip::{SKIP_BITS, SKIP_POLY_LEN};
    let mut univariate_polys = vec![UnivariatePolynomial::new(vec![EF::ZERO; SKIP_POLY_LEN])];
    univariate_polys
        .extend((SKIP_BITS..num_variables).map(|_| UnivariatePolynomial::new(vec![EF::ZERO; 5])));
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
                let preprocessed_width = p3_air::BaseAir::<F>::preprocessed_width(*chip);
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
/// has, for [`crate::stark::dummy_vk_and_shard_proof`]: a program
/// build reads only the shape.
///
/// # Inputs
///
/// * `chips` — the chips of the input shape (the caller joins the shape to
///   `machine.chips()`).
/// * `chip_heights_pairs` — per chip, (name, rows): exact row counts as the
///   prover pads them (`next_multiple_of_32_rows` of the shape's rows), not
///   log2 heights. They fill `chip_heights`, one entry per chip.
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
/// | `zerocheck_proof`      | `dummy_zerocheck_skip_proof(max_log_row_count)` |
/// | `opened_values`        | one zero entry per chip, shaped as the prover's |
/// | `chip_heights`         | one entry per chip from input shape (raw `2^log`) |
/// | `evaluation_proof`     | `EvaluationProof::Empty` — lift adapter handles the Empty arm |
pub fn dummy_jagged_shard_proof<F, EF, A>(
    chips: &[&Chip<F, A>],
    chip_heights_pairs: &[(String, usize)],
    max_log_row_count: usize,
    pins: Option<zkm_pcs::jagged::RecursionPins>,
    profile: zkm_pcs::whir::jagged::WhirProfile,
    global_round: Option<&std::collections::BTreeSet<String>>,
) -> JaggedShardProof<F, EF>
where
    F: Field + Copy + PrimeCharacteristicRing,
    EF: ExtensionField<F> + Copy + PrimeCharacteristicRing,
    A: MachineAir<F>,
{
    dummy_proof_of_rounds(
        chips,
        chip_heights_pairs,
        max_log_row_count,
        pins,
        profile,
        global_round.as_slice(),
        false,
    )
}

/// A zero-filled [`JaggedShardProof`] with the shape of a global proof of
/// `views`, the views of its table slots: the views named in `slots[s]` are
/// the slot `s`, a trace round under its global-round pin
/// ([`zkm_pcs::jagged::global_round_pin`]), the last slot the main round.
/// `view_heights_pairs` holds each view's (name, rows). A global proof has
/// no public values and no preprocessed round.
pub fn dummy_global_jagged_shard_proof<F, EF, A>(
    views: &[&Chip<F, A>],
    view_heights_pairs: &[(String, usize)],
    max_log_row_count: usize,
    profile: zkm_pcs::whir::jagged::WhirProfile,
    slots: &[std::collections::BTreeSet<String>],
) -> JaggedShardProof<F, EF>
where
    F: Field + Copy + PrimeCharacteristicRing,
    EF: ExtensionField<F> + Copy + PrimeCharacteristicRing,
    A: MachineAir<F>,
{
    let (_, preceding) = slots.split_last().expect("a global proof opens at least one round");
    dummy_proof_of_rounds(
        views,
        view_heights_pairs,
        max_log_row_count,
        None,
        profile,
        &preceding.iter().collect::<Vec<_>>(),
        true,
    )
}

/// [`dummy_jagged_shard_proof`] over the trace rounds `preceding_rounds`
/// before the main round, each under its global-round pin. A global proof
/// (`global_proof`) has no public values and commits its main round under a
/// global-round pin as well.
fn dummy_proof_of_rounds<F, EF, A>(
    chips: &[&Chip<F, A>],
    chip_heights_pairs: &[(String, usize)],
    max_log_row_count: usize,
    pins: Option<zkm_pcs::jagged::RecursionPins>,
    profile: zkm_pcs::whir::jagged::WhirProfile,
    preceding_rounds: &[&std::collections::BTreeSet<String>],
    global_proof: bool,
) -> JaggedShardProof<F, EF>
where
    F: Field + Copy + PrimeCharacteristicRing,
    EF: ExtensionField<F> + Copy + PrimeCharacteristicRing,
    A: MachineAir<F>,
{
    let public_values = if global_proof { Vec::new() } else { vec![F::ZERO; PROOF_MAX_NUM_PVS] };
    let main_commitment: [F; 8] = std::array::from_fn(|_| F::ZERO);
    let chips_by_name = {
        let mut by_name: Vec<&Chip<F, A>> = chips.to_vec();
        by_name.sort_by_key(|a| MachineAir::<F>::name(*a));
        by_name
    };
    let layout = zkm_pcs::shard_level::round_layout::TraceRoundLayout::for_rounds(
        &chips_by_name,
        preceding_rounds,
    );

    let logup_gkr_proof = dummy_logup_gkr_proof::<F, EF, A>(chips, max_log_row_count);

    let zerocheck_proof = dummy_zerocheck_skip_proof::<EF>(max_log_row_count);

    let opened_values = {
        let bit_len = max_log_row_count + 1;
        let heights_map: BTreeMap<String, usize> = chip_heights_pairs.iter().cloned().collect();
        let mut name_sorted: Vec<&&Chip<F, A>> = chips.iter().collect();
        name_sorted.sort_by_key(|a| MachineAir::<F>::name(**a));
        let chips_ov: Vec<ChipOpenedValues<EF>> = name_sorted
            .iter()
            .map(|chip| {
                let prep_w = p3_air::BaseAir::<F>::preprocessed_width(**chip);
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
                    local_cumulative_sum: EF::ZERO,
                    log_degree: log_h,
                }
            })
            .collect();
        ShardOpenedValues { chips: chips_ov }
    };

    let chip_heights: BTreeMap<String, usize> =
        chip_heights_pairs.iter().map(|(name, rows)| (name.clone(), *rows)).collect();

    let evaluation_proof = {
        let heights: BTreeMap<String, usize> = chip_heights_pairs.iter().cloned().collect();
        let mut name_sorted: Vec<&&Chip<F, A>> = chips.iter().collect();
        name_sorted.sort_by_key(|a| MachineAir::<F>::name(**a));
        let round_dims = |indices: &[usize]| -> Vec<(usize, usize)> {
            indices
                .iter()
                .map(|&i| {
                    let chip = name_sorted[i];
                    let name = MachineAir::<F>::name(*chip);
                    let w = <_ as BaseAir<F>>::width(&chip.air);
                    let rows = heights.get(&name).copied().unwrap_or(0);
                    (w, rows)
                })
                .collect()
        };
        let preceding_dims: Vec<Vec<(usize, usize)>> =
            layout.preceding().iter().map(|indices| round_dims(indices)).collect();
        let chip_dims = round_dims(layout.main_indices());
        let prep_dims: Vec<(usize, usize)> = name_sorted
            .iter()
            .filter_map(|chip| {
                let w = p3_air::BaseAir::<F>::preprocessed_width(**chip);
                if w == 0 {
                    return None;
                }
                let name = MachineAir::<F>::name(**chip);
                let rows = heights.get(&name).copied().unwrap_or(0);
                Some((w, rows))
            })
            .collect();
        zkm_pcs::shard_level::shard_proof::EvaluationProof::Bundle(dummy_bundle_of_rounds(
            &prep_dims,
            &preceding_dims.iter().map(Vec::as_slice).collect::<Vec<_>>(),
            &chip_dims,
            global_proof,
            max_log_row_count,
            pins,
            profile,
        ))
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
        chips.iter().filter(|c| <A as p3_air::BaseAir<F>>::preprocessed_width(&c.air) > 0).count();
    let preprocessed_row_counts: Vec<F> =
        if n_prep == 0 { Vec::new() } else { vec![F::ZERO; n_prep] };
    let preprocessed_original_commitment: [F; 8] = std::array::from_fn(|_| F::ZERO);
    let cube = 1usize << max_log_row_count;
    let log_stack = zkm_pcs::jagged_pcs::DEFAULT_LOG_STACKING_HEIGHT as usize;
    let pad_columns = |real: usize, pin: Option<zkm_pcs::jagged::AreaPin>| -> usize {
        if let Some(pin) = pin {
            return pin.pad_columns;
        }
        zkm_pcs::jagged::unpinned_pad_columns(real, log_stack, cube)
    };
    let heights_by_name: BTreeMap<String, usize> = chip_heights_pairs.iter().cloned().collect();
    let cells = |preprocessed: bool, c: &Chip<F, A>| -> usize {
        let w = if preprocessed {
            <A as p3_air::BaseAir<F>>::preprocessed_width(&c.air)
        } else {
            <_ as BaseAir<F>>::width(&c.air)
        };
        w * heights_by_name.get(&MachineAir::<F>::name(c)).copied().unwrap_or(0)
    };
    let round_real = |indices: &[usize]| -> usize {
        indices.iter().map(|&i| cells(false, chips_by_name[i])).sum()
    };
    let mut padding_row_heights: Vec<Vec<F>> = Vec::new();
    if n_prep > 0 {
        let real = chips.iter().map(|c| cells(true, c)).sum();
        padding_row_heights.push(vec![F::ZERO; pad_columns(real, pins.map(|p| p.prep))]);
    }
    for indices in layout.preceding() {
        let real = round_real(indices);
        let pin = zkm_pcs::jagged::global_round_pin(real, log_stack, cube);
        padding_row_heights.push(vec![F::ZERO; pad_columns(real, pin)]);
    }
    let main_real = round_real(layout.main_indices());
    let main_pin = if global_proof {
        zkm_pcs::jagged::global_round_pin(main_real, log_stack, cube)
    } else {
        pins.map(|p| p.main)
    };
    padding_row_heights.push(vec![F::ZERO; pad_columns(main_real, main_pin)]);

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
        evaluation_proof,
        fold_orientation: FoldOrientation::Msb,
        row_counts,
        padding_column_counts,
        main_original_commitment: std::array::from_fn(|_| F::ZERO),
        preceding_rounds: layout
            .preceding()
            .iter()
            .map(|_| zkm_pcs::shard_level::shard_proof::TraceRoundCommitment {
                commitment: std::array::from_fn(|_| F::ZERO),
                original_commitment: std::array::from_fn(|_| F::ZERO),
            })
            .collect(),
        global_pow_witness: None,
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
/// `max_log_row_count` = M (the WHIR stacking height / verifier num_variables).
///
/// Field LENGTHS (all derived from the shape; see
/// `ref_p2c_witness_the_bundle_plan` for the full law derivation):
/// * layout via [`compute_jagged_metadata_from_dims`] (no cells allocated) → offsets,
///   total_values, log_dense_size (L), column_counts.
/// * whir proof: [`dummy_stacked_whir_proof`] under the child's WHIR
///   schedule `profile`, one batch-evaluation vector per round.
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
pub fn dummy_jagged_bundle(
    prep_dims: &[(usize, usize)],
    global_dims: &[(usize, usize)],
    chip_dims: &[(usize, usize)],
    max_log_row_count: usize,
    pins: Option<zkm_pcs::jagged::RecursionPins>,
    profile: zkm_pcs::whir::jagged::WhirProfile,
) -> zkm_pcs::jagged_pcs::jagged::JaggedPcsProof {
    dummy_bundle_of_rounds(
        prep_dims,
        &[global_dims],
        chip_dims,
        false,
        max_log_row_count,
        pins,
        profile,
    )
}

/// [`dummy_jagged_bundle`] over the trace rounds `preceding_dims` before the
/// main round, each under its global-round pin; an empty one is not
/// committed. `main_is_global` commits the main round under a global-round
/// pin as well, as a global proof does.
fn dummy_bundle_of_rounds(
    prep_dims: &[(usize, usize)],
    preceding_dims: &[&[(usize, usize)]],
    chip_dims: &[(usize, usize)],
    main_is_global: bool,
    max_log_row_count: usize,
    pins: Option<zkm_pcs::jagged::RecursionPins>,
    profile: zkm_pcs::whir::jagged::WhirProfile,
) -> zkm_pcs::jagged_pcs::jagged::JaggedPcsProof {
    use p3_symmetric::MerkleCap;
    use zkm_pcs::jagged::compute_jagged_metadata_from_dims;
    use zkm_pcs::jagged_eval_sumcheck::JaggedSumcheckEvalProof;
    use zkm_pcs::jagged_pcs::jagged::{JaggedPcsProof, PackingMeta};
    use zkm_pcs::jagged_pcs::{pick_log_stacking_height, JaggedCommit};
    use zkm_pcs::jagged_sumcheck::{JaggedReductionProof, JaggedReductionRound};
    use zkm_pcs::shard_level::types::{PartialSumcheckProof, UnivariatePolynomial};
    use zkm_pcs::{InnerChallenge, InnerVal};

    type F = InnerVal;
    type EF = InnerChallenge;

    let mut round_dims: Vec<&[(usize, usize)]> = Vec::new();
    if !prep_dims.is_empty() {
        round_dims.push(prep_dims);
    }
    let first_trace_round = round_dims.len();
    for dims in preceding_dims.iter().filter(|dims| !dims.is_empty()) {
        assert!(pins.is_none(), "a pinned machine commits no global round");
        round_dims.push(dims);
    }
    let main_round = round_dims.len();
    round_dims.push(chip_dims);
    let under_global_pin = |r: usize| {
        (first_trace_round..main_round).contains(&r) || (main_is_global && r == main_round)
    };

    let pack_round = |dims: &[(usize, usize)]| {
        let dims: Vec<(String, usize, usize)> = dims
            .iter()
            .enumerate()
            .map(|(i, (width, rows))| (format!("chip{i}"), *rows, (*width).max(1)))
            .collect();
        compute_jagged_metadata_from_dims::<F>(&dims)
    };
    let packings: Vec<_> = round_dims.iter().map(|d| pack_round(d)).collect();

    let log_stacking = pick_log_stacking_height(packings[0].total_values) as usize;

    let cube = 1usize << max_log_row_count;
    let round_pin = |r: usize, n_rounds: usize| -> Option<zkm_pcs::jagged::AreaPin> {
        if under_global_pin(r) {
            return zkm_pcs::jagged::global_round_pin(packings[r].total_values, log_stacking, cube);
        }
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
        let pad_heights: Vec<usize> = {
            let k = round_pin(r, packings.len()).map_or_else(
                || zkm_pcs::jagged::unpinned_pad_columns(pk.total_values, log_stacking, cube),
                |pin| pin.pad_columns,
            );
            zkm_pcs::jagged::AreaPin::split_padding(pad, k, cube)
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
    let whir_proof = dummy_stacked_whir_proof(log_stacking, &round_stripes, profile);

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
    profile: zkm_pcs::whir::jagged::WhirProfile,
) -> zkm_pcs::whir::stacked::StackedWhirProof<
    zkm_pcs::InnerVal,
    zkm_pcs::InnerChallenge,
    zkm_pcs::jagged_pcs::JaggedMmcs,
> {
    use p3_symmetric::MerkleCap;
    use zkm_pcs::jagged_pcs::JaggedMmcs;
    use zkm_pcs::whir::merkle::{LeafOpening, MerkleOpening};
    use zkm_pcs::whir::proof::{ProofOfWork, SumcheckPoly, WhirProof};
    use zkm_pcs::whir::stacked::StackedWhirProof;
    use zkm_pcs::{InnerChallenge, InnerVal};

    type F = InnerVal;
    type EF = InnerChallenge;
    const D: usize = zkm_recursion_core::D;

    let config = zkm_pcs::whir::jagged::whir_config_for_profile(profile, log_stacking);
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

    use p3_field::extension::QuinticTrinomialExtensionField;
    use p3_koala_bear::KoalaBear;

    type F = KoalaBear;
    type EF = QuinticTrinomialExtensionField<F>;

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
    /// SAME jagged layout via `derive_row_and_padding_counts`.  The dummy
    /// lays out the given dims alone; the "real" reference lays out
    /// full-VALUE traces at the SAME dims the way the prover does — the
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
        use zkm_pcs::jagged::{compute_jagged_metadata, derive_row_and_padding_counts};
        use zkm_pcs::InnerVal;

        let max_log_row_count = 8usize;

        let dummy_bundle = dummy_jagged_bundle(
            &[],
            &[],
            chip_dims,
            max_log_row_count,
            None,
            zkm_pcs::whir::jagged::WhirProfile::Core,
        );
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
        let real_packing = compute_jagged_metadata::<InnerVal>(
            &zkm_pcs::jagged_pcs::jagged::views_over_traces(real_traces),
        );
        let log_stack = zkm_pcs::jagged_pcs::DEFAULT_LOG_STACKING_HEIGHT as usize;
        let area = zkm_pcs::jagged::committed_dense_len(real_packing.total_values, log_stack);
        let cube = 1usize << max_log_row_count;
        let mut real_column_counts: Vec<usize> =
            real_packing.chip_infos.iter().map(|ci| ci.column_count).collect();
        let mut real_offsets: Vec<usize> =
            real_packing.offsets.iter().take(real_packing.offsets.len() - 1).copied().collect();
        let pad = area.saturating_sub(real_packing.total_values);
        let k = zkm_pcs::jagged::unpinned_pad_columns(real_packing.total_values, log_stack, cube);
        let mut pad_off = real_packing.total_values;
        for h in zkm_pcs::jagged::AreaPin::split_padding(pad, k, cube) {
            real_offsets.push(pad_off);
            real_column_counts.push(1);
            pad_off += h;
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
