//! Jagged-WHIR wiring — the WHIR siblings of `jagged_pcs`'s commit / open /
//! verify entry points, sharing the jagged layer's dense-packing, stacking
//! interleave, and claim-binding conventions so the shard prover can swap the
//! inner PCS without touching the jagged reduction above it.
//!
//! Contract parity with the BaseFold path:
//!   * commit consumes the same `chip_traces` (in production a single width-1
//!     dense polynomial), runs the same `chips_to_mles_owned` +
//!     `interleave_multilinears_with_fixed_rate` stacking, and reports the
//!     same `(chip_dims, area, log_stacking_height)` metadata;
//!   * the interleaved stripes (width `DEFAULT_BATCH_SIZE`) are split into
//!     width-1 polynomials, so a round's polynomial count is exactly
//!     `area >> log_stacking_height` — the count the stacked verifier derives
//!     from `round_areas`, and the order matches BaseFold's flat
//!     `batch_evaluations` (stripe-major, then column);
//!   * verify first checks `evaluation_claim == interpolation of the echoed
//!     evaluations at the batch coordinates` (the `StackingMismatch` bind),
//!     then runs the stacked WHIR verifier on the stack coordinates.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use p3_challenger::{CanObserve, FieldChallenger, GrindingChallenger};
use p3_commit::Mmcs;
use p3_dft::TwoAdicSubgroupDft;
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;

use crate::basefold::mle::Mle;
use crate::basefold::stacked::interleave_multilinears_with_fixed_rate;
use crate::jagged_pcs::{
    chips_to_mles_owned, pick_log_stacking_height, JaggedChallenge, JaggedCommitGeneric, JaggedVal,
    DEFAULT_BATCH_SIZE,
};
use crate::whir::config::{RoundConfig, WhirConfig};
use crate::whir::stacked::{
    StackedWhirProof, StackedWhirProver, StackedWhirProverData, StackedWhirVerifier,
};
use crate::whir::verifier::WhirVerifierError;

/// Prover-side state kept after a jagged-WHIR commit.
pub struct JaggedWhirProverDataGeneric<MT: Mmcs<JaggedVal>> {
    pub stacked_data: StackedWhirProverData<JaggedVal, MT>,
    pub chip_dims: Vec<(usize, u32)>,
    pub area: usize,
    pub log_stacking_height: u32,
}

/// The WHIR configuration for a given stacking height: fold `ff` variables a
/// round until `final_log` remain, with the upstream escalating-rate
/// schedule (round r's folded codeword commits at `1 + 3(r+1)` bits of
/// blowup — the poly shrinks `2^ff`-fold per round, so the deeper, smaller
/// codewords afford lower rates and correspondingly fewer queries).
/// Query/PoW budgets here are the TEST shape; the production budget is
/// [`core_whir_config`].
pub fn whir_config_for_stack(lsh: usize, ff: usize, final_log: usize) -> WhirConfig {
    assert!(lsh > final_log && (lsh - final_log).is_multiple_of(ff), "lsh must fold evenly");
    let num_rounds = (lsh - final_log) / ff;
    whir_config_for_fold_schedule(lsh, &alloc::vec![ff; num_rounds], final_log)
}

/// The general (per-round) fold schedule: round `r` folds `folds[r]`
/// variables; `final_log` remain for the revealed final polynomial.  Each
/// round's committed codeword packs `2^folds[r+1]` positions per Merkle leaf
/// (the NEXT round's stir fold consumes one leaf per query), so a SMALLER
/// round-0 factor shrinks round-0 query leaves — which for the stacked form
/// span EVERY stripe's coset row — without touching the round count, the
/// rate escalation, or the query budgets (all round-indexed).
pub fn whir_config_for_fold_schedule(lsh: usize, folds: &[usize], final_log: usize) -> WhirConfig {
    assert!(!folds.is_empty() && folds.iter().all(|&f| f > 0));
    assert_eq!(
        folds.iter().sum::<usize>() + final_log,
        lsh,
        "fold schedule must consume lsh exactly"
    );
    let mut config = WhirConfig::default_whir_config();
    config.starting_ood_samples = 0;
    config.starting_log_inv_rate = 1;
    config.round_parameters = folds
        .iter()
        .enumerate()
        .map(|(r, &ff)| RoundConfig {
            folding_factor: ff,
            evaluation_domain_log_size: 0,
            queries_pow_bits: 0,
            pow_bits: alloc::vec![0usize; ff],
            num_queries: 4,
            ood_samples: 1,
            log_inv_rate: 1 + 3 * (r + 1),
        })
        .collect();
    config.final_poly_log_degree = final_log;
    config.final_queries = 4;
    config.final_pow_bits = 0;
    config
}

/// The production jagged-WHIR budget for a core-shard stack of height `2^lsh`:
/// 100 bits per round in the unique-decoding regime.
///
/// A query into a code of rate `ρ` is worth `-log2((1 + ρ)/2) < 1` bit, so a
/// round with `q` queries and a 16-bit query grind gives
/// `q·(-log2((1 + ρ)/2)) + 16` bits.  Round `r` queries the codeword committed
/// by round `r - 1` (round 0: the stripe trees at `ρ = 2^-2`), and each round
/// commits at `ρ` three halvings below the last:
///
/// ```text
///   ρ = 2^-2 : 124 · 0.678072 + 16 = 100.08
///   ρ = 2^-5 :  88 · 0.955606 + 16 = 100.09
///   ρ = 2^-8 :  85 · 0.994375 + 16 = 100.52   (and every later round)
/// ```
///
/// Each count is the least integer reaching 100, so one query fewer in any
/// round is below 100 bits.  Folds are `[3, 6, 6, …]`; OOD samples 2 per
/// committed round; folding grind 0.
pub fn core_whir_config(lsh: usize) -> WhirConfig {
    let mut config = core_whir_config_without_batch_grind(lsh);
    config.batch_pow_bits = WHIR_BATCH_GRINDING_BITS;
    config
}

/// Grinding bits on the stripe batching.  The batch combines every stripe of
/// both committed rounds with the powers of one challenge, `t <= 256` on a
/// core shard, and its error is `(t - 1) · L / |F|`: 94 bits at `t = 256`
/// with no grind, which was the binding term of the schedule.  Eight bits
/// put it at 102, above the 100-bit query rounds, for `2^8` hashes per
/// opening.
pub const WHIR_BATCH_GRINDING_BITS: usize = 8;

fn core_whir_config_without_batch_grind(lsh: usize) -> WhirConfig {
    const ROUND0_FF: usize = 3;
    const START_LOG_INV_RATE: usize = 2;
    let mut rem =
        lsh.checked_sub(ROUND0_FF).expect("stacking height must exceed the round-0 folding factor");
    let mut folds = alloc::vec![ROUND0_FF];
    while rem > 6 {
        folds.push(6);
        rem -= 6;
    }
    let mut config = whir_config_for_fold_schedule(lsh, &folds, rem);
    config.starting_log_inv_rate = START_LOG_INV_RATE;
    for (r, rp) in config.round_parameters.iter_mut().enumerate() {
        rp.log_inv_rate = START_LOG_INV_RATE + 3 * (r + 1);
    }
    let num_rounds = config.round_parameters.len();
    let queries = [124usize, 88, 85, 85, 85, 85, 85];
    for (r, rp) in config.round_parameters.iter_mut().enumerate() {
        rp.num_queries = queries[r.min(queries.len() - 1)];
        rp.queries_pow_bits = 16;
        rp.ood_samples = 2;
    }
    config.final_queries = queries[(num_rounds - 1).min(queries.len() - 1)];
    config.final_pow_bits = 16;
    config
}

/// Split the stacking interleave's width-`batch` stripes into width-1
/// polynomials, in the SAME flat order BaseFold's `round_batch_evaluations`
/// reports (stripe-major, then column: `eval_at` returns per-column evals).
fn split_stripes_to_polys(stripes: Vec<Arc<Mle<JaggedVal>>>) -> Vec<Arc<Mle<JaggedVal>>> {
    let mut polys = Vec::new();
    for stripe in stripes {
        let width = stripe.num_polynomials();
        let vals = stripe.guts().as_slice();
        if width <= 1 {
            polys.push(stripe.clone());
            continue;
        }
        let height = vals.len() / width;
        for col in 0..width {
            let column: Vec<JaggedVal> = (0..height).map(|r| vals[r * width + col]).collect();
            polys.push(Arc::new(Mle::from_row_major(RowMajorMatrix::new(column, 1))));
        }
    }
    polys
}

/// Commit chip traces under jagged-WHIR.  Transcript-silent, exactly like
/// `commit_jagged_pcs_generic`: the caller owns the commitment observe.
#[allow(clippy::type_complexity)]
pub fn commit_jagged_whir_generic<MT, D>(
    chip_traces: Vec<(String, RowMajorMatrix<JaggedVal>)>,
    mmcs: MT,
    dft: Arc<D>,
    config: WhirConfig,
) -> (JaggedCommitGeneric<MT>, JaggedWhirProverDataGeneric<MT>)
where
    MT: Mmcs<JaggedVal, Commitment: Clone, ProverData<RowMajorMatrix<JaggedVal>>: 'static> + Clone,
    D: TwoAdicSubgroupDft<JaggedVal> + Send + Sync,
{
    let (mles, chip_dims) = chips_to_mles_owned(chip_traces);
    let total_entries: usize = mles.iter().map(|m| m.guts().total_len()).sum();
    let log_stacking_height = pick_log_stacking_height(total_entries);
    let area = total_entries.next_multiple_of(1usize << log_stacking_height);

    let stripes =
        interleave_multilinears_with_fixed_rate(DEFAULT_BATCH_SIZE, mles, log_stacking_height);
    let polys = split_stripes_to_polys(stripes);
    debug_assert_eq!(polys.len(), area >> log_stacking_height);

    let prover = StackedWhirProver::<JaggedVal, JaggedChallenge, MT, D>::new(
        mmcs,
        dft,
        config,
        log_stacking_height,
    );
    let stacked_data = prover.commit_stripes(polys);

    let commit = JaggedCommitGeneric::<MT> {
        original_commitment: stacked_data.commitment.clone(),
        chip_dims: chip_dims.clone(),
        area,
        log_stacking_height,
    };
    let prover_data =
        JaggedWhirProverDataGeneric::<MT> { stacked_data, chip_dims, area, log_stacking_height };
    (commit, prover_data)
}

/// ONE batched open across every round's committed data — the WHIR sibling of
/// `open_jagged_pcs_rounds_generic`.
pub fn open_jagged_whir_rounds_generic<Challenger, MT, D, EFD>(
    rounds: &[&JaggedWhirProverDataGeneric<MT>],
    eval_point: Vec<JaggedChallenge>,
    challenger: &mut Challenger,
    mmcs: MT,
    dft: Arc<D>,
    ef_dft: Arc<EFD>,
    config: WhirConfig,
) -> StackedWhirProof<JaggedVal, JaggedChallenge, MT>
where
    MT: Mmcs<JaggedVal, Commitment: Clone, ProverData<RowMajorMatrix<JaggedVal>>: 'static> + Clone,
    D: TwoAdicSubgroupDft<JaggedVal> + Send + Sync,
    EFD: TwoAdicSubgroupDft<JaggedChallenge>,
    Challenger: FieldChallenger<JaggedVal>
        + GrindingChallenger<Witness = JaggedVal>
        + CanObserve<<MT as Mmcs<JaggedVal>>::Commitment>
        + 'static,
{
    open_jagged_whir_rounds_generic_with_engine::<Challenger, MT, D, EFD>(
        rounds, eval_point, challenger, mmcs, dft, ef_dft, config, None,
    )
}

/// [`open_jagged_whir_rounds_generic`] with an optional
/// [`crate::whir::stacked::WhirRound0Engine`] carrying the
/// stacking-height-sized work (see the trait docs); `None` is the plain
/// host path.
#[allow(clippy::too_many_arguments)]
pub fn open_jagged_whir_rounds_generic_with_engine<Challenger, MT, D, EFD>(
    rounds: &[&JaggedWhirProverDataGeneric<MT>],
    eval_point: Vec<JaggedChallenge>,
    challenger: &mut Challenger,
    mmcs: MT,
    dft: Arc<D>,
    ef_dft: Arc<EFD>,
    config: WhirConfig,
    engine: Option<&mut dyn crate::whir::stacked::WhirRound0Engine<JaggedVal, JaggedChallenge, MT>>,
) -> StackedWhirProof<JaggedVal, JaggedChallenge, MT>
where
    MT: Mmcs<JaggedVal, Commitment: Clone, ProverData<RowMajorMatrix<JaggedVal>>: 'static> + Clone,
    D: TwoAdicSubgroupDft<JaggedVal> + Send + Sync,
    EFD: TwoAdicSubgroupDft<JaggedChallenge>,
    Challenger: FieldChallenger<JaggedVal>
        + GrindingChallenger<Witness = JaggedVal>
        + CanObserve<<MT as Mmcs<JaggedVal>>::Commitment>
        + 'static,
{
    let log_stacking_height = rounds[0].log_stacking_height;
    let prover = StackedWhirProver::<JaggedVal, JaggedChallenge, MT, D>::new(
        mmcs,
        dft,
        config,
        log_stacking_height,
    );
    let stack_point: Vec<JaggedChallenge> = eval_point[..log_stacking_height as usize].to_vec();
    let stacked: Vec<&_> = rounds.iter().map(|r| &r.stacked_data).collect();
    prover.prove_trusted_evaluation_with_engine(ef_dft, stack_point, &stacked, challenger, engine)
}

/// Verify a jagged-WHIR batched open: bind the claim by interpolating the
/// echoed per-polynomial evaluations at the batch coordinates (the
/// `StackingMismatch` check), then run the stacked WHIR verifier on the stack
/// coordinates.
#[allow(clippy::too_many_arguments)]
pub fn verify_jagged_whir_rounds<Challenger, MT>(
    mmcs: MT,
    config: WhirConfig,
    log_stacking_height: u32,
    commitments: &[<MT as Mmcs<JaggedVal>>::Commitment],
    round_areas: &[usize],
    point: &[JaggedChallenge],
    proof: &StackedWhirProof<JaggedVal, JaggedChallenge, MT>,
    evaluation_claim: JaggedChallenge,
    challenger: &mut Challenger,
) -> Result<(), WhirVerifierError>
where
    MT: Mmcs<JaggedVal, Commitment: Clone> + Clone,
    Challenger: FieldChallenger<JaggedVal>
        + GrindingChallenger<Witness = JaggedVal>
        + CanObserve<<MT as Mmcs<JaggedVal>>::Commitment>
        + 'static,
{
    let lsh = log_stacking_height as usize;
    if point.len() < lsh {
        return Err(WhirVerifierError::IncorrectShape("point too short".into()));
    }
    let stack_point = &point[..lsh];
    let batch_point = &point[lsh..];

    let mut stripe_counts = Vec::with_capacity(round_areas.len());
    for &area in round_areas {
        if !area.is_multiple_of(1usize << lsh) {
            return Err(WhirVerifierError::IncorrectShape("area alignment".into()));
        }
        stripe_counts.push(area >> lsh);
    }

    let flat: Vec<JaggedChallenge> = proof.batch_evaluations.iter().flatten().copied().collect();
    let mut current = flat;
    current.resize(1usize << batch_point.len(), JaggedChallenge::ZERO);
    for &r in batch_point {
        let half = current.len() / 2;
        for i in 0..half {
            let lo = current[2 * i];
            let hi = current[2 * i + 1];
            current[i] = lo + r * (hi - lo);
        }
        current.truncate(half);
    }
    if current[0] != evaluation_claim {
        return Err(WhirVerifierError::IncorrectShape("stacking mismatch".into()));
    }

    let verifier = StackedWhirVerifier::<JaggedVal, JaggedChallenge, MT>::new(
        mmcs,
        config,
        log_stacking_height,
    );
    verifier.verify_trusted_evaluation(commitments, &stripe_counts, stack_point, proof, challenger)
}

#[cfg(test)]
mod tests {
    use super::core_whir_config;

    /// `-log2((1 + ρ)/2)` for `ρ = 2^-log_inv_rate`.
    fn bits_per_query(log_inv_rate: usize) -> f64 {
        -((1.0 + 2f64.powi(-(log_inv_rate as i32))) / 2.0).log2()
    }

    /// The least `q` with `q·bits + pow >= 100`.
    fn min_queries(log_inv_rate: usize, pow_bits: usize) -> usize {
        ((100.0 - pow_bits as f64) / bits_per_query(log_inv_rate)).ceil() as usize
    }

    /// Every round's query count is exactly the least integer that reaches
    /// 100 bits under the unique-decoding bound, at the rate of the codeword
    /// it queries: round 0 the starting rate, round `r` the rate round `r - 1`
    /// committed, the final queries the last round's rate.
    #[test]
    fn query_counts_are_the_unique_decoding_minimum() {
        for lsh in [20usize, 21, 22, 24] {
            let config = core_whir_config(lsh);
            let mut queried_rate = config.starting_log_inv_rate;
            for (r, rp) in config.round_parameters.iter().enumerate() {
                let bits = rp.num_queries as f64 * bits_per_query(queried_rate)
                    + rp.queries_pow_bits as f64;
                assert!(bits >= 100.0, "lsh {lsh} round {r}: {bits} bits");
                assert_eq!(
                    rp.num_queries,
                    min_queries(queried_rate, rp.queries_pow_bits),
                    "lsh {lsh} round {r} at rate 2^-{queried_rate}",
                );
                queried_rate = rp.log_inv_rate;
            }
            assert_eq!(
                config.final_queries,
                min_queries(queried_rate, config.final_pow_bits),
                "lsh {lsh} final queries at rate 2^-{queried_rate}",
            );
        }
    }
}
