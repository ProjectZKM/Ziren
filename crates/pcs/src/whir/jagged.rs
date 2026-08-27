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
use p3_field::{ExtensionField, PrimeCharacteristicRing, TwoAdicField};
use p3_matrix::dense::RowMajorMatrix;

use crate::basefold::mle::Mle;
use crate::basefold::stacked::interleave_multilinears_with_fixed_rate;
use crate::jagged_pcs::{
    chips_to_mles_owned, pick_log_stacking_height, JaggedChallenge, JaggedCommitGeneric,
    JaggedVal, DEFAULT_BATCH_SIZE,
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
    assert!(lsh > final_log && (lsh - final_log) % ff == 0, "lsh must fold evenly");
    let num_rounds = (lsh - final_log) / ff;
    let mut config = WhirConfig::default_whir_config();
    config.starting_ood_samples = 0; // stacked WHIR: OOD rides in round constraints
    config.starting_log_inv_rate = 1;
    config.round_parameters = (0..num_rounds)
        .map(|r| RoundConfig {
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

/// The PRODUCTION jagged-WHIR budget for a core-shard stack of height
/// `2^lsh`: the upstream production schedule mapped onto the stacked
/// three-round ff=7 structure.  Each round targets ~100 bits — queries x
/// per-query bits (the PREVIOUS codeword's log-inv-rate; ~1 bit/query at
/// the rate-1 start) plus a 16-bit query PoW grind:
///
///   round 0:  84 queries into the rate-1    stripe trees   (84 + 16)
///   round 1:  21 queries into the rate-2^-4 codeword       (84 + 16)
///   final  :  12 queries into the rate-2^-7 codeword       (84 + 16)
///
/// OOD samples are 2 per committed round (upstream production carries 2).
/// Folding PoW stays 0 like upstream production (soundness rides on the
/// query PoW).
pub fn core_whir_config(lsh: usize) -> WhirConfig {
    let mut config = whir_config_for_stack(lsh, 7, 0);
    let num_rounds = config.round_parameters.len();
    let queries = [84usize, 21, 12, 9, 9, 9, 9];
    for (r, rp) in config.round_parameters.iter_mut().enumerate() {
        rp.num_queries = queries[r.min(queries.len() - 1)];
        rp.queries_pow_bits = 16;
        rp.ood_samples = 2;
    }
    // The final queries open the LAST committed codeword (committed by
    // round num_rounds-2); its rate is that round's log_inv_rate.
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
    MT: Mmcs<JaggedVal, Commitment: Clone, ProverData<RowMajorMatrix<JaggedVal>>: 'static>
        + Clone,
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
    let prover_data = JaggedWhirProverDataGeneric::<MT> {
        stacked_data,
        chip_dims,
        area,
        log_stacking_height,
    };
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
    MT: Mmcs<JaggedVal, Commitment: Clone, ProverData<RowMajorMatrix<JaggedVal>>: 'static>
        + Clone,
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
    let stack_point: Vec<JaggedChallenge> =
        eval_point[..log_stacking_height as usize].to_vec();
    let stacked: Vec<&_> = rounds.iter().map(|r| &r.stacked_data).collect();
    prover.prove_trusted_evaluation(ef_dft, stack_point, &stacked, challenger)
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

    // Round stripe counts from the areas (the jagged layer's own metadata).
    let mut stripe_counts = Vec::with_capacity(round_areas.len());
    for &area in round_areas {
        if !area.is_multiple_of(1usize << lsh) {
            return Err(WhirVerifierError::IncorrectShape("area alignment".into()));
        }
        stripe_counts.push(area >> lsh);
    }

    // The StackingMismatch bind: the claim must equal the interpolation of the
    // flat echoed evaluations at the batch coordinates.
    let flat: Vec<JaggedChallenge> =
        proof.batch_evaluations.iter().flatten().copied().collect();
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

    let verifier =
        StackedWhirVerifier::<JaggedVal, JaggedChallenge, MT>::new(mmcs, config, log_stacking_height);
    verifier.verify_trusted_evaluation(commitments, &stripe_counts, stack_point, proof, challenger)
}
