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
use crate::whir::error::WhirVerifierError;
use crate::whir::stacked::{
    StackedWhirProof, StackedWhirProver, StackedWhirProverData, StackedWhirVerifier,
};

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

/// The jagged-WHIR schedule for a core-shard stack of height `2^lsh`, solved
/// so that the union over the transcript's components is at least 100 bits in
/// the unique-decoding regime.
///
/// The per-component target is [`per_component_target_bits`], 106 by default,
/// and 106 is chosen so that the union clears 100: a shard's transcript has
/// roughly two dozen components, and `100 + log2(24) = 104.6`.  Solving each
/// round for 100 instead would give a schedule that reads "100 bits" per round
/// and is worth 97.67 once its components are summed.
///
/// A query into a code of rate `ρ` is worth `-log2((1 + ρ)/2) < 1` bit, so a
/// round with `q` queries and `pow` bits of query grind gives
/// `q·(-log2((1 + ρ)/2)) + pow` bits.  Round `r` queries the codeword committed
/// by round `r - 1` (round 0: the stripe trees at `ρ = 2^-2`), and each round
/// commits at `ρ` three halvings below the last.  At the default target and
/// grinding the solver returns:
///
/// ```text
///   ρ = 2^-2 : 124 · 0.678072 + 22 = 106.08
///   ρ = 2^-5 :  88 · 0.955606 + 22 = 106.09
///   ρ = 2^-8 :  85 · 0.994375 + 22 = 106.52   (and every later round)
/// ```
///
/// Each count is the least integer reaching the target, so one query fewer in
/// any round falls below it.  The counts are solved rather than listed, so
/// lowering the grinding through the environment raises them instead of
/// weakening the round.  Folds are `[3, 6, 6, …]`; OOD samples 2 per committed
/// round; folding grind 0.
///
/// These are bounds on the interactive protocol.  The Fiat--Shamir compilation
/// costs a factor in the adversary's oracle queries, which no schedule here
/// buys back.
pub fn core_whir_config(lsh: usize) -> WhirConfig {
    let mut config = core_whir_config_without_batch_grind(lsh);
    config.batch_pow_bits = whir_batch_grinding_bits();
    config
}

/// Bits each transcript component is solved for.
///
/// The schedule used to target 100 bits per component, which is the
/// *minimum-component* convention: with roughly two dozen components a union
/// bound over them lands near 97.7, so a configuration that reads "100 bits"
/// per round is a sub-100-bit argument once the components are summed.  The
/// target is therefore the union goal plus the log of the component count,
/// `100 + log2(24) = 104.6`, rounded up for margin.
pub fn per_component_target_bits() -> f64 {
    crate::params::env_f64("ZIREN_SOUNDNESS_TARGET_BITS", 106.0)
}

/// Query-phase grinding, in bits.
///
/// Chosen so that retargeting costs no proof bytes: at `rho = 2^-2` a query is
/// worth 0.678 bits, so `124 · 0.678 + 22 = 106.1`, which is the same 124
/// queries the 100-bit target needed at 16 bits of grinding.  Six bits of
/// grinding buy six bits of soundness for an expected `2^22` permutations per
/// phase.
///
/// That expectation is only what the prover pays if the search is accelerated.
/// On the host it is a rayon search nested inside the per-shard parallelism
/// that already owns every core, so it is serial in practice and each bit
/// doubles it: measured on one reth block over four cards, moving the query,
/// LogUp and batching grinds to this schedule took 34.2 s to 166.2 s while the
/// grinds ran on the host, of which 123 s was the LogUp grind alone.  Buying
/// the same bits with queries instead cost 8.6%, which is the lever to reach
/// for if a prover has no accelerator registered.
pub fn query_grinding_bits() -> usize {
    crate::params::env_usize("ZIREN_WHIR_QUERY_GRINDING_BITS", 22)
}

/// Grinding bits on the stripe batching.
///
/// The batch combines every stripe of both committed rounds with the powers of
/// one challenge, `t <= 256` on a core shard, and its error is
/// `(t - 1) · L / |F|`: 94 bits at `t = 256` with no grind, which was the
/// binding term of the schedule.  Eight bits put it at 102; fourteen put it at
/// 108, above the query rounds, for one grind of `2^14` per opening.
pub fn whir_batch_grinding_bits() -> usize {
    crate::params::env_usize("ZIREN_WHIR_BATCH_GRINDING_BITS", 14)
}

/// The rate of the first committed oracle, `2^-START_LOG_INV_RATE`.
const START_LOG_INV_RATE: usize = 2;

/// The schedule at stacking height `lsh`, before the batching grind.
///
/// The query counts are solved, not listed: a round is worth
/// `q · bits_per_query(rate) + pow` bits, so listing `q` while `pow` and the
/// target are overridable would let an override weaken a round silently.  At
/// the defaults this yields the schedule it replaces, `[124, 88, 85]`.
fn core_whir_config_without_batch_grind(lsh: usize) -> WhirConfig {
    const ROUND0_FF: usize = 3;
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
    let pow = query_grinding_bits();
    for (r, rp) in config.round_parameters.iter_mut().enumerate() {
        rp.num_queries = min_queries(queried_log_inv_rate(r), pow);
        rp.queries_pow_bits = pow;
        rp.ood_samples = 2;
    }
    config.final_queries = min_queries(queried_log_inv_rate(num_rounds), pow);
    config.final_pow_bits = pow;
    config
}

/// `-log2((1 + rho)/2)`: what one shift query is worth at rate `2^-log_inv_rate`
/// in the unique-decoding regime.
pub fn bits_per_query(log_inv_rate: usize) -> f64 {
    -((1.0 + 2f64.powi(-(log_inv_rate as i32))) / 2.0).log2()
}

/// The rate of the codeword round `r` queries: round 0 queries the starting
/// rate, round `r` the rate round `r - 1` committed, and the final queries the
/// last committed round's rate.
fn queried_log_inv_rate(r: usize) -> usize {
    START_LOG_INV_RATE + 3 * r
}

/// The least query count reaching [`per_component_target_bits`] at this rate
/// with `pow` bits of grinding.
pub fn min_queries(log_inv_rate: usize, pow: usize) -> usize {
    ((per_component_target_bits() - pow as f64) / bits_per_query(log_inv_rate)).ceil() as usize
}

/// Which schedule a ring proves and verifies under.
///
/// The profile is a property of a stage's ring type
/// (`BasefoldRing::WHIR_PROFILE`), never of a proof: prover and verifier both
/// derive the schedule from their own ring and the committed stacking height,
/// so a proof cannot name a weaker schedule than the stage it claims to be.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WhirProfile {
    /// The schedule of the core shards, tuned for prover time: first rate
    /// `2^-2`, unique-decoding query accounting, folds `[3, 6, 6, …]`, no
    /// folding grind ([`core_whir_config`]).
    Core,
    /// The schedule of the recursion stages, tuned for the size of the
    /// published proof: by default first rate `2^-3`, Johnson-bound query
    /// accounting, folds `[2, 6, 6, …]`, and the folding and batching
    /// challenges ground ([`compress_whir_config`]).  Every parameter can be
    /// set for a different security requirement.
    Compress,
    /// The schedule of the Blake3 ring, the shrink proof the binary stage
    /// verifies: a low first rate, unique-decoding query accounting and no
    /// folding or query grind ([`blake3_whir_config`]).  Its prover is the
    /// host, where a grind is a serial Blake3 search, and its verifier is a
    /// Blake3 table over bits, where a query is cheap and a grind is not.
    Blake3,
}

/// The schedule of `profile` at stacking height `lsh`.
pub fn whir_config_for_profile(profile: WhirProfile, lsh: usize) -> WhirConfig {
    match profile {
        WhirProfile::Core => core_whir_config(lsh),
        WhirProfile::Compress => compress_whir_config(lsh),
        WhirProfile::Blake3 => blake3_whir_config(lsh),
    }
}

/// `log2(1/rho)` of the Blake3 schedule's first committed oracle, 3 by
/// default; bounded by the field's two-adic subgroup like the compress
/// schedule's.
pub fn blake3_log_inv_rate() -> usize {
    crate::params::env_usize("ZIREN_BLAKE3_LOG_INV_RATE", 3)
}

/// Grinding on the stripe batching of the Blake3 schedule, in bits: the one
/// grind kept, `2^14` Blake3 compressions on the host.
pub fn blake3_batch_grinding_bits() -> usize {
    crate::params::env_usize("ZIREN_BLAKE3_BATCH_GRINDING_BITS", 14)
}

/// The schedule of the Blake3 ring at stacking height `lsh`: the compress
/// schedule's folds and first rate, unique-decoding query counts solved to
/// the per-component target with no query grind, and no folding grind.
///
/// The verifier of this schedule is the binary stage's Blake3 table, where a
/// query costs Merkle paths of Blake3 compressions over bits, cheap beside
/// any grind the host prover would have to run serially.
pub fn blake3_whir_config(lsh: usize) -> WhirConfig {
    let rate = blake3_log_inv_rate();
    assert!(
        lsh + rate <= <JaggedVal as p3_field::TwoAdicField>::TWO_ADICITY,
        "blake3 schedule: the first oracle at stacking height {lsh} and rate 2^-{rate} \
         exceeds the field's two-adic subgroup",
    );
    let k0 = compress_round0_folding();
    let mut rem =
        lsh.checked_sub(k0).expect("stacking height must exceed the round-0 folding factor");
    let mut folds = alloc::vec![k0];
    while rem > 7 {
        folds.push(6);
        rem -= 6;
    }
    let mut config = whir_config_for_fold_schedule(lsh, &folds, rem);
    config.starting_log_inv_rate = rate;
    let num_rounds = config.round_parameters.len();
    for (r, rp) in config.round_parameters.iter_mut().enumerate() {
        rp.log_inv_rate = rate + 3 * (r + 1);
        rp.num_queries = min_queries(rate + 3 * r, 0);
        rp.queries_pow_bits = 0;
        rp.ood_samples = 2;
        rp.pow_bits = alloc::vec![0; rp.folding_factor];
    }
    config.final_queries = min_queries(rate + 3 * num_rounds, 0);
    config.final_pow_bits = 0;
    config.batch_pow_bits = blake3_batch_grinding_bits();
    config
}

/// `log2(1/rho)` of the compress schedule's first committed oracle, 3 by
/// default.
///
/// The first rate is bounded by the field: the first oracle is the stacked
/// polynomial encoded at `2^(lsh + rate)` points, which must fit the two-adic
/// subgroup, `2^24` for KoalaBear.  At the default stacking height of 21,
/// three is the lowest first rate the field admits.
pub fn compress_log_inv_rate() -> usize {
    crate::params::env_usize("ZIREN_COMPRESS_LOG_INV_RATE", 3)
}

/// The compress schedule's first folding factor, 2 by default.  A
/// first-round query opens one coset row of every stripe, `2^k0` elements
/// each, so halving `k0` halves the dominant term of the proof; the variables
/// move to the later rounds, whose queries are fewer.
pub fn compress_round0_folding() -> usize {
    crate::params::env_usize("ZIREN_COMPRESS_ROUND0_FOLDING", 2)
}

/// The Johnson-bound multiplicity `m` the compress schedule counts queries
/// with (BCHKS25, Theorem 4.2): the decoding radius is `1 - sqrt(rho) - eta`
/// with `eta = sqrt(rho) / (2m)`, and the list size `(m + 1/2) / sqrt(rho)`
/// enters the folding and batching terms, which is what their grinding pays
/// for.  Zero selects the unique-decoding accounting of the core schedule.
pub fn compress_johnson_m() -> usize {
    crate::params::env_usize("ZIREN_COMPRESS_JOHNSON_M", 6)
}

/// Query-phase grinding of the compress schedule, in bits.
pub fn compress_query_grinding_bits() -> usize {
    crate::params::env_usize("ZIREN_COMPRESS_QUERY_GRINDING_BITS", 26)
}

/// Grinding on every folding challenge of the compress schedule, in bits.
///
/// Under the Johnson bound the proximity-gap error of a fold carries the list
/// size, `(m + 1/2) / sqrt(rho)`, and the degree of the folded polynomial; at
/// `m = 6` and stacking height 21 the term sits near 79 bits without grinding
/// and clears the per-component target with 27.
pub fn compress_fold_grinding_bits() -> usize {
    crate::params::env_usize("ZIREN_COMPRESS_FOLD_GRINDING_BITS", 27)
}

/// Grinding on the stripe batching of the compress schedule, in bits; the
/// batching term carries the same list size as the folds.
pub fn compress_batch_grinding_bits() -> usize {
    crate::params::env_usize("ZIREN_COMPRESS_BATCH_GRINDING_BITS", 27)
}

/// What one shift query is worth at rate `2^-log_inv_rate` under the Johnson
/// bound with multiplicity `m`: the query misses a codeword at proximity
/// `1 - sqrt(rho) - eta` with probability `sqrt(rho) + eta`, `eta = sqrt(rho) / (2m)`,
/// so a query is worth `-log2(sqrt(rho) · (1 + 1/(2m)))` bits.
pub fn bits_per_query_johnson(log_inv_rate: usize, m: usize) -> f64 {
    let sqrt_rho = 2f64.powi(-(log_inv_rate as i32)).sqrt();
    -(sqrt_rho * (1.0 + 1.0 / (2.0 * m as f64))).log2()
}

/// The least query count reaching [`per_component_target_bits`] at this rate
/// under the compress schedule's accounting with `pow` bits of grinding.
pub fn min_queries_compress(log_inv_rate: usize, pow: usize) -> usize {
    let m = compress_johnson_m();
    let bits =
        if m == 0 { bits_per_query(log_inv_rate) } else { bits_per_query_johnson(log_inv_rate, m) };
    ((per_component_target_bits() - pow as f64) / bits).ceil() as usize
}

/// The size-tuned schedule of the recursion stages at stacking height `lsh`,
/// solved to the same per-component target as [`core_whir_config`].
///
/// Round `r` queries the codeword committed at `2^-(rate + 3r)`; the queries
/// of each round are the least count reaching the target under the Johnson
/// bound at [`compress_johnson_m`] with [`compress_query_grinding_bits`] of
/// grinding, every folding challenge is ground
/// [`compress_fold_grinding_bits`] and the batching challenge
/// [`compress_batch_grinding_bits`].  At the defaults and `lsh = 21`:
///
/// ```text
///   rho = 2^-3  : 58 · 1.3846 + 26 = 106.3
///   rho = 2^-6  : 28 · 2.8845 + 26 = 106.8
///   rho = 2^-9  : 19 · 4.3845 + 26 = 109.3
///   rho = 2^-12 : 14 · 5.8845 + 26 = 108.4   (final polynomial)
/// ```
///
/// against `[124, 88, 85, 85]` under the core schedule.  Folds are
/// `[2, 6, 6]` with seven final variables.
pub fn compress_whir_config(lsh: usize) -> WhirConfig {
    let rate = compress_log_inv_rate();
    assert!(
        lsh + rate <= <JaggedVal as p3_field::TwoAdicField>::TWO_ADICITY,
        "compress schedule: the first oracle at stacking height {lsh} and rate 2^-{rate} \
         exceeds the field's two-adic subgroup",
    );
    let k0 = compress_round0_folding();
    let mut rem =
        lsh.checked_sub(k0).expect("stacking height must exceed the round-0 folding factor");
    let mut folds = alloc::vec![k0];
    while rem > 7 {
        folds.push(6);
        rem -= 6;
    }
    let mut config = whir_config_for_fold_schedule(lsh, &folds, rem);
    config.starting_log_inv_rate = rate;
    let num_rounds = config.round_parameters.len();
    let pow = compress_query_grinding_bits();
    let fold_pow = compress_fold_grinding_bits();
    for (r, rp) in config.round_parameters.iter_mut().enumerate() {
        rp.log_inv_rate = rate + 3 * (r + 1);
        rp.num_queries = min_queries_compress(rate + 3 * r, pow);
        rp.queries_pow_bits = pow;
        rp.ood_samples = 2;
        rp.pow_bits = alloc::vec![fold_pow; rp.folding_factor];
    }
    config.final_queries = min_queries_compress(rate + 3 * num_rounds, pow);
    config.final_pow_bits = pow;
    config.batch_pow_bits = compress_batch_grinding_bits();
    config
}

/// Split the stacking interleave's width-`batch` stripes into width-1
/// polynomials, in the SAME flat order BaseFold's `round_batch_evaluations`
/// reports (stripe-major, then column: `eval_at` returns per-column evals).
///
/// One gather per column, the columns of an interleave in parallel: the
/// width-1 form is the one the round-0 engine and the device upload read
/// (one stripe per `Arc<Mle>`, each `2^log_stacking_height` values), so it
/// is kept as the committed representation.
fn split_stripes_to_polys(stripes: &[Arc<Mle<JaggedVal>>]) -> Vec<Arc<Mle<JaggedVal>>> {
    use p3_maybe_rayon::prelude::*;
    let mut polys = Vec::new();
    for stripe in stripes {
        let width = stripe.num_polynomials();
        let vals = stripe.guts().as_slice();
        if width <= 1 {
            polys.push(Arc::clone(stripe));
            continue;
        }
        let height = vals.len() / width;
        polys.par_extend((0..width).into_par_iter().map(|col| {
            let column: Vec<JaggedVal> = (0..height).map(|r| vals[r * width + col]).collect();
            Arc::new(Mle::from_row_major(RowMajorMatrix::new(column, 1)))
        }));
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
    commit_jagged_whir_from_stripes(
        &stripes,
        chip_dims,
        area,
        log_stacking_height,
        mmcs,
        dft,
        config,
    )
}

/// Commit an already stacked dense polynomial under jagged-WHIR: `stripes`
/// are its width-`DEFAULT_BATCH_SIZE` interleaves (column `c` of interleave
/// `i` is stripe `i · DEFAULT_BATCH_SIZE + c`), exactly what
/// `interleave_multilinears_with_fixed_rate` produces and what a BaseFold
/// stacking of the same dense keeps as its `interleaved_mles`.  A caller that
/// keeps the interleaves for the jagged reduction therefore stacks once and
/// commits once; the commitment and prover data are those of
/// [`commit_jagged_whir_generic`] over the same cells.
#[allow(clippy::type_complexity, clippy::too_many_arguments)]
pub fn commit_jagged_whir_from_stripes<MT, D>(
    stripes: &[Arc<Mle<JaggedVal>>],
    chip_dims: Vec<(usize, u32)>,
    area: usize,
    log_stacking_height: u32,
    mmcs: MT,
    dft: Arc<D>,
    config: WhirConfig,
) -> (JaggedCommitGeneric<MT>, JaggedWhirProverDataGeneric<MT>)
where
    MT: Mmcs<JaggedVal, Commitment: Clone, ProverData<RowMajorMatrix<JaggedVal>>: 'static> + Clone,
    D: TwoAdicSubgroupDft<JaggedVal> + Send + Sync,
{
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
    use super::{bits_per_query, core_whir_config, min_queries, per_component_target_bits};

    /// Every round's query count is exactly the least integer that reaches
    /// [`per_component_target_bits`] under the unique-decoding bound, at the
    /// rate of the codeword it queries: round 0 the starting rate, round `r`
    /// the rate round `r - 1` committed, the final queries the last round's
    /// rate.
    ///
    /// The comparison is self-consistency, not a fixed floor: whatever target
    /// the deployment configures, the solved schedule must reach it and must
    /// not overshoot it by a whole extra query.
    #[test]
    fn query_counts_are_the_unique_decoding_minimum() {
        for lsh in [20usize, 21, 22, 24] {
            let config = core_whir_config(lsh);
            let mut queried_rate = config.starting_log_inv_rate;
            for (r, rp) in config.round_parameters.iter().enumerate() {
                let bits = rp.num_queries as f64 * bits_per_query(queried_rate)
                    + rp.queries_pow_bits as f64;
                let target = per_component_target_bits();
                assert!(bits >= target, "lsh {lsh} round {r}: {bits} bits < {target}");
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
