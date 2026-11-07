//! The zero-knowledge stacked WHIR opening (feature `zk`): what the zk
//! shrink ring ([`crate::zk::KoalaBearPoseidon2ZkShrink`]) commits, opens
//! and verifies in place of [`super::stacked`].
//!
//! The plain stacked open is not hiding: it echoes every stripe's evaluation
//! at the stack point, opens raw stripe rows under unsalted Merkle leaves,
//! and every folded polynomial, out-of-domain answer, stir value and sumcheck
//! message it sends is a linear functional of the committed cells.  The zk
//! opening changes four things, all inside the opening of one ring, so that
//! the transcript carries nothing about the committed cells beyond the
//! evaluation claim the jagged layer reduces to:
//!
//! * **padded stripes** — a round's stripes are committed over
//!   `lsh + ZK_PAD_VARS` variables: the stripe the jagged layer stacked in the
//!   lower half (top variable `0`) and, on the main round, uniformly random
//!   cells in the upper half.  The stripe's evaluation at `(sp, 0)` is the
//!   evaluation at `sp` the jagged layer expects, and each row of its codeword
//!   the queries open is a full-rank linear image of the random half (every
//!   column of the interleaved encoding has a contiguous block of random
//!   coefficients, so its revealed evaluations form a Vandermonde system in
//!   them), hence uniform.  The preprocessed round pads with zeros: the key
//!   commits it and must stay deterministic, and its cells are public.
//! * **a random stripe** — the main round commits one extra, uniformly random
//!   stripe `R` that the jagged polynomial does not cover.  It enters the
//!   batched polynomial with the coefficient `μ·λ^k` of its position, so the
//!   batched polynomial is uniform and so is everything WHIR derives from it:
//!   the folds, the out-of-domain answers, the stir values, the final
//!   polynomial.
//! * **the claim funnel** — instead of echoing every stripe's evaluation the
//!   prover sends ONE value `c = Σ_j λ^j e_j` over every stripe (`R`
//!   included, `λ` drawn first); the verifier draws `μ` and runs WHIR on
//!   `G = Σ_j (eq(bp, j) + μ λ^j)·S_j` under the claim `v + μ c`, with `v`
//!   its own jagged evaluation claim and `eq(bp, j) = 0` for `R`.  A wrong
//!   `v` or `c` survives the affine check in `μ` with probability `1/|EF|`,
//!   on top of the batching error the `λ` powers already carry.
//! * **salted leaves** — the main round's Merkle tree hashes one extra
//!   matrix of `ZK_SALT_WIDTH` uniformly random cells into every leaf, so the
//!   sibling digests of an opened path reveal nothing of the rows they hash.
//!
//! * **the sumcheck masks** — the top [`ZK_MASK_CELLS`] cells of `R` are read
//!   as the coefficients of two [`LibraMask`]s, the zerocheck's and the
//!   jagged reduction's ([`crate::zk_mask`]); every other main stripe is
//!   zero there, the preprocessed round anyway.  The opening sends each
//!   mask's value at its point (`g(z)` at the zerocheck's reduced point,
//!   `h(z*)` at the WHIR point) next to the funnelled claim, and the verifier
//!   folds `μ²·w_g + μ³·w_h` into the weight, where `w_g` is the sparse
//!   public functional with `g(z)` at `R`'s mask cells and zero elsewhere:
//!   `Σ_x w_g(x)·G(x) = μλ^k·g(z)` because the other stripes vanish on the
//!   support.  Each support point is one Lagrange constraint of the final
//!   check.  The verifier compares the two values with what the masked
//!   sumchecks left over (`ρ·g(z)` and `ρ'·h(z*)`, [`ZkMaskClaims`]).
//!
//! The schedule is the shrink schedule one variable wider
//! ([`super::jagged::zk_shrink_whir_config`]); the funnelled claim and the
//! two mask values travel in [`StackedWhirProof::batch_evaluations`] as one
//! round of three values, so the proof and bundle types are those of every
//! other ring.  Nothing here runs on a device: the zk shrink is one small
//! terminal proof.

use alloc::sync::Arc;
use alloc::vec::Vec;

use p3_challenger::{CanObserve, FieldChallenger, GrindingChallenger};
use p3_commit::Mmcs;
use p3_dft::TwoAdicSubgroupDft;
use p3_field::{BasedVectorSpace, PrimeCharacteristicRing, PrimeField32, TwoAdicField};
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

use crate::config::WhirRing;
use crate::jagged_pcs::jagged::{ChipTraceView, PrecomputedJaggedCommitGeneric};
use crate::jagged_pcs::{JaggedChallenge, JaggedCommitGeneric, JaggedDft, JaggedVal};
use crate::whir::config::WhirConfig;
use crate::whir::error::WhirVerifierError;
use crate::whir::jagged::{split_stripes_to_polys, JaggedWhirProverDataGeneric};
use crate::whir::merkle::{LeafOpening, MerkleOpening};
use crate::whir::mle::Mle;
use crate::whir::monomial::{map_to_pow_lsb, mono_eval_lsb};
use crate::whir::proof::{ProofOfWork, WhirProof};
use crate::whir::stacked::{
    eq_weighted_sum, lambda_combination, StackedWhirProof, StackedWhirProver, StackedWhirProverData,
};
use crate::whir::sumcheck::{eq_table, WhirFolder};
use crate::zk_mask::{
    mask_cells, opening_weights, LibraMask, ZkMaskClaims, JAGGED_MASK_DEGREE, ZEROCHECK_MASK_DEGREE,
};

type F = JaggedVal;
type EF = JaggedChallenge;

/// The dimension of `EF` over `F`.
const EF_DIM: usize = <EF as BasedVectorSpace<F>>::DIMENSION;

fn ef_from_base(coefficients: &[F]) -> EF {
    <EF as BasedVectorSpace<F>>::from_basis_coefficients_iter(coefficients.iter().copied())
        .expect("one extension element per EF_DIM base coefficients")
}

/// Variables a zk stripe has beyond the jagged stacking height: one, so the
/// random padding is the upper half of every committed stripe.
pub const ZK_PAD_VARS: usize = 1;

/// Random cells hashed into every leaf of the main round's Merkle tree:
/// eight KoalaBear elements, 248 bits of salt, one round-0 query row wide.
pub const ZK_SALT_WIDTH: usize = 8;

/// Cells at the top of the random stripe that hold the sumcheck masks: the
/// zerocheck's coefficients, then the jagged reduction's.  Every other
/// stripe of the main round is zero on these cells.
pub const ZK_MASK_CELLS: usize =
    mask_cells(ZEROCHECK_MASK_DEGREE, EF_DIM) + mask_cells(JAGGED_MASK_DEGREE, EF_DIM);

/// The offsets of the zerocheck mask and of the jagged mask inside a padded
/// stripe of `padded_len` cells.
fn mask_offsets(padded_len: usize) -> (usize, usize) {
    assert!(padded_len >= ZK_MASK_CELLS, "zk stripes of {padded_len} cells cannot hold the masks");
    let zerocheck = padded_len - ZK_MASK_CELLS;
    (zerocheck, zerocheck + mask_cells(ZEROCHECK_MASK_DEGREE, EF_DIM))
}

/// The committed cells of the two masks of a main round: the zerocheck's
/// and the jagged reduction's, read off the random stripe.
pub fn zk_mask_cells<MT: Mmcs<F>>(data: &JaggedWhirProverDataGeneric<MT>) -> (&[F], &[F]) {
    let lsh = data.log_stacking_height as usize;
    assert_eq!(
        data.stacked_data.stripes.len(),
        (data.area >> lsh) + 1,
        "zk masks: the round carries no random stripe"
    );
    let random = data.stacked_data.stripes.last().expect("a random stripe").guts().as_slice();
    let (zerocheck, jagged) = mask_offsets(random.len());
    (&random[zerocheck..jagged], &random[jagged..])
}

/// The two masks of a main round, zerocheck's then jagged reduction's.
pub fn zk_masks<MT: Mmcs<F>>(
    data: &JaggedWhirProverDataGeneric<MT>,
) -> (LibraMask<EF>, LibraMask<EF>) {
    let (zerocheck, jagged) = zk_mask_cells(data);
    (
        LibraMask::from_cells(zerocheck, ZEROCHECK_MASK_DEGREE),
        LibraMask::from_cells(jagged, JAGGED_MASK_DEGREE),
    )
}

/// The boolean point of cell `index` over `n` variables, LSB first, as the
/// Lagrange constraints of the final check take it.
fn boolean_point(index: usize, n: usize) -> Vec<EF> {
    (0..n).map(|j| if (index >> j) & 1 == 1 { EF::ONE } else { EF::ZERO }).collect()
}

/// `n` uniformly random field elements from `rng`, filled in parallel from
/// per-block seeds drawn serially, so the cells are a function of `rng`
/// alone.
fn random_cells(rng: &mut StdRng, n: usize) -> Vec<F> {
    use p3_maybe_rayon::prelude::*;
    const BLOCK: usize = 1 << 16;
    let seeds: Vec<[u8; 32]> = (0..n.div_ceil(BLOCK)).map(|_| rng.gen()).collect();
    let mut out = alloc::vec![F::ZERO; n];
    out.par_chunks_mut(BLOCK).zip(seeds.into_par_iter()).for_each(
        |(block, seed): (&mut [F], _)| {
            let mut block_rng = StdRng::from_seed(seed);
            for cell in block.iter_mut() {
                *cell = F::from_u32(block_rng.gen_range(0..F::ORDER_U32));
            }
        },
    );
    out
}

/// The stack point of a zk opening: the jagged stack point with the padding
/// variables at zero, which selects the lower, data-carrying half of every
/// stripe.
fn zk_stack_point(stack_point: &[EF]) -> Vec<EF> {
    let mut point = stack_point.to_vec();
    point.resize(stack_point.len() + ZK_PAD_VARS, EF::ZERO);
    point
}

/// The stripes of a zk opening, per round: the stripes the jagged polynomial
/// covers (`area >> lsh`), plus the random stripe on the main (last) round.
struct ZkLayout {
    covered: Vec<usize>,
}

impl ZkLayout {
    fn new(covered: Vec<usize>) -> Self {
        assert!(!covered.is_empty(), "zk opening: no rounds");
        Self { covered }
    }

    fn main(&self) -> usize {
        self.covered.len() - 1
    }

    /// Stripes committed in round `r`.
    fn stripes(&self, r: usize) -> usize {
        self.covered[r] + usize::from(r == self.main())
    }

    /// Does round `r`'s tree carry the salt matrix?
    fn salted(&self, r: usize) -> bool {
        r == self.main()
    }

    fn total_covered(&self) -> usize {
        self.covered.iter().sum()
    }

    /// The batching coefficient of every stripe, per round, in commit order:
    /// `eq(bp, j) + μ λ^k` for the `j`-th covered stripe at position `k`,
    /// `μ λ^k` for the random stripe.
    fn coefficients(&self, eq_bp: &[EF], lambda: EF, mu: EF) -> Vec<Vec<EF>> {
        let mut lam = EF::ONE;
        let mut j = 0usize;
        (0..self.covered.len())
            .map(|r| {
                (0..self.stripes(r))
                    .map(|i| {
                        let covered = i < self.covered[r];
                        let g = if covered { eq_bp[j] + mu * lam } else { mu * lam };
                        j += usize::from(covered);
                        lam *= lambda;
                        g
                    })
                    .collect()
            })
            .collect()
    }
}

/// `Σ_j λ^j e_j` over every stripe of every round, in commit order.
fn funnel(evaluations: &[Vec<EF>], lambda: EF) -> EF {
    let mut c = EF::ZERO;
    let mut lam = EF::ONE;
    for e in evaluations.iter().flatten() {
        c += lam * *e;
        lam *= lambda;
    }
    c
}

/// Commit one round of the zk ring over the jagged layer's stripes (the
/// `DEFAULT_BATCH_SIZE`-wide interleaves of one dense polynomial of `area`
/// cells, as [`super::jagged::commit_jagged_whir_from_stripes`] takes
/// them).  Every stripe is padded to `lsh + ZK_PAD_VARS` variables; a `main`
/// round pads with fresh randomness, appends the random stripe and salts its
/// leaves, a preprocessed round pads with zeros and is deterministic.
///
/// The commit's `area` and `log_stacking_height` stay the jagged layer's:
/// the padding is the opening's business, and the verifier derives the
/// committed stripe count from the area alone.
#[allow(clippy::too_many_arguments, clippy::type_complexity)]
pub fn commit_zk_whir_round<MT, D>(
    stripes: &[Arc<Mle<F>>],
    chip_dims: Vec<(usize, u32)>,
    area: usize,
    log_stacking_height: u32,
    mmcs: MT,
    dft: Arc<D>,
    config: WhirConfig,
    main: bool,
) -> (JaggedCommitGeneric<MT>, JaggedWhirProverDataGeneric<MT>)
where
    MT: Mmcs<F, Commitment: Clone, ProverData<RowMajorMatrix<F>>: 'static> + Clone,
    D: TwoAdicSubgroupDft<F> + Send + Sync,
{
    let lsh = log_stacking_height as usize;
    let polys = split_stripes_to_polys(stripes);
    assert_eq!(
        polys.len(),
        area >> lsh,
        "zk commit: {} stripes for an area of {area} cells at height 2^{lsh}",
        polys.len(),
    );
    let stripe_len = 1usize << lsh;
    let padded_len = stripe_len << ZK_PAD_VARS;
    assert!(
        ZK_MASK_CELLS <= padded_len - stripe_len,
        "zk commit: the masks ({ZK_MASK_CELLS} cells) do not fit the random half of a stripe"
    );
    let mut rng = main.then(StdRng::from_entropy);
    let mut padded: Vec<Arc<Mle<F>>> = polys
        .iter()
        .map(|poly| {
            let cells = poly.guts().as_slice();
            assert_eq!(cells.len(), stripe_len, "zk commit: a stripe of {} cells", cells.len());
            let mut stripe = Vec::with_capacity(padded_len);
            stripe.extend_from_slice(cells);
            match rng.as_mut() {
                Some(rng) => {
                    stripe.extend(random_cells(rng, padded_len - stripe_len));
                    stripe[mask_offsets(padded_len).0..].fill(F::ZERO);
                }
                None => stripe.resize(padded_len, F::ZERO),
            }
            Arc::new(Mle::from_values(stripe))
        })
        .collect();
    if let Some(rng) = rng.as_mut() {
        padded.push(Arc::new(Mle::from_values(random_cells(rng, padded_len))));
    }

    let prover =
        StackedWhirProver::<F, EF, MT, D>::new(mmcs, dft, config, (lsh + ZK_PAD_VARS) as u32);
    let mut matrices: Vec<RowMajorMatrix<F>> =
        padded.iter().map(|stripe| prover.encode_stripe(stripe)).collect();
    if let Some(rng) = rng.as_mut() {
        let height = matrices[0].height();
        matrices
            .push(RowMajorMatrix::new(random_cells(rng, height * ZK_SALT_WIDTH), ZK_SALT_WIDTH));
    }
    let (commitment, prover_data) = prover.mmcs.commit(matrices);
    let stacked_data =
        StackedWhirProverData { stripes: padded, prover_data, commitment: commitment.clone() };
    let commit = JaggedCommitGeneric::<MT> {
        original_commitment: commitment,
        chip_dims: chip_dims.clone(),
        area,
        log_stacking_height,
    };
    let whir_data =
        JaggedWhirProverDataGeneric::<MT> { stacked_data, chip_dims, area, log_stacking_height };
    (commit, whir_data)
}

/// [`crate::config::commit_multilinears_default`] with the round committed
/// by [`commit_zk_whir_round`]: the zk ring's `commit_multilinears` (`main =
/// false`, the preprocessed round) and `commit_main_multilinears` (`main =
/// true`).
pub fn commit_multilinears_zk<R: WhirRing>(
    chip_traces: &[ChipTraceView],
    pin: Option<crate::jagged::AreaPin>,
    main: bool,
) -> PrecomputedJaggedCommitGeneric<R::WhirMmcs> {
    let input = crate::config::jagged_commit_input(chip_traces, pin);
    let cfg = R::whir_config(input.log_stacking_height as usize);
    let (commit, whir_data) = commit_zk_whir_round::<R::WhirMmcs, JaggedDft>(
        &input.interleaved_mles,
        input.chip_dims.clone(),
        input.area,
        input.log_stacking_height,
        R::whir_mmcs(),
        Arc::new(JaggedDft::default()),
        cfg,
        main,
    );
    let prover_data = crate::jagged_pcs::JaggedProverData::new(
        input.interleaved_mles,
        input.chip_dims,
        input.area,
        input.log_stacking_height,
    );
    PrecomputedJaggedCommitGeneric {
        packing: input.packing,
        commit,
        prover_data,
        whir_data,
        fixed_pad_columns: pin.map(|p| p.pad_columns),
    }
}

/// The zk sibling of [`super::jagged::open_jagged_whir_rounds_generic`]:
/// one batched opening of every round committed by
/// [`commit_zk_whir_round`] at `eval_point` (stack coordinates first, then
/// the batch coordinates), under `config`, the schedule over `lsh +
/// ZK_PAD_VARS` variables.  The transcript is the module's: batch grind,
/// `λ`, the funnelled claim and (with `zerocheck_point`) the two mask
/// values, `μ`, then the WHIR rounds of the stacked open.
///
/// `zerocheck_point`: the point the zerocheck mask is opened at; the jagged
/// mask is opened at `eval_point`.  `None` opens without masks (one funnelled
/// value), as the unit tests of the opening do.
#[allow(clippy::too_many_arguments)]
pub fn open_zk_whir_rounds<Challenger, MT, D, EFD>(
    rounds: &[&JaggedWhirProverDataGeneric<MT>],
    eval_point: Vec<EF>,
    zerocheck_point: Option<&[EF]>,
    challenger: &mut Challenger,
    mmcs: MT,
    dft: Arc<D>,
    ef_dft: Arc<EFD>,
    config: WhirConfig,
) -> StackedWhirProof<F, EF, MT>
where
    MT: Mmcs<F, Commitment: Clone, ProverData<RowMajorMatrix<F>>: 'static> + Clone,
    D: TwoAdicSubgroupDft<F> + Send + Sync,
    EFD: TwoAdicSubgroupDft<EF>,
    Challenger: FieldChallenger<F>
        + GrindingChallenger<Witness = F>
        + Clone
        + Sync
        + CanObserve<<MT as Mmcs<F>>::Commitment>
        + 'static,
{
    let lsh = rounds[0].log_stacking_height as usize;
    let n = lsh + ZK_PAD_VARS;
    let ff = config.round_parameters[0].folding_factor;
    let num_rounds = config.round_parameters.len();
    assert!(eval_point.len() >= lsh, "zk open: the point is shorter than the stacking height");
    let (sp, bp) = eval_point.split_at(lsh);
    let layout = ZkLayout::new(rounds.iter().map(|r| r.area >> lsh).collect());
    for (r, round) in rounds.iter().enumerate() {
        assert_eq!(round.log_stacking_height as usize, lsh, "zk open: rounds disagree on height");
        assert_eq!(
            round.stacked_data.stripes.len(),
            layout.stripes(r),
            "zk open: round {r} committed {} stripes, its area says {}",
            round.stacked_data.stripes.len(),
            layout.stripes(r),
        );
    }
    assert!(
        config.starting_ood_samples == 0,
        "zk open: the stacked schedule carries its OOD in round constraints"
    );
    let prover = StackedWhirProver::<F, EF, MT, D>::new(mmcs, dft, config.clone(), n as u32);
    let stack_point = zk_stack_point(sp);

    let eq_lower = eq_table(lsh, sp);
    let evaluations: Vec<Vec<EF>> = rounds
        .iter()
        .map(|round| {
            round
                .stacked_data
                .stripes
                .iter()
                .map(|stripe| eq_weighted_sum(&eq_lower, &stripe.guts().as_slice()[..1 << lsh]))
                .collect()
        })
        .collect();

    let masks = zerocheck_point.map(|zp| {
        let (zerocheck, jagged) = zk_masks(rounds[layout.main()]);
        (zerocheck.evaluate(zp), jagged.evaluate(&eval_point), zp.to_vec())
    });

    let batch_grinding_witness =
        crate::whir::grind::accelerated_grind(challenger, config.batch_pow_bits);
    let lambda: EF = challenger.sample_algebra_element();
    let funnelled = funnel(&evaluations, lambda);
    challenger.observe_algebra_element(funnelled);
    let mut batch_evaluations = alloc::vec![funnelled];
    if let Some((zerocheck_value, jagged_value, _)) = &masks {
        challenger.observe_algebra_element(*zerocheck_value);
        challenger.observe_algebra_element(*jagged_value);
        batch_evaluations.push(*zerocheck_value);
        batch_evaluations.push(*jagged_value);
    }
    let mu: EF = challenger.sample_algebra_element();
    let eq_bp = eq_table(bp.len(), bp);
    assert!(layout.total_covered() <= eq_bp.len(), "zk open: more stripes than batch points");
    let coefficients = layout.coefficients(&eq_bp, lambda, mu);

    let mut claim: EF =
        coefficients.iter().flatten().zip(evaluations.iter().flatten()).map(|(&g, &e)| g * e).sum();
    let mut weight = eq_table(n, &stack_point);
    if let Some((zerocheck_value, jagged_value, zp)) = &masks {
        let random_coefficient = *coefficients.last().and_then(|g| g.last()).expect("R");
        let (mu2, mu3) = (mu * mu, mu * mu * mu);
        claim += random_coefficient * (mu2 * *zerocheck_value + mu3 * *jagged_value);
        let (zerocheck_offset, jagged_offset) = mask_offsets(1usize << n);
        for (k, w) in opening_weights::<F, EF>(ZEROCHECK_MASK_DEGREE, zp).iter().enumerate() {
            weight[zerocheck_offset + k] += mu2 * *w;
        }
        for (k, w) in opening_weights::<F, EF>(JAGGED_MASK_DEGREE, &eval_point).iter().enumerate() {
            weight[jagged_offset + k] += mu3 * *w;
        }
    }
    let virt = {
        let weighted: Vec<(&[F], EF)> = rounds
            .iter()
            .zip(&coefficients)
            .flat_map(|(round, gs)| {
                round.stacked_data.stripes.iter().zip(gs).map(|(s, &g)| (s.guts().as_slice(), g))
            })
            .collect();
        lambda_combination(&weighted, 1usize << n)
    };
    let _batch: EF = challenger.sample_algebra_element();
    let mut folder = WhirFolder { f_vec: virt, weight, claimed_sum: claim };

    let mut prev_domain_log = (n - ff) + config.starting_log_inv_rate;
    let mut prev_tree: Option<MT::ProverData<RowMajorMatrix<F>>> = None;
    let mut round_sumcheck_polys = Vec::new();
    let mut round_ood_answers: Vec<Vec<EF>> = Vec::new();
    let mut round_commitments: Vec<MT::Commitment> = Vec::new();
    let mut round_query_openings: Vec<MerkleOpening<F, MT>> = Vec::new();
    let mut folding_pow: Vec<ProofOfWork<F>> = Vec::new();
    let mut cur_log = n;

    for (r, round_cfg) in config.round_parameters.iter().enumerate() {
        let mut this_round_randomness = Vec::new();
        let polys = folder.fold_variables::<F, _>(
            round_cfg.folding_factor,
            &round_cfg.pow_bits,
            challenger,
            &mut this_round_randomness,
        );
        round_sumcheck_polys.push(polys.iter().map(|(p, _)| p.clone()).collect::<Vec<_>>());
        folding_pow.extend(polys.iter().map(|(_, pow)| pow.clone()));
        cur_log -= round_cfg.folding_factor;
        if r + 1 == num_rounds {
            break;
        }

        let next_ff = config.round_parameters[r + 1].folding_factor;
        let rem = cur_log;
        let this_domain_log = (rem - next_ff) + round_cfg.log_inv_rate;
        let width = 1usize << next_ff;
        let mut padded = folder.f_vec.clone();
        padded.resize(padded.len() << round_cfg.log_inv_rate, EF::ZERO);
        let ef_mat = ef_dft.dft_batch(RowMajorMatrix::new(padded, width)).to_row_major_matrix();
        let base_vals: Vec<F> = ef_mat
            .values
            .iter()
            .flat_map(|e| {
                <EF as BasedVectorSpace<F>>::as_basis_coefficients_slice(e).iter().copied()
            })
            .collect();
        let leaves = RowMajorMatrix::new(base_vals, width * EF_DIM);
        let (commitment, this_tree) = prover.mmcs.commit(alloc::vec![leaves]);
        challenger.observe(commitment.clone());
        round_commitments.push(commitment);

        let folded = Mle::<EF>::from_row_major(RowMajorMatrix::new(folder.f_vec.clone(), 1));
        let mut ood_points = Vec::with_capacity(round_cfg.ood_samples);
        let mut ood_answers = Vec::with_capacity(round_cfg.ood_samples);
        for _ in 0..round_cfg.ood_samples {
            let pt: Vec<EF> = (0..rem).map(|_| challenger.sample_algebra_element()).collect();
            let ans = folded.eval_at::<EF>(&pt)[0];
            challenger.observe_algebra_element(ans);
            ood_points.push(pt);
            ood_answers.push(ans);
        }
        round_ood_answers.push(ood_answers.clone());

        folding_pow.push(ProofOfWork(crate::whir::grind::accelerated_grind(
            challenger,
            round_cfg.queries_pow_bits,
        )));
        let mask = (1usize << prev_domain_log) - 1;
        let indices: Vec<usize> = (0..round_cfg.num_queries)
            .map(|_| challenger.sample_bits(prev_domain_log) & mask)
            .collect();
        let g_prev = EF::two_adic_generator(prev_domain_log);
        let mut leaves_open = Vec::with_capacity(indices.len());
        let mut stir_points: Vec<Vec<EF>> = Vec::with_capacity(indices.len());
        let mut stir_values = Vec::with_capacity(indices.len());
        for &idx in &indices {
            let virt_leaf: Vec<EF> = match prev_tree.as_ref() {
                None => {
                    let mut virt_leaf = alloc::vec![EF::ZERO; 1usize << round_cfg.folding_factor];
                    for (round, gs) in rounds.iter().zip(&coefficients) {
                        let opening = prover.mmcs.open_batch(idx, &round.stacked_data.prover_data);
                        for (row, &g) in opening.opened_values.iter().zip(gs) {
                            for (v, &s) in virt_leaf.iter_mut().zip(row.iter()) {
                                *v += g * s;
                            }
                        }
                        leaves_open.push(LeafOpening {
                            values: opening.opened_values,
                            proof: opening.opening_proof,
                        });
                    }
                    virt_leaf
                }
                Some(tree) => {
                    let opening = prover.mmcs.open_batch(idx, tree);
                    let virt_leaf =
                        opening.opened_values[0].chunks_exact(EF_DIM).map(ef_from_base).collect();
                    leaves_open.push(LeafOpening {
                        values: opening.opened_values,
                        proof: opening.opening_proof,
                    });
                    virt_leaf
                }
            };
            stir_values.push(
                Mle::from_row_major(RowMajorMatrix::new(virt_leaf, 1))
                    .eval_at::<EF>(&this_round_randomness)[0],
            );
            stir_points.push(map_to_pow_lsb(g_prev.exp_u64(idx as u64), rem));
        }
        round_query_openings.push(MerkleOpening { leaves: leaves_open });

        let round_batch: EF = challenger.sample_algebra_element();
        let ood_coeffs = folder.ood_coeffs(&ood_answers, round_batch);
        folder.absorb_eq_tables(&ood_points, &ood_coeffs);
        let start_coeff = round_batch.exp_u64((ood_points.len() + 1) as u64);
        let (mono_coeffs, _) = folder.monomial_coeffs(&stir_values, round_batch, start_coeff);
        folder.absorb_monomial_tables(&stir_points, &mono_coeffs);

        prev_domain_log = this_domain_log;
        prev_tree = Some(this_tree);
    }

    let final_poly = folder.f_vec.clone();
    for c in final_poly.iter() {
        challenger.observe_algebra_element(*c);
    }
    let final_pow =
        ProofOfWork(crate::whir::grind::accelerated_grind(challenger, config.final_pow_bits));
    let final_mask = (1usize << prev_domain_log) - 1;
    let mut final_leaves = Vec::with_capacity(config.final_queries);
    for _ in 0..config.final_queries {
        let idx = challenger.sample_bits(prev_domain_log) & final_mask;
        match prev_tree.as_ref() {
            Some(tree) => {
                let opening = prover.mmcs.open_batch(idx, tree);
                final_leaves.push(LeafOpening {
                    values: opening.opened_values,
                    proof: opening.opening_proof,
                });
            }
            None => {
                for round in rounds.iter() {
                    let opening = prover.mmcs.open_batch(idx, &round.stacked_data.prover_data);
                    final_leaves.push(LeafOpening {
                        values: opening.opened_values,
                        proof: opening.opening_proof,
                    });
                }
            }
        }
    }
    round_query_openings.push(MerkleOpening { leaves: final_leaves });
    let final_sumcheck_polys = round_sumcheck_polys.pop().unwrap_or_default();

    StackedWhirProof {
        whir_proof: WhirProof {
            round_sumcheck_polys,
            round_ood_answers,
            round_commitments,
            round_query_openings,
            final_poly,
            final_sumcheck_polys,
            folding_pow,
            final_pow,
        },
        batch_evaluations: alloc::vec![batch_evaluations],
        batch_grinding_witness,
    }
}

/// The zk sibling of [`super::jagged::verify_jagged_whir_rounds`]: verify
/// an [`open_zk_whir_rounds`] proof of `commitments` (one per round, areas
/// in `round_areas`) at `point` against `evaluation_claim`, the jagged
/// layer's claim on the dense polynomial.
#[allow(clippy::too_many_arguments)]
pub fn verify_zk_whir_rounds<Challenger, MT>(
    mmcs: MT,
    config: WhirConfig,
    log_stacking_height: u32,
    commitments: &[<MT as Mmcs<F>>::Commitment],
    round_areas: &[usize],
    point: &[EF],
    proof: &StackedWhirProof<F, EF, MT>,
    evaluation_claim: EF,
    masks: Option<&ZkMaskClaims<EF>>,
    challenger: &mut Challenger,
) -> Result<(), WhirVerifierError>
where
    MT: Mmcs<F, Commitment: Clone> + Clone,
    Challenger: FieldChallenger<F>
        + GrindingChallenger<Witness = F>
        + Clone
        + Sync
        + CanObserve<<MT as Mmcs<F>>::Commitment>
        + 'static,
{
    let shape = |what: &str| WhirVerifierError::IncorrectShape(what.into());
    let lsh = log_stacking_height as usize;
    let n = lsh + ZK_PAD_VARS;
    if point.len() < lsh {
        return Err(shape("point too short"));
    }
    let (sp, bp) = point.split_at(lsh);
    if commitments.len() != round_areas.len() || round_areas.is_empty() {
        return Err(shape("round count"));
    }
    let mut covered = Vec::with_capacity(round_areas.len());
    for &area in round_areas {
        if area == 0 || !area.is_multiple_of(1usize << lsh) {
            return Err(shape("area alignment"));
        }
        covered.push(area >> lsh);
    }
    let layout = ZkLayout::new(covered);
    if layout.total_covered() > 1usize << bp.len() {
        return Err(shape("more stripes than batch points"));
    }
    let funnel_round = match proof.batch_evaluations.as_slice() {
        [round] if round.len() == 1 + 2 * usize::from(masks.is_some()) => round,
        _ => return Err(shape("funnelled claim")),
    };
    let funnelled = funnel_round[0];

    let ff = config.round_parameters[0].folding_factor;
    let num_rounds = config.round_parameters.len();
    let folds: Vec<usize> = config.round_parameters.iter().map(|rp| rp.folding_factor).collect();
    if folds.iter().sum::<usize>() > n {
        return Err(shape("schedule"));
    }
    let final_log = n - folds.iter().sum::<usize>();
    let whir = &proof.whir_proof;
    if whir.final_poly.len() != 1usize << final_log {
        return Err(shape("final_poly"));
    }
    {
        let expect = |what: &'static str, got: usize, want: usize| {
            if got == want {
                Ok(())
            } else {
                Err(WhirVerifierError::IncorrectShape(alloc::format!(
                    "{what}: {got} entries, the configuration fixes {want}"
                )))
            }
        };
        let non_final = num_rounds - 1;
        expect("round_commitments", whir.round_commitments.len(), non_final)?;
        expect("round_ood_answers", whir.round_ood_answers.len(), non_final)?;
        expect("round_sumcheck_polys", whir.round_sumcheck_polys.len(), non_final)?;
        expect("round_query_openings", whir.round_query_openings.len(), num_rounds)?;
        expect("final_sumcheck_polys", whir.final_sumcheck_polys.len(), folds[num_rounds - 1])?;
        expect("folding_pow", whir.folding_pow.len(), folds.iter().sum::<usize>() + non_final)?;
    }
    if config.starting_ood_samples != 0 {
        return Err(shape("stacked WHIR carries its OOD in round constraints"));
    }

    if !challenger.check_witness(config.batch_pow_bits, proof.batch_grinding_witness) {
        return Err(WhirVerifierError::BatchPowMismatch);
    }
    let lambda: EF = challenger.sample_algebra_element();
    challenger.observe_algebra_element(funnelled);
    if masks.is_some() {
        challenger.observe_algebra_element(funnel_round[1]);
        challenger.observe_algebra_element(funnel_round[2]);
    }
    let mu: EF = challenger.sample_algebra_element();
    let coefficients = layout.coefficients(&eq_table(bp.len(), bp), lambda, mu);
    let mut claim = evaluation_claim + mu * funnelled;
    let _batch: EF = challenger.sample_algebra_element();

    enum C {
        Lagrange { point: Vec<EF>, coeff: EF, vars: usize },
        Monomial { point: Vec<EF>, coeff: EF, vars: usize },
    }
    let mut constraints: Vec<C> =
        alloc::vec![C::Lagrange { point: zk_stack_point(sp), coeff: EF::ONE, vars: n }];
    if let Some(masks) = masks {
        let (zerocheck_value, jagged_value) = (funnel_round[1], funnel_round[2]);
        if masks.zerocheck.0 * zerocheck_value != masks.zerocheck.1 {
            return Err(WhirVerifierError::MaskMismatch("zerocheck"));
        }
        if masks.jagged.0 * jagged_value != masks.jagged.1 {
            return Err(WhirVerifierError::MaskMismatch("jagged reduction"));
        }
        if masks.zerocheck_point.len() > crate::zk_mask::ZK_MASK_MAX_VARS
            || point.len() > crate::zk_mask::ZK_MASK_MAX_VARS
        {
            return Err(shape("mask point"));
        }
        let random_coefficient = *coefficients.last().and_then(|g| g.last()).expect("R");
        let (mu2, mu3) = (mu * mu, mu * mu * mu);
        claim += random_coefficient * (mu2 * zerocheck_value + mu3 * jagged_value);
        let (zerocheck_offset, jagged_offset) = mask_offsets(1usize << n);
        let zerocheck_weights =
            opening_weights::<F, EF>(ZEROCHECK_MASK_DEGREE, &masks.zerocheck_point);
        let jagged_weights = opening_weights::<F, EF>(JAGGED_MASK_DEGREE, point);
        for (offset, scale, weights) in
            [(zerocheck_offset, mu2, zerocheck_weights), (jagged_offset, mu3, jagged_weights)]
        {
            for (k, w) in weights.into_iter().enumerate().filter(|(_, w)| *w != EF::ZERO) {
                constraints.push(C::Lagrange {
                    point: boolean_point(offset + k, n),
                    coeff: scale * w,
                    vars: n,
                });
            }
        }
    }

    let lagrange_eq = |a: &[EF], b: &[EF]| -> EF {
        a.iter().zip(b).map(|(&x, &y)| x * y + (EF::ONE - x) * (EF::ONE - y)).product()
    };
    let monomial_fold = |a: &[EF], b: &[EF]| -> EF {
        a.iter().zip(b).map(|(&x, &y)| EF::ONE - y + y * x).product()
    };

    let verify_round0_leaf = |leaf: &LeafOpening<F, MT>,
                              ri: usize,
                              idx: usize,
                              width: usize,
                              height_log: usize,
                              virt_leaf: &mut [EF]|
     -> Result<(), WhirVerifierError> {
        let stripes = layout.stripes(ri);
        let salted = layout.salted(ri);
        if leaf.values.len() != stripes + usize::from(salted) {
            return Err(WhirVerifierError::IncorrectShape("stripe rows".into()));
        }
        let mut dims: Vec<p3_matrix::Dimensions> = (0..stripes)
            .map(|_| p3_matrix::Dimensions { width, height: 1usize << height_log })
            .collect();
        if salted {
            dims.push(p3_matrix::Dimensions { width: ZK_SALT_WIDTH, height: 1usize << height_log });
        }
        let opened =
            p3_commit::BatchOpeningRef { opened_values: &leaf.values, opening_proof: &leaf.proof };
        mmcs.verify_batch(&commitments[ri], &dims, idx, opened)
            .map_err(|_| WhirVerifierError::IncorrectShape("merkle".into()))?;
        for (row, &g) in leaf.values.iter().zip(&coefficients[ri]) {
            if row.len() != width {
                return Err(WhirVerifierError::IncorrectShape("stripe row width".into()));
            }
            for (v, &s) in virt_leaf.iter_mut().zip(row.iter()) {
                *v += g * s;
            }
        }
        Ok(())
    };
    let folded_leaf = |leaf: &LeafOpening<F, MT>,
                       commitment: &<MT as Mmcs<F>>::Commitment,
                       idx: usize,
                       width: usize,
                       height_log: usize|
     -> Result<Vec<EF>, WhirVerifierError> {
        if leaf.values.len() != 1 || leaf.values[0].len() != width * EF_DIM {
            return Err(WhirVerifierError::IncorrectShape("folded row".into()));
        }
        let dims = alloc::vec![p3_matrix::Dimensions {
            width: width * EF_DIM,
            height: 1usize << height_log,
        }];
        let opened =
            p3_commit::BatchOpeningRef { opened_values: &leaf.values, opening_proof: &leaf.proof };
        mmcs.verify_batch(commitment, &dims, idx, opened)
            .map_err(|_| WhirVerifierError::IncorrectShape("merkle".into()))?;
        Ok(leaf.values[0].chunks_exact(EF_DIM).map(ef_from_base).collect())
    };

    let mut prev_domain_log = (n - ff) + config.starting_log_inv_rate;
    let mut prev_round0 = true;
    let mut all_fr: Vec<EF> = Vec::with_capacity(n - final_log);
    let mut pow_flat = 0usize;
    let mut folded_vars = 0usize;
    for (r, round_cfg) in config.round_parameters.iter().enumerate() {
        let msgs = if r + 1 == num_rounds {
            &whir.final_sumcheck_polys
        } else {
            whir.round_sumcheck_polys.get(r).ok_or_else(|| shape("round messages"))?
        };
        if msgs.len() != round_cfg.folding_factor {
            return Err(shape("round messages"));
        }
        let mut this_round_randomness: Vec<EF> = Vec::with_capacity(round_cfg.folding_factor);
        for (var, poly) in msgs.iter().enumerate() {
            let c = &poly.0;
            if c.len() != 3 {
                return Err(shape("degree-2"));
            }
            let (c0, c1, c2) = (c[0], c[1], c[2]);
            if c0 + (c0 + c1 + c2) != claim {
                return Err(WhirVerifierError::SumcheckMismatch { round: r, var });
            }
            challenger.observe_algebra_element(c0);
            challenger.observe_algebra_element(c1);
            challenger.observe_algebra_element(c2);
            let pow = whir.folding_pow.get(pow_flat).ok_or_else(|| shape("folding pow"))?;
            pow_flat += 1;
            if !challenger.check_witness(round_cfg.pow_bits.get(var).copied().unwrap_or(0), pow.0) {
                return Err(WhirVerifierError::PowMismatch { round: r, var });
            }
            let rc: EF = challenger.sample_algebra_element();
            claim = c0 + c1 * rc + c2 * rc * rc;
            all_fr.push(rc);
            this_round_randomness.push(rc);
        }
        folded_vars += round_cfg.folding_factor;
        if r + 1 == num_rounds {
            break;
        }

        challenger.observe(
            whir.round_commitments.get(r).ok_or_else(|| shape("round commitment"))?.clone(),
        );
        let rem = n - folded_vars;
        let ood_answers = whir.round_ood_answers.get(r).ok_or_else(|| shape("round ood"))?;
        if ood_answers.len() != round_cfg.ood_samples {
            return Err(shape("round ood count"));
        }
        let mut ood_points: Vec<Vec<EF>> = Vec::with_capacity(ood_answers.len());
        for ans in ood_answers.iter() {
            let pt: Vec<EF> = (0..rem).map(|_| challenger.sample_algebra_element()).collect();
            challenger.observe_algebra_element(*ans);
            ood_points.push(pt);
        }

        let query_pow = whir.folding_pow.get(pow_flat).ok_or_else(|| shape("query pow"))?;
        pow_flat += 1;
        if !challenger.check_witness(round_cfg.queries_pow_bits, query_pow.0) {
            return Err(WhirVerifierError::PowMismatch { round: r, var: usize::MAX });
        }
        let mask = (1usize << prev_domain_log) - 1;
        let indices: Vec<usize> = (0..round_cfg.num_queries)
            .map(|_| challenger.sample_bits(prev_domain_log) & mask)
            .collect();
        let openings =
            whir.round_query_openings.get(r).ok_or_else(|| shape("round query openings"))?;
        let leaves_per_query = if prev_round0 { commitments.len() } else { 1 };
        if openings.leaves.len() != indices.len() * leaves_per_query {
            return Err(shape("query openings"));
        }
        let g_prev = EF::two_adic_generator(prev_domain_log);
        let width = 1usize << round_cfg.folding_factor;
        let mut stir_points: Vec<Vec<EF>> = Vec::with_capacity(indices.len());
        let mut stir_values: Vec<EF> = Vec::with_capacity(indices.len());
        for (qi, &idx) in indices.iter().enumerate() {
            let virt_leaf: Vec<EF> = if prev_round0 {
                let mut virt_leaf = alloc::vec![EF::ZERO; width];
                for ri in 0..commitments.len() {
                    verify_round0_leaf(
                        &openings.leaves[qi * leaves_per_query + ri],
                        ri,
                        idx,
                        width,
                        prev_domain_log,
                        &mut virt_leaf,
                    )?;
                }
                virt_leaf
            } else {
                folded_leaf(
                    &openings.leaves[qi],
                    whir.round_commitments.get(r - 1).ok_or_else(|| shape("prev commitment"))?,
                    idx,
                    width,
                    prev_domain_log,
                )?
            };
            let stir = Mle::from_row_major(RowMajorMatrix::new(virt_leaf, 1))
                .eval_at::<EF>(&this_round_randomness)[0];
            stir_values.push(stir);
            stir_points.push(map_to_pow_lsb(g_prev.exp_u64(idx as u64), rem));
        }

        let round_batch: EF = challenger.sample_algebra_element();
        let mut cc = round_batch;
        for (a, p) in ood_answers.iter().zip(&ood_points) {
            claim += cc * *a;
            constraints.push(C::Lagrange { point: p.clone(), coeff: cc, vars: rem });
            cc *= round_batch;
        }
        for (v, p) in stir_values.iter().zip(&stir_points) {
            claim += cc * *v;
            constraints.push(C::Monomial { point: p.clone(), coeff: cc, vars: rem });
            cc *= round_batch;
        }

        prev_domain_log =
            (rem - config.round_parameters[r + 1].folding_factor) + round_cfg.log_inv_rate;
        prev_round0 = false;
    }

    for c in whir.final_poly.iter() {
        challenger.observe_algebra_element(*c);
    }
    if !challenger.check_witness(config.final_pow_bits, whir.final_pow.0) {
        return Err(WhirVerifierError::PowMismatch { round: num_rounds, var: usize::MAX });
    }
    let final_mask = (1usize << prev_domain_log) - 1;
    let final_openings =
        whir.round_query_openings.get(num_rounds - 1).ok_or_else(|| shape("final openings"))?;
    let leaves_per_query = if prev_round0 { commitments.len() } else { 1 };
    if final_openings.leaves.len() != config.final_queries * leaves_per_query {
        return Err(shape("final query count"));
    }
    let g_final = EF::two_adic_generator(prev_domain_log);
    let last_ff = *folds.last().unwrap();
    let last_randomness = &all_fr[all_fr.len() - last_ff..];
    for q in 0..config.final_queries {
        let idx = challenger.sample_bits(prev_domain_log) & final_mask;
        let virt_leaf: Vec<EF> = if prev_round0 {
            let mut virt_leaf = alloc::vec![EF::ZERO; 1usize << last_ff];
            for ri in 0..commitments.len() {
                verify_round0_leaf(
                    &final_openings.leaves[q * leaves_per_query + ri],
                    ri,
                    idx,
                    1usize << last_ff,
                    prev_domain_log,
                    &mut virt_leaf,
                )?;
            }
            virt_leaf
        } else {
            folded_leaf(
                &final_openings.leaves[q],
                whir.round_commitments
                    .get(num_rounds - 2)
                    .ok_or_else(|| shape("final commitment"))?,
                idx,
                1usize << last_ff,
                prev_domain_log,
            )?
        };
        let folded = Mle::from_row_major(RowMajorMatrix::new(virt_leaf, 1))
            .eval_at::<EF>(last_randomness)[0];
        let expected = mono_eval_lsb(
            &whir.final_poly,
            &map_to_pow_lsb(g_final.exp_u64(idx as u64), final_log),
        );
        if folded != expected {
            return Err(WhirVerifierError::TerminalMismatch);
        }
    }

    let final_mle = Mle::from_row_major(RowMajorMatrix::new(whir.final_poly.clone(), 1));
    let mut total = EF::ZERO;
    for c in &constraints {
        match c {
            C::Lagrange { point: p, coeff, vars } => {
                let k = vars - final_log;
                let eq_part = lagrange_eq(&p[..k], &all_fr[(n - vars)..(n - vars) + k]);
                let f_part = final_mle.eval_at::<EF>(&p[k..])[0];
                total += *coeff * eq_part * f_part;
            }
            C::Monomial { point: p, coeff, vars } => {
                let k = vars - final_log;
                let fold_part = monomial_fold(&p[..k], &all_fr[(n - vars)..(n - vars) + k]);
                let f_part = mono_eval_lsb(&whir.final_poly, &p[k..]);
                total += *coeff * fold_part * f_part;
            }
        }
    }
    if total != claim {
        return Err(WhirVerifierError::TerminalMismatch);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jagged_pcs::{jagged_mmcs, JaggedChallenger, JaggedMmcs};
    use crate::whir::jagged::whir_config_for_fold_schedule;
    use crate::whir::stripes::interleave_multilinears_with_fixed_rate;
    use p3_dft::Radix2DitParallel;
    use p3_field::PrimeCharacteristicRing;
    use zkm_primitives::poseidon2_init;

    const LSH: usize = 10;

    fn challenger() -> JaggedChallenger {
        JaggedChallenger::new(poseidon2_init())
    }

    fn config() -> WhirConfig {
        let mut cfg = whir_config_for_fold_schedule(LSH + ZK_PAD_VARS, &[4, 3, 2], 2);
        for rp in cfg.round_parameters.iter_mut() {
            rp.num_queries = 5;
        }
        cfg.final_queries = 5;
        cfg.batch_pow_bits = 3;
        cfg
    }

    fn rand_ef(rng: &mut StdRng) -> EF {
        let coefficients: Vec<F> =
            (0..EF_DIM).map(|_| F::from_u32(rng.gen::<u32>() >> 2)).collect();
        ef_from_base(&coefficients)
    }

    /// A round of `stripes` stripes of pseudo-random cells, as the jagged
    /// layer stacks them, committed by [`commit_zk_whir_round`].
    fn commit_round(
        rng: &mut StdRng,
        stripes: usize,
        main: bool,
    ) -> (Vec<Vec<F>>, JaggedWhirProverDataGeneric<JaggedMmcs>) {
        let cells: Vec<Vec<F>> = (0..stripes)
            .map(|_| (0..1usize << LSH).map(|_| F::from_u32(rng.gen::<u32>() >> 2)).collect())
            .collect();
        let interleaves = interleave_multilinears_with_fixed_rate(
            crate::jagged_pcs::DEFAULT_BATCH_SIZE,
            cells.iter().map(|stripe| Arc::new(Mle::from_values(stripe.clone()))).collect(),
            LSH as u32,
        );
        let (_, data) = commit_zk_whir_round::<JaggedMmcs, Radix2DitParallel<F>>(
            &interleaves,
            Vec::new(),
            stripes << LSH,
            LSH as u32,
            jagged_mmcs(),
            Arc::new(Radix2DitParallel::default()),
            config(),
            main,
        );
        (cells, data)
    }

    struct Instance {
        prep: JaggedWhirProverDataGeneric<JaggedMmcs>,
        main: JaggedWhirProverDataGeneric<JaggedMmcs>,
        point: Vec<EF>,
        claim: EF,
        zerocheck_point: Vec<EF>,
    }

    const RHO_ZEROCHECK: u32 = 1234;
    const RHO_JAGGED: u32 = 5678;

    /// The mask claims an honest shard would hand the verifier: `ρ·g(z)` and
    /// `ρ'·h(z*)` read off the committed masks.
    fn mask_claims(inst: &Instance) -> ZkMaskClaims<EF> {
        let (zerocheck, jagged) = zk_masks(&inst.main);
        let (rho_z, rho_j) = (EF::from_u32(RHO_ZEROCHECK), EF::from_u32(RHO_JAGGED));
        ZkMaskClaims {
            zerocheck_point: inst.zerocheck_point.clone(),
            zerocheck: (rho_z, rho_z * zerocheck.evaluate(&inst.zerocheck_point)),
            jagged: (rho_j, rho_j * jagged.evaluate(&inst.point)),
        }
    }

    /// Two rounds (3 + 2 stripes, 8 batch slots) and the dense polynomial's
    /// evaluation at `point`, the claim the jagged layer would reduce to.
    fn instance(seed: u64) -> Instance {
        let mut rng = StdRng::seed_from_u64(seed);
        let (prep_cells, prep) = commit_round(&mut rng, 3, false);
        let (main_cells, main) = commit_round(&mut rng, 2, true);
        let point: Vec<EF> = (0..LSH + 3).map(|_| rand_ef(&mut rng)).collect();
        let eq_sp = eq_table(LSH, &point[..LSH]);
        let eq_bp = eq_table(3, &point[LSH..]);
        let claim = prep_cells
            .iter()
            .chain(main_cells.iter())
            .enumerate()
            .map(|(j, stripe)| eq_bp[j] * eq_weighted_sum(&eq_sp, stripe))
            .sum();
        let zerocheck_point: Vec<EF> = (0..7).map(|_| rand_ef(&mut rng)).collect();
        Instance { prep, main, point, claim, zerocheck_point }
    }

    fn open_with(inst: &Instance, masked: bool) -> StackedWhirProof<F, EF, JaggedMmcs> {
        open_zk_whir_rounds::<JaggedChallenger, JaggedMmcs, _, _>(
            &[&inst.prep, &inst.main],
            inst.point.clone(),
            masked.then_some(inst.zerocheck_point.as_slice()),
            &mut challenger(),
            jagged_mmcs(),
            Arc::new(Radix2DitParallel::<F>::default()),
            Arc::new(Radix2DitParallel::<EF>::default()),
            config(),
        )
    }

    fn open(inst: &Instance) -> StackedWhirProof<F, EF, JaggedMmcs> {
        open_with(inst, true)
    }

    fn verify_with(
        inst: &Instance,
        proof: &StackedWhirProof<F, EF, JaggedMmcs>,
        claim: EF,
        masks: Option<&ZkMaskClaims<EF>>,
    ) -> Result<(), WhirVerifierError> {
        verify_zk_whir_rounds::<JaggedChallenger, JaggedMmcs>(
            jagged_mmcs(),
            config(),
            LSH as u32,
            &[inst.prep.stacked_data.commitment.clone(), inst.main.stacked_data.commitment.clone()],
            &[3 << LSH, 2 << LSH],
            &inst.point,
            proof,
            claim,
            masks,
            &mut challenger(),
        )
    }

    fn verify(
        inst: &Instance,
        proof: &StackedWhirProof<F, EF, JaggedMmcs>,
        claim: EF,
    ) -> Result<(), WhirVerifierError> {
        verify_with(inst, proof, claim, Some(&mask_claims(inst)))
    }

    /// The committed shapes: padded stripes, the random stripe and the salt
    /// on the main round only, the preprocessed round deterministic.
    #[test]
    fn rounds_commit_the_zk_layout() {
        let mut rng = StdRng::seed_from_u64(1);
        let (cells, prep) = commit_round(&mut rng, 3, false);
        assert_eq!(prep.stacked_data.stripes.len(), 3);
        for (stripe, data) in prep.stacked_data.stripes.iter().zip(&cells) {
            let vals = stripe.guts().as_slice();
            assert_eq!(vals.len(), 1 << (LSH + ZK_PAD_VARS));
            assert_eq!(&vals[..1 << LSH], data.as_slice());
            assert!(vals[1 << LSH..].iter().all(|v| *v == F::ZERO));
        }
        assert_eq!(jagged_mmcs().get_matrices(&prep.stacked_data.prover_data).len(), 3);
        let mut rng = StdRng::seed_from_u64(1);
        let (_, again) = commit_round(&mut rng, 3, false);
        assert_eq!(again.stacked_data.commitment, prep.stacked_data.commitment);

        let (cells, main) = commit_round(&mut StdRng::seed_from_u64(2), 2, true);
        assert_eq!(main.stacked_data.stripes.len(), 3);
        let padded_len = 1usize << (LSH + ZK_PAD_VARS);
        for (stripe, data) in main.stacked_data.stripes.iter().zip(&cells) {
            let vals = stripe.guts().as_slice();
            assert_eq!(&vals[..1 << LSH], data.as_slice());
            assert!(vals[1 << LSH..padded_len - ZK_MASK_CELLS].iter().any(|v| *v != F::ZERO));
            assert!(vals[padded_len - ZK_MASK_CELLS..].iter().all(|v| *v == F::ZERO));
        }
        let random = main.stacked_data.stripes[2].guts().as_slice();
        assert!(random[padded_len - ZK_MASK_CELLS..].iter().any(|v| *v != F::ZERO));
        let (zerocheck_cells, jagged_cells) = zk_mask_cells(&main);
        assert_eq!(zerocheck_cells.len(), mask_cells(ZEROCHECK_MASK_DEGREE, EF_DIM));
        assert_eq!(jagged_cells.len(), mask_cells(JAGGED_MASK_DEGREE, EF_DIM));
        assert_eq!(&random[padded_len - ZK_MASK_CELLS..][..zerocheck_cells.len()], zerocheck_cells);
        let matrices = jagged_mmcs().get_matrices(&main.stacked_data.prover_data);
        assert_eq!(matrices.len(), 4);
        assert_eq!(matrices[3].width(), ZK_SALT_WIDTH);
        assert_eq!(matrices[3].height(), matrices[0].height());
        let (same_cells, again) = commit_round(&mut StdRng::seed_from_u64(2), 2, true);
        assert_eq!(same_cells, cells);
        assert_ne!(again.stacked_data.commitment, main.stacked_data.commitment);
        assert_ne!(
            again.stacked_data.stripes[2].guts().as_slice(),
            main.stacked_data.stripes[2].guts().as_slice(),
            "the random stripe is fresh per commit"
        );
    }

    /// An honest opening verifies against the dense polynomial's evaluation
    /// and against nothing else.
    #[test]
    fn zk_opening_round_trip() {
        let inst = instance(7);
        let proof = open(&inst);
        assert_eq!(verify(&inst, &proof, inst.claim), Ok(()));
        assert_eq!(proof.batch_evaluations.len(), 1);
        assert_eq!(proof.batch_evaluations[0].len(), 3);
        assert!(verify(&inst, &proof, inst.claim + EF::ONE).is_err());

        let mut bad = proof.clone();
        bad.batch_evaluations[0][0] += EF::ONE;
        assert!(verify(&inst, &bad, inst.claim).is_err());

        let mut bad = proof.clone();
        bad.batch_evaluations = alloc::vec![alloc::vec![proof.batch_evaluations[0][0]; 2]];
        assert!(verify(&inst, &bad, inst.claim).is_err());

        let mut bad = proof.clone();
        bad.batch_evaluations[0].truncate(1);
        assert!(verify(&inst, &bad, inst.claim).is_err());
        assert!(verify_with(&inst, &bad, inst.claim, None).is_err());

        let plain = open_with(&inst, false);
        assert_eq!(plain.batch_evaluations[0].len(), 1);
        assert_eq!(verify_with(&inst, &plain, inst.claim, None), Ok(()));
        assert!(verify(&inst, &plain, inst.claim).is_err());

        let mut bad = proof.clone();
        bad.batch_grinding_witness += F::ONE;
        assert!(verify(&inst, &bad, inst.claim).is_err());

        let mut bad = proof.clone();
        bad.whir_proof.round_query_openings[0].leaves[0].values[0][0] += F::ONE;
        assert!(verify(&inst, &bad, inst.claim).is_err());

        let mut bad = proof.clone();
        let salt = bad.whir_proof.round_query_openings[0].leaves[1].values.last_mut().unwrap();
        assert_eq!(salt.len(), ZK_SALT_WIDTH);
        salt[0] += F::ONE;
        assert!(verify(&inst, &bad, inst.claim).is_err());

        let mut bad = proof.clone();
        bad.whir_proof.round_query_openings[0].leaves[1].values.pop();
        assert!(verify(&inst, &bad, inst.claim).is_err());

        let mut bad = proof.clone();
        bad.whir_proof.final_poly[0] += EF::ONE;
        assert!(verify(&inst, &bad, inst.claim).is_err());
    }

    /// The mask values the opening sends are the committed masks at their
    /// points and nothing else: a residue that disagrees with either, or a
    /// different zerocheck point, is rejected before the WHIR rounds.
    #[test]
    fn zk_opening_binds_the_sumcheck_masks() {
        let inst = instance(9);
        let proof = open(&inst);
        let claims = mask_claims(&inst);
        assert_eq!(verify_with(&inst, &proof, inst.claim, Some(&claims)), Ok(()));
        let (zerocheck, jagged) = zk_masks(&inst.main);
        assert_eq!(proof.batch_evaluations[0][1], zerocheck.evaluate(&inst.zerocheck_point));
        assert_eq!(proof.batch_evaluations[0][2], jagged.evaluate(&inst.point));

        let mut bad = claims.clone();
        bad.zerocheck.1 += EF::ONE;
        assert_eq!(
            verify_with(&inst, &proof, inst.claim, Some(&bad)),
            Err(WhirVerifierError::MaskMismatch("zerocheck"))
        );
        let mut bad = claims.clone();
        bad.jagged.1 += EF::ONE;
        assert_eq!(
            verify_with(&inst, &proof, inst.claim, Some(&bad)),
            Err(WhirVerifierError::MaskMismatch("jagged reduction"))
        );

        let mut bad = claims.clone();
        bad.zerocheck_point[0] += EF::ONE;
        assert!(verify_with(&inst, &proof, inst.claim, Some(&bad)).is_err());

        let mut forged = proof.clone();
        forged.batch_evaluations[0][1] += EF::ONE;
        let mut forged_claims = claims.clone();
        forged_claims.zerocheck.1 += claims.zerocheck.0;
        assert!(verify_with(&inst, &forged, inst.claim, Some(&forged_claims)).is_err());
    }

    /// Two openings of the same cells at the same point share nothing the
    /// verifier sees but the claim: the main commitment, the funnelled
    /// value, the opened rows, the salts, the folded commitments and the
    /// final polynomial all differ, while both verify.
    #[test]
    fn zk_openings_are_randomised() {
        let a = instance(11);
        let b = instance(11);
        assert_eq!(a.claim, b.claim);
        assert_eq!(a.prep.stacked_data.commitment, b.prep.stacked_data.commitment);
        assert_ne!(a.main.stacked_data.commitment, b.main.stacked_data.commitment);
        let pa = open(&a);
        let pb = open(&b);
        assert_eq!(verify(&a, &pa, a.claim), Ok(()));
        assert_eq!(verify(&b, &pb, b.claim), Ok(()));
        assert_ne!(pa.batch_evaluations, pb.batch_evaluations);
        assert_ne!(pa.whir_proof.final_poly, pb.whir_proof.final_poly);
        assert_ne!(pa.whir_proof.round_commitments, pb.whir_proof.round_commitments);
        let rows = |p: &StackedWhirProof<F, EF, JaggedMmcs>| {
            p.whir_proof.round_query_openings[0]
                .leaves
                .iter()
                .map(|l| l.values.clone())
                .collect::<Vec<_>>()
        };
        let (ra, rb) = (rows(&pa), rows(&pb));
        for (la, lb) in ra.iter().zip(&rb) {
            if la.len() == 4 {
                assert_ne!(la, lb, "a salted main-round leaf never repeats");
            }
        }
        assert!(verify(&a, &pb, a.claim).is_err(), "a proof binds its own commitment");
    }
}
