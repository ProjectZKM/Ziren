//! The zero-knowledge stacked WHIR opening (feature `zk`): what the zk
//! shrink ring ([`crate::zk::KoalaBearPoseidon2ZkShrink`]) commits, opens
//! and verifies in place of [`super::stacked`].
//!
//! The plain stacked open is not hiding: it echoes every stripe's evaluation
//! at the stack point, and every folded polynomial, out-of-domain answer,
//! query row and sumcheck message it sends is a linear functional of the
//! committed cells.  The zk opening is the zero-knowledge IOPP of Chiesa,
//! Fenzi and Weissenberg (ePrint 2026/391, Construction 11.1 with the
//! Reed–Solomon codes of its §11 and the unsalted commitments of its
//! Appendix B) run on the stacked layout:
//!
//! * **hiding rows** — every row of an oracle (one column of its interleaved
//!   codeword) is the polynomial `ev(seed, X) + X^T·ev(main, X) +
//!   X^{T+ℓ}·ev(aux, X)`, where `T` is one more than the oracle's query
//!   count.  The seeds make the opened evaluations of a row uniform, and with
//!   the extra coefficient an unopened leaf keeps enough entropy to be hashed
//!   without a salt.  The preprocessed round has zero seeds: the key commits
//!   it and its cells are public.
//! * **the input oracle** `G = Σ_j eq(bp, j)·S_j` over every stripe of every
//!   round, the jagged layer's own combination: `G` evaluates at the stack
//!   point to the jagged claim, so no per-stripe value is sent.  A query to
//!   `G` opens every stripe's row and combines them.  The main round's last
//!   stripe carries `G`'s auxiliary block: its mask coordinates and the mask
//!   region.
//! * **masked sumchecks** — each stage holds a mask polynomial `U = ŝ_0 +
//!   ŝ_1·(X_1 + … + X_k)` over its `k` row variables, `ŝ_e = Σ_{j ≤ k}
//!   σ_{j,e}·X_{j+1}⋯X_k`, whose values `ŝ_e(b)` sit in row `b`'s auxiliary
//!   block.  The prover sends `µ̃ = Σ_b U(b)`, the verifier draws `ε`, and the
//!   stage folds `U + ε·⟨weights, message⟩`; `U` enters as the weights `1`
//!   and `popcount(b)` on the mask coordinates.
//! * **code switch** — the next oracle re-encodes the fold: its main block is
//!   the folded main block, its auxiliary block holds its own masks, the
//!   folded auxiliary block and seeds, and a uniform pad.  The out-of-domain
//!   answer weighs the whole auxiliary block, the pad included, so it is
//!   uniform; a query value is a linear constraint on the new message.
//! * **base case** — the last oracle carries one uniform mask row `g`; the
//!   prover sends `µ⋆ = ⟨weights, g⟩`, the verifier draws `γ⋆`, and the
//!   prover discloses `D = g + γ⋆·fold` in place of the final polynomial.
//!   Each final query checks `D(x) = g(x) + γ⋆·fold(x)`.
//! * **the mask region** — the first [`region_cells`] cells of the main
//!   round's extra entry hold every mask of the shard, laid out by
//!   [`ZkCellLayout`]: the zerocheck's and the jagged reduction's
//!   [`LibraMask`]s, the virtual LogUp leaves and the LogUp-GKR rounds' masks
//!   ([`crate::shard_level::row_gkr::zk`]).  They are committed in `G`'s
//!   auxiliary block, so each value the verifier must learn of them, a
//!   [`ZkCellClaim`], is a linear constraint on `G`'s message, batched into
//!   the input claim with the powers of one challenge `μ`.  The jagged
//!   reduction's claim is built here, at the opening point; the others come
//!   from the shard.
//!
//! The schedule is the shrink schedule ([`super::jagged::zk_shrink_whir_config`]),
//! and the proof and bundle types are those of every other ring:
//! `batch_evaluations` carries `[µ̃_0, …, µ̃_{n−1}, µ⋆]` and `final_poly`
//! carries `D`.  Nothing here runs on a device: the zk shrink is one small
//! terminal proof.

use alloc::sync::Arc;
use alloc::vec::Vec;

use p3_challenger::{CanObserve, FieldChallenger, GrindingChallenger};
use p3_commit::Mmcs;
use p3_dft::TwoAdicSubgroupDft;
use p3_field::{BasedVectorSpace, PrimeCharacteristicRing, PrimeField32, TwoAdicField};
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;
use p3_maybe_rayon::prelude::*;
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
use crate::whir::monomial::map_to_pow_lsb;
use crate::whir::proof::{ProofOfWork, WhirProof};
use crate::whir::stacked::{lambda_combination, StackedWhirProof, StackedWhirProverData};
use crate::whir::sumcheck::WhirFolder;
use crate::zk_mask::{
    mask_claim_weights, LibraMask, ZkCellClaim, ZkCellLayout, JAGGED_MASK_DEGREE,
    ZEROCHECK_MASK_DEGREE, ZK_MASK_CELLS,
};

type F = JaggedVal;
type EF = JaggedChallenge;

/// The dimension of `EF` over `F`.
const EF_DIM: usize = <EF as BasedVectorSpace<F>>::DIMENSION;

fn ef_from_base(coefficients: &[F]) -> EF {
    <EF as BasedVectorSpace<F>>::from_basis_coefficients_iter(coefficients.iter().copied())
        .expect("one extension element per EF_DIM base coefficients")
}

/// The `u`-th basis element of `EF` over `F`.
fn basis(u: usize) -> EF {
    let mut unit = [F::ZERO; EF_DIM];
    unit[u] = F::ONE;
    ef_from_base(&unit)
}

/// Mask coordinates of a row: `ŝ_0(b)` and `ŝ_1(b)`, two extension elements
/// (the paper's masking degree three over `M = EF`).
pub const ZK_MASK_COORDS: usize = 2;

/// Auxiliary rows the input oracle's mask coordinates take: its rows are base
/// cells, so each extension coordinate spans `EF_DIM` of them.
const INPUT_MASK_ROWS: usize = ZK_MASK_COORDS * EF_DIM;

/// The cells of the mask region at log stacking height `lsh`:
/// [`ZK_MASK_CELLS`], or a quarter of a stripe on a stack too short for
/// that.
pub fn region_cells(lsh: usize) -> usize {
    ZK_MASK_CELLS.min(1usize << (lsh - 1))
}

/// Uniform seed coefficients of a row an oracle's `queries` queries open:
/// one more than the queries, so an unopened leaf keeps the entropy of one
/// coefficient (Appendix B of the paper) and no salt is needed.
pub fn zk_seeds(queries: usize) -> usize {
    queries + 1
}

/// The row geometry of one stage's oracle: `width` rows, each of `seeds +
/// main + aux` coefficients, encoded on `2^domain_log` points.  The stage's
/// message lists the seed block, the main block and the auxiliary block,
/// each `width`-wide row-major, so row `b`'s coefficient `q` is message entry
/// `q·width + b` and folding the low `log2(width)` bits of an index folds
/// the rows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZkStage {
    pub width: usize,
    pub seeds: usize,
    pub main: usize,
    pub aux: usize,
    /// Entries of the previous stage's fold this oracle carries in its
    /// auxiliary block: the folded auxiliary block, then the folded seeds.
    pub carried: usize,
    pub domain_log: usize,
    pub queries: usize,
}

impl ZkStage {
    pub fn coefficients(&self) -> usize {
        self.seeds + self.main + self.aux
    }

    pub fn len(&self) -> usize {
        self.coefficients() * self.width
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn main_offset(&self) -> usize {
        self.seeds * self.width
    }

    fn aux_offset(&self) -> usize {
        (self.seeds + self.main) * self.width
    }

    fn main_len(&self) -> usize {
        self.main * self.width
    }

    fn aux_len(&self) -> usize {
        self.aux * self.width
    }

    fn main_vars(&self) -> usize {
        self.main_len().trailing_zeros() as usize
    }

    fn aux_vars(&self) -> usize {
        ceil_log2(self.aux_len())
    }

    /// Where the carried entries start in the auxiliary block of a folded
    /// oracle, after its own mask rows.
    fn carried_offset(&self) -> usize {
        ZK_MASK_COORDS * self.width
    }
}

fn ceil_log2(n: usize) -> usize {
    n.next_power_of_two().trailing_zeros() as usize
}

/// The stages of a zk opening at log stacking height `lsh` under `config`:
/// stage 0 is the input oracle `G`, stage `s ≥ 1` the oracle committed after
/// round `s − 1`'s fold.  A stage's queries are round `s`'s, the last
/// stage's the final queries.
pub fn zk_stages(config: &WhirConfig, lsh: usize) -> Vec<ZkStage> {
    let n = config.round_parameters.len();
    assert!(n >= 2, "zk opening: the schedule commits no folded oracle");
    let mut stages: Vec<ZkStage> = Vec::with_capacity(n);
    let mut rem = lsh;
    for s in 0..n {
        let k = config.round_parameters[s].folding_factor;
        assert!(rem >= k, "zk opening: the schedule folds more variables than a stripe has");
        let width = 1usize << k;
        let queries =
            if s + 1 < n { config.round_parameters[s].num_queries } else { config.final_queries };
        let (aux, carried, rate) = match stages.last() {
            None => (INPUT_MASK_ROWS + region_cells(lsh) / width, 0, config.starting_log_inv_rate),
            Some(prev) => {
                let carried = prev.aux + prev.seeds;
                let pad = config.round_parameters[s - 1].ood_samples.max(1);
                (
                    ZK_MASK_COORDS + (carried + pad).div_ceil(width),
                    carried,
                    config.round_parameters[s - 1].log_inv_rate,
                )
            }
        };
        let stage = ZkStage {
            width,
            seeds: zk_seeds(queries),
            main: (1usize << rem) / width,
            aux,
            carried,
            domain_log: rem - k + rate,
            queries,
        };
        assert!(
            stage.coefficients() <= 1usize << stage.domain_log,
            "zk opening: stage {s} rows of {} coefficients exceed their 2^{} points",
            stage.coefficients(),
            stage.domain_log
        );
        stages.push(stage);
        rem -= k;
    }
    stages
}

/// Each stage's oracle rate, as `−log2(coefficients / 2^domain_log)`, and
/// what its queries are worth in the unique-decoding regime, grinding
/// included: the hiding rows' seeds and auxiliary block raise the rate the
/// schedule's own rate stands for.
pub fn zk_query_phase_bits(config: &WhirConfig, lsh: usize) -> Vec<(f64, f64)> {
    let n = config.round_parameters.len();
    zk_stages(config, lsh)
        .iter()
        .enumerate()
        .map(|(s, stage)| {
            let rate = stage.coefficients() as f64 / (1u64 << stage.domain_log) as f64;
            let pow = if s + 1 < n {
                config.round_parameters[s].queries_pow_bits
            } else {
                config.final_pow_bits
            };
            let bits = stage.queries as f64 * crate::whir::jagged::bits_per_query_at_rate(rate)
                + pow as f64;
            (-rate.log2(), bits)
        })
        .collect()
}

/// The mask region of a main round, read off its extra entry.
pub fn zk_region<MT: Mmcs<F>>(data: &JaggedWhirProverDataGeneric<MT>) -> &[F] {
    let lsh = data.log_stacking_height as usize;
    assert_eq!(
        data.stacked_data.stripes.len(),
        (data.area >> lsh) + 1,
        "zk masks: the round carries no extra entry"
    );
    let extras = data.stacked_data.stripes.last().expect("an extra entry").guts().as_slice();
    &extras[..region_cells(lsh)]
}

/// The layout of a shard's masks without LogUp-GKR rounds: what the
/// opening needs to place the jagged reduction's mask.
fn opening_layout() -> ZkCellLayout {
    ZkCellLayout::new(EF_DIM, &[])
}

/// The jagged reduction's mask of a main round.
pub fn jagged_mask<MT: Mmcs<F>>(data: &JaggedWhirProverDataGeneric<MT>) -> LibraMask<EF> {
    let layout = opening_layout();
    let region = zk_region(data);
    LibraMask::from_cells(&region[layout.jagged..layout.virtual_leaves], JAGGED_MASK_DEGREE)
}

/// The zerocheck's mask of a main round.
pub fn zerocheck_mask<MT: Mmcs<F>>(data: &JaggedWhirProverDataGeneric<MT>) -> LibraMask<EF> {
    let layout = opening_layout();
    let region = zk_region(data);
    LibraMask::from_cells(&region[layout.zerocheck..layout.jagged], ZEROCHECK_MASK_DEGREE)
}

/// The claim the jagged reduction leaves on its mask: `ρ·h(point) =
/// residue`, as the opening and the verifier both build it.
fn jagged_claim(rho: EF, residue: EF, point: &[EF]) -> ZkCellClaim<EF> {
    ZkCellClaim {
        value: residue,
        weights: mask_claim_weights::<F, EF>(
            opening_layout().jagged,
            JAGGED_MASK_DEGREE,
            point,
            rho,
        ),
    }
}

/// `n` uniformly random field elements from `rng`, filled in parallel from
/// per-block seeds drawn serially, so the cells are a function of `rng`
/// alone.
fn random_cells(rng: &mut StdRng, n: usize) -> Vec<F> {
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

fn random_ef(rng: &mut StdRng, n: usize) -> Vec<EF> {
    random_cells(rng, n * EF_DIM).chunks_exact(EF_DIM).map(ef_from_base).collect()
}

/// `eq(point, ·)` over `2^{point.len()}` cells, bit `j` of the index the
/// variable `j`.
fn eq_lsb(point: &[EF]) -> Vec<EF> {
    let mut table = alloc::vec![EF::ONE];
    for &z in point {
        let half = table.len();
        table.resize(2 * half, EF::ZERO);
        for x in 0..half {
            let lo = table[x];
            table[x + half] = lo * z;
            table[x] = lo - table[x + half];
        }
    }
    table
}

/// `Π_i point_i^{bit_i(x)}` over `2^{point.len()}` cells: the monomial
/// weights of the point `(y, y^2, y^4, …)` of `y`.
fn pow_lsb(point: &[EF]) -> Vec<EF> {
    let mut table = alloc::vec![EF::ONE];
    for &p in point {
        let half = table.len();
        table.extend_from_within(..);
        for v in table[half..].iter_mut() {
            *v *= p;
        }
    }
    table
}

fn dot(a: &[EF], b: &[EF]) -> EF {
    a.par_iter().zip(b.par_iter()).map(|(&x, &y)| x * y).sum()
}

/// `a ← a + c·(x^start, x^{start+1}, …)`.
fn add_powers(a: &mut [EF], c: EF, x: EF, start: u64) {
    const CHUNK: usize = 1 << 12;
    let step = x.exp_u64(CHUNK as u64);
    let first = c * x.exp_u64(start);
    let heads: Vec<EF> = core::iter::successors(Some(first), |&h| Some(h * step))
        .take(a.len().div_ceil(CHUNK))
        .collect();
    a.par_chunks_mut(CHUNK).zip(heads.into_par_iter()).for_each(|(chunk, head)| {
        let mut p = head;
        for v in chunk.iter_mut() {
            *v += p;
            p *= x;
        }
    });
}

/// Fold the low `k` bits of an index of `table` with `challenges`, the
/// first challenge on bit 0, as the folding sumcheck folds its message.
fn fold_low_bits(table: &mut Vec<EF>, challenges: &[EF]) {
    for &r in challenges {
        let half = table.len() / 2;
        for i in 0..half {
            let (lo, hi) = (table[2 * i], table[2 * i + 1]);
            table[i] = lo + r * (hi - lo);
        }
        table.truncate(half);
    }
}

/// The row polynomial with coefficients `coefficients` at `x`.
fn horner(coefficients: &[EF], x: EF) -> EF {
    coefficients.iter().rev().fold(EF::ZERO, |acc, &c| acc * x + c)
}

/// The mask coordinates `(ŝ_0(b), ŝ_1(b))` of the `2^k` rows of `σ`
/// (`k + 1` pairs): `ŝ_e(b) = Σ_j σ_{j,e}` over the `j` whose bits `j..k` of
/// `b` are all set, the values of `ŝ_e = Σ_j σ_{j,e}·X_{j+1}⋯X_k` on the
/// cube.
fn mask_rows(sigma: &[[EF; 2]]) -> Vec<[EF; 2]> {
    let k = sigma.len() - 1;
    (0..1usize << k)
        .map(|b| {
            let mut s = [EF::ZERO; 2];
            for (j, sj) in sigma.iter().enumerate() {
                if b >> j == (1usize << (k - j)) - 1 {
                    s[0] += sj[0];
                    s[1] += sj[1];
                }
            }
            s
        })
        .collect()
}

/// `U`'s weight on mask coordinate `e` of row `b`: `1` on `ŝ_0`,
/// `popcount(b)` on `ŝ_1`, so that `Σ_b weights·coordinates = Σ_b U(b)` and
/// the multilinear extension in the row variables is `U` itself.
fn mask_weight(e: usize, b: usize) -> EF {
    if e == 0 {
        EF::ONE
    } else {
        EF::from_u32(b.count_ones())
    }
}

/// Add `U`'s weights to the auxiliary block `aux` of `stage`: on the input
/// oracle each coordinate is `EF_DIM` base rows, weighed by the basis.
fn add_mask_weights(aux: &mut [EF], stage: &ZkStage, input: bool) {
    let w = stage.width;
    for e in 0..ZK_MASK_COORDS {
        for b in 0..w {
            let weight = mask_weight(e, b);
            if input {
                for u in 0..EF_DIM {
                    aux[(e * EF_DIM + u) * w + b] += weight * basis(u);
                }
            } else {
                aux[e * w + b] += weight;
            }
        }
    }
}

/// The input oracle's mask coordinates for `σ` in base rows: row
/// `e·EF_DIM + u`, column `b` holds base coordinate `u` of `ŝ_e(b)`.
fn input_mask_cells(sigma: &[[EF; 2]]) -> Vec<F> {
    let rows = mask_rows(sigma);
    let w = rows.len();
    let mut cells = alloc::vec![F::ZERO; INPUT_MASK_ROWS * w];
    for (b, s) in rows.iter().enumerate() {
        for (e, value) in s.iter().enumerate() {
            let coords = <EF as BasedVectorSpace<F>>::as_basis_coefficients_slice(value);
            for (u, &c) in coords.iter().enumerate() {
                cells[(e * EF_DIM + u) * w + b] = c;
            }
        }
    }
    cells
}

fn random_sigma(rng: &mut StdRng, width: usize) -> Vec<[EF; 2]> {
    let k = width.trailing_zeros() as usize;
    random_ef(rng, 2 * (k + 1)).chunks_exact(2).map(|p| [p[0], p[1]]).collect()
}

/// Encode base-field rows: `blocks` concatenated are the `width`-wide
/// row-major coefficients, padded to `2^domain_log` coefficients a row.
fn encode_base<D: TwoAdicSubgroupDft<F>>(
    dft: &D,
    blocks: &[&[F]],
    width: usize,
    domain_log: usize,
) -> RowMajorMatrix<F> {
    let mut coefficients = Vec::with_capacity(width << domain_log);
    for block in blocks {
        coefficients.extend_from_slice(block);
    }
    assert!(coefficients.len() <= width << domain_log, "zk encode: rows exceed the domain");
    coefficients.resize(width << domain_log, F::ZERO);
    dft.dft_batch(RowMajorMatrix::new(coefficients, width)).to_row_major_matrix()
}

/// Encode extension rows as base-coordinate leaves.
fn encode_ext<EFD: TwoAdicSubgroupDft<EF>>(
    dft: &EFD,
    coefficients: &[EF],
    width: usize,
    domain_log: usize,
) -> RowMajorMatrix<F> {
    let mut padded = coefficients.to_vec();
    assert!(padded.len() <= width << domain_log, "zk encode: rows exceed the domain");
    padded.resize(width << domain_log, EF::ZERO);
    let ef_mat = dft.dft_batch(RowMajorMatrix::new(padded, width)).to_row_major_matrix();
    let base: Vec<F> = ef_mat
        .values
        .iter()
        .flat_map(|e| <EF as BasedVectorSpace<F>>::as_basis_coefficients_slice(e).iter().copied())
        .collect();
    RowMajorMatrix::new(base, width * EF_DIM)
}

/// The stripes of a zk opening, per round: the stripes the jagged polynomial
/// covers (`area >> lsh`); the main (last) round also stores its extra entry.
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

    fn total_covered(&self) -> usize {
        self.covered.iter().sum()
    }

    /// `eq(bp, j)` of every stripe, per round, in commit order.
    fn coefficients(&self, eq_bp: &[EF]) -> Vec<Vec<EF>> {
        let mut j = 0usize;
        self.covered
            .iter()
            .map(|&c| {
                let out = eq_bp[j..j + c].to_vec();
                j += c;
                out
            })
            .collect()
    }
}

/// The main round's extra entry: the mask region, `G`'s mask coordinates,
/// then every data stripe's seeds, zero-padded to a power of two.
struct InputExtras<'a> {
    cells: &'a [F],
    masks: &'a [F],
    seeds: &'a [F],
}

fn input_extras<'a>(
    extras: &'a [F],
    stage: &ZkStage,
    lsh: usize,
    stripes: usize,
) -> InputExtras<'a> {
    let (cells, rest) = extras.split_at(region_cells(lsh));
    let (masks, rest) = rest.split_at(INPUT_MASK_ROWS * stage.width);
    InputExtras { cells, masks, seeds: &rest[..stripes * stage.seeds * stage.width] }
}

/// Commit one round of the zk ring over the jagged layer's stripes (the
/// `DEFAULT_BATCH_SIZE`-wide interleaves of one dense polynomial of `area`
/// cells, as [`super::jagged::commit_jagged_whir_from_stripes`] takes
/// them), every stripe a hiding row block.  A `main` round draws fresh
/// seeds, `G`'s masks and the mask region, and stores them after its
/// stripes; a preprocessed round has zero seeds and is deterministic.
///
/// The commit's `area` and `log_stacking_height` stay the jagged layer's:
/// the verifier derives the committed stripe count from the area alone.
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
    for poly in &polys {
        assert_eq!(poly.guts().as_slice().len(), 1usize << lsh, "zk commit: a short stripe");
    }
    let stage = zk_stages(&config, lsh)[0];
    assert!(
        region_cells(lsh) >= opening_layout().end,
        "zk commit: the masks do not fit the mask region of a stack of height 2^{lsh}"
    );
    let w = stage.width;
    let mut stored = polys.clone();
    let matrices: Vec<RowMajorMatrix<F>> = if main {
        let mut rng = StdRng::from_entropy();
        let cells = random_cells(&mut rng, region_cells(lsh));
        let masks = input_mask_cells(&random_sigma(&mut rng, w));
        let seeds = random_cells(&mut rng, polys.len() * stage.seeds * w);
        let last = polys.len() - 1;
        let matrices = polys
            .iter()
            .enumerate()
            .map(|(j, poly)| {
                let seed = &seeds[j * stage.seeds * w..(j + 1) * stage.seeds * w];
                let data = poly.guts().as_slice();
                if j == last {
                    encode_base(dft.as_ref(), &[seed, data, &masks, &cells], w, stage.domain_log)
                } else {
                    encode_base(dft.as_ref(), &[seed, data], w, stage.domain_log)
                }
            })
            .collect();
        let mut extras =
            Vec::with_capacity((cells.len() + masks.len() + seeds.len()).next_power_of_two());
        extras.extend_from_slice(&cells);
        extras.extend_from_slice(&masks);
        extras.extend_from_slice(&seeds);
        extras.resize(extras.len().next_power_of_two(), F::ZERO);
        stored.push(Arc::new(Mle::from_values(extras)));
        matrices
    } else {
        let zeros = alloc::vec![F::ZERO; stage.seeds * w];
        polys
            .iter()
            .map(|poly| {
                encode_base(dft.as_ref(), &[&zeros, poly.guts().as_slice()], w, stage.domain_log)
            })
            .collect()
    };

    let (commitment, prover_data) = mmcs.commit(matrices);
    let stacked_data =
        StackedWhirProverData { stripes: stored, prover_data, commitment: commitment.clone() };
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

/// The message of the next stage: the folded main block, then an auxiliary
/// block of fresh mask coordinates, the folded auxiliary block and seeds,
/// and a uniform pad, under fresh seeds.
fn next_message(rng: &mut StdRng, stage: &ZkStage, next: &ZkStage, folded: &[EF]) -> Vec<EF> {
    debug_assert_eq!(folded.len(), stage.coefficients());
    debug_assert_eq!(next.main_len(), stage.main);
    debug_assert_eq!(next.carried, stage.aux + stage.seeds);
    let mut msg = alloc::vec![EF::ZERO; next.len()];
    msg[..next.main_offset()].copy_from_slice(&random_ef(rng, next.main_offset()));
    msg[next.main_offset()..next.aux_offset()]
        .copy_from_slice(&folded[stage.seeds..stage.seeds + stage.main]);
    let aux = &mut msg[next.aux_offset()..];
    let w = next.width;
    for (b, s) in mask_rows(&random_sigma(rng, w)).iter().enumerate() {
        aux[b] = s[0];
        aux[w + b] = s[1];
    }
    let carried = next.carried_offset();
    aux[carried..carried + stage.aux].copy_from_slice(&folded[stage.seeds + stage.main..]);
    aux[carried + stage.aux..carried + next.carried].copy_from_slice(&folded[..stage.seeds]);
    let pad = next.aux_len() - carried - next.carried;
    aux[carried + next.carried..].copy_from_slice(&random_ef(rng, pad));
    msg
}

/// The zk sibling of [`super::jagged::open_jagged_whir_rounds_generic`]:
/// one batched opening of every round committed by
/// [`commit_zk_whir_round`] at `eval_point` (stack coordinates first, then
/// the batch coordinates), under `config`, the shrink schedule.  The
/// transcript is the module's: `μ`, then per stage `µ̃`, `ε`, the folding
/// sumcheck and, but for the last stage, the next commitment, its
/// out-of-domain answers and the queries; then `µ⋆`, `γ⋆`, `D` and the final
/// queries.
///
/// `masks`: the shard's claims on the mask region and the jagged
/// reduction's mask challenge `ρ`, whose claim the opening builds at
/// `eval_point`; `None` opens without cell claims, as the unit tests of the
/// opening do.
#[allow(clippy::too_many_arguments)]
pub fn open_zk_whir_rounds<Challenger, MT, D, EFD>(
    rounds: &[&JaggedWhirProverDataGeneric<MT>],
    eval_point: Vec<EF>,
    masks: Option<(&[ZkCellClaim<EF>], EF)>,
    challenger: &mut Challenger,
    mmcs: MT,
    _dft: Arc<D>,
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
    assert!(eval_point.len() >= lsh, "zk open: the point is shorter than the stacking height");
    assert!(
        config.starting_ood_samples == 0,
        "zk open: the stacked schedule carries its OOD in round constraints"
    );
    let stages = zk_stages(&config, lsh);
    let n = stages.len();
    let (sp, bp) = eval_point.split_at(lsh);
    let layout = ZkLayout::new(rounds.iter().map(|r| r.area >> lsh).collect());
    for (r, round) in rounds.iter().enumerate() {
        assert_eq!(round.log_stacking_height as usize, lsh, "zk open: rounds disagree on height");
        let stored = layout.covered[r] + usize::from(r == layout.main());
        assert_eq!(
            round.stacked_data.stripes.len(),
            stored,
            "zk open: round {r} stores {} entries, its area says {stored}",
            round.stacked_data.stripes.len(),
        );
    }
    tracing::debug!(covered = ?layout.covered, stages = ?stages, "zk opening");
    let eq_bp = eq_lsb(bp);
    assert!(layout.total_covered() <= eq_bp.len(), "zk open: more stripes than batch points");
    let coefficients = layout.coefficients(&eq_bp);
    let main_round = rounds[layout.main()];
    let main_stripes = layout.covered[layout.main()];
    assert!(main_stripes > 0, "zk open: the main round covers no stripe");
    let last_coefficient = coefficients[layout.main()][main_stripes - 1];

    let input = stages[0];
    let w = input.width;
    let extras = input_extras(
        main_round.stacked_data.stripes[main_stripes].guts().as_slice(),
        &input,
        lsh,
        main_stripes,
    );
    let mut msg = alloc::vec![EF::ZERO; input.len()];
    let seed_len = input.seeds * w;
    for (j, &g) in coefficients[layout.main()].iter().enumerate() {
        for (m, &s) in
            msg[..seed_len].iter_mut().zip(&extras.seeds[j * seed_len..(j + 1) * seed_len])
        {
            *m += g * s;
        }
    }
    {
        let weighted: Vec<(&[F], EF)> = rounds
            .iter()
            .zip(&coefficients)
            .flat_map(|(round, gs)| {
                round.stacked_data.stripes.iter().zip(gs).map(|(s, &g)| (s.guts().as_slice(), g))
            })
            .collect();
        let data = lambda_combination(&weighted, 1usize << lsh);
        msg[input.main_offset()..input.aux_offset()].copy_from_slice(&data);
    }
    for (m, &c) in msg[input.aux_offset()..].iter_mut().zip(extras.masks.iter().chain(extras.cells))
    {
        *m = last_coefficient * c;
    }

    let claims: Vec<ZkCellClaim<EF>> = masks
        .map(|(shard_claims, rho)| {
            let mut claims = shard_claims.to_vec();
            claims.push(jagged_claim(
                rho,
                rho * jagged_mask(main_round).evaluate(&eval_point),
                &eval_point,
            ));
            claims
        })
        .unwrap_or_default();
    let mu: EF = challenger.sample_algebra_element();
    let mut real = alloc::vec![EF::ZERO; input.len()];
    real[input.main_offset()..input.aux_offset()].copy_from_slice(&eq_lsb(sp));
    {
        let cells_at = input.aux_offset() + INPUT_MASK_ROWS * w;
        let region = region_cells(lsh);
        let mut power = mu;
        for c in &claims {
            for &(o, weight) in &c.weights {
                assert!(o < region, "zk open: a claim on cell {o} outside the mask region");
                real[cells_at + o] += power * weight;
            }
            power *= mu;
        }
    }

    let mut rng = StdRng::from_entropy();
    let mut sent: Vec<EF> = Vec::with_capacity(n + 1);
    let mut round_sumcheck_polys = Vec::new();
    let mut final_sumcheck_polys = Vec::new();
    let mut round_ood_answers: Vec<Vec<EF>> = Vec::new();
    let mut round_commitments: Vec<MT::Commitment> = Vec::new();
    let mut round_query_openings: Vec<MerkleOpening<F, MT>> = Vec::new();
    let mut folding_pow: Vec<ProofOfWork<F>> = Vec::new();
    let mut prev_tree: Option<MT::ProverData<RowMajorMatrix<F>>> = None;
    let mut mask_row: Vec<EF> = Vec::new();
    let mut disclosed: Vec<EF> = Vec::new();
    let mut final_pow = ProofOfWork(F::ZERO);

    for s in 0..n {
        let stage = stages[s];
        let round_cfg = &config.round_parameters[s];
        let mut mask_weights = alloc::vec![EF::ZERO; stage.aux_len()];
        add_mask_weights(&mut mask_weights, &stage, s == 0);
        let mu_tilde = dot(&mask_weights, &msg[stage.aux_offset()..]);
        challenger.observe_algebra_element(mu_tilde);
        sent.push(mu_tilde);
        let eps: EF = challenger.sample_algebra_element();
        let mut weight: Vec<EF> = real.par_iter().map(|&x| x * eps).collect();
        for (x, &m) in weight[stage.aux_offset()..].iter_mut().zip(&mask_weights) {
            *x += m;
        }
        let claimed_sum = dot(&weight, &msg);
        let mut folder = WhirFolder { f_vec: msg, weight, claimed_sum };
        let mut gamma = Vec::with_capacity(round_cfg.folding_factor);
        let polys = folder.fold_variables::<F, _>(
            round_cfg.folding_factor,
            &round_cfg.pow_bits,
            challenger,
            &mut gamma,
        );
        let sumcheck: Vec<_> = polys.iter().map(|(p, _)| p.clone()).collect();
        folding_pow.extend(polys.into_iter().map(|(_, pow)| pow));
        let WhirFolder { f_vec: folded, weight: folded_weight, .. } = folder;

        if s + 1 == n {
            final_sumcheck_polys = sumcheck;
            let mu_star = dot(&folded_weight, &mask_row);
            challenger.observe_algebra_element(mu_star);
            sent.push(mu_star);
            let gamma_star: EF = challenger.sample_algebra_element();
            disclosed = mask_row.iter().zip(&folded).map(|(&g, &f)| g + gamma_star * f).collect();
            for d in &disclosed {
                challenger.observe_algebra_element(*d);
            }
            final_pow = ProofOfWork(crate::whir::grind::accelerated_grind(
                challenger,
                config.final_pow_bits,
            ));
            let tree = prev_tree.as_ref().expect("a folded oracle");
            let domain_mask = (1usize << stage.domain_log) - 1;
            let leaves = (0..config.final_queries)
                .map(|_| {
                    let idx = challenger.sample_bits(stage.domain_log) & domain_mask;
                    let opening = mmcs.open_batch(idx, tree);
                    LeafOpening { values: opening.opened_values, proof: opening.opening_proof }
                })
                .collect();
            round_query_openings.push(MerkleOpening { leaves });
            break;
        }
        round_sumcheck_polys.push(sumcheck);

        let next = stages[s + 1];
        let next_msg = next_message(&mut rng, &stage, &next, &folded);
        let mut matrices =
            alloc::vec![encode_ext(ef_dft.as_ref(), &next_msg, next.width, next.domain_log)];
        if s + 2 == n {
            mask_row = random_ef(&mut rng, next.coefficients());
            matrices.push(encode_ext(ef_dft.as_ref(), &mask_row, 1, next.domain_log));
        }
        let (commitment, this_tree) = mmcs.commit(matrices);
        challenger.observe(commitment.clone());
        round_commitments.push(commitment);

        let next_main = &next_msg[next.main_offset()..next.aux_offset()];
        let next_aux = &next_msg[next.aux_offset()..];
        let mut ood_points: Vec<(Vec<EF>, Vec<EF>)> = Vec::with_capacity(round_cfg.ood_samples);
        let mut ood_answers = Vec::with_capacity(round_cfg.ood_samples);
        for _ in 0..round_cfg.ood_samples {
            let pt: Vec<EF> =
                (0..next.main_vars()).map(|_| challenger.sample_algebra_element()).collect();
            let pt_aux: Vec<EF> =
                (0..next.aux_vars()).map(|_| challenger.sample_algebra_element()).collect();
            let answer =
                dot(&eq_lsb(&pt), next_main) + dot(&eq_lsb(&pt_aux)[..next.aux_len()], next_aux);
            challenger.observe_algebra_element(answer);
            ood_points.push((pt, pt_aux));
            ood_answers.push(answer);
        }
        round_ood_answers.push(ood_answers);

        folding_pow.push(ProofOfWork(crate::whir::grind::accelerated_grind(
            challenger,
            round_cfg.queries_pow_bits,
        )));
        let domain_mask = (1usize << stage.domain_log) - 1;
        let indices: Vec<usize> = (0..round_cfg.num_queries)
            .map(|_| challenger.sample_bits(stage.domain_log) & domain_mask)
            .collect();
        let generator = EF::two_adic_generator(stage.domain_log);
        let mut leaves_open = Vec::with_capacity(indices.len());
        let mut points = Vec::with_capacity(indices.len());
        for &idx in &indices {
            match prev_tree.as_ref() {
                None => {
                    for round in rounds.iter() {
                        let opening = mmcs.open_batch(idx, &round.stacked_data.prover_data);
                        leaves_open.push(LeafOpening {
                            values: opening.opened_values,
                            proof: opening.opening_proof,
                        });
                    }
                }
                Some(tree) => {
                    let opening = mmcs.open_batch(idx, tree);
                    leaves_open.push(LeafOpening {
                        values: opening.opened_values,
                        proof: opening.opening_proof,
                    });
                }
            }
            points.push(generator.exp_u64(idx as u64));
        }
        round_query_openings.push(MerkleOpening { leaves: leaves_open });

        let rho: EF = challenger.sample_algebra_element();
        let mut next_real = alloc::vec![EF::ZERO; next.len()];
        next_real[next.main_offset()..next.aux_offset()]
            .copy_from_slice(&folded_weight[stage.seeds..stage.seeds + stage.main]);
        {
            let aux = &mut next_real[next.aux_offset()..];
            let carried = next.carried_offset();
            aux[carried..carried + stage.aux]
                .copy_from_slice(&folded_weight[stage.seeds + stage.main..]);
            aux[carried + stage.aux..carried + next.carried]
                .copy_from_slice(&folded_weight[..stage.seeds]);
        }
        let mut c = rho;
        for (pt, pt_aux) in &ood_points {
            let main_eq = eq_lsb(pt);
            next_real[next.main_offset()..next.aux_offset()]
                .par_iter_mut()
                .zip(main_eq.par_iter())
                .for_each(|(x, &e)| *x += c * e);
            let aux_eq = eq_lsb(pt_aux);
            for (x, &e) in next_real[next.aux_offset()..].iter_mut().zip(&aux_eq) {
                *x += c * e;
            }
            c *= rho;
        }
        for &x in &points {
            add_powers(
                &mut next_real[next.main_offset()..next.aux_offset()],
                c,
                x,
                stage.seeds as u64,
            );
            let carried = next.aux_offset() + next.carried_offset();
            add_powers(
                &mut next_real[carried..carried + stage.aux],
                c,
                x,
                (stage.seeds + stage.main) as u64,
            );
            add_powers(&mut next_real[carried + stage.aux..carried + next.carried], c, x, 0);
            c *= rho;
        }

        msg = next_msg;
        real = next_real;
        prev_tree = Some(this_tree);
    }

    StackedWhirProof {
        whir_proof: WhirProof {
            round_sumcheck_polys,
            round_ood_answers,
            round_commitments,
            round_query_openings,
            final_poly: disclosed,
            final_sumcheck_polys,
            folding_pow,
            final_pow,
        },
        batch_evaluations: alloc::vec![sent],
        batch_grinding_witness: F::ZERO,
    }
}

/// A main-block constraint the verifier tracks to the end: `coeff·eq(point,
/// ·)` or `coeff·Π_i point_i^{bit_i(·)}` over the `vars` main variables of
/// the stage that added it.
enum MainConstraint {
    Lagrange { point: Vec<EF>, coeff: EF, vars: usize },
    Monomial { point: Vec<EF>, coeff: EF, vars: usize },
}

/// The zk sibling of [`super::jagged::verify_jagged_whir_rounds`]: verify
/// an [`open_zk_whir_rounds`] proof of `commitments` (one per round, areas
/// in `round_areas`) at `point` against `evaluation_claim`, the jagged
/// layer's claim on the dense polynomial.
///
/// `masks`: the shard's claims on the mask region, and the jagged
/// reduction's mask challenge `ρ` with the residue `ρ·h(point)` its masked
/// sumcheck left; `None` on an opening without cell claims.
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
    masks: Option<(&[ZkCellClaim<EF>], (EF, EF))>,
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
    let n = config.round_parameters.len();
    let folds: Vec<usize> = config.round_parameters.iter().map(|rp| rp.folding_factor).collect();
    if n < 2 || folds.iter().sum::<usize>() > lsh || config.starting_ood_samples != 0 {
        return Err(shape("schedule"));
    }
    let stages = zk_stages(&config, lsh);
    let whir = &proof.whir_proof;
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
        let non_final = n - 1;
        expect("round_commitments", whir.round_commitments.len(), non_final)?;
        expect("round_ood_answers", whir.round_ood_answers.len(), non_final)?;
        expect("round_sumcheck_polys", whir.round_sumcheck_polys.len(), non_final)?;
        expect("round_query_openings", whir.round_query_openings.len(), n)?;
        expect("final_sumcheck_polys", whir.final_sumcheck_polys.len(), folds[n - 1])?;
        expect("folding_pow", whir.folding_pow.len(), folds.iter().sum::<usize>() + non_final)?;
        expect("final_poly", whir.final_poly.len(), stages[n - 1].coefficients())?;
    }
    let sent = match proof.batch_evaluations.as_slice() {
        [values] if values.len() == n + 1 => values,
        _ => return Err(shape("mask sums")),
    };
    if proof.batch_grinding_witness != F::ZERO {
        return Err(shape("batch grinding witness"));
    }

    let eq_bp = eq_lsb(bp);
    let coefficients = layout.coefficients(&eq_bp);
    let main_stripes = layout.covered[layout.main()];
    let last_coefficient = coefficients[layout.main()][main_stripes - 1];
    if last_coefficient == EF::ZERO {
        return Err(WhirVerifierError::DegenerateChallenge(
            "the main round's last stripe has a zero batch coefficient, so G carries no mask"
                .into(),
        ));
    }
    let input = stages[0];

    let mu: EF = challenger.sample_algebra_element();
    let mut target = evaluation_claim;
    let mut aux_real = alloc::vec![EF::ZERO; input.aux_len()];
    if let Some((shard_claims, (rho, residue))) = masks {
        if point.len() > crate::zk_mask::ZK_MASK_MAX_VARS {
            return Err(shape("mask point"));
        }
        let region = region_cells(lsh);
        let cells_at = INPUT_MASK_ROWS * input.width;
        let mut power = mu;
        for c in shard_claims.iter().chain(core::iter::once(&jagged_claim(rho, residue, point))) {
            target += power * last_coefficient * c.value;
            for &(o, weight) in &c.weights {
                if o >= region {
                    return Err(shape("a claim on a cell outside the mask region"));
                }
                aux_real[cells_at + o] += power * weight;
            }
            power *= mu;
        }
    }
    let mut constraints: Vec<MainConstraint> =
        alloc::vec![MainConstraint::Lagrange { point: sp.to_vec(), coeff: EF::ONE, vars: lsh }];

    let verify_input_leaf = |leaf: &LeafOpening<F, MT>,
                             ri: usize,
                             idx: usize,
                             row: &mut [EF]|
     -> Result<(), WhirVerifierError> {
        let stripes = layout.covered[ri];
        if leaf.values.len() != stripes {
            return Err(shape("stripe rows"));
        }
        let dims: Vec<p3_matrix::Dimensions> = (0..stripes)
            .map(|_| p3_matrix::Dimensions {
                width: input.width,
                height: 1usize << input.domain_log,
            })
            .collect();
        let opened =
            p3_commit::BatchOpeningRef { opened_values: &leaf.values, opening_proof: &leaf.proof };
        mmcs.verify_batch(&commitments[ri], &dims, idx, opened).map_err(|_| shape("merkle"))?;
        for (values, &g) in leaf.values.iter().zip(&coefficients[ri]) {
            if values.len() != input.width {
                return Err(shape("stripe row width"));
            }
            for (v, &x) in row.iter_mut().zip(values.iter()) {
                *v += g * x;
            }
        }
        Ok(())
    };
    let verify_folded_leaf = |leaf: &LeafOpening<F, MT>,
                              commitment: &<MT as Mmcs<F>>::Commitment,
                              idx: usize,
                              stage: &ZkStage,
                              with_mask: bool|
     -> Result<(Vec<EF>, EF), WhirVerifierError> {
        let matrices = 1 + usize::from(with_mask);
        if leaf.values.len() != matrices
            || leaf.values[0].len() != stage.width * EF_DIM
            || (with_mask && leaf.values[1].len() != EF_DIM)
        {
            return Err(shape("folded row"));
        }
        let mut dims = alloc::vec![p3_matrix::Dimensions {
            width: stage.width * EF_DIM,
            height: 1usize << stage.domain_log
        }];
        if with_mask {
            dims.push(p3_matrix::Dimensions { width: EF_DIM, height: 1usize << stage.domain_log });
        }
        let opened =
            p3_commit::BatchOpeningRef { opened_values: &leaf.values, opening_proof: &leaf.proof };
        mmcs.verify_batch(commitment, &dims, idx, opened).map_err(|_| shape("merkle"))?;
        let row = leaf.values[0].chunks_exact(EF_DIM).map(ef_from_base).collect();
        let g = if with_mask { ef_from_base(&leaf.values[1]) } else { EF::ZERO };
        Ok((row, g))
    };
    let row_fold = |row: Vec<EF>, gamma: &[EF]| -> EF {
        Mle::from_row_major(RowMajorMatrix::new(row, 1)).eval_at::<EF>(gamma)[0]
    };

    let mut all_fr: Vec<EF> = Vec::with_capacity(lsh);
    let mut pow_flat = 0usize;
    let mut claim = EF::ZERO;
    let mut gamma: Vec<EF> = Vec::new();
    let mut folded_aux: Vec<EF> = Vec::new();
    for s in 0..n {
        let stage = stages[s];
        let round_cfg = &config.round_parameters[s];
        let mu_tilde = sent[s];
        challenger.observe_algebra_element(mu_tilde);
        let eps: EF = challenger.sample_algebra_element();
        for c in constraints.iter_mut() {
            match c {
                MainConstraint::Lagrange { coeff, .. } | MainConstraint::Monomial { coeff, .. } => {
                    *coeff *= eps
                }
            }
        }
        for x in aux_real.iter_mut() {
            *x *= eps;
        }
        add_mask_weights(&mut aux_real, &stage, s == 0);
        claim = mu_tilde + eps * target;

        let msgs = if s + 1 == n {
            &whir.final_sumcheck_polys
        } else {
            whir.round_sumcheck_polys.get(s).ok_or_else(|| shape("round messages"))?
        };
        if msgs.len() != round_cfg.folding_factor {
            return Err(shape("round messages"));
        }
        gamma = Vec::with_capacity(round_cfg.folding_factor);
        for (var, poly) in msgs.iter().enumerate() {
            let c = &poly.0;
            if c.len() != 3 {
                return Err(shape("degree-2"));
            }
            let (c0, c1, c2) = (c[0], c[1], c[2]);
            if c0 + (c0 + c1 + c2) != claim {
                return Err(WhirVerifierError::SumcheckMismatch { round: s, var });
            }
            challenger.observe_algebra_element(c0);
            challenger.observe_algebra_element(c1);
            challenger.observe_algebra_element(c2);
            let pow = whir.folding_pow.get(pow_flat).ok_or_else(|| shape("folding pow"))?;
            pow_flat += 1;
            if !challenger.check_witness(round_cfg.pow_bits.get(var).copied().unwrap_or(0), pow.0) {
                return Err(WhirVerifierError::PowMismatch { round: s, var });
            }
            let r: EF = challenger.sample_algebra_element();
            claim = c0 + c1 * r + c2 * r * r;
            all_fr.push(r);
            gamma.push(r);
        }
        folded_aux = aux_real.clone();
        fold_low_bits(&mut folded_aux, &gamma);
        if s + 1 == n {
            break;
        }

        let next = stages[s + 1];
        challenger.observe(
            whir.round_commitments.get(s).ok_or_else(|| shape("round commitment"))?.clone(),
        );
        let ood_answers = whir.round_ood_answers.get(s).ok_or_else(|| shape("round ood"))?;
        if ood_answers.len() != round_cfg.ood_samples {
            return Err(shape("round ood count"));
        }
        let mut ood_points: Vec<(Vec<EF>, Vec<EF>)> = Vec::with_capacity(ood_answers.len());
        for answer in ood_answers.iter() {
            let pt: Vec<EF> =
                (0..next.main_vars()).map(|_| challenger.sample_algebra_element()).collect();
            let pt_aux: Vec<EF> =
                (0..next.aux_vars()).map(|_| challenger.sample_algebra_element()).collect();
            challenger.observe_algebra_element(*answer);
            ood_points.push((pt, pt_aux));
        }

        let query_pow = whir.folding_pow.get(pow_flat).ok_or_else(|| shape("query pow"))?;
        pow_flat += 1;
        if !challenger.check_witness(round_cfg.queries_pow_bits, query_pow.0) {
            return Err(WhirVerifierError::PowMismatch { round: s, var: usize::MAX });
        }
        let domain_mask = (1usize << stage.domain_log) - 1;
        let indices: Vec<usize> = (0..round_cfg.num_queries)
            .map(|_| challenger.sample_bits(stage.domain_log) & domain_mask)
            .collect();
        let openings =
            whir.round_query_openings.get(s).ok_or_else(|| shape("round query openings"))?;
        let leaves_per_query = if s == 0 { commitments.len() } else { 1 };
        if openings.leaves.len() != indices.len() * leaves_per_query {
            return Err(shape("query openings"));
        }
        let generator = EF::two_adic_generator(stage.domain_log);
        let mut stir: Vec<(EF, EF)> = Vec::with_capacity(indices.len());
        for (qi, &idx) in indices.iter().enumerate() {
            let row = if s == 0 {
                let mut row = alloc::vec![EF::ZERO; input.width];
                for ri in 0..commitments.len() {
                    verify_input_leaf(
                        &openings.leaves[qi * leaves_per_query + ri],
                        ri,
                        idx,
                        &mut row,
                    )?;
                }
                row
            } else {
                let commitment =
                    whir.round_commitments.get(s - 1).ok_or_else(|| shape("prev commitment"))?;
                verify_folded_leaf(&openings.leaves[qi], commitment, idx, &stage, false)?.0
            };
            stir.push((generator.exp_u64(idx as u64), row_fold(row, &gamma)));
        }

        let rho: EF = challenger.sample_algebra_element();
        target = claim;
        let mut next_aux = alloc::vec![EF::ZERO; next.aux_len()];
        let carried = next.carried_offset();
        next_aux[carried..carried + stage.aux].copy_from_slice(&folded_aux);
        let mut c = rho;
        for ((pt, pt_aux), &answer) in ood_points.into_iter().zip(ood_answers) {
            target += c * answer;
            for (x, &e) in next_aux.iter_mut().zip(&eq_lsb(&pt_aux)) {
                *x += c * e;
            }
            constraints.push(MainConstraint::Lagrange {
                point: pt,
                coeff: c,
                vars: next.main_vars(),
            });
            c *= rho;
        }
        for (x, value) in stir {
            target += c * value;
            add_powers(
                &mut next_aux[carried..carried + stage.aux],
                c,
                x,
                (stage.seeds + stage.main) as u64,
            );
            add_powers(&mut next_aux[carried + stage.aux..carried + next.carried], c, x, 0);
            constraints.push(MainConstraint::Monomial {
                point: map_to_pow_lsb(x, next.main_vars()),
                coeff: c * x.exp_u64(stage.seeds as u64),
                vars: next.main_vars(),
            });
            c *= rho;
        }
        aux_real = next_aux;
    }

    let last = stages[n - 1];
    let mu_star = sent[n];
    challenger.observe_algebra_element(mu_star);
    let gamma_star: EF = challenger.sample_algebra_element();
    let disclosed = &whir.final_poly;
    for d in disclosed.iter() {
        challenger.observe_algebra_element(*d);
    }
    if !challenger.check_witness(config.final_pow_bits, whir.final_pow.0) {
        return Err(WhirVerifierError::PowMismatch { round: n, var: usize::MAX });
    }
    let final_openings =
        whir.round_query_openings.get(n - 1).ok_or_else(|| shape("final openings"))?;
    if final_openings.leaves.len() != config.final_queries {
        return Err(shape("final query count"));
    }
    let last_commitment =
        whir.round_commitments.get(n - 2).ok_or_else(|| shape("final commitment"))?;
    let generator = EF::two_adic_generator(last.domain_log);
    let domain_mask = (1usize << last.domain_log) - 1;
    for leaf in &final_openings.leaves {
        let idx = challenger.sample_bits(last.domain_log) & domain_mask;
        let (row, g) = verify_folded_leaf(leaf, last_commitment, idx, &last, true)?;
        let x = generator.exp_u64(idx as u64);
        if horner(disclosed, x) != g + gamma_star * row_fold(row, &gamma) {
            return Err(WhirVerifierError::TerminalMismatch);
        }
    }

    let _final_span =
        tracing::info_span!("zk_whir_final_check", constraints = constraints.len()).entered();
    let final_log = last.main_vars() - folds[n - 1];
    let lagrange_eq = |a: &[EF], b: &[EF]| -> EF {
        a.iter().zip(b).map(|(&x, &y)| x * y + (EF::ONE - x) * (EF::ONE - y)).product()
    };
    let monomial_fold = |a: &[EF], b: &[EF]| -> EF {
        a.iter().zip(b).map(|(&x, &y)| EF::ONE - y + y * x).product()
    };
    let mut main_weight = alloc::vec![EF::ZERO; 1usize << final_log];
    for c in &constraints {
        let (table, factor) = match c {
            MainConstraint::Lagrange { point: p, coeff, vars } => {
                let k = vars - final_log;
                let offset = lsh - vars;
                (eq_lsb(&p[k..]), *coeff * lagrange_eq(&p[..k], &all_fr[offset..offset + k]))
            }
            MainConstraint::Monomial { point: p, coeff, vars } => {
                let k = vars - final_log;
                let offset = lsh - vars;
                (pow_lsb(&p[k..]), *coeff * monomial_fold(&p[..k], &all_fr[offset..offset + k]))
            }
        };
        for (x, &t) in main_weight.iter_mut().zip(&table) {
            *x += factor * t;
        }
    }
    let main_part: EF = main_weight
        .iter()
        .zip(&disclosed[last.seeds..last.seeds + last.main])
        .map(|(&a, &b)| a * b)
        .sum();
    let aux_part: EF =
        folded_aux.iter().zip(&disclosed[last.seeds + last.main..]).map(|(&a, &b)| a * b).sum();
    if main_part + aux_part != mu_star + gamma_star * claim {
        return Err(WhirVerifierError::TerminalMismatch);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jagged_pcs::{jagged_mmcs, JaggedChallenger, JaggedMmcs};
    use crate::whir::jagged::whir_config_for_fold_schedule;
    use crate::whir::stacked::eq_weighted_sum;
    use crate::whir::stripes::interleave_multilinears_with_fixed_rate;
    use p3_dft::Radix2DitParallel;
    use zkm_primitives::poseidon2_init;

    const LSH: usize = 11;

    fn challenger() -> JaggedChallenger {
        JaggedChallenger::new(poseidon2_init())
    }

    fn config() -> WhirConfig {
        let mut cfg = whir_config_for_fold_schedule(LSH, &[4, 3, 3], 1);
        for rp in cfg.round_parameters.iter_mut() {
            rp.num_queries = 5;
        }
        cfg.final_queries = 5;
        cfg.batch_pow_bits = 0;
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

    /// The claims an honest shard would hand the opening: the zerocheck's
    /// `ρ·g(z) = residue`, one claim on the virtual cells, and the jagged
    /// reduction's challenge with its residue `ρ'·h(z*)`.
    fn mask_claims(inst: &Instance) -> (Vec<ZkCellClaim<EF>>, (EF, EF)) {
        let layout = ZkCellLayout::new(EF_DIM, &[]);
        let region = zk_region(&inst.main);
        let rho_z = EF::from_u32(RHO_ZEROCHECK);
        let zerocheck = ZkCellClaim {
            value: rho_z * zerocheck_mask(&inst.main).evaluate(&inst.zerocheck_point),
            weights: crate::zk_mask::mask_claim_weights::<F, EF>(
                layout.zerocheck,
                ZEROCHECK_MASK_DEGREE,
                &inst.zerocheck_point,
                rho_z,
            ),
        };
        let weights: Vec<(usize, EF)> = (0..3)
            .flat_map(|k| {
                crate::zk_mask::ef_cell_weights::<F, EF>(
                    layout.virtual_leaves + k * EF_DIM,
                    EF::from_u32(7 + k as u32),
                )
            })
            .collect();
        let virtual_cells = ZkCellClaim {
            value: crate::zk_mask::claim_over_cells::<F, EF>(&weights, region),
            weights,
        };
        let rho_j = EF::from_u32(RHO_JAGGED);
        (
            alloc::vec![zerocheck, virtual_cells],
            (rho_j, rho_j * jagged_mask(&inst.main).evaluate(&inst.point)),
        )
    }

    /// Two rounds (3 + 2 stripes, 8 batch slots) and the dense polynomial's
    /// evaluation at `point`, the claim the jagged layer would reduce to.
    fn instance(seed: u64) -> Instance {
        instance_with(seed, false)
    }

    /// [`instance`], with the batch point's top coordinate zero when
    /// `zero_last`: stripe 4, the main round's last, then has `eq(bp, 4) = 0`.
    fn instance_with(seed: u64, zero_last: bool) -> Instance {
        let mut rng = StdRng::seed_from_u64(seed);
        let (prep_cells, prep) = commit_round(&mut rng, 3, false);
        let (main_cells, main) = commit_round(&mut rng, 2, true);
        let mut point: Vec<EF> = (0..LSH + 3).map(|_| rand_ef(&mut rng)).collect();
        if zero_last {
            point[LSH + 2] = EF::ZERO;
        }
        let eq_sp = eq_lsb(&point[..LSH]);
        let eq_bp = eq_lsb(&point[LSH..]);
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
        let (claims, (rho_j, _)) = mask_claims(inst);
        open_zk_whir_rounds::<JaggedChallenger, JaggedMmcs, _, _>(
            &[&inst.prep, &inst.main],
            inst.point.clone(),
            masked.then_some((claims.as_slice(), rho_j)),
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
        masks: Option<(&[ZkCellClaim<EF>], (EF, EF))>,
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
        let (claims, jagged) = mask_claims(inst);
        verify_with(inst, proof, claim, Some((claims.as_slice(), jagged)))
    }

    /// The committed rows: a preprocessed stripe's row `b` is `X^T·data_b(X)`
    /// on the stage-0 domain, the same on every commit; a main round draws
    /// fresh seeds and masks on every commit.
    #[test]
    fn rounds_commit_the_hiding_rows() {
        let stage = zk_stages(&config(), LSH)[0];
        let w = stage.width;
        let (cells, prep) = commit_round(&mut StdRng::seed_from_u64(1), 3, false);
        let (_, again) = commit_round(&mut StdRng::seed_from_u64(1), 3, false);
        assert_eq!(again.stacked_data.commitment, prep.stacked_data.commitment);
        let matrices = jagged_mmcs().get_matrices(&prep.stacked_data.prover_data);
        let generator = F::two_adic_generator(stage.domain_log);
        for idx in [0usize, 1, 77, (1 << stage.domain_log) - 1] {
            let x = generator.exp_u64(idx as u64);
            for (m, data) in matrices.iter().zip(&cells) {
                let row = m.row_slice(idx).expect("a row").to_vec();
                for (b, &value) in row.iter().enumerate() {
                    let data_b: Vec<F> = data.iter().skip(b).step_by(w).copied().collect();
                    let expected = x.exp_u64(stage.seeds as u64)
                        * data_b.iter().rev().fold(F::ZERO, |acc, &c| acc * x + c);
                    assert_eq!(value, expected, "row {b} at index {idx}");
                }
            }
        }

        let (_, main) = commit_round(&mut StdRng::seed_from_u64(2), 2, true);
        let (_, other) = commit_round(&mut StdRng::seed_from_u64(2), 2, true);
        assert_ne!(other.stacked_data.commitment, main.stacked_data.commitment);
        assert_ne!(zk_region(&other), zk_region(&main));
    }

    /// The mask coordinates are the values of `U`'s factors on the cube, so
    /// the weights `1, popcount(b)` sum them to `Σ_b U(b)`, and the folded
    /// coordinates give `U` at any point.
    #[test]
    fn mask_rows_are_the_mask_polynomial() {
        let mut rng = StdRng::seed_from_u64(3);
        let k = 3;
        let sigma: Vec<[EF; 2]> = (0..=k).map(|_| [rand_ef(&mut rng), rand_ef(&mut rng)]).collect();
        let s_hat = |e: usize, x: &[EF]| -> EF {
            (0..=k).map(|j| sigma[j][e] * x[j..].iter().copied().product::<EF>()).sum()
        };
        let u = |x: &[EF]| s_hat(0, x) + s_hat(1, x) * x.iter().copied().sum::<EF>();
        let rows = mask_rows(&sigma);
        for (b, s) in rows.iter().enumerate() {
            let bits: Vec<EF> = (0..k).map(|i| EF::from_u32(((b >> i) & 1) as u32)).collect();
            assert_eq!(s[0], s_hat(0, &bits));
            assert_eq!(s[1], s_hat(1, &bits));
        }
        let gamma: Vec<EF> = (0..k).map(|_| rand_ef(&mut rng)).collect();
        let mut s0: Vec<EF> = rows.iter().map(|s| s[0]).collect();
        let mut s1: Vec<EF> = rows.iter().map(|s| s[1]).collect();
        fold_low_bits(&mut s0, &gamma);
        fold_low_bits(&mut s1, &gamma);
        assert_eq!(s0[0] + s1[0] * gamma.iter().copied().sum::<EF>(), u(&gamma));
    }

    /// An honest opening verifies against the dense polynomial's evaluation
    /// and against nothing else; every value the proof carries is bound.
    #[test]
    fn zk_opening_round_trip() {
        let inst = instance(7);
        let proof = open(&inst);
        let stages = zk_stages(&config(), LSH);
        assert_eq!(verify(&inst, &proof, inst.claim), Ok(()));
        assert_eq!(proof.batch_evaluations, alloc::vec![proof.batch_evaluations[0].clone()]);
        assert_eq!(proof.batch_evaluations[0].len(), stages.len() + 1);
        assert_eq!(proof.whir_proof.final_poly.len(), stages.last().unwrap().coefficients());
        assert!(verify(&inst, &proof, inst.claim + EF::ONE).is_err());

        for k in 0..proof.batch_evaluations[0].len() {
            let mut bad = proof.clone();
            bad.batch_evaluations[0][k] += EF::ONE;
            assert!(verify(&inst, &bad, inst.claim).is_err(), "mask sum {k}");
        }
        let mut bad = proof.clone();
        bad.batch_evaluations[0].pop();
        assert!(verify(&inst, &bad, inst.claim).is_err());
        let mut bad = proof.clone();
        bad.batch_grinding_witness = F::ONE;
        assert!(verify(&inst, &bad, inst.claim).is_err());
        assert!(verify_with(&inst, &proof, inst.claim, None).is_err());

        let plain = open_with(&inst, false);
        assert_eq!(verify_with(&inst, &plain, inst.claim, None), Ok(()));
        assert!(verify(&inst, &plain, inst.claim).is_err());

        let mut bad = proof.clone();
        bad.whir_proof.round_query_openings[0].leaves[0].values[0][0] += F::ONE;
        assert!(verify(&inst, &bad, inst.claim).is_err());
        let mut bad = proof.clone();
        bad.whir_proof.round_query_openings[0].leaves[1].values[1][0] += F::ONE;
        assert!(verify(&inst, &bad, inst.claim).is_err());
        let mut bad = proof.clone();
        bad.whir_proof.round_query_openings[0].leaves[1].values.pop();
        assert!(verify(&inst, &bad, inst.claim).is_err());

        let last = proof.whir_proof.round_query_openings.len() - 1;
        for r in 1..=last {
            let leaf = &proof.whir_proof.round_query_openings[r].leaves[0];
            assert_eq!(leaf.values.len(), 1 + usize::from(r == last), "round {r}: rows, then g");
            for m in 0..leaf.values.len() {
                let mut bad = proof.clone();
                bad.whir_proof.round_query_openings[r].leaves[0].values[m][0] += F::ONE;
                assert!(verify(&inst, &bad, inst.claim).is_err(), "round {r} matrix {m}");
            }
            let mut bad = proof.clone();
            bad.whir_proof.round_query_openings[r].leaves[0].values.pop();
            assert!(verify(&inst, &bad, inst.claim).is_err());
        }
        for r in 0..proof.whir_proof.round_ood_answers.len() {
            let mut bad = proof.clone();
            bad.whir_proof.round_ood_answers[r][0] += EF::ONE;
            assert!(verify(&inst, &bad, inst.claim).is_err(), "ood {r}");
        }
        for k in [0, stages.last().unwrap().seeds, proof.whir_proof.final_poly.len() - 1] {
            let mut bad = proof.clone();
            bad.whir_proof.final_poly[k] += EF::ONE;
            assert!(verify(&inst, &bad, inst.claim).is_err(), "disclosed {k}");
        }
        let mut bad = proof.clone();
        bad.whir_proof.final_poly.pop();
        assert!(verify(&inst, &bad, inst.claim).is_err());
    }

    /// Every claim is bound to the committed cells: a claim whose value or
    /// weights differ from what the cells give, or a jagged residue off the
    /// mask, fails the final check.
    #[test]
    fn zk_opening_binds_the_cell_claims() {
        let inst = instance(9);
        let proof = open(&inst);
        let (claims, jagged) = mask_claims(&inst);
        assert_eq!(
            verify_with(&inst, &proof, inst.claim, Some((claims.as_slice(), jagged))),
            Ok(())
        );
        let region = zk_region(&inst.main);
        for c in &claims {
            assert_eq!(crate::zk_mask::claim_over_cells::<F, EF>(&c.weights, region), c.value);
        }

        for k in 0..claims.len() {
            let mut bad = claims.clone();
            bad[k].value += EF::ONE;
            assert!(
                verify_with(&inst, &proof, inst.claim, Some((bad.as_slice(), jagged))).is_err(),
                "claim {k}"
            );
            let mut bad = claims.clone();
            bad[k].weights[0].1 += EF::ONE;
            assert!(verify_with(&inst, &proof, inst.claim, Some((bad.as_slice(), jagged))).is_err());
        }
        let mut bad = claims.clone();
        bad[0].weights.push((region.len(), EF::ONE));
        assert!(verify_with(&inst, &proof, inst.claim, Some((bad.as_slice(), jagged))).is_err());

        let (rho_j, residue) = jagged;
        assert!(verify_with(
            &inst,
            &proof,
            inst.claim,
            Some((claims.as_slice(), (rho_j, residue + EF::ONE)))
        )
        .is_err());
        assert!(verify_with(
            &inst,
            &proof,
            inst.claim,
            Some((&claims, (rho_j + EF::ONE, residue)))
        )
        .is_err());
        assert!(verify_with(&inst, &proof, inst.claim, Some((&claims[..1], jagged))).is_err());
    }

    /// A jagged point that gives the main round's last stripe a zero
    /// coefficient leaves `G` without its masks and the cell claims without
    /// weight: the verifier rejects it as degenerate, so the prover opens
    /// again, though the opening is otherwise sound.
    #[test]
    fn a_zero_mask_coefficient_is_degenerate() {
        let inst = instance_with(13, true);
        let proof = open(&inst);
        assert!(matches!(
            verify(&inst, &proof, inst.claim),
            Err(WhirVerifierError::DegenerateChallenge(_))
        ));
        let inst = instance_with(13, false);
        assert_eq!(verify(&inst, &open(&inst), inst.claim), Ok(()));
    }

    /// Two openings of the same cells at the same point share nothing the
    /// verifier sees but the claim: the main commitment, the mask sums, the
    /// opened rows, the folded commitments, the out-of-domain answers and
    /// the disclosed vector all differ, while both verify.
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
        assert_ne!(pa.whir_proof.round_ood_answers, pb.whir_proof.round_ood_answers);
        let main_rows = |p: &StackedWhirProof<F, EF, JaggedMmcs>| {
            p.whir_proof.round_query_openings[0]
                .leaves
                .iter()
                .skip(1)
                .step_by(2)
                .map(|l| l.values.clone())
                .collect::<Vec<_>>()
        };
        for (la, lb) in main_rows(&pa).iter().zip(&main_rows(&pb)) {
            assert_ne!(la, lb, "an opened main-round leaf never repeats");
        }
        assert!(verify(&a, &pb, a.claim).is_err(), "a proof binds its own commitment");
    }
}
