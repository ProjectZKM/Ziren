//! Random rows for the zk shrink ring: the trace-level half of the
//! zero-knowledge shard proof (feature `zk` for the sampling; the rules and
//! the verifier's arithmetic are always compiled, so one verifier serves
//! both builds).
//!
//! The verifier of a shard learns every main column's multilinear extension
//! at two points: the LogUp-GKR anchor and the zerocheck's reduced point.
//! On the zk ring every chip therefore commits [`ZK_RANDOM_ROWS`] extra
//! rows after its real ones, so that each column's two openings carry a
//! uniformly random summand and reveal nothing of the real cells.  The
//! committed height is the real height plus [`ZK_RANDOM_ROWS`]; the
//! **constrained** height ([`constrained_height`]) is the real one, and it
//! is what the constraints are checked on.
//!
//! The random rows must leave both arguments of the shard proof intact:
//!
//! * **Constraints.**  A random row satisfies no constraint, so the
//!   zerocheck weighs the constraint polynomial with the equality table cut
//!   at the constrained height ([`constraint_weight_table`]) instead of
//!   the plain equality table.  The cut table is a multilinear in the row
//!   variables like the plain one, so the sumcheck keeps its degree, and
//!   its value at the reduced point ([`masked_eq_eval`]) is what the
//!   verifier multiplies the constraint evaluation by.  The trace openings
//!   keep the plain table: they are openings of the committed columns,
//!   random rows included.
//! * **Lookups.**  The random rows come in pairs.  Within a pair the two
//!   rows carry the same lookup values and opposite multiplicities, so
//!   their fractions cancel for every challenge and the lookup argument's
//!   balance is unchanged ([`RandomRowPlan`]).  A lookup whose multiplicity
//!   does not depend on the main columns (a constant, or a preprocessed
//!   column, which is zero past the real rows) cannot cancel in a pair; it
//!   has nothing to hide either, so the LogUp first layer zeroes its
//!   multiplicity on the random rows and the verifier reconstructs that
//!   leaf with the constrained height ([`multiplicity_is_constant_on_main`]).
//!
//! A column's two extension-field openings are eight base-field values, so
//! its random summand is uniform only when the column is free in both the
//! pair's sum and its difference: two scalars per pair, eight over the four
//! pairs.  [`RandomRowPlan::exposed_columns`] names the columns a chip's
//! lookups pin on both and [`RandomRowPlan::half_hidden_columns`] those
//! pinned on one, for the tests to assert both empty.
//!
//! A chip without main columns commits no random rows and is proved and
//! verified as on a plain shard.

use alloc::vec::Vec;

use p3_air::{PairCol, VirtualPairCol};
use p3_field::{BasedVectorSpace, ExtensionField, Field};

use crate::air::MachineAir;
use crate::lookup::Lookup;
use crate::Chip;

/// Random rows appended to every main trace of a zk shard: four pairs,
/// two free scalars each, the eight base-field coordinates of a column's
/// two openings.
pub const ZK_RANDOM_ROWS: usize = 8;

/// Does a ring's shard carry the random rows?  The zk shrink ring's does;
/// prover and verifier both read it off their own ring type, never off a
/// proof.
#[cfg(feature = "zk")]
pub fn ring_has_random_rows<SC: crate::WhirRing>() -> bool {
    SC::WHIR_PROFILE == crate::whir::jagged::WhirProfile::ZkShrink
}

/// Without the `zk` feature no ring carries random rows.
#[cfg(not(feature = "zk"))]
pub fn ring_has_random_rows<SC: crate::WhirRing>() -> bool {
    false
}

/// `log2` of the interaction axis of a shard's LogUp-GKR, as the first
/// layer sizes it: the chips' interactions rounded up to a power of two.
pub fn num_interaction_variables<F: Field, A: MachineAir<F>>(chips: &[&Chip<F, A>]) -> usize {
    let total: usize = chips.iter().map(|chip| chip.sends().len() + chip.receives().len()).sum();
    total.max(1).next_power_of_two().trailing_zeros() as usize
}

/// The constrained (real) height of a zk chip from its committed height:
/// a chip with main columns committed `ZK_RANDOM_ROWS` random rows past its
/// real ones, a chip without has nothing to hide.  `None` when a committed
/// height is too small to hold the random rows, which no honest zk shard
/// produces.
pub fn constrained_height(committed: usize, main_width: usize) -> Option<usize> {
    if main_width == 0 {
        Some(committed)
    } else {
        committed.checked_sub(ZK_RANDOM_ROWS)
    }
}

/// Does `lookup`'s multiplicity ignore the main columns?  Such a lookup
/// keeps its multiplicity on a random row (the preprocessed columns are
/// zero there), so its leaf is masked past the constrained height instead
/// of cancelled within the pair.
pub fn multiplicity_is_constant_on_main<F: Field>(lookup: &Lookup<F>) -> bool {
    lookup
        .multiplicity
        .column_weights()
        .iter()
        .all(|(column, weight)| matches!(column, PairCol::Preprocessed(_)) || *weight == F::ZERO)
}

/// The main-column weights and the constant of a virtual column on a row
/// whose preprocessed columns are zero.
fn main_affine<F: Field>(column: &VirtualPairCol<F>, width: usize) -> (Vec<F>, F) {
    let mut weights = alloc::vec![F::ZERO; width];
    for (col, weight) in column.column_weights().iter() {
        if let PairCol::Main(i) = col {
            weights[*i] += *weight;
        }
    }
    (weights, column.constant_term())
}

/// Row-reduce `rows · x = rhs` over `n` unknowns: a particular solution and
/// a basis of the homogeneous solutions, or `None` when the system is
/// inconsistent.
fn solve_affine<F: Field>(
    mut rows: Vec<Vec<F>>,
    mut rhs: Vec<F>,
    n: usize,
) -> Option<(Vec<F>, Vec<Vec<F>>)> {
    let m = rows.len();
    let mut pivot_cols: Vec<usize> = Vec::new();
    let mut r = 0usize;
    for c in 0..n {
        if r == m {
            break;
        }
        let Some(p) = (r..m).find(|&i| rows[i][c] != F::ZERO) else {
            continue;
        };
        rows.swap(r, p);
        rhs.swap(r, p);
        let inv = rows[r][c].inverse();
        for v in rows[r].iter_mut() {
            *v *= inv;
        }
        rhs[r] *= inv;
        let pivot_row = rows[r].clone();
        let pivot_rhs = rhs[r];
        for i in 0..m {
            if i == r || rows[i][c] == F::ZERO {
                continue;
            }
            let f = rows[i][c];
            for (v, p) in rows[i].iter_mut().zip(pivot_row.iter()) {
                *v -= f * *p;
            }
            rhs[i] -= f * pivot_rhs;
        }
        pivot_cols.push(c);
        r += 1;
    }
    if rhs[r..].iter().any(|v| *v != F::ZERO) {
        return None;
    }
    let mut particular = alloc::vec![F::ZERO; n];
    for (i, &c) in pivot_cols.iter().enumerate() {
        particular[c] = rhs[i];
    }
    let mut is_pivot = alloc::vec![false; n];
    for &c in pivot_cols.iter() {
        is_pivot[c] = true;
    }
    let null: Vec<Vec<F>> = (0..n)
        .filter(|&f| !is_pivot[f])
        .map(|f| {
            let mut v = alloc::vec![F::ZERO; n];
            v[f] = F::ONE;
            for (i, &c) in pivot_cols.iter().enumerate() {
                v[c] = -rows[i][f];
            }
            v
        })
        .collect();
    Some((particular, null))
}

/// How one chip's random rows are drawn: the affine spaces a pair's row sum
/// `s = x + x'` and row difference `d = x' − x` range over.
///
/// For every lookup `j` with multiplicity `c_j + L_j·x` and values
/// `e_{j,k} + V_{j,k}·x` on the main columns, the pair cancels iff
/// `L_j·s = −2 c_j` (opposite multiplicities) and `V_{j,k}·d = 0` (equal
/// values, hence equal denominators for every challenge).  Lookups whose
/// multiplicity is constant on the main columns are masked instead and put
/// no condition on the pair.
#[derive(Clone, Debug)]
pub struct RandomRowPlan<F> {
    width: usize,
    sum_particular: Vec<F>,
    sum_null: Vec<Vec<F>>,
    diff_null: Vec<Vec<F>>,
    exposed_dimension: usize,
}

/// The rank of `rows` over `n` unknowns.
fn rank<F: Field>(rows: Vec<Vec<F>>, n: usize) -> usize {
    let m = rows.len();
    let (_, null) = solve_affine(rows, alloc::vec![F::ZERO; m], n).expect("homogeneous");
    n - null.len()
}

impl<F: Field> RandomRowPlan<F> {
    /// The plan of `chip`'s random rows over `width` main columns, or the
    /// lookup that makes a cancelling pair impossible.
    pub fn new<A: MachineAir<F>>(chip: &Chip<F, A>, width: usize) -> Result<Self, String> {
        let lookups: Vec<&Lookup<F>> = chip.sends().iter().chain(chip.receives().iter()).collect();
        let mut sum_rows = Vec::new();
        let mut sum_rhs = Vec::new();
        let mut diff_rows = Vec::new();
        for lookup in lookups.iter().filter(|l| !multiplicity_is_constant_on_main(l)) {
            let (weights, constant) = main_affine(&lookup.multiplicity, width);
            sum_rows.push(weights);
            sum_rhs.push(-(constant + constant));
            for value in lookup.values.iter() {
                let (weights, _) = main_affine(value, width);
                diff_rows.push(weights);
            }
        }
        let diff_rhs = alloc::vec![F::ZERO; diff_rows.len()];
        let sum_rows_for_rank = sum_rows.clone();
        let (sum_particular, sum_null) =
            solve_affine(sum_rows, sum_rhs, width).ok_or_else(|| {
                alloc::format!(
                    "chip {}: its lookups' multiplicities admit no pair of rows with opposite \
                     multiplicities",
                    chip.name()
                )
            })?;
        let sum_rank = width - sum_null.len();
        let diff_rank = rank(diff_rows.clone(), width);
        let joint_rank =
            rank(sum_rows_for_rank.into_iter().chain(diff_rows.clone()).collect(), width);
        let (_, diff_null) =
            solve_affine(diff_rows, diff_rhs, width).expect("a homogeneous system is consistent");
        let exposed_dimension = sum_rank + diff_rank - joint_rank;
        Ok(Self { width, sum_particular, sum_null, diff_null, exposed_dimension })
    }

    /// The dimension of the linear functionals of a row that the random
    /// rows leave in the clear: the combinations of main columns that are at
    /// once a combination of the lookups' multiplicities and one of their
    /// values, since both the pair's sum and its difference are fixed on
    /// them.  Their multilinear extensions at the two opening points are
    /// what the shard proof still reveals of the real rows; zero means the
    /// openings reveal nothing.
    pub fn exposed_dimension(&self) -> usize {
        self.exposed_dimension
    }

    /// The main columns the lookups pin in both the sum and the difference
    /// of a pair: their random rows are determined, so their openings would
    /// stay in the clear.
    pub fn exposed_columns(&self) -> Vec<usize> {
        (0..self.width)
            .filter(|&k| {
                self.sum_null.iter().all(|v| v[k] == F::ZERO)
                    && self.diff_null.iter().all(|v| v[k] == F::ZERO)
            })
            .collect()
    }

    /// The main columns free in just one of a pair's sum and difference:
    /// one random scalar per pair, four over the four pairs, where the
    /// eight base-field coordinates of two openings need eight.
    pub fn half_hidden_columns(&self) -> Vec<usize> {
        (0..self.width)
            .filter(|&k| {
                self.sum_null.iter().any(|v| v[k] != F::ZERO)
                    != self.diff_null.iter().any(|v| v[k] != F::ZERO)
            })
            .collect()
    }

    /// `pairs` cancelling pairs of rows, row-major, drawn with `random`.
    pub fn sample(&self, pairs: usize, mut random: impl FnMut() -> F) -> Vec<F> {
        let half = F::TWO.inverse();
        let mut out = Vec::with_capacity(2 * pairs * self.width);
        for _ in 0..pairs {
            let mut s = self.sum_particular.clone();
            for basis in self.sum_null.iter() {
                let r = random();
                for (si, bi) in s.iter_mut().zip(basis) {
                    *si += r * *bi;
                }
            }
            let mut d = alloc::vec![F::ZERO; self.width];
            for basis in self.diff_null.iter() {
                let r = random();
                for (di, bi) in d.iter_mut().zip(basis) {
                    *di += r * *bi;
                }
            }
            out.extend(s.iter().zip(&d).map(|(&si, &di)| (si - di) * half));
            out.extend(s.iter().zip(&d).map(|(&si, &di)| (si + di) * half));
        }
        out
    }
}

/// The zerocheck's constraint weight on a zk chip: the big-endian equality
/// table of `anchor` on the rows below `constrained`, zero on the rows from
/// there to `committed`.  Its multilinear extension replaces the plain
/// table on the constraint part of the chip's zerocheck polynomial.
pub fn constraint_weight_table<EF: Field>(
    anchor: &[EF],
    constrained: usize,
    committed: usize,
) -> Vec<EF> {
    let mut table =
        crate::shard_level::zerocheck_poly::partial_lagrange_prefix(anchor, constrained);
    table.resize(committed, EF::ZERO);
    table
}

/// Whether the random rows hide a column opened at `anchor` and `z`: the
/// eight base-field coordinates of its two openings are `A·w + B·r` for the
/// real rows `w` and the random rows `r` of rows `constrained..constrained +
/// ZK_RANDOM_ROWS`, and `B` is the square matrix of the two equality
/// weights' coordinates at those rows.  `B` of full rank makes the eight
/// coordinates uniform; a rank below eight leaves a linear functional of
/// the real rows in the clear, so the verifier rejects the challenges
/// ([`crate::shard_level::verifier::JaggedShardVerifyError::DegenerateChallenge`]).
/// Both points are big-endian as in [`masked_eq_eval`].
///
/// Uniform points give a singular `B` with probability below `2^-23` by
/// Schwartz–Zippel (its determinant has degree at most eight times the
/// dimension in the points' coordinates) and about `2^-31` in a census of
/// ten thousand random slices.  When `constrained` is a multiple of eight
/// the rows share their high bits, whose weight scales each point's four
/// coordinates invertibly, so the rank is that of the two points' last
/// three coordinates alone.
///
/// # Panics
/// Panics if the points disagree on dimension or the random rows do not fit
/// the cube.
#[must_use]
pub fn random_rows_hide<F: Field, EF: ExtensionField<F>>(
    anchor: &[EF],
    z: &[EF],
    constrained: usize,
) -> bool {
    let m = anchor.len();
    assert_eq!(z.len(), m, "random_rows_hide: anchor and point disagree on dimension");
    assert!(constrained + ZK_RANDOM_ROWS <= 1usize << m, "random_rows_hide: rows do not fit");
    let weight = |point: &[EF], row: usize| -> EF {
        point.iter().enumerate().fold(EF::ONE, |acc, (k, &x)| {
            acc * if (row >> (m - 1 - k)) & 1 == 1 { x } else { EF::ONE - x }
        })
    };
    let dim = <EF as BasedVectorSpace<F>>::DIMENSION;
    let mut rows: Vec<Vec<F>> = alloc::vec![Vec::with_capacity(ZK_RANDOM_ROWS); 2 * dim];
    for row in constrained..constrained + ZK_RANDOM_ROWS {
        for (p, point) in [anchor, z].into_iter().enumerate() {
            let coordinates = weight(point, row);
            for (c, &coordinate) in coordinates.as_basis_coefficients_slice().iter().enumerate() {
                rows[p * dim + c].push(coordinate);
            }
        }
    }
    rank(rows, ZK_RANDOM_ROWS) == 2 * dim
}

/// `Σ_{b < rows} eq(anchor, b) · eq(z, b)` over the big-endian rows `b` of
/// the cube (`anchor[0]` and `z[0]` pair with the row's top bit): the value
/// at `z` of the multilinear extension of [`constraint_weight_table`].
pub fn masked_eq_eval<EF: Field>(anchor: &[EF], z: &[EF], rows: usize) -> EF {
    let m = anchor.len();
    assert_eq!(z.len(), m, "masked_eq_eval: anchor and point disagree on dimension");
    assert!(rows <= 1usize << m, "masked_eq_eval: {rows} rows do not fit 2^{m}");
    let lo = |k: usize| (EF::ONE - anchor[k]) * (EF::ONE - z[k]);
    let hi = |k: usize| anchor[k] * z[k];
    let mut suffix = alloc::vec![EF::ONE; m + 1];
    for k in (0..m).rev() {
        suffix[k] = suffix[k + 1] * (lo(k) + hi(k));
    }
    if rows == 1usize << m {
        return suffix[0];
    }
    let mut acc = EF::ZERO;
    let mut prefix = EF::ONE;
    let mut remaining = rows;
    for k in 0..m {
        if remaining == 0 {
            break;
        }
        let half = 1usize << (m - 1 - k);
        if remaining >= half {
            acc += prefix * lo(k) * suffix[k + 1];
            prefix *= hi(k);
            remaining -= half;
        } else {
            prefix *= lo(k);
        }
    }
    acc
}

/// The LogUp first layer's numerator mask for a zk chip: which of its
/// lookups (sends then receives, the first layer's order) keep a nonzero
/// multiplicity on a random row and so are zeroed past `constrained` rows.
pub fn numerator_masks<F: Field, A: MachineAir<F>>(chip: &Chip<F, A>) -> Vec<bool> {
    chip.sends()
        .iter()
        .chain(chip.receives().iter())
        .map(multiplicity_is_constant_on_main)
        .collect()
}

/// A uniform element of `F`: a uniform draw below the field order.
#[cfg(feature = "zk")]
pub fn random_element<F: p3_field::PrimeField64>(rng: &mut impl rand::Rng) -> F {
    F::from_u64(rng.gen_range(0..F::ORDER_U64))
}

/// Append [`ZK_RANDOM_ROWS`] random rows to every main trace of a shard,
/// drawn under the chip's [`RandomRowPlan`].  A chip without main columns
/// is left alone.  The traces keep their cube.
///
/// # Panics
/// When a trace names no chip, a chip's lookups admit no cancelling pair,
/// or a chip has an odd number of random rows to draw.
#[cfg(feature = "zk")]
pub fn append_random_rows<F, A>(
    chips: &[Chip<F, A>],
    traces: crate::traces::Traces<F>,
    rng: &mut impl rand::Rng,
) -> crate::traces::Traces<F>
where
    F: p3_field::PrimeField64,
    A: MachineAir<F>,
{
    use crate::multilinear::PaddedMle;
    use crate::whir::mle::Mle;
    use p3_matrix::dense::RowMajorMatrix;

    assert!(ZK_RANDOM_ROWS.is_multiple_of(2), "random rows come in pairs");
    let named_traces = traces
        .named_traces
        .into_iter()
        .map(|(name, pm)| {
            let width = pm.num_polynomials();
            let Some(mle) = pm.inner().as_ref() else {
                return (name, pm);
            };
            if width == 0 {
                return (name, pm);
            }
            let chip = chips
                .iter()
                .find(|chip| chip.name() == name)
                .unwrap_or_else(|| panic!("zk random rows: trace {name} names no chip"));
            let plan =
                RandomRowPlan::new(chip, width).unwrap_or_else(|e| panic!("zk random rows: {e}"));
            let exposed = plan.exposed_columns();
            let half_hidden = plan.half_hidden_columns();
            if !exposed.is_empty() || !half_hidden.is_empty() {
                tracing::warn!(
                    chip = %name,
                    pinned = ?exposed,
                    half_hidden = ?half_hidden,
                    "zk random rows: the chip's lookups pin these main columns, their openings \
                     are not hidden"
                );
            }
            let mut values: Vec<F> = mle.guts().as_slice().to_vec();
            values.extend(plan.sample(ZK_RANDOM_ROWS / 2, || random_element::<F>(rng)));
            let padded = PaddedMle::padded_with_zeros(
                alloc::sync::Arc::new(Mle::from_row_major(RowMajorMatrix::new(values, width))),
                pm.num_variables(),
            );
            (name, padded)
        })
        .collect();
    crate::traces::Traces { named_traces }
}

/// The numerator and denominator one lookup contributes on `main_row`
/// (preprocessed columns zero), for the tests.
#[cfg(test)]
fn lookup_fraction<F: Field, EF: p3_field::ExtensionField<F>>(
    lookup: &Lookup<F>,
    main_row: &[F],
    alpha: EF,
    betas: &[EF],
) -> (F, EF) {
    crate::shard_level::row_gkr::first_layer::generate_interaction_vals::<F, EF>(
        lookup,
        &[],
        main_row,
        true,
        alpha,
        betas,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lookup::LookupKind;
    use crate::{InnerChallenge as EF, InnerVal as F};
    use p3_air::VirtualPairCol;
    use p3_field::PrimeCharacteristicRing;

    fn lookup(values: Vec<VirtualPairCol<F>>, multiplicity: VirtualPairCol<F>) -> Lookup<F> {
        Lookup {
            values,
            multiplicity,
            kind: LookupKind::Byte,
            scope: crate::air::LookupScope::Local,
        }
    }

    fn lcg(seed: &mut u64) -> F {
        *seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        F::from_u64(*seed >> 11)
    }

    fn ef(seed: &mut u64) -> EF {
        EF::from(lcg(seed)) + EF::from(lcg(seed)) * EF::from_u64(1 << 20)
    }

    /// A plan built from a lookup list rather than a chip: the chip-level
    /// constructor only collects the chip's lookups.
    fn plan_of(lookups: &[Lookup<F>], width: usize) -> Result<RandomRowPlan<F>, String> {
        let mut sum_rows = Vec::new();
        let mut sum_rhs = Vec::new();
        let mut diff_rows = Vec::new();
        for l in lookups.iter().filter(|l| !multiplicity_is_constant_on_main(l)) {
            let (w, c) = main_affine(&l.multiplicity, width);
            sum_rows.push(w);
            sum_rhs.push(-(c + c));
            for v in l.values.iter() {
                diff_rows.push(main_affine(v, width).0);
            }
        }
        let n = diff_rows.len();
        let (sum_particular, sum_null) = solve_affine(sum_rows.clone(), sum_rhs, width)
            .ok_or_else(|| "inconsistent".to_string())?;
        let sum_rank = width - sum_null.len();
        let diff_rank = rank(diff_rows.clone(), width);
        let joint_rank = rank(sum_rows.into_iter().chain(diff_rows.clone()).collect(), width);
        let (_, diff_null) = solve_affine(diff_rows, alloc::vec![F::ZERO; n], width).unwrap();
        let exposed_dimension = sum_rank + diff_rank - joint_rank;
        Ok(RandomRowPlan { width, sum_particular, sum_null, diff_null, exposed_dimension })
    }

    /// Two opening points met in a production zk shrink proof whose random
    /// rows sit at `262144..262152`: the weight matrix has rank seven there
    /// and at every other run of eight rows aligned to eight, since the
    /// matrices at two aligned offsets differ by an invertible scaling of
    /// each point's four coordinates; runs across an alignment boundary and
    /// a shifted anchor have full rank.
    #[test]
    fn random_rows_hide_rejects_the_rank_seven_points() {
        let raw = RAW_POINTS;
        let points: Vec<Vec<EF>> = raw
            .iter()
            .map(|point| {
                point
                    .iter()
                    .map(|a| {
                        <EF as BasedVectorSpace<F>>::from_basis_coefficients_slice(
                            &a.map(F::from_u32),
                        )
                        .unwrap()
                    })
                    .collect()
            })
            .collect();
        let (anchor, z) = (&points[0], &points[1]);
        assert!(!random_rows_hide::<F, EF>(anchor, z, 1 << 18));
        for aligned in [0, 8, (1 << 18) + 8] {
            assert!(!random_rows_hide::<F, EF>(anchor, z, aligned));
        }
        for unaligned in [3, 5, (1 << 18) + 3, (1 << 18) + 11] {
            assert!(random_rows_hide::<F, EF>(anchor, z, unaligned));
        }
        let mut shifted = anchor.clone();
        shifted[21] += EF::ONE;
        assert!(random_rows_hide::<F, EF>(&shifted, z, 1 << 18));
        let mut seed = 11u64;
        let mut point = || -> Vec<EF> {
            (0..22).map(|_| EF::from_basis_coefficients_fn(|_| lcg(&mut seed))).collect()
        };
        for _ in 0..16 {
            let (a, b) = (point(), point());
            assert!(random_rows_hide::<F, EF>(&a, &b, 1 << 18));
            assert!(random_rows_hide::<F, EF>(&a, &b, 1 << 17 | 5));
        }
    }

    const RAW_POINTS: [[[u32; 4]; 22]; 2] = [
        [
            [394431667, 102234520, 1051859102, 623088223],
            [1329505860, 296427003, 910866976, 797484707],
            [391604959, 17529306, 1869066624, 1000181783],
            [1883084723, 204804436, 2022824412, 440445757],
            [1058962287, 459151456, 800495850, 2094959690],
            [1799556956, 346461355, 683917093, 1399203552],
            [2034106560, 1808091439, 1998386945, 649616054],
            [1724006961, 1974488290, 346699082, 795788994],
            [909990322, 858968075, 467165057, 1243281614],
            [1326284453, 900221624, 1848231681, 1504453775],
            [1664969617, 2085606265, 186445823, 402977461],
            [396852701, 1497359147, 543867422, 341323510],
            [1220090041, 1815798290, 975276521, 285684283],
            [637597905, 679612583, 765803392, 1359989500],
            [1026567590, 1645564873, 382876011, 990094598],
            [300688619, 1186044219, 1857707032, 403768908],
            [713875109, 2054157406, 1494184150, 171550328],
            [123240265, 310910995, 1315246590, 1988192704],
            [1474835735, 511366049, 127174084, 837470695],
            [545911966, 1884199111, 1283074703, 632661949],
            [1456447037, 679689936, 1749543787, 1719326024],
            [137791609, 351359303, 945332215, 1957360455],
        ],
        [
            [553145838, 526341834, 1763063501, 651408548],
            [1873948846, 1177547373, 2049068056, 1915837064],
            [1322127252, 325122829, 1408225907, 1101286757],
            [1468286719, 1341382662, 1485694544, 965339362],
            [1573152842, 843611517, 1627425351, 1451904561],
            [1055787759, 1700071114, 1951225095, 55932990],
            [965367463, 1081453401, 395641942, 222950980],
            [532713988, 1553606, 1801072267, 1856705481],
            [97239574, 424411437, 2062017418, 151002078],
            [251139980, 106793538, 865314555, 278690234],
            [145849050, 928396206, 236951904, 1506638643],
            [417509909, 13855291, 639309701, 1717713341],
            [1687101625, 1458745219, 1034782106, 891114684],
            [772222591, 1439561767, 1292187358, 915186893],
            [1409043577, 460707592, 1638460255, 1763328156],
            [1864549138, 1324873990, 540793457, 1886503682],
            [573731266, 2126939951, 1077062612, 443860498],
            [1301559594, 637818775, 2052042034, 939783762],
            [348358083, 1691320963, 1824953184, 1867840320],
            [1057936610, 1930554977, 637540858, 1022778162],
            [1977657886, 992300603, 1429169515, 1774429275],
            [662037850, 64021988, 1571832050, 1097744268],
        ],
    ];

    #[test]
    fn constrained_height_rule() {
        assert_eq!(constrained_height(ZK_RANDOM_ROWS + 5, 3), Some(5));
        assert_eq!(constrained_height(ZK_RANDOM_ROWS, 3), Some(0));
        assert_eq!(constrained_height(ZK_RANDOM_ROWS - 1, 3), None);
        assert_eq!(constrained_height(1, 0), Some(1));
    }

    #[test]
    fn solve_affine_particular_and_null_space() {
        let rows = alloc::vec![
            alloc::vec![F::ONE, F::TWO, F::ZERO, F::ONE],
            alloc::vec![F::ZERO, F::ONE, F::ONE, F::ZERO],
        ];
        let rhs = alloc::vec![F::from_u64(7), F::from_u64(3)];
        let (p, null) = solve_affine(rows.clone(), rhs.clone(), 4).unwrap();
        let apply = |x: &[F]| -> Vec<F> {
            rows.iter().map(|r| r.iter().zip(x).map(|(a, b)| *a * *b).sum()).collect()
        };
        assert_eq!(apply(&p), rhs);
        assert_eq!(null.len(), 2);
        for v in &null {
            assert!(apply(v).iter().all(|x| *x == F::ZERO));
        }
        let inconsistent = alloc::vec![alloc::vec![F::ONE, F::ONE], alloc::vec![F::TWO, F::TWO]];
        assert!(solve_affine(inconsistent, alloc::vec![F::ONE, F::ONE], 2).is_none());
    }

    /// Every pair's lookup fractions cancel for random challenges, the
    /// masked lookup keeps its constant multiplicity, and the free columns
    /// vary between draws.
    #[test]
    fn pairs_cancel_every_lookup() {
        let width = 5;
        let lookups = alloc::vec![
            lookup(
                alloc::vec![
                    VirtualPairCol::single_main(1),
                    VirtualPairCol::sum_main(alloc::vec![2, 3])
                ],
                VirtualPairCol::single_main(0),
            ),
            lookup(
                alloc::vec![VirtualPairCol::single_main(2)],
                VirtualPairCol::new_main(alloc::vec![(0, F::ONE), (4, F::TWO)], F::ONE),
            ),
            lookup(alloc::vec![VirtualPairCol::single_main(3)], VirtualPairCol::constant(F::ONE)),
        ];
        assert!(!multiplicity_is_constant_on_main(&lookups[0]));
        assert!(multiplicity_is_constant_on_main(&lookups[2]));
        let plan = plan_of(&lookups, width).unwrap();
        assert!(plan.exposed_columns().is_empty(), "{:?}", plan.exposed_columns());
        assert_eq!(plan.exposed_dimension(), 0);
        let mut seed = 7u64;
        let rows = plan.sample(3, || lcg(&mut seed));
        assert_eq!(rows.len(), 6 * width);
        let alpha = ef(&mut seed);
        let betas: Vec<EF> = (0..3).map(|_| ef(&mut seed)).collect();
        for pair in rows.chunks_exact(2 * width) {
            let (a, b) = pair.split_at(width);
            for l in &lookups[..2] {
                let (na, da) = lookup_fraction::<F, EF>(l, a, alpha, &betas);
                let (nb, db) = lookup_fraction::<F, EF>(l, b, alpha, &betas);
                assert_eq!(da, db, "equal values within the pair");
                assert_eq!(na + nb, F::ZERO, "opposite multiplicities within the pair");
            }
            let (na, _) = lookup_fraction::<F, EF>(&lookups[2], a, alpha, &betas);
            assert_eq!(na, F::ONE);
        }
        let again = plan.sample(3, || lcg(&mut seed));
        assert_ne!(rows, again);
    }

    #[test]
    fn a_multiplicity_pinned_by_its_values_is_exposed() {
        let lookups = alloc::vec![lookup(
            alloc::vec![VirtualPairCol::single_main(0)],
            VirtualPairCol::single_main(0)
        )];
        let plan = plan_of(&lookups, 2).unwrap();
        assert_eq!(plan.exposed_columns(), alloc::vec![0]);
        assert_eq!(plan.exposed_dimension(), 1);
        let diagonal = alloc::vec![lookup(
            alloc::vec![VirtualPairCol::sum_main(alloc::vec![0, 1])],
            VirtualPairCol::new_main(alloc::vec![(0, F::ONE), (1, F::ONE)], F::ZERO),
        )];
        let plan = plan_of(&diagonal, 2).unwrap();
        assert!(plan.exposed_columns().is_empty());
        assert_eq!(plan.exposed_dimension(), 1, "the column sum is pinned though no column is");
        let contradictory = alloc::vec![
            lookup(Vec::new(), VirtualPairCol::new_main(alloc::vec![(0, F::ONE)], F::ONE)),
            lookup(Vec::new(), VirtualPairCol::new_main(alloc::vec![(0, F::ONE)], F::TWO)),
        ];
        assert!(plan_of(&contradictory, 1).is_err());
    }

    #[test]
    fn a_column_pinned_on_one_side_is_half_hidden() {
        let lookups = alloc::vec![lookup(
            alloc::vec![VirtualPairCol::single_main(1)],
            VirtualPairCol::single_main(0)
        )];
        let plan = plan_of(&lookups, 3).unwrap();
        assert!(plan.exposed_columns().is_empty());
        assert_eq!(plan.exposed_dimension(), 0);
        assert_eq!(plan.half_hidden_columns(), alloc::vec![0, 1]);
        let masked = alloc::vec![lookup(
            alloc::vec![VirtualPairCol::single_main(1)],
            VirtualPairCol::constant(F::ONE)
        )];
        assert!(plan_of(&masked, 3).unwrap().half_hidden_columns().is_empty());
    }

    /// The closed form agrees with the brute-force sum over the cube at every
    /// cut, in the big-endian convention of the prover's table.
    #[test]
    fn masked_eq_matches_the_cut_table() {
        let mut seed = 3u64;
        for m in 0..=5usize {
            let anchor: Vec<EF> = (0..m).map(|_| ef(&mut seed)).collect();
            let z: Vec<EF> = (0..m).map(|_| ef(&mut seed)).collect();
            let eq_z = crate::shard_level::zerocheck_poly::partial_lagrange_prefix(&z, 1 << m);
            for rows in 0..=(1usize << m) {
                let table = constraint_weight_table(&anchor, rows, 1 << m);
                let brute: EF = table.iter().zip(&eq_z).map(|(w, e)| *w * *e).sum();
                assert_eq!(masked_eq_eval(&anchor, &z, rows), brute, "m={m} rows={rows}");
            }
        }
    }
}
