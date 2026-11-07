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
//! Every column's random summand is uniform as long as the column is free
//! in the pair's sum or difference; [`RandomRowPlan::exposed_columns`]
//! names the columns a chip's lookups pin on both, for the tests to assert
//! empty.
//!
//! A chip without main columns commits no random rows and is proved and
//! verified as on a plain shard.

use alloc::vec::Vec;

use p3_air::{PairCol, VirtualPairCol};
use p3_field::Field;

use crate::air::MachineAir;
use crate::lookup::Lookup;
use crate::Chip;

/// Random rows appended to every main trace of a zk shard: four pairs,
/// twice what two openings per column need for a uniform summand.
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

/// A uniform element of `F` from a 64-bit draw: the bias of the reduction
/// is `2^-33` for a 31-bit field.
#[cfg(feature = "zk")]
pub fn random_element<F: Field>(rng: &mut impl rand::Rng) -> F {
    F::from_u64(rng.gen::<u64>())
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
    F: Field,
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
            if !exposed.is_empty() {
                tracing::warn!(
                    chip = %name,
                    columns = ?exposed,
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
