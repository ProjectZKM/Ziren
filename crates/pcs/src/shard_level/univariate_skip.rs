//! Univariate skip for the shard zerocheck.
//!
//! The four lowest row bits of the zerocheck are replaced by one univariate
//! variable `Z` over the order-16 multiplicative subgroup `D = <ω>`: row
//! `16·x + b` is the value at `Z = ω^b` of the block-`x` column, and each
//! column restricted to block `x` is the degree-< 16 interpolant of its 16
//! rows on `D`.
//!
//! The prover's first message is
//!
//! ```text
//!   s(Z) = eq#(ζ_lo, Z) · Σ_x eq(ζ_hi, x) · F(Z, x)
//! ```
//!
//! where `F` is the per-row zerocheck expression (α-folded constraints minus
//! the padded-row term, plus the β-batched GKR openings), and
//! `eq#(ζ_lo, ·) = Σ_b eq(ζ_lo, b)·L_b` interpolates the low four bits of the
//! eq factor on `D`.  With constraints of degree ≤ 3, `s` has degree ≤ 60, so
//! it is sent as [`SKIP_POLY_LEN`] coefficients.  The verifier checks
//! `Σ_{z∈D} s(z) = 16·Σ_j c_{16j}` against the claim, samples `r0`, and the
//! remaining `N − 4` variables run as ordinary multilinear rounds over the
//! table folded 16:1 with the weights `L_b(r0)`.
//!
//! The constraint part vanishes on `D` (real rows satisfy the AIR, padded
//! rows cancel against the padded-row term), so it is divisible by
//! `Z^16 − 1`; its quotient has degree ≤ 29 and is recovered from 32 values
//! on the two cosets `g·D` and `g²·D`.  The GKR part has degree ≤ 15 and is
//! read on `D` directly.

use p3_air::Air;
use p3_field::{ExtensionField, Field, TwoAdicField};
use rayon::prelude::*;

use crate::air::MachineAir;
use crate::shard_level::constraint_folder::ShardConstraintFolder;
use crate::shard_level::types::UnivariatePolynomial;
use crate::shard_level::zerocheck_poly::{
    eval_air_constraints_at_row, interpolate_univariate_polynomial, partial_lagrange_prefix,
};
use crate::Chip;

/// Row bits replaced by the univariate variable.
pub const SKIP_BITS: usize = 4;
/// Size of the skip domain `D`.
pub const SKIP_SIZE: usize = 1 << SKIP_BITS;
/// Coefficients of the skip message: degree `15 + 3·15 = 60`.
pub const SKIP_POLY_LEN: usize = 4 * (SKIP_SIZE - 1) + 1;
/// Number of coset points the constraint quotient is read at (two cosets
/// of `D`).
pub const NUM_COSET_POINTS: usize = 2 * SKIP_SIZE;

/// The skip domain `[ω^0, …, ω^15]`.
#[must_use]
pub fn skip_domain<F: TwoAdicField>() -> [F; SKIP_SIZE] {
    let w = F::two_adic_generator(SKIP_BITS);
    let mut out = [F::ONE; SKIP_SIZE];
    for b in 1..SKIP_SIZE {
        out[b] = out[b - 1] * w;
    }
    out
}

/// Lagrange basis of `D` at `z`: `L_b(z) = ω^b (z^16 − 1) / (16 (z − ω^b))`,
/// the one-hot vector when `z ∈ D`.
#[must_use]
pub fn lagrange_weights<F: TwoAdicField, EF: ExtensionField<F>>(z: EF) -> [EF; SKIP_SIZE] {
    let dom = skip_domain::<F>();
    let vanish = z.exp_power_of_2(SKIP_BITS) - EF::ONE;
    let mut out = [EF::ZERO; SKIP_SIZE];
    if vanish.is_zero() {
        let b = dom.iter().position(|&w| EF::from(w) == z).expect("z^16 = 1 lies in D");
        out[b] = EF::ONE;
        return out;
    }
    let inv16 = F::from_u64(SKIP_SIZE as u64).inverse();
    for b in 0..SKIP_SIZE {
        out[b] = vanish * (dom[b] * inv16) * (z - dom[b]).inverse();
    }
    out
}

/// `eq(ζ_lo, b)` for the 16 low-bit patterns `b`; `zeta_lo` is LSB-first
/// (`zeta_lo[i]` is row bit `i`).
#[must_use]
pub fn eq_low_bits<EF: Field>(zeta_lo: &[EF]) -> [EF; SKIP_SIZE] {
    assert_eq!(zeta_lo.len(), SKIP_BITS);
    let mut out = [EF::ONE; SKIP_SIZE];
    for (b, slot) in out.iter_mut().enumerate() {
        for (i, &z) in zeta_lo.iter().enumerate() {
            *slot *= if (b >> i) & 1 == 1 { z } else { EF::ONE - z };
        }
    }
    out
}

/// `eq#(ζ_lo, z) = Σ_b eq(ζ_lo, b)·L_b(z)`.
#[must_use]
pub fn eq_sharp<F: TwoAdicField, EF: ExtensionField<F>>(zeta_lo: &[EF], z: EF) -> EF {
    let e = eq_low_bits(zeta_lo);
    let l = lagrange_weights::<F, EF>(z);
    e.iter().zip(l.iter()).fold(EF::ZERO, |acc, (&a, &b)| acc + a * b)
}

/// `Σ_{b ≥ lo} L_b(z)`: the padded-row indicator of the boundary block whose
/// first `lo` rows are real, at the skip point.
#[must_use]
pub fn tail_weight<EF: Field>(weights: &[EF; SKIP_SIZE], lo: usize) -> EF {
    weights[lo.min(SKIP_SIZE)..].iter().copied().fold(EF::ZERO, |a, b| a + b)
}

/// Monomial coefficients of the degree-< 16 interpolant of `values` on `D`
/// (inverse DFT: `c_j = (1/16) Σ_b v_b ω^{−bj}`).
#[must_use]
pub fn coeffs_from_domain_values<F: TwoAdicField, EF: ExtensionField<F>>(
    values: &[EF; SKIP_SIZE],
) -> Vec<EF> {
    let dom = skip_domain::<F>();
    let inv16 = F::from_u64(SKIP_SIZE as u64).inverse();
    (0..SKIP_SIZE)
        .map(|j| {
            let mut acc = EF::ZERO;
            for (b, &v) in values.iter().enumerate() {
                acc += v * dom[(SKIP_SIZE - (b * j) % SKIP_SIZE) % SKIP_SIZE];
            }
            acc * inv16
        })
        .collect()
}

/// `16 · Σ_j c_{16j}`: the sum of a coefficient-form polynomial over `D`.
#[must_use]
pub fn sum_over_domain<EF: Field>(coeffs: &[EF]) -> EF {
    let s = coeffs.iter().step_by(SKIP_SIZE).copied().fold(EF::ZERO, |a, b| a + b);
    s * EF::from_u64(SKIP_SIZE as u64)
}

fn poly_mul<EF: Field>(a: &[EF], b: &[EF]) -> Vec<EF> {
    if a.is_empty() || b.is_empty() {
        return Vec::new();
    }
    let mut out = vec![EF::ZERO; a.len() + b.len() - 1];
    for (i, &x) in a.iter().enumerate() {
        for (j, &y) in b.iter().enumerate() {
            out[i + j] += x * y;
        }
    }
    out
}

/// The 32 coset points `g·ω^j` (j < 16) then `g²·ω^j`, with `g` the field's
/// multiplicative generator.
#[must_use]
pub fn coset_points<F: TwoAdicField>() -> [F; NUM_COSET_POINTS] {
    let dom = skip_domain::<F>();
    let g = F::GENERATOR;
    let g2 = g * g;
    let mut out = [F::ZERO; NUM_COSET_POINTS];
    for j in 0..SKIP_SIZE {
        out[j] = g * dom[j];
        out[SKIP_SIZE + j] = g2 * dom[j];
    }
    out
}

/// Per-chip input to [`skip_round_poly`]: the real rows, row-major.
pub struct SkipChipInput<'a, F: Field, EF: Field, A> {
    pub chip: &'a Chip<F, A>,
    pub main_cells: &'a [F],
    pub num_main_cols: usize,
    pub prep_cells: Option<&'a [F]>,
    pub num_prep_cols: usize,
    pub height: usize,
    pub gkr_powers: &'a [EF],
    pub padded_row_adjustment: EF,
}

/// One chip's skip message `s_c(Z)` ([`SKIP_POLY_LEN`] coefficients).
///
/// `zeta` is the GKR point, LSB-first, `num_variables` long (> 4).
#[allow(clippy::too_many_lines)]
pub fn skip_round_poly<F, EF, A>(
    input: &SkipChipInput<'_, F, EF, A>,
    alpha: EF,
    public_values: &[F],
    zeta: &[EF],
) -> UnivariatePolynomial<EF>
where
    F: TwoAdicField,
    EF: ExtensionField<F>,
    A: MachineAir<F> + for<'b> Air<ShardConstraintFolder<'b, F, F, EF>> + Sync,
{
    assert!(zeta.len() > SKIP_BITS, "univariate skip needs more than 4 row variables");
    let h = input.height;
    let nm = input.num_main_cols;
    let np = input.num_prep_cols;
    let nblk = h.div_ceil(SKIP_SIZE);
    if nblk == 0 {
        return UnivariatePolynomial { coefficients: vec![EF::ZERO; SKIP_POLY_LEN] };
    }
    let zeta_hi_be: Vec<EF> = zeta[SKIP_BITS..].iter().rev().copied().collect();
    let eq_hi = partial_lagrange_prefix(&zeta_hi_be, nblk);

    let pts = coset_points::<F>();
    let lz_f: Vec<[F; SKIP_SIZE]> = pts.iter().map(|&z| lagrange_weights::<F, F>(z)).collect();
    let pra = input.padded_row_adjustment;
    let gk = input.gkr_powers;

    let zero_acc = || ([EF::ZERO; NUM_COSET_POINTS], [EF::ZERO; SKIP_SIZE]);
    let (a_vals, g_vals) = (0..nblk)
        .into_par_iter()
        .map_init(
            || (vec![F::ZERO; nm], vec![F::ZERO; np]),
            |(mz, pz), x| {
                let mut a = [EF::ZERO; NUM_COSET_POINTS];
                let mut g = [EF::ZERO; SKIP_SIZE];
                let eq = eq_hi[x];
                let row0 = x * SKIP_SIZE;
                let real = (h - row0).min(SKIP_SIZE);
                for (b, gb) in g.iter_mut().enumerate().take(real) {
                    let r = row0 + b;
                    let mut t = EF::ZERO;
                    for c in 0..nm {
                        t += gk[c] * input.main_cells[r * nm + c];
                    }
                    if let Some(p) = input.prep_cells {
                        for c in 0..np {
                            t += gk[nm + c] * p[r * np + c];
                        }
                    }
                    *gb = t * eq;
                }
                for (j, w) in lz_f.iter().enumerate() {
                    for c in 0..nm {
                        let mut v = F::ZERO;
                        for b in 0..real {
                            v += w[b] * input.main_cells[(row0 + b) * nm + c];
                        }
                        mz[c] = v;
                    }
                    if let Some(p) = input.prep_cells {
                        for c in 0..np {
                            let mut v = F::ZERO;
                            for b in 0..real {
                                v += w[b] * p[(row0 + b) * np + c];
                            }
                            pz[c] = v;
                        }
                    }
                    let cz = eval_air_constraints_at_row::<F, F, EF, A>(
                        input.chip,
                        alpha,
                        public_values,
                        pz,
                        mz,
                    );
                    let pad = w[real..].iter().copied().fold(F::ZERO, |s, v| s + v);
                    a[j] = (cz - pra * pad) * eq;
                }
                (a, g)
            },
        )
        .reduce(zero_acc, |(mut a1, mut g1), (a2, g2)| {
            for (x, y) in a1.iter_mut().zip(a2.iter()) {
                *x += *y;
            }
            for (x, y) in g1.iter_mut().zip(g2.iter()) {
                *x += *y;
            }
            (a1, g1)
        });

    skip_poly_from_sums::<F, EF>(&a_vals, &g_vals, &zeta[..SKIP_BITS])
}

/// One chip's skip message from its block sums: `a_vals[j]` is
/// `Σ_x eq_hi[x]·(C(row block x at coset point j) − pra·pad_x(j))` and
/// `g_vals[b]` is `Σ_x eq_hi[x]·T(row 16x + b)` (the β-batched GKR term).
/// `zeta_lo` is the GKR point's four low coordinates, LSB-first.
#[must_use]
pub fn skip_poly_from_sums<F: TwoAdicField, EF: ExtensionField<F>>(
    a_vals: &[EF; NUM_COSET_POINTS],
    g_vals: &[EF; SKIP_SIZE],
    zeta_lo: &[EF],
) -> UnivariatePolynomial<EF> {
    let pts = coset_points::<F>();
    let xs: Vec<EF> = pts.iter().map(|&z| EF::from(z)).collect();
    let qs: Vec<EF> = pts
        .iter()
        .zip(a_vals.iter())
        .map(|(&z, &a)| a * (z.exp_power_of_2(SKIP_BITS) - F::ONE).inverse())
        .collect();
    let q = interpolate_univariate_polynomial(&xs, &qs).coefficients;
    let mut inner = vec![EF::ZERO; SKIP_SIZE + q.len()];
    for (i, &c) in q.iter().enumerate() {
        inner[i + SKIP_SIZE] += c;
        inner[i] -= c;
    }
    for (i, c) in coeffs_from_domain_values::<F, EF>(g_vals).into_iter().enumerate() {
        inner[i] += c;
    }
    let eq_sharp_coeffs = coeffs_from_domain_values::<F, EF>(&eq_low_bits(zeta_lo));
    let mut s = poly_mul(&eq_sharp_coeffs, &inner);
    debug_assert!(
        s[SKIP_POLY_LEN.min(s.len())..].iter().all(|c| c.is_zero()),
        "skip message exceeds degree 60: a constraint of degree > 3 or an unsatisfied trace"
    );
    s.resize(SKIP_POLY_LEN, EF::ZERO);
    UnivariatePolynomial { coefficients: s }
}

/// Fold row-major real rows 16:1 with `weights` (`L_b(r0)`), rows past
/// `height` reading zero.  Output is row-major `ceil(height/16) × ncols`.
#[must_use]
pub fn fold_rows_16<F: Field, EF: ExtensionField<F>>(
    cells: &[F],
    ncols: usize,
    height: usize,
    weights: &[EF; SKIP_SIZE],
) -> Vec<EF> {
    let nblk = height.div_ceil(SKIP_SIZE);
    let mut out = vec![EF::ZERO; nblk * ncols];
    out.par_chunks_mut(ncols.max(1)).enumerate().for_each(|(x, row)| {
        if ncols == 0 {
            return;
        }
        let row0 = x * SKIP_SIZE;
        let real = (height - row0).min(SKIP_SIZE);
        for (c, slot) in row.iter_mut().enumerate() {
            let mut acc = EF::ZERO;
            for b in 0..real {
                acc += weights[b] * cells[(row0 + b) * ncols + c];
            }
            *slot = acc;
        }
    });
    out
}

/// Row-weight table of a skip row point `z_row` (big-endian, `N` long, the
/// four low slots all `r0`): entry `r` is `L_{r mod 16}(r0) · eq(z_hi, r >> 4)`,
/// `2^N` entries.  Replaces the multilinear `eq(z_row, r)` table everywhere the
/// jagged PCS weighs rows.
#[must_use]
pub fn skip_row_eq_table<EF: TwoAdicField + Send + Sync>(z_row: &[EF]) -> Vec<EF> {
    let n = z_row.len();
    assert!(n > SKIP_BITS, "skip row point needs more than 4 coordinates");
    let hi = crate::zerocheck_prover::eq_mle_table_rev::<EF>(&z_row[..n - SKIP_BITS]);
    let w = lagrange_weights::<EF, EF>(z_row[n - 1]);
    let mut out = vec![EF::ZERO; hi.len() * SKIP_SIZE];
    out.par_chunks_mut(SKIP_SIZE).zip(hi.par_iter()).for_each(|(chunk, &e)| {
        for (o, &l) in chunk.iter_mut().zip(w.iter()) {
            *o = e * l;
        }
    });
    out
}

/// The skip row point `(z_hi, r0, r0, r0, r0)` the zerocheck hands the
/// jagged PCS.
#[must_use]
pub fn skip_row_point<EF: Field>(z_hi_be: &[EF], r0: EF) -> Vec<EF> {
    let mut p = z_hi_be.to_vec();
    p.extend(core::iter::repeat_n(r0, SKIP_BITS));
    p
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_field::extension::BinomialExtensionField;
    use p3_field::{BasedVectorSpace, PrimeCharacteristicRing};
    use p3_koala_bear::KoalaBear;
    use rand::{Rng, SeedableRng};

    type F = KoalaBear;
    type EF = BinomialExtensionField<F, 4>;

    fn rand_ef(rng: &mut impl Rng) -> EF {
        EF::from_basis_coefficients_iter(
            (0..4).map(|_| F::from_u32(rng.gen::<u32>() % 0x7f00_0001)),
        )
        .unwrap()
    }

    #[test]
    fn lagrange_weights_interpolate() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(1);
        let coeffs: Vec<EF> = (0..SKIP_SIZE).map(|_| rand_ef(&mut rng)).collect();
        let p = UnivariatePolynomial { coefficients: coeffs.clone() };
        let dom = skip_domain::<F>();
        let vals: [EF; SKIP_SIZE] = core::array::from_fn(|b| p.eval_at_point(EF::from(dom[b])));
        assert_eq!(coeffs_from_domain_values::<F, EF>(&vals), coeffs);
        let z = rand_ef(&mut rng);
        let l = lagrange_weights::<F, EF>(z);
        let via = l.iter().zip(vals.iter()).fold(EF::ZERO, |a, (&x, &y)| a + x * y);
        assert_eq!(via, p.eval_at_point(z));
        assert_eq!(l.iter().copied().sum::<EF>(), EF::ONE);
        let on = lagrange_weights::<F, EF>(EF::from(dom[5]));
        assert_eq!(on[5], EF::ONE);
        assert_eq!(on.iter().copied().sum::<EF>(), EF::ONE);
    }

    #[test]
    fn eq_sharp_matches_hypercube_on_domain() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(2);
        let zl: Vec<EF> = (0..SKIP_BITS).map(|_| rand_ef(&mut rng)).collect();
        let e = eq_low_bits(&zl);
        let dom = skip_domain::<F>();
        for b in 0..SKIP_SIZE {
            assert_eq!(eq_sharp::<F, EF>(&zl, EF::from(dom[b])), e[b]);
        }
    }

    #[test]
    fn domain_sum_rule() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(3);
        let coeffs: Vec<EF> = (0..SKIP_POLY_LEN).map(|_| rand_ef(&mut rng)).collect();
        let p = UnivariatePolynomial { coefficients: coeffs.clone() };
        let direct: EF =
            skip_domain::<F>().iter().map(|&w| p.eval_at_point(EF::from(w))).sum::<EF>();
        assert_eq!(sum_over_domain(&coeffs), direct);
    }
}
