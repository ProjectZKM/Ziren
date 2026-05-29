//! Per-chip lazy `ZeroCheckPoly` for the SP1-aligned shard zerocheck.
//!
//! This is a CPU port of SP1's
//! [`hypercube::prover::zerocheck::ZeroCheckPoly`] (mod.rs / sum_as_poly.rs
//! / fix_last_variable.rs) plus the `slop_multilinear` primitives it
//! depends on (`VirtualGeq`, the LSB-adjacent MLE fold,
//! `partial_lagrange`) and `slop_algebra::interpolate_univariate_polynomial`.
//!
//! # Why this exists
//!
//! Ziren's legacy zerocheck materialized one dense per-chip C-table,
//! zero-padded every chip up to the shard's `max_log_row_count`,
//! lambda-RLC'd them into a single combined table, and ran a degree-1
//! sumcheck whose `claimed_sum` was forced to `0`.  That transcript is
//! NOT what the recursion verifier
//! (`crate::recursion_circuit::zerocheck::verify_zerocheck`) expects:
//! the circuit asserts `claimed_sum == λ-RLC(GKR opening batches)` and
//! that the reduced evaluation equals `Σ_chip λ^k·eq·(constraint_eval
//! + openings_batch)`, built from genuine eq-weighted degree-3 round
//! polynomials.  This module produces exactly that SP1-shape transcript
//! on the host, per chip, summing only over each chip's real rows
//! (`num_real_entries`) with the padded tail handled analytically by
//! [`VirtualGeq`] — so cost grows as `Σ chip_height`, not
//! `num_chips · 2^max_log_row_count`.
//!
//! # Conventions (must match `BasefoldConstraintFolder` + the recursion
//! circuit; see `verify_zerocheck_cryptographic_identity_host`)
//!
//!   * MLE fold: adjacent pairs `(2i, 2i+1)` → `i`, last odd row
//!     paired with the `ZERO` padding constant (LSB-first, identical to
//!     `crate::basefold::Mle` and `slop` `mle_fix_last_variable`).  The
//!     "last variable" fixed each round is the least-significant bit of
//!     the row index; `zeta`'s last coordinate.
//!   * `partial_lagrange`: big-endian, `point[0]` is the MSB.
//!   * constraint α-RLC: Horner (`acc·α + c`) via
//!     [`BasefoldConstraintFolder`] — algebraically identical to SP1's
//!     reversed `powers_of_alpha` array.
//!   * GKR-opening batch powers: `[β¹, β², …]`, columns ordered
//!     main-then-preprocessed.
//!
//! # Field typing
//!
//! SP1 keeps the first sumcheck round in the base field (`K = F`) for
//! speed, transitioning to `EF` after the first fold.  Ziren's
//! `SumcheckPoly` traits are monomorphic in the challenge field, so this
//! port lifts trace columns to `EF` up front and runs every round in
//! `EF`.  The result is bit-identical for honest traces (the dropped
//! base-field fast path only skips arithmetic that evaluates to the same
//! value); the first-round constraint-at-point-0 skip is preserved
//! exactly (it is `0` on satisfied real rows).

use std::marker::PhantomData;

use p3_air::Air;
use p3_challenger::{CanObserve, FieldChallenger};
use p3_field::{BasedVectorSpace, ExtensionField, Field};

use crate::air::MachineAir;
use crate::folder::PairWindow;
use crate::septic_curve::SepticCurve;
use crate::septic_digest::SepticDigest;
use crate::septic_extension::SepticExtension;
use crate::shard_level::basefold_constraint_folder::BasefoldConstraintFolder;
use crate::shard_level::sumcheck_poly::{
    ComponentPoly, SumcheckPoly, SumcheckPolyBase, SumcheckPolyFirstRound,
};
use crate::shard_level::types::{PartialSumcheckProof, UnivariatePolynomial};
use crate::Chip;

// ───────────────────────── serial sumcheck driver ────────────────────────
//
// A `Send + Sync`-free reduction over `ZeroCheckPoly`s (which borrow the
// chip and so are not `Sync` without an `A: Sync` bound that would
// cascade through the whole prover trait stack).  This is a faithful
// copy of `sumcheck_poly::reduce_sumcheck_to_evaluation`'s body — same
// `point.insert(0, alpha)` front-build, same per-coefficient base-field
// observation, same `claimed_sum = λ-RLC(claims)` — so the proof it
// emits is replayed identically by `verify_sumcheck_host`.  The polys
// are reduced sequentially (the original is also sequential over polys;
// the rayon parallelism lives inside each poly's `sum_as_poly`).

#[inline]
fn observe_ext<F, EF, Challenger>(challenger: &mut Challenger, v: EF)
where
    F: Field,
    EF: BasedVectorSpace<F>,
    Challenger: CanObserve<F>,
{
    for c in v.as_basis_coefficients_slice() {
        challenger.observe(*c);
    }
}

#[inline]
fn poly_eval<EF: Field>(coeffs: &[EF], x: EF) -> EF {
    let mut acc = EF::ZERO;
    for c in coeffs.iter().rev() {
        acc = acc * x + *c;
    }
    acc
}

/// `result = polys[0]·λ^{n-1} + … + polys[n-1]` (coefficient-wise).
fn rlc_univariate_polynomials<EF: Field>(
    polys: &[UnivariatePolynomial<EF>],
    lambda: EF,
) -> UnivariatePolynomial<EF> {
    if polys.is_empty() {
        return UnivariatePolynomial { coefficients: Vec::new() };
    }
    if polys.len() == 1 {
        return polys[0].clone();
    }
    let max_deg = polys.iter().map(|p| p.coefficients.len()).max().unwrap();
    let mut acc = vec![EF::ZERO; max_deg];
    for p in polys {
        for slot in acc.iter_mut() {
            *slot = *slot * lambda;
        }
        for (i, c) in p.coefficients.iter().enumerate() {
            acc[i] = acc[i] + *c;
        }
    }
    UnivariatePolynomial { coefficients: acc }
}

/// `result = vals[0]·λ^{n-1} + … + vals[n-1]`.
fn rlc_eval<EF: Field>(vals: &[EF], lambda: EF) -> EF {
    let mut acc = EF::ZERO;
    for &v in vals {
        acc = acc * lambda + v;
    }
    acc
}

/// Sequential `reduce_sumcheck_to_evaluation` (no `Send + Sync` bound on
/// the poly).  Returns only the `PartialSumcheckProof`; the per-chip
/// component openings are not needed by the zerocheck consumers.
/// Returns the proof plus per-poly `component_poly_evals` — each poly's
/// preprocessed-then-main column openings at the reduced point `z` (i.e.
/// trace@z), in the SAME order as the input `polys`.  These are the
/// trace evaluations the jagged PCS must open at `z` (see SP1
/// shard.rs:613-643).
pub(crate) fn reduce_sumcheck_serial<F, EF, P, Challenger>(
    polys: Vec<P>,
    challenger: &mut Challenger,
    claims: Vec<EF>,
    t: usize,
    lambda: EF,
) -> (PartialSumcheckProof<EF>, Vec<Vec<EF>>)
where
    F: Field,
    EF: ExtensionField<F> + BasedVectorSpace<F>,
    P: SumcheckPolyFirstRound<EF>,
    Challenger: FieldChallenger<F>,
{
    assert!(!polys.is_empty(), "reduce_sumcheck_serial: empty input");
    let num_variables = polys[0].num_variables();
    assert!(
        polys.iter().all(|poly| poly.num_variables() == num_variables),
        "reduce_sumcheck_serial: polys disagree on num_variables"
    );
    assert!(num_variables as usize >= t, "reduce_sumcheck_serial: t > num_variables");
    assert!(num_variables > 0, "reduce_sumcheck_serial: zero-variable poly");
    assert_eq!(claims.len(), polys.len());

    let mut point: Vec<EF> = Vec::with_capacity(num_variables as usize);
    let mut univariate_poly_msgs: Vec<UnivariatePolynomial<EF>> =
        Vec::with_capacity(num_variables as usize);

    // Round 0.
    let mut uni_polys: Vec<UnivariatePolynomial<EF>> = polys
        .iter()
        .zip(claims.iter())
        .map(|(poly, claim)| poly.sum_as_poly_in_last_t_variables(Some(*claim), t))
        .collect();
    let mut rlc_uni_poly = rlc_univariate_polynomials(&uni_polys, lambda);
    for c in &rlc_uni_poly.coefficients {
        observe_ext::<F, EF, _>(challenger, *c);
    }
    univariate_poly_msgs.push(rlc_uni_poly.clone());

    let mut alpha: EF = challenger.sample_algebra_element::<EF>();
    point.insert(0, alpha);

    let mut polys_cursor: Vec<P::NextRoundPoly> =
        polys.into_iter().map(|poly| poly.fix_t_variables(alpha, t)).collect();

    for _ in t..num_variables as usize {
        let alpha_prev = *point.first().unwrap();
        let round_claims: Vec<EF> =
            uni_polys.iter().map(|poly| poly_eval(&poly.coefficients, alpha_prev)).collect();

        uni_polys = polys_cursor
            .iter()
            .zip(round_claims.iter())
            .map(|(poly, &round_claim)| poly.sum_as_poly_in_last_variable(Some(round_claim)))
            .collect();
        rlc_uni_poly = rlc_univariate_polynomials(&uni_polys, lambda);
        for c in &rlc_uni_poly.coefficients {
            observe_ext::<F, EF, _>(challenger, *c);
        }
        univariate_poly_msgs.push(rlc_uni_poly.clone());

        alpha = challenger.sample_algebra_element::<EF>();
        point.insert(0, alpha);

        polys_cursor =
            polys_cursor.into_iter().map(|poly| poly.fix_last_variable(alpha)).collect();
    }

    let alpha_last = *point.first().unwrap();
    let evals: Vec<EF> =
        uni_polys.iter().map(|poly| poly_eval(&poly.coefficients, alpha_last)).collect();

    let claimed_sum = rlc_eval(&claims, lambda);
    let final_eval = rlc_eval(&evals, lambda);

    // Per-poly component openings (prep-then-main) at the reduced point.
    let component_poly_evals: Vec<Vec<EF>> =
        polys_cursor.iter().map(|poly| poly.get_component_poly_evals()).collect();

    (
        PartialSumcheckProof {
            univariate_polys: univariate_poly_msgs,
            claimed_sum,
            point_and_eval: (point, final_eval),
        },
        component_poly_evals,
    )
}

// ───────────────────────────── ported primitives ─────────────────────────

/// `eq(point, -)` lagrange weights over the `2^|point|` hypercube,
/// big-endian (`point[0]` = MSB).  Port of `slop` `partial_lagrange`.
pub(crate) fn partial_lagrange<EF: Field>(point: &[EF]) -> Vec<EF> {
    let mut evals = vec![EF::ONE];
    for &c in point {
        evals = evals
            .iter()
            .flat_map(|&v| {
                let prod = v * c;
                [v - prod, prod]
            })
            .collect();
    }
    evals
}

/// Lagrange-interpolate the polynomial through `(xs[i], ys[i])` into
/// monomial-basis coefficients.  Port of
/// `slop_algebra::interpolate_univariate_polynomial`.  Panics if `xs`
/// has duplicate points or `xs.len() != ys.len()`.
pub(crate) fn interpolate_univariate_polynomial<EF: Field>(
    xs: &[EF],
    ys: &[EF],
) -> UnivariatePolynomial<EF> {
    assert_eq!(xs.len(), ys.len());
    let mut result: Vec<EF> = vec![EF::ZERO];
    for (i, (&x, &y)) in xs.iter().zip(ys.iter()).enumerate() {
        // numerator = y · Π_{j≠i}(X − xj); denominator = Π_{j≠i}(x − xj).
        let mut numerator: Vec<EF> = vec![y];
        let mut denominator = EF::ONE;
        for (j, &xj) in xs.iter().enumerate() {
            if j == i {
                continue;
            }
            denominator *= x - xj;
            // numerator = numerator·X + numerator·(−xj)
            let neg_xj = -xj;
            let mut next = vec![EF::ZERO; numerator.len() + 1];
            for (k, c) in numerator.iter().enumerate() {
                next[k + 1] += *c; // ·X
                next[k] += *c * neg_xj; // ·(−xj)
            }
            numerator = next;
        }
        let inv = denominator.inverse();
        let len = result.len().max(numerator.len());
        let mut next = vec![EF::ZERO; len];
        for (k, slot) in next.iter_mut().enumerate() {
            let a = result.get(k).copied().unwrap_or(EF::ZERO);
            let b = numerator.get(k).copied().unwrap_or(EF::ZERO) * inv;
            *slot = a + b;
        }
        result = next;
    }
    UnivariatePolynomial { coefficients: result }
}

/// Dense linear combination of a geq and an eq polynomial sharing one
/// threshold.  Port of `slop_multilinear::VirtualGeq` restricted to the
/// `fix_last_variable` + `eval_at_usize` operations the zerocheck round
/// prover needs.
#[derive(Clone, Copy, Debug)]
pub(crate) struct VirtualGeq<F> {
    pub threshold: u32,
    pub geq_coefficient: F,
    pub eq_coefficient: F,
    pub num_vars: u32,
}

impl<F: Field> VirtualGeq<F> {
    pub fn new(threshold: u32, geq_coefficient: F, eq_coefficient: F, num_vars: u32) -> Self {
        assert!(threshold <= (1 << num_vars));
        Self { threshold, geq_coefficient, eq_coefficient, num_vars }
    }

    /// Fix the last (least-significant) variable to `alpha`.
    pub fn fix_last_variable(&self, alpha: F) -> VirtualGeq<F> {
        assert_ne!(self.num_vars, 0, "fix_last_variable on a 0-variable VirtualGeq");
        let new_threshold = self.threshold >> 1;
        let new_geq_coefficient = self.geq_coefficient;
        let new_eq_coefficient = if self.threshold & 1 == 0 {
            (F::ONE - alpha) * self.eq_coefficient
        } else {
            alpha * (self.eq_coefficient + self.geq_coefficient) - self.geq_coefficient
        };
        VirtualGeq {
            threshold: new_threshold,
            geq_coefficient: new_geq_coefficient,
            eq_coefficient: new_eq_coefficient,
            num_vars: self.num_vars.saturating_sub(1),
        }
    }

    /// Index into the length-`2^num_vars` virtual vector.
    pub fn eval_at_usize(&self, index: usize) -> F {
        assert!(index < (1 << self.num_vars));
        if index < self.threshold as usize {
            F::ZERO
        } else if index == self.threshold as usize {
            self.eq_coefficient + self.geq_coefficient
        } else {
            self.geq_coefficient
        }
    }
}

// ───────────────────────────── ZeroCheckPoly ─────────────────────────────

/// One chip's zerocheck sumcheck polynomial.
///
/// Lifetime `'a` borrows the chip + public values for the duration of a
/// single `prove_shard_zerocheck` call; the poly never escapes it.
pub struct ZeroCheckPoly<'a, F: Field, EF: ExtensionField<F>, A> {
    /// The chip whose AIR constraints are summed.
    air: &'a Chip<F, A>,
    /// Shard public values.
    public_values: &'a [F],
    /// Constraint-batching challenge (Horner α).
    alpha: EF,
    /// GKR-opening batch powers `[β¹, …, β^(main+prep)]` for this chip,
    /// indexed main-then-preprocessed.
    gkr_powers: Vec<EF>,
    /// The eq anchor — the LogUp-GKR emitted point; shrinks by one
    /// coordinate per fold.
    zeta: Vec<EF>,
    /// Real main-trace cells, row-major `num_real_entries × num_main_cols`
    /// (lifted to `EF`).
    main_cells: Vec<EF>,
    num_main_cols: usize,
    /// Real preprocessed-trace cells, if the chip has a preprocessed trace.
    prep_cells: Option<Vec<EF>>,
    num_prep_cols: usize,
    /// Number of real rows currently held (halves each fold).
    num_real_entries: usize,
    /// Logical variable count (= `max_log_row_count` initially); the
    /// `2^num_variables − num_real_entries` gap is virtual padding.
    num_variables: u32,
    /// Folded constant from the eq polynomial's already-fixed coordinates.
    eq_adjustment: EF,
    /// geq polynomial value (0 once ≥1 non-padded variable remains).
    geq_value: EF,
    /// Constraint accumulator the chip produces on an all-zero row.
    padded_row_adjustment: EF,
    /// Virtual padded-row indicator.
    virtual_geq: VirtualGeq<EF>,
    _marker: PhantomData<A>,
}

impl<'a, F, EF, A> ZeroCheckPoly<'a, F, EF, A>
where
    F: Field,
    EF: ExtensionField<F>,
    A: MachineAir<F> + for<'b> Air<BasefoldConstraintFolder<'b, F, EF>>,
{
    /// Construct a chip's zerocheck poly.  `main_cells` / `prep_cells`
    /// are the real (un-padded) trace rows, row-major, lifted to `EF`.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        air: &'a Chip<F, A>,
        public_values: &'a [F],
        alpha: EF,
        gkr_powers: Vec<EF>,
        zeta: Vec<EF>,
        main_cells: Vec<EF>,
        num_main_cols: usize,
        prep_cells: Option<Vec<EF>>,
        num_prep_cols: usize,
        num_real_entries: usize,
        num_variables: u32,
        eq_adjustment: EF,
        geq_value: EF,
        padded_row_adjustment: EF,
        virtual_geq: VirtualGeq<EF>,
    ) -> Self {
        debug_assert_eq!(zeta.len() as u32, num_variables, "zeta dim must equal num_variables");
        debug_assert!(num_real_entries <= 1 << num_variables);
        Self {
            air,
            public_values,
            alpha,
            gkr_powers,
            zeta,
            main_cells,
            num_main_cols,
            prep_cells,
            num_prep_cols,
            num_real_entries,
            num_variables,
            eq_adjustment,
            geq_value,
            padded_row_adjustment,
            virtual_geq,
            _marker: PhantomData,
        }
    }

    /// Evaluate the chip's α-RLC'd constraints at a single `EF` row.
    fn eval_air_at_row(&self, prep_row: &[EF], main_row: &[EF]) -> EF {
        eval_air_constraints_at_row(self.air, self.alpha, self.public_values, prep_row, main_row)
    }

    /// `Σ_i (main_row ++ prep_row)[i] · gkr_powers[i]`.
    fn gkr_batch(&self, main_row: &[EF], prep_row: &[EF]) -> EF {
        main_row
            .iter()
            .chain(prep_row.iter())
            .zip(self.gkr_powers.iter())
            .fold(EF::ZERO, |acc, (v, p)| acc + *v * *p)
    }

    /// Core round polynomial.  `IS_FIRST_ROUND` skips the
    /// constraint-eval at interpolation point 0 (it is `0` on satisfied
    /// real rows).
    fn sum_as_poly(&self, claim: Option<EF>, is_first_round: bool) -> UnivariatePolynomial<EF> {
        let num_real = self.num_real_entries;
        if num_real == 0 {
            // Pure-padding chip contributes nothing; emit a degree-4
            // dummy (5 zero coefficients) to byte-match SP1's
            // `UnivariatePolynomial::zero(4)` (= vec![zero; degree+1] = 5)
            // and the recursion dummy `dummy_partial_sumcheck_proof(.., 4)`,
            // and the real-path degree-4 interpolant over {0,1,2,4,eq-root}.
            return UnivariatePolynomial { coefficients: vec![EF::ZERO; 5] };
        }
        let claim = claim.expect("sum_as_poly: claim required for the zerocheck poly");

        let dim = self.zeta.len();
        let last = self.zeta[dim - 1];
        let rest_point = &self.zeta[..dim - 1];
        let partial = partial_lagrange(rest_point);

        let nm = self.num_main_cols;
        let np = self.num_prep_cols;
        let num_pairs = num_real.div_ceil(2);

        let (mut y_0, mut y_2, mut y_4) = (EF::ZERO, EF::ZERO, EF::ZERO);

        // Scratch buffers reused across pairs.
        let mut m0 = vec![EF::ZERO; nm];
        let mut m2 = vec![EF::ZERO; nm];
        let mut m4 = vec![EF::ZERO; nm];
        let mut p0 = vec![EF::ZERO; np];
        let mut p2 = vec![EF::ZERO; np];
        let mut p4 = vec![EF::ZERO; np];

        for pair in 0..num_pairs {
            let eq = partial[pair];
            let row0 = 2 * pair;
            let row1 = 2 * pair + 1;

            interp_pair(&self.main_cells, nm, num_real, row0, row1, &mut m0, &mut m2, &mut m4);
            if np > 0 {
                let prep = self.prep_cells.as_ref().expect("prep_cells present when np > 0");
                interp_pair(prep, np, num_real, row0, row1, &mut p0, &mut p2, &mut p4);
            }

            let g0 = self.gkr_batch(&m0, &p0);
            let g2 = self.gkr_batch(&m2, &p2);
            let g4 = g2 + g2 - g0; // gkr is linear in the row values

            let c0 = if is_first_round { EF::ZERO } else { self.eval_air_at_row(&p0, &m0) };
            let c2 = self.eval_air_at_row(&p2, &m2);
            let c4 = self.eval_air_at_row(&p4, &m4);

            y_0 += (c0 + g0) * eq;
            y_2 += (c2 + g2) * eq;
            y_4 += (c4 + g4) * eq;
        }

        // Padded-row correction at the boundary index.
        let threshold_half = num_pairs - 1;
        let msb_lagrange_eval: EF = self.eq_adjustment
            * if threshold_half < (1usize << (self.num_variables - 1)) {
                partial[threshold_half]
            } else {
                EF::ZERO
            };
        let virtual_0 = self.virtual_geq.fix_last_variable(EF::ZERO).eval_at_usize(threshold_half);
        let virtual_2 =
            self.virtual_geq.fix_last_variable(EF::from_u64(2)).eval_at_usize(threshold_half);
        let virtual_4 =
            self.virtual_geq.fix_last_variable(EF::from_u64(4)).eval_at_usize(threshold_half);

        // Interpolation samples: points {0, 1, 2, 4, eq-root}; the
        // degree-3 round poly has a known root where the eq term's last
        // factor vanishes, plus y_1 = claim − y_0 ties p(0)+p(1)=claim.
        let mut xs: Vec<EF> = Vec::with_capacity(5);
        let mut ys: Vec<EF> = Vec::with_capacity(5);

        xs.push(EF::ZERO);
        let elf_0 = EF::ONE - last;
        y_0 = y_0 * (elf_0 * self.eq_adjustment)
            - self.padded_row_adjustment * virtual_0 * msb_lagrange_eval * elf_0;
        ys.push(y_0);

        xs.push(EF::ONE);
        ys.push(claim - y_0);

        xs.push(EF::from_u64(2));
        let elf_2 = last * EF::from_u64(3) - EF::ONE;
        y_2 = y_2 * (elf_2 * self.eq_adjustment)
            - self.padded_row_adjustment * virtual_2 * msb_lagrange_eval * elf_2;
        ys.push(y_2);

        xs.push(EF::from_u64(4));
        let elf_4 = last * EF::from_u64(7) - EF::from_u64(3);
        y_4 = y_4 * (elf_4 * self.eq_adjustment)
            - self.padded_row_adjustment * virtual_4 * msb_lagrange_eval * elf_4;
        ys.push(y_4);

        // eq-first-term root: b = (1 − last) / (1 − 2·last).
        let b_const = (EF::ONE - last) * (EF::ONE - last.double()).inverse();
        xs.push(b_const);
        ys.push(EF::ZERO);

        interpolate_univariate_polynomial(&xs, &ys)
    }

    /// Fix the last (least-significant) variable to `alpha`.
    fn fix_last(self, alpha: EF) -> Self {
        let new_main = fold_cells(&self.main_cells, self.num_main_cols, self.num_real_entries, alpha);
        let new_prep = self
            .prep_cells
            .as_ref()
            .map(|c| fold_cells(c, self.num_prep_cols, self.num_real_entries, alpha));
        let new_num_real = self.num_real_entries.div_ceil(2);
        let new_num_vars = self.num_variables - 1;
        let new_virtual_geq = self.virtual_geq.fix_last_variable(alpha);

        let dim = self.zeta.len();
        let last = self.zeta[dim - 1];
        let rest: Vec<EF> = self.zeta[..dim - 1].to_vec();

        if self.num_real_entries == 0 {
            // Pure padding: nothing to weight, keep eq/geq/pra as-is.
            return Self {
                zeta: rest,
                main_cells: new_main,
                prep_cells: new_prep,
                num_real_entries: new_num_real,
                num_variables: new_num_vars,
                virtual_geq: new_virtual_geq,
                ..self
            };
        }

        // Factor out the fixed eq coordinate as a constant.
        let eq_adjustment =
            self.eq_adjustment * ((alpha * last) + (EF::ONE - alpha) * (EF::ONE - last));

        let has_non_padded_vars = self.num_real_entries > 1;
        let geq_value = if has_non_padded_vars {
            EF::ZERO
        } else {
            (EF::ONE - self.geq_value) * alpha + self.geq_value
        };

        Self {
            zeta: rest,
            main_cells: new_main,
            prep_cells: new_prep,
            num_real_entries: new_num_real,
            num_variables: new_num_vars,
            eq_adjustment,
            geq_value,
            virtual_geq: new_virtual_geq,
            ..self
        }
    }
}

/// Evaluate a chip's α-RLC'd AIR constraints at one `EF` row through
/// the [`BasefoldConstraintFolder`] (Horner α; cumulative sums held at
/// zero — lookup soundness rides on LogUp-GKR, not this zerocheck).
pub fn eval_air_constraints_at_row<F, EF, A>(
    chip: &Chip<F, A>,
    alpha: EF,
    public_values: &[F],
    prep_row: &[EF],
    main_row: &[EF],
) -> EF
where
    F: Field,
    EF: ExtensionField<F>,
    A: MachineAir<F> + for<'b> Air<BasefoldConstraintFolder<'b, F, EF>>,
{
    let local_sum = EF::ZERO;
    let global_sum: SepticDigest<F> = SepticDigest(SepticCurve {
        x: SepticExtension::<F>([F::ZERO; 7]),
        y: SepticExtension::<F>([F::ZERO; 7]),
    });
    let mut folder = BasefoldConstraintFolder::<F, EF> {
        preprocessed: PairWindow { local: prep_row, next: prep_row },
        main: PairWindow { local: main_row, next: main_row },
        alpha,
        accumulator: EF::ZERO,
        public_values,
        local_cumulative_sum: &local_sum,
        global_cumulative_sum: &global_sum,
        _marker: PhantomData,
    };
    chip.eval(&mut folder);
    folder.accumulator
}

/// Constraint accumulator the chip produces on an all-zero row; the
/// padded-row contribution the sumcheck subtracts (gated by
/// `virtual_geq`).  `main_width`/`prep_width` are the chip's column
/// counts.
pub fn compute_padded_row_adjustment<F, EF, A>(
    chip: &Chip<F, A>,
    alpha: EF,
    public_values: &[F],
    main_width: usize,
    prep_width: usize,
) -> EF
where
    F: Field,
    EF: ExtensionField<F>,
    A: MachineAir<F> + for<'b> Air<BasefoldConstraintFolder<'b, F, EF>>,
{
    let main_row = vec![EF::ZERO; main_width];
    let prep_row = vec![EF::ZERO; prep_width];
    eval_air_constraints_at_row(chip, alpha, public_values, &prep_row, &main_row)
}

/// Linear interpolation of one column-pair `(row0, row1)` at last-var
/// points 0, 2, 4.  Out-of-range `row1` (odd tail) is the `ZERO`
/// padding constant.  `vals_0 = r0`, `vals_2 = r0 + 2·slope`,
/// `vals_4 = r0 + 4·slope`, `slope = r1 − r0`.
fn interp_pair<EF: Field>(
    cells: &[EF],
    ncols: usize,
    num_real: usize,
    row0: usize,
    row1: usize,
    vals_0: &mut [EF],
    vals_2: &mut [EF],
    vals_4: &mut [EF],
) {
    let r0 = &cells[row0 * ncols..row0 * ncols + ncols];
    for c in 0..ncols {
        let a = r0[c];
        let b = if row1 < num_real { cells[row1 * ncols + c] } else { EF::ZERO };
        let slope = b - a;
        let slope2 = slope + slope;
        let slope4 = slope2 + slope2;
        vals_0[c] = a;
        vals_2[c] = slope2 + a;
        vals_4[c] = slope4 + a;
    }
}

/// Fold the last (least-significant) variable of a real-cell buffer:
/// `out[i] = α·(row_{2i+1} − row_{2i}) + row_{2i}`, odd tail vs `ZERO`.
fn fold_cells<EF: Field>(cells: &[EF], ncols: usize, num_real: usize, alpha: EF) -> Vec<EF> {
    if ncols == 0 || num_real == 0 {
        return Vec::new();
    }
    let out_rows = num_real.div_ceil(2);
    let mut out = vec![EF::ZERO; out_rows * ncols];
    for i in 0..out_rows {
        let r0 = 2 * i;
        let r1 = 2 * i + 1;
        for c in 0..ncols {
            let x = cells[r0 * ncols + c];
            let y = if r1 < num_real { cells[r1 * ncols + c] } else { EF::ZERO };
            out[i * ncols + c] = alpha * (y - x) + x;
        }
    }
    out
}

// ───────────────────────────── trait impls ───────────────────────────────

impl<F, EF, A> SumcheckPolyBase for ZeroCheckPoly<'_, F, EF, A>
where
    F: Field,
    EF: ExtensionField<F>,
{
    fn num_variables(&self) -> u32 {
        self.num_variables
    }
}

impl<F, EF, A> ComponentPoly<EF> for ZeroCheckPoly<'_, F, EF, A>
where
    F: Field,
    EF: ExtensionField<F>,
{
    /// Final per-column evaluations at the reduced point, preprocessed
    /// then main (SP1 ordering).  Ziren's zerocheck consumers discard
    /// this (openings come from the GKR phase); provided for the trait.
    fn get_component_poly_evals(&self) -> Vec<EF> {
        debug_assert_eq!(self.num_variables, 0, "get_component_poly_evals before full reduction");
        let mut out = Vec::with_capacity(self.num_prep_cols + self.num_main_cols);
        if self.num_real_entries >= 1 {
            if let Some(prep) = self.prep_cells.as_ref() {
                out.extend_from_slice(&prep[..self.num_prep_cols.min(prep.len())]);
            } else {
                out.extend(std::iter::repeat(EF::ZERO).take(self.num_prep_cols));
            }
            out.extend_from_slice(&self.main_cells[..self.num_main_cols.min(self.main_cells.len())]);
        } else {
            out.extend(std::iter::repeat(EF::ZERO).take(self.num_prep_cols + self.num_main_cols));
        }
        out
    }
}

impl<F, EF, A> SumcheckPoly<EF> for ZeroCheckPoly<'_, F, EF, A>
where
    F: Field,
    EF: ExtensionField<F>,
    A: MachineAir<F> + for<'b> Air<BasefoldConstraintFolder<'b, F, EF>>,
{
    fn fix_last_variable(self, alpha: EF) -> Self {
        self.fix_last(alpha)
    }

    fn sum_as_poly_in_last_variable(&self, claim: Option<EF>) -> UnivariatePolynomial<EF> {
        self.sum_as_poly(claim, false)
    }
}

impl<'a, F, EF, A> SumcheckPolyFirstRound<EF> for ZeroCheckPoly<'a, F, EF, A>
where
    F: Field,
    EF: ExtensionField<F>,
    A: MachineAir<F> + for<'b> Air<BasefoldConstraintFolder<'b, F, EF>>,
{
    type NextRoundPoly = ZeroCheckPoly<'a, F, EF, A>;

    fn fix_t_variables(self, alpha: EF, t: usize) -> Self::NextRoundPoly {
        assert_eq!(t, 1, "ZeroCheckPoly only supports t = 1");
        self.fix_last(alpha)
    }

    fn sum_as_poly_in_last_t_variables(
        &self,
        claim: Option<EF>,
        t: usize,
    ) -> UnivariatePolynomial<EF> {
        assert_eq!(t, 1, "ZeroCheckPoly only supports t = 1");
        self.sum_as_poly(claim, true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{InnerChallenge, InnerVal};
    use p3_field::PrimeCharacteristicRing;

    type EF = InnerChallenge;

    /// Standard multilinear evaluation of a dense table at `point`, with
    /// `point[k]` bound to bit `k` (LSB-first) of the table index — the
    /// convention the LSB-adjacent `fold_cells` realizes.
    fn padded_mle_eval(table: &[EF], point: &[EF]) -> EF {
        assert_eq!(table.len(), 1 << point.len());
        let mut acc = EF::ZERO;
        for (i, &v) in table.iter().enumerate() {
            let mut w = EF::ONE;
            for (k, &p) in point.iter().enumerate() {
                let bit = (i >> k) & 1;
                w *= if bit == 1 { p } else { EF::ONE - p };
            }
            acc += v * w;
        }
        acc
    }

    /// `fold_cells` applied round-by-round (fixing the LSB each round, as
    /// `reduce_sumcheck_serial` does) over a real-cell buffer must equal
    /// the multilinear extension of the ZERO-padded table at the reduced
    /// point — i.e. `component_poly_evals` = padded-MLE@z (the zerocheck
    /// "dense claim").  Uses a non-power-of-two `num_real` (3) so the
    /// odd-tail / virtual-padding path is exercised.
    #[test]
    fn fold_cells_equals_padded_mle_at_z() {
        let num_vars = 3usize;
        // Single column, 3 real rows; padded hypercube is 2^3 = 8.
        let c = [EF::from_u64(7), EF::from_u64(11), EF::from_u64(19)];
        let mut padded = vec![EF::ZERO; 1 << num_vars];
        padded[..c.len()].copy_from_slice(&c);

        // Round challenges a_0..a_{num_vars-1}; round k fixes bit k.
        let alphas = [EF::from_u64(5), EF::from_u64(13), EF::from_u64(23)];

        // Fold round-by-round: num_real halves via div_ceil; odd tail
        // folds against the ZERO padding constant.
        let mut cells = c.to_vec();
        let mut num_real = c.len();
        for &alpha in alphas.iter() {
            cells = fold_cells(&cells, 1, num_real, alpha);
            num_real = num_real.div_ceil(2);
        }
        assert_eq!(cells.len(), 1);
        let folded = cells[0];

        let brute = padded_mle_eval(&padded, &alphas);
        assert_eq!(folded, brute, "fold_cells must equal padded-MLE@z (dense claim)");
    }

    /// Multi-column variant: each column folds independently and must
    /// equal that column's padded-MLE@z.
    #[test]
    fn fold_cells_multicol_equals_padded_mle() {
        let num_vars = 2usize;
        let ncols = 2usize;
        // 3 real rows x 2 cols, row-major.
        let cells0 = vec![
            EF::from_u64(2), EF::from_u64(3), // row 0
            EF::from_u64(5), EF::from_u64(7), // row 1
            EF::from_u64(11), EF::from_u64(13), // row 2
        ];
        let alphas = [EF::from_u64(4), EF::from_u64(9)];

        let mut cells = cells0.clone();
        let mut num_real = 3usize;
        for &alpha in alphas.iter() {
            cells = fold_cells(&cells, ncols, num_real, alpha);
            num_real = num_real.div_ceil(2);
        }
        assert_eq!(cells.len(), ncols);

        for col in 0..ncols {
            let mut padded = vec![EF::ZERO; 1 << num_vars];
            for row in 0..3 {
                padded[row] = cells0[row * ncols + col];
            }
            assert_eq!(cells[col], padded_mle_eval(&padded, &alphas), "col {col} padded-MLE mismatch");
        }
    }

    /// `VirtualGeq::fix_last_variable` then `eval_at_usize` must agree
    /// with directly evaluating the geq/eq combination — guards the
    /// padded-row correction used in `sum_as_poly`.
    #[test]
    fn virtual_geq_fold_matches_threshold_indicator() {
        // threshold = 2 real rows, 3 variables, geq=1 eq=0 (as the prover sets).
        let vg = VirtualGeq::<EF>::new(2, EF::ONE, EF::ZERO, 3);
        // After fixing the last variable to alpha, eval_at_usize at the
        // halved threshold index must equal the analytic recurrence.
        let alpha = EF::from_u64(6);
        let folded = vg.fix_last_variable(alpha);
        // threshold 2 is even -> new_threshold=1, new_eq=(1-alpha)*0=0, new_geq=1.
        assert_eq!(folded.threshold, 1);
        assert_eq!(folded.eq_coefficient, EF::ZERO);
        assert_eq!(folded.geq_coefficient, EF::ONE);
        // index 1 == threshold -> eq+geq = 0 + 1 = 1; index 0 (< threshold) -> 0.
        assert_eq!(folded.eval_at_usize(1), EF::ONE);
        assert_eq!(folded.eval_at_usize(0), EF::ZERO);
    }

    /// Lagrange interpolation round-trips: the interpolant evaluated at
    /// each node returns the node value, including the eq-root sample.
    #[test]
    fn interpolate_round_trips_through_nodes() {
        let xs = [EF::from_u64(0), EF::from_u64(1), EF::from_u64(2), EF::from_u64(4), EF::from_u64(9)];
        let ys = [EF::from_u64(3), EF::from_u64(8), EF::from_u64(21), EF::from_u64(40), EF::from_u64(0)];
        let poly = interpolate_univariate_polynomial(&xs, &ys);
        for (x, y) in xs.iter().zip(ys.iter()) {
            // Horner eval.
            let mut acc = EF::ZERO;
            for c in poly.coefficients.iter().rev() {
                acc = acc * *x + *c;
            }
            assert_eq!(acc, *y, "interpolant must pass through node x={x:?}");
        }
        let _ = InnerVal::ONE; // keep InnerVal import used
    }
}
