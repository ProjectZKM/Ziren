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
    let round0_claims: Vec<Option<EF>> = claims.iter().map(|c| Some(*c)).collect();
    let mut uni_polys: Vec<UnivariatePolynomial<EF>> =
        P::batched_sum_as_poly_in_last_t_variables(&polys, &round0_claims, t);
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

        let round_claims_opt: Vec<Option<EF>> =
            round_claims.iter().map(|c| Some(*c)).collect();
        uni_polys = P::NextRoundPoly::batched_sum_as_poly_in_last_variable(
            &polys_cursor,
            &round_claims_opt,
        );
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
    /// #108 device-fold: erased device cell handle (ColMajorMatrixDevice<Felt>
    /// at round 0, DeviceBuffer<Ef4> after the first fold). When `Some`, the
    /// per-round y-tuple + the fold run on DEVICE (no host `main_cells`).
    device_cells: Option<std::sync::Arc<dyn core::any::Any + Send + Sync>>,
    device_prep: Option<std::sync::Arc<dyn core::any::Any + Send + Sync>>,
    /// true until the first device fold (round-0 cells are Felt; later Ef4).
    device_round0: bool,
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
            device_cells: None,
            device_prep: None,
            device_round0: true,
            _marker: PhantomData,
        }
    }

    /// #108: attach device-resident cells (the chip's trace on device, from the
    /// per-shard provider) so the zerocheck runs fully on device for this chip.
    /// `cells` is round-0 Felt (`ColMajorMatrixDevice<KoalaBear>`); the fold
    /// hook returns later-round Ef4 buffers.
    pub fn with_device_cells(
        mut self,
        cells: std::sync::Arc<dyn core::any::Any + Send + Sync>,
        prep: Option<std::sync::Arc<dyn core::any::Any + Send + Sync>>,
    ) -> Self {
        self.device_cells = Some(cells);
        self.device_prep = prep;
        self.device_round0 = true;
        self
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

        // The per-pair degree-4 eq-weighted accumulation (the device zerocheck
        // kernel's job) and the analytic finalize (host-only, transcript-
        // critical) are split so a device path can replace ONLY the
        // accumulator.  This is a pure extraction — byte-identical to the
        // original fused loop (validated by `orientation_sweep` inv1/inv2 and
        // `sum_as_poly_matches_spec_reference`).
        let (y_0, y_2, y_3, y_4) = self.accumulate_y_tuple(&partial, is_first_round);
        self.finalize_round_poly(claim, last, &partial, y_0, y_2, y_3, y_4)
    }

    /// B2.2 chip fusion: compute ALL chips' (y_0,y_2,y_3,y_4) in ONE fused
    /// device call (TypeId-guarded), then per-chip host finalize.  Returns the
    /// same per-chip round polynomials as the per-chip `sum_as_poly` loop, or
    /// `None` to signal whole-round host fallback (no hook / wrong field /
    /// shape mismatch).
    fn batched_device_round(
        polys: &[Self],
        claims: &[Option<EF>],
        is_first_round: bool,
    ) -> Option<Vec<UnivariatePolynomial<EF>>> {
        use core::any::TypeId;
        type Ef4 = p3_field::extension::BinomialExtensionField<p3_koala_bear::KoalaBear, 4>;
        type Kb = p3_koala_bear::KoalaBear;
        if TypeId::of::<EF>() != TypeId::of::<Ef4>() || TypeId::of::<F>() != TypeId::of::<Kb>() {
            return None;
        }
        let hook = crate::shard_level::sumcheck_poly::get_gpu_zerocheck_batched_ytuple_hook()?;
        if polys.is_empty() {
            return Some(Vec::new());
        }
        // #108-core residency: the batched (fused) hook reads HOST main_cells.
        // When any device-eligible chip has its host cells emptied (the core
        // device-fold residency path leaves main_cells empty + device_cells set),
        // the fused hook cannot serve it -> decline the whole round so the driver
        // falls to the per-chip sum_as_poly path, where gpu_y_tuple_device reads
        // the device cells. (This is the per-chip device-fold the operator opted
        // into via ZIREN_GPU_CORE_DEVICE_FOLD; it forfeits fusion for residency.)
        if polys.iter().any(|p| {
            p.num_real_entries > 0
                && p.num_prep_cols == 0
                && p.main_cells.is_empty()
                && p.device_cells.is_some()
        }) {
            return None;
        }

        // Per REAL chip (num_real > 0): partial-lagrange + last coord + owned
        // name must outlive the borrowed inputs.  `real_poly_idx` maps the
        // real-chip order back to the full poly order.
        let mut partials: Vec<Vec<EF>> = Vec::new();
        let mut names: Vec<String> = Vec::new();
        let mut lasts: Vec<EF> = Vec::new();
        let mut real_poly_idx: Vec<usize> = Vec::new();
        for (i, poly) in polys.iter().enumerate() {
            // Device set = REAL chips with NO preprocessed trace. np>0 chips
            // and pure-padding chips are handled on host below (the device
            // kernel has no prep-cell path, matching the per-chip np==0 gate).
            if poly.num_real_entries == 0 || poly.num_prep_cols != 0 {
                continue;
            }
            let dim = poly.zeta.len();
            lasts.push(poly.zeta[dim - 1]);
            partials.push(partial_lagrange(&poly.zeta[..dim - 1]));
            names.push(poly.air.name());
            real_poly_idx.push(i);
        }

        // No device-eligible (real, np==0) chip this round -> host fallback.
        if real_poly_idx.is_empty() {
            return None;
        }

        // SAFETY: TypeId guard above => EF == Ef4 and F == Kb, so these slice /
        // scalar reinterpretations are layout-safe (shared borrows only).
        let empty: Vec<Ef4> = Vec::new();
        let inputs: Vec<crate::shard_level::sumcheck_poly::ZerocheckChipYTupleInput<'_>> =
            real_poly_idx
                .iter()
                .enumerate()
                .map(|(r, &i)| {
                    let poly = &polys[i];
                    let main_ef4: &[Ef4] = unsafe {
                        core::slice::from_raw_parts(
                            poly.main_cells.as_ptr().cast::<Ef4>(),
                            poly.main_cells.len(),
                        )
                    };
                    let prep_ef4: &[Ef4] = match poly.prep_cells.as_ref() {
                        Some(p) => unsafe {
                            core::slice::from_raw_parts(p.as_ptr().cast::<Ef4>(), p.len())
                        },
                        None => &empty,
                    };
                    let gkr_ef4: &[Ef4] = unsafe {
                        core::slice::from_raw_parts(
                            poly.gkr_powers.as_ptr().cast::<Ef4>(),
                            poly.gkr_powers.len(),
                        )
                    };
                    let eq_ef4: &[Ef4] = unsafe {
                        core::slice::from_raw_parts(
                            partials[r].as_ptr().cast::<Ef4>(),
                            partials[r].len(),
                        )
                    };
                    let alpha_ef4: Ef4 = unsafe { core::mem::transmute_copy(&poly.alpha) };
                    crate::shard_level::sumcheck_poly::ZerocheckChipYTupleInput {
                        chip_name: names[r].as_str(),
                        main_cells: main_ef4,
                        num_main_cols: poly.num_main_cols,
                        prep_cells: prep_ef4,
                        num_prep_cols: poly.num_prep_cols,
                        gkr_powers: gkr_ef4,
                        alpha: alpha_ef4,
                        eq: eq_ef4,
                        num_real: poly.num_real_entries,
                    }
                })
                .collect();

        let pv_kb: &[Kb] = unsafe {
            core::slice::from_raw_parts(
                polys[0].public_values.as_ptr().cast::<Kb>(),
                polys[0].public_values.len(),
            )
        };
        let tuples = hook(&inputs, pv_kb, is_first_round)?;
        if tuples.len() != real_poly_idx.len() {
            return None; // shape mismatch -> host fallback
        }
        drop(inputs); // release the shared borrows before finalize

        let to_ef = |x: &Ef4| -> EF { unsafe { core::mem::transmute_copy(x) } };
        let mut out: Vec<UnivariatePolynomial<EF>> = Vec::with_capacity(polys.len());
        let mut r = 0usize;
        for (i, poly) in polys.iter().enumerate() {
            if poly.num_real_entries == 0 {
                out.push(UnivariatePolynomial { coefficients: vec![EF::ZERO; 5] });
                continue;
            }
            if poly.num_prep_cols != 0 {
                // np>0 chip: host path (device kernel has no prep-cell support).
                out.push(poly.sum_as_poly(claims[i], is_first_round));
                continue;
            }
            let yt = &tuples[r];
            let claim = claims[i].expect("batched_device_round: claim required");
            out.push(poly.finalize_round_poly(
                claim,
                lasts[r],
                &partials[r],
                to_ef(&yt[0]),
                to_ef(&yt[1]),
                to_ef(&yt[2]),
                to_ef(&yt[3]),
            ));
            r += 1;
        }

        // VERIFY: the batched path bypasses accumulate_y_tuple's own dual-run,
        // so cross-check each device-eligible chip's finalized round poly against
        // the per-chip sum_as_poly path (itself device-vs-host validated).
        if std::env::var("ZIREN_GPU_ZEROCHECK_YTUPLE_VERIFY")
            .map(|v| v == "1")
            .unwrap_or(false)
        {
            for (i, poly) in polys.iter().enumerate() {
                if poly.num_real_entries == 0 || poly.num_prep_cols != 0 {
                    continue;
                }
                let reference = poly.sum_as_poly(claims[i], is_first_round);
                assert_eq!(
                    out[i].coefficients, reference.coefficients,
                    "ZIREN_GPU_ZEROCHECK_YTUPLE_VERIFY: batched round poly != per-chip for chip {} (is_first_round={})",
                    poly.air.name(), is_first_round,
                );
            }
        }
        Some(out)
    }

    /// Device-or-host dispatch for the per-pair y-tuple accumulator.
    /// Under `ZIREN_GPU_ZEROCHECK_YTUPLE=1` with a registered
    /// `GpuZerocheckYTupleFn` and `EF == Ef4`, computes the tuple on the
    /// device; otherwise (and on any hook `None`) runs the byte-identical
    /// host loop.  With `ZIREN_GPU_ZEROCHECK_YTUPLE_VERIFY=1` it runs BOTH
    /// and asserts the device result equals the host loop (the P0 parity
    /// gate; mirrors the prover's device-resident-verify pattern).  The
    /// transcript is unaffected either way — `finalize_round_poly` and the
    /// challenger stay host.
    fn accumulate_y_tuple(&self, partial: &[EF], is_first_round: bool) -> (EF, EF, EF, EF) {
        // #108 device-fold: if cells live on device, compute the y-tuple on
        // device directly (no host upload). Falls through to the host-cell
        // paths below if the device hook is unregistered.
        if self.device_cells.is_some() {
            if let Some(dev) = self.gpu_y_tuple_device(partial, is_first_round) {
                return dev;
            }
            // #108-core residency: device cells were set (host trace emptied)
            // but the device y-tuple hook declined for this chip. main_cells is
            // empty, so the host-cell paths below would OOB. Fail loudly +
            // actionably rather than corrupt -- this chip type is not yet
            // supported under the per-chip device-fold residency path.
            if self.main_cells.is_empty() && self.num_real_entries > 0 {
                panic!(
                    "core device-fold: gpu_y_tuple_device declined for chip {} \
                     under device residency (host trace emptied, no device \
                     y-tuple support) -- disable ZIREN_GPU_CORE_DEVICE_FOLD or \
                     extend the device y-tuple hook for this chip type",
                    self.air.name(),
                );
            }
        }
        // Device-on by default; gpu_y_tuple returns None (-> host) unless EF==Ef4,
        // F==KoalaBear and a hook is registered (the TypeId guard is the safety net).
        if let Some(dev) = self.gpu_y_tuple(partial, is_first_round) {
            let verify = std::env::var("ZIREN_GPU_ZEROCHECK_YTUPLE_VERIFY")
                .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                .unwrap_or(false);
            if verify {
                let h = self.accumulate_y_tuple_host(partial, is_first_round);
                assert!(
                    dev.0 == h.0 && dev.1 == h.1 && dev.2 == h.2 && dev.3 == h.3,
                    "ZIREN_GPU_ZEROCHECK_YTUPLE_VERIFY: device y-tuple != host for chip {} \
                     (is_first_round={is_first_round})",
                    self.air.name(),
                );
            }
            return dev;
        }
        self.accumulate_y_tuple_host(partial, is_first_round)
    }

    /// TypeId-guarded bridge to the registered device y-tuple hook.
    /// Returns `None` (host fallback) unless `EF == Ef4`, `F == KoalaBear`,
    /// and a hook is registered.  All reinterpretations are sound under the
    /// `TypeId` equalities (identical layout).
    fn gpu_y_tuple(&self, partial: &[EF], is_first_round: bool) -> Option<(EF, EF, EF, EF)> {
        use core::any::TypeId;
        type Ef4 = p3_field::extension::BinomialExtensionField<p3_koala_bear::KoalaBear, 4>;
        type Kb = p3_koala_bear::KoalaBear;
        if TypeId::of::<EF>() != TypeId::of::<Ef4>() || TypeId::of::<F>() != TypeId::of::<Kb>() {
            return None;
        }
        let hook = crate::shard_level::sumcheck_poly::get_gpu_zerocheck_ytuple_hook()?;

        // SAFETY: the TypeId equalities above guarantee `EF == Ef4` and
        // `F == Kb`, so these slice / scalar reinterpretations are
        // layout-safe for the duration of the call (shared borrows only).
        let main_ef4: &[Ef4] = unsafe {
            core::slice::from_raw_parts(self.main_cells.as_ptr().cast::<Ef4>(), self.main_cells.len())
        };
        let empty: Vec<Ef4> = Vec::new();
        let prep_ef4: &[Ef4] = match self.prep_cells.as_ref() {
            Some(p) => unsafe { core::slice::from_raw_parts(p.as_ptr().cast::<Ef4>(), p.len()) },
            None => &empty,
        };
        let gkr_ef4: &[Ef4] = unsafe {
            core::slice::from_raw_parts(self.gkr_powers.as_ptr().cast::<Ef4>(), self.gkr_powers.len())
        };
        let eq_ef4: &[Ef4] =
            unsafe { core::slice::from_raw_parts(partial.as_ptr().cast::<Ef4>(), partial.len()) };
        let pv_kb: &[Kb] = unsafe {
            core::slice::from_raw_parts(
                self.public_values.as_ptr().cast::<Kb>(),
                self.public_values.len(),
            )
        };
        let alpha_ef4: Ef4 = unsafe { core::mem::transmute_copy(&self.alpha) };

        let name = self.air.name();
        let out = hook(
            &name,
            main_ef4,
            self.num_main_cols,
            prep_ef4,
            self.num_prep_cols,
            gkr_ef4,
            alpha_ef4,
            eq_ef4,
            pv_kb,
            self.num_real_entries,
            is_first_round,
        )?;

        // SAFETY: `Ef4 == EF` under the TypeId guard.
        let to_ef = |x: &Ef4| -> EF { unsafe { core::mem::transmute_copy(x) } };
        Some((to_ef(&out[0]), to_ef(&out[1]), to_ef(&out[2]), to_ef(&out[3])))
    }

    /// #108 device-fold: per-round y-tuple from DEVICE cells via the registered
    /// device hook. `None` unless EF==Ef4, F==Kb, device_cells set, hook present.
    fn gpu_y_tuple_device(&self, partial: &[EF], is_first_round: bool) -> Option<(EF, EF, EF, EF)> {
        use core::any::TypeId;
        type Ef4 = p3_field::extension::BinomialExtensionField<p3_koala_bear::KoalaBear, 4>;
        type Kb = p3_koala_bear::KoalaBear;
        if TypeId::of::<EF>() != TypeId::of::<Ef4>() || TypeId::of::<F>() != TypeId::of::<Kb>() {
            return None;
        }
        let dc = self.device_cells.as_ref()?;
        let hook = crate::shard_level::sumcheck_poly::get_gpu_zerocheck_ytuple_device_hook()?;
        // SAFETY: TypeId equalities -> layout-safe reinterpretation (shared borrows).
        let gkr_ef4: &[Ef4] = unsafe {
            core::slice::from_raw_parts(self.gkr_powers.as_ptr().cast::<Ef4>(), self.gkr_powers.len())
        };
        let eq_ef4: &[Ef4] =
            unsafe { core::slice::from_raw_parts(partial.as_ptr().cast::<Ef4>(), partial.len()) };
        let pv_kb: &[Kb] = unsafe {
            core::slice::from_raw_parts(self.public_values.as_ptr().cast::<Kb>(), self.public_values.len())
        };
        let alpha_ef4: Ef4 = unsafe { core::mem::transmute_copy(&self.alpha) };
        let prep_dyn: Option<&(dyn core::any::Any + Send + Sync)> =
            self.device_prep.as_deref();
        let name = self.air.name();
        let out = hook(
            &name,
            dc.as_ref(),
            self.num_main_cols,
            prep_dyn,
            self.num_prep_cols,
            gkr_ef4,
            alpha_ef4,
            eq_ef4,
            pv_kb,
            self.num_real_entries,
            is_first_round,
        )?;
        let to_ef = |x: &Ef4| -> EF { unsafe { core::mem::transmute_copy(x) } };
        Some((to_ef(&out[0]), to_ef(&out[1]), to_ef(&out[2]), to_ef(&out[3])))
    }

    /// #108 device-fold: fold the device cells on the last variable, on device.
    fn gpu_fold_device(&self, alpha: EF) -> Option<std::sync::Arc<dyn core::any::Any + Send + Sync>> {
        use core::any::TypeId;
        type Ef4 = p3_field::extension::BinomialExtensionField<p3_koala_bear::KoalaBear, 4>;
        if TypeId::of::<EF>() != TypeId::of::<Ef4>() {
            return None;
        }
        let dc = self.device_cells.as_ref()?;
        let hook = crate::shard_level::sumcheck_poly::get_gpu_zerocheck_fold_device_hook()?;
        let alpha_ef4: Ef4 = unsafe { core::mem::transmute_copy(&alpha) };
        hook(dc.as_ref(), self.num_main_cols, self.num_real_entries, alpha_ef4, self.device_round0)
    }

    /// The per-pair degree-4 eq-weighted accumulator: returns
    /// `(y_0, y_2, y_3, y_4)` BEFORE the elf/eq_adjustment scaling and
    /// VirtualGeq padded-row correction.  This is exactly the per-chip
    /// per-round quantity the device zerocheck kernel computes (consuming the
    /// bit-reversed trace at interpolation samples `X ∈ {0,2,3,4}`); the host
    /// retains `finalize_round_poly`.  `partial = partial_lagrange(zeta[..dim-1])`.
    /// Caller guarantees `num_real_entries > 0`.
    fn accumulate_y_tuple_host(&self, partial: &[EF], is_first_round: bool) -> (EF, EF, EF, EF) {
        let num_real = self.num_real_entries;
        let nm = self.num_main_cols;
        let np = self.num_prep_cols;
        let num_pairs = num_real.div_ceil(2);

        let (mut y_0, mut y_2, mut y_3, mut y_4) = (EF::ZERO, EF::ZERO, EF::ZERO, EF::ZERO);

        // Scratch buffers reused across pairs.
        let mut m0 = vec![EF::ZERO; nm];
        let mut m2 = vec![EF::ZERO; nm];
        let mut m3 = vec![EF::ZERO; nm];
        let mut m4 = vec![EF::ZERO; nm];
        let mut p0 = vec![EF::ZERO; np];
        let mut p2 = vec![EF::ZERO; np];
        let mut p3 = vec![EF::ZERO; np];
        let mut p4 = vec![EF::ZERO; np];
        // Sample point 3 lies on the row-pair line midway between 2 and 4
        // (interp_pair is affine in the sample point): m3 = (m2 + m4)/2.
        let half = EF::from_u64(2).inverse();

        for pair in 0..num_pairs {
            let eq = partial[pair];
            let row0 = 2 * pair;
            let row1 = 2 * pair + 1;

            interp_pair(&self.main_cells, nm, num_real, row0, row1, &mut m0, &mut m2, &mut m4);
            if np > 0 {
                let prep = self.prep_cells.as_ref().expect("prep_cells present when np > 0");
                interp_pair(prep, np, num_real, row0, row1, &mut p0, &mut p2, &mut p4);
            }
            for c in 0..nm {
                m3[c] = (m2[c] + m4[c]) * half;
            }
            for c in 0..np {
                p3[c] = (p2[c] + p4[c]) * half;
            }

            let g0 = self.gkr_batch(&m0, &p0);
            let g2 = self.gkr_batch(&m2, &p2);
            let g4 = g2 + g2 - g0; // gkr is linear in the row values
            let g3 = (g2 + g4) * half; // linear interpolant at 3

            let c0 = if is_first_round { EF::ZERO } else { self.eval_air_at_row(&p0, &m0) };
            let c2 = self.eval_air_at_row(&p2, &m2);
            let c3 = self.eval_air_at_row(&p3, &m3);
            let c4 = self.eval_air_at_row(&p4, &m4);

            y_0 += (c0 + g0) * eq;
            y_2 += (c2 + g2) * eq;
            y_3 += (c3 + g3) * eq;
            y_4 += (c4 + g4) * eq;
        }
        (y_0, y_2, y_3, y_4)
    }

    /// Analytic finalize (host-only, transcript-critical): scale the per-pair
    /// accumulators by `elf_X · eq_adjustment`, subtract the VirtualGeq
    /// padded-row correction, fix `y_1 = claim − y_0`, and Lagrange-interpolate
    /// the degree-4 round poly over `{0,1,2,3,4}`.  `last` / `partial` are the
    /// same values `accumulate_y_tuple_host` consumed.  Pure extraction of the
    /// original fused tail.
    ///
    /// Interpolation samples: the degree-4 round poly over the always-distinct
    /// points {0,1,2,3,4}.  Point 1 is fixed by the sumcheck relation
    /// p(0)+p(1)=claim.  The eq term's known root is *implied* by these samples,
    /// so it need not be sampled explicitly — avoiding the original
    /// {0,1,2,4,eq-root} scheme's `(1 − 2·last)` inverse (panics at last = 1/2)
    /// and its `eq-root ∈ {0,1,2,4}` duplicate-point collision.  Same
    /// coefficients → identical proof/transcript.  `elf_X = (2X − 1)·last −
    /// (X − 1)` is the eq term's last factor at X.
    fn finalize_round_poly(
        &self,
        claim: EF,
        last: EF,
        partial: &[EF],
        y_0: EF,
        y_2: EF,
        y_3: EF,
        y_4: EF,
    ) -> UnivariatePolynomial<EF> {
        let (mut y_0, mut y_2, mut y_3, mut y_4) = (y_0, y_2, y_3, y_4);
        let num_pairs = self.num_real_entries.div_ceil(2);

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
        let virtual_3 =
            self.virtual_geq.fix_last_variable(EF::from_u64(3)).eval_at_usize(threshold_half);
        let virtual_4 =
            self.virtual_geq.fix_last_variable(EF::from_u64(4)).eval_at_usize(threshold_half);

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

        xs.push(EF::from_u64(3));
        let elf_3 = last * EF::from_u64(5) - EF::from_u64(2);
        y_3 = y_3 * (elf_3 * self.eq_adjustment)
            - self.padded_row_adjustment * virtual_3 * msb_lagrange_eval * elf_3;
        ys.push(y_3);

        xs.push(EF::from_u64(4));
        let elf_4 = last * EF::from_u64(7) - EF::from_u64(3);
        y_4 = y_4 * (elf_4 * self.eq_adjustment)
            - self.padded_row_adjustment * virtual_4 * msb_lagrange_eval * elf_4;
        ys.push(y_4);

        interpolate_univariate_polynomial(&xs, &ys)
    }

    /// Fix the last (least-significant) variable to `alpha`.
    fn fix_last(self, alpha: EF) -> Self {
        // #108 device-fold: fold the device cells on device; host cells unused.
        let new_device_cells: Option<std::sync::Arc<dyn core::any::Any + Send + Sync>> =
            if self.device_cells.is_some() {
                Some(self.gpu_fold_device(alpha).expect(
                    "#108: device_cells set but fold hook unregistered/typeid-mismatch",
                ))
            } else {
                None
            };
        let new_main = if self.device_cells.is_some() {
            Vec::new()
        } else {
            fold_cells(&self.main_cells, self.num_main_cols, self.num_real_entries, alpha)
        };
        let new_prep = if self.device_cells.is_some() {
            None
        } else {
            self.prep_cells
                .as_ref()
                .map(|c| fold_cells(c, self.num_prep_cols, self.num_real_entries, alpha))
        };
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
                device_cells: new_device_cells,
                device_round0: false,
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
            device_cells: new_device_cells,
            device_round0: false,
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
    // A width-0 main trace (absent / placeholder chip in this shard) => main_height==0
    // => num_real==0 => sum_as_poly emits the degree-4 dummy and never uses this
    // padded-row adjustment. Skip the eval, which would borrow the chip cols from an
    // empty row and panic (index out of bounds len 0). Transcript-neutral (value unused).
    if main_width == 0 {
        return EF::ZERO;
    }
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

/// Bit-reverse the rows of a row-major cell buffer over `log2(height)` bits
/// (row `r` -> row `bitrev(r)`).  `height` must be a power of two.
///
/// ORIENTATION FIX: the GKR per-chip opening (`evaluate_trace_columns_at_point`
/// -> `eq_mle_table`) is LSB-first (`point[0]` <-> row-LSB), while this module's
/// zerocheck poly is big-endian (`partial_lagrange` / `fold_cells` peel
/// `zeta[dim-1]` <-> row-LSB, matching SP1).  Feeding the bit-reversed trace to
/// the poly makes its big-endian boolean-cube sum equal the LSB-first GKR-batch
/// claim, restoring `claim == cube-sum` without touching `zeta`, the GKR
/// openings, or the claim.
pub(crate) fn bitrev_rows<EF: Field>(cells: &[EF], ncols: usize, height: usize) -> Vec<EF> {
    if height <= 1 || ncols == 0 {
        return cells.to_vec();
    }
    let log_h = (height as u32).trailing_zeros();
    debug_assert_eq!(1usize << log_h, height, "bitrev_rows: height must be 2^k");
    let mut out = vec![EF::ZERO; height * ncols];
    for r in 0..height {
        let rr = ((r as u32).reverse_bits() >> (32 - log_h)) as usize;
        out[rr * ncols..rr * ncols + ncols]
            .copy_from_slice(&cells[r * ncols..r * ncols + ncols]);
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
            // #108 device-fold: extract the folded 1-row openings from device cells.
            if let Some(dc) = self.device_cells.as_ref() {
                use core::any::TypeId;
                type Ef4 = p3_field::extension::BinomialExtensionField<p3_koala_bear::KoalaBear, 4>;
                if TypeId::of::<EF>() == TypeId::of::<Ef4>() {
                    if let Some(hook) =
                        crate::shard_level::sumcheck_poly::get_gpu_zerocheck_extract_final_hook()
                    {
                        // np>0: the device buffer is the COMBINED [main ++ prep]
                        // col-major block (prep columns FOLLOW main, e051ffd), so
                        // extract num_main_cols + num_prep_cols residuals and emit
                        // them prep-then-main (the host/SP1 trace@z order below).
                        // np==0 chips extract exactly num_main_cols (unchanged).
                        let want = self.num_main_cols + self.num_prep_cols;
                        if let Some(res_ef4) = hook(dc.as_ref(), want) {
                            // SAFETY: TypeId equality guarantees EF == Ef4.
                            let res: Vec<EF> = unsafe {
                                let len = res_ef4.len();
                                let cap = res_ef4.capacity();
                                let ptr =
                                    core::mem::ManuallyDrop::new(res_ef4).as_mut_ptr() as *mut EF;
                                Vec::from_raw_parts(ptr, len, cap)
                            };
                            if res.len() == want {
                                // prep residuals (buffer cols nm..nm+np) first.
                                out.extend_from_slice(&res[self.num_main_cols..]);
                                out.extend_from_slice(&res[..self.num_main_cols]);
                            } else {
                                // Device buffer carries main only (legacy np==0
                                // shape): zero prep slots, then main residuals.
                                out.extend(
                                    std::iter::repeat(EF::ZERO).take(self.num_prep_cols),
                                );
                                out.extend_from_slice(&res[..self.num_main_cols.min(res.len())]);
                            }
                            return out;
                        }
                    }
                }
            }
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

    fn batched_sum_as_poly_in_last_variable(
        polys: &[Self],
        claims: &[Option<EF>],
    ) -> Vec<UnivariatePolynomial<EF>> {
        if let Some(r) = Self::batched_device_round(polys, claims, false) {
            return r;
        }
        polys
            .iter()
            .zip(claims.iter())
            .map(|(p, c)| p.sum_as_poly_in_last_variable(*c))
            .collect()
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

    fn batched_sum_as_poly_in_last_t_variables(
        polys: &[Self],
        claims: &[Option<EF>],
        t: usize,
    ) -> Vec<UnivariatePolynomial<EF>> {
        assert_eq!(t, 1, "ZeroCheckPoly only supports t = 1");
        if let Some(r) = Self::batched_device_round(polys, claims, true) {
            return r;
        }
        polys
            .iter()
            .zip(claims.iter())
            .map(|(p, c)| p.sum_as_poly_in_last_t_variables(*c, t))
            .collect()
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

    // ───── reduce_sumcheck_serial end-to-end identity (host sum_as_poly) ─────
    use crate::air::{MachineAir, MachineProgram};
    use crate::chip::Chip;
    use crate::record::MachineRecord;
    use crate::septic_digest::SepticDigest;
    use crate::air::{AirLookup, BaseAirBuilder, LookupScope};
    use crate::lookup::LookupKind;
    use p3_air::{Air, BaseAir, WindowAccess};
    use p3_matrix::dense::RowMajorMatrix;

    #[derive(Clone, Default)]
    struct MockRecord;
    impl MachineRecord for MockRecord {
        type Config = ();
        fn stats(&self) -> hashbrown::HashMap<String, usize> {
            hashbrown::HashMap::new()
        }
        fn append(&mut self, _other: &mut Self) {}
        fn public_values<FF: p3_field::PrimeCharacteristicRing>(&self) -> Vec<FF> {
            Vec::new()
        }
    }
    #[derive(Clone, Default)]
    struct MockProgram;
    impl MachineProgram<InnerVal> for MockProgram {
        fn pc_start(&self) -> InnerVal {
            InnerVal::ZERO
        }
        fn initial_global_cumulative_sum(&self) -> SepticDigest<InnerVal> {
            SepticDigest::<InnerVal>::zero()
        }
    }
    #[derive(Clone)]
    struct MockAir {
        ncols: usize,
    }
    impl<F> BaseAir<F> for MockAir {
        fn width(&self) -> usize {
            self.ncols
        }
    }
    impl<AB: BaseAirBuilder> Air<AB> for MockAir {
        fn eval(&self, builder: &mut AB) {
            let main = builder.main();
            let row = main.current_slice();
            // Degree-3 algebraic constraint on column 0 (matches AddSub's degree).
            let x: AB::Expr = row[0].into();
            // Degree-3 constraint x·(x-1)·(x-2), satisfied by rows in {0,1,2}.
            let one = AB::Expr::ONE;
            let two = AB::Expr::ONE + AB::Expr::ONE;
            builder.assert_zero(x.clone() * (x.clone() - one) * (x.clone() - two));
            // One (no-op for the BaseFold folder) interaction so the chip has a
            // permutation trace (permutation_trace_width > 0) — makes Chip::eval's
            // eval_permutation_constraints early-return instead of panicking on
            // empty permutation_randomness.
            builder.send(
                AirLookup::new(vec![x.clone()], AB::Expr::ONE, LookupKind::Byte),
                LookupScope::Local,
            );
        }
    }
    impl MachineAir<InnerVal> for MockAir {
        type Record = MockRecord;
        type Program = MockProgram;
        type Error = std::convert::Infallible;
        fn name(&self) -> String {
            "Mock".to_string()
        }
        fn generate_trace(
            &self,
            _input: &MockRecord,
            _output: &mut MockRecord,
        ) -> Result<RowMajorMatrix<InnerVal>, Self::Error> {
            unreachable!("generate_trace not exercised by this test")
        }
        fn included(&self, _shard: &MockRecord) -> bool {
            true
        }
    }

    fn eq_pt(a: &[EF], b: &[EF]) -> EF {
        a.iter()
            .zip(b.iter())
            .map(|(&ai, &bi)| (EF::ONE - ai) * (EF::ONE - bi) + ai * bi)
            .product()
    }

    fn poly_horner(coeffs: &[EF], x: EF) -> EF {
        let mut acc = EF::ZERO;
        for c in coeffs.iter().rev() {
            acc = acc * x + *c;
        }
        acc
    }

    /// The zerocheck sumcheck must reduce its claim to
    /// `eq(zeta,z) * (C(trace@z) + batch(trace@z))` at the reduced point z —
    /// the exact identity the recursion verifier asserts.  Fully-packed
    /// (no padding) so the VirtualGeq/padded term is inert: this isolates
    /// the core `sum_as_poly` reduction.
    #[test]
    fn reduce_sumcheck_reduces_to_eq_times_constraint_plus_batch() {
        use p3_challenger::DuplexChallenger;
        use p3_koala_bear::Poseidon2KoalaBear;
        let perm: Poseidon2KoalaBear<16> = zkm_primitives::poseidon2_init();
        let mut challenger = DuplexChallenger::<InnerVal, _, 16, 8>::new(perm);

        let num_vars = 4u32;
        let ncols = 1usize;
        let num_real = 2usize; // HEAVY padding: 2 real rows in a 2^4 = 16 hypercube
                               // (high variables fully padded; fold sits at num_real=1)

        // Honest trace: every real row value in {0,1} → C=0 on real rows.
        let main_cells: Vec<EF> =
            (0..num_real * ncols).map(|i| EF::from_u64((i % 2) as u64)).collect();
        // zeta MATCHES the real system: the GKR point is left-padded with ZERO
        // for the high (MSB) row variables down to log2(num_real); only the
        // trailing log2(num_real) coords are "real" sampled challenges.
        let real_vars = (num_real as u32).trailing_zeros() as usize; // num_real is 2^k
        let zeta: Vec<EF> = (0..num_vars as usize)
            .map(|k| {
                if k < (num_vars as usize - real_vars) {
                    EF::ZERO // leading-zero padding for fully-padded high variables
                } else {
                    EF::from_u64((k * 5 + 2) as u64 + 100)
                }
            })
            .collect();
        let alpha = EF::from_u64(17);
        let beta = EF::from_u64(29);
        let lambda = EF::from_u64(31);
        let pv: Vec<InnerVal> = Vec::new();

        let chip = Chip::new(MockAir { ncols });
        let main_width = ncols;
        let prep_width = 0usize;
        let combined = main_width + prep_width;
        let gkr_powers: Vec<EF> = {
            let mut v = Vec::new();
            let mut acc = EF::ONE;
            for _ in 0..combined {
                acc *= beta;
                v.push(acc);
            }
            v
        };

        let batch = |row: &[EF]| -> EF {
            row.iter().zip(gkr_powers.iter()).map(|(&v, &p)| v * p).sum()
        };
        let cval = |main_row: &[EF]| -> EF {
            eval_air_constraints_at_row::<InnerVal, EF, MockAir>(&chip, alpha, &pv, &[], main_row)
        };
        let zero_row = vec![EF::ZERO; ncols];
        let h = |x: usize| -> EF {
            // Padded rows (x >= num_real) are the ZERO row.
            let row: &[EF] = if x < num_real {
                &main_cells[x * ncols..x * ncols + ncols]
            } else {
                &zero_row
            };
            cval(row) + batch(row)
        };

        // claim = Σ_x eq(zeta, x) · h(x).  boolean_point(x)[k] = bit_{n-1-k}(x)
        // matches the z = point_and_eval.0 = [a_{n-1},…,a_0] orientation.
        let n = num_vars as usize;
        let mut claim = EF::ZERO;
        for x in 0..(1usize << n) {
            let pt: Vec<EF> = (0..n)
                .map(|k| if (x >> (n - 1 - k)) & 1 == 1 { EF::ONE } else { EF::ZERO })
                .collect();
            claim += eq_pt(&zeta, &pt) * h(x);
        }

        let pra = compute_padded_row_adjustment::<InnerVal, EF, MockAir>(
            &chip, alpha, &pv, main_width, prep_width,
        );
        let main_height = num_real;
        let vg = VirtualGeq::new(main_height as u32, EF::ONE, EF::ZERO, num_vars);
        let init_geq = if main_height > 0 { EF::ZERO } else { EF::ONE };
        let poly = ZeroCheckPoly::<InnerVal, EF, MockAir>::new(
            &chip,
            &pv,
            alpha,
            gkr_powers.clone(),
            zeta.clone(),
            main_cells.clone(),
            main_width,
            None,
            prep_width,
            num_real,
            num_vars,
            EF::ONE,
            init_geq,
            pra,
            vg,
        );

        let (proof, cpe) = reduce_sumcheck_serial::<InnerVal, EF, _, _>(
            vec![poly],
            &mut challenger,
            vec![claim],
            1,
            lambda,
        );

        // SANITY: a correct claim must satisfy p_0(0)+p_0(1)=claim.  If this
        // fails, the bug is in this test's claim convention, not sum_as_poly.
        let p0 = &proof.univariate_polys[0].coefficients;
        assert_eq!(
            claim,
            poly_horner(p0, EF::ZERO) + poly_horner(p0, EF::ONE),
            "test claim convention wrong (round-0 sumcheck relation broken)"
        );

        // THE IDENTITY: evals[0] (== point_and_eval.1) must equal
        // eq(zeta,z)·(C(trace@z)+batch(trace@z)).
        let z = &proof.point_and_eval.0;
        let trace_at_z = &cpe[0]; // prep-then-main; prep_width=0 → all main
        let main_at_z = &trace_at_z[prep_width..];
        let expected = eq_pt(&zeta, z) * (cval(main_at_z) + batch(main_at_z));
        assert_eq!(
            proof.point_and_eval.1, expected,
            "sum_as_poly reduction != eq*(C(trace@z)+batch) — host zerocheck bug reproduced"
        );
    }

    // The orientation fix under test is the module-scope `super::bitrev_rows`
    // (the same helper `zerocheck_prover` feeds the poly), exercised below.
    use super::bitrev_rows;

    /// REPRODUCTION of the zeta-orientation bug + REGRESSION for its fix.
    ///
    /// Feeds the poly the *real* prover's GKR-forward claim — built from
    /// `main_trace_evaluations = evaluate_trace_columns_at_point` over the
    /// trailing `log2(height)` coords of `zeta` (forward: row-bit k ←
    /// zeta[start+k]; `zerocheck_prover.rs:474-479`, `row_gkr/top_level.rs:
    /// 330-347`) — NOT the poly-convention brute force used by the sibling
    /// test.  The poly's own fold is LSB-first → it binds row-bit k ←
    /// zeta[dim-1-k] (REVERSED).  So on a row-distinct trace the poly's
    /// true boolean-cube sum (reversed batch) != the forward claim, and the
    /// sumcheck reduces to a wrong value (`point_and_eval.1` !=
    /// `eq(zeta,z)·(C+batch(trace@z))`) — the recursion verifier rejects.
    ///
    /// THE FIX (`fix = true`): bit-reverse the chip's real trace rows over
    /// `log2(height)` bits before building the poly.  This re-aligns the
    /// LSB fold to the GKR-forward orientation WITHOUT touching `zeta`, the
    /// GKR openings, the jagged `r_row`, or any transcript-observe — so the
    /// poly's cube-sum becomes the forward claim (invariant 1 restored) and
    /// `point_and_eval.1 == eq_eval(zeta_ORIGINAL, z)·(C+batch)` still holds
    /// (invariant 2 preserved, because zeta is untouched).
    fn run_orientation_case(fix: bool) -> bool {
        use crate::shard_level::logup_gkr_prover::evaluate_trace_columns_at_point;
        use p3_challenger::DuplexChallenger;
        use p3_koala_bear::Poseidon2KoalaBear;
        let perm: Poseidon2KoalaBear<16> = zkm_primitives::poseidon2_init();
        let mut challenger = DuplexChallenger::<InnerVal, _, 16, 8>::new(perm);

        let num_vars = 4u32;
        let ncols = 2usize;
        // 4 real rows in a 2^4 hypercube → 2 trailing real coords, 2 leading
        // ZERO-pad coords (exercises the leading-zero padding offset).
        let height = 4usize;
        let real_vars = (height as u32).trailing_zeros() as usize; // 2

        // Row-DISTINCT honest trace (so the trace MLE is orientation-
        // sensitive).  Column 0 in {0,1,2} → MockAir x(x-1)(x-2) = 0 on real
        // rows; column 1 arbitrary.
        let col0 = [0u64, 1, 2, 1];
        let col1 = [9u64, 4, 7, 13];
        let trace_base: Vec<InnerVal> = (0..height)
            .flat_map(|r| [InnerVal::from_u64(col0[r]), InnerVal::from_u64(col1[r])])
            .collect();
        let main_cells: Vec<EF> = trace_base.iter().map(|&v| EF::from(v)).collect();

        // zeta: leading-ZERO padded, trailing `real_vars` sampled.
        let zeta: Vec<EF> = (0..num_vars as usize)
            .map(|k| {
                if k < (num_vars as usize - real_vars) {
                    EF::ZERO
                } else {
                    EF::from_u64((k * 7 + 3) as u64 + 200)
                }
            })
            .collect();

        let alpha = EF::from_u64(17);
        let beta = EF::from_u64(29);
        let lambda = EF::from_u64(31);
        let pv: Vec<InnerVal> = Vec::new();

        let chip = Chip::new(MockAir { ncols });
        let main_width = ncols;
        let prep_width = 0usize;
        let combined = main_width + prep_width;
        let gkr_powers: Vec<EF> = {
            let mut v = Vec::new();
            let mut acc = EF::ONE;
            for _ in 0..combined {
                acc *= beta;
                v.push(acc);
            }
            v
        };
        let batch = |row: &[EF]| -> EF { row.iter().zip(gkr_powers.iter()).map(|(&v, &p)| v * p).sum() };
        let cval = |main_row: &[EF]| -> EF {
            eval_air_constraints_at_row::<InnerVal, EF, MockAir>(&chip, alpha, &pv, &[], main_row)
        };

        // *** THE REAL PROVER'S CLAIM ***  GKR-forward main_trace_evaluations
        // at the trailing `real_vars` coords of zeta, then `Σ evals · β^(1..)`.
        let start = num_vars as usize - real_vars;
        let main_evals =
            evaluate_trace_columns_at_point::<InnerVal, EF>(&trace_base, main_width, &zeta[start..]);
        let claim: EF =
            main_evals.iter().zip(gkr_powers.iter()).fold(EF::ZERO, |acc, (o, p)| acc + *o * *p);

        // The poly input: bit-reverse the trace rows iff `fix` (keeps zeta,
        // GKR openings, jagged r_row, transcript-observe byte-identical).
        let poly_cells =
            if fix { bitrev_rows(&main_cells, ncols, height) } else { main_cells.clone() };

        let pra = compute_padded_row_adjustment::<InnerVal, EF, MockAir>(
            &chip, alpha, &pv, main_width, prep_width,
        );
        let vg = VirtualGeq::new(height as u32, EF::ONE, EF::ZERO, num_vars);
        let poly = ZeroCheckPoly::<InnerVal, EF, MockAir>::new(
            &chip, &pv, alpha, gkr_powers.clone(), zeta.clone(), poly_cells, main_width, None,
            prep_width, height, num_vars, EF::ONE, EF::ZERO, pra, vg,
        );

        let (proof, cpe) =
            reduce_sumcheck_serial::<InnerVal, EF, _, _>(vec![poly], &mut challenger, vec![claim], 1, lambda);

        // INVARIANT (2) — the exact identity the recursion verifier asserts
        // (zerocheck.rs:628/648): reduced value == eq_eval(zeta_ORIGINAL, z)
        // · (C(trace@z) + batch(trace@z)).  Returns whether it holds.  zeta is
        // UNTOUCHED by the fix, so the verifier needs no change.
        let z = &proof.point_and_eval.0;
        let main_at_z = &cpe[0][prep_width..];
        let expected = eq_pt(&zeta, z) * (cval(main_at_z) + batch(main_at_z));
        proof.point_and_eval.1 == expected
    }

    /// Same harness over a NON-power-of-two height (3 real rows in 2^4) to
    /// prove the bit-reverse-rows fix is COMPATIBLE with the VirtualGeq
    /// contiguous-real-rows optimization.  The trace is padded to the next
    /// power of two (height_pow2) with ZERO rows BEFORE bit-reversal — so
    /// real rows land at their bit-reversed positions in the pow2 hypercube,
    /// exactly mirroring GKR's pow2-padded forward eval; the remaining slots
    /// stay ZERO and are summed analytically by VirtualGeq.
    fn run_orientation_nonpow2(fix: bool) -> bool {
        use crate::shard_level::logup_gkr_prover::evaluate_trace_columns_at_point;
        use p3_challenger::DuplexChallenger;
        use p3_koala_bear::Poseidon2KoalaBear;
        let perm: Poseidon2KoalaBear<16> = zkm_primitives::poseidon2_init();
        let mut challenger = DuplexChallenger::<InnerVal, _, 16, 8>::new(perm);

        let num_vars = 4u32;
        let ncols = 2usize;
        let real_rows = 3usize; // NON power of two
        let height_pow2 = real_rows.next_power_of_two(); // 4
        let log_h = (height_pow2 as u32).trailing_zeros() as usize; // 2

        let col0 = [0u64, 1, 2];
        let col1 = [9u64, 4, 7];
        // pow2-padded base trace (GKR evaluates this).
        let trace_base: Vec<InnerVal> = (0..height_pow2)
            .flat_map(|r| {
                if r < real_rows {
                    [InnerVal::from_u64(col0[r]), InnerVal::from_u64(col1[r])]
                } else {
                    [InnerVal::ZERO, InnerVal::ZERO]
                }
            })
            .collect();

        let zeta: Vec<EF> = (0..num_vars as usize)
            .map(|k| {
                if k < (num_vars as usize - log_h) {
                    EF::ZERO
                } else {
                    EF::from_u64((k * 11 + 5) as u64 + 300)
                }
            })
            .collect();

        let alpha = EF::from_u64(19);
        let beta = EF::from_u64(23);
        let lambda = EF::from_u64(37);
        let pv: Vec<InnerVal> = Vec::new();

        let chip = Chip::new(MockAir { ncols });
        let main_width = ncols;
        let prep_width = 0usize;
        let gkr_powers: Vec<EF> = {
            let mut v = Vec::new();
            let mut acc = EF::ONE;
            for _ in 0..main_width {
                acc *= beta;
                v.push(acc);
            }
            v
        };
        let batch = |row: &[EF]| -> EF { row.iter().zip(gkr_powers.iter()).map(|(&v, &p)| v * p).sum() };
        let cval = |main_row: &[EF]| -> EF {
            eval_air_constraints_at_row::<InnerVal, EF, MockAir>(&chip, alpha, &pv, &[], main_row)
        };

        // GKR-forward claim over the pow2-padded trace at trailing log_h coords.
        let start = num_vars as usize - log_h;
        let main_evals =
            evaluate_trace_columns_at_point::<InnerVal, EF>(&trace_base, main_width, &zeta[start..]);
        let claim: EF =
            main_evals.iter().zip(gkr_powers.iter()).fold(EF::ZERO, |acc, (o, p)| acc + *o * *p);

        // The poly cells.  Unfixed: contiguous real rows (VirtualGeq path),
        // num_real = real_rows (NON-pow2).  Fixed: bit-reverse the FULL pow2
        // trace (real rows scatter to bit-reversed slots, gaps stay ZERO),
        // num_real = height_pow2 so the now-non-contiguous reals are all
        // summed (VirtualGeq threshold = full height → inert padded term).
        let main_cells: Vec<EF> = trace_base.iter().map(|&v| EF::from(v)).collect();
        let (poly_cells, num_real, vg_threshold) = if fix {
            (bitrev_rows(&main_cells, ncols, height_pow2), height_pow2, height_pow2 as u32)
        } else {
            // contiguous real-rows slice (length real_rows * ncols).
            (main_cells[..real_rows * ncols].to_vec(), real_rows, real_rows as u32)
        };

        let pra = compute_padded_row_adjustment::<InnerVal, EF, MockAir>(
            &chip, alpha, &pv, main_width, prep_width,
        );
        let vg = VirtualGeq::new(vg_threshold, EF::ONE, EF::ZERO, num_vars);
        let poly = ZeroCheckPoly::<InnerVal, EF, MockAir>::new(
            &chip, &pv, alpha, gkr_powers.clone(), zeta.clone(), poly_cells, main_width, None,
            prep_width, num_real, num_vars, EF::ONE, EF::ZERO, pra, vg,
        );

        let (proof, cpe) =
            reduce_sumcheck_serial::<InnerVal, EF, _, _>(vec![poly], &mut challenger, vec![claim], 1, lambda);

        let z = &proof.point_and_eval.0;
        let main_at_z = &cpe[0][prep_width..];
        let expected = eq_pt(&zeta, z) * (cval(main_at_z) + batch(main_at_z));
        proof.point_and_eval.1 == expected
    }

    /// Without the fix, the GKR-forward claim is inconsistent with the
    /// poly's reversed cube-sum → the reduced value != verifier recon.
    #[test]
    fn orientation_bug_reproduced_without_fix() {
        assert!(
            !run_orientation_case(false),
            "expected the zeta-orientation bug to make point_and_eval.1 != eq*(C+batch)"
        );
    }

    /// With the bit-reverse-rows fix, invariant (2) is restored while zeta /
    /// GKR openings / jagged r_row stay byte-identical.
    #[test]
    fn orientation_fix_restores_verifier_identity() {
        assert!(
            run_orientation_case(true),
            "bit-reverse-rows fix must restore point_and_eval.1 == eq*(C+batch)"
        );
    }

    /// Non-power-of-two height: bug present without fix, restored with the
    /// pow2-padded bit-reverse-rows fix (VirtualGeq-compatible).
    #[test]
    fn orientation_nonpow2_bug_then_fix() {
        assert!(!run_orientation_nonpow2(false), "non-pow2 bug should reproduce");
        assert!(
            run_orientation_nonpow2(true),
            "non-pow2 pow2-padded bit-reverse fix must restore the identity"
        );
    }

    /// Parametrized harness: returns (inv1_holds, inv2_holds) for a given
    /// (num_vars, real_vars, ncols) shape.  inv1 = `claim == boolean-cube
    /// sum` (brute force, poly's LSB↔zeta[dim-1] orientation); inv2 =
    /// `reduced == eq(zeta,z)·(C+batch(trace@z))` (the verifier's assert).
    /// Sweeps the unit-test shape up to the e2e shape to localize any
    /// shape-dependent break in the bit-reverse-rows fix.
    fn run_sweep_case(num_vars: u32, real_vars: u32, ncols: usize, fix: bool) -> (bool, bool) {
        // Existing behaviour: nonzero-zeta width == real_vars (chip is the
        // tallest in the shard, no nonzero-zeta padding rounds).
        run_sweep_case_z(num_vars, real_vars, real_vars, ncols, fix)
    }

    /// Generalized sweep: `real_vars` = log2(num_real rows); `zeta_real_vars`
    /// = number of NONZERO trailing zeta coords (= the shard's max chip
    /// log-height, `num_row_variables`).  When `zeta_real_vars > real_vars`
    /// (this chip is SHORTER than the tallest chip in the shard) the poly
    /// folds `zeta_real_vars - real_vars` padding rounds over NONZERO zeta —
    /// the case the original sweep never exercised, and the exact AddSub-in-a-
    /// mixed-height-shard situation.  The GKR claim still opens at the trailing
    /// `real_vars` coords (top_level.rs uses the chip's own log_main_height).
    fn run_sweep_case_z(
        num_vars: u32,
        real_vars: u32,
        zeta_real_vars: u32,
        ncols: usize,
        fix: bool,
    ) -> (bool, bool) {
        use crate::shard_level::logup_gkr_prover::evaluate_trace_columns_at_point;
        use p3_challenger::DuplexChallenger;
        use p3_koala_bear::Poseidon2KoalaBear;
        let perm: Poseidon2KoalaBear<16> = zkm_primitives::poseidon2_init();
        let mut challenger = DuplexChallenger::<InnerVal, _, 16, 8>::new(perm);

        assert!(real_vars <= zeta_real_vars && zeta_real_vars <= num_vars);
        let height = 1usize << real_vars; // pow2 real rows

        // Row-distinct honest trace: col0 cycles {0,1,2} (MockAir C=0 on real
        // rows); other cols arbitrary-distinct (affect batch / trace-MLE only).
        let trace_base: Vec<InnerVal> = (0..height)
            .flat_map(|r| {
                (0..ncols)
                    .map(move |c| {
                        if c == 0 {
                            InnerVal::from_u64((r % 3) as u64)
                        } else {
                            InnerVal::from_u64((r * 13 + c * 7 + 1) as u64)
                        }
                    })
                    .collect::<Vec<_>>()
            })
            .collect();
        let main_cells: Vec<EF> = trace_base.iter().map(|&v| EF::from(v)).collect();

        let zeta: Vec<EF> = (0..num_vars as usize)
            .map(|k| {
                if (k as u32) < (num_vars - zeta_real_vars) {
                    EF::ZERO
                } else {
                    EF::from_u64((k * 7 + 3) as u64 + 200)
                }
            })
            .collect();

        let alpha = EF::from_u64(17);
        let beta = EF::from_u64(29);
        let lambda = EF::from_u64(31);
        let pv: Vec<InnerVal> = Vec::new();

        let chip = Chip::new(MockAir { ncols });
        let main_width = ncols;
        let prep_width = 0usize;
        let gkr_powers: Vec<EF> = {
            let mut v = Vec::new();
            let mut acc = EF::ONE;
            for _ in 0..main_width {
                acc *= beta;
                v.push(acc);
            }
            v
        };
        let batch =
            |row: &[EF]| -> EF { row.iter().zip(gkr_powers.iter()).map(|(&v, &p)| v * p).sum() };
        let cval = |main_row: &[EF]| -> EF {
            eval_air_constraints_at_row::<InnerVal, EF, MockAir>(&chip, alpha, &pv, &[], main_row)
        };

        let start = (num_vars - real_vars) as usize;
        let main_evals =
            evaluate_trace_columns_at_point::<InnerVal, EF>(&trace_base, main_width, &zeta[start..]);
        let claim_gkr: EF =
            main_evals.iter().zip(gkr_powers.iter()).fold(EF::ZERO, |a, (o, p)| a + *o * *p);

        // SP1-FAITHFUL CLAIM CORRECTION (PaddedMle::eval_at_eq embedding):
        // SP1 opens each chip at the FULL max-dim point, so its opening already
        // carries Π_{extra}(1 − zeta[k]) over the nonzero zeta coords BETWEEN
        // this chip's trailing log_h and the shard max (`num_row_variables`).
        // Ziren's GKR opens at the trailing log_h only, dropping that factor.
        // Re-apply it so the zerocheck claim equals the embedded boolean-cube
        // sum.  The extra coords are zeta[num_vars - zeta_real_vars ..
        // num_vars - real_vars]; for an equal-height chip this range is empty
        // (factor = 1, no-op).
        let embed_factor: EF = zeta
            [(num_vars - zeta_real_vars) as usize..(num_vars - real_vars) as usize]
            .iter()
            .fold(EF::ONE, |acc, &zk| acc * (EF::ONE - zk));
        let claim: EF = claim_gkr * embed_factor;

        let poly_cells =
            if fix { bitrev_rows(&main_cells, ncols, height) } else { main_cells.clone() };

        let pra = compute_padded_row_adjustment::<InnerVal, EF, MockAir>(
            &chip, alpha, &pv, main_width, prep_width,
        );
        let vg = VirtualGeq::new(height as u32, EF::ONE, EF::ZERO, num_vars);
        let poly = ZeroCheckPoly::<InnerVal, EF, MockAir>::new(
            &chip,
            &pv,
            alpha,
            gkr_powers.clone(),
            zeta.clone(),
            poly_cells.clone(),
            main_width,
            None,
            prep_width,
            height,
            num_vars,
            EF::ONE,
            EF::ZERO,
            pra,
            vg,
        );

        // INVARIANT (1): brute-force boolean-cube sum == claim.  The poly folds
        // the LSB first and peels zeta[dim-1] first, so row-bit b ↔ zeta[dim-1-b];
        // padding rows (x ≥ height) contribute eq·pra, which VirtualGeq cancels.
        let dim = num_vars as usize;
        let mut cube_sum = EF::ZERO;
        for x in 0..height {
            let mut pt = vec![EF::ZERO; dim];
            for b in 0..(real_vars as usize) {
                if (x >> b) & 1 == 1 {
                    pt[dim - 1 - b] = EF::ONE;
                }
            }
            let row = &poly_cells[x * ncols..x * ncols + ncols];
            cube_sum += eq_pt(&zeta, &pt) * (cval(row) + batch(row));
        }
        let inv1 = cube_sum == claim;

        let (proof, cpe) = reduce_sumcheck_serial::<InnerVal, EF, _, _>(
            vec![poly],
            &mut challenger,
            vec![claim],
            1,
            lambda,
        );
        let z = &proof.point_and_eval.0;
        let main_at_z = &cpe[0][prep_width..];
        let expected = eq_pt(&zeta, z) * (cval(main_at_z) + batch(main_at_z));
        let inv2 = proof.point_and_eval.1 == expected;
        (inv1, inv2)
    }

    /// Bisect the unit-test shape (4,2,2 — passes) toward the e2e shape
    /// (22,16,2 — AddSub chip0) to localize any shape-dependent break in
    /// the bit-reverse-rows orientation fix.  Prints per-config results; the
    /// final assert flags any config whose FIX path fails invariant (2).
    #[test]
    fn orientation_sweep() {
        let configs = [
            (4u32, 2u32, 2usize), // baseline == run_orientation_case
            (4, 2, 5),            // wider
            (5, 2, 2),            // +1 padding round
            (6, 2, 2),            // +2 padding rounds (gap 4)
            (8, 2, 2),            // gap 6 (== e2e gap), few real rounds
            (6, 4, 2),            // 4 real rounds
            (8, 4, 2),            // 4 real + gap 4
            (10, 8, 2),           // 8 real rounds
            (12, 6, 8),           // wide + medium
            (16, 10, 4),          // large
            (22, 16, 2),          // *** e2e shape (chip0 AddSub) ***
        ];
        let mut any_fix_inv2_fail = false;
        for &(nv, rv, nc) in configs.iter() {
            let (i1f, i2f) = run_sweep_case(nv, rv, nc, true);
            let (i1n, i2n) = run_sweep_case(nv, rv, nc, false);
            eprintln!(
                "SWEEP nv={:>2} rv={:>2} nc={} | FIX inv1={} inv2={} | NOFIX inv1={} inv2={}",
                nv, rv, nc, i1f, i2f, i1n, i2n
            );
            if !i2f {
                any_fix_inv2_fail = true;
            }
        }
        assert!(
            !any_fix_inv2_fail,
            "some FIX config failed invariant (2) — bit-reverse fix is shape-dependent (see SWEEP lines)"
        );
    }

    /// MIXED-HEIGHT sweep: the chip is SHORTER than the tallest chip in the
    /// shard, so `zeta` has nonzero coords BEYOND this chip's log-height
    /// (`zeta_real_vars > real_vars`).  This is the exact e2e situation for
    /// AddSub (and any sub-max-height chip) that the equal-height sweep never
    /// exercised.  Prints results; does NOT assert (diagnostic) so we see the
    /// full pattern.
    #[test]
    fn orientation_sweep_mixed_height() {
        // (num_vars, real_vars = log2(rows), zeta_real_vars = nonzero zeta coords, ncols)
        let configs = [
            (8u32, 2u32, 2u32, 2usize),  // equal-height control (should pass)
            (8, 2, 3, 2),                // +1 nonzero-zeta padding round
            (8, 2, 4, 2),                // +2 nonzero-zeta padding rounds
            (8, 2, 6, 2),                // +4
            (22, 10, 16, 2),             // e2e-like: 2^10 rows, 16 nonzero zeta coords
            (22, 10, 20, 2),             // taller shard
            (12, 6, 6, 4),               // equal-height control wide
            (12, 4, 8, 4),               // shorter chip, wide
        ];
        for &(nv, rv, zrv, nc) in configs.iter() {
            let (i1f, i2f) = run_sweep_case_z(nv, rv, zrv, nc, true);
            let (i1n, i2n) = run_sweep_case_z(nv, rv, zrv, nc, false);
            eprintln!(
                "MIXED nv={:>2} rv={:>2} zrv={:>2} nc={} | FIX inv1={} inv2={} | NOFIX inv1={} inv2={}",
                nv, rv, zrv, nc, i1f, i2f, i1n, i2n
            );
        }
    }

    // ─────────────────── sum_as_poly spec-reference parity ───────────────────
    //
    // An INDEPENDENT re-implementation of one chip's one-round degree-4 round
    // poly, derived from the byte-exact spec of `sum_as_poly` (the exact thing
    // the device zerocheck kernel must reproduce).  It is structured DIFFERENTLY
    // from the host on purpose, so a shared transcription bug is unlikely:
    //   * sample rows via field-mult LDE `a + X·(b−a)` (host uses doubling);
    //   * g_X computed by DIRECT `gkr_batch` at all four samples (host uses the
    //     `g4 = 2·g2 − g0`, `g3 = (g2+g4)/2` linear extrapolation) — this also
    //     cross-checks that `gkr_batch` is affine in the sample point;
    //   * the eq weight `partial[pair]` reimplemented big-endian from scratch
    //     (host uses `partial_lagrange`).
    // The finalize (elf_X pre-scale + VirtualGeq padded subtraction + degree-4
    // interpolation) is mirrored from the spec — the end-to-end correctness of
    // that stage is independently pinned by `orientation_sweep`'s inv1/inv2.
    fn cpu_ref_round_poly(
        poly: &ZeroCheckPoly<InnerVal, EF, MockAir>,
        claim: EF,
        is_first_round: bool,
    ) -> UnivariatePolynomial<EF> {
        let num_real = poly.num_real_entries;
        if num_real == 0 {
            return UnivariatePolynomial { coefficients: vec![EF::ZERO; 5] };
        }
        let nm = poly.num_main_cols;
        let np = poly.num_prep_cols;
        let dim = poly.zeta.len();
        let last = poly.zeta[dim - 1];
        let rest = &poly.zeta[..dim - 1];
        let num_pairs = num_real.div_ceil(2);
        let gkr = &poly.gkr_powers;

        // big-endian eq weight: bit k (LSB) of `pair` binds rest[rest.len()-1-k];
        // bit set -> z, bit clear -> (1 - z).  (Reimplements partial_lagrange.)
        let eqw = |pair: usize| -> EF {
            let rl = rest.len();
            let mut acc = EF::ONE;
            for k in 0..rl {
                let z = rest[rl - 1 - k];
                acc *= if (pair >> k) & 1 == 1 { z } else { EF::ONE - z };
            }
            acc
        };
        // field-mult LDE of one row-pair at sample X (odd tail -> partner ZERO).
        let lerp = |cells: &[EF], ncols: usize, r0: usize, r1: usize, x: u64| -> Vec<EF> {
            let xx = EF::from_u64(x);
            (0..ncols)
                .map(|c| {
                    let a = cells[r0 * ncols + c];
                    let b = if r1 < num_real { cells[r1 * ncols + c] } else { EF::ZERO };
                    a + xx * (b - a)
                })
                .collect()
        };
        let gkr_batch = |m: &[EF], p: &[EF]| -> EF {
            m.iter().chain(p.iter()).zip(gkr.iter()).fold(EF::ZERO, |a, (v, pw)| a + *v * *pw)
        };
        let cval = |p: &[EF], m: &[EF]| -> EF {
            eval_air_constraints_at_row::<InnerVal, EF, MockAir>(
                poly.air,
                poly.alpha,
                poly.public_values,
                p,
                m,
            )
        };

        let prep = poly.prep_cells.as_ref();
        let empty: Vec<EF> = Vec::new();
        let (mut y0, mut y2, mut y3, mut y4) = (EF::ZERO, EF::ZERO, EF::ZERO, EF::ZERO);
        for pair in 0..num_pairs {
            let eq = eqw(pair);
            let (r0, r1) = (2 * pair, 2 * pair + 1);
            let m0 = lerp(&poly.main_cells, nm, r0, r1, 0);
            let m2 = lerp(&poly.main_cells, nm, r0, r1, 2);
            let m3 = lerp(&poly.main_cells, nm, r0, r1, 3);
            let m4 = lerp(&poly.main_cells, nm, r0, r1, 4);
            let (p0, p2, p3, p4) = if np > 0 {
                let pc = prep.expect("prep_cells present when np > 0");
                (
                    lerp(pc, np, r0, r1, 0),
                    lerp(pc, np, r0, r1, 2),
                    lerp(pc, np, r0, r1, 3),
                    lerp(pc, np, r0, r1, 4),
                )
            } else {
                (empty.clone(), empty.clone(), empty.clone(), empty.clone())
            };
            // direct gkr at every sample (no g4=2g2-g0 extrapolation).
            let g0 = gkr_batch(&m0, &p0);
            let g2 = gkr_batch(&m2, &p2);
            let g3 = gkr_batch(&m3, &p3);
            let g4 = gkr_batch(&m4, &p4);
            let c0 = if is_first_round { EF::ZERO } else { cval(&p0, &m0) };
            let c2 = cval(&p2, &m2);
            let c3 = cval(&p3, &m3);
            let c4 = cval(&p4, &m4);
            y0 += (c0 + g0) * eq;
            y2 += (c2 + g2) * eq;
            y3 += (c3 + g3) * eq;
            y4 += (c4 + g4) * eq;
        }

        // finalize: SCALE accumulated y_X by (elf_X · eq_adjustment), then
        // SUBTRACT padded_row_adjustment · virtual_X · msb_lagrange_eval · elf_X.
        let threshold_half = num_pairs - 1;
        let eq_adj = poly.eq_adjustment;
        let msb = eq_adj
            * if threshold_half < (1usize << (poly.num_variables - 1)) {
                eqw(threshold_half)
            } else {
                EF::ZERO
            };
        let pra = poly.padded_row_adjustment;
        let virt = |x: u64| -> EF {
            poly.virtual_geq.fix_last_variable(EF::from_u64(x)).eval_at_usize(threshold_half)
        };
        let elf0 = EF::ONE - last;
        let elf2 = last * EF::from_u64(3) - EF::ONE;
        let elf3 = last * EF::from_u64(5) - EF::from_u64(2);
        let elf4 = last * EF::from_u64(7) - EF::from_u64(3);
        let yy0 = y0 * (elf0 * eq_adj) - pra * virt(0) * msb * elf0;
        let yy2 = y2 * (elf2 * eq_adj) - pra * virt(2) * msb * elf2;
        let yy3 = y3 * (elf3 * eq_adj) - pra * virt(3) * msb * elf3;
        let yy4 = y4 * (elf4 * eq_adj) - pra * virt(4) * msb * elf4;

        let xs = vec![EF::ZERO, EF::ONE, EF::from_u64(2), EF::from_u64(3), EF::from_u64(4)];
        let ys = vec![yy0, claim - yy0, yy2, yy3, yy4];
        interpolate_univariate_polynomial(&xs, &ys)
    }

    /// Honest pow2-height fixture (mirrors `run_sweep_case_z`); asserts the
    /// independent reference equals the live `sum_as_poly` for round 0 and
    /// round 1, plus the sumcheck relation `p(0)+p(1)==claim`.
    fn check_sum_as_poly_ref(num_vars: u32, real_vars: u32, zeta_real_vars: u32, ncols: usize) {
        use crate::shard_level::logup_gkr_prover::evaluate_trace_columns_at_point;
        assert!(real_vars <= zeta_real_vars && zeta_real_vars <= num_vars);
        let height = 1usize << real_vars;
        let trace_base: Vec<InnerVal> = (0..height)
            .flat_map(|r| {
                (0..ncols)
                    .map(move |c| {
                        if c == 0 {
                            InnerVal::from_u64((r % 3) as u64)
                        } else {
                            InnerVal::from_u64((r * 13 + c * 7 + 1) as u64)
                        }
                    })
                    .collect::<Vec<_>>()
            })
            .collect();
        let main_cells: Vec<EF> = trace_base.iter().map(|&v| EF::from(v)).collect();
        let zeta: Vec<EF> = (0..num_vars as usize)
            .map(|k| {
                if (k as u32) < (num_vars - zeta_real_vars) {
                    EF::ZERO
                } else {
                    EF::from_u64((k * 7 + 3) as u64 + 200)
                }
            })
            .collect();
        let alpha = EF::from_u64(17);
        let beta = EF::from_u64(29);
        let pv: Vec<InnerVal> = Vec::new();
        let chip = Chip::new(MockAir { ncols });
        let main_width = ncols;
        let prep_width = 0usize;
        let gkr_powers: Vec<EF> = {
            let mut v = Vec::new();
            let mut acc = EF::ONE;
            for _ in 0..main_width {
                acc *= beta;
                v.push(acc);
            }
            v
        };
        let start = (num_vars - real_vars) as usize;
        let main_evals =
            evaluate_trace_columns_at_point::<InnerVal, EF>(&trace_base, main_width, &zeta[start..]);
        let claim_gkr: EF =
            main_evals.iter().zip(gkr_powers.iter()).fold(EF::ZERO, |a, (o, p)| a + *o * *p);
        let embed_factor: EF = zeta
            [(num_vars - zeta_real_vars) as usize..(num_vars - real_vars) as usize]
            .iter()
            .fold(EF::ONE, |acc, &zk| acc * (EF::ONE - zk));
        let claim: EF = claim_gkr * embed_factor;
        let poly_cells = bitrev_rows(&main_cells, ncols, height);
        let pra = compute_padded_row_adjustment::<InnerVal, EF, MockAir>(
            &chip, alpha, &pv, main_width, prep_width,
        );
        let vg = VirtualGeq::new(height as u32, EF::ONE, EF::ZERO, num_vars);
        let poly = ZeroCheckPoly::<InnerVal, EF, MockAir>::new(
            &chip, &pv, alpha, gkr_powers, zeta, poly_cells, main_width, None, prep_width, height,
            num_vars, EF::ONE, EF::ZERO, pra, vg,
        );

        // Round 0 (is_first_round = true -> c0 skipped).
        let host0 = poly.sum_as_poly(Some(claim), true);
        let ref0 = cpu_ref_round_poly(&poly, claim, true);
        assert_eq!(
            ref0.coefficients, host0.coefficients,
            "round0 mismatch nv={num_vars} rv={real_vars} zrv={zeta_real_vars} nc={ncols}"
        );
        assert_eq!(
            poly_horner(&host0.coefficients, EF::ZERO) + poly_horner(&host0.coefficients, EF::ONE),
            claim,
            "sumcheck relation p(0)+p(1)==claim nv={num_vars}"
        );

        // Round 1 (fold by an arbitrary challenge; is_first_round = false).
        let alpha_fold = EF::from_u64(101);
        let claim1 = poly_horner(&host0.coefficients, alpha_fold);
        let poly1 = poly.fix_last(alpha_fold);
        let host1 = poly1.sum_as_poly(Some(claim1), false);
        let ref1 = cpu_ref_round_poly(&poly1, claim1, false);
        assert_eq!(
            ref1.coefficients, host1.coefficients,
            "round1 mismatch nv={num_vars} rv={real_vars} zrv={zeta_real_vars} nc={ncols}"
        );
    }

    /// Pure-padding (num_real=0) and odd-real (odd-tail + non-trivial
    /// VirtualGeq) cases.  The claim need not be valid: the reference and the
    /// host must agree on the COMPUTATION for the same arbitrary inputs.
    fn check_pad_and_odd_tail() {
        let alpha = EF::from_u64(17);
        let beta = EF::from_u64(29);
        let pv: Vec<InnerVal> = Vec::new();
        let ncols = 3usize;
        let chip = Chip::new(MockAir { ncols });
        let gkr_powers: Vec<EF> = {
            let mut v = Vec::new();
            let mut acc = EF::ONE;
            for _ in 0..ncols {
                acc *= beta;
                v.push(acc);
            }
            v
        };
        let pra =
            compute_padded_row_adjustment::<InnerVal, EF, MockAir>(&chip, alpha, &pv, ncols, 0);
        let num_vars = 4u32;
        let zeta: Vec<EF> =
            (0..num_vars as usize).map(|k| EF::from_u64((k * 7 + 3) as u64 + 200)).collect();

        // pure padding.
        let vg0 = VirtualGeq::new(0, EF::ONE, EF::ZERO, num_vars);
        let poly0 = ZeroCheckPoly::<InnerVal, EF, MockAir>::new(
            &chip, &pv, alpha, gkr_powers.clone(), zeta.clone(), Vec::new(), ncols, None, 0, 0,
            num_vars, EF::ONE, EF::ZERO, pra, vg0,
        );
        let arb = EF::from_u64(999983);
        let h0 = poly0.sum_as_poly(Some(arb), false);
        let r0 = cpu_ref_round_poly(&poly0, arb, false);
        assert_eq!(r0.coefficients, h0.coefficients, "pure-padding mismatch");
        assert_eq!(h0.coefficients, vec![EF::ZERO; 5], "pure-padding must be [0;5]");

        // odd real (num_real=3): exercises interp odd-tail + non-zero virtual_X.
        let num_real = 3usize;
        let main_cells: Vec<EF> = (0..num_real)
            .flat_map(|r| {
                (0..ncols).map(move |c| EF::from_u64((r * 13 + c * 7 + 1) as u64)).collect::<Vec<_>>()
            })
            .collect();
        let vg = VirtualGeq::new(num_real as u32, EF::ONE, EF::ZERO, num_vars);
        let poly = ZeroCheckPoly::<InnerVal, EF, MockAir>::new(
            &chip, &pv, alpha, gkr_powers, zeta, main_cells, ncols, None, 0, num_real, num_vars,
            EF::ONE, EF::ZERO, pra, vg,
        );
        let arb2 = EF::from_u64(424242);
        let h = poly.sum_as_poly(Some(arb2), true);
        let r = cpu_ref_round_poly(&poly, arb2, true);
        assert_eq!(r.coefficients, h.coefficients, "odd-tail mismatch");
    }

    /// The byte-exact device-kernel target: independent reference == live
    /// `sum_as_poly` for the full degree-4 round poly across mixed-height,
    /// wide, e2e-like, pure-padding, and odd-tail fixtures.
    #[test]
    fn sum_as_poly_matches_spec_reference() {
        check_sum_as_poly_ref(4, 2, 2, 2); // equal-height, padded
        check_sum_as_poly_ref(4, 2, 3, 2); // mixed-height (embed_factor != 1)
        check_sum_as_poly_ref(8, 2, 4, 2); // more padding rounds
        check_sum_as_poly_ref(8, 3, 6, 3); // wider + taller, shorter chip
        check_sum_as_poly_ref(6, 4, 4, 4); // wide, equal-height
        check_sum_as_poly_ref(22, 10, 16, 2); // e2e-like (AddSub chip0 shape)
        check_pad_and_odd_tail();
    }
}
