//! Generic sumcheck driver + the four sumcheck-poly traits.
//!
//! Conventions:
//!   * Round polys carried in coefficient form (verifier expects
//!     this on the wire).
//!   * EF coefficients are observed by decomposing into base-field
//!     basis coefficients (matches the verifier's observation).
//!   * MSB fold with `point.insert(0, alpha)` so the reduced point
//!     reads `point[k]` = challenge for variable k of the flat
//!     index under an LSB-first MLE consumer.
//!   * `t = 1` only; the `t` parameter is kept so a multi-variable
//!     first round stays drop-in.

use alloc::vec::Vec;

use p3_challenger::{CanObserve, FieldChallenger};
use p3_field::{BasedVectorSpace, ExtensionField, Field};

use crate::shard_level::types::{PartialSumcheckProof, UnivariatePolynomial};

pub trait SumcheckPolyBase {
    fn num_variables(&self) -> u32;
}

pub trait ComponentPoly<K: Field> {
    fn get_component_poly_evals(&self) -> Vec<K>;
}

pub trait SumcheckPoly<K: Field>: SumcheckPolyBase + ComponentPoly<K> + Sized {
    fn fix_last_variable(self, alpha: K) -> Self;

    /// `claim = prev_poly(alpha_prev)` enables the 3-eval trick
    /// `p(0) = claim - p(1)`. When `None`, compute `p(0)` directly.
    fn sum_as_poly_in_last_variable(&self, claim: Option<K>) -> UnivariatePolynomial<K>;

    /// Batched form over ALL polys (chips) at once, enabling a single fused
    /// device call across chips.  Default = per-poly loop (GKR / tests keep
    /// the host path); the zerocheck poly overrides this to fuse on-device.
    fn batched_sum_as_poly_in_last_variable(
        polys: &[Self],
        claims: &[Option<K>],
    ) -> Vec<UnivariatePolynomial<K>>
    where
        Self: Sized,
    {
        polys.iter().zip(claims.iter()).map(|(p, c)| p.sum_as_poly_in_last_variable(*c)).collect()
    }
}

/// Sumcheckable polynomial whose first round binds `t` variables at
/// once. Ziren only consumes `t = 1`.
pub trait SumcheckPolyFirstRound<K: Field>: SumcheckPolyBase {
    type NextRoundPoly: SumcheckPoly<K>;

    fn fix_t_variables(self, alpha: K, t: usize) -> Self::NextRoundPoly;

    fn sum_as_poly_in_last_t_variables(
        &self,
        claim: Option<K>,
        t: usize,
    ) -> UnivariatePolynomial<K>;

    /// Batched first-round form over ALL polys (chips).  Default = per-poly
    /// loop; the zerocheck poly overrides this to fuse on-device.
    fn batched_sum_as_poly_in_last_t_variables(
        polys: &[Self],
        claims: &[Option<K>],
        t: usize,
    ) -> Vec<UnivariatePolynomial<K>>
    where
        Self: Sized,
    {
        polys
            .iter()
            .zip(claims.iter())
            .map(|(p, c)| p.sum_as_poly_in_last_t_variables(*c, t))
            .collect()
    }
}

/// Observe an EF element into a base-field challenger by decomposing
/// into basis coefficients.
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

/// Evaluate a coefficient-form polynomial at a point via Horner's.
#[inline]
fn poly_eval<EF: Field>(coeffs: &[EF], x: EF) -> EF {
    let mut acc = EF::ZERO;
    for c in coeffs.iter().rev() {
        acc = acc * x + *c;
    }
    acc
}

/// Generic sumcheck driver — reduces a sumcheck claim to an evaluation
/// claim about the polynomial at a randomly-sampled point.
///
/// Round polys are observed per-coefficient in base-field basis (the
/// verifier's observation pattern).
///
/// # Single-poly case (`polys.len() == 1`)
///
/// When a caller passes one polynomial (e.g. `prove_gkr_round`), the
/// `lambda` argument is unused (no RLC batching needed),
/// but it is kept in the signature to make
/// multi-poly batching drop-in.
///
/// # Returns
///
/// `(PartialSumcheckProof<EF>, component_poly_evals)` where
/// `component_poly_evals[i]` is the i-th input polynomial's component
/// openings at the reduced point — see
/// [`ComponentPoly::get_component_poly_evals`].
///
/// # Panics
///
/// Panics if `polys.is_empty()`, if any polynomial has fewer than `t`
/// variables, or if the polynomials disagree on `num_variables()`.
pub fn reduce_sumcheck_to_evaluation<F, EF, P, Challenger>(
    polys: Vec<P>,
    challenger: &mut Challenger,
    claims: Vec<EF>,
    t: usize,
    lambda: EF,
) -> (PartialSumcheckProof<EF>, Vec<Vec<EF>>)
where
    F: Field,
    EF: ExtensionField<F> + BasedVectorSpace<F>,
    P: SumcheckPolyFirstRound<EF> + Send + Sync,
    P::NextRoundPoly: Send + Sync,
    Challenger: FieldChallenger<F>,
{
    assert!(!polys.is_empty(), "reduce_sumcheck_to_evaluation: empty input");

    let num_variables = polys[0].num_variables();
    assert!(
        polys.iter().all(|poly| poly.num_variables() == num_variables),
        "reduce_sumcheck_to_evaluation: polys disagree on num_variables"
    );
    assert!(num_variables >= t as u32, "reduce_sumcheck_to_evaluation: t > num_variables");
    assert!(num_variables > 0, "reduce_sumcheck_to_evaluation: zero-variable poly");
    assert_eq!(claims.len(), polys.len());

    let mut point: Vec<EF> = Vec::with_capacity(num_variables as usize);

    let mut univariate_poly_msgs: Vec<UnivariatePolynomial<EF>> =
        Vec::with_capacity(num_variables as usize);

    use p3_maybe_rayon::prelude::*;

    let mut uni_polys: Vec<UnivariatePolynomial<EF>> = polys
        .par_iter()
        .zip(claims.par_iter())
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
        polys.into_par_iter().map(|poly| poly.fix_t_variables(alpha, t)).collect();

    for _ in t..num_variables as usize {
        let alpha_prev = *point.first().unwrap();
        let round_claims: Vec<EF> =
            uni_polys.iter().map(|poly| poly_eval(&poly.coefficients, alpha_prev)).collect();

        uni_polys = polys_cursor
            .par_iter()
            .zip(round_claims.par_iter())
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
            polys_cursor.into_par_iter().map(|poly| poly.fix_last_variable(alpha)).collect();
    }

    let alpha_last = *point.first().unwrap();
    let evals: Vec<EF> =
        uni_polys.iter().map(|poly| poly_eval(&poly.coefficients, alpha_last)).collect();

    let component_poly_evals: Vec<Vec<EF>> =
        polys_cursor.iter().map(|poly| poly.get_component_poly_evals()).collect();

    let claimed_sum = rlc_eval(&claims, lambda);
    let final_eval = rlc_eval(&evals, lambda);

    (
        PartialSumcheckProof {
            univariate_polys: univariate_poly_msgs,
            claimed_sum,
            point_and_eval: (point, final_eval),
        },
        component_poly_evals,
    )
}

/// Random-linear-combination of multiple univariate polynomials by
/// powers of `lambda`.
///
/// Port of
/// `rlc_univariate_polynomials`
/// adapted to Ziren's coefficient-form `UnivariatePolynomial`.
///
/// `result = polys[0] · λ^{n-1} + polys[1] · λ^{n-2} + ... + polys[n-1]`
///
/// For the `n == 1` case (today's only caller) the result is just
/// `polys[0]` cloned — `lambda` is unused.
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
            *slot *= lambda;
        }
        for (i, c) in p.coefficients.iter().enumerate() {
            acc[i] += *c;
        }
    }
    UnivariatePolynomial { coefficients: acc }
}

/// `result = vals[0] · λ^{n-1} + vals[1] · λ^{n-2} + ... + vals[n-1]`.
fn rlc_eval<EF: Field>(vals: &[EF], lambda: EF) -> EF {
    let mut acc = EF::ZERO;
    for &v in vals {
        acc = acc * lambda + v;
    }
    acc
}

type Ef4 = p3_field::extension::BinomialExtensionField<p3_koala_bear::KoalaBear, 4>;

/// Type-erased challenger so a device zerocheck kernel signature doesn't depend
/// on `SC::Challenger`. Not `Send`: single-threaded per shard.
pub trait GpuZerocheckChallenger {
    fn observe_ef(&mut self, v: Ef4);
    fn sample_ef(&mut self) -> Ef4;
}

// The per-round zerocheck / LogUp-GKR GPU entry points are methods on
// `ShardDeviceOps` (see `crate::shard_level::device_ops`), threaded by prover
// type; the device-ABI types they use live in the GPU crate.
//
// Transcript invariant: the device returns the per-pair `(y_0, y_2, y_3, y_4)`
// accumulators before `finalize_round_poly` applies the `elf_X · eq_adjustment`
// scaling and the VirtualGeq padded-row correction.  That finalize is analytic
// and stays on the host, so the Fiat-Shamir transcript is byte-identical
// whichever side computed the accumulators.

// ------------------------------------------------------------------
// Device-built logup-round eq_row tables.
//
// The GKR logup-round `eq_row` weight table has `2^row_vars` entries of 16 B.
// On the device-eq path the host stashes only the `row_point` coordinates here
// (≤ row_vars Ef4 elements) and passes an empty `eq_row` Vec; the GPU crate
// detects the empty slot, reads this point, and builds the table on device
// (`partialLagrangeNaiveEf`) instead of uploading it every round/layer.
//
// `build_eq_table` is LSB-first (index bit k <-> coords[k]), identical to the
// kernel's `(i >> k) & 1 ? point[k] : 1-point[k]`, so the device table is
// byte-identical to the host one -- NO point reversal here, unlike the
// big-endian fused-zerocheck device-eq path.
//
// Slot is per-round transient: the host publishes immediately before the hook
// call and the hook takes it at entry.

std::thread_local! {
    static LOGUP_DEVICE_EQ_ROW_POINT: std::cell::RefCell<Option<Vec<Ef4>>> =
        const { std::cell::RefCell::new(None) };
}

/// Host stashes the row_point (LSB-first coords) for the GPU hook
/// to device-build the eq_row table from.  Published immediately
/// before the hook dispatch; the empty `eq_row` Vec is the signal.
pub fn publish_logup_device_eq_row_point(point: Vec<Ef4>) {
    LOGUP_DEVICE_EQ_ROW_POINT.with(|c| *c.borrow_mut() = Some(point));
}

/// Hook consumes the stashed row_point.  `None` ⇒ the host eq_row was
/// uploaded (device-build disabled or not published).
#[must_use]
pub fn take_logup_device_eq_row_point() -> Option<Vec<Ef4>> {
    LOGUP_DEVICE_EQ_ROW_POINT.with(|c| c.borrow_mut().take())
}

// ------------------------------------------------------------------
// Device pack: per-chip first-layer metadata channel.
//
// The GPU device-pack kernel builds the packed first-layer slab from the
// per-chip device tables (numerator/denominator).  Mapping those tables to
// the global interaction axis + row-parity split requires per-chip metadata
// (num_interactions, and each quadrant's real-row count) that lives on the
// host `LogUpGkrCpuLayer`.  The host publishes it here — only for the
// FirstLayer, only when the device-pack / slab-oracle env gate is set —
// immediately before the V3 hook dispatch; the GPU hook takes it at entry.
// Positionally aligned with the drained per-chip stash (both in
// `LogUpGkrCpuLayer` chip order).
#[derive(Clone, Debug)]
pub struct Nv28ChipMeta {
    /// Layer row variables `R` (rows = `2^R` = `eq_row.len()`).
    pub num_row_variables: usize,
    /// Layer interaction variables `I` (cols = `2^I` = `eq_int.len()`).
    pub num_interaction_variables: usize,
    /// Per-chip raw interaction (local column) count.
    pub per_chip_num_int: Vec<u32>,
    /// Per-chip quadrant-0 (even rows) real row count (`numerator_0.num_real_rows`).
    pub per_chip_real_upper: Vec<u32>,
    /// Per-chip quadrant-1 (odd rows) real row count (`numerator_1.num_real_rows`).
    pub per_chip_real_lower: Vec<u32>,
}

std::thread_local! {
    static NV28_CHIP_META: std::cell::RefCell<Option<Nv28ChipMeta>> =
        const { std::cell::RefCell::new(None) };
}

/// Host publishes per-chip first-layer metadata for the GPU device-pack
/// kernel.  Published immediately before the V3 hook dispatch (FirstLayer
/// only); the hook takes it at entry.
pub fn publish_nv28_chip_meta(meta: Nv28ChipMeta) {
    NV28_CHIP_META.with(|c| *c.borrow_mut() = Some(meta));
}

/// GPU hook consumes the stashed per-chip metadata.  `None` => not a
/// FirstLayer call, or the device-pack env gate is off.
#[must_use]
pub fn take_nv28_chip_meta() -> Option<Nv28ChipMeta> {
    NV28_CHIP_META.with(|c| c.borrow_mut().take())
}

// BaseFold-over-BN254 wrap port: OUTER-ring jagged BaseFold open/verify
//
// The OUTER (wrap) ring proves/verifies the jagged BaseFold open over
// `OuterValMmcs` (Poseidon2-BN254) + `OuterChallenger` (MultiField32). Those
// types live in recursion-core, which depends on zkm-pcs, so zkm-pcs cannot
// name them.  The shard prover (`prove_trusted_evaluations`) and host
// verifier (`verify_jagged_pcs_host`) reach them STATICALLY via the
// `BasefoldRing` associated types
// (`prove_jagged_rounds_generic` /
// `build_jagged_verify_inputs` + `verify_jagged_inner_generic`);
// the setup commit is the typed `StarkGenericConfig::prep_commit` method,
// implemented directly by the inner and wrap configs.  `Val`/`Challenge` are
// identical KoalaBear / KoalaBear^4 for both rings, so trace/point payloads
// cross the boundary unchanged; only the challenger + MMCS differ.

#[cfg(test)]
mod tests {
    use p3_challenger::DuplexChallenger;
    use p3_field::PrimeCharacteristicRing;
    use p3_koala_bear::{KoalaBear, Poseidon2KoalaBear};

    use super::*;
    use crate::Challenge;

    type SC = crate::koala_bear_poseidon2::KoalaBearPoseidon2;
    type EF = Challenge<SC>;

    fn test_challenger() -> DuplexChallenger<KoalaBear, Poseidon2KoalaBear<16>, 16, 8> {
        let perm = crate::kb31_poseidon2::inner_perm();
        DuplexChallenger::new(perm)
    }

    /// A trivial sumchecakable poly: `f(x_0, ..., x_{n-1}) = c` (a constant).
    /// Round poly = `c` per round; always degree-0 (1 coefficient).
    #[derive(Clone)]
    struct ConstantPoly {
        n: u32,
        c: EF,
    }

    impl SumcheckPolyBase for ConstantPoly {
        fn num_variables(&self) -> u32 {
            self.n
        }
    }
    impl ComponentPoly<EF> for ConstantPoly {
        fn get_component_poly_evals(&self) -> Vec<EF> {
            vec![self.c]
        }
    }
    impl SumcheckPoly<EF> for ConstantPoly {
        fn fix_last_variable(self, _alpha: EF) -> Self {
            ConstantPoly { n: self.n - 1, c: self.c }
        }
        fn sum_as_poly_in_last_variable(&self, _claim: Option<EF>) -> UnivariatePolynomial<EF> {
            let two = EF::ONE.double();
            let mut s = self.c;
            for _ in 1..self.n {
                s *= two;
            }
            UnivariatePolynomial { coefficients: vec![s] }
        }
    }
    impl SumcheckPolyFirstRound<EF> for ConstantPoly {
        type NextRoundPoly = ConstantPoly;
        fn fix_t_variables(self, alpha: EF, t: usize) -> Self {
            assert_eq!(t, 1);
            self.fix_last_variable(alpha)
        }
        fn sum_as_poly_in_last_t_variables(
            &self,
            claim: Option<EF>,
            t: usize,
        ) -> UnivariatePolynomial<EF> {
            assert_eq!(t, 1);
            self.sum_as_poly_in_last_variable(claim)
        }
    }

    #[test]
    fn driver_handles_trivial_constant_poly() {
        let n: u32 = 2;
        let c = EF::from_u32(7);
        let poly = ConstantPoly { n, c };
        let claim = c * EF::from_u32(4);

        let mut challenger = test_challenger();
        let (proof, evals) = reduce_sumcheck_to_evaluation::<KoalaBear, EF, _, _>(
            vec![poly],
            &mut challenger,
            vec![claim],
            1,
            EF::ONE,
        );

        assert_eq!(proof.univariate_polys.len(), n as usize);
        assert_eq!(proof.point_and_eval.0.len(), n as usize);
        assert_eq!(proof.claimed_sum, claim);
        assert_eq!(evals.len(), 1);
        assert_eq!(evals[0], vec![c]);
    }

    /// `rlc_univariate_polynomials` with one poly is identity.
    #[test]
    fn rlc_one_poly_is_identity() {
        let p = UnivariatePolynomial { coefficients: vec![EF::from_u32(3), EF::from_u32(5)] };
        let r = rlc_univariate_polynomials(std::slice::from_ref(&p), EF::from_u32(99));
        assert_eq!(r.coefficients, p.coefficients);
    }

    /// `rlc_univariate_polynomials` with two polys interleaves correctly.
    #[test]
    fn rlc_two_polys_combines_with_lambda() {
        let p0 = UnivariatePolynomial { coefficients: vec![EF::from_u32(1), EF::from_u32(2)] };
        let p1 = UnivariatePolynomial { coefficients: vec![EF::from_u32(3), EF::from_u32(4)] };
        let lambda = EF::from_u32(10);
        let r = rlc_univariate_polynomials(&[p0, p1], lambda);
        assert_eq!(r.coefficients[0], EF::from_u32(13));
        assert_eq!(r.coefficients[1], EF::from_u32(24));
    }
}
