//! `LongMle` — a multilinear held as a LIST of component MLEs instead of one
//! flat evaluation table.
//!
//! This is the shape SP1's jagged sumcheck runs on
//! (`slop/crates/jagged/src/long.rs`): the components stay separate, and the
//! "long" polynomial exists only through the way a point is split across them.
//! Ziren's jagged path currently does the opposite — `materialize_dense_jagged`
//! transposes every chip's row-major trace into one column-major
//! `Vec<F>` of length `2^log_dense_size`, twice per shard (commit + reduce).
//! Under SP1's structure that buffer has nowhere to live: the jagged geometry is
//! carried by the point decomposition, not by a physically packed vector.
//!
//! ## Point convention
//!
//! A point of `num_variables()` coordinates splits into
//! `(batch_point, stack_point)`, where `stack_point` is the trailing
//! `log_stacking_height` coordinates — the variables *inside* a component — and
//! `batch_point` selects among the components' polynomials. Evaluation is
//! therefore: evaluate every component at `stack_point` (one value per
//! polynomial in that component), concatenate those values in component order,
//! and evaluate the resulting small MLE at `batch_point`.

extern crate alloc;
use alloc::vec::Vec;

use p3_field::{ExtensionField, Field};

use crate::basefold::mle::{Message, Mle};
use crate::tensor::CpuBackend;

/// A multilinear polynomial stored as its component MLEs plus the number of
/// variables each component carries (`log_stacking_height`).
#[derive(Clone, Debug)]
pub struct LongMle<F> {
    components: Message<Mle<F, CpuBackend>>,
    log_stacking_height: u32,
}

impl<F> LongMle<F> {
    /// Wrap an already-`Arc`'d component list.
    pub const fn new(components: Message<Mle<F, CpuBackend>>, log_stacking_height: u32) -> Self {
        Self { components, log_stacking_height }
    }

    /// Wrap owned components (each is `Arc`'d here).
    pub fn from_components(components: Vec<Mle<F, CpuBackend>>, log_stacking_height: u32) -> Self {
        Self {
            components: components.into_iter().map(alloc::sync::Arc::new).collect(),
            log_stacking_height,
        }
    }

    /// Wrap a `Message` (refcount bump only — this is the zero-copy entry point
    /// the shard prover uses, since its trace store is already `Arc<Mle>`).
    pub const fn from_message(
        message: Message<Mle<F, CpuBackend>>,
        log_stacking_height: u32,
    ) -> Self {
        Self { components: message, log_stacking_height }
    }

    /// Variables carried inside each component.
    #[inline]
    pub const fn log_stacking_height(&self) -> u32 {
        self.log_stacking_height
    }

    #[inline]
    pub fn components(&self) -> &Message<Mle<F, CpuBackend>> {
        &self.components
    }

    #[inline]
    pub fn into_components(self) -> Message<Mle<F, CpuBackend>> {
        self.components
    }

    #[inline]
    pub fn num_components(&self) -> usize {
        self.components.len()
    }

    /// Total values across all components — `sum(num_polynomials * 2^num_variables)`.
    pub fn total_values(&self) -> usize {
        self.components
            .iter()
            .map(|mle| mle.num_polynomials() << mle.num_variables())
            .sum::<usize>()
    }

    /// Total variables of the long polynomial.
    ///
    /// Mirrors SP1 `long.rs:95`, which takes a plain `ilog2()` — i.e. it ASSUMES
    /// the components stack EXACTLY into a power of two.  That is not a free
    /// property: it is what `log_stacking_height` and
    /// `interleave_multilinears_with_fixed_rate` exist to arrange.  Asserted
    /// here rather than papered over by zero-padding, because a floor-`ilog2`
    /// on a non-power-of-two total silently returns a polynomial one or more
    /// variables too small.
    pub fn num_variables(&self) -> u32 {
        let total = self.total_values();
        assert!(
            total.is_power_of_two(),
            "LongMle: components must stack exactly into a power of two, got {total} \
             (stack/interleave them first)",
        );
        total.ilog2()
    }
}

impl<F: Field> LongMle<F> {
    /// Evaluate the long polynomial at `point` (LSB-first, length
    /// `num_variables()`).
    ///
    /// See the module note on the point split. Mirrors SP1 `long.rs:39`.
    pub fn eval_at<EF>(&self, point: &[EF]) -> EF
    where
        EF: ExtensionField<F> + Send + Sync,
        F: Sync,
    {
        let split = point.len() - self.log_stacking_height as usize;
        let (batch_point, stack_point) = point.split_at(split);

        // One evaluation per polynomial per component, in component order.
        let component_evaluations: Vec<EF> =
            self.components.iter().flat_map(|mle| mle.eval_at(stack_point)).collect();

        // Small MLE over the component/polynomial index.  No padding: the
        // exact-stacking invariant asserted by `num_variables` means this is
        // already a power of two.
        Mle::from_values(component_evaluations).eval_at(batch_point)[0]
    }

    /// Fix the stride-1 (LSB) variable of every component to `alpha`.
    ///
    /// Uses the LAGRANGE fold (`(1-alpha)·lo + alpha·hi`) via
    /// [`Mle::fix_last_variable`] — NOT `Mle::fold`, which is the BaseFold rule
    /// and would silently change the polynomial being proved.
    ///
    /// Mirrors SP1 `long.rs:62`.  SP1 additionally RE-INTERLEAVES when
    /// `log_stacking_height <= 2`, restacking the components into one before
    /// folding.  That only changes anything when there is more than one
    /// component: for a single component the re-interleave is the identity, and
    /// the sumcheck always holds a single (already restacked) component.  So the
    /// multi-component small-stack case is rejected rather than silently taking
    /// a path with no equivalence coverage.
    pub fn fix_last_variable<EF>(&self, alpha: EF) -> LongMle<EF>
    where
        EF: ExtensionField<F> + Send + Sync,
        F: Sync,
    {
        assert!(
            self.log_stacking_height > 2 || self.components.len() == 1,
            "LongMle::fix_last_variable: multi-component fold at log_stacking_height <= 2 needs \
             SP1's re-interleaving path (long.rs:64-84), which is not ported yet",
        );
        let components: Vec<Mle<EF, CpuBackend>> =
            self.components.iter().map(|mle| mle.fix_last_variable(alpha)).collect();
        LongMle::from_components(components, self.log_stacking_height - 1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{InnerChallenge, InnerVal};
    use p3_field::PrimeCharacteristicRing;
    use p3_matrix::dense::RowMajorMatrix;
    use rand::{rngs::StdRng, Rng, SeedableRng};

    /// Build `num_components` components, each `2^lsh` rows by `widths[c]` cols.
    fn build(rng: &mut StdRng, widths: &[usize], lsh: u32) -> Vec<Mle<InnerVal, CpuBackend>> {
        let height = 1usize << lsh;
        widths
            .iter()
            .map(|&w| {
                let vals: Vec<InnerVal> =
                    (0..height * w).map(|_| InnerVal::from_u32(rng.gen::<u32>() % 1000)).collect();
                Mle::from_row_major(RowMajorMatrix::new(vals, w))
            })
            .collect()
    }

    /// The flat evaluation table the `LongMle` stands for.
    ///
    /// `eval_at` splits the point as `(batch_point, stack_point)` with `stack`
    /// TRAILING, and Ziren's `Mle::eval_at` is LSB-first — so the batch
    /// coordinates are the LOW variables and the batch index varies fastest.
    fn flat_reference(components: &[Mle<InnerVal, CpuBackend>], lsh: u32) -> Vec<InnerVal> {
        let height = 1usize << lsh;
        let batch: usize = components.iter().map(|m| m.num_polynomials()).sum();
        assert!(batch.is_power_of_two(), "test fixtures must stack exactly");
        let mut flat = vec![InnerVal::ZERO; batch * height];
        for stack in 0..height {
            let mut b = 0usize;
            for m in components {
                let w = m.num_polynomials();
                let g = m.guts().as_slice();
                for col in 0..w {
                    flat[stack * batch + b] = g[stack * w + col];
                    b += 1;
                }
            }
        }
        flat
    }

    #[test]
    fn eval_at_matches_the_flat_table() {
        let mut rng = StdRng::seed_from_u64(0xA11CE);
        // Totals must be powers of two (the exact-stacking invariant): 1, 4, 8, 8, 16.
        for widths in [vec![1usize], vec![2, 2], vec![3, 1, 4], vec![5, 3], vec![6, 6, 4]] {
            for lsh in [3u32, 4] {
                let comps = build(&mut rng, &widths, lsh);
                let flat = flat_reference(&comps, lsh);
                let long = LongMle::from_components(comps, lsh);

                let nv = long.num_variables() as usize;
                assert_eq!(1usize << nv, flat.len(), "num_variables disagrees with flat length");

                let point: Vec<InnerChallenge> =
                    (0..nv).map(|_| InnerChallenge::from_u32(rng.gen::<u32>() % 1000)).collect();

                let got = long.eval_at(&point);
                let want = Mle::from_values(flat).eval_at(&point)[0];
                assert_eq!(got, want, "widths={widths:?} lsh={lsh}");
            }
        }
    }

    /// Fixing a component's stride-1 variable must agree with evaluating the
    /// long polynomial at that coordinate directly.  The component's stride-1
    /// variable is `stack_point[0]`, i.e. `point[split]` — neither the first nor
    /// the last coordinate of the long point — which is exactly the sort of
    /// off-by-one this test exists to catch.
    #[test]
    fn fix_last_variable_agrees_with_direct_evaluation() {
        let mut rng = StdRng::seed_from_u64(0xF01D);
        for widths in [vec![2usize, 2], vec![3, 1, 4], vec![6, 6, 4]] {
            for lsh in [3u32, 4] {
                let comps = build(&mut rng, &widths, lsh);
                let long = LongMle::from_components(comps, lsh);
                let nv = long.num_variables() as usize;
                let split = nv - lsh as usize;

                let alpha = InnerChallenge::from_u32(rng.gen::<u32>() % 1000);
                let rest: Vec<InnerChallenge> = (0..nv - 1)
                    .map(|_| InnerChallenge::from_u32(rng.gen::<u32>() % 1000))
                    .collect();

                // Folded polynomial evaluated at `rest`.
                let folded = long.fix_last_variable(alpha);
                let got = folded.eval_at(&rest);

                // Same point with `alpha` re-inserted at the component's
                // stride-1 slot.
                let mut full = rest.clone();
                full.insert(split, alpha);
                let want = long.eval_at(&full);

                assert_eq!(got, want, "widths={widths:?} lsh={lsh}");
            }
        }
    }

    /// The sumcheck invariant, which is what actually validates the round
    /// polynomial: `p(0) + p(1)` must equal the current claim, and after
    /// binding the variable to `alpha` the folded polynomial's total sum must
    /// equal `p(alpha)`.  If the three-point interpolation or the 1/2
    /// evaluation were wrong, the second half of this fails even though the
    /// first half passes.
    #[test]
    fn hadamard_round_poly_satisfies_the_sumcheck_invariant() {
        use crate::shard_level::sumcheck_poly::{SumcheckPoly, SumcheckPolyFirstRound};

        let mut rng = StdRng::seed_from_u64(0x5C0DE);
        for nv in [3u32, 4, 6] {
            let n = 1usize << nv;
            let bvals: Vec<InnerVal> =
                (0..n).map(|_| InnerVal::from_u32(rng.gen::<u32>() % 1000)).collect();
            let evals: Vec<InnerChallenge> =
                (0..n).map(|_| InnerChallenge::from_u32(rng.gen::<u32>() % 1000)).collect();

            let base = LongMle::from_components(vec![Mle::from_values(bvals.clone())], nv);
            let ext = LongMle::from_components(vec![Mle::from_values(evals.clone())], nv);
            let hp = HadamardProduct { base, ext };

            // Total sum of the pointwise product.
            let claim: InnerChallenge = evals
                .iter()
                .zip(bvals.iter())
                .map(|(e, b)| *e * *b)
                .fold(InnerChallenge::ZERO, |a, x| a + x);

            // p(0) + p(1) == claim  (computed WITHOUT the claim shortcut).
            let p = hp.sum_as_poly_in_last_t_variables(None, 1);
            let p0 = p.eval_at_point(InnerChallenge::ZERO);
            let p1 = p.eval_at_point(InnerChallenge::ONE);
            assert_eq!(p0 + p1, claim, "nv={nv}: p(0)+p(1) != claim");

            // Bind and check the folded total equals p(alpha).
            let alpha = InnerChallenge::from_u32(rng.gen::<u32>() % 1000 + 1);
            let folded = hp.fix_t_variables(alpha, 1);
            let folded_sum = folded
                .ext
                .first_component()
                .guts()
                .as_slice()
                .iter()
                .zip(folded.base.first_component().guts().as_slice().iter())
                .map(|(e, b)| *e * *b)
                .fold(InnerChallenge::ZERO, |a, x| a + x);
            assert_eq!(folded_sum, p.eval_at_point(alpha), "nv={nv}: folded sum != p(alpha)");

            // And the next round is the ext x ext case.
            let _ = SumcheckPoly::sum_as_poly_in_last_variable(&folded, Some(folded_sum));
        }
    }

    /// The builder must preserve the trace values: restacking through
    /// `interleave_multilinears_with_fixed_rate` reorders and zero-pads, so the
    /// check is that the MULTISET of non-zero cells survives and the total
    /// length is the padded power of two.
    #[test]
    fn jagged_hadamard_poly_preserves_the_trace_cells() {
        let mut rng = StdRng::seed_from_u64(0xBEEF);
        for widths in [vec![2usize, 2], vec![3, 1, 4]] {
            let lsh = 3u32;
            let comps = build(&mut rng, &widths, lsh);
            let mut want: Vec<InnerVal> = Vec::new();
            for m in &comps {
                want.extend_from_slice(m.guts().as_slice());
            }
            want.sort_by_key(|v| format!("{v}"));

            let msg: Vec<std::sync::Arc<Mle<InnerVal, CpuBackend>>> =
                comps.into_iter().map(std::sync::Arc::new).collect();
            let total: usize = want.len().next_power_of_two();
            let weights: Vec<InnerChallenge> =
                (0..total).map(|_| InnerChallenge::from_u32(rng.gen::<u32>() % 1000)).collect();

            let hp = jagged_hadamard_poly(msg, lsh, weights);

            let got_all = hp.base.first_component().guts().as_slice();
            assert_eq!(got_all.len(), total, "restacked length");
            let mut got: Vec<InnerVal> =
                got_all.iter().copied().filter(|v| *v != InnerVal::ZERO).collect();
            got.sort_by_key(|v| format!("{v}"));
            let mut want_nz: Vec<InnerVal> =
                want.into_iter().filter(|v| *v != InnerVal::ZERO).collect();
            want_nz.sort_by_key(|v| format!("{v}"));
            assert_eq!(got, want_nz, "widths={widths:?}: trace cells not preserved");
        }
    }

    /// The reduction must satisfy the sumcheck contract end to end:
    ///   * round 0's `p(0) + p(1)` equals the claim `sum q*w`, and
    ///   * the final `q_at_z` equals the trace polynomial evaluated at the
    ///     recorded `eval_point`.
    /// The second is the one that pins the binding order: with `push` vs
    /// `insert(0, ..)` reversed, the point no longer addresses the variable the
    /// fold actually bound and this fails.
    #[test]
    fn hadamard_reduction_satisfies_the_sumcheck_contract() {
        use crate::kb31_poseidon2::{InnerChallenger, InnerPerm};

        let mut rng = StdRng::seed_from_u64(0xD09E);
        for widths in [vec![2usize, 2], vec![4, 4]] {
            let lsh = 3u32;
            let comps = build(&mut rng, &widths, lsh);
            let total: usize = comps.iter().map(|m| m.num_polynomials() << m.num_variables()).sum();
            assert!(total.is_power_of_two());

            let weights: Vec<InnerChallenge> =
                (0..total).map(|_| InnerChallenge::from_u32(rng.gen::<u32>() % 1000)).collect();

            let msg: Vec<std::sync::Arc<Mle<InnerVal, CpuBackend>>> =
                comps.into_iter().map(std::sync::Arc::new).collect();

            // Claim = sum over the restacked layout of base*ext.
            let hp = jagged_hadamard_poly(msg.clone(), lsh, weights.clone());
            let claim: InnerChallenge = hp
                .ext
                .first_component()
                .guts()
                .as_slice()
                .iter()
                .zip(hp.base.first_component().guts().as_slice().iter())
                .map(|(e, b)| *e * *b)
                .fold(InnerChallenge::ZERO, |a, x| a + x);

            let perm: InnerPerm = zkm_primitives::poseidon2_init();
            let mut ch = InnerChallenger::new(perm);
            let proof = prove_jagged_reduction_hadamard(msg, lsh, weights, &mut ch);

            // Round 0 opens on the claim.
            let [p0, p1, _] = proof.rounds[0].evals;
            assert_eq!(p0 + p1, claim, "widths={widths:?}: round 0 does not open on the claim");

            // Final base value == trace poly at the recorded point.
            let base_full = LongMle::from_components(
                vec![Mle::from_values(hp.base.first_component().guts().as_slice().to_vec())],
                hp.base.num_variables(),
            );
            let want = base_full.eval_at(&proof.eval_point);
            assert_eq!(
                InnerChallenge::from(proof.q_at_z),
                want,
                "widths={widths:?}: q_at_z != base(eval_point) — binding order/point order disagree",
            );
        }
    }

    /// Full prover -> verifier round trip for the LSB convention, replaying the
    /// verifier's side of `verify_jagged_reduction` inline: same transcript
    /// order (observe the round poly, check `p(0)+p(1) == claim`, sample), and
    /// the recorded point checked in SAMPLE order rather than the reversed
    /// order the MSB convention uses.
    ///
    /// This is the evidence that the Option-B switch is self-consistent before
    /// any call site or the recursion mirror moves.
    #[test]
    fn hadamard_reduction_round_trips_against_a_replayed_verifier() {
        use crate::jagged_sumcheck::observe_round_poly_evals;
        use crate::kb31_poseidon2::{InnerChallenger, InnerPerm};
        use p3_challenger::FieldChallenger;

        let mut rng = StdRng::seed_from_u64(0xA0FF);
        let lsh = 3u32;
        let comps = build(&mut rng, &[4usize, 4], lsh);
        let total: usize = comps.iter().map(|m| m.num_polynomials() << m.num_variables()).sum();
        let weights: Vec<InnerChallenge> =
            (0..total).map(|_| InnerChallenge::from_u32(rng.gen::<u32>() % 1000)).collect();
        let msg: Vec<std::sync::Arc<Mle<InnerVal, CpuBackend>>> =
            comps.into_iter().map(std::sync::Arc::new).collect();

        let hp = jagged_hadamard_poly(msg.clone(), lsh, weights.clone());
        let claim: InnerChallenge = hp
            .ext
            .first_component()
            .guts()
            .as_slice()
            .iter()
            .zip(hp.base.first_component().guts().as_slice().iter())
            .map(|(e, b)| *e * *b)
            .fold(InnerChallenge::ZERO, |a, x| a + x);

        let perm: InnerPerm = zkm_primitives::poseidon2_init();
        let mut pch = InnerChallenger::new(perm.clone());
        let proof = prove_jagged_reduction_hadamard(msg, lsh, weights, &mut pch);

        // ── verifier replay ──
        let mut vch = InnerChallenger::new(perm);
        let mut current = claim;
        let mut sampled: Vec<InnerChallenge> = Vec::new();
        for (i, round) in proof.rounds.iter().enumerate() {
            let [p0, p1, p2] = round.evals;
            observe_round_poly_evals(&mut vch, [p0, p1, p2]);
            assert_eq!(p0 + p1, current, "round {i}: sumcheck identity failed");
            let r: InnerChallenge = vch.sample_algebra_element();
            sampled.push(r);
            // p(r) via Lagrange on {0,1,2}, the same closed form the verifier uses.
            let two_inv = InnerChallenge::from_u8(2).inverse();
            let l0 = (r - InnerChallenge::ONE) * (r - InnerChallenge::from_u8(2)) * two_inv;
            let l1 = r * (r - InnerChallenge::from_u8(2)) * (-InnerChallenge::ONE);
            let l2 = r * (r - InnerChallenge::ONE) * two_inv;
            current = p0 * l0 + p1 * l1 + p2 * l2;
        }

        // SAMPLE order, not reversed — this is the Option-B delta.
        assert_eq!(sampled, proof.eval_point, "recorded point is not in sample order");

        // Closing identity: q_at_z * w_at_z == final claim.
        let w_full = LongMle::from_components(
            vec![Mle::from_values(hp.ext.first_component().guts().as_slice().to_vec())],
            hp.ext.num_variables(),
        );
        let w_at_z = w_full.eval_at(&proof.eval_point);
        assert_eq!(
            InnerChallenge::from(proof.q_at_z) * w_at_z,
            current,
            "closing identity q(z*)*w(z*) != final claim",
        );
    }

    /// ★ THE RECONCILIATION, pinned.
    ///
    /// `interleave_multilinears_with_fixed_rate` (SP1's restacking) and
    /// `materialize_dense_jagged` produce the IDENTICAL layout — provided the
    /// dense is built in NATURAL row order (`use_rev = true`).  The only thing
    /// that ever separated them is Ziren's LEGACY BIT-REVERSED row order, which
    /// `use_rev = false` applies and which SP1 has no equivalent of:
    ///
    ///     dense(rev=false) = [594,  74, 102, 552, 710, 606,  84, 68, ..]
    ///     dense(rev=true)  = [594, 710, 102,  84,  74, 606, 552, 68, ..]
    ///     interleaved      = [594, 710, 102,  84,  74, 606, 552, 68, ..]
    ///
    /// This matters because the weight side is never materialized alongside the
    /// base: `full_jagged_evaluation` derives `w(z*)` in closed form from the
    /// jagged packing geometry.  Under natural order the interleaved base
    /// addresses exactly the cells that closed form assumes, so
    /// `HadamardProduct` can be wired into the reduction on the CORE path
    /// (`core_rev() == true`) with no layout work at all.  The recursion /
    /// shrink / wrap stages still commit under the legacy bitrev and are what
    /// the authorised VK regen has to move.
    #[test]
    fn interleaved_layout_equals_natural_order_dense_layout() {
        use crate::multilinear::PaddedMle;

        let mut rng = StdRng::seed_from_u64(0x1A70);
        for widths in [vec![2usize, 2], vec![4, 4]] {
            let lsh = 3u32;
            let comps = build(&mut rng, &widths, lsh);

            let named: Vec<(String, PaddedMle<InnerVal>)> = comps
                .iter()
                .enumerate()
                .map(|(i, m)| {
                    (
                        format!("chip{i}"),
                        PaddedMle::padded_with_zeros(std::sync::Arc::new(m.clone()), lsh),
                    )
                })
                .collect();
            let packing = crate::jagged::compute_jagged_metadata(&named);
            let natural = crate::jagged::materialize_dense_jagged::<InnerVal>(
                &named,
                packing.dense_len,
                true,
            );
            let legacy = crate::jagged::materialize_dense_jagged::<InnerVal>(
                &named,
                packing.dense_len,
                false,
            );

            let msg: Vec<std::sync::Arc<Mle<InnerVal, CpuBackend>>> =
                comps.into_iter().map(std::sync::Arc::new).collect();
            let hp = jagged_hadamard_poly(msg, lsh, vec![InnerChallenge::ZERO; natural.len()]);
            let inter = hp.base.first_component().guts().as_slice();

            assert_eq!(
                &natural[..],
                inter,
                "widths={widths:?}: interleaved base must equal the NATURAL-order dense layout",
            );
            assert_ne!(
                &legacy[..],
                inter,
                "widths={widths:?}: legacy bitrev is the one real difference — if this stops \
                 holding the orientation flag has changed meaning",
            );
        }
    }

    /// A non-power-of-two total must be REJECTED, not silently truncated by
    /// floor-`ilog2` (SP1 `long.rs:95` has no guard; this is the ported check).
    #[test]
    #[should_panic(expected = "stack exactly into a power of two")]
    fn non_power_of_two_total_is_rejected() {
        let mut rng = StdRng::seed_from_u64(7);
        // 3 + 2 = 5 columns over 2^3 rows => 40 values, not a power of two.
        let comps = build(&mut rng, &[3, 2], 3);
        let _ = LongMle::from_components(comps, 3).num_variables();
    }
}

impl<F> LongMle<F> {
    /// The single component, for the sumcheck path (which requires an
    /// already-restacked, one-component `LongMle`).
    #[inline]
    pub fn first_component(&self) -> &Mle<F, CpuBackend> {
        assert_eq!(
            self.components.len(),
            1,
            "HadamardProduct sumcheck needs a restacked single-component LongMle \
             (interleave first)",
        );
        &self.components[0]
    }
}

/// The pointwise product of a base-field and an extension-field multilinear —
/// SP1's jagged sumcheck polynomial (`slop/crates/jagged/src/hadamard.rs`).
///
/// Both sides must be restacked to a SINGLE component before the sumcheck runs;
/// SP1 arranges that with `interleave_multilinears_with_fixed_rate` in
/// `jagged_sumcheck_poly`.
#[derive(Clone, Debug)]
pub struct HadamardProduct<F, EF = F> {
    /// The trace side (base field on the first round).
    pub base: LongMle<F>,
    /// The jagged-weight side.
    pub ext: LongMle<EF>,
}

impl<F, EF> crate::shard_level::sumcheck_poly::SumcheckPolyBase for HadamardProduct<F, EF> {
    #[inline]
    fn num_variables(&self) -> u32 {
        self.base.num_variables()
    }
}

impl<F, EF> crate::shard_level::sumcheck_poly::ComponentPoly<EF> for HadamardProduct<F, EF>
where
    F: Field,
    EF: ExtensionField<F>,
{
    fn get_component_poly_evals(&self) -> Vec<EF> {
        let base_eval: EF = self.base.first_component().guts().as_slice()[0].into();
        let ext_eval: EF = self.ext.first_component().guts().as_slice()[0];
        vec![base_eval, ext_eval]
    }
}

/// The round polynomial, shared by the first (base x ext) and later
/// (ext x ext) rounds.
///
/// The product is multi-quadratic, so three evaluations pin it down.  Mirrors
/// SP1 `hadamard.rs:95`: evaluate at 0 and 1 over the even/odd halves of the
/// stride-1 variable, and at 1/2 via `(e0 + e1)(b0 + b1) / 4`.
fn hadamard_round_poly<F, EF>(
    base: &Mle<F, CpuBackend>,
    ext: &Mle<EF, CpuBackend>,
    claim: Option<EF>,
) -> crate::shard_level::types::UnivariatePolynomial<EF>
where
    F: Field + Sync,
    EF: ExtensionField<F> + Send + Sync,
{
    use p3_maybe_rayon::prelude::*;

    let b = base.guts().as_slice();
    let e = ext.guts().as_slice();
    debug_assert_eq!(b.len(), e.len());

    let eval_0: EF =
        e.par_iter().step_by(2).zip(b.par_iter().step_by(2)).map(|(x, y)| *x * *y).sum();

    // `claim = p(0) + p(1)` lets the odd half be skipped entirely.
    let eval_1: EF = claim.map(|c| c - eval_0).unwrap_or_else(|| {
        e.par_iter()
            .skip(1)
            .step_by(2)
            .zip(b.par_iter().skip(1).step_by(2))
            .map(|(x, y)| *x * *y)
            .sum()
    });

    let eval_half_scaled: EF = e
        .par_iter()
        .step_by(2)
        .zip(e.par_iter().skip(1).step_by(2))
        .zip(b.par_iter().step_by(2))
        .zip(b.par_iter().skip(1).step_by(2))
        .map(|(((e0, e1), b0), b1)| (*e0 + *e1) * (*b0 + *b1))
        .sum();

    let two_inv = EF::from_u16(2).inverse();
    let four_inv = EF::from_u16(4).inverse();
    crate::shard_level::zerocheck_poly::interpolate_univariate_polynomial(
        &[EF::ZERO, EF::ONE, two_inv],
        &[eval_0, eval_1, eval_half_scaled * four_inv],
    )
}

impl<EF> crate::shard_level::sumcheck_poly::SumcheckPoly<EF> for HadamardProduct<EF, EF>
where
    EF: Field + Send + Sync,
{
    fn fix_last_variable(self, alpha: EF) -> Self {
        HadamardProduct {
            base: self.base.fix_last_variable(alpha),
            ext: self.ext.fix_last_variable(alpha),
        }
    }

    fn sum_as_poly_in_last_variable(
        &self,
        claim: Option<EF>,
    ) -> crate::shard_level::types::UnivariatePolynomial<EF> {
        hadamard_round_poly(self.base.first_component(), self.ext.first_component(), claim)
    }
}

impl<F, EF> crate::shard_level::sumcheck_poly::SumcheckPolyFirstRound<EF> for HadamardProduct<F, EF>
where
    F: Field + Sync,
    EF: ExtensionField<F> + Send + Sync,
{
    /// The first round lifts the trace side F -> EF, so every later round is
    /// the ext x ext case.
    type NextRoundPoly = HadamardProduct<EF, EF>;

    fn fix_t_variables(self, alpha: EF, t: usize) -> Self::NextRoundPoly {
        assert_eq!(t, 1, "HadamardProduct binds one variable per round");
        HadamardProduct {
            base: self.base.fix_last_variable(alpha),
            ext: self.ext.fix_last_variable(alpha),
        }
    }

    fn sum_as_poly_in_last_t_variables(
        &self,
        claim: Option<EF>,
        t: usize,
    ) -> crate::shard_level::types::UnivariatePolynomial<EF> {
        assert_eq!(t, 1, "HadamardProduct binds one variable per round");
        hadamard_round_poly(self.base.first_component(), self.ext.first_component(), claim)
    }
}

/// Build the jagged sumcheck polynomial from the per-chip trace MLEs and the
/// jagged weight table — Ziren's counterpart of SP1's `jagged_sumcheck_poly`
/// (`slop/crates/jagged/src/sumcheck.rs:13`).
///
/// `base` is the trace side: the per-chip component MLEs restacked into the
/// single component the sumcheck requires, via
/// [`crate::basefold::stacked::interleave_multilinears_with_fixed_rate`] — the
/// same helper SP1 uses, already ported and (measured: zero calls on the GPU
/// prove path) currently never exercised there.
///
/// `ext` is the weight side.  SP1's `partial_jagged_multilinear`
/// (`populate.rs`) is just `partial_jagged_little_polynomial_evaluation`
/// wrapped in a one-component `LongMle`, and Ziren's `build_weight_table`
/// already documents itself as mirroring that same function — so the weights
/// are wrapped here rather than recomputed.
///
/// NOTE this does not yet replace `prove_jagged_reduction_owned`: that swap
/// also has to reconcile the binding order (Ziren's jagged reduction folds
/// MSB-first, `LongMle` folds LSB) which is what moves the proof format.
pub fn jagged_hadamard_poly(
    trace_components: Message<Mle<crate::InnerVal, CpuBackend>>,
    log_stacking_height: u32,
    weights: alloc::vec::Vec<crate::InnerChallenge>,
) -> HadamardProduct<crate::InnerVal, crate::InnerChallenge> {
    assert!(
        weights.len().is_power_of_two(),
        "jagged weight table must be a power of two, got {}",
        weights.len(),
    );
    let total_num_variables = LongMle::from_message(trace_components.clone(), log_stacking_height)
        .total_values()
        .next_power_of_two()
        .ilog2();
    let restacked = crate::basefold::stacked::interleave_multilinears_with_fixed_rate(
        1,
        trace_components,
        total_num_variables,
    );
    HadamardProduct {
        base: LongMle::from_message(restacked, total_num_variables),
        ext: LongMle::from_components(
            alloc::vec![Mle::from_values(weights.clone())],
            weights.len().ilog2(),
        ),
    }
}

/// The jagged reduction sumcheck run on [`HadamardProduct`] — SP1's structure,
/// with NO dense materialization.
///
/// Differences from [`crate::jagged_sumcheck::prove_jagged_reduction_owned`],
/// which this is intended to replace:
///
///   * Takes the per-chip trace MLEs, not a flat `dense_q`.  The
///     `2^log_dense_size` base-field buffer — built twice per shard, once for
///     the commit and again inside the reduce closure — is never allocated.
///   * Binds the stride-1 (LSB) variable per round, as SP1 does, instead of the
///     MSB pairing `(i, i+half)`.  The recorded `eval_point` is therefore in
///     sample order (`push`), not reverse order (`insert(0, ..)`).
///
/// The wire shape is unchanged: `JaggedReductionRound` still carries the round
/// polynomial as its evaluations at {0, 1, 2}, and the challenger still observes
/// the coefficients — so only the VALUES move, driven by the binding order.
pub fn prove_jagged_reduction_hadamard<C>(
    trace_components: Message<Mle<crate::InnerVal, CpuBackend>>,
    log_stacking_height: u32,
    weights: alloc::vec::Vec<crate::InnerChallenge>,
    challenger: &mut C,
) -> crate::jagged_sumcheck::JaggedReductionProof<crate::InnerChallenge>
where
    C: p3_challenger::FieldChallenger<crate::InnerVal>,
{
    let hp = jagged_hadamard_poly(trace_components, log_stacking_height, weights);
    prove_jagged_reduction_hadamard_poly(hp, challenger)
}

/// The reduction over an already-built [`HadamardProduct`].
///
/// The jagged dense area is a PREFIX of the commitment's interleaved stripes
/// (the stripes also carry the stacking padding), so a caller holding the
/// committed stripes must extract that prefix first — it cannot hand the
/// stripes over directly.
pub fn prove_jagged_reduction_hadamard_poly<C>(
    hp: HadamardProduct<crate::InnerVal, crate::InnerChallenge>,
    challenger: &mut C,
) -> crate::jagged_sumcheck::JaggedReductionProof<crate::InnerChallenge>
where
    C: p3_challenger::FieldChallenger<crate::InnerVal>,
{
    use crate::jagged_sumcheck::{JaggedReductionProof, JaggedReductionRound};
    use crate::shard_level::sumcheck_poly::{SumcheckPoly, SumcheckPolyFirstRound};
    let n = <HadamardProduct<crate::InnerVal, crate::InnerChallenge> as
        crate::shard_level::sumcheck_poly::SumcheckPolyBase>::num_variables(&hp);

    let mut rounds: alloc::vec::Vec<JaggedReductionRound<crate::InnerChallenge>> =
        alloc::vec::Vec::with_capacity(n as usize);
    let mut eval_point: alloc::vec::Vec<crate::InnerChallenge> =
        alloc::vec::Vec::with_capacity(n as usize);

    // Round 0 lifts the trace side F -> EF.
    let poly = hp.sum_as_poly_in_last_t_variables(None, 1);
    let evals = round_evals_at_012(&poly);
    crate::jagged_sumcheck::observe_round_poly_evals(challenger, evals);
    let r0: crate::InnerChallenge = challenger.sample_algebra_element();
    eval_point.push(r0);
    rounds.push(JaggedReductionRound { evals });
    let mut claim = poly.eval_at_point(r0);
    let mut cur = hp.fix_t_variables(r0, 1);

    for _ in 1..n {
        let poly = cur.sum_as_poly_in_last_variable(Some(claim));
        let evals = round_evals_at_012(&poly);
        crate::jagged_sumcheck::observe_round_poly_evals(challenger, evals);
        let r: crate::InnerChallenge = challenger.sample_algebra_element();
        eval_point.push(r);
        rounds.push(JaggedReductionRound { evals });
        claim = poly.eval_at_point(r);
        cur = SumcheckPoly::fix_last_variable(cur, r);
    }

    let q_at_z = cur.base.first_component().guts().as_slice()[0];
    JaggedReductionProof { rounds, eval_point, q_at_z }
}

/// The round polynomial's evaluations at {0, 1, 2} — the wire form
/// `JaggedReductionRound` carries.
fn round_evals_at_012(
    poly: &crate::shard_level::types::UnivariatePolynomial<crate::InnerChallenge>,
) -> [crate::InnerChallenge; 3] {
    use p3_field::PrimeCharacteristicRing;
    [
        poly.eval_at_point(crate::InnerChallenge::ZERO),
        poly.eval_at_point(crate::InnerChallenge::ONE),
        poly.eval_at_point(crate::InnerChallenge::from_u8(2)),
    ]
}
