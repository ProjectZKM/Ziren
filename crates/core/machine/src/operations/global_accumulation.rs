use crate::operations::GlobalLookupOperation;
use p3_air::AirBuilder;
use p3_field::Field;
use p3_field::PrimeCharacteristicRing;
use p3_field::PrimeField32;
use zkm_derive::AlignedBorrow;
use zkm_pcs::air::SepticExtensionAirBuilder;
use zkm_pcs::septic_curve::SepticCurveComplete;
use zkm_pcs::ZKMAirBuilder;
use zkm_pcs::{
    septic_curve::SepticCurve,
    septic_extension::{SepticBlock, SepticExtension},
};

/// A set of columns needed to compute the global lookup elliptic curve digest.
/// It is critical that this struct is at the end of the main trace, as the permutation constraints will be dependent on this fact.
/// It is also critical the cumulative sum is at the end of this struct, for the same reason.
#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct GlobalAccumulationOperation<T, const N: usize> {
    pub initial_digest: [SepticBlock<T>; 2],
    /// `(x2 - x1)^{-1}` for each accumulation step — the witness that makes the
    /// chord denominator provably nonzero (ZR-28).
    ///
    /// Placed BETWEEN `initial_digest` and `cumulative_sum` on purpose: the
    /// struct must stay at the end of the main trace with `cumulative_sum` last
    /// (the permutation constraints and the shard-digest read depend on it), and
    /// `initial_digest` must stay at `GLOBAL_INITIAL_DIGEST_POS`.
    pub denominator_inv: [SepticBlock<T>; N],
    pub cumulative_sum: [[SepticBlock<T>; 2]; N],
}

impl<T: Default, const N: usize> Default for GlobalAccumulationOperation<T, N> {
    fn default() -> Self {
        Self {
            initial_digest: core::array::from_fn(|_| SepticBlock::<T>::default()),
            denominator_inv: core::array::from_fn(|_| SepticBlock::<T>::default()),
            cumulative_sum: core::array::from_fn(|_| {
                [SepticBlock::<T>::default(), SepticBlock::<T>::default()]
            }),
        }
    }
}

impl<F: PrimeField32, const N: usize> GlobalAccumulationOperation<F, N> {
    pub fn populate(
        &mut self,
        initial_digest: &mut SepticCurve<F>,
        global_lookup_cols: [GlobalLookupOperation<F>; N],
        is_real: [F; N],
    ) {
        self.initial_digest[0] = SepticBlock::from(initial_digest.x.0);
        self.initial_digest[1] = SepticBlock::from(initial_digest.y.0);

        for i in 0..N {
            let point_cur = SepticCurve {
                x: SepticExtension(global_lookup_cols[i].x_coordinate.0),
                y: SepticExtension(global_lookup_cols[i].y_coordinate.0),
            };
            assert!(is_real[i] == F::ONE || is_real[i] == F::ZERO);
            // Within a real row a padding slot (N > 1) keeps the running sum; whole
            // padding rows are laid out by `populate_dummy`.
            let sum_point = if is_real[i] == F::ONE {
                point_cur.add_incomplete(*initial_digest)
            } else {
                *initial_digest
            };
            self.cumulative_sum[i][0] = SepticBlock::from(sum_point.x.0);
            self.cumulative_sum[i][1] = SepticBlock::from(sum_point.y.0);
            *initial_digest = sum_point;
        }
    }

    /// Lay out a padding row as a GENUINE addition `final_digest = (final_digest - dummy) +
    /// dummy`: `initial_digest = final_digest - dummy`, `cumulative_sum = final_digest`, with the
    /// lookup point set to `dummy` by `GlobalLookupOperation::populate_dummy`.  This keeps the
    /// unconditional `sum_checker_x == 0` true without a witness column, and keeps the shard's
    /// digest in the LAST row's trailing 14 columns, which is where the prover reads the chip's
    /// global cumulative sum from and what `permutation.rs` pins with `when_last_row`.  Padding
    /// rows are outside the `GlobalAccumulation` bus chain (multiplicity `is_real == 0`).
    pub fn populate_dummy(&mut self, final_digest: SepticCurve<F>) {
        let dummy = SepticCurve::<F>::dummy();
        let initial = final_digest.add_incomplete(dummy.neg());
        self.initial_digest[0] = SepticBlock::from(initial.x.0);
        self.initial_digest[1] = SepticBlock::from(initial.y.0);
        // ZR-28: the padding layout is the genuine addition
        // `(final - dummy) + dummy`, so its chord denominator is
        // `dummy.x - initial.x`, and it is nonzero for the same reason the row
        // is a valid addition at all.
        let denom = dummy.x - initial.x;
        assert!(
            denom != SepticExtension::<F>::ZERO,
            "padding row: the dummy layout's chord denominator is zero, so the row is not a \
             valid addition",
        );
        let inv = denom.inverse();
        for i in 0..N {
            self.denominator_inv[i] = SepticBlock::from(inv.0);
        }
        for i in 0..N {
            self.cumulative_sum[i][0] = SepticBlock::from(final_digest.x.0);
            self.cumulative_sum[i][1] = SepticBlock::from(final_digest.y.0);
        }
    }

    /// `point_to_add_x` is the row's event point x-coordinate — the `x2` of the
    /// chord — needed for the ZR-28 denominator witness.
    pub fn populate_real(
        &mut self,
        sums: &[SepticCurveComplete<F>],
        point_to_add_x: SepticExtension<F>,
    ) {
        let len = sums.len();
        debug_assert!(len >= 2);
        let sums = sums.iter().map(|complete_point| complete_point.point()).collect::<Vec<_>>();
        self.initial_digest[0] = SepticBlock::from(sums[0].x.0);
        self.initial_digest[1] = SepticBlock::from(sums[0].y.0);
        // ZR-28: `x2 - x1` is nonzero on every honest row — the running sum can
        // equal neither the event point nor its negation (the latter would make
        // the sum the point at infinity, which the generator cannot represent
        // and panics on).  `inverse()` would panic on zero, which is the right
        // failure: a trace that reaches the exceptional case is not provable
        // rather than silently unconstrained.
        let denom = point_to_add_x - sums[0].x;
        // A named failure rather than `inverse()`'s bare division-by-zero: this
        // is the exceptional case, and it should say so.
        assert!(
            denom != SepticExtension::<F>::ZERO,
            "the running sum equals the event point, so the chord addition is exceptional \
             (x2 == x1): this trace is not provable",
        );
        let inv = denom.inverse();
        for i in 0..N {
            self.denominator_inv[i] = SepticBlock::from(inv.0);
        }
        for i in 0..N {
            let s = &sums[(i + 1).min(len - 1)];
            self.cumulative_sum[i][0] = SepticBlock::from(s.x.0);
            self.cumulative_sum[i][1] = SepticBlock::from(s.y.0);
        }
    }
}

impl<F: Field, const N: usize> GlobalAccumulationOperation<F, N> {
    pub fn eval_accumulation<AB: ZKMAirBuilder>(
        builder: &mut AB,
        global_lookup_cols: [GlobalLookupOperation<AB::Var>; N],
        local_is_real: [AB::Var; N],
        local_accumulation: GlobalAccumulationOperation<AB::Var, N>,
    ) {
        // First, constrain the control flow regarding `is_real`.
        // Constrain that all `is_real` values are boolean.
        for i in 0..N {
            builder.assert_bool(local_is_real[i]);
        }

        // Constrain that `is_real = 0` implies the next `is_real` values are all zero
        // (within-row, for N > 1).
        for i in 0..N - 1 {
            // `is_real[i] == 0` implies `is_real[i + 1] == 0`.
            builder.when_not(local_is_real[i]).assert_zero(local_is_real[i + 1]);
        }

        // Option 2: the cross-row `is_real` monotonicity is dropped — the
        // GlobalAccumulation bus does not require a contiguous real-row
        // prefix (the index chain + multiset balance handle it).

        // Next, constrain the accumulation.
        let initial_digest = SepticCurve::<AB::Expr> {
            x: SepticExtension::<AB::Expr>::from_base_fn(|i| {
                local_accumulation.initial_digest[0][i].into()
            }),
            y: SepticExtension::<AB::Expr>::from_base_fn(|i| {
                local_accumulation.initial_digest[1][i].into()
            }),
        };

        let assert_on_curve = |builder: &mut AB, point: SepticCurve<AB::Expr>| {
            builder.assert_septic_ext_eq(
                point.y.square(),
                SepticCurve::<AB::Expr>::curve_formula(point.x),
            );
        };

        let ith_cumulative_sum = |idx: usize| SepticCurve::<AB::Expr> {
            x: SepticExtension::<AB::Expr>::from_base_fn(|i| {
                local_accumulation.cumulative_sum[idx][0].0[i].into()
            }),
            y: SepticExtension::<AB::Expr>::from_base_fn(|i| {
                local_accumulation.cumulative_sum[idx][1].0[i].into()
            }),
        };

        let ith_point_to_add = |idx: usize| SepticCurve::<AB::Expr> {
            x: SepticExtension::<AB::Expr>::from_base_fn(|i| {
                global_lookup_cols[idx].x_coordinate.0[i].into()
            }),
            y: SepticExtension::<AB::Expr>::from_base_fn(|i| {
                global_lookup_cols[idx].y_coordinate.0[i].into()
            }),
        };

        // Option 2: the first-row `initial_digest == ZERO` anchor is
        // dropped — the GlobalAccumulation bus's initial endpoint
        // `(0, ZERO_DIGEST)`, emitted by the public-values AIR
        // (`eval_global_sum`) and received by row 0, enforces it.

        // Defense-in-depth: every witnessed running digest must stay on-curve even if the
        // incomplete Weierstrass addition edge case is triggered.
        assert_on_curve(builder, initial_digest.clone());

        // Constrain that when `is_real = 1`, addition is being carried out, and when `is_real = 0`, the sum remains the same.
        for i in 0..N {
            let current_sum =
                if i == 0 { initial_digest.clone() } else { ith_cumulative_sum(i - 1) };
            let point_to_add = ith_point_to_add(i);
            let next_sum = ith_cumulative_sum(i);
            assert_on_curve(builder, next_sum.clone());
            // `sum_checker_x` is degree 3 and is asserted UNCONDITIONALLY (SP1-hypercube
            // shape): padding rows are laid out as the genuine addition
            // `(final - dummy) + dummy == final` (`populate_dummy`), so no witnessed copy
            // is needed.  `sum_checker_y` is degree 2 and gated by
            // `is_real` (degree 3).  Together, on a real row, `next_sum == current_sum +
            // point_to_add` (incomplete addition, as before).
            let sum_checker_x = SepticCurve::<AB::Expr>::sum_checker_x(
                current_sum.clone(),
                point_to_add.clone(),
                next_sum.clone(),
            );
            let sum_checker_y =
                SepticCurve::<AB::Expr>::sum_checker_y(current_sum.clone(), point_to_add, next_sum);
            builder.assert_septic_ext_eq(
                sum_checker_x,
                SepticExtension::<AB::Expr>::from_base_fn(|_| AB::Expr::ZERO),
            );
            builder.when(local_is_real[i]).assert_septic_ext_eq(
                sum_checker_y,
                SepticExtension::<AB::Expr>::from_base_fn(|_| AB::Expr::ZERO),
            );

            // ZR-28: the chord denominator is NONZERO.
            //
            // Both checkers carry the factor `(x2 - x1)`:
            //
            //   Cx = (x1 + x2 + x3)(x2 - x1)^2 - (y2 - y1)^2
            //   Cy = (y1 + y3)(x2 - x1)       - (y2 - y1)(x1 - x3)
            //
            // so at `P2 == P1` both differences vanish and `Cx = Cy = 0` holds
            // for EVERY `P3` — the addition is unconstrained and the only
            // surviving restriction on the next running digest is that it is on
            // the curve.  (`P2 == -P1` is already rejected: there `Cx = -4y1^2`,
            // nonzero whenever `y1 != 0`, and `y1 == 0` collapses into
            // `P2 == P1`.)  Witnessing `(x2 - x1)^{-1}` and requiring
            //
            //   (x2 - x1) * inv = 1
            //
            // makes `x2 != x1` a constraint rather than an assumption, which is
            // what closes the doubling case.
            //
            // Degree 3: `(x2 - x1)` and `inv` are degree 1, their septic product
            // degree 2, and the `is_real` gate adds one — the same cap the
            // existing `sum_checker_x` already sits at, so the quotient degree
            // is unchanged.
            //
            // Gated by `is_real` because padding rows are laid out as
            // `(final - dummy) + dummy`, whose denominator is likewise nonzero;
            // the gate keeps a padding row that carries no meaningful inverse
            // from being rejected.
            let denominator = ith_point_to_add(i).x - current_sum.x.clone();
            let denominator_inv = SepticExtension::<AB::Expr>::from_base_fn(|j| {
                local_accumulation.denominator_inv[i].0[j].into()
            });
            builder.when(local_is_real[i]).assert_septic_ext_eq(
                denominator * denominator_inv,
                SepticExtension::<AB::Expr>::from_base_fn(|j| {
                    if j == 0 {
                        AB::Expr::ONE
                    } else {
                        AB::Expr::ZERO
                    }
                }),
            );
        }

        // Option 2: the cross-row `final_digest == next.initial_digest`
        // chain is dropped — the GlobalAccumulation bus (emitted in
        // GlobalChip::eval as receive(index, initial_digest) +
        // send(index+1, cumulative_sum[N-1])) chains consecutive rows via
        // the multiset balance, and the public-values AIR closes the chain
        // at both ends (initial (0, ZERO), final (global_count,
        // global_cumulative_sum)).
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_field::PrimeCharacteristicRing;
    use p3_koala_bear::KoalaBear;
    use zkm_pcs::septic_curve::{SepticCurve, SepticCurveComplete};
    use zkm_pcs::septic_extension::SepticExtension;

    type F = KoalaBear;

    /// A deterministic on-curve point, lifted from an x the curve accepts.
    fn point(seed: u32) -> SepticCurve<F> {
        let x: SepticExtension<F> = SepticExtension::from_base_fn(|i| F::from_u32(seed + i as u32));
        let (p, _) = SepticCurve::<F>::lift_x(x);
        assert!(p.check_on_point(), "lift_x must land on the curve");
        p
    }

    /// The witness the ZR-28 constraint checks is
    /// `is_real * ((x2 - x1) * denominator_inv - 1) == 0`, so on an honest row
    /// the populated inverse must satisfy `(x2 - x1) * inv == 1` EXACTLY.  A
    /// populate path that filled zeros (as the GPU kernel did before the device
    /// half of the fix) leaves the constraint unsatisfiable, which is how it
    /// took production down — so this asserts the witness, not just that
    /// populate returned.
    fn assert_inverse_witness(
        cols: &GlobalAccumulationOperation<F, 1>,
        x2: SepticExtension<F>,
        x1: SepticExtension<F>,
    ) {
        let inv = SepticExtension::<F>::from_base_fn(|j| cols.denominator_inv[0].0[j]);
        let denom = x2 - x1;
        assert_eq!(
            denom * inv,
            SepticExtension::<F>::ONE,
            "the populated denominator_inv does not invert the chord denominator, so the \
             ZR-28 constraint is unsatisfiable on an honest row",
        );
    }

    /// ORDINARY ADDITION (`x2 != x1`): provable, and the witness inverts the
    /// chord denominator.
    #[test]
    fn global_accumulation_ordinary_addition_is_provable() {
        let p1 = point(0x2013);
        let p2 = point(0x7777);
        assert_ne!(p1.x, p2.x, "the fixture must be a genuine addition");
        let sums = vec![
            SepticCurveComplete::Affine(p1),
            SepticCurveComplete::Affine(p1.add_incomplete(p2)),
        ];
        let mut cols = GlobalAccumulationOperation::<F, 1>::default();
        cols.populate_real(&sums, p2.x);
        assert_inverse_witness(&cols, p2.x, p1.x);
    }

    /// DOUBLING (`x2 == x1`, same point): the chord denominator vanishes, so the
    /// row is the exceptional case and the trace is NOT provable.  This is the
    /// case ZR-28 was about — before the fix the denominator was unconstrained,
    /// so a doubling could be presented as an addition with an arbitrary
    /// successor.
    #[test]
    #[should_panic(expected = "this trace is not provable")]
    fn global_accumulation_doubling_is_not_provable() {
        let p = point(0x2013);
        let sums = vec![SepticCurveComplete::Affine(p), SepticCurveComplete::Affine(p.double())];
        let mut cols = GlobalAccumulationOperation::<F, 1>::default();
        // x2 == x1: adding the running sum to itself.
        cols.populate_real(&sums, p.x);
    }

    /// INVERSE (`x2 == x1`, `y2 == -y1`): the other vanishing-denominator case.
    /// Its sum is the point at infinity, which the digest cannot represent, so
    /// it must fail for the same reason rather than produce a row.
    #[test]
    #[should_panic(expected = "this trace is not provable")]
    fn global_accumulation_inverse_pair_is_not_provable() {
        let p = point(0x2013);
        let neg = p.neg();
        assert_eq!(p.x, neg.x, "an inverse pair shares its x");
        assert_ne!(p.y, neg.y, "...and negates its y");
        let sums = vec![SepticCurveComplete::Affine(p), SepticCurveComplete::Affine(p)];
        let mut cols = GlobalAccumulationOperation::<F, 1>::default();
        cols.populate_real(&sums, neg.x);
    }

    /// PADDING / no-event rows: the dummy layout is the genuine addition
    /// `(final - dummy) + dummy`, so it must be provable too — the padding rows
    /// are the majority of the chip and a vanishing denominator there would make
    /// every shard unprovable.
    #[test]
    fn global_accumulation_padding_row_is_provable() {
        let final_digest = point(0x4242);
        let dummy = SepticCurve::<F>::dummy();
        let initial = final_digest.add_incomplete(dummy.neg());
        let mut cols = GlobalAccumulationOperation::<F, 1>::default();
        cols.populate_dummy(final_digest);
        assert_inverse_witness(&cols, dummy.x, initial.x);
    }
}
