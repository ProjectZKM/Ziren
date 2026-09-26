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
    /// chord denominator provably nonzero.
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
    /// chord — needed for the denominator witness (x2 - x1)^{-1}.
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
        let denom = point_to_add_x - sums[0].x;
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
        for i in 0..N {
            builder.assert_bool(local_is_real[i]);
        }

        for i in 0..N - 1 {
            builder.when_not(local_is_real[i]).assert_zero(local_is_real[i + 1]);
        }

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

        assert_on_curve(builder, initial_digest.clone());

        for i in 0..N {
            let current_sum =
                if i == 0 { initial_digest.clone() } else { ith_cumulative_sum(i - 1) };
            let point_to_add = ith_point_to_add(i);
            let next_sum = ith_cumulative_sum(i);
            assert_on_curve(builder, next_sum.clone());
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

    /// The constraint is `is_real · ((x2 - x1) · inv - 1) = 0`, so on an honest
    /// row the populated inverse must satisfy `(x2 - x1) · inv = 1` exactly. A
    /// populate path that leaves `inv = 0` makes every real row unsatisfiable,
    /// so this asserts the witness, not just that populate returned.
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
             constraint is_real * ((x2 - x1) * inv - 1) = 0 is unsatisfiable on an honest row",
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
    /// row is the exceptional case and the trace is not provable. With the
    /// denominator unconstrained, both chord identities vanish at `x2 = x1` and
    /// a doubling could be presented as an addition with any on-curve
    /// successor.
    #[test]
    #[should_panic(expected = "this trace is not provable")]
    fn global_accumulation_doubling_is_not_provable() {
        let p = point(0x2013);
        let sums = vec![SepticCurveComplete::Affine(p), SepticCurveComplete::Affine(p.double())];
        let mut cols = GlobalAccumulationOperation::<F, 1>::default();
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
