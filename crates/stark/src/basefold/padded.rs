//! `PaddedMle` — a multilinear polynomial with a logical
//! `num_variables` shape but only `num_real_entries` cells materialized.
//!
//! Source-mapped from
//! [`/tmp/sp1/slop/crates/multilinear/src/padded.rs`](file:///tmp/sp1/slop/crates/multilinear/src/padded.rs).
//!
//! ## Why
//!
//! In LogUp-GKR a layer's row dimension is fixed at
//! `2^num_row_variables = max(chip heights, padded up)`, but most chips
//! have real heights far below that bound.  Materializing the
//! identity-fraction padding (`(0, 1)` rows) inflates per-chip storage
//! by `2^num_row_variables / real_height`.  Production reth shards
//! observe ≥ 30 % of total chip-MLE bytes spent on padding alone.
//!
//! `PaddedMle` carries the inner real-only `Mle<F>` plus a `Padding<F>`
//! tag, and answers `eval_at` / `fix_last_variable` analytically over
//! the padding region — no zero/one cells ever land in the inner data
//! array.
//!
//! ## Differences from SP1
//!
//! Ziren's `Mle<F>` is CPU-only (`RowMajorMatrix<F>` storage), so the
//! `A: Backend` parameter is dropped.  Only the two padding shapes
//! actually used by Ziren's row-only LogUp-GKR backend are ported:
//!
//! | SP1 variant            | Ziren equivalent          |
//! |------------------------|---------------------------|
//! | `Padding::Constant`    | `Padding::Constant(F)`    |
//! | `Padding::Generic`     | (omitted — unused)        |
//!
//! `ZeroPadding` is `Padding::Constant(F::ZERO)`.
//!
//! ## API surface
//!
//! Just enough for the row-binding rounds of
//! `crate::shard_level::row_gkr::round::ChipLayerState`:
//!   * [`PaddedMle::new`] — wrap a real-only data buffer with a logical
//!     padded shape.
//!   * [`PaddedMle::num_real_rows`] / [`PaddedMle::num_padded_rows`].
//!   * [`PaddedMle::fold_row_msb`] — fold along the MSB row variable
//!     against `alpha`, returning a smaller `PaddedMle` whose padding
//!     tag is preserved.
//!
//! No `eval_at` is needed here — the GKR round already projects to
//! 1-row-per-chip via the per-round folds, after which the standard
//! `Mle::eval_at` (or analytic identity-fraction handling) applies.

use alloc::vec::Vec;

use p3_field::Field;

/// Padding shape for [`PaddedMle`].  Only the constant variant is
/// ported (Ziren's row-only LogUp-GKR doesn't use SP1's
/// `Padding::Generic`).
///
/// `Padding::Constant(c)` means "all virtual rows beyond the real
/// region carry the value `c`".  For LogUp-GKR:
///   * numerators (`n0`, `n1`) use `c = F::ZERO` (multiplicative
///     identity for addition; `eq · (0 · *) = 0`).
///   * denominators (`d0`, `d1`) use `c = F::ONE` (multiplicative
///     identity for the fraction-product).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Padding<F> {
    Constant(F),
}

impl<F: Field> Padding<F> {
    /// Convenience: `Padding::Constant(F::ZERO)`.
    #[inline]
    #[must_use]
    pub fn zero() -> Self {
        Padding::Constant(F::ZERO)
    }

    /// Convenience: `Padding::Constant(F::ONE)`.
    #[inline]
    #[must_use]
    pub fn one() -> Self {
        Padding::Constant(F::ONE)
    }

    /// Underlying scalar value.
    #[inline]
    #[must_use]
    pub fn value(&self) -> F {
        match self {
            Padding::Constant(v) => *v,
        }
    }
}

/// A multilinear-polynomial-shaped buffer with `num_real_rows`
/// materialized cells (each row is a length-`num_cols` slice) and a
/// logical "virtual" size of `num_padded_rows` rows.  Rows in
/// `[num_real_rows, num_padded_rows)` carry the constant
/// `padding.value()` repeated across all `num_cols` slots.
///
/// Storage: `cells.len() == num_real_rows * num_cols`.  When
/// `num_real_rows == num_padded_rows` the table is "fully real" and
/// behaves identically to a plain row-major buffer.
///
/// This wrapper is intentionally minimal — it only exposes the row-
/// MSB fold needed by `ChipLayerState` in
/// `crate::shard_level::row_gkr::round`.  Other operations (eval_at,
/// fix_first_variable, ...) are handled by the caller using the
/// `padding` tag plus `num_real_rows` directly.
#[derive(Clone, Debug)]
pub struct PaddedMle<F> {
    /// Materialized cells in row-major order:
    /// `cells[row * num_cols + col]` for `row < num_real_rows`.
    pub cells: Vec<F>,
    /// Number of real (materialized) rows.  Always `<= num_padded_rows`.
    pub num_real_rows: usize,
    /// Number of logical / virtual rows after padding (always a power
    /// of two for sumcheck purposes).
    pub num_padded_rows: usize,
    /// Per-row width (= number of polynomials in the batch).
    pub num_cols: usize,
    /// Constant value to use for any row in `[num_real_rows, num_padded_rows)`.
    pub padding: Padding<F>,
}

impl<F: Field> PaddedMle<F> {
    /// Wrap an already-allocated real-only `cells` buffer.  Caller is
    /// responsible for ensuring `cells.len() == num_real_rows * num_cols`
    /// and `num_real_rows <= num_padded_rows`.
    #[inline]
    #[must_use]
    pub fn new(
        cells: Vec<F>,
        num_real_rows: usize,
        num_padded_rows: usize,
        num_cols: usize,
        padding: Padding<F>,
    ) -> Self {
        debug_assert!(num_real_rows <= num_padded_rows);
        debug_assert!(
            num_cols == 0 || cells.len() == num_real_rows * num_cols,
            "PaddedMle::new: cells.len() {} != num_real_rows {} * num_cols {}",
            cells.len(),
            num_real_rows,
            num_cols,
        );
        debug_assert!(
            num_padded_rows == 0 || num_padded_rows.is_power_of_two(),
            "PaddedMle::new: num_padded_rows {} must be a power of two",
            num_padded_rows,
        );
        Self { cells, num_real_rows, num_padded_rows, num_cols, padding }
    }

    /// Construct a fully-padded ("dummy") MLE — no real cells, every
    /// virtual row is the padding constant.  Useful when a chip has no
    /// real rows but still participates in the layer.
    #[inline]
    #[must_use]
    pub fn dummy(num_padded_rows: usize, num_cols: usize, padding: Padding<F>) -> Self {
        Self::new(Vec::new(), 0, num_padded_rows, num_cols, padding)
    }

    /// Read row `row, col`, returning the materialized cell when
    /// `row < num_real_rows` and the padding constant otherwise.
    #[inline]
    #[must_use]
    pub fn get(&self, row: usize, col: usize) -> F {
        debug_assert!(row < self.num_padded_rows);
        debug_assert!(col < self.num_cols);
        if row < self.num_real_rows {
            self.cells[row * self.num_cols + col]
        } else {
            self.padding.value()
        }
    }

    /// Number of real (materialized) rows.
    #[inline]
    #[must_use]
    pub const fn num_real_rows(&self) -> usize {
        self.num_real_rows
    }

    /// Logical / virtual row count after padding.
    #[inline]
    #[must_use]
    pub const fn num_padded_rows(&self) -> usize {
        self.num_padded_rows
    }

    /// Per-row width (number of cols / batch dim).
    #[inline]
    #[must_use]
    pub const fn num_cols(&self) -> usize {
        self.num_cols
    }

    /// Padding tag.
    #[inline]
    #[must_use]
    pub const fn padding(&self) -> Padding<F> {
        self.padding
    }

    /// True if the entire MLE is padding (no real rows).
    #[inline]
    #[must_use]
    pub const fn is_pure_padding(&self) -> bool {
        self.num_real_rows == 0
    }

    /// True if the table is "fully real" (no virtual padding cells).
    #[inline]
    #[must_use]
    pub const fn is_fully_real(&self) -> bool {
        self.num_real_rows == self.num_padded_rows
    }

    /// Fold along the row MSB at challenge `alpha`.
    ///
    /// Pairs row `r` with row `r + half`, where `half = num_padded_rows / 2`.
    /// Returns a new [`PaddedMle`] with `num_padded_rows = half` and the
    /// same padding tag.  Only the **real-real** and **real-pad** pair
    /// outputs are materialized; **pad-pad** pairs analytically collapse
    /// to the padding constant.
    ///
    /// Per-pair output: `lo + alpha * (hi - lo)`
    /// where `lo = self.get(r, *)`, `hi = self.get(r + half, *)`.
    ///
    /// New `num_real_rows`:
    ///   * if `num_real_rows >= half`: pad cells start at row `half`,
    ///     so every output row `r ∈ [0, half)` involves at least one
    ///     real input — `new_num_real_rows = half` (the MLE becomes
    ///     fully real along the row axis at this stage).
    ///   * if `num_real_rows < half`: only outputs `r ∈ [0, num_real_rows)`
    ///     pull from real input cells.  Outputs `r ∈ [num_real_rows, half)`
    ///     are pad-pad and analytically equal the padding constant.
    ///     `new_num_real_rows = num_real_rows`.
    ///
    /// (Identical to SP1's `mle_fix_last_variable_constant_padding`
    /// when interpreted on the chip's per-chip block.)
    #[must_use]
    pub fn fold_row_msb(&self, alpha: F) -> Self {
        debug_assert!(self.num_padded_rows >= 2, "fold_row_msb needs >= 1 row variable");
        let half = self.num_padded_rows / 2;
        let cols = self.num_cols;
        let pad = self.padding.value();

        // Branchless cases, written as analytically-distinct paths to
        // make the per-cell hot loop simpler (no per-cell `is_real`
        // check).  The new num_real_rows is determined ahead of time.
        if self.num_real_rows == 0 {
            // Every input row is pad; every output row is pad too.
            // Output: pad + alpha * (pad - pad) = pad.  Carry the
            // padding tag forward unchanged with empty inner cells.
            return Self::new(Vec::new(), 0, half, cols, self.padding);
        }

        if self.num_real_rows >= half {
            // Lower half is fully real; upper half is real for
            // r ∈ [half, num_real_rows) and pad for r ∈ [num_real_rows, num_padded).
            // Every output index r ∈ [0, half) reads at least one real
            // cell, so new_num_real_rows = half (MLE becomes fully real).
            let upper_real = self.num_real_rows.saturating_sub(half);
            let mut out: Vec<F> = vec![F::ZERO; half * cols];
            // First chunk: r ∈ [0, upper_real) — both halves real.
            for r in 0..upper_real {
                let lo_base = r * cols;
                let hi_base = (r + half) * cols;
                let dst_base = r * cols;
                for c in 0..cols {
                    let lo = self.cells[lo_base + c];
                    let hi = self.cells[hi_base + c];
                    out[dst_base + c] = lo + alpha * (hi - lo);
                }
            }
            // Second chunk: r ∈ [upper_real, half) — lo real, hi pad.
            for r in upper_real..half {
                let lo_base = r * cols;
                let dst_base = r * cols;
                for c in 0..cols {
                    let lo = self.cells[lo_base + c];
                    out[dst_base + c] = lo + alpha * (pad - lo);
                }
            }
            return Self::new(out, half, half, cols, self.padding);
        }

        // num_real_rows ∈ (0, half): only the lower half has any real
        // cells — upper half (rows ≥ half) is entirely pad.  Output
        // r ∈ [0, num_real_rows) reads (real lo, pad hi).  Output
        // r ∈ [num_real_rows, half) reads (pad, pad) → pad.  We
        // materialize ONLY the real-real / real-pad outputs (rows
        // [0, num_real_rows)); the rest stays virtual via the padding
        // tag.
        let new_real = self.num_real_rows;
        let mut out: Vec<F> = vec![F::ZERO; new_real * cols];
        for r in 0..new_real {
            let lo_base = r * cols;
            let dst_base = r * cols;
            for c in 0..cols {
                let lo = self.cells[lo_base + c];
                out[dst_base + c] = lo + alpha * (pad - lo);
            }
        }
        Self::new(out, new_real, half, cols, self.padding)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Challenge;
    use p3_field::PrimeCharacteristicRing;

    type SC = crate::koala_bear_poseidon2::KoalaBearPoseidon2;
    type EF = Challenge<SC>;

    /// Build a "ground truth" length-`2^k` virtual table by reading every
    /// virtual row from the PaddedMle (real cells + padding constant).
    fn materialize<F: Field>(p: &PaddedMle<F>) -> Vec<F> {
        let mut out = vec![F::ZERO; p.num_padded_rows * p.num_cols];
        for r in 0..p.num_padded_rows {
            for c in 0..p.num_cols {
                out[r * p.num_cols + c] = p.get(r, c);
            }
        }
        out
    }

    /// Reference fold: take a fully-materialized table and apply the
    /// LSB-pair fold `lo + alpha * (hi - lo)` for the highest variable
    /// (= MSB pairing `(r, r + half)`).  Returns the post-fold buffer.
    fn fold_reference<F: Field>(values: &[F], num_cols: usize, alpha: F) -> Vec<F> {
        let n = values.len() / num_cols;
        debug_assert!(n.is_power_of_two() && n >= 2);
        let half = n / 2;
        let mut out = vec![F::ZERO; half * num_cols];
        for r in 0..half {
            for c in 0..num_cols {
                let lo = values[r * num_cols + c];
                let hi = values[(r + half) * num_cols + c];
                out[r * num_cols + c] = lo + alpha * (hi - lo);
            }
        }
        out
    }

    #[test]
    fn padded_mle_get_returns_padding_for_virtual_rows() {
        // 2 real rows × 3 cols, padded to 4 logical rows with constant 7.
        let cells: Vec<EF> = (1u32..=6).map(EF::from_u32).collect();
        let p = PaddedMle::new(cells.clone(), 2, 4, 3, Padding::Constant(EF::from_u32(7)));
        assert_eq!(p.num_real_rows(), 2);
        assert_eq!(p.num_padded_rows(), 4);
        for r in 0..2 {
            for c in 0..3 {
                assert_eq!(p.get(r, c), cells[r * 3 + c]);
            }
        }
        for r in 2..4 {
            for c in 0..3 {
                assert_eq!(p.get(r, c), EF::from_u32(7));
            }
        }
    }

    #[test]
    fn fold_row_msb_matches_materialized_fold_when_real_geq_half() {
        // 4 real rows out of 4 padded — fully real.
        let cells: Vec<EF> = (1u32..=8).map(EF::from_u32).collect();
        let p = PaddedMle::new(cells, 4, 4, 2, Padding::Constant(EF::ONE));
        let alpha = EF::from_u32(13);

        let folded = p.fold_row_msb(alpha);
        let expected = fold_reference(&materialize(&p), 2, alpha);

        assert_eq!(folded.num_padded_rows(), 2);
        assert_eq!(folded.num_real_rows(), 2);
        for r in 0..2 {
            for c in 0..2 {
                assert_eq!(folded.get(r, c), expected[r * 2 + c]);
            }
        }
    }

    #[test]
    fn fold_row_msb_matches_materialized_fold_when_real_lt_half() {
        // 1 real row out of 4 padded — pad constant 5, num_cols=2.
        let cells: Vec<EF> = vec![EF::from_u32(11), EF::from_u32(22)];
        let p = PaddedMle::new(cells, 1, 4, 2, Padding::Constant(EF::from_u32(5)));
        let alpha = EF::from_u32(7);

        let folded = p.fold_row_msb(alpha);
        let expected = fold_reference(&materialize(&p), 2, alpha);

        assert_eq!(folded.num_padded_rows(), 2);
        // Output r=0 is real (lo real, hi pad); r=1 is pad-pad → pad.
        assert_eq!(folded.num_real_rows(), 1);
        for r in 0..2 {
            for c in 0..2 {
                assert_eq!(folded.get(r, c), expected[r * 2 + c]);
            }
        }
    }

    #[test]
    fn fold_row_msb_matches_materialized_fold_when_real_eq_half() {
        // 2 real rows out of 4 padded — boundary case.
        let cells: Vec<EF> = (1u32..=4).map(EF::from_u32).collect();
        let p = PaddedMle::new(cells, 2, 4, 2, Padding::Constant(EF::from_u32(9)));
        let alpha = EF::from_u32(3);

        let folded = p.fold_row_msb(alpha);
        let expected = fold_reference(&materialize(&p), 2, alpha);

        assert_eq!(folded.num_padded_rows(), 2);
        // Lower half real, upper half pad → both outputs read (real, pad).
        assert_eq!(folded.num_real_rows(), 2);
        for r in 0..2 {
            for c in 0..2 {
                assert_eq!(folded.get(r, c), expected[r * 2 + c]);
            }
        }
    }

    #[test]
    fn fold_row_msb_pure_padding_stays_pure_padding() {
        let p = PaddedMle::<EF>::dummy(8, 3, Padding::Constant(EF::from_u32(42)));
        let folded = p.fold_row_msb(EF::from_u32(13));
        assert_eq!(folded.num_padded_rows(), 4);
        assert_eq!(folded.num_real_rows(), 0);
        assert!(folded.is_pure_padding());
        for r in 0..4 {
            for c in 0..3 {
                assert_eq!(folded.get(r, c), EF::from_u32(42));
            }
        }
    }

    #[test]
    fn full_fold_collapse_to_single_value() {
        // 1 real row, 4 padded rows, 1 col, pad = 1, real cell = 5,
        // alpha[0] = 7, alpha[1] = 11.
        // Materialized: [5, 1, 1, 1].
        // After fold(7) — pairs (0,2)+(1,3): lo=[5, 1], hi=[1, 1] → [5+7(1-5), 1+7(1-1)] = [5-28, 1] = [-23, 1].
        // After fold(11) — pair (0,1): lo=-23, hi=1 → -23 + 11*(1-(-23)) = -23 + 11*24 = -23 + 264 = 241.
        let cells = vec![EF::from_u32(5)];
        let p = PaddedMle::new(cells, 1, 4, 1, Padding::Constant(EF::ONE));
        let folded1 = p.fold_row_msb(EF::from_u32(7));
        // After 1 round: num_padded=2, num_real=1 (real-pad output for r=0; pad-pad output for r=1).
        assert_eq!(folded1.num_padded_rows(), 2);
        assert_eq!(folded1.num_real_rows(), 1);
        let folded2 = folded1.fold_row_msb(EF::from_u32(11));
        // After 2 rounds: num_padded=1, num_real=1 (lo real, hi pad).
        assert_eq!(folded2.num_padded_rows(), 1);
        assert_eq!(folded2.num_real_rows(), 1);
        let expected = EF::from_u32(241);
        assert_eq!(folded2.get(0, 0), expected);
    }
}
