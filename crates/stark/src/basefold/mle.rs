//! Minimal `Mle<F>` (Multilinear Extension) wrapper used throughout
//! the Ziren basefold port.
//!
//! Source-mapped from SP1's `slop_multilinear::Mle`.  The SP1 type
//! carries a backend-generic `Tensor<F, A>`; here we use
//! `RowMajorMatrix<F>` directly because Ziren only has the CPU
//! backend.
//!
//! # Layout convention
//!
//! `guts` is a row-major matrix where:
//!   * **height** = `2^num_variables` (one row per hypercube point)
//!   * **width**  = `num_polynomials` (one column per polynomial in
//!     the batch)
//!
//! This matches SP1's storage convention and lines up with Plonky3's
//! [`TwoAdicSubgroupDft`] APIs (which DFT each column independently).

use alloc::sync::Arc;
use alloc::vec::Vec;

use p3_field::{ExtensionField, Field};
use p3_matrix::Matrix;
use p3_matrix::dense::RowMajorMatrix;

#[derive(Clone, Debug)]
pub struct Mle<F: Field> {
    pub guts: RowMajorMatrix<F>,
}

impl<F: Field> Mle<F> {
    pub const fn new(guts: RowMajorMatrix<F>) -> Self {
        Self { guts }
    }

    /// Single-polynomial constructor: `values` interpreted as the
    /// dense evaluation table on the hypercube.
    pub fn from_values(values: Vec<F>) -> Self {
        debug_assert!(values.len().is_power_of_two());
        Self { guts: RowMajorMatrix::new_col(values) }
    }

    pub fn num_polynomials(&self) -> usize {
        self.guts.width()
    }

    pub fn num_variables(&self) -> u32 {
        self.guts.height().trailing_zeros()
    }

    pub fn hypercube_size(&self) -> usize {
        self.guts.height()
    }

    pub fn guts(&self) -> &RowMajorMatrix<F> {
        &self.guts
    }

    /// Standard multilinear evaluation at an extension-field point.
    /// Folds via adjacent-pair (`v[2i], v[2i+1]`) to match
    /// [`Self::fold`] and the rest of the BaseFold module — `point[i]`
    /// substitutes for var `i` (first-var-first convention).  Note
    /// this is the *Lagrange* combination `(1-r)·lo + r·hi`, not the
    /// monomial fold used by [`Self::fold`].
    pub fn eval_at<EF: ExtensionField<F>>(&self, point: &[EF]) -> Vec<EF>
    where
        EF: Send + Sync,
        F: Sync,
    {
        debug_assert_eq!(point.len(), self.num_variables() as usize);
        let n_polys = self.num_polynomials();
        use p3_maybe_rayon::prelude::*;
        // Parallelize only the initial F → EF lift (the largest single
        // pass).  The per-round Lagrange fold remains sequential to
        // preserve in-place write semantics — earlier attempts to
        // parallelize the fold via fresh-vec allocation broke the
        // recursion-circuit's bit-exact OOD checks (root cause not
        // isolated; the algorithm here still produces the same Vec<EF>
        // but the proof bytes change in a way the verifier rejects).
        let mut current: Vec<EF> =
            self.guts.values.par_iter().map(|&v| EF::from(v)).collect();
        let mut n_rows = self.hypercube_size();
        for &r in point {
            let half = n_rows / 2;
            for i in 0..half {
                for k in 0..n_polys {
                    let lo = current[2 * i * n_polys + k];
                    let hi = current[(2 * i + 1) * n_polys + k];
                    current[i * n_polys + k] = lo + r * (hi - lo);
                }
            }
            n_rows = half;
        }
        current.truncate(n_polys);
        current
    }

    /// Basefold-style fold by `beta`: pairs adjacent rows (index `2i`
    /// and `2i+1`) into `v[2i] + beta * v[2i+1]`.  This must mirror
    /// the FRI codeword fold used in
    /// [`super::fri::fold_even_odd_ext`] — same pairing scheme, same
    /// monomial-basis reduction — so the K-round constants match
    /// (the BaseFold key invariant).
    ///
    /// Phase 4 perf fix (Apr 25 2026): parallelize the per-row pair
    /// fold. Each row pair `(2i, 2i+1)` is independent → write into
    /// separate slots of the pre-allocated output. Called per round
    /// in `commit_phase_round`; total work across rounds is ~2N
    /// elements (geometric sum).
    pub fn fold<EF: ExtensionField<F> + Send + Sync>(self, beta: EF) -> Mle<EF>
    where
        F: Sync,
    {
        let width = self.guts.width();
        let height = self.guts.height();
        debug_assert!(height >= 2);
        let half = height / 2;

        let values = self.guts.values;
        // Allocator opt: skip vec![EF::ZERO; half*width] zero-init; every
        // slot is written by the for_each closure below.
        let new_len = half * width;
        // FLAKE FIX: see round.rs note about KoalaBear u32 serde.
        let mut folded: Vec<EF> = vec![EF::ZERO; new_len];
        if width > 0 {
            use p3_maybe_rayon::prelude::*;
            folded.par_chunks_exact_mut(width).enumerate().for_each(|(i, dst)| {
                for k in 0..width {
                    let lo: EF = values[2 * i * width + k].into();
                    let hi: EF = values[(2 * i + 1) * width + k].into();
                    dst[k] = lo + beta * hi;
                }
            });
        }
        Mle { guts: RowMajorMatrix::new(folded, width) }
    }
}

/// `Message<T>` mirrors SP1's `slop_commit::Message<T>` — an Arc-
/// shared sequence of items used in basefold's per-round flows.  We
/// alias to a plain `Vec<Arc<T>>` since Ziren has no equivalent of
/// SP1's tensor backend abstraction.
pub type Message<T> = Vec<Arc<T>>;

/// `Rounds<T>` mirrors SP1's `slop_commit::Rounds<T>` — a flat
/// sequence indexed by round number.
pub type Rounds<T> = Vec<T>;

/// Build a `Message` from any `IntoIterator<Item=T>`.
pub fn message_from_iter<T, I: IntoIterator<Item = T>>(iter: I) -> Message<T> {
    iter.into_iter().map(Arc::new).collect()
}

