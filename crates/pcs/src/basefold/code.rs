//! Reed-Solomon codeword type used throughout the BaseFold protocol.
//!
//! Source-mapped from
//! `slop/crates/basefold/src/code.rs`.
//!
//! In the SP1 source this is a `Tensor<F, A>` wrapper.  Ziren uses
//! `RowMajorMatrix<F>` from `p3_matrix` instead, which has the same
//! row-major shape semantics that the `commit_phase_round` reshape
//! ("merge even/odd into adjacent columns") relies on.

use p3_field::Field;
use p3_matrix::dense::RowMajorMatrix;

/// Reed-Solomon encoded codeword.
///
/// `data.values` is the bit-reversed evaluation vector of length
/// `2^(num_variables + log_blowup)`.  When the underlying MLE is over
/// the extension field `EF`, the row-major matrix has width `EF::D`
/// (one column per base-field component), so the same codeword type
/// works for base- and extension-field encodings.
#[derive(Clone, Debug)]
pub struct RsCodeWord<F: Field> {
    pub data: RowMajorMatrix<F>,
}

impl<F: Field> RsCodeWord<F> {
    pub const fn new(data: RowMajorMatrix<F>) -> Self {
        Self { data }
    }

    /// Number of rows in the row-major encoding.
    pub fn num_rows(&self) -> usize {
        self.data.values.len() / self.data.width.max(1)
    }

    pub fn width(&self) -> usize {
        self.data.width
    }

}
