//! Reed-Solomon codeword type used throughout the WHIR protocol, and the
//! storage helpers the provers move codewords through.
//!
//! Backed by a row-major `RowMajorMatrix<F>` from `p3_matrix`.

use alloc::vec::Vec;

use p3_field::{BasedVectorSpace, ExtensionField, Field, TwoAdicField};
use p3_matrix::dense::RowMajorMatrix;

use super::mle::Message;

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

/// Move the cells of a freshly-encoded codeword out of its `Arc`.
///
/// `Message<T> = Vec<Arc<T>>`, so the cells are behind a shared pointer and
/// cannot be moved in general.  On return from `Encoder::encode_batch` the
/// refcount is 1, so `try_unwrap` succeeds; the `Err` arm clones, since the type
/// does not encode uniqueness.
pub fn take_codeword_values<F: Field>(codewords: Message<RsCodeWord<F>>) -> Vec<F> {
    let mut codewords = codewords;
    let first = codewords.swap_remove(0);
    match alloc::sync::Arc::try_unwrap(first) {
        Ok(owned) => owned.data.values,
        Err(shared) => shared.data.values.clone(),
    }
}

/// Repack an EF codeword into base-field [`RsCodeWord`] storage.
pub fn codeword_from_ef<F, EF>(codeword_ef: Vec<EF>) -> RsCodeWord<F>
where
    F: TwoAdicField,
    EF: ExtensionField<F> + TwoAdicField,
{
    let storage = <EF as BasedVectorSpace<F>>::flatten_to_base(codeword_ef);
    RsCodeWord::new(RowMajorMatrix::new(storage, EF::DIMENSION))
}
