//! Reed-Solomon encoder for the WHIR protocol.
//!
//! # Encoding choice
//!
//! Each column of the input MLE contains `2^n` Boolean-hypercube values.
//! The encoder treats those values as univariate polynomial coefficients,
//! zero-pads them to `2^(n + log_blowup)`, and evaluates them on the two-adic
//! subgroup with [`TwoAdicSubgroupDft::dft_batch`]. It then bit-reverses the
//! evaluation rows. No inverse DFT or coset shift is applied.

use alloc::sync::Arc;
use core::marker::PhantomData;

use p3_dft::TwoAdicSubgroupDft;
use p3_field::{Field, TwoAdicField};
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::util::reverse_matrix_index_bits;
use p3_matrix::Matrix;

use super::code::RsCodeWord;
use super::mle::{Message, Mle};

/// CPU-resident DFT-based RS encoder.
///
/// Generic over the DFT impl `D` (typically `Radix2DitParallel<F>`).
#[derive(Debug, Clone)]
pub struct DftEncoder<F: Field, D> {
    /// `log2` of the blowup: a codeword is `2^log_blowup` times its message.
    pub log_blowup: usize,
    pub dft: Arc<D>,
    _marker: PhantomData<F>,
}

impl<F, D> DftEncoder<F, D>
where
    F: TwoAdicField,
    D: TwoAdicSubgroupDft<F>,
{
    pub const fn new(log_blowup: usize, dft: Arc<D>) -> Self {
        Self { log_blowup, dft, _marker: PhantomData }
    }

    /// Encode a stream of MLEs into RS codewords.  Each MLE is
    /// encoded independently — no cross-MLE materialization, which
    /// is the structural OOM win over a dense-vec commit path.
    ///
    /// MLE values are interpreted as the **coefficients** of the
    /// underlying degree-`(2^k - 1)` polynomial.  We
    /// zero-pad coefficients to length `N << log_blowup`, DFT
    /// directly, then bit-reverse the evaluation rows.
    pub fn encode_batch(&self, data: Message<Mle<F>>) -> Message<RsCodeWord<F>> {
        let log_blowup = self.log_blowup;
        data.into_iter()
            .map(|mle| {
                let width = mle.num_polynomials();
                let mut padded = mle.guts().as_slice().to_vec();
                padded.resize(padded.len() << log_blowup, F::ZERO);
                let mat = RowMajorMatrix::new(padded, width);
                let evals = self.dft.dft_batch(mat);
                let mut br = evals.to_row_major_matrix();
                reverse_matrix_index_bits(&mut br);
                Arc::new(RsCodeWord::new(br))
            })
            .collect()
    }
}
