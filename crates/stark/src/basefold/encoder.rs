//! Reed-Solomon encoder for the Basefold protocol.
//!
//! Source-mapped from
//! [`/tmp/sp1/slop/crates/basefold-prover/src/encoder.rs`](file:///tmp/sp1/slop/crates/basefold-prover/src/encoder.rs).
//!
//! # Encoding choice
//!
//! The protocol receives an MLE as `2^n` evaluations on the Boolean
//! hypercube and needs the corresponding RS-encoded codeword on a
//! coset of size `2^(n + log_blowup)`.  We use Plonky3's
//! [`TwoAdicSubgroupDft::coset_lde_batch`] which:
//!   1. iDFTs to recover polynomial coefficients
//!   2. zero-pads to the larger length
//!   3. coset-DFTs to evaluation form on `shift * H_large`
//!
//! Output is in bit-reversed order, which is exactly what
//! [`p3_fri::fold_even_odd`] consumes in
//! [`super::fri::commit_phase_round`].

use alloc::sync::Arc;
use core::marker::PhantomData;

use p3_dft::TwoAdicSubgroupDft;
use p3_field::{Field, TwoAdicField};
use p3_matrix::Matrix;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::util::reverse_matrix_index_bits;

use super::code::RsCodeWord;
use super::config::FriConfig;
use super::mle::{Message, Mle};

/// CPU-resident DFT-based RS encoder.
///
/// Generic over the DFT impl `D` (typically `Radix2DitParallel<F>`).
#[derive(Debug, Clone)]
pub struct DftEncoder<F: Field, D> {
    pub config: FriConfig<F>,
    pub dft: Arc<D>,
    _marker: PhantomData<F>,
}

impl<F, D> DftEncoder<F, D>
where
    F: TwoAdicField,
    D: TwoAdicSubgroupDft<F>,
{
    pub const fn new(config: FriConfig<F>, dft: Arc<D>) -> Self {
        Self { config, dft, _marker: PhantomData }
    }

    pub fn config(&self) -> &FriConfig<F> {
        &self.config
    }

    /// Encode a stream of MLEs into RS codewords.  Each MLE is
    /// encoded independently — no cross-MLE materialization, which
    /// is the structural OOM win over WHIR's dense-vec commit path.
    ///
    /// MLE values are interpreted as the **coefficients** of the
    /// underlying degree-`(2^k - 1)` polynomial (matches SP1's
    /// `slop_dft::Dft::dft(data, log_blowup, BitReversed, 0)`).  We
    /// zero-pad coefficients to length `N << log_blowup`, then DFT
    /// directly — `dft_batch` returns bit-reversed evaluations,
    /// which is exactly what `fold_even_odd_ext` expects.  Using the
    /// coefficient interpretation is what lets the FRI commit-phase
    /// fold and the multilinear-extension fold collapse to the same
    /// constant (the BaseFold key insight).
    pub fn encode_batch(&self, data: Message<Mle<F>>) -> Message<RsCodeWord<F>> {
        let log_blowup = self.config.log_blowup();
        data.into_iter()
            .map(|mle| {
                let width = mle.guts.width();
                let mut padded = mle.guts.values.clone();
                padded.resize(padded.len() << log_blowup, F::ZERO);
                let mat = RowMajorMatrix::new(padded, width);
                // We need the codeword in BIT-REVERSED row order
                // (that's what `fold_even_odd_ext` consumes).  The
                // generic `Evaluations` associated type is opaque,
                // so go through `to_row_major_matrix()` (natural
                // order) and explicitly bit-reverse afterwards.
                let evals = self.dft.dft_batch(mat);
                let mut br = evals.to_row_major_matrix();
                reverse_matrix_index_bits(&mut br);
                Arc::new(RsCodeWord::new(br))
            })
            .collect()
    }
}
