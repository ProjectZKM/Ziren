//! Backend-dispatched MLE shape accessors.
//!
//! # Why this trait exists
//!
//! An MLE's storage layout is a property of its BACKEND, not of the MLE. The
//! host stores a batch row-major as `[num_non_zero_entries, num_polynomials]`;
//! a device stores it transposed, `[num_polynomials, num_non_zero_entries]`,
//! because that is the layout its kernels want.
//!
//! [`Mle`](crate::basefold::Mle) therefore cannot read its own dimensions
//! directly. It asks the backend, which is what lets one `Mle<F, A>` describe
//! both a host trace and a column-major device trace without a conversion at
//! the boundary.
//!
//! `CpuBackend` is the only implementor in this tree; `ziren-gpu` supplies the
//! device half for `CudaBackend`.

use crate::tensor::{Backend, CpuBackend, Tensor};

/// The per-backend layout contract for an MLE's backing tensor.
pub trait MleBaseBackend<F>: Backend {
    /// Number of polynomials in the batch.
    fn num_polynomials(guts: &Tensor<F, Self>) -> usize;

    /// `log2` of the hypercube size, rounded up.
    fn num_variables(guts: &Tensor<F, Self>) -> u32;

    /// Number of non-zero (real, unpadded) entries per polynomial.
    fn num_non_zero_entries(guts: &Tensor<F, Self>) -> usize;

    /// Allocate an uninitialized backing tensor in this backend's layout.
    fn uninit_mle(&self, num_polynomials: usize, num_non_zero_entries: usize) -> Tensor<F, Self>;
}

impl<F> MleBaseBackend<F> for CpuBackend {
    /// Host layout is `[entries, polynomials]`, so the polynomial count is the
    /// COLUMN count.
    #[inline]
    fn num_polynomials(guts: &Tensor<F, Self>) -> usize {
        guts.sizes()[1]
    }

    #[inline]
    fn num_variables(guts: &Tensor<F, Self>) -> u32 {
        guts.sizes()[0].next_power_of_two().ilog2()
    }

    #[inline]
    fn num_non_zero_entries(guts: &Tensor<F, Self>) -> usize {
        guts.sizes()[0]
    }

    #[inline]
    fn uninit_mle(&self, num_polynomials: usize, num_non_zero_entries: usize) -> Tensor<F, Self> {
        Tensor::with_sizes_in([num_non_zero_entries, num_polynomials], *self)
    }
}
