//! Backend-generic 2D row-major tensor: [`Tensor`].
//!
//! A `Tensor<T, A>` is a [`Buffer<T, A>`] paired with its 2D
//! [`Dimensions`] (`[rows, cols]`, row-major).  It is the storage type
//! for [`crate::basefold::Mle`].
//!
//! The *shape* accessors (`sizes`, `total_len`) are backend-agnostic —
//! they read only the [`Dimensions`].  The *data* accessors
//! (`as_slice`, `into_buffer`, `to_row_major_matrix`, `From<RowMajorMatrix>`)
//! are CPU-only and zero-copy, so `Tensor<T, CpuBackend>` is a
//! byte-identical, allocation-neutral stand-in for the `RowMajorMatrix`
//! that `Mle` used to hold directly.

use alloc::vec::Vec;

use p3_matrix::dense::RowMajorMatrix;

use super::backend::{Backend, CpuBackend};
use super::buffer::Buffer;
use super::dimensions::Dimensions;
use super::raw_buffer::TryReserveError;

/// A backend-generic 2D row-major tensor (see the module docs).
#[derive(Clone, Debug)]
pub struct Tensor<T, A: Backend = CpuBackend> {
    storage: Buffer<T, A>,
    dimensions: Dimensions,
}

impl<T, A: Backend> Tensor<T, A> {
    /// Allocate an `[rows, cols]` tensor in `allocator`'s memory space,
    /// leaving the storage **uninitialized** (`len == 0`, `capacity ==
    /// rows * cols`).
    ///
    /// The caller is responsible for filling the storage (e.g. a
    /// [`crate::tensor::mem::DeviceMemory::copy_nonoverlapping`] into
    /// [`Self::as_mut_buffer`]) and then declaring the initialized prefix
    /// via [`Buffer::set_len`].
    ///
    /// # Errors
    ///
    /// Returns `Err(TryReserveError)` if the allocator fails to allocate.
    #[inline]
    pub fn try_with_sizes_in(sizes: [usize; 2], allocator: A) -> Result<Self, TryReserveError> {
        let dimensions = Dimensions::new(sizes[0], sizes[1]);
        let storage = Buffer::try_with_capacity_in(dimensions.total_len(), allocator)?;
        Ok(Self { storage, dimensions })
    }

    /// [`Self::try_with_sizes_in`], panicking on allocation failure.
    ///
    /// # Panics
    ///
    /// Panics if the allocator fails to allocate.
    #[inline]
    #[must_use]
    pub fn with_sizes_in(sizes: [usize; 2], allocator: A) -> Self {
        Self::try_with_sizes_in(sizes, allocator).unwrap()
    }

    /// Allocate an `[rows, cols]` tensor in `allocator`'s memory space and
    /// zero every byte of it (via the backend's
    /// [`crate::tensor::mem::DeviceMemory::write_bytes`]), yielding a fully
    /// initialized tensor (`len == rows * cols`).
    ///
    /// # Panics
    ///
    /// Panics if the allocator fails to allocate or the zeroing fails.
    #[inline]
    #[must_use]
    pub fn zeros_in(sizes: [usize; 2], allocator: A) -> Self {
        let mut tensor = Self::with_sizes_in(sizes, allocator);
        let bytes = tensor.dimensions.total_len() * core::mem::size_of::<T>();
        tensor.storage.write_bytes(0, bytes).unwrap();
        tensor
    }

    /// Borrow the backing [`Buffer`].  Backend-agnostic.
    #[inline]
    pub fn as_buffer(&self) -> &Buffer<T, A> {
        &self.storage
    }

    /// Mutably borrow the backing [`Buffer`].  Backend-agnostic.
    #[inline]
    pub fn as_mut_buffer(&mut self) -> &mut Buffer<T, A> {
        &mut self.storage
    }

    /// The `[rows, cols]` extents.  Backend-agnostic (reads only the
    /// [`Dimensions`]).
    #[inline]
    pub fn sizes(&self) -> [usize; 2] {
        self.dimensions.sizes()
    }

    /// Total number of cells (`rows * cols`).  Backend-agnostic.
    #[inline]
    pub fn total_len(&self) -> usize {
        self.dimensions.total_len()
    }

    /// Borrow the shape descriptor.  Backend-agnostic.
    #[inline]
    pub fn dimensions(&self) -> &Dimensions {
        &self.dimensions
    }
}

impl<T, A: Backend> Tensor<T, A> {
    /// Adopt an existing buffer under an explicit `[rows, cols]` shape,
    /// zero-copy, in whatever memory space the buffer already lives in.
    ///
    /// This is the seam a device-resident matrix crosses to become a
    /// `Tensor<T, CudaBackend>` (and so an `Mle`) without a copy: the buffer
    /// carries its own allocation and allocator, so ownership simply moves.
    #[inline]
    pub fn from_buffer_in(storage: Buffer<T, A>, rows: usize, cols: usize) -> Self {
        debug_assert_eq!(
            storage.len(),
            rows * cols,
            "Tensor::from_buffer_in: buffer len != rows*cols",
        );
        Self { storage, dimensions: Dimensions::new(rows, cols) }
    }
}

impl<T> Tensor<T, CpuBackend> {
    /// Build a CPU tensor from a linear buffer and an explicit
    /// `[rows, cols]` shape.  Zero-copy.
    #[inline]
    pub fn new(storage: Buffer<T, CpuBackend>, rows: usize, cols: usize) -> Self {
        Self::from_buffer_in(storage, rows, cols)
    }

    /// Borrow the storage as a flat row-major slice (zero-copy).  This is
    /// the accessor the CPU hot loops obtain **once** and index directly.
    #[inline]
    pub fn as_slice(&self) -> &[T] {
        self.storage.as_slice()
    }

    /// Borrow the storage as a mutable flat row-major slice (zero-copy).
    #[inline]
    pub fn as_mut_slice(&mut self) -> &mut [T] {
        self.storage.as_mut_slice()
    }

    /// Consume, returning the backing [`Buffer`] (zero-copy move).
    #[inline]
    pub fn into_buffer(self) -> Buffer<T, CpuBackend> {
        self.storage
    }

    /// Reshape to `[rows, cols]`, preserving the linear storage and total
    /// length (zero-copy — only the [`Dimensions`] change).
    #[inline]
    pub fn reshape(mut self, sizes: [usize; 2]) -> Self {
        debug_assert_eq!(
            sizes[0] * sizes[1],
            self.total_len(),
            "Tensor::reshape must preserve total length",
        );
        self.dimensions = Dimensions::new(sizes[0], sizes[1]);
        self
    }

    /// Zero-copy conversion into a Plonky3 row-major matrix (width =
    /// `cols`, the linear storage is moved as-is).
    #[inline]
    pub fn to_row_major_matrix(self) -> RowMajorMatrix<T>
    where
        T: Clone + Send + Sync,
    {
        let width = self.dimensions.sizes()[1];
        RowMajorMatrix::new(self.storage.into_vec(), width)
    }
}

impl<T> From<RowMajorMatrix<T>> for Tensor<T, CpuBackend> {
    /// Zero-copy move of a Plonky3 row-major matrix into a tensor with
    /// `sizes = [height, width]`.  Height is computed exactly as
    /// `DenseMatrix::height` (`0` when `width == 0`) so the tensor shape
    /// matches the matrix's `Matrix::height()` / `width()` bit-for-bit.
    #[inline]
    fn from(mat: RowMajorMatrix<T>) -> Self {
        let width = mat.width;
        let height = if width == 0 { 0 } else { mat.values.len() / width };
        Tensor { storage: Buffer::from(mat.values), dimensions: Dimensions::new(height, width) }
    }
}

impl<T> From<Vec<T>> for Tensor<T, CpuBackend> {
    /// A flat `Vec<T>` becomes a single-column `[len, 1]` tensor
    /// (matches `RowMajorMatrix::new_col`).  Zero-copy.
    #[inline]
    fn from(values: Vec<T>) -> Self {
        let len = values.len();
        Tensor { storage: Buffer::from(values), dimensions: Dimensions::new(len, 1) }
    }
}
