//! Backend-generic linear storage: [`Buffer`].
//!
//! For the only current backend ([`CpuBackend`]) a `Buffer<T>` is a thin
//! newtype over `Vec<T>`.  The storage is **byte-identical** to a plain
//! `Vec<T>` and every accessor below is a zero-copy borrow or move:
//! `from(Vec<T>)`, `into_vec()`, `as_slice()`, `as_mut_slice()`.  This
//! is what keeps the CPU hot loops (`Mle::fold`, the stacked transpose)
//! machine-code-identical to the pre-tensor code.
//!
//! A future device backend would generalize the internal representation
//! (e.g. a raw device pointer + length); the CPU accessors are gated on
//! `A = CpuBackend`, so that generalization is additive.

use alloc::vec::Vec;
use core::marker::PhantomData;

use super::backend::{Backend, CpuBackend};

/// Backend-generic linear storage (see the module docs).
#[derive(Clone, Debug)]
pub struct Buffer<T, A: Backend = CpuBackend> {
    values: Vec<T>,
    _backend: PhantomData<A>,
}

impl<T> Buffer<T, CpuBackend> {
    /// Borrow the storage as a flat slice (zero-copy).
    #[inline]
    pub fn as_slice(&self) -> &[T] {
        &self.values
    }

    /// Borrow the storage as a mutable flat slice (zero-copy).
    #[inline]
    pub fn as_mut_slice(&mut self) -> &mut [T] {
        &mut self.values
    }

    /// Consume, returning the backing `Vec<T>` (zero-copy move).
    #[inline]
    pub fn into_vec(self) -> Vec<T> {
        self.values
    }

    /// Number of elements.
    #[inline]
    pub fn len(&self) -> usize {
        self.values.len()
    }

    /// True when the buffer holds no elements.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }
}

impl<T> From<Vec<T>> for Buffer<T, CpuBackend> {
    /// Zero-copy move of an owned `Vec<T>` into a CPU buffer.
    #[inline]
    fn from(values: Vec<T>) -> Self {
        Self { values, _backend: PhantomData }
    }
}
