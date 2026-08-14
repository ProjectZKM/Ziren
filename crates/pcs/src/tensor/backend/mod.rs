//! Part of the Ziren backend-generic tensor stack.
//!
//! `CpuBackend` is the only implementor **in this tree**; `ziren-gpu` implements the
//! device half as `CudaBackend` (`core/src/device/backend.rs`), a thin wrapper over its
//! `CudaStream` (`cudaMallocAsync` / `cudaFreeAsync` / `cudaMemcpyAsync` /
//! `cudaMemsetAsync`).
//! So `Buffer<T, CudaBackend>` / `Tensor<T, CudaBackend>` are real, device-resident
//! types over there.
//!
//! What that does NOT mean: nothing in either tree currently **consumes** a non-CPU
//! backend. Every shard-prover use site still pins `CpuBackend` — the CPU/GPU split
//! lives at the PROVER level, not in this parameter. In particular ziren-gpu's device
//! traces remain a bespoke COLUMN-major `ColMajorMatrixDevice` over `DeviceBuffer`,
//! whereas `Tensor` here is ROW-major, so the two stacks are still not interchangeable.
//! Do not infer from the generics that a device backend is wired into any proving path.

mod cpu;
mod io;

use std::{borrow::Cow, fmt::Debug, rc::Rc, sync::Arc};

pub use cpu::*;
pub use io::*;

use crate::tensor::{
    mem::{CopyError, DeviceMemory},
    Allocator,
};

/// # Safety
///
/// TODO
pub unsafe trait Backend:
    Sized + Allocator + DeviceMemory + Clone + Debug + Send + Sync + 'static
{
    fn copy_from<B, T>(&self, data: T) -> Result<T::Output, CopyError>
    where
        B: Backend,
        T: HasBackend + CopyIntoBackend<Self, B>,
    {
        data.copy_into_backend(self)
    }
}

pub trait GlobalBackend: Backend + 'static {
    fn global() -> &'static Self;
}

pub trait HasBackend {
    type Backend: Backend;

    fn backend(&self) -> &Self::Backend;
}

impl<T> HasBackend for &T
where
    T: HasBackend,
{
    type Backend = T::Backend;

    fn backend(&self) -> &Self::Backend {
        (**self).backend()
    }
}

impl<T> HasBackend for &mut T
where
    T: HasBackend,
{
    type Backend = T::Backend;

    fn backend(&self) -> &Self::Backend {
        (**self).backend()
    }
}

impl<'a, T> HasBackend for Cow<'a, T>
where
    T: HasBackend + Clone,
{
    type Backend = T::Backend;

    fn backend(&self) -> &Self::Backend {
        self.as_ref().backend()
    }
}

impl<T> HasBackend for Box<T>
where
    T: HasBackend,
{
    type Backend = T::Backend;

    fn backend(&self) -> &Self::Backend {
        self.as_ref().backend()
    }
}

impl<T> HasBackend for Arc<T>
where
    T: HasBackend,
{
    type Backend = T::Backend;

    fn backend(&self) -> &Self::Backend {
        self.as_ref().backend()
    }
}

impl<T> HasBackend for Rc<T>
where
    T: HasBackend,
{
    type Backend = T::Backend;

    fn backend(&self) -> &Self::Backend {
        self.as_ref().backend()
    }
}
