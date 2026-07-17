//! PORTED VERBATIM from SP1 `slop/crates/alloc/src/backend/mod.rs` (succinctlabs/sp1) for the
//! Ziren backend-generic tensor stack (#125 INC-6, full SP1-fidelity Buffer port).
//! Ziren adaptations vs upstream: `crate::` -> `crate::tensor::`; `thiserror` errors
//! hand-written; `slop_algebra` -> `p3_field`.
//!
//! `CpuBackend` is the ONLY implementor, in either tree — there is no `CudaBackend`.
//! `ziren-gpu` does not reference this abstraction at all; its device traces are a
//! bespoke COLUMN-major `ColMajorMatrixDevice` over `DeviceBuffer`, whereas `Tensor`
//! here is ROW-major, so the two stacks are not interchangeable as they stand.
//!
//! This module is therefore a faithful port that is currently CPU-only. Note also that
//! upstream SP1 pins `CpuBackend` at every shard-prover use site (`MainTraceData<_, _,
//! CpuBackend>`), so the `Backend` parameter is vestigial there too — SP1 separates CPU
//! from GPU at the PROVER level, not via this parameter. Do not infer from the generics
//! that a device backend is wired up or that one would be cheap to wire up.

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
