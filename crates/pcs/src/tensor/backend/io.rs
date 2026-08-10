//! PORTED VERBATIM from SP1 `slop/crates/alloc/src/backend/io.rs` (succinctlabs/sp1) for the
//! Ziren backend-generic tensor stack — a full SP1-fidelity Buffer port.
//! Ziren adaptations vs upstream: `crate::` -> `crate::tensor::`; `thiserror` errors
//! hand-written; `slop_algebra` -> `p3_field`. Only `CpuBackend` is implemented here
//! (host stays device-dependency-free); `ziren-gpu` implements `CudaBackend` against
//! this `Backend`/`RawBuffer`/`Slice`/`DeviceMemory` abstraction.

use crate::tensor::mem::CopyError;

use super::{Backend, CpuBackend, GlobalBackend, HasBackend};

/// Copy data between different backends
pub trait CopyIntoBackend<Dst: Backend, Src: Backend>: HasBackend<Backend = Src> {
    type Output: HasBackend<Backend = Dst>;
    fn copy_into_backend(self, backend: &Dst) -> Result<Self::Output, CopyError>;
}

impl<T, A> CopyIntoBackend<A, A> for T
where
    A: Backend,
    T: HasBackend<Backend = A> + Send + Sync,
{
    type Output = T;
    fn copy_into_backend(self, _backend: &A) -> Result<Self::Output, CopyError> {
        Ok(self)
    }
}

pub trait CanCopyFrom<T, Src>: Backend
where
    Src: Backend,
{
    type Output;
    fn copy_into(&self, value: T) -> Result<Self::Output, CopyError>;
}

pub trait CanCopyInto<T, Dst>: Backend
where
    Dst: Backend,
{
    type Output;
    fn copy_to_dst(dst: &Dst, value: T) -> Result<Self::Output, CopyError>;
}

impl<T, Dst, A> CanCopyInto<T, Dst> for A
where
    A: Backend,
    Dst: Backend,
    T: HasBackend<Backend = Self>,
    Dst: CanCopyFrom<T, Self>,
{
    type Output = <Dst as CanCopyFrom<T, Self>>::Output;
    fn copy_to_dst(dst: &Dst, value: T) -> Result<Self::Output, CopyError> {
        dst.copy_into(value)
    }
}

impl<T, Src, A> CanCopyFrom<T, Src> for A
where
    A: Backend,
    Src: Backend,
    T: CopyIntoBackend<Self, Src>,
{
    type Output = T::Output;
    fn copy_into(&self, value: T) -> Result<Self::Output, CopyError> {
        value.copy_into_backend(self)
    }
}

pub trait CanCopyFromRef<T, Src>: Backend
where
    Src: Backend,
{
    type Output;
    fn copy_to(&self, value: &T) -> Result<Self::Output, CopyError>;
}

pub trait CanCopyIntoRef<T, Dst>: Backend
where
    Dst: Backend,
{
    type Output;
    fn copy_to_dst(dst: &Dst, value: &T) -> Result<Self::Output, CopyError>;
}

impl<T, Dst, Src> CanCopyIntoRef<T, Dst> for Src
where
    Src: Backend,
    Dst: Backend,
    T: HasBackend<Backend = Self>,
    Dst: CanCopyFromRef<T, Self>,
{
    type Output = <Dst as CanCopyFromRef<T, Self>>::Output;
    fn copy_to_dst(dst: &Dst, value: &T) -> Result<Self::Output, CopyError> {
        dst.copy_to(value)
    }
}

impl<T, Src, A> CanCopyFromRef<T, Src> for A
where
    A: Backend,
    Src: Backend,
    T: CopyToBackend<Self, Src>,
{
    type Output = <T as CopyToBackend<Self, Src>>::Output;
    fn copy_to(&self, value: &T) -> Result<Self::Output, CopyError> {
        value.copy_to_backend(self)
    }
}

pub trait CopyToBackend<Dst: Backend, Src: Backend>: HasBackend<Backend = Src> {
    type Output: HasBackend<Backend = Dst>;
    fn copy_to_backend(&self, backend: &Dst) -> Result<Self::Output, CopyError>;
}

impl<T: HasBackend<Backend = A> + Clone + Sync, A: Backend> CopyToBackend<A, A> for T {
    type Output = T;
    fn copy_to_backend(&self, _backend: &A) -> Result<Self::Output, CopyError> {
        Ok(self.clone())
    }
}

pub trait IntoGlobal<Dst: GlobalBackend>: HasBackend {
    type Output;
    fn into_global(self) -> Result<Self::Output, CopyError>;
}

impl<T, Dst: GlobalBackend> IntoGlobal<Dst> for T
where
    T: HasBackend,
    T::Backend: CanCopyInto<T, Dst>,
{
    type Output = <T::Backend as CanCopyInto<T, Dst>>::Output;
    #[inline]
    fn into_global(self) -> Result<Self::Output, CopyError> {
        <T::Backend as CanCopyInto<T, Dst>>::copy_to_dst(Dst::global(), self)
    }
}

pub trait ToGlobal<Dst: GlobalBackend>: HasBackend {
    type Output;
    fn to_global(&self) -> Result<Self::Output, CopyError>;
}

impl<T, Dst: GlobalBackend> ToGlobal<Dst> for T
where
    T: HasBackend,
    T::Backend: CanCopyIntoRef<T, Dst>,
{
    type Output = <T::Backend as CanCopyIntoRef<T, Dst>>::Output;
    #[inline]
    fn to_global(&self) -> Result<Self::Output, CopyError> {
        <T::Backend as CanCopyIntoRef<T, Dst>>::copy_to_dst(Dst::global(), self)
    }
}

pub trait IntoHost: IntoGlobal<CpuBackend> + Sized {
    #[inline]
    fn into_host(self) -> Result<Self::Output, CopyError> {
        self.into_global()
    }
}

impl<T> IntoHost for T where T: IntoGlobal<CpuBackend> {}

pub trait ToHost: ToGlobal<CpuBackend> {
    #[inline]
    fn to_host(&self) -> Result<Self::Output, CopyError> {
        self.to_global()
    }
}

impl<T> ToHost for T where T: ToGlobal<CpuBackend> {}
