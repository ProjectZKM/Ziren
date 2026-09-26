//! Part of the Ziren backend-generic tensor stack. Only `CpuBackend` is implemented here
//! (host stays device-dependency-free); `ziren-gpu` implements `CudaBackend` against
//! this `Backend`/`RawBuffer`/`Slice`/`DeviceMemory` abstraction.

use std::{rc::Rc, sync::Arc};

use core::fmt;

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct CopyError;

impl fmt::Display for CopyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("copy error")
    }
}

impl std::error::Error for CopyError {}

/// The [CopyDirection] enum represents the direction of a memory copy operation.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum CopyDirection {
    HostToDevice,
    DeviceToHost,
    DeviceToDevice,
}

/// Memory operations within, and across, one backend's memory space.
///
/// # Completion
///
/// Both operations must be COMPLETE when they return.
///
/// This is not a performance note, it is a soundness condition on the safe
/// callers above: `Buffer::extend_from_host_slice` takes the source as a
/// borrow, and a borrow ends when the call does; `Buffer::clone` and
/// `Init::copy_into_host` read the destination on the next line. An
/// implementation that only ENQUEUES the transfer therefore lets the source be
/// freed while a read of it is still outstanding, and lets the destination be
/// read before it has been written — a use-after-free and a read of
/// uninitialized memory, at call sites that carry no `unsafe` block to mark
/// either.
///
/// An asynchronous backend must synchronize before returning from these, or
/// expose its asynchronous form through its own API where the caller can be
/// made responsible for the lifetimes and the completion.
pub trait DeviceMemory {
    /// Copy `size` bytes from `src` to `dst` across `direction`.
    ///
    /// # Safety
    ///
    /// `src` must be valid for reads of `size` bytes, `dst` valid for writes
    /// of `size` bytes, each in the memory space `direction` names for it, and
    /// the two regions must not overlap. See the trait's completion condition.
    unsafe fn copy_nonoverlapping(
        &self,
        src: *const u8,
        dst: *mut u8,
        size: usize,
        direction: CopyDirection,
    ) -> Result<(), CopyError>;

    /// Set `size` bytes at `dst` to `value`.
    ///
    /// # Safety
    ///
    /// `dst` must be valid for writes of `size` bytes in this backend's memory
    /// space. Whether the resulting byte pattern is a valid value of the
    /// element type is the CALLER's obligation, not this trait's — see
    /// [`crate::tensor::Zeroable`] and `Buffer::write_bytes`. See also the
    /// trait's completion condition.
    unsafe fn write_bytes(&self, dst: *mut u8, value: u8, size: usize) -> Result<(), CopyError>;
}

impl<T: DeviceMemory> DeviceMemory for &T {
    #[inline]
    unsafe fn copy_nonoverlapping(
        &self,
        src: *const u8,
        dst: *mut u8,
        size: usize,
        direction: CopyDirection,
    ) -> Result<(), CopyError> {
        (**self).copy_nonoverlapping(src, dst, size, direction)
    }

    #[inline]
    unsafe fn write_bytes(&self, dst: *mut u8, value: u8, size: usize) -> Result<(), CopyError> {
        (**self).write_bytes(dst, value, size)
    }
}

impl<T: DeviceMemory> DeviceMemory for Rc<T> {
    #[inline]
    unsafe fn copy_nonoverlapping(
        &self,
        src: *const u8,
        dst: *mut u8,
        size: usize,
        direction: CopyDirection,
    ) -> Result<(), CopyError> {
        (**self).copy_nonoverlapping(src, dst, size, direction)
    }

    #[inline]
    unsafe fn write_bytes(&self, dst: *mut u8, value: u8, size: usize) -> Result<(), CopyError> {
        (**self).write_bytes(dst, value, size)
    }
}

impl<T: DeviceMemory> DeviceMemory for Arc<T> {
    #[inline]
    unsafe fn copy_nonoverlapping(
        &self,
        src: *const u8,
        dst: *mut u8,
        size: usize,
        direction: CopyDirection,
    ) -> Result<(), CopyError> {
        (**self).copy_nonoverlapping(src, dst, size, direction)
    }

    #[inline]
    unsafe fn write_bytes(&self, dst: *mut u8, value: u8, size: usize) -> Result<(), CopyError> {
        (**self).write_bytes(dst, value, size)
    }
}
