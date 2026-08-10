//! PORTED VERBATIM from SP1 `slop/crates/alloc/src/mem.rs` (succinctlabs/sp1) for the
//! Ziren backend-generic tensor stack — a full SP1-fidelity Buffer port.
//! Ziren adaptations vs upstream: `crate::` -> `crate::tensor::`; `thiserror` errors
//! hand-written; `slop_algebra` -> `p3_field`. Only `CpuBackend` is implemented here
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

/// A trait that defines memory operations for a device.
pub trait DeviceMemory {
    /// # Safety
    unsafe fn copy_nonoverlapping(
        &self,
        src: *const u8,
        dst: *mut u8,
        size: usize,
        direction: CopyDirection,
    ) -> Result<(), CopyError>;

    /// TODO
    ///
    /// # Safety
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
