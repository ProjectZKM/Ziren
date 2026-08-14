//! Part of the Ziren backend-generic tensor stack. Only `CpuBackend` is implemented here
//! (host stays device-dependency-free); `ziren-gpu` implements `CudaBackend` against
//! this `Backend`/`RawBuffer`/`Slice`/`DeviceMemory` abstraction.

use std::{
    alloc::Layout,
    ptr::{self, NonNull},
};

use serde::{Deserialize, Serialize};

use crate::tensor::{
    mem::{CopyDirection, CopyError, DeviceMemory},
    AllocError, Allocator,
};

use super::{Backend, GlobalBackend};

pub const GLOBAL_CPU_BACKEND: CpuBackend = CpuBackend;

#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
pub struct CpuBackend;

impl GlobalBackend for CpuBackend {
    fn global() -> &'static Self {
        &GLOBAL_CPU_BACKEND
    }
}

unsafe impl Allocator for CpuBackend {
    #[inline]
    unsafe fn allocate(&self, layout: Layout) -> Result<ptr::NonNull<[u8]>, AllocError> {
        let ptr = std::alloc::alloc(layout);
        Ok(NonNull::slice_from_raw_parts(NonNull::new_unchecked(ptr), layout.size()))
    }

    #[inline]
    unsafe fn deallocate(&self, ptr: NonNull<u8>, layout: Layout) {
        std::alloc::dealloc(ptr.as_ptr(), layout);
    }
}

impl DeviceMemory for CpuBackend {
    #[inline]
    unsafe fn copy_nonoverlapping(
        &self,
        src: *const u8,
        dst: *mut u8,
        size: usize,
        _direction: CopyDirection,
    ) -> Result<(), CopyError> {
        src.copy_to_nonoverlapping(dst, size);
        Ok(())
    }

    #[inline]
    unsafe fn write_bytes(&self, dst: *mut u8, value: u8, size: usize) -> Result<(), CopyError> {
        dst.write_bytes(value, size);
        Ok(())
    }
}

unsafe impl Backend for CpuBackend {}
