//! Part of the Ziren backend-generic tensor stack. Only `CpuBackend` is implemented here
//! (host stays device-dependency-free); `ziren-gpu` implements `CudaBackend` against
//! this `Backend`/`RawBuffer`/`Slice`/`DeviceMemory` abstraction.

use core::{alloc::Layout, ptr::NonNull};
use std::{rc::Rc, sync::Arc};

use core::fmt;

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct AllocError;

impl fmt::Display for AllocError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("allocation error")
    }
}

impl std::error::Error for AllocError {}

/// An implementation of `Allocator` can allocate, grow, shrink, and deallocate arbitrary blocks of
/// data described via [`Layout`][]
///
/// # Safety
///
/// * Memory blocks returned from an allocator that are [*currently allocated*] must point to valid
///   memory and retain their validity while they are [*currently allocated*] and the shorter of:
///   - the borrow-checker lifetime of the allocator type itself.
///   - as long as at least one of the instance and all of its clones has not been dropped.
///
/// * copying, cloning, or moving the allocator must not invalidate memory blocks returned from this
///   allocator. A copied or cloned allocator must behave like the same allocator, and
///
/// * any pointer to a memory block which is [*currently allocated*] may be passed to any other
///   method of the allocator.
pub unsafe trait Allocator {
    /// Attempts to allocate a block of memory.
    ///
    /// On success, returns a [`NonNull<[u8]>`][NonNull] meeting the size and alignment guarantees
    /// of `layout`.
    ///
    /// The returned block may have a larger size than specified by `layout.size()`, and may or may
    /// not have its contents initialized.
    ///
    /// The returned block of memory remains valid as long as it is [*currently allocated*] and the
    /// shorter of:
    ///   - the borrow-checker lifetime of the allocator type itself.
    ///   - as long as at the allocator and all its clones has not been dropped.
    ///
    /// # Errors
    ///
    /// Returning `Err` indicates that either memory is exhausted or `layout` does not meet
    /// allocator's size or alignment constraints.
    ///
    /// # Safety
    ///
    /// The memory is not necessarily available upon return from this function. The caller must
    /// ensure that the proper synchronization is performed before using the memory, if necessary.
    unsafe fn allocate(&self, layout: Layout) -> Result<NonNull<[u8]>, AllocError>;

    /// Deallocates the memory referenced by `ptr`.
    ///
    /// # Safety
    ///
    /// * `ptr` must denote a block of memory [*currently allocated*] via this allocator, and
    /// * `layout` must [*fit*] that block of memory.
    unsafe fn deallocate(&self, ptr: NonNull<u8>, layout: Layout);

    fn by_ref(&self) -> &Self
    where
        Self: Sized,
    {
        self
    }
}

unsafe impl<A> Allocator for &A
where
    A: Allocator + ?Sized,
{
    #[inline]
    unsafe fn allocate(&self, layout: Layout) -> Result<NonNull<[u8]>, AllocError> {
        (**self).allocate(layout)
    }

    #[inline]
    unsafe fn deallocate(&self, ptr: NonNull<u8>, layout: Layout) {
        // SAFETY: the safety contract must be upheld by the caller
        unsafe { (**self).deallocate(ptr, layout) }
    }
}

unsafe impl<A> Allocator for Rc<A>
where
    A: Allocator + ?Sized,
{
    #[inline]
    unsafe fn allocate(&self, layout: Layout) -> Result<NonNull<[u8]>, AllocError> {
        (**self).allocate(layout)
    }

    #[inline]
    unsafe fn deallocate(&self, ptr: NonNull<u8>, layout: Layout) {
        // SAFETY: the safety contract must be upheld by the caller
        unsafe { (**self).deallocate(ptr, layout) }
    }
}

unsafe impl<A> Allocator for Arc<A>
where
    A: Allocator + ?Sized,
{
    #[inline]
    unsafe fn allocate(&self, layout: Layout) -> Result<NonNull<[u8]>, AllocError> {
        (**self).allocate(layout)
    }

    #[inline]
    unsafe fn deallocate(&self, ptr: NonNull<u8>, layout: Layout) {
        // SAFETY: the safety contract must be upheld by the caller
        unsafe { (**self).deallocate(ptr, layout) }
    }
}
