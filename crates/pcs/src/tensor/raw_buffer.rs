//! PORTED VERBATIM from SP1 `slop/crates/alloc/src/raw_buffer.rs` (succinctlabs/sp1) for the
//! Ziren backend-generic tensor stack — a full SP1-fidelity Buffer port.
//! Ziren adaptations vs upstream: `crate::` -> `crate::tensor::`; `thiserror` errors
//! hand-written; `slop_algebra` -> `p3_field`. Only `CpuBackend` is implemented here
//! (host stays device-dependency-free); `ziren-gpu` implements `CudaBackend` against
//! this `Backend`/`RawBuffer`/`Slice`/`DeviceMemory` abstraction.

use core::{alloc::Layout, marker::PhantomData, mem, ptr::NonNull};

use crate::tensor::Allocator;

#[derive(Debug)]
pub struct RawBuffer<T, A: Allocator> {
    inner: RawBufferInner<A>,
    _marker: PhantomData<T>,
}

#[derive(Debug)]
struct RawBufferInner<A> {
    ptr: NonNull<u8>,
    cap: usize,
    alloc: A,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum TryReserveError {
    /// Error due to the computed capacity exceeding the collection's maximum
    /// (usually `isize::MAX` bytes).
    CapacityOverflow,

    /// The memory allocator returned an error
    AllocError {
        /// The layout of allocation request that failed
        layout: Layout,
    },
}

impl core::fmt::Display for TryReserveError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            TryReserveError::CapacityOverflow => f.write_str("capacity overflow"),
            TryReserveError::AllocError { layout } => {
                write!(f, "allocation error for layout {:?}", layout)
            }
        }
    }
}

impl std::error::Error for TryReserveError {}

impl<T, A: Allocator> RawBuffer<T, A> {
    /// Like `new`, but parameterized over the choice of allocator for
    /// the returned `RawVec`.
    #[inline]
    pub const fn new_in(alloc: A) -> Self {
        Self { inner: RawBufferInner::new_in(alloc, align_of::<T>()), _marker: PhantomData }
    }

    #[inline]
    pub fn with_capacity_in(capacity: usize, alloc: A) -> Self {
        Self { inner: RawBufferInner::with_capacity_in::<T>(capacity, alloc), _marker: PhantomData }
    }

    #[inline]
    pub fn try_with_capacity_in(capacity: usize, alloc: A) -> Result<Self, TryReserveError> {
        match RawBufferInner::try_with_capacity_in::<T>(capacity, alloc) {
            Ok(inner) => Ok(Self { inner, _marker: PhantomData }),
            Err(e) => Err(e),
        }
    }

    /// Reconstitutes a `RawBuffer` from a pointer, capacity, and allocator.
    ///
    /// # Safety
    ///
    /// The `ptr` must be allocated (via the given allocator `alloc`), and with the given
    /// `capacity`.
    /// The `capacity` cannot exceed `isize::MAX` for sized types. (only a concern on 32-bit
    /// systems). For ZSTs capacity is ignored.
    /// If the `ptr` and `capacity` come from a `RawBuffer` created via `alloc`, then this is
    /// guaranteed.
    #[inline]
    pub unsafe fn from_raw_parts_in(ptr: *mut T, capacity: usize, alloc: A) -> Self {
        // SAFETY: Precondition passed to the caller
        unsafe {
            let ptr = ptr.cast();
            Self {
                inner: RawBufferInner::from_raw_parts_in(ptr, capacity, alloc),
                _marker: PhantomData,
            }
        }
    }

    /// Gets a raw pointer to the start of the allocation. Note that this is
    /// `Unique::dangling()` if `capacity == 0` or `T` is zero-sized. In the former case, you must
    /// be careful.
    #[inline]
    pub fn ptr(&self) -> *mut T {
        self.inner.ptr()
    }

    #[inline]
    pub fn non_null(&self) -> NonNull<T> {
        self.inner.non_null()
    }

    /// Gets the capacity of the allocation.
    ///
    /// This will always be `usize::MAX` if `T` is zero-sized.
    #[inline]
    pub fn capacity(&self) -> usize {
        self.inner.capacity(size_of::<T>())
    }

    /// Returns a shared reference to the allocator backing this `RawVec`.
    #[inline]
    pub const fn allocator(&self) -> &A {
        self.inner.allocator()
    }

    /// # Safety
    ///
    /// TODO
    #[inline]
    pub unsafe fn allocator_mut(&mut self) -> &mut A {
        &mut self.inner.alloc
    }
}

impl<A: Allocator> RawBufferInner<A> {
    /// Like `new`, but parameterized over the choice of allocator for
    /// the returned `RawVec`.
    #[inline]
    const fn new_in(alloc: A, align: usize) -> Self {
        let ptr = unsafe { core::mem::transmute::<usize, NonNull<u8>>(align) };
        // `cap: 0` means "unallocated". zero-sized types are ignored.
        Self { ptr, cap: 0, alloc }
    }

    #[inline]
    fn with_capacity_in<T>(capacity: usize, alloc: A) -> Self {
        match Self::try_allocate_in::<T>(capacity, alloc) {
            Ok(this) => this,
            Err(err) => handle_error(err),
        }
    }

    fn try_allocate_in<T>(capacity: usize, alloc: A) -> Result<Self, TryReserveError> {
        // We avoid `unwrap_or_else` here because it bloats the amount of
        // LLVM IR generated.
        let layout = Layout::array::<T>(capacity).map_err(|_| TryReserveError::CapacityOverflow)?;

        // Don't allocate here because `Drop` will not deallocate when `capacity` is 0.
        if layout.size() == 0 {
            return Ok(Self::new_in(alloc, layout.align()));
        }

        alloc_guard(layout.size())?;

        let result = unsafe { alloc.allocate(layout) };

        let ptr = match result {
            Ok(ptr) => ptr,
            Err(_) => return Err(TryReserveError::AllocError { layout }),
        };

        // Allocators currently return a `NonNull<[u8]>` whose length
        // matches the size requested. If that ever changes, the capacity
        // here should change to `ptr.len() / mem::size_of::<T>()`.
        Ok(Self { ptr: ptr.cast(), cap: capacity, alloc })
    }

    #[inline]
    fn ptr<T>(&self) -> *mut T {
        self.non_null::<T>().as_ptr()
    }

    #[inline]
    fn non_null<T>(&self) -> NonNull<T> {
        self.ptr.cast()
    }

    #[inline]
    fn capacity(&self, elem_size: usize) -> usize {
        if elem_size == 0 {
            usize::MAX
        } else {
            self.cap
        }
    }

    #[inline]
    unsafe fn from_raw_parts_in(ptr: *mut u8, cap: usize, alloc: A) -> Self {
        Self { ptr: unsafe { NonNull::new_unchecked(ptr) }, cap, alloc }
    }

    #[inline]
    const fn allocator(&self) -> &A {
        &self.alloc
    }

    #[inline]
    fn current_memory(&self, elem_layout: Layout) -> Option<(NonNull<u8>, Layout)> {
        if elem_layout.size() == 0 || self.cap == 0 {
            None
        } else {
            // We could use Layout::array here which ensures the absence of isize and usize
            // overflows and could hypothetically handle differences between stride and
            // size, but this memory has already been allocated so we know it can't
            // overflow and currently Rust does not support such types. So we can do
            // better by skipping some checks and avoid an unwrap.
            unsafe {
                let alloc_size = elem_layout.size().unchecked_mul(self.cap);
                let layout = Layout::from_size_align_unchecked(alloc_size, elem_layout.align());
                Some((self.ptr, layout))
            }
        }
    }

    #[inline]
    fn try_with_capacity_in<T>(capacity: usize, alloc: A) -> Result<Self, TryReserveError> {
        Self::try_allocate_in::<T>(capacity, alloc)
    }

    /// # Safety
    ///
    /// This function deallocates the owned allocation, but does not update `ptr` or `cap` to
    /// prevent double-free or use-after-free. Essentially, do not do anything with the caller
    /// after this function returns.
    /// Ideally this function would take `self` by move, but it cannot because it exists to be
    /// called from a `Drop` impl.
    unsafe fn deallocate(&mut self, elem_layout: Layout) {
        if let Some((ptr, layout)) = self.current_memory(elem_layout) {
            unsafe {
                self.alloc.deallocate(ptr, layout);
            }
        }
    }
}

impl<T, A: Allocator> Drop for RawBuffer<T, A> {
    /// Frees the memory owned by the `RawVec` *without* trying to drop its contents.
    fn drop(&mut self) {
        // SAFETY: We are in a Drop impl, self.inner will not be used again.
        unsafe {
            let layout =
                Layout::from_size_align_unchecked(mem::size_of::<T>(), mem::align_of::<T>());
            self.inner.deallocate(layout)
        }
    }
}

// Central function for reserve error handling.
#[cold]
fn handle_error(e: TryReserveError) -> ! {
    match e {
        TryReserveError::CapacityOverflow => capacity_overflow(),
        TryReserveError::AllocError { layout } => handle_alloc_error(layout),
    }
}

// One central function responsible for reporting capacity overflows. This'll
// ensure that the code generation related to these panics is minimal as there's
// only one location which panics rather than a bunch throughout the module.
#[inline(never)]
fn capacity_overflow() -> ! {
    panic!("capacity overflow");
}

#[cold]
pub const fn handle_alloc_error(layout: Layout) -> ! {
    const fn ct_error(_: Layout) -> ! {
        panic!("allocation failed");
    }

    ct_error(layout)
}

// We need to guarantee the following:
// * We don't ever allocate `> isize::MAX` byte-size objects.
// * We don't overflow `usize::MAX` and actually allocate too little.
//
// On 64-bit we just need to check for overflow since trying to allocate
// `> isize::MAX` bytes will surely fail. On 32-bit and 16-bit we need to add
// an extra guard for this in case we're running on a platform which can use
// all 4GB in user-space, e.g., PAE or x32.
#[inline]
fn alloc_guard(alloc_size: usize) -> Result<(), TryReserveError> {
    if usize::BITS < 64 && alloc_size > isize::MAX as usize {
        Err(TryReserveError::CapacityOverflow)
    } else {
        Ok(())
    }
}
