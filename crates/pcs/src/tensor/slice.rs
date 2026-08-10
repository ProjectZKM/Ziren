//! PORTED VERBATIM from SP1 `slop/crates/alloc/src/slice.rs` (succinctlabs/sp1) for the
//! Ziren backend-generic tensor stack — a full SP1-fidelity Buffer port.
//! Ziren adaptations vs upstream: `crate::` -> `crate::tensor::`; `thiserror` errors
//! hand-written; `slop_algebra` -> `p3_field`. Only `CpuBackend` is implemented here
//! (host stays device-dependency-free); `ziren-gpu` implements `CudaBackend` against
//! this `Backend`/`RawBuffer`/`Slice`/`DeviceMemory` abstraction.

use std::{
    alloc::Layout,
    marker::PhantomData,
    ops::{
        Deref, DerefMut, Index, IndexMut, Range, RangeFrom, RangeFull, RangeInclusive, RangeTo,
        RangeToInclusive,
    },
};

use crate::tensor::{
    backend::CpuBackend,
    mem::{CopyDirection, CopyError, DeviceMemory},
    Allocator, Init,
};

/// A slice of data associated with a specific allocator type.
///
/// This type is enssentially a wrapper around a slice and has an indicator for the type of the
/// allocator to induicate where the memory resides but it
#[repr(transparent)]
pub struct Slice<T, A = CpuBackend> {
    allocator: PhantomData<A>,
    slice: [T],
}

impl<T, A: Allocator> Slice<T, A> {
    #[inline]
    pub const fn len(&self) -> usize {
        self.slice.len()
    }

    #[inline]
    pub const fn is_empty(&self) -> bool {
        self.slice.is_empty()
    }

    #[inline]
    pub fn as_ptr(&self) -> *const T {
        self.slice.as_ptr()
    }

    #[inline]
    pub fn as_mut_ptr(&mut self) -> *mut T {
        self.slice.as_mut_ptr()
    }

    #[inline(always)]
    pub(crate) unsafe fn from_slice(src: &[T]) -> &Self {
        &*(src as *const [T] as *const Self)
    }

    /// # Safety
    #[inline]
    pub unsafe fn from_raw_parts<'a>(data: *const T, len: usize) -> &'a Self {
        Self::from_slice(std::slice::from_raw_parts(data, len))
    }

    #[inline(always)]
    pub(crate) unsafe fn from_slice_mut(src: &mut [T]) -> &mut Self {
        &mut *(src as *mut [T] as *mut Self)
    }

    /// # Safety
    pub unsafe fn from_raw_parts_mut<'a>(data: *mut T, len: usize) -> &'a mut Self {
        Self::from_slice_mut(std::slice::from_raw_parts_mut(data, len))
    }

    #[inline]
    pub fn split_at_mut(&mut self, mid: usize) -> (&mut Self, &mut Self) {
        let (left, right) = self.slice.split_at_mut(mid);
        unsafe { (Self::from_slice_mut(left), Self::from_slice_mut(right)) }
    }

    #[inline]
    pub fn split_at(&self, mid: usize) -> (&Self, &Self) {
        let (left, right) = self.slice.split_at(mid);
        unsafe { (Self::from_slice(left), Self::from_slice(right)) }
    }

    /// Copies all elements from `src` into `self`, using `copy_nonoverlapping`.
    ///
    /// The length of `src` must be the same as `self`.
    ///
    /// # Panics
    ///
    /// This function will panic if the two slices have different lengths or if cudaMalloc
    /// returned an error.
    ///
    /// # Safety
    /// This operation is potentially asynchronous. The caller must insure the memory of the source
    /// is valid for the duration of the operation.
    #[inline]
    #[track_caller]
    pub unsafe fn copy_from_slice(
        &mut self,
        src: &Slice<T, A>,
        allocator: &A,
    ) -> Result<(), CopyError>
    where
        A: DeviceMemory,
    {
        // The panic code path was put into a cold function to not bloat the
        // call site.
        #[inline(never)]
        #[cold]
        #[track_caller]
        fn len_mismatch_fail(dst_len: usize, src_len: usize) -> ! {
            panic!(
                "source slice length ({src_len}) does not match destination slice length ({dst_len})",
            );
        }

        if self.len() != src.len() {
            len_mismatch_fail(self.len(), src.len());
        }

        let layout = Layout::array::<T>(src.len()).unwrap();

        unsafe {
            allocator.copy_nonoverlapping(
                src.as_ptr() as *const u8,
                self.as_mut_ptr() as *mut u8,
                layout.size(),
                CopyDirection::DeviceToDevice,
            )
        }
    }
}

macro_rules! impl_index {
    ($($t:ty)*) => {
        $(
            impl<T, A: Allocator> Index<$t> for Slice<T, A>
            {
                type Output = Slice<T, A>;

                fn index(&self, index: $t) -> &Self {
                    unsafe { Slice::from_slice(self.slice.index(index)) }
                }
            }

            impl<T, A: Allocator> IndexMut<$t> for Slice<T, A>
            {
                fn index_mut(&mut self, index: $t) -> &mut Self {
                    unsafe { Slice::from_slice_mut( self.slice.index_mut(index)) }
                }
            }
        )*
    }
}

impl_index! {
    Range<usize>
    RangeFull
    RangeFrom<usize>
    RangeInclusive<usize>
    RangeTo<usize>
    RangeToInclusive<usize>
}

impl<T, A: Allocator> Index<usize> for Slice<T, A> {
    type Output = Init<T, A>;

    #[inline]
    fn index(&self, index: usize) -> &Self::Output {
        let ptr = self.slice.index(index) as *const T as *const Init<T, A>;
        unsafe { ptr.as_ref().unwrap() }
    }
}

impl<T, A: Allocator> IndexMut<usize> for Slice<T, A> {
    #[inline]
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        let ptr = self.slice.index_mut(index) as *mut T as *mut Init<T, A>;
        unsafe { ptr.as_mut().unwrap() }
    }
}

impl<T> Slice<T, CpuBackend> {
    #[inline]
    pub fn to_vec(&self) -> Vec<T>
    where
        T: Clone,
    {
        self.slice.to_vec()
    }
}

impl<T> Deref for Slice<T, CpuBackend> {
    type Target = [T];

    fn deref(&self) -> &Self::Target {
        unsafe { std::slice::from_raw_parts(self.as_ptr(), self.len()) }
    }
}

impl<T> DerefMut for Slice<T, CpuBackend> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { std::slice::from_raw_parts_mut(self.as_mut_ptr(), self.len()) }
    }
}

impl<T: PartialEq> PartialEq for Slice<T, CpuBackend> {
    fn eq(&self, other: &Self) -> bool {
        self.slice == other.slice
    }
}

impl<T: Eq> Eq for Slice<T, CpuBackend> {}
