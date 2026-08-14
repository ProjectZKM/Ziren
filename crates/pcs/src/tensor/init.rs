//! Part of the Ziren backend-generic tensor stack. Only `CpuBackend` is implemented here
//! (host stays device-dependency-free); `ziren-gpu` implements `CudaBackend` against
//! this `Backend`/`RawBuffer`/`Slice`/`DeviceMemory` abstraction.

use std::{
    alloc::Layout,
    marker::PhantomData,
    mem::MaybeUninit,
    ops::{Deref, DerefMut},
};

use crate::tensor::{backend::CpuBackend, mem::CopyDirection, Allocator, Backend};

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct Init<T, A = CpuBackend> {
    inner: T,
    _marker: PhantomData<A>,
}

impl<T, A: Allocator> Init<T, A> {
    #[inline]
    pub const fn as_ptr(&self) -> *const T {
        &self.inner
    }

    #[inline]
    pub fn as_mut_ptr(&mut self) -> *mut T {
        &mut self.inner
    }

    pub fn copy_into_host(&self, alloc: &A) -> T
    where
        A: Backend,
        T: Copy,
    {
        let mut value = MaybeUninit::<T>::uninit();
        let layout = Layout::new::<T>();
        unsafe {
            alloc
                .copy_nonoverlapping(
                    self.as_ptr() as *const u8,
                    value.as_mut_ptr() as *mut u8,
                    layout.size(),
                    CopyDirection::DeviceToHost,
                )
                .unwrap();

            value.assume_init()
        }
    }
}

impl<T> Deref for Init<T, CpuBackend> {
    type Target = T;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<T> DerefMut for Init<T, CpuBackend> {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl<T: Clone> Clone for Init<T, CpuBackend> {
    fn clone(&self) -> Self {
        Self { inner: self.inner.clone(), _marker: PhantomData }
    }
}

impl<T: Copy> Copy for Init<T, CpuBackend> {}
