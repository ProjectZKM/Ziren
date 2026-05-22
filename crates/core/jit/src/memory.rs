//! JIT memory traits and impls.
//!
//! P1 (skeleton): trait declarations and a non-shared anon-mmap
//! `OwnedMemory` impl for in-process testing.  P2 will add the
//! memfd-backed `ShmMemory` impl needed for fork-based crash isolation
//! (see [`crate::shm`]).

use std::ops::{Deref, DerefMut};
use std::os::fd::{AsRawFd, RawFd};

/// JIT-side memory backing.  Implementations expose a contiguous byte
/// region accessible by the JIT'd code via `memory_ptr` (in
/// [`crate::JitContext`]).
pub trait JitMemory: Sized + Deref<Target = [u8]> + DerefMut + AsRawFd {
    /// Allocate a new memory region of the given size.
    fn new(memory_size: usize) -> Self;
}

/// Memory backings that support a `reset()` operation, used to clear
/// state between JIT invocations of the same program (e.g. test
/// suites running many programs sequentially).
pub trait JitResetableMemory: JitMemory {
    /// Reset all bytes of the memory region to zero.
    fn reset(&mut self);
}

/// In-process anon-mmap memory backing.  Used as the default in v1 —
/// the memfd-backed [`crate::shm::ShmMemory`] becomes the production
/// default once P6 (crash isolation) lands.
#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
pub struct OwnedMemory {
    map: memmap2::MmapMut,
}

#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
impl OwnedMemory {
    /// Returns the size of the underlying mmap'd region in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Returns `true` if the underlying region is zero-length.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
impl JitMemory for OwnedMemory {
    fn new(memory_size: usize) -> Self {
        let map = memmap2::MmapOptions::new()
            .len(memory_size)
            .map_anon()
            .expect("anon mmap for JIT memory");
        Self { map }
    }
}

#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
impl JitResetableMemory for OwnedMemory {
    fn reset(&mut self) {
        // Use madvise(MADV_DONTNEED) for a fast page-table reset;
        // touched pages return zero on next access.
        unsafe {
            libc::madvise(
                self.map.as_mut_ptr().cast(),
                self.map.len(),
                libc::MADV_DONTNEED,
            );
        }
    }
}

#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
impl Deref for OwnedMemory {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        &self.map[..]
    }
}

#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
impl DerefMut for OwnedMemory {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.map[..]
    }
}

#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
impl AsRawFd for OwnedMemory {
    fn as_raw_fd(&self) -> RawFd {
        // Anon mmap has no fd; return -1 to indicate "no shared
        // descriptor".  Code paths that actually need an fd (P6 fork
        // isolation) must use `crate::shm::ShmMemory` instead.
        -1
    }
}

#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn owned_memory_round_trip() {
        let mut mem = OwnedMemory::new(4096);
        assert_eq!(mem.len(), 4096);
        mem[0] = 0xAB;
        mem[4095] = 0xCD;
        assert_eq!(mem[0], 0xAB);
        assert_eq!(mem[4095], 0xCD);
    }

    #[test]
    fn owned_memory_reset_zeros_pages() {
        let mut mem = OwnedMemory::new(4096);
        mem[0] = 0xAB;
        mem.reset();
        assert_eq!(mem[0], 0);
    }
}
