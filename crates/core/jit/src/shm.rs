//! POSIX shared-memory wrappers (memfd + mmap).
//!
//! P1 (skeleton): types only.  Functional impls land in P5 (trace ring)
//! and P6 (fork-based crash isolation).  Modeled on SP1's
//! `crates/core/jit/src/shm.rs`.

#![cfg(all(target_arch = "x86_64", target_os = "linux"))]

use std::os::fd::{AsRawFd, RawFd};

/// Crash details propagated from a forked child JIT process to the
/// parent.  Lives in shared memory so even a SIGSEGV'd child can leave
/// useful info behind.  Filled in P6.
#[repr(C)]
pub struct CrashDetails {
    /// Signal that killed the child (e.g. SIGSEGV = 11).
    pub signal: i32,
    /// Faulting address (set by the SIGSEGV handler in the child).
    pub fault_addr: u64,
    /// MIPS PC at the time of the fault.
    pub mips_pc: u32,
    /// Number of MIPS instructions executed before the fault.
    pub instr_count: u64,
}

/// Single-producer/single-consumer ring buffer for trace events.
/// Producer = JIT'd code (writes via raw pointer offsets); consumer
/// = host-side Rust thread.  Atomic head/tail in the first 16 bytes
/// of the underlying shm region; events follow.
///
/// Each event is a fixed-size record (`event_size` bytes).  Producer
/// writes at `tail % capacity`, then atomically bumps `tail`.
/// Consumer reads from `head % capacity`, processes, then atomically
/// bumps `head`.  Capacity is a power of two so wrap-around is a
/// bitwise AND.
#[repr(C)]
pub struct ShmTraceRingHeader {
    /// Atomic write cursor (producer).
    pub tail: std::sync::atomic::AtomicU64,
    /// Atomic read cursor (consumer).
    pub head: std::sync::atomic::AtomicU64,
}

/// Wrapper around `ShmMemory` that exposes the trace-ring layout.
pub struct ShmTraceRing {
    shm: ShmMemory,
    capacity: usize,
    event_size: usize,
}

impl ShmTraceRing {
    /// Allocate a new trace ring with `capacity` event slots, each
    /// `event_size` bytes.  `capacity` must be a power of two.
    ///
    /// # Errors
    ///
    /// Returns `Err` if shm allocation fails.
    pub fn new(capacity: usize, event_size: usize) -> std::io::Result<Self> {
        assert!(capacity.is_power_of_two(), "capacity must be power of two");
        let total = std::mem::size_of::<ShmTraceRingHeader>() + capacity * event_size;
        let mut shm = ShmMemory::new(total)?;
        // Zero the header.
        let header_ptr = shm.as_mut_ptr().cast::<ShmTraceRingHeader>();
        unsafe {
            std::ptr::write(
                header_ptr,
                ShmTraceRingHeader {
                    tail: std::sync::atomic::AtomicU64::new(0),
                    head: std::sync::atomic::AtomicU64::new(0),
                },
            );
        }
        Ok(Self {
            shm,
            capacity,
            event_size,
        })
    }

    /// Pointer to the ring header (atomic head/tail).
    #[must_use]
    pub fn header(&self) -> *const ShmTraceRingHeader {
        self.shm.as_ptr().cast()
    }

    /// Mutable pointer to the ring header.
    #[must_use]
    pub fn header_mut(&mut self) -> *mut ShmTraceRingHeader {
        self.shm.as_mut_ptr().cast()
    }

    /// Pointer to the start of the event-slot region.
    #[must_use]
    pub fn slots_ptr(&self) -> *const u8 {
        unsafe {
            self.shm
                .as_ptr()
                .add(std::mem::size_of::<ShmTraceRingHeader>())
        }
    }

    /// Number of event slots.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Per-event byte size.
    #[must_use]
    pub fn event_size(&self) -> usize {
        self.event_size
    }
}

/// Producer-side guard: held by the JIT'd code (or its host-side
/// shim).  Writes a single event at the current tail and bumps the
/// counter atomically.  Blocks on full ring (consumer hasn't drained).
pub struct ProducerGuard<'a> {
    ring: &'a mut ShmTraceRing,
}

impl<'a> ProducerGuard<'a> {
    /// New producer guard.  Caller asserts single-producer.
    pub fn new(ring: &'a mut ShmTraceRing) -> Self {
        Self { ring }
    }

    /// Push one event into the ring.  Spins if the ring is full.
    ///
    /// # Safety
    ///
    /// `event` must be exactly `ring.event_size()` bytes.
    pub unsafe fn push(&mut self, event: &[u8]) {
        debug_assert_eq!(event.len(), self.ring.event_size);
        let header = unsafe { &*self.ring.header() };
        let tail = header.tail.load(std::sync::atomic::Ordering::Relaxed);
        let head = header.head.load(std::sync::atomic::Ordering::Acquire);
        // Spin while ring is full.
        while tail.wrapping_sub(head) >= self.ring.capacity as u64 {
            std::hint::spin_loop();
        }
        let slot_idx = (tail as usize) & (self.ring.capacity - 1);
        let dst = unsafe {
            (self.ring.slots_ptr() as *mut u8).add(slot_idx * self.ring.event_size)
        };
        unsafe {
            std::ptr::copy_nonoverlapping(event.as_ptr(), dst, self.ring.event_size);
        }
        header
            .tail
            .store(tail + 1, std::sync::atomic::Ordering::Release);
    }
}

/// Consumer-side guard: held by the host Rust thread that drains the
/// ring.
pub struct ConsumerGuard<'a> {
    ring: &'a ShmTraceRing,
}

impl<'a> ConsumerGuard<'a> {
    /// New consumer guard.
    #[must_use]
    pub fn new(ring: &'a ShmTraceRing) -> Self {
        Self { ring }
    }

    /// Pop one event from the ring.  Returns `None` if empty.
    ///
    /// The returned slice is borrowed from the shm region; copy it
    /// out before releasing the guard or before the next `push`.
    #[must_use]
    pub fn pop(&self) -> Option<&[u8]> {
        let header = unsafe { &*self.ring.header() };
        let head = header.head.load(std::sync::atomic::Ordering::Relaxed);
        let tail = header.tail.load(std::sync::atomic::Ordering::Acquire);
        if head == tail {
            return None;
        }
        let slot_idx = (head as usize) & (self.ring.capacity - 1);
        let src = unsafe {
            self.ring.slots_ptr().add(slot_idx * self.ring.event_size)
        };
        let slice =
            unsafe { std::slice::from_raw_parts(src, self.ring.event_size) };
        header
            .head
            .store(head + 1, std::sync::atomic::Ordering::Release);
        Some(slice)
    }
}

/// A handle to a POSIX shared-memory object.  P5 will use this for the
/// trace ring; P6 will use it for guest memory shared with the forked
/// child.
pub struct ShmMemory {
    fd: RawFd,
    map_ptr: *mut libc::c_void,
    len: usize,
}

impl ShmMemory {
    /// Allocate a new shared-memory region of `size` bytes via memfd.
    ///
    /// # Errors
    ///
    /// Returns `Err` if `memfd_create` or `mmap` fails.
    pub fn new(size: usize) -> std::io::Result<Self> {
        let fd = memfd::MemfdOptions::default()
            .close_on_exec(false)
            .create("zkm-jit-shm")
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        let raw_fd = fd.as_raw_fd();

        // Re-set length.
        if unsafe { libc::ftruncate(raw_fd, size as libc::off_t) } < 0 {
            return Err(std::io::Error::last_os_error());
        }

        // Map shared so a forked child sees the same bytes.
        let map_ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                raw_fd,
                0,
            )
        };
        if map_ptr == libc::MAP_FAILED {
            return Err(std::io::Error::last_os_error());
        }

        // Persist the fd; once `Memfd` drops the kernel will reclaim
        // the object on last close.
        let dup = unsafe { libc::dup(raw_fd) };
        if dup < 0 {
            return Err(std::io::Error::last_os_error());
        }

        Ok(Self {
            fd: dup,
            map_ptr,
            len: size,
        })
    }

    /// Pointer to the mapped region.
    #[must_use]
    pub fn as_ptr(&self) -> *const u8 {
        self.map_ptr.cast()
    }

    /// Mutable pointer to the mapped region.
    #[must_use]
    pub fn as_mut_ptr(&mut self) -> *mut u8 {
        self.map_ptr.cast()
    }

    /// Length in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.len
    }

    /// `true` iff zero-length.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl Drop for ShmMemory {
    fn drop(&mut self) {
        unsafe {
            libc::munmap(self.map_ptr, self.len);
            libc::close(self.fd);
        }
    }
}

impl AsRawFd for ShmMemory {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

// SAFETY: The mmap region is owned by this struct; clones / sharing
// across threads requires explicit synchronization by the caller.
unsafe impl Send for ShmMemory {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shm_round_trip() -> std::io::Result<()> {
        let mut shm = ShmMemory::new(4096)?;
        unsafe {
            *shm.as_mut_ptr() = 0xAB;
        }
        assert_eq!(unsafe { *shm.as_ptr() }, 0xAB);
        assert_eq!(shm.len(), 4096);
        Ok(())
    }

    #[test]
    fn ring_push_pop_round_trip() -> std::io::Result<()> {
        let mut ring = ShmTraceRing::new(16, 8)?;
        {
            let mut prod = ProducerGuard::new(&mut ring);
            unsafe {
                prod.push(&1u64.to_le_bytes());
                prod.push(&2u64.to_le_bytes());
                prod.push(&3u64.to_le_bytes());
            }
        }
        let cons = ConsumerGuard::new(&ring);
        assert_eq!(cons.pop().map(|s| s.to_vec()), Some(1u64.to_le_bytes().to_vec()));
        assert_eq!(cons.pop().map(|s| s.to_vec()), Some(2u64.to_le_bytes().to_vec()));
        assert_eq!(cons.pop().map(|s| s.to_vec()), Some(3u64.to_le_bytes().to_vec()));
        assert!(cons.pop().is_none());
        Ok(())
    }
}
