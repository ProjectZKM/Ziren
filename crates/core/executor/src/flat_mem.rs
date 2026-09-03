//! Flat guest memory for the minimal-trace PRODUCER.
//!
//! The paged `Memory` behind `state.memory` costs a two-level table walk plus
//! an `Option` probe per access, and its page-granular checkpoint/diff
//! bookkeeping was written for the checkpoint executor. The producer (the
//! multi-GPU parent running `execute_minimal`) needs none of that: it runs in
//! `Simple` mode, never restores a checkpoint, and rolls an unconstrained
//! block back wholesale. SP1's producer (`sp1_jit`) keeps guest memory as one
//! flat array of 16-byte `{clk, word}` entries for the same reason; this is
//! the Ziren shape of it, `{value, timestamp, shard}` because Ziren's memory
//! records carry the shard as well.
//!
//! One entry per guest WORD, indexed by `addr >> 2` -- the same aliasing of
//! unaligned addresses the paged table has (`PagedMemory::compress_addr`).
//! The array is a `MAP_SHARED | MAP_NORESERVE` view of a `memfd`, so it is
//! sparse (only touched pages are ever committed) and an unconstrained block
//! can be entered by mapping a `MAP_PRIVATE` copy-on-write view of the same
//! fd and left by unmapping it -- the rollback the paged executor does with a
//! per-address `memory_diff` becomes one `munmap`.
//!
//! An entry's first 12 bytes are exactly a [`crate::minimal_trace::MemValue`]
//! image, so the producer's oracle push is one 12-byte copy of the entry as
//! it stood before the access.
use crate::minimal_trace::MemValue;
use crate::MAX_MEMORY;

/// One guest word: `{value, timestamp, shard}` plus padding to 16 bytes.
///
/// `shard == 0 && timestamp == 0` is the never-accessed state the paged
/// table represents by absence; `value` then holds the program image word, a
/// hint word (see [`FlatMem::seed_uninit`]) or 0.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FlatEntry {
    /// The word.
    pub value: u32,
    /// Timestamp of the last access, 0 if never accessed.
    pub timestamp: u32,
    /// Shard of the last access, 0 if never accessed.
    pub shard: u32,
    /// Padding: 16-byte entries keep `addr >> 2` a shift-and-scale index.
    pub _pad: u32,
}

const _: () = assert!(std::mem::size_of::<FlatEntry>() == 16);
const _: () = assert!(std::mem::size_of::<MemValue>() == 12);
const _: () = assert!(std::mem::align_of::<FlatEntry>() == 4);

impl FlatEntry {
    /// The entry as the oracle's pre-access record.
    #[inline]
    #[must_use]
    pub const fn mem_value(&self) -> MemValue {
        MemValue { value: self.value, timestamp: self.timestamp, shard: self.shard }
    }
}

/// Entries the array holds: every word address the paged table can address.
/// `PagedMemory` indexes `MAX_MEMORY / 4 / PAGE_LEN + 1` pages of `PAGE_LEN`
/// words; anything beyond panics there and panics here.
const PAGE_LEN: usize = 1 << 14;
const NUM_ENTRIES: usize = (MAX_MEMORY / 4 / PAGE_LEN + 1) * PAGE_LEN;
const BYTE_LEN: usize = NUM_ENTRIES * std::mem::size_of::<FlatEntry>();

/// The flat memory. See the module docs.
#[cfg(target_os = "linux")]
pub struct FlatMem {
    /// The live view: `primary` outside an unconstrained block, the COW
    /// mapping inside one.
    cur: *mut FlatEntry,
    /// The `MAP_SHARED` view of the fd. Writes through it persist on the fd,
    /// so a later `MAP_PRIVATE` view starts as a copy of the current state.
    primary: *mut FlatEntry,
    /// The `MAP_PRIVATE` view in effect inside an unconstrained block.
    cow: *mut FlatEntry,
    /// The backing `memfd`.
    fd: libc::c_int,
}

// SAFETY: the mappings are process-wide and only ever touched through the
// owning `FlatMem`; the executor that owns it is used from one thread at a
// time.
#[cfg(target_os = "linux")]
unsafe impl Send for FlatMem {}

#[cfg(target_os = "linux")]
impl FlatMem {
    /// Map a fresh, all-zero flat memory.
    ///
    /// # Errors
    /// The `memfd_create` / `ftruncate` / `mmap` error.
    pub fn new() -> std::io::Result<Self> {
        let name = b"ziren-flat-mem\0";
        let fd = unsafe {
            libc::syscall(
                libc::SYS_memfd_create,
                name.as_ptr() as *const libc::c_char,
                libc::MFD_CLOEXEC,
            ) as libc::c_int
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        if unsafe { libc::ftruncate(fd, BYTE_LEN as libc::off_t) } != 0 {
            let err = std::io::Error::last_os_error();
            unsafe { libc::close(fd) };
            return Err(err);
        }
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                BYTE_LEN,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED | libc::MAP_NORESERVE,
                fd,
                0,
            )
        };
        if ptr == libc::MAP_FAILED {
            let err = std::io::Error::last_os_error();
            unsafe { libc::close(fd) };
            return Err(err);
        }
        let primary = ptr.cast::<FlatEntry>();
        Ok(Self { cur: primary, primary, cow: std::ptr::null_mut(), fd })
    }

    #[inline]
    fn index(addr: u32) -> usize {
        let idx = (addr >> 2) as usize;
        assert!(idx < NUM_ENTRIES, "guest address {addr:#x} beyond MAX_MEMORY");
        idx
    }

    /// The entry of the word containing `addr`.
    #[inline]
    #[must_use]
    pub fn get(&self, addr: u32) -> &FlatEntry {
        // SAFETY: `index` bounds the offset inside the mapping, which lives
        // as long as `self`.
        unsafe { &*self.cur.add(Self::index(addr)) }
    }

    /// The entry of the word containing `addr`, mutably.
    #[inline]
    pub fn get_mut(&mut self, addr: u32) -> &mut FlatEntry {
        // SAFETY: as in `get`; `&mut self` makes the reference unique.
        unsafe { &mut *self.cur.add(Self::index(addr)) }
    }

    /// The live view's base pointer (the JIT's memory register).
    #[inline]
    #[must_use]
    pub fn as_ptr(&self) -> *mut FlatEntry {
        self.cur
    }

    /// Seed a never-accessed word with an initial value (a program-image word
    /// or a hint word), the flat form of `uninitialized_memory`. A no-op on a
    /// word that has already been accessed, exactly as the paged executor's
    /// first-touch `uninitialized_memory` lookup never sees a later hint.
    #[inline]
    pub fn seed_uninit(&mut self, addr: u32, value: u32) {
        let e = self.get_mut(addr);
        if e.shard == 0 && e.timestamp == 0 {
            e.value = value;
        }
    }

    /// Whether an unconstrained block is open.
    #[inline]
    #[must_use]
    pub fn in_unconstrained(&self) -> bool {
        !self.cow.is_null()
    }

    /// Enter an unconstrained block: every access from here on goes to a
    /// private copy-on-write view of the memory.
    ///
    /// # Errors
    /// The `mmap` error.
    pub fn enter_unconstrained(&mut self) -> std::io::Result<()> {
        assert!(!self.in_unconstrained(), "nested unconstrained block");
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                BYTE_LEN,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_NORESERVE,
                self.fd,
                0,
            )
        };
        if ptr == libc::MAP_FAILED {
            return Err(std::io::Error::last_os_error());
        }
        self.cow = ptr.cast();
        self.cur = self.cow;
        Ok(())
    }

    /// Leave an unconstrained block, discarding every access made inside it.
    pub fn exit_unconstrained(&mut self) {
        assert!(self.in_unconstrained(), "exit_unconstrained outside a block");
        unsafe {
            libc::munmap(self.cow.cast(), BYTE_LEN);
        }
        self.cow = std::ptr::null_mut();
        self.cur = self.primary;
    }

    /// Every entry that may have been written, in ascending address order:
    /// the data extents of the backing fd (`SEEK_DATA` / `SEEK_HOLE`), which
    /// hold exactly the pages some access has committed. Never-committed
    /// pages are holes and hold nothing. Must not be called inside an
    /// unconstrained block (its pages are private to the COW view).
    ///
    /// Yields `(addr, entry)` for entries with `f(entry)`.
    pub fn for_each_committed(&self, mut f: impl FnMut(u32, &FlatEntry)) {
        assert!(!self.in_unconstrained(), "for_each_committed inside an unconstrained block");
        let entry_len = std::mem::size_of::<FlatEntry>() as libc::off_t;
        let end = BYTE_LEN as libc::off_t;
        let mut off: libc::off_t = 0;
        while off < end {
            let data = unsafe { libc::lseek(self.fd, off, libc::SEEK_DATA) };
            if data < 0 {
                // ENXIO: no more data past `off`.
                break;
            }
            let hole = unsafe { libc::lseek(self.fd, data, libc::SEEK_HOLE) };
            let hole = if hole < 0 { end } else { hole.min(end) };
            let first = (data / entry_len) as usize;
            let last = (hole / entry_len) as usize;
            for idx in first..last {
                // SAFETY: `idx < NUM_ENTRIES` since `hole <= BYTE_LEN`.
                let e = unsafe { &*self.primary.add(idx) };
                f((idx as u32) << 2, e);
            }
            off = hole;
        }
    }
}

#[cfg(target_os = "linux")]
impl Drop for FlatMem {
    fn drop(&mut self) {
        unsafe {
            if !self.cow.is_null() {
                libc::munmap(self.cow.cast(), BYTE_LEN);
            }
            libc::munmap(self.primary.cast(), BYTE_LEN);
            libc::close(self.fd);
        }
    }
}

/// The flat memory is `memfd` + `SEEK_DATA`, Linux only: elsewhere it never
/// constructs and the executor stays on the paged table.
#[cfg(not(target_os = "linux"))]
pub struct FlatMem {
    _never: std::convert::Infallible,
}

#[cfg(not(target_os = "linux"))]
impl FlatMem {
    /// Always `Err`: unsupported platform.
    ///
    /// # Errors
    /// Always.
    pub fn new() -> std::io::Result<Self> {
        Err(std::io::Error::new(std::io::ErrorKind::Unsupported, "flat memory is Linux-only"))
    }
    #[inline]
    #[must_use]
    pub fn get(&self, _addr: u32) -> &FlatEntry {
        match self._never {}
    }
    #[inline]
    pub fn get_mut(&mut self, _addr: u32) -> &mut FlatEntry {
        match self._never {}
    }
    #[must_use]
    pub fn as_ptr(&self) -> *mut FlatEntry {
        match self._never {}
    }
    pub fn seed_uninit(&mut self, _addr: u32, _value: u32) {
        match self._never {}
    }
    #[must_use]
    pub fn in_unconstrained(&self) -> bool {
        match self._never {}
    }
    /// # Errors
    /// Never returns.
    pub fn enter_unconstrained(&mut self) -> std::io::Result<()> {
        match self._never {}
    }
    pub fn exit_unconstrained(&mut self) {
        match self._never {}
    }
    pub fn for_each_committed(&self, _f: impl FnMut(u32, &FlatEntry)) {
        match self._never {}
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    fn cow_rollback_and_extents() {
        let mut m = FlatMem::new().expect("flat mem");
        let a = 0x1000_0000u32;
        let b = 0x4000_0004u32;
        m.get_mut(a).value = 7;
        m.get_mut(a).shard = 1;
        m.seed_uninit(b, 9);
        m.enter_unconstrained().expect("cow");
        m.get_mut(a).value = 8;
        m.get_mut(0x2000_0000).value = 5;
        m.get_mut(0x2000_0000).shard = 1;
        assert_eq!(m.get(a).value, 8);
        m.exit_unconstrained();
        assert_eq!(m.get(a).value, 7);
        assert_eq!(m.get(0x2000_0000).shard, 0);
        let mut seen = Vec::new();
        m.for_each_committed(|addr, e| {
            if e.shard != 0 || e.value != 0 {
                seen.push((addr, e.value, e.shard));
            }
        });
        assert_eq!(seen, vec![(a, 7, 1), (b, 9, 0)]);
        // Seeding an accessed word is a no-op.
        m.seed_uninit(a, 100);
        assert_eq!(m.get(a).value, 7);
    }
}
