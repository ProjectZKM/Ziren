use std::cell::UnsafeCell;
use std::mem::{self, MaybeUninit};

use p3_field::PrimeField64;
use vec_map::{Entry, VecMap};

use crate::{air::Block, Address};

#[derive(Debug, Clone, Default, Copy)]
pub struct MemoryEntry<F> {
    pub val: Block<F>,
    pub mult: F,
}

pub trait Memory<F> {
    /// Allocates memory with at least the given capacity.
    fn with_capacity(capacity: usize) -> Self;

    /// Read from a memory address.
    ///
    /// The previous `mr_mult(addr, mult)` API decremented
    /// `MemoryEntry::mult` on every read. The decrement result was
    /// never read by any consumer (chips read mult from the
    /// instruction-side preprocessed columns, not from `MemoryEntry`),
    /// so the bookkeeping was dead code. Mirroring SP1's `MemVec`
    /// (crates/recursion/executor/src/memory.rs), the only read API
    /// is `mr` — no mult decrement happens at runtime.  This removes
    /// the last barrier to using `ParMemVec` for parallel
    /// `SeqBlock::Parallel` execution: with no shared mult counter to
    /// alias, concurrent reads of disjoint addresses are race-free
    /// without atomics.
    ///
    /// # Panics
    /// Panics if the address is unassigned.
    fn mr(&mut self, addr: Address<F>) -> &mut MemoryEntry<F>;

    /// Write to a memory address, setting the given value and mult.
    ///
    /// `mult` is stored on the entry but never read at runtime; it is
    /// retained only so the existing tests / future audit hooks can
    /// inspect the originally-written value. A later cleanup may drop
    /// the field entirely once the parallel runtime is wired and the
    /// chip-side audit confirms it never reads `MemoryEntry::mult`.
    ///
    /// # Panics
    /// Panics if the address is already assigned.
    fn mw(&mut self, addr: Address<F>, val: Block<F>, mult: F) -> &mut MemoryEntry<F>;
}

#[derive(Clone, Debug, Default)]
pub struct MemVecMap<F>(pub VecMap<MemoryEntry<F>>);

impl<F: PrimeField64> Memory<F> for MemVecMap<F> {
    fn with_capacity(capacity: usize) -> Self {
        Self(VecMap::with_capacity(capacity))
    }

    fn mr(&mut self, addr: Address<F>) -> &mut MemoryEntry<F> {
        match self.0.entry(addr.as_usize()) {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(_) => panic!("tried to read from unassigned address: {addr:?}",),
        }
    }

    fn mw(&mut self, addr: Address<F>, val: Block<F>, mult: F) -> &mut MemoryEntry<F> {
        let index = addr.as_usize();
        match self.0.entry(index) {
            Entry::Occupied(entry) => {
                panic!("tried to write to assigned address {}: {:?}", index, entry.get())
            }
            Entry::Vacant(entry) => entry.insert(MemoryEntry { val, mult }),
        }
    }
}

#[derive(Clone, Debug, Default)]
#[allow(dead_code)]
pub struct MemVec<F>(pub Vec<Option<MemoryEntry<F>>>);

impl<F: PrimeField64> Memory<F> for MemVec<F> {
    fn with_capacity(capacity: usize) -> Self {
        Self(Vec::with_capacity(capacity))
    }

    fn mr(&mut self, addr: Address<F>) -> &mut MemoryEntry<F> {
        match self.0.get_mut(addr.as_usize()) {
            Some(Some(entry)) => entry,
            _ => panic!(
                "tried to read from unassigned address: {addr:?}\nbacktrace: {:?}",
                backtrace::Backtrace::new()
            ),
        }
    }

    fn mw(&mut self, addr: Address<F>, val: Block<F>, mult: F) -> &mut MemoryEntry<F> {
        let addr_usize = addr.as_usize();
        self.0.extend(std::iter::repeat_n(None, (addr_usize + 1).saturating_sub(self.0.len())));
        match &mut self.0[addr_usize] {
            Some(entry) => panic!(
                "tried to write to assigned address: {entry:?}\nbacktrace: {:?}",
                backtrace::Backtrace::new()
            ),
            entry @ None => entry.insert(MemoryEntry { val, mult }),
        }
    }
}

/// `UnsafeCell` made `Sync`. Replicates the still-unstable
/// `std::cell::SyncUnsafeCell`. SP1 ref:
/// crates/recursion/executor/src/memory.rs::SyncUnsafeCell.
#[derive(Debug, Default)]
#[repr(transparent)]
struct SyncUnsafeCell<T: ?Sized>(UnsafeCell<T>);

// SAFETY: caller is responsible for the happens-before discipline that
// guarantees no concurrent reads/writes alias the same cell. The
// `RawProgram::seq_blocks` parallel-block invariant (each parallel
// sub-program writes to a disjoint address range) provides this.
unsafe impl<T: ?Sized + Sync> Sync for SyncUnsafeCell<T> {}

/// Parallel-safe memory layer using `SyncUnsafeCell<MaybeUninit<...>>`
/// per cell. Read/write through `&self` via `unsafe` methods that the
/// caller must invoke under the address-disjointness discipline of
/// `RawProgram::SeqBlock::Parallel`.
///
/// Additive type, not yet wired into the runtime. SP1 ref:
/// crates/recursion/executor/src/memory.rs::MemVec.
///
/// Differences from SP1's `MemVec`:
/// - SP1's `MemoryEntry` is `{ val }` only; Ziren's still carries
///   `mult` for binary compatibility with the existing chip preprocessed
///   layout. Audit established that `MemoryEntry::mult`
///   is **never read** at runtime — chips read mult from the
///   instruction-side preprocessed columns, not from `MemoryEntry`. The
///   `mr_mult` decrement was therefore dead, and was removed (along with
///   `mr_mult` from the `Memory` trait). `ParMemVec` consequently needs
///   no thread-safe mult-update path: with no shared counter to alias,
///   parallel reads of disjoint addresses are race-free without atomics.
///   `mr_unchecked` returns `&MemoryEntry<F>` and only `val` is consumed
///   downstream.
#[derive(Debug, Default)]
#[allow(dead_code)]
pub struct ParMemVec<F>(Vec<SyncUnsafeCell<MaybeUninit<MemoryEntry<F>>>>);

impl<F: PrimeField64> ParMemVec<F> {
    pub fn with_capacity(capacity: usize) -> Self {
        // SAFETY: SyncUnsafeCell is `repr(transparent)` over UnsafeCell
        // which is `repr(transparent)` over its inner type. This makes
        // the layout of `Vec<SyncUnsafeCell<MaybeUninit<E>>>` identical
        // to `Vec<MaybeUninit<E>>`.
        // SP1 ref: crates/recursion/executor/src/memory.rs::ParMemVec::with_capacity.
        Self(unsafe {
            mem::transmute::<
                Vec<MaybeUninit<MemoryEntry<F>>>,
                Vec<SyncUnsafeCell<MaybeUninit<MemoryEntry<F>>>>,
            >(vec![MaybeUninit::uninit(); capacity])
        })
    }

    /// Read from a cell. Caller-asserted exclusive access via `&mut self`.
    pub fn mr(&mut self, addr: Address<F>) -> &MemoryEntry<F> {
        // SAFETY: exclusive access via `&mut self` precludes any data race.
        unsafe { self.mr_unchecked(addr) }
    }

    /// # Safety
    /// Caller must ensure that no other thread is writing to the same
    /// address concurrently. Writes happen-before all reads under the
    /// `RawProgram` disjoint-address invariant. The address must have
    /// been written via `mw_unchecked` or `mw` before being read.
    pub unsafe fn mr_unchecked(&self, addr: Address<F>) -> &MemoryEntry<F> {
        match self.0.get(addr.as_usize()) {
            Some(cell) => {
                // SAFETY: per the RawProgram disjoint-address invariant,
                // no other thread aliases this cell mutably. The borrow
                // returned shares the lifetime of `&self`.
                let init: &MaybeUninit<MemoryEntry<F>> = unsafe { &*cell.0.get() };
                // SAFETY: mw_unchecked must have initialized this cell
                // before any read (RawProgram happens-before invariant).
                unsafe { init.assume_init_ref() }
            }
            None => panic!(
                "ParMemVec::mr_unchecked: address {} out of bounds (len={})",
                addr.as_usize(),
                self.0.len()
            ),
        }
    }

    /// Write to a cell. Caller-asserted exclusive access via `&mut self`.
    pub fn mw(&mut self, addr: Address<F>, val: Block<F>, mult: F) {
        // SAFETY: exclusive access via `&mut self` precludes any data race.
        unsafe { self.mw_unchecked(addr, val, mult) }
    }

    /// # Safety
    /// Caller must ensure no other thread reads OR writes to the same
    /// address concurrently. Each address must be written exactly once
    /// (RawProgram single-write invariant).
    pub unsafe fn mw_unchecked(&self, addr: Address<F>, val: Block<F>, mult: F) {
        match self.0.get(addr.as_usize()) {
            Some(cell) => {
                // SAFETY: per the RawProgram disjoint-address invariant,
                // no other thread aliases this cell.
                let slot: &mut MaybeUninit<MemoryEntry<F>> = unsafe { &mut *cell.0.get() };
                slot.write(MemoryEntry { val, mult });
            }
            None => panic!(
                "ParMemVec::mw_unchecked: address {} out of bounds (len={})",
                addr.as_usize(),
                self.0.len()
            ),
        }
    }
}

#[cfg(test)]
mod par_mem_vec_tests {
    use super::*;
    use p3_field::PrimeCharacteristicRing;
    use p3_koala_bear::KoalaBear;

    fn k(v: u32) -> KoalaBear {
        KoalaBear::from_u32(v)
    }

    #[test]
    fn write_then_read_roundtrip() {
        let mem = ParMemVec::<KoalaBear>::with_capacity(4);
        let addr = Address(k(0));
        let val = Block([k(7); 4]);
        // SAFETY: single-thread test, exclusive access trivially true.
        unsafe {
            mem.mw_unchecked(addr, val, k(2));
            let entry = mem.mr_unchecked(addr);
            assert_eq!(entry.val.0[0], k(7));
            assert_eq!(entry.mult, k(2));
        }
    }

    #[test]
    fn parallel_disjoint_writes() {
        // Verifies the type-system contract: `&self` with disjoint
        // addresses across threads. `std::thread::scope` borrows self
        // by shared ref — only compiles because ParMemVec is Sync.
        let mem = ParMemVec::<KoalaBear>::with_capacity(64);
        std::thread::scope(|s| {
            for tid in 0..4 {
                let m = &mem;
                s.spawn(move || {
                    for i in 0..16 {
                        let addr_idx = (tid * 16 + i) as u32;
                        let addr = Address(k(addr_idx));
                        let val = Block([k(addr_idx); 4]);
                        // SAFETY: per-thread address ranges are disjoint
                        // (tid * 16 .. (tid+1) * 16); no aliasing.
                        unsafe { m.mw_unchecked(addr, val, KoalaBear::ONE) };
                    }
                });
            }
        });
        // Read back from main thread.
        for i in 0..64 {
            // SAFETY: all writers joined; sole reader.
            let entry = unsafe { mem.mr_unchecked(Address(k(i))) };
            assert_eq!(entry.val.0[0], k(i));
        }
    }
}
