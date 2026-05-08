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

    /// Read from a memory address. Decrements the memory entry's mult count.
    ///
    /// # Panics
    /// Panics if the address is unassigned.
    fn mr(&mut self, addr: Address<F>) -> &mut MemoryEntry<F>;

    /// Read from a memory address. Reduces the memory entry's mult count by the given amount.
    ///
    /// # Panics
    /// Panics if the address is unassigned.
    fn mr_mult(&mut self, addr: Address<F>, mult: F) -> &mut MemoryEntry<F>;

    /// Write to a memory address, setting the given value and mult.
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
        self.mr_mult(addr, F::ONE)
    }

    fn mr_mult(&mut self, addr: Address<F>, mult: F) -> &mut MemoryEntry<F> {
        match self.0.entry(addr.as_usize()) {
            Entry::Occupied(mut entry) => {
                let entry_mult = &mut entry.get_mut().mult;
                *entry_mult -= mult;
                entry.into_mut()
            }
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
        self.mr_mult(addr, F::ONE)
    }

    fn mr_mult(&mut self, addr: Address<F>, mult: F) -> &mut MemoryEntry<F> {
        match self.0.get_mut(addr.as_usize()) {
            Some(Some(entry)) => {
                entry.mult -= mult;
                entry
            }
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
/// `/tmp/sp1/crates/recursion/executor/src/memory.rs:18-22`.
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
/// This is the #259 Phase B step 1 foundation — added as an additive
/// type, not yet wired into the runtime. SP1 ref:
/// `/tmp/sp1/crates/recursion/executor/src/memory.rs:25-100`.
///
/// Differences from SP1's `MemVec`:
/// - SP1's `MemoryEntry` is `{ val }` only; Ziren's adds `mult` for
///   logup multiplicity tracking. The mult field is held inline today
///   — concurrent writes to different cells are race-free, but
///   concurrent decrements through `mr_unchecked`'s `&MemoryEntry`
///   would alias. Phase B step 2 will resolve mult-tracking for
///   parallel reads (current options: move mult to a separate Vec
///   updated by the runtime; or wrap mult in `AtomicU{32,64}` with
///   canonical-repr conversion to F).
/// - For now, `mr_unchecked` returns `&MemoryEntry<F>` (read-only). The
///   caller cannot decrement mult through it. Phase B step 2 supplies
///   a thread-safe mult-update path.
#[derive(Debug, Default)]
#[allow(dead_code)]
pub struct ParMemVec<F>(Vec<SyncUnsafeCell<MaybeUninit<MemoryEntry<F>>>>);

impl<F: PrimeField64> ParMemVec<F> {
    pub fn with_capacity(capacity: usize) -> Self {
        // SAFETY: SyncUnsafeCell is `repr(transparent)` over UnsafeCell
        // which is `repr(transparent)` over its inner type. This makes
        // the layout of `Vec<SyncUnsafeCell<MaybeUninit<E>>>` identical
        // to `Vec<MaybeUninit<E>>`.
        // SP1 ref: `/tmp/sp1/crates/recursion/executor/src/memory.rs:30-37`.
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
