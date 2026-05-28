use std::{array, cell::UnsafeCell, mem::MaybeUninit, sync::Arc};

use hashbrown::HashMap;
use p3_field::{Field, PrimeCharacteristicRing, PrimeField32};
use serde::{Deserialize, Serialize};
use zkm_stark::{air::MachineAir, MachineRecord, ZKMCoreOpts, PROOF_MAX_NUM_PVS};

use crate::machine::RecursionAirEventCount;

use super::{
    BaseAluEvent, CommitPublicValuesEvent, ExpReverseBitsEvent, ExtAluEvent,
    MemEvent, Poseidon2Event, RecursionProgram, RecursionPublicValues, SelectEvent,
};

#[derive(Clone, Default, Debug, Serialize, Deserialize)]
#[serde(bound(serialize = "F: Serialize", deserialize = "F: Deserialize<'de> + Default"))]
pub struct ExecutionRecord<F> {
    /// Skipped on the wire — the coordinator sends `program` separately
    /// (cached server-side by `program_cache_key`) and the shard-server
    /// re-attaches it to the deserialized record before driving the
    /// shard-level prover.  Avoids paying the program serialization cost
    /// per shard when many shards share the same compose program (#272
    /// process-per-GPU architecture).
    #[serde(skip)]
    pub program: Arc<RecursionProgram<F>>,
    /// The index of the shard.
    pub index: u32,

    pub base_alu_events: Vec<BaseAluEvent<F>>,
    pub ext_alu_events: Vec<ExtAluEvent<F>>,
    pub mem_const_count: usize,
    pub mem_var_events: Vec<MemEvent<F>>,
    /// The public values.
    pub public_values: RecursionPublicValues<F>,

    pub poseidon2_events: Vec<Poseidon2Event<F>>,
    pub select_events: Vec<SelectEvent<F>>,
    pub exp_reverse_bits_len_events: Vec<ExpReverseBitsEvent<F>>,
    pub commit_pv_hash_events: Vec<CommitPublicValuesEvent<F>>,
}

impl<F: PrimeField32> MachineRecord for ExecutionRecord<F> {
    type Config = ZKMCoreOpts;

    fn stats(&self) -> hashbrown::HashMap<String, usize> {
        let mut stats = HashMap::new();
        stats.insert("base_alu_events".to_string(), self.base_alu_events.len());
        stats.insert("ext_alu_events".to_string(), self.ext_alu_events.len());
        stats.insert("mem_var_events".to_string(), self.mem_var_events.len());

        stats.insert("poseidon2_events".to_string(), self.poseidon2_events.len());
        stats.insert("exp_reverse_bits_events".to_string(), self.exp_reverse_bits_len_events.len());

        stats
    }

    fn append(&mut self, other: &mut Self) {
        // Exhaustive destructuring for refactoring purposes.
        let Self {
            program: _,
            index: _,
            base_alu_events,
            ext_alu_events,
            mem_const_count,
            mem_var_events,
            public_values: _,
            poseidon2_events,
            select_events,
            exp_reverse_bits_len_events,
            commit_pv_hash_events,
        } = self;
        base_alu_events.append(&mut other.base_alu_events);
        ext_alu_events.append(&mut other.ext_alu_events);
        *mem_const_count += other.mem_const_count;
        mem_var_events.append(&mut other.mem_var_events);
        poseidon2_events.append(&mut other.poseidon2_events);
        select_events.append(&mut other.select_events);
        exp_reverse_bits_len_events.append(&mut other.exp_reverse_bits_len_events);
        commit_pv_hash_events.append(&mut other.commit_pv_hash_events);
    }

    fn public_values<T: PrimeCharacteristicRing>(&self) -> Vec<T> {
        let pv_elms = self.public_values.as_array();

        let ret: [T; PROOF_MAX_NUM_PVS] = array::from_fn(|i| {
            if i < pv_elms.len() {
                T::from_u32(pv_elms[i].as_canonical_u32())
            } else {
                T::ZERO
            }
        });

        ret.to_vec()
    }
}

impl<F: Field> ExecutionRecord<F> {
    #[inline]
    pub fn fixed_log2_rows<A: MachineAir<F>>(&self, air: &A) -> Option<usize> {
        self.program.fixed_log2_rows(air)
    }
}

/// Pre-sized, interior-mutable record for parallel-safe event writes.
///
/// Each event Vec is sized at `new()` time from the analyzed event
/// counts; events are then written by
/// offset (computed by the analyze pass) into `MaybeUninit<UnsafeCell<...>>`
/// slots. With the `RawProgram::Parallel` disjoint-address invariant in
/// place, parallel sub-walks can write into disjoint offsets through a
/// shared `&UnsafeRecord` without locking.
///
/// **Soundness condition**: every slot must be initialized exactly once
/// before `into_record()` is called. The analyze pass guarantees one
/// offset per event-emitting instruction; the runtime walker ensures
/// each instruction is executed exactly once.
///
/// SP1 ref: crates/recursion/executor/src/record.rs::UnsafeRecord.
#[derive(Debug)]
pub struct UnsafeRecord<F> {
    pub base_alu_events: Vec<MaybeUninit<UnsafeCell<BaseAluEvent<F>>>>,
    pub ext_alu_events: Vec<MaybeUninit<UnsafeCell<ExtAluEvent<F>>>>,
    pub mem_const_count: usize,
    pub mem_var_events: Vec<MaybeUninit<UnsafeCell<MemEvent<F>>>>,
    pub public_values: MaybeUninit<UnsafeCell<RecursionPublicValues<F>>>,
    pub poseidon2_events: Vec<MaybeUninit<UnsafeCell<Poseidon2Event<F>>>>,
    pub select_events: Vec<MaybeUninit<UnsafeCell<SelectEvent<F>>>>,
    pub exp_reverse_bits_len_events: Vec<MaybeUninit<UnsafeCell<ExpReverseBitsEvent<F>>>>,
    pub commit_pv_hash_events: Vec<MaybeUninit<UnsafeCell<CommitPublicValuesEvent<F>>>>,
}

// SAFETY: caller is responsible for the discipline that no two threads
// write to the same offset concurrently — provided by `RawProgram::Parallel`'s
// disjoint-address invariant + analyze()'s monotonic offset assignment.
unsafe impl<F> Sync for UnsafeRecord<F> {}

impl<F> UnsafeRecord<F> {
    /// Allocate event vectors of the exact sizes from the analyzed counts.
    /// Slots start uninitialized; the runtime is expected to write each
    /// slot exactly once before [`Self::into_record`].
    pub fn new(event_counts: RecursionAirEventCount) -> Self
    where
        F: Field,
    {
        #[inline]
        fn create_uninit_vec<T>(len: usize) -> Vec<MaybeUninit<T>> {
            let mut vec: Vec<MaybeUninit<T>> = Vec::with_capacity(len);
            // SAFETY: capacity is `len`, and `MaybeUninit<T>` is the
            // canonical type for uninitialized memory.
            unsafe { vec.set_len(len) };
            vec
        }
        Self {
            base_alu_events: create_uninit_vec(event_counts.base_alu_events),
            ext_alu_events: create_uninit_vec(event_counts.ext_alu_events),
            mem_const_count: event_counts.mem_const_events,
            mem_var_events: create_uninit_vec(event_counts.mem_var_events),
            public_values: MaybeUninit::uninit(),
            poseidon2_events: create_uninit_vec(event_counts.poseidon2_wide_events),
            select_events: create_uninit_vec(event_counts.select_events),
            exp_reverse_bits_len_events: create_uninit_vec(
                event_counts.exp_reverse_bits_len_events,
            ),
            // Pre-size from the counters added to RecursionAirEventCount
            // so all 11 event vecs are ready for offset-based writes.
            commit_pv_hash_events: create_uninit_vec(event_counts.commit_pv_hash_events),
        }
    }

    /// Convert into the standard `ExecutionRecord`.
    ///
    /// # Safety
    /// Every event slot pre-allocated in `new()` must have been written
    /// exactly once by the runtime walker. `public_values` must also
    /// have been written. The transmute relies on `T` and
    /// `MaybeUninit<UnsafeCell<T>>` having the same memory layout — true
    /// since both `UnsafeCell<T>` and `MaybeUninit<T>` are
    /// `repr(transparent)` over `T`.
    pub unsafe fn into_record(
        self,
        program: Arc<RecursionProgram<F>>,
        index: u32,
    ) -> ExecutionRecord<F> {
        ExecutionRecord {
            program,
            index,
            // SAFETY: layout-equivalence of T / MaybeUninit<UnsafeCell<T>>.
            base_alu_events: std::mem::transmute::<
                Vec<MaybeUninit<UnsafeCell<BaseAluEvent<F>>>>,
                Vec<BaseAluEvent<F>>,
            >(self.base_alu_events),
            ext_alu_events: std::mem::transmute::<
                Vec<MaybeUninit<UnsafeCell<ExtAluEvent<F>>>>,
                Vec<ExtAluEvent<F>>,
            >(self.ext_alu_events),
            mem_const_count: self.mem_const_count,
            mem_var_events: std::mem::transmute::<
                Vec<MaybeUninit<UnsafeCell<MemEvent<F>>>>,
                Vec<MemEvent<F>>,
            >(self.mem_var_events),
            public_values: self.public_values.assume_init().into_inner(),
            poseidon2_events: std::mem::transmute::<
                Vec<MaybeUninit<UnsafeCell<Poseidon2Event<F>>>>,
                Vec<Poseidon2Event<F>>,
            >(self.poseidon2_events),
            select_events: std::mem::transmute::<
                Vec<MaybeUninit<UnsafeCell<SelectEvent<F>>>>,
                Vec<SelectEvent<F>>,
            >(self.select_events),
            exp_reverse_bits_len_events: std::mem::transmute::<
                Vec<MaybeUninit<UnsafeCell<ExpReverseBitsEvent<F>>>>,
                Vec<ExpReverseBitsEvent<F>>,
            >(self.exp_reverse_bits_len_events),
            commit_pv_hash_events: std::mem::transmute::<
                Vec<MaybeUninit<UnsafeCell<CommitPublicValuesEvent<F>>>>,
                Vec<CommitPublicValuesEvent<F>>,
            >(self.commit_pv_hash_events),
        }
    }
}

#[cfg(test)]
mod unsafe_record_tests {
    use super::*;
    use crate::air::Block;
    use p3_field::PrimeCharacteristicRing;
    use p3_koala_bear::KoalaBear;

    fn k(v: u32) -> KoalaBear {
        KoalaBear::from_u32(v)
    }

    #[test]
    fn new_pre_sizes_to_event_counts() {
        let mut counts = RecursionAirEventCount::default();
        counts.base_alu_events = 4;
        counts.ext_alu_events = 2;
        counts.poseidon2_wide_events = 1;
        let rec = UnsafeRecord::<KoalaBear>::new(counts);
        assert_eq!(rec.base_alu_events.len(), 4);
        assert_eq!(rec.ext_alu_events.len(), 2);
        assert_eq!(rec.poseidon2_events.len(), 1);
        assert_eq!(rec.select_events.len(), 0);
    }

    #[test]
    fn into_record_round_trip_after_offset_writes() {
        let mut counts = RecursionAirEventCount::default();
        counts.base_alu_events = 3;
        let mut rec = UnsafeRecord::<KoalaBear>::new(counts);
        let evs = [
            BaseAluEvent { out: k(7), in1: k(1), in2: k(2) },
            BaseAluEvent { out: k(8), in1: k(3), in2: k(4) },
            BaseAluEvent { out: k(9), in1: k(5), in2: k(6) },
        ];
        // Initialize each MaybeUninit slot with an UnsafeCell::new wrapping the event.
        // This is the canonical way to populate UnsafeRecord in tests; the runtime
        // walker will use the SP1 idiom
        // `UnsafeCell::raw_get(slot.as_ptr() as *const UnsafeCell<T>).write(ev)`
        // to write through `&UnsafeRecord` from parallel threads.
        for (i, e) in evs.iter().enumerate() {
            rec.base_alu_events[i] = MaybeUninit::new(UnsafeCell::new(*e));
        }
        rec.public_values = MaybeUninit::new(UnsafeCell::new(RecursionPublicValues::default()));
        // SAFETY: all event slots and public_values initialized.
        let exec = unsafe { rec.into_record(Arc::new(RecursionProgram::default()), 0) };
        assert_eq!(exec.base_alu_events.len(), 3);
        assert_eq!(exec.base_alu_events[0].out, k(7));
        assert_eq!(exec.base_alu_events[2].in2, k(6));
        assert_eq!(exec.ext_alu_events.len(), 0);
        assert_eq!(exec.poseidon2_events.len(), 0);
        let _ = Block([k(0); 4]); // suppress unused import warning
    }
}
