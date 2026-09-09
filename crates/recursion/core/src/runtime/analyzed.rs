//! Per-instruction event-offset analysis scaffolding.
//!
//! `AnalyzedInstruction { inner, offset }` wraps each instruction with a
//! pre-computed offset into the (eventually) pre-sized `ExecutionRecord`
//! event vectors. With offsets baked in, parallel sub-program execution
//! over `SeqBlock::Parallel` can write events to disjoint indices via
//! interior mutability without locking.
//!
//! This module is **scaffolding only** — the runtime still walks
//! `seq_blocks` via `iter_instructions()` and uses dynamic `Vec::push`
//! for events. The future wiring step will:
//!
//!   1. Replace `Runtime::run` with a SeqBlock-aware walker that consumes
//!      `RawProgram<AnalyzedInstruction<F>>`.
//!   2. Pre-size `ExecutionRecord::*_events` to the analyzed counts.
//!   3. Switch from `record.foo_events.push(ev)` to offset-based writes
//!      via `UnsafeCell<MaybeUninit<...>>` cells.
//!   4. Add `par_iter` dispatch on `SeqBlock::Parallel`.

use serde::{Deserialize, Serialize};

use crate::machine::RecursionAirEventCount;
use crate::runtime::instruction::{
    HintBitsInstr, HintExt2FeltsInstr, HintInstr, Instruction,
};
use crate::runtime::seq_block::{BasicBlock, RawProgram, SeqBlock};
use crate::Address;

/// An instruction tagged with its event-write offset.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalyzedInstruction<F> {
    pub(crate) inner: Instruction<F>,
    pub(crate) offset: usize,
    /// Secondary chip offset for multi-chip emitters.
    ///
    /// All current instructions emit to one chip-event vec — `offset`
    /// is enough.  The slot is retained as `usize::MAX` sentinel for
    /// "none" so the type stays `Copy`-shaped and serde-stable, and is
    /// kept for future multi-chip instructions.
    /// `secondary_offset()` returns `Option<usize>` for ergonomics.
    #[serde(default = "default_secondary_offset")]
    pub(crate) secondary_offset: usize,
}

fn default_secondary_offset() -> usize {
    usize::MAX
}

impl<F> AnalyzedInstruction<F> {
    pub const fn new(inner: Instruction<F>, offset: usize) -> Self {
        Self { inner, offset, secondary_offset: usize::MAX }
    }

    pub const fn inner(&self) -> &Instruction<F> {
        &self.inner
    }

    pub const fn offset(&self) -> usize {
        self.offset
    }

    /// Returns the secondary chip offset for multi-chip emitters,
    /// or `None` if the instruction emits to a single chip vec.
    pub const fn secondary_offset(&self) -> Option<usize> {
        if self.secondary_offset == usize::MAX {
            None
        } else {
            Some(self.secondary_offset)
        }
    }
}

/// Where a basic block's `DivF` divisors live, so the walk can invert them
/// all at once instead of one at a time.
///
/// A field inversion is ~51 ns against a multiply's ~13 (measured, KoalaBear
/// on this host: `BaseAlu/Div` 64.5 ns vs `BaseAlu/Mul` 13.3).  Montgomery's
/// trick turns `n` inversions into `3n` multiplies and ONE inversion, so it
/// pays as soon as a block has more than a couple of divisions — and the
/// recursion programs are 16.8-18.6% `DivF` by base-ALU instruction
/// (298,341 of them in the leaf).
///
/// It needs every divisor of the block in hand BEFORE the block runs, which
/// is exactly what the census says is available: 298,338 of 298,341 leaf
/// divisors are already live at block entry (99.98%), because a recursion
/// program writes each address once and the divisors come from earlier
/// blocks.  So the plan is the divisors' ADDRESSES, in execution order —
/// addresses are compile-time constants even though the values are not.
///
/// Holding addresses rather than instruction indices is deliberate: the
/// gather pass then touches only the memory cells the block is about to read
/// anyway, instead of a second sparse pass over a 78 MB instruction stream.
///
/// A block is all-or-nothing.  If ANY of its `DivF` divisors is produced
/// inside the block, the whole block keeps the per-instruction path; mixing
/// the two would need a per-instruction marker, and the marker would cost
/// every instruction in the program the width to carry it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DivPlan<F> {
    /// This basic block's `DivF` divisor addresses, in execution order.
    /// Empty means "invert per instruction" — either the block has no
    /// division, or one of its divisors is not live at block entry.
    Basic(Box<[Address<F>]>),
    /// Mirrors `SeqBlock::Parallel`: one `Vec<DivPlan>` per sub-program,
    /// matching that sub-program's `seq_blocks` element for element.
    Parallel(Vec<Vec<DivPlan<F>>>),
}

/// `stamps[addr] == generation` iff the block currently being analyzed has
/// already written `addr`.
///
/// A `HashSet` would be the obvious spelling and is the wrong one: a program
/// is built often enough for this to matter (roughly 15 per worker per block
/// under `FIX_CORE_SHAPES=off`), and hashing every one of a leaf's 4.3 M
/// written addresses cost 122 ms — comparable to `analyze` itself.  Recursion
/// addresses are dense and assigned in increasing order, so a stamp array is
/// a near-sequential write, and the generation counter means no clearing
/// between blocks.
struct Written {
    stamps: Vec<u32>,
    generation: u32,
}

impl Written {
    fn next_block(&mut self) {
        self.generation += 1;
    }

    #[inline]
    fn insert(&mut self, addr: usize) {
        if addr >= self.stamps.len() {
            // 0 is never a live generation (the counter starts at 1), so a
            // freshly grown slot reads as "not written".
            self.stamps.resize((addr + 1).next_power_of_two(), 0);
        }
        self.stamps[addr] = self.generation;
    }

    #[inline]
    fn contains(&self, addr: usize) -> bool {
        self.stamps.get(addr).is_some_and(|&g| g == self.generation)
    }
}

impl<F: p3_field::PrimeField64> RawProgram<Instruction<F>> {
    /// Walk seq_blocks (recursing into `SeqBlock::Parallel` sub-programs)
    /// and accumulate per-chip event counts without rewriting the program.
    ///
    /// Used by [`crate::runtime::Runtime::preallocate_record`] to size the
    /// `ExecutionRecord` event vectors before walking. Equivalent to
    /// running [`Self::analyze`] and discarding the offset assignments,
    /// but cheaper because no Vec rebuild happens.
    pub fn event_counts(&self) -> RecursionAirEventCount {
        fn walk_block<T>(block: &SeqBlock<Instruction<T>>, counts: &mut RecursionAirEventCount) {
            match block {
                SeqBlock::Basic(basic) => {
                    for instr in &basic.instrs {
                        *counts += instr;
                    }
                }
                SeqBlock::Parallel(par_blocks) => {
                    for sub in par_blocks {
                        for b in &sub.seq_blocks {
                            walk_block(b, counts);
                        }
                    }
                }
            }
        }
        let mut counts = RecursionAirEventCount::default();
        for b in &self.seq_blocks {
            walk_block(b, &mut counts);
        }
        counts
    }

    /// Analyze the program: assign each instruction an offset into the
    /// per-chip event vectors, and return the total per-chip event count.
    ///
    /// **Soundness condition**: the result is
    /// only sound if the IR-level discipline holds — namely, the
    /// compiler emits each `SeqBlock::Parallel` sub-program with
    /// monotonic, non-overlapping address ranges and no cross-block
    /// data dependencies. The runtime relies on this without verifying.
    /// Also returns the batch-inversion plan ([`DivPlan`]), built in the same
    /// traversal.  Built separately it cost 122 ms on a 4.3 M-instruction
    /// leaf — as much as `analyze` itself — because the expensive part is
    /// walking every instruction, not the bookkeeping.  Sharing the walk
    /// makes it marginal.
    pub fn analyze(
        self,
    ) -> (RawProgram<AnalyzedInstruction<F>>, RecursionAirEventCount, Vec<DivPlan<F>>) {
        fn instr_offset<T>(instr: &Instruction<T>, counts: &mut RecursionAirEventCount) -> usize {
            fn incr(num: &mut usize, amt: usize) -> usize {
                let start = *num;
                *num += amt;
                start
            }
            match instr {
                Instruction::BaseAlu(_) => incr(&mut counts.base_alu_events, 1),
                Instruction::ExtAlu(_) => incr(&mut counts.ext_alu_events, 1),
                Instruction::Mem(_) => incr(&mut counts.mem_const_events, 1),
                Instruction::Poseidon2(_) => incr(&mut counts.poseidon2_wide_events, 1),
                Instruction::Select(_) => incr(&mut counts.select_events, 1),
                // ExpReverseBitsLen: 1 event per instruction (event carries
                // `exp: Vec<F>` of all bits inline). Match runtime push.
                // FriFold: runtime emits ps_at_z.len() events per instruction
                // (one per polynomial in the batch). Was off-by-default-1.
                Instruction::Hint(HintInstr { output_addrs_mults })
                | Instruction::HintBits(HintBitsInstr { output_addrs_mults, input_addr: _ }) => {
                    incr(&mut counts.mem_var_events, output_addrs_mults.len())
                }
                Instruction::HintExt2Felts(HintExt2FeltsInstr {
                    output_addrs_mults,
                    input_addr: _,
                }) => incr(&mut counts.mem_var_events, output_addrs_mults.len()),
                // One event per instruction: the event carries the input
                // block; the addresses ride the preprocessed trace.
                Instruction::Ext2Felts(_) => incr(&mut counts.ext2felt_events, 1),
                Instruction::HintAddCurve(instr) => incr(
                    &mut counts.mem_var_events,
                    instr.output_x_addrs_mults.len() + instr.output_y_addrs_mults.len(),
                ),
                // Assign event-vec offsets for the two newly-tracked
                // event types.
                Instruction::CommitPublicValues(_) => incr(&mut counts.commit_pv_hash_events, 1),
                // No event-vector slot consumed; offset is meaningless.
                Instruction::Print(_) => 0,
            }
        }

        fn analyze_block<T: p3_field::PrimeField64>(
            block: SeqBlock<Instruction<T>>,
            counts: &mut RecursionAirEventCount,
            written: &mut Written,
        ) -> (SeqBlock<AnalyzedInstruction<T>>, DivPlan<T>) {
            match block {
                SeqBlock::Basic(basic) => {
                    written.next_block();
                    let mut divisors: Vec<Address<T>> = Vec::new();
                    // Set once a divisor turns out to be produced inside this
                    // block: the value is not there to gather, and the plan
                    // is all-or-nothing per block (see [`DivPlan`]).
                    let mut given_up = false;
                    let analyzed = basic
                        .instrs
                        .into_iter()
                        .map(|instr| {
                            if !given_up {
                                if let Instruction::BaseAlu(i) = &instr {
                                    if matches!(
                                        i.opcode,
                                        crate::BaseAluOpcode::DivF
                                            | crate::BaseAluOpcode::DivFAssert
                                    ) {
                                        if written.contains(i.addrs.in2.as_usize()) {
                                            given_up = true;
                                            divisors.clear();
                                        } else {
                                            divisors.push(i.addrs.in2);
                                        }
                                    }
                                }
                            }
                            // EXHAUSTIVE, and it must stay that way: a missed
                            // write would let a divisor be gathered above the
                            // instruction that produces it, and the walk
                            // would divide by a stale cell.
                            instr.for_each_written_addr(|a| written.insert(a.as_usize()));
                            let offset = instr_offset(&instr, counts);
                            AnalyzedInstruction::new(instr, offset)
                        })
                        .collect();
                    (
                        SeqBlock::Basic(BasicBlock { instrs: analyzed }),
                        DivPlan::Basic(divisors.into_boxed_slice()),
                    )
                }
                SeqBlock::Parallel(par_blocks) => {
                    let (analyzed, plans): (Vec<_>, Vec<_>) = par_blocks
                        .into_iter()
                        .map(|sub| {
                            let (blocks, plans): (Vec<_>, Vec<_>) = sub
                                .seq_blocks
                                .into_iter()
                                .map(|b| analyze_block(b, counts, written))
                                .unzip();
                            (RawProgram { seq_blocks: blocks }, plans)
                        })
                        .unzip();
                    (SeqBlock::Parallel(analyzed), DivPlan::Parallel(plans))
                }
            }
        }

        let mut counts = RecursionAirEventCount::default();
        let mut written = Written { stamps: Vec::new(), generation: 0 };
        let (analyzed_blocks, div_plan): (Vec<_>, Vec<_>) = self
            .seq_blocks
            .into_iter()
            .map(|b| analyze_block(b, &mut counts, &mut written))
            .unzip();
        (RawProgram { seq_blocks: analyzed_blocks }, counts, div_plan)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::air::Block;
    use crate::{Address, BaseAluInstr, BaseAluIo, BaseAluOpcode, MemAccessKind, MemInstr, MemIo};
    use p3_field::PrimeCharacteristicRing;
    use p3_koala_bear::KoalaBear;

    fn k(v: u32) -> KoalaBear {
        KoalaBear::from_u32(v)
    }

    fn dummy_base_alu() -> Instruction<KoalaBear> {
        Instruction::BaseAlu(BaseAluInstr {
            opcode: BaseAluOpcode::AddF,
            mult: KoalaBear::ONE,
            addrs: BaseAluIo { out: Address(k(0)), in1: Address(k(1)), in2: Address(k(2)) },
        })
    }

    fn dummy_mem() -> Instruction<KoalaBear> {
        Instruction::Mem(MemInstr {
            addrs: MemIo { inner: Address(k(0)) },
            vals: MemIo { inner: Block([k(0); 4]) },
            mult: KoalaBear::ONE,
            kind: MemAccessKind::Write,
        })
    }

    #[test]
    fn analyze_assigns_monotonic_offsets() {
        let prog: RawProgram<Instruction<KoalaBear>> = RawProgram {
            seq_blocks: vec![SeqBlock::Basic(BasicBlock {
                instrs: vec![dummy_base_alu(), dummy_base_alu(), dummy_mem(), dummy_base_alu()],
            })],
        };
        let (analyzed, counts, _) = prog.analyze();
        assert_eq!(counts.base_alu_events, 3);
        assert_eq!(counts.mem_const_events, 1);
        let mut base_alu_offsets = Vec::new();
        let mut mem_offsets = Vec::new();
        for b in &analyzed.seq_blocks {
            if let SeqBlock::Basic(basic) = b {
                for ai in &basic.instrs {
                    match ai.inner() {
                        Instruction::BaseAlu(_) => base_alu_offsets.push(ai.offset()),
                        Instruction::Mem(_) => mem_offsets.push(ai.offset()),
                        _ => {}
                    }
                }
            }
        }
        assert_eq!(base_alu_offsets, vec![0, 1, 2]);
        assert_eq!(mem_offsets, vec![0]);
    }

    // (removed) sumcheck_verify_carries_secondary_offset test:
    // SumcheckVerify pipeline deleted, no multi-chip emitters remain.

    #[test]
    fn analyze_handles_parallel_blocks() {
        let make_basic =
            || SeqBlock::Basic(BasicBlock { instrs: vec![dummy_base_alu(), dummy_base_alu()] });
        let par_subs: Vec<RawProgram<Instruction<KoalaBear>>> = vec![
            RawProgram { seq_blocks: vec![make_basic()] },
            RawProgram { seq_blocks: vec![make_basic()] },
        ];
        let prog: RawProgram<Instruction<KoalaBear>> = RawProgram {
            seq_blocks: vec![make_basic(), SeqBlock::Parallel(par_subs), make_basic()],
        };
        let (_, counts, _) = prog.analyze();
        // 4 outer (2+2) + 2 sub × 2 instrs each = 4 + 4 = 8 base_alu events.
        assert_eq!(counts.base_alu_events, 8);
    }

    #[test]
    fn event_counts_matches_analyze_for_parallel_program() {
        // Same shape as analyze_handles_parallel_blocks, but verify the
        // non-consuming `event_counts()` produces the same totals as
        // the consuming `analyze()` path. This is the contract that
        // `Runtime::preallocate_record` relies on.
        let make_basic = || {
            SeqBlock::Basic(BasicBlock {
                instrs: vec![dummy_base_alu(), dummy_base_alu(), dummy_mem()],
            })
        };
        let par_subs: Vec<RawProgram<Instruction<KoalaBear>>> = vec![
            RawProgram { seq_blocks: vec![make_basic()] },
            RawProgram { seq_blocks: vec![make_basic(), make_basic()] },
        ];
        let prog: RawProgram<Instruction<KoalaBear>> = RawProgram {
            seq_blocks: vec![make_basic(), SeqBlock::Parallel(par_subs), make_basic()],
        };
        let counts_via_event_counts = prog.event_counts();
        let (_, counts_via_analyze, _) = prog.analyze();
        assert_eq!(counts_via_event_counts.base_alu_events, counts_via_analyze.base_alu_events);
        assert_eq!(counts_via_event_counts.mem_const_events, counts_via_analyze.mem_const_events);
        assert_eq!(counts_via_event_counts.ext_alu_events, counts_via_analyze.ext_alu_events);
        assert_eq!(
            counts_via_event_counts.poseidon2_wide_events,
            counts_via_analyze.poseidon2_wide_events
        );
        // Total instructions: 1 outer + 3 inner sub-progs + 1 outer trailer
        // = 5 basic blocks × 3 instrs each = 15 → 10 base_alu + 5 mem.
        assert_eq!(counts_via_event_counts.base_alu_events, 10);
        assert_eq!(counts_via_event_counts.mem_const_events, 5);
    }
}
