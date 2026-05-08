//! Per-instruction event-offset analysis (#259 Phase C step 2 scaffolding).
//!
//! `AnalyzedInstruction { inner, offset }` wraps each instruction with a
//! pre-computed offset into the (eventually) pre-sized `ExecutionRecord`
//! event vectors. With offsets baked in, parallel sub-program execution
//! over `SeqBlock::Parallel` can write events to disjoint indices via
//! interior mutability without locking.
//!
//! This module is **scaffolding only** — the runtime still walks
//! `seq_blocks` via `iter_instructions()` (Phase A4) and uses dynamic
//! `Vec::push` for events. The wiring step (Phase C step 2b) will:
//!
//!   1. Replace `Runtime::run` with a SeqBlock-aware walker that consumes
//!      `RawProgram<AnalyzedInstruction<F>>`.
//!   2. Pre-size `ExecutionRecord::*_events` to the analyzed counts.
//!   3. Switch from `record.foo_events.push(ev)` to offset-based writes
//!      via `UnsafeCell<MaybeUninit<...>>` cells.
//!   4. Add `par_iter` dispatch on `SeqBlock::Parallel`.
//!
//! SP1 ref: `/tmp/sp1/crates/recursion/executor/src/analyzed.rs`.

use serde::{Deserialize, Serialize};

use crate::machine::RecursionAirEventCount;
use crate::runtime::instruction::{
    HintAddCurveInstr, HintBitsInstr, HintExt2FeltsInstr, HintInstr, Instruction,
};
use crate::runtime::seq_block::{BasicBlock, RawProgram, SeqBlock};

/// An instruction tagged with its event-write offset.
///
/// SP1 ref: `/tmp/sp1/crates/recursion/executor/src/analyzed.rs:11-15`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalyzedInstruction<F> {
    pub(crate) inner: Instruction<F>,
    pub(crate) offset: usize,
}

impl<F> AnalyzedInstruction<F> {
    pub const fn new(inner: Instruction<F>, offset: usize) -> Self {
        Self { inner, offset }
    }

    pub const fn inner(&self) -> &Instruction<F> {
        &self.inner
    }

    pub const fn offset(&self) -> usize {
        self.offset
    }
}

impl<F> RawProgram<Instruction<F>> {
    /// Analyze the program: assign each instruction an offset into the
    /// per-chip event vectors, and return the total per-chip event count.
    ///
    /// **Soundness condition** (matches SP1's invariant): the result is
    /// only sound if the IR-level discipline holds — namely, the
    /// compiler emits each `SeqBlock::Parallel` sub-program with
    /// monotonic, non-overlapping address ranges and no cross-block
    /// data dependencies. The runtime relies on this without verifying.
    ///
    /// SP1 ref: `/tmp/sp1/crates/recursion/executor/src/analyzed.rs:33-128`.
    pub fn analyze(self) -> (RawProgram<AnalyzedInstruction<F>>, RecursionAirEventCount) {
        fn instr_offset<T>(
            instr: &Instruction<T>,
            counts: &mut RecursionAirEventCount,
        ) -> usize {
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
                Instruction::ExpReverseBitsLen(instr) => {
                    incr(&mut counts.exp_reverse_bits_len_events, instr.addrs.exp.len())
                }
                Instruction::FriFold(_) => incr(&mut counts.fri_fold_events, 1),
                Instruction::BatchFRI(instr) => incr(
                    &mut counts.batch_fri_events,
                    instr.base_vec_addrs.p_at_x.len(),
                ),
                Instruction::Hint(HintInstr { output_addrs_mults })
                | Instruction::HintBits(HintBitsInstr {
                    output_addrs_mults,
                    input_addr: _,
                }) => incr(&mut counts.mem_var_events, output_addrs_mults.len()),
                Instruction::HintExt2Felts(HintExt2FeltsInstr {
                    output_addrs_mults,
                    input_addr: _,
                }) => incr(&mut counts.mem_var_events, output_addrs_mults.len()),
                Instruction::HintAddCurve(HintAddCurveInstr {
                    output_x_addrs_mults,
                    output_y_addrs_mults,
                    ..
                }) => incr(
                    &mut counts.mem_var_events,
                    output_x_addrs_mults.len() + output_y_addrs_mults.len(),
                ),
                // No event-vector slot consumed; offset is meaningless.
                Instruction::CommitPublicValues(_)
                | Instruction::Print(_)
                | Instruction::SumcheckVerify(_) => 0,
            }
        }

        fn analyze_block<T>(
            block: SeqBlock<Instruction<T>>,
            counts: &mut RecursionAirEventCount,
        ) -> SeqBlock<AnalyzedInstruction<T>> {
            match block {
                SeqBlock::Basic(basic) => {
                    let analyzed = basic
                        .instrs
                        .into_iter()
                        .map(|instr| {
                            let offset = instr_offset(&instr, counts);
                            AnalyzedInstruction::new(instr, offset)
                        })
                        .collect();
                    SeqBlock::Basic(BasicBlock { instrs: analyzed })
                }
                SeqBlock::Parallel(par_blocks) => {
                    let analyzed = par_blocks
                        .into_iter()
                        .map(|sub| RawProgram {
                            seq_blocks: sub
                                .seq_blocks
                                .into_iter()
                                .map(|b| analyze_block(b, counts))
                                .collect(),
                        })
                        .collect();
                    SeqBlock::Parallel(analyzed)
                }
            }
        }

        let mut counts = RecursionAirEventCount::default();
        let analyzed_blocks = self
            .seq_blocks
            .into_iter()
            .map(|b| analyze_block(b, &mut counts))
            .collect();
        (RawProgram { seq_blocks: analyzed_blocks }, counts)
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
            addrs: BaseAluIo {
                out: Address(k(0)),
                in1: Address(k(1)),
                in2: Address(k(2)),
            },
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
        let (analyzed, counts) = prog.analyze();
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

    #[test]
    fn analyze_handles_parallel_blocks() {
        let make_basic = || {
            SeqBlock::Basic(BasicBlock {
                instrs: vec![dummy_base_alu(), dummy_base_alu()],
            })
        };
        let par_subs: Vec<RawProgram<Instruction<KoalaBear>>> = vec![
            RawProgram { seq_blocks: vec![make_basic()] },
            RawProgram { seq_blocks: vec![make_basic()] },
        ];
        let prog: RawProgram<Instruction<KoalaBear>> = RawProgram {
            seq_blocks: vec![
                make_basic(),
                SeqBlock::Parallel(par_subs),
                make_basic(),
            ],
        };
        let (_, counts) = prog.analyze();
        // 4 outer (2+2) + 2 sub × 2 instrs each = 4 + 4 = 8 base_alu events.
        assert_eq!(counts.base_alu_events, 8);
    }
}
