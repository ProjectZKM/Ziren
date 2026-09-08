//! JIT compiler for the Ziren recursion (compress) executor, Linux x86_64.
//!
//! The recursion runtime walks an enum-dispatched interpreter over the
//! compress program — `Runtime::execute_one` in `zkm-recursion-core`.  On a
//! real reth block that walk is **250 nodes, 427,077,721 instructions,
//! 13.95 s of host CPU** (mean 55.8 ms/node, p50 48, p90 85, max 182), a
//! rate of 30.6 M instr/s.  Thirty-three nanoseconds is about a hundred
//! cycles to do one field add and one store: almost all of it is dispatch.
//! Ziren's guest JIT (`zkm-core-jit`, the same `dynasmrt` stack SP1 uses for
//! `sp1-jit`) took the analogous MIPS loop from 9.1 s to 2.25 s.
//!
//! The recursion VM is a far easier target than MIPS:
//!
//! * **Twelve** instruction variants, and **no control flow** — a program is
//!   straight-line `SeqBlock::Basic` runs with `SeqBlock::Parallel` fan-outs.
//!   There is no PC to track and no branch to resolve.
//! * Memory is a flat `Vec<MemoryEntry<F>>` indexed directly by address, so
//!   an operand is a fixed displacement off one base register.
//! * **Every address and every record offset is a compile-time constant.**
//!   `analyze()` assigns each instruction's record offset before the walk,
//!   and `addrs.in1/in2/out` are baked into the program.  A JIT'd `BaseAlu`
//!   is two loads at immediate displacements, one field op, one store and
//!   one event write — no dispatch, no decode, no bounds check.
//! * Programs are already cached by shape (`zkm-prover`'s `program_cache`,
//!   with disk persistence), so compiled code amortises over many nodes
//!   rather than being paid per node.
//!
//! # Status
//!
//! This crate is being built in phases, and ships the interpreter fallback
//! at every one of them: [`plan`] reports what a given phase can cover, and
//! anything uncovered stays on `execute_one`.
//!
//! - [x] **P1** — layout contract, coverage planner, workspace wiring
//! - [ ] **P2** — `BaseAlu` / `Mem` emission
//! - [ ] **P3** — `ExtAlu` / `Select`
//! - [ ] **P4** — call-outs for `Poseidon2`, `DivF` inverse and the hints
//! - [ ] **P5** — wire into `Runtime::run`, keyed by program identity
//! - [ ] **P6** — default-on + benchmarks

#![warn(missing_docs)]
#![cfg_attr(not(all(target_arch = "x86_64", target_os = "linux")), allow(unused))]

#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
pub mod compile;
#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
pub mod x86;

use p3_koala_bear::KoalaBear;
use zkm_recursion_core::air::Block;
use zkm_recursion_core::runtime::memory::MemoryEntry;
use zkm_recursion_core::runtime::{
    AnalyzedInstruction, BaseAluOpcode, ExtAluOpcode, Instruction, RawProgram, SeqBlock,
};

/// Why a program could not be compiled.
#[derive(Debug, thiserror::Error)]
pub enum JitError {
    /// This build has no backend (not Linux x86_64).
    #[error("the recursion JIT is only available on Linux x86_64")]
    Unavailable,
    /// The program uses an instruction the current phase cannot emit.
    #[error("no emitter for {0}")]
    Unsupported(&'static str),
}

// ── Layout contract ──────────────────────────────────────────────────────
// The emitted code addresses memory as `base + addr * size_of::<MemoryEntry>`
// with the value at offset 0.  These are the assumptions that makes, checked
// at compile time so a layout change in `zkm-recursion-core` breaks the
// build rather than silently producing a JIT that reads the wrong words.

/// Bytes per memory cell, and the stride the emitted code scales an address
/// by.
pub const MEMORY_ENTRY_SIZE: usize = core::mem::size_of::<MemoryEntry<KoalaBear>>();
/// Bytes per field element — the width of an emitted load or store.
pub const FELT_SIZE: usize = core::mem::size_of::<KoalaBear>();

const _: () = {
    assert!(FELT_SIZE == 4, "emitted loads/stores are 32-bit");
    assert!(
        core::mem::size_of::<Block<KoalaBear>>() == 4 * FELT_SIZE,
        "a Block is four contiguous field elements"
    );
    assert!(
        MEMORY_ENTRY_SIZE == core::mem::size_of::<Block<KoalaBear>>(),
        "a MemoryEntry is exactly its Block: the emitted stride is size_of::<Block>()"
    );
    assert!(MEMORY_ENTRY_SIZE == 16, "stride must stay a power of two for scaled indexing");
};

/// How the planner classifies one instruction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Coverage {
    /// Emitted as straight-line machine code.
    Native,
    /// Emitted as a call to a Rust helper — correct, but at call cost.
    CallOut,
    /// No emitter in this phase; the program falls back to the interpreter.
    Fallback,
}

/// What a compile of this program would achieve, without compiling it.
///
/// This is the number that says whether the next phase is worth writing: a
/// phase that emits natively for 3% of a program's instructions cannot beat
/// the interpreter no matter how good the code is.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Plan {
    /// Instructions emitted as straight-line code.
    pub native: usize,
    /// Instructions emitted as helper calls.
    pub call_out: usize,
    /// Instructions with no emitter yet.
    pub fallback: usize,
    /// Per-variant counts, in [`Plan::VARIANTS`] order.
    pub mix: [usize; 12],
    /// `BaseAlu` by opcode: Add, Sub, Mul, Div (Div folds in DivFAssert).
    pub base_ops: [usize; 4],
    /// `ExtAlu` by opcode: Add, Sub, Mul, Div (Div folds in DivEAssert).
    ///
    /// This is what decides how much of the extension arithmetic is worth
    /// inlining: a lane-wise add is four instructions, a quartic multiply
    /// mod `X^4 - 3` is sixteen Montgomery multiplies and their reduction.
    pub ext_ops: [usize; 4],
}

impl Plan {
    /// Variant names, indexed as [`Plan::mix`].
    pub const VARIANTS: [&'static str; 12] = [
        "BaseAlu",
        "ExtAlu",
        "Mem",
        "Poseidon2",
        "Select",
        "HintBits",
        "HintAddCurve",
        "Print",
        "HintExt2Felts",
        "Ext2Felts",
        "CommitPublicValues",
        "Hint",
    ];

    /// Total instructions considered.
    #[must_use]
    pub fn total(&self) -> usize {
        self.native + self.call_out + self.fallback
    }

    /// Fraction of instructions that would leave the interpreter entirely.
    #[must_use]
    pub fn native_fraction(&self) -> f64 {
        if self.total() == 0 {
            return 0.0;
        }
        self.native as f64 / self.total() as f64
    }
}

/// Which variants the current phase can emit.
fn coverage_of<F>(instr: &Instruction<F>) -> (usize, Coverage) {
    match instr {
        // P2/P3 targets: pure address-to-address arithmetic, every operand a
        // compile-time constant.
        Instruction::BaseAlu(_) => (0, Coverage::Fallback),
        Instruction::ExtAlu(_) => (1, Coverage::Fallback),
        Instruction::Mem(_) => (2, Coverage::Fallback),
        Instruction::Select(_) => (4, Coverage::Fallback),
        // P4: too much work per instruction to inline, but rare enough that a
        // call is free relative to the permutation itself.
        Instruction::Poseidon2(_) => (3, Coverage::Fallback),
        Instruction::HintBits(_) => (5, Coverage::Fallback),
        Instruction::HintAddCurve(_) => (6, Coverage::Fallback),
        Instruction::Print(_) => (7, Coverage::Fallback),
        Instruction::HintExt2Felts(_) => (8, Coverage::Fallback),
        Instruction::Ext2Felts(_) => (9, Coverage::Fallback),
        Instruction::CommitPublicValues(_) => (10, Coverage::Fallback),
        Instruction::Hint(_) => (11, Coverage::Fallback),
    }
}

/// Classify every instruction in an analyzed program.
#[must_use]
pub fn plan<F>(program: &RawProgram<AnalyzedInstruction<F>>) -> Plan {
    let mut p = Plan::default();
    fn walk<F>(blocks: &[SeqBlock<AnalyzedInstruction<F>>], p: &mut Plan) {
        for block in blocks {
            match block {
                SeqBlock::Basic(basic) => {
                    for ai in &basic.instrs {
                        let (idx, cov) = coverage_of(ai.inner());
                        p.mix[idx] += 1;
                        match ai.inner() {
                            Instruction::BaseAlu(i) => {
                                p.base_ops[match i.opcode {
                                    BaseAluOpcode::AddF => 0,
                                    BaseAluOpcode::SubF => 1,
                                    BaseAluOpcode::MulF => 2,
                                    BaseAluOpcode::DivF | BaseAluOpcode::DivFAssert => 3,
                                }] += 1;
                            }
                            Instruction::ExtAlu(i) => {
                                p.ext_ops[match i.opcode {
                                    ExtAluOpcode::AddE => 0,
                                    ExtAluOpcode::SubE => 1,
                                    ExtAluOpcode::MulE => 2,
                                    ExtAluOpcode::DivE | ExtAluOpcode::DivEAssert => 3,
                                }] += 1;
                            }
                            _ => {}
                        }
                        match cov {
                            Coverage::Native => p.native += 1,
                            Coverage::CallOut => p.call_out += 1,
                            Coverage::Fallback => p.fallback += 1,
                        }
                    }
                }
                SeqBlock::Parallel(subs) => {
                    // Counted, not skipped: the walker's `nb_*` counters drop
                    // these because a sub-walk runs on a fresh state, which is
                    // exactly how they came to be undercounted before.
                    for sub in subs {
                        walk(&sub.seq_blocks, p);
                    }
                }
            }
        }
    }
    walk(&program.seq_blocks, &mut p);
    p
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_empty_program_plans_to_nothing() {
        let p: Plan = plan::<KoalaBear>(&RawProgram::default());
        assert_eq!(p.total(), 0);
        assert_eq!(p.native_fraction(), 0.0);
    }

    /// The layout contract is a `const` assertion, so reaching this test at
    /// all means it held; the test records WHY those numbers matter.
    #[test]
    fn the_emitted_addressing_matches_the_runtime_layout() {
        assert_eq!(MEMORY_ENTRY_SIZE, 16);
        assert_eq!(FELT_SIZE, 4);
        assert_eq!(Plan::VARIANTS.len(), 12);
    }
}
