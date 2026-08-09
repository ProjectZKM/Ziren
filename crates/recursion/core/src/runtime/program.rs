use backtrace::Backtrace;
use p3_field::Field;
use serde::{Deserialize, Serialize};
use shape::RecursionShape;
use zkm_pcs::air::{MachineAir, MachineProgram};
use zkm_pcs::septic_digest::SepticDigest;

use crate::runtime::RawProgram;
use crate::*;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RecursionProgram<F> {
    /// SeqBlock representation of the program — the canonical
    /// instruction container. An earlier refactor migrated the
    /// runtime off the flat `instructions` Vec and onto
    /// `iter_instructions()`, and the redundant `instructions`
    /// field has been dropped entirely. The compiler emits one
    /// `Basic` block today; a future revision will introduce
    /// `Parallel` blocks once the memory layer is thread-safe.
    #[serde(default = "RawProgram::default")]
    pub seq_blocks: RawProgram<Instruction<F>>,
    pub total_memory: usize,
    #[serde(skip)]
    pub traces: Vec<Option<Backtrace>>,
    pub shape: Option<RecursionShape>,
}

impl<F> RecursionProgram<F> {
    /// Iterate over the program's instructions in execution order,
    /// recursing through parallel sub-programs in deterministic vec
    /// order (the runtime collapses Parallel to sequential today; a
    /// follow-up will dispatch via `par_iter` once the memory layer
    /// is thread-safe).
    ///
    /// SP1 ref: crates/recursion/executor/src/program.rs::raw::RawProgram::iter.
    pub fn iter_instructions(&self) -> impl Iterator<Item = &Instruction<F>> {
        self.seq_blocks.iter()
    }

    /// Total instruction count, recursing through parallel sub-programs.
    pub fn instruction_count(&self) -> usize {
        self.seq_blocks.instruction_count()
    }
}

impl<F: p3_field::PrimeField64> RecursionProgram<F> {
    /// Number of memory cells the program addresses, i.e. `max(addr) + 1`.
    ///
    /// `Runtime::new` sizes its `ParMemVec` from `total_memory`, and
    /// `ParMemVec` never grows -- the disjoint-address invariant that makes
    /// its unsafe writes sound depends on a fixed allocation.  The compiler
    /// sets the field while lowering (`AsmCompiler::compile`), but a program
    /// assembled by hand from instructions has no such step, and
    /// `..Default::default()` leaves it at 0.  Every write then panics with
    /// "address N out of bounds (len=0)".
    ///
    /// The match is exhaustive on purpose: a new `Instruction` variant that
    /// addresses memory must be accounted for here, and the compiler will say
    /// so rather than letting the omission surface as a runtime panic.
    #[must_use]
    pub fn computed_total_memory(&self) -> usize {
        let mut max_addr: Option<u32> = None;
        let mut see = |a: &Address<F>| {
            let v = a.as_usize() as u32;
            max_addr = Some(max_addr.map_or(v, |m| m.max(v)));
        };
        for instruction in self.iter_instructions() {
            match instruction {
                Instruction::BaseAlu(i) => {
                    see(&i.addrs.out);
                    see(&i.addrs.in1);
                    see(&i.addrs.in2);
                }
                Instruction::ExtAlu(i) => {
                    see(&i.addrs.out);
                    see(&i.addrs.in1);
                    see(&i.addrs.in2);
                }
                Instruction::Mem(i) => see(&i.addrs.inner),
                Instruction::Poseidon2(i) => {
                    i.addrs.input.iter().for_each(&mut see);
                    i.addrs.output.iter().for_each(&mut see);
                }
                Instruction::Select(i) => {
                    see(&i.addrs.bit);
                    see(&i.addrs.out1);
                    see(&i.addrs.out2);
                    see(&i.addrs.in1);
                    see(&i.addrs.in2);
                }
                Instruction::HintBits(i) => {
                    see(&i.input_addr);
                    i.output_addrs_mults.iter().for_each(|(a, _)| see(a));
                }
                Instruction::HintAddCurve(i) => {
                    i.output_x_addrs_mults.iter().for_each(|(a, _)| see(a));
                    i.output_y_addrs_mults.iter().for_each(|(a, _)| see(a));
                }
                Instruction::Print(i) => see(&i.addr),
                Instruction::HintExt2Felts(i) => {
                    see(&i.input_addr);
                    i.output_addrs_mults.iter().for_each(|(a, _)| see(a));
                }
                Instruction::CommitPublicValues(i) => {
                    i.pv_addrs.as_array().iter().for_each(&mut see);
                }
                Instruction::Hint(i) => {
                    i.output_addrs_mults.iter().for_each(|(a, _)| see(a));
                }
                // 9d1c21d4 retired these three chips, but their instructions
                // remain in the ISA and the VM still executes them, so their
                // addresses still count towards the allocation.
            }
        }
        max_addr.map_or(0, |m| m as usize + 1)
    }
}

impl<F: Field> MachineProgram<F> for RecursionProgram<F> {
    fn pc_start(&self) -> F {
        F::ZERO
    }

    fn initial_global_cumulative_sum(&self) -> SepticDigest<F> {
        SepticDigest::<F>::zero()
    }
}

impl<F: Field> RecursionProgram<F> {
    #[inline]
    pub fn fixed_log2_rows<A: MachineAir<F>>(&self, air: &A) -> Option<usize> {
        self.shape
            .as_ref()
            .map(|shape| {
                shape
                    .inner
                    .get(&air.name())
                    .unwrap_or_else(|| panic!("Chip {} not found in specified shape", air.name()))
            })
            .copied()
    }

    pub fn shape_mut(&mut self) -> &mut Option<RecursionShape> {
        &mut self.shape
    }
}
