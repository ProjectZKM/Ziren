use backtrace::Backtrace;
use p3_field::Field;
use serde::{Deserialize, Serialize};
use shape::RecursionShape;
use zkm_stark::air::{MachineAir, MachineProgram};
use zkm_stark::septic_digest::SepticDigest;

use crate::runtime::RawProgram;
use crate::*;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RecursionProgram<F> {
    /// Linearly ordered instruction list. Today this is the canonical
    /// program representation that the runtime executes; the compiler
    /// emits it directly. SeqBlock-based programs (`seq_blocks` below)
    /// are introduced by #259 Phase A1/A2 as additive scaffolding for
    /// the SP1 parallel-runtime port — empty for now, populated once
    /// the compiler is migrated in Phase A3.
    pub instructions: Vec<Instruction<F>>,
    /// Optional SeqBlock representation of the program (#259 Phase A2).
    /// Empty for compiler output today; will become the canonical
    /// representation once Phase A3 (compiler) and Phase A4 (runtime)
    /// land. `#[serde(default)]` keeps backward compatibility with
    /// programs serialized before this field existed.
    #[serde(default = "RawProgram::default")]
    pub seq_blocks: RawProgram<Instruction<F>>,
    pub total_memory: usize,
    #[serde(skip)]
    pub traces: Vec<Option<Backtrace>>,
    pub shape: Option<RecursionShape>,
}

impl<F> RecursionProgram<F> {
    /// Iterate over the program's instructions in execution order.
    ///
    /// If `seq_blocks` is populated (post-Phase A3 compiler), walks the
    /// SeqBlock structure (recursing through parallel sub-programs in
    /// vec order — execution order is canonical even though parallel
    /// sub-programs may run concurrently at runtime). Otherwise falls
    /// back to the flat `instructions` list (current compiler output).
    ///
    /// SP1 ref: `/tmp/sp1/crates/recursion/executor/src/program.rs::raw::RawProgram::iter`.
    pub fn iter_instructions(&self) -> Box<dyn Iterator<Item = &Instruction<F>> + '_> {
        if !self.seq_blocks.seq_blocks.is_empty() {
            Box::new(self.seq_blocks.iter())
        } else {
            Box::new(self.instructions.iter())
        }
    }

    /// Total instruction count, recursing through parallel sub-programs
    /// when `seq_blocks` is populated.
    pub fn instruction_count(&self) -> usize {
        if !self.seq_blocks.seq_blocks.is_empty() {
            self.seq_blocks.instruction_count()
        } else {
            self.instructions.len()
        }
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
