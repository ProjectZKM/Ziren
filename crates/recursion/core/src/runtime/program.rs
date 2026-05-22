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
    /// SeqBlock representation of the program — the canonical
    /// instruction container. Phase A4 (#259) migrated the runtime
    /// off the flat `instructions` Vec and onto `iter_instructions()`,
    /// and Phase A5 dropped the redundant `instructions` field
    /// entirely. The compiler emits one `Basic` block today; Phase C
    /// will introduce `Parallel` blocks once the memory layer is
    /// thread-safe.
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
