use std::error::Error;

use p3_air::BaseAir;
use p3_field::Field;
use p3_matrix::dense::RowMajorMatrix;

use crate::{septic_digest::SepticDigest, MachineRecord, PicusInfo};

pub use zkm_derive::MachineAir;

use super::LookupScope;

/// An AIR that is part of a multi table AIR arithmetization.
pub trait MachineAir<F: Field>: BaseAir<F> + 'static + Send + Sync {
    /// The execution record containing events for producing the air trace.
    type Record: MachineRecord;

    /// The program that defines the control flow of the machine.
    type Program: MachineProgram<F>;

    /// The type used for error handling.
    type Error: Error + Send + Sync;

    /// A unique identifier for this AIR as part of a machine.
    fn name(&self) -> String;

    /// The number of rows in the trace
    fn num_rows(&self, _input: &Self::Record) -> Option<usize> {
        None
    }

    /// Generate the trace for a given execution record.
    ///
    /// - `input` is the execution record containing the events to be written to the trace.
    /// - `output` is the execution record containing events that the `MachineAir` can add to the
    ///   record such as byte lookup requests.
    fn generate_trace(
        &self,
        input: &Self::Record,
        output: &mut Self::Record,
    ) -> Result<RowMajorMatrix<F>, Self::Error>;

    /// Generate the dependencies for a given execution record.
    fn generate_dependencies(
        &self,
        input: &Self::Record,
        output: &mut Self::Record,
    ) -> Result<(), Self::Error> {
        self.generate_trace(input, output)?;
        Ok(())
    }

    /// Whether this execution record contains events for this air.
    fn included(&self, shard: &Self::Record) -> bool;

    /// The width of the preprocessed trace.
    fn preprocessed_width(&self) -> usize {
        0
    }

    /// The number of rows in the preprocessed trace
    fn preprocessed_num_rows(&self, _program: &Self::Program, _instrs_len: usize) -> Option<usize> {
        None
    }

    /// Generate the preprocessed trace given a specific program.
    fn generate_preprocessed_trace(&self, _program: &Self::Program) -> Option<RowMajorMatrix<F>> {
        None
    }

    /// Specifies whether it's trace should be part of either the global or local commit.
    fn commit_scope(&self) -> LookupScope {
        LookupScope::Local
    }

    /// Specifies whether the air only uses the local row, and not the next row.
    fn local_only(&self) -> bool {
        false
    }

    /// Specifies whether a local-only AIR still depends on absolute row position.
    ///
    /// This is for chips that never read the next row, but do use predicates like
    /// `when_first_row()` or `when_last_row()` to distinguish the beginning or end
    /// of the trace. Such chips still need `FirstRow` / `Transition` / `LastRow`
    /// extraction phases even though they are `local_only()`.
    fn local_only_row_sensitive(&self) -> bool {
        false
    }

    /// Returns information about Picus annotations on AIR columns.
    ///
    /// This includes:
    /// - Input ranges: columns marked with `#[picus(input)]`
    /// - Output ranges: columns marked with `#[picus(output)]`
    /// - Transition-input ranges: columns marked with `#[picus(transition_input)]`
    /// - Transition-output ranges: columns marked with `#[picus(transition_output)]`
    /// - Selector indices: columns marked with `#[picus(selector)]`
    fn picus_info(&self) -> PicusInfo {
        PicusInfo::default()
    }

    /// Specifies whether the chip's Picus selectors partition the set of real rows.
    ///
    /// When this returns `true`, Picus may emit a stronger selector-shape top module asserting
    /// that the sum of all selector columns is exactly `is_real`, rather than merely proving the
    /// selectors are boolean and mutually exclusive. This is opt-in so existing chips keep their
    /// current selector semantics unless they explicitly declare the stronger invariant.
    fn selectors_partition_real_rows(&self) -> bool {
        false
    }

    /// Specifies whether Picus should generate a selector-specialized module for this
    /// `(phase, selector)` pair.
    ///
    /// `phase` is the stable Picus extraction phase suffix, such as `first_row`, `transition`,
    /// `boundary`, or `last_row`. `selector_name` is the user-facing selector annotation name
    /// from `PicusInfo`.
    ///
    /// Most chips can keep the default `true`. Override this only when some phase/selector pairs
    /// are impossible by trace construction and would therefore produce contradictory modules.
    fn picus_selector_specialization_allowed(&self, _phase: &str, _selector_name: &str) -> bool {
        true
    }
}

/// A program that defines the control flow of a machine through a program counter.
pub trait MachineProgram<F>: Send + Sync {
    /// Gets the starting program counter.
    fn pc_start(&self) -> F;

    /// Gets the initial global cumulative sum.
    fn initial_global_cumulative_sum(&self) -> SepticDigest<F>;
}
