use std::error::Error;

use p3_air::{
    capture_symbolic_constraints, Air, AirLayout, BaseAir, SymbolicAirBuilder, SymbolicConstraints,
};
use p3_field::Field;
use p3_matrix::{dense::RowMajorMatrix, Matrix};

use crate::{septic_digest::SepticDigest, MachineRecord, PicusInfo, PROOF_MAX_NUM_PVS};

pub use zkm_derive::MachineAir;

use super::LookupScope;

/// Capture a machine AIR's constraints using the shared public-values buffer layout.
///
/// Machine AIRs receive `PROOF_MAX_NUM_PVS` public-value slots, independently of
/// `BaseAir::num_public_values` (which they may leave at its default of zero). We therefore
/// use `capture_symbolic_constraints` without validating the layout against that metadata.
/// Keep this layout shared by degree inference, constraint counts, and the soundness census.
pub fn capture_machine_constraints<F, A>(air: &A) -> SymbolicConstraints<F>
where
    F: Field,
    A: MachineAir<F> + Air<SymbolicAirBuilder<F>>,
{
    capture_symbolic_constraints(
        AirLayout {
            preprocessed_width: air.preprocessed_width(),
            main_width: air.width(),
            num_public_values: PROOF_MAX_NUM_PVS,
            ..Default::default()
        },
        |builder| air.eval(builder),
    )
}

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

    /// Returns information about Picus annotations on AIR columns.
    ///
    /// This includes:
    /// - Input ranges: columns marked with `#[picus(input)]`
    /// - Selector indices: columns marked with `#[picus(selector)]`
    fn picus_info(&self) -> PicusInfo {
        PicusInfo::default()
    }

    /// Whether the chip's `#[picus(selector)]` columns partition its real rows.
    ///
    /// When `true`, the Picus `top` module asserts that the selector columns sum to exactly
    /// `is_real` (or to one when `is_real` is specialized), rather than merely being boolean and
    /// mutually exclusive.  Opt-in: an instruction chip whose selectors are its opcode flags
    /// declares it; table chips keep the weaker default.
    fn selectors_partition_real_rows(&self) -> bool {
        false
    }

    /// Whether Picus should generate a selector-specialized module for `selector_name`.
    ///
    /// Override only when a selector value is impossible by trace construction and would make
    /// the specialized module contradictory (and therefore vacuously deterministic).
    fn picus_selector_specialization_allowed(&self, _selector_name: &str) -> bool {
        true
    }
}

/// A program that defines the control flow of a machine through a program counter.
pub trait MachineProgram<F>: Send + Sync {
    /// Gets the starting program counter.
    fn pc_start(&self) -> F;

    /// Gets the initial global cumulative sum.
    fn initial_global_cumulative_sum(&self) -> SepticDigest<F>;

    /// The area pins this program's proofs commit under, when the program
    /// carries them (a recursion program's shape names its pin class); `None`
    /// leaves the choice to the machine.
    fn area_pins(&self) -> Option<crate::jagged::RecursionPins> {
        None
    }
}

/// Asserts that each AIR's `BaseAir::preprocessed_width` equals the width of the trace its
/// `generate_preprocessed_trace` produces for `program`, or zero when it produces none.
pub fn assert_preprocessed_widths_match<F, A>(
    airs: impl IntoIterator<Item = A>,
    program: &A::Program,
) where
    F: Field,
    A: MachineAir<F>,
{
    for air in airs {
        let trace = air.generate_preprocessed_trace(program);
        let expected = trace.as_ref().map_or(0, |trace| trace.width());
        assert_eq!(BaseAir::<F>::preprocessed_width(&air), expected, "chip {}", air.name());
    }
}
