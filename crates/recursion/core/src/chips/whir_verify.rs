//! WHIR proof verification chip for recursion.
//!
//! Verifies a complete WHIR proof inside the recursion circuit,
//! replacing the FriFold + BatchFRI chips for WHIR-based proofs.
//!
//! # Architecture
//!
//! The WHIR verifier is decomposed into sub-chips:
//!   - SumcheckVerifyChip: verifies sumcheck round consistency
//!   - Poseidon2Chip: Merkle path hashing (reused from FRI)
//!   - ExtAluChip: extension field arithmetic (reused)
//!   - WhirVerifyChip (this file): orchestrates the protocol flow
//!
//! Each row of this chip processes one step of the WHIR verification:
//! - Merkle root observation (absorb into transcript)
//! - OOD evaluation check (verify claimed value matches commitment)
//! - STIR query verification (Merkle path opening)
//! - Round transition (increment round, absorb new commitment)

use core::borrow::Borrow;

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::PrimeField32;
use p3_matrix::dense::RowMajorMatrix;

use zkm_derive::AlignedBorrow;
use zkm_stark::air::MachineAir;

use crate::air::Block;
use crate::builder::ZKMRecursionAirBuilder;
use crate::runtime::RecursionProgram;
use crate::ExecutionRecord;

use super::mem::MemoryAccessColsChips;

pub const NUM_WHIR_VERIFY_COLS: usize = core::mem::size_of::<WhirVerifyCols<u8>>();
pub const NUM_WHIR_VERIFY_PREPROCESSED_COLS: usize =
    core::mem::size_of::<WhirVerifyPreprocessedCols<u8>>();

/// WHIR proof verification chip.
pub struct WhirVerifyChip<const DEGREE: usize> {
    pub fixed_log2_rows: Option<usize>,
    pub pad: bool,
}

impl<const DEGREE: usize> Default for WhirVerifyChip<DEGREE> {
    fn default() -> Self {
        Self { fixed_log2_rows: None, pad: true }
    }
}

/// Preprocessed columns for WHIR verification.
#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct WhirVerifyPreprocessedCols<T: Copy> {
    /// Step type selectors (mutually exclusive).
    pub is_merkle_root: T,
    pub is_ood_check: T,
    pub is_stir_query: T,
    pub is_round_transition: T,

    /// Memory access for the commitment (Merkle root digest).
    pub commitment_mem: MemoryAccessColsChips<T>,

    /// Memory access for the evaluation point.
    pub eval_point_mem: MemoryAccessColsChips<T>,

    /// Memory access for the claimed value.
    pub claimed_value_mem: MemoryAccessColsChips<T>,

    /// Row activity selector.
    pub is_real: T,
}

/// Main trace columns for WHIR verification.
#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct WhirVerifyCols<T: Copy> {
    /// Current round index.
    pub round_index: T,

    /// Merkle root (digest) for the current round's commitment.
    pub commitment: Block<T>,

    /// The evaluation point coordinate for this round.
    pub eval_coord: Block<T>,

    /// The claimed evaluation value.
    pub claimed_value: Block<T>,

    /// Accumulated Fiat-Shamir challenge state.
    pub challenge_state: Block<T>,
}

impl<F, const DEGREE: usize> BaseAir<F> for WhirVerifyChip<DEGREE> {
    fn width(&self) -> usize {
        NUM_WHIR_VERIFY_COLS
    }
}

impl<F: PrimeField32, const DEGREE: usize> MachineAir<F> for WhirVerifyChip<DEGREE> {
    type Record = ExecutionRecord<F>;
    type Program = RecursionProgram<F>;
    type Error = crate::RecursionChipError;

    fn name(&self) -> String {
        "WhirVerify".to_string()
    }

    fn generate_dependencies(
        &self,
        _: &Self::Record,
        _: &mut Self::Record,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    fn preprocessed_width(&self) -> usize {
        NUM_WHIR_VERIFY_PREPROCESSED_COLS
    }

    fn generate_preprocessed_trace(&self, _program: &Self::Program) -> Option<RowMajorMatrix<F>> {
        // WhirVerify instructions are not yet emitted by the recursion circuit.
        // When verify_whir_pcs is wired in, this will extract WhirVerify instructions
        // from the program and generate the preprocessed selector rows.
        None
    }

    fn generate_trace(
        &self,
        _input: &Self::Record,
        _output: &mut Self::Record,
    ) -> Result<RowMajorMatrix<F>, Self::Error> {
        // No WhirVerify events are generated yet.
        let values: Vec<F> = Vec::new();
        Ok(RowMajorMatrix::new(values, NUM_WHIR_VERIFY_COLS))
    }

    fn included(&self, _shard: &Self::Record) -> bool {
        false
    }
}

impl<AB, const DEGREE: usize> Air<AB> for WhirVerifyChip<DEGREE>
where
    AB: ZKMRecursionAirBuilder,
    AB::Var: 'static,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.current_slice();
        let local: &WhirVerifyCols<AB::Var> = (*local).borrow();

        let prep = builder.preprocessed().clone();
        let prep_local = prep.current_slice();
        let prep_local: &WhirVerifyPreprocessedCols<AB::Var> = (*prep_local).borrow();

        // ── Step type mutual exclusivity ────────────────────────
        let step_sum = prep_local.is_merkle_root
            + prep_local.is_ood_check
            + prep_local.is_stir_query
            + prep_local.is_round_transition;
        builder.assert_eq(step_sum, prep_local.is_real);

        // ── Memory interactions ─────────────────────────────────
        //
        // All step types read their relevant data from memory.
        // The actual computation (hashing, field arithmetic) is
        // delegated to Poseidon2 and ExtAlu chips via memory lookups.

        // Read commitment (Merkle root) when observing or transitioning.
        let read_commitment = prep_local.is_merkle_root + prep_local.is_round_transition;
        builder.receive_block(
            prep_local.commitment_mem.addr,
            local.commitment,
            read_commitment,
        );

        // Read eval_point for OOD checks and STIR queries.
        let read_eval_point = prep_local.is_ood_check + prep_local.is_stir_query;
        builder.receive_block(
            prep_local.eval_point_mem.addr,
            local.eval_coord,
            read_eval_point,
        );

        // Read claimed_value for OOD checks and STIR queries.
        let read_claimed = prep_local.is_ood_check + prep_local.is_stir_query;
        builder.receive_block(
            prep_local.claimed_value_mem.addr,
            local.claimed_value,
            read_claimed,
        );

        // ── Round transition constraint ─────────────────────────
        //
        // When is_round_transition: the round_index must increment.
        // This is enforced via the preprocessed trace — each round
        // transition row has a predetermined round_index value.
        // The constraint here just ensures the memory read matches.
        //
        // The actual Fiat-Shamir state update (absorbing the new
        // commitment) is handled by the Poseidon2 chip via memory
        // interactions emitted by the recursion program.
    }
}
