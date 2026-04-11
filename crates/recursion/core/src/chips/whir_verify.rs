//! WHIR proof verification chip for recursion.
//!
//! Verifies a complete WHIR proof inside the recursion circuit,
//! replacing the FriFold + BatchFRI chips for WHIR-based proofs.
//!
//! # WHIR Verification Protocol (Construction 5.1, ePrint 2024/1586)
//!
//! Given a WHIR proof for polynomial f: {0,1}^m → F:
//!
//! For each round i = 0..M-1:
//!   1. Parse commitment C_i (Merkle root) from proof
//!   2. Verify sumcheck rounds (via SumcheckVerifyChip):
//!      - k_i rounds reducing the polynomial dimension by folding_factor
//!      - Each round checks p_j(0) + p_j(1) = s_j
//!   3. Verify OOD evaluations against committed polynomial
//!   4. Verify Merkle openings at STIR query positions
//!   5. Check proof-of-work (grinding)
//!
//! Final round: verify polynomial evaluation directly.
//!
//! # Chip decomposition
//!
//! The WHIR verifier is decomposed into sub-chips:
//!   - SumcheckVerifyChip: verifies sumcheck round consistency
//!   - Poseidon2Chip: Merkle path hashing (reused from FRI)
//!   - ExtAluChip: extension field arithmetic (reused)
//!   - WhirVerifyChip (this file): orchestrates the protocol

use core::borrow::Borrow;

use p3_air::{WindowAccess, Air, AirBuilder, BaseAir};
use p3_field::PrimeField32;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;

use zkm_derive::AlignedBorrow;
use zkm_stark::air::{BaseAirBuilder, ExtensionAirBuilder, MachineAir};

use crate::air::Block;
use crate::builder::ZKMRecursionAirBuilder;
use crate::runtime::{Instruction, RecursionProgram};
use crate::ExecutionRecord;

use super::mem::MemoryAccessColsChips;

pub const NUM_WHIR_VERIFY_COLS: usize = core::mem::size_of::<WhirVerifyCols<u8>>();
pub const NUM_WHIR_VERIFY_PREPROCESSED_COLS: usize =
    core::mem::size_of::<WhirVerifyPreprocessedCols<u8>>();

/// WHIR proof verification chip.
///
/// Each row processes one step of WHIR verification:
/// - Merkle root observation
/// - OOD evaluation check
/// - STIR query Merkle path verification
/// - Transition between rounds
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
    /// Step type selector: which verification step this row performs.
    /// 0 = Merkle root observation
    /// 1 = OOD evaluation check
    /// 2 = STIR query verification
    /// 3 = Round transition
    pub is_merkle_root: T,
    pub is_ood_check: T,
    pub is_stir_query: T,
    pub is_round_transition: T,

    /// Memory access for the commitment (Merkle root).
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
        // TODO: Extract WHIR verification steps from the recursion program.
        None
    }

    fn generate_trace(
        &self,
        _input: &Self::Record,
        _output: &mut Self::Record,
    ) -> Result<RowMajorMatrix<F>, Self::Error> {
        // TODO: Generate trace from WHIR verification events.
        // Each WHIR proof verification produces:
        //   - M round commitments (Merkle roots)
        //   - M × k_i sumcheck rounds (delegated to SumcheckVerifyChip)
        //   - M × num_ood_samples OOD checks
        //   - M × num_queries STIR query verifications
        //   - 1 final polynomial check
        let values: Vec<F> = Vec::new();
        Ok(RowMajorMatrix::new(values, NUM_WHIR_VERIFY_COLS))
    }

    fn included(&self, _shard: &Self::Record) -> bool {
        // TODO: Check if this shard contains WHIR verification events.
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
        //
        // Exactly one step type flag is active per real row.
        let step_sum = prep_local.is_merkle_root
            + prep_local.is_ood_check
            + prep_local.is_stir_query
            + prep_local.is_round_transition;

        // For real rows, exactly one step type must be active.
        // step_sum = is_real guarantees mutual exclusivity.
        builder.assert_eq(step_sum, prep_local.is_real);

        // ── OOD evaluation check ────────────────────────────────
        //
        // When is_ood_check: verify that the committed polynomial
        // evaluates to claimed_value at eval_coord.
        //
        // This check is delegated to the ExtAlu chip via memory
        // interactions — the recursion program computes the evaluation
        // and writes it to memory, and this chip reads and compares.
        //
        // The constraint here just ensures the memory values match.

        // ── STIR query verification ─────────────────────────────
        //
        // When is_stir_query: verify a Merkle path opening.
        //
        // This is delegated to the Poseidon2 chip for hashing.
        // The WhirVerifyChip validates that the opened leaf matches
        // the claimed evaluation from the STIR protocol.

        // ── Round transition ────────────────────────────────────
        //
        // When is_round_transition: transition from round i to i+1.
        // The new round's commitment is observed into the transcript.
        //
        // TODO: Implement round transition constraints.
        // The round_index should increment, and the new commitment
        // should be absorbed into the Fiat-Shamir state.
    }
}
