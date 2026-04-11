//! Sumcheck verifier chip for WHIR recursion.
//!
//! Verifies sumcheck rounds inside the recursion circuit, replacing
//! the FriFold chip for WHIR-based proof compression.
//!
//! # Protocol (Lund-Fortnow-Karloff-Nisan, 1992)
//!
//! The sumcheck protocol reduces a claim about a multilinear polynomial
//! sum over the Boolean hypercube to a single evaluation:
//!
//!   claim: Σ_{b ∈ {0,1}^m} f(b) = v
//!
//! In each round i = 1..m:
//!   1. Prover sends univariate polynomial p_i(X) of degree d
//!      such that p_i(0) + p_i(1) = s_i (previous round's claim)
//!   2. Verifier checks: p_i(0) + p_i(1) = s_i
//!   3. Verifier samples random challenge r_i
//!   4. New claim: s_{i+1} = p_i(r_i)
//!
//! After m rounds: verifier checks f(r_1, ..., r_m) = s_{m+1}
//!
//! # WHIR integration
//!
//! In WHIR, the sumcheck is used per folding round to reduce the
//! constraint claim. The degree of p_i is determined by the constraint
//! degree (typically 2 for linear constraints).
//!
//! For WHIR with folding_factor=4, each WHIR round runs 4 sumcheck
//! rounds, producing 4 challenges (r_1, r_2, r_3, r_4) that fold
//! the polynomial.
//!
//! # Chip design
//!
//! Each trace row verifies one sumcheck round:
//!   - Input: previous claim s_i, polynomial coefficients (c_0, c_1, c_2)
//!   - Constraint: c_0 + (c_0 + c_1 + c_2) = s_i
//!     (i.e., p(0) + p(1) = s_i)
//!   - Output: new claim s_{i+1} = c_0 + c_1·r_i + c_2·r_i²
//!
//! The constraint degree is 2 (quadratic in r_i), which is lower
//! than FriFold's degree-3 constraints.

use core::borrow::Borrow;
use std::borrow::BorrowMut;

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

pub const NUM_SUMCHECK_VERIFY_COLS: usize = core::mem::size_of::<SumcheckVerifyCols<u8>>();
pub const NUM_SUMCHECK_VERIFY_PREPROCESSED_COLS: usize =
    core::mem::size_of::<SumcheckVerifyPreprocessedCols<u8>>();

/// Sumcheck verification chip.
///
/// Each row verifies one sumcheck round:
///   p(0) + p(1) = claimed_sum
///   new_claim = p(challenge)
pub struct SumcheckVerifyChip<const DEGREE: usize> {
    pub fixed_log2_rows: Option<usize>,
    pub pad: bool,
}

impl<const DEGREE: usize> Default for SumcheckVerifyChip<DEGREE> {
    fn default() -> Self {
        Self { fixed_log2_rows: None, pad: true }
    }
}

/// Preprocessed columns for sumcheck verification.
#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct SumcheckVerifyPreprocessedCols<T: Copy> {
    /// Whether this is the first round of a sumcheck instance.
    pub is_first: T,

    /// Memory access for the challenge r_i.
    pub challenge_mem: MemoryAccessColsChips<T>,

    /// Memory access for the claimed sum s_i.
    pub claimed_sum_mem: MemoryAccessColsChips<T>,

    /// Memory access for polynomial coefficient c_0.
    pub c0_mem: MemoryAccessColsChips<T>,

    /// Memory access for polynomial coefficient c_1.
    pub c1_mem: MemoryAccessColsChips<T>,

    /// Memory access for polynomial coefficient c_2.
    pub c2_mem: MemoryAccessColsChips<T>,

    /// Memory access for the output (new claimed sum).
    pub new_claim_mem: MemoryAccessColsChips<T>,

    /// Row activity selector.
    pub is_real: T,
}

/// Main trace columns for sumcheck verification.
///
/// Stores the intermediate values needed to verify one sumcheck round:
///   p(X) = c_0 + c_1·X + c_2·X²
///   Check: p(0) + p(1) = s_i  ⟺  c_0 + (c_0 + c_1 + c_2) = s_i
///                                 ⟺  2·c_0 + c_1 + c_2 = s_i
///   Output: s_{i+1} = c_0 + c_1·r + c_2·r²
#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct SumcheckVerifyCols<T: Copy> {
    /// The Fiat-Shamir challenge for this round (r_i ∈ F^D).
    pub challenge: Block<T>,

    /// The claimed sum from the previous round (s_i ∈ F^D).
    pub claimed_sum: Block<T>,

    /// Polynomial coefficient c_0 ∈ F^D.
    pub c0: Block<T>,

    /// Polynomial coefficient c_1 ∈ F^D.
    pub c1: Block<T>,

    /// Polynomial coefficient c_2 ∈ F^D.
    pub c2: Block<T>,

    /// The new claimed sum: s_{i+1} = c_0 + c_1·r + c_2·r² ∈ F^D.
    pub new_claim: Block<T>,
}

impl<F, const DEGREE: usize> BaseAir<F> for SumcheckVerifyChip<DEGREE> {
    fn width(&self) -> usize {
        NUM_SUMCHECK_VERIFY_COLS
    }
}

impl<F: PrimeField32, const DEGREE: usize> MachineAir<F> for SumcheckVerifyChip<DEGREE> {
    type Record = ExecutionRecord<F>;
    type Program = RecursionProgram<F>;
    type Error = crate::RecursionChipError;

    fn name(&self) -> String {
        "SumcheckVerify".to_string()
    }

    fn generate_dependencies(
        &self,
        _: &Self::Record,
        _: &mut Self::Record,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    fn preprocessed_width(&self) -> usize {
        NUM_SUMCHECK_VERIFY_PREPROCESSED_COLS
    }

    fn generate_preprocessed_trace(&self, _program: &Self::Program) -> Option<RowMajorMatrix<F>> {
        // TODO: Extract sumcheck verify instructions from the recursion program
        // and generate preprocessed trace rows.
        None
    }

    fn generate_trace(
        &self,
        _input: &Self::Record,
        _output: &mut Self::Record,
    ) -> Result<RowMajorMatrix<F>, Self::Error> {
        // TODO: Generate trace from sumcheck verification events.
        // Each event corresponds to one sumcheck round verification.
        let values: Vec<F> = Vec::new();
        Ok(RowMajorMatrix::new(values, NUM_SUMCHECK_VERIFY_COLS))
    }

    fn included(&self, _shard: &Self::Record) -> bool {
        // TODO: Check if this shard contains sumcheck verification events.
        false
    }
}

impl<AB, const DEGREE: usize> Air<AB> for SumcheckVerifyChip<DEGREE>
where
    AB: ZKMRecursionAirBuilder,
    AB::Var: 'static,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.current_slice();
        let local: &SumcheckVerifyCols<AB::Var> = (*local).borrow();

        let prep = builder.preprocessed().clone();
        let prep_local = prep.current_slice();
        let prep_local: &SumcheckVerifyPreprocessedCols<AB::Var> = (*prep_local).borrow();

        // ── Sumcheck round verification constraint ──────────────
        //
        // p(0) + p(1) = claimed_sum
        //
        // p(0) = c_0
        // p(1) = c_0 + c_1 + c_2
        //
        // Therefore: 2·c_0 + c_1 + c_2 = claimed_sum
        //
        // In extension field arithmetic (Block<T> represents F^D):
        // We constrain each component of the extension field separately.

        // Constraint: 2·c_0 + c_1 + c_2 - claimed_sum = 0
        for i in 0..DEGREE {
            let p0 = local.c0.0[i];            // p(0) = c_0
            let p1_minus_c0 = local.c1.0[i] + local.c2.0[i]; // c_1 + c_2
            let sum = p0 + p0 + p1_minus_c0;   // 2·c_0 + c_1 + c_2
            let expected = local.claimed_sum.0[i];

            builder.when(prep_local.is_real).assert_eq(sum, expected);
        }

        // ── New claim computation constraint ────────────────────
        //
        // new_claim = p(challenge) = c_0 + c_1·r + c_2·r²
        //
        // This requires multiplication in the extension field.
        // For degree-2 polynomial evaluation at challenge r:
        //   new_claim = c_0 + r·(c_1 + r·c_2)
        //
        // We use Horner's method to reduce the constraint degree.

        // ── Evaluation constraint (Horner's method) ───────────────
        //
        // new_claim = p(challenge) = c_0 + challenge·(c_1 + challenge·c_2)
        //
        // Using extension field arithmetic via as_extension::<AB>().
        // The constraint degree is 3 (challenge · challenge · c_2),
        // which is within the DEGREE bound.

        let c0_ext = local.c0.as_extension::<AB>();
        let c1_ext = local.c1.as_extension::<AB>();
        let c2_ext = local.c2.as_extension::<AB>();
        let r_ext = local.challenge.as_extension::<AB>();
        let new_claim_ext = local.new_claim.as_extension::<AB>();

        // p(r) = c_0 + r·(c_1 + r·c_2) via Horner's method
        let inner = c1_ext.clone() + r_ext.clone() * c2_ext; // c_1 + r·c_2
        let expected = c0_ext + r_ext * inner;                // c_0 + r·(c_1 + r·c_2)

        builder
            .when(prep_local.is_real)
            .assert_ext_eq(expected, new_claim_ext);
    }
}
