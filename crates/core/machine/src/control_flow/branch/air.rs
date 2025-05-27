use std::borrow::Borrow;

use p3_air::{Air, AirBuilder};
use p3_field::FieldAlgebra;
use p3_matrix::Matrix;
use zkm_core_executor::Opcode;
use zkm_stark::{
    air::{BaseAirBuilder, ZKMAirBuilder},
    Word,
};

use crate::{air::WordAirBuilder, operations::KoalaBearWordRangeChecker};

use super::{BranchChip, BranchColumns};

/// Verifies all the branching related columns.
///
/// It does this in few parts:
/// 1. It verifies that the next next pc is correct based on the branching column.  That column is a
///    boolean that indicates whether the branch condition is true.
/// 2. It verifies the correct value of branching based on the helper bool columns (a_eq_b,
///    a_gt_b, a_lt_b).
/// 3. It verifier the correct values of the helper bool columns based on op_a and op_b.
///
impl<AB> Air<AB> for BranchChip
where
    AB: ZKMAirBuilder,
    AB::Var: Sized,
{
    #[inline(never)]
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &BranchColumns<AB::Var> = (*local).borrow();

        // SAFETY: All selectors `is_beq`, `is_bne`, `is_bltz`, `is_bgez`, `is_blez`, `is_bgtz` are checked to be boolean.
        // Each "real" row has exactly one selector turned on, as `is_real`, the sum of the six selectors, is boolean.
        // Therefore, the `opcode` matches the corresponding opcode.
        builder.assert_bool(local.is_beq);
        builder.assert_bool(local.is_bne);
        builder.assert_bool(local.is_bltz);
        builder.assert_bool(local.is_bgez);
        builder.assert_bool(local.is_blez);
        builder.assert_bool(local.is_bgtz);
        let is_real = local.is_beq
            + local.is_bne
            + local.is_bltz
            + local.is_bgez
            + local.is_blez
            + local.is_bgtz;
        builder.assert_bool(is_real.clone());

        let opcode = local.is_beq * Opcode::BEQ.as_field::<AB::F>()
            + local.is_bne * Opcode::BNE.as_field::<AB::F>()
            + local.is_bltz * Opcode::BLTZ.as_field::<AB::F>()
            + local.is_bgez * Opcode::BGEZ.as_field::<AB::F>()
            + local.is_blez * Opcode::BLEZ.as_field::<AB::F>()
            + local.is_bgtz * Opcode::BGTZ.as_field::<AB::F>();

        // SAFETY: This checks the following.
        // - `num_extra_cycles = 0`
        // - `op_a_val` will be constrained in the BranchChip as `op_a_immutable = 1`
        // - `op_a_immutable = 1`, as this is a branch instruction
        // - `is_memory = 0`
        // - `is_syscall = 0`
        // - `is_halt = 0`
        // `next_pc` still has to be constrained, and this is done below.
        builder.receive_instruction(
            AB::Expr::ZERO,
            AB::Expr::ZERO,
            local.pc,
            local.next_pc.reduce::<AB>(),
            AB::Expr::ZERO,
            opcode,
            local.op_a_value,
            local.op_b_value,
            local.op_c_value,
            Word([AB::Expr::ZERO; 4]),
            AB::Expr::ONE,
            AB::Expr::ZERO,
            AB::Expr::ZERO,
            AB::Expr::ZERO,
            AB::Expr::ZERO,
            AB::Expr::ZERO,
            is_real.clone(),
        );

        // Evaluate program counter constraints.
        {
            // Range check local.next_pc, local.next_next_pc and local.target_pc, .
            // SAFETY: `is_real` is already checked to be boolean.
            // The `KoalaBearWordRangeChecker` assumes that the value is checked to be a valid word.
            // This is done when the word form is relevant, i.e. when `pc` and `next_pc` are sent to the ADD ALU table.
            // The ADD ALU table checks the inputs are valid words, when it invokes `AddOperation`.
            KoalaBearWordRangeChecker::<AB::F>::range_check(
                builder,
                local.next_pc,
                local.next_pc_range_checker,
                is_real.clone(),
            );

            KoalaBearWordRangeChecker::<AB::F>::range_check(
                builder,
                local.next_next_pc,
                local.next_next_pc_range_checker,
                is_real.clone(),
            );

            // When we are branching, assert that local.target_pc <==> local.next_pc + c.
            builder.send_alu(
                Opcode::ADD.as_field::<AB::F>(),
                local.target_pc,
                local.next_pc,
                local.op_c_value,
                local.is_branching,
            );

            // When we are not branching, assert that local.next_pc + 4 <==> next.next_next_pc.
            builder.when(is_real.clone()).when_not(local.is_branching).assert_eq(
                local.next_pc.reduce::<AB>() + AB::Expr::from_canonical_u32(4),
                local.next_next_pc.reduce::<AB>(),
            );

            // When we are branching, assert that local.next_next_pc <==> next.target_pc.
            builder
                .when(is_real.clone())
                .when(local.is_branching)
                .assert_word_eq(local.target_pc, local.next_next_pc);

            // To prevent the ALU send above to be non-zero when the row is a padding row.
            builder.when_not(is_real.clone()).assert_zero(local.is_branching);

            // Assert the branching or not branching when the instruction is a
            builder.when(is_real.clone()).assert_bool(local.is_branching);
        }

        // Evaluate branching value constraints.
        {
            // When the opcode is BEQ and we are branching, assert that a_gt_b + a_lt_b is false.
            builder
                .when(local.is_beq * local.is_branching)
                .assert_zero(local.a_gt_b + local.a_lt_b);

            // When the opcode is BEQ and we are not branching, assert that either a_gt_b or a_lt_b
            // is true.
            builder
                .when(local.is_beq)
                .when_not(local.is_branching)
                .assert_one(local.a_gt_b + local.a_lt_b);

            // When the opcode is BNE and we are branching, assert that either a_gt_b or a_lt_b is
            // true.
            builder.when(local.is_bne * local.is_branching).assert_one(local.a_gt_b + local.a_lt_b);

            // When the opcode is BNE and we are not branching, assert that a_gt_b + a_lt_b is false.
            builder
                .when(local.is_bne)
                .when_not(local.is_branching)
                .assert_zero(local.a_gt_b + local.a_lt_b);

            // When the opcode is BLTZ and we are branching, assert that a_lt_b is true.
            builder.when(local.is_bltz * local.is_branching).assert_one(local.a_lt_b);

            // When the opcode is BLTZ and we are not branching, assert a_lt_b is false.
            builder.when(local.is_bltz).when_not(local.is_branching).assert_zero(local.a_lt_b);

            // When the opcode is BLEZ and we are branching, assert that either a_gt_b is false
            builder.when(local.is_blez * local.is_branching).assert_zero(local.a_gt_b);

            // When the opcode is BLEZ and we are not branching, assert that a_gt_b is true.
            builder.when(local.is_blez).when_not(local.is_branching).assert_one(local.a_gt_b);

            // When the opcode is BGTZ and we are branching, assert that a_gt_b is true.
            builder.when(local.is_bgtz * local.is_branching).assert_one(local.a_gt_b);

            // When the opcode is BGTZ and we are not branching, assert that a_gt_b is false.
            builder.when(local.is_bgtz).when_not(local.is_branching).assert_zero(local.a_gt_b);

            // When the opcode is BGEZ and we are branching, assert that a_lt_b is false.
            builder.when(local.is_bgez * local.is_branching).assert_zero(local.a_lt_b);

            // When the opcode is BGEZ and we are not branching, assert that a_lt_b is true.
            builder.when(local.is_bgez).when_not(local.is_branching).assert_one(local.a_lt_b);
        }

        // Calculate a_lt_b <==> a < b (using appropriate signedness).
        // SAFETY: `use_signed_comparison` is boolean, since at most one selector is turned on.
        builder.send_alu(
            Opcode::SLT.as_field::<AB::F>(),
            Word::extend_var::<AB>(local.a_lt_b),
            local.op_a_value,
            local.op_b_value,
            is_real.clone(),
        );

        // Calculate a_gt_b <==> a > b (using appropriate signedness).
        builder.send_alu(
            Opcode::SLT.as_field::<AB::F>(),
            Word::extend_var::<AB>(local.a_gt_b),
            local.op_b_value,
            local.op_a_value,
            is_real.clone(),
        );
    }
}
