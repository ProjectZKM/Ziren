use p3_air::AirBuilder;
use p3_field::FieldAlgebra;
use zkm2_stark::{
    air::{BaseAirBuilder, ZKMAirBuilder},
    Word,
};

use crate::{
    air::WordAirBuilder,
    cpu::{
        columns::{CpuCols, OpcodeSelectorCols},
        CpuChip,
    },
    operations::KoalaBearWordRangeChecker,
};

use zkm2_core_executor::Opcode;

impl CpuChip {
    /// Computes whether the opcode is a branch instruction.
    pub(crate) fn is_branch_instruction<AB: ZKMAirBuilder>(
        &self,
        opcode_selectors: &OpcodeSelectorCols<AB::Var>,
    ) -> AB::Expr {
        opcode_selectors.is_beq
            + opcode_selectors.is_bne
            + opcode_selectors.is_bltz
            + opcode_selectors.is_blez
            + opcode_selectors.is_bgtz
            + opcode_selectors.is_bgez
    }

    /// Verifies all the branching related columns.
    ///
    /// It does this in few parts:
    /// 1. It verifies that the next pc is correct based on the branching column.  That column is a
    ///    boolean that indicates whether the branch condition is true.
    /// 2. It verifies the correct value of branching based on the helper bool columns (a_eq_b,
    ///    a_eq_0, a_gt_0, a_lt_0).
    /// 3. It verifier the correct values of the helper bool columns based on op_a and op_b.
    pub(crate) fn eval_branch_ops<AB: ZKMAirBuilder>(
        &self,
        builder: &mut AB,
        is_branch_instruction: AB::Expr,
        local: &CpuCols<AB::Var>,
        next: &CpuCols<AB::Var>,
    ) {
        // Get the branch specific columns.
        let branch_cols = local.opcode_specific_columns.branch();

        builder.assert_bool(local.selectors.is_beq);
        builder.assert_bool(local.selectors.is_bne);
        builder.assert_bool(local.selectors.is_bltz);
        builder.assert_bool(local.selectors.is_bgez);
        builder.assert_bool(local.selectors.is_blez);
        builder.assert_bool(local.selectors.is_bgtz);
        builder.assert_bool(is_branch_instruction.clone());

        // Evaluate program counter constraints.
        {
            // When we are branching, assert that local.next_pc <==> branch_columns.next_pc as Word.
            builder
                .when_transition()
                .when(next.is_real)
                .when(local.branching)
                .assert_eq(branch_cols.next_pc.reduce::<AB>(), local.next_pc);

            // When we are branching, assert that next.next_pc <==> branch_columns.target_pc as Word.
            builder
                .when_transition()
                .when(next.is_real)
                .when(local.branching)
                .assert_eq(branch_cols.target_pc.reduce::<AB>(), next.next_pc);

            // Range check branch_cols.pc and branch_cols.next_pc.
            KoalaBearWordRangeChecker::<AB::F>::range_check(
                builder,
                branch_cols.next_pc,
                branch_cols.next_pc_range_checker,
                is_branch_instruction.clone(),
            );
            KoalaBearWordRangeChecker::<AB::F>::range_check(
                builder,
                branch_cols.target_pc,
                branch_cols.target_pc_range_checker,
                is_branch_instruction.clone(),
            );

            // When we are branching, calculate branch_cols.target_pc <==> branch_cols.next_pc + c.
            builder.send_alu(
                Opcode::ADD.as_field::<AB::F>(),
                branch_cols.target_pc,
                branch_cols.next_pc,
                local.op_c_val(),
                local.shard,
                branch_cols.target_pc_nonce,
                local.branching,
            );

            // When we are not branching, assert that local.pc + 8 <==> next.next_pc.
            builder
                .when_transition()
                .when(next.is_real)
                .when(local.not_branching)
                .assert_eq(local.pc + AB::Expr::from_canonical_u8(8), next.next_pc);

            // When local.not_branching is true, assert that local.is_real is true.
            builder.when(local.not_branching).assert_one(local.is_real);

            // Assert that either we are branching or not branching when the instruction is a branch.
            builder
                .when(is_branch_instruction.clone())
                .assert_one(local.branching + local.not_branching);
            builder.when(is_branch_instruction.clone()).assert_bool(local.branching);
            builder.when(is_branch_instruction.clone()).assert_bool(local.not_branching);
        }

        // Evaluate branching value constraints.
        {
            // When the opcode is BEQ and we are branching, assert that a_eq_b is true.
            builder.when(local.selectors.is_beq * local.branching).assert_one(branch_cols.a_eq_b);

            // When the opcode is BEQ and we are not branching, assert that a_eq_b is false.
            builder
                .when(local.selectors.is_beq)
                .when_not(local.branching)
                .assert_zero(branch_cols.a_eq_b);

            // When the opcode is BNE and we are branching, assert that a_eq_b is false.
            builder
                .when(local.selectors.is_bne * local.branching)
                .assert_zero(branch_cols.a_eq_b);

            // When the opcode is BNE and we are not branching, assert that a_eq_b is true.
            builder
                .when(local.selectors.is_bne)
                .when_not(local.branching)
                .assert_one(branch_cols.a_eq_b);

            // When the opcode is BLTZ and we are branching, assert that either a_lt_0 is true.
            builder
                .when(local.selectors.is_bltz * local.branching)
                .assert_one(branch_cols.a_lt_0);

            // When the opcode is BLTZ and we are not branching, assert that either a_eq_0 or a_gt_0 is true.
            builder
                .when(local.selectors.is_bltz)
                .when_not(local.branching)
                .assert_one(branch_cols.a_eq_0 + branch_cols.a_gt_0);

            // When the opcode is BGEZ and we are branching, assert that a_eq_0 or a_gt_0 is true.
            builder
                .when(local.selectors.is_bgez * local.branching)
                .assert_one(branch_cols.a_eq_0 + branch_cols.a_gt_0);

            // When the opcode is BGEZ and we are not branching, assert that either a_lt_0 is true.
            builder
                .when(local.selectors.is_bgez)
                .when_not(local.branching)
                .assert_one(branch_cols.a_lt_0);

            // When the opcode is BLEZ and we are branching, assert that either a_eq_0 or a_lt_0 is true.
            builder
                .when(local.selectors.is_blez * local.branching)
                .assert_one(branch_cols.a_eq_0 + branch_cols.a_lt_0);

            // When the opcode is BLEZ and we are not branching, assert that a_gt_0 is true.
            builder
                .when(local.selectors.is_blez)
                .when_not(local.branching)
                .assert_one(branch_cols.a_gt_0);

            // When the opcode is BGTZ and we are branching, assert that a_gt_0 is true.
            builder
                .when(local.selectors.is_bgtz * local.branching)
                .assert_one(branch_cols.a_gt_0);

            // When the opcode is BGTZ and we are not branching, assert that a_eq_0 or a_lt_0 is true.
            builder
                .when(local.selectors.is_bgez)
                .when_not(local.branching)
                .assert_one(branch_cols.a_eq_0 + branch_cols.a_lt_0);
        }

        // When it's a branch instruction and a_eq_b, assert that a == b.
        builder
            .when(is_branch_instruction.clone() * branch_cols.a_eq_b)
            .assert_word_eq(local.op_a_val(), local.op_b_val());

        // When it's a branch instruction and a_eq_0, assert that a == 0.
        builder
            .when(is_branch_instruction.clone() * branch_cols.a_eq_0)
            .assert_word_eq(local.op_a_val(), Word::zero::<AB>());

        //  To prevent this ALU send to be arbitrarily large when is_branch_instruction is false.
        builder.when_not(is_branch_instruction.clone()).assert_zero(local.branching);

        let check_a = local.selectors.is_bltz
            + local.selectors.is_bgez
            + local.selectors.is_blez
            + local.selectors.is_bgtz;

        // Calculate a_lt_0 <==> a < 0 (using appropriate signedness).
        builder.send_alu(
            Opcode::SLT.as_field::<AB::F>(),
            Word::extend_var::<AB>(branch_cols.a_lt_0),
            local.op_a_val(),
            Word::zero::<AB>(),
            local.shard,
            branch_cols.a_lt_0_nonce,
            check_a.clone(),
        );

        // Calculate a_gt_0 <==> a > 0 (using appropriate signedness).
        builder.send_alu(
             Opcode::SLT.as_field::<AB::F>(),
            Word::extend_var::<AB>(branch_cols.a_gt_0),
            Word::zero::<AB>(),
            local.op_a_val(),
            local.shard,
            branch_cols.a_gt_0_nonce,
            check_a.clone(),
        );
    }
}
