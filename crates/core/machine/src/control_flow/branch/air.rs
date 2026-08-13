use crate::memory::RegisterCols;
use std::borrow::Borrow;

use p3_air::{WindowAccess, Air, AirBuilder};
use p3_field::PrimeCharacteristicRing;
use zkm_core_executor::Opcode;
use zkm_pcs::{
    air::{BaseAirBuilder, ZKMAirBuilder},
    Word,
};

use crate::{
    air::WordAirBuilder,
    operations::{AddOperation, KoalaBearWordRangeChecker, LtOperation},
};

use super::{BranchChip, BranchColumns};

/// Verifies all the branching related columns.
///
/// It does this in few parts:
/// 1. It verifies that the next next pc is correct based on the branching column.  That column is a
///    boolean that indicates whether the branch condition is true.
/// 2. It verifies the correct value of branching based on the helper bool columns (a_eq_b,
///    a_gt_b, a_lt_b).
/// 3. It verifies the correct values of the helper bool columns based on op_a and op_b.
///
impl<AB> Air<AB> for BranchChip
where
    AB: ZKMAirBuilder,
    AB::Var: Sized,
{
    #[inline(never)]
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.current_slice();
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

        let _ = opcode;

        // A real instruction carries its own program fetch, register access and
        // `(clk, pc)` chaining.  A branch's next_next_pc is the TARGET (or the
        // fallthrough), already a constrained Word column; branches never halt.
        crate::frame::eval_instruction_frame(
            builder,
            &local.frame,
            local.pc.into(),
            local.next_pc.reduce::<AB>(),
            local.next_next_pc.reduce::<AB>(),
            local.next_pc.reduce::<AB>(),
            AB::Expr::ZERO,
            is_real.clone(),
        );
        // A branch READS op_a immutably: the register write carries the
        // previous value through unchanged.
        builder.when(is_real.clone()).assert_word_eq(
            *local.frame.op_a_access.value(),
            local.frame.op_a_access.prev_value,
        );

        // Bind this chip's operand columns to the frame's register-file view:
        // the chip must compute on exactly the values the register accesses
        // commit.  UNGATED by op_a_0: a read of register 0 must see 0, which
        // is exactly what the access value is forced to.
        builder
            .when(is_real.clone())
            .assert_word_eq(local.op_a_value, *local.frame.op_a_access.value());
        builder.when(is_real.clone()).assert_word_eq(local.op_b_value, local.frame.op_b_val());
        builder.when(is_real.clone()).assert_word_eq(local.op_c_value, local.frame.op_c_val());

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

            // When we are branching, prove target = next_pc + c IN-ROW (the
            // AddSub request row is gone; the memory chips' inlined address
            // add set the precedent).
            AddOperation::<AB::F>::eval(
                builder,
                local.next_pc,
                local.op_c_value,
                local.target_add,
                local.is_branching.into(),
            );

            // When we are not branching, assert that local.next_pc + 4 <==> next.next_next_pc.
            builder.when(is_real.clone()).when_not(local.is_branching).assert_eq(
                local.next_pc.reduce::<AB>() + AB::Expr::from_u32(4),
                local.next_next_pc.reduce::<AB>(),
            );

            // check local.next_pc/next_next_pc to be valid word when we are not branching.
            // they are checked as valid value by the ADD ALU table when we are branching.
            builder.slice_range_check_u8(&local.next_pc.0, is_real.clone() - local.is_branching);
            builder
                .slice_range_check_u8(&local.next_next_pc.0, is_real.clone() - local.is_branching);

            // When we are branching, assert that next_next_pc is the target.
            builder
                .when(is_real.clone())
                .when(local.is_branching)
                .assert_word_eq(local.target_add.value, local.next_next_pc);

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

        // The SIGNED comparison of op_a and op_b, proven IN-ROW — one gadget
        // yields lt / eq / gt by trichotomy, replacing the two SLT request
        // rows the chip used to push onto the `Lt` chip.  MIPS semantics are
        // untouched: `a_lt_b = (a as i32) < (b as i32)` exactly as before.
        LtOperation::<AB::F>::eval(
            builder,
            local.op_a_value,
            local.op_b_value,
            &local.compare,
            is_real.clone(),
            AB::Expr::ZERO,
        );
        builder.assert_eq(local.a_lt_b, local.compare.lt);
        // gt = 1 − lt − eq (true 32-bit equality: masked bytes AND sign bits
        // agree), on real rows.
        builder.when(is_real.clone()).assert_eq(
            local.a_gt_b,
            AB::Expr::ONE
                - local.compare.lt
                - local.compare.is_comp_eq * local.compare.is_sign_eq,
        );
    }
}
