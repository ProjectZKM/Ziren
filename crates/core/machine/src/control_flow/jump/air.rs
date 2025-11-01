use std::borrow::Borrow;

use p3_air::{Air, AirBuilder};
use p3_field::FieldAlgebra;
use p3_matrix::Matrix;
use zkm_core_executor::Opcode;
use zkm_stark::{air::ZKMAirBuilder, Word};

use crate::air::WordAirBuilder;

use crate::operations::KoalaBearWordRangeChecker;

use super::{JumpChip, JumpColumns};

impl<AB> Air<AB> for JumpChip
where
    AB: ZKMAirBuilder,
    AB::Var: Sized,
{
    #[inline(never)]
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &JumpColumns<AB::Var> = (*local).borrow();

        // SAFETY: All selectors `is_jump`, `is_jumpi`, `is_jumpdirect`  are checked to be boolean.
        // Each "real" row has exactly one selector turned on, as `is_real = is_jump + is_jumpi + is_jumpdirect` is boolean.
        // Therefore, the `opcode` matches the corresponding opcode.
        builder.assert_bool(local.is_jump);
        builder.assert_bool(local.is_jumpi);
        builder.assert_bool(local.is_jumpdirect);
        let is_real = local.is_jump + local.is_jumpi + local.is_jumpdirect;
        builder.assert_bool(is_real.clone());

        let opcode = local.is_jump * Opcode::Jump.as_field::<AB::F>()
            + local.is_jumpi * Opcode::Jumpi.as_field::<AB::F>()
            + local.is_jumpdirect * Opcode::JumpDirect.as_field::<AB::F>();

        // SAFETY: This checks the following.
        // - `num_extra_cycles = 0`
        // - `op_a_immutable = 0`
        // - `is_rw_a = 0`
        // - `is_syscall = 0`
        // - `is_halt = 0`
        // `next_pc` and `op_a_value` still has to be constrained, and this is done below.
        builder.receive_instruction(
            AB::Expr::zero(),
            AB::Expr::zero(),
            local.pc,
            local.next_pc.reduce::<AB>(),
            local.next_next_pc.reduce::<AB>(),
            AB::Expr::zero(),
            opcode,
            local.op_a_value,
            local.op_b_value,
            local.op_c_value,
            Word([AB::Expr::zero(), AB::Expr::zero(), AB::Expr::zero(), AB::Expr::zero()]),
            AB::Expr::zero(),
            AB::Expr::zero(),
            AB::Expr::zero(),
            AB::Expr::zero(),
            AB::Expr::zero(),
            is_real.clone(),
        );

        // Verify that the local.next_pc + 4 is op_a_value for all jump instructions.
        builder.when(is_real.clone()).assert_eq(
            local.op_a_value.reduce::<AB>(),
            local.next_pc.reduce::<AB>() + AB::F::from_canonical_u32(4),
        );

        // Range check op_a, pc, and next_pc.
        // SAFETY: `is_real` is already checked to be boolean.
        // `op_a_value` is checked to be a valid word, as it matches the one in the CpuChip.
        // In the CpuChip's `eval_registers`, it's checked that this is valid word saved in op_a when `op_a_0 = 0`
        // Combined with the `op_a_value = next_pc + 4` check above, this fully constrains `op_a_value`.
        KoalaBearWordRangeChecker::<AB::F>::range_check(
            builder,
            local.op_a_value,
            local.op_a_range_checker,
            is_real.clone(),
        );
        // SAFETY: `is_real` is already checked to be boolean.
        // `local.next_pc`, `local.next_next_pc` are checked to a valid word when relevant.
        // This is due to the ADD ALU table checking all inputs and outputs are valid words.
        // This is done when the `AddOperation` is invoked in the ADD ALU table.
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

        // We now constrain `next_next_pc` for J/JR/JALR.
        builder
            .when(local.is_jump + local.is_jumpi)
            .assert_word_eq(local.next_next_pc, local.op_b_value);

        // Verify that the next_next_pc is calculated correctly for BAL instructions.
        // SAFETY: `is_jumpdirect` is boolean, and zero for padding rows.
        builder.send_alu(
            AB::Expr::from_canonical_u32(Opcode::ADD as u32),
            local.next_next_pc,
            local.next_pc,
            local.op_b_value,
            local.is_jumpdirect,
        );
    }
}
