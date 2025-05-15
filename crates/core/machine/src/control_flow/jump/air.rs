use std::borrow::Borrow;

use p3_air::{Air, AirBuilder};
use p3_field::FieldAlgebra;
use p3_matrix::Matrix;
use zkm_core_executor::Opcode;
use zkm_stark::{
    air::{BaseAirBuilder, ZKMAirBuilder},
    Word,
};

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
        // - `is_memory = 0`
        // - `is_syscall = 0`
        // - `is_halt = 0`
        // `next_pc` and `op_a_value` still has to be constrained, and this is done below.
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
            local.op_a_0,
            AB::Expr::ZERO,
            AB::Expr::ZERO,
            AB::Expr::ZERO,
            AB::Expr::ZERO,
            AB::Expr::ZERO,
            is_real.clone(),
        );
        // Verify that the local.next_pc + 4 is saved in op_a for both jump instructions.
        // When op_a is set to register X0, the MIPS spec states that the jump instruction will
        // not have a return destination address (it is effectively a GOTO command).  In this case,
        // we shouldn't verify the return address.
        builder.when(is_real.clone()).when_not(local.op_a_0).assert_eq(
            local.op_a_value.reduce::<AB>(),
            local.next_pc.reduce::<AB>() + AB::F::from_canonical_u32(4),
        );

        // Range check op_a, pc, and next_pc.
        // SAFETY: `is_real` is already checked to be boolean.
        // `op_a_value` is checked to be a valid word, as it matches the one in the CpuChip.
        // In the CpuChip's `eval_registers`, it's checked that this is a valid word.
        // Combined with the `op_a_value = pc + 4` check above when `op_a_0 = 0`, this fully constrains `op_a_value`.
        KoalaBearWordRangeChecker::<AB::F>::range_check(
            builder,
            local.op_a_value,
            local.op_a_range_checker,
            is_real.clone(),
        );
        // SAFETY: `is_real` is already checked to be boolean.
        // `local.pc`, `local.next_pc` are checked to a valid word when relevant.
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

        // We now constrain `next_pc`.

        // Verify that the new pc is calculated correctly for JAL instructions.
        // SAFETY: `is_jal` is boolean, and zero for padding rows.
        builder.send_alu(
            AB::Expr::from_canonical_u32(Opcode::ADD as u32),
            local.next_next_pc,
            local.next_pc,
            local.op_b_value,
            local.is_jumpdirect,
        );
    }
}
