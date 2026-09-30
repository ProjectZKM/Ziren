use crate::memory::RegisterCols;
use std::borrow::Borrow;
use zkm_pcs::air::BaseAirBuilder;

use p3_air::{Air, AirBuilder, WindowAccess};
use p3_field::PrimeCharacteristicRing;
use zkm_core_executor::Opcode;
use zkm_pcs::air::ZKMAirBuilder;

use crate::air::WordAirBuilder;

use crate::operations::KoalaBearWordRangeChecker;

use super::{JumpChip, JumpColumns};

impl<AB> Air<AB> for JumpChip
where
    AB: ZKMAirBuilder,
    AB::Var: Sized,
{
    /// Constrains one jump row. `is_jump`, `is_jumpi`, `is_jumpdirect` and their
    /// sum `is_real` are boolean, so a real row has exactly one selector on and
    /// `opcode` matches it; `is_jumpdirect` is zero on padding rows.
    #[inline(never)]
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.current_slice();
        let local: &JumpColumns<AB::Var> = (*local).borrow();

        builder.assert_bool(local.is_jump);
        builder.assert_bool(local.is_jumpi);
        builder.assert_bool(local.is_jumpdirect);
        let is_real = local.is_jump + local.is_jumpi + local.is_jumpdirect;
        builder.assert_bool(is_real.clone());

        let opcode = local.is_jump * Opcode::Jump.as_field::<AB::F>()
            + local.is_jumpi * Opcode::Jumpi.as_field::<AB::F>()
            + local.is_jumpdirect * Opcode::JumpDirect.as_field::<AB::F>();

        let _ = opcode;

        crate::frame::eval_instruction_frame(
            builder,
            &local.frame,
            local.is_jump * Opcode::Jump.as_field::<AB::F>()
                + local.is_jumpi * Opcode::Jumpi.as_field::<AB::F>()
                + local.is_jumpdirect * Opcode::JumpDirect.as_field::<AB::F>(),
            local.pc.into(),
            local.next_pc.reduce::<AB>(),
            local.next_next_pc.reduce::<AB>(),
            local.next_pc.reduce::<AB>(),
            AB::Expr::ZERO,
            is_real.clone(),
        );

        let link = *local.frame.op_a_access.value();
        builder
            .when(is_real.clone())
            .when_not(local.frame.instruction.op_a_0)
            .assert_eq(link.reduce::<AB>(), local.next_pc.reduce::<AB>() + AB::F::from_u32(4));

        KoalaBearWordRangeChecker::<AB::F>::range_check(
            builder,
            link,
            local.op_a_range_checker,
            is_real.clone(),
        );
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

        builder
            .when(local.is_jump + local.is_jumpi)
            .assert_word_eq(local.next_next_pc, local.frame.op_b_val());

        crate::operations::AddOperation::<AB::F>::eval(
            builder,
            local.next_pc,
            local.frame.op_b_val(),
            local.target_add,
            local.is_jumpdirect.into(),
        );
        builder
            .when(local.is_jumpdirect)
            .assert_word_eq(local.target_add.value, local.next_next_pc);
    }
}
