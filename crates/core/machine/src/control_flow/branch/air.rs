use crate::memory::RegisterCols;
use std::borrow::Borrow;

use p3_air::{Air, AirBuilder, WindowAccess};
use p3_field::PrimeCharacteristicRing;
use zkm_core_executor::Opcode;
use zkm_pcs::air::{BaseAirBuilder, ZKMAirBuilder};

use crate::{
    air::WordAirBuilder,
    operations::{AddOperation, KoalaBearWordRangeChecker},
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
impl<AB> Air<AB> for BranchChip
where
    AB: ZKMAirBuilder,
    AB::Var: Sized,
{
    /// Constrains one branch row. The six opcode selectors and their sum `is_real`
    /// are boolean, so a real row has exactly one selector on and `opcode` matches it.
    #[inline(never)]
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.current_slice();
        let local: &BranchColumns<AB::Var> = (*local).borrow();

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

        crate::frame::eval_i_type_frame(
            builder,
            &local.frame,
            local.is_beq * Opcode::BEQ.as_field::<AB::F>()
                + local.is_bne * Opcode::BNE.as_field::<AB::F>()
                + local.is_bltz * Opcode::BLTZ.as_field::<AB::F>()
                + local.is_bgez * Opcode::BGEZ.as_field::<AB::F>()
                + local.is_blez * Opcode::BLEZ.as_field::<AB::F>()
                + local.is_bgtz * Opcode::BGTZ.as_field::<AB::F>(),
            local.pc.into(),
            local.next_pc.reduce::<AB>(),
            local.next_next_pc.reduce::<AB>(),
            local.next_pc.reduce::<AB>(),
            AB::Expr::ZERO,
            is_real.clone(),
        );
        builder
            .when(is_real.clone())
            .assert_word_eq(*local.frame.op_a_access.value(), local.frame.op_a_access.prev_value);

        {
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

            AddOperation::<AB::F>::eval(
                builder,
                local.next_pc,
                local.frame.op_c_val(),
                local.target_add,
                local.is_branching.into(),
            );

            builder.when(is_real.clone()).when_not(local.is_branching).assert_eq(
                local.next_pc.reduce::<AB>() + AB::Expr::from_u32(4),
                local.next_next_pc.reduce::<AB>(),
            );

            builder.slice_range_check_u8(&local.next_pc.0, is_real.clone() - local.is_branching);
            builder
                .slice_range_check_u8(&local.next_next_pc.0, is_real.clone() - local.is_branching);

            builder
                .when(is_real.clone())
                .when(local.is_branching)
                .assert_word_eq(local.target_add.value, local.next_next_pc);

            builder.when_not(is_real.clone()).assert_zero(local.is_branching);

            builder.when(is_real.clone()).assert_bool(local.is_branching);
        }

        let av = *local.frame.op_a_access.value();
        let bv = local.frame.op_b_val();
        let two_pow_8 = AB::Expr::from_u32(1 << 8);
        let d_lo = (av[0] - bv[0]) + (av[1] - bv[1]) * two_pow_8.clone();
        let d_hi = (av[2] - bv[2]) + (av[3] - bv[3]) * two_pow_8;

        builder.when(is_real.clone()).assert_zero(local.eq_lo * d_lo.clone());
        builder
            .when(is_real.clone())
            .assert_eq(local.eq_lo, AB::Expr::ONE - d_lo * local.eq_lo_inv);
        builder.when(is_real.clone()).assert_zero(local.eq_hi * d_hi.clone());
        builder
            .when(is_real.clone())
            .assert_eq(local.eq_hi, AB::Expr::ONE - d_hi * local.eq_hi_inv);
        builder.when(is_real.clone()).assert_eq(local.a_eq_b, local.eq_lo * local.eq_hi);

        let zero_ops = local.is_bltz + local.is_blez + local.is_bgtz + local.is_bgez;
        builder.send_byte(
            AB::Expr::from_u8(zkm_core_executor::ByteOpcode::MSB as u8),
            local.msb_a,
            av[3],
            AB::Expr::ZERO,
            zero_ops.clone(),
        );
        builder.when(zero_ops).assert_eq(
            local.a_gt_0,
            (AB::Expr::ONE - local.msb_a) * (AB::Expr::ONE - local.a_eq_b),
        );

        builder.when(local.is_beq * local.is_branching).assert_one(local.a_eq_b);
        builder.when(local.is_beq).when_not(local.is_branching).assert_zero(local.a_eq_b);
        builder.when(local.is_bne * local.is_branching).assert_zero(local.a_eq_b);
        builder.when(local.is_bne).when_not(local.is_branching).assert_one(local.a_eq_b);
        builder.when(local.is_bltz * local.is_branching).assert_one(local.msb_a);
        builder.when(local.is_bltz).when_not(local.is_branching).assert_zero(local.msb_a);
        builder.when(local.is_blez * local.is_branching).assert_zero(local.a_gt_0);
        builder.when(local.is_blez).when_not(local.is_branching).assert_one(local.a_gt_0);
        builder.when(local.is_bgtz * local.is_branching).assert_one(local.a_gt_0);
        builder.when(local.is_bgtz).when_not(local.is_branching).assert_zero(local.a_gt_0);
        builder.when(local.is_bgez * local.is_branching).assert_zero(local.msb_a);
        builder.when(local.is_bgez).when_not(local.is_branching).assert_one(local.msb_a);
    }
}
