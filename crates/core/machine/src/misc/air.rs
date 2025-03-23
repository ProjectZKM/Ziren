use std::borrow::Borrow;

use p3_air::{Air, AirBuilder};
use p3_field::FieldAlgebra;
use p3_matrix::Matrix;
use zkm2_core_executor::Opcode;
use zkm2_stark::air::ZKMAirBuilder;

use super::{columns::MiscInstrColumns, MiscInstrsChip};

impl<AB> Air<AB> for MiscInstrsChip
where
    AB: ZKMAirBuilder,
    AB::Var: Sized,
{
    #[inline(never)]
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &MiscInstrColumns<AB::Var> = (*local).borrow();

        let cpu_opcode = local.is_wsbh * Opcode::WSBH.as_field::<AB::F>()
            + local.is_seb * Opcode::SEXT.as_field::<AB::F>()
            + local.is_ins * Opcode::INS.as_field::<AB::F>()
            + local.is_ext * Opcode::EXT.as_field::<AB::F>()
            + local.is_maddu * Opcode::MADDU.as_field::<AB::F>()
            + local.is_msubu * Opcode::MSUBU.as_field::<AB::F>()
            + local.is_meq * Opcode::MEQ.as_field::<AB::F>()
            + local.is_mne * Opcode::MNE.as_field::<AB::F>()
            + local.is_nop * Opcode::NOP.as_field::<AB::F>()
            + local.is_teq * Opcode::TEQ.as_field::<AB::F>();

        let is_real = local.is_wsbh
            + local.is_seb
            + local.is_ins
            + local.is_ext
            + local.is_maddu
            + local.is_msubu
            + local.is_meq
            + local.is_mne
            + local.is_nop
            + local.is_teq;

        builder.receive_instruction(
            AB::Expr::ZERO,
            AB::Expr::ZERO,
            local.pc,
            local.next_pc,
            AB::Expr::ZERO,
            cpu_opcode,
            local.op_a_value,
            local.op_b_value,
            local.op_c_value,
            local.op_hi_value,
            local.op_a_0,
            AB::Expr::ZERO,
            AB::Expr::ZERO,
            AB::Expr::ZERO,
            AB::Expr::ZERO,
            is_real,
        );

        self.eval_wsbh(builder, local);
    }

}

impl MiscInstrsChip {
    pub(crate) fn eval_wsbh<AB: ZKMAirBuilder>(
        &self,
        builder: &mut AB,
        local: &MiscInstrColumns<AB::Var>
    ) {
        builder
            .when(local.is_wsbh.clone())
            .assert_eq(local.op_a_value[0], local.op_b_value[1]);

        builder
            .when(local.is_wsbh.clone())
            .assert_eq(local.op_a_value[1], local.op_b_value[0]);

        builder
            .when(local.is_wsbh.clone())
            .assert_eq(local.op_a_value[2], local.op_b_value[3]);

        builder
            .when(local.is_wsbh.clone())
            .assert_eq(local.op_a_value[3], local.op_b_value[2]);
    }
}
