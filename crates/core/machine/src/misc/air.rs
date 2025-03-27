use std::borrow::Borrow;

use p3_air::{Air, AirBuilder};
use p3_field::FieldAlgebra;
use p3_matrix::Matrix;
use zkm2_core_executor::{ Opcode, ByteOpcode };
use zkm2_stark::{
    air::{BaseAirBuilder, ZKMAirBuilder},
    Word,
};

use crate::{air::WordAirBuilder, operations::AddCarryOperation};

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
            + local.is_teq * Opcode::TEQ.as_field::<AB::F>();

        let is_real = local.is_wsbh
            + local.is_seb
            + local.is_ins
            + local.is_ext
            + local.is_maddu
            + local.is_msubu
            + local.is_meq
            + local.is_mne
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
        self.eval_ext(builder, local);
        self.eval_ins(builder, local);
        self.eval_movcond(builder, local);
        self.eval_maddsub(builder, local);
        self.eval_seb(builder, local);
    }

}

impl MiscInstrsChip {
    pub(crate) fn eval_seb<AB: ZKMAirBuilder>(
        &self,
        builder: &mut AB,
        local: &MiscInstrColumns<AB::Var>
    ) {
        let seb_cols = local.misc_specific_columns.seb();
        builder.send_byte(
            ByteOpcode::MSB.as_field::<AB::F>(),
            seb_cols.most_sig_bit,
            local.op_b_value[0],
            AB::Expr::ZERO,
            local.is_seb.clone(),
        );

        let sign_byte = AB::Expr::from_canonical_u8(0xFF) * seb_cols.most_sig_bit;
        builder
            .when(local.is_seb.clone())
            .assert_eq(local.op_a_value[0], local.op_b_value[0]);

        builder
            .when(local.is_seb.clone())
            .assert_eq(local.op_a_value[1],  sign_byte.clone());

        builder
            .when(local.is_seb.clone())
            .assert_eq(local.op_a_value[2],  sign_byte.clone());
        
        builder
            .when(local.is_seb.clone())
            .assert_eq(local.op_a_value[3],  sign_byte);
        
    }

    pub(crate) fn eval_maddsub<AB: ZKMAirBuilder>(
        &self,
        builder: &mut AB,
        local: &MiscInstrColumns<AB::Var>
    ) {
        let maddsub_cols = local.misc_specific_columns.maddsub();
        let is_real = local.is_maddu + local.is_msubu;
        builder.send_alu_with_hi(
            Opcode::MULTU.as_field::<AB::F>(),
            maddsub_cols.mul_lo,
            local.op_b_value,
            local.op_c_value,
            maddsub_cols.mul_hi,
            is_real.clone(),
        );

        AddCarryOperation::<AB::F>::eval(
            builder,
            maddsub_cols.mul_lo,
            maddsub_cols.src2_lo,
              maddsub_cols.carry,
            maddsub_cols.low_add_operation,
            is_real.clone(),
        );

        AddCarryOperation::<AB::F>::eval(
            builder,
            maddsub_cols.mul_hi,
            maddsub_cols.src2_hi,
            maddsub_cols.low_add_operation.carry[3],
            maddsub_cols.hi_add_operation,
            is_real,
        );
    }

    pub(crate) fn eval_movcond<AB: ZKMAirBuilder>(
        &self,
        builder: &mut AB,
        local: &MiscInstrColumns<AB::Var>
    ) {
        let cond_cols = local.misc_specific_columns.movcond();
        let is_real = local.is_meq + local.is_mne + local.is_teq;
        
        builder
            .when(is_real.clone() * cond_cols.a_eq_b)
            .assert_word_eq(local.op_a_value, local.op_b_value);
        
        builder
            .when(is_real.clone() * cond_cols.c_eq_0)
            .assert_word_zero(local.op_c_value);
        
        builder
            .when(local.is_teq.clone())
            .assert_zero(cond_cols.a_eq_b);

        builder
            .when(local.is_meq)
            .when(cond_cols.c_eq_0)
            .assert_word_eq(local.op_a_value, local.op_b_value);

        builder
            .when(local.is_meq)
            .when_not(cond_cols.c_eq_0)
            .assert_word_eq(local.op_a_value, cond_cols.op_a_access.prev_value);
        
        builder
            .when(local.is_mne)
            .when_not(cond_cols.c_eq_0)
            .assert_word_eq(local.op_a_value, local.op_b_value);

        builder
            .when(local.is_mne)
            .when(cond_cols.c_eq_0)
            .assert_word_eq(local.op_a_value, cond_cols.op_a_access.prev_value);
        
    }

    pub(crate) fn eval_ins<AB: ZKMAirBuilder>(
        &self,
        builder: &mut AB,
        local: &MiscInstrColumns<AB::Var>
    ) {
        let ins_cols = local.misc_specific_columns.ins();

        builder.send_alu(
            Opcode::ROR.as_field::<AB::F>(),
            ins_cols.ror_val,
            ins_cols.op_a_access.prev_value,
            Word([AB::Expr::from_canonical_u32(0) + ins_cols.lsb, AB::Expr::ZERO, AB::Expr::ZERO, AB::Expr::ZERO]),
            local.is_ins.clone(),
        );

        builder.send_alu(
            Opcode::SRL.as_field::<AB::F>(),
            ins_cols.srl_val,
            ins_cols.ror_val,
            Word([AB::Expr::from_canonical_u32(1) + ins_cols.msb - ins_cols.lsb, AB::Expr::ZERO, AB::Expr::ZERO, AB::Expr::ZERO]),
            local.is_ins.clone(),
        );

        builder.send_alu(
            Opcode::SLL.as_field::<AB::F>(),
            ins_cols.sll_val,
            local.op_b_value,
            Word([AB::Expr::from_canonical_u32(31) - ins_cols.msb + ins_cols.lsb, AB::Expr::ZERO, AB::Expr::ZERO, AB::Expr::ZERO]),
            local.is_ins.clone(),
        );
       
        builder.send_alu(
            Opcode::ADD.as_field::<AB::F>(),
            ins_cols.add_val,
            ins_cols.srl_val,
            ins_cols.sll_val,
            local.is_ins.clone(),
        );

        builder.send_alu(
            Opcode::ROR.as_field::<AB::F>(),
            local.op_a_value,
            ins_cols.add_val,
            Word([AB::Expr::from_canonical_u32(31) - ins_cols.msb, AB::Expr::ZERO, AB::Expr::ZERO, AB::Expr::ZERO]),
            local.is_ins.clone(),
        );

        builder
            .when(local.is_ins)
            .assert_eq(local.op_c_value[0] + local.op_c_value[1] * AB::Expr::from_canonical_u32(256),
                     ins_cols.lsb + ins_cols.msb * AB::Expr::from_canonical_u32(32));

    }

    pub(crate) fn eval_ext<AB: ZKMAirBuilder>(
        &self,
        builder: &mut AB,
        local: &MiscInstrColumns<AB::Var>
    ) {
        let ext_cols = local.misc_specific_columns.ext();

        builder.send_alu(
            Opcode::SLL.as_field::<AB::F>(),
            ext_cols.sll_val,
            local.op_b_value,
            Word([AB::Expr::from_canonical_u32(31) - ext_cols.lsb - ext_cols.msbd, AB::Expr::ZERO, AB::Expr::ZERO, AB::Expr::ZERO]),
            local.is_ext.clone(),
        );

        builder.send_alu(
            Opcode::SRL.as_field::<AB::F>(),
            local.op_a_value,
            ext_cols.sll_val,
            Word([AB::Expr::from_canonical_u32(31) - ext_cols.lsb, AB::Expr::ZERO, AB::Expr::ZERO, AB::Expr::ZERO]),
            local.is_ext.clone(),
        );

        builder
            .when(local.is_ext)
            .assert_eq(local.op_c_value[0] + local.op_c_value[1] * AB::Expr::from_canonical_u32(256) , 
                       ext_cols.lsb + ext_cols.msbd * AB::Expr::from_canonical_u32(32));
    }

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
