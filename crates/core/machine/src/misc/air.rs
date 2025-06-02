use std::borrow::Borrow;

use crate::memory::MemoryCols;
use p3_air::{Air, AirBuilder};
use p3_field::FieldAlgebra;
use p3_matrix::Matrix;
use zkm_core_executor::{events::MemoryAccessPosition, ByteOpcode, Opcode};
use zkm_primitives::consts::WORD_SIZE;
use zkm_stark::{
    air::{BaseAirBuilder, ZKMAirBuilder},
    Word,
};

use crate::{
    air::{MemoryAirBuilder, WordAirBuilder},
    operations::AddDoubleOperation,
};

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
            + local.is_sext * Opcode::SEXT.as_field::<AB::F>()
            + local.is_ins * Opcode::INS.as_field::<AB::F>()
            + local.is_ext * Opcode::EXT.as_field::<AB::F>()
            + local.is_maddu * Opcode::MADDU.as_field::<AB::F>()
            + local.is_msubu * Opcode::MSUBU.as_field::<AB::F>()
            + local.is_meq * Opcode::MEQ.as_field::<AB::F>()
            + local.is_mne * Opcode::MNE.as_field::<AB::F>()
            + local.is_teq * Opcode::TEQ.as_field::<AB::F>();

        let is_real = local.is_wsbh
            + local.is_sext
            + local.is_ins
            + local.is_ext
            + local.is_maddu
            + local.is_msubu
            + local.is_meq
            + local.is_mne
            + local.is_teq;

        builder.assert_bool(local.is_wsbh);
        builder.assert_bool(local.is_sext);
        builder.assert_bool(local.is_ins);
        builder.assert_bool(local.is_ext);
        builder.assert_bool(local.is_maddu);
        builder.assert_bool(local.is_msubu);
        builder.assert_bool(local.is_meq);
        builder.assert_bool(local.is_mne);
        builder.assert_bool(local.is_teq);
        builder.assert_bool(is_real.clone());

        let is_rw_a = local.is_maddu + local.is_msubu + local.is_ins + local.is_mne + local.is_meq;
        builder.receive_instruction(
            local.shard,
            local.clk,
            local.pc,
            local.next_pc,
            AB::Expr::ZERO,
            cpu_opcode.clone(),
            local.op_a_value,
            local.op_b_value,
            local.op_c_value,
            local.prev_a_value,
            AB::Expr::ZERO,
            AB::Expr::ZERO,
            AB::Expr::ONE,
            AB::Expr::ZERO,
            AB::Expr::ZERO,
            AB::Expr::ONE,
            is_rw_a,
        );

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
            local.prev_a_value,
            AB::Expr::ZERO,
            AB::Expr::ZERO,
            AB::Expr::ZERO,
            AB::Expr::ZERO,
            AB::Expr::ZERO,
            AB::Expr::ONE,
            local.is_wsbh + local.is_sext + local.is_teq + local.is_ext,
        );

        self.eval_wsbh(builder, local);
        self.eval_ext(builder, local);
        self.eval_ins(builder, local);
        self.eval_movcond(builder, local);
        self.eval_maddsub(builder, local);
        self.eval_sext(builder, local);

        builder.when(local.is_ins + local.is_ext).assert_zero(local.op_c_value[2]);
        builder.when(local.is_ins + local.is_ext).assert_zero(local.op_c_value[3]);
    }
}

impl MiscInstrsChip {
    pub(crate) fn eval_sext<AB: ZKMAirBuilder>(
        &self,
        builder: &mut AB,
        local: &MiscInstrColumns<AB::Var>,
    ) {
        let sext_cols = local.misc_specific_columns.sext();

        // most_sig_bit is bit 7 of sig_byte.
        builder.send_byte(
            ByteOpcode::MSB.as_field::<AB::F>(),
            sext_cols.most_sig_bit,
            sext_cols.sig_byte,
            AB::Expr::ZERO,
            local.is_sext,
        );

        // op_c can be 0 (for seb) and 1(for seh).
        builder.when(local.is_sext).assert_bool(local.op_c_value[0]);
        builder.when(local.is_sext).when(sext_cols.is_seb).assert_zero(local.op_c_value[0]);
        builder.when(local.is_sext).when(sext_cols.is_seh).assert_one(local.op_c_value[0]);

        // For seb, sig_byte is byte 0 of op_a.
        // For seh, sig_byte is byte 1 of op_a.
        {
            builder
                .when(local.is_sext)
                .when(sext_cols.is_seb)
                .assert_eq(local.op_b_value[0], sext_cols.sig_byte);

            builder
                .when(local.is_sext)
                .when(sext_cols.is_seh)
                .assert_eq(local.op_b_value[1], sext_cols.sig_byte);
        }

        // Constraints for result value:
        // For both seb and seh, bytes lower than sig_byte(contain) equal op_b,
        // bytes upper than sig_byte equal sign byte(0xff when sig_bit is 1, otherwise 0).
        {
            let sign_byte = AB::Expr::from_canonical_u8(0xFF) * sext_cols.most_sig_bit;

            builder.when(local.is_sext).assert_eq(local.op_a_value[0], local.op_b_value[0]);

            builder
                .when(local.is_sext)
                .when(sext_cols.is_seb)
                .assert_eq(local.op_a_value[1], sign_byte.clone());

            builder
                .when(local.is_sext)
                .when(sext_cols.is_seh)
                .assert_eq(local.op_a_value[1], local.op_b_value[1]);

            builder.when(local.is_sext).assert_eq(local.op_a_value[2], sign_byte.clone());

            builder.when(local.is_sext).assert_eq(local.op_a_value[3], sign_byte);
        }
    }

    pub(crate) fn eval_maddsub<AB: ZKMAirBuilder>(
        &self,
        builder: &mut AB,
        local: &MiscInstrColumns<AB::Var>,
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

        for i in 0..WORD_SIZE {
            builder.when(is_real.clone()).assert_eq(
                maddsub_cols.src2_hi[i],
                maddsub_cols.op_hi_access.prev_value[i] * local.is_maddu
                    + (*maddsub_cols.op_hi_access.value())[i] * local.is_msubu,
            );
            builder.when(is_real.clone()).assert_eq(
                maddsub_cols.src2_lo[i],
                local.prev_a_value[i] * local.is_maddu + local.op_a_value[i] * local.is_msubu,
            );
        }

        AddDoubleOperation::<AB::F>::eval(
            builder,
            maddsub_cols.mul_lo,
            maddsub_cols.mul_hi,
            maddsub_cols.src2_lo,
            maddsub_cols.src2_hi,
            maddsub_cols.add_operation,
            is_real.clone(),
        );

        builder
            .when(local.is_maddu)
            .assert_word_eq(local.op_a_value, maddsub_cols.add_operation.value);

        builder.when(local.is_maddu).assert_word_eq(
            *maddsub_cols.op_hi_access.value(),
            maddsub_cols.add_operation.value_hi,
        );

        builder
            .when(local.is_msubu)
            .assert_word_eq(local.prev_a_value, maddsub_cols.add_operation.value);

        builder.when(local.is_msubu).assert_word_eq(
            maddsub_cols.op_hi_access.prev_value,
            maddsub_cols.add_operation.value_hi,
        );

        builder.eval_memory_access(
            local.shard,
            local.clk + AB::F::from_canonical_u32(MemoryAccessPosition::HI as u32),
            AB::F::from_canonical_u32(33),
            &maddsub_cols.op_hi_access,
            is_real.clone(),
        );
    }

    pub(crate) fn eval_movcond<AB: ZKMAirBuilder>(
        &self,
        builder: &mut AB,
        local: &MiscInstrColumns<AB::Var>,
    ) {
        let cond_cols = local.misc_specific_columns.movcond();
        let is_real = local.is_meq + local.is_mne + local.is_teq;

        builder
            .when(is_real.clone() * cond_cols.a_eq_b)
            .assert_word_eq(local.op_a_value, local.op_b_value);

        builder.when(is_real.clone() * cond_cols.c_eq_0).assert_word_zero(local.op_c_value);

        // For teq, a cannot equal b, otherwise trap will be triggered.
        builder.when(local.is_teq).assert_zero(cond_cols.a_eq_b);

        // Constraints for condition move result:
        // op_a = op_b, when condition is true.
        // Otherwise, op_a remains unchanged.
        {
            builder
                .when(local.is_meq)
                .when(cond_cols.c_eq_0)
                .assert_word_eq(local.op_a_value, local.op_b_value);

            builder
                .when(local.is_meq)
                .when_not(cond_cols.c_eq_0)
                .assert_word_eq(local.op_a_value, local.prev_a_value);

            builder
                .when(local.is_mne)
                .when_not(cond_cols.c_eq_0)
                .assert_word_eq(local.op_a_value, local.op_b_value);

            builder
                .when(local.is_mne)
                .when(cond_cols.c_eq_0)
                .assert_word_eq(local.op_a_value, local.prev_a_value);
        }
    }

    pub(crate) fn eval_ins<AB: ZKMAirBuilder>(
        &self,
        builder: &mut AB,
        local: &MiscInstrColumns<AB::Var>,
    ) {
        let ins_cols = local.misc_specific_columns.ins();

        // Ins can be divided into 5 operations:
        //    ror_val = rotate_right(op_a, lsb)
        //    srl_val = ror_val >> (msb - lsb + 1)
        //    sll_val = op_b << (31 - msb + lsb)
        //    add_val = srl_val + sll_val
        //    result = rotate_right(op_a, 31 - msb)
        {
            builder.send_alu(
                Opcode::ROR.as_field::<AB::F>(),
                ins_cols.ror_val,
                local.prev_a_value,
                Word([
                    AB::Expr::from_canonical_u32(0) + ins_cols.lsb,
                    AB::Expr::ZERO,
                    AB::Expr::ZERO,
                    AB::Expr::ZERO,
                ]),
                local.is_ins,
            );

            builder.send_alu(
                Opcode::SRL.as_field::<AB::F>(),
                ins_cols.srl_val,
                ins_cols.ror_val,
                Word([
                    AB::Expr::from_canonical_u32(1) + ins_cols.msb - ins_cols.lsb,
                    AB::Expr::ZERO,
                    AB::Expr::ZERO,
                    AB::Expr::ZERO,
                ]),
                local.is_ins,
            );

            builder.send_alu(
                Opcode::SLL.as_field::<AB::F>(),
                ins_cols.sll_val,
                local.op_b_value,
                Word([
                    AB::Expr::from_canonical_u32(31) - ins_cols.msb + ins_cols.lsb,
                    AB::Expr::ZERO,
                    AB::Expr::ZERO,
                    AB::Expr::ZERO,
                ]),
                local.is_ins,
            );

            builder.send_alu(
                Opcode::ADD.as_field::<AB::F>(),
                ins_cols.add_val,
                ins_cols.srl_val,
                ins_cols.sll_val,
                local.is_ins,
            );

            builder.send_alu(
                Opcode::ROR.as_field::<AB::F>(),
                local.op_a_value,
                ins_cols.add_val,
                Word([
                    AB::Expr::from_canonical_u32(31) - ins_cols.msb,
                    AB::Expr::ZERO,
                    AB::Expr::ZERO,
                    AB::Expr::ZERO,
                ]),
                local.is_ins,
            );
        }
        // op_c = (msb << 5) + lsb
        builder.when(local.is_ins).assert_eq(
            local.op_c_value.reduce::<AB>(),
            ins_cols.lsb + ins_cols.msb * AB::Expr::from_canonical_u32(32),
        );

        // 32 > msb >= lsb >=0.
        builder.send_byte(
            ByteOpcode::U8Range.as_field::<AB::F>(),
            AB::Expr::ZERO,
            ins_cols.lsb,
            ins_cols.msb,
            local.is_ins,
        );

        builder.send_byte(
            ByteOpcode::LTU.as_field::<AB::F>(),
            AB::Expr::ONE,
            ins_cols.lsb,
            ins_cols.msb + AB::Expr::ONE,
            local.is_ins,
        );

        builder.send_byte(
            ByteOpcode::LTU.as_field::<AB::F>(),
            AB::Expr::ONE,
            ins_cols.msb,
            AB::Expr::from_canonical_u32(32),
            local.is_ins,
        );
    }

    pub(crate) fn eval_ext<AB: ZKMAirBuilder>(
        &self,
        builder: &mut AB,
        local: &MiscInstrColumns<AB::Var>,
    ) {
        let ext_cols = local.misc_specific_columns.ext();

        // Ext can be divided into 2 operations:
        //    sll_val = op_b << (31 - lsb - msbd)
        //    result = sll_val >> (31 - msbd)
        {
            builder.send_alu(
                Opcode::SLL.as_field::<AB::F>(),
                ext_cols.sll_val,
                local.op_b_value,
                Word([
                    AB::Expr::from_canonical_u32(31) - ext_cols.lsb - ext_cols.msbd,
                    AB::Expr::ZERO,
                    AB::Expr::ZERO,
                    AB::Expr::ZERO,
                ]),
                local.is_ext,
            );

            builder.send_alu(
                Opcode::SRL.as_field::<AB::F>(),
                local.op_a_value,
                ext_cols.sll_val,
                Word([
                    AB::Expr::from_canonical_u32(31) - ext_cols.msbd,
                    AB::Expr::ZERO,
                    AB::Expr::ZERO,
                    AB::Expr::ZERO,
                ]),
                local.is_ext,
            );
        }

        // op_c = (msbd << 5) + lsb
        builder.when(local.is_ext).assert_eq(
            local.op_c_value.reduce::<AB>(),
            ext_cols.lsb + ext_cols.msbd * AB::Expr::from_canonical_u32(32),
        );

        // 0=< lsb/msbd < 32 , lsb + msbd < 32.
        builder.send_byte(
            ByteOpcode::U8Range.as_field::<AB::F>(),
            AB::Expr::ZERO,
            ext_cols.lsb,
            ext_cols.msbd,
            local.is_ext,
        );

        builder.send_byte(
            ByteOpcode::LTU.as_field::<AB::F>(),
            AB::Expr::ONE,
            ext_cols.lsb + ext_cols.msbd,
            AB::Expr::from_canonical_u32(32),
            local.is_ext,
        );
    }

    pub(crate) fn eval_wsbh<AB: ZKMAirBuilder>(
        &self,
        builder: &mut AB,
        local: &MiscInstrColumns<AB::Var>,
    ) {
        builder.when(local.is_wsbh).assert_eq(local.op_a_value[0], local.op_b_value[1]);

        builder.when(local.is_wsbh).assert_eq(local.op_a_value[1], local.op_b_value[0]);

        builder.when(local.is_wsbh).assert_eq(local.op_a_value[2], local.op_b_value[3]);

        builder.when(local.is_wsbh).assert_eq(local.op_a_value[3], local.op_b_value[2]);
    }
}
