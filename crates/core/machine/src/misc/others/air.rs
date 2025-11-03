use std::borrow::Borrow;

use crate::memory::MemoryCols;
use p3_air::{Air, AirBuilder};
use p3_field::FieldAlgebra;
use p3_matrix::Matrix;
use zkm_core_executor::{events::MemoryAccessPosition, ByteOpcode, Opcode};
use zkm_primitives::consts::WORD_SIZE;
use zkm_stark::{air::ZKMAirBuilder, Word};

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

        let cpu_opcode = local.is_sext * Opcode::SEXT.as_field::<AB::F>()
            + local.is_ins * Opcode::INS.as_field::<AB::F>()
            + local.is_ext * Opcode::EXT.as_field::<AB::F>()
            + local.is_maddu * Opcode::MADDU.as_field::<AB::F>()
            + local.is_msubu * Opcode::MSUBU.as_field::<AB::F>()
            + local.is_madd * Opcode::MADD.as_field::<AB::F>()
            + local.is_msub * Opcode::MSUB.as_field::<AB::F>()
            + local.is_teq * Opcode::TEQ.as_field::<AB::F>();

        let is_real = local.is_sext
            + local.is_ins
            + local.is_ext
            + local.is_maddu
            + local.is_msubu
            + local.is_madd
            + local.is_msub
            + local.is_teq;

        builder.assert_bool(local.is_sext);
        builder.assert_bool(local.is_ins);
        builder.assert_bool(local.is_ext);
        builder.assert_bool(local.is_maddu);
        builder.assert_bool(local.is_msubu);
        builder.assert_bool(local.is_madd);
        builder.assert_bool(local.is_msub);
        builder.assert_bool(local.is_teq);
        builder.assert_bool(is_real.clone());

        let is_rw_a =
            local.is_maddu + local.is_msubu + local.is_madd + local.is_msub + local.is_ins;

        let is_check_memory = local.is_maddu + local.is_msubu + local.is_madd + local.is_msub;

        builder.receive_instruction(
            local.shard,
            local.clk,
            local.pc,
            local.next_pc,
            local.next_pc + AB::Expr::from_canonical_u32(4),
            AB::Expr::zero(),
            cpu_opcode.clone(),
            local.op_a_value,
            local.op_b_value,
            local.op_c_value,
            local.prev_a_value,
            AB::Expr::zero(),
            is_rw_a.clone(),
            is_check_memory.clone(),
            AB::Expr::zero(),
            AB::Expr::one(),
            is_check_memory,
        );

        builder.receive_instruction(
            AB::Expr::zero(),
            AB::Expr::zero(),
            local.pc,
            local.next_pc,
            local.next_pc + AB::Expr::from_canonical_u32(4),
            AB::Expr::zero(),
            cpu_opcode,
            local.op_a_value,
            local.op_b_value,
            local.op_c_value,
            local.prev_a_value,
            AB::Expr::zero(),
            is_rw_a,
            AB::Expr::zero(),
            AB::Expr::zero(),
            AB::Expr::one(),
            local.is_sext + local.is_teq + local.is_ext + local.is_ins,
        );

        self.eval_ext(builder, local);
        self.eval_ins(builder, local);
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

        builder
            .when(local.is_teq * sext_cols.a_eq_b)
            .assert_word_eq(local.op_a_value, local.op_b_value);

        builder.when(local.is_teq).assert_zero(sext_cols.a_eq_b);

        // most_sig_bit is bit 7 of sig_byte.
        builder.send_byte(
            ByteOpcode::MSB.as_field::<AB::F>(),
            sext_cols.most_sig_bit,
            sext_cols.sig_byte,
            AB::Expr::zero(),
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
        let is_real = local.is_maddu + local.is_msubu + local.is_madd + local.is_msub;
        let is_sign = local.is_madd + local.is_msub;
        let is_unsign = local.is_maddu + local.is_msubu;
        let is_add = local.is_maddu + local.is_madd;
        let is_sub = local.is_msubu + local.is_msub;

        let opcode = is_sign * Opcode::MULT.as_field::<AB::F>()
            + is_unsign * Opcode::MULTU.as_field::<AB::F>();

        builder.send_alu_with_hi(
            opcode,
            maddsub_cols.mul_lo,
            local.op_b_value,
            local.op_c_value,
            maddsub_cols.mul_hi,
            is_real.clone(),
        );

        for i in 0..WORD_SIZE {
            builder.when(is_real.clone()).assert_eq(
                maddsub_cols.src2_hi[i],
                maddsub_cols.op_hi_access.prev_value[i] * is_add.clone()
                    + (*maddsub_cols.op_hi_access.value())[i] * is_sub.clone(),
            );
            builder.when(is_real.clone()).assert_eq(
                maddsub_cols.src2_lo[i],
                local.prev_a_value[i] * is_add.clone() + local.op_a_value[i] * is_sub.clone(),
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
            .when(is_add.clone())
            .assert_word_eq(local.op_a_value, maddsub_cols.add_operation.value);

        builder.when(is_add).assert_word_eq(
            *maddsub_cols.op_hi_access.value(),
            maddsub_cols.add_operation.value_hi,
        );

        builder
            .when(is_sub.clone())
            .assert_word_eq(local.prev_a_value, maddsub_cols.add_operation.value);

        builder.when(is_sub).assert_word_eq(
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
                    AB::Expr::zero(),
                    AB::Expr::zero(),
                    AB::Expr::zero(),
                ]),
                local.is_ins,
            );

            builder.send_alu(
                Opcode::SRL.as_field::<AB::F>(),
                ins_cols.srl_val,
                ins_cols.ror_val,
                Word([
                    AB::Expr::from_canonical_u32(1) + ins_cols.msb - ins_cols.lsb,
                    AB::Expr::zero(),
                    AB::Expr::zero(),
                    AB::Expr::zero(),
                ]),
                local.is_ins,
            );

            builder.send_alu(
                Opcode::SLL.as_field::<AB::F>(),
                ins_cols.sll_val,
                local.op_b_value,
                Word([
                    AB::Expr::from_canonical_u32(31) - ins_cols.msb + ins_cols.lsb,
                    AB::Expr::zero(),
                    AB::Expr::zero(),
                    AB::Expr::zero(),
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
                    AB::Expr::zero(),
                    AB::Expr::zero(),
                    AB::Expr::zero(),
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
            AB::Expr::zero(),
            ins_cols.lsb,
            ins_cols.msb,
            local.is_ins,
        );

        builder.send_byte(
            ByteOpcode::LTU.as_field::<AB::F>(),
            AB::Expr::one(),
            ins_cols.lsb,
            ins_cols.msb + AB::Expr::one(),
            local.is_ins,
        );

        builder.send_byte(
            ByteOpcode::LTU.as_field::<AB::F>(),
            AB::Expr::one(),
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
                    AB::Expr::zero(),
                    AB::Expr::zero(),
                    AB::Expr::zero(),
                ]),
                local.is_ext,
            );

            builder.send_alu(
                Opcode::SRL.as_field::<AB::F>(),
                local.op_a_value,
                ext_cols.sll_val,
                Word([
                    AB::Expr::from_canonical_u32(31) - ext_cols.msbd,
                    AB::Expr::zero(),
                    AB::Expr::zero(),
                    AB::Expr::zero(),
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
            AB::Expr::zero(),
            ext_cols.lsb,
            ext_cols.msbd,
            local.is_ext,
        );

        builder.send_byte(
            ByteOpcode::LTU.as_field::<AB::F>(),
            AB::Expr::one(),
            ext_cols.lsb + ext_cols.msbd,
            AB::Expr::from_canonical_u32(32),
            local.is_ext,
        );
    }
}
