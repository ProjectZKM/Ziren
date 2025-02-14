use p3_air::AirBuilder;
use p3_field::FieldAlgebra;
use zkm2_stark::{air::ZKMAirBuilder, Word};

use crate::{
    air::{ZKMCoreAirBuilder, WordAirBuilder},
    cpu::{
        columns::{CpuCols, MemoryColumns, OpcodeSelectorCols},
        CpuChip,
    },
    memory::MemoryCols,
    operations::BabyBearWordRangeChecker,
};
use zkm2_core_executor::{events::MemoryAccessPosition, Opcode};

impl CpuChip {
    /// Computes whether the opcode is a memory instruction.
    pub(crate) fn is_memory_instruction<AB: ZKMAirBuilder>(
        &self,
        opcode_selectors: &OpcodeSelectorCols<AB::Var>,
    ) -> AB::Expr {
        opcode_selectors.is_lb
            + opcode_selectors.is_lbu
            + opcode_selectors.is_lh
            + opcode_selectors.is_lhu
            + opcode_selectors.is_lwl
            + opcode_selectors.is_lwr
            + opcode_selectors.is_ll
            + opcode_selectors.is_lw
            + opcode_selectors.is_sb
            + opcode_selectors.is_sh
            + opcode_selectors.is_sw
            + opcode_selectors.is_swl
            + opcode_selectors.is_swr
            + opcode_selectors.is_sc
            // + opcode_selectors.is_sdc1
    }

    /// Computes whether the opcode is a load instruction.
    pub(crate) fn is_load_instruction<AB: ZKMAirBuilder>(
        &self,
        opcode_selectors: &OpcodeSelectorCols<AB::Var>,
    ) -> AB::Expr {
        opcode_selectors.is_lb
            + opcode_selectors.is_lbu
            + opcode_selectors.is_lh
            + opcode_selectors.is_lhu
            + opcode_selectors.is_lw
            + opcode_selectors.is_lwr
            + opcode_selectors.is_lwl
            + opcode_selectors.is_ll
    }

    /// Computes whether the opcode is a store instruction.
    pub(crate) fn is_store_instruction<AB: ZKMAirBuilder>(
        &self,
        opcode_selectors: &OpcodeSelectorCols<AB::Var>,
    ) -> AB::Expr {
        opcode_selectors.is_sb
            + opcode_selectors.is_sh
            + opcode_selectors.is_sw
            + opcode_selectors.is_swr
            + opcode_selectors.is_swl
            + opcode_selectors.is_sc
            // + opcode_selectors.is_sdc1
    }

    /// Computes whether the opcode is a store instruction.
    pub(crate) fn is_store_instruction_except_sc<AB: ZKMAirBuilder>(
        &self,
        opcode_selectors: &OpcodeSelectorCols<AB::Var>,
    ) -> AB::Expr {
        opcode_selectors.is_sb
            + opcode_selectors.is_sh
            + opcode_selectors.is_sw
            + opcode_selectors.is_swr
            + opcode_selectors.is_swl
    }

    /// Constrains the addr_aligned, addr_offset, and addr_word memory columns.
    ///
    /// This method will do the following:
    /// 1. Calculate that the unaligned address is correctly computed to be op_b.value + op_c.value.
    /// 2. Calculate that the address offset is address % 4.
    /// 3. Assert the validity of the aligned address given the address offset and the unaligned
    ///    address.
    pub(crate) fn eval_memory_address_and_access<AB: ZKMCoreAirBuilder>(
        &self,
        builder: &mut AB,
        local: &CpuCols<AB::Var>,
        is_memory_instruction: AB::Expr,
    ) {
        // Get the memory specific columns.
        let memory_columns = local.opcode_specific_columns.memory();

        // Send to the ALU table to verify correct calculation of addr_word.
        builder.send_alu(
            AB::Expr::from_canonical_u32(Opcode::ADD as u32),
            memory_columns.addr_word,
            local.op_b_val(),
            local.op_c_val(),
            local.shard,
            memory_columns.addr_word_nonce,
            is_memory_instruction.clone(),
        );

        // Range check the addr_word to be a valid babybear word.
        BabyBearWordRangeChecker::<AB::F>::range_check(
            builder,
            memory_columns.addr_word,
            memory_columns.addr_word_range_checker,
            is_memory_instruction.clone(),
        );

        // Check that each addr_word element is a byte.
        builder.slice_range_check_u8(&memory_columns.addr_word.0, is_memory_instruction.clone());

        // Evaluate the addr_offset column and offset flags.
        self.eval_offset_value_flags(builder, memory_columns, local);

        // Assert that reduce(addr_word) == addr_aligned + addr_offset.
        builder.when(is_memory_instruction.clone()).assert_eq::<AB::Expr, AB::Expr>(
            memory_columns.addr_aligned + memory_columns.addr_offset,
            memory_columns.addr_word.reduce::<AB>(),
        );

        // Verify that the least significant byte of addr_word - addr_offset is divisible by 4.
        let offset = [
            memory_columns.offset_is_one,
            memory_columns.offset_is_two,
            memory_columns.offset_is_three,
        ]
            .iter()
            .enumerate()
            .fold(AB::Expr::ZERO, |acc, (index, &value)| {
                acc + AB::Expr::from_canonical_usize(index + 1) * value
            });
        let mut recomposed_byte = AB::Expr::ZERO;
        memory_columns.aa_least_sig_byte_decomp.iter().enumerate().for_each(|(i, value)| {
            builder.when(is_memory_instruction.clone()).assert_bool(*value);

            recomposed_byte =
                recomposed_byte.clone() + AB::Expr::from_canonical_usize(1 << (i + 2)) * *value;
        });

        builder
            .when(is_memory_instruction.clone())
            .assert_eq(memory_columns.addr_word[0] - offset, recomposed_byte);

        // For operations that require reading from memory (not registers), we need to read the
        // value into the memory columns.
        builder.eval_memory_access(
            local.shard,
            local.clk + AB::F::from_canonical_u32(MemoryAccessPosition::Memory as u32),
            memory_columns.addr_aligned,
            &memory_columns.memory_access,
            is_memory_instruction.clone(),
        );

        // On memory load instructions, make sure that the memory value is not changed.
        builder.when(self.is_load_instruction::<AB>(&local.selectors)).assert_word_eq(
            *memory_columns.memory_access.value(),
            *memory_columns.memory_access.prev_value(),
        );
    }

    /// Evaluates constraints related to loading from memory.
    pub(crate) fn eval_memory_load<AB: ZKMAirBuilder>(
        &self,
        builder: &mut AB,
        local: &CpuCols<AB::Var>,
    ) {
        // Get the memory specific columns.
        let memory_columns = local.opcode_specific_columns.memory();

        // Verify the unsigned_mem_value column.
        self.eval_unsigned_mem_value(builder, memory_columns, local);

        // If it's a signed operation (such as LB or LH), then we need verify the bit decomposition
        // of the most significant byte to get it's sign.
        self.eval_most_sig_byte_bit_decomp(builder, memory_columns, local, &local.unsigned_mem_val);

        // Assert that correct value of `mem_value_is_neg_not_x0`.
        builder.assert_eq(
            local.mem_value_is_neg_not_x0,
            (local.selectors.is_lb + local.selectors.is_lh)
                * memory_columns.most_sig_byte_decomp[7]
                * (AB::Expr::ONE - local.instruction.op_a_0),
        );

        // When the memory value is negative and not writing to x0, use the SUB opcode to compute
        // the signed value of the memory value and verify that the op_a value is correct.
        let signed_value = Word([
            AB::Expr::ZERO,
            AB::Expr::ONE * local.selectors.is_lb,
            AB::Expr::ONE * local.selectors.is_lh,
            AB::Expr::ZERO,
        ]);
        builder.send_alu(
            Opcode::SUB.as_field::<AB::F>(),
            local.op_a_val(),
            local.unsigned_mem_val,
            signed_value,
            local.shard,
            local.unsigned_mem_val_nonce,
            local.mem_value_is_neg_not_x0,
        );

        // Assert that correct value of `mem_value_is_pos_not_x0`.
        let mem_value_is_pos = (local.selectors.is_lb + local.selectors.is_lh)
            * (AB::Expr::ONE - memory_columns.most_sig_byte_decomp[7])
            + local.selectors.is_lbu
            + local.selectors.is_lhu
            + local.selectors.is_lw;
        builder.assert_eq(
            local.mem_value_is_pos_not_x0,
            mem_value_is_pos * (AB::Expr::ONE - local.instruction.op_a_0),
        );

        // When the memory value is not positive and not writing to x0, assert that op_a value is
        // equal to the unsigned memory value.
        builder
            .when(local.mem_value_is_pos_not_x0)
            .assert_word_eq(local.unsigned_mem_val, local.op_a_val());

        let offset_is_zero = AB::Expr::ONE
            - memory_columns.offset_is_one
            - memory_columns.offset_is_two
            - memory_columns.offset_is_three;
        let one = AB::Expr::ONE;
        let prev_a_val = local.op_a_access.prev_value();
        let a_val = local.op_a_val();

        let mem_val = *memory_columns.memory_access.value();
        let prev_mem_val = *memory_columns.memory_access.prev_value();

        // Compute the expected stored value for a LWR instruction.
        let lwr_expected_load_value = Word([
            mem_val[0] * offset_is_zero.clone()
               + mem_val[1] * memory_columns.offset_is_one
               + mem_val[2] * memory_columns.offset_is_two
               + mem_val[3] * memory_columns.offset_is_three,
            mem_val[1] * offset_is_zero.clone()
               + mem_val[2] * memory_columns.offset_is_one
               + mem_val[3] * memory_columns.offset_is_two
               + prev_a_val[1] * memory_columns.offset_is_three,
            mem_val[2] * offset_is_zero.clone()
               + mem_val[3] * memory_columns.offset_is_one
               + prev_a_val[2] * (one.clone() - memory_columns.offset_is_one - offset_is_zero.clone()),
            mem_val[3] * offset_is_zero.clone()
               + prev_a_val[3] * (one.clone() - offset_is_zero.clone())
        ]);
        builder
            .when(local.selectors.is_lwr)
            .assert_word_eq(a_val.map(|x| x.into()), lwr_expected_load_value);


        // Compute the expected stored value for a LWL instruction.
        let lwl_expected_load_value = Word([
            mem_val[0] * memory_columns.offset_is_three
                + prev_a_val[0] * (one.clone() - memory_columns.offset_is_three),
            mem_val[1] * memory_columns.offset_is_three
                + mem_val[0] * memory_columns.offset_is_two
                + prev_a_val[1] * memory_columns.offset_is_one
                + prev_a_val[1] * offset_is_zero.clone(),
            mem_val[2] * memory_columns.offset_is_three
                + mem_val[1] * memory_columns.offset_is_two
                + mem_val[0] * memory_columns.offset_is_one
                + prev_a_val[2] * offset_is_zero.clone(),
            mem_val[3] * memory_columns.offset_is_three
                + mem_val[2] * memory_columns.offset_is_two
                + mem_val[1] * memory_columns.offset_is_one
                + mem_val[0] * offset_is_zero.clone(),
        ]);
        builder
            .when(local.selectors.is_lwl)
            .assert_word_eq(a_val.map(|x| x.into()), lwl_expected_load_value);

        // Compute the expected stored value for a LL instruction.
        builder.when(local.selectors.is_ll).assert_word_eq(a_val.map(|x| x.into()), mem_val);
        // Ensure that the offset is 0.
        builder.when(local.selectors.is_ll).assert_one(offset_is_zero.clone());

        // value stay the same.
        builder.when(local.selectors.is_lwr)
        .assert_word_eq(mem_val.map(|x| x.into()), prev_mem_val);
        builder.when(local.selectors.is_lwl)
            .assert_word_eq(mem_val.map(|x| x.into()), prev_mem_val);
        builder.when(local.selectors.is_ll)
            .assert_word_eq(mem_val.map(|x| x.into()), prev_mem_val);
    }

    /// Evaluates constraints related to storing to memory.
    pub(crate) fn eval_memory_store<AB: ZKMAirBuilder>(
        &self,
        builder: &mut AB,
        local: &CpuCols<AB::Var>,
    ) {
        let memory_columns = local.opcode_specific_columns.memory();

        // Get the memory offset flags.
        self.eval_offset_value_flags(builder, memory_columns, local);
        // Compute the offset_is_zero flag.  The other offset flags are already constrained by the
        // method `eval_memory_address_and_access`, which is called in
        // `eval_memory_address_and_access`.
        let offset_is_zero = AB::Expr::ONE
            - memory_columns.offset_is_one
            - memory_columns.offset_is_two
            - memory_columns.offset_is_three;

        // Compute the expected stored value for a SB instruction.
        let one = AB::Expr::ONE;
        let a_val = local.op_a_val();
        let mem_val = *memory_columns.memory_access.value();
        let prev_mem_val = *memory_columns.memory_access.prev_value();
        let sb_expected_stored_value = Word([
            a_val[0] * offset_is_zero.clone()
                + (one.clone() - offset_is_zero.clone()) * prev_mem_val[0],
            a_val[0] * memory_columns.offset_is_one
                + (one.clone() - memory_columns.offset_is_one) * prev_mem_val[1],
            a_val[0] * memory_columns.offset_is_two
                + (one.clone() - memory_columns.offset_is_two) * prev_mem_val[2],
            a_val[0] * memory_columns.offset_is_three
                + (one.clone() - memory_columns.offset_is_three) * prev_mem_val[3],
        ]);

        builder
            .when(local.selectors.is_sb)
            .assert_word_eq(mem_val.map(|x| x.into()), sb_expected_stored_value);

        // FIXME: stephen add constraints for other instructions, LWR, LWL, LL, SWL, SWR, SC, SDC1.

        // When the instruction is SH, make sure both offset one and three are off.
        builder
            .when(local.selectors.is_sh)
            .assert_zero(memory_columns.offset_is_one + memory_columns.offset_is_three);

        // When the instruction is SW, ensure that the offset is 0.
        builder.when(local.selectors.is_sw).assert_one(offset_is_zero.clone());

        // Compute the expected stored value for a SH instruction.
        let a_is_lower_half = offset_is_zero.clone();
        let a_is_upper_half = memory_columns.offset_is_two;
        let sh_expected_stored_value = Word([
            a_val[0] * a_is_lower_half.clone()
                + (one.clone() - a_is_lower_half.clone()) * prev_mem_val[0],
            a_val[1] * a_is_lower_half.clone() + (one.clone() - a_is_lower_half) * prev_mem_val[1],
            a_val[0] * a_is_upper_half + (one.clone() - a_is_upper_half) * prev_mem_val[2],
            a_val[1] * a_is_upper_half + (one.clone() - a_is_upper_half) * prev_mem_val[3],
        ]);
        builder
            .when(local.selectors.is_sh)
            .assert_word_eq(mem_val.map(|x| x.into()), sh_expected_stored_value);

        // When the instruction is SW, just use the word without masking.
        builder
            .when(local.selectors.is_sw)
            .assert_word_eq(mem_val.map(|x| x.into()), a_val.map(|x| x.into()));

        // When the instruction is SWL: compute the expected stored value
        let swl_expected_stored_value = Word([
            a_val[3] * offset_is_zero.clone()
                + a_val[2] * memory_columns.offset_is_one
                + a_val[1] * memory_columns.offset_is_two
                + a_val[0] * memory_columns.offset_is_three,
            prev_mem_val[1] * offset_is_zero.clone()
                + a_val[3] * memory_columns.offset_is_one
                + a_val[2] * memory_columns.offset_is_two
                + a_val[1] * memory_columns.offset_is_three,
            prev_mem_val[2] * (offset_is_zero.clone() + memory_columns.offset_is_one)
                + a_val[3] * memory_columns.offset_is_two
                + a_val[2] * memory_columns.offset_is_three,
            prev_mem_val[3] * (one.clone() - memory_columns.offset_is_three)
                + a_val[3] * memory_columns.offset_is_three
        ]);
        builder
            .when(local.selectors.is_swl)
            .assert_word_eq(mem_val.map(|x| x.into()), swl_expected_stored_value);

        // When the instruction is SWR: compute the expected stored value
        let swr_expected_stored_value = Word([
            a_val[0] * offset_is_zero.clone()
                + prev_mem_val[0] * (one.clone() - offset_is_zero.clone()),
            a_val[1] * offset_is_zero.clone()
                + a_val[0] * memory_columns.offset_is_one
                + prev_mem_val[1] * (memory_columns.offset_is_two + memory_columns.offset_is_three),
            a_val[2] * offset_is_zero.clone()
                + a_val[1] * memory_columns.offset_is_one
                + a_val[0] * memory_columns.offset_is_two
                + prev_mem_val[2] * memory_columns.offset_is_three,
            a_val[3] * offset_is_zero.clone()
                + a_val[2] * memory_columns.offset_is_one
                + a_val[1] * memory_columns.offset_is_two
                + a_val[0] * memory_columns.offset_is_three,
        ]);
        builder
            .when(local.selectors.is_swr)
            .assert_word_eq(mem_val.map(|x| x.into()), swr_expected_stored_value);

        // When the instruction is SC: compute the expected stored value
        // let prev_a_val = local.op_a_access.prev_value();

        // Ensure that the offset is 0.
        // builder.when(local.selectors.is_sc).assert_one(offset_is_zero.clone());

        // mem_val = prev_a_val
        // builder.when(local.selectors.is_sc)
        //     .assert_word_eq(prev_a_val.map(|x| x.into()), mem_val.map(|x| x.into()));

        // a_val = 1
        // builder.when(local.selectors.is_sc).assert_one(a_val);


        // When the instruction is SDC1: compute the expected stored value
        builder.when(local.selectors.is_sdc1).assert_zero(mem_val[0].into());
        builder.when(local.selectors.is_sdc1).assert_zero(mem_val[1].into());
        builder.when(local.selectors.is_sdc1).assert_zero(mem_val[2].into());
        builder.when(local.selectors.is_sdc1).assert_zero(mem_val[3].into());

        // address should be doubleword-aligned
        builder.when(local.selectors.is_sdc1).assert_one(offset_is_zero.clone());
    }

    /// This function is used to evaluate the unsigned memory value for the load memory
    /// instructions.
    pub(crate) fn eval_unsigned_mem_value<AB: ZKMAirBuilder>(
        &self,
        builder: &mut AB,
        memory_columns: &MemoryColumns<AB::Var>,
        local: &CpuCols<AB::Var>,
    ) {
        let mem_val = *memory_columns.memory_access.value();
        let prev_mem_val = *memory_columns.memory_access.prev_value();

        // Compute the offset_is_zero flag.  The other offset flags are already constrained by the
        // method `eval_memory_address_and_access`, which is called in
        // `eval_memory_address_and_access`.
        let offset_is_zero = AB::Expr::ONE
            - memory_columns.offset_is_one
            - memory_columns.offset_is_two
            - memory_columns.offset_is_three;

        // Compute the byte value.
        let mem_byte = mem_val[0] * offset_is_zero.clone()
            + mem_val[1] * memory_columns.offset_is_one
            + mem_val[2] * memory_columns.offset_is_two
            + mem_val[3] * memory_columns.offset_is_three;
        let byte_value = Word::extend_expr::<AB>(mem_byte.clone());

        // When the instruction is LB or LBU, just use the lower byte.
        builder
            .when(local.selectors.is_lb + local.selectors.is_lbu)
            .assert_word_eq(byte_value, local.unsigned_mem_val.map(|x| x.into()));

        // When the instruction is LH or LHU, use the lower half.
        builder
            .when(local.selectors.is_lh + local.selectors.is_lhu)
            .assert_zero(memory_columns.offset_is_one + memory_columns.offset_is_three);

        // When the instruction is LW, ensure that the offset is zero.
        builder.when(local.selectors.is_lw).assert_one(offset_is_zero.clone());

        //   addr_offset = addr % 4
        //   offset = 1 - (addr_offset >> 1)
        //   value = match offset % 2 {
        //      0 => mem_value & 0x0000FFFF,
        //      1 => (mem_value & 0xFFFF0000) >> 16,
        //   }
        //    le  be
        // 0   0   1
        // 1   0   1
        // 2   1   0
        // 3   1   0
        // value=0x12_34_56_78,  addr=0x27654320, addr_offset=0, offset=1, value=0x12_34,
        let one = AB::Expr::ONE;
        let use_lower_half = offset_is_zero.clone();
        let use_upper_half = memory_columns.offset_is_two;
        let half_value = Word([
            use_lower_half.clone() * mem_val[0] + use_upper_half * mem_val[2],
            use_lower_half * mem_val[1] + use_upper_half * mem_val[3],
            AB::Expr::ZERO,
            AB::Expr::ZERO,
        ]);
        builder
            .when(local.selectors.is_lh + local.selectors.is_lhu)
            .assert_word_eq(half_value, local.unsigned_mem_val.map(|x| x.into()));

        // When the instruction is LW, just use the word.
        builder.when(local.selectors.is_lw).assert_word_eq(mem_val, local.unsigned_mem_val);

        // When the instruction is LWR:
        //     val = mem_value >> (24 - addr_offset * 8);
        //     mask = 0xffFFffFFu32 >> (24 - addr_offset * 8);
        //     unsigned_mem_val = ((mem_value & (!mask)) | val);
        let lwr_unsigned_mem_val = Word([
            mem_val[0] * memory_columns.offset_is_three
                + mem_val[1] * memory_columns.offset_is_two
                + mem_val[2] * memory_columns.offset_is_one
                + mem_val[3] * offset_is_zero.clone(),
            mem_val[1] * memory_columns.offset_is_three
                + mem_val[2] * memory_columns.offset_is_two
                + mem_val[3] * memory_columns.offset_is_one
                + mem_val[1] * offset_is_zero.clone(),
            mem_val[2] * memory_columns.offset_is_three
                + mem_val[3] * memory_columns.offset_is_two
                + mem_val[2] * memory_columns.offset_is_one
                + mem_val[2] * offset_is_zero.clone(),
            mem_val[3].into(),
        ]);
        builder
            .when(local.selectors.is_lwr)
            .assert_word_eq(lwr_unsigned_mem_val, local.unsigned_mem_val.map(|x| x.into()));


        // When the instruction is LWL:
        // val = mem_value << (addr_offset * 8);
        // mask = 0xffFFffFFu32 << (addr_offset * 8);
        // unsigned_mem_val = (mem_value & (!mask)) | val)
        let lwl_unsigned_mem_val = Word([
            mem_val[0].into(),
            mem_val[0] * memory_columns.offset_is_one
                + (one.clone() - memory_columns.offset_is_one) * mem_val[1],
            mem_val[0] * memory_columns.offset_is_two
                + mem_val[1] * memory_columns.offset_is_one
                + (one.clone() - memory_columns.offset_is_two - memory_columns.offset_is_one) * mem_val[2],
            mem_val[0] * memory_columns.offset_is_three
                + mem_val[1] * memory_columns.offset_is_two
                + mem_val[2] * memory_columns.offset_is_one
                + offset_is_zero.clone() * mem_val[3],
        ]);
        builder
            .when(local.selectors.is_lwl)
            .assert_word_eq(lwl_unsigned_mem_val, local.unsigned_mem_val.map(|x| x.into()));

        // When the instruction is LL:
        // unsigned_mem_val = mem_value
        builder
            .when(local.selectors.is_ll)
            .assert_word_eq(mem_val, local.unsigned_mem_val.map(|x| x.into()));

    }

    /// Evaluates the decomposition of the most significant byte of the memory value.
    pub(crate) fn eval_most_sig_byte_bit_decomp<AB: ZKMAirBuilder>(
        &self,
        builder: &mut AB,
        memory_columns: &MemoryColumns<AB::Var>,
        local: &CpuCols<AB::Var>,
        unsigned_mem_val: &Word<AB::Var>,
    ) {
        let is_mem = self.is_memory_instruction::<AB>(&local.selectors);
        let mut recomposed_byte = AB::Expr::ZERO;
        for i in 0..8 {
            builder.when(is_mem.clone()).assert_bool(memory_columns.most_sig_byte_decomp[i]);
            recomposed_byte = recomposed_byte.clone()
                + memory_columns.most_sig_byte_decomp[i] * AB::Expr::from_canonical_u8(1 << i);
        }
        builder.when(local.selectors.is_lb).assert_eq(recomposed_byte.clone(), unsigned_mem_val[0]);
        builder.when(local.selectors.is_lh).assert_eq(recomposed_byte, unsigned_mem_val[1]);
    }

    /// Evaluates the offset value flags.
    pub(crate) fn eval_offset_value_flags<AB: ZKMAirBuilder>(
        &self,
        builder: &mut AB,
        memory_columns: &MemoryColumns<AB::Var>,
        local: &CpuCols<AB::Var>,
    ) {
        let is_mem_op = self.is_memory_instruction::<AB>(&local.selectors);
        let offset_is_zero = AB::Expr::ONE
            - memory_columns.offset_is_one
            - memory_columns.offset_is_two
            - memory_columns.offset_is_three;

        let mut filtered_builder = builder.when(is_mem_op);

        // Assert that the value flags are boolean
        filtered_builder.assert_bool(memory_columns.offset_is_one);
        filtered_builder.assert_bool(memory_columns.offset_is_two);
        filtered_builder.assert_bool(memory_columns.offset_is_three);

        // Assert that only one of the value flags is true
        filtered_builder.assert_one(
            offset_is_zero.clone()
                + memory_columns.offset_is_one
                + memory_columns.offset_is_two
                + memory_columns.offset_is_three,
        );

        // Assert that the correct value flag is set
        filtered_builder.when(offset_is_zero).assert_zero(memory_columns.addr_offset);
        filtered_builder.when(memory_columns.offset_is_one).assert_one(memory_columns.addr_offset);
        filtered_builder
            .when(memory_columns.offset_is_two)
            .assert_eq(memory_columns.addr_offset, AB::Expr::TWO);
        filtered_builder
            .when(memory_columns.offset_is_three)
            .assert_eq(memory_columns.addr_offset, AB::Expr::from_canonical_u8(3));
    }
}