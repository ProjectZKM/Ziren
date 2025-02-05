use p3_air::AirBuilder;
use p3_field::FieldAlgebra;
use zkm2_core_executor::syscalls::SyscallCode;
use zkm2_stark::{
    air::{
        BaseAirBuilder, InteractionScope, PublicValues, ZKMAirBuilder, POSEIDON_NUM_WORDS,
        PV_DIGEST_NUM_WORDS,
    },
    Word,
};

use crate::{
    air::WordAirBuilder,
    cpu::{
        columns::{CpuCols, OpcodeSelectorCols},
        CpuChip,
    },
    memory::MemoryCols,
    operations::{BabyBearWordRangeChecker, IsZeroOperation},
};

impl CpuChip {
    /// Whether the instruction is an syscall instruction.
    pub(crate) fn is_syscall_instruction<AB: ZKMAirBuilder>(
        &self,
        opcode_selectors: &OpcodeSelectorCols<AB::Var>,
    ) -> AB::Expr {
        opcode_selectors.is_syscall.into()
    }

    /// Constraints related to the syscall opcode.
    ///
    /// This method will do the following:
    /// 1. Send the syscall to the precompile table, if needed.
    /// 2. Check for valid op_a values.
    pub(crate) fn eval_syscall<AB: ZKMAirBuilder>(&self, builder: &mut AB, local: &CpuCols<AB::Var>) {
        let syscall_cols = local.opcode_specific_columns.syscall();
        let is_syscall_instruction = self.is_syscall_instruction::<AB>(&local.selectors);

        // The syscall code is the read-in value of op_a at the start of the instruction.
        let syscall_code = local.op_a_access.prev_value();

        // We interpret the syscall_code as little-endian bytes and interpret each byte as a u8
        // with different information.
        let syscall_id = syscall_code[0];
        let send_to_table = syscall_code[1];

        // Handle cases:
        // - is_syscall_instruction = 1 => syscall_mul_send_to_table == send_to_table
        // - is_syscall_instruction = 0 => syscall_mul_send_to_table == 0
        builder
            .assert_eq(local.syscall_mul_send_to_table, send_to_table * is_syscall_instruction.clone());

        builder.send_syscall(
            local.shard,
            local.clk,
            syscall_cols.syscall_nonce,
            syscall_id,
            local.op_b_val().reduce::<AB>(),
            local.op_c_val().reduce::<AB>(),
            local.syscall_mul_send_to_table,
            InteractionScope::Local,
        );

        // Compute whether this syscall is ENTER_UNCONSTRAINED.
        let is_enter_unconstrained = {
            IsZeroOperation::<AB::F>::eval(
                builder,
                syscall_id
                    - AB::Expr::from_canonical_u32(SyscallCode::ENTER_UNCONSTRAINED.syscall_id()),
                syscall_cols.is_enter_unconstrained,
                is_syscall_instruction.clone(),
            );
            syscall_cols.is_enter_unconstrained.result
        };

        // Compute whether this syscall is HINT_LEN.
        let is_hint_len = {
            IsZeroOperation::<AB::F>::eval(
                builder,
                syscall_id - AB::Expr::from_canonical_u32(SyscallCode::SYSHINTLEN.syscall_id()),
                syscall_cols.is_hint_len,
                is_syscall_instruction.clone(),
            );
            syscall_cols.is_hint_len.result
        };

        // When syscall_id is ENTER_UNCONSTRAINED, the new value of op_a should be 0.
        let zero_word = Word::<AB::F>::from(0);
        builder
            .when(is_syscall_instruction.clone() * is_enter_unconstrained)
            .assert_word_eq(local.op_a_val(), zero_word);

        // When the syscall is not one of ENTER_UNCONSTRAINED or HINT_LEN, op_a shouldn't change.
        builder
            .when(is_syscall_instruction.clone())
            .when_not(is_enter_unconstrained + is_hint_len)
            .assert_word_eq(local.op_a_val(), local.op_a_access.prev_value);

        // Verify value of syscall_range_check_operand column.
        builder.assert_eq(
            local.syscall_range_check_operand,
            is_syscall_instruction
                * (syscall_cols.is_halt.result + syscall_cols.is_commit_deferred_proofs.result),
        );

        // Babybear range check the operand_to_check word.
        BabyBearWordRangeChecker::<AB::F>::range_check::<AB>(
            builder,
            syscall_cols.operand_to_check,
            syscall_cols.operand_range_check_cols,
            local.syscall_range_check_operand.into(),
        );
    }

    /// Constraints related to the COMMIT and COMMIT_DEFERRED_PROOFS instructions.
    pub(crate) fn eval_commit<AB: ZKMAirBuilder>(
        &self,
        builder: &mut AB,
        local: &CpuCols<AB::Var>,
        commit_digest: [Word<AB::PublicVar>; PV_DIGEST_NUM_WORDS],
        deferred_proofs_digest: [AB::PublicVar; POSEIDON_NUM_WORDS],
    ) {
        let (is_commit, is_commit_deferred_proofs) =
            self.get_is_commit_related_syscall(builder, local);

        // Get the syscall specific columns.
        let syscall_columns = local.opcode_specific_columns.syscall();

        // Verify the index bitmap.
        let mut bitmap_sum = AB::Expr::ZERO;
        // They should all be bools.
        for bit in syscall_columns.index_bitmap.iter() {
            builder.when(local.selectors.is_syscall).assert_bool(*bit);
            bitmap_sum = bitmap_sum.clone() + (*bit).into();
        }
        // When the syscall is COMMIT or COMMIT_DEFERRED_PROOFS, there should be one set bit.
        builder
            .when(
                local.selectors.is_syscall * (is_commit.clone() + is_commit_deferred_proofs.clone()),
            )
            .assert_one(bitmap_sum.clone());
        // When it's some other syscall, there should be no set bits.
        builder
            .when(
                local.selectors.is_syscall
                    * (AB::Expr::ONE - (is_commit.clone() + is_commit_deferred_proofs.clone())),
            )
            .assert_zero(bitmap_sum);

        // Verify that word_idx corresponds to the set bit in index bitmap.
        for (i, bit) in syscall_columns.index_bitmap.iter().enumerate() {
            builder.when(*bit * local.selectors.is_syscall).assert_eq(
                local.op_b_access.prev_value()[0],
                AB::Expr::from_canonical_u32(i as u32),
            );
        }
        // Verify that the 3 upper bytes of the word_idx are 0.
        for i in 0..3 {
            builder
                .when(
                    local.selectors.is_syscall
                        * (is_commit.clone() + is_commit_deferred_proofs.clone()),
                )
                .assert_eq(local.op_b_access.prev_value()[i + 1], AB::Expr::from_canonical_u32(0));
        }

        // Retrieve the expected public values digest word to check against the one passed into the
        // commit syscall. Note that for the interaction builder, it will not have any digest words,
        // since it's used during AIR compilation time to parse for all send/receives. Since
        // that interaction builder will ignore the other constraints of the air, it is safe
        // to not include the verification check of the expected public values digest word.
        let expected_pv_digest_word =
            builder.index_word_array(&commit_digest, &syscall_columns.index_bitmap);

        let digest_word = local.op_c_access.prev_value();

        // Verify the public_values_digest_word.
        builder
            .when(local.selectors.is_syscall * is_commit)
            .assert_word_eq(expected_pv_digest_word, *digest_word);

        let expected_deferred_proofs_digest_element =
            builder.index_array(&deferred_proofs_digest, &syscall_columns.index_bitmap);

        // Verify that the operand that was range checked is digest_word.
        builder
            .when(local.selectors.is_syscall * is_commit_deferred_proofs.clone())
            .assert_word_eq(*digest_word, syscall_columns.operand_to_check);

        builder
            .when(local.selectors.is_syscall * is_commit_deferred_proofs)
            .assert_eq(expected_deferred_proofs_digest_element, digest_word.reduce::<AB>());
    }

    /// Constraint related to the halt and unimpl instruction.
    pub(crate) fn eval_halt_unimpl<AB: ZKMAirBuilder>(
        &self,
        builder: &mut AB,
        local: &CpuCols<AB::Var>,
        next: &CpuCols<AB::Var>,
        public_values: &PublicValues<Word<AB::PublicVar>, AB::PublicVar>,
    ) {
        let is_halt = self.get_is_halt_syscall(builder, local);

        // If we're halting and it's a transition, then the next.is_real should be 0.
        builder
            .when_transition()
            .when(is_halt.clone() + local.selectors.is_unimpl)
            .assert_zero(next.is_real);

        builder.when(is_halt.clone()).assert_zero(local.next_pc);

        // Verify that the operand that was range checked is op_b.
        let syscall_columns = local.opcode_specific_columns.syscall();
        builder
            .when(is_halt.clone())
            .assert_word_eq(local.op_b_val(), syscall_columns.operand_to_check);

        builder
            .when(is_halt.clone())
            .assert_eq(local.op_b_access.value().reduce::<AB>(), public_values.exit_code);
    }

    /// Returns a boolean expression indicating whether the instruction is a HALT instruction.
    pub(crate) fn get_is_halt_syscall<AB: ZKMAirBuilder>(
        &self,
        builder: &mut AB,
        local: &CpuCols<AB::Var>,
    ) -> AB::Expr {
        let syscall_cols = local.opcode_specific_columns.syscall();
        let is_syscall_instruction = self.is_syscall_instruction::<AB>(&local.selectors);

        // The syscall code is the read-in value of op_a at the start of the instruction.
        let syscall_code = local.op_a_access.prev_value();

        let syscall_id = syscall_code[0];

        // Compute whether this syscall is HALT.
        let is_halt = {
            IsZeroOperation::<AB::F>::eval(
                builder,
                syscall_id - AB::Expr::from_canonical_u32(SyscallCode::HALT.syscall_id()),
                syscall_cols.is_halt,
                is_syscall_instruction.clone(),
            );
            syscall_cols.is_halt.result
        };

        is_halt * is_syscall_instruction
    }

    /// Returns two boolean expression indicating whether the instruction is a COMMIT or
    /// COMMIT_DEFERRED_PROOFS instruction.
    pub(crate) fn get_is_commit_related_syscall<AB: ZKMAirBuilder>(
        &self,
        builder: &mut AB,
        local: &CpuCols<AB::Var>,
    ) -> (AB::Expr, AB::Expr) {
        let syscall_cols = local.opcode_specific_columns.syscall();

        let is_syscall_instruction = self.is_syscall_instruction::<AB>(&local.selectors);

        // The syscall code is the read-in value of op_a at the start of the instruction.
        let syscall_code = local.op_a_access.prev_value();

        let syscall_id = syscall_code[0];

        // Compute whether this syscall is COMMIT.
        let is_commit = {
            IsZeroOperation::<AB::F>::eval(
                builder,
                syscall_id - AB::Expr::from_canonical_u32(SyscallCode::COMMIT.syscall_id()),
                syscall_cols.is_commit,
                is_syscall_instruction.clone(),
            );
            syscall_cols.is_commit.result
        };

        // Compute whether this syscall is COMMIT_DEFERRED_PROOFS.
        let is_commit_deferred_proofs = {
            IsZeroOperation::<AB::F>::eval(
                builder,
                syscall_id
                    - AB::Expr::from_canonical_u32(
                        SyscallCode::COMMIT_DEFERRED_PROOFS.syscall_id(),
                    ),
                syscall_cols.is_commit_deferred_proofs,
                is_syscall_instruction.clone(),
            );
            syscall_cols.is_commit_deferred_proofs.result
        };

        (is_commit.into(), is_commit_deferred_proofs.into())
    }

    /// Returns the number of extra cycles from an syscall instruction.
    pub(crate) fn get_num_extra_syscall_cycles<AB: ZKMAirBuilder>(
        &self,
        local: &CpuCols<AB::Var>,
    ) -> AB::Expr {
        let is_syscall_instruction = self.is_syscall_instruction::<AB>(&local.selectors);

        // The syscall code is the read-in value of op_a at the start of the instruction.
        let syscall_code = local.op_a_access.prev_value();

        let num_extra_cycles = syscall_code[2];

        num_extra_cycles * is_syscall_instruction.clone()
    }
}
