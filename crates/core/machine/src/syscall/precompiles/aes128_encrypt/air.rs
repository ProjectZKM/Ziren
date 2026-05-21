use crate::air::{MemoryAirBuilder, WordAirBuilder};
use crate::memory::MemoryCols;
use crate::operations::mix_column::MixColumn;
use crate::operations::round_key::{NextRoundKey, ROUND_CONST};
use crate::operations::subs_byte::SubsByte;
use crate::syscall::precompiles::aes128_encrypt::columns::{
    AES128EncryptionCols, NUM_AES128_ENCRYPTION_COLS,
};
use crate::syscall::precompiles::aes128_encrypt::AES128EncryptChip;
use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::FieldAlgebra;
use p3_matrix::Matrix;
use std::borrow::Borrow;
use zkm_core_executor::events::AES_128_BLOCK_BYTES;
use zkm_core_executor::syscalls::SyscallCode;
use zkm_core_executor::ByteOpcode;
use zkm_stark::{LookupScope, ZKMAirBuilder};

impl<F> BaseAir<F> for AES128EncryptChip {
    fn width(&self) -> usize {
        NUM_AES128_ENCRYPTION_COLS
    }
}

impl<AB> Air<AB> for AES128EncryptChip
where
    AB: ZKMAirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let (local, next) = (main.row_slice(0), main.row_slice(1));
        let local: &AES128EncryptionCols<AB::Var> = (*local).borrow();
        let next: &AES128EncryptionCols<AB::Var> = (*next).borrow();

        builder.receive_syscall(
            local.shard,
            local.clk,
            AB::F::from_canonical_u32(SyscallCode::AES128_ENCRYPT.syscall_id()),
            local.block_address,
            local.key_address,
            local.receive_syscall,
            LookupScope::Local,
        );

        self.eval_flags(builder, local);
        self.eval_memory_access(builder, local);
        self.eval_subs_byte(builder, local);
        self.eval_mix_column(builder, local);
        self.eval_add_round_key(builder, local);
        self.eval_compute_round_key(builder, local);
        self.eval_input_output(builder, local);
        self.eval_transition(builder, local, next);
    }
}

impl AES128EncryptChip {
    fn eval_flags<AB: ZKMAirBuilder>(
        &self,
        builder: &mut AB,
        local: &AES128EncryptionCols<AB::Var>,
    ) {
        let first_round = local.round[0];
        let last_round = local.round[10];
        for i in 0..11 {
            builder.assert_bool(local.round[i]);
        }
        builder.assert_bool(local.round_1to9);
        let mut computed_1to9 = AB::Expr::ZERO;
        for i in 1..10 {
            computed_1to9 = computed_1to9 + local.round[i];
        }
        builder.assert_eq(computed_1to9, local.round_1to9);
        builder.assert_eq(first_round * local.is_real, local.receive_syscall);
        builder.assert_eq(last_round + first_round + local.round_1to9, local.is_real);
    }

    fn eval_memory_access<AB: ZKMAirBuilder>(
        &self,
        builder: &mut AB,
        local: &AES128EncryptionCols<AB::Var>,
    ) {
        let mut round = AB::Expr::ZERO;
        for i in 0..11 {
            round = round + local.round[i] * AB::F::from_canonical_u32(i as u32);
        }

        // if this is the first row, populate reading key
        for i in 0..4 {
            builder.eval_memory_access(
                local.shard,
                local.clk,
                local.key_address + AB::F::from_canonical_u32(i as u32 * 4),
                &local.key[i],
                local.round[0],
            );
        }

        // if this is the first row, populate reading input
        for i in 0..4 {
            builder.eval_memory_access(
                local.shard,
                local.clk,
                local.block_address + AB::F::from_canonical_u32(i as u32 * 4),
                &local.block[i],
                local.round[0],
            );
        }

        // if this is the last row, populate writing output
        for i in 0..4 {
            builder.eval_memory_access(
                local.shard,
                local.clk + AB::Expr::ONE,
                local.block_address + AB::F::from_canonical_u32((i * 4) as u32),
                &local.block[i],
                local.round[10],
            );
        }
    }

    fn eval_subs_byte<AB: ZKMAirBuilder>(
        &self,
        builder: &mut AB,
        local: &AES128EncryptionCols<AB::Var>,
    ) {
        let round_1to10 = local.round_1to9 + local.round[10];
        for i in 0..16 {
            SubsByte::<AB::F>::eval(
                builder,
                local.state_subs_byte[i],
                local.state_matrix[i],
                round_1to10.clone(),
            );
        }
    }

    fn eval_mix_column<AB: ZKMAirBuilder>(
        &self,
        builder: &mut AB,
        local: &AES128EncryptionCols<AB::Var>,
    ) {
        let shifted_state = [
            local.state_subs_byte[0].value,
            local.state_subs_byte[5].value,
            local.state_subs_byte[10].value,
            local.state_subs_byte[15].value,
            local.state_subs_byte[4].value,
            local.state_subs_byte[9].value,
            local.state_subs_byte[14].value,
            local.state_subs_byte[3].value,
            local.state_subs_byte[8].value,
            local.state_subs_byte[13].value,
            local.state_subs_byte[2].value,
            local.state_subs_byte[7].value,
            local.state_subs_byte[12].value,
            local.state_subs_byte[1].value,
            local.state_subs_byte[6].value,
            local.state_subs_byte[11].value,
        ];
        MixColumn::<AB::F>::eval(builder, shifted_state, local.mix_column, local.round_1to9);
    }

    fn eval_add_round_key<AB: ZKMAirBuilder>(
        &self,
        builder: &mut AB,
        local: &AES128EncryptionCols<AB::Var>,
    ) {
        for i in 0..AES_128_BLOCK_BYTES {
            builder.send_byte(
                AB::F::from_canonical_u32(ByteOpcode::XOR as u32),
                local.add_round_key[i],
                local.mix_column.xor_byte4s[i].value,
                local.round_key_matrix[i],
                local.is_real,
            )
        }
    }

    fn eval_compute_round_key<AB: ZKMAirBuilder>(
        &self,
        builder: &mut AB,
        local: &AES128EncryptionCols<AB::Var>,
    ) {
        let round_0to9 = local.round_1to9 + local.round[0];
        NextRoundKey::<AB::F>::eval(
            builder,
            local.next_round_key,
            local.round_key_matrix,
            local.round_const,
            round_0to9,
        );

        for i in 0..11 {
            builder
                .when(local.round[i])
                .assert_eq(local.round_const, AB::F::from_canonical_u8(ROUND_CONST[i]));
        }
    }

    fn eval_input_output<AB: ZKMAirBuilder>(
        &self,
        builder: &mut AB,
        local: &AES128EncryptionCols<AB::Var>,
    ) {
        // In round 0, all state matrix values and key values are in [0, 255]
        for i in 0..AES_128_BLOCK_BYTES {
            builder.send_byte(
                AB::Expr::from_canonical_u8(ByteOpcode::U8Range as u8),
                AB::Expr::ZERO,
                AB::Expr::ZERO,
                local.state_matrix[i],
                local.round[0],
            );

            builder.send_byte(
                AB::Expr::from_canonical_u8(ByteOpcode::U8Range as u8),
                AB::Expr::ZERO,
                AB::Expr::ZERO,
                local.round_key_matrix[i],
                local.round[0],
            );
        }

        // In round 0, state and key matrix should be derived from cols.block and cols.key
        for i in 0..4 {
            for j in 0..4 {
                let idx = i * 4 + j;
                builder
                    .when(local.round[0])
                    .assert_eq(local.state_matrix[idx], local.block[i].access.value[j]);
                builder
                    .when(local.round[0])
                    .assert_eq(local.round_key_matrix[idx], local.key[i].access.value[j]);
            }
        }

        // In round 1-9, block should remain the same
        for i in 0..4 {
            builder
                .when(local.round_1to9)
                .assert_word_eq(*local.block[i].prev_value(), *local.block[i].value());
        }

        // In round 10, output block should be derived from state matrix
        for i in 0..4 {
            for j in 0..4 {
                let idx = i * 4 + j;
                builder
                    .when(local.round[10])
                    .assert_eq(local.block[i].access.value[j], local.add_round_key[idx]);
            }
        }
    }

    fn eval_transition<AB: ZKMAirBuilder>(
        &self,
        builder: &mut AB,
        local: &AES128EncryptionCols<AB::Var>,
        next: &AES128EncryptionCols<AB::Var>,
    ) {
        // if it's not the last round, shard, clk remain the same
        let round_0to9 = local.round_1to9 + local.round[0];
        builder.when(round_0to9.clone()).assert_eq(next.shard, local.shard);
        builder.when(round_0to9.clone()).assert_eq(next.clk, local.clk);

        // key_address, block_address, sbox_address remain the same
        builder.when(round_0to9.clone()).assert_eq(next.key_address, local.key_address);
        builder.when(round_0to9.clone()).assert_eq(next.block_address, local.block_address);

        // round transition
        for i in 0..10 {
            builder.when(round_0to9.clone()).assert_eq(local.round[i], next.round[i + 1]);
        }

        // state transition
        for i in 0..AES_128_BLOCK_BYTES {
            builder
                .when(round_0to9.clone())
                .assert_eq(local.add_round_key[i], next.state_matrix[i]);
        }

        // round key transition
        for i in 0..4 {
            builder
                .when(round_0to9.clone())
                .assert_eq(local.next_round_key.w4[i], next.round_key_matrix[i]);

            builder
                .when(round_0to9.clone())
                .assert_eq(local.next_round_key.w5[i], next.round_key_matrix[i + 4]);

            builder
                .when(round_0to9.clone())
                .assert_eq(local.next_round_key.w6[i], next.round_key_matrix[i + 8]);

            builder
                .when(round_0to9.clone())
                .assert_eq(local.next_round_key.w7[i], next.round_key_matrix[i + 12]);
        }
    }
}
