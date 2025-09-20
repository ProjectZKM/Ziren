use std::borrow::Borrow;
use log::__private_api::loc;
use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::FieldAlgebra;
use p3_matrix::Matrix;
use tempfile::Builder;
use zkm_core_executor::ByteOpcode;
use zkm_core_executor::events::AES_128_BLOCK_BYTES;
use zkm_core_executor::syscalls::SyscallCode;
use zkm_stark::{LookupScope, MachineAir, ZKMAirBuilder};
use crate::air::MemoryAirBuilder;
use crate::KeccakSpongeChip;
use crate::memory::MemoryCols;
use crate::operations::mix_column::MixColumn;
use crate::operations::round_key::{NextRoundKey, ROUND_CONST};
use crate::syscall::precompiles::aes128_encrypt::AES128EncryptChip;
use crate::syscall::precompiles::aes128_encrypt::columns::{AES128EncryptionCols, NUM_AES128_ENCRYPTION_COLS};

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

        self.eval_mix_column(builder, local);
        self.eval_compute_round_key(builder, local);
        // self.eval_add_round_key(builder, local);

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
                local.key_address + AB::F::from_canonical_u32((i as u32 * 4)),
                &local.key[i],
                local.round[0],
            );
        }

        // if this is the first row, populate reading input
        for i in 0..4 {
            builder.eval_memory_access(
                local.shard,
                local.clk,
                local.block_address + AB::F::from_canonical_u32(i  as u32 * 4),
                &local.block[i],
                local.round[0],
            );
        }

        // if this is the first row, populate reading sbox_addr
        builder.eval_memory_access(
            local.shard,
            local.clk,
            AB::F::from_canonical_u8(6),
            &local.sbox_addr_read,
            local.round[0],
        );
        
        // if this is the last row, populate writing output
        for i in 0..4 {
            builder.eval_memory_access(
                local.shard,
                local.clk + AB::Expr::ONE,
                local.block_address + AB::F::from_canonical_u32((i * 4) as u32),
                &local.block[i],
                local.round[10]
            );
        }

        let round_1to10 = local.round[10] + local.round_1to9;
        
        // subs_bytes for state matrix
        for i in 0..AES_128_BLOCK_BYTES {
            let index = local.state_matrix[i];
            builder.eval_memory_access(
                local.shard,
                local.clk,
                local.sbox_address + index * AB::F::from_canonical_u8(4),
                &local.state_subs_bytes[i],
                round_1to10.clone(),
            )
        }
        
        // sbox elements
        let round_0to9 = local.round_1to9 + local.round[0];
        let start = round * AB::F::from_canonical_u32(24);
        for i in 0..24 {
            builder.eval_memory_access(
                local.shard,
                local.clk,
                local.sbox_address
                    + (start.clone() + AB::F::from_canonical_u32(i as u32)) * AB::F::from_canonical_u8(4),
                &local.sbox[i],
                round_0to9.clone()
            );
        }
        for i in 0..16 {
            builder.eval_memory_access(
                local.shard,
                local.clk,
                local.sbox_address
                    + (start.clone() + AB::F::from_canonical_u32(i as u32)) * AB::F::from_canonical_u8(4),
                &local.sbox[i],
                local.round[10].clone(),
            );
        }
        
        // round key subs bytes
        let key_id = [13, 14, 15, 12];
        for (i, id) in key_id.iter().enumerate() {
        builder.eval_memory_access(
                local.shard,
                local.clk,
                local.sbox_address + local.round_key_matrix[*id as usize] * AB::F::from_canonical_u8(4),
                &local.roundkey_subs_bytes[i],
                round_0to9.clone(),
            );
        }
    }

    fn eval_mix_column<AB: ZKMAirBuilder>(
        &self,
        builder: &mut AB,
        local: &AES128EncryptionCols<AB::Var>,
    ) {
        let shifted_state = [
            local.state_subs_bytes[0].value()[0],
            local.state_subs_bytes[5].value()[0],
            local.state_subs_bytes[10].value()[0],
            local.state_subs_bytes[15].value()[0],
            local.state_subs_bytes[4].value()[0],
            local.state_subs_bytes[9].value()[0],
            local.state_subs_bytes[14].value()[0],
            local.state_subs_bytes[3].value()[0],
            local.state_subs_bytes[8].value()[0],
            local.state_subs_bytes[13].value()[0],
            local.state_subs_bytes[2].value()[0],
            local.state_subs_bytes[7].value()[0],
            local.state_subs_bytes[12].value()[0],
            local.state_subs_bytes[1].value()[0],
            local.state_subs_bytes[6].value()[0],
            local.state_subs_bytes[11].value()[0],
        ];
        MixColumn::<AB::F>::eval(
            builder,
            shifted_state,
            local.mix_column,
            local.round_1to9
        );
    }

    fn eval_compute_round_key<AB: ZKMAirBuilder>(
        &self,
        builder: &mut AB,
        local: &AES128EncryptionCols<AB::Var>,
    ) {
        NextRoundKey::<AB::F>::eval(
            builder,
            local.next_round_key,
            local.round_key_matrix,
            &local.roundkey_subs_bytes,
            local.round_const,
            local.round[0],
        );
        NextRoundKey::<AB::F>::eval(
            builder,
            local.next_round_key,
            local.round_key_matrix,
            &local.roundkey_subs_bytes,
            local.round_const,
            local.round_1to9,
        );

        for i in 0..11 {
            builder.when(local.round[i]).assert_eq(
                local.round_const,
                AB::F::from_canonical_u8(ROUND_CONST[i])
            );
        }

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
}