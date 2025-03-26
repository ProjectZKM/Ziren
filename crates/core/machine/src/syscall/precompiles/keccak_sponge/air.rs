use std::borrow::Borrow;
use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::FieldAlgebra;
use p3_matrix::Matrix;
use zkm2_core_executor::syscalls::SyscallCode;
use zkm2_stark::{LookupScope, ZKMAirBuilder};
use crate::air::{MemoryAirBuilder, WordAirBuilder};
use crate::memory::MemoryCols;
use crate::operations::XorOperation;
use crate::syscall::precompiles::keccak_sponge::columns::{KeccakSpongeCols, NUM_KECCAK_SPONGE_COLS};
use crate::syscall::precompiles::keccak_sponge::{KeccakSpongeChip, KECCAK_GENERAL_OUTPUT_U32S, KECCAK_GENERAL_RATE_U32S, KECCAK_STATE_U32S};

impl<F> BaseAir<F> for KeccakSpongeChip {
    fn width(&self) -> usize {
        NUM_KECCAK_SPONGE_COLS
    }
}

impl<AB> Air<AB> for KeccakSpongeChip
where
    AB: ZKMAirBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let (local, next) = (main.row_slice(0), main.row_slice(1));
        let local: &KeccakSpongeCols<AB::Var> = (*local).borrow();
        let next: &KeccakSpongeCols<AB::Var> = (*next).borrow();

        let first_block = local.is_first_input_block;
        let final_block = local.is_last_input_block;
        let not_final_block = AB::Expr::ONE - final_block;

        // receive syscall
        builder.receive_syscall(
            local.shard,
            local.clk,
            AB::F::from_canonical_u32(SyscallCode::KECCAK_SPONGE.syscall_id()),
            local.input_address,
            local.output_address,
            first_block,
            LookupScope::Local,
        );

        // Constrain that the inputs stay the same throughout the rows of each cycle
        let mut transition_builder = builder.when_transition();
        let mut transition_not_final_builder = transition_builder.when(not_final_block.clone());
        transition_not_final_builder.assert_eq(local.shard, next.shard);
        transition_not_final_builder.assert_eq(local.clk, next.clk);
        transition_not_final_builder.assert_eq(local.is_real, next.is_real);

        // if this is the first row, populate reading input length
        builder.eval_memory_access(
            local.shard,
            local.clk,
            local.output_address + AB::Expr::from_canonical_u32(64),
            &local.input_length_mem,
            first_block
        );

        // Read the input for each block
        for i in 0..KECCAK_GENERAL_RATE_U32S as u32 {
            builder.eval_memory_access(
                local.shard,
                local.clk,
                local.input_address + AB::Expr::from_canonical_u32(i * 4),
                &local.block_mem[i as usize],
                local.is_real,
            );
        }
        // Verify the input has not changed
        for i in 0..KECCAK_GENERAL_RATE_U32S {
            builder.when(local.is_real).assert_word_eq(
                *local.block_mem[i].value(),
                *local.block_mem[i].prev_value());
        }

        // If this is the last block, write the output
        for i in 0..KECCAK_GENERAL_OUTPUT_U32S as u32 {
            builder.eval_memory_access(
                local.shard,
                local.clk + AB::Expr::ONE,
                local.output_address + AB::Expr::from_canonical_u32(i * 4),
                &local.output_mem[i as usize],
                final_block,
            );
        }

        // xor
        for i in 0..KECCAK_GENERAL_RATE_U32S {
            XorOperation::<AB::F>::eval(
                builder,
                local.original_state[i],
                local.block_mem[i].access.value,
                local.xored_general_rate[i],
                local.is_real,
            );
        }

        // check the absorbed bytes
        // If this is the first block, absorbed bytes should be 0
        builder.when(first_block).assert_eq(local.already_absorbed_u32s, AB::Expr::ZERO);
        // // If this is the last block, absorbed bytes should be equal to the input length - KECCAK_GENERAL_RATE_U32S
        builder.when(final_block).assert_eq(
            local.already_absorbed_u32s,
            local.len - AB::Expr::from_canonical_u32(KECCAK_GENERAL_RATE_U32S as u32),
        );
        // // If local is real and not the last block, absorbed bytes in next should be
        // // equal to the previous absorbed bytes + KECCAK_GENERAL_RATE_U32S
        builder.when(not_final_block.clone() * local.is_real).assert_eq(
            local.already_absorbed_u32s,
            next.already_absorbed_u32s - AB::Expr::from_canonical_u32(KECCAK_GENERAL_RATE_U32S as u32),
        );

        // check the state
        let not_final_block = AB::Expr::ONE - final_block;
        for i in 0..KECCAK_STATE_U32S {
            builder.when(not_final_block.clone() * local.is_real).assert_word_eq(
                local.updated_state[i],
                next.original_state[i]
            );
        }

        // check the output if this is the final block
        for i in 0..KECCAK_GENERAL_OUTPUT_U32S {
            builder.when(final_block).assert_word_eq(
                local.updated_state[i],
                *local.output_mem[i].value(),
            );
        }

        // Range check all the values in `input length`, `block_mem`, `xored_rate_mem` to be bytes.
        for i in 0..KECCAK_GENERAL_RATE_U32S {
            builder.slice_range_check_u8(&local.block_mem[i].value().0, local.is_real);
        }
        builder.slice_range_check_u8(&local.input_length_mem.value().0, first_block);
        for i in 0..KECCAK_GENERAL_OUTPUT_U32S {
            builder.slice_range_check_u8(&local.output_mem[i].value().0, final_block);
        }
    }
}