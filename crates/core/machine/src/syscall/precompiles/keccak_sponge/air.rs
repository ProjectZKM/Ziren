use crate::air::{MemoryAirBuilder, WordAirBuilder};
use crate::memory::MemoryCols;
use crate::operations::XorOperation;
use crate::syscall::precompiles::keccak_sponge::columns::{
    KeccakSpongeCols, NUM_KECCAK_SPONGE_COLS,
};
use crate::syscall::precompiles::keccak_sponge::{
    KeccakSpongeChip, KECCAK_GENERAL_OUTPUT_U32S, KECCAK_GENERAL_RATE_U32S, KECCAK_STATE_U32S,
};

use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::FieldAlgebra;
use p3_keccak_air::{KeccakAir, NUM_KECCAK_COLS, NUM_ROUNDS, U64_LIMBS};
use p3_matrix::Matrix;
use std::borrow::Borrow;
use zkm_core_executor::syscalls::SyscallCode;
use zkm_stark::{LookupScope, SubAirBuilder, ZKMAirBuilder};

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
        let final_block = local.is_final_input_block;
        let final_step = local.keccak.step_flags[NUM_ROUNDS - 1];
        let not_final_step = AB::Expr::one() - final_step;
        let not_final_sponge = AB::Expr::one() - local.write_output;

        // Constrain flags
        self.eval_flags(builder, local);
        // Constrain memory
        self.eval_memory_access(builder, local);
        // Constrain the state
        self.eval_state_keccakf(builder, local, next);

        // Receive syscall
        builder.receive_syscall(
            local.shard,
            local.clk,
            AB::F::from_canonical_u32(SyscallCode::KECCAK_SPONGE.syscall_id()),
            local.input_address,
            local.output_address,
            local.receive_syscall,
            LookupScope::Local,
        );

        // Constrain that the inputs stay the same throughout the rows of each cycle
        let mut transition_builder = builder.when_transition();
        let mut transition_not_final_builder = transition_builder.when(not_final_sponge.clone());
        transition_not_final_builder.assert_eq(local.shard, next.shard);
        transition_not_final_builder.assert_eq(local.clk, next.clk);
        transition_not_final_builder.assert_eq(local.is_real, next.is_real);
        transition_not_final_builder.assert_eq(local.input_len, next.input_len);
        transition_not_final_builder.assert_eq(local.output_address, next.output_address);
        // The final row must be nonreal because NUM_ROUNDS is not a power of 2. This constraint
        // ensures that the table does not end abruptly.
        builder.when_last_row().assert_zero(local.is_real);

        // Xor
        for i in 0..KECCAK_GENERAL_RATE_U32S {
            XorOperation::<AB::F>::eval(
                builder,
                local.original_state[i],
                local.block_mem[i].access.value,
                local.xored_general_rate[i],
                local.read_block,
            );
        }

        // Constrain the absorbed bytes
        builder
            .when_transition()
            .when(not_final_step)
            .assert_eq(local.already_absorbed_u32s, next.already_absorbed_u32s);
        // If this is the first block, absorbed bytes should be 0
        builder.when(first_block).assert_eq(local.already_absorbed_u32s, AB::Expr::zero());
        // If this is the final block, absorbed bytes should be equal to the input length - KECCAK_GENERAL_RATE_U32S
        builder.when(final_block).assert_eq(
            local.already_absorbed_u32s,
            local.input_len - AB::Expr::from_canonical_u32(KECCAK_GENERAL_RATE_U32S as u32),
        );
        // If local is real and not the final block, absorbed bytes in next block should be
        // equal to the previous absorbed bytes + KECCAK_GENERAL_RATE_U32S
        builder.when(local.is_absorbed).assert_eq(
            local.already_absorbed_u32s,
            next.already_absorbed_u32s
                - AB::Expr::from_canonical_u32(KECCAK_GENERAL_RATE_U32S as u32),
        );
        // check the input address
        builder.when(local.is_absorbed).assert_eq(
            local.input_address,
            next.input_address - AB::Expr::from_canonical_u32(KECCAK_GENERAL_RATE_U32S as u32 * 4),
        );

        // Eval the plonky3 keccak air
        let mut sub_builder =
            SubAirBuilder::<AB, KeccakAir, AB::Var>::new(builder, 0..NUM_KECCAK_COLS);
        self.p3_keccak.eval(&mut sub_builder);
    }
}

impl KeccakSpongeChip {
    fn eval_flags<AB: ZKMAirBuilder>(&self, builder: &mut AB, local: &KeccakSpongeCols<AB::Var>) {
        let first_block = local.is_first_input_block;
        let final_block = local.is_final_input_block;
        let not_final_block = AB::Expr::one() - final_block;

        let first_step = local.keccak.step_flags[0];
        let final_step = local.keccak.step_flags[NUM_ROUNDS - 1];

        // receive syscall
        builder.assert_eq(first_block * first_step * local.is_real, local.receive_syscall);

        // write output flag
        builder.assert_eq(final_block * final_step * local.is_real, local.write_output);

        // check the absorbed bytes
        builder.assert_eq(local.is_absorbed, final_step * not_final_block * local.is_real);
    }

    fn eval_memory_access<AB: ZKMAirBuilder>(
        &self,
        builder: &mut AB,
        local: &KeccakSpongeCols<AB::Var>,
    ) {
        // if this is the first row, populate reading input length
        builder.eval_memory_access(
            local.shard,
            local.clk,
            local.output_address + AB::Expr::from_canonical_u32(64),
            &local.input_length_mem,
            local.receive_syscall,
        );
        // Verify the input length has not changed
        builder
            .when(local.is_real)
            .assert_word_eq(*local.input_length_mem.value(), *local.input_length_mem.prev_value());

        // Read the input block
        for i in 0..KECCAK_GENERAL_RATE_U32S as u32 {
            builder.eval_memory_access(
                local.shard,
                local.clk,
                local.input_address + AB::Expr::from_canonical_u32(i * 4),
                &local.block_mem[i as usize],
                local.read_block,
            );
        }
        // Verify the input has not changed
        for i in 0..KECCAK_GENERAL_RATE_U32S {
            builder
                .when(local.is_real)
                .assert_word_eq(*local.block_mem[i].value(), *local.block_mem[i].prev_value());
        }

        // If this is the final round of the final block, write the output
        for i in 0..KECCAK_GENERAL_OUTPUT_U32S as u32 {
            builder.eval_memory_access(
                local.shard,
                local.clk + AB::Expr::one(),
                local.output_address + AB::Expr::from_canonical_u32(i * 4),
                &local.output_mem[i as usize],
                local.write_output,
            );
        }
    }
    fn eval_state_keccakf<AB: ZKMAirBuilder>(
        &self,
        builder: &mut AB,
        local: &KeccakSpongeCols<AB::Var>,
        next: &KeccakSpongeCols<AB::Var>,
    ) {
        let first_step = local.keccak.step_flags[0];
        // constrain the state
        let expr_2_pow_8 = AB::Expr::from_canonical_u32(2u32.pow(8));

        for i in 0..(KECCAK_GENERAL_RATE_U32S / 2) as u32 {
            let y_idx = i / 5;
            let x_idx = i % 5;

            // Interpret u32 memory words as u16 limbs
            let least_sig_word = local.xored_general_rate[(i * 2) as usize].value;
            let most_sig_word = local.xored_general_rate[(i * 2 + 1) as usize].value;
            let memory_limbs = [
                least_sig_word[0] + least_sig_word[1] * expr_2_pow_8.clone(),
                least_sig_word[2] + least_sig_word[3] * expr_2_pow_8.clone(),
                most_sig_word[0] + most_sig_word[1] * expr_2_pow_8.clone(),
                most_sig_word[2] + most_sig_word[3] * expr_2_pow_8.clone(),
            ];
            // On a first round, verify memory matches with local.p3_keccak_cols.a
            let a_value_limbs = local.keccak.a[y_idx as usize][x_idx as usize];
            for j in 0..U64_LIMBS {
                builder
                    .when(first_step * local.is_real)
                    .assert_eq(memory_limbs[j].clone(), a_value_limbs[j]);
            }

            // On a final round, verify memory matches with
            // local.p3_keccak_cols.a_prime_prime_prime (except for the final block)
            let least_sig_word = next.original_state[(i * 2) as usize];
            let most_sig_word = next.original_state[(i * 2 + 1) as usize];
            let memory_limbs = [
                least_sig_word[0] + least_sig_word[1] * expr_2_pow_8.clone(),
                least_sig_word[2] + least_sig_word[3] * expr_2_pow_8.clone(),
                most_sig_word[0] + most_sig_word[1] * expr_2_pow_8.clone(),
                most_sig_word[2] + most_sig_word[3] * expr_2_pow_8.clone(),
            ];
            for j in 0..U64_LIMBS {
                builder.when(local.is_absorbed).assert_eq(
                    memory_limbs[j].clone(),
                    local.keccak.a_prime_prime_prime(y_idx as usize, x_idx as usize, j),
                )
            }
        }

        for i in (KECCAK_GENERAL_RATE_U32S / 2)..(KECCAK_STATE_U32S / 2) {
            let y_idx = i / 5;
            let x_idx = i % 5;

            let least_sig_word = local.original_state[(i * 2) as usize];
            let most_sig_word = local.original_state[(i * 2 + 1) as usize];
            let memory_limbs = [
                least_sig_word[0] + least_sig_word[1] * expr_2_pow_8.clone(),
                least_sig_word[2] + least_sig_word[3] * expr_2_pow_8.clone(),
                most_sig_word[0] + most_sig_word[1] * expr_2_pow_8.clone(),
                most_sig_word[2] + most_sig_word[3] * expr_2_pow_8.clone(),
            ];
            let a_value_limbs = local.keccak.a[y_idx as usize][x_idx as usize];
            for j in 0..U64_LIMBS {
                builder
                    .when(first_step * local.is_real)
                    .assert_eq(memory_limbs[j].clone(), a_value_limbs[j]);
            }

            let least_sig_word = next.original_state[(i * 2) as usize];
            let most_sig_word = next.original_state[(i * 2 + 1) as usize];
            let memory_limbs = [
                least_sig_word[0] + least_sig_word[1] * expr_2_pow_8.clone(),
                least_sig_word[2] + least_sig_word[3] * expr_2_pow_8.clone(),
                most_sig_word[0] + most_sig_word[1] * expr_2_pow_8.clone(),
                most_sig_word[2] + most_sig_word[3] * expr_2_pow_8.clone(),
            ];
            for j in 0..U64_LIMBS {
                builder.when(local.is_absorbed).assert_eq(
                    memory_limbs[j].clone(),
                    local.keccak.a_prime_prime_prime(y_idx as usize, x_idx as usize, j),
                )
            }
        }

        // if this is the final round of the final block, verify output memory with
        // local.p3_keccak_cols.a_prime_prime_prime
        for i in 0..(KECCAK_GENERAL_OUTPUT_U32S / 2) as u32 {
            let y_idx = i / 5;
            let x_idx = i % 5;

            let least_sig_word = local.output_mem[(i * 2) as usize].value();
            let most_sig_word = local.output_mem[(i * 2 + 1) as usize].value();
            let memory_limbs = [
                least_sig_word[0] + least_sig_word[1] * expr_2_pow_8.clone(),
                least_sig_word[2] + least_sig_word[3] * expr_2_pow_8.clone(),
                most_sig_word[0] + most_sig_word[1] * expr_2_pow_8.clone(),
                most_sig_word[2] + most_sig_word[3] * expr_2_pow_8.clone(),
            ];
            for j in 0..U64_LIMBS {
                builder.when(local.write_output).assert_eq(
                    memory_limbs[j].clone(),
                    local.keccak.a_prime_prime_prime(y_idx as usize, x_idx as usize, j),
                )
            }
        }
    }
}
