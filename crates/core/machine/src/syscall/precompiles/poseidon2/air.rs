use std::borrow::Borrow;

use p3_air::{Air, AirBuilder, BaseAir, PairBuilder};
use p3_field::FieldAlgebra;
use p3_matrix::Matrix;

use crate::operations::poseidon2::air::{eval_external_round, eval_internal_rounds};
use crate::operations::poseidon2::permutation::Poseidon2Cols;
use crate::operations::poseidon2::{NUM_EXTERNAL_ROUNDS, WIDTH};
use crate::operations::KoalaBearWordRangeChecker;
use crate::syscall::precompiles::poseidon2::{
    columns::{Poseidon2MemCols, NUM_COLS},
    Poseidon2PermuteChip,
};
use crate::{air::MemoryAirBuilder, memory::MemoryCols};
use zkm_core_executor::syscalls::SyscallCode;
use zkm_stark::air::{LookupScope, ZKMAirBuilder};

impl<F> BaseAir<F> for Poseidon2PermuteChip {
    fn width(&self) -> usize {
        NUM_COLS
    }
}

impl<AB> Air<AB> for Poseidon2PermuteChip
where
    AB: ZKMAirBuilder + PairBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &Poseidon2MemCols<AB::Var> = (*local).borrow();

        // Assert that is_real is a boolean.
        builder.assert_bool(local.is_real);

        for i in 0..WIDTH {
            // Range check the previous value of the state in memory. This ensures that each part
            // of the state is in KoalaBear field.
            KoalaBearWordRangeChecker::<AB::F>::range_check(
                builder,
                *local.state_mem[i].prev_value(),
                local.pre_state_range_check_cols[i],
                local.is_real.into(),
            );
            let pre_state_word = local.state_mem[i].prev_value().0;
            let pre_state = pre_state_word
                .iter()
                .enumerate()
                .map(|(j, limb)| (*limb).into() * AB::Expr::from_canonical_u32(1 << (j * 8)))
                .sum::<AB::Expr>();
            // If this is a real operation, assert that the reconstructed pre-state from memory
            // matches the input to the Poseidon2 permutation AIR.
            builder.when(local.is_real).assert_eq(
                local.poseidon2.permutation.external_rounds_state()[0][i].into(),
                pre_state,
            );
        }

        // // Constrain the permutation.
        for r in 0..NUM_EXTERNAL_ROUNDS {
            eval_external_round(builder, &local.poseidon2.permutation, r);
        }
        eval_internal_rounds(builder, &local.poseidon2.permutation);

        for i in 0..WIDTH {
            // Range check the current value of the state in memory. This ensures that each part
            // of the state is in KoalaBear field.
            KoalaBearWordRangeChecker::<AB::F>::range_check(
                builder,
                *local.state_mem[i].value(),
                local.post_state_range_check_cols[i],
                local.is_real.into(),
            );
            let post_state_word = local.state_mem[i].value().0;
            let post_state = post_state_word
                .iter()
                .enumerate()
                .map(|(j, limb)| (*limb).into() * AB::Expr::from_canonical_u32(1 << (j * 8)))
                .sum::<AB::Expr>();
            // If this is a real operation, assert that the reconstructed post-state from memory
            // matches the output from the Poseidon2 permutation AIR.
            builder
                .when(local.is_real)
                .assert_eq(local.poseidon2.permutation.perm_output()[i].into(), post_state);
        }

        // Read and write the state memory.
        builder.eval_memory_access_slice(
            local.shard,
            local.clk.into(),
            local.state_addr,
            &local.state_mem,
            local.is_real,
        );

        // Receive the arguments.
        builder.receive_syscall(
            local.shard,
            local.clk,
            AB::F::from_canonical_u32(SyscallCode::POSEIDON2_PERMUTE.syscall_id()),
            local.state_addr,
            AB::Expr::ZERO,
            local.is_real,
            LookupScope::Local,
        );
    }
}
